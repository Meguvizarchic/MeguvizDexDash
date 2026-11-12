"""Fixed A1 wrong-task cleanup checks with simulated assertions; not A2 qualification."""
import asyncio
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys

import win32api
import win32process

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_bounded_candidate import A1BoundedCandidate, CandidateError
from a2_compact_adapter import OrderTerm
from a2_input_inventory import PinnedInputInventory
from a2_mcp_transport import McpPipeLimits
from a2_windows_job_owner import JobLimits
from a2_windows_pipe_owner import PipeLimits, WindowsJobPipeOwner


class Memory(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint32), ('load', ctypes.c_uint32)] + [
        (name, ctypes.c_uint64) for name in ('total', 'available', 'page_total',
        'page_available', 'virtual_total', 'virtual_available', 'extended')]


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def admission():
    memory = Memory(); memory.length = ctypes.sizeof(memory)
    require(ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)), 'memory observation failed')
    minimum = 3 * 1024 ** 3
    return {'available_bytes': str(memory.available), 'minimum_bytes': str(minimum),
            'admitted': memory.available >= minimum}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def main():
    admissions = []
    def admit():
        item = admission(); admissions.append(item)
        (HERE / 'admission-cross-task.json').write_text(json.dumps(admissions, indent=2) + '\n', encoding='utf8')
        require(item['admitted'], 'below original 3 GiB admission before owned child')
    admit()
    allowed, _ = win32process.GetProcessAffinityMask(win32api.GetCurrentProcess())
    job = JobLimits(memory_commit_bytes=512 * 1024 ** 2, affinity_mask=allowed & -allowed,
                    active_processes=8, lifetime_seconds=45, cleanup_seconds=5)
    pipe = PipeLimits(max_write_bytes=4096, max_input_bytes=1024 * 1024,
                      max_read_bytes=4096, max_output_bytes=4 * 1024 * 1024,
                      max_stderr_bytes=128 * 1024, io_seconds=5)
    mcp = McpPipeLimits(max_frame_bytes=128 * 1024, max_input_bytes=4 * 1024 * 1024,
                        max_output_bytes=1024 * 1024, max_input_frames=128,
                        max_output_frames=128)
    env = {k: v for k, v in os.environ.items() if k.upper() in
           {'SYSTEMROOT', 'WINDIR', 'PATH', 'TEMP', 'TMP', 'COMSPEC', 'PATHEXT'}}
    engine = (ROOT / 'artifacts/local/baseline-engines/A1-0.1.1-windows/dexsql-windows-amd64.exe').resolve(strict=True)
    fixture = (ROOT / 'tests/fixtures/generated/structured-035.dex').resolve(strict=True)
    engine_sha = '602105c98232120c14d6124fb33574f2f95f12e50e51d25b8834f893925f28d6'
    fixture_sha = '108cf907d330b823c6e32d38eaab8f23709fe493f52537688bbd09ba3e271605'
    require(sha(engine) == engine_sha and sha(fixture) == fixture_sha, 'fixed input identity differs')
    checks = []

    async def create():
        admit()
        owner = await WindowsJobPipeOwner.launch(engine,
            ['--threads','1','mcp','--max-datasets','1','--timeout-ms','5000'],
            cwd=ROOT, env=env, expected_sha256=engine_sha, job_limits=job, pipe_limits=pipe)
        try:
            source = PinnedInputInventory(fixture, fixture_sha)
            # Explicitly simulated caller assertions; no real producer snapshot,
            # total-order or logical-inventory proof is claimed by this test.
            candidate = A1BoundedCandidate(owner, source, mcp_limits=mcp,
                verify_snapshot_binding=lambda dataset,digest,producer:
                    bool(dataset and digest == fixture_sha and producer == engine_sha),
                verify_ordering=lambda original,projected:
                    bool('ORDER BY' in original and 'ORDER BY' in projected),
                verify_inventory=lambda path,files: bool(path == fixture and files),
                continuation_reason=lambda _sql: None,
                ordering_terms=lambda _sql,columns:
                    [OrderTerm('file_id')] if 'file_id' in columns else [], timeout=30)
            return owner, candidate
        except BaseException:
            await owner.close()
            raise

    async def exercise(mode):
        owner, candidate = await create()
        ready, resume = asyncio.Event(), asyncio.Event()
        original_close = owner.close
        outcome = []
        async def entering_task():
            try:
                async with candidate:
                    ready.set()
                    await resume.wait()
            except CandidateError as error:
                outcome.append(str(error))
        entering = asyncio.create_task(entering_task())
        try:
            await asyncio.wait_for(ready.wait(), timeout=20)
            require(candidate.qualified is False and not candidate.deliveries, 'unexpected qualification or receipt')
            if mode == 'close_error':
                injected = OSError(5, 'synthetic owned close failure')
                async def failed_close():
                    raise injected
                owner.close = failed_close
                try:
                    try:
                        await candidate.__aexit__(None, None, None)
                        raise RuntimeError('cross-task exit succeeded')
                    except CandidateError as error:
                        require(error.__cause__ is injected and error.__cause__.errno == 5,
                                'owned close exception was not retained')
                        require(any('cleanup was not confirmed' in note for note in getattr(error, '__notes__', [])),
                                'unconfirmed cleanup note missing')
                        require(not owner.tree_empty_verified, 'failed close falsely confirmed Job')
                finally:
                    owner.close = original_close
                    await owner.close()
            elif mode == 'cancel_during_close':
                await owner._cleanup_lock.acquire()
                foreign = asyncio.create_task(candidate.__aexit__(None, None, None))
                try:
                    await asyncio.sleep(.03)
                    foreign.cancel()
                    await asyncio.sleep(0)
                finally:
                    owner._cleanup_lock.release()
                try:
                    await foreign
                    raise RuntimeError('cross-task cancellation was swallowed')
                except asyncio.CancelledError as error:
                    require(any('cross-task exit was rejected' in note for note in getattr(error, '__notes__', [])),
                            'cancellation context missing')
            else:
                try:
                    await candidate.__aexit__(None, None, None)
                    raise RuntimeError('cross-task exit succeeded')
                except CandidateError as error:
                    require('entering task' in str(error), 'wrong cross-task error')
            require(owner.tree_empty_verified and candidate._state == 'failed' and not candidate.deliveries,
                    'cross-task failure did not stop owned Job or emitted receipt')
            resume.set()
            await asyncio.wait_for(entering, timeout=20)
            require(outcome and 'cross-task exit left' in outcome[0], 'entering task did not unwind as incomplete')
            require(candidate._state == 'failed' and not candidate.deliveries,
                    'entering task falsely completed the candidate')
            checks.append(mode)
        finally:
            owner.close = original_close
            if not owner.tree_empty_verified:
                await owner.close()
            resume.set()
            if not entering.done():
                try:
                    await asyncio.wait_for(entering, timeout=5)
                except BaseException:
                    entering.cancel()
                    try:
                        await entering
                    except BaseException:
                        pass
            await owner.close()

    for mode in ('wrong_task_closes_owned_job', 'close_error', 'cancel_during_close'):
        await exercise(mode)
    require(sha(engine) == engine_sha and sha(fixture) == fixture_sha, 'fixed input changed')
    print(json.dumps({'status':'passed','checks':checks,'a1_sha256':engine_sha,
        'fixture_sha256':fixture_sha,'scope':'fixed A1 synthetic input and simulated caller assertions; no full session, snapshot, audit, A2 or performance qualification'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))
