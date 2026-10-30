"""Fixed A1 integration with simulated caller assertions; never A2 qualification."""
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
        (HERE / 'admission.json').write_text(json.dumps(admissions, indent=2) + '\n', encoding='utf8')
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
    sql = 'SELECT string_pool_id,string_idx,value FROM strings ORDER BY string_pool_id,string_idx'
    zero_sql = 'SELECT string_pool_id,string_idx,value FROM strings WHERE 0 ORDER BY string_pool_id,string_idx'
    checks = []

    async def create(snapshot_ok=True):
        admit()
        owner = await WindowsJobPipeOwner.launch(engine,
            ['--threads','1','mcp','--max-datasets','1','--timeout-ms','5000'],
            cwd=ROOT, env=env, expected_sha256=engine_sha, job_limits=job, pipe_limits=pipe)
        try:
            source = PinnedInputInventory(fixture, fixture_sha)
        except BaseException:
            await owner.close()
            raise
        # These callbacks are deliberately simulated for this public fixture.
        # They are not producer snapshot/order/041 proofs and cannot qualify A2.
        def snapshot(dataset, digest, producer):
            return bool(snapshot_ok and dataset and digest == fixture_sha and producer == engine_sha)
        def ordering(original, projected):
            return bool('ORDER BY' in original and 'ORDER BY' in projected)
        def inventory(path, files):
            return bool(path == fixture and files)
        def terms(original, columns):
            if 'file_id' in columns:
                return [OrderTerm('file_id')]
            if 'string_pool_id' in columns and 'string_idx' in columns:
                return [OrderTerm('string_pool_id'), OrderTerm('string_idx')]
            raise RuntimeError('unexpected fixture shape')
        try:
            candidate = A1BoundedCandidate(owner, source, mcp_limits=mcp,
                verify_snapshot_binding=snapshot, verify_ordering=ordering,
                verify_inventory=inventory, continuation_reason=lambda _sql: None,
                ordering_terms=terms, timeout=30)
        except BaseException:
            await owner.close()
            raise
        return owner, candidate

    # Complete only the explicitly requested queries. This is not an audit.
    owner, candidate = await create()
    try:
        async with candidate as session:
            require(session.qualified is False and session.files, 'candidate incorrectly qualified')
            rows = [row async for row in session.rows(sql, page_size=2)]
            require(len(rows) == 7, 'fixture row count differs')
            zero = [row async for row in session.rows(zero_sql, page_size=2)]
            require(zero == [], 'zero query produced rows')
            require(len(session.deliveries) == 2 and session.deliveries[0].row_count == 7,
                    'completed consumption receipt missing')
            require(session.deliveries[1].row_count == 0 and
                    session.deliveries[1].columns == ('string_pool_id','string_idx','value'),
                    'zero-row schema receipt missing')
        require(owner.tree_empty_verified and candidate.qualified is False, 'owned completion missing')
        checks.append('complete_and_zero_row_receipts')
    finally:
        await owner.close()

    # Registering but not starting a query is not complete consumption.
    owner, candidate = await create()
    unstarted = None
    try:
        try:
            async with candidate as session:
                unstarted = session.rows(sql, page_size=2)
            raise RuntimeError('unstarted query returned successful context')
        except CandidateError as error:
            require('not fully consumed' in str(error), 'unstarted query failure changed')
        require(not candidate.deliveries and owner.tree_empty_verified, 'unstarted query appeared complete')
        checks.append('unstarted_query_fails')
    finally:
        if unstarted is not None:
            await unstarted.aclose()
        await owner.close()

    # Breaking after one row does not acknowledge the rest of the page.
    owner, candidate = await create()
    partial = None
    try:
        try:
            async with candidate as session:
                partial = session.rows(sql, page_size=2)
                require(isinstance(await anext(partial), dict), 'first row missing')
            raise RuntimeError('partial query returned successful context')
        except CandidateError as error:
            require('not fully consumed' in str(error), 'partial query failure changed')
        require(not candidate.deliveries and owner.tree_empty_verified, 'partial query appeared complete')
        checks.append('partial_consumption_fails')
    finally:
        if partial is not None:
            await partial.aclose()
        await owner.close()

    # Refusing the caller's snapshot assertion must stop before query use.
    owner, candidate = await create(snapshot_ok=False)
    try:
        try:
            async with candidate:
                raise RuntimeError('unverified snapshot was accepted')
        except CandidateError as error:
            require('snapshot' in str(error), 'snapshot failure changed')
        require(owner.tree_empty_verified and not candidate.deliveries, 'snapshot failure cleanup incomplete')
        checks.append('missing_snapshot_assertion_fails')
    finally:
        await owner.close()

    # Actual task cancellation after a consumed prefix must remain cancellation.
    owner, candidate = await create()
    ready = asyncio.Event(); iterator = None
    async def consumer():
        nonlocal iterator
        async with candidate as session:
            iterator = session.rows(sql, page_size=2)
            require(isinstance(await anext(iterator), dict), 'cancel case missing row')
            ready.set()
            await asyncio.Event().wait()
    task = asyncio.create_task(consumer())
    try:
        await asyncio.wait_for(ready.wait(), timeout=20)
        task.cancel()
        try:
            await task
            raise RuntimeError('consumer cancellation was swallowed')
        except asyncio.CancelledError:
            pass
        require(owner.tree_empty_verified and not candidate.deliveries, 'cancel appeared complete')
        checks.append('consumer_cancellation_fails')
    finally:
        if not task.done():
            task.cancel()
            try:
                await task
            except BaseException:
                pass
        if iterator is not None:
            await iterator.aclose()
        await owner.close()

    # Forced owned-worker loss cannot produce a query receipt.
    owner, candidate = await create()
    failed_query = None
    try:
        try:
            async with candidate as session:
                await owner.close()
                failed_query = session.rows(sql, page_size=2)
                await anext(failed_query)
        except Exception as error:
            require(candidate._failed, 'worker loss did not mark the query failed')
            require(str(error), 'worker loss error was empty')
        else:
            raise RuntimeError('worker loss returned successful context')
        require(owner.tree_empty_verified and not candidate.deliveries, 'worker loss appeared complete')
        checks.append('worker_loss_fails')
    finally:
        if failed_query is not None:
            await failed_query.aclose()
        await owner.close()

    require(sha(engine) == engine_sha and sha(fixture) == fixture_sha, 'fixed input changed')
    print(json.dumps({'status':'passed','checks':checks,'a1_sha256':engine_sha,
        'fixture_sha256':fixture_sha,'scope':'real A1 synthetic fixture with simulated caller assertions; not snapshot, audit, A2 or performance qualification'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))
