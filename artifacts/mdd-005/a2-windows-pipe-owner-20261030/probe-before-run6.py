"""Bounded synthetic checks of an owned Windows async pipe Job; not MCP/A2."""
import asyncio
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import win32api
import win32event
import win32process
import _winapi

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_windows_job_owner import JobLimits
from a2_windows_pipe_owner import PipeLimits, PipeOwnerError, WindowsJobPipeOwner


class Memory(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint32), ('load', ctypes.c_uint32)] + [
        (name, ctypes.c_uint64) for name in ('total', 'available', 'page_total',
        'page_available', 'virtual_total', 'virtual_available', 'extended')]


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def admit():
    memory = Memory(); memory.length = ctypes.sizeof(memory)
    require(ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)), 'memory observation failed')
    minimum = 3 * 1024 ** 3
    return {'available_bytes': str(memory.available), 'minimum_bytes': str(minimum),
            'admitted': memory.available >= minimum}


async def main():
    admitted = admit()
    (Path(__file__).parent / 'admission-run6.json').write_text(json.dumps(admitted, indent=2) + '\n', encoding='utf8')
    if not admitted['admitted']:
        print(json.dumps({'status': 'blocked', 'child_started': False}))
        return 2
    executable = Path(sys.executable).resolve(strict=True)
    sha = hashlib.sha256(executable.read_bytes()).hexdigest()
    allowed, _ = win32process.GetProcessAffinityMask(win32api.GetCurrentProcess())
    job = JobLimits(memory_commit_bytes=512 * 1024 ** 2, affinity_mask=allowed & -allowed,
                    active_processes=8, lifetime_seconds=15, cleanup_seconds=5)
    bounds = PipeLimits(max_write_bytes=4096, max_input_bytes=8192,
                        max_read_bytes=4096, max_output_bytes=8192,
                        max_stderr_bytes=512, io_seconds=.5)
    # No secret values are written to evidence. The child gets only a minimal
    # environment required by the Python runtime.
    env = {k: v for k, v in os.environ.items() if k.upper() in
           {'SYSTEMROOT', 'WINDIR', 'PATH', 'TEMP', 'TMP', 'COMSPEC', 'PATHEXT'}}
    observed = []

    async def create(script, arguments=(), pipe_bounds=bounds, job_bounds=job):
        require(admit()['admitted'], 'insufficient free memory before child launch')
        return await WindowsJobPipeOwner.launch(executable, ['-B', '-c', script, *arguments],
            cwd=ROOT, env=env, expected_sha256=sha, job_limits=job_bounds, pipe_limits=pipe_bounds)

    sentinel = win32event.CreateEvent(None, True, False, None)
    os.set_handle_inheritable(int(sentinel), True)
    try:
        script = ('import ctypes,json,sys; '
                  'ctypes.windll.kernel32.SetEvent(ctypes.c_void_p(int(sys.argv[1]))); '
                  'v=sys.stdin.buffer.readline(); sys.stdout.write(json.dumps({"input":v.decode("ascii")})+"\\n"); '
                  'sys.stdout.flush(); sys.stdin.buffer.read()')
        owner = await create(script, [str(int(sentinel))])
        try:
            await owner.write(b'hello\n')
            response = json.loads((await owner.read(4096)).decode('utf8'))
            print(json.dumps({'roundtrip_observed': response}), flush=True)
            require(response == {'input': 'hello\n'}, 'pipe roundtrip failed')
            require(win32event.WaitForSingleObject(sentinel, 0) == win32event.WAIT_TIMEOUT,
                    'non-whitelisted sentinel event was inherited')
        finally:
            await owner.close()
        require(owner.tree_empty_verified, 'roundtrip job not empty')
        observed.append('roundtrip_and_handle_whitelist')
    finally:
        sentinel.Close()

    owner = await create('import time;time.sleep(10)')
    try:
        try:
            await owner.read(64)
            raise RuntimeError('timeout was not raised')
        except TimeoutError:
            require(owner.tree_empty_verified, 'timeout job not empty')
            observed.append('read_timeout_stops_owned_job')
    finally:
        await owner.close()

    small = PipeLimits(max_write_bytes=64, max_input_bytes=64, max_read_bytes=64,
                       max_output_bytes=128, max_stderr_bytes=64, io_seconds=2)
    owner = await create('import sys;sys.stdin.buffer.read()', pipe_bounds=small)
    try:
        await owner.write(b'x' * 64)
        try:
            await owner.write(b'y')
            raise RuntimeError('input budget was not raised')
        except PipeOwnerError:
            require(owner.tree_empty_verified, 'input quota job not empty')
            observed.append('input_quota_stops_owned_job')
    finally:
        await owner.close()

    owner = await create('import sys,time;sys.stderr.buffer.write(b"e"*1024);sys.stderr.buffer.flush();time.sleep(10)', pipe_bounds=small)
    try:
        deadline = time.monotonic() + 5
        while owner._state != 'closed' and time.monotonic() < deadline:
            await asyncio.sleep(.01)
        require(owner._state == 'closed' and owner.tree_empty_verified, 'stderr budget did not stop owned job')
        observed.append('stderr_quota_stops_owned_job')
    finally:
        await owner.close()

    owner = await create('import time;time.sleep(10)')
    try:
        task = asyncio.create_task(owner.read(64))
        await asyncio.sleep(.05)
        task.cancel()
        try:
            await task
            raise RuntimeError('cancellation was not propagated')
        except asyncio.CancelledError:
            require(owner.tree_empty_verified, 'cancelled read job not empty')
            observed.append('cancelled_read_stops_owned_job')
    finally:
        await owner.close()

    owner = await create('import sys,time;sys.stdout.buffer.write(b"o"*256);sys.stdout.buffer.flush();time.sleep(10)', pipe_bounds=small)
    try:
        try:
            while True:
                await owner.read(64)
        except PipeOwnerError as error:
            require('stdout byte budget' in str(error), 'wrong stdout quota error')
            require(owner.tree_empty_verified, 'stdout quota job not empty')
            observed.append('stdout_quota_stops_owned_job')
    finally:
        await owner.close()

    owner = await create('pass')
    try:
        try:
            await owner.read(64)
            raise RuntimeError('EOF was treated as a result')
        except PipeOwnerError as error:
            require('EOF' in str(error), 'wrong EOF error')
            require(owner.tree_empty_verified, 'EOF job not empty')
            observed.append('eof_is_not_protocol_success')
    finally:
        await owner.close()

    owner = await create('import sys;sys.stdin.buffer.read()')
    try:
        original_writer = owner._stdin
        gate = asyncio.Event()
        class BlockedWriter:
            def write(self, data):
                original_writer.write(data)
            async def drain(self):
                await gate.wait()
        owner._stdin = BlockedWriter()
        writing = asyncio.create_task(owner.write(b'x'))
        await asyncio.sleep(.03)
        writing.cancel()
        try:
            await writing
            raise RuntimeError('write cancellation was swallowed')
        except asyncio.CancelledError:
            require(owner.tree_empty_verified, 'cancelled write job not empty')
            observed.append('cancelled_write_stops_owned_job')
    finally:
        await owner.close()

    # Hold the front-end read after bytes are available until the actual
    # stderr quota task has recorded its failure. No payload may be returned.
    owner = await create('import sys,time;sys.stdin.buffer.read(1);sys.stdout.buffer.write(b"data");sys.stdout.buffer.flush();sys.stderr.buffer.write(b"e"*1024);sys.stderr.buffer.flush();time.sleep(10)', pipe_bounds=small)
    try:
        original = owner._stdout
        class GatedReader:
            async def read(self, maximum):
                data = await original.read(maximum)
                while owner._failure is None:
                    await asyncio.sleep(0)
                return data
        owner._stdout = GatedReader()
        reading = asyncio.create_task(owner.read(64))
        await asyncio.sleep(.03)
        owner._stdin.write(b'x')
        await owner._stdin.drain()
        try:
            await reading
            raise RuntimeError('read succeeded after stderr quota')
        except PipeOwnerError:
            require(owner._failure is not None and 'stderr byte budget' in str(owner._failure), 'original stderr quota lost')
            require(owner.tree_empty_verified, 'read race job not empty')
            observed.append('stderr_failure_blocks_pending_read')
    finally:
        await owner.close()

    owner = await create('import sys,time;sys.stdin.buffer.read(1);sys.stderr.buffer.write(b"e"*1024);sys.stderr.buffer.flush();time.sleep(10)', pipe_bounds=small)
    try:
        original_writer = owner._stdin
        class GatedWriter:
            def write(self, data):
                original_writer.write(data)
            async def drain(self):
                await original_writer.drain()
                while owner._failure is None:
                    await asyncio.sleep(0)
        owner._stdin = GatedWriter()
        try:
            await owner.write(b'x')
            raise RuntimeError('write succeeded after stderr quota')
        except PipeOwnerError:
            require(owner._failure is not None and 'stderr byte budget' in str(owner._failure), 'original stderr quota lost')
            require(owner.tree_empty_verified, 'write race job not empty')
            observed.append('stderr_failure_blocks_pending_write')
    finally:
        await owner.close()

    short_job = JobLimits(memory_commit_bytes=job.memory_commit_bytes, affinity_mask=job.affinity_mask,
                          active_processes=job.active_processes, lifetime_seconds=.3, cleanup_seconds=5)
    owner = await create('import time;time.sleep(10)', job_bounds=short_job)
    try:
        deadline = time.monotonic() + 5
        while owner._state != 'closed' and time.monotonic() < deadline:
            await asyncio.sleep(.01)
        require(owner._state == 'closed' and owner.tree_empty_verified, 'idle lifetime was not enforced')
        require(isinstance(owner._failure, TimeoutError), 'lifetime failure identity lost')
        observed.append('idle_lifetime_stops_owned_job')
    finally:
        await owner.close()

    owner = await create('import time;time.sleep(10)')
    await owner._cleanup_lock.acquire()
    closing = asyncio.create_task(owner.close())
    await asyncio.sleep(.03)
    closing.cancel()
    await asyncio.sleep(0)
    owner._cleanup_lock.release()
    try:
        await closing
        raise RuntimeError('close cancellation was swallowed')
    except asyncio.CancelledError:
        require(owner.tree_empty_verified and owner._state == 'closed', 'cancelled close did not confirm cleanup')
        observed.append('cancelled_close_preserves_identity_and_cleanup')

    owner = await create('import time;time.sleep(10)')
    class FailingTransport:
        def close(self):
            raise OSError('synthetic transport close failure')
    failing = FailingTransport()
    owner._transports.insert(0, failing)
    try:
        try:
            await owner.close()
            raise RuntimeError('transport close failure was swallowed')
        except PipeOwnerError as error:
            require('synthetic transport close failure' in str(error), 'transport error lost')
            require(owner._state == 'closed' and owner._job is None and owner._process is None,
                    'remaining owned handles were not released')
            require(not owner.tree_empty_verified, 'failed cleanup was reported as confirmed')
            observed.append('transport_close_failure_continues_owned_cleanup')
    finally:
        if owner._state != 'closed':
            owner._transports.remove(failing)
            await owner.close()

    print(json.dumps({'status': 'passed', 'checks': observed, 'executable_sha256': sha,
                      'scope': 'self-owned hidden synthetic children only; no MCP, snapshot or A2 qualification'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))
