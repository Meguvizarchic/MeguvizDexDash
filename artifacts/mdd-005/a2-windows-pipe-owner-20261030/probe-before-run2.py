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
    (Path(__file__).parent / 'admission-run2.json').write_text(json.dumps(admitted, indent=2) + '\n', encoding='utf8')
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

    async def create(script, arguments=(), pipe_bounds=bounds):
        require(admit()['admitted'], 'insufficient free memory before child launch')
        return await WindowsJobPipeOwner.launch(executable, ['-B', '-c', script, *arguments],
            cwd=ROOT, env=env, expected_sha256=sha, job_limits=job, pipe_limits=pipe_bounds)

    sentinel_read, sentinel_write = _winapi.CreatePipe(None, 0)
    os.set_handle_inheritable(sentinel_write, True)
    try:
        script = ('import ctypes,json,sys; f=ctypes.c_uint32(); '
                  's=bool(ctypes.windll.kernel32.GetHandleInformation(ctypes.c_void_p(int(sys.argv[1])),ctypes.byref(f))); '
                  'v=sys.stdin.buffer.readline(); sys.stdout.write(json.dumps({"input":v.decode("ascii"),"sentinel":s})+"\\n"); '
                  'sys.stdout.flush(); sys.stdin.buffer.read()')
        owner = await create(script, [str(sentinel_write)])
        try:
            await owner.write(b'hello\n')
            response = json.loads((await owner.read(4096)).decode('utf8'))
            print(json.dumps({'roundtrip_observed': response}), flush=True)
            require(response == {'input': 'hello\n', 'sentinel': False}, 'pipe or handle whitelist failed')
        finally:
            await owner.close()
        require(owner.tree_empty_verified, 'roundtrip job not empty')
        observed.append('roundtrip_and_handle_whitelist')
    finally:
        _winapi.CloseHandle(sentinel_read)
        _winapi.CloseHandle(sentinel_write)

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

    print(json.dumps({'status': 'passed', 'checks': observed, 'executable_sha256': sha,
                      'scope': 'self-owned hidden synthetic children only; no MCP, snapshot or A2 qualification'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))
