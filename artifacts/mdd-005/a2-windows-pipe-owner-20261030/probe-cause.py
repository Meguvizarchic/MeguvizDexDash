"""Two targeted cleanup-error checks on owned short children; not MCP/A2."""
import asyncio
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys
import _winapi
import win32api
import win32con
import win32event
import win32process

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_windows_job_owner import JobLimits
from a2_windows_pipe_owner import PipeLimits, PipeOwnerError, WindowsJobPipeOwner


class Memory(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint32), ('load', ctypes.c_uint32)] + [
        (name, ctypes.c_uint64) for name in ('total', 'available', 'page_total',
        'page_available', 'virtual_total', 'virtual_available', 'extended')]


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def observe():
    memory = Memory(); memory.length = ctypes.sizeof(memory)
    require(ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)), 'memory observation failed')
    minimum = 3 * 1024 ** 3
    return {'available_bytes': str(memory.available), 'minimum_bytes': str(minimum),
            'admitted': memory.available >= minimum}


async def main():
    first = observe()
    admissions = [first]
    admission_path = Path(__file__).parent / 'admission-cause.json'
    admission_path.write_text(json.dumps(admissions, indent=2) + '\n', encoding='utf8')
    if not first['admitted']:
        print(json.dumps({'status': 'blocked', 'child_started': False}))
        return 2
    executable = Path(sys.executable).resolve(strict=True)
    sha = hashlib.sha256(executable.read_bytes()).hexdigest()
    allowed, _ = win32process.GetProcessAffinityMask(win32api.GetCurrentProcess())
    job = JobLimits(memory_commit_bytes=512 * 1024 ** 2, affinity_mask=allowed & -allowed,
                    active_processes=8, lifetime_seconds=15, cleanup_seconds=5)
    bounds = PipeLimits(max_write_bytes=64, max_input_bytes=128, max_read_bytes=64,
                        max_output_bytes=128, max_stderr_bytes=64, io_seconds=2)
    env = {k: v for k, v in os.environ.items() if k.upper() in
           {'SYSTEMROOT', 'WINDIR', 'PATH', 'TEMP', 'TMP', 'COMSPEC', 'PATHEXT'}}

    async def owner():
        current = observe(); admissions.append(current)
        admission_path.write_text(json.dumps(admissions, indent=2) + '\n', encoding='utf8')
        require(current['admitted'], 'memory below original admission before launch')
        return await WindowsJobPipeOwner.launch(executable, ['-B', '-c', 'import time;time.sleep(10)'],
            cwd=ROOT, env=env, expected_sha256=sha, job_limits=job, pipe_limits=bounds)

    def duplicate_process(handle):
        current = win32api.GetCurrentProcess()
        return win32api.DuplicateHandle(current, handle, current, 0, False,
                                        win32con.DUPLICATE_SAME_ACCESS)

    checks = []
    instance = await owner()
    duplicate = duplicate_process(instance._process)
    first_error = OSError(5, 'first synthetic close error')
    class First:
        def close(self):
            raise first_error
        def abort(self):
            raise RuntimeError('secondary synthetic abort error')
    class Second:
        def close(self):
            raise ValueError('third synthetic close error')
    instance._transports[0:0] = [First(), Second()]
    try:
        try:
            await instance.close()
            raise RuntimeError('close unexpectedly succeeded')
        except PipeOwnerError as error:
            require(error.__cause__ is first_error, 'first exception object was not preserved')
            require(error.__cause__.errno == 5, 'first exception errno was not preserved')
            require('secondary synthetic abort error' in str(error), 'secondary abort error omitted')
            require('third synthetic close error' in str(error), 'third close error omitted')
            require(instance._state == 'closed' and instance._job is None and instance._process is None,
                    'remaining owned handles were not processed')
            require(not instance.tree_empty_verified, 'failed cleanup was reported as fully confirmed')
            require(win32event.WaitForSingleObject(duplicate, 0) == win32event.WAIT_OBJECT_0,
                    'owned child exit was not observed')
            checks.append('first_exception_identity_and_secondary_errors')
    finally:
        duplicate.Close()
        if instance._state != 'closed':
            instance._transports = [t for t in instance._transports if not isinstance(t, (First, Second))]
            await instance.close()

    instance = await owner()
    duplicate = duplicate_process(instance._process)
    cancelled = asyncio.CancelledError('synthetic transport interruption')
    class Interrupted:
        def close(self):
            raise cancelled
    instance._transports.insert(0, Interrupted())
    try:
        try:
            await instance.close()
            raise RuntimeError('cancellation was swallowed')
        except asyncio.CancelledError:
            require(instance._state == 'closed' and instance._job is None and instance._process is None,
                    'owned handles were not processed after cancellation')
            require(not instance.tree_empty_verified, 'cancelled cleanup was reported as confirmed')
            require(win32event.WaitForSingleObject(duplicate, 0) == win32event.WAIT_OBJECT_0,
                    'owned child exit was not observed after cancellation')
            checks.append('cancellation_type_and_remaining_cleanup')
    finally:
        duplicate.Close()
        if instance._state != 'closed':
            instance._transports = [t for t in instance._transports if not isinstance(t, Interrupted)]
            await instance.close()

    print(json.dumps({'status': 'passed', 'checks': checks, 'executable_sha256': sha,
                      'scope': 'owned hidden synthetic children only; no MCP, snapshot or A2 qualification'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))
