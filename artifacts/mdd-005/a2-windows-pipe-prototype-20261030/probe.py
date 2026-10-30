"""Self-owned suspended child and explicit handle-list probe; not MCP/A2."""
import ctypes
import hashlib
import json
import msvcrt
import os
from pathlib import Path
import subprocess
import sys
import time
import _winapi
import win32api
import win32con
import win32event
import win32job
import win32process

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


class Memory(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint32), ('load', ctypes.c_uint32)] + [
        (name, ctypes.c_uint64) for name in ('total', 'available', 'page_total',
        'page_available', 'virtual_total', 'virtual_available', 'extended')]


def require(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    memory = Memory(); memory.length = ctypes.sizeof(memory)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):
        raise RuntimeError('cannot observe free memory')
    minimum = 3 * 1024 ** 3
    (HERE / 'admission.json').write_text(json.dumps({'available_bytes': str(memory.available),
        'minimum_bytes': str(minimum), 'admitted': memory.available >= minimum,
        'scope': 'self-owned short process only; not performance'}, indent=2) + '\n', encoding='utf8')
    if memory.available < minimum:
        print(json.dumps({'status': 'blocked', 'child_started': False}))
        return 2
    executable = Path(sys.executable).resolve(strict=True)
    sha = hashlib.sha256(executable.read_bytes()).hexdigest()
    allowed, _ = win32process.GetProcessAffinityMask(win32api.GetCurrentProcess())
    job = process = thread = None
    handles = set()
    assigned = False

    def pipe():
        read, write = _winapi.CreatePipe(None, 0)
        handles.update([read, write])
        return read, write

    def close(handle):
        if handle in handles:
            _winapi.CloseHandle(handle)
            handles.remove(handle)

    try:
        job = win32job.CreateJobObject(None, '')
        extended = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
        basic = extended['BasicLimitInformation']
        basic['LimitFlags'] = (win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | win32job.JOB_OBJECT_LIMIT_JOB_MEMORY | win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | win32job.JOB_OBJECT_LIMIT_AFFINITY)
        basic['Affinity'], basic['ActiveProcessLimit'] = allowed & -allowed, 8
        extended['JobMemoryLimit'] = 512 * 1024 * 1024
        win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, extended)
        stdin_read, stdin_write = pipe()
        stdout_read, stdout_write = pipe()
        stderr_read, stderr_write = pipe()
        sentinel_read, sentinel_write = pipe()
        # This extra handle is deliberately inheritable but absent from the
        # explicit whitelist. The child must not be able to see it.
        child_handles = [stdin_read, stdout_write, stderr_write]
        for handle in [*child_handles, sentinel_write]:
            os.set_handle_inheritable(handle, True)
        for handle in [stdin_write, stdout_read, stderr_read, sentinel_read]:
            os.set_handle_inheritable(handle, False)
        startup = subprocess.STARTUPINFO()
        startup.dwFlags = win32con.STARTF_USESTDHANDLES | win32con.STARTF_USESHOWWINDOW
        startup.wShowWindow = win32con.SW_HIDE
        startup.hStdInput, startup.hStdOutput, startup.hStdError = child_handles
        startup.lpAttributeList['handle_list'] = child_handles
        child = ('import ctypes,json,sys;flags=ctypes.c_uint32();'
                 'seen=bool(ctypes.windll.kernel32.GetHandleInformation('
                 'ctypes.c_void_p(int(sys.argv[1])),ctypes.byref(flags)));'
                 'line=sys.stdin.buffer.readline();'
                 'sys.stdout.write(json.dumps({"line":line.decode("ascii"),"extra_handle":seen})+"\\n");'
                 'sys.stdout.flush()')
        command = subprocess.list2cmdline([str(executable), '-B', '-c', child, str(sentinel_write)])
        flags = win32con.CREATE_SUSPENDED | win32con.CREATE_NO_WINDOW | win32con.CREATE_UNICODE_ENVIRONMENT
        process, thread, _, _ = _winapi.CreateProcess(str(executable), command, None, None,
            True, flags, dict(os.environ), str(ROOT), startup)
        # No child code may execute until this owner confirms membership.
        win32job.AssignProcessToJobObject(job, process)
        require(win32job.IsProcessInJob(process, job), 'created child is not in owned Job')
        assigned = True
        for handle in child_handles:
            close(handle)
        win32process.ResumeThread(thread)
        _winapi.CloseHandle(thread); thread = None
        fd = msvcrt.open_osfhandle(stdin_write, 0); handles.remove(stdin_write)
        try:
            os.write(fd, b'hello\n')
        finally:
            os.close(fd)
        status = _winapi.WaitForSingleObject(process, 5000)
        require(status == win32event.WAIT_OBJECT_0, 'owned child timed out')
        code = _winapi.GetExitCodeProcess(process)
        require(code == 0, 'owned child exited unsuccessfully')
        end = time.monotonic() + 5
        while win32job.QueryInformationJobObject(job, win32job.JobObjectBasicAccountingInformation)['ActiveProcesses']:
            if time.monotonic() >= end:
                raise RuntimeError('owned Job did not reach zero active processes')
            time.sleep(.01)
        fd = msvcrt.open_osfhandle(stdout_read, 0); handles.remove(stdout_read)
        try:
            output = os.read(fd, 4096)
        finally:
            os.close(fd)
        response = json.loads(output.decode('utf8'))
        require(response == {'line': 'hello\n', 'extra_handle': False},
                'pipe response or handle whitelist differs')
        result = {'status': 'passed', 'assigned_before_resume': assigned,
            'tree_empty_verified': True, 'child_exit': code, 'extra_inheritable_handle_seen': False,
            'roundtrip': 'hello', 'executable_sha256': sha,
            'scope': 'self-owned hidden synthetic child only; no MCP, snapshot or A2 qualification'}
    finally:
        # Every handle here was created in this process. No PID lookup or
        # external process is ever targeted, including failure cleanup.
        original_error = sys.exception()
        cleanup_errors = []
        if job is not None:
            try:
                if win32job.QueryInformationJobObject(job, win32job.JobObjectBasicAccountingInformation)['ActiveProcesses']:
                    win32job.TerminateJobObject(job, 125)
            except Exception as error:
                cleanup_errors.append('owned Job termination: ' + str(error))
        if process is not None:
            try:
                if _winapi.WaitForSingleObject(process, 0) != win32event.WAIT_OBJECT_0:
                    try:
                        _winapi.TerminateProcess(process, 125)
                    except Exception as error:
                        cleanup_errors.append('owned process termination: ' + str(error))
                require(_winapi.WaitForSingleObject(process, 5000) == win32event.WAIT_OBJECT_0,
                        'owned child termination not confirmed')
            except Exception as error:
                cleanup_errors.append('owned child wait: ' + str(error))
            finally:
                try:
                    _winapi.CloseHandle(process)
                except Exception as error:
                    cleanup_errors.append('owned process handle: ' + str(error))
        if job is not None:
            try:
                end = time.monotonic() + 5
                while win32job.QueryInformationJobObject(job, win32job.JobObjectBasicAccountingInformation)['ActiveProcesses']:
                    if time.monotonic() >= end:
                        raise RuntimeError('owned Job termination not confirmed')
                    time.sleep(.01)
            except Exception as error:
                cleanup_errors.append('owned Job wait: ' + str(error))
        if thread is not None:
            try:
                _winapi.CloseHandle(thread)
            except Exception as error:
                cleanup_errors.append('owned thread handle: ' + str(error))
        for handle in list(handles):
            try:
                close(handle)
            except Exception as error:
                cleanup_errors.append('owned pipe handle: ' + str(error))
        if job is not None:
            try:
                job.Close()
            except Exception as error:
                cleanup_errors.append('owned Job handle: ' + str(error))
        if cleanup_errors:
            if original_error is not None:
                original_error.add_note('; '.join(cleanup_errors))
            else:
                raise RuntimeError('; '.join(cleanup_errors))
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
