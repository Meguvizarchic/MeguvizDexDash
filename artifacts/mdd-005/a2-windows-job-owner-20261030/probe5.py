"""Short, self-owned Windows processes only; not MCP/A2/performance qualification."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import win32api
import win32con
import win32event
import win32job
import win32process

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_windows_job_owner import JobLimits, JobOwnerError, WindowsJobOwner


class Memory(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint32), ('load', ctypes.c_uint32)] + [
        (name, ctypes.c_uint64) for name in ('total', 'available', 'page_total',
        'page_available', 'virtual_total', 'virtual_available', 'extended')]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    memory = Memory(); memory.length = ctypes.sizeof(memory)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):
        raise RuntimeError('cannot observe free memory')
    minimum = 3 * 1024 ** 3
    admission = {'available_bytes': str(memory.available), 'minimum_bytes': str(minimum),
                 'status': 'admitted' if memory.available >= minimum else 'blocked',
                 'scope': 'development-only self-owned short processes; not performance'}
    (HERE / 'admission-run5.json').write_text(json.dumps(admission, indent=2) + '\n', encoding='utf8')
    if memory.available < minimum:
        print(json.dumps({'status': 'blocked', 'child_started': False}))
        return 2
    executable = Path(sys.executable).resolve(strict=True)
    sha = hashlib.sha256(executable.read_bytes()).hexdigest()
    allowed, _ = win32process.GetProcessAffinityMask(win32api.GetCurrentProcess())
    mask = allowed & -allowed
    limits = JobLimits(512 * 1024 * 1024, mask, 8, 10.0, 5.0)
    checks = []

    def wait(owner):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            terminal = owner.poll()
            if terminal is not None:
                return terminal
            time.sleep(0.01)
        raise RuntimeError('owned child failed to reach terminal')

    captured = []
    original = win32process.CreateProcess
    def observed(*args):
        captured.append((args[4], args[5]))
        return original(*args)
    win32process.CreateProcess = observed
    try:
        with WindowsJobOwner(executable, ['-c', 'import sys;sys.exit(0)'],
                             cwd=ROOT, env=dict(os.environ), expected_sha256=sha,
                             limits=limits) as owner:
            terminal = wait(owner)
            require(terminal.reason == 'child_exit' and terminal.exit_code == 0
                    and terminal.tree_empty_verified, 'normal child did not finish')
            require(captured and captured[0][0] is False
                    and captured[0][1] & win32con.CREATE_SUSPENDED
                    and captured[0][1] & win32con.CREATE_NO_WINDOW,
                    'spawn inherited handles or omitted required hidden/suspended flags')
        require(owner.terminal == terminal, 'verified terminal lost after close')
        checks.append('normal_exit_hidden_no_inheritance')
    finally:
        win32process.CreateProcess = original

    original_in_job = win32job.IsProcessInJob
    original_query = win32job.QueryInformationJobObject
    original_wait = win32event.WaitForSingleObject
    original_terminate = win32api.TerminateProcess
    observed_cleanup = {'membership_was_true': False, 'active_zero': False, 'child_signalled': False}
    direct_termination_errors = []
    injected_error_notes = []
    def injected_membership(process, job):
        observed_cleanup['membership_was_true'] = bool(original_in_job(process, job))
        return False
    def observed_query(job, info):
        result = original_query(job, info)
        if info == win32job.JobObjectBasicAccountingInformation and result['ActiveProcesses'] == 0:
            observed_cleanup['active_zero'] = True
        return result
    def observed_wait(handle, timeout):
        result = original_wait(handle, timeout)
        if timeout > 0 and result == win32event.WAIT_OBJECT_0:
            observed_cleanup['child_signalled'] = True
        return result
    def observed_terminate(handle, exit_code):
        try:
            return original_terminate(handle, exit_code)
        except Exception as error:
            direct_termination_errors.append(str(error))
            raise
    win32job.IsProcessInJob = injected_membership
    win32job.QueryInformationJobObject = observed_query
    win32event.WaitForSingleObject = observed_wait
    win32api.TerminateProcess = observed_terminate
    try:
        try:
            WindowsJobOwner(executable, ['-c', 'import time;time.sleep(30)'],
                            cwd=ROOT, env=dict(os.environ), expected_sha256=sha, limits=limits)
        except JobOwnerError as error:
            require('not in its Job' in str(error), 'membership error was replaced')
            injected_error_notes.extend(getattr(error, '__notes__', []))
            require(all(observed_cleanup.values()), 'created child or Job cleanup was not observed')
            if direct_termination_errors:
                require(any('direct termination returned' in note for note in getattr(error, '__notes__', [])),
                        'direct termination error was hidden')
                require(any('independently confirmed' in note for note in getattr(error, '__notes__', [])),
                        'subsequent confirmed exit was not distinguished')
            checks.append('creation_failure_reaps_owned_child_and_job')
        else:
            raise RuntimeError('injected membership failure did not fail')
    finally:
        win32job.IsProcessInJob = original_in_job
        win32job.QueryInformationJobObject = original_query
        win32event.WaitForSingleObject = original_wait
        win32api.TerminateProcess = original_terminate

    with WindowsJobOwner(executable, ['-c', 'import time;time.sleep(30)'],
                         cwd=ROOT, env=dict(os.environ), expected_sha256=sha,
                         limits=limits) as owner:
        terminal = owner.abort('synthetic_cancel')
        require(terminal.reason == 'synthetic_cancel' and terminal.tree_empty_verified,
                'owned cancellation incomplete')
        require(owner.abort('ignored') == terminal, 'terminal was overwritten')
    try:
        owner.poll()
    except JobOwnerError:
        checks.append('owned_cancel_and_no_reuse')
    else:
        raise RuntimeError('closed owner reused')

    short = JobLimits(512 * 1024 * 1024, mask, 8, 0.05, 5.0)
    with WindowsJobOwner(executable, ['-c', 'import time;time.sleep(30)'],
                         cwd=ROOT, env=dict(os.environ), expected_sha256=sha,
                         limits=short) as owner:
        terminal = wait(owner)
        require(terminal.reason == 'deadline' and terminal.tree_empty_verified,
                'deadline did not terminate owned Job')
    checks.append('deadline_tree_empty')

    descendant = ('import subprocess,sys,time;'
                  'subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"],'
                  'stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,'
                  'creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0));time.sleep(.3)')
    with WindowsJobOwner(executable, ['-c', descendant], cwd=ROOT, env=dict(os.environ),
                         expected_sha256=sha, limits=limits) as owner:
        terminal = wait(owner)
        require(terminal.reason == 'child_exited_with_descendants'
                and terminal.tree_empty_verified and terminal.process_count >= 3,
                'owned descendant was not observed and terminated')
    checks.append('root_exit_with_descendant')

    try:
        WindowsJobOwner(executable, ['-c', 'pass'], cwd=ROOT, env=dict(os.environ),
                        expected_sha256='0' * 64, limits=limits)
    except JobOwnerError:
        checks.append('wrong_binary_rejected_before_spawn')
    else:
        raise RuntimeError('wrong binary identity accepted')
    print(json.dumps({'status': 'passed', 'checks': checks, 'exe_sha256': sha,
                      'creation_failure_observation': {'result': 'expected_membership_failure',
                          'direct_termination_errors': direct_termination_errors,
                          'original_error_notes': injected_error_notes,
                          'observed': observed_cleanup},
                      'owner_source_sha256': hashlib.sha256(
                          (ROOT / 'benchmarks/a2_windows_job_owner.py').read_bytes()).hexdigest(),
                      'scope': 'self-owned hidden short processes; no MCP/snapshot/A2/performance qualification'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
