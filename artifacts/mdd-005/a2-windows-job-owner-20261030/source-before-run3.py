"""Windows-only retained Job owner for a process created by this instance.

This development component does not provide MCP streams, an input snapshot,
or A2 qualification. It never attaches to or terminates a process by PID.
No inheritable handles or stdio channel are provided to the child.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import re
import subprocess
import time


class JobOwnerError(RuntimeError):
    """A self-owned Job could not be created or its termination confirmed."""


@dataclass(frozen=True)
class JobLimits:
    memory_commit_bytes: int
    affinity_mask: int
    active_processes: int
    lifetime_seconds: float
    cleanup_seconds: float = 15.0

    def validate(self):
        for value in (self.memory_commit_bytes, self.affinity_mask, self.active_processes):
            if type(value) is not int or value <= 0:
                raise ValueError('explicit positive integer Job limits are required')
        if self.active_processes > 0xffffffff:
            raise ValueError('active process limit is too large')
        for value in (self.lifetime_seconds, self.cleanup_seconds):
            if (not isinstance(value, (int, float)) or isinstance(value, bool)
                    or not math.isfinite(value) or value <= 0):
                raise ValueError('finite positive deadlines are required')
        if self.cleanup_seconds * 1000 >= 0xffffffff:
            raise ValueError('cleanup deadline exceeds the finite Windows wait range')


@dataclass(frozen=True)
class JobTerminal:
    reason: str
    exit_code: int
    tree_empty_verified: bool
    peak_job_commit_bytes: int
    process_count: int


def _observed_file_identity(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        before = os.fstat(source.fileno())
        while block := source.read(1024 * 1024):
            digest.update(block)
        after = os.fstat(source.fileno())
    current = path.stat()
    key = lambda stat: (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
    if key(before) != key(after) or key(after) != key(current):
        raise JobOwnerError('executable changed during identity observation')
    return digest.hexdigest(), key(current)


class WindowsJobOwner:
    """Retain handles only to this instance's unnamed Job and created child.

    The child is created suspended with a hidden window and without handle
    inheritance, assigned to the new Job, verified, then resumed. This class
    intentionally has no way to attach by PID and supplies no stdio transport.
    Callers must use a context manager or explicitly call close().
    """

    def __init__(self, executable, arguments, *, cwd, env, expected_sha256, limits: JobLimits):
        if os.name != 'nt':
            raise JobOwnerError('Windows Job owner is unavailable on this platform')
        if not isinstance(limits, JobLimits):
            raise ValueError('JobLimits are required')
        limits.validate()
        if not isinstance(expected_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256):
            raise ValueError('a pinned lowercase executable SHA-256 is required')
        executable = Path(executable).resolve(strict=True)
        cwd = Path(cwd).resolve(strict=True)
        if not executable.is_file() or not cwd.is_dir():
            raise ValueError('exact executable and working directory are required')
        if not isinstance(arguments, (list, tuple)) or any(
                not isinstance(arg, str) or '\0' in arg for arg in arguments):
            raise ValueError('arguments must be NUL-free strings')
        if not isinstance(env, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                            or '\0' in k or '\0' in v for k, v in env.items()):
            raise ValueError('explicit string environment is required')
        try:
            import win32api
            import win32con
            import win32event
            import win32job
            import win32process
        except ImportError as error:
            raise JobOwnerError('baseline pywin32 is unavailable') from error
        observed, identity = _observed_file_identity(executable)
        if observed != expected_sha256:
            raise JobOwnerError('executable SHA-256 differs from the pinned identity')
        allowed, _ = win32process.GetProcessAffinityMask(win32api.GetCurrentProcess())
        if limits.affinity_mask & allowed != limits.affinity_mask:
            raise ValueError('requested affinity is outside the current process mask')

        self._api, self._con, self._event = win32api, win32con, win32event
        self._job_api, self._process_api = win32job, win32process
        self._job = self._process = self._thread = None
        self._limits = limits
        self._state = 'creating'
        self._terminal = None
        self.executable_sha256 = observed
        self.executable_path = executable
        self._started = time.monotonic()
        try:
            # An unnamed handle avoids opening or terminating any external Job.
            self._job = win32job.CreateJobObject(None, '')
            extended = win32job.QueryInformationJobObject(
                self._job, win32job.JobObjectExtendedLimitInformation)
            basic = extended['BasicLimitInformation']
            basic['LimitFlags'] = (win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                                   | win32job.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
                                   | win32job.JOB_OBJECT_LIMIT_JOB_MEMORY
                                   | win32job.JOB_OBJECT_LIMIT_AFFINITY
                                   | win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
            basic['Affinity'] = limits.affinity_mask
            basic['ActiveProcessLimit'] = limits.active_processes
            extended['JobMemoryLimit'] = limits.memory_commit_bytes
            win32job.SetInformationJobObject(self._job, win32job.JobObjectExtendedLimitInformation, extended)
            confirmed = win32job.QueryInformationJobObject(
                self._job, win32job.JobObjectExtendedLimitInformation)
            if (confirmed['BasicLimitInformation']['LimitFlags'] & basic['LimitFlags'] != basic['LimitFlags']
                    or confirmed['BasicLimitInformation']['Affinity'] != limits.affinity_mask
                    or confirmed['BasicLimitInformation']['ActiveProcessLimit'] != limits.active_processes
                    or confirmed['JobMemoryLimit'] != limits.memory_commit_bytes):
                raise JobOwnerError('Job limits were not confirmed')
            startup = win32process.STARTUPINFO()
            startup.dwFlags = win32con.STARTF_USESHOWWINDOW
            startup.wShowWindow = win32con.SW_HIDE
            flags = (win32con.CREATE_SUSPENDED | win32con.CREATE_NO_WINDOW
                     | win32con.CREATE_UNICODE_ENVIRONMENT)
            command = subprocess.list2cmdline([str(executable), *arguments])
            self._process, self._thread, _, _ = win32process.CreateProcess(
                str(executable), command, None, None, False, flags, dict(env), str(cwd), startup)
            win32job.AssignProcessToJobObject(self._job, self._process)
            if not win32job.IsProcessInJob(self._process, self._job):
                raise JobOwnerError('created child is not in its Job')
            observed_after, identity_after = _observed_file_identity(executable)
            if observed_after != observed or identity_after != identity:
                raise JobOwnerError('executable identity changed before child resume')
            win32process.ResumeThread(self._thread)
            self._thread.Close()
            self._thread = None
            self._state = 'running'
        except BaseException as error:
            self._state = 'failed'
            # The process handle is owned by this instance; terminate the owned
            # Job first and use the owned process handle if assignment failed.
            if self._job is not None:
                try:
                    win32job.TerminateJobObject(self._job, 126)
                except Exception as cleanup_error:
                    error.add_note('owned Job termination failed: ' + str(cleanup_error))
            if self._process is not None:
                try:
                    if win32event.WaitForSingleObject(self._process, 0) == win32event.WAIT_TIMEOUT:
                        win32api.TerminateProcess(self._process, 126)
                    if win32event.WaitForSingleObject(
                            self._process, max(1, int(limits.cleanup_seconds * 1000))) != win32event.WAIT_OBJECT_0:
                        error.add_note('owned child exit was not confirmed before cleanup deadline')
                except Exception as cleanup_error:
                    error.add_note('owned child termination was not confirmed: ' + str(cleanup_error))
            if self._job is not None:
                try:
                    self._await_empty(limits.cleanup_seconds)
                except Exception as cleanup_error:
                    error.add_note('owned Job emptiness was not confirmed: ' + str(cleanup_error))
            try:
                self._release_handles()
            except Exception as cleanup_error:
                error.add_note('owned handle release failed: ' + str(cleanup_error))
            raise

    def _account(self):
        return self._job_api.QueryInformationJobObject(
            self._job, self._job_api.JobObjectBasicAccountingInformation)

    @property
    def terminal(self):
        """Return the verified terminal if one exists, including after close."""
        return self._terminal

    def _tree_empty(self):
        return self._account()['ActiveProcesses'] == 0

    def _await_empty(self, seconds):
        deadline = time.monotonic() + seconds
        while not self._tree_empty():
            if time.monotonic() >= deadline:
                raise JobOwnerError('owned Job did not become empty before cleanup deadline')
            time.sleep(0.01)

    def _finish(self, reason):
        self._await_empty(self._limits.cleanup_seconds)
        if self._event.WaitForSingleObject(
                self._process, max(1, int(self._limits.cleanup_seconds * 1000))) != self._event.WAIT_OBJECT_0:
            raise JobOwnerError('owned child has not exited after Job became empty')
        exit_code = self._process_api.GetExitCodeProcess(self._process)
        account = self._account()
        info = self._job_api.QueryInformationJobObject(
            self._job, self._job_api.JobObjectExtendedLimitInformation)
        self._terminal = JobTerminal(reason, exit_code, True,
                                     info['PeakJobMemoryUsed'], account['TotalProcesses'])
        self._state = 'terminal'
        return self._terminal

    def poll(self):
        """Return None while running, or a verified terminal; never ordinary EOF."""
        if self._state == 'terminal':
            return self._terminal
        if self._state != 'running':
            raise JobOwnerError('Job owner is not running')
        status = self._event.WaitForSingleObject(self._process, 0)
        if status == self._event.WAIT_OBJECT_0:
            # A root that exits while descendants remain cannot be treated as a
            # finished operation. Allow short Job-accounting teardown first.
            try:
                self._await_empty(min(1.0, self._limits.cleanup_seconds))
            except JobOwnerError:
                return self.abort('child_exited_with_descendants')
            return self._finish('child_exit')
        if status != self._event.WAIT_TIMEOUT:
            raise JobOwnerError('unexpected owned child wait status')
        if time.monotonic() - self._started >= self._limits.lifetime_seconds:
            return self.abort('deadline')
        return None

    def abort(self, reason='cancelled'):
        """Terminate only this owned Job and confirm both Job and child ended."""
        if self._state == 'terminal':
            return self._terminal
        if self._state != 'running':
            raise JobOwnerError('Job owner cannot be aborted in its current state')
        if not isinstance(reason, str) or not reason:
            raise ValueError('termination reason is required')
        self._state = 'terminating'
        try:
            if not self._tree_empty():
                self._job_api.TerminateJobObject(self._job, 125)
            return self._finish(reason)
        except BaseException:
            self._state = 'failed'
            raise

    def _release_handles(self):
        errors = []
        for name in ('_thread', '_process', '_job'):
            handle = getattr(self, name, None)
            if handle is not None:
                try:
                    handle.Close()
                except Exception as error:
                    errors.append(name + ': ' + str(error))
                finally:
                    setattr(self, name, None)
        if errors:
            raise JobOwnerError('owned handle release failed: ' + '; '.join(errors))

    def close(self):
        """Close own handles; an unconfirmed cleanup remains an error."""
        if self._state == 'closed':
            return
        failure = None
        try:
            if self._state == 'running':
                self.abort('owner_closed')
            if self._state != 'terminal':
                raise JobOwnerError('owned Job cleanup was not confirmed')
        except BaseException as error:
            failure = error
        try:
            self._release_handles()
        except BaseException as error:
            if failure is None:
                failure = error
            else:
                failure.add_note('owned handle release failed: ' + str(error))
        self._state = 'closed'
        if failure is not None:
            raise failure

    def __enter__(self):
        if self._state != 'running':
            raise JobOwnerError('Job owner is not running')
        return self

    def __exit__(self, error_type, error, traceback):
        try:
            self.close()
        except BaseException as cleanup_error:
            if error is not None:
                error.add_note('owned Job cleanup failed: ' + str(cleanup_error))
                return False
            raise
        return False
