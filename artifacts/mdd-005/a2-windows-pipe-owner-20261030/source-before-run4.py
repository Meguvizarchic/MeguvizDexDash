"""Bounded Windows pipes for one newly created, Job-owned child.

This is a development transport primitive, not an MCP client or a result
certificate. EOF, child exit and successful cleanup never imply query success.
The caller must close it and separately establish protocol and snapshot proofs.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time

if __package__:
    from .a2_windows_job_owner import JobLimits, JobOwnerError, _observed_file_identity
else:
    from a2_windows_job_owner import JobLimits, JobOwnerError, _observed_file_identity


class PipeOwnerError(RuntimeError):
    """The bounded owned transport failed; no complete result is implied."""


@dataclass(frozen=True)
class PipeLimits:
    max_write_bytes: int
    max_input_bytes: int
    max_read_bytes: int
    max_output_bytes: int
    max_stderr_bytes: int
    io_seconds: float

    def validate(self):
        values = (self.max_write_bytes, self.max_input_bytes, self.max_read_bytes,
                  self.max_output_bytes, self.max_stderr_bytes)
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError('positive explicit pipe byte limits are required')
        if self.max_write_bytes > self.max_input_bytes or self.max_read_bytes > self.max_output_bytes:
            raise ValueError('per-call pipe bounds exceed cumulative limits')
        if self.max_read_bytes > 1024 * 1024 or self.max_write_bytes > 1024 * 1024:
            raise ValueError('per-call pipe bounds exceed one MiB')
        if (not isinstance(self.io_seconds, (int, float)) or isinstance(self.io_seconds, bool)
                or not math.isfinite(self.io_seconds) or self.io_seconds <= 0):
            raise ValueError('a finite positive pipe deadline is required')


class WindowsJobPipeOwner:
    """Exclusive async pipes and lifetime for exactly one owned Job and child.

    The child receives only its three explicit stdio handles. It is created
    hidden and suspended, then assigned and verified before resume. This API
    does not attach to a PID or make claims about decoded protocol messages.
    """

    @classmethod
    async def launch(cls, executable, arguments, *, cwd, env, expected_sha256,
                     job_limits: JobLimits, pipe_limits: PipeLimits):
        if os.name != 'nt':
            raise PipeOwnerError('Windows pipe owner is unavailable on this platform')
        if not isinstance(job_limits, JobLimits) or not isinstance(pipe_limits, PipeLimits):
            raise ValueError('explicit Job and pipe limits are required')
        job_limits.validate()
        pipe_limits.validate()
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
            import _winapi
            import win32api
            import win32con
            import win32event
            import win32job
            import win32process
            from asyncio.windows_utils import PipeHandle, pipe
        except ImportError as error:
            raise PipeOwnerError('baseline Windows Job or pipe support is unavailable') from error
        loop = asyncio.get_running_loop()
        observed, identity = _observed_file_identity(executable)
        if observed != expected_sha256:
            raise PipeOwnerError('executable SHA-256 differs from pinned identity')
        allowed, _ = win32process.GetProcessAffinityMask(win32api.GetCurrentProcess())
        if job_limits.affinity_mask & allowed != job_limits.affinity_mask:
            raise ValueError('requested affinity is outside the current process mask')

        self = cls.__new__(cls)
        self._winapi, self._job_api, self._event = _winapi, win32job, win32event
        self._loop, self._limits, self._job_limits = loop, pipe_limits, job_limits
        self._job = self._process = self._thread = None
        self._assigned = False
        self._transports = []
        self._state = 'creating'
        self._failure = None
        self._stderr_task = None
        self._watchdog_task = None
        self._read_lock, self._write_lock = asyncio.Lock(), asyncio.Lock()
        self._cleanup_lock = asyncio.Lock()
        self._input_bytes = self._output_bytes = self._stderr_bytes = 0
        self._deadline = time.monotonic() + job_limits.lifetime_seconds
        self.executable_sha256 = observed
        self.tree_empty_verified = False
        handles = set()

        def close_raw(handle):
            if handle in handles:
                _winapi.CloseHandle(handle)
                handles.remove(handle)

        try:
            self._job = win32job.CreateJobObject(None, '')
            extended = win32job.QueryInformationJobObject(
                self._job, win32job.JobObjectExtendedLimitInformation)
            basic = extended['BasicLimitInformation']
            basic['LimitFlags'] = (win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                                   | win32job.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
                                   | win32job.JOB_OBJECT_LIMIT_JOB_MEMORY
                                   | win32job.JOB_OBJECT_LIMIT_AFFINITY
                                   | win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
            basic['Affinity'] = job_limits.affinity_mask
            basic['ActiveProcessLimit'] = job_limits.active_processes
            extended['JobMemoryLimit'] = job_limits.memory_commit_bytes
            win32job.SetInformationJobObject(self._job, win32job.JobObjectExtendedLimitInformation, extended)
            confirmed = win32job.QueryInformationJobObject(
                self._job, win32job.JobObjectExtendedLimitInformation)
            if (confirmed['BasicLimitInformation']['LimitFlags'] & basic['LimitFlags'] != basic['LimitFlags']
                    or confirmed['BasicLimitInformation']['Affinity'] != job_limits.affinity_mask
                    or confirmed['BasicLimitInformation']['ActiveProcessLimit'] != job_limits.active_processes
                    or confirmed['JobMemoryLimit'] != job_limits.memory_commit_bytes):
                raise PipeOwnerError('Job limits were not confirmed')
            stdin_read, stdin_write = pipe(overlapped=(False, True), duplex=True)
            handles.update((stdin_read, stdin_write))
            stdout_read, stdout_write = pipe(overlapped=(True, False))
            handles.update((stdout_read, stdout_write))
            stderr_read, stderr_write = pipe(overlapped=(True, False))
            handles.update((stderr_read, stderr_write))
            child_handles = [stdin_read, stdout_write, stderr_write]
            for handle in child_handles:
                os.set_handle_inheritable(handle, True)
            for handle in (stdin_write, stdout_read, stderr_read):
                os.set_handle_inheritable(handle, False)
            startup = subprocess.STARTUPINFO()
            startup.dwFlags = win32con.STARTF_USESTDHANDLES | win32con.STARTF_USESHOWWINDOW
            startup.wShowWindow = win32con.SW_HIDE
            startup.hStdInput, startup.hStdOutput, startup.hStdError = child_handles
            startup.lpAttributeList['handle_list'] = child_handles
            flags = (win32con.CREATE_SUSPENDED | win32con.CREATE_NO_WINDOW
                     | win32con.CREATE_UNICODE_ENVIRONMENT)
            command = subprocess.list2cmdline([str(executable), *arguments])
            self._process, self._thread, _, _ = _winapi.CreateProcess(
                str(executable), command, None, None, True, flags, dict(env), str(cwd), startup)
            win32job.AssignProcessToJobObject(self._job, self._process)
            if not win32job.IsProcessInJob(self._process, self._job):
                raise PipeOwnerError('created child is not in its owned Job')
            self._assigned = True
            observed_after, identity_after = _observed_file_identity(executable)
            if observed_after != observed or identity_after != identity:
                raise PipeOwnerError('executable identity changed before child resume')
            for handle in child_handles:
                close_raw(handle)

            async def connect_reader(handle):
                reader = asyncio.StreamReader(limit=pipe_limits.max_read_bytes)
                protocol = asyncio.StreamReaderProtocol(reader)
                wrapper = PipeHandle(handle)
                handles.remove(handle)
                try:
                    transport, _ = await loop.connect_read_pipe(lambda: protocol, wrapper)
                except BaseException:
                    wrapper.close()
                    raise
                self._transports.append(transport)
                return reader

            self._stdout = await connect_reader(stdout_read)
            self._stderr = await connect_reader(stderr_read)
            wrapper = PipeHandle(stdin_write)
            handles.remove(stdin_write)
            protocol = asyncio.streams.FlowControlMixin(loop=loop)
            try:
                transport, _ = await loop.connect_write_pipe(lambda: protocol, wrapper)
            except BaseException:
                wrapper.close()
                raise
            self._transports.append(transport)
            self._stdin = asyncio.StreamWriter(transport, protocol, None, loop)
            win32process.ResumeThread(self._thread)
            _winapi.CloseHandle(self._thread)
            self._thread = None
            self._state = 'running'
            self._stderr_task = loop.create_task(self._drain_stderr())
            self._watchdog_task = loop.create_task(self._watchdog())
            return self
        except BaseException as error:
            try:
                await self._cleanup('launch_failed')
            except BaseException as cleanup_error:
                error.add_note('owned transport cleanup failed: ' + str(cleanup_error))
            raise
        finally:
            active_error = sys.exception()
            close_errors = []
            for handle in tuple(handles):
                try:
                    close_raw(handle)
                except Exception as close_error:
                    close_errors.append(str(close_error))
            if close_errors:
                if active_error is not None:
                    active_error.add_note('owned pipe handle release failed: ' + '; '.join(close_errors))
                else:
                    error = PipeOwnerError('owned pipe handle release failed: ' + '; '.join(close_errors))
                    try:
                        await self._cleanup('launch_pipe_close_failed')
                    except BaseException as cleanup_error:
                        error.add_note('owned transport cleanup failed: ' + str(cleanup_error))
                    raise error

    def _timeout(self):
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('owned pipe lifetime expired')
        return min(float(self._limits.io_seconds), remaining)

    def _check(self):
        if self._state != 'running' or self._failure is not None:
            raise PipeOwnerError('owned pipe is not running') from self._failure

    async def _fail(self, error):
        if self._failure is None:
            self._failure = error
        try:
            await self._cleanup('io_failed')
        except BaseException as cleanup_error:
            error.add_note('owned transport cleanup failed: ' + str(cleanup_error))

    async def write(self, data: bytes):
        async with self._write_lock:
            self._check()
            if not isinstance(data, bytes) or not data or len(data) > self._limits.max_write_bytes:
                raise ValueError('nonempty bytes within the per-write bound are required')
            if self._input_bytes + len(data) > self._limits.max_input_bytes:
                error = PipeOwnerError('cumulative stdin byte budget exceeded')
                await self._fail(error)
                raise error
            self._input_bytes += len(data)
            try:
                self._stdin.write(data)
                await asyncio.wait_for(self._stdin.drain(), timeout=self._timeout())
                self._check()
            except BaseException as error:
                await self._fail(error)
                raise

    async def read(self, maximum: int):
        async with self._read_lock:
            self._check()
            if type(maximum) is not int or not 0 < maximum <= self._limits.max_read_bytes:
                raise ValueError('read bound exceeds per-read budget')
            try:
                data = await asyncio.wait_for(self._stdout.read(maximum), timeout=self._timeout())
                self._check()
                if not data:
                    raise PipeOwnerError('stdout EOF is not a complete protocol result')
                self._output_bytes += len(data)
                if self._output_bytes > self._limits.max_output_bytes:
                    raise PipeOwnerError('cumulative stdout byte budget exceeded')
                return data
            except BaseException as error:
                await self._fail(error)
                raise

    async def _drain_stderr(self):
        try:
            while self._state == 'running':
                data = await self._stderr.read(min(4096, self._limits.max_read_bytes))
                if not data:
                    return
                self._stderr_bytes += len(data)
                if self._stderr_bytes > self._limits.max_stderr_bytes:
                    raise PipeOwnerError('cumulative stderr byte budget exceeded')
        except asyncio.CancelledError:
            raise
        except BaseException as error:
            await self._fail(error)

    async def _watchdog(self):
        try:
            await asyncio.sleep(max(0, self._deadline - time.monotonic()))
            if self._state == 'running':
                await self._fail(TimeoutError('owned pipe lifetime expired'))
        except asyncio.CancelledError:
            raise

    async def _cleanup(self, reason):
        async with self._cleanup_lock:
            await self._cleanup_locked(reason)

    async def _cleanup_locked(self, reason):
        if self._state == 'closed':
            return
        self._state = 'terminating'
        errors = []
        job_termination_accepted = False
        if self._job is not None:
            try:
                self._job_api.TerminateJobObject(self._job, 125)
                job_termination_accepted = True
            except Exception as error:
                errors.append('owned Job termination: ' + str(error))
        if self._process is not None:
            try:
                if (not (self._assigned and job_termination_accepted)
                        and self._winapi.WaitForSingleObject(self._process, 0) == self._event.WAIT_TIMEOUT):
                    try:
                        self._winapi.TerminateProcess(self._process, 125)
                    except Exception as error:
                        errors.append('owned child direct termination: ' + str(error))
                deadline = time.monotonic() + self._job_limits.cleanup_seconds
                while self._winapi.WaitForSingleObject(self._process, 0) != self._event.WAIT_OBJECT_0:
                    if time.monotonic() >= deadline:
                        raise PipeOwnerError('owned child exit was not confirmed')
                    await asyncio.sleep(.01)
            except BaseException as error:
                errors.append('owned child wait: ' + str(error))
        if self._job is not None:
            try:
                deadline = time.monotonic() + self._job_limits.cleanup_seconds
                while self._job_api.QueryInformationJobObject(
                        self._job, self._job_api.JobObjectBasicAccountingInformation)['ActiveProcesses']:
                    if time.monotonic() >= deadline:
                        raise PipeOwnerError('owned Job did not become empty')
                    await asyncio.sleep(.01)
                self.tree_empty_verified = True
            except BaseException as error:
                errors.append('owned Job wait: ' + str(error))
        for transport in self._transports:
            transport.close()
        task = self._stderr_task
        if task is not None and task is not asyncio.current_task():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as error:
                errors.append('stderr task: ' + str(error))
        watchdog = self._watchdog_task
        if watchdog is not None and watchdog is not asyncio.current_task():
            watchdog.cancel()
            try:
                await watchdog
            except asyncio.CancelledError:
                pass
            except Exception as error:
                errors.append('watchdog task: ' + str(error))
        for name in ('_thread', '_process'):
            handle = getattr(self, name)
            if handle is not None:
                try:
                    self._winapi.CloseHandle(handle)
                except Exception as error:
                    errors.append(name + ': ' + str(error))
                setattr(self, name, None)
        if self._job is not None:
            try:
                self._job.Close()
            except Exception as error:
                errors.append('owned Job handle: ' + str(error))
            self._job = None
        self._state = 'closed'
        if errors:
            raise PipeOwnerError(reason + ': ' + '; '.join(errors))

    async def close(self):
        """Stop the owned Job; cleanup is not a protocol success receipt."""
        task = self._loop.create_task(self._cleanup('owner_closed'))
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as error:
            try:
                await asyncio.shield(task)
            except BaseException as cleanup_error:
                error.add_note('owned transport cleanup was not confirmed: ' + str(cleanup_error))
            raise

    async def __aenter__(self):
        self._check()
        return self

    async def __aexit__(self, error_type, error, traceback):
        try:
            await self.close()
        except BaseException as cleanup_error:
            if error is not None:
                error.add_note('owned transport cleanup failed: ' + str(cleanup_error))
                return False
            raise
        return False
