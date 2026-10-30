"""Synchronous HostLab consumer bridge for an externally owned compact dataset.

This candidate neither launches an engine nor establishes snapshot/order proofs.
The caller owns the already-running MCP event loop and process. Each query is
fully materialized before its first synchronous row is returned; that changes
producer/consumer overlap and is not a qualified performance comparison.
"""
from __future__ import annotations

import asyncio
from concurrent.futures import CancelledError, TimeoutError as FutureTimeout
from pathlib import Path
import threading
import time
from typing import Callable


class HostlabSessionError(RuntimeError):
    """The adapter session cannot safely deliver a complete HostLab result."""


class HostlabCompactSession:
    """One thread-confined HostLab session over an externally owned async client.

    The adapter must already be bound to a real dataset and require source,
    snapshot and total-order checks. ``verify_inventory`` must compare the
    actual physical source inventory against returned logical files using the
    pinned HostLab rules. ``close_dataset`` is an async callable returning True
    only after the producer confirms close. ``abort_transport`` is a sync
    callable returning True only after the owner confirms process-tree shutdown.
    Neither callback may fabricate a success or operate on unrelated processes.
    """

    def __init__(self, apk, adapter, loop: asyncio.AbstractEventLoop, *,
                 verify_inventory: Callable, close_dataset: Callable,
                 abort_transport: Callable):
        self.apk = Path(apk).resolve(strict=True)
        if not self.apk.is_file():
            raise ValueError("HostLab input is not a file")
        if not isinstance(loop, asyncio.AbstractEventLoop):
            raise ValueError("a running owner event loop is required")
        if not all(callable(fn) for fn in (verify_inventory, close_dataset, abort_transport)):
            raise ValueError("inventory, close and abort callbacks are required")
        if not all(callable(getattr(adapter, name, None)) for name in ("rows", "remaining_seconds", "verify_binding")):
            raise ValueError("a bound compact rows adapter is required")
        self._adapter, self._loop = adapter, loop
        self._verify_inventory, self._close_dataset, self._abort_transport = (
            verify_inventory, close_dataset, abort_transport)
        self._thread = threading.get_ident()
        self._entered = False
        self._closed = False
        self._failed = False
        self._uncertain_transport = False
        self._active = 0
        self.files = {}
        self.queries = 0

    def _check_thread(self, *, allow_stopped=False):
        if threading.get_ident() != self._thread:
            raise HostlabSessionError("HostLab session is confined to its creating thread")
        try:
            caller_loop = asyncio.get_running_loop()
        except RuntimeError:
            caller_loop = None
        if caller_loop is self._loop:
            raise HostlabSessionError("cannot synchronously block the MCP event-loop thread")
        if not allow_stopped and not self._loop.is_running():
            raise HostlabSessionError("MCP owner event loop is not running")

    def _wait(self, coroutine):
        try:
            self._check_thread()
            remaining = self._adapter.remaining_seconds()
            if remaining <= 0:
                raise TimeoutError("HostLab compact session deadline exhausted")
            future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
        except BaseException:
            coroutine.close()
            self._failed = True
            raise
        try:
            return future.result(timeout=remaining)
        except (FutureTimeout, CancelledError):
            # Do not issue another query/close into a dataset whose operation
            # may still be running. The owner must terminate its transport.
            future.cancel()
            self._failed = True
            self._uncertain_transport = True
            raise
        except BaseException:
            self._failed = True
            raise

    def __enter__(self):
        self._check_thread()
        if self._entered or self._closed:
            raise HostlabSessionError("HostLab session cannot be entered twice")
        self._entered = True
        started = time.monotonic()
        try:
            records = list(self.rows("SELECT file_id,entry_name FROM dex_files ORDER BY file_id"))
            files = {}
            for record in records:
                try:
                    file_id, entry_name = int(record["file_id"]), record["entry_name"]
                except (KeyError, TypeError, ValueError) as exc:
                    raise HostlabSessionError("invalid DEX inventory row") from exc
                if file_id < 0 or file_id in files or not isinstance(entry_name, str) or not entry_name:
                    raise HostlabSessionError("ambiguous DEX inventory identity")
                files[file_id] = entry_name
            if not files:
                raise HostlabSessionError("producer returned no DEX inventory")
            self._verify_inventory(self.apk, files)
            self._adapter.verify_binding()
            self.files = files
            self.opened = {"transport": "mcp_compact_candidate",
                           "session_adaptation_ms": (time.monotonic() - started) * 1000,
                           "producer_prepare_included": False,
                           "files": dict(files), "qualified": False}
            return self
        except BaseException as exc:
            self._failed = True
            try:
                self._finish()
            except BaseException as close_error:
                exc.add_note("compact session cleanup failed: " + str(close_error))
            raise

    def rows(self, sql, *, page_size=1000, max_rows=500000, max_bytes=128 * 1024 * 1024):
        self._check_thread()
        if not self._entered or self._closed or self._failed:
            raise HostlabSessionError("HostLab compact session is not usable")
        self._active += 1
        exhausted = False
        try:
            records = self._wait(self._adapter.rows(sql, page_size=page_size,
                                                    max_rows=max_rows, max_bytes=max_bytes))
            for record in records:
                if self._closed or self._failed:
                    raise HostlabSessionError("compact session closed before row consumption")
                yield record
            exhausted = True
            self.queries += 1
        finally:
            self._active -= 1
            if not exhausted:
                self._failed = True

    def all(self, sql, **bounds):
        return list(self.rows(sql, **bounds))

    async def _close(self):
        if await self._close_dataset() is not True:
            raise HostlabSessionError("producer did not confirm dataset close")

    def _finish(self):
        if self._closed:
            return
        self._closed = True
        if self._uncertain_transport:
            if self._abort_transport() is not True:
                raise HostlabSessionError("owner did not confirm uncertain transport shutdown")
            return
        try:
            self._adapter.verify_binding()
            self._wait(self._close())
        except BaseException as exc:
            self._failed = True
            try:
                stopped = self._abort_transport()
            except BaseException as abort_error:
                exc.add_note("transport shutdown raised: " + str(abort_error))
            else:
                if stopped is not True:
                    exc.add_note("owner did not confirm transport shutdown")
            raise

    def __exit__(self, error_type, error, traceback):
        self._check_thread(allow_stopped=True)
        if not self._loop.is_running():
            self._failed = True
            self._uncertain_transport = True
        incomplete = self._failed or self._active != 0
        try:
            self._finish()
        except BaseException as exc:
            if error is not None:
                error.add_note("compact session cleanup failed: " + str(exc))
                return False
            raise
        if incomplete and error is None:
            raise HostlabSessionError("unconsumed or failed compact session cannot complete")
        return False
