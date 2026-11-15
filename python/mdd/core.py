"""Snapshots, sessions and queries as Python objects.

Every object owns exactly one ABI handle. It is released once, by `close()`, by leaving
a ``with`` block, or - as a last resort - by the garbage collector. Children keep their
parents alive, so the parent is never collected under a live child. A closed object
raises `Closed` instead of passing a dead handle to the library.
"""
from __future__ import annotations

import ctypes
import json
import weakref
from dataclasses import dataclass, field
from typing import Any, Iterator, Sequence

from . import _ffi, errors
from ._cells import decode_cell

DEFAULT_DEMAND_ROWS = 1000


def _release(lib: _ffi.Library, name: str, handle: int) -> None:
    lib.release(name, handle)


class _Owned:
    _what = "object"

    def __init__(self, lib: _ffi.Library, handle: int, release_name: str, parent: Any = None):
        self._lib = lib
        self._parent = parent  # keeps the parent alive for as long as this object lives
        self._handle = handle
        self._finalizer = weakref.finalize(self, _release, lib, release_name, handle)
        self._finalizer.atexit = False

    @property
    def closed(self) -> bool:
        return not self._finalizer.alive

    def _h(self) -> int:
        if self.closed:
            raise errors.Closed(f"the {self._what} is closed", code="SNAPSHOT_CLOSED", stage="sdk")
        return self._handle

    def _drop(self) -> None:
        self._finalizer()

    def __enter__(self):
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:  # overridden where the ABI has a close step
        self._drop()


@dataclass(frozen=True)
class Batch:
    """One delivered batch: `rows` are rows `first_row ..` of the result."""

    sequence: int
    first_row: int
    columns: tuple[str, ...]
    rows: tuple[tuple[Any, ...], ...]


@dataclass
class Result:
    """A query that ran to its end. `terminal` is the engine's own verdict."""

    columns: tuple[str, ...]
    rows: list[tuple[Any, ...]]
    terminal: dict[str, Any]

    @property
    def coverage(self) -> dict[str, Any]:
        return self.terminal["coverage"]

    @property
    def is_complete(self) -> bool:
        return is_complete(self.terminal)


def is_complete(terminal: dict[str, Any]) -> bool:
    """A complete result: ok, executed to the end, nothing cut or left, facts and
    input covered. Anything else - a page, a failure, a cancel - is not."""
    response = terminal.get("response") or {}
    coverage = terminal.get("coverage") or {}
    return (terminal.get("operation_status") == "ok"
            and (terminal.get("execution") or {}).get("complete") is True
            and not response.get("truncated") and not response.get("more_available")
            and response.get("next_cursor") is None
            and coverage.get("input") == "complete" and coverage.get("facts") == "complete")


class Snapshot(_Owned):
    _what = "snapshot"

    def __init__(self, lib: _ffi.Library, handle: int):
        super().__init__(lib, handle, "mdd_snapshot_release", None)
        self._manifest: dict[str, Any] | None = None

    @property
    def manifest(self) -> dict[str, Any]:
        if self._manifest is None:
            self._manifest = self._lib.json_view("mdd_snapshot_manifest_json_v1", self._h())
        return self._manifest

    def open_session(self, *, layers: Sequence[str] | None = None,
                     limits: dict[str, int] | None = None) -> "Session":
        request: dict[str, Any] = {}
        if layers is not None:
            request["layers"] = list(layers)
        if limits:
            request["limits"] = limits
        data = json.dumps(request).encode() if request else b""
        view, keep = _ffi.view_of(data)
        out = ctypes.c_uint64(0)
        self._lib.call("mdd_open_session_v1", self._h(), ctypes.byref(view), ctypes.byref(out))
        del keep
        return Session(self._lib, out.value, self)

    def close(self) -> None:
        """Stop new sessions on this snapshot and give up this reference. Sessions that
        already exist keep working."""
        if not self.closed:
            try:
                self._lib.call("mdd_snapshot_close_v1", self._handle)
            finally:
                self._drop()


class Session(_Owned):
    _what = "session"

    def __init__(self, lib: _ffi.Library, handle: int, snapshot: Snapshot):
        super().__init__(lib, handle, "mdd_session_release", snapshot)

    def prepare(self, sql: str) -> "Prepared":
        view, keep = _ffi.view_of(json.dumps({"kind": "sql", "sql": sql}).encode())
        out = ctypes.c_uint64(0)
        self._lib.call("mdd_prepare_query_v1", self._h(), ctypes.byref(view), ctypes.byref(out))
        del keep
        return Prepared(self._lib, out.value, self)

    def query(self, sql: str, *, limits: dict[str, int] | None = None) -> "Query":
        """Prepare and start in one step. Nothing runs until the first batch is asked for."""
        with self.prepare(sql) as prepared:
            return prepared.start(limits=limits)

    def execute(self, sql: str, *, demand_rows: int = DEFAULT_DEMAND_ROWS) -> Result:
        """Run to the end and return every row, or raise: a failed, cancelled or cut-short
        query is never returned as a shorter list of rows."""
        with self.query(sql) as query:
            return query.collect(demand_rows=demand_rows)

    def close(self) -> None:
        if not self.closed:
            try:
                self._lib.call("mdd_session_close_v1", self._handle)
            finally:
                self._drop()


class Prepared(_Owned):
    _what = "prepared query"

    def __init__(self, lib: _ffi.Library, handle: int, session: Session):
        super().__init__(lib, handle, "mdd_prepared_release", session)

    def start(self, *, limits: dict[str, int] | None = None) -> "Query":
        data = json.dumps({"limits": limits}).encode() if limits else b""
        view, keep = _ffi.view_of(data)
        out = ctypes.c_uint64(0)
        self._lib.call("mdd_start_query_v1", self._h(), ctypes.byref(view), ctypes.byref(out))
        del keep
        return Query(self._lib, out.value, self._parent)


class Query(_Owned):
    _what = "query"

    def __init__(self, lib: _ffi.Library, handle: int, session: Session):
        super().__init__(lib, handle, "mdd_query_release", session)
        self.terminal: dict[str, Any] | None = None

    def cancel(self) -> None:
        """Ask the query to stop. Safe from any thread, also while another thread is
        waiting for a batch. The stream then ends in a CANCELLED terminal."""
        self._lib.call("mdd_query_cancel_v1", self._h())

    def batches(self, demand_rows: int = DEFAULT_DEMAND_ROWS) -> Iterator[Batch]:
        """Yield every batch, then raise if the terminal is not a success.

        Each batch is copied out, acknowledged and released before the next is asked
        for, so no batch is held by the library while the caller works on it. After a
        normal end `self.terminal` holds the verdict.
        """
        lib = self._lib
        while True:
            event = ctypes.c_uint64(0)
            lib.call("mdd_query_next_v1", self._h(), demand_rows, ctypes.byref(event))
            try:
                kind = ctypes.c_uint32(0)
                lib.call("mdd_event_kind_v1", event.value, ctypes.byref(kind))
                if kind.value == _ffi.EVENT_TERMINAL:
                    self.terminal = lib.json_view("mdd_event_terminal_json_v1", event.value)
                    batch = None
                else:
                    handle = ctypes.c_uint64(0)
                    lib.call("mdd_event_batch_v1", event.value, ctypes.byref(handle))
                    document = lib.json_view("mdd_batch_json_v1", handle.value)
                    lib.call("mdd_batch_ack_v1", handle.value)
                    batch = Batch(
                        sequence=int(document["sequence"]), first_row=int(document["first_row"]),
                        columns=tuple(document["columns"]),
                        rows=tuple(tuple(decode_cell(c) for c in row) for row in document["rows"]))
            finally:
                lib.release("mdd_event_release", event.value)
            if batch is None:
                break
            yield batch
        terminal = self.terminal
        if terminal is not None and terminal.get("operation_status") != "ok":
            error = errors.from_terminal(terminal.get("error") or {})
            error.terminal = terminal  # type: ignore[attr-defined]
            raise error

    def collect(self, demand_rows: int = DEFAULT_DEMAND_ROWS) -> Result:
        columns: tuple[str, ...] = ()
        rows: list[tuple[Any, ...]] = []
        for batch in self.batches(demand_rows):
            columns = batch.columns
            rows.extend(batch.rows)
        if self.terminal is None:
            raise errors.MddError("the stream ended without a terminal", code="INTERNAL_FAULT", stage="sdk")
        result = Result(columns, rows, self.terminal)
        if not result.is_complete:
            raise errors.MddError("the query ended without a complete result",
                                  code="INCOMPLETE_RESULT", stage="sdk",
                                  details={"terminal": self.terminal})
        return result

    def close(self) -> None:
        """Cancel whatever is unfinished and give up this reference."""
        if not self.closed:
            try:
                self._lib.raw("mdd_query_cancel_v1", self._handle, None)
            finally:
                self._drop()


@dataclass
class Input:
    path: str
    kind: str = "auto"
    expected_sha256: str | None = None

    def as_request(self) -> dict[str, Any]:
        entry: dict[str, Any] = {"path": str(self.path), "kind": self.kind}
        if self.expected_sha256:
            entry["expected_sha256"] = self.expected_sha256
        return entry


def open_snapshot(inputs: Sequence[Input | str], *, lib: _ffi.Library | None = None) -> Snapshot:
    """Capture the inputs into a private snapshot. Strict: all or nothing."""
    lib = lib or _ffi.library()
    entries = [(item if isinstance(item, Input) else Input(str(item))).as_request() for item in inputs]
    view, keep = _ffi.view_of(json.dumps({"inputs": entries}).encode())
    out = ctypes.c_uint64(0)
    lib.call("mdd_open_snapshot_v1", ctypes.byref(view), ctypes.byref(out))
    del keep
    return Snapshot(lib, out.value)
