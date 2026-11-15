#!/usr/bin/env python3
"""Run conformance/abi/ownership-cases.json against the raw C ABI.

Usage: python -I conformance/abi/ownership_cases.py [--library PATH]

Every case is run through the exported functions with ctypes, not through the Python
SDK, so the SDK's own bookkeeping cannot hide an ownership bug. After each case the
handles it still holds are released (a failing case must not poison the next one) and
the count of live handles must be back to what it was before the case.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

from mdd import _ffi  # noqa: E402

STATUS = {
    "OK": 0, "INVALID_ARGUMENT": 1, "INVALID_HANDLE": 2, "CLOSED": 3, "BUSY": 4,
    "OUTSTANDING_BATCH": 5, "CANCELLED": 6, "DEADLINE_EXCEEDED": 7, "QUOTA_EXCEEDED": 8,
    "UNSUPPORTED": 9, "INCOMPLETE_FACTS": 10, "INVALID_INPUT": 11, "ABI_MISMATCH": 12,
    "INTERNAL_FAULT": 13,
}
# How to give a handle back at the end of a case, by the kind of name that holds it.
RELEASE = {
    "snapshot": "mdd_snapshot_release", "session": "mdd_session_release",
    "prepared": "mdd_prepared_release", "query": "mdd_query_release",
    "event": "mdd_event_release", "batch": "mdd_batch_release", "error": "mdd_error_release",
}


class CaseFailed(Exception):
    pass


class Runner:
    def __init__(self, lib: _ffi.Library, spec: dict):
        self.lib = lib
        self.spec = spec
        self.names: dict[str, int] = {}
        self.kinds: dict[str, str] = {}
        self.trace: list[str] = []

    # -- helpers ---------------------------------------------------------------------
    def fail(self, message: str) -> None:
        raise CaseFailed(message + " | trace: " + " ; ".join(self.trace))

    def handle(self, argument) -> int:
        if isinstance(argument, dict):
            return int(argument["literal"])
        if argument not in self.names:
            self.fail(f"unknown name {argument!r}")
        return self.names[argument]

    def bind(self, name: str, kind: str, handle: int) -> None:
        self.names[name], self.kinds[name] = handle, kind

    def check(self, label: str, got: int, expect: str) -> None:
        self.trace.append(f"{label}->{got}")
        if got != STATUS[expect]:
            self.fail(f"{label}: wanted {expect} ({STATUS[expect]}), got {got}")

    def raw(self, fn: str, *args) -> tuple[int, int]:
        """Call; returns (status, error handle). The error handle is the caller's."""
        takes_error = _ffi._SIGNATURES[fn][1]
        error = ctypes.c_uint64(0)
        status = self.lib.raw(fn, *args, *([ctypes.byref(error)] if takes_error else []))
        return status, error.value

    def release_quietly(self, error: int) -> None:
        if error:
            self.lib.raw("mdd_error_release", error)

    # -- ops -------------------------------------------------------------------------------
    def op_snapshot(self, op) -> None:
        request = json.dumps({"inputs": [{"path": str(ROOT / self.spec["fixture"]), "kind": "raw_dex"}]}).encode()
        view, keep = _ffi.view_of(request)
        out = ctypes.c_uint64(0)
        status, error = self.raw("mdd_open_snapshot_v1", ctypes.byref(view), ctypes.byref(out))
        self.release_quietly(error)
        self.check("open_snapshot", status, "OK")
        self.bind(op["as"], "snapshot", out.value)

    def op_session(self, op) -> None:
        view, keep = _ffi.view_of(b"")
        out = ctypes.c_uint64(0)
        status, error = self.raw("mdd_open_session_v1", self.handle(op["from"]), ctypes.byref(view), ctypes.byref(out))
        self.release_quietly(error)
        self.check("open_session", status, "OK")
        self.bind(op["as"], "session", out.value)

    def op_query(self, op) -> None:
        view, keep = _ffi.view_of(json.dumps({"kind": "sql", "sql": self.spec["sql"]}).encode())
        prepared, query = ctypes.c_uint64(0), ctypes.c_uint64(0)
        status, error = self.raw("mdd_prepare_query_v1", self.handle(op["from"]), ctypes.byref(view), ctypes.byref(prepared))
        self.release_quietly(error)
        self.check("prepare", status, "OK")
        self.bind(op["prepared"], "prepared", prepared.value)
        empty, keep2 = _ffi.view_of(b"")
        status, error = self.raw("mdd_start_query_v1", prepared.value, ctypes.byref(empty), ctypes.byref(query))
        self.release_quietly(error)
        self.check("start", status, "OK")
        self.bind(op["as"], "query", query.value)

    def op_next(self, op) -> None:
        event = ctypes.c_uint64(0)
        status, error = self.raw("mdd_query_next_v1", self.handle(op["query"]), op["demand"], ctypes.byref(event))
        self.release_quietly(error)
        self.check("next", status, op["expect"])
        if "as" in op and event.value:
            self.bind(op["as"], "event", event.value)

    def op_batch(self, op) -> None:
        out = ctypes.c_uint64(0)
        status, error = self.raw("mdd_event_batch_v1", self.handle(op["event"]), ctypes.byref(out))
        self.release_quietly(error)
        self.check("event_batch", status, "OK")
        # Borrowed from the event: not ours to release at cleanup, but we track the value.
        self.names[op["as"]] = out.value
        self.kinds[op["as"]] = "borrowed-batch"

    def op_call(self, op) -> None:
        args = [self.handle(a) for a in op["args"]]
        status, error = self.raw(op["fn"], *args)
        if op.get("error_as"):
            self.bind(op["error_as"], "error", error)
        else:
            self.release_quietly(error)
        self.check(op["fn"], status, op["expect"])

    def op_view(self, op) -> None:
        view = _ffi.BytesView()
        args = [self.handle(a) for a in op["args"]]
        takes_error = _ffi._SIGNATURES[op["fn"]][1]
        error = ctypes.c_uint64(0)
        extra = [ctypes.byref(view)] + ([ctypes.byref(error)] if takes_error else [])
        status = self.lib.raw(op["fn"], *args, *extra)
        self.release_quietly(error.value)
        self.check(op["fn"], status, op["expect"])
        if status == 0 and view.len:
            json.loads(_ffi.read_view(view))  # a view the library hands out must be readable

    def op_drain(self, op) -> None:
        query = self.handle(op["query"])
        for _ in range(10_000):
            event = ctypes.c_uint64(0)
            status, error = self.raw("mdd_query_next_v1", query, op["demand"], ctypes.byref(event))
            self.release_quietly(error)
            self.check("drain.next", status, "OK")
            kind = ctypes.c_uint32(0)
            self.release_quietly(self.raw("mdd_event_kind_v1", event.value, ctypes.byref(kind))[1])
            if kind.value == _ffi.EVENT_BATCH:
                batch = ctypes.c_uint64(0)
                self.release_quietly(self.raw("mdd_event_batch_v1", event.value, ctypes.byref(batch))[1])
                self.check("drain.ack", self.raw("mdd_batch_ack_v1", batch.value)[0], "OK")
                self.lib.raw("mdd_event_release", event.value)
                continue
            view = _ffi.BytesView()
            self.release_quietly(self.raw("mdd_event_terminal_json_v1", event.value, ctypes.byref(view))[1])
            terminal = json.loads(_ffi.read_view(view))
            self.lib.raw("mdd_event_release", event.value)
            if terminal["operation_status"] != op["expect_terminal"]:
                self.fail(f"terminal was {terminal['operation_status']}")
            return
        self.fail("the stream did not end")

    def cleanup(self) -> None:
        for name, kind in self.kinds.items():
            if kind in RELEASE:
                self.lib.raw(RELEASE[kind], self.names[name])


def run_case(lib: _ffi.Library, spec: dict, case: dict) -> dict:
    before = lib.live_handles()
    runner = Runner(lib, spec)
    problem = None
    try:
        for op in case["ops"]:
            getattr(runner, "op_" + op["op"])(op)
    except CaseFailed as error:
        problem = str(error)
    finally:
        runner.cleanup()
    leaked = lib.live_handles() - before
    if problem is None and leaked:
        problem = f"leaked {leaked} handle(s)"
    return {"id": case["id"], "why": case["why"], "ops": len(case["ops"]),
            "passed": problem is None, "problem": problem}


def run_all(lib: _ffi.Library | None = None, path: Path | None = None) -> list[dict]:
    lib = lib or _ffi.library()
    path = path or ROOT / "conformance/abi/ownership-cases.json"
    spec = json.loads(path.read_text(encoding="utf-8"))
    return [run_case(lib, spec, case) for case in spec["cases"]]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path)
    args = parser.parse_args()
    lib = _ffi.load(args.library) if args.library else _ffi.library()
    results = run_all(lib)
    for result in results:
        print(("ok   " if result["passed"] else "FAIL ") + result["id"] + ("" if result["passed"] else ": " + str(result["problem"])))
    failed = [r for r in results if not r["passed"]]
    print(f"{len(results) - len(failed)}/{len(results)} ownership cases passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
