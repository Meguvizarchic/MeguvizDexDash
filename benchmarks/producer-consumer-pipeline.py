#!/usr/bin/env python3
"""MDD-044: the real producer/consumer pipeline and the optional column-batch evaluation.

Every channel here is a real OS pipe to the real engine binary; nothing is replayed
offline. The workload is the full public NewPipe 0.28.6 five-column `class_methods`
export (55,763 rows), pinned by the input digest in conformance/manifests/input-corpus.json,
plus small synthetic Unicode / NULL / duplicate counterexamples whose expected rows are
computed from the fixture recipe, not from the engine's answer.

Channels
  cli-query      `meguvizdexdash query --format jsonl`, one process per statement.
  cli-serve-raw  `meguvizdexdash serve`, raw framed lines captured byte-exactly; this
                 capture is also the source of the typed batch documents the encoding
                 evaluation compares.
  sdk-worker     the python/mdd SDK `Worker` (serve over stdin/stdout), instrumented at
                 runtime (a counting stdout proxy and a `_next` override) without editing
                 any SDK file.
  mcp            `meguvizdexdash mcp`, JSON-RPC over stdio, 1000-row pages walked to the
                 exact total. MCP stays JSON; no binary encoding is offered or used here.

Timing boundary: t0 is the instant before the engine process is spawned (for the worker,
before `Worker()` starts serve and waits for `opened`); the clock stops when the complete
application object exists and the terminal/page invariants have been verified. Process
teardown is measured separately. These are diagnostic development timings on a shared
host, not a performance qualification (MDD-060/082 own the exclusive window).

Reported separately, never derived from one another:
  wire bytes   counted on the pipe (reader thread / stdout proxy / JSON-RPC frames),
  queueing     line arrival (reader thread) vs consumption timestamps, and consumer block
               time; the MCP client is synchronous and reports request round trips,
  CPU          producer user+kernel (GetProcessTimes on Windows, /proc samples on POSIX)
               and consumer process_time delta,
  peak RSS     producer PeakWorkingSetSize (exact on Windows, VmHWM samples on POSIX) and
               consumer working-set samples at 5 ms. Encoding size is never used to
               estimate RSS.

The column-batch candidate (`columns-v1`) is a consumer-side prototype over the same typed
cells of mdd.sdk-batch.v1, laid out as docs/02_ARCHITECTURE_AND_CONTRACTS.md 10.3 prescribes:
little-endian fixed-width values, a validity bitmap (1 = non-NULL, LSB first, trailing bits
zero), row_count+1 u64 offsets plus contiguous bytes for variable-length columns, NULL rows
carrying zero-length values and zeroed fixed-width placeholders, raw bits for f64. It is
evaluated only on the worker/SDK wire; the engine's mdd-wire/1 negotiation currently offers
`json` alone, so enabling columns-v1 would need engine work that is out of this task's scope.

Fail-closed: partial/unknown coverage, truncation, leftover pages, a missing terminal, a row
count that disagrees with the terminal, a lost worker or a non-zero exit are errors, never an
empty success. Validation uses explicit raises, never bare asserts.

Usage:
  python -I benchmarks/producer-consumer-pipeline.py gen-cases [--cases-out PATH]
  python -I benchmarks/producer-consumer-pipeline.py run [--binary PATH] [--apk PATH]
      [--rounds N] [--batch-rows N] [--page-limit N] [--out-dir DIR] [--fixtures-dir DIR]

`MDD_WORKER_BINARY` selects the engine binary when --binary is absent. The public APK is
resolved from the corpus manifest (artifacts/local is ignored and never committed); its
sha256 and size are verified before any run and a mismatch aborts.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import queue
import re
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "conformance" / "mcp"))

import jsonschema  # noqa: E402

import mdd  # noqa: E402
import mdd.worker as mdd_worker  # noqa: E402
from mdd._cells import DexMutf8, decode_cell  # noqa: E402
from mcp_client import McpClient  # noqa: E402
import tiny_dex  # noqa: E402

WORKLOAD_SQL = ("SELECT file_id,class_descriptor,method_idx,method_name,method_descriptor "
                "FROM class_methods ORDER BY file_id,class_idx,method_idx")
NULL_SQL = ("SELECT CASE WHEN method_idx = 0 THEN NULL ELSE method_name END AS maybe_null, "
            "'' AS empty_text, method_name FROM class_methods ORDER BY file_id,class_idx,method_idx")
DIALECT = "dexsql-0.1.1"
EXPECTED_WORKLOAD_ROWS = 55763
CORPUS_MANIFEST = "conformance/manifests/input-corpus.json"
PUBLIC_INPUT_ID = "newpipe-0.28.6"
STREAM_PROTOCOL = "mdd.cli-stream.v1"
MAX_LINE_BYTES = 64 * 1024 * 1024
QUEUE_DEPTH = 64
RUN_DEADLINE_SECONDS = 600.0
SAMPLER_INTERVAL = 0.005
# The MCP server caps a per-operation timeout_ms at 300000 ms; stay under it. The consumer-side
# watchdog (MeasuredMcp) still enforces the overall RUN_DEADLINE_SECONDS across the page walk.
MCP_OPERATION_TIMEOUT_MS = 120000

DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")
SIGNED_DECIMAL = re.compile(r"^-?(0|[1-9][0-9]*)$")
HEX_LOWER = re.compile(r"^([0-9a-f]{2})*$")
F64_BITS = re.compile(r"^[0-9a-f]{16}$")


class PipelineError(RuntimeError):
    def __init__(self, code: str, message: str = "", **details: Any):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.details = details


# ---- platform metrics ---------------------------------------------------------

if os.name == "nt":
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _FILETIME(ctypes.Structure):
        _fields_ = [("lo", wintypes.DWORD), ("hi", wintypes.DWORD)]

    class _PMC(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

    _k32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(_FILETIME)] * 4
    _k32.GetProcessTimes.restype = wintypes.BOOL
    try:
        _get_pmc = _k32.K32GetProcessMemoryInfo
    except AttributeError:  # pragma: no cover - older windows
        _get_pmc = ctypes.WinDLL("psapi").GetProcessMemoryInfo
    _get_pmc.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PMC), wintypes.DWORD]
    _get_pmc.restype = wintypes.BOOL


def _filetime_seconds(ft: "_FILETIME") -> float:
    return ((ft.hi << 32) | ft.lo) / 1e7


def windows_process_metrics(handle: int) -> dict:
    """Exact producer CPU and peak working set from an open process handle (valid after exit)."""
    creation, exit_, kernel, user = (_FILETIME() for _ in range(4))
    if not _k32.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_),
                                ctypes.byref(kernel), ctypes.byref(user)):
        raise PipelineError("metrics_unavailable", "GetProcessTimes failed", win_error=ctypes.get_last_error())
    counters = _PMC(ctypes.sizeof(_PMC))
    if not _get_pmc(handle, ctypes.byref(counters), ctypes.sizeof(_PMC)):
        raise PipelineError("metrics_unavailable", "GetProcessMemoryInfo failed", win_error=ctypes.get_last_error())
    return {"producer_user_seconds": _filetime_seconds(user),
            "producer_kernel_seconds": _filetime_seconds(kernel),
            "producer_peak_working_set_bytes": int(counters.PeakWorkingSetSize),
            "method": "GetProcessTimes+PeakWorkingSetSize (exact)"}


def _posix_proc_sample(pid: int) -> tuple[float, int] | None:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        status = Path(f"/proc/{pid}/status").read_text()
    except OSError:
        return None
    fields = stat.rpartition(")")[2].split()
    ticks = os.sysconf("SC_CLK_TCK")
    cpu = (int(fields[11]) + int(fields[12])) / ticks  # utime + stime after the comm field
    hwm = next((int(line.split()[1]) * 1024 for line in status.splitlines()
                if line.startswith("VmHWM:")), None)
    if hwm is None:
        return None
    return cpu, hwm


def own_working_set_bytes() -> int:
    if os.name == "nt":
        counters = _PMC(ctypes.sizeof(_PMC))
        pseudo = wintypes.HANDLE(-1)
        if not _get_pmc(pseudo, ctypes.byref(counters), ctypes.sizeof(_PMC)):
            raise PipelineError("metrics_unavailable", "own working set unreadable")
        return int(counters.WorkingSetSize)
    sample = _posix_proc_sample(os.getpid())
    if sample is None:
        raise PipelineError("metrics_unavailable", "/proc/self unreadable")
    return sample[1]


class RssSampler:
    """Samples this process's working set (and, on POSIX, a producer's CPU/VmHWM) while a run lives.

    The consumer peak is the maximum of the samples: a sampled peak, not an OS-tracked one;
    the interval is reported with every number. On Windows the producer peak is read exactly
    after exit instead, so no producer sampling is needed there."""

    def __init__(self, producer_pid: int | None = None, interval: float = SAMPLER_INTERVAL):
        self.interval = interval
        self.producer_pid = producer_pid
        self.peak = 0
        self.producer_cpu_seconds = 0.0
        self.producer_peak_bytes = 0
        self.samples = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="mdd044-rss", daemon=True)

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.peak = max(self.peak, own_working_set_bytes())
            self.samples += 1
            if os.name != "nt" and self.producer_pid is not None:
                sample = _posix_proc_sample(self.producer_pid)
                if sample is not None:
                    self.producer_cpu_seconds, self.producer_peak_bytes = sample
            self._stop.wait(self.interval)

    def __enter__(self) -> "RssSampler":
        self.peak = own_working_set_bytes()
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=5.0)
        self.peak = max(self.peak, own_working_set_bytes())

    def consumer_memory(self) -> dict:
        if self.samples == 0:
            raise PipelineError("metrics_unavailable", "the RSS sampler took no sample")
        return {"consumer_peak_working_set_sampled_bytes": self.peak,
                "consumer_rss_samples": self.samples, "sampler_interval_ms": self.interval * 1000}


def producer_metrics(proc: subprocess.Popen, sampler: RssSampler) -> dict:
    if os.name == "nt":
        handle = getattr(proc, "_handle", None)
        if handle is None:
            raise PipelineError("metrics_unavailable", "the process handle is not available")
        return windows_process_metrics(int(handle))
    if sampler.producer_pid is None or sampler.producer_peak_bytes == 0:
        raise PipelineError("metrics_unavailable", "no /proc sample of the producer was taken")
    return {"producer_user_seconds": None, "producer_kernel_seconds": None,
            "producer_cpu_seconds_sampled": sampler.producer_cpu_seconds,
            "producer_peak_working_set_bytes": sampler.producer_peak_bytes,
            "method": "/proc utime+stime and VmHWM, sampled at the run interval"}


def load_snapshot() -> dict:
    """Objective load signals: how many engine processes exist besides ours, and the host shape."""
    count = None
    try:
        if os.name == "nt":
            out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq meguvizdexdash.exe", "/FO", "CSV", "/NH"],
                                 capture_output=True, text=True, timeout=30).stdout
            count = sum(1 for line in out.splitlines() if line.lower().startswith('"meguvizdexdash.exe"'))
        else:
            out = subprocess.run(["pgrep", "-c", "-x", "meguvizdexdash"], capture_output=True, text=True, timeout=30).stdout
            count = int(out.strip() or 0)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        count = None
    return {"exclusive_window": False,
            "note": "shared host: other agents run tests/builds concurrently; diagnostic timing only",
            "meguvizdexdash_processes_at_start": count, "cpu_count": os.cpu_count(),
            "platform": platform.platform(), "python": sys.version.split()[0]}


# ---- the counted line reader (real OS pipe, bounded queue, arrival timestamps) ----

class LineReader:
    """A reader thread over a pipe with a bounded queue, like the SDK worker's plumbing.

    Records per-line arrival timestamps and byte counts so queue residency (arrival to
    consumption) and wire bytes are measured, not estimated. EOF, a partial final line and
    an oversize line are faults, never a clean end."""

    def __init__(self, stream: Any, max_line: int = MAX_LINE_BYTES, depth: int = QUEUE_DEPTH):
        self.max_line = max_line
        self.bytes = 0
        self.arrivals: list[float] = []
        self.line_bytes: list[int] = []
        self.consumer_wait_seconds = 0.0
        self._queue: queue.Queue = queue.Queue(maxsize=depth)
        self._stop = threading.Event()
        self._stream = stream
        self._thread = threading.Thread(target=self._read, name="mdd044-reader", daemon=True)
        self._thread.start()

    def _put(self, item: tuple) -> None:
        while not self._stop.is_set():
            try:
                self._queue.put(item, timeout=0.2)
                return
            except queue.Full:
                continue

    def _read(self) -> None:
        try:
            while not self._stop.is_set():
                raw = self._stream.readline(self.max_line + 1)
                if not raw:
                    break
                if len(raw) > self.max_line and not raw.endswith(b"\n"):
                    self._put(("oversize", None))
                    return
                if not raw.endswith(b"\n"):
                    self._put(("partial", raw))
                    return
                arrival = time.perf_counter()
                self.arrivals.append(arrival)
                self.line_bytes.append(len(raw))
                self.bytes += len(raw)
                self._put(("line", raw, arrival))
        except (OSError, ValueError):
            pass
        finally:
            try:
                self._stream.close()
            except (OSError, ValueError):
                pass
        self._put(("eof", None))

    def next(self, deadline: float) -> tuple[bytes, float, float]:
        """(raw line, arrival ts, consumption ts). Raises on fault, EOF-before-answer or deadline."""
        wait_total = 0.0
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise PipelineError("deadline_exceeded", "the consumer deadline passed")
            t0 = time.perf_counter()
            try:
                item = self._queue.get(timeout=min(0.25, remaining))
            except queue.Empty:
                wait_total += time.perf_counter() - t0
                continue
            wait_total += time.perf_counter() - t0
            self.consumer_wait_seconds += wait_total
            kind = item[0]
            if kind == "line":
                return item[1], item[2], time.perf_counter()
            if kind == "eof":
                raise PipelineError("eof_before_terminal", "the pipe ended before the answer did")
            if kind == "partial":
                raise PipelineError("partial_line", "the pipe ended mid-line", partial_bytes=len(item[1]))
            raise PipelineError("oversize_line", f"a line exceeds {self.max_line} bytes")

    def expect_eof(self, deadline: float) -> None:
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise PipelineError("deadline_exceeded", "waiting for EOF")
            try:
                item = self._queue.get(timeout=min(0.25, remaining))
            except queue.Empty:
                continue
            kind = item[0]
            if kind == "eof":
                return
            if kind == "line":
                raise PipelineError("frame_after_terminal", "a line arrived after the terminal")
            raise PipelineError("partial_line" if kind == "partial" else "oversize_line", "fault at end of stream")

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5.0)


# ---- cells: canonical form, digests, statistics ---------------------------------

def has_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def canonical_cell(cell: dict) -> dict:
    """The comparison form of a typed cell: NULL stays NULL, empty stays empty, text with
    unpaired surrogates is the UTF-16 unit form, integers are canonical decimals, f64 keeps
    its raw bits (NaN payload and -0.0 included)."""
    tag = cell["t"]
    if tag == "null":
        return {"t": "null"}
    if tag == "bool":
        return {"t": "bool", "v": bool(cell["v"])}
    if tag in ("i64", "u64"):
        return {"t": tag, "v": str(int(cell["v"]))}
    if tag == "f64":
        return {"t": "f64", "bits": cell["bits"].lower()}
    if tag == "bytes":
        return {"t": "bytes", "v": cell["v"].lower()}
    if tag == "dex_mutf8":
        return {"t": "dex_mutf8", "v": cell["v"].lower(), "utf16_units": str(int(cell["utf16_units"]))}
    if tag == "text":
        if "units" in cell:
            text = bytes.fromhex(cell["units"]).decode("utf-16-be", "surrogatepass")
            if has_surrogate(text):
                return {"t": "text", "units": cell["units"].lower()}
            return {"t": "text", "v": text}
        text = cell["v"]
        if has_surrogate(text):
            return {"t": "text", "units": text.encode("utf-16-be", "surrogatepass").hex()}
        return {"t": "text", "v": text}
    raise PipelineError("unknown_cell_tag", tag)


def canonical_rows(columns: Any, rows: list) -> list:
    return [[canonical_cell(cell) for cell in row] for row in rows]


def rows_digest(columns: Any, rows: list) -> str:
    """sha256 over the canonical typed rows: covers column identity, cell types, NULL,
    order, duplicates and every value. Not a hash of display strings."""
    document = {"columns": list(columns), "rows": canonical_rows(columns, rows)}
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def app_value(value: Any) -> list:
    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["bool", value]
    if isinstance(value, int):
        return ["int", str(value)]
    if isinstance(value, float):
        return ["f64", struct.pack(">d", value).hex()]
    if isinstance(value, str):
        if has_surrogate(value):
            return ["text16", value.encode("utf-16-be", "surrogatepass").hex()]
        return ["text", value]
    if isinstance(value, bytes):
        return ["bytes", value.hex()]
    if isinstance(value, DexMutf8):
        return ["mutf8", value.raw.hex(), value.utf16_units]
    raise PipelineError("unknown_app_value", type(value).__name__)


def app_digest(columns: Any, decoded_rows: list) -> str:
    """Value-level digest of the materialized application object (the SDK decodes i64/u64
    both to int, so tags collapse here; the tag-preserving digest is `rows_digest`)."""
    document = {"columns": list(columns), "rows": [[app_value(v) for v in row] for row in decoded_rows]}
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def row_statistics(columns: Any, rows: list) -> dict:
    nulls = sum(1 for row in rows for cell in row if cell["t"] == "null")
    keys = [json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            for row in canonical_rows(columns, rows)]
    census: dict[str, dict[str, int]] = {name: {} for name in columns}
    for row in rows:
        for name, cell in zip(columns, row):
            census[name][cell["t"]] = census[name].get(cell["t"], 0) + 1
    return {"null_cells": nulls, "rows": len(rows), "distinct_rows": len(set(keys)),
            "duplicate_rows": len(rows) - len(set(keys)), "type_census": census}


# ---- the mdd.sdk-batch.v1 document schema ----------------------------------------

_CELL_SCHEMA = {
    "type": "object",
    "oneOf": [
        {"properties": {"t": {"const": "null"}}, "required": ["t"], "additionalProperties": False},
        {"properties": {"t": {"const": "bool"}, "v": {"type": "boolean"}},
         "required": ["t", "v"], "additionalProperties": False},
        {"properties": {"t": {"const": "i64"}, "v": {"type": "string", "pattern": "^-?(0|[1-9][0-9]*)$"}},
         "required": ["t", "v"], "additionalProperties": False},
        {"properties": {"t": {"const": "u64"}, "v": {"type": "string", "pattern": "^(0|[1-9][0-9]*)$"}},
         "required": ["t", "v"], "additionalProperties": False},
        {"properties": {"t": {"const": "f64"}, "bits": {"type": "string", "pattern": "^[0-9a-f]{16}$"}},
         "required": ["t", "bits"], "additionalProperties": False},
        {"properties": {"t": {"const": "text"}, "v": {"type": "string"},
                        "units": {"type": "string", "pattern": "^([0-9a-f]{2})*$"}},
         "required": ["t"], "additionalProperties": False,
         "oneOf": [{"required": ["v"]}, {"required": ["units"]}]},
        {"properties": {"t": {"const": "bytes"}, "v": {"type": "string", "pattern": "^([0-9a-f]{2})*$"}},
         "required": ["t", "v"], "additionalProperties": False},
        {"properties": {"t": {"const": "dex_mutf8"}, "v": {"type": "string", "pattern": "^([0-9a-f]{2})*$"},
                        "utf16_units": {"type": "string", "pattern": "^(0|[1-9][0-9]*)$"}},
         "required": ["t", "v", "utf16_units"], "additionalProperties": False},
    ],
}

BATCH_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "mdd.sdk-batch.v1 batch document (as observed on the CLI/worker wire)",
    "type": "object",
    "required": ["columns", "first_row", "row_count", "rows", "schema", "sequence"],
    "additionalProperties": False,
    "properties": {
        "schema": {"const": "mdd.sdk-batch.v1"},
        "columns": {"type": "array", "minItems": 1, "items": {"type": "string"}},
        "first_row": {"type": "string", "pattern": "^(0|[1-9][0-9]*)$"},
        "sequence": {"type": "string", "pattern": "^(0|[1-9][0-9]*)$"},
        "row_count": {"type": "integer", "minimum": 0},
        "rows": {"type": "array", "items": {"type": "array", "items": _CELL_SCHEMA}},
    },
}

_BATCH_VALIDATOR = jsonschema.Draft202012Validator(BATCH_SCHEMA)


def validate_batch_document(document: Any) -> None:
    errors = sorted(_BATCH_VALIDATOR.iter_errors(document), key=lambda e: list(e.path))
    if errors:
        raise PipelineError("batch_schema_invalid", errors[0].message, path=list(errors[0].path))
    if document["row_count"] != len(document["rows"]):
        raise PipelineError("count_mismatch", "row_count differs from the rows delivered")
    width = len(document["columns"])
    for index, row in enumerate(document["rows"]):
        if len(row) != width:
            raise PipelineError("row_shape_mismatch", f"row {index} has {len(row)} cells, {width} columns")


def require_complete(terminal: Any, delivered_rows: int, expected_rows: int | None = None) -> dict:
    """The completeness gate. Anything partial, cut, left over, failed or absent raises."""
    if not isinstance(terminal, dict):
        raise PipelineError("missing_terminal", "the stream ended without a terminal object")
    if terminal.get("operation_status") != "ok":
        raise PipelineError("operation_not_ok", json.dumps(terminal.get("error") or {}, ensure_ascii=False),
                            operation_status=terminal.get("operation_status"))
    if (terminal.get("execution") or {}).get("complete") is not True:
        raise PipelineError("execution_incomplete", "execution.complete is not true")
    response = terminal.get("response") or {}
    if response.get("truncated") is not False:
        raise PipelineError("truncated", "the result is truncated")
    if response.get("more_available") is not False:
        raise PipelineError("more_available", "rows are still available")
    if response.get("next_cursor") is not None:
        raise PipelineError("cursor_left", "a next_cursor remains")
    coverage = terminal.get("coverage") or {}
    if coverage.get("input") != "complete" or coverage.get("facts") != "complete":
        raise PipelineError("coverage_incomplete", json.dumps(coverage, ensure_ascii=False))
    emitted = response.get("emitted_rows")
    if not isinstance(emitted, str) or not DECIMAL.match(emitted):
        raise PipelineError("malformed_terminal", "emitted_rows is not a canonical decimal string")
    if int(emitted) != delivered_rows:
        raise PipelineError("count_mismatch", f"terminal says {emitted} rows, {delivered_rows} were delivered")
    if response.get("total_rows_exact") is True:
        total = response.get("total_rows")
        if not isinstance(total, str) or not DECIMAL.match(total) or int(total) != delivered_rows:
            raise PipelineError("count_mismatch", "exact total_rows differs from the delivered rows")
    if expected_rows is not None and delivered_rows != expected_rows:
        raise PipelineError("row_count_mismatch", f"{delivered_rows} rows delivered, {expected_rows} expected")
    return {"operation_status": "ok", "emitted_rows": int(emitted),
            "total_rows": None if response.get("total_rows") is None else int(response["total_rows"]),
            "total_rows_exact": response.get("total_rows_exact"),
            "coverage_input": coverage.get("input"), "coverage_facts": coverage.get("facts")}


def mcp_cell_to_sdk(cell: dict) -> dict:
    """MCP's JSON cell form into the typed sdk-batch form. MCP float64 travels as a JSON
    number, so a NaN payload cannot survive MCP itself; that is a declared MCP limitation
    and this workload carries no floats. The column-batch evaluation never uses MCP cells."""
    kind = cell["type"]
    if kind == "null":
        return {"t": "null"}
    value = cell.get("value")
    if kind == "int64":
        return {"t": "i64", "v": str(int(value))}
    if kind == "uint64":
        return {"t": "u64", "v": str(int(value))}
    if kind == "utf8":
        return {"t": "text", "v": value}
    if kind == "binary":
        return {"t": "bytes", "v": value.lower()}
    if kind == "float64":
        return {"t": "f64", "bits": struct.pack(">d", float(value)).hex()}
    raise PipelineError("unknown_mcp_cell_type", kind)


# ---- the columns-v1 candidate codec ----------------------------------------------

TYPE_TAGS = {"bool": 1, "i64": 2, "u64": 3, "f64": 4, "utf8": 5, "bytes": 6, "dex_mutf8": 7}
TAG_TYPES = {value: key for key, value in TYPE_TAGS.items()}
SDK_TO_WIRE = {"text": "utf8", "bool": "bool", "i64": "i64", "u64": "u64",
               "f64": "f64", "bytes": "bytes", "dex_mutf8": "dex_mutf8"}
FIXED_WIDTH = {"bool": 1, "i64": 8, "u64": 8, "f64": 8}
VARLEN = ("utf8", "bytes", "dex_mutf8")
MAGIC = b"MDC1"
HEADER = struct.Struct("<4sQQI")
DESC_FIXED = struct.Struct("<BBH")
U64 = struct.Struct("<Q")


def _mutf8_units(raw: bytes) -> int:
    """Validate MUTF-8 structure and count UTF-16 units; raises cell_type_mismatch."""
    units, i = 0, 0
    while i < len(raw):
        byte = raw[i]
        if byte == 0:
            raise PipelineError("cell_type_mismatch", "a raw NUL byte in MUTF-8")
        if byte < 0x80:
            units += 1
            i += 1
        elif 0xC0 <= byte <= 0xDF:
            if i + 1 >= len(raw) or not 0x80 <= raw[i + 1] <= 0xBF:
                raise PipelineError("cell_type_mismatch", "truncated 2-byte MUTF-8 sequence")
            units += 1
            i += 2
        elif 0xE0 <= byte <= 0xEF:
            if i + 2 >= len(raw) or not (0x80 <= raw[i + 1] <= 0xBF and 0x80 <= raw[i + 2] <= 0xBF):
                raise PipelineError("cell_type_mismatch", "truncated 3-byte MUTF-8 sequence")
            units += 1
            i += 3
        else:
            raise PipelineError("cell_type_mismatch", "invalid MUTF-8 lead byte")
    return units


def _validate_cell_for_column(cell: dict, column: dict) -> None:
    tag = cell["t"]
    if tag == "null":
        if not column["nullable"]:
            raise PipelineError("cell_type_mismatch", "NULL in a non-nullable column")
        return
    if SDK_TO_WIRE.get(tag) != column["type"]:
        raise PipelineError("cell_type_mismatch", f"cell tag {tag} in column of type {column['type']}")
    if tag in ("i64", "u64"):
        value = cell["v"]
        if not isinstance(value, str) or not SIGNED_DECIMAL.match(value) or value == "-0":
            raise PipelineError("malformed_body", "non-canonical integer cell")
        number = int(value)
        if tag == "i64" and not -(2**63) <= number < 2**63:
            raise PipelineError("malformed_body", "i64 out of range")
        if tag == "u64" and not 0 <= number < 2**64:
            raise PipelineError("malformed_body", "u64 out of range")
    elif tag == "f64":
        if not isinstance(cell.get("bits"), str) or not F64_BITS.match(cell["bits"]):
            raise PipelineError("malformed_body", "f64 needs 16 lowercase hex bits")
    elif tag in ("bytes", "dex_mutf8"):
        if not isinstance(cell.get("v"), str) or not HEX_LOWER.match(cell["v"]):
            raise PipelineError("malformed_body", "lowercase hex bytes required")
        if tag == "dex_mutf8":
            units = cell.get("utf16_units")
            if not isinstance(units, str) or not DECIMAL.match(units):
                raise PipelineError("malformed_body", "utf16_units must be a canonical decimal string")
            if _mutf8_units(bytes.fromhex(cell["v"])) != int(units):
                raise PipelineError("cell_type_mismatch", "utf16_units does not match the MUTF-8 bytes")
    elif tag == "text":
        if "units" in cell:
            if not isinstance(cell["units"], str) or not HEX_LOWER.match(cell["units"]):
                raise PipelineError("malformed_body", "text units must be lowercase UTF-16BE hex")
        elif not isinstance(cell.get("v"), str):
            raise PipelineError("malformed_body", "text cell needs v or units")
    elif tag == "bool":
        if not isinstance(cell.get("v"), bool):
            raise PipelineError("malformed_body", "bool cell needs a JSON boolean")


def _bitmap_bytes(row_count: int) -> int:
    return (row_count + 7) // 8


def _text_value_bytes(cell: dict) -> bytes:
    if "units" in cell:
        text = bytes.fromhex(cell["units"]).decode("utf-16-be", "surrogatepass")
    else:
        text = cell["v"]
    return text.encode("utf-8", "surrogatepass")


def encode_columns(columns: list[str], rows: list, *, sequence: int, schema: dict) -> bytes:
    """Encode typed sdk-batch cells into the columns-v1 candidate body (docs 10.3 layout)."""
    schema_columns = schema["columns"]
    if [c["name"] for c in schema_columns] != list(columns):
        raise PipelineError("schema_mismatch", "schema column names differ from the batch columns")
    if [c["ordinal"] for c in schema_columns] != list(range(len(columns))):
        raise PipelineError("schema_mismatch", "schema ordinals must be 0..n-1")
    if len({c["stable_id"] for c in schema_columns}) != len(schema_columns):
        raise PipelineError("schema_mismatch", "stable ids must be unique")
    row_count = len(rows)
    buffers: list[bytearray] = []
    for column in schema_columns:
        ctype = column["type"]
        if ctype not in TYPE_TAGS:
            raise PipelineError("schema_mismatch", f"unknown column type {ctype}")
        bitmap = bytearray(_bitmap_bytes(row_count))
        values = bytearray()
        offsets = [0]
        units = bytearray()
        for index, row in enumerate(rows):
            if len(row) != len(schema_columns):
                raise PipelineError("row_shape_mismatch", f"row {index} width")
            cell = row[column["ordinal"]]
            _validate_cell_for_column(cell, column)
            if cell["t"] == "null":
                if ctype in FIXED_WIDTH:
                    values.extend(b"\0" * FIXED_WIDTH[ctype])
                else:
                    offsets.append(len(values))
                    if ctype == "dex_mutf8":
                        units.extend(b"\0" * 8)
                continue
            bitmap[index // 8] |= 1 << (index % 8)
            if ctype == "bool":
                values.append(1 if cell["v"] else 0)
            elif ctype in ("i64", "u64"):
                values.extend(struct.pack("<q" if ctype == "i64" else "<Q", int(cell["v"])))
            elif ctype == "f64":
                values.extend(struct.pack("<Q", int(cell["bits"], 16)))
            else:
                if ctype == "utf8":
                    raw = _text_value_bytes(cell)
                elif ctype == "bytes":
                    raw = bytes.fromhex(cell["v"])
                else:
                    raw = bytes.fromhex(cell["v"])
                    units.extend(struct.pack("<Q", int(cell["utf16_units"])))
                values.extend(raw)
                offsets.append(len(values))
        if ctype in FIXED_WIDTH:
            body = bytes(bitmap) + bytes(values)
        else:
            body = bytes(bitmap) + b"".join(struct.pack("<Q", off) for off in offsets) + bytes(values) + bytes(units)
        buffers.append(bytearray(body))
    head = bytearray(HEADER.pack(MAGIC, sequence, row_count, len(schema_columns)))
    descriptor_size = sum(DESC_FIXED.size + len(c["name"].encode("utf-8")) + 16 for c in schema_columns)
    cursor = len(head) + descriptor_size
    descriptors = bytearray()
    for column, buffer in zip(schema_columns, buffers):
        name = column["name"].encode("utf-8")
        descriptors.extend(DESC_FIXED.pack(TYPE_TAGS[column["type"]], 0, len(name)))
        descriptors.extend(name)
        descriptors.extend(struct.pack("<QQ", cursor, len(buffer)))
        cursor += len(buffer)
    return bytes(head) + bytes(descriptors) + b"".join(bytes(b) for b in buffers)


def _split_blob(blob: bytes) -> tuple:
    if len(blob) < HEADER.size:
        raise PipelineError("truncated_body", "shorter than the header")
    magic, sequence, row_count, column_count = HEADER.unpack_from(blob, 0)
    if magic != MAGIC:
        raise PipelineError("magic", "not a columns-v1 body")
    cursor = HEADER.size
    descriptors = []
    for _ in range(column_count):
        if cursor + DESC_FIXED.size > len(blob):
            raise PipelineError("truncated_body", "descriptor cut")
        type_tag, flags, name_len = DESC_FIXED.unpack_from(blob, cursor)
        cursor += DESC_FIXED.size
        if cursor + name_len + 16 > len(blob):
            raise PipelineError("truncated_body", "descriptor name/buffers cut")
        name = blob[cursor:cursor + name_len].decode("utf-8")
        cursor += name_len
        offset, length = struct.unpack_from("<QQ", blob, cursor)
        cursor += 16
        descriptors.append({"type_tag": type_tag, "flags": flags, "name": name,
                            "offset": offset, "length": length})
    return {"magic": magic, "sequence": sequence, "row_count": row_count,
            "column_count": column_count, "descriptors": descriptors, "desc_end": cursor}


def _column_buffer(blob: bytes, descriptor: dict) -> bytes:
    start, length = descriptor["offset"], descriptor["length"]
    if start + length > len(blob):
        raise PipelineError("buffer_bounds", "a column buffer runs past the body")
    return blob[start:start + length]


def decode_columns(blob: bytes, schema: dict) -> dict:
    """Decode and validate a columns-v1 body back into typed sdk-batch cells."""
    parts = _split_blob(blob)
    row_count, descriptors = parts["row_count"], parts["descriptors"]
    schema_columns = schema["columns"]
    if parts["column_count"] != len(schema_columns):
        raise PipelineError("count_mismatch", "column count differs from the schema")
    if row_count > len(blob):
        raise PipelineError("count_mismatch", "row_count is beyond any possible body")
    ordered = sorted(descriptors, key=lambda d: d["offset"])
    cursor = parts["desc_end"]
    for descriptor in ordered:
        if descriptor["offset"] != cursor:
            raise PipelineError("buffer_bounds", "column buffers must tile the body exactly")
        cursor += descriptor["length"]
    if cursor != len(blob):
        raise PipelineError("buffer_bounds", "unaccounted bytes in the body")
    rows: list[list[dict]] = [[] for _ in range(row_count)]
    names = []
    for ordinal, (descriptor, column) in enumerate(zip(descriptors, schema_columns)):
        if descriptor["flags"] != 0:
            raise PipelineError("malformed_body", "nonzero descriptor flags")
        if descriptor["name"] != column["name"] or descriptor["type_tag"] != TYPE_TAGS.get(column["type"]):
            raise PipelineError("schema_mismatch", f"descriptor {ordinal} differs from the schema")
        names.append(descriptor["name"])
        ctype = column["type"]
        buffer = _column_buffer(blob, descriptor)
        bitmap_len = _bitmap_bytes(row_count)
        if len(buffer) < bitmap_len:
            raise PipelineError("truncated_body", "bitmap cut")
        bitmap = buffer[:bitmap_len]
        if row_count % 8 and bitmap[-1] >> (row_count % 8):
            raise PipelineError("bitmap_padding", "trailing bitmap bits are not zero")
        present = [(bitmap[i // 8] >> (i % 8)) & 1 for i in range(row_count)]
        payload = buffer[bitmap_len:]
        if ctype in FIXED_WIDTH:
            width = FIXED_WIDTH[ctype]
            if len(payload) != row_count * width:
                raise PipelineError("count_mismatch", "fixed-width buffer size does not match row_count")
            for i in range(row_count):
                slot = payload[i * width:(i + 1) * width]
                if not present[i]:
                    if slot != b"\0" * width:
                        raise PipelineError("null_padding", "a NULL slot is not zeroed")
                    rows[i].append({"t": "null"})
                elif ctype == "bool":
                    if slot[0] not in (0, 1):
                        raise PipelineError("malformed_body", "bool slot is not 0/1")
                    rows[i].append({"t": "bool", "v": slot[0] == 1})
                elif ctype == "i64":
                    rows[i].append({"t": "i64", "v": str(struct.unpack("<q", slot)[0])})
                elif ctype == "u64":
                    rows[i].append({"t": "u64", "v": str(struct.unpack("<Q", slot)[0])})
                else:
                    rows[i].append({"t": "f64", "bits": "%016x" % struct.unpack("<Q", slot)[0]})
            continue
        offsets_len = (row_count + 1) * 8
        if len(payload) < offsets_len:
            raise PipelineError("truncated_body", "offsets cut")
        offsets = list(struct.unpack_from("<%dQ" % (row_count + 1), payload, 0))
        if offsets[0] != 0:
            raise PipelineError("offset_order", "the first offset is not 0")
        if any(a > b for a, b in zip(offsets, offsets[1:])):
            raise PipelineError("offset_order", "offsets are not monotonic")
        value_bytes = payload[offsets_len:]
        units_len = row_count * 8 if ctype == "dex_mutf8" else 0
        if len(value_bytes) != offsets[-1] + units_len:
            raise PipelineError("offset_tail", "the tail offset does not equal the value buffer length")
        units = (list(struct.unpack_from("<%dQ" % row_count, value_bytes, offsets[-1]))
                 if ctype == "dex_mutf8" else [0] * row_count)
        values = value_bytes[:offsets[-1]]
        for i in range(row_count):
            raw = values[offsets[i]:offsets[i + 1]]
            if not present[i]:
                if len(raw) != 0 or units[i] != 0:
                    raise PipelineError("null_padding", "a NULL varlen row must carry zero length and zero units")
                rows[i].append({"t": "null"})
                continue
            if ctype == "utf8":
                text = raw.decode("utf-8", "surrogatepass")
                if has_surrogate(text):
                    rows[i].append({"t": "text", "units": text.encode("utf-16-be", "surrogatepass").hex()})
                else:
                    rows[i].append({"t": "text", "v": text})
            elif ctype == "bytes":
                rows[i].append({"t": "bytes", "v": raw.hex()})
            else:
                if _mutf8_units(raw) != units[i]:
                    raise PipelineError("cell_type_mismatch", "utf16_units does not match the MUTF-8 bytes")
                rows[i].append({"t": "dex_mutf8", "v": raw.hex(), "utf16_units": str(units[i])})
    return {"columns": names, "sequence": str(parts["sequence"]), "row_count": row_count, "rows": rows}


def corrupt_blob(blob: bytes, schema: dict, op: dict) -> bytes:
    """Apply one named corruption to an encoded body; the conformance cases use these."""
    parts = _split_blob(blob)
    buffers = [_column_buffer(blob, d) for d in parts["descriptors"]]
    kind = op["op"]
    if kind == "magic":
        return b"XXXX" + blob[4:]
    if kind == "truncate":
        return blob[:op["keep"]]
    if kind == "row_count":
        return blob[:12] + struct.pack("<Q", parts["row_count"] + op["delta"]) + blob[20:]
    if kind == "descriptor_type":
        cursor = HEADER.size
        for index, descriptor in enumerate(parts["descriptors"]):
            if index == op["column"]:
                return blob[:cursor] + bytes([TYPE_TAGS[op["type"]]]) + blob[cursor + 1:]
            cursor += DESC_FIXED.size + len(descriptor["name"].encode("utf-8")) + 16
        raise PipelineError("bad_corrupt_op", "column out of range")
    ordinal = op.get("column", 0)
    buffer = bytearray(buffers[ordinal])
    row_count = parts["row_count"]
    bitmap_len = _bitmap_bytes(row_count)
    ctype = schema["columns"][ordinal]["type"]
    if kind == "flip_bitmap":
        row = op["row"]
        buffer[row // 8] ^= 1 << (row % 8)
    elif kind == "trailing_bit":
        if row_count % 8 == 0:
            raise PipelineError("bad_corrupt_op", "no trailing bits exist")
        buffer[bitmap_len - 1] |= 1 << (row_count % 8)
    elif kind == "null_slot_byte":
        row = op["row"]
        buffer[bitmap_len + row * FIXED_WIDTH[ctype]] = 1
    elif kind in ("offset_order", "offset_tail", "varlen_null_length", "units_lie", "f64_bits"):
        if ctype in VARLEN:
            offsets_at = bitmap_len
            offsets = list(struct.unpack_from("<%dQ" % (row_count + 1), buffer, offsets_at))
            values_at = offsets_at + (row_count + 1) * 8
            if kind == "offset_order":
                index = op["index"]
                offsets[index], offsets[index + 1] = offsets[index + 1], offsets[index]
                struct.pack_into("<%dQ" % (row_count + 1), buffer, offsets_at, *offsets)
            elif kind == "offset_tail":
                struct.pack_into("<Q", buffer, offsets_at + row_count * 8, offsets[-1] + op["delta"])
            elif kind == "varlen_null_length":
                row = op["row"]
                offsets[row + 1] += 1
                for later in range(row + 2, row_count + 1):
                    offsets[later] += 1
                struct.pack_into("<%dQ" % (row_count + 1), buffer, offsets_at, *offsets)
                insert_at = values_at + offsets[row]
                buffer[insert_at:insert_at] = b"\x00"
            elif kind == "units_lie":
                units_at = values_at + offsets[-1]
                row = op["row"]
                current = struct.unpack_from("<Q", buffer, units_at + row * 8)[0]
                struct.pack_into("<Q", buffer, units_at + row * 8, current + op["delta"])
        elif ctype == "f64" and kind == "f64_bits":
            row = op["row"]
            struct.pack_into("<Q", buffer, bitmap_len + row * 8, int(op["bits"], 16))
        else:
            raise PipelineError("bad_corrupt_op", f"{kind} does not apply to {ctype}")
    else:
        raise PipelineError("bad_corrupt_op", kind)
    buffers[ordinal] = bytes(buffer)
    head = bytearray(HEADER.pack(parts["magic"], parts["sequence"], row_count, parts["column_count"]))
    cursor = len(head) + sum(DESC_FIXED.size + len(d["name"].encode("utf-8")) + 16
                             for d in parts["descriptors"])
    descriptors = bytearray()
    for descriptor, buffer in zip(parts["descriptors"], buffers):
        name = descriptor["name"].encode("utf-8")
        descriptors.extend(DESC_FIXED.pack(descriptor["type_tag"], descriptor["flags"], len(name)))
        descriptors.extend(name)
        descriptors.extend(struct.pack("<QQ", cursor, len(buffer)))
        cursor += len(buffer)
    return bytes(head) + bytes(descriptors) + b"".join(buffers)


def infer_schema(columns: list[str], batches: list[dict], schema_id: str) -> dict:
    """Column types from the observed cells: one tag per column or a fail-closed error."""
    tags: list[set] = [set() for _ in columns]
    nullable = [False] * len(columns)
    for document in batches:
        if document["columns"] != columns:
            raise PipelineError("schema_mismatch", "a batch changed the column list")
        for row in document["rows"]:
            for ordinal, cell in enumerate(row):
                if cell["t"] == "null":
                    nullable[ordinal] = True
                else:
                    tags[ordinal].add(SDK_TO_WIRE[cell["t"]])
    schema_columns = []
    for ordinal, name in enumerate(columns):
        if len(tags[ordinal]) != 1:
            raise PipelineError("mixed_column_types", f"column {name} carries {sorted(tags[ordinal])}")
        schema_columns.append({"ordinal": ordinal, "stable_id": f"c{ordinal}", "name": name,
                               "type": next(iter(tags[ordinal])), "nullable": nullable[ordinal]})
    return {"schema_id": schema_id, "columns": schema_columns}


def wire_v1_digest(schema: dict, batches: list[tuple[int, list]]) -> str:
    """The documented mdd-wire/1 integrity digest, re-implemented independently:
    state0 = sha256('mdd-wire/1\\0digest\\0' + schema_canonical); each batch absorbs
    hex(state) + '|' + u64le(sequence) + u64le(rows) + the canonical cell bytes.
    `batches` is a list of (sequence, rows) so the batch's own sequence number is absorbed,
    not a positional counter. Text cells must be strict UTF-8 here; surrogate unit forms are
    not representable in this contract digest and callers check that before using it."""
    def lp(data: bytes) -> bytes:
        return struct.pack("<Q", len(data)) + data

    canonical = lp(schema["schema_id"].encode()) + struct.pack("<Q", len(schema["columns"]))
    for column in schema["columns"]:
        canonical += struct.pack("<I", column["ordinal"]) + lp(column["stable_id"].encode())
        canonical += bytes([TYPE_TAGS[column["type"]], 1 if column["nullable"] else 0])
    state = hashlib.sha256(b"mdd-wire/1\0digest\0" + canonical).hexdigest()
    for sequence, rows in batches:
        buffer = state.encode() + b"|" + struct.pack("<Q", sequence) + struct.pack("<Q", len(rows))
        for row in rows:
            for cell in row:
                tag = cell["t"]
                if tag == "null":
                    buffer += b"\x00"
                elif tag == "bool":
                    buffer += bytes([TYPE_TAGS["bool"], 1 if cell["v"] else 0])
                elif tag == "i64":
                    buffer += bytes([TYPE_TAGS["i64"]]) + struct.pack("<q", int(cell["v"]))
                elif tag == "u64":
                    buffer += bytes([TYPE_TAGS["u64"]]) + struct.pack("<Q", int(cell["v"]))
                elif tag == "f64":
                    buffer += bytes([TYPE_TAGS["f64"]]) + struct.pack("<Q", int(cell["bits"], 16))
                elif tag == "text":
                    if "units" in cell:
                        raise PipelineError("not_representable", "surrogate text in the wire-v1 digest")
                    buffer += bytes([TYPE_TAGS["utf8"]]) + lp(cell["v"].encode("utf-8"))
                elif tag == "bytes":
                    buffer += bytes([TYPE_TAGS["bytes"]]) + lp(bytes.fromhex(cell["v"]))
                elif tag == "dex_mutf8":
                    buffer += (bytes([TYPE_TAGS["dex_mutf8"]]) + lp(bytes.fromhex(cell["v"]))
                               + struct.pack("<Q", int(cell["utf16_units"])))
                else:
                    raise PipelineError("unknown_cell_tag", tag)
        state = hashlib.sha256(buffer).hexdigest()
    return state


# ---- encoding evaluation ----------------------------------------------------------

def evaluate_encodings(raw_batches: list[tuple[bytes, dict]], columns: list[str],
                       request_id: str | None = None) -> dict:
    """Compare the JSON batch representation with the columns-v1 candidate on the same
    typed cells: wire bytes, encode/parse/decode/materialize CPU, and fidelity. Any
    distortion vetoes the candidate outright."""
    documents = [document for _, document in raw_batches]
    schema = infer_schema(columns, documents, "mdd.sdk-batch.v1:columns-v1-eval")
    totals = {"json_body_bytes": 0, "columns_body_bytes": 0, "json_parse_seconds": 0.0,
              "columns_encode_seconds": 0.0, "columns_decode_seconds": 0.0,
              "json_materialize_seconds": 0.0, "columns_materialize_seconds": 0.0,
              "rows": 0, "batches": len(documents)}
    reserialization_mismatches = 0
    json_batch_rows: list[list] = []
    columns_batch_rows: list[list] = []
    per_batch = []
    for raw_line, document in raw_batches:
        body = json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        envelope = json.dumps({"kind": "batch", "id": request_id, "batch": document},
                              separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
        if envelope != raw_line:
            reserialization_mismatches += 1
        t0 = time.perf_counter()
        parsed = json.loads(body)
        t1 = time.perf_counter()
        json_rows = [[decode_cell(cell) for cell in row] for row in parsed["rows"]]
        t2 = time.perf_counter()
        blob = encode_columns(document["columns"], document["rows"],
                              sequence=int(document["sequence"]), schema=schema)
        t3 = time.perf_counter()
        decoded = decode_columns(blob, schema)
        t4 = time.perf_counter()
        columns_rows = [[decode_cell(cell) for cell in row] for row in decoded["rows"]]
        t5 = time.perf_counter()
        if decoded["columns"] != document["columns"]:
            raise PipelineError("fidelity_columns", "the candidate changed the column list")
        if decoded["row_count"] != document["row_count"] or len(decoded["rows"]) != len(document["rows"]):
            raise PipelineError("fidelity_row_count", "the candidate changed the row count")
        if canonical_rows(document["columns"], decoded["rows"]) != canonical_rows(document["columns"], document["rows"]):
            raise PipelineError("fidelity_cells", "the candidate changed a cell value, type or NULL")
        if rows_digest(document["columns"], decoded["rows"]) != rows_digest(document["columns"], document["rows"]):
            raise PipelineError("fidelity_digest", "the canonical digest differs after the candidate round trip")
        totals["json_body_bytes"] += len(body)
        totals["columns_body_bytes"] += len(blob)
        totals["json_parse_seconds"] += t1 - t0
        totals["json_materialize_seconds"] += t2 - t1
        totals["columns_encode_seconds"] += t3 - t2
        totals["columns_decode_seconds"] += t4 - t3
        totals["columns_materialize_seconds"] += t5 - t4
        totals["rows"] += len(document["rows"])
        json_batch_rows.append((int(document["sequence"]), document["rows"]))
        columns_batch_rows.append((int(decoded["sequence"]), decoded["rows"]))
        per_batch.append({"sequence": document["sequence"], "rows": len(document["rows"]),
                          "json_body_bytes": len(body), "columns_body_bytes": len(blob)})
    if rows_digest(columns, [row for _, batch in json_batch_rows for row in batch]) != \
            rows_digest(columns, [row for _, batch in columns_batch_rows for row in batch]):
        raise PipelineError("fidelity_digest", "the full-result canonical digest differs")
    wire_digest = None
    try:
        wire_digest = wire_v1_digest(schema, json_batch_rows)
        if wire_v1_digest(schema, columns_batch_rows) != wire_digest:
            raise PipelineError("fidelity_digest", "the mdd-wire/1 contract digest differs")
    except PipelineError as error:
        if error.code != "not_representable":
            raise
    return {"schema": schema, "totals": totals, "per_batch": per_batch,
            "reserialization_mismatches": reserialization_mismatches,
            "wire_v1_contract_digest": wire_digest,
            "fidelity": {"columns_equal": True, "row_count_equal": True, "canonical_cells_equal": True,
                         "canonical_digest_equal": True,
                         "full_result_digest": rows_digest(columns, [r for _, b in json_batch_rows for r in b])}}


def encoding_decision(evaluation: dict, *, binary_identity: dict, input_identity: dict,
                      load: dict, counterexample_fidelity: list, sources: dict) -> dict:
    totals = evaluation["totals"]
    json_bytes = totals["json_body_bytes"]
    columns_bytes = totals["columns_body_bytes"]
    json_path = totals["json_parse_seconds"] + totals["json_materialize_seconds"]
    columns_path = totals["columns_decode_seconds"] + totals["columns_materialize_seconds"]
    byte_advantage = columns_bytes < json_bytes
    cpu_advantage = columns_path < json_path
    reasons = [
        "fidelity verified on the full workload and the counterexamples: fields, types, NULL, "
        "duplicates, row count and canonical digest are identical after the columns-v1 round trip",
        f"wire bytes: json {json_bytes} vs columns-v1 {columns_bytes} "
        f"({columns_bytes / json_bytes:.3f}x)" if json_bytes else "wire bytes: empty workload",
        f"consumer CPU to the application object: json parse+materialize {json_path:.4f}s vs "
        f"columns decode+materialize {columns_path:.4f}s (encode adds "
        f"{totals['columns_encode_seconds']:.4f}s on the producer side)",
        "the engine's mdd-wire/1 hello offers encoding `json` only (conformance/protocol/wire-v1-cases.json "
        "negotiation cases); columns-v1 has no engine implementation, so no end-to-end advantage "
        "through the real OS pipe can be demonstrated without engine-side work, which this task does not do",
        "a consumer-side prototype's byte/CPU numbers are not an end-to-end result; RSS was measured "
        "separately per run and is never derived from encoding size",
    ]
    if not byte_advantage:
        reasons.append("the candidate is not smaller on this workload")
    if not cpu_advantage:
        reasons.append("the candidate's Python decode+materialize path is not faster than the JSON path")
    verdict = "disabled"
    if not evaluation["fidelity"]["canonical_digest_equal"]:
        verdict = "rejected_distortion"
    return {
        "schema_version": "mdd.encoding-decision.v1",
        "task": "MDD-044",
        "kind": "development evidence; diagnostic timing on a shared host, not a performance qualification",
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "binary": binary_identity,
        "input": input_identity,
        "workload": {"sql": WORKLOAD_SQL, "dialect": DIALECT, "rows": totals["rows"],
                     "batches": totals["batches"]},
        "candidate": {
            "name": "columns-v1",
            "status": "consumer-side prototype only; not implemented by the engine wire",
            "layout": "docs/02_ARCHITECTURE_AND_CONTRACTS.md 10.3: LE fixed-width values, validity bitmap "
                      "(1=non-NULL, LSB first, trailing bits zero), row_count+1 u64 offsets + contiguous bytes, "
                      "NULL rows zero-length/zeroed, f64 raw bits, dex_mutf8 raw bytes + u64 unit counts",
            "text_encoding": "utf-8/surrogatepass; unpaired surrogates recover as the UTF-16 unit cell form",
        },
        "measurements": totals,
        "fidelity": evaluation["fidelity"],
        "wire_v1_contract_digest": evaluation["wire_v1_contract_digest"],
        "reserialization_mismatches": evaluation["reserialization_mismatches"],
        "counterexample_fidelity": counterexample_fidelity,
        "verdict": verdict,
        "reasons": reasons,
        "mcp": "stays JSON; no binary encoding is offered on MCP stdout",
        "binary_channel": "binary/column encodings only via the dedicated worker/SDK channel (mdd-wire/1); "
                          "enabling columns-v1 there requires engine implementation and a fresh end-to-end "
                          "comparison, not this prototype",
        "load_conditions": load,
        "sources_sha256": sources,
        "reproduce": [
            "python -I benchmarks/producer-consumer-pipeline.py gen-cases",
            "MDD_WORKER_BINARY=<main-tree>/target/debug/meguvizdexdash.exe "
            "python -I benchmarks/producer-consumer-pipeline.py run --rounds 2",
            "python -I -m unittest discover -s benchmarks -p test_producer_consumer_pipeline.py -v",
            "python -I artifacts/mdd-044/mutation/mutate_pipeline.py",
        ],
    }


# ---- shared stream consumption ------------------------------------------------------

class StreamOutcome:
    def __init__(self, columns: tuple, decoded_rows: list, raw_batches: list, terminal: dict,
                 batch_bytes: int, resids: list, wait: float, opened_ts: float, terminal_ts: float):
        self.columns = columns
        self.decoded_rows = decoded_rows
        self.raw_batches = raw_batches
        self.terminal = terminal
        self.batch_bytes = batch_bytes
        self.residencies = resids
        self.consumer_wait_seconds = wait
        self.opened_ts = opened_ts
        self.terminal_ts = terminal_ts


def consume_query_stream(reader: LineReader, *, expected_rows: int | None,
                         deadline: float) -> StreamOutcome:
    """Consume opened -> batches -> terminal of one statement to the application object."""
    raw, arrival, consumed = reader.next(deadline)
    opened = json.loads(raw)
    if opened.get("kind") != "opened" or opened.get("protocol") != STREAM_PROTOCOL:
        raise PipelineError("protocol_fault", "the first line is not opened with mdd.cli-stream.v1")
    opened_ts = consumed
    columns: tuple = ()
    decoded_rows: list = []
    raw_batches: list = []
    batch_bytes = 0
    residencies: list = []
    next_sequence, next_row = 0, 0
    terminal = None
    while True:
        raw, arrival, consumed = reader.next(deadline)
        message = json.loads(raw)
        kind = message.get("kind")
        if kind == "terminal":
            terminal = message.get("terminal")
            terminal_ts = consumed
            break
        if kind == "rejected":
            raise PipelineError("rejected", json.dumps(message.get("error") or {}, ensure_ascii=False))
        if kind != "batch":
            raise PipelineError("protocol_fault", f"a {kind!r} line inside the query")
        document = message.get("batch")
        validate_batch_document(document)
        sequence, first_row = int(document["sequence"]), int(document["first_row"])
        if sequence != next_sequence or first_row != next_row:
            raise PipelineError("sequence_gap", f"batch {sequence} from {first_row}, expected {next_sequence} from {next_row}")
        next_sequence, next_row = sequence + 1, first_row + len(document["rows"])
        if columns and tuple(document["columns"]) != columns:
            raise PipelineError("schema_mismatch", "a batch changed the columns")
        columns = tuple(document["columns"])
        decoded_rows.extend(tuple(decode_cell(cell) for cell in row) for row in document["rows"])
        raw_batches.append((raw, document))
        batch_bytes += len(raw)
        residencies.append(consumed - arrival)
    completeness = require_complete(terminal, len(decoded_rows), expected_rows)
    return StreamOutcome(columns, decoded_rows, raw_batches, completeness, batch_bytes,
                         residencies, reader.consumer_wait_seconds, opened_ts, terminal_ts)


def _queue_stats(residencies: list, wait: float, model: str) -> dict:
    return {"model": model,
            "residency_seconds_total": sum(residencies),
            "residency_seconds_max": max(residencies) if residencies else 0.0,
            "residency_seconds_mean": (sum(residencies) / len(residencies)) if residencies else 0.0,
            "consumer_wait_seconds": wait, "queued_lines": len(residencies)}


def _kill(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.kill()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        pass


def _base_record(channel: str, workload: str, sql: str, identity: dict, load: dict,
                 round_no: int, extra: dict | None = None) -> dict:
    record = {"schema_version": "mdd.pipeline-run.v1", "task": "MDD-044",
              "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "channel": channel, "workload": workload, "sql": sql, "dialect": DIALECT,
              "round": round_no, "binary": identity["binary"], "input": identity["input"],
              "load_conditions": load,
              "timing_boundary": "t0 before engine process spawn; stop at the verified complete "
                                 "application object/terminal; teardown measured separately",
              "kind": "development evidence; not a performance qualification"}
    if extra:
        record.update(extra)
    return record


def _finish_stream_run(proc: subprocess.Popen, reader: LineReader, outcome: StreamOutcome,
                       sampler: RssSampler, t0: float, cpu0: float, teardown_start: float,
                       record: dict, *, expect_rc_zero: bool = True) -> dict:
    rc = proc.returncode
    if expect_rc_zero and rc != 0:
        raise PipelineError("producer_exit", f"the engine exited with {rc}")
    metrics = producer_metrics(proc, sampler)
    record["timing"] = {"total_seconds": time.perf_counter() - t0,
                        "startup_seconds": outcome.opened_ts - t0,
                        "answer_seconds": outcome.terminal_ts - outcome.opened_ts,
                        "teardown_seconds": time.perf_counter() - teardown_start}
    record["wire"] = {"bytes": reader.bytes, "batch_bytes": outcome.batch_bytes,
                      "lines": len(reader.arrivals), "batches": len(outcome.raw_batches)}
    record["queue"] = _queue_stats(outcome.residencies, outcome.consumer_wait_seconds,
                                   f"reader thread + bounded queue({QUEUE_DEPTH})")
    record["cpu"] = {"producer_user_seconds": metrics.get("producer_user_seconds"),
                     "producer_kernel_seconds": metrics.get("producer_kernel_seconds"),
                     "producer_cpu_seconds_sampled": metrics.get("producer_cpu_seconds_sampled"),
                     "consumer_seconds": time.process_time() - cpu0,
                     "producer_method": metrics["method"]}
    record["memory"] = {"producer_peak_working_set_bytes": metrics["producer_peak_working_set_bytes"],
                        **sampler.consumer_memory()}
    record["rows"] = len(outcome.decoded_rows)
    record["columns"] = list(outcome.columns)
    record["canonical_digest"] = rows_digest(outcome.columns, _raw_rows(outcome))
    record["app_digest"] = app_digest(outcome.columns, outcome.decoded_rows)
    record["statistics"] = row_statistics(outcome.columns, _raw_rows(outcome))
    record["completeness"] = outcome.terminal
    record["status"] = "ok"
    return record


def _raw_rows(outcome: StreamOutcome) -> list:
    return [row for _, document in outcome.raw_batches for row in document["rows"]]


def run_cli_stream(binary: Path, inputs: list[str], sql: str, *, identity: dict, load: dict,
                   round_no: int, workload: str, batch_rows: int, expected_rows: int | None,
                   serve: bool, extra_args: list[str] | None = None,
                   expect_failure: str | None = None) -> tuple[dict, StreamOutcome | None]:
    sampler = RssSampler()
    reader = None
    proc = None
    t0 = time.perf_counter()
    cpu0 = time.process_time()
    outcome = None
    try:
        with sampler:
            argv = [str(binary), "serve" if serve else "query"]
            for path in inputs:
                argv += ["--input", path]
            argv += ["--dialect", DIALECT]
            if not serve:
                argv += ["--sql", sql, "--format", "jsonl", "--batch-rows", str(batch_rows)]
            argv += list(extra_args or [])
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE if serve else subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            sampler.producer_pid = proc.pid
            reader = LineReader(proc.stdout)
            deadline = t0 + RUN_DEADLINE_SECONDS
            if serve:
                request = json.dumps({"id": "q1", "sql": sql, "batch_rows": batch_rows},
                                     separators=(",", ":")) + "\n"
                proc.stdin.write(request.encode("utf-8"))
                proc.stdin.flush()
            outcome = consume_query_stream(reader, expected_rows=expected_rows, deadline=deadline)
            if serve:
                proc.stdin.write(b'{"op":"close"}\n')
                proc.stdin.flush()
                proc.stdin.close()
            reader.expect_eof(deadline)
            rc = proc.wait(timeout=60)
            if rc != 0:
                raise PipelineError("producer_exit", f"the engine exited with {rc}",
                                    stderr=proc.stderr.read().decode("utf-8", "replace")[-2000:])
            teardown_start = time.perf_counter()
            channel = "cli-serve-raw" if serve else "cli-query"
            record = _base_record(channel, workload, sql, identity, load, round_no,
                                  {"batch_rows": batch_rows,
                                   "consumer_validation": "jsonschema mdd.sdk-batch.v1 on every batch + typed decode "
                                                          "(a consumer-side cost the SDK channel does not pay)"})
            record = _finish_stream_run(proc, reader, outcome, sampler, t0, cpu0, teardown_start, record)
            return record, outcome
    except PipelineError as error:
        if expect_failure is not None and error.code == expect_failure:
            record = _base_record("cli-query", workload, sql, identity, load, round_no,
                                  {"batch_rows": batch_rows, "extra_args": list(extra_args or [])})
            record["status"] = "expected_failure"
            record["expected_failure"] = expect_failure
            record["gate_error"] = {"code": error.code, "message": str(error), "details": error.details}
            record["rows_delivered_before_gate"] = None if outcome is None else len(outcome.decoded_rows)
            record["status_note"] = "the completeness gate refused a cut result; this is a pass of the negative control"
            return record, None
        raise
    finally:
        if reader is not None:
            reader.stop()
        if proc is not None:
            _kill(proc)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except (OSError, ValueError):
                        pass


# ---- the SDK worker channel (runtime instrumentation, no SDK file edits) ------------

class CountingStdout:
    """A pipe proxy that counts bytes and stamps arrivals; the SDK reader thread uses it
    exactly like the real stdout (readline/close)."""

    def __init__(self, real: Any):
        self._real = real
        self.arrivals: list[float] = []
        self.line_bytes: list[int] = []
        self.bytes = 0

    def readline(self, size: int = -1) -> bytes:
        data = self._real.readline(size)
        if data:
            self.arrivals.append(time.perf_counter())
            self.line_bytes.append(len(data))
            self.bytes += len(data)
        return data

    def close(self) -> None:
        self._real.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


class MeasuredWorker(mdd.Worker):
    """Worker with per-message consumption timestamps and channel wait time."""

    def __init__(self, *args: Any, **kwargs: Any):
        self.consumed: list[tuple[float, str]] = []
        self.wait_seconds = 0.0
        super().__init__(*args, **kwargs)

    def _next(self, deadline: float | None, *, during: str) -> dict:
        t0 = time.perf_counter()
        message = super()._next(deadline, during=during)
        now = time.perf_counter()
        self.wait_seconds += now - t0
        self.consumed.append((now, message.get("kind", "?")))
        return message


def run_sdk_worker(binary: Path, inputs: list[str], sql: str, *, identity: dict, load: dict,
                   round_no: int, workload: str, batch_rows: int,
                   expected_rows: int | None) -> dict:
    sampler = RssSampler()
    original_popen = mdd_worker.subprocess.Popen
    proxy_holder: dict = {}

    class InstrumentedPopen(original_popen):  # type: ignore[misc,valid-type]
        def __init__(self, *args: Any, **kwargs: Any):
            super().__init__(*args, **kwargs)
            if self.stdout is not None:
                proxy = CountingStdout(self.stdout)
                proxy_holder["proxy"] = proxy
                self.stdout = proxy

    mdd_worker.subprocess.Popen = InstrumentedPopen
    worker = None
    t0 = time.perf_counter()
    cpu0 = time.process_time()
    try:
        with sampler:
            worker = MeasuredWorker(inputs, dialect=DIALECT, binary=binary, startup_timeout=300.0)
            opened_ts = time.perf_counter()
            sampler.producer_pid = worker.pid
            query = worker.query(sql, batch_rows=batch_rows, timeout=RUN_DEADLINE_SECONDS)
            columns: tuple = ()
            decoded_rows: list = []
            batch_count = 0
            with query:
                for batch in query.batches():
                    columns = batch.columns
                    decoded_rows.extend(batch.rows)
                    batch_count += 1
                terminal = query.terminal
            completeness = require_complete(terminal, len(decoded_rows), expected_rows)
            answer_ts = time.perf_counter()
            teardown_start = time.perf_counter()
            worker.close()
            proxy = proxy_holder.get("proxy")
            if proxy is None:
                raise PipelineError("metrics_unavailable", "the stdout proxy was not installed")
            if len(proxy.arrivals) != len(worker.consumed):
                raise PipelineError("metrics_unavailable", "arrival/consumption logs disagree")
            residencies = [consumed_ts - proxy.arrivals[index]
                           for index, (consumed_ts, kind) in enumerate(worker.consumed) if kind == "batch"]
            batch_bytes = sum(proxy.line_bytes[index] for index, (_, kind) in enumerate(worker.consumed)
                              if kind == "batch")
            metrics = producer_metrics(worker._process, sampler)
            record = _base_record("sdk-worker", workload, sql, identity, load, round_no,
                                  {"batch_rows": batch_rows, "sdk": "python/mdd Worker (mdd.cli-stream.v1)",
                                   "instrumentation": "runtime stdout proxy + _next override; no SDK file edited",
                                   "consumer_validation": "typed decode only (SDK); no per-batch jsonschema"})
            record["timing"] = {"total_seconds": answer_ts - t0,
                                "startup_seconds": opened_ts - t0,
                                "answer_seconds": answer_ts - opened_ts,
                                "teardown_seconds": time.perf_counter() - teardown_start}
            record["wire"] = {"bytes": proxy.bytes, "batch_bytes": batch_bytes,
                              "lines": len(proxy.arrivals), "batches": batch_count}
            record["queue"] = _queue_stats(residencies, worker.wait_seconds,
                                           f"SDK reader thread + bounded queue({mdd_worker._QUEUE_LINES})")
            record["cpu"] = {"producer_user_seconds": metrics.get("producer_user_seconds"),
                             "producer_kernel_seconds": metrics.get("producer_kernel_seconds"),
                             "producer_cpu_seconds_sampled": metrics.get("producer_cpu_seconds_sampled"),
                             "consumer_seconds": time.process_time() - cpu0,
                             "producer_method": metrics["method"]}
            record["memory"] = {"producer_peak_working_set_bytes": metrics["producer_peak_working_set_bytes"],
                                **sampler.consumer_memory()}
            record["rows"] = len(decoded_rows)
            record["columns"] = list(columns)
            record["app_digest"] = app_digest(columns, decoded_rows)
            record["statistics_decoded"] = {"null_cells": sum(1 for row in decoded_rows for v in row if v is None),
                                            "rows": len(decoded_rows)}
            record["completeness"] = completeness
            record["status"] = "ok"
            return record
    finally:
        mdd_worker.subprocess.Popen = original_popen
        if worker is not None:
            worker.close()


# ---- the MCP channel -----------------------------------------------------------------

class MeasuredMcp(McpClient):
    """McpClient with byte counters, request latencies and a consumer-side deadline watchdog."""

    def __init__(self, *args: Any, deadline_seconds: float = RUN_DEADLINE_SECONDS, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.bytes_in = 0
        self.bytes_out = 0
        self.frames_in = 0
        self.frames_out = 0
        self.latencies: list[float] = []
        self._deadline_seconds = deadline_seconds

    def send_raw(self, line: bytes) -> None:
        self.bytes_out += len(line) + 1
        self.frames_out += 1
        super().send_raw(line)

    def read_message(self) -> dict:
        timer = threading.Timer(self._deadline_seconds, self.process.kill)
        timer.start()
        try:
            raw = self.process.stdout.readline()
        finally:
            timer.cancel()
        if not raw:
            raise PipelineError("eof_before_terminal",
                                "the MCP server closed stdout: "
                                + self.process.stderr.read().decode("utf-8", "replace")[-2000:])
        self.bytes_in += len(raw)
        self.frames_in += 1
        return json.loads(raw)

    def request(self, method: str, params: dict | None = None) -> dict:
        t0 = time.perf_counter()
        response = super().request(method, params)
        self.latencies.append(time.perf_counter() - t0)
        return response


def run_mcp(binary: Path, inputs: list[str], statements: list[tuple[str, str, int | None]], *,
            identity: dict, load: dict, round_no: int, page_limit: int) -> list[dict]:
    """One MCP session; each (workload, sql, expected_rows) statement is walked page by page
    to its exact total. Completeness here is the page-walk invariant set: contiguous offsets,
    exact total_rows, every page consumed, the last page untruncated with no next_offset."""
    sampler = RssSampler()
    client = None
    t0 = time.perf_counter()
    cpu0 = time.process_time()
    records = []
    try:
        with sampler:
            client = MeasuredMcp(binary, args=["--dialect", DIALECT])
            started_ts = time.perf_counter()
            sampler.producer_pid = client.process.pid
            client.initialize()
            opened = client.call("open_dataset", inputs=[str(path) for path in inputs])
            if opened.get("_is_error"):
                raise PipelineError("open_refused", json.dumps(opened.get("error") or {}, ensure_ascii=False))
            dataset = opened["dataset_id"]
            opened_ts = time.perf_counter()
            for workload, sql, expected_rows in statements:
                statement_t0 = time.perf_counter()
                columns: tuple = ()
                rows: list = []
                offset = 0
                pages = 0
                total = None
                while True:
                    reply = client.call("query", dataset_id=dataset, sql=[sql], limit=page_limit,
                                        offset=offset, timeout_ms=MCP_OPERATION_TIMEOUT_MS)
                    if reply.get("_is_error"):
                        raise PipelineError("query_refused", json.dumps(reply.get("error") or {}, ensure_ascii=False))
                    statement = reply["statements"][0]
                    pages += 1
                    if pages > 10000:
                        raise PipelineError("page_walk_runaway", "more than 10000 pages")
                    if statement["offset"] != offset:
                        raise PipelineError("offset_mismatch", f"page offset {statement['offset']} != {offset}")
                    page_columns = tuple(column["name"] for column in statement["columns"])
                    if columns and page_columns != columns:
                        raise PipelineError("schema_mismatch", "a page changed the columns")
                    columns = page_columns
                    page_rows = [[mcp_cell_to_sdk(cell) for cell in row] for row in statement["rows"]]
                    if len(page_rows) > page_limit:
                        raise PipelineError("page_over_limit", "a page returned more rows than the limit")
                    rows.extend(page_rows)
                    page_total = statement.get("total_rows")
                    if page_total is None:
                        raise PipelineError("missing_total", "MCP page without total_rows")
                    if total is not None and int(page_total) != total:
                        raise PipelineError("total_changed", "total_rows changed between pages")
                    total = int(page_total)
                    next_offset = statement["next_offset"]
                    if next_offset is None:
                        if statement["truncated"] is not False:
                            raise PipelineError("truncated", "the last page is still truncated")
                        if len(page_rows) != total - offset:
                            raise PipelineError("count_mismatch", "the last page does not complete the exact total")
                        break
                    if statement["truncated"] is not True:
                        raise PipelineError("page_invariant", "next_offset present but truncated is not true")
                    if len(page_rows) != page_limit:
                        raise PipelineError("count_mismatch", "a full page returned fewer rows than the limit")
                    if next_offset != offset + page_limit:
                        raise PipelineError("offset_mismatch", "next_offset does not continue the walk")
                    offset = next_offset
                if len(rows) != total:
                    raise PipelineError("count_mismatch", f"{len(rows)} rows consumed, exact total {total}")
                if expected_rows is not None and len(rows) != expected_rows:
                    raise PipelineError("row_count_mismatch", f"{len(rows)} rows, {expected_rows} expected")
                decoded = [tuple(decode_cell(cell) for cell in row) for row in rows]
                answer_ts = time.perf_counter()
                record = _base_record("mcp", workload, sql, identity, load, round_no,
                                      {"page_limit": page_limit, "pages": pages,
                                       "transport": "MCP JSON-RPC over stdio (JSON only)"})
                record["timing"] = {"total_seconds": answer_ts - t0,
                                    "startup_seconds": opened_ts - t0,
                                    "statement_seconds": answer_ts - statement_t0,
                                    "session_spawn_seconds": started_ts - t0}
                record["wire"] = {"bytes_in": client.bytes_in, "bytes_out": client.bytes_out,
                                  "frames_in": client.frames_in, "frames_out": client.frames_out,
                                  "note": "session-cumulative counters; per-statement deltas are not separated"}
                record["queue"] = {"model": "synchronous request/response; no consumer queue",
                                   "request_latency_seconds_total": sum(client.latencies),
                                   "request_latency_seconds_max": max(client.latencies) if client.latencies else 0.0,
                                   "requests": len(client.latencies)}
                record["rows"] = len(rows)
                record["columns"] = list(columns)
                record["canonical_digest"] = rows_digest(columns, rows)
                record["app_digest"] = app_digest(columns, decoded)
                record["statistics"] = row_statistics(columns, rows)
                record["completeness"] = {"page_walk": "complete", "total_rows": total,
                                          "total_rows_exact": True, "pages": pages,
                                          "last_page_truncated": False, "next_offset": None}
                record["status"] = "ok"
                records.append(record)
            teardown_start = time.perf_counter()
            rc = client.close()
            if rc != 0:
                raise PipelineError("producer_exit", f"the MCP server exited with {rc}")
            metrics = producer_metrics(client.process, sampler)
            for record in records:
                record["cpu"] = {"producer_user_seconds": metrics.get("producer_user_seconds"),
                                 "producer_kernel_seconds": metrics.get("producer_kernel_seconds"),
                                 "producer_cpu_seconds_sampled": metrics.get("producer_cpu_seconds_sampled"),
                                 "consumer_seconds": time.process_time() - cpu0,
                                 "producer_method": metrics["method"],
                                 "note": "session-level producer CPU and consumer CPU shared by the statements"}
                record["memory"] = {"producer_peak_working_set_bytes": metrics["producer_peak_working_set_bytes"],
                                    **sampler.consumer_memory()}
                record["timing"]["teardown_seconds"] = time.perf_counter() - teardown_start
            return records
    finally:
        if client is not None and client.process.poll() is None:
            client.process.kill()
            client.process.wait(timeout=30)


# ---- fixtures and counterexample expectations ------------------------------------------

def build_fixtures(directory: Path) -> dict:
    """Synthetic counterexample DEX files (tiny_dex layout, no engine import).

    uni.dex   one class with an accented/CJK/emoji method name and a non-ASCII literal.
    dup_a/b   identical bytes defining Ldemo/A;->foo()V: the same method defined in two
              files must stay two rows (physical dedup must not erase source occurrences).
    A lone-surrogate DEX name was probed and is refused by the engine at capture; surrogate
    fidelity is therefore exercised at the codec level (column-batch-cases.json), not here.
    """
    directory.mkdir(parents=True, exist_ok=True)
    uni = directory / "uni.dex"
    uni.write_bytes(tiny_dex.build("Ldemo/Ü;", [{
        "name": "méthode_中文😀", "access": 0x9, "registers": 1, "outs": 0,
        "code": [("const-string", 0, "é\U0001f600"), ("return-void",)]}]))
    dup_a = directory / "dup_a.dex"
    dup_b = directory / "dup_b.dex"
    dup_a.write_bytes(tiny_dex.foo_a())
    dup_b.write_bytes(tiny_dex.foo_a())
    paths = [str(uni), str(dup_a), str(dup_b)]
    digests = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (uni, dup_a, dup_b)}
    uni_name = "méthode_中文😀"
    uni_descriptor = f"Ldemo/Ü;->{uni_name}()V"
    export_rows = [
        [{"t": "u64", "v": "0"}, {"t": "text", "v": "Ldemo/Ü;"}, {"t": "u64", "v": "0"},
         {"t": "text", "v": uni_name}, {"t": "text", "v": uni_descriptor}],
        [{"t": "u64", "v": "1"}, {"t": "text", "v": "Ldemo/A;"}, {"t": "u64", "v": "0"},
         {"t": "text", "v": "foo"}, {"t": "text", "v": "Ldemo/A;->foo()V"}],
        [{"t": "u64", "v": "2"}, {"t": "text", "v": "Ldemo/A;"}, {"t": "u64", "v": "0"},
         {"t": "text", "v": "foo"}, {"t": "text", "v": "Ldemo/A;->foo()V"}],
    ]
    # every fixture method has method_idx 0, so maybe_null is NULL for all three rows; the
    # method_name column still carries each file's own name (uni is not "foo")
    null_rows = [[{"t": "null"}, {"t": "text", "v": ""}, {"t": "text", "v": name}]
                 for name in (uni_name, "foo", "foo")]
    return {"paths": paths, "digests": digests,
            "fixture_identity": {"kind": "synthetic", "generator": "conformance/mcp/tiny_dex.py build/foo_a",
                                 "sha256": digests, "paths_placeholder": "artifacts/local/mdd-044-fixtures/"},
            "expected": {"counterexample-export": export_rows, "counterexample-null": null_rows}}


def check_counterexample(record: dict, expected_rows: list, label: str) -> dict:
    """Independent expectations: the decoded application object must equal the recipe's rows,
    NULL must stay None, '' must stay '', duplicates must keep their multiplicity."""
    raise_if(record.get("status") != "ok", "counterexample_status", f"{label}: run did not succeed")
    columns = record["columns"]
    expected_columns = {
        "counterexample-export": ["file_id", "class_descriptor", "method_idx", "method_name", "method_descriptor"],
        "counterexample-null": ["maybe_null", "empty_text", "method_name"],
    }[label]
    raise_if(columns != expected_columns, "counterexample_columns", f"{label}: {columns}")
    expected_digest = rows_digest(expected_columns, expected_rows)
    raise_if(record.get("canonical_digest") != expected_digest, "counterexample_digest",
             f"{label}: canonical digest differs from the recipe expectation")
    decoded_expected = [tuple(decode_cell(cell) for cell in row) for row in expected_rows]
    raise_if(record.get("app_digest") != app_digest(expected_columns, decoded_expected),
             "counterexample_app_digest", f"{label}: application digest differs")
    stats = record.get("statistics") or {}
    if label == "counterexample-null":
        raise_if(stats.get("null_cells") != len(expected_rows), "counterexample_nulls",
                 f"{label}: expected {len(expected_rows)} NULL cells")
        raise_if(stats.get("type_census", {}).get("empty_text", {}).get("text") != len(expected_rows),
                 "counterexample_empty", f"{label}: empty strings must stay text cells")
    if label == "counterexample-export":
        keys = [(row[1]["v"], row[2]["v"], row[3]["v"], row[4]["v"]) for row in expected_rows]
        duplicates = len(keys) - len(set(keys))
        raise_if(duplicates != 1, "counterexample_duplicate_recipe", "the recipe itself must carry one duplicate pair")
        raise_if(stats.get("duplicate_rows") != 0, "counterexample_fullrow",
                 f"{label}: full rows differ by file_id; none may be merged")
    return {"label": label, "expected_rows": len(expected_rows), "expected_digest": expected_digest,
            "matched": True}


def raise_if(condition: bool, code: str, message: str) -> None:
    if condition:
        raise PipelineError(code, message)


# ---- conformance cases for the candidate codec ------------------------------------------

def _schema(columns: list[tuple[str, str, bool]], schema_id: str = "mdd.rows.v1:column-case") -> dict:
    return {"schema_id": schema_id,
            "columns": [{"ordinal": i, "stable_id": f"s{i}", "name": name, "type": ctype, "nullable": nullable}
                        for i, (name, ctype, nullable) in enumerate(columns)]}


def _c_null() -> dict: return {"t": "null"}
def _c_bool(v: bool) -> dict: return {"t": "bool", "v": v}
def _c_i64(v: int) -> dict: return {"t": "i64", "v": str(v)}
def _c_u64(v: int) -> dict: return {"t": "u64", "v": str(v)}
def _c_f64(bits: int) -> dict: return {"t": "f64", "bits": "%016x" % bits}
def _c_text(v: str) -> dict: return {"t": "text", "v": v}
def _c_units(v: str) -> dict: return {"t": "text", "units": v}
def _c_bytes(v: bytes) -> dict: return {"t": "bytes", "v": v.hex()}
def _c_mutf8(v: bytes, units: int) -> dict: return {"t": "dex_mutf8", "v": v.hex(), "utf16_units": str(units)}


def column_batch_cases() -> dict:
    cases: list[dict] = []

    def roundtrip(name: str, schema: dict, rows: list, sequence: int = 0) -> None:
        cases.append({"name": name, "schema": schema, "sequence": sequence, "rows": rows,
                      "expect": {"roundtrip": True}})

    def corrupt(name: str, schema: dict, rows: list, op: dict, error: str) -> None:
        cases.append({"name": name, "schema": schema, "sequence": 0, "rows": rows,
                      "expect": {"error": error, "corrupt": op}})

    wide = _schema([("b", "bool", True), ("i", "i64", True), ("u", "u64", True), ("f", "f64", True),
                    ("s", "utf8", True), ("y", "bytes", True), ("m", "dex_mutf8", True)])
    full_row = [_c_bool(True), _c_i64(-(2**63)), _c_u64(2**64 - 1), _c_f64(0x7FF8000000000001),
                _c_text("é\U0001f600"), _c_bytes(b"\x00\xff"), _c_mutf8(b"\xed\xa0\x80", 1)]
    null_row = [_c_null()] * 7
    empties = [_c_bool(False), _c_i64(0), _c_u64(0), _c_f64(0x8000000000000000),
               _c_text(""), _c_bytes(b""), _c_mutf8(b"", 0)]
    roundtrip("every_type_null_empty_extremes_and_duplicates", wide,
              [full_row, null_row, empties, full_row])
    roundtrip("zero_rows", _schema([("n", "i64", False)]), [])
    one = _schema([("n", "i64", False)])
    roundtrip("duplicate_rows_kept", one, [[_c_i64(1)], [_c_i64(2)], [_c_i64(2)], [_c_i64(1)]])
    roundtrip("nonzero_sequence_preserved", one, [[_c_i64(1)], [_c_i64(2)]], sequence=2)
    text_col = _schema([("s", "utf8", True)])
    roundtrip("null_vs_empty_string", text_col,
              [[_c_null()], [_c_text("")], [_c_null()], [_c_text("x")], [_c_text("")]])
    roundtrip("unicode_cjk_emoji_accents", text_col,
              [[_c_text("中文😀éÜ")], [_c_text("")], [_c_text("plain")]])
    roundtrip("unpaired_surrogate_unit_forms", text_col,
              [[_c_units("d800")], [_c_text("a\ud800b")], [_c_units("dc00")], [_c_text("ok")]])
    roundtrip("mutf8_embedded_nul_and_surrogates", _schema([("m", "dex_mutf8", True)]),
              [[_c_mutf8(b"\xc0\x80", 1)], [_c_mutf8(b"\xed\xa0\x81", 1)], [_c_mutf8(b"ab", 2)], [_c_null()]])
    roundtrip("f64_nan_payloads_infinities_and_minus_zero", _schema([("f", "f64", True)]),
              [[_c_f64(0x7FF8000000000001)], [_c_f64(0x7FF8000000000002)], [_c_f64(0x7FF0000000000000)],
               [_c_f64(0xFFF0000000000000)], [_c_f64(0x8000000000000000)], [_c_f64(0x0000000000000001)],
               [_c_null()]])
    roundtrip("integer_extremes", _schema([("i", "i64", True), ("u", "u64", True)]),
              [[_c_i64(-(2**63)), _c_u64(0)], [_c_i64(2**63 - 1), _c_u64(2**64 - 1)],
               [_c_i64(0), _c_null()], [_c_null(), _c_u64(0)]])
    roundtrip("all_byte_values", _schema([("y", "bytes", True)]),
              [[_c_bytes(bytes(range(256)))], [_c_bytes(b"")], [_c_null()]])
    dup_names = {"schema_id": "mdd.rows.v1:dup-names",
                 "columns": [{"ordinal": 0, "stable_id": "a", "name": "same", "type": "i64", "nullable": False},
                             {"ordinal": 1, "stable_id": "b", "name": "same", "type": "utf8", "nullable": False}]}
    roundtrip("display_names_may_repeat", dup_names, [[_c_i64(7), _c_text("seven")]])
    generated = [[_c_i64(index - 250), _c_text(f"row-{index}-é"), _c_null() if index % 7 == 0 else _c_u64(index)]
                 for index in range(500)]
    roundtrip("five_hundred_generated_rows",
              _schema([("i", "i64", False), ("s", "utf8", False), ("u", "u64", True)]), generated)

    # corruption cases: decode must refuse, or fidelity must catch the distortion
    corrupt("err_bad_magic", one, [[_c_i64(1)]], {"op": "magic"}, "magic")
    corrupt("err_truncated_body", one, [[_c_i64(1)]], {"op": "truncate", "keep": 10}, "truncated_body")
    corrupt("err_row_count_lies", one, [[_c_i64(1)], [_c_i64(2)]], {"op": "row_count", "delta": 1}, "count_mismatch")
    corrupt("err_descriptor_type_changed", one, [[_c_i64(1)]],
            {"op": "descriptor_type", "column": 0, "type": "u64"}, "schema_mismatch")
    corrupt("err_bitmap_trailing_bit_set", one, [[_c_i64(1)], [_c_i64(2)], [_c_i64(3)]],
            {"op": "trailing_bit", "column": 0}, "bitmap_padding")
    corrupt("err_null_slot_not_zeroed", _schema([("n", "i64", True)]), [[_c_null()], [_c_i64(5)]],
            {"op": "null_slot_byte", "column": 0, "row": 0}, "null_padding")
    corrupt("err_offsets_not_monotonic", text_col, [[_c_text("aa")], [_c_text("b")], [_c_text("ccc")]],
            {"op": "offset_order", "column": 0, "index": 1}, "offset_order")
    corrupt("err_tail_offset_wrong", text_col, [[_c_text("aa")], [_c_text("b")]],
            {"op": "offset_tail", "column": 0, "delta": 1}, "offset_tail")
    corrupt("err_null_varlen_row_carries_bytes", text_col, [[_c_null()], [_c_text("x")]],
            {"op": "varlen_null_length", "column": 0, "row": 0}, "null_padding")
    corrupt("err_mutf8_units_lie", _schema([("m", "dex_mutf8", True)]), [[_c_mutf8(b"\xc0\x80", 1)]],
            {"op": "units_lie", "column": 0, "row": 0, "delta": 1}, "cell_type_mismatch")
    corrupt("err_f64_nan_payload_changed", _schema([("f", "f64", True)]), [[_c_f64(0x7FF8000000000001)]],
            {"op": "f64_bits", "column": 0, "row": 0, "bits": "7ff8000000000002"}, "fidelity_mismatch")
    corrupt("err_null_becomes_empty_string", text_col, [[_c_null()], [_c_text("x")]],
            {"op": "flip_bitmap", "column": 0, "row": 0}, "fidelity_mismatch")
    corrupt("err_null_becomes_zero", _schema([("n", "i64", True)]), [[_c_null()], [_c_i64(5)]],
            {"op": "flip_bitmap", "column": 0, "row": 0}, "fidelity_mismatch")
    return {
        "schema_version": "mdd.column-batch-cases.v1",
        "task": "MDD-044",
        "generator": "benchmarks/producer-consumer-pipeline.py gen-cases",
        "candidate": "columns-v1 consumer prototype over mdd.sdk-batch.v1 typed cells",
        "layout": "docs/02_ARCHITECTURE_AND_CONTRACTS.md 10.3; body: MDC1 magic, u64 sequence, u64 row_count, "
                  "u32 column_count, descriptors (u8 type, u8 flags, u16 name_len, name, u64 offset, u64 length), "
                  "then per-column buffers: validity bitmap (1=non-NULL, LSB first, trailing bits zero), "
                  "fixed-width LE values with zeroed NULL slots, or (row_count+1) u64 offsets + contiguous bytes "
                  "(+ u64 utf16_units per row for dex_mutf8); NULL varlen rows are zero-length",
        "text_encoding": "utf-8/surrogatepass; unpaired surrogates recover as the UTF-16 unit cell form",
        "fidelity_rule": "decoded cells must equal the canonical form of the source cells (types, NULL, order, "
                         "duplicates, values); the canonical digest and, where representable, the mdd-wire/1 "
                         "contract digest must be unchanged; `fidelity_mismatch` cases decode successfully but "
                         "must fail that comparison",
        "cases": cases,
    }


CASES_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["schema_version", "cases"],
    "properties": {
        "schema_version": {"const": "mdd.column-batch-cases.v1"},
        "cases": {"type": "array", "minItems": 1, "items": {
            "type": "object",
            "required": ["name", "schema", "sequence", "rows", "expect"],
            "properties": {
                "name": {"type": "string"},
                "sequence": {"type": "integer", "minimum": 0},
                "schema": {"type": "object", "required": ["schema_id", "columns"]},
                "rows": {"type": "array"},
                "expect": {"type": "object", "oneOf": [
                    {"required": ["roundtrip"], "properties": {"roundtrip": {"const": True}}},
                    {"required": ["error", "corrupt"], "properties": {"error": {"type": "string"}}},
                ]},
            },
        }},
    },
}


# ---- identity and driver ----------------------------------------------------------------

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_public_apk(explicit: str | None) -> tuple[Path, dict]:
    manifest = json.loads((ROOT / CORPUS_MANIFEST).read_text(encoding="utf-8"))
    entry = next((item for item in manifest["inputs"] if item["id"] == PUBLIC_INPUT_ID), None)
    if entry is None or entry.get("visibility") != "public":
        raise PipelineError("corpus_manifest", "the public input entry is missing")
    candidates = [Path(explicit)] if explicit else []
    candidates.append(ROOT / entry["local_path"])
    if len(ROOT.parents) >= 3:
        candidates.append(ROOT.parents[2] / entry["local_path"])
    chosen = next((path for path in candidates if path.is_file()), None)
    if chosen is None:
        raise PipelineError("input_missing",
                            "the public APK is not present; fetch the official origin_url in the manifest "
                            "into artifacts/local/inputs (ignored) and verify its identity")
    size = chosen.stat().st_size
    digest = sha256_file(chosen)
    if digest != entry["expected_sha256"] or size != entry["expected_bytes"]:
        raise PipelineError("input_identity", "the local bytes do not match the pinned digest/size",
                            expected_sha256=entry["expected_sha256"], actual_sha256=digest,
                            expected_bytes=entry["expected_bytes"], actual_bytes=size)
    return chosen, {"id": entry["id"], "sha256": digest, "bytes": size,
                    "path_placeholder": entry["local_path"], "visibility": "public",
                    "origin_url": entry["origin_url"]}


def binary_identity(binary: Path) -> dict:
    if not binary.is_file():
        raise PipelineError("binary_missing", str(binary))
    capabilities = subprocess.run([str(binary), "capabilities"], capture_output=True, timeout=120)
    if capabilities.returncode != 0:
        raise PipelineError("binary_refused", capabilities.stderr.decode("utf-8", "replace")[-2000:])
    document = json.loads(capabilities.stdout)
    return {"sha256": sha256_file(binary), "build_id": document["build_id"],
            "engine_version": document["engine_version"],
            "transports": document["transports"],
            "path_placeholder": "target/debug/meguvizdexdash (main tree, read-only; MDD_WORKER_BINARY)"}


def default_binary() -> Path:
    explicit = os.environ.get("MDD_WORKER_BINARY")
    if explicit:
        return Path(explicit)
    name = "meguvizdexdash.exe" if os.name == "nt" else "meguvizdexdash"
    for root in [ROOT, ROOT.parents[2] if len(ROOT.parents) >= 3 else ROOT]:
        candidate = root / "target" / "debug" / name
        if candidate.is_file():
            return candidate
    raise PipelineError("binary_missing", "set MDD_WORKER_BINARY or pass --binary")


def sources_sha256() -> dict:
    files = ["benchmarks/producer-consumer-pipeline.py",
             "benchmarks/test_producer_consumer_pipeline.py",
             "conformance/protocol/column-batch-cases.json"]
    out = {}
    for relative in files:
        path = ROOT / relative
        if path.is_file():
            out[relative] = sha256_file(path)
    return out


def run_all(args: argparse.Namespace) -> int:
    binary = Path(args.binary) if args.binary else default_binary()
    apk, input_identity = resolve_public_apk(args.apk)
    identity = {"binary": binary_identity(binary), "input": input_identity}
    load = load_snapshot()
    fixtures_dir = Path(args.fixtures_dir) if args.fixtures_dir else Path(
        os.environ.get("MDD044_FIXTURES", str(ROOT / "artifacts" / "local" / "mdd-044-fixtures")))
    fixtures = build_fixtures(fixtures_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    big_outcomes: dict[str, StreamOutcome] = {}
    workload_identity = dict(identity)

    print(f"binary {identity['binary']['build_id']} sha256 {identity['binary']['sha256'][:16]}...")
    print(f"input {input_identity['id']} sha256 verified ({input_identity['bytes']} bytes)")

    fixture_identity = {"binary": identity["binary"], "input": fixtures["fixture_identity"]}
    for round_no in range(1, args.rounds + 1):
        record, outcome = run_cli_stream(binary, [str(apk)], WORKLOAD_SQL, identity=workload_identity,
                                         load=load, round_no=round_no, workload="public-method-export",
                                         batch_rows=args.batch_rows, expected_rows=EXPECTED_WORKLOAD_ROWS,
                                         serve=False)
        records.append(record)
        print(f"cli-query round {round_no}: rows={record['rows']} wire={record['wire']['bytes']} "
              f"total={record['timing']['total_seconds']:.3f}s")
        record, outcome = run_cli_stream(binary, [str(apk)], WORKLOAD_SQL, identity=workload_identity,
                                         load=load, round_no=round_no, workload="public-method-export",
                                         batch_rows=args.batch_rows, expected_rows=EXPECTED_WORKLOAD_ROWS,
                                         serve=True)
        records.append(record)
        if round_no == 1:
            big_outcomes["serve"] = outcome
        print(f"cli-serve-raw round {round_no}: rows={record['rows']} wire={record['wire']['bytes']} "
              f"total={record['timing']['total_seconds']:.3f}s")
        record = run_sdk_worker(binary, [str(apk)], WORKLOAD_SQL, identity=workload_identity,
                                load=load, round_no=round_no, workload="public-method-export",
                                batch_rows=args.batch_rows, expected_rows=EXPECTED_WORKLOAD_ROWS)
        records.append(record)
        print(f"sdk-worker round {round_no}: rows={record['rows']} wire={record['wire']['bytes']} "
              f"total={record['timing']['total_seconds']:.3f}s")
        mcp_records = run_mcp(binary, [str(apk)],
                              [("public-method-export", WORKLOAD_SQL, EXPECTED_WORKLOAD_ROWS)],
                              identity=workload_identity, load=load, round_no=round_no,
                              page_limit=args.page_limit)
        records.extend(mcp_records)
        print(f"mcp round {round_no}: rows={mcp_records[0]['rows']} pages={mcp_records[0]['pages']} "
              f"in={mcp_records[0]['wire']['bytes_in']}")

    # cross-channel equality on the full workload
    digests = {record["canonical_digest"] for record in records
               if record["workload"] == "public-method-export" and record["status"] == "ok"
               and "canonical_digest" in record}
    raise_if(len(digests) != 1, "cross_channel_digest", f"canonical digests differ across channels: {digests}")
    app_digests = {record["app_digest"] for record in records
                   if record["workload"] == "public-method-export" and record["status"] == "ok"}
    raise_if(len(app_digests) != 1, "cross_channel_app_digest", "application digests differ across channels")
    row_counts = {record["rows"] for record in records
                  if record["workload"] == "public-method-export" and record["status"] == "ok"}
    raise_if(row_counts != {EXPECTED_WORKLOAD_ROWS}, "cross_channel_rows", f"row counts differ: {row_counts}")

    # counterexamples through every channel
    counterexample_fidelity = []
    for channel in ("cli-query", "cli-serve-raw", "sdk-worker", "mcp"):
        for label, sql in (("counterexample-export", WORKLOAD_SQL), ("counterexample-null", NULL_SQL)):
            expected = fixtures["expected"][label]
            if channel == "mcp":
                mcp_records = run_mcp(binary, fixtures["paths"], [(label, sql, len(expected))],
                                      identity=fixture_identity, load=load, round_no=1,
                                      page_limit=args.page_limit)
                record = mcp_records[0]
            elif channel == "sdk-worker":
                record = run_sdk_worker(binary, fixtures["paths"], sql, identity=fixture_identity,
                                        load=load, round_no=1, workload=label,
                                        batch_rows=args.batch_rows, expected_rows=len(expected))
                record["canonical_digest"] = None  # the SDK decodes cells; the app digest carries the comparison
            else:
                record, _ = run_cli_stream(binary, fixtures["paths"], sql, identity=fixture_identity,
                                           load=load, round_no=1, workload=label,
                                           batch_rows=args.batch_rows, expected_rows=len(expected),
                                           serve=(channel == "cli-serve-raw"))
            records.append(record)
            if channel == "sdk-worker":
                decoded_expected = [tuple(decode_cell(cell) for cell in row) for row in expected]
                columns = record["columns"]
                raise_if(record["app_digest"] != app_digest(columns, decoded_expected),
                         "counterexample_app_digest", f"{channel}/{label}: application digest differs")
                counterexample_fidelity.append({"channel": channel, "label": label,
                                                "expected_rows": len(expected), "matched": True,
                                                "comparison": "app_digest (SDK decodes cells)"})
            else:
                counterexample_fidelity.append({"channel": channel, **check_counterexample(record, expected, label)})
            print(f"{channel} {label}: ok")

    # negative control: a cut result must never pass the completeness gate. --max-rows makes the
    # engine emit operation_status=error (QUOTA_EXCEEDED) with truncated=true; the gate refuses it
    # on operation_status first (the truncated=True path is covered separately in the unit matrix).
    record, _ = run_cli_stream(binary, [str(apk)], WORKLOAD_SQL, identity=workload_identity,
                               load=load, round_no=1, workload="negative-control-truncation",
                               batch_rows=args.batch_rows, expected_rows=None, serve=False,
                               extra_args=["--max-rows", "10"], expect_failure="operation_not_ok")
    records.append(record)
    raise_if(record["status"] != "expected_failure", "negative_control", "the truncation gate did not fire")
    print("negative control: cut result (QUOTA_EXCEEDED/truncated) refused by the gate")

    # encoding evaluation on the real captured batches
    outcome = big_outcomes["serve"]
    evaluation = evaluate_encodings(outcome.raw_batches, list(outcome.columns), request_id="q1")
    decision = encoding_decision(evaluation, binary_identity=identity["binary"],
                                 input_identity=input_identity, load=load,
                                 counterexample_fidelity=counterexample_fidelity,
                                 sources=sources_sha256())
    decision["cross_channel"] = {"canonical_digest": next(iter(digests)),
                                 "app_digest": next(iter(app_digests)),
                                 "rows": EXPECTED_WORKLOAD_ROWS,
                                 "channels": ["cli-query", "cli-serve-raw", "sdk-worker", "mcp"]}
    decision["negative_controls"] = [{"name": "quota_truncation_gate", "status": "passed",
                                      "detail": "--max-rows 10 -> QUOTA_EXCEEDED/truncated terminal refused by require_complete"}]
    decision["not_run"] = [
        "in-process C ABI SDK (python/mdd core) for this workload: the FFI session dialect is fixed to "
        "native-v1, which has no class_methods relation; the dexsql contract dialect is only offered by "
        "CLI/serve/MCP, and engine-side changes are out of this task's scope. The SDK OS-pipe path is "
        "covered by mdd.worker.",
        "a columns-v1 end-to-end run through the engine: the wire negotiation offers json only; the "
        "candidate is a consumer-side prototype, so its numbers are representation-level, not pipe-level",
        "exclusive-window performance qualification (MDD-060/082)",
    ]
    runs_path = out_dir / "pipeline-runs.jsonl"
    with runs_path.open("a", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    decision_path = out_dir / "encoding-decision.json"
    decision_path.write_text(json.dumps(decision, ensure_ascii=False, indent=1) + "\n",
                             encoding="utf-8", newline="\n")
    print(f"wrote {runs_path} ({len(records)} records appended) and {decision_path}")
    totals = evaluation["totals"]
    print(f"encoding: json {totals['json_body_bytes']} B vs columns {totals['columns_body_bytes']} B; "
          f"json path {totals['json_parse_seconds'] + totals['json_materialize_seconds']:.4f}s vs "
          f"columns path {totals['columns_decode_seconds'] + totals['columns_materialize_seconds']:.4f}s; "
          f"verdict {decision['verdict']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=["run", "gen-cases"])
    parser.add_argument("--binary")
    parser.add_argument("--apk")
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--batch-rows", type=int, default=1000)
    parser.add_argument("--page-limit", type=int, default=1000)
    parser.add_argument("--out-dir", default=str(ROOT / "artifacts" / "mdd-044"))
    parser.add_argument("--fixtures-dir")
    parser.add_argument("--cases-out", default=str(ROOT / "conformance" / "protocol" / "column-batch-cases.json"))
    args = parser.parse_args()
    if args.mode == "gen-cases":
        document = column_batch_cases()
        jsonschema.Draft202012Validator(CASES_SCHEMA).validate(document)
        path = Path(args.cases_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        # ensure_ascii: the surrogate unit-form cases carry lone surrogates, which strict
        # UTF-8 cannot encode; \udXXX escapes keep the file valid JSON and lossless.
        path.write_text(json.dumps(document, ensure_ascii=True, indent=1) + "\n", encoding="utf-8", newline="\n")
        print(f"wrote {path} ({len(document['cases'])} cases)")
        return 0
    return run_all(args)


if __name__ == "__main__":
    sys.exit(main())