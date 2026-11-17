"""HostLab's `native_session` for the MeguvizDexDash engine (MDD-051). Integration layer; standard library only.

HostLab's structural audit (`native_graph`, `native_rules`, `native_audit`, `native_surface`) is written against
a small surface: `literal` and `in_list` to build SQL, and `NativeSession(apk, timeout=, threads=)`, a context
manager with `files`, `apk`, `opened`, `queries`, `rows(sql, ...)` and `all(sql, ...)`, whose rows are dicts of
`str` or `None`. In HostLab, `NativeSession` is `native_cli.CliSession`, an owned DexSQL process that is driven
through Unicode tables and a boundary marker. This module is a drop-in for the whole `native_session` module,
so that the Graph and the 27 FEATURE rules run unchanged:

* `literal`, `in_list` are HostLab's, with the same behaviour (the tests compare them to the frozen source).
* `NativeSession(...)` looks at the provider setting `native_engine` first. `dexsql` (the default, and the
  rollback value) returns HostLab's own `native_cli.CliSession` and starts nothing of ours; `meguvizdexdash`
  returns one of the two sessions below, on the wire chosen by the structural setting `wire`.
* `B0Session` keeps what the consumer sees and sends: the same statements in the same order (the `LIMIT 0`
  shape query, then the hex projection `CASE WHEN c IS NULL THEN 'N' ELSE hex(CAST(c AS TEXT)) END`), the same
  guards (stable ordering, unambiguous columns, complete row and byte budgets, strict UTF-8), the same DTO.
  Only the wire differs: framed JSON lines of `meguvizdexdash serve` instead of Unicode tables.
* `B1Session` reads the typed batches directly: no shape query, no hex round trip, the DTO built from typed
  cells, and a `batches()` iterator for consumers that want the typed values. It builds the same DTO as B0 for
  the cells the audit reads (NULL, integers, text) and refuses the others instead of rendering them.

Both sessions treat the engine's answer the way the engine states it. A statement that the engine rejects, that
it did not finish, whose coverage is not complete, whose row count disagrees with its frames, or a process that
goes away before the terminal frame raises an `EngineError`; none of these is ever returned as a shorter list of
rows, and none is a business verdict. `WIRE_CHANGES` registers every difference from DexSQL's transport.

This module contains no knowledge of the audited application.
"""
from __future__ import annotations

import importlib
import json
import os
import queue
import re
import struct
import subprocess
import threading
import time
from concurrent.futures import Future, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import provider

STREAM_PROTOCOL = "mdd.cli-stream.v1"
BATCH_SCHEMA = "mdd.sdk-batch.v1"
STRUCTURAL_SCHEMA = "mdd.hostlab-structural-config.v1"
ENV_STRUCTURAL = "HOSTLAB_STRUCTURAL_CONFIG"
WIRES = ("b0", "b1")
MAX_SQL_BYTES = 256 * 1024          # HostLab's statement budget (native_cli.CliSession.write)
MAX_LINE_BYTES = 64 * 1024 * 1024   # one frame; HostLab's budget is 4 MiB per table row, a frame holds a batch of rows
MAX_RESPONSE_BYTES = 512 * 1024 * 1024
QUEUE_SLOTS = 8
SQL_LIMIT_KEYS = ("steps", "scanned_rows", "result_rows")
INCOMPLETE_CODES = ("INCOMPLETE_FACTS", "PARTIAL_INPUT")


# ---- SQL literals: HostLab's, unchanged ------------------------------------------------------------------

def literal(value):
    if any(c in value for c in "\r\n\0"):
        raise ValueError("audit SQL literal contains unsupported control characters")
    return "'" + value.replace("'", "''") + "'"


def in_list(values):
    return ",".join(literal(value) for value in values)


# ---- errors ------------------------------------------------------------------------------------------------
# EngineError is a RuntimeError, as every failure of HostLab's CliSession is. `detail["error"]["code"]` is where
# provider.classify_failure looks for the engine's code, so an engine failure is classified by what the engine
# said and anything else stays UNCLASSIFIED.

class EngineError(RuntimeError):
    code = "INTERNAL_FAULT"
    stage = "hostlab.session"

    def __init__(self, message: str, *, code: "str | None" = None, stage: "str | None" = None,
                 body: "dict | None" = None, detail: "dict | None" = None):
        super().__init__(message)
        if code is None and body and isinstance(body.get("code"), str):
            code = body["code"]  # the engine's own code is the code
        if stage is None and body and isinstance(body.get("stage"), str):
            stage = body["stage"]
        if code is not None:
            self.code = code
        if stage is not None:
            self.stage = stage
        error = dict(body) if body else {"code": self.code, "stage": self.stage, "message": message}
        self.detail = dict(detail or {}, error=error)


class EngineRejected(EngineError):
    """The engine refused the statement or the open: its own error, with its own code."""


class EngineIncomplete(EngineError):
    """The engine answered but did not (or could not) cover everything: never a business verdict."""

    code = "INCOMPLETE_FACTS"


class EngineProtocolError(EngineError):
    """What arrived is not the stream protocol, or contradicts itself."""

    code = "INTERNAL_FAULT"


class EngineLost(EngineError):
    """The process ended before it delivered a terminal frame."""

    code = "WORKER_LOST"


class SessionClosed(EngineError):
    code = "SNAPSHOT_CLOSED"


# ---- the registry of differences from DexSQL's transport -------------------------------------------------------

WIRE_CHANGES = (
    {"id": "W-B0-1", "session": "b0", "layer": "transport", "a0": "Unicode table lines on stdout, read in 64 KiB pieces",
     "new": "framed JSON lines (mdd.cli-stream.v1): opened, batch*, one terminal per request",
     "effect": "the consumer sees the same DTO; the bytes on the pipe differ"},
    {"id": "W-B0-2", "session": "b0", "layer": "request framing",
     "a0": "every statement is followed by a marker SELECT whose row ends the result",
     "new": "no marker statement; the terminal frame of the request id ends the result",
     "effect": "the HostLab-visible statements (rows/all) are identical; the marker statement is not sent"},
    {"id": "W-B0-3", "session": "b0", "layer": "process",
     "a0": "dexsql --threads N query --input APK --interactive",
     "new": "meguvizdexdash serve --dialect D --deadline-ms T --input APK; threads travel in MDD_FACTS_THREADS",
     "effect": "the engine has no global --threads (docs: integrations/hostlab/README.md)"},
    {"id": "W-B0-4", "session": "b0", "layer": "errors",
     "a0": "a Unicode error text or an exit status",
     "new": "a typed terminal/rejected frame with an engine code; raised as EngineRejected/EngineIncomplete/EngineLost",
     "effect": "failures carry the engine's code for provider.classify_failure; they are still RuntimeError"},
    {"id": "W-B0-5", "session": "b0", "layer": "budgets",
     "a0": "4 MiB per table row, 512 MiB per response, checked on text lines",
     "new": "64 MiB per frame (a frame holds a batch of rows), 512 MiB per response, checked on frames",
     "effect": "the row and byte budgets of rows() (500000 rows, 128 MiB of cell bytes) are unchanged"},
    {"id": "W-B0-6", "session": "b0", "layer": "coverage",
     "a0": "no coverage report; the audit sets complete=True itself",
     "new": "every terminal reports input/facts coverage; anything but complete raises EngineIncomplete",
     "effect": "a result is complete only if every statement was covered completely"},
    {"id": "W-B1-1", "session": "b1", "layer": "serialization",
     "a0": "hex text cells decoded with strict UTF-8", "new": "typed cells (null, i64/u64, text, dex_mutf8) read directly",
     "effect": "REAL, BLOB and bool cells are refused in the DTO, not rendered; text must be valid Unicode"},
    {"id": "W-B1-2", "session": "b1", "layer": "request scheduling",
     "a0": "a LIMIT 0 shape statement, then the data statement (two round trips per rows())",
     "new": "the data statement only; the columns come from the frames and the terminal",
     "effect": "half the round trips; the rows are the same; the ORDER BY and column-identity guards are kept"},
    {"id": "W-B1-3", "session": "b1", "layer": "text decoding",
     "a0": "MUTF-8 that is not valid UTF-8 (NUL as C0 80, supplementary characters as surrogate pairs) fails the strict decode",
     "new": "dex_mutf8 cells are decoded as MUTF-8; only a lone surrogate is refused",
     "effect": "B1 can read strings that B0 and DexSQL refuse; it never returns a different value for a string both accept"},
    {"id": "W-B1-4", "session": "b1", "layer": "consumer",
     "a0": "a dict per row, built after the hex decode", "new": "a dict per row built from the typed row; batches() hands out typed rows without dicts",
     "effect": "the DTO is the same; consumers that want typed values need no round trip through str"},
)


# ---- configuration of this module (the provider setting is provider.py's) ----------------------------------------

@dataclass(frozen=True)
class StructuralConfig:
    wire: str = "b0"
    sql_limits: tuple = ()          # (("steps", n), ...) in key order
    max_line_bytes: int = MAX_LINE_BYTES

    def limits(self) -> dict:
        return dict(self.sql_limits)


def parse_structural_config(obj: Any) -> StructuralConfig:
    """Strict: an unknown key or a wrong type is an error, never a default."""
    if not isinstance(obj, dict):
        raise provider.ConfigError("structural config must be an object")
    extra = set(obj) - {"schema", "wire", "sql_limits", "max_line_bytes"}
    if extra:
        raise provider.ConfigError(f"structural config has unsupported keys: {sorted(extra)}")
    if obj.get("schema") != STRUCTURAL_SCHEMA:
        raise provider.ConfigError("structural config.schema must be " + STRUCTURAL_SCHEMA)
    wire = obj.get("wire", "b0")
    if wire not in WIRES:
        raise provider.ConfigError(f"structural config.wire must be one of {list(WIRES)}")
    limits = obj.get("sql_limits", {})
    if not isinstance(limits, dict) or set(limits) - set(SQL_LIMIT_KEYS):
        raise provider.ConfigError(f"structural config.sql_limits may hold only {list(SQL_LIMIT_KEYS)}")
    for key, value in limits.items():
        if type(value) is not int or not 1 <= value <= (1 << 40):
            raise provider.ConfigError(f"structural config.sql_limits.{key} must be a positive integer")
    line = obj.get("max_line_bytes", MAX_LINE_BYTES)
    if type(line) is not int or not 1024 <= line <= (1 << 31):
        raise provider.ConfigError("structural config.max_line_bytes must be an integer 1024..2^31")
    return StructuralConfig(wire, tuple((key, limits[key]) for key in SQL_LIMIT_KEYS if key in limits), line)


def load_structural_config(source: "dict | str | os.PathLike[str] | None" = None,
                           environ: "dict | None" = None) -> StructuralConfig:
    env = os.environ if environ is None else environ
    if source is None and env.get(ENV_STRUCTURAL):
        source = env[ENV_STRUCTURAL]
    if source is None:
        return StructuralConfig()
    if isinstance(source, dict):
        return parse_structural_config(source)
    path = Path(source)
    if path.stat().st_size > 64 * 1024:
        raise provider.ConfigError("the structural configuration exceeds 64 KiB")
    try:
        return parse_structural_config(json.loads(path.read_text(encoding="utf-8")))
    except ValueError as error:
        if isinstance(error, provider.ConfigError):
            raise
        raise provider.ConfigError("the structural configuration is not JSON") from None


# ---- typed cells -------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class DexMutf8:
    """A DEX string as the original MUTF-8 bytes and the UTF-16 unit count."""

    raw: bytes
    utf16_units: int

    def text(self) -> str:
        units: list[int] = []
        data, i = self.raw, 0
        while i < len(data):
            b = data[i]
            if b < 0x80:
                units.append(b)
                i += 1
            elif b & 0xE0 == 0xC0 and i + 1 < len(data):
                units.append(((b & 0x1F) << 6) | (data[i + 1] & 0x3F))
                i += 2
            elif b & 0xF0 == 0xE0 and i + 2 < len(data):
                units.append(((b & 0x0F) << 12) | ((data[i + 1] & 0x3F) << 6) | (data[i + 2] & 0x3F))
                i += 3
            else:
                raise EngineProtocolError("a dex_mutf8 cell is not well-formed MUTF-8")
        return b"".join(struct.pack(">H", u) for u in units).decode("utf-16-be", "surrogatepass")


@dataclass(frozen=True)
class SurrogateText:
    """Text that holds an unpaired surrogate, as the UTF-16 units it arrived in."""

    units: bytes

    def text(self) -> str:
        return self.units.decode("utf-16-be", "surrogatepass")


def decode_cell(cell: Any) -> Any:
    """A typed cell as a Python value; NULL is None and nothing else is. The same rules as the SDK's decoder."""
    try:
        tag = cell["t"]
        if tag == "null":
            return None
        if tag == "bool":
            return bool(cell["v"])
        if tag in ("i64", "u64"):
            return int(cell["v"])
        if tag == "f64":
            return struct.unpack(">d", bytes.fromhex(cell["bits"]))[0]
        if tag == "bytes":
            return bytes.fromhex(cell["v"])
        if tag == "dex_mutf8":
            return DexMutf8(bytes.fromhex(cell["v"]), int(cell["utf16_units"]))
        if tag == "text":
            if "units" in cell:
                return SurrogateText(bytes.fromhex(cell["units"]))
            if not isinstance(cell["v"], str):
                raise TypeError
            return cell["v"]
    except (KeyError, TypeError, ValueError, struct.error):
        raise EngineProtocolError("a cell that does not decode") from None
    raise EngineProtocolError(f"an unknown cell tag {tag!r}")


def dto_value(value: Any) -> "str | None":
    """The audit DTO of a typed value: `None`, or `str` as CAST(x AS TEXT) gives it for the cells the audit reads."""
    if value is None:
        return None
    if type(value) is int:
        return str(value)
    if type(value) is str:
        return value
    if isinstance(value, (DexMutf8, SurrogateText)):
        text = value.text()
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            raise EngineProtocolError("a text cell holds an unpaired surrogate; it is not valid Unicode text") from None
        return text
    raise EngineProtocolError(f"a {type(value).__name__} cell cannot be represented in the audit DTO")


# ---- the transport: one `meguvizdexdash serve` process ------------------------------------------------------------

@dataclass
class Opened:
    dex_count: int
    layer_issues: list
    profile: str
    sql_dialect: str
    snapshot_id: str
    scope_id: str

    def describe(self) -> dict:
        return {"protocol": STREAM_PROTOCOL, "dex_count": self.dex_count, "profile": self.profile,
                "sql_dialect": self.sql_dialect, "snapshot_id": self.snapshot_id, "scope_id": self.scope_id,
                "layer_issues": [issue_summary(issue) for issue in self.layer_issues]}


def issue_summary(issue: Any) -> dict:
    """A layer issue reduced to what a report needs: where, which layers, which error."""
    if not isinstance(issue, dict):
        return {"issue": str(issue)[:500]}
    error = issue.get("error") if isinstance(issue.get("error"), dict) else {}
    return {"dex_occurrence_id": issue.get("dex_occurrence_id"), "layers": issue.get("layers"),
            "code": error.get("code"), "stage": error.get("stage"), "message": str(error.get("message", ""))[:300],
            "reason": (error.get("details") or {}).get("reason") if isinstance(error.get("details"), dict) else None}


@dataclass
class Statement:
    id: str
    sql: str
    rows: int = 0
    next_sequence: int = 0
    finished: bool = False


@dataclass
class Coverage:
    """What the engine said about every statement of a session, summed up. `statements` counts the terminals that
    were read and validated; `abandoned` counts the statements the consumer walked away from, whose terminal was
    skipped instead of read. A statement that was sent but never covered is not a complete result."""

    statements: int = 0
    abandoned: int = 0
    input: str = "complete"
    facts: str = "complete"
    layers: set = field(default_factory=set)
    issues: list = field(default_factory=list)

    @staticmethod
    def _worse(a: str, b: str) -> str:
        order = {"complete": 0, "partial": 1, "unknown": 2}
        return a if order.get(a, 3) >= order.get(b, 3) else b

    def add(self, coverage: dict) -> None:
        self.statements += 1
        self.input = self._worse(self.input, coverage.get("input", "unknown"))
        self.facts = self._worse(self.facts, coverage.get("facts", "unknown"))
        self.layers.update(coverage.get("required_layers") or [])
        self.issues.extend(coverage.get("issues") or [])

    def describe(self) -> dict:
        return {"statements": self.statements, "abandoned": self.abandoned, "input": self.input, "facts": self.facts,
                "required_layers": sorted(self.layers), "issues": list(self.issues)}


class Transport:
    """Starts the engine, sends one statement at a time and hands out its frames, validated.

    Every read is bounded by the session's deadline; a reader thread keeps the pipe drained into a bounded
    queue, as HostLab's CliSession does, so a stalled consumer applies backpressure instead of growing memory."""

    CLOSE_WAIT = 5.0  # seconds an engine gets to leave after the close request, as HostLab's session gives DexSQL 3

    def __init__(self, command: list, env: "dict | None", deadline: float, *, max_line_bytes: int = MAX_LINE_BYTES):
        self.command, self.env, self.deadline, self.max_line = list(command), env, deadline, max_line_bytes
        self.process: "subprocess.Popen | None" = None
        self.messages: "queue.Queue" = queue.Queue(maxsize=QUEUE_SLOTS)
        self.closed = threading.Event()
        self.reader: "threading.Thread | None" = None
        self.stderr_reader: "threading.Thread | None" = None
        self.stderr_tail = bytearray()
        self.broken: "EngineError | None" = None
        self.abandoned: "set[str]" = set()
        self.statement_count = 0
        self.response_bytes = 0
        self.opened: "Opened | None" = None
        self.coverage = Coverage()
        self.last_terminal: "dict | None" = None

    # -- process --

    def start(self) -> Opened:
        self.process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, env=self.env, close_fds=True,
                                        start_new_session=os.name != "nt")
        self.reader = threading.Thread(target=self._read_stdout, daemon=True, name="hostlab-mdd-reader")
        self.stderr_reader = threading.Thread(target=self._read_stderr, daemon=True, name="hostlab-mdd-stderr")
        self.reader.start()
        self.stderr_reader.start()
        frame = self._frame(opening=True)
        if frame.get("kind") != "opened" or frame.get("protocol") != STREAM_PROTOCOL:
            raise self._broken(EngineProtocolError("the engine did not open with the expected stream protocol"))
        dataset = frame.get("dataset")
        try:
            self.opened = Opened(int(dataset["dex_count"]), list(dataset["layer_issues"]), str(dataset["profile"]),
                                 str(dataset["sql_dialect"]), str(dataset["snapshot_id"]), str(dataset["scope_id"]))
        except (KeyError, TypeError, ValueError):
            raise self._broken(EngineProtocolError("the opened frame does not describe a dataset")) from None
        return self.opened

    def _read_stdout(self) -> None:
        stream = self.process.stdout
        while not self.closed.is_set():
            try:
                line = stream.readline(self.max_line + 1)
                item: Any = line
                if line and (len(line) > self.max_line or not line.endswith(b"\n")):
                    item = EngineProtocolError("an engine frame exceeds its byte budget or ends without a newline")
            except (OSError, ValueError):
                item = EngineLost("the engine output could not be read")
            while not self.closed.is_set():
                try:
                    self.messages.put(item, timeout=0.1)
                    break
                except queue.Full:
                    continue
            if not item or isinstance(item, Exception):
                return

    def _read_stderr(self) -> None:
        stream = self.process.stderr
        try:
            while not self.closed.is_set():
                chunk = stream.read1(4096)
                if not chunk:
                    return
                self.stderr_tail.extend(chunk)
                del self.stderr_tail[:-8192]
        except (OSError, ValueError):
            return

    def stderr_text(self) -> str:
        return bytes(self.stderr_tail).decode("utf-8", "replace")

    def _broken(self, error: EngineError) -> EngineError:
        if self.broken is None:
            self.broken = error
        return error

    def _refusal(self) -> "EngineError | None":
        """The engine's own error when it ended before opening: a JSON error object on stderr."""
        for line in reversed(self.stderr_text().strip().splitlines()):
            try:
                body = json.loads(line)
            except ValueError:
                continue
            if isinstance(body, dict) and isinstance(body.get("code"), str):
                return EngineRejected(str(body.get("message", "the engine refused to start")), body=body)
        return None

    # -- frames --

    def _frame(self, opening: bool = False) -> dict:
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise self._broken_timeout("native audit deadline exhausted")
            try:
                item = self.messages.get(timeout=remaining)
            except queue.Empty:
                raise self._broken_timeout("native audit CLI response timed out") from None
            if isinstance(item, Exception):
                raise self._broken(item)
            if not item:
                if self.process is not None:
                    try:
                        self.process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
                if self.stderr_reader is not None:  # what the engine said about why it ended is in its stderr
                    self.stderr_reader.join(timeout=2)
                refusal = self._refusal() if opening or self.opened is None else None
                if refusal is not None:
                    raise self._broken(refusal)
                code = self.process.returncode if self.process is not None else None
                raise self._broken(EngineLost("native audit CLI exited before a complete result"
                                              + (f" (exit status {code})" if code is not None else "")
                                              + (": " + self.stderr_text()[-400:] if self.stderr_text() else "")))
            self.response_bytes += len(item)
            if self.response_bytes > MAX_RESPONSE_BYTES:
                raise self._broken(EngineProtocolError("native audit CLI response exceeds byte budget"))
            if not item.strip():
                continue
            try:
                frame = json.loads(item)
            except ValueError:
                raise self._broken(EngineProtocolError("a line of the engine output is not JSON")) from None
            if not isinstance(frame, dict) or not isinstance(frame.get("kind"), str):
                raise self._broken(EngineProtocolError("a frame that is not an object with a kind"))
            return frame

    def _broken_timeout(self, message: str) -> TimeoutError:
        error = TimeoutError(message)
        if self.broken is None:
            self.broken = EngineError(message, code="DEADLINE_EXCEEDED")
        return error

    # -- one statement --

    def send(self, request: dict) -> None:
        data = (json.dumps(request) + "\n").encode("utf-8")
        done: Future = Future()

        def write() -> None:
            try:
                self.process.stdin.write(data)
                self.process.stdin.flush()
                done.set_result(None)
            except BaseException as exc:  # noqa: BLE001 - handed to the caller through the future
                done.set_exception(exc)

        writer = threading.Thread(target=write, daemon=True, name="hostlab-mdd-writer")
        writer.start()
        try:
            done.result(timeout=max(0.001, self.deadline - time.monotonic()))
        except FutureTimeout:
            self.kill()
            raise self._broken_timeout("native audit CLI input timed out") from None
        except (BrokenPipeError, OSError, ValueError):
            raise self._broken(EngineLost("the engine closed its input before the statement was sent")) from None

    def statement(self, sql: str, **options: Any) -> Iterator[tuple]:
        """Yield ("batch", document) for each batch and finally ("terminal", terminal). Raises for anything the
        engine rejects, does not finish or contradicts. A generator closed before the terminal marks the statement
        abandoned; its frames are skipped when the next statement is sent."""
        if self.broken is not None:
            raise SessionClosed("the session is broken: " + str(self.broken))
        if self.closed.is_set() or self.process is None:
            raise SessionClosed("the session is closed")
        if time.monotonic() >= self.deadline:
            raise self._broken_timeout("native audit deadline exhausted")
        if len(sql.encode("utf-8")) > MAX_SQL_BYTES:
            raise EngineProtocolError("native audit SQL exceeds its byte budget", code="INVALID_ARGUMENT", stage="hostlab.session")
        self._skip_abandoned()
        self.statement_count += 1
        state = Statement(f"s{self.statement_count}", sql)
        self.send({"id": state.id, "sql": sql, **options})
        try:
            while True:
                frame = self._frame()
                kind = frame["kind"]
                if frame.get("id") in self.abandoned:
                    if kind in ("terminal", "rejected"):
                        self.abandoned.discard(frame["id"])
                        self.coverage.abandoned += 1
                    continue
                if kind == "rejected":
                    state.finished = True
                    body = frame.get("error") if isinstance(frame.get("error"), dict) else {}
                    raise EngineRejected(str(body.get("message", "the engine rejected the request")), body=body or None)
                if frame.get("id") != state.id:
                    raise self._broken(EngineProtocolError("a frame for another request arrived"))
                if kind == "batch":
                    yield "batch", self._batch(frame.get("batch"), state)
                elif kind == "terminal":
                    state.finished = True  # received: whatever it says, nothing more of this request is coming
                    yield "terminal", self._terminal(frame.get("terminal"), state)
                    return
                else:
                    raise self._broken(EngineProtocolError(f"a {kind!r} frame inside a statement"))
        finally:
            if not state.finished:
                self.abandoned.add(state.id)

    def _skip_abandoned(self) -> None:
        while self.abandoned:
            frame = self._frame()
            if frame.get("id") in self.abandoned:
                if frame["kind"] in ("terminal", "rejected"):
                    self.abandoned.discard(frame["id"])
                    self.coverage.abandoned += 1  # sent but not covered: the result is not complete
                continue
            raise self._broken(EngineProtocolError("a frame for no known request arrived"))

    def _batch(self, document: Any, state: Statement) -> dict:
        try:
            ok = (document["schema"] == BATCH_SCHEMA and int(document["sequence"]) == state.next_sequence
                  and int(document["first_row"]) == state.rows and int(document["row_count"]) == len(document["rows"])
                  and isinstance(document["columns"], list)
                  and all(isinstance(row, list) and len(row) == len(document["columns"]) for row in document["rows"]))
        except (KeyError, TypeError, ValueError):
            ok = False
        if not ok:
            raise self._broken(EngineProtocolError("a batch that is out of order, mislabelled or ragged"))
        state.next_sequence += 1
        state.rows += len(document["rows"])
        return document

    def _terminal(self, terminal: Any, state: Statement) -> dict:
        if not isinstance(terminal, dict) or terminal.get("operation_status") not in provider.OPERATION_STATES:
            raise self._broken(EngineProtocolError("a terminal that does not state its operation status"))
        self.last_terminal = terminal
        coverage = terminal.get("coverage") if isinstance(terminal.get("coverage"), dict) else {}
        response = terminal.get("response") if isinstance(terminal.get("response"), dict) else {}
        execution = terminal.get("execution") if isinstance(terminal.get("execution"), dict) else {}
        self.coverage.add(coverage)
        if terminal["operation_status"] != "ok":
            error = terminal.get("error") if isinstance(terminal.get("error"), dict) else {}
            code = error.get("code")
            cls = EngineIncomplete if code in INCOMPLETE_CODES else EngineRejected
            raise cls(str(error.get("message", "the statement failed")), body=error or None,
                      detail={"coverage": coverage, "emitted_rows": response.get("emitted_rows")})
        try:
            emitted = int(response["emitted_rows"])
        except (KeyError, TypeError, ValueError):
            raise self._broken(EngineProtocolError("a terminal without a row count")) from None
        if emitted != state.rows:
            raise self._broken(EngineProtocolError("the terminal row count differs from the rows delivered"))
        try:
            complete = provider.completeness("ok", coverage.get("input"), coverage.get("facts"), execution.get("complete"))
        except provider.ProviderError:
            raise self._broken(EngineProtocolError("a terminal with an unrecognised coverage state")) from None
        if response.get("truncated") is not False or response.get("more_available") is not False:
            raise EngineIncomplete("the statement was cut short; its result is not complete",
                                   detail={"coverage": coverage, "response": response})
        if not complete["complete"]:
            raise EngineIncomplete("the statement's coverage is not complete: " + ",".join(complete["reasons"]),
                                   detail={"coverage": coverage, "reasons": complete["reasons"]})
        return terminal

    # -- end --

    def kill(self) -> None:
        process = self.process
        if process is not None and process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass

    def close(self, clean: bool) -> None:
        """End the process. `clean` asks it to stop (close op, end of input) and checks its exit status; otherwise
        it is killed. Pipes are closed and both reader threads joined either way."""
        process = self.process
        problem: "EngineError | None" = None
        self.closed.set()
        try:
            if process is None:
                return
            if clean and process.poll() is None:
                try:
                    process.stdin.write(b'{"op":"close"}\n')
                    process.stdin.flush()
                    process.stdin.close()
                except (BrokenPipeError, OSError, ValueError):
                    pass
                try:
                    process.wait(timeout=self.CLOSE_WAIT)
                except subprocess.TimeoutExpired:
                    self.kill()
                    problem = EngineLost("native audit CLI did not exit after close")
            elif process.poll() is None:
                self.kill()
            if clean and problem is None and process.poll() is not None and process.returncode:
                problem = EngineLost(f"native audit CLI exited unsuccessfully ({process.returncode})")
        finally:
            if process is not None:
                if process.poll() is None:
                    self.kill()
                for stream in (process.stdin, process.stdout, process.stderr):
                    try:
                        stream.close()
                    except (BrokenPipeError, OSError, ValueError):
                        pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            for thread in (self.reader, self.stderr_reader):
                if thread is not None:
                    thread.join(timeout=3)
        if problem is not None:
            raise problem


# ---- how the engine is started ----------------------------------------------------------------------------------

@dataclass
class EngineLaunch:
    command: list
    env: dict
    identity: "dict | None"
    namespaces: dict = field(default_factory=dict)
    config: "provider.Config | None" = None


def serve_command(binary: str, inputs: list, *, dialect: str, timeout_seconds: float, sql_limits: "dict | None" = None) -> list:
    """`serve` takes its inputs, dialect, deadline and SQL budgets as options; there is no global --threads."""
    command = [str(binary), "serve", "--dialect", dialect, "--deadline-ms", str(max(1, int(timeout_seconds * 1000)))]
    for key in SQL_LIMIT_KEYS:
        if sql_limits and key in sql_limits:
            command += ["--sql-max-" + key.replace("_", "-"), str(sql_limits[key])]
    for path in inputs:
        command += ["--input", str(path)]
    return command


def engine_launch(config: "provider.Config", inputs: list, *, timeout: float, threads: int, state: Any,
                  settings: StructuralConfig, runner: Any = None, environ: "dict | None" = None) -> EngineLaunch:
    """Verify the pinned engine again at the moment of starting it (provider.launch), then say how to start `serve`."""
    launched = provider.launch(config, threads=threads, timeout_seconds=max(1, int(timeout)), state=Path(state),
                               runner=runner, environ=environ)
    command = serve_command(launched.command, inputs, dialect=config.engine.dialect, timeout_seconds=timeout,
                            sql_limits=settings.limits())
    return EngineLaunch(command, launched.env, launched.identity, launched.namespaces, config)


# ---- sessions ---------------------------------------------------------------------------------------------------------

class _Session:
    """What B0 and B1 share: the process, the HostLab-facing attributes, the guards of `rows`."""

    wire = ""
    transport_name = ""

    def __init__(self, apk, timeout=900, threads=2, *, launch: EngineLaunch, settings: "StructuralConfig | None" = None):
        self.apk = Path(apk).resolve(strict=True)
        self.timeout, self.threads = timeout, threads
        self.deadline = time.monotonic() + timeout
        self.queries = 0
        self.settings = settings or StructuralConfig()
        self.launch = launch
        self.transport = Transport(launch.command, launch.env, self.deadline, max_line_bytes=self.settings.max_line_bytes)
        self.files: dict = {}
        self.opened: dict = {}
        self.statements: list = []

    # -- life cycle --

    def __enter__(self):
        started = time.monotonic()
        expected = provider.archive_inventory(self.apk)
        try:
            opened = self.transport.start()
            self.files = {int(r["file_id"]): r["entry_name"]
                          for r in self.rows("SELECT file_id,entry_name FROM dex_files ORDER BY file_id")}
            provider.verify_inventory(expected, self.files)
            self.opened = {"backend": provider.ENGINE, "transport": self.transport_name, "wire": self.wire,
                           "prepare_ms": (time.monotonic() - started) * 1000, "files": self.files,
                           "cache": "memory_session", "source_diagnostics": [issue_summary(i) for i in opened.layer_issues],
                           "dataset": opened.describe(), "identity": self.launch.identity}
            return self
        except BaseException:
            self.__exit__(RuntimeError, None, None)
            raise

    def __exit__(self, error, *_):
        self.transport.close(clean=error is None and self.transport.broken is None)

    # -- what the session knows about the engine's answers --

    @property
    def coverage(self) -> dict:
        described = self.transport.coverage.describe()
        # statements abandoned whose terminal has not been read yet are uncovered too
        described["abandoned"] += len(self.transport.abandoned)
        return described

    @property
    def layer_issues(self) -> list:
        return list(self.transport.opened.layer_issues) if self.transport.opened else []

    def identity(self) -> dict:
        return {"engine": self.launch.identity, "wire": self.wire, "transport": self.transport_name,
                "dataset": self.transport.opened.describe() if self.transport.opened else None,
                "coverage": self.coverage, "queries": self.queries}

    # -- guards of rows(), the same for both wires --

    @staticmethod
    def _need_stable_order(sql: str) -> None:
        if "ORDER BY" not in sql.upper():
            raise ValueError("native audit requires stable ordering")

    @staticmethod
    def _need_unambiguous(columns) -> None:
        if not columns or len(columns) != len(set(columns)):
            raise EngineProtocolError("ambiguous native audit columns", code="INVALID_ARGUMENT")

    def all(self, sql, **bounds):
        return list(self.rows(sql, **bounds))


class B0Session(_Session):
    """HostLab's contract over the engine: the statements and the DTO of native_cli.CliSession."""

    wire = "b0"
    transport_name = "cli_jsonl_v1"

    def table(self, sql, *, expected=None):
        """(columns, None) once, then (columns, cells) per row - the cells are the text the hex projection returned."""
        columns = None
        for kind, payload in self.transport.statement(sql):
            if kind == "batch":
                if columns is None:
                    columns = self._columns(payload["columns"], expected)
                    yield columns, None
                elif payload["columns"] != columns:
                    raise EngineProtocolError("native audit CLI column identity mismatch")
                for row in payload["rows"]:
                    cells = []
                    for cell in row:
                        if not (isinstance(cell, dict) and cell.get("t") == "text" and isinstance(cell.get("v"), str)):
                            raise EngineProtocolError("the hex projection returned a cell that is not text")
                        cells.append(cell["v"])
                    yield columns, cells
            else:  # the terminal: its columns must agree with the batches, as B1 requires
                final = (payload.get("data") or {}).get("columns")
                if columns is None:
                    columns = self._columns(final, expected)
                    yield columns, None
                elif final is not None and final != columns:
                    raise EngineProtocolError("native audit CLI column identity mismatch")
        if columns is None:
            raise EngineProtocolError("native audit CLI did not return the requested columns")

    @staticmethod
    def _columns(columns, expected):
        if not isinstance(columns, list) or not all(isinstance(name, str) for name in columns):
            raise EngineProtocolError("the engine did not name its columns")
        if expected is not None and columns != expected:
            raise EngineProtocolError("native audit CLI column identity mismatch")
        return columns

    def rows(self, sql, *, page_size=1000, max_rows=500000, max_bytes=128 * 1024 * 1024):
        self._need_stable_order(sql)
        columns = None
        for names, row in self.table("SELECT * FROM (" + sql + ") AS hostlab_shape LIMIT 0"):
            if row is not None:
                raise EngineProtocolError("native audit shape query unexpectedly returned data")
            columns = names
        self._need_unambiguous(columns)

        def identifier(name):
            return '"' + name.replace('"', '""') + '"'

        projected = ["CASE WHEN " + identifier(name) + " IS NULL THEN 'N' ELSE hex(CAST(" + identifier(name) + " AS TEXT)) END AS " + identifier(name) for name in columns]
        statement = "SELECT " + ",".join(projected) + " FROM (" + sql + ") AS hostlab_rows"
        self.statements.append(sql)
        used, count = 0, 0
        for names, cells in self.table(statement, expected=columns):
            if cells is None:
                continue
            count += 1
            if count > max_rows:
                raise EngineProtocolError("native audit exceeded its complete row budget", code="QUOTA_EXCEEDED")
            decoded = []
            for cell in cells:
                if cell == "N":
                    value = None
                else:
                    try:
                        value = bytes.fromhex(cell).decode("utf-8", "strict")
                    except (ValueError, UnicodeError):
                        raise EngineProtocolError("native audit returned a malformed hex cell") from None
                used += len(value.encode()) if value is not None else 0
                if used > max_bytes:
                    raise EngineProtocolError("native audit exceeded its complete byte budget", code="QUOTA_EXCEEDED")
                decoded.append(value)
            yield dict(zip(names, decoded))
        self.queries += 1


@dataclass(frozen=True)
class TypedBatch:
    """One delivered batch of typed rows: rows `first_row ..` of the result."""

    sequence: int
    first_row: int
    columns: tuple
    rows: tuple


class B1Session(_Session):
    """The typed batches, read directly: one round trip per statement and no hex."""

    wire = "b1"
    transport_name = "typed_batch_v1"

    def batches(self, sql: str, **options: Any) -> Iterator[TypedBatch]:
        """Run one statement and yield its typed batches. A statement that fails or is incomplete raises after the
        batches that were delivered; the caller never gets a shorter result that looks complete."""
        columns: "tuple | None" = None
        for kind, payload in self.transport.statement(sql, **options):
            if kind == "batch":
                names = tuple(payload["columns"])
                if columns is not None and names != columns:
                    raise EngineProtocolError("the columns changed between batches")
                columns = names
                yield TypedBatch(int(payload["sequence"]), int(payload["first_row"]), names,
                                 tuple(tuple(decode_cell(cell) for cell in row) for row in payload["rows"]))
            else:
                final = (payload.get("data") or {}).get("columns")
                if columns is not None and final is not None and tuple(final) != columns:
                    raise EngineProtocolError("the terminal names other columns than the batches")
                self.last_columns = tuple(final) if final is not None else columns

    last_columns: "tuple | None" = None

    def rows(self, sql, *, page_size=1000, max_rows=500000, max_bytes=128 * 1024 * 1024):
        self._need_stable_order(sql)
        self.statements.append(sql)
        used, count = 0, 0
        names = None
        for batch in self.batches(sql):
            if names is None:
                names = list(batch.columns)
                self._need_unambiguous(names)
            for row in batch.rows:
                count += 1
                if count > max_rows:
                    raise EngineProtocolError("native audit exceeded its complete row budget", code="QUOTA_EXCEEDED")
                values = [dto_value(value) for value in row]
                for value in values:
                    if value is not None:
                        used += len(value.encode())
                if used > max_bytes:
                    raise EngineProtocolError("native audit exceeded its complete byte budget", code="QUOTA_EXCEEDED")
                yield dict(zip(names, values))
        if names is None:  # no rows: the terminal still has to name distinct columns
            self._need_unambiguous(list(self.last_columns or ()))
        self.queries += 1


SESSIONS = {"b0": B0Session, "b1": B1Session}


# ---- the HostLab entry point -----------------------------------------------------------------------------------------

def original_session():
    """HostLab's own session class: the rollback path. Imported only when it is used."""
    return importlib.import_module("native_cli").CliSession


def default_state():
    return Path(importlib.import_module("hostlab").STATE)


def NativeSession(apk, timeout=900, threads=2, *, provider_config=None, structural=None, state=None,
                  original=None, runner=None, environ=None):  # noqa: N802 - the name HostLab imports
    """What `from native_session import NativeSession` gives HostLab.

    `native_engine` of the provider configuration decides: `dexsql` (the default and the rollback value) returns
    HostLab's own session and nothing of this module's engine is started; `meguvizdexdash` returns a B0 or B1
    session, as the structural configuration says."""
    config = provider.load_config(provider_config, environ)
    if config.native_engine != provider.ENGINE:
        return (original or original_session())(apk, timeout=timeout, threads=threads)
    settings = load_structural_config(structural, environ)
    path = Path(apk).resolve(strict=True)
    launch = engine_launch(config, [path], timeout=timeout, threads=threads,
                           state=state if state is not None else default_state(), settings=settings,
                           runner=runner, environ=environ)
    return SESSIONS[settings.wire](path, timeout=timeout, threads=threads, launch=launch, settings=settings)
