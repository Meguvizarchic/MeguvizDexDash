"""A worker process as an SDK session.

`Worker` starts ``meguvizdexdash serve`` over some inputs and talks to it in lines on its
standard input and output (protocol ``mdd.cli-stream.v1``): the same engine, the same
batches (``mdd.sdk-batch.v1``) and the same terminal envelope as the in-process library, but
in another process that can die. When it does, nothing is made up:

* a worker that goes away before a query's terminal arrived raises `WorkerLost` (code
  ``WORKER_LOST``); the batches already delivered stay delivered, no shorter list of rows is
  ever returned as a result, and `collect` / `execute` never return;
* a worker that sends something that is not the protocol raises `WorkerProtocol` and is ended;
* a worker that does not answer within the caller's time is ended and raises
  `DeadlineExceeded`;
* a worker that refuses to start (a missing input, say) raises the engine's own error, not
  `WorkerLost`: it did not get lost, it said no.

Cleanup is bounded and the same on every path: stdin is closed, the process is killed if it
does not leave within the grace period, both pipes are closed, both reader threads are
joined, and the process has been waited for. A worker cannot be told to stop one query, so a
query that is abandoned half way, or cancelled, ends the worker. At most one query runs on a
worker at a time (a second asks for `Busy`).

Standard library only.
"""
from __future__ import annotations

import collections
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
import weakref
from pathlib import Path
from typing import Any, Iterator, Sequence

from . import errors
from ._cells import decode_cell
from .core import Batch, Input, Result, is_complete

STREAM_PROTOCOL = "mdd.cli-stream.v1"
DEFAULT_MAX_LINE_BYTES = 64 * 1024 * 1024
_STDERR_TAIL = 8192
_QUEUE_LINES = 64


def find_worker() -> Path:
    """`MDD_WORKER_BINARY`, else the newest ``meguvizdexdash`` under this checkout's target directory."""
    explicit = os.environ.get("MDD_WORKER_BINARY")
    if explicit:
        return Path(explicit)
    root = Path(__file__).resolve().parents[2]
    name = "meguvizdexdash.exe" if sys.platform == "win32" else "meguvizdexdash"
    found = [root / "target" / profile / name for profile in ("release", "debug")
             if (root / "target" / profile / name).is_file()]
    if not found:
        raise FileNotFoundError(
            "the meguvizdexdash binary was not found; build it with `cargo build -p mdd-cli` "
            "or set MDD_WORKER_BINARY")
    return max(found, key=lambda path: path.stat().st_mtime)


# ---- the threads and the reaping do not hold the Worker, so a dropped Worker is collected ----

def _close(stream: Any) -> None:
    try:
        if stream is not None:
            stream.close()
    except (OSError, ValueError):
        pass


def _read_stdout(stream: Any, out: "queue.Queue[tuple[str, bytes | None]]", stop: threading.Event,
                 limit: int) -> None:
    """Read lines until the pipe ends, then close it. Only this thread ever closes it: closing a
    buffered stream under a blocked read waits for that read, which would make the close unbounded."""
    def put(item: tuple[str, bytes | None]) -> bool:
        while not stop.is_set():
            try:
                out.put(item, timeout=0.2)
                return True
            except queue.Full:
                continue
        return False

    try:
        while not stop.is_set():
            line = stream.readline(limit + 1)
            if not line:
                break
            if len(line) > limit and not line.endswith(b"\n"):
                put(("oversize", None))
                return
            if not line.endswith(b"\n"):
                put(("partial", line))
                break
            if not put(("line", line)):
                return
    except (OSError, ValueError):
        pass
    finally:
        _close(stream)
    put(("eof", None))


def _read_stderr(stream: Any, tail: "collections.deque[bytes]", stop: threading.Event) -> None:
    kept = 0
    try:
        while not stop.is_set():
            chunk = stream.read1(4096) if hasattr(stream, "read1") else stream.read(4096)
            if not chunk:
                return
            tail.append(chunk)
            kept += len(chunk)
            while kept > _STDERR_TAIL and len(tail) > 1:
                kept -= len(tail.popleft())
    except (OSError, ValueError):
        return
    finally:
        _close(stream)


def _kill_tree(process: subprocess.Popen) -> None:
    """End the process and anything it started. On POSIX the worker leads its own process group."""
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True, check=False)
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass


def _reap(process: subprocess.Popen, stop: threading.Event, grace: float) -> None:
    """End a process and release what is ours to release. Safe to call twice and from a finalizer.

    The reader threads close the process's output pipes themselves when those end, which they do
    once the process (and anything holding the pipe) is gone."""
    stop.set()
    _kill_tree(process)
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:  # a process that survives a kill: nothing more can be done here
        pass
    try:
        if process.stdin is not None:
            process.stdin.close()  # the process is gone, so there is nothing to flush into
    except (OSError, ValueError):
        pass


class Worker:
    """A ``meguvizdexdash serve`` process over a set of inputs. See the module text."""

    def __init__(self, inputs: Sequence[Input | str], *, dialect: str = "native-v1",
                 binary: str | os.PathLike[str] | None = None, command: Sequence[str] | None = None,
                 startup_timeout: float = 120.0, grace: float = 5.0,
                 max_line_bytes: int = DEFAULT_MAX_LINE_BYTES, env: dict[str, str] | None = None):
        paths = [(item.path if isinstance(item, Input) else str(item)) for item in inputs]
        if not paths:
            raise errors.InvalidArgument("a worker needs at least one input", code="INVALID_ARGUMENT", stage="sdk.worker")
        self._grace = grace
        self._max_line = max_line_bytes
        self._next_id = 0
        self._busy = threading.Lock()
        self._closing = False
        self._dead: errors.MddError | None = None
        self._delivered = {"batches": 0, "rows": 0}
        self._stderr: collections.deque[bytes] = collections.deque()
        self._stop = threading.Event()
        self.abandoned_threads: list[str] = []
        self.description: dict[str, Any] = {}
        argv = list(command) if command is not None else [
            str(binary or find_worker()), "serve", *[a for p in paths for a in ("--input", str(p))],
            "--dialect", dialect]
        self._process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, **(env or {})}, close_fds=True,
            start_new_session=(os.name != "nt"))
        self._lines: queue.Queue[tuple[str, bytes | None]] = queue.Queue(maxsize=_QUEUE_LINES)
        self._threads = [
            threading.Thread(target=_read_stdout, args=(self._process.stdout, self._lines, self._stop, max_line_bytes),
                             name="mdd-worker-stdout", daemon=True),
            threading.Thread(target=_read_stderr, args=(self._process.stderr, self._stderr, self._stop),
                             name="mdd-worker-stderr", daemon=True),
        ]
        for thread in self._threads:
            thread.start()
        self._finalizer = weakref.finalize(self, _reap, self._process, self._stop, grace)
        try:
            self._open(time.monotonic() + startup_timeout)
        except BaseException:
            self._teardown()
            raise

    # ---- state ----

    @property
    def closed(self) -> bool:
        return self._closing or self._dead is not None

    @property
    def pid(self) -> int:
        return self._process.pid

    def _stderr_text(self) -> str:
        return b"".join(self._stderr).decode("utf-8", "replace")[-_STDERR_TAIL:]

    def _teardown(self) -> None:
        """Bounded and idempotent: close stdin, kill, wait, close the pipes, join the readers."""
        _reap(self._process, self._stop, self._grace)
        for thread in self._threads:
            thread.join(timeout=self._grace)
        # A reader that is still blocked means something other than the process holds the pipe open.
        # It is a daemon thread and is left; it is never waited for without a limit.
        self.abandoned_threads = [thread.name for thread in self._threads if thread.is_alive()]
        self._finalizer.detach()

    def _die(self, error: errors.MddError) -> errors.MddError:
        if self._dead is None:
            self._dead = error
        self._teardown()
        return error

    def _lost(self, why: str, *, during: str, partial: bytes | None = None) -> errors.WorkerLost:
        try:
            self._process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            pass
        code = self._process.returncode
        details: dict[str, Any] = {
            "during": during, "exit_code": code, "stderr_tail": self._stderr_text(),
            "batches_delivered": self._delivered["batches"], "rows_delivered": self._delivered["rows"],
        }
        if partial:
            details["partial_line_bytes"] = len(partial)
        error = errors.WorkerLost(f"the worker was lost: {why}", code="WORKER_LOST", stage="sdk.worker",
                                  details=details)
        self._die(error)
        return error

    def _protocol(self, why: str, *, during: str) -> errors.WorkerProtocol:
        error = errors.WorkerProtocol(f"the worker broke the protocol: {why}", code="WORKER_PROTOCOL",
                                      stage="sdk.worker", details={"during": during, "stderr_tail": self._stderr_text()})
        self._die(error)
        return error  # type: ignore[return-value]

    def _expired(self, during: str, seconds: float | None) -> errors.DeadlineExceeded:
        error = errors.DeadlineExceeded(
            f"the worker gave no answer in time{'' if seconds is None else f' ({seconds:g} s)'}",
            code="DEADLINE_EXCEEDED", stage="sdk.worker", details={"during": during})
        self._die(error)
        return error  # type: ignore[return-value]

    # ---- reading ----

    def _next(self, deadline: float | None, *, during: str) -> dict[str, Any]:
        """The next protocol line, as an object. Every way it can fail is an exception of this module."""
        while True:
            if self._dead is not None:  # ended meanwhile (cancelled, say): that is the answer
                raise self._dead
            if self._closing:
                raise errors.Closed("the worker was closed during the query", code="SNAPSHOT_CLOSED", stage="sdk.worker")
            wait = 0.25 if deadline is None else max(0.0, min(0.25, deadline - time.monotonic()))
            try:
                kind, data = self._lines.get(timeout=wait)
            except queue.Empty:
                if deadline is not None and time.monotonic() >= deadline:
                    raise self._expired(during, None)
                if self._process.poll() is not None and self._lines.empty():
                    # the process is gone but the reader has not said so yet: give it a moment
                    time.sleep(0.05)
                    if self._lines.empty():
                        raise self._lost("the process exited", during=during)
                continue
            if kind == "eof":
                if self._closing:
                    raise errors.Closed("the worker was closed during the query", code="SNAPSHOT_CLOSED", stage="sdk.worker")
                raise self._lost("its output ended before the answer did", during=during)
            if kind == "partial":
                raise self._lost("its output stopped in the middle of a line", during=during, partial=data)
            if kind == "oversize":
                raise self._protocol(f"a line longer than {self._max_line} bytes", during=during)
            try:
                message = json.loads(data)  # type: ignore[arg-type]
            except ValueError:
                raise self._protocol("a line that is not JSON", during=during) from None
            if not isinstance(message, dict) or not isinstance(message.get("kind"), str):
                raise self._protocol("a line that is not an object with a kind", during=during)
            return message

    def _open(self, deadline: float) -> None:
        try:
            message = self._next(deadline, during="startup")
        except errors.WorkerLost as lost:
            # A refusal is not a loss: the engine says what it refused on standard error, then exits.
            refusal = self._refusal(lost.details.get("exit_code"), lost.details.get("stderr_tail", ""))
            if refusal is not None:
                self._dead = refusal
                raise refusal from None
            raise
        if message["kind"] != "opened" or message.get("protocol") != STREAM_PROTOCOL:
            raise self._protocol(f"{message.get('kind')!r} where `opened` with protocol {STREAM_PROTOCOL} was due",
                                 during="startup")
        self.description = message.get("dataset") or {}

    @staticmethod
    def _refusal(exit_code: int | None, stderr: str) -> errors.MddError | None:
        if exit_code not in (1, 2):
            return None
        for line in reversed(stderr.strip().splitlines()):
            try:
                body = json.loads(line)
            except ValueError:
                continue
            if isinstance(body, dict) and isinstance(body.get("code"), str):
                error = errors.from_terminal(body)
                error.details = {**error.details, "exit_code": exit_code}
                return error
        return None

    # ---- queries ----

    def query(self, sql: str, *, batch_rows: int | None = None, max_rows: int | None = None,
              deadline_ms: int | None = None, timeout: float | None = None) -> "WorkerQuery":
        """Start a statement. Nothing is read until the batches are asked for. `timeout` is the
        seconds the whole answer may take; `deadline_ms` is the engine's own deadline for it."""
        if self._dead is not None:
            raise errors.Closed("the worker is gone: " + str(self._dead), code="SNAPSHOT_CLOSED", stage="sdk.worker")
        if self._closing:
            raise errors.Closed("the worker is closed", code="SNAPSHOT_CLOSED", stage="sdk.worker")
        if not self._busy.acquire(blocking=False):
            raise errors.Busy("a worker answers one query at a time", code="BUSY", stage="sdk.worker", retryable=True)
        self._next_id += 1
        request: dict[str, Any] = {"id": f"q{self._next_id}", "sql": sql}
        for key, value in (("batch_rows", batch_rows), ("max_rows", max_rows), ("deadline_ms", deadline_ms)):
            if value is not None:
                request[key] = value
        try:
            self._send(request)
        except BaseException:
            self._busy.release()
            raise
        return WorkerQuery(self, request["id"], timeout)

    def execute(self, sql: str, **options: Any) -> Result:
        """Run to the end and return every row, or raise."""
        with self.query(sql, **options) as query:
            return query.collect()

    def _send(self, request: dict[str, Any]) -> None:
        data = (json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            self._process.stdin.write(data)  # type: ignore[union-attr]
            self._process.stdin.flush()  # type: ignore[union-attr]
        except (OSError, ValueError):
            raise self._lost("it did not take the request", during="request") from None

    # ---- ending ----

    def close(self) -> None:
        """Ask the worker to end, wait for it for the grace period, then end it. Idempotent."""
        if self._closing and self._dead is None:
            return
        self._closing = True
        try:
            if self._process.poll() is None and self._dead is None:
                try:
                    self._process.stdin.write(b'{"op":"close"}\n')  # type: ignore[union-attr]
                    self._process.stdin.flush()  # type: ignore[union-attr]
                    self._process.stdin.close()  # type: ignore[union-attr]
                except (OSError, ValueError):
                    pass
                try:
                    self._process.wait(timeout=self._grace)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            self._teardown()

    def __enter__(self) -> "Worker":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class WorkerQuery:
    """One statement on a worker."""

    def __init__(self, worker: Worker, request_id: str, timeout: float | None):
        self._worker = worker
        self.id = request_id
        self._deadline = None if timeout is None else time.monotonic() + timeout
        self._timeout = timeout
        self.terminal: dict[str, Any] | None = None
        self._finished = False
        self._started = False

    def _release(self, *, ended: bool) -> None:
        """The worker is free again only after a terminal; anything else leaves its output out of step."""
        if self._finished:
            return
        self._finished = True
        worker = self._worker
        if not ended and worker._dead is None and not worker._closing:
            worker._die(errors.Cancelled("the query was abandoned before its terminal, so the worker was ended",
                                         code="CANCELLED", stage="sdk.worker"))
        worker._busy.release()

    def batches(self) -> Iterator[Batch]:
        """Yield every batch, then raise if the terminal is not a success. The batches yielded
        before a worker is lost stay yielded; the loss is raised after them."""
        if self._started:
            raise errors.Busy("the batches of a query are read once", code="BUSY", stage="sdk.worker")
        self._started = True
        worker = self._worker
        next_sequence, next_row = 0, 0
        ended = False
        try:
            while True:
                message = worker._next(self._deadline, during=f"query {self.id}")
                kind = message["kind"]
                if kind == "rejected":
                    if message.get("id") not in (self.id, None):
                        raise worker._protocol("an answer for another request", during=f"query {self.id}")
                    ended = True
                    error = errors.from_terminal(message.get("error") or {})
                    raise error
                if message.get("id") != self.id:
                    raise worker._protocol(f"a {kind} line for request {message.get('id')!r} while {self.id!r} is open",
                                           during=f"query {self.id}")
                if kind == "terminal":
                    self.terminal = message.get("terminal")
                    if not isinstance(self.terminal, dict):
                        raise worker._protocol("a terminal that is not an object", during=f"query {self.id}")
                    ended = True
                    break
                if kind != "batch":
                    raise worker._protocol(f"a {kind!r} line inside a query", during=f"query {self.id}")
                document = message.get("batch")
                try:
                    sequence, first_row = int(document["sequence"]), int(document["first_row"])
                    columns = tuple(document["columns"])
                    rows = tuple(tuple(decode_cell(cell) for cell in row) for row in document["rows"])
                except (KeyError, TypeError, ValueError):
                    raise worker._protocol("a batch that does not decode", during=f"query {self.id}") from None
                if sequence != next_sequence or first_row != next_row:
                    raise worker._protocol(
                        f"batch {sequence} from row {first_row} where {next_sequence} from row {next_row} was due",
                        during=f"query {self.id}")
                next_sequence, next_row = sequence + 1, first_row + len(rows)
                worker._delivered["batches"] += 1
                worker._delivered["rows"] += len(rows)
                yield Batch(sequence=sequence, first_row=first_row, columns=columns, rows=rows)
        finally:
            self._release(ended=ended)
        terminal = self.terminal
        if terminal is not None and terminal.get("operation_status") != "ok":
            error = errors.from_terminal(terminal.get("error") or {})
            error.terminal = terminal  # type: ignore[attr-defined]
            raise error

    def collect(self) -> Result:
        columns: tuple[str, ...] = ()
        rows: list[tuple[Any, ...]] = []
        for batch in self.batches():
            columns = batch.columns
            rows.extend(batch.rows)
        if self.terminal is None:
            raise errors.MddError("the stream ended without a terminal", code="INTERNAL_FAULT", stage="sdk.worker")
        result = Result(columns, rows, self.terminal)
        if not result.is_complete:
            raise errors.MddError("the query ended without a complete result", code="INCOMPLETE_RESULT",
                                  stage="sdk.worker", details={"terminal": self.terminal})
        return result

    def cancel(self) -> None:
        """Stop the query. A worker cannot be told to stop one statement, so this ends the worker."""
        worker = self._worker
        if worker._dead is None and not worker._closing:
            worker._die(errors.Cancelled("the query was cancelled, which ends the worker",
                                         code="CANCELLED", stage="sdk.worker"))

    def close(self) -> None:
        """Give up the query; one that has not ended ends the worker."""
        self._release(ended=self.terminal is not None)

    def __enter__(self) -> "WorkerQuery":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        # A query that is dropped without being read to its end would keep the worker busy for ever.
        try:
            self.close()
        except Exception:  # noqa: BLE001 - nothing can be done about it in a finalizer
            pass


__all__ = ["DEFAULT_MAX_LINE_BYTES", "STREAM_PROTOCOL", "Worker", "WorkerQuery", "find_worker", "is_complete"]
