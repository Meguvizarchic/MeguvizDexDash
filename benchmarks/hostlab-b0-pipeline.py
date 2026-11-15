#!/usr/bin/env python3
"""B0: the HostLab consumption contract over the MeguvizDexDash CLI.

B0 keeps what HostLab's native audit consumes - the request order, the SQL it sends,
and the DTO it builds - and replaces the engine behind it. This script is that
adapter plus a driver that runs a fixed request list through it.

`B0Session` has the public surface of HostLab's `native_cli.CliSession`
(context manager, `files`, `opened`, `rows`, `all`) and builds the same DTO: a list
of dicts whose values are `str` or `None`. It sends the same statements that
`CliSession.rows` sends - a `LIMIT 0` shape query, then the hex projection
`CASE WHEN c IS NULL THEN 'N' ELSE hex(CAST(c AS TEXT)) END` - and applies the same
guards (stable ordering, complete row and byte budgets, strict UTF-8, no ambiguous
columns). Only the wire differs: the framed JSON lines of `meguvizdexdash serve`
instead of Unicode table lines read in 64 KiB pieces into an 8-slot queue.

What this is not: it does not import or run HostLab's own modules (`native_audit`,
`analysis_batch`, `install_dexsql`), so it does not show that HostLab's rules run
unchanged on this engine; that is the HostLab adapter task. It is not a performance
qualification: the timings it records are one run's wall clock on one host, taken
outside an exclusive measurement window.

Usage:
  python -I benchmarks/hostlab-b0-pipeline.py verify  [--binary PATH] [--out FILE]
  python -I benchmarks/hostlab-b0-pipeline.py run     --input PATH... [--statements FILE] [--binary PATH] [--rounds N] [--out FILE]

`verify` replays the frozen required variants against the frozen A0 golden through
the CLI and checks the DTO against the typed rows. `run` replays a statement list over
any inputs (for example a public APK) and records counts, digests and timings.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = "conformance/corpus/hostlab/required-variants.json"
GOLDEN = "conformance/corpus/hostlab/expected-results/hostlab-a0-golden.json"
DEFAULT_BINARY = ROOT / "target" / "debug" / ("meguvizdexdash.exe" if os.name == "nt" else "meguvizdexdash")
MAX_LINE_BYTES = 4 * 1024 * 1024  # HostLab's native CLI row budget
MAX_SQL_BYTES = 256 * 1024  # HostLab's statement budget


class B0Error(RuntimeError):
    pass


def canonical_cell(cell: dict) -> str:
    """The cell form `generate_golden.py` records for A0: N, i:, f:, t:, b:."""
    tag = cell["t"]
    if tag == "null":
        return "N"
    if tag in ("i64", "u64"):
        return "i:" + cell["v"]
    if tag == "text":
        if "v" in cell:
            return "t:" + cell["v"].encode("utf-8").hex()
        return "t:<non-scalar>"
    if tag == "bytes":
        return "b:" + cell["v"]
    if tag == "f64":
        bits = int(cell["bits"], 16)
        if (bits >> 52) & 0x7FF == 0x7FF and bits & ((1 << 52) - 1):
            return "f:nan"
        return "f:" + cell["bits"]
    raise B0Error("unknown cell tag " + tag)


class B0Session:
    """Same surface as HostLab's CliSession, over `meguvizdexdash serve`."""

    def __init__(self, inputs, timeout=900, binary=None, dialect="dexsql-0.1.0", sql_limits=None):
        self.inputs = [Path(p).resolve(strict=True) for p in (inputs if isinstance(inputs, (list, tuple)) else [inputs])]
        self.timeout = timeout
        self.binary = Path(binary) if binary else DEFAULT_BINARY
        self.dialect = dialect
        # The engine's own SQL budgets (--sql-max-steps, --sql-max-scanned-rows,
        # --sql-max-result-rows), when the caller needs more than the defaults.
        self.sql_limits = dict(sql_limits or {})
        self.deadline = time.monotonic() + timeout
        self.queries = 0
        self.next_id = 0
        self.stdout_bytes = 0
        self.request_seconds = 0.0

    def __enter__(self):
        started = time.perf_counter()
        command = [str(self.binary), "serve", "--dialect", self.dialect,
                   "--deadline-ms", str(int(self.timeout * 1000))]
        for name, value in self.sql_limits.items():
            command += ["--sql-max-" + name.replace("_", "-"), str(value)]
        for path in self.inputs:
            command += ["--input", str(path)]
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
        self.stderr_text = b""
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        try:
            opened = self._line()
            if opened.get("kind") != "opened" or opened.get("protocol") != "mdd.cli-stream.v1":
                raise B0Error("serve did not open with the expected stream protocol")
            self.dataset = opened["dataset"]
            self.files = {int(r["file_id"]): r["entry_name"]
                          for r in self.rows("SELECT file_id,entry_name FROM dex_files ORDER BY file_id")}
            self.opened = {"backend": "meguvizdexdash", "transport": "cli_jsonl_v1",
                           "prepare_ms": (time.perf_counter() - started) * 1000, "files": self.files,
                           "cache": "memory_session", "layer_issues": self.dataset["layer_issues"]}
            return self
        except BaseException:
            self.__exit__(RuntimeError, None, None)
            raise

    def _drain_stderr(self):
        data = self.process.stderr.read()
        self.stderr_text = data

    def _line(self):
        if time.monotonic() >= self.deadline:
            raise TimeoutError("native audit deadline exhausted")
        timer = threading.Timer(max(0.001, self.deadline - time.monotonic()), self.process.kill)
        timer.start()
        try:
            raw = self.process.stdout.readline(MAX_LINE_BYTES + 1)
        finally:
            timer.cancel()
        if not raw:
            raise B0Error("native audit CLI exited before a complete result: " + self.stderr_text.decode("utf-8", "replace"))
        if len(raw) > MAX_LINE_BYTES or not raw.endswith(b"\n"):
            raise B0Error("native CLI row exceeds its byte budget")
        self.stdout_bytes += len(raw)
        return json.loads(raw)

    def request(self, sql, **options):
        """Send one statement; yield its frames, ending with the terminal."""
        if len(sql.encode("utf-8")) > MAX_SQL_BYTES:
            raise B0Error("native audit SQL exceeds its byte budget")
        self.next_id += 1
        rid = f"b0-{self.next_id}"
        message = {"id": rid, "sql": sql, **options}
        self.process.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
        self.process.stdin.flush()
        started = time.perf_counter()
        try:
            while True:
                frame = self._line()
                if frame.get("id") != rid:
                    raise B0Error("a frame for another request arrived")
                if frame["kind"] == "rejected":
                    raise B0Error("request rejected: " + json.dumps(frame["error"]))
                yield frame
                if frame["kind"] == "terminal":
                    return
        finally:
            self.request_seconds += time.perf_counter() - started

    def typed(self, sql, **options):
        """(columns, rows of canonical cells, terminal). Raises if the statement failed."""
        columns, rows = None, []
        for frame in self.request(sql, **options):
            if frame["kind"] == "batch":
                columns = frame["batch"]["columns"]
                rows.extend([canonical_cell(c) for c in row] for row in frame["batch"]["rows"])
            else:
                terminal = frame["terminal"]
                if terminal["operation_status"] != "ok":
                    raise B0Error("statement failed: " + json.dumps(terminal["error"]))
                if not terminal["execution"]["complete"] or terminal["response"]["truncated"]:
                    raise B0Error("statement did not finish completely")
                columns = terminal["data"]["columns"]
                if int(terminal["response"]["emitted_rows"]) != len(rows):
                    raise B0Error("terminal row count differs from the rows delivered")
        return columns, rows

    def table(self, sql, *, expected=None):
        """Yield (columns, None) then (columns, cells) per row, like CliSession.table."""
        columns, used = None, 0
        for frame in self.request(sql):
            if frame["kind"] == "batch":
                if columns is None:
                    columns = self._columns(frame["batch"]["columns"], expected)
                    yield columns, None
                for row in frame["batch"]["rows"]:
                    used += 1
                    yield columns, [cell["v"] for cell in row]
            else:
                terminal = frame["terminal"]
                if terminal["operation_status"] != "ok":
                    raise B0Error("native audit CLI failed: " + json.dumps(terminal["error"]))
                if columns is None:
                    columns = self._columns(terminal["data"]["columns"], expected)
                    yield columns, None
        if columns is None:
            raise B0Error("native audit CLI did not return the requested columns")

    @staticmethod
    def _columns(columns, expected):
        if expected is not None and columns != expected:
            raise B0Error("native audit CLI column identity mismatch")
        return columns

    def rows(self, sql, *, page_size=1000, max_rows=500000, max_bytes=128 * 1024 * 1024):
        if "ORDER BY" not in sql.upper():
            raise ValueError("native audit requires stable ordering")
        columns = None
        for names, row in self.table("SELECT * FROM (" + sql + ") AS hostlab_shape LIMIT 0"):
            if row is not None:
                raise B0Error("native audit shape query unexpectedly returned data")
            columns = names
        if not columns or len(columns) != len(set(columns)):
            raise B0Error("ambiguous native audit columns")

        def identifier(name):
            return '"' + name.replace('"', '""') + '"'

        projected = ["CASE WHEN " + identifier(n) + " IS NULL THEN 'N' ELSE hex(CAST(" + identifier(n) + " AS TEXT)) END AS " + identifier(n)
                     for n in columns]
        statement = "SELECT " + ",".join(projected) + " FROM (" + sql + ") AS hostlab_rows"
        used, count = 0, 0
        for names, cells in self.table(statement, expected=columns):
            if cells is None:
                continue
            count += 1
            if count > max_rows:
                raise B0Error("native audit exceeded its complete row budget")
            decoded = []
            for cell in cells:
                if cell == "N":
                    value = None
                else:
                    try:
                        value = bytes.fromhex(cell).decode("utf-8", "strict")
                    except (ValueError, UnicodeError):
                        raise B0Error("native audit returned a malformed hex cell") from None
                used += len(value.encode()) if value is not None else 0
                if used > max_bytes:
                    raise B0Error("native audit exceeded its complete byte budget")
                decoded.append(value)
            yield dict(zip(names, decoded))
        self.queries += 1

    def all(self, sql, **bounds):
        return list(self.rows(sql, **bounds))

    def __exit__(self, error, *_):
        process = getattr(self, "process", None)
        if process is None:
            return
        try:
            if error is None and process.poll() is None:
                process.stdin.write(b'{"op":"close"}\n')
                process.stdin.flush()
                process.stdin.close()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    raise B0Error("native audit CLI did not exit after close") from None
                if process.returncode:
                    raise B0Error("native audit CLI exited unsuccessfully: " + str(process.returncode))
            elif process.poll() is None:
                process.kill()
        finally:
            if process.poll() is None:
                process.kill()
            for stream in (process.stdin, process.stdout):
                try:
                    stream.close()
                except (BrokenPipeError, OSError, ValueError):
                    pass
            process.wait()


# ---- the driver --------------------------------------------------------------


def load(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def text_of(cell: str):
    """What CAST(x AS TEXT) gives for a canonical typed cell, or a reason it is not compared."""
    if cell == "N":
        return None, None
    kind, _, body = cell.partition(":")
    if kind == "i":
        return body, None
    if kind == "t" and body != "<non-scalar>":
        return bytes.fromhex(body).decode("utf-8"), None
    return None, kind


def verify(binary, dialect="dexsql-0.1.1") -> dict:
    spec, golden = load(VARIANTS), load(GOLDEN)
    if golden["inputs"] != spec["inputs"]:
        raise B0Error("golden and variants name different inputs")
    inputs = [ROOT / p for p in spec["inputs"]]
    counts = {"statements": 0, "compared_to_a0": 0, "skipped_windowed": 0, "dto_compared": 0,
              "dto_skipped_no_order_by": 0, "dto_skipped_duplicate_names": 0,
              "dto_skipped_float_or_bytes": 0, "cells": 0,
              "script_variants_refused": 0}
    script_refusals = []
    differences = []
    with B0Session(inputs, binary=binary, dialect=dialect) as session:
        for variant, case in zip(spec["variants"], golden["cases"]):
            key = variant["family"] + "/" + variant["variant"]
            if (case["family"], case["variant"]) != (variant["family"], variant["variant"]):
                raise B0Error("golden is out of step with the variants at " + key)
            first = case["pages"][0]["statements"]
            for index, sql in enumerate(case["statements"]):
                counts["statements"] += 1
                expected = first[index]
                windowed = case["offset"] != 0 or case["walk"] or expected["truncated"] or expected["next_offset"] is not None
                try:
                    columns, rows = session.typed(sql)
                except B0Error as error:
                    # Splitting a script into statements is the MCP layer's job (MDD-042);
                    # the CLI runs exactly one statement per request. Only the script
                    # variants of Q13 may be refused, only as INVALID_ARGUMENT, and each
                    # refusal is listed with its reason.
                    if key.startswith("Q13/script") and '"code": "INVALID_ARGUMENT"' in str(error):
                        counts["script_variants_refused"] += 1
                        script_refusals.append({"case": key, "statement": index, "reason": str(error)[:160]})
                        continue
                    raise
                if windowed:
                    counts["skipped_windowed"] += 1
                else:
                    counts["compared_to_a0"] += 1
                    counts["cells"] += sum(len(r) for r in rows)
                    if columns != expected["columns"] or rows != expected["rows"]:
                        differences.append({"case": key, "statement": index, "what": "typed rows differ from the A0 golden"})
                if "ORDER BY" not in sql.upper():
                    counts["dto_skipped_no_order_by"] += 1
                    continue
                if len(columns) != len(set(columns)):
                    # HostLab's own guard refuses ambiguous column names for the same
                    # reason; through the wrapper they would come back renamed.
                    counts["dto_skipped_duplicate_names"] += 1
                    continue
                dto = session.all(sql)
                if len(dto) != len(rows) or any(list(d) != columns for d in dto):
                    differences.append({"case": key, "statement": index, "what": "DTO shape differs from the typed rows"})
                    continue
                skipped = False
                for d, typed in zip(dto, rows):
                    for name, cell in zip(columns, typed):
                        value, reason = text_of(cell)
                        if reason is not None:
                            skipped = True
                        elif d[name] != value:
                            differences.append({"case": key, "statement": index, "what": "DTO cell differs", "column": name})
                            break
                    else:
                        continue
                    break
                counts["dto_skipped_float_or_bytes" if skipped else "dto_compared"] += 1
        timing = {"stdout_bytes": session.stdout_bytes, "request_seconds": round(session.request_seconds, 4)}
    return {"mode": "verify", "dialect": dialect, "inputs": spec["inputs"], "counts": counts,
            "script_refusals": script_refusals, "differences": differences, "equal": not differences, "diagnostic_timing": timing}


def statements_from(path):
    spec = json.loads(Path(path).read_text(encoding="utf-8"))
    return [s for variant in spec["variants"] for s in variant["statements"]]


def run(inputs, statements, binary, rounds, dialect="dexsql-0.1.0", sql_limits=None) -> dict:
    ordered = [s for s in statements if "ORDER BY" in s.upper()]
    rounds_out = []
    for number in range(rounds):
        started = time.perf_counter()
        digests, row_count, cell_count = [], 0, 0
        with B0Session(inputs, binary=binary, dialect=dialect, sql_limits=sql_limits) as session:
            opened = time.perf_counter() - started
            per_statement = []
            for sql in ordered:
                t0 = time.perf_counter()
                dto = session.all(sql)
                per_statement.append(time.perf_counter() - t0)
                digests.append(digest(dto))
                row_count += len(dto)
                cell_count += sum(len(d) for d in dto)
            stdout_bytes = session.stdout_bytes
        rounds_out.append({
            "round": number + 1, "open_seconds": round(opened, 4),
            "request_seconds": round(sum(per_statement), 4),
            "total_seconds": round(time.perf_counter() - started, 4),
            "rows": row_count, "cells": cell_count, "stdout_bytes": stdout_bytes,
            "result_digest": digest(digests),
        })
    stable = len({r["result_digest"] for r in rounds_out}) == 1
    return {"mode": "run", "dialect": dialect, "sql_limits": dict(sql_limits or {}), "statements_total": len(statements),
            "statements_run": len(ordered), "statements_skipped_no_order_by": len(statements) - len(ordered),
            "rounds": rounds_out, "digest_stable_across_rounds": stable}


DIFFERENCES = [
    {"layer": "producer", "a0": "DexSQL 0.1.0 (frozen build)", "b0": "MeguvizDexDash facts and SQL bridge", "attributable": "engine implementation, not isolated"},
    {"layer": "wire", "a0": "Unicode table lines on stdout", "b0": "framed JSON lines (mdd.cli-stream.v1)", "attributable": "transport"},
    {"layer": "serialization", "a0": "hex text cells inside table rows", "b0": "typed cells in JSON, then the same hex projection decoded by the adapter", "attributable": "serialization"},
    {"layer": "reader", "a0": "64 KiB read1 into an 8-slot queue, boundary marker query", "b0": "blocking line reads, one terminal per request, no marker query", "attributable": "consumer plumbing"},
    {"layer": "process model", "a0": "one process per APK, interactive", "b0": "one process per input set, serve", "attributable": "same shape"},
    {"layer": "consumer", "a0": "HostLab native_cli.CliSession and native_audit", "b0": "B0Session, same DTO and request order, HostLab modules not imported", "attributable": "adapter"},
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=["verify", "run"])
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--input", action="append", type=Path)
    parser.add_argument("--statements", type=Path, default=ROOT / VARIANTS)
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--dialect")
    for name in ("steps", "scanned-rows", "result-rows"):
        parser.add_argument("--sql-max-" + name, type=int)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.mode == "verify":
        result = verify(args.binary, args.dialect or "dexsql-0.1.1")
    else:
        if not args.input:
            parser.error("run needs at least one --input")
        limits = {name: getattr(args, "sql_max_" + name) for name in ("steps", "scanned_rows", "result_rows")
                  if getattr(args, "sql_max_" + name) is not None}
        result = run(args.input, statements_from(args.statements), args.binary, args.rounds,
                     args.dialect or "dexsql-0.1.0", limits)
    result["differences_from_a0"] = DIFFERENCES
    result["not_a_performance_qualification"] = "one host, no exclusive measurement window, no A0 run alongside"
    text = json.dumps(result, ensure_ascii=False, indent=1) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8", newline="\n")
    print(text if not args.out else f"{args.mode}: wrote {args.out}")
    ok = result.get("equal", True) and result.get("digest_stable_across_rounds", True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
