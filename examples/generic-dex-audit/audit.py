#!/usr/bin/env python3
"""Generic DEX/APK structural inventory and cross-DEX reachability auditor.

Depends ONLY on public MeguvizDexDash contracts:
  - Python SDK over C ABI 1.0 (`mdd.open_snapshot`, `mdd.Worker`)
  - CLI worker stream (`meguvizdexdash serve`, protocol `mdd.cli-stream.v1`)
  - MCP JSON-RPC stdio (`meguvizdexdash mcp`)

Contains zero custom DEX/ZIP/AXML binary parsers and zero business-adapter or external-engine symbols.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

CONSUMER_VERSION = "0.1.0"
AUDIT_SCHEMA = "mdd.generic-dex-audit.v1"
STRUCTURE_SCHEMA = "mdd.generic-structure-audit.v1"
REACHABILITY_SCHEMA = "mdd.generic-reachability-audit.v1"
DEFAULT_ENTRYPOINT_NAMES = ("onCreate", "onStartCommand", "onReceive", "runSync", "main", "foo")

REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON_SDK_DIR = REPO_ROOT / "python"
if str(PYTHON_SDK_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_SDK_DIR))

import mdd  # noqa: E402
from mdd import errors as mdd_errors  # noqa: E402


class AuditError(RuntimeError):
    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.details = details or {}


def _sql_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _sql_like_escape_prefix(prefix: str) -> str:
    escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"LIKE {_sql_quote(escaped + '%')} ESCAPE '\\'"


def _normalize_cell(cell: Any) -> Any:
    if isinstance(cell, mdd.DexMutf8):
        return {
            "kind": "dex_mutf8",
            "hex": cell.raw.hex(),
            "utf16_units": cell.utf16_units,
        }
    if isinstance(cell, bytes):
        return {"kind": "bytes", "hex": cell.hex()}
    return cell


def _decode_mcp_cell(cell: dict[str, Any]) -> Any:
    kind = cell.get("type")
    val = cell.get("value")
    if kind == "null":
        return None
    if kind in ("uint64", "int64"):
        return int(val)
    if kind == "float64":
        return val
    if kind == "utf8":
        return str(val)
    if kind == "binary":
        return {"kind": "bytes", "hex": str(val).lower()}
    raise AuditError("PROTOCOL_ERROR", f"unexpected MCP cell type: {kind!r}")


def _verify_sdk_completeness(result: mdd.Result, label: str) -> None:
    if not mdd.is_complete(result.terminal) or not result.is_complete:
        raise AuditError(
            "INCOMPLETE_RESULT",
            f"query {label!r} returned non-complete terminal",
            {"terminal": result.terminal},
        )
    cov = result.coverage
    if cov.get("input") != "complete" or cov.get("facts") != "complete":
        raise AuditError(
            "INCOMPLETE_COVERAGE",
            f"query {label!r} did not achieve complete input/facts coverage",
            {"coverage": cov},
        )


def _display_input(path_str: str) -> str:
    resolved = Path(path_str).resolve()
    if resolved.is_relative_to(REPO_ROOT):
        return resolved.relative_to(REPO_ROOT).as_posix()
    return resolved.name


class _McpSession:
    def __init__(self, binary: Path, dialect: str, timeout_ms: int):
        self._proc = subprocess.Popen(
            [str(binary), "mcp", "--dialect", dialect, "--timeout-ms", str(timeout_ms)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=REPO_ROOT,
        )
        self._req_id = 0
        self.dataset_id: str | None = None
        self.opened: dict[str, Any] = {}

    def _request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._req_id += 1
        req = {"jsonrpc": "2.0", "id": self._req_id, "method": method}
        if params is not None:
            req["params"] = params
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._proc.stdin.write((json.dumps(req) + "\n").encode("utf-8"))
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            stderr = self._proc.stderr.read().decode("utf-8", "replace") if self._proc.stderr else ""
            raise AuditError("WORKER_LOST", f"MCP server closed stdout unexpectedly: {stderr}")
        resp = json.loads(line)
        if resp.get("id") != self._req_id:
            raise AuditError("PROTOCOL_ERROR", f"mismatched MCP response id: {resp!r}")
        if "error" in resp:
            err = resp["error"]
            raise AuditError(str(err.get("code", "MCP_ERROR")), str(err.get("message", err)), err)
        return resp["result"]

    def initialize(self) -> None:
        self._request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mdd-generic-dex-audit", "version": CONSUMER_VERSION},
            },
        )
        assert self._proc.stdin is not None
        notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        self._proc.stdin.write((json.dumps(notif) + "\n").encode("utf-8"))
        self._proc.stdin.flush()

    def call_tool(self, name: str, **arguments: Any) -> dict[str, Any]:
        result = self._request("tools/call", {"name": name, "arguments": arguments})
        structured = dict(result["structuredContent"])
        if result.get("isError"):
            code = str(structured.get("code") or structured.get("kind") or "TOOL_ERROR")
            raise AuditError(code, str(structured.get("message") or structured), structured)
        return structured

    def open_dataset(self, inputs: list[str]) -> dict[str, Any]:
        self.opened = self.call_tool("open_dataset", inputs=inputs)
        self.dataset_id = str(self.opened["dataset_id"])
        return self.opened

    def query_all(self, sql: str, *, page_limit: int = 1000) -> tuple[tuple[str, ...], list[tuple[Any, ...]]]:
        assert self.dataset_id is not None
        offset = 0
        columns: tuple[str, ...] = ()
        rows: list[tuple[Any, ...]] = []
        while True:
            reply = self.call_tool("query", dataset_id=self.dataset_id, sql=[sql], offset=offset, limit=page_limit)
            stmts = reply.get("statements") or []
            if len(stmts) != 1:
                raise AuditError("PROTOCOL_ERROR", f"expected 1 statement result, got {len(stmts)}")
            stmt = stmts[0]
            if not columns:
                columns = tuple(col["name"] for col in stmt["columns"])
            for raw_row in stmt["rows"]:
                rows.append(tuple(_decode_mcp_cell(cell) for cell in raw_row))
            next_off = stmt.get("next_offset")
            if next_off is None:
                if stmt.get("truncated"):
                    raise AuditError("INCOMPLETE_RESULT", "statement remained truncated without next_offset", stmt)
                break
            offset = int(next_off)
        return columns, rows

    def close(self) -> None:
        try:
            if self.dataset_id is not None and self._proc.poll() is None:
                try:
                    self.call_tool("close_dataset", dataset_id=self.dataset_id)
                except Exception:
                    pass
            if self._proc.stdin is not None:
                try:
                    self._proc.stdin.close()
                except OSError:
                    pass
            if self._proc.poll() is None:
                try:
                    self._proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    self._proc.wait(timeout=5)
        finally:
            for stream in (self._proc.stdout, self._proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass


def _build_structure_audit_native(
    execute_fn,
    class_prefix: str | None,
) -> dict[str, Any]:
    occ_res = execute_fn(
        "SELECT dex_occurrence_id, physical_dex_id, member_id, content_id FROM native_dex_occurrences"
    )
    occ_to_ordinal: dict[str, int] = {}
    occurrences = []
    for idx, row in enumerate(occ_res.rows):
        occ_id, phys_id, member_id, content_id = row
        occ_to_ordinal[occ_id] = idx
        occurrences.append(
            {
                "occurrence_ordinal": idx,
                "content_id": content_id,
                "dex_version": None,
                "entry_name": None,
                "member_suffix": member_id.split(":", 2)[-1] if ":" in member_id else member_id,
            }
        )

    where_clause = f" WHERE c.descriptor {_sql_like_escape_prefix(class_prefix)}" if class_prefix else ""
    cls_res = execute_fn(
        "SELECT c.dex_occurrence_id, c.descriptor, c.access_flags, sup.descriptor AS superclass_descriptor "
        "FROM native_classes c "
        "LEFT JOIN native_types sup ON sup.dex_occurrence_id = c.dex_occurrence_id "
        "AND sup.type_idx = c.superclass_type_idx"
        f"{where_clause}"
    )
    classes = sorted(
        [
            {
                "occurrence_ordinal": occ_to_ordinal[row[0]],
                "descriptor": row[1],
                "access_flags": int(row[2]),
                "superclass_descriptor": row[3],
            }
            for row in cls_res.rows
        ],
        key=lambda item: (item["occurrence_ordinal"], item["descriptor"]),
    )

    m_res = execute_fn(
        "SELECT m.dex_occurrence_id, c.descriptor AS class_descriptor, m.method_idx, "
        "mr.name, p.descriptor AS proto, m.kind, m.access_flags, m.code_byte_offset, m.declared_insns_size "
        "FROM native_classes c "
        "JOIN native_method_definitions m ON m.dex_occurrence_id = c.dex_occurrence_id AND m.class_def_idx = c.class_def_idx "
        "JOIN native_method_references mr ON mr.dex_occurrence_id = c.dex_occurrence_id AND mr.method_idx = m.method_idx "
        "JOIN native_prototypes p ON p.dex_occurrence_id = c.dex_occurrence_id AND p.proto_idx = mr.prototype_idx"
        f"{where_clause}"
    )
    methods = sorted(
        [
            {
                "occurrence_ordinal": occ_to_ordinal[row[0]],
                "class_descriptor": row[1],
                "method_idx": int(row[2]),
                "method_name": row[3],
                "method_descriptor": f"{row[1]}->{row[3]}{row[4]}",
                "kind": row[5],
                "access_flags": int(row[6]),
                "code_off": int(row[7]) if row[7] is not None else None,
                "insns_size": int(row[8]) if row[8] is not None else None,
            }
            for row in m_res.rows
        ],
        key=lambda item: (item["occurrence_ordinal"], item["method_idx"]),
    )

    # Also capture up to 50 sample strings (showing MUTF-8 preservation for embedded NUL / non-ASCII).
    str_where = " WHERE " + (
        "string_idx < 50" if not class_prefix else f"value {_sql_like_escape_prefix(class_prefix)}"
    )
    str_res = execute_fn(
        f"SELECT dex_occurrence_id, string_idx, value, raw_mutf8 FROM native_strings{str_where} ORDER BY dex_occurrence_id, string_idx LIMIT 50"
    )
    sample_strings = [
        {
            "occurrence_ordinal": occ_to_ordinal[row[0]],
            "string_idx": int(row[1]),
            "value": _normalize_cell(row[2]),
            "raw_mutf8": _normalize_cell(row[3]),
        }
        for row in str_res.rows
    ]

    structure = {
        "schema": STRUCTURE_SCHEMA,
        "occurrence_count": len(occurrences),
        "distinct_content_count": len({o["content_id"] for o in occurrences}),
        "class_count": len(classes),
        "defined_method_count": len(methods),
        "classes": classes,
        "defined_methods": methods,
    }
    return structure, occurrences, sample_strings


def _build_structure_and_reachability_dexsql(
    query_fn,
    class_prefix: str | None,
    entrypoint_names: list[str],
    max_hops: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    _, dex_rows = query_fn(
        "SELECT file_id, entry_name, dex_version, byte_len, signature_hex, class_count, method_count "
        "FROM dex_files ORDER BY file_id"
    )
    occurrences = [
        {
            "occurrence_ordinal": int(row[0]),
            "signature_sha1": row[4],
            "dex_version": row[2],
            "entry_name": row[1],
            "byte_len": int(row[3]),
            "class_count": int(row[5]),
            "method_count": int(row[6]),
        }
        for row in dex_rows
    ]

    def _pair_in_sql(pairs: list[tuple[int, int]], second_col: str, chunk_size: int = 200) -> list[str]:
        by_file: dict[int, list[int]] = {}
        for fid, idx in pairs:
            by_file.setdefault(fid, []).append(idx)
        clauses: list[str] = []
        for fid, idxs in sorted(by_file.items()):
            uniq_sorted = sorted(set(idxs))
            for start in range(0, len(uniq_sorted), chunk_size):
                chunk = ", ".join(str(x) for x in uniq_sorted[start : start + chunk_size])
                clauses.append(f"(file_id = {fid} AND {second_col} IN ({chunk}))")
        batches: list[str] = []
        for start in range(0, len(clauses), 20):
            batches.append("(" + " OR ".join(clauses[start : start + 20]) + ")")
        return batches

    cls_where = f" WHERE descriptor {_sql_like_escape_prefix(class_prefix)}" if class_prefix else ""
    _, cls_rows = query_fn(
        f"SELECT file_id, class_idx, descriptor, access_flags, superclass_descriptor FROM classes{cls_where}"
    )
    classes = sorted(
        [
            {
                "occurrence_ordinal": int(row[0]),
                "descriptor": row[2],
                "access_flags": int(row[3]),
                "superclass_descriptor": row[4],
            }
            for row in cls_rows
        ],
        key=lambda item: (item["occurrence_ordinal"], item["descriptor"]),
    )

    class_pairs = [(int(row[0]), int(row[1])) for row in cls_rows]
    cm_rows: list[tuple[Any, ...]] = []
    for where_cls in _pair_in_sql(class_pairs, "class_idx"):
        _, part = query_fn(
            "SELECT file_id, class_descriptor, method_idx, method_name, method_descriptor, kind, access_flags "
            f"FROM class_methods WHERE {where_cls}"
        )
        cm_rows.extend(part)

    method_pairs = [(int(row[0]), int(row[2])) for row in cm_rows]
    code_by_method: dict[tuple[int, int], tuple[int, int | None, int | None]] = {}
    for where_meth in _pair_in_sql(method_pairs, "method_idx"):
        _, part = query_fn(
            f"SELECT file_id, method_idx, code_off, insns_off, insns_size FROM code_items WHERE {where_meth}"
        )
        for crow in part:
            code_by_method[(int(crow[0]), int(crow[1]))] = (
                int(crow[2]),
                int(crow[3]) if crow[3] is not None else None,
                int(crow[4]) if crow[4] is not None else None,
            )

    defined_methods = sorted(
        [
            {
                "occurrence_ordinal": int(row[0]),
                "class_descriptor": row[1],
                "method_idx": int(row[2]),
                "method_name": row[3],
                "method_descriptor": row[4],
                "kind": row[5],
                "access_flags": int(row[6]),
                "code_off": code_by_method.get((int(row[0]), int(row[2])), (None, None, None))[0],
                "insns_size": code_by_method.get((int(row[0]), int(row[2])), (None, None, None))[2],
            }
            for row in cm_rows
        ],
        key=lambda item: (item["occurrence_ordinal"], item["method_idx"]),
    )

    structure = {
        "schema": STRUCTURE_SCHEMA,
        "occurrence_count": len(occurrences),
        "distinct_content_count": len({o["signature_sha1"] for o in occurrences}),
        "class_count": len(classes),
        "defined_method_count": len(defined_methods),
        "classes": classes,
        "defined_methods": defined_methods,
    }

    # --- Reachability audit ---
    ep_set = set(entrypoint_names)
    seed_defs = [
        m for m in defined_methods if (not ep_set or m["method_name"] in ep_set)
    ][:200]
    seed_keys = [(int(m["occurrence_ordinal"]), int(m["method_idx"])) for m in seed_defs]
    seeds = [
        {
            "file_id": int(m["occurrence_ordinal"]),
            "method_idx": int(m["method_idx"]),
            "class_descriptor": m["class_descriptor"],
            "method_name": m["method_name"],
            "method_descriptor": m["method_descriptor"],
        }
        for m in seed_defs
    ]

    visited: set[tuple[int, int]] = set(seed_keys)
    frontier: list[tuple[int, int]] = list(seed_keys)
    call_edges: dict[tuple[int, int, str, str], int] = {}
    reachable_methods: dict[tuple[int, int], dict[str, Any]] = {}

    if visited:
        for _hop in range(max_hops):
            if not frontier:
                break
            callee_descs: set[str] = set()
            for where_pair in _pair_in_sql(frontier, "method_idx"):
                _, calls = query_fn(
                    "SELECT file_id, method_idx, method, method_class, callee, callee_class "
                    f"FROM method_calls WHERE {where_pair} ORDER BY file_id, method_idx, callee"
                )
                for r in calls:
                    key = (int(r[0]), int(r[1]), r[2], r[4])
                    call_edges[key] = call_edges.get(key, 0) + 1
                    callee_descs.add(r[4])
            next_frontier: list[tuple[int, int]] = []
            sorted_callees = sorted(callee_descs)
            for start in range(0, len(sorted_callees), 100):
                in_callees = ", ".join(_sql_quote(d) for d in sorted_callees[start : start + 100])
                _, resolved_defs = query_fn(
                    "SELECT file_id, method_idx FROM class_methods "
                    f"WHERE method_descriptor IN ({in_callees}) ORDER BY file_id, method_idx"
                )
                for r in resolved_defs:
                    node = (int(r[0]), int(r[1]))
                    if node not in visited:
                        visited.add(node)
                        next_frontier.append(node)
            frontier = next_frontier

        # Collect metadata, raw bytecode SHA-256, and string literals for all reachable methods.
        all_nodes = sorted(visited)
        detail_rows: list[tuple[Any, ...]] = []
        str_rows: list[tuple[Any, ...]] = []
        for where_nodes in _pair_in_sql(all_nodes, "method_idx"):
            _, m_part = query_fn(
                "SELECT file_id, method_idx, descriptor, class_descriptor, name, opcode_count, opcode_hex "
                f"FROM methods WHERE {where_nodes} ORDER BY file_id, method_idx"
            )
            detail_rows.extend(m_part)
            _, c_part = query_fn(
                f"SELECT file_id, method_idx, code_off, insns_off, insns_size FROM code_items WHERE {where_nodes}"
            )
            for crow in c_part:
                code_by_method[(int(crow[0]), int(crow[1]))] = (
                    int(crow[2]),
                    int(crow[3]) if crow[3] is not None else None,
                    int(crow[4]) if crow[4] is not None else None,
                )
            _, s_part = query_fn(
                f"SELECT file_id, method_idx, value FROM method_strings WHERE {where_nodes} ORDER BY file_id, method_idx, string_idx"
            )
            str_rows.extend(s_part)

        strings_by_method: dict[tuple[int, int], list[Any]] = {}
        for fid, midx, val in str_rows:
            strings_by_method.setdefault((int(fid), int(midx)), []).append(_normalize_cell(val))

        for r in detail_rows:
            fid, midx = int(r[0]), int(r[1])
            opcode_hex = r[6]
            opcode_bytes = bytes.fromhex(opcode_hex) if isinstance(opcode_hex, str) else b""
            c_info = code_by_method.get((fid, midx), (None, None, None))
            reachable_methods[(fid, midx)] = {
                "file_id": fid,
                "method_idx": midx,
                "descriptor": r[2],
                "class_descriptor": r[3],
                "name": r[4],
                "opcode_count": int(r[5]) if r[5] is not None else None,
                "opcode_hex": opcode_hex,
                "opcode_sha256": hashlib.sha256(opcode_bytes).hexdigest() if opcode_hex else None,
                "code_off": c_info[0],
                "insns_off": c_info[1],
                "insns_size": c_info[2],
                "referenced_strings": strings_by_method.get((fid, midx), []),
            }

    # Resolve target definitions to annotate cross-DEX edges deterministically.
    defs_by_desc: dict[str, list[int]] = {}
    unique_callees = sorted({k[3] for k in call_edges})
    for start in range(0, len(unique_callees), 100):
        in_callees = ", ".join(_sql_quote(d) for d in unique_callees[start : start + 100])
        _, all_targets = query_fn(
            "SELECT method_descriptor, file_id FROM class_methods "
            f"WHERE method_descriptor IN ({in_callees}) ORDER BY method_descriptor, file_id"
        )
        for desc, fid in all_targets:
            defs_by_desc.setdefault(desc, []).append(int(fid))

    edges_out = []
    total_call_sites = 0
    cross_dex_edges = 0
    for (src_fid, src_midx, src_desc, dst_desc), count in sorted(call_edges.items()):
        total_call_sites += count
        target_files = sorted(set(defs_by_desc.get(dst_desc, [])))
        is_cross_dex = bool(target_files) and any(tf != src_fid for tf in target_files)
        if is_cross_dex:
            cross_dex_edges += 1
        edges_out.append(
            {
                "caller_file_id": src_fid,
                "caller_method_idx": src_midx,
                "caller_descriptor": src_desc,
                "callee_descriptor": dst_desc,
                "callee_defined_in_file_ids": target_files,
                "cross_dex": is_cross_dex,
                "call_site_count": count,
            }
        )

    reachability = {
        "schema": REACHABILITY_SCHEMA,
        "max_hops": max_hops,
        "seed_count": len(seeds),
        "reachable_method_count": len(reachable_methods),
        "distinct_edge_count": len(edges_out),
        "total_call_site_count": total_call_sites,
        "cross_dex_edge_count": cross_dex_edges,
        "seeds": seeds,
        "edges": edges_out,
        "reachable_methods": [reachable_methods[k] for k in sorted(reachable_methods)],
    }
    return structure, occurrences, reachability


def _run_cancel_probe(transport: str, inputs: list[str], binary: str | None) -> dict[str, Any]:
    """Start a large streaming cross-join query, cancel after first batch, verify CANCELLED terminal."""
    heavy_sql = "SELECT a.string_idx, b.string_idx FROM native_strings a, native_strings b, native_strings c"
    batches_seen = 0
    cancelled_error: str | None = None
    if transport == "in-process":
        with mdd.open_snapshot(inputs) as snapshot, snapshot.open_session() as session:
            with session.query(heavy_sql) as query:
                try:
                    for _batch in query.batches(demand_rows=5):
                        batches_seen += 1
                        query.cancel()
                except mdd_errors.Cancelled as err:
                    cancelled_error = err.code
                except mdd_errors.MddError as err:
                    raise AuditError("UNEXPECTED_CANCEL_ERROR", f"expected CANCELLED, got {err.code}: {err}") from err
    elif transport == "worker":
        with mdd.Worker(inputs, dialect="native-v1", binary=binary) as worker:
            with worker.query(heavy_sql, batch_rows=5) as query:
                try:
                    for _batch in query.batches():
                        batches_seen += 1
                        query.cancel()
                except mdd_errors.Cancelled as err:
                    cancelled_error = err.code
                except mdd_errors.MddError as err:
                    raise AuditError("UNEXPECTED_CANCEL_ERROR", f"expected CANCELLED, got {err.code}: {err}") from err
            if worker.abandoned_threads:
                raise AuditError("LEAKED_THREADS", f"worker left abandoned threads: {worker.abandoned_threads}")
    else:
        raise AuditError("INVALID_ARGUMENT", f"--cancel-probe supports in-process or worker, got {transport!r}")

    if cancelled_error != "CANCELLED":
        raise AuditError("CANCEL_NOT_ENFORCED", f"query finished without CANCELLED error (batches={batches_seen})")
    return {
        "status": "passed",
        "batches_before_cancel": batches_seen,
        "error_code": cancelled_error,
        "partial_rows_returned_as_complete": False,
    }


def run_audit(argv: list[str] | None = None) -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", required=True, dest="inputs", help="DEX or APK input path")
    parser.add_argument("--transport", choices=("in-process", "worker", "mcp"), default="in-process")
    parser.add_argument("--dialect", choices=("native-v1", "dexsql-0.1.0", "dexsql-0.1.1"), default=None)
    parser.add_argument("--entrypoint-prefix", default=None, help="Class descriptor prefix filter, e.g. Lorg/publicdemo/")
    parser.add_argument(
        "--entrypoint-name",
        action="append",
        dest="entrypoint_names",
        help="Seed method names for reachability audit (default: onCreate,onStartCommand,onReceive,runSync,main,foo)",
    )
    parser.add_argument("--max-hops", type=int, default=2)
    parser.add_argument("--binary", default=None, help="Path to meguvizdexdash CLI executable")
    parser.add_argument("--ffi-lib", default=None, help="Path to mdd_ffi shared library")
    parser.add_argument("--timeout-ms", type=int, default=30000)
    parser.add_argument("--cancel-probe", action="store_true", help="Run cancellation/completeness check and include result")
    parser.add_argument("--out", default=None, help="Write JSON report to FILE instead of stdout")
    args = parser.parse_args(argv)

    if args.ffi_lib:
        os.environ["MDD_FFI_LIBRARY"] = str(Path(args.ffi_lib).resolve())
        mdd.load(args.ffi_lib)
    if args.binary:
        os.environ["MDD_WORKER_BINARY"] = str(Path(args.binary).resolve())

    dialect = args.dialect or ("native-v1" if args.transport == "in-process" else "dexsql-0.1.1")
    if args.transport == "in-process" and dialect != "native-v1":
        raise AuditError("UNSUPPORTED_CAPABILITY", "in-process C ABI 1.0 serves native-v1 dialect only")
    if args.transport == "mcp" and dialect == "native-v1":
        raise AuditError("UNSUPPORTED_CAPABILITY", "MCP server requires dexsql-0.1.0 or dexsql-0.1.1")

    entrypoint_names = args.entrypoint_names if args.entrypoint_names is not None else list(DEFAULT_ENTRYPOINT_NAMES)
    input_displays = [_display_input(p) for p in args.inputs]

    snapshot_info: dict[str, Any] = {}
    structure_audit: dict[str, Any]
    dex_occurrences: list[dict[str, Any]]
    mutf8_samples: list[dict[str, Any]] | None = None
    reachability_audit: dict[str, Any] | None = None
    mcp_enrichment: dict[str, Any] | None = None

    if args.transport == "in-process":
        try:
            with mdd.open_snapshot(args.inputs) as snapshot:
                manifest = snapshot.manifest
                snapshot_info = {
                    "snapshot_content_key": manifest["snapshot_content_key"],
                    "captured_input_bytes": int(manifest["captured_input_bytes"]),
                    "source_count": len(manifest["sources"]),
                    "inputs": input_displays,
                }
                with snapshot.open_session() as session:
                    def _exec(sql: str) -> mdd.Result:
                        res = session.execute(sql)
                        _verify_sdk_completeness(res, sql)
                        return res

                    structure_audit, dex_occurrences, mutf8_samples = _build_structure_audit_native(
                        _exec, args.entrypoint_prefix
                    )
        except mdd_errors.MddError as err:
            raise AuditError(err.code or "ENGINE_ERROR", str(err), getattr(err, "details", {})) from err

    elif args.transport == "worker":
        try:
            with mdd.Worker(args.inputs, dialect=dialect, binary=args.binary) as worker:
                snapshot_info = {
                    "snapshot_content_key": None,
                    "scope_id": worker.description.get("scope_id"),
                    "dex_count": worker.description.get("dex_count"),
                    "profile": worker.description.get("profile"),
                    "inputs": input_displays,
                }

                def _exec_worker(sql: str) -> mdd.Result:
                    res = worker.execute(sql)
                    _verify_sdk_completeness(res, sql)
                    return res

                if dialect == "native-v1":
                    structure_audit, dex_occurrences, mutf8_samples = _build_structure_audit_native(
                        _exec_worker, args.entrypoint_prefix
                    )
                else:
                    def _query_rows(sql: str) -> tuple[tuple[str, ...], list[tuple[Any, ...]]]:
                        res = _exec_worker(sql)
                        return res.columns, res.rows

                    structure_audit, dex_occurrences, reachability_audit = _build_structure_and_reachability_dexsql(
                        _query_rows, args.entrypoint_prefix, entrypoint_names, args.max_hops
                    )
        except mdd_errors.MddError as err:
            raise AuditError(err.code or "WORKER_ERROR", str(err), getattr(err, "details", {})) from err

    else:  # mcp
        cli_bin = Path(args.binary).resolve() if args.binary else mdd.find_worker()
        client = _McpSession(cli_bin, dialect, args.timeout_ms)
        try:
            client.initialize()
            opened = client.open_dataset(args.inputs)
            manifest = opened.get("snapshot_manifest") or {}
            snapshot_info = {
                "snapshot_content_key": manifest.get("snapshot_content_key"),
                "scope_id": opened.get("scope_id"),
                "dex_count": opened.get("dex_count"),
                "profile": opened.get("profile"),
                "captured_input_bytes": int(manifest["captured_input_bytes"]) if "captured_input_bytes" in manifest else opened.get("input_bytes"),
                "inputs": input_displays,
            }
            if not opened.get("has_dex"):
                raise AuditError("NO_DEX", "input contains no valid DEX members")
            structure_audit, dex_occurrences, reachability_audit = _build_structure_and_reachability_dexsql(
                client.query_all, args.entrypoint_prefix, entrypoint_names, args.max_hops
            )

            # Optional MCP-only enrichment (kept strictly separate from raw SQL facts).
            exported_components: list[dict[str, Any]] = []
            archive_inputs = opened.get("archive_inputs") or []
            if archive_inputs:
                comp_offset = 0
                while True:
                    comp_page = client.call_tool(
                        "get_manifest_components",
                        dataset_id=client.dataset_id,
                        only_exported=True,
                        offset=comp_offset,
                        limit=200,
                    )
                    exported_components.extend(comp_page.get("components") or [])
                    if comp_page.get("next_offset") is None:
                        break
                    comp_offset = int(comp_page["next_offset"])

            smali_preview = None
            for m in reachability_audit["reachable_methods"]:
                if m.get("code_off") is not None:
                    decoded = client.call_tool(
                        "decode",
                        dataset_id=client.dataset_id,
                        file_id=m["file_id"],
                        method_idx=m["method_idx"],
                        mode="smali",
                        max_lines=40,
                    )
                    smali_text = ((decoded.get("methods") or [{}])[0].get("smali") or "")
                    smali_preview = {
                        "file_id": m["file_id"],
                        "method_idx": m["method_idx"],
                        "descriptor": m["descriptor"],
                        "text_format": decoded.get("text_format"),
                        "replaces_raw_bytecode_facts": False,
                        "line_count": len(smali_text.splitlines()),
                        "excerpt": smali_text[:400],
                    }
                    break

            mcp_enrichment = {
                "exported_components": exported_components,
                "smali_preview": smali_preview,
            }
        finally:
            client.close()

    snapshot_info["dex_occurrences"] = dex_occurrences
    report: dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "consumer": {
            "name": "mdd-generic-dex-audit",
            "version": CONSUMER_VERSION,
            "transport": args.transport,
            "sql_dialect": dialect,
            "core_boundary": "public SDK/worker/MCP only; zero business-adapter or external-engine imports",
        },
        "snapshot": snapshot_info,
        "structure_audit": structure_audit,
        "mutf8_samples": mutf8_samples,
        "reachability_audit": reachability_audit,
        "mcp_enrichment": mcp_enrichment,
    }
    if args.cancel_probe:
        report["cancel_probe"] = _run_cancel_probe(args.transport, args.inputs, args.binary)
    return report


def main(argv: list[str] | None = None) -> int:
    try:
        report = run_audit(argv)
    except AuditError as err:
        sys.stderr.write(json.dumps({"error": {"code": err.code, "message": str(err), "details": err.details}}) + "\n")
        return 1
    out_flag = None
    raw_argv = argv if argv is not None else sys.argv[1:]
    for idx, token in enumerate(raw_argv):
        if token == "--out" and idx + 1 < len(raw_argv):
            out_flag = raw_argv[idx + 1]
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if out_flag:
        out_path = Path(out_flag)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(encoded, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    sys.exit(main())
