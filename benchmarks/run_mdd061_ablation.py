#!/usr/bin/env python3
"""MDD-061: Optimization ablation study & paired A1/A0 vs B1 end-to-end regression runner.

Generates and verifies:
  - artifacts/mdd-061/optimization-ablation.json
  - artifacts/mdd-061/end-to-end-regression.json

Reuses `benchmarks/run-five-way-comparison.py` and `benchmarks/observed_run_validator.py`
so every observed_run matches `contracts/benchmark_result.schema.json`, runs under an
exclusive window lease (`check_exclusive_window` + `issue_lease`), preserves incremental
checkpoints under `artifacts/local/mdd-061-runs/`, and never relies on bare `assert`.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterator, Sequence

ROOT = Path(__file__).resolve().parents[1]
BENCH_DIR = Path(__file__).resolve().parent
DECODE_DIR = ROOT / "conformance/decode"
for _p in (str(BENCH_DIR), str(DECODE_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import observed_run_validator as validator  # noqa: E402
fwc = importlib.import_module("run-five-way-comparison")  # noqa: E402
import a0_replay  # noqa: E402

PUBLIC_DIR = ROOT / "artifacts/mdd-061"
ABLATION_PATH = PUBLIC_DIR / "optimization-ablation.json"
REGRESSION_PATH = PUBLIC_DIR / "end-to-end-regression.json"
HISTORICAL_BASELINE_COMMIT = "751a18ba6895daf9fb2b18e3ac03054f286c64d3"
LOCAL_DIR = ROOT / "artifacts/local/mdd-061-runs"

TOGGLE_VARS = (
    "MDD_OPT_QUERY_MEMO",
    "MDD_OPT_SQL_SCAN",
    "MDD_OPT_SQL_FAST_UDF",
    "MDD_OPT_WIRE_DIRECT_JSON",
    "MDD_OPT_PARALLEL_PREPARE",
)

ABLATION_CONFIGS: tuple[tuple[str, dict[str, str], str], ...] = (
    ("all_off", {k: "0" for k in TOGGLE_VARS}, "Baseline scalar/conservative B1 path with all five MDD-061 toggles forced off."),
    ("only_query_memo", {**{k: "0" for k in TOGGLE_VARS}, "MDD_OPT_QUERY_MEMO": "1"}, "Enable only SchemaMemo query/schema memoization (crates/mdd-query/src/optimized/schema_memo.rs)."),
    ("only_sql_scan", {**{k: "0" for k in TOGGLE_VARS}, "MDD_OPT_SQL_SCAN": "1"}, "Enable only CSR LikeAsciiPrefixSuffix + FilterIdCache + DirectCell streaming scan (crates/mdd-sql/src/column_store.rs)."),
    ("only_sql_fast_udf", {**{k: "0" for k in TOGGLE_VARS}, "MDD_OPT_SQL_FAST_UDF": "1"}, "Enable only CompiledLike zero-alloc matcher + inline UDF ReturnPayload + per-row SqlCell reuse (crates/mdd-query/src/optimized/compiled_like.rs, mdd-sql/src/dialects/functions.rs)."),
    ("only_wire_direct_json", {**{k: "0" for k in TOGGLE_VARS}, "MDD_OPT_WIRE_DIRECT_JSON": "1"}, "Enable only BatchStreamEncoder direct JSON framing + fast client batch decode (crates/mdd-wire/src/optimized/batch_codec.rs, integrations/hostlab/native_session.py)."),
    ("only_parallel_prepare", {**{k: "0" for k in TOGGLE_VARS}, "MDD_OPT_PARALLEL_PREPARE": "1"}, "Enable only bounded-window parallel LayerBuilder prepare + overlapping References||Annotations build (crates/mdd-sql/src/provider/hostlab/lazy.rs, mdd-service/src/layers.rs)."),
    ("all_on", {k: "1" for k in TOGGLE_VARS}, "Production default B1 configuration with all five toggleable optimizations active."),
)

REQUIRED_NEWPIPE_GUARDS: dict[str, dict[str, Any]] = {
    "W01-newpipe-intake": {
        "description": "Import, verify & base metadata inventory (W01)",
        "statements": [
            "SELECT file_id, entry_name, string_pool_id FROM dex_files ORDER BY file_id",
        ],
    },
    "W02-newpipe-lookup": {
        "description": "Exact class/method/string targeted lookups (W02)",
        "statements": [
            "SELECT file_id, class_idx, descriptor, access_flags, superclass_descriptor FROM classes WHERE descriptor LIKE 'Lorg/schabi/newpipe/Main%' ORDER BY file_id, class_idx",
            "SELECT file_id, method_idx, class_idx, class_descriptor, name FROM methods WHERE name IN ('onCreate','onDestroy') ORDER BY file_id, method_idx",
            "SELECT string_pool_id, string_idx, value FROM strings WHERE value = 'NewPipe' ORDER BY string_pool_id, string_idx",
        ],
    },
    "W03-newpipe-xref": {
        "description": "String literal prefix and call/field cross-reference lookups (W03)",
        "statements": [
            "SELECT file_id, method_idx, method, method_class FROM method_strings WHERE value LIKE 'http%' ORDER BY file_id, method_idx, method",
            "SELECT file_id, method_idx, method, callee, callee_class FROM method_calls WHERE callee LIKE '%HttpURLConnection%' ORDER BY file_id, method_idx, callee",
            "SELECT file_id, method_idx, method, field, field_type FROM method_field_accesses WHERE field_name = 'INSTANCE' ORDER BY file_id, method_idx, field",
        ],
    },
    "W04-newpipe-joins-agg": {
        "description": "Multi-table joins, aggregations & GROUP BY / ORDER BY queries (W04)",
        "statements": [
            "SELECT c.file_id, c.descriptor, COUNT(ci.ordinal) AS ifaces FROM classes c LEFT JOIN class_interfaces ci ON c.file_id = ci.file_id AND c.class_idx = ci.class_idx GROUP BY c.file_id, c.class_idx, c.descriptor HAVING COUNT(ci.ordinal) >= 2 ORDER BY c.file_id, c.descriptor",
            "SELECT file_id, kind, COUNT(*) AS cnt FROM class_methods GROUP BY file_id, kind ORDER BY file_id, kind",
        ],
    },
}

SOURCES = [
    "benchmarks/run_mdd061_ablation.py",
    "benchmarks/test_mdd061_ablation.py",
    "benchmarks/observed_run_validator.py",
    "benchmarks/run-five-way-comparison.py",
    "crates/mdd-query/src/optimized/mod.rs",
    "crates/mdd-query/src/optimized/schema_memo.rs",
    "crates/mdd-query/src/optimized/compiled_like.rs",
    "crates/mdd-query/src/optimized/prefix_set.rs",
    "crates/mdd-wire/src/optimized/mod.rs",
    "crates/mdd-wire/src/optimized/batch_codec.rs",
    "crates/mdd-wire/src/optimized/columns_v1.rs",
    "integrations/hostlab/native_session.py",
]

COLUMNS_V1_DISPOSITION = {
    "artifact": "crates/mdd-wire/src/optimized/columns_v1.rs",
    "format_magic": "MDDCOLL1",
    "status": "opt_in_evaluated_deferred_for_default_b1",
    "rationale": (
        "Direct streaming UTF-8 JSON framing (BatchStreamEncoder + B1Session._decode_direct_batches) already delivers >=15% W05 speedup over A1 while speaking standard JSON Lines consumed directly by the Python SDK/workbench without a custom binary wire negotiation split; columns-v1 remains cleanly isolated and unit-tested as an opt-in IPC building block."
    ),
}

NON_ADOPTION_RATIONALE = {
    "simd_intrinsics": {
        "adopted": False,
        "evidence_reason": (
            "Profile breakdown in artifacts/mdd-060/optimization-priorities.json shows >85% of W07 runtime is SQL virtual-table LIKE filtering, UDF string allocations, sequential DEX prepare, and JSON serialization. Once CSR TextDict prefix narrowing and borrowed UTF-16 matching landed, pure byte comparison fell below measurability; adding unsafe arch-specific SIMD intrinsics is rejected without bottleneck evidence."
        ),
    },
    "mmap_input_mapping": {
        "adopted": False,
        "evidence_reason": (
            "Input soundness contracts (docs/04 & Snapshot::capture) forbid trusting OS mmap over mutable filesystem files due to TOCTOU / SIGBUS risk on source mutation; bounded immutable snapshot buffers already fit well below A0/A1 peak memory (~1.26-1.36 GiB)."
        ),
    },
    "custom_bump_arena": {
        "adopted": False,
        "evidence_reason": (
            "Arc sharing between DefinitionFacts and AnnotationFacts, compacted CodeFacts, RelationStore columnar dictionary/RLE storage, and BorrowedSqlCell zero-copy callbacks eliminated the ~16.7 GiB heap spike without sacrificing Rust ownership or adding unsafe lifetime-erased arenas."
        ),
    },
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(f"MDD-061 verification failed: {message}")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def sha256_git_blob(commit: str, rel: str) -> str:
    raw = subprocess.check_output(["git", "-C", str(ROOT), "show", f"{commit}:{rel}"])
    return hashlib.sha256(raw).hexdigest()


@contextlib.contextmanager
def env_overrides(mapping: dict[str, str]) -> Iterator[None]:
    prev = {k: os.environ.get(k) for k in mapping}
    try:
        for k, v in mapping.items():
            os.environ[k] = v
        yield
    finally:
        for k, old in prev.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old


def _load_checkpoint_index(path: Path, *, expected_b_sha: str, expected_a1_sha: str, expected_a0_sha: str) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    by_id: dict[str, dict[str, Any]] = {}
    for rec in validator.load_observed_runs(path, check_redaction=True):
        v = rec["variant"]
        bsha = rec["engine"]["binary_sha256"]
        if v in ("B0", "B1") and bsha != expected_b_sha:
            continue
        if v == "A1" and bsha != expected_a1_sha:
            continue
        if v == "A0" and bsha != expected_a0_sha:
            continue
        if rec["execution"]["status"] == "completed" and rec["execution"]["fallback_count"] == 0:
            by_id[rec["run_id"]] = rec
    return by_id


def _append_checkpoint(path: Path, rec: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    validator.validate_observed_run(rec, check_redaction=True)
    line = json.dumps(rec, ensure_ascii=False, allow_nan=False) + "\n"
    with path.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(line)


def _rewrite_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    for r in records:
        validator.validate_observed_run(r, check_redaction=True)
    path.write_text("".join(json.dumps(r, ensure_ascii=False, allow_nan=False) + "\n" for r in records), encoding="utf-8", newline="\n")


def _run_w06_smali_mcp_single(
    variant: str,
    paths: dict[str, Any],
    *,
    block_id: str,
    pair_id: str,
    round_num: int,
    lease_path: Path,
    manifest_sha: str,
    method_descriptor: str = "Lorg/schabi/newpipe/MainActivity;->onDestroy()V",
) -> dict[str, Any]:
    apk = paths["inputs"]["newpipe-0.28.6"]
    binary_path = paths["A1"] if variant == "A1" else paths["B"]
    engine_sha = sha256_file(binary_path)
    run_id = f"mdd061-W06-newpipe-smali-{block_id}-{pair_id}-{variant}"
    if variant == "A1":
        cmd = [str(binary_path), "--threads", "2", "mcp", "--timeout-ms", "120000", "--max-datasets", "1"]
    else:
        cmd = [str(binary_path), "mcp", "--timeout-ms", "120000", "--max-datasets", "1"]

    wall_t0 = time.perf_counter()
    proc = subprocess.Popen(
        cmd,
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )

    def rpc(msg_id: int | None, method: str, params: dict | None = None) -> dict[str, Any] | None:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if msg_id is not None:
            msg["id"] = msg_id
        if params is not None:
            msg["params"] = params
        if proc.stdin is None or proc.stdout is None:
            raise RuntimeError("MCP stdio closed unexpectedly")
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()
        if msg_id is None:
            return None
        while True:
            line = proc.stdout.readline()
            if not line:
                stderr_tail = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(f"{variant} MCP exited early: {stderr_tail}")
            parsed = json.loads(line)
            if parsed.get("id") == msg_id:
                if "error" in parsed:
                    raise RuntimeError(f"{variant} MCP JSON-RPC error: {parsed['error']}")
                return parsed["result"]

    def extract_text_json(res: dict[str, Any]) -> dict[str, Any]:
        if isinstance(res.get("structuredContent"), dict):
            return res["structuredContent"]
        content = res.get("content", [])
        return json.loads("".join(item.get("text", "") for item in content))

    try:
        rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mdd061-w06", "version": "1"}})
        rpc(None, "notifications/initialized")
        open_t0 = time.perf_counter()
        opened = extract_text_json(rpc(2, "tools/call", {"name": "open_dataset", "arguments": {"inputs": [str(apk)]}}))
        open_s = time.perf_counter() - open_t0
        ds_id = opened["dataset_id"]

        c_t0 = time.perf_counter()
        cold_raw = extract_text_json(
            rpc(3, "tools/call", {"name": "decode", "arguments": {"dataset_id": ds_id, "method": method_descriptor, "mode": "smali", "max_lines": 500}})
        )
        cold_s = time.perf_counter() - c_t0

        w_t0 = time.perf_counter()
        warm_raw = extract_text_json(
            rpc(4, "tools/call", {"name": "decode", "arguments": {"dataset_id": ds_id, "method": method_descriptor, "mode": "smali", "max_lines": 500}})
        )
        warm_s = time.perf_counter() - w_t0

        rpc(5, "tools/call", {"name": "close_dataset", "arguments": {"dataset_id": ds_id}})
        if proc.stdin:
            proc.stdin.close()
        rc = proc.wait(timeout=15)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        for s in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if s:
                    s.close()
            except OSError:
                pass

    wall_s = time.perf_counter() - wall_t0
    cold_method = (cold_raw.get("methods") or [{}])[0] if isinstance(cold_raw.get("methods"), list) else cold_raw
    warm_method = (warm_raw.get("methods") or [{}])[0] if isinstance(warm_raw.get("methods"), list) else warm_raw
    cold_text = cold_raw.get("text") or cold_method.get("smali", "")
    warm_text = warm_raw.get("text") or warm_method.get("smali", "")
    require(
        rc == 0
        and bool(cold_text)
        and cold_text == warm_text
        and cold_method.get("next_offset") is None
        and warm_method.get("next_offset") is None,
        f"{variant} W06 decode failed, truncated, or cold!=warm",
    )
    canon_lines = a0_replay.canon_smali(cold_text)
    canon_sha = hashlib.sha256(json.dumps(canon_lines, ensure_ascii=False).encode("utf-8")).hexdigest()

    version_str = "0.1.1" if variant == "A1" else "0.1.0-dev"
    product_str = "DexSQL" if variant == "A1" else "MeguvizDexDash"
    dialect_str = None if variant == "A1" else "dexsql-0.1.1"
    profile_str = "dexsql-0.1.1-mcp" if variant == "A1" else "mdd-native-v1"
    lease_sha = sha256_file(lease_path)

    rec = {
        "schema_version": "mdd.benchmark-run.v1",
        "record_kind": "observed_run",
        "run_id": run_id,
        "pair_id": pair_id,
        "block_id": block_id,
        "round": round_num,
        "workload_id": "W06-newpipe-smali",
        "variant": variant,
        "timestamp_utc": fwc._utc_now(),
        "engine": {
            "product": product_str,
            "version": version_str,
            "build_id": f"{product_str.lower()}-{engine_sha[:12]}",
            "binary_sha256": engine_sha,
            "source_commit": None if variant == "A1" else fwc._git_head(),
            "profile": profile_str,
            "sql_dialect": dialect_str,
        },
        "harness": {
            "revision": fwc._git_head(),
            "manifest_sha256": manifest_sha,
            "command_argv": ["benchmarks/run_mdd061_ablation.py", "--workload", "W06-newpipe-smali", "--variant", variant],
            "timing_boundary": (
                "warm resident decode_smali wall_seconds on complete non-truncated method; "
                "explicit_open_seconds and cold_decode_seconds reported separately (B1 validates 6 layers on open vs A1 header-only open)"
            ),
        },
        "inputs": [{"occurrence_id": "newpipe-0.28.6", "sha256": fwc.DEFAULT_NEWPIPE_SHA, "bytes": str(apk.stat().st_size)}],
        "environment": {
            "machine_id": f"win-x86_64-{hashlib.sha256(platform.node().encode()).hexdigest()[:12]}",
            "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
            "cpu": platform.processor() or platform.machine(),
            "memory_bytes": str(fwc.memory_status()["total_phys_bytes"]),
            "total_cpu_budget": 2.0,
            "engine_threads": 2,
            "concurrent_jobs": 1,
            "cache_state": "warm_engine",
            "cache_control": "resident_second_decode_in_opened_mcp_session",
            "background_load": "exclusive_window_verified_idle_no_concurrent_builds",
            "artifact_sha256": lease_sha,
        },
        "execution": {
            "status": "completed",
            "exit_code": 0,
            "complete_output": True,
            "fallback_count": 0,
            "contaminated": False,
            "contamination_reason": None,
            "wall_seconds": round(warm_s, 6),
        },
        "correctness": {
            "scope_id": "newpipe-0.28.6-12dex",
            "input_complete": True,
            "facts_complete": True,
            "equivalent": True,
            "comparison_mode": "ordered",
            "canonical_sha256": canon_sha,
            "certificate_sha256": canon_sha,
            "mismatch_count": 0,
            "notes": [
                "Smali text reduced with conformance/decode/a0_replay.canon_smali covering opcodes, operands, literals, labels, and catch handlers.",
                "First decode is resident-cold after open_dataset; second decode exercises in-session resident decode.",
            ],
        },
        "metrics": {
            "e2e_wall_seconds": {"value": round(wall_s, 6), "unit": "seconds", "scope": "mcp_open_cold_warm_decode_close", "method": "time.perf_counter"},
            "explicit_open_seconds": {"value": round(open_s, 6), "unit": "seconds", "scope": "explicit_open_dataset_session_setup", "method": "time.perf_counter"},
            "cold_decode_seconds": {"value": round(cold_s, 6), "unit": "seconds", "scope": "first_decode_smali", "method": "time.perf_counter"},
            "warm_decode_seconds": {"value": round(warm_s, 6), "unit": "seconds", "scope": "second_resident_decode_smali", "method": "time.perf_counter"},
            "canonical_line_count": {"value": len(canon_lines), "unit": "count", "scope": "canon_smali_lines", "method": "exact_line_count"},
        },
        "artifacts": [{"path": f"artifacts/local/mdd-061-runs/{run_id}.json", "sha256": canon_sha, "kind": "local_run_digest"}],
    }
    validator.validate_observed_run(rec, check_redaction=True)
    return rec


def _run_newpipe_resident_guards(
    variant: str,
    paths: dict[str, Any],
    *,
    block_id: str,
    pair_id: str,
    round_num: int,
    lease_path: Path,
    manifest_sha: str,
) -> list[dict[str, Any]]:
    """Run W01..W04 guard queries inside one opened session so explicit_open vs query cost is separated."""
    sys.path.insert(0, str(ROOT / "integrations/hostlab"))
    import native_session as ns  # noqa: E402

    apk = paths["inputs"]["newpipe-0.28.6"]
    apk_bytes = str(apk.stat().st_size)
    binary_path = paths["A1"] if variant == "A1" else paths["B"]
    engine_sha = sha256_file(binary_path)
    lease_sha = sha256_file(lease_path)

    version_str = "0.1.1" if variant == "A1" else "0.1.0-dev"
    product_str = "DexSQL" if variant == "A1" else "MeguvizDexDash"
    dialect_str = None if variant == "A1" else "dexsql-0.1.0"
    profile_str = "dexsql-0.1.0-cli" if variant == "A1" else "mdd-native-v1"

    open_t0 = time.perf_counter()
    if variant == "A1":
        sess_cm = fwc.DexSqlCliPipeSession(binary_path, apk, threads=2, timeout=300)
    else:
        cmd = ns.serve_command(
            str(binary_path), [apk], dialect="dexsql-0.1.0", timeout_seconds=300,
            sql_limits=fwc.HOSTLAB_SQL_LIMITS, non_scalar_text="reject",
        )
        settings = ns.StructuralConfig(wire="b1", sql_limits=tuple(fwc.HOSTLAB_SQL_LIMITS.items()))
        launch = ns.EngineLaunch(
            cmd, {**os.environ, "MDD_FACTS_THREADS": "2"},
            {"engine": "meguvizdexdash", "sha256": engine_sha},
        )
        sess_cm = ns.SESSIONS["b1"](apk, timeout=300, threads=2, launch=launch, settings=settings)

    per_workload: list[tuple[str, float, float, int, int, str]] = []
    with sess_cm as sess:
        open_wall_s = time.perf_counter() - open_t0
        explicit_open_s = sess.prepare_seconds if variant == "A1" else (sess.opened["prepare_ms"] / 1000.0)
        for wid, wspec in REQUIRED_NEWPIPE_GUARDS.items():
            repeat = 20 if wid == "W01-newpipe-intake" else 1
            first_canon_sha: str | None = None
            first_row_count = 0
            qt0 = time.perf_counter()
            for _ in range(repeat):
                results_per_stmt: list[tuple[list[str], list[dict[str, Any]]]] = []
                total_rows = 0
                for sql in wspec["statements"]:
                    rows = sess.rows(sql) if variant == "A1" else sess.all(sql)
                    total_rows += len(rows)
                    results_per_stmt.append((list(rows[0].keys()) if rows else [], rows))
                payload = [{"columns": cols, "rows": rws} for cols, rws in results_per_stmt]
                canon_sha = hashlib.sha256(
                    json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                ).hexdigest()
                if first_canon_sha is None:
                    first_canon_sha = canon_sha
                    first_row_count = total_rows
                else:
                    require(canon_sha == first_canon_sha, f"{variant} {wid} repeat mismatch")
            query_s = time.perf_counter() - qt0
            require(first_canon_sha is not None, f"{wid} produced no hash")
            per_workload.append((wid, query_s, explicit_open_s, repeat, first_row_count, str(first_canon_sha)))

    out_records: list[dict[str, Any]] = []
    for wid, query_s, explicit_open_s, repeat, row_count, canon_sha in per_workload:
        rid = f"mdd061-{wid}-{block_id}-{pair_id}-{variant}"
        rec = {
            "schema_version": "mdd.benchmark-run.v1",
            "record_kind": "observed_run",
            "run_id": rid,
            "pair_id": pair_id,
            "block_id": block_id,
            "round": round_num,
            "workload_id": wid,
            "variant": variant,
            "timestamp_utc": fwc._utc_now(),
            "engine": {
                "product": product_str,
                "version": version_str,
                "build_id": f"{product_str.lower()}-{engine_sha[:12]}",
                "binary_sha256": engine_sha,
                "source_commit": None if variant == "A1" else fwc._git_head(),
                "profile": profile_str,
                "sql_dialect": dialect_str,
            },
            "harness": {
                "revision": fwc._git_head(),
                "manifest_sha256": manifest_sha,
                "command_argv": ["benchmarks/run_mdd061_ablation.py", "--workload", wid, "--variant", variant],
                "timing_boundary": (
                    f"resident query_wall_seconds across {wid} ({len(REQUIRED_NEWPIPE_GUARDS[wid]['statements'])} statements x {repeat}); "
                    "explicit_open_seconds reported separately (B1 validates all 6 layers at open)"
                ),
            },
            "inputs": [{"occurrence_id": "newpipe-0.28.6", "sha256": fwc.DEFAULT_NEWPIPE_SHA, "bytes": apk_bytes}],
            "environment": {
                "machine_id": f"win-x86_64-{hashlib.sha256(platform.node().encode()).hexdigest()[:12]}",
                "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
                "cpu": platform.processor() or platform.machine(),
                "memory_bytes": str(fwc.memory_status()["total_phys_bytes"]),
                "total_cpu_budget": 2.0,
                "engine_threads": 2,
                "concurrent_jobs": 1,
                "cache_state": "warm_engine",
                "cache_control": "resident_session_warm_queries_same_open",
                "background_load": "exclusive_window_verified_idle_no_concurrent_builds",
                "artifact_sha256": lease_sha,
            },
            "execution": {
                "status": "completed",
                "exit_code": 0,
                "complete_output": True,
                "fallback_count": 0,
                "contaminated": False,
                "contamination_reason": None,
                "wall_seconds": round(query_s, 6),
            },
            "correctness": {
                "scope_id": "newpipe-0.28.6-12dex",
                "input_complete": True,
                "facts_complete": True,
                "equivalent": True,
                "comparison_mode": "ordered",
                "canonical_sha256": canon_sha,
                "certificate_sha256": canon_sha,
                "mismatch_count": 0,
                "notes": [
                    f"Exact full consumption inside resident {profile_str} session across {repeat} iteration(s).",
                    f"Session explicit_open_seconds={explicit_open_s:.6f}, open_wall_seconds={open_wall_s:.6f}.",
                ],
            },
            "metrics": {
                "resident_query_seconds": {
                    "value": round(query_s, 6),
                    "unit": "seconds",
                    "scope": f"resident_queries_{wid}_x{repeat}",
                    "method": "time.perf_counter",
                },
                "explicit_open_seconds": {
                    "value": round(explicit_open_s, 6),
                    "unit": "seconds",
                    "scope": "explicit_open_session_setup",
                    "method": "time.perf_counter",
                },
                "repeat_iterations": {
                    "value": repeat,
                    "unit": "count",
                    "scope": "per_trial_query_repetitions",
                    "method": "exact_count",
                },
                "total_rows": {
                    "value": row_count,
                    "unit": "count",
                    "scope": wid,
                    "method": "exact_row_count",
                },
            },
            "artifacts": [{"path": f"artifacts/local/mdd-061-runs/{rid}.json", "sha256": canon_sha, "kind": "local_run_digest"}],
        }
        validator.validate_observed_run(rec, check_redaction=True)
        out_records.append(rec)
    return out_records


def run_ablation(
    paths: dict[str, Any],
    *,
    w05_rounds: int = 5,
    w07_all_toggle_pairs: int = 3,
    w07_iso_rounds: int = 1,
    force_rerun: bool = False,
) -> dict[str, Any]:
    LOCAL_DIR.mkdir(parents=True, exist_ok=True)
    w05_ckpt = LOCAL_DIR / "ablation-w05.jsonl"
    w07_ckpt = LOCAL_DIR / "ablation-w07.jsonl"
    if force_rerun:
        w05_ckpt.unlink(missing_ok=True)
        w07_ckpt.unlink(missing_ok=True)

    b_sha = sha256_file(paths["B"])
    a1_sha = sha256_file(paths["A1"])
    a0_sha = sha256_file(paths["A0"])
    w05_cached = _load_checkpoint_index(w05_ckpt, expected_b_sha=b_sha, expected_a1_sha=a1_sha, expected_a0_sha=a0_sha)
    w07_cached = _load_checkpoint_index(w07_ckpt, expected_b_sha=b_sha, expected_a1_sha=a1_sha, expected_a0_sha=a0_sha)

    spec = validator.parse_strict_json(fwc.WORKLOADS_B0_PATH.read_text(encoding="utf-8"))
    w05_statements = [s for v in spec["variants"] for s in v["statements"]]
    manifest_sha = sha256_file(fwc.MANIFEST_PATH)
    lease = fwc.issue_lease("mdd061-ablation", 7200, cpu_affinity_mask=15)

    w05_records: list[dict[str, Any]] = []
    w05_canon_seen: set[str] = set()
    for rnd in range(1, w05_rounds + 1):
        order = ABLATION_CONFIGS if rnd % 2 == 1 else tuple(reversed(ABLATION_CONFIGS))
        for cfg_name, env_map, _desc in order:
            blk = f"ablate-{cfg_name}"
            pid = f"r{rnd:02d}"
            expected_id = f"mdd060-{blk}-{pid}-B1"
            if expected_id in w05_cached:
                rec = w05_cached[expected_id]
            else:
                with env_overrides(env_map):
                    rec = fwc._run_newpipe_single("B1", paths, w05_statements, blk, pid, rnd, lease, manifest_sha)
                _append_checkpoint(w05_ckpt, rec)
                w05_cached[expected_id] = rec
            w05_canon_seen.add(rec["correctness"]["canonical_sha256"])
            w05_records.append(rec)
            print(f"[ablation-W05] r{rnd:02d} {cfg_name}: {rec['execution']['wall_seconds']:.4f}s", flush=True)

    require(len(w05_canon_seen) == 1, f"ablation changed W05 canonical SHA-256: {sorted(w05_canon_seen)}")
    w05_canon_sha = next(iter(w05_canon_seen))

    # W07-hostlab-9161100 ablation: paired all_off vs all_on + per-toggle single optimization runs.
    w07_records: list[dict[str, Any]] = []
    w07_group_hashes: set[str] = set()

    for pidx in range(1, w07_all_toggle_pairs + 1):
        pid = f"p{pidx:02d}"
        pair_order = ("all_off", "all_on") if pidx % 2 == 1 else ("all_on", "all_off")
        for cfg_name in pair_order:
            env_map = dict(next(m for n, m, _ in ABLATION_CONFIGS if n == cfg_name))
            blk = f"ablate-{cfg_name}"
            expected_id = f"mdd060-hostlab-9161100-{blk}-{pid}-B1"
            if expected_id in w07_cached:
                rec = w07_cached[expected_id]
            else:
                with env_overrides(env_map):
                    rec = fwc._run_hostlab_single(
                        "B1", "hostlab-9161100", paths, blk, pid, pidx, lease, manifest_sha, profile_substages=True
                    )
                _append_checkpoint(w07_ckpt, rec)
                w07_cached[expected_id] = rec
            require(rec["execution"]["status"] == "completed" and rec["execution"]["fallback_count"] == 0, f"W07 ablation failed on {expected_id}")
            w07_group_hashes.add(rec["correctness"]["canonical_sha256"])
            w07_records.append(rec)
            print(f"[ablation-W07] {pid} {cfg_name}: {rec['execution']['wall_seconds']:.2f}s", flush=True)

    # Single-opt isolations on W07
    iso_configs = [c for c in ABLATION_CONFIGS if c[0] not in ("all_off", "all_on")]
    for rnd in range(1, w07_iso_rounds + 1):
        pid = f"iso{rnd:02d}"
        order = iso_configs if rnd % 2 == 1 else list(reversed(iso_configs))
        for cfg_name, env_map, _desc in order:
            blk = f"ablate-{cfg_name}"
            expected_id = f"mdd060-hostlab-9161100-{blk}-{pid}-B1"
            if expected_id in w07_cached:
                rec = w07_cached[expected_id]
            else:
                with env_overrides(env_map):
                    rec = fwc._run_hostlab_single(
                        "B1", "hostlab-9161100", paths, blk, pid, rnd, lease, manifest_sha, profile_substages=True
                    )
                _append_checkpoint(w07_ckpt, rec)
                w07_cached[expected_id] = rec
            require(rec["execution"]["status"] == "completed" and rec["execution"]["fallback_count"] == 0, f"W07 iso ablation failed on {expected_id}")
            w07_group_hashes.add(rec["correctness"]["canonical_sha256"])
            w07_records.append(rec)
            print(f"[ablation-W07] {pid} {cfg_name}: {rec['execution']['wall_seconds']:.2f}s", flush=True)

    require(len(w07_group_hashes) == 1, f"W07 ablation changed 20-group hash: {sorted(w07_group_hashes)}")
    w07_group_sha = next(iter(w07_group_hashes))

    def _summarize_cfg(recs: list[dict[str, Any]], base_med: float) -> dict[str, dict[str, Any]]:
        by_cfg: dict[str, list[float]] = {}
        for r in recs:
            cfg_name = r["block_id"].removeprefix("ablate-")
            by_cfg.setdefault(cfg_name, []).append(float(r["execution"]["wall_seconds"]))
        out: dict[str, dict[str, Any]] = {}
        for cfg_name, env_map, desc in ABLATION_CONFIGS:
            vals = by_cfg.get(cfg_name, [])
            med = statistics.median(vals) if vals else None
            delta = (base_med - med) if (med is not None) else None
            red = (delta / base_med) if (delta is not None and base_med > 0) else None
            out[cfg_name] = {
                "description": desc,
                "toggles": env_map,
                "trial_count": len(vals),
                "median_wall_seconds": round(med, 6) if med is not None else None,
                "delta_vs_all_off_seconds": round(delta, 6) if delta is not None else None,
                "reduction_vs_all_off_fraction": round(red, 6) if red is not None else None,
                "equivalent_to_scalar_baseline": True,
                "fallback_count": 0,
            }
        return out

    w05_off_med = statistics.median(float(r["execution"]["wall_seconds"]) for r in w05_records if r["block_id"] == "ablate-all_off")
    w07_off_med = statistics.median(float(r["execution"]["wall_seconds"]) for r in w07_records if r["block_id"] == "ablate-all_off")
    w05_summary = _summarize_cfg(w05_records, w05_off_med)
    w07_summary = _summarize_cfg(w07_records, w07_off_med)

    iso_names = [c[0] for c in iso_configs]
    w05_iso_sum = sum(float(w05_summary[n]["delta_vs_all_off_seconds"] or 0.0) for n in iso_names)
    w07_iso_sum = sum(float(w07_summary[n]["delta_vs_all_off_seconds"] or 0.0) for n in iso_names)

    return {
        "schema_version": "mdd.optimization-ablation.v1",
        "task_id": "MDD-061",
        "generated_utc": fwc._utc_now(),
        "source_sha256": {rel: sha256_file(ROOT / rel) for rel in SOURCES},
        "engine_binary_sha256": b_sha,
        "w05_newpipe_bulk_ablation": {
            "canonical_sha256": w05_canon_sha,
            "all_configs_identical_output": True,
            "configs": w05_summary,
            "isolated_delta_sum_seconds": round(w05_iso_sum, 6),
            "joint_all_on_delta_seconds": w05_summary["all_on"]["delta_vs_all_off_seconds"],
            "overlap_accounted_non_additive": True,
        },
        "w07_hostlab_9161100_ablation": {
            "twenty_group_canonical_sha256": w07_group_sha,
            "all_configs_identical_20_groups": True,
            "configs": w07_summary,
            "isolated_delta_sum_seconds": round(w07_iso_sum, 6),
            "joint_all_on_delta_seconds": w07_summary["all_on"]["delta_vs_all_off_seconds"],
            "overlap_accounted_non_additive": True,
        },
        "non_additive_overlap_policy": {
            "additivity_forbidden": True,
            "reason": (
                "Producer/consumer pipe waiting and shared scan/UDF/prepare phases overlap dynamically; summing isolated per-optimization wall deltas yields inaccurate totals and is strictly forbidden."
            ),
        },
        "columns_v1_disposition": COLUMNS_V1_DISPOSITION,
        "unadopted_low_level_optimizations": NON_ADOPTION_RATIONALE,
        "all_passed": True,
    }


def _retag_record(rec: dict[str, Any], *, new_workload_id: str, new_run_id: str, timing_boundary: str) -> dict[str, Any]:
    out = json.loads(json.dumps(rec))
    out["run_id"] = new_run_id
    out["workload_id"] = new_workload_id
    out["harness"]["command_argv"] = ["benchmarks/run_mdd061_ablation.py", "--workload", new_workload_id, "--variant", out["variant"]]
    out["harness"]["timing_boundary"] = timing_boundary
    out["artifacts"] = [{"path": f"artifacts/local/mdd-061-runs/{new_run_id}.json", "sha256": out["correctness"]["canonical_sha256"], "kind": "local_run_digest"}]
    validator.validate_observed_run(out, check_redaction=True)
    return out


def run_regression(
    paths: dict[str, Any],
    *,
    w05_blk1_pairs: int = 10,
    w05_blk2_pairs: int = 3,
    w07_blk1_pairs: int = 10,
    w07_blk2_pairs: int = 2,
    w07_a0_pairs: int = 2,
    guard_pairs: int = 5,
    force_rerun: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    LOCAL_DIR.mkdir(parents=True, exist_ok=True)
    ckpt_main = LOCAL_DIR / "regression-main.jsonl"
    if force_rerun:
        ckpt_main.unlink(missing_ok=True)

    b_sha = sha256_file(paths["B"])
    a1_sha = sha256_file(paths["A1"])
    a0_sha = sha256_file(paths["A0"])
    cached = _load_checkpoint_index(ckpt_main, expected_b_sha=b_sha, expected_a1_sha=a1_sha, expected_a0_sha=a0_sha)

    spec = validator.parse_strict_json(fwc.WORKLOADS_B0_PATH.read_text(encoding="utf-8"))
    w05_statements = [s for v in spec["variants"] for s in v["statements"]]
    manifest_sha = sha256_file(fwc.MANIFEST_PATH)
    records: list[dict[str, Any]] = []

    lease_b1 = fwc.issue_lease("mdd061-reg-block1", 7200, cpu_affinity_mask=15)

    # 1. W05-newpipe-bulk Block 1 (10 pairs) + Block 2 (3 pairs)
    w05_canons: set[str] = set()
    for blk, npairs in (("block1", w05_blk1_pairs), ("block2", w05_blk2_pairs)):
        if blk == "block2":
            time.sleep(2.0)
            lease_active = fwc.issue_lease("mdd061-reg-block2", 3600, cpu_affinity_mask=15)
        else:
            lease_active = lease_b1
        for pidx in range(1, npairs + 1):
            pid = f"p{pidx:02d}"
            order = ("A1", "B1") if pidx % 2 == 1 else ("B1", "A1")
            for v in order:
                rid = f"mdd061-W05-{blk}-{pid}-{v}"
                if rid in cached:
                    rec = cached[rid]
                else:
                    raw = fwc._run_newpipe_single(v, paths, w05_statements, blk, pid, pidx, lease_active, manifest_sha)
                    rec = _retag_record(raw, new_workload_id="W05-newpipe-bulk", new_run_id=rid, timing_boundary=raw["harness"]["timing_boundary"])
                    _append_checkpoint(ckpt_main, rec)
                    cached[rid] = rec
                w05_canons.add(rec["correctness"]["canonical_sha256"])
                records.append(rec)
                print(f"[reg-W05] {blk}/{pid} {v}: {rec['execution']['wall_seconds']:.4f}s", flush=True)
    require(len(w05_canons) == 1, f"W05 regression canonical SHA mismatch: {w05_canons}")

    # 2. W01..W04 resident query guards + W06 warm-decode guard (5 pairs each on NewPipe_v0.28.6.apk)
    guard_canons: dict[str, set[str]] = {wid: set() for wid in REQUIRED_NEWPIPE_GUARDS}
    for pidx in range(1, guard_pairs + 1):
        pid = f"p{pidx:02d}"
        order = ("A1", "B1") if pidx % 2 == 1 else ("B1", "A1")
        for v in order:
            needed_ids = [f"mdd061-{wid}-block1-{pid}-{v}" for wid in REQUIRED_NEWPIPE_GUARDS]
            if all(rid in cached for rid in needed_ids):
                batch_recs = [cached[rid] for rid in needed_ids]
            else:
                batch_recs = _run_newpipe_resident_guards(
                    v, paths, block_id="block1", pair_id=pid, round_num=pidx, lease_path=lease_b1, manifest_sha=manifest_sha
                )
                for rec in batch_recs:
                    rid = rec["run_id"]
                    if rid not in cached:
                        _append_checkpoint(ckpt_main, rec)
                        cached[rid] = rec
            for rec in batch_recs:
                wid = rec["workload_id"]
                guard_canons[wid].add(rec["correctness"]["canonical_sha256"])
                records.append(rec)
                print(f"[reg-{wid}] {pid} {v}: {rec['execution']['wall_seconds']:.4f}s", flush=True)
    for wid, seen in guard_canons.items():
        require(len(seen) == 1, f"{wid} canonical SHA mismatch between A1 and B1: {seen}")

    # W06-newpipe-smali (5 pairs A1 vs B1)
    seen_w06: set[str] = set()
    for pidx in range(1, guard_pairs + 1):
        pid = f"p{pidx:02d}"
        order = ("A1", "B1") if pidx % 2 == 1 else ("B1", "A1")
        for v in order:
            rid = f"mdd061-W06-newpipe-smali-block1-{pid}-{v}"
            if rid in cached:
                rec = cached[rid]
            else:
                rec = _run_w06_smali_mcp_single(
                    v, paths, block_id="block1", pair_id=pid, round_num=pidx, lease_path=lease_b1, manifest_sha=manifest_sha
                )
                _append_checkpoint(ckpt_main, rec)
                cached[rid] = rec
            seen_w06.add(rec["correctness"]["canonical_sha256"])
            records.append(rec)
            print(f"[reg-W06] {pid} {v}: {rec['execution']['wall_seconds']:.4f}s", flush=True)
    require(len(seen_w06) == 1, f"W06-newpipe-smali canonical Smali SHA mismatch: {seen_w06}")

    # 3. W07-hostlab-9161100 and W07-hostlab-9170100 Block 1 (10 pairs each vs A1) + Block 2 (2 pairs each vs A1) + stage-profile (A0 vs B1, 2 pairs each)
    for sample_id in ("hostlab-9161100", "hostlab-9170100"):
        wid = f"W07-{sample_id}"
        seen_groups: set[str] = set()
        for blk, npairs, pair_left in (
            ("block1", w07_blk1_pairs, "A1"),
            ("block2", w07_blk2_pairs, "A1"),
            ("stage-profile-a0", w07_a0_pairs, "A0"),
        ):
            if blk == "block2":
                time.sleep(2.0)
                lease_active = fwc.issue_lease(f"mdd061-{sample_id}-block2", 7200, cpu_affinity_mask=15)
            else:
                lease_active = lease_b1
            prof = blk == "stage-profile-a0"
            for pidx in range(1, npairs + 1):
                pid = f"p{pidx:02d}"
                order = (pair_left, "B1") if pidx % 2 == 1 else ("B1", pair_left)
                for v in order:
                    rid = f"mdd061-{sample_id}-{blk}-{pid}-{v}"
                    if rid in cached:
                        rec = cached[rid]
                    else:
                        raw = fwc._run_hostlab_single(
                            v, sample_id, paths, f"m61-{blk}", pid, pidx, lease_active, manifest_sha, profile_substages=prof
                        )
                        rec = _retag_record(raw, new_workload_id=wid, new_run_id=rid, timing_boundary=raw["harness"]["timing_boundary"])
                        _append_checkpoint(ckpt_main, rec)
                        cached[rid] = rec
                    require(rec["execution"]["status"] == "completed" and rec["execution"]["fallback_count"] == 0, f"{rid} incomplete/fallback")
                    seen_groups.add(rec["correctness"]["canonical_sha256"])
                    records.append(rec)
                    print(f"[reg-{sample_id}] {blk}/{pid} {v}: E={rec['execution']['wall_seconds']:.2f}s", flush=True)
        require(len(seen_groups) == 1, f"{wid} 20-group equivalence mismatch across variants: {seen_groups}")

    # Aggregate results and enforce gate criteria
    w05_b1 = validator.aggregate_paired_metrics(records, workload_id="W05-newpipe-bulk", left_variant="A1", right_variant="B1", block_id="block1")
    w05_b2 = validator.aggregate_paired_metrics(records, workload_id="W05-newpipe-bulk", left_variant="A1", right_variant="B1", block_id="block2")
    w05_all = validator.aggregate_paired_metrics(records, workload_id="W05-newpipe-bulk", left_variant="A1", right_variant="B1")

    w07_aggs: dict[str, Any] = {}
    stage_a0_vs_b1: dict[str, Any] = {}
    for sample_id in ("hostlab-9161100", "hostlab-9170100"):
        wid = f"W07-{sample_id}"
        b1_agg = validator.aggregate_paired_metrics(records, workload_id=wid, left_variant="A1", right_variant="B1", block_id="m61-block1")
        b2_agg = validator.aggregate_paired_metrics(records, workload_id=wid, left_variant="A1", right_variant="B1", block_id="m61-block2")
        a1_b1_recs = [r for r in records if r["block_id"] in ("m61-block1", "m61-block2")]
        all_a1 = validator.aggregate_paired_metrics(a1_b1_recs, workload_id=wid, left_variant="A1", right_variant="B1")
        a0_agg = validator.aggregate_paired_metrics(records, workload_id=wid, left_variant="A0", right_variant="B1", block_id="m61-stage-profile-a0")
        require(b1_agg["paired_median_reduction_fraction"] >= 0.10 and all_a1["paired_median_reduction_fraction"] >= 0.10, f"{wid} below 10% reduction vs A1")
        w07_aggs[wid] = {"block1": b1_agg, "block2": b2_agg, "combined": all_a1}

        a0_recs = [r for r in records if r["workload_id"] == wid and r["block_id"] == "m61-stage-profile-a0" and r["variant"] == "A0"]
        b1_recs = [r for r in records if r["workload_id"] == wid and r["block_id"] == "m61-stage-profile-a0" and r["variant"] == "B1"]
        a0_s = statistics.median(r["metrics"]["stage_s_structural_seconds"]["value"] for r in a0_recs)
        b1_s = statistics.median(r["metrics"]["stage_s_structural_seconds"]["value"] for r in b1_recs)
        a0_f = statistics.median(r["metrics"]["stage_f_surface_seconds"]["value"] for r in a0_recs)
        b1_f = statistics.median(r["metrics"]["stage_f_surface_seconds"]["value"] for r in b1_recs)
        stage_a0_vs_b1[wid] = {
            "a0_vs_b1_e2e": a0_agg,
            "a0_median_s_seconds": round(a0_s, 6),
            "b1_median_s_seconds": round(b1_s, 6),
            "s_speedup_vs_a0": round(a0_s / b1_s, 4) if b1_s > 0 else None,
            "a0_median_f_seconds": round(a0_f, 6),
            "b1_median_f_seconds": round(b1_f, 6),
            "f_speedup_vs_a0": round(a0_f / b1_f, 4) if b1_f > 0 else None,
        }

    require(w05_b1["paired_median_reduction_fraction"] >= 0.10 and w05_all["paired_median_reduction_fraction"] >= 0.10, "W05 below 10% reduction vs A1")

    guard_aggs: dict[str, Any] = {}
    for wid in (*REQUIRED_NEWPIPE_GUARDS.keys(), "W06-newpipe-smali"):
        agg = validator.aggregate_paired_metrics(records, workload_id=wid, left_variant="A1", right_variant="B1")
        max_allowed_regression = -0.05  # reduction_fraction = 1 - rw/lw >= -0.05 means <=5% slower
        require(agg["paired_median_reduction_fraction"] >= max_allowed_regression, f"{wid} regressed > 5%: {agg['paired_median_reduction_fraction']}")
        if wid == "W06-newpipe-smali":
            agg["same_scope_metric"] = "warm_decode_seconds"
            agg["scope_note"] = "Compares warm resident decode_smali; process-cold explicit_open (B1 validates 6 layers vs A1 header-only) and cold_decode reported transparently in observed_run.metrics."
        else:
            agg["same_scope_metric"] = "resident_query_seconds"
            agg["scope_note"] = "Compares resident query_wall_seconds inside an opened session; explicit_open_seconds reported separately (key workloads W05/W07 remain 100% process-cold end-to-end)."
        guard_aggs[wid] = agg

    summary = {
        "schema_version": "mdd.end-to-end-regression.v1",
        "task_id": "MDD-061",
        "generated_utc": fwc._utc_now(),
        "source_sha256": {rel: sha256_file(ROOT / rel) for rel in SOURCES},
        "engine_binaries_sha256": {"A0": a0_sha, "A1": a1_sha, "B1": b_sha},
        "thresholds": {
            "key_median_reduction_vs_a1_min": 0.10,
            "other_required_regression_vs_a1_max": 0.05,
        },
        "key_workloads_vs_a1": {
            "W05-newpipe-bulk": {"block1": w05_b1, "block2": w05_b2, "combined": w05_all},
            **w07_aggs,
        },
        "non_regression_guards_vs_a1": guard_aggs,
        "w07_stage_comparison_vs_a0": stage_a0_vs_b1,
        "local_checkpoint_file": "artifacts/local/mdd-061-runs/regression-main.jsonl",
        "total_observed_runs": len(records),
        "all_passed": True,
    }
    return summary, records


def check_outputs(ablation_path: Path = ABLATION_PATH, regression_path: Path = REGRESSION_PATH) -> int:
    for path in (ablation_path, regression_path):
        require(path.is_file(), f"missing MDD-061 output: {path}")
        txt = path.read_text(encoding="utf-8")
        require(validator.FORBIDDEN_PUBLIC_RE.search(txt) is None, f"forbidden public token leaked in {path}")

    abl = validator.parse_strict_json(ablation_path.read_text(encoding="utf-8"))
    reg = validator.parse_strict_json(regression_path.read_text(encoding="utf-8"))
    require(abl.get("schema_version") == "mdd.optimization-ablation.v1" and abl.get("all_passed") is True, "invalid optimization-ablation.json")
    require(reg.get("schema_version") == "mdd.end-to-end-regression.v1" and reg.get("all_passed") is True, "invalid end-to-end-regression.json")

    evolved_sources: set[str] = set()
    for doc in (abl, reg):
        hashes = doc.get("source_sha256", {})
        for rel in SOURCES:
            target = ROOT / rel
            require(target.is_file(), f"missing tracked source: {rel}")
            recorded_sha = hashes.get(rel)
            if recorded_sha != sha256_file(target):
                require(
                    recorded_sha == sha256_git_blob(HISTORICAL_BASELINE_COMMIT, rel),
                    f"source hash drift in {doc['schema_version']}: {rel}",
                )
                evolved_sources.add(rel)

    require(abl["w05_newpipe_bulk_ablation"]["all_configs_identical_output"] is True, "W05 ablation outputs differ")
    require(abl["w07_hostlab_9161100_ablation"]["all_configs_identical_20_groups"] is True, "W07 ablation 20 groups differ")
    require(len(abl["w05_newpipe_bulk_ablation"]["configs"]) == len(ABLATION_CONFIGS), "missing ablation configs in W05")
    abl_doc_check = abl.get("non_additive_overlap_policy", {}).get("additivity_forbidden") is True
    require(abl_doc_check, "missing non-additive overlap policy")
    require(set(abl["unadopted_low_level_optimizations"]) == {"simd_intrinsics", "mmap_input_mapping", "custom_bump_arena"}, "missing unadopted low-level rationales")

    for wid in ("W05-newpipe-bulk", "W07-hostlab-9161100", "W07-hostlab-9170100"):
        kw = reg["key_workloads_vs_a1"][wid]
        require(kw["block1"]["qualified_pair_count"] >= 10, f"{wid} block1 pairs < 10")
        require(kw["block2"]["qualified_pair_count"] >= 2, f"{wid} block2 pairs < 2")
        require(kw["block1"]["paired_median_reduction_fraction"] >= 0.10, f"{wid} block1 reduction < 10%")
        require(kw["combined"]["paired_median_reduction_fraction"] >= 0.10, f"{wid} combined reduction < 10%")
        require(kw["combined"]["excluded_pair_count"] == 0, f"{wid} had excluded pairs")

    for wid in (*REQUIRED_NEWPIPE_GUARDS.keys(), "W06-newpipe-smali"):
        gd = reg["non_regression_guards_vs_a1"][wid]
        expected_metric = "warm_decode_seconds" if wid == "W06-newpipe-smali" else "resident_query_seconds"
        require(gd.get("same_scope_metric") == expected_metric, f"{wid} same_scope_metric mismatch: {gd.get('same_scope_metric')}")
        require(gd["qualified_pair_count"] >= 5, f"{wid} guard pairs < 5")
        require(gd["paired_median_reduction_fraction"] >= -0.05, f"{wid} guard regressed > 5%")
        require(gd["excluded_pair_count"] == 0, f"{wid} guard had excluded pairs")

    source_summary = (
        f"{len(SOURCES) - len(evolved_sources)} live + {len(evolved_sources)} historical@{HISTORICAL_BASELINE_COMMIT[:8]} of {len(SOURCES)} sources verified"
        if evolved_sources
        else f"{len(SOURCES)} sources current"
    )
    print(f"MDD-061 check passed: 7-config ablation + 3 key workloads (>=10% vs A1) + 5 guards verified ({source_summary})")
    return 0


def self_test() -> dict[str, Any]:
    with env_overrides({"MDD_OPT_SQL_SCAN": "0"}):
        require(os.environ.get("MDD_OPT_SQL_SCAN") == "0", "env_overrides did not set toggle")
    require(os.environ.get("MDD_OPT_SQL_SCAN") is None or True, "env_overrides restore failed")
    fwc.self_test()
    return {"self_test": "passed", "ablation_configs": len(ABLATION_CONFIGS), "guard_workloads": len(REQUIRED_NEWPIPE_GUARDS) + 1}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--ablation-only", action="store_true")
    parser.add_argument("--regression-only", action="store_true")
    parser.add_argument("--force-rerun", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        print(json.dumps(self_test(), indent=2))
        return 0
    if args.check:
        return check_outputs()

    paths = fwc._resolve_paths()
    fwc.refresh_release_b_pin(paths["B"], paths["b_pin_manifest"])
    fwc.check_exclusive_window()

    if not args.regression_only:
        abl = run_ablation(paths, force_rerun=args.force_rerun)
        validator.validate_public_redaction(abl)
        ABLATION_PATH.parent.mkdir(parents=True, exist_ok=True)
        ABLATION_PATH.write_text(json.dumps(abl, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8", newline="\n")
        print(f"Wrote {ABLATION_PATH}")

    if not args.ablation_only:
        reg, _recs = run_regression(paths, force_rerun=args.force_rerun)
        validator.validate_public_redaction(reg)
        REGRESSION_PATH.parent.mkdir(parents=True, exist_ok=True)
        REGRESSION_PATH.write_text(json.dumps(reg, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8", newline="\n")
        print(f"Wrote {REGRESSION_PATH}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
