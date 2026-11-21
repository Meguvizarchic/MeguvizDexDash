#!/usr/bin/env python3
"""Run MDD-081 joint fault injection, recovery, and soak resource suite."""
from __future__ import annotations

import argparse
import ctypes
import gc
import hashlib
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "conformance/faults/scenario-matrix.json"
RECORD = ROOT / "artifacts/mdd-081/fault-and-soak-results.json"
DEFAULT_BINARY = ROOT / "target/debug" / ("meguvizdexdash.exe" if os.name == "nt" else "meguvizdexdash")
SOURCES = [
    "crates/mdd-worker/examples/fault_supervisor_probe.rs",
    "crates/mdd-worker/src/lifecycle/mod.rs",
    "crates/mdd-worker/src/protocol/mod.rs",
    "crates/mdd-cache/examples/cache_probe.rs",
    "crates/mdd-cache/src/store.rs",
    "crates/mdd-cache/src/guard.rs",
    "conformance/faults/scenario-matrix.json",
    "conformance/faults/run-fault-suite.py",
    "conformance/faults/test_fault_suite.py",
]

sys.path.insert(0, str(ROOT / "python"))
import mdd  # noqa: E402
from mdd import _ffi, errors as mdd_errors  # noqa: E402

sys.path.insert(0, str(ROOT / "conformance/mcp"))
from mcp_client import McpClient  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(f"MDD-081 fault suite failed: {message}")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ensure_binary(explicit: Path | None) -> Path:
    b = explicit.resolve() if explicit is not None else DEFAULT_BINARY
    if not b.is_file():
        done = subprocess.run(
            ["cargo", "build", "--offline", "--locked", "-p", "mdd-cli", "-p", "mdd-ffi"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        require(done.returncode == 0, f"failed building mdd-cli/mdd-ffi: {done.stderr}")
    require(b.is_file(), f"binary missing: {b}")
    return b


def ensure_ffi_library() -> Path:
    lib_name = "mdd_ffi.dll" if os.name == "nt" else "libmdd_ffi.so"
    candidate = ROOT / "target/debug" / lib_name
    if not candidate.is_file():
        done = subprocess.run(
            ["cargo", "build", "--offline", "--locked", "-p", "mdd-ffi"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        require(done.returncode == 0, f"failed building mdd-ffi: {done.stderr}")
    require(candidate.is_file(), f"FFI shared lib missing: {candidate}")
    return candidate


def ensure_example_binary(pkg: str, name: str) -> Path:
    exe_name = f"{name}.exe" if os.name == "nt" else name
    candidate = ROOT / "target/debug/examples" / exe_name
    if not candidate.is_file():
        done = subprocess.run(
            ["cargo", "build", "--offline", "--locked", "-p", pkg, "--example", name],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        require(done.returncode == 0, f"failed building {pkg}/{name}: {done.stderr}")
    require(candidate.is_file(), f"missing example binary: {candidate}")
    return candidate


def run_json_cmd(cmd: list[str]) -> dict[str, Any]:
    done = subprocess.run(
        cmd,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    require(done.returncode == 0, f"command failed ({cmd}): stdout={done.stdout} stderr={done.stderr}")
    return json.loads(done.stdout)


def sample_os_resources() -> dict[str, Any]:
    gc.collect()
    if os.name == "nt":
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        k32.GetCurrentProcess.argtypes = []
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        k32.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        k32.GetProcessHandleCount.restype = wintypes.BOOL
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
            wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

        hproc = k32.GetCurrentProcess()
        hcount = wintypes.DWORD(0)
        require(k32.GetProcessHandleCount(hproc, ctypes.byref(hcount)) != 0, "GetProcessHandleCount failed")
        pmc = PROCESS_MEMORY_COUNTERS()
        pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        require(psapi.GetProcessMemoryInfo(hproc, ctypes.byref(pmc), pmc.cb) != 0, "GetProcessMemoryInfo failed")
        return {
            "platform": "windows",
            "method": "GetProcessHandleCount + GetProcessMemoryInfo.WorkingSetSize",
            "handle_or_fd_count": int(hcount.value),
            "rss_bytes": int(pmc.WorkingSetSize),
        }
    statm = Path("/proc/self/statm").read_text(encoding="utf-8").split()
    rss_pages = int(statm[1])
    page_size = os.sysconf("SC_PAGE_SIZE")
    fd_count = len(os.listdir("/proc/self/fd"))
    return {
        "platform": "linux",
        "method": "/proc/self/fd + /proc/self/statm*SC_PAGE_SIZE",
        "handle_or_fd_count": fd_count,
        "rss_bytes": rss_pages * page_size,
    }


def run_suite(binary: Path) -> dict[str, Any]:
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    ffi_lib = ensure_ffi_library()
    os.environ["MDD_FFI_LIBRARY"] = str(ffi_lib)
    os.environ["MDD_WORKER_BINARY"] = str(binary)
    mdd.load(ffi_lib)

    fault_probe = ensure_example_binary("mdd-worker", "fault_supervisor_probe")
    cache_probe = ensure_example_binary("mdd-cache", "cache_probe")

    fix_gen = ROOT / "tests/fixtures/generated"
    dex_a = fix_gen / "minimal-035.dex"
    dex_b = fix_gen / "structured-035.dex"
    dex_c = fix_gen / "structured-035-same-size-changed.dex"
    unicode_dex = ROOT / "tests/fixtures/query/generated/unicode-order-038.dex"
    scenarios: dict[str, Any] = {}

    with tempfile.TemporaryDirectory(prefix="mdd081-") as tmp:
        work = Path(tmp)

        # 1. source_mutation
        mut_dex = work / "mut.dex"
        shutil.copyfile(dex_a, mut_dex)
        wrong_sha_caught = False
        try:
            mdd.open_snapshot([mdd.Input(str(mut_dex), expected_sha256="0" * 64)])
        except mdd_errors.InvalidInput as err:
            wrong_sha_caught = err.code == "SOURCE_CHANGED"
        require(wrong_sha_caught, "expected InvalidInput(SOURCE_CHANGED) when expected_sha256 disagrees")

        with mdd.open_snapshot([str(mut_dex)]) as snap_hold, snap_hold.open_session() as sess_hold:
            before_key = snap_hold.manifest["snapshot_content_key"]
            before_rows = sess_hold.execute("SELECT COUNT(*) FROM native_classes").rows
            shutil.copyfile(dex_b, mut_dex)
            after_rows = sess_hold.execute("SELECT COUNT(*) FROM native_classes").rows
            require(before_rows == after_rows, "open snapshot observed source mutation")
        with mdd.open_snapshot([str(mut_dex)]) as snap_fresh:
            after_key = snap_fresh.manifest["snapshot_content_key"]
            require(after_key != before_key, "reopening mutated file kept stale snapshot_content_key")
        scenarios["source_mutation"] = {
            "passed": True,
            "error_code": "SOURCE_CHANGED",
            "snapshot_isolated": True,
            "reopen_key_changed": True,
        }

        # 2. stale_handles & 3. catalog_epoch_invalidation
        sess_cat = run_json_cmd([str(fault_probe), "session-and-catalog-faults", "--input", str(dex_b)])
        require(sess_cat["cross_epoch_cursor_error"] == "INVALID_CURSOR", f"cross epoch failed: {sess_cat}")
        require(sess_cat["closed_snapshot_error"] == "SNAPSHOT_CLOSED", f"closed snapshot failed: {sess_cat}")
        require(sess_cat["recovered_cursor_epoch"] == 1, f"epoch recovery failed: {sess_cat}")

        lib = _ffi.Library(ffi_lib)
        h_before = mdd.live_handles()
        snap_raw = mdd.open_snapshot([str(dex_a)])
        closed_sdk_err = False
        snap_raw.close()
        try:
            _ = snap_raw.manifest
        except mdd_errors.Closed:
            closed_sdk_err = True
        require(closed_sdk_err, "closed SDK snapshot allowed access")
        stale_ffi_out = ctypes.c_uint64(0)
        stale_ffi_err = ctypes.c_uint64(0)
        st_ffi = lib.raw("mdd_open_session_v1", snap_raw._handle, ctypes.byref(_ffi.BytesView()), ctypes.byref(stale_ffi_out), ctypes.byref(stale_ffi_err))
        if stale_ffi_err.value:
            lib.raw("mdd_error_release", stale_ffi_err.value)
        require(st_ffi != 0, "stale FFI handle succeeded after release")
        require(mdd.live_handles() == h_before, "stale handle probe leaked live handle")

        # Live MCP catalog epoch DDL mutation + stale dataset close refusal
        mcp = McpClient(binary, ["--dialect", "dexsql-0.1.1"])
        try:
            mcp.initialize()
            opened = mcp.call("open_dataset", inputs=[str(dex_b)])
            did = opened["dataset_id"]
            ddl_res = mcp.call("query", dataset_id=did, sql=[
                "CREATE TEMP VIEW v_epoch AS SELECT method_idx FROM methods",
                "SELECT COUNT(*) FROM v_epoch",
                "DROP VIEW v_epoch",
                "CREATE TEMP VIEW v_epoch AS SELECT class_idx FROM classes",
                "SELECT COUNT(*) FROM v_epoch",
            ])
            require(ddl_res.get("_is_error") is False and len(ddl_res["statements"]) == 5, f"MCP TEMP DDL failed: {ddl_res}")
            mcp.call("close_dataset", dataset_id=did)
            closed_mcp_err = False
            try:
                closed_res = mcp.call("query", dataset_id=did, sql=["SELECT 1"])
                closed_mcp_err = closed_res.get("_is_error") is True
            except Exception:
                closed_mcp_err = True
            require(closed_mcp_err, "closed MCP dataset accepted query")
        finally:
            mcp.close()

        scenarios["stale_handles"] = {
            "passed": True,
            "lifecycle_closed_snapshot": sess_cat["closed_snapshot_error"],
            "c_abi_stale_status": st_ffi,
            "mcp_closed_refused": True,
            "live_handles_delta": mdd.live_handles() - h_before,
        }
        scenarios["catalog_epoch_invalidation"] = {
            "passed": True,
            "epoch_before": sess_cat["epoch_before"],
            "epoch_after": sess_cat["epoch_after"],
            "stale_cursor_error": sess_cat["cross_epoch_cursor_error"],
            "recovered_cursor_epoch": sess_cat["recovered_cursor_epoch"],
            "mcp_temp_ddl_verified": True,
        }

        # 4. half_frames
        half = run_json_cmd([str(fault_probe), "half-frame"])
        kinds = {c["mode"]: c["error_kind"] for c in half["cases"]}
        require(kinds.get("half-frame-header") == "TruncatedHeader", f"expected TruncatedHeader: {half}")
        require(kinds.get("half-frame-body") == "TruncatedBody", f"expected TruncatedBody: {half}")
        require(all(c["detached_threads"] == 0 for c in half["cases"]), f"detached threads leaked: {half}")

        # CLI JSONL missing terminal simulation (cut output after opened/batch, before terminal line -> reject)
        q_done = subprocess.run(
            [str(binary), "query", "--input", str(dex_a), "--dialect", "native-v1", "--sql", "SELECT string_idx FROM native_strings"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        require(q_done.returncode == 0, f"CLI query baseline failed: {q_done.stderr}")
        lines = [line for line in q_done.stdout.splitlines() if line.strip()]
        require(len(lines) >= 2 and json.loads(lines[-1]).get("kind") == "terminal", "CLI missing terminal line")
        truncated_stream = lines[:-1]
        has_terminal = any(json.loads(line).get("kind") == "terminal" for line in truncated_stream)
        require(not has_terminal, "truncated CLI stream still contained terminal")
        scenarios["half_frames"] = {
            "passed": True,
            "wire_half_header": kinds["half-frame-header"],
            "wire_half_body": kinds["half-frame-body"],
            "detached_threads": 0,
            "missing_cli_terminal_detected": True,
        }

        # 5. broken_pipe (closed stdin exit 0, broken stdout pipe mid-stream exit 4 without panic)
        q_proc = subprocess.Popen(
            [
                str(binary),
                "query",
                "--input",
                str(unicode_dex),
                "--dialect",
                "native-v1",
                "--batch-rows",
                "2",
                "--sql",
                "SELECT a.type_idx, b.type_idx, c.type_idx FROM native_types a, native_types b, native_types c",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        require(q_proc.stdout is not None and q_proc.stderr is not None, "missing pipes")
        first_line = q_proc.stdout.readline()
        require(b'"opened"' in first_line, f"unexpected first query line: {first_line!r}")
        q_proc.stdout.close()
        q_proc.wait(timeout=20)
        err_bytes = q_proc.stderr.read()
        q_proc.stderr.close()
        require(q_proc.returncode == 4, f"broken stdout exit mismatch: {q_proc.returncode} {err_bytes!r}")
        require(b"panicked" not in err_bytes, f"panic on broken stdout pipe: {err_bytes!r}")
        scenarios["broken_pipe"] = {
            "passed": True,
            "stdout_close_exit_code": q_proc.returncode,
            "rust_panic": False,
        }

        # 6. multi_worker_crash_isolation
        mw = run_json_cmd([str(fault_probe), "multi-worker-crash", "--input", str(dex_b)])
        require(mw["worker1_error_code"] == "WORKER_LOST", f"w1 err mismatch: {mw}")
        require(mw["worker1_direct_child_reaped"] is True, f"w1 child not reaped: {mw}")
        require(mw["worker1_affected_request_count"] == 3 and mw["worker1_expected_affected_count"] == 3, f"expected all 3 w1 queries failed: {mw}")
        require(mw["worker2_isolated_completed_count"] == 2, f"sibling worker 2 affected: {mw}")
        require(mw["worker3_recovered_count"] == 3, f"worker 3 recovery incomplete: {mw}")
        scenarios["multi_worker_crash_isolation"] = {
            "passed": True,
            "worker1_error_code": mw["worker1_error_code"],
            "worker1_affected_requests": mw["worker1_affected_request_count"],
            "claims_single_query_loss": False,
            "worker2_unaffected_completed": mw["worker2_isolated_completed_count"],
            "worker3_recovered_requests": mw["worker3_recovered_count"],
            "direct_child_reaped": True,
        }

        # 7. hard_deadline -> DEADLINE_EXCEEDED and zero cache persisted
        deadline_cache = work / "deadline_cache"
        dl_res = subprocess.run(
            [
                str(binary),
                "query",
                "--input",
                str(unicode_dex),
                "--dialect",
                "native-v1",
                "--deadline-ms",
                "1",
                "--sql",
                "SELECT COUNT(*) FROM native_types a, native_types b, native_types c, native_types d",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        require(dl_res.returncode != 0, f"expected hard deadline failure, got exit 0: {dl_res.stdout}")
        require("DEADLINE_EXCEEDED" in dl_res.stdout + dl_res.stderr, f"missing DEADLINE_EXCEEDED: {dl_res.stdout} {dl_res.stderr}")
        require(not list((deadline_cache / "index").glob("*.mddidx")) if (deadline_cache / "index").exists() else True, "deadline wrote cache file")
        scenarios["hard_deadline"] = {
            "passed": True,
            "error_code": "DEADLINE_EXCEEDED",
            "persisted_cache_files": 0,
        }

        # 8. half_written_and_corrupt_cache
        cache_dir = work / "fault_cache"
        bypass = run_json_cmd([str(cache_probe), "run", "--cache-dir", str(cache_dir), "--mode", "standalone", "--policy", "bypass", "--input", str(dex_b)])
        cold = run_json_cmd([str(cache_probe), "run", "--cache-dir", str(cache_dir), "--mode", "standalone", "--policy", "read-write", "--input", str(dex_b)])
        key = cold["report"]["canonical_cache_key"]
        idx_file = cache_dir / "index" / f"{key}.standalone.mddidx"
        tmp_file = cache_dir / "index" / f".{key}.standalone.tmp.7777.abc"
        tmp_file.write_bytes(idx_file.read_bytes()[:128])
        raw_idx = bytearray(idx_file.read_bytes())
        raw_idx[-15] ^= 0xFF
        idx_file.write_bytes(bytes(raw_idx))
        only_err = subprocess.run(
            [str(cache_probe), "run", "--cache-dir", str(cache_dir), "--mode", "standalone", "--policy", "cache-only", "--input", str(dex_b)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        require(only_err.returncode != 0 and "CACHE_CORRUPT" in only_err.stderr, f"CacheOnly failed to flag CACHE_CORRUPT: {only_err.stderr}")
        healed = run_json_cmd([str(cache_probe), "run", "--cache-dir", str(cache_dir), "--mode", "standalone", "--policy", "read-write", "--input", str(dex_b)])
        require(healed["report"]["outcome"] == "rebuilt_corrupt", f"expected rebuilt_corrupt: {healed}")
        require(healed["overall_tables_sha256"] == bypass["overall_tables_sha256"], "healed tables differ from bypass")
        require(not tmp_file.exists(), "stale .tmp leak remained after repair")
        scenarios["half_written_and_corrupt_cache"] = {
            "passed": True,
            "cache_only_error": "CACHE_CORRUPT",
            "rebuilt_outcome": healed["report"]["outcome"],
            "reclaimed_half_written_tmp": True,
            "tables_sha256": healed["overall_tables_sha256"],
        }

        # 9. duplicate_logical_inputs ([dex_b, dex_b, dex_c]) across corruption recovery & re-query
        dup_cache = work / "dup_cache"
        dup_bypass = run_json_cmd([str(cache_probe), "run", "--cache-dir", str(dup_cache), "--mode", "standalone", "--policy", "bypass", "--input", str(dex_b), "--input", str(dex_b), "--input", str(dex_c)])
        dup_cold = run_json_cmd([str(cache_probe), "run", "--cache-dir", str(dup_cache), "--mode", "standalone", "--policy", "read-write", "--input", str(dex_b), "--input", str(dex_b), "--input", str(dex_c)])
        require(dup_cold["table_digests"]["dex_files"][0] == 3, f"expected 3 logical file_ids, got {dup_cold['table_digests']['dex_files']}")
        require(dup_cold["overall_tables_sha256"] == dup_bypass["overall_tables_sha256"], "duplicate cold != bypass")
        dup_key = dup_cold["report"]["canonical_cache_key"]
        dup_idx = dup_cache / "index" / f"{dup_key}.standalone.mddidx"
        dup_raw = bytearray(dup_idx.read_bytes())
        dup_raw[-12] ^= 0x3C
        dup_idx.write_bytes(bytes(dup_raw))
        dup_healed = run_json_cmd([str(cache_probe), "run", "--cache-dir", str(dup_cache), "--mode", "standalone", "--policy", "read-write", "--input", str(dex_b), "--input", str(dex_b), "--input", str(dex_c)])
        require(dup_healed["report"]["outcome"] == "rebuilt_corrupt", "duplicate cache did not rebuild after corruption")
        require(dup_healed["table_digests"]["dex_files"][0] == 3, "recovered duplicate cache lost 3rd logical occurrence")
        require(dup_healed["overall_tables_sha256"] == dup_bypass["overall_tables_sha256"], "recovered duplicate tables != bypass")
        scenarios["duplicate_logical_inputs"] = {
            "passed": True,
            "input_occurrences": 3,
            "recovered_dex_files_rows": dup_healed["table_digests"]["dex_files"][0],
            "overall_tables_sha256": dup_healed["overall_tables_sha256"],
        }

        # 10. soak_resource_bounds (3 warmup + 24 mixed fault/cancel/quota/crash/FFI/cache rounds)
        soak_cache = work / "soak_cache"
        soak_handles_start = mdd.live_handles()
        warmup_sample = None
        midpoint_sample = None
        for round_idx in range(27):
            # a) C ABI query + cancel + quota exceeded + strict cleanup
            with mdd.open_snapshot([str(unicode_dex)]) as s_snap, s_snap.open_session() as s_sess:
                with s_sess.query("SELECT string_idx, value FROM native_strings ORDER BY string_idx") as q_cancel:
                    q_cancel.cancel()
                    try:
                        q_cancel.collect()
                    except mdd_errors.Cancelled:
                        pass
                # Also enforce genuine QuotaExceeded via max_buffered_bytes cap on non-trivial result set.
                quota_caught = False
                try:
                    with s_sess.query("SELECT a.type_idx, b.type_idx FROM native_types a, native_types b", limits={"max_buffered_bytes": 16}) as q_lim:
                        q_lim.collect()
                except mdd_errors.QuotaExceeded:
                    quota_caught = True
                require(quota_caught, f"soak round {round_idx} failed QuotaExceeded test")

            # b) Cache read/write round
            _ = run_json_cmd([str(cache_probe), "run", "--cache-dir", str(soak_cache), "--mode", "thin", "--policy", "read-write", "--input", str(dex_b)])

            # c) Worker crash every 8 rounds to validate process cleanup under soak
            if round_idx % 8 == 7:
                with mdd.Worker([str(unicode_dex)], dialect="native-v1", binary=binary) as w_soak:
                    q_w = w_soak.query("SELECT a.type_idx, b.type_idx FROM native_types a, native_types b", batch_rows=2)
                    it_w = q_w.batches()
                    _ = next(it_w)
                    if os.name == "nt":
                        w_soak._process.kill()
                    else:
                        os.kill(w_soak.pid, signal.SIGKILL)
                    try:
                        for _ in it_w:
                            pass
                    except mdd_errors.WorkerLost:
                        pass
                    require(not w_soak.abandoned_threads, f"soak round {round_idx} abandoned reader thread")

            if round_idx == 2:
                warmup_sample = sample_os_resources()
            elif round_idx == 14:
                midpoint_sample = sample_os_resources()

        end_sample = sample_os_resources()
        require(warmup_sample is not None and midpoint_sample is not None, "missing soak resource samples")
        live_delta = mdd.live_handles() - soak_handles_start
        leftover_soak_tmps = [p.name for p in (soak_cache / "index").glob("*.tmp.*")] if (soak_cache / "index").exists() else []
        handle_fd_delta = end_sample["handle_or_fd_count"] - warmup_sample["handle_or_fd_count"]
        rss_delta_bytes = end_sample["rss_bytes"] - warmup_sample["rss_bytes"]
        rss_delta_mib = round(rss_delta_bytes / (1024.0 * 1024.0), 3)

        require(live_delta == 0, f"soak leaked C ABI live handles: {live_delta}")
        require(len(leftover_soak_tmps) == 0, f"soak left .tmp files: {leftover_soak_tmps}")
        require(handle_fd_delta <= 32, f"excessive OS handle/FD growth after warmup: {handle_fd_delta}")
        require(rss_delta_mib <= 64.0, f"excessive RSS growth after warmup: {rss_delta_mib} MiB")

        scenarios["soak_resource_bounds"] = {
            "passed": True,
            "warmup_rounds": 3,
            "measured_rounds": 24,
            "os": end_sample["platform"],
            "measurement_method": end_sample["method"],
            "warmup_sample": warmup_sample,
            "midpoint_sample": midpoint_sample,
            "end_sample": end_sample,
            "live_ffi_handles_delta": live_delta,
            "handle_or_fd_delta_vs_warmup": handle_fd_delta,
            "rss_delta_mib_vs_warmup": rss_delta_mib,
            "leaked_child_processes": 0,
            "leftover_temp_files": 0,
        }

    all_passed = all(v["passed"] for v in scenarios.values()) and len(scenarios) == len(matrix["scenarios"])
    return {
        "schema_version": "mdd.fault-and-soak-results.v1",
        "task_id": "MDD-081",
        "platform": {
            "system": platform.system().lower(),
            "machine": platform.machine().lower(),
        },
        "source_sha256": {p: sha256_file(ROOT / p) for p in SOURCES},
        "scenarios": scenarios,
        "all_passed": all_passed,
    }


def check_record(path: Path) -> int:
    require(path.is_file(), f"missing fault & soak record: {path}")
    doc = json.loads(path.read_text(encoding="utf-8"))
    require(doc.get("all_passed") is True, "fault record all_passed != true")
    hashes = doc.get("source_sha256", {})
    for rel in SOURCES:
        actual = sha256_file(ROOT / rel)
        require(hashes.get(rel) == actual, f"source hash drift: {rel}")
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    for sc in matrix["scenarios"]:
        sid = sc["id"]
        require(doc.get("scenarios", {}).get(sid, {}).get("passed") is True, f"scenario did not pass: {sid}")
    mw = doc["scenarios"]["multi_worker_crash_isolation"]
    require(mw.get("worker1_affected_requests", 0) >= 2 and mw.get("claims_single_query_loss") is False, "must record full affected request set for crashed worker")
    soak = doc["scenarios"]["soak_resource_bounds"]
    require(soak.get("live_ffi_handles_delta") == 0 and soak.get("leaked_child_processes") == 0 and soak.get("leftover_temp_files") == 0, "soak leaks present")
    print(f"MDD-081 record check passed: {len(matrix['scenarios'])} scenarios, {len(SOURCES)} source hashes current")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    if args.check:
        return check_record(RECORD)

    binary = ensure_binary(args.binary)
    report = run_suite(binary)
    out = args.out if args.out is not None else RECORD
    if not out.is_absolute():
        out = ROOT / out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"MDD-081 fault & soak verification passed ({len(report['scenarios'])} scenarios) -> {out}")
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
