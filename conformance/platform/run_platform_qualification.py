#!/usr/bin/env python3
"""Native Linux/Windows x86_64 platform, C ABI, CLI/MCP/SDK & lifecycle qualification (MDD-080).

Must run natively on the target OS (no cross-compile stand-ins).
Never uses bare `assert` for conformance verification.

Usage:
    python -I conformance/platform/run_platform_qualification.py --binary target/debug/meguvizdexdash[.exe] --out FILE
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MATRIX_PATH = HERE / "platform-matrix.json"
MPROTECT_HEADER = ROOT / "include" / "mdd.h"

PUBLIC_APK = ROOT / "conformance/generic-consumer/fixtures/public-app-audit.apk"
DECODE_CLASS_DEX = ROOT / "tests/fixtures/decode/generated/decode-class.dex"
RESOURCES_SMALL_APK = ROOT / "tests/fixtures/resources/generated/resources-small.apk"
UNICODE_DEX = ROOT / "tests/fixtures/query/generated/unicode-order-038.dex"
DESKTOP_DIR = ROOT / "tests/fixtures/desktop/generated"

EXPECTED_MCP_TOOLS = [
    "open_dataset",
    "list_datasets",
    "close_dataset",
    "list_tables",
    "describe_table",
    "query",
    "decode",
    "get_manifest",
    "get_manifest_components",
    "list_resource_files",
    "read_resource",
    "query_resources",
]

sys.path.insert(0, str(ROOT / "python"))
import mdd  # noqa: E402
from mdd import _ffi, errors as mdd_errors  # noqa: E402

sys.path.insert(0, str(ROOT / "conformance" / "mcp"))
from mcp_client import McpClient, McpError  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(f"platform qualification check failed: {message}")


def _platform_id() -> str:
    sys_name = platform.system().lower()
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64", "x64"):
        arch = "x86_64"
    elif machine in ("arm64", "aarch64"):
        arch = "aarch64"
    else:
        arch = machine
    if sys_name.startswith("win"):
        return f"windows-{arch}"
    if sys_name.startswith("linux"):
        return f"linux-{arch}"
    if sys_name.startswith("darwin"):
        return f"macos-{arch}"
    return f"{sys_name}-{arch}"


def _canonical_sha256(obj: Any) -> str:
    encoded = json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _resolve_ffi_lib(binary: Path, explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit.resolve()
    name = "mdd_ffi.dll" if sys.platform == "win32" else ("libmdd_ffi.dylib" if sys.platform == "darwin" else "libmdd_ffi.so")
    sibling = binary.resolve().parent / name
    require(sibling.is_file(), f"missing FFI library next to binary: {sibling}")
    return sibling


def _normalize_sdk_cell(val: Any) -> Any:
    if isinstance(val, mdd.DexMutf8):
        return {"kind": "dex_mutf8", "hex": val.raw.hex(), "utf16_units": val.utf16_units}
    if isinstance(val, bytes):
        return {"kind": "bytes", "hex": val.hex()}
    if isinstance(val, str):
        # Preserve unpaired surrogates losslessly via explicit UTF-16 code units JSON list.
        try:
            val.encode("utf-8")
            return {"kind": "utf8", "v": val}
        except UnicodeEncodeError:
            raw = val.encode("utf-16-le", "surrogatepass")
            units = [f"{int.from_bytes(raw[i:i+2], 'little'):04x}" for i in range(0, len(raw), 2)]
            return {"kind": "utf16_units", "u": units}
    return val


def _verify_cli_surface(binary: Path) -> dict[str, Any]:
    ver = subprocess.run([str(binary), "version"], cwd=ROOT, capture_output=True, text=True, check=False)
    require(ver.returncode == 0, f"cli version failed: {ver.stderr}")
    ver_doc = json.loads(ver.stdout)
    require(bool(ver_doc.get("engine_version")), "version payload missing engine_version")

    caps = subprocess.run([str(binary), "capabilities"], cwd=ROOT, capture_output=True, text=True, check=False)
    require(caps.returncode == 0, f"cli capabilities failed: {caps.stderr}")
    caps_doc = json.loads(caps.stdout)
    for prof in caps_doc.get("profiles", []):
        require(prof.get("admitted") is not True, f"capabilities unexpectedly admitted profile: {prof}")
    dex_fmt = [f for f in caps_doc.get("input_formats", []) if f.get("kind") == "dex-header"]
    require(bool(dex_fmt) and "041" not in dex_fmt[0].get("versions", []), f"dex-041 unexpectedly advertised: {dex_fmt}")

    q_jsonl = subprocess.run(
        [str(binary), "query", "--input", str(PUBLIC_APK), "--dialect", "dexsql-0.1.1", "--format", "jsonl", "--sql", "SELECT COUNT(*) AS n FROM dex_files"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    require(q_jsonl.returncode == 0, f"cli query jsonl failed: {q_jsonl.stderr}")
    lines = [json.loads(line) for line in q_jsonl.stdout.splitlines() if line.strip()]
    require(lines[0]["kind"] == "opened" and lines[-1]["kind"] == "terminal", "cli query missing framing")
    require(lines[-1]["terminal"]["operation_status"] == "ok", "cli query terminal not ok")

    q_text = subprocess.run(
        [str(binary), "query", "--input", str(DESKTOP_DIR / "a.dex"), "--format", "text", "--sql", "SELECT descriptor FROM native_classes ORDER BY descriptor"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    require(q_text.returncode == 0 and "Ldemo/A;" in q_text.stdout, f"cli text output mismatch: {q_text.stdout}")

    bad_usage = subprocess.run([str(binary), "query"], cwd=ROOT, capture_output=True, text=True, check=False)
    require(bad_usage.returncode == 2, f"expected refusal exit 2, got {bad_usage.returncode}")
    bad_sql = subprocess.run(
        [str(binary), "query", "--input", str(DESKTOP_DIR / "a.dex"), "--sql", "SELECT * FROM no_such_table"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    require(bad_sql.returncode == 1, f"expected failure terminal exit 1, got {bad_sql.returncode}")
    return {
        "passed": True,
        "engine_version": ver_doc.get("engine_version"),
        "exit_codes_verified": {"ok": 0, "statement_error": 1, "refusal": 2},
    }


def _mcp_call(client: McpClient, tool_name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    response = client.request("tools/call", {"name": tool_name, "arguments": arguments or {}})
    if "error" in response:
        raise McpError(response["error"])
    result = response["result"]
    structured = dict(result["structuredContent"])
    structured["_is_error"] = result["isError"]
    return structured


def _verify_mcp_and_canonical_workloads(binary: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    client = McpClient(binary, ["--dialect", "dexsql-0.1.1"])
    workloads: dict[str, dict[str, Any]] = {}
    try:
        init = client.initialize()
        require("serverInfo" in init, "MCP initialize missing serverInfo")
        tool_list = client.tools()
        names = [t["name"] for t in tool_list]
        require(sorted(names) == sorted(EXPECTED_MCP_TOOLS), f"unexpected MCP tools: {names}")

        # Open 3 public fixtures at once to exercise list_datasets + close_dataset + 12 tools.
        op_pub = _mcp_call(client, "open_dataset", {"inputs": [str(PUBLIC_APK)]})
        did_pub = op_pub["dataset_id"]
        op_dec = _mcp_call(client, "open_dataset", {"inputs": [str(DECODE_CLASS_DEX)]})
        did_dec = op_dec["dataset_id"]
        op_res = _mcp_call(client, "open_dataset", {"inputs": [str(RESOURCES_SMALL_APK)]})
        did_res = op_res["dataset_id"]

        ds_list = _mcp_call(client, "list_datasets")
        require(len(ds_list["datasets"]) == 3, f"expected 3 open datasets, got {len(ds_list['datasets'])}")

        tables = _mcp_call(client, "list_tables")
        require(len(tables["tables"]) == 56, f"expected 56 advertised tables, got {len(tables['tables'])}")
        desc = _mcp_call(client, "describe_table", {"name": "method_calls"})
        require(any(c["name"] == "callee" for c in desc["columns"]), "describe_table missing callee column")

        # Workload 1: public APK relational + manifest components
        def _query_all(dataset_id: str, sql: str) -> dict[str, Any]:
            rows_all: list[Any] = []
            cols: Any = None
            off = 0
            while True:
                res = _mcp_call(client, "query", {"dataset_id": dataset_id, "sql": [sql], "offset": off, "limit": 1000})
                stmt = res["statements"][0]
                if cols is None:
                    cols = stmt["columns"]
                rows_all.extend(stmt["rows"])
                if stmt.get("next_offset") is None:
                    require(not stmt["truncated"], "truncated without next_offset")
                    break
                off = int(stmt["next_offset"])
            return {"columns": cols, "rows": rows_all}

        df_q = _query_all(
            did_pub,
            "SELECT file_id, entry_name, dex_version, byte_len, checksum, signature_hex, class_count, method_count FROM dex_files ORDER BY file_id",
        )
        cls_q = _query_all(did_pub, "SELECT file_id, class_idx, descriptor, access_flags, superclass_descriptor FROM classes ORDER BY file_id, class_idx")
        mc_q = _query_all(did_pub, "SELECT file_id, method_idx, method, callee FROM method_calls ORDER BY file_id, method_idx, callee")
        ms_q = _query_all(did_pub, "SELECT file_id, method_idx, value FROM method_strings ORDER BY file_id, method_idx, value")
        ci_q = _query_all(did_pub, "SELECT file_id, method_idx, code_off, insns_off, insns_size FROM code_items ORDER BY file_id, method_idx")
        comps_pub = _mcp_call(client, "get_manifest_components", {"dataset_id": did_pub})
        public_bundle = {
            "snapshot_content_key": op_pub["snapshot_manifest"]["snapshot_content_key"],
            "dex_files": df_q,
            "classes": cls_q,
            "method_calls": mc_q,
            "method_strings": ms_q,
            "code_items": ci_q,
            "components": comps_pub["components"],
        }
        workloads["public_apk_facts_digest"] = {
            "canonical_sha256": _canonical_sha256(public_bundle),
            "dex_rows": len(df_q["rows"]),
            "call_rows": len(mc_q["rows"]),
        }

        # Workload 2: decode summary + smali (paged) + context
        dec_sum = _mcp_call(client, "decode", {"dataset_id": did_dec, "class": "Ldecode/K;", "mode": "summary", "method_limit": 5})
        require(not dec_sum.get("_is_error") and dec_sum.get("methods"), f"decode class summary failed: {dec_sum}")
        dec_m = dec_sum["methods"][0]
        dec_smali_pages = []
        off = 0
        while True:
            page = _mcp_call(client, "decode", {"dataset_id": did_dec, "file_id": 0, "method_idx": dec_m["method_idx"], "mode": "smali", "offset": off, "max_bytes": 1024})
            m_row = page["methods"][0]
            dec_smali_pages.append(m_row["smali"])
            next_off = m_row.get("next_offset")
            if next_off is None:
                break
            off = int(next_off)
        dec_ctx = _mcp_call(client, "decode", {"dataset_id": did_dec, "file_id": 0, "method_idx": dec_m["method_idx"], "mode": "context"})
        decode_bundle = {
            "summary_count": len(dec_sum["methods"]),
            "total_methods": dec_sum["total_methods"],
            "text_format": dec_ctx.get("text_format"),
            "smali_full": "".join(dec_smali_pages),
            "context_text": dec_ctx["methods"][0]["smali"],
        }
        require(bool(decode_bundle["smali_full"]) and bool(decode_bundle["context_text"]), "empty decode text")
        workloads["decode_smali_and_context_digest"] = {
            "canonical_sha256": _canonical_sha256(decode_bundle),
            "total_methods": dec_sum["total_methods"],
            "smali_pages": len(dec_smali_pages),
        }

        # Workload 3: manifest summary/xml + resource files + read_resource + query_resources
        man_sum = _mcp_call(client, "get_manifest", {"dataset_id": did_res, "mode": "summary"})
        xml_parts = []
        off = 0
        while True:
            page = _mcp_call(client, "get_manifest", {"dataset_id": did_res, "mode": "xml", "offset": off, "max_bytes": 4096})
            p = page["page"]
            xml_parts.append(p["text"])
            next_off = p.get("next_offset")
            if next_off is None:
                break
            off = int(next_off)
        res_comps = _mcp_call(client, "get_manifest_components", {"dataset_id": did_res})
        res_files = _mcp_call(client, "list_resource_files", {"dataset_id": did_res})
        res_layout = _mcp_call(client, "read_resource", {"dataset_id": did_res, "name": "res/layout/main.xml", "format": "auto"})
        res_bin = _mcp_call(client, "read_resource", {"dataset_id": did_res, "name": "assets/blob.bin", "format": "hex"})
        res_q = _mcp_call(client, "query_resources", {"dataset_id": did_res, "resource_type": "string"})
        res_bundle = {
            "manifest_summary": {k: v for k, v in man_sum.items() if k != "dataset_id"},
            "manifest_xml": "".join(xml_parts),
            "components": res_comps["components"],
            "files": res_files["files"],
            "layout_auto": (res_layout.get("page") or {}).get("text"),
            "blob_hex": res_bin.get("content"),
            "string_resources": res_q["values"],
        }
        require("<manifest" in res_bundle["manifest_xml"], "manifest_xml missing <manifest>")
        require(bool(res_bundle["layout_auto"]), "read_resource(auto) returned empty layout XML")
        require(bool(res_bundle["blob_hex"]) and len(res_bundle["blob_hex"]) == 512, "read_resource(hex) mismatch")
        require(len(res_bundle["string_resources"]) >= 4, "query_resources missing multi-config string variants")
        workloads["resources_and_manifest_digest"] = {
            "canonical_sha256": _canonical_sha256(res_bundle),
            "resource_files": len(res_files["files"]),
        }

        # Verify close_dataset and post-close refusal.
        closed = _mcp_call(client, "close_dataset", {"dataset_id": did_pub})
        require(closed["closed"] is True, "close_dataset failed")
        bad_after_close = _mcp_call(client, "list_resource_files", {"dataset_id": did_pub})
        require(bad_after_close.get("_is_error") is True, "closed dataset answered without error")
        return {"passed": True, "tools_verified": 12, "tables_count": len(tables["tables"])}, workloads
    finally:
        client.close()


def _verify_sdk_and_canonical_cells(binary: Path, ffi_lib: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    os.environ["MDD_FFI_LIBRARY"] = str(ffi_lib)
    os.environ["MDD_WORKER_BINARY"] = str(binary)
    mdd.load(ffi_lib)
    probe_sql = (
        "SELECT 9223372036854775807, -9223372036854775808, NULL, '', "
        "CAST(x'EDA080' AS TEXT), x'00FF', 1.25, -0.0, string_idx, value, raw_mutf8 "
        "FROM native_strings ORDER BY string_idx"
    )
    with mdd.open_snapshot([str(UNICODE_DEX)]) as snap, snap.open_session() as sess:
        local = sess.execute(probe_sql)
        snap_key = snap.manifest["snapshot_content_key"]
    with mdd.Worker([str(UNICODE_DEX)], dialect="native-v1", binary=binary) as worker:
        remote = worker.execute(probe_sql)
    require(local.rows == remote.rows and local.columns == remote.columns, "SDK in-process and Worker diverged on scalar/MUTF-8 cells")
    normalized_rows = [[_normalize_sdk_cell(c) for c in row] for row in local.rows]
    workloads = {
        "mutf8_and_scalar_cells_digest": {
            "canonical_sha256": _canonical_sha256({"snapshot_content_key": snap_key, "rows": normalized_rows}),
            "row_count": len(normalized_rows),
        }
    }
    return {"passed": True, "mutf8_rows_checked": len(normalized_rows)}, workloads


def _verify_desktop_evidence(plat_id: str) -> dict[str, Any]:
    preview_path = ROOT / "artifacts/mdd-073/preview-manifest.json"
    require(preview_path.is_file(), "missing artifacts/mdd-073/preview-manifest.json")
    preview = json.loads(preview_path.read_text(encoding="utf-8"))
    require(preview.get("preview") is True and preview.get("performance_replacement_qualified") is False, "invalid MDD-073 preview flags")
    matching = [p for p in preview["tested_platforms"] if f"{p['os']}-{p['arch']}" == plat_id]
    require(len(matching) >= 1, f"MDD-073 preview manifest has no entry for {plat_id}")
    checked_files: list[str] = []
    for entry in matching:
        ev = ROOT / entry["evidence"]
        require(ev.is_file(), f"missing MDD-073 evidence file: {entry['evidence']}")
        ev_doc = json.loads(ev.read_text(encoding="utf-8"))
        flows = ev_doc.get("flows") or {}
        require(flows.get("failed") == 0 and flows.get("passed", 0) >= 14, f"MDD-073 package check had failures: {entry['evidence']}")
        require(ev_doc.get("preview") is True, f"MDD-073 package check missing preview=true: {entry['evidence']}")
        checked_files.append(entry["evidence"])
    return {
        "passed": True,
        "preview": True,
        "performance_replacement_qualified": False,
        "verified_evidence_files": checked_files,
    }


def _probe_unicode_paths(binary: Path, ffi_lib: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        u_dir = Path(tmp) / "mdd_平台_प्रणाली_δείγμα"
        u_dir.mkdir(parents=True, exist_ok=True)
        u_apk = u_dir / "样本_αβγ.apk"
        u_apk.write_bytes(PUBLIC_APK.read_bytes())

        with mdd.open_snapshot([str(u_apk)]) as snap, snap.open_session() as sess:
            rows = sess.execute("SELECT COUNT(*) FROM native_classes").rows
            require(rows == [(5,)], f"unicode SDK class count mismatch: {rows}")
            snap_key = snap.manifest["snapshot_content_key"]

        with mdd.Worker([str(u_apk)], dialect="dexsql-0.1.1", binary=binary) as worker:
            w_rows = worker.execute("SELECT COUNT(*) FROM dex_files").rows
            require(w_rows == [(5,)], f"unicode worker dex count mismatch: {w_rows}")

        client = McpClient(binary, ["--dialect", "dexsql-0.1.1"])
        try:
            client.initialize()
            opened = client.call("open_dataset", inputs=[str(u_apk)])
            require(opened["snapshot_manifest"]["snapshot_content_key"] == snap_key, "unicode path MCP snapshot key mismatch")
        finally:
            client.close()
    return {"passed": True, "tested_filename": "mdd_平台_प्रणाली_δείγμα/样本_αβγ.apk"}


def _probe_source_replace_and_delete(binary: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        mutated = Path(tmp) / "mutated.dex"
        deleted = Path(tmp) / "deleted.dex"
        mutated.write_bytes((DESKTOP_DIR / "a.dex").read_bytes())
        deleted.write_bytes((DESKTOP_DIR / "c.dex").read_bytes())

        snap = mdd.open_snapshot([str(mutated), str(deleted)])
        sess = snap.open_session()
        worker = mdd.Worker([str(mutated), str(deleted)], dialect="dexsql-0.1.1", binary=binary)
        mcp = McpClient(binary, ["--dialect", "dexsql-0.1.1"])
        try:
            mcp.initialize()
            opened = mcp.call("open_dataset", inputs=[str(mutated), str(deleted)])
            did = opened["dataset_id"]

            before_sdk = sess.execute("SELECT mr.name FROM native_method_references mr ORDER BY mr.name").rows
            before_w = worker.execute("SELECT method_descriptor FROM class_methods ORDER BY file_id, method_idx").rows

            # Mutate one source file in-place and delete the other while all handles remain open.
            mutated.write_bytes((DESKTOP_DIR / "b.dex").read_bytes())
            deleted.unlink()

            after_sdk = sess.execute("SELECT mr.name FROM native_method_references mr ORDER BY mr.name").rows
            after_w = worker.execute("SELECT method_descriptor FROM class_methods ORDER BY file_id, method_idx").rows
            after_mcp = mcp.call("query", dataset_id=did, sql=["SELECT method_descriptor FROM class_methods ORDER BY file_id, method_idx"])
            require(before_sdk == after_sdk, "open C ABI snapshot observed post-capture file mutation")
            require(before_w == after_w, "open Worker observed post-capture file mutation")
            require(len(after_mcp["statements"][0]["rows"]) == len(after_w), "open MCP dataset lost deleted file rows")

            # A fresh snapshot MUST observe the replaced content and fail on the deleted input.
            with mdd.open_snapshot([str(mutated)]) as snap2, snap2.open_session() as sess2:
                fresh_names = [r[0] for r in sess2.execute("SELECT mr.name FROM native_method_references mr").rows]
                require("added" in fresh_names and "gone" not in fresh_names, f"fresh snapshot did not read replaced bytes: {fresh_names}")
            missing_raised = False
            try:
                mdd.open_snapshot([str(deleted)])
            except mdd_errors.InvalidInput:
                missing_raised = True
            require(missing_raised, "opening deleted file did not raise InvalidInput")
        finally:
            mcp.close()
            worker.close()
            sess.close()
            snap.close()
    return {"passed": True}


def _probe_worker_crash_cleanup(binary: Path) -> dict[str, Any]:
    long_dex = DESKTOP_DIR / "long.dex"
    heavy_sql = "SELECT a.method_idx, b.method_idx FROM native_method_definitions a, native_method_definitions b"
    # long.dex only has 1 method, so use decode-all or cross-join native_types
    heavy_sql = "SELECT a.type_idx, b.type_idx, c.type_idx FROM native_types a, native_types b, native_types c"
    with mdd.Worker([str(UNICODE_DEX)], dialect="native-v1", binary=binary) as worker:
        query = worker.query(heavy_sql, batch_rows=5)
        it = query.batches()
        first = next(it)
        require(len(first.rows) == 5, "expected first batch before forced kill")
        pid = worker.pid
        if os.name == "nt":
            worker._process.kill()
        else:
            os.kill(pid, signal.SIGKILL)
        got_lost = False
        try:
            for _ in it:
                pass
        except mdd_errors.WorkerLost as err:
            got_lost = err.code == "WORKER_LOST"
        require(got_lost, "killing active worker did not raise WorkerLost(WORKER_LOST)")
        require(not worker.abandoned_threads, f"abandoned reader threads: {worker.abandoned_threads}")
        require(worker._process.poll() is not None, "killed worker process still alive")
    return {"passed": True, "error_code": "WORKER_LOST", "abandoned_threads": 0}


def _probe_pipe_close(binary: Path) -> dict[str, Any]:
    # 1. Clean stdin close on `mcp` and `serve` -> exit code 0, empty stderr.
    for cmd in (
        [str(binary), "mcp"],
        [str(binary), "serve", "--input", str(DESKTOP_DIR / "a.dex")],
    ):
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate(input=b"", timeout=15)
        require(proc.returncode == 0, f"{cmd[1]} did not exit cleanly on closed stdin: rc={proc.returncode}, err={err!r}")
        require(b"panicked" not in err, f"panic on closed stdin in {cmd[1]}: {err!r}")

    # 2. Mid-stream stdout pipe close on `query` -> exit code 4 (OUTPUT), no Rust panic.
    q_proc = subprocess.Popen(
        [
            str(binary),
            "query",
            "--input",
            str(UNICODE_DEX),
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
    require(q_proc.stdout is not None and q_proc.stderr is not None, "missing query stdio pipes")
    first_line = q_proc.stdout.readline()
    require(b'"opened"' in first_line, f"unexpected first query line: {first_line!r}")
    q_proc.stdout.close()
    q_proc.wait(timeout=20)
    err_bytes = q_proc.stderr.read()
    q_proc.stderr.close()
    require(q_proc.returncode == 4, f"expected exit code 4 on broken stdout pipe, got {q_proc.returncode} stderr={err_bytes!r}")
    require(b"panicked" not in err_bytes, f"panic on broken stdout pipe: {err_bytes!r}")
    return {"passed": True, "closed_stdin_exit": 0, "closed_stdout_exit": 4}


def _probe_c_abi_lifecycle(ffi_lib: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    lib = _ffi.Library(ffi_lib)
    require(ctypes.sizeof(_ffi.AbiInfo) == 16, "unexpected mdd_abi_info size")
    require(ctypes.sizeof(_ffi.BytesView) == 16, "unexpected mdd_bytes_view size")

    # Verify all 29 declared symbols exist in the compiled shared library.
    header_text = MPROTECT_HEADER.read_text(encoding="utf-8")
    declared = sorted(set(re.findall(r"\b(mdd_[a-z0-9_]+)\s*\(", header_text)))
    require(len(declared) == 29, f"expected 29 exported mdd_* functions in header, found {len(declared)}")
    for sym in declared:
        require(hasattr(lib._dll, sym), f"missing exported symbol {sym} in {ffi_lib.name}")

    # ABI mismatch negative test + error handle release.
    bad_info = _ffi.AbiInfo(ctypes.sizeof(_ffi.AbiInfo), 2, 0, 0)
    err_h = ctypes.c_uint64(0)
    status = lib.raw("mdd_abi_negotiate_v1", 2, 0, ctypes.byref(bad_info), ctypes.byref(err_h))
    require(status == 12 and err_h.value != 0, f"expected ABI_MISMATCH (12), got {status}")
    err_view = _ffi.BytesView()
    require(lib.raw("mdd_error_json_v1", err_h.value, ctypes.byref(err_view)) == 0, "mdd_error_json_v1 failed")
    err_doc = json.loads(_ffi.read_view(err_view))
    require(err_doc.get("code") == "ABI_MISMATCH", f"unexpected mismatch error code: {err_doc}")
    require(lib.raw("mdd_error_release", err_h.value) == 0, "mdd_error_release failed")

    # Retain batch across full teardown of event -> query -> prepared -> session -> snapshot.
    before_handles = lib.live_handles()
    req_bytes = json.dumps({"inputs": [{"path": str(DECODE_CLASS_DEX), "kind": "raw_dex"}]}).encode()
    view, keep = _ffi.view_of(req_bytes)
    snap_h = ctypes.c_uint64(0)
    lib.call("mdd_open_snapshot_v1", ctypes.byref(view), ctypes.byref(snap_h))
    del keep

    manifest_doc = lib.json_view("mdd_snapshot_manifest_json_v1", snap_h.value)
    empty_v, _ = _ffi.view_of(b"")
    sess_h = ctypes.c_uint64(0)
    lib.call("mdd_open_session_v1", snap_h.value, ctypes.byref(empty_v), ctypes.byref(sess_h))

    sql_v, keep_sql = _ffi.view_of(
        json.dumps({"kind": "sql", "sql": "SELECT class_def_idx, descriptor FROM native_classes ORDER BY class_def_idx"}).encode()
    )
    prep_h = ctypes.c_uint64(0)
    lib.call("mdd_prepare_query_v1", sess_h.value, ctypes.byref(sql_v), ctypes.byref(prep_h))
    del keep_sql

    qry_h = ctypes.c_uint64(0)
    lib.call("mdd_start_query_v1", prep_h.value, ctypes.byref(empty_v), ctypes.byref(qry_h))

    evt_h = ctypes.c_uint64(0)
    lib.call("mdd_query_next_v1", qry_h.value, 100, ctypes.byref(evt_h))
    kind = ctypes.c_uint32(0)
    lib.call("mdd_event_kind_v1", evt_h.value, ctypes.byref(kind))
    require(kind.value == _ffi.EVENT_BATCH, "expected EVENT_BATCH")

    batch_h = ctypes.c_uint64(0)
    lib.call("mdd_event_batch_v1", evt_h.value, ctypes.byref(batch_h))
    require(lib.raw("mdd_batch_retain", batch_h.value) == 0, "mdd_batch_retain failed")
    lib.call("mdd_batch_ack_v1", batch_h.value)
    require(lib.raw("mdd_event_release", evt_h.value) == 0, "mdd_event_release failed")

    # Flow control: asking for the next event while a retained batch is still live returns OUTSTANDING_BATCH (5).
    blocked_evt = ctypes.c_uint64(0)
    blocked_err = ctypes.c_uint64(0)
    blocked_st = lib.raw("mdd_query_next_v1", qry_h.value, 100, ctypes.byref(blocked_evt), ctypes.byref(blocked_err))
    if blocked_err.value:
        lib.raw("mdd_error_release", blocked_err.value)
    require(blocked_st == 5, f"expected MDD_E_OUTSTANDING_BATCH (5), got {blocked_st}")

    # Close and release every parent while the retained batch handle remains alive.
    lib.call("mdd_snapshot_close_v1", snap_h.value)
    lib.call("mdd_session_close_v1", sess_h.value)
    for fn, h in (
        ("mdd_query_release", qry_h.value),
        ("mdd_prepared_release", prep_h.value),
        ("mdd_session_release", sess_h.value),
        ("mdd_snapshot_release", snap_h.value),
    ):
        require(lib.raw(fn, h) == 0, f"{fn} failed")

    # Retained batch view MUST still be valid after every parent is closed and released.
    batch_doc = lib.json_view("mdd_batch_json_v1", batch_h.value)
    require(batch_doc.get("schema") == "mdd.sdk-batch.v1" and batch_doc.get("row_count") >= 1, "retained batch unreadable")
    require(lib.raw("mdd_batch_release", batch_h.value) == 0, "retained batch release failed")
    require(lib.raw("mdd_batch_release", batch_h.value) == 2, "double release did not return MDD_E_INVALID_HANDLE")

    # Stale snapshot handle after opening a new snapshot must still return MDD_E_INVALID_HANDLE (2).
    view2, keep2 = _ffi.view_of(req_bytes)
    snap2_h = ctypes.c_uint64(0)
    lib.call("mdd_open_snapshot_v1", ctypes.byref(view2), ctypes.byref(snap2_h))
    del keep2
    stale_err = ctypes.c_uint64(0)
    stale_status = lib.raw("mdd_snapshot_close_v1", snap_h.value, ctypes.byref(stale_err))
    if stale_err.value:
        lib.raw("mdd_error_release", stale_err.value)
    require(stale_status == 2, f"stale handle returned {stale_status}, expected 2 (MDD_E_INVALID_HANDLE)")
    require(lib.raw("mdd_snapshot_release", snap2_h.value) == 0, "snap2 release failed")

    after_handles = lib.live_handles()
    require(after_handles == before_handles, f"C ABI handle leak: before={before_handles}, after={after_handles}")

    canonical_codec = {
        "snapshot_content_key": manifest_doc["snapshot_content_key"],
        "captured_input_bytes": manifest_doc["captured_input_bytes"],
        "sources": [
            {
                "input_kind": s["input_kind"],
                "byte_length": s["byte_length"],
                "content_id": s["content_id"],
            }
            for s in manifest_doc["sources"]
        ],
        "batch": batch_doc,
    }
    return (
        {
            "passed": True,
            "exported_symbols_verified": len(declared),
            "retained_batch_outlived_parents": True,
            "double_release_rejected": True,
            "stale_handle_rejected": True,
            "live_handles_delta": after_handles - before_handles,
        },
        {"c_abi_batch_codec_digest": {"canonical_sha256": _canonical_sha256(canonical_codec), "row_count": batch_doc["row_count"]}},
    )


def _probe_multi_session_isolation(binary: Path, ffi_lib: Path) -> dict[str, Any]:
    os.environ["MDD_FFI_LIBRARY"] = str(ffi_lib)
    mdd.load(ffi_lib)
    errors: list[str] = []
    results: dict[str, Any] = {}

    def _run_a() -> None:
        try:
            with mdd.open_snapshot([str(DESKTOP_DIR / "a.dex")]) as sa, sa.open_session() as s1:
                with s1.query("SELECT a.type_idx, b.type_idx FROM native_types a, native_types b") as q:
                    for _ in q.batches(demand_rows=2):
                        q.cancel()
                        break
                res_a = s1.execute("SELECT mr.name FROM native_method_references mr ORDER BY mr.name")
                results["a"] = [r[0] for r in res_a.rows]
        except BaseException as exc:
            errors.append(f"session_a: {exc!r}")

    def _run_b() -> None:
        try:
            with mdd.open_snapshot([str(DESKTOP_DIR / "b.dex"), str(DESKTOP_DIR / "c.dex")]) as sb, sb.open_session() as s2:
                time.sleep(0.05)
                res_b = s2.execute("SELECT descriptor FROM native_classes ORDER BY descriptor")
                results["b"] = [r[0] for r in res_b.rows]
        except BaseException as exc:
            errors.append(f"session_b: {exc!r}")

    t1 = threading.Thread(target=_run_a)
    t2 = threading.Thread(target=_run_b)
    t1.start()
    t2.start()
    t1.join(timeout=15)
    t2.join(timeout=15)
    require(not errors, f"multi-session thread errors: {errors}")
    require("gone" in results.get("a", []) and "added" not in results.get("a", []), f"session A saw wrong facts: {results}")
    require(results.get("b") == ["Ldemo/A;", "Ldemo/C;"], f"session B saw wrong classes: {results}")

    # Concurrent MCP datasets inside one server.
    client = McpClient(binary, ["--dialect", "dexsql-0.1.1"])
    try:
        client.initialize()
        d1 = client.call("open_dataset", inputs=[str(DESKTOP_DIR / "a.dex")])["dataset_id"]
        d2 = client.call("open_dataset", inputs=[str(DESKTOP_DIR / "c.dex")])["dataset_id"]
        require(client.call("close_dataset", dataset_id=d1)["closed"] is True, "failed to close d1")
        q2 = client.call("query", dataset_id=d2, sql=["SELECT descriptor FROM classes"])
        require(q2["statements"][0]["rows"][0][0]["value"] == "Ldemo/C;", "closing d1 affected d2")
    finally:
        client.close()
    return {"passed": True, "live_handles_after_close": mdd.live_handles()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "target" / "debug" / ("meguvizdexdash.exe" if sys.platform == "win32" else "meguvizdexdash"))
    parser.add_argument("--ffi-lib", type=Path, default=None)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    binary = args.binary.resolve()
    require(binary.is_file(), f"CLI binary not found: {binary}")
    ffi_lib = _resolve_ffi_lib(binary, args.ffi_lib)

    plat_id = _platform_id()
    require(plat_id in ("windows-x86_64", "linux-x86_64"), f"unexpected platform {plat_id!r} for Tier-1 qualification")

    cli_res = _verify_cli_surface(binary)
    mcp_res, mcp_workloads = _verify_mcp_and_canonical_workloads(binary)
    sdk_res, sdk_workloads = _verify_sdk_and_canonical_cells(binary, ffi_lib)
    desk_res = _verify_desktop_evidence(plat_id)

    edge_probes = {
        "unicode_paths": _probe_unicode_paths(binary, ffi_lib),
        "source_replace_and_delete": _probe_source_replace_and_delete(binary),
        "worker_crash_cleanup": _probe_worker_crash_cleanup(binary),
        "pipe_close_handling": _probe_pipe_close(binary),
        "multi_session_isolation": _probe_multi_session_isolation(binary, ffi_lib),
    }
    abi_res, abi_workloads = _probe_c_abi_lifecycle(ffi_lib)
    edge_probes["c_abi_buffer_and_handle_lifecycle"] = abi_res

    all_workloads = {**mcp_workloads, **sdk_workloads, **abi_workloads}
    overall_hash = _canonical_sha256({k: v["canonical_sha256"] for k, v in sorted(all_workloads.items())})

    result = {
        "schema": "mdd.platform-results.v1",
        "task": "MDD-080",
        "kind": "native runtime platform qualification evidence; does not admit performance replacement",
        "platform_id": plat_id,
        "os": platform.system().lower(),
        "arch": "x86_64",
        "os_release": platform.release(),
        "python_version": platform.python_version(),
        "cross_compiled": False,
        "executed_natively": True,
        "performance_replacement_qualified": False,
        "recorded_utc": datetime.now(timezone.utc).isoformat(),
        "surfaces": {
            "cli": cli_res,
            "mcp": mcp_res,
            "python_sdk": sdk_res,
            "desktop_preview": desk_res,
        },
        "lifecycle_edge_probes": edge_probes,
        "canonical_workloads": all_workloads,
        "overall_canonical_sha256": overall_hash,
        "overall_passed": True,
    }

    out_path = args.out if args.out.is_absolute() else (ROOT / args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"MDD-080 native platform qualification passed on {plat_id}: overall_canonical_sha256={overall_hash}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
