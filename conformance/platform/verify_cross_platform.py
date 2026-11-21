#!/usr/bin/env python3
"""Cross-platform canonical equivalence and platform matrix verifier (MDD-080).

Never uses bare `assert` for conformance validation.
Usage:
    python -I conformance/platform/verify_cross_platform.py --check
    python -I conformance/platform/verify_cross_platform.py --write
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MATRIX_PATH = HERE / "platform-matrix.json"
WIN_RESULTS = ROOT / "artifacts" / "mdd-080" / "windows-x86_64-results.json"
LIN_RESULTS = ROOT / "artifacts" / "mdd-080" / "linux-x86_64-results.json"
COMPAT_PATH = ROOT / "artifacts" / "mdd-080" / "abi-compatibility.json"
BACKLOG_PATH = ROOT / "tasks" / "backlog.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(f"cross-platform verification failed: {message}")


def validate_matrix(matrix: dict[str, Any]) -> None:
    require(matrix.get("schema") == "mdd.platform-matrix.v1", "unexpected platform-matrix schema")
    require(matrix.get("depends_on_mdd_074") is False, "platform qualification must stay independent of MDD-074")
    require(matrix.get("performance_replacement_qualified") is False, "must not mark performance replacement qualified")
    tier1 = matrix.get("tier1_platforms") or {}
    require("linux-x86_64" in tier1 and "windows-x86_64" in tier1, "missing Tier-1 platforms")
    for key in ("linux-x86_64", "windows-x86_64"):
        entry = tier1[key]
        require(entry.get("cross_compile_substitutes_runtime") is False, f"{key} allows cross-compile substitution")
        require(entry.get("performance_replacement_qualified") is False, f"{key} prematurely claims performance qualification")
    unadmitted = matrix.get("unadmitted_platforms") or []
    ids = {u.get("id"): u for u in unadmitted}
    require("macos-arm64" in ids, "platform-matrix must explicitly list macos-arm64 as not_admitted")
    for uid, u in ids.items():
        require(u.get("status") == "not_admitted", f"{uid} must have status=not_admitted")
        require(u.get("advertised") is False, f"{uid} must not be advertised")
        require(u.get("runtime_verified") is False, f"{uid} cannot claim runtime_verified")
    opt = (matrix.get("format_scope_boundary") or {}).get("optional_formats_separate_qualification") or []
    require(any(o.get("id") == "dex-041" and o.get("advertised") is False for o in opt), "dex-041 must stay separate and unadvertised")


def validate_platform_result(res: dict[str, Any], expected_platform: str, expected_os: str, matrix: dict[str, Any]) -> None:
    require(res.get("schema") == "mdd.platform-results.v1", f"{expected_platform}: unexpected schema")
    require(res.get("platform_id") == expected_platform, f"expected platform {expected_platform}, got {res.get('platform_id')}")
    require(res.get("os") == expected_os and res.get("arch") == "x86_64", f"{expected_platform}: os/arch mismatch")
    require(res.get("executed_natively") is True and res.get("cross_compiled") is False, f"{expected_platform}: not natively executed")
    require(res.get("overall_passed") is True, f"{expected_platform}: overall_passed is not True")
    surfaces = res.get("surfaces") or {}
    for skey in ("cli", "mcp", "python_sdk", "desktop_preview"):
        require((surfaces.get(skey) or {}).get("passed") is True, f"{expected_platform}: surface {skey} not passed")
    probes = res.get("lifecycle_edge_probes") or {}
    for pkey in (
        "unicode_paths",
        "source_replace_and_delete",
        "worker_crash_cleanup",
        "pipe_close_handling",
        "c_abi_buffer_and_handle_lifecycle",
        "multi_session_isolation",
    ):
        require((probes.get(pkey) or {}).get("passed") is True, f"{expected_platform}: probe {pkey} not passed")
    c_abi = probes["c_abi_buffer_and_handle_lifecycle"]
    require(c_abi.get("live_handles_delta") == 0, f"{expected_platform}: C ABI handle leak detected")
    require(c_abi.get("retained_batch_outlived_parents") is True, f"{expected_platform}: retained batch probe invalid")
    workloads = res.get("canonical_workloads") or {}
    for wid in matrix.get("canonical_workload_ids", []):
        require(wid in workloads and bool(workloads[wid].get("canonical_sha256")), f"{expected_platform}: missing canonical workload {wid}")


def build_compatibility_report(matrix: dict[str, Any], win: dict[str, Any], lin: dict[str, Any]) -> dict[str, Any]:
    validate_matrix(matrix)
    validate_platform_result(win, "windows-x86_64", "windows", matrix)
    validate_platform_result(lin, "linux-x86_64", "linux", matrix)

    require(
        win.get("overall_canonical_sha256") == lin.get("overall_canonical_sha256"),
        f"canonical hash mismatch windows={win.get('overall_canonical_sha256')} vs linux={lin.get('overall_canonical_sha256')}",
    )
    comparisons = {}
    for wid in matrix["canonical_workload_ids"]:
        wh = win["canonical_workloads"][wid]["canonical_sha256"]
        lh = lin["canonical_workloads"][wid]["canonical_sha256"]
        require(wh == lh, f"workload {wid} hash mismatch windows={wh} vs linux={lh}")
        comparisons[wid] = {"windows_sha256": wh, "linux_sha256": lh, "equal": True}

    return {
        "schema": "mdd.abi-compatibility.v1",
        "task": "MDD-080",
        "kind": "dual-OS native runtime & C ABI 1.0 compatibility certificate; does not admit performance replacement",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "abi_version": {"major": 1, "minor": 0, "header": "include/mdd.h"},
        "depends_on_mdd_074": False,
        "performance_replacement_qualified": False,
        "qualified_platforms": ["windows-x86_64", "linux-x86_64"],
        "unadmitted_platforms": [u["id"] for u in matrix["unadmitted_platforms"]],
        "overall_canonical_sha256": win["overall_canonical_sha256"],
        "canonical_hashes_equal": True,
        "workload_comparisons": comparisons,
        "allowed_platform_differences": [d["id"] for d in matrix["allowed_platform_differences"]],
        "evidence_sha256": {
            "conformance/platform/platform-matrix.json": hashlib.sha256(MATRIX_PATH.read_bytes()).hexdigest(),
            "artifacts/mdd-080/windows-x86_64-results.json": hashlib.sha256(WIN_RESULTS.read_bytes()).hexdigest(),
            "artifacts/mdd-080/linux-x86_64-results.json": hashlib.sha256(LIN_RESULTS.read_bytes()).hexdigest(),
        },
        "overall_passed": True,
    }


def _mdd080_is_done() -> bool:
    if not BACKLOG_PATH.is_file():
        return False
    backlog = json.loads(BACKLOG_PATH.read_text(encoding="utf-8"))
    for task in backlog.get("tasks", []):
        if task.get("id") == "MDD-080":
            return task.get("status") == "done"
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)

    matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    validate_matrix(matrix)

    if args.write:
        require(WIN_RESULTS.is_file(), f"missing {WIN_RESULTS}")
        require(LIN_RESULTS.is_file(), f"missing {LIN_RESULTS}")
        win = json.loads(WIN_RESULTS.read_text(encoding="utf-8"))
        lin = json.loads(LIN_RESULTS.read_text(encoding="utf-8"))
        report = build_compatibility_report(matrix, win, lin)
        COMPAT_PATH.parent.mkdir(parents=True, exist_ok=True)
        COMPAT_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
        print(f"wrote {COMPAT_PATH} (overall_canonical_sha256={report['overall_canonical_sha256']})")
        return 0

    # --check mode
    if WIN_RESULTS.is_file():
        win = json.loads(WIN_RESULTS.read_text(encoding="utf-8"))
        validate_platform_result(win, "windows-x86_64", "windows", matrix)
    must_have_pair = _mdd080_is_done() or (WIN_RESULTS.is_file() and LIN_RESULTS.is_file() and COMPAT_PATH.is_file())
    if must_have_pair:
        require(WIN_RESULTS.is_file() and LIN_RESULTS.is_file() and COMPAT_PATH.is_file(), "MDD-080 done requires both OS results and abi-compatibility.json")
        win = json.loads(WIN_RESULTS.read_text(encoding="utf-8"))
        lin = json.loads(LIN_RESULTS.read_text(encoding="utf-8"))
        expected = build_compatibility_report(matrix, win, lin)
        actual = json.loads(COMPAT_PATH.read_text(encoding="utf-8"))
        require(actual.get("overall_canonical_sha256") == expected["overall_canonical_sha256"], "stale abi-compatibility canonical hash")
        require(actual.get("evidence_sha256") == expected["evidence_sha256"], "stale abi-compatibility evidence digests")
    print("platform matrix and available MDD-080 evidence checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
