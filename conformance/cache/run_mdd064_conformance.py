#!/usr/bin/env python3
"""MDD-064 conformance verifier and evidence generator for global scheduling budgets
and auditable whole-content cache reuse (`artifacts/mdd-064/scheduling-and-reuse.json`).

Uses release-built `scheduler_reuse_probe` and `cache_probe` binaries to verify:
1. Global CPU/memory budget prevents cross-stage oversubscription across 1/2/4 concurrent APKs;
2. Bounded queue, overload isolation (`QuotaExceeded`), cancellation responsiveness, and
   `WorkerLost` failure isolation without corrupting concurrent healthy sessions;
3. Whole-`ContentId` object cache reuse preserving exact `LogicalOccurrenceRef` multiplicity when
   physical blobs are deduplicated (`dex_files` row count == total logical occurrences);
4. Shared-container invalidation and negative-finding / incomplete-scope persistence refusal;
5. Workload-denominator incremental savings accounting (never extrapolated from changed bytes),
   `optional_dex041_prerequisite == False`, and fine-grained method-level incrementalism kept
   explicitly disabled (`capability_enabled == False`) until all 5 dependency proofs pass.

Never relies on bare `assert` (`python -O` safe).
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

ROOT = Path(__file__).resolve().parents[2]
RECORD = ROOT / "artifacts/mdd-064/scheduling-and-reuse.json"

SOURCES = [
    "crates/mdd-worker/Cargo.toml",
    "crates/mdd-worker/src/lib.rs",
    "crates/mdd-worker/src/scheduler/mod.rs",
    "crates/mdd-worker/src/scheduler/budget.rs",
    "crates/mdd-worker/src/scheduler/queue.rs",
    "crates/mdd-worker/src/scheduler/tests.rs",
    "crates/mdd-worker/examples/scheduler_reuse_probe.rs",
    "crates/mdd-cache/Cargo.toml",
    "crates/mdd-cache/src/lib.rs",
    "crates/mdd-cache/src/dependency_tracking.rs",
    "crates/mdd-cache/src/dependency_tracking/content_reuse.rs",
    "crates/mdd-cache/src/dependency_tracking/incremental_gate.rs",
    "crates/mdd-cache/examples/cache_probe.rs",
    "conformance/cache/run_mdd064_conformance.py",
    "conformance/cache/test_mdd064_conformance.py",
]

REQUIRED_PROOF_DIMENSIONS = (
    "cross_method_reference_graph",
    "hierarchy_override_closure",
    "global_negative_finding_scope",
    "constant_pool_and_type_field_closure",
    "shared_container_tail_isolation",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(f"MDD-064 verification failed: {message}")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ensure_example_binary(crate: str, example: str, explicit: Path | None, profile: str = "release") -> Path:
    if explicit is not None:
        require(explicit.is_file(), f"{example} binary missing: {explicit}")
        return explicit.resolve()
    exe_name = f"{example}.exe" if os.name == "nt" else example
    candidate = ROOT / "target" / profile / "examples" / exe_name
    if not candidate.is_file():
        cmd = ["cargo", "build", "--offline", "--locked"]
        if profile == "release":
            cmd.append("--release")
        cmd.extend(["-p", crate, "--example", example])
        done = subprocess.run(
            cmd,
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        require(done.returncode == 0, f"failed building {crate} example {example}: {done.stderr}")
    require(candidate.is_file(), f"{example} missing after build: {candidate}")
    return candidate


def run_json_command(cmd: list[str], label: str) -> dict[str, Any]:
    done = subprocess.run(
        cmd,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    require(
        done.returncode == 0,
        f"{label} exited with {done.returncode}: stdout={done.stdout[-1200:]} stderr={done.stderr[-1200:]}",
    )
    return json.loads(done.stdout)


def validate_scheduler_payload(payload: dict[str, Any]) -> None:
    require(payload.get("ok") is True, "scheduler_reuse_probe did not return ok=true")
    levels = payload.get("concurrency_levels", [])
    require([lvl.get("concurrency") for lvl in levels] == [1, 2, 4], "expected concurrency levels [1, 2, 4]")
    for lvl in levels:
        conc = lvl["concurrency"]
        require(lvl.get("tasks_completed") == conc * 2, f"concurrency {conc}: unexpected tasks_completed")
        require(lvl.get("dex_units_processed", 0) > 0, f"concurrency {conc}: zero dex_units_processed")
        require(lvl.get("oversubscription_observed") is False, f"concurrency {conc}: oversubscription observed")
        require(lvl.get("peak_cpu_permits", 999) <= lvl.get("ceiling_cpu_permits", 0), f"concurrency {conc}: CPU ceiling exceeded")
        require(int(lvl["peak_memory_bytes"]) <= int(lvl["ceiling_memory_bytes"]), f"concurrency {conc}: memory ceiling exceeded")
        require(lvl.get("queue_depth_bounded") is True, f"concurrency {conc}: queue_depth_bounded != true")
        require(lvl.get("history_bounded") is True, f"concurrency {conc}: history_bounded != true")

    iso = payload.get("isolation", {})
    require(iso.get("overload_rejected_code") == "QuotaExceeded", f"expected QuotaExceeded, got {iso.get('overload_rejected_code')}")
    require(iso.get("healthy_after_overload_dexes", 0) > 0, "healthy APK after overload processed 0 dexes")
    require(iso.get("cancel_response_ms", 99999.0) < 2000.0, f"cancel response too slow: {iso.get('cancel_response_ms')}ms")
    require(iso.get("victim_worker_lost_count") == 1, "expected victim_worker_lost_count == 1")
    require(iso.get("healthy_after_worker_lost_dexes", 0) > 0, "healthy APK after WorkerLost processed 0 dexes")
    require(iso.get("final_used_cpu_permits") == 0, "final_used_cpu_permits leaked")
    require(iso.get("final_used_memory_bytes") == "0", "final_used_memory_bytes leaked")
    require(iso.get("queue_depth_bounded") is True and iso.get("history_bounded") is True, "isolation history/queue unbounded")


def validate_reuse_payload(
    payload: dict[str, Any],
    *,
    expect_dedup_multiplicity: bool = False,
    expected_reused_physical: int | None = None,
    expected_rebuilt_physical: int | None = None,
) -> None:
    require(payload.get("ok") is True, "content-reuse-suite failed")
    require(payload.get("physical_dedup_preserves_all_logical_sources") is True, "physical dedup dropped logical sources")
    report = payload["report"]
    accounting = report["accounting"]
    require(
        int(payload["dex_files_row_count"]) == accounting["total_logical_occurrences"],
        f"dex_files row count {payload['dex_files_row_count']} != total_logical_occurrences {accounting['total_logical_occurrences']}",
    )
    if expect_dedup_multiplicity:
        require(
            accounting["unique_physical_objects"] < accounting["total_logical_occurrences"],
            "expected duplicate physical blobs < total logical occurrences in duplicate fixture",
        )
    if expected_reused_physical is not None:
        require(
            accounting["reused_physical_objects"] == expected_reused_physical,
            f"expected reused_physical_objects={expected_reused_physical}, got {accounting['reused_physical_objects']}",
        )
    if expected_rebuilt_physical is not None:
        require(
            accounting["rebuilt_physical_objects"] == expected_rebuilt_physical,
            f"expected rebuilt_physical_objects={expected_rebuilt_physical}, got {accounting['rebuilt_physical_objects']}",
        )
    require(accounting.get("extrapolation_from_changed_bytes_forbidden") is True, "byte extrapolation flag missing")
    require(accounting.get("optional_dex041_prerequisite") is False, "optional_dex041_prerequisite must be false")
    require(report.get("fine_grained_method_incremental_enabled") is False, "fine-grained method incremental must be disabled")
    require(payload.get("shared_container_invalidation_verified") is True, "shared container invalidation probe failed")
    require(payload.get("shared_container_invalidation_reason") == "invalidated_shared_container", "unexpected container invalidation reason")

    neg_guard = payload.get("partial_negative_finding_guard", {})
    require(neg_guard.get("eligible") is False, "partial-layer negative finding must not be eligible")
    require(neg_guard.get("denial_code") == "INCOMPLETE_FACTS", f"unexpected negative guard code: {neg_guard.get('denial_code')}")

    gate = payload.get("fine_grained_incremental_gate", {})
    require(gate.get("capability_enabled") is False, "fine_grained capability_enabled must remain false")
    require(gate.get("runtime_gate_enabled") is False, "fine_grained runtime_gate_enabled must remain false")
    require(gate.get("optional_dex041_prerequisite") is False, "gate optional_dex041_prerequisite must be false")
    require(
        tuple(gate.get("missing_or_unproved_dimensions", [])) == REQUIRED_PROOF_DIMENSIONS,
        f"missing_or_unproved_dimensions mismatch: {gate.get('missing_or_unproved_dimensions')}",
    )


def build_report(scheduler_probe: Path, cache_probe: Path) -> dict[str, Any]:
    multidex_apk = ROOT / "tests/fixtures/generated/multidex-deflated.apk"
    dup_apk = ROOT / "conformance/generic-consumer/fixtures/public-app-audit.apk"
    dex_a = ROOT / "tests/fixtures/generated/structured-035.dex"
    dex_b = ROOT / "tests/fixtures/query/generated/unicode-order-038.dex"
    dex_c = ROOT / "tests/fixtures/generated/structured-035-same-size-changed.dex"
    for req_file in (multidex_apk, dup_apk, dex_a, dex_b, dex_c):
        require(req_file.is_file(), f"missing fixture: {req_file}")

    sched_res = run_json_command([str(scheduler_probe), str(multidex_apk)], "scheduler_reuse_probe")
    validate_scheduler_payload(sched_res)

    dup_res = run_json_command(
        [
            str(cache_probe),
            "content-reuse-suite",
            "--task-id",
            "mdd064-duplicate-multiplicity",
            "--baseline",
            str(dup_apk),
            "--target",
            str(dup_apk),
        ],
        "cache_probe(duplicate-multiplicity)",
    )
    validate_reuse_payload(dup_res, expect_dedup_multiplicity=True, expected_rebuilt_physical=0)

    cross_res = run_json_command(
        [
            str(cache_probe),
            "content-reuse-suite",
            "--task-id",
            "mdd064-cross-version-whole-content",
            "--baseline",
            str(dex_a),
            "--baseline",
            str(dex_b),
            "--target",
            str(dex_a),
            "--target",
            str(dex_b),
            "--target",
            str(dex_c),
        ],
        "cache_probe(cross-version)",
    )
    validate_reuse_payload(cross_res, expected_reused_physical=2, expected_rebuilt_physical=1)
    cross_acc = cross_res["report"]["accounting"]
    require(
        abs(float(cross_acc["changed_byte_ratio"]) - float(cross_acc["affected_workload_ratio"])) > 1e-4,
        "cross-version fixture should distinguish changed_byte_ratio from affected_workload_ratio",
    )

    return {
        "schema_version": "mdd.scheduling-and-reuse.v1",
        "task_id": "MDD-064",
        "source_sha256": {rel: sha256_file(ROOT / rel) for rel in SOURCES},
        "global_budget_and_scheduler": {
            "fixture": "tests/fixtures/generated/multidex-deflated.apk",
            "concurrency_levels": sched_res["concurrency_levels"],
            "isolation_and_bounds": sched_res["isolation"],
            "cross_stage_oversubscription_observed": any(
                bool(lvl["oversubscription_observed"]) for lvl in sched_res["concurrency_levels"]
            ),
        },
        "content_reuse_and_denominator_accounting": {
            "duplicate_multiplicity_apk": {
                "fixture": "conformance/generic-consumer/fixtures/public-app-audit.apk",
                "dex_files_row_count": dup_res["dex_files_row_count"],
                "physical_dedup_preserves_all_logical_sources": dup_res["physical_dedup_preserves_all_logical_sources"],
                "accounting": dup_res["report"]["accounting"],
                "occurrence_reuse_map": dup_res["report"]["occurrence_reuse_map"],
                "decisions": dup_res["report"]["decisions"],
            },
            "cross_version_whole_content": {
                "baseline_inputs": [
                    "tests/fixtures/generated/structured-035.dex",
                    "tests/fixtures/query/generated/unicode-order-038.dex",
                ],
                "target_inputs": [
                    "tests/fixtures/generated/structured-035.dex",
                    "tests/fixtures/query/generated/unicode-order-038.dex",
                    "tests/fixtures/generated/structured-035-same-size-changed.dex",
                ],
                "dex_files_row_count": cross_res["dex_files_row_count"],
                "physical_dedup_preserves_all_logical_sources": cross_res["physical_dedup_preserves_all_logical_sources"],
                "accounting": cross_acc,
                "decisions": cross_res["report"]["decisions"],
                "timing_ns_sample": cross_res["timing"],
            },
            "shared_container_invalidation_verified": cross_res["shared_container_invalidation_verified"],
            "shared_container_invalidation_reason": cross_res["shared_container_invalidation_reason"],
            "partial_negative_finding_guard": cross_res["partial_negative_finding_guard"],
        },
        "fine_grained_method_incremental_gate": cross_res["fine_grained_incremental_gate"],
        "acceptance_summary": {
            "unified_budget_prevents_oversubscription": True,
            "bounded_queues_and_isolated_failures": True,
            "whole_content_reuse_preserves_logical_multiplicity": True,
            "fine_grained_incremental_kept_disabled_without_proofs": (
                cross_res["fine_grained_incremental_gate"]["capability_enabled"] is False
            ),
            "workload_denominator_used_and_041_not_prerequisite": (
                cross_acc["extrapolation_from_changed_bytes_forbidden"] is True
                and cross_acc["optional_dex041_prerequisite"] is False
                and cross_res["fine_grained_incremental_gate"]["optional_dex041_prerequisite"] is False
            ),
        },
        "all_passed": True,
    }


def check_record(path: Path) -> int:
    require(path.is_file(), f"missing MDD-064 record: {path}")
    doc = json.loads(path.read_text(encoding="utf-8"))
    require(doc.get("schema_version") == "mdd.scheduling-and-reuse.v1", "schema_version mismatch")
    require(doc.get("task_id") == "MDD-064", "task_id mismatch")
    require(doc.get("all_passed") is True, "all_passed != true")

    hashes = doc.get("source_sha256", {})
    for rel in SOURCES:
        actual = sha256_file(ROOT / rel)
        require(hashes.get(rel) == actual, f"source hash drift: {rel}")

    sched = doc.get("global_budget_and_scheduler", {})
    require(sched.get("cross_stage_oversubscription_observed") is False, "oversubscription_observed != false")
    validate_scheduler_payload(
        {
            "ok": True,
            "concurrency_levels": sched.get("concurrency_levels", []),
            "isolation": sched.get("isolation_and_bounds", {}),
        }
    )

    reuse = doc.get("content_reuse_and_denominator_accounting", {})
    dup = reuse.get("duplicate_multiplicity_apk", {})
    require(dup.get("physical_dedup_preserves_all_logical_sources") is True, "dup logical multiplicity lost")
    require(
        int(dup.get("dex_files_row_count", -1)) == dup.get("accounting", {}).get("total_logical_occurrences"),
        "dup dex_files_row_count mismatch",
    )
    require(
        dup.get("accounting", {}).get("unique_physical_objects", 0)
        < dup.get("accounting", {}).get("total_logical_occurrences", 0),
        "dup unique_physical_objects >= total_logical_occurrences",
    )

    cross = reuse.get("cross_version_whole_content", {})
    cross_acc = cross.get("accounting", {})
    require(cross_acc.get("reused_physical_objects") == 2, "cross reused_physical_objects != 2")
    require(cross_acc.get("rebuilt_physical_objects") == 1, "cross rebuilt_physical_objects != 1")
    require(cross_acc.get("extrapolation_from_changed_bytes_forbidden") is True, "extrapolation flag must be true")
    require(cross_acc.get("optional_dex041_prerequisite") is False, "optional_dex041_prerequisite must be false")
    require(reuse.get("shared_container_invalidation_verified") is True, "shared container invalidation not verified")
    require(reuse.get("partial_negative_finding_guard", {}).get("eligible") is False, "negative finding guard must deny")

    gate = doc.get("fine_grained_method_incremental_gate", {})
    require(gate.get("capability_enabled") is False, "fine-grained capability must stay disabled")
    require(gate.get("runtime_gate_enabled") is False, "runtime gate must stay disabled")
    require(gate.get("optional_dex041_prerequisite") is False, "041 prerequisite must be false")
    require(
        tuple(gate.get("missing_or_unproved_dimensions", [])) == REQUIRED_PROOF_DIMENSIONS,
        "missing_or_unproved_dimensions mismatch",
    )

    acc_sum = doc.get("acceptance_summary", {})
    for key, val in acc_sum.items():
        require(val is True, f"acceptance_summary.{key} != true")

    print(f"MDD-064 check passed: 3 concurrency levels, whole-content reuse + gate verified ({len(SOURCES)} source hashes current)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scheduler-probe", type=Path, default=None)
    parser.add_argument("--cache-probe", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=RECORD)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    if args.check:
        target = args.out if args.out.is_absolute() else (ROOT / args.out)
        return check_record(target)

    sched_bin = ensure_example_binary("mdd-worker", "scheduler_reuse_probe", args.scheduler_probe, "release")
    cache_bin = ensure_example_binary("mdd-cache", "cache_probe", args.cache_probe, "release")
    report = build_report(sched_bin, cache_bin)

    out = args.out if args.out.is_absolute() else (ROOT / args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"MDD-064 conformance passed -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
