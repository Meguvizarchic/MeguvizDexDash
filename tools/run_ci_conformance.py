#!/usr/bin/env python3
"""Unified conformance gate driver for MeguvizDexDash CI and local ucodex runs.

Replaces the long ungrouped command list in .github/workflows/ci.yml while keeping
every unique check intact and removing exact duplicate invocations already executed
inside unittest suites (e.g. test_remote_records.py and test_surface_goldens.py).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BINARY = ROOT / "target" / "debug" / ("meguvizdexdash.exe" if os.name == "nt" else "meguvizdexdash")


def build_groups(binary: str, out_dir: Path) -> dict[str, list[tuple[str, list[str]]]]:
    py = [sys.executable, "-I"]
    return {
        "cli": [
            ("cli-contract", [*py, "conformance/check-cli-contract.py", "--binary", binary]),
            ("cli-inspection", [*py, "conformance/check-inspection.py", "--binary", binary]),
            ("cli-cases", [*py, "conformance/cli/cli_cases.py", "--binary", binary]),
            ("b0-pipeline", [*py, "benchmarks/hostlab-b0-pipeline.py", "verify", "--binary", binary]),
        ],
        "mcp-decode": [
            ("decode-fixtures", [*py, "tests/fixtures/decode/generate.py", "--check"]),
            ("decode-class-fixtures", [*py, "tests/fixtures/decode/generate_class.py", "--check"]),
            ("mcp-golden-replay", [*py, "conformance/mcp/golden_replay.py", "--binary", binary]),
            ("mcp-lifecycle-replay", [*py, "conformance/mcp/lifecycle_replay.py", "--binary", binary]),
            ("mcp-manifest-replay", [*py, "conformance/mcp/manifest_replay.py", "--binary", binary]),
            ("decode-conformance", [*py, "conformance/decode/run_decode_conformance.py", "--binary", binary]),
            ("decode-a0-replay", [*py, "conformance/decode/a0_replay.py", "--binary", binary]),
            ("decode-a0-controls", [*py, "conformance/decode/test_a0_replay.py"]),
            ("decode-full-conformance", [*py, "conformance/decode/run_decode_full.py", "--binary", binary]),
            ("decode-full-contract", [*py, "conformance/decode/build_decode_contract.py", "--binary", binary, "--check"]),
            ("decode-full-controls", [*py, "conformance/decode/test_decode_full.py"]),
            ("mcp-hostlab-required-tools", [*py, "conformance/mcp/check_hostlab_required_tools.py", "--binary", binary]),
            ("mcp-hostlab-tools-controls", [*py, "conformance/mcp/test_hostlab_required_tools.py"]),
            ("mcp-replay-controls", [*py, "conformance/mcp/test_replays.py"]),
            ("mdd-042-record-and-anchors", [*py, "conformance/mcp/run_mcp_conformance.py", "--check"]),
            ("mdd-071-record-and-anchors", [*py, "conformance/decode/build_mdd071_record.py", "--check"]),
        ],
        "resources": [
            ("resources-fixtures", [*py, "tests/fixtures/resources/generate.py", "--check"]),
            ("resources-replay-controls", [*py, "conformance/mcp/test_resources_replay.py"]),
            ("resources-replay", [*py, "conformance/mcp/resources_replay.py", "--binary", binary, "--out", str(out_dir / "resources-replay.json")]),
            ("mdd-072-record-and-anchors", [*py, "artifacts/mdd-072/build_record.py", "--check"]),
        ],
        "hostlab": [
            ("hostlab-unittests", [*py, "-m", "unittest", "discover", "-s", "integrations/hostlab", "-p", "test_*.py"]),
            ("mdd-050-provider-selection", [*py, "integrations/hostlab/make_provider_selection.py", "--check"]),
            ("mdd-051-structural-equivalence", [*py, "integrations/hostlab/make_structural_equivalence.py", "--check"]),
            ("mdd-052-surface-equivalence", [*py, "integrations/hostlab/surface_make_equivalence.py", "--check"]),
        ],
        "relations": [
            ("or-chain-repro", [*py, "artifacts/mdd-084/repro_or_chain_overflow.py", "--binary", binary, "--phase", "post", "--out", str(out_dir / "mdd-084-repro-post.json")]),
            ("mdd-084-record-and-anchors", [*py, "artifacts/mdd-084/build_record.py", "--check"]),
            ("public-relations-fixtures", [*py, "tests/fixtures/public_relations/generate.py", "--check"]),
            ("public-relations-controls", [*py, "conformance/relations/test_public_relations_diff.py"]),
            ("public-relations-diff-0.1.0", [*py, "conformance/relations/public_relations_diff.py", "--binary", binary, "--dialect", "dexsql-0.1.0", "--out", str(out_dir / "public-relations-diff.json"), "--quiet"]),
            ("public-relations-diff-0.1.1", [*py, "conformance/relations/public_relations_diff.py", "--binary", binary, "--dialect", "dexsql-0.1.1", "--probe-dir", "artifacts/mdd-070/a1-probe", "--out", str(out_dir / "public-relations-diff-0.1.1.json"), "--quiet"]),
            ("public-relations-ref-versions", [*py, "conformance/relations/compare_references.py", "--check"]),
            ("public-relations-qualification", [*py, "conformance/relations/build_qualification.py", "--check"]),
            ("mdd-070-record-and-anchors", [*py, "artifacts/mdd-070/build_record.py", "--check"]),
            ("producer-consumer-pipeline-tests", [*py, "benchmarks/test_producer_consumer_pipeline.py"]),
        ],
        "generic-consumer": [
            ("generic-sample-fixture", [*py, "conformance/generic-consumer/make_public_sample.py", "--check"]),
            ("generic-consumer-controls", [*py, "conformance/generic-consumer/test_generic_consumer.py"]),
            ("generic-consumer-conformance", [*py, "conformance/generic-consumer/run_generic_consumer_conformance.py", "--binary", binary, "--out", str(out_dir / "consumer-portability.json")]),
            ("mdd-065-record", [*py, "conformance/generic-consumer/run_generic_consumer_conformance.py", "--check"]),
        ],
        "platform": [
            ("platform-controls", [*py, "conformance/platform/test_platform_qualification.py"]),
            ("platform-native-qualification", [*py, "conformance/platform/run_platform_qualification.py", "--binary", binary, "--out", str(out_dir / "platform-results.json")]),
            ("platform-matrix-check", [*py, "conformance/platform/verify_cross_platform.py", "--check"]),
        ],
        "cache": [
            ("cache-controls", [*py, "conformance/cache/test_cache_conformance.py"]),
            ("cache-conformance", [*py, "conformance/cache/run_cache_conformance.py", "--binary", binary, "--out", str(out_dir / "cache-fault-recovery.json")]),
            ("mdd-063-record", [*py, "conformance/cache/run_cache_conformance.py", "--check"]),
        ],
        "optional-formats": [
            ("optional-formats-controls", [*py, "conformance/optional_formats/test_optional_conformance.py"]),
            ("optional-formats-conformance", [*py, "conformance/optional_formats/run_optional_conformance.py", "--binary", binary, "--out", str(out_dir / "optional-format-qualification.json")]),
            ("mdd-074-record", [*py, "conformance/optional_formats/run_optional_conformance.py", "--check"]),
        ],
        "faults": [
            ("faults-controls", [*py, "conformance/faults/test_fault_suite.py"]),
            ("faults-conformance", [*py, "conformance/faults/run-fault-suite.py", "--binary", binary, "--out", str(out_dir / "fault-and-soak-results.json")]),
            ("mdd-081-record", [*py, "conformance/faults/run-fault-suite.py", "--check"]),
        ],
        "qualification": [
            ("mdd-060-controls", [*py, "-m", "unittest", "discover", "-s", "benchmarks", "-p", "test_run_five_way_comparison.py", "-t", "benchmarks"]),
            ("mdd-061-controls", [*py, "-m", "unittest", "discover", "-s", "benchmarks", "-p", "test_mdd061_ablation.py", "-t", "benchmarks"]),
            ("mdd-061-record", [*py, "benchmarks/run_mdd061_ablation.py", "--check"]),
            ("mdd-062-record", [*py, "integrations/hostlab/audit_data_provider.py", "--check"]),
            ("mdd-064-controls", [*py, "-m", "unittest", "discover", "-s", "conformance/cache", "-p", "test_mdd064_conformance.py", "-t", "conformance/cache"]),
            ("mdd-064-record", [*py, "conformance/cache/run_mdd064_conformance.py", "--check"]),
            ("mdd-066-record", [*py, "tools/verify_mdd066.py", "--check"]),
            ("mdd-082-record", [*py, "tools/verify_mdd082.py", "--check"]),
            ("mdd-083-record", [*py, "tools/verify_mdd083.py", "--check"]),
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--out-dir", type=Path, default=ROOT / "artifacts/local/ci")
    parser.add_argument("--group", default="all", help="all, or comma-separated group names: cli,mcp-decode,resources,hostlab,relations,generic-consumer,platform,cache,optional-formats,faults,qualification")
    args = parser.parse_args(argv)

    binary = args.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"binary not found: {binary}")
    out_dir = args.out_dir if args.out_dir.is_absolute() else (ROOT / args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    groups = build_groups(str(binary), out_dir)
    selected = list(groups) if args.group == "all" else [g.strip() for g in args.group.split(",") if g.strip()]
    unknown = [g for g in selected if g not in groups]
    if unknown:
        raise SystemExit(f"unknown group(s): {unknown}")

    total_started = time.monotonic()
    total_steps = 0
    for group_name in selected:
        steps = groups[group_name]
        print(f"==> [{group_name}] ({len(steps)} checks)", flush=True)
        for step_id, cmd in steps:
            total_steps += 1
            started = time.monotonic()
            done = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
            elapsed = time.monotonic() - started
            if done.returncode != 0:
                print(f"FAIL {group_name}/{step_id} ({elapsed:.2f}s, exit={done.returncode})", file=sys.stderr, flush=True)
                if done.stdout:
                    print("--- stdout ---\n" + done.stdout[-3000:], file=sys.stderr, flush=True)
                if done.stderr:
                    print("--- stderr ---\n" + done.stderr[-3000:], file=sys.stderr, flush=True)
                return done.returncode or 1
            print(f"  PASS {step_id} ({elapsed:.2f}s)", flush=True)

    print(f"All {total_steps} conformance checks passed in {time.monotonic() - total_started:.2f}s", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
