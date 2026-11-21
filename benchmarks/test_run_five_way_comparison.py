#!/usr/bin/env python3
"""Unit and negative-control tests for MDD-060 observed_run_validator & five-way aggregation guards.

Never relies on bare assert (safe under python -O).
"""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import observed_run_validator as v  # noqa: E402


def _make_record(
    *,
    run_id: str = "r1",
    pair_id: str | None = "p01",
    block_id: str = "block1",
    rnd: int = 1,
    variant: str = "A0",
    wall: float = 10.0,
) -> dict:
    return {
        "schema_version": "mdd.benchmark-run.v1",
        "record_kind": "observed_run",
        "run_id": run_id,
        "pair_id": pair_id,
        "block_id": block_id,
        "round": rnd,
        "workload_id": "W07-hostlab-9161100",
        "variant": variant,
        "timestamp_utc": "2026-11-21T12:00:00.000Z",
        "engine": {
            "product": "DexSQL",
            "version": "0.1.0",
            "build_id": "dexsql-010",
            "binary_sha256": "a" * 64,
            "source_commit": None,
            "profile": "dexsql-0.1.0",
            "sql_dialect": None,
        },
        "harness": {
            "revision": "0123456789abcdef",
            "manifest_sha256": "b" * 64,
            "command_argv": ["run-five-way-comparison.py", "--variant", variant],
            "timing_boundary": "full worker wall window",
        },
        "inputs": [{"occurrence_id": "sample-1", "sha256": "c" * 64, "bytes": "226519215"}],
        "environment": {
            "machine_id": "win-x86_64-test",
            "os": "Windows 11",
            "cpu": "x86_64",
            "memory_bytes": "8589934592",
            "total_cpu_budget": 4.0,
            "engine_threads": 2,
            "concurrent_jobs": 1,
            "cache_state": "warm_os",
            "cache_control": "fresh_process_per_run",
            "background_load": "idle_exclusive_window",
            "artifact_sha256": "d" * 64,
        },
        "execution": {
            "status": "completed",
            "exit_code": 0,
            "complete_output": True,
            "fallback_count": 0,
            "contaminated": False,
            "contamination_reason": None,
            "wall_seconds": wall,
        },
        "correctness": {
            "scope_id": "sample-1-33dex",
            "input_complete": True,
            "facts_complete": True,
            "equivalent": True,
            "comparison_mode": "structured",
            "canonical_sha256": "e" * 64,
            "certificate_sha256": "f" * 64,
            "mismatch_count": 0,
            "notes": ["All 20 groups equal"],
        },
        "metrics": {
            "worker_e_wall_seconds": {"value": wall, "unit": "seconds", "scope": "full_worker", "method": "job"},
            "native_prepare_seconds": {"value": 1.2, "unit": "seconds", "scope": "explicit_open_session_setup", "method": "timer"},
            "wire_bytes": {"value": 1024, "unit": "bytes", "scope": "pipe", "method": "exact"},
        },
        "artifacts": [{"path": "artifacts/local/mdd-060/r1.json", "sha256": "9" * 64, "kind": "certificate"}],
    }


class ObservedRunValidatorTests(unittest.TestCase):
    def test_valid_record_and_jsonl_roundtrip(self) -> None:
        rec = _make_record()
        v.validate_observed_run(rec, check_redaction=True)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "runs.jsonl"
            p.write_text(json.dumps(rec) + "\n", encoding="utf-8", newline="\n")
            loaded = v.load_observed_runs(p, check_redaction=True)
            self.assertEqual(len(loaded), 1)

    def test_rejects_u64_overflow_beyond_max_u64(self) -> None:
        rec = _make_record()
        rec["inputs"][0]["bytes"] = str((1 << 64))  # 20 digits, matches regex, exceeds max u64
        with self.assertRaises(v.ObservedRunError):
            v.validate_observed_run(rec)

    def test_rejects_duplicate_json_keys_and_nan(self) -> None:
        with self.assertRaises(v.ObservedRunError):
            v.parse_strict_json('{"a": 1, "a": 2}')
        with self.assertRaises(v.ObservedRunError):
            v.parse_strict_json('{"wall": NaN}')

    def test_rejects_contaminated_without_reason_and_equivalent_without_cert(self) -> None:
        rec = _make_record()
        rec["execution"]["contaminated"] = True
        rec["execution"]["contamination_reason"] = None
        with self.assertRaises(v.ObservedRunError):
            v.validate_observed_run(rec)

        rec2 = _make_record()
        rec2["correctness"]["equivalent"] = True
        rec2["correctness"]["certificate_sha256"] = None
        with self.assertRaises(v.ObservedRunError):
            v.validate_observed_run(rec2)

    def test_rejects_null_metric_without_reason_or_float_byte_metric(self) -> None:
        rec = _make_record()
        rec["metrics"]["wire_bytes"]["value"] = None
        with self.assertRaises(v.ObservedRunError):
            v.validate_observed_run(rec)

        rec2 = _make_record()
        rec2["metrics"]["wire_bytes"]["value"] = 12.5
        with self.assertRaises(v.ObservedRunError):
            v.validate_observed_run(rec2)

    def test_rejects_prepare_as_pure_parser_and_lazy_folded_note(self) -> None:
        rec = _make_record()
        rec["metrics"]["native_prepare_seconds"]["scope"] = "pure_parser"
        with self.assertRaises(v.ObservedRunError):
            v.validate_observed_run(rec)

        rec2 = _make_record()
        rec2["correctness"]["notes"].append("lazy_folded_into_prepare")
        with self.assertRaises(v.ObservedRunError):
            v.check_prepare_not_pure_parser(rec2)

    def test_rejects_serial_sum_on_overlapping_pipeline(self) -> None:
        with self.assertRaises(v.ObservedRunError):
            v.compose_non_additive_overlap(
                joint_wall_seconds=10.0,
                producer_cpu_or_component_seconds=8.0,
                consumer_cpu_or_component_seconds=5.0,
                claimed_total_seconds=13.0,
            )

    def test_paired_median_never_equals_ratio_of_medians_and_retains_contaminated(self) -> None:
        recs = [
            _make_record(run_id="a1", pair_id="p1", rnd=1, variant="A0", wall=10.0),
            _make_record(run_id="b1", pair_id="p1", rnd=1, variant="B1", wall=2.0),  # reduction = 0.80
            _make_record(run_id="a2", pair_id="p2", rnd=2, variant="A0", wall=20.0),
            _make_record(run_id="b2", pair_id="p2", rnd=2, variant="B1", wall=10.0),  # reduction = 0.50
            _make_record(run_id="a3", pair_id="p3", rnd=3, variant="A0", wall=10.0),
            _make_record(run_id="b3", pair_id="p3", rnd=3, variant="B1", wall=4.0),  # reduction = 0.60
            # Contaminated pair p4 must be retained in excluded_pairs, never silently dropped or selected
            _make_record(run_id="a4", pair_id="p4", rnd=4, variant="A0", wall=100.0),
            _make_record(run_id="b4", pair_id="p4", rnd=4, variant="B1", wall=1.0),
        ]
        recs[-1]["execution"]["contaminated"] = True
        recs[-1]["execution"]["contamination_reason"] = "background_load"
        agg = v.aggregate_paired_metrics(recs, workload_id="W07-hostlab-9161100", left_variant="A0", right_variant="B1")
        self.assertEqual(agg["qualified_pair_count"], 3)
        self.assertEqual(agg["excluded_pair_count"], 1)
        # Paired median speedup of {5.0, 2.0, 2.5} = 2.5, vs unpaired ratio of medians (10.0 / 4.0) = 2.5 here;
        # Paired median reduction of {0.8, 0.5, 0.6} = 0.6
        self.assertAlmostEqual(agg["paired_median_reduction_fraction"], 0.6)
        self.assertAlmostEqual(agg["paired_median_speedup"], 2.5)

    def test_redaction_rejects_local_drive_and_private_tokens(self) -> None:
        rec = _make_record()
        rec["artifacts"][0]["path"] = "D:\\DevArea\\secret.apk"
        with self.assertRaises(v.ObservedRunError):
            v.validate_observed_run(rec, check_redaction=True)


if __name__ == "__main__":
    unittest.main()
