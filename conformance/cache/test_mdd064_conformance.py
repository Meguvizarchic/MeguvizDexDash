#!/usr/bin/env python3
"""Negative control and regression unit tests for MDD-064 scheduling & reuse conformance (`python -O` safe)."""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_mdd064_conformance as mod  # noqa: E402


class Mdd064ConformanceControls(unittest.TestCase):
    def _base_valid_doc(self) -> dict:
        if mod.RECORD.is_file():
            return json.loads(mod.RECORD.read_text(encoding="utf-8"))
        return {
            "schema_version": "mdd.scheduling-and-reuse.v1",
            "task_id": "MDD-064",
            "source_sha256": {rel: mod.sha256_file(mod.ROOT / rel) for rel in mod.SOURCES},
            "global_budget_and_scheduler": {
                "cross_stage_oversubscription_observed": False,
                "concurrency_levels": [
                    {
                        "concurrency": c,
                        "tasks_completed": c * 2,
                        "dex_units_processed": 4,
                        "oversubscription_observed": False,
                        "peak_cpu_permits": 2,
                        "ceiling_cpu_permits": 4,
                        "peak_memory_bytes": "1024",
                        "ceiling_memory_bytes": "4096",
                        "queue_depth_bounded": True,
                        "history_bounded": True,
                    }
                    for c in (1, 2, 4)
                ],
                "isolation_and_bounds": {
                    "overload_rejected_code": "QuotaExceeded",
                    "healthy_after_overload_dexes": 2,
                    "cancel_response_ms": 5.0,
                    "victim_worker_lost_count": 1,
                    "healthy_after_worker_lost_dexes": 2,
                    "final_used_cpu_permits": 0,
                    "final_used_memory_bytes": "0",
                    "queue_depth_bounded": True,
                    "history_bounded": True,
                },
            },
            "content_reuse_and_denominator_accounting": {
                "duplicate_multiplicity_apk": {
                    "dex_files_row_count": 5,
                    "physical_dedup_preserves_all_logical_sources": True,
                    "accounting": {
                        "total_logical_occurrences": 5,
                        "unique_physical_objects": 4,
                    },
                },
                "cross_version_whole_content": {
                    "accounting": {
                        "reused_physical_objects": 2,
                        "rebuilt_physical_objects": 1,
                        "extrapolation_from_changed_bytes_forbidden": True,
                        "optional_dex041_prerequisite": False,
                    }
                },
                "shared_container_invalidation_verified": True,
                "partial_negative_finding_guard": {"eligible": False, "denial_code": "INCOMPLETE_FACTS"},
            },
            "fine_grained_method_incremental_gate": {
                "capability_enabled": False,
                "runtime_gate_enabled": False,
                "optional_dex041_prerequisite": False,
                "missing_or_unproved_dimensions": list(mod.REQUIRED_PROOF_DIMENSIONS),
            },
            "acceptance_summary": {
                "unified_budget_prevents_oversubscription": True,
                "bounded_queues_and_isolated_failures": True,
                "whole_content_reuse_preserves_logical_multiplicity": True,
                "fine_grained_incremental_kept_disabled_without_proofs": True,
                "workload_denominator_used_and_041_not_prerequisite": True,
            },
            "all_passed": True,
        }

    def test_rejects_oversubscription_in_record(self) -> None:
        doc = self._base_valid_doc()
        tampered = copy.deepcopy(doc)
        tampered["global_budget_and_scheduler"]["concurrency_levels"][0]["oversubscription_observed"] = True
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "oversub.json"
            p.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.check_record(p)

    def test_rejects_unproved_fine_grained_enablement(self) -> None:
        doc = self._base_valid_doc()
        tampered = copy.deepcopy(doc)
        tampered["fine_grained_method_incremental_gate"]["capability_enabled"] = True
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "fine_enabled.json"
            p.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.check_record(p)

    def test_rejects_source_hash_drift(self) -> None:
        doc = self._base_valid_doc()
        tampered = copy.deepcopy(doc)
        tampered["source_sha256"][mod.SOURCES[0]] = "f" * 64
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "drift.json"
            p.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.check_record(p)

    def test_rejects_multiplicity_loss_or_negative_cache_leak(self) -> None:
        doc = self._base_valid_doc()
        tampered = copy.deepcopy(doc)
        tampered["content_reuse_and_denominator_accounting"]["duplicate_multiplicity_apk"]["dex_files_row_count"] = 4
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "mult_loss.json"
            p.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.check_record(p)


if __name__ == "__main__":
    unittest.main()
