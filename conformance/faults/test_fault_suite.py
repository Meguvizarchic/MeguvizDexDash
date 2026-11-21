#!/usr/bin/env python3
"""Negative control tests ensuring MDD-081 fault & soak record validator cannot pass tampered records."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SUITE_PATH = Path(__file__).resolve().parent / "run-fault-suite.py"
SPEC = importlib.util.spec_from_file_location("run_fault_suite", SUITE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"failed loading {SUITE_PATH}")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class FaultSuiteControls(unittest.TestCase):
    def _base_valid_doc(self) -> dict:
        matrix = json.loads(MOD.MATRIX.read_text(encoding="utf-8"))
        scenarios = {s["id"]: {"passed": True} for s in matrix["scenarios"]}
        scenarios["multi_worker_crash_isolation"].update({"worker1_affected_requests": 3, "claims_single_query_loss": False})
        scenarios["soak_resource_bounds"].update({"live_ffi_handles_delta": 0, "leaked_child_processes": 0, "leftover_temp_files": 0})
        return {
            "schema_version": "mdd.fault-and-soak-results.v1",
            "task_id": "MDD-081",
            "source_sha256": {p: MOD.sha256_file(MOD.ROOT / p) for p in MOD.SOURCES},
            "scenarios": scenarios,
            "all_passed": True,
        }

    def test_rejects_single_query_crash_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            doc = self._base_valid_doc()
            doc["scenarios"]["multi_worker_crash_isolation"]["claims_single_query_loss"] = True
            p = Path(tmp) / "bad_claim.json"
            p.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(ValueError):
                MOD.check_record(p)

    def test_rejects_handle_leak(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            doc = self._base_valid_doc()
            doc["scenarios"]["soak_resource_bounds"]["live_ffi_handles_delta"] = 1
            p = Path(tmp) / "leak.json"
            p.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(ValueError):
                MOD.check_record(p)


if __name__ == "__main__":
    unittest.main()
