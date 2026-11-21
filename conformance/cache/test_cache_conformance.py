#!/usr/bin/env python3
"""Negative control self-tests ensuring MDD-063 cache verifier rejects tampered records and inputs."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_cache_conformance as mod  # noqa: E402


class CacheConformanceControls(unittest.TestCase):
    def test_rejects_failed_case_in_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            doc = {
                "schema_version": "mdd.cache-fault-recovery.v1",
                "task_id": "MDD-063",
                "source_sha256": {p: mod.sha256_file(mod.ROOT / p) for p in mod.SOURCES},
                "cases": {"cold_warm_bypass_equivalence_standalone": {"passed": False}},
                "all_passed": False,
            }
            p = Path(tmp) / "bad.json"
            p.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.check_record(p)

    def test_rejects_source_hash_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            matrix = json.loads(mod.MATRIX.read_text(encoding="utf-8"))
            hashes = {p: mod.sha256_file(mod.ROOT / p) for p in mod.SOURCES}
            hashes[mod.SOURCES[0]] = "0" * 64
            doc = {
                "schema_version": "mdd.cache-fault-recovery.v1",
                "task_id": "MDD-063",
                "source_sha256": hashes,
                "cases": {c["id"]: {"passed": True} for c in matrix["cases"]},
                "all_passed": True,
            }
            p = Path(tmp) / "drift.json"
            p.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.check_record(p)


if __name__ == "__main__":
    unittest.main()
