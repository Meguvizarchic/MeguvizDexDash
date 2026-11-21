#!/usr/bin/env python3
"""Negative control tests for MDD-074 optional format & provider qualification."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_optional_conformance as mod  # noqa: E402


class OptionalFormatControls(unittest.TestCase):
    def test_rejects_premature_standard_release_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            doc = {
                "schema_version": "mdd.optional-format-qualification.v1",
                "task_id": "MDD-074",
                "standard_release_depends_on_mdd_074": True,
                "source_sha256": {p: mod.sha256_file(mod.ROOT / p) for p in mod.SOURCES},
                "special_containers_disabled": {k: {"passed": True} for k in ("cdex", "vdex", "oat")},
                "isolated_provider": {"passed": True},
                "all_passed": True,
            }
            p = Path(tmp) / "bad.json"
            p.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.check_record(p)

    def test_rejects_source_hash_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hashes = {p: mod.sha256_file(mod.ROOT / p) for p in mod.SOURCES}
            hashes[mod.SOURCES[0]] = "f" * 64
            doc = {
                "schema_version": "mdd.optional-format-qualification.v1",
                "task_id": "MDD-074",
                "standard_release_depends_on_mdd_074": False,
                "source_sha256": hashes,
                "special_containers_disabled": {k: {"passed": True} for k in ("cdex", "vdex", "oat")},
                "isolated_provider": {"passed": True},
                "all_passed": True,
            }
            p = Path(tmp) / "drift.json"
            p.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.check_record(p)


if __name__ == "__main__":
    unittest.main()
