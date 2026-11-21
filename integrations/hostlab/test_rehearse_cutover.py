"""Tests for MDD-055 enablement example config and live HostLab cutover/rollback rehearsal."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import hostlab_test_support as support  # noqa: E402
import native_session as ns  # noqa: E402
import provider  # noqa: E402
import rehearse_cutover  # noqa: E402


class EnablementExampleTests(unittest.TestCase):
    def test_example_configs_parse_and_match_schema(self):
        doc = json.loads((HERE / "enablement-config.example.json").read_text(encoding="utf-8"))
        schema = json.loads((HERE / "config-schema.json").read_text(encoding="utf-8"))
        self.assertFalse(doc["default_production_cutover"])

        self.assertTrue(support.schema_valid(schema, doc["provider_config"]))
        parsed_on = provider.parse_config(doc["provider_config"])
        self.assertEqual(parsed_on.native_engine, "meguvizdexdash")
        self.assertEqual(parsed_on.engine.dialect, "dexsql-0.1.0")
        self.assertEqual(parsed_on.engine.fallback.to, "none")

        self.assertTrue(support.schema_valid(schema, doc["rollback_provider_config"]))
        parsed_off = provider.parse_config(doc["rollback_provider_config"])
        self.assertEqual(parsed_off.native_engine, "dexsql")

        structural = ns.parse_structural_config(doc["structural_config"])
        self.assertEqual(structural.wire, "b0")
        self.assertEqual(structural.non_scalar_text, "lossy-replacement")
        self.assertGreater(structural.limits()["steps"], 0)


class CutoverRehearsalTests(unittest.TestCase):
    def test_live_cutover_and_rollback_rehearsal_passes(self):
        record = rehearse_cutover.rehearse()
        self.assertFalse(record["performance_replacement_qualified"])
        self.assertFalse(record["default_production_cutover"])
        self.assertEqual(record["stage_1_baseline"]["native_engine"], "dexsql")
        self.assertTrue(record["stage_1_baseline"]["forced_mdd_rejected_when_off"])
        self.assertEqual(record["stage_2_cutover"]["reconstructed_provenance"]["fallback_count"], 0)
        self.assertTrue(record["stage_2_cutover"]["session"]["completeness_verdict"]["complete"])
        self.assertEqual(record["stage_2_cutover"]["session"]["abandoned"], 0)
        self.assertIsNone(record["stage_2_cutover"]["session"]["next_cursor"])
        self.assertTrue(record["stage_2_cutover"]["legacy_tree_unchanged"])
        self.assertTrue(record["stage_3_rollback"]["matches_baseline_plan"])
        self.assertTrue(record["stage_3_rollback"]["cross_engine_checkpoint_refused"])
        self.assertTrue(record["stage_3_rollback"]["delegated_to_legacy_session"])
        self.assertTrue(record["stage_3_rollback"]["legacy_tree_unchanged_after_rollback"])


if __name__ == "__main__":
    unittest.main()
