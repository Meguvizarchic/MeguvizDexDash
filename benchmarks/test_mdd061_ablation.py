#!/usr/bin/env python3
"""Negative control and verifier unit tests for MDD-061 ablation & regression (`python -O` safe)."""
from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent
if str(BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(BENCH_DIR))

import run_mdd061_ablation as mod  # noqa: E402


def _dummy_agg(wid: str, blk: str | None, pairs: int, red: float) -> dict:
    return {
        "workload_id": wid,
        "block_filter": blk,
        "left_variant": "A1",
        "right_variant": "B1",
        "qualified_pair_count": pairs,
        "excluded_pair_count": 0,
        "excluded_pairs": [],
        "unpaired_runs": [],
        "paired_median_speedup": round(1.0 / max(1.0 - red, 0.05), 4),
        "paired_median_reduction_fraction": red,
        "paired_reduction_min": red,
        "paired_reduction_max": red,
        "left_median_wall_seconds": 10.0,
        "right_median_wall_seconds": round(10.0 * (1.0 - red), 4),
        "left_iqr_seconds": 0.1,
        "right_iqr_seconds": 0.1,
        "unpaired_median_ratio_for_reference_only": 1.0,
        "pairs": [],
    }


def _dummy_pair_docs() -> tuple[dict, dict]:
    hashes = {rel: mod.sha256_file(mod.ROOT / rel) for rel in mod.SOURCES}
    abl = {
        "schema_version": "mdd.optimization-ablation.v1",
        "task_id": "MDD-061",
        "source_sha256": hashes,
        "w05_newpipe_bulk_ablation": {
            "all_configs_identical_output": True,
            "configs": {name: {"trial_count": 5, "fallback_count": 0} for name, _, _ in mod.ABLATION_CONFIGS},
        },
        "w07_hostlab_9161100_ablation": {
            "all_configs_identical_20_groups": True,
            "configs": {name: {"trial_count": 2, "fallback_count": 0} for name, _, _ in mod.ABLATION_CONFIGS},
        },
        "non_additive_overlap_policy": {"additivity_forbidden": True},
        "unadopted_low_level_optimizations": mod.NON_ADOPTION_RATIONALE,
        "all_passed": True,
    }
    reg = {
        "schema_version": "mdd.end-to-end-regression.v1",
        "task_id": "MDD-061",
        "source_sha256": hashes,
        "key_workloads_vs_a1": {
            wid: {
                "block1": _dummy_agg(wid, "block1", 10, 0.18),
                "block2": _dummy_agg(wid, "block2", 2, 0.17),
                "combined": _dummy_agg(wid, None, 12, 0.18),
            }
            for wid in ("W05-newpipe-bulk", "W07-hostlab-9161100", "W07-hostlab-9170100")
        },
        "non_regression_guards_vs_a1": {
            wid: {
                **_dummy_agg(wid, None, 5, 0.02),
                "same_scope_metric": "warm_decode_seconds" if wid == "W06-newpipe-smali" else "resident_query_seconds",
            }
            for wid in (*mod.REQUIRED_NEWPIPE_GUARDS.keys(), "W06-newpipe-smali")
        },
        "all_passed": True,
    }
    return abl, reg


class Mdd061AblationControls(unittest.TestCase):
    def test_self_test_and_toggle_restoration(self) -> None:
        before = os.environ.get("MDD_OPT_QUERY_MEMO")
        with mod.env_overrides({"MDD_OPT_QUERY_MEMO": "0"}):
            self.assertEqual(os.environ.get("MDD_OPT_QUERY_MEMO"), "0")
        self.assertEqual(os.environ.get("MDD_OPT_QUERY_MEMO"), before)
        res = mod.self_test()
        self.assertEqual(res["self_test"], "passed")

    def test_check_rejects_regression_below_threshold_or_guard_violation(self) -> None:
        abl, reg = _dummy_pair_docs()
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            p_abl = t / "abl.json"
            p_reg = t / "reg.json"
            p_abl.write_text(json.dumps(abl), encoding="utf-8")
            p_reg.write_text(json.dumps(reg), encoding="utf-8")
            self.assertEqual(mod.check_outputs(p_abl, p_reg), 0)

            bad_w05 = copy.deepcopy(reg)
            bad_w05["key_workloads_vs_a1"]["W05-newpipe-bulk"]["block1"]["paired_median_reduction_fraction"] = 0.08
            p_reg.write_text(json.dumps(bad_w05), encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.check_outputs(p_abl, p_reg)

            bad_guard = copy.deepcopy(reg)
            bad_guard["non_regression_guards_vs_a1"]["W03-newpipe-xref"]["paired_median_reduction_fraction"] = -0.08
            p_reg.write_text(json.dumps(bad_guard), encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.check_outputs(p_abl, p_reg)

            bad_scope = copy.deepcopy(reg)
            bad_scope["non_regression_guards_vs_a1"]["W06-newpipe-smali"]["same_scope_metric"] = "wrong"
            p_reg.write_text(json.dumps(bad_scope), encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.check_outputs(p_abl, p_reg)

            bad_abl = copy.deepcopy(abl)
            bad_abl["w05_newpipe_bulk_ablation"]["all_configs_identical_output"] = False
            p_abl.write_text(json.dumps(bad_abl), encoding="utf-8")
            p_reg.write_text(json.dumps(reg), encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.check_outputs(p_abl, p_reg)


if __name__ == "__main__":
    unittest.main()
