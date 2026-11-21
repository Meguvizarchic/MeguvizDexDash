#!/usr/bin/env python3
"""Negative control tests for MDD-080 cross-platform qualification logic.

Usage:
    python -I conformance/platform/test_platform_qualification.py
"""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import verify_cross_platform as vcp  # noqa: E402


def _sample_result(plat_id: str, os_name: str, overall_hash: str) -> dict:
    return {
        "schema": "mdd.platform-results.v1",
        "platform_id": plat_id,
        "os": os_name,
        "arch": "x86_64",
        "executed_natively": True,
        "cross_compiled": False,
        "performance_replacement_qualified": False,
        "surfaces": {
            "cli": {"passed": True},
            "mcp": {"passed": True},
            "python_sdk": {"passed": True},
            "desktop_preview": {"passed": True},
        },
        "lifecycle_edge_probes": {
            "unicode_paths": {"passed": True},
            "source_replace_and_delete": {"passed": True},
            "worker_crash_cleanup": {"passed": True},
            "pipe_close_handling": {"passed": True},
            "c_abi_buffer_and_handle_lifecycle": {
                "passed": True,
                "live_handles_delta": 0,
                "retained_batch_outlived_parents": True,
            },
            "multi_session_isolation": {"passed": True},
        },
        "canonical_workloads": {
            "public_apk_facts_digest": {"canonical_sha256": "aaa"},
            "decode_smali_and_context_digest": {"canonical_sha256": "bbb"},
            "resources_and_manifest_digest": {"canonical_sha256": "ccc"},
            "mutf8_and_scalar_cells_digest": {"canonical_sha256": "ddd"},
            "c_abi_batch_codec_digest": {"canonical_sha256": "eee"},
        },
        "overall_canonical_sha256": overall_hash,
        "overall_passed": True,
    }


class CrossPlatformNegativeControls(unittest.TestCase):
    def setUp(self) -> None:
        self.matrix = json.loads(vcp.MATRIX_PATH.read_text(encoding="utf-8"))

    def test_valid_pair_passes(self) -> None:
        win = _sample_result("windows-x86_64", "windows", "deadbeef")
        lin = _sample_result("linux-x86_64", "linux", "deadbeef")
        # Compare ignoring disk sha256 file check in validate helper
        vcp.validate_matrix(self.matrix)
        vcp.validate_platform_result(win, "windows-x86_64", "windows", self.matrix)
        vcp.validate_platform_result(lin, "linux-x86_64", "linux", self.matrix)

    def test_rejects_cross_compiled_stand_in(self) -> None:
        lin = _sample_result("linux-x86_64", "linux", "deadbeef")
        lin["cross_compiled"] = True
        with self.assertRaises(ValueError):
            vcp.validate_platform_result(lin, "linux-x86_64", "linux", self.matrix)

    def test_rejects_canonical_hash_divergence(self) -> None:
        win = _sample_result("windows-x86_64", "windows", "deadbeef")
        lin = _sample_result("linux-x86_64", "linux", "cafebabe")
        with self.assertRaises(ValueError):
            vcp.build_compatibility_report(self.matrix, win, lin)

    def test_rejects_advertised_macos_arm64(self) -> None:
        bad = copy.deepcopy(self.matrix)
        bad["unadmitted_platforms"][0]["advertised"] = True
        with self.assertRaises(ValueError):
            vcp.validate_matrix(bad)

    def test_rejects_handle_leak_or_failed_probe(self) -> None:
        win = _sample_result("windows-x86_64", "windows", "deadbeef")
        win["lifecycle_edge_probes"]["c_abi_buffer_and_handle_lifecycle"]["live_handles_delta"] = 1
        with self.assertRaises(ValueError):
            vcp.validate_platform_result(win, "windows-x86_64", "windows", self.matrix)


if __name__ == "__main__":
    unittest.main(verbosity=1)
