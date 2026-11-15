#!/usr/bin/env python3
"""Negative controls for the lifecycle, decode and manifest replays.

A replay that cannot fail proves nothing. Each control damages one thing the replay reads
(a recorded answer, a hand-written text, the independent renderer) and requires the replay
to report a difference. The damage is made in memory; no recorded file is touched.

Usage: python -I conformance/mcp/test_replays.py [--binary PATH]
"""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "decode"))
import lifecycle_replay  # noqa: E402
import manifest_replay  # noqa: E402
import oracle  # noqa: E402
import run_decode_conformance as decode_runner  # noqa: E402
from mcp_client import DEFAULT_BINARY  # noqa: E402

BINARY = DEFAULT_BINARY


def failed_names(result: dict) -> list[str]:
    return [c["name"] for c in result["checks"] if c["equal"] is False]


class LifecycleControls(unittest.TestCase):
    def damaged(self, change) -> list[str]:
        original = lifecycle_replay.load_records
        records = original()
        copied = copy.deepcopy(records)
        change(copied)
        lifecycle_replay.load_records = lambda: copied
        try:
            return failed_names(lifecycle_replay.run(BINARY))
        finally:
            lifecycle_replay.load_records = original

    def test_the_undamaged_replay_passes(self):
        self.assertEqual(failed_names(lifecycle_replay.run(BINARY)), [])

    def test_a_changed_quota_message_is_caught(self):
        def change(r):
            r[153]["message"]["result"]["structuredContent"]["error"]["message"] += " (damaged)"
        self.assertTrue(any("quota" in n for n in self.damaged(change)))

    def test_a_changed_recorded_decode_text_is_caught(self):
        def change(r):
            sc = r[44]["message"]["result"]["structuredContent"]
            sc["methods"][0]["smali"] = sc["methods"][0]["smali"].replace("return-void", "return-void ")
        self.assertTrue(any("decode" in n for n in self.damaged(change)))

    def test_a_changed_recorded_count_is_caught(self):
        def change(r):
            r[90]["message"]["result"]["structuredContent"]["statements"][0]["rows"][0][0]["value"] = "5"
        self.assertTrue(any("count" in n for n in self.damaged(change)))

    def test_a_recorded_cell_type_that_differs_is_caught(self):
        def change(r):
            r[90]["message"]["result"]["structuredContent"]["statements"][0]["rows"][0][0]["type"] = "int64"
        self.assertTrue(any("count" in n for n in self.damaged(change)))

    def test_a_recorded_timeout_wording_that_differs_is_caught(self):
        def change(r):
            r[176]["message"]["result"]["structuredContent"]["error"]["message"] = "damaged"
        self.assertTrue(any("deadline" in n for n in self.damaged(change)))

    def test_a_recorded_temp_error_that_differs_is_caught(self):
        def change(r):
            r[69]["message"]["result"]["structuredContent"]["error"]["message"] = "unknown relation `other`"
        self.assertTrue(any("TEMP step 68" in n for n in self.damaged(change)))

    def test_a_recorded_close_answer_that_differs_is_caught(self):
        def change(r):
            r[14]["message"]["result"]["structuredContent"]["closed"] = False
        self.assertTrue(any("close_dataset" in n for n in self.damaged(change)))


class DecodeControls(unittest.TestCase):
    def test_the_undamaged_run_passes(self):
        self.assertEqual(failed_names(decode_runner.run(BINARY)), [])

    def test_a_changed_hand_written_text_is_caught(self):
        original = decode_runner.read_hand

        def damaged():
            hand = original()
            key = "Ldecode/T;->op_71()V"
            hand[key] = hand[key].replace("{v1, v2, v3}", "{v1, v2}")
            return hand
        decode_runner.read_hand = damaged
        try:
            self.assertTrue(any("hand-written" in n for n in failed_names(decode_runner.run(BINARY))))
        finally:
            decode_runner.read_hand = original

    def test_a_different_independent_renderer_is_caught(self):
        original = oracle.render_all

        def damaged(data):
            return {k: v.replace("    nop\n", "    nop \n") for k, v in original(data).items()}
        oracle.render_all = damaged
        try:
            self.assertTrue(any("independent renderer" in n for n in failed_names(decode_runner.run(BINARY))))
        finally:
            oracle.render_all = original

    def test_a_renderer_that_loses_a_method_is_caught(self):
        original = oracle.facts_of

        def damaged(data):
            facts = original(data)
            first = next(iter(facts))
            facts[first] = dict(facts[first], registers=(facts[first]["registers"] or 0) + 1)
            return facts
        oracle.facts_of = damaged
        try:
            self.assertTrue(failed_names(decode_runner.run(BINARY)))
        finally:
            oracle.facts_of = original


class ManifestControls(unittest.TestCase):
    @unittest.skipUnless(manifest_replay.APK.exists(), "the public APK is an ignored local input")
    def test_a_changed_recorded_page_is_caught(self):
        original = manifest_replay.load_record
        pages, opened, closed = original()
        pages = copy.deepcopy(pages)
        pages[2]["permissions"][0]["attributes"]["android:name"] = "damaged"
        manifest_replay.load_record = lambda: (pages, opened, closed)
        try:
            result = manifest_replay.run(BINARY)
            self.assertTrue(any("page 2" in n for n in failed_names(result)))
        finally:
            manifest_replay.load_record = original

    @unittest.skipUnless(manifest_replay.APK.exists(), "the public APK is an ignored local input")
    def test_a_changed_recorded_application_attribute_is_caught(self):
        original = manifest_replay.load_record
        pages, opened, closed = original()
        pages = copy.deepcopy(pages)
        for page in pages:
            page["application"]["android:icon"] = "@7f100001"
        manifest_replay.load_record = lambda: (pages, opened, closed)
        try:
            self.assertTrue(failed_names(manifest_replay.run(BINARY)))
        finally:
            manifest_replay.load_record = original


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=1)
