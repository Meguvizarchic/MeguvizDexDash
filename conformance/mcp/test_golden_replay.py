#!/usr/bin/env python3
"""Negative controls for the A0 replay.

A comparison that accepts a damaged recording proves nothing. Each test damages one
recorded page in a single way and requires `first_difference` to object, then checks
the cell canonicalisation against the recorded forms and the refusal comparison.

Usage: python -I conformance/mcp/test_golden_replay.py
"""
from __future__ import annotations

import copy
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import golden_replay as gr  # noqa: E402

GOLDEN = json.loads((gr.ROOT / gr.GOLDEN).read_text(encoding="utf-8"))
SPEC = json.loads((gr.ROOT / gr.VARIANTS).read_text(encoding="utf-8"))


def case(name: str) -> dict:
    return next(c for c in GOLDEN["cases"] if f"{c['family']}/{c['variant']}" == name)


def multi_row_case() -> dict:
    return next(c for c in GOLDEN["cases"]
                if any(len(s["rows"]) >= 2 and len(s["rows"][0]) >= 2 for s in c["pages"][0].get("statements", [])))


class Comparison(unittest.TestCase):
    def test_a_page_equals_itself(self):
        for c in GOLDEN["cases"]:
            self.assertIsNone(gr.first_difference(c["pages"], c["pages"]), c["variant"])

    def damaged(self, change):
        c = copy.deepcopy(multi_row_case())
        change(c["pages"][0]["statements"][0])
        original = multi_row_case()
        return gr.first_difference(c["pages"], original["pages"])

    def first_statement_with_rows(self):
        return next(s for s in multi_row_case()["pages"][0]["statements"] if len(s["rows"]) >= 2)

    def test_a_changed_cell_is_caught(self):
        index = multi_row_case()["pages"][0]["statements"].index(self.first_statement_with_rows())
        c = copy.deepcopy(multi_row_case())
        c["pages"][0]["statements"][index]["rows"][1][0] = "t:00"
        self.assertIsNotNone(gr.first_difference(c["pages"], multi_row_case()["pages"]))

    def test_a_dropped_row_is_caught(self):
        index = multi_row_case()["pages"][0]["statements"].index(self.first_statement_with_rows())
        c = copy.deepcopy(multi_row_case())
        c["pages"][0]["statements"][index]["rows"].pop()
        self.assertIsNotNone(gr.first_difference(c["pages"], multi_row_case()["pages"]))

    def test_a_swapped_row_order_is_caught(self):
        index = multi_row_case()["pages"][0]["statements"].index(self.first_statement_with_rows())
        c = copy.deepcopy(multi_row_case())
        rows = c["pages"][0]["statements"][index]["rows"]
        if rows[0] == rows[1]:
            self.skipTest("the first two rows are equal")
        rows[0], rows[1] = rows[1], rows[0]
        self.assertIsNotNone(gr.first_difference(c["pages"], multi_row_case()["pages"]))

    def test_each_window_field_is_compared(self):
        for key, value in (("offset", 12345), ("next_offset", 12345), ("truncated", "maybe"), ("total_rows", 12345), ("columns", ["x"])):
            self.assertIsNotNone(self.damaged(lambda s, k=key, v=value: s.__setitem__(k, v)), key)

    def test_a_missing_page_and_a_refused_page_are_caught(self):
        walk = next(c for c in GOLDEN["cases"] if c["walk"] and len(c["pages"]) > 2)
        self.assertIsNotNone(gr.first_difference(walk["pages"][:-1], walk["pages"]))
        refused = [{"refused": "tool", "statement_index": 0, "error": {}}] + walk["pages"][1:]
        self.assertIsNotNone(gr.first_difference(refused, walk["pages"]))


class Canonical(unittest.TestCase):
    def test_the_recorded_forms(self):
        self.assertEqual(gr.canonical({"type": "null", "value": None}), "N")
        self.assertEqual(gr.canonical({"type": "uint64", "value": "18446744073709551615"}), "i:18446744073709551615")
        self.assertEqual(gr.canonical({"type": "int64", "value": "-5"}), "i:-5")
        self.assertEqual(gr.canonical({"type": "utf8", "value": "é"}), "t:c3a9")
        self.assertEqual(gr.canonical({"type": "binary", "value": "00AB"}), "b:00ab")
        self.assertEqual(gr.canonical({"type": "float64", "value": 1.5}), "f:" + struct.pack(">d", 1.5).hex())
        self.assertEqual(gr.canonical({"type": "float64", "value": "NaN"}), "f:nan")
        with self.assertRaises(ValueError):
            gr.canonical({"type": "mystery", "value": 1})

    def test_the_replay_covers_the_whole_recording(self):
        self.assertEqual(len(GOLDEN["cases"]), len(SPEC["variants"]))
        self.assertGreaterEqual(len(GOLDEN["cases"]), 76)
        self.assertEqual(len(GOLDEN["rejections"]), len(SPEC["rejections"]))


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], "-v"])
