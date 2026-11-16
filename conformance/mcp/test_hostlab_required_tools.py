#!/usr/bin/env python3
"""Controls for check_hostlab_required_tools.py: a damaged manifest must be caught.

Usage: python -I conformance/mcp/test_hostlab_required_tools.py
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check_hostlab_required_tools as checker  # noqa: E402
from mcp_client import DEFAULT_BINARY  # noqa: E402


def failures(manifest: dict) -> list[str]:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return [r["name"] for r in checker.run(DEFAULT_BINARY, path) if not r["ok"]]


class Fetch(unittest.TestCase):
    def test_paths(self):
        value = {"a": [{"b": 1}, {"b": 2}], "c": None}
        self.assertEqual(checker.fetch(value, "a[].b"), [1, 2])
        self.assertEqual(checker.fetch(value, "a[1].b"), [2])
        self.assertEqual(checker.fetch(value, "c"), [None])
        for missing in ("d", "a[].x", "c.y"):
            with self.assertRaises(KeyError):
                checker.fetch(value, missing)


class Damage(unittest.TestCase):
    base = json.loads(checker.MANIFEST.read_text(encoding="utf-8"))

    def damaged(self, change) -> list[str]:
        manifest = json.loads(json.dumps(self.base))
        change(manifest)
        return failures(manifest)

    def test_the_undamaged_manifest_passes(self):
        self.assertEqual(failures(self.base), [])

    def test_an_argument_the_schema_does_not_have_is_found(self):
        def change(m):
            m["calls"][3]["arguments"]["compact"] = True
        self.assertTrue(any("published schema" in name for name in self.damaged(change)))

    def test_a_field_the_answer_does_not_have_is_found(self):
        def change(m):
            m["calls"][3]["reads"].append("methods[0].no_such_field")
        self.assertTrue(any("no_such_field" in name for name in self.damaged(change)))

    def test_a_wrong_column_expectation_is_found(self):
        def change(m):
            m["calls"][2]["expect_columns"] = ["file_id", "name"]
        self.assertTrue(any("the columns are" in name for name in self.damaged(change)))

    def test_a_tool_the_server_lacks_is_found(self):
        def change(m):
            m["calls"][0]["tool"] = "find_refs"
        self.assertTrue(self.damaged(change))

    def test_a_listed_tool_that_must_stay_unregistered_is_found(self):
        def change(m):
            m["discovery"]["not_registered"].append("query")
        self.assertTrue(any("not listed" in name for name in self.damaged(change)))


if __name__ == "__main__":
    unittest.main(verbosity=1)
