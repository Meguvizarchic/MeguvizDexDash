#!/usr/bin/env python3
"""Negative controls for conformance/analysis/oracle.py.

Run: python -I conformance/analysis/test_oracle.py

An oracle that always agrees proves nothing. Each case below damages one hand-written
expectation in a copy of the fixture file and requires the oracle to disagree. The
untouched file must agree. unittest assertions are used because `-O` does not remove them.
"""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = HERE / "soundness-cases.json"


def run_oracle(document: dict) -> int:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "cases.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        done = subprocess.run([sys.executable, "-I", str(HERE / "oracle.py"), "--cases", str(path)],
                              capture_output=True, text=True, check=False)
    return done.returncode


def case(document: dict, name: str) -> dict:
    return next(c for c in document["cases"] if c["name"] == name)


class Oracle(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(CASES.read_text(encoding="utf-8"))

    def damaged(self, name: str, change) -> int:
        document = copy.deepcopy(self.document)
        change(case(document, name)["expect"])
        return run_oracle(document)

    def test_the_untouched_file_agrees(self):
        self.assertEqual(run_oracle(self.document), 0)

    def test_a_wrong_certainty_is_caught(self):
        def flip(expect):
            expect["edges"][0][3] = "possible" if expect["edges"][0][3] == "definite" else "definite"
        self.assertEqual(self.damaged("diamond", flip), 1)

    def test_a_missing_edge_is_caught(self):
        self.assertEqual(self.damaged("loop", lambda e: e["edges"].pop()), 1)

    def test_an_invented_edge_is_caught(self):
        self.assertEqual(self.damaged("loop", lambda e: e["edges"].append(["done", "head", "branch", "definite"])), 1)

    def test_a_wrong_reaching_definition_is_caught(self):
        def change(expect):
            for use in expect["uses"]:
                if use[0] == "join":
                    use[2] = ["l:v1"]
        self.assertEqual(self.damaged("diamond", change), 1)

    def test_a_dropped_undefined_flag_is_caught(self):
        def change(expect):
            for use in expect["uses"]:
                use[3] = False
        self.assertEqual(self.damaged("maybe-undefined-use", change), 1)

    def test_a_missing_unreachable_block_is_caught(self):
        self.assertEqual(self.damaged("unreachable-code-after-return", lambda e: e["unreachable"].clear()), 1)

    def test_a_dropped_issue_is_caught(self):
        self.assertEqual(self.damaged("fallthrough-past-the-end", lambda e: e["issues"].clear()), 1)

    def test_a_wrong_switch_key_is_caught(self):
        def change(expect):
            for edge in expect["edges"]:
                if edge[2] == "switch:1":
                    edge[2] = "switch:2"
        self.assertEqual(self.damaged("packed-switch", change), 1)

    def test_a_handler_that_sees_the_throwing_definition_is_caught(self):
        def change(expect):
            for use in expect["uses"]:
                if use[0] == "hu":
                    use[2] = ["e:v1", "ts:v1"]
        self.assertEqual(self.damaged("handler-sees-the-state-before-the-throw", change), 1)


if __name__ == "__main__":
    unittest.main(verbosity=1)
