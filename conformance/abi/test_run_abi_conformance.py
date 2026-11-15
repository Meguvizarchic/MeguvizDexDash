#!/usr/bin/env python3
"""Negative controls for conformance/abi/run_abi_conformance.py.

Run: python -I conformance/abi/test_run_abi_conformance.py

The runner turns test output into verdicts. These cases feed it outcomes it must not
call proven: a missing test, an ambiguous name, a failed or skipped test, an open
clause that disappeared. unittest assertions are used because `-O` does not remove them.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("runner", HERE / "run_abi_conformance.py")
runner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runner
spec.loader.exec_module(runner)


def everything(outcome="ok"):
    results, extra = {}, {}
    for _, names in runner.ACCEPTANCE:
        for name in names:
            if name.startswith(("ownership-cases", "workspace-boundaries")):
                extra[name] = outcome
            else:
                results[name] = [outcome]
    return results, extra


class Parsing(unittest.TestCase):
    def test_rust_lines_are_collected_per_name(self):
        text = "test a::b ... ok\ntest c ... FAILED\nnoise\n"
        self.assertEqual(runner.rust_results(text), {"a::b": ["ok"], "c": ["FAILED"]})

    def test_python_verbose_lines_are_collected(self):
        text = "test_x (tests.test_sdk.Basics.test_x) ... ok\ntest_y (tests.test_sdk.Rows.test_y) ... FAIL\n"
        self.assertEqual(runner.python_results(text), {"test_x": ["ok"], "test_y": ["FAIL"]})

    def test_a_skipped_python_test_is_recorded_as_skipped(self):
        text = "test_z (tests.test_sdk.Rows.test_z) ... skipped 'no library'\n"
        self.assertEqual(runner.python_results(text), {"test_z": ["skipped"]})


class Lookup(unittest.TestCase):
    def test_unique_is_found(self):
        self.assertEqual(runner.lookup({"m::t": ["ok"]}, "t"), ("m::t", "ok"))

    def test_missing_is_not_run(self):
        self.assertEqual(runner.lookup({}, "t")[1], "not_run")

    def test_same_name_twice_is_ambiguous(self):
        self.assertEqual(runner.lookup({"a::t": ["ok"], "b::t": ["ok"]}, "t")[1], "ambiguous(2)")
        self.assertEqual(runner.lookup({"t": ["ok", "ok"]}, "t")[1], "ambiguous(2)")


class Acceptance(unittest.TestCase):
    def test_all_ok_proves_every_row(self):
        results, extra = everything()
        self.assertTrue(all(r["all_passed"] for r in runner.acceptance_rows(results, extra)))

    def test_one_failed_test_unproves_only_its_row(self):
        results, extra = everything()
        results["double_release_is_a_detected_error_for_every_handle_kind"] = ["FAILED"]
        rows = runner.acceptance_rows(results, extra)
        self.assertEqual([r["all_passed"] for r in rows].count(False), 1)

    def test_a_skipped_test_is_not_proof(self):
        results, extra = everything("skipped")
        self.assertFalse(any(r["all_passed"] for r in runner.acceptance_rows(results, extra)))

    def test_failed_ownership_cases_or_boundaries_unprove_their_rows(self):
        results, extra = everything()
        for key in extra:
            extra[key] = "failed"
        rows = runner.acceptance_rows(results, extra)
        self.assertFalse(rows[1]["all_passed"])
        self.assertFalse(rows[4]["all_passed"])

    def test_the_worker_lost_clause_stays_declared_open(self):
        self.assertTrue(any(c["case"] == "worker lost" and c["status"] == "open" for c in runner.OPEN_CLAUSES))


class Currency(unittest.TestCase):
    def test_the_hash_covers_sources_as_well_as_tests(self):
        covered = set(runner.MUTATION_SOURCES)
        self.assertIn("crates/mdd-ffi/src/engine.rs", covered)
        self.assertIn("python/mdd/core.py", covered)
        self.assertIn("python/tests/test_sdk.py", covered)
        self.assertIn("include/mdd.h", covered)

    def test_every_covered_source_exists(self):
        for relative in runner.MUTATION_SOURCES:
            self.assertTrue((runner.ROOT / relative).is_file(), relative)


if __name__ == "__main__":
    unittest.main(verbosity=1)
