#!/usr/bin/env python3
"""Negative controls for conformance/run-required-query-suite.py.

Run: python -I conformance/test_run_required_query_suite.py

The runner turns cargo output into verdicts. These cases feed it outcomes it must
refuse to call proven: a missing test, an ambiguous name, a failed test, a family
without corpus. unittest assertions are used because `-O` does not remove them.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("runner", HERE / "run-required-query-suite.py")
runner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runner
spec.loader.exec_module(runner)


def every_named_test(outcome="ok"):
    return {f"some::module::{name}": [outcome] for _, names in runner.ACCEPTANCE for name in names}


class Lookup(unittest.TestCase):
    def test_unique_name_is_found(self):
        self.assertEqual(runner.lookup({"a::b::t": ["ok"]}, "t"), ("a::b::t", "ok"))

    def test_missing_test_is_not_run(self):
        self.assertEqual(runner.lookup({"a::b::t": ["ok"]}, "other")[1], "not_run")

    def test_same_name_in_two_modules_is_ambiguous(self):
        results = {"a::t": ["ok"], "b::t": ["ok"]}
        self.assertEqual(runner.lookup(results, "t")[1], "ambiguous(2)")

    def test_same_name_in_two_binaries_is_ambiguous(self):
        self.assertEqual(runner.lookup({"t": ["ok", "ok"]}, "t")[1], "ambiguous(2)")

    def test_a_suffix_inside_a_longer_name_is_not_a_match(self):
        self.assertEqual(runner.lookup({"a::not_t": ["ok"]}, "t")[1], "not_run")


class Acceptance(unittest.TestCase):
    def test_all_ok_proves_every_row(self):
        rows = runner.acceptance_rows(every_named_test())
        self.assertTrue(rows and all(row["all_passed"] for row in rows))

    def test_one_failed_test_unproves_its_row_only(self):
        results = every_named_test()
        victim = next(name for name in results if name.endswith("blocking_warning_cannot_be_a_complete_result"))
        results[victim] = ["FAILED"]
        rows = runner.acceptance_rows(results)
        self.assertEqual([row["all_passed"] for row in rows].count(False), 1)

    def test_a_missing_test_unproves_the_row(self):
        results = every_named_test()
        results = {name: v for name, v in results.items() if not name.endswith("full_scan_projection_agrees_on_all_paths")}
        self.assertTrue(any(not row["all_passed"] for row in runner.acceptance_rows(results)))

    def test_an_ignored_test_is_not_proof(self):
        results = every_named_test("ignored")
        self.assertTrue(all(not row["all_passed"] for row in runner.acceptance_rows(results)))


class Divergences(unittest.TestCase):
    def test_empty_declaration_means_none(self):
        source = "const GOLDEN_DIVERGENCES: &[(&str, &str)] = &[];"
        self.assertEqual(runner.parse_divergences(source), {})

    def test_declared_entries_are_grouped_by_family(self):
        source = 'const GOLDEN_DIVERGENCES: &[(&str, &str)] = &[("Q13/shape", "why"), ("Q13/other", "x"), ("Q04/a", "y")];'
        self.assertEqual(runner.parse_divergences(source), {"Q13": ["Q13/shape", "Q13/other"], "Q04": ["Q04/a"]})

    def test_a_missing_declaration_is_refused(self):
        with self.assertRaises(SystemExit):
            runner.parse_divergences("fn nothing() {}")


class Divergences2(unittest.TestCase):
    def test_reason_text_that_looks_like_a_tuple_is_not_a_key(self):
        source = 'const GOLDEN_DIVERGENCES: &[(&str, &str)] = &[("Q13/shape", "see (\"x\", y)")];'
        self.assertEqual(runner.parse_divergences(source), {"Q13": ["Q13/shape"]})


class Mutation(unittest.TestCase):
    def test_record_for_other_tests_is_stale(self):
        self.assertFalse(runner.mutation_is_current(["tests sha256: aaa"], "bbb"))

    def test_record_without_a_hash_is_stale(self):
        self.assertFalse(runner.mutation_is_current(["KILLED x"], "bbb"))

    def test_matching_record_is_current(self):
        self.assertTrue(runner.mutation_is_current(["KILLED x", "tests sha256: bbb"], "bbb"))


class Profiles(unittest.TestCase):
    def families(self, verdict="equal_to_a0", drop=()):
        names = [f"Q{n:02d}" for n in range(1, 16)]
        return {name: {"verdict": verdict, "variants": 1} for name in names if name not in drop}

    def test_full_evidence_passes_the_audit_profile(self):
        audit = next(p for p in runner.profile_records(self.families()) if p["id"] == "hostlab-audit-v1")
        self.assertEqual((audit["query_layer"], audit["families_without_full_evidence"]), ("passed", []))

    def test_a_family_without_corpus_leaves_the_profile_partial(self):
        records = runner.profile_records(self.families(drop=("Q16",)))
        compat = next(p for p in records if p["id"] == "dexsql-0.1.1-compat-v1")
        self.assertEqual(compat["query_layer"], "partial")
        self.assertEqual(compat["families"]["Q16"]["verdict"], "no_labelled_corpus")

    def test_a_declared_divergence_is_not_full_evidence(self):
        families = self.families()
        families["Q05"]["verdict"] = "equal_to_a0_except_declared_divergences"
        audit = next(p for p in runner.profile_records(families) if p["id"] == "hostlab-audit-v1")
        self.assertEqual(audit["query_layer"], "partial")

    def test_unproven_families_never_pass(self):
        audit = next(p for p in runner.profile_records(self.families("not_proven")) if p["id"] == "hostlab-audit-v1")
        self.assertEqual(audit["query_layer"], "partial")

    def test_no_profile_is_admitted_by_this_runner(self):
        self.assertTrue(all(not p["admitted"] for p in runner.profile_records(self.families())))


if __name__ == "__main__":
    unittest.main(verbosity=1)
