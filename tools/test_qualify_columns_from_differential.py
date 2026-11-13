#!/usr/bin/env python3
"""Negative controls for tools/qualify_columns_from_differential.py.

Run: python -I tools/test_qualify_columns_from_differential.py

Each case builds a tiny synthetic corpus and shows the fold refuses to raise a
category it has no evidence for (and refuses inconsistent inputs). The checks use
unittest assertions, which `-O` does not remove.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("qualify", HERE / "qualify_columns_from_differential.py")
qualify = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = qualify
spec.loader.exec_module(qualify)


def text(value: str) -> str:
    return "text:" + value.encode("utf-8").hex().upper()


def integer(value: int) -> str:
    return "integer:" + str(value).encode("ascii").hex().upper()


def record(relation, columns, rows, ok=True, name="a.dex"):
    return {"input": name, "relation": relation, "columns": columns, "a0": {"ok": ok, "rows": rows}}


def run_collect(records, equal=None):
    corpus = {"records": records}
    keys = equal if equal is not None else [{"input": r["input"], "relation": r["relation"]} for r in records]
    return qualify.collect(corpus, {"records": keys})


def column(relation, name, data_type, nullable, **states):
    state = {category: "satisfied" for category in qualify.CATEGORIES}
    state.update(states)
    return {"relation": relation, "ordinal": 0, "name": name, "data_type": data_type, "nullable": nullable,
            "category_state": state}


class OpcodePair(unittest.TestCase):
    def test_verdicts(self):
        self.assertEqual(qualify.opcode_pair_verdict(integer(2), text("70 0e")), "non_empty")
        self.assertEqual(qualify.opcode_pair_verdict(integer(0), text("")), "empty")
        self.assertEqual(qualify.opcode_pair_verdict("N", "N"), "null")
        self.assertEqual(qualify.opcode_pair_verdict("N", text("70")), "violation")
        self.assertEqual(qualify.opcode_pair_verdict(integer(2), text("70")), "violation")
        self.assertEqual(qualify.opcode_pair_verdict(integer(0), text("70")), "violation")
        self.assertEqual(qualify.opcode_pair_verdict(integer(1), text("7G")), "violation")
        self.assertEqual(qualify.opcode_pair_verdict(integer(1), text("0E")), "violation")  # upper case
        self.assertEqual(qualify.opcode_pair_verdict(integer(2), text("70  0e")), "violation")  # double space
        self.assertEqual(qualify.opcode_pair_verdict("integer:ZZ", text("70")), "violation")


class Fold(unittest.TestCase):
    def methods_stats(self, count_cells, hex_cells, extra_columns=()):
        rows = [[c, h] for c, h in zip(count_cells, hex_cells)]
        stats, _ = run_collect([record("methods", ["opcode_count", "opcode_hex"], rows)])
        return stats

    def test_raw_fingerprint_needs_content_not_only_the_type(self):
        stats = self.methods_stats([integer(0), integer(0)], [text(""), text("")])
        raised = qualify.evaluate(column("methods", "opcode_hex", "Utf8View", True, field_type="partial",
                                         raw_fingerprint="partial"), stats, {"cases": []})
        self.assertEqual(raised["raw_fingerprint"]["state"], "partial")
        self.assertEqual(raised["field_type"]["state"], "satisfied")

    def test_raw_fingerprint_of_a_text_column_needs_a_non_empty_value(self):
        # param_descriptors has no pair cross-check, so only the content rule can refuse it.
        empty, _ = run_collect([record("methods", ["param_descriptors", "opcode_count", "opcode_hex"],
                                       [[text(""), integer(0), text("")], [text(""), integer(0), text("")]])])
        col = column("methods", "param_descriptors", "Utf8View", False, raw_fingerprint="partial")
        self.assertEqual(qualify.evaluate(col, empty, {"cases": []})["raw_fingerprint"]["state"], "partial")
        full, _ = run_collect([record("methods", ["param_descriptors", "opcode_count", "opcode_hex"],
                                      [[text("I,J"), integer(0), text("")]])])
        self.assertEqual(qualify.evaluate(col, full, {"cases": []})["raw_fingerprint"]["state"], "satisfied")

    def test_raw_fingerprint_is_refused_when_the_pair_disagrees(self):
        stats = self.methods_stats([integer(2), integer(1)], [text("70 0e"), text("70 0e")])
        raised = qualify.evaluate(column("methods", "opcode_count", "UInt32", True, raw_fingerprint="partial"),
                                  stats, {"cases": []})
        self.assertEqual(raised["raw_fingerprint"]["state"], "partial")

    def test_raw_fingerprint_is_raised_with_content_and_a_consistent_pair(self):
        stats = self.methods_stats([integer(2), integer(0)], [text("70 0e"), text("")])
        raised = qualify.evaluate(column("methods", "opcode_hex", "Utf8View", True, raw_fingerprint="partial"),
                                  stats, {"cases": []})
        self.assertEqual(raised["raw_fingerprint"]["state"], "satisfied")

    def test_field_type_is_refused_for_the_wrong_storage_class(self):
        stats, _ = run_collect([record("strings", ["string_pool_id"], [[text("0")], [text("0")]])])
        raised = qualify.evaluate(column("strings", "string_pool_id", "UInt32", False, field_type="partial"),
                                  stats, {"cases": []})
        self.assertEqual(raised["field_type"]["state"], "partial")

    def test_field_type_is_refused_for_null_in_a_non_nullable_column(self):
        stats, _ = run_collect([record("strings", ["string_pool_id"], [[integer(0)], ["N"]])])
        raised = qualify.evaluate(column("strings", "string_pool_id", "UInt32", False, field_type="partial"),
                                  stats, {"cases": []})
        self.assertEqual(raised["field_type"]["state"], "partial")

    def test_value_repetition_needs_a_repeated_value(self):
        stats, _ = run_collect([record("types", ["file_id"], [[integer(0)], [integer(1)]])])
        raised = qualify.evaluate(column("types", "file_id", "UInt32", False, multiplicity="partial"),
                                  stats, {"cases": []})
        self.assertNotIn("multiplicity", raised)
        stats, _ = run_collect([record("types", ["file_id"], [[integer(0)], [integer(0)]])])
        raised = qualify.evaluate(column("types", "file_id", "UInt32", False, multiplicity="partial"),
                                  stats, {"cases": []})
        self.assertEqual(raised["multiplicity"]["state"], "satisfied")

    def test_other_columns_are_not_raised_by_value_repetition(self):
        stats, _ = run_collect([record("types", ["descriptor"], [[text("I")], [text("I")]])])
        raised = qualify.evaluate(column("types", "descriptor", "Utf8", False, multiplicity="partial"),
                                  stats, {"cases": []})
        self.assertNotIn("multiplicity", raised)

    def test_not_applicable_is_refused_when_the_key_repeats(self):
        stats, _ = run_collect([record("dex_files", ["file_id"], [[integer(0)], [integer(0)]])])
        with self.assertRaises(qualify.Refused):
            qualify.evaluate(column("dex_files", "file_id", "UInt32", False, multiplicity="partial"),
                             stats, {"cases": []})

    def test_provenance_case_needs_two_rows_with_one_value(self):
        stats, _ = run_collect([record("dex_files", ["entry_name"], [[text("a")]])])
        distinct = {"cases": [{"case": "x", "a0_dex_rows": [{"entry_name": "a"}, {"entry_name": "b"}]}]}
        repeated = {"cases": [{"case": "x", "a0_dex_rows": [{"entry_name": "a"}, {"entry_name": "a"}]}]}
        col = column("dex_files", "entry_name", "Utf8", False, multiplicity="partial")
        self.assertNotIn("multiplicity", qualify.evaluate(col, stats, distinct))
        self.assertEqual(qualify.evaluate(col, stats, repeated)["multiplicity"]["state"], "satisfied")

    def test_null_by_exhaustion_needs_a_compared_non_null_cell(self):
        stats, _ = run_collect([record("method_field_accesses", ["using_type"], [["N"]])])
        with self.assertRaises(qualify.Refused):
            qualify.evaluate(column("method_field_accesses", "using_type", "Utf8", True, null="missing"),
                             stats, {"cases": []})


class Inputs(unittest.TestCase):
    def test_a_manifest_record_missing_from_the_corpus_is_refused(self):
        with self.assertRaises(qualify.Refused):
            run_collect([record("types", ["file_id"], [])],
                        equal=[{"input": "a.dex", "relation": "types"}, {"input": "b.dex", "relation": "types"}])

    def test_a_manifest_record_that_a0_did_not_answer_is_refused(self):
        with self.assertRaises(qualify.Refused):
            run_collect([record("types", ["file_id"], [], ok=False)])

    def test_records_outside_the_manifest_are_not_evidence(self):
        records = [record("types", ["file_id"], [[integer(0)], [integer(0)]], name="in.dex"),
                   record("types", ["file_id"], [[text("x")], [text("x")]], name="out.dex")]
        stats, count = run_collect(records, equal=[{"input": "in.dex", "relation": "types"}])
        self.assertEqual(count, 1)
        self.assertEqual(dict(stats[("types", "file_id")]["classes"]), {"integer": 2})

    def test_a_duplicate_manifest_entry_is_refused(self):
        with self.assertRaises(qualify.Refused):
            run_collect([record("types", ["file_id"], [])],
                        equal=[{"input": "a.dex", "relation": "types"}, {"input": "a.dex", "relation": "types"}])


if __name__ == "__main__":
    unittest.main(verbosity=1)
