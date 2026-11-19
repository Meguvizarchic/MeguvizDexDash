"""MDD-054: the full-report comparator against a synthetic run, and against edits that it must notice.

Nothing here needs an engine or an APK. The synthetic run has the shape of a HostLab full audit: a report, the
published FEATURE rows and the 20 evidence groups, with a repeated element, a NULL and an integer-like text in them so that
the edits that matter (drop a repetition, turn NULL into "", turn 1 into "1") have something to damage.
"""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "conformance/hostlab"))

import compare_full_reports as C  # noqa: E402

FEATURES = [f"feature_{n:02d}" for n in range(27)]


def make_run(engine: str = "A") -> dict:
    features = {name: {"status": "FOUND" if n % 3 else "MISSING", "detail": f"detail {n}"} for n, name in enumerate(FEATURES)}
    summary = {
        "audit_backend": "dexsql", "audit_complete": True, "backend_fallback_reason": None, "coverage_gaps": [],
        "features": features, "home_probe_exit_code": 0, "intake_exit_code": 0, "mode": "full",
        "native_audit": {
            "complete": True, "source_sha_reverified": True, "class_count": 120, "queries": 635, "reference_sha256": "r" * 64,
            "elapsed_ms": 90000.5 if engine == "A" else 61234.25,
            "native": {"version": "0.1.0" if engine == "A" else "0.9.0", "sha256": engine * 64, "path": f"/engine/{engine}"},
            "phases": {"prepare_ms": 1.0 if engine == "A" else 2.0, "structural_ms": 3.0, "surface_ms": 4.0 if engine == "A" else 5.0},
        },
        "runtime_verified": False, "sample": {"sha256": "s" * 64, "version_code": 7, "package": "x.y"},
        "scope": "static only", "tools": {"native_audit.py": "t" * 64},
    }
    tsv = "META\tapk\tx.apk\nMETA\tclass_count\t120\n" + "".join(
        f"FEATURE\t{name}\t{feature['status']}\t{feature['detail']}\n" for name, feature in features.items()) + "META\taudit_complete\ttrue\n"
    edge = ["Lx/A;->a()V", "Lx/B;->b()V", 3]
    evidence = {
        "class_records": [{"file_id": 1, "class": "Lx/A;", "superclass": None, "fields": [], "methods": ["a"]},
                         {"file_id": 2, "class": "Lx/B;", "superclass": "Lx/A;", "fields": [], "methods": []}],
        "discoveries": [["f", "Lx/A;", "a"], ["f", "Lx/A;", "a"]],
        "families": {"one": 1, "two": None}, "features": {n: f["status"] for n, f in features.items()},
        "gates": {"audit_complete": True, "intake_exit_code": 0, "home_probe_exit_code": 0},
        "home_probe_sha256": "h" * 64, "invoke_edges": [edge, edge, ["Lx/A;->c()V", "Lx/B;->b()V", 1]],
        "limitations": ["first", "second"], "page_path_matrix": {"home": ["a", "b"]},
        "protocol_definitions": [["P", "m"], ["P", "n"]], "protocol_paths": {"search": ["x"]},
        "protocol_twins": [{"java": "A", "kotlin": "B"}], "resource_fingerprints": {"res/a.xml": "ff", "res/b.xml": "00"},
        "rule_sha256": "u" * 64, "rule_version": 4, "sample": {"package": "x.y", "size": "10", "version_code": 7},
        "scope": "static only", "unclassified_protocol_callers": [["a", "b"], ["a", "b"]],
        "unknown_families": ["u1"], "unregistered_protocols": ["q1", "q2"],
    }
    return {"summary": summary, "tsv": tsv, "evidence": evidence,
            "certificate": {"fallback_count": 0, "output_fully_materialized": True, "more_available": False, "truncated": False,
                            "input_sha256": "s" * 64, "reference_source_commit": "c" * 40, "tools": {"native_audit.py": "t" * 64}}}


def layer(result: dict, name: str) -> dict:
    return next(item for item in result["layers"] if item["layer"] == name)


class EqualRuns(unittest.TestCase):
    def test_two_runs_that_differ_only_in_engine_identity_and_clocks_are_equal(self):
        result = C.compare(make_run("A"), make_run("B"))
        self.assertTrue(result["equal"], json.dumps(result, indent=1)[:1500])
        self.assertEqual([item["layer"] for item in result["layers"]], ["run", "report", "tsv", "groups"])

    def test_the_ignore_list_is_exactly_the_engine_identity_and_the_clocks(self):
        self.assertEqual(C.IGNORE_LIST["report_paths"], (
            "/native_audit/native", "/native_audit/elapsed_ms", "/native_audit/phases/prepare_ms",
            "/native_audit/phases/structural_ms", "/native_audit/phases/surface_ms"))
        for forbidden in ("NULL against empty", "repeat counts", "source-local ids", "declaration order", "coverage", "fingerprints"):
            self.assertIn(forbidden, C.IGNORE_LIST["not_ignorable"])

    def test_the_key_order_of_an_object_is_not_part_of_a_value(self):
        b = make_run("B")
        b["evidence"]["gates"] = dict(reversed(list(b["evidence"]["gates"].items())))
        b["evidence"]["resource_fingerprints"] = dict(reversed(list(b["evidence"]["resource_fingerprints"].items())))
        b["evidence"]["class_records"][0] = dict(reversed(list(b["evidence"]["class_records"][0].items())))
        self.assertTrue(C.compare(make_run("A"), b)["equal"])

    def test_a_multiset_group_in_another_order_is_equal_and_an_ordered_group_is_not(self):
        b = make_run("B")
        b["evidence"]["invoke_edges"].reverse()
        b["evidence"]["class_records"].reverse()
        self.assertTrue(C.compare(make_run("A"), b)["equal"])
        b["evidence"]["limitations"].reverse()
        result = C.compare(make_run("A"), b)
        self.assertFalse(result["equal"])
        self.assertFalse(layer(result, "groups")["detail"]["groups"]["limitations"]["equal"])

    def test_the_certificate_of_the_baseline_driver_hashes_the_same_way(self):
        # The 2026-10-28 baseline driver hashed a group as sha256(json.dumps(sorted canonical items)) for a bag, and of the
        # value for the rest. The comparator's digests must be the numbers that certificate holds.
        import hashlib
        run = make_run("A")
        for name, value in run["evidence"].items():
            if name in C.MULTISET_GROUPS:
                value = sorted(json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False) for v in value)
            expected = hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
            self.assertEqual(C.group_digest(name, run["evidence"][name])["sha256"], expected, name)


class Damage(unittest.TestCase):
    """Each edit of B must make the comparison fail, in the named layer."""

    def check(self, edit, name: str, in_layer: str, group: "str | None" = None):
        b = make_run("B")
        edit(b)
        result = C.compare(make_run("A"), b)
        self.assertFalse(result["equal"], name)
        self.assertFalse(layer(result, in_layer)["equal"], name)
        if group:
            self.assertFalse(layer(result, "groups")["detail"]["groups"][group]["equal"], name)
        return result

    def test_a_dropped_repetition_is_a_difference_with_its_count(self):
        def edit(b):
            b["evidence"]["invoke_edges"].pop(0)
        result = self.check(edit, "an invoke edge counted once instead of twice", "groups", "invoke_edges")
        bag = layer(result, "groups")["detail"]["groups"]["invoke_edges"]["bag"]
        self.assertEqual((bag["missing_count"], bag["extra_count"]), (1, 0))
        self.assertEqual(bag["missing_first"][0]["times"], 1)

    def test_a_repetition_added_is_a_difference(self):
        self.check(lambda b: b["evidence"]["discoveries"].append(["f", "Lx/A;", "a"]), "a repeated discovery", "groups", "discoveries")

    def test_null_is_not_empty_and_a_number_is_not_its_text(self):
        self.check(lambda b: b["evidence"]["class_records"][0].__setitem__("superclass", ""), "NULL became an empty text", "groups", "class_records")
        self.check(lambda b: b["evidence"]["class_records"][0].__setitem__("fields", None), "an empty list became NULL", "groups", "class_records")
        self.check(lambda b: b["evidence"]["class_records"][0].__setitem__("file_id", "1"), "an integer became its text", "groups", "class_records")
        self.check(lambda b: b["evidence"]["class_records"][0].__setitem__("file_id", True), "an integer became a boolean", "groups", "class_records")
        self.check(lambda b: b["evidence"]["families"].__setitem__("two", ""), "a NULL value became empty text", "groups", "families")
        self.check(lambda b: b["evidence"]["families"].__setitem__("one", 1.0), "an integer became a real", "groups", "families")

    def test_a_source_local_id_is_compared(self):
        self.check(lambda b: b["evidence"]["class_records"][1].__setitem__("file_id", 3), "a class attributed to another DEX", "groups", "class_records")

    def test_a_fingerprint_a_flag_and_a_gate_are_compared(self):
        self.check(lambda b: b["evidence"]["resource_fingerprints"].__setitem__("res/a.xml", "fe"), "a resource fingerprint", "groups", "resource_fingerprints")
        self.check(lambda b: b["evidence"]["resource_fingerprints"].pop("res/b.xml"), "a resource fingerprint missing", "groups", "resource_fingerprints")
        self.check(lambda b: b["evidence"]["gates"].__setitem__("home_probe_exit_code", 1), "a gate state", "groups", "gates")
        self.check(lambda b: b["evidence"].__setitem__("home_probe_sha256", "0" * 64), "the home probe fingerprint", "groups", "home_probe_sha256")
        self.check(lambda b: b["evidence"].__setitem__("rule_version", 5), "the rule version", "groups", "rule_version")

    def test_a_group_missing_or_added_is_a_difference(self):
        self.check(lambda b: b["evidence"].pop("unknown_families"), "a group missing", "groups", "unknown_families")
        self.check(lambda b: b["evidence"].__setitem__("extra_group", []), "a group added", "run")

    def test_a_feature_changes_in_every_place_it_is_kept(self):
        def edit(b):
            b["summary"]["features"]["feature_01"]["status"] = "MISSING"
        self.check(edit, "a feature status in the report", "report")
        self.check(lambda b: b["summary"]["features"]["feature_01"].__setitem__("detail", "detail 1x"), "a feature detail", "report")
        self.check(lambda b: b["summary"]["features"].pop("feature_01"), "a feature missing", "run")

    def test_the_published_rows_fix_the_declaration_order(self):
        def edit(b):
            rows = b["tsv"].splitlines(keepends=True)
            rows[2], rows[3] = rows[3], rows[2]
            b["tsv"] = "".join(rows)
        result = self.check(edit, "two FEATURE rows swapped", "tsv")
        self.assertEqual(layer(result, "tsv")["difference_count"], 2)
        self.check(lambda b: b.__setitem__("tsv", b["tsv"].replace("audit_complete\ttrue", "audit_complete\tfalse")), "the final marker", "tsv")
        self.check(lambda b: b.__setitem__("tsv", b["tsv"] + "\n"), "an extra line", "tsv")

    def test_the_report_outside_the_ignore_list_is_compared(self):
        self.check(lambda b: b["summary"]["native_audit"].__setitem__("queries", 636), "the number of queries", "report")
        self.check(lambda b: b["summary"]["native_audit"].__setitem__("class_count", 121), "the class count", "report")
        self.check(lambda b: b["summary"]["native_audit"].__setitem__("reference_sha256", "x" * 64), "the reference digest", "report")
        self.check(lambda b: b["summary"].__setitem__("coverage_gaps", ["a gap"]), "coverage", "report")
        self.check(lambda b: b["summary"].__setitem__("intake_exit_code", 1), "a gate exit code", "report")
        self.check(lambda b: b["summary"].__setitem__("extra", 1), "a field added", "report")
        self.check(lambda b: b["summary"]["native_audit"]["phases"].__setitem__("other_ms", 1), "a phase added outside the clocks", "report")

    def test_a_run_that_is_not_the_same_complete_run_is_refused_first(self):
        self.check(lambda b: b["summary"].__setitem__("audit_complete", False), "an incomplete audit", "run")
        self.check(lambda b: b["summary"].__setitem__("backend_fallback_reason", "engine failed"), "a fallback", "run")
        self.check(lambda b: b["summary"]["native_audit"].__setitem__("source_sha_reverified", False), "the source not re-verified", "run")
        self.check(lambda b: b["summary"]["sample"].__setitem__("sha256", "z" * 64), "another input", "run")
        self.check(lambda b: b["summary"]["tools"].__setitem__("native_audit.py", "z" * 64), "other tools", "run")
        self.check(lambda b: b["certificate"].__setitem__("fallback_count", 1), "a counted fallback", "run")
        self.check(lambda b: b["certificate"].__setitem__("truncated", True), "a truncated result", "run")
        self.check(lambda b: b["certificate"].__setitem__("more_available", True), "an unconsumed page", "run")
        self.check(lambda b: b["certificate"].__setitem__("reference_source_commit", "d" * 40), "another reference source", "run")

    def test_a_difference_keeps_the_evidence_and_not_only_the_word_failed(self):
        def edit(b):
            b["evidence"]["limitations"][0] = "changed"
        result = self.check(edit, "an ordered element", "groups", "limitations")
        first = layer(result, "groups")["detail"]["groups"]["limitations"]["first_differences"][0]
        self.assertEqual(first["path"], "/limitations[0]")
        self.assertIn("first", first["expected"]["value"])
        self.assertIn("changed", first["observed"]["value"])
        self.assertEqual(len(first["observed"]["sha256"]), 64)

    def test_a_long_value_is_cut_but_keeps_its_length_and_digest(self):
        b = make_run("B")
        b["evidence"]["limitations"][0] = "y" * 5000
        result = C.compare(make_run("A"), b)
        observed = layer(result, "groups")["detail"]["groups"]["limitations"]["first_differences"][0]["observed"]
        self.assertTrue(observed["value"].endswith("..."))
        self.assertGreater(observed["length"], 5000)


class Reading(unittest.TestCase):
    def test_a_duplicate_key_and_a_non_finite_number_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "x.json"
            path.write_text('{"a": 1, "a": 2}', encoding="utf-8")
            with self.assertRaises(ValueError):
                C.read_json(path)
            path.write_text('{"a": NaN}', encoding="utf-8")
            with self.assertRaises(ValueError):
                C.read_json(path)

    def test_a_bag_group_that_is_not_a_list_is_refused_not_compared(self):
        with self.assertRaises(ValueError):
            C.group_form("invoke_edges", {"not": "a list"})

    def test_a_run_directory_with_two_reports_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            for stamp in ("a", "b"):
                target = Path(folder) / "state/reports/v/s" / stamp
                target.mkdir(parents=True)
                (target / "summary.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                C.load_run(folder)


if __name__ == "__main__":
    unittest.main()
