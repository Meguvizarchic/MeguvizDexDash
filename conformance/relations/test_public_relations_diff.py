"""Controls of the comparison of conformance/relations/public_relations_diff.py: it must be able to fail.

A comparison that cannot say "different" proves nothing, so each declared difference is pinned together with the
change just past it that must still be caught.

Run: python -I conformance/relations/test_public_relations_diff.py
"""
from __future__ import annotations

import json
import math
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "conformance" / "mcp"))

import public_relations_diff as D  # noqa: E402

ROOT = HERE.parents[1]


def u(value):
    return {"type": "uint64", "value": str(value)}


def i(value):
    return {"type": "int64", "value": str(value)}


def t(value):
    return {"type": "utf8", "value": value}


def f(value):
    return {"type": "float64", "value": value}


NULL = {"type": "null", "value": None}


def column(name, kind="uint64", nullable=False):
    return {"name": name, "data_type": kind, "nullable": nullable}


def recorded(columns, rows):
    return {"columns": columns, "rows": rows}


def got(columns, rows, error=None):
    return {"columns": columns, "rows": rows, "error": error}


class Verdicts(unittest.TestCase):
    cols = [column("a"), column("b", "utf8")]

    def test_equal_cells_in_the_recorded_order_match(self):
        rows = [[u(1), t("x")], [u(2), t("y")]]
        self.assertEqual(D.compare("r", recorded(self.cols, rows), got(self.cols, rows))["verdict"], "match")

    def test_one_changed_cell_differs(self):
        want = [[u(1), t("x")], [u(2), t("y")]]
        have = [[u(1), t("x")], [u(2), t("z")]]
        out = D.compare("r", recorded(self.cols, want), got(self.cols, have))
        self.assertEqual(out["verdict"], "differs")
        self.assertEqual(out["first_difference"]["row"], 1)

    def test_a_missing_or_an_extra_row_differs(self):
        rows = [[u(1), t("x")], [u(2), t("y")]]
        self.assertEqual(D.compare("r", recorded(self.cols, rows), got(self.cols, rows[:1]))["verdict"], "differs")
        self.assertEqual(D.compare("r", recorded(self.cols, rows[:1]), got(self.cols, rows))["verdict"], "differs")

    def test_a_cell_type_that_is_not_a_declared_difference_differs(self):
        want = [[u(1), t("x")]]
        have = [[{"type": "int64", "value": "1"}, t("x")]]
        self.assertEqual(D.compare("r", recorded(self.cols, want), got(self.cols, have))["verdict"], "differs")

    def test_the_same_rows_in_another_order_are_reordered_not_equal(self):
        want = [[u(1), t("x")], [u(2), t("y")]]
        out = D.compare("r", recorded(self.cols, want), got(self.cols, list(reversed(want))))
        self.assertEqual(out["verdict"], "reordered")

    def test_a_duplicated_row_in_place_of_another_is_not_a_reordering(self):
        want = [[u(1), t("x")], [u(2), t("y")]]
        have = [[u(1), t("x")], [u(1), t("x")]]
        self.assertEqual(D.compare("r", recorded(self.cols, want), got(self.cols, have))["verdict"], "differs")

    def test_other_column_names_differ(self):
        rows = [[u(1), t("x")]]
        other = [column("a"), column("c", "utf8")]
        self.assertEqual(D.compare("r", recorded(self.cols, rows), got(other, rows))["verdict"], "differs")

    def test_the_type_the_engine_reports_for_an_empty_result_is_a_note_only(self):
        out = D.compare("r", recorded(self.cols, []), got([column("a", "unknown"), column("b", "unknown")], []))
        self.assertEqual(out["verdict"], "match_cells")
        self.assertEqual(len(out["column_metadata_notes"]), 2)

    def test_an_engine_error_is_an_error_unless_it_is_the_declared_refusal(self):
        rows = [[u(1), t("x")]]
        self.assertEqual(D.compare("r", recorded(self.cols, rows), got(self.cols, [], "boom"))["verdict"], "error")
        declared = "INCOMPLETE_FACTS non_scalar_UTF16_cannot_be_plain_UTF8"
        self.assertEqual(D.compare("r", recorded(self.cols, rows), got(self.cols, [], declared))["verdict"], "refused_by_design")


class TheReferenceGaps(unittest.TestCase):
    cols = [column("a"), column("b", "utf8")]
    pair = ("parameter-empty-zero-proto", "type_list_entries")

    def test_rows_the_reference_left_out_are_a_declared_gap_only_for_the_declared_pair(self):
        have = [[u(1), t("x")], [u(2), t("y")]]
        out = D.compare(self.pair[1], recorded(self.cols, []), got(self.cols, have), self.pair[0])
        self.assertEqual(out["verdict"], "reference_incomplete")
        # the same difference anywhere else is a difference
        self.assertEqual(D.compare(self.pair[1], recorded(self.cols, []), got(self.cols, have), "other")["verdict"], "differs")
        self.assertEqual(D.compare("other", recorded(self.cols, []), got(self.cols, have), self.pair[0])["verdict"], "differs")

    def test_a_row_the_engine_lacks_is_not_excused_by_the_gap(self):
        want = [[u(1), t("x")], [u(3), t("z")]]
        have = [[u(1), t("x")], [u(2), t("y")]]
        self.assertEqual(D.compare(self.pair[1], recorded(self.cols, want), got(self.cols, have), self.pair[0])["verdict"], "differs")

    def test_the_gaps_are_the_stalled_pairs_and_the_entries_of_the_unreferenced_lists(self):
        self.assertLessEqual(D.A0_PAGING_DEFECTS, D.REFERENCE_GAPS)
        self.assertEqual(len(D.REFERENCE_GAPS - D.A0_PAGING_DEFECTS), 2)


class DeclaredDifferences(unittest.TestCase):
    def test_a_non_negative_value_of_an_int64_column_may_carry_either_tag_a_negative_one_may_not(self):
        cols = [column("v", "int64")]
        self.assertEqual(D.compare("r", recorded(cols, [[i(65535)]]), got(cols, [[u(65535)]]))["verdict"], "match")
        self.assertEqual(D.compare("r", recorded(cols, [[i(-1)]]), got(cols, [[u(1)]]))["verdict"], "differs")
        self.assertEqual(D.compare("r", recorded(cols, [[i(-1)]]), got(cols, [[i(-1)]]))["verdict"], "match")
        # another value under the same tag is still another value
        self.assertEqual(D.compare("r", recorded(cols, [[i(7)]]), got(cols, [[u(8)]]))["verdict"], "differs")

    def test_the_tag_of_a_uint64_column_is_not_relaxed(self):
        cols = [column("v", "uint64")]
        self.assertEqual(D.compare("r", recorded(cols, [[u(5)]]), got(cols, [[i(5)]]))["verdict"], "differs")

    def test_a_float_within_one_unit_in_the_last_place_matches_two_units_away_does_not(self):
        cols = [column("d", "float64", True)]
        value = -1.2313300687736947e303
        one = math.nextafter(value, -math.inf)
        two = math.nextafter(one, -math.inf)
        self.assertEqual(D.compare("r", recorded(cols, [[f(one)]]), got(cols, [[f(value)]]))["verdict"], "match")
        self.assertEqual(D.compare("r", recorded(cols, [[f(two)]]), got(cols, [[f(value)]]))["verdict"], "differs")
        self.assertEqual(D.compare("r", recorded(cols, [[f("NaN")]]), got(cols, [[f("NaN")]]))["verdict"], "match")
        self.assertEqual(D.compare("r", recorded(cols, [[f(1.0)]]), got(cols, [[f("NaN")]]))["verdict"], "differs")

    def test_the_local_path_column_is_not_compared_anything_else_is(self):
        cols = [column("file_id"), column("source_path", "utf8"), column("entry_name", "utf8")]
        want = [[u(0), t("tests/x.dex"), t("x.dex")]]
        have = [[u(0), t("C:\\elsewhere\\x.dex"), t("x.dex")]]
        self.assertEqual(D.compare("dex_files", recorded(cols, want), got(cols, have))["verdict"], "match")
        have = [[u(0), t("C:\\elsewhere\\x.dex"), t("y.dex")]]
        self.assertEqual(D.compare("dex_files", recorded(cols, want), got(cols, have))["verdict"], "differs")
        # the same column of another relation is compared
        self.assertEqual(D.compare("other", recorded(cols, want), got(cols, [[u(0), t("C:\\elsewhere\\x.dex"), t("x.dex")]]))["verdict"], "differs")


class TheRecordedAnswers(unittest.TestCase):
    def test_no_probe_record_names_a_local_directory(self):
        for path in sorted((ROOT / "artifacts" / "mdd-070" / "a0-probe").glob("*.json")):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("DevArea", text, path.name)
            self.assertNotIn(":\\\\", text, path.name)

    def test_every_record_of_both_references_holds_the_fifty_six_frozen_relations_of_one_fixture(self):
        manifest = json.loads((ROOT / "conformance" / "manifests" / "relations.json").read_text(encoding="utf-8"))
        names = [entry["name"] for entry in manifest["relations"]]
        fixtures = {}
        for directory in ("a0-probe", "a1-probe"):
            records = [p for p in sorted((ROOT / "artifacts" / "mdd-070" / directory).glob("*.json")) if p.name != "describe-tables.json"]
            self.assertGreaterEqual(len(records), 47, directory)
            fixtures[directory] = [p.name for p in records]
            for path in records:
                record = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(list(record["relations"]), names, f"{directory}/{path.name}")
                self.assertEqual(D.sha256(ROOT / record["fixture"]), record["fixture_sha256"], f"{directory}/{path.name}")
                for name, answer in record["relations"].items():
                    self.assertIsNone(answer["error"], f"{directory}/{path.name} {name}")
                    # the reference's paging defect is declared, pair by pair, and no other pair may show it
                    self.assertEqual(answer["paging_stuck"], (path.stem, name) in D.A0_PAGING_DEFECTS, f"{directory}/{path.name} {name}")
        # both references were asked about the same fixtures
        self.assertEqual(fixtures["a0-probe"], fixtures["a1-probe"])


if __name__ == "__main__":
    unittest.main()
