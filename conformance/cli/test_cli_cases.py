#!/usr/bin/env python3
"""Negative controls for the CLI contract checker.

A checker that accepts a damaged expectation proves nothing. Each test here takes one
frozen case, damages it in a single way and requires the checker to object, then
checks the stream invariants on hand-made broken streams.

Usage: python -I conformance/cli/test_cli_cases.py
"""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cli_cases as cc  # noqa: E402

DOCUMENT = cc.load_cases()
CASES = {case["name"]: case for case in DOCUMENT["cases"]}
INPUTS = DOCUMENT["inputs"]


def problems(case: dict) -> list[str]:
    return cc.check_case(cc.DEFAULT_BINARY, case, INPUTS, cc.schema_check)


def damaged(name: str, change) -> dict:
    case = copy.deepcopy(CASES[name])
    change(case)
    return case


class DamagedExpectations(unittest.TestCase):
    def test_the_undamaged_cases_hold(self):
        for name in ("query_complete", "query_row_limit_truncates", "refuse_unknown_dialect", "serve_two_requests_then_close"):
            self.assertEqual(problems(CASES[name]), [], name)

    def test_a_wrong_exit_code_is_caught(self):
        case = damaged("query_row_limit_truncates", lambda c: c.update(exit=0))
        self.assertTrue(any("exit code" in p for p in problems(case)))

    def test_a_truncated_flag_frozen_wrongly_is_caught(self):
        def change(c):
            c["stdout"]["jsonl"]["terminal"]["truncated"] = False
        self.assertTrue(any("truncated" in p for p in problems(damaged("query_row_limit_truncates", change))))

    def test_a_wrong_row_count_is_caught(self):
        def change(c):
            c["stdout"]["jsonl"]["terminal"]["emitted_rows"] = "3"
        self.assertTrue(any("emitted_rows" in p for p in problems(damaged("query_complete", change))))

    def test_a_wrong_error_code_is_caught(self):
        def change(c):
            c["stdout"]["jsonl"]["terminal"]["error_code"] = "CANCELLED"
        self.assertTrue(problems(damaged("query_deadline", change)))

    def test_output_on_a_stream_that_must_be_empty_is_caught(self):
        case = damaged("refuse_unknown_dialect", lambda c: c.update(stdout={"jsonl": {"kinds": ["opened"]}}))
        self.assertTrue(problems(case))

    def test_a_stderr_that_must_be_clean_but_is_not_is_caught(self):
        case = damaged("refuse_unknown_dialect", lambda c: c.update(stderr="empty"))
        self.assertTrue(any("stderr is not empty" in p for p in problems(case)))

    def test_a_missing_line_kind_is_caught(self):
        def change(c):
            c["stdout"]["jsonl"]["kinds"] = ["opened", "terminal"]
        self.assertTrue(problems(damaged("query_complete", change)))

    def test_terminal_ids_out_of_order_are_caught(self):
        def change(c):
            c["stdout"]["jsonl"]["terminal_ids"] = ["b", "a"]
        self.assertTrue(problems(damaged("serve_two_requests_then_close", change)))

    def test_a_session_that_should_have_ended_at_close_is_caught(self):
        def change(c):
            c["stdout"]["jsonl"]["terminal_ids"] = ["a", "b", "never"]
        self.assertTrue(problems(damaged("serve_two_requests_then_close", change)))

    def test_an_empty_result_must_still_name_its_columns(self):
        def change(c):
            c["stdout"]["jsonl"]["terminal"]["columns"] = ["other"]
        self.assertTrue(problems(damaged("query_empty_result", change)))


def line(kind, rid=None, **fields):
    return {"kind": kind, "id": rid, **fields}


def batch(rid, sequence, first_row, count):
    return line("batch", rid, batch={"schema": "mdd.sdk-batch.v1", "sequence": str(sequence),
                                    "first_row": str(first_row), "row_count": count, "rows": [[]] * count})


def terminal(rid, emitted):
    return line("terminal", rid, terminal={"response": {"emitted_rows": str(emitted)}})


OPENED = {"kind": "opened", "protocol": "mdd.cli-stream.v1"}


class BrokenStreams(unittest.TestCase):
    def test_a_sound_stream_has_no_problem(self):
        self.assertEqual(cc.stream_problems([OPENED, batch("a", 0, 0, 2), batch("a", 1, 2, 1), terminal("a", 3)]), [])

    def test_a_sequence_gap_is_caught(self):
        self.assertTrue(cc.stream_problems([OPENED, batch("a", 1, 0, 1), terminal("a", 1)]))

    def test_a_first_row_that_does_not_accumulate_is_caught(self):
        self.assertTrue(cc.stream_problems([OPENED, batch("a", 0, 0, 2), batch("a", 1, 5, 1), terminal("a", 3)]))

    def test_a_terminal_count_that_disagrees_with_the_rows_is_caught(self):
        self.assertTrue(cc.stream_problems([OPENED, batch("a", 0, 0, 2), terminal("a", 3)]))

    def test_rows_claimed_without_any_batch_are_caught(self):
        self.assertTrue(cc.stream_problems([OPENED, terminal("a", 2)]))

    def test_batches_without_a_terminal_are_caught(self):
        self.assertTrue(cc.stream_problems([OPENED, batch("a", 0, 0, 1)]))

    def test_a_stream_that_does_not_open_is_caught(self):
        self.assertTrue(cc.stream_problems([batch("a", 0, 0, 1), terminal("a", 1)]))

    def test_a_row_count_that_disagrees_with_its_rows_is_caught(self):
        broken = batch("a", 0, 0, 2)
        broken["batch"]["rows"] = [[]]
        self.assertTrue(cc.stream_problems([OPENED, broken, terminal("a", 2)]))


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], "-v"])
