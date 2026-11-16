#!/usr/bin/env python3
"""Controls for a0_replay.py: the comparison must see what it is there to see.

A replay that cannot fail proves nothing, so each kind of difference it must find is put to it here.

Usage: python -I conformance/decode/test_a0_replay.py
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import a0_cases  # noqa: E402
import a0_replay as replay  # noqa: E402

# switch_packed() of the fixtures, as the reference wrote it and as this server writes it
REFERENCE = """.method public static switch_packed()V
    .registers 4

    packed-switch v0, :payload_0006_0000
    goto :label_0005
    :label_0004
    const/4 v1, 0x1
    :label_0005
    return-void
    :payload_0006_0000
    .packed-switch -0x1
        :label_0004
        :label_0005
        :label_0004
    .end packed-switch
.end method
"""
OURS = """.method public static switch_packed()V
    .registers 4

    packed-switch v0, :pswitch_data_6
    goto :goto_5
    :pswitch_4
    const/4 v1, 0x1
    :goto_5
    :pswitch_5
    return-void
    :pswitch_data_6
    .packed-switch -0x1
        :pswitch_4
        :pswitch_5
        :pswitch_4
    .end packed-switch
.end method
"""
TRY_REFERENCE = """.method public static try_catch()V
    .registers 3

    :label_0000
    invoke-static {}, Ldecode/Other;->work()V
    :label_0003
    invoke-static {}, Ldecode/Other;->work()V
    :label_0009
    return-void
    :label_000a
    move-exception v0
    throw v0
    :label_000c
    move-exception v1
    return-void
    .catch Ljava/io/IOException; {:label_0000 .. :label_0003} :label_000a
    .catch Ljava/lang/Exception; {:label_0003 .. :label_0009} :label_000c
    .catchall {:label_0003 .. :label_0009} :label_000a
.end method
"""
TRY_OURS = """.method public static try_catch()V
    .registers 3

    :try_start_0
    invoke-static {}, Ldecode/Other;->work()V
    :try_end_3
    :try_start_3
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_3} :catch_a
    invoke-static {}, Ldecode/Other;->work()V
    :try_end_9
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_9} :catch_c
    .catchall {:try_start_3 .. :try_end_9} :catchall_a
    return-void
    :catch_a
    :catchall_a
    move-exception v0
    throw v0
    :catch_c
    move-exception v1
    return-void
.end method
"""


def ok(**method) -> dict:
    base = {"access_flags": 9, "code_units": 16, "descriptor": "Lx;->f()V", "file_id": 0, "method_idx": 1,
            "registers": 4, "try_count": 0, "offset": 0, "next_offset": None, "smali": REFERENCE,
            "total_bytes": len(REFERENCE), "total_lines": REFERENCE.count("\n"), "start_line": 0, "end_line": 16,
            "starts_mid_line": False, "ends_mid_line": False, "declaration": ".method public static switch_packed()V"}
    base.update(method)
    return {"dataset_id": "DS", "method_offset": 0, "methods": [base], "mode": "smali", "next_method_offset": None, "total_methods": 1}


def refusal(kind="not_found", message="method is not defined in the selected DEX", **extra) -> dict:
    return {"dataset_id": "DS", "error": {"kind": kind, "message": message, **extra}}


def answered(body: dict, error: bool = False) -> dict:
    return {"is_error": error, "reply": body}


class Canon(unittest.TestCase):
    def test_two_writings_of_one_method_are_the_same_text(self):
        self.assertEqual(replay.canon_smali(REFERENCE), replay.canon_smali(OURS))

    def test_the_exception_table_is_the_same_wherever_it_is_written(self):
        self.assertEqual(replay.canon_smali(TRY_REFERENCE), replay.canon_smali(TRY_OURS))
        self.assertEqual(replay.canon_smali(TRY_OURS)[1][0][:2], ("catch", "Ljava/io/IOException;"))

    def test_parameter_registers_are_the_registers_they_name(self):
        reference = ".method public <init>(IJ)V\n    .registers 6\n\n    move-wide v2, v3\n    move v1, v5\n.end method\n"
        ours = ".method public <init>(IJ)V\n    .registers 6\n\n    move-wide p1, p2\n    move p0, p4\n.end method\n"
        # 6 registers, 4 of them parameters (this, I, J): p0 is v2
        self.assertEqual(replay.canon_smali(ours)[0][2:4], ["move-wide v3, v4", "move v2, v6"])
        self.assertNotEqual(replay.canon_smali(reference), replay.canon_smali(ours))

    def test_how_many_registers_the_parameters_take(self):
        self.assertEqual(replay.parameter_registers(".method public static f(II)V"), 2)
        self.assertEqual(replay.parameter_registers(".method public f(JI)V"), 4)
        self.assertEqual(replay.parameter_registers(".method public f([JLjava/lang/String;D)V"), 1 + 1 + 1 + 2)
        self.assertEqual(replay.parameter_registers(".method public abstract abstract_one(I)I"), 2)

    def test_wide_literals_and_apostrophes_are_writing_not_content(self):
        a = ".method f()V\n    .registers 2\n    const-wide/16 v0, -0x1\n    const-string v0, \"a'b\"\n.end method\n"
        b = ".method f()V\n    .registers 2\n    const-wide/16 v0, -0x1L\n    const-string v0, \"a\\'b\"\n.end method\n"
        self.assertEqual(replay.canon_smali(a), replay.canon_smali(b))

    def test_a_changed_literal_is_found(self):
        self.assertNotEqual(replay.canon_smali(OURS), replay.canon_smali(OURS.replace("0x1\n", "0x2\n", 1)))

    def test_a_changed_register_is_found(self):
        self.assertNotEqual(replay.canon_smali(OURS), replay.canon_smali(OURS.replace("const/4 v1", "const/4 v2")))

    def test_a_changed_branch_target_is_found(self):
        self.assertNotEqual(replay.canon_smali(OURS), replay.canon_smali(OURS.replace("goto :goto_5", "goto :pswitch_4")))

    def test_a_changed_switch_case_is_found(self):
        self.assertNotEqual(replay.canon_smali(OURS), replay.canon_smali(OURS.replace("        :pswitch_5\n", "        :pswitch_4\n")))

    def test_a_changed_opcode_is_found(self):
        self.assertNotEqual(replay.canon_smali(OURS), replay.canon_smali(OURS.replace("const/4", "const/16")))

    def test_a_missing_instruction_is_found(self):
        self.assertNotEqual(replay.canon_smali(OURS), replay.canon_smali(OURS.replace("    return-void\n", "")))

    def test_a_changed_exception_range_is_found(self):
        other = TRY_OURS.replace("{:try_start_3 .. :try_end_9} :catch_c", "{:try_start_0 .. :try_end_9} :catch_c")
        self.assertNotEqual(replay.canon_smali(TRY_OURS), replay.canon_smali(other))

    def test_a_dropped_exception_handler_is_found(self):
        other = TRY_OURS.replace("    .catchall {:try_start_3 .. :try_end_9} :catchall_a\n", "")
        self.assertNotEqual(replay.canon_smali(TRY_OURS), replay.canon_smali(other))


class Comparison(unittest.TestCase):
    def reference(self, body: dict, error: bool = False, case_id: str = "decode-text") -> dict:
        return {"id": case_id, "is_error": error, "reply": body}

    def test_the_same_text_in_the_other_writing_is_equal_with_its_own_numbers(self):
        mine = ok(smali=OURS, total_bytes=len(OURS), total_lines=OURS.count("\n") + 1, end_line=17)
        problems, declared = replay.compare_case(self.reference(ok()), answered(mine))
        self.assertEqual(problems, [])

    def test_a_text_that_says_something_else_is_a_difference(self):
        mine = ok(smali=OURS.replace("0x1\n", "0x2\n", 1), total_bytes=len(OURS), total_lines=17, end_line=17)
        problems, _ = replay.compare_case(self.reference(ok()), answered(mine))
        self.assertTrue(problems and "the text says something else" in problems[0], problems)

    def test_a_number_a_client_reads_is_compared(self):
        mine = ok(smali=OURS, total_bytes=len(OURS), total_lines=17, end_line=17, registers=5)
        problems, _ = replay.compare_case(self.reference(ok()), answered(mine))
        self.assertTrue(any("registers" in p for p in problems), problems)

    def test_the_same_text_must_have_the_same_numbers(self):
        mine = ok(total_lines=99)
        problems, _ = replay.compare_case(self.reference(ok()), answered(mine))
        self.assertTrue(any("total_lines" in p for p in problems), problems)

    def test_an_error_of_another_kind_is_a_difference(self):
        problems, _ = replay.compare_case(self.reference(refusal(), True), answered(refusal(kind="unknown_dataset"), True))
        self.assertTrue(any("error kind" in p for p in problems), problems)

    def test_an_error_that_stops_echoing_the_request_is_a_difference(self):
        want = refusal(file_id=0, method_idx=7)
        got = refusal(file_id=None, method_idx=None)
        problems, _ = replay.compare_case(self.reference(want, True), answered(got, True))
        self.assertTrue(any("file_id" in p for p in problems), problems)

    def test_other_words_for_the_same_kind_are_declared_not_hidden(self):
        got = refusal(message="method X is not defined in this dataset", code="INVALID_ARGUMENT", stage="mcp", retryable=False, details={})
        problems, declared = replay.compare_case(self.reference(refusal(), True), answered(got, True))
        self.assertEqual((problems, declared), ([], "ERROR WORDING"))

    def test_an_answer_where_the_reference_refused_is_a_difference(self):
        problems, _ = replay.compare_case(self.reference(refusal(), True), answered(ok()))
        self.assertTrue(problems)

    def test_a_refusal_where_the_reference_answered_is_a_difference(self):
        problems, _ = replay.compare_case(self.reference(ok()), answered(refusal(), True))
        self.assertTrue(problems)

    def test_a_protocol_error_is_excused_only_for_arguments(self):
        reply = {"jsonrpc_error": {"code": -32602, "message": "x"}}
        _, declared = replay.compare_case(self.reference({"raw_text": "failed to deserialize parameters: x"}, True), reply)
        self.assertEqual(declared, "MALFORMED ARGUMENTS")
        problems, _ = replay.compare_case(self.reference(ok()), reply)
        self.assertTrue(problems)

    def test_a_malformed_invoke_must_still_come_with_its_text(self):
        want = refusal(kind="invalid_input", message="invoke argument count does not match prototype", code_unit_offset=0)
        _, declared = replay.compare_case(self.reference(want, True), answered(ok()))
        self.assertEqual(declared, "MALFORMED CODE")
        problems, _ = replay.compare_case(self.reference(want, True), answered(ok(smali="")))
        self.assertTrue(problems)

    def test_the_summary_may_name_the_declaration_and_nothing_else(self):
        summary = {"access_flags": 9, "code_units": 16, "descriptor": "Lx;->f()V", "file_id": 0, "method_idx": 1,
                   "registers": 4, "try_count": 0, "next_offset": None}
        want = {"dataset_id": "DS", "method_offset": 0, "methods": [summary], "mode": "summary", "next_method_offset": None, "total_methods": 1}
        mine = json.loads(json.dumps(want))
        mine["methods"][0]["declaration"] = ".method public static f()V"
        self.assertEqual(replay.compare_case(self.reference(want), answered(mine))[0], [])
        del mine["methods"][0]["next_offset"]
        self.assertTrue(replay.compare_case(self.reference(want), answered(mine))[0])

    def test_several_mistakes_at_once_may_be_named_in_another_order(self):
        case = {"id": "decode-combo-x", "is_error": True, "reply": refusal(kind="unknown_dataset", message="dataset is not open")}
        _, declared = replay.compare_case(case, answered(refusal(kind="not_found"), True))
        self.assertEqual(declared, "ORDER OF CHECKS")
        problems, _ = replay.compare_case(case, answered(ok()))
        self.assertTrue(problems)


class Golden(unittest.TestCase):
    golden = json.loads(a0_cases.GOLDEN.read_text(encoding="utf-8"))

    def test_it_was_recorded_from_the_pinned_binary(self):
        self.assertEqual(self.golden["reference"]["sha256"], a0_cases.A0_SHA256)
        self.assertEqual(self.golden["reference"]["version"], "0.1.0")

    def test_every_request_that_is_put_has_a_frozen_answer_and_no_other_is_kept(self):
        wanted = {c["id"] for c in a0_cases.all_cases()}
        frozen = {c["id"] for c in self.golden["cases"]}
        self.assertEqual(wanted, frozen)

    def test_the_fixtures_are_the_ones_it_was_recorded_on(self):
        for name, digest in self.golden["fixtures_sha256"].items():
            self.assertEqual(a0_cases.sha256(a0_cases.FIXTURES / name), digest, name)

    def test_every_method_of_the_fixtures_is_in_it(self):
        self.assertEqual(len(self.golden["methods"]), 252)
        self.assertEqual(sum(1 for m in self.golden["methods"] if m["is_error"]), 11)

    def test_what_the_replay_does_not_run_is_the_unimplemented_and_nothing_more(self):
        ids = {c["id"] for c in self.golden["cases"]}
        self.assertTrue(set(replay.NOT_IMPLEMENTED) <= ids)
        self.assertTrue(set(replay.TIMING) <= ids)
        self.assertTrue(set(replay.LENIENT) <= ids)
        self.assertTrue(set(replay.TEXT_LENGTH) <= ids)
        for case_id in replay.NOT_IMPLEMENTED:
            self.assertTrue(any(word in case_id for word in ("class", "context", "xml", "mode")), case_id)


if __name__ == "__main__":
    unittest.main(verbosity=1)
