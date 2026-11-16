#!/usr/bin/env python3
"""Controls for run_decode_full.py and oracle_class.py: the checks must see what they are there to see.

A check that cannot fail proves nothing, so each kind of fault the full decode runner is meant to find is put to its helpers
here, and the independent reader's own arithmetic (floats, values, debug programs) is held to known answers.

Usage: python -I conformance/decode/test_decode_full.py
"""
from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "conformance" / "mcp"))
import oracle_class as oc  # noqa: E402
import run_decode_full as full  # noqa: E402

TEXT = ".method a\n    .registers 1\n\n    nop\n.end method\n"


def page(text: str, offset: int, piece: str, last: bool, **changes) -> dict:
    data = text.encode()
    end = offset + len(piece.encode())
    row = {
        "smali": piece, "offset": offset, "next_offset": None if last else end,
        "total_bytes": len(data), "total_lines": full.lines_of(text),
        "start_line": data[:offset].count(b"\n"),
        "starts_mid_line": offset > 0 and data[offset - 1:offset] != b"\n",
        "ends_mid_line": 0 < end < len(data) and data[end - 1:end] != b"\n",
    }
    touched = data[offset:end].count(b"\n") + (1 if end > offset and data[end - 1:end] != b"\n" else 0)
    row["end_line"] = row["start_line"] + touched
    row.update(changes)
    return row


def pages_of(text: str, cuts: list[int]) -> list[dict]:
    data = text.encode()
    edges = [0, *cuts, len(data)]
    return [page(text, a, data[a:b].decode(), b == len(data)) for a, b in zip(edges, edges[1:])]


class PageNumbers(unittest.TestCase):
    def test_correct_pages_are_accepted(self):
        self.assertEqual(full.check_page_numbers(pages_of(TEXT, []), TEXT), "")
        self.assertEqual(full.check_page_numbers(pages_of(TEXT, [5, 27]), TEXT), "")

    def test_a_wrong_offset_is_found(self):
        rows = pages_of(TEXT, [5, 27])
        rows[1]["offset"] = 6
        self.assertIn("offset", full.check_page_numbers(rows, TEXT))

    def test_a_next_offset_that_continues_in_the_wrong_place_is_found(self):
        rows = pages_of(TEXT, [5, 27])
        rows[0]["next_offset"] = 4
        self.assertIn("next_offset", full.check_page_numbers(rows, TEXT))

    def test_a_last_page_that_names_a_continuation_is_found(self):
        rows = pages_of(TEXT, [5])
        rows[-1]["next_offset"] = len(TEXT.encode())
        self.assertIn("next_offset", full.check_page_numbers(rows, TEXT))

    def test_pages_that_do_not_cover_the_text_are_found(self):
        rows = pages_of(TEXT, [5, 27])[:-1]
        rows[-1]["next_offset"] = None
        self.assertNotEqual(full.check_page_numbers(rows, TEXT), "")

    def test_a_wrong_line_number_or_flag_is_found(self):
        for key, value in (("start_line", 1), ("end_line", 9), ("starts_mid_line", False), ("ends_mid_line", True), ("total_lines", 99), ("total_bytes", 1)):
            rows = pages_of(TEXT, [5, 27])
            rows[1][key] = value
            self.assertNotEqual(full.check_page_numbers(rows, TEXT), "", key)

    def test_a_page_with_other_text_is_found(self):
        rows = pages_of(TEXT, [5])
        rows[0]["smali"] = ".metho"
        self.assertNotEqual(full.check_page_numbers(rows, TEXT), "")

    def test_bytes_are_not_characters(self):
        text = "é中\nx\n"
        self.assertEqual(full.check_page_numbers(pages_of(text, [2, 5]), text), "")
        rows = pages_of(text, [2, 5])
        rows[1]["offset"] = 1  # a character count would say 1
        self.assertNotEqual(full.check_page_numbers(rows, text), "")


class Reader(unittest.TestCase):
    def test_floats(self):
        f32 = lambda x: struct.unpack("<I", struct.pack("<f", x))[0]
        f64 = lambda x: struct.unpack("<Q", struct.pack("<d", x))[0]
        for bits, width, want in [
            (f32(1.0), 32, "1.0f"), (f32(0.1), 32, "0.1f"), (f32(-0.0), 32, "-0.0f"), (f32(1e16), 32, "1.0e16f"), (f32(1e-5), 32, "1.0e-5f"),
            (f64(0.1), 64, "0.1"), (f64(1e15), 64, "1000000000000000.0"), (f64(1e16), 64, "1.0e16"), (f64(5e-324), 64, "5.0e-324"),
            (0x7fc01234, 32, "NaNf"), (0xff800000, 32, "-Infinityf"), (0x7ff0000000000000, 64, "Infinity"),
        ]:
            self.assertEqual(oc.float_text(bits, width), want)

    def test_a_context_numbers_the_lines_of_the_full_text(self):
        text = ".method f()V\n    .registers 1\n\n    :goto_0\n    nop\n    goto :goto_0\n.end method\n"
        view = oc.context(text)
        self.assertEqual(view.splitlines()[1:], ["line 0: .method f()V", "line 1:     .registers 1", "line 3:     :goto_0"])
        for entry in view.splitlines()[1:]:
            number, line = entry[5:].split(": ", 1)
            self.assertEqual(text.splitlines()[int(number)], line)

    def test_a_debug_program_is_read_by_its_opcodes(self):
        # line_start 10, no parameters: prologue, position(+0,+0), advance_pc 2, position(+0,+1), end
        program = bytes([10, 0, 0x07, 0x0E, 0x01, 2, 0x0F, 0x00])
        data = bytearray(program)
        events = self.read(data)
        self.assertEqual([(e["op"], e["pc"], e["line"]) for e in events], [(7, 0, 10), (0x0E, 0, 10), (1, 2, 10), (0x0F, 2, 11), (0, 2, None)])

    @staticmethod
    def read(program: bytearray) -> list[dict]:
        class Fake:
            data = bytes(program)
        return oc.debug_program(Fake, 0)[1]

    def test_the_pc_to_pc_pattern_is_recognised_only_whole(self):
        names, events = [], [{"op": 0x0E}, {"op": 0x1E}, {"op": 0x1E}, {"op": 0}]
        self.assertTrue(oc.pc_to_pc(1, names, events))
        self.assertFalse(oc.pc_to_pc(5, names, events))
        self.assertFalse(oc.pc_to_pc(1, [3], events))
        self.assertFalse(oc.pc_to_pc(1, names, [{"op": 0x0E}, {"op": 0x2E}, {"op": 0}]))


class Hand(unittest.TestCase):
    def test_every_hand_entry_names_a_known_fixture_and_kind(self):
        entries = full.read_hand()
        self.assertGreaterEqual(len(entries), 11)
        for fixture, kind, descriptor in entries:
            self.assertIn(fixture, full.FIXTURES)
            self.assertIn(kind, full.KINDS)
            self.assertTrue(descriptor.startswith("L"))

    def test_the_hand_texts_end_with_a_newline_and_the_header_comment_is_not_an_entry(self):
        for text in full.read_hand().values():
            self.assertTrue(text.endswith("\n"))
            self.assertFalse(text.startswith("###"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
