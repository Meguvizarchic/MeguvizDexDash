#!/usr/bin/env python3
"""Controls for the resource-tool replay (MDD-072): its comparison must be able to fail.

A replay that excuses every difference proves nothing. These cases put synthetic recorded and
served answers to the comparison and the classifier and require that an identical answer is a
match, that each declared class is recognised only for the difference it names, and that any
other difference (a changed value, a lost row, a changed number, an invented attribute) is
not excused.

Usage: python -I conformance/mcp/test_resources_replay.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import resources_replay as rr  # noqa: E402

XML = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    "<manifest\n"
    '  xmlns:android="http://schemas.android.com/apk/res/android"\n'
    '  package="example.test">\n'
    '  <application android:label="x"/>\n'
    "</manifest>\n"
)


def page(text: str) -> dict:
    return {"page": {"text": text, "total_bytes": len(text.encode()), "next_offset": None, "offset": 0,
                     "start_line": 0, "end_line": text.count("\n"), "starts_mid_line": False,
                     "ends_mid_line": False}}


def verdict(record, reference, ours):
    diffs = rr.compare(reference, ours)
    return rr.classify(record, reference, ours, diffs)


XML_RECORD = {"tool": "get_manifest", "arguments": {"mode": "xml"}, "is_error": False}


class Comparison(unittest.TestCase):
    def test_an_identical_answer_is_a_match(self):
        self.assertEqual(verdict(XML_RECORD, page(XML), {**page(XML), "_is_error": False}), ["match"])

    def test_fields_this_engine_adds_are_not_differences_but_others_are(self):
        reference = {"total_rows": 1, "values": []}
        self.assertEqual(rr.compare(reference, {**reference, "source": {"sha256": "x"}, "skipped_chunks": 0}), [])
        self.assertTrue(rr.compare(reference, {**reference, "invented": 1}))

    def test_a_changed_number_or_a_lost_row_is_a_difference(self):
        reference = {"total_rows": 2, "values": [{"name": "a"}, {"name": "b"}]}
        self.assertTrue(rr.compare(reference, {"total_rows": 3, "values": reference["values"]}))
        self.assertTrue(rr.compare(reference, {"total_rows": 2, "values": reference["values"][:1]}))


class XmlClasses(unittest.TestCase):
    def test_a_text_node_is_declared(self):
        ours = XML.replace("</manifest>", "  text\n</manifest>")
        self.assertEqual(rr.xml_classes(XML, ours), {"XML_TEXT_NODES"})

    def test_a_kept_namespace_is_declared(self):
        ours = XML.replace('  package="example.test">', '  xmlns:app="urn:x"\n  package="example.test"\n  app:y="1">')
        self.assertEqual(rr.xml_classes(XML, ours), {"NAMESPACES_KEPT"})

    def test_the_document_prefix_instead_of_android_is_declared(self):
        ours = XML.replace("android:", "a:").replace("xmlns:a:", "xmlns:a")
        self.assertEqual(rr.xml_classes(XML, ours), {"NAMESPACES_KEPT"})

    def test_a_changed_attribute_value_is_not_declared(self):
        self.assertIsNone(rr.xml_classes(XML, XML.replace('"x"', '"y"')))

    def test_a_lost_line_is_not_declared(self):
        self.assertIsNone(rr.xml_classes(XML, XML.replace('  <application android:label="x"/>\n', "")))

    def test_an_invented_element_is_not_declared(self):
        self.assertIsNone(rr.xml_classes(XML, XML.replace("</manifest>", "  <uses-sdk/>\n</manifest>")))

    def test_an_attribute_of_another_name_is_not_declared(self):
        self.assertIsNone(rr.xml_classes(XML, XML.replace("android:label", "android:icon")))


class Values(unittest.TestCase):
    def test_each_value_class_needs_its_own_evidence(self):
        self.assertEqual(rr.value_class("/a", "@android:attr/theme", "@01010000"), "FRAMEWORK_NAMES")
        self.assertEqual(rr.value_class("/a", "a bcde", "a\rb\x0bc\x0cd\x01e"), "CONTROL_CHARS")
        self.assertEqual(rr.value_class("/a", "12", "<0xc06, type Dimension, unit 6>"), "UNKNOWN_UNIT")
        self.assertEqual(rr.value_class("/application/android:protectionLevel", "privileged|signature", "signature"),
                         "ENUM_ON_STRING_TYPE")

    def test_other_differences_are_not_excused(self):
        self.assertIsNone(rr.value_class("/a", "12px", "13px"))
        self.assertIsNone(rr.value_class("/a", "@7f010000", "@7f010001"))
        self.assertIsNone(rr.value_class("/a", "abc", "abd"))
        # an unknown unit is excused only when the reference wrote a bare number
        self.assertIsNone(rr.value_class("/a", "12dip", "<0xc06, type Dimension, unit 6>"))
        # control characters are excused only when removing them gives the reference's text
        self.assertIsNone(rr.value_class("/a", "ab", "a\x01c"))


class Errors(unittest.TestCase):
    def error(self, kind, message="m"):
        return {"error": {"kind": kind, "message": message}}

    def test_the_same_kind_with_other_words_is_declared(self):
        record = {"tool": "read_resource", "arguments": {}, "is_error": True}
        reference = self.error("not_found", "archive entry not found: x")
        ours = {**self.error("not_found", "no such member"), "_is_error": True}
        self.assertEqual(verdict(record, reference, ours), ["ERROR_WORDING"])

    def test_another_kind_is_not_excused(self):
        record = {"tool": "read_resource", "arguments": {}, "is_error": True}
        ours = {**self.error("invalid_input"), "_is_error": True}
        self.assertIsNone(verdict(record, self.error("not_found"), ours))

    def test_a_refusal_where_the_reference_answered_is_excused_only_for_strict_input(self):
        record = {"tool": "query_resources", "arguments": {}, "is_error": False}
        strict = {"error": {"kind": "invalid_resource_table", "message": "not a resource table, or its size field is wrong"},
                  "_is_error": True}
        other = {"error": {"kind": "invalid_resource_table", "message": "something else broke"}, "_is_error": True}
        diffs = [("/is_error", False, True)]
        self.assertEqual(rr.classify(record, {"values": []}, strict, diffs), ["STRICT_INPUT"])
        self.assertIsNone(rr.classify(record, {"values": []}, other, diffs))

    def test_an_answer_where_the_reference_refused_is_not_excused(self):
        record = {"tool": "read_resource", "arguments": {}, "is_error": True}
        diffs = [("/is_error", True, False)]
        self.assertIsNone(rr.classify(record, self.error("not_found"), {"dataset_id": "d", "_is_error": False}, diffs))

    def test_an_argument_range_error_is_declared_only_as_a_json_rpc_error(self):
        record = {"tool": "read_resource", "arguments": {}, "is_error": True}
        reference = self.error("invalid_input")
        ours = {"_is_error": True, "_jsonrpc_error": {"code": -32602, "message": "m"}}
        self.assertEqual(rr.classify(record, reference, ours, [("/jsonrpc_error", 1, 2)]), ["ARGUMENT_RANGE_SHAPE"])
        self.assertIsNone(rr.classify(record, self.error("not_found"), ours, [("/jsonrpc_error", 1, 2)]))


class Rows(unittest.TestCase):
    def test_a_shorter_page_is_a_row_budget_difference_only_for_the_same_rows(self):
        record = {"tool": "query_resources", "arguments": {"max_bytes": 4096}, "is_error": False}
        reference = {"values": [{"n": 1}, {"n": 2}, {"n": 3}], "next_offset": 3}
        ours = {"values": [{"n": 1}, {"n": 2}], "next_offset": 2, "_is_error": False}
        self.assertEqual(verdict(record, reference, ours), ["ROW_BUDGET"])
        other = {"values": [{"n": 1}, {"n": 9}], "next_offset": 2, "_is_error": False}
        self.assertIsNone(verdict(record, reference, other))
        # without a byte budget asked for, a shorter page is not excused
        self.assertIsNone(verdict({**record, "arguments": {}}, reference, ours))


if __name__ == "__main__":
    unittest.main()
