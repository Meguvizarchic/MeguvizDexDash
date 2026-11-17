#!/usr/bin/env python3
"""Unit tests for the MDD-044 pipeline benchmark's consumer-side logic.

No engine, no APK, no network: these exercise the codec, the digests, the completeness
gate, the batch-document schema, the MCP cell normalization, the counted line reader,
the stream consumer, the fixture recipe expectations and the encoding evaluation, all
against the committed conformance/protocol/column-batch-cases.json. The mdd-wire/1
contract digest is cross-checked against the independent implementation in
conformance/protocol/generate_wire_cases.py.

Run: python -I -m unittest discover -s benchmarks -p test_producer_consumer_pipeline.py -v
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import struct
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pipe = _load("mdd044_pipeline", HERE / "producer-consumer-pipeline.py")
wiregen = _load("mdd044_wiregen", ROOT / "conformance" / "protocol" / "generate_wire_cases.py")
CASES_PATH = ROOT / "conformance" / "protocol" / "column-batch-cases.json"


def _columns(schema: dict) -> list:
    return [column["name"] for column in schema["columns"]]


def _canonical(schema: dict, rows: list) -> list:
    return pipe.canonical_rows(_columns(schema), rows)


def _encode(case: dict) -> bytes:
    return pipe.encode_columns(_columns(case["schema"]), case["rows"],
                               sequence=case["sequence"], schema=case["schema"])


def _good_terminal(rows: int) -> dict:
    return {"operation_status": "ok", "execution": {"complete": True},
            "response": {"emitted_rows": str(rows), "total_rows": str(rows), "total_rows_exact": True,
                         "truncated": False, "more_available": False, "next_cursor": None},
            "coverage": {"input": "complete", "facts": "complete"}}


def _batch_document(columns: list, rows: list, sequence: int, first_row: int) -> dict:
    return {"columns": list(columns), "first_row": str(first_row), "row_count": len(rows),
            "rows": rows, "schema": "mdd.sdk-batch.v1", "sequence": str(sequence)}


def _line(message: dict) -> bytes:
    return json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def _synth_record(columns: list, rows: list) -> dict:
    decoded = [tuple(pipe.decode_cell(cell) for cell in row) for row in rows]
    return {"status": "ok", "columns": list(columns),
            "canonical_digest": pipe.rows_digest(columns, rows),
            "app_digest": pipe.app_digest(columns, decoded),
            "statistics": pipe.row_statistics(columns, rows)}


class CasesFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(CASES_PATH.read_text(encoding="utf-8"))
        cls.cases = cls.document["cases"]

    def test_file_matches_generator(self):
        self.assertEqual(self.document, pipe.column_batch_cases())

    def test_schema_valid(self):
        pipe.jsonschema.Draft202012Validator(pipe.CASES_SCHEMA).validate(self.document)

    def test_names_unique(self):
        names = [case["name"] for case in self.cases]
        self.assertEqual(len(names), len(set(names)))

    def test_roundtrip_cases(self):
        for case in self.cases:
            if "roundtrip" not in case["expect"]:
                continue
            with self.subTest(case=case["name"]):
                blob = _encode(case)
                decoded = pipe.decode_columns(blob, case["schema"])
                self.assertEqual(decoded["columns"], _columns(case["schema"]))
                self.assertEqual(decoded["row_count"], len(case["rows"]))
                self.assertEqual(len(decoded["rows"]), len(case["rows"]))
                self.assertEqual(decoded["sequence"], str(case["sequence"]))
                self.assertEqual(_canonical(case["schema"], decoded["rows"]),
                                 _canonical(case["schema"], case["rows"]))
                self.assertEqual(pipe.rows_digest(_columns(case["schema"]), decoded["rows"]),
                                 pipe.rows_digest(_columns(case["schema"]), case["rows"]))

    def test_corruption_cases(self):
        for case in self.cases:
            expect = case["expect"]
            if "error" not in expect:
                continue
            with self.subTest(case=case["name"]):
                blob = pipe.corrupt_blob(_encode(case), case["schema"], expect["corrupt"])
                if expect["error"] == "fidelity_mismatch":
                    decoded = pipe.decode_columns(blob, case["schema"])
                    self.assertNotEqual(_canonical(case["schema"], decoded["rows"]),
                                        _canonical(case["schema"], case["rows"]))
                else:
                    with self.assertRaises(pipe.PipelineError) as caught:
                        pipe.decode_columns(blob, case["schema"])
                    self.assertEqual(caught.exception.code, expect["error"])

    def test_all_types_and_ops_covered(self):
        types = set()
        ops = set()
        for case in self.cases:
            for column in case["schema"]["columns"]:
                types.add(column["type"])
            if "corrupt" in case["expect"]:
                ops.add(case["expect"]["corrupt"]["op"])
        self.assertEqual(types, set(pipe.TYPE_TAGS))
        self.assertTrue({"magic", "truncate", "row_count", "descriptor_type", "flip_bitmap",
                         "trailing_bit", "null_slot_byte", "offset_order", "offset_tail",
                         "varlen_null_length", "units_lie", "f64_bits"} <= ops)

    def test_wire_digest_crosscheck_on_representable_cases(self):
        for case in self.cases:
            if "roundtrip" not in case["expect"]:
                continue
            with self.subTest(case=case["name"]):
                surrogate = any(cell["t"] == "text" and ("units" in cell or pipe.has_surrogate(cell.get("v", "")))
                                for row in case["rows"] for cell in row)
                if surrogate:
                    # unpaired surrogates are not representable in the strict-UTF-8 contract digest
                    with self.assertRaises((pipe.PipelineError, UnicodeEncodeError)):
                        pipe.wire_v1_digest(case["schema"], [(case["sequence"], case["rows"])])
                    continue
                wire_rows = [[({"t": "utf8", "v": cell["v"]} if cell["t"] == "text" else cell) for cell in row]
                             for row in case["rows"]]
                reference = wiregen.Digest(case["schema"])
                reference.absorb(case["sequence"], wire_rows)
                self.assertEqual(pipe.wire_v1_digest(case["schema"], [(case["sequence"], case["rows"])]),
                                 reference.state)


class DigestSensitivityTests(unittest.TestCase):
    columns = ["a", "b"]

    def digest(self, rows):
        return pipe.rows_digest(self.columns, rows)

    def test_null_vs_empty_string(self):
        self.assertNotEqual(self.digest([[{"t": "null"}, {"t": "text", "v": ""}]]),
                            self.digest([[{"t": "text", "v": ""}, {"t": "text", "v": ""}]]))

    def test_order_matters(self):
        one = [{"t": "i64", "v": "1"}]
        two = [{"t": "i64", "v": "2"}]
        self.assertNotEqual(self.digest([one, two]), self.digest([two, one]))

    def test_duplicates_matter(self):
        row = [{"t": "i64", "v": "1"}]
        self.assertNotEqual(self.digest([row, row]), self.digest([row]))

    def test_integer_tags_differ_canonical_but_collapse_in_app(self):
        i64 = [[{"t": "i64", "v": "7"}]]
        u64 = [[{"t": "u64", "v": "7"}]]
        self.assertNotEqual(self.digest(i64), self.digest(u64))
        decoded_i = [[pipe.decode_cell(cell) for cell in row] for row in i64]
        decoded_u = [[pipe.decode_cell(cell) for cell in row] for row in u64]
        self.assertEqual(pipe.app_digest(["a"], decoded_i), pipe.app_digest(["a"], decoded_u))
        self.assertEqual(pipe.app_value(7), ["int", "7"])

    def test_f64_nan_payload_and_minus_zero(self):
        a = [[{"t": "f64", "bits": "7ff8000000000001"}]]
        b = [[{"t": "f64", "bits": "7ff8000000000002"}]]
        self.assertNotEqual(self.digest(a), self.digest(b))
        self.assertNotEqual(self.digest([[{"t": "f64", "bits": "8000000000000000"}]]),
                            self.digest([[{"t": "f64", "bits": "0000000000000000"}]]))
        self.assertNotEqual(pipe.app_value(float("nan")), pipe.app_value(0.0))

    def test_surrogate_forms_canonicalize_equal(self):
        v_form = [{"t": "text", "v": "a\ud800b"}]
        units_form = [{"t": "text", "units": v_form[0]["v"].encode("utf-16-be", "surrogatepass").hex()}]
        self.assertEqual(pipe.canonical_cell(v_form[0]), pipe.canonical_cell(units_form[0]))
        self.assertEqual(self.digest([v_form]), self.digest([units_form]))

    def test_column_names_matter(self):
        rows = [[{"t": "i64", "v": "1"}]]
        self.assertNotEqual(pipe.rows_digest(["a"], rows), pipe.rows_digest(["b"], rows))

    def test_mutf8_units_matter(self):
        a = [[{"t": "dex_mutf8", "v": "c080", "utf16_units": "1"}]]
        b = [[{"t": "dex_mutf8", "v": "c080", "utf16_units": "2"}]]
        self.assertNotEqual(self.digest(a), self.digest(b))

    def test_bool_vs_int_and_bytes_vs_text(self):
        self.assertNotEqual(self.digest([[{"t": "bool", "v": True}]]),
                            self.digest([[{"t": "i64", "v": "1"}]]))
        self.assertNotEqual(self.digest([[{"t": "bytes", "v": "61"}]]),
                            self.digest([[{"t": "text", "v": "a"}]]))

    def test_app_value_forms(self):
        self.assertEqual(pipe.app_value(None), ["null"])
        self.assertEqual(pipe.app_value(True), ["bool", True])
        self.assertEqual(pipe.app_value(b"\x00\xff"), ["bytes", "00ff"])
        self.assertEqual(pipe.app_value(pipe.DexMutf8(b"\xc0\x80", 1)), ["mutf8", "c080", 1])
        self.assertEqual(pipe.app_value("\ud800"), ["text16", "d800"])
        with self.assertRaises(pipe.PipelineError):
            pipe.app_value([1, 2])

    def test_row_statistics(self):
        rows = [[{"t": "null"}, {"t": "text", "v": ""}],
                [{"t": "i64", "v": "1"}, {"t": "text", "v": "x"}],
                [{"t": "i64", "v": "1"}, {"t": "text", "v": "x"}]]
        stats = pipe.row_statistics(self.columns, rows)
        self.assertEqual(stats["null_cells"], 1)
        self.assertEqual(stats["rows"], 3)
        self.assertEqual(stats["distinct_rows"], 2)
        self.assertEqual(stats["duplicate_rows"], 1)
        self.assertEqual(stats["type_census"]["a"], {"null": 1, "i64": 2})


class CompletenessGateTests(unittest.TestCase):
    def test_good_terminal_passes(self):
        summary = pipe.require_complete(_good_terminal(3), 3, 3)
        self.assertEqual(summary["emitted_rows"], 3)
        self.assertEqual(summary["total_rows"], 3)
        self.assertTrue(summary["total_rows_exact"])

    def test_fail_closed_matrix(self):
        missing = object()

        def mutated(**changes):
            terminal = _good_terminal(3)
            for path, value in changes.items():
                node = terminal
                keys = path.split(".")
                for key in keys[:-1]:
                    node = node[key]
                if value is missing:
                    node.pop(keys[-1], None)
                else:
                    node[keys[-1]] = value
            return terminal

        matrix = [
            (None, "missing_terminal"),
            (mutated(**{"operation_status": "error"}), "operation_not_ok"),
            (mutated(**{"execution.complete": False}), "execution_incomplete"),
            (mutated(**{"execution.complete": missing}), "execution_incomplete"),
            (mutated(**{"response.truncated": True}), "truncated"),
            (mutated(**{"response.truncated": missing}), "truncated"),
            (mutated(**{"response.more_available": True}), "more_available"),
            (mutated(**{"response.next_cursor": "c1"}), "cursor_left"),
            (mutated(**{"coverage.input": "partial"}), "coverage_incomplete"),
            (mutated(**{"coverage.facts": "unknown"}), "coverage_incomplete"),
            (mutated(**{"response.emitted_rows": 3}), "malformed_terminal"),
            (mutated(**{"response.emitted_rows": "03"}), "malformed_terminal"),
            (mutated(**{"response.emitted_rows": "4"}), "count_mismatch"),
            (mutated(**{"response.total_rows": "9"}), "count_mismatch"),
        ]
        for terminal, code in matrix:
            with self.subTest(code=code):
                with self.assertRaises(pipe.PipelineError) as caught:
                    pipe.require_complete(terminal, 3)
                self.assertEqual(caught.exception.code, code)
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.require_complete(_good_terminal(3), 3, 55763)
        self.assertEqual(caught.exception.code, "row_count_mismatch")


class BatchDocumentValidationTests(unittest.TestCase):
    def document(self, **over):
        doc = _batch_document(["n"], [[{"t": "i64", "v": "1"}]], 0, 0)
        doc.update(over)
        return doc

    def test_good_document(self):
        pipe.validate_batch_document(self.document())

    def test_count_mismatch(self):
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.validate_batch_document(self.document(row_count=2))
        self.assertEqual(caught.exception.code, "count_mismatch")

    def test_row_shape(self):
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.validate_batch_document(self.document(rows=[[{"t": "i64", "v": "1"}, {"t": "null"}]]))
        self.assertEqual(caught.exception.code, "row_shape_mismatch")

    def test_schema_rejections(self):
        bad_docs = [
            self.document(rows=[[{"t": "i64", "v": "01"}]]),
            self.document(rows=[[{"t": "bytes", "v": "AB"}]]),
            self.document(rows=[[{"t": "text", "v": "a", "units": "0061"}]]),
            self.document(rows=[[{"t": "mystery", "v": "1"}]]),
            self.document(rows=[[{"t": "f64", "bits": "00"}]]),
            self.document(schema="mdd.sdk-batch.v2"),
            self.document(sequence="00"),
        ]
        for doc in bad_docs:
            with self.subTest(doc=doc):
                with self.assertRaises(pipe.PipelineError) as caught:
                    pipe.validate_batch_document(doc)
                self.assertEqual(caught.exception.code, "batch_schema_invalid")


class McpCellTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(pipe.mcp_cell_to_sdk({"type": "null"}), {"t": "null"})
        self.assertEqual(pipe.mcp_cell_to_sdk({"type": "int64", "value": -5}), {"t": "i64", "v": "-5"})
        self.assertEqual(pipe.mcp_cell_to_sdk({"type": "uint64", "value": 2**64 - 1}),
                         {"t": "u64", "v": str(2**64 - 1)})
        self.assertEqual(pipe.mcp_cell_to_sdk({"type": "utf8", "value": "é"}), {"t": "text", "v": "é"})
        self.assertEqual(pipe.mcp_cell_to_sdk({"type": "binary", "value": "AB00"}), {"t": "bytes", "v": "ab00"})
        self.assertEqual(pipe.mcp_cell_to_sdk({"type": "float64", "value": 1.5}),
                         {"t": "f64", "bits": "3ff8000000000000"})

    def test_unknown_type_raises(self):
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.mcp_cell_to_sdk({"type": "decimal", "value": "1"})
        self.assertEqual(caught.exception.code, "unknown_mcp_cell_type")


class CodecGuardTests(unittest.TestCase):
    def test_null_in_non_nullable_column(self):
        schema = pipe._schema([("n", "i64", False)])
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.encode_columns(["n"], [[{"t": "null"}]], sequence=0, schema=schema)
        self.assertEqual(caught.exception.code, "cell_type_mismatch")

    def test_mixed_column_types(self):
        columns = ["n"]
        batches = [_batch_document(columns, [[{"t": "i64", "v": "1"}]], 0, 0),
                   _batch_document(columns, [[{"t": "text", "v": "x"}]], 1, 1)]
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.infer_schema(columns, batches, "s")
        self.assertEqual(caught.exception.code, "mixed_column_types")

    def test_all_null_column_is_mixed(self):
        columns = ["n"]
        batches = [_batch_document(columns, [[{"t": "null"}]], 0, 0)]
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.infer_schema(columns, batches, "s")
        self.assertEqual(caught.exception.code, "mixed_column_types")

    def test_integer_range_and_canonical(self):
        schema = pipe._schema([("i", "i64", False), ("u", "u64", False)])
        bad_rows = [
            [[{"t": "i64", "v": str(2**63)}, {"t": "u64", "v": "0"}]],
            [[{"t": "i64", "v": "0"}, {"t": "u64", "v": str(2**64)}]],
            [[{"t": "i64", "v": "-0"}, {"t": "u64", "v": "0"}]],
            [[{"t": "i64", "v": "01"}, {"t": "u64", "v": "0"}]],
        ]
        for rows in bad_rows:
            with self.subTest(rows=rows):
                with self.assertRaises(pipe.PipelineError) as caught:
                    pipe.encode_columns(["i", "u"], rows, sequence=0, schema=schema)
                self.assertEqual(caught.exception.code, "malformed_body")

    def test_mutf8_validation(self):
        self.assertEqual(pipe._mutf8_units(b"\xc0\x80"), 1)
        self.assertEqual(pipe._mutf8_units(b"\xed\xa0\x80"), 1)
        self.assertEqual(pipe._mutf8_units(b"ab"), 2)
        for raw in (b"\x00", b"\xf0\x90\x80\x80", b"\xc0", b"\xe0\x80"):
            with self.subTest(raw=raw):
                with self.assertRaises(pipe.PipelineError):
                    pipe._mutf8_units(raw)
        schema = pipe._schema([("m", "dex_mutf8", False)])
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.encode_columns(["m"], [[{"t": "dex_mutf8", "v": "c080", "utf16_units": "2"}]],
                                sequence=0, schema=schema)
        self.assertEqual(caught.exception.code, "cell_type_mismatch")

    def test_schema_mismatch(self):
        schema = pipe._schema([("n", "i64", False)])
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.encode_columns(["other"], [[{"t": "i64", "v": "1"}]], sequence=0, schema=schema)
        self.assertEqual(caught.exception.code, "schema_mismatch")

    def test_row_shape(self):
        schema = pipe._schema([("n", "i64", False), ("m", "i64", False)])
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.encode_columns(["n", "m"], [[{"t": "i64", "v": "1"}]], sequence=0, schema=schema)
        self.assertEqual(caught.exception.code, "row_shape_mismatch")

    def _patched_blob(self, schema, rows, patch):
        blob = pipe.encode_columns(_columns(schema), rows, sequence=0, schema=schema)
        parts = pipe._split_blob(blob)
        descriptor = parts["descriptors"][0]
        buffer = bytearray(pipe._column_buffer(blob, descriptor))
        patch(buffer, parts, descriptor)
        start = descriptor["offset"]
        return blob[:start] + bytes(buffer) + blob[start + len(buffer):]

    def test_bool_slot_must_be_zero_or_one(self):
        schema = pipe._schema([("b", "bool", False)])
        bitmap_len = pipe._bitmap_bytes(1)

        def patch(buffer, parts, descriptor):
            buffer[bitmap_len] = 2

        blob = self._patched_blob(schema, [[{"t": "bool", "v": True}]], patch)
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.decode_columns(blob, schema)
        self.assertEqual(caught.exception.code, "malformed_body")

    def test_descriptor_flags_must_be_zero(self):
        schema = pipe._schema([("n", "i64", False)])
        blob = bytearray(pipe.encode_columns(["n"], [[{"t": "i64", "v": "1"}]], sequence=0, schema=schema))
        blob[pipe.HEADER.size + 1] = 1
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.decode_columns(bytes(blob), schema)
        self.assertEqual(caught.exception.code, "malformed_body")

    def test_descriptor_name_must_match_schema(self):
        schema = pipe._schema([("n", "i64", False)])
        blob = bytearray(pipe.encode_columns(["n"], [[{"t": "i64", "v": "1"}]], sequence=0, schema=schema))
        blob[pipe.HEADER.size + pipe.DESC_FIXED.size] = ord("x")
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.decode_columns(bytes(blob), schema)
        self.assertEqual(caught.exception.code, "schema_mismatch")

    def test_buffers_must_tile_exactly(self):
        schema = pipe._schema([("n", "i64", False)])
        blob = pipe.encode_columns(["n"], [[{"t": "i64", "v": "1"}]], sequence=0, schema=schema)
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.decode_columns(blob + b"\x00", schema)
        self.assertEqual(caught.exception.code, "buffer_bounds")
        shifted = bytearray(blob)
        struct.pack_into("<Q", shifted, pipe.HEADER.size + pipe.DESC_FIXED.size + 1,
                         struct.unpack_from("<Q", blob, pipe.HEADER.size + pipe.DESC_FIXED.size + 1)[0] + 1)
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.decode_columns(bytes(shifted), schema)
        self.assertEqual(caught.exception.code, "buffer_bounds")

    def test_surrogate_text_roundtrips_to_units(self):
        schema = pipe._schema([("s", "utf8", False)])
        rows = [[{"t": "text", "v": "a\ud800b"}]]
        blob = pipe.encode_columns(["s"], rows, sequence=0, schema=schema)
        decoded = pipe.decode_columns(blob, schema)
        self.assertEqual(decoded["rows"][0][0],
                         {"t": "text", "units": "a\ud800b".encode("utf-16-be", "surrogatepass").hex()})

    def test_f64_bits_survive_exactly(self):
        schema = pipe._schema([("f", "f64", False)])
        bits = ["7ff8000000000001", "7ff8000000000002", "8000000000000000", "fff0000000000000"]
        rows = [[{"t": "f64", "bits": b}] for b in bits]
        decoded = pipe.decode_columns(pipe.encode_columns(["f"], rows, sequence=0, schema=schema), schema)
        self.assertEqual([cell["bits"] for row in decoded["rows"] for cell in row], bits)

    def test_bad_corrupt_ops(self):
        schema = pipe._schema([("n", "i64", False)])
        blob = pipe.encode_columns(["n"], [[{"t": "i64", "v": "1"}]], sequence=0, schema=schema)
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.corrupt_blob(blob, schema, {"op": "nonsense"})
        self.assertEqual(caught.exception.code, "bad_corrupt_op")
        # trailing bits only exist when row_count is not a multiple of 8; with 8 rows there are none
        eight = pipe.encode_columns(["n"], [[{"t": "i64", "v": str(i)}] for i in range(8)],
                                    sequence=0, schema=schema)
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.corrupt_blob(eight, schema, {"op": "trailing_bit", "column": 0})
        self.assertEqual(caught.exception.code, "bad_corrupt_op")


class WireDigestTests(unittest.TestCase):
    def test_crosscheck_with_independent_implementation(self):
        schema = pipe._schema([("i", "i64", True), ("s", "utf8", False)])
        rows = [[{"t": "i64", "v": "-5"}, {"t": "text", "v": "héllo"}],
                [{"t": "null"}, {"t": "text", "v": ""}]]
        wire_rows = [[({"t": "utf8", "v": cell["v"]} if cell["t"] == "text" else cell) for cell in row]
                     for row in rows]
        reference = wiregen.Digest(schema)
        reference.absorb(0, wire_rows)
        reference.absorb(1, [])
        self.assertEqual(pipe.wire_v1_digest(schema, [(0, rows), (1, [])]), reference.state)

    def test_schema_and_cells_change_the_digest(self):
        schema = pipe._schema([("i", "i64", True)])
        rows = [[{"t": "i64", "v": "1"}]]
        base = pipe.wire_v1_digest(schema, [(0, rows)])
        self.assertNotEqual(base, pipe.wire_v1_digest(schema, [(0, [[{"t": "i64", "v": "2"}]])]))
        nullable_flipped = pipe._schema([("i", "i64", False)])
        self.assertNotEqual(base, pipe.wire_v1_digest(nullable_flipped, [(0, rows)]))
        self.assertNotEqual(base, pipe.wire_v1_digest(schema, [(0, rows), (1, [])]))
        self.assertNotEqual(base, pipe.wire_v1_digest(schema, [(7, rows)]))

    def test_surrogate_not_representable(self):
        schema = pipe._schema([("s", "utf8", False)])
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.wire_v1_digest(schema, [(0, [[{"t": "text", "units": "d800"}]])])
        self.assertEqual(caught.exception.code, "not_representable")


class LineReaderTests(unittest.TestCase):
    def setUp(self):
        self.read_fd, self.write_fd = os.pipe()
        self.stream = os.fdopen(self.read_fd, "rb")
        self.reader = pipe.LineReader(self.stream, max_line=64, depth=4)

    def tearDown(self):
        # close the write end first so the reader thread sees EOF and exits promptly;
        # otherwise stop() would join a thread still blocked in readline (5 s timeout)
        try:
            os.close(self.write_fd)
        except OSError:
            pass
        self.reader.stop()

    def deadline(self):
        return time.perf_counter() + 10.0

    def test_lines_bytes_and_timestamps(self):
        os.write(self.write_fd, b'{"kind":"opened"}\n{"kind":"batch"}\n')
        first, arrival1, consumed1 = self.reader.next(self.deadline())
        second, arrival2, consumed2 = self.reader.next(self.deadline())
        self.assertEqual(first, b'{"kind":"opened"}\n')
        self.assertEqual(second, b'{"kind":"batch"}\n')
        self.assertEqual(self.reader.bytes, len(first) + len(second))
        self.assertLessEqual(arrival1, consumed1)
        self.assertLessEqual(arrival2, consumed2)
        self.assertGreaterEqual(self.reader.consumer_wait_seconds, 0.0)

    def test_eof_before_terminal(self):
        os.close(self.write_fd)
        with self.assertRaises(pipe.PipelineError) as caught:
            self.reader.next(self.deadline())
        self.assertEqual(caught.exception.code, "eof_before_terminal")

    def test_partial_line(self):
        os.write(self.write_fd, b"abc")
        os.close(self.write_fd)
        with self.assertRaises(pipe.PipelineError) as caught:
            self.reader.next(self.deadline())
        self.assertEqual(caught.exception.code, "partial_line")

    def test_oversize_line(self):
        # a dedicated pipe: self.reader already owns self.stream, so a second reader there
        # would race for the same bytes
        read_fd, write_fd = os.pipe()
        reader = pipe.LineReader(os.fdopen(read_fd, "rb"), max_line=8, depth=4)
        try:
            os.write(write_fd, b"0123456789\n")
            with self.assertRaises(pipe.PipelineError) as caught:
                reader.next(self.deadline())
            self.assertEqual(caught.exception.code, "oversize_line")
        finally:
            os.close(write_fd)
            reader.stop()

    def test_expect_eof_and_frame_after_terminal(self):
        os.write(self.write_fd, b'{"kind":"terminal"}\n')
        self.reader.next(self.deadline())
        os.close(self.write_fd)
        self.reader.expect_eof(self.deadline())
        read_fd2, write_fd2 = os.pipe()
        reader2 = pipe.LineReader(os.fdopen(read_fd2, "rb"), max_line=64, depth=4)
        try:
            os.write(write_fd2, b'{"kind":"terminal"}\n{"kind":"batch"}\n')
            reader2.next(self.deadline())
            with self.assertRaises(pipe.PipelineError) as caught:
                reader2.expect_eof(self.deadline())
            self.assertEqual(caught.exception.code, "frame_after_terminal")
        finally:
            os.close(write_fd2)
            reader2.stop()

    def test_deadline(self):
        with self.assertRaises(pipe.PipelineError) as caught:
            self.reader.next(time.perf_counter() - 1.0)
        self.assertEqual(caught.exception.code, "deadline_exceeded")


class CountingStdoutTests(unittest.TestCase):
    def test_counts_and_delegation(self):
        real = io.BytesIO(b"line1\nline2\n")
        proxy = pipe.CountingStdout(real)
        self.assertEqual(proxy.readline(-1), b"line1\n")
        self.assertEqual(proxy.readline(64), b"line2\n")
        self.assertEqual(proxy.readline(-1), b"")
        self.assertEqual(proxy.bytes, 12)
        self.assertEqual(proxy.line_bytes, [6, 6])
        self.assertEqual(len(proxy.arrivals), 2)
        proxy.seek(0)
        self.assertEqual(proxy.read(), b"line1\nline2\n")
        proxy.close()
        self.assertTrue(real.closed)


class FakeReader:
    def __init__(self, lines):
        self.lines = list(lines)
        self.consumer_wait_seconds = 0.0

    def next(self, deadline):
        if not self.lines:
            raise pipe.PipelineError("eof_before_terminal", "fake pipe ended")
        raw = self.lines.pop(0)
        now = time.perf_counter()
        return raw, now, now


class StreamConsumeTests(unittest.TestCase):
    columns = ["n"]

    def opened(self):
        return _line({"kind": "opened", "protocol": "mdd.cli-stream.v1", "dataset": {}})

    def batch(self, rows, sequence, first_row, columns=None):
        return _line({"kind": "batch", "id": None,
                      "batch": _batch_document(columns or self.columns, rows, sequence, first_row)})

    def terminal(self, rows):
        return _line({"kind": "terminal", "id": None, "terminal": _good_terminal(rows)})

    def consume(self, lines, expected_rows=None):
        return pipe.consume_query_stream(FakeReader(lines), expected_rows=expected_rows,
                                         deadline=time.perf_counter() + 10.0)

    def test_happy_path(self):
        rows0 = [[{"t": "i64", "v": "1"}]]
        rows1 = [[{"t": "i64", "v": "2"}], [{"t": "null"}]]
        outcome = self.consume([self.opened(), self.batch(rows0, 0, 0), self.batch(rows1, 1, 1),
                                self.terminal(3)], expected_rows=3)
        self.assertEqual(outcome.columns, ("n",))
        self.assertEqual(len(outcome.decoded_rows), 3)
        self.assertEqual(outcome.decoded_rows[2], (None,))
        self.assertEqual(len(outcome.raw_batches), 2)
        self.assertEqual(outcome.terminal["emitted_rows"], 3)

    def test_sequence_gap(self):
        with self.assertRaises(pipe.PipelineError) as caught:
            self.consume([self.opened(), self.batch([[{"t": "i64", "v": "1"}]], 1, 0), self.terminal(1)])
        self.assertEqual(caught.exception.code, "sequence_gap")

    def test_first_row_gap(self):
        with self.assertRaises(pipe.PipelineError) as caught:
            self.consume([self.opened(), self.batch([[{"t": "i64", "v": "1"}]], 0, 5), self.terminal(1)])
        self.assertEqual(caught.exception.code, "sequence_gap")

    def test_column_change(self):
        with self.assertRaises(pipe.PipelineError) as caught:
            self.consume([self.opened(), self.batch([[{"t": "i64", "v": "1"}]], 0, 0),
                          self.batch([[{"t": "i64", "v": "2"}]], 1, 1, columns=["other"]),
                          self.terminal(2)])
        self.assertEqual(caught.exception.code, "schema_mismatch")

    def test_rejected(self):
        with self.assertRaises(pipe.PipelineError) as caught:
            self.consume([self.opened(), _line({"kind": "rejected", "error": {"code": "X"}})])
        self.assertEqual(caught.exception.code, "rejected")

    def test_unknown_kind(self):
        with self.assertRaises(pipe.PipelineError) as caught:
            self.consume([self.opened(), _line({"kind": "progress"})])
        self.assertEqual(caught.exception.code, "protocol_fault")

    def test_bad_opened(self):
        with self.assertRaises(pipe.PipelineError) as caught:
            self.consume([_line({"kind": "batch"})])
        self.assertEqual(caught.exception.code, "protocol_fault")

    def test_truncated_terminal_refused(self):
        terminal = _good_terminal(1)
        terminal["response"]["truncated"] = True
        with self.assertRaises(pipe.PipelineError) as caught:
            self.consume([self.opened(), self.batch([[{"t": "i64", "v": "1"}]], 0, 0),
                          _line({"kind": "terminal", "terminal": terminal})])
        self.assertEqual(caught.exception.code, "truncated")

    def test_eof_before_terminal(self):
        with self.assertRaises(pipe.PipelineError) as caught:
            self.consume([self.opened(), self.batch([[{"t": "i64", "v": "1"}]], 0, 0)])
        self.assertEqual(caught.exception.code, "eof_before_terminal")


class FixtureRecipeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixtures = pipe.build_fixtures(Path(self.temp.name))

    def test_recipe_shape(self):
        export = self.fixtures["expected"]["counterexample-export"]
        nulls = self.fixtures["expected"]["counterexample-null"]
        self.assertEqual(len(export), 3)
        self.assertEqual(len(nulls), 3)
        keys = [(row[1]["v"], row[3]["v"], row[4]["v"]) for row in export]
        self.assertEqual(len(keys) - len(set(keys)), 1)
        for row in nulls:
            self.assertEqual(row[0], {"t": "null"})
            self.assertEqual(row[1], {"t": "text", "v": ""})
        # the recipe must carry each file's own method name, not a blanket "foo": the uni
        # fixture's method is "méthode_中文😀"; this is checked against the known fixture
        # construction, independently of the engine and of the recipe's own digest
        self.assertEqual(nulls[0][2], {"t": "text", "v": "méthode_中文😀"})
        self.assertEqual(nulls[1][2], {"t": "text", "v": "foo"})
        self.assertEqual(nulls[2][2], {"t": "text", "v": "foo"})
        self.assertEqual(export[0][3], {"t": "text", "v": "méthode_中文😀"})
        self.assertEqual(export[0][1], {"t": "text", "v": "Ldemo/Ü;"})
        self.assertEqual(len(self.fixtures["paths"]), 3)
        for path in self.fixtures["paths"]:
            self.assertTrue(Path(path).is_file())

    def test_check_counterexample_passes_on_recipe(self):
        export_columns = ["file_id", "class_descriptor", "method_idx", "method_name", "method_descriptor"]
        null_columns = ["maybe_null", "empty_text", "method_name"]
        for label, columns in (("counterexample-export", export_columns), ("counterexample-null", null_columns)):
            rows = self.fixtures["expected"][label]
            record = _synth_record(columns, rows)
            result = pipe.check_counterexample(record, rows, label)
            self.assertTrue(result["matched"])

    def test_null_turned_empty_is_refused(self):
        columns = ["maybe_null", "empty_text", "method_name"]
        rows = [list(row) for row in self.fixtures["expected"]["counterexample-null"]]
        rows[0][0] = {"t": "text", "v": ""}
        record = _synth_record(columns, rows)
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.check_counterexample(record, self.fixtures["expected"]["counterexample-null"],
                                      "counterexample-null")
        self.assertEqual(caught.exception.code, "counterexample_digest")

    def test_merged_duplicate_is_refused(self):
        columns = ["file_id", "class_descriptor", "method_idx", "method_name", "method_descriptor"]
        rows = self.fixtures["expected"]["counterexample-export"][:2]
        record = _synth_record(columns, rows)
        with self.assertRaises(pipe.PipelineError) as caught:
            pipe.check_counterexample(record, self.fixtures["expected"]["counterexample-export"],
                                      "counterexample-export")
        self.assertEqual(caught.exception.code, "counterexample_digest")


class EvaluateEncodingsTests(unittest.TestCase):
    def setUp(self):
        self.columns = ["n", "s"]
        self.rows0 = [[{"t": "u64", "v": "1"}, {"t": "text", "v": "é"}]]
        self.rows1 = [[{"t": "u64", "v": "2"}, {"t": "text", "v": "中文"}],
                      [{"t": "u64", "v": "3"}, {"t": "null"}]]
        self.documents = [_batch_document(self.columns, self.rows0, 0, 0),
                          _batch_document(self.columns, self.rows1, 1, 1)]
        self.raw = [(_line({"kind": "batch", "id": "q1", "batch": doc}), doc) for doc in self.documents]

    def test_fidelity_and_reserialization(self):
        evaluation = pipe.evaluate_encodings(self.raw, self.columns, request_id="q1")
        self.assertEqual(evaluation["reserialization_mismatches"], 0)
        self.assertEqual(evaluation["totals"]["rows"], 3)
        self.assertEqual(evaluation["totals"]["batches"], 2)
        self.assertTrue(all(evaluation["fidelity"][key] for key in
                            ("columns_equal", "row_count_equal", "canonical_cells_equal", "canonical_digest_equal")))
        self.assertIsNotNone(evaluation["wire_v1_contract_digest"])
        self.assertGreater(evaluation["totals"]["json_body_bytes"], 0)
        self.assertGreater(evaluation["totals"]["columns_body_bytes"], 0)

    def test_wrong_request_id_counts_mismatches(self):
        evaluation = pipe.evaluate_encodings(self.raw, self.columns, request_id=None)
        self.assertEqual(evaluation["reserialization_mismatches"], 2)

    def test_distortion_is_vetoed(self):
        real_decode = pipe.decode_columns

        def distorted(blob, schema):
            decoded = real_decode(blob, schema)
            decoded["rows"][0][0] = {"t": "u64", "v": "999"}
            return decoded

        with mock.patch.object(pipe, "decode_columns", distorted):
            with self.assertRaises(pipe.PipelineError) as caught:
                pipe.evaluate_encodings(self.raw, self.columns, request_id="q1")
        self.assertEqual(caught.exception.code, "fidelity_cells")

    def test_wire_digest_matches_independent_implementation(self):
        evaluation = pipe.evaluate_encodings(self.raw, self.columns, request_id="q1")
        schema = evaluation["schema"]
        wire_rows = [[({"t": "utf8", "v": cell["v"]} if cell["t"] == "text" else cell) for cell in row]
                     for row in self.rows0 + self.rows1]
        reference = wiregen.Digest(schema)
        reference.absorb(0, wire_rows[:1])
        reference.absorb(1, wire_rows[1:])
        self.assertEqual(evaluation["wire_v1_contract_digest"], reference.state)


if __name__ == "__main__":
    unittest.main()