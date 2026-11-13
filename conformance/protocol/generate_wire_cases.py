#!/usr/bin/env python3
"""Generate mdd-wire/1 conformance cases from an independent implementation.

Usage: python -I generate_wire_cases.py OUTPUT_JSON

This script re-implements the framing layout, the cell JSON form and the
integrity digest of docs/02_ARCHITECTURE_AND_CONTRACTS.md section 10 with only
`struct`, `json` and `hashlib`; it shares no code with crates/mdd-wire. The Rust
tests decode these bytes and must reach the recorded verdicts. A case lists the
expected *outcome*, not the Rust implementation's output.
"""
import hashlib
import json
import struct
import sys

MAGIC = b"MDDW"
KINDS = {"hello": 1, "request": 2, "schema": 3, "batch": 4, "progress": 5,
         "end": 6, "error": 7, "cancel": 8, "credit": 9}
TAGS = {"bool": 1, "i64": 2, "u64": 3, "f64": 4, "utf8": 5, "bytes": 6, "dex_mutf8": 7}


def header(kind=4, flags=0, stream=1, body=0, major=1, minor=0, header_bytes=32, magic=MAGIC):
    return (magic + struct.pack("<HHHHIQQ", major, minor, kind, flags, header_bytes, stream, body))


def frame_bytes(kind, stream, body: bytes, **kw):
    return header(kind=KINDS[kind] if isinstance(kind, str) else kind, stream=stream, body=len(body), **kw) + body


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


# ---- cells --------------------------------------------------------------

def c_null(): return {"t": "null"}
def c_bool(v): return {"t": "bool", "v": v}
def c_i64(v): return {"t": "i64", "v": str(v)}
def c_u64(v): return {"t": "u64", "v": str(v)}
def c_f64_bits(bits): return {"t": "f64", "bits": "%016x" % bits}
def c_utf8(v): return {"t": "utf8", "v": v}
def c_bytes(b): return {"t": "bytes", "v": b.hex()}
def c_mutf8(b, units): return {"t": "dex_mutf8", "v": b.hex(), "utf16_units": str(units)}


def lp(b: bytes) -> bytes:
    return struct.pack("<Q", len(b)) + b


def cell_digest(cell) -> bytes:
    t = cell["t"]
    if t == "null": return b"\x00"
    if t == "bool": return bytes([TAGS["bool"], 1 if cell["v"] else 0])
    if t == "i64": return bytes([TAGS["i64"]]) + struct.pack("<q", int(cell["v"]))
    if t == "u64": return bytes([TAGS["u64"]]) + struct.pack("<Q", int(cell["v"]))
    if t == "f64": return bytes([TAGS["f64"]]) + struct.pack("<Q", int(cell["bits"], 16))
    if t == "utf8": return bytes([TAGS["utf8"]]) + lp(cell["v"].encode("utf-8"))
    if t == "bytes": return bytes([TAGS["bytes"]]) + lp(bytes.fromhex(cell["v"]))
    if t == "dex_mutf8":
        return bytes([TAGS["dex_mutf8"]]) + lp(bytes.fromhex(cell["v"])) + struct.pack("<Q", int(cell["utf16_units"]))
    raise ValueError(t)


def schema_canonical(schema) -> bytes:
    out = lp(schema["schema_id"].encode()) + struct.pack("<Q", len(schema["columns"]))
    for column in schema["columns"]:
        out += struct.pack("<I", column["ordinal"]) + lp(column["stable_id"].encode())
        out += bytes([TAGS[column["type"]], 1 if column["nullable"] else 0])
    return out


class Digest:
    def __init__(self, schema):
        self.state = hashlib.sha256(b"mdd-wire/1\0digest\0" + schema_canonical(schema)).hexdigest()

    def absorb(self, sequence, rows):
        buffer = self.state.encode() + b"|" + struct.pack("<Q", sequence) + struct.pack("<Q", len(rows))
        for row in rows:
            for cell in row:
                buffer += cell_digest(cell)
        self.state = hashlib.sha256(buffer).hexdigest()


def col(ordinal, stable, name, ty, nullable=True):
    return {"ordinal": ordinal, "stable_id": stable, "name": name, "type": ty, "nullable": nullable}


def schema_of(columns, schema_id="mdd.rows.v1:case"):
    return {"schema_id": schema_id, "columns": columns}


def f(kind, stream, value=None, text=None):
    body = text if text is not None else compact(value)
    return {"kind": kind, "stream_id": stream, "body_text": body}


def batch_body(schema, seq, rows, **over):
    body = {"schema_id": schema["schema_id"], "sequence": str(seq), "row_count": str(len(rows)), "rows": rows}
    body.update(over)
    return body


def stream_frames(schema, batch_list, stream=1, end=True, **end_over):
    digest = Digest(schema)
    frames = [f("schema", stream, schema)]
    total = 0
    for sequence, rows in enumerate(batch_list):
        frames.append(f("batch", stream, batch_body(schema, sequence, rows)))
        digest.absorb(sequence, rows)
        total += len(rows)
    if end:
        summary = {"rows": str(total), "batches": str(len(batch_list)), "digest": digest.state}
        summary.update(end_over)
        frames.append(f("end", stream, summary))
    return frames


def complete(rows, batches):
    return {"complete": {"rows": rows, "batches": batches}}


def failure(kind, at=None, rows_received=None):
    out = {"error": kind}
    if at is not None:
        out["at_frame"] = at
    if rows_received is not None:
        out["rows_received"] = rows_received
    return out


# ---- cases --------------------------------------------------------------

def frame_cases():
    ok_body = compact({"x": 1}).encode()
    cases = []

    def add(name, data: bytes, expect, max_body=1 << 20):
        cases.append({"name": name, "hex": data.hex(), "max_body_bytes": max_body, "expect": expect})

    def ok(*frames):
        return {"frames": [{"kind": k, "stream_id": s, "body_hex": b.hex()} for k, s, b in frames]}

    add("clean_end_of_input_is_no_frame", b"", ok())
    add("one_request_frame", frame_bytes("request", 1, ok_body), ok(("request", 1, ok_body)))
    add("empty_body_cancel", frame_bytes("cancel", 7, b""), ok(("cancel", 7, b"")))
    add("two_frames_back_to_back", frame_bytes("progress", 2, ok_body) + frame_bytes("end", 2, b"{}"),
        ok(("progress", 2, ok_body), ("end", 2, b"{}")))
    add("optional_high_flag_is_ignored", header(kind=2, flags=0x0100, body=len(ok_body)) + ok_body, ok(("request", 1, ok_body)))
    add("minor_version_above_zero_is_accepted", header(kind=2, minor=5, body=len(ok_body)) + ok_body, ok(("request", 1, ok_body)))
    add("bad_magic", header(magic=b"MDDX"), failure("bad_magic"))
    add("major_two", header(major=2), failure("unsupported_version"))
    add("major_zero", header(major=0), failure("unsupported_version"))
    add("header_bytes_31", header(header_bytes=31), failure("bad_header_length"))
    add("header_bytes_33", header(header_bytes=33), failure("bad_header_length"))
    add("header_bytes_64", header(header_bytes=64), failure("bad_header_length"))
    add("frame_kind_zero", header(kind=0), failure("unknown_frame_kind"))
    add("frame_kind_ten", header(kind=10), failure("unknown_frame_kind"))
    add("frame_kind_65535", header(kind=65535), failure("unknown_frame_kind"))
    add("required_flag_bit0", header(kind=2, flags=1), failure("unknown_required_flag"))
    add("required_flag_bit7", header(kind=2, flags=0x80), failure("unknown_required_flag"))
    add("required_flag_with_optional", header(kind=2, flags=0x0101), failure("unknown_required_flag"))
    add("body_exceeds_limit", header(kind=4, body=1025), failure("frame_too_large"), max_body=1024)
    add("body_u64_max_is_rejected_before_reading", header(kind=4, body=2**64 - 1), failure("frame_too_large"), max_body=1024)
    add("body_exactly_at_limit", header(kind=4, body=4) + b"abcd", ok(("batch", 1, b"abcd")), max_body=4)
    add("truncated_header_one_byte", b"M", failure("truncated_header"))
    add("truncated_header_31_bytes", header(kind=2)[:31], failure("truncated_header"))
    add("truncated_body", header(kind=4, body=10) + b"abc", failure("truncated_body"))
    add("declared_body_with_no_bytes", header(kind=4, body=1), failure("truncated_body"))
    add("good_frame_then_half_header", frame_bytes("progress", 1, ok_body) + b"MDDW\x01\x00", failure("truncated_header"))
    add("good_frame_then_bad_magic", frame_bytes("progress", 1, ok_body) + header(magic=b"JUNK"), failure("bad_magic"))
    return cases


def hello_body(versions, max_frame, encodings):
    return {"protocol": "mdd-wire", "versions": [{"major": a, "minor": b} for a, b in versions],
            "max_frame_bytes": str(max_frame), "encodings": encodings}


def negotiation_cases():
    cases = []

    def add(name, local, peer, expect):
        cases.append({"name": name, "local": local, "peer": peer, "expect": expect})

    base = hello_body([(1, 0)], 4096, ["json"])
    add("agree_on_json_and_smaller_frame", hello_body([(1, 2)], 1 << 20, ["json"]), base,
        {"agreed": {"major": 1, "minor": 0, "max_frame_bytes": 4096, "encoding": "json"}})
    add("highest_common_minor", hello_body([(1, 3)], 8192, ["json"]), hello_body([(1, 1)], 8192, ["json"]),
        {"agreed": {"major": 1, "minor": 1, "max_frame_bytes": 8192, "encoding": "json"}})
    add("local_preference_picks_first_common_readable_encoding",
        hello_body([(1, 0)], 8192, ["columns-v1", "json"]), hello_body([(1, 0)], 8192, ["json", "columns-v1"]),
        {"agreed": {"major": 1, "minor": 0, "max_frame_bytes": 8192, "encoding": "json"}})
    add("no_common_major", hello_body([(2, 0)], 8192, ["json"]), base, failure("negotiation_failed"))
    add("common_major_that_is_not_implemented", hello_body([(2, 0), (1, 0)], 8192, ["json"]),
        hello_body([(2, 0)], 8192, ["json"]), failure("negotiation_failed"))
    add("no_common_encoding", hello_body([(1, 0)], 8192, ["columns-v1"]), hello_body([(1, 0)], 8192, ["columns-v1"]),
        failure("negotiation_failed"))
    add("frame_size_below_minimum", hello_body([(1, 0)], 512, ["json"]), base, failure("negotiation_failed"))
    add("frame_size_exactly_minimum", hello_body([(1, 0)], 1024, ["json"]), hello_body([(1, 0)], 1 << 30, ["json"]),
        {"agreed": {"major": 1, "minor": 0, "max_frame_bytes": 1024, "encoding": "json"}})
    return cases


def stream_cases():
    cases = []

    def add(name, frames, expect, stream=1, limits=None, grants=None, note=None):
        case = {"name": name, "stream_id": stream, "frames": frames, "expect": expect}
        if limits:
            case["limits"] = limits
        if grants:
            case["credit_grants"] = grants
        if note:
            case["note"] = note
        cases.append(case)

    one = schema_of([col(0, "c0", "n", "i64", False)])
    rows3 = [[c_i64(1)], [c_i64(2)], [c_i64(2)]]
    wide = schema_of([
        col(0, "b", "b", "bool"), col(1, "i", "i", "i64"), col(2, "u", "u", "u64"), col(3, "f", "f", "f64"),
        col(4, "s", "s", "utf8"), col(5, "y", "y", "bytes"), col(6, "m", "m", "dex_mutf8"),
    ])
    full_row = [c_bool(True), c_i64(-2**63), c_u64(2**64 - 1), c_f64_bits(0x7ff8000000000001),
                c_utf8("é\U0001f600"), c_bytes(b"\x00\xff"), c_mutf8(b"\xed\xa0\x80", 1)]
    null_row = [c_null()] * 7
    empties = [c_bool(False), c_i64(0), c_u64(0), c_f64_bits(0x8000000000000000), c_utf8(""), c_bytes(b""), c_mutf8(b"", 0)]
    inf_row = [c_bool(True), c_i64(2**63 - 1), c_u64(0), c_f64_bits(0x7ff0000000000000), c_utf8("NULL"), c_bytes(b"NULL"), c_mutf8(b"\xc0\x80", 1)]

    add("complete_zero_rows", stream_frames(one, []), complete([], 0))
    add("complete_one_batch_duplicate_rows_kept", stream_frames(one, [rows3]), complete(rows3, 1))
    add("complete_every_type_null_empty_and_extremes", stream_frames(wide, [[full_row, null_row, empties, inf_row, full_row]]),
        complete([full_row, null_row, empties, inf_row, full_row], 1))
    add("complete_with_an_empty_batch_in_the_middle", stream_frames(one, [[[c_i64(1)]], [], [[c_i64(2)]]]),
        complete([[c_i64(1)], [c_i64(2)]], 3))
    dup_names = schema_of([col(0, "a", "same", "i64"), col(1, "b", "same", "utf8")])
    add("complete_display_names_may_repeat", stream_frames(dup_names, [[[c_i64(1), c_utf8("x")]]]),
        complete([[c_i64(1), c_utf8("x")]], 1))
    add("complete_on_another_stream_id", stream_frames(one, [rows3], stream=9), complete(rows3, 1), stream=9)

    good = stream_frames(one, [rows3, rows3])
    add("err_sequence_starts_at_one", [good[0], f("batch", 1, batch_body(one, 1, rows3))], failure("sequence_gap", 1))
    seq_dup = stream_frames(one, [rows3, rows3], end=False)
    seq_dup[2] = f("batch", 1, batch_body(one, 0, rows3))
    add("err_duplicate_batch_sequence", seq_dup, failure("sequence_gap", 2))
    swapped = stream_frames(one, [rows3, rows3], end=False)
    swapped[1], swapped[2] = swapped[2], swapped[1]
    add("err_batches_out_of_order", swapped, failure("sequence_gap", 1))
    add("err_batch_before_schema", [good[1]], failure("unexpected_frame", 0))
    add("err_second_schema", [good[0], good[0]], failure("unexpected_frame", 1))
    add("err_end_before_schema", [f("end", 1, {"rows": "0", "batches": "0", "digest": "0" * 64})], failure("unexpected_frame", 0))
    add("err_end_states_too_many_rows", stream_frames(one, [rows3], rows="4"), failure("count_mismatch", 2))
    add("err_end_states_too_few_rows", stream_frames(one, [rows3], rows="2"), failure("count_mismatch", 2))
    add("err_end_states_wrong_batch_count", stream_frames(one, [rows3], batches="2"), failure("count_mismatch", 2))
    flipped = stream_frames(one, [rows3])
    tampered = [[c_i64(1)], [c_i64(3)], [c_i64(2)]]
    flipped[1] = f("batch", 1, batch_body(one, 0, tampered))
    add("err_value_changed_after_digest", flipped, failure("digest_mismatch", 2))
    reordered = stream_frames(one, [[[c_i64(1)], [c_i64(2)]]])
    reordered[1] = f("batch", 1, batch_body(one, 0, [[c_i64(2)], [c_i64(1)]]))
    add("err_row_order_changed_after_digest", reordered, failure("digest_mismatch", 2))
    nulled = stream_frames(wide, [[full_row]])
    nulled[1] = f("batch", 1, batch_body(wide, 0, [[c_null()] + full_row[1:]]))
    add("err_null_replaced_a_value", nulled, failure("digest_mismatch", 2))
    empty_for_null = stream_frames(wide, [[null_row]])
    empty_for_null[1] = f("batch", 1, batch_body(wide, 0, [[c_null()] * 4 + [c_utf8("")] + [c_null()] * 2]))
    add("err_empty_string_for_null", empty_for_null, failure("digest_mismatch", 2))
    mutf8_units = stream_frames(wide, [[full_row]])
    changed_units = list(full_row)
    changed_units[6] = c_mutf8(b"\xed\xa0\x80", 2)
    mutf8_units[1] = f("batch", 1, batch_body(wide, 0, [changed_units]))
    add("err_utf16_unit_count_changed", mutf8_units, failure("digest_mismatch", 2))
    nan_payload = stream_frames(wide, [[full_row]])
    other_nan = list(full_row)
    other_nan[3] = c_f64_bits(0x7ff8000000000002)
    nan_payload[1] = f("batch", 1, batch_body(wide, 0, [other_nan]))
    add("err_nan_payload_changed", nan_payload, failure("digest_mismatch", 2))
    add("err_schema_id_changed_in_a_batch", [good[0], f("batch", 1, batch_body(one, 0, rows3, schema_id="mdd.rows.v1:other"))],
        failure("schema_invalid", 1))
    add("err_row_count_lies", [good[0], f("batch", 1, batch_body(one, 0, rows3, row_count="5"))], failure("count_mismatch", 1))
    add("err_ragged_row", [good[0], f("batch", 1, batch_body(one, 0, [[c_i64(1), c_i64(2)]]))], failure("row_shape_mismatch", 1))
    add("err_short_row", [stream_frames(wide, [])[0], f("batch", 1, batch_body(wide, 0, [[c_bool(True)]]))],
        failure("row_shape_mismatch", 1))
    add("err_wrong_cell_type", [good[0], f("batch", 1, batch_body(one, 0, [[c_utf8("1")]]))], failure("cell_type_mismatch", 1))
    add("err_u64_cell_in_i64_column", [good[0], f("batch", 1, batch_body(one, 0, [[c_u64(1)]]))], failure("cell_type_mismatch", 1))
    add("err_null_in_non_nullable_column", [good[0], f("batch", 1, batch_body(one, 0, [[c_null()]]))], failure("cell_type_mismatch", 1))
    add("err_sequence_is_not_canonical_decimal", [good[0], f("batch", 1, batch_body(one, 0, rows3, sequence="00"))],
        failure("malformed_body", 1))
    add("err_i64_not_canonical", [good[0], f("batch", 1, batch_body(one, 0, [[{"t": "i64", "v": "+1"}]]))], failure("malformed_body", 1))
    add("err_i64_out_of_range", [good[0], f("batch", 1, batch_body(one, 0, [[{"t": "i64", "v": "9223372036854775808"}]]))],
        failure("malformed_body", 1))
    add("err_i64_negative_zero", [good[0], f("batch", 1, batch_body(one, 0, [[{"t": "i64", "v": "-0"}]]))], failure("malformed_body", 1))
    add("err_i64_as_json_number", [good[0], f("batch", 1, batch_body(one, 0, [[{"t": "i64", "v": 1}]]))], failure("malformed_body", 1))
    add("err_bytes_uppercase_hex", [stream_frames(wide, [])[0], f("batch", 1, batch_body(wide, 0, [[c_null()] * 5 + [{"t": "bytes", "v": "FF"}, c_null()]]))],
        failure("malformed_body", 1))
    add("err_f64_as_json_number", [stream_frames(wide, [])[0], f("batch", 1, batch_body(wide, 0, [[c_null()] * 3 + [{"t": "f64", "v": 1.5}] + [c_null()] * 3]))],
        failure("malformed_body", 1))
    add("err_unknown_cell_field", [good[0], f("batch", 1, batch_body(one, 0, [[{"t": "i64", "v": "1", "extra": 1}]]))], failure("malformed_body", 1))
    add("err_unknown_cell_tag", [good[0], f("batch", 1, batch_body(one, 0, [[{"t": "decimal", "v": "1"}]]))], failure("malformed_body", 1))
    add("err_unknown_batch_field", [good[0], f("batch", 1, batch_body(one, 0, rows3, extra=1))], failure("malformed_body", 1))
    add("err_body_is_not_json", [f("schema", 1, text="not json")], failure("malformed_body", 0))
    add("err_schema_ordinal_gap", [f("schema", 1, schema_of([col(0, "a", "a", "i64"), col(2, "b", "b", "i64")]))], failure("schema_invalid", 0))
    add("err_schema_repeated_stable_id", [f("schema", 1, schema_of([col(0, "a", "x", "i64"), col(1, "a", "y", "i64")]))], failure("schema_invalid", 0))
    add("err_schema_no_columns", [f("schema", 1, schema_of([]))], failure("schema_invalid", 0))
    add("err_schema_unknown_type", [f("schema", 1, schema_of([col(0, "a", "a", "decimal")]))], failure("schema_invalid", 0))
    add("err_frame_for_another_stream", [good[0], f("batch", 2, batch_body(one, 0, rows3))], failure("bad_stream_id", 1))
    add("err_request_frame_in_a_response", [good[0], f("request", 1, {"op": "x"})], failure("unexpected_frame", 1))
    add("err_missing_end_is_a_disconnect", stream_frames(one, [rows3], end=False), failure("disconnected", rows_received=3))
    add("err_nothing_at_all_is_a_disconnect", [], failure("disconnected", rows_received=0))
    add("err_schema_only_is_a_disconnect", stream_frames(one, [], end=False), failure("disconnected", rows_received=0))
    dup_end = stream_frames(one, [rows3])
    add("err_duplicate_end", dup_end + [dup_end[-1]], failure("frame_after_terminal", 3))
    add("err_batch_after_end", dup_end + [f("batch", 1, batch_body(one, 1, rows3))], failure("frame_after_terminal", 3))
    err_frame = f("error", 1, {"code": "QUOTA_EXCEEDED", "message": "budget", "details": {"budget": "max_rows"}})
    add("err_error_terminal_after_rows_is_a_failure", stream_frames(one, [rows3], end=False) + [err_frame],
        {"error": "peer_error", "rows_received": 3, "peer_code": "QUOTA_EXCEEDED"})
    add("err_error_terminal_with_no_rows", [err_frame], {"error": "peer_error", "rows_received": 0, "peer_code": "QUOTA_EXCEEDED"})
    add("err_error_then_end_is_not_a_success", stream_frames(one, [rows3], end=False) + [err_frame, dup_end[-1]],
        failure("frame_after_terminal", 3))
    add("err_end_then_error", dup_end + [err_frame], failure("frame_after_terminal", 3))
    add("err_peer_cancel", stream_frames(one, [rows3], end=False) + [f("cancel", 1, text="{}")], failure("cancelled", rows_received=3))
    add("err_error_body_unknown_field", [f("error", 1, {"code": "X", "message": "m", "extra": 1})], failure("malformed_body", 0))
    add("progress_frames_are_ignored_but_must_be_json", [good[0], f("progress", 1, {"rows": "0"})] + good[1:],
        complete(rows3 + rows3, 2))
    add("err_progress_not_json", [good[0], f("progress", 1, text="[")], failure("malformed_body", 1))

    big = schema_of([col(0, "s", "s", "utf8")])
    add("err_cell_over_the_hard_limit", stream_frames(big, [[[c_utf8("x" * 33)]]], end=False),
        failure("cell_too_large", 1), limits={"max_cell_bytes": 32})
    add("complete_cell_exactly_at_the_hard_limit", stream_frames(big, [[[c_utf8("x" * 32)]]]),
        complete([[c_utf8("x" * 32)]], 1), limits={"max_cell_bytes": 32})
    add("err_more_rows_than_a_batch_may_hold", stream_frames(one, [rows3], end=False), failure("batch_too_large", 1),
        limits={"max_rows_per_batch": 2})
    many = stream_frames(one, [rows3, rows3, rows3], end=False)
    add("err_buffer_quota_across_batches", many, failure("buffer_quota", 3), limits={"max_buffered_bytes": 330})
    size = len(many[1]["body_text"].encode())
    add("err_batch_without_credit", stream_frames(one, [rows3], end=False), failure("credit_exceeded", 1),
        limits={"enforce_credit": True})
    add("complete_within_granted_credit", stream_frames(one, [rows3, rows3]), complete(rows3 + rows3, 2),
        limits={"enforce_credit": True}, grants=[{"bytes": 2 * size, "batches": 2}])
    add("err_byte_credit_runs_out", stream_frames(one, [rows3, rows3], end=False), failure("credit_exceeded", 2),
        limits={"enforce_credit": True}, grants=[{"bytes": size + size // 2, "batches": 5}])
    add("err_batch_credit_runs_out", stream_frames(one, [rows3, rows3], end=False), failure("credit_exceeded", 2),
        limits={"enforce_credit": True}, grants=[{"bytes": 10 * size, "batches": 1}])
    add("zero_stream_id_is_rejected", stream_frames(one, [], stream=0), failure("bad_stream_id"), stream=0)
    return cases


def main():
    document = {
        "schema_version": "mdd.wire-v1-cases.v1",
        "generator": "conformance/protocol/generate_wire_cases.py",
        "independence": "framing, cell JSON and digest are re-implemented here with struct/json/hashlib; no code is shared with crates/mdd-wire",
        "digest": "state0 = sha256('mdd-wire/1\\0digest\\0' + schema_canonical); state = sha256(hex(state) + '|' + u64le(sequence) + u64le(rows) + cell bytes...)",
        "frame_cases": frame_cases(),
        "negotiation_cases": negotiation_cases(),
        "stream_cases": stream_cases(),
    }
    with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(document, ensure_ascii=False, indent=1) + "\n")
    print(f"frame={len(document['frame_cases'])} negotiation={len(document['negotiation_cases'])} stream={len(document['stream_cases'])}")


if __name__ == "__main__":
    main()
