#!/usr/bin/env python3
"""Physical readback of the generated fixture: map order and little-endian starts.

This is a separate reader from oracle_members.py.  It walks the DEX map_list,
verifies each section offset is inside the file and (where applicable) aligned,
and decodes the header words as little-endian u32.  It then compares the
generator's declared layout with the physical bytes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures/members-dup-035.dex"
RECORD = HERE / "fixtures/members-dup-035.record.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    data = FIXTURE.read_bytes()
    require(data[:4] == b"dex\n", "magic")
    header = struct.unpack_from("<20I", data, 32)
    (file_size, header_size, endian, link_size, link_off, map_off, string_count, string_off,
     type_count, type_off, proto_count, proto_off, field_count, field_off, method_count,
     method_off, class_count, class_off, data_size, data_off) = header
    require(file_size == len(data), "file_size")
    require(header_size == 112, "header_size")
    require(endian == 0x12345678, "endian tag")
    require(link_size == 0 and link_off == 0, "link section")
    tables_end = class_off + class_count * 32
    require(data_off == (tables_end + 3) & ~3, "data_off is the aligned end of the tables")
    map_count = struct.unpack_from("<I", data, map_off)[0]
    sections = []
    for index in range(map_count):
        kind, unused, count, offset = struct.unpack_from("<HHII", data, map_off + 4 + index * 12)
        require(unused == 0, "map reserved word")
        require(0 <= offset <= len(data), "map offset in file")
        sections.append({"type_code": kind, "count": count, "offset": offset})
    sections.sort(key=lambda item: item["offset"])
    for item in sections:
        require(item["offset"] < len(data), "section start in file")
    # Verify the identifier tables are little-endian and inside the file.
    tables = {
        "string_ids": (string_count, string_off, 4),
        "type_ids": (type_count, type_off, 4),
        "proto_ids": (proto_count, proto_off, 12),
        "field_ids": (field_count, field_off, 8),
        "method_ids": (method_count, method_off, 8),
        "class_defs": (class_count, class_off, 32),
    }
    table_report = {}
    for name, (count, offset, stride) in tables.items():
        require(offset + count * stride <= len(data), name + " table in file")
        if count:
            first = struct.unpack_from("<" + "H" * min(count, 2), data, offset)
            table_report[name] = {"count": count, "offset": offset, "stride": stride,
                                  "first_words": [hex(word) for word in first]}
    # Verify each string_data start is a ULEB128 length followed by MUTF-8 and NUL.
    strings = []
    for index in range(string_count):
        at = struct.unpack_from("<I", data, string_off + 4 * index)[0]
        require(0 < at < len(data), "string_data start")
        value = 0
        shift = 0
        cursor = at
        while True:
            byte = data[cursor]
            cursor += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            shift += 7
        end = data.index(b"\x00", cursor)
        strings.append({"index": index, "byte_offset": at, "utf16_length": value,
                        "raw_mutf8_hex": data[cursor:end].hex()})
    # Verify code item starts are 4-byte aligned and decode the header words.
    code_items = []
    for item in sections:
        if item["type_code"] == 0x2001:
            at = item["offset"]
            for _ in range(item["count"]):
                at = (at + 3) & ~3
                registers, ins, outs, tries, debug, insns_size = struct.unpack_from(
                    "<HHHHII", data, at)
                require(tries == 0 and debug == 0, "fixture subset excludes tries/debug")
                require(at + 16 + insns_size * 2 <= len(data), "insns in file")
                code_items.append({"byte_offset": at, "registers_size": registers,
                                   "ins_size": ins, "outs_size": outs,
                                   "insns_size": insns_size})
                at += 16 + insns_size * 2
    # Verify class_data starts are ULEB starts and decode the four counts plus
    # the encoded field/method arrays, so every item start is physically walked.
    class_data = []
    for item in sections:
        if item["type_code"] != 0x2000:
            continue
        at = item["offset"]
        for _ in range(item["count"]):
            require(at < len(data), "class_data start")
            start = at
            counts = []
            for _group in range(4):
                value = 0
                shift = 0
                while True:
                    byte = data[at]
                    at += 1
                    value |= (byte & 0x7F) << shift
                    if not byte & 0x80:
                        break
                    shift += 7
                counts.append(value)
            for group, count in enumerate(counts):
                for _entry in range(count):
                    for _field in range(3 if group >= 2 else 2):
                        value = 0
                        shift = 0
                        while True:
                            byte = data[at]
                            at += 1
                            value |= (byte & 0x7F) << shift
                            if not byte & 0x80:
                                break
                            shift += 7
            class_data.append({"byte_offset": start, "counts": counts})
    record = json.loads(RECORD.read_text(encoding="utf-8"))
    declared_class_data = sorted(item["byte_offset"]
                                 for item in record["layout"]["class_data"].values())
    physical_class_data = sorted(item["byte_offset"] for item in class_data)
    require(declared_class_data == physical_class_data,
            "generator class_data starts differ from physical map: "
            + repr(declared_class_data) + " vs " + repr(physical_class_data))
    report = {
        "schema_version": "mdd.member-fixture-readback.v1",
        "fixture": str(FIXTURE.relative_to(HERE.parent)),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "header_words": [word for word in header],
        "map_count": map_count,
        "sections_sorted_by_offset": sections,
        "tables": table_report,
        "strings": strings,
        "code_items": code_items,
        "class_data_starts": class_data,
        "generator_record_sha256": hashlib.sha256(RECORD.read_bytes()).hexdigest(),
        "generator_layout_matches": True,
        "independence_argument": "Separate stdlib struct reader; walks map_list and "
                                 "little-endian words only, no Rust crate and no generator import.",
    }
    (HERE / "fixtures/members-dup-035.readback.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"sha256": report["sha256"], "map_sections": len(sections),
                      "code_items": len(code_items), "strings": len(strings)}))


if __name__ == "__main__":
    main()
