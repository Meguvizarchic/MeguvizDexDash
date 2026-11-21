#!/usr/bin/env python3
"""Deterministic, reviewable fixture writer; never imports production readers."""
from __future__ import annotations

import hashlib
import io
import json
import struct
import warnings
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "generated"
SPEC = "https://source.android.com/docs/core/runtime/dex-format"


def uleb(value: int) -> bytes:
    result = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        result.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(result)


def finalize(data: bytearray, version: str, fields: list[int]) -> bytes:
    data[:8] = b"dex\n" + version.encode("ascii") + b"\0"
    struct.pack_into("<20I", data, 32, len(data), 112, 0x12345678, *fields)
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return bytes(data)


def minimal(version: str) -> bytes:
    data = bytearray(112)
    data.extend(struct.pack("<IHHIIHHII", 2, 0, 0, 1, 0, 0x1000, 0, 1, 112))
    return finalize(data, version, [0, 0, 112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 112])


def string_only() -> bytes:
    # Entries are sorted by decoded UTF-16 units, not encoded octets.
    values = [(0, b""), (1, b"\xc0\x80"), (1, b"A"), (1, b"\xe4\xb8\xad"),
              (1, b"\xed\xa0\x80"), (2, b"\xed\xa0\xbd\xed\xb8\x80"), (1, b"\xed\xb0\x80")]
    data = bytearray(112 + len(values) * 4)
    string_start = len(data)
    for index, (size, encoded) in enumerate(values):
        struct.pack_into("<I", data, 112 + index * 4, len(data))
        data.extend(uleb(size) + encoded + b"\0")
    while len(data) % 4:
        data.append(0)
    map_off = len(data)
    entries = [(0, 1, 0), (1, len(values), 112), (0x2002, len(values), string_start), (0x1000, 1, map_off)]
    data.extend(struct.pack("<I", len(entries)))
    for kind, count, offset in entries:
        data.extend(struct.pack("<HHII", kind, 0, count, offset))
    return finalize(data, "035", [0, 0, map_off, len(values), 112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                   len(data) - string_start, string_start])


def reordered_classes(reverse: bool) -> bytes:
    # Canonically sorted ID tables remain sorted. Independent class definitions
    # may exchange order; all data offsets are rewritten for the new layout.
    strings = [b"Lfixture/A;", b"Lfixture/B;", b"Ljava/lang/Object;", b"V", b"a", b"b"]
    string_off, type_off, proto_off, method_off, class_off, data_off = 112, 136, 152, 164, 180, 244
    data = bytearray(data_off)
    string_start = len(data)
    order = list(reversed(range(6))) if reverse else list(range(6))
    for index in order:
        struct.pack_into("<I", data, string_off + index * 4, len(data))
        data.extend(uleb(len(strings[index])) + strings[index] + b"\0")
    for index in range(4):
        struct.pack_into("<I", data, type_off + index * 4, index)
    struct.pack_into("<III", data, proto_off, 3, 3, 0)
    struct.pack_into("<HHIHHI", data, method_off, 0, 0, 4, 1, 0, 5)
    cdata_start = len(data)
    cdata_offsets = {}
    class_order = [1, 0] if reverse else [0, 1]
    for class_type_idx in class_order:
        cdata_offsets[class_type_idx] = len(data)
        data.extend(b"\0\0\x01\0" + uleb(class_type_idx) + uleb(0x109) + b"\0")
    for ordinal, class_type_idx in enumerate(class_order):
        struct.pack_into("<8I", data, class_off + ordinal * 32, class_type_idx, 1, 2, 0, 0xffffffff, 0,
                         cdata_offsets[class_type_idx], 0)
    while len(data) % 4:
        data.append(0)
    map_off = len(data)
    entries = [(0, 1, 0), (1, 6, string_off), (2, 4, type_off), (3, 1, proto_off),
               (5, 2, method_off), (6, 2, class_off), (0x2002, 6, string_start),
               (0x2000, 2, cdata_start), (0x1000, 1, map_off)]
    data.extend(struct.pack("<I", len(entries)))
    for kind, count, offset in entries:
        data.extend(struct.pack("<HHII", kind, 0, count, offset))
    return finalize(data, "035", [0, 0, map_off, 6, string_off, 4, type_off, 1, proto_off,
                                   0, 0, 2, method_off, 2, class_off, len(data) - data_off, data_off])


def structured() -> tuple[bytes, dict]:
    strings = [b"Lfixture/A;", b"Ljava/lang/Object;", b"V", b"caller", b"nativeNoBody", b"target", b"withTry"]
    string_off, type_off, proto_off, method_off, class_off = 112, 140, 152, 164, 196
    data_off = 228
    data = bytearray(data_off)
    string_start = len(data)
    for index, value in enumerate(strings):
        struct.pack_into("<I", data, string_off + index * 4, len(data))
        data.extend(uleb(len(value)) + value + b"\0")
    for index in range(3):
        struct.pack_into("<I", data, type_off + index * 4, index)
    struct.pack_into("<III", data, proto_off, 2, 2, 0)
    for index, name in enumerate([3, 4, 5, 6]):
        struct.pack_into("<HHI", data, method_off + index * 8, 0, 0, name)
    while len(data) % 4:
        data.append(0)
    code_start = len(data)
    offsets = {}
    bodies = {
        "caller": [0x0071, 2, 0, 0x0071, 2, 0, 0x000e],
        "target": [0x000e],
        "withTry": [0x0012, 0x0027, 0x000d, 0x000e],
    }
    for name, words in bodies.items():
        while len(data) % 4:
            data.append(0)
        offsets[name] = len(data)
        registers = 1 if name == "withTry" else 0
        data.extend(struct.pack("<HHHHII", registers, 0, 0, int(name == "withTry"), 0, len(words)))
        data.extend(struct.pack("<" + "H" * len(words), *words))
        if name == "withTry":
            data.extend(struct.pack("<IHH", 0, 2, 1))
            data.extend(b"\x01\x00\x02")  # one handler, zero typed entries, catch-all PC 2
    class_data_off = len(data)
    data.extend(b"\x00\x00\x04\x00")
    for delta, flags, code in [(0, 9, offsets["caller"]), (1, 0x109, 0), (1, 9, offsets["target"]), (1, 9, offsets["withTry"])]:
        data.extend(uleb(delta) + uleb(flags) + uleb(code))
    struct.pack_into("<8I", data, class_off, 0, 1, 1, 0, 0xffffffff, 0, class_data_off, 0)
    while len(data) % 4:
        data.append(0)
    map_off = len(data)
    entries = [(0, 1, 0), (1, 7, string_off), (2, 3, type_off), (3, 1, proto_off),
               (5, 4, method_off), (6, 1, class_off), (0x2002, 7, string_start),
               (0x2001, 3, code_start), (0x2000, 1, class_data_off), (0x1000, 1, map_off)]
    data.extend(struct.pack("<I", len(entries)))
    for kind, count, offset in entries:
        data.extend(struct.pack("<HHII", kind, 0, count, offset))
    result = finalize(data, "035", [0, 0, map_off, 7, string_off, 3, type_off, 1, proto_off,
                                    0, 0, 4, method_off, 1, class_off, len(data) - data_off, data_off])
    expected = {
        "strings_utf16": [list(value) for value in strings],
        "type_descriptor_string_indices": [0, 1, 2],
        "proto": {"shorty_string_idx": 2, "return_type_idx": 2, "parameters_off": 0},
        "method_refs": [{"method_idx": i, "owner_type_idx": 0, "proto_idx": 0, "name_string_idx": n}
                        for i, n in enumerate([3, 4, 5, 6])],
        "method_definitions": [{"method_idx": 0, "access_flags": 9, "code_off": offsets["caller"]},
                               {"method_idx": 1, "access_flags": 0x109, "code_off": 0},
                               {"method_idx": 2, "access_flags": 9, "code_off": offsets["target"]},
                               {"method_idx": 3, "access_flags": 9, "code_off": offsets["withTry"]}],
        "call_sites": [{"caller_method_idx": 0, "code_unit_pc": pc, "target_method_idx": 2,
                        "opcode": "invoke-static"} for pc in (0, 3)],
        "code_items": [{"name": name, "offset": offsets[name], "insns_hex": struct.pack("<" + "H" * len(words), *words).hex(),
                        "insns_size_code_units": len(words)} for name, words in bodies.items()],
        "try_catch": {"method_idx": 3, "try_start_pc": 0, "try_length": 2, "handler_off": 1,
                      "catch_all_pc": 2, "handler_list_hex": "010002"},
        "claim": "synthetic structural DEX fixture; not externally ART-verified or an installable application",
    }
    return result, expected


def archive(entries: list[tuple[str, bytes]], compression: int) -> bytes:
    target = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(target, "w", compression=compression) as writer:
        warnings.simplefilter("ignore", UserWarning)
        for name, data in entries:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = compression
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            writer.writestr(info, data)
    return target.getvalue()


def axml() -> bytes:
    # RES_XML_TYPE with UTF-8 string pool ["manifest"] and one empty element.
    encoded = b"\x08\x08manifest\0"
    encoded += b"\0" * (-len(encoded) % 4)
    pool = struct.pack("<HH6I", 1, 28, 32 + len(encoded), 1, 0, 0x100, 32, 0) + struct.pack("<I", 0) + encoded
    start = struct.pack("<HHIII", 0x102, 16, 36, 1, 0xffffffff)
    start += struct.pack("<II6H", 0xffffffff, 0, 20, 20, 0, 0, 0, 0)
    end = struct.pack("<HHIIIII", 0x103, 16, 24, 1, 0xffffffff, 0xffffffff, 0)
    return struct.pack("<HHI", 3, 8, 8 + len(pool) + len(start) + len(end)) + pool + start + end


def vectors() -> dict:
    return {
        "mutf8": [
            {"id": "empty", "hex": "00", "utf16_size": 0, "expected_units": []},
            {"id": "nul", "hex": "c08000", "utf16_size": 1, "expected_units": [0]},
            {"id": "bmp", "hex": "e4b8ad00", "utf16_size": 1, "expected_units": [0x4e2d]},
            {"id": "surrogate-pair", "hex": "eda0bdedb88000", "utf16_size": 2, "expected_units": [0xd83d, 0xde00]},
            {"id": "isolated-high", "hex": "eda08000", "utf16_size": 1, "expected_units": [0xd800]},
            {"id": "isolated-low", "hex": "edb08000", "utf16_size": 1, "expected_units": [0xdc00]},
            {"id": "bad-continuation", "hex": "c04100", "utf16_size": 1, "error": "INVALID_MUTF8"},
            {"id": "four-byte-utf8", "hex": "f09f988000", "utf16_size": 2, "error": "INVALID_MUTF8"},
            {"id": "length-mismatch", "hex": "4100", "utf16_size": 2, "error": "STRING_LENGTH_MISMATCH"},
            {"id": "missing-terminator", "hex": "41", "utf16_size": 1, "error": "TRUNCATED"},
            {"id": "overlong-non-nul", "hex": "c18100", "utf16_size": 1, "error": "INVALID_MUTF8"},
            {"id": "three-byte-overlong", "hex": "e0808000", "utf16_size": 1, "error": "INVALID_MUTF8"},
            {"id": "continuation-as-leading", "hex": "8000", "utf16_size": 1, "error": "INVALID_MUTF8"},
            {"id": "truncated-three-byte", "hex": "e4b8", "utf16_size": 1, "error": "TRUNCATED"},
            {"id": "raw-nul-is-terminator", "hex": "00", "utf16_size": 1, "error": "STRING_LENGTH_MISMATCH"},
        ],
        "leb32": [
            {"id": "uleb-zero", "kind": "uleb", "hex": "00", "value": 0},
            {"id": "uleb-max", "kind": "uleb", "hex": "ffffffff0f", "value": 0xffffffff},
            {"id": "uleb-overflow", "kind": "uleb", "hex": "ffffffff10", "error": "LEB_OVERFLOW"},
            {"id": "uleb-truncated", "kind": "uleb", "hex": "80", "error": "TRUNCATED"},
            {"id": "uleb-unterminated", "kind": "uleb", "hex": "8080808080", "error": "LEB_OVERFLOW"},
            {"id": "sleb-minus-one", "kind": "sleb", "hex": "7f", "value": -1},
            {"id": "sleb-minus-128", "kind": "sleb", "hex": "807f", "value": -128},
            {"id": "sleb-minus-64", "kind": "sleb", "hex": "40", "value": -64},
            {"id": "sleb-minus-65", "kind": "sleb", "hex": "bf7f", "value": -65},
            {"id": "sleb-63", "kind": "sleb", "hex": "3f", "value": 63},
            {"id": "sleb-64", "kind": "sleb", "hex": "c000", "value": 64},
            {"id": "sleb-min", "kind": "sleb", "hex": "8080808078", "value": -0x80000000},
            {"id": "sleb-max", "kind": "sleb", "hex": "ffffffff07", "value": 0x7fffffff},
            {"id": "sleb-min-plus-one", "kind": "sleb", "hex": "8180808078", "value": -0x7fffffff},
            {"id": "sleb-max-minus-one", "kind": "sleb", "hex": "feffffff07", "value": 0x7ffffffe},
            {"id": "sleb-positive-overflow", "kind": "sleb", "hex": "8080808008", "error": "LEB_OVERFLOW"},
            {"id": "sleb-negative-overflow", "kind": "sleb", "hex": "ffffffff77", "error": "LEB_OVERFLOW"},
            {"id": "sleb-unsigned-max-is-overflow", "kind": "sleb", "hex": "ffffffff0f", "error": "LEB_OVERFLOW"},
            {"id": "sleb-truncated", "kind": "sleb", "hex": "ff", "error": "TRUNCATED"},
            {"id": "sleb-nonshortest-negative", "kind": "sleb", "hex": "ff7f", "value": -1},
            {"id": "sleb-five-byte-sign-extension", "kind": "sleb", "hex": "ffffffff7f", "value": -1},
            {"id": "uleb-six-bytes", "kind": "uleb", "hex": "808080808000", "error": "LEB_OVERFLOW"},
            {"id": "uleb-nonshortest", "kind": "uleb", "hex": "8000", "value": 0,
             "profile": "bounded-permissive-leb32-v1; non-shortest encodings retained"},
        ],
        "code_layout": [
            {"id": "packed-switch", "kind": "packed-switch-payload", "hex": "000101000000000003000000",
             "expected": {"size": 1, "first_key": 0, "relative_targets": [3]}, "alignment_code_units": 2},
            {"id": "packed-switch-truncated", "kind": "packed-switch-payload", "hex": "0001010000000000", "error": "TRUNCATED"},
            {"id": "sparse-switch", "kind": "sparse-switch-payload", "hex": "00020200ffffffff050000000300000004000000",
             "expected": {"size": 2, "keys": [-1, 5], "relative_targets": [3, 4]}, "alignment_code_units": 2},
            {"id": "array-data", "kind": "array-data-payload", "hex": "000301000300000041424300",
             "expected": {"element_width": 1, "element_count": 3, "data_hex": "414243"}, "alignment_code_units": 2},
            {"id": "array-data-count-overflow", "kind": "array-data-payload", "hex": "00030800ffffffff", "error": "TRUNCATED"},
        ],
    }


def generate() -> dict[str, tuple[bytes, dict]]:
    cases = {}
    for version in ["035", "037", "038", "039", "040"]:
        cases[f"minimal-{version}.dex"] = (minimal(version), {"kind": "dex", "expected": "valid_header_and_map", "version": version})
    for version in ["036", "041"]:
        cases[f"unsupported-{version}.dex"] = (minimal(version), {"kind": "dex", "expected": "UNSUPPORTED_CAPABILITY", "version": version,
            "note": "magic discrimination vector, not a valid implementation of the unsupported format"})
    small = minimal("035")
    full, expected = structured()
    cases["structured-035.dex"] = (full, {"kind": "dex", "expected": "valid_synthetic_structure", "version": "035", "facts": expected})
    cases["strings-mutf8-035.dex"] = (string_only(), {"kind": "dex", "expected": "valid_header_and_strings", "version": "035",
        "strings_utf16": [[], [0], [65], [0x4e2d], [0xd800], [0xd83d, 0xde00], [0xdc00]]})
    for reverse in [False, True]:
        name = "class-reorder-after.dex" if reverse else "class-reorder-before.dex"
        cases[name] = (reordered_classes(reverse), {"kind": "dex", "expected": "valid_reordered_structure", "version": "035",
            "class_type_indices_by_definition_ordinal": [1, 0] if reverse else [0, 1],
            "semantic_equivalence_group": "two-independent-native-classes-v1",
            "note": "class_def table order, string_data order and class_data order differ; all references and offsets must preserve class/method semantics"})
    changed = bytearray(full)
    at = changed.index(b"Lfixture/A;")
    changed[at + 9] = ord("B")
    cases["structured-035-same-size-changed.dex"] = (finalize(changed, "035", list(struct.unpack_from("<17I", changed, 44))),
        {"kind": "dex", "expected": "valid_synthetic_structure", "version": "035", "source_mutation_of": "structured-035.dex", "same_length": True})
    bad_magic = bytearray(small); bad_magic[0] = 0
    cases["bad-magic.dex"] = (bytes(bad_magic), {"kind": "dex", "expected": "INVALID_MAGIC"})
    cases["truncated-header.dex"] = (small[:80], {"kind": "dex", "expected": "TRUNCATED"})
    bad_checksum = bytearray(small); bad_checksum[8] ^= 1
    cases["bad-checksum.dex"] = (bytes(bad_checksum), {"kind": "dex", "expected": "CHECKSUM_MISMATCH"})
    bad_signature = bytearray(small); bad_signature[12] ^= 1
    struct.pack_into("<I", bad_signature, 8, zlib.adler32(bad_signature[12:]) & 0xffffffff)
    cases["bad-signature.dex"] = (bytes(bad_signature), {"kind": "dex", "expected": "SIGNATURE_MISMATCH"})
    bad_map = bytearray(small); struct.pack_into("<I", bad_map, 136, 0xffffffff)
    cases["bad-map-offset.dex"] = (finalize(bad_map, "035", list(struct.unpack_from("<17I", bad_map, 44))), {"kind": "dex", "expected": "INVALID_MAP"})
    overflow = bytearray(small); struct.pack_into("<II", overflow, 56, 0xffffffff, 112)
    cases["table-count-overflow.dex"] = (finalize(overflow, "035", list(struct.unpack_from("<17I", overflow, 44))), {"kind": "dex", "expected": "TABLE_RANGE"})
    binary_xml = axml()
    cases["manifest-minimal.axml"] = (binary_xml, {"kind": "axml", "expected": "valid_chunk_layout", "root_element": "manifest", "string_count": 1})
    broken_xml = bytearray(binary_xml); struct.pack_into("<I", broken_xml, 12, 0xffffffff)
    cases["manifest-bad-chunk.axml"] = (bytes(broken_xml), {"kind": "axml", "expected": "INVALID_CHUNK"})
    entries = [("classes.dex", full), ("classes2.dex", small), ("AndroidManifest.xml", binary_xml), ("assets/raw.bin", b"\0\xffresource")]
    for mode, compression in [("stored", zipfile.ZIP_STORED), ("deflated", zipfile.ZIP_DEFLATED)]:
        cases[f"multidex-{mode}.apk"] = (archive(entries, compression), {"kind": "zip", "expected": "valid_inventory", "member_names": [x[0] for x in entries],
            "dex_member_ordinals": [0, 1], "installable_claim": False})
    renamed = [("renamed.dex" if name == "classes.dex" else name, value) for name, value in entries]
    cases["renamed-member.apk"] = (archive(renamed, 0), {"kind": "zip", "expected": "explicit_selection_required",
        "member_names": [name for name, _ in renamed], "must_preserve_dex_bytes": True})
    cases["duplicate-content.apk"] = (archive([("classes.dex", full), ("classes2.dex", full)], 0),
        {"kind": "zip", "expected": "valid_inventory", "member_names": ["classes.dex", "classes2.dex"],
         "same_local_type_idx_in_distinct_dex": 0, "dex_occurrences": 2, "distinct_dex_content_ids": 1})
    duplicate = [("classes.dex", full), ("classes.dex", small)]
    cases["duplicate-name.apk"] = (archive(duplicate, 0), {"kind": "zip", "expected": "ambiguous_hostlab_inventory", "member_names": [x[0] for x in duplicate], "physical_member_count": 2})
    names = [("classes10.dex", small), ("classes2.dex", small), ("nested/classes.dex", small), ("../escape.dex", small)]
    cases["member-policy.apk"] = (archive(names, 0), {"kind": "zip", "expected": "policy_dependent_inventory", "member_names": [x[0] for x in names],
        "hostlab_selected_member_ordinals": [0, 1], "must_not_extract_member_names_as_paths": True})
    cases["invalid-dex-member.apk"] = (archive([("classes.dex", b"not-a-dex")], 0), {"kind": "zip", "expected": "invalid_selected_dex_magic", "member_names": ["classes.dex"]})
    crc = bytearray(archive([("classes.dex", small)], 0)); payload_off = 30 + len("classes.dex")
    crc[payload_off] ^= 1
    cases["bad-crc.apk"] = (bytes(crc), {"kind": "zip", "expected": "CRC_MISMATCH", "member_names": ["classes.dex"]})
    return cases


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    generated = generate()
    files = []
    for name, (data, meta) in generated.items():
        (OUT / name).write_bytes(data)
        files.append({"id": name.rsplit(".", 1)[0], "path": "tests/fixtures/generated/" + name,
                      "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "origin": "hand-authored synthetic generator", **meta})
    vector_payload = (json.dumps(vectors(), ensure_ascii=True, indent=2) + "\n").encode()
    (OUT / "component-vectors.json").write_bytes(vector_payload)
    files.append({"id": "component-vectors", "path": "tests/fixtures/generated/component-vectors.json", "kind": "component_vectors",
                  "bytes": len(vector_payload), "sha256": hashlib.sha256(vector_payload).hexdigest(), "expected": "per-vector-status"})
    manifest = {"schema_version": "mdd.fixture-manifest.v1", "generator": "tests/fixtures/generate.py", "source_reference": SPEC,
                "source_revision_anchor": "platform/art@6484611fd45e69db9f33f98bfd6864014b030ecf",
                "license": "project-authored test data; no third-party APK redistribution", "installability_verified": False,
                "files": files,
                "fuzz_seed_plan": [
                    {"target": "dex_header_and_checked_tables", "seeds": ["minimal-035.dex", "structured-035.dex", "bad-map-offset.dex", "table-count-overflow.dex"], "status": "seeded_not_fuzzed"},
                    {"target": "mutf8_and_leb32", "seeds": ["strings-mutf8-035.dex", "component-vectors.json"], "status": "seeded_not_fuzzed"},
                    {"target": "code_payload_handlers", "seeds": ["structured-035.dex", "component-vectors.json"], "status": "seeded_not_fuzzed"},
                    {"target": "archive_inventory_crc_and_selection", "seeds": ["multidex-stored.apk", "multidex-deflated.apk", "duplicate-name.apk", "bad-crc.apk", "member-policy.apk"], "status": "seeded_not_fuzzed"},
                    {"target": "axml_chunk_bounds", "seeds": ["manifest-minimal.axml", "manifest-bad-chunk.axml"], "status": "seeded_not_fuzzed"}],
                "not_run": ["fixed AOSP verifier/dexdump", "dexlib2 independent full DEX parser", "AAPT2 resource semantic dump", "production engine differential"]}
    (OUT.parent / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"generated {len(files)} fixture files")


if __name__ == "__main__":
    main()
