#!/usr/bin/env python3
"""Independent bounded reference checks; no imports from fixture writer or Rust."""
from __future__ import annotations

import hashlib
import io
import json
import struct
import sys
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class Invalid(ValueError):
    pass


def require(condition, error):
    if not condition:
        raise Invalid(error)


def leb(data, signed=False):
    value = 0
    for index in range(5):
        require(index < len(data), "TRUNCATED")
        octet = data[index]
        value |= (octet & 127) << (index * 7)
        if octet < 128:
            width = (index + 1) * 7
            if signed and octet & 64:
                value -= 1 << width
            lower, upper = (-2**31, 2**31 - 1) if signed else (0, 2**32 - 1)
            require(lower <= value <= upper, "LEB_OVERFLOW")
            return value, index + 1
    raise Invalid("LEB_OVERFLOW")


def leb_radix_reference(data, signed=False):
    # A second arithmetic formulation: sign-extended last base-128 digit,
    # then right-to-left Horner evaluation, rather than bit shifts by position.
    terminal = next((i for i, value in enumerate(data[:5]) if value < 128), None)
    if terminal is None:
        raise Invalid("TRUNCATED" if len(data) < 5 else "LEB_OVERFLOW")
    result = (data[terminal] & 127) - (128 if signed and data[terminal] & 64 else 0)
    for octet in reversed(data[:terminal]):
        result = result * 128 + (octet & 127)
    require((-2**31 <= result <= 2**31 - 1) if signed else (0 <= result <= 2**32 - 1), "LEB_OVERFLOW")
    return result, terminal + 1


def mutf(data, length):
    units = []
    offset = 0
    while True:
        require(offset < len(data), "TRUNCATED")
        first = data[offset]; offset += 1
        if first == 0:
            require(len(units) == length, "STRING_LENGTH_MISMATCH")
            return units
        if first < 128:
            value = first
        elif 0xc0 <= first <= 0xdf:
            require(offset < len(data), "TRUNCATED")
            second = data[offset]; offset += 1
            require(second & 0xc0 == 0x80, "INVALID_MUTF8")
            value = ((first & 31) << 6) | (second & 63)
            require(value == 0 or value >= 128, "INVALID_MUTF8")
        elif 0xe0 <= first <= 0xef:
            require(offset + 2 <= len(data), "TRUNCATED")
            second, third = data[offset:offset + 2]; offset += 2
            require(second & 0xc0 == 0x80 and third & 0xc0 == 0x80, "INVALID_MUTF8")
            value = ((first & 15) << 12) | ((second & 63) << 6) | (third & 63)
            require(value >= 2048, "INVALID_MUTF8")
        else:
            raise Invalid("INVALID_MUTF8")
        units.append(value)


def mutf_codec_reference(data, length):
    # Python's UTF-8 implementation is independent of the handwritten decoder.
    # Replace DEX's sole allowed overlong encoding (NUL), reject four-byte UTF-8,
    # and preserve surrogate units explicitly through surrogatepass.
    end = data.find(b"\0")
    require(end >= 0, "TRUNCATED")
    encoded = data[:end]
    require(not any(octet >= 0xf0 for octet in encoded), "INVALID_MUTF8")
    try:
        decoded = encoded.replace(b"\xc0\x80", b"\0").decode("utf-8", "surrogatepass")
    except UnicodeDecodeError as exc:
        raise Invalid("INVALID_MUTF8") from exc
    utf16 = decoded.encode("utf-16-le", "surrogatepass")
    result = list(struct.unpack("<" + "H" * (len(utf16) // 2), utf16))
    require(len(result) == length, "STRING_LENGTH_MISMATCH")
    return result


def dex(data):
    require(len(data) >= 8, "TRUNCATED")
    require(data[:4] == b"dex\n" and data[7] == 0, "INVALID_MAGIC")
    require(data[4:7] in [b"035", b"037", b"038", b"039", b"040"], "UNSUPPORTED_CAPABILITY")
    require(len(data) >= 112, "TRUNCATED")
    h = struct.unpack_from("<20I", data, 32)
    require(h[0] == len(data) and h[1] == 112 and h[2] == 0x12345678, "INVALID_HEADER")
    require(struct.unpack_from("<I", data, 8)[0] == zlib.adler32(data[12:]) & 0xffffffff, "CHECKSUM_MISMATCH")
    require(data[12:32] == hashlib.sha1(data[32:]).digest(), "SIGNATURE_MISMATCH")
    for position, stride in [(6, 4), (8, 4), (10, 12), (12, 8), (14, 8), (16, 32)]:
        count, offset = h[position:position + 2]
        require((count == 0 and offset == 0) or (offset >= 112 and offset % 4 == 0 and count <= (len(data) - offset) // stride), "TABLE_RANGE")
    map_off = h[5]
    require(map_off >= 112 and map_off % 4 == 0 and map_off + 4 <= len(data), "INVALID_MAP")
    n = struct.unpack_from("<I", data, map_off)[0]
    require(n <= (len(data) - map_off - 4) // 12, "INVALID_MAP")
    entries = [struct.unpack_from("<HHII", data, map_off + 4 + i * 12) for i in range(n)]
    require(all(unused == 0 and count > 0 and off < len(data) for _, unused, count, off in entries), "INVALID_MAP")
    require(len({e[0] for e in entries}) == n and [e[3] for e in entries] == sorted(e[3] for e in entries), "INVALID_MAP")
    require((0, 0, 1, 0) in entries and (0x1000, 0, 1, map_off) in entries, "INVALID_MAP")
    result = {"version": data[4:7].decode(), "strings_utf16": [], "map_entries": len(entries), "class_count": h[16], "method_ref_count": h[14]}
    for index in range(h[6]):
        off = struct.unpack_from("<I", data, h[7] + index * 4)[0]
        require(112 <= off < len(data), "STRING_RANGE")
        length, consumed = leb(data[off:])
        result["strings_utf16"].append(mutf(data[off + consumed:], length))
    return result


def class_semantics(data):
    base = dex(data)
    strings = ["".join(chr(unit) for unit in units) for units in base["strings_utf16"]]
    h = struct.unpack_from("<20I", data, 32)
    types = []
    for ordinal in range(h[8]):
        index = struct.unpack_from("<I", data, h[9] + ordinal * 4)[0]
        require(index < len(strings), "TYPE_INDEX")
        types.append(strings[index])
    protos = []
    for ordinal in range(h[10]):
        shorty, result, parameters = struct.unpack_from("<III", data, h[11] + ordinal * 12)
        require(shorty < len(strings) and result < len(types) and parameters == 0, "PROTO_INDEX")
        require(strings[shorty] == "V" and types[result] == "V", "PROTO_EXPECTATION")
        protos.append("()" + types[result])
    methods = []
    for ordinal in range(h[14]):
        owner, proto, name = struct.unpack_from("<HHI", data, h[15] + ordinal * 8)
        require(owner < len(types) and proto < len(protos) and name < len(strings), "METHOD_INDEX")
        methods.append({"owner": types[owner], "name": strings[name], "proto": protos[proto]})
    result, physical = [], []
    for ordinal in range(h[16]):
        owner, flags, parent, interfaces, source, annotations, class_data, values = struct.unpack_from("<8I", data, h[17] + ordinal * 32)
        require(owner < len(types) and parent < len(types), "CLASS_TYPE_INDEX")
        require(interfaces == annotations == values == 0 and source == 0xffffffff, "CLASS_EXPECTATION")
        require(h[19] <= class_data < len(data), "CLASS_DATA_RANGE")
        counts, pos = [], class_data
        for _ in range(4):
            count, length = leb(data[pos:]); pos += length; counts.append(count)
        require(counts == [0, 0, 1, 0], "CLASS_COUNTS")
        method_id, length = leb(data[pos:]); pos += length
        method_flags, length = leb(data[pos:]); pos += length
        code_off, length = leb(data[pos:])
        require(method_id < len(methods) and methods[method_id]["owner"] == types[owner], "CLASS_METHOD_OWNER")
        require(method_flags == 0x109 and code_off == 0, "NATIVE_METHOD_EXPECTATION")
        result.append({"descriptor": types[owner], "flags": flags, "superclass": types[parent],
                       "methods": [{**methods[method_id], "flags": method_flags, "body": None}]})
        physical.append({"class_def_idx": ordinal, "type_idx": owner, "descriptor": types[owner], "class_data_off": class_data, "method_ref_idx": method_id})
    require(len({entry["descriptor"] for entry in result}) == len(result), "DUPLICATE_CLASS")
    return {"semantic_classes": sorted(result, key=lambda item: item["descriptor"]), "physical_mapping": physical,
            "string_data_offsets": [struct.unpack_from("<I", data, h[7] + i * 4)[0] for i in range(h[6])]}


def xml_layout(data):
    require(len(data) >= 8, "INVALID_CHUNK")
    kind, header, size = struct.unpack_from("<HHI", data)
    require(kind == 3 and header == 8 and size == len(data), "INVALID_CHUNK")
    offset, kinds = header, []
    while offset < size:
        require(offset + 8 <= size, "INVALID_CHUNK")
        kind, header, length = struct.unpack_from("<HHI", data, offset)
        require(8 <= header <= length and length <= size - offset and length % 4 == 0, "INVALID_CHUNK")
        kinds.append(kind); offset += length
    require(kinds == [1, 0x102, 0x103], "INVALID_CHUNK")
    return {"chunk_types": kinds, "semantic_validation": "not_run"}


def payload(vector):
    data = bytes.fromhex(vector["hex"])
    require(len(data) >= 4, "TRUNCATED")
    ident, size = struct.unpack_from("<HH", data)
    if vector["kind"] == "packed-switch-payload":
        require(ident == 0x100 and len(data) == 8 + size * 4, "TRUNCATED")
        return {"size": size, "first_key": struct.unpack_from("<i", data, 4)[0],
                "relative_targets": list(struct.unpack_from("<" + "i" * size, data, 8))}
    if vector["kind"] == "sparse-switch-payload":
        require(ident == 0x200 and len(data) == 4 + size * 8, "TRUNCATED")
        keys = list(struct.unpack_from("<" + "i" * size, data, 4))
        require(keys == sorted(set(keys)), "INVALID_KEYS")
        return {"size": size, "keys": keys,
                "relative_targets": list(struct.unpack_from("<" + "i" * size, data, 4 + size * 4))}
    require(ident == 0x300 and len(data) >= 8, "TRUNCATED")
    count = struct.unpack_from("<I", data, 4)[0]
    require(size in [1, 2, 4, 8] and size * count <= len(data) - 8, "TRUNCATED")
    return {"element_width": size, "element_count": count, "data_hex": data[8:8 + size * count].hex()}


def main():
    manifest = json.loads((ROOT / "tests/fixtures/manifest.json").read_text())
    expected = json.loads((ROOT / "conformance/oracles/expected-results.json").read_text())
    checks, failures = [], []
    for fixture in manifest["files"]:
        data = (ROOT / fixture["path"]).read_bytes()
        require(len(data) == fixture["bytes"] and hashlib.sha256(data).hexdigest() == fixture["sha256"], "FIXTURE_IDENTITY")
        observed = None
        try:
            if fixture["kind"] == "dex":
                observed = dex(data)
                require(fixture["expected"].startswith("valid_"), "UNEXPECTED_ACCEPT")
                if fixture["id"] == "strings-mutf8-035":
                    require(observed["strings_utf16"] == expected["strings-mutf8-035"]["strings_utf16"], "STRING_EXPECTATION")
                if fixture["id"].startswith("class-reorder-"):
                    semantic = class_semantics(data)
                    require(semantic["semantic_classes"] == expected["class-reorder"]["semantic_classes"], "REORDER_SEMANTIC_EXPECTATION")
                    require([row["type_idx"] for row in semantic["physical_mapping"]] == fixture["class_type_indices_by_definition_ordinal"], "REORDER_PHYSICAL_EXPECTATION")
                    observed["class_reorder"] = semantic
                if fixture["id"] == "structured-035":
                    require(observed["strings_utf16"] == expected["structured-035"]["strings_utf16"], "STRING_EXPECTATION")
                    h = struct.unpack_from("<20I", data, 32)
                    require([struct.unpack_from("<I", data, h[9] + i * 4)[0] for i in range(h[8])] == [0, 1, 2], "TYPE_EXPECTATION")
                    methods = [struct.unpack_from("<HHI", data, h[15] + i * 8) for i in range(h[14])]
                    require(methods == [(0, 0, 3), (0, 0, 4), (0, 0, 5), (0, 0, 6)], "METHOD_EXPECTATION")
                    cdata = struct.unpack_from("<I", data, h[17] + 24)[0]
                    require(data[cdata:cdata + 4] == b"\0\0\x04\0", "CLASS_DATA_EXPECTATION")
                    pos, method_index = cdata + 4, 0
                    definitions = []
                    for _ in range(4):
                        delta, n = leb(data[pos:]); pos += n
                        flags, n = leb(data[pos:]); pos += n
                        code, n = leb(data[pos:]); pos += n
                        method_index += delta
                        definitions.append({"method_idx": method_index, "access_flags": flags, "code_off": code})
                    require(definitions == expected["structured-035"]["method_definitions"], "DEFINITION_EXPECTATION")
                    sites = []
                    for code in expected["structured-035"]["code_items"]:
                        count = struct.unpack_from("<I", data, code["offset"] + 12)[0]
                        raw = data[code["offset"] + 16:code["offset"] + 16 + count * 2]
                        require(count == code["insns_size_code_units"] and raw.hex() == code["insns_hex"], "RAW_CODE_EXPECTATION")
                        if code["name"] == "caller":
                            words = struct.unpack("<7H", raw)
                            require(words == (0x71, 2, 0, 0x71, 2, 0, 0xe), "INVOKE_LAYOUT")
                            sites = [{"caller_method_idx": 0, "code_unit_pc": pc, "target_method_idx": words[pc + 1], "opcode": "invoke-static"} for pc in [0, 3]]
                        if code["name"] == "withTry":
                            tail = code["offset"] + 16 + count * 2
                            require(struct.unpack_from("<IHH", data, tail) == (0, 2, 1) and data[tail + 8:tail + 11] == b"\x01\0\x02", "HANDLER_EXPECTATION")
                    require(sites == expected["structured-035"]["call_sites"], "CALL_SITE_MULTIPLICITY")
            elif fixture["kind"] == "axml":
                observed = xml_layout(data)
                require(fixture["expected"] == "valid_chunk_layout", "UNEXPECTED_ACCEPT")
            elif fixture["kind"] == "zip":
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    members = archive.infolist()
                    require([m.filename for m in members] == fixture["member_names"], "MEMBER_OCCURRENCES")
                    try:
                        for item in members:
                            archive.read(item)
                    except zipfile.BadZipFile as exc:
                        raise Invalid("CRC_MISMATCH") from exc
                    require(fixture["expected"] != "CRC_MISMATCH", "UNEXPECTED_ACCEPT")
                    if fixture["expected"] == "ambiguous_hostlab_inventory":
                        require(len(members) == 2 and members[0].filename == members[1].filename, "AMBIGUITY_EXPECTATION")
                    if fixture["expected"] == "invalid_selected_dex_magic":
                        require(archive.read(members[0])[:4] != b"dex\n", "MAGIC_EXPECTATION")
                    if fixture["id"] == "duplicate-content":
                        require(len(members) == 2 and archive.read(members[0]) == archive.read(members[1]), "OCCURRENCE_EXPECTATION")
                        require(dex(archive.read(members[0]))["method_ref_count"] == 4, "LOCAL_ID_EXPECTATION")
                    observed = {"physical_members": len(members), "names": [m.filename for m in members], "profile_classification": fixture["expected"]}
            elif fixture["kind"] == "component_vectors":
                values = json.loads(data)
                for group, items in values.items():
                    for item in items:
                        try:
                            if group == "mutf8":
                                actual = mutf(bytes.fromhex(item["hex"]), item["utf16_size"])
                                require(actual == mutf_codec_reference(bytes.fromhex(item["hex"]), item["utf16_size"]), "INDEPENDENT_MUTF_EXPECTATION")
                                require(actual == item.get("expected_units"), "VECTOR_EXPECTATION")
                            elif group == "leb32":
                                actual, n = leb(bytes.fromhex(item["hex"]), item["kind"] == "sleb")
                                require((actual, n) == leb_radix_reference(bytes.fromhex(item["hex"]), item["kind"] == "sleb"), "INDEPENDENT_LEB_EXPECTATION")
                                require(actual == item.get("value") and n == len(bytes.fromhex(item["hex"])), "VECTOR_EXPECTATION")
                            else:
                                require(payload(item) == item.get("expected"), "VECTOR_EXPECTATION")
                            require("error" not in item, "UNEXPECTED_ACCEPT")
                            checks.append({"case": group + "/" + item["id"], "status": "passed"})
                        except Invalid as exc:
                            if str(exc) == item.get("error"):
                                if group in ["mutf8", "leb32"]:
                                    reference_error = None
                                    try:
                                        if group == "mutf8":
                                            mutf_codec_reference(bytes.fromhex(item["hex"]), item["utf16_size"])
                                        else:
                                            leb_radix_reference(bytes.fromhex(item["hex"]), item["kind"] == "sleb")
                                    except Invalid as independent:
                                        reference_error = str(independent)
                                    if reference_error != item["error"]:
                                        failures.append({"case": group + "/" + item["id"], "independent_error": reference_error, "expected": item["error"]})
                                checks.append({"case": group + "/" + item["id"], "status": "passed", "observed_rejection": str(exc)})
                            else:
                                failures.append({"case": group + "/" + item["id"], "error": str(exc), "expected": item.get("error")})
                observed = {"component_vectors": sum(map(len, values.values()))}
            checks.append({"case": fixture["id"], "status": "passed", "observed": observed})
        except Invalid as exc:
            if str(exc) == fixture["expected"]:
                checks.append({"case": fixture["id"], "status": "passed", "observed_rejection": str(exc)})
            else:
                failures.append({"case": fixture["id"], "error": str(exc), "expected": fixture["expected"]})
    report = {"schema_version": "mdd.oracle-check.v1", "checker": "conformance/oracles/check_fixtures.py", "python": sys.version,
              "scope": "bounded handwritten header/map/string/table/raw-code/component checks and Python zipfile inventory; not ART execution verification",
              "checks": checks, "failures": failures, "success": not failures,
              "unexecuted": ["AOSP verifier/dexdump", "dexlib2", "AAPT2", "production parser comparison", "fuzz"]}
    output = Path(sys.argv[sys.argv.index("--out") + 1]) if "--out" in sys.argv else ROOT / "artifacts/mdd-004/oracle-checks.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    print(f"oracle checks: {len(checks)} passed, {len(failures)} failed")
    if failures:
        print(json.dumps(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
