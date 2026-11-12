#!/usr/bin/env python3
"""Synthetic DEX generator for the MDD-026 member-relation evidence.

The generator is Python stdlib only and is independent of the Rust engine.
It writes a tiny DEX 035 file whose physical layout is verified by
oracle_members.py (map order, little-endian words, ULEB starts, code-item
starts and class_data starts).

Fixture purpose (members-dup-035.dex):
  * class_fields: the same field name "value" is defined by two classes, so
    the field_name column repeats a value while field_idx/field_descriptor
    cannot repeat (they are global identifiers).
  * class_methods: the same method names "<init>"/"dup" are defined by two
    classes, so method_name repeats while method_idx/method_descriptor
    cannot repeat.
  * method_field_accesses: one method performs the same sget-object twice, so
    two compared rows are byte-identical (exact duplicate row).
  * method_strings / method_used_types: one method performs the same
    const-string / const-class twice, producing exact duplicate rows.
  * methods: one method_id (External.missing) has no class_data definition, so
    the nullable access_flags/opcode_count/opcode_hex/method_kind cells are
    NULL while the other rows are populated.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import zlib

A = "Lfixture/A;"
B = "Lfixture/B;"
E = "Lfixture/External;"
O = "Ljava/lang/Object;"
S = "Ljava/lang/String;"
I = "I"
V = "V"

# (owner, name, type) - field_ids are sorted by (class_idx, name_idx, type_idx)
FIELDS = [(A, "value", I), (B, "value", I), (E, "shared", S)]
# (owner, name, return, args) - method_ids are sorted by (class_idx, proto_idx, name_idx)
METHODS = [(A, "<init>", V, ()), (A, "caller", V, ()), (A, "dup", V, ()),
           (B, "<init>", V, ()), (B, "dup", V, ()), (E, "external", V, ()),
           (E, "missing", V, ())]
# class_def order: A, B, External (superclass Object is a type, not a class_def)
CLASS_ORDER = [A, B, E]
CLASS_DATA = {
    A: {"static": [], "instance": [("value", 1)],
        "direct": [("<init>", 0x10001), ("caller", 2), ("dup", 2)], "virtual": []},
    B: {"static": [], "instance": [("value", 1)],
        "direct": [("<init>", 0x10001), ("dup", 2)], "virtual": []},
    E: {"static": [("shared", 9)], "instance": [], "direct": [("external", 0x109)],
        "virtual": []},
}
CODE = {
    (A, "<init>"): [0x000E],
    (A, "caller"): [0x0062, 2, 0x0069, 2, 0x000E],
    (A, "dup"): [0x0062, 2, 0x0062, 2, 0x001A, None, 0x001A, None,
                 0x001C, 2, 0x001C, 2, 0x000E],
    (B, "<init>"): [0x000E],
    (B, "dup"): [0x000E],
}
# Word placeholders that depend on the string/type index assignment.
REPEAT_STRING = "repeat"


def leb(value):
    out = bytearray()
    while True:
        part = value & 127
        value >>= 7
        out.append(part | (128 if value else 0))
        if not value:
            return bytes(out)


def build():
    descriptors = sorted({I, V, A, B, E, O, S})
    prototypes = sorted({(ret, args) for _, _, ret, args in METHODS},
                        key=lambda item: (descriptors.index(item[0]),
                                          tuple(descriptors.index(t) for t in item[1])))
    shorty = lambda ret, args: ("L" if ret.startswith(("L", "[")) else ret) + "".join(
        "L" if t.startswith(("L", "[")) else t for t in args)
    text = sorted(set(descriptors)
                  | {name for _, name, _ in FIELDS}
                  | {name for _, name, _, _ in METHODS}
                  | {shorty(ret, args) for ret, args in prototypes}
                  | {"A.java", "B.java", "External.java", REPEAT_STRING})
    sx = {value: index for index, value in enumerate(text)}
    tx = {value: index for index, value in enumerate(descriptors)}
    px = {value: index for index, value in enumerate(prototypes)}
    fields = sorted(FIELDS, key=lambda f: (tx[f[0]], sx[f[1]], tx[f[2]]))
    methods = sorted(METHODS, key=lambda m: (tx[m[0]], px[(m[2], m[3])], sx[m[1]]))
    fi = {(owner, name): index for index, (owner, name, _t) in enumerate(fields)}
    mi = {(owner, name): index for index, (owner, name, _r, _a) in enumerate(methods)}
    # Fill the two const-string word placeholders with the real string index.
    repeat_index = sx[REPEAT_STRING]
    code_words = {}
    for key, words in CODE.items():
        code_words[key] = [repeat_index if word is None else word for word in words]

    counts = [len(text), len(descriptors), len(prototypes), len(fields), len(methods),
              len(CLASS_ORDER)]
    strides = [4, 4, 12, 8, 8, 32]
    offsets = []
    cursor = 112
    for count, stride in zip(counts, strides):
        offsets.append(cursor)
        cursor += count * stride
    data_off = (cursor + 3) & ~3
    data = bytearray()
    absolute = lambda: data_off + len(data)

    def align():
        while absolute() % 4:
            data.append(0)

    sections = []
    # string_data
    sections.append((0x2002, len(text), absolute()))
    string_offsets = []
    for value in text:
        string_offsets.append(absolute())
        encoded = value.encode("utf-16-le", "surrogatepass")
        units = struct.unpack("<" + "H" * (len(encoded) // 2), encoded)
        raw = bytearray()
        for unit in units:
            if 1 <= unit <= 127:
                raw.append(unit)
            elif unit <= 2047:
                raw.extend([0xC0 | (unit >> 6), 0x80 | (unit & 63)])
            else:
                raw.extend([0xE0 | (unit >> 12), 0x80 | ((unit >> 6) & 63), 0x80 | (unit & 63)])
        data.extend(leb(len(units)) + raw + b"\0")
    # code items
    align()
    code_start = absolute()
    code_offsets = {}
    code_count = 0
    for owner, name, _ret, _args in methods:
        key = (owner, name)
        if key not in code_words:
            continue
        definition = next((item for item in CODE_DEFINITIONS(owner, name)), None)
        if definition is None:
            continue
        align()
        code_offsets[key] = absolute()
        code_count += 1
        words = code_words[key]
        data.extend(struct.pack("<HHHHII", 1, 1, 0, 0, 0, len(words)))
        data.extend(struct.pack("<" + "H" * len(words), *words))
    sections.append((0x2001, code_count, code_start))
    # class_data
    class_data_start = absolute()
    class_offsets = {}
    layout = {}
    for owner in CLASS_ORDER:
        class_offsets[owner] = absolute()
        start = absolute()
        groups = [list(CLASS_DATA[owner]["static"]), list(CLASS_DATA[owner]["instance"]),
                  list(CLASS_DATA[owner]["direct"]), list(CLASS_DATA[owner]["virtual"])]
        for group in groups:
            data.extend(leb(len(group)))
        local = {}
        for kind, group in zip(("static", "instance", "direct", "virtual"), groups):
            previous = 0
            local[kind] = []
            for ordinal, (name, flags) in enumerate(group):
                is_field = kind in ("static", "instance")
                index = (fi if is_field else mi)[(owner, name)]
                delta = index - previous
                at = absolute()
                data.extend(leb(delta) + leb(flags))
                code_off = 0
                if not is_field:
                    code_off = code_offsets.get((owner, name), 0)
                    data.extend(leb(code_off))
                local[kind].append({"ordinal": ordinal, "name": name, "index": index,
                                    "delta": delta, "byte_offset": at, "access_flags": flags,
                                    "code_off": code_off})
                previous = index
        layout[owner] = {"byte_offset": start, "byte_end": absolute(), "groups": local}
    sections.append((0x2000, len(set(class_offsets.values())), class_data_start))
    # map_list
    align()
    map_off = absolute()
    map_rows = [(0, 1, 0)]
    map_rows += [(kind, count, offset) for kind, count, offset in zip(range(1, 7), counts, offsets)]
    map_rows += sections
    map_rows.append((0x1000, 1, map_off))
    map_rows.sort(key=lambda row: row[2])
    data.extend(struct.pack("<I", len(map_rows)))
    for kind, count, offset in map_rows:
        data.extend(struct.pack("<HHII", kind, 0, count, offset))

    out = bytearray(data_off) + data
    out[:8] = b"dex\n035\0"
    struct.pack_into("<20I", out, 32, len(out), 112, 0x12345678, 0, 0, map_off,
                     *[word for pair in zip(counts, offsets) for word in pair],
                     len(data), data_off)
    for index, offset in enumerate(string_offsets):
        struct.pack_into("<I", out, offsets[0] + 4 * index, offset)
    for index, descriptor in enumerate(descriptors):
        struct.pack_into("<I", out, offsets[1] + 4 * index, sx[descriptor])
    for index, (ret, args) in enumerate(prototypes):
        struct.pack_into("<III", out, offsets[2] + 12 * index, sx[shorty(ret, args)],
                         tx[ret], 0)
    for index, (owner, name, field_type) in enumerate(fields):
        struct.pack_into("<HHI", out, offsets[3] + 8 * index, tx[owner], tx[field_type], sx[name])
    for index, (owner, name, ret, args) in enumerate(methods):
        struct.pack_into("<HHI", out, offsets[4] + 8 * index, tx[owner], px[(ret, args)], sx[name])
    for ordinal, owner in enumerate(CLASS_ORDER):
        superclass = O
        class_data = class_offsets.get(owner, 0)
        filename = owner.split("/")[-1][:-1] + ".java"
        source_index = sx[filename]
        struct.pack_into("<8I", out, offsets[5] + 32 * ordinal, tx[owner],
                         0x401 if owner in (A, B) else 1, tx[superclass], 0,
                         source_index, 0, class_data, 0)
    out[12:32] = hashlib.sha1(out[32:]).digest()
    struct.pack_into("<I", out, 8, zlib.adler32(out[12:]))
    return bytes(out), {"field_indices": {o + "->" + n: i for (o, n), i in fi.items()},
                        "method_indices": {o + "->" + n: i for (o, n), i in mi.items()},
                        "type_indices": tx, "class_data": layout, "class_order": CLASS_ORDER,
                        "string_indices": sx}


def CODE_DEFINITIONS(owner, name):
    """Whether the (owner, name) method is defined with a code item."""
    direct = dict(CLASS_DATA[owner]["direct"])
    virtual = dict(CLASS_DATA[owner]["virtual"])
    flags = direct.get(name, virtual.get(name))
    if flags is None:
        return []
    if flags & (0x100 | 0x400):
        return []
    return [True]


def main():
    destination = Path(__file__).resolve().parent / "fixtures"
    destination.mkdir(parents=True, exist_ok=True)
    data, layout = build()
    path = destination / "members-dup-035.dex"
    path.write_bytes(data)
    record = {
        "generator": "artifacts/mdd-026/evidence-members-20261111T064757Z/generate_fixture.py",
        "path": path.as_posix(),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "version": "035",
        "layout": layout,
        "purpose": "repeated field/method names, exact-duplicate field/string/type rows, "
                   "and a reference-only method for NULL cells",
    }
    (destination / "members-dup-035.record.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"path": record["path"], "bytes": len(data),
                      "sha256": record["sha256"]}))


if __name__ == "__main__":
    main()
