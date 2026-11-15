#!/usr/bin/env python3
"""A tiny DEX writer for the MCP lifecycle and decode checks. Standard library only.

It writes one class with direct methods, each a handful of instructions, in the layout
the format prescribes (sorted pools, map list, SHA-1 signature and Adler-32 checksum).
It does not import the engine under test. The recorded reference sessions
(evidence/compatibility/0.1.0/mcp-records.json) used 500-byte files that are not kept;
these files have the same content as far as the recordings show it (class Ldemo/A; with
public static foo()V: two const-string "needle", invoke-static Ldemo/B;->bar()V,
return-void), not the same bytes.
"""
from __future__ import annotations

import hashlib
import struct
import zlib

NO_INDEX = 0xFFFFFFFF
OBJECT = "Ljava/lang/Object;"


def uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def mutf8(text: str) -> bytes:
    units = struct.unpack("<%dH" % (len(text.encode("utf-16-le")) // 2), text.encode("utf-16-le"))
    data = bytearray(uleb(len(units)))
    for unit in units:
        if 0 < unit < 0x80:
            data.append(unit)
        elif unit < 0x800:
            data.extend([0xC0 | (unit >> 6), 0x80 | (unit & 0x3F)])
        else:
            data.extend([0xE0 | (unit >> 12), 0x80 | ((unit >> 6) & 0x3F), 0x80 | (unit & 0x3F)])
    return bytes(data) + b"\0"


def utf16_key(text: str):
    raw = text.encode("utf-16-le", "surrogatepass")
    return struct.unpack("<%dH" % (len(raw) // 2), raw)


def build(class_name: str, methods: list[dict], version: str = "035") -> bytes:
    """`methods`: dicts with name, access, registers, outs and code, a list of operations:

    ("const-string", register, text)           21c
    ("invoke-static", owner, name)             35c, no arguments, ()V
    ("return-void",)                           10x
    ("raw", [code units])                      emitted unchanged
    """
    referenced = []
    for method in methods:
        for op in method["code"]:
            if op[0] == "invoke-static":
                referenced.append((op[1], op[2]))
    defined = [(class_name, m["name"]) for m in methods]
    method_keys = sorted(set(defined) | set(referenced))
    literals = sorted({op[2] for m in methods for op in m["code"] if op[0] == "const-string"})
    type_names = {class_name, OBJECT, "V"} | {owner for owner, _ in method_keys}
    names = {name for _, name in method_keys}
    strings = sorted(type_names | names | set(literals), key=utf16_key)
    sidx = {s: i for i, s in enumerate(strings)}
    types = sorted(type_names, key=lambda t: sidx[t])
    tidx = {t: i for i, t in enumerate(types)}
    method_keys.sort(key=lambda key: (tidx[key[0]], sidx[key[1]], 0))
    midx = {key: i for i, key in enumerate(method_keys)}

    string_off = 112
    type_off = string_off + 4 * len(strings)
    proto_off = type_off + 4 * len(types)
    method_off = proto_off + 12
    class_off = method_off + 8 * len(method_keys)
    data_off = class_off + 32
    body = bytearray()

    def here() -> int:
        return data_off + len(body)

    def align(n: int = 4) -> None:
        body.extend(b"\0" * (-len(body) % n))

    string_data_off = here()
    string_offsets = []
    for s in strings:
        string_offsets.append(here())
        body.extend(mutf8(s))

    code_offsets = {}
    for method in methods:
        align()
        code_offsets[method["name"]] = here()
        units: list[int] = []
        for op in method["code"]:
            if op[0] == "const-string":
                units.extend([0x001A | (op[1] << 8), sidx[op[2]]])
            elif op[0] == "invoke-static":
                units.extend([0x0071, midx[(op[1], op[2])], 0x0000])
            elif op[0] == "return-void":
                units.append(0x000E)
            elif op[0] == "raw":
                units.extend(op[1])
            else:
                raise ValueError(op)
        body.extend(struct.pack("<HHHHII", method["registers"], 0, method["outs"], 0, 0, len(units)))
        for unit in units:
            body.extend(struct.pack("<H", unit))

    align()
    class_data_off = here()
    ordered = sorted(methods, key=lambda m: midx[(class_name, m["name"])])
    body.extend(uleb(0) + uleb(0) + uleb(len(ordered)) + uleb(0))
    previous = 0
    for method in ordered:
        index = midx[(class_name, method["name"])]
        body.extend(uleb(index - previous) + uleb(method["access"]) + uleb(code_offsets[method["name"]]))
        previous = index

    align()
    map_off = here()
    sections = [
        (0x0000, 1, 0),
        (0x0001, len(strings), string_off),
        (0x0002, len(types), type_off),
        (0x0003, 1, proto_off),
        (0x0005, len(method_keys), method_off),
        (0x0006, 1, class_off),
        (0x2002, len(strings), string_data_off),
        (0x2001, len(methods), min(code_offsets.values())),
        (0x2000, 1, class_data_off),
        (0x1000, 1, map_off),
    ]
    body.extend(struct.pack("<I", len(sections)))
    for kind, size, offset in sections:
        body.extend(struct.pack("<HHII", kind, 0, size, offset))

    head = bytearray(data_off)
    for i, offset in enumerate(string_offsets):
        struct.pack_into("<I", head, string_off + 4 * i, offset)
    for i, t in enumerate(types):
        struct.pack_into("<I", head, type_off + 4 * i, sidx[t])
    struct.pack_into("<III", head, proto_off, sidx["V"], tidx["V"], 0)
    for i, (owner, name) in enumerate(method_keys):
        struct.pack_into("<HHI", head, method_off + 8 * i, tidx[owner], 0, sidx[name])
    struct.pack_into("<IIIIIIII", head, class_off, tidx[class_name], 1, tidx[OBJECT], 0, NO_INDEX, 0, class_data_off, 0)
    data = bytearray(head + body)
    total = len(data)
    data[0:8] = b"dex\n" + version.encode() + b"\0"
    struct.pack_into("<I", data, 32, total)
    struct.pack_into("<I", data, 36, 112)
    struct.pack_into("<I", data, 40, 0x12345678)
    struct.pack_into("<I", data, 52, map_off)
    for position, (size, offset) in {
        56: (len(strings), string_off),
        64: (len(types), type_off),
        72: (1, proto_off),
        80: (0, 0),
        88: (len(method_keys), method_off),
        96: (1, class_off),
        104: (total - data_off, data_off),
    }.items():
        struct.pack_into("<II", data, position, size, offset)
    data[12:32] = hashlib.sha1(bytes(data[32:])).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF)
    return bytes(data)


def foo_a() -> bytes:
    """The recorded fixture's content: Ldemo/A;->foo()V."""
    return build("Ldemo/A;", [{
        "name": "foo", "access": 0x9, "registers": 1, "outs": 0,
        "code": [("const-string", 0, "needle"), ("const-string", 0, "needle"),
                 ("invoke-static", "Ldemo/B;", "bar"), ("return-void",)],
    }])


def bar_b() -> bytes:
    """A second DEX that defines Ldemo/B;->bar()V and refers to Ldemo/A;->foo()V."""
    return build("Ldemo/B;", [{
        "name": "bar", "access": 0x9, "registers": 0, "outs": 0,
        "code": [("invoke-static", "Ldemo/A;", "foo"), ("return-void",)],
    }])
