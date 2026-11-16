#!/usr/bin/env python3
"""Write decode-class.dex: a DEX with what a class has beyond its methods' instructions.

The fixture exists to be decoded into smali and compared with an independent reading of its
bytes (conformance/decode/oracle.py), so every feature of the class-level text is present once:

* Ldecode/Marker; - an interface (public interface abstract) with a static final int ID = 7 and
  an abstract method ping()V.
* Ldecode/K; - public final (and ACC_SUPER), source file "K.java", two interfaces (one defined in
  the file, one not), class annotations, twelve static fields whose static-values array holds
  eleven values of every simple kind (the last field has none), two instance fields, one of them
  annotated and volatile+transient (its annotation has an empty array), and six methods:
    <init>()V                    a constructor with a debug program of one line
    f(IJLjava/lang/String;)V     parameter names (the second unnamed), every debug opcode, a
                                 position that is no source line, an event inside an instruction,
                                 an event at the end of the code
    g(I)V                        a method annotation and a parameter annotation
    r8()V                        the pc-to-pc debug pattern R8 writes (no event is a source line)
    run()V                       an instance method with one line
    h(IJ)V                       an instance method: named and annotated parameters whose registers
                                 start after `this` (a long takes two), locals on parameter registers

Written by hand, byte by byte, from the DEX format; it imports nothing from the engine and no
reader of annotations or debug programs. Standard library only.

Usage: python -I tests/fixtures/decode/generate_class.py [--check]
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "generated"
MANIFEST = HERE / "class-manifest.json"
NO_INDEX = 0xFFFFFFFF

OBJECT = "Ljava/lang/Object;"
STRING = "Ljava/lang/String;"
KLASS = "Ldecode/K;"
MARKER = "Ldecode/Marker;"
ANN = "Ldecode/Ann;"
RUNNABLE = "Ljava/lang/Runnable;"
CLASS = "Ljava/lang/Class;"

ACC_SUPER = 0x20


def uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def sleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40):
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def mutf8(text: str) -> bytes:
    assert all(0 < ord(c) < 0x80 for c in text), "ASCII only"
    return uleb(len(text)) + text.encode("ascii") + b"\0"


SHORTY = {"V": "V", "I": "I", "J": "J", "D": "D", "F": "F", "Z": "Z", "B": "B", "S": "S", "C": "C"}


def shorty(ret: str, params) -> str:
    one = lambda t: SHORTY.get(t, "L")
    return one(ret) + "".join(one(p) for p in params)


def build() -> bytes:
    # ---- the names -------------------------------------------------------------------------
    type_names = {"I", "J", "D", "F", "Z", "B", "S", "C", "V", OBJECT, STRING, KLASS, MARKER, ANN, RUNNABLE, CLASS}
    protos = {("V", ()), ("V", ("I",)), ("V", ("I", "J")), ("V", ("I", "J", STRING))}
    fields = [  # (class, name, type)
        (KLASS, "a_int", "I"), (KLASS, "b_str", STRING), (KLASS, "c_long", "J"), (KLASS, "d_double", "D"),
        (KLASS, "e_float", "F"), (KLASS, "f_bool", "Z"), (KLASS, "g_byte", "B"), (KLASS, "h_short", "S"),
        (KLASS, "i_char", "C"), (KLASS, "j_type", CLASS), (KLASS, "k_null", OBJECT), (KLASS, "z_none", "I"),
        (KLASS, "m_plain", "I"), (KLASS, "n_annotated", STRING), (MARKER, "ID", "I"),
    ]
    methods = [  # (class, name, ret, params)
        (KLASS, "<init>", "V", ()), (KLASS, "f", "V", ("I", "J", STRING)), (KLASS, "g", "V", ("I",)),
        (KLASS, "r8", "V", ()), (KLASS, "run", "V", ()), (KLASS, "h", "V", ("I", "J")), (MARKER, "ping", "V", ()),
        (OBJECT, "<init>", "V", ()),
    ]
    value_strings = ["s\"q\n", "K.java", "kk", "a", "b", "count", "k", "x", "y", "label", "TT;", "F.java"]
    strings = set(type_names) | {shorty(r, p) for r, p in protos} | {f[1] for f in fields} | {m[1] for m in methods}
    strings |= set(value_strings)
    strings = sorted(strings)  # ASCII only, so the order of code points is the order of UTF-16 code units
    sid = {s: i for i, s in enumerate(strings)}
    types = sorted(type_names, key=lambda t: sid[t])
    tid = {t: i for i, t in enumerate(types)}
    protos = sorted(protos, key=lambda p: (tid[p[0]], [tid[x] for x in p[1]]))
    pid = {p: i for i, p in enumerate(protos)}
    fields = sorted(fields, key=lambda f: (tid[f[0]], sid[f[1]], tid[f[2]]))
    fid = {f: i for i, f in enumerate(fields)}
    methods = sorted(methods, key=lambda m: (tid[m[0]], sid[m[1]], pid[(m[2], m[3])]))
    mid = {m: i for i, m in enumerate(methods)}

    string_off = 112
    type_off = string_off + 4 * len(strings)
    proto_off = type_off + 4 * len(types)
    field_off = proto_off + 12 * len(protos)
    method_off = field_off + 8 * len(fields)
    class_off = method_off + 8 * len(methods)
    data_off = class_off + 2 * 32
    body = bytearray()
    map_entries: list[tuple[int, int, int]] = []

    def here() -> int:
        return data_off + len(body)

    def align() -> None:
        body.extend(b"\0" * (-len(body) % 4))

    def section(kind: int, count: int) -> None:
        align()
        map_entries.append((kind, count, here()))

    # ---- type lists (interfaces and parameters) ----------------------------------------------
    section(0x1001, 4)
    param_lists = {}
    for params in (("I",), ("I", "J"), ("I", "J", STRING)):
        align()
        param_lists[params] = here()
        body.extend(struct.pack("<I", len(params)) + b"".join(struct.pack("<H", tid[p]) for p in params))
    interfaces = sorted([MARKER, RUNNABLE], key=lambda t: tid[t])
    align()
    interface_list = here()
    body.extend(struct.pack("<I", len(interfaces)) + b"".join(struct.pack("<H", tid[t]) for t in interfaces))

    # ---- annotations -----------------------------------------------------------------------
    def element(name: str, value: bytes) -> bytes:
        return uleb(sid[name]) + value

    def annotation(visibility: int, type_name: str, elements: list[tuple[str, bytes]]) -> bytes:
        ordered = sorted(elements, key=lambda e: sid[e[0]])
        return bytes([visibility]) + uleb(tid[type_name]) + uleb(len(ordered)) + b"".join(element(n, v) for n, v in ordered)

    string_value = lambda s: bytes([0x17, sid[s]])
    annotation_items = {
        "class": annotation(1, ANN, [("count", bytes([0x04, 3])), ("k", string_value("kk"))]),
        "field": annotation(0, ANN, [("count", bytes([0x00, 0x7F])), ("k", bytes([0x1C, 0]))]),
        "method": annotation(1, ANN, [("k", bytes([0x1C, 2]) + string_value("a") + string_value("b"))]),
        "param": annotation(1, ANN, []),
    }
    section(0x2004, len(annotation_items))
    annotation_off = {}
    for name, data in annotation_items.items():
        annotation_off[name] = here()
        body.extend(data)
    section(0x1003, 4)
    set_off = {}
    for name in ("class", "field", "method", "param"):
        align()
        set_off[name] = here()
        body.extend(struct.pack("<II", 1, annotation_off[name]))
    section(0x1002, 2)
    ref_list = here()
    body.extend(struct.pack("<II", 1, set_off["param"]))
    h_ref_list = here()
    body.extend(struct.pack("<III", 2, 0, set_off["param"]))
    # the directory of K: class set, one annotated field, one annotated method, one annotated parameter list
    section(0x2006, 1)
    directory = here()
    n_annotated = fid[(KLASS, "n_annotated", STRING)]
    g_method = mid[(KLASS, "g", "V", ("I",))]
    h_method = mid[(KLASS, "h", "V", ("I", "J"))]
    body.extend(struct.pack("<IIII", set_off["class"], 1, 1, 2))
    body.extend(struct.pack("<II", n_annotated, set_off["field"]))
    body.extend(struct.pack("<II", g_method, set_off["method"]))
    body.extend(struct.pack("<II", g_method, ref_list))
    body.extend(struct.pack("<II", h_method, h_ref_list))

    # ---- static values ---------------------------------------------------------------------
    section(0x2005, 2)
    marker_values = here()
    body.extend(bytes([1, 0x04, 7]))
    k_values_list = [
        bytes([0x04, 1]),                                  # a_int = 1
        string_value("s\"q\n"),                            # b_str
        bytes([0x06, 0xFE]),                               # c_long = -2
        bytes([0x31, 0x04, 0x40]),                         # d_double = 2.5 (the two high bytes)
        bytes([0x70, 0xCD, 0xCC, 0xCC, 0x3D]),             # e_float = 0.1f
        bytes([0x3F]),                                     # f_bool = true
        bytes([0x00, 0xFF]),                               # g_byte = -1
        bytes([0x22, 0xD4, 0xFE]),                         # h_short = -300
        bytes([0x03, 0x41]),                               # i_char = 'A'
        bytes([0x18, tid[STRING]]),                        # j_type = Ljava/lang/String;
        bytes([0x1E]),                                     # k_null
    ]
    k_values = here()
    body.extend(uleb(len(k_values_list)) + b"".join(k_values_list))

    # ---- debug programs --------------------------------------------------------------------
    section(0x2003, 5)
    p1 = lambda index: uleb(index + 1)
    debug = {}
    # <init>: line 5 at address 0
    debug["init"] = here()
    body.extend(uleb(5) + uleb(0) + bytes([0x0E, 0x00]))
    # f: line_start 10, three parameters (count, none, label)
    debug["f"] = here()
    program = bytearray()
    program += uleb(10) + uleb(3) + p1(sid["count"]) + uleb(0) + p1(sid["label"])
    program += bytes([0x07])                                                # prologue end at 0
    program += bytes([0x0E])                                                # position: line 10 at 0
    program += bytes([0x03, 0]) + p1(sid["x"]) + p1(tid["I"])               # start local v0 "x":I at 0
    program += bytes([0x1E])                                                # position: line 11 at 1
    program += bytes([0x04, 1]) + p1(sid["y"]) + p1(tid[STRING]) + p1(sid["TT;"])  # local v1 with signature at 1
    program += bytes([0x01, 2]) + bytes([0x0E])                             # pc 3, position: line 11
    program += bytes([0x05, 0])                                             # end local v0 at 3
    program += bytes([0x06, 0])                                             # restart local v0 at 3
    program += bytes([0x01, 2]) + bytes([0x09]) + p1(sid["F.java"])         # pc 5 (inside an instruction): set file
    program += bytes([0x01, 1]) + bytes([0x0D])                             # pc 6, position: line 10
    program += bytes([0x01, 1]) + bytes([0x02]) + sleb(-20) + bytes([0x0E]) # pc 7, line -10: no source line
    program += bytes([0x08])                                                # epilogue at 7
    program += bytes([0x01, 1]) + bytes([0x05, 1])                          # pc 8 (the end of the code): end local v1
    program += bytes([0x00])
    body.extend(program)
    # r8: the pc-to-pc pattern, line_start 1, no parameters
    debug["r8"] = here()
    body.extend(uleb(1) + uleb(0) + bytes([0x0E, 0x1E, 0x1E, 0x00]))
    # run: line 30 at address 0
    run_debug = here()
    body.extend(uleb(30) + uleb(0) + bytes([0x0E, 0x00]))
    # h: parameters x and y; locals on both parameter registers, a position, an end of one local
    # (v1 is `this`, v2 the int, v3-v4 the long: registers 5, ins 4, so the first parameter register is 1)
    h_debug = here()
    program = bytearray()
    program += uleb(40) + uleb(2) + p1(sid["x"]) + p1(sid["y"])
    program += bytes([0x03, 2]) + p1(sid["x"]) + p1(tid["I"])             # start local v2 (p1) "x":I at 0
    program += bytes([0x03, 3]) + p1(sid["y"]) + p1(tid["J"])             # start local v3 (p2) "y":J at 0
    program += bytes([0x0E])                                              # position: line 40 at 0
    program += bytes([0x01, 1]) + bytes([0x05, 2])                        # pc 1: end local v2 (p1)
    program += bytes([0x00])
    body.extend(program)

    # ---- code items ------------------------------------------------------------------------
    section(0x2001, 6)
    code_off = {}

    def code(name: str, registers: int, ins: int, outs: int, debug_off: int, units: list[int]) -> None:
        align()
        code_off[name] = here()
        body.extend(struct.pack("<HHHHII", registers, ins, outs, 0, debug_off, len(units)))
        body.extend(b"".join(struct.pack("<H", u) for u in units))

    object_init = mid[(OBJECT, "<init>", "V", ())]
    g_idx = mid[(KLASS, "g", "V", ("I",))]
    code("init", 1, 1, 1, debug["init"], [0x1070, object_init, 0x0000, 0x000E])
    code("f", 6, 4, 1, debug["f"], [
        0x1012,                          # 0: const/4 v0, 0x1
        0x011A, sid["x"],                # 1: const-string v1, "x"
        0x1071, g_idx, 0x0002,           # 3: invoke-static {p0}, Ldecode/K;->g(I)V
        0x0000,                          # 6: nop
        0x000E,                          # 7: return-void
    ])
    code("g", 1, 1, 0, 0, [0x000E])
    code("r8", 1, 0, 0, debug["r8"], [0x0000, 0x0000, 0x000E])
    code("run", 1, 1, 0, run_debug, [0x000E, 0x0000])
    code("h", 5, 4, 0, h_debug, [0x0000, 0x000E])
    section(0x2000, 2)
    # ---- class data -----------------------------------------------------------------------
    marker_data = here()
    id_field = fid[(MARKER, "ID", "I")]
    ping = mid[(MARKER, "ping", "V", ())]
    body.extend(uleb(1) + uleb(0) + uleb(0) + uleb(1))
    body.extend(uleb(id_field) + uleb(0x19))
    body.extend(uleb(ping) + uleb(0x401) + uleb(0))
    k_data = here()  # class_data items are byte-aligned and follow one another: the reader walks the section
    static_names = ["a_int", "b_str", "c_long", "d_double", "e_float", "f_bool", "g_byte", "h_short", "i_char", "j_type", "k_null", "z_none"]
    static_types = ["I", STRING, "J", "D", "F", "Z", "B", "S", "C", CLASS, OBJECT, "I"]
    static_flags = [0x19, 0x2 | 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8]
    body.extend(uleb(12) + uleb(2) + uleb(4) + uleb(2))
    previous = 0
    for name, ty, flags in zip(static_names, static_types, static_flags):
        index = fid[(KLASS, name, ty)]
        body.extend(uleb(index - previous) + uleb(flags))
        previous = index
    previous = 0
    for name, ty, flags in (("m_plain", "I", 0x1), ("n_annotated", STRING, 0x2 | 0x40 | 0x80)):
        index = fid[(KLASS, name, ty)]
        body.extend(uleb(index - previous) + uleb(flags))
        previous = index
    direct = [(mid[(KLASS, "<init>", "V", ())], 0x10001, "init"), (mid[(KLASS, "f", "V", ("I", "J", STRING))], 0x9, "f"),
              (g_idx, 0x9, "g"), (mid[(KLASS, "r8", "V", ())], 0x9, "r8")]
    previous = 0
    for index, flags, name in sorted(direct):
        body.extend(uleb(index - previous) + uleb(flags) + uleb(code_off[name]))
        previous = index
    previous = 0
    for index, flags, name in sorted([(mid[(KLASS, "run", "V", ())], 0x1, "run"), (mid[(KLASS, "h", "V", ("I", "J"))], 0x1, "h")]):
        body.extend(uleb(index - previous) + uleb(flags) + uleb(code_off[name]))
        previous = index

    # ---- strings ---------------------------------------------------------------------------
    section(0x2002, len(strings))
    string_offsets = []
    for s in strings:
        string_offsets.append(here())
        body.extend(mutf8(s))
    # ---- map -------------------------------------------------------------------------------
    align()
    map_off = here()
    entries = [(0x0000, 1, 0), (0x0001, len(strings), string_off), (0x0002, len(types), type_off),
               (0x0003, len(protos), proto_off), (0x0004, len(fields), field_off), (0x0005, len(methods), method_off),
               (0x0006, 2, class_off), (0x1000, 1, map_off)] + map_entries
    entries.sort(key=lambda e: e[2])
    body.extend(struct.pack("<I", len(entries)))
    for kind, count, offset in entries:
        body.extend(struct.pack("<HHII", kind, 0, count, offset))

    # ---- the id tables and the headers ----------------------------------------------------
    head = bytearray(data_off)
    for i, offset in enumerate(string_offsets):
        struct.pack_into("<I", head, string_off + 4 * i, offset)
    for i, t in enumerate(types):
        struct.pack_into("<I", head, type_off + 4 * i, sid[t])
    for i, (ret, params) in enumerate(protos):
        struct.pack_into("<III", head, proto_off + 12 * i, sid[shorty(ret, params)], tid[ret], param_lists.get(params, 0))
    for i, (owner, name, ty) in enumerate(fields):
        struct.pack_into("<HHI", head, field_off + 8 * i, tid[owner], tid[ty], sid[name])
    for i, (owner, name, ret, params) in enumerate(methods):
        struct.pack_into("<HHI", head, method_off + 8 * i, tid[owner], pid[(ret, params)], sid[name])
    # class_def: class_idx, access, superclass, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off
    struct.pack_into("<IIIIIIII", head, class_off, tid[MARKER], 0x601, tid[OBJECT], 0, NO_INDEX, 0, marker_data, marker_values)
    struct.pack_into("<IIIIIIII", head, class_off + 32, tid[KLASS], 0x1 | 0x10 | ACC_SUPER, tid[OBJECT], interface_list,
                     sid["K.java"], directory, k_data, k_values)
    data = bytearray(head + body)
    total = len(data)
    data[0:8] = b"dex\n039\0"
    struct.pack_into("<I", data, 32, total)
    struct.pack_into("<I", data, 36, 112)
    struct.pack_into("<I", data, 40, 0x12345678)
    struct.pack_into("<I", data, 52, map_off)
    for position, (size, offset) in {56: (len(strings), string_off), 64: (len(types), type_off), 72: (len(protos), proto_off),
                                     80: (len(fields), field_off), 88: (len(methods), method_off), 96: (2, class_off),
                                     104: (total - data_off, data_off)}.items():
        struct.pack_into("<II", data, position, size, offset)
    data[12:32] = hashlib.sha1(bytes(data[32:])).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF)
    return bytes(data)


def main(argv: list[str]) -> int:
    data = build()
    digest = hashlib.sha256(data).hexdigest()
    record = {"files": {"decode-class.dex": {"bytes": len(data), "sha256": digest}}, "generator": "tests/fixtures/decode/generate_class.py",
              "note": "a synthetic class with annotations, fields, static values and debug programs; written byte by byte",
              "schema_version": "mdd.decode-class-fixture.v1"}
    text = json.dumps(record, indent=1, sort_keys=True) + "\n"
    if "--check" in argv:
        current = (OUT / "decode-class.dex").read_bytes() if (OUT / "decode-class.dex").exists() else b""
        ok = current == data and MANIFEST.exists() and MANIFEST.read_text(encoding="utf-8") == text
        print("decode-class.dex is current" if ok else "decode-class.dex is stale; run generate_class.py")
        return 0 if ok else 1
    OUT.mkdir(exist_ok=True)
    (OUT / "decode-class.dex").write_bytes(data)
    MANIFEST.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote decode-class.dex: {len(data)} bytes, sha256 {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
