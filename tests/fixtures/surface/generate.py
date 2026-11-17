#!/usr/bin/env python3
"""Write the synthetic APKs that the MDD-052 surface checks read, and the hand-derived expectations for them.

Everything here is written from the DEX and ZIP formats, byte by byte, and imports nothing from the engine or
from HostLab. The classes are placed in the package families that HostLab's surface rules look at
(`Lcom/bilibili/app/comm/comment2/`, `Lkntr/common/comment/`, `Lcom/bapis/.../ReplyMoss;`, ...) because the rules
only select by name; no real application is involved.

What the fixtures are built to exercise
  base.apk     two DEX files whose family methods share method_idx numbers (the same number names different
               methods in classes.dex and classes2.dex); the same class defined in both DEX files; a method with
               a body, an abstract method and a native method (no body); overloads `m(I)V` and `m(IJ)V` whose
               order differs between the plain prototype and the legacy spaced one; a Composer signature; the
               three protocol cases (registered, Kotlin twin, unregistered); callers inside a family, outside
               every family and across families; resources of every kind the fingerprint takes (an empty one,
               a deflated one) and ones it must leave alone.
  target.apk   the next "version" of base.apk: one body changed, one family retired, one new family, one protocol
               signature added, and resources added, removed and changed.
  fields-only.apk
               family classes that have fields and no methods at all (the frozen scan raises KeyError there).
  plain.apk    no family class at all.
  duplicate-resource.apk
               two physical members with the same resource name.

Written bytes are reproducible: the ZIP writer is hand-made (fixed timestamps, no platform compressor; the "deflated"
member is a single stored deflate block), so `--check` gives the same answer on every platform.

Usage: python -I tests/fixtures/surface/generate.py [--check]
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "generated"
EXPECTED = HERE / "expected.json"
NO_INDEX = 0xFFFFFFFF

PUBLIC, PRIVATE, STATIC, FINAL, NATIVE, ABSTRACT, CONSTRUCTOR, ACC_SUPER = 0x1, 0x2, 0x8, 0x10, 0x100, 0x400, 0x10000, 0x20
INVOKE = {"virtual": 0x6E, "super": 0x6F, "direct": 0x70, "static": 0x71, "interface": 0x72}
INVOKE_RANGE = {"virtual": 0x74, "super": 0x75, "direct": 0x76, "static": 0x77, "interface": 0x78}

OBJ = "Ljava/lang/Object;"
STR = "Ljava/lang/String;"
COMPOSER = "Landroidx/compose/runtime/Composer;"
REPLY = "Lcom/bapis/bilibili/main/community/reply/v1/ReplyMoss;"
KREPLY = "Lcom/bapis/bilibili/main/community/reply/v1/KReplyMoss;"
FOO = "Lcom/bapis/bilibili/zzz/FooMoss;"
HOLDER = "Lcom/bilibili/app/comm/comment2/Holder;"
ITEM = "Lcom/bilibili/app/comment3/ui/holder/Item;"
OTHERUI = "Lcom/bilibili/app/comment3/ui/other/Z;"
PANEL = "Lkntr/common/comment/Panel;"
CARD = "Lcom/bilibili/bplus/dynamicFoo/Card;"
MISC = "Lkntr/app/following/Misc;"
HOME = "Ltv/danmaku/bili/khome/Home;"
SEARCH = "Lcom/bilibili/search2/Feed;"
PGC = "Lcom/bilibili/bangumi/ui/Page;"
CALLER = "Lcom/example/Caller;"
PLAIN = "Lcom/example/Plain;"


# ---- the classes -------------------------------------------------------------------------------

@dataclass
class Method:
    name: str
    ret: str
    params: tuple
    access: int
    ops: "list | None"  # None: no code item (abstract, native)


@dataclass
class Klass:
    desc: str
    access: int
    sup: "str | None"
    fields: list  # (name, type, access)
    methods: list  # Method
    family: "str | None" = None  # what HostLab's rules must say about this class; written by hand


def ref(owner, name, ret="V", params=()):
    return (owner, name, ret, tuple(params))


def call(kind, owner, name, ret="V", params=(), args=()):
    return ("invoke", kind, ref(owner, name, ret, params), tuple(args))


def meth(name, ret="V", params=(), access=PUBLIC, ops=("default",)):
    if ops == ("default",):
        ops = [("ret",)]
    return Method(name, ret, tuple(params), access, None if ops is None else list(ops))


def units_of_ops(ops, method_index) -> list[int]:
    out: list[int] = []
    for op in ops:
        kind = op[0]
        if kind == "nop":
            out.append(0x0000)
        elif kind == "ret":
            out.append(0x000E)
        elif kind == "const4":
            out.append((op[2] << 12) | (op[1] << 8) | 0x12)
        elif kind == "invoke":
            args = op[3]
            registers = list(args) + [0] * (5 - len(args))
            out += [(len(args) << 12) | (registers[4] << 8) | INVOKE[op[1]], method_index[op[2]],
                    (registers[3] << 12) | (registers[2] << 8) | (registers[1] << 4) | registers[0]]
        elif kind == "range":
            out += [(op[4] << 8) | INVOKE_RANGE[op[1]], method_index[op[2]], op[3]]
        else:
            raise ValueError(kind)
    return out


def uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def mutf8(text: str) -> bytes:
    if not all(0 < ord(c) < 0x80 for c in text):
        raise ValueError(f"mutf8 fixture text must be printable ASCII: {text!r}")
    return uleb(len(text)) + text.encode("ascii") + b"\0"


def shorty(ret: str, params) -> str:
    one = lambda t: t if len(t) == 1 else "L"
    return one(ret) + "".join(one(p) for p in params)


def proto_text(m: Method) -> str:
    return "(" + "".join(m.params) + ")" + m.ret


def build_dex(classes: list, version: str = "035") -> "tuple[bytes, list]":
    """The DEX bytes and, for every class, [(method, method_idx, insns_off, insns_units|None)]."""
    types: set = set()
    protos: set = set()
    fields: set = set()
    methods: set = set()

    def need(t):
        types.add(t)

    for c in classes:
        need(c.desc)
        if c.sup:
            need(c.sup)
        for name, ty, _ in c.fields:
            fields.add((c.desc, name, ty))
            need(ty)
        for m in c.methods:
            methods.add((c.desc, m.name, m.ret, m.params))
            for op in m.ops or ():
                if op[0] in ("invoke", "range"):
                    methods.add(op[2])
    for owner, _name, ret, params in methods:
        protos.add((ret, params))
        need(owner)
    for ret, params in protos:
        need(ret)
        for p in params:
            need(p)
    strings = set(types) | {shorty(r, p) for r, p in protos} | {f[1] for f in fields} | {m[1] for m in methods}
    strings = sorted(strings)
    sid = {s: i for i, s in enumerate(strings)}
    type_list = sorted(types, key=lambda t: sid[t])
    tid = {t: i for i, t in enumerate(type_list)}
    proto_list = sorted(protos, key=lambda p: (tid[p[0]], [tid[x] for x in p[1]]))
    pid = {p: i for i, p in enumerate(proto_list)}
    field_list = sorted(fields, key=lambda f: (tid[f[0]], sid[f[1]], tid[f[2]]))
    fid = {f: i for i, f in enumerate(field_list)}
    method_list = sorted(methods, key=lambda m: (tid[m[0]], sid[m[1]], pid[(m[2], m[3])]))
    mid = {m: i for i, m in enumerate(method_list)}

    string_off = 112
    type_off = string_off + 4 * len(strings)
    proto_off = type_off + 4 * len(type_list)
    field_off = proto_off + 12 * len(proto_list)
    method_off = field_off + 8 * len(field_list)
    class_off = method_off + 8 * len(method_list)
    data_off = class_off + 32 * len(classes)
    body = bytearray()
    sections: list = []

    def here() -> int:
        return data_off + len(body)

    def align() -> None:
        body.extend(b"\0" * (-len(body) % 4))

    def section(kind: int, count: int) -> None:
        if count:
            align()
            sections.append((kind, count, here()))

    param_lists = {}
    wanted = sorted({p[1] for p in proto_list if p[1]})
    section(0x1001, len(wanted))
    for params in wanted:
        align()
        param_lists[params] = here()
        body.extend(struct.pack("<I", len(params)) + b"".join(struct.pack("<H", tid[p]) for p in params))

    code_total = sum(1 for c in classes for m in c.methods if m.ops is not None)
    section(0x2001, code_total)
    layout: list = []
    code_off: dict = {}
    for c in classes:
        rows = []
        for m in c.methods:
            index = mid[(c.desc, m.name, m.ret, m.params)]
            if m.ops is None:
                rows.append((m, index, None, None))
                continue
            align()
            units = units_of_ops(m.ops, mid)
            ins = sum(2 if p in ("J", "D") else 1 for p in m.params) + (0 if m.access & STATIC else 1)
            offset = here()
            outs = max([len(op[3]) if op[0] == "invoke" else op[4] for op in m.ops if op[0] in ("invoke", "range")] or [0])
            body.extend(struct.pack("<HHHHII", max(ins + 2, outs), ins, outs, 0, 0, len(units)))
            body.extend(b"".join(struct.pack("<H", u) for u in units))
            code_off[(c.desc, m.name, m.ret, m.params)] = offset
            rows.append((m, index, offset + 16, len(units)))
        layout.append((c, rows))

    data_class_count = sum(1 for c in classes if c.fields or c.methods)
    section(0x2000, data_class_count)
    class_data: dict = {}
    for c in classes:
        if not (c.fields or c.methods):
            continue
        class_data[c.desc] = here()
        static_f = sorted((fid[(c.desc, n, t)], a) for n, t, a in c.fields if a & STATIC)
        inst_f = sorted((fid[(c.desc, n, t)], a) for n, t, a in c.fields if not a & STATIC)

        def is_direct(m):
            return m.access & (STATIC | PRIVATE | CONSTRUCTOR) or m.name == "<init>"

        direct = sorted((mid[(c.desc, m.name, m.ret, m.params)], m.access,
                         code_off.get((c.desc, m.name, m.ret, m.params), 0)) for m in c.methods if is_direct(m))
        virtual = sorted((mid[(c.desc, m.name, m.ret, m.params)], m.access,
                          code_off.get((c.desc, m.name, m.ret, m.params), 0)) for m in c.methods if not is_direct(m))
        body.extend(uleb(len(static_f)) + uleb(len(inst_f)) + uleb(len(direct)) + uleb(len(virtual)))
        for group in (static_f, inst_f):
            previous = 0
            for index, access in group:
                body.extend(uleb(index - previous) + uleb(access))
                previous = index
        for group in (direct, virtual):
            previous = 0
            for index, access, offset in group:
                body.extend(uleb(index - previous) + uleb(access) + uleb(offset))
                previous = index

    section(0x2002, len(strings))
    string_offsets = []
    for s in strings:
        string_offsets.append(here())
        body.extend(mutf8(s))
    align()
    map_off = here()
    entries = [(0x0000, 1, 0), (0x0001, len(strings), string_off), (0x0002, len(type_list), type_off)]
    if proto_list:
        entries.append((0x0003, len(proto_list), proto_off))
    if field_list:
        entries.append((0x0004, len(field_list), field_off))
    if method_list:
        entries.append((0x0005, len(method_list), method_off))
    if classes:
        entries.append((0x0006, len(classes), class_off))
    entries += [(0x1000, 1, map_off)] + sections
    entries.sort(key=lambda e: e[2])
    body.extend(struct.pack("<I", len(entries)))
    for kind, count, offset in entries:
        body.extend(struct.pack("<HHII", kind, 0, count, offset))

    head = bytearray(data_off)
    for i, offset in enumerate(string_offsets):
        struct.pack_into("<I", head, string_off + 4 * i, offset)
    for i, t in enumerate(type_list):
        struct.pack_into("<I", head, type_off + 4 * i, sid[t])
    for i, (ret, params) in enumerate(proto_list):
        struct.pack_into("<III", head, proto_off + 12 * i, sid[shorty(ret, params)], tid[ret], param_lists.get(params, 0))
    for i, (owner, name, ty) in enumerate(field_list):
        struct.pack_into("<HHI", head, field_off + 8 * i, tid[owner], tid[ty], sid[name])
    for i, (owner, name, ret, params) in enumerate(method_list):
        struct.pack_into("<HHI", head, method_off + 8 * i, tid[owner], pid[(ret, params)], sid[name])
    for i, c in enumerate(classes):
        struct.pack_into("<IIIIIIII", head, class_off + 32 * i, tid[c.desc], c.access, tid[c.sup] if c.sup else NO_INDEX, 0,
                         NO_INDEX, 0, class_data.get(c.desc, 0), 0)
    data = bytearray(head + body)
    total = len(data)
    data[0:8] = b"dex\n" + version.encode("ascii") + b"\0"
    struct.pack_into("<I", data, 32, total)
    struct.pack_into("<I", data, 36, 112)
    struct.pack_into("<I", data, 40, 0x12345678)
    struct.pack_into("<I", data, 52, map_off)
    tables = {56: (len(strings), string_off), 64: (len(type_list), type_off), 72: (len(proto_list), proto_off if proto_list else 0),
              80: (len(field_list), field_off if field_list else 0), 88: (len(method_list), method_off if method_list else 0),
              96: (len(classes), class_off if classes else 0), 104: (total - data_off, data_off)}
    for position, (size, offset) in tables.items():
        struct.pack_into("<II", data, position, size, offset)
    data[12:32] = hashlib.sha1(bytes(data[32:])).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF)
    return bytes(data), layout


# ---- the ZIP ------------------------------------------------------------------------------------

def deflate_stored(data: bytes) -> bytes:
    if len(data) >= 0xFFFF:
        raise ValueError(f"a stored deflate fixture block must be under 65535 bytes, got {len(data)}")
    return b"\x01" + struct.pack("<HH", len(data), len(data) ^ 0xFFFF) + data


def zip_bytes(entries: list) -> bytes:
    """entries: (name, data, method) with method "stored" or "deflated". Duplicate names are written as given."""
    out = bytearray()
    central = bytearray()
    for name, data, method in entries:
        raw = name.encode("utf-8")
        payload, code = (data, 0) if method == "stored" else (deflate_stored(data), 8)
        crc = zlib.crc32(data) & 0xFFFFFFFF
        offset = len(out)
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, code, 0, 0x21, crc, len(payload), len(data), len(raw), 0) + raw + payload
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, (3 << 8) | 20, 20, 0, code, 0, 0x21, crc, len(payload), len(data),
                               len(raw), 0, 0, 0, 0, 0o100644 << 16, offset) + raw
    start = len(out)
    out += central
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(central), start, 0)
    return bytes(out)


# ---- the scenarios --------------------------------------------------------------------------------

def base_dex1() -> list:
    return [
        Klass(HOLDER, PUBLIC | ABSTRACT, OBJ, [("tag", STR, PRIVATE), ("COUNT", "I", PUBLIC | STATIC)], [
            meth("<init>", access=PUBLIC | CONSTRUCTOR, ops=[call("direct", OBJ, "<init>", args=(0,)), ("ret",)]),
            meth("bind", params=(STR, "I"), ops=[call("static", REPLY, "fetch", params=(STR,), args=(1,)), ("nop",), ("ret",)]),
            meth("m", params=("I",), ops=[("const4", 0, 1), ("ret",)]),
            meth("m", params=("I", "J"), ops=[("const4", 0, 2), ("ret",)]),
            meth("hook", params=("I",), access=PUBLIC | ABSTRACT, ops=None),
            meth("jni", ret="I", access=PUBLIC | NATIVE, ops=None),
        ], family="comment_legacy_v2"),
        Klass(ITEM, PUBLIC, OBJ, [], [
            meth("render", params=(COMPOSER, "I"), ops=[call("virtual", HOLDER, "bind", params=(STR, "I"), args=(0, 1, 2)), ("ret",)]),
        ], family="comment_native_legacy"),
        Klass(OTHERUI, PUBLIC, OBJ, [], [meth("x")], family="comment_other_ui:other"),
        Klass(PANEL, PUBLIC, OBJ, [], [
            meth("Content", params=(COMPOSER, "I"), access=PUBLIC | STATIC,
                 ops=[call("static", KREPLY, "list", args=()), ("ret",)]),
        ], family="comment_compose"),
        Klass(CARD, PUBLIC, OBJ, [("id", "J", PUBLIC)], [
            meth("bind", ops=[call("static", FOO, "ping", args=()), ("ret",)]),
        ], family="dynamic_other_legacy"),
        Klass(MISC, PUBLIC, OBJ, [], [
            meth("y", ops=[call("virtual", MISC, "y", args=(0,)), ("ret",)]),
        ], family="dynamic_other:(root)"),
        Klass(REPLY, PUBLIC, OBJ, [], [
            meth("fetch", params=(STR,), access=PUBLIC | STATIC),
            meth("list", access=PUBLIC | STATIC),
        ]),
        Klass(KREPLY, PUBLIC, OBJ, [], [meth("list", access=PUBLIC | STATIC)]),
        Klass(FOO, PUBLIC, OBJ, [], [meth("ping", access=PUBLIC | STATIC)]),
        Klass(CALLER, PUBLIC, OBJ, [], [
            meth("run", access=PUBLIC | STATIC, ops=[
                call("static", REPLY, "fetch", params=(STR,), args=(0,)), call("static", FOO, "ping"),
                ("range", "virtual", ref(HOLDER, "bind", "V", (STR, "I")), 0, 3), ("ret",)]),
            meth("plain"),
        ]),
    ]


def base_dex2() -> list:
    return [
        Klass(HOLDER, PUBLIC | ABSTRACT, OBJ, [("tag", STR, PRIVATE)], [
            meth("<init>", access=PUBLIC | CONSTRUCTOR, ops=[call("direct", OBJ, "<init>", args=(0,)), ("ret",)]),
            meth("other", ops=[("nop",), ("nop",), ("ret",)]),
        ], family="comment_legacy_v2"),
        Klass(HOME, PUBLIC, OBJ, [], [
            meth("show", ops=[call("static", REPLY, "other", params=("I",), args=(1,)), ("ret",)]),
        ], family="home_new_frame"),
        Klass(SEARCH, PUBLIC, OBJ, [("rows", "I", PUBLIC)], [
            meth("load", ops=[call("static", KREPLY, "list"), call("virtual", HOLDER, "other", args=(0,)), ("ret",)]),
            meth("count", ret="I", ops=[("const4", 0, 3), ("ret",)]),
        ], family="search_native"),
        Klass(REPLY, PUBLIC, OBJ, [], [meth("other", params=("I",), access=PUBLIC | STATIC)]),
        Klass(PLAIN, PUBLIC, OBJ, [], [meth("a"), meth("b")]),
    ]


RESOURCES_BASE = [
    ("resources.arsc", bytes.fromhex("00ff72657375726365"), "stored"),
    ("res/layout/a.xml", b"<layout a=1/>", "deflated"),
    ("res/xml/b.xml", b"<xml b=2/>", "stored"),
    ("res/layout/empty.xml", b"", "stored"),
    ("res/raw/blob.bin", b"not an xml resource", "stored"),
    ("res/drawable/not_xml.png", b"\x89PNG", "stored"),
    ("assets/c.xml", b"<outside res/>", "stored"),
    ("AndroidManifest.xml", b"binary manifest stand-in", "stored"),
]


def with_resource(entries: list, name: str, data: "bytes | None", method: str = "stored") -> list:
    out = [e for e in entries if e[0] != name]
    if data is not None:
        out.append((name, data, method))
    return out


def target_dex1() -> list:
    classes = [c for c in base_dex1() if c.desc != ITEM]  # a family retired
    for c in classes:
        if c.desc == HOLDER:  # a body changed: one more nop
            bind = next(m for m in c.methods if m.name == "bind")
            bind.ops = [call("static", REPLY, "fetch", params=(STR,), args=(1,)), ("nop",), ("nop",), ("ret",)]
        if c.desc == REPLY:  # a protocol signature added
            c.methods.append(meth("extra", access=PUBLIC | STATIC))
    return classes


def target_dex2() -> list:
    return base_dex2() + [Klass(PGC, PUBLIC, OBJ, [], [meth("open", ops=[call("static", REPLY, "fetch", params=(STR,), args=(0,)), ("ret",)])],
                                family="pgc_legacy")]


def fields_only_dex() -> list:
    return [Klass(HOLDER, PUBLIC | ABSTRACT, OBJ, [("tag", STR, PRIVATE), ("COUNT", "I", PUBLIC | STATIC)], [],
                  family="comment_legacy_v2"),
            Klass(CARD, PUBLIC, OBJ, [("id", "J", PUBLIC)], [], family="dynamic_other_legacy")]


def plain_dex() -> list:
    return [Klass(PLAIN, PUBLIC, OBJ, [], [meth("a"), meth("b")])]


def scenarios() -> dict:
    """name -> (ordered members [(name, bytes, method)], dex layouts {member: layout}, classes by member)"""
    result = {}

    def make(name, dex_members, resources):
        entries, layouts = [], {}
        for member, classes in dex_members.items():
            data, layout = build_dex(classes)
            entries.append((member, data, "stored"))
            layouts[member] = layout
        result[name] = (entries + list(resources), layouts, dex_members)

    make("base.apk", {"classes.dex": base_dex1(), "classes2.dex": base_dex2()}, RESOURCES_BASE)
    resources = with_resource(RESOURCES_BASE, "res/layout/a.xml", b"<layout a=1 changed/>", "deflated")
    resources = with_resource(resources, "res/xml/b.xml", None)
    resources = with_resource(resources, "res/layout/new.xml", b"<new/>")
    make("target.apk", {"classes.dex": target_dex1(), "classes2.dex": target_dex2()}, resources)
    make("fields-only.apk", {"classes.dex": fields_only_dex()}, [("resources.arsc", b"\x00", "stored")])
    make("plain.apk", {"classes.dex": plain_dex()}, [])
    make("duplicate-resource.apk", {"classes.dex": plain_dex()},
         [("res/layout/a.xml", b"first", "stored"), ("res/layout/a.xml", b"second", "stored")])
    return result


# ---- hand-derived expectations -----------------------------------------------------------------------

def spaced(proto: str) -> str:
    """The legacy fingerprint's order of prototypes: arguments separated by spaces (independently written here)."""
    inner, result = proto[1:].split(")", 1)
    tokens, i = [], 0
    while i < len(inner):
        j = i
        while inner[j] == "[":
            j += 1
        j = inner.index(";", j) + 1 if inner[j] == "L" else j + 1
        tokens.append(inner[i:j])
        i = j
    return "(" + " ".join(tokens) + ")" + result


def expectation(entries: list, layouts: dict, classes_by_member: dict) -> dict:
    out = {"members": [e[0] for e in entries], "dex": {}, "resource_sha256": {}}
    for member, classes in classes_by_member.items():
        dex = []
        for klass, rows in layouts[member]:
            methods = []
            for m, index, insns_off, units in rows:
                calls = [f"{op[2][0]}->{op[2][1]}(" + "".join(op[2][3]) + ")" + op[2][2] for op in (m.ops or ()) if op[0] in ("invoke", "range")]
                methods.append({"name": m.name, "proto": proto_text(m), "method_idx": index, "access": m.access,
                                "body": "none" if m.ops is None else "present", "insns_units": units, "insns_off": insns_off,
                                "calls": calls})
            dex.append({"descriptor": klass.desc, "expected_family": klass.family, "methods": methods,
                        "fields": sorted([n, t] for n, t, _ in klass.fields)})
        out["dex"][member] = dex
    for name, data, _method in entries:
        if name == "resources.arsc" or (name.startswith("res/") and name.endswith(".xml")):
            out["resource_sha256"][name] = hashlib.sha256(data).hexdigest()  # a duplicate keeps its last occurrence
    return out


def class_digest(members: list) -> str:
    """The class-body recipe, written independently here: sorted by (name, spaced prototype), each method contributes
    name+prototype and then its raw instruction bytes (nothing if it has none)."""
    digest = hashlib.sha256()
    for name, proto, raw in sorted(members, key=lambda m: (m[0], spaced(m[1]))):
        digest.update((name + proto).encode())
        digest.update(raw)
    return digest.hexdigest()


def expected_all(files: dict) -> dict:
    out = {}
    for name, (entries, layouts, classes_by_member) in files.items():
        info = expectation(entries, layouts, classes_by_member)
        # the raw bytes of every body and the class digest, from the units the generator wrote
        for member, dex in info["dex"].items():
            data = dict((e[0], e[1]) for e in entries)[member]
            for item in dex:
                parts = []
                for m in item["methods"]:
                    raw = b""
                    if m["insns_units"] is not None:
                        raw = data[m["insns_off"]:m["insns_off"] + 2 * m["insns_units"]]
                        m["insns_hex"] = raw.hex()
                        m["insns_sha256"] = hashlib.sha256(raw).hexdigest()
                    else:
                        m["insns_hex"] = None
                        m["insns_sha256"] = None
                    parts.append((m["name"], m["proto"], raw))
                item["method_bodies_sha256"] = class_digest(parts)
        out[name] = info
    return out


def main(argv: list[str]) -> int:
    files = scenarios()
    # the point of base.apk: the same number names different methods in the two DEX files
    base_layouts = files["base.apk"][1]
    seen = {}
    for member, layout in base_layouts.items():
        for klass, rows in layout:
            if klass.family:
                for m, index, _off, _units in rows:
                    seen.setdefault(index, {}).setdefault(member, set()).add((klass.desc, m.name, proto_text(m)))
    shared = sorted(i for i, per in seen.items() if len(per) == 2 and per["classes.dex"] != per["classes2.dex"])
    if not shared:
        raise RuntimeError("base.apk must have a method_idx that means different methods in its two DEX files")
    data = {}
    for name, (entries, _layouts, _classes) in files.items():
        data[name] = zip_bytes(entries)
    expected = expected_all(files)
    expected = {"schema": "mdd.surface-fixture-expectations.v1", "generator": "tests/fixtures/surface/generate.py",
                "shared_method_idx_in_base": shared,
                "files": {name: {"bytes": len(blob), "sha256": hashlib.sha256(blob).hexdigest(), **expected[name]}
                          for name, blob in data.items()}}
    text = json.dumps(expected, indent=1, sort_keys=True) + "\n"
    if "--check" in argv:
        ok = EXPECTED.exists() and EXPECTED.read_text(encoding="utf-8") == text
        for name, blob in data.items():
            path = OUT / name
            ok = ok and path.exists() and path.read_bytes() == blob
        print("surface fixtures are current" if ok else "surface fixtures are stale; run tests/fixtures/surface/generate.py")
        return 0 if ok else 1
    OUT.mkdir(exist_ok=True)
    for name, blob in data.items():
        (OUT / name).write_bytes(blob)
    EXPECTED.write_text(text, encoding="utf-8", newline="\n")
    for name, blob in data.items():
        print(f"wrote {name}: {len(blob)} bytes, sha256 {hashlib.sha256(blob).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
