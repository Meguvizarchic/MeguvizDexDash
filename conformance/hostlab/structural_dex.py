#!/usr/bin/env python3
"""A declarative writer for small synthetic DEX files and APKs (MDD-051 fixtures). Standard library only.

It exists so that the structural audit can be run over inputs whose every byte is known: classes with
superclass and interfaces, fields, methods (with or without a body), generic `dalvik.annotation.Signature`
annotations on classes, fields and methods, string constants in method bodies and repeated calls.
It does not import the engine under test, any reader of DEX files, or HostLab. The files it writes are
not claimed to be ART-verified or installable; they follow the layout the format prescribes (sorted
pools, a map list, SHA-1 signature, Adler-32 checksum), which is what the engine and the reference
engine parse.

Only ASCII names and strings are accepted: for those, the order of code points is the order of UTF-16
code units, which is the order the format requires for the string pool.
"""
from __future__ import annotations

import hashlib
import io
import struct
import warnings
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Sequence

NO_INDEX = 0xFFFFFFFF
OBJECT = "Ljava/lang/Object;"
SIGNATURE = "Ldalvik/annotation/Signature;"
ACC_PUBLIC, ACC_PRIVATE, ACC_PROTECTED, ACC_STATIC, ACC_FINAL = 0x1, 0x2, 0x4, 0x8, 0x10
ACC_ABSTRACT, ACC_INTERFACE, ACC_ENUM, ACC_SYNTHETIC, ACC_CONSTRUCTOR = 0x400, 0x200, 0x4000, 0x1000, 0x10000
ACC_SUPER = 0x20
INVOKE = {"virtual": 0x6E, "super": 0x6F, "direct": 0x70, "static": 0x71, "interface": 0x72}
PRIMITIVES = set("VZBSCIJFD")


@dataclass
class FieldSpec:
    name: str
    type: str
    access: int = ACC_PUBLIC
    signature: "str | None" = None


@dataclass
class MethodSpec:
    name: str
    ret: str = "V"
    params: tuple = ()
    access: int = ACC_PUBLIC
    signature: "str | None" = None
    # None: a default body (or none for an abstract method). Otherwise a list of operations:
    #   ("const-string", register, text)         21c
    #   ("const4", register, literal)            11n
    #   ("invoke", kind, (owner, name, ret, params), (registers...))   35c, kind in INVOKE
    #   ("return-void",) / ("return", register)
    code: "list | None" = None
    ins_words: "int | None" = None  # override of the incoming register words (a deliberately wrong code item)


@dataclass
class ClassSpec:
    descriptor: str
    access: int = ACC_PUBLIC
    superclass: "str | None" = OBJECT
    interfaces: tuple = ()
    fields: list = field(default_factory=list)
    methods: list = field(default_factory=list)
    signature: "str | None" = None
    source_file: "str | None" = None


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
        raise ValueError("the synthetic writer accepts non-NUL ASCII strings only: " + repr(text))
    return uleb(len(text)) + text.encode("ascii") + b"\0"


def shorty_letter(descriptor: str) -> str:
    return descriptor if descriptor in PRIMITIVES else "L"


def shorty(ret: str, params: Sequence[str]) -> str:
    return shorty_letter(ret) + "".join(shorty_letter(p) for p in params)


def signature_pieces(text: str) -> list[str]:
    """Split a generic signature the way compilers do: after each type name, so that every piece is short."""
    pieces, current = [], ""
    for char in text:
        current += char
        if char in ";<>(":
            pieces.append(current)
            current = ""
    if current:
        pieces.append(current)
    return pieces


def _value_width(index: int) -> int:
    return max(1, (index.bit_length() + 7) // 8)


def _string_value(index: int) -> bytes:
    width = _value_width(index)
    return bytes([((width - 1) << 5) | 0x17]) + index.to_bytes(width, "little")


def _default_body(method: MethodSpec) -> "list | None":
    if method.access & (ACC_ABSTRACT | 0x100):  # abstract or native
        return None
    ret = method.ret
    if ret == "V":
        return [("return-void",)]
    return [("const4", 0, 0), ("return", 0)]


def _return_op(ret: str) -> int:
    if ret in ("J", "D"):
        return 0x10
    if ret in PRIMITIVES:
        return 0x0F
    return 0x11


def build_dex(classes: Sequence[ClassSpec], version: str = "039") -> bytes:
    classes = _class_order(list(classes))
    defined = {c.descriptor for c in classes}
    if len(defined) != len(classes):
        raise ValueError("a class is defined twice in one DEX")

    # ---- every name the file mentions ------------------------------------------------------
    type_names: set[str] = {SIGNATURE} if any(
        c.signature or any(f.signature for f in c.fields) or any(m.signature for m in c.methods) for c in classes) else set()
    strings: set[str] = set()
    proto_set: set[tuple] = set()
    field_set: set[tuple] = set()
    method_set: set[tuple] = set()

    def need_type(name: str) -> None:
        type_names.add(name)

    def need_method(owner: str, name: str, ret: str, params: tuple) -> None:
        need_type(owner)
        need_type(ret)
        for p in params:
            need_type(p)
        proto_set.add((ret, tuple(params)))
        method_set.add((owner, name, ret, tuple(params)))

    for c in classes:
        need_type(c.descriptor)
        if c.superclass:
            need_type(c.superclass)
        for i in c.interfaces:
            need_type(i)
        for f in c.fields:
            need_type(f.type)
            field_set.add((c.descriptor, f.name, f.type))
        for m in c.methods:
            need_method(c.descriptor, m.name, m.ret, tuple(m.params))
            body = m.code if m.code is not None else _default_body(m)
            for op in body or []:
                if op[0] == "invoke":
                    need_method(*op[2][:3], tuple(op[2][3]))
                elif op[0] == "const-string":
                    strings.add(op[2])
        if c.source_file:
            strings.add(c.source_file)
        for text in [c.signature] + [f.signature for f in c.fields] + [m.signature for m in c.methods]:
            if text:
                strings.update(signature_pieces(text))
    if any(c.signature or any(f.signature for f in c.fields) or any(m.signature for m in c.methods) for c in classes):
        strings.add("value")
    strings |= type_names
    strings |= {f[1] for f in field_set} | {m[1] for m in method_set}
    strings |= {shorty(r, p) for r, p in proto_set}
    for text in strings:
        mutf8(text)  # ASCII check
    strings_sorted = sorted(strings)
    sid = {s: i for i, s in enumerate(strings_sorted)}
    types = sorted(type_names, key=lambda t: sid[t])
    tid = {t: i for i, t in enumerate(types)}
    protos = sorted(proto_set, key=lambda p: (tid[p[0]], [tid[x] for x in p[1]]))
    pid = {p: i for i, p in enumerate(protos)}
    fields = sorted(field_set, key=lambda f: (tid[f[0]], sid[f[1]], tid[f[2]]))
    fid = {f: i for i, f in enumerate(fields)}
    methods = sorted(method_set, key=lambda m: (tid[m[0]], sid[m[1]], pid[(m[2], m[3])]))
    mid = {m: i for i, m in enumerate(methods)}

    string_off = 112
    type_off = string_off + 4 * len(strings_sorted)
    proto_off = type_off + 4 * len(types)
    field_off = proto_off + 12 * len(protos)
    method_off = field_off + 8 * len(fields)
    class_off = method_off + 8 * len(methods)
    data_off = class_off + 32 * len(classes)
    body = bytearray()
    map_entries: list[tuple[int, int, int]] = []

    def here() -> int:
        return data_off + len(body)

    def align() -> None:
        body.extend(b"\0" * (-len(body) % 4))

    def section(kind: int, count: int) -> None:
        if count:
            align()
            map_entries.append((kind, count, here()))

    # ---- type lists: parameters and interfaces -----------------------------------------------
    lists: dict[tuple, int] = {}
    wanted = []
    for params in sorted({p for _, p in protos if p}):
        wanted.append(params)
    for c in classes:
        if c.interfaces and tuple(c.interfaces) not in wanted:
            wanted.append(tuple(c.interfaces))
    section(0x1001, len(wanted))
    for params in wanted:
        align()
        lists[params] = here()
        body.extend(struct.pack("<I", len(params)) + b"".join(struct.pack("<H", tid[p]) for p in params))

    # ---- annotations (Signature only) ---------------------------------------------------------
    items: dict[str, bytes] = {}

    def signature_item(text: str) -> bytes:
        pieces = signature_pieces(text)
        value = bytes([0x1C]) + uleb(len(pieces)) + b"".join(_string_value(sid[p]) for p in pieces)
        return bytes([2]) + uleb(tid[SIGNATURE]) + uleb(1) + uleb(sid["value"]) + value

    wanted_items = sorted({t for c in classes for t in
                           [c.signature] + [f.signature for f in c.fields] + [m.signature for m in c.methods] if t})
    section(0x2004, len(wanted_items))
    item_off: dict[str, int] = {}
    for text in wanted_items:
        item_off[text] = here()
        body.extend(signature_item(text))
    section(0x1003, len(wanted_items))
    set_off: dict[str, int] = {}
    for text in wanted_items:
        align()
        set_off[text] = here()
        body.extend(struct.pack("<II", 1, item_off[text]))
    directories: dict[str, int] = {}
    with_directory = [c for c in classes if c.signature or any(f.signature for f in c.fields)
                      or any(m.signature for m in c.methods)]
    section(0x2006, len(with_directory))
    for c in with_directory:
        align()
        directories[c.descriptor] = here()
        annotated_fields = sorted((fid[(c.descriptor, f.name, f.type)], set_off[f.signature]) for f in c.fields if f.signature)
        annotated_methods = sorted((mid[(c.descriptor, m.name, m.ret, tuple(m.params))], set_off[m.signature])
                                   for m in c.methods if m.signature)
        body.extend(struct.pack("<IIII", set_off[c.signature] if c.signature else 0, len(annotated_fields),
                                len(annotated_methods), 0))
        for index, off in annotated_fields + annotated_methods:
            body.extend(struct.pack("<II", index, off))

    # ---- code items ----------------------------------------------------------------------------
    code_off: dict[tuple, int] = {}
    bodies = []
    for c in classes:
        for m in c.methods:
            ops = m.code if m.code is not None else _default_body(m)
            if ops is not None:
                bodies.append((c, m, ops))
    section(0x2001, len(bodies))
    for c, m, ops in bodies:
        units: list[int] = []
        outs = 0
        used = 0
        for op in ops:
            kind = op[0]
            if kind == "const-string":
                units += [(op[1] << 8) | 0x1A, sid[op[2]]]
                used = max(used, op[1] + 1)
            elif kind == "const4":
                units += [((op[2] & 0xF) << 12) | (op[1] << 8) | 0x12]
                used = max(used, op[1] + 1)
            elif kind == "invoke":
                regs = list(op[3])
                if len(regs) > 5 or any(r > 15 for r in regs):
                    raise ValueError("an invoke takes at most five registers v0..v15")
                target = mid[(op[2][0], op[2][1], op[2][2], tuple(op[2][3]))]
                nibbles = (regs + [0] * 5)[:5]
                units += [(len(regs) << 12) | (nibbles[4] << 8) | INVOKE[op[1]], target,
                          nibbles[0] | (nibbles[1] << 4) | (nibbles[2] << 8) | (nibbles[3] << 12)]
                outs = max(outs, len(regs))
                used = max(used, max(regs, default=-1) + 1)
            elif kind == "return-void":
                units += [0x000E]
            elif kind == "return":
                units += [(op[1] << 8) | _return_op(m.ret)]
                used = max(used, op[1] + 1)
            else:
                raise ValueError("unknown operation " + kind)
        ins = (m.ins_words if m.ins_words is not None
               else sum(2 if p in ("J", "D") else 1 for p in m.params) + (0 if m.access & ACC_STATIC else 1))  # wide values take two words
        registers = max(ins + 1, used + 1, 2 if m.ret in ("J", "D") else 1)
        align()
        code_off[(c.descriptor, m.name, m.ret, tuple(m.params))] = here()
        body.extend(struct.pack("<HHHHII", registers, ins, outs, 0, 0, len(units)))
        body.extend(b"".join(struct.pack("<H", u & 0xFFFF) for u in units))

    # ---- class data ------------------------------------------------------------------------------
    section(0x2000, sum(1 for c in classes if c.fields or c.methods))
    class_data: dict[str, int] = {}
    for c in classes:
        if not (c.fields or c.methods):
            continue
        static_fields = sorted((fid[(c.descriptor, f.name, f.type)], f.access) for f in c.fields if f.access & ACC_STATIC)
        instance_fields = sorted((fid[(c.descriptor, f.name, f.type)], f.access) for f in c.fields if not f.access & ACC_STATIC)

        def is_direct(m: MethodSpec) -> bool:
            return bool(m.access & (ACC_STATIC | ACC_PRIVATE | ACC_CONSTRUCTOR)) or m.name in ("<init>", "<clinit>")

        def flags(m: MethodSpec) -> int:
            return m.access | (ACC_CONSTRUCTOR if m.name in ("<init>", "<clinit>") else 0)

        direct = sorted((mid[(c.descriptor, m.name, m.ret, tuple(m.params))], flags(m), m) for m in c.methods if is_direct(m))
        virtual = sorted((mid[(c.descriptor, m.name, m.ret, tuple(m.params))], flags(m), m) for m in c.methods if not is_direct(m))
        class_data[c.descriptor] = here()
        body.extend(uleb(len(static_fields)) + uleb(len(instance_fields)) + uleb(len(direct)) + uleb(len(virtual)))
        for group in (static_fields, instance_fields):
            previous = 0
            for index, access in group:
                body.extend(uleb(index - previous) + uleb(access))
                previous = index
        for group in (direct, virtual):
            previous = 0
            for index, access, m in group:
                body.extend(uleb(index - previous) + uleb(access)
                            + uleb(code_off.get((c.descriptor, m.name, m.ret, tuple(m.params)), 0)))
                previous = index

    # ---- string data ------------------------------------------------------------------------------
    section(0x2002, len(strings_sorted))
    string_offsets = []
    for s in strings_sorted:
        string_offsets.append(here())
        body.extend(mutf8(s))
    align()
    map_off = here()
    entries = [(0x0000, 1, 0), (0x0001, len(strings_sorted), string_off), (0x0002, len(types), type_off),
               (0x0003, len(protos), proto_off), (0x0004, len(fields), field_off), (0x0005, len(methods), method_off),
               (0x0006, len(classes), class_off), (0x1000, 1, map_off)]
    entries = [e for e in entries if e[1]] + map_entries
    entries.sort(key=lambda e: e[2])
    body.extend(struct.pack("<I", len(entries)))
    for kind, count, offset in entries:
        body.extend(struct.pack("<HHII", kind, 0, count, offset))

    # ---- the id tables and the header --------------------------------------------------------------
    head = bytearray(data_off)
    for i, offset in enumerate(string_offsets):
        struct.pack_into("<I", head, string_off + 4 * i, offset)
    for i, t in enumerate(types):
        struct.pack_into("<I", head, type_off + 4 * i, sid[t])
    for i, (ret, params) in enumerate(protos):
        struct.pack_into("<III", head, proto_off + 12 * i, sid[shorty(ret, params)], tid[ret], lists.get(params, 0))
    for i, (owner, name, ty) in enumerate(fields):
        struct.pack_into("<HHI", head, field_off + 8 * i, tid[owner], tid[ty], sid[name])
    for i, (owner, name, ret, params) in enumerate(methods):
        struct.pack_into("<HHI", head, method_off + 8 * i, tid[owner], pid[(ret, params)], sid[name])
    for i, c in enumerate(classes):
        struct.pack_into("<IIIIIIII", head, class_off + 32 * i, tid[c.descriptor], c.access,
                         tid[c.superclass] if c.superclass else NO_INDEX,
                         lists.get(tuple(c.interfaces), 0) if c.interfaces else 0,
                         sid[c.source_file] if c.source_file else NO_INDEX,
                         directories.get(c.descriptor, 0), class_data.get(c.descriptor, 0), 0)
    data = bytearray(head + body)
    total = len(data)
    data[0:8] = b"dex\n" + version.encode("ascii") + b"\0"
    struct.pack_into("<I", data, 32, total)
    struct.pack_into("<I", data, 36, 112)
    struct.pack_into("<I", data, 40, 0x12345678)
    struct.pack_into("<I", data, 52, map_off)
    for position, (size, offset) in {56: (len(strings_sorted), string_off), 64: (len(types), type_off),
                                     72: (len(protos), proto_off), 80: (len(fields), field_off),
                                     88: (len(methods), method_off), 96: (len(classes), class_off),
                                     104: (total - data_off, data_off)}.items():
        struct.pack_into("<II", data, position, size, offset if size else 0)
    data[12:32] = hashlib.sha1(bytes(data[32:])).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF)
    return bytes(data)


def _class_order(classes: list[ClassSpec]) -> list[ClassSpec]:
    """Superclasses and interfaces defined in the file come first, as the format requires; otherwise the given order."""
    by_name = {c.descriptor: c for c in classes}
    ordered: list[ClassSpec] = []
    state: dict[str, int] = {}

    def visit(c: ClassSpec) -> None:
        if state.get(c.descriptor) == 2:
            return
        if state.get(c.descriptor) == 1:
            raise ValueError("cyclic class hierarchy: " + c.descriptor)
        state[c.descriptor] = 1
        for parent in [c.superclass, *c.interfaces]:
            if parent in by_name:
                visit(by_name[parent])
        state[c.descriptor] = 2
        ordered.append(c)

    for c in classes:
        visit(c)
    return ordered


def build_apk(members: "Sequence[tuple[str, bytes]]") -> bytes:
    """A stored ZIP with fixed timestamps: the same bytes on every run and with every zlib."""
    target = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as writer:
        warnings.simplefilter("ignore", UserWarning)
        for name, data in members:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            writer.writestr(info, data)
    return target.getvalue()


# ---- short ways to write descriptors -------------------------------------------------------------------------

PRIMITIVE_NAMES = {"void": "V", "boolean": "Z", "byte": "B", "short": "S", "char": "C", "int": "I", "long": "J",
                   "float": "F", "double": "D"}


def desc(java_name: str) -> str:
    """`java.util.List` -> `Ljava/util/List;`; `int` -> `I`; `int[]` -> `[I`."""
    if java_name.endswith("[]"):
        return "[" + desc(java_name[:-2])
    if java_name in PRIMITIVE_NAMES:
        return PRIMITIVE_NAMES[java_name]
    return "L" + java_name.replace(".", "/") + ";"
