#!/usr/bin/env python3
"""Write the DEX fixtures that the decode checks read. Standard library only.

The programs are written symbolically (an operation name, its operands, labels for branch
targets) and assembled here with the Dalvik instruction formats. Nothing in this file
renders smali, and it does not import the engine; the expected texts are written by hand
in conformance/decode/hand-expected.json and by the independent renderer in
conformance/decode/oracle.py, which reads the DEX bytes this script writes.

The opcode names and formats come from conformance/dex/instruction-matrix.json, the
AOSP-derived table the instruction decoder is tested against; it is shared data, not a
second opinion on what an opcode does.

Usage: python -I tests/fixtures/decode/generate.py [--check]
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import struct
import sys
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUT = HERE / "generated"
NO_INDEX = 0xFFFFFFFF
OBJECT = "Ljava/lang/Object;"
THIS = "Ldecode/T;"

MATRIX = json.loads((ROOT / "conformance/dex/instruction-matrix.json").read_text(encoding="utf-8"))["entries"]
BY_NAME = {e["mnemonic"]: e for e in MATRIX if not e["reserved"]}
WIDTH = {**{f: 1 for f in ("10x", "12x", "11n", "11x", "10t")},
         **{f: 2 for f in ("20t", "22x", "21t", "21s", "21h", "21c", "23x", "22b", "22t", "22s", "22c")},
         **{f: 3 for f in ("32x", "30t", "31t", "31i", "31c", "35c", "3rc")}, "45cc": 4, "4rcc": 4, "51l": 5}

ACC = {"public": 1, "private": 2, "protected": 4, "static": 8, "final": 0x10, "synchronized": 0x20, "bridge": 0x40,
       "varargs": 0x80, "native": 0x100, "abstract": 0x400, "strictfp": 0x800, "synthetic": 0x1000,
       "constructor": 0x10000, "declared-synchronized": 0x20000}


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


def units_of(text: str) -> list[int]:
    raw = text.encode("utf-16-le", "surrogatepass")
    return list(struct.unpack("<%dH" % (len(raw) // 2), raw))


def mutf8(text: str) -> bytes:
    units = units_of(text)
    data = bytearray(uleb(len(units)))
    for unit in units:
        if 0 < unit < 0x80:
            data.append(unit)
        elif unit < 0x800:
            data.extend([0xC0 | (unit >> 6), 0x80 | (unit & 0x3F)])
        else:
            data.extend([0xE0 | (unit >> 12), 0x80 | ((unit >> 6) & 0x3F), 0x80 | (unit & 0x3F)])
    return bytes(data) + b"\0"


class Method:
    def __init__(self, name, flags, params=(), ret="V", registers=0, ins=None, outs=0, code=None, tries=()):
        self.name, self.flags, self.params, self.ret = name, flags, tuple(params), ret
        self.registers, self.outs, self.code, self.tries = registers, outs, code, list(tries)
        if ins is None:
            ins = sum(2 if p in ("J", "D") else 1 for p in self.params) + (0 if "static" in flags else 1)
        self.ins = ins

    @property
    def access(self):
        return sum(ACC[f] for f in self.flags)

    @property
    def is_direct(self):
        return any(f in self.flags for f in ("static", "private", "constructor"))


class Program:
    """Collects every name the methods use, then assembles with final indexes."""

    def __init__(self):
        self.methods: list[Method] = []

    # ---- pools ----
    def pools(self):
        strings, types, fields, methods, protos = set(), {THIS, OBJECT, "V"}, set(), set(), set()
        for m in self.methods:
            types |= {m.ret, *m.params}
            protos.add((m.ret, m.params))
            methods.add((THIS, m.name, m.ret, m.params))
            for op in m.code or ():
                kind = op[0]
                if kind == "op":
                    for key, value in op[2].items():
                        if key == "string":
                            strings.add(value)
                        elif key == "type":
                            types.add(value)
                        elif key == "field":
                            fields.add(value)
                            types |= {value[0], value[2]}
                        elif key == "method":
                            methods.add(value)
                            types |= {value[0], value[2], *value[3]}
                            protos.add((value[2], value[3]))
                        elif key == "proto":
                            protos.add(value)
                            types |= {value[0], *value[1]}
            for t in m.tries:
                for catch in t["catches"]:
                    if catch[0] is not None:
                        types.add(catch[0])
        for ret, params in protos:
            types |= {ret, *params}
        names = {n for (_, n, *_) in methods} | {n for (_, n, _) in fields}
        shorty = lambda ret, params: ("L" if ret[0] in "L[" else ret) + "".join("L" if p[0] in "L[" else p for p in params)
        all_strings = strings | types | names | {shorty(r, p) for r, p in protos}
        return all_strings, types, fields, methods, protos, shorty

    def build(self, version="039") -> bytes:
        all_strings, types, fields, methods, protos, shorty = self.pools()
        key = lambda s: units_of(s)
        strings = sorted(all_strings, key=key)
        sidx = {s: i for i, s in enumerate(strings)}
        types = sorted(types, key=lambda t: sidx[t])
        tidx = {t: i for i, t in enumerate(types)}
        protos = sorted(protos, key=lambda p: (tidx[p[0]], [tidx[x] for x in p[1]]))
        pidx = {p: i for i, p in enumerate(protos)}
        fields = sorted(fields, key=lambda f: (tidx[f[0]], sidx[f[1]], tidx[f[2]]))
        fidx = {f: i for i, f in enumerate(fields)}
        methods = sorted(methods, key=lambda m: (tidx[m[0]], sidx[m[1]], pidx[(m[2], m[3])]))
        midx = {m: i for i, m in enumerate(methods)}

        string_off = 112
        type_off = string_off + 4 * len(strings)
        proto_off = type_off + 4 * len(types)
        field_off = proto_off + 12 * len(protos)
        method_off = field_off + 8 * len(fields)
        class_off = method_off + 8 * len(methods)
        data_off = class_off + 32
        body = bytearray()

        def here():
            return data_off + len(body)

        def align(n=4):
            body.extend(b"\0" * (-len(body) % n))

        # parameter lists
        param_lists = {}
        for ret, params in protos:
            if params and params not in param_lists:
                align()
                param_lists[params] = here()
                body.extend(struct.pack("<I", len(params)) + b"".join(struct.pack("<H", tidx[p]) for p in params))
                if len(params) % 2:
                    body.extend(b"\0\0")
        string_offsets = []
        string_data_off = here()
        for s in strings:
            string_offsets.append(here())
            body.extend(mutf8(s))

        code_offsets = {}
        first_code = None
        for m in self.methods:
            if m.code is None:
                continue
            align()
            if first_code is None:
                first_code = here()
            code_offsets[m.name] = here()
            units = self.assemble(m, sidx, tidx, fidx, midx, pidx)
            tries_bytes = b""
            if m.tries:
                handlers = bytearray(uleb(len(m.tries)))
                try_items = bytearray()
                for t in m.tries:
                    handler_at = len(handlers)
                    catches = t["catches"]
                    typed = [c for c in catches if c[0] is not None]
                    catch_all = [c for c in catches if c[0] is None]
                    handlers.extend(sleb(-len(typed) if catch_all else len(typed)))
                    for descriptor, label in typed:
                        handlers.extend(uleb(tidx[descriptor]) + uleb(t["labels"][label]))
                    if catch_all:
                        handlers.extend(uleb(t["labels"][catch_all[0][1]]))
                    try_items.extend(struct.pack("<IHH", t["start"], t["count"], handler_at))
                tries_bytes = bytes(try_items) + bytes(handlers)
            header = struct.pack("<HHHHII", m.registers, m.ins, m.outs, len(m.tries), 0, len(units))
            body.extend(header + b"".join(struct.pack("<H", u) for u in units))
            if m.tries and len(units) % 2:
                body.extend(b"\0\0")
            body.extend(tries_bytes)

        align()
        class_data_off = here()
        direct = sorted([m for m in self.methods if m.is_direct], key=lambda m: midx[(THIS, m.name, m.ret, m.params)])
        virtual = sorted([m for m in self.methods if not m.is_direct], key=lambda m: midx[(THIS, m.name, m.ret, m.params)])
        body.extend(uleb(0) + uleb(0) + uleb(len(direct)) + uleb(len(virtual)))
        for group in (direct, virtual):
            previous = 0
            for m in group:
                index = midx[(THIS, m.name, m.ret, m.params)]
                body.extend(uleb(index - previous) + uleb(m.access) + uleb(code_offsets.get(m.name, 0)))
                previous = index
        align()
        map_off = here()
        sections = [(0x0000, 1, 0), (0x0001, len(strings), string_off), (0x0002, len(types), type_off),
                    (0x0003, len(protos), proto_off)]
        if fields:
            sections.append((0x0004, len(fields), field_off))
        sections += [(0x0005, len(methods), method_off), (0x0006, 1, class_off)]
        if param_lists:
            sections.append((0x1001, len(param_lists), min(param_lists.values())))
        sections.append((0x2002, len(strings), string_data_off))
        if code_offsets:
            sections.append((0x2001, len(code_offsets), first_code))
        sections += [(0x2000, 1, class_data_off), (0x1000, 1, map_off)]
        sections.sort(key=lambda s: s[2])
        body.extend(struct.pack("<I", len(sections)))
        for kind, size, offset in sections:
            body.extend(struct.pack("<HHII", kind, 0, size, offset))

        head = bytearray(data_off)
        for i, offset in enumerate(string_offsets):
            struct.pack_into("<I", head, string_off + 4 * i, offset)
        for i, t in enumerate(types):
            struct.pack_into("<I", head, type_off + 4 * i, sidx[t])
        for i, (ret, params) in enumerate(protos):
            struct.pack_into("<III", head, proto_off + 12 * i, sidx[shorty(ret, params)], tidx[ret], param_lists.get(params, 0))
        for i, (owner, name, ty) in enumerate(fields):
            struct.pack_into("<HHI", head, field_off + 8 * i, tidx[owner], tidx[ty], sidx[name])
        for i, (owner, name, ret, params) in enumerate(methods):
            struct.pack_into("<HHI", head, method_off + 8 * i, tidx[owner], pidx[(ret, params)], sidx[name])
        struct.pack_into("<IIIIIIII", head, class_off, tidx[THIS], 1, tidx[OBJECT], 0, NO_INDEX, 0, class_data_off, 0)
        data = bytearray(head + body)
        total = len(data)
        data[0:8] = b"dex\n" + version.encode() + b"\0"
        struct.pack_into("<I", data, 32, total)
        struct.pack_into("<I", data, 36, 112)
        struct.pack_into("<I", data, 40, 0x12345678)
        struct.pack_into("<I", data, 52, map_off)
        for position, (size, offset) in {56: (len(strings), string_off), 64: (len(types), type_off),
                                         72: (len(protos), proto_off), 80: (len(fields), field_off if fields else 0),
                                         88: (len(methods), method_off), 96: (1, class_off),
                                         104: (total - data_off, data_off)}.items():
            struct.pack_into("<II", data, position, size, offset)
        data[12:32] = hashlib.sha1(bytes(data[32:])).digest()
        struct.pack_into("<I", data, 8, zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF)
        return bytes(data)

    # ---- assembly ----
    def assemble(self, method, sidx, tidx, fidx, midx, pidx):
        address, labels, placed = 0, {}, []
        for item in method.code:
            kind = item[0]
            if kind == "label":
                labels[item[1]] = address
            elif kind == "op":
                placed.append((address, item))
                address += WIDTH[BY_NAME[item[1]]["format"]]
            elif kind == "raw":
                placed.append((address, item))
                address += len(item[1])
            elif kind == "payload":
                if address % 2:  # a payload starts on an even code unit; the gap is a nop
                    placed.append((address, ("raw", [0])))
                    address += 1
                labels[item[1]] = address
                placed.append((address, item))
                address += item[3]
            else:
                raise ValueError(kind)
        units = []
        for at, item in placed:
            units.extend([0] * (at - len(units)))
            if item[0] == "raw":
                units.extend(item[1])
            elif item[0] == "payload":
                units.extend(self.payload_units(item, labels))
            else:
                units.extend(self.encode(item, at, labels, sidx, tidx, fidx, midx, pidx))
        for t in method.tries:
            t["labels"] = labels
            t["start"] = labels[t["start_label"]]
            t["count"] = labels[t["end_label"]] - labels[t["start_label"]]
        return units

    def payload_units(self, item, labels):
        """("payload", name, kind, width, ...). Switch offsets are relative to the switch instruction."""
        kind = item[2]
        if kind == "packed":
            first, targets = item[4], item[5]
            base = labels["__owner_" + item[1]]
            words = [0x0100, len(targets)] + split32(first)
            for target in targets:
                words += split32(labels[target] - base)
            return words
        if kind == "sparse":
            keys, targets = item[4], item[5]
            base = labels["__owner_" + item[1]]
            words = [0x0200, len(keys)]
            for k in keys:
                words += split32(k)
            for target in targets:
                words += split32(labels[target] - base)
            return words
        if kind == "array":
            width, values = item[4], item[5]
            raw = b"".join(int(v).to_bytes(width, "little", signed=True) for v in values)
            if len(raw) % 2:
                raw += b"\x00"
            words = [0x0300, width] + split32(len(values))
            words += list(struct.unpack("<%dH" % (len(raw) // 2), raw))
            return words
        raise ValueError(kind)

    def encode(self, item, at, labels, sidx, tidx, fidx, midx, pidx):
        _, name, o = item
        entry = BY_NAME[name]
        op, fmt = entry["opcode"], entry["format"]
        reg = o.get("regs", [])
        lit = o.get("literal")
        def ref():
            if "string" in o:
                return sidx[o["string"]]
            if "type" in o:
                return tidx[o["type"]]
            if "field" in o:
                return fidx[o["field"]]
            if "method" in o:
                return midx[o["method"]]
            if "proto" in o:
                return pidx[o["proto"]]
            return o["index"]
        off = lambda: labels[o["target"]] - at if "target" in o else o["offset"]
        if fmt == "10x":
            return [op]
        if fmt == "12x":
            return [op | reg[0] << 8 | reg[1] << 12]
        if fmt == "11n":
            return [op | reg[0] << 8 | (lit & 0xF) << 12]
        if fmt == "11x":
            return [op | reg[0] << 8]
        if fmt == "10t":
            return [op | (off() & 0xFF) << 8]
        if fmt == "20t":
            return [op, off() & 0xFFFF]
        if fmt == "22x":
            return [op | reg[0] << 8, reg[1]]
        if fmt == "21t":
            return [op | reg[0] << 8, off() & 0xFFFF]
        if fmt in ("21s", "21h"):
            return [op | reg[0] << 8, lit & 0xFFFF]
        if fmt == "21c":
            return [op | reg[0] << 8, ref()]
        if fmt == "23x":
            return [op | reg[0] << 8, reg[1] | reg[2] << 8]
        if fmt == "22b":
            return [op | reg[0] << 8, reg[1] | (lit & 0xFF) << 8]
        if fmt == "22t":
            return [op | reg[0] << 8 | reg[1] << 12, off() & 0xFFFF]
        if fmt == "22s":
            return [op | reg[0] << 8 | reg[1] << 12, lit & 0xFFFF]
        if fmt == "22c":
            return [op | reg[0] << 8 | reg[1] << 12, ref()]
        if fmt == "32x":
            return [op, reg[0], reg[1]]
        if fmt == "30t":
            return [op] + split32(off())
        if fmt == "31t":
            return [op | reg[0] << 8] + split32(labels[o["payload"]] - at)
        if fmt == "31i":
            return [op | reg[0] << 8] + split32(lit)
        if fmt == "31c":
            return [op | reg[0] << 8] + split32(ref())
        if fmt in ("35c", "45cc"):
            r = list(reg) + [0] * (5 - len(reg))
            words = [op | r[4] << 8 | len(reg) << 12, ref() if fmt == "35c" else midx[o["method"]],
                     r[0] | r[1] << 4 | r[2] << 8 | r[3] << 12]
            if fmt == "45cc":
                words.append(pidx[o["proto"]])
            return words
        if fmt in ("3rc", "4rcc"):
            words = [op | o["count"] << 8, ref() if fmt == "3rc" else midx[o["method"]], o["first"]]
            if fmt == "4rcc":
                words.append(pidx[o["proto"]])
            return words
        if fmt == "51l":
            bits = lit & 0xFFFFFFFFFFFFFFFF
            return [op | reg[0] << 8] + [(bits >> s) & 0xFFFF for s in (0, 16, 32, 48)]
        raise ValueError(fmt)


def split32(value: int) -> list[int]:
    value &= 0xFFFFFFFF
    return [value & 0xFFFF, value >> 16]


# ---- the programs ------------------------------------------------------------------------


def op(name, **operands):
    return ("op", name, operands)


def label(name):
    return ("label", name)


RET = op("return-void")

F_INT = (THIS, "count", "I")
F_OBJ = (THIS, "next", "Ldecode/T;")
F_WIDE = (THIS, "big", "J")
M_STATIC = ("Ldecode/Other;", "work", "V", ())
M_STATIC3 = ("Ldecode/Other;", "s3", "V", ("I", "I", "I"))
M_INSTANCE2 = ("Ldecode/Other;", "i2", "V", ("I", "I"))
M_VIRT = ("Ldecode/Other;", "poke", "V", ("I",))
M_INVOKE_EXACT = ("Ljava/lang/invoke/MethodHandle;", "invokeExact", "Ljava/lang/Object;", ("[Ljava/lang/Object;",))
P_POLY = ("V", ("I",))
STRING_CASES = ["plain", "quote\"and'apostrophe", "back\\slash", "line\nbreak\ttab\rreturn", "bell\bform\f",
                "nul\u0000char", "café", "中文", "emoji\U0001f600", "lone\ud800surrogate", "\u007fdel"]


def canned(name, entry):
    """One instruction for an opcode, with operands that are valid in a 16-register method."""
    fmt, index = entry["format"], entry["index_kind"]
    # the references layer checks that an invoke passes the words its prototype takes
    method = M_STATIC3 if name.startswith("invoke-static") else M_INSTANCE2
    ref = {"kIndexStringRef": {"string": "needle"}, "kIndexTypeRef": {"type": "Ljava/lang/String;"},
           "kIndexFieldRef": {"field": F_INT}, "kIndexMethodRef": {"method": method},
           "kIndexNone": {}}.get(index)
    if index == "kIndexTypeRef" and name in ("new-array", "filled-new-array", "filled-new-array/range"):
        ref = {"type": "[I"}
    if index == "kIndexFieldRef" and "wide" in name:
        ref = {"field": F_WIDE}
    if index == "kIndexFieldRef" and "object" in name:
        ref = {"field": F_OBJ}
    if fmt == "10x":
        return op(name)
    if fmt == "12x":
        return op(name, regs=[1, 2])
    if fmt == "11n":
        return op(name, regs=[1], literal=-3)
    if fmt == "11x":
        return op(name, regs=[3])
    if fmt in ("10t", "20t", "30t"):
        return op(name, target="after")
    if fmt == "22x":
        return op(name, regs=[1, 5])
    if fmt == "32x":
        return op(name, regs=[7, 8])
    if fmt == "21t":
        return op(name, regs=[2], target="after")
    if fmt == "21s":
        return op(name, regs=[2], literal=-12345)
    if fmt == "21h":
        return op(name, regs=[2], literal=0x3F80 if name == "const/high16" else 0xBFF0)
    if fmt == "21c":
        return op(name, regs=[4], **ref)
    if fmt == "23x":
        return op(name, regs=[1, 2, 3])
    if fmt == "22b":
        return op(name, regs=[1, 2], literal=-5)
    if fmt == "22t":
        return op(name, regs=[1, 2], target="after")
    if fmt == "22s":
        return op(name, regs=[1, 2], literal=-1234)
    if fmt == "22c":
        return op(name, regs=[1, 2], **ref)
    if fmt == "31i":
        return op(name, regs=[2], literal=-123456789)
    if fmt == "31c":
        return op(name, regs=[2], string="needle")
    if fmt == "35c":
        if name == "filled-new-array":
            return op(name, regs=[1, 2, 3], type="[I")
        return op(name, regs=[1, 2, 3], **ref)
    if fmt == "3rc":
        if name == "filled-new-array/range":
            return op(name, count=3, first=2, type="[I")
        return op(name, count=3, first=2, **ref)
    if fmt == "45cc":
        return op(name, regs=[1, 2], method=M_INVOKE_EXACT, proto=P_POLY)
    if fmt == "4rcc":
        return op(name, count=2, first=2, method=M_INVOKE_EXACT, proto=P_POLY)
    if fmt == "51l":
        return op(name, regs=[2], literal=-0x0123456789ABCDEF)
    raise ValueError((name, fmt))


# opcodes whose operands need tables this fixture does not build (call sites, method handles)
SKIPPED = {"invoke-custom", "invoke-custom/range", "const-method-handle", "const-method-type"}
PAYLOAD_OPS = {"fill-array-data", "packed-switch", "sparse-switch"}


def program() -> Program:
    p = Program()
    # one method per opcode
    for entry in MATRIX:
        if entry["reserved"] or entry["mnemonic"] in SKIPPED | PAYLOAD_OPS:
            continue
        name = entry["mnemonic"]
        if name in ("move-result", "move-result-wide", "move-result-object", "move-exception", "return-void", "throw"):
            pass
        p.methods.append(Method("op_%02x" % entry["opcode"], ["public", "static"], registers=16, outs=5,
                                code=[canned(name, entry), label("after"), RET]))
    # payload instructions
    p.methods.append(Method("switch_packed", ["public", "static"], registers=4, code=[
        op("packed-switch", regs=[0], payload="table"), op("goto", target="out"), label("one"), op("const/4", regs=[1], literal=1),
        label("out"), RET, ("payload", "table", "packed", 8, -1, ["one", "out", "one"], None)]))
    p.methods.append(Method("switch_sparse", ["public", "static"], registers=4, code=[
        op("sparse-switch", regs=[0], payload="table"), op("goto", target="out"), label("a"), op("const/4", regs=[1], literal=1),
        label("out"), RET, ("payload", "table", "sparse", 12, [-5, 7, 100000], ["a", "out", "a"], None)]))
    for width in (1, 2, 4, 8):
        values = [1, -2, 3] if width < 8 else [1, -2, 0x7FFFFFFFFFFFFFFF]
        p.methods.append(Method("array_w%d" % width, ["public", "static"], registers=3, code=[
            op("fill-array-data", regs=[0], payload="data"), RET, ("payload", "data", "array", 0, width, values, None)]))
    return p


def set_payload_sizes(p: Program):
    """Fill in each payload item's width in code units (the assembler needs it before it can encode)."""
    for m in p.methods:
        if not m.code:
            continue
        fixed = []
        for item in m.code:
            if item[0] == "payload":
                kind = item[2]
                if kind == "packed":
                    width = 4 + 2 * len(item[5])
                elif kind == "sparse":
                    width = 2 + 4 * len(item[4])
                else:
                    width = 4 + (len(item[5]) * item[4] + 1) // 2
                fixed.append(("payload", item[1], kind, width, item[4], item[5], item[6]))
            elif item[0] == "op" and item[1] in ("packed-switch", "sparse-switch"):
                # offsets in a switch payload are relative to the switch instruction
                fixed.append(("label", "__owner_" + item[2]["payload"]))
                fixed.append(item)
            else:
                fixed.append(item)
        m.code = fixed


def more_methods(p: Program):
    S = ["public", "static"]
    # parameters and the p-register names: instance method (this + I + J + String), registers 6, ins 5
    p.methods.append(Method("params_instance", ["public"], params=["I", "J", "Ljava/lang/String;"], ret="I", registers=7, outs=2,
                            code=[op("move", regs=[0, 1]), op("move-wide", regs=[2, 3]), op("move-object", regs=[4, 6]),
                                  op("invoke-virtual", regs=[2, 5], method=M_VIRT), op("return", regs=[0])]))
    p.methods.append(Method("params_static", S, params=["J", "I"], ret="J", registers=4, outs=0,
                            code=[op("move-wide", regs=[0, 2]), op("return-wide", regs=[0])]))
    p.methods.append(Method("call_ranges", S, registers=8, outs=5, code=[
        op("invoke-static/range", count=4, first=3, method=("Ldecode/Other;", "wide", "V", ("I", "I", "I", "I"))),
        op("invoke-static/range", count=1, first=7, method=("Ldecode/Other;", "one", "V", ("I",))),
        op("invoke-static", method=M_STATIC), op("invoke-static", regs=[0, 1, 2, 3, 4], method=("Ldecode/Other;", "five", "V", ("I",) * 5)), RET]))
    # literals
    p.methods.append(Method("literals", S, registers=4, code=[
        op("const/4", regs=[0], literal=7), op("const/4", regs=[0], literal=-8), op("const/16", regs=[1], literal=0x7FFF),
        op("const", regs=[1], literal=-2147483648), op("const", regs=[1], literal=2147483647),
        op("const/high16", regs=[1], literal=0x8000), op("const-wide/16", regs=[2], literal=-1),
        op("const-wide/32", regs=[2], literal=0x7FFFFFFF), op("const-wide", regs=[2], literal=-0x8000000000000000),
        op("const-wide", regs=[2], literal=0x7FFFFFFFFFFFFFFF), op("const-wide/high16", regs=[2], literal=0x8000),
        op("add-int/lit8", regs=[0, 1], literal=127), op("add-int/lit8", regs=[0, 1], literal=-128),
        op("add-int/lit16", regs=[0, 1], literal=-32768), op("rsub-int", regs=[0, 1], literal=32767), RET]))
    # strings and the characters that need escapes
    p.methods.append(Method("strings", S, registers=2, code=[op("const-string", regs=[0], string=s) for s in STRING_CASES] + [
        op("const-string/jumbo", regs=[1], string="plain"), RET]))
    # branches forward and backward
    p.methods.append(Method("branches", S, registers=3, code=[
        label("top"), op("if-eq", regs=[0, 1], target="done"), op("if-nez", regs=[0], target="top"),
        op("goto/16", target="done"), op("goto/32", target="top"), op("goto", target="done"), label("done"), RET]))
    # try / catch
    p.methods.append(Method("try_catch", S, registers=3, outs=0, code=[
        label("s1"), op("invoke-static", method=M_STATIC), label("e1"), label("s2"),
        op("invoke-static", method=M_STATIC), op("invoke-static", method=M_STATIC), label("e2"), RET,
        label("h1"), op("move-exception", regs=[0]), op("throw", regs=[0]),
        label("h2"), op("move-exception", regs=[1]), RET],
        tries=[{"start_label": "s1", "end_label": "e1", "catches": [("Ljava/io/IOException;", "h1"), ("Ljava/lang/RuntimeException;", "h2")]},
               {"start_label": "s2", "end_label": "e2", "catches": [("Ljava/lang/Exception;", "h2"), (None, "h1")]}]))
    p.methods.append(Method("try_to_end", S, registers=2, outs=0, code=[
        label("s"), op("invoke-static", method=M_STATIC), op("nop"), label("e")],
        tries=[{"start_label": "s", "end_label": "e", "catches": [(None, "s")]}]))
    # no body
    p.methods.append(Method("abstract_one", ["public", "abstract"], params=["I"], ret="I"))
    p.methods.append(Method("native_one", ["public", "static", "native", "synchronized"], params=["Ljava/lang/String;"], ret="Z"))
    p.methods.append(Method("<init>", ["public", "constructor"], registers=1, outs=1, code=[
        op("invoke-direct", regs=[0], method=(OBJECT, "<init>", "V", ())), RET]))
    p.methods.append(Method("<clinit>", ["static", "constructor"], registers=1, code=[RET]))
    p.methods.append(Method("all_flags", ["public", "final", "synchronized", "bridge", "varargs", "synthetic"], params=["[I"], registers=2, code=[RET]))
    # a method name that is not ASCII, so a page can be cut inside a character (2 and 3 bytes)
    p.methods.append(Method(chr(0xE9) + chr(0x4E2D), S, registers=1, code=[
        op("const-string", regs=[0], string="needle"), RET]))
    # a long method for paging: 1500 lines of body
    p.methods.append(Method("long_body", S, registers=2, code=[op("const/4", regs=[i % 2], literal=i % 8) for i in range(1500)] + [RET]))


def build_all() -> dict[str, bytes]:
    p = program()
    more_methods(p)
    set_payload_sizes(p)
    dex = small().build("035")
    return {"decode-all.dex": p.build(), "decode-v035.dex": dex,
            "decode-bad-invoke.dex": bad_invoke().build("035"),
            "manifest-small.apk": apk({"AndroidManifest.xml": manifest_axml(), "classes.dex": dex}),
            "no-manifest.apk": apk({"classes.dex": dex})}


def manifest_axml() -> bytes:
    """The compiled manifest of tests/fixtures/manifest, without typed application attributes."""
    spec = importlib.util.spec_from_file_location("manifest_fixture", ROOT / "tests/fixtures/manifest/generate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    data, _tree = module.encode(typed=False)
    return data


def apk(members: dict[str, bytes]) -> bytes:
    """A stored (uncompressed) ZIP with fixed timestamps, so the bytes are reproducible."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, data in members.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o644 << 16
            info.create_system = 3  # Unix, whatever host writes the file: the bytes must not depend on it
            archive.writestr(info, data)
    return buffer.getvalue()


def small() -> Program:
    """A second, tiny DEX of an older version, for the identity and file_id checks."""
    p = Program()
    p.methods.append(Method("only_here", ["public", "static"], registers=1, code=[
        op("const-string", regs=[0], string="old"), RET]))
    p.methods.append(Method("op_00", ["public", "static"], registers=16, code=[op("nop"), label("after"), RET]))
    return p


def bad_invoke() -> Program:
    """Instructions that decode, but one invoke passes fewer words than its prototype takes."""
    p = Program()
    p.methods.append(Method("good", ["public", "static"], registers=1, code=[
        op("const-string", regs=[0], string="fine"), RET]))
    p.methods.append(Method("mismatch", ["public", "static"], registers=2, outs=1, code=[
        op("invoke-static", regs=[0], method=("Ldecode/Other;", "two", "V", ("I", "I"))), RET]))
    return p


def main(argv: list[str]) -> int:
    files = build_all()
    OUT.mkdir(exist_ok=True)
    manifest = {"schema_version": "mdd.decode-fixtures.v1", "generator": "tests/fixtures/decode/generate.py",
                "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)} for name, data in sorted(files.items())},
                "note": "synthetic layout fixtures, not installable APKs; programs are written symbolically and assembled here"}
    if "--check" in argv:
        recorded = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
        same = recorded == manifest and all((OUT / n).read_bytes() == d for n, d in files.items())
        print("fixtures reproduce byte for byte:", same)
        return 0 if same else 1
    for name, data in files.items():
        (OUT / name).write_bytes(data)
    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print({n: len(d) for n, d in files.items()})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
