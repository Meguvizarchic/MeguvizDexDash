#!/usr/bin/env python3
"""Synthetic DEX fixtures for MDD-070 public-relation qualification.

Standard library only; does not import the engine under test. Each file is a
labelled synthetic layout fixture (not an installable APK) that exercises a
relation family no existing fixture covers with a *method-bound* fact:

* debug-methods-035.dex   debug_info/debug_parameters/debug_positions/
                          debug_locals/debug_opcodes bound to real methods
* hiddenapi-039.dex       hiddenapi_flags (map 0xf000, version 039)
* static-values-035.dex   class_static_values with a non-empty encoded array
* proto-share-035.dex     proto_params ordering when two protos share one
                          physical parameter type_list
* debug-programs-035.dex  debug programs with unnamed parameters, locals that end or restart before they start,
                          markers that reset after a position, a position past the code end, a shared program
* hiddenapi-order-039.dex hidden API flags where the member index order differs from the class data order
* marker-annotation-038.dex  an annotation without elements, reachable through a method's set
* build-annotation-038.dex   an annotation of build visibility
* call-site-extra-args-038.dex  a call site array with static arguments after the three it must start with
* root-class-035.dex      a class definition with no superclass
* static-values-nested-035.dex  a static value array holding an array

Usage: python -I tests/fixtures/public_relations/generate.py [--check]
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


def sleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        sign = byte & 0x40
        done = (value == 0 and not sign) or (value == -1 and sign)
        out.append(byte if done else byte | 0x80)
        if done:
            return bytes(out)


def units_of(text: str) -> tuple[int, ...]:
    raw = text.encode("utf-16-le", "surrogatepass")
    return struct.unpack("<%dH" % (len(raw) // 2), raw)


def mutf8(text: str) -> bytes:
    data = bytearray(uleb(len(units_of(text))))
    for unit in units_of(text):
        if 0 < unit < 0x80:
            data.append(unit)
        elif unit < 0x800:
            data.extend([0xC0 | (unit >> 6), 0x80 | (unit & 0x3F)])
        else:
            data.extend([0xE0 | (unit >> 12), 0x80 | ((unit >> 6) & 0x3F), 0x80 | (unit & 0x3F)])
    return bytes(data) + b"\0"


class Field:
    def __init__(self, name: str, ty: str, flags: list[str]):
        self.name, self.ty, self.flags = name, ty, flags

    @property
    def access(self) -> int:
        acc = {"public": 1, "private": 2, "static": 8, "final": 0x10}
        return sum(acc[f] for f in self.flags)

    @property
    def is_static(self) -> bool:
        return "static" in self.flags


class Method:
    def __init__(self, name: str, flags: list[str], params=(), ret: str = "V",
                 registers: int = 0, outs: int = 0, units=(), debug: bytes | None = None):
        self.name, self.flags, self.params, self.ret = name, flags, tuple(params), ret
        self.registers, self.outs, self.units, self.debug = registers, outs, list(units), debug
        self.ins = sum(2 if p in ("J", "D") else 1 for p in self.params) + (0 if "static" in flags else 1)

    @property
    def access(self) -> int:
        acc = {"public": 1, "private": 2, "static": 8, "final": 0x10,
               "abstract": 0x400, "native": 0x100, "constructor": 0x10000}
        return sum(acc[f] for f in self.flags)

    @property
    def is_direct(self) -> bool:
        return any(f in self.flags for f in ("static", "private", "constructor"))


class Dex:
    """One class, sorted pools, physical map, SHA-1 signature and Adler-32 checksum."""

    def __init__(self, class_name: str):
        self.class_name = class_name
        self.fields: list[Field] = []
        self.methods: list[Method] = []
        self.extra_strings: set[str] = set()
        self.extra_types: set[str] = set()
        self.static_values: bytes | None = None  # encoded_array_item payload
        self.hiddenapi: bytes | None = None  # hiddenapi_class_data_item payload
        self.source_file: str | None = None
        self.root = False  # a class with no superclass

    def build(self, version: str = "035") -> bytes:
        types = {self.class_name, OBJECT, "V"} | self.extra_types
        protos: set[tuple[str, tuple[str, ...]]] = set()
        for f in self.fields:
            types.add(f.ty)
        for m in self.methods:
            types |= {m.ret, *m.params}
            protos.add((m.ret, m.params))
        strings = set(types) | {f.name for f in self.fields} | {m.name for m in self.methods}
        strings |= self.extra_strings
        if self.source_file:
            strings.add(self.source_file)
        shorty = lambda ret, params: ("L" if ret[0] in "L[" else ret) + "".join(
            "L" if p[0] in "L[" else p for p in params)
        strings |= {shorty(r, p) for r, p in protos}
        strings = sorted(strings, key=units_of)
        sidx = {s: i for i, s in enumerate(strings)}
        types = sorted(types, key=lambda t: sidx[t])
        tidx = {t: i for i, t in enumerate(types)}
        protos = sorted(protos, key=lambda p: (tidx[p[0]], [tidx[x] for x in p[1]]))
        pidx = {p: i for i, p in enumerate(protos)}
        fields = sorted([(self.class_name, f.name, f.ty) for f in self.fields],
                        key=lambda f: (tidx[f[0]], sidx[f[1]], tidx[f[2]]))
        fidx = {f: i for i, f in enumerate(fields)}
        methods = sorted([(self.class_name, m.name, m.ret, m.params) for m in self.methods],
                         key=lambda m: (tidx[m[0]], sidx[m[1]], pidx[(m[2], m[3])]))
        midx = {m: i for i, m in enumerate(methods)}

        # A0 0.1.0 (and the repo fixture convention) keeps the 0x70 header for all
        # versions; hiddenapi_class_data is located through the 0xF000 map entry.
        string_off = 112
        type_off = string_off + 4 * len(strings)
        proto_off = type_off + 4 * len(types)
        field_off = proto_off + 12 * len(protos)
        method_off = field_off + 8 * len(fields)
        class_off = method_off + 8 * len(methods)
        data_off = class_off + 32
        body = bytearray()

        def here() -> int:
            return data_off + len(body)

        def align(n: int = 4) -> None:
            body.extend(b"\0" * (-len(body) % n))

        param_lists: dict[tuple[str, ...], int] = {}
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

        debug_offsets: dict[bytes, int] = {}
        code_offsets: dict[str, int] = {}
        first_code = None
        # the debug_info_item section is contiguous: every distinct program, then the code items
        for m in self.methods:
            if m.debug is not None and m.debug not in debug_offsets:
                debug_offsets[m.debug] = here()
                body.extend(m.debug)
        for m in self.methods:
            if not m.units and "abstract" in m.flags or "native" in m.flags:
                continue
            align()
            if first_code is None:
                first_code = here()
            code_offsets[m.name] = here()
            debug_at = debug_offsets.get(m.debug, 0) if m.debug is not None else 0
            body.extend(struct.pack("<HHHHII", m.registers, m.ins, m.outs, 0, debug_at, len(m.units)))
            body.extend(b"".join(struct.pack("<H", u) for u in m.units))

        static_values_off = 0
        if self.static_values is not None:
            static_values_off = here()
            body.extend(self.static_values)

        align()
        class_data_off = here()
        static_fields = sorted([f for f in self.fields if f.is_static],
                               key=lambda f: fidx[(self.class_name, f.name, f.ty)])
        instance_fields = sorted([f for f in self.fields if not f.is_static],
                                 key=lambda f: fidx[(self.class_name, f.name, f.ty)])
        direct = sorted([m for m in self.methods if m.is_direct],
                        key=lambda m: midx[(self.class_name, m.name, m.ret, m.params)])
        virtual = sorted([m for m in self.methods if not m.is_direct],
                         key=lambda m: midx[(self.class_name, m.name, m.ret, m.params)])
        body.extend(uleb(len(static_fields)) + uleb(len(instance_fields)) + uleb(len(direct)) + uleb(len(virtual)))
        for group in (static_fields, instance_fields):
            previous = 0
            for f in group:
                index = fidx[(self.class_name, f.name, f.ty)]
                body.extend(uleb(index - previous) + uleb(f.access))
                previous = index
        for group in (direct, virtual):
            previous = 0
            for m in group:
                index = midx[(self.class_name, m.name, m.ret, m.params)]
                body.extend(uleb(index - previous) + uleb(m.access) + uleb(code_offsets.get(m.name, 0)))
                previous = index

        hiddenapi_off = 0
        if self.hiddenapi is not None:
            align()
            hiddenapi_off = here()
            body.extend(self.hiddenapi)

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
        if debug_offsets:
            sections.append((0x2003, len(debug_offsets), min(debug_offsets.values())))
        if self.static_values is not None:
            sections.append((0x2005, 1, static_values_off))
        sections.append((0x2000, 1, class_data_off))
        if self.hiddenapi is not None:
            sections.append((0xF000, 1, hiddenapi_off))
        sections.append((0x1000, 1, map_off))
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
            struct.pack_into("<III", head, proto_off + 12 * i, sidx[shorty(ret, params)], tidx[ret],
                             param_lists.get(params, 0))
        for i, (owner, name, ty) in enumerate(fields):
            struct.pack_into("<HHI", head, field_off + 8 * i, tidx[owner], tidx[ty], sidx[name])
        for i, (owner, name, ret, params) in enumerate(methods):
            struct.pack_into("<HHI", head, method_off + 8 * i, tidx[owner], pidx[(ret, params)], sidx[name])
        struct.pack_into("<IIIIIIII", head, class_off, tidx[self.class_name], 1, NO_INDEX if self.root else tidx[OBJECT], 0,
                         sidx[self.source_file] if self.source_file else NO_INDEX, 0, class_data_off,
                         static_values_off)
        data = bytearray(head + body)
        total = len(data)
        data[0:8] = b"dex\n" + version.encode() + b"\0"
        struct.pack_into("<I", data, 32, total)
        struct.pack_into("<I", data, 36, 112)
        struct.pack_into("<I", data, 40, 0x12345678)
        struct.pack_into("<I", data, 52, map_off)
        for position, (size, offset) in {
                56: (len(strings), string_off), 64: (len(types), type_off),
                72: (len(protos), proto_off), 80: (len(fields), field_off if fields else 0),
                88: (len(methods), method_off), 96: (1, class_off),
                104: (total - data_off, data_off)}.items():
            struct.pack_into("<II", data, position, size, offset)
        data[12:32] = hashlib.sha1(bytes(data[32:])).digest()
        struct.pack_into("<I", data, 8, zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF)
        return bytes(data)


def debug_program(line_start: int, parameter_names: list[int | None], events: bytes) -> bytes:
    out = bytearray(uleb(line_start))
    out.extend(uleb(len(parameter_names)))
    for name in parameter_names:
        out.extend(uleb(0 if name is None else name + 1))  # uleb128p1: no name is -1, written as 0
    out.extend(events)
    return bytes(out)


def encoded_value(kind: str, payload: bytes, arg: int = 0) -> bytes:
    tags = {"byte": 0x00, "short": 0x02, "char": 0x03, "int": 0x04, "long": 0x06,
            "float": 0x10, "double": 0x11, "string": 0x17, "type": 0x18,
            "field": 0x19, "method": 0x1a, "enum": 0x1b, "array": 0x1c,
            "annotation": 0x1d, "null": 0x1e, "boolean": 0x1f}
    return bytes([(arg << 5) | tags[kind]]) + payload


def build_debug_methods() -> Dex:
    dex = Dex("Lpub/D;")
    dex.source_file = "D.java"
    dex.extra_strings |= {"x", "y", "p0", "Ljava/lang/String;"}
    dex.extra_types.add("J")
    # m(I)I: instance, ins=2 (this + p0), registers=3.
    # const/4 v0,#1 ; add-int/lit8 v0,v0,#7 ; return v0
    units = [0x1012, 0x00D8, 0x0700, 0x000F]
    dex.methods.append(Method("m", ["public"], params=("I",), ret="I", registers=3, units=units))
    dex.methods.append(Method("n", ["public", "static"], registers=1, units=[0x000E]))
    return dex


def debug_events(sidx: dict[str, int], tidx: dict[str, int]) -> bytes:
    ev = bytearray()
    ev.extend(bytes([0x01]) + uleb(1))          # advance_pc +1 -> addr 1
    ev.extend(bytes([0x02]) + sleb(2))          # advance_line +2
    ev.extend(bytes([0x03]) + uleb(0) + uleb(sidx["x"] + 1) + uleb(tidx["I"] + 1))  # start_local v0 x:I
    ev.extend(bytes([0x01]) + uleb(1))          # advance_pc +1 -> addr 2
    ev.extend(bytes([0x05]) + uleb(0))          # end_local v0
    ev.extend(bytes([0x06]) + uleb(0))          # restart_local v0
    ev.extend(bytes([0x07]))                    # prologue_end
    ev.extend(bytes([0x08]))                    # epilogue_begin
    ev.extend(bytes([0x09]) + uleb(sidx["D.java"] + 1))  # set_file
    ev.extend(bytes([0x0E]))                    # special: line += 4
    ev.extend(bytes([0x04]) + uleb(1) + uleb(sidx["y"] + 1) + uleb(tidx["J"] + 1)
              + uleb(sidx["Ljava/lang/String;"] + 1))  # start_local_extended v1 y:J sig
    ev.extend(bytes([0x00]))                    # end_sequence
    return bytes(ev)


def build_hiddenapi() -> Dex:
    dex = Dex("Lpub/H;")
    dex.fields.append(Field("fI", "I", ["public", "static"]))
    dex.fields.append(Field("fJ", "J", ["public", "static"]))
    dex.methods.append(Method("m", ["public", "static"], registers=1, units=[0x000E]))
    dex.methods.append(Method("n", ["public"], registers=1, units=[0x000E]))
    # A0 0.1.0 hiddenapi_class_data_item layout (pinned by probe):
    #   uint32 size_in_bytes; uint32 offsets[num_classes] (relative to item start);
    #   per-class uleb128 stream = field flags then method flags (no implicit class
    #   flag row is exposed). One class Lpub/H;: fields fI=1,fJ=2; methods m=3,n=0.
    stream = uleb(1) + uleb(2) + uleb(3) + uleb(0)
    padded = stream + b"\0" * (-len(stream) % 4)
    offsets = struct.pack("<I", 8)  # flag data starts after size + one offset
    dex.hiddenapi = struct.pack("<I", 4 + len(offsets) + len(padded)) + offsets + padded
    return dex



def build_debug_programs() -> Dex:
    """Debug programs that the first fixture does not reach: unnamed parameters, a local that ends or restarts
    before it started, locals without a name or a type, markers that must reset after a position, a position past
    the end of the code, and one program shared by two methods."""
    dex = Dex("Lpub/Q;")
    dex.source_file = "Q.java"
    dex.extra_strings |= {"x", "p0", "f.java"}
    dex.methods.append(Method("a", ["public"], params=("I", "I"), registers=4, units=[0x0000, 0x0000, 0x000E]))
    dex.methods.append(Method("b", ["public", "static"], registers=1, units=[0x0000, 0x000E]))
    dex.methods.append(Method("c", ["public", "static"], registers=1, units=[0x0000, 0x000E]))
    dex.methods.append(Method("d", ["public", "static"], registers=1, units=[0x000E]))
    return dex


def debug_programs(sidx: dict[str, int], tidx: dict[str, int]) -> tuple[bytes, bytes]:
    ev = bytearray()
    ev.extend(bytes([0x09]) + uleb(sidx["f.java"] + 1))   # set_file
    ev.extend(bytes([0x07]))                              # prologue_end
    ev.extend(bytes([0x0E]))                              # special: pc +0, line +0  -> position
    ev.extend(bytes([0x08]))                              # epilogue_begin
    ev.extend(bytes([0x1E]))                              # special: pc +1, line +1  -> position
    ev.extend(bytes([0x05]) + uleb(1))                    # end_local v1 (never started)
    ev.extend(bytes([0x06]) + uleb(2))                    # restart_local v2 (never started)
    ev.extend(bytes([0x03]) + uleb(0) + uleb(sidx["x"] + 1) + uleb(0))   # start_local v0 x:(no type)
    ev.extend(bytes([0x03]) + uleb(3) + uleb(0) + uleb(tidx["I"] + 1))   # start_local v3 (no name):I
    ev.extend(bytes([0x05]) + uleb(0))                    # end_local v0
    ev.extend(bytes([0x06]) + uleb(0))                    # restart_local v0
    ev.extend(bytes([0x01]) + uleb(100))                  # advance_pc +100 (far past the 3 code units)
    ev.extend(bytes([0x0E]))                              # special -> position past the code end
    ev.extend(bytes([0x00]))
    shared = bytearray()
    shared.extend(bytes([0x0E]))
    shared.extend(bytes([0x2D]))                          # special: pc +2, line +...
    shared.extend(bytes([0x00]))
    return (debug_program(5, [sidx["p0"], None], bytes(ev)), debug_program(1, [], bytes(shared)))


def build_hiddenapi_order() -> Dex:
    """Class members whose index order differs from the order of the class data: an instance field with a lower
    field index than the static one, a virtual method with a lower index than the direct one."""
    dex = Dex("Lpub/O;")
    dex.fields.append(Field("a", "I", ["public"]))
    dex.fields.append(Field("b", "I", ["public", "static"]))
    dex.methods.append(Method("m", ["public"], registers=1, units=[0x000E]))
    dex.methods.append(Method("n", ["public", "static"], registers=1, units=[0x000E]))
    # class data order: static fields (b), instance fields (a), direct methods (n), virtual methods (m)
    stream = uleb(5) + uleb(6) + uleb(7) + uleb(8)
    padded = stream + b"\0" * (-len(stream) % 4)
    offsets = struct.pack("<I", 8)
    dex.hiddenapi = struct.pack("<I", 4 + len(offsets) + len(padded)) + offsets + padded
    return dex



def build_root_class() -> Dex:
    """A class definition with no superclass (superclass_idx is the no-index value)."""
    dex = Dex("Lpub/R;")
    dex.root = True
    dex.methods.append(Method("m", ["public", "static"], registers=1, units=[0x000E]))
    return dex


def build_nested_static_values() -> Dex:
    dex = Dex("Lpub/N;")
    dex.fields.append(Field("a", "I", ["public", "static"]))
    dex.fields.append(Field("b", "I", ["public", "static"]))
    dex.methods.append(Method("m", ["public", "static"], registers=0, units=[0x000E]))
    return dex


def nested_static_values_payload() -> bytes:
    """Two static values; the second is itself an array of two ints."""
    inner = uleb(2) + encoded_value("int", bytes([1])) + encoded_value("int", bytes([2]))
    return uleb(2) + encoded_value("int", bytes([5])) + encoded_value("array", inner)


def build_static_values() -> Dex:
    dex = Dex("Lpub/S;")
    dex.fields.append(Field("a", "I", ["public", "static"]))
    dex.fields.append(Field("b", "J", ["public", "static"]))
    dex.fields.append(Field("c", "Ljava/lang/String;", ["public", "static"]))
    dex.fields.append(Field("d", "I", ["public"]))
    dex.extra_strings.add("sv")
    dex.methods.append(Method("m", ["public", "static"], registers=0, units=[0x000E]))
    return dex


def static_values_payload(sidx: dict[str, int]) -> bytes:
    values = encoded_value("int", bytes([42]), arg=0)
    values += encoded_value("long", bytes([0xFF]), arg=0)
    values += encoded_value("string", uleb(sidx["sv"]))
    return uleb(3) + values


def build_proto_share() -> Dex:
    dex = Dex("Lpub/P;")
    dex.methods.append(Method("m1", ["public", "static"], params=("I", "J"), registers=3, units=[0x000E]))
    dex.methods.append(Method("m2", ["public", "static"], params=("I", "J"), ret="I", registers=3,
                                units=[0x1012, 0x000F]))
    dex.methods.append(Method("m3", ["public", "static"], params=("J", "I"), registers=3, units=[0x000E]))
    return dex


def pool_of(data: bytes) -> tuple[dict[str, int], dict[str, int]]:
    """Recover the sorted string/type pools from an assembled DEX image."""
    count, off = struct.unpack_from("<II", data, 56)
    offsets = struct.unpack_from("<%dI" % count, data, off)
    strings = []
    for so in offsets:
        pos = so
        while data[pos] & 0x80:
            pos += 1
        pos += 1
        end = data.index(b"\0", pos)
        strings.append(data[pos:end].decode("utf-8", "surrogateescape"))
    sidx = {s: i for i, s in enumerate(strings)}
    tcount, toff = struct.unpack_from("<II", data, 64)
    tdesc = struct.unpack_from("<%dI" % tcount, data, toff)
    tidx = {strings[d]: i for i, d in enumerate(tdesc)}
    return sidx, tidx


def main(argv: list[str]) -> int:
    OUT.mkdir(exist_ok=True)
    # Debug programs reference pool indexes, so assemble once without debug to
    # learn the sorted pools (debug adds no new strings), then attach programs.
    dex = build_debug_methods()
    sidx, tidx = pool_of(dex.build("035"))
    dex.methods[0].debug = debug_program(10, [sidx["p0"]], debug_events(sidx, tidx))
    dex.methods[1].debug = None

    sv = build_static_values()
    sv_sidx, _ = pool_of(sv.build("035"))
    sv.static_values = static_values_payload(sv_sidx)

    dp = build_debug_programs()
    dp_sidx, dp_tidx = pool_of(dp.build("035"))
    shared_program, program_a = None, None
    program_a, shared_program = debug_programs(dp_sidx, dp_tidx)
    dp.methods[0].debug = program_a
    dp.methods[1].debug = shared_program
    dp.methods[2].debug = shared_program
    dp.methods[3].debug = None

    # an annotation without elements, reachable through a method's set (the annotation generator's own build)
    import importlib.util
    spec = importlib.util.spec_from_file_location("annotation_fixtures", HERE.parent / "annotations" / "generate.py")
    annotation_fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(annotation_fixtures)
    marker_dex, _ = annotation_fixtures.build({"marker_annotation"})
    build_dex, _ = annotation_fixtures.build({"build_annotation"})
    extra_args_dex, _ = annotation_fixtures.build({"call_site_extra_args"})
    nested = build_nested_static_values()
    nested.static_values = nested_static_values_payload()

    fixtures = {
        "marker-annotation-038.dex": marker_dex,
        "build-annotation-038.dex": build_dex,
        "call-site-extra-args-038.dex": extra_args_dex,
        "root-class-035.dex": build_root_class().build("035"),
        "static-values-nested-035.dex": nested.build("035"),
        "debug-programs-035.dex": dp.build("035"),
        "hiddenapi-order-039.dex": build_hiddenapi_order().build("039"),
        "debug-methods-035.dex": dex.build("035"),
        "hiddenapi-039.dex": build_hiddenapi().build("039"),
        "static-values-035.dex": sv.build("035"),
        "proto-share-035.dex": build_proto_share().build("035"),
    }
    records = []
    for name, data in fixtures.items():
        path = OUT / name
        if "--check" in argv:
            if not path.is_file() or path.read_bytes() != data:
                raise SystemExit(f"fixture drift: {name}")
        else:
            path.write_bytes(data)
        records.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                        "kind": "synthetic-layout-fixture-not-installable-APK",
                        "encoded_expectation": "valid"})
    manifest = {"schema_version": "mdd.public-relation-fixtures.v1",
                "generator": "tests/fixtures/public_relations/generate.py",
                "files": records,
                "note": "Method-bound debug (two programs), hiddenapi (two member orders), an annotation without elements, non-empty static values and shared proto parameter lists; independent of the engine under test."}
    if "--check" not in argv:
        (HERE / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"fixtures": len(records)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))