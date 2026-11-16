#!/usr/bin/env python3
"""An independent smali renderer, written from the DEX bytes and the format description.

It imports nothing from the engine and nothing from the fixture generator: it reads a DEX
file with `struct`, decodes the Dalvik instruction formats itself and writes the text the
spec in crates/mdd-facts/src/smali/mod.rs (the complete format) and crates/mdd-facts/src/smali_required/mod.rs (the instructions) describes. Two programs written
separately from one description agree only if the description is unambiguous; neither
shows that the description is what any other tool prints (the one reference output on
record is the frame of the first test case).

Opcode names, formats and index kinds are read from conformance/dex/instruction-matrix.json,
the AOSP-derived table. It is shared data.

Usage: python -I conformance/decode/oracle.py FILE.dex   (prints every defined method)
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MATRIX = json.loads((ROOT / "conformance/dex/instruction-matrix.json").read_text(encoding="utf-8"))["entries"]
OPCODE = {e["opcode"]: e for e in MATRIX if not e["reserved"]}
FLAGS = [(0x1, "public"), (0x2, "private"), (0x4, "protected"), (0x8, "static"), (0x10, "final"), (0x20, "synchronized"),
         (0x40, "bridge"), (0x80, "varargs"), (0x100, "native"), (0x400, "abstract"), (0x800, "strictfp"),
         (0x1000, "synthetic"), (0x10000, "constructor"), (0x20000, "declared-synchronized")]
WIDTH = {**{f: 1 for f in ("10x", "12x", "11n", "11x", "10t")},
         **{f: 2 for f in ("20t", "22x", "21t", "21s", "21h", "21c", "23x", "22b", "22t", "22s", "22c")},
         **{f: 3 for f in ("32x", "30t", "31t", "31i", "31c", "35c", "3rc")}, "45cc": 4, "4rcc": 4, "51l": 5}


def uleb(data, at):
    value = shift = 0
    while True:
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, at


def sleb(data, at):
    value = shift = 0
    while True:
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:
                value -= 1 << shift
            return value, at


def mutf8_units(data, at):
    """The UTF-16 code units of the string at `at`, and the unit count it declares."""
    count, at = uleb(data, at)
    units = []
    while data[at] != 0:
        b = data[at]
        if b < 0x80:
            units.append(b)
            at += 1
        elif b >> 5 == 0b110:
            units.append(((b & 0x1F) << 6) | (data[at + 1] & 0x3F))
            at += 2
        else:
            units.append(((b & 0x0F) << 12) | ((data[at + 1] & 0x3F) << 6) | (data[at + 2] & 0x3F))
            at += 3
    assert len(units) == count, "declared length"
    return units


def text(units):
    return struct.pack("<%dH" % len(units), *units).decode("utf-16-le", "surrogatepass")


def u16(data, at):
    return struct.unpack_from("<H", data, at)[0]


def u32(data, at):
    return struct.unpack_from("<I", data, at)[0]


class Dex:
    def __init__(self, data: bytes):
        self.data = data
        d = data
        counts = {k: (u32(d, o), u32(d, o + 4)) for k, o in
                  dict(strings=56, types=64, protos=72, fields=80, methods=88, classes=96).items()}
        self.units = [mutf8_units(d, u32(d, counts["strings"][1] + 4 * i)) for i in range(counts["strings"][0])]
        self.strings = [text(u) for u in self.units]
        self.types = [self.strings[u32(d, counts["types"][1] + 4 * i)] for i in range(counts["types"][0])]
        self.protos = []
        for i in range(counts["protos"][0]):
            at = counts["protos"][1] + 12 * i
            params_off = u32(d, at + 8)
            params = []
            if params_off:
                params = [self.types[u16(d, params_off + 4 + 2 * j)] for j in range(u32(d, params_off))]
            self.protos.append((self.types[u32(d, at + 4)], params))
        self.fields = []
        for i in range(counts["fields"][0]):
            at = counts["fields"][1] + 8 * i
            self.fields.append((self.types[u16(d, at)], self.strings[u32(d, at + 4)], self.types[u16(d, at + 2)]))
        self.methods = []
        for i in range(counts["methods"][0]):
            at = counts["methods"][1] + 8 * i
            self.methods.append((self.types[u16(d, at)], self.strings[u32(d, at + 4)], self.protos[u16(d, at + 2)]))
        self.defined = []  # (method_idx, access, code_off)
        for i in range(counts["classes"][0]):
            at = counts["classes"][1] + 32 * i
            class_data = u32(d, at + 24)
            if not class_data:
                continue
            sf, p = uleb(d, class_data)
            inf, p = uleb(d, p)
            direct, p = uleb(d, p)
            virtual, p = uleb(d, p)
            for _ in range(sf + inf):
                _, p = uleb(d, p)
                _, p = uleb(d, p)
            for group in (direct, virtual):
                index = 0
                for _ in range(group):
                    delta, p = uleb(d, p)
                    access, p = uleb(d, p)
                    code, p = uleb(d, p)
                    index += delta
                    self.defined.append((index, access, code))

    def method_text(self, index):
        owner, name, (ret, params) = self.methods[index]
        return "%s->%s(%s)%s" % (owner, name, "".join(params), ret)

    def field_text(self, index):
        owner, name, ty = self.fields[index]
        return "%s->%s:%s" % (owner, name, ty)

    def proto_text(self, index):
        ret, params = self.protos[index]
        return "(%s)%s" % ("".join(params), ret)


def hexs(value):
    return "-0x%x" % -value if value < 0 else "0x%x" % value


def signed(value, bits):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


def literal_text(units):
    out = ['"']
    for u in units:
        if u == 0x22:
            out.append('\\"')
        elif u == 0x27:
            out.append("\\'")
        elif u == 0x5C:
            out.append("\\\\")
        elif u in (8, 9, 10, 12, 13):
            out.append({8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r"}[u])
        elif 0x20 <= u <= 0x7E:
            out.append(chr(u))
        else:
            out.append("\\u%04x" % u)
    out.append('"')
    return "".join(out)


def render(dex: Dex, index: int, access: int, code_off: int, extra=None) -> str:
    """The text of one method. `extra` (oracle_class.Extras) adds the lines of the complete format; without it the text is
    the instruction text of MDD-042."""
    owner, name, (ret, params) = dex.methods[index]
    words = [w for bit, w in FLAGS if access & bit]
    # ".method <flags> name(params)ret"; with no flags there is a single space
    prefix = ".method " + "".join(w + " " for w in words)
    out = ["%s%s(%s)%s" % (prefix, name, "".join(params), ret)]
    if not code_off:
        if extra is not None:
            out.extend(extra.header(None))
        out.append(".end method")
        return "\n".join(out) + "\n"
    d = dex.data
    registers, ins, outs, tries, _debug, size = struct.unpack_from("<HHHHII", d, code_off)
    units = list(struct.unpack_from("<%dH" % size, d, code_off + 16))
    first_param = registers - ins

    def reg(n):
        return "p%d" % (n - first_param) if n >= first_param else "v%d" % n

    # ---- walk the code ----
    items = []  # (address, kind, payload)
    labels = {}

    def label(address, prefix):
        labels.setdefault(address, set()).add("%s%x" % (prefix, address))
        return "%s%x" % (prefix, address)

    pc = 0
    while pc < size:
        unit = units[pc]
        if unit in (0x0100, 0x0200, 0x0300):
            if unit == 0x0100:
                n = units[pc + 1]
                width = 4 + 2 * n
                first = signed(units[pc + 2] | units[pc + 3] << 16, 32)
                rel = [signed(units[pc + 4 + 2 * i] | units[pc + 5 + 2 * i] << 16, 32) for i in range(n)]
                items.append((pc, "packed", (width, first, rel)))
            elif unit == 0x0200:
                n = units[pc + 1]
                width = 2 + 4 * n
                keys = [signed(units[pc + 2 + 2 * i] | units[pc + 3 + 2 * i] << 16, 32) for i in range(n)]
                base = pc + 2 + 2 * n
                rel = [signed(units[base + 2 * i] | units[base + 1 + 2 * i] << 16, 32) for i in range(n)]
                items.append((pc, "sparse", (width, keys, rel)))
            else:
                elem = units[pc + 1]
                count = units[pc + 2] | units[pc + 3] << 16
                width = 4 + (count * elem + 1) // 2
                raw = struct.pack("<%dH" % (width - 4), *units[pc + 4:pc + width])[:count * elem]
                items.append((pc, "array", (width, elem, raw)))
            pc += width
            continue
        entry = OPCODE[unit & 0xFF]
        fmt = entry["format"]
        w = WIDTH[fmt]
        items.append((pc, "insn", (entry, units[pc:pc + w])))
        pc += w
    insn_at = {a: p for a, k, p in items if k == "insn"}
    payload_at = {a: (k, p) for a, k, p in items if k != "insn"}

    # ---- render each instruction ----
    lines = {}
    switch_owner = {}
    for address, kind, payload in items:
        if kind != "insn":
            continue
        entry, w = payload
        op, fmt, mnem, index_kind = entry["opcode"], entry["format"], entry["mnemonic"], entry["index_kind"]
        hi = w[0] >> 8
        regs, text_ops = [], ""

        def ref(i):
            if index_kind == "kIndexStringRef":
                return literal_text(dex.units[i])
            if index_kind == "kIndexTypeRef":
                return dex.types[i]
            if index_kind == "kIndexFieldRef":
                return dex.field_text(i)
            if index_kind in ("kIndexMethodRef", "kIndexMethodAndProtoRef"):
                return dex.method_text(i)
            if index_kind == "kIndexProtoRef":
                return dex.proto_text(i)
            if index_kind == "kIndexCallSiteRef":
                return "call_site_%d" % i
            return "method_handle_%d" % i

        def goto_label(rel):
            prefix = "goto_" if 0x28 <= op <= 0x2A else "cond_"
            return ":" + label(address + rel, prefix)

        def lit_text(value):
            return hexs(value) + ("L" if mnem.startswith("const-wide") else "")

        if fmt == "10x":
            text_ops = ""
        elif fmt == "12x":
            text_ops = "%s, %s" % (reg(hi & 15), reg(hi >> 4))
        elif fmt == "11n":
            text_ops = "%s, %s" % (reg(hi & 15), lit_text(signed(hi >> 4, 4)))
        elif fmt == "11x":
            text_ops = reg(hi)
        elif fmt == "10t":
            text_ops = goto_label(signed(hi, 8))
        elif fmt == "20t":
            text_ops = goto_label(signed(w[1], 16))
        elif fmt == "30t":
            text_ops = goto_label(signed(w[1] | w[2] << 16, 32))
        elif fmt == "22x":
            text_ops = "%s, %s" % (reg(hi), reg(w[1]))
        elif fmt == "32x":
            text_ops = "%s, %s" % (reg(w[1]), reg(w[2]))
        elif fmt == "21t":
            text_ops = "%s, %s" % (reg(hi), goto_label(signed(w[1], 16)))
        elif fmt == "21s":
            text_ops = "%s, %s" % (reg(hi), lit_text(signed(w[1], 16)))
        elif fmt == "21h":
            value = signed(w[1] << 48, 64) if op == 0x19 else signed(w[1] << 16, 32)
            text_ops = "%s, %s" % (reg(hi), lit_text(value))
        elif fmt in ("21c", "31c"):
            i = w[1] if fmt == "21c" else w[1] | w[2] << 16
            text_ops = "%s, %s" % (reg(hi), ref(i))
        elif fmt == "23x":
            text_ops = "%s, %s, %s" % (reg(hi), reg(w[1] & 0xFF), reg(w[1] >> 8))
        elif fmt == "22b":
            text_ops = "%s, %s, %s" % (reg(hi), reg(w[1] & 0xFF), lit_text(signed(w[1] >> 8, 8)))
        elif fmt == "22t":
            text_ops = "%s, %s, %s" % (reg(hi & 15), reg(hi >> 4), goto_label(signed(w[1], 16)))
        elif fmt == "22s":
            text_ops = "%s, %s, %s" % (reg(hi & 15), reg(hi >> 4), lit_text(signed(w[1], 16)))
        elif fmt == "22c":
            text_ops = "%s, %s, %s" % (reg(hi & 15), reg(hi >> 4), ref(w[1]))
        elif fmt == "31i":
            text_ops = "%s, %s" % (reg(hi), lit_text(signed(w[1] | w[2] << 16, 32)))
        elif fmt == "31t":
            target = address + signed(w[1] | w[2] << 16, 32)
            kind = payload_at[target][0]
            prefix = {"packed": "pswitch_data_", "sparse": "sswitch_data_", "array": "array_"}[kind]
            switch_owner[target] = address
            text_ops = "%s, :%s" % (reg(hi), label(target, prefix))
        elif fmt in ("35c", "45cc"):
            count = hi >> 4
            all_regs = [w[2] & 15, (w[2] >> 4) & 15, (w[2] >> 8) & 15, w[2] >> 12, hi & 15]
            listing = "{%s}" % ", ".join(reg(r) for r in all_regs[:count])
            text_ops = "%s, %s" % (listing, ref(w[1]))
            if fmt == "45cc":
                text_ops += ", " + dex.proto_text(w[3])
        elif fmt in ("3rc", "4rcc"):
            count, first = hi, w[2]
            listing = "{}" if count == 0 else "{%s .. %s}" % (reg(first), reg(first + count - 1))
            text_ops = "%s, %s" % (listing, ref(w[1]))
            if fmt == "4rcc":
                text_ops += ", " + dex.proto_text(w[3])
        elif fmt == "51l":
            bits = w[1] | w[2] << 16 | w[3] << 32 | w[4] << 48
            text_ops = "%s, %s" % (reg(hi), lit_text(signed(bits, 64)))
        lines[address] = ["    %s %s" % (mnem, text_ops) if text_ops else "    " + mnem]

    # ---- payloads ----
    for address, kind, payload in items:
        if kind == "insn":
            continue
        out_lines = []
        base = switch_owner.get(address, address)
        if kind == "packed":
            width, first, rel = payload
            labels.setdefault(address, set()).add("pswitch_data_%x" % address)
            out_lines.append("    .packed-switch %s" % hexs(first))
            for r in rel:
                out_lines.append("        :" + label(base + r, "pswitch_"))
            out_lines.append("    .end packed-switch")
        elif kind == "sparse":
            width, keys, rel = payload
            labels.setdefault(address, set()).add("sswitch_data_%x" % address)
            out_lines.append("    .sparse-switch")
            for k, r in zip(keys, rel):
                out_lines.append("        %s -> :%s" % (hexs(k), label(base + r, "sswitch_")))
            out_lines.append("    .end sparse-switch")
        else:
            width, elem, raw = payload
            labels.setdefault(address, set()).add("array_%x" % address)
            out_lines.append("    .array-data %d" % elem)
            suffix = {1: "t", 2: "s", 4: "", 8: "L"}[elem]
            for i in range(0, len(raw), elem):
                out_lines.append("        %s%s" % (hexs(int.from_bytes(raw[i:i + elem], "little", signed=True)), suffix))
            out_lines.append("    .end array-data")
        lines[address] = out_lines

    # ---- tries ----
    catches_at = {}
    if tries:
        at = code_off + 16 + 2 * size + (2 if size % 2 else 0)
        list_start = at + 8 * tries
        for i in range(tries):
            start, count, handler_off = struct.unpack_from("<IHH", d, at + 8 * i)
            label(start, "try_start_")
            end = start + count
            label(end, "try_end_")
            p = list_start + handler_off
            n, p = sleb(d, p)
            typed = abs(n)
            entries = []
            for _ in range(typed):
                type_idx, p = uleb(d, p)
                addr, p = uleb(d, p)
                entries.append(".catch %s {:try_start_%x .. :try_end_%x} :%s" % (dex.types[type_idx], start, end, label(addr, "catch_")))
            if n <= 0:
                addr, p = uleb(d, p)
                entries.append(".catchall {:try_start_%x .. :try_end_%x} :%s" % (start, end, label(addr, "catchall_")))
            catches_at.setdefault(end, []).extend(entries)

    # ---- assemble the body ----
    body = []
    addresses = sorted(lines)
    insn_starts = set(insn_at)
    added = extra.at_address(code_off, size, insn_starts, first_param) if extra is not None else {}
    for address in addresses + [size]:
        for l in sorted(labels.get(address, ())):
            body.append("    :" + l)
        for entry in catches_at.get(address, ()):
            body.append("    " + entry)
        if address in insn_starts or address == size:
            body.extend(added.get(address, ()))
        if address in lines:
            body.extend(lines[address])
    out.append("    .registers %d" % registers)
    if extra is not None:
        out.extend(extra.header(first_param))
    out.append("")
    out.extend(body)
    out.append(".end method")
    return "\n".join(out) + "\n"


def render_all(data: bytes) -> dict[str, str]:
    dex = Dex(data)
    return {dex.method_text(i): render(dex, i, access, code) for i, access, code in dex.defined}


def facts_of(data: bytes) -> dict[str, dict]:
    """Per defined method: the numbers a decode answer carries, read from the code item."""
    dex = Dex(data)
    out = {}
    for i, access, code in dex.defined:
        entry = {"method_idx": i, "access_flags": access, "registers": None, "code_units": None, "try_count": None}
        if code:
            registers, _ins, _outs, tries, _debug, size = struct.unpack_from("<HHHHII", data, code)
            entry.update(registers=registers, code_units=size, try_count=tries)
        out[dex.method_text(i)] = entry
    return out


def main(argv):
    for descriptor, text_ in render_all(Path(argv[0]).read_bytes()).items():
        print("#", descriptor)
        print(text_, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
