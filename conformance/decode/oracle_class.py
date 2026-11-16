#!/usr/bin/env python3
"""An independent reading of what a class has beyond its instructions: annotations, parameter names, debug
programs, fields, static values, the class header; and the context view.

Like oracle.py it reads the DEX bytes with `struct` and writes the text the specification in
crates/mdd-facts/src/smali/mod.rs describes (mdd.smali.v1). It imports nothing from the engine. Two programs written
separately from one description agree only if the description is unambiguous; neither shows that the description is
what any other tool prints.

Usage: python -I conformance/decode/oracle_class.py FILE.dex [CLASS_DESCRIPTOR]
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import oracle  # noqa: E402
from oracle import Dex, hexs, literal_text, signed, sleb, u16, u32, uleb  # noqa: E402

NO_INDEX = 0xFFFFFFFF
CONTEXT_HEADER = "# Original zero-based smali line numbers; labels retain method-relative code-unit offsets."
CLASS_CONTEXT_HEADER = "# Original zero-based smali line numbers of the class text; fields and interfaces are listed with their lines."
CLASS_FLAGS = [(0x1, "public"), (0x2, "private"), (0x4, "protected"), (0x8, "static"), (0x10, "final"), (0x200, "interface"),
               (0x400, "abstract"), (0x1000, "synthetic"), (0x2000, "annotation"), (0x4000, "enum")]
FIELD_FLAGS = [(0x1, "public"), (0x2, "private"), (0x4, "protected"), (0x8, "static"), (0x10, "final"), (0x40, "volatile"),
               (0x80, "transient"), (0x1000, "synthetic"), (0x4000, "enum")]
VISIBILITY = {0: "build", 1: "runtime", 2: "system"}


# ---- numbers ------------------------------------------------------------------------------------

def float_text(bits: int, width: int) -> str:
    """The shortest decimal that reads back as the same bits: plain digits (at least one after the point) when the decimal
    exponent is in -4..15, otherwise d.ddde<exp>; NaN, Infinity, -Infinity; a float carries the suffix f."""
    suffix = "f" if width == 32 else ""
    if width == 32:
        value = struct.unpack("<f", struct.pack("<I", bits))[0]
    else:
        value = struct.unpack("<d", struct.pack("<Q", bits))[0]
    if value != value:
        return "NaN" + suffix
    if value in (float("inf"), float("-inf")):
        return ("-" if value < 0 else "") + "Infinity" + suffix
    pack, unpack, limit = ("<f", "<I", 9) if width == 32 else ("<d", "<Q", 17)
    for digits in range(1, limit + 1):
        text = "%.*e" % (digits - 1, value)
        try:
            if struct.unpack(unpack, struct.pack(pack, float(text)))[0] == bits:
                break
        except OverflowError:  # a short reading that rounds past the largest float is not this value
            continue
    mantissa, exponent = text.split("e")
    exponent = int(exponent)
    sign = "-" if mantissa.startswith("-") else ""
    digits = mantissa.lstrip("-").replace(".", "")
    digits = digits.rstrip("0") or "0"  # %e pads with zeros only when it is exact in fewer digits
    if value == 0:
        digits, exponent = "0", 0
    if -4 <= exponent < 16:
        point = exponent + 1
        if point <= 0:
            body = "0." + "0" * (-point) + digits
        elif point >= len(digits):
            body = digits + "0" * (point - len(digits)) + ".0"
        else:
            body = digits[:point] + "." + digits[point:]
    elif len(digits) == 1:
        body = "%s.0e%d" % (digits, exponent)
    else:
        body = "%s.%se%d" % (digits[0], digits[1:], exponent)
    return sign + body + suffix


# ---- values -------------------------------------------------------------------------------------

def char_literal(unit: int) -> str:
    return "'" + literal_text([unit])[1:-1] + "'"


def read_value(dex: Dex, p: int, indent: int) -> tuple[str, int]:
    """One encoded value at p: its text (a multi-line value continues at `indent`) and the position after it."""
    d = dex.data
    head = d[p]
    p += 1
    kind, arg = head & 0x1F, head >> 5
    size = arg + 1
    if kind == 0x1F:
        return ("true" if arg else "false"), p
    if kind == 0x1E:
        return "null", p
    if kind == 0x1C:
        count, p = uleb(d, p)
        if count == 0:
            return "{}", p
        lines = ["{"]
        for position in range(count):
            text, p = read_value(dex, p, indent + 4)
            lines.append(" " * (indent + 4) + text + ("," if position != count - 1 else ""))
        lines.append(" " * indent + "}")
        return "\n".join(lines), p
    if kind == 0x1D:
        type_idx, p = uleb(d, p)
        count, p = uleb(d, p)
        lines = [".subannotation " + dex.types[type_idx]]
        for _ in range(count):
            name, p = uleb(d, p)
            text, p = read_value(dex, p, indent + 4)
            lines.append(" " * (indent + 4) + dex.strings[name] + " = " + text)
        lines.append(" " * indent + ".end subannotation")
        return "\n".join(lines), p
    raw = d[p:p + size]
    p += size
    unsigned = int.from_bytes(raw, "little")
    if kind == 0x00:
        return hexs(signed(unsigned, 8 * size)) + "t", p
    if kind == 0x02:
        return hexs(signed(unsigned, 8 * size)) + "s", p
    if kind == 0x03:
        return char_literal(unsigned), p
    if kind == 0x04:
        return hexs(signed(unsigned, 8 * size)), p
    if kind == 0x06:
        return hexs(signed(unsigned, 8 * size)) + "L", p
    if kind == 0x10:
        return float_text(unsigned << (8 * (4 - size)), 32), p
    if kind == 0x11:
        return float_text(unsigned << (8 * (8 - size)), 64), p
    if kind == 0x15:
        return dex.proto_text(unsigned), p
    if kind == 0x16:
        return "method_handle_%d" % unsigned, p
    if kind == 0x17:
        return literal_text(dex.units[unsigned]), p
    if kind == 0x18:
        return dex.types[unsigned], p
    if kind == 0x19:
        return dex.field_text(unsigned), p
    if kind == 0x1A:
        return dex.method_text(unsigned), p
    if kind == 0x1B:
        return ".enum " + dex.field_text(unsigned), p
    raise ValueError("unknown encoded value tag 0x%x" % kind)


def annotation_lines(dex: Dex, set_off: int, indent: int) -> list[str]:
    """The blocks of the annotation set at set_off, as lines."""
    d = dex.data
    lines: list[str] = []
    count = u32(d, set_off)
    for i in range(count):
        item = u32(d, set_off + 4 + 4 * i)
        visibility = d[item]
        p = item + 1
        type_idx, p = uleb(d, p)
        elements, p = uleb(d, p)
        lines.append(" " * indent + ".annotation %s %s" % (VISIBILITY[visibility], dex.types[type_idx]))
        for _ in range(elements):
            name, p = uleb(d, p)
            text, p = read_value(dex, p, indent + 4)
            lines.append(" " * (indent + 4) + dex.strings[name] + " = " + text)
        lines.append(" " * indent + ".end annotation")
    return "\n".join(lines).split("\n") if lines else []


# ---- the facts of a DEX, read again ---------------------------------------------------------------

class Classes:
    """Class definitions, their members, their annotation directories and the debug programs of their methods."""

    def __init__(self, data: bytes):
        self.dex = Dex(data)
        d = data
        self.data = d
        class_count, class_off = u32(d, 96), u32(d, 100)
        self.classes = []
        for i in range(class_count):
            at = class_off + 32 * i
            (class_idx, access, super_idx, interfaces_off, source_idx, annotations_off, class_data_off,
             static_values_off) = struct.unpack_from("<8I", d, at)
            entry = {
                "index": i, "descriptor": self.dex.types[class_idx], "access": access,
                "super": None if super_idx == NO_INDEX else self.dex.types[super_idx],
                "source": None if source_idx == NO_INDEX else self.dex.units[source_idx],
                "interfaces": [], "annotations_off": annotations_off, "static_values_off": static_values_off,
                "static_fields": [], "instance_fields": [], "direct": [], "virtual": [],
                "field_sets": {}, "method_sets": {}, "parameter_lists": {}, "class_set": 0,
            }
            if interfaces_off:
                n = u32(d, interfaces_off)
                entry["interfaces"] = [self.dex.types[u16(d, interfaces_off + 4 + 2 * j)] for j in range(n)]
            if class_data_off:
                p = class_data_off
                counts = []
                for _ in range(4):
                    v, p = uleb(d, p)
                    counts.append(v)
                for key, n in zip(("static_fields", "instance_fields"), counts[:2]):
                    index = 0
                    for _ in range(n):
                        delta, p = uleb(d, p)
                        flags, p = uleb(d, p)
                        index += delta
                        entry[key].append((index, flags))
                for key, n in zip(("direct", "virtual"), counts[2:]):
                    index = 0
                    for _ in range(n):
                        delta, p = uleb(d, p)
                        flags, p = uleb(d, p)
                        code, p = uleb(d, p)
                        index += delta
                        entry[key].append((index, flags, code))
            if annotations_off:
                class_set, fields, methods, parameters = struct.unpack_from("<4I", d, annotations_off)
                entry["class_set"] = class_set
                p = annotations_off + 16
                for _ in range(fields):
                    idx, off = struct.unpack_from("<II", d, p)
                    entry["field_sets"][idx] = off
                    p += 8
                for _ in range(methods):
                    idx, off = struct.unpack_from("<II", d, p)
                    entry["method_sets"][idx] = off
                    p += 8
                for _ in range(parameters):
                    idx, off = struct.unpack_from("<II", d, p)
                    entry["parameter_lists"][idx] = off
                    p += 8
            self.classes.append(entry)
        self.owner = {}
        for entry in self.classes:
            for method in entry["direct"] + entry["virtual"]:
                self.owner[method[0]] = entry

    def by_descriptor(self, descriptor: str) -> dict:
        return next(c for c in self.classes if c["descriptor"] == descriptor)


# ---- debug programs ---------------------------------------------------------------------------------

def debug_program(dex: Dex, offset: int) -> tuple[list[int | None], list[dict]]:
    """(parameter name string indices, events). An event is a dict with the opcode, the address and what it names."""
    d = dex.data
    p = offset
    line, p = uleb(d, p)
    count, p = uleb(d, p)
    names = []
    for _ in range(count):
        v, p = uleb(d, p)
        names.append(None if v == 0 else v - 1)
    events = []
    pc = 0
    optional = lambda: None
    while True:
        op = d[p]
        p += 1
        event = {"op": op, "pc": None, "line": None, "reg": None, "name": None, "type": None, "sig": None, "file": None, "position": False}
        if op == 0x00:
            event["pc"] = pc
            events.append(event)
            return names, events
        if op == 0x01:
            v, p = uleb(d, p)
            pc += v
        elif op == 0x02:
            v, p = sleb(d, p)
            line += v
        elif op in (0x03, 0x04):
            event["reg"], p = uleb(d, p)
            for key in ("name", "type") + (("sig",) if op == 0x04 else ()):
                v, p = uleb(d, p)
                event[key] = None if v == 0 else v - 1
        elif op in (0x05, 0x06):
            event["reg"], p = uleb(d, p)
        elif op in (0x07, 0x08):
            pass
        elif op == 0x09:
            v, p = uleb(d, p)
            event["file"] = None if v == 0 else v - 1
        else:
            adjusted = op - 10
            pc += adjusted // 15
            line += -4 + adjusted % 15
            event["position"] = True
        event["pc"] = pc
        event["line"] = line
        events.append(event)


def pc_to_pc(initial_line: int, names: list, events: list[dict]) -> bool:
    """The pattern R8 writes: a zero-change position, then (pc+1, line+1) positions, no parameter names."""
    ops = [e["op"] for e in events]
    return (initial_line <= 1 and all(n is None for n in names) and len(ops) >= 2 and ops[0] == 0x0E and ops[-1] == 0
            and all(o == 0x1E for o in ops[1:-1]))


class Extras:
    """The lines of the complete format that one method adds to its instruction text."""

    def __init__(self, classes: Classes, method_idx: int, access: int, code_off: int):
        self.classes = classes
        self.dex = classes.dex
        self.method_idx = method_idx
        self.access = access
        self.code_off = code_off
        self.entry = classes.owner[method_idx]
        self.unplaced = 0
        self.not_lines = 0

    def parameter_starts(self) -> list[int]:
        _, _, (_, params) = self.dex.methods[self.method_idx]
        starts, next_register = [], 0 if self.access & 0x8 else 1
        for p in params:
            starts.append(next_register)
            next_register += 2 if p in ("J", "D") else 1
        return starts

    def header(self, first_param) -> list[str]:
        d = self.dex.data
        _, _, (_, params) = self.dex.methods[self.method_idx]
        names = []
        if self.code_off:
            debug_off = struct.unpack_from("<I", d, self.code_off + 8)[0]
            if debug_off:
                names = debug_program(self.dex, debug_off)[0]
        slots = []
        list_off = self.entry["parameter_lists"].get(self.method_idx)
        if list_off:
            n = u32(d, list_off)
            if n == len(params):
                slots = [u32(d, list_off + 4 + 4 * i) for i in range(n)]
        out = []
        for position, start in enumerate(self.parameter_starts()):
            name = names[position] if position < len(names) else None
            blocks = annotation_lines(self.dex, slots[position], 8) if position < len(slots) and slots[position] else []
            if name is None and not blocks:
                continue
            line = "    .param p%d" % start
            if name is not None:
                line += ", " + literal_text(self.dex.units[name])
            out.append(line)
            if blocks:
                out.extend(blocks)
                out.append("    .end param")
        method_set = self.entry["method_sets"].get(self.method_idx)
        if method_set:
            out.extend(annotation_lines(self.dex, method_set, 4))
        return out

    def at_address(self, code_off: int, size: int, insn_starts: set, first_param: int) -> dict[int, list[str]]:
        d = self.dex.data
        debug_off = struct.unpack_from("<I", d, code_off + 8)[0]
        if not debug_off:
            return {}
        names, events = debug_program(self.dex, debug_off)
        initial_line = uleb(d, debug_off)[0]
        surrogate = pc_to_pc(initial_line, names, events)
        reg = lambda n: "p%d" % (n - first_param) if n >= first_param else "v%d" % n
        out: dict[int, list[str]] = {}
        for e in events:
            op = e["op"]
            if op <= 2:
                continue
            if op in (0x03, 0x04):
                name = literal_text(self.dex.units[e["name"]]) if e["name"] is not None else "null"
                ty = self.dex.types[e["type"]] if e["type"] is not None else "null"
                text = ".local %s, %s:%s" % (reg(e["reg"]), name, ty)
                if e["sig"] is not None:
                    text += ", " + literal_text(self.dex.units[e["sig"]])
            elif op == 0x05:
                text = ".end local " + reg(e["reg"])
            elif op == 0x06:
                text = ".restart local " + reg(e["reg"])
            elif op == 0x07:
                text = ".prologue"
            elif op == 0x08:
                text = ".epilogue"
            elif op == 0x09:
                text = ".source " + (literal_text(self.dex.units[e["file"]]) if e["file"] is not None else "null")
            else:
                if surrogate or e["line"] <= 0 or e["pc"] >= size:
                    self.not_lines += 1
                    continue
                text = ".line %d" % e["line"]
            pc = e["pc"]
            if pc in insn_starts or pc == size:
                out.setdefault(pc, []).append("    " + text)
            else:
                self.unplaced += 1
        return out


# ---- texts --------------------------------------------------------------------------------------------

def method_text(classes: Classes, method_idx: int, access: int, code_off: int) -> tuple[str, Extras]:
    extras = Extras(classes, method_idx, access, code_off)
    return oracle.render(classes.dex, method_idx, access, code_off, extras), extras


def flag_words(table, flags: int) -> str:
    return "".join(" " + word for bit, word in table if flags & bit)


def class_text(classes: Classes, descriptor: str) -> str:
    dex, d = classes.dex, classes.data
    c = classes.by_descriptor(descriptor)
    out = [".class%s %s" % (flag_words(CLASS_FLAGS, c["access"]), c["descriptor"])]
    if c["super"]:
        out.append(".super " + c["super"])
    if c["source"] is not None:
        out.append(".source " + literal_text(c["source"]))
    if c["interfaces"]:
        out.append("")
        out.extend(".implements " + i for i in c["interfaces"])
    if c["class_set"]:
        blocks = annotation_lines(dex, c["class_set"], 0)
        if blocks:
            out.append("")
            out.extend(blocks)
    values = []
    if c["static_values_off"]:
        p = c["static_values_off"]
        count, p = uleb(d, p)
        for _ in range(count):
            text, p = read_value(dex, p, 0)
            values.append(text)
    for key, with_values in (("static_fields", True), ("instance_fields", False)):
        if not c[key]:
            continue
        out.append("")
        for position, (index, flags) in enumerate(c[key]):
            _, name, ty = dex.fields[index]
            line = ".field%s %s:%s" % (flag_words(FIELD_FLAGS, flags), name, ty)
            if with_values and position < len(values):
                line += " = " + values[position]
            out.append(line)
            set_off = c["field_sets"].get(index)
            blocks = annotation_lines(dex, set_off, 4) if set_off else []
            if blocks:
                out.extend(blocks)
                out.append(".end field")
    return "\n".join(out) + "\n"


def context(text: str, header: str = CONTEXT_HEADER, words=(".method", ".registers", ".catch")) -> str:
    out = [header]
    for number, line in enumerate(text.split("\n")[:-1] if text.endswith("\n") else text.split("\n")):
        t = line.lstrip()
        if t.startswith(":") or t.startswith(tuple(words)):
            out.append("line %d: %s" % (number, line))
    return "\n".join(out) + "\n"


def class_context(text: str) -> str:
    return context(text, CLASS_CONTEXT_HEADER, (".class", ".super", ".source", ".implements", ".field"))


def render_all_full(data: bytes) -> dict[str, tuple[str, Extras]]:
    classes = Classes(data)
    return {classes.dex.method_text(i): method_text(classes, i, access, code) for i, access, code in classes.dex.defined}


def main(argv: list[str]) -> int:
    data = Path(argv[0]).read_bytes()
    classes = Classes(data)
    for entry in classes.classes:
        if len(argv) > 1 and entry["descriptor"] != argv[1]:
            continue
        print(class_text(classes, entry["descriptor"]), end="")
        for index, access, code in classes.dex.defined:
            if classes.owner[index] is entry:
                print(method_text(classes, index, access, code)[0], end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
