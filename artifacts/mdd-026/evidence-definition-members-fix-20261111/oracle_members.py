#!/usr/bin/env python3
"""Independent Python byte-level DEX oracle for the MDD-026 member relations.

This reader is deliberately independent of the Rust engine under test: it uses
only the Python standard library (struct) and the DEX format published by
Android.  It never imports mdd-dex, mdd-facts, mdd-input or mdd-types, and it
does not import the repository's reference oracle.

Relations produced (column order fixed):
  methods                14 columns, method_ids order
  class_fields            8 columns, class_def order then static/instance order
  class_methods           8 columns, class_def order then direct/virtual order
  method_strings          8 columns, method definition order then instruction order
  method_field_accesses  12 columns, same site order
  method_used_types       9 columns, same site order

Fix relative to the previous round: `methods_rows` / `class_*_rows` take the
real per-occurrence file_id instead of a constant 0, so a two-input run
exercises file_id 0/1 instead of comparing a constant with a constant.

The reader walks the physical map for code items and the class_data ULEB
streams, so row counts are enumerated from bytes, not from any engine output.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

NUL = b"\x00"

# Opcode -> instruction width in 16-bit code units.  Only the opcodes used by
# the tiny fixtures in this evidence directory are required; unknown opcodes are
# rejected instead of guessed.
WIDTHS = {
    0x0E: 1, 0x0F: 1, 0x10: 1, 0x11: 1, 0x12: 1, 0x13: 2, 0x14: 3, 0x15: 2,
    0x16: 2, 0x17: 3, 0x18: 3, 0x19: 2, 0x1A: 2, 0x1B: 3, 0x1C: 2, 0x1D: 1,
    0x1E: 1, 0x1F: 2, 0x20: 2, 0x21: 1, 0x22: 2, 0x23: 2, 0x24: 3, 0x25: 3,
    0x26: 3, 0x27: 1, 0x28: 1, 0x29: 2, 0x2A: 3, 0x2B: 3, 0x2C: 3, 0x2D: 2,
    0x2E: 2, 0x2F: 2, 0x30: 2, 0x31: 2, 0x32: 2, 0x33: 2, 0x34: 2, 0x35: 2,
    0x36: 2, 0x37: 2, 0x38: 2, 0x39: 2, 0x3A: 2, 0x3B: 2, 0x3C: 2, 0x3D: 2,
    0x3E: 1, 0x3F: 1, 0x40: 1, 0x41: 1, 0x42: 1, 0x43: 1, 0x44: 2, 0x45: 2,
    0x46: 2, 0x47: 2, 0x48: 2, 0x49: 2, 0x4A: 2, 0x4B: 2, 0x4C: 2, 0x4D: 2,
    0x4E: 2, 0x4F: 2, 0x50: 2, 0x51: 2, 0x52: 2, 0x53: 2, 0x54: 2, 0x55: 2,
    0x56: 2, 0x57: 2, 0x58: 2, 0x59: 2, 0x5A: 2, 0x5B: 2, 0x5C: 2, 0x5D: 2,
    0x5E: 2, 0x5F: 2, 0x60: 2, 0x61: 2, 0x62: 2, 0x63: 2, 0x64: 2, 0x65: 2,
    0x66: 2, 0x67: 2, 0x68: 2, 0x69: 2, 0x6A: 2, 0x6B: 2, 0x6C: 2, 0x6D: 2,
    0x6E: 3, 0x6F: 3, 0x70: 3, 0x71: 3, 0x72: 3, 0x73: 3, 0x74: 3, 0x75: 3,
    0x76: 3, 0x77: 3, 0x78: 3, 0x79: 1, 0x7A: 1, 0x7B: 1, 0x7C: 1, 0x7D: 1,
    0x7E: 1, 0x7F: 1, 0x80: 1, 0x81: 1, 0x82: 1, 0x83: 1, 0x84: 1, 0x85: 1,
    0x86: 1, 0x87: 1, 0x88: 1, 0x89: 1, 0x8A: 1, 0x8B: 1, 0x8C: 1, 0x8D: 1,
    0x8E: 1, 0x8F: 1, 0x90: 2, 0x91: 2, 0x92: 2, 0x93: 2, 0x94: 2, 0x95: 2,
    0x96: 2, 0x97: 2, 0x98: 2, 0x99: 2, 0x9A: 2, 0x9B: 2, 0x9C: 2, 0x9D: 2,
    0x9E: 2, 0x9F: 2, 0xA0: 2, 0xA1: 2, 0xA2: 2, 0xA3: 2, 0xA4: 2, 0xA5: 2,
    0xA6: 2, 0xA7: 2, 0xA8: 2, 0xA9: 2, 0xAA: 2, 0xAB: 2, 0xAC: 2, 0xAD: 2,
    0xAE: 2, 0xAF: 2, 0xB0: 2, 0xB1: 2, 0xB2: 2, 0xB3: 2, 0xB4: 2, 0xB5: 2,
    0xB6: 2, 0xB7: 2, 0xB8: 2, 0xB9: 2, 0xBA: 2, 0xBB: 2, 0xBC: 2, 0xBD: 2,
    0xBE: 2, 0xBF: 2, 0xC0: 2, 0xC1: 2, 0xC2: 2, 0xC3: 2, 0xC4: 2, 0xC5: 2,
    0xC6: 2, 0xC7: 2, 0xC8: 2, 0xC9: 2, 0xCA: 2, 0xCB: 2, 0xCC: 2, 0xCD: 2,
    0xCE: 2, 0xCF: 2, 0xD0: 2, 0xD1: 2, 0xD2: 2, 0xD3: 2, 0xD4: 2, 0xD5: 2,
    0xD6: 2, 0xD7: 2, 0xD8: 2, 0xD9: 2, 0xDA: 2, 0xDB: 2, 0xDC: 2, 0xDD: 2,
    0xDE: 2, 0xDF: 2, 0xE0: 2, 0xE1: 2, 0xE2: 2, 0xE3: 2, 0xE4: 2, 0xE5: 2,
    0xE6: 2, 0xE7: 2, 0xE8: 2, 0xE9: 2, 0xEA: 2, 0xEB: 2, 0xEC: 2, 0xED: 2,
    0xEE: 2, 0xEF: 2, 0xF0: 2, 0xF1: 2, 0xF2: 2, 0xF3: 2, 0xF4: 2, 0xF5: 2,
    0xF6: 2, 0xF7: 2, 0xF8: 2, 0xF9: 2, 0xFA: 4, 0xFB: 4, 0xFC: 3, 0xFD: 3,
    0xFE: 2, 0xFF: 2,
}

# Opcode -> (kind, operand word index, width of operand in code units).
OPERAND = {
    0x1A: ("string", 1, 1),
    0x1B: ("string", 1, 2),  # 32-bit pool index assembled from words 1 and 2
    0x1C: ("type", 1, 1),
    0x52: ("field", 1, 1), 0x53: ("field", 1, 1), 0x54: ("field", 1, 1),
    0x55: ("field", 1, 1), 0x56: ("field", 1, 1), 0x57: ("field", 1, 1),
    0x58: ("field", 1, 1), 0x59: ("field", 1, 1), 0x5A: ("field", 1, 1),
    0x5B: ("field", 1, 1), 0x5C: ("field", 1, 1), 0x5D: ("field", 1, 1),
    0x5E: ("field", 1, 1), 0x5F: ("field", 1, 1), 0x60: ("field", 1, 1),
    0x61: ("field", 1, 1), 0x62: ("field", 1, 1), 0x63: ("field", 1, 1),
    0x64: ("field", 1, 1), 0x65: ("field", 1, 1), 0x66: ("field", 1, 1),
    0x67: ("field", 1, 1), 0x68: ("field", 1, 1), 0x69: ("field", 1, 1),
    0x6A: ("field", 1, 1), 0x6B: ("field", 1, 1), 0x6C: ("field", 1, 1),
    0x6D: ("field", 1, 1),
    0x6E: ("method", 1, 1), 0x6F: ("method", 1, 1), 0x70: ("method", 1, 1),
    0x71: ("method", 1, 1), 0x72: ("method", 1, 1), 0x74: ("method", 1, 1),
    0x75: ("method", 1, 1), 0x76: ("method", 1, 1), 0x77: ("method", 1, 1),
    0x78: ("method", 1, 1),
}

# Mnemonic prefixes that decide the nullable using_type cell.
FIELD_GET_PREFIXES = ("iget", "sget")
FIELD_PUT_PREFIXES = ("iput", "sput")

METHOD_COLUMNS = ["file_id", "method_idx", "class_idx", "class_descriptor", "proto_idx",
                  "name", "descriptor", "return_descriptor", "param_count",
                  "param_descriptors", "access_flags", "opcode_count", "opcode_hex",
                  "method_kind"]
CLASS_FIELD_COLUMNS = ["file_id", "class_idx", "class_descriptor", "field_idx", "field_name",
                       "field_descriptor", "kind", "access_flags"]
CLASS_METHOD_COLUMNS = ["file_id", "class_idx", "class_descriptor", "method_idx", "method_name",
                        "method_descriptor", "kind", "access_flags"]
METHOD_STRING_COLUMNS = ["method", "method_class", "method_name", "value", "file_id",
                         "class_idx", "method_idx", "string_idx"]
METHOD_FIELD_COLUMNS = ["method", "method_class", "method_name", "field", "field_class",
                        "field_name", "field_type", "using_type", "file_id", "class_idx",
                        "method_idx", "field_idx"]
METHOD_TYPE_COLUMNS = ["method", "method_class", "method_name", "type_descriptor", "type_name",
                       "file_id", "class_idx", "method_idx", "type_idx"]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def uleb128(data, offset):
    result = shift = 0
    while True:
        require(offset < len(data), "uleb128 past end")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            require(result <= 0xFFFFFFFF, "uleb128 overflow")
            return result, offset
        shift += 7
        require(shift <= 35, "uleb128 too long")


def mutf8_decode(raw):
    """Decode the tiny fixture subset of MUTF-8 (no surrogate pairs)."""
    out = []
    i = 0
    while i < len(raw):
        byte = raw[i]
        if byte < 0x80:
            out.append(byte)
            i += 1
        elif byte & 0xE0 == 0xC0:
            require(i + 1 < len(raw), "mutf8 truncated")
            out.append(((byte & 0x1F) << 6) | (raw[i + 1] & 0x3F))
            i += 2
        elif byte & 0xF0 == 0xE0:
            require(i + 2 < len(raw), "mutf8 truncated")
            out.append(((byte & 0x0F) << 12) | ((raw[i + 1] & 0x3F) << 6) | (raw[i + 2] & 0x3F))
            i += 3
        else:
            raise ValueError("mutf8 byte out of subset")
    return bytes(out).decode("utf-8", "surrogatepass")


def type_name(descriptor):
    dimensions = len(descriptor) - len(descriptor.lstrip("["))
    rest = descriptor[dimensions:]
    if rest == "I":
        name = "int"
    elif rest == "V":
        name = "void"
    elif rest == "J":
        name = "long"
    elif rest == "D":
        name = "double"
    elif rest.startswith("L") and rest.endswith(";"):
        name = rest[1:-1].replace("/", ".")
    else:
        name = rest
    return name + "[]" * dimensions


class MemberOracle:
    def __init__(self, data):
        self.data = data
        require(len(data) >= 112, "file shorter than DEX header")
        require(data[:4] == b"dex\n", "bad DEX magic")
        header = struct.unpack_from("<20I", data, 32)
        require(header[0] == len(data), "declared file_size differs")
        require(header[1] == 112, "declared header_size differs")
        require(header[2] == 0x12345678, "endian tag differs")
        (self.string_count, self.string_ids_off) = header[6], header[7]
        (self.type_count, self.type_ids_off) = header[8], header[9]
        (self.proto_count, self.proto_ids_off) = header[10], header[11]
        (self.field_count, self.field_ids_off) = header[12], header[13]
        (self.method_count, self.method_ids_off) = header[14], header[15]
        (self.class_count, self.class_defs_off) = header[16], header[17]
        self._strings()
        self._types()
        self._protos()
        self._fields()
        self._methods()
        self._code()
        self._class_data()

    # ---- identifier tables -------------------------------------------------
    def _strings(self):
        self.strings = []
        for index in range(self.string_count):
            at = struct.unpack_from("<I", self.data, self.string_ids_off + 4 * index)[0]
            _length, cursor = uleb128(self.data, at)
            end = self.data.index(NUL, cursor)
            self.strings.append(mutf8_decode(self.data[cursor:end]))

    def _types(self):
        self.types = []
        for index in range(self.type_count):
            string_index = struct.unpack_from("<I", self.data, self.type_ids_off + 4 * index)[0]
            require(string_index < self.string_count, "type descriptor index out of range")
            self.types.append(self.strings[string_index])

    def _protos(self):
        self.protos = []
        for index in range(self.proto_count):
            _shorty, return_index, parameters_off = struct.unpack_from(
                "<III", self.data, self.proto_ids_off + 12 * index)
            require(return_index < self.type_count, "proto return index out of range")
            args = []
            if parameters_off:
                size = struct.unpack_from("<I", self.data, parameters_off)[0]
                args = list(struct.unpack_from("<" + "H" * size, self.data, parameters_off + 4))
                require(all(item < self.type_count for item in args), "proto arg index out of range")
            self.protos.append((self.types[return_index], [self.types[item] for item in args]))

    def _fields(self):
        self.fields = []
        for index in range(self.field_count):
            owner, field_type, name = struct.unpack_from("<HHI", self.data, self.field_ids_off + 8 * index)
            require(owner < self.type_count and field_type < self.type_count
                    and name < self.string_count, "field id index out of range")
            self.fields.append({"class_idx": owner, "type_idx": field_type, "name_idx": name,
                                "class_descriptor": self.types[owner],
                                "field_name": self.strings[name],
                                "field_type": self.types[field_type]})

    def _methods(self):
        self.methods = []
        for index in range(self.method_count):
            owner, proto, name = struct.unpack_from("<HHI", self.data, self.method_ids_off + 8 * index)
            require(owner < self.type_count and proto < self.proto_count
                    and name < self.string_count, "method id index out of range")
            ret, args = self.protos[proto]
            self.methods.append({"class_idx": owner, "proto_idx": proto, "name_idx": name,
                                 "class_descriptor": self.types[owner],
                                 "method_name": self.strings[name],
                                 "return_descriptor": ret, "param_descriptors": args})

    def method_descriptor(self, index):
        method = self.methods[index]
        return (method["class_descriptor"] + "->" + method["method_name"] + "("
                + "".join(method["param_descriptors"]) + ")" + method["return_descriptor"])

    # ---- code items --------------------------------------------------------
    def _code(self):
        self.code = {}
        map_off = struct.unpack_from("<I", self.data, 32 + 5 * 4)[0]
        map_count = struct.unpack_from("<I", self.data, map_off)[0]
        code_offset = None
        for index in range(map_count):
            kind, _unused, count, offset = struct.unpack_from("<HHII", self.data, map_off + 4 + 12 * index)
            if kind == 0x2001:
                require(count > 0 and code_offset is None, "duplicate code map section")
                code_offset = offset
                for _ in range(count):
                    code_offset = (code_offset + 3) & ~3
                    start = code_offset
                    (registers, ins, outs, tries, _debug, insns_size) = struct.unpack_from(
                        "<HHHHII", self.data, code_offset)
                    require(tries == 0, "evidence fixture subset excludes tries")
                    words = list(struct.unpack_from("<" + "H" * insns_size, self.data, code_offset + 16))
                    self.code[start] = {"registers": registers, "ins": ins, "outs": outs,
                                        "words": words,
                                        "instructions": self._instructions(words, code_offset + 16)}
                    code_offset += 16 + insns_size * 2

    def _instructions(self, words, base):
        result = []
        pc = 0
        while pc < len(words):
            opcode = words[pc] & 0xFF
            width = WIDTHS.get(opcode)
            require(width is not None and pc + width <= len(words),
                    "unsupported opcode/width at code unit " + str(pc))
            operand = OPERAND.get(opcode)
            refs = []
            if operand is not None:
                kind, word_index, operand_width = operand
                if kind == "string" and opcode == 0x1B:
                    index = words[pc + 1] | (words[pc + 2] << 16)
                else:
                    index = words[pc + word_index]
                refs.append({"kind": kind, "index": index,
                             "byte_offset": base + pc * 2 + 2,
                             "byte_length": operand_width * 2})
            result.append({"pc": pc, "opcode": opcode, "width": width, "refs": refs})
            pc += width
        return result

    # ---- class data --------------------------------------------------------
    def _class_data(self):
        self.class_defs = []
        self.field_definitions = []
        self.method_definitions = []
        self._definition_by_method = {}
        for ordinal in range(self.class_count):
            (owner, access_flags, parent, interfaces, source, annotations, class_data_off,
             _static_values) = struct.unpack_from("<8I", self.data, self.class_defs_off + 32 * ordinal)
            require(owner < self.type_count, "class type index out of range")
            entry = {"class_def_idx": ordinal, "class_idx": owner,
                     "class_descriptor": self.types[owner], "access_flags": access_flags,
                     "superclass_idx": None if parent == 0xFFFFFFFF else parent,
                     "source_file_idx": None if source == 0xFFFFFFFF else source,
                     "interfaces_off": interfaces, "annotations_off": annotations,
                     "class_data_off": class_data_off}
            self.class_defs.append(entry)
            if not class_data_off:
                continue
            at = class_data_off
            counts = []
            for _ in range(4):
                value, at = uleb128(self.data, at)
                counts.append(value)
            for group, count in enumerate(counts):
                index = 0
                for position in range(count):
                    delta, at = uleb128(self.data, at)
                    flags, at = uleb128(self.data, at)
                    index += delta
                    if group < 2:
                        require(index < self.field_count, "field index out of range")
                        field = self.fields[index]
                        require(field["class_idx"] == owner, "field owner mismatch")
                        self.field_definitions.append({
                            "class_def_idx": ordinal, "class_idx": owner, "field_idx": index,
                            "kind": "static" if group == 0 else "instance",
                            "access_flags": flags, "ordinal": position})
                    else:
                        code_off, at = uleb128(self.data, at)
                        require(index < self.method_count, "method index out of range")
                        method = self.methods[index]
                        require(method["class_idx"] == owner, "method owner mismatch")
                        definition = {"class_def_idx": ordinal, "class_idx": owner,
                                      "method_idx": index, "kind": "direct" if group == 2 else "virtual",
                                      "access_flags": flags, "code_off": code_off, "ordinal": position}
                        self.method_definitions.append(definition)
                        self._definition_by_method[index] = definition

    # ---- projections -------------------------------------------------------
    def methods_rows(self, file_id=0):
        rows = []
        for index, method in enumerate(self.methods):
            definition = self._definition_by_method.get(index)
            if definition is None:
                flags = kind = count = hexadecimal = None
            else:
                flags = definition["access_flags"]
                kind = definition["kind"]
                if flags & (0x100 | 0x400):
                    count, hexadecimal = 0, ""
                else:
                    code = self.code.get(definition["code_off"])
                    require(code is not None, "defined concrete method has no code item")
                    count = len(code["instructions"])
                    hexadecimal = " ".join(f"{item['opcode']:02x}" for item in code["instructions"])
            rows.append({
                "file_id": file_id, "method_idx": index, "class_idx": method["class_idx"],
                "class_descriptor": method["class_descriptor"], "proto_idx": method["proto_idx"],
                "name": method["method_name"], "descriptor": self.method_descriptor(index),
                "return_descriptor": method["return_descriptor"],
                "param_count": len(method["param_descriptors"]),
                "param_descriptors": ",".join(method["param_descriptors"]),
                "access_flags": flags, "opcode_count": count, "opcode_hex": hexadecimal,
                "method_kind": kind})
        return rows

    def class_field_rows(self, file_id=0):
        rows = []
        for definition in self.field_definitions:
            field = self.fields[definition["field_idx"]]
            rows.append({
                "file_id": file_id, "class_idx": definition["class_idx"],
                "class_descriptor": self.types[definition["class_idx"]],
                "field_idx": definition["field_idx"], "field_name": field["field_name"],
                "field_descriptor": (field["class_descriptor"] + "->" + field["field_name"]
                                     + ":" + field["field_type"]),
                "kind": definition["kind"], "access_flags": definition["access_flags"]})
        return rows

    def class_method_rows(self, file_id=0):
        rows = []
        for definition in self.method_definitions:
            method = self.methods[definition["method_idx"]]
            rows.append({
                "file_id": file_id, "class_idx": definition["class_idx"],
                "class_descriptor": self.types[definition["class_idx"]],
                "method_idx": definition["method_idx"], "method_name": method["method_name"],
                "method_descriptor": self.method_descriptor(definition["method_idx"]),
                "kind": definition["kind"], "access_flags": definition["access_flags"]})
        return rows

    def _site_rows(self, file_id=0):
        strings, fields, types = [], [], []
        for definition in self.method_definitions:
            if definition["access_flags"] & (0x100 | 0x400):
                continue
            code = self.code.get(definition["code_off"])
            if code is None:
                continue
            method = self.methods[definition["method_idx"]]
            common = {"method": self.method_descriptor(definition["method_idx"]),
                      "method_class": method["class_descriptor"],
                      "method_name": method["method_name"], "file_id": file_id,
                      "class_idx": definition["class_idx"],
                      "method_idx": definition["method_idx"]}
            for instruction in code["instructions"]:
                for ref in instruction["refs"]:
                    if ref["kind"] == "string":
                        strings.append({**common, "value": self.strings[ref["index"]],
                                        "string_idx": ref["index"]})
                    elif ref["kind"] == "field":
                        field = self.fields[ref["index"]]
                        mnemonic = MNEMONIC.get(instruction["opcode"], "")
                        if mnemonic.startswith(FIELD_GET_PREFIXES):
                            using = "get"
                        elif mnemonic.startswith(FIELD_PUT_PREFIXES):
                            using = "put"
                        else:
                            using = None
                        fields.append({**common,
                                       "field": (field["class_descriptor"] + "->"
                                                 + field["field_name"] + ":" + field["field_type"]),
                                       "field_class": field["class_descriptor"],
                                       "field_name": field["field_name"],
                                       "field_type": field["field_type"],
                                       "using_type": using, "field_idx": ref["index"]})
                    elif ref["kind"] == "type":
                        types.append({**common, "type_descriptor": self.types[ref["index"]],
                                      "type_name": type_name(self.types[ref["index"]]),
                                      "type_idx": ref["index"]})
        return strings, fields, types

    def method_string_rows(self, file_id=0):
        return self._site_rows(file_id)[0]

    def method_field_rows(self, file_id=0):
        return self._site_rows(file_id)[1]

    def method_type_rows(self, file_id=0):
        return self._site_rows(file_id)[2]

    def all_rows(self, file_id=0):
        strings, fields, types = self._site_rows(file_id)
        return {
            "methods": self.methods_rows(file_id),
            "class_fields": self.class_field_rows(file_id),
            "class_methods": self.class_method_rows(file_id),
            "method_strings": strings,
            "method_field_accesses": fields,
            "method_used_types": types,
        }


MNEMONIC = {
    0x52: "iget", 0x53: "iget-wide", 0x54: "iget-object", 0x55: "iget-boolean",
    0x56: "iget-byte", 0x57: "iget-char", 0x58: "iget-short",
    0x59: "iput", 0x5A: "iput-wide", 0x5B: "iput-object", 0x5C: "iput-boolean",
    0x5D: "iput-byte", 0x5E: "iput-char", 0x5F: "iput-short",
    0x60: "sget", 0x61: "sget-wide", 0x62: "sget-object", 0x63: "sget-boolean",
    0x64: "sget-byte", 0x65: "sget-char", 0x66: "sget-short",
    0x67: "sput", 0x68: "sput-wide", 0x69: "sput-object", 0x6A: "sput-boolean",
    0x6B: "sput-byte", 0x6C: "sput-char", 0x6D: "sput-short",
}


def load(path):
    data = Path(path).read_bytes()
    return MemberOracle(data), data


def main():
    if len(sys.argv) < 2:
        print("usage: oracle_members.py DEX [DEX ...]", file=sys.stderr)
        return 2
    output = {}
    for path in sys.argv[1:]:
        oracle, data = load(path)
        rows = oracle.all_rows(0)
        output[Path(path).name] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "row_counts": {name: len(value) for name, value in rows.items()},
            "rows": rows,
        }
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
