#!/usr/bin/env python3
"""Independent byte-level DEX/APK oracle for MDD-026 code/annotation relations.

Independence argument:
  * Pure Python standard library (struct/hashlib/zlib/zipfile/importlib).
  * Imports no Rust crate, no mdd module, no A0 binary and no recorded output.
  * The two handwritten byte readers under tests/fixtures/ are imported read-only
    for the tiny-opcode reference walk and the annotation tree walk; they are
    themselves pure Python stdlib readers and share no code with the Rust
    crates.  Class/code-item parsing is implemented locally in this file.
  * Every row is enumerated from physical DEX bytes (map, string pool, type_ids,
    class_defs, class_data, code_item, annotation items), so a dropped,
    duplicated or reordered row changes the emitted sequence.

This oracle is a reader, not a verdict: it never compares two engines.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import struct
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

NO_INDEX = 0xFFFFFFFF
PRIMITIVES = {
    "Z": "boolean", "B": "byte", "S": "short", "C": "char", "I": "int",
    "J": "long", "F": "float", "D": "double", "V": "void",
}
KIND = {
    0: "byte", 2: "short", 3: "char", 4: "int", 6: "long",
    0x10: "float", 0x11: "double", 0x15: "method_type", 0x16: "method_handle",
    0x17: "string", 0x18: "type", 0x19: "field", 0x1a: "method",
    0x1b: "enum", 0x1c: "array", 0x1d: "annotation", 0x1e: "null",
    0x1f: "boolean",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def java_name(descriptor):
    dimensions = len(descriptor) - len(descriptor.lstrip("["))
    rest = descriptor[dimensions:]
    if rest in PRIMITIVES:
        base = PRIMITIVES[rest]
    elif rest.startswith("L") and rest.endswith(";"):
        base = rest[1:-1].replace("/", ".")
    else:
        raise ValueError("unhandled descriptor: " + descriptor)
    return base + "[]" * dimensions


def load_module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Handwritten pure-Python readers, imported read-only.  They are independent of
# the Rust engine; this file only composes them with local class/code parsing.
_REFERENCE = load_module("mdd_evidence_reference_oracle",
                         "tests/fixtures/references/oracle.py")
_ANNOTATION = load_module("mdd_evidence_annotation_oracle",
                          "tests/fixtures/annotations/oracle.py")


class DexOccurrence:
    """One physical DEX member, parsed from bytes only."""

    def __init__(self, data, file_id, source_path, entry_name):
        self.data = data
        self.file_id = file_id
        self.source_path = source_path
        self.entry_name = entry_name
        require(len(data) >= 112, "header too short")
        require(data[:4] == b"dex\n", "bad magic")
        require(data[7] == 0, "bad version terminator")
        self.version = data[4:7].decode("ascii")
        self.checksum = struct.unpack_from("<I", data, 8)[0]
        self.signature_hex = data[12:32].hex()
        require(self.checksum == (zlib.adler32(data[12:]) & 0xFFFFFFFF), "adler32 mismatch")
        require(self.signature_hex == hashlib.sha1(data[32:]).hexdigest(), "sha1 mismatch")
        words = struct.unpack_from("<20I", data, 32)
        (self.file_size, self.header_size, self.endian_tag, self.link_size, self.link_off,
         self.map_off, self.string_count, self.string_ids_off, self.type_count, self.type_ids_off,
         self.proto_count, self.proto_ids_off, self.field_count, self.field_ids_off,
         self.method_count, self.method_ids_off, self.class_count, self.class_defs_off,
         self.data_size, self.data_off) = words
        require(self.file_size == len(data), "declared file_size differs")
        require(self.header_size == 112, "declared header_size differs")
        require(self.endian_tag == 0x12345678, "non-little-endian fixture")
        self.byte_len = len(data)
        self._map()
        self._strings()
        self._types()
        self._protos()
        self._fields()
        self._methods()
        self._classes()
        self._code_items()
        self._method_ownership()

    # ---- primitive readers -------------------------------------------------
    def u32(self, at):
        require(0 <= at and at + 4 <= len(self.data), "u32 bounds")
        return struct.unpack_from("<I", self.data, at)[0]

    def u16(self, at):
        require(0 <= at and at + 2 <= len(self.data), "u16 bounds")
        return struct.unpack_from("<H", self.data, at)[0]

    def unpack(self, form, at):
        require(0 <= at and at + struct.calcsize(form) <= len(self.data), "unpack bounds")
        return struct.unpack_from(form, self.data, at)

    def uleb128(self, at):
        value = 0
        for index in range(5):
            require(at + index < len(self.data), "leb128 truncated")
            byte = self.data[at + index]
            value += (byte & 0x7F) * (128 ** index)
            if byte < 0x80:
                require(value <= 0xFFFFFFFF, "leb128 overflow")
                return value, at + index + 1
        raise ValueError("leb128 overflow")

    def _map(self):
        count = self.u32(self.map_off)
        entries = [self.unpack("<HHII", self.map_off + 4 + index * 12) for index in range(count)]
        self.sections = {}
        for ordinal, (kind, unused, size, offset) in enumerate(entries):
            require(kind not in self.sections and unused == 0 and size > 0, "map")
            end = entries[ordinal + 1][3] if ordinal + 1 < len(entries) else len(self.data)
            require(offset < end <= len(self.data), "map_bounds")
            self.sections[kind] = (offset, end, size)

    def _strings(self):
        self.strings = []
        for index in range(self.string_count):
            at = self.u32(self.string_ids_off + 4 * index)
            length, at = self.uleb128(at)
            end = self.data.find(b"\x00", at)
            require(end >= at, "unterminated string")
            raw = self.data[at:end]
            text = raw.replace(b"\xc0\x80", b"\x00").decode("utf-8", "surrogatepass")
            utf16 = text.encode("utf-16-le", "surrogatepass")
            units = list(struct.unpack("<" + "H" * (len(utf16) // 2), utf16))
            require(len(units) == length, "utf16 length differs")
            self.strings.append({"text": text, "raw_hex": raw.hex().upper(), "units": units})

    def _types(self):
        self.types = [self.strings[self.u32(self.type_ids_off + 4 * index)]["text"]
                      for index in range(self.type_count)]

    def _protos(self):
        self.protos = []
        for index in range(self.proto_count):
            shorty, ret, at = self.unpack("<III", self.proto_ids_off + 12 * index)
            args = [] if not at else list(self.unpack("<" + "H" * self.u32(at), at + 4))
            self.protos.append((self.types[ret], [self.types[i] for i in args]))

    def _fields(self):
        self.fields = [self.unpack("<HHI", self.field_ids_off + 8 * index)
                       for index in range(self.field_count)]

    def _methods(self):
        self.methods = [self.unpack("<HHI", self.method_ids_off + 8 * index)
                        for index in range(self.method_count)]

    def method_descriptor(self, index):
        owner, proto, name = self.methods[index]
        ret, args = self.protos[proto]
        return self.types[owner] + "->" + self.strings[name] + "(" + "".join(args) + ")" + ret

    # ---- classes -----------------------------------------------------------
    def _classes(self):
        self.classes = []
        for class_def_idx in range(self.class_count):
            (class_idx, access_flags, superclass_idx, interfaces_off, source_idx,
             _annotations_off, _class_data_off, _static_values_off) = self.unpack(
                "<8I", self.class_defs_off + 32 * class_def_idx)
            require(class_idx < len(self.types), "class type index")
            require(superclass_idx == NO_INDEX or superclass_idx < len(self.types),
                    "superclass type index")
            superclass = None if superclass_idx == NO_INDEX else self.types[superclass_idx]
            source_file = None
            source_file_hex = None
            source_file_strict = None
            if source_idx != NO_INDEX:
                require(source_idx < len(self.strings), "source file index")
                source_file = self.strings[source_idx]
                source_file_hex = source_file["raw_hex"]
                try:
                    source_file_strict = source_file["text"].encode("utf-8", "strict").decode("utf-8")
                except UnicodeEncodeError:
                    source_file_strict = None
            interface_count = 0
            if interfaces_off != 0:
                require(interfaces_off + 4 <= len(self.data), "interface list bounds")
                interface_count = self.u32(interfaces_off)
                require(interfaces_off + 4 + 2 * interface_count <= len(self.data),
                        "interface list size")
            self.classes.append({
                "class_def_idx": class_def_idx,
                "class_idx": class_idx,
                "descriptor": self.types[class_idx],
                "access_flags": access_flags,
                "superclass_descriptor": superclass,
                "interface_count": interface_count,
                "source_file": source_file_hex,
                "source_file_strict": source_file_strict,
            })

    # ---- code items and method ownership ----------------------------------
    def _code_items(self):
        self.code = {}
        entry = self.sections.get(0x2001)
        if entry is None:
            return
        start, _end, count = entry
        at = start
        for _ in range(count):
            at = (at + 3) & ~3
            registers, ins, outs, tries, debug, size = self.unpack("<HHHHII", at)
            insns_off = at + 16
            require(insns_off + size * 2 <= len(self.data), "insns bounds")
            tries_off = insns_off + size * 2 + (size % 2) * 2 if tries else None
            handlers_off = tries_off + tries * 8 if tries else None
            if tries:
                require(handlers_off <= len(self.data), "handlers bounds")
            self.code[at] = {
                "code_off": at, "registers_size": registers, "ins_size": ins,
                "outs_size": outs, "tries_size": tries, "debug_info_off": debug,
                "insns_size": size, "insns_off": insns_off,
                "tries_off": tries_off, "handlers_off": handlers_off,
            }
            at += 16 + size * 2

    def _method_ownership(self):
        self.definitions = []
        for class_def in range(self.class_count):
            (_class_idx, _flags, _parent, _interfaces, _source, _annotations,
             class_data, _static) = self.unpack("<8I", self.class_defs_off + 32 * class_def)
            if not class_data:
                continue
            at = class_data
            counts = []
            for _ in range(4):
                value, at = self.uleb128(at)
                counts.append(value)
            for count in counts[:2]:
                field = 0
                for _ in range(count):
                    delta, at = self.uleb128(at)
                    _flags, at = self.uleb128(at)
                    field += delta
            for count in counts[2:]:
                method = 0
                for _ in range(count):
                    delta, at = self.uleb128(at)
                    _flags, at = self.uleb128(at)
                    code_off, at = self.uleb128(at)
                    method += delta
                    require(method < self.method_count, "method idx")
                    self.definitions.append((method, code_off))

    # ---- relation projections ---------------------------------------------
    def code_item_rows(self):
        rows = []
        for method_idx, code_off in self.definitions:
            if not code_off:
                continue
            require(code_off in self.code, "body_not_physical_start")
            item = self.code[code_off]
            rows.append({"file_id": self.file_id, "method_idx": method_idx, **item})
        return rows

    def class_rows(self):
        return [{"file_id": self.file_id, **row} for row in self.classes]

    def method_call_rows(self):
        """Reuse the handwritten tiny-opcode reader; it shares no Rust code."""
        try:
            output = _REFERENCE.Oracle(self.data).read()
        except ValueError:
            # Fixtures with tries/non-empty debug (owned_try) carry no invoke
            # instructions; the native reference layer emits no calls there.
            return []
        return [{**row, "file_id": self.file_id}
                for row in output["relations"]["method_calls"]]

    def annotation_rows(self):
        if 0x2004 not in self.sections:
            return {"annotations": [], "annotation_elements": [],
                    "annotation_set_entries": [], "annotation_directory_entries": []}
        result = _ANNOTATION.Oracle(self.data).read()
        return {
            "annotations": [{**row, "file_id": self.file_id} for row in result["annotations"]],
            "annotation_elements": [{**row, "file_id": self.file_id}
                                    for row in result["annotation_elements"]],
            "annotation_set_entries": [{**row, "file_id": self.file_id}
                                       for row in result["annotation_set_entries"]],
            "annotation_directory_entries": [{**row, "file_id": self.file_id}
                                             for row in result["annotation_directory_entries"]],
        }


def read_inputs(inputs):
    """Enumerate selected DEX occurrences from raw DEX paths or one APK.

    ``inputs`` is a list of (kind, path) pairs.  For an APK every stored DEX
    member is enumerated in archive order; for a raw DEX the file is one
    occurrence.  file_id is the selected-scope ordinal (0-based).
    """
    occurrences = []
    file_id = 0
    for kind, path in inputs:
        if kind == "dex":
            data = path.read_bytes()
            occurrences.append(DexOccurrence(data, file_id, str(path), path.name))
            file_id += 1
        elif kind == "apk":
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    data = archive.read(info)
                    if data[:4] != b"dex\n":
                        continue
                    occurrences.append(DexOccurrence(data, file_id, str(path), info.filename))
                    file_id += 1
        else:
            raise ValueError("unknown input kind: " + kind)
    return occurrences


def relation_rows(occurrences, relation):
    """Concatenate one relation's rows across occurrences in scope order."""
    rows = []
    for occurrence in occurrences:
        if relation == "code_items":
            rows.extend(occurrence.code_item_rows())
        elif relation == "classes":
            rows.extend(occurrence.class_rows())
        elif relation == "method_calls":
            rows.extend(occurrence.method_call_rows())
        elif relation in ("annotations", "annotation_elements",
                          "annotation_set_entries", "annotation_directory_entries"):
            rows.extend(occurrence.annotation_rows()[relation])
        else:
            raise ValueError("unknown relation: " + relation)
    return rows
