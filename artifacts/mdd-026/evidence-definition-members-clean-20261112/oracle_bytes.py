#!/usr/bin/env python3
"""Independent byte-level DEX/APK oracle for MDD-026 definition relations.

Independence argument:
  * Pure Python standard library over the source bytes (zipfile/struct/hashlib/zlib).
  * Imports no Rust crate, no mdd-* module, no A0 binary and no recorded output.
  * Every row is enumerated from the physical DEX map / string pool / type_ids /
    class_defs / interface type_list, so a dropped, duplicated or reordered row
    changes the emitted sequence.

Fix relative to the previous round: `string_pool_id` is no longer fabricated as
the occurrence ordinal.  The engine exposes a content-derived pool identity
(`sha256:<content>:physical-dex:0:string-pool:<string_ids_off>:<string_count>`);
this oracle recomputes that identity from the same bytes, so the native value
is checked against an independent digest instead of against a constant.

This oracle is a reader, not a verdict: it never compares two engines.
"""
from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib

PRIMITIVES = {
    "Z": "boolean", "B": "byte", "S": "short", "C": "char", "I": "int",
    "J": "long", "F": "float", "D": "double", "V": "void",
}
NO_INDEX = 0xFFFFFFFF


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


def physical_dex_id(data):
    """Content-derived physical DEX identity, recomputed from bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest() + ":physical-dex:0"


def expected_string_pool_id(data):
    """Content-derived string-pool identity, recomputed from bytes.

    Format observed from the engine and from crates/mdd-facts/src/metadata.rs:
    `<physical_dex_id>:string-pool:<string_ids_off>:<string_count>`.
    """
    require(len(data) >= 112, "header too short")
    require(data[:4] == b"dex\n", "bad magic")
    string_count, string_ids_off = struct.unpack_from("<II", data, 32 + 6 * 4)
    return physical_dex_id(data) + ":string-pool:" + str(string_ids_off) + ":" + str(string_count)


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
        # A0 and the native engine expose the signature as lowercase hex text.
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
        self.physical_dex_id = physical_dex_id(data)
        self.string_pool_id = self.physical_dex_id + ":string-pool:" + str(self.string_ids_off) + ":" + str(self.string_count)
        self._strings()
        self._types()
        self._classes()

    def u32(self, at):
        require(0 <= at and at + 4 <= len(self.data), "u32 bounds")
        return struct.unpack_from("<I", self.data, at)[0]

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

    def _strings(self):
        self.strings = []
        for index in range(self.string_count):
            at = self.u32(self.string_ids_off + 4 * index)
            length, at = self.uleb128(at)
            end = self.data.find(b"\x00", at)
            require(end >= 0, "unterminated string")
            raw = self.data[at:end]
            text = raw.replace(b"\xc0\x80", b"\x00").decode("utf-8", "surrogatepass")
            utf16 = text.encode("utf-16-le", "surrogatepass")
            units = list(struct.unpack("<" + "H" * (len(utf16) // 2), utf16))
            require(len(units) == length, "utf16 length differs")
            self.strings.append({
                "string_idx": index,
                "value_hex": raw.hex().upper(),
                "value": text,
                "utf16_units": units,
            })

    def _types(self):
        self.types = []
        for index in range(self.type_count):
            string_index = self.u32(self.type_ids_off + 4 * index)
            require(string_index < len(self.strings), "type string index")
            descriptor = self.strings[string_index]["value"]
            self.types.append({
                "type_idx": index,
                "descriptor": descriptor,
                "java_name": java_name(descriptor),
            })

    def _classes(self):
        self.classes = []
        self.interfaces = []
        for class_def_idx in range(self.class_count):
            (class_idx, access_flags, superclass_idx, interfaces_off, source_idx,
             _annotations_off, _class_data_off, _static_values_off) = struct.unpack_from(
                "<8I", self.data, self.class_defs_off + 32 * class_def_idx)
            require(class_idx < len(self.types), "class type index")
            require(superclass_idx == NO_INDEX or superclass_idx < len(self.types),
                    "superclass type index")
            superclass = None if superclass_idx == NO_INDEX else self.types[superclass_idx]["descriptor"]
            source_file = None
            source_file_hex = None
            if source_idx != NO_INDEX:
                require(source_idx < len(self.strings), "source file index")
                source_file = self.strings[source_idx]["value"]
                source_file_hex = self.strings[source_idx]["value_hex"]
            interface_count = 0
            if interfaces_off != 0:
                require(interfaces_off + 4 <= len(self.data), "interface list bounds")
                interface_count = self.u32(interfaces_off)
                require(interfaces_off + 4 + 2 * interface_count <= len(self.data),
                        "interface list size")
                for ordinal in range(interface_count):
                    type_index = struct.unpack_from("<H", self.data, interfaces_off + 4 + 2 * ordinal)[0]
                    require(type_index < len(self.types), "interface type index")
                    self.interfaces.append({
                        "class_def_idx": class_def_idx,
                        "class_idx": class_idx,
                        "ordinal": ordinal,
                        "interface_type_idx": type_index,
                        "interface_descriptor": self.types[type_index]["descriptor"],
                    })
            self.classes.append({
                "class_def_idx": class_def_idx,
                "class_idx": class_idx,
                "descriptor": self.types[class_idx]["descriptor"],
                "access_flags": access_flags,
                "superclass_descriptor": superclass,
                "interface_count": interface_count,
                "source_file": source_file,
                "source_file_hex": source_file_hex,
            })

    # ---- relation projections (column order matches the declared schema) ----
    def header_row(self):
        return {
            "byte_len": self.byte_len,
            "dex_version": self.version,
            "checksum": self.checksum,
            "signature_hex": self.signature_hex,
            "file_size": self.file_size,
            "header_size": self.header_size,
            "endian_tag": self.endian_tag,
            "link_size": self.link_size,
            "link_off": self.link_off,
            "map_off": self.map_off,
            "string_count": self.string_count,
            "string_ids_off": self.string_ids_off,
            "type_count": self.type_count,
            "type_ids_off": self.type_ids_off,
            "proto_count": self.proto_count,
            "proto_ids_off": self.proto_ids_off,
            "field_count": self.field_count,
            "field_ids_off": self.field_ids_off,
            "method_count": self.method_count,
            "method_ids_off": self.method_ids_off,
            "class_count": self.class_count,
            "class_defs_off": self.class_defs_off,
            "data_size": self.data_size,
            "data_off": self.data_off,
        }

    def identity_row(self):
        return {
            "file_id": self.file_id,
            "string_pool_id": self.string_pool_id,
            "source_path": self.source_path,
            "entry_name": self.entry_name,
        }

    def string_rows(self):
        return [{
            "string_pool_id": self.string_pool_id,
            "string_idx": item["string_idx"],
            "value": item["value_hex"],
        } for item in self.strings]

    def type_rows(self):
        return [{
            "file_id": self.file_id,
            "type_idx": item["type_idx"],
            "descriptor": item["descriptor"],
            "java_name": item["java_name"],
        } for item in self.types]

    def class_rows(self):
        return [{
            "file_id": self.file_id,
            "class_def_idx": item["class_def_idx"],
            "class_idx": item["class_idx"],
            "descriptor": item["descriptor"],
            "access_flags": item["access_flags"],
            "superclass_descriptor": item["superclass_descriptor"],
            "interface_count": item["interface_count"],
            "source_file": item["source_file_hex"],
        } for item in self.classes]

    def interface_rows(self):
        return [{
            "file_id": self.file_id,
            "class_idx": item["class_idx"],
            "ordinal": item["ordinal"],
            "interface_type_idx": item["interface_type_idx"],
            "interface_descriptor": item["interface_descriptor"],
        } for item in self.interfaces]


def read_inputs(inputs):
    """Enumerate selected DEX occurrences from raw DEX paths or one APK.

    `inputs` is a list of (kind, path) pairs. For an APK every stored DEX
    member is enumerated in archive order; for a raw DEX the single file is
    one occurrence. file_id is the selected-scope ordinal (0-based), matching
    the native scope numbering.
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


def relation_rows(occurrences, relation, include_key=True):
    """Project a relation across occurrences.

    `include_key=False` drops the occurrence key column (file_id, and
    string_pool_id for strings) so that two identical occurrences produce
    byte-identical rows. That is the projection used to exercise exact
    duplicate preservation across occurrences; the key columns are always
    compared separately with include_key=True.
    """
    rows = []
    for occurrence in occurrences:
        if relation == "dex_files_header":
            rows.append(occurrence.header_row())
        elif relation == "dex_files_identity":
            rows.append(occurrence.identity_row())
        elif relation == "strings":
            for row in occurrence.string_rows():
                if not include_key:
                    row = {k: v for k, v in row.items() if k not in ("string_pool_id",)}
                rows.append(row)
        elif relation == "types":
            for row in occurrence.type_rows():
                if not include_key:
                    row = {k: v for k, v in row.items() if k != "file_id"}
                rows.append(row)
        elif relation == "classes":
            for row in occurrence.class_rows():
                if not include_key:
                    row = {k: v for k, v in row.items() if k != "file_id"}
                rows.append(row)
        elif relation == "class_interfaces":
            for row in occurrence.interface_rows():
                if not include_key:
                    row = {k: v for k, v in row.items() if k != "file_id"}
                rows.append(row)
        else:
            raise ValueError("unknown relation: " + relation)
    return rows
