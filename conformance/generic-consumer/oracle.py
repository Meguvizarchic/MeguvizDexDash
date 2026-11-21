#!/usr/bin/env python3
"""Independent pure-Python DEX/APK reader for MDD-065 generic consumer conformance.

Standard library only; never imports `mdd` or any Rust/crate code.
Independently parses ZIP containers (`classes*.dex` in archive order), DEX headers,
string/type/proto/method ID pools, class_defs, class_data_item, and code_item
instruction streams (`const-string` and `invoke-*` call sites), computing raw bytecode
facts and opcodes directly from bytes.
"""
from __future__ import annotations

import hashlib
import struct
import zipfile
from pathlib import Path
from typing import Any

# Standard Dalvik bytecode instruction width in 16-bit code units for every opcode 0x00..0xFF.
# Payloads (0x0100 packed-switch, 0x0200 sparse-switch, 0x0300 fill-array-data) are handled
# dynamically when full 16-bit opcode word matches.
_WIDTH_BY_OPCODE = [1] * 256
for _op in (0x01, 0x04, 0x07, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x1D, 0x1E, 0x21, 0x27, 0x28, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF):
    _WIDTH_BY_OPCODE[_op] = 1
for _op in (0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1A, 0x1C, 0x1F, 0x20, 0x22, 0x23, 0x29, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0xFE, 0xFF):
    _WIDTH_BY_OPCODE[_op] = 2
for _op in range(0x90, 0xB0):
    _WIDTH_BY_OPCODE[_op] = 2
for _op in range(0xD0, 0xE3):
    _WIDTH_BY_OPCODE[_op] = 2
for _op in (0x03, 0x06, 0x09, 0x14, 0x17, 0x1B, 0x24, 0x25, 0x26, 0x2A, 0x2B, 0x2C, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78, 0xFC, 0xFD):
    _WIDTH_BY_OPCODE[_op] = 3
_WIDTH_BY_OPCODE[0xFA] = 4  # invoke-polymorphic
_WIDTH_BY_OPCODE[0xFB] = 4  # invoke-polymorphic/range
_WIDTH_BY_OPCODE[0x18] = 5  # const-wide

_INVOKE_KIND_OPS = {0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}


def _uleb128(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, offset
        shift += 7


def _decode_mutf8_item(data: bytes, offset: int) -> tuple[str, bytes, int]:
    _utf16_len, pos = _uleb128(data, offset)
    end = data.index(0, pos)
    raw = data[pos:end]
    units: list[int] = []
    i = 0
    while i < len(raw):
        b0 = raw[i]
        if b0 < 0x80:
            units.append(b0)
            i += 1
        elif (b0 & 0xE0) == 0xC0:
            b1 = raw[i + 1]
            units.append(((b0 & 0x1F) << 6) | (b1 & 0x3F))
            i += 2
        else:
            b1, b2 = raw[i + 1], raw[i + 2]
            units.append(((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F))
            i += 3
    text = struct.pack(f"<{len(units)}H", *units).decode("utf-16-le", "surrogatepass") if units else ""
    return text, raw, end + 1


def _top_level_dex_name(name: str) -> bool:
    return "/" not in name and name.startswith("classes") and name.endswith(".dex")


def parse_dex(raw: bytes) -> dict[str, Any]:
    """Parse one DEX buffer into headers, strings, methods, classes, and code calls/strings."""
    if len(raw) < 112 or raw[:4] != b"dex\n" or raw[7:8] != b"\x00":
        raise ValueError("invalid DEX magic")
    version = raw[4:7].decode("ascii")
    checksum = struct.unpack_from("<I", raw, 8)[0]
    sig_hex = raw[12:32].hex()
    file_size, _hdr_size, endian_tag = struct.unpack_from("<III", raw, 32)
    if endian_tag != 0x12345678 or file_size != len(raw):
        raise ValueError("invalid DEX size or endianness")
    (
        string_ids_size,
        string_ids_off,
        type_ids_size,
        type_ids_off,
        proto_ids_size,
        proto_ids_off,
        _field_ids_size,
        _field_ids_off,
        method_ids_size,
        method_ids_off,
        class_defs_size,
        class_defs_off,
    ) = struct.unpack_from("<12I", raw, 56)

    strings: list[str] = []
    strings_raw: list[bytes] = []
    for i in range(string_ids_size):
        str_off = struct.unpack_from("<I", raw, string_ids_off + i * 4)[0]
        text, rbytes, _ = _decode_mutf8_item(raw, str_off)
        strings.append(text)
        strings_raw.append(rbytes)

    types: list[str] = [
        strings[struct.unpack_from("<I", raw, type_ids_off + i * 4)[0]]
        for i in range(type_ids_size)
    ]

    protos: list[str] = []
    for i in range(proto_ids_size):
        _shorty_idx, ret_idx, params_off = struct.unpack_from("<III", raw, proto_ids_off + i * 12)
        if params_off == 0:
            param_str = ""
        else:
            pcount = struct.unpack_from("<I", raw, params_off)[0]
            pidxs = struct.unpack_from(f"<{pcount}H", raw, params_off + 4)
            param_str = "".join(types[p] for p in pidxs)
        protos.append(f"({param_str}){types[ret_idx]}")

    methods: list[dict[str, Any]] = []
    for i in range(method_ids_size):
        cls_idx, proto_idx, name_idx = struct.unpack_from("<HHI", raw, method_ids_off + i * 8)
        cls_desc = types[cls_idx]
        name = strings[name_idx]
        proto_desc = protos[proto_idx]
        methods.append(
            {
                "method_idx": i,
                "class_descriptor": cls_desc,
                "name": name,
                "proto_descriptor": proto_desc,
                "descriptor": f"{cls_desc}->{name}{proto_desc}",
            }
        )

    classes: list[dict[str, Any]] = []
    defined_methods: list[dict[str, Any]] = []
    calls_by_method: dict[int, list[str]] = {}
    strings_by_method: dict[int, list[str]] = {}
    code_by_method: dict[int, dict[str, Any]] = {}

    for _cdef_idx in range(class_defs_size):
        base = class_defs_off + _cdef_idx * 32
        cls_idx, access_flags, super_idx, _ifaces_off, _src_idx, _ann_off, class_data_off, _static_off = struct.unpack_from("<8I", raw, base)
        super_desc = None if super_idx == 0xFFFFFFFF else types[super_idx]
        classes.append(
            {
                "descriptor": types[cls_idx],
                "access_flags": access_flags,
                "superclass_descriptor": super_desc,
            }
        )
        if class_data_off == 0:
            continue
        pos = class_data_off
        sf_count, pos = _uleb128(raw, pos)
        if_count, pos = _uleb128(raw, pos)
        dm_count, pos = _uleb128(raw, pos)
        vm_count, pos = _uleb128(raw, pos)
        for _ in range(sf_count + if_count):
            _, pos = _uleb128(raw, pos)
            _, pos = _uleb128(raw, pos)

        for kind, count in (("direct", dm_count), ("virtual", vm_count)):
            midx = 0
            for _ in range(count):
                delta, pos = _uleb128(raw, pos)
                midx += delta
                m_access, pos = _uleb128(raw, pos)
                code_off, pos = _uleb128(raw, pos)
                m_info = methods[midx]
                insns_size = None
                if code_off != 0:
                    insns_size = struct.unpack_from("<I", raw, code_off + 12)[0]
                    insns_off = code_off + 16
                    units = list(struct.unpack_from(f"<{insns_size}H", raw, insns_off))
                    op_bytes: list[int] = []
                    m_calls: list[str] = []
                    m_strs: list[str] = []
                    pc = 0
                    while pc < len(units):
                        word = units[pc]
                        if word == 0x0100 and pc + 1 < len(units):
                            pc += 4 + units[pc + 1] * 2
                            continue
                        if word == 0x0200 and pc + 1 < len(units):
                            pc += 2 + units[pc + 1] * 4
                            continue
                        if word == 0x0300 and pc + 3 < len(units):
                            elem_width = units[pc + 1]
                            elem_cnt = units[pc + 2] | (units[pc + 3] << 16)
                            pc += 4 + (elem_cnt * elem_width + 1) // 2
                            continue
                        op = word & 0xFF
                        op_bytes.append(op)
                        if op == 0x1A and pc + 1 < len(units):
                            m_strs.append(strings[units[pc + 1]])
                        elif op == 0x1B and pc + 2 < len(units):
                            s_idx = units[pc + 1] | (units[pc + 2] << 16)
                            m_strs.append(strings[s_idx])
                        elif op in _INVOKE_KIND_OPS and pc + 1 < len(units):
                            m_calls.append(methods[units[pc + 1]]["descriptor"])
                        pc += _WIDTH_BY_OPCODE[op]
                    opcode_hex = bytes(op_bytes).hex()
                    calls_by_method[midx] = m_calls
                    strings_by_method[midx] = m_strs
                    code_by_method[midx] = {
                        "code_off": code_off,
                        "insns_off": insns_off,
                        "insns_size": insns_size,
                        "opcode_count": len(op_bytes),
                        "opcode_hex": opcode_hex,
                        "opcode_sha256": hashlib.sha256(bytes(op_bytes)).hexdigest(),
                    }
                defined_methods.append(
                    {
                        "class_descriptor": m_info["class_descriptor"],
                        "method_idx": midx,
                        "method_name": m_info["name"],
                        "method_descriptor": m_info["descriptor"],
                        "kind": kind,
                        "access_flags": m_access,
                        "code_off": None if code_off == 0 else code_off,
                        "insns_size": insns_size,
                    }
                )

    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "dex_version": version,
        "checksum": checksum,
        "signature_sha1": sig_hex,
        "byte_len": len(raw),
        "strings": strings,
        "strings_raw": strings_raw,
        "classes": classes,
        "defined_methods": defined_methods,
        "calls_by_method": calls_by_method,
        "strings_by_method": strings_by_method,
        "code_by_method": code_by_method,
    }


def read_inputs(paths: list[Path], *, class_prefix: str | None = None) -> dict[str, Any]:
    """Read raw DEX files or APK top-level classes*.dex in archive order."""
    dex_blobs: list[tuple[str, bytes]] = []
    for path in paths:
        raw = path.read_bytes()
        if raw[:4] == b"dex\n":
            dex_blobs.append((path.name, raw))
        elif zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, "r") as zf:
                for info in zf.infolist():
                    if not info.is_dir() and _top_level_dex_name(info.filename):
                        dex_blobs.append((info.filename, zf.read(info.filename)))
        else:
            raise ValueError(f"unsupported input format: {path}")

    parsed_occurrences = [parse_dex(blob) for _, blob in dex_blobs]
    classes = []
    defined_methods = []
    for fid, parsed in enumerate(parsed_occurrences):
        for cls in parsed["classes"]:
            if not class_prefix or cls["descriptor"].startswith(class_prefix):
                classes.append({"occurrence_ordinal": fid, **cls})
        for dm in parsed["defined_methods"]:
            if not class_prefix or dm["class_descriptor"].startswith(class_prefix):
                defined_methods.append({"occurrence_ordinal": fid, **dm})

    classes.sort(key=lambda item: (item["occurrence_ordinal"], item["descriptor"]))
    defined_methods.sort(key=lambda item: (item["occurrence_ordinal"], item["method_idx"]))

    return {
        "occurrence_count": len(parsed_occurrences),
        "distinct_content_count": len({p["sha256"] for p in parsed_occurrences}),
        "occurrences": parsed_occurrences,
        "classes": classes,
        "defined_methods": defined_methods,
    }
