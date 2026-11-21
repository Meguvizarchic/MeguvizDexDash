#!/usr/bin/env python3
"""Unit and boundary tests for MDD-062 AuditDataProvider (`python -O` safe)."""
from __future__ import annotations

import hashlib
import json
import re
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import audit_data_provider as mod  # noqa: E402
import native_session as ns  # noqa: E402

CASES_PATH = ROOT / "conformance/hostlab/gate-reuse-cases.json"


def _encode_const_string(reg: int, sidx: int) -> bytes:
    if sidx <= 0xFFFF:
        return struct.pack("<HH", 0x1A | ((reg & 0xFF) << 8), sidx)
    return struct.pack("<HI", 0x1B | ((reg & 0xFF) << 8), sidx)


def _encode_move_obj(dst: int, src: int) -> bytes:
    return struct.pack("<H", 0x07 | ((dst & 0xF) << 8) | ((src & 0xF) << 12))


def _encode_iput_obj(val_reg: int, obj_reg: int, fidx: int) -> bytes:
    return struct.pack("<HH", 0x5B | ((val_reg & 0xF) << 8) | ((obj_reg & 0xF) << 12), fidx)


def _encode_return_void() -> bytes:
    return struct.pack("<H", 0x0E)


class _StubSliceReader:
    def __init__(self, slices: dict[tuple[int, int, int], bytes]) -> None:
        self._slices = slices

    def read_insns(self, file_id: int, insns_off: int, insns_size_units: int) -> bytes:
        key = (file_id, insns_off, insns_size_units)
        if key not in self._slices:
            raise KeyError(f"missing slice {key}")
        return self._slices[key]


class _FakeSqlSession:
    """Deterministic SQL responder mirroring exact queries emitted by `audit_data_provider`."""

    def __init__(
        self,
        *,
        files: dict[int, str],
        opened: dict[str, Any],
        coverage: dict[str, Any],
        layer_issues: list[dict[str, Any]],
        strings: list[dict[str, Any]],
        types: list[dict[str, Any]],
        classes: list[dict[str, Any]],
        class_fields: list[dict[str, Any]],
        class_methods: list[dict[str, Any]],
        methods: list[dict[str, Any]],
        code_items: list[dict[str, Any]],
        method_strings: list[dict[str, Any]],
        ann_dirs: list[dict[str, Any]],
        ann_sets: list[dict[str, Any]],
        anns: list[dict[str, Any]],
        ann_elems: list[dict[str, Any]],
        fail_table: str | None = None,
    ) -> None:
        self.files = files
        self.opened = opened
        self._coverage = coverage
        self._layer_issues = layer_issues
        self.strings = strings
        self.types = types
        self.classes = classes
        self.class_fields = class_fields
        self.class_methods = class_methods
        self.methods = methods
        self.code_items = code_items
        self.method_strings = method_strings
        self.ann_dirs = ann_dirs
        self.ann_sets = ann_sets
        self.anns = anns
        self.ann_elems = ann_elems
        self.fail_table = fail_table

    @property
    def coverage(self) -> dict[str, Any]:
        return self._coverage

    @property
    def layer_issues(self) -> list[dict[str, Any]]:
        return self._layer_issues

    def _fail_if(self, table: str) -> None:
        if self.fail_table == table:
            raise ns.EngineIncomplete(f"missing layer for {table}", code="INCOMPLETE_FACTS")

    @staticmethod
    def _parse_in_list(sql: str, pattern: str) -> set[str]:
        m = re.search(pattern, sql)
        if not m:
            return set()
        raw = m.group(1)
        return {item.strip()[1:-1].replace("''", "'") for item in raw.split(",") if item.strip()}

    @staticmethod
    def _parse_in_ints(sql: str, pattern: str) -> set[int]:
        m = re.search(pattern, sql)
        if not m:
            return set()
        return {int(x.strip()) for x in m.group(1).split(",") if x.strip()}

    @staticmethod
    def _like_match(value: str, pattern: str) -> bool:
        regex = "^" + "".join(".*" if ch == "%" else "." if ch == "_" else re.escape(ch) for ch in pattern) + "$"
        return re.match(regex, value) is not None

    def all(self, sql: str, **_bounds: Any) -> list[dict[str, Any]]:
        if "FROM dex_files" in sql:
            return [{"file_id": fid, "string_pool_id": fid, "entry_name": name} for fid, name in self.files.items()]
        if "FROM strings" in sql and "LIMIT 1" in sql:
            self._fail_if("strings")
            return self.strings[:1]
        if "FROM classes" in sql and "LIMIT 1" in sql:
            self._fail_if("classes")
            return self.classes[:1]
        if "FROM code_items" in sql and "LIMIT 1" in sql:
            self._fail_if("code_items")
            return self.code_items[:1]
        if "FROM annotations" in sql and "LIMIT 1" in sql:
            self._fail_if("annotations")
            return self.anns[:1]
        if "FROM method_strings" in sql and "LIMIT 1" in sql:
            self._fail_if("method_strings")
            return self.method_strings[:1]

        if "FROM class_methods WHERE method_descriptor LIKE" in sql:
            m = re.search(r"method_descriptor LIKE '([^']+)'", sql)
            pat = m.group(1)
            return [r for r in self.class_methods if self._like_match(r["method_descriptor"], pat)]

        if "FROM classes WHERE descriptor LIKE" in sql:
            m = re.search(r"descriptor LIKE '([^']+)'", sql)
            prefix = m.group(1).rstrip("%")
            return [r for r in self.classes if r["descriptor"].startswith(prefix)]

        if "FROM class_methods cm WHERE cm.class_descriptor IN" in sql:
            wanted = self._parse_in_list(sql, r"cm\.class_descriptor IN \(([^)]+)\)")
            return [r for r in self.class_methods if r["class_descriptor"] in wanted]

        if "FROM class_methods WHERE class_descriptor IN" in sql:
            wanted = self._parse_in_list(sql, r"class_descriptor IN \(([^)]+)\)")
            return [r for r in self.class_methods if r["class_descriptor"] in wanted]

        if "FROM method_strings ms" in sql:
            m = re.search(r"ms\.value = '([^']+)'", sql)
            val = m.group(1)
            cls_map = {(c["file_id"], c["descriptor"]): c["class_def_idx"] for c in self.classes}
            out = []
            for ms in self.method_strings:
                if ms["value"] == val and (ms["file_id"], ms["method_class"]) in cls_map:
                    out.append(
                        {
                            "file_id": ms["file_id"],
                            "class_def_idx": cls_map[(ms["file_id"], ms["method_class"])],
                            "method_class": ms["method_class"],
                            "method_idx": ms["method_idx"],
                        }
                    )
            out.sort(key=lambda r: (r["file_id"], r["class_def_idx"], r["method_idx"]))
            return out

        if "FROM strings WHERE string_pool_id =" in sql and "AND value =" in sql:
            m = re.search(r"string_pool_id = (\d+) AND value = '([^']+)'", sql)
            spid, val = int(m.group(1)), m.group(2)
            return [r for r in self.strings if r["string_pool_id"] == spid and r["value"] == val]

        if "FROM code_items WHERE file_id =" in sql:
            m = re.search(r"file_id = (\d+) AND method_idx = (\d+)", sql)
            fid, midx = int(m.group(1)), int(m.group(2))
            return [r for r in self.code_items if r["file_id"] == fid and r["method_idx"] == midx]

        if "FROM strings WHERE string_pool_id =" in sql and "string_idx IN" in sql:
            m = re.search(r"string_pool_id = (\d+)", sql)
            spid = int(m.group(1))
            idxs = self._parse_in_ints(sql, r"string_idx IN \(([^)]+)\)")
            return [r for r in self.strings if r["string_pool_id"] == spid and r["string_idx"] in idxs]

        if "FROM classes WHERE descriptor =" in sql:
            m = re.search(r"descriptor = '([^']+)'", sql)
            desc = m.group(1)
            return [r for r in self.classes if r["descriptor"] == desc]

        if "FROM class_fields WHERE file_id =" in sql:
            m = re.search(r"file_id = (\d+) AND class_idx = (\d+)", sql)
            fid, cidx = int(m.group(1)), int(m.group(2))
            return [r for r in self.class_fields if r["file_id"] == fid and r["class_idx"] == cidx]

        if "FROM class_methods cm" in sql and "LEFT JOIN code_items ci" in sql:
            m = re.search(r"cm\.file_id = (\d+) AND cm\.class_idx = (\d+) AND cm\.method_name = '<init>'", sql)
            fid, cidx = int(m.group(1)), int(m.group(2))
            ci_map = {(r["file_id"], r["method_idx"]): r for r in self.code_items}
            out = []
            for cm in self.class_methods:
                if cm["file_id"] == fid and cm["class_idx"] == cidx and cm["method_name"] == "<init>":
                    ci = ci_map.get((fid, cm["method_idx"]), {})
                    out.append(
                        {
                            "method_idx": cm["method_idx"],
                            "descriptor": cm["method_descriptor"],
                            "method_kind": cm["kind"],
                            "registers_size": ci.get("registers_size"),
                            "ins_size": ci.get("ins_size"),
                            "insns_off": ci.get("insns_off"),
                            "insns_size": ci.get("insns_size"),
                        }
                    )
            return out

        if "FROM types WHERE file_id =" in sql:
            m = re.search(r"file_id = (\d+) AND descriptor = '([^']+)'", sql)
            fid, desc = int(m.group(1)), m.group(2)
            return [r for r in self.types if r["file_id"] == fid and r["descriptor"] == desc]

        if "FROM annotation_directory_entries" in sql:
            m = re.search(r"file_id = (\d+) AND class_idx = (\d+)", sql)
            fid, cidx = int(m.group(1)), int(m.group(2))
            return [r for r in self.ann_dirs if r["file_id"] == fid and r["class_idx"] == cidx and r["entry_kind"] == "field" and r["annotation_set_off"] is not None]

        if "FROM annotation_set_entries" in sql:
            m = re.search(r"file_id = (\d+)", sql)
            fid = int(m.group(1))
            offs = self._parse_in_ints(sql, r"annotation_set_off IN \(([^)]+)\)")
            return [r for r in self.ann_sets if r["file_id"] == fid and r["annotation_set_off"] in offs]

        if "FROM annotations WHERE file_id =" in sql:
            m = re.search(r"file_id = (\d+)", sql)
            fid = int(m.group(1))
            offs = self._parse_in_ints(sql, r"annotation_off IN \(([^)]+)\)")
            t_m = re.search(r"type_idx = (\d+)", sql)
            tidx = int(t_m.group(1))
            return [r for r in self.anns if r["file_id"] == fid and r["annotation_off"] in offs and r["type_idx"] == tidx]

        if "FROM annotation_elements" in sql:
            m = re.search(r"file_id = (\d+)", sql)
            fid = int(m.group(1))
            offs = self._parse_in_ints(sql, r"annotation_off IN \(([^)]+)\)")
            return [r for r in self.ann_elems if r["file_id"] == fid and r["annotation_off"] in offs]

        if "FROM class_fields WHERE class_descriptor IN" in sql:
            wanted = self._parse_in_list(sql, r"class_descriptor IN \(([^)]+)\)")
            m_eq = re.search(r"field_descriptor = '([^']+)'", sql)
            m_like = re.search(r"field_descriptor LIKE '([^']+)'", sql)
            eq_desc = m_eq.group(1)
            like_desc = m_like.group(1) if m_like else None
            return [
                r
                for r in self.class_fields
                if r["class_descriptor"] in wanted
                and r["kind"] == "instance"
                and (r["field_descriptor"] == eq_desc or (like_desc is not None and self._like_match(r["field_descriptor"], like_desc)))
            ]

        if "DISTINCT value FROM strings WHERE value IN" in sql:
            wanted = self._parse_in_list(sql, r"value IN \(([^)]+)\)")
            vals = sorted({r["value"] for r in self.strings if r["value"] in wanted})
            return [{"value": v} for v in vals]

        if "DISTINCT descriptor FROM classes WHERE descriptor IN" in sql:
            wanted = self._parse_in_list(sql, r"descriptor IN \(([^)]+)\)")
            descs = sorted({r["descriptor"] for r in self.classes if r["descriptor"] in wanted})
            return [{"descriptor": d} for d in descs]

        raise AssertionError(f"unexpected SQL query in test stub: {sql}")


def _build_synthetic_fixture(
    *,
    mapper_classes: list[str],
    swap_ctor_fields: bool = False,
    include_companion: bool = True,
    fail_table: str | None = None,
    coverage_abandoned: int = 0,
    blocking_issue: bool = False,
) -> tuple[_FakeSqlSession, _StubSliceReader]:
    data_clinit = (
        _encode_const_string(0, 10)  # TAB_DATA
        + _encode_const_string(1, 11)  # element 0: "alpha"
        + _encode_const_string(2, 12)  # element 1: "beta"
        + _encode_return_void()
    )
    item_clinit = (
        _encode_const_string(0, 20)  # TAB_ITEM
        + _encode_const_string(1, 21)  # element 0: "title"
        + _encode_return_void()
    )
    # Constructor params: (I, String, String, SerializationMarker) -> ins=4, regs=5 => first_param_reg=2:
    # param 0 ("I") -> r2, param 1 ("String") -> r3 -> alpha(fidx=100), param 2 ("String") -> r4 -> beta(fidx=101).
    if swap_ctor_fields:
        data_ctor = _encode_iput_obj(3, 0, 101) + _encode_iput_obj(4, 0, 100) + _encode_return_void()
    else:
        data_ctor = _encode_move_obj(1, 3) + _encode_iput_obj(1, 0, 100) + _encode_iput_obj(4, 0, 101) + _encode_return_void()
    item_ctor = _encode_iput_obj(3, 0, 200) + _encode_return_void()

    slices = {
        (0, 1000, len(data_clinit) // 2): data_clinit,
        (0, 2000, len(item_clinit) // 2): item_clinit,
        (0, 3000, len(data_ctor) // 2): data_ctor,
        (0, 4000, len(item_ctor) // 2): item_ctor,
    }
    strings = [
        {"string_pool_id": 0, "string_idx": 10, "value": "org.sample.khome.HomeTabData"},
        {"string_pool_id": 0, "string_idx": 11, "value": "alpha"},
        {"string_pool_id": 0, "string_idx": 12, "value": "beta"},
        {"string_pool_id": 0, "string_idx": 20, "value": "org.sample.khome.HomeTabItemData"},
        {"string_pool_id": 0, "string_idx": 21, "value": "title"},
        {"string_pool_id": 0, "string_idx": 30, "value": "Lorg/sample/khome/HomeState;"},
        {"string_pool_id": 0, "string_idx": 40, "value": "getSerialName"},
        {"string_pool_id": 0, "string_idx": 41, "value": "getElementName"},
        {"string_pool_id": 0, "string_idx": 42, "value": "getElementsCount"},
        {"string_pool_id": 0, "string_idx": 43, "value": "getDescriptor"},
    ]
    classes = [
        {"file_id": 0, "class_def_idx": 0, "class_idx": 1, "descriptor": "Lorg/sample/khome/HomeTabData;", "access_flags": 0x1, "superclass_descriptor": "Ljava/lang/Object;"},
        {"file_id": 0, "class_def_idx": 1, "class_idx": 2, "descriptor": "Lorg/sample/khome/HomeTabData$serializer;", "access_flags": 0x1, "superclass_descriptor": "Ljava/lang/Object;"},
        {"file_id": 0, "class_def_idx": 2, "class_idx": 3, "descriptor": "Lorg/sample/khome/HomeTabData$Companion;", "access_flags": 0x1, "superclass_descriptor": "Ljava/lang/Object;"},
        {"file_id": 0, "class_def_idx": 3, "class_idx": 4, "descriptor": "Lorg/sample/khome/HomeTabItemData;", "access_flags": 0x1, "superclass_descriptor": "Ljava/lang/Object;"},
        {"file_id": 0, "class_def_idx": 4, "class_idx": 5, "descriptor": "Lorg/sample/khome/HomeTabItemData$serializer;", "access_flags": 0x1, "superclass_descriptor": "Ljava/lang/Object;"},
        {"file_id": 0, "class_def_idx": 5, "class_idx": 6, "descriptor": "Lorg/sample/khome/HomeTabItemData$Companion;", "access_flags": 0x1, "superclass_descriptor": "Ljava/lang/Object;"},
        {"file_id": 0, "class_def_idx": 6, "class_idx": 7, "descriptor": "Lorg/sample/khome/vm/HomeFrameViewModel;", "access_flags": 0x1, "superclass_descriptor": "Ljava/lang/Object;"},
        {"file_id": 0, "class_def_idx": 7, "class_idx": 8, "descriptor": "Lorg/sample/khome/HomeState;", "access_flags": 0x1, "superclass_descriptor": "Ljava/lang/Object;"},
        {"file_id": 0, "class_def_idx": 8, "class_idx": 9, "descriptor": "Lorg/sample/intro/relate/a;", "access_flags": 0x1, "superclass_descriptor": "Lorg/sample/ui/base/x;"},
        {"file_id": 0, "class_def_idx": 9, "class_idx": 10, "descriptor": "Lorg/sample/ui/base/x;", "access_flags": 0x401, "superclass_descriptor": "Ljava/lang/Object;"},
        {"file_id": 0, "class_def_idx": 10, "class_idx": 11, "descriptor": "Lorg/sample/home/HomeFragment;", "access_flags": 0x1, "superclass_descriptor": "Ljava/lang/Object;"},
        {"file_id": 0, "class_def_idx": 11, "class_idx": 12, "descriptor": "Lorg/sample/home/BaseHomeFragment;", "access_flags": 0x401, "superclass_descriptor": "Ljava/lang/Object;"},
    ]
    class_methods = [
        {"file_id": 0, "class_idx": 1, "class_descriptor": "Lorg/sample/khome/HomeTabData;", "method_idx": 300, "method_name": "<init>", "method_descriptor": "Lorg/sample/khome/HomeTabData;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V", "kind": "direct", "access_flags": 0x1},
        {"file_id": 0, "class_idx": 2, "class_descriptor": "Lorg/sample/khome/HomeTabData$serializer;", "method_idx": 100, "method_name": "<clinit>", "method_descriptor": "Lorg/sample/khome/HomeTabData$serializer;-><clinit>()V", "kind": "direct", "access_flags": 0x8},
        {"file_id": 0, "class_idx": 4, "class_descriptor": "Lorg/sample/khome/HomeTabItemData;", "method_idx": 400, "method_name": "<init>", "method_descriptor": "Lorg/sample/khome/HomeTabItemData;-><init>(ILjava/lang/String;Ljava/lang/Object;)V", "kind": "direct", "access_flags": 0x1},
        {"file_id": 0, "class_idx": 5, "class_descriptor": "Lorg/sample/khome/HomeTabItemData$serializer;", "method_idx": 200, "method_name": "<clinit>", "method_descriptor": "Lorg/sample/khome/HomeTabItemData$serializer;-><clinit>()V", "kind": "direct", "access_flags": 0x8},
        {"file_id": 0, "class_idx": 9, "class_descriptor": "Lorg/sample/intro/relate/a;", "method_idx": 500, "method_name": "create", "method_descriptor": "Lorg/sample/intro/relate/a;->create(Landroid/content/Context;Landroid/view/LayoutInflater;Landroid/view/ViewGroup;)Landroidx/viewbinding/ViewBinding;", "kind": "virtual", "access_flags": 0x1},
        {"file_id": 0, "class_idx": 9, "class_descriptor": "Lorg/sample/intro/relate/a;", "method_idx": 501, "method_name": "bind", "method_descriptor": "Lorg/sample/intro/relate/a;->bind(Landroidx/viewbinding/ViewBinding;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "kind": "virtual", "access_flags": 0x1},
        {"file_id": 0, "class_idx": 10, "class_descriptor": "Lorg/sample/ui/base/x;", "method_idx": 600, "method_name": "createViewEntry", "method_descriptor": "Lorg/sample/ui/base/x;->createViewEntry(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", "kind": "virtual", "access_flags": 0x401},
        {"file_id": 0, "class_idx": 10, "class_descriptor": "Lorg/sample/ui/base/x;", "method_idx": 601, "method_name": "bindToView", "method_descriptor": "Lorg/sample/ui/base/x;->bindToView(Ljava/lang/Object;Ljava/lang/Object;)V", "kind": "virtual", "access_flags": 0x401},
    ]
    if include_companion:
        class_methods.append(
            {"file_id": 0, "class_idx": 3, "class_descriptor": "Lorg/sample/khome/HomeTabData$Companion;", "method_idx": 700, "method_name": "serializer", "method_descriptor": "Lorg/sample/khome/HomeTabData$Companion;->serializer()Lkotlinx/serialization/KSerializer;", "kind": "virtual", "access_flags": 0x1}
        )
        class_methods.append(
            {"file_id": 0, "class_idx": 6, "class_descriptor": "Lorg/sample/khome/HomeTabItemData$Companion;", "method_idx": 701, "method_name": "serializer", "method_descriptor": "Lorg/sample/khome/HomeTabItemData$Companion;->serializer()Lkotlinx/serialization/KSerializer;", "kind": "virtual", "access_flags": 0x1}
        )

    for idx, mc in enumerate(mapper_classes):
        cidx = 50 + idx
        classes.append({"file_id": 0, "class_def_idx": 20 + idx, "class_idx": cidx, "descriptor": mc, "access_flags": 0x1, "superclass_descriptor": "Ljava/lang/Object;"})
        class_methods.append(
            {
                "file_id": 0,
                "class_idx": cidx,
                "class_descriptor": mc,
                "method_idx": 900 + idx,
                "method_name": "map",
                "method_descriptor": f"{mc}->map(Lorg/sample/proto/v1/ReplyInfo;)Lorg/sample/model/CommentItem;",
                "kind": "direct",
                "access_flags": 0x9,
            }
        )

    class_fields = [
        {"file_id": 0, "class_idx": 1, "class_descriptor": "Lorg/sample/khome/HomeTabData;", "field_idx": 100, "field_name": "alpha", "field_descriptor": "Lorg/sample/khome/HomeTabData;->alpha:Ljava/lang/String;", "kind": "instance"},
        {"file_id": 0, "class_idx": 1, "class_descriptor": "Lorg/sample/khome/HomeTabData;", "field_idx": 101, "field_name": "beta", "field_descriptor": "Lorg/sample/khome/HomeTabData;->beta:Ljava/lang/String;", "kind": "instance"},
        {"file_id": 0, "class_idx": 1, "class_descriptor": "Lorg/sample/khome/HomeTabData;", "field_idx": 102, "field_name": "Companion", "field_descriptor": "Lorg/sample/khome/HomeTabData;->Companion:Lorg/sample/khome/HomeTabData$Companion;", "kind": "static"},
        {"file_id": 0, "class_idx": 4, "class_descriptor": "Lorg/sample/khome/HomeTabItemData;", "field_idx": 200, "field_name": "title", "field_descriptor": "Lorg/sample/khome/HomeTabItemData;->title:Ljava/lang/String;", "kind": "instance"},
        {"file_id": 0, "class_idx": 4, "class_descriptor": "Lorg/sample/khome/HomeTabItemData;", "field_idx": 201, "field_name": "Companion", "field_descriptor": "Lorg/sample/khome/HomeTabItemData;->Companion:Lorg/sample/khome/HomeTabItemData$Companion;", "kind": "static"},
        {"file_id": 0, "class_idx": 8, "class_descriptor": "Lorg/sample/khome/HomeState;", "field_idx": 300, "field_name": "tabData", "field_descriptor": "Lorg/sample/khome/HomeState;->tabData:Lorg/sample/khome/HomeTabData;", "kind": "instance"},
    ]
    methods = [
        {"file_id": 0, "method_idx": 300, "descriptor": "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V"},
        {"file_id": 0, "method_idx": 400, "descriptor": "(ILjava/lang/String;Ljava/lang/Object;)V"},
    ]
    code_items = [
        {"file_id": 0, "method_idx": 100, "registers_size": 3, "ins_size": 0, "insns_off": 1000, "insns_size": len(data_clinit) // 2},
        {"file_id": 0, "method_idx": 200, "registers_size": 2, "ins_size": 0, "insns_off": 2000, "insns_size": len(item_clinit) // 2},
        {"file_id": 0, "method_idx": 300, "registers_size": 5, "ins_size": 4, "insns_off": 3000, "insns_size": len(data_ctor) // 2},
        {"file_id": 0, "method_idx": 400, "registers_size": 4, "ins_size": 3, "insns_off": 4000, "insns_size": len(item_ctor) // 2},
    ]
    method_strings = [
        {"file_id": 0, "method_idx": 100, "method_class": "Lorg/sample/khome/HomeTabData$serializer;", "value": "org.sample.khome.HomeTabData"},
        {"file_id": 0, "method_idx": 200, "method_class": "Lorg/sample/khome/HomeTabItemData$serializer;", "value": "org.sample.khome.HomeTabItemData"},
    ]
    types = [{"file_id": 0, "type_idx": 1, "descriptor": "Ldalvik/annotation/Signature;"}]
    ann_dirs = [{"file_id": 0, "class_idx": 7, "entry_kind": "field", "entry_idx": 900, "annotation_set_off": 5000}]
    ann_sets = [{"file_id": 0, "annotation_set_off": 5000, "annotation_off": 6000, "ordinal": 0}]
    anns = [{"file_id": 0, "annotation_off": 6000, "type_idx": 1}]
    ann_elems = [{"file_id": 0, "annotation_off": 6000, "depth": 1, "ordinal": 0, "value_kind": "string", "value_index": 30}]

    issues = [{"layer": "annotations", "reason": "truncated", "blocking": True}] if blocking_issue else []
    sess = _FakeSqlSession(
        files={0: "classes.dex"},
        opened={"layers": list(mod.REQUIRED_GATE_LAYERS)},
        coverage={"abandoned": coverage_abandoned},
        layer_issues=issues,
        strings=strings,
        types=types,
        classes=classes,
        class_fields=class_fields,
        class_methods=class_methods,
        methods=methods,
        code_items=code_items,
        method_strings=method_strings,
        ann_dirs=ann_dirs,
        ann_sets=ann_sets,
        anns=anns,
        ann_elems=ann_elems,
        fail_table=fail_table,
    )
    return sess, _StubSliceReader(slices)


class AuditDataProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cases_doc = json.loads(CASES_PATH.read_text(encoding="utf-8"))
        self.targets = mod.targets_from_neutral_spec(self.cases_doc["neutral_domain"])
        self.config = mod.GateConfig(mode="mdd_fact_reuse")

    def test_default_rollback_config_and_refusal_of_silent_mixing(self) -> None:
        default_cfg = mod.GateConfig()
        self.assertEqual(default_cfg.mode, "legacy_independent")
        self.assertFalse(default_cfg.allow_mid_run_fallback)
        with self.assertRaises(ValueError):
            mod.GateConfig(mode="mdd_fact_reuse", allow_mid_run_fallback=True)
        with self.assertRaises(mod.AuditDataProviderError):
            mod.run_audit_gates(ROOT / "tests/fixtures/generated/multidex-deflated.apk", config=default_cfg, tools_dir=None)

    def test_intake_covered_drift_and_multi_owner_fail_closed(self) -> None:
        sess_ok, _ = _build_synthetic_fixture(mapper_classes=["Lorg/sample/source/v1/a;"])
        ok_res = mod.run_intake_from_session(sess_ok, self.targets, self.config)
        self.assertEqual(ok_res["exit_code"], 0)
        self.assertTrue(ok_res["mapper_ok"])
        self.assertTrue(ok_res["relate_ok"])
        self.assertTrue(ok_res["gemini_ok"])
        self.assertFalse(ok_res["multi_owner_warning"])

        sess_drift, _ = _build_synthetic_fixture(mapper_classes=["Lorg/sample/source/v1/OutOfAlphabet;"])
        drift_res = mod.run_intake_from_session(sess_drift, self.targets, self.config)
        self.assertEqual(drift_res["exit_code"], 1)
        self.assertFalse(drift_res["mapper_ok"])

        sess_multi, _ = _build_synthetic_fixture(mapper_classes=["Lorg/sample/source/v1/a;", "Lorg/sample/source/v1/b;"])
        multi_res = mod.run_intake_from_session(sess_multi, self.targets, self.config)
        self.assertEqual(multi_res["exit_code"], 0)
        self.assertTrue(multi_res["mapper_ok"])
        self.assertTrue(multi_res["multi_owner_warning"])

    def test_home_order_ok_2hop_reach_companion_and_mismatch(self) -> None:
        sess_ok, sr_ok = _build_synthetic_fixture(mapper_classes=["Lorg/sample/source/v1/a;"])
        home_ok = mod.run_home_from_session(sess_ok, sr_ok, self.targets, self.config)
        self.assertTrue(home_ok["data.order"].startswith("order-ok "))
        self.assertTrue(home_ok["item.order"].startswith("order-ok "))
        self.assertEqual(home_ok["vm.reach"], "sigs=1 direct=False via_state=True")
        self.assertTrue(all(home_ok["kx." + k] for k in mod.KX_ACCESSORS))
        self.assertTrue(home_ok["cls.HomeFragment"])
        self.assertTrue(home_ok["cls.BaseHomeFragment"])
        self.assertFalse(home_ok["cls.MediatorFragment"])
        self.assertNotEqual(home_ok["data.companion"], "MISSING")

        sess_bad, sr_bad = _build_synthetic_fixture(
            mapper_classes=["Lorg/sample/source/v1/a;"],
            swap_ctor_fields=True,
            include_companion=False,
        )
        home_bad = mod.run_home_from_session(sess_bad, sr_bad, self.targets, self.config)
        self.assertTrue(home_bad["data.order"].startswith("ORDER-MISMATCH "))
        self.assertEqual(home_bad["data.companion"], "MISSING")

    def test_missing_layer_or_incomplete_coverage_refused_never_empty_hit(self) -> None:
        sess_missing_ann, sr = _build_synthetic_fixture(mapper_classes=["Lorg/sample/source/v1/a;"], fail_table="annotations")
        with self.assertRaises(mod.AuditDataProviderError) as ctx1:
            mod.run_home_from_session(sess_missing_ann, sr, self.targets, self.config)
        self.assertEqual(ctx1.exception.code, "INCOMPLETE_FACTS")

        sess_abandoned, sr2 = _build_synthetic_fixture(mapper_classes=["Lorg/sample/source/v1/a;"], coverage_abandoned=1)
        with self.assertRaises(mod.AuditDataProviderError) as ctx2:
            mod.run_intake_from_session(sess_abandoned, self.targets, self.config)
        self.assertEqual(ctx2.exception.code, "INCOMPLETE_FACTS")

        sess_blocked, sr3 = _build_synthetic_fixture(mapper_classes=["Lorg/sample/source/v1/a;"], blocking_issue=True)
        with self.assertRaises(mod.AuditDataProviderError) as ctx3:
            mod.run_home_from_session(sess_blocked, sr3, self.targets, self.config)
        self.assertEqual(ctx3.exception.code, "INCOMPLETE_FACTS")

        sess_missing_declared, sr4 = _build_synthetic_fixture(mapper_classes=["Lorg/sample/source/v1/a;"])
        sess_missing_declared.opened = {"layers": ["inventory", "metadata"]}
        with self.assertRaises(mod.AuditDataProviderError) as ctx4:
            mod.run_intake_from_session(sess_missing_declared, self.targets, self.config)
        self.assertEqual(ctx4.exception.code, "INCOMPLETE_FACTS")

    def test_compare_gate_outputs_normalizes_expected_features_and_detects_drift(self) -> None:
        base_intake = {
            "gate": "intake",
            "mapper_owners": ["org.sample.source.v1.a"],
            "mapper_ok": True,
            "relate_game_owners": ["org.sample.intro.relate.a"],
            "relate_ok": True,
            "gemini_bases": ["org.sample.ui.base.a"],
            "gemini_ok": True,
            "multi_owner_warning": False,
            "exit_code": 0,
        }
        base_home = {
            "apk": "synthetic.apk",
            "data.owner": "Lorg/sample/khome/HomeTabData;",
            "data.order": "order-ok fields=2 elements=2 unproven=[]",
            "item.order": "order-ok fields=1 elements=1 unproven=[]",
            "vm.reach": "sigs=1 direct=False via_state=True",
            "kx.getSerialName": True,
        }
        legacy = {
            "intake": dict(base_intake),
            "home": dict(base_home),
            "intake_exit_code": 0,
            "home_exit_code": 0,
        }
        reuse = {
            "intake": {**base_intake, "expected_features": ["f1", "f2"]},
            "home": dict(base_home),
            "intake_exit_code": 0,
            "home_exit_code": 0,
        }
        same = mod.compare_gate_outputs(legacy, reuse)
        self.assertTrue(same["equivalent"])
        self.assertTrue(same["exit_code_match"])
        self.assertEqual(same["legacy_verdict_sha256"], same["reuse_verdict_sha256"])
        self.assertEqual(same["mismatches"], [])

        drifted = {
            **reuse,
            "home": {**base_home, "vm.reach": "vm-missing"},
        }
        diff = mod.compare_gate_outputs(legacy, drifted)
        self.assertFalse(diff["equivalent"])
        self.assertIn("home.vm.reach mismatch", diff["mismatches"])

    def test_legacy_stdout_parsers_cover_complete_and_missing_states(self) -> None:
        intake_stdout = "\n".join([
            "== alphabet drift ==",
            "    mapper owners      : ['org.sample.v1.a', 'org.sample.v1.b']  covered=True",
            "    relate game owners : -  covered=False",
            "    gemini bases       : -  covered=n/a",
            "    WARNING: mapper has multiple owners — treat as MISSING (fail-closed)",
        ])
        parsed_in = mod.parse_legacy_intake_stdout(intake_stdout, 1)
        self.assertEqual(parsed_in["mapper_owners"], ["org.sample.v1.a", "org.sample.v1.b"])
        self.assertTrue(parsed_in["mapper_ok"])
        self.assertEqual(parsed_in["relate_game_owners"], [])
        self.assertFalse(parsed_in["relate_ok"])
        self.assertEqual(parsed_in["gemini_ok"], "n/a")
        self.assertTrue(parsed_in["multi_owner_warning"])
        self.assertEqual(parsed_in["exit_code"], 1)

        with self.assertRaises(mod.AuditDataProviderError):
            mod.parse_legacy_intake_stdout("== incomplete ==", 1)

        home_stdout = "\n".join([
            "======== demo.apk",
            "  data.owner: None",
            "  data.elements: []",
            "  data.companion: MISSING",
            "  vm.reach: vm-missing",
            "  kx.getSerialName: False",
            "  cls.HomeFragment: True",
        ])
        parsed_hm = mod.parse_legacy_home_stdout(home_stdout, "demo.apk")
        self.assertIsNone(parsed_hm["data.owner"])
        self.assertEqual(parsed_hm["data.elements"], [])
        self.assertEqual(parsed_hm["data.companion"], "MISSING")
        self.assertFalse(parsed_hm["kx.getSerialName"])
        self.assertTrue(parsed_hm["cls.HomeFragment"])

    def test_zip_archive_slice_reader_enforces_sha_and_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            apk_path = Path(tmp_str) / "sample.apk"
            payload = b"ABCD\x0e\x00WXYZ"
            with zipfile.ZipFile(apk_path, "w") as zf:
                zf.writestr("classes.dex", payload)
            good_sha = hashlib.sha256(apk_path.read_bytes()).hexdigest()

            reader = mod.ZipArchiveSliceReader(apk_path, {0: "classes.dex"}, good_sha)
            try:
                self.assertEqual(reader.read_insns(0, 4, 1), b"\x0e\x00")
                with self.assertRaises(mod.AuditDataProviderError) as oob:
                    reader.read_insns(0, 8, 2)
                self.assertEqual(oob.exception.code, "CACHE_CORRUPT")
            finally:
                reader.close()

            bad_reader = mod.ZipArchiveSliceReader(apk_path, {0: "classes.dex"}, "0" * 64)
            try:
                with self.assertRaises(mod.AuditDataProviderError) as changed:
                    bad_reader.read_insns(0, 4, 1)
                self.assertEqual(changed.exception.code, "SOURCE_CHANGED")
            finally:
                bad_reader.close()

    def test_resolve_reference_tools_dir_and_pinned_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            root_dir = Path(tmp_str)
            analysis_dir = root_dir / "tools" / "hostlab" / "analysis"
            analysis_dir.mkdir(parents=True)
            intake_py = analysis_dir / "run_intake.py"
            home_py = analysis_dir / "home_frame_audit.py"
            drift_py = analysis_dir / "obfuscated_owner_drift.py"
            intake_py.write_text("EXPECTED_FEATURES = ['f1']\ndef print_identity(x):\n    if x == 'org.sample.app':\n        pass\n", encoding="utf-8")
            home_py.write_text(
                "TAB_DATA = 'a'\nTAB_ITEM = 'b'\nVM = 'Lc;'\nfor marker in ('Lx/M;',):\n    pass\n",
                encoding="utf-8",
            )
            drift_py.write_text(
                "REPLY_INFO = 'R'\nCOMMENT_ITEM = 'C'\nMAPPER_PACKAGE = 'm'\nRELATE_GAME_PACKAGE = 'r'\nGEMINI_UI_PACKAGE = 'g'\n",
                encoding="utf-8",
            )

            resolved = mod.resolve_reference_tools_dir(root_dir)
            self.assertEqual(resolved, (root_dir / "tools" / "hostlab").resolve())

            matching = {
                "intake": hashlib.sha256(intake_py.read_bytes()).hexdigest(),
                "home": hashlib.sha256(home_py.read_bytes()).hexdigest(),
            }
            with mock.patch.object(mod.surface_gate, "pinned_digests", return_value=matching):
                targets = mod.load_targets_from_reference(root_dir)
                self.assertEqual(targets.expected_features, ("f1",))
                self.assertEqual(targets.marker_classes, ("Lx/M;",))

            with mock.patch.object(mod.surface_gate, "pinned_digests", return_value={**matching, "home": "f" * 64}):
                with self.assertRaises(mod.AuditDataProviderError) as err:
                    mod.load_targets_from_reference(root_dir)
                self.assertEqual(err.exception.code, "SOURCE_CHANGED")

    def test_descriptor_parsers_accept_full_hostlab_and_bare_signatures(self) -> None:
        params, ret = mod.parse_method_descriptor(
            "Lcom/example/RelateGameComponent$bind$11$1$1;-><init>(Lorg/sample/widget/ForegroundConstraintLayout;Lkotlin/coroutines/Continuation;)V"
        )
        self.assertEqual(
            params,
            [
                "Lorg/sample/widget/ForegroundConstraintLayout;",
                "Lkotlin/coroutines/Continuation;",
            ],
        )
        self.assertEqual(ret, "V")
        self.assertEqual(mod.parse_method_descriptor("([Ljava/lang/String;I)Z"), (["[Ljava/lang/String;", "I"], "Z"))
        self.assertEqual(
            mod.extract_field_type_descriptor("Lorg/sample/HomeState;->tabData:Lorg/sample/HomeTabData;"),
            "Lorg/sample/HomeTabData;",
        )
        self.assertEqual(mod.extract_field_type_descriptor("Ljava/lang/String;"), "Ljava/lang/String;")

        for bad_method in ("", "->foo()V", "Lcls;->foo", "Lcls;->foo(I)", "(I)", "bar(I)V"):
            with self.assertRaises(mod.AuditDataProviderError):
                mod.parse_method_descriptor(bad_method)

        for bad_field in ("", "->foo:I", "Lcls;->foo", "Lcls;->:I", "Lcls;->foo:"):
            with self.assertRaises(mod.AuditDataProviderError):
                mod.extract_field_type_descriptor(bad_field)


if __name__ == "__main__":
    unittest.main()
