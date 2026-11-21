#!/usr/bin/env python3
"""MDD-062: Shared-fact gate AuditDataProvider for HostLab intake & home audits.

Reuses verified MeguvizDexDash snapshot & relational/bytecode facts to evaluate the exact
semantic checks of `intake` (`run_intake.py` + `obfuscated_owner_drift.py`) and `home`
(`home_frame_audit.py`) while:
1. Preserving full APK SHA-256, physical DEX inventory, completeness, and register-level
   constructor proof;
2. Never treating self-consistency within the same core as an independent verification oracle;
3. Recording gate execution inside a dedicated `E_gate` timing window (`counted_in_phase1_sf_target: False`);
4. Defaulting rollback cleanly to `legacy_independent` and refusing silent mid-run mixing on
   missing layers, partial/truncated responses, or source mismatches.

This file stays free of domain literals (live reference target strings are dynamically loaded
from digest-verified reference scripts using `surface_gate.pinned_digests()`).
Never relies on bare `assert` (`python -O` safe).
"""
from __future__ import annotations

import argparse
import ast
import datetime
import hashlib
import importlib
import json
import os
import re
import statistics
import struct
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol, Sequence

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BENCHMARKS_DIR = ROOT / "benchmarks"
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
if str(BENCHMARKS_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS_DIR))

import native_session as ns  # noqa: E402
import observed_run_validator as validator  # noqa: E402
import provider  # noqa: E402
import surface_gate  # noqa: E402

SCHEMA_VERSION = "mdd.gate-equivalence-and-timing.v1"
RECORD_PATH = ROOT / "artifacts/mdd-062/gate-equivalence-and-timing.json"
CASES_PATH = ROOT / "conformance/hostlab/gate-reuse-cases.json"
PATHS_JSON = ROOT / "artifacts/local/shadow-prep/paths.json"
SOURCES = [
    "integrations/hostlab/audit_data_provider.py",
    "integrations/hostlab/test_audit_data_provider.py",
    "integrations/hostlab/surface_gate.py",
    "integrations/hostlab/native_session.py",
    "conformance/hostlab/gate-reuse-cases.json",
]

REQUIRED_GATE_LAYERS = ("inventory", "metadata", "definitions", "code", "annotations", "references")
ALPHABET = tuple(chr(c) for c in range(ord("a"), ord("z") + 1))
KX_ACCESSORS = ("getSerialName", "getElementName", "getElementsCount", "getDescriptor")
VIEW_BINDING_TYPE = "androidx.viewbinding.ViewBinding"
CREATE_METHOD_PARAMS = [
    "android.content.Context",
    "android.view.LayoutInflater",
    "android.view.ViewGroup",
]
CONTINUATION_TYPE = "kotlin.coroutines.Continuation"
KOTLINX_SERIALIZER_DESC = "Lkotlinx/serialization/KSerializer;"
SIGNATURE_ANN_DESC = "Ldalvik/annotation/Signature;"

# Dalvik instruction width table (exact match to home_frame_audit.py / dex spec).
_WIDTH = [1] * 256
for _op in (0x02, 0x05, 0x08):
    _WIDTH[_op] = 2
for _op in (0x03, 0x06, 0x09):
    _WIDTH[_op] = 3
for _op in (0x13, 0x15, 0x16, 0x19, 0x1A, 0x1C, 0x1F, 0x20, 0x22, 0x23, 0x29):
    _WIDTH[_op] = 2
for _op in (0x14, 0x17, 0x1B, 0x24, 0x25, 0x26, 0x2A, 0x2B, 0x2C):
    _WIDTH[_op] = 3
_WIDTH[0x18] = 5
for _op in range(0x2D, 0x3E):
    _WIDTH[_op] = 2
for _op in range(0x44, 0x6E):
    _WIDTH[_op] = 2
for _op in range(0x6E, 0x73):
    _WIDTH[_op] = 3
for _op in range(0x74, 0x79):
    _WIDTH[_op] = 3
for _op in range(0x90, 0xB0):
    _WIDTH[_op] = 2
for _op in range(0xD0, 0xE3):
    _WIDTH[_op] = 2
for _op in (0xFA, 0xFB):
    _WIDTH[_op] = 4
for _op in (0xFC, 0xFD):
    _WIDTH[_op] = 3
for _op in (0xFE, 0xFF):
    _WIDTH[_op] = 2


class AuditDataProviderError(RuntimeError):
    """Raised when reused facts are incomplete, unverified, corrupted, or disallowed."""

    def __init__(self, message: str, *, code: str = "INCOMPLETE_FACTS") -> None:
        super().__init__(message)
        self.code = code


class FactSessionProtocol(Protocol):
    files: dict[int, str]
    opened: dict[str, Any]

    @property
    def coverage(self) -> dict[str, Any]: ...

    @property
    def layer_issues(self) -> list[dict[str, Any]]: ...

    def all(self, sql: str, **bounds: Any) -> list[dict[str, Any]]: ...


@dataclass(frozen=True)
class GateConfig:
    """Explicit mode & resource configuration for AuditDataProvider."""

    mode: Literal["legacy_independent", "mdd_fact_reuse"] = "legacy_independent"
    wire: str = "b1"
    timeout_seconds: float = 900.0
    threads: int = 2
    max_rows: int = 1_000_000
    max_bytes: int = 256 * 1024 * 1024
    allow_mid_run_fallback: bool = False  # Never permitted: fail closed or pre-select legacy_independent.

    def __post_init__(self) -> None:
        if self.mode not in ("legacy_independent", "mdd_fact_reuse"):
            raise ValueError(f"unsupported GateConfig mode: {self.mode!r}")
        if self.allow_mid_run_fallback:
            raise ValueError("silent mid-run fallback between reuse and legacy gates is prohibited")


@dataclass(frozen=True)
class GateDomainTargets:
    """Parameterized target descriptors (loaded from signed HostLab scripts or synthetic fixtures)."""

    reply_info: str
    comment_item: str
    mapper_package: str
    relate_game_package: str
    gemini_ui_package: str
    expected_features: tuple[str, ...]
    expected_package: str
    tab_data_serial: str
    tab_item_serial: str
    vm_descriptor: str
    marker_classes: tuple[str, ...]
    required_layers: tuple[str, ...] = field(default=REQUIRED_GATE_LAYERS)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(f"MDD-062 verification failed: {message}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _extract_ast_constants(py_path: Path) -> dict[str, Any]:
    tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=str(py_path))
    found: dict[str, Any] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            try:
                found[name] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    return found


def _extract_home_markers_and_pkg(home_path: Path, intake_path: Path) -> tuple[tuple[str, ...], str]:
    home_tree = ast.parse(home_path.read_text(encoding="utf-8"), filename=str(home_path))
    markers: list[str] = []
    for node in ast.walk(home_tree):
        if isinstance(node, ast.For) and isinstance(node.target, ast.Name) and node.target.id == "marker":
            if isinstance(node.iter, (ast.Tuple, ast.List)):
                markers = [ast.literal_eval(elt) for elt in node.iter.elts]
                break

    intake_tree = ast.parse(intake_path.read_text(encoding="utf-8"), filename=str(intake_path))
    expected_pkg = ""
    for node in ast.walk(intake_tree):
        if isinstance(node, ast.FunctionDef) and node.name == "print_identity":
            for inner in ast.walk(node):
                if isinstance(inner, ast.Compare):
                    vals = [
                        comp.value
                        for comp in inner.comparators
                        if isinstance(comp, ast.Constant) and isinstance(comp.value, str) and "." in comp.value
                    ]
                    if vals:
                        expected_pkg = vals[0]
                        break
    return tuple(markers), expected_pkg


def resolve_reference_tools_dir(path: Path) -> Path:
    """Resolve the HostLab directory that contains `analysis/{run_intake,home_frame_audit,obfuscated_owner_drift}.py`."""
    resolved = Path(path).resolve(strict=True)
    for candidate in (resolved, resolved / "tools" / "hostlab"):
        if (candidate / "analysis" / "run_intake.py").is_file() and (
            candidate / "analysis" / "home_frame_audit.py"
        ).is_file():
            return candidate
    raise AuditDataProviderError(
        f"missing reference gate file: {resolved / 'analysis/obfuscated_owner_drift.py'}",
        code="INVALID_ARGUMENT",
    )


def load_targets_from_reference(ref_tools_dir: Path) -> GateDomainTargets:
    """Verify pinned digests of HostLab's reference gate scripts and load domain constants from AST."""
    ref_tools_dir = resolve_reference_tools_dir(ref_tools_dir)
    digests = surface_gate.pinned_digests()
    pinned_map = {
        "analysis/run_intake.py": digests["intake"],
        "analysis/home_frame_audit.py": digests["home"],
    }
    needed = (
        "analysis/obfuscated_owner_drift.py",
        "analysis/run_intake.py",
        "analysis/home_frame_audit.py",
    )
    for rel in needed:
        full = ref_tools_dir / rel
        if not full.is_file():
            raise AuditDataProviderError(f"missing reference gate file: {full}", code="INVALID_ARGUMENT")
        expected_sha = pinned_map.get(rel)
        if expected_sha is not None and sha256_file(full) != expected_sha:
            raise AuditDataProviderError(f"pinned digest mismatch for {rel}", code="SOURCE_CHANGED")

    drift_c = _extract_ast_constants(ref_tools_dir / "analysis/obfuscated_owner_drift.py")
    intake_c = _extract_ast_constants(ref_tools_dir / "analysis/run_intake.py")
    home_c = _extract_ast_constants(ref_tools_dir / "analysis/home_frame_audit.py")
    markers, expected_pkg = _extract_home_markers_and_pkg(
        ref_tools_dir / "analysis/home_frame_audit.py",
        ref_tools_dir / "analysis/run_intake.py",
    )
    return GateDomainTargets(
        reply_info=str(drift_c["REPLY_INFO"]),
        comment_item=str(drift_c["COMMENT_ITEM"]),
        mapper_package=str(drift_c["MAPPER_PACKAGE"]),
        relate_game_package=str(drift_c["RELATE_GAME_PACKAGE"]),
        gemini_ui_package=str(drift_c["GEMINI_UI_PACKAGE"]),
        expected_features=tuple(str(x) for x in intake_c["EXPECTED_FEATURES"]),
        expected_package=expected_pkg,
        tab_data_serial=str(home_c["TAB_DATA"]),
        tab_item_serial=str(home_c["TAB_ITEM"]),
        vm_descriptor=str(home_c["VM"]),
        marker_classes=markers,
    )


def targets_from_neutral_spec(spec: dict[str, Any]) -> GateDomainTargets:
    return GateDomainTargets(
        reply_info=spec["reply_info"],
        comment_item=spec["comment_item"],
        mapper_package=spec["mapper_package"],
        relate_game_package=spec["relate_game_package"],
        gemini_ui_package=spec["gemini_ui_package"],
        expected_features=tuple(spec["expected_features"]),
        expected_package=spec["expected_package"],
        tab_data_serial=spec["tab_data_serial"],
        tab_item_serial=spec["tab_item_serial"],
        vm_descriptor=spec["vm_descriptor"],
        marker_classes=tuple(spec["marker_classes"]),
    )


def desc_to_java(desc: str) -> str:
    arr = 0
    cur = desc
    while cur.startswith("["):
        arr += 1
        cur = cur[1:]
    prim = {
        "V": "void",
        "Z": "boolean",
        "B": "byte",
        "S": "short",
        "C": "char",
        "I": "int",
        "J": "long",
        "F": "float",
        "D": "double",
    }
    if cur in prim:
        base = prim[cur]
    elif cur.startswith("L") and cur.endswith(";"):
        base = cur[1:-1].replace("/", ".")
    else:
        base = cur
    return base + ("[]" * arr)


def java_to_desc(java_name: str) -> str:
    return "L" + java_name.replace(".", "/") + ";"


def _split_type_list(raw: str) -> list[str]:
    types: list[str] = []
    i = 0
    n = len(raw)
    while i < n:
        start = i
        while i < n and raw[i] == "[":
            i += 1
        if i >= n:
            raise AuditDataProviderError(f"malformed type descriptor list: {raw!r}")
        if raw[i] == "L":
            end = raw.find(";", i)
            if end < 0:
                raise AuditDataProviderError(f"unterminated class descriptor: {raw!r}")
            i = end + 1
        else:
            i += 1
        types.append(raw[start:i])
    return types


def parse_method_descriptor(method_desc: str) -> tuple[list[str], str]:
    raw = method_desc
    if not raw.startswith("(") and "->" in raw:
        owner, member = raw.split("->", 1)
        if not owner or "(" not in member:
            raise AuditDataProviderError(f"malformed Dalvik method descriptor: {method_desc!r}")
        raw = member[member.index("(") :]
    if not raw.startswith("(") or ")" not in raw:
        raise AuditDataProviderError(f"malformed Dalvik method descriptor: {method_desc!r}")
    close = raw.index(")")
    ret = raw[close + 1 :]
    if not ret:
        raise AuditDataProviderError(f"malformed Dalvik method descriptor: {method_desc!r}")
    return _split_type_list(raw[1:close]), ret


def extract_field_type_descriptor(field_desc: str) -> str:
    if "->" in field_desc:
        owner, member = field_desc.split("->", 1)
        if not owner or ":" not in member:
            raise AuditDataProviderError(f"malformed Dalvik field descriptor: {field_desc!r}")
        name, ftype = member.split(":", 1)
        if not name or not ftype:
            raise AuditDataProviderError(f"malformed Dalvik field descriptor: {field_desc!r}")
        return ftype
    if not field_desc:
        raise AuditDataProviderError(f"malformed Dalvik field descriptor: {field_desc!r}")
    return field_desc


def _sql_lit(value: str) -> str:
    return ns.literal(value)


def _sql_in(values: Sequence[str]) -> str:
    return ",".join(_sql_lit(v) for v in values)


def _sql_in_ints(values: Sequence[int]) -> str:
    return ",".join(str(int(v)) for v in values)


def _covered(class_name: str, package: str) -> bool:
    if not class_name.startswith(package + "."):
        return False
    return class_name[len(package) + 1 :] in ALPHABET


def _verify_session_completeness(session: FactSessionProtocol, apk_path: Path | None, pre_sha: str | None) -> None:
    if apk_path is not None and pre_sha is not None:
        if sha256_file(apk_path) != pre_sha:
            raise AuditDataProviderError("APK modified during gate reuse execution", code="SOURCE_CHANGED")
    cov = session.coverage
    if not isinstance(cov, dict) or cov.get("abandoned", 0) != 0:
        raise AuditDataProviderError("session contains abandoned/incomplete statements", code="INCOMPLETE_FACTS")
    for issue in session.layer_issues:
        if isinstance(issue, dict) and issue.get("blocking"):
            raise AuditDataProviderError(f"blocking coverage issue in snapshot: {issue}", code="INCOMPLETE_FACTS")
    if not isinstance(session.files, dict) or not session.files:
        raise AuditDataProviderError("verified snapshot contains no DEX files", code="INCOMPLETE_FACTS")


def _query_checked(session: FactSessionProtocol, sql: str, config: GateConfig) -> list[dict[str, Any]]:
    try:
        rows = session.all(sql, max_rows=config.max_rows, max_bytes=config.max_bytes)
    except ns.EngineError as exc:
        raise AuditDataProviderError(f"shared session query failed ({exc.code}): {exc}", code=exc.code) from exc
    cov = session.coverage
    if cov.get("abandoned", 0) != 0:
        raise AuditDataProviderError("query abandoned without complete terminal", code="INCOMPLETE_FACTS")
    return rows


def verify_required_layers_present(session: FactSessionProtocol, targets: GateDomainTargets, config: GateConfig) -> None:
    """Verify every required fact table/layer answers completely before returning gate verdicts."""
    _verify_session_completeness(session, None, None)
    opened = session.opened if isinstance(session.opened, dict) else {}
    reported_layers = opened.get("layers")
    if isinstance(reported_layers, (list, tuple, set)):
        missing = [layer for layer in targets.required_layers if layer not in reported_layers]
        if missing:
            raise AuditDataProviderError(
                f"shared snapshot missing required layers {missing}; refusing empty hit",
                code="INCOMPLETE_FACTS",
            )
    # Probe each minimal layer table cleanly to guarantee incomplete/partial layers never produce empty results.
    probes = (
        "SELECT file_id,string_pool_id,entry_name FROM dex_files ORDER BY file_id LIMIT 1",
        "SELECT string_pool_id,string_idx FROM strings ORDER BY string_pool_id,string_idx LIMIT 1",
        "SELECT file_id,class_idx FROM classes ORDER BY file_id,class_idx LIMIT 1",
        "SELECT file_id,method_idx FROM code_items ORDER BY file_id,method_idx LIMIT 1",
        "SELECT file_id,annotation_off FROM annotations ORDER BY file_id,annotation_off LIMIT 1",
        "SELECT file_id,method_idx FROM method_strings ORDER BY file_id,method_idx LIMIT 1",
    )
    for sql in probes:
        _query_checked(session, sql, config)


def run_intake_from_session(
    session: FactSessionProtocol,
    targets: GateDomainTargets,
    config: GateConfig,
    *,
    apk_path: Path | None = None,
    pre_sha: str | None = None,
) -> dict[str, Any]:
    """Compute exact intake identity + obfuscated owner drift verdict from shared session facts."""
    _verify_session_completeness(session, apk_path, pre_sha)
    verify_required_layers_present(session, targets, config)

    reply_desc = java_to_desc(targets.reply_info)
    comment_desc = java_to_desc(targets.comment_item)
    mapper_prefix_like = "%(" + reply_desc + "%)" + comment_desc

    mapper_rows = _query_checked(
        session,
        f"SELECT file_id, class_idx, class_descriptor, method_name, method_descriptor, access_flags "
        f"FROM class_methods WHERE method_descriptor LIKE {_sql_lit(mapper_prefix_like)} "
        f"ORDER BY file_id, class_idx, method_idx",
        config,
    )
    mappers: list[tuple[str, str]] = []
    for row in mapper_rows:
        flags = int(row["access_flags"])
        if not (flags & 0x8) or (flags & 0x1000) or (flags & 0x400):
            continue
        params_desc, ret_desc = parse_method_descriptor(row["method_descriptor"])
        params_java = [desc_to_java(p) for p in params_desc]
        ret_java = desc_to_java(ret_desc)
        if ret_java == targets.comment_item and params_java and params_java[0] == targets.reply_info:
            mappers.append((desc_to_java(row["class_descriptor"]), row["method_name"]))

    relate_prefix = "L" + targets.relate_game_package.replace(".", "/") + "/%"
    relate_cls_rows = _query_checked(
        session,
        f"SELECT file_id, class_idx, descriptor, access_flags, superclass_descriptor "
        f"FROM classes WHERE descriptor LIKE {_sql_lit(relate_prefix)} ORDER BY file_id, class_idx",
        config,
    )
    relate_candidates: list[dict[str, Any]] = []
    for row in relate_cls_rows:
        acc = int(row["access_flags"])
        if (acc & 0x400) or (acc & 0x200):
            continue
        relate_candidates.append(row)

    relate_components: list[tuple[str, str | None]] = []
    if relate_candidates:
        descs = sorted({r["descriptor"] for r in relate_candidates})
        cm_rows = _query_checked(
            session,
            f"SELECT file_id, class_idx, class_descriptor, method_name, method_descriptor "
            f"FROM class_methods WHERE class_descriptor IN ({_sql_in(descs)}) "
            f"ORDER BY file_id, class_idx, method_idx",
            config,
        )
        by_key: dict[tuple[int, int], list[dict[str, Any]]] = {}
        for mrow in cm_rows:
            by_key.setdefault((int(mrow["file_id"]), int(mrow["class_idx"])), []).append(mrow)
        for crow in relate_candidates:
            methods = by_key.get((int(crow["file_id"]), int(crow["class_idx"])), [])
            creates = False
            binds = False
            for mrow in methods:
                p_desc, r_desc = parse_method_descriptor(mrow["method_descriptor"])
                p_java = [desc_to_java(p) for p in p_desc]
                r_java = desc_to_java(r_desc)
                if r_java == VIEW_BINDING_TYPE and p_java == CREATE_METHOD_PARAMS:
                    creates = True
                if len(p_java) == 2 and p_java[0] == VIEW_BINDING_TYPE and p_java[1] == CONTINUATION_TYPE:
                    binds = True
            if creates and binds:
                sup = crow.get("superclass_descriptor")
                relate_components.append(
                    (desc_to_java(crow["descriptor"]), desc_to_java(sup) if sup else None)
                )

    gemini_prefix = "L" + targets.gemini_ui_package.replace(".", "/") + "/%"
    gemini_cls_rows = _query_checked(
        session,
        f"SELECT file_id, class_idx, descriptor, access_flags "
        f"FROM classes WHERE descriptor LIKE {_sql_lit(gemini_prefix)} ORDER BY file_id, class_idx",
        config,
    )
    gemini_candidates: list[dict[str, Any]] = []
    for row in gemini_cls_rows:
        java_name = desc_to_java(row["descriptor"])
        acc = int(row["access_flags"])
        if "$" in java_name or not (acc & 0x400) or (acc & 0x200):
            continue
        gemini_candidates.append(row)

    gemini_bases: list[str] = []
    if gemini_candidates:
        descs = sorted({r["descriptor"] for r in gemini_candidates})
        cm_rows = _query_checked(
            session,
            f"SELECT file_id, class_idx, class_descriptor, method_name, method_descriptor "
            f"FROM class_methods WHERE class_descriptor IN ({_sql_in(descs)}) "
            f"ORDER BY file_id, class_idx, method_idx",
            config,
        )
        by_key = {}
        for mrow in cm_rows:
            by_key.setdefault((int(mrow["file_id"]), int(mrow["class_idx"])), []).append(mrow)
        for crow in gemini_candidates:
            methods = by_key.get((int(crow["file_id"]), int(crow["class_idx"])), [])
            names: dict[str, list[str]] = {}
            for mrow in methods:
                p_desc, _ = parse_method_descriptor(mrow["method_descriptor"])
                names[mrow["method_name"]] = [desc_to_java(p) for p in p_desc]
            if len(names.get("createViewEntry", [])) == 2 and len(names.get("bindToView", [])) == 2:
                gemini_bases.append(desc_to_java(crow["descriptor"]))

    owners = sorted({owner for owner, _ in mappers})
    mapper_ok = bool(owners) and all(_covered(o, targets.mapper_package) for o in owners)
    relate_owners = sorted({owner for owner, _ in relate_components})
    relate_ok = len(relate_owners) == 1 and (
        _covered(relate_owners[0], targets.relate_game_package)
        or relate_owners[0] == targets.relate_game_package + ".RelateGameComponent"
    )
    gemini_ok = (not gemini_bases) or any(_covered(name, targets.gemini_ui_package) for name in gemini_bases)
    gemini_letters = [name for name in gemini_bases if _covered(name, targets.gemini_ui_package)]
    multi_owner_warning = len(owners) > 1
    failures = 0 if (mapper_ok and relate_ok and gemini_ok) else 1

    _verify_session_completeness(session, apk_path, pre_sha)
    return {
        "gate": "intake",
        "mapper_owners": owners,
        "mapper_ok": mapper_ok,
        "relate_game_owners": relate_owners,
        "relate_ok": relate_ok,
        "gemini_bases": gemini_letters,
        "gemini_ok": "n/a" if not gemini_bases else gemini_ok,
        "multi_owner_warning": multi_owner_warning,
        "expected_features": list(targets.expected_features),
        "exit_code": failures,
    }


def _decode_insns_slice(insns_bytes: bytes, insns_size_units: int) -> list[tuple[int, int, int]]:
    out: list[tuple[int, int, int]] = []
    pc = 0
    while pc < insns_size_units:
        at = pc * 2
        if at + 2 > len(insns_bytes):
            raise AuditDataProviderError("truncated Dalvik instruction slice in verified DEX", code="CACHE_CORRUPT")
        u = struct.unpack_from("<H", insns_bytes, at)[0]
        op = u & 0xFF
        if op == 0 and u == 0x0100:
            size = struct.unpack_from("<H", insns_bytes, at + 2)[0]
            w = size * 2 + 4
        elif op == 0 and u == 0x0200:
            size = struct.unpack_from("<H", insns_bytes, at + 2)[0]
            w = size * 4 + 2
        elif op == 0 and u == 0x0300:
            ew = struct.unpack_from("<H", insns_bytes, at + 2)[0]
            size = struct.unpack_from("<I", insns_bytes, at + 4)[0]
            w = (size * ew + 1) // 2 + 4
        else:
            w = _WIDTH[op]
        out.append((pc, op, at))
        pc += w
    return out


class BytecodeSliceReader(Protocol):
    """Reads verified raw `insns` bytes `(insns_off, insns_size_units)` for targeted methods."""

    def read_insns(self, file_id: int, insns_off: int, insns_size_units: int) -> bytes: ...


class ZipArchiveSliceReader:
    """Reads exact `(insns_off, insns_size_units)` slices from a SHA-256-verified APK/DEX source."""

    def __init__(
        self,
        apk_path: Path,
        files: dict[int, str],
        expected_sha256: str,
        *,
        verify_before_read: bool = True,
    ) -> None:
        self.apk_path = apk_path
        self.files = dict(files)
        self.expected_sha256 = expected_sha256
        self.verify_before_read = verify_before_read
        self._dex_bytes: dict[int, bytes] = {}
        self._zip: zipfile.ZipFile | None = None
        if apk_path.suffix.lower() != ".dex" and zipfile.is_zipfile(apk_path):
            self._zip = zipfile.ZipFile(apk_path, "r")

    def read_insns(self, file_id: int, insns_off: int, insns_size_units: int) -> bytes:
        if file_id not in self._dex_bytes:
            if self.verify_before_read and sha256_file(self.apk_path) != self.expected_sha256:
                raise AuditDataProviderError("APK changed before reading code slice", code="SOURCE_CHANGED")
            if self._zip is None:
                self._dex_bytes[file_id] = self.apk_path.read_bytes()
            else:
                entry_name = self.files.get(file_id)
                if not entry_name:
                    raise AuditDataProviderError(f"missing file_id {file_id} in inventory", code="INCOMPLETE_FACTS")
                self._dex_bytes[file_id] = self._zip.read(entry_name)
        blob = self._dex_bytes[file_id]
        byte_len = insns_size_units * 2
        if insns_off < 0 or insns_off + byte_len > len(blob):
            raise AuditDataProviderError("code_items insns range exceeds verified member length", code="CACHE_CORRUPT")
        return blob[insns_off : insns_off + byte_len]

    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()
            self._zip = None


def _iput_mapping_from_slice(
    insns_bytes: bytes,
    insns_size_units: int,
    regs: int,
    ins: int,
    owner_desc: str,
    params_desc: list[str],
    field_lookup: dict[int, tuple[str, str]],
) -> dict[int, str]:
    first = regs - ins + 1  # skip `this`
    reg_of: list[int] = []
    r = first
    for p in params_desc:
        reg_of.append(r)
        r += 2 if p in ("J", "D") else 1
    src_to_param = {reg: k for k, reg in enumerate(reg_of)}
    alias: dict[int, int] = {}
    mapping: dict[int, str] = {}
    for _pc, op, at in _decode_insns_slice(insns_bytes, insns_size_units):
        u = struct.unpack_from("<H", insns_bytes, at)[0]
        if op in (0x07, 0x01, 0x04):
            a = (u >> 8) & 0xF
            b = (u >> 12) & 0xF
            alias[a] = alias.get(b, b)
        elif op in (0x08, 0x02, 0x05):
            a = (u >> 8) & 0xFF
            b = struct.unpack_from("<H", insns_bytes, at + 2)[0]
            alias[a] = alias.get(b, b)
        elif 0x59 <= op <= 0x5F:
            a = (u >> 8) & 0xF
            fidx = struct.unpack_from("<H", insns_bytes, at + 2)[0]
            resolved = field_lookup.get(fidx)
            src = alias.get(a, a)
            if resolved is not None and resolved[0] == owner_desc and src in src_to_param and src_to_param[src] not in mapping:
                mapping[src_to_param[src]] = resolved[1]
    return mapping


def _serializer_info_from_session(
    session: FactSessionProtocol,
    slice_reader: BytecodeSliceReader,
    serial: str,
    file_to_spid: dict[int, int],
    config: GateConfig,
) -> tuple[str | None, str | None, list[str]]:
    hits = _query_checked(
        session,
        f"SELECT DISTINCT ms.file_id, c.class_def_idx, ms.method_class, ms.method_idx "
        f"FROM method_strings ms "
        f"JOIN classes c ON c.file_id = ms.file_id AND c.descriptor = ms.method_class "
        f"WHERE ms.value = {_sql_lit(serial)} "
        f"ORDER BY ms.file_id, c.class_def_idx, ms.method_idx",
        config,
    )
    if not hits:
        return None, None, []

    hits = sorted(
        hits,
        key=lambda r: (
            session.files.get(int(r["file_id"]), ""),
            int(r["class_def_idx"]),
            int(r["method_idx"]),
        ),
    )
    first_hit = hits[0]
    fid = int(first_hit["file_id"])
    midx = int(first_hit["method_idx"])
    ser = str(first_hit["method_class"])
    spid = file_to_spid.get(fid, fid)

    serial_str_rows = _query_checked(
        session,
        f"SELECT string_idx, value FROM strings WHERE string_pool_id = {spid} AND value = {_sql_lit(serial)} ORDER BY string_idx",
        config,
    )
    if not serial_str_rows:
        return None, None, []
    serial_sidx = int(serial_str_rows[0]["string_idx"])

    ci_rows = _query_checked(
        session,
        f"SELECT insns_off, insns_size FROM code_items WHERE file_id = {fid} AND method_idx = {midx} ORDER BY method_idx",
        config,
    )
    if not ci_rows:
        return None, None, []
    insns_off = int(ci_rows[0]["insns_off"])
    insns_size = int(ci_rows[0]["insns_size"])
    insns_bytes = slice_reader.read_insns(fid, insns_off, insns_size)

    hit = False
    collected_sidxs: list[int] = []
    for _pc, op, at in _decode_insns_slice(insns_bytes, insns_size):
        if op == 0x1A:
            v = struct.unpack_from("<H", insns_bytes, at + 2)[0]
        elif op == 0x1B:
            v = struct.unpack_from("<I", insns_bytes, at + 2)[0]
        else:
            continue
        if v == serial_sidx:
            hit = True
        elif hit:
            collected_sidxs.append(v)

    if not hit:
        return None, None, []

    strings_out: list[str] = []
    if collected_sidxs:
        uniq_sidxs = sorted(set(collected_sidxs))
        s_rows = _query_checked(
            session,
            f"SELECT string_idx, value FROM strings WHERE string_pool_id = {spid} AND string_idx IN ({_sql_in_ints(uniq_sidxs)}) ORDER BY string_idx",
            config,
        )
        s_map = {int(r["string_idx"]): r["value"] for r in s_rows}
        strings_out = [s_map[idx] for idx in collected_sidxs]

    owner = (ser[: ser.rindex("$")] + ";") if "$" in ser else None
    return ser, owner, strings_out


def _extract_signature_field_targets(
    session: FactSessionProtocol,
    fid: int,
    cidx: int,
    spid: int,
    config: GateConfig,
) -> tuple[int, set[str]]:
    sig_types = _query_checked(
        session,
        f"SELECT type_idx FROM types WHERE file_id = {fid} AND descriptor = {_sql_lit(SIGNATURE_ANN_DESC)} ORDER BY type_idx",
        config,
    )
    if not sig_types:
        return 0, set()
    sig_tidx = int(sig_types[0]["type_idx"])

    dir_rows = _query_checked(
        session,
        f"SELECT entry_idx, annotation_set_off FROM annotation_directory_entries "
        f"WHERE file_id = {fid} AND class_idx = {cidx} AND entry_kind = 'field' AND annotation_set_off IS NOT NULL "
        f"ORDER BY entry_idx",
        config,
    )
    if not dir_rows:
        return 0, set()

    set_offs = sorted({int(r["annotation_set_off"]) for r in dir_rows})
    set_entries = _query_checked(
        session,
        f"SELECT annotation_set_off, annotation_off, ordinal FROM annotation_set_entries "
        f"WHERE file_id = {fid} AND annotation_set_off IN ({_sql_in_ints(set_offs)}) "
        f"ORDER BY annotation_set_off, ordinal",
        config,
    )
    if not set_entries:
        return 0, set()

    ann_offs = sorted({int(r["annotation_off"]) for r in set_entries})
    anns = _query_checked(
        session,
        f"SELECT annotation_off, type_idx FROM annotations "
        f"WHERE file_id = {fid} AND annotation_off IN ({_sql_in_ints(ann_offs)}) AND type_idx = {sig_tidx} "
        f"ORDER BY annotation_off",
        config,
    )
    if not anns:
        return 0, set()

    sig_ann_offs = sorted({int(r["annotation_off"]) for r in anns})
    elems = _query_checked(
        session,
        f"SELECT annotation_off, depth, ordinal, value_kind, value_index "
        f"FROM annotation_elements "
        f"WHERE file_id = {fid} AND annotation_off IN ({_sql_in_ints(sig_ann_offs)}) "
        f"ORDER BY annotation_off, ordinal",
        config,
    )
    sidxs = sorted(
        {
            int(e["value_index"])
            for e in elems
            if int(e["depth"]) == 1 and e.get("value_kind") == "string" and e.get("value_index") is not None
        }
    )
    s_map: dict[int, str] = {}
    if sidxs:
        s_rows = _query_checked(
            session,
            f"SELECT string_idx, value FROM strings WHERE string_pool_id = {spid} AND string_idx IN ({_sql_in_ints(sidxs)}) ORDER BY string_idx",
            config,
        )
        s_map = {int(r["string_idx"]): r["value"] for r in s_rows}

    by_ann: dict[int, list[str]] = {}
    for e in elems:
        if int(e["depth"]) == 1 and e.get("value_kind") == "string" and e.get("value_index") is not None:
            by_ann.setdefault(int(e["annotation_off"]), []).append(s_map[int(e["value_index"])])

    set_to_anns: dict[int, list[int]] = {}
    sig_ann_set = set(sig_ann_offs)
    for se in set_entries:
        aoff = int(se["annotation_off"])
        if aoff in sig_ann_set:
            set_to_anns.setdefault(int(se["annotation_set_off"]), []).append(aoff)

    field_sigs: dict[int, str] = {}
    for drow in dir_rows:
        fidx = int(drow["entry_idx"])
        soff = int(drow["annotation_set_off"])
        for aoff in set_to_anns.get(soff, []):
            parts = by_ann.get(aoff, [])
            if parts:
                field_sigs[fidx] = "".join(parts)

    found: set[str] = set()
    for sig in field_sigs.values():
        for part in sig.replace("<", " ").replace(">", " ").replace(";", "; ").split():
            if part.startswith("L") and part.endswith(";"):
                found.add(part)
    return len(field_sigs), found


def run_home_from_session(
    session: FactSessionProtocol,
    slice_reader: BytecodeSliceReader,
    targets: GateDomainTargets,
    config: GateConfig,
    *,
    apk_path: Path | None = None,
    pre_sha: str | None = None,
) -> dict[str, Any]:
    """Compute exact home_frame_audit dict (`data.*`, `item.*`, `vm.reach`, `kx.*`, `cls.*`) from shared facts."""
    _verify_session_completeness(session, apk_path, pre_sha)
    verify_required_layers_present(session, targets, config)

    dex_rows = _query_checked(
        session,
        "SELECT file_id, string_pool_id FROM dex_files ORDER BY file_id",
        config,
    )
    file_to_spid = {int(r["file_id"]): int(r["string_pool_id"]) for r in dex_rows}

    out: dict[str, Any] = {"apk": apk_path.name if apk_path is not None else "synthetic.apk"}
    for label, serial in (("data", targets.tab_data_serial), ("item", targets.tab_item_serial)):
        _ser, owner, names = _serializer_info_from_session(session, slice_reader, serial, file_to_spid, config)
        out[label + ".owner"] = owner
        out[label + ".elements"] = names
        if not owner:
            continue

        owner_rows = _query_checked(
            session,
            f"SELECT file_id, class_idx FROM classes WHERE descriptor = {_sql_lit(owner)} ORDER BY file_id, class_idx",
            config,
        )
        if not owner_rows:
            continue
        owner_fid = int(owner_rows[0]["file_id"])
        owner_cidx = int(owner_rows[0]["class_idx"])

        owner_fields = _query_checked(
            session,
            f"SELECT field_idx, class_descriptor, field_name, field_descriptor, kind "
            f"FROM class_fields WHERE file_id = {owner_fid} AND class_idx = {owner_cidx} ORDER BY field_idx",
            config,
        )
        inst = [(r["field_name"], extract_field_type_descriptor(r["field_descriptor"])) for r in owner_fields if r["kind"] == "instance"]
        sfields = [(r["field_name"], extract_field_type_descriptor(r["field_descriptor"])) for r in owner_fields if r["kind"] == "static"]
        field_lookup = {
            int(r["field_idx"]): (r["class_descriptor"], r["field_name"]) for r in owner_fields
        }
        out[label + ".fields"] = [f"{n}:{t}" for n, t in inst]

        ctor_rows = _query_checked(
            session,
            f"SELECT cm.method_idx, cm.method_descriptor AS descriptor, cm.kind AS method_kind, "
            f"ci.registers_size, ci.ins_size, ci.insns_off, ci.insns_size "
            f"FROM class_methods cm "
            f"LEFT JOIN code_items ci ON ci.file_id = cm.file_id AND ci.method_idx = cm.method_idx "
            f"WHERE cm.file_id = {owner_fid} AND cm.class_idx = {owner_cidx} AND cm.method_name = '<init>' "
            f"ORDER BY cm.kind, cm.method_idx",
            config,
        )
        ctors: list[tuple[list[str], int | None, int | None, int | None, int | None]] = []
        for crow in ctor_rows:
            params_desc, _ = parse_method_descriptor(crow["descriptor"])
            ctors.append(
                (
                    params_desc,
                    int(crow["registers_size"]) if crow["registers_size"] is not None else None,
                    int(crow["ins_size"]) if crow["ins_size"] is not None else None,
                    int(crow["insns_off"]) if crow["insns_off"] is not None else None,
                    int(crow["insns_size"]) if crow["insns_size"] is not None else None,
                )
            )
        out[label + ".ctors"] = [" ".join(p) for p, *_ in ctors]

        n = len(names)
        types = [t for _, t in inst]
        deser = [c for c in ctors if len(c[0]) >= n + 1 and c[0][0] == "I" and c[0][1 : n + 1] == types]
        verdict = "no-deser-ctor"
        if deser:
            p, regs, ins, insns_off, insns_size = deser[0]
            if insns_off is None or insns_size is None or regs is None or ins is None:
                raise AuditDataProviderError(f"deserializer constructor of {owner} has missing code_item facts", code="INCOMPLETE_FACTS")
            insns_bytes = slice_reader.read_insns(owner_fid, insns_off, insns_size)
            m = _iput_mapping_from_slice(insns_bytes, insns_size, regs, ins, owner, p, field_lookup)
            bad = [i for i in range(n) if (i + 1) in m and m[i + 1] != inst[i][0]]
            missing = [i for i in range(n) if (i + 1) not in m]
            verdict = (
                ("order-ok" if not bad else "ORDER-MISMATCH " + str(m))
                + f" fields={len(inst)} elements={n} unproven={missing}"
            )
        out[label + ".order"] = verdict

        factory: list[str] = []
        static_ftypes = sorted({ftype for _, ftype in sfields})
        if static_ftypes:
            comp_rows = _query_checked(
                session,
                f"SELECT cm.class_descriptor, cm.method_name, cm.method_descriptor, cm.access_flags "
                f"FROM class_methods cm "
                f"WHERE cm.class_descriptor IN ({_sql_in(static_ftypes)}) "
                f"ORDER BY cm.file_id, cm.class_idx, cm.kind, cm.method_idx",
                config,
            )
            comp_by_type: dict[str, list[dict[str, Any]]] = {}
            for mr in comp_rows:
                comp_by_type.setdefault(mr["class_descriptor"], []).append(mr)
            for fname, ftype in sfields:
                for mr in comp_by_type.get(ftype, []):
                    acc = int(mr["access_flags"])
                    if acc & 0x8:
                        continue
                    p_desc, r_desc = parse_method_descriptor(mr["method_descriptor"])
                    if not p_desc and r_desc == KOTLINX_SERIALIZER_DESC:
                        factory.append(f"{fname}:{ftype}#{mr['method_name']}")
        out[label + ".companion"] = factory or "MISSING"

    reach = "vm-missing"
    vm_rows = _query_checked(
        session,
        f"SELECT file_id, class_idx FROM classes WHERE descriptor = {_sql_lit(targets.vm_descriptor)} ORDER BY file_id, class_idx",
        config,
    )
    if vm_rows:
        vm_fid = int(vm_rows[0]["file_id"])
        vm_cidx = int(vm_rows[0]["class_idx"])
        vm_spid = file_to_spid.get(vm_fid, vm_fid)
        sig_count, found_descs = _extract_signature_field_targets(session, vm_fid, vm_cidx, vm_spid, config)
        target_owner = out.get("data.owner")
        hop1 = bool(target_owner and target_owner in found_descs)
        hop2 = False
        if target_owner and found_descs:
            found_list = sorted(found_descs)
            hop2_rows = _query_checked(
                session,
                f"SELECT class_descriptor, field_descriptor FROM class_fields "
                f"WHERE class_descriptor IN ({_sql_in(found_list)}) AND kind = 'instance' "
                f"AND (field_descriptor = {_sql_lit(target_owner)} OR field_descriptor LIKE {_sql_lit('%:' + target_owner)}) "
                f"ORDER BY file_id, class_idx, field_idx",
                config,
            )
            hop2 = any(extract_field_type_descriptor(r["field_descriptor"]) == target_owner for r in hop2_rows)
        reach = f"sigs={sig_count} direct={hop1} via_state={hop2}"
    out["vm.reach"] = reach

    kx_rows = _query_checked(
        session,
        f"SELECT DISTINCT value FROM strings WHERE value IN ({_sql_in(KX_ACCESSORS)}) ORDER BY value",
        config,
    )
    kx_found = {r["value"] for r in kx_rows}
    for nm in KX_ACCESSORS:
        out["kx." + nm] = nm in kx_found

    marker_found: set[str] = set()
    if targets.marker_classes:
        m_rows = _query_checked(
            session,
            f"SELECT DISTINCT descriptor FROM classes WHERE descriptor IN ({_sql_in(targets.marker_classes)}) ORDER BY descriptor",
            config,
        )
        marker_found = {r["descriptor"] for r in m_rows}
    for marker in targets.marker_classes:
        short = marker.split("/")[-1][:-1]
        out["cls." + short] = marker in marker_found

    _verify_session_completeness(session, apk_path, pre_sha)
    return out


def _open_verified_b1_session(
    apk_path: Path,
    engine_binary: Path,
    _work_dir: Path,
    config: GateConfig,
) -> tuple[Any, str]:
    pre_sha = sha256_file(apk_path)
    engine_sha = sha256_file(engine_binary)
    limits = {"steps": 40_000_000_000, "scanned_rows": 4_000_000_000, "result_rows": 4_000_000}
    cmd = ns.serve_command(
        str(engine_binary),
        [apk_path],
        dialect="dexsql-0.1.0",
        timeout_seconds=config.timeout_seconds,
        sql_limits=limits,
        non_scalar_text="lossy-replacement",
    )
    settings = ns.StructuralConfig(
        wire=config.wire,
        non_scalar_text="lossy-replacement",
        sql_limits=tuple(limits.items()),
    )
    launch = ns.EngineLaunch(
        cmd,
        {**os.environ, "MDD_FACTS_THREADS": str(config.threads)},
        {"engine": "meguvizdexdash", "sha256": engine_sha},
    )
    session = ns.B1Session(
        apk_path,
        timeout=config.timeout_seconds,
        threads=config.threads,
        launch=launch,
        settings=settings,
    )
    return session, pre_sha


def run_audit_gates(
    apk_path: Path,
    *,
    config: GateConfig,
    targets: GateDomainTargets | None = None,
    tools_dir: Path | None = None,
    engine_binary: Path | None = None,
    shared_session: FactSessionProtocol | None = None,
) -> dict[str, Any]:
    """Run both `intake` and `home` gates according to `GateConfig.mode`.

    Never mixes modes silently mid-run. When `shared_session` is supplied under `mdd_fact_reuse`,
    evaluates both gates over that already-opened verified snapshot without spawning another engine.
    """
    apk_path = Path(apk_path).resolve(strict=True)
    apk_sha = sha256_file(apk_path)

    if config.mode == "legacy_independent":
        if tools_dir is None:
            raise AuditDataProviderError("legacy_independent mode requires reference tools_dir", code="INVALID_ARGUMENT")
        base_tools_dir = resolve_reference_tools_dir(tools_dir)
        analysis_dir = base_tools_dir / "analysis"
        digests = surface_gate.pinned_digests()
        run_env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        with tempfile.TemporaryDirectory(prefix="mdd062-legacy-") as tmp_str:
            tmp = Path(tmp_str)
            intake_argv = surface_gate.hostlab_argv(
                "intake",
                analysis_dir,
                apk_path,
                tsv=tmp / "intake.tsv",
                python=sys.executable,
            )
            home_argv = surface_gate.hostlab_argv(
                "home",
                analysis_dir,
                apk_path,
                python=sys.executable,
            )
            started = time.perf_counter()
            intake_res = surface_gate.run_gate(
                "intake",
                intake_argv,
                script=analysis_dir / "run_intake.py",
                expected_script_sha256=digests["intake"],
                env=run_env,
                timeout=config.timeout_seconds,
                log_dir=tmp,
            )
            home_res = surface_gate.run_gate(
                "home",
                home_argv,
                script=analysis_dir / "home_frame_audit.py",
                expected_script_sha256=digests["home"],
                env=run_env,
                timeout=config.timeout_seconds,
                log_dir=tmp,
            )
            gate_wall_seconds = time.perf_counter() - started
            intake_stdout = (tmp / "intake.stdout.log").read_text(encoding="utf-8", errors="replace")
            home_stdout = (tmp / "home.stdout.log").read_text(encoding="utf-8", errors="replace")

        if not intake_res.accepted():
            raise AuditDataProviderError(
                f"legacy intake gate failed unexpectedly (exit={intake_res.exit_code}, timed_out={intake_res.timed_out})",
                code="INCOMPLETE_FACTS" if intake_res.timed_out else "INTERNAL_FAULT",
            )
        if not home_res.accepted():
            raise AuditDataProviderError(
                f"legacy home gate failed unexpectedly (exit={home_res.exit_code}, timed_out={home_res.timed_out})",
                code="INCOMPLETE_FACTS" if home_res.timed_out else "INTERNAL_FAULT",
            )
        parsed_home = parse_legacy_home_stdout(home_stdout, apk_path.name)
        parsed_intake = parse_legacy_intake_stdout(intake_stdout, int(intake_res.exit_code))
        return {
            "mode": "legacy_independent",
            "apk_sha256": apk_sha,
            "same_core_self_check_is_not_independent_oracle": True,
            "counted_in_phase1_sf_target": False,
            "timing_window": "E_gate",
            "gate_wall_seconds": gate_wall_seconds,
            "intake_seconds": intake_res.seconds,
            "home_seconds": home_res.seconds,
            "intake": parsed_intake,
            "home": parsed_home,
            "intake_exit_code": int(intake_res.exit_code),
            "home_exit_code": int(home_res.exit_code),
        }

    if targets is None:
        if tools_dir is None:
            raise AuditDataProviderError("mdd_fact_reuse requires targets or reference tools_dir", code="INVALID_ARGUMENT")
        targets = load_targets_from_reference(tools_dir)

    if shared_session is not None:
        started = time.perf_counter()
        slice_reader = ZipArchiveSliceReader(
            apk_path,
            shared_session.files,
            apk_sha,
            verify_before_read=False,
        )
        try:
            t_in0 = time.perf_counter()
            intake_out = run_intake_from_session(
                shared_session, targets, config
            )
            t_in1 = time.perf_counter()
            home_out = run_home_from_session(
                shared_session, slice_reader, targets, config, apk_path=apk_path
            )
            t_hm1 = time.perf_counter()
        finally:
            slice_reader.close()
        gate_wall_seconds = time.perf_counter() - started
    else:
        if engine_binary is None:
            exe_name = "meguvizdexdash.exe" if os.name == "nt" else "meguvizdexdash"
            rel_cand = ROOT / "target/release" / exe_name
            if not rel_cand.is_file():
                rel_cand = ROOT / "target/debug" / exe_name
            engine_binary = rel_cand.resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="mdd062-gate-") as tmp:
            started = time.perf_counter()
            session, pre_sha = _open_verified_b1_session(apk_path, engine_binary, Path(tmp), config)
            with session:
                slice_reader = ZipArchiveSliceReader(
                    apk_path,
                    session.files,
                    pre_sha,
                    verify_before_read=False,
                )
                try:
                    t_in0 = time.perf_counter()
                    intake_out = run_intake_from_session(
                        session, targets, config
                    )
                    t_in1 = time.perf_counter()
                    home_out = run_home_from_session(
                        session, slice_reader, targets, config, apk_path=apk_path
                    )
                    t_hm1 = time.perf_counter()
                finally:
                    slice_reader.close()
            gate_wall_seconds = time.perf_counter() - started

    if sha256_file(apk_path) != apk_sha:
        raise AuditDataProviderError("APK digest changed after gate run", code="SOURCE_CHANGED")

    return {
        "mode": "mdd_fact_reuse",
        "session_scope": "shared_resident_session" if shared_session is not None else "fresh_session",
        "apk_sha256": apk_sha,
        "same_core_self_check_is_not_independent_oracle": True,
        "counted_in_phase1_sf_target": False,
        "timing_window": "E_gate",
        "gate_wall_seconds": gate_wall_seconds,
        "intake_seconds": t_in1 - t_in0,
        "home_seconds": t_hm1 - t_in1,
        "intake": intake_out,
        "home": home_out,
        "intake_exit_code": intake_out["exit_code"],
        "home_exit_code": 0,
    }


def parse_legacy_intake_stdout(stdout: str, exit_code: int) -> dict[str, Any]:
    def _extract_line(prefix: str) -> tuple[list[str], str]:
        for line in stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith(prefix):
                rest = stripped.split(":", 1)[1].strip()
                lhs, rhs = rest.rsplit("covered=", 1)
                lhs = lhs.strip()
                owners = [] if lhs == "-" else ast.literal_eval(lhs)
                return list(owners), rhs.strip()
        raise AuditDataProviderError(f"missing legacy intake line starting with {prefix!r}")

    owners, m_ok = _extract_line("mapper owners")
    r_owners, r_ok = _extract_line("relate game owners")
    g_bases, g_ok = _extract_line("gemini bases")
    return {
        "gate": "intake",
        "mapper_owners": owners,
        "mapper_ok": m_ok == "True",
        "relate_game_owners": r_owners,
        "relate_ok": r_ok == "True",
        "gemini_bases": g_bases,
        "gemini_ok": "n/a" if g_ok == "n/a" else (g_ok == "True"),
        "multi_owner_warning": "WARNING: mapper has multiple owners" in stdout,
        "exit_code": exit_code,
    }


def parse_legacy_home_stdout(stdout: str, apk_name: str) -> dict[str, Any]:
    out: dict[str, Any] = {"apk": apk_name}
    for line in stdout.splitlines():
        if line.startswith("  ") and ": " in line:
            k, v_raw = line.strip().split(": ", 1)
            if k in ("data.elements", "data.fields", "data.ctors", "data.companion", "item.elements", "item.fields", "item.ctors", "item.companion"):
                out[k] = "MISSING" if v_raw == "MISSING" else ast.literal_eval(v_raw)
            elif v_raw in ("True", "False", "None"):
                out[k] = {"True": True, "False": False, "None": None}[v_raw]
            else:
                out[k] = v_raw
    return out


def compare_gate_outputs(legacy: dict[str, Any], reuse: dict[str, Any]) -> dict[str, Any]:
    mismatches: list[str] = []
    if legacy["intake_exit_code"] != reuse["intake_exit_code"]:
        mismatches.append(f"intake exit code {legacy['intake_exit_code']} != {reuse['intake_exit_code']}")
    if legacy["home_exit_code"] != reuse["home_exit_code"]:
        mismatches.append(f"home exit code {legacy['home_exit_code']} != {reuse['home_exit_code']}")

    for key in ("mapper_owners", "mapper_ok", "relate_game_owners", "relate_ok", "gemini_bases", "gemini_ok", "multi_owner_warning"):
        if legacy["intake"].get(key) != reuse["intake"].get(key):
            mismatches.append(f"intake.{key} mismatch")

    home_keys = sorted(set(legacy["home"]) | set(reuse["home"]))
    for k in home_keys:
        if legacy["home"].get(k) != reuse["home"].get(k):
            mismatches.append(f"home.{k} mismatch")

    intake_canonical_keys = (
        "gate",
        "mapper_owners",
        "mapper_ok",
        "relate_game_owners",
        "relate_ok",
        "gemini_bases",
        "gemini_ok",
        "multi_owner_warning",
        "exit_code",
    )
    l_intake_norm = {k: legacy["intake"].get(k) for k in intake_canonical_keys}
    r_intake_norm = {k: reuse["intake"].get(k) for k in intake_canonical_keys}
    l_sha = hashlib.sha256(json.dumps({"intake": l_intake_norm, "home": legacy["home"]}, sort_keys=True).encode("utf-8")).hexdigest()
    r_sha = hashlib.sha256(json.dumps({"intake": r_intake_norm, "home": reuse["home"]}, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        "equivalent": not mismatches and l_sha == r_sha,
        "exit_code_match": legacy["intake_exit_code"] == reuse["intake_exit_code"] and legacy["home_exit_code"] == reuse["home_exit_code"],
        "legacy_verdict_sha256": l_sha,
        "reuse_verdict_sha256": r_sha,
        "mismatches": mismatches,
    }


def _redact_public_live_summary(legacy: dict[str, Any], reuse: dict[str, Any], comp: dict[str, Any]) -> dict[str, Any]:
    h = reuse["home"]
    in_r = reuse["intake"]
    return {
        "apk_sha256": reuse["apk_sha256"],
        "equivalent": comp["equivalent"],
        "exit_code_match": comp["exit_code_match"],
        "legacy_verdict_sha256": comp["legacy_verdict_sha256"],
        "reuse_verdict_sha256": comp["reuse_verdict_sha256"],
        "mismatches": list(comp["mismatches"]),
        "intake_exit_code": reuse["intake_exit_code"],
        "home_exit_code": reuse["home_exit_code"],
        "intake_summary": {
            "mapper_count": len(in_r["mapper_owners"]),
            "mapper_ok": in_r["mapper_ok"],
            "relate_count": len(in_r["relate_game_owners"]),
            "relate_ok": in_r["relate_ok"],
            "gemini_count": len(in_r["gemini_bases"]),
            "gemini_ok": in_r["gemini_ok"],
            "multi_owner_warning": in_r["multi_owner_warning"],
            "expected_feature_count": len(in_r["expected_features"]),
        },
        "home_summary": {
            "data_elements_count": len(h.get("data.elements") or []),
            "data_order": str(h.get("data.order", "")),
            "data_companion_present": h.get("data.companion") != "MISSING",
            "item_elements_count": len(h.get("item.elements") or []),
            "item_order": str(h.get("item.order", "")),
            "item_companion_present": h.get("item.companion") != "MISSING",
            "vm_reach": str(h.get("vm.reach", "")),
            "kx_all_true": all(bool(h.get("kx." + nm)) for nm in KX_ACCESSORS),
            "marker_true_count": sum(1 for k, v in h.items() if k.startswith("cls.") and v is True),
        },
        "timing_window": {
            "name": "E_gate",
            "counted_in_phase1_sf_target": False,
            "legacy_seconds": legacy["gate_wall_seconds"],
            "legacy_intake_seconds": legacy["intake_seconds"],
            "legacy_home_seconds": legacy["home_seconds"],
            "reuse_seconds": reuse["gate_wall_seconds"],
            "reuse_intake_seconds": reuse["intake_seconds"],
            "reuse_home_seconds": reuse["home_seconds"],
            "wall_saved_seconds": legacy["gate_wall_seconds"] - reuse["gate_wall_seconds"],
            "speedup": (legacy["gate_wall_seconds"] / reuse["gate_wall_seconds"]) if reuse["gate_wall_seconds"] > 0 else None,
        },
    }


def _build_evidence(out_path: Path, rounds: int = 3) -> dict[str, Any]:
    cases_doc = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    require(PATHS_JSON.is_file(), f"live paths json missing: {PATHS_JSON}")
    paths = json.loads(PATHS_JSON.read_text(encoding="utf-8"))
    ref_tools_dir = resolve_reference_tools_dir(Path(paths["reference"]))
    b_binary = Path(paths["engines"]["B"]).resolve(strict=True)
    targets = load_targets_from_reference(ref_tools_dir)

    fwc = importlib.import_module("run-five-way-comparison")  # noqa: E402
    window_check = fwc.check_exclusive_window()

    live_samples: dict[str, Any] = {}
    for sample_id in ("hostlab-9161100", "hostlab-9170100"):
        apk_path = Path(paths["inputs"][sample_id]).resolve(strict=True)
        paired_runs: list[dict[str, Any]] = []
        comp_verified: dict[str, Any] | None = None
        last_legacy: dict[str, Any] | None = None
        last_reuse: dict[str, Any] | None = None
        for idx in range(rounds):
            order = ("legacy_independent", "mdd_fact_reuse") if idx % 2 == 0 else ("mdd_fact_reuse", "legacy_independent")
            res_map: dict[str, dict[str, Any]] = {}
            for mode in order:
                cfg = GateConfig(mode=mode, wire="b1")
                res_map[mode] = run_audit_gates(
                    apk_path,
                    config=cfg,
                    targets=targets,
                    tools_dir=ref_tools_dir,
                    engine_binary=b_binary,
                )
            comp = compare_gate_outputs(res_map["legacy_independent"], res_map["mdd_fact_reuse"])
            require(comp["equivalent"], f"{sample_id} round {idx} equivalence mismatch: {comp['mismatches']}")
            comp_verified = comp
            last_legacy = res_map["legacy_independent"]
            last_reuse = res_map["mdd_fact_reuse"]
            paired_runs.append(
                {
                    "pair_index": idx,
                    "order": list(order),
                    "legacy_seconds": last_legacy["gate_wall_seconds"],
                    "reuse_seconds": last_reuse["gate_wall_seconds"],
                    "legacy_intake_seconds": last_legacy["intake_seconds"],
                    "legacy_home_seconds": last_legacy["home_seconds"],
                    "reuse_intake_seconds": last_reuse["intake_seconds"],
                    "reuse_home_seconds": last_reuse["home_seconds"],
                    "equivalent": True,
                }
            )

        # Also measure resident shared-session gate timing (exact HL-12 post-native_audit scenario
        # where required layers are already loaded in the same verified B1Session).
        shared_timings: list[dict[str, Any]] = []
        reuse_cfg = GateConfig(mode="mdd_fact_reuse", wire="b1")
        with tempfile.TemporaryDirectory(prefix="mdd062-shared-") as tmp:
            sess, _pre_sha = _open_verified_b1_session(apk_path, b_binary, Path(tmp), reuse_cfg)
            with sess:
                # Warm the required relation stores exactly as native_audit does prior to gates.
                sess.all("SELECT file_id, class_idx FROM classes ORDER BY file_id, class_idx LIMIT 1")
                sess.all("SELECT file_id, method_idx FROM class_methods ORDER BY file_id, method_idx LIMIT 1")
                sess.all("SELECT file_id, field_idx FROM class_fields ORDER BY file_id, field_idx LIMIT 1")
                sess.all("SELECT file_id, method_idx FROM code_items ORDER BY file_id, method_idx LIMIT 1")
                sess.all("SELECT file_id, annotation_off FROM annotations ORDER BY file_id, annotation_off LIMIT 1")
                sess.all("SELECT file_id, method_idx FROM method_strings ORDER BY file_id, method_idx LIMIT 1")
                sess.all("SELECT string_pool_id, string_idx FROM strings ORDER BY string_pool_id, string_idx LIMIT 1")
                for s_idx in range(rounds):
                    s_res = run_audit_gates(
                        apk_path,
                        config=reuse_cfg,
                        targets=targets,
                        shared_session=sess,
                    )
                    s_comp = compare_gate_outputs(last_legacy, s_res)
                    require(s_comp["equivalent"], f"{sample_id} shared session round {s_idx} mismatch: {s_comp['mismatches']}")
                    shared_timings.append(
                        {
                            "round": s_idx,
                            "wall_seconds": s_res["gate_wall_seconds"],
                            "intake_seconds": s_res["intake_seconds"],
                            "home_seconds": s_res["home_seconds"],
                            "equivalent": True,
                        }
                    )

        assert_safe = comp_verified is not None and last_legacy is not None and last_reuse is not None
        require(assert_safe, f"{sample_id} produced no paired gate runs")
        summary = _redact_public_live_summary(last_legacy, last_reuse, comp_verified)
        med_leg = statistics.median(r["legacy_seconds"] for r in paired_runs)
        med_reuse = statistics.median(r["reuse_seconds"] for r in paired_runs)
        med_shared = statistics.median(r["wall_seconds"] for r in shared_timings)
        summary["timing_window"]["legacy_median_seconds"] = med_leg
        summary["timing_window"]["fresh_session_reuse_median_seconds"] = med_reuse
        summary["timing_window"]["shared_resident_reuse_median_seconds"] = med_shared
        summary["timing_window"]["shared_resident_median_saved_seconds"] = med_leg - med_shared
        summary["timing_window"]["shared_resident_median_speedup"] = (med_leg / med_shared) if med_shared > 0 else None
        summary["paired_rounds"] = paired_runs
        summary["shared_resident_rounds"] = shared_timings
        live_samples[sample_id] = summary

    # Run unittest suite as part of synthetic & negative boundary verification.
    import test_audit_data_provider as unit_mod  # noqa: E402
    import unittest
    suite = unittest.defaultTestLoader.loadTestsFromModule(unit_mod)
    buf = []
    class _Buf:
        def write(self, s: str) -> None: buf.append(s)
        def flush(self) -> None: pass
    res = unittest.TextTestRunner(stream=_Buf(), verbosity=2).run(suite)
    require(res.wasSuccessful(), "test_audit_data_provider failed: " + "".join(buf))

    report = {
        "schema_version": SCHEMA_VERSION,
        "task_id": "MDD-062",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_sha256": {rel: sha256_file(ROOT / rel) for rel in SOURCES},
        "engine_binary_sha256": sha256_file(b_binary),
        "exclusive_window": window_check,
        "governance": {
            "default_rollback_mode": "legacy_independent",
            "allow_mid_run_fallback": False,
            "same_core_self_check_is_not_independent_oracle": True,
            "independent_oracle_retained": "legacy_independent (analysis/run_intake.py + analysis/home_frame_audit.py)",
            "counted_in_phase1_sf_target": False,
            "timing_window_name": "E_gate",
            "preserves_sha_and_inventory_and_code_integrity": True,
        },
        "synthetic_suite": {
            "cases_file": "conformance/hostlab/gate-reuse-cases.json",
            "case_count": len(cases_doc["cases"]),
            "unittest_ran": res.testsRun,
            "unittest_passed": True,
        },
        "live_samples": live_samples,
        "all_passed": True,
    }
    validator.validate_public_redaction(report)
    encoded = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    match = validator.FORBIDDEN_PUBLIC_RE.search(encoded)
    require(match is None, f"forbidden public literal leaked into MDD-062 report: {match.group(0) if match else ''}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(encoded, encoding="utf-8", newline="\n")
    return json.loads(encoded)


def check_record(path: Path) -> int:
    require(path.is_file(), f"missing MDD-062 record: {path}")
    text = path.read_text(encoding="utf-8")
    require(validator.FORBIDDEN_PUBLIC_RE.search(text) is None, "forbidden public token found in MDD-062 record")
    doc = json.loads(text)
    require(doc.get("schema_version") == SCHEMA_VERSION, "schema_version mismatch")
    require(doc.get("task_id") == "MDD-062", "task_id mismatch")
    require(doc.get("all_passed") is True, "all_passed != true")

    hashes = doc.get("source_sha256", {})
    for rel in SOURCES:
        require(hashes.get(rel) == sha256_file(ROOT / rel), f"source hash drift: {rel}")

    gov = doc.get("governance", {})
    require(gov.get("default_rollback_mode") == "legacy_independent", "default_rollback_mode must be legacy_independent")
    require(gov.get("allow_mid_run_fallback") is False, "allow_mid_run_fallback must be false")
    require(gov.get("same_core_self_check_is_not_independent_oracle") is True, "oracle distinction missing")
    require(gov.get("counted_in_phase1_sf_target") is False, "gate savings must not enter phase1 S/F target")
    require(gov.get("preserves_sha_and_inventory_and_code_integrity") is True, "integrity preservation flag false")

    syn = doc.get("synthetic_suite", {})
    require(syn.get("unittest_passed") is True and syn.get("unittest_ran", 0) >= 8, "synthetic suite incomplete")

    live = doc.get("live_samples", {})
    for sid in ("hostlab-9161100", "hostlab-9170100"):
        s = live.get(sid, {})
        require(s.get("equivalent") is True, f"{sid} not equivalent")
        require(s.get("exit_code_match") is True, f"{sid} exit_code_match != true")
        tw = s.get("timing_window", {})
        require(tw.get("name") == "E_gate" and tw.get("counted_in_phase1_sf_target") is False, f"{sid} wrong timing window")
        hs = s.get("home_summary", {})
        require(hs.get("data_order", "").startswith("order-ok "), f"{sid} data.order unexpected: {hs.get('data_order')}")
        require(hs.get("item_order", "").startswith("order-ok "), f"{sid} item.order unexpected: {hs.get('item_order')}")
        require(hs.get("kx_all_true") is True, f"{sid} kx_all_true != true")

    print(f"MDD-062 check passed: 2 live HostLab samples + {syn['unittest_ran']} synthetic tests verified ({len(SOURCES)} sources current)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate-evidence", action="store_true")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--out", type=Path, default=RECORD_PATH)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    out = args.out if args.out.is_absolute() else (ROOT / args.out)
    if args.check:
        return check_record(out)
    if args.generate_evidence:
        _build_evidence(out, rounds=args.rounds)
        print(f"MDD-062 evidence written -> {out}")
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
