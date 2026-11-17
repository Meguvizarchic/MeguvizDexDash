"""HostLab's class/method surface and raw fingerprints, served by the MeguvizDexDash engine (MDD-052).
Integration layer; standard library only. Nothing here knows about the engine's internals: it reads the engine's
facts through the `serve` stream and the original bytes from the archive, and it leaves HostLab's rules to HostLab.

What moves, and what does not
* The scan (`native_surface.scan`) is ported: the same facts, read per DEX file, selected by the same two-layer
  filter (the engine's case-insensitive LIKE as a candidate superset, HostLab's exact classifier as the gate), put
  in the same order, with the same de-duplication, and summarised by HostLab's own `surface_workers.summarize`.
  The report is HostLab's report, not a new one: its SHA-256 (`report_digest`) is what the checks compare.
* Raw bytes are the engine's offsets into the original DEX member and the original ZIP members. No Smali, IR or Java
  text stands in for them, and the `decode` tool is never called.
* HostLab's classification (`family`, `FAMILIES`, `PROTOCOLS`), the cross-version `compare`, `resource_changes` and
  `verdict` stay HostLab's: they are injected through `Host`, not copied.
* The independent intake/home gates are not touched here; `surface_gate.py` runs them unchanged and times them whole.

The switch
`surface_provider` is its own setting (`dexsql`, the default and the rollback value, or `meguvizdexdash`). It does
not depend on `native_engine` of provider.py: the engine may serve only the surface, or only the structural audit.
With `dexsql` the original functions are called and the engine is never started.

Cache schemas never mix: a result of this provider is stored only under the engine's own namespace, in a directory
claimed by a schema marker, keyed by source SHA-256, rule hash, engine build and dialect, and a stored entry that
does not say exactly that is refused, never read and never replaced.

Differences from the original path (each one is tested; the reason is in the test's name)
* a family class in a DEX file in which no family class has a method is fingerprinted as an empty class; the
  original raises KeyError in `summarize` for it;
* every row of every relation read (classes, class_fields, class_methods, method_calls and code_items) is checked to
  belong to the DEX file that was asked for; the bytes read from the archive are bound to the engine's facts by the
  recorded DEX header fields (length, version, checksum, signature) before any offset is used. The binding compares
  those fields; it does not recompute adler32 or SHA-1 over the body. Whole-file identity is the APK SHA-256 checked
  before and after the run, and the ZIP reader checks each member's CRC;
* a method_idx that names two methods of one DEX file, or two code rows for one method, is refused (the original
  keeps the last one silently);
* the engine's answers are admitted only when the stream says they are complete; a partial, truncated or errored
  statement is an error, never an empty or shorter result;
* `scan_execution.backend` says which engine did the work.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import queue
import re
import subprocess
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence

import provider as base

SCHEMA = "mdd.hostlab-surface.v1"
CONFIG_SCHEMA = "mdd.hostlab-surface-config.v1"
EVIDENCE_SCHEMA = "mdd.hostlab-surface-evidence.v1"
STORE_MARKER = "mdd.hostlab-surface-store.v1"
LEGACY = "dexsql"
ENGINE = base.ENGINE
PROVIDERS = (LEGACY, ENGINE)
STORE_DIRECTORY = "surface"
DEX_VERSIONS = (b"035", b"036", b"037", b"038", b"039", b"040")
MAX_DEX_BYTES = 128 * 1024 * 1024
COMPOSER = "Landroidx/compose/runtime/Composer;"
VOLATILE = ("scan_execution", "sample")  # fields of the report that are not part of its identity
ENGINE_PROTOCOL = "mdd.cli-stream.v1"
LINE_BUDGET = 64 * 1024 * 1024
# The engine's debug build (Windows) aborts the whole process with a stack overflow (0xC00000FD) on a condition whose
# parentheses nest about ten deep, or on a long chain of ORs. Nine levels are answered; ten are not. The provider
# refuses anything deeper before sending it, and caps the OR terms so the balanced tree cannot grow past that depth.
MAX_SQL_DEPTH = 9
MAX_OR_TERMS = 64


# ---- errors ---------------------------------------------------------------------------------------------

class SurfaceError(RuntimeError):
    """A failure of the surface scan that is not 'the original refuses this input' (that is `Host.unsupported`)."""


class SourceMismatch(SurfaceError):
    """The bytes, the engine's facts or the file asked for do not describe the same source."""


class IncompleteFacts(SurfaceError):
    """The engine did not say that an answer is complete."""


class EngineFailure(SurfaceError):
    """The engine reported an error. `detail` has the shape provider.classify_failure reads."""

    def __init__(self, message: str, detail: "dict | None" = None):
        super().__init__(message)
        self.detail = detail


class CacheMismatch(SurfaceError):
    pass


# ---- the switch -------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class SurfaceConfig:
    """`surface_provider` is the one switch: `dexsql` is the rollback value."""

    surface_provider: str = LEGACY

    def effective(self) -> dict[str, Any]:
        return {"schema": CONFIG_SCHEMA, "surface_provider": self.surface_provider}

    def digest(self) -> str:
        return base.digest_of(self.effective())


def parse_surface_config(obj: Any) -> SurfaceConfig:
    """Strict: an unknown key, a wrong type or an unknown provider is an error, never a default."""
    if not isinstance(obj, dict):
        raise base.ConfigError("surface config must be an object")
    extra = set(obj) - {"schema", "surface_provider"}
    if extra:
        raise base.ConfigError(f"surface config has unsupported keys: {sorted(extra)}")
    if obj.get("schema") != CONFIG_SCHEMA:
        raise base.ConfigError("surface config.schema must be " + CONFIG_SCHEMA)
    chosen = obj.get("surface_provider", LEGACY)
    if not isinstance(chosen, str) or chosen not in PROVIDERS:
        raise base.ConfigError(f"surface config.surface_provider must be one of {list(PROVIDERS)}")
    return SurfaceConfig(chosen)


def load_surface_config(source: "dict | str | os.PathLike[str] | None" = None, environ: "dict | None" = None) -> SurfaceConfig:
    """A dict, a file, `HOSTLAB_SURFACE_CONFIG`, or the default (which keeps the original path)."""
    env = os.environ if environ is None else environ
    if source is None and env.get("HOSTLAB_SURFACE_CONFIG"):
        source = env["HOSTLAB_SURFACE_CONFIG"]
    if source is None:
        return SurfaceConfig()
    if isinstance(source, dict):
        return parse_surface_config(source)
    path = Path(source)
    if path.stat().st_size > 64 * 1024:
        raise base.ConfigError("the surface configuration exceeds 64 KiB")
    try:
        return parse_surface_config(json.loads(path.read_text(encoding="utf-8")))
    except ValueError as error:
        if isinstance(error, base.ConfigError):
            raise
        raise base.ConfigError("the surface configuration is not JSON") from None


# ---- HostLab's side -----------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Host:
    """What the provider takes from HostLab instead of copying: the family rules, the exact-membership classifier, the
    comparison functions, the original resource fingerprints and the refusal type of the original scan."""

    workers: Any  # surface_workers: FAMILIES, PROTOCOLS, RULE_SHA256, family, summarize, compare
    resource_fingerprints: Callable[[Any], dict]  # audit_common.resource_fingerprints
    unsupported: type  # native_graph.UnsupportedAudit
    legacy_scan: "Callable[[Any], dict] | None" = None  # native_surface.scan
    resource_changes: "Callable[[dict, dict], dict] | None" = None  # priority_analysis.resource_changes
    verdict: "Callable[..., dict] | None" = None  # priority_analysis.verdict


def default_host() -> Host:
    """HostLab's modules by name, for use inside HostLab's own tools directory."""
    workers = importlib.import_module("surface_workers")
    graph = importlib.import_module("native_graph")
    surface = importlib.import_module("native_surface")
    common = importlib.import_module("audit_common")
    priority = importlib.import_module("priority_analysis")
    return Host(workers, common.resource_fingerprints, graph.UnsupportedAudit, surface.scan,
                priority.resource_changes, priority.verdict)


# ---- the two-layer filter, as SQL text -------------------------------------------------------------------------

def literal(value: str) -> str:
    if any(c in value for c in "\r\n\0"):
        raise ValueError("audit SQL literal contains unsupported control characters")
    return "'" + value.replace("'", "''") + "'"


def in_list(values: Sequence[str]) -> str:
    return ",".join(literal(value) for value in values)


def prefix(column: str, value: str) -> str:
    # LIKE is case-insensitive: it only ever selects a superset. The exact, case-sensitive classifier runs in Python.
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return column + " LIKE " + literal(escaped + "%") + " ESCAPE '\\'"


def sql_depth(sql: str) -> int:
    """The deepest nesting of parentheses in a statement (0 when there are none). The engine's stack limit is about
    this depth, so it is measured on the statement actually sent, not on one fragment of it."""
    depth = deepest = 0
    for character in sql:
        if character == "(":
            depth += 1
            deepest = max(deepest, depth)
        elif character == ")":
            depth -= 1
    return deepest


def balanced_or(terms: Sequence[str]) -> str:
    """`terms` joined by OR as a balanced tree, not a chain: the same condition, but of logarithmic depth. The engine
    (debug build, Windows) aborts the whole process with a stack overflow on a chain of 20 terms, and on a condition
    whose nested parentheses reach about ten levels."""
    if not terms:
        raise SurfaceError("an OR condition needs at least one term")
    if len(terms) > MAX_OR_TERMS:
        raise SurfaceError(f"an OR condition of {len(terms)} terms is deeper than the engine's stack admits (cap {MAX_OR_TERMS})")
    if len(terms) == 1:
        return terms[0]
    middle = len(terms) // 2
    return "(" + balanced_or(terms[:middle]) + " OR " + balanced_or(terms[middle:]) + ")"


def family_filter(workers: Any, column: str) -> str:
    """A superset of the exact family test: every family prefix, and the legacy dynamic-page names under bplus.
    The original writes `bplus AND (dynamic OR following OR feed)`; the same condition is written here as three legs
    of `bplus AND word`, so that no leaf of the balanced tree is itself nested."""
    prefixes = {p for values in workers.FAMILIES.values() for p in values}
    prefixes.update({"Lcom/bilibili/app/comment3/ui/", "Lkntr/common/comment", "Lkntr/app/following/"})
    legs = ["(" + prefix(column, "Lcom/bilibili/bplus/") + " AND lower(" + column + ") LIKE '%" + word + "%')"
            for word in ("dynamic", "following", "feed")]
    return balanced_or([prefix(column, p) for p in sorted(prefixes)] + legs)


def protocol_filter(workers: Any, column: str) -> str:
    return "(" + column + " IN (" + in_list(list(workers.PROTOCOLS.values())) + ") OR " + column + " LIKE 'Lcom/bapis/%Moss;')"


# ---- small parsers -----------------------------------------------------------------------------------------------

def member(value: Any) -> tuple[str, str, str]:
    """`Lowner;->name(args)ret` as (owner, name, '(args)ret')."""
    if not isinstance(value, str) or "->" not in value:
        raise SurfaceError(f"not a member descriptor: {value!r}")
    owner, tail = value.split("->", 1)
    if "(" not in tail:
        raise SurfaceError(f"not a method descriptor: {value!r}")
    name, proto = tail.split("(", 1)
    return owner, name, "(" + proto


def field_type(descriptor: Any) -> str:
    """The type of a field from `Lowner;->name:Ltype;`."""
    if not isinstance(descriptor, str) or ":" not in descriptor:
        raise SurfaceError(f"not a field descriptor: {descriptor!r}")
    return descriptor.split(":", 1)[1]


def legacy_body_order(proto: str, unsupported: type) -> str:
    """The order in which the original fingerprint visits overloads: arguments separated by spaces."""
    parameters, result = proto[1:].split(")", 1)
    tokens = re.findall(r"\[*(?:[ZBSCIJFD]|L[^;]+;)", parameters)
    if "".join(tokens) != parameters:
        raise unsupported("method prototype cannot preserve the legacy bytecode fingerprint ordering")
    return "(" + " ".join(tokens) + ")" + result


def as_int(value: Any, what: str) -> int:
    """A non-negative integer from an engine cell (a number or its decimal text); anything else is an error."""
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str) and value.isascii() and value.isdigit():
        return int(value)
    raise SurfaceError(f"{what} is not a non-negative integer: {value!r}")


def as_text(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise SurfaceError(f"{what} is not text: {value!r}")
    return value


def numeric_key(name: str) -> int:
    return int(re.sub(r"\D", "", name) or 1)


# ---- the DEX files of a session -----------------------------------------------------------------------------------

@dataclass(frozen=True)
class DexIdentity:
    """A local `file_id` with the identity of the bytes it stands for."""

    file_id: int
    entry_name: str
    byte_len: int
    version: str
    checksum: int
    signature_hex: str


IDENTITY_SQL = "SELECT file_id,entry_name,byte_len,dex_version,checksum,signature_hex FROM dex_files ORDER BY file_id"


def read_identities(session: Any) -> dict[int, DexIdentity]:
    found: dict[int, DexIdentity] = {}
    for row in session.rows(IDENTITY_SQL):
        identity = DexIdentity(as_int(row["file_id"], "dex_files.file_id"), as_text(row["entry_name"], "dex_files.entry_name"),
                               as_int(row["byte_len"], "dex_files.byte_len"), as_text(row["dex_version"], "dex_files.dex_version"),
                               as_int(row["checksum"], "dex_files.checksum"), as_text(row["signature_hex"], "dex_files.signature_hex"))
        if identity.file_id in found:
            raise SourceMismatch(f"file_id {identity.file_id} names two DEX files")
        found[identity.file_id] = identity
    if len({i.entry_name for i in found.values()}) != len(found):
        raise SourceMismatch("two DEX files of one dataset have the same entry name")
    return found


def bind_dex(raw: bytes, identity: DexIdentity, unsupported: type) -> None:
    """The bytes read from the archive are the ones the engine's facts were read from: the recorded header fields
    (length, version, checksum, signature) must agree before any offset is applied to them. This compares those fields;
    it does not recompute adler32 or SHA-1 over the body. Whole-file identity rests on the APK SHA-256 checked before
    and after the run, and on the ZIP reader's per-member CRC."""
    if raw[:4] != b"dex\n" or raw[4:7] not in DEX_VERSIONS:
        raise unsupported("native raw-code fingerprint DEX version is not admitted")
    problems = []
    if len(raw) != identity.byte_len:
        problems.append("length")
    if raw[4:7].decode("ascii") != identity.version:
        problems.append("version")
    if int.from_bytes(raw[8:12], "little") != identity.checksum:
        problems.append("checksum")
    if raw[12:32].hex() != identity.signature_hex:
        problems.append("signature")
    if problems:
        raise SourceMismatch(f"{identity.entry_name} (file_id {identity.file_id}): the archive's bytes differ from the engine's facts in "
                             + ", ".join(problems))


# ---- the scan ---------------------------------------------------------------------------------------------------------

def per_file(session: Any, files: Sequence[int], select: str, condition: str, order: str, *, group: "str | None" = None,
             **bounds: Any) -> Iterator[tuple[int, dict]]:
    """Rows of each DEX file in turn, with the file they were asked for. A row that belongs to another file is refused."""
    for file in files:
        sql = select + " WHERE file_id=" + str(file) + " AND (" + condition + ")"
        if group:
            sql += " GROUP BY " + group
        sql += " ORDER BY file_id," + order
        depth = sql_depth(sql)
        if depth > MAX_SQL_DEPTH:
            raise SurfaceError(f"the audit SQL nests {depth} parentheses; above {MAX_SQL_DEPTH} the engine's debug build "
                               "overflows its stack, so the condition is refused before it is sent")
        for row in session.rows(sql, **bounds):
            if as_int(row["file_id"], "file_id") != file:
                raise SourceMismatch(f"a row of file_id {row['file_id']} came back for file_id {file}")
            yield file, row


def code_locations(session: Any, methods: dict[int, dict[int, tuple]]) -> dict[tuple[int, int], tuple[int, int]]:
    """(file_id, method_idx) -> (byte offset, byte length) of the instructions; absent for a method without a body."""
    result: dict[tuple[int, int], tuple[int, int]] = {}
    for file, values in methods.items():
        if not values:
            continue
        lower, upper = min(values), max(values)
        sql = ("SELECT file_id,method_idx,insns_off,insns_size FROM code_items WHERE file_id=" + str(file)
               + " AND method_idx BETWEEN " + str(lower) + " AND " + str(upper) + " ORDER BY file_id,method_idx")
        for row in session.rows(sql, max_rows=200000):
            if as_int(row["file_id"], "code_items.file_id") != file:
                raise SourceMismatch(f"a code row of file_id {row['file_id']} came back for file_id {file}")
            index = as_int(row["method_idx"], "code_items.method_idx")
            if not lower <= index <= upper:
                raise RuntimeError("native code location is outside the requested method range")
            if index in values:
                if (file, index) in result:
                    raise SurfaceError(f"two code rows for method_idx {index} of file_id {file}")
                result[(file, index)] = (as_int(row["insns_off"], "code_items.insns_off"),
                                         as_int(row["insns_size"], "code_items.insns_size") * 2)
    return result


def scan_parts(session: Any, host: Host, apk: "str | Path", *, evidence: "dict | None" = None) -> list[dict]:
    """The per-DEX parts of the original scan, in HostLab's order: numeric DEX order, then class definition order."""
    workers, unsupported = host.workers, host.unsupported
    identities = read_identities(session)
    names = sorted((i.entry_name for i in identities.values()), key=numeric_key)
    if any("#" in n for n in names):
        raise unsupported("DEX 041 container fingerprint equivalence is not admitted")
    numeric = [numeric_key(name) for name in names]
    if len(numeric) != len(set(numeric)):
        raise unsupported("ambiguous numeric DEX ordering in fingerprint input")
    ordinal = {file: names.index(identity.entry_name) for file, identity in identities.items()}
    files = sorted(identities)
    records: dict[tuple[int, str], dict] = {}
    methods: dict[int, dict[int, tuple]] = {}
    handles: dict[tuple[int, str, str, str], int] = {}
    classes_sql = "SELECT file_id,class_def_idx,descriptor,superclass_descriptor FROM classes"
    for file, row in per_file(session, files, classes_sql, family_filter(workers, "descriptor"), "class_def_idx"):
        owner = as_text(row["descriptor"], "classes.descriptor")
        group = workers.family(owner)
        if group is None:
            continue
        if (file, owner) in records:
            raise unsupported("duplicate class definition in native surface scan")
        records[(file, owner)] = {"file_id": ordinal[file], "family": group, "class": owner,
                                  "superclass": row["superclass_descriptor"], "fields": [], "methods": []}
    fields_sql = "SELECT file_id,class_descriptor,field_name,field_descriptor FROM class_fields"
    for file, row in per_file(session, files, fields_sql, family_filter(workers, "class_descriptor"), "class_idx,field_idx"):
        key = (file, as_text(row["class_descriptor"], "class_fields.class_descriptor"))
        if key not in records:
            continue
        records[key]["fields"].append((row["field_name"], field_type(row["field_descriptor"])))
    methods_sql = "SELECT file_id,class_descriptor,method_idx,method_name,method_descriptor FROM class_methods"
    for file, row in per_file(session, files, methods_sql, family_filter(workers, "class_descriptor"), "class_idx,method_idx"):
        index, owner = as_int(row["method_idx"], "class_methods.method_idx"), as_text(row["class_descriptor"], "class_methods.class_descriptor")
        if (file, owner) not in records:
            continue
        _, name, proto = member(row["method_descriptor"])
        if (file, owner, name, proto) in handles:
            raise unsupported("duplicate method definition in native surface scan")
        if index in methods.get(file, {}):
            raise SurfaceError(f"method_idx {index} of file_id {file} names two methods")
        records[(file, owner)]["methods"].append((name, proto))
        methods.setdefault(file, {})[index] = (owner, name, proto)
        handles[(file, owner, name, proto)] = index
    code = code_locations(session, methods)
    raw_of: dict[int, bytes] = {}
    if methods:
        with zipfile.ZipFile(apk) as archive:
            members = [i.filename for i in archive.infolist()]
            for file in methods:
                identity = identities[file]
                if members.count(identity.entry_name) != 1:
                    raise SourceMismatch(f"the archive has {members.count(identity.entry_name)} members named {identity.entry_name}")
                info = archive.getinfo(identity.entry_name)
                if info.file_size > MAX_DEX_BYTES:
                    raise unsupported("single DEX fingerprint input exceeds admitted memory budget")
                raw_of[file] = archive.read(info)
                bind_dex(raw_of[file], identity, unsupported)
    for (file, owner), record in records.items():
        raw = raw_of.get(file, b"")
        digest = hashlib.sha256()
        record["fields"].sort()
        record["methods"].sort()
        for name, proto in sorted(record["methods"], key=lambda m: (m[0], legacy_body_order(m[1], unsupported))):
            digest.update((name + proto).encode())
            index = handles[(file, owner, name, proto)]
            position = code.get((file, index))
            if position is not None:
                offset, size = position
                if offset < 0 or offset + size > len(raw) or offset % 2:
                    raise RuntimeError("native code interval is outside the verified DEX")
                digest.update(raw[offset:offset + size])
            if evidence is not None:
                evidence["methods"].append(_method_evidence(identities[file], ordinal[file], owner, name, proto, index, position, raw))
        record["method_bodies_sha256"] = digest.hexdigest()
        record["compose_signatures"] = [name + proto for name, proto in record["methods"] if COMPOSER in proto]
    edges: set = set()
    counts: dict[tuple[int, str, str], int] = {}
    condition = family_filter(workers, "callee_class") + " OR " + protocol_filter(workers, "callee_class")
    calls_sql = "SELECT file_id,method,callee,COUNT(*) AS n FROM method_calls"
    protocols = list(workers.PROTOCOLS.items())
    for file, row in per_file(session, files, calls_sql, condition, "method,callee", group="file_id,method,callee",
                              max_rows=1000000, max_bytes=256 * 1024 * 1024):
        caller, name, proto = member(row["method"])
        callee, target_name, target_proto = member(row["callee"])
        group = next((key for key, value in protocols if value == callee), None)
        group = group or ("unregistered_protocol:" + callee if callee.startswith("Lcom/bapis/") and callee.endswith("Moss;")
                          else workers.family(callee))
        if group is None:
            continue
        source = workers.family(caller) or "external_or_unknown"
        edges.add((ordinal[file], source, caller, name, proto, group, callee, target_name, target_proto))
        counts[(ordinal[file], source, group)] = counts.get((ordinal[file], source, group), 0) + as_int(row["n"], "method_calls.n")
    definitions: list[tuple] = []
    definitions_sql = "SELECT file_id,method_descriptor FROM class_methods"
    registered = {value for _, value in protocols}
    for file, row in per_file(session, files, definitions_sql, protocol_filter(workers, "class_descriptor"), "class_idx,method_idx"):
        owner, name, proto = member(row["method_descriptor"])
        if owner not in registered and not (owner.startswith("Lcom/bapis/") and owner.endswith("Moss;")):
            continue
        group = next((key for key, value in protocols if value == owner), "unregistered_protocol:" + owner)
        definitions.append((ordinal[file], group, name, proto))
    if evidence is not None:
        evidence["dex"] = [{"file_id": ordinal[f], "entry_name": identities[f].entry_name, "byte_len": identities[f].byte_len,
                            "checksum": identities[f].checksum, "signature_hex": identities[f].signature_hex}
                           for f in sorted(identities, key=lambda f: ordinal[f])]
    return [{"rule_sha256": workers.RULE_SHA256, "classes": [r for r in records.values() if r["file_id"] == file],
             "edges": sorted(e for e in edges if e[0] == file),
             "edge_counts": [(a, b, count) for (f, a, b), count in sorted(counts.items()) if f == file],
             "protocol_definitions": [r for r in definitions if r[0] == file]} for file in range(len(names))]


def _method_evidence(identity: DexIdentity, ordinal: int, owner: str, name: str, proto: str, index: int,
                     position: "tuple[int, int] | None", raw: bytes) -> dict:
    """What a method's body is, stated: 'none' (no code item), 'empty' (a code item without instructions) or 'present'."""
    if position is None:
        return {"file_id": ordinal, "entry_name": identity.entry_name, "class": owner, "name": name, "proto": proto,
                "method_idx": index, "body": "none", "insns_off": None, "insns_bytes": None, "insns_sha256": None}
    offset, size = position
    body = raw[offset:offset + size]
    return {"file_id": ordinal, "entry_name": identity.entry_name, "class": owner, "name": name, "proto": proto,
            "method_idx": index, "body": "present" if size else "empty", "insns_off": offset, "insns_bytes": size,
            "insns_sha256": hashlib.sha256(body).hexdigest()}


# ---- resources ----------------------------------------------------------------------------------------------------------

def is_fingerprinted(name: str) -> bool:
    return name == "resources.arsc" or (name.startswith("res/") and name.endswith(".xml"))


def resource_fingerprints(apk: "str | Path", *, evidence: "dict | None" = None) -> dict[str, str]:
    """SHA-256 of the original, decompressed bytes of resources.arsc and every res/**/*.xml (CRC-checked by the ZIP reader).
    A name that occurs twice keeps its last occurrence, as in the original; every occurrence is listed in `evidence`."""
    result: dict[str, str] = {}
    seen: list[dict] = []
    with zipfile.ZipFile(apk) as archive:
        for entry in archive.infolist():
            if not is_fingerprinted(entry.filename):
                continue
            digest = hashlib.sha256()
            size = 0
            with archive.open(entry) as stream:
                for chunk in iter(lambda: stream.read(65536), b""):
                    digest.update(chunk)
                    size += len(chunk)
            result[entry.filename] = digest.hexdigest()
            seen.append({"name": entry.filename, "bytes": size, "sha256": digest.hexdigest()})
    if evidence is not None:
        evidence["resources"] = seen
        evidence["resource_duplicates"] = sorted({s["name"] for s in seen if sum(t["name"] == s["name"] for t in seen) > 1})
    return result


# ---- identity of a report ------------------------------------------------------------------------------------------------

def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def report_digest(report: dict) -> str:
    """SHA-256 of a surface report without its timing and sample fields."""
    return hashlib.sha256(canonical_json({k: v for k, v in report.items() if k not in VOLATILE}).encode()).hexdigest()


def first_difference(a: Any, b: Any, path: str = "") -> "str | None":
    """Where two reports first differ, as a coordinate such as `class_records[3].method_bodies_sha256`, or None.
    A tuple and a list holding the same things are the same thing (a report that went through JSON)."""
    sequences = (list, tuple)
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b), key=str):
            if key not in a or key not in b:
                return f"{path}.{key}" if path else str(key)
            found = first_difference(a[key], b[key], f"{path}.{key}" if path else str(key))
            if found:
                return found
        return None
    if isinstance(a, sequences) and isinstance(b, sequences):
        for index, (left, right) in enumerate(zip(a, b)):
            found = first_difference(left, right, f"{path}[{index}]")
            if found:
                return found
        return f"{path}[{min(len(a), len(b))}]" if len(a) != len(b) else None
    return None if type(a) is type(b) and a == b else (path or "<root>")


def restore_shapes(report: dict) -> dict:
    """JSON turns tuples into lists; HostLab's `compare` tells `[...]` from `(...)`. A stored report gets its tuples back
    so that a stored report compares with a fresh one exactly as two fresh ones do."""
    def signatures(path: dict) -> None:
        path["signatures"] = [tuple(s) for s in path["signatures"]]

    for path in report.get("protocol_paths", {}).values():
        signatures(path)
    for twin in report.get("protocol_twins", []):
        signatures(twin["java_path"])
        signatures(twin["kotlin_path"])
    for page in report.get("page_path_matrix", {}).values():
        for path in page.get("protocols", {}).values():
            signatures(path)
    for key in ("unclassified_protocol_callers", "invoke_edges", "protocol_definitions"):
        if key in report:
            report[key] = [tuple(item) for item in report[key]]
    for record in report.get("class_records", []):
        record["fields"] = [tuple(f) for f in record["fields"]]
        record["methods"] = [tuple(m) for m in record["methods"]]
    return report


# ---- the engine's stream -----------------------------------------------------------------------------------------------------

def cell(value: Any) -> Any:
    """A cell of the stream as a Python value. Only the kinds the surface relations hold are admitted."""
    kind = value.get("t") if isinstance(value, dict) else None
    if kind == "null":
        return None
    if kind in ("u64", "i64") and isinstance(value.get("v"), str):
        return int(value["v"])
    if kind == "text" and isinstance(value.get("v"), str):
        return value["v"]
    raise SurfaceError(f"unsupported cell in the engine's stream: {value!r}")


class ServeSession:
    """HostLab's session interface (`files`, `apk`, `rows`) over `meguvizdexdash serve`: one dataset, one request per
    line, every answer framed by a terminal line that says whether it is complete. A statement's rows are handed over
    only after its terminal line says ok, complete, untruncated and of the snapshot that was opened."""

    def __init__(self, argv: Sequence[str], apk: "str | Path", *, env: "dict | None" = None, deadline_seconds: float = 900.0,
                 dialect: "str | None" = None, batch_rows: int = 1000):
        self.argv, self.apk, self.env = list(argv), Path(apk), env
        self.dialect, self.batch_rows = dialect, batch_rows
        self.deadline = time.monotonic() + deadline_seconds
        self.queries = 0
        self.opened: dict[str, Any] = {}
        self.files: dict[int, str] = {}
        self._lines: "queue.Queue[Any]" = queue.Queue(maxsize=64)
        self._closed = threading.Event()

    @classmethod
    def from_launch(cls, launched: base.Launch, apk: "str | Path", *, dialect: str, deadline_seconds: float = 900.0,
                    batch_rows: int = 1000) -> "ServeSession":
        argv = [launched.command, "serve", "--input", str(apk), "--dialect", dialect,
                "--deadline-ms", str(int(deadline_seconds * 1000))]
        return cls(argv, apk, env=launched.env, deadline_seconds=deadline_seconds, dialect=dialect, batch_rows=batch_rows)

    # -- lifecycle
    def __enter__(self) -> "ServeSession":
        self._errors = tempfile.TemporaryFile()
        try:
            self._process = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self._errors, env=self.env)
            self._reader = threading.Thread(target=self._read, daemon=True, name="hostlab-surface-reader")
            self._reader.start()
            opened = self._next()
            if opened.get("kind") != "opened" or opened.get("protocol") != ENGINE_PROTOCOL:
                raise IncompleteFacts("the engine did not open a " + ENGINE_PROTOCOL + " dataset")
            self.opened = opened["dataset"]
            if self.opened.get("layer_issues"):
                raise IncompleteFacts("the engine could not build every fact layer: " + canonical_json(self.opened["layer_issues"]))
            if self.dialect is not None and self.opened.get("sql_dialect") != self.dialect:
                raise IncompleteFacts(f"the engine opened the dialect {self.opened.get('sql_dialect')!r}, not {self.dialect!r}")
            self.files = {as_int(r["file_id"], "file_id"): r["entry_name"] for r in
                          self.rows("SELECT file_id,entry_name FROM dex_files ORDER BY file_id")}
            return self
        except BaseException:
            self._shutdown(clean=False)
            raise

    def __exit__(self, error: Any, *_: Any) -> None:
        self._shutdown(clean=error is None)

    def _shutdown(self, *, clean: bool) -> None:
        self._closed.set()
        process = getattr(self, "_process", None)
        try:
            if process is not None:
                if clean and process.poll() is None:
                    try:
                        process.stdin.write(b'{"op":"close"}\n')
                        process.stdin.flush()
                        process.stdin.close()
                    except OSError:
                        pass
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                if process.poll() is None:
                    process.kill()
                process.wait()
                for stream in (process.stdin, process.stdout):
                    try:
                        stream.close()
                    except OSError:
                        pass
                if clean and process.returncode:
                    raise SurfaceError(f"the engine exited with status {process.returncode}")
        finally:
            reader = getattr(self, "_reader", None)
            if reader is not None:
                reader.join(timeout=5)
            errors = getattr(self, "_errors", None)
            if errors is not None:
                errors.close()

    # -- the stream
    def _read(self) -> None:
        stream = self._process.stdout
        while not self._closed.is_set():
            try:
                line = stream.readline(LINE_BUDGET + 1)
            except (OSError, ValueError):
                line = RuntimeError("the engine's output could not be read")
            item: Any = line
            if isinstance(line, bytes) and len(line) > LINE_BUDGET:
                item = RuntimeError("a line of the engine's output exceeds its byte budget")
            while not self._closed.is_set():
                try:
                    self._lines.put(item, timeout=0.1)
                    break
                except queue.Full:
                    continue
            if not line or isinstance(item, Exception):
                return

    def _next(self) -> dict:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("the surface scan's deadline is exhausted")
        try:
            item = self._lines.get(timeout=remaining)
        except queue.Empty:
            self._process.kill()
            raise TimeoutError("the engine did not answer in time") from None
        if isinstance(item, Exception):
            raise item
        if not item:
            try:
                status = self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                status = None
            self._errors.seek(0)
            tail = self._errors.read()[-300:].decode("utf-8", "replace").strip()
            raise IncompleteFacts(f"the engine ended its output before the answer was complete (exit status {status}; {tail or 'no message'})")
        try:
            value = json.loads(item)
        except ValueError:
            raise IncompleteFacts("the engine wrote a line that is not JSON") from None
        if not isinstance(value, dict):
            raise IncompleteFacts("the engine wrote a line that is not an object")
        return value

    def _send(self, encoded: bytes) -> None:
        """Write one request with a bounded wait. A large statement can block once the pipe buffer is full and the
        engine has stopped reading stdin; that is stopped at the deadline and the engine is killed, not waited for
        forever. This is the only place the clean path waits on the engine without a bound otherwise."""
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("the surface scan's deadline is exhausted")
        failure: list[BaseException] = []

        def write() -> None:
            try:
                self._process.stdin.write(encoded)
                self._process.stdin.flush()
            except OSError as error:
                failure.append(error)

        writer = threading.Thread(target=write, daemon=True, name="hostlab-surface-writer")
        writer.start()
        writer.join(timeout=remaining)
        if writer.is_alive():
            self._process.kill()
            raise TimeoutError("the engine did not read the request in time")
        if failure:
            raise IncompleteFacts("the engine is gone") from None

    def rows(self, sql: str, *, page_size: int = 0, max_rows: int = 500000, max_bytes: int = 128 * 1024 * 1024) -> Iterator[dict]:
        """Runs the statement now and returns its rows once the whole answer has been checked."""
        if "ORDER BY" not in sql.upper():
            raise ValueError("native audit requires stable ordering")
        if page_size != 0:
            raise ValueError("the serve stream pages by batch_rows; page_size is not a field of the mdd.cli-stream.v1 request")
        self.queries += 1
        ident = f"r{self.queries}"
        request = {"id": ident, "sql": sql, "batch_rows": self.batch_rows, "max_rows": max_rows}
        encoded = (json.dumps(request) + "\n").encode()
        if len(encoded) > 256 * 1024:
            raise RuntimeError("native audit SQL exceeds its byte budget")
        self._send(encoded)
        columns: "list[str] | None" = None
        collected: list[dict] = []
        used = 0
        while True:
            line = self._next()
            kind = line.get("kind")
            if kind == "rejected":
                raise EngineFailure("the engine rejected the statement", {"error": line.get("error")})
            if line.get("id") != ident:
                raise IncompleteFacts(f"an answer for {line.get('id')!r} arrived for the request {ident!r}")
            if kind == "batch":
                batch = line["batch"]
                if columns is None:
                    columns = list(batch["columns"])
                    if len(columns) != len(set(columns)):
                        raise RuntimeError("ambiguous native audit columns")
                elif columns != batch["columns"]:
                    raise IncompleteFacts("the columns of one result changed between batches")
                for raw in batch["rows"]:
                    if len(raw) != len(columns):
                        raise RuntimeError("ambiguous native CLI row")
                    values = [cell(c) for c in raw]
                    used += sum(len(v.encode()) for v in values if isinstance(v, str))
                    if used > max_bytes:
                        raise RuntimeError("native audit exceeded its complete byte budget")
                    collected.append(dict(zip(columns, values)))
                continue
            if kind != "terminal":
                raise IncompleteFacts(f"unexpected line kind {kind!r} in the engine's stream")
            self._admit(line["terminal"], len(collected), max_rows)
            break
        return iter(collected)

    def _admit(self, terminal: dict, emitted: int, max_rows: int) -> None:
        """Only a complete, untruncated answer of the opened snapshot is a result."""
        if terminal.get("operation_status") != "ok":
            error = terminal.get("error")
            raise EngineFailure("the engine reported an error", {"error": error} if error else None)
        coverage, execution, response = terminal.get("coverage") or {}, terminal.get("execution") or {}, terminal.get("response") or {}
        problems = []
        if coverage.get("input") != "complete":
            problems.append("input coverage " + str(coverage.get("input")))
        if coverage.get("facts") != "complete":
            problems.append("fact coverage " + str(coverage.get("facts")))
        if execution.get("complete") is not True:
            problems.append("execution incomplete")
        if response.get("truncated") is not False or response.get("more_available") is not False:
            problems.append("result truncated")
        if str(response.get("emitted_rows")) != str(emitted):
            problems.append(f"emitted_rows {response.get('emitted_rows')} but {emitted} rows arrived")
        if emitted > max_rows:
            problems.append("row budget exceeded")
        if terminal.get("snapshot_id") != self.opened.get("snapshot_id"):
            problems.append("the answer is of another snapshot")
        if problems:
            raise IncompleteFacts("; ".join(problems))

    def all(self, sql: str, **bounds: Any) -> list:
        return list(self.rows(sql, **bounds))


# ---- the report ------------------------------------------------------------------------------------------------------------------

def build_report(session: Any, host: Host, apk: Path, *, backend: str, workers: int, evidence: "dict | None" = None) -> dict:
    """HostLab's surface report for the DEX files of `session`, plus the original resource fingerprints."""
    began = time.monotonic()
    report = host.workers.summarize(scan_parts(session, host, apk, evidence=evidence))
    report["resource_fingerprints"] = resource_fingerprints(apk, evidence=evidence)
    report["scan_execution"] = {"backend": backend, "workers": workers, "dex_files": len(session.files),
                                "elapsed_ms": (time.monotonic() - began) * 1000}
    return report


def source_block(apk: Path, sha256: str, session: Any = None) -> dict:
    opened = getattr(session, "opened", None) or {}
    return {"name": apk.name, "sha256": sha256, "bytes": apk.stat().st_size,
            "snapshot_id": opened.get("snapshot_id"), "scope_id": opened.get("scope_id")}


def envelope(report: dict, *, provider: str, source: dict, engine: "dict | None", evidence: "dict | None" = None) -> dict:
    result = {"schema": SCHEMA, "provider": provider, "engine": engine, "source": source,
              "rule_sha256": report.get("rule_sha256"), "report_sha256": report_digest(report), "report": report}
    if evidence is not None:
        result["evidence"] = dict(evidence, schema=EVIDENCE_SCHEMA)
    return result


def run_surface(apk: "str | Path", *, sha256: str, surface: SurfaceConfig, config: base.Config, host: Host, state: "str | Path",
                threads: int = 2, timeout: int = 900, legacy_session: "Callable[..., Any] | None" = None,
                runner: Any = None, environ: "dict | None" = None, evidence: bool = False, use_store: bool = False) -> dict:
    """The surface of `apk` by the provider that `surface` selects.

    `dexsql` calls the original scan on HostLab's own session and starts nothing else. `meguvizdexdash` starts the engine
    (verified again at this moment), reads the facts through its stream, holds them to the physical DEX inventory of the
    archive, and checks the source before and after. With `use_store`, a stored result of exactly this source, rule set,
    engine build and dialect is returned instead of a rescan, and a fresh one is stored. The evidence side-car is never
    stored: a run that asks for it does not touch the store."""
    apk = Path(apk).resolve(strict=True)
    if base.file_sha256(apk) != sha256:
        raise RuntimeError("native audit input does not match its immutable APK identity")
    if surface.surface_provider == LEGACY:
        if legacy_session is None or host.legacy_scan is None:
            raise SurfaceError("the original path needs HostLab's session and native_surface.scan")
        with legacy_session(apk, timeout=timeout, threads=2) as session:
            began = time.monotonic()
            report = host.legacy_scan(session)
            report["resource_fingerprints"] = host.resource_fingerprints(apk)
            report["scan_execution"] = {"backend": "dexsql", "workers": 2, "dex_files": len(session.files),
                                        "elapsed_ms": (time.monotonic() - began) * 1000}
        result = envelope(report, provider=LEGACY, source=source_block(apk, sha256), engine=None)
        saved = False
    else:
        inventory = base.archive_inventory(apk)
        launched = base.launch(config, threads=threads, timeout_seconds=timeout, state=Path(state), runner=runner, environ=environ)
        store = (SurfaceStore(launched.namespaces["reports"], launched.identity, host.workers.RULE_SHA256)
                 if use_store and not evidence else None)
        cached = store.load(sha256) if store is not None else None
        if cached is not None:
            return cached
        extra: "dict | None" = {"methods": [], "dex": [], "resources": [], "resource_duplicates": []} if evidence else None
        with ServeSession.from_launch(launched, apk, dialect=config.engine.dialect, deadline_seconds=timeout) as session:
            base.verify_inventory(inventory, session.files)
            report = build_report(session, host, apk, backend=ENGINE, workers=base.effective_threads(threads), evidence=extra)
            source = source_block(apk, sha256, session)
        result = envelope(report, provider=ENGINE, source=source, engine=launched.identity, evidence=extra)
        saved = store is not None
    if base.file_sha256(apk) != sha256:
        raise RuntimeError("native audit APK changed during analysis")
    if saved:
        try:
            store.save(result)
        except base.NamespaceCollision:  # another run stored its result meanwhile: the same one, or it is an error
            existing = store.load(sha256)
            if existing is None or existing["report_sha256"] != result["report_sha256"]:
                raise CacheMismatch("a different result of this source is already stored") from None
    return result


def cross_version(baseline: dict, target: dict, host: Host, *, context: "dict | None" = None) -> dict:
    """HostLab's own comparison of two surface reports: the changes, the resource changes and the verdict."""
    if host.resource_changes is None or host.verdict is None:
        raise SurfaceError("the host has no resource_changes/verdict")
    changes = host.workers.compare(baseline, target)
    resources = host.resource_changes(baseline, target)
    return {"changes": changes, "resource_changes": resources,
            "verdict": host.verdict(changes, target, context, resources, True)}


# ---- the store: this provider's results, apart from every other ------------------------------------------------------------------

class SurfaceStore:
    """Results of this provider below the engine's own reports directory. The directory is claimed by a schema marker,
    an entry is addressed by source, rule, engine build and dialect, and nothing that does not say so is read or replaced."""

    def __init__(self, reports: "str | Path", engine: dict, rule_sha256: str):
        self.root = Path(reports) / STORE_DIRECTORY
        self.engine, self.rule_sha256 = engine, rule_sha256
        self.root.mkdir(parents=True, exist_ok=True)
        marker = {"schema": STORE_MARKER, "entry_schema": SCHEMA}
        path = self.root / "SCHEMA.json"
        try:
            with path.open("x", encoding="utf-8") as stream:
                stream.write(json.dumps(marker, indent=2, sort_keys=True) + "\n")
        except FileExistsError:
            if json.loads(path.read_text(encoding="utf-8")) != marker:
                raise CacheMismatch(f"{self.root} is claimed by another cache schema") from None

    def key(self, sha256: str) -> str:
        return base.digest_of({"schema": SCHEMA, "source_sha256": sha256, "rule_sha256": self.rule_sha256,
                               "build_id": self.engine["build_id"], "binary_sha256": self.engine["binary_sha256"],
                               "dialect": self.engine["dialect"]["engine"]})

    def path(self, sha256: str) -> Path:
        return self.root / (self.key(sha256) + ".json")

    def save(self, entry: dict) -> Path:
        self.check(entry, entry["source"]["sha256"])
        return base.publish(self.root, self.key(entry["source"]["sha256"]) + ".json", entry)

    def load(self, sha256: str) -> "dict | None":
        path = self.path(sha256)
        if not path.is_file():
            return None
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            raise CacheMismatch(f"{path.name} is not JSON") from None
        self.check(entry, sha256)
        restore_shapes(entry["report"])
        return entry

    def check(self, entry: Any, sha256: str) -> None:
        if not isinstance(entry, dict) or entry.get("schema") != SCHEMA or entry.get("provider") != ENGINE:
            raise CacheMismatch("the entry is not a result of this provider's schema")
        if (entry.get("source") or {}).get("sha256") != sha256:
            raise CacheMismatch("the entry is of another source")
        if entry.get("rule_sha256") != self.rule_sha256 or (entry.get("report") or {}).get("rule_sha256") != self.rule_sha256:
            raise CacheMismatch("the entry was made under other rules")
        identity = entry.get("engine") or {}
        if (identity.get("build_id"), identity.get("binary_sha256"), (identity.get("dialect") or {}).get("engine")) != (
                self.engine["build_id"], self.engine["binary_sha256"], self.engine["dialect"]["engine"]):
            raise CacheMismatch("the entry was made by another engine build or dialect")
        if report_digest(entry["report"]) != entry.get("report_sha256"):
            raise CacheMismatch("the report does not match its recorded digest")
