"""Shared pieces of the MDD-052 surface checks: the frozen HostLab sources as an oracle, a relational stand-in
for an engine, and the recording of what the frozen scan reads. Not imported by the provider itself.

The frozen sources are loaded only after their SHA-256 equals the one recorded next to them (the corpus
manifest, or this task's manifest, which `conformance/hostlab/surface_import_sources.py --check` ties to
evidence/hostlab_verification.json). A changed oracle fails the run instead of silently changing what is
compared.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3
import subprocess
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import hostlab_test_support as support  # noqa: E402

FROZEN = support.FROZEN
SURFACE_SOURCES = ROOT / "conformance/hostlab/surface-source-8782f43"
FIXTURES = ROOT / "tests/fixtures/surface"
GENERATED = FIXTURES / "generated"
GOLDENS = ROOT / "conformance/hostlab/surface-goldens.json"
# The relations the scan reads, with the columns of conformance/manifests/relations.json (and their kinds, so that the
# text an engine returns is stored as the number it is).
RELATIONS = {
    "dex_files": (("file_id", "INTEGER"), ("entry_name", "TEXT"), ("byte_len", "INTEGER"), ("dex_version", "TEXT"),
                  ("checksum", "INTEGER"), ("signature_hex", "TEXT")),
    "classes": (("file_id", "INTEGER"), ("class_def_idx", "INTEGER"), ("class_idx", "INTEGER"), ("descriptor", "TEXT"),
                ("superclass_descriptor", "TEXT")),
    "class_fields": (("file_id", "INTEGER"), ("class_idx", "INTEGER"), ("class_descriptor", "TEXT"), ("field_idx", "INTEGER"),
                     ("field_name", "TEXT"), ("field_descriptor", "TEXT")),
    "class_methods": (("file_id", "INTEGER"), ("class_idx", "INTEGER"), ("class_descriptor", "TEXT"), ("method_idx", "INTEGER"),
                      ("method_name", "TEXT"), ("method_descriptor", "TEXT")),
    "code_items": (("file_id", "INTEGER"), ("method_idx", "INTEGER"), ("insns_off", "INTEGER"), ("insns_size", "INTEGER")),
    "method_calls": (("file_id", "INTEGER"), ("method_idx", "INTEGER"), ("callee_method_idx", "INTEGER"), ("method", "TEXT"),
                     ("callee", "TEXT"), ("callee_class", "TEXT")),
}


@contextlib.contextmanager
def _modules(extra: "dict[str, types.ModuleType]"):
    saved = {key: sys.modules.get(key) for key in extra}
    sys.modules.update(extra)
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value


def _digest(manifest: Path, relative: str) -> str:
    items = json.loads(manifest.read_text(encoding="utf-8"))["files"]
    return next(item["sha256"] for item in items if item.get("path") == relative)


def _load(path: Path, name: str, expected: str, stubs: "dict[str, types.ModuleType] | None") -> types.ModuleType:
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise AssertionError(f"{path.name} is not the frozen HostLab source recorded in its manifest")
    module = types.ModuleType(name)
    module.__file__ = str(path)  # surface_workers hashes its own file into RULE_SHA256
    # the module is registered while it runs: `dataclass` looks its own module up in sys.modules
    with _modules({**(stubs or {}), name: module}):
        exec(compile(data, str(path), "exec"), module.__dict__)
    return module


def load_corpus(name: str, stubs: "dict[str, types.ModuleType] | None" = None) -> types.ModuleType:
    """A source of conformance/corpus/hostlab/source-8782f43, checked against that corpus's manifest."""
    expected = _digest(FROZEN / "manifest.json", f"conformance/corpus/hostlab/source-8782f43/{name}.py")
    return _load(FROZEN / f"{name}.py", name, expected, stubs)


def load_surface_source(name: str, stubs: "dict[str, types.ModuleType] | None" = None) -> types.ModuleType:
    """One of the three sources imported by conformance/hostlab/surface_import_sources.py."""
    expected = _digest(SURFACE_SOURCES / "manifest.json", f"conformance/hostlab/surface-source-8782f43/{name}.py")
    return _load(SURFACE_SOURCES / f"{name}.py", name, expected, stubs)


def _stub(name: str, **attributes: Any) -> types.ModuleType:
    module = types.ModuleType(name)
    for key, value in attributes.items():
        setattr(module, key, value)
    return module


@dataclass
class Frozen:
    """The frozen HostLab modules the surface path is made of, wired together the way HostLab imports them."""

    workers: types.ModuleType
    audit_common: types.ModuleType
    priority: types.ModuleType
    graph: types.ModuleType
    session_module: types.ModuleType
    surface: types.ModuleType
    cli: "types.ModuleType | None" = None

    @property
    def unsupported(self) -> type:
        return self.graph.UnsupportedAudit


def load_frozen_surface(state: Path, a0_binary: "Path | None" = None) -> Frozen:
    """Everything `native_surface.scan` needs. With `a0_binary`, the frozen `native_cli.CliSession` is loaded too and
    drives that binary (the reference engine), so the report it produces is the original path's own."""
    workers = load_surface_source("surface_workers", {
        "dexq_workers": _stub("dexq_workers", init_worker=None, load_dex=None, norm_proto=None)})  # the Python-parser path is not used
    audit_common = load_surface_source("audit_common")
    priority = load_surface_source("priority_analysis", {
        "analyze": _stub("analyze"), "hostlab": _stub("hostlab", STATE=state, ROOT=state),
        "surface_workers": workers, "source_snapshot": _stub("source_snapshot"),
        "snapshot_transport": _stub("snapshot_transport"), "runner_resources": _stub("runner_resources"),
        "audit_common": audit_common})
    cli = None
    if a0_binary is not None:
        batch = support.frozen_batch(state)
        verified = _stub("install_dexsql", verify=lambda: Path(a0_binary))
        process_control = _stub("process_control", terminate_tree=lambda process: process.kill())
        cli = load_corpus("native_cli", {"analysis_batch": batch, "install_dexsql": verified,
                                                  "process_control": process_control})
        session_module = load_corpus("native_session", {"native_cli": cli})
    else:
        session_module = load_corpus("native_session", {"native_cli": _stub("native_cli", CliSession=object)})
    graph = load_corpus("native_graph", {"native_session": session_module})
    surface = load_corpus("native_surface", {"native_graph": graph, "native_session": session_module,
                                                      "surface_workers": workers})
    return Frozen(workers, audit_common, priority, graph, session_module, surface, cli)


# ---- a relational stand-in for an engine ---------------------------------------------------------------------

class FactSession:
    """The session interface the frozen scan consumes (`files`, `apk`, `rows`), answered from relation tables held in
    SQLite. Cells come back as text or None, as the frozen CliSession returns them (it reads `hex(CAST(x AS TEXT))`),
    so the frozen code sees what it sees from the real transport.

    SQLite's LIKE is case-insensitive for ASCII, as the reference engine's is; the frozen code relies on that only as
    a candidate superset. `statements` records every statement and its rows."""

    def __init__(self, apk: "str | Path", tables: "dict[str, list[list]]", files: "dict[int, str] | None" = None):
        self.apk = Path(apk)
        self.statements: list[dict] = []
        self.queries = 0
        self._db = sqlite3.connect(":memory:")
        for name, typed in RELATIONS.items():
            columns = [c for c, _ in typed]
            rows = tables.get(name, [])
            self._db.execute(f"CREATE TABLE {name} ({','.join(c + ' ' + k for c, k in typed)})")
            for row in rows:
                if len(row) != len(columns):
                    raise ValueError(f"{name}: a row has {len(row)} cells, expected {len(columns)}")
                self._db.execute(f"INSERT INTO {name} VALUES ({','.join('?' * len(columns))})", row)
        self.files = dict(files) if files is not None else {int(r[0]): r[1] for r in
                                                           self._db.execute("SELECT file_id,entry_name FROM dex_files ORDER BY file_id")}

    def rows(self, sql: str, *, page_size: int = 1000, max_rows: int = 500000, max_bytes: int = 128 * 1024 * 1024):
        if "ORDER BY" not in sql.upper():
            raise ValueError("native audit requires stable ordering")
        cursor = self._db.execute(sql)
        names = [d[0] for d in cursor.description]
        out = [dict(zip(names, (None if v is None else str(v) for v in row))) for row in cursor.fetchall()]
        if len(out) > max_rows:
            raise RuntimeError("native audit exceeded its complete row budget")
        self.statements.append({"sql": sql, "columns": names, "rows": [[r[n] for n in names] for r in out]})
        self.queries += 1
        yield from out

    def all(self, sql: str, **bounds: Any) -> list:
        return list(self.rows(sql, **bounds))

    def close(self) -> None:
        self._db.close()

    def __del__(self) -> None:
        try:
            self._db.close()
        except Exception:  # noqa: BLE001 - nothing to report from a finalizer
            pass


def record_relations(run_rows) -> "dict[str, list[list]]":
    """Read each relation whole through `run_rows(sql) -> list of rows (lists of text/None)`, in the order of all its columns."""
    tables: dict[str, list[list]] = {}
    for name, typed in RELATIONS.items():
        columns = ",".join(c for c, _ in typed)
        tables[name] = [list(row) for row in run_rows(f"SELECT {columns} FROM {name} ORDER BY {columns}")]
    return tables


class ReplaySession:
    """Answers exactly the statements that were recorded, in order, with the rows that were recorded. A statement that
    was not recorded, or arrives out of order, is an error: the frozen scan cannot be fed anything but what was read."""

    def __init__(self, apk: "str | Path", files: "dict[int, str]", statements: "list[dict]"):
        self.apk, self.files = Path(apk), dict(files)
        self._statements = list(statements)
        self._next = 0
        self.queries = 0

    def rows(self, sql: str, **_bounds: Any):
        if self._next >= len(self._statements):
            raise AssertionError("the scan issued a statement that was not recorded: " + sql[:120])
        recorded = self._statements[self._next]
        if recorded["sql"] != sql:
            raise AssertionError(f"statement {self._next} differs from the recorded one: {sql[:200]!r} != {recorded['sql'][:200]!r}")
        self._next += 1
        self.queries += 1
        columns = recorded["columns"]
        for row in recorded["rows"]:
            yield dict(zip(columns, row))

    def finished(self) -> bool:
        return self._next == len(self._statements)


class RecordingSession:
    """Wraps a session and keeps every statement the code under test issues, with the rows it received."""

    def __init__(self, inner: Any):
        self._inner = inner
        self.statements: list[dict] = []

    @property
    def files(self):
        return self._inner.files

    @property
    def apk(self):
        return self._inner.apk

    @property
    def queries(self):
        return self._inner.queries

    def rows(self, sql: str, **bounds: Any):
        collected = []
        for row in self._inner.rows(sql, **bounds):
            collected.append(row)
            yield row
        self.statements.append({"sql": sql, "columns": list(collected[0]) if collected else None,
                                "rows": [[r[k] for k in r] for r in collected]})

    def all(self, sql: str, **bounds: Any) -> list:
        return list(self.rows(sql, **bounds))


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sha256_text(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def run_a0(binary: Path, args: "list[str]") -> subprocess.CompletedProcess:
    return subprocess.run([str(binary), "--threads", "1", *args], capture_output=True, timeout=300)


# ---- what the tests share -------------------------------------------------------------------------------------------

_CACHE: dict = {}


def golden() -> dict:
    if "golden" not in _CACHE:
        _CACHE["golden"] = json.loads(GOLDENS.read_text(encoding="utf-8"))
    return _CACHE["golden"]


def expected() -> dict:
    if "expected" not in _CACHE:
        _CACHE["expected"] = json.loads((FIXTURES / "expected.json").read_text(encoding="utf-8"))
    return _CACHE["expected"]


def frozen() -> Frozen:
    """The frozen modules, loaded once (the reference binary is not needed to run them over a stand-in)."""
    if "frozen" not in _CACHE:
        import tempfile
        state = tempfile.mkdtemp(prefix="mdd052-state-")
        _CACHE["frozen"] = load_frozen_surface(Path(state))
    return _CACHE["frozen"]


def host():
    import surface_provider as provider
    f = frozen()
    return provider.Host(f.workers, f.audit_common.resource_fingerprints, f.unsupported, f.surface.scan,
                         f.priority.resource_changes, f.priority.verdict)


def facts(name: str, edit: Any = None, apk: "str | Path | None" = None) -> FactSession:
    """A stand-in for the engine holding the relations the reference engine returned for fixture `name`."""
    import copy
    scenario = golden()["scenarios"][name]
    tables = copy.deepcopy(scenario["relations"])
    if edit is not None:
        edit(tables)
    return FactSession(apk or GENERATED / name, tables)


def renumber(tables: "dict[str, list[list]]", mapping: "dict[int, int]") -> None:
    """Give the engine's local file ids other numbers, consistently in every relation."""
    for rows in tables.values():
        for row in rows:
            row[0] = str(mapping[int(row[0])])

