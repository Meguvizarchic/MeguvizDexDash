"""Stand-ins for the checkpoint tests and for the record generator: HostLab's own batch executor (the frozen
`analysis_batch.py`, hash-checked by hostlab_test_support.load_frozen) driven by a scripted MCP client that answers
the way the engine's MCP server does. Nothing here is imported by the adapters.

`FakeDexsql` is a stand-in. It proves what the executor and the adapters do with answers of the real shape; it does
not prove what the engine answers. test_checkpoint_live_engine.py puts the same flows to the real binary.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import re
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import hostlab_test_support as support
import install_meguvizdexdash as installer
import provider

ROOT = support.ROOT
FIXTURES = ROOT / "tests/fixtures/generated"
APK_A = FIXTURES / "multidex-deflated.apk"
APK_B = FIXTURES / "multidex-stored.apk"
DEX_FILES = "SELECT file_id,entry_name FROM dex_files ORDER BY file_id"
NUMBERS = "SELECT n FROM numbers ORDER BY n"
NUMBERS_TOTAL = 7


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _cells(row: list) -> list:
    return [{"type": "utf8" if isinstance(value, str) else "uint64", "value": str(value)} for value in row]


class FakeDexsql:
    """The MCP calls HostLab's Session makes, answered from tables. `snapshot_manifest` is computed from the real bytes
    of the input, and the session handles change on every open, as the real engine's do."""

    def __init__(self, *, numbers: int = NUMBERS_TOTAL):
        self.queries: "dict[str, tuple[list[str], list[list]]]" = {
            DEX_FILES: (["file_id", "entry_name"], [[0, "classes.dex"], [1, "classes2.dex"]]),
            NUMBERS: (["n"], [[n] for n in range(numbers)]),
        }
        self.rules: "list[tuple[str, tuple[list[str], list[list]]]]" = [
            ("FROM classes WHERE descriptor", (["file_id", "descriptor"], [[0, "Lfoo;"]])),
            ("FROM class_methods WHERE method_name", (["file_id", "descriptor"], [[0, "Lfoo;->bar()V"]])),
        ]
        self.calls: "list[tuple[str, dict]]" = []
        self.hooks: "list[Callable[[str, dict], Any]]" = []
        self.open_edit: "Callable[[dict], dict] | None" = None  # rewrites the answer to open_dataset
        self.opens = 0

    def reset(self) -> None:
        self.calls.clear()

    def sql_calls(self, needle: str = "") -> "list[dict]":
        return [args for name, args in self.calls if name == "query" and needle in args["sql"][0]]

    def _table(self, sql: str):
        if sql in self.queries:
            return self.queries[sql]
        for needle, table in self.rules:
            if needle in sql:
                return table
        return None

    def answer(self, name: str, arguments: dict) -> "tuple[bool, dict]":
        self.calls.append((name, json.loads(json.dumps(arguments))))
        for hook in self.hooks:
            outcome = hook(name, arguments)
            if outcome is not None:
                return outcome
        if name == "open_dataset":
            self.opens += 1
            path = Path(arguments["inputs"][0])
            content = "sha256:" + sha256_file(path)
            key = "sha256:" + hashlib.sha256(("snapshot|" + content).encode()).hexdigest()
            token = hashlib.sha256(f"{self.opens}|{path}".encode()).hexdigest()
            body = {"dataset_id": "dataset-" + token, "has_dex": True, "cache": "memory_dataset", "diagnostics": [],
                           "snapshot_id": "snapshot-" + token[::-1], "scope_id": "sha256:" + token,
                           "snapshot_manifest": {"snapshot_content_key": key, "snapshot_id": "snapshot-" + token[::-1],
                                                 "sources": [{"byte_length": str(path.stat().st_size), "content_id": content,
                                                              "input_kind": "apk-zip", "input_ordinal": "0",
                                                              "occurrence_id": "x", "origin_display": str(path)}]}}
            return False, (self.open_edit(body) if self.open_edit else body)
        if name == "close_dataset":
            return False, {"closed": True}
        if name == "query":
            sql = arguments["sql"][0]
            table = self._table(sql)
            if table is None:
                return True, {"error": {"kind": "invalid_query", "code": "UNSUPPORTED_QUERY", "message": "no such statement"}}
            columns, rows = table
            limit_in_sql = re.search(r"\sLIMIT\s+(\d+)\s*$", sql)
            if limit_in_sql:
                rows = rows[:int(limit_in_sql[1])]
            offset, limit = arguments.get("offset", 0), arguments["limit"]
            page = rows[offset:offset + limit]
            cursor = offset + len(page) if offset + len(page) < len(rows) else None
            statement = {"columns": [{"name": c, "data_type": "utf8", "nullable": False} for c in columns], "kind": "query",
                         "next_offset": cursor, "offset": offset, "rows": [_cells(r) for r in page], "sql": sql,
                         "statement_index": 0, "total_rows": len(rows), "truncated": cursor is not None}
            return False, {"dataset_id": arguments["dataset_id"], "diagnostics": [], "statements": [statement], "timing": None}
        if name == "get_manifest":
            return False, {"package": "fixture.app", "next_offset": None}
        if name == "decode":
            return False, {"methods": [{"smali": ".method bar()V\n.end method\n", "next_offset": None, "file_id": 0,
                                        "method_idx": 1, "code_units": 1}]}
        return True, {"error": {"kind": "invalid_input", "message": "unknown tool " + name}}

    def client(self, params: Any = None) -> "FakeClient":
        return FakeClient(self)


class FakeClient:
    def __init__(self, server: FakeDexsql):
        self.server = server

    async def __aenter__(self) -> "FakeClient":
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    async def call_tool(self, name: str, arguments: dict, *args: Any, **kwargs: Any) -> Any:
        failed, body = self.server.answer(name, arguments)
        return SimpleNamespace(content=[SimpleNamespace(text=json.dumps(body))], is_error=failed)


def worker_lost_after(n: int, error: "dict | None" = None) -> Callable[[str, dict], Any]:
    """After `n` successful queries the engine answers every query with a WORKER_LOST error, as the engine reports
    a worker it lost (mdd-session ErrorCode::WorkerLost)."""
    seen = {"queries": 0}
    body = error or {"error": {"kind": "internal", "code": "WORKER_LOST", "message": "the worker was lost",
                               "dataset_closed": True}}

    def hook(name: str, arguments: dict) -> Any:
        if name != "query":
            return None
        seen["queries"] += 1
        return (True, body) if seen["queries"] > n else None

    return hook


@contextlib.contextmanager
def _installed(modules: "dict[str, types.ModuleType]"):
    saved = {key: sys.modules.get(key) for key in modules}
    sys.modules.update(modules)
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value


def load_batch(state: Path, server: FakeDexsql) -> types.ModuleType:
    """The frozen analysis_batch, wired to `server`. Its planner and paging modules are the frozen ones; its MCP
    client, its `hostlab` module and its DexSQL installer are stand-ins."""
    mcp = types.ModuleType("mcp")
    mcp.Client = object  # type: ignore[attr-defined]
    client = types.ModuleType("mcp.client")
    stdio = types.ModuleType("mcp.client.stdio")
    stdio.StdioServerParameters = lambda **kw: SimpleNamespace(**kw)  # type: ignore[attr-defined]
    hostlab = types.ModuleType("hostlab")
    hostlab.STATE = Path(state)  # type: ignore[attr-defined]
    hostlab.ROOT = Path(state)  # type: ignore[attr-defined]
    hostlab.digest = sha256_file  # type: ignore[attr-defined]
    installer = types.ModuleType("install_dexsql")
    installer.status = lambda: {"available": True, "version": "stand-in"}  # type: ignore[attr-defined]
    installer.verify = lambda: Path("dexsql-stand-in")  # type: ignore[attr-defined]
    stubs = {"mcp": mcp, "mcp.client": client, "mcp.client.stdio": stdio, "hostlab": hostlab, "install_dexsql": installer,
             "analysis_plan": support.load_frozen("analysis_plan"), "analysis_paging": support.load_frozen("analysis_paging")}
    module = support.load_frozen("analysis_batch", stubs)
    module.Client = server.client  # type: ignore[attr-defined]
    return module


def run(module: types.ModuleType, apk: Path, request: dict, *, sample: "dict | None" = None, resume: "dict | None" = None,
        checkpoint: "Callable | None" = None, roots: "list | None" = None) -> dict:
    """analysis_batch.execute, as HostLab's `run_batch` calls it."""
    return asyncio.run(module.execute(apk, request, roots=roots or [Path(apk).parent], sample=sample, resume=resume,
                                      checkpoint=checkpoint))


def normalized(report: dict) -> dict:
    """A report without the wall-clock fields, for comparing two runs of the same work."""
    text = json.dumps(report, sort_keys=True)
    text = re.sub(r'"(elapsed_ms|prepare_ms|execute_ms)": [0-9.e+-]+', r'"\1": 0', text)
    return json.loads(text)


def sample_of(apk: Path) -> dict:
    return {"sha256": sha256_file(apk), "version_code": 1}


# ---- the provider's view of the engine ---------------------------------------------------------------------------------

class Setup(SimpleNamespace):
    """A pinned stand-in engine and a configuration that routes to it. `plan` is provider.plan under both."""

    def plan(self, request: dict, **options: Any) -> dict:
        return provider.plan(request, self.config, legacy=self.legacy, engine_status=self.status, **options)


def engine_setup(directory: Path, *, fake: "support.FakeEngine | None" = None, content: bytes = b"stand-in engine 1",
                 platform_name: "str | None" = None, **engine_config: Any) -> Setup:
    """`platform_name` fixes the platform recorded in the engine's identity (the record generator needs a record that does
    not depend on the machine)."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    binary, manifest, fake = support.pin_binary(directory, fake or support.FakeEngine(), content)
    if platform_name is not None:
        manifest.unlink()
        installer.pin(binary, manifest, runner=fake, platform_name=platform_name)
    document = {"schema": provider.CONFIG_SCHEMA, "native_engine": provider.ENGINE,
                provider.ENGINE: {"profile_policy": "allow_unadmitted", **engine_config}}
    config = provider.parse_config(document)
    status = installer.status(binary, manifest, fake, deep=True, **({"platform_name": platform_name} if platform_name else {}))
    return Setup(config=config, status=status, legacy=support.load_frozen("analysis_plan"), binary=binary,
                 manifest=manifest, fake=fake, directory=directory)


def engine_request(*tasks: dict, backend: str = provider.ENGINE, **extra: Any) -> dict:
    return support.request(*tasks, backend=backend, **extra)


# ---- a request run attempt after attempt through the frozen executor, with the adapter wired in ---------------------------

import checkpoint_adapter as adapter  # noqa: E402


def hex_id(number: int) -> str:
    return f"{number:032x}"


class Attempt(SimpleNamespace):
    pass


class Flow:
    """One request on one source. Each `attempt` is a fresh call of analysis_batch.execute with a fresh capture and
    writer (a new process, as far as the adapter is concerned); the stand-in server and the directories persist."""

    def __init__(self, directory: Path, request: dict, *, apk: Path = APK_A, revision: "str | None" = "rev-1",
                 server: "FakeDexsql | None" = None, setup: "Setup | None" = None, rule_catalog: "str | None" = None,
                 catalog_epoch: "int | None" = None, client_factory: "Callable | None" = None):
        self.directory = Path(directory)
        self.setup = setup or engine_setup(self.directory / "engine")
        self.request, self.apk, self.revision = request, Path(apk), revision
        self.server = server or FakeDexsql()
        self.client_factory = client_factory or self.server.client  # the real engine can stand here (see the live test)
        self.batch = load_batch(self.directory, self.server)
        self.sha = sha256_file(self.apk)
        self.plan = self.setup.plan(request)
        self.engine = self.plan["provider"]["engine"]
        self.expected = adapter.expected_identity(self.plan, self.setup.config, request=request, sha256=self.sha,
                                                  revision=revision, legacy=self.setup.legacy,
                                                  rule_catalog_sha256=rule_catalog, catalog_epoch=catalog_epoch)
        self.ns = provider.namespaces(self.directory / "state", self.engine, self.setup.config)
        provider.ensure_namespaces(self.ns, self.engine)
        self.root = adapter.checkpoint_root(self.ns)
        self.attempts = 0

    def frozen_request(self, claim: "dict | None" = None) -> dict:
        shaped = {k: v for k, v in self.request.items() if k not in ("negotiation", "resume")}
        shaped["backend"] = "dexsql"  # the frozen planner knows sqlite/dexsql; the engine's name is the adapter's
        if claim is not None:
            shaped["resume"] = {k: claim[k] for k in ("run_id", "attempt", "request_id")}
        return shaped

    def attempt(self, *, resume: "adapter.Resume | None" = None, hint: "str | None" = None, wire_capture: bool = True,
                apk: "Path | None" = None, expected: "dict | None" = None, sha: "str | None" = None,
                checkpoint: bool = True) -> Attempt:
        self.attempts += 1
        origin = {"run_id": 100 + self.attempts, "attempt": 1, "request_id": hex_id(self.attempts)}
        source = Path(apk or self.apk)
        capture = adapter.OpenCapture(sha256=sha or sha256_file(source), resume=resume) if wire_capture else None
        self.batch.Client = capture.wrap(self.client_factory) if capture else self.client_factory
        writer = adapter.CheckpointWriter(self.root, expected or self.expected, self.request, origin=origin,
                                          capture=capture, resume=resume, legacy=self.setup.legacy)
        if hint:
            writer.note(hint)
        claim = resume.claim if resume is not None else None
        report = run(self.batch, source, self.frozen_request(claim), sample={"sha256": sha or sha256_file(source)},
                     resume=resume.seed() if resume is not None else None, checkpoint=writer if checkpoint else None)
        return Attempt(report=report, writer=writer, capture=capture, origin=origin, document=writer.document)

    def resume(self, previous: Attempt, *, expected: "dict | None" = None, claim: "dict | None" = "origin") -> "adapter.Resume":
        return adapter.import_checkpoint(previous.document, expected or self.expected,
                                         claim=previous.origin if claim == "origin" else claim, legacy=self.setup.legacy)
