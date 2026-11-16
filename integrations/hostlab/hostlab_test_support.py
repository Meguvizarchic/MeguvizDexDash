"""Shared pieces of the provider tests: the frozen HostLab sources as an oracle, a stand-in engine, and a
small JSON Schema checker. Not imported by the provider itself.

The frozen sources are loaded only after their SHA-256 equals the one recorded in
conformance/corpus/hostlab/source-8782f43/manifest.json, so a changed oracle fails the run instead of
silently changing what is compared.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import sys
import types
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FROZEN = ROOT / "conformance/corpus/hostlab/source-8782f43"
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import install_meguvizdexdash as installer  # noqa: E402


def _frozen_digest(name: str) -> str:
    manifest = json.loads((FROZEN / "manifest.json").read_text(encoding="utf-8"))
    wanted = f"conformance/corpus/hostlab/source-8782f43/{name}.py"
    return next(item["sha256"] for item in manifest["files"] if item.get("path") == wanted)


@contextlib.contextmanager
def _modules(extra: dict[str, types.ModuleType]):
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


def load_frozen(name: str, stubs: "dict[str, types.ModuleType] | None" = None) -> types.ModuleType:
    path = FROZEN / f"{name}.py"
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != _frozen_digest(name):
        raise AssertionError(f"{path.name} is not the frozen HostLab source recorded in its manifest")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    with _modules(dict(stubs or {})):
        exec(compile(data, str(path), "exec"), module.__dict__)
    return module


def frozen_batch(state: Path) -> types.ModuleType:
    """HostLab's analysis_batch, with its MCP client and `hostlab` module replaced by empty stand-ins
    (neither is used by the gate functions that the tests call)."""
    mcp = types.ModuleType("mcp")
    mcp.Client = object  # type: ignore[attr-defined]
    client = types.ModuleType("mcp.client")
    stdio = types.ModuleType("mcp.client.stdio")
    stdio.StdioServerParameters = object  # type: ignore[attr-defined]
    hostlab = types.ModuleType("hostlab")
    hostlab.STATE = state  # type: ignore[attr-defined]
    hostlab.ROOT = state  # type: ignore[attr-defined]
    stubs = {"mcp": mcp, "mcp.client": client, "mcp.client.stdio": stdio, "hostlab": hostlab,
             "analysis_plan": load_frozen("analysis_plan"), "install_dexsql": load_frozen("install_dexsql")}
    stubs["analysis_paging"] = load_frozen("analysis_paging")
    return load_frozen("analysis_batch", stubs)


# ---- analysis requests shared by the tests and the record generator -----------------------------------------

def request(*tasks, backend="auto", **extra):
    return {"schema": 1, "backend": backend, "tasks": list(tasks), **extra}


QUERY = {"id": "q", "operation": "query", "sql": "SELECT file_id FROM dex_files ORDER BY file_id", "dialect": "dexsql"}
SQLITE_QUERY = {"id": "sq", "operation": "query", "sql": "SELECT 1", "dialect": "sqlite"}
LOCATE = {"id": "l", "operation": "locate", "kind": "class", "name": "Lfoo;"}
DECODE = {"id": "d", "operation": "decode", "method": "Lfoo;->bar()V"}
INFO = {"id": "i", "operation": "info"}
REFS = {"id": "r", "operation": "refs", "kind": "string", "target": "x", "detail": "methods"}
REFS_SITES = {"id": "rs", "operation": "refs", "kind": "string", "target": "x", "detail": "sites"}


# ---- a stand-in engine ---------------------------------------------------------------------------------

TOOLS = ("open_dataset", "list_datasets", "close_dataset", "list_tables", "describe_table", "query", "decode",
         "get_manifest")
BUILD_ID = "source-sha256:" + "ab" * 32


class FakeEngine:
    """Answers `version`, `capabilities` and `mcp` the way the real binary does. `calls` records every run,
    so a test can show that a file was never run."""

    def __init__(self, *, version: str = "0.1.0-test", build_id: str = BUILD_ID, admitted: bool = False,
                 tools: "tuple[str, ...]" = TOOLS, dialects: "list | None" = None, server_version: "str | None" = None,
                 scope: str = "unqualified development build", fail: "str | None" = None, product: str = "MeguvizDexDash"):
        self.version, self.build_id, self.admitted, self.tools = version, build_id, admitted, tuple(tools)
        self.server_version = server_version or version
        self.scope, self.fail, self.product = scope, fail, product
        self.dialects = dialects if dialects is not None else [
            {"name": "native-v1", "revision": "1", "features": ["layers:metadata,structure"]},
            {"name": "dexsql-0.1.0", "revision": "0.1.0", "features": ["hostlab-contract-relations"]},
            {"name": "dexsql-0.1.1", "revision": "0.1.1", "features": ["hostlab-contract-relations"]}]
        self.calls: list[list[str]] = []

    def profiles(self) -> list[dict[str, Any]]:
        digest = "cd" * 32 if self.admitted else None
        return [{"name": "mdd-native-v1", "admitted": self.admitted, "conformance_manifest_sha256": digest},
                {"name": "mdd-header-inspection-dev-v1", "admitted": False, "conformance_manifest_sha256": None}]

    def __call__(self, argv, stdin=None, timeout=30.0):
        self.calls.append([Path(argv[0]).name, *argv[1:]])
        if self.fail == argv[1]:
            return 1, b"", b"boom"
        command = argv[1]
        if command == "version":
            return 0, json.dumps({"product": self.product, "engine_version": self.version, "build_id": self.build_id,
                                  "implementation_scope": self.scope}).encode(), b""
        if command == "capabilities":
            return 0, json.dumps({"schema_version": "mdd.capabilities.v1", "product": "MeguvizDexDash",
                                  "engine_version": self.version, "build_id": self.build_id,
                                  "profiles": self.profiles(), "sql_dialects": self.dialects}).encode(), b""
        if command == "mcp":
            first = {"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": "meguvizdexdash",
                                                                          "version": self.server_version}}}
            tools = [{"name": name, "inputSchema": {"type": "object", "title": name}} for name in self.tools]
            second = {"jsonrpc": "2.0", "id": 2, "result": {"tools": tools}}
            return 0, (json.dumps(first) + "\n" + json.dumps(second) + "\n").encode(), b""
        return 2, b"", b"usage"


def make_binary(directory: Path, content: bytes = b"stand-in engine 1", name: str = "meguvizdexdash.exe") -> Path:
    path = directory / name
    path.write_bytes(content)
    return path


def pin_binary(directory: Path, engine: "FakeEngine | None" = None, content: bytes = b"stand-in engine 1",
               name: str = "meguvizdexdash.exe") -> tuple[Path, Path, FakeEngine]:
    """A binary file, a manifest pinning it, and the stand-in that answers for it."""
    engine = engine or FakeEngine()
    binary = make_binary(directory, content, name)
    manifest = directory / "manifest.json"
    installer.pin(binary, manifest, runner=engine)
    return binary, manifest, engine


# ---- a small JSON Schema checker (the subset the provider schema uses) ----------------------------------------

def schema_valid(schema: dict, value: Any) -> bool:
    if "const" in schema and (value != schema["const"] or type(value) is not type(schema["const"])):
        return False
    if "enum" in schema and not any(value == option and type(value) is type(option) for option in schema["enum"]):
        return False
    kinds = schema.get("type")
    if kinds is not None:
        names = kinds if isinstance(kinds, list) else [kinds]
        checks = {"object": lambda v: isinstance(v, dict), "array": lambda v: isinstance(v, list),
                  "string": lambda v: isinstance(v, str), "null": lambda v: v is None,
                  "integer": lambda v: type(v) is int, "boolean": lambda v: type(v) is bool,
                  "number": lambda v: type(v) in (int, float)}
        if not any(checks[name](value) for name in names):
            return False
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 1 << 60):
            return False
    if type(value) is int:
        if value < schema.get("minimum", -(1 << 60)) or value > schema.get("maximum", 1 << 60):
            return False
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 1 << 60):
            return False
        if schema.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
            return False
        if "items" in schema and not all(schema_valid(schema["items"], item) for item in value):
            return False
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if any(key not in value for key in schema.get("required", [])):
            return False
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            return False
        for key, sub in properties.items():
            if key in value and not schema_valid(sub, value[key]):
                return False
    if "oneOf" in schema and sum(schema_valid(option, value) for option in schema["oneOf"]) != 1:
        return False
    return True
