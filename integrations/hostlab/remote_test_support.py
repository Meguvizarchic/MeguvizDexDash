"""Stand-ins for the remote-path tests and for the record generator: HostLab's frozen gateway (`remote_mcp.py`,
hash-checked by hostlab_test_support.load_frozen) with its MCP framework, its `hostlab` module, `subprocess` (so `gh`
runs nothing) and the modules it imports inside its tools replaced. Nothing here is imported by the adapters.

What this can show: the gateway's own code, the part that is in the frozen copy (argument checks, journal, lookup by
title, result paging, task summary, the arguments handed on to the modules that are not). What it cannot show: those
other modules (`version_matrix`, `remote_schedule`, `remote_artifacts`, `remote_dispatch`, ...). They are recorders here.
"""
from __future__ import annotations

import contextlib
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import hostlab_test_support as support
import remote_runner_adapter as remote

REPO = "jichuo1/innocent-lab-host-analysis"
WORKFLOW = "host-analysis.yml"
HEAD = "0123456789abcdef0123456789abcdef01234567"
REQUEST_ID = "ab" * 16
OTHER_REQUEST_ID = "cd" * 16


class ToolError(Exception):
    pass


class MCPServer:
    def __init__(self, name: str, instructions: str = ""):
        self.name, self.instructions, self.tools = name, instructions, {}

    def tool(self) -> Callable:
        def register(function: Callable) -> Callable:
            self.tools[function.__name__] = function
            return function
        return register

    def run(self, transport: str = "stdio") -> None:  # pragma: no cover - never started
        raise AssertionError("the stand-in server is not run")


def run_record(request_id: str = REQUEST_ID, *, run_id: int = 4242, attempt: int = 1, status: str = "completed",
               conclusion: "str | None" = "success", head: str = HEAD) -> dict:
    return {"id": run_id, "display_title": "hostlab-" + request_id, "status": status, "conclusion": conclusion,
            "html_url": f"https://github.example/runs/{run_id}", "head_sha": head, "run_attempt": attempt}


class FakeGitHub:
    """Answers the read-only `gh api` calls the gateway makes from a list of runs. A call that could dispatch is refused
    by the guard before it gets here (unless the test allows it) and every call is on record."""

    def __init__(self, runs: "list[dict] | None" = None, *, allow_mutation: bool = False):
        self.runs = list(runs or [])
        self.ran: "list[list[str]]" = []  # what got past the guard
        self.guard = remote.GhGuard(self._answer, allow_mutation=allow_mutation)

    def _answer(self, argv: "list[str]", input: Any = None, **kwargs: Any) -> Any:
        args = argv[1:]
        self.ran.append(list(args))
        path = args[1] if len(args) > 1 and args[0] == "api" else ""
        if path == f"repos/{REPO}/actions/workflows/{WORKFLOW}/runs?per_page=50":
            return _done(argv, {"workflow_runs": self.runs})
        prefix = f"repos/{REPO}/actions/runs/"
        if path.startswith(prefix):
            found = [r for r in self.runs if str(r["id"]) == path[len(prefix):]]
            if found:
                return _done(argv, found[0])
        return types.SimpleNamespace(returncode=1, stdout="", stderr="not found")

    @property
    def calls(self) -> "list[dict]":
        return self.guard.calls


def _done(argv: "list[str]", body: Any) -> Any:
    return types.SimpleNamespace(returncode=0, stdout=json.dumps(body), stderr="")


class Recorder:
    """The modules the gateway imports inside its tools. Each function records its call and returns what the test set."""

    NAMES = {
        "version_matrix": ("plan", "create", "advance", "recover", "prefetch", "compare", "load", "group_payload"),
        "remote_schedule": ("describe", "submit", "observe", "reconcile", "public_status"),
        "remote_artifacts": ("get",),
        "runner_group": ("collect",),
        "adaptive_schedule": ("observe",),
        "snapshot_transport": ("prepare",),
        "remote_dispatch": ("dispatch",),
        "source_snapshot": ("compare",),
    }

    def __init__(self, state: Path):
        self.state = Path(state)
        self.calls: "list[dict]" = []
        self.returns: "dict[str, Any]" = {
            "version_matrix.plan": {"plan": "stand-in"}, "version_matrix.create": {"matrix_id": "m1"},
            "version_matrix.advance": {"matrix_id": "m1", "jobs": []}, "version_matrix.recover": {"matrix_id": "m2"},
            "version_matrix.prefetch": {"prefetched": 0}, "version_matrix.compare": {"compared": 0},
            "remote_schedule.describe": {"schema": 1, "plan": "stand-in"},
            "remote_schedule.submit": {"request_id": REQUEST_ID, "dispatched": True},
            "remote_schedule.observe": None, "remote_schedule.reconcile": None,
            "remote_schedule.public_status": "queued",
            "snapshot_transport.prepare": {"snapshot_sha256": "00" * 32},
            "remote_dispatch.dispatch": {"dispatched": True, "status": "queued"},
            "source_snapshot.compare": {"status": "current"},
        }
        self.raises: "dict[str, BaseException]" = {}
        self.journal_at_dispatch: "list[dict]" = []
        self.artifact_files: "Callable[[str, dict], dict] | None" = None

    def module(self, name: str) -> types.ModuleType:
        module = types.ModuleType(name)
        for function in self.NAMES[name]:
            setattr(module, function, self._function(name, function))
        if name == "remote_artifacts":
            module.ArtifactError = type("ArtifactError", (ValueError,), {})  # type: ignore[attr-defined]
        return module

    def _function(self, module: str, function: str) -> Callable:
        label = f"{module}.{function}"

        def stand_in(*args: Any, **kwargs: Any) -> Any:
            self.calls.append({"call": label, "args": args, "kwargs": kwargs})
            if label == "remote_dispatch.dispatch":  # what the journal held at the moment of dispatch, even if it then fails
                journal = self.state / "remote-requests" / (args[2]["request_id"] + ".json")
                self.journal_at_dispatch.append(json.loads(journal.read_text(encoding="utf-8")) if journal.is_file() else {})
            if label in self.raises:
                raise self.raises[label]
            if label == "remote_artifacts.get" and self.artifact_files is not None:
                return self.artifact_files(args[1], args[2])
            return self.returns.get(label)

        return stand_in

    def named(self, label: str) -> "list[dict]":
        return [call for call in self.calls if call["call"] == label]


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


class Gateway:
    """The frozen `remote_mcp` module, loaded once, and a way to call its tools with the stand-ins installed."""

    def __init__(self, state: Path, github: "FakeGitHub | None" = None):
        self.state = Path(state)
        self.github = github or FakeGitHub()
        self.recorder = Recorder(self.state)
        hostlab = types.ModuleType("hostlab")
        hostlab.STATE = self.state  # type: ignore[attr-defined]
        hostlab.ROOT = self.state  # type: ignore[attr-defined]

        def write_json(path: Path, value: Any) -> None:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(json.dumps(value), encoding="utf-8")

        hostlab.write_json = write_json  # type: ignore[attr-defined]
        framework = {"mcp": types.ModuleType("mcp"), "mcp.server": types.ModuleType("mcp.server"),
                     "mcp.server.mcpserver": types.ModuleType("mcp.server.mcpserver"),
                     "mcp.server.mcpserver.exceptions": types.ModuleType("mcp.server.mcpserver.exceptions")}
        framework["mcp.server.mcpserver"].MCPServer = MCPServer  # type: ignore[attr-defined]
        framework["mcp.server.mcpserver.exceptions"].ToolError = ToolError  # type: ignore[attr-defined]
        self.modules = {**framework, "hostlab": hostlab,
                        **{name: self.recorder.module(name) for name in Recorder.NAMES}}
        self.module = support.load_frozen("remote_mcp", {k: v for k, v in self.modules.items() if k in framework or k == "hostlab"})
        self.module.subprocess = SimpleNamespace(run=self.github.guard.run)  # gh() now runs nothing real
        self.server = self.module.mcp

    def call(self, tool: str, **arguments: Any) -> Any:
        with _installed(self.modules):
            return self.server.tools[tool](**arguments)

    def journal(self, request_id: str) -> "dict | None":
        path = self.state / "remote-requests" / (request_id + ".json")
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def write_artifact(root: Path, request_id: str = REQUEST_ID, *, tasks: "list[dict] | None" = None,
                   extra: "dict[str, str] | None" = None) -> "list[Path]":
    """A small result artifact: result.txt holds an analysis report's tasks, as `job_result` summarises them."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    report = {"schema": 1, "tasks": tasks if tasks is not None else [{"id": "a", "status": "complete"}]}
    files = {"result.txt": json.dumps(report), "job.json": json.dumps({"request_id": request_id}),
             "summary.json": json.dumps({"ok": True}), **(extra or {})}
    paths = []
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
        paths.append(root / name)
    return paths
