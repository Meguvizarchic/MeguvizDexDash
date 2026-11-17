"""HostLab's remote orchestration around the MeguvizDexDash engine (MDD-053, HL-15). Integration layer only.

HostLab's local MCP gateway (`remote_mcp.py`, server `hostlab-remote`) has twelve orchestration tools that plan,
dispatch and collect GitHub Actions analysis jobs. They are not the engine's tools: the engine's MCP server
(`meguvizdexdash mcp`) has `open_dataset`, `query`, `decode` and so on, and the legacy dexq server has eight of its own,
with names that overlap the engine's. Nothing here changes the twelve tools, their parameters, their answers or the
queue behind them. What this module adds sits beside them:

* a registry that says which server a tool belongs to and refuses to route one server's tool name to another;
* a guard for the `gh` command that lets read-only calls through and refuses everything that could dispatch, so that
  the planning, status and result tools can be shown to dispatch nothing;
* `plan_ci`, which pins a job to a runner revision, a sample (SHA-256 and revision) and a backend/engine/config, and
  `check_pin`, which refuses a job whose pin differs;
* the run binding (repository, workflow, request id, run id, run attempt, head SHA, display title) and a sealed result
  manifest that ties an artifact's files, the sample, the engine pin and the run attempt together;
* the state of a job (an unknown dispatch is never replayed) and who may be re-dispatched or recovered;
* the path scopes: HostLab's `samples`, `reports`, `source-snapshots`, `artifact-cache` and friends stay HostLab's;
  the engine's copies live under its own namespace, and nothing here writes into a HostLab scope.

Not reproduced here: `version_matrix`, `remote_schedule`, `remote_artifacts`, `remote_dispatch`, `runner_worker`,
`snapshot_transport`. None is in the main frozen copy the gateway tests load (`source-8782f43`); six of them
(`analysis_checkpoint`, `remote_artifacts`, `remote_job`, `remote_schedule`, `runner_worker`, `snapshot_transport`) are
in the frozen `source-8782f43-extra` copy as source evidence, hashed in the records, but their behaviour is still not
executed by these controls (the gateway's calls into them are stubbed and recorded). `version_matrix`, `remote_dispatch`,
`runner_group`, `source_snapshot` and `adaptive_schedule` were not obtained. Their behaviour is neither reproduced nor claimed.

Standard library only, plus `provider` (MDD-050).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

import provider

REMOTE_SCHEMA = "mdd.hostlab-remote.v1"
RESULT_SCHEMA = "mdd.hostlab-remote-result.v1"
REMOTE_SERVER = "hostlab-remote"
ENGINE_SERVER = "meguvizdexdash"
LEGACY_SERVER = "dexq"

# remote_mcp.py, in source order. The contract file (conformance/hostlab/remote-contracts.json) is generated from the
# frozen source and the tests compare these constants with it, so they cannot drift.
REMOTE_TOOLS = ("plan_version_matrix", "submit_version_matrix", "advance_version_matrix", "version_matrix_status",
                "version_matrix_result", "recover_version_matrix", "plan_analysis", "submit_analysis", "submit_job",
                "job_status", "list_jobs", "job_result")
# The tools whose docstrings say they use Actions minutes or submit work. Every other tool is read-only or local.
DISPATCHING_TOOLS = ("submit_version_matrix", "advance_version_matrix", "recover_version_matrix", "submit_analysis",
                     "submit_job")
NON_DISPATCHING_TOOLS = tuple(name for name in REMOTE_TOOLS if name not in DISPATCHING_TOOLS)
ENGINE_NATIVE_TOOLS = ("close_dataset", "decode", "describe_table", "get_manifest", "get_manifest_components",
                       "list_datasets", "list_resource_files", "list_tables", "open_dataset", "query", "query_resources",
                       "read_resource")
LEGACY_DEXQ_TOOLS = ("open_dataset", "list_datasets", "close_dataset", "describe_tables", "query", "decode", "find_refs",
                     "apk_info")
SERVER_TOOLS = {REMOTE_SERVER: REMOTE_TOOLS, ENGINE_SERVER: ENGINE_NATIVE_TOOLS, LEGACY_SERVER: LEGACY_DEXQ_TOOLS}
SUBMIT_JOB_OPERATIONS = ("inventory", "audit", "decompile", "query", "decode", "string_refs", "info", "multipath_audit",
                         "regenerate_ai", "source_check")

# remote_artifacts' limits: evidence/hostlab_integration_inventory.json (cache_layers.artifact) and the frozen
# source-8782f43-extra/remote_artifacts.py:21-24 (MAX_ARCHIVE_BYTES/MAX_RESULT_BYTES/MAX_FILE_BYTES/MAX_FILES), which the
# records verify are equal. max_zip_bytes=MAX_ARCHIVE_BYTES, max_unpacked_bytes=MAX_RESULT_BYTES, max_file_bytes=MAX_FILE_BYTES.
ARTIFACT_LIMITS = {"max_zip_bytes": 64 * 1024 * 1024, "max_unpacked_bytes": 128 * 1024 * 1024,
                   "max_file_bytes": 32 * 1024 * 1024, "max_files": 4096}
# HostLab's path scopes (docs/03_HOSTLAB_MIGRATION.md 8.3): the engine may read a staged sample and nothing else
SCOPES = {"samples": "read", "reports": "none", "source-snapshots": "none", "artifact-cache": "none",
          "remote-output": "none", "remote-results": "none", "analysis-schedule": "none", "remote-requests": "none",
          "remote-job-map": "none", "version-matrices": "none", "dexq-cache": "none"}

REASONS = {
    "tool_not_on_server": "INVALID_ARGUMENT", "unknown_server": "INVALID_ARGUMENT",
    "dispatch_refused": "INVALID_ARGUMENT",
    "invalid_runner_revision": "INVALID_ARGUMENT", "invalid_sample": "INVALID_ARGUMENT",
    "runner_changed": "STALE_CACHE", "backend_changed": "STALE_CACHE", "engine_changed": "STALE_CACHE",
    "config_changed": "STALE_CACHE", "request_changed": "INVALID_ARGUMENT", "source_changed": "SOURCE_CHANGED",
    "invalid_run": "INVALID_ARGUMENT", "run_not_completed": "INVALID_ARGUMENT", "run_not_successful": "INVALID_ARGUMENT",
    "request_id_mismatch": "INVALID_ARGUMENT", "run_mismatch": "STALE_CACHE", "run_attempt_mismatch": "STALE_CACHE",
    "head_sha_mismatch": "STALE_CACHE", "title_mismatch": "STALE_CACHE", "repository_mismatch": "STALE_CACHE",
    "manifest_malformed": "CACHE_CORRUPT", "manifest_seal_mismatch": "CACHE_CORRUPT",
    "file_missing": "CACHE_CORRUPT", "file_changed": "CACHE_CORRUPT", "unexpected_file": "CACHE_CORRUPT",
    "file_outside_root": "CACHE_CORRUPT", "artifact_limit": "QUOTA_EXCEEDED",
    "not_registrable": "INVALID_ARGUMENT", "write_outside_engine_namespace": "INVALID_ARGUMENT",
    "sample_missing": "INVALID_ARGUMENT", "sample_changed": "SOURCE_CHANGED",
}


class RemoteRefused(provider.ProviderError):
    """Something the remote path must not do. `reason` is stable; `code` is an engine error code that never falls back."""

    def __init__(self, reason: str, message: "str | None" = None, *, component: "str | None" = None):
        super().__init__(message or reason)
        self.reason, self.component = reason, component
        self.code = REASONS[reason]


class DispatchRefused(RemoteRefused):
    pass


_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT = re.compile(r"[0-9a-f]{40}")
_REQUEST_ID = re.compile(r"[0-9a-f]{32}")


def canonical(value: Any) -> str:
    return provider.canonical(value)


def digest_of(value: Any) -> str:
    return provider.digest_of(value)


# ---- which server a tool belongs to ------------------------------------------------------------------------------------

def route(server: str, tool: str) -> str:
    """The family of `tool` on `server`, or a refusal. `query` exists on the engine's server and on the legacy dexq
    server, `open_dataset` on both; none of the twelve orchestration tools exists on either. A tool name alone proves
    nothing, so a call is routed by the pair."""
    if server not in SERVER_TOOLS:
        raise RemoteRefused("unknown_server", f"unknown MCP server {server!r}")
    if tool not in SERVER_TOOLS[server]:
        owners = sorted(name for name, tools in SERVER_TOOLS.items() if tool in tools)
        raise RemoteRefused("tool_not_on_server", f"{tool!r} is not a tool of {server!r}"
                            + (f" (it belongs to {', '.join(owners)})" if owners else ""), component=tool)
    return {REMOTE_SERVER: "remote_orchestration", ENGINE_SERVER: "engine_native", LEGACY_SERVER: "legacy_dexq"}[server]


def dispatch_class(tool: str) -> str:
    if tool not in REMOTE_TOOLS:
        raise RemoteRefused("tool_not_on_server", f"{tool!r} is not a remote orchestration tool", component=tool)
    return "dispatching" if tool in DISPATCHING_TOOLS else "non_dispatching"


# ---- the gh guard ------------------------------------------------------------------------------------------------------

_BODY_FLAGS = {"-f", "-F", "--field", "--raw-field", "--input"}
_READ_SUBCOMMANDS = {"run": {"list", "view", "download"}, "workflow": {"list", "view"}, "release": {"list", "view"}}


def gh_effect(args: Sequence[str], payload: Any = None) -> str:
    """'read' or 'mutate' for the arguments HostLab passes to `gh` (without the binary). Anything not known to be
    read-only is a mutation: `gh api` with a method other than GET or with a body, an attached shorthand (`-fref=main`)
    or cluster (`-if`, `-z`) that is not a read-only header/jq/template flag, and every `workflow run`. HostLab's gateway
    only uses separated flags, so this stays bounded to what it actually sends."""
    args = [str(a) for a in args]
    if payload is not None or not args:
        return "mutate"
    if args[0] == "api":
        rest = args[1:]
        for index, arg in enumerate(rest):
            if arg in _BODY_FLAGS or arg.split("=", 1)[0] in _BODY_FLAGS:
                return "mutate"
            if arg in ("-X", "--method"):
                if (rest[index + 1] if index + 1 < len(rest) else "").upper() != "GET":
                    return "mutate"
            elif arg.startswith("--method="):
                if arg.split("=", 1)[1].upper() != "GET":
                    return "mutate"
            elif arg.startswith("-X") and arg[2:].upper() != "GET":
                return "mutate"
            elif arg.startswith("-") and not arg.startswith(("--", "-X")) and arg != "-i" and not arg.startswith(("-H", "-q", "-t")):
                return "mutate"  # an attached or unknown shorthand (-fref=main, -if, -z) is not provably read-only
        return "read"
    if len(args) > 1 and args[1] in _READ_SUBCOMMANDS.get(args[0], ()):
        return "read"
    return "mutate"


class GhGuard:
    """Stands where `subprocess.run` stands for HostLab's `gh()`. It records every call and, unless mutation is allowed,
    refuses a call that could dispatch before anything is run. With no `inner` it runs nothing at all."""

    def __init__(self, inner: "Callable[..., Any] | None" = None, *, allow_mutation: bool = False):
        self.inner, self.allow_mutation = inner, allow_mutation
        self.calls: "list[dict]" = []

    def run(self, argv: Sequence[str], input: Any = None, **kwargs: Any) -> Any:
        args = list(argv)[1:]
        effect = gh_effect(args, json.loads(input) if isinstance(input, str) else input)
        self.calls.append({"args": [str(a) for a in args], "effect": effect, "has_input": input is not None})
        if effect == "mutate" and not self.allow_mutation:
            raise DispatchRefused("dispatch_refused", "refused a gh call that could dispatch: " + " ".join(map(str, args[:3])))
        if self.inner is None:
            return subprocess.CompletedProcess(list(argv), 1, "", "nothing is run through this guard")
        return self.inner(list(argv), input=input, **kwargs)

    @property
    def mutations(self) -> "list[dict]":
        return [call for call in self.calls if call["effect"] == "mutate"]


# ---- the pin of a job ----------------------------------------------------------------------------------------------------

def _sample(sample: Any) -> dict:
    if (not isinstance(sample, Mapping) or not isinstance(sample.get("sha256"), str) or not _SHA256.fullmatch(sample["sha256"])
            or not isinstance(sample.get("revision"), str) or not sample["revision"] or len(sample["revision"]) > 256):
        raise RemoteRefused("invalid_sample", "a sample needs an SHA-256 and a revision")
    version = sample.get("version_code")
    if version is not None and (type(version) is not int or not 0 < version <= 9999999999):
        raise RemoteRefused("invalid_sample", "invalid version_code")
    return {"apk_sha256": sample["sha256"], "revision": sample["revision"], "version_code": version}


def plan_ci(request: Any, config: provider.Config, *, runner_revision: str, sample: Mapping, legacy: Any = None,
            engine_status: "dict | None" = None, dexsql_available: bool = True, sqlite_cache_hit: bool = False) -> dict:
    """What a remote job will run on, before anything is dispatched. No I/O. The backend of each task, the engine's
    identity (None when the work stays on a legacy backend), the configuration, the request, the runner revision and the
    sample are the pin; the request's `resume` is not (a resumed job keeps the pin of the original)."""
    if not isinstance(runner_revision, str) or not _GIT.fullmatch(runner_revision):
        raise RemoteRefused("invalid_runner_revision", "the runner revision is a full git commit SHA")
    pinned_sample = _sample(sample)
    without_resume = {k: v for k, v in request.items() if k != "resume"} if isinstance(request, dict) else request
    planned = provider.plan(without_resume, config, legacy=legacy, dexsql_available=dexsql_available,
                            engine_status=engine_status, sqlite_cache_hit=sqlite_cache_hit)
    block = planned.get("provider") or {}
    pin = {"runner_revision": runner_revision,
           "task_backends": {task["id"]: task["backend"] for task in planned["tasks"]},
           "engine": block.get("engine"), "config_digest": block.get("config_digest", config.digest()),
           "request_sha256": planned["request_sha256"], "sample": pinned_sample}
    return {"schema": REMOTE_SCHEMA, "dispatches": False, "plan": planned, "pin": pin, "pin_sha256": digest_of(pin)}


def check_pin(saved: Mapping, current: Mapping) -> None:
    """A job, a receipt or a result belongs to the pin it was made under. The first component that differs is named."""
    order = (("runner_changed", "runner_revision", lambda p: p.get("runner_revision")),
             ("backend_changed", "task_backends", lambda p: p.get("task_backends")),
             ("engine_changed", "engine", lambda p: p.get("engine")),
             ("config_changed", "config_digest", lambda p: p.get("config_digest")),
             ("request_changed", "request_sha256", lambda p: p.get("request_sha256")),
             ("source_changed", "sample", lambda p: p.get("sample")))
    for reason, component, get in order:
        if get(saved) != get(current):
            raise RemoteRefused(reason, f"the job was pinned under another {component}", component=component)


# ---- the run, its artifact and the result manifest ----------------------------------------------------------------------

def run_binding(run: Any, request_id: str, repository: str, workflow: str) -> dict:
    """The fields a GitHub run must have for HostLab to trust its artifact: HostLab asks `remote_artifacts.get` for
    `repository/request/run/attempt/head SHA`, and finds the run by the title `hostlab-<request id>`."""
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
        raise RemoteRefused("request_id_mismatch", "invalid request id")
    if (not isinstance(run, Mapping) or type(run.get("id")) is not int or run["id"] < 1
            or type(run.get("run_attempt")) is not int or run["run_attempt"] < 1
            or not isinstance(run.get("head_sha"), str) or not _GIT.fullmatch(run["head_sha"])):
        raise RemoteRefused("invalid_run", "a run needs an id, a run_attempt and a head_sha")
    if run.get("display_title") != "hostlab-" + request_id:
        raise RemoteRefused("title_mismatch", "the run's title does not name the request", component="display_title")
    return {"repository": repository, "workflow": workflow, "request_id": request_id, "run_id": run["id"],
            "run_attempt": run["run_attempt"], "head_sha": run["head_sha"], "display_title": run["display_title"]}


def _entry(root: Path, path: Path) -> dict:
    resolved = Path(path).resolve()
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise RemoteRefused("file_outside_root", f"{path} is not a file below the artifact root")
    data = resolved.read_bytes()
    return {"path": PurePosixPath(resolved.relative_to(root.resolve())).as_posix(),
            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def file_entries(root: Path, files: Sequence[Path]) -> "list[dict]":
    entries = sorted((_entry(Path(root), Path(f)) for f in files), key=lambda e: e["path"])
    if (len(entries) > ARTIFACT_LIMITS["max_files"] or any(e["bytes"] > ARTIFACT_LIMITS["max_file_bytes"] for e in entries)
            or sum(e["bytes"] for e in entries) > ARTIFACT_LIMITS["max_unpacked_bytes"]):
        raise RemoteRefused("artifact_limit", "the artifact exceeds HostLab's file, size or count limits")
    if len({e["path"] for e in entries}) != len(entries):
        raise RemoteRefused("manifest_malformed", "duplicate artifact paths")
    return entries


def result_manifest(run: Mapping, request_id: str, repository: str, workflow: str, root: Path, files: Sequence[Path], *,
                    pin: Mapping, termination: "str | None") -> dict:
    """A sealed record of one run's artifact: which run and attempt, which files with which digests, which sample and
    engine pin, and how the analysis ended (`termination` is a checkpoint_adapter termination). A run that did not
    complete successfully has no manifest; one that did but did not finish its analysis has one that says so and is
    never registrable as a completion. The manifest is kept beside the artifact root, not inside it."""
    binding = run_binding(run, request_id, repository, workflow)
    if run.get("status") != "completed":
        raise RemoteRefused("run_not_completed", "the run has not completed")
    if run.get("conclusion") != "success":
        raise RemoteRefused("run_not_successful", "the run concluded " + str(run.get("conclusion")))
    entries = file_entries(root, files)
    if not entries:
        raise RemoteRefused("manifest_malformed", "a result manifest lists at least one file")
    body = {"schema": RESULT_SCHEMA, "binding": binding, "pin": json.loads(json.dumps(pin)),
            "outcome": {"conclusion": "success", "termination": termination}, "files": entries}
    return dict(body, seal={"algorithm": "sha256", "digest": digest_of(body)})


def registrable_as_complete(manifest: Mapping) -> bool:
    """Only a successful run whose analysis completed (sealed checkpoint termination `complete`) may be registered as a
    completed result. Cancelled, failed, worker-lost, source-changed and partial analyses never are."""
    outcome = manifest.get("outcome") or {}
    return outcome.get("conclusion") == "success" and outcome.get("termination") == "complete"


def require_registrable(manifest: Mapping) -> None:
    if not registrable_as_complete(manifest):
        raise RemoteRefused("not_registrable", "this result is not a completed analysis: "
                            + str((manifest.get("outcome") or {}).get("termination")))


def verify_result_manifest(manifest: Any, *, run: Mapping, request_id: str, repository: str, workflow: str,
                           pin: Mapping, root: Path) -> None:
    """Everything a result must still match when it is read back: the seal, the repository, workflow, request, run id,
    run attempt, head SHA and title of the run in hand, the pin, and every file on disk (digest and size, no extras)."""
    if (not isinstance(manifest, Mapping) or manifest.get("schema") != RESULT_SCHEMA
            or not all(key in manifest for key in ("binding", "pin", "outcome", "files", "seal"))):
        raise RemoteRefused("manifest_malformed", "not a result manifest")
    body = {key: manifest[key] for key in ("schema", "binding", "pin", "outcome", "files")}
    if not isinstance(manifest["seal"], Mapping) or manifest["seal"].get("digest") != digest_of(body):
        raise RemoteRefused("manifest_seal_mismatch", "the manifest does not match its seal")
    current = run_binding(run, request_id, repository, workflow)
    saved = manifest["binding"]
    for reason, key in (("repository_mismatch", "repository"), ("repository_mismatch", "workflow"),
                        ("request_id_mismatch", "request_id"), ("run_mismatch", "run_id"),
                        ("run_attempt_mismatch", "run_attempt"), ("head_sha_mismatch", "head_sha")):
        if saved.get(key) != current[key]:
            raise RemoteRefused(reason, f"the manifest was made for another {key}", component=key)
    check_pin(manifest["pin"], pin)
    listed = {entry["path"]: entry for entry in manifest["files"]}
    base = Path(root).resolve()
    for relative, entry in listed.items():
        target = (base / relative).resolve()
        if not target.is_relative_to(base):
            raise RemoteRefused("file_outside_root", f"{relative} leaves the artifact root")
        if not target.is_file():
            raise RemoteRefused("file_missing", f"{relative} is missing", component=relative)
        data = target.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise RemoteRefused("file_changed", f"{relative} differs from the manifest", component=relative)
    present = {PurePosixPath(p.relative_to(base)).as_posix() for p in base.rglob("*") if p.is_file()}
    if present - set(listed):
        raise RemoteRefused("unexpected_file", "files outside the manifest: " + ", ".join(sorted(present - set(listed))[:5]))


# ---- the state of a job ------------------------------------------------------------------------------------------------------

JOB_STATES = ("dispatch_unknown", "dispatch_pending", "running", "succeeded", "failed", "cancelled", "skipped", "unknown")


def job_state(record: "Mapping | None", run: "Mapping | None") -> str:
    """Where a job stands, from HostLab's request journal and the GitHub run (remote_mcp.job_status). A dispatch whose
    outcome was never learned is `dispatch_unknown`: it is looked up by title, never sent again."""
    if run is None:
        if record is not None and record.get("status") == "dispatch_unknown":
            return "dispatch_unknown"
        return "dispatch_pending" if record is not None else "unknown"
    if run.get("status") != "completed":
        return "running"
    conclusion = run.get("conclusion")
    if conclusion == "success":
        return "succeeded"
    if conclusion in ("cancelled", "skipped"):
        return conclusion
    return "failed" if isinstance(conclusion, str) and conclusion else "unknown"


def redispatch_allowed(state: str, *, new_idempotency_key: bool) -> bool:
    """A failed, cancelled or skipped job may be sent again only under a new idempotency key (the explicit decision of
    the caller). A job that is running, unknown, pending or already succeeded is never sent again."""
    return state in ("failed", "cancelled", "skipped") and new_idempotency_key is True


def recover_eligible(state: str, *, verified: bool, include_unverified_results: bool) -> bool:
    """recover_version_matrix: confirmed failed/skipped (and cancelled) work; succeeded work only when its results are
    unverified and the caller opted in; never running or unknown dispatches."""
    if state in ("failed", "cancelled", "skipped"):
        return True
    return state == "succeeded" and not verified and include_unverified_results is True


# ---- path scopes ------------------------------------------------------------------------------------------------------------

def scope_table(state: Path, ns: Mapping[str, Path]) -> "dict[str, dict]":
    """HostLab's scopes (below `state`) and the engine's copy of each (below its namespace). HostLab's are read-only to
    the adapter except `samples`, which the engine may read; the engine never writes in any of them."""
    base = Path(state).resolve()
    engine = Path(ns["reports"]).name
    root = Path(ns["root"]) / "remote" / engine
    table = {}
    for name, access in SCOPES.items():
        table[name] = {"hostlab": str(base / name), "adapter_access": access,
                       "engine": str(Path(ns["reports"])) if name == "reports" else str(root / name)}
    return table


def assert_writable(path: Path, state: Path, ns: Mapping[str, Path]) -> Path:
    """The adapter writes only below the engine's own directories (provider.namespaces), and never inside one of HostLab's
    scopes."""
    target = Path(path).resolve()
    mine = [Path(ns[name]).resolve() for name in ("root", "cache", "reports", "completion")]
    if not any(target.is_relative_to(directory) for directory in mine):
        raise RemoteRefused("write_outside_engine_namespace", f"{path} is outside the engine namespace")
    for name in SCOPES:
        if target.is_relative_to(Path(state).resolve() / name):
            raise RemoteRefused("write_outside_engine_namespace", f"{path} is inside HostLab's {name} scope")
    return target


def sample_path(state: Path, sha256: str, *, verify: bool = True) -> Path:
    """The staged sample the engine may read: `<state>/samples/<sha256>/base.apk`, no other spelling. HostLab stages and
    verifies it; the engine neither downloads it nor holds a token."""
    if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
        raise RemoteRefused("invalid_sample", "a sample is named by its SHA-256")
    path = Path(state).resolve() / "samples" / sha256 / "base.apk"
    if not path.is_file():
        raise RemoteRefused("sample_missing", "the sample has not been staged")
    if verify and hashlib.sha256(path.read_bytes()).hexdigest() != sha256:
        raise RemoteRefused("sample_changed", "the staged sample does not match its SHA-256", component="sha256")
    return path
