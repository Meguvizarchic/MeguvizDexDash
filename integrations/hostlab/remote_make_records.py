#!/usr/bin/env python3
"""Regenerate the MDD-053 records, or check that they are current.

    python -I integrations/hostlab/remote_make_records.py            # write both
    python -I integrations/hostlab/remote_make_records.py --check    # exit 1 if either file differs

  conformance/hostlab/remote-contracts.json                       what HostLab's twelve remote orchestration tools are
  artifacts/mdd-053/remote-and-resume-equivalence.json            what the adapters do with them, controls included

Both are produced by running code, never typed in. The contract is read out of the frozen HostLab source
(conformance/corpus/hostlab/source-8782f43, loaded only after its SHA-256 matches the manifest): the signatures and the calls
each tool hands on come from its syntax tree, the answers and the argument checks come from running the frozen gateway under
the stand-ins of remote_test_support.py, and the worker task contract comes from running the frozen planner. The equivalence
record runs the adapters through the frozen batch executor and the frozen paging module against a scripted engine stand-in
(checkpoint_test_support.py) and lists every comparison with the negative control that must fail. Every input is named with its
SHA-256. Deterministic: no clock, no path, no timing, a fixed platform for the stand-in engine.

What a stand-in cannot show is said in `not_proven`; this is not evidence about the real engine (test_checkpoint_live_engine.py
runs the resume flow against the real binary) and nothing here dispatched, called the network or touched a production branch.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import checkpoint_adapter as ca  # noqa: E402
import checkpoint_test_support as cts  # noqa: E402
import hostlab_test_support as support  # noqa: E402
import provider  # noqa: E402
import remote_runner_adapter as remote  # noqa: E402
import remote_test_support as rts  # noqa: E402

ROOT = support.ROOT
CONTRACTS = ROOT / "conformance/hostlab/remote-contracts.json"
EQUIVALENCE = ROOT / "artifacts/mdd-053/remote-and-resume-equivalence.json"
FROZEN = "conformance/corpus/hostlab/source-8782f43/"
EXTRA = "conformance/corpus/hostlab/source-8782f43-extra/"
PLATFORM = "fixture/platform"
INPUTS = [
    FROZEN + "manifest.json", FROZEN + "remote_mcp.py", FROZEN + "analysis_plan.py", FROZEN + "analysis_paging.py",
    FROZEN + "analysis_batch.py", FROZEN + "native_cli.py", FROZEN + "native_surface.py",
    EXTRA + "manifest.json", EXTRA + "analysis_checkpoint.py", EXTRA + "remote_artifacts.py", EXTRA + "remote_job.py",
    EXTRA + "remote_schedule.py", EXTRA + "runner_worker.py", EXTRA + "snapshot_transport.py",
    "conformance/manifests/tools-and-options.json", "evidence/hostlab_integration_inventory.json",
    "integrations/hostlab/provider.py", "integrations/hostlab/checkpoint_adapter.py",
    "integrations/hostlab/remote_runner_adapter.py", "integrations/hostlab/checkpoint_test_support.py",
    "integrations/hostlab/remote_test_support.py", "integrations/hostlab/remote_make_records.py",
]
STUBBED = tuple(rts.Recorder.NAMES)


class Violation(Exception):
    """A fact the records are built on does not hold: nothing is written."""


def need(condition: Any, message: str) -> None:
    if not condition:
        raise Violation(message)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def inputs() -> "list[dict]":
    return [{"path": path, "sha256": sha256_file(ROOT / path), "bytes": (ROOT / path).stat().st_size} for path in INPUTS]


def outcome(call: Callable[[], Any]) -> str:
    """How a call ended, in words that do not depend on the machine."""
    try:
        call()
    except rts.ToolError as error:
        return "ToolError: " + str(error)
    except ValueError as error:
        return "ValueError: " + str(error)
    except Exception as error:  # noqa: BLE001 - recorded, not hidden
        return type(error).__name__
    return "accepted"


def refusal(function: Callable, *args: Any, **kwargs: Any) -> "str | None":
    try:
        function(*args, **kwargs)
    except (ca.CheckpointRefused, remote.RemoteRefused) as error:
        return error.reason
    return None


# ================================================================================================================
# the contract of the twelve remote tools
# ================================================================================================================

def tool_nodes(tree: ast.Module) -> "list[ast.FunctionDef]":
    def is_tool(node: ast.expr) -> bool:
        return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "tool"
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "mcp")
    return [n for n in tree.body if isinstance(n, ast.FunctionDef) and any(is_tool(d) for d in n.decorator_list)]


def parameters(node: ast.FunctionDef) -> "list[dict]":
    args = node.args
    defaults = [None] * (len(args.args) - len(args.defaults)) + list(args.defaults)
    return [{"name": a.arg, "annotation": ast.unparse(a.annotation) if a.annotation else None,
             "default": ast.unparse(d) if d is not None else None, "required": d is None} for a, d in zip(args.args, defaults)]


def signature(items: "list[dict]") -> str:
    return ", ".join(p["name"] + (": " + p["annotation"] if p["annotation"] else "") + ("=" + p["default"] if p["default"] is not None else "")
                     for p in items)


def forwards(node: ast.FunctionDef) -> "list[dict]":
    """The calls a tool makes into the modules that are not in the frozen copy, as written in the source."""
    found = []
    for sub in ast.walk(node):
        if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and isinstance(sub.func.value, ast.Name)
                and sub.func.value.id in STUBBED):
            found.append({"call": f"{sub.func.value.id}.{sub.func.attr}", "line": sub.lineno,
                          "args": [ast.unparse(a) for a in sub.args],
                          "kwargs": {k.arg: ast.unparse(k.value) for k in sub.keywords if k.arg}})
    return sorted(found, key=lambda item: (item["line"], item["call"]))


def imported_inside_tools(tree: ast.Module) -> "list[str]":
    names = set()
    for sub in ast.walk(tree):
        if isinstance(sub, ast.Import):
            names.update(alias.name for alias in sub.names if alias.name in STUBBED)
    return sorted(names)


DOC_PHRASES = {
    "plan_version_matrix": ["Plan 1..40 exact APKs over at most 4 runners", "runner_batch_size=1..4", "native up to 12, otherwise 4",
                            "No dispatch here"],
    "submit_version_matrix": ["dispatches up to two jobs per call", "fills up to four physical slots",
                              "Unknown dispatches and failures never replay automatically"],
    "advance_version_matrix": ["dispatch at most two jobs per call", "adaptive queues fill up to four",
                               "a deadline stops new dispatches without cancelling accepted jobs"],
    "version_matrix_status": ["without submitting additional work"],
    "version_matrix_result": ["1..4 download workers", "prefetch_only=true downloads only completed entries"],
    "recover_version_matrix": ["Running/unknown dispatches stay excluded", "Uses Actions minutes"],
    "plan_analysis": ["Plan up to 16 related tasks without dispatching", "max_pages:1..32,max_rows:1..10000,max_bytes:1024..1048576",
                      "default 8/1000/1048576"],
    "submit_analysis": ["exact APK SHA and sample revision are required", "never by replaying its prefix",
                        "Ordinary arbitrary SQL is not completion-cached", "Unknown dispatch is never replayed", "Uses Actions minutes"],
    "submit_job": ["Uses Actions minutes; returns immediately"],
    "job_status": ["Does not wait"],
    "list_jobs": ["List the latest ten analysis runs"],
    "job_result": ["1024..128000", "does not submit another Actions analysis job", "sample_index=0..11"],
}


def tool_table(source: str, earlier: "list[dict]") -> "list[dict]":
    tree = ast.parse(source)
    nodes = tool_nodes(tree)
    need([n.name for n in nodes] == list(remote.REMOTE_TOOLS), "the frozen gateway registers other tools than the adapter lists")
    by_name = {t["name"]: t for t in earlier}
    table = []
    for node in nodes:
        items = parameters(node)
        doc = ast.get_docstring(node) or ""
        before = by_name[node.name]
        need(signature(items) == before["signature"], f"{node.name}: the signature differs from the earlier extraction")
        need(doc == before["docstring"], f"{node.name}: the docstring differs from the earlier extraction")
        phrases = {phrase: phrase in doc for phrase in DOC_PHRASES[node.name]}
        need(all(phrases.values()), f"{node.name}: a documented limit is missing from its docstring: {phrases}")
        table.append({"name": node.name, "lines": [before["line"], before["end_line"]], "parameters": items,
                      "signature": signature(items), "signature_matches_mdd003_extraction": True,
                      "docstring_sha256": hashlib.sha256(doc.encode("utf-8")).hexdigest(),
                      "docstring_matches_mdd003_extraction": True,
                      "dispatch_class": remote.dispatch_class(node.name), "documented_limits": phrases,
                      "forwards": forwards(node)})
    return table


def new_gateway(work: Path, name: str, runs: "list[dict] | None" = None) -> rts.Gateway:
    gateway = rts.Gateway(work / name, rts.FakeGitHub(runs))
    gateway.recorder.artifact_files = lambda request_id, run: _artifact(work, name, request_id, run)
    return gateway


def _artifact(work: Path, name: str, request_id: str, run: dict) -> dict:
    root = work / (name + "-artifact")
    paths = rts.write_artifact(root, request_id)
    return {"files": [str(p) for p in paths], "root": str(root), "cache_hit": False, "artifact": {"name": "result"},
            "integrity": "verified", "elapsed_ms": 1.0, "run_attempt": run["run_attempt"]}


def keys(text: str) -> "list[str]":
    return sorted(json.loads(text))


def responses(work: Path) -> dict:
    run = rts.run_record(attempt=2)
    g = new_gateway(work, "responses", [run])
    g.recorder.returns["remote_schedule.observe"] = {
        "status": "completed", "conclusion": "success", "run_attempt": 2, "queued_at": 1.0, "dispatch": "confirmed",
        "run_updated_at": "t", "state_uncertain": False, "stale_observation_ignored": False}
    g.recorder.returns["remote_schedule.public_status"] = "succeeded"
    result = json.loads(g.call("job_result", request_id=rts.REQUEST_ID))
    submitted = json.loads(g.call("submit_job", version_code=1, operation="info"))
    return {
        "job_status_known_run": keys(g.call("job_status", request_id=rts.REQUEST_ID)),
        "job_status_no_run_yet": keys(g.call("job_status", request_id=rts.OTHER_REQUEST_ID)),
        "list_jobs_item": sorted(json.loads(g.call("list_jobs"))[0]),
        "submit_job": sorted(submitted),
        "job_result": sorted(result), "job_result.collection": sorted(result["collection"]),
        "job_result.task_summary": sorted(result["task_summary"]), "job_result.result_page": sorted(result["result_page"]),
        "job_result.file_pages_item": sorted(next(iter(result["file_pages"].values()))),
        "plan_analysis_passthrough": json.loads(g.call("plan_analysis", request={})) == g.recorder.returns["remote_schedule.describe"],
        "submit_analysis_passthrough": json.loads(g.call("submit_analysis", version_code=1, request={}))
        == g.recorder.returns["remote_schedule.submit"],
        "version_matrix_status_passthrough": json.loads(g.call("version_matrix_status", matrix_id="m"))
        == g.recorder.returns["version_matrix.advance"],
    }


def validation(work: Path) -> dict:
    def job_result(**arguments: Any) -> str:
        g = new_gateway(work, "validate-result", [rts.run_record()])
        return outcome(lambda: g.call("job_result", request_id=rts.REQUEST_ID, **arguments))

    def submit_job(**arguments: Any) -> str:
        return outcome(lambda: new_gateway(work, "validate-submit").call("submit_job", **arguments))

    result_probes = [{}, dict(result_offset=0, page_chars=1024), dict(page_chars=128000), dict(result_file="job.json"),
                     dict(result_offset=-1), dict(result_offset=2147483648), dict(result_offset=True), dict(sample_index=-2),
                     dict(sample_index=12), dict(sample_index=0), dict(page_chars=1023), dict(page_chars=128001),
                     dict(result_file=5), dict(result_file="../result.txt"), dict(result_file="C:/result.txt"),
                     dict(result_file="a//b.txt"), dict(result_file="evil.sh")]
    submit_probes = [dict(version_code=1, operation=op) for op in remote.SUBMIT_JOB_OPERATIONS] + [
        dict(version_code=0, operation="info"), dict(version_code=10 ** 10, operation="info"),
        dict(version_code=1, operation="plan_analysis"), dict(version_code=1, operation="info", argument="x" * 4097),
        dict(version_code=1, operation="query", max_cell_chars=16000), dict(version_code=1, operation="query", max_cell_chars=16001),
        dict(version_code=1, operation="info", max_cell_chars=301), dict(version_code=1, operation="info", source_mode="worktree"),
        dict(version_code=1, operation="multipath_audit", source_mode="historical"),
        dict(version_code=1, operation="regenerate_ai", source_mode="historical")]
    return {"job_result": [{"arguments": a, "outcome": job_result(**a)} for a in result_probes],
            "submit_job": [{"arguments": a, "outcome": submit_job(**a)} for a in submit_probes],
            "request_id_pattern": "[0-9a-f]{32}",
            "bad_request_id": outcome(lambda: new_gateway(work, "bad-id").call("job_status", request_id="not-an-id"))}


def worker_task_contract() -> dict:
    plan = support.load_frozen("analysis_plan")
    paging = support.load_frozen("analysis_paging")
    tasks = [{"id": "a", "operation": "info"}]
    query = {"id": "q", "operation": "query", "sql": "SELECT 1 ORDER BY 1", "dialect": "dexsql"}

    def probe(request: Any) -> str:
        return outcome(lambda: plan.validate(request))

    resume = {"run_id": 5, "attempt": 2, "request_id": "ab" * 16}
    probes = {
        "minimal request": {"tasks": tasks},
        "backend meguvizdexdash (not a frozen backend)": {"backend": "meguvizdexdash", "tasks": tasks},
        "negotiation block (provider-only)": {"negotiation": {"fallback": "forbid"}, "tasks": tasks},
        "backends sqlite and dexsql": {"backend": "sqlite", "tasks": [dict(tasks[0], id="b")]},
        "16 tasks": {"tasks": [{"id": f"t{i}", "operation": "info"} for i in range(16)]},
        "17 tasks": {"tasks": [{"id": f"t{i}", "operation": "info"} for i in range(17)]},
        "resume with run, attempt and request": {"tasks": tasks, "resume": resume},
        "resume without attempt": {"tasks": tasks, "resume": {"run_id": 5, "request_id": "ab" * 16}},
        "resume with a short request id": {"tasks": tasks, "resume": dict(resume, request_id="ab")},
        "resume with sample_index 11": {"tasks": tasks, "resume": dict(resume, sample_index=11)},
        "resume with sample_index 12": {"tasks": tasks, "resume": dict(resume, sample_index=12)},
        "query with pagination": {"tasks": [dict(query, pagination={"max_pages": 32, "max_rows": 10000, "max_bytes": 1048576})]},
        "query with pagination beyond bounds": {"tasks": [dict(query, pagination={"max_pages": 33})]},
        "query offset 99000": {"tasks": [dict(query, offset=99000)]},
        "query offset 99001": {"tasks": [dict(query, offset=99001)]},
        "sqlite query with offset": {"tasks": [dict(query, dialect="sqlite", offset=1)]},
        "timeout 600 and threads 6": {"tasks": tasks, "timeout_seconds": 600, "threads": 6},
        "timeout 601": {"tasks": tasks, "timeout_seconds": 601},
        "unknown field": {"tasks": tasks, "extra": 1},
    }
    normal = plan.validate({"tasks": tasks})
    resumed = plan.validate({"tasks": tasks, "resume": resume})
    return {
        "limits": {"schema": plan.SCHEMA, "max_tasks": plan.MAX_TASKS, "max_request_bytes": plan.MAX_REQUEST_BYTES,
                   "backends": sorted(plan.BACKENDS), "operations": sorted(plan.OPERATIONS),
                   "paging_defaults": paging.DEFAULTS},
        "probes": [{"name": name, "outcome": probe(request)} for name, request in probes.items()],
        "fingerprint_covers_resume": plan.fingerprint({"tasks": tasks}) != plan.fingerprint({"tasks": tasks, "resume": resume}),
        "normalized_resume": resumed["resume"], "normalized_has_resume_without": "resume" not in normal,
        "continuation_requires": {
            "outer ORDER BY": paging.continuation_reason("SELECT n FROM t ORDER BY n"),
            "no ORDER BY": paging.continuation_reason("SELECT n FROM t"),
            "ORDER BY only inside a subquery": paging.continuation_reason("SELECT n FROM (SELECT n FROM t ORDER BY n)"),
            "volatile random()": paging.continuation_reason("SELECT random() ORDER BY 1"),
        },
    }


def scope_table_record() -> dict:
    templates = {"samples": "runtime/hostlab/samples/<apk_sha>/base.apk", "reports": "runtime/hostlab/reports/<version>/<sha-prefix>/<stamp>/",
                 "source-snapshots": "runtime/hostlab/source-snapshots/<sha>/context.json",
                 "artifact-cache": "runtime/hostlab/artifact-cache/<scope>/<run>/attempt-<n>/",
                 "remote-output": "runtime/hostlab/remote-output/", "remote-results": "runtime/hostlab/remote-results/",
                 "analysis-schedule": "runtime/hostlab/analysis-schedule/", "remote-requests": "runtime/hostlab/remote-requests/",
                 "remote-job-map": "runtime/hostlab/remote-job-map/", "version-matrices": "runtime/hostlab/version-matrices/",
                 "dexq-cache": "runtime/hostlab/dexq-cache/"}
    need(set(templates) == set(remote.SCOPES) == set(provider.LEGACY_NAMES), "the scope tables disagree")
    return {name: {"hostlab": templates[name], "adapter_access": remote.SCOPES[name],
                   "engine_copy": ("runtime/hostlab/mdd-engine/reports/<engine_dir>" if name == "reports"
                                   else "runtime/hostlab/mdd-engine/remote/<engine_dir>/" + name)} for name in sorted(templates)}


def _artifact_constants(text: str) -> dict:
    """The four limit constants of the frozen -extra remote_artifacts.py, evaluated from its syntax tree (pure arithmetic)."""
    wanted = {"MAX_ARCHIVE_BYTES", "MAX_RESULT_BYTES", "MAX_FILE_BYTES", "MAX_FILES"}
    found = {}
    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                and node.targets[0].id in wanted:
            found[node.targets[0].id] = eval(compile(ast.Expression(node.value), "<frozen-remote_artifacts>", "eval"), {})
    need(set(found) == wanted, "the frozen remote_artifacts limits are not all found")
    return found


def _loader_overwrites_origin(text: str) -> bool:
    """Whether load_actions assigns report['resume_origin'] as an unconditional top-level statement (so whatever the
    report carried is replaced by the loader's own binding)."""
    fn = next(n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == "load_actions")
    for stmt in fn.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id == "report" \
                        and isinstance(target.slice, ast.Constant) and target.slice.value == "resume_origin":
                    return True
    return False


def _frozen_summary() -> Callable:
    """The frozen -extra analysis_checkpoint.summary, extracted from the hash-checked source and run on its own (the
    module imports hostlab, which was not obtained; summary itself only needs re and Path)."""
    node = next(n for n in ast.parse(read(EXTRA + "analysis_checkpoint.py")).body
                if isinstance(n, ast.FunctionDef) and n.name == "summary")
    namespace: dict = {"re": re, "Path": Path}
    exec(compile(ast.Module(body=[node], type_ignores=[]), EXTRA + "analysis_checkpoint.py", "exec"), namespace)
    return namespace["summary"]


def loader_lineage_demo(work: Path) -> dict:
    """Run the frozen summary against a report carrying the adapter's nested resume_origin lineage, then against the
    loader's flat origin. The adapter's lineage has no top-level run_id, so HostLab's summary cannot read it."""
    summary = _frozen_summary()
    path = work / "summary.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {"tasks": [{"id": "l1", "status": "complete", "result": {}}], "complete": True}
    adapter_lineage = {"seal": "0" * 64, "identity_sha256": "0" * 64,
                       "origin": {"run_id": 5, "attempt": 1, "request_id": "a" * 32}, "claim": None}
    loader_origin = {"run_id": 5, "attempt": 1, "request_id": "a" * 32, "artifact_id": 123, "reused_complete_tasks": 1}
    return {"summary_with_adapter_lineage": outcome(lambda: summary(path, dict(report, resume_origin=adapter_lineage))),
            "summary_with_loader_origin": outcome(lambda: summary(path, dict(report, resume_origin=loader_origin)))}


def frozen_extra_evidence(work: Path) -> dict:
    """The six frozen -extra modules: hashed, verified equal to the inventory, and the two facts the records used to
    claim were unproven — remote_artifacts' limits equal ARTIFACT_LIMITS, and analysis_checkpoint's loader overwrites
    resume_origin while its summary cannot read the adapter's nested lineage."""
    manifest = json.loads(read(EXTRA + "manifest.json"))
    inventory = json.loads(read("evidence/hostlab_integration_inventory.json"))
    listed = {Path(f["path"]).stem: f for f in inventory["reviewed_source_files"]}
    modules = []
    for entry in manifest["files"]:
        path = entry["path"]
        stem = Path(path).stem
        data = (ROOT / path).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        need(digest == entry["sha256"] and len(data) == entry["bytes"], f"{path} is not the frozen -extra source")
        need(stem in listed and listed[stem]["sha256"] == digest and listed[stem]["bytes"] == len(data),
             f"{path} does not match the inventory it was obtained against")
        modules.append({"module": stem, "path": path, "sha256": digest, "bytes": len(data),
                        "origin_url": entry["origin_url"], "matches_inventory": True})
    mapping = {"max_zip_bytes": "MAX_ARCHIVE_BYTES", "max_unpacked_bytes": "MAX_RESULT_BYTES",
               "max_file_bytes": "MAX_FILE_BYTES", "max_files": "MAX_FILES"}
    constants = _artifact_constants(read(EXTRA + "remote_artifacts.py"))
    match = {key: remote.ARTIFACT_LIMITS[key] == constants[name] for key, name in mapping.items()}
    need(all(match.values()), "ARTIFACT_LIMITS differ from the frozen -extra remote_artifacts constants")
    checkpoint_text = read(EXTRA + "analysis_checkpoint.py")
    anchor = 'report["resume_origin"] = {**binding,'
    need(checkpoint_text.count(anchor) == 1, "the loader resume_origin anchor is not found exactly once")
    need(_loader_overwrites_origin(checkpoint_text), "the loader does not overwrite resume_origin unconditionally")
    demo = loader_lineage_demo(work)
    need(demo == {"summary_with_adapter_lineage": "KeyError", "summary_with_loader_origin": "accepted"},
         "the frozen summary does not behave as the loader evidence says")
    return {
        "about": "Six more files of the frozen HostLab commit, in source-8782f43-extra (not the main copy the gateway tests "
                 "load). Hashed here and verified equal to evidence/hostlab_integration_inventory.json. Their behaviour is "
                 "still not executed by the controls (the gateway's calls into them are stubbed), except the two facts "
                 "demonstrated below from the frozen source itself.",
        "manifest": {"path": EXTRA + "manifest.json", "sha256": sha256_file(ROOT / EXTRA / "manifest.json"),
                     "commit": manifest["commit"]},
        "modules": modules,
        "not_obtained": manifest["not_obtained"],
        "remote_artifacts_limits": {"frozen_constants": constants, "mapping_to_ARTIFACT_LIMITS": mapping,
                                    "equals_adapter_ARTIFACT_LIMITS": match,
                                    "source": EXTRA + "remote_artifacts.py:21-24"},
        "analysis_checkpoint_loader": {
            "resume_origin_overwritten_unconditionally": True, "anchor": anchor,
            "summary_consumes_flat_keys": ["run_id", "attempt", "artifact_id", "reused_complete_tasks"],
            "demonstrated": demo,
            "meaning": "HostLab's loader builds its own resume_origin from the run binding and overwrites the report's; its "
                       "summary reads flat keys the adapter's nested lineage {seal, identity_sha256, origin, claim} does not "
                       "have, so the adapter's lineage is its own chain, not consumed by HostLab's loader or summary",
            "source": EXTRA + "analysis_checkpoint.py:237-256"},
    }


def build_contracts(work: Path) -> dict:
    manifest = json.loads(read(FROZEN + "manifest.json"))
    entry = next(f for f in manifest["files"] if f.get("path") == FROZEN + "remote_mcp.py")
    source_file = ROOT / entry["path"]
    need(sha256_file(source_file) == entry["sha256"], "remote_mcp.py is not the frozen source")
    source = source_file.read_text(encoding="utf-8")
    earlier = json.loads(read("conformance/manifests/tools-and-options.json"))
    inventory = json.loads(read("evidence/hostlab_integration_inventory.json"))
    gateway = rts.Gateway(work / "constants", rts.FakeGitHub())
    tree = ast.parse(source)
    table = tool_table(source, earlier["remote_orchestration"])
    imported = imported_inside_tools(tree)
    listed = {Path(f["path"]).stem: f for f in inventory["reviewed_source_files"]}
    matrix_artifact = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "matrix_artifact")
    needed = next(s for s in ast.walk(matrix_artifact) if isinstance(s, ast.Set))
    native = sorted(t["name"] if isinstance(t, dict) else t for t in earlier["native_mcp"]["0.1.0"])
    legacy = [t["name"] for t in earlier["legacy_dexq"]]
    need(tuple(native) == remote.ENGINE_NATIVE_TOOLS and tuple(legacy) == remote.LEGACY_DEXQ_TOOLS, "tool inventories drifted")
    other = set(native) | set(legacy)
    need(not (set(remote.REMOTE_TOOLS) & other), "an orchestration tool shares a name with an engine or dexq tool")
    module = gateway.module
    need(not any((ROOT / FROZEN / (name + ".py")).exists() for name in imported),
         "a module the gateway imports is in the frozen copy after all: it should be loaded, not recorded")
    return {
        "schema": "mdd.hostlab-remote-contracts.v1", "task": "MDD-053",
        "generated_by": {"script": "integrations/hostlab/remote_make_records.py", "command": "python -I integrations/hostlab/remote_make_records.py",
                         "check": "... --check", "deterministic": True},
        "about": "The twelve orchestration tools of HostLab's local gateway, read out of the frozen source. They are served by the "
                 "`hostlab-remote` MCP server; the engine's own MCP server (`meguvizdexdash mcp`) and the legacy dexq server have other "
                 "tools, some with overlapping names. The adapters keep this contract; they do not change it.",
        "source": {"commit": earlier["source_commit"], "path": entry["path"], "sha256": entry["sha256"], "bytes": entry["bytes"],
                   "origin_url": entry["origin_url"]},
        "inputs": inputs(),
        "server": {"name": gateway.server.name, "transport": "stdio", "repository": module.REPO, "workflow": module.WORKFLOW,
                   "instructions_sha256": hashlib.sha256(gateway.server.instructions.encode("utf-8")).hexdigest(),
                   "public_http_configured": False},
        "constants": {"RESULT_PAGE_CHARS": module.RESULT_PAGE_CHARS, "MAX_RESULT_PAGE_CHARS": module.MAX_RESULT_PAGE_CHARS,
                      "PREVIEW_FILES": sorted(module.PREVIEW_FILES), "PAGEABLE_FILES": sorted(module.PAGEABLE_FILES)},
        "tools": table,
        "not_engine_tools": {
            "remote_orchestration": list(remote.REMOTE_TOOLS), "engine_native_mcp": native, "legacy_dexq": legacy,
            "engine_tools_served_today": sorted(support.TOOLS),
            "orchestration_vs_engine_overlap": sorted(set(remote.REMOTE_TOOLS) & set(native)),
            "orchestration_vs_dexq_overlap": sorted(set(remote.REMOTE_TOOLS) & set(legacy)),
            "engine_vs_dexq_overlap": sorted(set(native) & set(legacy)),
            "rule": "a call is routed by (server, tool), never by the tool name: `query` is a tool of two servers and of neither orchestration "
                    "call; the `operation` values of submit_job are arguments, not tools",
            "submit_job_operations": list(remote.SUBMIT_JOB_OPERATIONS)},
        "dispatch": {"dispatching": list(remote.DISPATCHING_TOOLS), "non_dispatching": list(remote.NON_DISPATCHING_TOOLS),
                     "evidence": "each tool's dispatch class is checked against the calls it hands on when the frozen gateway runs "
                                 "(test_remote_runner_adapter.py::Registry); version_matrix_status hands on dispatch=False"},
        "responses_keys": responses(work),
        "argument_checks": validation(work),
        "run_attempt_and_artifact_binding": {
            "lookup": "the run is found by the title `hostlab-<request_id>` among the latest 50 runs of the workflow",
            "lookup_title_found_in_source": 'r["display_title"] == "hostlab-" + request_id' in source,
            "artifact_call": "remote_artifacts.get(REPO, request_id, run, gh)",
            "artifact_call_found_in_source": "remote_artifacts.get(REPO, request_id, run, gh)" in source,
            "run_keys_required_for_a_stored_matrix_run": sorted(ast.literal_eval(ast.unparse(needed))),
            "job_status_carries": ["queued_at", "dispatch", "run_attempt", "run_updated_at"],
            "job_result_collection_carries": ["cache_hit", "artifact", "integrity", "elapsed_ms", "run_attempt"],
            "artifact_limits": remote.ARTIFACT_LIMITS,
            "artifact_limits_verified_against": "frozen_extra_copy.remote_artifacts_limits (source-8782f43-extra/remote_artifacts.py:21-24) "
                                                "and inventory cache_layers.artifact",
            "artifact_identity": "repository/request/run/attempt/head SHA + ZIP/files integrity (inventory cache_layers.artifact)",
            "adapter_binding": "run_binding + result_manifest (remote_runner_adapter.py)"},
        "source_sha_binding": {
            "submit_analysis_parameters": ["version_code", "request", "apk_sha256", "sample_revision", "idempotency_key"],
            "passed_on_unchanged": "remote_schedule.submit(version_code, request, gh, lookup, runs, repository=REPO, workflow=WORKFLOW, "
                                   "apk_sha256=apk_sha256, sample_revision=sample_revision, idempotency_key=idempotency_key)",
            "passed_on_found_in_source": "apk_sha256=apk_sha256" in source and "sample_revision=sample_revision" in source,
            "resume": "request.resume={run_id,attempt,request_id} needs the exact APK SHA and sample revision (docstring)"},
        "worker_task_contract": worker_task_contract(),
        "path_scopes": scope_table_record(),
        "not_in_the_frozen_copy": {
            "note": "the main frozen copy the gateway tests load is source-8782f43; six of these modules are in the frozen "
                    "source-8782f43-extra copy (see frozen_extra_copy), the rest were not obtained",
            "modules": [{"module": name, "in_frozen_copy": (ROOT / FROZEN / (name + ".py")).exists(),
                         "in_frozen_extra_copy": (ROOT / EXTRA / (name + ".py")).exists(),
                         "inventory": ({"sha256": listed[name]["sha256"], "bytes": listed[name]["bytes"]} if name in listed else None)}
                        for name in imported],
            "also_not_in_the_main_frozen_copy": [{"module": name, "in_frozen_extra_copy": (ROOT / EXTRA / (name + ".py")).exists(),
                                                  "inventory": {"sha256": listed[name]["sha256"], "bytes": listed[name]["bytes"]}}
                                                 for name in ("analysis_checkpoint", "remote_job", "runner_worker") if name in listed],
            "consequence": "their behaviour is not executed by these controls (the gateway's calls into them are stubbed and "
                           "recorded); the six in the frozen -extra copy are source evidence only, and version_matrix, "
                           "remote_dispatch, runner_group, source_snapshot and adaptive_schedule were not obtained",
        },
        "frozen_extra_copy": frozen_extra_evidence(work / "extra"),
    }


# ================================================================================================================
# the equivalence record
# ================================================================================================================

class Controls:
    def __init__(self) -> None:
        self.items: "list[dict]" = []

    def add(self, name: str, description: str, expected: Any, observed: Any) -> None:
        self.items.append({"id": name, "description": description, "expected": expected, "observed": observed,
                           "ok": expected == observed})


def the_request(*tasks: dict) -> dict:
    return cts.engine_request(*tasks)


def flow(work: Path, name: str, *tasks: dict, **kwargs: Any) -> cts.Flow:
    setup = kwargs.pop("setup", None) or cts.engine_setup(work / name / "engine", platform_name=PLATFORM)
    return cts.Flow(work / name, the_request(*tasks), setup=setup, **kwargs)


def query_task(**extra: Any) -> dict:
    return {"id": "q", "operation": "query", "sql": cts.NUMBERS, "dialect": "dexsql", "limit": 3, **extra}


LOCATE = {"id": "l1", "operation": "locate", "kind": "class", "name": "Lfoo;"}
INFO = {"id": "i", "operation": "info"}


def offsets(server: cts.FakeDexsql) -> "list[list[int]]":
    return [[a["offset"], a["limit"]] for a in server.sql_calls("FROM numbers")]


def states(attempt: cts.Attempt) -> dict:
    state = attempt.document["state"]
    return {"termination": state["termination"], "tasks": [[t["id"], t["status"], t["disposition"]] for t in state["tasks"]],
            "failure_codes": state["failure_codes"]}


def solid(attempt: cts.Attempt, name: str) -> cts.Attempt:
    """An attempt whose every task has a result; otherwise say why not, instead of failing later on a missing key."""
    bad = [[t["id"], t["status"], t.get("error"), str(t.get("message", ""))[:200]] for t in attempt.report["tasks"] if "result" not in t]
    failed = [[s.get("backend"), s.get("error"), str(s.get("message", ""))[:200]] for s in attempt.report["sessions"] if "error" in s]
    need(not bad, f"{name}: tasks without a result: {bad}; failed sessions: {failed}")
    return attempt


def resume_controls(work: Path, controls: Controls) -> None:
    add = controls.add
    # --- a request resumed page by page, nothing run twice
    f = flow(work, "walk", query_task(pagination={"max_pages": 1}), LOCATE)
    first = solid(f.attempt(), "walk 1")
    second = solid(f.attempt(resume=f.resume(first)), "walk 2")
    third = solid(f.attempt(resume=f.resume(second)), "walk 3")
    whole = solid(flow(work, "whole", query_task(), LOCATE).attempt(), "whole")
    walked = third.report["tasks"][0]["result"]["rows"]
    add("resume.walk.offsets", "three attempts with one page each ask the engine for offsets 0, 3, 6 and for the locate task once",
        {"offsets": [[0, 3], [3, 3], [6, 1]], "locate_queries": 1},
        {"offsets": offsets(f.server), "locate_queries": len(f.server.sql_calls("FROM classes"))})
    add("resume.walk.rows", "the rows of the three attempts are the rows of one uninterrupted run, none repeated, none dropped",
        {"equal": True, "count": 7, "unique": 7},
        {"equal": walked == whole.report["tasks"][0]["result"]["rows"], "count": len(walked), "unique": len({r[0] for r in walked})})
    add("resume.walk.terminations", "partial, partial, complete; each attempt names the one before it",
        {"terminations": ["partial", "partial", "complete"], "lineage": [None, True, True]},
        {"terminations": [a.document["state"]["termination"] for a in (first, second, third)],
         "lineage": [None, second.document["resumed_from"]["seal"] == ca.seal_digest(first.document),
                     third.document["resumed_from"]["seal"] == ca.seal_digest(second.document)]})
    add("resume.complete_task_reused", "a complete task is reused, not run again",
        {"reused": 1, "reused_flag": True}, {"reused": third.report["execution"]["reused_complete_tasks"],
                                              "reused_flag": next(t for t in third.report["tasks"] if t["id"] == "l1")["checkpoint_reused"]})

    # --- the adapter changes nothing the executor does
    wired = flow(work, "wired", query_task(), LOCATE, dict(LOCATE, id="l2"), INFO)
    bare = flow(work, "bare", query_task(), LOCATE, dict(LOCATE, id="l2"), INFO)
    with_adapter = solid(wired.attempt(), "wired")
    without = cts.run(bare.batch, bare.apk, bare.frozen_request(), sample={"sha256": bare.sha})
    by_id = {t["id"]: t for t in with_adapter.report["tasks"]}
    add("optimizations.adapter_transparent", "the executor's report is the same with the adapter wired in and without it (wall-clock fields aside)",
        {"reports_equal": True, "same_engine_calls": True},
        {"reports_equal": cts.normalized(with_adapter.report) == cts.normalized(without),
         "same_engine_calls": wired.server.calls[1:] == bare.server.calls[1:]})
    add("optimizations.non_query_memo", "an identical non-query task is answered from the first one: one engine query, reused_from set",
        {"reused_from": "l1", "locate_queries": 1, "dataset_opens": 1, "query_pages": 3},
        {"reused_from": by_id["l2"]["reused_from"], "locate_queries": len(wired.server.sql_calls("FROM classes")),
         "dataset_opens": with_adapter.report["execution"]["dataset_opens"],
         "query_pages": with_adapter.report["execution"]["admitted_query_pages"]})

    # --- identity: each component refuses with its own reason
    base = flow(work, "identity", query_task(pagination={"max_pages": 1}), LOCATE, rule_catalog="ab" * 32, catalog_epoch=0)
    document = base.attempt().document

    def changed(edit: Callable[[dict], None]) -> "str | None":
        expected = json.loads(json.dumps(base.expected))
        edit(expected)
        return refusal(ca.import_checkpoint, document, expected, legacy=base.setup.legacy)

    components = [
        ("schema_changed", lambda e: e["versions"].update(adapter=2)),
        ("engine_changed", lambda e: e["engine"].update(build_id="source-sha256:" + "cd" * 32)),
        ("capability_changed", lambda e: e["engine"].update(mcp_tools_sha256="0" * 64)),
        ("profile_changed", lambda e: e["engine"]["profile"].update(admitted=True)),
        ("dialect_changed", lambda e: e["engine"]["dialect"].update(engine="dexsql-0.1.1")),
        ("config_changed", lambda e: e["engine"].update(config_digest="0" * 64)),
        ("generation_changed", lambda e: e["generation"].update(catalog_epoch=1)),
        ("generation_changed", lambda e: e["generation"].update(namespace="eng-other")),
        ("request_changed", lambda e: e["rule"].update(request_sha256="0" * 64)),
        ("rule_changed", lambda e: e["rule"].update(catalog_sha256="0" * 64)),
        ("source_changed", lambda e: e["source"].update(sha256="0" * 64)),
        ("source_changed", lambda e: e["source"].update(revision="rev-2")),
    ]
    for reason, edit in components:
        add("identity." + reason, "a checkpoint is refused when this component differs", reason, changed(edit))
    add("identity.same", "the same identity resumes", None,
        refusal(ca.import_checkpoint, document, base.expected, legacy=base.setup.legacy))
    add("identity.legacy_schema", "a HostLab schema-2 checkpoint is not upgraded", "legacy_checkpoint_not_upgraded",
        refusal(ca.import_checkpoint, dict(document, schema=2), base.expected, legacy=base.setup.legacy))
    add("identity.tampered", "a document changed after sealing", "seal_mismatch",
        refusal(ca.import_checkpoint, dict(document, origin={"run_id": 9, "attempt": 1, "request_id": "a" * 32}), base.expected,
                legacy=base.setup.legacy))
    forged = json.loads(json.dumps(document))
    forged["state"]["termination"] = "complete"
    body = {k: forged[k] for k in ca._BODY}
    forged["seal"] = {"algorithm": "sha256", "digest": ca.digest_of(body)}
    add("identity.forged_state", "a state edited and sealed again is not trusted: it does not follow from the report", "state_mismatch",
        refusal(ca.import_checkpoint, forged, base.expected, legacy=base.setup.legacy))
    add("identity.origin", "the run, attempt and request claimed must be the ones that made it", "origin_mismatch",
        refusal(ca.import_checkpoint, document, base.expected, claim={"run_id": 999, "attempt": 1, "request_id": "a" * 32},
                legacy=base.setup.legacy))

    # --- snapshots
    pg = flow(work, "snap", query_task(pagination={"max_pages": 1}), LOCATE)
    snap_first = pg.attempt()
    other_bytes = flow(work, "snap-b", query_task(pagination={"max_pages": 1}), LOCATE, apk=cts.APK_B)
    add("snapshot.other_bytes_same_shape", "APK_B answers the same query with the same columns, rows and total but is another source: refused at import",
        "source_changed", refusal(ca.import_checkpoint, snap_first.document, other_bytes.expected, legacy=other_bytes.setup.legacy))
    pg.server.reset()
    refused_run = pg.attempt(resume=pg.resume(snap_first), apk=cts.APK_B, sha=pg.sha)
    add("snapshot.engine_captured_other_bytes", "HostLab hashed A, the engine captured B: refused when the dataset opens, no page read",
        {"pages_read": 0, "reason": "source_binding_mismatch", "termination": "source_changed", "complete": False},
        {"pages_read": len(pg.server.sql_calls("FROM numbers")),
         "reason": refused_run.report["sessions"][-1]["detail"]["error"]["reason"],
         "termination": refused_run.document["state"]["termination"], "complete": refused_run.report["complete"]})
    add("snapshot.refusal_leaves_checkpoint_usable", "the checkpoint it was refused from is untouched and still resumes", "partial",
        pg.resume(snap_first).termination)
    recap = flow(work, "recapture", query_task(pagination={"max_pages": 1}), LOCATE)
    recap_first = recap.attempt()
    recap.server.reset()

    def recapture(body: dict) -> dict:
        body["snapshot_manifest"]["snapshot_content_key"] = "sha256:" + "0" * 64
        return body

    recap.server.open_edit = recapture
    recap_run = recap.attempt(resume=recap.resume(recap_first))
    add("snapshot.engine_captured_differently", "same bytes, another capture: refused when the dataset opens, no page read",
        {"pages_read": 0, "reason": "snapshot_changed"},
        {"pages_read": len(recap.server.sql_calls("FROM numbers")), "reason": recap_run.report["sessions"][-1]["detail"]["error"]["reason"]})
    moved = flow(work, "moved", query_task(pagination={"max_pages": 1}), LOCATE)
    moved_first = moved.attempt()
    elsewhere = work / "moved-copy" / "base.apk"
    elsewhere.parent.mkdir(parents=True, exist_ok=True)
    elsewhere.write_bytes(cts.APK_A.read_bytes())
    moved_second = moved.attempt(resume=moved.resume(moved_first), apk=elsewhere)
    add("snapshot.same_bytes_other_path", "the same bytes at another path resume (the identity is the content, not the path)",
        {"offsets": [[0, 3], [3, 3]], "same_snapshot": True},
        {"offsets": offsets(moved.server),
         "same_snapshot": moved_second.document["identity"]["snapshot"] == moved_first.document["identity"]["snapshot"]})
    server = cts.FakeDexsql()
    first_open = ca.snapshot_identity(server.answer("open_dataset", {"inputs": [str(cts.APK_A)]})[1])
    second_open = ca.snapshot_identity(server.answer("open_dataset", {"inputs": [str(cts.APK_A)]})[1])
    handles = [server.answer("open_dataset", {"inputs": [str(cts.APK_A)]})[1]["dataset_id"] for _ in range(2)]
    add("snapshot.handles_are_not_identity", "two opens of the same bytes: different dataset ids, the same snapshot identity",
        {"dataset_ids_differ": True, "identities_equal": True}, {"dataset_ids_differ": handles[0] != handles[1],
                                                                  "identities_equal": first_open == second_open})
    # --- native cursor
    entry = next(t for t in snap_first.report["tasks"] if t["id"] == "q")
    definition = pg.setup.legacy.validate(pg.frozen_request())["tasks"][0]
    position = ca.page_position(definition, entry["result"])
    add("position.compat_offset", "a partial query is recorded as a compatible offset: where it stopped, how many rows, which columns",
        {"mode": "compat_offset", "next_offset": 3, "rows": 3, "total_rows": 7},
        {k: position[k] for k in ("mode", "next_offset", "rows", "total_rows")})
    add("position.native_cursor_refused", "a position that carries a native cursor token is refused (the cursor dies with its worker)",
        "native_cursor_not_persistable", refusal(ca.check_position, dict(position, next_cursor="tok"), definition, entry["result"]))
    add("position.gap_refused", "a position that does not end where its rows end is refused", "position_inconsistent",
        refusal(ca.check_position, dict(position, next_offset=4), definition, entry["result"]))

    # --- endings: never a completion, never a success
    endings = {}

    def ending(name: str, build: Callable[[], "tuple[cts.Flow, cts.Attempt]"]) -> None:
        owner, attempt = build()
        cache = ca.CompletionCache(owner.ns["completion"])
        resume = ca.import_checkpoint(attempt.document, owner.expected, legacy=owner.setup.legacy) \
            if attempt.document["state"]["termination"] != "source_changed" else None
        endings[name] = {"termination": attempt.document["state"]["termination"],
                         "complete_flag": attempt.report["complete"],
                         "cache_refusal": refusal(cache.store, attempt.document, legacy=owner.setup.legacy),
                         "resume_refusal": refusal(ca.import_checkpoint, attempt.document, owner.expected, legacy=owner.setup.legacy),
                         "resume_success": resume.success if resume else None}

    def lost():
        o = flow(work, "end-lost", LOCATE, INFO)
        o.server.hooks.append(cts.worker_lost_after(1))
        return o, o.attempt()

    def lost_with_prefix():
        o = flow(work, "end-lost-prefix", query_task(), LOCATE)
        o.server.hooks.append(cts.worker_lost_after(2))
        return o, o.attempt()

    def cancelled():
        o = flow(work, "end-cancelled", query_task(), LOCATE)
        o.server.hooks.append(cts.worker_lost_after(2, {"error": {"kind": "cancelled", "code": "CANCELLED", "message": "cancelled",
                                                                  "dataset_closed": True}}))
        return o, o.attempt()

    def cancelled_hint():
        o = flow(work, "end-cancel-hint", LOCATE, INFO)
        return o, o.attempt(hint="cancelled")

    def changed_source():
        o = flow(work, "end-source", LOCATE, INFO)
        o.apk = work / "end-source-moving.apk"
        o.apk.write_bytes(cts.APK_A.read_bytes())
        o.sha = cts.sha256_file(o.apk)
        o.server.hooks.append(lambda name, arguments: o.apk.write_bytes(cts.APK_B.read_bytes()) if name == "close_dataset" else None)
        return o, o.attempt()

    def partial():
        o = flow(work, "end-partial", query_task(pagination={"max_pages": 1}), LOCATE)
        return o, o.attempt()

    def complete():
        o = flow(work, "end-complete", LOCATE, INFO)
        return o, o.attempt()

    for name, build in (("worker_lost_before_any_result", lost), ("worker_lost_after_a_page", lost_with_prefix),
                        ("cancelled_by_engine_code", cancelled), ("cancelled_by_hint", cancelled_hint),
                        ("source_changed_during_the_run", changed_source), ("partial_by_budget", partial),
                        ("complete", complete)):
        ending(name, build)
    expected_endings = {
        "worker_lost_before_any_result": {"termination": "worker_lost", "complete_flag": False, "cache_refusal": "worker_lost",
                                          "resume_refusal": None, "resume_success": False},
        "worker_lost_after_a_page": {"termination": "worker_lost", "complete_flag": False, "cache_refusal": "worker_lost",
                                     "resume_refusal": None, "resume_success": False},
        "cancelled_by_engine_code": {"termination": "cancelled", "complete_flag": False, "cache_refusal": "cancelled",
                                     "resume_refusal": None, "resume_success": False},
        "cancelled_by_hint": {"termination": "cancelled", "complete_flag": True, "cache_refusal": "cancelled",
                              "resume_refusal": None, "resume_success": False},
        "source_changed_during_the_run": {"termination": "source_changed", "complete_flag": False, "cache_refusal": "source_changed",
                                          "resume_refusal": "source_changed", "resume_success": None},
        "partial_by_budget": {"termination": "partial", "complete_flag": False, "cache_refusal": "partial", "resume_refusal": None,
                              "resume_success": False},
        "complete": {"termination": "complete", "complete_flag": True, "cache_refusal": None, "resume_refusal": None,
                     "resume_success": True},
    }
    for name, expected in expected_endings.items():
        add("ending." + name, "how the run ended decides whether it is cached and whether a resume is a success", expected, endings[name])

    # --- the completion cache
    c = flow(work, "cache", LOCATE, INFO)
    done = c.attempt()
    cache = ca.CompletionCache(c.ns["completion"])
    stored = cache.store(done.document, legacy=c.setup.legacy)
    hit = cache.lookup(c.expected, legacy=c.setup.legacy)
    add("cache.store_and_find", "a complete structured result is stored and found again under the same identity",
        {"stored_in_completion_dir": True, "found": True, "no_overwrite": "NamespaceCollision"},
        {"stored_in_completion_dir": stored.parent == c.ns["completion"], "found": hit is not None and hit["seal"] == done.document["seal"],
         "no_overwrite": _collision(cache, done.document, c)})
    sql_flow = flow(work, "cache-sql", query_task(), LOCATE)
    add("cache.arbitrary_sql", "arbitrary SQL is not completion-cached (HostLab does not either)", "arbitrary_sql_not_cached",
        refusal(ca.CompletionCache(sql_flow.ns["completion"]).store, sql_flow.attempt().document, legacy=sql_flow.setup.legacy))
    other = flow(work, "cache-other", LOCATE, INFO, setup=cts.engine_setup(work / "cache-other-engine", platform_name=PLATFORM,
                                                                           content=b"stand-in engine 2",
                                                                           fake=support.FakeEngine(build_id="source-sha256:" + "cd" * 32)))
    add("cache.other_engine_directory", "the completion directory of another engine build is not written", "generation_changed",
        refusal(ca.CompletionCache(other.ns["completion"]).store, done.document, legacy=c.setup.legacy))
    add("cache.other_revision_is_a_miss", "another sample revision is a different entry", None,
        ca.CompletionCache(c.ns["completion"]).lookup(flow(work, "cache-rev", LOCATE, INFO, revision="rev-2").expected,
                                                      legacy=c.setup.legacy))
    entry_path = c.ns["completion"] / (cache.key(c.expected) + ".json")
    entry_path.write_bytes(b"corrupt")
    miss = ca.CompletionCache(c.ns["completion"])
    add("cache.corrupt_entry", "a corrupt entry is not served, not replaced, and reported",
        {"served": False, "kept": True, "rejected": 1},
        {"served": miss.lookup(c.expected, legacy=c.setup.legacy) is not None, "kept": entry_path.read_bytes() == b"corrupt",
         "rejected": len(miss.rejected)})

    # --- rollback
    job = {"backend": "meguvizdexdash", "pages_accepted": 0, "rows_accepted": 0, "temp_side_effects": 0}
    walk = ca.accepted_work(first.report)
    replays = {
        "fresh job, explicit dexsql": (job, "dexsql", True), "fresh job, auto": (job, "auto", True),
        "fresh job, not explicit": (job, "dexsql", False), "same engine": (job, "meguvizdexdash", True),
        "pages accepted": (dict(job, **walk), "dexsql", True), "temp side effect": (dict(job, temp_side_effects=1), "dexsql", True),
    }
    add("rollback.replay", "a new job names its backend; after a page was accepted or TEMP touched it is not replayed on another engine",
        {"fresh job, explicit dexsql": "replay", "fresh job, auto": "refuse", "fresh job, not explicit": "refuse",
         "same engine": "same_engine", "pages accepted": "refuse", "temp side effect": "refuse"},
        {name: ca.replay_decision(j, target, explicit=e).action for name, (j, target, e) in replays.items()})
    path = c.root / "readback.json"
    path.write_text(json.dumps(done.document), encoding="utf-8")
    before = path.read_bytes()
    read = ca.read_back(path)
    add("rollback.read_back", "an engine job is read back under its own identity and nothing is written or converted",
        {"kind": "mdd_checkpoint", "same_identity": True, "unchanged": True},
        {"kind": read.kind, "same_identity": read.identity == done.document["identity"], "unchanged": path.read_bytes() == before})
    bare_report = cts.run(c.batch, c.apk, c.frozen_request(), sample={"sha256": c.sha})
    legacy_read = ca.read_back(bare_report, c.expected)
    add("rollback.hostlab_checkpoint", "a HostLab report/checkpoint is read as its original engine's and is never resumed by the new engine",
        {"kind": "hostlab_legacy", "backends": ["dexsql"], "reason": "legacy_checkpoint_not_upgraded"},
        {"kind": legacy_read.kind, "backends": legacy_read.identity["backends"], "reason": legacy_read.reason})


def _collision(cache: ca.CompletionCache, document: dict, owner: cts.Flow) -> str:
    try:
        cache.store(document, legacy=owner.setup.legacy)
    except provider.NamespaceCollision:
        return "NamespaceCollision"
    return "overwritten"


def remote_controls(work: Path, controls: Controls) -> None:
    add = controls.add
    gateway = rts.Gateway(work / "remote-dispatch", rts.FakeGitHub())
    gateway.recorder.raises["remote_dispatch.dispatch"] = RuntimeError("died during dispatch")
    try:
        gateway.call("submit_job", version_code=1, operation="info")
    except RuntimeError:
        pass
    request_id = gateway.recorder.named("remote_dispatch.dispatch")[0]["args"][2]["request_id"]
    gateway.call("job_status", request_id=request_id)
    add("remote.unknown_dispatch_not_replayed", "a dispatch that died is journalled first, looked up by title, and never sent again",
        {"journal_before_dispatch": "dispatch_unknown", "journal_after": "dispatch_unknown", "dispatches": 1, "mutating_gh_calls": 0,
         "job_state": "dispatch_unknown", "redispatch_allowed": False},
        {"journal_before_dispatch": gateway.recorder.journal_at_dispatch[0]["status"], "journal_after": gateway.journal(request_id)["status"],
         "dispatches": len(gateway.recorder.named("remote_dispatch.dispatch")), "mutating_gh_calls": len(gateway.github.guard.mutations),
         "job_state": remote.job_state(gateway.journal(request_id), None),
         "redispatch_allowed": remote.redispatch_allowed("dispatch_unknown", new_idempotency_key=True)})
    audit = {}
    minimal = {"plan_version_matrix": dict(samples=[], request={}), "advance_version_matrix": dict(matrix_id="m"),
               "version_matrix_status": dict(matrix_id="m"), "version_matrix_result": dict(matrix_id="m"),
               "plan_analysis": dict(request={}), "job_status": dict(request_id=rts.REQUEST_ID), "list_jobs": {},
               "job_result": dict(request_id=rts.REQUEST_ID), "submit_version_matrix": dict(samples=[], request={}),
               "recover_version_matrix": dict(matrix_id="m"), "submit_analysis": dict(version_code=1, request={}),
               "submit_job": dict(version_code=1, operation="info")}
    dispatching_labels = {"version_matrix.create", "version_matrix.recover", "remote_schedule.submit", "remote_dispatch.dispatch"}
    for tool in remote.REMOTE_TOOLS:
        g = new_gateway(work, "audit-" + tool, [rts.run_record()])
        g.call(tool, **minimal[tool])
        handed = [c["call"] for c in g.recorder.calls
                  if c["call"] in dispatching_labels or (c["call"] == "version_matrix.advance" and c["kwargs"].get("dispatch", True))]
        audit[tool] = {"class": remote.dispatch_class(tool), "hands_on_a_dispatching_call": bool(handed),
                       "gh_calls": len(g.github.calls), "mutating_gh_calls": len(g.github.guard.mutations)}
    add("remote.dispatch_audit", "the seven non-dispatching tools hand on no dispatching call and run no mutating gh call; the five dispatching ones do hand one on",
        {tool: {"class": remote.dispatch_class(tool), "hands_on_a_dispatching_call": tool in remote.DISPATCHING_TOOLS,
                "mutating_gh_calls": 0} for tool in remote.REMOTE_TOOLS},
        {tool: {k: v[k] for k in ("class", "hands_on_a_dispatching_call", "mutating_gh_calls")} for tool, v in audit.items()})
    status = new_gateway(work, "status", [])
    status.call("version_matrix_status", matrix_id="m")
    add("remote.status_does_not_dispatch", "version_matrix_status asks the queue to advance with dispatch=False", False,
        status.recorder.named("version_matrix.advance")[0]["kwargs"]["dispatch"])
    both = [rts.run_record(attempt=2)]
    g = new_gateway(work, "binding", both)
    g.call("job_result", request_id=rts.REQUEST_ID)
    handed_run = g.recorder.named("remote_artifacts.get")[0]["args"][2]
    run = both[0]
    root = work / "binding-artifact"
    files = sorted(p for p in root.rglob("*") if p.is_file())
    pin = {"runner_revision": rts.HEAD, "sample": {"apk_sha256": "ab" * 32}, "engine": {"build_id": "b"}, "task_backends": {"a": "meguvizdexdash"},
           "config_digest": "c" * 64, "request_sha256": "d" * 64}
    manifest = remote.result_manifest(handed_run, rts.REQUEST_ID, rts.REPO, rts.WORKFLOW, root, files, pin=pin, termination="complete")
    ok = {"run": handed_run, "request_id": rts.REQUEST_ID, "repository": rts.REPO, "workflow": rts.WORKFLOW, "pin": pin, "root": root}
    add("remote.binding.positive", "the run the gateway hands to the artifact check binds the artifact to its attempt, head SHA, sample and engine pin",
        {"verified": None, "attempt": 2, "files": 3, "registrable": True},
        {"verified": refusal(remote.verify_result_manifest, manifest, **ok), "attempt": manifest["binding"]["run_attempt"],
         "files": len(manifest["files"]), "registrable": remote.registrable_as_complete(manifest)})

    def other_pin(edit: Callable[[dict], None]) -> dict:
        changed = json.loads(json.dumps(pin))
        edit(changed)
        return changed

    negatives = {
        "another attempt": ({"run": dict(run, run_attempt=3)}, "run_attempt_mismatch"),
        "another run": ({"run": dict(run, id=1)}, "run_mismatch"),
        "another head sha": ({"run": dict(run, head_sha="1" * 40)}, "head_sha_mismatch"),
        "another request": ({"request_id": rts.OTHER_REQUEST_ID, "run": dict(run, display_title="hostlab-" + rts.OTHER_REQUEST_ID)},
                            "request_id_mismatch"),
        "another repository": ({"repository": "other/repo"}, "repository_mismatch"),
        "another engine": ({"pin": other_pin(lambda p: p.update(engine={"build_id": "other"}))}, "engine_changed"),
        "another sample": ({"pin": other_pin(lambda p: p["sample"].update(apk_sha256="0" * 64))}, "source_changed"),
        "another runner revision": ({"pin": other_pin(lambda p: p.update(runner_revision="2" * 40))}, "runner_changed"),
    }
    add("remote.binding.negatives", "a result is not read back for another attempt, run, head SHA, request, repository, engine, sample or runner",
        {name: reason for name, (_, reason) in negatives.items()},
        {name: refusal(remote.verify_result_manifest, manifest, **{**ok, **changes}) for name, (changes, _) in negatives.items()})
    (root / "result.txt").write_text("changed", encoding="utf-8")
    add("remote.binding.file_changed", "a changed artifact file is refused", "file_changed",
        refusal(remote.verify_result_manifest, manifest, **ok))
    ends = {t: remote.registrable_as_complete(remote.result_manifest(handed_run, rts.REQUEST_ID, rts.REPO, rts.WORKFLOW, root, files,
                                                                     pin=pin, termination=t))
            for t in ("complete", "partial", "cancelled", "worker_lost", "source_changed")}
    add("remote.registrable", "only a completed analysis of a successful run is registrable as a completion",
        {"complete": True, "partial": False, "cancelled": False, "worker_lost": False, "source_changed": False}, ends)
    add("remote.failed_run_has_no_manifest", "a failed, cancelled or running run has no result manifest",
        ["run_not_successful", "run_not_successful", "run_not_completed"],
        [refusal(remote.result_manifest, dict(run, conclusion=c), rts.REQUEST_ID, rts.REPO, rts.WORKFLOW, root, files, pin=pin,
                 termination="complete") for c in ("failure", "cancelled")]
        + [refusal(remote.result_manifest, dict(run, status="in_progress", conclusion=None), rts.REQUEST_ID, rts.REPO, rts.WORKFLOW, root,
                   files, pin=pin, termination="complete")])
    # the pin of a job, built before anything is dispatched
    setup = cts.engine_setup(work / "pin-engine", platform_name=PLATFORM)
    sample = {"sha256": "ab" * 32, "revision": "rev-1", "version_code": 9170100}
    request = the_request(LOCATE, query_task())
    planned = remote.plan_ci(request, setup.config, runner_revision=rts.HEAD, sample=sample, legacy=setup.legacy, engine_status=setup.status)
    resumed = remote.plan_ci(dict(request, resume={"run_id": 5, "attempt": 1, "request_id": "a" * 32}), setup.config,
                             runner_revision=rts.HEAD, sample=sample, legacy=setup.legacy, engine_status=setup.status)
    legacy_plan = remote.plan_ci(dict(the_request(LOCATE), backend="dexsql"), setup.config, runner_revision=rts.HEAD,
                                 sample=sample, legacy=setup.legacy, engine_status=None)
    add("remote.pin", "a job is pinned to runner, sample, backend, engine and configuration before it is dispatched; resume does not change the pin; work on a legacy backend has no engine",
        {"dispatches": False, "task_backends": {"l1": "meguvizdexdash", "q": "meguvizdexdash"}, "resume_same_pin": True,
         "legacy_engine": None, "legacy_backends": {"l1": "dexsql"}},
        {"dispatches": planned["dispatches"], "task_backends": planned["pin"]["task_backends"], "resume_same_pin": resumed["pin"] == planned["pin"],
         "legacy_engine": legacy_plan["pin"]["engine"], "legacy_backends": legacy_plan["pin"]["task_backends"]})
    add("remote.pin.engine_changed", "a job pinned under one engine build is refused under another", "engine_changed",
        refusal(remote.check_pin, planned["pin"], other_pin_of(planned["pin"], build_id="source-sha256:" + "cd" * 32)))
    add("remote.routing", "an orchestration tool is not an engine tool and an engine tool is not an orchestration tool; `query` is routed by its server",
        {"plan_analysis@engine": "tool_not_on_server", "open_dataset@hostlab-remote": "tool_not_on_server",
         "query@meguvizdexdash": "engine_native", "query@dexq": "legacy_dexq", "plan_analysis@hostlab-remote": "remote_orchestration"},
        {"plan_analysis@engine": refusal(remote.route, remote.ENGINE_SERVER, "plan_analysis"),
         "open_dataset@hostlab-remote": refusal(remote.route, remote.REMOTE_SERVER, "open_dataset"),
         "query@meguvizdexdash": remote.route(remote.ENGINE_SERVER, "query"), "query@dexq": remote.route(remote.LEGACY_SERVER, "query"),
         "plan_analysis@hostlab-remote": remote.route(remote.REMOTE_SERVER, "plan_analysis")})


def other_pin_of(pin: dict, **engine: Any) -> dict:
    changed = json.loads(json.dumps(pin))
    changed["engine"].update(engine)
    return changed


ANCHORS = [
    ("non-query memo", FROZEN + "analysis_batch.py", 'reused = memo.get(identity) if task["operation"] != "query" else None',
     "complete non-query tasks of one backend session are answered from the first identical one"),
    ("memo is filled only by complete non-query results", FROZEN + "analysis_batch.py",
     'if not output["partial"] and task["operation"] != "query":\n                                memo[identity] = (name, output)', "no partial or query result is memoised"),
    ("one session per backend", FROZEN + "analysis_plan.py", '"execution": "one_sequential_session_per_backend"', "one prepared dataset per backend group"),
    ("bounded batch result budget", FROZEN + "analysis_batch.py", "MAX_RESULT_BYTES = 2 * 1024 * 1024", "2 MiB of results per batch"),
    ("bounded decode text", FROZEN + "analysis_batch.py", "len(body.encode()) < 64000", "decode continues only while the text stays under 64000 bytes"),
    ("64 KiB read chunks", FROZEN + "native_cli.py", "self.process.stdout.read1(64*1024)", "the audit CLI is read in chunks of at most 64 KiB"),
    ("bounded queue", FROZEN + "native_cli.py", "self.messages = queue.Queue(maxsize=8)", "at most 8 chunks wait for the consumer"),
    ("range filter", FROZEN + "native_surface.py", '" AND method_idx BETWEEN "', "code_items are narrowed to the min/max method index per DEX"),
    ("checkpoint resume", FROZEN + "analysis_batch.py", 'report["resume_origin"] = copy.deepcopy(resume["resume_origin"])',
     "complete tasks are reused, partial queries continue at their cursor"),
    ("durable version-matrix queue", FROZEN + "remote_mcp.py", "Create a durable exact-version queue", "the queue behind submit/advance/status/result"),
    ("no completion cache for arbitrary SQL", FROZEN + "remote_mcp.py", "Ordinary arbitrary SQL is not completion-cached",
     "HostLab does not completion-cache arbitrary SQL"),
]


def optimizations() -> dict:
    manifest = {f["path"]: f["sha256"] for f in json.loads(read(FROZEN + "manifest.json"))["files"] if "path" in f}
    adapters = "\n".join(read(p) for p in ("integrations/hostlab/checkpoint_adapter.py", "integrations/hostlab/remote_runner_adapter.py"))
    kept = []
    for name, path, anchor, meaning in ANCHORS:
        text = read(path)
        need(text.count(anchor) == 1, f"optimisation anchor not found exactly once: {name}")
        need(sha256_file(ROOT / path) == manifest[path], f"{path} is not the frozen source")
        kept.append({"name": name, "evidence": {"file": path, "sha256": manifest[path], "anchor": anchor}, "meaning": meaning,
                     "status": "kept_as_is", "reimplemented_by_the_adapters": anchor in adapters, "claimed_as_new_gain": False})
    need(not any(k["reimplemented_by_the_adapters"] for k in kept), "an adapter reimplements an existing optimisation")
    return {"rule": "these exist in HostLab at the frozen commit and are not registered as gains of the new engine; the adapters neither "
                    "reimplement nor bypass them (the differential control optimizations.adapter_transparent)",
            "kept": kept, "new_gains_claimed": []}


def build_equivalence(work: Path, contracts_text: str) -> dict:
    controls = Controls()
    remote_controls(work, controls)
    resume_controls(work, controls)
    controls.add("resume.hostlab_loader_lineage",
                 "the frozen -extra analysis_checkpoint.summary cannot read the adapter's nested resume_origin lineage (KeyError) "
                 "but reads the loader's flat origin; the loader overwrites resume_origin (frozen_extra_copy.analysis_checkpoint_loader)",
                 {"summary_with_adapter_lineage": "KeyError", "summary_with_loader_origin": "accepted"},
                 loader_lineage_demo(work / "loader"))
    failed = [c["id"] for c in controls.items if not c["ok"]]
    need(not failed, "controls failed: " + ", ".join(failed))
    return {
        "schema": "mdd.hostlab-remote-resume-equivalence.v1", "task": "MDD-053",
        "generated_by": {"script": "integrations/hostlab/remote_make_records.py", "command": "python -I integrations/hostlab/remote_make_records.py",
                         "check": "... --check", "deterministic": True},
        "engine_identity_source": {"kind": "stand-in", "platform": PLATFORM,
                                   "note": "hostlab_test_support.FakeEngine answers version/capabilities/mcp, pinned and probed through install_meguvizdexdash.py; "
                                           "checkpoint_test_support.FakeDexsql answers the MCP calls with the real shape. HostLab's batch executor and paging "
                                           "module are the frozen originals. test_checkpoint_live_engine.py runs the resume flow against the real binary."},
        "inputs": {"files": inputs()},
        "controls": controls.items,
        "summary": {"controls": len(controls.items), "ok": sum(c["ok"] for c in controls.items), "failed": failed},
        "existing_optimizations": optimizations(),
        "remote_contract": {"file": "conformance/hostlab/remote-contracts.json",
                            "sha256": hashlib.sha256(contracts_text.encode("utf-8")).hexdigest()},
        "not_run": [
            "any GitHub Actions run, any `gh` call to the network, any workflow dispatch: the gh runner is a guard that runs nothing",
            "the real engine inside these controls: they use stand-ins (the real-engine flow is test_checkpoint_live_engine.py)",
            "the 0.1.1 dialect, Linux and macOS"],
        "not_proven": [
            "the frozen -extra analysis_checkpoint.py shows HostLab's loader builds its own `resume_origin` and overwrites the report's, and its summary "
            "reads flat keys (run_id/attempt/artifact_id/reused_complete_tasks) the adapter's nested lineage does not have: the sealed envelope here is the "
            "adapter's own chain, not consumed by HostLab's loader or summary (demonstrated by resume.hostlab_loader_lineage). version_matrix.py, "
            "remote_dispatch.py, runner_group.py, source_snapshot.py and adaptive_schedule.py were not obtained; submit/recover idempotency and the queue are not shown",
            "that analysis_batch.execute, wired to the provider, runs a whole analysis on the new engine: the frozen executor only knows the backends "
            "sqlite and dexsql, so these controls label the engine's work `dexsql`; the mapping to `meguvizdexdash` is the integration's",
            "the snapshot capture on a real HostLab deployment: it needs analysis_batch.Client replaced by OpenCapture.wrap(Client)",
            "any performance claim: nothing here is timed, and no existing optimisation is counted as a gain"],
    }


def shown(path: Path) -> str:
    return str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)


def render(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def build_all() -> "tuple[str, str]":
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
        work = Path(directory).resolve()
        contracts = render(build_contracts(work / "contracts"))
        return contracts, render(build_equivalence(work / "equivalence", contracts))


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if a committed record differs from a fresh run")
    args = parser.parse_args(argv)
    try:
        contracts, equivalence = build_all()
    except Violation as error:
        print("a fact the records are built on does not hold: " + str(error), file=sys.stderr)
        return 2
    records = ((CONTRACTS, contracts), (EQUIVALENCE, equivalence))
    if args.check:
        stale = [path for path, text in records if not path.exists() or path.read_text(encoding="utf-8") != text]
        for path in stale:
            print(f"{shown(path)} is not what the generator produces; run it without --check", file=sys.stderr)
        if stale:
            return 1
        for path, _ in records:
            print(f"{shown(path)} is current")
        return 0
    for path, text in records:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {shown(path)} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
