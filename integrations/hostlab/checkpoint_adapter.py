"""HostLab checkpoint, resume identity and page position for the MeguvizDexDash engine (MDD-053, HL-13/HL-14).

HostLab's batch executor (analysis_batch.execute) already knows how to resume: it reuses `complete` tasks,
continues a partial DexSQL-dialect query at its admitted `next_offset`, and never replays an admitted prefix.
This module changes none of that. It adds what the executor cannot know about a new engine: which engine build,
profile, dialect, configuration, request, rule set, source bytes and directory generation produced a checkpoint,
and a refusal to resume it under any other. The executor is not edited; this layer wraps it:

* `OpenCapture` wraps the MCP client factory and keeps the `open_dataset` answer that `Session.open` throws away
  (the engine's `snapshot_manifest`). It is also where a resume is bound to the snapshot the engine really opened.
* `CheckpointWriter` is the executor's `checkpoint=` callback. Progress is written to one replaceable in-flight
  file; the final report is sealed into a new file that is never overwritten.
* `import_checkpoint` verifies a sealed document and hands the executor a `resume=` seed that contains only what may
  be reused: complete tasks, and partial queries whose position is consistent with the rows they carry.
* `CompletionCache` stores only a complete, source-verified, snapshot-bound result of a structured (non-SQL)
  request, in the engine's own completion directory.
* `replay_decision` and `read_back` are the rollback rules: a job is read back under the identity it was made
  with, and never replayed on another engine after a page was accepted or a TEMP side effect happened.

What outlives a process, and what does not (measured on the real engine, see test_checkpoint_live_engine.py):
`snapshot_id`, `dataset_id` and `scope_id` are new for every open of the same bytes, so they are never part of an
identity. `snapshot_manifest.snapshot_content_key` and the per-input `content_id` (the SHA-256 of the input bytes)
are the same for the same bytes at any path, and they are the source identity. A native cursor token is bound to
one worker generation and dies with it (mdd-session cursors.rs); a checkpoint therefore records the compatible
offset (`next_offset`) and nothing else, and a position that carries a cursor token is refused.

Standard library only, plus `provider` (the MDD-050 selection layer, used as it is). Nothing here touches the
network or HostLab's own directories.
"""
from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

import provider

CHECKPOINT_SCHEMA = "mdd.hostlab-checkpoint.v1"
IDENTITY_SCHEMA = "mdd.hostlab-checkpoint-identity.v1"
POSITION_SCHEMA = "mdd.hostlab-page-position.v1"
ADAPTER_SCHEMA = 1
REPORT_SCHEMA = 1  # analysis_batch.execute: report["schema"]
REQUEST_SCHEMA = 1  # analysis_plan.SCHEMA
LEGACY_CHECKPOINT_SCHEMA = 2  # HostLab's own checkpoint.json; read back, never rewritten or upgraded
PAGING_MODE = "compat_offset"
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024  # HostLab's result budget is 2 MiB; the rest is identity and request
MAX_OFFSET = 100000  # analysis_paging: the DexSQL offset budget

TERMINATIONS = ("complete", "partial", "worker_lost", "cancelled", "source_changed", "in_flight")
RESUMABLE = ("complete", "partial", "worker_lost", "cancelled")  # a verified source; some work may remain
HINTS = (None, "cancelled", "worker_lost")
_TYPE_CODES = {"WorkerLost": "WORKER_LOST", "Cancelled": "CANCELLED", "CancelledError": "CANCELLED"}

# Every refusal has a reason and an engine error code (provider.ENGINE_CODES, checked by the tests). None of the
# codes is one of provider.FALLBACK_ELIGIBLE: a refused resume is a failure, never a reason to switch engines.
REASONS = {
    "malformed_checkpoint": "CACHE_CORRUPT", "document_too_large": "CACHE_CORRUPT", "seal_mismatch": "CACHE_CORRUPT",
    "state_mismatch": "CACHE_CORRUPT", "checkpoint_not_sealed": "CACHE_CORRUPT",
    "unknown_checkpoint_schema": "STALE_CACHE", "legacy_checkpoint_not_upgraded": "STALE_CACHE",
    "schema_changed": "STALE_CACHE", "engine_changed": "STALE_CACHE", "capability_changed": "STALE_CACHE",
    "profile_changed": "STALE_CACHE", "dialect_changed": "STALE_CACHE", "config_changed": "STALE_CACHE",
    "generation_changed": "STALE_CACHE", "rule_changed": "STALE_CACHE",
    "request_changed": "INVALID_ARGUMENT", "origin_mismatch": "INVALID_ARGUMENT", "origin_invalid": "INVALID_ARGUMENT",
    "plan_does_not_use_engine": "INVALID_ARGUMENT", "invalid_hint": "INVALID_ARGUMENT",
    "source_changed": "SOURCE_CHANGED", "snapshot_changed": "SOURCE_CHANGED", "source_binding_mismatch": "SOURCE_CHANGED",
    "source_not_bound": "SOURCE_CHANGED", "results_without_snapshot_binding": "SOURCE_CHANGED",
    "snapshot_unreadable": "SOURCE_CHANGED", "snapshots_disagree": "SOURCE_CHANGED",
    "native_cursor_not_persistable": "INVALID_CURSOR", "position_inconsistent": "INVALID_CURSOR",
    "page_does_not_continue": "INVALID_CURSOR",
    "cancelled": "CANCELLED", "worker_lost": "WORKER_LOST", "partial": "INVALID_ARGUMENT",
    "in_flight": "INVALID_ARGUMENT", "arbitrary_sql_not_cached": "INVALID_ARGUMENT",
    "snapshot_not_bound": "SOURCE_CHANGED",
    "nothing_reusable": "INVALID_ARGUMENT",
    "backend_not_explicit": "INVALID_ARGUMENT", "pages_already_accepted": "INVALID_ARGUMENT",
    "temp_side_effects": "INVALID_ARGUMENT", "invalid_job": "INVALID_ARGUMENT",
}


class CheckpointRefused(provider.ProviderError):
    """A checkpoint, cache entry or replay that must not be used. `reason` is stable, `code` is the engine's."""

    def __init__(self, reason: str, message: "str | None" = None, *, component: "str | None" = None, **detail: Any):
        super().__init__(message or reason)
        self.reason, self.component = reason, component
        self.code = REASONS[reason]
        # HostLab records `exc.detail` in its report; provider.classify_failure reads the engine code from it
        self.detail = {"error": {"kind": "checkpoint_refused", "code": self.code, "reason": reason}, **detail}


class ResumeRefused(CheckpointRefused):
    pass


class WorkerLost(RuntimeError):
    """The engine's channel ended during a call: the process died, the pipe broke, the stream closed. HostLab records the
    exception by type name and `detail`; this one carries the engine's own code so that the report says WORKER_LOST."""

    code = "WORKER_LOST"

    def __init__(self, message: str):
        super().__init__(message)
        self.detail = {"error": {"kind": "worker_lost", "code": self.code, "message": message}}


_TRANSPORT_LOST = (ConnectionError, EOFError)  # ConnectionError covers BrokenPipeError and ConnectionResetError
_TRANSPORT_LOST_NAMES = frozenset({"ClosedResourceError", "BrokenResourceError", "EndOfStream", "IncompleteReadError"})


class CompletionRefused(CheckpointRefused):
    pass


class ReplayRefused(CheckpointRefused):
    pass


def canonical(value: Any) -> str:
    return provider.canonical(value)


def digest_of(value: Any) -> str:
    return provider.digest_of(value)


def _plain(value: Any) -> Any:
    """A deep copy through JSON: what a file would hold (int keys become strings, tuples lists)."""
    return json.loads(json.dumps(value, ensure_ascii=False))


def _legacy() -> Any:
    return importlib.import_module("analysis_plan")


_SHA = re.compile(r"[0-9a-f]{64}")
_CONTENT = re.compile(r"sha256:[0-9a-f]{64}")
_REQUEST_ID = re.compile(r"[0-9a-f]{32}")


# ---- the request ---------------------------------------------------------------------------------------------

def normalize_request(request: Any, legacy: Any = None) -> "tuple[dict, str, dict]":
    """The request as HostLab's planner validates it, its fingerprint, and the request as sealed. `resume` is dropped
    from all three: a resumed request must keep the identity of the original, and HostLab's fingerprint covers
    `resume`. The fingerprint is the provider's, so a request that names the new engine never shares one with the
    same request for DexSQL (HostLab's planner is shown it as `dexsql`, as provider.plan does)."""
    legacy = legacy or _legacy()
    if not isinstance(request, dict):
        raise CheckpointRefused("request_changed", "the request is not an object")
    sealed = {key: value for key, value in request.items() if key != "resume"}
    base, _ = provider.split_request(sealed)
    shaped = dict(base, backend="dexsql") if isinstance(base, dict) and base.get("backend") == provider.ENGINE else base
    return legacy.validate(shaped), provider.request_fingerprint(sealed, legacy), _plain(sealed)


# ---- identity --------------------------------------------------------------------------------------------------

_ENGINE_REQUIRED = ("engine_version", "build_id", "binary_sha256", "profile", "dialect", "config_digest",
                    "mcp_tools_sha256")
_NAMED = ("mcp_tools_sha256", "profile", "dialect", "config_digest")


def expected_identity(plan_: Mapping, config: provider.Config, *, request: Any, sha256: str,
                      revision: "str | None" = None, legacy: Any = None,
                      rule_catalog_sha256: "str | None" = None, catalog_epoch: "int | None" = None) -> dict:
    """Everything that is known before the engine opens the source. `snapshot` is None until it has."""
    engine = (plan_.get("provider") or {}).get("engine")
    if engine is None:
        raise CheckpointRefused("plan_does_not_use_engine", "this plan does not use " + provider.ENGINE)
    if any(key not in engine for key in _ENGINE_REQUIRED):
        raise CheckpointRefused("malformed_checkpoint", "the plan's engine identity is incomplete")
    if engine["config_digest"] != config.digest():
        raise CheckpointRefused("config_changed", "the plan was made under another configuration")
    if not isinstance(sha256, str) or not _SHA.fullmatch(sha256):
        raise CheckpointRefused("source_changed", "the source needs a SHA-256", component="sha256")
    if revision is not None and (not isinstance(revision, str) or not revision or len(revision) > 256):
        raise CheckpointRefused("source_changed", "invalid sample revision", component="revision")
    if rule_catalog_sha256 is not None and not (isinstance(rule_catalog_sha256, str) and _SHA.fullmatch(rule_catalog_sha256)):
        raise CheckpointRefused("rule_changed", "the rule catalog needs a SHA-256")
    if catalog_epoch is not None and (type(catalog_epoch) is not int or catalog_epoch < 0):
        raise CheckpointRefused("generation_changed", "invalid catalog epoch")
    _, fingerprint, _ = normalize_request(request, legacy)
    return {"schema": IDENTITY_SCHEMA,
            "versions": {"checkpoint": CHECKPOINT_SCHEMA, "adapter": ADAPTER_SCHEMA, "report": REPORT_SCHEMA,
                         "request": REQUEST_SCHEMA, "paging": PAGING_MODE},
            "engine": _plain(engine),
            "generation": {"namespace": provider.engine_dir(engine), "catalog_epoch": catalog_epoch},
            "rule": {"request_sha256": fingerprint, "catalog_sha256": rule_catalog_sha256},
            "source": {"sha256": sha256, "revision": revision},
            "snapshot": None}


def with_snapshot(identity: Mapping, snapshot: "Mapping | None") -> dict:
    result = _plain(identity)
    result["snapshot"] = _plain(snapshot) if snapshot is not None else None
    return result


def _whole(value: Any, where: str) -> int:
    text = str(value)
    if not (text.isascii() and text.isdigit()):
        raise CheckpointRefused("snapshot_unreadable", f"{where} is not a non-negative integer")
    return int(text)


def snapshot_identity(opened: Any) -> dict:
    """The part of an `open_dataset` answer that survives a process: the content key and one content id per input,
    in order. The session handles of the answer (`snapshot_id`, `dataset_id`, `scope_id`) are left out on purpose."""
    manifest = opened.get("snapshot_manifest") if isinstance(opened, Mapping) else None
    if not isinstance(manifest, Mapping):
        raise CheckpointRefused("snapshot_unreadable", "open_dataset carried no snapshot manifest")
    key, sources = manifest.get("snapshot_content_key"), manifest.get("sources")
    if not isinstance(key, str) or not _CONTENT.fullmatch(key) or not isinstance(sources, list) or not sources:
        raise CheckpointRefused("snapshot_unreadable", "the snapshot manifest has no content key or no sources")
    inputs = []
    for source in sources:
        if not isinstance(source, Mapping) or not isinstance(source.get("content_id"), str) \
                or not _CONTENT.fullmatch(source["content_id"]) or not isinstance(source.get("input_kind"), str):
            raise CheckpointRefused("snapshot_unreadable", "a snapshot source is malformed")
        inputs.append({"ordinal": _whole(source.get("input_ordinal"), "input_ordinal"), "kind": source["input_kind"],
                       "content_id": source["content_id"], "byte_length": _whole(source.get("byte_length"), "byte_length")})
    if [item["ordinal"] for item in inputs] != list(range(len(inputs))):
        raise CheckpointRefused("snapshot_unreadable", "snapshot inputs are not numbered 0..n-1 in order")
    return {"content_key": key, "inputs": inputs}


def bind_to_sample(snapshot: Mapping, sha256: str) -> None:
    """HostLab analyses one input per job and names it by SHA-256: the engine must have captured exactly those bytes."""
    inputs = snapshot["inputs"]
    if len(inputs) != 1 or inputs[0]["content_id"] != "sha256:" + sha256:
        raise ResumeRefused("source_binding_mismatch",
                            "the engine did not capture the bytes HostLab hashed", component="sha256")


def handles(opened: Mapping) -> dict:
    """The session-scoped names of one open. Diagnostic only: a new process gets new ones for the same bytes."""
    return {key: opened.get(key) for key in ("dataset_id", "snapshot_id", "scope_id")}


# ---- page position: mdd cursor -> compatible offset ------------------------------------------------------------------

def columns_digest(columns: Any) -> str:
    return digest_of([[c.get("name"), c.get("data_type"), c.get("nullable")] for c in columns])


def _statement(result: Any) -> dict:
    try:
        return result["typed_result"]["statements"][0]
    except (KeyError, TypeError, IndexError):
        raise CheckpointRefused("position_inconsistent", "the result has no typed query statement") from None


def page_position(task: Mapping, result: Mapping) -> "dict | None":
    """Where a partial DexSQL-dialect query stopped, as a compatible offset. None when there is nothing to continue
    (a complete result, or a backend that truncated without a cursor). Refuses a result whose rows, offset, SQL or
    totals disagree with each other: a position that cannot be proven is not recorded."""
    statement = _statement(result)
    cursor = statement.get("next_offset")
    if cursor is None:
        return None
    rows, pagination = statement.get("rows"), result.get("pagination")
    start = task.get("offset", 0)
    if (type(cursor) is not int or not isinstance(rows, list) or not isinstance(pagination, Mapping)
            or type(start) is not int or statement.get("offset") != start or not 0 <= cursor <= MAX_OFFSET
            or cursor != start + len(rows) or pagination.get("next_offset") != cursor
            or len(result.get("rows") or []) != len(rows)
            or pagination.get("sql_sha256") != hashlib.sha256(task.get("sql", "").encode("utf-8")).hexdigest()
            or type(pagination.get("pages")) is not int or pagination["pages"] < 1):
        raise CheckpointRefused("position_inconsistent", "the admitted rows do not end at the recorded offset")
    return {"schema": POSITION_SCHEMA, "mode": PAGING_MODE, "task": task.get("id"),
            "sql_sha256": pagination["sql_sha256"], "start_offset": start, "next_offset": cursor, "rows": len(rows),
            "pages": pagination["pages"], "total_rows": statement.get("total_rows"),
            "page_limit_cap": pagination.get("page_limit_cap"), "columns_sha256": columns_digest(statement.get("columns") or []),
            "rows_sha256": digest_of(rows)}


def check_position(position: Mapping, task: Mapping, result: Mapping) -> None:
    """A recorded position is the one that `result` would produce now. A cursor token anywhere in it is refused."""
    if not isinstance(position, Mapping):
        raise CheckpointRefused("position_inconsistent", "no position")
    if position.get("mode") != PAGING_MODE or any(key in position for key in ("cursor", "next_cursor", "cursor_token")):
        raise CheckpointRefused("native_cursor_not_persistable",
                                "only a compatible offset survives a process; a native cursor dies with its worker")
    if position != page_position(task, result):
        raise CheckpointRefused("position_inconsistent", "the position does not match the admitted rows")


def next_page_check(position: Mapping, statement: Mapping) -> None:
    """The next page of a resumed query must start where the checkpoint stopped, with the same columns and total."""
    if (statement.get("offset") != position["next_offset"]
            or columns_digest(statement.get("columns") or []) != position["columns_sha256"]
            or (position["total_rows"] is not None and statement.get("total_rows") != position["total_rows"])):
        raise CheckpointRefused("page_does_not_continue", "the page does not continue the admitted prefix")


def compat_position_from_native(binding: Mapping, *, task: str, sql_sha256: str, start_offset: int,
                                rows_delivered: int, pages: int, total_rows: "int | None",
                                columns_sha256: str, rows_sha256: str) -> dict:
    """A native snapshot cursor (mdd-session CursorBinding) mapped to the compatible offset that outlives its worker.
    The token itself is never kept; the binding contributes the source fingerprint the offset must still match."""
    if any(type(value) is not int or value < 0 for value in (start_offset, rows_delivered, pages)) \
            or start_offset + rows_delivered > MAX_OFFSET or not isinstance(binding, Mapping) \
            or not _SHA.fullmatch(str(binding.get("source_fingerprint", ""))) or binding.get("mode") != "native_snapshot":
        raise CheckpointRefused("position_inconsistent", "not a native cursor binding with a usable delivery count")
    if total_rows is not None and (type(total_rows) is not int or total_rows < start_offset + rows_delivered):
        raise CheckpointRefused("position_inconsistent", "the delivered rows exceed the total")
    return {"schema": POSITION_SCHEMA, "mode": PAGING_MODE, "task": task, "sql_sha256": sql_sha256,
            "start_offset": start_offset, "next_offset": start_offset + rows_delivered, "rows": rows_delivered,
            "pages": pages, "total_rows": total_rows, "page_limit_cap": None, "columns_sha256": columns_sha256,
            "rows_sha256": rows_sha256, "from_native": {"source_fingerprint": binding["source_fingerprint"],
                                                        "worker_generation": str(binding.get("worker_generation")),
                                                        "cursor": "dropped"}}


# ---- state: what a report says about itself --------------------------------------------------------------------------

def failure_codes(report: Mapping) -> "set[str]":
    """Engine codes (provider.classify_failure) of every recorded task failure and failed session."""
    records = []
    for entry in report.get("tasks") or []:
        if isinstance(entry.get("failure"), dict):
            records.append(entry["failure"])
        elif entry.get("status") == "error":
            records.append(entry)
    records.extend(session for session in report.get("sessions") or [] if isinstance(session, dict) and "error" in session)
    codes = set()
    for record in records:
        code = provider.classify_failure(record).code
        codes.add(_TYPE_CODES.get(str(record.get("error")), code) if code == "UNCLASSIFIED" else code)
    return codes


def derive_state(report: Mapping, request: Mapping, *, final: bool, hint: "str | None" = None) -> dict:
    """The termination of a report and what may be done with each task. Deterministic from its arguments, so an
    importer derives it again and compares: a state that does not follow from its report is not trusted."""
    if hint not in HINTS:
        raise CheckpointRefused("invalid_hint", "termination hint must be cancelled or worker_lost")
    codes = failure_codes(report)
    all_complete = bool(report.get("tasks")) and all(t.get("status") == "complete" for t in report["tasks"]) \
        and len(report["tasks"]) == len(request["tasks"]) \
        and {t.get("id") for t in report["tasks"]} == {t["id"] for t in request["tasks"]}
    if not final:
        termination = "in_flight"
    elif report.get("source_unchanged") is not True or "SOURCE_CHANGED" in codes:
        termination = "source_changed"
    elif hint == "cancelled" or "CANCELLED" in codes:
        termination = "cancelled"
    elif hint == "worker_lost" or "WORKER_LOST" in codes:
        termination = "worker_lost"
    elif report.get("complete") is True and all_complete \
            and not any(isinstance(s, dict) and "error" in s for s in report.get("sessions") or []):
        termination = "complete"
    else:
        termination = "partial"
    definitions = {t["id"]: t for t in request["tasks"]}
    tasks = []
    for entry in report.get("tasks") or []:
        definition = definitions.get(entry.get("id"), {})
        operation, status, result = definition.get("operation"), entry.get("status"), entry.get("result")
        position, problem, disposition = None, None, "rerun"
        if termination in RESUMABLE:
            if status == "complete":
                disposition = "reuse"
            elif status == "partial" and operation == "query" and isinstance(result, Mapping) and "typed_result" in result:
                try:
                    position = page_position(definition, result)
                except CheckpointRefused as refusal:
                    problem = refusal.reason
                if position is not None:
                    disposition = "continue"
        tasks.append({"id": entry.get("id"), "operation": operation, "backend": entry.get("backend"), "status": status,
                      "disposition": disposition, "position": position, "position_problem": problem,
                      "result_sha256": digest_of(result) if result is not None else None})
    return {"final": bool(final), "hint": hint, "termination": termination, "complete": report.get("complete") is True,
            "source_unchanged": report.get("source_unchanged"), "failure_codes": sorted(codes), "tasks": tasks}


# ---- sealing ---------------------------------------------------------------------------------------------------------

_BODY = ("schema", "identity", "origin", "resumed_from", "request", "state", "report")


def _origin(origin: Any) -> "dict | None":
    if origin is None:
        return None
    if (not isinstance(origin, Mapping) or not {"run_id", "attempt", "request_id"} <= set(origin)
            or set(origin) - {"run_id", "attempt", "request_id", "sample_index"}
            or any(type(origin[key]) is not int or origin[key] < 1 for key in ("run_id", "attempt"))
            or not isinstance(origin["request_id"], str) or not _REQUEST_ID.fullmatch(origin["request_id"])
            or ("sample_index" in origin and (type(origin["sample_index"]) is not int or not 0 <= origin["sample_index"] <= 11))):
        raise CheckpointRefused("origin_invalid", "origin needs run_id, attempt and request_id (and optional sample_index)")
    return dict(origin)


def seal(report: Mapping, *, identity: Mapping, request: Any, final: bool, termination_hint: "str | None" = None,
         origin: "Mapping | None" = None, resumed_from: "Mapping | None" = None, legacy: Any = None) -> dict:
    """Bind a report to the identity that made it. The seal is an integrity check, not an authentication."""
    validated, fingerprint, sealed = normalize_request(request, legacy)
    if fingerprint != identity["rule"]["request_sha256"]:
        raise CheckpointRefused("request_changed", "the report belongs to another request")
    plain = _plain(report)
    state = derive_state(plain, validated, final=final, hint=termination_hint)
    if identity.get("snapshot") is None and any(t["disposition"] in ("reuse", "continue") for t in state["tasks"]):
        raise CheckpointRefused("results_without_snapshot_binding",
                                "results exist but the snapshot they came from was never captured")
    body = {"schema": CHECKPOINT_SCHEMA, "identity": _plain(identity), "origin": _origin(origin),
            "resumed_from": _plain(resumed_from) if resumed_from is not None else None,
            "request": sealed, "state": state, "report": plain}
    return dict(body, seal={"algorithm": "sha256", "digest": digest_of(body)})


def verify_seal(document: Any, *, error: type = ResumeRefused) -> None:
    if not isinstance(document, Mapping) or not all(key in document for key in (*_BODY, "seal")):
        raise error("malformed_checkpoint", "the checkpoint is missing parts")
    seal_ = document["seal"]
    if not isinstance(seal_, Mapping) or seal_.get("algorithm") != "sha256" \
            or seal_.get("digest") != digest_of({key: document[key] for key in _BODY}):
        raise error("seal_mismatch", "the checkpoint does not match its seal")


def seal_digest(document: Mapping) -> str:
    return document["seal"]["digest"]


# ---- importing -------------------------------------------------------------------------------------------------------

def _engine_parts(engine: Mapping) -> dict:
    return {"engine": {k: v for k, v in engine.items() if k not in _NAMED}, "capability": engine.get("mcp_tools_sha256"),
            "profile": engine.get("profile"), "dialect": engine.get("dialect"), "config": engine.get("config_digest")}


def compare_identity(saved: Mapping, current: Mapping) -> None:
    """Raise ResumeRefused for the first component that differs. The snapshot is bound later (`Resume.bind_source`),
    once the engine has opened the source, because only then does it exist."""
    checks = [("schema_changed", "schema", (saved.get("schema"), saved.get("versions")), (current.get("schema"), current.get("versions")))]
    old, new = _engine_parts(saved.get("engine") or {}), _engine_parts(current.get("engine") or {})
    for reason, key in (("engine_changed", "engine"), ("capability_changed", "capability"), ("profile_changed", "profile"),
                        ("dialect_changed", "dialect"), ("config_changed", "config")):
        checks.append((reason, key, old[key], new[key]))
    checks.append(("generation_changed", "generation", saved.get("generation"), current.get("generation")))
    checks.append(("request_changed", "request_sha256", (saved.get("rule") or {}).get("request_sha256"),
                   (current.get("rule") or {}).get("request_sha256")))
    checks.append(("rule_changed", "catalog_sha256", (saved.get("rule") or {}).get("catalog_sha256"),
                   (current.get("rule") or {}).get("catalog_sha256")))
    checks.append(("source_changed", "sha256", (saved.get("source") or {}).get("sha256"), (current.get("source") or {}).get("sha256")))
    checks.append(("source_changed", "revision", (saved.get("source") or {}).get("revision"), (current.get("source") or {}).get("revision")))
    for reason, component, before, after in checks:
        if before != after:
            raise ResumeRefused(reason, f"the checkpoint was made under another {component}", component=component)


@dataclass
class Resume:
    """A verified checkpoint, not yet bound to the snapshot the engine will open. It never reports success unless the
    checkpoint itself was a complete, source-verified result."""

    document: dict
    expected: dict
    claim: "dict | None"
    source_bound: bool = False

    @property
    def termination(self) -> str:
        return self.document["state"]["termination"]

    @property
    def success(self) -> bool:
        return self.termination == "complete"

    @property
    def identity(self) -> dict:
        return self.document["identity"]

    @property
    def seal(self) -> str:
        return seal_digest(self.document)

    def lineage(self) -> dict:
        return {"seal": self.seal, "identity_sha256": digest_of(self.identity), "origin": self.document["origin"],
                "claim": self.claim}

    def tasks(self, disposition: str) -> "list[str]":
        return [t["id"] for t in self.document["state"]["tasks"] if t["disposition"] == disposition]

    def bind_source(self, snapshot: Mapping) -> None:
        """Called with the snapshot the engine really opened. A different one means different bytes or a different
        capture: nothing is continued."""
        saved = self.identity["snapshot"]
        if saved is not None and _plain(snapshot) != saved:
            raise ResumeRefused("snapshot_changed", "the engine opened another snapshot than the checkpoint was made from",
                                component="snapshot")
        self.source_bound = True

    def seed(self) -> dict:
        """`resume=` for analysis_batch.execute: complete tasks and consistent partial queries, nothing else. A partial
        locate/refs/decode task is left out on purpose: the executor cannot continue one (QueryPages refuses it) and
        would raise before running anything."""
        keep = {t["id"] for t in self.document["state"]["tasks"] if t["disposition"] in ("reuse", "continue")}
        if not keep:
            raise ResumeRefused("nothing_reusable", "no task of the checkpoint may be reused; run a new attempt instead")
        report = copy.deepcopy(self.document["report"])
        return {"plan": report.get("plan"), "sessions": [s for s in report.get("sessions") or [] if "files" in s],
                "tasks": [t for t in report.get("tasks") or [] if t.get("id") in keep],
                "resume_origin": self.lineage()}


def _load(document: Any) -> dict:
    if isinstance(document, (bytes, bytearray)) or isinstance(document, str):
        raise CheckpointRefused("malformed_checkpoint", "pass a parsed document or a path to read_back")
    return _plain(document)


def _schema_gate(document: Any, error: type = ResumeRefused) -> None:
    if not isinstance(document, Mapping):
        raise error("malformed_checkpoint", "the checkpoint is not an object")
    schema = document.get("schema")
    if type(schema) is int:
        raise error("legacy_checkpoint_not_upgraded",
                    "a HostLab schema-%d checkpoint belongs to the engine that wrote it; it is not upgraded" % schema)
    if schema != CHECKPOINT_SCHEMA:
        raise error("unknown_checkpoint_schema", "unknown checkpoint schema")


def _check_state(document: Mapping, legacy: Any) -> dict:
    """Re-derive the state and the request identity from the report and compare them with what the seal covers."""
    try:
        validated, fingerprint, sealed = normalize_request(document["request"], legacy)
    except ValueError:
        raise ResumeRefused("state_mismatch", "the sealed request is not a valid request") from None
    identity = document["identity"]
    if (sealed != document["request"] or not isinstance(identity, Mapping)
            or (identity.get("rule") or {}).get("request_sha256") != fingerprint):
        raise ResumeRefused("state_mismatch", "the request does not match the identity it is sealed with")
    state = document["state"]
    try:
        derived = derive_state(document["report"], validated, final=state.get("final"), hint=state.get("hint"))
    except CheckpointRefused:
        raise ResumeRefused("state_mismatch", "the state does not follow from the report") from None
    if not isinstance(state, Mapping) or state != derived:
        raise ResumeRefused("state_mismatch", "the state does not follow from the report")
    return state


def import_checkpoint(document: Any, expected: Mapping, *, claim: "Mapping | None" = None, legacy: Any = None) -> Resume:
    """Verify a sealed checkpoint against the identity the new run would have. The order of the refusals is fixed:
    form and schema, seal, state, how it ended, the snapshot its results are bound to, identity component by component,
    then the origin claim."""
    legacy = legacy or _legacy()
    doc = _load(document)
    if isinstance(doc, dict) and len(json.dumps(doc)) > MAX_DOCUMENT_BYTES:
        raise ResumeRefused("document_too_large", "the checkpoint exceeds its size budget")
    _schema_gate(doc)
    verify_seal(doc)
    state = _check_state(doc, legacy)
    if state["termination"] == "in_flight":
        raise ResumeRefused("checkpoint_not_sealed", "an in-flight checkpoint has no verified source; it is not resumed")
    if state["termination"] == "source_changed":
        raise ResumeRefused("source_changed", "the source changed while the checkpoint was made; nothing in it is reused",
                            component="source")
    if doc["identity"].get("snapshot") is None and any(t["disposition"] in ("reuse", "continue") for t in state["tasks"]):
        raise ResumeRefused("results_without_snapshot_binding",
                            "results exist but the snapshot they came from was never captured")
    compare_identity(doc["identity"], expected)
    claimed = None
    if claim is not None:
        claimed = _origin(claim)
        saved = doc["origin"]
        if saved is None or any(saved.get(key) != claimed.get(key) for key in ("run_id", "attempt", "request_id")) \
                or ("sample_index" in claimed and saved.get("sample_index") != claimed["sample_index"]):
            raise ResumeRefused("origin_mismatch", "the checkpoint was not made by the run, attempt and request claimed")
    return Resume(doc, _plain(expected), claimed)


# ---- capturing what Session.open throws away -------------------------------------------------------------------------

class OpenCapture:
    """Wrap the MCP client factory (`analysis_batch.Client`) so that every successful `open_dataset` of the engine is
    read: the snapshot is bound to the sample's SHA-256 and, when a resume is in progress, to the checkpoint, before
    HostLab sees the answer. A refusal propagates out of the call, so no page is read from or added to that dataset.
    Answers without a `snapshot_manifest` (the legacy sqlite backend) are not the engine's and are ignored. A call that
    fails because the channel to the engine ended (a broken pipe, a closed stream) is re-raised as `WorkerLost`, which
    HostLab records with the engine's code WORKER_LOST; any other exception, a deadline and a cancellation included,
    passes through as it is."""

    def __init__(self, *, sha256: "str | None" = None, resume: "Resume | None" = None):
        self.sha256, self.resume = sha256, resume
        self.opens: "list[dict]" = []

    def record(self, text: str) -> None:
        try:
            opened = json.loads(text)
        except ValueError:
            return
        if not isinstance(opened, Mapping) or "snapshot_manifest" not in opened:
            return
        snapshot = snapshot_identity(opened)
        if self.sha256 is not None:
            bind_to_sample(snapshot, self.sha256)
        if self.resume is not None:
            self.resume.bind_source(snapshot)
        self.opens.append({"snapshot": snapshot, "handles": handles(opened)})

    def snapshot(self) -> "dict | None":
        if not self.opens:
            return None
        if any(item["snapshot"] != self.opens[0]["snapshot"] for item in self.opens):
            raise CheckpointRefused("snapshots_disagree", "the engine opened different snapshots in one run")
        return copy.deepcopy(self.opens[0]["snapshot"])

    def wrap(self, factory: Callable[[Any], Any]) -> Callable[[Any], Any]:
        capture = self

        class Captured:
            def __init__(self, params: Any):
                self._inner = factory(params)

            async def __aenter__(self) -> "Captured":
                self._client = await self._inner.__aenter__()
                return self

            async def __aexit__(self, *exc: Any) -> Any:
                return await self._inner.__aexit__(*exc)

            async def call_tool(self, name: str, arguments: Any, *args: Any, **kwargs: Any) -> Any:
                try:
                    response = await self._client.call_tool(name, arguments, *args, **kwargs)
                except Exception as error:
                    if isinstance(error, _TRANSPORT_LOST) or type(error).__name__ in _TRANSPORT_LOST_NAMES:
                        raise WorkerLost(f"the engine's channel was lost during {name}: {type(error).__name__}") from error
                    raise
                if name == "open_dataset" and not getattr(response, "is_error", False):
                    capture.record("\n".join(getattr(item, "text", "") for item in response.content))
                return response

        return Captured


# ---- the executor's checkpoint callback ------------------------------------------------------------------------------

def checkpoint_root(ns: Mapping[str, Path]) -> Path:
    """Checkpoints live in the engine's own reports directory (provider.namespaces keeps it clear of HostLab's)."""
    return Path(ns["reports"]) / "checkpoints"


class CheckpointWriter:
    """`checkpoint=` for analysis_batch.execute. Progress replaces one in-flight file (never resumed); the final
    report is sealed into a file that is never overwritten. A worker that dies leaves only the in-flight file.

    The in-flight file is a diagnostic record, so writing it is best effort: HostLab's executor treats an exception from
    this callback as a failure of the task being run, and on Windows a file scanner holding the destination for a moment
    makes `os.replace` fail (observed: a partial query ended with PermissionError and the next task was skipped). It is
    tried again a few times, and a write that still fails is listed in `inflight_errors`, not raised. The final seal is
    what a resume stands on; its write is never best effort."""

    INFLIGHT = "checkpoint.inflight.json"
    INFLIGHT_TRIES = 5

    def __init__(self, root: Path, expected: Mapping, request: Any, *, origin: "Mapping | None" = None,
                 capture: "OpenCapture | None" = None, resume: "Resume | None" = None, legacy: Any = None):
        self.root, self.expected, self.request = Path(root), expected, request
        self.origin, self.capture, self.resume, self.legacy = _origin(origin), capture, resume, legacy
        self.hint: "str | None" = None
        self.document: "dict | None" = None
        self.path: "Path | None" = None
        self.inflight_errors: "list[str]" = []

    def note(self, hint: "str | None") -> None:
        """Say how the run ended when the report cannot (cancelled, or the worker was lost). Called before the final report."""
        if hint not in HINTS:
            raise CheckpointRefused("invalid_hint", "termination hint must be cancelled or worker_lost")
        self.hint = hint

    def _identity(self, report: Mapping, final: bool) -> dict:
        snapshot = self.capture.snapshot() if self.capture is not None else None
        opened = (report.get("execution") or {}).get("dataset_opens", 0)
        if final and opened and snapshot is None:
            raise CheckpointRefused("source_not_bound", "the engine was opened but its snapshot was never captured")
        if final and opened and self.resume is not None and not self.resume.source_bound:
            raise CheckpointRefused("source_not_bound", "a resumed run opened the engine without binding the checkpoint")
        if snapshot is None and self.resume is not None:
            snapshot = self.resume.identity["snapshot"]
        elif snapshot is not None and self.resume is not None and self.resume.identity["snapshot"] not in (None, snapshot):
            raise CheckpointRefused("snapshot_changed", "the resumed run captured another snapshot")
        return with_snapshot(self.expected, snapshot)

    def __call__(self, report: Mapping, final: bool) -> None:
        document = seal(report, identity=self._identity(report, bool(final)), request=self.request, final=bool(final),
                        termination_hint=self.hint, origin=self.origin,
                        resumed_from=self.resume.lineage() if self.resume is not None else None, legacy=self.legacy)
        self.document = document
        self.root.mkdir(parents=True, exist_ok=True)
        if final:
            label = "{run_id}-{attempt}".format(**self.origin) if self.origin else seal_digest(document)[:16]
            self.path = provider.publish(self.root, f"checkpoint-{label}.json", document)
            return
        self._write_inflight(document)

    def _write_inflight(self, document: Mapping) -> None:
        staged = self.root / f".{self.INFLIGHT}.{os.getpid()}.part"
        error: "OSError | None" = None
        for attempt in range(self.INFLIGHT_TRIES):
            try:
                staged.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                os.replace(staged, self.root / self.INFLIGHT)
                return
            except OSError as caught:
                error = caught
                time.sleep(0.01 * 2 ** attempt)
        staged.unlink(missing_ok=True)
        self.inflight_errors.append(type(error).__name__)


# ---- the completion cache -----------------------------------------------------------------------------------------------

class CompletionCache:
    """Complete results of structured requests, in the engine's own completion directory. A source that changed, a
    lost worker, a cancellation, a partial or in-flight result, a report with a failed session, and arbitrary SQL
    (which HostLab never completion-caches either) are refused. An entry is never overwritten."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.rejected: "list[dict]" = []

    def key(self, identity: Mapping) -> str:
        """By everything known before the engine opens the source: HostLab looks up a completed request that way."""
        return digest_of(dict(identity, snapshot=None))

    def _marker(self, document: Mapping) -> None:
        try:
            marker = json.loads((self.root / "NAMESPACE.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise CompletionRefused("generation_changed", "the completion directory is not claimed by an engine") from None
        if marker.get("engine_dir") != document["identity"]["generation"]["namespace"]:
            raise CompletionRefused("generation_changed", "the completion directory belongs to another engine build",
                                    component="generation")

    def store(self, document: Any, *, legacy: Any = None) -> Path:
        doc = _load(document)
        _schema_gate(doc, CompletionRefused)
        verify_seal(doc, error=CompletionRefused)
        try:
            state = _check_state(doc, legacy or _legacy())
        except ResumeRefused as refusal:
            raise CompletionRefused(refusal.reason, str(refusal)) from None
        if state["termination"] != "complete":
            raise CompletionRefused(state["termination"], f"a {state['termination']} result is never cached")
        if any(task["operation"] == "query" for task in state["tasks"]):
            raise CompletionRefused("arbitrary_sql_not_cached", "arbitrary SQL is not completion-cached")
        snapshot = doc["identity"]["snapshot"]
        if snapshot is None:
            raise CompletionRefused("snapshot_not_bound", "the result was never bound to a captured snapshot")
        if len(snapshot["inputs"]) != 1 or snapshot["inputs"][0]["content_id"] != "sha256:" + doc["identity"]["source"]["sha256"]:
            raise CompletionRefused("source_binding_mismatch", "the captured bytes are not the sample's bytes")
        self._marker(doc)
        return provider.publish(self.root, self.key(doc["identity"]) + ".json", doc)

    def lookup(self, expected: Mapping, *, legacy: Any = None) -> "dict | None":
        path = self.root / (self.key(expected) + ".json")
        if not path.is_file():
            return None
        try:
            if path.stat().st_size > MAX_DOCUMENT_BYTES:
                raise ResumeRefused("document_too_large", "oversized cache entry")
            doc = json.loads(path.read_text(encoding="utf-8"))
            _schema_gate(doc)
            verify_seal(doc)
            _check_state(doc, legacy or _legacy())
            if doc["state"]["termination"] != "complete":
                raise ResumeRefused("partial", "not a complete entry")
            compare_identity(doc["identity"], expected)
            snapshot = doc["identity"]["snapshot"]
            if snapshot is None or snapshot["inputs"][0]["content_id"] != "sha256:" + expected["source"]["sha256"]:
                raise ResumeRefused("snapshot_changed", "the entry is not bound to this source")
        except (ResumeRefused, ValueError, OSError, KeyError, IndexError, TypeError) as error:
            self.rejected.append({"entry": path.name, "reason": getattr(error, "reason", type(error).__name__)})
            return None  # kept where it is, reported, and never served or replaced
        return doc


# ---- rollback: replay and read-back ------------------------------------------------------------------------------------

CONCRETE_BACKENDS = ("sqlite", "dexsql", provider.ENGINE)


@dataclass(frozen=True)
class ReplayDecision:
    action: str  # "replay" | "same_engine" | "refuse"
    reason: str

    def to_dict(self) -> dict:
        return {"action": self.action, "reason": self.reason}


def accepted_work(report: Mapping) -> dict:
    """What a report already holds that another engine would have to repeat or contradict: the pages of each query,
    the rows of every result, and the single answer of each non-query task that finished or stopped part way."""
    pages = rows = 0
    for entry in report.get("tasks") or []:
        result = entry.get("result")
        if not isinstance(result, Mapping):
            continue
        rows += len(result.get("rows") or [])
        pagination = result.get("pagination")
        if isinstance(pagination, Mapping):
            pages += pagination.get("pages") or 0
        elif entry.get("status") in ("complete", "partial"):
            pages += 1
    return {"pages_accepted": pages, "rows_accepted": rows}


_SQL_MUTATING = re.compile(
    r"\b(insert|update|delete|replace|create|drop|alter|attach|detach|pragma|vacuum|reindex|analyze|"
    r"begin|commit|rollback|savepoint|release|grant|revoke|truncate|merge|call|exec|execute|set|into)\b", re.I)


def _mask_sql(sql: str) -> "str | None":
    """Replace string literals, quoted identifiers and comments with spaces, so a keyword inside them is not read as
    SQL. None when a literal or block comment is left open: such text cannot be proven to be one pure query."""
    out = []
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch in "'\"`":
            i += 1
            closed = False
            while i < n:
                if sql[i] == ch:
                    if i + 1 < n and sql[i + 1] == ch:
                        i += 2
                        continue
                    i += 1
                    closed = True
                    break
                i += 1
            if not closed:
                return None
            out.append(" ")
        elif ch == "[":
            end = sql.find("]", i + 1)
            if end < 0:
                return None
            i = end + 1
            out.append(" ")
        elif sql.startswith("--", i):
            end = sql.find("\n", i)
            i = n if end < 0 else end
            out.append(" ")
        elif sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            if end < 0:
                return None
            i = end + 2
            out.append(" ")
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _is_pure_query(sql: str) -> bool:
    """Whether `sql` is provably a single SELECT or WITH-SELECT with no data or catalog change. Conservative: anything
    not proven pure (several statements, a modifying keyword, an open literal) is not pure, so it counts as a side effect."""
    masked = _mask_sql(sql)
    if masked is None:
        return False
    statements = [s for s in masked.split(";") if s.strip()]
    if len(statements) != 1:
        return False
    statement = statements[0]
    if not re.match(r"(?is)^\s*(select|with)\b", statement):
        return False
    return _SQL_MUTATING.search(statement) is None


def is_temp_side_effect(arguments: Mapping) -> bool:
    """Whether an engine `query` call changes the session's TEMP catalog. HostLab v1 sends one pure SELECT/WITH per call,
    which stays False; a call that is not provably a single pure SELECT/WITH-SELECT counts as a side effect, so a WITH
    that ends in INSERT or a second statement after a semicolon can never be replayed across engines unnoticed."""
    if arguments.get("named_temp_queries"):
        return True
    statements = arguments.get("sql")
    statements = [statements] if isinstance(statements, str) else statements
    return any(not isinstance(sql, str) or not _is_pure_query(sql) for sql in statements or [])


def replay_decision(job: Mapping, target_backend: str, *, explicit: bool) -> ReplayDecision:
    """May this job be run again on `target_backend`? A new job names its backend. Once a page was accepted or a TEMP
    object created, the work cannot be repeated on another engine without mixing two engines' answers."""
    if (not isinstance(job, Mapping) or job.get("backend") not in CONCRETE_BACKENDS
            or any(type(job.get(key)) is not int or job[key] < 0 for key in ("pages_accepted", "rows_accepted", "temp_side_effects"))):
        raise ReplayRefused("invalid_job", "the job record is not usable")
    if target_backend not in CONCRETE_BACKENDS or explicit is not True:
        return ReplayDecision("refuse", "backend_not_explicit")
    if target_backend == job["backend"]:
        return ReplayDecision("same_engine", "not_a_cross_engine_replay")
    if job["pages_accepted"] or job["rows_accepted"]:
        return ReplayDecision("refuse", "pages_already_accepted")
    if job["temp_side_effects"]:
        return ReplayDecision("refuse", "temp_side_effects")
    return ReplayDecision("replay", "nothing_accepted_and_no_side_effects")


def require_replay(job: Mapping, target_backend: str, *, explicit: bool) -> ReplayDecision:
    decision = replay_decision(job, target_backend, explicit=explicit)
    if decision.action == "refuse":
        raise ReplayRefused(decision.reason, f"job cannot be replayed on {target_backend}: {decision.reason}")
    return decision


@dataclass(frozen=True)
class ReadBack:
    kind: str  # "mdd_checkpoint" | "hostlab_legacy"
    identity: dict
    termination: "str | None"
    resumable_here: bool
    reason: "str | None"
    report: dict
    document_sha256: str


def read_back(source: Any, expected: "Mapping | None" = None, *, legacy: Any = None) -> ReadBack:
    """Read a checkpoint under the identity it was made with, whichever engine is configured now. Reading writes
    nothing and converts nothing; `resumable_here` only says what an import under `expected` would do."""
    raw = None
    if isinstance(source, (str, os.PathLike)):
        path = Path(source)
        if path.stat().st_size > MAX_DOCUMENT_BYTES:
            raise ResumeRefused("document_too_large", "the checkpoint exceeds its size budget")
        raw = path.read_bytes()
        try:
            document = json.loads(raw.decode("utf-8"))
        except ValueError:
            raise ResumeRefused("malformed_checkpoint", "the checkpoint is not JSON") from None
        fingerprint = hashlib.sha256(raw).hexdigest()
    else:
        document = _plain(source)
        fingerprint = digest_of(document)
    if not isinstance(document, Mapping):
        raise ResumeRefused("malformed_checkpoint", "the checkpoint is not an object")
    if type(document.get("schema")) is int:  # HostLab's own file: the original engine's identity, as recorded
        report = _plain(document)
        backends = sorted({t.get("backend") for t in (report.get("plan") or {}).get("tasks", []) if t.get("backend")})
        identity = {"schema": document["schema"], "backends": backends, "backend_versions": report.get("backend_versions")}
        return ReadBack("hostlab_legacy", identity, None, False, "legacy_checkpoint_not_upgraded", report, fingerprint)
    _schema_gate(document)
    verify_seal(document)
    doc = _plain(document)
    termination, reason, ok = doc["state"].get("termination"), None, False
    if expected is not None:
        try:
            if termination not in RESUMABLE:
                raise ResumeRefused("checkpoint_not_sealed" if termination == "in_flight" else "source_changed", "not resumable")
            compare_identity(doc["identity"], expected)
            ok = True
        except ResumeRefused as refusal:
            reason = refusal.reason
    return ReadBack("mdd_checkpoint", doc["identity"], termination, ok, reason, doc["report"], fingerprint)
