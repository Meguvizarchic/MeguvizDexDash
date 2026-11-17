"""Mutation check for MDD-053: change one behaviour of the checkpoint adapter or the remote runner adapter at a time and
require the tests to notice.

    python -I artifacts/mdd-053/mutation/mutate_checkpoint_remote.py             # all mutants, 6 at a time
    python -I artifacts/mdd-053/mutation/mutate_checkpoint_remote.py --dry-run   # only check that every pattern matches once
    python -I artifacts/mdd-053/mutation/mutate_checkpoint_remote.py --only gh_effect --jobs 2

Each mutant replaces one exact piece of integrations/hostlab/checkpoint_adapter.py or remote_runner_adapter.py in a private
copy of what the tests need (integrations/hostlab, the frozen HostLab sources, the tool inventory, two fixture APKs), runs
test_checkpoint_adapter.py and test_remote_runner_adapter.py (stand-in engine, frozen HostLab code, no network) until the
first failure, and puts the original back. The working tree is never edited, so an interrupted run leaves nothing behind. A
mutant that leaves the tests green is a survivor and exits 1; one that hangs the tests is counted as killed. A pattern that no
longer matches exactly once is also a failure, so the list cannot rot silently. The real-engine tests (test_checkpoint_live_engine.py) and the record tests (test_remote_records.py,
whose inputs are hashed on purpose) are not part of it. The run ends with a `sources sha256:` line binding the verdicts to the
exact source and fixture bytes (SOURCES + FIXTURES, hashed by relative path then content)."""
import argparse
import concurrent.futures
import hashlib
import queue
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
HOSTLAB = REPO / "integrations" / "hostlab"
CP, RR = "checkpoint_adapter.py", "remote_runner_adapter.py"

# The sources and fixtures the verdicts are bound to: the two mutated adapters, the tests that run against them, their
# stand-in supports and provider, the tool inventory, and the whole frozen HostLab corpus the tests load (hash-checked).
SOURCES = [
    "integrations/hostlab/checkpoint_adapter.py", "integrations/hostlab/remote_runner_adapter.py",
    "integrations/hostlab/provider.py", "integrations/hostlab/hostlab_test_support.py",
    "integrations/hostlab/checkpoint_test_support.py", "integrations/hostlab/remote_test_support.py",
    "integrations/hostlab/test_checkpoint_adapter.py", "integrations/hostlab/test_remote_runner_adapter.py",
    "conformance/manifests/tools-and-options.json",
    "conformance/corpus/hostlab/source-8782f43/manifest.json",
    "conformance/corpus/hostlab/source-8782f43/analysis_batch.py",
    "conformance/corpus/hostlab/source-8782f43/analysis_paging.py",
    "conformance/corpus/hostlab/source-8782f43/analysis_plan.py",
    "conformance/corpus/hostlab/source-8782f43/install_dexsql.py",
    "conformance/corpus/hostlab/source-8782f43/remote_mcp.py",
    "conformance/corpus/hostlab/source-8782f43/native_cli.py",
    "conformance/corpus/hostlab/source-8782f43/native_surface.py",
    "conformance/corpus/hostlab/source-8782f43/native_audit.py",
    "conformance/corpus/hostlab/source-8782f43/native_graph.py",
    "conformance/corpus/hostlab/source-8782f43/native_rules.py",
    "conformance/corpus/hostlab/source-8782f43/native_session.py",
    "conformance/corpus/hostlab/source-8782f43/dexq_cli.py",
    "conformance/corpus/hostlab/source-8782f43/dexq/server.py",
]
FIXTURES = [
    "tests/fixtures/generated/multidex-deflated.apk", "tests/fixtures/generated/multidex-stored.apk",
]


def hash_files(relatives) -> bytes:
    digest = hashlib.sha256()
    for relative in relatives:
        digest.update(relative.encode())
        digest.update((REPO / relative).read_bytes())
    return digest.digest()


def sources_sha256() -> str:
    digest = hashlib.sha256()
    digest.update(hash_files(SOURCES))
    digest.update(hash_files(FIXTURES))
    return digest.hexdigest()


def swap(file, label, old, new):
    return (file, label, old, new)


MUTANTS = [
    # ---- the request and the identity
    swap(CP, "a resumed request does not keep the identity of the original", 'sealed = {key: value for key, value in request.items() if key != "resume"}', 'sealed = dict(request)'),
    swap(CP, "a request for the engine shares an identity with the same request for dexsql", 'return legacy.validate(shaped), provider.request_fingerprint(sealed, legacy), _plain(sealed)', 'return legacy.validate(shaped), legacy.fingerprint(shaped), _plain(sealed)'),
    swap(CP, "a plan made under another configuration is accepted", 'if engine["config_digest"] != config.digest():', 'if False:'),
    swap(CP, "the source SHA-256 is not checked", 'if not isinstance(sha256, str) or not _SHA.fullmatch(sha256):', 'if False:'),
    swap(CP, "the sample revision is not checked", 'if revision is not None and (not isinstance(revision, str) or not revision or len(revision) > 256):', 'if False:'),
    swap(CP, "the rule catalog digest is not checked", 'if rule_catalog_sha256 is not None and not (isinstance(rule_catalog_sha256, str) and _SHA.fullmatch(rule_catalog_sha256)):', 'if False:'),
    swap(CP, "the catalog epoch is not checked", 'if catalog_epoch is not None and (type(catalog_epoch) is not int or catalog_epoch < 0):', 'if False:'),
    swap(CP, "the directory generation is a constant", '"generation": {"namespace": provider.engine_dir(engine), "catalog_epoch": catalog_epoch},', '"generation": {"namespace": "fixed", "catalog_epoch": catalog_epoch},'),
    swap(CP, "an incomplete engine identity is accepted", 'if any(key not in engine for key in _ENGINE_REQUIRED):', 'if False:'),
    swap(CP, "a plan that does not use the engine gets an identity", 'if engine is None:\n        raise CheckpointRefused("plan_does_not_use_engine"', 'if False:\n        raise CheckpointRefused("plan_does_not_use_engine"'),
    # ---- the snapshot
    swap(CP, "snapshot inputs need not be numbered in order", 'if [item["ordinal"] for item in inputs] != list(range(len(inputs))):', 'if False:'),
    swap(CP, "the snapshot content key is not checked", 'if not isinstance(key, str) or not _CONTENT.fullmatch(key) or not isinstance(sources, list) or not sources:', 'if not isinstance(key, str) or not isinstance(sources, list) or not sources:'),
    swap(CP, "a non-ASCII digit is a byte length", 'if not (text.isascii() and text.isdigit()):', 'if not text.isdigit():'),
    swap(CP, "a source need not have a content id", 'or not _CONTENT.fullmatch(source["content_id"]) or not isinstance(source.get("input_kind"), str):', 'or not isinstance(source.get("input_kind"), str):'),
    swap(CP, "the captured bytes need not be the bytes HostLab hashed", 'if len(inputs) != 1 or inputs[0]["content_id"] != "sha256:" + sha256:', 'if False:'),
    swap(CP, "the session handles are part of the snapshot identity", 'return {"content_key": key, "inputs": inputs}', 'return {"content_key": key, "inputs": inputs, "dataset_id": manifest.get("snapshot_id")}'),
    # ---- the page position
    swap(CP, "a position need not end where its rows end", 'or cursor != start + len(rows) or pagination.get("next_offset") != cursor', 'or pagination.get("next_offset") != cursor'),
    swap(CP, "pagination may disagree with the statement", 'or cursor != start + len(rows) or pagination.get("next_offset") != cursor', 'or cursor != start + len(rows)'),
    swap(CP, "the flat rows may disagree with the typed rows", 'or len(result.get("rows") or []) != len(rows)', ''),
    swap(CP, "the SQL of the position is not checked", 'or pagination.get("sql_sha256") != hashlib.sha256(task.get("sql", "").encode("utf-8")).hexdigest()', ''),
    swap(CP, "the start offset is not checked", 'or type(start) is not int or statement.get("offset") != start or not 0 <= cursor <= MAX_OFFSET', 'or type(start) is not int or not 0 <= cursor <= MAX_OFFSET'),
    swap(CP, "a complete result gets a position", 'cursor = statement.get("next_offset")\n    if cursor is None:\n        return None', 'cursor = statement.get("next_offset")\n    if False:\n        return None'),
    swap(CP, "a native cursor token is accepted in a position", 'if position.get("mode") != PAGING_MODE or any(key in position for key in ("cursor", "next_cursor", "cursor_token")):', 'if position.get("mode") != PAGING_MODE:'),
    swap(CP, "a position is not compared with the rows", 'if position != page_position(task, result):', 'if False:'),
    swap(CP, "the next page need not start at the cursor", 'if (statement.get("offset") != position["next_offset"]\n            or columns_digest', 'if (False\n            or columns_digest'),
    swap(CP, "the next page may change its columns", 'or columns_digest(statement.get("columns") or []) != position["columns_sha256"]', ''),
    swap(CP, "the next page may change the total", 'or (position["total_rows"] is not None and statement.get("total_rows") != position["total_rows"])', ''),
    swap(CP, "any binding maps to a compatible offset", 'or binding.get("mode") != "native_snapshot":', ':'),
    swap(CP, "the delivered rows may exceed the total", 'if total_rows is not None and (type(total_rows) is not int or total_rows < start_offset + rows_delivered):', 'if False:'),
    # ---- the state of a report
    swap(CP, "a worker lost by type name is not found", '_TYPE_CODES.get(str(record.get("error")), code) if code == "UNCLASSIFIED" else code', 'code'),
    swap(CP, "an unverified source counts as unchanged", 'elif report.get("source_unchanged") is not True or "SOURCE_CHANGED" in codes:', 'elif report.get("source_unchanged") is False or "SOURCE_CHANGED" in codes:'),
    swap(CP, "an engine SOURCE_CHANGED does not end the run as source_changed", 'elif report.get("source_unchanged") is not True or "SOURCE_CHANGED" in codes:', 'elif report.get("source_unchanged") is not True:'),
    swap(CP, "a cancellation code is ignored", 'elif hint == "cancelled" or "CANCELLED" in codes:', 'elif hint == "cancelled":'),
    swap(CP, "the cancelled hint is ignored", 'elif hint == "cancelled" or "CANCELLED" in codes:', 'elif "CANCELLED" in codes:'),
    swap(CP, "a worker-lost code is ignored", 'elif hint == "worker_lost" or "WORKER_LOST" in codes:', 'elif hint == "worker_lost":'),
    swap(CP, "the worker-lost hint is ignored", 'elif hint == "worker_lost" or "WORKER_LOST" in codes:', 'elif "WORKER_LOST" in codes:'),
    swap(CP, "complete does not need the report to say complete", 'elif report.get("complete") is True and all_complete \\', 'elif all_complete \\'),
    swap(CP, "complete does not need every task complete", 'elif report.get("complete") is True and all_complete \\', 'elif report.get("complete") is True \\'),
    swap(CP, "a failed session does not stop a result being complete", 'and not any(isinstance(s, dict) and "error" in s for s in report.get("sessions") or []):', ':'),
    swap(CP, "fewer tasks than requested are complete", 'and len(report["tasks"]) == len(request["tasks"])', ''),
    swap(CP, "a progress report is not in flight", 'if not final:\n        termination = "in_flight"', 'if False:\n        termination = "in_flight"'),
    swap(CP, "nothing is excluded from reuse by how the run ended", 'if termination in RESUMABLE:', 'if True:'),
    swap(CP, "a partial non-query task is continued", 'elif status == "partial" and operation == "query" and isinstance(result, Mapping) and "typed_result" in result:', 'elif status == "partial" and isinstance(result, Mapping) and "typed_result" in result:'),
    swap(CP, "a complete task is not reused", 'if status == "complete":\n                disposition = "reuse"', 'if False:\n                disposition = "reuse"'),
    swap(CP, "a hint outside cancelled and worker_lost is accepted", 'if hint not in HINTS:\n        raise CheckpointRefused("invalid_hint", "termination hint must be cancelled or worker_lost")\n    codes', 'if False:\n        raise CheckpointRefused("invalid_hint", "termination hint must be cancelled or worker_lost")\n    codes'),
    # ---- sealing
    swap(CP, "a report is sealed for another request", 'if fingerprint != identity["rule"]["request_sha256"]:\n        raise CheckpointRefused("request_changed", "the report belongs to another request")', 'if False:\n        raise CheckpointRefused("request_changed", "the report belongs to another request")'),
    swap(CP, "results are sealed without a snapshot", 'if identity.get("snapshot") is None and any(t["disposition"] in ("reuse", "continue") for t in state["tasks"]):', 'if False:'),
    swap(CP, "the seal digest is not checked", 'or seal_.get("digest") != digest_of({key: document[key] for key in _BODY}):', ':'),
    swap(CP, "the seal algorithm is not checked", 'seal_.get("algorithm") != "sha256"', 'False'),
    swap(CP, "an origin need not have a run id and attempt", 'or any(type(origin[key]) is not int or origin[key] < 1 for key in ("run_id", "attempt"))', ''),
    swap(CP, "an origin need not have a request id", 'or not isinstance(origin["request_id"], str) or not _REQUEST_ID.fullmatch(origin["request_id"])', ''),
    # ---- importing
    swap(CP, "a schema-2 checkpoint is upgraded", 'if type(schema) is int:', 'if False:'),
    swap(CP, "an unknown schema is accepted", 'if schema != CHECKPOINT_SCHEMA:', 'if False:'),
    swap(CP, "a request that does not match its identity is trusted", 'if (sealed != document["request"] or not isinstance(identity, Mapping)', 'if (False or not isinstance(identity, Mapping)'),
    swap(CP, "the sealed request fingerprint is not compared", 'or (identity.get("rule") or {}).get("request_sha256") != fingerprint):', '):'),
    swap(CP, "a state that does not follow from the report is trusted", 'if not isinstance(state, Mapping) or state != derived:', 'if not isinstance(state, Mapping):'),
    swap(CP, "an in-flight checkpoint is resumed", 'if state["termination"] == "in_flight":', 'if False:'),
    swap(CP, "a checkpoint of a changed source is resumed", 'if state["termination"] == "source_changed":', 'if False:'),
    swap(CP, "the origin claim is not compared", 'any(saved.get(key) != claimed.get(key) for key in ("run_id", "attempt", "request_id"))', 'False'),
    swap(CP, "a missing origin satisfies a claim", 'if saved is None or any(', 'if any('),
    swap(CP, "the sample index of the claim is not compared", 'or ("sample_index" in claimed and saved.get("sample_index") != claimed["sample_index"]):', ':'),
    swap(CP, "an oversized document is read", 'if isinstance(doc, dict) and len(json.dumps(doc)) > MAX_DOCUMENT_BYTES:', 'if False:'),
    swap(CP, "another snapshot may be bound", 'if saved is not None and _plain(snapshot) != saved:', 'if False:'),
    swap(CP, "a refused snapshot still binds the checkpoint", 'saved = self.identity["snapshot"]\n        if saved is not None and _plain(snapshot) != saved:', 'saved = self.identity["snapshot"]\n        self.source_bound = True\n        if saved is not None and _plain(snapshot) != saved:'),
    swap(CP, "a resume with nothing reusable is a resume", 'if not keep:', 'if False:'),
    swap(CP, "everything is seeded", 'if t["disposition"] in ("reuse", "continue")}\n        if not keep:', 'if True}\n        if not keep:'),
    swap(CP, "every resume is a success", 'return self.termination == "complete"', 'return True'),
    swap(CP, "the seed carries no lineage", '"resume_origin": self.lineage()}', '"resume_origin": {}}'),
    # ---- the identity components
    swap(CP, "the schema version is not compared", 'checks = [("schema_changed", "schema", (saved.get("schema"), saved.get("versions")), (current.get("schema"), current.get("versions")))]', 'checks = []'),
    swap(CP, "the engine build is not compared", '(("engine_changed", "engine"), ("capability_changed", "capability")', '((("engine_changed", "engine") if False else ("capability_changed", "capability")), ("capability_changed", "capability")'),
    swap(CP, "the capability digest is not compared", '("capability_changed", "capability"), ', ''),
    swap(CP, "the profile is not compared", '("profile_changed", "profile"),\n', '\n'),
    swap(CP, "the dialect is not compared", '("dialect_changed", "dialect"), ', ''),
    swap(CP, "the configuration is not compared", ', ("config_changed", "config")):', '):'),
    swap(CP, "the directory generation is not compared", 'checks.append(("generation_changed", "generation", saved.get("generation"), current.get("generation")))', 'pass'),
    swap(CP, "the request is not compared", 'checks.append(("request_changed", "request_sha256", (saved.get("rule") or {}).get("request_sha256"),\n                   (current.get("rule") or {}).get("request_sha256")))', 'pass'),
    swap(CP, "the rule catalog is not compared", 'checks.append(("rule_changed", "catalog_sha256", (saved.get("rule") or {}).get("catalog_sha256"),\n                   (current.get("rule") or {}).get("catalog_sha256")))', 'pass'),
    swap(CP, "the source SHA-256 is not compared", 'checks.append(("source_changed", "sha256", (saved.get("source") or {}).get("sha256"), (current.get("source") or {}).get("sha256")))', 'pass'),
    swap(CP, "the sample revision is not compared", 'checks.append(("source_changed", "revision", (saved.get("source") or {}).get("revision"), (current.get("source") or {}).get("revision")))', 'pass'),
    swap(CP, "profile, dialect and configuration are folded into the engine", '_NAMED = ("mcp_tools_sha256", "profile", "dialect", "config_digest")', '_NAMED = ()'),
    # ---- the capture and the writer
    swap(CP, "the sample hash is not checked when the engine opens", 'if self.sha256 is not None:\n            bind_to_sample(snapshot, self.sha256)', 'if False:\n            bind_to_sample(snapshot, self.sha256)'),
    swap(CP, "the checkpoint is not checked when the engine opens", 'if self.resume is not None:\n            self.resume.bind_source(snapshot)', 'if False:\n            self.resume.bind_source(snapshot)'),
    swap(CP, "an answer without a manifest is read as the engine's", 'if not isinstance(opened, Mapping) or "snapshot_manifest" not in opened:', 'if not isinstance(opened, Mapping):'),
    swap(CP, "different snapshots in one run are accepted", 'if any(item["snapshot"] != self.opens[0]["snapshot"] for item in self.opens):', 'if False:'),
    swap(CP, "every exception becomes a lost worker", 'if isinstance(error, _TRANSPORT_LOST) or type(error).__name__ in _TRANSPORT_LOST_NAMES:', 'if True:'),
    swap(CP, "a lost channel is not a lost worker", 'if isinstance(error, _TRANSPORT_LOST) or type(error).__name__ in _TRANSPORT_LOST_NAMES:', 'if False:'),
    swap(CP, "a stream error by name is not a lost worker", 'or type(error).__name__ in _TRANSPORT_LOST_NAMES:', ':'),
    swap(CP, "an error answer to open_dataset is read", 'if name == "open_dataset" and not getattr(response, "is_error", False):', 'if name == "open_dataset":'),
    swap(CP, "the lost worker carries no engine code", 'self.detail = {"error": {"kind": "worker_lost", "code": self.code, "message": message}}', 'self.detail = {}'),
    swap(CP, "a refusal carries no engine code", 'self.detail = {"error": {"kind": "checkpoint_refused", "code": self.code, "reason": reason}, **detail}', 'self.detail = dict(detail)'),
    swap(CP, "a run that opened the engine need not have captured it", 'if final and opened and snapshot is None:', 'if False:'),
    swap(CP, "a resumed run need not have bound the checkpoint", 'if final and opened and self.resume is not None and not self.resume.source_bound:', 'if False:'),
    swap(CP, "a resumed run may capture another snapshot", 'elif snapshot is not None and self.resume is not None and self.resume.identity["snapshot"] not in (None, snapshot):', 'elif False:'),
    swap(CP, "the final checkpoint may be overwritten", 'self.path = provider.publish(self.root, f"checkpoint-{label}.json", document)', 'self.path = self.root / f"checkpoint-{label}.json"\n            self.path.write_text(json.dumps(document), encoding="utf-8")'),
    swap(CP, "a progress file that cannot be written stops the analysis", 'self.inflight_errors.append(type(error).__name__)', 'raise error'),
    swap(CP, "a progress file is not tried again", 'for attempt in range(self.INFLIGHT_TRIES):', 'for attempt in range(1):'),
    swap(CP, "a failed progress write leaves its staged file", 'staged.unlink(missing_ok=True)\n        self.inflight_errors', 'self.inflight_errors'),
    swap(CP, "a progress write failure is not listed", 'self.inflight_errors.append(type(error).__name__)', 'pass'),
    swap(CP, "a progress write does not wait before the next try", 'time.sleep(0.01 * 2 ** attempt)', 'pass'),
    swap(CP, "the writer accepts any hint", 'if hint not in HINTS:\n            raise CheckpointRefused("invalid_hint", "termination hint must be cancelled or worker_lost")\n        self.hint = hint', 'self.hint = hint'),
    swap(CP, "the writer forgets how the run ended", 'termination_hint=self.hint, origin=self.origin,', 'termination_hint=None, origin=self.origin,'),
    swap(CP, "a resumed checkpoint does not name its parent", 'resumed_from=self.resume.lineage() if self.resume is not None else None, legacy=self.legacy)', 'resumed_from=None, legacy=self.legacy)'),
    swap(CP, "checkpoints live beside HostLab's reports", 'return Path(ns["reports"]) / "checkpoints"', 'return Path(ns["root"]).parent / "reports" / "checkpoints"'),
    # ---- the completion cache
    swap(CP, "a result that did not complete is cached", 'if state["termination"] != "complete":\n            raise CompletionRefused(', 'if False:\n            raise CompletionRefused('),
    swap(CP, "arbitrary SQL is cached", 'if any(task["operation"] == "query" for task in state["tasks"]):', 'if False:'),
    swap(CP, "a result without a snapshot is cached", 'if snapshot is None:\n            raise CompletionRefused("snapshot_not_bound"', 'if False:\n            raise CompletionRefused("snapshot_not_bound"'),
    swap(CP, "bytes other than the sample\'s are cached", 'if len(snapshot["inputs"]) != 1 or snapshot["inputs"][0]["content_id"] != "sha256:" + doc["identity"]["source"]["sha256"]:', 'if False:'),
    swap(CP, "the completion directory of another build is written", 'self._marker(doc)', 'pass'),
    swap(CP, "the directory marker is not compared", 'if marker.get("engine_dir") != document["identity"]["generation"]["namespace"]:', 'if False:'),
    swap(CP, "an entry may be overwritten", 'return provider.publish(self.root, self.key(doc["identity"]) + ".json", doc)', 'path = self.root / (self.key(doc["identity"]) + ".json")\n        path.write_text(json.dumps(doc), encoding="utf-8")\n        return path'),
    swap(CP, "the cache key includes the snapshot", 'return digest_of(dict(identity, snapshot=None))', 'return digest_of(identity)'),
    swap(CP, "an entry of another identity is served", '            compare_identity(doc["identity"], expected)\n            snapshot = doc["identity"]["snapshot"]\n            if snapshot is None', '            snapshot = doc["identity"]["snapshot"]\n            if snapshot is None'),
    swap(CP, "a partial entry is served", 'if doc["state"]["termination"] != "complete":\n                raise ResumeRefused("partial", "not a complete entry")', 'if False:\n                raise ResumeRefused("partial", "not a complete entry")'),
    swap(CP, "an entry for other bytes is served", 'if snapshot is None or snapshot["inputs"][0]["content_id"] != "sha256:" + expected["source"]["sha256"]:', 'if False:'),
    swap(CP, "a rejected entry is not reported", 'self.rejected.append({"entry": path.name, "reason": getattr(error, "reason", type(error).__name__)})', 'pass'),
    swap(CP, "an oversized entry is read", 'if path.stat().st_size > MAX_DOCUMENT_BYTES:\n                raise ResumeRefused("document_too_large", "oversized cache entry")', 'if False:\n                raise ResumeRefused("document_too_large", "oversized cache entry")'),
    # ---- rollback
    swap(CP, "a replay needs no explicit backend", 'if target_backend not in CONCRETE_BACKENDS or explicit is not True:', 'if target_backend not in CONCRETE_BACKENDS:'),
    swap(CP, "auto is an explicit backend", 'if target_backend not in CONCRETE_BACKENDS or explicit is not True:', 'if explicit is not True:'),
    swap(CP, "a replay on the same engine is a cross-engine replay", 'if target_backend == job["backend"]:', 'if False:'),
    swap(CP, "accepted rows do not stop a replay", 'if job["pages_accepted"] or job["rows_accepted"]:', 'if job["pages_accepted"]:'),
    swap(CP, "accepted pages do not stop a replay", 'if job["pages_accepted"] or job["rows_accepted"]:', 'if job["rows_accepted"]:'),
    swap(CP, "TEMP side effects do not stop a replay", 'if job["temp_side_effects"]:', 'if False:'),
    swap(CP, "a job on an unknown backend is replayed", 'if (not isinstance(job, Mapping) or job.get("backend") not in CONCRETE_BACKENDS', 'if (not isinstance(job, Mapping)'),
    swap(CP, "a refused replay does not raise", 'if decision.action == "refuse":', 'if False:'),
    swap(CP, "the rows of non-query results are not counted", 'rows += len(result.get("rows") or [])', 'pass'),
    swap(CP, "a partial answer is not an accepted page", 'elif entry.get("status") in ("complete", "partial"):', 'elif entry.get("status") == "complete":'),
    swap(CP, "a TEMP query is not a side effect", 'if arguments.get("named_temp_queries"):\n        return True', 'if False:\n        return True'),
    swap(CP, "a statement that is not SELECT is not a side effect", 'return any(not isinstance(sql, str) or not _is_pure_query(sql) for sql in statements or [])', 'return False'),
    swap(CP, "a HostLab checkpoint is read as the engine\'s", 'if type(document.get("schema")) is int:  # HostLab\'s own file', 'if False:  # HostLab\'s own file'),
    swap(CP, "a corrupt checkpoint is read back", '    _schema_gate(document)\n    verify_seal(document)\n    doc = _plain(document)', '    _schema_gate(document)\n    doc = _plain(document)'),
    swap(CP, "reading back an in-flight checkpoint says it is resumable", 'if termination not in RESUMABLE:\n                raise ResumeRefused("checkpoint_not_sealed" if termination == "in_flight" else "source_changed", "not resumable")', 'if False:\n                raise ResumeRefused("checkpoint_not_sealed" if termination == "in_flight" else "source_changed", "not resumable")'),
    swap(CP, "an oversized checkpoint is read back", 'if path.stat().st_size > MAX_DOCUMENT_BYTES:\n            raise ResumeRefused("document_too_large", "the checkpoint exceeds its size budget")\n        raw', 'if False:\n            raise ResumeRefused("document_too_large", "the checkpoint exceeds its size budget")\n        raw'),
    swap(CP, "a refusal can cause a fallback", '"seal_mismatch": "CACHE_CORRUPT"', '"seal_mismatch": "UNSUPPORTED_QUERY"'),
    swap(CP, "a lost worker is a fallback code", '"worker_lost": "WORKER_LOST"', '"worker_lost": "UNAVAILABLE_BACKEND"'),
    # ---- the remote runner adapter
    swap(RR, "a tool is routed on any server", 'if tool not in SERVER_TOOLS[server]:', 'if False:'),
    swap(RR, "an unknown server is routed", 'if server not in SERVER_TOOLS:', 'if False:'),
    swap(RR, "advance is not a dispatching tool", 'DISPATCHING_TOOLS = ("submit_version_matrix", "advance_version_matrix", "recover_version_matrix", "submit_analysis",', 'DISPATCHING_TOOLS = ("submit_version_matrix", "recover_version_matrix", "submit_analysis",'),
    swap(RR, "an engine tool has the wrong name", '"list_datasets", "list_resource_files"', '"list_datasets", "list_resource_file"'),
    swap(RR, "dexq has a tool too many", 'LEGACY_DEXQ_TOOLS = ("open_dataset", "list_datasets"', 'LEGACY_DEXQ_TOOLS = ("plan_analysis", "list_datasets"'),
    swap(RR, "a body does not make a call a mutation", 'if payload is not None or not args:', 'if not args:'),
    swap(RR, "an empty command is a read", 'if payload is not None or not args:', 'if payload is not None:'),
    swap(RR, "a field flag is not a mutation", 'if arg in _BODY_FLAGS or arg.split("=", 1)[0] in _BODY_FLAGS:', 'if arg in _BODY_FLAGS:'),
    swap(RR, "a body flag is not a mutation", '_BODY_FLAGS = {"-f", "-F", "--field", "--raw-field", "--input"}', '_BODY_FLAGS = {"-f", "-F", "--field", "--raw-field"}'),
    swap(RR, "a POST is a read", 'if (rest[index + 1] if index + 1 < len(rest) else "").upper() != "GET":', 'if False:'),
    swap(RR, "a trailing method flag is a read", 'if (rest[index + 1] if index + 1 < len(rest) else "").upper() != "GET":', 'if (rest[index + 1] if index + 1 < len(rest) else "GET").upper() != "GET":'),
    swap(RR, "--method=DELETE is a read", 'elif arg.startswith("--method="):\n                if arg.split("=", 1)[1].upper() != "GET":', 'elif arg.startswith("--method="):\n                if False:'),
    swap(RR, "-XPUT is a read", 'elif arg.startswith("-X") and arg[2:].upper() != "GET":', 'elif False:'),
    swap(RR, "a run rerun is a read", '_READ_SUBCOMMANDS = {"run": {"list", "view", "download"}', '_READ_SUBCOMMANDS = {"run": {"list", "view", "download", "rerun"}'),
    swap(RR, "a release create is a read", '"release": {"list", "view"}}', '"release": {"list", "view", "create"}}'),
    swap(RR, "an unknown command is a read", '        return "read"\n    return "mutate"', '        return "read"\n    return "read"'),
    swap(RR, "the guard runs a mutation", 'if effect == "mutate" and not self.allow_mutation:', 'if False:'),
    swap(RR, "the guard does not record", 'self.calls.append({"args": [str(a) for a in args], "effect": effect, "has_input": input is not None})', 'pass'),
    swap(RR, "the guard cannot be told to allow", 'if effect == "mutate" and not self.allow_mutation:', 'if effect == "mutate":'),
    swap(RR, "the runner revision is not checked", 'if not isinstance(runner_revision, str) or not _GIT.fullmatch(runner_revision):', 'if False:'),
    swap(RR, "the resume claim is part of the pin", 'without_resume = {k: v for k, v in request.items() if k != "resume"} if isinstance(request, dict) else request', 'without_resume = request'),
    swap(RR, "the sample SHA-256 is not checked", 'or not _SHA256.fullmatch(sample["sha256"])', ''),
    swap(RR, "the sample revision is not checked", 'or not isinstance(sample.get("revision"), str) or not sample["revision"] or len(sample["revision"]) > 256):', '):'),
    swap(RR, "the version code is not checked", 'if version is not None and (type(version) is not int or not 0 < version <= 9999999999):', 'if False:'),
    swap(RR, "the pin has no engine", '"engine": block.get("engine"), "config_digest"', '"engine": None, "config_digest"'),
    swap(RR, "the pin does not name the runner", '"runner_revision": runner_revision,', '"runner_revision": "",'),
    swap(RR, "the runner revision is not compared", '("runner_changed", "runner_revision", lambda p: p.get("runner_revision")),', ''),
    swap(RR, "the backends are not compared", '("backend_changed", "task_backends", lambda p: p.get("task_backends")),', ''),
    swap(RR, "the engine is not compared", '("engine_changed", "engine", lambda p: p.get("engine")),', ''),
    swap(RR, "the configuration is not compared", '("config_changed", "config_digest", lambda p: p.get("config_digest")),', ''),
    swap(RR, "the request is not compared", '("request_changed", "request_sha256", lambda p: p.get("request_sha256")),', ''),
    swap(RR, "the sample is not compared", '("source_changed", "sample", lambda p: p.get("sample")))', '("source_changed", "sample", lambda p: None))'),
    swap(RR, "the request id is not checked", 'if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):', 'if False:'),
    swap(RR, "the run attempt is not required", 'or type(run.get("run_attempt")) is not int or run["run_attempt"] < 1', ''),
    swap(RR, "the head SHA is not required", 'or not isinstance(run.get("head_sha"), str) or not _GIT.fullmatch(run["head_sha"])):', '):'),
    swap(RR, "the run id is not required", 'if (not isinstance(run, Mapping) or type(run.get("id")) is not int or run["id"] < 1', 'if (not isinstance(run, Mapping)'),
    swap(RR, "the title need not name the request", 'if run.get("display_title") != "hostlab-" + request_id:', 'if False:'),
    swap(RR, "an unfinished run has a manifest", 'if run.get("status") != "completed":\n        raise RemoteRefused("run_not_completed"', 'if False:\n        raise RemoteRefused("run_not_completed"'),
    swap(RR, "a failed run has a manifest", 'if run.get("conclusion") != "success":', 'if False:'),
    swap(RR, "an empty result has a manifest", 'if not entries:\n        raise RemoteRefused("manifest_malformed", "a result manifest lists at least one file")', 'if False:\n        raise RemoteRefused("manifest_malformed", "a result manifest lists at least one file")'),
    swap(RR, "a file outside the root is listed", 'if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():', 'if not resolved.is_file():'),
    swap(RR, "the number of files is not limited", 'len(entries) > ARTIFACT_LIMITS["max_files"] or ', ''),
    swap(RR, "the size of a file is not limited", 'or any(e["bytes"] > ARTIFACT_LIMITS["max_file_bytes"] for e in entries)', ''),
    swap(RR, "the unpacked size is not limited", 'or sum(e["bytes"] for e in entries) > ARTIFACT_LIMITS["max_unpacked_bytes"]):', '):'),
    swap(RR, "duplicate files are listed", 'if len({e["path"] for e in entries}) != len(entries):', 'if False:'),
    swap(RR, "a limit is not the cache\'s", '"max_files": 4096}', '"max_files": 4097}'),
    swap(RR, "a partial analysis is registrable", 'outcome.get("termination") == "complete"', 'outcome.get("termination") in ("complete", "partial")'),
    swap(RR, "a failed run is registrable", 'return outcome.get("conclusion") == "success" and outcome.get("termination") == "complete"', 'return outcome.get("termination") == "complete"'),
    swap(RR, "registrability is not enforced", 'if not registrable_as_complete(manifest):', 'if False:'),
    swap(RR, "the manifest seal is not checked", 'if not isinstance(manifest["seal"], Mapping) or manifest["seal"].get("digest") != digest_of(body):', 'if False:'),
    swap(RR, "the manifest schema is not checked", 'manifest.get("schema") != RESULT_SCHEMA\n            or not all', 'False\n            or not all'),
    swap(RR, "the repository is not compared", '("repository_mismatch", "repository"), ("repository_mismatch", "workflow"),', '("repository_mismatch", "workflow"),'),
    swap(RR, "the workflow is not compared", '("repository_mismatch", "repository"), ("repository_mismatch", "workflow"),', '("repository_mismatch", "repository"),'),
    swap(RR, "the request is not compared in the manifest", '("request_id_mismatch", "request_id"), ("run_mismatch", "run_id"),', '("run_mismatch", "run_id"),'),
    swap(RR, "the run is not compared", '("run_mismatch", "run_id"),', ''),
    swap(RR, "the run attempt is not compared", '("run_attempt_mismatch", "run_attempt"), ("head_sha_mismatch", "head_sha")):', '("head_sha_mismatch", "head_sha")):'),
    swap(RR, "the head SHA is not compared", ', ("head_sha_mismatch", "head_sha")):', '):'),
    swap(RR, "the pin is not compared", 'check_pin(manifest["pin"], pin)', 'pass'),
    swap(RR, "a listed path may leave the root", 'if not target.is_relative_to(base):\n            raise RemoteRefused("file_outside_root", f"{relative} leaves the artifact root")', 'if False:\n            raise RemoteRefused("file_outside_root", f"{relative} leaves the artifact root")'),
    swap(RR, "a missing file is not noticed", 'if not target.is_file():\n            raise RemoteRefused("file_missing"', 'if False:\n            raise RemoteRefused("file_missing"'),
    swap(RR, "a changed file is not noticed", 'if hashlib.sha256(data).hexdigest() != entry["sha256"]:', 'if False:'),
    swap(RR, "an extra file is not noticed", 'if present - set(listed):', 'if False:'),
    swap(RR, "an unknown dispatch is replayed", 'if record is not None and record.get("status") == "dispatch_unknown":', 'if False:'),
    swap(RR, "a run in progress is not running", 'if run.get("status") != "completed":\n        return "running"', 'if False:\n        return "running"'),
    swap(RR, "a failed conclusion is not a failure", 'return "failed" if isinstance(conclusion, str) and conclusion else "unknown"', 'return "unknown"'),
    swap(RR, "a cancelled run is not cancelled", 'if conclusion in ("cancelled", "skipped"):', 'if conclusion == "skipped":'),
    swap(RR, "a running job may be sent again", 'return state in ("failed", "cancelled", "skipped") and new_idempotency_key is True', 'return state in ("failed", "cancelled", "skipped", "running") and new_idempotency_key is True'),
    swap(RR, "a failed job is sent again under the old key", 'return state in ("failed", "cancelled", "skipped") and new_idempotency_key is True', 'return state in ("failed", "cancelled", "skipped")'),
    swap(RR, "an unknown dispatch is recovered", 'if state in ("failed", "cancelled", "skipped"):\n        return True', 'if state in ("failed", "cancelled", "skipped", "dispatch_unknown"):\n        return True'),
    swap(RR, "a verified success is recovered", 'return state == "succeeded" and not verified and include_unverified_results is True', 'return state == "succeeded" and include_unverified_results is True'),
    swap(RR, "an unverified success is recovered without asking", 'return state == "succeeded" and not verified and include_unverified_results is True', 'return state == "succeeded" and not verified'),
    swap(RR, "the adapter writes anywhere", 'if not any(target.is_relative_to(directory) for directory in mine):', 'if False:'),
    swap(RR, "the adapter writes in HostLab\'s scopes", 'if target.is_relative_to(Path(state).resolve() / name):', 'if False:'),
    swap(RR, "the engine\'s cache is not writable", 'for name in ("root", "cache", "reports", "completion")]', 'for name in ("root", "reports", "completion")]'),
    swap(RR, "a sample is read by any spelling", 'if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):\n        raise RemoteRefused("invalid_sample", "a sample is named by its SHA-256")', 'if False:\n        raise RemoteRefused("invalid_sample", "a sample is named by its SHA-256")'),
    swap(RR, "a missing sample is read", 'if not path.is_file():\n        raise RemoteRefused("sample_missing"', 'if False:\n        raise RemoteRefused("sample_missing"'),
    swap(RR, "a changed sample is read", 'if verify and hashlib.sha256(path.read_bytes()).hexdigest() != sha256:', 'if False:'),
    swap(RR, "a scope is writable by the adapter", '"samples": "read", "reports": "none"', '"samples": "read", "reports": "write"'),
    swap(RR, "a refusal can cause a fallback", '"dispatch_refused": "INVALID_ARGUMENT"', '"dispatch_refused": "UNSUPPORTED_QUERY"'),
    swap(RR, "a changed engine is a fallback code", '"engine_changed": "STALE_CACHE"', '"engine_changed": "UNAVAILABLE_BACKEND"'),
    # ---- MDD-053 adversarial-review fixes
    # P1-1: import must mirror seal's snapshot-binding refusal
    swap(CP, "results are imported without a snapshot", 'if doc["identity"].get("snapshot") is None and any(t["disposition"] in ("reuse", "continue") for t in state["tasks"]):', 'if False:'),
    swap(CP, "a continued result without a snapshot is imported", 'if doc["identity"].get("snapshot") is None and any(t["disposition"] in ("reuse", "continue") for t in state["tasks"]):', 'if doc["identity"].get("snapshot") is None and any(t["disposition"] == "reuse" for t in state["tasks"]):'),
    # P2-1: a duplicate-id report is not complete (id set, not just count)
    swap(CP, "duplicate task ids make a report complete", 'and {t.get("id") for t in report["tasks"]} == {t["id"] for t in request["tasks"]}', ''),
    # P1-2: the TEMP side-effect guard proves a single pure SELECT/WITH-SELECT
    swap(CP, "a second statement after a semicolon is ignored", 'if len(statements) != 1:', 'if len(statements) < 1:'),
    swap(CP, "a modifying keyword in a WITH is ignored", 'return _SQL_MUTATING.search(statement) is None', 'return True'),
    swap(CP, "literals and comments are not masked", 'masked = _mask_sql(sql)', 'masked = sql'),
    swap(CP, "a statement need not start with SELECT or WITH", 'if not re.match(r"(?is)^\\s*(select|with)\\b", statement):', 'if False:'),
    # P2-2: an attached gh shorthand is a mutation unless provably read-only
    swap(RR, "an attached field shorthand is a read", 'elif arg.startswith("-") and not arg.startswith(("--", "-X")) and arg != "-i" and not arg.startswith(("-H", "-q", "-t")):', 'elif arg.startswith("-") and not arg.startswith(("--", "-X")) and arg != "-i" and not arg.startswith(("-H", "-q", "-t", "-f", "-F")):'),
    swap(RR, "an unknown shorthand cluster is a read", 'elif arg.startswith("-") and not arg.startswith(("--", "-X")) and arg != "-i" and not arg.startswith(("-H", "-q", "-t")):', 'elif False:'),
    swap(RR, "an attached header is a mutation", 'not arg.startswith(("-H", "-q", "-t"))', 'not arg.startswith(("-q", "-t"))'),
    swap(RR, "the include shorthand is a mutation", 'and arg != "-i" and', 'and'),
]


COPY = ["integrations/hostlab", "conformance/corpus/hostlab/source-8782f43", "conformance/manifests/tools-and-options.json",
        "tests/fixtures/generated/multidex-deflated.apk", "tests/fixtures/generated/multidex-stored.apk"]


def workspace(base, index):
    root = base / f"w{index}"
    for relative in COPY:
        source, target = REPO / relative, root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", "vendor", "*.pyc"))
        else:
            shutil.copyfile(source, target)
    return root


def run_mutant(root, item):
    name, label, old, new = item
    path = root / "integrations" / "hostlab" / name
    original = path.read_text(encoding="utf-8")
    path.write_text(original.replace(old, new), encoding="utf-8", newline="\n")
    try:
        done = subprocess.run([sys.executable, "-I", "-m", "unittest", "discover", "-f", "-s", str(root / "integrations" / "hostlab"),
                               "-p", "test_[cr]*_adapter.py"], capture_output=True, text=True, cwd=str(root), timeout=300)
        return "killed" if done.returncode != 0 else "SURVIVED"
    except subprocess.TimeoutExpired:
        return "killed (the tests hung)"
    finally:
        path.write_text(original, encoding="utf-8", newline="\n")


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="only check that every pattern matches exactly once")
    parser.add_argument("--only", default="", help="run the mutants whose label contains this text")
    parser.add_argument("--jobs", type=int, default=6, help="mutants run at the same time, each in its own copy")
    options = parser.parse_args(argv)
    chosen = [(index, item) for index, item in enumerate(MUTANTS, 1) if options.only in item[1] or options.only in item[0]]
    problems = []
    runnable = []
    for index, item in chosen:
        count = (HOSTLAB / item[0]).read_text(encoding="utf-8").count(item[2])
        if count != 1:
            print(f"{index:3} NOT APPLICABLE ({count} matches): {item[1]}", flush=True)
            problems.append((index, item[1], "pattern"))
        else:
            runnable.append((index, item))
    if options.dry_run:
        print(f"{len(chosen)} patterns checked; problems: {problems}")
        return 1 if problems else 0
    base = Path(tempfile.mkdtemp(prefix="mdd053-mutation-"))
    try:
        free = queue.Queue()
        for number in range(max(1, min(options.jobs, len(runnable) or 1))):
            free.put(workspace(base, number))

        def work(entry):
            index, item = entry
            root = free.get()
            try:
                verdict = run_mutant(root, item)
            finally:
                free.put(root)
            print(f"{index:3} {verdict}: {item[1]}", flush=True)
            return index, item[1], verdict

        with concurrent.futures.ThreadPoolExecutor(max_workers=options.jobs) as pool:
            results = list(pool.map(work, runnable))
    finally:
        shutil.rmtree(base, ignore_errors=True)
    problems += [(index, label, "survived") for index, label, verdict in results if verdict == "SURVIVED"]
    print(f"{len(chosen)} mutants; survivors: {sorted(problems)}")
    print("sources sha256:", sources_sha256())
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
