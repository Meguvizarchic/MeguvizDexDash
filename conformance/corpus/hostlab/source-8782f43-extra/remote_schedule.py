"""Caller-side bounded batch scheduling. Unknown dispatch outcomes are never replayed."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid
from datetime import datetime

import analysis_plan
import hostlab


def admission_lock(path):
    """OS releases this nonblocking lock even if the caller crashes."""
    stream = path.open("a+b", buffering=0)
    try:
        # Another Windows opener can lock the first byte between our size
        # check and initialization. That sharing conflict is also a busy lock.
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b" ")
            stream.flush()
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        try:
            stream.close()
        except OSError:
            pass
        return None
    return stream


def reconcile(receipt, run):
    """Within a proven run attempt, terminal and newer observations are monotonic."""
    def positive(value):
        return value if type(value) is int and value > 0 else None
    def instant(value):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() if isinstance(value, str) else None
        except ValueError:
            return None
    old_id, new_id = positive(receipt.get("run_id")), positive(run.get("id"))
    old_attempt, new_attempt = positive(receipt.get("run_attempt")), positive(run.get("run_attempt"))
    old_at, new_at = instant(receipt.get("run_updated_at")), instant(run.get("updated_at"))
    same_run = old_id is not None and old_id == new_id
    higher = same_run and old_attempt is not None and new_attempt is not None and new_attempt > old_attempt
    if same_run and old_attempt is not None and new_attempt is not None and new_attempt < old_attempt:
        return {**receipt, "stale_observation_ignored": True}
    if (same_run and old_attempt is not None and old_attempt == new_attempt
            and old_at is not None and new_at is not None and new_at < old_at):
        return {**receipt, "stale_observation_ignored": True}
    if receipt.get("status") == "completed" and run.get("status") != "completed" and not higher:
        # A same-attempt final state cannot regress. An unproven newer active
        # observation may be a rerun not yet numbered; retain an occupied slot.
        proved_old = same_run and old_attempt is not None and new_attempt == old_attempt and (
            old_at is not None and new_at is not None and new_at <= old_at)
        return {**receipt, "stale_observation_ignored": bool(proved_old), "state_uncertain": not proved_old}
    if old_id is not None and new_id is not None and old_id != new_id:
        return {**receipt, "state_uncertain": True, "observed_run_id": new_id}
    updated = {**receipt, "status": run["status"], "conclusion": run.get("conclusion"),
               "state_uncertain": False, "stale_observation_ignored": False}
    if new_id is not None:
        updated["run_id"] = new_id
    if new_attempt is not None:
        updated["run_attempt"] = new_attempt
    if isinstance(run.get("updated_at"), str) and new_at is not None:
        updated["run_updated_at"] = run["updated_at"]
    if isinstance(run.get("created_at"), str):
        updated["run_created_at"] = run["created_at"]
    return updated


def active_receipt(receipt):
    return receipt.get("state_uncertain") is True or receipt.get("status") != "completed"


def public_status(receipt):
    return "status_unconfirmed" if receipt.get("state_uncertain") else receipt.get("status", "dispatch_unknown")


def describe(request):
    request = analysis_plan.validate(request)
    result = analysis_plan.plan(request)
    result.update({"environment": "remote_runner", "availability": "verified_on_runner_before_use",
                   "legacy_commands_default": "sqlite", "jadx_path": "unchanged",
                   "max_tasks": analysis_plan.MAX_TASKS, "max_request_bytes": analysis_plan.MAX_REQUEST_BYTES,
                   "completed_reuse": "requires_exact_apk_sha_and_sample_revision", "unknown_dispatch": "look_up_existing_request_do_not_replay"})
    return result


def submit(version_code, request, gh, lookup, runs, *, repository, workflow,
           apk_sha256="", sample_revision="", idempotency_key="", runner_revision=None,
           reuse_completed=True):
    request = analysis_plan.validate(request)
    analysis_plan.integer(version_code, 1, 9999999999, "version_code")
    if bool(apk_sha256) != bool(sample_revision):
        raise ValueError("provide both immutable APK SHA-256 and sample revision, or neither")
    if apk_sha256 and not re.fullmatch(r"[0-9a-f]{64}", apk_sha256):
        raise ValueError("invalid APK SHA-256")
    if sample_revision and not re.fullmatch(r"[0-9a-f]{40}", sample_revision):
        raise ValueError("invalid sample revision")
    if "resume" in request:
        if not apk_sha256 or not sample_revision:
            raise ValueError("resume requires exact APK SHA-256 and sample revision")
        if not idempotency_key:
            idempotency_key = "resume-" + hashlib.sha256(json.dumps(request["resume"], sort_keys=True).encode()).hexdigest()[:32]
    if idempotency_key and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", idempotency_key):
        raise ValueError("invalid idempotency key")
    head = runner_revision or json.loads(gh(["api", f"repos/{repository}/git/ref/heads/main"]))["object"]["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("invalid runner source revision")
    identity = {"version_code": version_code, "request": request, "apk_sha256": apk_sha256,
                "sample_revision": sample_revision, "runner_revision": head, "key": idempotency_key}
    inputs = {"version_code": str(version_code), "operation": "batch",
              "argument": json.dumps(request, separators=(",", ":"), ensure_ascii=False)}
    if apk_sha256:
        inputs.update(apk_sha256=apk_sha256, source_revision=sample_revision)
    return _submit(identity, inputs, describe(request), gh, lookup, runs, repository=repository,
                   workflow=workflow, idempotency_key=idempotency_key, head=head,
                   reuse_completed=reuse_completed and bool(apk_sha256)
                   and all(task["operation"] != "query" for task in request["tasks"]))


def submit_group(samples, request, gh, lookup, runs, *, repository, workflow,
                 idempotency_key="", runner_revision=None, reuse_completed=True, execution=None):
    import runner_group
    payload = runner_group.validate({"schema": 2 if execution is not None else 1, "samples": samples, "request": request,
                                    **({"execution": execution} if execution is not None else {})})
    head = runner_revision or json.loads(gh(["api", f"repos/{repository}/git/ref/heads/main"]))["object"]["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("invalid runner source revision")
    if idempotency_key and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", idempotency_key):
        raise ValueError("invalid idempotency key")
    identity = {"operation": "batch_group", "samples": payload["samples"], "request": payload["request"],
                "runner_revision": head, "key": idempotency_key,
                **({"execution": execution} if execution is not None else {})}
    inputs = {"version_code": str(payload["samples"][0]["version_code"]), "operation": "batch_group",
              "argument": json.dumps(payload, separators=(",", ":"), ensure_ascii=False)}
    return _submit(identity, inputs, {**describe(payload["request"]), "runner_batch_size": len(samples)},
                   gh, lookup, runs, repository=repository, workflow=workflow,
                   idempotency_key=idempotency_key, head=head,
                   reuse_completed=reuse_completed and all(t["operation"] != "query" for t in payload["request"]["tasks"]))


def _submit(identity, inputs, plan, gh, lookup, runs, *, repository, workflow,
            idempotency_key, head, reuse_completed):
    """One durable admission protocol for single and grouped runner submissions."""
    payload_hash = hashlib.sha256(json.dumps(identity, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    key = hashlib.sha256(("idempotency:" + idempotency_key).encode()).hexdigest() if idempotency_key else payload_hash
    directory = hostlab.STATE / "analysis-schedule"
    directory.mkdir(parents=True, exist_ok=True)
    record_path, lock_path = directory / (key + ".json"), directory / "admission.lock"
    lock = admission_lock(lock_path)
    if lock is None:
        return {"status": "scheduler_busy", "dispatched": False, "request_sha256": key}
    try:
        if record_path.exists():
            old = json.loads(record_path.read_text(encoding="utf-8"))
            if old["request_sha256"] != payload_hash:
                raise ValueError("idempotency key is already bound to a different immutable request")
            run = lookup(old["request_id"])
            if run is not None:
                old = reconcile(old, run)
                hostlab.write_json(record_path, old)
            if run is None or active_receipt(old):
                return {**old, "reused": True, "dispatched": False,
                        "status": public_status(old)}
            if idempotency_key or reuse_completed and old.get("conclusion") == "success" and time.time() - old["created_at"] < 86400:
                return {**old, "reused": True, "dispatched": False, "status": "completed"}
        recent = runs()
        observed = {r.get("display_title", "").removeprefix("hostlab-"):r for r in recent}
        active = {key for key,r in observed.items() if r.get("status") != "completed"}
        for path in directory.glob("*.json"):
            receipt = json.loads(path.read_text(encoding="utf-8"))
            if receipt["request_id"] in observed:
                updated = reconcile(receipt, observed[receipt["request_id"]])
                if updated != receipt:
                    hostlab.write_json(path, updated)
                if active_receipt(updated):
                    active.add(receipt["request_id"])
                else:
                    active.discard(receipt["request_id"])
            elif active_receipt(receipt):
                active.add(receipt["request_id"])
        if len(active) >= 4:
            return {"status": "capacity_full", "dispatched": False, "active_jobs": len(active), "limit": 4}
        request_id = uuid.uuid4().hex
        record = {"request_id": request_id, "request_sha256": payload_hash, "status": "dispatch_unknown",
                  "created_at": time.time(), "runner_revision": head, "plan": plan,
                  **{k: v for k, v in identity.items() if k not in {"request", "key", "runner_revision"}}}
        record["queued_at"] = record["created_at"]
        # Write before the network request: a client/network crash must not cause automatic paid replay.
        hostlab.write_json(record_path, record)
        hostlab.write_json(hostlab.STATE / "remote-requests" / (request_id + ".json"), record)
        inputs = {**inputs, "request_id": request_id, "runner_revision": head}
        import remote_dispatch
        dispatched = remote_dispatch.dispatch(repository, workflow, inputs, gh)
        record.update({key: value for key, value in dispatched.items() if key not in {"dispatched", "next_action"}})
        record["queued_at"] = record["created_at"]
        hostlab.write_json(record_path, record)
        hostlab.write_json(hostlab.STATE / "remote-requests" / (request_id + ".json"), record)
        return {**record, "dispatched": dispatched["dispatched"], "reused": False, "repository": repository,
                **({"next_action": dispatched["next_action"]} if "next_action" in dispatched else {})}
    finally:
        lock.close()


def observe(request_id, run):
    """Update only known receipts after an authenticated status read."""
    directory = hostlab.STATE / "analysis-schedule"
    directory.mkdir(parents=True, exist_ok=True)
    lock = admission_lock(directory / "admission.lock")
    if lock is None:
        return
    try:
        selected = None
        for path in directory.glob("*.json"):
            receipt = json.loads(path.read_text(encoding="utf-8"))
            if receipt["request_id"] == request_id:
                selected = reconcile(receipt, run)
                hostlab.write_json(path, selected)
        journal = hostlab.STATE / "remote-requests" / (request_id + ".json")
        if journal.exists():
            old = json.loads(journal.read_text(encoding="utf-8"))
            selected = reconcile({**old, **(selected or {})}, run)
            hostlab.write_json(journal, selected)
        return selected
    finally:
        lock.close()
