"""Run a bounded group with isolated per-sample analysis and two-way input prefetch."""
from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from collections import deque
import json
import os
import shutil
import time

import analyze
import analysis_plan
import hostlab
import runner_group
import runner_resources

PREFETCH = 2
SAMPLE_REPOSITORY = "innocent-lab-dev/bilibili-host-apks"
FETCH_BUDGET_SECONDS = 600
MAX_GROUP_SECONDS = 3300


def bound_decisions(state):
    decisions = state.get("prefetch_decisions", [])
    while decisions and (len(decisions) > 48 or len(json.dumps(decisions, indent=2).encode()) > 24576
                         or len(json.dumps(state, ensure_ascii=False, indent=2).encode()) > 64000):
        del decisions[16 if len(decisions) > 16 else 0]
        state["prefetch_decisions_omitted"] += 1


def fetch(row, revision, origin, submitted):
    started = time.monotonic()
    timings = {}
    try:
        apk = analyze.fetch_sample(row, SAMPLE_REPOSITORY, revision, timings=timings)
        prepared = {"apk": apk}
    except Exception as exc:
        prepared = {"error": exc}
    finished = time.monotonic()
    timings.update(group_fetch_started_ms=(started-origin)*1000,
                   group_fetch_finished_ms=(finished-origin)*1000,
                   group_fetch_queue_ms=(started-submitted)*1000)
    return {**prepared, "timings": timings, "fetch_ms": (finished - started) * 1000}


def failed_output(output, sample, request, index, exc, execution_sha256=None):
    """Retain a bounded pair even if preparation or per-sample reporting raised."""
    output.mkdir(parents=True, exist_ok=True)
    report = {"complete": False, "scope": "offline_static_only", "error": type(exc).__name__,
              "message": type(exc).__name__, "tasks": []}
    (output / "result.txt").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    import remote_job
    metadata = {"operation": "batch", "version_code": sample["version_code"],
        "apk_sha256": sample["apk_sha256"], "sample_revision": sample["sample_revision"],
        "request_sha256": analysis_plan.fingerprint(request), "group_index": index,
        "runner_revision": os.environ.get("HOSTLAB_RUNNER_REVISION") or os.environ.get("GITHUB_SHA"),
        "workflow_revision": os.environ.get("GITHUB_SHA"), "scope": "offline_static_only",
        "complete": False, "exit_code": 1, "error": type(exc).__name__,
        "tools": remote_job.batch_tool_hashes(), "backend_versions": None, "fetch_ms": None,
        "phases": {}, "preparation": None, "total_ms": 0.0}
    if execution_sha256 is not None:
        metadata["execution_sha256"] = execution_sha256
    hostlab.write_json(output / "job.json", metadata)


def run(payload, *, entry_started=None):
    payload = runner_group.validate(payload)
    started = time.monotonic()
    output = hostlab.STATE / "remote-output"
    output.mkdir(parents=True, exist_ok=True)
    state = {}
    sampler = runner_resources.make_sampler(origin=started, disk_path=hostlab.STATE)
    try:
        sampler.start()
        return execute(payload, state, sampler, started, output, entry_started=entry_started)
    finally:
        sampler.set_phase("shutdown")
        try:
            resources = sampler.stop(output / "resources.json")
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            resources = {**sampler.summary(), "artifact_error": type(exc).__name__}
        if state:
            state["resources"] = resources
            state["elapsed_ms"] = (time.monotonic()-started)*1000
            bound_decisions(state)
            hostlab.write_json(output / "group.json", state)


def execute(payload, state, sampler, started, output, *, entry_started=None):
    import remote_job

    request, samples = payload["request"], payload["samples"]
    adaptive = payload["schema"] == 2
    execution_sha = runner_group.execution_fingerprint(payload)
    controller = runner_resources.AdaptivePrefetch(payload["execution"]["prefetch_max"]) if adaptive else None
    budget = min(MAX_GROUP_SECONDS, len(samples) * (request["timeout_seconds"] + FETCH_BUDGET_SECONDS))
    admission_deadline = started + budget
    state.update({"schema": 1, "request_sha256": analysis_plan.fingerprint(request),
        "runner_revision": os.environ.get("HOSTLAB_RUNNER_REVISION") or os.environ.get("GITHUB_SHA"),
        "samples": [{"sample": sample, "index": index, "status": "not_started"}
                    for index, sample in enumerate(samples)],
        "prefetch_parallel": PREFETCH, "admission_budget_seconds": budget,
        "deadline_exhausted": False, "processing_order": [], "sample_timings": [],
        "prefetch_decisions": [], "prefetch_decisions_omitted": 0})
    if adaptive:
        state["execution"] = payload["execution"]

    def save():
        state["elapsed_ms"] = (time.monotonic() - started) * 1000
        bound_decisions(state)
        hostlab.write_json(output / "group.json", state)

    # Every selector is durably represented before the first network access.
    save()
    contexts, errors = {}, {}
    gate_started = time.monotonic()
    try:
        hostlab.api_private(SAMPLE_REPOSITORY)
    except Exception as exc:
        errors = {index: exc for index in range(len(samples))}
    state["phases"] = {"repo_info_ms": (time.monotonic() - gate_started) * 1000}
    manifests, manifest_errors = {}, {}
    if not errors:
        for revision in dict.fromkeys(sample["sample_revision"] for sample in samples):
            manifest_started = time.monotonic()
            try:
                manifests[revision] = hostlab.manifest(SAMPLE_REPOSITORY, revision)
            except Exception as exc:
                manifest_errors[revision] = exc
            state["phases"].setdefault("manifest_ms", {})[revision] = (time.monotonic() - manifest_started) * 1000
        for index, sample in enumerate(samples):
            revision = sample["sample_revision"]
            try:
                if revision in manifest_errors:
                    raise manifest_errors[revision]
                row = hostlab.select(manifests[revision], sample["version_code"], sample["apk_sha256"])
                if type(row.get("size")) is not int or not 1 <= row["size"] <= 1024**3:
                    raise RuntimeError("Invalid immutable sample size")
                contexts[index] = row
            except Exception as exc:
                errors[index] = exc
    save()

    def finish(index, prepared):
        sample = samples[index]
        target = output / "samples" / str(index)
        processing_started = time.monotonic()
        sampler.set_phase("processing")
        phases = {"group_processing_started_ms": (processing_started-started)*1000}
        if "group_fetch_finished_ms" in prepared["timings"]:
            phases["group_prefetch_ready_wait_ms"] = max(0.0,
                phases["group_processing_started_ms"]-prepared["timings"]["group_fetch_finished_ms"])
        try:
            row = contexts.get(index, {"version_code": sample["version_code"], "sha256": sample["apk_sha256"]})
            rc = remote_job.run_batch(request, row, SAMPLE_REPOSITORY, sample["sample_revision"],
                output=target, prepared_input=prepared, group_index=index, context_timings=phases,
                resource_sampler=sampler, group_origin=started, execution_sha256=execution_sha)
            status = "complete" if rc == 0 else "failed"
        except Exception as exc:
            failed_output(target, sample, request, index, exc, execution_sha)
            status = "failed"
        sampler.set_phase("waiting_inputs")
        processing_finished = time.monotonic()
        if controller is not None and status == "complete":
            controller.observe(fetch_ms=prepared["fetch_ms"], processing_ms=(processing_finished-processing_started)*1000,
                               ready_wait_ms=phases.get("group_prefetch_ready_wait_ms", 0))
        state["samples"][index]["status"] = status
        state["processing_order"].append(index)
        state["sample_timings"].append({"index": index, **prepared["timings"], **phases,
            "group_processing_finished_ms": (processing_finished-started)*1000})
        save()

    # Invalid/missing selectors fail individually; unrelated revisions can still run.
    for index, exc in errors.items():
        finish(index, {"error": exc, "timings": {}, "fetch_ms": 0.0})
    pending = deque(index for index in range(len(samples)) if index not in errors)
    sampler.set_phase("waiting_inputs")
    # Only input preparation overlaps. Each analysis keeps a fresh backend session,
    # so RSS is bounded by one prepared dataset plus two streaming downloads.
    with ThreadPoolExecutor(max_workers=PREFETCH) as pool:
        inflight = {}

        def fill(phase="waiting_inputs"):
            while pending and len(inflight) < PREFETCH and time.monotonic() < admission_deadline:
                index = pending[0]
                snapshot = sampler.snapshot()
                try:
                    observed_free = shutil.disk_usage(hostlab.STATE).free
                except OSError:
                    observed_free = None
                reserved = 2*sum(contexts[queued]["size"] for queued in inflight.values())
                snapshot["disk_free_bytes"] = max(0, observed_free-reserved) if observed_free is not None else None
                if controller is not None:
                    decision = controller.decide(snapshot, phase=phase, next_size=contexts[index]["size"], inflight=len(inflight))
                else:
                    free = snapshot.get("disk_free_bytes")
                    admitted = free is None or free >= 2*contexts[index]["size"]+512*1024**2
                    decision = {"target": PREFETCH, "admit": admitted, "phase": phase,
                        "reason": ["legacy_fixed_prefetch"] if admitted else ["disk_capacity"],
                        "effect": "admission_only", "inputs": {"ts_ms": snapshot.get("ts_ms"),
                            "disk_free_bytes": free, "next_sample_bytes": contexts[index]["size"]}}
                action = "submit" if decision["admit"] and len(inflight) < decision["target"] else "limit"
                decision["inputs"].update(disk_free_observed_bytes=observed_free, reserved_download_bytes=reserved)
                previous_target = state["prefetch_decisions"][-1]["target"] if state["prefetch_decisions"] else (1 if adaptive else PREFETCH)
                state["prefetch_decisions"].append({"index": index, "action": action, **decision,
                    "ts_ms": (time.monotonic()-started)*1000,
                    "prefetch_before": previous_target, "prefetch_after": decision["target"],
                    "window_entries_before": len(inflight),
                    "window_entries_after": len(inflight)+(1 if action == "submit" else 0)})
                bound_decisions(state)
                if not decision["admit"]:
                    for queued in pending:
                        state["samples"][queued]["reason"] = "disk_capacity"
                    break
                if len(inflight) >= decision["target"]:
                    break
                pending.popleft()
                state["samples"][index].pop("reason", None)
                future = pool.submit(fetch, contexts[index], samples[index]["sample_revision"], started, time.monotonic())
                inflight[future] = index

        fill()
        while inflight:
            remaining = admission_deadline-time.monotonic()
            if remaining <= 0:
                state["deadline_exhausted"] = True
                save()
                break
            done, _ = wait(inflight, timeout=remaining, return_when=FIRST_COMPLETED)
            if not done:
                state["deadline_exhausted"] = True
                save()
                break
            # Completion wins over input order; the stable index binds output identity.
            future = min(done, key=lambda item: inflight[item])
            index = inflight.pop(future)
            try:
                prepared = future.result()
            except Exception as exc:
                prepared = {"error": exc, "timings": {}, "fetch_ms": 0.0}
            if "error" not in prepared and admission_deadline-time.monotonic() < request["timeout_seconds"]:
                state["deadline_exhausted"] = True
                save()
                break
            fill("processing")
            finish(index, prepared)
            fill()
        # Stop admission; native transfers cannot be interrupted by Future.cancel().
        # Join running downloads here; Actions supplies the outer process deadline.
        for future in inflight:
            future.cancel()
    state["complete"] = all(row["status"] == "complete" for row in state["samples"])
    if any(row["status"] == "not_started" and row.get("reason") != "disk_capacity" for row in state["samples"]):
        state["deadline_exhausted"] = True
    if entry_started is not None:
        state["entry_ms"] = (time.monotonic() - entry_started) * 1000
    save()
    print(json.dumps({"operation": "batch_group", "complete": state["complete"],
        "samples": [{"index": row["index"], "status": row["status"]} for row in state["samples"]]}))
    return 0 if state["complete"] else 2
