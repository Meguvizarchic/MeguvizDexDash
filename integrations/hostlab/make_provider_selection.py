#!/usr/bin/env python3
"""Regenerate artifacts/mdd-050/provider-selection.json (or check that it is current).

    python -I integrations/hostlab/make_provider_selection.py            # write it
    python -I integrations/hostlab/make_provider_selection.py --check    # exit 1 if the file differs

The record is produced by running the provider (provider.py, install_meguvizdexdash.py) over a fixed set of
scenarios and over the frozen HostLab planner, so it is not edited by hand. It is deterministic: no clock, no
local path, a fixed stand-in for the engine. Every input is named with its SHA-256, so a changed input shows up
as a changed record. What a stand-in cannot show (the real binary) is checked by test_live_engine.py and said so
in `not_proven`; this record is not evidence about the real engine's behaviour.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import hostlab_test_support as support  # noqa: E402
import install_meguvizdexdash as installer  # noqa: E402
import provider  # noqa: E402

ROOT = support.ROOT
OUTPUT = ROOT / "artifacts/mdd-050/provider-selection.json"
FIXTURE_PLATFORM = "fixture/platform"
ENGINE = provider.ENGINE
LEGACY = support.load_frozen("analysis_plan")
INPUTS = [
    "integrations/hostlab/provider.py", "integrations/hostlab/install_meguvizdexdash.py",
    "integrations/hostlab/config-schema.json", "integrations/hostlab/hostlab_test_support.py",
    "integrations/hostlab/make_provider_selection.py",
    "conformance/corpus/hostlab/source-8782f43/manifest.json",
    "conformance/corpus/hostlab/source-8782f43/analysis_plan.py",
    "conformance/corpus/hostlab/source-8782f43/analysis_batch.py",
    "conformance/corpus/hostlab/source-8782f43/install_dexsql.py",
    "conformance/mcp/hostlab-required-tools.json",
]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cfg(native=ENGINE, **engine):
    document = {"schema": provider.CONFIG_SCHEMA, "native_engine": native}
    if engine:
        document[ENGINE] = engine
    return provider.parse_config(document)


ALL_ON = ("UNAVAILABLE_BACKEND", "UNSUPPORTED_CAPABILITY", "UNSUPPORTED_QUERY")


def summarize(plan: dict) -> dict:
    block = plan.get("provider")
    return {
        "tasks": [{key: task[key] for key in ("id", "backend", "reason", "fallback_from", "forced") if key in task}
                  for task in plan["tasks"]],
        "groups": plan["groups"], "dataset_opens": plan["dataset_opens"], "request_sha256": plan["request_sha256"],
        "provider": None if block is None else {
            "native_engine": block["native_engine"], "selection": block["selection"], "negotiation": block["negotiation"],
            "config_digest": block["config_digest"], "fallbacks": block["fallbacks"], "engine": block["engine"]},
    }


def engines(directory: Path) -> dict:
    """Named stand-in engines, each pinned and probed through the real installer code."""
    made = {}
    for label, options, tamper in (
        ("available", {}, False), ("admitted", {"admitted": True}, False),
        ("bad_sha", {}, True), ("no_decode_tool", {"tools": tuple(t for t in support.TOOLS if t != "decode")}, False),
    ):
        folder = directory / label
        folder.mkdir()
        binary, manifest, fake = support.pin_binary(folder, support.FakeEngine(**options))
        # re-pin under the fixed platform name so the record does not depend on the machine
        manifest.unlink()
        installer.pin(binary, manifest, runner=fake, platform_name=FIXTURE_PLATFORM)
        if tamper:
            binary.write_bytes(b"stand-in engine 1, altered after the pin")
        made[label] = installer.status(binary, manifest, fake, deep=True, platform_name=FIXTURE_PLATFORM)
    return made


request, Q, SQ, L, D, I, RS = (support.request, support.QUERY, support.SQLITE_QUERY, support.LOCATE, support.DECODE,
                               support.INFO, support.REFS_SITES)


SCENARIOS = [
    ("legacy-default-auto", "no engine setting: an auto request is planned exactly as HostLab always did",
     cfg("dexsql"), request(Q, L, D, RS), "available", True),
    ("legacy-dexsql-not-moved", "backend dexsql is DexSQL even when the engine is routed and available",
     cfg(profile_policy="allow_unadmitted"), request(Q, L, D, backend="dexsql"), "available", True),
    ("legacy-sqlite-not-moved", "backend sqlite stays sqlite",
     cfg(profile_policy="allow_unadmitted"), request(L, backend="sqlite"), "available", True),
    ("legacy-dexsql-engine-unavailable", "backend dexsql with the engine unusable is still DexSQL, not a fallback",
     cfg(profile_policy="allow_unadmitted", fallback={"to": "dexsql", "on": list(ALL_ON)}),
     request(Q, backend="dexsql"), "bad_sha", True),
    ("auto-routed-to-engine", "native_engine=meguvizdexdash: the work DexSQL would get goes to the engine; sqlite-only work stays",
     cfg(profile_policy="allow_unadmitted"), request(Q, L, D, I, RS), "available", False),
    ("auto-routed-profile-not-admitted", "the default policy refuses a profile that is not admitted",
     cfg(), request(Q), "available", False),
    ("auto-routed-profile-admitted", "an admitted profile is recorded as admitted",
     cfg(), request(Q), "admitted", False),
    ("forced-engine", "backend meguvizdexdash is served by the engine and has its own request identity",
     cfg(profile_policy="allow_unadmitted"), request(Q, L, D, I, backend=ENGINE), "available", False),
    ("forced-engine-switched-off", "the rollback value refuses a request for the engine; nothing is substituted",
     cfg("dexsql"), request(Q, backend=ENGINE), "available", False),
    ("forced-engine-bad-sha", "a bad SHA makes the engine unusable; a configured fallback does not serve a forced request",
     cfg(profile_policy="allow_unadmitted", fallback={"to": "dexsql", "on": list(ALL_ON)}),
     request(Q, backend=ENGINE), "bad_sha", False),
    ("auto-bad-sha-no-fallback", "without a configured fallback an unusable engine fails the plan",
     cfg(profile_policy="allow_unadmitted"), request(Q, L), "bad_sha", False),
    ("auto-bad-sha-explicit-fallback", "with the fallback configured the move to dexsql is explicit and recorded",
     cfg(profile_policy="allow_unadmitted", fallback={"to": "dexsql", "on": list(ALL_ON)}), request(Q, L), "bad_sha", False),
    ("auto-bad-sha-fallback-forbidden", "a request can forbid the fallback",
     cfg(profile_policy="allow_unadmitted", fallback={"to": "dexsql", "on": list(ALL_ON)}),
     request(Q, negotiation={"fallback": "forbid"}), "bad_sha", False),
    ("auto-missing-tool-fallback-only-that-task", "a tool the engine lacks is visible in the plan; only that task falls back",
     cfg(profile_policy="allow_unadmitted", fallback={"to": "dexsql", "on": list(ALL_ON)}), request(Q, D), "no_decode_tool", False),
    ("forced-engine-sqlite-dialect", "SQLite-dialect SQL cannot be served by the engine and the plan says so",
     cfg(profile_policy="allow_unadmitted"), request(SQ, backend=ENGINE), "available", False),
    ("forced-engine-reference-sites", "legacy reference sites are not provided by the engine; the plan says so",
     cfg(profile_policy="allow_unadmitted"), request(RS, backend=ENGINE), "available", False),
]


def run_scenario(item, statuses) -> dict:
    name, description, config, req, status_label, expect_frozen = item
    record = {"id": name, "description": description, "native_engine": config.native_engine,
              "fallback": {"to": config.engine.fallback.to, "on": list(config.engine.fallback.on)},
              "profile_policy": config.engine.profile_policy, "engine": status_label, "request": req}
    try:
        planned = provider.plan(req, config, legacy=LEGACY, engine_status=statuses[status_label])
    except ValueError as error:
        record["outcome"] = "refused"
        record["error"] = {"type": type(error).__name__, "code": getattr(error, "code", None),
                           "reason": getattr(error, "reason", None), "message": str(error)}
        return record
    record["outcome"] = "plan"
    record["plan"] = summarize(planned)
    if expect_frozen:
        frozen = LEGACY.plan(req)
        record["identical_to_frozen_planner"] = planned == frozen
    return record


def legacy_equivalence(statuses) -> dict:
    requests = [request(SQ, L, backend="sqlite"), request(Q, L, D, backend="dexsql"), request(Q, SQ), request(L, RS, D),
                request(dict(D, file_id=0)), request(I, backend="dexsql"), request(Q, backend="sqlite"),
                request(RS, backend="dexsql"), request(backend="auto"), request(L, backend="nope")]
    configs = [provider.Config(), cfg("dexsql")]
    same = total = 0
    for req, config, available, hit in itertools.product(requests, configs, (True, False), (True, False)):
        def outcome(call):
            try:
                return ("plan", call())
            except ValueError as error:
                return ("refused", str(error))
        expected = outcome(lambda: LEGACY.plan(req, dexsql_available=available, sqlite_cache_hit=hit))
        actual = outcome(lambda: provider.plan(req, config, legacy=LEGACY, dexsql_available=available,
                                               engine_status=statuses["available"], sqlite_cache_hit=hit))
        total += 1
        same += expected == actual
    return {"oracle": "conformance/corpus/hostlab/source-8782f43/analysis_plan.py", "requests": len(requests),
            "combinations": total, "identical": same,
            "covers": "configs with native_engine=dexsql x dexsql_available x sqlite_cache_hit; refused requests must be refused with the same message"}


def decision_table() -> list:
    config = cfg(profile_policy="allow_unadmitted", fallback={"to": "dexsql", "on": list(ALL_ON)})
    auto = {"id": "t", "backend": ENGINE, "forced": False}
    rows = []
    for code in provider.ENGINE_CODES:
        failure = provider.Failure(code, "engine", "BackendError", "")
        rows.append({
            "code": code,
            "auto_task": provider.decide_fallback(config, {}, auto, failure).to_dict()["action"],
            "forced_task": provider.decide_fallback(config, {}, dict(auto, forced=True), failure).to_dict()["action"],
            "request_forbids": provider.decide_fallback(config, {"fallback": "forbid"}, auto, failure).to_dict()["action"],
            "rows_already_admitted": provider.decide_fallback(config, {}, auto, failure, admitted_rows=1).to_dict()["action"],
        })
    unclassified = provider.Failure("UNCLASSIFIED", "unclassified", "RuntimeError", "")
    rows.append({"code": "UNCLASSIFIED (any other exception)", "auto_task": provider.decide_fallback(config, {}, auto, unclassified).action,
                 "forced_task": "fail", "request_forbids": "fail", "rows_already_admitted": "fail"})
    return rows


def namespace_record(statuses) -> dict:
    config = cfg(profile_policy="allow_unadmitted")
    identity = provider.engine_identity(statuses["available"], config)
    with tempfile.TemporaryDirectory() as raw:
        state = Path(raw).resolve() / "state"
        ns = provider.namespaces(state, identity, config, {})
        legacy = provider.legacy_paths(state.resolve(), {})
        refused = {}
        for label, value in (("the old query cache", "dexq-cache"), ("inside the old reports", "reports/1"),
                             ("HostLab's state directory", "."), ("the completion cache of HostLab", "analysis-schedule")):
            try:
                provider.namespaces(state, identity, cfg(profile_policy="allow_unadmitted", cache_dir=value), {})
                refused[label] = "accepted"
            except provider.NamespaceCollision:
                refused[label] = "refused"
        return {"layout": {name: path.relative_to(state.resolve()).as_posix() for name, path in ns.items()},
                "legacy_paths_never_written": {name: path.relative_to(state.resolve()).as_posix() for name, path in legacy.items()},
                "disjoint": not any(provider._related(a, b) for a in ns.values() for b in legacy.values()),
                "mdd_cache_dir_is": "layout.cache", "engine_dir_from": "build_id + binary_sha256",
                "cache_dir_overrides": refused}


def cache_readers() -> dict:
    hits = sorted(path.relative_to(ROOT).as_posix() for path in (ROOT / "crates").rglob("*.rs")
                  if "MDD_CACHE_DIR" in path.read_text(encoding="utf-8", errors="replace"))
    return {"searched": "crates/**/*.rs", "pattern": "MDD_CACHE_DIR", "files_matching": hits}


def build() -> dict:
    with tempfile.TemporaryDirectory() as raw:
        statuses = engines(Path(raw))
    return {
        "schema": "mdd.hostlab-provider-selection.v1", "task": "MDD-050",
        "about": "How HostLab selects between sqlite, dexsql and meguvizdexdash, what a plan and a report say about the engine, and where fallback is and is not allowed. Produced by integrations/hostlab/make_provider_selection.py; do not edit by hand.",
        "generated_by": {"script": "integrations/hostlab/make_provider_selection.py",
                         "command": "python -I integrations/hostlab/make_provider_selection.py", "check": "... --check",
                         "deterministic": True},
        "engine_identity_source": {
            "kind": "stand-in", "platform": FIXTURE_PLATFORM,
            "note": "hostlab_test_support.FakeEngine answers version/capabilities/mcp, pinned and probed through install_meguvizdexdash.py. The identities below are fixtures, not a real build; test_live_engine.py runs the same code against the real binary."},
        "inputs": {"files": [{"path": path, "sha256": sha256_file(ROOT / path), "bytes": (ROOT / path).stat().st_size}
                             for path in INPUTS]},
        "legacy_equivalence": legacy_equivalence(statuses),
        "scenarios": [run_scenario(item, statuses) for item in SCENARIOS],
        "fallback_policy": {
            "eligible_codes": list(provider.FALLBACK_ELIGIBLE), "engine_codes": list(provider.ENGINE_CODES),
            "rule": "a task that `auto` gave the engine may move to dexsql only for an eligible code, only if the operator enabled that code, the request did not forbid it, the task had produced no rows, and dexsql is available; every other exception reaches HostLab unchanged with its decision attached",
            "decisions": decision_table()},
        "namespaces": namespace_record(statuses),
        "engine_cache_variable": cache_readers(),
        "not_proven": [
            "that HostLab, patched to call provider.py, runs a whole analysis on the new engine: the HostLab repository is not part of this one and no patch was applied or run",
            "that the engine uses MDD_CACHE_DIR: files_matching lists every file under crates/ that mentions it",
            "that any profile of the engine is admitted: every build seen so far reports admitted=false, and the default policy refuses it",
            "any remote dispatch, GitHub Actions run or source-snapshot behaviour: the provider adds no field to a dispatch and was not run against one",
            "performance: nothing here is timed"],
    }


def render(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if the committed record differs from a fresh run")
    args = parser.parse_args(argv)
    text = render(build())
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else None
        if current != text:
            print(f"{OUTPUT.relative_to(ROOT)} is not what the generator produces; run it without --check", file=sys.stderr)
            return 1
        print(f"{OUTPUT.relative_to(ROOT)} is current")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
