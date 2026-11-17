#!/usr/bin/env python3
"""Regenerate artifacts/mdd-051/structural-equivalence.json (or check that it is current).

    python -I integrations/hostlab/make_structural_equivalence.py            # write it
    python -I integrations/hostlab/make_structural_equivalence.py --check    # exit 1 if the file differs

The record is produced by running HostLab's frozen structural audit (Graph and 27 FEATURE rules, SHA-256 checked) over the
real meguvizdexdash binary, once through B0 and once through B1, for every synthetic input of
conformance/hostlab/structural_worlds.py, and comparing each run item by item with the golden of the reference engine
(conformance/hostlab/structural-goldens.json). It then repeats the comparison with damaged goldens, with changed rules and with
changed sources to show that it can fail. It is not edited by hand.

Needs the built binary (`cargo build -p mdd-cli`) or MDD_WORKER_BINARY; a missing binary is an error, never a skip. The reference
binary is not needed (its answers are in the golden). Everything is hashed: the inputs of this record are listed with their SHA-256
and `--check` compares everything except `volatile`, the identity of the binary and run-dependent ids, which change with every
build of the engine and are recorded for the reader, not for the comparison.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import native_session as ns  # noqa: E402
import provider  # noqa: E402
import structural_compare as compare  # noqa: E402
import structural_equivalence as eq  # noqa: E402
import structural_frozen as F  # noqa: E402

ROOT = F.ROOT
OUTPUT = ROOT / "artifacts/mdd-051/structural-equivalence.json"
SCHEMA = "mdd.hostlab-structural-equivalence.v1"
INPUTS = (
    "conformance/hostlab/structural-goldens.json", "conformance/hostlab/structural_dex.py", "conformance/hostlab/structural_worlds.py",
    "conformance/hostlab/structural_a0_golden.py", "conformance/hostlab/structural-catalog/analysis/audit_catalog.json",
    "conformance/hostlab/structural-catalog/analysis/HostCompatibilityAudit.java",
    "integrations/hostlab/native_session.py", "integrations/hostlab/structural_provider.py", "integrations/hostlab/structural_compare.py",
    "integrations/hostlab/structural_frozen.py", "integrations/hostlab/structural_equivalence.py",
    "integrations/hostlab/make_structural_equivalence.py", "integrations/hostlab/provider.py",
    "integrations/hostlab/install_meguvizdexdash.py", "conformance/corpus/hostlab/source-8782f43/manifest.json",
    "conformance/corpus/hostlab/source-8782f43/native_graph.py", "conformance/corpus/hostlab/source-8782f43/native_rules.py",
    "conformance/corpus/hostlab/source-8782f43/native_session.py", "conformance/corpus/hostlab/source-8782f43/native_cli.py",
    "conformance/corpus/hostlab/source-8782f43/native_audit.py", "tests/fixtures/query/generated/unicode-order-038.dex",
    "tests/fixtures/generated/invalid-dex-member.apk",
)
LITERALS = ("tv.danmaku", "tv/danmaku", "com.bilibili", "com/bilibili", "com.bapis", "com/bapis", "kntr.", "kntr/", "pegasus",
            "theseus", "gemini", "biligame", "videodetail")


def boundary_scan() -> dict:
    scanned, offenders, holders = 0, [], set()
    features = F.emitted_features()
    for path in sorted((ROOT / "crates").glob("*/src/**/*.rs")):
        relative = path.relative_to(ROOT).as_posix()
        if path.name == "tests.rs" or path.name.endswith("_tests.rs") or "/tests/" in relative:
            continue
        text = path.read_text(encoding="utf-8")
        marker = text.find("\n#[cfg(test)]")
        production = text if marker < 0 else text[:marker]
        scanned += 1
        hits = [token for token in LITERALS if token in production.lower()]
        if hits:
            offenders.append({"file": relative, "literals": hits})
        if any(re.search('"' + feature + '"', production) for feature in features):
            holders.add(relative)
    adapter = {}
    for name in ("native_session.py", "structural_provider.py"):
        text = (HERE / name).read_text(encoding="utf-8").lower()
        adapter[name] = {"application_literals": [t for t in LITERALS + ("bilibili",) if t in text],
                         "feature_names": [f for f in features if re.search(r"(?<![a-z_])" + f + r"(?![a-z_])", text)]}
    return {"core_production_files_scanned": scanned, "core_files_with_application_literals": offenders,
            "core_files_naming_a_feature": sorted(holders), "new_modules": adapter,
            "known_exception": ("crates/mdd-facts/src/hostlab/rules.rs (built before MDD-051) names FEATUREs in a core crate; "
                                "AGENTS.md keeps FEATURE out of the generic core. It is pinned by test_structural_provider.py, "
                                "not endorsed, and is not on the HostLab path this task adds.")}


def world_entry(live, golden, world: str) -> dict:
    wires = {}
    for wire in eq.WIRES:
        got = eq.run_world(live, golden, world, wire)
        wires[wire] = {
            "outcome": got["outcome"], "equal_to_golden": not (got["differences"] or got["audit_differences"] or got["tsv_differences"]),
            "differences": len(got["differences"]), "audit_differences": len(got["audit_differences"]),
            "tsv_differences": len(got["tsv_differences"]), "record_digest": got["record_digest"],
            "tsv_digest": got.get("tsv_digest"), "logical_statements": got["logical_statements"],
            "wire_requests": got["wire_requests"], "queries": got["queries"], "items_compared": got["counts"]}
    return {"input": golden["worlds"][world]["input"], "input_sha256": golden["inputs"][golden["worlds"][world]["input"]]["sha256"],
            "golden_counts": golden["worlds"][world]["counts"],
            "golden_verdicts": _verdicts(golden["worlds"][world]["record"]["features"]), "wires": wires,
            "b0_equals_b1": wires["b0"]["record_digest"] == wires["b1"]["record_digest"]}


def _verdicts(features: dict) -> dict:
    out: dict = {}
    for value in features.values():
        out[value["status"]] = out.get(value["status"], 0) + 1
    return out


def negative_controls(live, golden) -> dict:
    damage = {}
    for world in sorted(golden["worlds"]):
        record = golden["worlds"][world]["record"]
        cases = eq.damages(record)
        results = [eq.detected(record, damaged, prefix)[0] for _, prefix, damaged in cases]
        damage[world] = {"damages": len(cases), "detected": sum(results), "all_detected": all(results)}
    rules = []
    for change in eq.RULE_CHANGES:
        graph, changed = eq.with_changed_rule(live, change)
        for wire in eq.WIRES:
            run = live.record(live.path(change["world"]), wire, rules=changed, graph=graph)
            found = compare.compare(golden["worlds"][change["world"]]["record"], run, limit=400)
            rules.append({"change": change["name"], "world": change["world"], "wire": wire, "module": change["module"],
                          "reported_at": change["reported"], "detected": any(i["path"].startswith(change["reported"]) for i in found),
                          "differences": len(found)})
    return {"damaged_goldens": damage, "changed_rules": rules,
            "the_unchanged_run_has_no_difference": all(
                not (eq.run_world(live, golden, w, "b0")["differences"]) for w in ("partial",))}


def probes(live, golden) -> dict:
    out = {}
    for name, probe in eq.run_probes(live, golden).items():
        out[name] = {"a0": probe["a0"], "b0": probe["wires"]["b0"], "b1": probe["wires"]["b1"],
                     "declared_difference": probe["declared_difference"], "declared_expected": probe.get("declared_expected"),
                     "known_engine_difference": bool(probe["known_engine_difference"]),
                     "b0_as_expected": eq.probe_agreement(probe, "b0"), "b1_as_expected": eq.probe_agreement(probe, "b1")}
    return out


def outcomes(live, golden) -> dict:
    out: dict = {}
    for label, path, kwargs in (
            ("unreadable_facts", live.path("badrefs"), {}),
            ("invalid_dex_member", F.ROOT / "tests/fixtures/generated/invalid-dex-member.apk", {}),
            ("result_budget_exceeded", live.path("full"), {"sql_limits": {"result_rows": 1}}),
            ("wrong_source_digest", live.path("full"), {"sha256": "00" * 32})):
        out[label] = {}
        for wire in eq.WIRES:
            outcome = live.outcome(path, wire, **kwargs)
            record = outcome.record
            out[label][wire] = {"outcome": outcome.outcome, "complete": record["complete"], "features": len(record["features"]),
                                "failure": None if record["failure"] is None else {k: record["failure"][k] for k in ("code", "origin", "type")},
                                "incomplete_reasons": None if record["incomplete"] is None else record["incomplete"]["reasons"],
                                "engine_error_code": None if record["incomplete"] is None else record["incomplete"]["engine_error"]["code"]}
    out["reference_engine_on_unreadable_facts"] = golden["engine_worlds"]["badrefs"]["reference_engine_observation"]
    return out


def build() -> dict:
    golden = eq.load_golden()
    with tempfile.TemporaryDirectory(prefix="mdd051-equivalence-") as directory:
        live = F.Live(directory)
        worlds = {world: world_entry(live, golden, world) for world in sorted(golden["worlds"])}
        identity = eq.run_world(live, golden, "sparse", "b1")
        entry = json.loads(live.manifest.read_text(encoding="utf-8"))["builds"][-1]
        controls = negative_controls(live, golden)
        document = {
            "schema": SCHEMA, "task": "MDD-051",
            "about": ("HostLab's frozen structural audit (Graph, class records, 27 FEATURE rules) run over the "
                      "MeguvizDexDash engine through B0 (HostLab's statements and DTO) and B1 (typed batches), compared item by item "
                      "with the reference engine's golden. Synthetic inputs and a synthetic catalog: no application was analysed."),
            "generated_by": {"script": "integrations/hostlab/make_structural_equivalence.py",
                             "command": "python -I integrations/hostlab/make_structural_equivalence.py", "check": "... --check",
                             "deterministic": "everything outside `volatile`"},
            "inputs": {"files": [{"path": path, "sha256": F.sha256_file(ROOT / path), "bytes": (ROOT / path).stat().st_size} for path in INPUTS],
                       "synthetic_inputs": {name: golden["inputs"][name]["sha256"] for name in sorted(golden["inputs"])}},
            "reference": {"engine": golden["oracle"]["reference_engine"], "driver": golden["oracle"]["driver"],
                          "golden_sha256": F.sha256_file(eq.GOLDEN)},
            "expected_features": golden["expected_features"],
            "summary": {
                "worlds": len(worlds), "runs": len(worlds) * len(eq.WIRES),
                "all_equal_to_golden": all(w["wires"][b]["equal_to_golden"] for w in worlds.values() for b in eq.WIRES),
                "b0_equals_b1_everywhere": all(w["b0_equals_b1"] for w in worlds.values()),
                "items_compared_per_wire": {k: sum(w["golden_counts"][k] for w in worlds.values()) for k in worlds["full"]["golden_counts"]},
                "verdicts": {w: worlds[w]["golden_verdicts"] for w in worlds},
                "b0_wire_requests_are_twice_the_queries": all(
                    worlds[w]["wires"]["b0"]["wire_requests"] == 2 * worlds[w]["wires"]["b0"]["queries"] for w in ("full", "partial", "sparse")),
                "b1_wire_requests_equal_the_queries": all(
                    worlds[w]["wires"]["b1"]["wire_requests"] == worlds[w]["wires"]["b1"]["queries"] for w in ("full", "partial", "sparse"))},
            "worlds": worlds,
            "single_statements": probes(live, golden),
            "outcomes": outcomes(live, golden),
            "negative_controls": controls,
            "boundary": boundary_scan(),
            "wire_changes": list(ns.WIRE_CHANGES),
            "serve_command_template": ns.serve_command("<engine>", ["<input>"], dialect="dexsql-0.1.0", timeout_seconds=900,
                                                      sql_limits={"result_rows": 1000000}),
            "not_proven": [
                "anything about the real application: no APK of it exists here and none was fetched; the catalog is synthetic, so the real catalog's lists, the real class graph and the real counts are untested",
                "HostLab's surface scan (families, protocols, fingerprints): surface_workers.py is not in the frozen corpus and belongs to MDD-052; only the call-count and protocol statements are compared here, as statements",
                "that HostLab itself, patched to import integrations/hostlab/native_session.py, runs unchanged: the HostLab repository is not part of this one and was not run",
                "performance: nothing here is timed; B1 halving the wire requests is a count, not a speed",
                "any profile of the engine is admitted: every build reports admitted=false, recorded in the engine identity",
                "Linux: the run above was made on one Windows host; the CI runs the same tests on Linux",
                "the SQL layer's reading of the integer literal -9223372036854775808 as REAL (a pinned difference from the reference engine in single_statements.int64-min-literal); the audit's statements contain no such literal"],
            "volatile": {
                "note": "changes with every build of the engine or every run; recorded for the reader, not compared by --check",
                "engine": identity["engine"], "dataset": identity["dataset"], "binary_manifest_entry": {k: entry[k] for k in ("engine_version", "build_id", "sha256", "platform")}},
        }
    return document


def render(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def stable(document: dict) -> dict:
    return {key: value for key, value in document.items() if key != "volatile"}


def stale_inputs(document: dict) -> list:
    return [item["path"] for item in document["inputs"]["files"]
            if not (ROOT / item["path"]).is_file() or F.sha256_file(ROOT / item["path"]) != item["sha256"]]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if the committed record differs from a fresh run")
    args = parser.parse_args(argv)
    if args.check:
        if not OUTPUT.exists():
            print(f"{OUTPUT.relative_to(ROOT)} does not exist", file=sys.stderr)
            return 1
        committed = json.loads(OUTPUT.read_text(encoding="utf-8"))
        stale = stale_inputs(committed)
        if stale:
            print("inputs changed since the record was made: " + ", ".join(stale), file=sys.stderr)
            return 1
    document = build()
    if not (document["summary"]["all_equal_to_golden"] and document["summary"]["b0_equals_b1_everywhere"]):
        print("the engine does not reproduce the golden; nothing is written", file=sys.stderr)
        print(json.dumps(document["summary"], indent=2, sort_keys=True), file=sys.stderr)
        return 1
    if args.check:
        if render(stable(document)) != render(stable(committed)):
            fresh, old = stable(document), stable(committed)
            changed = sorted(key for key in set(fresh) | set(old) if fresh.get(key) != old.get(key))
            print(f"{OUTPUT.relative_to(ROOT)} is not what the generator produces (differs in: {', '.join(changed)})", file=sys.stderr)
            return 1
        print(f"{OUTPUT.relative_to(ROOT)} is current")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    text = render(document)
    OUTPUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
