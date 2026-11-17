#!/usr/bin/env python3
"""Freeze what HostLab's own surface path answers, with the reference engine, into conformance/hostlab/surface-goldens.json.

The frozen `native_cli.CliSession` drives the reference binary (dexsql 0.1.0); the frozen `native_surface.scan` and
`audit_common.resource_fingerprints` run unchanged on it. For every synthetic APK of tests/fixtures/surface the golden
keeps the report (or the exception) of that path, every statement the scan issued with the rows it was given, and the
whole of each relation the scan reads. The cross-version results (`compare`, `resource_changes`, `verdict`) are those of the
frozen functions applied to those reports.

  --a0 PATH   write the golden (needs the reference binary; its SHA-256 is checked and recorded; it is not copied)
  --check     offline: the fixtures and sources are the ones recorded, the recorded statements replayed through the frozen
              scan give the recorded reports, the relations in a relational stand-in give the recorded statements, the
              cross-version results are those of the frozen functions on the recorded reports, and the declared differences
              are the maker's current text
  --declare   offline: refresh only the authored declared_differences block (no reference binary), then check

Usage: python -I integrations/hostlab/surface_make_goldens.py --a0 <dexsql-windows-amd64.exe>
       python -I integrations/hostlab/surface_make_goldens.py --check
       python -I integrations/hostlab/surface_make_goldens.py --declare
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import surface_provider as provider  # noqa: E402
import surface_support as support  # noqa: E402

SCHEMA = "mdd.hostlab-surface-goldens.v1"
A0_SHA256 = "f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448"
FIXTURES = ("base.apk", "target.apk", "plain.apk", "fields-only.apk", "duplicate-resource.apk")
PAIRS = (("base.apk", "target.apk"), ("target.apk", "base.apk"), ("base.apk", "base.apk"))
CONTEXT = {"unmapped_multi_path_candidates": [], "working_tree_dirty": False}
FROZEN_FILES = ("native_surface", "native_cli", "native_session", "native_graph", "analysis_batch", "install_dexsql")
SURFACE_FILES = ("surface_workers", "audit_common", "priority_analysis")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stable(report: dict) -> dict:
    """The report as the original path produced it, without the fields that are about time."""
    return json.loads(provider.canonical_json({k: v for k, v in report.items() if k not in provider.VOLATILE}))


def source_hashes() -> dict:
    corpus = {name: sha256_file(support.FROZEN / f"{name}.py") for name in FROZEN_FILES}
    surface = {name: sha256_file(support.SURFACE_SOURCES / f"{name}.py") for name in SURFACE_FILES}
    return {"conformance/corpus/hostlab/source-8782f43": corpus, "conformance/hostlab/surface-source-8782f43": surface}


def fixture_hashes() -> dict:
    return {name: {"bytes": (support.GENERATED / name).stat().st_size, "sha256": sha256_file(support.GENERATED / name)}
            for name in FIXTURES}


# ---- generation ---------------------------------------------------------------------------------------------

def scenario_with_a0(frozen: "support.Frozen", apk: Path) -> "tuple[dict, dict | None]":
    """The recorded scenario and, if the original produced one, its report as it came (tuples and all)."""
    fresh = None
    with frozen.cli.CliSession(apk, timeout=300, threads=1) as session:
        files = dict(session.files)
        relations = support.record_relations(lambda sql: [[row[k] for k in row] for row in session.rows(sql)])
        recording = support.RecordingSession(session)
        try:
            fresh = frozen.surface.scan(recording)
            fresh["resource_fingerprints"] = frozen.audit_common.resource_fingerprints(apk)
            outcome = {"outcome": "report", "report_sha256": provider.report_digest(fresh), "report": stable(fresh)}
        except BaseException as error:  # noqa: BLE001 - the original's failure is the golden
            outcome = {"outcome": "raised", "type": type(error).__name__, "message": str(error),
                       "resource_fingerprints": frozen.audit_common.resource_fingerprints(apk)}
    scenario = {"files": {str(k): v for k, v in files.items()}, "relations": relations,
                "legacy": dict(outcome, statements=recording.statements)}
    return scenario, fresh


def build(a0: Path) -> dict:
    if sha256_file(a0) != A0_SHA256:
        raise SystemExit(f"{a0} is not the reference binary (SHA-256 {sha256_file(a0)})")
    with tempfile.TemporaryDirectory() as state:
        frozen = support.load_frozen_surface(Path(state), a0)
        made = {name: scenario_with_a0(frozen, support.GENERATED / name) for name in FIXTURES}
        scenarios = {name: pair[0] for name, pair in made.items()}
        golden = assemble(scenarios, frozen)
        # the pairs from the reports as they came must be the ones from the stored (JSON) reports
        for (before, after), key in ((p, f"{p[0]}->{p[1]}") for p in PAIRS):
            if made[before][1] is None or made[after][1] is None:
                continue
            changes = frozen.workers.compare(made[before][1], made[after][1])
            resources = frozen.priority.resource_changes(made[before][1], made[after][1])
            verdict = frozen.priority.verdict(changes, made[after][1], CONTEXT, resources, True)
            direct = json.loads(provider.canonical_json({"changes": changes, "resource_changes": resources, "verdict": verdict}))
            if direct != golden["cross_version"][key]:
                raise SystemExit(f"{key}: the comparison of the stored reports differs from that of the fresh ones")
    return golden


def pair_results(frozen: "support.Frozen", scenarios: dict) -> dict:
    results = {}
    for before, after in PAIRS:
        a, b = scenarios[before]["legacy"], scenarios[after]["legacy"]
        if a["outcome"] != "report" or b["outcome"] != "report":
            continue
        base_report, target_report = restore(a["report"]), restore(b["report"])
        changes = frozen.workers.compare(base_report, target_report)
        resources = frozen.priority.resource_changes(base_report, target_report)
        verdict = frozen.priority.verdict(changes, target_report, CONTEXT, resources, True)
        results[f"{before}->{after}"] = json.loads(provider.canonical_json(
            {"changes": changes, "resource_changes": resources, "verdict": verdict}))
    return results


def restore(report: dict) -> dict:
    return provider.restore_shapes(json.loads(json.dumps(report)))


DECLARED = [
    {"id": "DIFF-1", "scenario": "fields-only.apk",
     "title": "a family class in a DEX file in which no family class has a method",
     "original": "native_surface.scan completes but never sets method_bodies_sha256 and compose_signatures for those classes; "
                 "surface_workers.summarize then raises KeyError",
     "new": "such a class is fingerprinted as a class without methods: SHA-256 of nothing, no Composer signatures",
     "reason": "a crash that depends on which DEX file a class is in is not a behaviour worth keeping; the defined value is the one "
               "the original gives to a method-less class in a DEX file that does have methods"},
    {"id": "DIFF-2", "scenario": None, "title": "rows are checked against the file they were asked for, and bytes against the facts",
     "original": "the scan reads each relation with `WHERE file_id=...` but never re-checks the file_id of the rows it gets back, and "
                 "code_items is selected without its file_id at all; the archive bytes are used without comparing them to the engine's facts",
     "new": "every relation read (classes, class_fields, class_methods, method_calls, code_items) selects file_id and refuses a row of "
            "another file (SourceMismatch); the archive bytes are bound to the engine's recorded header fields (length, version, checksum, "
            "signature) before any offset is used",
     "reason": "a local id is only meaningful with the source it came from. The binding compares the header fields the engine recorded; it "
               "does not recompute adler32 or SHA-1 over the body. Whole-file identity is the APK SHA-256 checked before and after the run, "
               "and the ZIP reader checks each member's CRC"},
    {"id": "DIFF-3", "scenario": None, "title": "one method_idx naming two methods, or two code rows for one method, in one DEX file",
     "original": "the last one silently replaces the first", "new": "refused",
     "reason": "a silent replacement binds a body to the wrong method"},
    {"id": "DIFF-4", "scenario": None, "title": "partial, truncated or errored engine answers",
     "original": "the transport reads the rows it is given until the marker", "new": "admitted only when the stream's terminal line says ok, complete, "
     "untruncated and of the opened snapshot",
     "reason": "an incomplete answer must never be an empty or shorter result"},
    {"id": "DIFF-5", "scenario": None, "title": "the SQL of the family filter",
     "original": "one chain `a OR b OR ...`", "new": "the same condition as a balanced tree of the same predicates (the dynamic-page "
     "test distributed over its three words); the provider refuses more than 64 OR terms, or a statement whose parentheses nest more "
     "than 9 deep (SurfaceError), before sending it",
     "reason": "the debug build of the engine aborts the process with a stack overflow on a chain of 20 terms, or on a condition nested "
               "about ten deep (nine levels are answered, ten are not); the cap keeps every statement sent within what the engine admits"},
    {"id": "DIFF-6", "scenario": None, "title": "scan_execution", "original": "backend dexsql, workers 2",
     "new": "backend meguvizdexdash, workers as run", "reason": "the report says which engine did the work; it is not part of the report digest"},
    {"id": "DIFF-7", "scenario": None, "title": "an archive with two members named like one DEX file of the dataset",
     "original": "zipfile.getinfo keeps the last member of a name; the scan reads it without noticing the earlier one",
     "new": "refused (SourceMismatch) before any of its bytes are used",
     "reason": "physical occurrences are not deduplicated: which member's bytes the facts describe cannot be decided, so the scan refuses "
               "instead of silently choosing the last"},
    {"id": "DIFF-8", "scenario": None, "title": "a file_id naming two DEX files, or two DEX files sharing one entry name",
     "original": "session.files is a dict, so a repeated file_id keeps the last row silently; two equal names fall into the ambiguous-number "
                 "refusal only after the scan has begun",
     "new": "read_identities refuses both (SourceMismatch) before any fact is read",
     "reason": "a local id and a member name must each name exactly one source; the archive is read by name, so a shared name cannot be "
               "bound to one file's facts"},
]


def assemble(scenarios: dict, frozen: "support.Frozen") -> dict:
    return {
        "schema": SCHEMA, "task": "MDD-052",
        "about": "What HostLab's own surface path (the frozen native_surface.scan, native_cli.CliSession and audit_common) answers on "
                 "the reference engine for the synthetic APKs of tests/fixtures/surface; generated by "
                 "integrations/hostlab/surface_make_goldens.py, checked offline with --check.",
        "oracle": {"reference_engine": {"name": "dexsql", "version": "0.1.0", "sha256": A0_SHA256},
                   "commit": "8782f43d537c442905123e35af325c412caa5188", "sources": source_hashes(),
                   "rule_sha256": frozen.workers.RULE_SHA256,
                   "report_identity": "sha256 of the report as sorted-key ASCII JSON without scan_execution and sample"},
        "fixtures": fixture_hashes(), "context": CONTEXT, "scenarios": scenarios,
        "cross_version": pair_results(frozen, scenarios), "declared_differences": DECLARED,
    }


def relations_against_the_fixture(name: str, relations: dict, expected: dict) -> list[str]:
    """Every row of the recorded relations is what the fixture generator built (its hand-derived expectations and the DEX
    bytes), not only what the reference engine said: the two are independent."""
    import zipfile
    problems: list[str] = []
    dex = expected["files"][name]["dex"]
    with zipfile.ZipFile(support.GENERATED / name) as archive:
        raw = {member: archive.read(member) for member in dex}
    members = sorted(dex, key=provider.numeric_key)
    by_file = {}  # the engine's file_id of each member, from dex_files
    for row in relations["dex_files"]:
        by_file[int(row[0])] = row[1]
    got = {(r[1], r[2], r[3], r[4], r[5]) for r in relations["dex_files"]}
    want = set()
    for member, data in raw.items():
        want.add((member, str(len(data)), data[4:7].decode(), str(int.from_bytes(data[8:12], "little")), data[12:32].hex()))
    if got != want or len(relations["dex_files"]) != len(raw):
        problems.append(f"{name}: dex_files differ from the DEX members' headers")
    expectation = {
        "classes": [(m, c["descriptor"]) for m in members for c in dex[m]],
        "class_fields": sorted((m, c["descriptor"], f[0], f[1]) for m in members for c in dex[m] for f in c["fields"]),
        "class_methods": sorted((m, c["descriptor"], str(x["method_idx"]), x["name"], x["proto"]) for m in members for c in dex[m] for x in c["methods"]),
        "code_items": sorted((m, str(x["method_idx"]), str(x["insns_off"]), str(x["insns_units"])) for m in members for c in dex[m]
                             for x in c["methods"] if x["insns_units"] is not None),
        "method_calls": sorted((m, f"{c['descriptor']}->{x['name']}{x['proto']}", callee) for m in members for c in dex[m]
                               for x in c["methods"] for callee in x["calls"]),
    }
    seen = {
        "classes": [(by_file[int(r[0])], r[3]) for r in sorted(relations["classes"], key=lambda r: (int(r[0]), int(r[1])))],
        "class_fields": sorted((by_file[int(r[0])], r[2], r[4], r[5].split(":", 1)[1]) for r in relations["class_fields"]),
        "class_methods": sorted((by_file[int(r[0])], r[2], r[3], r[4], "(" + r[5].split("(", 1)[1]) for r in relations["class_methods"]),
        "code_items": sorted((by_file[int(r[0])], r[1], r[2], r[3]) for r in relations["code_items"]),
        "method_calls": sorted((by_file[int(r[0])], r[3], r[4]) for r in relations["method_calls"]),
    }
    # classes of different files are listed per file in definition order; compare per file
    if sorted(seen["classes"]) != sorted(expectation["classes"]) or [c for c in seen["classes"] if c[0] == members[0]] != [
            c for c in expectation["classes"] if c[0] == members[0]]:
        problems.append(f"{name}: classes differ from what the fixture generator built")
    for key in ("class_fields", "class_methods", "code_items", "method_calls"):
        if seen[key] != expectation[key]:
            problems.append(f"{name}: {key} differ from what the fixture generator built")
    return problems


# ---- the offline check --------------------------------------------------------------------------------------

def check(path: Path = support.GOLDENS) -> list[str]:
    problems: list[str] = []
    golden = json.loads(path.read_text(encoding="utf-8"))
    if golden.get("schema") != SCHEMA:
        return ["not a surface golden"]
    if golden["fixtures"] != fixture_hashes():
        problems.append("the fixtures differ from the ones the golden was made on")
    if golden["oracle"]["sources"] != source_hashes():
        problems.append("the frozen sources differ from the ones recorded")
    with tempfile.TemporaryDirectory() as state:
        frozen = support.load_frozen_surface(Path(state))
    if golden["oracle"]["rule_sha256"] != frozen.workers.RULE_SHA256:
        problems.append("the rule hash differs")
    for name, scenario in golden["scenarios"].items():
        legacy = scenario["legacy"]
        apk = support.GENERATED / name
        files = {int(k): v for k, v in scenario["files"].items()}
        replay = support.ReplaySession(apk, files, legacy["statements"])
        try:
            report = frozen.surface.scan(replay)
            report["resource_fingerprints"] = frozen.audit_common.resource_fingerprints(apk)
            seen = {"outcome": "report", "report_sha256": provider.report_digest(report), "report": stable(report)}
        except BaseException as error:  # noqa: BLE001
            seen = {"outcome": "raised", "type": type(error).__name__, "message": str(error)}
        for key, value in seen.items():
            if legacy.get(key) != value:
                problems.append(f"{name}: replaying the recorded statements through the frozen scan gives a different {key}")
        if seen["outcome"] == "report" and not replay.finished():
            problems.append(f"{name}: the frozen scan did not consume every recorded statement")
        if legacy["outcome"] == "raised" and legacy["resource_fingerprints"] != frozen.audit_common.resource_fingerprints(apk):
            problems.append(f"{name}: the recorded resource fingerprints differ from the frozen function's")
        problems += relations_against_the_fixture(name, scenario["relations"], support.expected())
        stand_in = support.FactSession(apk, scenario["relations"], files)
        if seen["outcome"] == "report":
            try:
                again = frozen.surface.scan(stand_in)
            except BaseException as error:  # noqa: BLE001
                problems.append(f"{name}: the frozen scan over the stand-in raised {type(error).__name__}")
            else:
                if [(s["sql"], s["rows"]) for s in stand_in.statements] != [(s["sql"], s["rows"]) for s in legacy["statements"]]:
                    problems.append(f"{name}: the relational stand-in answers the scan's statements differently from the reference engine")
                again["resource_fingerprints"] = frozen.audit_common.resource_fingerprints(apk)
                if provider.report_digest(again) != legacy["report_sha256"]:
                    problems.append(f"{name}: the frozen scan over the stand-in gives another report")
    if golden["cross_version"] != pair_results(frozen, golden["scenarios"]):
        problems.append("the cross-version results differ from the frozen functions' on the recorded reports")
    if golden.get("declared_differences") != DECLARED:
        problems.append("the declared differences differ from the maker's current text")
    return problems


def declare(path: Path = support.GOLDENS) -> None:
    """Refresh only the authored `declared_differences` block (documentation of the integration's refusals, not engine output);
    every other byte of the golden stays as the reference engine produced it. Offline; needs no reference binary."""
    golden = json.loads(path.read_text(encoding="utf-8"))
    if golden.get("schema") != SCHEMA:
        raise SystemExit("not a surface golden")
    golden["declared_differences"] = DECLARED
    path.write_text(json.dumps(golden, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--a0", help="the reference binary (dexsql-windows-amd64.exe)")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--declare", action="store_true", help="offline: refresh only the declared_differences block, then check")
    args = parser.parse_args(argv)
    if args.declare:
        declare()
        print(f"refreshed declared_differences in {support.GOLDENS.relative_to(support.ROOT)}")
    if args.check or args.declare:
        problems = check()
        for problem in problems:
            print(problem, file=sys.stderr)
        print("surface goldens are current" if not problems else "surface goldens are NOT current")
        return 1 if problems else 0
    if not args.a0:
        parser.error("--a0 is required unless --check or --declare")
    golden = build(Path(args.a0))
    support.GOLDENS.parent.mkdir(parents=True, exist_ok=True)
    support.GOLDENS.write_text(json.dumps(golden, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {support.GOLDENS.relative_to(support.ROOT)} ({support.GOLDENS.stat().st_size} bytes)")
    problems = check()
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
