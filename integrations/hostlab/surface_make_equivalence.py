#!/usr/bin/env python3
"""Make artifacts/mdd-052/surface-equivalence.json: the surface provider run on the real engine against HostLab's own
surface path, every input hashed, every negative control executed. The file is written by this script, never by hand.

  (no flag)  run and write
  --check    run again and require the same file, except for the `observed` block (the engine's build and the timings
             change with the engine's sources and the machine; they are recorded, not compared)

The engine is the built binary: --engine PATH, or MDD_WORKER_BINARY, or target/{release,debug}. It is never skipped.

Usage: python -I integrations/hostlab/surface_make_equivalence.py [--engine PATH] [--check]
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import install_meguvizdexdash as installer  # noqa: E402
import provider as base  # noqa: E402
import surface_gate as gates  # noqa: E402
import surface_make_goldens as goldens  # noqa: E402
import surface_provider as P  # noqa: E402
import surface_support as S  # noqa: E402

SCHEMA = "mdd.hostlab-surface-equivalence.v1"
OUTPUT = S.ROOT / "artifacts/mdd-052/surface-equivalence.json"
IMPLEMENTATION = ("integrations/hostlab/surface_provider.py", "integrations/hostlab/surface_gate.py", "integrations/hostlab/surface_support.py",
                  "integrations/hostlab/surface_make_goldens.py", "integrations/hostlab/surface_make_equivalence.py",
                  "integrations/hostlab/surface_fake_serve.py", "tests/fixtures/surface/generate.py", "tests/fixtures/surface/expected.json",
                  "conformance/hostlab/surface-goldens.json")
NOT_PROVEN = [
    "no real host APK was available or fetched: every result is on the synthetic fixtures of tests/fixtures/surface (5 APKs, 1-2 DEX files each)",
    "HostLab itself was not changed or run: run_surface is not wired into native_audit/analyze, and the real run_intake.py/home_frame_audit.py "
    "gates were not run (they need a host APK); the gate harness was exercised with a stand-in script",
    "no performance claim: no timing is compared, and no saving for sharing facts with the gates is counted (HL-12 is not implemented)",
    "the engine is the unqualified development build: every profile has admitted=false, so the run needs profile_policy=allow_unadmitted",
    "the reference engine was run only to make the golden (local, not in the repository); Linux was not run on this machine (CI covers it)",
    "the 041 container, DEX versions other than 035 and the 128 MiB per-DEX limit are refused as the original refuses them, but only the "
    "refusal of a non-admitted version is exercised on a fixture",
]


def find_binary(explicit: "str | None") -> Path:
    if explicit or os.environ.get("MDD_WORKER_BINARY"):
        return Path(explicit or os.environ["MDD_WORKER_BINARY"])
    name = "meguvizdexdash.exe" if sys.platform == "win32" else "meguvizdexdash"
    found = [S.ROOT / "target" / p / name for p in ("release", "debug") if (S.ROOT / "target" / p / name).is_file()]
    if not found:
        raise SystemExit("the meguvizdexdash binary was not found; build it or pass --engine (this is never skipped)")
    return max(found, key=lambda path: path.stat().st_mtime)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def outcome(call) -> str:
    try:
        call()
    except BaseException as error:  # noqa: BLE001 - the class of the refusal is what is recorded
        return type(error).__name__
    return "no error"


def modified_apk(directory: Path, name: str, edit) -> Path:
    spec = importlib.util.spec_from_file_location("surface_fixture_generator", S.FIXTURES / "generate.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    with zipfile.ZipFile(S.GENERATED / name) as archive:
        members = [[i.filename, archive.read(i), "deflated" if i.compress_type == zipfile.ZIP_DEFLATED else "stored"] for i in archive.infolist()]
    edit(members)
    path = directory / name
    path.write_bytes(module.zip_bytes([tuple(m) for m in members]))
    return path


def build(binary: Path) -> dict:
    golden, expected, host = S.golden(), S.expected(), S.host()
    problems = goldens.check()
    if problems:
        raise SystemExit("the golden is not current: " + "; ".join(problems))
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
        work = Path(directory).resolve()
        manifest = work / "manifest.json"
        entry = installer.pin(binary, manifest)
        config = base.parse_config({"schema": base.CONFIG_SCHEMA, "native_engine": "dexsql", base.ENGINE: {
            "manifest": str(manifest), "profile_policy": "allow_unadmitted"}})
        state = work / "state"
        surface = P.parse_surface_config({"schema": P.CONFIG_SCHEMA, "surface_provider": "meguvizdexdash"})

        def run(name: str, **options):
            with mock.patch.dict(os.environ, {installer.ENV_BINARY: str(binary)}):
                return P.run_surface(S.GENERATED / name, sha256=golden["fixtures"][name]["sha256"], surface=surface, config=config,
                                     host=host, state=state, **options)

        scenarios, timings, reports = {}, {}, {}
        for name, scenario in golden["scenarios"].items():
            legacy = scenario["legacy"]
            began = time.monotonic()
            result = run(name, evidence=True)
            timings[name] = (time.monotonic() - began) * 1000
            reports[name] = result["report"]
            stand_in = S.facts(name)
            offline = P.report_digest(P.build_report(stand_in, host, S.GENERATED / name, backend="meguvizdexdash", workers=1))
            built = {}
            for member, classes in expected["files"][name]["dex"].items():
                for item in classes:
                    if item["expected_family"]:
                        for m in item["methods"]:
                            built[(member, item["descriptor"], m["name"], m["proto"])] = m
            seen = {(m["entry_name"], m["class"], m["name"], m["proto"]): m for m in result["evidence"]["methods"]}
            raw_equal = set(seen) == set(built) and all(
                (seen[k]["body"], seen[k]["insns_sha256"], seen[k]["method_idx"]) == (v["body"], v["insns_sha256"], v["method_idx"])
                for k, v in built.items())
            class_equal = {(r["file_id"], r["class"]): r["method_bodies_sha256"] for r in result["report"]["class_records"]} == {
                (sorted(expected["files"][name]["dex"], key=P.numeric_key).index(member), item["descriptor"]): item["method_bodies_sha256"]
                for member, classes in expected["files"][name]["dex"].items() for item in classes if item["expected_family"]}
            frozen_resources = S.frozen().audit_common.resource_fingerprints(S.GENERATED / name)
            entry_record = {
                "original": {"outcome": legacy["outcome"], "report_sha256": legacy.get("report_sha256"), "exception": legacy.get("type")},
                "engine_report_sha256": result["report_sha256"],
                "stand_in_report_sha256": offline,
                "report_hash_equal_to_original": legacy["outcome"] == "report" and result["report_sha256"] == legacy["report_sha256"],
                "first_difference": (None if legacy["outcome"] != "report" else
                                     P.first_difference({k: v for k, v in result["report"].items() if k not in P.VOLATILE}, legacy["report"])),
                "raw_insns": {"methods_compared": len(built), "bodies": sum(1 for v in built.values() if v["body"] == "present"),
                              "without_body": sum(1 for v in built.values() if v["body"] == "none"), "equal_to_fixture_bytes": raw_equal},
                "class_digests_equal_to_independent_recipe": class_equal,
                "resources": {"members": len(result["report"]["resource_fingerprints"]),
                              "equal_to_original_function": result["report"]["resource_fingerprints"] == frozen_resources,
                              "equal_to_hand_made_hashes": result["report"]["resource_fingerprints"] == expected["files"][name]["resource_sha256"],
                              "duplicate_names": result["evidence"]["resource_duplicates"]},
            }
            scenarios[name] = entry_record
        pairs = {}
        for key, wanted in golden["cross_version"].items():
            before, after = key.split("->")
            got = json.loads(P.canonical_json(P.cross_version(reports[before], reports[after], host, context=golden["context"])))
            pairs[key] = {"equal_to_original": got == wanted, "classifications": sorted({c["kind"] for c in got["changes"]}),
                          "families_changed": [c["family"] for c in got["changes"]], "resource_changes": {k: v for k, v in got["resource_changes"].items() if k != "scope"},
                          "verdict": got["verdict"]}
        controls = negative_controls(work, binary, config, state, host)
        gate_block, gate_observed = gates_stand_in(work)
        observed = {"engine": {"engine_version": entry["engine_version"], "build_id": entry["build_id"], "binary_sha256": entry["sha256"]},
                    "elapsed_ms_per_fixture": {k: round(v, 1) for k, v in timings.items()},
                    "or_chain_of_the_original_filter": engine_on_the_original_chain(binary),
                    "gate_stand_in": gate_observed}
    return {
        "schema": SCHEMA, "task": "MDD-052",
        "about": "The surface provider (integrations/hostlab/surface_provider.py) on the real engine against HostLab's own surface path as the "
                 "reference engine answered it (conformance/hostlab/surface-goldens.json). Made by integrations/hostlab/surface_make_equivalence.py.",
        "inputs": {"implementation": {p: sha256_file(S.ROOT / p) for p in IMPLEMENTATION},
                   "fixtures": golden["fixtures"], "frozen_sources": golden["oracle"]["sources"],
                   "reference_engine": golden["oracle"]["reference_engine"], "rule_sha256": golden["oracle"]["rule_sha256"],
                   "gate_scripts_sha256": gates.pinned_digests()},
        "results": {"scenarios": scenarios, "cross_version": pairs, "negative_controls": controls,
                    "all_report_hashes_equal": all(s["report_hash_equal_to_original"] for s in scenarios.values() if s["original"]["outcome"] == "report"),
                    "all_negative_controls_fail_as_required": all(c["fails_as_required"] for c in controls)},
        "gates": gate_block,
        "rollback": {"switch": "surface_provider (dexsql | meguvizdexdash), independent of native_engine",
                     "default": "dexsql", "store_schema": P.SCHEMA, "store_marker": P.STORE_MARKER},
        "declared_differences": golden["declared_differences"], "not_proven": NOT_PROVEN, "observed": observed,
    }


def negative_controls(work: Path, binary: Path, config, state: Path, host) -> list[dict]:
    golden = S.golden()
    legacy = golden["scenarios"]["base.apk"]["legacy"]
    report = P.build_report(S.facts("base.apk"), host, S.GENERATED / "base.apk", backend="meguvizdexdash", workers=1)
    results = []

    def control(identifier: str, what: str, observed: str, ok: bool) -> None:
        results.append({"id": identifier, "damage": what, "observed": observed, "fails_as_required": ok})

    broken = copy.deepcopy(legacy)
    broken["report_sha256"] = ("0" if broken["report_sha256"][0] != "0" else "1") + broken["report_sha256"][1:]
    difference = goldens_difference(report, broken)
    control("golden-digest", "one hex digit of the golden's report digest changed", str(difference), difference is not None)

    holder = next(m["insns_off"] for item in S.expected()["files"]["base.apk"]["dex"]["classes.dex"] if item["descriptor"] == "Lcom/bilibili/app/comm/comment2/Holder;"
                  for m in item["methods"] if m["name"] == "bind")

    def flip(members):
        data = bytearray(next(m for m in members if m[0] == "classes.dex")[1])
        data[holder] ^= 1
        next(m for m in members if m[0] == "classes.dex")[1] = bytes(data)

    apk = modified_apk(work, "base.apk", flip)
    changed = P.build_report(S.facts("base.apk", apk=apk), host, apk, backend="meguvizdexdash", workers=1)
    difference = goldens_difference(changed, legacy)
    control("changed-byte", "one bit of one method's instructions changed in the DEX member", str(difference),
            bool(difference) and re.match(r"class_records\[\d+\]\.method_bodies_sha256|families\.", difference) is not None)

    def swap(tables):
        rows = tables["dex_files"]
        rows[0][1], rows[1][1] = rows[1][1], rows[0][1]

    control("swapped-names", "the entry names of the two DEX files swapped in the engine's facts",
            outcome(lambda: P.build_report(S.facts("base.apk", swap), host, S.GENERATED / "base.apk", backend="x", workers=1)),
            outcome(lambda: P.build_report(S.facts("base.apk", swap), host, S.GENERATED / "base.apk", backend="x", workers=1)) == "SourceMismatch")
    foreign = outcome(lambda: P.build_report(S.facts("base.apk", apk=S.GENERATED / "target.apk"), host, S.GENERATED / "target.apk", backend="x", workers=1))
    control("foreign-bytes", "the facts of base.apk read with the DEX bytes of target.apk", foreign, foreign == "SourceMismatch")

    class OtherFile(S.FactSession):
        def rows(self, sql, **bounds):
            for row in super().rows(sql, **bounds):
                yield dict(row, file_id="1") if "FROM classes" in sql and "file_id=0" in sql else row

    wrong = outcome(lambda: P.build_report(OtherFile(S.GENERATED / "base.apk", copy.deepcopy(golden["scenarios"]["base.apk"]["relations"])),
                                           host, S.GENERATED / "base.apk", backend="x", workers=1))
    control("row-of-another-file", "rows of file_id 1 answering a question about file_id 0", wrong, wrong == "SourceMismatch")

    class OtherCodeFile(S.FactSession):
        def rows(self, sql, **bounds):
            for row in super().rows(sql, **bounds):
                yield dict(row, file_id="1") if "FROM code_items" in sql and "file_id=0" in sql else row

    wrong_code = outcome(lambda: P.build_report(OtherCodeFile(S.GENERATED / "base.apk", copy.deepcopy(golden["scenarios"]["base.apk"]["relations"])),
                                                host, S.GENERATED / "base.apk", backend="x", workers=1))
    control("code-row-of-another-file", "code_items rows of file_id 1 answering a question about file_id 0", wrong_code, wrong_code == "SourceMismatch")

    deep = "(" * (P.MAX_SQL_DEPTH + 1) + "descriptor LIKE 'L%'" + ")" * (P.MAX_SQL_DEPTH + 1)
    deep_out = outcome(lambda: list(P.per_file(S.facts("base.apk"), [0], "SELECT file_id,class_def_idx,descriptor FROM classes", deep, "class_def_idx")))
    control("condition-too-deep", f"a condition nested {P.MAX_SQL_DEPTH + 1} deep offered to the per-file reader (cap {P.MAX_SQL_DEPTH})", deep_out, deep_out == "SurfaceError")
    terms_out = outcome(lambda: P.balanced_or([f"t{i}" for i in range(P.MAX_OR_TERMS + 1)]))
    control("too-many-or-terms", f"{P.MAX_OR_TERMS + 1} OR terms offered to the balanced-tree builder (cap {P.MAX_OR_TERMS})", terms_out, terms_out == "SurfaceError")
    saving = outcome(lambda: gates.accounting(1.0, [], gate_reuse_benefit_seconds=22.0))
    control("gate-reuse-saving", "a saving for sharing facts with the gates passed to the accounting", saving, saving == "ValueError")
    store = P.SurfaceStore(work / "reports", {"build_id": "b", "binary_sha256": "s", "dialect": {"engine": DIALECT}}, golden["oracle"]["rule_sha256"])
    store.path("a" * 64).write_text(json.dumps(legacy["report"]), encoding="utf-8")
    bare = outcome(lambda: store.load("a" * 64))
    control("bare-legacy-report-in-the-store", "the original path's bare report placed where the new schema's entry belongs", bare, bare == "CacheMismatch")
    with mock.patch.dict(os.environ, {installer.ENV_BINARY: str(binary)}):
        launched = base.launch(config, threads=1, timeout_seconds=60, state=state)
    with P.ServeSession.from_launch(launched, S.GENERATED / "base.apk", dialect=DIALECT, deadline_seconds=60) as session:
        budget = outcome(lambda: session.all("SELECT file_id FROM classes ORDER BY file_id,class_def_idx", max_rows=3))
    control("row-budget", "a result larger than the row budget asked of the real engine", budget, budget == "EngineFailure")
    return results


DIALECT = "dexsql-0.1.0"


def goldens_difference(report, legacy):
    if P.report_digest(report) == legacy["report_sha256"]:
        return None
    stable = json.loads(P.canonical_json({k: v for k, v in report.items() if k not in P.VOLATILE}))
    return P.first_difference(stable, legacy["report"]) or "report_sha256"


def engine_on_the_original_chain(binary: Path) -> dict:
    """Observation, not a claim about the provider: what this build of the engine does with the original filter's chain of ORs."""
    chain = S.frozen().surface.family_filter("descriptor")
    sql = "SELECT file_id,descriptor FROM classes WHERE file_id=0 AND (" + chain + ") ORDER BY file_id,class_def_idx"
    request = json.dumps({"id": "x", "sql": sql}) + "\n" + '{"op":"close"}\n'
    done = subprocess.run([str(binary), "serve", "--input", str(S.GENERATED / "base.apk"), "--dialect", DIALECT], input=request.encode(),
                          capture_output=True, timeout=120)
    return {"statement_terms": chain.count(" OR ") + 1, "exit_status": done.returncode, "answered": b'"kind":"terminal"' in done.stdout}


GATE_PROBE = '''\
import json, os, sys, time
args = sys.argv[1:]
sleep, code = float(args[0]), int(args[1])
print(json.dumps({"argv": args, "cwd": os.getcwd(), "probe": os.environ.get("GATE_PROBE")}))
sys.stderr.write("diagnostic\\n")
time.sleep(sleep)
sys.exit(code)
'''


def gates_stand_in(work: Path) -> "tuple[dict, dict]":
    """Exercise the gate harness with a stand-in script and record what it actually did. HostLab's real run_intake.py and
    home_frame_audit.py are not in this repository and need a host APK, so they are marked not_run with their pinned digests.
    The `scripts_run_unchanged` claim is computed from the two pinned stand-in runs, not asserted; the runs themselves (their
    argv, timings and output digests depend on the temporary directory and the machine) go into the observed block."""
    script = work / "gate.py"
    script.write_text(GATE_PROBE, encoding="utf-8", newline="\n")
    digest = gates.sha256_file(script)
    runs = [gates.run_gate(name, [sys.executable, "-I", str(script), "0.05", "0"], script=script,
                           expected_script_sha256=digest, log_dir=work / "gate-logs") for name in ("intake", "home")]
    block = {
        "run_by": "integrations/hostlab/surface_gate.py",
        "real_scripts": {"status": "not_run",
                         "reason": "run_intake.py and home_frame_audit.py are not in this repository and need a real host APK; "
                                   "their pinned digests are recorded under inputs.gate_scripts_sha256",
                         "pinned_sha256": gates.pinned_digests()},
        "stand_in_script_sha256": digest,
        "stand_in_runs": len(runs),
        "scripts_run_unchanged": len(runs) == 2 and all(r.script_sha256 == digest for r in runs),
        "scripts_run_unchanged_scope": "the two stand-in runs recorded under observed.gate_stand_in; the real gate scripts were not run",
        "all_stand_in_gates_accepted": all(r.accepted() for r in runs),
        "timed": "from before the start to after the end, output read",
        "reuse_benefit_seconds_counted": 0.0,
        "reuse_status": "not_implemented (HL-12)",
        "accounting_refuses_a_saving": outcome(lambda: gates.accounting(1.0, [], gate_reuse_benefit_seconds=1.0)) == "ValueError",
    }
    observed = {"gate_stand_in_runs": [r.record() for r in runs], "gate_stand_in_accounting": gates.accounting(0.0, runs)}
    return block, observed


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--engine")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    document = build(find_binary(args.engine))
    text = json.dumps(document, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
    if args.check:
        current = json.loads(OUTPUT.read_text(encoding="utf-8")) if OUTPUT.exists() else None
        same = current is not None and {k: v for k, v in current.items() if k != "observed"} == {k: v for k, v in document.items() if k != "observed"}
        if not same and current is not None:
            for key in document:
                if key != "observed" and current.get(key) != document[key]:
                    print("differs:", key, file=sys.stderr)
        print("surface equivalence is current" if same else "surface equivalence is NOT current; run surface_make_equivalence.py")
        return 0 if same else 1
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUTPUT.relative_to(S.ROOT)} ({len(text)} bytes)")
    return 0 if document["results"]["all_report_hashes_equal"] and document["results"]["all_negative_controls_fail_as_required"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
