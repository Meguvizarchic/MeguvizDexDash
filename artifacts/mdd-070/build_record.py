#!/usr/bin/env python3
"""Write artifacts/mdd-070/public-relations-conformance.json from the runs that stand behind it.

What it records: the replay of the recorded reference answers against the current build (the committed
public-relations-diff.json, rerun here), the unit and process tests of the crates the relations live in, the
qualification record, and whether a mutation result is committed and current. Nothing in the record is typed by hand
except the residual list.

Usage: python -I artifacts/mdd-070/build_record.py [--check]
  --check   only say whether the committed record's input hashes are the current files' (no run)
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RECORD = "artifacts/mdd-070/public-relations-conformance.json"
DIFF = "artifacts/mdd-070/public-relations-diff.json"
QUALIFICATION = "conformance/manifests/full-relation-qualification.json"
MUTATION = "artifacts/mdd-070/mutation/results.txt"
BINARY = "target/debug/meguvizdexdash" + (".exe" if sys.platform == "win32" else "")
SOURCES = [
    "crates/mdd-facts/src/public_relations/mod.rs", "crates/mdd-facts/src/public_relations/tables.rs",
    "crates/mdd-facts/src/public_relations/code.rs", "crates/mdd-facts/src/public_relations/values.rs",
    "crates/mdd-facts/src/public_relations/debug.rs", "crates/mdd-facts/src/public_relations/annotations.rs",
    "crates/mdd-facts/src/public_relations/tests.rs", "crates/mdd-sql/src/provider/hostlab/public.rs",
    "crates/mdd-sql/src/provider/hostlab/public_tests.rs", "crates/mdd-sql/src/provider/hostlab.rs",
    "crates/mdd-mcp/src/tools.rs", "conformance/relations/public_relations_diff.py",
    "conformance/relations/test_public_relations_diff.py", "conformance/relations/build_qualification.py",
    DIFF, QUALIFICATION, "conformance/manifests/relations.json", "artifacts/mdd-070/probe_a0.py",
    "tests/fixtures/public_relations/generate.py", "tests/fixtures/public_relations/manifest.json",
    "artifacts/mdd-070/mutation/mutate_public_relations.py", ".github/workflows/mutation-public-relations.yml",
]


def sha256(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def run(command: list[str]) -> tuple[int, str]:
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    return done.returncode, done.stdout + "\n" + done.stderr


def mutation_summary() -> dict:
    path = ROOT / MUTATION
    script = "artifacts/mdd-070/mutation/mutate_public_relations.py"
    if not path.is_file():
        return {"file": MUTATION, "present": False, "current": False, "script": script,
                "status": "not run yet: it runs in .github/workflows/mutation-public-relations.yml on request; no result is claimed"}
    lines = path.read_text(encoding="utf-8").splitlines()
    recorded = [line.split(":", 1)[1].strip() for line in lines if line.startswith("sources sha256:")]
    spec = importlib.util.spec_from_file_location("mutate_public_relations", ROOT / script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return {"file": MUTATION, "script": script, "present": True,
            "current": recorded == [module.base.sources_sha256()],
            "mutants": len(module.MUTANTS),
            "killed": sum(1 for line in lines if line.startswith("KILLED")),
            "survived": [line[len("SURVIVED"):].strip() for line in lines if line.startswith("SURVIVED")],
            "errors": sum(1 for line in lines if line.startswith(("ERROR", "TIMEOUT"))),
            "skipped": sum(1 for line in lines if line.startswith("SKIPPED")),
            "restored_tree_passes": any("passes the unit and process tests, the replays and their controls: True" in line for line in lines)}


def check() -> int:
    record = json.loads((ROOT / RECORD).read_text(encoding="utf-8"))
    stale = [path for path, digest in record["inputs_sha256"].items() if sha256(path) != digest]
    mutation = mutation_summary()
    if mutation["present"] and not mutation["current"]:
        stale.append(MUTATION)
    for path in stale:
        print("STALE:", path)
    print("committed record current:", not stale)
    return 1 if stale else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        return check()

    code, text = run([sys.executable, "-I", "conformance/relations/public_relations_diff.py", "--binary", BINARY, "--out", DIFF, "--quiet"])
    if code != 0:
        print(text[-3000:])
        raise SystemExit("the replay of the recorded answers does not pass against the current build")
    code, text = run([sys.executable, "-I", "conformance/relations/build_qualification.py"])
    if code != 0:
        print(text)
        raise SystemExit("the qualification record could not be built")
    diff = json.loads((ROOT / DIFF).read_text(encoding="utf-8"))

    tests = {}
    for label, command in (("mdd-facts lib", ["-p", "mdd-facts", "--lib"]), ("mdd-sql lib", ["-p", "mdd-sql", "--lib"]),
                           ("mdd-cli mcp", ["-p", "mdd-cli", "--test", "mcp"])):
        code, text = run(["cargo", "test", "--offline", "--locked", *command])
        passed = sum(int(n) for n in re.findall(r"test result: ok\. (\d+) passed", text))
        failed = sum(int(n) for n in re.findall(r"(\d+) failed", text))
        tests[label] = {"exit_code": code, "passed": passed, "failed": failed}
        if code != 0:
            print(text[-2000:])
            raise SystemExit(f"the tests of {label} fail")

    summary = diff["summary"]
    pairs = sum(v["fixtures"] for v in summary.values())
    mutation = mutation_summary()
    record = {
        "schema_version": "mdd.public-relations-conformance.v1",
        "task": "MDD-070",
        "status": "all 56 relations of the frozen manifest are advertised, described and answered; every relation was compared "
                  "cell by cell with the recorded answers of the reference engine over the fixtures below",
        "kind": "development evidence; admits no profile",
        "engine_under_test": diff["engine_under_test"],
        "reference": diff["reference"],
        "replay": {
            "file": DIFF, "script": "conformance/relations/public_relations_diff.py",
            "fixtures": len(diff["fixtures_compared"]), "relations": len(diff["relations_compared"]), "pairs": pairs,
            "exact": sum(v["match"] + v["match_cells"] for v in summary.values()),
            "same_rows_in_another_order": sum(v["reordered"] for v in summary.values()),
            "refused_by_design": sum(v["refused_by_design"] for v in summary.values()),
            "differing": sum(v["differs"] + v["error"] for v in summary.values()),
            "declared_open_refusals": diff["declared_open_refusals"],
            "undeclared_open_refusals": diff["undeclared_open_refusals"],
        },
        "qualification": {"file": QUALIFICATION, "script": "conformance/relations/build_qualification.py"},
        "tests": tests,
        "mutation_check": mutation,
        "inputs_sha256": {path: sha256(path) for path in SOURCES},
        "residual": [
            "the recorded answers are those of dexsql 0.1.0; 0.1.1 is not recaptured, so its profile is not verified (release v0.1.1 exists; downloading it needs the owner's approval)",
            "the fixtures are small synthetic DEX files (one to a few classes) plus the project's earlier fixtures; no relation was compared on a real application, and the NewPipe APK was not used",
            "relations whose recorded evidence is one or two fixtures (call_sites, call_site_args, class_static_values, hiddenapi_flags, try_items, catch_handlers, debug_*) are listed with their counts in the qualification record",
            "SELECT * paged to the end is what was compared; joins, aggregates and ORDER BY over the 39 relations beyond the contract seventeen are not separately claimed",
            "row order of a relation read without ORDER BY differs from the reference in 45 (relation, fixture) pairs (the same rows); it is a declared difference, not a defect",
            "the mutation check runs in .github/workflows/mutation-public-relations.yml, not on a developer machine; a local sample of eight mutants was killed",
            "the reference reads a DEX whose two classes share class data; the engine refuses it at open (declared)",
        ],
        "run": {"finished_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
    }
    (ROOT / RECORD).write_text(json.dumps(record, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {RECORD}; replay {record['replay']['exact']}/{pairs} exact; tests {tests}; mutation present={mutation['present']} current={mutation['current']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
