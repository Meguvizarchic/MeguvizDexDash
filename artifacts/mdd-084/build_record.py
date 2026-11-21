#!/usr/bin/env python3
"""Write artifacts/mdd-084/or-chain-overflow.json from the runs that stand behind it.

What it records: the crash reproduction before the fix (repro-pre.json, captured once from the unfixed build and kept) and
after it (repro-post.json, rerun here against the current build), the unit tests of the two crates the fix touches, and
whether a mutation result is committed and current. Nothing in the record is typed by hand.

Usage: python -I artifacts/mdd-084/build_record.py [--check]
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
sys.path.insert(0, str(ROOT / "tools"))
import mutation_harness as H  # noqa: E402

RECORD = "artifacts/mdd-084/or-chain-overflow.json"
MUTATION = "artifacts/mdd-084/mutation/results.txt"
BINARY = "target/debug/meguvizdexdash" + (".exe" if sys.platform == "win32" else "")
SOURCES = [
    "crates/mdd-query/src/operators/mod.rs",
    "crates/mdd-query/src/executor/tests.rs",
    "crates/mdd-sql/src/dialects/ast.rs",
    "crates/mdd-sql/src/dialects/ast/binding.rs",
    "crates/mdd-sql/src/dialects/ast/affinity.rs",
    "crates/mdd-sql/src/dialects/ast/compound.rs",
    "crates/mdd-sql/src/dialects/ast/rewrite.rs",
    "crates/mdd-sql/src/dialects/ast/validate.rs",
    "artifacts/mdd-084/repro_or_chain_overflow.py",
    "artifacts/mdd-084/repro-pre.json",
    "artifacts/mdd-084/mutation/mutate_or_chain.py",
    ".github/workflows/mutation-or-chain.yml",
]


def sha256(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def run(command: list[str]) -> tuple[int, str]:
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    return done.returncode, done.stdout + "\n" + done.stderr


def mutation_summary() -> dict:
    path = ROOT / MUTATION
    if not path.is_file():
        return {"file": MUTATION, "present": False, "current": False,
                "status": "not run yet: it runs in .github/workflows/mutation-or-chain.yml on request; no result is claimed",
                "script": "artifacts/mdd-084/mutation/mutate_or_chain.py"}
    lines = path.read_text(encoding="utf-8").splitlines()
    recorded = [line.split(":", 1)[1].strip() for line in lines if line.startswith("sources sha256:")]
    spec = importlib.util.spec_from_file_location("mutate_or_chain", ROOT / "artifacts/mdd-084/mutation/mutate_or_chain.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return {"file": MUTATION, "script": "artifacts/mdd-084/mutation/mutate_or_chain.py", "present": True,
            "current": recorded == [module.base.sources_sha256()],
            "killed": sum(1 for line in lines if line.startswith("KILLED")),
            "survived": [line[len("SURVIVED"):].strip() for line in lines if line.startswith("SURVIVED")],
            "errors": sum(1 for line in lines if line.startswith(("ERROR", "TIMEOUT"))),
            "skipped": sum(1 for line in lines if line.startswith("SKIPPED")),
            "restored_tree_passes": any("passes the unit and process tests, the replays and their controls: True" in line for line in lines)}


def check(strict_provenance: bool = False) -> int:
    spec = importlib.util.spec_from_file_location("mutate_or_chain", ROOT / "artifacts/mdd-084/mutation/mutate_or_chain.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    issues = H.check_evidence(RECORD, module.SUITE, MUTATION, "artifacts/mdd-084/mutation/mutate_or_chain.py", strict_provenance=strict_provenance)
    record = json.loads((ROOT / RECORD).read_text(encoding="utf-8"))
    if any(t.get("failed", 1) != 0 for t in record.get("tests", {}).values()):
        issues.append("RECORD_TESTS_FAILED")
    after_cases = record.get("reproduction", {}).get("after", {}).get("cases", {})
    if not after_cases or any(c.get("stack_overflow") for c in after_cases.values()):
        issues.append("REPRO_AFTER_STACK_OVERFLOW")
    for path in issues:
        print("CHECK_FAIL:", path)
    print("committed record current:", not issues)
    return 1 if issues else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--strict-provenance", action="store_true")
    args = parser.parse_args()
    if args.check:
        return check(strict_provenance=args.strict_provenance)

    post_path = "artifacts/mdd-084/repro-post.json"
    code, text = run([sys.executable, "-I", "artifacts/mdd-084/repro_or_chain_overflow.py", "--binary", BINARY, "--phase", "post", "--out", post_path])
    if code != 0:
        print(text)
        raise SystemExit("the crash reproduction does not pass against the current build")
    pre = json.loads((ROOT / "artifacts/mdd-084/repro-pre.json").read_text(encoding="utf-8"))
    post = json.loads((ROOT / post_path).read_text(encoding="utf-8"))

    tests = {}
    for crate in ("mdd-query", "mdd-sql"):
        code, text = run(["cargo", "test", "--offline", "--locked", "-p", crate, "--lib"])
        passed = sum(int(n) for n in re.findall(r"test result: ok\. (\d+) passed", text))
        failed = sum(int(n) for n in re.findall(r"(\d+) failed", text))
        tests[crate] = {"exit_code": code, "passed": passed, "failed": failed}
        if code != 0:
            print(text[-2000:])
            raise SystemExit(f"the tests of {crate} fail")

    def summary(evidence: dict) -> dict:
        return {name: {"exit_code": case["exit_code"], "stack_overflow": case["stack_overflow"],
                       "operation_status": (case["terminal"] or {}).get("operation_status"),
                       "error_code": (case["terminal"] or {}).get("error_code"),
                       "error_message": (case["terminal"] or {}).get("error_message")}
                for name, case in evidence["cases"].items()}

    mutation = mutation_summary()
    record = {
        "schema_version": "mdd.or-chain-overflow.v1",
        "task": "MDD-084",
        "status": "fixed: the cases that crashed the process are evaluated, and a chain beyond the limits is refused with a structured error",
        "kind": "development evidence; admits no profile",
        "defect": "a SQL statement with ten nested parentheses of OR/LIKE, or a flat OR of twenty terms, ended the process with a stack overflow "
                  "(0xC00000FD on Windows) in a debug build: the predicate evaluator recursed through one large frame per level and the SQL rewrite recursed on the caller's stack",
        "fix": {
            "evaluator": "crates/mdd-query/src/operators/mod.rs: `predicate` recurses through a small frame (`predicate_at`), the evaluation of a leaf is a separate function that is never inlined into it; "
                         "a predicate deeper than 64 is refused with PREDICATE_DEPTH_LIMIT by the evaluator as well as by validation. Steps are charged as before: one per node, parent first, left before right, no short-circuit.",
            "reference_like": "the reference-dialect LIKE matcher keeps its backtracking on the heap instead of recursing once per pattern token, with the same charge per state",
            "rewrite": "crates/mdd-sql/src/dialects/ast.rs: the recursive SQL rewrite runs on a 16 MiB thread and its depth is capped at 64 (the default `max_ast_depth` is 48), beyond which it refuses with QUOTA_EXCEEDED / SQL_AST_NODE_OR_DEPTH; "
                       "a thread that cannot start or that panics is an INTERNAL_FAULT, never an empty success",
        },
        "reproduction": {
            "script": "artifacts/mdd-084/repro_or_chain_overflow.py",
            "before": {"binary_sha256": pre["binary_sha256"], "cases": summary(pre)},
            "after": {"binary_sha256": post["binary_sha256"], "cases": summary(post)},
        },
        "tests": tests,
        "mutation_check": mutation,
        "inputs_sha256": {path: sha256(path) for path in SOURCES},
        "residual": [
            "the reproduction and the unit tests ran on one Windows host in a debug build; Linux is covered by the repository CI, and a release build was not run",
            "the integration layer of MDD-052 keeps its own hard limit on the OR terms and the nesting depth (DIFF-5); relaxing it is a separate change after this fix is merged, as the task says",
            "a statement between 48 and 64 levels of nesting is admitted only if `max_ast_depth` is raised; the default of 48 is unchanged",
            "the mutation check runs in .github/workflows/mutation-or-chain.yml, not on a developer machine",
        ],
        "run": {"finished_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
    }
    (ROOT / RECORD).write_text(json.dumps(record, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {RECORD}; tests {tests}; mutation present={mutation['present']} current={mutation['current']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
