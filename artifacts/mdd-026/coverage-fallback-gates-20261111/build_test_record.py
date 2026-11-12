#!/usr/bin/env python3
"""Record the exact commands and results used to validate the seven fallback
relation gates and the production `for_relations` entry point.

Every row is copied from a command that ran; nothing is synthesised.
"""
import datetime
import hashlib
import json
import pathlib
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

COMMANDS = [
    ("unit_and_integration_tests", ["cargo", "test", "--offline", "-p", "mdd-facts"]),
    (
        "clippy_all_targets",
        [
            "cargo",
            "clippy",
            "--offline",
            "-p",
            "mdd-facts",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    ),
    ("downstream_check", ["cargo", "check", "--offline", "-p", "mdd-query", "-p", "mdd-sql"]),
]

FILES = [
    "crates/mdd-facts/src/coverage.rs",
    "crates/mdd-facts/src/indexes/mod.rs",
    "crates/mdd-facts/src/indexes/tests.rs",
]


def run(argv):
    proc = subprocess.run(
        argv, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    out = proc.stdout.strip().splitlines()
    err = proc.stderr.strip().splitlines()
    return {
        "argv": argv,
        "cwd": str(ROOT),
        "exit_code": proc.returncode,
        "stdout_tail": out[-80:],
        "stderr_tail": err[-15:],
    }


def main():
    record = {
        "schema_version": "mdd.coverage-fallback-gate-test-record.v1",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "task": "MDD-026",
        "offline": True,
        "commands": {},
        "source_sha256": {
            rel: hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() for rel in FILES
        },
        "not_claimed": ["admitted", "task_complete_proven", "profile_issued"],
    }
    failed = []
    for name, argv in COMMANDS:
        result = run(argv)
        record["commands"][name] = result
        if result["exit_code"] != 0:
            failed.append(name)
    record["all_passed"] = not failed
    record["failed_commands"] = failed
    out = HERE / "test-record.json"
    out.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"wrote": str(out), "all_passed": record["all_passed"], "failed": failed}))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
