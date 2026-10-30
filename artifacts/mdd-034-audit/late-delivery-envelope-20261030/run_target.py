#!/usr/bin/env python3
"""Record a focused real-session late-delivery test, not a profile qualification."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
FILES = [
    "Cargo.lock", "crates/mdd-query/src/executor.rs",
    "crates/mdd-query/src/executor/runtime_tests.rs", "crates/mdd-query/src/budget.rs",
    "crates/mdd-session/src/lib.rs", "crates/mdd-session/src/cancellation.rs",
    "crates/mdd-types/src/result.rs", "tests/fixtures/generated/minimal-035.dex",
]


def source():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in FILES}


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"red", "green"}:
        raise ValueError("expected red or green")
    label = sys.argv[1]
    folder = HERE / label
    folder.mkdir(parents=True, exist_ok=False)
    command = ["cargo", "test", "-p", "mdd-query", "--locked", "--offline", "--jobs", "1",
               "late_delivery_failures_return_coverage_and_computation_envelope", "--", "--nocapture"]
    before = source()
    started = datetime.now(timezone.utc).isoformat()
    result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=300)
    after = source()
    (folder / "stdout.txt").write_bytes(result.stdout)
    (folder / "stderr.txt").write_bytes(result.stderr)
    record = {"command": command, "started_utc": started,
              "finished_utc": datetime.now(timezone.utc).isoformat(),
              "exit_code": result.returncode, "source_before": before, "source_after": after,
              "source_unchanged": before == after,
              "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
              "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
              "scope": "targeted local actual query/queue; no profile or full qualification"}
    (folder / "record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"stage": label, "exit_code": result.returncode, "source_unchanged": before == after}))
    expected = 101 if label == "red" else 0
    if result.returncode != expected or before != after:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
