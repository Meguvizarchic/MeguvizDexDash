#!/usr/bin/env python3
"""Record focused delivery regressions; this is not full qualification."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
FILES = [
    "Cargo.lock", "crates/mdd-query/src/executor.rs",
    "crates/mdd-query/src/executor/runtime_tests.rs", "crates/mdd-query/src/budget.rs",
    "crates/mdd-session/src/lib.rs", "crates/mdd-session/src/cancellation.rs",
    "crates/mdd-types/src/result.rs", "tests/fixtures/generated/minimal-035.dex",
]
CASES = [
    "failed_receipt_cleanup_preserves_producer_error_after_query_release",
    "inconsistent_terminal_count_never_fabricates_an_envelope",
    "receipt_cannot_confirm_another_query",
    "execute_into_zero_row_still_requires_end_and_receipt",
    "queued_rows_are_not_delivery_without_consumer_acknowledgement",
    "delivery_receipt_does_not_succeed_after_query_budget_deadline",
    "delivery_receipt_preserves_existing_failure_after_budget_deadline",
    "worker_loss_and_cancel_before_final_receipt_are_not_success",
    "error_receipt_requires_every_original_error_field",
    "nonpristine_terminal_is_rejected_before_queue_claim",
]


def source():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in FILES}


def main():
    expected = source()
    base = HERE / "regressions"
    base.mkdir(parents=True, exist_ok=False)
    for name in CASES:
        folder = base / name
        folder.mkdir()
        command = ["cargo", "test", "-p", "mdd-query", "--locked", "--offline", "--jobs", "1",
                   name, "--", "--nocapture"]
        started = datetime.now(timezone.utc).isoformat()
        result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=300)
        after = source()
        passed = bool(re.search(rb"test result: ok\. 1 passed; 0 failed; 0 ignored;", result.stdout))
        (folder / "stdout.txt").write_bytes(result.stdout)
        (folder / "stderr.txt").write_bytes(result.stderr)
        record = {"command": command, "started_utc": started,
                  "finished_utc": datetime.now(timezone.utc).isoformat(),
                  "exit_code": result.returncode, "one_test_passed": passed, "source_sha256": expected,
                  "source_unchanged": expected == after,
                  "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                  "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
                  "scope": "targeted local query/queue; not full qualification"}
        (folder / "record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"case": name, "exit_code": result.returncode,
                          "source_unchanged": expected == after}), flush=True)
        if result.returncode != 0 or not passed or expected != after:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
