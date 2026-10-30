#!/usr/bin/env python3
"""Record a targeted bound-queue red/green run, never a qualification."""
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
FILES = ("Cargo.lock", "crates/mdd-query/src/budget.rs",
         "crates/mdd-query/src/budget/tests.rs", "crates/mdd-query/src/executor/runtime_tests.rs")


def hashes():
    return {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in FILES}


def main():
    phases = ("red", "red2", "green", "green2", "final-bound", "final-unbound", "race-red",
              "race-green", "race-regression", "race-unbound", "reserved-red", "reserved-green", "reserved-green2",
              "execute-regression", "reserved-final-bound", "reserved-final-unbound", "reserved-receipt",
              "producer-red", "producer-green", "producer-drop", "producer-zero", "producer-multi",
              "producer-cancel", "producer-binding", "producer-quota", "producer-public", "producer-unbound",
              "producer-race-final", "producer-reserved", "producer-postcancel")
    if len(sys.argv) != 2 or sys.argv[1] not in phases:
        raise ValueError("expected a registered test phase")
    folder = HERE / sys.argv[1]
    folder.mkdir(parents=True, exist_ok=False)
    producer_cases = {
        "producer-drop": "producer_lease_drop_and_external_error_preserve_first_terminal",
        "producer-zero": "execute_into_zero_row_still_requires_end_and_receipt",
        "producer-multi": "queue_with_real_backpressure_completes_only_after_consumer_end",
        "producer-cancel": "native_cancel_after_prefix_isolated_from_sibling_and_computed_spool_retained",
        "producer-binding": "wrong_terminal_binding_does_not_poison_or_claim_the_original_queue",
        "producer-quota": "execute_into_reserved_queue_quota_keeps_pending_delivery_error",
        "producer-public": "executor::runtime_tests::bound_sender_",
        "producer-unbound": "unbound_sender_quota_remains_recoverable",
        "producer-postcancel": "worker_loss_and_cancel_before_final_receipt_are_not_success",
    }
    if sys.argv[1] == "producer-race-final":
        selected = "execute_into_counting_cannot_race_external_successful_end"
    elif sys.argv[1] == "producer-reserved":
        selected = "bound_reserved_sender_in_flight_failure_cannot_race_successful_end"
    elif sys.argv[1] in producer_cases:
        selected = producer_cases[sys.argv[1]]
    elif sys.argv[1] in ("producer-red", "producer-green"):
        selected = "execute_into_counting_cannot_race_external_successful_end"
    elif sys.argv[1] == "reserved-receipt":
        selected = "error_receipt_requires_every_original_error_field"
    elif sys.argv[1] == "execute-regression":
        selected = "execute_into_reserved_queue_quota_keeps_pending_delivery_error"
    elif sys.argv[1] in ("reserved-red", "reserved-green", "reserved-green2"):
        selected = "bound_reserved_sender_in_flight_failure_cannot_race_successful_end"
    elif sys.argv[1] in ("race-red", "race-green"):
        selected = "bound_sender_in_flight_failure_cannot_race_successful_end"
    elif sys.argv[1] in ("final-bound", "race-regression", "reserved-final-bound"):
        selected = "executor::runtime_tests::bound_sender_"
    elif sys.argv[1] in ("final-unbound", "race-unbound", "reserved-final-unbound"):
        selected = "unbound_sender_quota_remains_recoverable"
    else:
        selected = ("bound_sender_cannot_mark_success_after_oversized_send"
                    if sys.argv[1].endswith("2") else
                    "bound_sender_quota_is_sticky_and_cannot_be_finished_as_success")
    command = ["cargo", "test", "-p", "mdd-query", "--locked", "--offline", "--jobs", "1",
               selected, "--", "--nocapture"]
    before = hashes()
    start = datetime.now(timezone.utc).isoformat()
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=300)
    after = hashes()
    (folder / "stdout.txt").write_bytes(result.stdout)
    (folder / "stderr.txt").write_bytes(result.stderr)
    record = {"command": command, "started_utc": start,
              "finished_utc": datetime.now(timezone.utc).isoformat(), "exit_code": result.returncode,
              "source_before": before, "source_after": after, "source_unchanged": before == after,
              "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
              "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
              "scope": "targeted local queue test; no worker or profile qualification"}
    (folder / "record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    expected = result.returncode != 0 if sys.argv[1].startswith("red") or sys.argv[1] in ("race-red", "reserved-red", "producer-red") else result.returncode == 0
    if not expected or before != after:
        raise RuntimeError("target outcome or source identity differs")
    print(json.dumps({"phase": sys.argv[1], "exit_code": result.returncode, "source_unchanged": True}))


if __name__ == "__main__":
    main()
