#!/usr/bin/env python3
"""Build the current MDD-034 record: budgets, cancellation and terminal states.

Usage: python tools/build_mdd034_evidence.py [--raw-dir DIR]

Runs the library tests of mdd-types, mdd-session, mdd-query and mdd-worker, and
the repository's own runtime check (`conformance/runtime/qualify.py`, which
launches two live SQLite connections and an owned child process), then writes
artifacts/mdd-034/current-conformance.json: every acceptance clause with the
named tests that prove it and their outcome in this run.

`qualify.py` rewrites the historical record artifacts/mdd-034/
budget-and-terminal-states.json with fresh source identities. That file keeps its
2026-10-28 meaning, so this script restores it from git after the run.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL = "artifacts/mdd-034/budget-and-terminal-states.json"
COMMAND = ["cargo", "test", "--offline", "--locked", "-p", "mdd-types", "-p", "mdd-session",
           "-p", "mdd-query", "-p", "mdd-worker", "--lib"]

ACCEPTANCE = [
    ("operation_status, input/facts three-state coverage, execution.complete and more_available/truncated/next_cursor are independently verifiable",
     ["coverage_execution_and_delivery_axes_are_independent_and_protocol_faults_sticky",
      "computed_spool_cancel_page_and_complete_zero_are_independent",
      "complete_result_requires_an_exact_matching_total",
      "exact_total_larger_than_delivered_is_not_complete",
      "blocking_warning_cannot_be_a_complete_result",
      "pristine_builder_rejects_even_a_recorded_zero_row_batch"]),
    ("budget exhaustion and deadlines never return ordinary EOF; an explicit failure terminal follows partial rows and the consumer cannot take it as complete",
     ["part_rows_error_and_eof_never_complete",
      "queue_deadline_has_explicit_error_end_and_no_complete_success",
      "zero_deadline_and_unconsumed_cursor_do_not_become_empty_success",
      "quota_after_rows_has_failure_terminal_and_preserves_real_compute_axis",
      "json_batches_zero_partial_and_limits_never_fake_complete",
      "unbound_terminal_delivered_after_deadline_is_not_success",
      "worker_loss_and_cancel_before_final_receipt_are_not_success",
      "consumer_count_errors_remain_failed_and_do_not_partially_commit"]),
    ("native cancel affects only the target query; SQLite interrupt is isolated per connection; a killed worker visibly fails all its unfinished tasks",
     ["native_cancel_after_prefix_isolated_from_sibling_and_computed_spool_retained",
      "production_queue_native_cancel_is_isolated_from_sibling_and_keeps_partial_failure",
      "in_process_worker_lost_fails_inflight_query_and_is_not_a_fallback_error",
      "producer_drop_after_prefix_is_worker_lost_and_explicit_failure_stays_failure",
      "supervisor_observes_real_process_exit_pipe_close_and_limits"]),
    ("compat_cancel_closes_dataset is declared per profile and verified, never confused with native cancel",
     ["compat_cancel_profile_closes_only_owning_dataset_and_is_distinct_from_native",
      "native_query_cancel_and_explicit_dataset_profile_have_distinct_ownership"]),
    ("only UNAVAILABLE_BACKEND, UNSUPPORTED_CAPABILITY and UNSUPPORTED_QUERY may fall back, under an explicit equivalence policy",
     ["fallback_is_exact_three_code_gate_and_never_replays_partial_or_mutated_work",
      "fallback_whitelist_rejects_real_query_terminal_errors"]),
]


def load_sibling():
    path = ROOT / "tools/build_mdd032_033_evidence.py"
    spec = importlib.util.spec_from_file_location("mdd032_033_evidence", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_qualify() -> dict:
    done = subprocess.run([sys.executable, "-O", "conformance/runtime/qualify.py"], cwd=ROOT,
                          capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    # Keep the historical record as it was; only the stdout summary is evidence here.
    subprocess.run(["git", "checkout", "--", HISTORICAL], cwd=ROOT, check=True)
    summary = None
    for line in done.stdout.strip().splitlines()[::-1]:
        try:
            summary = json.loads(line)
            break
        except ValueError:
            continue
    return {"command": ["python", "-O", "conformance/runtime/qualify.py"], "exit_code": done.returncode,
            "summary": summary}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, default=ROOT / "artifacts/local/mdd-034-runs-20261113")
    args = parser.parse_args()
    sibling = load_sibling()
    sibling.COMMAND = COMMAND
    run = sibling.run_tests(args.raw_dir)
    qualify = run_qualify()
    rows = sibling.acceptance_rows(ACCEPTANCE, run["results"])
    ok = (run["exit_code"] == 0 and qualify["exit_code"] == 0 and qualify["summary"] is not None
          and qualify["summary"].get("status", "").startswith("passed") and all(r["all_passed"] for r in rows))
    document = {
        "schema_version": "mdd.budget-terminal-current.v1",
        "task": "MDD-034",
        "kind": "development evidence; admits no profile",
        "supersedes_nothing": "the 2026-10-28 record artifacts/mdd-034/budget-and-terminal-states.json keeps its historical meaning",
        "acceptance": rows,
        "runtime_check": qualify,
        "residual": [
            "the production worker IPC, framing and cross-process consumption acknowledgement are task MDD-040; here a worker is an in-process producer or an owned child process under the supervisor",
            "budgets are logical, conservative reservations, not allocator or RSS measurements",
            "no profile is admitted and no formal performance run was made",
        ],
        "run": {k: v for k, v in run.items() if k != "results"},
    }
    target = ROOT / "artifacts/mdd-034/current-conformance.json"
    target.write_text(json.dumps(document, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    unproven = [r["acceptance"] for r in rows if not r["all_passed"]]
    print(f"acceptance rows={len(rows)} unproven={len(unproven)} tests: exit={run['exit_code']} "
          f"passed={run['passed']} failed={run['failed']} runtime_check={qualify['summary']}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
