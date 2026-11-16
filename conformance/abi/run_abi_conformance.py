#!/usr/bin/env python3
"""Run the MDD-043 SDK and C ABI conformance and write its record.

Usage: python -I conformance/abi/run_abi_conformance.py [--raw-dir DIR] [--no-write] [--check]

It builds the library, runs the Rust tests of mdd-ffi, the Python SDK tests and the
data-driven ownership cases against the raw ABI, runs the workspace dependency-boundary
check, maps each acceptance clause of MDD-043 to named tests whose outcomes come from
that run, and writes artifacts/mdd-043/sdk-and-abi-conformance.json.

The record covers the in-process C ABI, the Python binding over it and the Python
worker transport (mdd.worker: a `meguvizdexdash serve` process behind the same Batch and
Result types). It admits no profile. Clause 4 of the acceptance names "worker lost": the
ABI itself is in-process and has no worker to lose, so the case is proven on the worker
transport, with the real binary killed mid-stream and a stand-in worker that fails in each
way a worker should not.

The mutation check of this task runs in .github/workflows/mutation-abi.yml (about an hour of
Rust builds is not run on a developer machine). Until its results.txt is committed the
record says the check has not run, and claims nothing.

--check runs nothing: it verifies that the committed record still matches its inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "conformance/abi"))

RECORD = "artifacts/mdd-043/sdk-and-abi-conformance.json"
MUTATION = "artifacts/mdd-043/mutation/results.txt"
# The tests and the sources they test; keep in step with mutate_abi.py.
MUTATION_SOURCES = [
    "crates/mdd-ffi/tests/abi_contract.rs",
    "python/tests/test_sdk.py",
    "python/tests/test_worker.py",
    "python/tests/stub_worker.py",
    "conformance/abi/ownership-cases.json",
    "conformance/abi/ownership_cases.py",
    "include/mdd.h",
    "crates/mdd-ffi/src/abi.rs",
    "crates/mdd-ffi/src/codec.rs",
    "crates/mdd-ffi/src/engine.rs",
    "crates/mdd-ffi/src/error.rs",
    "crates/mdd-ffi/src/handle.rs",
    "python/mdd/_cells.py",
    "python/mdd/_ffi.py",
    "python/mdd/core.py",
    "python/mdd/errors.py",
    "python/mdd/worker.py",
]
INPUTS = ["include/mdd.h", "conformance/abi/ownership-cases.json", "crates/mdd-ffi/Cargo.toml"]

RUST = ["cargo", "test", "--offline", "--locked", "-p", "mdd-ffi"]
# the library, and the worker binary that the SDK's worker transport starts
BUILD = ["cargo", "build", "--offline", "--locked", "-p", "mdd-ffi", "-p", "mdd-cli"]
PYTHON = [sys.executable, "-I", "-m", "unittest", "discover", "-s", "python/tests", "-t", "python", "-v"]
BOUNDARIES = [sys.executable, "-I", "conformance/check-workspace-boundaries.py"]

OWNERSHIP_CASES = "ownership-cases (every data-driven case, through the raw ABI)"

ACCEPTANCE = [
    ("open_snapshot, open_session, prepare_query, start_query, next_batch, cancel_query, close_session and close_snapshot are implemented, with version negotiation",
     ["negotiation_accepts_1_0_and_refuses_other_majors_and_future_minors",
      "capabilities_name_the_profile_as_unadmitted_and_list_what_is_unsupported",
      "a_full_stream_ends_in_a_complete_terminal_with_derived_coverage",
      "cancel_before_the_first_batch_ends_in_a_cancelled_terminal_and_after_the_end_is_accepted",
      "close_is_idempotent_refuses_new_work_and_keeps_what_exists",
      "unsupported_forms_are_refused_by_name_and_not_ignored",
      "the_header_declares_exactly_the_exported_symbols",
      "test_the_library_negotiates_abi_1_0_and_is_not_an_admitted_profile",
      "test_a_future_abi_is_refused_with_the_offered_version"]),
    ("no Rust private layout crosses the ABI; buffers have an explicit owner; double release and old handles cause no undefined access",
     ["the_header_exposes_only_fixed_width_scalars_and_two_plain_structs",
      "double_release_is_a_detected_error_for_every_handle_kind",
      "forged_zero_and_wrong_kind_handles_are_refused_without_touching_anything",
      "a_reused_slot_does_not_answer_to_an_old_handle",
      "null_and_misaligned_pointers_are_refused",
      "a_retained_batch_outlives_its_event_query_session_and_snapshot",
      "a_batch_must_be_released_before_the_next_and_acknowledged_before_the_end",
      OWNERSHIP_CASES]),
    ("Python keeps NULL, exact integers, provenance, duplicates, error codes and the final coverage, and never reads a missing page as an empty list",
     ["cells_keep_null_exact_integers_and_unpaired_surrogates",
      "test_rows_keep_null_exact_integers_unpaired_surrogates_and_duplicates",
      "test_original_mutf8_text_keeps_its_bytes_and_unit_count",
      "test_a_complete_result_carries_its_coverage_and_binds_the_snapshot",
      "test_batches_respect_the_demand_and_are_contiguous",
      "test_a_statement_that_cannot_run_raises_with_the_engine_code_never_an_empty_list",
      "test_a_cancelled_query_raises_and_never_returns_a_short_list",
      "test_a_worker_answers_like_the_in_process_library",
      "test_original_mutf8_text_arrives_with_its_bytes_and_unit_count",
      "test_a_row_limit_is_a_failure_not_a_shorter_result",
      "test_a_result_that_is_not_complete_is_not_returned",
      "test_an_unavailable_layer_is_refused_by_name",
      "test_a_missing_input_is_an_input_error"]),
    ("concurrency, cancellation, GC and explicit close, abnormal exit and worker lost have bounded cleanup evidence",
     ["cancel_from_another_thread_stops_a_running_statement",
      "a_second_consumer_gets_busy_instead_of_waiting",
      "releasing_the_query_handle_while_another_thread_consumes_it_is_safe",
      "a_panic_is_contained_and_reported_as_an_internal_fault",
      "a_panic_inside_a_query_poisons_it_so_the_next_use_fails_instead_of_running_on",
      "a_poisoned_session_list_makes_close_fail_loudly",
      "test_cancel_from_another_thread_stops_a_running_statement",
      "test_parallel_queries_on_one_session_give_identical_complete_results",
      "test_the_session_thread_limit_is_enforced_and_reported_not_queued",
      "test_a_second_consumer_of_one_query_is_told_to_retry_not_blocked",
      "test_leaving_a_with_block_by_exception_cancels_and_releases",
      "test_abandoning_a_generator_midway_leaves_nothing_behind",
      "test_unclosed_objects_are_released_by_the_garbage_collector",
      "test_use_after_close_raises_closed_and_close_is_idempotent",
      "test_closing_the_snapshot_keeps_the_sessions_that_already_exist",
      "test_a_parent_is_not_collected_under_a_live_child",
      # worker lost, on the worker transport
      "test_a_worker_killed_mid_stream_raises_worker_lost_after_the_batches_it_delivered",
      "test_execute_never_returns_when_the_worker_dies_it_raises",
      "test_a_lost_worker_stays_lost_and_says_so_promptly",
      "test_a_worker_that_crashes_before_it_is_open_is_lost",
      "test_a_worker_that_refuses_to_start_is_not_lost",
      "test_a_missing_input_is_refused_not_lost",
      "test_a_worker_that_dies_inside_a_query_is_lost_with_its_exit_code",
      "test_a_worker_that_exits_cleanly_without_a_terminal_is_still_lost",
      "test_a_line_cut_short_is_a_loss_not_a_short_result",
      "test_a_silent_worker_is_ended_at_the_callers_deadline",
      "test_a_line_that_is_not_json_ends_the_worker",
      "test_an_answer_for_another_request_ends_the_worker",
      "test_batches_out_of_order_end_the_worker",
      "test_a_line_over_the_limit_ends_the_worker_without_buffering_it",
      "test_a_peer_that_does_not_speak_the_protocol_is_refused_at_startup",
      "test_a_failure_terminal_raises_after_its_batches",
      "test_close_asks_the_worker_to_end_and_is_idempotent",
      "test_a_worker_that_ignores_close_is_killed_after_the_grace_period",
      "test_leaving_a_with_block_by_exception_ends_the_worker",
      "test_abandoning_a_query_half_way_ends_the_worker_and_says_so",
      "test_a_second_query_while_one_is_open_is_told_busy",
      "test_dropping_a_worker_without_closing_it_reaps_its_process",
      "test_cancel_from_another_thread_ends_the_worker_and_the_waiting_reader_raises",
      "test_a_cancelled_query_raises_cancelled_and_never_returns_a_short_list",
      "test_workers_are_independent"]),
    ("a public fixture is read without importing any HostLab or BIL business package",
     ["test_no_business_package_is_imported_or_named",
      "test_no_business_package_is_imported_or_named_by_the_worker_transport",
      "workspace-boundaries (mdd-ffi depends only on core crates)"]),
]

# Nothing is open. The clause that was ("worker lost") is proven on the worker transport; see the
# last acceptance row. What is not offered is listed under "residual" in the record.
OPEN_CLAUSES: list = []


def sha256(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def sources_sha256() -> str:
    digest = hashlib.sha256()
    for relative in MUTATION_SOURCES:
        digest.update((ROOT / relative).read_bytes())
    return digest.hexdigest()


def run(command: list[str], raw: Path, name: str) -> dict:
    started = datetime.now(timezone.utc).isoformat()
    done = subprocess.run(command, cwd=ROOT, capture_output=True, check=False)
    log = done.stdout + b"\n--- stderr ---\n" + done.stderr
    raw.mkdir(parents=True, exist_ok=True)
    (raw / f"{name}.log").write_bytes(log)
    return {"command": [Path(command[0]).name, *command[1:]], "started_utc": started,
            "exit_code": done.returncode, "log_sha256": hashlib.sha256(log).hexdigest(),
            "text": log.decode("utf-8", "replace")}


def rust_results(text: str) -> dict:
    results: dict[str, list[str]] = {}
    for name, outcome in re.findall(r"^test (\S+) \.\.\. (\w+)", text, re.M):
        results.setdefault(name, []).append(outcome)
    return results


def python_results(text: str) -> dict:
    results: dict[str, list[str]] = {}
    for name, outcome in re.findall(r"^(test\w+) \([\w.]+\) \.\.\. (\w+)", text, re.M):
        results.setdefault(name, []).append(outcome)
    return results


def lookup(results: dict, suffix: str) -> tuple[str, str]:
    hits = [(name, outcomes) for name, outcomes in results.items()
            if name == suffix or name.endswith("::" + suffix)]
    if len(hits) != 1:
        return suffix, "not_run" if not hits else f"ambiguous({len(hits)})"
    name, outcomes = hits[0]
    return (name, outcomes[0]) if len(outcomes) == 1 else (name, f"ambiguous({len(outcomes)})")


def acceptance_rows(results: dict, extra: dict) -> list:
    rows = []
    for statement, names in ACCEPTANCE:
        proofs = []
        for name in names:
            if name in extra:
                proofs.append({"test": name, "outcome": extra[name]})
            else:
                full, outcome = lookup(results, name)
                proofs.append({"test": full, "outcome": outcome})
        rows.append({"acceptance": statement, "tests": proofs,
                     "all_passed": all(p["outcome"] == "ok" for p in proofs)})
    return rows


def mutation_summary() -> dict:
    path = ROOT / MUTATION
    if not path.is_file():
        return {"file": MUTATION, "present": False, "current": False,
                "status": "not run yet: it runs in .github/workflows/mutation-abi.yml on request; no result is claimed",
                "script": "artifacts/mdd-043/mutation/mutate_abi.py",
                "earlier_result": "artifacts/mdd-043/mutation/results-before-worker.txt (11 Rust and 5 Python faults, before the worker transport)"}
    lines = path.read_text(encoding="utf-8").splitlines()
    recorded = [line.split(":", 1)[1].strip() for line in lines if line.startswith("tests sha256:")]
    return {
        "file": MUTATION, "script": "artifacts/mdd-043/mutation/mutate_abi.py", "present": True,
        "current": recorded == [sources_sha256()],
        "killed": sum(1 for line in lines if line.startswith("KILLED")),
        "survived": [line[len("SURVIVED"):].strip() for line in lines if line.startswith("SURVIVED")],
        "errors": sum(1 for line in lines if line.startswith(("ERROR", "TIMEOUT"))),
        "restored_tree_passes": any("restored tree passes every test set: True" in line for line in lines),
    }


def check_committed() -> int:
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
    parser.add_argument("--raw-dir", type=Path, default=ROOT / "artifacts/local/mdd-043-runs")
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        return check_committed()

    import ownership_cases  # noqa: E402  (needs the library, so imported after the build)

    build = run(BUILD, args.raw_dir, "build")
    if build["exit_code"] != 0:
        print("build failed")
        return 1
    rust = run(RUST, args.raw_dir, "rust-tests")
    python = run(PYTHON, args.raw_dir, "python-tests")
    boundaries = run(BOUNDARIES, args.raw_dir, "boundaries")
    cases = ownership_cases.run_all()

    results = {**rust_results(rust["text"]), **python_results(python["text"])}
    extra = {
        OWNERSHIP_CASES: "ok" if cases and all(c["passed"] for c in cases) else "failed",
        "workspace-boundaries (mdd-ffi depends only on core crates)": "ok" if boundaries["exit_code"] == 0 else "failed",
    }
    rows = acceptance_rows(results, extra)
    mutation = mutation_summary()
    header = (ROOT / "include/mdd.h").read_text(encoding="utf-8")
    totals = lambda r: re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed", r["text"])  # noqa: E731
    python_ran = re.search(r"^Ran (\d+) tests", python["text"], re.M)
    record = {
        "schema_version": "mdd.sdk-and-abi-conformance.v1",
        "task": "MDD-043",
        "kind": "development evidence for the in-process C ABI and its Python binding; admits no profile",
        "abi": {"major": 1, "minor": 0, "header": "include/mdd.h",
                "exported_symbols": len(re.findall(r"^uint32_t mdd_", header, re.M))},
        "acceptance": rows,
        "open_clauses": OPEN_CLAUSES,
        "ownership_cases": [{k: c[k] for k in ("id", "why", "ops", "passed")} for c in cases],
        "tests": {
            "rust": {"exit_code": rust["exit_code"], "passed": sum(int(t[1]) for t in totals(rust)),
                     "failed": sum(int(t[2]) for t in totals(rust))},
            "python": {"exit_code": python["exit_code"], "ran": int(python_ran.group(1)) if python_ran else 0},
            "boundaries_exit_code": boundaries["exit_code"],
            "log_sha256": {"build": build["log_sha256"], "rust": rust["log_sha256"],
                           "python": python["log_sha256"], "boundaries": boundaries["log_sha256"]},
            "raw_logs_kept_at": "artifacts/local/ (ignored; carries developer-machine output)",
        },
        "inputs_sha256": {path: sha256(path) for path in INPUTS},
        "mutation_check": mutation,
        "residual": [
            "a worker cannot be told to stop one statement: cancelling a query, or abandoning it half way, ends the worker",
            "a worker's reader threads close their own pipes; if something other than the worker holds a pipe open they are daemon threads, are left, and are reported in Worker.abandoned_threads rather than waited for without limit",
            "the worker transport speaks the line protocol of `meguvizdexdash serve` (JSON, mdd.sdk-batch.v1); there is no columnar or Arrow encoding, and one worker serves one dataset and one query at a time",
            "typed IR queries, query parameters and the code, reference and annotation fact layers are not available through this ABI version; each is refused by name (UNSUPPORTED_QUERY or UNSUPPORTED_CAPABILITY)",
            "the result is computed completely before the first batch leaves; a cursor then serves it in owned batches, so peak memory is the whole result, not a window",
            "batches are JSON (schema mdd.sdk-batch.v1); there is no columnar or Arrow encoding",
            "one Windows host here; the Python tests (library and worker) run on Windows and Linux in the repository CI from this commit, and a Linux-only hang in a neighbouring test was found by that kind of run (see STATE)",
            "the mutation check has no result yet (it runs in a GitHub workflow); the conformance runner and its --check are not wired into CI",
        ],
        "run": {"started_utc": build["started_utc"], "profile": "native-unqualified (never admitted)"},
    }
    if not args.no_write:
        target = ROOT / RECORD
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(record, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")

    unproven = [row["acceptance"] for row in rows if not row["all_passed"]]
    print(f"rust: exit={rust['exit_code']} passed={record['tests']['rust']['passed']} failed={record['tests']['rust']['failed']}")
    print(f"python: exit={python['exit_code']} ran={record['tests']['python']['ran']}")
    print(f"ownership cases: {sum(c['passed'] for c in cases)}/{len(cases)}   boundaries exit={boundaries['exit_code']}")
    print(f"acceptance rows={len(rows)} unproven={len(unproven)} open clauses={len(OPEN_CLAUSES)}")
    print(f"mutation: present={mutation['present']} killed={mutation.get('killed')} survived={mutation.get('survived')} current={mutation['current']}")
    for item in unproven:
        print("UNPROVEN:", item)
    ok = (rust["exit_code"] == 0 and python["exit_code"] == 0 and boundaries["exit_code"] == 0 and not unproven
          and (not mutation["present"] or (mutation["current"] and not mutation.get("survived")
                                           and not mutation.get("errors"))))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
