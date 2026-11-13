#!/usr/bin/env python3
"""Build the MDD-040 record: mdd-wire/1 framing, batches, backpressure, MCP guard.

Usage: python tools/build_mdd040_evidence.py [--raw-dir DIR]

Runs the tests of mdd-wire (framing, an independent Python case set, producer and
consumer behaviour) and mdd-worker (a real child process: negotiation, credit,
bounded queue, cancel, deadline, reaping), and writes
artifacts/mdd-040/wire-conformance.json mapping every acceptance clause to named
tests with their outcome in this run. The worker scenarios come from a custom
test harness (the child must write only frames to stdout), whose `ok <name>` lines
are parsed as test results.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = "conformance/protocol/wire-v1-cases.json"
GENERATOR = "conformance/protocol/generate_wire_cases.py"
COMMAND = ["cargo", "test", "--offline", "--locked", "-p", "mdd-wire", "-p", "mdd-worker"]

ACCEPTANCE = [
    ("frame length, version, schema, source and budget are verifiable; half frames, oversized frames, reordering and repeated terminals fail explicitly",
     ["frame_cases_reach_the_recorded_verdicts", "stream_cases_reach_the_recorded_verdicts",
      "negotiation_cases_reach_the_recorded_verdicts", "header_round_trips_and_has_the_documented_layout",
      "a half frame is a truncated body", "a duplicate terminal is not ignored",
      "a batch after End is not ignored", "a_sticky_failure_is_reported_again_instead_of_being_reinterpreted"]),
    ("NULL, integer precision, UTF-16/MUTF-8 display boundaries, empty batches and duplicate rows are not lost to encoding",
     ["stream_cases_reach_the_recorded_verdicts",
      "the_rust_producer_reproduces_the_independent_implementations_bodies_and_digest",
      "a_producer_stream_is_accepted_by_a_consumer_and_returns_exactly_its_rows",
      "a_batch_over_the_frame_limit_is_refused_not_truncated",
      "rows too large for one frame are split into several batches"]),
    ("a stopped or cancelling consumer stalls the producer only boundedly and the queue never grows without limit",
     ["a_producer_without_credit_waits_boundedly_and_gives_up", "cancellation_releases_a_waiting_producer_promptly",
      "a_late_grant_wakes_a_waiting_producer", "consumer_credit_is_spent_by_batches_and_refilled_by_grants",
      "a paused consumer bounds what the worker may write",
      "a consumer that never resumes ends at the deadline with the worker stopped",
      "cancel reaches a stalled worker promptly", "a worker that stops talking is bounded by the deadline and killed",
      "a worker that never reads cannot hold the client past its deadline",
      "cancel is sent to a live worker, which stops by itself and is not killed",
      "a worker that ignores end of input leaves only because Cancel was sent",
      "a_failed_write_latches_the_writer_so_no_frame_follows_a_partial_one",
      "an_unbounded_wait_is_capped_instead_of_overflowing_the_clock"]),
    ("receiving row batches is not completion: rows are committed only when the End counts and digest match everything received",
     ["a worker that exits before End is a disconnect, not a short result",
      "a worker killed mid-stream reports its exit status and a disconnect",
      "an error after rows is a failure that keeps the worker's code",
      "an_error_terminal_after_rows_is_a_failure_with_the_rows_counted",
      "a row the worker cannot encode ends in an Error terminal with the reason",
      "complete stream is verified, negotiated and reaped"]),
    ("MCP stdout carries only valid JSON protocol; binary batches never enter that stream",
     ["mcp_stdout_accepts_only_one_json_rpc_line",
      "frames_round_trip_through_a_writer_and_reader_and_only_on_the_dedicated_channel",
      "log text on the dedicated channel is a protocol failure"]),
]


def load_sibling():
    path = ROOT / "tools/build_mdd032_033_evidence.py"
    spec = importlib.util.spec_from_file_location("mdd032_033_evidence", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sha256(path: str) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, default=ROOT / "artifacts/local/mdd-040-runs-20261113")
    args = parser.parse_args()
    sibling = load_sibling()
    sibling.COMMAND = COMMAND
    run = sibling.run_tests(args.raw_dir)
    log = (args.raw_dir / "mdd032-033-lib-tests.log").read_text(encoding="utf-8", errors="replace")
    scenarios = re.findall(r"^ok (.+?) \(\d+ ms\)$", log, re.M)
    finished = "all wire child scenarios passed" in log
    results = dict(run["results"])
    for name in scenarios:
        results[f"wire_child::{name}"] = "ok" if finished else "unfinished"
    rows = sibling.acceptance_rows(ACCEPTANCE, results)
    cases = json.loads((ROOT / CASES).read_text(encoding="utf-8"))
    document = {
        "schema_version": "mdd.wire-conformance.v1",
        "task": "MDD-040",
        "kind": "development evidence; admits no profile",
        "protocol": "mdd-wire/1 (JSON batches; serial streams; no columnar encoding)",
        "independent_oracle": {
            "generator": GENERATOR, "generator_sha256": sha256(GENERATOR),
            "cases": CASES, "cases_sha256": sha256(CASES),
            "frame_cases": len(cases["frame_cases"]), "negotiation_cases": len(cases["negotiation_cases"]),
            "stream_cases": len(cases["stream_cases"]),
            "note": "framing layout, cell JSON and the integrity digest are re-implemented in Python with struct/json/hashlib; Rust must decode those bytes and the Rust producer must reproduce the Python bodies and digests",
        },
        "worker_scenarios": {"count": len(scenarios), "all_finished": finished, "names": scenarios},
        "acceptance": rows,
        "residual": [
            "streams are serial; multiplexing stays off until multi-stream state, cancel and quota are verified",
            "only the JSON batch encoding exists; a columnar encoding needs its own cases and an end-to-end measurement before it can be a default",
            "the CLI, MCP façade and SDK do not use this protocol yet (MDD-041 to MDD-043); here the client is a library and the worker a test child process",
            "pipes only (no socket transport) and Windows only in this run; Linux was not run",
            "buffers and credit are logical byte counts of frame bodies, not allocator or RSS measurements",
        ],
        "run": {k: v for k, v in run.items() if k != "results"},
    }
    target = ROOT / "artifacts/mdd-040/wire-conformance.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    unproven = [r["acceptance"] for r in rows if not r["all_passed"]]
    print(f"acceptance rows={len(rows)} unproven={len(unproven)} scenarios={len(scenarios)} finished={finished} "
          f"tests: exit={run['exit_code']} passed={run['passed']} failed={run['failed']}")
    return 0 if run["exit_code"] == 0 and finished and not unproven else 1


if __name__ == "__main__":
    sys.exit(main())
