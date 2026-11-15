#!/usr/bin/env python3
"""Run the MDD-041 CLI conformance and write the pipeline record.

Usage: python -I conformance/cli/run_cli_conformance.py [--raw-dir DIR] [--apk PATH] [--no-write] [--check]

Run it with the validation environment's Python (it needs `jsonschema`). It builds the
CLI, runs the mdd-cli tests and a clippy pass, checks every frozen case of
command-and-output-cases.json against the real binary, runs the checker's negative
controls, replays the frozen HostLab variants through the B0 adapter against the frozen
A0 golden, and replays the bulk statements through the adapter for a diagnostic
end-to-end timing. Each acceptance clause of MDD-041 is mapped to checks whose outcomes
come from that run. It writes artifacts/mdd-041/cli-pipeline-conformance.json.

--apk adds one diagnostic run of the bulk statements over a local public APK; the raw
result stays under the ignored artifacts/local and only its summary enters the record.
--check runs nothing: it verifies the committed record still matches its inputs.

The record admits no profile and is not a performance qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import cli_cases  # noqa: E402

RECORD = "artifacts/mdd-041/cli-pipeline-conformance.json"
MUTATION = "artifacts/mdd-041/mutation/results.txt"
CASES = "conformance/cli/command-and-output-cases.json"
B0 = "benchmarks/hostlab-b0-pipeline.py"
BULK = "benchmarks/workloads/b0-bulk-statements.json"
BINARY = cli_cases.DEFAULT_BINARY
SOURCES = [
    "crates/mdd-cli/src/main.rs", "crates/mdd-cli/src/args.rs", "crates/mdd-cli/src/commands.rs",
    "crates/mdd-cli/src/dataset.rs", "crates/mdd-cli/src/output.rs", "crates/mdd-cli/src/run.rs",
    "crates/mdd-cli/src/serve.rs", "crates/mdd-cli/tests/cli.rs", CASES,
    "conformance/cli/cli_cases.py", "conformance/cli/test_cli_cases.py", B0, BULK,
]

RUST = ["cargo", "test", "--offline", "--locked", "-p", "mdd-cli"]
CLIPPY = ["cargo", "clippy", "--offline", "--locked", "-p", "mdd-cli", "--all-targets", "--", "-D", "warnings"]
BUILD = ["cargo", "build", "--offline", "--locked", "-p", "mdd-cli"]
PY = [sys.executable, "-I"]

CASE_CHECK = "frozen cases: every case holds against the real binary"
CONTROLS = "frozen cases: damaged expectations and broken streams are caught"
NO_PRODUCER = "the CLI answers with no other program on PATH and spawns none"
B0_GOLDEN = "B0: typed rows equal the frozen A0 golden through the real process"
B0_DTO = "B0: the HostLab DTO built by the adapter equals the typed rows"
B0_RUN = "B0: bulk statements replay end to end with a stable result digest"

ACCEPTANCE = [
    ("every result comes from this engine's facts; DexSQL is not a hidden producer",
     [NO_PRODUCER, B0_GOLDEN, "a_layer_that_cannot_be_built_is_named_and_its_relations_refuse_instead_of_answering_empty"]),
    ("exit codes, stdout/stderr, errors, empty results and complete or truncated status are a frozen contract",
     [CASE_CHECK, CONTROLS,
      "a_complete_query_ends_in_an_ok_terminal_with_exit_zero_and_a_clean_stderr",
      "an_empty_result_is_a_complete_success_with_no_batch",
      "a_row_limit_ends_in_a_truncated_failure_never_a_success",
      "a_statement_the_engine_refuses_is_a_failure_terminal_on_stdout_with_exit_one",
      "a_refusal_has_an_empty_stdout_a_json_error_on_stderr_and_exit_two",
      "a_statement_that_outlives_its_deadline_ends_in_a_deadline_terminal_with_no_rows",
      "a_closed_output_pipe_ends_the_command_with_exit_four"]),
    ("B0 restores the same DTO, request order and consumer boundary through an adapter, without imitating the old table wire, and records what it does not imitate",
     [B0_GOLDEN, B0_DTO, "serve_answers_requests_in_order_and_each_ends_in_exactly_one_terminal"]),
    ("B0 timing covers the real producer, transport and complete DTO consumption, and each wire, serialization and producer difference is listed",
     [B0_RUN]),
    ("the human and machine forms each state their scope, and an option that is not implemented is refused, never a fake success",
     ["text_output_is_a_table_on_stdout_and_the_summary_is_on_stderr",
      "text_output_of_a_failed_statement_prints_no_table_and_exits_one",
      "a_relation_the_dialect_does_not_have_is_an_error_not_an_empty_table",
      "the_dialect_that_was_asked_for_is_the_one_that_answers", CASE_CHECK]),
]

CAPABILITIES = [
    {"name": "query", "provided": True, "scope": "one SQL statement per run; dialects native-v1 (metadata and structure layers) and dexsql-0.1.0 / dexsql-0.1.1 over the 17 HostLab contract relations"},
    {"name": "serve", "provided": True, "scope": "one dataset, many statements, one framed JSON-lines request per input line; one statement at a time"},
    {"name": "machine_output_jsonl", "provided": True, "scope": "mdd.cli-stream.v1 lines; batches in mdd.sdk-batch.v1 (exact integers, NULL, bytes, original text units)"},
    {"name": "human_output_text", "provided": True, "scope": "an aligned table for a complete answer only; lossy by design (NULL and the word NULL print alike, controls are escaped)"},
    {"name": "dexsql_unicode_table_output", "provided": False, "reason": "refused as UNSUPPORTED_CAPABILITY; B0 does not need it"},
    {"name": "multi_statement_scripts", "provided": False, "reason": "one statement per request; splitting scripts belongs to the MCP layer (MDD-042)"},
    {"name": "query_parameters", "provided": False, "reason": "not implemented"},
    {"name": "typed_ir_queries", "provided": False, "reason": "not implemented"},
    {"name": "pagination_and_cursors", "provided": False, "reason": "the whole result is computed before the first batch leaves; a row limit ends in a truncated failure"},
]


def sha256(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def sources_sha256() -> str:
    """The hash the mutation record is bound to, computed by the mutation script itself."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("mutate_cli", ROOT / "artifacts/mdd-041/mutation/mutate_cli.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.sources_sha256()


def run(command: list[str], raw: Path, name: str) -> dict:
    started = datetime.now(timezone.utc).isoformat()
    done = subprocess.run(command, cwd=ROOT, capture_output=True, check=False)
    log = done.stdout + b"\n--- stderr ---\n" + done.stderr
    raw.mkdir(parents=True, exist_ok=True)
    (raw / f"{name}.log").write_bytes(log)
    return {"started_utc": started, "exit_code": done.returncode,
            "log_sha256": hashlib.sha256(log).hexdigest(), "text": log.decode("utf-8", "replace")}


def rust_results(text: str) -> dict:
    results: dict[str, list[str]] = {}
    for name, outcome in re.findall(r"^test (\S+) \.\.\. (\w+)", text, re.M):
        results.setdefault(name, []).append(outcome)
    return results


def lookup(results: dict, suffix: str) -> tuple[str, str]:
    hits = [(name, outcomes) for name, outcomes in results.items() if name == suffix or name.endswith("::" + suffix)]
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
        rows.append({"acceptance": statement, "tests": proofs, "all_passed": all(p["outcome"] == "ok" for p in proofs)})
    return rows


def no_external_producer() -> tuple[bool, str]:
    """The source spawns no process, and the CLI answers with nothing else on PATH."""
    for path in (ROOT / "crates/mdd-cli/src").glob("*.rs"):
        text = path.read_text(encoding="utf-8")
        if "process::Command" in text or "Command::new" in text:
            return False, f"{path.name} spawns a process"
    empty = ROOT / "artifacts" / "local" / "mdd-041-runs" / "empty-path"
    empty.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items() if k.upper() != "PATH"}
    env["PATH"] = str(empty)
    done = subprocess.run(
        [str(BINARY), "query", "--input", str(ROOT / "tests/fixtures/definitions/generated/definitions-038.dex"),
         "--dialect", "dexsql-0.1.0", "--sql", "SELECT type_idx FROM types ORDER BY type_idx"],
        capture_output=True, env=env, check=False, cwd=ROOT)
    last = done.stdout.splitlines()[-1] if done.stdout.strip() else b"{}"
    ok = done.returncode == 0 and json.loads(last).get("terminal", {}).get("operation_status") == "ok"
    return ok, "exit " + str(done.returncode)


def mutation_summary() -> dict:
    path = ROOT / MUTATION
    if not path.is_file():
        return {"file": MUTATION, "present": False, "current": False}
    lines = path.read_text(encoding="utf-8").splitlines()
    recorded = [line.split(":", 1)[1].strip() for line in lines if line.startswith("sources sha256:")]
    return {
        "file": MUTATION, "script": "artifacts/mdd-041/mutation/mutate_cli.py", "present": True,
        "current": recorded == [sources_sha256()],
        "killed": sum(1 for line in lines if line.startswith("KILLED")),
        "survived": [line[len("SURVIVED"):].strip() for line in lines if line.startswith("SURVIVED")],
        "errors": sum(1 for line in lines if line.startswith("ERROR")),
        "skipped": sum(1 for line in lines if line.startswith("SKIPPED")),
        "restored_tree_passes": any("passes the CLI tests, the frozen cases and their controls: True" in line for line in lines),
    }


def check_committed() -> int:
    record = json.loads((ROOT / RECORD).read_text(encoding="utf-8"))
    stale = [path for path, digest in record["inputs_sha256"].items() if sha256(path) != digest]
    if not mutation_summary()["current"]:
        stale.append(MUTATION)
    for path in stale:
        print("STALE:", path)
    print("committed record current:", not stale)
    return 1 if stale else 0


def json_of(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--raw-dir", type=Path, default=ROOT / "artifacts/local/mdd-041-runs")
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        return check_committed()
    raw = args.raw_dir

    rust = run(RUST, raw, "cli-tests")
    clippy = run(CLIPPY, raw, "clippy")
    build = run(BUILD, raw, "build")

    document = cli_cases.load_cases()
    case_problems = cli_cases.run_all(BINARY, document) if build["exit_code"] == 0 else {"build": ["the CLI did not build"]}
    failed_cases = {name: p for name, p in case_problems.items() if p}
    controls = run([*PY, "conformance/cli/test_cli_cases.py"], raw, "controls")
    producer_ok, producer_note = no_external_producer()

    verify_path, run_path = raw / "b0-verify.json", raw / "b0-run.json"
    verify = run([*PY, B0, "verify", "--binary", str(BINARY), "--out", str(verify_path)], raw, "b0-verify")
    fixtures = [ROOT / p for p in json_of(ROOT / "conformance/corpus/hostlab/required-variants.json")["inputs"]]
    bulk = run([*PY, B0, "run", "--binary", str(BINARY), "--statements", str(ROOT / BULK), "--rounds", "3",
                *[a for f in fixtures for a in ("--input", str(f))], "--out", str(run_path)], raw, "b0-run")
    verified = json_of(verify_path) if verify["exit_code"] == 0 and verify_path.is_file() else None
    replayed = json_of(run_path) if bulk["exit_code"] == 0 and run_path.is_file() else None

    local_run = None
    if args.apk:
        apk_path = raw / "b0-run-public-apk.json"
        budgets = {"result-rows": 500000, "scanned-rows": 100000000, "steps": 2000000000}
        done = run([*PY, B0, "run", "--binary", str(BINARY), "--statements", str(ROOT / BULK), "--rounds", "3",
                    *[a for name, value in budgets.items() for a in ("--sql-max-" + name, str(value))],
                    "--input", str(args.apk), "--out", str(apk_path)], raw, "b0-run-public-apk")
        if done["exit_code"] == 0:
            result = json_of(apk_path)
            local_run = {
                "input_sha256": hashlib.sha256(args.apk.read_bytes()).hexdigest(), "input_bytes": args.apk.stat().st_size,
                "binary": "release" if "release" in str(BINARY) else "debug",
                "sql_budgets_raised_to": budgets,
                "rounds": result["rounds"], "digest_stable_across_rounds": result["digest_stable_across_rounds"],
                "raw_kept_at": "artifacts/local/ (ignored)",
                "caveat": "one host, no exclusive window, not compared with an A0 run: a pipeline completeness check, not a performance result",
            }

    extra = {
        CASE_CHECK: "ok" if not failed_cases else "failed",
        CONTROLS: "ok" if controls["exit_code"] == 0 else "failed",
        NO_PRODUCER: "ok" if producer_ok else "failed",
        B0_GOLDEN: "ok" if verified and verified["equal"] and verified["counts"]["compared_to_a0"] > 0 else "failed",
        B0_DTO: "ok" if verified and verified["equal"] and verified["counts"]["dto_compared"] > 0 else "failed",
        B0_RUN: "ok" if replayed and replayed["digest_stable_across_rounds"] and replayed["statements_run"] > 0 else "failed",
    }
    rows = acceptance_rows(rust_results(rust["text"]), extra)
    mutation = mutation_summary()
    totals = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed", rust["text"])

    record = {
        "schema_version": "mdd.cli-pipeline-conformance.v1",
        "task": "MDD-041",
        "kind": "development evidence for the command line and the B0 path; admits no profile and is not a performance qualification",
        "capabilities": CAPABILITIES,
        "exit_codes": document["exit_codes"],
        "acceptance": rows,
        "frozen_cases": {"file": CASES, "cases": len(case_problems), "failed": sorted(failed_cases), "all_hold": not failed_cases},
        "no_external_producer": {"holds": producer_ok, "note": producer_note},
        "b0": {
            "adapter": B0,
            "does_not": "import or run HostLab's own modules; shows the DTO, request order and guards, not that HostLab's rules run unchanged",
            "verify": verified and {"dialect": verified["dialect"], "counts": verified["counts"], "equal": verified["equal"],
                                    "script_refusals": verified["script_refusals"]},
            "bulk_replay": replayed and {"statements_run": replayed["statements_run"], "rounds": replayed["rounds"],
                                         "digest_stable_across_rounds": replayed["digest_stable_across_rounds"]},
            "differences_from_a0": (verified or replayed or {}).get("differences_from_a0"),
            "local_public_apk_run": local_run,
            "timing_scope": "producer, transport and complete DTO consumption inside one adapter process tree; wall clock on one host outside an exclusive window",
        },
        "tests": {
            "rust": {"exit_code": rust["exit_code"], "passed": sum(int(t[1]) for t in totals), "failed": sum(int(t[2]) for t in totals)},
            "clippy_exit_code": clippy["exit_code"], "build_exit_code": build["exit_code"],
            "controls_exit_code": controls["exit_code"],
            "log_sha256": {"rust": rust["log_sha256"], "clippy": clippy["log_sha256"], "controls": controls["log_sha256"]},
            "raw_logs_kept_at": "artifacts/local/ (ignored; carries developer-machine output)",
        },
        "inputs_sha256": {path: sha256(path) for path in SOURCES},
        "mutation_check": mutation,
        "residual": [
            "one statement per request: no script splitting, no parameters, no typed IR, no pagination or cursors",
            "the whole result is computed before the first batch leaves; peak memory is the whole result",
            "native-v1 reads the metadata and structure layers only; a DEX whose code, reference or annotation layer cannot be built keeps its structure relations and refuses the others",
            "the text form is lossy and for people; machine consumers use jsonl",
            "B0 does not run HostLab's own audit code and does not use the real HostLab request mix; its bulk statements are written for this adapter",
            "the two private HostLab APKs are not available, so only the frozen fixtures and, with --apk, a public APK were replayed",
            "the engine's default SQL budgets (100,000 result rows, 1,000,000 scanned rows, 5,000,000 steps) refuse HostLab-style bulk reads of a real APK; the CLI exposes --sql-max-* to raise them, and what HostLab's real APKs need is not known until MDD-005 has them",
            "HostLab's strict UTF-8 decode of the hex projection refuses string values that contain NUL (stored as C0 80): 19 of 68,476 strings in NewPipe 0.28.6; whether the frozen A0 emits the same bytes for them was not checked",
            "no A0 run took place beside the B0 run, so the timings give no ratio",
            "one Windows host; the frozen cases and the B0 verify are added to the CI workflow but have not yet run there, so Linux is unverified",
        ],
        "run": {"started_utc": rust["started_utc"]},
    }
    if not args.no_write:
        target = ROOT / RECORD
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(record, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")

    unproven = [row["acceptance"] for row in rows if not row["all_passed"]]
    print(f"rust: exit={rust['exit_code']} passed={record['tests']['rust']['passed']} failed={record['tests']['rust']['failed']}   clippy={clippy['exit_code']}   build={build['exit_code']}")
    print(f"frozen cases: {len(case_problems) - len(failed_cases)}/{len(case_problems)} hold   controls exit={controls['exit_code']}   no external producer: {producer_ok}")
    if verified:
        print(f"B0 verify: {verified['counts']}")
    print(f"acceptance rows={len(rows)} unproven={len(unproven)}")
    print(f"mutation: killed={mutation.get('killed')} survived={mutation.get('survived')} current={mutation['current']}")
    for name, problems in failed_cases.items():
        print("CASE FAILED:", name, problems)
    for item in unproven:
        print("UNPROVEN:", item)
    ok = (rust["exit_code"] == 0 and clippy["exit_code"] == 0 and build["exit_code"] == 0 and not failed_cases
          and controls["exit_code"] == 0 and not unproven and mutation["current"]
          and not mutation.get("survived") and not mutation.get("errors"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
