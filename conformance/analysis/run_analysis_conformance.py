#!/usr/bin/env python3
"""Run the MDD-075 analysis conformance and write the capability qualification.

Usage: python -I conformance/analysis/run_analysis_conformance.py [--raw-dir DIR] [--no-write] [--check]

It runs the analysis tests of mdd-facts, the independent Python oracle against the
hand-written fixtures, the oracle's negative controls and a clippy pass over the crate,
maps each acceptance clause of MDD-075 to named tests whose outcomes come from that run,
and writes artifacts/mdd-075/analysis-capability-qualification.json.

The record qualifies an *optional* analysis. It lists what is provided, what is not, and
what every result rests on. It admits no profile and adds no gate; a rule that came to
depend on this analysis would need its own gate first.

--check runs nothing: it verifies the committed record still matches its inputs.
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
RECORD = "artifacts/mdd-075/analysis-capability-qualification.json"
MUTATION = "artifacts/mdd-075/mutation/results.txt"
CASES = "conformance/analysis/soundness-cases.json"
SOURCES = [
    "crates/mdd-facts/src/analysis/mod.rs", "crates/mdd-facts/src/analysis/cfg.rs",
    "crates/mdd-facts/src/analysis/defuse.rs", "crates/mdd-facts/src/analysis/reach.rs",
    "crates/mdd-facts/src/analysis/calls.rs", "crates/mdd-facts/src/analysis/opcodes.rs",
    "crates/mdd-facts/src/analysis/tests.rs", CASES, "conformance/analysis/oracle.py",
    "artifacts/mdd-023/aosp-reference/dex_instruction_list.h",
]

RUST = ["cargo", "test", "--offline", "--locked", "-p", "mdd-facts", "--lib", "analysis"]
CLIPPY = ["cargo", "clippy", "--offline", "--locked", "-p", "mdd-facts", "--all-targets", "--", "-D", "warnings"]
ORACLE = [sys.executable, "-I", "conformance/analysis/oracle.py"]
ORACLE_TESTS = [sys.executable, "-I", "conformance/analysis/test_oracle.py"]

ORACLE_AGREES = "oracle: every hand fixture agrees with an independent implementation"
ORACLE_CONTROLS = "oracle: damaged expectations are caught"

ACCEPTANCE = [
    ("the CFG handles branches, switches, payloads, try/catch and unreachable or invalid ranges, and positions trace back to the DEX",
     ["every_hand_fixture_matches_its_hand_derived_expectation",
      "the_opcode_table_agrees_with_aosp_for_all_256_opcodes",
      "register_roles_follow_the_opcode_family_for_every_opcode",
      "every_real_code_item_yields_a_consistent_cfg_and_chains",
      "blocks_trace_back_to_dex_offsets_and_to_source_lines",
      "an_exception_edge_is_only_usable_from_the_throwing_instruction_onward",
      "no_path_is_refused_when_the_graph_left_something_out"]),
    ("results carry the analysis version, assumptions, required scope and precision or coverage status, and an unknown target is never written as a definite call edge",
     ["a_result_carries_its_version_scope_assumptions_and_status",
      "calls_are_classified_and_none_is_resolved_to_a_callee",
      "hand_assembled_calls_are_classified_by_opcode_and_by_try_membership",
      "reachability_says_yes_certainly_yes_maybe_and_a_proven_no",
      "the_result_says_whether_method_names_were_consulted_for_calls"]),
    ("reflection, dynamic loading and invoke-custom are explicitly unknown, and an empty set is never used to claim there is no path",
     ["reflection_and_loaders_hide_the_target_whatever_the_opcode_says",
      "calls_are_classified_and_none_is_resolved_to_a_callee",
      "no_path_is_refused_when_the_graph_left_something_out",
      "an_offset_that_is_not_an_instruction_is_unknown_not_no",
      "a_path_that_loops_back_through_the_start_block_is_found_not_denied"]),
    ("the declared properties hold on independent hand fixtures and under metamorphic tests, and a budget interruption is marked incomplete",
     ["every_hand_fixture_matches_its_hand_derived_expectation",
      ORACLE_AGREES, ORACLE_CONTROLS,
      "renaming_registers_renames_the_chains_and_changes_nothing_else",
      "a_leading_trampoline_adds_one_block_and_one_edge_and_changes_nothing_else",
      "dead_code_appended_at_the_end_never_changes_what_the_reachable_part_says",
      "a_budget_interruption_is_reported_and_leaves_no_partial_facts"]),
    ("the ordinary core release does not wait for this optional capability",
     ["nothing_outside_the_analysis_module_depends_on_it"]),
]

CAPABILITIES = [
    {"name": "control_flow_graph", "provided": True,
     "precision": "exact for the decoded code: every branch, switch case, fall-through and return is drawn; anything that does not fit is an issue, not an edge"},
    {"name": "exception_edges", "provided": True,
     "precision": "over-approximate: every may-throw instruction in a try may enter every handler of that try, and leaves the method when there is no catch-all; handler types are not matched, so these edges are 'possible'"},
    {"name": "register_def_use", "provided": True,
     "precision": "a may-analysis over registers only: the reaching set is a superset of what can reach a use; fields, array elements and the heap are not tracked"},
    {"name": "call_site_classification", "provided": True,
     "precision": "classification, never resolution: a site names a method, or is dispatch-dependent, or is unknown (polymorphic, custom bootstrap, reflection, code loading); callee sets are not computed"},
    {"name": "method_local_reachability", "provided": True,
     "precision": "yes (certain or maybe), no (proven only on a complete, well-formed CFG) or unknown with causes"},
    {"name": "constant_propagation", "provided": False, "reason": "not implemented"},
    {"name": "interprocedural_call_graph", "provided": False, "reason": "calls are classified, not followed"},
    {"name": "heap_field_and_array_analysis", "provided": False, "reason": "not implemented"},
    {"name": "type_inference", "provided": False, "reason": "not implemented"},
]


def fixtures_digest() -> bytes:
    """Hash of every .dex fixture the real-data tests iterate over."""
    digest = hashlib.sha256()
    for path in sorted((ROOT / "tests/fixtures").rglob("*.dex")):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.digest()


def sha256(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def sources_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCES:
        digest.update((ROOT / relative).read_bytes())
    digest.update(fixtures_digest())
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
        return {"file": MUTATION, "present": False, "current": False}
    lines = path.read_text(encoding="utf-8").splitlines()
    recorded = [line.split(":", 1)[1].strip() for line in lines if line.startswith("sources sha256:")]
    return {
        "file": MUTATION, "script": "artifacts/mdd-075/mutation/mutate_analysis.py", "present": True,
        "current": recorded == [sources_sha256()],
        "killed": sum(1 for line in lines if line.startswith("KILLED")),
        "survived": [line[len("SURVIVED"):].strip() for line in lines if line.startswith("SURVIVED")],
        "errors": sum(1 for line in lines if line.startswith("ERROR")),
        "restored_tree_passes": any("restored tree passes the analysis tests and the oracle: True" in line for line in lines),
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--raw-dir", type=Path, default=ROOT / "artifacts/local/mdd-075-runs")
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        return check_committed()

    rust = run(RUST, args.raw_dir, "analysis-tests")
    clippy = run(CLIPPY, args.raw_dir, "clippy")
    oracle = run(ORACLE, args.raw_dir, "oracle")
    controls = run(ORACLE_TESTS, args.raw_dir, "oracle-controls")
    agreed = re.search(r"^(\d+)/(\d+) cases agree", oracle["text"], re.M)
    cases_total = len(json.loads((ROOT / CASES).read_text(encoding="utf-8"))["cases"])
    extra = {
        ORACLE_AGREES: "ok" if oracle["exit_code"] == 0 and agreed and int(agreed.group(1)) == int(agreed.group(2)) == cases_total else "failed",
        ORACLE_CONTROLS: "ok" if controls["exit_code"] == 0 else "failed",
    }
    rows = acceptance_rows(rust_results(rust["text"]), extra)
    mutation = mutation_summary()
    totals = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed", rust["text"])
    document = json.loads((ROOT / CASES).read_text(encoding="utf-8"))
    record = {
        "schema_version": "mdd.analysis-capability-qualification.v1",
        "task": "MDD-075",
        "kind": "development evidence for an optional analysis; admits no profile and adds no gate",
        "analysis_version": document["analysis_version"],
        "scope": document["scope"],
        "capabilities": CAPABILITIES,
        "acceptance": rows,
        "fixtures": {"file": CASES, "cases": cases_total,
                     "independent_oracle": "conformance/analysis/oracle.py",
                     "oracle_agreed": extra[ORACLE_AGREES] == "ok"},
        "tests": {
            "rust": {"exit_code": rust["exit_code"], "passed": sum(int(t[1]) for t in totals),
                     "failed": sum(int(t[2]) for t in totals)},
            "clippy_exit_code": clippy["exit_code"],
            "oracle_controls_exit_code": controls["exit_code"],
            "log_sha256": {"rust": rust["log_sha256"], "clippy": clippy["log_sha256"],
                           "oracle": oracle["log_sha256"], "oracle_controls": controls["log_sha256"]},
            "raw_logs_kept_at": "artifacts/local/ (ignored; carries developer-machine output)",
        },
        "inputs_sha256": {path: sha256(path) for path in SOURCES},
        "mutation_check": mutation,
        "if_a_rule_depends_on_this": "a HostLab rule that needs CFG, def-use or reachability would need its own required gate before the rule is enabled; this record is not that gate",
        "residual": [
            "single method only: no call is followed, so there is no whole-program reachability or call graph",
            "exception edges are over-approximate by design; the handler type is never matched, so 'possible' exception edges can be infeasible",
            "def-use covers registers only; values that travel through fields, arrays or the heap are invisible to it",
            "register roles of opcodes the hand fixtures do not use are checked against opcode-name families and AOSP operand shapes, not against hand-derived programs",
            "reflection and code-loading calls are recognised by name through an Environment built from the DEX's method references; the repository's fixtures contain none, so that path is exercised with hand-made references and a real invoke whose index is marked",
            "wide register pairs are modelled as two registers and their pairing is not validated",
            "no constant propagation, no type inference, no heap analysis",
            "one Windows host; Linux is covered only by the repository CI",
            "the runner and its --check are not wired into CI",
        ],
        "run": {"started_utc": rust["started_utc"]},
    }
    if not args.no_write:
        target = ROOT / RECORD
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(record, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")

    unproven = [row["acceptance"] for row in rows if not row["all_passed"]]
    print(f"rust: exit={rust['exit_code']} passed={record['tests']['rust']['passed']} failed={record['tests']['rust']['failed']}")
    print(f"clippy exit={clippy['exit_code']}   oracle: {agreed.group(0) if agreed else 'no result'}   oracle controls exit={controls['exit_code']}")
    print(f"acceptance rows={len(rows)} unproven={len(unproven)}")
    print(f"mutation: killed={mutation.get('killed')} survived={mutation.get('survived')} current={mutation['current']}")
    for item in unproven:
        print("UNPROVEN:", item)
    ok = (rust["exit_code"] == 0 and clippy["exit_code"] == 0 and oracle["exit_code"] == 0
          and controls["exit_code"] == 0 and not unproven and mutation["current"]
          and not mutation.get("survived") and not mutation.get("errors"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
