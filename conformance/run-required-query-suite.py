#!/usr/bin/env python3
"""Run the MDD-035 required-query suite and write its qualification records.

Usage: python -I conformance/run-required-query-suite.py [--raw-dir DIR] [--online] [--no-write]

It runs the query-layer tests of mdd-types, mdd-facts, mdd-query, mdd-session and
mdd-sql (unit and integration targets), maps the five acceptance clauses of MDD-035
to named tests whose outcomes come from that run, derives a verdict for every
required query family of every profile from the frozen corpus and the A0 golden, and
writes
  artifacts/mdd-035/required-query-results.json
  conformance/manifests/query-profile-qualification.json
The records qualify the query layer only. They admit no profile and say nothing about
the whole hostlab-audit-v1 workflow, which needs MDD-055.

Exit code 0 only when cargo succeeded, no test failed, every acceptance row is
proven and hostlab-audit-v1 passes at the query layer.
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

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ["mdd-types", "mdd-facts", "mdd-query", "mdd-session", "mdd-sql"]
RESULTS = "artifacts/mdd-035/required-query-results.json"
PROFILES = "conformance/manifests/query-profile-qualification.json"
REQUIREMENTS = "conformance/manifests/profile-requirements.json"
VARIANTS = "conformance/corpus/hostlab/required-variants.json"
GOLDEN = "conformance/corpus/hostlab/expected-results/hostlab-a0-golden.json"
PAGING = "conformance/session/catalog-and-paging.json"
GOLDEN_TESTS = "crates/mdd-sql/src/provider/hostlab/tests.rs"
MUTATION = "artifacts/mdd-035/mutation/results.txt"
MUTATION_TEST_SOURCES = [
    "crates/mdd-sql/tests/cross_path_equivalence.rs",
    "crates/mdd-sql/src/provider/hostlab/combo_tests.rs",
]

GOLDEN_TEST = "hostlab_variants_match_the_a0_golden_results"
TEMP_TEST = "temp_scenarios_match_the_recorded_a0_behaviour"

ACCEPTANCE = [
    ("every frozen required HostLab statement agrees with A0 field by field, type by type, in multiplicity and in the required order",
     [GOLDEN_TEST,
      "calls_the_reference_refuses_are_refused_with_the_same_failing_statement",
      TEMP_TEST,
      "every_relation_matches_the_recorded_a0_readback_row_for_row",
      "a0_differential_over_the_fixture_corpus_has_only_declared_divergences"]),
    ("complete holds only when the required scope's input and facts are complete, execution finished and no page remains",
     ["missing_provider_object_is_unknown_not_complete",
      "unmapped_relation_is_never_gated_to_complete",
      "coverage_ledger_gates_each_relation_on_the_layers_that_prove_it",
      "blocking_warning_cannot_be_a_complete_result",
      "exact_total_larger_than_delivered_is_not_complete",
      "pages_that_disagree_with_the_exact_total_are_rejected",
      "all_rows_dequeued_but_one_unacknowledged_still_cannot_complete",
      "dropped_unacknowledged_rows_and_unread_end_never_complete",
      "part_rows_error_and_eof_never_complete",
      "an_unbuilt_layer_is_an_error_under_every_window_and_never_an_empty_page"]),
    ("the same request gives no silent difference between the typed IR, the SQL bridge and the conservative reference path",
     ["independent_small_table_oracle_both_execution_paths",
      "full_scan_projection_agrees_on_all_paths",
      "order_by_text_follows_utf16_code_units_on_all_paths",
      "offset_window_over_an_ordered_request_agrees_on_all_paths",
      "grouped_count_keeps_the_multiplicity_of_both_occurrences",
      "equality_filter_hits_and_misses_agree_on_all_paths",
      "join_through_the_descriptor_string_keeps_occurrence_identity",
      "class_scan_agrees_on_all_paths_for_definition_relations",
      "field_kind_histogram_agrees_on_all_paths_for_definition_relations",
      "field_to_class_join_keeps_occurrence_identity_for_definition_relations",
      "class_interface_pairs_agree_on_all_paths_for_definition_relations",
      "sql_order_puts_the_supplementary_string_where_the_python_record_does",
      "sql_original_mutf8_cells_declare_the_unit_count_of_their_text",
      "count_star_is_unsigned_in_the_typed_ir_and_signed_in_the_sql_bridge",
      "fixture_discriminates_utf16_order_from_utf8_order",
      "the_comparison_itself_rejects_a_wrong_row_a_missing_row_and_a_wrong_order"]),
    ("paging, cancellation, TEMP and unusable-input combinations are refused or preserved correctly, and failure or an unknown format is never recorded as a normal MISSING",
     ["a_cancelled_page_is_an_error_and_the_walk_resumes_with_identical_rows",
      "a_cancelled_read_of_a_temp_definition_changes_neither_the_catalog_nor_the_rows",
      "an_unbuilt_layer_is_an_error_under_every_window_and_never_an_empty_page",
      "computed_spool_cancel_page_and_complete_zero_are_independent",
      "calls_the_reference_refuses_are_refused_with_the_same_failing_statement",
      "known_unsupported_forms_fail_closed_with_the_unsupported_classification",
      "a0_differential_over_the_fixture_corpus_has_only_declared_divergences",
      TEMP_TEST]),
]

# Differences between the typed IR and the SQL bridge that are intended and pinned by a
# test: a change on either side fails that test instead of passing unseen.
KNOWN_REPRESENTATION_DIFFERENCES = [
    {
        "what": "COUNT(*)",
        "typed_ir": "u64",
        "sql_bridge": "i64",
        "pinned_by": "count_star_is_unsigned_in_the_typed_ir_and_signed_in_the_sql_bridge",
        "comparison": "the SQL cell is converted to unsigned for that one column, from a non-negative signed value only",
    },
    {
        "what": "original MUTF-8 text bytes (strings.raw_mutf8)",
        "typed_ir": "bytes",
        "sql_bridge": "dex_mutf8 with a declared UTF-16 unit count",
        "pinned_by": "sql_original_mutf8_cells_declare_the_unit_count_of_their_text",
        "comparison": "bytes are compared across paths; the unit count is checked against the text on the SQL side",
    },
]


def load(relative: str):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def sha256(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def run_cargo(raw_dir: Path, online: bool) -> dict:
    command = ["cargo", "test", *([] if online else ["--offline"]), "--locked"]
    for package in PACKAGES:
        command += ["-p", package]
    command += ["--lib", "--tests"]
    started = datetime.now(timezone.utc).isoformat()
    done = subprocess.run(command, cwd=ROOT, capture_output=True, check=False)
    finished = datetime.now(timezone.utc).isoformat()
    log = done.stdout + b"\n--- stderr ---\n" + done.stderr
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "query-suite.log").write_bytes(log)
    text = log.decode("utf-8", "replace")
    results: dict[str, list[str]] = {}
    for name, outcome in re.findall(r"^test (\S+) \.\.\. (\w+)", text, re.M):
        results.setdefault(name, []).append(outcome)
    totals = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored", text)
    return {
        "command": command,
        "started_utc": started,
        "finished_utc": finished,
        "exit_code": done.returncode,
        "raw_log_sha256": hashlib.sha256(log).hexdigest(),
        "raw_log_bytes": len(log),
        "raw_log_kept_at": "artifacts/local/ (ignored; carries developer-machine output)",
        "targets": len(totals),
        "passed": sum(int(t[1]) for t in totals),
        "failed": sum(int(t[2]) for t in totals),
        "ignored": sum(int(t[3]) for t in totals),
        "results": results,
    }


def lookup(results: dict, suffix: str) -> tuple[str, str]:
    hits = [(name, outcomes) for name, outcomes in results.items()
            if name == suffix or name.endswith("::" + suffix)]
    if len(hits) != 1:
        return suffix, "not_run" if not hits else f"ambiguous({len(hits)})"
    name, outcomes = hits[0]
    if len(outcomes) != 1:
        return name, f"ambiguous({len(outcomes)})"
    return name, outcomes[0]


def acceptance_rows(results: dict) -> list:
    rows = []
    for statement, names in ACCEPTANCE:
        proofs = []
        for suffix in names:
            full, outcome = lookup(results, suffix)
            proofs.append({"test": full, "outcome": outcome})
        rows.append({"acceptance": statement, "tests": proofs,
                     "all_passed": all(p["outcome"] == "ok" for p in proofs)})
    return rows


def parse_divergences(source: str) -> dict:
    """Families with variants the engine knowingly answers differently from A0."""
    match = re.search(r"const GOLDEN_DIVERGENCES:\s*&\[\(&str,\s*&str\)\]\s*=\s*&\[(.*?)\];", source, re.S)
    if match is None:
        raise SystemExit("GOLDEN_DIVERGENCES not found; the divergence declaration moved")
    by_family: dict[str, list[str]] = {}
    for key in re.findall(r'\(\s*"([A-Z]\d{2}/[A-Za-z0-9_]+)"\s*,', match.group(1)):
        by_family.setdefault(key.split("/")[0], []).append(key)
    return by_family


def declared_divergences() -> dict:
    return parse_divergences((ROOT / GOLDEN_TESTS).read_text(encoding="utf-8"))


def family_table(results: dict) -> dict:
    variants = load(VARIANTS)["variants"]
    golden = load(GOLDEN)["cases"]
    if len(variants) != len(golden):
        raise SystemExit("golden and variants differ in length; regenerate the golden")
    diverged = declared_divergences()
    _, golden_outcome = lookup(results, GOLDEN_TEST)
    families: dict[str, dict] = {}
    for variant, case in zip(variants, golden):
        if (variant["family"], variant["variant"]) != (case["family"], case["variant"]):
            raise SystemExit(f"golden is out of step with {VARIANTS}: {variant['variant']}")
        entry = families.setdefault(case["family"], {"variants": 0, "statements": 0, "pages": 0})
        entry["variants"] += 1
        entry["statements"] += len(case["statements"])
        entry["pages"] += len(case["pages"])
    for family, entry in families.items():
        if golden_outcome != "ok":
            entry["verdict"] = "not_proven"
        elif family in diverged:
            entry["verdict"] = "equal_to_a0_except_declared_divergences"
            entry["declared_divergences"] = diverged[family]
        else:
            entry["verdict"] = "equal_to_a0"
    return families


def profile_records(families: dict) -> list:
    required = load(REQUIREMENTS)
    records = []
    for profile in required["profiles"]:
        states = {}
        for family in profile["required_query_families"]:
            entry = families.get(family)
            if entry is None:
                states[family] = {"verdict": "no_labelled_corpus"}
            else:
                states[family] = {"verdict": entry["verdict"], "variants": entry["variants"]}
        gaps = sorted(f for f, s in states.items() if s["verdict"] != "equal_to_a0")
        records.append({
            "id": profile["id"],
            "admitted": profile["admitted"],
            "query_layer": "passed" if not gaps else "partial",
            "families": states,
            "families_without_full_evidence": gaps,
            "workflow_replacement": "not claimed; needs MDD-055",
        })
    return records


def current_tests_sha256() -> str:
    digest = hashlib.sha256()
    for relative in MUTATION_TEST_SOURCES:
        digest.update((ROOT / relative).read_bytes())
    return digest.hexdigest()


def mutation_is_current(lines: list, current: str) -> bool:
    """The mutation record names the hash of the tests it ran against."""
    recorded = [line.split(":", 1)[1].strip() for line in lines if line.startswith("tests sha256:")]
    return recorded == [current]


def mutation_summary() -> dict:
    path = ROOT / MUTATION
    if not path.is_file():
        return {"file": MUTATION, "present": False, "current": False}
    lines = path.read_text(encoding="utf-8").splitlines()
    return {
        "current": mutation_is_current(lines, current_tests_sha256()),
        "errors": sum(1 for line in lines if line.startswith("ERROR")),
        "file": MUTATION,
        "present": True,
        "script": "artifacts/mdd-035/mutation/mutate_query_paths.py",
        "killed": sum(1 for line in lines if line.startswith("KILLED")),
        "survived": [line[len("SURVIVED"):].strip() for line in lines if line.startswith("SURVIVED")],
        "restored_tree_passes": any("restored tree passes both test sets: True" in line for line in lines),
    }


def check_committed() -> int:
    """Stale committed records: corpus, golden or tests changed since the last run."""
    results = load(RESULTS)
    stale = [path for path, digest in results["inputs_sha256"].items() if sha256(path) != digest]
    if not mutation_summary()["current"]:
        stale.append(MUTATION)
    for path in stale:
        print("STALE:", path)
    print("committed records current:", not stale)
    return 1 if stale else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--raw-dir", type=Path, default=ROOT / "artifacts/local/mdd-035-runs")
    parser.add_argument("--online", action="store_true", help="do not pass --offline to cargo")
    parser.add_argument("--no-write", action="store_true", help="run and report without writing records")
    parser.add_argument("--check", action="store_true",
                        help="do not run cargo: verify the committed records still match their inputs")
    args = parser.parse_args()
    if args.check:
        return check_committed()

    run = run_cargo(args.raw_dir, args.online)
    rows = acceptance_rows(run["results"])
    families = family_table(run["results"])
    profiles = profile_records(families)
    _, temp_outcome = lookup(run["results"], TEMP_TEST)
    paging = load(PAGING)

    results = {
        "schema_version": "mdd.required-query-results.v1",
        "task": "MDD-035",
        "kind": "development evidence for the query layer; admits no profile",
        "acceptance": rows,
        "scope_declaration": {
            "acceptance": "only the query layer is registered; the whole hostlab-audit-v1 workflow needs MDD-055 before it can be called a replacement",
            "no_profile_admitted": not any(profile["admitted"] for profile in profiles),
            "workflow_replacement": "not claimed",
        },
        "known_representation_differences": KNOWN_REPRESENTATION_DIFFERENCES,
        "families": dict(sorted(families.items())),
        "temp_and_paging": {
            "corpus": PAGING,
            "scenarios": len(paging["scenarios"]),
            "replayed_equal_to_a0": temp_outcome == "ok",
        },
        "inputs_sha256": {path: sha256(path) for path in (VARIANTS, GOLDEN, PAGING, REQUIREMENTS)},
        "mutation_check": mutation_summary(),
        "residual": [
            "the three-path comparison (typed IR streaming, typed IR reference, SQL bridge) covers the native relations strings, types, classes, class_interfaces and field_definitions over two small two-occurrence fixtures; method_definitions, code, reference and annotation relations are compared with A0 through the SQL path only, not through the typed IR",
            "no Q16-labelled corpus exists in required-variants.json: Q16 is evidenced only through the recorded TEMP and paging scenarios and the MDD-031 SQL semantics suite, so the dexsql compatibility profiles stay partial",
            "unusable inputs reach the query layer through the A0 differential, whose corpus holds malformed DEX files: wherever A0 refuses, the engine refuses too and none becomes a zero-row success; they are not combined again with paging beyond the rejection corpus, which is replayed under windows",
            "cancellation combinations use a control cancelled before the call, which is deterministic; a cancel racing a running page is covered by the separate cancellation tests, not by these combinations",
            "one mutant survived: bypassing both the coverage ledger and require_layer still fails closed because the fact accessor is a third guard; the two guards are tested separately in coverage_ledger_gates_each_relation_on_the_layers_that_prove_it",
            "run on one Windows host; Linux is covered only by the repository CI",
            "no performance run and no profile admitted; the whole hostlab-audit-v1 workflow needs MDD-055",
        ],
        "run": {k: v for k, v in run.items() if k != "results"},
    }
    qualification = {
        "schema_version": "mdd.query-profile-qualification.v1",
        "task": "MDD-035",
        "scope": "query layer only: statements, typed results, completeness and paging; not the HostLab workflow",
        "source": RESULTS,
        "results_run_exit_code": run["exit_code"],
        "profiles": profiles,
        "note": "query_layer passed means every required family equals A0 on the frozen corpus; it does not admit the profile",
    }
    if not args.no_write:
        for relative, document in ((RESULTS, results), (PROFILES, qualification)):
            target = ROOT / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(document, ensure_ascii=False, indent=1) + "\n",
                              encoding="utf-8", newline="\n")

    unproven = [row["acceptance"] for row in rows if not row["all_passed"]]
    if any(profile["admitted"] for profile in profiles):
        unproven.append("only the query layer is registered: a profile is marked admitted")
    audit = next(p for p in profiles if p["id"] == "hostlab-audit-v1")
    print(f"tests: exit={run['exit_code']} targets={run['targets']} passed={run['passed']} failed={run['failed']}")
    print(f"acceptance rows={len(rows)} unproven={len(unproven)}")
    for profile in profiles:
        print(f"profile {profile['id']}: query_layer={profile['query_layer']} gaps={profile['families_without_full_evidence']}")
    for item in unproven:
        print("UNPROVEN:", item)
    mutation = results["mutation_check"]
    if not mutation["current"] or mutation.get("errors"):
        print("mutation record is missing, stale or has build errors: rerun mutate_query_paths.py")
    ok = (run["exit_code"] == 0 and run["failed"] == 0 and not unproven and audit["query_layer"] == "passed"
          and mutation["current"] and not mutation.get("errors"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
