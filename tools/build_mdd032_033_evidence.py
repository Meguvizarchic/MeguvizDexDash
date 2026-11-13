#!/usr/bin/env python3
"""Build the MDD-032 query matrix and the MDD-033 paging/isolation record.

Usage: python tools/build_mdd032_033_evidence.py [--raw-dir DIR]

The script runs the library tests of `mdd-sql` and `mdd-session` once, keeps the
raw log under --raw-dir (default artifacts/local/, which is ignored: the cargo
log of a developer machine is not repository content), and writes two JSON
records that cite individual test results by name together with the SHA-256 of
the files the tests compare against. It reads, never writes, the A0 goldens; a
test that did not run or did not pass is recorded as such rather than omitted.

The records are development evidence. They admit no profile.
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
VARIANTS = "conformance/corpus/hostlab/required-variants.json"
GOLDEN = "conformance/corpus/hostlab/expected-results/hostlab-a0-golden.json"
SCENARIOS = "conformance/session/catalog-and-paging.json"
PAGING_CASES = "conformance/corpus/hostlab/paging-blocker-cases.json"
QUERIES = "conformance/corpus/hostlab/queries.jsonl"
COMMAND = ["cargo", "test", "--offline", "--locked", "-p", "mdd-sql", "-p", "mdd-session", "--lib"]

# Acceptance bullet -> tests that prove it. Names are matched as suffixes of the
# full libtest path, so a rename shows up as "not_run" instead of silently passing.
MDD032_ACCEPTANCE = [
    ("seventeen relations satisfy the frozen column contract and match A0 row for row",
     ["a0_differential_over_the_fixture_corpus_has_only_declared_divergences",
      "all_seventeen_relations_return_rows_from_real_facts",
      "coverage_ledger_gates_each_relation_on_the_layers_that_prove_it"]),
    ("every required template, dynamic-parameter class and helper statement executes completely",
     ["hostlab_variants_match_the_a0_golden_results"]),
    ("cross-DEX string correlation, COUNT(*) multiplicity, generic ordering, cf./cm. columns and raw code units have counterexamples",
     ["hostlab_variants_match_the_a0_golden_results"]),
    ("LIKE candidates keep the full superset the exact Python classification needs",
     ["hostlab_variants_match_the_a0_golden_results"]),
    ("no required query is unsupported, short, NULL-wrong or answered by the old engine",
     ["hostlab_variants_match_the_a0_golden_results",
      "calls_the_reference_refuses_are_refused_with_the_same_failing_statement",
      "paging_blocker_matches_the_frozen_reference_on_recorded_cases"]),
]
MDD033_ACCEPTANCE = [
    ("a cursor binds snapshot, session, catalog_epoch, query and schema; other scope or an old generation fails explicitly",
     ["native_cursor_binds_every_identity_component", "forged_worker_generation_is_rejected",
      "a_new_worker_generation_invalidates_older_cursors", "definitions_and_bindings_do_not_cross_sessions",
      "a_bridge_over_another_snapshot_is_refused_at_construction"]),
    ("catalog_epoch is a decimal u64 string and a running cursor is never migrated to a new TEMP definition",
     ["a_native_cursor_keeps_the_definition_it_was_prepared_with"]),
    ("the same SQL with the same row count and schema over a changed source cannot be stitched into mixed pages",
     ["same_sql_same_schema_different_source_cannot_be_stitched",
      "a_redefinition_between_pages_is_refused_instead_of_stitching_two_definitions",
      "a_changed_row_count_under_the_same_statement_shape_is_refused_as_a_changed_total",
      "a_changed_definition_shape_between_pages_is_refused_as_a_different_statement"]),
    ("compatible-offset re-execution cost and stability are explicit and a native cursor is not presented as it",
     ["compat_offset_walks_pages_with_lookahead_and_no_cursor",
      "a_compatible_offset_sequence_over_a_definition_completes_and_counts_its_reexecutions",
      "compat_offset_budget_and_epoch_observation_are_explicit",
      "exhausting_the_row_budget_is_reported_not_presented_as_the_end",
      "paging_modes_never_share_a_token"]),
    ("TEMP catalog cycles, IF NOT EXISTS, DROP, redefinition and cross-session isolation behave like the validated profile",
     ["temp_scenarios_match_the_recorded_a0_behaviour",
      "a_name_that_is_only_an_output_alias_is_not_a_dependency",
      "volatile_definitions_and_unreadable_bodies_are_refused_without_a_catalog_change"]),
]


def sha256(path: str) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def run_tests(raw_dir: Path) -> dict:
    started = datetime.now(timezone.utc).isoformat()
    done = subprocess.run(COMMAND, cwd=ROOT, capture_output=True, check=False)
    finished = datetime.now(timezone.utc).isoformat()
    raw_dir.mkdir(parents=True, exist_ok=True)
    log = done.stdout + b"\n--- stderr ---\n" + done.stderr
    log_path = raw_dir / "mdd032-033-lib-tests.log"
    log_path.write_bytes(log)
    text = log.decode("utf-8", "replace")
    results = {}
    for name, outcome in re.findall(r"^test (\S+) \.\.\. (\w+)", text, re.M):
        results[name] = outcome
    totals = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored", text)
    return {
        "command": COMMAND,
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
    hits = [(name, outcome) for name, outcome in results.items() if name.endswith("::" + suffix) or name == suffix]
    if len(hits) != 1:
        return (suffix, "not_run" if not hits else f"ambiguous({len(hits)})")
    return hits[0][0], hits[0][1]


def acceptance_rows(table, results) -> list:
    rows = []
    for statement, names in table:
        proofs = []
        for suffix in names:
            full, outcome = lookup(results, suffix)
            proofs.append({"test": full, "outcome": outcome})
        rows.append({"acceptance": statement, "tests": proofs,
                     "all_passed": all(p["outcome"] == "ok" for p in proofs)})
    return rows


def build_032(run: dict) -> dict:
    variants = json.loads((ROOT / VARIANTS).read_text(encoding="utf-8"))
    golden = json.loads((ROOT / GOLDEN).read_text(encoding="utf-8"))
    paging = json.loads((ROOT / PAGING_CASES).read_text(encoding="utf-8"))
    titles = {}
    for line in (ROOT / QUERIES).read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        titles[entry["id"]] = {"title": entry["title"], "required_profile": entry["required_profile"]}
    compared = run["results"].get("provider::hostlab::tests::hostlab_variants_match_the_a0_golden_results") == "ok"
    families = {}
    if len(variants["variants"]) != len(golden["cases"]):
        raise SystemExit("golden and variants differ in length; regenerate the golden")
    for variant, case in zip(variants["variants"], golden["cases"]):
        if (variant["family"], variant["variant"]) != (case["family"], case["variant"]):
            raise SystemExit(f"golden is out of step with {VARIANTS}: {variant['variant']} vs {case['variant']}")
        statements = [s for page in case["pages"] for s in page["statements"]]
        families.setdefault(case["family"], []).append({
            "variant": case["variant"],
            "statement_count": len(case["statements"]),
            "window": {"limit": case["limit"], "offset": case["offset"], "walk": case["walk"]},
            "pages": len(case["pages"]),
            "rows_returned": sum(len(s["rows"]) for s in statements),
            "a0_total_rows": [s["total_rows"] for s in case["pages"][0]["statements"]],
            "engine_vs_a0": "cell_equal" if compared else "not_verified",
        })
    return {
        "schema_version": "mdd.hostlab-query-matrix.v1",
        "task": "MDD-032",
        "kind": "development evidence; admits no profile",
        "reference": {"backend": "dexsql 0.1.0 (frozen A0)", "sha256": golden["a0_sha256"],
                      "role": "independent oracle for expected values; never used to produce engine results"},
        "inputs": variants["inputs"],
        "sources": {path: sha256(path) for path in (VARIANTS, GOLDEN, PAGING_CASES, QUERIES)},
        "comparison": {"engine_cells_equal_to_a0": compared, "variants": len(variants["variants"]),
                       "pages": sum(len(c["pages"]) for c in golden["cases"]),
                       "rejections_checked": len(golden["rejections"]),
                       "paging_blocker_cases": len(paging["cases"])},
        "families": [
            {"family": family, **titles.get(family, {}), "variants": rows}
            for family, rows in sorted(families.items())
        ] + [{"family": "Q16", **titles["Q16"], "variants": [],
              "status": "outside hostlab-audit-v1; session TEMP behaviour is recorded in artifacts/mdd-033/paging-isolation.json"}],
        "rejections": [{"name": r["name"], "a0_refused": r["refused"],
                        "a0_failing_statement": (r.get("error") or {}).get("statement_index")}
                       for r in golden["rejections"]],
        "acceptance": acceptance_rows(MDD032_ACCEPTANCE, run["results"]),
        "not_covered": [
            "Q16 named_temp_queries tool argument",
            "recursive CTE (engine refuses with RECURSIVE_CTE_NOT_YET_QUALIFIED; no frozen template uses it)",
            "GLOB operator (engine refuses with BINARY_OPERATOR_NOT_IMPLEMENTED; no frozen template uses it)",
            "double-quoted string literals: the reference falls back to a string literal for an unknown double-quoted identifier, the engine refuses it",
            "NaN payload bits of value_f64 (the reference MCP JSON cannot carry them; compared in the CLI readback test)",
        ],
        "run": {k: v for k, v in run.items() if k != "results"},
    }


def build_033(run: dict) -> dict:
    scenarios = json.loads((ROOT / SCENARIOS).read_text(encoding="utf-8"))
    return {
        "schema_version": "mdd.paging-isolation.v1",
        "task": "MDD-033",
        "kind": "development evidence; admits no profile",
        "reference": {"backend": "dexsql 0.1.0 (frozen A0)", "sha256": scenarios["a0_sha256"]},
        "sources": {SCENARIOS: sha256(SCENARIOS)},
        "scenario_replay": {
            "scenarios": len(scenarios["scenarios"]),
            "steps": sum(len(s["steps"]) for s in scenarios["scenarios"]),
            "a0_refusals": sum(1 for s in scenarios["scenarios"] for st in s["steps"] if "error" in st["a0"]),
            "engine_matches_a0_on_every_step": run["results"].get(
                "provider::hostlab::temp_tests::temp_scenarios_match_the_recorded_a0_behaviour") == "ok",
            "names": [s["name"] for s in scenarios["scenarios"]],
        },
        "acceptance": acceptance_rows(MDD033_ACCEPTANCE, run["results"]),
        "declared_divergences_from_a0": [
            {"id": "compatible-offset-redefinition-is-refused",
             "reference": "page 2 is answered from the new definition: rows 1-2 'before', rows 3-4 'after' in one sequence (scenario paging_across_a_redefinition)",
             "engine": "the page source identity carries the digest of the TEMP definitions the statement was expanded with, so the sequence is refused as source_changed; a native cursor keeps its own definition",
             "tests": ["a_redefinition_between_pages_is_refused_instead_of_stitching_two_definitions",
                       "a_native_cursor_keeps_the_definition_it_was_prepared_with"]},
            {"id": "volatile-definitions-are-refused",
             "reference": "random() in a definition body is refused by the read-only subset; CURRENT_TIMESTAMP is refused as well (scenario volatile_bodies)",
             "engine": "any volatile call or clock keyword in a definition body is refused before the catalog changes",
             "tests": ["volatile_definitions_and_unreadable_bodies_are_refused_without_a_catalog_change"]},
            {"id": "definitions-are-late-bound-not-materialized",
             "reference": "a TABLE defined over another table sees that table's later redefinition (scenario views_and_tables_are_late_bound)",
             "engine": "identical; the catalog stores the query and its fingerprint, nothing is materialized",
             "tests": ["temp_scenarios_match_the_recorded_a0_behaviour"]},
        ],
        "not_covered": [
            "transport wiring: no MCP/CLI entry point calls TempSqlSession or the cursor APIs yet",
            "mdd.result.v1 carries no offset field by design; compatible offsets are request-side",
            "named_temp_queries tool argument of the reference query tool",
            "recursive CTE inside a definition (the engine refuses recursive CTEs everywhere)",
        ],
        "run": {k: v for k, v in run.items() if k != "results"},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, default=ROOT / "artifacts/local/mdd-032-033-runs-20261112")
    args = parser.parse_args()
    run = run_tests(args.raw_dir)
    for target, document in (("artifacts/mdd-032/hostlab-query-matrix.json", build_032(run)),
                             ("artifacts/mdd-033/paging-isolation.json", build_033(run))):
        path = ROOT / target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
        unproven = [a["acceptance"] for a in document["acceptance"] if not a["all_passed"]]
        print(f"{target}: acceptance rows={len(document['acceptance'])} unproven={len(unproven)}")
    print(f"tests: exit={run['exit_code']} passed={run['passed']} failed={run['failed']} targets={run['targets']}")
    return 0 if run["exit_code"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
