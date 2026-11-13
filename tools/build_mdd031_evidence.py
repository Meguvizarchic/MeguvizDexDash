#!/usr/bin/env python3
"""Build the MDD-031 SQL bridge conformance records.

Usage: python tools/build_mdd031_evidence.py [--raw-dir DIR]

Writes conformance/query/sql-semantics.json (what the bridge's SQL semantics are,
read from source constants and the independent oracle files) and
artifacts/mdd-031/sql-bridge-conformance.json (each acceptance clause with the
named tests that prove it and their outcome in a run made now).

It reuses the test runner of build_mdd032_033_evidence.py, so a clause whose test
did not run or did not pass is recorded as such. The records are development
evidence and admit no profile.
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
ORACLE = "artifacts/mdd-031-audit/gap-closure-20261111/oracle/oracle-results.json"
A0_GOLDEN = "conformance/corpus/hostlab/expected-results/hostlab-a0-golden.json"
POLICY_SOURCE = "crates/mdd-sql/src/virtual_tables/mod.rs"
DIALECT_SOURCE = "crates/mdd-sql/src/dialects/mod.rs"

ACCEPTANCE = [
    ("no full facts ETL as the default access path; load and lazy-build cost is inside the measured budget",
     ["schema_prewarm_preserves_limits_and_never_opens_facts",
      "owned_cursor_is_lazy_and_preserves_multiplicity_and_nul",
      "lazy_scan_cost_is_measured_after_prepare",
      "coverage_ledger_gates_each_relation_on_the_layers_that_prove_it"]),
    ("NULL, CAST, LIKE/ESCAPE, string length, comparison, aggregate, ORDER, JOIN/CTE verified per declared dialect",
     ["dialect_feature_matrix_matches_sqlite_for_null_cast_like_length_compare_aggregate_order_join_cte",
      "hostlab_q_series_shapes_match_sqlite_per_dialect",
      "native_v1_integer_cast_requires_exact_text_and_diverges_from_sqlite_prefix",
      "hostlab_variants_match_the_a0_golden_results"]),
    ("omit, orderByConsumed, LIMIT/OFFSET and IN pushdown only with full equivalence evidence; a candidate filter never claims exact handling",
     ["pushdown_policy_matches_vtab_capabilities_and_results_match_sqlite"]),
    ("syntax, binding and input errors are separate from real unsupported; no regex rewriting of user SQL",
     ["sql_authority_and_real_errors_are_not_success_or_unsupported",
      "unsupported_function_in_visible_cte_keeps_real_binding_errors",
      "known_unsupported_forms_fail_closed_with_the_unsupported_classification",
      "compatibility_failure_preserves_counterexample_without_profile_admission"]),
    ("every query binds one snapshot/session; a compatibility failure keeps its counterexample and blocks the declared profile",
     ["cross_scope_execute_is_rejected",
      "a_bridge_over_another_snapshot_is_refused_at_construction",
      "unsupported_query_blocks_declared_profile_and_preserves_counterexample",
      "non_compatibility_failures_never_block_profile",
      "execute_stage_gap_blocks_profile_for_prepared_statement",
      "profile_block_is_scoped_to_declared_profile_and_registry"]),
]

# Forms the reference answers and the engine refuses; pinned by the named test.
FAIL_CLOSED = [
    {"form": "GLOB operator", "classification": "UnsupportedQuery"},
    {"form": "recursive CTE", "classification": "UnsupportedQuery"},
    {"form": "abs()", "classification": "UnsupportedQuery"},
    {"form": "trim()", "classification": "UnsupportedQuery"},
    {"form": "total()", "classification": "UnsupportedQuery"},
    {"form": "unknown double-quoted identifier as a string literal", "classification": "InvalidArgument (binding error)"},
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


def policy() -> dict:
    text = (ROOT / POLICY_SOURCE).read_text(encoding="utf-8")
    block = re.search(r"VTB_POLICY: VtabPolicy = VtabPolicy \{(.*?)\};", text, re.S)
    if not block:
        raise SystemExit("VTB_POLICY not found; the pushdown record cannot be built")
    fields = dict(re.findall(r"(\w+):\s*(true|false)", block.group(1)))
    return {name: value == "true" for name, value in fields.items()}


def dialects() -> list:
    text = (ROOT / DIALECT_SOURCE).read_text(encoding="utf-8")
    body = re.search(r"pub enum SqlDialect \{(.*?)\}", text, re.S)
    if not body:
        raise SystemExit("SqlDialect not found")
    return [name for name in re.findall(r"^\s*(\w+),", body.group(1), re.M)]


def sqlite_build() -> dict:
    lock = (ROOT / "Cargo.lock").read_text(encoding="utf-8")
    found = re.search(r'name = "libsqlite3-sys"\nversion = "([^"]+)"', lock)
    return {"libsqlite3_sys": found.group(1) if found else None, "bundled": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, default=ROOT / "artifacts/local/mdd-031-runs-20261113")
    args = parser.parse_args()
    sibling = load_sibling()
    run = sibling.run_tests(args.raw_dir)
    oracle = json.loads((ROOT / ORACLE).read_text(encoding="utf-8"))
    flags = policy()
    semantics = {
        "schema_version": "mdd.sql-semantics.v1",
        "task": "MDD-031",
        "kind": "development evidence; admits no profile",
        "engine_sqlite": sqlite_build(),
        "dialects": dialects(),
        "pushdown_policy": {**flags, "all_disabled": not any(flags.values()),
                            "source": POLICY_SOURCE,
                            "meaning": "xFilter receives argv_index 0 and SQLite performs every filter, sort, LIMIT, OFFSET and IN itself; nothing is claimed as exactly handled"},
        "independent_oracles": [
            {"name": "python stdlib sqlite3", "sqlite_version": oracle["sqlite_version"], "file": ORACLE,
             "sha256": sha256(ORACLE), "scope": oracle["scope"], "q_series_shapes": len(oracle["q_series"]),
             "feature_shapes": len(oracle["features"]), "integer_cast_cases": len(oracle["sqlite_integer_cast"])},
            {"name": "frozen A0 dexsql 0.1.0", "file": A0_GOLDEN, "sha256": sha256(A0_GOLDEN),
             "scope": "DexSql011 only: 77 variants over three synthetic DEX fixtures"},
        ],
        "documented_dialect_policy": [
            {"dialect": "NativeV1", "behavior": "CAST of text to INTEGER requires exact text (INVALID_INTEGER_CAST); SQLite and the legacy dialects use the numeric prefix",
             "test": "native_v1_integer_cast_requires_exact_text_and_diverges_from_sqlite_prefix"},
            {"dialect": "NativeV1", "behavior": "unaliased result expressions keep SQLite's expression-text names and result names keep their case; the DexSql dialects follow the reference (`column`, function name, ASCII lower case)",
             "test": "hostlab_variants_match_the_a0_golden_results"},
        ],
        "fail_closed_gaps": [{**gap, "test": "known_unsupported_forms_fail_closed_with_the_unsupported_classification"}
                             for gap in FAIL_CLOSED],
    }
    rows = sibling.acceptance_rows(ACCEPTANCE, run["results"])
    conformance = {
        "schema_version": "mdd.sql-bridge-conformance.v1",
        "task": "MDD-031",
        "kind": "development evidence; admits no profile",
        "sources": {ORACLE: sha256(ORACLE), A0_GOLDEN: sha256(A0_GOLDEN), POLICY_SOURCE: sha256(POLICY_SOURCE)},
        "acceptance": rows,
        "residual": [
            "acceptance 3 holds because no pushdown is enabled (all four flags are false and the xBestIndex report is asserted); enabling any of them later needs its own equivalence evidence and a changed constant",
            "wall-clock and RSS of a real-APK lazy fact build are not measured here: the budget accounting is (steps, scanned rows, result bytes), and formal performance comparison belongs to the exclusive-measurement task MDD-082",
            "the independent feature oracle runs on synthetic rows and the frozen HostLab Q-series shapes; DexSql010 and NativeV1 have no reference backend beyond SQLite itself",
            "the fail-closed gaps listed in sql-semantics.json are real functionality the reference has; none is used by a frozen HostLab template",
        ],
        "run": {k: v for k, v in run.items() if k != "results"},
    }
    for target, document in (("conformance/query/sql-semantics.json", semantics),
                             ("artifacts/mdd-031/sql-bridge-conformance.json", conformance)):
        path = ROOT / target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    unproven = [r["acceptance"] for r in rows if not r["all_passed"]]
    print(f"acceptance rows={len(rows)} unproven={len(unproven)} dialects={semantics['dialects']} "
          f"pushdown_all_disabled={semantics['pushdown_policy']['all_disabled']}")
    print(f"tests: exit={run['exit_code']} passed={run['passed']} failed={run['failed']}")
    return 0 if run["exit_code"] == 0 and not unproven else 1


if __name__ == "__main__":
    sys.exit(main())
