#!/usr/bin/env python3
"""Build the MDD-026 closure record: acceptance clauses -> named tests -> outcomes now.

Usage: python -I tools/build_mdd026_evidence.py [--raw-dir DIR]

Runs the library tests of mdd-facts, mdd-dex and mdd-sql, checks that the committed
column qualification (tools/qualify_columns_from_differential.py) is current with the
files it was computed from, and writes
artifacts/mdd-026/column-qualification-20261113/conformance.json. The qualification
itself needs the local-only merged matrix and is regenerated separately; this builder
only verifies that the committed result still matches its inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = "artifacts/mdd-026/column-qualification-20261113"
COMMAND = ["cargo", "test", "--offline", "--locked", "-p", "mdd-facts", "-p", "mdd-dex", "-p", "mdd-sql", "--lib"]

ACCEPTANCE = [
    ("candidate indexes never miss a hit; every approximate candidate passes an exact predicate before it enters a result",
     ["utf16_raw_candidates_match_scalar_and_hand_oracle_without_occurrence_dedup",
      "exhaustive_candidate_probe_for_independent_code_unit_oracle",
      "scalar_reference_scan_is_independent_of_lazy_candidate_failure",
      "raw_mutf8_reference_index_preserves_exact_sites_and_source_occurrences",
      "string_utf16_reference_index_preserves_nonscalar_sites_and_occurrences",
      "definition_name_postings_use_utf16_code_unit_order",
      "type_descriptor_reference_index_preserves_exact_sites_and_occurrences",
      "callsite_encoded_byte_key_keeps_same_content_and_all_occurrence_sites"]),
    ("lazy build, concurrent first build and error retry have one auditable terminal state; an unbuilt index is never read as zero facts",
     ["concurrent_first_build_publishes_one_immutable_terminal",
      "panic_quota_deadline_failures_are_audited_without_implicit_retry",
      "joined_failed_attempt_survives_immediate_ready_retry",
      "index_quota_deadline_and_unbuilt_failures_never_publish_ready_or_zero",
      "exact_class_lookup_exposes_scope_and_rejects_unbuilt_coverage",
      "coverage_retains_late_genuine_errors_and_rejects_terminal_overwrite"]),
    ("the input/facts three-state coverage of required_layers and scope_id is recomputable and a failed required layer blocks a complete result",
     ["missing_provider_object_is_unknown_not_complete",
      "provider_gate_rejection_reports_unknown_with_provider_error",
      "unmapped_relation_is_never_gated_to_complete",
      "relation_request_fills_columns_and_scope_request_stays_layer_only",
      "coverage_for_relations_fills_columns_and_uses_the_provider_gate",
      "fine_coverage_parameter_positions_projection_bodies_source_and_resource",
      "explicit_subset_negative_proof_and_foreign_generation_are_bounded",
      "coverage_ledger_gates_each_relation_on_the_layers_that_prove_it",
      "source_error_scope_detail_is_preserved"]),
    ("every required HostLab fact has field/type, NULL, order, multiplicity, source and raw-fingerprint evidence (see the column qualification below)",
     ["newly_assembled_columns_keep_contract_type_and_nullability",
      "relation_projections_match_contract_columns_types_and_nullability",
      "every_relation_matches_the_recorded_a0_readback_row_for_row",
      "a0_differential_over_the_fixture_corpus_has_only_declared_divergences",
      "dex_file_provenance_matches_recorded_a0_entries",
      "every_field_referencing_opcode_is_a_get_or_a_put"]),
    ("verified through hand fixtures, independent oracles and the scalar path, not a parser compared with itself",
     ["utf16_raw_candidates_match_scalar_and_hand_oracle_without_occurrence_dedup",
      "exhaustive_candidate_probe_for_independent_code_unit_oracle",
      "hostlab_variants_match_the_a0_golden_results",
      "a0_differential_over_the_fixture_corpus_has_only_declared_divergences",
      "param_descriptors_match_recorded_a0_rows",
      "methods_rows_assemble_all_contract_columns_and_match_recorded_a0"]),
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


def qualification_status() -> dict:
    """Is the committed qualification still computed from the files in the tree?"""
    record = json.loads((ROOT / OUT / "column-qualification.json").read_text(encoding="utf-8"))
    stale = []
    for name in ("a0_corpus", "engine_equal_records", "recorded_a0_provenance"):
        item = record["inputs"][name]
        if sha256(item["path"]) != item["sha256"]:
            stale.append(name)
    summary = record["summary"]
    return {
        "file": f"{OUT}/column-qualification.json",
        "file_sha256": sha256(f"{OUT}/column-qualification.json"),
        "merged_matrix_v10_sha256": record["inputs"]["merged_matrix_v10"]["sha256"],
        "inputs_current": not stale,
        "stale_inputs": stale,
        "columns": summary["columns"],
        "satisfied_in_all_six_by_base": summary["satisfied_in_all_six_by_base"],
        "satisfied_in_all_six_after_fold": summary["satisfied_in_all_six_after_fold"],
        "declared_not_applicable": summary["declared_not_applicable"],
        "unresolved": summary["unresolved"],
        "not_raised_by_fold": summary["not_raised_by_fold"],
    }


def run_tool_tests() -> dict:
    """The negative controls of the qualification tool (unittest assertions, immune to -O)."""
    command = [sys.executable, "-I", "tools/test_qualify_columns_from_differential.py"]
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", check=False)
    tail = done.stderr.strip().splitlines()[-3:]
    return {"command": ["python", "-I", "tools/test_qualify_columns_from_differential.py"],
            "exit_code": done.returncode, "summary": tail}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, default=ROOT / "artifacts/local/mdd-026-runs-20261113")
    args = parser.parse_args()
    sibling = load_sibling()
    sibling.COMMAND = COMMAND
    run = sibling.run_tests(args.raw_dir)
    rows = sibling.acceptance_rows(ACCEPTANCE, run["results"])
    qualification = qualification_status()
    tool_tests = run_tool_tests()
    document = {
        "schema_version": "mdd.facts-qualification-conformance.v1",
        "task": "MDD-026",
        "kind": "development evidence; admits no profile",
        "acceptance": rows,
        "column_qualification": qualification,
        "qualification_tool_negative_controls": {
            **tool_tests,
            "mutation_results": f"{OUT}/mutation/results.txt",
            "mutation_script": f"{OUT}/mutation/mutate_qualify.py",
        },
        "residual": [
            "the typed-IR executor path (mdd-query) requests layers only; column-level coverage is wired for the HostLab SQL provider path",
            "column evidence rests on the 185 fixture inputs of the A0 differential, the recorded A0 readback and the fix-round harnesses; no private workload or real APK corpus",
            "the fold of differential evidence into the six categories is a policy choice recorded in the qualification file; it can be reversed by regenerating without it",
            "dex_files.file_id and dex_files.string_pool_id multiplicity is declared not_applicable (unique occurrence coordinates), not proven",
            "the 2026-10-28 qualification generator conformance/facts/qualify.py stays a historical record and still fails on source drift by design",
        ],
        "run": {k: v for k, v in run.items() if k != "results"},
    }
    target = ROOT / OUT / "conformance.json"
    target.write_text(json.dumps(document, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    unproven = [r["acceptance"] for r in rows if not r["all_passed"]]
    print(f"acceptance rows={len(rows)} unproven={len(unproven)} tests: exit={run['exit_code']} "
          f"passed={run['passed']} failed={run['failed']} qualification: inputs_current={qualification['inputs_current']} "
          f"unresolved={qualification['unresolved']} tool_tests_exit={tool_tests['exit_code']}")
    for item in unproven:
        print("UNPROVEN:", item)
    ok = (run["exit_code"] == 0 and not unproven and qualification["inputs_current"]
          and not qualification["unresolved"] and tool_tests["exit_code"] == 0)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
