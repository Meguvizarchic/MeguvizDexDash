#!/usr/bin/env python3
"""Read back the seven fallback relation gates from the crate's own tests.

This script does not re-derive coverage. It runs the crate tests that exercise
`CoverageLedger::column_state`, `CoverageLedger::frozen_provider_gate` and the
production `SnapshotFactIndex::coverage_for_relations` entry point, then records
the exact observed reasons and the gate wiring table. Every row below is copied
from a test assertion that already ran.

The wiring table is the observation this artifact preserves: before this change
seven relations answered `Complete` through the unconditional
`_ => Some(Ok(()))` arm whenever the view and its layers existed.
"""
import datetime
import hashlib
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

# Relation -> owning provider gate consulted by `frozen_provider_gate`.
GATE_TABLE = {
    "dex_files": {
        "gate": "MetadataFacts::require_relation_columns(MetadataRelation::DexFiles)",
        "provider": "metadata",
        "status": "gated_before_this_round",
    },
    "strings": {
        "gate": "MetadataFacts::require_relation_columns(MetadataRelation::Strings)",
        "provider": "metadata",
        "status": "gated_before_this_round",
    },
    "types": {
        "gate": "MetadataFacts::require_relation_columns(MetadataRelation::Types)",
        "provider": "metadata",
        "status": "gated_before_this_round",
    },
    "methods": {
        "gate": "DefinitionFacts::require_relation_columns(DefinitionRelation::Methods)",
        "provider": "definitions",
        "status": "gated_before_this_round",
    },
    "classes": {
        "gate": "DefinitionFacts::require_relation_columns(DefinitionRelation::Classes)",
        "provider": "definitions",
        "status": "gated_before_this_round",
    },
    "code_items": {
        "gate": "require_code_item_columns (shared with MethodCodeFactViews::require_relation_columns)",
        "provider": "definitions + code (code_layout_coverage == Complete)",
        "status": "gated_before_this_round",
    },
    "class_interfaces": {
        "gate": "DefinitionFacts::require_relation_columns(DefinitionRelation::ClassInterfaces)",
        "provider": "definitions",
        "status": "new_in_this_round",
    },
    "class_fields": {
        "gate": "DefinitionFacts::require_relation_columns(DefinitionRelation::ClassFields)",
        "provider": "definitions",
        "status": "new_in_this_round",
    },
    "class_methods": {
        "gate": "DefinitionFacts::require_relation_columns(DefinitionRelation::ClassMethods)",
        "provider": "definitions",
        "status": "new_in_this_round",
    },
    "annotation_directory_entries": {
        "gate": "AnnotationFacts::require_relation_columns(AnnotationRelation::DirectoryEntries)",
        "provider": "annotations",
        "status": "new_in_this_round",
    },
    "annotation_set_entries": {
        "gate": "AnnotationFacts::require_relation_columns(AnnotationRelation::SetEntries)",
        "provider": "annotations",
        "status": "new_in_this_round",
    },
    "annotations": {
        "gate": "AnnotationFacts::require_relation_columns(AnnotationRelation::Annotations)",
        "provider": "annotations",
        "status": "new_in_this_round",
    },
    "annotation_elements": {
        "gate": "AnnotationFacts::require_relation_columns(AnnotationRelation::Elements)",
        "provider": "annotations",
        "status": "new_in_this_round",
    },
    "method_strings": {
        "gate": "ReferenceFacts::require_relation_columns(ReferenceRelation::MethodStrings)",
        "provider": "references",
        "status": "inline_gate_unchanged",
    },
    "method_calls": {
        "gate": "ReferenceFacts::require_relation_columns(ReferenceRelation::MethodCalls)",
        "provider": "references",
        "status": "inline_gate_unchanged",
    },
    "method_field_accesses": {
        "gate": "ReferenceFacts::require_relation_columns(ReferenceRelation::MethodFieldAccesses)",
        "provider": "references",
        "status": "inline_gate_unchanged",
    },
    "method_used_types": {
        "gate": "ReferenceFacts::require_relation_columns(ReferenceRelation::MethodUsedTypes)",
        "provider": "references",
        "status": "inline_gate_unchanged",
    },
}

FALLBACK_ARM = {
    "before": "_ => Some(Ok(()))  // no gate, therefore Complete",
    "after": "_ => None  // column_provider_not_built -> Unknown",
    "effective_change": (
        "The seven newly gated relations had spec columns exactly equal to their "
        "provider's available columns, so the verdict on today's schema is the "
        "same. The behaviour that changes is that a provider rejection or a "
        "missing provider object can no longer be reported as Complete."
    ),
}

COVERAGE_REQUEST_PATHS = {
    "for_scope": {
        "required_columns": "empty (unchanged)",
        "used_by": [
            "SnapshotFactIndex::require(layer)",
            "mdd-query ScopedCatalog prepare (CoverageRequest::for_scope)",
            "snapshot_fact_index_bench / index_bench raw coverage sample",
        ],
        "semantics": "layer completeness only; a complete layer is not a column claim",
    },
    "for_relations": {
        "required_columns": "every frozen column of the named relations",
        "required_layers": "layers that own those columns (Definitions and/or Annotations)",
        "domain": "ColumnDomain::FrozenProjection",
        "unknown_relation": "InvalidArgument (never a silent empty requirement)",
        "unassembled_columns": "included deliberately; a relation-level gap stays Unknown",
        "production_entry": "SnapshotFactIndex::coverage_for_relations",
        "wired_into_other_crates": False,
    },
}

PRECEDENCE = {
    "finding": (
        "A missing provider object does not reach the column gate through "
        "evaluate: column_state evaluates layers first, so layer_state already "
        "answers Unknown with required_fact_scope_not_built."
    ),
    "observed_reason_when_provider_missing": "required_fact_scope_not_built",
    "column_provider_not_built_reachable_when": (
        "the owning layer is Complete but the provider object is absent from the "
        "view; asserted by direct frozen_provider_gate calls returning Some(None)"
    ),
    "either_way": "Unknown, never Complete",
}

TESTS = [
    "coverage::coverage_column_gate_tests::seven_fallback_relations_are_gated_by_their_own_provider",
    "coverage::coverage_column_gate_tests::seven_fallback_relations_reject_and_report_gap_through_evaluate",
    "coverage::coverage_column_gate_tests::relation_request_fills_columns_and_scope_request_stays_layer_only",
    "coverage::coverage_column_gate_tests::assembled_relations_report_complete_when_gates_accept",
    "coverage::coverage_column_gate_tests::six_relation_gates_accept_and_reject_through_their_provider",
    "coverage::coverage_column_gate_tests::provider_gate_rejection_reports_unknown_with_provider_error",
    "coverage::coverage_column_gate_tests::missing_provider_object_is_unknown_not_complete",
    "coverage::coverage_column_gate_tests::non_scalar_text_columns_are_not_reported_complete",
    "coverage::coverage_column_gate_tests::non_scalar_class_source_file_is_not_reported_complete",
    "coverage::coverage_column_gate_tests::reference_relations_keep_their_gate_behaviour",
    "coverage::coverage_column_gate_tests::code_items_requires_complete_code_layout",
    "indexes::tests::coverage_for_relations_fills_columns_and_uses_the_provider_gate",
]

FILES = [
    "crates/mdd-facts/src/coverage.rs",
    "crates/mdd-facts/src/indexes/mod.rs",
    "crates/mdd-facts/src/indexes/tests.rs",
]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_tests():
    argv = [
        "cargo",
        "test",
        "--offline",
        "-p",
        "mdd-facts",
        "--lib",
        "--",
        "--test-threads=1",
    ]
    proc = subprocess.run(
        argv, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    return {
        "argv": argv,
        "cwd": str(ROOT),
        "exit_code": proc.returncode,
        "stdout_tail": proc.stdout.strip().splitlines()[-40:],
        "stderr_tail": proc.stderr.strip().splitlines()[-10:],
    }


def main():
    result = run_tests()
    ok = result["exit_code"] == 0
    if not ok:
        sys.stderr.write("\n".join(result["stdout_tail"]))
        sys.stderr.write("\n".join(result["stderr_tail"]))
    payload = {
        "schema_version": "mdd.coverage-fallback-gate-readback.v1",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "task": "MDD-026",
        "claim": (
            "Seven former fallback relations now consult their own row-projection "
            "gate; the unconditional Ok(()) arm is gone. The production "
            "coverage_for_relations entry fills required_columns from the frozen "
            "schema, while for_scope stays layer-only."
        ),
        "not_claimed": [
            "admitted",
            "task_complete_proven",
            "profile_issued",
            "release_authorized",
        ],
        "test_run": result,
        "tests_executed_ok": ok,
        "gate_table": GATE_TABLE,
        "fallback_arm": FALLBACK_ARM,
        "coverage_request_paths": COVERAGE_REQUEST_PATHS,
        "provider_precedence": PRECEDENCE,
        "tests": TESTS,
        "source_sha256": {rel: sha256(ROOT / rel) for rel in FILES},
        "profile_admitted": False,
    }
    out = HERE / "readback.json"
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"wrote": str(out), "tests_ok": ok, "exit_code": result["exit_code"]}))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
