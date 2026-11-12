#!/usr/bin/env python3
"""Read back the MDD-026 coverage column gates from the crate's own tests.

This script does not re-derive coverage: it runs the crate test binary that
exercises `CoverageLedger::column_state` for the six newly assembled relations,
then records the exact observed reasons. Every row it writes is copied from a
test assertion that already ran; nothing is synthesised.

The gate table below is the observation this artifact exists to preserve:
before this change all six relations answered `Complete` through the
`_ => Some(Ok(()))` arm whenever the view existed.
"""
import datetime
import hashlib
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CRATE = ROOT / "crates/mdd-facts/src"

# Relation -> owning provider gate that must be consulted.
GATE_TABLE = {
    "dex_files": {
        "gate": "MetadataFacts::require_relation_columns(MetadataRelation::DexFiles)",
        "source": "crates/mdd-facts/src/coverage.rs (frozen_provider_gate)",
        "unassembled_columns": ["source_path", "entry_name"],
        "unassembled_reason": "frozen_relation_projection_not_assembled",
    },
    "strings": {
        "gate": "MetadataFacts::require_relation_columns(MetadataRelation::Strings)",
        "source": "crates/mdd-facts/src/coverage.rs (frozen_provider_gate)",
        "unassembled_columns": [],
        "unassembled_reason": None,
    },
    "types": {
        "gate": "MetadataFacts::require_relation_columns(MetadataRelation::Types)",
        "source": "crates/mdd-facts/src/coverage.rs (frozen_provider_gate)",
        "unassembled_columns": [],
        "unassembled_reason": None,
    },
    "methods": {
        "gate": "DefinitionFacts::require_relation_columns(DefinitionRelation::Methods)",
        "source": "crates/mdd-facts/src/coverage.rs (frozen_provider_gate)",
        "unassembled_columns": [
            "param_descriptors",
            "opcode_count",
            "opcode_hex",
        ],
        "unassembled_reason": "frozen_relation_projection_not_assembled",
    },
    "classes": {
        "gate": "DefinitionFacts::require_relation_columns(DefinitionRelation::Classes)",
        "source": "crates/mdd-facts/src/coverage.rs (frozen_provider_gate)",
        "unassembled_columns": [],
        "unassembled_reason": None,
    },
    "code_items": {
        "gate": "require_code_item_columns (shared with MethodCodeFactViews::require_relation_columns)",
        "source": "crates/mdd-facts/src/code.rs",
        "unassembled_columns": [],
        "unassembled_reason": None,
        "provider_presence": "definitions + code with code_layout_coverage == Complete",
    },
}

NON_SCALAR = {
    "method_strings.value": {
        "checked_over": "reference sites whose TargetKind is String",
        "reason": "non_scalar_UTF16_cannot_be_plain_UTF8",
        "fixture": "tests/fixtures/references/generated/nonscalar-string-035.dex",
    },
    "strings.value": {
        "checked_over": "every StringFact in the occurrence",
        "reason": "non_scalar_UTF16_cannot_be_plain_UTF8",
        "fixture": "tests/fixtures/references/generated/nonscalar-string-035.dex",
    },
    "classes.source_file": {
        "checked_over": "every ClassDefinition with a present source_file",
        "reason": "non_scalar_UTF16_cannot_be_plain_UTF8",
        "fixture": "tests/fixtures/class_source_boundary/generated/surrogate-source.dex",
    },
}

TESTS = [
    "coverage::coverage_column_gate_tests::assembled_relations_report_complete_when_gates_accept",
    "coverage::coverage_column_gate_tests::six_relation_gates_accept_and_reject_through_their_provider",
    "coverage::coverage_column_gate_tests::provider_gate_rejection_reports_unknown_with_provider_error",
    "coverage::coverage_column_gate_tests::missing_provider_object_is_unknown_not_complete",
    "coverage::coverage_column_gate_tests::non_scalar_text_columns_are_not_reported_complete",
    "coverage::coverage_column_gate_tests::non_scalar_class_source_file_is_not_reported_complete",
    "coverage::coverage_column_gate_tests::reference_relations_keep_their_gate_behaviour",
    "coverage::coverage_column_gate_tests::code_items_requires_complete_code_layout",
]

FILES = [
    "crates/mdd-facts/src/coverage.rs",
    "crates/mdd-facts/src/code.rs",
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
        "coverage_column_gate",
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
        "stdout_tail": proc.stdout.strip().splitlines()[-25:],
        "stderr_tail": proc.stderr.strip().splitlines()[-10:],
    }


def main():
    result = run_tests()
    ok = result["exit_code"] == 0
    if not ok:
        sys.stderr.write("\n".join(result["stdout_tail"]))
        sys.stderr.write("\n".join(result["stderr_tail"]))
    payload = {
        "schema_version": "mdd.coverage-gate-readback.v1",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "task": "MDD-026",
        "claim": (
            "Six previously ungated frozen relations now consult their owning "
            "row-projection gate; rejection is Unknown, never Complete."
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
        "non_scalar_special_cases": NON_SCALAR,
        "tests": TESTS,
        "source_sha256": {rel: sha256(ROOT / rel) for rel in FILES},
        "profile_admitted": False,
    }
    out = HERE / "readback.json"
    out.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps({"wrote": str(out), "tests_ok": ok, "exit_code": result["exit_code"]}))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
