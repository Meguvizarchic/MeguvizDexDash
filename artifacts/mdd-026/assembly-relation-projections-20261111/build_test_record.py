#!/usr/bin/env python3
"""Record the exact verification commands and their observed results."""
import datetime
import hashlib
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[3]
HERE = pathlib.Path(__file__).resolve().parent

NEW_TESTS = [
    "metadata::tests::dex_file_rows_project_validated_raw_header_words",
    "metadata::tests::dex_file_relation_rejects_provenance_columns_and_star",
    "metadata::tests::string_rows_preserve_dex_order_and_lossless_text",
    "metadata::tests::type_rows_use_exact_descriptor_display_names",
    "metadata::tests::relation_projections_match_contract_columns_types_and_nullability",
    "metadata::tests::method_relation_keeps_restricted_columns_rejected",
    "definitions::tests::methods_and_classes_wildcard_columns_match_frozen_reference_schema",
    "definitions::tests::method_rows_preserve_reference_only_nulls_and_definition_join",
    "definitions::tests::class_rows_match_independent_raw_class_def_oracle",
    "definitions::tests::class_rows_project_encoded_no_index_as_genuine_null",
    "code::tests::code_item_rows_match_independent_raw_header_oracle",
    "code::tests::code_item_rows_expand_shared_bodies_once_per_method_owner",
    "indexes::tests::index_quota_deadline_and_unbuilt_failures_never_publish_ready_or_zero",
]


def run(argv):
    completed = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True)
    return {
        "argv": argv,
        "exit_code": completed.returncode,
        "stdout_tail": completed.stdout.strip().splitlines()[-1:] ,
        "stderr_tail": completed.stderr.strip().splitlines()[-3:],
    }


def main():
    test_run = run(
        ["cargo", "test", "-p", "mdd-facts", "--lib", "--locked", "--offline"]
    )
    clippy = run(
        ["cargo", "clippy", "-p", "mdd-facts", "--lib", "--locked", "--offline"]
    )
    workspace = run(["cargo", "check", "--workspace", "--locked", "--offline"])
    named = run(
        [
            "cargo",
            "test",
            "-p",
            "mdd-facts",
            "--lib",
            "--locked",
            "--offline",
            "--",
            "--list",
        ]
    )
    available = set(named["stdout_tail"] and [] or [])
    listed = subprocess.run(
        ["cargo", "test", "-p", "mdd-facts", "--lib", "--locked", "--offline", "--", "--list"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    ).stdout
    present = [name for name in NEW_TESTS if name + ":" in listed]
    missing = [name for name in NEW_TESTS if name not in present]

    report = {
        "schema_version": "mdd.relation-projection-test-record.v1",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "task": "MDD-026",
        "commands": {
            "unit_tests": test_run,
            "clippy": clippy,
            "workspace_check": workspace,
        },
        "new_tests": present,
        "missing_tests": missing,
        "changed_sources": {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [
                ROOT / "crates/mdd-facts/src/metadata.rs",
                ROOT / "crates/mdd-facts/src/definitions.rs",
                ROOT / "crates/mdd-facts/src/code.rs",
                ROOT / "crates/mdd-facts/src/indexes/columns.rs",
                ROOT / "crates/mdd-facts/src/indexes/tests.rs",
            ]
        },
        "not_run": [
            "HostLab workload and private inputs (out of scope for this task)",
            "SQL transport qualification (no mdd-sql change was authorised)",
            "performance measurement (no performance claim is made)",
        ],
        "task_complete_proven": False,
        "profile_admitted": False,
    }
    (HERE / "test-record.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps({key: value["exit_code"] for key, value in report["commands"].items()}, indent=1))
    print("new tests present:", len(present), "missing:", missing)


if __name__ == "__main__":
    main()
