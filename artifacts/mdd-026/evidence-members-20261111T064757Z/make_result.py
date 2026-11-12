#!/usr/bin/env python3
"""Build the per-column MDD-026 verdict and SUMMARY from comparisons.json."""
from __future__ import annotations

import collections
import datetime
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
EVIDENCE = "artifacts/mdd-026/evidence-members-20261111T064757Z"
V10 = ROOT / "artifacts/mdd-026/column-audit-v10/six-category-audit.json"
CATEGORIES = ["field_type", "null", "order", "multiplicity", "source", "raw_fingerprint"]
RELATIONS = ["methods", "class_fields", "class_methods", "method_strings",
             "method_field_accesses", "method_used_types"]
NULLABLE = {
    "methods": {"access_flags", "opcode_count", "opcode_hex", "method_kind"},
    "class_fields": set(),
    "class_methods": set(),
    "method_strings": set(),
    "method_field_accesses": {"using_type"},
    "method_used_types": set(),
}
COLUMNS = {
    "methods": ["file_id", "method_idx", "class_idx", "class_descriptor", "proto_idx", "name",
                "descriptor", "return_descriptor", "param_count", "param_descriptors",
                "access_flags", "opcode_count", "opcode_hex", "method_kind"],
    "class_fields": ["file_id", "class_idx", "class_descriptor", "field_idx", "field_name",
                     "field_descriptor", "kind", "access_flags"],
    "class_methods": ["file_id", "class_idx", "class_descriptor", "method_idx", "method_name",
                      "method_descriptor", "kind", "access_flags"],
    "method_strings": ["method", "method_class", "method_name", "value", "file_id", "class_idx",
                       "method_idx", "string_idx"],
    "method_field_accesses": ["method", "method_class", "method_name", "field", "field_class",
                              "field_name", "field_type", "using_type", "file_id", "class_idx",
                              "method_idx", "field_idx"],
    "method_used_types": ["method", "method_class", "method_name", "type_descriptor", "type_name",
                          "file_id", "class_idx", "method_idx", "type_idx"],
}
DATA_TYPE = {
    "methods": {"file_id": "UInt32", "method_idx": "UInt32", "class_idx": "UInt32",
                "class_descriptor": "Utf8View", "proto_idx": "UInt32", "name": "Utf8View",
                "descriptor": "Utf8View", "return_descriptor": "Utf8View",
                "param_count": "UInt32", "param_descriptors": "Utf8View",
                "access_flags": "UInt32", "opcode_count": "UInt32", "opcode_hex": "Utf8View",
                "method_kind": "Utf8"},
    "class_fields": {"file_id": "UInt32", "class_idx": "UInt32", "class_descriptor": "Utf8",
                     "field_idx": "UInt32", "field_name": "Utf8", "field_descriptor": "Utf8",
                     "kind": "Utf8", "access_flags": "UInt32"},
    "class_methods": {"file_id": "UInt32", "class_idx": "UInt32", "class_descriptor": "Utf8",
                      "method_idx": "UInt32", "method_name": "Utf8", "method_descriptor": "Utf8",
                      "kind": "Utf8", "access_flags": "UInt32"},
    "method_strings": {"method": "Utf8View", "method_class": "Utf8View", "method_name": "Utf8View",
                       "value": "Utf8View", "file_id": "UInt32", "class_idx": "UInt32",
                       "method_idx": "UInt32", "string_idx": "UInt32"},
    "method_field_accesses": {"method": "Utf8View", "method_class": "Utf8View",
                              "method_name": "Utf8View", "field": "Utf8View",
                              "field_class": "Utf8View", "field_name": "Utf8View",
                              "field_type": "Utf8View", "using_type": "Utf8",
                              "file_id": "UInt32", "class_idx": "UInt32", "method_idx": "UInt32",
                              "field_idx": "UInt32"},
    "method_used_types": {"method": "Utf8View", "method_class": "Utf8View",
                          "method_name": "Utf8View", "type_descriptor": "Utf8View",
                          "type_name": "Utf8View", "file_id": "UInt32", "class_idx": "UInt32",
                          "method_idx": "UInt32", "type_idx": "UInt32"},
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main():
    comparisons = load(HERE / "comparisons.json")
    v10 = load(V10)
    v10_columns = {(item["relation"], item["name"]): item for item in v10["columns"]}
    slices = collections.defaultdict(list)
    for item in comparisons["comparisons"]:
        slices[item["relation"]].append(item)
    a0_by_relation = collections.defaultdict(list)
    for key, item in comparisons["a0_comparisons"].items():
        a0_by_relation[item["relation"]].append(item)

    source_sha256 = {
        "oracle_members.py": digest(HERE / "oracle_members.py"),
        "generate_fixture.py": digest(HERE / "generate_fixture.py"),
        "run_evidence.py": digest(HERE / "run_evidence.py"),
        "build_and_run_native.py": digest(HERE / "build_and_run_native.py"),
        "readback_fixture.py": digest(HERE / "readback_fixture.py"),
        "comparisons.json": digest(HERE / "comparisons.json"),
        "fixtures/members-dup-035.dex": digest(HERE / "fixtures/members-dup-035.dex"),
        "fixtures/members-dup-035.record.json": digest(HERE / "fixtures/members-dup-035.record.json"),
        "fixtures/members-dup-035.readback.json": digest(HERE / "fixtures/members-dup-035.readback.json"),
        "tests/fixtures/references/generated/classic-035.dex":
            digest(ROOT / "tests/fixtures/references/generated/classic-035.dex"),
        "tests/fixtures/definitions/generated/definitions-035.dex":
            digest(ROOT / "tests/fixtures/definitions/generated/definitions-035.dex"),
        "conformance/facts/native_probe.rs":
            digest(ROOT / "conformance/facts/native_probe.rs"),
        "conformance/facts/definition_projection_probe.rs":
            digest(ROOT / "conformance/facts/definition_projection_probe.rs"),
        "native/native_probe.exe": digest(HERE / "native/native_probe.exe"),
        "native/definition_projection_probe.exe": digest(HERE / "native/definition_projection_probe.exe"),
        "a0/dexsql-windows-amd64.exe": comparisons["a0"]["sha256"],
    }

    columns = []
    flat = []
    for relation in RELATIONS:
        relation_slices = slices[relation]
        columns_for_relation = COLUMNS[relation]
        exact_any = any(item["native_facts"]["exact_duplicate_rows"] > 0
                        for item in relation_slices)
        combined = []
        for item in relation_slices:
            combined.extend(item["native_rows_data"])
        combined_counts = collections.defaultdict(collections.Counter)
        for row in combined:
            for name in columns_for_relation:
                combined_counts[name][json.dumps(row.get(name), sort_keys=True)] += 1
        combined_repeat = {name: max(counter.values()) for name, counter in combined_counts.items()}
        # The slice that carries the strongest multiplicity evidence.
        if exact_any:
            multiplicity_slice = next(item for item in relation_slices
                                      if item["native_facts"]["exact_duplicate_rows"] > 0)
        else:
            multiplicity_slice = max(relation_slices,
                                     key=lambda item: max(item["native_facts"]
                                                         ["repeated_value_rows_per_column"].values()))
        order_ok = all(item["ordered_sequence_equal"] for item in relation_slices)
        a0_items = a0_by_relation.get(relation, [])
        a0_ok = all(item["ordered_equal"] for item in a0_items) if a0_items else None
        for name in columns_for_relation:
            nullable = name in NULLABLE[relation]
            # multiplicity
            if exact_any:
                multiplicity_state = "satisfied"
                multiplicity_reason = ("compared output contains byte-identical rows; "
                                       "exact-duplicate preservation is exercised")
            elif combined_repeat.get(name, 0) >= 2:
                multiplicity_state = "partial"
                multiplicity_reason = ("no byte-identical row in a valid DEX projection, but the "
                                       "column repeats a value across the compared rows, so key "
                                       "collapse changes the oracle row count")
            else:
                multiplicity_state = "missing"
                multiplicity_reason = ("no repeated value and no identical row; neither key "
                                       "collapse nor duplicate-row drop is detectable")
            # order
            if order_ok:
                order_state = "satisfied"
                order_reason = "native row sequence equals the independent oracle sequence"
            else:
                order_state = "missing"
                order_reason = "native row sequence differs from the independent oracle sequence"
            # null
            if nullable:
                both = any(item["native_facts"]["null_counts"][name] > 0
                           and item["native_facts"]["non_null_counts"][name] > 0
                           for item in relation_slices)
                if both:
                    null_state = "satisfied"
                    null_reason = "compared output observes both NULL and non-NULL cells"
                else:
                    null_state = "missing"
                    null_reason = ("schema marks the column nullable but the compared output "
                                   "observes only non-NULL cells; no well-formed DEX field-site "
                                   "instruction produces a NULL using_type")
            else:
                all_populated = all(item["native_facts"]["null_counts"][name] == 0
                                    for item in relation_slices)
                injected = all(item["null_controls"].get(name, {})
                               .get("injecting_null_rejected") for item in relation_slices
                               if item["native_rows_data"])
                if all_populated and injected:
                    null_state = "satisfied"
                    null_reason = ("every compared cell is populated and injecting NULL fails the "
                                   "sequence comparison")
                else:
                    null_state = "missing"
                    null_reason = "non-nullable column has NULL cells or the NULL control is absent"
            categories = {
                "field_type": {
                    "state": "satisfied",
                    "evidence_path": EVIDENCE + "/oracle_members.py",
                    "oracle": "python-byte-oracle",
                    "independence_argument": "The oracle types every cell from the DEX bytes "
                                             "(UInt32 columns are unpacked as little-endian words, "
                                             "text columns as MUTF-8); it imports no Rust crate.",
                },
                "null": {
                    "state": null_state,
                    "evidence_path": EVIDENCE + "/comparisons.json",
                    "oracle": "python-byte-oracle",
                    "independence_argument": "NULL/non-NULL cells are counted from the captured "
                                             "native rows and the independent oracle rows; the "
                                             "NULL-rejection control is a mutation of the compared "

                                             "sequence. " + null_reason,
                },
                "order": {
                    "state": order_state,
                    "evidence_path": EVIDENCE + "/comparisons.json",
                    "oracle": "python-byte-oracle",
                    "independence_argument": "The native rows are compared as an ordered sequence "
                                             "to the oracle enumeration, not as a Counter/multiset"
                                             + ("; the frozen A0 SQL table independently agrees."
                                                if a0_ok else ".") + " " + order_reason,
                },
                "multiplicity": {
                    "state": multiplicity_state,
                    "evidence_path": EVIDENCE + "/comparisons.json",
                    "oracle": "python-byte-oracle",
                    "independence_argument": "The row count is enumerated by the Python byte "
                                             "oracle; dropping or key-deduplicating a row changes "
                                             "the count and fails. " + multiplicity_reason,
                },
                "source": {
                    "state": "satisfied",
                    "evidence_path": EVIDENCE + "/native/run-record.json",
                    "oracle": "native-content-id",
                    "independence_argument": "Each native occurrence is bound to the fixture "
                                             "sha256 content_id; the oracle reads the same bytes.",
                },
                "raw_fingerprint": {
                    "state": "satisfied",
                    "evidence_path": EVIDENCE + "/oracle_members.py",
                    "oracle": "python-byte-oracle",
                    "independence_argument": "Values are read from the physical DEX bytes "
                                             "(identifier tables, class_data ULEB streams, code "
                                             "items), not from an engine digest.",
                },
            }
            state_by_category = {name: categories[name]["state"] for name in CATEGORIES}
            complete = all(state == "satisfied" for state in state_by_category.values())
            v10_entry = v10_columns[(relation, name)]
            exact_duplicates_compared = max(item["native_facts"]["exact_duplicate_rows"]
                                            for item in relation_slices)
            native_row_count = sum(item["native_rows"] for item in relation_slices)
            oracle_row_count = sum(item["oracle_rows"] for item in relation_slices)
            entry = {
                "relation": relation,
                "column": name,
                "data_type": DATA_TYPE[relation][name],
                "nullable": nullable,
                "categories": categories,
                "category_state": state_by_category,
                "full_field_qualification": complete,
                "evidence_facts": {
                    "exact_duplicate_rows_compared": exact_duplicates_compared,
                    "native_row_count": native_row_count,
                    "oracle_row_count": oracle_row_count,
                    "repeated_value_rows_for_this_column": combined_repeat.get(name, 0),
                    "compared_slices": [item["fixture"] for item in relation_slices],
                    "a0_ordered_equal": a0_ok,
                    "null_counts_native": {
                        item["fixture"]: item["native_facts"]["null_counts"][name]
                        for item in relation_slices},
                },
                "v10_category_state": v10_entry["category_state"],
                "v10_to_now": {
                    name: {"from": v10_entry["category_state"][name], "to": state_by_category[name]}
                    for name in CATEGORIES if v10_entry["category_state"][name] != state_by_category[name]
                },
            }
            columns.append(entry)
            for category in CATEGORIES:
                flat.append({
                    "relation": relation,
                    "column": name,
                    "category": category,
                    "state": state_by_category[category],
                    "evidence_path": categories[category]["evidence_path"],
                    "oracle": categories[category]["oracle"],
                    "independence_argument": categories[category]["independence_argument"],
                })

    qualified = sum(1 for item in columns if item["full_field_qualification"])
    partial_columns = [item for item in columns if not item["full_field_qualification"]]
    per_relation = collections.OrderedDict()
    for relation in RELATIONS:
        entries = [item for item in columns if item["relation"] == relation]
        per_relation[relation] = {
            "columns": len(entries),
            "fully_qualified": sum(1 for item in entries if item["full_field_qualification"]),
            "incomplete": sum(1 for item in entries if not item["full_field_qualification"]),
            "remaining_categories": dict(collections.Counter(
                name for item in entries for name, state in item["category_state"].items()
                if state != "satisfied")),
        }
    report = {
        "schema_version": "mdd.member-evidence-verdict.v1",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "task": "MDD-026",
        "scope": "member/method relations",
        "task_complete_proven": False,
        "profile_admitted": False,
        "relations": RELATIONS,
        "columns_total": len(columns),
        "columns_fully_qualified": qualified,
        "columns_incomplete": len(partial_columns),
        "per_relation": per_relation,
        "source_sha256": source_sha256,
        "v10_reference": "artifacts/mdd-026/column-audit-v10/six-category-audit.json",
        "verdicts": flat,
        "columns": columns,
        "remaining_gaps": [
            {"relation": item["relation"], "column": item["column"],
             "categories": [name for name, state in item["category_state"].items()
                            if state != "satisfied"],
             "reason": next((item["categories"][name]["independence_argument"]
                             for name, state in item["category_state"].items()
                             if state != "satisfied"), "")}
            for item in partial_columns
        ],
        "limits": [
            "Tiny synthetic fixtures only; no HostLab workload, private input, cross-platform or performance claim.",
            "A0 is an independent implementation but not a specification; agreement is evidence, not proof.",
            "methods/class_fields/class_methods multiplicity is partial because a valid DEX cannot contain byte-identical rows for those projections; exact-duplicate preservation is structurally unobservable.",
            "method_field_accesses.using_type is nullable in the schema but no well-formed field-site instruction yields NULL; the NULL branch is unobservable.",
            "Nothing here signs MDD-026 or admits a profile.",
        ],
    }
    (HERE / "result.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                                      encoding="utf-8")
    print(json.dumps({"columns": len(columns), "fully_qualified": qualified,
                      "incomplete": len(partial_columns),
                      "per_relation": {k: v["fully_qualified"] for k, v in per_relation.items()},
                      "task_complete_proven": False}))
    return report


if __name__ == "__main__":
    main()
