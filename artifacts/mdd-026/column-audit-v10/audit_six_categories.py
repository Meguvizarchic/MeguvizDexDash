#!/usr/bin/env python3
"""Per-column six-category evidence audit over the current-source rerun.

MDD-026 was reopened because the qualification script checked *atomic
availability* of 17 relations / 156 columns, not whether each column has
independent evidence for its field/type, NULL, ordering, multiplicity, source
and raw fingerprint. This script computes that per-column matrix from recorded
artifacts and demotes every claim the artifacts cannot support.

Category model (a column is graded per category, never per relation):

  field_type        an independent oracle or A0 comparison constrains the
                    declared column type for this relation.
  null              for a nullable column, at least one NULL and one non-NULL
                    cell are observed in the compared output; for a
                    non-nullable column, every compared cell is non-NULL and the
                    comparison would fail on NULL. Both read from the recorded
                    A0 tables, so this is measured, not asserted.
  order             the slice compares row *sequence* (not a Counter/multiset).
  multiplicity      the compared row count comes from an independent oracle
                    enumeration, so a dropped or deduplicated row changes the
                    count and fails. Exact-duplicate preservation is tracked
                    separately (`exact_duplicate_rows_compared`), because only a
                    fixture with identical rows exercises it.
  source            the compared row is bound to an occurrence/content/DEX
                    identity produced by the reader.
  raw_fingerprint   the value is checked against source bytes or a raw digest.

States: satisfied / partial / missing. `partial` is used where the property is
only partly exercised (for example a repeated value without any duplicate row).

Nothing here signs MDD-026.

Usage:
    python audit_six_categories.py [--rerun DIR] [--out FILE]
"""
from __future__ import annotations

import argparse
import collections
import datetime
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
V9 = "artifacts/mdd-026/column-ledger-v9/20261029T051751932521Z/column-ledger.json"
DEFAULT_RERUN = "artifacts/mdd-026/current-source-rerun-20261109/20261109T050453443034Z"
CATEGORIES = ("field_type", "null", "order", "multiplicity", "source", "raw_fingerprint")

# Relation -> A0 dump labels used to measure NULL and duplicate facts.
A0_DUMPS = {
    "annotations": {
        "annotation_directory_entries": ["a0-annotation_directory_entries"],
        "annotation_set_entries": ["a0-annotation_set_entries"],
        "annotations": ["a0-annotations"],
        "annotation_elements": ["a0-annotation_elements"],
    },
    "definition_rows": {
        "class_interfaces": ["a0-class_interfaces"],
        "class_fields": ["a0-class_fields"],
        "class_methods": ["a0-class_methods"],
    },
    "methods": {"methods": ["a0-shared", "a0-dynamic", "a0-definitions"]},
    "code_atoms": {"code_items": ["a0-classic", "a0-shared"]},
    "owned_try": {"code_items": ["a0-owned-try-even.dex", "a0-owned-try-odd.dex"]},
    "cross_dex": {
        "dex_files": ["a0-dex-files-duplicate-raw-input", "a0-dex-files-two-distinct-raw",
                      "a0-dex-files-same-content-multidex-apk"],
        "strings": ["a0-join-duplicate-raw-input", "a0-join-two-distinct-raw",
                    "a0-join-same-content-multidex-apk"],
    },
    "types_text": {
        "types": ["a0-types-type-names", "a0-types-definitions"],
    },
    "field_type_multi_source": {
        "method_field_accesses": ["a0-method_field_accesses"],
        "method_used_types": ["a0-method_used_types"],
    },
    "mixed_reference_occurrences": {"method_calls": ["a0-calls"]},
    "dynamic_orphan_multi_source": {"method_calls": ["a0-method-calls"]},
    "nonempty_partial_reference_scope": {"method_calls": ["a0-full-two-sources"]},
    "mixed_invalid_reference_scope": {
        "method_calls": ["a0-good", "a0-valid-first", "a0-bad-first"]},
    "class_source_boundaries": {"classes": ["a0-multi"]},
}

# Row identity within one occurrence; used for the duplicate/repeat analysis.
ROW_KEYS = {
    ("annotations", "annotation_directory_entries"): ["class_idx", "entry_kind", "entry_idx"],
    ("annotations", "annotation_set_entries"): ["annotation_set_off", "ordinal"],
    ("annotations", "annotations"): ["annotation_off"],
    ("annotations", "annotation_elements"): ["annotation_off", "depth", "ordinal"],
    ("definition_rows", "class_interfaces"): ["class_idx", "ordinal"],
    ("definition_rows", "class_fields"): ["class_idx", "field_idx"],
    ("definition_rows", "class_methods"): ["class_idx", "method_idx"],
    ("methods", "methods"): ["method_idx"],
    ("code_atoms", "code_items"): ["method_idx"],
    ("types_text", "types"): ["type_idx"],
    ("cross_dex", "strings"): ["string_idx"],
    ("class_source_boundaries", "classes"): ["class_def_idx"],
    ("field_type_multi_source", "method_field_accesses"): ["method_idx", "field_idx", "using_type"],
    ("field_type_multi_source", "method_used_types"): ["method_idx", "type_idx"],
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identity(relative):
    data = (ROOT / relative).read_bytes()
    return {"path": relative, "bytes": len(data), "sha256": digest(data)}


def parse_a0_table(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = [line for line in text.splitlines() if line.startswith("|")]
    if not lines:
        return None
    parsed = [[cell.strip() for cell in line.strip("|").split("|")] for line in lines]
    require(all(len(row) == len(parsed[0]) for row in parsed), "A0 table width differs: " + path.name)
    return {"columns": parsed[0], "rows": parsed[1:]}


def measure(rerun):
    """Measured NULL / duplicate / repeat facts per slice+relation from A0 dumps.

    Duplicate detection must stay inside one dump. Two dumps of the same
    relation are different fixtures (or different generation of the same
    fixture), so merging them and counting identical rows would manufacture
    "duplicate rows" that no comparison actually exercised.
    """
    measured = {}
    for slice_key, relations in A0_DUMPS.items():
        for relation, labels in relations.items():
            columns = None
            rows = []
            duplicate_rows = 0
            duplicate_dumps = []
            for label in labels:
                table = parse_a0_table(ROOT / rerun / slice_key / label / "stdout.txt")
                require(table is not None, "empty A0 dump: " + slice_key + "/" + label)
                columns = columns or table["columns"]
                require(table["columns"] == columns, "A0 column drift in " + slice_key)
                dump_rows = [dict(zip(table["columns"], row)) for row in table["rows"]]
                canonical = collections.Counter(json.dumps(row, sort_keys=True) for row in dump_rows)
                extra = sum(value - 1 for value in canonical.values() if value > 1)
                if extra:
                    duplicate_rows += extra
                    duplicate_dumps.append(label)
                rows.extend(dump_rows)
            nulls = collections.Counter()
            non_nulls = collections.Counter()
            value_counts = collections.defaultdict(collections.Counter)
            for row in rows:
                for name, cell in row.items():
                    value_counts[name][cell] += 1
                    if cell == "N":
                        nulls[name] += 1
                    else:
                        non_nulls[name] += 1
            per_occurrence = collections.defaultdict(list)
            key_columns = [name for name in ROW_KEYS.get((slice_key, relation), [])
                           if name in columns]
            for row in rows:
                bucket = (slice_key, row.get("file_id", "single"))
                per_occurrence[bucket].append(
                    tuple(row[name] for name in key_columns) if key_columns else None)
            measured[(slice_key, relation)] = {
                "rows": len(rows),
                "dumps": labels,
                "columns": columns,
                "exact_duplicate_rows": duplicate_rows,
                "duplicate_dumps": duplicate_dumps,
                "repeated_value_rows_per_column": {name: max(counter.values())
                                                   for name, counter in value_counts.items()},
                "null_counts": dict(nulls),
                "non_null_counts": dict(non_nulls),
                "occurrences": len(per_occurrence),
                "row_key_unique_within_occurrence": (
                    all(len(values) == len(set(values)) for values in per_occurrence.values())
                    if key_columns else None),
                "rows_per_occurrence": {str(key): len(value)
                                        for key, value in per_occurrence.items()},
            }
    return measured


def coverage(reference, rerun, measured):
    columns = collections.OrderedDict()
    for entry in reference["columns"]:
        columns[(entry["relation"], entry["name"])] = {
            "relation": entry["relation"], "ordinal": entry["ordinal"], "name": entry["name"],
            "data_type": entry["data_type"], "nullable": entry["nullable"],
            "production_projection": entry["production_projection"],
            "state": {name: "missing" for name in CATEGORIES},
            "evidence": {name: [] for name in CATEGORIES},
            "rejected": [],
            "notes": [],
        }

    def mark(relation, names, category, evidence, state="satisfied"):
        targets = [names] if isinstance(names, str) else list(names)
        for name in targets:
            key = (relation, name)
            require(key in columns, "unknown column marked: " + relation + "." + name)
            bucket = columns[key]
            if state == "satisfied" or bucket["state"][category] == "missing":
                if bucket["state"][category] != "satisfied":
                    bucket["state"][category] = state
            if evidence not in bucket["evidence"][category]:
                bucket["evidence"][category].append(evidence)

    def reject(relation, names, category, reason):
        targets = [names] if isinstance(names, str) else list(names)
        for name in targets:
            key = (relation, name)
            require(key in columns, "unknown column rejected: " + relation + "." + name)
            columns[key]["rejected"].append({"category": category, "reason": reason})

    def multiplicity(relation, names, slice_key, evidence, occurrence_case=False):
        """Multiplicity from an independently enumerated row count.

        The compared count comes from the Python oracle / A0, not from the
        native output, so a dropped or key-collapsed row changes the count and
        fails the comparison. Exact-duplicate preservation needs identical rows
        in the fixture; when they are absent the column is graded partial.
        """
        fact = measured.get((slice_key, relation))
        require(fact is not None, "no measurement for " + slice_key + "/" + relation)
        targets = [names] if isinstance(names, str) else list(names)
        for name in targets:
            key = (relation, name)
            require(key in columns, "unknown column gated: " + relation + "." + name)
            if fact["exact_duplicate_rows"] > 0:
                mark(relation, name, "multiplicity",
                     evidence + ":oracle_row_count_and_identical_rows_compared")
            elif occurrence_case and fact["occurrences"] >= 2:
                mark(relation, name, "multiplicity",
                     evidence + ":oracle_row_count_covers_two_occurrences", "partial")
                columns[key]["notes"].append(
                    "row count is independently enumerated across two occurrences, but the "
                    "fixture holds no byte-identical row, so exact-duplicate preservation is not exercised")
            elif fact["repeated_value_rows_per_column"].get(name, 0) >= 2:
                mark(relation, name, "multiplicity",
                     evidence + ":oracle_row_count_with_repeated_value", "partial")
                columns[key]["notes"].append(
                    name + " repeats a value across compared rows, so key-level collapse is detectable "
                    "while an exact-duplicate row drop is not")
            else:
                reject(relation, name, "multiplicity",
                       slice_key + " compares " + relation + " but " + name
                       + " never repeats, so neither key collapse nor duplicate-row drop is detectable")

    def null_facts(relation, names, slice_key, evidence):
        """NULL grade from measured A0 cells, not from the schema nullability."""
        fact = measured.get((slice_key, relation))
        require(fact is not None, "no measurement for " + slice_key + "/" + relation)
        targets = [names] if isinstance(names, str) else list(names)
        for name in targets:
            key = (relation, name)
            require(key in columns, "unknown column gated: " + relation + "." + name)
            column = columns[key]
            nulls = fact["null_counts"].get(name, 0)
            non_nulls = fact["non_null_counts"].get(name, 0)
            if column["nullable"]:
                if nulls > 0 and non_nulls > 0:
                    mark(relation, name, "null", evidence + ":both_null_and_non_null_observed")
                elif non_nulls > 0:
                    reject(relation, name, "null",
                           "schema marks " + relation + "." + name + " nullable but every compared cell is "
                           "non-NULL, so the NULL path is unobserved")
                else:
                    reject(relation, name, "null",
                           "only NULL cells observed; the non-NULL path is unobserved")
            elif non_nulls > 0 and nulls == 0:
                mark(relation, name, "null",
                     evidence + ":non_nullable_and_all_cells_populated_in_compared_output")
            else:
                reject(relation, name, "null",
                       "non-nullable column has NULL cells in the compared output: " + name)

    # ---- annotations (current-source ordered verifier) --------------------
    annotations = load(rerun + "/annotations/result.json")
    require(annotations["status"] == "passed-native-ordered-facts-a0-normalized-observations",
            "annotation slice terminal differs")
    require(annotations["a0_negative_zero_display_sign_changes"] == 2,
            "annotation float display observation differs")
    require(annotations["nullable_column_sample_counts"]["annotation_elements"]["value_f64"]["null"] > 0,
            "annotation nullable element sample missing")
    for relation in ("annotation_directory_entries", "annotation_set_entries", "annotations",
                     "annotation_elements"):
        names = [name for (rel, name) in columns if rel == relation]
        mark(relation, names, "field_type", "annotations:validate_types_per_declared_schema_column")
        mark(relation, names, "order", "annotations:compare_exact_row_sequence_two_occurrences")
        mark(relation, names, "source", "annotations:per_occurrence_content_and_file_id_binding")
        mark(relation, names, "raw_fingerprint", "annotations:python_scalar_byte_oracle_same_fixture")
        null_facts(relation, names, "annotations", "annotations:measured_a0_cells")
        multiplicity(relation, names, "annotations", "annotations:oracle_row_count", occurrence_case=True)

    # ---- definition rows --------------------------------------------------
    definitions = load(rerun + "/definition_rows/result.json")
    require(definitions["status"] == "passed-small-fixture-only", "definition slice terminal differs")
    definition_columns = {item["relation"]: item["columns"] for item in definitions["results"]}
    require(set(definition_columns) == {"class_interfaces", "class_fields", "class_methods"},
            "definition relation set differs")
    for relation, names in definition_columns.items():
        mark(relation, names, "field_type", "definition_rows:encode_UInt32_and_null_projection")
        mark(relation, names, "source", "definition_rows:two_occurrences_file_id_rebound")
        mark(relation, names, "raw_fingerprint", "definition_rows:python_byte_oracle_fixture_bytes")
        null_facts(relation, names, "definition_rows", "definition_rows:measured_a0_cells")
        multiplicity(relation, names, "definition_rows", "definition_rows:oracle_row_count")
        reject(relation, names, "order",
               "definition_rows compares A0 rows as canonical multisets; its own result states "
               "that ordering is not proven")

    # ---- methods ----------------------------------------------------------
    methods = load(rerun + "/methods/result.json")
    require(methods["status"] == "passed-small-fixtures-only", "methods slice terminal differs")
    method_columns = methods["results"][0]["columns"]
    require(len(method_columns) == 14, "methods column count differs")
    require(sum(item["reference_only_null_rows"] for item in methods["results"]) == 7,
            "methods reference-only NULL rows differ")
    mark("methods", method_columns, "field_type", "methods:UInt32_range_assertion_on_numeric_columns")
    mark("methods", method_columns, "order", "methods:compare_rows_exact_sequence_native_and_A0")
    mark("methods", method_columns, "source", "methods:source_content_id_and_code_source_binding")
    mark("methods", method_columns, "raw_fingerprint", "methods:python_byte_oracle_opcode_widths")
    null_facts("methods", method_columns, "methods", "methods:measured_a0_cells")
    multiplicity("methods", method_columns, "methods", "methods:oracle_row_count")
    mark("methods", ["access_flags", "opcode_count", "opcode_hex", "method_kind"], "null",
         "methods:reference_only_NULL_and_defined_no_body_empty_both_present")

    # ---- code_items -------------------------------------------------------
    code = load(rerun + "/code_atoms/result.json")
    require(code["status"] == "passed-small-fixtures-only", "code slice terminal differs")
    code_columns = next(item for item in code["results"] if item["case"] == "classic")["columns"]
    require(len(code_columns) == 12, "code column count differs")
    mark("code_items", code_columns, "field_type", "code_atoms:raw_u16_u32_unpacking_per_column")
    mark("code_items", code_columns, "order", "code_atoms:compare_rows_exact_sequence")
    mark("code_items", code_columns, "source", "code_atoms:code_source_equals_occurrence_source")
    mark("code_items", code_columns, "raw_fingerprint", "code_atoms:raw_insns_sha256_per_method")
    null_facts("code_items", code_columns, "code_atoms", "code_atoms:measured_a0_cells")
    multiplicity("code_items", code_columns, "code_atoms", "code_atoms:oracle_row_count")

    owned = load(rerun + "/owned_try/result.json")
    require(owned["status"] == "passed-small-structural-fixtures", "owned try terminal differs")
    # tries_off/handlers_off are NULL in a0-classic/shared and non-NULL only in
    # this slice, and the two facts come from different independent oracles.
    mark("code_items", ["tries_off", "handlers_off"], "null",
         "code_atoms+owned_try:NULL_and_non_NULL_try_offsets_both_observed")
    mark("code_items", ["tries_off", "handlers_off"], "raw_fingerprint",
         "owned_try:byte_oracle_try_handler_offsets_with_padding")
    mark("code_items", ["tries_off", "handlers_off"], "source",
         "owned_try:method_owned_code_bound_to_source")
    mark("code_items", ["tries_off", "handlers_off"], "field_type",
         "owned_try:sdk_dexdump_agrees_on_try_layout")

    # ---- dex_files: 24 header columns -------------------------------------
    header = load(rerun + "/header_bytes/result.json")
    require(header["status"] == "passed-small-fixtures-only", "header slice terminal differs")
    header_columns = header["results"][0]["columns_compared"]
    require(len(header_columns) == 24, "header compared column count differs")
    mark("dex_files", header_columns, "field_type", "header_bytes:python_struct_words_and_native_types")
    mark("dex_files", header_columns, "order", "header_bytes:file_id_0_1_ordered_two_occurrences")
    mark("dex_files", header_columns, "source", "header_bytes:content_id_per_occurrence")
    mark("dex_files", header_columns, "raw_fingerprint", "header_bytes:adler32_sha1_and_words_from_bytes")
    mark("dex_files", header_columns, "null", "header_bytes:every_compared_word_non_null")
    reject("dex_files", header_columns, "multiplicity",
           "header_bytes compares one A0 row per fixture and the duplicate occurrence is native-only, "
           "so no duplicate dex_files row enters the A0 comparison")

    # ---- dex_files / strings identity columns -----------------------------
    cross = load(rerun + "/cross_dex/result.json")
    require(cross["status"] == "passed-small-multi-input-observations", "cross dex terminal differs")
    identity_names = ("file_id", "string_pool_id", "source_path", "entry_name")
    for name in identity_names:
        mark("dex_files", [name], "field_type", "cross_dex:A0_text_cells_and_ordered_file_id")
        mark("dex_files", [name], "order", "cross_dex:A0_ORDER_BY_file_id")
        mark("dex_files", [name], "source", "cross_dex:physical_source_and_pool_identity_separate")
        mark("dex_files", [name], "raw_fingerprint", "cross_dex:python_string_oracle_from_bytes")
    null_facts("dex_files", identity_names, "cross_dex", "cross_dex:measured_a0_cells")
    multiplicity("dex_files", identity_names, "cross_dex", "cross_dex:oracle_row_count",
                 occurrence_case=True)

    string_names = ("string_pool_id", "string_idx", "value")
    for name in string_names:
        mark("strings", [name], "field_type", "cross_dex:ordered_join_columns_typed")
        mark("strings", [name], "order", "cross_dex:ordered_join_by_file_id_string_idx")
        mark("strings", [name], "source", "cross_dex:pool_identity_per_occurrence")
        mark("strings", [name], "raw_fingerprint", "cross_dex:utf16_units_and_raw_mutf8_from_bytes")
    null_facts("strings", string_names, "cross_dex", "cross_dex:measured_a0_cells")
    multiplicity("strings", string_names, "cross_dex", "cross_dex:oracle_row_count",
                 occurrence_case=True)

    # ---- types ------------------------------------------------------------
    types = load(rerun + "/types_text/result.json")
    require(types["status"] == "passed-limited-raw-observations", "type text terminal differs")
    type_names = ("file_id", "type_idx", "descriptor", "java_name")
    for name in type_names:
        mark("types", [name], "field_type", "types_text:A0_typed_cells_and_index_integers")
        mark("types", [name], "order", "types_text:A0_ORDER_BY_type_idx_and_native_index_order")
        mark("types", [name], "source", "types_text:descriptor_string_occurrence_binding")
        mark("types", [name], "raw_fingerprint", "types_text:descriptor_bytes_from_python_oracle")
    null_facts("types", type_names, "types_text", "types_text:measured_a0_cells")
    multiplicity("types", type_names, "types_text", "types_text:oracle_row_count")

    # ---- reference layer --------------------------------------------------
    reference_columns = {
        "method_calls": ["method", "method_class", "method_name", "callee", "callee_class",
                         "callee_name", "file_id", "class_idx", "method_idx", "callee_method_idx"],
        "method_field_accesses": ["method", "method_class", "method_name", "field", "field_class",
                                  "field_name", "field_type", "using_type", "file_id", "class_idx",
                                  "method_idx", "field_idx"],
        "method_used_types": ["method", "method_class", "method_name", "type_descriptor", "type_name",
                              "file_id", "class_idx", "method_idx", "type_idx"],
        "method_strings": ["method", "method_class", "method_name", "value", "file_id", "class_idx",
                           "method_idx", "string_idx"],
    }
    call_names = reference_columns["method_calls"]
    mixed = load(rerun + "/mixed_reference_occurrences/result.json")
    require(mixed["status"] == "passed-scoped-mixed-reference-comparison", "mixed reference terminal differs")
    require(mixed["all_site_count"] == 40 and mixed["a0_method_call_rows"] == 16,
            "mixed reference counts differ")
    mark("method_calls", call_names, "field_type", "mixed_reference:A0_cells_typed_by_schema_check")
    mark("method_calls", call_names, "order", "mixed_reference:ORDER_BY_file_id_method_idx_callee")
    mark("method_calls", call_names, "source", "mixed_reference:local_target_sites_per_occurrence")
    mark("method_calls", call_names, "raw_fingerprint", "mixed_reference:operand_bytes_and_sites_from_raw")
    null_facts("method_calls", call_names, "mixed_reference_occurrences", "mixed_reference:measured_a0_cells")
    multiplicity("method_calls", call_names, "mixed_reference_occurrences",
                 "mixed_reference:oracle_row_count")

    dynamic = load(rerun + "/dynamic_orphan_multi_source/result.json")
    require(dynamic["status"] == "passed-scoped-dynamic-source-observation", "dynamic terminal differs")
    require(dynamic["site_counts"] == [17, 13, 10, 17] and dynamic["a0_method_call_rows"] == 20,
            "dynamic counts differ")
    mark("method_calls", call_names, "order", "dynamic_source:per_occurrence_native_row_sequence")

    partial = load(rerun + "/nonempty_partial_reference_scope/result.json")
    require(partial["status"] == "passed-nonempty-partial-reference-scope", "partial terminal differs")
    mark("method_calls", call_names, "source",
         "partial_reference:nonempty_partial_bound_to_duplicate_occurrence")

    invalid = load(rerun + "/mixed_invalid_reference_scope/result.json")
    require(invalid["status"] == "passed-scoped-native-failure-coverage", "mixed failure terminal differs")

    field_type_result = load(rerun + "/field_type_multi_source/result.json")
    require(field_type_result["status"] == "passed-scoped-field-type-observation",
            "field type terminal differs")
    require(field_type_result["a0_row_counts"] == {"method_field_accesses": 7, "method_used_types": 6},
            "field type A0 rows differ")
    for relation in ("method_field_accesses", "method_used_types"):
        relation_names = reference_columns[relation]
        mark(relation, relation_names, "field_type", "field_type:A0_typed_columns_and_schema_check")
        mark(relation, relation_names, "source", "field_type:source_bound_local_target_lookup")
        mark(relation, relation_names, "raw_fingerprint", "field_type:operand_byte_sites_from_oracle")
        null_facts(relation, relation_names, "field_type_multi_source", "field_type:measured_a0_cells")
        multiplicity(relation, relation_names, "field_type_multi_source", "field_type:oracle_row_count")
        reject(relation, relation_names, "order",
               "field_type compares A0 rows with collections.Counter; row order is not asserted")

    # ---- method_strings: saved native rows only ---------------------------
    string_names = reference_columns["method_strings"]
    for name in string_names:
        mark("method_strings", [name], "field_type", "facts_differential:schema_rows_declared_type_check")
        mark("method_strings", [name], "raw_fingerprint",
             "facts_differential:python_reference_oracle_vs_saved_native_rows")
        mark("method_strings", [name], "source",
             "facts_differential:duplicate_occurrences_keep_distinct_dex_identity")
        reject("method_strings", [name], "null",
               "no A0 dump records method_strings, so NULL/NULL-absence is unmeasured for this relation")
        reject("method_strings", [name], "multiplicity",
               "no A0 dump records method_strings; only saved native rows were compared, so no "
               "independent duplicate or count evidence exists")
        reject("method_strings", [name], "order",
               "facts_differential compares canonical Counters, so set equality is proven but row order is not")

    # ---- classes: boundary slice only, no ordered relation comparison -----
    class_names = ["file_id", "class_def_idx", "class_idx", "descriptor", "access_flags",
                   "superclass_descriptor", "interface_count", "source_file"]
    mark("classes", class_names, "raw_fingerprint", "class_source:python_byte_oracle_over_fixture_bytes")
    mark("classes", class_names, "field_type", "class_source:A0_typed_cells_and_SDK_dexdump")
    mark("classes", class_names, "order", "class_source:A0_ORDER_BY_file_id_class_def_idx")
    mark("classes", class_names, "source", "class_source:four_source_occurrences_bound")
    null_facts("classes", class_names, "class_source_boundaries", "class_source:measured_a0_cells")
    multiplicity("classes", class_names, "class_source_boundaries", "class_source:oracle_row_count",
                 occurrence_case=True)

    return columns


def build(reference, rerun, measured):
    columns = coverage(reference, rerun, measured)
    entries = []
    qualified = 0
    satisfied_counts = collections.Counter()
    partial_counts = collections.Counter()
    missing_counts = collections.Counter()
    per_relation = collections.OrderedDict()
    for entry in columns.values():
        states = entry["state"]
        satisfied = [name for name in CATEGORIES if states[name] == "satisfied"]
        partial = [name for name in CATEGORIES if states[name] == "partial"]
        missing = [name for name in CATEGORIES if states[name] == "missing"]
        is_qualified = not partial and not missing
        qualified += 1 if is_qualified else 0
        relation = per_relation.setdefault(entry["relation"],
                                           {"columns": 0, "qualified": 0,
                                            "missing_categories": collections.Counter(),
                                            "partial_categories": collections.Counter()})
        relation["columns"] += 1
        relation["qualified"] += 1 if is_qualified else 0
        for name in satisfied:
            satisfied_counts[name] += 1
        for name in partial:
            partial_counts[name] += 1
            relation["partial_categories"][name] += 1
        for name in missing:
            missing_counts[name] += 1
            relation["missing_categories"][name] += 1
        entries.append({
            "relation": entry["relation"], "ordinal": entry["ordinal"], "name": entry["name"],
            "data_type": entry["data_type"], "nullable": entry["nullable"],
            "production_projection": entry["production_projection"],
            "satisfied_categories": satisfied,
            "partial_categories": partial,
            "missing_categories": missing,
            "category_state": dict(states),
            "category_evidence": {name: entry["evidence"][name] for name in CATEGORIES
                                  if entry["evidence"][name]},
            "rejected_claims": entry["rejected"],
            "notes": entry["notes"],
            "full_field_qualification": is_qualified,
        })
    require(len(entries) == 156, "audit lost columns")
    gaps = []
    for entry in entries:
        for name in entry["missing_categories"] + entry["partial_categories"]:
            gaps.append({"column": entry["relation"] + "." + entry["name"], "category": name,
                         "state": entry["category_state"][name],
                         "reason": next((item["reason"] for item in entry["rejected_claims"]
                                         if item["category"] == name),
                                        next((note for note in entry["notes"] if name in note), ""))})
    return {
        "schema_version": "mdd.six-category-column-audit.v3",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "task": "MDD-026",
        "purpose": "Per-column six-category evidence matrix measured from recorded artifacts.",
        "categories": list(CATEGORIES),
        "category_definition": {
            "field_type": "an independent oracle/A0 comparison constrains the declared column type",
            "null": "nullable needs both NULL and non-NULL cells in the compared output; non-nullable needs all cells populated",
            "order": "the slice compares row sequence, not a Counter/multiset",
            "multiplicity": "the compared row count comes from an independent oracle enumeration; identical-row preservation tracked separately",
            "source": "the compared row is bound to an occurrence/content/DEX identity",
            "raw_fingerprint": "the value is checked against source bytes or a raw digest",
        },
        "reference_ledger": identity(V9),
        "current_source_rerun": identity(rerun + "/run-record.json"),
        "required_relations": 17,
        "required_columns": 156,
        "summary": {
            "columns": 156,
            "fully_qualified": qualified,
            "incomplete": 156 - qualified,
            "per_category_satisfied": dict(satisfied_counts),
            "per_category_partial": dict(partial_counts),
            "per_category_missing": dict(missing_counts),
            "per_relation": {key: {"columns": value["columns"], "qualified": value["qualified"],
                                   "partial_categories": dict(value["partial_categories"]),
                                   "missing_categories": dict(value["missing_categories"])}
                             for key, value in per_relation.items()},
            "all_columns_qualified": qualified == 156,
        },
        "measured_a0_facts": {key[0] + "/" + key[1]: value for key, value in measured.items()},
        "gap_count": len(gaps),
        "gaps": gaps,
        "columns": entries,
        "task_complete_proven": False,
        "profile_admitted": False,
        "limits": [
            "Six categories are necessary, not sufficient, for the original acceptance; HostLab workload, SQL transport and private inputs remain unqualified.",
            "Several categories cite one slice; that does not make it independent for a different category.",
            "method_strings rests on saved native rows re-checked by the Python oracle, not a current-source native run.",
            "Multiplicity grades row-count detection; exact-duplicate preservation is only exercised where a fixture holds identical rows.",
            "69 compatibility projections remain unassembled and are outside this matrix.",
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rerun", default=DEFAULT_RERUN)
    parser.add_argument("--out", default=None)
    arguments = parser.parse_args()
    require((ROOT / arguments.rerun / "run-record.json").is_file(), "rerun record absent")
    reference = load(V9)
    require(reference["required_columns"] == 156 and len(reference["columns"]) == 156,
            "reference denominator differs")
    measured = measure(arguments.rerun)
    report = build(reference, arguments.rerun, measured)
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if arguments.out:
        (ROOT / arguments.out).write_text(text, encoding="utf-8")
    print(json.dumps({"summary": report["summary"]["per_category_satisfied"],
                      "partial": report["summary"]["per_category_partial"],
                      "missing": report["summary"]["per_category_missing"],
                      "qualified": report["summary"]["fully_qualified"],
                      "gaps": report["gap_count"], "out": arguments.out}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
