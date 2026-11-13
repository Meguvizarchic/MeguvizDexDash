#!/usr/bin/env python3
"""Fold the A0 differential into the MDD-026 six-category column matrix.

Usage:
  python -I tools/qualify_columns_from_differential.py --base MERGED_MATRIX.json \
      [--out-dir artifacts/mdd-026/column-qualification-20261113]

The merged matrix (v10 strict rule) is a local-only input: its evidence paths point
into a withheld tree. It is read here for the per-column state of the six
categories only, and the result embeds those states, so the output is
self-contained and carries no path of this machine.

Policy (a reviewed, reversible choice; see the summary written next to the matrix):

  R1  field_type / raw_fingerprint. A column the harness demoted statically may be
      raised by the production-path differential: in every record the engine
      answered identically to A0 (the committed engine-equal-records manifest, which
      the Rust differential test asserts exactly), all non-NULL cells have the
      SQLite storage class the declared type implies, NULL only where the column is
      nullable, and at least one non-NULL cell was compared byte-for-byte (hex).
  R2  multiplicity. Value repetition kept by the engine and equal to A0 counts for a
      column whose relation has unique full rows by construction. dex_files.file_id
      and dex_files.string_pool_id are occurrence coordinates, unique per row, so the
      category is not_applicable (reported separately, never folded into the count of
      satisfied). dex_files.source_path / entry_name repeat only when the same input
      is listed twice; the recorded A0 case for that is used.
  R3  NULL. A nullable column whose NULL branch is unreachable is satisfied by
      exhaustion only when a named test proves the branch unreachable; the tool does
      not decide that, it records the named test.

Only engine-equal records are evidence. Declared divergences, A0 failures and
engine-only answers are never counted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = "artifacts/mdd-032-audit/a0-differential-20261112/a0-corpus.json"
EQUAL = "artifacts/mdd-032-audit/a0-differential-20261112/engine-equal-records.json"
PROVENANCE = "tests/fixtures/provenance/a0-dex-files-provenance.json"
CATEGORIES = ["field_type", "null", "order", "multiplicity", "source", "raw_fingerprint"]
EXPECTED_CLASS = {"UInt32": "integer", "Utf8": "text", "Utf8View": "text"}

# Columns whose relation has unique full rows, so exact duplicate rows cannot occur and the
# category is carried by repetition of the column's value among the relation's rows.
NOT_APPLICABLE_MULTIPLICITY = {
    ("dex_files", "file_id"): "occurrence coordinate: one dex_files row per occurrence, unique by construction",
    ("dex_files", "string_pool_id"): "occurrence coordinate: one dex_files row per occurrence, unique by construction",
}
PROVENANCE_MULTIPLICITY = {("dex_files", "source_path"), ("dex_files", "entry_name")}
VALUE_REPETITION_MULTIPLICITY = {(relation, "file_id") for relation in (
    "types", "methods", "classes", "class_interfaces", "class_fields", "class_methods", "annotation_elements")}
RAISE_BY_DIFFERENTIAL = {
    "field_type": {("dex_files", "string_pool_id"), ("strings", "string_pool_id"),
                   ("methods", "param_descriptors"), ("methods", "opcode_count"), ("methods", "opcode_hex")},
    "raw_fingerprint": {("methods", "param_descriptors"), ("methods", "opcode_count"), ("methods", "opcode_hex")},
}
NULL_BY_EXHAUSTION = {
    ("method_field_accesses", "using_type"): {
        "test": "instructions::tests::every_field_referencing_opcode_is_a_get_or_a_put",
        "crate": "mdd-dex",
        "claim": "every opcode that references a field is an iget, iput, sget or sput; using_type is NULL only for any other opcode, so no instruction can produce NULL",
    },
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Refused(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refused(message)


OPCODE_PAIR = ("methods", "<opcode_count/opcode_hex pair>")
HEX_DIGITS = set("0123456789abcdef")


def payload_hex(cell: str) -> str:
    """Hex of the value's bytes; storage classes without a payload (real) have none."""
    return cell.split(":", 1)[1] if ":" in cell else ""


def decode_payload(cell: str) -> str:
    """Text a differential cell stands for: cells are `class:HEX` of the value's UTF-8 rendering."""
    return bytes.fromhex(cell.split(":", 1)[1]).decode("utf-8")


def opcode_pair_verdict(count_cell: str, hex_cell: str) -> str:
    """Cross-check that needs no engine: the A0 count equals the number of two-digit tokens in the A0 text.

    `empty` is a count of 0 with an empty text; `non_empty` is a count of n >= 1 with exactly n
    lower-case two-digit hex tokens separated by single spaces; both NULL is `null`.
    """
    if count_cell == "N" or hex_cell == "N":
        return "null" if count_cell == hex_cell else "violation"
    try:
        count, text = decode_payload(count_cell), decode_payload(hex_cell)
    except (ValueError, IndexError):
        return "violation"
    if not count.isdigit():
        return "violation"
    if int(count) == 0:
        return "empty" if text == "" else "violation"
    tokens = text.split(" ")
    well_formed = all(len(token) == 2 and set(token) <= HEX_DIGITS for token in tokens)
    return "non_empty" if well_formed and len(tokens) == int(count) else "violation"


def load_inputs(base_path: Path):
    base = json.loads(base_path.read_text(encoding="utf-8"))
    corpus = json.loads((ROOT / CORPUS).read_text(encoding="utf-8"))
    equal = json.loads((ROOT / EQUAL).read_text(encoding="utf-8"))
    provenance = json.loads((ROOT / PROVENANCE).read_text(encoding="utf-8"))
    require(base.get("schema_version") == "mdd.md-d026-merged-column-matrix.v1", "unexpected base schema")
    require(len(base["columns"]) == 156, f"expected 156 frozen columns, got {len(base['columns'])}")
    require(corpus["a0_sha256"] == equal["a0_sha256"], "corpus and equal-record manifest name different A0 builds")
    return base, corpus, equal, provenance


def collect(corpus, equal):
    """Per (relation, column): counts over engine-equal records only."""
    equal_keys = {(r["input"], r["relation"]) for r in equal["records"]}
    require(len(equal_keys) == len(equal["records"]), "duplicate entries in the equal-record manifest")
    seen = set()
    stats: dict = {}
    for record in corpus["records"]:
        key = (record["input"], record["relation"])
        if key not in equal_keys:
            continue
        seen.add(key)
        require(record["a0"].get("ok") is True, f"{key} is in the equal manifest but A0 did not answer it")
        rows = record["a0"]["rows"]
        columns = record["columns"]
        for position, column in enumerate(columns):
            entry = stats.setdefault((record["relation"], column), {
                "records": 0, "records_with_rows": 0, "cells": 0, "null_cells": 0, "informative_cells": 0,
                "classes": Counter(), "records_with_repeat": 0, "repeated_cells": 0, "inputs": []})
            values = [row[position] for row in rows]
            entry["records"] += 1
            if values:
                entry["records_with_rows"] += 1
                if len(entry["inputs"]) < 3:
                    entry["inputs"].append(record["input"])
            entry["cells"] += len(values)
            for value in values:
                if value == "N":
                    entry["null_cells"] += 1
                else:
                    entry["classes"][value.split(":", 1)[0]] += 1
                    if payload_hex(value) not in ("", "30"):  # "30" is the text 0
                        entry["informative_cells"] += 1
            counts = Counter(values)
            repeated = sum(count - 1 for count in counts.values() if count > 1)
            if repeated:
                entry["records_with_repeat"] += 1
                entry["repeated_cells"] += repeated
        if record["relation"] == "methods":
            pair = stats.setdefault(OPCODE_PAIR, {"rows": 0, "non_empty_rows": 0, "violations": 0})
            count_at, hex_at = columns.index("opcode_count"), columns.index("opcode_hex")
            for row in rows:
                pair["rows"] += 1
                verdict = opcode_pair_verdict(row[count_at], row[hex_at])
                pair["non_empty_rows"] += verdict == "non_empty"
                pair["violations"] += verdict == "violation"
    require(seen == equal_keys, f"{len(equal_keys - seen)} manifest records are not in the corpus")
    return stats, len(equal_keys)


def provenance_repeat(provenance, column):
    """A recorded A0 case in which the same input listed twice gives two rows with one value."""
    for case in provenance["cases"]:
        rows = case["a0_dex_rows"]
        values = [row[column] for row in rows]
        if len(values) >= 2 and len(set(values)) < len(values):
            return {"case": case["case"], "rows": len(values), "distinct_values": len(set(values))}
    return None


def evaluate(column, stats, provenance):
    """Return {category: replacement dict} for the categories this policy can raise."""
    relation, name, data_type, nullable = column["relation"], column["name"], column["data_type"], column["nullable"]
    key = (relation, name)
    state = column["category_state"]
    changes = {}
    entry = stats.get(key)
    expected_class = EXPECTED_CLASS.get(data_type)

    def counts_of(entry):
        return {"records_compared": entry["records_with_rows"], "cells": entry["cells"],
                "non_null_cells": entry["cells"] - entry["null_cells"], "null_cells": entry["null_cells"],
                "storage_classes": dict(sorted(entry["classes"].items())), "example_inputs": sorted(entry["inputs"])}

    for category in ("field_type", "raw_fingerprint"):
        if state[category] == "satisfied" or key not in RAISE_BY_DIFFERENTIAL[category]:
            continue
        require(entry is not None and expected_class is not None, f"{key}: no differential data or unknown type {data_type}")
        classes = set(entry["classes"])
        non_null = entry["cells"] - entry["null_cells"]
        ok = (classes <= {expected_class}) and non_null > 0 and (nullable or entry["null_cells"] == 0)
        extra = {"informative_cells": entry["informative_cells"]}
        if category == "raw_fingerprint":
            # The value must carry content (a non-empty text or a non-zero number), not only the right type.
            ok = ok and entry["informative_cells"] > 0
            if name in ("opcode_count", "opcode_hex"):
                pair = stats.get(OPCODE_PAIR)
                require(pair is not None, "no methods records for the opcode_count/opcode_hex cross-check")
                ok = ok and pair["violations"] == 0 and pair["non_empty_rows"] > 0
                extra["opcode_pair_cross_check"] = dict(pair)
        if ok:
            changes[category] = {"state": "satisfied", "basis": "a0_differential_engine_equal_records",
                                 "rule": "R1", "expected_storage_class": expected_class, **counts_of(entry), **extra}
        else:
            changes[category] = {"state": state[category], "basis": "a0_differential_insufficient",
                                 "rule": "R1", "expected_storage_class": expected_class, **counts_of(entry), **extra}

    if state["multiplicity"] != "satisfied":
        if key in NOT_APPLICABLE_MULTIPLICITY:
            require(entry is not None and entry["repeated_cells"] == 0, f"{key}: expected a unique-per-row column")
            changes["multiplicity"] = {"state": "not_applicable", "basis": NOT_APPLICABLE_MULTIPLICITY[key],
                                       "rule": "R2", **counts_of(entry), "repeated_cells": entry["repeated_cells"]}
        elif key in PROVENANCE_MULTIPLICITY:
            seen = provenance_repeat(provenance, name)
            if seen is not None:
                changes["multiplicity"] = {
                    "state": "satisfied", "basis": "recorded_a0_case_with_the_same_input_listed_twice", "rule": "R2",
                    "case": seen["case"], "a0_rows": seen["rows"], "a0_distinct_values": seen["distinct_values"],
                    "engine_test": "indexes::scope::metadata_rows_tests::dex_file_provenance_matches_recorded_a0_entries"}
        elif key in VALUE_REPETITION_MULTIPLICITY and entry is not None and entry["repeated_cells"] > 0:
            changes["multiplicity"] = {
                "state": "satisfied", "basis": "a0_differential_value_repetition_engine_equal_records", "rule": "R2",
                "records_with_repeat": entry["records_with_repeat"], "repeated_cells": entry["repeated_cells"],
                **counts_of(entry)}

    if state["null"] != "satisfied" and key in NULL_BY_EXHAUSTION:
        require(entry is not None and entry["cells"] - entry["null_cells"] > 0, f"{key}: no non-NULL cell compared")
        changes["null"] = {"state": "satisfied", "basis": "null_branch_unreachable_by_exhaustion", "rule": "R3",
                           **NULL_BY_EXHAUSTION[key], **counts_of(entry)}
    return changes


def build(base_path: Path):
    base, corpus, equal, provenance = load_inputs(base_path)
    stats, equal_count = collect(corpus, equal)
    columns = []
    for column in base["columns"]:
        changes = evaluate(column, stats, provenance)
        states = {}
        for category in CATEGORIES:
            base_state = column["category_state"][category]
            change = changes.get(category)
            if change is None:
                states[category] = {"state": base_state, "basis": "merged_matrix_v10"}
            else:
                states[category] = change
        resolved = all(states[c]["state"] in ("satisfied", "not_applicable") for c in CATEGORIES)
        applicable = all(states[c]["state"] == "satisfied" for c in CATEGORIES)
        columns.append({
            "relation": column["relation"], "ordinal": column["ordinal"], "name": column["name"],
            "data_type": column["data_type"], "nullable": column["nullable"],
            "base_category_state": column["category_state"],
            "categories": states,
            "resolved": resolved,
            "satisfied_in_all_six": applicable,
        })
    summary = {
        "columns": len(columns),
        "satisfied_in_all_six_by_base": sum(1 for c in base["columns"] if not c["partial_categories"] and not c["missing_categories"]),
        "satisfied_in_all_six_after_fold": sum(1 for c in columns if c["satisfied_in_all_six"]),
        "resolved_with_not_applicable": sum(1 for c in columns if c["resolved"] and not c["satisfied_in_all_six"]),
        "unresolved": [f"{c['relation']}.{c['name']}" for c in columns if not c["resolved"]],
        "raised_by_fold": sorted(f"{c['relation']}.{c['name']}:{cat}" for c in columns for cat in CATEGORIES
                                 if c["categories"][cat]["basis"] != "merged_matrix_v10" and c["categories"][cat]["state"] == "satisfied"),
        "declared_not_applicable": sorted(f"{c['relation']}.{c['name']}:{cat}" for c in columns for cat in CATEGORIES
                                          if c["categories"][cat]["state"] == "not_applicable"),
        "not_raised_by_fold": sorted(f"{c['relation']}.{c['name']}:{cat}" for c in columns for cat in CATEGORIES
                                     if c["categories"][cat]["basis"] == "a0_differential_insufficient"),
    }
    document = {
        "schema_version": "mdd.column-qualification.v1",
        "task": "MDD-026",
        "kind": "development evidence; admits no profile and does not by itself close the task",
        "inputs": {
            "merged_matrix_v10": {"sha256": sha256(base_path), "note": "local-only; its states are embedded below, its evidence paths are not"},
            "a0_corpus": {"path": CORPUS, "sha256": sha256(ROOT / CORPUS)},
            "engine_equal_records": {"path": EQUAL, "sha256": sha256(ROOT / EQUAL), "records": equal_count},
            "recorded_a0_provenance": {"path": PROVENANCE, "sha256": sha256(ROOT / PROVENANCE)},
            "a0_sha256": corpus["a0_sha256"],
        },
        "policy": "R1" + __doc__.split("  R1", 1)[1].rstrip("\n"),
        "summary": summary,
        "limits": [
            "The differential compares whole-relation projections; single-column projections are derived from them, not separately differential-tested.",
            f"Evidence is limited to the {corpus['inputs']} fixture inputs of the corpus and to records on which the engine equals A0; declared divergences (non-BMP parameter descriptors) are not qualified by this fold.",
            "not_applicable is a policy statement about unique row keys, not evidence; it is reported separately from satisfied.",
            "This is a policy decision about how differential evidence counts toward the six categories; it can be reversed by re-running this tool without the fold rules.",
        ],
        "columns": columns,
    }
    return document


def render_summary(document) -> str:
    s = document["summary"]
    lines = [
        "# MDD-026 column qualification (A0 differential folded in)",
        "",
        "Development evidence. Admits no profile and does not by itself close MDD-026.",
        "",
        f"- Frozen columns: {s['columns']}",
        f"- All six categories satisfied by the merged v10 matrix alone: {s['satisfied_in_all_six_by_base']}",
        f"- All six categories satisfied after the fold: {s['satisfied_in_all_six_after_fold']}",
        f"- Resolved with a `not_applicable` category: {s['resolved_with_not_applicable']}",
        f"- Unresolved: {len(s['unresolved'])} {s['unresolved']}",
        "",
        "## Categories raised by the fold",
        "",
    ]
    lines += [f"- `{item}`" for item in s["raised_by_fold"]] or ["- none"]
    lines += ["", "## Declared not applicable (policy statement, not evidence)", ""]
    lines += [f"- `{item}`" for item in s["declared_not_applicable"]] or ["- none"]
    if s["not_raised_by_fold"]:
        lines += ["", "## Categories the fold could not raise", ""]
        lines += [f"- `{item}`" for item in s["not_raised_by_fold"]]
    lines += ["", "## Policy", "", document["policy"], "", "## Limits", ""]
    lines += [f"- {item}" for item in document["limits"]]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, default=ROOT / "artifacts/mdd-026/column-qualification-20261113")
    args = parser.parse_args()
    try:
        document = build(args.base)
    except Refused as refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return 2
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "column-qualification.json").write_text(
        json.dumps(document, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    (args.out_dir / "SUMMARY.md").write_text(render_summary(document), encoding="utf-8", newline="\n")
    s = document["summary"]
    print(f"columns={s['columns']} base_all_six={s['satisfied_in_all_six_by_base']} "
          f"after_fold_all_six={s['satisfied_in_all_six_after_fold']} with_not_applicable={s['resolved_with_not_applicable']} "
          f"unresolved={s['unresolved']} not_raised={s['not_raised_by_fold']}")
    return 0 if not s["unresolved"] else 1


if __name__ == "__main__":
    sys.exit(main())
