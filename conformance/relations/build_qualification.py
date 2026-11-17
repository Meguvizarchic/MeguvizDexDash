#!/usr/bin/env python3
"""MDD-070: write the relation-by-relation qualification record of all 56 public relations.

Inputs (all committed): the frozen manifest (columns, types, NULLs), the recorded reference answers
(artifacts/mdd-070/a0-probe/), and the result of replaying them against the engine
(artifacts/mdd-070/public-relations-diff.json, written by public_relations_diff.py). What the script adds is the part
a replay cannot say by itself, kept in the table below, one entry per relation: the scope of a row, how often a row
can repeat, the order the engine keeps, the DEX versions the relation exists in, and how it refuses.

Writes conformance/manifests/full-relation-qualification.json. Nothing in the record is a count typed by hand: the
numbers are read from the replay result, which names the binary it ran against.

Usage: python -I conformance/relations/build_qualification.py [--check]
  --check   only say whether the committed record is built from the current inputs (no write)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "conformance/manifests/relations.json"
DIFF = "artifacts/mdd-070/public-relations-diff.json"
DIFF_011 = "artifacts/mdd-070/public-relations-diff-0.1.1.json"
MODULE = "crates/mdd-sql/src/profiles/compatibility/mod.rs"
REFERENCE_VERSIONS = "artifacts/mdd-070/reference-versions.json"
OUT = "conformance/manifests/full-relation-qualification.json"
PROBES = "artifacts/mdd-070/a0-probe"
INPUTS = [MANIFEST, DIFF, DIFF_011, MODULE, REFERENCE_VERSIONS, "conformance/relations/public_relations_diff.py", "conformance/relations/build_qualification.py",
          "tests/fixtures/public_relations/manifest.json"]

LAYER_REFUSAL = ("INCOMPLETE_FACTS, naming the relation and the layer, when the layer is not built or not complete; "
                 "never an empty table")
NON_SCALAR = ("INCOMPLETE_FACTS (NON_SCALAR_TEXT_PROJECTION) for a DEX holding a legal non-scalar string that the plain UTF-8 "
              "column cannot carry; the reference substitutes text")
TEXT = "NON_SCALAR_TEXT_PROJECTION: UNSUPPORTED_QUERY when a name is a legal non-scalar string"

# name: (scope of a row, multiplicity, order, earliest DEX version, additional refusal)
S = "one DEX occurrence (file_id)"
KNOWLEDGE: dict[str, tuple[str, str, str, str, str]] = {
    "dex_files": (S, "exactly one row per selected DEX occurrence; two byte-identical occurrences are two rows", "selected-DEX roster order", "035", "INCOMPLETE_FACTS naming the column when source_path or entry_name has no lossless text"),
    "map_items": (S, "one row per map list entry, the map list item included", "map order (the file order of the sections)", "035", ""),
    "id_items": (S, "one row per item of the string, type, proto, field, method, class and (038+) call site and method handle id tables", "table by table in map type order, then item index", "035", ""),
    "strings": ("one string pool (string_pool_id)", "one row per string id; equal strings stay separate rows", "string index", "035", NON_SCALAR),
    "type_ids": (S, "one row per type id", "type index", "035", ""),
    "types": (S, "one row per type id", "type index", "035", ""),
    "type_lists": (S, "one row per type list of the type_list section, referenced or not; a list several prototypes share is one row", "offset", "035", ""),
    "type_list_entries": (S, "one row per member of every type list; a shared list is listed once", "list offset, then position", "035", ""),
    "proto_ids": (S, "one row per prototype id", "prototype index", "035", ""),
    "protos": (S, "one row per prototype id", "prototype index", "035", ""),
    "proto_params": (S, "one row per parameter of every prototype, so a list two prototypes share is read twice, once for each", "prototype index, then position", "035", ""),
    "field_ids": (S, "one row per field id", "field index", "035", ""),
    "fields": (S, "one row per field id", "field index", "035", ""),
    "method_ids": (S, "one row per method id", "method index", "035", ""),
    "method_opcodes": (S, "one row per method id; NULL only for a method with no definition", "method index", "035", LAYER_REFUSAL),
    "class_data_methods": (S, "one row per method a class data item declares, direct before virtual", "class definition order, direct then virtual, then declaration order", "035", ""),
    "methods": (S, "one row per method id", "method index", "035", ""),
    "method_handles": (S, "one row per method handle", "handle index", "038", ""),
    "call_sites": (S, "one row per call site id", "call site index", "038", ""),
    "call_site_args": (S, "one row per top-level value of every call site array", "call site index, then position", "038", ""),
    "encoded_arrays": (S, "one row per encoded array item, referenced or not", "offset", "035", ""),
    "encoded_array_values": (S, "one row per value node of every encoded array, nested ones included", "array offset, then document order", "035", ""),
    "encoded_array_owners": (S, "one row per call site or class that uses an array; an array nothing uses has none; an array two classes share has two", "array offset, call sites before classes", "035", ""),
    "class_defs": (S, "one row per class definition", "class definition order", "035", ""),
    "classes": (S, "one row per class definition", "class definition order", "035", ""),
    "class_interfaces": (S, "one row per interface of every class", "class definition order, then position", "035", ""),
    "class_data_items": (S, "one row per class that has class data; two classes sharing class data are refused with the DEX", "class definition order", "035", ""),
    "class_fields": (S, "one row per declared field", "class definition order, static before instance", "035", ""),
    "class_static_values": (S, "one row per top-level value of the static value array of every class that has one", "class definition order, then position", "035", ""),
    "class_methods": (S, "one row per declared method", "class definition order, direct before virtual", "035", ""),
    "hiddenapi_flags": (S, "one row per member of every class that has flags: static fields, instance fields, direct methods, virtual methods, in class data order; member_idx is the field or method index of the DEX", "class definition order, then class data order", "039", "INVALID_INPUT (HIDDENAPI_SIZE, HIDDENAPI_CLASS_OFFSET, HIDDENAPI_FLAGS) for a malformed section; no section is no rows"),
    "code_items": (S, "one row per method that owns a body; a body several methods share is one row for each; a code item no method declares is no row (the reference counts it and delivers none)", "method index", "035", LAYER_REFUSAL),
    "try_items": (S, "one row per try block of a method-owned body, a shared body once per method", "method index, then try index", "035", LAYER_REFUSAL),
    "catch_handlers": (S, "one row per typed catch of a method-owned body, then one for its catch-all", "method index, handler index, then position", "035", LAYER_REFUSAL),
    "debug_info": (S, "one row per method-owned body that has a debug program; a program two methods share is one row for each", "method index", "035", LAYER_REFUSAL),
    "debug_parameters": (S, "one row per parameter name slot of every such program", "method index, then position", "035", LAYER_REFUSAL),
    "debug_positions": (S, "one row per position a program emits, wherever its address lies", "method index, then emission order", "035", LAYER_REFUSAL),
    "debug_locals": (S, "one row per local variable event; an end or restart shows the name, type and signature its register was started with, NULL if it never was", "method index, then program order", "035", LAYER_REFUSAL),
    "debug_opcodes": (S, "one row per opcode of every program, the closing END_SEQUENCE included", "method index, then program order", "035", LAYER_REFUSAL),
    "annotation_directories": (S, "one row per class annotation directory", "class definition order", "035", ""),
    "annotation_directory_entries": (S, "one row per field, method and parameter entry of a class directory", "class definition order, then entry order", "035", ""),
    "annotation_sets": (S, "one row per annotation set a class directory reaches, shared or not", "offset", "035", ""),
    "annotation_set_entries": (S, "one row per annotation of a reachable set", "set offset, then position", "035", ""),
    "annotation_set_ref_lists": (S, "one row per parameter reference list a class directory names", "offset", "035", ""),
    "annotation_set_refs": (S, "one row per slot of those lists; a parameter without annotations is a NULL set", "list offset, then position", "035", ""),
    "annotations": (S, "one row per annotation of a reachable set", "offset", "035", ""),
    "annotation_elements": (S, "one row per value node of a reachable annotation, nested ones included", "annotation offset, then document order", "035", ""),
    "method_refs": (S, "one row per reference operand of an instruction; the prototype operand of an invoke-polymorphic is not a row (the reference omits it)", "method index, then instruction order", "035", LAYER_REFUSAL),
    "method_numbers": (S, "one row per numeric literal an instruction carries, a body shared by methods once for each", "method index, then instruction order", "035", LAYER_REFUSAL),
    "method_using_numbers": (S, "the rows of method_numbers with the method spelled out", "method index, then instruction order", "035", LAYER_REFUSAL),
    "method_strings": ("one DEX occurrence (file_id); the method is spelled out", "one row per string operand of an instruction", "method index, then instruction order", "035", NON_SCALAR),
    "method_calls": ("one DEX occurrence (file_id); the method is spelled out", "one row per invoke instruction", "method index, then instruction order", "035", LAYER_REFUSAL),
    "method_field_accesses": ("one DEX occurrence (file_id); the method is spelled out", "one row per field access instruction", "method index, then instruction order", "035", LAYER_REFUSAL),
    "method_used_types": ("one DEX occurrence (file_id); the method is spelled out", "one row per type operand of an instruction", "method index, then instruction order", "035", LAYER_REFUSAL),
    "annotation_values": (S, "one row per value node of every annotation of every owner; a set several owners share is read once for each", "directory order: class, fields, methods, parameters", "035", TEXT),
    "annotation_elements_resolved": (S, "one row per top-level element of every annotation of every owner; an annotation without elements is one row with NULL element columns", "directory order: class, fields, methods, parameters", "035", TEXT),
}

DECLARED = {
    "INT_TAG": "a cell of a column declared Int64 holds a non-negative value: the reference tags it int64, the engine derives the tag from the value (uint64 when it is not negative); the value is identical",
    "FLOAT_ULP": "a float64 cell the reference computed from a 64-bit pattern (method_numbers.double_value) is up to one unit in the last place from the exact reading of the pattern, which the engine returns",
    "ORDER": "a relation read without ORDER BY has no promised order; the engine keeps the stable order named for each relation, the reference's depends on its query plan; the rows are the same multiset",
    "NON_SCALAR": "the plain UTF-8 relations refuse a DEX holding a legal non-scalar string; the reference substitutes text",
    "STRICT_INPUT": "a DEX in which two class definitions share one class_data_item is refused at open; the reference reads it",
    "COLUMN_TYPE_OF_EMPTY_RESULT": "the type the engine reports for a result column is taken from the values, so a column with no value or only NULLs is reported 'unknown'; the reference reports the declared type",
    "DYNAMIC_COLUMNS": "owner_kind, parameter_idx and retention_policy are computed columns the reference types 'sqlite_dynamic'; the engine types them by their values",
    "A0_PAGING_DEFECT": "reading code_items of a DEX with a code item no method declares, or type_lists of a DEX with a type list nothing refers to, the reference counts the item and delivers no page (next_offset stays); the engine answers code_items with the method-bound items (none here) and type_lists with every list of the section",
    "REFERENCE_INCOMPLETE": "type_list_entries of a type list nothing refers to: the reference has no entries for it, the engine lists them; every row the reference delivers is the engine's too (two fixtures)",
    "LOCAL_PATH": "dex_files.source_path is the path the input was opened from and differs by machine; it is not compared",
}


def sha256(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def replay_summary(diff: dict) -> dict:
    summary = diff["summary"]
    return {
        "reference": diff["reference"], "dialect": diff["engine_under_test"].get("dialect"),
        "fixtures": len(diff["fixtures_compared"]), "pairs": sum(v["fixtures"] for v in summary.values()),
        "exact": sum(v["match"] + v["match_cells"] for v in summary.values()),
        "same_rows_in_another_order": sum(v["reordered"] for v in summary.values()),
        "refused_by_design": sum(v["refused_by_design"] for v in summary.values()),
        "reference_incomplete": sum(v.get("reference_incomplete", 0) for v in summary.values()),
        "differing": sum(v["differs"] + v["error"] for v in summary.values()),
        "blocking_relations": diff["blocking_relations"],
    }


def build() -> dict:
    manifest = json.loads((ROOT / MANIFEST).read_text(encoding="utf-8"))
    diff = json.loads((ROOT / DIFF).read_text(encoding="utf-8"))
    diff_011 = json.loads((ROOT / DIFF_011).read_text(encoding="utf-8"))
    names = [entry["name"] for entry in manifest["relations"]]
    if set(KNOWLEDGE) != set(names):
        raise SystemExit(f"the knowledge table and the manifest differ: {sorted(set(KNOWLEDGE) ^ set(names))}")
    if diff["relations_compared"] != names:
        raise SystemExit("the replay result does not cover the 56 relations in manifest order")
    versions: dict[str, str] = {}
    for path in sorted((ROOT / PROBES).glob("*.json")):
        if path.name == "describe-tables.json":
            continue
        record = json.loads(path.read_text(encoding="utf-8"))
        files = record["relations"]["dex_files"]
        at = [c["name"] for c in files["columns"]].index("dex_version")
        versions[path.stem] = files["rows"][0][at]["value"]
    relations = []
    for entry in manifest["relations"]:
        name = entry["name"]
        scope, multiplicity, order, earliest, refusal = KNOWLEDGE[name]
        summary = diff["summary"][name]
        nonempty = [f for f, per in diff["results"].items() if "open_error" not in per and per[name]["rows_recorded"] > 0]
        relations.append({
            "name": name,
            "required_by_hostlab": entry["required_by_hostlab"],
            "columns": [{"name": c["name"], "type": c["data_type"], "nullable": c["nullable"]} for c in entry["columns"]],
            "scope": scope,
            "multiplicity": multiplicity,
            "order": order,
            "earliest_dex_version": earliest,
            "refusals": ([refusal] if refusal else []) + ([LAYER_REFUSAL] if not refusal.startswith("INCOMPLETE_FACTS, naming") and name not in ("dex_files",) else []),
            "evidence": {
                "fixtures_compared": summary["fixtures"],
                "fixtures_with_rows": len(nonempty),
                "dex_versions_with_rows": sorted({versions[f] for f in nonempty}),
                "exact": summary["match"] + summary["match_cells"],
                "same_rows_in_another_order": summary["reordered"],
                "refused_by_design": summary["refused_by_design"],
                "reference_incomplete": summary.get("reference_incomplete", 0),
                "differing": summary["differs"] + summary["error"],
                "fixtures_with_rows_list": nonempty,
            },
        })
    return {
        "schema_version": "mdd.full-relation-qualification.v1",
        "task": "MDD-070",
        "kind": "development evidence; admits no profile",
        "reference": diff["reference"],
        "engine_under_test": diff["engine_under_test"],
        "relations_count": len(relations),
        "fixtures": sorted(versions),
        "fixture_dex_versions": versions,
        "declared_differences": DECLARED,
        "declared_open_refusals": diff["declared_open_refusals"],
        "profiles": {
            "dexsql-0.1.0-compat-v1": {
                "status": "compared, not admitted",
                "basis": "the recorded answers of dexsql 0.1.0 (artifacts/mdd-070/a0-probe/) replayed by conformance/relations/public_relations_diff.py with the server in the dexsql-0.1.0 dialect",
                "replay": replay_summary(diff),
            },
            "dexsql-0.1.1-compat-v1": {
                "status": "compared, not admitted",
                "basis": "the recorded answers of dexsql 0.1.1 (artifacts/mdd-070/a1-probe/; windows-amd64, sha256 602105c98232120c14d6124fb33574f2f95f12e50e51d25b8834f893925f28d6, checked against the release's SHA256SUMS and the asset digest GitHub holds) replayed with the server in the dexsql-0.1.1 dialect",
                "replay": replay_summary(diff_011),
                "against_0.1.0": "the recorded answers of the two versions are identical on every fixture and relation (artifacts/mdd-070/reference-versions.json); the differences between the profiles that are recorded are therefore none, within those fixtures and that question",
            },
        },
        "dialects": {
            "dexsql-0.1.0": {"relations_advertised": len(names), "evidence": DIFF, "module": MODULE},
            "dexsql-0.1.1": {"relations_advertised": len(names), "evidence": DIFF_011, "module": MODULE},
        },
        "sql_surface": "each relation is exercised by SELECT * paged to the end; the 17 contract relations are additionally exercised by the MDD-035 corpus (joins, aggregates, CTEs, ORDER BY). General SQL over the 39 others is not claimed beyond what the query layer proves for any relation.",
        "special_formats": "no relation here depends on DEX 041, compact DEX, OAT or VDEX; those keep their own capability matrix (compatibility/ledger.json format_qualifications)",
        "relations": relations,
        "inputs_sha256": {path: sha256(path) for path in INPUTS},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        record = json.loads((ROOT / OUT).read_text(encoding="utf-8"))
        stale = [p for p, digest in record["inputs_sha256"].items() if sha256(p) != digest]
        for path in stale:
            print("STALE:", path)
        print("committed qualification current:", not stale)
        return 1 if stale else 0
    record = build()
    (ROOT / OUT).write_text(json.dumps(record, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    exact = sum(r["evidence"]["exact"] for r in record["relations"])
    print(f"wrote {OUT}: {record['relations_count']} relations, {exact} exact (relation, fixture) pairs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
