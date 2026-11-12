#!/usr/bin/env python3
"""Build the per-relation, per-column MDD-026 projection mapping analysis."""
import datetime
import hashlib
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[3]
CONTRACT = ROOT / "conformance/manifests/relations.json"


def rust_columns(struct):
    for candidate in (
        ROOT / "crates/mdd-facts/src/metadata.rs",
        ROOT / "crates/mdd-facts/src/definitions.rs",
        ROOT / "crates/mdd-facts/src/code.rs",
    ):
        body = candidate.read_text(encoding="utf-8")
        match = re.search(
            r"impl "
            + struct
            + r" \{\s*/// Assembled column names in contract order\.\s*"
            + r"pub const COLUMNS: &\[&str\] = &\[(.*?)\];",
            body,
            re.S,
        )
        if match:
            return re.findall(r'"([^"]+)"', match.group(1))
    raise SystemExit("missing " + struct)


def main():
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    relations = {entry["name"]: entry for entry in contract["relations"]}

    sources = {
        "dex_files": {
            "file_id": ("caller_supplied_catalog_coordinate", "row API argument; same convention as every other fact row API"),
            "string_pool_id": ("caller_supplied_catalog_coordinate", "row API argument; native StringPoolIdentity::string_pool_id is an opaque String and no UInt32 catalog assigner exists"),
            "source_path": (None, "owned by Snapshot SourceIdentity::origin_display (Option<String>); not part of MetadataFacts"),
            "entry_name": (None, "owned by ArchiveInventory MemberIdentity raw_name/name_utf8; not part of MetadataFacts"),
            "byte_len": "MetadataFacts::bytes().len() of the same validated DEX member",
            "dex_version": "DexHeader::version",
            "checksum": "DexHeader::declared_checksum (verified Adler32)",
            "signature_hex": "DexHeader::declared_signature_sha1 (verified SHA1, 40 lowercase hex)",
            "file_size": "DexHeader::file_size",
            "header_size": "DexHeader::header_range.byte_length",
            "endian_tag": "raw little-endian header word at byte offset 40",
            "link_size": "raw little-endian header word at byte offset 44; encoded zero when no link section exists",
            "link_off": "raw little-endian header word at byte offset 48; encoded zero when no link section exists",
            "map_off": "raw little-endian header word at byte offset 52",
            "string_count": "DexHeader::tables[string_ids].count",
            "string_ids_off": "DexHeader::tables[string_ids].range.byte_offset",
            "type_count": "DexHeader::tables[type_ids].count",
            "type_ids_off": "DexHeader::tables[type_ids].range.byte_offset",
            "proto_count": "DexHeader::tables[proto_ids].count",
            "proto_ids_off": "DexHeader::tables[proto_ids].range.byte_offset",
            "field_count": "DexHeader::tables[field_ids].count",
            "field_ids_off": "DexHeader::tables[field_ids].range.byte_offset",
            "method_count": "DexHeader::tables[method_ids].count",
            "method_ids_off": "DexHeader::tables[method_ids].range.byte_offset",
            "class_count": "DexHeader::tables[class_defs].count",
            "class_defs_off": "DexHeader::tables[class_defs].range.byte_offset",
            "data_size": "DexHeader::data_range.byte_length",
            "data_off": "DexHeader::data_range.byte_offset",
        },
        "strings": {
            "string_pool_id": ("caller_supplied_catalog_coordinate", "row API argument; native StringPoolIdentity::string_pool_id is an opaque String and no UInt32 catalog assigner exists"),
            "string_idx": "StringFact::data::string_idx",
            "value": "DexText::strict_utf8(); a legal non-scalar DEX string is rejected with UnsupportedQuery instead of a lossy placeholder",
        },
        "types": {
            "file_id": ("caller_supplied_catalog_coordinate", "row API argument"),
            "type_idx": "TypeFact::data::type_idx",
            "descriptor": "TypeFact::data::descriptor",
            "java_name": "MetadataFacts::java_type_name (exact descriptor grammar with version-specific rules)",
        },
        "methods": {
            "file_id": ("caller_supplied_catalog_coordinate", "row API argument"),
            "method_idx": "MethodReference::method_idx; reference IDs are retained without a definition",
            "class_idx": "MethodReference::class_idx",
            "class_descriptor": "MethodReference::class_descriptor",
            "proto_idx": "MethodReference::proto_idx",
            "name": "MethodReference::method_name",
            "descriptor": "MethodReference::descriptor",
            "return_descriptor": "MethodReference::return_descriptor",
            "param_count": "MethodReference::parameter_descriptors.len()",
            "param_descriptors": (None, 'engine self-reports IncompleteFacts: "native parameter descriptors are exact; compatibility text encoding is not qualified"'),
            "access_flags": "MethodDefinition::access_flags; genuine NULL for reference-only members",
            "opcode_count": (None, "engine self-reports IncompleteFacts: requires the code_layout layer; not fabricated here"),
            "opcode_hex": (None, "engine self-reports IncompleteFacts: requires the code_layout layer; not fabricated here"),
            "method_kind": "MethodDefinition::kind (direct/virtual); genuine NULL for reference-only members",
        },
        "classes": {
            "file_id": ("caller_supplied_catalog_coordinate", "row API argument"),
            "class_def_idx": "ClassDefinition::class_def_idx",
            "class_idx": "ClassDefinition::class_idx",
            "descriptor": "ClassDefinition::descriptor",
            "access_flags": "ClassDefinition::access_flags",
            "superclass_descriptor": "ClassDefinition::superclass_descriptor; encoded NO_INDEX projects as genuine NULL",
            "interface_count": "count(InterfaceDefinition where the same class_def_idx)",
            "source_file": "ClassDefinition::source_file DexText::strict_utf8(); encoded NO_INDEX projects as genuine NULL and non-scalar text is rejected, never converted lossily",
        },
        "code_items": {
            "file_id": ("caller_supplied_catalog_coordinate", "row API argument"),
            "method_idx": "DefinitionFacts method definition joined to the same-occurrence CodeFacts physical start; a shared body expands once per owning method",
            "code_off": "CodeItem::raw_range.byte_offset",
            "registers_size": "CodeItem::registers_size",
            "ins_size": "CodeItem::ins_size",
            "outs_size": "CodeItem::outs_size",
            "tries_size": "CodeItem::tries.len()",
            "debug_info_off": "CodeItem::debug_info_byte_offset; an absent debug section is the encoded zero offset, not NULL",
            "insns_size": "CodeItem::insns_size_code_units (code units, not an instruction count)",
            "insns_off": "CodeItem::insns_range.byte_offset",
            "tries_off": "validated insns end plus one u16 alignment word iff the code-unit count is odd and tries is nonempty; otherwise NULL",
            "handlers_off": "validated tries_off + tries_size*8 iff the try list is nonempty; otherwise NULL",
        },
    }

    struct_for = {
        "dex_files": "DexFileRow",
        "strings": "StringRow",
        "types": "TypeRow",
        "methods": "MethodRow",
        "classes": "ClassRow",
        "code_items": "CodeItemRow",
    }
    api_for = {
        "dex_files": "MetadataFacts::dex_file_rows(file_id, string_pool_id) -> Vec<DexFileRow>",
        "strings": "MetadataFacts::string_rows(file_id, string_pool_id) -> Vec<StringRow>",
        "types": "MetadataFacts::type_rows(file_id) -> Vec<TypeRow>",
        "methods": "DefinitionFacts::method_rows(file_id) -> Vec<MethodRow>",
        "classes": "DefinitionFacts::class_rows(file_id) -> Vec<ClassRow>",
        "code_items": "MethodCodeFactViews::code_item_rows(file_id) -> Vec<CodeItemRow>",
    }
    gate_for = {
        "dex_files": "MetadataFacts::require_relation_columns(MetadataRelation::DexFiles, ..)",
        "strings": "MetadataFacts::require_relation_columns(MetadataRelation::Strings, ..)",
        "types": "MetadataFacts::require_relation_columns(MetadataRelation::Types, ..)",
        "methods": "DefinitionFacts::require_relation_columns(DefinitionRelation::Methods, ..)",
        "classes": "DefinitionFacts::require_relation_columns(DefinitionRelation::Classes, ..)",
        "code_items": "MethodCodeFactViews::require_relation_columns(CodeRelation::CodeItems, ..)",
    }

    report = {
        "schema_version": "mdd.relation-projection-mapping.v1",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "task": "MDD-026",
        "scope": "six relations that were unassembled_production_relation in the frozen HostLab contract",
        "contract": "conformance/manifests/relations.json",
        "contract_sha256": hashlib.sha256(CONTRACT.read_bytes()).hexdigest(),
        "summary": {},
        "relations": [],
    }
    total_assembled = 0
    total_gap = 0
    for relation in ("dex_files", "strings", "types", "methods", "classes", "code_items"):
        assembled = rust_columns(struct_for[relation])
        columns = []
        for spec in relations[relation]["columns"]:
            name = spec["name"]
            raw = sources[relation].get(name)
            if isinstance(raw, tuple):
                source, note = raw
            else:
                source, note = raw, ""
            if name in assembled and source is not None:
                state = (
                    "assembled_caller_catalog_coordinate"
                    if source == "caller_supplied_catalog_coordinate"
                    else "assembled"
                )
            else:
                state = "unassembled"
                source = None
            columns.append(
                {
                    "name": name,
                    "data_type": spec["data_type"],
                    "nullable": spec["nullable"],
                    "state": state,
                    "native_source": source,
                    "note": note,
                }
            )
        assembled_count = sum(1 for item in columns if item["state"].startswith("assembled"))
        gap_count = sum(1 for item in columns if item["state"] == "unassembled")
        total_assembled += assembled_count
        total_gap += gap_count
        report["relations"].append(
            {
                "relation": relation,
                "contract_columns": len(columns),
                "assembled_columns": assembled_count,
                "unassembled_columns": gap_count,
                "projection_api": api_for[relation],
                "column_gate": gate_for[relation],
                "row_type": struct_for[relation],
                "columns": columns,
            }
        )
    report["summary"] = {
        "relations": 6,
        "contract_columns": total_assembled + total_gap,
        "assembled_columns": total_assembled,
        "unassembled_columns": total_gap,
    }
    target = pathlib.Path(__file__).with_name("mapping-analysis.json")
    target.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], indent=1))
    for entry in report["relations"]:
        gap = [item["name"] for item in entry["columns"] if item["state"] == "unassembled"]
        print(entry["relation"], entry["assembled_columns"], "/", entry["contract_columns"], "gap:", gap)


if __name__ == "__main__":
    main()
