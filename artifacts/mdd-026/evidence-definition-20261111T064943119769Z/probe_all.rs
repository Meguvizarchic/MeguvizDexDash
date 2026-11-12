//! Evidence probe: per-occurrence header/string/type/class/interface facts.
//!
//! This probe only reads facts through the public mdd-facts API and prints
//! JSON. It never compares anything itself; every comparison is done by the
//! independent Python byte oracle and the third-party A0 binary in
//! run_evidence.py.
use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
use mdd_facts::{
    MetadataFacts, definitions::DefinitionFacts, indexes::SelectedScope,
    metadata::TypeNameLimits,
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde_json::{Value, json};
use std::{path::PathBuf, process::ExitCode};

fn header_row(facts: &MetadataFacts) -> MddResult<Value> {
    let header = facts.header();
    let tables = header
        .tables
        .iter()
        .map(|item| {
            (
                item.name.clone(),
                json!({"count": item.count, "offset": item.range.byte_offset.0}),
            )
        })
        .collect::<serde_json::Map<String, Value>>();
    let table = |name: &str| -> MddResult<(u32, u64)> {
        tables
            .get(name)
            .ok_or_else(|| MddError::new(ErrorCode::InternalFault, "probe_all", "missing table"))
            .map(|item| {
                (
                    item["count"].as_u64().unwrap_or(0) as u32,
                    item["offset"].as_u64().unwrap_or(0),
                )
            })
    };
    let (string_count, string_ids_off) = table("string_ids")?;
    let (type_count, type_ids_off) = table("type_ids")?;
    let (proto_count, proto_ids_off) = table("proto_ids")?;
    let (field_count, field_ids_off) = table("field_ids")?;
    let (method_count, method_ids_off) = table("method_ids")?;
    let (class_count, class_defs_off) = table("class_defs")?;
    let link = header.link_range.as_ref();
    Ok(json!({
        "byte_len": facts.bytes().len(),
        "dex_version": header.version,
        "checksum": header.declared_checksum,
        "signature_hex": header.declared_signature_sha1,
        "file_size": header.file_size.0,
        "header_size": header.header_range.byte_length.0,
        "endian_tag": 0x12345678u32,
        "link_size": link.map_or(0, |range| range.byte_length.0),
        "link_off": link.map_or(0, |range| range.byte_offset.0),
        "map_off": header.map.iter().find(|item| item.name == "map_list")
            .map_or(0, |item| item.byte_offset.0),
        "string_count": string_count,
        "string_ids_off": string_ids_off,
        "type_count": type_count,
        "type_ids_off": type_ids_off,
        "proto_count": proto_count,
        "proto_ids_off": proto_ids_off,
        "field_count": field_count,
        "field_ids_off": field_ids_off,
        "method_count": method_count,
        "method_ids_off": method_ids_off,
        "class_count": class_count,
        "class_defs_off": class_defs_off,
        "data_size": header.data_range.byte_length.0,
        "data_off": header.data_range.byte_offset.0,
    }))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<String>()
}

fn string_rows(facts: &MetadataFacts) -> Vec<Value> {
    facts
        .strings()
        .iter()
        .map(|item| {
            let text = &item.data.text;
            json!({
                "string_idx": item.data.string_idx,
                "value_hex": hex(&text.raw_mutf8),
                "value": text.strict_utf8().ok(),
                "utf16_units": text.utf16_units,
            })
        })
        .collect()
}

fn type_rows(facts: &MetadataFacts) -> MddResult<Vec<Value>> {
    let mut rows = Vec::new();
    for item in facts.types() {
        let name = facts.java_type_name(&item.entity, TypeNameLimits::default())?;
        rows.push(json!({
            "type_idx": item.data.type_idx,
            "descriptor": item.data.descriptor,
            "java_name": name.value,
        }));
    }
    Ok(rows)
}

fn class_rows(facts: &DefinitionFacts) -> Vec<Value> {
    let interfaces = &facts.definitions().interfaces;
    facts
        .definitions()
        .classes
        .iter()
        .map(|class| {
            let interface_count = interfaces
                .iter()
                .filter(|item| item.class_def_idx == class.class_def_idx)
                .count() as u32;
            let source = class.source_file.as_ref();
            let source_value = source.and_then(|text| text.strict_utf8().ok());
            let source_hex = source.map(|text| hex(&text.raw_mutf8));
            json!({
                "class_def_idx": class.class_def_idx,
                "class_idx": class.class_idx,
                "descriptor": class.descriptor,
                "access_flags": class.access_flags,
                "superclass_descriptor": class.superclass_descriptor,
                "interface_count": interface_count,
                "source_file": source_value,
                "source_file_hex": source_hex,
            })
        })
        .collect()
}

fn interface_rows(facts: &DefinitionFacts) -> Vec<Value> {
    facts
        .definitions()
        .interfaces
        .iter()
        .map(|item| {
            json!({
                "class_def_idx": item.class_def_idx,
                "class_idx": item.class_idx,
                "ordinal": item.ordinal,
                "interface_type_idx": item.interface_type_idx,
                "interface_descriptor": item.interface_descriptor,
            })
        })
        .collect()
}

fn run() -> MddResult<Value> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args.len() % 2 != 0 || args.len() > 8 {
        return Err(MddError::new(
            ErrorCode::InvalidArgument,
            "probe_all",
            "need 1..4 kind/path pairs",
        ));
    }
    let mut inputs = Vec::new();
    for pair in args.chunks_exact(2) {
        let kind = match pair[0].to_str() {
            Some("dex") => InputKind::RawDex,
            Some("apk") => InputKind::Apk,
            _ => {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "probe_all",
                    "invalid input kind",
                ))
            }
        };
        inputs.push(InputSpec {
            path: PathBuf::from(&pair[1]),
            kind,
            expected_sha256: None,
        });
    }
    let snapshot = Snapshot::capture(&inputs, CaptureLimits::default())?;
    let inventories = snapshot
        .sources()
        .iter()
        .map(|source| {
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
        })
        .collect::<MddResult<Vec<_>>>()?;
    let refs = inventories.iter().collect::<Vec<_>>();
    let scope = SelectedScope::from_inventories(&snapshot, &refs)?;
    if !scope.roster_complete() || !scope.covers_all_captured_sources() {
        return Err(MddError::new(
            ErrorCode::IncompleteFacts,
            "probe_all",
            "incomplete roster",
        ));
    }
    let source_paths = scope
        .inputs()
        .iter()
        .filter_map(|input| {
            input
                .origin_display
                .as_ref()
                .map(|origin| (input.source_occurrence_id.clone(), origin.clone()))
        })
        .collect::<std::collections::HashMap<_, _>>();
    let mut occurrences = Vec::new();
    let mut scope_index = 0;
    for inventory in &inventories {
        let source_path = source_paths
            .get(&inventory.manifest().source_occurrence_id)
            .cloned()
            .ok_or_else(|| {
                MddError::new(ErrorCode::InternalFault, "probe_all", "source path missing")
            })?;
        for (index, dex) in inventory.selected_dexes().iter().enumerate() {
            let metadata = MetadataFacts::build(&snapshot, inventory, index, StringLimits::default())?;
            let facts = DefinitionFacts::build(metadata, DefinitionLimits::default())?;
            let selected = scope.dexes().get(scope_index).ok_or_else(|| {
                MddError::new(ErrorCode::InternalFault, "probe_all", "selected DEX missing")
            })?;
            if selected.dex_occurrence_id != facts.metadata().source().dex_occurrence_id {
                return Err(MddError::new(
                    ErrorCode::InternalFault,
                    "probe_all",
                    "occurrence mismatch",
                ));
            }
            occurrences.push(json!({
                "file_id": selected.file_id,
                "content_id": selected.content_id,
                "dex_occurrence_id": selected.dex_occurrence_id,
                "source_path": source_path,
                "entry_name": dex.blob.identity.name_utf8,
                "string_pool_id": facts.metadata().string_pool().string_pool_id,
                "header": header_row(facts.metadata())?,
                "strings": string_rows(facts.metadata()),
                "types": type_rows(facts.metadata())?,
                "classes": class_rows(&facts),
                "class_interfaces": interface_rows(&facts),
            }));
            scope_index += 1;
        }
    }
    if scope_index != scope.dexes().len() {
        return Err(MddError::new(
            ErrorCode::InternalFault,
            "probe_all",
            "extra selected DEX",
        ));
    }
    Ok(json!({
        "operation_status": "ok",
        "probe_complete": true,
        "snapshot_id": scope.snapshot_id(),
        "scope_id": scope.scope_id(),
        "inputs": scope.inputs(),
        "occurrences": occurrences,
        "profile_admitted": false,
    }))
}

fn main() -> ExitCode {
    match run() {
        Ok(value) => {
            println!("{value}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error:?}");
            ExitCode::FAILURE
        }
    }
}
