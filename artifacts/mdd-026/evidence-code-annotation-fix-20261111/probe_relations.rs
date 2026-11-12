//! Evidence probe for MDD-026 code/annotation relation multiplicity.
//!
//! Reads facts only through the public mdd-facts API and prints JSON.  It never
//! compares anything: every comparison is done by the independent Python byte
//! oracle and the third-party A0 binary in run_evidence.py.
//!
//! Rows are emitted per selected DEX occurrence with the scope's own ``file_id``
//! (the same numbering the native scope assigns), so a byte-identical DEX
//! presented twice yields two occurrences whose content projection contains
//! exact duplicate rows.  The probe never collapses occurrences.
use mdd_dex::{
    annotations::AnnotationLimits,
    definitions::{DefinitionLimits, MethodBody},
    instructions::CodeLimits,
    strings::StringLimits,
};
use mdd_facts::{
    MetadataFacts,
    annotations::AnnotationFacts,
    code::CodeFacts,
    definitions::DefinitionFacts,
    indexes::SelectedScope,
    references::{ReferenceFacts, ReferenceLimits},
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde_json::{Value, json};
use std::{collections::HashMap, path::PathBuf, process::ExitCode};

fn require(ok: bool, message: &str) -> MddResult<()> {
    if ok {
        Ok(())
    } else {
        Err(MddError::new(
            ErrorCode::InternalFault,
            "conformance.evidence.probe_relations",
            message,
        ))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<String>()
}

fn run() -> MddResult<Value> {
    let paths: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    require(
        !paths.is_empty() && paths.len() <= 8,
        "evidence probe needs 1..8 raw DEX inputs",
    )?;
    for path in &paths {
        let size = std::fs::metadata(path)
            .map_err(|e| {
                MddError::new(ErrorCode::InvalidInput, "evidence.probe_relations", e.to_string())
            })?
            .len();
        require(
            size <= 1024 * 1024,
            "evidence probe refuses an input above 1MiB",
        )?;
    }
    let specs: Vec<_> = paths
        .into_iter()
        .map(|path| InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        })
        .collect();
    let snapshot = Snapshot::capture(&specs, CaptureLimits::default())?;
    let inventories = snapshot
        .sources()
        .iter()
        .map(|source| {
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
        })
        .collect::<MddResult<Vec<_>>>()?;
    let refs = inventories.iter().collect::<Vec<_>>();
    let scope = SelectedScope::from_inventories(&snapshot, &refs)?;
    require(
        scope.roster_complete() && scope.covers_all_captured_sources(),
        "incomplete source roster",
    )?;
    let mut occurrences = Vec::new();
    let mut scope_index = 0usize;
    for inventory in &inventories {
        for index in 0..inventory.selected_dexes().len() {
            let metadata =
                MetadataFacts::build(&snapshot, inventory, index, StringLimits::default())?;
            let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default())?;
            let selected = scope.dexes().get(scope_index).ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "evidence.probe_relations",
                    "selected DEX missing",
                )
            })?;
            require(
                selected.dex_occurrence_id == definitions.metadata().source().dex_occurrence_id,
                "occurrence identity mismatch",
            )?;
            let file_id = selected.file_id;

            let code = CodeFacts::build_all_code_items(
                &snapshot,
                inventory,
                index,
                CodeLimits::default(),
            )?;
            let mut code_by_offset: HashMap<u64, &mdd_facts::code::CodeFact> = HashMap::new();
            for item in code.items() {
                code_by_offset.insert(item.data().raw_range.byte_offset.0, item);
            }
            let mut code_rows = Vec::new();
            for method in &definitions.definitions().method_definitions {
                let MethodBody::Present {
                    code_byte_offset, ..
                } = method.body
                else {
                    continue;
                };
                let offset = code_byte_offset.0;
                let item = code_by_offset.get(&offset).ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "evidence.probe_relations",
                        "method body has no physical code item",
                    )
                })?;
                let data = item.data();
                let insns_off = data.insns_range.byte_offset.0;
                let size = data.insns_size_code_units as u64;
                let tries = data.tries.len() as u64;
                let tries_off = if tries > 0 {
                    Some(insns_off + size * 2 + (size % 2) * 2)
                } else {
                    None
                };
                let handlers_off = tries_off.map(|at| at + tries * 8);
                code_rows.push(json!({
                    "file_id": file_id,
                    "method_idx": method.method_idx,
                    "code_off": data.raw_range.byte_offset.0,
                    "registers_size": data.registers_size,
                    "ins_size": data.ins_size,
                    "outs_size": data.outs_size,
                    "tries_size": tries,
                    "debug_info_off": data.debug_info_byte_offset.map(|v| v.0).unwrap_or(0),
                    "insns_size": data.insns_size_code_units,
                    "insns_off": insns_off,
                    "tries_off": tries_off,
                    "handlers_off": handlers_off,
                }));
            }

            let interfaces = &definitions.definitions().interfaces;
            let class_rows: Vec<Value> = definitions
                .definitions()
                .classes
                .iter()
                .map(|class| {
                    let interface_count = interfaces
                        .iter()
                        .filter(|item| item.class_def_idx == class.class_def_idx)
                        .count() as u32;
                    let source_hex = class
                        .source_file
                        .as_ref()
                        .map(|text| hex(&text.raw_mutf8));
                    let source_strict = class
                        .source_file
                        .as_ref()
                        .and_then(|text| text.strict_utf8().ok());
                    json!({
                        "file_id": file_id,
                        "class_def_idx": class.class_def_idx,
                        "class_idx": class.class_idx,
                        "descriptor": class.descriptor,
                        "access_flags": class.access_flags,
                        "superclass_descriptor": class.superclass_descriptor,
                        "interface_count": interface_count,
                        "source_file": source_hex,
                        "source_file_strict": source_strict,
                    })
                })
                .collect();

            let references = ReferenceFacts::build(
                definitions.clone(),
                code,
                ReferenceLimits::default(),
            )?;
            let method_calls = references.method_call_rows(file_id)?;
            let annotations = match AnnotationFacts::build(
                definitions,
                AnnotationLimits::default(),
            ) {
                Ok(facts) => json!({
                    "operation_status": "ok",
                    "annotation_directory_entries": facts.directory_entry_rows(file_id),
                    "annotation_set_entries": facts.set_entry_rows(file_id),
                    "annotations": facts.annotation_rows(file_id),
                    "annotation_elements": facts.element_rows(file_id),
                }),
                Err(error) => json!({"operation_status": "error", "error": error}),
            };

            occurrences.push(json!({
                "file_id": file_id,
                "content_id": selected.content_id,
                "dex_occurrence_id": selected.dex_occurrence_id,
                "code_items": code_rows,
                "classes": class_rows,
                "annotations": annotations,
                "method_calls": method_calls,
            }));
            scope_index += 1;
        }
    }
    require(
        scope_index == scope.dexes().len(),
        "extra selected DEX occurrence",
    )?;
    Ok(json!({
        "operation_status": "ok",
        "probe_complete": true,
        "snapshot_id": scope.snapshot_id(),
        "scope_id": scope.scope_id(),
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
