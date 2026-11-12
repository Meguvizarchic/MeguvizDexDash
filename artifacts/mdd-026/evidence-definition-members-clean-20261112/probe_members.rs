//! Evidence probe: member/method facts with real per-occurrence file_id.
//!
//! This probe only reads facts through the public mdd-facts API and prints
//! JSON. It never compares anything itself.
//!
//! Fix relative to the previous round: `file_id` is taken from the selected
//! scope (`SelectedScope`), so a two-input run emits file_id 0/1 instead of a
//! constant 0. The engine's own `method_column_gates` are recorded verbatim so
//! the harness can demote columns the engine self-reports as INCOMPLETE_FACTS.
use mdd_dex::{
    definitions::DefinitionLimits, instructions::CodeLimits, strings::StringLimits,
};
use mdd_facts::{
    MetadataFacts,
    code::CodeFacts,
    definitions::{DefinitionFacts, DefinitionRelation},
    indexes::SelectedScope,
    references::{ReferenceFacts, ReferenceLimits},
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde_json::{Value, json};
use std::{path::PathBuf, process::ExitCode};

fn require(ok: bool, message: &str) -> MddResult<()> {
    if ok {
        Ok(())
    } else {
        Err(MddError::new(
            ErrorCode::InternalFault,
            "probe_members",
            message,
        ))
    }
}

fn run() -> MddResult<Value> {
    let paths: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    require(
        !paths.is_empty() && paths.len() <= 8,
        "member probe needs 1..8 raw DEX inputs",
    )?;
    for path in &paths {
        let size = std::fs::metadata(path)
            .map_err(|e| {
                MddError::new(ErrorCode::InvalidInput, "probe_members", e.to_string())
            })?
            .len();
        require(
            size <= 1024 * 1024,
            "member probe refuses an input above 1MiB",
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
    if !scope.roster_complete() || !scope.covers_all_captured_sources() {
        return Err(MddError::new(
            ErrorCode::IncompleteFacts,
            "probe_members",
            "incomplete roster",
        ));
    }
    let mut results = Vec::new();
    let mut scope_index = 0;
    for inventory in &inventories {
        for index in 0..inventory.selected_dexes().len() {
            let metadata =
                MetadataFacts::build(&snapshot, inventory, index, StringLimits::default())?;
            let facts = DefinitionFacts::build(metadata, DefinitionLimits::default())?;
            let code = CodeFacts::build_all_code_items(
                &snapshot,
                inventory,
                index,
                CodeLimits::default(),
            )?;
            let selected = scope.dexes().get(scope_index).ok_or_else(|| {
                MddError::new(ErrorCode::InternalFault, "probe_members", "selected DEX missing")
            })?;
            if selected.dex_occurrence_id != facts.metadata().source().dex_occurrence_id {
                return Err(MddError::new(
                    ErrorCode::InternalFault,
                    "probe_members",
                    "occurrence mismatch",
                ));
            }
            let definitions_json = json!(facts.definitions());
            let code_json = json!(code);
            let class_fields = facts.class_field_rows(selected.file_id);
            let class_methods = facts.class_method_rows(selected.file_id);
            let class_interfaces = facts.class_interface_rows(selected.file_id);
            let mut method_columns = serde_json::Map::new();
            for name in ["opcode_count", "opcode_hex", "param_descriptors", "*"] {
                method_columns.insert(
                    name.to_owned(),
                    json!(facts
                        .require_relation_columns(DefinitionRelation::Methods, &[name])
                        .err()),
                );
            }
            let references = ReferenceFacts::build(facts, code, ReferenceLimits::default())?;
            let strings = references
                .method_string_rows(selected.file_id)
                .map(|rows| json!({"operation_status":"ok", "rows":rows}))
                .unwrap_or_else(|error| json!({"operation_status":"error", "error":error}));
            results.push(json!({
                "file_id": selected.file_id,
                "content_id": selected.content_id,
                "source": references.source(),
                "metadata": json!(references.definitions().metadata()),
                "definitions": definitions_json,
                "code": code_json,
                "class_fields": class_fields,
                "class_methods": class_methods,
                "class_interfaces": class_interfaces,
                "method_column_gates": Value::Object(method_columns),
                "references": {
                    "coverage": references.coverage(),
                    "sites": references.sites(),
                    "method_strings": strings,
                    "method_field_accesses": references.method_field_rows(selected.file_id)?,
                    "method_used_types": references.method_type_rows(selected.file_id)?,
                },
            }));
            scope_index += 1;
        }
    }
    if scope_index != scope.dexes().len() {
        return Err(MddError::new(
            ErrorCode::InternalFault,
            "probe_members",
            "extra selected DEX",
        ));
    }
    Ok(json!({
        "probe": "evidence-member-public-fact-composition-v2",
        "operation_status": "ok",
        "snapshot_id": scope.snapshot_id(),
        "scope_id": scope.scope_id(),
        "inputs": scope.inputs(),
        "dex_occurrences": results,
        "probe_complete": true,
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
            println!(
                "{}",
                json!({"operation_status":"error","error":error,"probe_complete":false})
            );
            ExitCode::FAILURE
        }
    }
}
