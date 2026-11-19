//! A complete metadata consumer with bounded summary output, not an audit backend.
use mdd_dex::strings::StringLimits;
use mdd_facts::MetadataFacts;
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde::Serialize;
use std::{path::PathBuf, process::ExitCode};

#[derive(Serialize)]
struct DexSummary {
    dex_occurrence_id: String,
    content_id: String,
    version: String,
    strings: usize,
    utf16_code_units: u64,
    strings_without_scalar_utf8: usize,
    types: usize,
    prototypes: usize,
    parameter_references: u64,
    completed_layers: Vec<String>,
    unbuilt_layers: Vec<String>,
    signature_verified: bool,
    full_dex_validation_complete: bool,
}

fn run() -> MddResult<serde_json::Value> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "example",
                "usage: metadata_summary INPUT [EXPECTED_SHA256]",
            )
        })?;
    let expected_sha256 = std::env::args().nth(2);
    let kind = if path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("dex"))
    {
        InputKind::RawDex
    } else {
        InputKind::Apk
    };
    let snapshot = Snapshot::capture(
        &[InputSpec {
            path,
            kind,
            expected_sha256,
        }],
        CaptureLimits::default(),
    )?;
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )?;
    let mut dexes = Vec::new();
    for index in 0..inventory.selected_dexes().len() {
        let facts = MetadataFacts::build(&snapshot, &inventory, index, StringLimits::default())?;
        dexes.push(DexSummary {
            dex_occurrence_id: facts.source().dex_occurrence_id.to_string(),
            content_id: facts.source().content_id.clone(),
            version: facts.header().version.clone(),
            strings: facts.strings().len(),
            utf16_code_units: facts
                .strings()
                .iter()
                .map(|item| item.data.text.utf16_units.len() as u64)
                .sum(),
            strings_without_scalar_utf8: facts
                .strings()
                .iter()
                .filter(|item| item.data.text.strict_utf8().is_err())
                .count(),
            types: facts.types().len(),
            prototypes: facts.prototypes().len(),
            parameter_references: facts
                .prototypes()
                .iter()
                .map(|item| item.data.parameter_type_indices.len() as u64)
                .sum(),
            completed_layers: facts.completed_layers().to_vec(),
            unbuilt_layers: facts.unbuilt_layers().to_vec(),
            signature_verified: facts.header().signature_verified,
            full_dex_validation_complete: facts.header().full_dex_validation_complete,
        });
    }
    Ok(serde_json::json!({
        "operation_status":"ok", "scope":"strings-types-prototypes-only-v1", "snapshot_id": snapshot.manifest().snapshot_id,
        "input_content_id": snapshot.manifest().sources[0].content_id,
        "captured_input_bytes": snapshot.manifest().captured_input_bytes,
        "selected_dexes": dexes, "metadata_calculation_complete":true,
        "required_dex_occurrences": inventory.selected_dexes().len(),
        "full_audit_complete": false,
        "qualification":"actual complete metadata construction; no HostLab, full facts or performance qualification"
    }))
}

fn main() -> ExitCode {
    match run() {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({"operation_status":"error", "error":error,"full_audit_complete":false})
            );
            ExitCode::FAILURE
        }
    }
}
