//! MDD-026 evidence probe: the five formerly unassembled columns.
//!
//! Compiled directly with rustc against the already-built workspace rlibs (the
//! same approach as the earlier MDD-026 evidence harnesses), so it needs no new
//! Cargo target or dependency. It calls the production row APIs on the same
//! fixtures whose A0 slices were recorded and writes one JSON document.
//! `readback.py` recomputes every expected value from raw bytes and the archive
//! directory without using this crate.
//!
//! The probe claims no completion and no profile.
use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits, strings::StringLimits};
use mdd_facts::{
    MetadataFacts,
    code::{CodeFacts, MethodCodeFactViews, MethodCodeViewLimits},
    definitions::DefinitionFacts,
    indexes::SelectedScope,
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::MddResult;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::ExitCode;

const APK: &str = "artifacts/mdd-026/column-audit-v10/_probe-verify_cross_dex_identity/20261109T045613053519Z/synthetic-same-content.apk";
const CLASSIC: &str = "tests/fixtures/references/generated/classic-035.dex";
const SHARED: &str = "tests/fixtures/references/generated/shared-code-035.dex";
const DEFINITIONS: &str = "tests/fixtures/definitions/generated/definitions-035.dex";
const DYNAMIC: &str = "tests/fixtures/references/generated/poly-custom-038.dex";

fn root() -> PathBuf {
    // The probe is compiled by rustc outside Cargo, so the repository root comes
    // from an explicit argument rather than a build-time environment variable.
    let mut args = std::env::args_os().skip(1);
    let root = args
        .next()
        .map(PathBuf::from)
        .expect("first argument must be the repository root");
    assert!(args.next().is_none(), "only the repository root is accepted");
    root
}

fn build(inputs: &[(&str, InputKind)]) -> MddResult<(Snapshot, Vec<ArchiveInventory>)> {
    let root = root();
    let specs = inputs
        .iter()
        .map(|(relative, kind)| InputSpec {
            // Join one component at a time so the recorded source path uses the
            // platform separator throughout, exactly as a caller would spell it.
            path: relative
                .split('/')
                .fold(root.clone(), |path, part| path.join(part)),
            kind: *kind,
            expected_sha256: None,
        })
        .collect::<Vec<_>>();
    let snapshot = Snapshot::capture(&specs, CaptureLimits::default())?;
    let inventories = snapshot
        .sources()
        .iter()
        .map(|source| {
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
        })
        .collect::<MddResult<Vec<_>>>()?;
    Ok((snapshot, inventories))
}

fn dex_file_cases() -> MddResult<Value> {
    let mut output = serde_json::Map::new();
    for (label, inputs) in [
        (
            "duplicate-raw-input",
            vec![(CLASSIC, InputKind::RawDex), (CLASSIC, InputKind::RawDex)],
        ),
        (
            "two-distinct-raw",
            vec![(CLASSIC, InputKind::RawDex), (SHARED, InputKind::RawDex)],
        ),
        ("same-content-multidex-apk", vec![(APK, InputKind::Apk)]),
    ] {
        let (snapshot, inventories) = build(&inputs)?;
        let facts = inventories
            .iter()
            .flat_map(|inventory| {
                (0..inventory.selected_dexes().len()).map(move |index| (inventory, index))
            })
            .map(|(inventory, index)| {
                MetadataFacts::build(&snapshot, inventory, index, StringLimits::default())
            })
            .collect::<MddResult<Vec<_>>>()?;
        let references = facts.iter().collect::<Vec<_>>();
        let scope =
            SelectedScope::from_inventories(&snapshot, &inventories.iter().collect::<Vec<_>>())?;
        let pool_ids = (0..scope.dexes().len() as u32).collect::<Vec<_>>();
        let rows = scope.dex_file_rows(&references, &pool_ids, 8)?;
        output.insert(label.into(), serde_json::to_value(&rows).unwrap());
    }
    Ok(Value::Object(output))
}

fn method_cases() -> MddResult<Value> {
    let mut output = serde_json::Map::new();
    for (label, relative) in [
        ("definitions", DEFINITIONS),
        ("shared", SHARED),
        ("dynamic", DYNAMIC),
    ] {
        let (snapshot, inventories) = build(&[(relative, InputKind::RawDex)])?;
        let inventory = &inventories[0];
        let metadata = MetadataFacts::build(&snapshot, inventory, 0, StringLimits::default())?;
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default())?;
        let code =
            CodeFacts::build_all_code_items(&snapshot, inventory, 0, CodeLimits::default())?;
        let views =
            MethodCodeFactViews::build(&definitions, &code, MethodCodeViewLimits::default())?;
        let rows = views.method_rows(0)?;
        output.insert(label.into(), serde_json::to_value(&rows).unwrap());
    }
    Ok(Value::Object(output))
}

fn run() -> MddResult<Value> {
    Ok(json!({
        "operation_status": "ok",
        "probe_complete": true,
        "dex_files": dex_file_cases()?,
        "methods": method_cases()?,
        "task_complete_proven": false,
        "profile_admitted": false,
    }))
}

fn main() -> ExitCode {
    match run() {
        Ok(value) => {
            println!("{}", serde_json::to_string(&value).unwrap());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!(
                "{}",
                json!({
                    "code": error.code,
                    "stage": error.stage,
                    "message": error.message,
                    "details": error.details,
                })
            );
            ExitCode::FAILURE
        }
    }
}
