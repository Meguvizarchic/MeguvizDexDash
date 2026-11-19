//! Fully consume one held AndroidManifest.xml, keeping raw member identity.
use mdd_facts::raw_fingerprints::ResourceByteEvidence;
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, DexSelection, InventoryPolicy},
    manifest::{ManifestLimits, parse_manifest},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use std::{path::PathBuf, process::ExitCode, sync::Arc};

fn run() -> MddResult<serde_json::Value> {
    let mut args = std::env::args_os().skip(1);
    let path = PathBuf::from(args.next().ok_or_else(|| {
        MddError::new(
            ErrorCode::InvalidArgument,
            "example",
            "usage: manifest_summary APK [EXPECTED_SHA256]",
        )
    })?);
    let expected_sha256 = args
        .next()
        .map(|v| {
            v.into_string().map_err(|_| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "example",
                    "expected SHA-256 must be text",
                )
            })
        })
        .transpose()?;
    if args.next().is_some() {
        return Err(MddError::new(
            ErrorCode::InvalidArgument,
            "example",
            "unexpected arguments",
        ));
    }
    let snapshot = Snapshot::capture(
        &[InputSpec {
            path,
            kind: InputKind::Apk,
            expected_sha256,
        }],
        CaptureLimits::default(),
    )?;
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy {
            dex_selection: DexSelection::ResourcesOnly,
            require_dex: false,
            reject_duplicate_selected_names: false,
            hold_dex_bytes: true,
        },
        ArchiveLimits::default(),
    )?;
    let manifests: Vec<_> = inventory
        .manifest()
        .members
        .iter()
        .filter(|member| member.raw_name == b"AndroidManifest.xml")
        .collect();
    if manifests.is_empty() {
        return Err(MddError::new(
            ErrorCode::InvalidInput,
            "example",
            "AndroidManifest.xml member is absent",
        ));
    }
    // Every physical occurrence is consumed; duplicate names do not choose an
    // arbitrary winner and do not imply a uniquely resolved application.
    let mut results = Vec::new();
    for member in manifests {
        let evidence = ResourceByteEvidence::build(&snapshot, &inventory, &member.member_id)?;
        let bytes = evidence.lease();
        let document = parse_manifest(Arc::clone(&bytes), ManifestLimits::default())?;
        if !Arc::ptr_eq(&bytes, &document.lease()) {
            return Err(MddError::new(
                ErrorCode::InternalFault,
                "example",
                "Manifest document lost its immutable member lease",
            ));
        }
        results.push(
            serde_json::json!({"resource":evidence,"document":document,"manifest_complete":true,
            "source_byte_lease_shared":true}),
        );
    }
    Ok(
        serde_json::json!({"operation_status":"ok","input_content_id":inventory.manifest().source_content_id,
        "manifest_occurrences":results.len(),"manifests":results,"calculation_complete":true,
        "full_audit_complete":false,"scope":"complete Manifest tree and typed attributes; unresolved resource references; no ARSC/runtime defaults/tool paging qualification"}),
    )
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
                serde_json::json!({"operation_status":"error","error":error,"calculation_complete":false,"full_audit_complete":false})
            );
            ExitCode::FAILURE
        }
    }
}
