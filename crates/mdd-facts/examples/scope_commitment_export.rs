//! Export a bounded selected-scope preimage and roster for independent checking.
//! Accepts one or more explicit raw DEX or APK paths. Not a coverage certificate.
use mdd_dex::strings::StringLimits;
use mdd_facts::{MetadataFacts, indexes::SelectedScope};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use serde_json::json;
use std::{error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let paths: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    if paths.is_empty() {
        return Err("provide explicit DEX or APK input paths".into());
    }
    let inputs = paths
        .into_iter()
        .map(|path| {
            let kind = match path.extension().and_then(|v| v.to_str()) {
                Some(ext) if ext.eq_ignore_ascii_case("dex") => InputKind::RawDex,
                Some(ext) if ext.eq_ignore_ascii_case("apk") => InputKind::Apk,
                _ => return Err("only raw DEX and APK are supported by this example"),
            };
            Ok(InputSpec {
                path,
                kind,
                expected_sha256: None,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let snapshot = Snapshot::capture(&inputs, CaptureLimits::default())?;
    let inventories = snapshot
        .sources()
        .iter()
        .map(|source| {
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let inventory_refs: Vec<_> = inventories.iter().collect();
    let scope = SelectedScope::from_inventories(&snapshot, &inventory_refs)?;
    let mut facts = Vec::new();
    for inventory in &inventories {
        for index in 0..inventory.selected_dexes().len() {
            facts.push(MetadataFacts::build(
                &snapshot,
                inventory,
                index,
                StringLimits::default(),
            )?);
        }
    }
    let fact_refs: Vec<_> = facts.iter().collect();
    let preimage = scope.commitment_preimage(
        &snapshot,
        &inventory_refs,
        &fact_refs,
        1_000_000,
        128 * 1024 * 1024,
    )?;
    let roster: Vec<_> = scope
        .inputs()
        .iter()
        .zip(&inventories)
        .map(|(input, inventory)| {
            let dexes: Vec<_> = inventory.selected_dexes().iter().map(|dex| json!({
            "content_id": dex.blob.content_id,
            "archive_member_ordinal": dex.blob.identity.archive_member_ordinal.map(|v| v.0),
            "logical_header_byte_offset": dex.logical_header_byte_offset.0,
        })).collect();
            json!({"input_ordinal": input.input_ordinal.0, "content_id": input.content_id,
            "selection_policy": input.selection_policy, "dexes": dexes})
        })
        .collect();
    let hex: String = preimage.iter().map(|byte| format!("{byte:02x}")).collect();
    // The manifest is for identity comparison; do not export local input paths.
    let mut manifest = serde_json::to_value(snapshot.manifest())?;
    let sources = manifest
        .get_mut("sources")
        .and_then(|v| v.as_array_mut())
        .ok_or("snapshot manifest sources are not an array")?;
    for source in sources {
        source
            .as_object_mut()
            .ok_or("snapshot source is not an object")?
            .remove("origin_display");
    }
    println!(
        "{}",
        serde_json::to_string(&json!({"snapshot_id": scope.snapshot_id(),
        "scope_id": scope.scope_id(), "scope_content_key": scope.scope_content_key(),
        "preimage_hex": hex, "roster": roster, "snapshot_manifest": manifest}))?
    );
    Ok(())
}
