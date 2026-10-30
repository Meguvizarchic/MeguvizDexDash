use crate::MetadataFacts;
use mdd_input::{
    archive::{ArchiveInventory, DexCandidate, DexSelection},
    snapshot::Snapshot,
};
use mdd_types::{Completeness, DecimalU64, ErrorCode, MddError, MddResult, content_id};
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Debug, Serialize)]
pub struct SelectedDex {
    pub dex_occurrence_id: String,
    pub source_occurrence_id: String,
    pub member_id: String,
    pub content_id: String,
    pub file_id: u32,
    pub detected_version: String,
}

/// A scope-local occurrence coordinate and its validated physical string pool.
/// The ordinal is scoped to this selection and never replaces physical identity.
pub struct OccurrencePoolCoordinate<'a> {
    pub dex: &'a SelectedDex,
    pub occurrence_pool_ordinal: u32,
    pub physical_pool: &'a crate::metadata::StringPoolIdentity,
}

/// Candidate one-selected-DEX-per-pool numbering; not a legacy profile admission.
pub struct ScopedPoolCoordinates<'a> {
    pub scope: &'a SelectedScope,
    pub rows: Vec<OccurrencePoolCoordinate<'a>>,
}

#[cfg(test)]
mod metadata_rows_tests {
    use super::*;
    use mdd_dex::strings::StringLimits;
    use mdd_input::{
        archive::{ArchiveLimits, InventoryPolicy},
        snapshot::{CaptureLimits, InputKind, InputSpec},
    };
    use std::path::PathBuf;

    #[test]
    fn scope_commitment_preimage_binds_snapshot_and_selected_members() {
        fn frame<'a>(bytes: &'a [u8], cursor: &mut usize) -> &'a [u8] {
            let end = *cursor + 8;
            let size = u64::from_le_bytes(bytes[*cursor..end].try_into().unwrap()) as usize;
            *cursor = end + size;
            &bytes[end..*cursor]
        }
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/generated/multidex-stored.apk");
        let input = InputSpec {
            path,
            kind: InputKind::Apk,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input.clone()], CaptureLimits::default()).unwrap();
        let inventories: Vec<_> = snapshot
            .sources()
            .iter()
            .map(|source| {
                ArchiveInventory::build(
                    source,
                    InventoryPolicy::default(),
                    ArchiveLimits::default(),
                )
                .unwrap()
            })
            .collect();
        let facts: Vec<_> = inventories
            .iter()
            .flat_map(|inventory| {
                (0..inventory.selected_dexes().len())
                    .map(|index| {
                        MetadataFacts::build(&snapshot, inventory, index, StringLimits::default())
                            .unwrap()
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let refs: Vec<_> = facts.iter().collect();
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0], &inventories[1]])
            .unwrap();
        let bytes = scope
            .commitment_preimage(
                &snapshot,
                &[&inventories[1], &inventories[0]],
                &refs,
                4,
                8192,
            )
            .unwrap();
        let prefix = b"mdd-selected-scope-v1";
        assert!(bytes.starts_with(prefix));
        let mut cursor = prefix.len();
        for (source, inventory) in snapshot.sources().iter().zip(&inventories) {
            assert_eq!(
                frame(&bytes, &mut cursor),
                source.identity().input_ordinal.0.to_le_bytes()
            );
            assert_eq!(
                frame(&bytes, &mut cursor),
                source.identity().content_id.as_bytes()
            );
            assert_eq!(frame(&bytes, &mut cursor), b"top-level-classes-v1");
            for dex in inventory.selected_dexes() {
                assert_eq!(frame(&bytes, &mut cursor), dex.blob.content_id.as_bytes());
                assert_eq!(
                    frame(&bytes, &mut cursor),
                    dex.blob
                        .identity
                        .archive_member_ordinal
                        .map_or(u64::MAX, |v| v.0)
                        .to_le_bytes()
                );
                assert_eq!(
                    frame(&bytes, &mut cursor),
                    dex.logical_header_byte_offset.0.to_le_bytes()
                );
            }
        }
        assert_eq!(content_id(&bytes[..cursor]), scope.scope_content_key());
        assert_eq!(
            frame(&bytes, &mut cursor),
            snapshot.manifest().snapshot_id.as_bytes()
        );
        assert_eq!(cursor, bytes.len());
        assert_eq!(content_id(&bytes), scope.scope_id());
        let mut tampered = bytes.clone();
        tampered[prefix.len() + 8] ^= 1;
        assert_ne!(content_id(&tampered), scope.scope_id());
        assert_eq!(
            scope
                .commitment_preimage(
                    &snapshot,
                    &[&inventories[0], &inventories[1]],
                    &refs,
                    4,
                    (bytes.len() - 1) as u64
                )
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        let mut bad = scope.clone();
        bad.scope_id = "sha256:forged".into();
        assert_eq!(
            bad.commitment_preimage(
                &snapshot,
                &[&inventories[0], &inventories[1]],
                &refs,
                4,
                8192
            )
            .unwrap_err()
            .code,
            ErrorCode::InternalFault
        );
        let foreign = Snapshot::capture(&[input], CaptureLimits::default()).unwrap();
        assert_eq!(
            scope
                .commitment_preimage(
                    &foreign,
                    &[&inventories[0], &inventories[1]],
                    &refs,
                    4,
                    8192
                )
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        let subset = SelectedScope::from_inventories(&snapshot, &[&inventories[1]]).unwrap();
        let subfacts: Vec<_> = facts
            .iter()
            .filter(|f| {
                f.source().source_occurrence_id == snapshot.sources()[1].identity().occurrence_id
            })
            .collect();
        let sub = subset
            .commitment_preimage(&snapshot, &[&inventories[1]], &subfacts, 4, 8192)
            .unwrap();
        assert!(!subset.covers_all_captured_sources());
        assert_eq!(content_id(&sub), subset.scope_id());
        assert_ne!(scope.scope_id(), subset.scope_id());

        // A one-DEX selected subset still has two captured input sources.
        // The snapshot roster must be bounded before its identity map allocates.
        let raw = InputSpec {
            path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/generated/structured-035.dex"),
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let two = Snapshot::capture(&[raw.clone(), raw], CaptureLimits::default()).unwrap();
        let first = ArchiveInventory::build(
            &two.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let metadata = MetadataFacts::build(&two, &first, 0, StringLimits::default()).unwrap();
        let selected = SelectedScope::from_inventories(&two, &[&first]).unwrap();
        assert_eq!(
            selected
                .inventory_metadata_rows(&[&first], &[&metadata], 1)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            selected
                .commitment_preimage(&two, &[&first], &[&metadata], 1, 8192)
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert!(
            selected
                .commitment_preimage(&two, &[&first], &[&metadata], 2, 8192)
                .is_ok()
        );
    }

    #[test]
    fn scope_inventory_metadata_binds_captured_member_and_occurrence() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/generated/multidex-stored.apk");
        let input = InputSpec {
            path,
            kind: InputKind::Apk,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input.clone()], CaptureLimits::default()).unwrap();
        let inventories: Vec<_> = snapshot
            .sources()
            .iter()
            .map(|source| {
                ArchiveInventory::build(
                    source,
                    InventoryPolicy::default(),
                    ArchiveLimits::default(),
                )
                .unwrap()
            })
            .collect();
        let facts: Vec<_> = inventories
            .iter()
            .flat_map(|inventory| {
                (0..inventory.selected_dexes().len())
                    .map(|n| {
                        MetadataFacts::build(&snapshot, inventory, n, StringLimits::default())
                            .unwrap()
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0], &inventories[1]])
            .unwrap();
        let fact_refs: Vec<_> = facts.iter().rev().collect();
        let rows = scope
            .inventory_metadata_rows(&[&inventories[1], &inventories[0]], &fact_refs, 4)
            .unwrap();
        assert_eq!(rows.len(), 4);
        assert_eq!(
            rows.iter()
                .map(|(_, _, dex, _)| dex.blob.identity.raw_name.as_slice())
                .collect::<Vec<_>>(),
            vec![
                b"classes.dex".as_slice(),
                b"classes2.dex".as_slice(),
                b"classes.dex".as_slice(),
                b"classes2.dex".as_slice()
            ]
        );
        for (index, (selected_input, selected, dex, fact)) in rows.iter().enumerate() {
            assert_eq!(selected.file_id as usize, index);
            assert_eq!(
                selected_input.source_occurrence_id,
                dex.blob.identity.source_occurrence_id
            );
            assert_eq!(selected.member_id, dex.blob.identity.member_id);
            assert_eq!(selected.dex_occurrence_id, fact.source().dex_occurrence_id);
            assert_eq!(dex.physical_dex_id, fact.source().physical_dex_id);
        }
        assert_ne!(rows[0].1.dex_occurrence_id, rows[2].1.dex_occurrence_id);
        assert_eq!(rows[0].2.physical_dex_id, rows[2].2.physical_dex_id);
        assert_eq!(
            scope
                .inventory_metadata_rows(&[&inventories[0]], &fact_refs, 4)
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        assert_eq!(
            scope
                .inventory_metadata_rows(&[&inventories[0], &inventories[0]], &fact_refs, 4)
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            scope
                .inventory_metadata_rows(&[&inventories[0], &inventories[1]], &fact_refs, 3)
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        let foreign = Snapshot::capture(&[input], CaptureLimits::default()).unwrap();
        let foreign_inventory = ArchiveInventory::build(
            &foreign.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        assert_eq!(
            scope
                .inventory_metadata_rows(&[&inventories[0], &foreign_inventory], &fact_refs, 4)
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let second_inventory = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        assert_eq!(
            scope
                .inventory_metadata_rows(&[&second_inventory, &inventories[1]], &fact_refs, 4)
                .unwrap()
                .len(),
            4
        );

        // An input may select no DEX; the input roster still needs a bound
        // before its index is built even though the DEX/metadata rosters are empty.
        let empty = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/zip64/generated/empty.zip");
        let spec = InputSpec {
            path: empty,
            kind: InputKind::Apk,
            expected_sha256: None,
        };
        let empty_snapshot =
            Snapshot::capture(&[spec.clone(), spec], CaptureLimits::default()).unwrap();
        let policy = InventoryPolicy {
            require_dex: false,
            ..InventoryPolicy::default()
        };
        let empty_inventories: Vec<_> = empty_snapshot
            .sources()
            .iter()
            .map(|source| {
                ArchiveInventory::build(source, policy, ArchiveLimits::default()).unwrap()
            })
            .collect();
        let empty_scope = SelectedScope::from_inventories(
            &empty_snapshot,
            &[&empty_inventories[0], &empty_inventories[1]],
        )
        .unwrap();
        assert!(empty_scope.roster_complete());
        assert_eq!(
            empty_scope
                .inventory_metadata_rows(&[&empty_inventories[0]], &[], 1)
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert!(
            empty_scope
                .inventory_metadata_rows(&[&empty_inventories[0], &empty_inventories[1]], &[], 2)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn pool_coordinates_preserve_occurrences_and_match_saved_a0_sample() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let saved_bytes = std::fs::read(
            root.join("artifacts/mdd-026/cross-dex-audit/20261028T164250980578Z/result.json"),
        )
        .unwrap();
        assert_eq!(
            mdd_types::sha256(&saved_bytes),
            "0f3f4f46764973908fad5e6c540ee0b804ed023ec43278464d26318c38ea92e3"
        );
        let saved: serde_json::Value = serde_json::from_slice(&saved_bytes).unwrap();
        let classic = root.join("tests/fixtures/references/generated/classic-035.dex");
        let shared = root.join("tests/fixtures/references/generated/shared-code-035.dex");
        assert_eq!(
            mdd_types::sha256(&std::fs::read(&classic).unwrap()),
            "076dcc64b96b8369327e7ee6e5c05c864ef3bde26c746b6318ee12c52c654dc8"
        );
        assert_eq!(
            mdd_types::sha256(&std::fs::read(&shared).unwrap()),
            "22eb2d4020f172334a99f5c75538af5f2b3e80673adb11803b368cc68aaec0ab"
        );
        for (name, second, same_physical) in [
            ("duplicate-raw-input", classic.clone(), true),
            ("two-distinct-raw", shared, false),
        ] {
            let inputs = [classic.clone(), second].map(|path| InputSpec {
                path,
                kind: InputKind::RawDex,
                expected_sha256: None,
            });
            let snapshot = Snapshot::capture(&inputs, CaptureLimits::default()).unwrap();
            let inventories: Vec<_> = snapshot
                .sources()
                .iter()
                .map(|source| {
                    ArchiveInventory::build(
                        source,
                        InventoryPolicy::default(),
                        ArchiveLimits::default(),
                    )
                    .unwrap()
                })
                .collect();
            let facts: Vec<_> = inventories
                .iter()
                .map(|inventory| {
                    MetadataFacts::build(&snapshot, inventory, 0, StringLimits::default()).unwrap()
                })
                .collect();
            let scope =
                SelectedScope::from_inventories(&snapshot, &[&inventories[0], &inventories[1]])
                    .unwrap();
            let result = scope
                .occurrence_pool_coordinates(&[&facts[1], &facts[0]], 2)
                .unwrap();
            assert_eq!(result.scope.scope_id(), scope.scope_id());
            assert!(result.scope.covers_all_captured_sources());
            assert_eq!(result.rows.len(), 2);
            assert_ne!(
                result.rows[0].dex.dex_occurrence_id,
                result.rows[1].dex.dex_occurrence_id
            );
            assert_eq!(
                result.rows[0].physical_pool.string_pool_id
                    == result.rows[1].physical_pool.string_pool_id,
                same_physical
            );
            let expected = saved["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["case"] == name)
                .unwrap();
            let expected = expected["a0_dex_rows"].as_array().unwrap();
            for (ordinal, row) in result.rows.iter().enumerate() {
                assert_eq!(
                    row.dex.file_id.to_string(),
                    expected[ordinal]["file_id"].as_str().unwrap()
                );
                assert_eq!(
                    row.occurrence_pool_ordinal.to_string(),
                    expected[ordinal]["string_pool_id"].as_str().unwrap()
                );
                assert_eq!(
                    row.physical_pool.dex_occurrence_id,
                    row.dex.dex_occurrence_id
                );
            }
            assert_eq!(
                scope
                    .occurrence_pool_coordinates(&[&facts[0]], 2)
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::IncompleteFacts
            );
            assert_eq!(
                scope
                    .occurrence_pool_coordinates(&[&facts[0], &facts[1]], 1)
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
            let mut invalid = facts[0].clone();
            invalid.string_pool.dex_occurrence_id = "wrong".into();
            assert_eq!(
                scope
                    .occurrence_pool_coordinates(&[&invalid, &facts[1]], 2)
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::InternalFault
            );
            let sub = SelectedScope::from_inventories(&snapshot, &[&inventories[1]]).unwrap();
            let sub_rows = sub.occurrence_pool_coordinates(&[&facts[1]], 1).unwrap();
            assert!(!sub_rows.scope.covers_all_captured_sources());
            assert_eq!(sub_rows.rows[0].occurrence_pool_ordinal, 0);
        }
    }

    #[test]
    fn selected_metadata_rows_preserve_occurrences_and_scope() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input.clone()], CaptureLimits::default()).unwrap();
        let inventories: Vec<_> = snapshot
            .sources()
            .iter()
            .map(|source| {
                ArchiveInventory::build(
                    source,
                    InventoryPolicy::default(),
                    ArchiveLimits::default(),
                )
                .unwrap()
            })
            .collect();
        let facts: Vec<_> = inventories
            .iter()
            .map(|inventory| {
                MetadataFacts::build(&snapshot, inventory, 0, StringLimits::default()).unwrap()
            })
            .collect();
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0], &inventories[1]])
            .unwrap();
        let rows = scope.metadata_rows(&[&facts[1], &facts[0]], 2).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].0.file_id, rows[1].0.file_id), (0, 1));
        assert_ne!(
            rows[0].1.source().dex_occurrence_id,
            rows[1].1.source().dex_occurrence_id
        );
        assert_eq!(
            rows[0].1.source().physical_dex_id,
            rows[1].1.source().physical_dex_id
        );
        assert_eq!(
            rows[0].1.string_pool().string_pool_id,
            rows[1].1.string_pool().string_pool_id
        );
        assert_eq!(rows[0].1.header().file_size, rows[1].1.header().file_size);
        assert!(scope.covers_all_captured_sources());
        assert_eq!(
            scope
                .metadata_rows(&[&facts[0], &facts[1]], 1)
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            scope.metadata_rows(&[&facts[0]], 2).err().unwrap().code,
            ErrorCode::IncompleteFacts
        );
        assert_eq!(
            scope
                .metadata_rows(&[&facts[0], &facts[0]], 2)
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let sub = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        assert!(!sub.covers_all_captured_sources());
        assert_eq!(sub.metadata_rows(&[&facts[0]], 1).unwrap().len(), 1);
        assert_eq!(
            sub.metadata_rows(&[&facts[0], &facts[1]], 2)
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let pending = SelectedScope::pending(&snapshot);
        assert_eq!(
            pending.metadata_rows(&[], 2).err().unwrap().code,
            ErrorCode::IncompleteFacts
        );
        let mut partial = facts[0].clone();
        partial.metadata_coverage = Completeness::Partial;
        assert_eq!(
            sub.metadata_rows(&[&partial], 1).err().unwrap().code,
            ErrorCode::IncompleteFacts
        );
        let other = Snapshot::capture(&[input], CaptureLimits::default()).unwrap();
        let foreign_inventory = ArchiveInventory::build(
            &other.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let foreign =
            MetadataFacts::build(&other, &foreign_inventory, 0, StringLimits::default()).unwrap();
        assert_eq!(
            sub.metadata_rows(&[&foreign], 1).err().unwrap().code,
            ErrorCode::InvalidArgument
        );
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct SelectedInput {
    pub source_occurrence_id: String,
    pub content_id: String,
    pub input_ordinal: DecimalU64,
    pub selection_policy: String,
    pub inventory_complete: bool,
    pub selected_bytes_complete: bool,
    pub origin_display: Option<String>,
}
#[derive(Clone, Serialize)]
pub struct SelectedScope {
    snapshot_id: String,
    scope_id: String,
    scope_content_key: String,
    inputs: Vec<SelectedInput>,
    dexes: Vec<SelectedDex>,
    roster_complete: bool,
    covers_all_captured_sources: bool,
    #[serde(skip)]
    leases: Vec<Arc<[u8]>>,
}
fn error(message: &str) -> MddError {
    MddError::new(ErrorCode::InvalidArgument, "facts.index_scope", message)
}
fn part(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_le_bytes());
    target.extend_from_slice(value);
}
impl SelectedScope {
    /// Before inventory is available the selected DEX roster is unknown, never empty-complete.
    pub fn pending(snapshot: &Snapshot) -> Self {
        let mut bytes = b"mdd-selected-scope-pending-v1".to_vec();
        part(&mut bytes, snapshot.manifest().snapshot_id.as_bytes());
        let inputs = snapshot
            .sources()
            .iter()
            .map(|source| {
                let identity = source.identity();
                part(&mut bytes, identity.occurrence_id.as_bytes());
                SelectedInput {
                    source_occurrence_id: identity.occurrence_id.clone(),
                    content_id: identity.content_id.clone(),
                    input_ordinal: identity.input_ordinal,
                    selection_policy: "inventory_not_built".into(),
                    inventory_complete: false,
                    selected_bytes_complete: false,
                    origin_display: identity.origin_display.clone(),
                }
            })
            .collect();
        Self {
            snapshot_id: snapshot.manifest().snapshot_id.clone(),
            scope_id: content_id(&bytes),
            scope_content_key: snapshot.manifest().snapshot_content_key.clone(),
            inputs,
            dexes: Vec::new(),
            roster_complete: false,
            covers_all_captured_sources: true,
            leases: snapshot
                .sources()
                .iter()
                .map(|source| source.lease())
                .collect(),
        }
    }
    pub fn from_inventories(
        snapshot: &Snapshot,
        inventories: &[&ArchiveInventory],
    ) -> MddResult<Self> {
        if inventories.is_empty() {
            return Err(error(
                "explicit selected scope requires inventories; use pending while unbuilt",
            ));
        }
        let captured: BTreeMap<_, _> = snapshot
            .sources()
            .iter()
            .map(|source| (source.identity().occurrence_id.as_str(), source))
            .collect();
        let mut provided = BTreeMap::new();
        for inventory in inventories {
            let manifest = inventory.manifest();
            let source = captured
                .get(manifest.source_occurrence_id.as_str())
                .ok_or_else(|| error("inventory is outside snapshot"))?;
            if manifest.source_content_id != source.identity().content_id
                || provided
                    .insert(manifest.source_occurrence_id.as_str(), *inventory)
                    .is_some()
            {
                return Err(error("inventory identity mismatch or duplicate source"));
            }
        }
        let mut inputs = Vec::new();
        let mut dexes = Vec::new();
        let mut leases = Vec::new();
        let mut roster_complete = true;
        let mut canonical = b"mdd-selected-scope-v1".to_vec();
        for source in snapshot.sources() {
            let identity = source.identity();
            let Some(inventory) = provided.get(identity.occurrence_id.as_str()) else {
                continue;
            };
            let manifest = inventory.manifest();
            let (policy, dex_selection) = match manifest.selection {
                DexSelection::TopLevelClasses => ("top-level-classes-v1", true),
                DexSelection::AllDexMembers => ("all-dex-members-v1", true),
                DexSelection::ResourcesOnly => ("resources-only-v1", false),
            };
            roster_complete &= manifest.directory_complete
                && manifest.selected_dex_bytes_complete
                && dex_selection;
            part(&mut canonical, &identity.input_ordinal.0.to_le_bytes());
            part(&mut canonical, identity.content_id.as_bytes());
            part(&mut canonical, policy.as_bytes());
            leases.push(source.lease());
            inputs.push(SelectedInput {
                source_occurrence_id: identity.occurrence_id.clone(),
                content_id: identity.content_id.clone(),
                input_ordinal: identity.input_ordinal,
                selection_policy: policy.into(),
                inventory_complete: manifest.directory_complete,
                selected_bytes_complete: manifest.selected_dex_bytes_complete,
                origin_display: identity.origin_display.clone(),
            });
            for dex in inventory.selected_dexes() {
                if dexes.len() >= 1_000_000 {
                    return Err(MddError::new(
                        ErrorCode::QuotaExceeded,
                        "facts.index_scope",
                        "selected DEX roster exceeds budget",
                    ));
                }
                if dex.blob.identity.source_occurrence_id != identity.occurrence_id {
                    return Err(error("selected DEX source occurrence mismatch"));
                }
                part(&mut canonical, dex.blob.content_id.as_bytes());
                part(
                    &mut canonical,
                    &dex.blob
                        .identity
                        .archive_member_ordinal
                        .map_or(u64::MAX, |ordinal| ordinal.0)
                        .to_le_bytes(),
                );
                part(
                    &mut canonical,
                    &dex.logical_header_byte_offset.0.to_le_bytes(),
                );
                dexes.push(SelectedDex {
                    dex_occurrence_id: dex.dex_occurrence_id.clone(),
                    source_occurrence_id: identity.occurrence_id.clone(),
                    member_id: dex.blob.identity.member_id.clone(),
                    content_id: dex.blob.content_id.clone(),
                    file_id: dexes.len() as u32,
                    detected_version: dex.detected_version.clone(),
                });
                leases.push(dex.blob.lease());
            }
        }
        let scope_content_key = content_id(&canonical);
        part(&mut canonical, snapshot.manifest().snapshot_id.as_bytes());
        Ok(Self {
            snapshot_id: snapshot.manifest().snapshot_id.clone(),
            scope_id: content_id(&canonical),
            scope_content_key,
            inputs,
            dexes,
            roster_complete,
            covers_all_captured_sources: provided.len() == captured.len(),
            leases,
        })
    }
    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }
    pub fn scope_content_key(&self) -> &str {
        &self.scope_content_key
    }
    pub fn inputs(&self) -> &[SelectedInput] {
        &self.inputs
    }
    pub fn dexes(&self) -> &[SelectedDex] {
        &self.dexes
    }
    pub fn roster_complete(&self) -> bool {
        self.roster_complete
    }
    pub fn covers_all_captured_sources(&self) -> bool {
        self.covers_all_captured_sources
    }
    pub fn contains_dex(&self, id: &str) -> bool {
        self.dexes.iter().any(|dex| dex.dex_occurrence_id == id)
    }
    pub fn retained_blob_leases(&self) -> usize {
        self.leases.len()
    }

    /// Reconstruct the existing `mdd-selected-scope-v1` commitment preimage
    /// from the captured snapshot and selected inventories. Every component is
    /// length-prefixed with a little-endian u64; the final component is the
    /// snapshot ID. Hashing all bytes yields `scope_id`; hashing the prefix
    /// before that final framed component yields `scope_content_key`.
    ///
    /// This checks identities and both commitments against this scope, but is
    /// not a signature, a coverage certificate, or an independent DEX oracle.
    /// `max_bytes` limits the returned preimage only; `max_entries` limits the
    /// entire captured source roster, selected inputs, and DEX inventories,
    /// including when only a subset is selected. Neither is an RSS or CPU bound.
    /// Frame boundaries between inputs and DEX members require the validated
    /// inventory roster; these bytes alone do not independently describe it.
    pub fn commitment_preimage(
        &self,
        snapshot: &Snapshot,
        inventories: &[&ArchiveInventory],
        facts: &[&MetadataFacts],
        max_entries: u64,
        max_bytes: u64,
    ) -> MddResult<Vec<u8>> {
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.scope_commitment",
                "scope commitment budget exceeded",
            )
        };
        let broken = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.scope_commitment",
                "scope commitment is inconsistent",
            )
        };
        if snapshot.manifest().snapshot_id != self.snapshot_id {
            return Err(error("scope commitment snapshot mismatch"));
        }
        if u64::try_from(snapshot.sources().len()).map_err(|_| quota())? > max_entries {
            return Err(quota());
        }
        let rows = self.inventory_metadata_rows(inventories, facts, max_entries)?;
        let captured: BTreeMap<_, _> = snapshot
            .sources()
            .iter()
            .map(|s| (s.identity().occurrence_id.as_str(), s.identity()))
            .collect();
        if self.inputs.len() > captured.len()
            || self.covers_all_captured_sources != (self.inputs.len() == captured.len())
        {
            return Err(broken());
        }
        let prefix = b"mdd-selected-scope-v1";
        if u64::try_from(prefix.len()).map_err(|_| quota())? > max_bytes {
            return Err(quota());
        }
        let mut canonical = Vec::new();
        canonical
            .try_reserve_exact(prefix.len())
            .map_err(|_| quota())?;
        canonical.extend_from_slice(prefix);
        let append = |bytes: &mut Vec<u8>, value: &[u8]| -> MddResult<()> {
            let n = u64::try_from(value.len()).map_err(|_| quota())?;
            let end = bytes
                .len()
                .checked_add(8)
                .and_then(|v| v.checked_add(value.len()))
                .ok_or_else(quota)?;
            if u64::try_from(end).map_err(|_| quota())? > max_bytes {
                return Err(quota());
            }
            bytes
                .try_reserve_exact(end - bytes.len())
                .map_err(|_| quota())?;
            bytes.extend_from_slice(&n.to_le_bytes());
            bytes.extend_from_slice(value);
            Ok(())
        };
        let mut rows = rows.into_iter().peekable();
        let mut last_ordinal = None;
        for input in &self.inputs {
            let identity = captured
                .get(input.source_occurrence_id.as_str())
                .ok_or_else(broken)?;
            if identity.content_id != input.content_id
                || identity.input_ordinal != input.input_ordinal
                || last_ordinal.is_some_and(|last| last >= input.input_ordinal.0)
            {
                return Err(broken());
            }
            last_ordinal = Some(input.input_ordinal.0);
            append(&mut canonical, &input.input_ordinal.0.to_le_bytes())?;
            append(&mut canonical, input.content_id.as_bytes())?;
            append(&mut canonical, input.selection_policy.as_bytes())?;
            while rows
                .peek()
                .is_some_and(|row| row.0.source_occurrence_id == input.source_occurrence_id)
            {
                let (_, _, dex, _) = rows.next().ok_or_else(broken)?;
                append(&mut canonical, dex.blob.content_id.as_bytes())?;
                append(
                    &mut canonical,
                    &dex.blob
                        .identity
                        .archive_member_ordinal
                        .map_or(u64::MAX, |v| v.0)
                        .to_le_bytes(),
                )?;
                append(
                    &mut canonical,
                    &dex.logical_header_byte_offset.0.to_le_bytes(),
                )?;
            }
        }
        if rows.next().is_some() || content_id(&canonical) != self.scope_content_key {
            return Err(broken());
        }
        append(&mut canonical, self.snapshot_id.as_bytes())?;
        if content_id(&canonical) != self.scope_id {
            return Err(broken());
        }
        Ok(canonical)
    }

    /// Pair the selected DEX roster with complete validated metadata in scope order.
    /// Each tuple retains the scope's file coordinate and the source-bound header;
    /// the scope itself exposes whether all captured sources were selected. This is
    /// not an admitted legacy `dex_files` or string-pool numbering projection.
    /// `max_entries` limits both supplied and selected entries, not CPU or RSS.
    pub fn metadata_rows<'a>(
        &'a self,
        facts: &[&'a MetadataFacts],
        max_entries: u64,
    ) -> MddResult<Vec<(&'a SelectedDex, &'a MetadataFacts)>> {
        if !self.roster_complete {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.scope_metadata",
                "selected DEX roster is incomplete",
            ));
        }
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.scope_metadata",
                "metadata entry budget exceeded",
            )
        };
        if u64::try_from(self.dexes.len()).map_err(|_| quota())? > max_entries
            || u64::try_from(facts.len()).map_err(|_| quota())? > max_entries
        {
            return Err(quota());
        }
        let mut by_occurrence = BTreeMap::new();
        for fact in facts {
            let source = fact.source();
            if source.snapshot_id != self.snapshot_id
                || by_occurrence
                    .insert(source.dex_occurrence_id.as_str(), *fact)
                    .is_some()
            {
                return Err(error("metadata snapshot mismatch or duplicate occurrence"));
            }
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.dexes.len())
            .map_err(|_| quota())?;
        for (index, dex) in self.dexes.iter().enumerate() {
            let fact = by_occurrence
                .remove(dex.dex_occurrence_id.as_str())
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.scope_metadata",
                        "selected DEX metadata missing",
                    )
                })?;
            if fact.metadata_coverage() != Completeness::Complete {
                return Err(MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.scope_metadata",
                    "selected DEX metadata is incomplete",
                ));
            }
            let source = fact.source();
            if usize::try_from(dex.file_id).ok() != Some(index)
                || source.source_occurrence_id != dex.source_occurrence_id
                || source.member_id != dex.member_id
                || source.content_id != dex.content_id
                || fact.header().version != dex.detected_version
            {
                return Err(error("metadata and selected DEX identities differ"));
            }
            rows.push((dex, fact));
        }
        if !by_occurrence.is_empty() {
            return Err(error("metadata occurrence outside selected scope"));
        }
        Ok(rows)
    }

    /// Resolve selected inputs and logical DEX occurrences back to their captured
    /// physical archive members and validated metadata. Rows follow scope order;
    /// raw member names remain available without lossy text conversion. This
    /// does not assign legacy paths, pool numbers, or whole-snapshot coverage.
    /// `max_entries` bounds selected inputs, supplied inventories, candidate
    /// DEXes, and result rows, not total allocation overhead, CPU, or RSS.
    pub fn inventory_metadata_rows<'a>(
        &'a self,
        inventories: &[&'a ArchiveInventory],
        facts: &[&'a MetadataFacts],
        max_entries: u64,
    ) -> MddResult<
        Vec<(
            &'a SelectedInput,
            &'a SelectedDex,
            &'a DexCandidate,
            &'a MetadataFacts,
        )>,
    > {
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.scope_inventory",
                "scope inventory entry budget exceeded",
            )
        };
        if u64::try_from(inventories.len()).map_err(|_| quota())? > max_entries
            || u64::try_from(self.inputs.len()).map_err(|_| quota())? > max_entries
        {
            return Err(quota());
        }
        let metadata = self.metadata_rows(facts, max_entries)?;
        let mut inputs = BTreeMap::new();
        for input in &self.inputs {
            if inputs
                .insert(input.source_occurrence_id.as_str(), input)
                .is_some()
            {
                return Err(error("duplicate selected input identity"));
            }
        }
        let mut seen_inputs = BTreeMap::new();
        let mut dexes = BTreeMap::new();
        let mut count = 0u64;
        for inventory in inventories {
            let manifest = inventory.manifest();
            let input = inputs
                .get(manifest.source_occurrence_id.as_str())
                .ok_or_else(|| error("inventory outside selected scope"))?;
            if seen_inputs
                .insert(manifest.source_occurrence_id.as_str(), ())
                .is_some()
                || manifest.source_content_id != input.content_id
            {
                return Err(error("duplicate or changed inventory identity"));
            }
            let policy = match manifest.selection {
                DexSelection::TopLevelClasses => "top-level-classes-v1",
                DexSelection::AllDexMembers => "all-dex-members-v1",
                DexSelection::ResourcesOnly => "resources-only-v1",
            };
            if policy != input.selection_policy
                || manifest.directory_complete != input.inventory_complete
                || manifest.selected_dex_bytes_complete != input.selected_bytes_complete
            {
                return Err(error(
                    "inventory selection or completeness differs from scope",
                ));
            }
            for dex in inventory.selected_dexes() {
                count = count.checked_add(1).ok_or_else(quota)?;
                if count > max_entries {
                    return Err(quota());
                }
                if dexes.insert(dex.dex_occurrence_id.as_str(), dex).is_some() {
                    return Err(error("duplicate selected DEX occurrence"));
                }
            }
        }
        if seen_inputs.len() != inputs.len() {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.scope_inventory",
                "selected input inventory missing",
            ));
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(metadata.len())
            .map_err(|_| quota())?;
        for (selected, fact) in metadata {
            let dex = dexes
                .remove(selected.dex_occurrence_id.as_str())
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.scope_inventory",
                        "selected DEX inventory missing",
                    )
                })?;
            let input = *inputs
                .get(selected.source_occurrence_id.as_str())
                .ok_or_else(|| error("selected DEX input missing"))?;
            if dex.blob.identity.source_occurrence_id != input.source_occurrence_id
                || dex.blob.identity.input_ordinal != input.input_ordinal
                || dex.blob.identity.member_id != selected.member_id
                || dex.blob.content_id != selected.content_id
                || dex.physical_dex_id != fact.source().physical_dex_id
                || dex.detected_version != selected.detected_version
                || dex.logical_header_byte_offset != fact.header().header_range.byte_offset
            {
                return Err(error("DEX inventory and metadata identities differ"));
            }
            rows.push((input, selected, dex, fact));
        }
        if !dexes.is_empty() {
            return Err(error("inventory DEX outside selected scope"));
        }
        Ok(rows)
    }

    /// Assign one scope-local pool ordinal per selected DEX occurrence, even
    /// when byte-identical occurrences share a physical pool. This candidate
    /// requires complete selected metadata and carries the originating scope;
    /// it does not establish legacy numbering for all DEX formats or inputs.
    /// `max_entries` bounds logical row counts, not allocation overhead or CPU.
    pub fn occurrence_pool_coordinates<'a>(
        &'a self,
        facts: &[&'a MetadataFacts],
        max_entries: u64,
    ) -> MddResult<ScopedPoolCoordinates<'a>> {
        let metadata = self.metadata_rows(facts, max_entries)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(metadata.len()).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.scope_pool",
                "pool row allocation failed",
            )
        })?;
        for (dex, fact) in metadata {
            let pool = fact.string_pool();
            let source = fact.source();
            if pool.dex_occurrence_id != source.dex_occurrence_id
                || pool.physical_dex_id != source.physical_dex_id
                || pool.content_id != source.content_id
            {
                return Err(MddError::new(
                    ErrorCode::InternalFault,
                    "facts.scope_pool",
                    "validated string pool identity differs from source",
                ));
            }
            rows.push(OccurrencePoolCoordinate {
                dex,
                occurrence_pool_ordinal: dex.file_id,
                physical_pool: pool,
            });
        }
        Ok(ScopedPoolCoordinates { scope: self, rows })
    }
}
