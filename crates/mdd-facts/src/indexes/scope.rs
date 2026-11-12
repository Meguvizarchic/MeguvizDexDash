use crate::MetadataFacts;
use mdd_input::{
    archive::{ArchiveInventory, DexCandidate, DexSelection},
    snapshot::Snapshot,
};
use mdd_types::{Completeness, DecimalU64, ErrorCode, MddError, MddResult, content_id};
use serde::Serialize;
use std::{collections::BTreeMap, path::Path, sync::Arc};

#[derive(Clone, Debug, Serialize)]
pub struct SelectedDex {
    pub dex_occurrence_id: String,
    pub source_occurrence_id: String,
    pub member_id: String,
    pub content_id: String,
    pub file_id: u32,
    pub detected_version: String,
    /// Archive member name when the captured inventory decoded it losslessly.
    /// `None` covers both a raw DEX input (no archive member) and an archive
    /// member whose name is not UTF-8; `archive_member_ordinal` distinguishes
    /// the two, so a name is never invented for a non-UTF-8 member.
    pub member_name: Option<String>,
    /// `None` only for a raw DEX capture, whose member is the captured file
    /// itself rather than an archive entry.
    pub archive_member_ordinal: Option<DecimalU64>,
}

/// The two `dex_files` provenance columns of one selected DEX occurrence.
///
/// Both are exact UTF-8 text or an explicit error: a non-UTF-8 source path or
/// archive member name is refused instead of being replaced by a lossy
/// spelling. `source_path` is the snapshot's recorded source display and
/// `entry_name` follows an explicit policy: an archive member name for an APK,
/// and the captured file's final path component for a raw DEX.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DexFileProvenance {
    pub source_path: String,
    pub entry_name: String,
}

/// One complete 28-column `dex_files` row: the 26 validated metadata atoms plus
/// the two snapshot/archive provenance columns.
///
/// `string_pool_id` stays a caller-supplied catalog coordinate, exactly like
/// [`crate::MetadataFacts::dex_file_rows`]; this scope does not assign legacy
/// pool numbers. `file_id` is the scope-local occurrence ordinal.
#[derive(Clone, Debug, Serialize)]
pub struct ScopeDexFileRow {
    pub file_id: u32,
    pub string_pool_id: u32,
    pub source_path: String,
    pub entry_name: String,
    pub byte_len: u64,
    pub dex_version: String,
    pub checksum: u32,
    pub signature_hex: String,
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_count: u32,
    pub string_ids_off: u32,
    pub type_count: u32,
    pub type_ids_off: u32,
    pub proto_count: u32,
    pub proto_ids_off: u32,
    pub field_count: u32,
    pub field_ids_off: u32,
    pub method_count: u32,
    pub method_ids_off: u32,
    pub class_count: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

impl ScopeDexFileRow {
    /// Assembled column names in contract order.
    pub const COLUMNS: &[&str] = &[
        "file_id",
        "string_pool_id",
        "source_path",
        "entry_name",
        "byte_len",
        "dex_version",
        "checksum",
        "signature_hex",
        "file_size",
        "header_size",
        "endian_tag",
        "link_size",
        "link_off",
        "map_off",
        "string_count",
        "string_ids_off",
        "type_count",
        "type_ids_off",
        "proto_count",
        "proto_ids_off",
        "field_count",
        "field_ids_off",
        "method_count",
        "method_ids_off",
        "class_count",
        "class_defs_off",
        "data_size",
        "data_off",
    ];
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

    /// The two `dex_files` provenance columns come from the same captured
    /// snapshot/inventory generation as the header atoms, and the complete row
    /// matches the recorded A0 slice for both a raw DEX and a multi-DEX APK.
    #[test]
    fn dex_file_rows_bind_scope_provenance_and_match_recorded_a0() {
        let dex = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/references/generated/classic-035.dex");
        let apk = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/generated/multidex-stored.apk");
        for (path, kind, expected_names) in [
            (dex.clone(), InputKind::RawDex, vec!["classic-035.dex"]),
            (
                apk.clone(),
                InputKind::Apk,
                vec!["classes.dex", "classes2.dex"],
            ),
        ] {
            let snapshot = Snapshot::capture(
                &[InputSpec {
                    path: path.clone(),
                    kind,
                    expected_sha256: None,
                }],
                CaptureLimits::default(),
            )
            .unwrap();
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
                            MetadataFacts::build(
                                &snapshot,
                                inventory,
                                index,
                                StringLimits::default(),
                            )
                            .unwrap()
                        })
                        .collect::<Vec<_>>()
                })
                .collect();
            let references: Vec<_> = facts.iter().collect();
            let scope =
                SelectedScope::from_inventories(&snapshot, &inventories.iter().collect::<Vec<_>>())
                    .unwrap();
            let pool_ids = (0..scope.dexes().len() as u32).collect::<Vec<_>>();
            let rows = scope
                .dex_file_rows(&references, &pool_ids, 4)
                .unwrap_or_else(|error| panic!("{path:?}: {error}"));
            assert_eq!(rows.len(), expected_names.len());
            // Column set: exactly the 28 contract columns, in contract order.
            let actual = serde_json::to_value(&rows).unwrap();
            let first = actual.as_array().unwrap()[0].as_object().unwrap();
            assert_eq!(first.len(), 28);
            let mut names = first.keys().map(String::as_str).collect::<Vec<_>>();
            names.sort_unstable();
            let mut expected_columns = ScopeDexFileRow::COLUMNS.to_vec();
            expected_columns.sort_unstable();
            assert_eq!(names, expected_columns);
            for (ordinal, row) in rows.iter().enumerate() {
                assert_eq!(row.file_id, ordinal as u32);
                assert_eq!(row.string_pool_id, ordinal as u32);
                // `source_path` is the recorded capture path, not a reconstruction.
                assert_eq!(
                    row.source_path,
                    path.to_str().unwrap(),
                    "raw-DEX and APK captures both record their own path"
                );
                assert_eq!(row.entry_name, expected_names[ordinal]);
                // Non-nullable text columns must not be empty placeholders.
                assert!(!row.source_path.is_empty());
                assert!(!row.entry_name.is_empty());
                assert!(!row.dex_version.is_empty());
                assert_eq!(row.signature_hex.len(), 40);
                // The header atoms agree with the same-occurrence metadata row.
                let base = facts[ordinal]
                    .dex_file_rows(row.file_id, row.string_pool_id)
                    .unwrap();
                let base = &base[0];
                assert_eq!(row.byte_len, base.byte_len);
                assert_eq!(row.checksum, base.checksum);
                assert_eq!(row.signature_hex, base.signature_hex);
                assert_eq!(row.file_size, base.file_size);
                assert_eq!(row.header_size, base.header_size);
                assert_eq!(row.endian_tag, base.endian_tag);
                assert_eq!(row.link_size, base.link_size);
                assert_eq!(row.link_off, base.link_off);
                assert_eq!(row.map_off, base.map_off);
                assert_eq!(row.string_count, base.string_count);
                assert_eq!(row.string_ids_off, base.string_ids_off);
                assert_eq!(row.type_count, base.type_count);
                assert_eq!(row.type_ids_off, base.type_ids_off);
                assert_eq!(row.proto_count, base.proto_count);
                assert_eq!(row.proto_ids_off, base.proto_ids_off);
                assert_eq!(row.field_count, base.field_count);
                assert_eq!(row.field_ids_off, base.field_ids_off);
                assert_eq!(row.method_count, base.method_count);
                assert_eq!(row.method_ids_off, base.method_ids_off);
                assert_eq!(row.class_count, base.class_count);
                assert_eq!(row.class_defs_off, base.class_defs_off);
                assert_eq!(row.data_size, base.data_size);
                assert_eq!(row.data_off, base.data_off);
            }
        }
    }

    /// The two columns are gated as a pair of exact columns, and an unknown
    /// column is an explicit argument error rather than a silent projection.
    #[test]
    fn dex_file_column_gate_accepts_the_contract_and_rejects_unknown_columns() {
        assert!(SelectedScope::require_dex_file_columns(&["*"]).is_ok());
        assert!(SelectedScope::require_dex_file_columns(ScopeDexFileRow::COLUMNS).is_ok());
        for column in ["source_path", "entry_name"] {
            assert!(SelectedScope::require_dex_file_columns(&[column]).is_ok());
        }
        let error = SelectedScope::require_dex_file_columns(&["file_path"]).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(error.details["column"], "file_path");
    }

    /// A raw-DEX entry name is the captured file's final component, and a
    /// per-occurrence pool coordinate list must match the roster exactly.
    #[test]
    fn dex_file_provenance_policy_and_budgets_fail_closed() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/references/generated/classic-035.dex");
        let snapshot = Snapshot::capture(
            &[InputSpec {
                path: path.clone(),
                kind: InputKind::RawDex,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
        )
        .unwrap();
        let inventory = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventory]).unwrap();
        let provenance = scope.dex_file_provenance(&scope.dexes()[0]).unwrap();
        assert_eq!(provenance.entry_name, "classic-035.dex");
        assert_eq!(provenance.source_path, path.to_str().unwrap());
        assert_eq!(
            scope
                .dex_file_rows(&[&metadata], &[], 4)
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument,
            "one pool coordinate per selected DEX is required"
        );
        assert_eq!(
            scope
                .dex_file_rows(&[&metadata], &[0, 1], 4)
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        // A forged pool coordinate list is not silently truncated either.
        let mut forged = scope.clone();
        forged.dexes[0].member_name = None;
        forged.dexes[0].archive_member_ordinal = Some(DecimalU64(3));
        let error = forged.dex_file_provenance(&forged.dexes[0]).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedQuery);
        assert_eq!(error.details["reason"], "ENTRY_NAME_NOT_UTF8");
    }

    /// The recorded A0 `dex_files` provenance slice for the same fixtures: a raw
    /// DEX reports its own path and file name, and a two-member APK reports the
    /// shared APK path with each member name in roster order.
    #[test]
    fn dex_file_provenance_matches_recorded_a0_entries() {
        let recorded: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/provenance/a0-dex-files-provenance.json"
        ))
        .unwrap();
        let cases = recorded["cases"].as_array().unwrap();
        // Each recorded case captured a specific input list, so the reproduction
        // must use the same list rather than one representative fixture. The
        // recorded `source_path` is the caller's own spelling (the projection is
        // the snapshot's `origin_display` verbatim), so the paths are rebuilt
        // component by component to keep the platform separators identical.
        let classic: &[&str] = &[
            "tests",
            "fixtures",
            "references",
            "generated",
            "classic-035.dex",
        ];
        let shared: &[&str] = &[
            "tests",
            "fixtures",
            "references",
            "generated",
            "shared-code-035.dex",
        ];
        let synthetic: &[&str] = &[
            "artifacts",
            "mdd-026",
            "column-audit-v10",
            "_probe-verify_cross_dex_identity",
            "20261109T045613053519Z",
            "synthetic-same-content.apk",
        ];
        let sources = [
            (
                "duplicate-raw-input",
                vec![(classic, InputKind::RawDex), (classic, InputKind::RawDex)],
            ),
            (
                "two-distinct-raw",
                vec![(classic, InputKind::RawDex), (shared, InputKind::RawDex)],
            ),
            (
                "same-content-multidex-apk",
                vec![(synthetic, InputKind::Apk)],
            ),
        ];
        for (case, inputs) in sources {
            let entry = cases
                .iter()
                .find(|entry| entry["case"] == case)
                .unwrap_or_else(|| panic!("recorded case {case} missing"));
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(Path::parent)
                .expect("crate sits two levels below the repository root")
                .to_path_buf();
            let specs = inputs
                .into_iter()
                .map(|(fixture, kind)| InputSpec {
                    path: fixture
                        .iter()
                        .fold(root.clone(), |path, part| path.join(part)),
                    kind,
                    expected_sha256: None,
                })
                .collect::<Vec<_>>();
            let snapshot = Snapshot::capture(&specs, CaptureLimits::default()).unwrap();
            let inventories = snapshot
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
                .collect::<Vec<_>>();
            let scope =
                SelectedScope::from_inventories(&snapshot, &inventories.iter().collect::<Vec<_>>())
                    .unwrap();
            let recorded_rows = entry["a0_dex_rows"].as_array().unwrap();
            assert_eq!(scope.dexes().len(), recorded_rows.len(), "{case}");
            for (ordinal, expected) in recorded_rows.iter().enumerate() {
                let provenance = scope.dex_file_provenance(&scope.dexes()[ordinal]).unwrap();
                // The fixture keeps A0's echoed path relative to the checkout it ran in,
                // so strip this checkout's root instead of depending on where the
                // repository happens to live.
                let relative = Path::new(&provenance.source_path)
                    .strip_prefix(&root)
                    .unwrap_or_else(|_| {
                        panic!(
                            "{case} row {ordinal}: source_path is not under the checkout root: {}",
                            provenance.source_path
                        )
                    })
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                assert_eq!(
                    relative,
                    expected["source_path"].as_str().unwrap(),
                    "{case} source_path row {ordinal}"
                );
                assert_eq!(
                    provenance.entry_name,
                    expected["entry_name"].as_str().unwrap(),
                    "{case} entry_name row {ordinal}"
                );
            }
        }
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
                    member_name: dex.blob.identity.name_utf8.clone(),
                    archive_member_ordinal: dex.blob.identity.archive_member_ordinal,
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

    /// Resolve the two `dex_files` provenance columns for one selected DEX.
    ///
    /// `source_path` is the snapshot's recorded source display, which is exact
    /// UTF-8 by construction or absent. `entry_name` is the archive member name
    /// for an APK input and the captured file's final path component for a raw
    /// DEX input, matching the reference behaviour that a raw `.dex` has no
    /// archive member yet still reports one entry name. A non-UTF-8 archive
    /// member name or source path is refused with `UnsupportedQuery`: the
    /// contract column is non-nullable `Utf8`, so no lossy spelling is
    /// substituted.
    pub fn dex_file_provenance(&self, dex: &SelectedDex) -> MddResult<DexFileProvenance> {
        let input = self
            .inputs
            .iter()
            .find(|input| input.source_occurrence_id == dex.source_occurrence_id)
            .ok_or_else(|| error("selected DEX input outside scope"))?;
        let source_path = input.origin_display.clone().ok_or_else(|| {
            MddError::new(
                ErrorCode::UnsupportedQuery,
                "facts.scope_provenance",
                "captured source has no lossless UTF-8 path representation",
            )
            .detail("reason", "SOURCE_PATH_NOT_UTF8")
            .detail("snapshot_id", self.snapshot_id.clone())
            .detail("source_occurrence_id", input.source_occurrence_id.clone())
            .detail("dex_occurrence_id", dex.dex_occurrence_id.clone())
        })?;
        let entry_name = match (&dex.member_name, dex.archive_member_ordinal) {
            // A selected archive member: the decoded name is authoritative only
            // when the inventory produced exact UTF-8 for it.
            (Some(name), Some(_)) => name.clone(),
            (None, Some(ordinal)) => {
                return Err(MddError::new(
                    ErrorCode::UnsupportedQuery,
                    "facts.scope_provenance",
                    "archive member name is not lossless UTF-8",
                )
                .detail("reason", "ENTRY_NAME_NOT_UTF8")
                .detail("snapshot_id", self.snapshot_id.clone())
                .detail("member_id", dex.member_id.clone())
                .detail("archive_member_ordinal", ordinal.0.to_string())
                .detail("dex_occurrence_id", dex.dex_occurrence_id.clone()));
            }
            // A raw DEX capture has no archive member: the reference reports the
            // captured file's last path component.
            (None, None) => Path::new(&source_path)
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::UnsupportedQuery,
                        "facts.scope_provenance",
                        "captured raw DEX path has no lossless UTF-8 final component",
                    )
                    .detail("reason", "ENTRY_NAME_POLICY_UNAVAILABLE")
                    .detail("snapshot_id", self.snapshot_id.clone())
                    .detail("dex_occurrence_id", dex.dex_occurrence_id.clone())
                })?,
            // A member name without a member ordinal is an internal inconsistency:
            // falling back to the path would silently report a name this occurrence
            // does not have.
            (Some(_), None) => {
                return Err(MddError::new(
                    ErrorCode::InternalFault,
                    "facts.scope_provenance",
                    "selected DEX has a member name but no archive member ordinal",
                )
                .detail("snapshot_id", self.snapshot_id.clone())
                .detail("member_id", dex.member_id.clone())
                .detail("dex_occurrence_id", dex.dex_occurrence_id.clone()));
            }
        };
        if entry_name.is_empty() {
            return Err(MddError::new(
                ErrorCode::UnsupportedQuery,
                "facts.scope_provenance",
                "entry name is empty",
            )
            .detail("reason", "ENTRY_NAME_POLICY_UNAVAILABLE")
            .detail("snapshot_id", self.snapshot_id.clone())
            .detail("dex_occurrence_id", dex.dex_occurrence_id.clone()));
        }
        Ok(DexFileProvenance {
            source_path,
            entry_name,
        })
    }

    /// Gate a requested `dex_files` column list against the complete 28-column
    /// scope projection. `*` is accepted because every contract column of this
    /// relation now has a production value.
    pub fn require_dex_file_columns(columns: &[&str]) -> MddResult<()> {
        for column in columns {
            if *column != "*" && !ScopeDexFileRow::COLUMNS.contains(column) {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.scope_provenance",
                    "unknown dex_files column",
                )
                .detail("column", (*column).to_owned()));
            }
        }
        Ok(())
    }

    /// Project one complete `dex_files` row per selected DEX occurrence, in
    /// `file_id` order.
    ///
    /// The 26 header/table atoms come from each occurrence's own validated
    /// metadata; `source_path`/`entry_name` come from the same captured snapshot
    /// and inventory generation. `string_pool_id` is supplied by the caller,
    /// exactly as in [`MetadataFacts::dex_file_rows`]: this scope never invents
    /// legacy pool numbers. `max_entries` bounds selected DEX rows only.
    pub fn dex_file_rows(
        &self,
        facts: &[&MetadataFacts],
        string_pool_ids: &[u32],
        max_entries: u64,
    ) -> MddResult<Vec<ScopeDexFileRow>> {
        Self::require_dex_file_columns(ScopeDexFileRow::COLUMNS)?;
        if !self.roster_complete {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.scope_provenance",
                "selected DEX roster is incomplete",
            ));
        }
        if string_pool_ids.len() != self.dexes.len() {
            return Err(error(
                "string_pool_ids must supply exactly one coordinate per selected DEX",
            ));
        }
        let rows = self.metadata_rows(facts, max_entries)?;
        let mut output = Vec::new();
        output.try_reserve_exact(rows.len()).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.scope_provenance",
                "dex_files row allocation failed",
            )
        })?;
        for (ordinal, (dex, fact)) in rows.into_iter().enumerate() {
            let provenance = self.dex_file_provenance(dex)?;
            let base = fact
                .dex_file_rows(dex.file_id, string_pool_ids[ordinal])?
                .pop()
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.scope_provenance",
                        "metadata dex_files row is missing",
                    )
                })?;
            output.push(ScopeDexFileRow {
                file_id: base.file_id,
                string_pool_id: base.string_pool_id,
                source_path: provenance.source_path,
                entry_name: provenance.entry_name,
                byte_len: base.byte_len,
                dex_version: base.dex_version,
                checksum: base.checksum,
                signature_hex: base.signature_hex,
                file_size: base.file_size,
                header_size: base.header_size,
                endian_tag: base.endian_tag,
                link_size: base.link_size,
                link_off: base.link_off,
                map_off: base.map_off,
                string_count: base.string_count,
                string_ids_off: base.string_ids_off,
                type_count: base.type_count,
                type_ids_off: base.type_ids_off,
                proto_count: base.proto_count,
                proto_ids_off: base.proto_ids_off,
                field_count: base.field_count,
                field_ids_off: base.field_ids_off,
                method_count: base.method_count,
                method_ids_off: base.method_ids_off,
                class_count: base.class_count,
                class_defs_off: base.class_defs_off,
                data_size: base.data_size,
                data_off: base.data_off,
            });
        }
        Ok(output)
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
