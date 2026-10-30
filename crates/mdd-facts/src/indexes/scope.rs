use crate::MetadataFacts;
use mdd_input::{
    archive::{ArchiveInventory, DexSelection},
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
