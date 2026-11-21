//! Auditable content-object and container dependency tracking (foundation for MDD-064 & MDD-074).

use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Explicit mapping preserving every logical DEX occurrence even when physical `content_id` blobs
/// are deduplicated in storage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalOccurrenceRef {
    pub file_id: u32,
    pub dex_occurrence_id: String,
    pub source_occurrence_id: String,
    pub member_name: Option<String>,
    pub logical_header_offset: DecimalU64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalContentEntry {
    pub content_id: String,
    pub byte_length: DecimalU64,
    pub occurrences: Vec<LogicalOccurrenceRef>,
}

/// Preserves exact multiplicity for physical content deduplication.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceReuseMap {
    pub by_content_id: BTreeMap<String, PhysicalContentEntry>,
}

impl OccurrenceReuseMap {
    pub fn record(&mut self, content_id: String, byte_length: u64, occ: LogicalOccurrenceRef) {
        let entry = self
            .by_content_id
            .entry(content_id.clone())
            .or_insert_with(|| PhysicalContentEntry {
                content_id,
                byte_length: DecimalU64(byte_length),
                occurrences: Vec::new(),
            });
        entry.occurrences.push(occ);
    }

    pub fn total_logical_occurrences(&self) -> usize {
        self.by_content_id
            .values()
            .map(|entry| entry.occurrences.len())
            .sum()
    }

    pub fn physical_blob_count(&self) -> usize {
        self.by_content_id.len()
    }
}

/// Shared-container cache dependency for multi-header formats (such as DEX `041`).
///
/// Changing any byte in the physical container or in any forward-shared tail region invalidates
/// every logical DEX cached against that container.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedContainerDependency {
    pub container_format: String,
    pub physical_container_content_id: String,
    pub physical_container_bytes: DecimalU64,
    pub logical_dex_ordinal: u32,
    pub logical_header_offset: DecimalU64,
    pub shared_ranges_sha256: String,
}

impl SharedContainerDependency {
    pub fn verify_against_container(
        &self,
        actual_container_content_id: &str,
        actual_shared_ranges_sha256: &str,
    ) -> MddResult<()> {
        if self.physical_container_content_id != actual_container_content_id
            || self.shared_ranges_sha256 != actual_shared_ranges_sha256
        {
            return Err(MddError::new(
                ErrorCode::StaleCache,
                "cache.dependency",
                "shared container bytes changed; logical DEX cache invalidated",
            )
            .detail(
                "expected_container",
                self.physical_container_content_id.clone(),
            )
            .detail("actual_container", actual_container_content_id.to_owned()));
        }
        Ok(())
    }
}

/// Fine-grained method-level incremental dependency tracking remains explicitly disabled until
/// cross-method negative/hierarchy/constant-pool proofs are established in MDD-064.
pub fn fine_grained_method_incremental_enabled() -> bool {
    false
}
