//! Lossless typed fact payloads serialized into `mdd-index/1` sections.

use crate::dependency_tracking::{LogicalOccurrenceRef, OccurrenceReuseMap};
use mdd_facts::{
    DexFacts,
    raw_fingerprints::{FingerprintLimits, RawBodyKind, RawCodeEvidence},
};
use mdd_input::{archive::ArchiveInventory, snapshot::Snapshot};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult, sha256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Lossless typed cell matching SQL/Core carrier semantics without storing raw pointers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "val", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum CachedCell {
    Null,
    Bool(bool),
    I64(i64),
    U64(DecimalU64),
    F64Bits(DecimalU64),
    Utf8(String),
    Utf16 {
        units: Vec<u16>,
        original_mutf8: Option<Vec<u8>>,
    },
    Bytes(Vec<u8>),
    DexMutf8 {
        bytes: Vec<u8>,
        utf16_code_units: DecimalU64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedRelationTable {
    pub name: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<CachedCell>>,
    pub row_count: DecimalU64,
    pub table_sha256: String,
}

impl CachedRelationTable {
    pub fn from_rows(
        name: impl Into<String>,
        columns: Vec<String>,
        rows: Vec<Vec<CachedCell>>,
    ) -> MddResult<Self> {
        let name = name.into();
        for (idx, row) in rows.iter().enumerate() {
            if row.len() != columns.len() {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "cache.facts_codec",
                    format!(
                        "table `{name}` row {idx} width {} differs from columns {}",
                        row.len(),
                        columns.len()
                    ),
                ));
            }
        }
        let encoded_rows = serde_json::to_vec(&(&name, &columns, &rows)).map_err(|error| {
            MddError::new(
                ErrorCode::InternalFault,
                "cache.facts_codec",
                error.to_string(),
            )
        })?;
        Ok(Self {
            name,
            columns,
            row_count: DecimalU64(rows.len() as u64),
            rows,
            table_sha256: sha256(&encoded_rows),
        })
    }

    pub fn verify(&self) -> MddResult<()> {
        if self.row_count.0 as usize != self.rows.len() {
            return Err(MddError::new(
                ErrorCode::CacheCorrupt,
                "cache.facts_codec",
                format!("cached table `{}` row_count mismatch", self.name),
            ));
        }
        for row in &self.rows {
            if row.len() != self.columns.len() {
                return Err(MddError::new(
                    ErrorCode::CacheCorrupt,
                    "cache.facts_codec",
                    format!("cached table `{}` row width mismatch", self.name),
                ));
            }
        }
        let encoded =
            serde_json::to_vec(&(&self.name, &self.columns, &self.rows)).map_err(|e| {
                MddError::new(ErrorCode::InternalFault, "cache.facts_codec", e.to_string())
            })?;
        if sha256(&encoded) != self.table_sha256 {
            return Err(MddError::new(
                ErrorCode::CacheCorrupt,
                "cache.facts_codec",
                format!("cached table `{}` digest mismatch", self.name),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceSummary {
    pub file_id: u32,
    pub string_pool_id: u32,
    pub dex_occurrence_id: String,
    pub source_occurrence_id: String,
    pub content_id: String,
    pub byte_length: DecimalU64,
    pub member_name: Option<String>,
    pub logical_header_offset: DecimalU64,
    pub dex_version: String,
    pub string_count: u32,
    pub type_count: u32,
    pub proto_count: u32,
    pub field_count: u32,
    pub method_count: u32,
    pub class_count: u32,
    pub code_item_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedRawCodeMethod {
    pub file_id: u32,
    pub method_idx: u32,
    pub body_kind: String,
    pub code_item_byte_offset: Option<DecimalU64>,
    pub insns_offset: Option<DecimalU64>,
    pub insns_length: Option<DecimalU64>,
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeFindingRecord {
    pub scope_id: String,
    pub canonical_cache_key: String,
    pub predicate_id: String,
    pub covered_layers: Vec<String>,
    pub matched_count: DecimalU64,
    pub verified_complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotAndInventorySection {
    pub snapshot_content_key: String,
    pub capture_policy: String,
    pub occurrence_summaries: Vec<OccurrenceSummary>,
    pub occurrence_reuse_map: OccurrenceReuseMap,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedFactsPayload {
    pub snapshot_and_inventory: SnapshotAndInventorySection,
    pub tables: Vec<CachedRelationTable>,
    pub raw_code_methods: Vec<CachedRawCodeMethod>,
    pub negative_findings: Vec<NegativeFindingRecord>,
}

impl CachedFactsPayload {
    /// Build snapshot/inventory summary + raw code fingerprint evidence from validated `DexFacts`.
    pub fn build_core_sections(
        snapshot: &Snapshot,
        inventories: &[ArchiveInventory],
        dex_facts: &[DexFacts],
    ) -> MddResult<(SnapshotAndInventorySection, Vec<CachedRawCodeMethod>)> {
        let mut by_occ_id: BTreeMap<&str, _> = BTreeMap::new();
        for inv in inventories {
            for cand in inv.selected_dexes() {
                by_occ_id.insert(cand.dex_occurrence_id.as_str(), cand);
            }
        }
        let mut summaries = Vec::with_capacity(dex_facts.len());
        let mut reuse_map = OccurrenceReuseMap::default();
        let mut raw_methods = Vec::new();

        for (ordinal, fact) in dex_facts.iter().enumerate() {
            let file_id = u32::try_from(ordinal).map_err(|_| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "cache.facts_codec",
                    "file_id overflow",
                )
            })?;
            let meta = fact.metadata.as_ref();
            let header = meta.header();
            let cand = by_occ_id.get(fact.occurrence.as_str()).ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "cache.facts_codec",
                    "missing selected candidate matching DexFacts occurrence",
                )
            })?;
            summaries.push(OccurrenceSummary {
                file_id,
                string_pool_id: file_id,
                dex_occurrence_id: fact.occurrence.clone(),
                source_occurrence_id: meta.source().source_occurrence_id.clone(),
                content_id: meta.source().content_id.clone(),
                byte_length: DecimalU64(cand.blob.len() as u64),
                member_name: cand.blob.identity.name_utf8.clone(),
                logical_header_offset: cand.logical_header_byte_offset,
                dex_version: header.version.clone(),
                string_count: meta.strings().len() as u32,
                type_count: meta.types().len() as u32,
                proto_count: meta.prototypes().len() as u32,
                field_count: fact.definitions.definitions().field_references.len() as u32,
                method_count: fact.definitions.definitions().method_references.len() as u32,
                class_count: fact.definitions.definitions().classes.len() as u32,
                code_item_count: fact.code.items().len() as u32,
            });
            reuse_map.record(
                meta.source().content_id.clone(),
                cand.blob.len() as u64,
                LogicalOccurrenceRef {
                    file_id,
                    dex_occurrence_id: fact.occurrence.clone(),
                    source_occurrence_id: meta.source().source_occurrence_id.clone(),
                    member_name: cand.blob.identity.name_utf8.clone(),
                    logical_header_offset: cand.logical_header_byte_offset,
                },
            );

            let raw = RawCodeEvidence::build(
                fact.definitions.as_ref(),
                fact.code.as_ref(),
                FingerprintLimits::default(),
            )?;
            for method in raw.methods() {
                let kind = match method.body_kind {
                    RawBodyKind::Present => "present",
                    RawBodyKind::NativeNoBody => "native_no_body",
                    RawBodyKind::AbstractNoBody => "abstract_no_body",
                };
                raw_methods.push(CachedRawCodeMethod {
                    file_id,
                    method_idx: method.method.local_index,
                    body_kind: kind.to_owned(),
                    code_item_byte_offset: method.code_item_byte_offset,
                    insns_offset: method.insns_range.as_ref().map(|r| r.byte_offset),
                    insns_length: method.insns_range.as_ref().map(|r| r.byte_length),
                    sha256: method.sha256.clone(),
                });
            }
        }

        let section = SnapshotAndInventorySection {
            snapshot_content_key: snapshot.manifest().snapshot_content_key.clone(),
            capture_policy: snapshot.manifest().capture_policy.clone(),
            occurrence_summaries: summaries,
            occurrence_reuse_map: reuse_map,
        };
        Ok((section, raw_methods))
    }

    pub fn verify(&self) -> MddResult<()> {
        for table in &self.tables {
            table.verify()?;
        }
        for neg in &self.negative_findings {
            if !neg.verified_complete {
                return Err(MddError::new(
                    ErrorCode::CacheCorrupt,
                    "cache.facts_codec",
                    "corrupt cache contains non-complete negative finding record",
                ));
            }
        }
        Ok(())
    }
}
