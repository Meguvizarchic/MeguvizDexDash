//! Auditable whole-`ContentId` object reuse, container invalidation, and workload-denominator
//! accounting for persistent fact caches (`MDD-064`).

use crate::dependency_tracking::{
    LogicalOccurrenceRef, OccurrenceReuseMap, SharedContainerDependency,
};
use crate::facts_codec::{NegativeFindingRecord, OccurrenceSummary};
use crate::guard::{PersistEligibility, PersistScopeCheck};
use mdd_types::{
    Coverage, DecimalU64, ErrorCode, Execution, MddError, MddResult, Response, sha256,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Structured workload metrics for a single logical DEX member used as the denominator
/// when computing incremental reuse savings (never extrapolated from changed file bytes).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadUnitSummary {
    pub member_bytes: DecimalU64,
    pub string_count: u32,
    pub type_count: u32,
    pub proto_count: u32,
    pub field_count: u32,
    pub method_count: u32,
    pub class_count: u32,
    pub code_item_count: u32,
}

impl Default for WorkloadUnitSummary {
    fn default() -> Self {
        Self {
            member_bytes: DecimalU64(0),
            string_count: 0,
            type_count: 0,
            proto_count: 0,
            field_count: 0,
            method_count: 0,
            class_count: 0,
            code_item_count: 0,
        }
    }
}

impl WorkloadUnitSummary {
    pub fn from_occurrence_summary(summary: &OccurrenceSummary) -> Self {
        Self {
            member_bytes: summary.byte_length,
            string_count: summary.string_count,
            type_count: summary.type_count,
            proto_count: summary.proto_count,
            field_count: summary.field_count,
            method_count: summary.method_count,
            class_count: summary.class_count,
            code_item_count: summary.code_item_count,
        }
    }

    /// Deterministic fact-build workload weight combining tables that drive parser, definitions,
    /// code decoding, and cross-reference passes. Guaranteed `>= 1` for any valid member.
    pub fn total_work_units(&self) -> u64 {
        let structural = u64::from(self.string_count)
            + u64::from(self.type_count)
            + u64::from(self.proto_count)
            + u64::from(self.field_count)
            + u64::from(self.method_count) * 2
            + u64::from(self.class_count) * 2
            + u64::from(self.code_item_count) * 4;
        structural.max(1)
    }
}

/// Verified physical `content_id` object stored in an auditable whole-object reuse index.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentCacheRecord {
    pub semantics_digest: String,
    pub content_id: String,
    pub workload: WorkloadUnitSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_dependency: Option<SharedContainerDependency>,
    pub persisted_scope_id: String,
}

/// Reason why a cached physical `content_id` could or could not be reused for an occurrence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReuseOutcomeReason {
    /// Identical physical `content_id` and `semantics_digest` with valid container checks.
    ReusedWholeContentId,
    /// No prior verified entry for `(semantics_digest, content_id)`.
    ColdMissNewContent,
    /// Shared container bytes or tail signature changed; whole member must rebuild.
    InvalidatedSharedContainer,
    /// Explicit container dependency mismatch (`None` vs `Some` or ordinal/offset mismatch).
    InvalidatedContainerBoundaryMismatch,
}

/// Per-logical-occurrence decision ensuring physical deduplication never erases any logical source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalOccurrenceReuseDecision {
    pub file_id: u32,
    pub dex_occurrence_id: String,
    pub source_occurrence_id: String,
    pub member_name: Option<String>,
    pub logical_header_offset: DecimalU64,
    pub content_id: String,
    pub reused: bool,
    pub reason: ReuseOutcomeReason,
    pub workload_units: DecimalU64,
    pub member_bytes: DecimalU64,
}

/// One logical member target passed into `ContentObjectReuseIndex::evaluate_target`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetMemberSpec {
    pub occurrence: LogicalOccurrenceRef,
    pub content_id: String,
    pub workload: WorkloadUnitSummary,
    pub container_dependency: Option<SharedContainerDependency>,
}

/// Whole-task denominator breakdown proving savings are computed from affected workload,
/// never extrapolated from changed byte percentage.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadReuseAccounting {
    pub denominator_task_id: String,
    pub total_logical_occurrences: usize,
    pub unique_physical_objects: usize,
    pub reused_physical_objects: usize,
    pub rebuilt_physical_objects: usize,
    pub logical_occurrences_backed_by_reuse: usize,
    pub logical_occurrences_requiring_rebuild: usize,
    pub total_member_bytes: DecimalU64,
    pub reused_member_bytes: DecimalU64,
    pub changed_or_rebuilt_bytes: DecimalU64,
    pub changed_byte_ratio: f64,
    pub total_workload_units: DecimalU64,
    pub reused_workload_units: DecimalU64,
    pub affected_workload_units: DecimalU64,
    pub affected_workload_ratio: f64,
    pub realized_workload_saving_ratio: f64,
    pub extrapolation_from_changed_bytes_forbidden: bool,
    pub optional_dex041_prerequisite: bool,
}

/// Full auditable report returned by `ContentObjectReuseIndex::evaluate_target`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentReuseReport {
    pub semantics_digest: String,
    pub occurrence_reuse_map: OccurrenceReuseMap,
    pub decisions: Vec<LogicalOccurrenceReuseDecision>,
    pub accounting: WorkloadReuseAccounting,
    pub fine_grained_method_incremental_enabled: bool,
}

/// Index mapping `(semantics_digest, content_id)` to verified whole-content records.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentObjectReuseIndex {
    records: BTreeMap<(String, String), ContentCacheRecord>,
}

impl ContentObjectReuseIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Registers a verified whole-`content_id` member only if its originating envelope passed
    /// completeness validation (`PersistScopeCheck::from_envelope_parts`).
    pub fn register_verified(
        &mut self,
        coverage: &Coverage,
        execution: &Execution,
        response: &Response,
        operation_error: Option<&MddError>,
        record: ContentCacheRecord,
    ) -> MddResult<()> {
        PersistScopeCheck::from_envelope_parts(coverage, execution, response, operation_error)?;
        if record.semantics_digest.is_empty() || record.content_id.is_empty() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cache.content_reuse",
                "semantics_digest and content_id must be non-empty",
            ));
        }
        self.records.insert(
            (record.semantics_digest.clone(), record.content_id.clone()),
            record,
        );
        Ok(())
    }

    /// Evaluates reuse for every logical occurrence in `targets` while preserving physical
    /// multiplicity and computing denominator savings from actual affected workload units.
    pub fn evaluate_target(
        &self,
        denominator_task_id: &str,
        semantics_digest: &str,
        targets: &[TargetMemberSpec],
    ) -> MddResult<ContentReuseReport> {
        if denominator_task_id.is_empty() || semantics_digest.is_empty() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cache.content_reuse",
                "denominator_task_id and semantics_digest must be non-empty",
            ));
        }

        let mut reuse_map = OccurrenceReuseMap::default();
        let mut decisions = Vec::with_capacity(targets.len());
        let mut unique_physical: BTreeSet<&str> = BTreeSet::new();
        let mut reused_physical: BTreeSet<&str> = BTreeSet::new();
        let mut rebuilt_physical: BTreeSet<&str> = BTreeSet::new();

        let mut reused_occ_count = 0usize;
        let mut rebuilt_occ_count = 0usize;
        let mut total_bytes = 0u64;
        let mut reused_bytes = 0u64;
        let mut changed_bytes = 0u64;
        let mut total_units = 0u64;
        let mut reused_units = 0u64;
        let mut affected_units = 0u64;

        for spec in targets {
            reuse_map.record(
                spec.content_id.clone(),
                spec.workload.member_bytes.0,
                spec.occurrence.clone(),
            );
            unique_physical.insert(spec.content_id.as_str());

            let work_units = spec.workload.total_work_units();
            let member_bytes = spec.workload.member_bytes.0;
            total_units = total_units.saturating_add(work_units);
            total_bytes = total_bytes.saturating_add(member_bytes);

            let key = (semantics_digest.to_owned(), spec.content_id.clone());
            let (reused, reason) = match self.records.get(&key) {
                None => (false, ReuseOutcomeReason::ColdMissNewContent),
                Some(cached) => validate_container_compatibility(
                    cached.container_dependency.as_ref(),
                    spec.container_dependency.as_ref(),
                ),
            };

            if reused {
                reused_occ_count += 1;
                reused_bytes = reused_bytes.saturating_add(member_bytes);
                reused_units = reused_units.saturating_add(work_units);
                reused_physical.insert(spec.content_id.as_str());
            } else {
                rebuilt_occ_count += 1;
                changed_bytes = changed_bytes.saturating_add(member_bytes);
                affected_units = affected_units.saturating_add(work_units);
                rebuilt_physical.insert(spec.content_id.as_str());
            }

            decisions.push(LogicalOccurrenceReuseDecision {
                file_id: spec.occurrence.file_id,
                dex_occurrence_id: spec.occurrence.dex_occurrence_id.clone(),
                source_occurrence_id: spec.occurrence.source_occurrence_id.clone(),
                member_name: spec.occurrence.member_name.clone(),
                logical_header_offset: spec.occurrence.logical_header_offset,
                content_id: spec.content_id.clone(),
                reused,
                reason,
                workload_units: DecimalU64(work_units),
                member_bytes: DecimalU64(member_bytes),
            });
        }

        let changed_byte_ratio = ratio(changed_bytes, total_bytes);
        let affected_workload_ratio = ratio(affected_units, total_units);
        let realized_workload_saving_ratio = ratio(reused_units, total_units);

        Ok(ContentReuseReport {
            semantics_digest: semantics_digest.to_owned(),
            occurrence_reuse_map: reuse_map,
            decisions,
            accounting: WorkloadReuseAccounting {
                denominator_task_id: denominator_task_id.to_owned(),
                total_logical_occurrences: targets.len(),
                unique_physical_objects: unique_physical.len(),
                reused_physical_objects: reused_physical.len(),
                rebuilt_physical_objects: rebuilt_physical.len(),
                logical_occurrences_backed_by_reuse: reused_occ_count,
                logical_occurrences_requiring_rebuild: rebuilt_occ_count,
                total_member_bytes: DecimalU64(total_bytes),
                reused_member_bytes: DecimalU64(reused_bytes),
                changed_or_rebuilt_bytes: DecimalU64(changed_bytes),
                changed_byte_ratio,
                total_workload_units: DecimalU64(total_units),
                reused_workload_units: DecimalU64(reused_units),
                affected_workload_units: DecimalU64(affected_units),
                affected_workload_ratio,
                realized_workload_saving_ratio,
                extrapolation_from_changed_bytes_forbidden: true,
                optional_dex041_prerequisite: false,
            },
            fine_grained_method_incremental_enabled:
                crate::dependency_tracking::fine_grained_method_incremental_enabled(),
        })
    }
}

/// Validates whether a negative finding record is complete across all required layers and
/// safe to store or reuse.
pub fn validate_negative_finding_reuse(
    coverage: &Coverage,
    execution: &Execution,
    response: &Response,
    operation_error: Option<&MddError>,
    required_layers: &[String],
    finding: &NegativeFindingRecord,
) -> PersistEligibility {
    let base = PersistScopeCheck::evaluate_negative_finding(
        coverage,
        execution,
        response,
        operation_error,
        required_layers,
    );
    if !base.eligible {
        return base;
    }
    if !finding.verified_complete {
        return PersistEligibility {
            eligible: false,
            denial_code: Some(ErrorCode::IncompleteFacts),
            reason: "negative finding record is not verified complete".to_owned(),
        };
    }
    for needed in required_layers {
        if !finding.covered_layers.contains(needed) {
            return PersistEligibility {
                eligible: false,
                denial_code: Some(ErrorCode::IncompleteFacts),
                reason: format!("negative finding missing required layer `{needed}`"),
            };
        }
    }
    PersistEligibility {
        eligible: true,
        denial_code: None,
        reason: "negative finding covers all required layers and complete scope".to_owned(),
    }
}

/// Builds a canonical container dependency descriptor covering container bytes and forward-shared
/// tail byte ranges. Any single-byte edit to the container or shared region alters the digests.
pub fn shared_container_dependency(
    container_format: impl Into<String>,
    container_bytes: &[u8],
    logical_dex_ordinal: u32,
    logical_header_offset: u64,
    shared_tail_range: &[u8],
) -> SharedContainerDependency {
    SharedContainerDependency {
        container_format: container_format.into(),
        physical_container_content_id: sha256(container_bytes),
        physical_container_bytes: DecimalU64(container_bytes.len() as u64),
        logical_dex_ordinal,
        logical_header_offset: DecimalU64(logical_header_offset),
        shared_ranges_sha256: sha256(shared_tail_range),
    }
}

fn validate_container_compatibility(
    cached: Option<&SharedContainerDependency>,
    current: Option<&SharedContainerDependency>,
) -> (bool, ReuseOutcomeReason) {
    match (cached, current) {
        (None, None) => (true, ReuseOutcomeReason::ReusedWholeContentId),
        (Some(prev), Some(next)) => {
            if prev.container_format == next.container_format
                && prev.physical_container_content_id == next.physical_container_content_id
                && prev.physical_container_bytes == next.physical_container_bytes
                && prev.logical_dex_ordinal == next.logical_dex_ordinal
                && prev.logical_header_offset == next.logical_header_offset
                && prev.shared_ranges_sha256 == next.shared_ranges_sha256
            {
                (true, ReuseOutcomeReason::ReusedWholeContentId)
            } else {
                (false, ReuseOutcomeReason::InvalidatedSharedContainer)
            }
        }
        (Some(_), None) | (None, Some(_)) => (
            false,
            ReuseOutcomeReason::InvalidatedContainerBoundaryMismatch,
        ),
    }
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        (numerator as f64) / (denominator as f64)
    }
}
