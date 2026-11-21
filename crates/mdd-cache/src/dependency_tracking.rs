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

pub mod content_reuse;
pub mod incremental_gate;

pub use content_reuse::{
    ContentCacheRecord, ContentObjectReuseIndex, ContentReuseReport,
    LogicalOccurrenceReuseDecision, ReuseOutcomeReason, TargetMemberSpec, WorkloadReuseAccounting,
    WorkloadUnitSummary, shared_container_dependency, validate_negative_finding_reuse,
};
pub use incremental_gate::{
    DimensionProofRecord, FineGrainedIncrementalDecision, IncrementalDependencyBoundary,
    ProofDimension, evaluate_default_conservative_gate, evaluate_fine_grained_candidate,
};

/// Fine-grained method-level incremental dependency tracking remains explicitly disabled until
/// cross-method negative/hierarchy/constant-pool proofs are established in MDD-064.
pub fn fine_grained_method_incremental_enabled() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts_codec::NegativeFindingRecord;
    use mdd_types::{Completeness, Coverage, Execution, Issue, Response};

    fn complete_envelope(scope: &str) -> (Coverage, Execution, Response) {
        (
            Coverage {
                scope_id: scope.to_owned(),
                input: Completeness::Complete,
                facts: Completeness::Complete,
                required_layers: vec![
                    "inventory".to_owned(),
                    "metadata".to_owned(),
                    "definitions".to_owned(),
                    "code".to_owned(),
                    "references".to_owned(),
                    "annotations".to_owned(),
                ],
                issues: Vec::new(),
            },
            Execution { complete: true },
            Response {
                schema_id: Some("mdd.cache.relations.v1".to_owned()),
                emitted_rows: DecimalU64(0),
                total_rows: None,
                total_rows_exact: false,
                more_available: false,
                truncated: false,
                next_cursor: None,
            },
        )
    }

    fn member_spec(
        file_id: u32,
        member_name: &str,
        content_id: &str,
        bytes: u64,
        methods_and_code: (u32, u32),
        container_dep: Option<SharedContainerDependency>,
    ) -> TargetMemberSpec {
        TargetMemberSpec {
            occurrence: LogicalOccurrenceRef {
                file_id,
                dex_occurrence_id: format!("occ:{file_id}"),
                source_occurrence_id: "src:0".to_owned(),
                member_name: Some(member_name.to_owned()),
                logical_header_offset: DecimalU64(0),
            },
            content_id: content_id.to_owned(),
            workload: WorkloadUnitSummary {
                member_bytes: DecimalU64(bytes),
                string_count: 100,
                type_count: 25,
                proto_count: 10,
                field_count: 20,
                method_count: methods_and_code.0,
                class_count: 8,
                code_item_count: methods_and_code.1,
            },
            container_dependency: container_dep,
        }
    }

    #[test]
    fn whole_content_reuse_preserves_physical_dedup_multiplicity_and_rebuilds_only_changed_dex() {
        let (cov, exec, resp) = complete_envelope("v1-build");
        let mut index = ContentObjectReuseIndex::new();
        let sem = "sem-v1";

        let unchanged_workload = WorkloadUnitSummary {
            member_bytes: DecimalU64(10_000),
            string_count: 100,
            type_count: 25,
            proto_count: 10,
            field_count: 20,
            method_count: 400,
            class_count: 8,
            code_item_count: 350,
        };
        index
            .register_verified(
                &cov,
                &exec,
                &resp,
                None,
                ContentCacheRecord {
                    semantics_digest: sem.to_owned(),
                    content_id: "sha256:dex-unchanged".to_owned(),
                    workload: unchanged_workload,
                    container_dependency: None,
                    persisted_scope_id: "v1-build".to_owned(),
                },
            )
            .unwrap();

        // Target APK has two logical occurrences backed by the same physical DEX (`classes.dex`,
        // `assets/dup-classes.dex`) plus one modified `classes2.dex` with heavy code workload.
        let report = index
            .evaluate_target(
                "apk-upgrade-v2",
                sem,
                &[
                    member_spec(
                        0,
                        "classes.dex",
                        "sha256:dex-unchanged",
                        10_000,
                        (400, 350),
                        None,
                    ),
                    member_spec(
                        1,
                        "assets/dup-classes.dex",
                        "sha256:dex-unchanged",
                        10_000,
                        (400, 350),
                        None,
                    ),
                    member_spec(
                        2,
                        "classes2.dex",
                        "sha256:dex-changed",
                        2_000,
                        (50, 50),
                        None,
                    ),
                ],
            )
            .unwrap();

        assert!(!report.fine_grained_method_incremental_enabled);
        assert_eq!(report.occurrence_reuse_map.total_logical_occurrences(), 3);
        assert_eq!(report.occurrence_reuse_map.physical_blob_count(), 2);
        assert_eq!(report.decisions.len(), 3);
        assert!(report.decisions[0].reused);
        assert!(report.decisions[1].reused);
        assert!(!report.decisions[2].reused);
        assert_eq!(
            report.decisions[2].reason,
            ReuseOutcomeReason::ColdMissNewContent
        );

        assert_eq!(report.accounting.total_logical_occurrences, 3);
        assert_eq!(report.accounting.unique_physical_objects, 2);
        assert_eq!(report.accounting.reused_physical_objects, 1);
        assert_eq!(report.accounting.rebuilt_physical_objects, 1);
        assert_eq!(report.accounting.logical_occurrences_backed_by_reuse, 2);
        assert_eq!(report.accounting.logical_occurrences_requiring_rebuild, 1);
        // Changed byte ratio (2000/22000 = 0.0909) != affected workload ratio (471 / 5213).
        assert!(report.accounting.extrapolation_from_changed_bytes_forbidden);
        assert!(!report.accounting.optional_dex041_prerequisite);
        assert!(
            (report.accounting.changed_byte_ratio - report.accounting.affected_workload_ratio)
                .abs()
                > 1e-4
        );
    }

    #[test]
    fn shared_container_change_invalidates_even_matching_logical_content_id() {
        let (cov, exec, resp) = complete_envelope("container-v1");
        let mut index = ContentObjectReuseIndex::new();
        let dep_v1 =
            shared_container_dependency("dex-041-container", b"hdr1+tailA", 0, 128, b"tailA");
        let dep_v2 =
            shared_container_dependency("dex-041-container", b"hdr1+tailB", 0, 128, b"tailB");

        index
            .register_verified(
                &cov,
                &exec,
                &resp,
                None,
                ContentCacheRecord {
                    semantics_digest: "sem-v1".to_owned(),
                    content_id: "sha256:logical-slice-0".to_owned(),
                    workload: WorkloadUnitSummary {
                        member_bytes: DecimalU64(4096),
                        method_count: 10,
                        code_item_count: 10,
                        ..WorkloadUnitSummary::default()
                    },
                    container_dependency: Some(dep_v1),
                    persisted_scope_id: "container-v1".to_owned(),
                },
            )
            .unwrap();

        let report = index
            .evaluate_target(
                "container-v2",
                "sem-v1",
                &[member_spec(
                    0,
                    "classes.dex",
                    "sha256:logical-slice-0",
                    4096,
                    (10, 10),
                    Some(dep_v2),
                )],
            )
            .unwrap();

        assert_eq!(report.decisions.len(), 1);
        assert!(!report.decisions[0].reused);
        assert_eq!(
            report.decisions[0].reason,
            ReuseOutcomeReason::InvalidatedSharedContainer
        );
        assert_eq!(report.accounting.reused_physical_objects, 0);
        assert_eq!(report.accounting.rebuilt_physical_objects, 1);
    }

    #[test]
    fn incomplete_or_truncated_or_missing_layer_results_are_refused() {
        let (mut cov, mut exec, mut resp) = complete_envelope("bad");
        let mut index = ContentObjectReuseIndex::new();
        let rec = ContentCacheRecord {
            semantics_digest: "sem-v1".to_owned(),
            content_id: "sha256:bad".to_owned(),
            workload: WorkloadUnitSummary::default(),
            container_dependency: None,
            persisted_scope_id: "bad".to_owned(),
        };

        cov.input = Completeness::Partial;
        assert!(
            index
                .register_verified(&cov, &exec, &resp, None, rec.clone())
                .is_err()
        );
        cov.input = Completeness::Complete;

        cov.issues.push(Issue {
            layer: "inventory".to_owned(),
            reason: "truncated_member".to_owned(),
            blocking: true,
            entity_id: None,
            member_id: None,
            range: None,
            details: None,
        });
        assert!(
            index
                .register_verified(&cov, &exec, &resp, None, rec.clone())
                .is_err()
        );
        cov.issues.clear();

        exec.complete = false;
        assert!(
            index
                .register_verified(&cov, &exec, &resp, None, rec.clone())
                .is_err()
        );
        exec.complete = true;

        resp.truncated = true;
        assert!(
            index
                .register_verified(&cov, &exec, &resp, None, rec.clone())
                .is_err()
        );
        resp.truncated = false;

        resp.more_available = true;
        assert!(
            index
                .register_verified(&cov, &exec, &resp, None, rec)
                .is_err()
        );
        resp.more_available = false;

        let neg = NegativeFindingRecord {
            scope_id: "bad".to_owned(),
            canonical_cache_key: "k1".to_owned(),
            predicate_id: "pred-1".to_owned(),
            covered_layers: vec!["inventory".to_owned(), "metadata".to_owned()],
            matched_count: DecimalU64(0),
            verified_complete: true,
        };
        let elig = validate_negative_finding_reuse(
            &cov,
            &exec,
            &resp,
            None,
            &[
                "inventory".to_owned(),
                "metadata".to_owned(),
                "references".to_owned(),
            ],
            &neg,
        );
        assert!(!elig.eligible);
        assert_eq!(elig.denial_code, Some(ErrorCode::IncompleteFacts));
    }

    #[test]
    fn fine_grained_method_incremental_remains_disabled_without_complete_closure_proofs() {
        assert!(!fine_grained_method_incremental_enabled());
        let boundary = IncrementalDependencyBoundary {
            candidate_id: "cand-method-edit".to_owned(),
            touched_method_count: DecimalU64(1),
            outbound_method_ref_edges: DecimalU64(14),
            hierarchy_override_edges: DecimalU64(3),
            negative_query_dependencies: 2,
            constant_pool_references: DecimalU64(9),
            optional_dex041_container_present: false,
            shared_container_dependency: None,
        };

        let decision = evaluate_default_conservative_gate(boundary.clone());
        assert!(!decision.capability_enabled);
        assert!(!decision.all_required_dimensions_proved);
        assert!(!decision.optional_dex041_prerequisite);
        assert_eq!(decision.missing_or_unproved_dimensions.len(), 5);
        assert!(!decision.rejection_reasons.is_empty());

        // Even if all 5 proof records claim proved=true, the runtime gate refuses activation
        // until explicitly verified and admitted.
        let optimistic: Vec<DimensionProofRecord> = ProofDimension::ALL
            .into_iter()
            .map(|dim| DimensionProofRecord {
                dimension: dim,
                proved: true,
                boundary_summary: "test".to_owned(),
                blocking_reason: None,
            })
            .collect();
        let gated = evaluate_fine_grained_candidate(boundary, &optimistic);
        assert!(gated.all_required_dimensions_proved);
        assert!(!gated.runtime_gate_enabled);
        assert!(!gated.capability_enabled);
    }
}
