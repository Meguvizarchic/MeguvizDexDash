//! Qualification gate for fine-grained method-level incremental caching (`MDD-064`).
//!
//! Fine-grained method-level incrementalism remains **disabled** (`false`) unless all five
//! dependency-closure proofs are established AND the explicit capability gate returns `true`.
//! Optional DEX `041` shared-container support is explicitly excluded from ordinary release
//! prerequisites (`optional_dex041_prerequisite = false`).

use crate::dependency_tracking::{
    SharedContainerDependency, fine_grained_method_incremental_enabled,
};
use mdd_types::DecimalU64;
use serde::{Deserialize, Serialize};

/// The five independent closure and scope proofs required before method-level incremental
/// fact mutation could ever be considered sound.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofDimension {
    CrossMethodReferenceGraph,
    HierarchyOverrideClosure,
    GlobalNegativeFindingScope,
    ConstantPoolAndTypeFieldClosure,
    SharedContainerTailIsolation,
}

impl ProofDimension {
    pub const ALL: [Self; 5] = [
        Self::CrossMethodReferenceGraph,
        Self::HierarchyOverrideClosure,
        Self::GlobalNegativeFindingScope,
        Self::ConstantPoolAndTypeFieldClosure,
        Self::SharedContainerTailIsolation,
    ];
}

/// Recorded proof status for one required dependency dimension.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DimensionProofRecord {
    pub dimension: ProofDimension,
    pub proved: bool,
    pub boundary_summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocking_reason: Option<String>,
}

/// Auditable boundary description of what a candidate fine-grained change touches.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncrementalDependencyBoundary {
    pub candidate_id: String,
    pub touched_method_count: DecimalU64,
    pub outbound_method_ref_edges: DecimalU64,
    pub hierarchy_override_edges: DecimalU64,
    pub negative_query_dependencies: usize,
    pub constant_pool_references: DecimalU64,
    pub optional_dex041_container_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_container_dependency: Option<SharedContainerDependency>,
}

/// Complete audit decision determining whether fine-grained method-level incremental caching
/// may be enabled.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FineGrainedIncrementalDecision {
    pub candidate_id: String,
    pub capability_enabled: bool,
    pub runtime_gate_enabled: bool,
    pub all_required_dimensions_proved: bool,
    pub optional_dex041_prerequisite: bool,
    pub missing_or_unproved_dimensions: Vec<ProofDimension>,
    pub rejection_reasons: Vec<String>,
    pub boundaries: IncrementalDependencyBoundary,
    pub dimensions: Vec<DimensionProofRecord>,
}

/// Evaluates whether fine-grained method-level incremental caching can be enabled given recorded
/// dependency boundaries and dimension proof records.
///
/// Even if callers supply partial or optimistic proof records, `capability_enabled` stays `false`
/// whenever any of the five required dimensions lacks proof or
/// `fine_grained_method_incremental_enabled()` returns `false`.
pub fn evaluate_fine_grained_candidate(
    boundaries: IncrementalDependencyBoundary,
    supplied_proofs: &[DimensionProofRecord],
) -> FineGrainedIncrementalDecision {
    let mut dimensions = Vec::with_capacity(ProofDimension::ALL.len());
    let mut missing_or_unproved = Vec::new();
    let mut rejection_reasons = Vec::new();

    for required in ProofDimension::ALL {
        let record = supplied_proofs
            .iter()
            .find(|item| item.dimension == required)
            .cloned()
            .unwrap_or_else(|| DimensionProofRecord {
                dimension: required,
                proved: false,
                boundary_summary: default_boundary_summary(required, &boundaries),
                blocking_reason: Some(default_blocking_reason(required).to_owned()),
            });
        if !record.proved {
            missing_or_unproved.push(required);
            let reason = record
                .blocking_reason
                .clone()
                .unwrap_or_else(|| default_blocking_reason(required).to_owned());
            rejection_reasons.push(reason);
        }
        dimensions.push(record);
    }

    let all_proved = missing_or_unproved.is_empty();
    let runtime_gate_enabled = fine_grained_method_incremental_enabled();
    if all_proved && !runtime_gate_enabled {
        rejection_reasons.push(
            "runtime gate `fine_grained_method_incremental_enabled()` remains disabled pending end-to-end negative and hierarchy invariance verification"
                .to_owned(),
        );
    }

    let capability_enabled = all_proved && runtime_gate_enabled;

    FineGrainedIncrementalDecision {
        candidate_id: boundaries.candidate_id.clone(),
        capability_enabled,
        runtime_gate_enabled,
        all_required_dimensions_proved: all_proved,
        optional_dex041_prerequisite: false,
        missing_or_unproved_dimensions: missing_or_unproved,
        rejection_reasons,
        boundaries,
        dimensions,
    }
}

/// Default conservative evaluation when no cross-method/hierarchy/constant-pool proofs exist:
/// forces capability disabled and falls back to whole-`ContentId` reuse.
pub fn evaluate_default_conservative_gate(
    boundaries: IncrementalDependencyBoundary,
) -> FineGrainedIncrementalDecision {
    evaluate_fine_grained_candidate(boundaries, &[])
}

fn default_boundary_summary(
    dimension: ProofDimension,
    b: &IncrementalDependencyBoundary,
) -> String {
    match dimension {
        ProofDimension::CrossMethodReferenceGraph => format!(
            "{} touched methods with {} outbound call/ref edges",
            b.touched_method_count.0, b.outbound_method_ref_edges.0
        ),
        ProofDimension::HierarchyOverrideClosure => format!(
            "{} class/interface override propagation edges",
            b.hierarchy_override_edges.0
        ),
        ProofDimension::GlobalNegativeFindingScope => format!(
            "{} negative query scopes requiring whole-snapshot completeness",
            b.negative_query_dependencies
        ),
        ProofDimension::ConstantPoolAndTypeFieldClosure => format!(
            "{} constant-pool string/type/field index dependencies",
            b.constant_pool_references.0
        ),
        ProofDimension::SharedContainerTailIsolation => match &b.shared_container_dependency {
            Some(dep) => format!(
                "container `{}` bytes={} tail_sha={}",
                dep.container_format, dep.physical_container_bytes.0, dep.shared_ranges_sha256
            ),
            None => format!(
                "standard DEX isolation only (optional_dex041_present={})",
                b.optional_dex041_container_present
            ),
        },
    }
}

fn default_blocking_reason(dimension: ProofDimension) -> &'static str {
    match dimension {
        ProofDimension::CrossMethodReferenceGraph => {
            "missing exhaustive cross-method call/reference invalidation closure proof"
        }
        ProofDimension::HierarchyOverrideClosure => {
            "missing class hierarchy and virtual-override transitivity proof"
        }
        ProofDimension::GlobalNegativeFindingScope => {
            "missing proof that global negative queries remain invariant under method edits"
        }
        ProofDimension::ConstantPoolAndTypeFieldClosure => {
            "missing proof bounding string/type/proto/field/method index renumbering across partial edits"
        }
        ProofDimension::SharedContainerTailIsolation => {
            "missing shared-container tail/offset isolation proof (standard DEX builds keep method incremental disabled without requiring DEX 041)"
        }
    }
}
