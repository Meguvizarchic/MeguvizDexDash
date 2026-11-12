//! HostLab structural-audit migration skeleton.
//!
//! This module is the native equivalent of the frozen HostLab
//! `NativeSession`/`Graph`/`Rules` stack (`tools/hostlab/native_*.py` at
//! commit `8782f43d`). It binds one captured snapshot, one validated archive
//! inventory and the fact layers built from that same snapshot. No value here
//! is read from a second capture and no layer is substituted by a heuristic.
//!
//! Deliberate limits of this skeleton:
//!
//! * Only the four dependency-light FEATURE rules are evaluated. Every other
//!   catalog entry is reported as [`FeatureStatus::NotImplemented`]; it is
//!   never reported as a business `MISSING`, and [`RuleRun::admitted`] stays
//!   `false` until all 27 rules have their own equivalence evidence.
//! * `dex_ordinal` is the position of a selected DEX in the validated archive
//!   inventory. It is **not** proven equal to DexSQL's `file_id`; the
//!   divergence is recorded in [`SEMANTIC_DIVERGENCES`] and must be settled
//!   against the frozen Q01 inventory before any cross-backend result compare.
//! * Method arguments and results are the erased prototype types. Generic
//!   `dalvik.annotation.Signature` interpretation is not applied yet, so
//!   rules that need generics are pending instead of approximated.
use crate::{
    MetadataFacts,
    annotations::AnnotationFacts,
    code::CodeFacts,
    definitions::DefinitionFacts,
    references::ReferenceFacts,
    session::{FactsLimits, FactsSession},
};
use mdd_input::{
    archive::ArchiveInventory,
    snapshot::{InputSpec, Snapshot},
};
use mdd_types::{Completeness, ErrorCode, MddError, MddResult};
use serde::Serialize;
use std::{collections::BTreeMap, path::Path, sync::Arc};

pub mod catalog;
pub mod graph;
pub mod rules;

pub use graph::{ClassNode, FieldInfo, Graph, MethodInfo, TypeRef};
pub use rules::{
    CATALOG, EXPECTED_FEATURES, FeatureImplementation, FeatureReport, FeatureSpec, FeatureStatus,
    HostlabCatalog, RuleRun, Rules, SEMANTIC_DIVERGENCES, SemanticDivergence,
};

/// Optional fact layers beyond metadata and definitions.
///
/// Definitions are always required: every structural rule consumes class,
/// field or method definitions, and reporting a rule without them would turn
/// an unbuilt layer into a false business conclusion.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeLayers {
    /// Build code-layout facts (needed for call-site/string rules later).
    pub code: bool,
    /// Build encoded reference facts (needed for `method_strings`/calls).
    pub references: bool,
    /// Build annotation/Signature facts (needed for generic rules).
    pub annotations: bool,
}

impl NativeLayers {
    /// Metadata + definitions only; the layer set the current rules use.
    pub const STRUCTURAL: Self = Self {
        code: false,
        references: false,
        annotations: false,
    };
}

/// Completeness of one built fact layer for one occurrence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerState {
    NotBuilt,
    Complete,
    Partial,
    Unknown,
}

impl LayerState {
    fn of(value: Completeness) -> Self {
        match value {
            Completeness::Complete => Self::Complete,
            Completeness::Partial => Self::Partial,
            Completeness::Unknown => Self::Unknown,
        }
    }
}

/// One selected DEX occurrence and the layers actually built for it.
pub struct OccurrenceState {
    pub dex_ordinal: u32,
    /// Archive member name; `None` for a raw DEX input, where the frozen
    /// reference backend reports a path-derived `entry_name` instead.
    pub entry_name: Option<String>,
    pub dex_occurrence_id: String,
    pub content_id: String,
    metadata: Option<Arc<MetadataFacts>>,
    definitions: Option<Arc<DefinitionFacts>>,
    code: Option<Arc<CodeFacts>>,
    references: Option<Arc<ReferenceFacts>>,
    annotations: Option<Arc<AnnotationFacts>>,
}

impl OccurrenceState {
    pub fn metadata(&self) -> Option<&MetadataFacts> {
        self.metadata.as_deref()
    }
    pub fn definitions(&self) -> Option<&DefinitionFacts> {
        self.definitions.as_deref()
    }
    pub fn code(&self) -> Option<&CodeFacts> {
        self.code.as_deref()
    }
    pub fn references(&self) -> Option<&ReferenceFacts> {
        self.references.as_deref()
    }
    pub fn annotations(&self) -> Option<&AnnotationFacts> {
        self.annotations.as_deref()
    }
    /// Number of class definitions in this occurrence; `None` until built.
    pub fn class_count(&self) -> Option<u64> {
        self.definitions
            .as_ref()
            .map(|facts| facts.definitions().classes.len() as u64)
    }
    pub fn method_count(&self) -> Option<u64> {
        self.definitions
            .as_ref()
            .map(|facts| facts.definitions().method_definitions.len() as u64)
    }
    pub fn field_count(&self) -> Option<u64> {
        self.definitions
            .as_ref()
            .map(|facts| facts.definitions().field_definitions.len() as u64)
    }
}

/// Serializable occurrence evidence; this is the audit's provenance row.
#[derive(Clone, Debug, Serialize)]
pub struct OccurrenceSummary {
    pub dex_ordinal: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_name: Option<String>,
    pub dex_occurrence_id: String,
    pub content_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_count: Option<u64>,
    pub metadata: LayerState,
    pub definitions: LayerState,
    pub code: LayerState,
    pub references: LayerState,
    pub annotations: LayerState,
}

/// Per-occurrence coverage plus roster and class-index facts.
#[derive(Clone, Debug, Serialize)]
pub struct NativeCoverage {
    pub schema_version: String,
    pub snapshot_id: String,
    pub selected_dex_count: usize,
    pub archive_directory_complete: bool,
    pub selected_dex_bytes_complete: bool,
    pub occurrences: Vec<OccurrenceSummary>,
    /// Number of descriptors in the class index; equal to the total class
    /// definition count only when no descriptor repeats across occurrences.
    pub class_index_entries: usize,
    pub total_class_definitions: u64,
    pub duplicate_class_descriptor_count: usize,
    /// Deterministically ordered duplicate descriptors, capped for output.
    pub duplicate_class_descriptors: Vec<String>,
    pub duplicate_class_descriptors_truncated: bool,
    pub duplicate_class_descriptor_limit: usize,
}

/// A class definition site in the occurrence-scoped index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClassSite {
    pub dex_ordinal: u32,
    pub class_def_idx: u32,
}

const DUPLICATE_DESCRIPTOR_REPORT_LIMIT: usize = 64;

/// Snapshot-bound structural session.
///
/// Opening captures and validates the input inventory only. [`Self::prepare`]
/// then builds the fact layers for every selected DEX; any layer error aborts
/// the whole preparation, so a later rule never sees a partially built
/// occurrence as complete.
pub struct NativeSession {
    facts: FactsSession,
    layers: NativeLayers,
    occurrences: Vec<OccurrenceState>,
    class_index: BTreeMap<String, Vec<ClassSite>>,
    duplicate_descriptors: Vec<String>,
    prepared: bool,
}

impl NativeSession {
    pub fn open(path: impl AsRef<Path>) -> MddResult<Self> {
        Self::open_with(path, FactsLimits::default())
    }

    pub fn open_with(path: impl AsRef<Path>, limits: FactsLimits) -> MddResult<Self> {
        Self::from_facts(FactsSession::open_with(path, limits)?)
    }

    /// Open with an immutable digest expectation; the snapshot capture rejects
    /// a different input before any fact layer is built.
    pub fn open_verified(
        path: impl AsRef<Path>,
        expected_sha256: &str,
        limits: FactsLimits,
    ) -> MddResult<Self> {
        let path = path.as_ref();
        let kind = mdd_input::snapshot::InputKind::detect(path)?;
        let facts = FactsSession::open_spec(
            InputSpec {
                path: path.to_path_buf(),
                kind,
                expected_sha256: Some(expected_sha256.to_owned()),
            },
            limits,
        )?;
        Self::from_facts(facts)
    }

    fn from_facts(facts: FactsSession) -> MddResult<Self> {
        if facts.dex_count() == 0 {
            return Err(MddError::new(
                ErrorCode::PartialInput,
                "hostlab.session",
                "structural audit requires at least one selected DEX occurrence",
            ));
        }
        let occurrences = facts
            .inventory()
            .selected_dexes()
            .iter()
            .enumerate()
            .map(|(index, candidate)| {
                let dex_ordinal = u32::try_from(index).map_err(|_| {
                    MddError::new(
                        ErrorCode::QuotaExceeded,
                        "hostlab.session",
                        "DEX occurrence ordinal overflow",
                    )
                })?;
                Ok(OccurrenceState {
                    dex_ordinal,
                    entry_name: candidate.blob.identity.name_utf8.clone(),
                    dex_occurrence_id: candidate.dex_occurrence_id.clone(),
                    content_id: candidate.blob.content_id.clone(),
                    metadata: None,
                    definitions: None,
                    code: None,
                    references: None,
                    annotations: None,
                })
            })
            .collect::<MddResult<Vec<_>>>()?;
        Ok(Self {
            facts,
            layers: NativeLayers::default(),
            occurrences,
            class_index: BTreeMap::new(),
            duplicate_descriptors: Vec::new(),
            prepared: false,
        })
    }

    pub fn snapshot(&self) -> &Snapshot {
        self.facts.snapshot()
    }
    pub fn inventory(&self) -> &ArchiveInventory {
        self.facts.inventory()
    }
    pub fn occurrences(&self) -> &[OccurrenceState] {
        &self.occurrences
    }
    pub fn layers(&self) -> NativeLayers {
        self.layers
    }
    pub fn is_prepared(&self) -> bool {
        self.prepared
    }

    /// Build metadata and definitions for every selected DEX, then the
    /// descriptor index. Optional layers are built in dependency order.
    pub fn prepare(&mut self, layers: NativeLayers) -> MddResult<()> {
        for index in 0..self.occurrences.len() {
            let metadata = self.facts.metadata(index)?;
            let definitions = self.facts.definitions(index)?;
            let state = &mut self.occurrences[index];
            state.metadata = Some(metadata);
            state.definitions = Some(definitions);
        }
        if layers.references || layers.code {
            for index in 0..self.occurrences.len() {
                let code = self.facts.code(index)?;
                self.occurrences[index].code = Some(code);
            }
        }
        if layers.references {
            for index in 0..self.occurrences.len() {
                let references = self.facts.references(index)?;
                self.occurrences[index].references = Some(references);
            }
        }
        if layers.annotations {
            for index in 0..self.occurrences.len() {
                let annotations = self.facts.annotations(index)?;
                self.occurrences[index].annotations = Some(annotations);
            }
        }
        self.layers = layers;
        self.build_class_index()?;
        self.prepared = true;
        Ok(())
    }

    fn build_class_index(&mut self) -> MddResult<()> {
        let mut index: BTreeMap<String, Vec<ClassSite>> = BTreeMap::new();
        for state in &self.occurrences {
            let definitions = state.definitions.as_deref().ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "hostlab.session",
                    "definitions missing while building the class index",
                )
            })?;
            for (position, class) in definitions.definitions().classes.iter().enumerate() {
                if u32::try_from(position).ok() != Some(class.class_def_idx) {
                    return Err(MddError::new(
                        ErrorCode::InternalFault,
                        "hostlab.session",
                        "class definition order is inconsistent with its index",
                    ));
                }
                index
                    .entry(class.descriptor.clone())
                    .or_default()
                    .push(ClassSite {
                        dex_ordinal: state.dex_ordinal,
                        class_def_idx: class.class_def_idx,
                    });
            }
        }
        self.duplicate_descriptors = index
            .iter()
            .filter(|(_, sites)| sites.len() > 1)
            .map(|(descriptor, _)| descriptor.clone())
            .collect();
        self.class_index = index;
        Ok(())
    }

    /// Require every occurrence's metadata and definitions to be complete.
    pub fn require_structural_complete(&self) -> MddResult<()> {
        if !self.prepared {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "hostlab.session",
                "structural facts are not prepared",
            )
            .detail("required_layer", "definitions"));
        }
        for state in &self.occurrences {
            let metadata = state
                .metadata
                .as_deref()
                .ok_or_else(|| incomplete(state, "metadata"))?;
            let definitions = state
                .definitions
                .as_deref()
                .ok_or_else(|| incomplete(state, "definitions"))?;
            if metadata.metadata_coverage() != Completeness::Complete
                || definitions.definition_coverage() != Completeness::Complete
            {
                return Err(incomplete(state, "definitions"));
            }
        }
        Ok(())
    }

    /// The frozen Q07 aggregate: total `classes` rows across all occurrences.
    pub fn class_count(&self) -> MddResult<u64> {
        self.require_structural_complete()?;
        let mut total = 0u64;
        for state in &self.occurrences {
            total = total
                .checked_add(state.class_count().unwrap_or(0))
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::QuotaExceeded,
                        "hostlab.session",
                        "class count overflow",
                    )
                })?;
        }
        Ok(total)
    }

    pub fn coverage(&self) -> NativeCoverage {
        let mut total = 0u64;
        let occurrences = self
            .occurrences
            .iter()
            .map(|state| {
                let class_count = state.class_count();
                total = total.saturating_add(class_count.unwrap_or(0));
                OccurrenceSummary {
                    dex_ordinal: state.dex_ordinal,
                    entry_name: state.entry_name.clone(),
                    dex_occurrence_id: state.dex_occurrence_id.clone(),
                    content_id: state.content_id.clone(),
                    class_count,
                    method_count: state.method_count(),
                    field_count: state.field_count(),
                    metadata: state
                        .metadata
                        .as_deref()
                        .map_or(LayerState::NotBuilt, |facts| {
                            LayerState::of(facts.metadata_coverage())
                        }),
                    definitions: state
                        .definitions
                        .as_deref()
                        .map_or(LayerState::NotBuilt, |facts| {
                            LayerState::of(facts.definition_coverage())
                        }),
                    code: state.code.as_deref().map_or(LayerState::NotBuilt, |facts| {
                        LayerState::of(facts.code_layout_coverage())
                    }),
                    references: state
                        .references
                        .as_deref()
                        .map_or(LayerState::NotBuilt, |facts| {
                            LayerState::of(facts.coverage().facts)
                        }),
                    annotations: state
                        .annotations
                        .as_deref()
                        .map_or(LayerState::NotBuilt, |facts| {
                            LayerState::of(facts.annotation_coverage())
                        }),
                }
            })
            .collect();
        let truncated = self.duplicate_descriptors.len() > DUPLICATE_DESCRIPTOR_REPORT_LIMIT;
        NativeCoverage {
            schema_version: "mdd.hostlab-native-coverage.v1".into(),
            snapshot_id: self.snapshot().manifest().snapshot_id.clone(),
            selected_dex_count: self.occurrences.len(),
            archive_directory_complete: self.inventory().manifest().directory_complete,
            selected_dex_bytes_complete: self.inventory().manifest().selected_dex_bytes_complete,
            occurrences,
            class_index_entries: self.class_index.len(),
            total_class_definitions: total,
            duplicate_class_descriptor_count: self.duplicate_descriptors.len(),
            duplicate_class_descriptors: self
                .duplicate_descriptors
                .iter()
                .take(DUPLICATE_DESCRIPTOR_REPORT_LIMIT)
                .cloned()
                .collect(),
            duplicate_class_descriptors_truncated: truncated,
            duplicate_class_descriptor_limit: DUPLICATE_DESCRIPTOR_REPORT_LIMIT,
        }
    }

    /// Map each native `dex_ordinal` to the HostLab/DexSQL `file_id`.
    ///
    /// The frozen backend (A0, `dexsql 0.1.0`) numbers the selected DEX members
    /// in **archive enumeration order**, which is exactly the order of the
    /// validated inventory. It does not re-sort `classes<N>.dex` numerically:
    /// on Bilibili 9.16.1 (`classes.dex`, `classes10.dex`, `classes11.dex`, ...)
    /// A0 reports `file_id=4` for `classes13.dex` (7,328 classes), not for
    /// `classes5.dex` (12,038 classes). Synthetic archives with out-of-order
    /// members confirm the same rule; see
    /// `artifacts/mdd-032-audit/file-id-adjudication-20261112/`.
    ///
    /// The mapping is therefore the identity on `dex_ordinal`, and a raw DEX
    /// input is the single file `0`. It is kept as an explicit function so that
    /// every rule or projection that emits or compares a `file_id` goes through
    /// one place, and so that an inventory whose ordinals are not the dense
    /// enumeration is rejected instead of silently mislabelled.
    pub fn hostlab_file_ids(&self) -> MddResult<Vec<u32>> {
        if self.occurrences.len() != 1 && self.occurrences.iter().any(|s| s.entry_name.is_none()) {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "hostlab.session",
                "multi-occurrence archive contains an unnamed DEX member",
            ));
        }
        self.occurrences
            .iter()
            .enumerate()
            .map(|(position, state)| {
                if usize::try_from(state.dex_ordinal).ok() != Some(position) {
                    return Err(MddError::new(
                        ErrorCode::InvalidArgument,
                        "hostlab.session",
                        "DEX ordinals are not the dense archive enumeration",
                    )
                    .detail("dex_ordinal", state.dex_ordinal)
                    .detail("position", position.to_string()));
                }
                Ok(state.dex_ordinal)
            })
            .collect()
    }

    /// Build the structural graph. Fails unless definitions are prepared.
    pub fn graph(&self) -> MddResult<Graph<'_>> {
        self.require_structural_complete()?;
        Ok(Graph::new(self))
    }

    /// Evaluate the HostLab rules against an explicit catalog. Retained for API
    /// parity with `Rules(session).run()` in the frozen reference, which reads
    /// its catalog from a file.
    pub fn run_rules(&self, catalog: &HostlabCatalog) -> MddResult<RuleRun> {
        Rules::with_catalog(self, catalog)?.run()
    }

    pub(crate) fn class_sites(&self, descriptor: &str) -> Option<&[ClassSite]> {
        self.class_index.get(descriptor).map(Vec::as_slice)
    }

    /// One occurrence by validated inventory ordinal.
    pub fn occurrence_state(&self, dex_ordinal: u32) -> MddResult<&OccurrenceState> {
        self.occurrences
            .get(dex_ordinal as usize)
            .filter(|state| state.dex_ordinal == dex_ordinal)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "hostlab.session",
                    "DEX ordinal is outside this session",
                )
                .detail("dex_ordinal", dex_ordinal)
            })
    }
}

fn incomplete(state: &OccurrenceState, layer: &str) -> MddError {
    MddError::new(
        ErrorCode::IncompleteFacts,
        "hostlab.session",
        "a required fact layer is not complete for this occurrence",
    )
    .detail("dex_ordinal", state.dex_ordinal)
    .detail("dex_occurrence_id", state.dex_occurrence_id.clone())
    .detail("required_layer", layer)
}
