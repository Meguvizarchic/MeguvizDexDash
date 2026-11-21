//! Scope-relative native fact coverage; projection readiness is an independent contract.
use crate::annotations::AnnotationRelation;
use crate::code::{MethodCodeFactViews, require_code_item_columns};
use crate::definitions::DefinitionRelation;
use crate::indexes::{ColumnSpec, FactView, SelectedScope, column_specs};
use crate::metadata::MetadataRelation;
use crate::{
    raw_fingerprints::ResourceByteEvidence,
    references::{ReferenceRelation, TargetKind},
};
use mdd_dex::definitions::MethodBody;
use mdd_types::{Completeness, ErrorCode, MddError, MddResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Policy governing legal non-scalar UTF-16 strings (unpaired surrogates) in plain-UTF-8 relations.
///
/// Strict rejection is always the default; lossy U+FFFD replacement requires explicit opt-in and
/// leaves a non-blocking diagnostic in coverage reports.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NonScalarTextPolicy {
    #[default]
    Reject,
    LossyReplacement,
}

impl NonScalarTextPolicy {
    pub fn parse(name: &str) -> MddResult<Self> {
        match name {
            "reject" => Ok(Self::Reject),
            "lossy-replacement" => Ok(Self::LossyReplacement),
            other => Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.coverage",
                format!(
                    "unknown non-scalar text policy `{other}`; use reject or lossy-replacement"
                ),
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::LossyReplacement => "lossy-replacement",
        }
    }

    pub fn is_reject(&self) -> bool {
        *self == Self::Reject
    }

    pub fn project_dex_text(&self, text: &mdd_dex::strings::DexText) -> Option<String> {
        match text.strict_utf8() {
            Ok(scalar) => Some(scalar),
            Err(_) if *self == Self::LossyReplacement => Some(text.display_lossy()),
            Err(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FactLayer {
    Metadata,
    Definitions,
    Structure,
    CodeProjection,
    AllPhysicalCode,
    MethodBindings,
    AllMethodBodies,
    References,
    Annotations,
    PrototypeParameterPositions,
    RawCode,
    SourcePositions,
    DerivedAnalysis,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputNeed {
    CapturedBytes,
    SelectedInventory,
    ValidatedStandardDex,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ColumnDomain {
    NativeAtoms,
    FrozenProjection,
}
#[derive(Clone, Debug, Serialize)]
pub struct ColumnRequirement {
    pub relation: String,
    pub column: String,
    pub domain: ColumnDomain,
}
#[derive(Clone, Debug, Serialize)]
pub struct CoverageRequest {
    pub scope_id: String,
    pub input: InputNeed,
    pub required_layers: Vec<FactLayer>,
    pub required_columns: Vec<ColumnRequirement>,
    pub required_resource_members: Vec<String>,
    #[serde(skip_serializing_if = "NonScalarTextPolicy::is_reject")]
    pub non_scalar_text_policy: NonScalarTextPolicy,
}
impl CoverageRequest {
    /// Scope-bound request for an explicit layer set. Columns are **not**
    /// inferred: a layer requirement does not by itself claim that every
    /// relation column of that layer is projectable. Callers that read a
    /// specific frozen relation must ask for its columns through
    /// [`CoverageRequest::for_relations`] or by pushing
    /// [`ColumnRequirement`] entries.
    pub fn for_scope(scope: &SelectedScope, layers: &[FactLayer]) -> Self {
        Self {
            scope_id: scope.scope_id().into(),
            input: InputNeed::ValidatedStandardDex,
            required_layers: layers.to_vec(),
            required_columns: Vec::new(),
            required_resource_members: Vec::new(),
            non_scalar_text_policy: NonScalarTextPolicy::Reject,
        }
    }
    /// Scope-bound request that requires **every** frozen column of the named
    /// relations, plus the fact layers that own them.
    ///
    /// This is the production entry for relation-scoped coverage: unlike
    /// [`CoverageRequest::for_scope`] it fills `required_columns` from the
    /// frozen schema, so a relation whose provider gate rejects (unknown
    /// column, unassembled column, non-scalar UTF-8 projection, unbuilt
    /// provider) reports `Unknown` instead of `Complete`. The HostLab SQL
    /// provider calls it before it opens any relation.
    ///
    /// Every frozen column is included, assembled or not. Asking for a relation
    /// means "prove this relation", so a column without a production projection
    /// would keep the whole relation `Unknown` instead of silently narrowing the
    /// request to the assembled subset. All 156 columns are assembled today.
    pub fn for_relations(scope: &SelectedScope, relations: &[&str]) -> MddResult<Self> {
        for relation in relations {
            if !column_specs().iter().any(|spec| spec.relation == *relation) {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.coverage",
                    "unknown frozen relation",
                )
                .detail("relation", (*relation).to_owned()));
            }
        }
        let mut required_columns = Vec::new();
        let mut required_layers = BTreeSet::new();
        for relation in relations {
            for spec in column_specs()
                .iter()
                .filter(|spec| spec.relation == *relation)
            {
                required_layers.extend(column_layers(spec.relation, spec.column));
                required_columns.push(ColumnRequirement {
                    relation: spec.relation.to_owned(),
                    column: spec.column.to_owned(),
                    domain: ColumnDomain::FrozenProjection,
                });
            }
        }
        Ok(Self {
            scope_id: scope.scope_id().into(),
            input: InputNeed::ValidatedStandardDex,
            required_layers: required_layers.into_iter().collect(),
            required_columns,
            required_resource_members: Vec::new(),
            non_scalar_text_policy: NonScalarTextPolicy::Reject,
        })
    }

    pub fn with_non_scalar_text_policy(mut self, policy: NonScalarTextPolicy) -> Self {
        self.non_scalar_text_policy = policy;
        self
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct CoverageIssue {
    pub occurrence: Option<String>,
    pub layer: String,
    pub column: Option<String>,
    pub reason: String,
    pub blocking: bool,
    pub error: Option<MddError>,
}
#[derive(Clone, Debug, Serialize)]
pub struct CoverageReport {
    pub snapshot_id: String,
    pub scope_id: String,
    pub scope_content_key: String,
    pub covers_all_captured_sources: bool,
    pub selected_dex_occurrences: Vec<String>,
    pub input: Completeness,
    pub facts: Completeness,
    pub required_layers: Vec<FactLayer>,
    pub issues: Vec<CoverageIssue>,
    pub native_facts_only: bool,
    pub profile_admitted: bool,
}
impl CoverageReport {
    pub fn require_complete(&self) -> MddResult<()> {
        if self.input == Completeness::Complete
            && self.facts == Completeness::Complete
            && self.issues.iter().all(|issue| !issue.blocking)
        {
            return Ok(());
        }
        if let Some(error) = self
            .issues
            .iter()
            .filter_map(|issue| issue.error.as_ref())
            .max_by_key(|error| error_priority(error.code))
        {
            let error = error.clone();
            match error.details.get("scope_id") {
                None => return Err(error.detail("scope_id", self.scope_id.clone())),
                Some(existing) if existing.as_str() == Some(self.scope_id.as_str()) => {
                    return Err(error);
                }
                Some(_) => (),
            }
            if let Some(attempts) = error.details.len().checked_add(1) {
                for ordinal in 0..attempts {
                    let key = format!("coverage_scope_id_{ordinal}");
                    if !error.details.contains_key(&key) {
                        return Err(error.detail(key, self.scope_id.clone()));
                    }
                }
            }
            return Err(error);
        }
        Err(MddError::new(
            if self.input == Completeness::Partial {
                ErrorCode::PartialInput
            } else {
                ErrorCode::IncompleteFacts
            },
            "facts.coverage",
            "required input/fact/column scope is not complete",
        )
        .detail("scope_id", self.scope_id.clone())
        .detail(
            "blocking_issues",
            self.issues
                .iter()
                .filter(|issue| issue.blocking)
                .count()
                .to_string(),
        ))
    }
}

/// A state a layer or a column is in for one occurrence, with the reason and error that explain it when it is not complete.
type State = (Completeness, Option<String>, Option<MddError>);

/// What one logical occurrence contributes to a coverage report: the state of each required layer and of each required
/// column, in the order of the request. It holds no reference to the occurrence's facts, so a caller that builds the
/// facts of one DEX at a time can keep these and let the facts go (see `CoverageLedger::evaluate_from_states`).
#[derive(Clone, Debug)]
pub struct OccurrenceStates {
    occurrence: String,
    layers: Vec<State>,
    /// `None` for a required column the frozen specs do not know; that is reported once for the request, not per DEX.
    columns: Vec<Option<State>>,
    /// Whether this occurrence's view proves a standard DEX header, which is what `ValidatedStandardDex` input needs of
    /// every occurrence of the scope.
    standard_header_proven: bool,
}

impl OccurrenceStates {
    pub fn occurrence(&self) -> &str {
        &self.occurrence
    }

    /// True when every required layer and every required column is complete for this occurrence, and the frozen
    /// specs know every required column. A caller that would only produce rows for an occurrence the ledger accepts
    /// can skip the work for one it will refuse.
    pub fn is_complete(&self) -> bool {
        self.layers
            .iter()
            .all(|(state, ..)| *state == Completeness::Complete)
            && self.columns.iter().all(|column| {
                column
                    .as_ref()
                    .is_some_and(|(state, ..)| *state == Completeness::Complete)
            })
    }
}

pub struct CoverageLedger<'a> {
    scope: SelectedScope,
    views: BTreeMap<String, FactView<'a>>,
    failures: BTreeMap<(String, FactLayer), MddError>,
    input_failure: Option<MddError>,
    resources: BTreeMap<String, &'a ResourceByteEvidence>,
}
fn issue(
    occurrence: Option<&str>,
    layer: impl Into<String>,
    column: Option<String>,
    reason: impl Into<String>,
    error: Option<MddError>,
) -> CoverageIssue {
    CoverageIssue {
        occurrence: occurrence.map(str::to_owned),
        layer: layer.into(),
        column,
        reason: reason.into(),
        blocking: true,
        error,
    }
}
fn combine(values: impl IntoIterator<Item = Completeness>) -> Completeness {
    let mut unknown = false;
    for value in values {
        match value {
            Completeness::Partial => return Completeness::Partial,
            Completeness::Unknown => unknown = true,
            Completeness::Complete => {}
        }
    }
    if unknown {
        Completeness::Unknown
    } else {
        Completeness::Complete
    }
}
fn error_priority(code: ErrorCode) -> u8 {
    match code {
        ErrorCode::InternalFault | ErrorCode::WorkerLost => 10,
        ErrorCode::InvalidInput | ErrorCode::SourceChanged | ErrorCode::CacheCorrupt => 9,
        ErrorCode::Cancelled | ErrorCode::QuotaExceeded | ErrorCode::DeadlineExceeded => 8,
        ErrorCode::UnsupportedCapability
        | ErrorCode::UnsupportedQuery
        | ErrorCode::UnavailableBackend => 1,
        ErrorCode::IncompleteFacts | ErrorCode::PartialInput => 3,
        _ => 6,
    }
}
/// Fact layers a frozen relation column is projected from.
///
/// Shared by [`CoverageRequest::for_relations`] (which derives the layer set it
/// must require) and by `column_state` (which evaluates those layers before the
/// column gate). An empty slice means the relation has no known producer, which
/// `column_state` reports as `unknown_native_column_producer`.
fn column_layers(relation: &str, column: &str) -> Vec<FactLayer> {
    match relation {
        "dex_files" | "strings" | "types" => vec![FactLayer::Metadata],
        "methods" if matches!(column, "opcode_count" | "opcode_hex") => vec![
            FactLayer::Definitions,
            FactLayer::MethodBindings,
            FactLayer::AllMethodBodies,
        ],
        "methods" | "classes" | "class_interfaces" | "class_fields" | "class_methods" => {
            vec![FactLayer::Definitions]
        }
        "code_items" => vec![
            FactLayer::Definitions,
            FactLayer::MethodBindings,
            FactLayer::AllMethodBodies,
        ],
        "annotation_directory_entries"
        | "annotation_set_entries"
        | "annotations"
        | "annotation_elements" => vec![FactLayer::Annotations],
        "method_strings" | "method_calls" | "method_field_accesses" | "method_used_types" => {
            vec![FactLayer::References]
        }
        _ => Vec::new(),
    }
}
fn dependencies(layer: FactLayer) -> &'static [FactLayer] {
    match layer {
        FactLayer::Definitions => &[FactLayer::Metadata],
        FactLayer::Structure => &[FactLayer::Metadata, FactLayer::Definitions],
        FactLayer::References
        | FactLayer::MethodBindings
        | FactLayer::AllMethodBodies
        | FactLayer::RawCode => &[
            FactLayer::Metadata,
            FactLayer::Definitions,
            FactLayer::CodeProjection,
        ],
        FactLayer::Annotations => &[FactLayer::Metadata, FactLayer::Definitions],
        FactLayer::PrototypeParameterPositions => &[
            FactLayer::Metadata,
            FactLayer::Definitions,
            FactLayer::Annotations,
        ],
        FactLayer::AllPhysicalCode | FactLayer::SourcePositions => &[FactLayer::CodeProjection],
        _ => &[],
    }
}

impl<'a> CoverageLedger<'a> {
    pub fn new(scope: SelectedScope, views: &[FactView<'a>]) -> MddResult<Self> {
        let mut map = BTreeMap::new();
        for view in views {
            view.validate(&scope)?;
            if map
                .insert(view.occurrence().to_owned(), view.clone())
                .is_some()
            {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.coverage",
                    "duplicate fact view for one logical occurrence",
                ));
            }
        }
        Ok(Self {
            scope,
            views: map,
            failures: BTreeMap::new(),
            input_failure: None,
            resources: BTreeMap::new(),
        })
    }
    pub fn scope(&self) -> &SelectedScope {
        &self.scope
    }
    pub fn record_failure(
        &mut self,
        occurrence: &str,
        layer: FactLayer,
        error: MddError,
    ) -> MddResult<()> {
        if !self.scope.contains_dex(occurrence) {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.coverage",
                "failed occurrence is outside selected scope",
            ));
        }
        let key = (occurrence.to_owned(), layer);
        if self.failures.contains_key(&key) {
            return Err(MddError::new(ErrorCode::InvalidArgument,"facts.coverage","terminal producer failure already recorded; use a new evidence epoch for a new attempt").detail("reason","FAILURE_ALREADY_RECORDED"));
        }
        self.failures.insert(key, error);
        Ok(())
    }
    pub fn record_input_failure(&mut self, error: MddError) -> MddResult<()> {
        if self.input_failure.is_some() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.coverage",
                "terminal input failure already recorded",
            )
            .detail("reason", "FAILURE_ALREADY_RECORDED"));
        }
        self.input_failure = Some(error);
        Ok(())
    }
    pub fn record_resource(&mut self, resource: &'a ResourceByteEvidence) -> MddResult<()> {
        if resource.snapshot_id() != self.scope.snapshot_id()
            || !self
                .scope
                .inputs()
                .iter()
                .any(|input| input.source_occurrence_id == resource.member().source_occurrence_id)
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.coverage",
                "resource proof is outside selected immutable inputs",
            ));
        }
        self.resources
            .insert(resource.member().member_id.clone(), resource);
        Ok(())
    }
    fn input_state(
        &self,
        need: InputNeed,
        standard_header_proven: &dyn Fn(&str) -> bool,
    ) -> Completeness {
        if self.input_failure.is_some() {
            return Completeness::Partial;
        }
        match need {
            InputNeed::CapturedBytes => Completeness::Complete,
            InputNeed::SelectedInventory => {
                if self
                    .scope
                    .inputs()
                    .iter()
                    .all(|input| input.inventory_complete && input.selected_bytes_complete)
                {
                    Completeness::Complete
                } else {
                    Completeness::Unknown
                }
            }
            InputNeed::ValidatedStandardDex => {
                if !self.scope.roster_complete() {
                    Completeness::Unknown
                } else if self
                    .scope
                    .dexes()
                    .iter()
                    .all(|dex| standard_header_proven(&dex.dex_occurrence_id))
                {
                    Completeness::Complete
                } else {
                    Completeness::Unknown
                }
            }
        }
    }
    fn layer_state(
        &self,
        occurrence: &str,
        layer: FactLayer,
    ) -> (Completeness, Option<String>, Option<MddError>) {
        if let Some(error) = self.failures.get(&(occurrence.to_owned(), layer)) {
            return (
                Completeness::Partial,
                Some("required_producer_failed".into()),
                Some(error.clone()),
            );
        }
        let failed_dependencies = dependencies(layer)
            .iter()
            .filter_map(|dependency| {
                self.failures
                    .get(&(occurrence.to_owned(), *dependency))
                    .map(|error| (*dependency, error))
            })
            .collect::<Vec<_>>();
        if let Some((dependency, error)) = failed_dependencies
            .iter()
            .max_by_key(|(_, error)| error_priority(error.code))
        {
            return (
                Completeness::Partial,
                Some(format!("required_dependency_failed:{dependency:?}")),
                Some((*error).clone()),
            );
        }
        let Some(view) = self.views.get(occurrence) else {
            return (
                Completeness::Unknown,
                Some("fact_view_not_built".into()),
                None,
            );
        };
        let state =
            match layer {
                FactLayer::Metadata => view
                    .metadata
                    .map(|value| value.metadata_coverage())
                    .unwrap_or(Completeness::Unknown),
                FactLayer::Definitions => view
                    .definitions
                    .map(|value| value.definition_coverage())
                    .unwrap_or(Completeness::Unknown),
                FactLayer::Structure => combine([
                    view.metadata
                        .map(|v| v.metadata_coverage())
                        .unwrap_or(Completeness::Unknown),
                    view.definitions
                        .map(|v| v.definition_coverage())
                        .unwrap_or(Completeness::Unknown),
                ]),
                FactLayer::CodeProjection => view
                    .code
                    .map(|value| value.code_layout_coverage())
                    .unwrap_or(Completeness::Unknown),
                FactLayer::AllPhysicalCode => view
                    .code
                    .map(|value| {
                        let provided = value
                            .items()
                            .iter()
                            .map(|item| item.data().raw_range.byte_offset.0)
                            .collect::<BTreeSet<_>>();
                        if value
                            .declared_code_item_byte_offsets()
                            .iter()
                            .all(|offset| provided.contains(&offset.0))
                        {
                            value.code_layout_coverage()
                        } else {
                            Completeness::Partial
                        }
                    })
                    .unwrap_or(Completeness::Unknown),
                FactLayer::MethodBindings => {
                    if view.references.is_some()
                        || view.raw_code.is_some()
                        || view.definitions.is_some_and(|definitions| {
                            definitions
                                .definitions()
                                .method_definitions
                                .iter()
                                .all(|method| !matches!(method.body, MethodBody::Present { .. }))
                        })
                    {
                        Completeness::Complete
                    } else {
                        Completeness::Unknown
                    }
                }
                FactLayer::AllMethodBodies => {
                    if let Some(references) = view.references {
                        references.coverage().facts
                    } else if let Some(definitions) = view.definitions {
                        let mut missing = false;
                        for method in &definitions.definitions().method_definitions {
                            if let MethodBody::Present {
                                code_byte_offset, ..
                            } = method.body
                            {
                                let Some(code) = view.code else {
                                    missing = true;
                                    continue;
                                };
                                if !code.known_code_item_start(code_byte_offset.0) {
                                    return (
                                    Completeness::Partial,
                                    Some("method_body_not_physical_item_start".into()),
                                    Some(
                                        MddError::new(
                                            ErrorCode::InvalidInput,
                                            "facts.coverage",
                                            "method body pointer is not a physical code item start",
                                        )
                                        .detail("byte_offset", code_byte_offset.0.to_string()),
                                    ),
                                );
                                }
                                if !code.items().iter().any(|item| {
                                    item.data().raw_range.byte_offset == code_byte_offset
                                }) {
                                    missing = true;
                                }
                            }
                        }
                        if missing {
                            Completeness::Partial
                        } else {
                            Completeness::Complete
                        }
                    } else {
                        Completeness::Unknown
                    }
                }
                FactLayer::References => view
                    .references
                    .map(|value| value.coverage().facts)
                    .unwrap_or(Completeness::Unknown),
                FactLayer::Annotations => view
                    .annotations
                    .map(|value| value.annotation_coverage())
                    .unwrap_or(Completeness::Unknown),
                FactLayer::PrototypeParameterPositions => {
                    if let Some(value) = view.annotations {
                        if let Err(error) = value.require_complete_parameter_positions() {
                            return (
                                Completeness::Unknown,
                                Some("prototype_positions_not_proven_by_encoded_slots".into()),
                                Some(error),
                            );
                        }
                        Completeness::Complete
                    } else {
                        Completeness::Unknown
                    }
                }
                FactLayer::RawCode => {
                    if view.raw_code.is_some() {
                        Completeness::Complete
                    } else {
                        Completeness::Unknown
                    }
                }
                FactLayer::SourcePositions => {
                    if view
                        .code
                        .is_some_and(|value| value.source_positions_built())
                    {
                        Completeness::Complete
                    } else {
                        Completeness::Unknown
                    }
                }
                FactLayer::DerivedAnalysis => Completeness::Unknown,
            };
        (
            state,
            (state != Completeness::Complete).then(|| {
                if state == Completeness::Partial {
                    "declared_required_scope_partially_built".into()
                } else {
                    "required_fact_scope_not_built".into()
                }
            }),
            None,
        )
    }
    fn native_column_layers(spec: &ColumnSpec) -> Vec<FactLayer> {
        column_layers(spec.relation, spec.column)
    }
    /// Provider gate for every frozen relation that has a production row
    /// projection.
    ///
    /// The outer `Option` is `None` for relations the coverage ledger answers
    /// through its own match arms (the four `method_*` reference relations). The
    /// inner `Option` is `None` when the fact object that owns the projection was
    /// never built: that is an explicit gap, never a silent `Complete`. A
    /// provider rejection is returned as the provider's own error so coverage
    /// reports the real reason.
    ///
    /// Returning `Some` here is the contract that the relation is *gated*: no
    /// frozen relation may reach an unconditional `Ok(())` after this point, so
    /// `column_state` treats an unmapped relation as an explicit `Unknown`.
    fn frozen_provider_gate(
        view: &FactView<'_>,
        spec: &ColumnSpec,
    ) -> Option<Option<MddResult<()>>> {
        let columns = [spec.column];
        match spec.relation {
            // `dex_files.source_path`/`entry_name` are snapshot/inventory
            // provenance, so they are gated by the scope projection rather than
            // by the metadata object. The remaining `dex_files` columns stay on
            // the metadata gate, and `strings`/`types` are metadata-only.
            "dex_files" if matches!(spec.column, "source_path" | "entry_name") => {
                Some(Some(SelectedScope::require_dex_file_columns(&columns)))
            }
            "dex_files" | "strings" | "types" => {
                Some(view.metadata.map(|facts| match spec.relation {
                    "dex_files" => {
                        facts.require_relation_columns(MetadataRelation::DexFiles, &columns)
                    }
                    "strings" => {
                        facts.require_relation_columns(MetadataRelation::Strings, &columns)
                    }
                    _ => facts.require_relation_columns(MetadataRelation::Types, &columns),
                }))
            }
            // `opcode_count`/`opcode_hex` need the code-layout layer, which only
            // `MethodCodeFactViews` holds. Its presence plus a complete code
            // layout is the provider condition.
            "methods" if matches!(spec.column, "opcode_count" | "opcode_hex") => {
                Some(match (view.definitions, view.code) {
                    (Some(_), Some(code))
                        if code.code_layout_coverage() == Completeness::Complete =>
                    {
                        Some(MethodCodeFactViews::require_method_columns(&columns))
                    }
                    _ => None,
                })
            }
            "methods" | "classes" => Some(view.definitions.map(|facts| match spec.relation {
                "methods" => facts.require_relation_columns(DefinitionRelation::Methods, &columns),
                _ => facts.require_relation_columns(DefinitionRelation::Classes, &columns),
            })),
            // `class_interfaces` / `class_fields` / `class_methods` rows are
            // projected from `DefinitionFacts`; `annotations` and its three
            // index-derived relations are projected from `AnnotationFacts`,
            // which itself owns a `DefinitionFacts` clone. A missing provider is
            // reported as `None` instead of borrowing another relation's columns.
            "class_interfaces" => Some(view.definitions.map(|facts| {
                facts.require_relation_columns(DefinitionRelation::ClassInterfaces, &columns)
            })),
            "class_fields" => Some(view.definitions.map(|facts| {
                facts.require_relation_columns(DefinitionRelation::ClassFields, &columns)
            })),
            "class_methods" => Some(view.definitions.map(|facts| {
                facts.require_relation_columns(DefinitionRelation::ClassMethods, &columns)
            })),
            "annotation_directory_entries" => Some(view.annotations.map(|facts| {
                facts.require_relation_columns(AnnotationRelation::DirectoryEntries, &columns)
            })),
            "annotation_set_entries" => Some(view.annotations.map(|facts| {
                facts.require_relation_columns(AnnotationRelation::SetEntries, &columns)
            })),
            "annotations" => Some(view.annotations.map(|facts| {
                facts.require_relation_columns(AnnotationRelation::Annotations, &columns)
            })),
            "annotation_elements" => Some(view.annotations.map(|facts| {
                facts.require_relation_columns(AnnotationRelation::Elements, &columns)
            })),
            // `code_items` rows are projected by `MethodCodeFactViews`, which
            // needs both the definition join and a complete code layout. The
            // column names themselves are pure header atoms, so the column gate
            // is build-free; the provider presence is checked here instead of
            // being assumed from a layer that can be complete without code.
            "code_items" => Some(match (view.definitions, view.code) {
                (Some(_), Some(code)) if code.code_layout_coverage() == Completeness::Complete => {
                    Some(require_code_item_columns(&columns))
                }
                _ => None,
            }),
            _ => None,
        }
    }

    /// Frozen projections that render validated `DexText` as a plain UTF-8
    /// column. When the scope contains a legal non-scalar value the row
    /// projection itself answers `UnsupportedQuery`, so coverage must not
    /// report `Complete`.
    fn non_scalar_text_gap(view: &FactView<'_>, spec: &ColumnSpec) -> bool {
        match (spec.relation, spec.column) {
            ("method_strings", "value") => view.references.is_some_and(|references| {
                references
                    .sites()
                    .iter()
                    .filter(|site| site.target_kind == TargetKind::String)
                    .any(|site| {
                        !references
                            .definitions()
                            .metadata()
                            .strings()
                            .get(site.target_local_index as usize)
                            .is_some_and(|fact| fact.data.text.strict_utf8().is_ok())
                    })
            }),
            ("strings", "value") => view.metadata.is_some_and(|metadata| {
                metadata
                    .strings()
                    .iter()
                    .any(|fact| fact.data.text.strict_utf8().is_err())
            }),
            ("classes", "source_file") => view.definitions.is_some_and(|definitions| {
                definitions.definitions().classes.iter().any(|class| {
                    class
                        .source_file
                        .as_ref()
                        .is_some_and(|text| text.strict_utf8().is_err())
                })
            }),
            _ => false,
        }
    }

    /// Explicit evidence when the snapshot/inventory provenance of one selected
    /// occurrence cannot be projected as non-nullable UTF-8. `None` means the
    /// pair is available, so the caller may report `Complete`.
    fn provenance_gap(
        &self,
        occurrence: &str,
    ) -> Option<(Completeness, Option<String>, Option<MddError>)> {
        let dex = self
            .scope
            .dexes()
            .iter()
            .find(|dex| dex.dex_occurrence_id == occurrence)?;
        let error = self.scope.dex_file_provenance(dex).err()?;
        let reason = match error.details.get("reason").and_then(|value| value.as_str()) {
            Some("ENTRY_NAME_NOT_UTF8") => "lossless_entry_name_representation_unavailable",
            Some("ENTRY_NAME_POLICY_UNAVAILABLE") => "entry_name_policy_unavailable",
            Some(_) => "lossless_source_path_representation_unavailable",
            // No `reason` detail means the scope itself is inconsistent; retain
            // that fault as the evidence instead of naming a text gap.
            None => return Some((Completeness::Unknown, None, Some(error))),
        };
        Some((Completeness::Unknown, Some(reason.into()), None))
    }

    #[cfg(test)]
    fn column_state(
        &self,
        occurrence: &str,
        spec: &ColumnSpec,
        domain: ColumnDomain,
    ) -> (Completeness, Option<String>, Option<MddError>) {
        self.column_state_with_policy(occurrence, spec, domain, NonScalarTextPolicy::Reject)
    }

    fn column_state_with_policy(
        &self,
        occurrence: &str,
        spec: &ColumnSpec,
        domain: ColumnDomain,
        non_scalar_text_policy: NonScalarTextPolicy,
    ) -> (Completeness, Option<String>, Option<MddError>) {
        let layers = Self::native_column_layers(spec);
        if layers.is_empty() {
            return (
                Completeness::Unknown,
                Some("unknown_native_column_producer".into()),
                None,
            );
        }
        let results = layers
            .into_iter()
            .map(|layer| self.layer_state(occurrence, layer))
            .collect::<Vec<_>>();
        let state = combine(results.iter().map(|result| result.0));
        if state != Completeness::Complete {
            let selected = results
                .iter()
                .filter(|result| result.2.is_some())
                .max_by_key(|result| {
                    result
                        .2
                        .as_ref()
                        .map_or(0, |error| error_priority(error.code))
                })
                .or_else(|| {
                    results
                        .iter()
                        .find(|result| result.0 == Completeness::Partial)
                })
                .or_else(|| {
                    results
                        .iter()
                        .find(|result| result.0 != Completeness::Complete)
                });
            if let Some(selected) = selected {
                return (state, selected.1.clone(), selected.2.clone());
            }
            return (
                Completeness::Unknown,
                Some("coverage_internal_invariant".into()),
                Some(MddError::new(
                    ErrorCode::InternalFault,
                    "facts.coverage",
                    "noncomplete aggregate had no evidence",
                )),
            );
        }
        if domain == ColumnDomain::NativeAtoms {
            // Snapshot/inventory provenance must be representable for this
            // occurrence. A missing source display or a non-UTF-8 archive member
            // name is an explicit gap, not a silently lossy value.
            if spec.relation == "dex_files"
                && matches!(spec.column, "source_path" | "entry_name")
                && let Some(evidence) = self.provenance_gap(occurrence)
            {
                return evidence;
            }
            return (state, None, None);
        }
        if !spec.assembled_projection {
            return (
                Completeness::Unknown,
                Some("frozen_relation_projection_not_assembled".into()),
                None,
            );
        }
        // The provenance pair is produced by the selected scope, not by a fact
        // view, so it must be proven representable here as well: a missing or
        // non-UTF-8 source path/member name cannot be a Complete projection.
        if spec.relation == "dex_files" && matches!(spec.column, "source_path" | "entry_name") {
            if let Some(evidence) = self.provenance_gap(occurrence) {
                return evidence;
            }
            return (Completeness::Complete, None, None);
        }
        let Some(view) = self.views.get(occurrence) else {
            return (
                Completeness::Unknown,
                Some("column_source_not_built".into()),
                None,
            );
        };
        // A projection that renders validated `DexText` as plain UTF-8 fails for
        // a legal non-scalar value under the default strict policy. With an
        // explicit opt-in lossy replacement policy, the provider gate still
        // validates the column and records a non-blocking diagnostic.
        let has_non_scalar_gap = Self::non_scalar_text_gap(view, spec);
        if has_non_scalar_gap && non_scalar_text_policy == NonScalarTextPolicy::Reject {
            return (
                Completeness::Unknown,
                Some("non_scalar_UTF16_cannot_be_plain_UTF8".into()),
                None,
            );
        }
        let with_lossy_note = |state: (Completeness, Option<String>, Option<MddError>)| {
            if state.0 == Completeness::Complete && has_non_scalar_gap {
                (
                    Completeness::Complete,
                    Some("non_scalar_UTF16_lossy_replacement_applied".into()),
                    None,
                )
            } else {
                state
            }
        };
        // Every frozen relation with a production row projection is gated by its
        // owning provider (`frozen_provider_gate`); a rejection is an explicit
        // Unknown carrying the provider's own error. The four `method_*`
        // relations below are gated inline, and their rejection is likewise an
        // explicit Unknown. A relation that reaches neither gate has no proven
        // producer, so it is reported as Unknown rather than defaulted to
        // `Complete`.
        if let Some(result) = Self::frozen_provider_gate(view, spec) {
            return with_lossy_note(match result {
                Some(Ok(())) => (Completeness::Complete, None, None),
                Some(Err(error)) => (
                    Completeness::Unknown,
                    Some("column_gate_rejected_required_scope".into()),
                    Some(error),
                ),
                None => (
                    Completeness::Unknown,
                    Some("column_provider_not_built".into()),
                    None,
                ),
            });
        }
        let result = match spec.relation {
            "method_strings" => view.references.map(|value| {
                value.require_relation_columns(ReferenceRelation::MethodStrings, &[spec.column])
            }),
            "method_calls" => view.references.map(|value| {
                value.require_relation_columns(ReferenceRelation::MethodCalls, &[spec.column])
            }),
            "method_field_accesses" => view.references.map(|value| {
                value.require_relation_columns(
                    ReferenceRelation::MethodFieldAccesses,
                    &[spec.column],
                )
            }),
            "method_used_types" => view.references.map(|value| {
                value.require_relation_columns(ReferenceRelation::MethodUsedTypes, &[spec.column])
            }),
            _ => None,
        };
        with_lossy_note(match result {
            Some(Ok(())) => (Completeness::Complete, None, None),
            Some(Err(error)) => (
                Completeness::Unknown,
                Some("column_gate_rejected_required_scope".into()),
                Some(error),
            ),
            None => (
                Completeness::Unknown,
                Some("column_provider_not_built".into()),
                None,
            ),
        })
    }
    /// The state of every required layer and column for one logical occurrence of the scope, read from this ledger's
    /// view of it. A ledger built over a single view answers for that view alone.
    pub fn occurrence_states(
        &self,
        request: &CoverageRequest,
        occurrence: &str,
    ) -> OccurrenceStates {
        OccurrenceStates {
            occurrence: occurrence.to_owned(),
            standard_header_proven: self
                .views
                .get(occurrence)
                .is_some_and(FactView::standard_header_proven),
            layers: request
                .required_layers
                .iter()
                .map(|layer| self.layer_state(occurrence, *layer))
                .collect(),
            columns: request
                .required_columns
                .iter()
                .map(|required| {
                    column_specs()
                        .iter()
                        .find(|spec| {
                            spec.relation == required.relation && spec.column == required.column
                        })
                        .map(|spec| {
                            self.column_state_with_policy(
                                occurrence,
                                spec,
                                required.domain,
                                request.non_scalar_text_policy,
                            )
                        })
                })
                .collect(),
        }
    }

    pub fn evaluate(&self, request: &CoverageRequest) -> MddResult<CoverageReport> {
        let states: Vec<OccurrenceStates> = self
            .scope
            .dexes()
            .iter()
            .map(|dex| self.occurrence_states(request, &dex.dex_occurrence_id))
            .collect();
        self.evaluate_from_states(request, &states)
    }

    /// The report for `request` from the per-occurrence states of every DEX of the scope, in any order. `evaluate` is this
    /// over the states of this ledger's own views; a caller that cannot hold every DEX's facts at once computes each
    /// DEX's states with a ledger over that DEX's view alone and hands them all here, and gets the same report.
    pub fn evaluate_from_states(
        &self,
        request: &CoverageRequest,
        states: &[OccurrenceStates],
    ) -> MddResult<CoverageReport> {
        let by_occurrence: BTreeMap<&str, &OccurrenceStates> = states
            .iter()
            .map(|state| (state.occurrence.as_str(), state))
            .collect();
        if by_occurrence.len() != states.len() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.coverage",
                "two states for one logical occurrence",
            ));
        }
        for dex in self.scope.dexes() {
            if !by_occurrence.contains_key(dex.dex_occurrence_id.as_str()) {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.coverage",
                    "no state for a logical occurrence of the scope",
                )
                .detail("dex_occurrence_id", dex.dex_occurrence_id.clone()));
            }
        }
        if request.scope_id != self.scope.scope_id() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.coverage",
                "request scope_id does not bind this ledger",
            ));
        }
        if request.required_layers.len() > 128
            || request.required_columns.len() > 4096
            || request.required_resource_members.len() > 4096
        {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.coverage",
                "coverage requirement count exceeds budget",
            ));
        }
        if request
            .required_columns
            .iter()
            .any(|column| column.relation.len() > 256 || column.column.len() > 256)
            || request
                .required_resource_members
                .iter()
                .any(|member| member.len() > 512)
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.coverage",
                "coverage relation/column/member identity exceeds supported length",
            ));
        }
        let checks = request
            .required_layers
            .len()
            .checked_add(request.required_columns.len())
            .and_then(|count| count.checked_mul(self.scope.dexes().len().max(1)))
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.coverage",
                    "coverage check count overflow",
                )
            })?;
        if checks > 65536 {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.coverage",
                "coverage check matrix exceeds budget; split explicit scopes",
            ));
        }
        let input = self.input_state(request.input, &|occurrence| {
            by_occurrence
                .get(occurrence)
                .is_some_and(|state| state.standard_header_proven)
        });
        let mut issues = Vec::new();
        if input != Completeness::Complete {
            issues.push(issue(
                None,
                "input",
                None,
                "required_input_scope_not_complete",
                self.input_failure.clone(),
            ));
        }
        let mut values = Vec::new();
        let mut required = request
            .required_layers
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        for column in &request.required_columns {
            if let Some(spec) = column_specs()
                .iter()
                .find(|spec| spec.relation == column.relation && spec.column == column.column)
            {
                required.extend(Self::native_column_layers(spec));
            }
        }
        let mut pending = required.iter().copied().collect::<Vec<_>>();
        while let Some(layer) = pending.pop() {
            for dependency in dependencies(layer) {
                if required.insert(*dependency) {
                    pending.push(*dependency);
                }
            }
        }
        for ((occurrence, layer), error) in &self.failures {
            if required.contains(layer) {
                values.push(Completeness::Partial);
                issues.push(issue(
                    Some(occurrence),
                    format!("{layer:?}"),
                    None,
                    "required_producer_failure_retained",
                    Some(error.clone()),
                ));
            }
        }
        for (layer_position, layer) in request.required_layers.iter().enumerate() {
            if self.scope.dexes().is_empty()
                && (!self.scope.roster_complete()
                    || matches!(
                        layer,
                        FactLayer::SourcePositions | FactLayer::DerivedAnalysis
                    ))
            {
                values.push(Completeness::Unknown);
                issues.push(issue(
                    None,
                    format!("{layer:?}"),
                    None,
                    "no_complete_roster_or_required_producer",
                    None,
                ));
            }
            for dex in self.scope.dexes() {
                let (state, reason, error) =
                    by_occurrence[dex.dex_occurrence_id.as_str()].layers[layer_position].clone();
                values.push(state);
                if let Some(reason) = reason {
                    issues.push(issue(
                        Some(&dex.dex_occurrence_id),
                        format!("{layer:?}"),
                        None,
                        reason,
                        error,
                    ));
                }
            }
        }
        for (column_position, required) in request.required_columns.iter().enumerate() {
            let key = format!("{}.{}", required.relation, required.column);
            let Some(spec) = column_specs()
                .iter()
                .find(|spec| spec.relation == required.relation && spec.column == required.column)
            else {
                values.push(Completeness::Unknown);
                issues.push(issue(
                    None,
                    "column",
                    Some(key),
                    "unknown_relation_or_column",
                    None,
                ));
                continue;
            };
            if self.scope.dexes().is_empty()
                && (!self.scope.roster_complete()
                    || (required.domain == ColumnDomain::FrozenProjection
                        && !spec.assembled_projection))
            {
                values.push(Completeness::Unknown);
                issues.push(issue(
                    None,
                    "column",
                    Some(key.clone()),
                    "required_projection_or_input_scope_not_built",
                    None,
                ));
            }
            for dex in self.scope.dexes() {
                let (state, reason, error) = by_occurrence[dex.dex_occurrence_id.as_str()].columns
                    [column_position]
                    .clone()
                    .unwrap_or_else(|| {
                        (
                            Completeness::Unknown,
                            Some("unknown_relation_or_column".into()),
                            None,
                        )
                    });
                values.push(state);
                if let Some(reason) = reason {
                    issues.push(CoverageIssue {
                        occurrence: Some(dex.dex_occurrence_id.clone()),
                        layer: "column".into(),
                        column: Some(key.clone()),
                        reason,
                        blocking: state != Completeness::Complete,
                        error,
                    });
                }
            }
        }
        for member in &request.required_resource_members {
            let state = if self.resources.contains_key(member) {
                Completeness::Complete
            } else {
                issues.push(issue(
                    None,
                    "raw_resource",
                    Some(member.clone()),
                    "required_member_bytes_not_built",
                    None,
                ));
                Completeness::Unknown
            };
            values.push(state);
        }
        Ok(CoverageReport {
            snapshot_id: self.scope.snapshot_id().into(),
            scope_id: self.scope.scope_id().into(),
            scope_content_key: self.scope.scope_content_key().into(),
            covers_all_captured_sources: self.scope.covers_all_captured_sources(),
            selected_dex_occurrences: self
                .scope
                .dexes()
                .iter()
                .map(|dex| dex.dex_occurrence_id.clone())
                .collect(),
            input,
            facts: combine(values),
            required_layers: request.required_layers.clone(),
            issues,
            native_facts_only: request
                .required_columns
                .iter()
                .all(|column| column.domain == ColumnDomain::NativeAtoms),
            profile_admitted: false,
        })
    }
}

#[cfg(test)]
#[path = "coverage_tests.rs"]
mod coverage_tests;
