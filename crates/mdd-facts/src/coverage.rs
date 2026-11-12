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
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

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
        })
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

#[cfg(test)]
// This regression module sits next to the helper it covers rather than at the
// end of the file, which keeps the red/green pair readable.
#[allow(clippy::items_after_test_module)]
mod error_detail_tests {
    use super::*;

    #[test]
    fn source_error_scope_detail_is_preserved() {
        let original = MddError::new(ErrorCode::InvalidInput, "input", "bad input")
            .detail("scope_id", "prior")
            .detail("coverage_scope_id_0", "prior collision");
        let report = CoverageReport {
            snapshot_id: "snapshot".into(),
            scope_id: "actual".into(),
            scope_content_key: "key".into(),
            covers_all_captured_sources: false,
            selected_dex_occurrences: vec![],
            input: Completeness::Partial,
            facts: Completeness::Partial,
            required_layers: vec![],
            issues: vec![CoverageIssue {
                occurrence: None,
                layer: "input".into(),
                column: None,
                reason: "bad".into(),
                blocking: true,
                error: Some(original.clone()),
            }],
            native_facts_only: true,
            profile_admitted: false,
        };
        let returned = report.require_complete().unwrap_err();
        assert_eq!(returned.code, original.code);
        assert_eq!(returned.stage, original.stage);
        assert_eq!(returned.message, original.message);
        for (key, value) in &original.details {
            assert_eq!(returned.details.get(key), Some(value));
        }
        assert_eq!(returned.details["coverage_scope_id_1"], "actual");
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
    fn input_state(&self, need: InputNeed) -> Completeness {
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
                } else if self.scope.dexes().iter().all(|dex| {
                    self.views
                        .get(&dex.dex_occurrence_id)
                        .is_some_and(FactView::standard_header_proven)
                }) {
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

    fn column_state(
        &self,
        occurrence: &str,
        spec: &ColumnSpec,
        domain: ColumnDomain,
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
        // a legal non-scalar value even when every fact layer is complete. That
        // gap must surface as Unknown instead of a fabricated Complete.
        if Self::non_scalar_text_gap(view, spec) {
            return (
                Completeness::Unknown,
                Some("non_scalar_UTF16_cannot_be_plain_UTF8".into()),
                None,
            );
        }
        // Every frozen relation with a production row projection is gated by its
        // owning provider (`frozen_provider_gate`); a rejection is an explicit
        // Unknown carrying the provider's own error. The four `method_*`
        // relations below are gated inline, and their rejection is likewise an
        // explicit Unknown. A relation that reaches neither gate has no proven
        // producer, so it is reported as Unknown rather than defaulted to
        // `Complete`.
        if let Some(result) = Self::frozen_provider_gate(view, spec) {
            return match result {
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
            };
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
        match result {
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
        }
    }
    pub fn evaluate(&self, request: &CoverageRequest) -> MddResult<CoverageReport> {
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
        let input = self.input_state(request.input);
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
        for layer in &request.required_layers {
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
                let (state, reason, error) = self.layer_state(&dex.dex_occurrence_id, *layer);
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
        for required in &request.required_columns {
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
                let (state, reason, error) =
                    self.column_state(&dex.dex_occurrence_id, spec, required.domain);
                values.push(state);
                if let Some(reason) = reason {
                    issues.push(issue(
                        Some(&dex.dex_occurrence_id),
                        "column",
                        Some(key.clone()),
                        reason,
                        error,
                    ));
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
mod coverage_column_gate_tests {
    use super::*;
    use crate::code::CodeFacts;
    use crate::definitions::DefinitionFacts;
    use crate::indexes::{FactView, SelectedScope};
    use crate::metadata::MetadataFacts;
    use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits, strings::StringLimits};
    use mdd_input::{
        archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
        snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
    };
    use std::path::PathBuf;

    fn fixture(relative: &str, copies: usize) -> (Snapshot, Vec<ArchiveInventory>) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(relative);
        let inputs = (0..copies)
            .map(|_| InputSpec {
                path: path.clone(),
                kind: InputKind::RawDex,
                expected_sha256: None,
            })
            .collect::<Vec<_>>();
        let snapshot = Snapshot::capture(&inputs, CaptureLimits::default()).unwrap();
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
        (snapshot, inventories)
    }

    fn metadata(snapshot: &Snapshot, inventory: &ArchiveInventory) -> MetadataFacts {
        MetadataFacts::build(snapshot, inventory, 0, StringLimits::default()).unwrap()
    }

    fn definitions(snapshot: &Snapshot, inventory: &ArchiveInventory) -> DefinitionFacts {
        DefinitionFacts::build(metadata(snapshot, inventory), DefinitionLimits::default()).unwrap()
    }

    fn code(snapshot: &Snapshot, inventory: &ArchiveInventory) -> CodeFacts {
        CodeFacts::build_all_code_items(snapshot, inventory, 0, CodeLimits::default()).unwrap()
    }

    fn column_request(scope: &SelectedScope, relation: &str, name: &str) -> CoverageRequest {
        let mut request = CoverageRequest::for_scope(scope, &[]);
        request.required_columns.push(ColumnRequirement {
            relation: relation.into(),
            column: name.into(),
            domain: ColumnDomain::FrozenProjection,
        });
        request
    }

    /// Every column of the six newly assembled relations reports `Complete`
    /// when its provider gate accepts the request.
    #[test]
    fn assembled_relations_report_complete_when_gates_accept() {
        let (snapshot, inventories) = fixture("references/generated/classic-035.dex", 1);
        let defs = definitions(&snapshot, &inventories[0]);
        let codes = code(&snapshot, &inventories[0]);
        let refs = crate::references::ReferenceFacts::build(
            defs,
            codes,
            crate::references::ReferenceLimits::default(),
        )
        .unwrap();
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let view = FactView::unbuilt(&refs.source().dex_occurrence_id).with_references(&refs);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        let cases: [(&str, &[&str]); 6] = [
            ("dex_files", &["file_id", "byte_len", "map_off"]),
            ("strings", &["string_pool_id", "string_idx", "value"]),
            ("types", &["file_id", "type_idx", "descriptor", "java_name"]),
            (
                "methods",
                &["method_idx", "class_descriptor", "access_flags"],
            ),
            (
                "classes",
                &["class_idx", "descriptor", "superclass_descriptor"],
            ),
            ("code_items", &["method_idx", "code_off", "insns_off"]),
        ];
        for (relation, columns) in cases {
            for column in columns {
                let report = ledger
                    .evaluate(&column_request(&scope, relation, column))
                    .unwrap();
                assert_eq!(
                    report.facts,
                    Completeness::Complete,
                    "{relation}.{column} must be complete when its gate accepts: {:?}",
                    report.issues
                );
                assert!(
                    report.issues.is_empty(),
                    "{relation}.{column} produced issues: {:?}",
                    report.issues
                );
            }
        }
    }

    /// Each of the six relations routes its column through the owning provider
    /// gate: a known column passes and an unknown column is rejected with a real
    /// error, never an unconditional `Ok`.
    #[test]
    fn six_relation_gates_accept_and_reject_through_their_provider() {
        let (snapshot, inventories) = fixture("references/generated/classic-035.dex", 1);
        let defs = definitions(&snapshot, &inventories[0]);
        let codes = code(&snapshot, &inventories[0]);
        let refs = crate::references::ReferenceFacts::build(
            defs,
            codes,
            crate::references::ReferenceLimits::default(),
        )
        .unwrap();
        let view = FactView::unbuilt(&refs.source().dex_occurrence_id).with_references(&refs);
        let cases: [(&str, &str); 6] = [
            ("dex_files", "byte_len"),
            ("strings", "string_idx"),
            ("types", "type_idx"),
            ("methods", "method_idx"),
            ("classes", "class_idx"),
            ("code_items", "code_off"),
        ];
        for (relation, column) in cases {
            let accepted = ColumnSpec {
                relation,
                column,
                data_type: "UInt32",
                nullable: false,
                assembled_projection: true,
            };
            assert!(
                matches!(
                    CoverageLedger::frozen_provider_gate(&view, &accepted),
                    Some(Some(Ok(())))
                ),
                "{relation}.{column} must be accepted by its provider gate"
            );
            let unknown = ColumnSpec {
                column: "invented_column",
                ..accepted
            };
            assert!(
                matches!(
                    CoverageLedger::frozen_provider_gate(&view, &unknown),
                    Some(Some(Err(ref error))) if error.code == ErrorCode::InvalidArgument
                ),
                "{relation} must reject an unknown column through its provider gate"
            );
        }
    }

    /// A relation that no gate arm maps has no proven producer. The gate must
    /// decline (`None`) so `column_state` reports it as `Unknown`; an
    /// unconditional `Ok(())` for the fallback arm would silently complete an
    /// unmapped relation. The four `method_*` relations decline for the same
    /// reason because they are gated inline, not here.
    #[test]
    fn unmapped_relation_is_never_gated_to_complete() {
        let (snapshot, inventories) = fixture("references/generated/classic-035.dex", 1);
        let defs = definitions(&snapshot, &inventories[0]);
        let codes = code(&snapshot, &inventories[0]);
        let refs = crate::references::ReferenceFacts::build(
            defs,
            codes,
            crate::references::ReferenceLimits::default(),
        )
        .unwrap();
        let view = FactView::unbuilt(&refs.source().dex_occurrence_id).with_references(&refs);
        for relation in [
            "invented_relation",
            "method_calls",
            "method_strings",
            "method_field_accesses",
            "method_used_types",
        ] {
            let spec = ColumnSpec {
                relation,
                column: "file_id",
                data_type: "UInt32",
                nullable: false,
                assembled_projection: true,
            };
            assert!(
                CoverageLedger::frozen_provider_gate(&view, &spec).is_none(),
                "{relation} must not be gated by the frozen-provider table"
            );
        }
    }

    /// A column the owning provider refuses must report `Unknown` with the
    /// provider's own error, not an unconditional `Complete`.
    #[test]
    fn provider_gate_rejection_reports_unknown_with_provider_error() {
        let (snapshot, inventories) = fixture("references/generated/classic-035.dex", 1);
        let names = metadata(&snapshot, &inventories[0]);
        let defs = DefinitionFacts::build(names.clone(), DefinitionLimits::default()).unwrap();
        let codes = code(&snapshot, &inventories[0]);
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let view = FactView::unbuilt(&names.source().dex_occurrence_id)
            .with_definitions(&defs)
            .with_code(&codes);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        // Columns with a production projection report `Complete` through the
        // provider that now owns them: `param_descriptors` through the definition
        // gate and the two provenance columns through the scope gate.
        for (relation, column) in [
            ("methods", "param_descriptors"),
            ("dex_files", "source_path"),
            ("dex_files", "entry_name"),
        ] {
            let report = ledger
                .evaluate(&column_request(&scope, relation, column))
                .unwrap();
            assert_eq!(report.facts, Completeness::Complete, "{relation}.{column}");
            assert!(report.issues.is_empty(), "{relation}.{column}");
        }
        // The definition object alone cannot answer the opcode columns: it does
        // not hold the code layout. `column_state` must report the missing
        // provider explicitly rather than fabricating a value.
        let definitions_only =
            FactView::unbuilt(&names.source().dex_occurrence_id).with_definitions(&defs);
        let ledger =
            CoverageLedger::new(scope.clone(), std::slice::from_ref(&definitions_only)).unwrap();
        let occurrence = scope.dexes()[0].dex_occurrence_id.clone();
        for column in ["opcode_count", "opcode_hex"] {
            let spec = ColumnSpec {
                relation: "methods",
                column,
                data_type: "UInt32",
                nullable: true,
                assembled_projection: true,
            };
            assert!(matches!(
                CoverageLedger::frozen_provider_gate(&definitions_only, &spec),
                Some(None)
            ));
            // Without code layout the `AllMethodBodies` layer is itself
            // incomplete, so the aggregate is Partial before the column gate is
            // consulted; the important property is that it is never Complete.
            let (state, reason, _) =
                ledger.column_state(&occurrence, &spec, ColumnDomain::FrozenProjection);
            assert_ne!(state, Completeness::Complete, "methods.{column}");
            assert!(reason.is_some(), "methods.{column}");
            assert_ne!(
                ledger
                    .evaluate(&column_request(&scope, "methods", column))
                    .unwrap()
                    .facts,
                Completeness::Complete,
                "methods.{column} without the code provider"
            );
        }
        // With the code-layout layer present those two columns are complete.
        let definitions_and_code = FactView::unbuilt(&names.source().dex_occurrence_id)
            .with_definitions(&defs)
            .with_code(&codes);
        for column in ["opcode_count", "opcode_hex"] {
            let spec = ColumnSpec {
                relation: "methods",
                column,
                data_type: "UInt32",
                nullable: true,
                assembled_projection: true,
            };
            assert!(
                matches!(
                    CoverageLedger::frozen_provider_gate(&definitions_and_code, &spec),
                    Some(Some(Ok(())))
                ),
                "methods.{column} must be accepted once code layout is built"
            );
        }
        // A provider rejection reaches the caller as Unknown carrying the
        // provider error, not as an unconditional Complete. A reference-backed
        // view is used so every column's layer state is complete first and only
        // the column gate can reject.
        let defs = DefinitionFacts::build(names.clone(), DefinitionLimits::default()).unwrap();
        let refs = crate::references::ReferenceFacts::build(
            defs,
            codes.clone(),
            crate::references::ReferenceLimits::default(),
        )
        .unwrap();
        let view = FactView::unbuilt(&names.source().dex_occurrence_id).with_references(&refs);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        for (relation, column) in [
            ("dex_files", "invented_column"),
            ("strings", "invented_column"),
            ("types", "invented_column"),
            ("methods", "invented_column"),
            ("classes", "invented_column"),
            ("code_items", "invented_column"),
        ] {
            let spec = ColumnSpec {
                relation,
                column,
                data_type: "UInt32",
                nullable: false,
                assembled_projection: true,
            };
            let occurrence = &scope.dexes()[0].dex_occurrence_id;
            let (state, reason, error) =
                ledger.column_state(occurrence, &spec, ColumnDomain::FrozenProjection);
            assert_eq!(state, Completeness::Unknown, "{relation}.{column}");
            assert_eq!(
                reason.as_deref(),
                Some("column_gate_rejected_required_scope"),
                "{relation}.{column}"
            );
            assert!(
                error.is_some(),
                "{relation}.{column} must carry the provider error"
            );
        }
    }

    /// A missing provider object is an explicit gap, never a silent `Complete`.
    #[test]
    fn missing_provider_object_is_unknown_not_complete() {
        let (snapshot, inventories) = fixture("references/generated/classic-035.dex", 1);
        let names = metadata(&snapshot, &inventories[0]);
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        // Metadata-only view: definitions-backed and code-backed columns are gaps.
        let view = FactView::unbuilt(&names.source().dex_occurrence_id).with_metadata(&names);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        for (relation, column) in [
            ("methods", "method_idx"),
            ("classes", "class_idx"),
            ("code_items", "code_off"),
        ] {
            assert_eq!(
                ledger
                    .evaluate(&column_request(&scope, relation, column))
                    .unwrap()
                    .facts,
                Completeness::Unknown,
                "{relation}.{column} without its provider object"
            );
        }
        // Metadata-only columns still resolve through their own provider.
        for (relation, column) in [("dex_files", "byte_len"), ("strings", "string_idx")] {
            assert_eq!(
                ledger
                    .evaluate(&column_request(&scope, relation, column))
                    .unwrap()
                    .facts,
                Completeness::Complete,
                "{relation}.{column} with its provider present"
            );
        }
    }

    /// A legal non-scalar UTF-16 value makes the plain-UTF-8 projections fail;
    /// coverage must not claim those columns are complete.
    #[test]
    fn non_scalar_text_columns_are_not_reported_complete() {
        let (snapshot, inventories) = fixture("references/generated/nonscalar-string-035.dex", 1);
        let names = metadata(&snapshot, &inventories[0]);
        let defs = DefinitionFacts::build(names.clone(), DefinitionLimits::default()).unwrap();
        assert!(
            names
                .strings()
                .iter()
                .any(|fact| fact.data.text.strict_utf8().is_err()),
            "fixture must contain a legal non-scalar string"
        );
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let view = FactView::unbuilt(&names.source().dex_occurrence_id).with_definitions(&defs);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        // The row projection itself is the ground truth for the gap.
        assert!(matches!(
            names.string_rows(0, 0).unwrap_err().code,
            ErrorCode::UnsupportedQuery
        ));
        let report = ledger
            .evaluate(&column_request(&scope, "strings", "value"))
            .unwrap();
        assert_eq!(report.facts, Completeness::Unknown);
        assert!(report.issues.iter().any(|issue| {
            issue.column.as_deref() == Some("strings.value")
                && issue.reason == "non_scalar_UTF16_cannot_be_plain_UTF8"
        }));
        assert!(report.require_complete().is_err());
        // A scalar-only column of the same relation is unaffected.
        assert_eq!(
            ledger
                .evaluate(&column_request(&scope, "strings", "string_idx"))
                .unwrap()
                .facts,
            Completeness::Complete
        );
    }

    /// `classes.source_file` uses the same plain-UTF-8 contract, so a non-scalar
    /// source file must report `Unknown` instead of `Complete`.
    #[test]
    fn non_scalar_class_source_file_is_not_reported_complete() {
        let (snapshot, inventories) =
            fixture("class_source_boundary/generated/surrogate-source.dex", 1);
        let names = metadata(&snapshot, &inventories[0]);
        let defs = DefinitionFacts::build(names.clone(), DefinitionLimits::default()).unwrap();
        assert!(
            defs.definitions().classes.iter().any(|class| class
                .source_file
                .as_ref()
                .is_some_and(|text| text.strict_utf8().is_err())),
            "fixture must carry a non-scalar source file name"
        );
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let view = FactView::unbuilt(&names.source().dex_occurrence_id).with_definitions(&defs);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        assert!(matches!(
            defs.class_rows(0).unwrap_err().code,
            ErrorCode::UnsupportedQuery
        ));
        let report = ledger
            .evaluate(&column_request(&scope, "classes", "source_file"))
            .unwrap();
        assert_eq!(report.facts, Completeness::Unknown);
        assert!(report.issues.iter().any(|issue| {
            issue.column.as_deref() == Some("classes.source_file")
                && issue.reason == "non_scalar_UTF16_cannot_be_plain_UTF8"
        }));
        // An absent source file is a genuine NULL, not a text-conversion gap.
        let (snapshot, inventories) = fixture("class_source_boundary/generated/null-source.dex", 1);
        let names = metadata(&snapshot, &inventories[0]);
        let defs = DefinitionFacts::build(names.clone(), DefinitionLimits::default()).unwrap();
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let view = FactView::unbuilt(&names.source().dex_occurrence_id).with_definitions(&defs);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        assert_eq!(
            ledger
                .evaluate(&column_request(&scope, "classes", "source_file"))
                .unwrap()
                .facts,
            Completeness::Complete
        );
    }

    /// The four reference relations keep their existing behaviour.
    #[test]
    fn reference_relations_keep_their_gate_behaviour() {
        let (snapshot, inventories) = fixture("references/generated/classic-035.dex", 1);
        let defs = definitions(&snapshot, &inventories[0]);
        let codes = code(&snapshot, &inventories[0]);
        let refs = crate::references::ReferenceFacts::build(
            defs,
            codes,
            crate::references::ReferenceLimits::default(),
        )
        .unwrap();
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let view = FactView::unbuilt(&refs.source().dex_occurrence_id).with_references(&refs);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        for (relation, column) in [
            ("method_strings", "method_idx"),
            ("method_calls", "callee_method_idx"),
            ("method_field_accesses", "field_idx"),
            ("method_used_types", "type_idx"),
        ] {
            let report = ledger
                .evaluate(&column_request(&scope, relation, column))
                .unwrap();
            assert_eq!(report.facts, Completeness::Complete, "{relation}.{column}");
        }
        // An unknown column still reports Unknown through the reference gate.
        let report = ledger
            .evaluate(&column_request(&scope, "method_calls", "invented_column"))
            .unwrap();
        assert_eq!(report.facts, Completeness::Unknown);
        // Without reference facts the provider is missing.
        let bare = FactView::unbuilt(&refs.source().dex_occurrence_id);
        let ledger = CoverageLedger::new(scope.clone(), &[bare]).unwrap();
        assert_eq!(
            ledger
                .evaluate(&column_request(&scope, "method_strings", "method_idx"))
                .unwrap()
                .facts,
            Completeness::Unknown
        );
    }

    /// `code_items` needs a complete code layout, not just a present code leaf.
    #[test]
    fn code_items_requires_complete_code_layout() {
        let (snapshot, inventories) = fixture("references/generated/classic-035.dex", 1);
        let names = metadata(&snapshot, &inventories[0]);
        let defs = DefinitionFacts::build(names.clone(), DefinitionLimits::default()).unwrap();
        let projected =
            CodeFacts::build_offsets(&snapshot, &inventories[0], 0, &[], CodeLimits::default())
                .unwrap();
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let view = FactView::unbuilt(&names.source().dex_occurrence_id)
            .with_definitions(&defs)
            .with_code(&projected);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        // The scoped projection omits real bodies, so code_items cannot be complete.
        let report = ledger
            .evaluate(&column_request(&scope, "code_items", "code_off"))
            .unwrap();
        assert_ne!(report.facts, Completeness::Complete);
        assert!(report.require_complete().is_err());
        // The build-free column gate still rejects unknown names and accepts the
        // provider's own assembled column set.
        assert_eq!(
            require_code_item_columns(&["invented_column"])
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert!(require_code_item_columns(crate::code::CodeItemRow::COLUMNS).is_ok());
        assert!(require_code_item_columns(&["*"]).is_ok());
    }

    /// Every frozen column of the seven former fallback relations is gated by
    /// its own provider: a known column passes and an invented column is
    /// rejected with the provider's own error, never an unconditional `Ok`.
    ///
    /// `class_*` relations consult `DefinitionFacts`; the four annotation
    /// relations consult `AnnotationFacts`, so the assertion also pins which
    /// fact object owns each projection.
    #[test]
    fn seven_fallback_relations_are_gated_by_their_own_provider() {
        let (snapshot, inventories) = fixture("annotations/generated/annotations-038.dex", 1);
        let definitions = definitions(&snapshot, &inventories[0]);
        let annotations = crate::annotations::AnnotationFacts::build(
            definitions.clone(),
            mdd_dex::annotations::AnnotationLimits::default(),
        )
        .unwrap();
        let view = FactView::unbuilt(&annotations.source().dex_occurrence_id)
            .with_annotations(&annotations);
        // Each relation: (accepted column, owning provider).
        let cases: [(&str, &str, &str); 7] = [
            ("class_interfaces", "interface_descriptor", "definitions"),
            ("class_fields", "field_name", "definitions"),
            ("class_methods", "method_descriptor", "definitions"),
            (
                "annotation_directory_entries",
                "annotation_set_off",
                "annotations",
            ),
            ("annotation_set_entries", "annotation_off", "annotations"),
            ("annotations", "visibility", "annotations"),
            ("annotation_elements", "value_kind", "annotations"),
        ];
        for (relation, column, provider) in cases {
            let accepted = ColumnSpec {
                relation,
                column,
                data_type: "UInt32",
                nullable: false,
                assembled_projection: true,
            };
            assert!(
                matches!(
                    CoverageLedger::frozen_provider_gate(&view, &accepted),
                    Some(Some(Ok(())))
                ),
                "{relation}.{column} must be accepted by its {provider} gate"
            );
            let unknown = ColumnSpec {
                column: "invented_column",
                ..accepted
            };
            assert!(
                matches!(
                    CoverageLedger::frozen_provider_gate(&view, &unknown),
                    Some(Some(Err(ref error))) if error.code == ErrorCode::InvalidArgument
                ),
                "{relation} must reject an unknown column through its {provider} gate"
            );
            // A view that does not carry the owning provider must report the gap
            // instead of borrowing columns from a fact object it lacks.
            let other = FactView::unbuilt(&annotations.source().dex_occurrence_id);
            assert!(
                matches!(
                    CoverageLedger::frozen_provider_gate(&other, &accepted),
                    Some(None)
                ),
                "{relation} without its {provider} provider must be an explicit gap"
            );
        }
        // Every relation in the frozen schema now either has a provider gate or
        // is one of the four inline-gated reference relations. No relation may
        // reach the unconditional fallback that used to answer `Complete`.
        let ungated = column_specs()
            .iter()
            .map(|spec| spec.relation)
            .filter(|relation| {
                !matches!(
                    *relation,
                    "method_strings"
                        | "method_calls"
                        | "method_field_accesses"
                        | "method_used_types"
                )
            })
            .filter(|relation| {
                let spec = ColumnSpec {
                    relation,
                    column: "*",
                    data_type: "UInt32",
                    nullable: false,
                    assembled_projection: true,
                };
                CoverageLedger::frozen_provider_gate(&view, &spec).is_none()
            })
            .collect::<BTreeSet<_>>();
        assert!(
            ungated.is_empty(),
            "relations with no provider gate: {ungated:?}"
        );
    }

    /// A relation the provider refuses must reach the caller as `Unknown`
    /// carrying the provider's own error, and a missing provider object must
    /// be an explicit gap — both through the public `evaluate` path.
    #[test]
    fn seven_fallback_relations_reject_and_report_gap_through_evaluate() {
        let (snapshot, inventories) = fixture("annotations/generated/annotations-038.dex", 1);
        let definitions = definitions(&snapshot, &inventories[0]);
        let annotations = crate::annotations::AnnotationFacts::build(
            definitions.clone(),
            mdd_dex::annotations::AnnotationLimits::default(),
        )
        .unwrap();
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let occurrence = annotations.source().dex_occurrence_id.clone();
        let view = FactView::unbuilt(&occurrence).with_annotations(&annotations);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        for (relation, column) in [
            ("class_interfaces", "invented_column"),
            ("class_fields", "invented_column"),
            ("class_methods", "invented_column"),
            ("annotation_directory_entries", "invented_column"),
            ("annotation_set_entries", "invented_column"),
            ("annotations", "invented_column"),
            ("annotation_elements", "invented_column"),
        ] {
            let spec = ColumnSpec {
                relation,
                column,
                data_type: "UInt32",
                nullable: false,
                assembled_projection: true,
            };
            let (state, reason, error) =
                ledger.column_state(&occurrence, &spec, ColumnDomain::FrozenProjection);
            assert_eq!(state, Completeness::Unknown, "{relation}.{column}");
            assert_eq!(
                reason.as_deref(),
                Some("column_gate_rejected_required_scope"),
                "{relation}.{column}"
            );
            assert!(
                error.is_some_and(|error| error.code == ErrorCode::InvalidArgument),
                "{relation}.{column} must carry the provider's InvalidArgument"
            );
        }
        // A missing provider object never reaches the column gate through
        // `evaluate`: the owning fact layer is already `Unknown`, and
        // `layer_state` answers first. That precedence is asserted here so the
        // column gate cannot be mistaken for the only guard against a missing
        // provider — both arms report `Unknown`, never `Complete`.
        let bare = FactView::unbuilt(&occurrence);
        let ledger = CoverageLedger::new(scope.clone(), &[bare]).unwrap();
        for (relation, column) in [
            ("class_interfaces", "interface_descriptor"),
            ("class_fields", "field_name"),
            ("class_methods", "method_descriptor"),
            ("annotation_directory_entries", "annotation_set_off"),
            ("annotation_set_entries", "annotation_off"),
            ("annotations", "visibility"),
            ("annotation_elements", "value_kind"),
        ] {
            let spec = ColumnSpec {
                relation,
                column,
                data_type: "UInt32",
                nullable: false,
                assembled_projection: true,
            };
            let (state, reason, error) =
                ledger.column_state(&occurrence, &spec, ColumnDomain::FrozenProjection);
            assert_eq!(state, Completeness::Unknown, "{relation}.{column}");
            assert_eq!(
                reason.as_deref(),
                Some("required_fact_scope_not_built"),
                "{relation}.{column}"
            );
            assert!(error.is_none(), "{relation}.{column} has no provider error");
        }
    }

    /// `CoverageRequest::for_scope` still requires no columns (layer-only
    /// semantics are unchanged), while `for_relations` fills them from the
    /// frozen schema and requires the owning fact layers.
    #[test]
    fn relation_request_fills_columns_and_scope_request_stays_layer_only() {
        let (snapshot, inventories) = fixture("annotations/generated/annotations-038.dex", 1);
        let definitions = definitions(&snapshot, &inventories[0]);
        let annotations = crate::annotations::AnnotationFacts::build(
            definitions.clone(),
            mdd_dex::annotations::AnnotationLimits::default(),
        )
        .unwrap();
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let view = FactView::unbuilt(&annotations.source().dex_occurrence_id)
            .with_annotations(&annotations);

        // `for_scope` is unchanged: layers only, no column claims.
        let layer_only = CoverageRequest::for_scope(&scope, &[FactLayer::Annotations]);
        assert!(layer_only.required_columns.is_empty());

        let request = CoverageRequest::for_relations(
            &scope,
            &[
                "class_interfaces",
                "class_fields",
                "class_methods",
                "annotation_directory_entries",
                "annotation_set_entries",
                "annotations",
                "annotation_elements",
            ],
        )
        .unwrap();
        let expected_columns = column_specs()
            .iter()
            .filter(|spec| {
                matches!(
                    spec.relation,
                    "class_interfaces"
                        | "class_fields"
                        | "class_methods"
                        | "annotation_directory_entries"
                        | "annotation_set_entries"
                        | "annotations"
                        | "annotation_elements"
                )
            })
            .count();
        assert_eq!(request.required_columns.len(), expected_columns);
        assert!(
            request
                .required_columns
                .iter()
                .all(|column| column.domain == ColumnDomain::FrozenProjection),
            "relation coverage must stay in the frozen projection domain"
        );
        assert!(
            request.required_layers.contains(&FactLayer::Definitions)
                && request.required_layers.contains(&FactLayer::Annotations),
            "the relation request must require the layers that own the columns: {:?}",
            request.required_layers
        );
        // An unknown relation is rejected rather than silently matching nothing.
        assert_eq!(
            CoverageRequest::for_relations(&scope, &["invented_relation"])
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );

        // The production path reaches the same verdicts as the direct ledger
        // call: the seven relations are Complete only because their providers
        // accept, and an unbuilt provider is Unknown.
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        let report = ledger.evaluate(&request).unwrap();
        assert_eq!(
            report.facts,
            Completeness::Complete,
            "every gated column must be complete here: {:?}",
            report.issues
        );
        assert!(report.require_complete().is_ok());
        assert!(report.required_layers.contains(&FactLayer::Annotations));

        // Dropping the annotation provider turns the four annotation relations
        // into gaps. The `Annotations` layer answers first with
        // `required_fact_scope_not_built`, and every annotation column follows;
        // the three class relations stay complete because their provider and
        // layer are untouched.
        let definitions_only = FactView::unbuilt(&annotations.source().dex_occurrence_id)
            .with_definitions(&definitions);
        let ledger = CoverageLedger::new(scope.clone(), &[definitions_only]).unwrap();
        let report = ledger.evaluate(&request).unwrap();
        assert_eq!(report.facts, Completeness::Unknown);
        assert_eq!(
            report
                .issues
                .iter()
                .filter(|issue| issue.reason == "required_fact_scope_not_built")
                .filter(|issue| issue.layer == "Annotations")
                .count(),
            1,
            "the missing annotation layer must be reported once: {:?}",
            report.issues
        );
        for relation in [
            "annotation_directory_entries",
            "annotation_set_entries",
            "annotations",
            "annotation_elements",
        ] {
            assert!(
                report.issues.iter().any(|issue| issue
                    .column
                    .as_deref()
                    .is_some_and(|column| column.starts_with(&format!("{relation}.")))),
                "{relation} must report a column issue: {:?}",
                report.issues
            );
        }
        for relation in ["class_interfaces", "class_fields", "class_methods"] {
            assert!(
                !report.issues.iter().any(|issue| issue
                    .column
                    .as_deref()
                    .is_some_and(|column| column.starts_with(&format!("{relation}.")))),
                "{relation} keeps its provider and must not report a column issue: {:?}",
                report.issues
            );
        }
        assert!(
            report.require_complete().is_err(),
            "an unbuilt annotation provider must not be reported complete"
        );
    }
}
