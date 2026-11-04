//! Scope-relative native fact coverage; projection readiness is an independent contract.
use crate::indexes::{ColumnSpec, FactView, SelectedScope, column_specs};
use crate::{raw_fingerprints::ResourceByteEvidence, references::ReferenceRelation};
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
    pub fn for_scope(scope: &SelectedScope, layers: &[FactLayer]) -> Self {
        Self {
            scope_id: scope.scope_id().into(),
            input: InputNeed::ValidatedStandardDex,
            required_layers: layers.to_vec(),
            required_columns: Vec::new(),
            required_resource_members: Vec::new(),
        }
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
        match spec.relation {
            "dex_files" | "strings" | "types" => vec![FactLayer::Metadata],
            "methods" if matches!(spec.column, "opcode_count" | "opcode_hex") => vec![
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
            if spec.relation == "dex_files"
                && spec.column == "source_path"
                && self
                    .scope
                    .inputs()
                    .iter()
                    .any(|input| input.origin_display.is_none())
            {
                return (
                    Completeness::Unknown,
                    Some("lossless_source_path_representation_unavailable".into()),
                    None,
                );
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
        let Some(view) = self.views.get(occurrence) else {
            return (
                Completeness::Unknown,
                Some("column_source_not_built".into()),
                None,
            );
        };
        if spec.relation == "method_strings"
            && spec.column == "value"
            && let Some(references) = view.references
        {
            for site in references
                .sites()
                .iter()
                .filter(|site| site.target_kind == crate::references::TargetKind::String)
            {
                if references.definitions().metadata().strings()[site.target_local_index as usize]
                    .data
                    .text
                    .strict_utf8()
                    .is_err()
                {
                    return (
                        Completeness::Unknown,
                        Some("non_scalar_UTF16_cannot_be_plain_UTF8".into()),
                        None,
                    );
                }
            }
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
            _ => Some(Ok(())),
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
