//! Snapshot/selected-scope candidate indexes; every candidate is exactly rechecked.
mod columns;
pub mod lazy;
mod scope;
#[cfg(test)]
mod tests;
mod views;
use crate::{
    coverage::{CoverageLedger, CoverageReport, CoverageRequest, FactLayer},
    metadata::{EntityKind, EntityRef},
    references::{
        FieldSymbol, MethodSymbol, ReferenceFacts, ReferenceMatches, ReferenceTargetId, TargetKind,
    },
};
use lazy::{IndexAudit, LazyIndex};
use mdd_dex::annotations::{EncodedKind, MethodHandleTarget};
use mdd_types::{ErrorCode, MddError, MddResult};
pub use scope::{SelectedDex, SelectedInput, SelectedScope};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};
pub use views::FactView;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ColumnSpec {
    pub relation: &'static str,
    pub column: &'static str,
    pub data_type: &'static str,
    pub nullable: bool,
    pub assembled_projection: bool,
}
pub fn column_specs() -> &'static [ColumnSpec] {
    columns::COLUMNS
}
#[derive(Clone, Copy, Debug)]
pub struct IndexLimits {
    pub max_entries: u64,
    pub max_index_bytes: u64,
    pub max_result_entries: u64,
    pub max_result_bytes: u64,
    pub max_build_attempts: u64,
    pub build_duration: Option<Duration>,
}
impl Default for IndexLimits {
    fn default() -> Self {
        Self {
            max_entries: 8_000_000,
            max_index_bytes: 512 * 1024 * 1024,
            max_result_entries: 1_000_000,
            max_result_bytes: 256 * 1024 * 1024,
            max_build_attempts: 32,
            build_duration: None,
        }
    }
}
struct Budget {
    limits: IndexLimits,
    entries: u64,
    bytes: u64,
    started: Instant,
}
impl Budget {
    fn new(limits: IndexLimits) -> Self {
        Self {
            limits,
            entries: 0,
            bytes: 0,
            started: Instant::now(),
        }
    }
    fn charge(&mut self, entries: u64, bytes: u64) -> MddResult<()> {
        if self
            .limits
            .build_duration
            .is_some_and(|duration| self.started.elapsed() >= duration)
        {
            return Err(MddError::new(
                ErrorCode::DeadlineExceeded,
                "facts.index_build",
                "index build deadline reached",
            )
            .detail("budget", "index_build_duration"));
        }
        self.entries = self
            .entries
            .checked_add(entries)
            .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| quota("INDEX_BYTE_BUDGET"))?;
        if self.entries > self.limits.max_entries {
            return Err(quota("INDEX_ENTRY_BUDGET"));
        }
        if self.bytes > self.limits.max_index_bytes {
            return Err(quota("INDEX_BYTE_BUDGET"));
        }
        Ok(())
    }
}
fn quota(reason: &str) -> MddError {
    MddError::new(ErrorCode::QuotaExceeded, "facts.index", reason).detail("reason", reason)
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Utf16Predicate {
    Any,
    Equal(Vec<u16>),
    Prefix(Vec<u16>),
    Contains(Vec<u16>),
}
impl Utf16Predicate {
    pub fn matches(&self, value: &[u16]) -> bool {
        match self {
            Self::Any => true,
            Self::Equal(expected) => value == expected,
            Self::Prefix(prefix) => value.starts_with(prefix),
            Self::Contains(needle) => {
                needle.is_empty() || value.windows(needle.len()).any(|part| part == needle)
            }
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefinitionKind {
    Class,
    Field,
    Method,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Atom {
    view: u32,
    local: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct DefinitionAtom {
    view: u32,
    kind: DefinitionKind,
    local: u32,
}
#[derive(Clone, Copy, Debug)]
struct ReferenceAtom {
    view: u32,
    local: u32,
}
struct StringIndex {
    all: Vec<Atom>,
    utf16: BTreeMap<Vec<u16>, Vec<Atom>>,
    raw: BTreeMap<Vec<u8>, Vec<Atom>>,
    units: BTreeMap<u16, Vec<Atom>>,
}
struct DefinitionIndex {
    names: BTreeMap<(DefinitionKind, Vec<u16>), Vec<DefinitionAtom>>,
    owners: BTreeMap<(u32, u32, DefinitionKind), Vec<DefinitionAtom>>,
    all: Vec<DefinitionAtom>,
}
struct ReferenceSymbolIndex {
    methods: BTreeMap<MethodSymbol, Vec<ReferenceAtom>>,
}
struct FieldReferenceSymbolIndex {
    fields: BTreeMap<FieldSymbol, Vec<ReferenceAtom>>,
}
struct TypeReferenceIndex {
    descriptors: BTreeMap<String, Vec<Atom>>,
}
struct PrototypeReferenceIndex {
    descriptors: BTreeMap<String, Vec<Atom>>,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(tag = "target_kind", rename_all = "snake_case")]
pub enum MethodHandleSymbol {
    Field {
        handle_kind: u16,
        target: FieldSymbol,
    },
    Method {
        handle_kind: u16,
        target: MethodSymbol,
    },
}
/// Exact bytes of one validated call-site array, bound to its complete DEX content.
/// This key deliberately does not assert semantic equality between different DEX files.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CallSiteEncodedKey {
    snapshot_id: String,
    dex_content_id: String,
    encoded_array: Vec<u8>,
}
impl CallSiteEncodedKey {
    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }
    pub fn dex_content_id(&self) -> &str {
        &self.dex_content_id
    }
    pub fn encoded_array(&self) -> &[u8] {
        &self.encoded_array
    }
}
struct MethodHandleIndex {
    symbols: BTreeMap<MethodHandleSymbol, Vec<Atom>>,
}
struct CallerSiteIndex {
    sites: BTreeMap<Atom, Vec<u32>>,
}
enum HandleTargetRef<'a> {
    Field {
        kind: u16,
        owner: &'a str,
        name: &'a str,
        field_type: &'a str,
    },
    Method {
        kind: u16,
        owner: &'a str,
        name: &'a str,
        prototype: &'a str,
    },
}
impl HandleTargetRef<'_> {
    fn bytes(&self) -> MddResult<u64> {
        let (owner, name, signature) = match self {
            Self::Field {
                owner,
                name,
                field_type,
                ..
            } => (*owner, *name, *field_type),
            Self::Method {
                owner,
                name,
                prototype,
                ..
            } => (*owner, *name, *prototype),
        };
        owner
            .len()
            .checked_add(name.len())
            .and_then(|n| n.checked_add(signature.len()))
            .and_then(|n| n.checked_add(80))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(|| quota("INDEX_BYTE_BUDGET"))
    }
    fn owned(&self) -> MethodHandleSymbol {
        match self {
            Self::Field {
                kind,
                owner,
                name,
                field_type,
            } => MethodHandleSymbol::Field {
                handle_kind: *kind,
                target: FieldSymbol {
                    owner: (*owner).into(),
                    name: (*name).into(),
                    field_type: (*field_type).into(),
                },
            },
            Self::Method {
                kind,
                owner,
                name,
                prototype,
            } => MethodHandleSymbol::Method {
                handle_kind: *kind,
                target: MethodSymbol {
                    owner: (*owner).into(),
                    name: (*name).into(),
                    prototype: (*prototype).into(),
                },
            },
        }
    }
    fn matches(&self, other: &MethodHandleSymbol) -> bool {
        match (self, other) {
            (
                Self::Field {
                    kind,
                    owner,
                    name,
                    field_type,
                },
                MethodHandleSymbol::Field {
                    handle_kind,
                    target,
                },
            ) => {
                kind == handle_kind
                    && *owner == target.owner
                    && *name == target.name
                    && *field_type == target.field_type
            }
            (
                Self::Method {
                    kind,
                    owner,
                    name,
                    prototype,
                },
                MethodHandleSymbol::Method {
                    handle_kind,
                    target,
                },
            ) => {
                kind == handle_kind
                    && *owner == target.owner
                    && *name == target.name
                    && *prototype == target.prototype
            }
            _ => false,
        }
    }
}
fn handle_target<'a>(
    facts: &'a ReferenceFacts,
    handle: &MethodHandleTarget,
) -> MddResult<HandleTargetRef<'a>> {
    let definitions = facts.definitions().definitions();
    let malformed = || {
        MddError::new(
            ErrorCode::InternalFault,
            "facts.index",
            "validated method handle target missing or inconsistent",
        )
    };
    match handle.target_kind {
        EncodedKind::Field if handle.handle_kind <= 3 => {
            let field = definitions
                .field_references
                .get(handle.target_index as usize)
                .ok_or_else(malformed)?;
            Ok(HandleTargetRef::Field {
                kind: handle.handle_kind,
                owner: &field.class_descriptor,
                name: &field.field_name,
                field_type: &field.type_descriptor,
            })
        }
        EncodedKind::Method if (4..=8).contains(&handle.handle_kind) => {
            let method = definitions
                .method_references
                .get(handle.target_index as usize)
                .ok_or_else(malformed)?;
            let proto = facts
                .definitions()
                .metadata()
                .prototypes()
                .get(method.proto_idx as usize)
                .ok_or_else(malformed)?;
            Ok(HandleTargetRef::Method {
                kind: handle.handle_kind,
                owner: &method.class_descriptor,
                name: &method.method_name,
                prototype: &proto.data.descriptor,
            })
        }
        _ => Err(malformed()),
    }
}
fn handle_metadata(facts: &ReferenceFacts) -> MddResult<&[MethodHandleTarget]> {
    if let Some(handles) = facts.method_handle_metadata() {
        return Ok(handles);
    }
    if facts
        .sites()
        .iter()
        .any(|site| site.target_kind == TargetKind::MethodHandle)
    {
        return Err(MddError::new(
            ErrorCode::IncompleteFacts,
            "facts.index",
            "method handle operands lack metadata",
        ));
    }
    Ok(&[])
}
fn call_site_array_bytes(facts: &ReferenceFacts, local: u32) -> MddResult<&[u8]> {
    let missing = || {
        MddError::new(
            ErrorCode::IncompleteFacts,
            "facts.index",
            "call-site encoded arrays are not built",
        )
    };
    let broken = || {
        MddError::new(
            ErrorCode::InternalFault,
            "facts.index",
            "validated call-site encoded array is inconsistent",
        )
    };
    let section = facts.call_site_metadata().ok_or_else(missing)?;
    let binding = section
        .call_site_arrays
        .get(local as usize)
        .filter(|v| v.call_site_idx == local)
        .ok_or_else(broken)?;
    let array = section
        .arrays
        .get(binding.encoded_array_index as usize)
        .ok_or_else(broken)?;
    if array.byte_offset != binding.encoded_array_byte_offset
        || array.encoded_range.byte_offset.0 != u64::from(array.byte_offset)
        || array.elements.len() < 3
    {
        return Err(broken());
    }
    let start = usize::try_from(array.encoded_range.byte_offset.0).map_err(|_| broken())?;
    let length = usize::try_from(array.encoded_range.byte_length.0).map_err(|_| broken())?;
    let end = start.checked_add(length).ok_or_else(broken)?;
    facts
        .definitions()
        .bytes()
        .get(start..end)
        .ok_or_else(broken)
}
#[derive(Clone, Copy)]
enum ReferenceResultKind {
    Method,
    Field,
    String,
    Type,
    Prototype,
    MethodHandle,
    CallSiteBytes,
    Caller,
}
#[derive(Clone, Debug, Serialize)]
pub struct IndexMatches {
    pub scope_id: String,
    pub snapshot_id: String,
    pub index_attempt: Option<IndexAudit>,
    pub access_path: String,
    pub candidate_count: u64,
    pub exact_match_count: u64,
    pub entities: Vec<EntityRef>,
    pub absence_proven_within_selected_scope: bool,
    pub covers_all_captured_sources: bool,
    pub coverage: CoverageReport,
}
#[derive(Clone, Debug, Serialize)]
pub struct ReferenceIndexMatches {
    pub snapshot_id: String,
    pub scope_id: String,
    pub index_attempt: Option<IndexAudit>,
    pub access_path: String,
    pub candidate_reference_count: u64,
    pub sites: Vec<crate::references::ReferenceSiteId>,
    pub absence_proven_within_selected_encoded_scope: bool,
    pub covers_all_captured_sources: bool,
    pub runtime_resolution: &'static str,
    pub coverage: CoverageReport,
}
pub struct SnapshotFactIndex<'a> {
    scope: SelectedScope,
    views: Vec<FactView<'a>>,
    by_occurrence: BTreeMap<String, u32>,
    ledger: CoverageLedger<'a>,
    limits: IndexLimits,
    strings: LazyIndex<StringIndex>,
    definitions: LazyIndex<DefinitionIndex>,
    reference_symbols: LazyIndex<ReferenceSymbolIndex>,
    field_reference_symbols: LazyIndex<FieldReferenceSymbolIndex>,
    type_references: LazyIndex<TypeReferenceIndex>,
    prototype_references: LazyIndex<PrototypeReferenceIndex>,
    method_handles: LazyIndex<MethodHandleIndex>,
    caller_sites: LazyIndex<CallerSiteIndex>,
}

impl<'a> SnapshotFactIndex<'a> {
    pub fn new(
        scope: SelectedScope,
        views: &[FactView<'a>],
        limits: IndexLimits,
    ) -> MddResult<Self> {
        let ledger = CoverageLedger::new(scope.clone(), views)?;
        let mut ordered = Vec::new();
        let mut by_occurrence = BTreeMap::new();
        for dex in scope.dexes() {
            if let Some(view) = views
                .iter()
                .find(|view| view.occurrence() == dex.dex_occurrence_id)
            {
                view.validate(&scope)?;
                by_occurrence.insert(dex.dex_occurrence_id.clone(), ordered.len() as u32);
                ordered.push(view.clone());
            }
        }
        Ok(Self {
            strings: LazyIndex::new(
                scope.scope_id(),
                "strings-utf16-raw-candidates-v1",
                limits.max_build_attempts,
            )?,
            definitions: LazyIndex::new(
                scope.scope_id(),
                "definitions-owner-candidates-v1",
                limits.max_build_attempts,
            )?,
            reference_symbols: LazyIndex::new(
                scope.scope_id(),
                "encoded-reference-symbol-candidates-v1",
                limits.max_build_attempts,
            )?,
            field_reference_symbols: LazyIndex::new(
                scope.scope_id(),
                "encoded-field-reference-symbol-candidates-v1",
                limits.max_build_attempts,
            )?,
            type_references: LazyIndex::new(
                scope.scope_id(),
                "encoded-type-reference-descriptor-candidates-v1",
                limits.max_build_attempts,
            )?,
            prototype_references: LazyIndex::new(
                scope.scope_id(),
                "encoded-prototype-reference-descriptor-candidates-v1",
                limits.max_build_attempts,
            )?,
            method_handles: LazyIndex::new(
                scope.scope_id(),
                "encoded-method-handle-symbol-candidates-v1",
                limits.max_build_attempts,
            )?,
            caller_sites: LazyIndex::new(
                scope.scope_id(),
                "encoded-caller-site-candidates-v1",
                limits.max_build_attempts,
            )?,
            scope,
            views: ordered,
            by_occurrence,
            ledger,
            limits,
        })
    }
    pub fn scope(&self) -> &SelectedScope {
        &self.scope
    }
    pub fn coverage(&self, request: &CoverageRequest) -> MddResult<CoverageReport> {
        self.ledger.evaluate(request)
    }
    pub fn audits(&self) -> MddResult<Vec<IndexAudit>> {
        Ok(vec![
            self.strings.audit()?,
            self.definitions.audit()?,
            self.reference_symbols.audit()?,
            self.field_reference_symbols.audit()?,
            self.type_references.audit()?,
            self.prototype_references.audit()?,
            self.method_handles.audit()?,
            self.caller_sites.audit()?,
        ])
    }
    fn require(&self, layer: FactLayer) -> MddResult<CoverageReport> {
        let report = self
            .ledger
            .evaluate(&CoverageRequest::for_scope(&self.scope, &[layer]))?;
        report.require_complete()?;
        Ok(report)
    }
    fn metadata(&self, view: u32) -> MddResult<&crate::MetadataFacts> {
        self.views
            .get(view as usize)
            .and_then(|view| view.metadata)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "metadata not built",
                )
            })
    }
    fn definition_facts(&self, view: u32) -> MddResult<&crate::definitions::DefinitionFacts> {
        self.views
            .get(view as usize)
            .and_then(|view| view.definitions)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "definitions not built",
                )
            })
    }
    fn string_entity(&self, atom: Atom) -> MddResult<EntityRef> {
        self.metadata(atom.view)?
            .entity(EntityKind::String, atom.local)
    }
    fn definition_entity(&self, atom: DefinitionAtom) -> MddResult<EntityRef> {
        self.definition_facts(atom.view)?.entity(
            match atom.kind {
                DefinitionKind::Class => EntityKind::ClassDefinition,
                DefinitionKind::Field => EntityKind::FieldDefinition,
                DefinitionKind::Method => EntityKind::MethodDefinition,
            },
            atom.local,
        )
    }
    fn result(
        &self,
        mut entities: Vec<EntityRef>,
        candidates: usize,
        path: &str,
        audit: Option<IndexAudit>,
        coverage: CoverageReport,
    ) -> MddResult<IndexMatches> {
        let bytes = entities
            .iter()
            .try_fold(0u64, |sum, entity| {
                sum.checked_add(
                    (entity.snapshot_id.len()
                        + entity.dex_occurrence_id.len()
                        + std::mem::size_of::<EntityRef>()) as u64,
                )
            })
            .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
        if entities.len() as u64 > self.limits.max_result_entries
            || bytes > self.limits.max_result_bytes
        {
            return Err(quota("INDEX_RESULT_BUDGET"));
        }
        entities.sort_by_key(|entity| {
            (
                self.by_occurrence[&entity.dex_occurrence_id],
                entity.local_index,
            )
        });
        Ok(IndexMatches {
            scope_id: self.scope.scope_id().into(),
            snapshot_id: self.scope.snapshot_id().into(),
            index_attempt: audit,
            access_path: path.into(),
            candidate_count: candidates as u64,
            exact_match_count: entities.len() as u64,
            absence_proven_within_selected_scope: entities.is_empty()
                && coverage.input == mdd_types::Completeness::Complete
                && coverage.facts == mdd_types::Completeness::Complete,
            covers_all_captured_sources: self.scope.covers_all_captured_sources(),
            entities,
            coverage,
        })
    }
    fn check_predicate(predicate: &Utf16Predicate) -> MddResult<()> {
        let length = match predicate {
            Utf16Predicate::Any => 0,
            Utf16Predicate::Equal(v) | Utf16Predicate::Prefix(v) | Utf16Predicate::Contains(v) => {
                v.len()
            }
        };
        if length > 1_000_000 {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        Ok(())
    }
    fn append_entity(
        &self,
        result: &mut Vec<EntityRef>,
        bytes: &mut u64,
        view: u32,
        make: impl FnOnce() -> MddResult<EntityRef>,
    ) -> MddResult<()> {
        let cost = (self.scope.snapshot_id().len()
            + self.views[view as usize].occurrence().len()
            + std::mem::size_of::<EntityRef>()) as u64;
        *bytes = bytes
            .checked_add(cost)
            .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
        if result.len() as u64 >= self.limits.max_result_entries
            || *bytes > self.limits.max_result_bytes
        {
            return Err(quota("INDEX_RESULT_BUDGET"));
        }
        result
            .try_reserve(1)
            .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
        result.push(make()?);
        Ok(())
    }
    fn build_strings(&self) -> MddResult<StringIndex> {
        self.require(FactLayer::Metadata)?;
        let mut index = StringIndex {
            all: Vec::new(),
            utf16: BTreeMap::new(),
            raw: BTreeMap::new(),
            units: BTreeMap::new(),
        };
        let mut budget = Budget::new(self.limits);
        budget.charge(0, 0)?;
        for (view_id, view) in self.views.iter().enumerate() {
            let metadata = view.metadata.ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "metadata missing",
                )
            })?;
            for string in metadata.strings() {
                let atom = Atom {
                    view: view_id as u32,
                    local: string.data.string_idx,
                };
                budget.charge(1, 16)?;
                index.all.push(atom);
                if !index.utf16.contains_key(&string.data.text.utf16_units) {
                    budget.charge(0, string.data.text.utf16_units.len() as u64 * 2 + 64)?;
                }
                index
                    .utf16
                    .entry(string.data.text.utf16_units.clone())
                    .or_default()
                    .push(atom);
                budget.charge(1, 8)?;
                if !index.raw.contains_key(&string.data.text.raw_mutf8) {
                    budget.charge(0, string.data.text.raw_mutf8.len() as u64 + 64)?;
                }
                index
                    .raw
                    .entry(string.data.text.raw_mutf8.clone())
                    .or_default()
                    .push(atom);
                budget.charge(1, 8)?;
                for unit in string
                    .data
                    .text
                    .utf16_units
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>()
                {
                    budget.charge(1, 8)?;
                    index.units.entry(unit).or_default().push(atom);
                }
            }
        }
        Ok(index)
    }
    fn string_candidates<'b>(
        index: &'b StringIndex,
        predicate: &'b Utf16Predicate,
    ) -> Box<dyn Iterator<Item = Atom> + 'b> {
        match predicate {
            Utf16Predicate::Any => Box::new(index.all.iter().copied()),
            Utf16Predicate::Equal(value) => {
                Box::new(index.utf16.get(value).into_iter().flatten().copied())
            }
            Utf16Predicate::Prefix(prefix) => Box::new(
                index
                    .utf16
                    .range(prefix.clone()..)
                    .take_while(|(key, _)| key.starts_with(prefix))
                    .flat_map(|(_, values)| values.iter().copied()),
            ),
            Utf16Predicate::Contains(value) => match value.first() {
                None => Box::new(index.all.iter().copied()),
                Some(unit) => Box::new(index.units.get(unit).into_iter().flatten().copied()),
            },
        }
    }
    pub fn strings_indexed(&self, predicate: &Utf16Predicate) -> MddResult<IndexMatches> {
        Self::check_predicate(predicate)?;
        let coverage = self.require(FactLayer::Metadata)?;
        let index = self.strings.get_or_build(|| self.build_strings())?;
        let candidates = Self::string_candidates(&index, predicate);
        let mut entities = Vec::new();
        let mut result_bytes = 0;
        let mut candidate_count = 0;
        for atom in candidates {
            candidate_count += 1;
            let text = &self.metadata(atom.view)?.strings()[atom.local as usize]
                .data
                .text;
            if predicate.matches(&text.utf16_units) {
                self.append_entity(&mut entities, &mut result_bytes, atom.view, || {
                    self.string_entity(atom)
                })?;
            }
        }
        self.result(
            entities,
            candidate_count,
            "utf16_candidate_then_exact_residual",
            Some(self.strings.audit()?),
            coverage,
        )
    }
    pub fn strings_scalar(&self, predicate: &Utf16Predicate) -> MddResult<IndexMatches> {
        Self::check_predicate(predicate)?;
        let coverage = self.require(FactLayer::Metadata)?;
        let mut entities = Vec::new();
        let mut candidates = 0;
        let mut result_bytes = 0;
        for (view, entry) in self.views.iter().enumerate() {
            for string in entry
                .metadata
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "metadata missing",
                    )
                })?
                .strings()
            {
                candidates += 1;
                if predicate.matches(&string.data.text.utf16_units) {
                    self.append_entity(&mut entities, &mut result_bytes, view as u32, || {
                        self.string_entity(Atom {
                            view: view as u32,
                            local: string.data.string_idx,
                        })
                    })?;
                }
            }
        }
        self.result(
            entities,
            candidates,
            "scalar_full_string_scan",
            None,
            coverage,
        )
    }
    pub fn strings_raw_mutf8(&self, raw: &[u8]) -> MddResult<IndexMatches> {
        if raw.len() > 16 * 1024 * 1024 {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let coverage = self.require(FactLayer::Metadata)?;
        let index = self.strings.get_or_build(|| self.build_strings())?;
        let candidates = index.raw.get(raw).map(Vec::as_slice).unwrap_or_default();
        let mut entities = Vec::new();
        let mut result_bytes = 0;
        for atom in candidates {
            if self.metadata(atom.view)?.strings()[atom.local as usize]
                .data
                .text
                .raw_mutf8
                == raw
            {
                self.append_entity(&mut entities, &mut result_bytes, atom.view, || {
                    self.string_entity(*atom)
                })?;
            }
        }
        self.result(
            entities,
            candidates.len(),
            "raw_mutf8_exact",
            Some(self.strings.audit()?),
            coverage,
        )
    }
    pub fn retry_string_index(&self) -> MddResult<IndexAudit> {
        self.strings.retry_failed(|| self.build_strings())?;
        self.strings.audit()
    }
    fn build_definitions(&self) -> MddResult<DefinitionIndex> {
        self.require(FactLayer::Definitions)?;
        let mut index = DefinitionIndex {
            names: BTreeMap::new(),
            owners: BTreeMap::new(),
            all: Vec::new(),
        };
        let mut budget = Budget::new(self.limits);
        budget.charge(0, 0)?;
        for (view_id, view) in self.views.iter().enumerate() {
            let facts = view.definitions.ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "definitions missing",
                )
            })?;
            let view = view_id as u32;
            for class in &facts.definitions().classes {
                let atom = DefinitionAtom {
                    view,
                    kind: DefinitionKind::Class,
                    local: class.class_def_idx,
                };
                let descriptor = class.descriptor.encode_utf16().collect::<Vec<_>>();
                budget.charge(1, descriptor.len() as u64 * 2 + 24)?;
                index
                    .names
                    .entry((DefinitionKind::Class, descriptor))
                    .or_default()
                    .push(atom);
                index.all.push(atom);
            }
            for field in &facts.definitions().field_definitions {
                let reference = &facts.definitions().field_references[field.field_idx as usize];
                let atom = DefinitionAtom {
                    view,
                    kind: DefinitionKind::Field,
                    local: field.field_idx,
                };
                let name = reference.field_name.encode_utf16().collect::<Vec<_>>();
                budget.charge(1, name.len() as u64 * 2 + 48)?;
                index
                    .names
                    .entry((DefinitionKind::Field, name))
                    .or_default()
                    .push(atom);
                index
                    .owners
                    .entry((view, field.class_def_idx, DefinitionKind::Field))
                    .or_default()
                    .push(atom);
                index.all.push(atom);
            }
            for method in &facts.definitions().method_definitions {
                let reference = &facts.definitions().method_references[method.method_idx as usize];
                let atom = DefinitionAtom {
                    view,
                    kind: DefinitionKind::Method,
                    local: method.method_idx,
                };
                let name = reference.method_name.encode_utf16().collect::<Vec<_>>();
                budget.charge(1, name.len() as u64 * 2 + 48)?;
                index
                    .names
                    .entry((DefinitionKind::Method, name))
                    .or_default()
                    .push(atom);
                index
                    .owners
                    .entry((view, method.class_def_idx, DefinitionKind::Method))
                    .or_default()
                    .push(atom);
                index.all.push(atom);
            }
        }
        Ok(index)
    }
    fn definition_name(&self, atom: DefinitionAtom) -> MddResult<Vec<u16>> {
        let facts = self.definition_facts(atom.view)?;
        Ok(match atom.kind {
            DefinitionKind::Class => facts.definitions().classes[atom.local as usize]
                .descriptor
                .encode_utf16()
                .collect(),
            DefinitionKind::Field => facts.definitions().field_references[atom.local as usize]
                .field_name
                .encode_utf16()
                .collect(),
            DefinitionKind::Method => facts.definitions().method_references[atom.local as usize]
                .method_name
                .encode_utf16()
                .collect(),
        })
    }
    pub fn definition_names(
        &self,
        kind: DefinitionKind,
        predicate: &Utf16Predicate,
    ) -> MddResult<IndexMatches> {
        Self::check_predicate(predicate)?;
        let coverage = self.require(FactLayer::Definitions)?;
        let index = self.definitions.get_or_build(|| self.build_definitions())?;
        let candidates: Box<dyn Iterator<Item = DefinitionAtom> + '_> = match predicate {
            Utf16Predicate::Equal(name) => Box::new(
                index
                    .names
                    .get(&(kind, name.clone()))
                    .into_iter()
                    .flatten()
                    .copied(),
            ),
            Utf16Predicate::Prefix(prefix) => Box::new(
                index
                    .names
                    .range((kind, prefix.clone())..)
                    .take_while(|((found, key), _)| *found == kind && key.starts_with(prefix))
                    .flat_map(|(_, values)| values.iter().copied()),
            ),
            _ => Box::new(index.all.iter().filter(|atom| atom.kind == kind).copied()),
        };
        let mut entities = Vec::new();
        let mut result_bytes = 0;
        let mut candidate_count = 0;
        for atom in candidates {
            candidate_count += 1;
            if predicate.matches(&self.definition_name(atom)?) {
                self.append_entity(&mut entities, &mut result_bytes, atom.view, || {
                    self.definition_entity(atom)
                })?;
            }
        }
        self.result(
            entities,
            candidate_count,
            "definition_name_candidates_then_exact",
            Some(self.definitions.audit()?),
            coverage,
        )
    }
    pub fn definition_names_scalar(
        &self,
        kind: DefinitionKind,
        predicate: &Utf16Predicate,
    ) -> MddResult<IndexMatches> {
        Self::check_predicate(predicate)?;
        let coverage = self.require(FactLayer::Definitions)?;
        let mut entities = Vec::new();
        let mut candidates = 0;
        let mut result_bytes = 0;
        for (view, entry) in self.views.iter().enumerate() {
            let facts = entry.definitions.ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "definitions missing",
                )
            })?;
            let locals = match kind {
                DefinitionKind::Class => facts
                    .definitions()
                    .classes
                    .iter()
                    .map(|item| item.class_def_idx)
                    .collect::<Vec<_>>(),
                DefinitionKind::Field => facts
                    .definitions()
                    .field_definitions
                    .iter()
                    .map(|item| item.field_idx)
                    .collect(),
                DefinitionKind::Method => facts
                    .definitions()
                    .method_definitions
                    .iter()
                    .map(|item| item.method_idx)
                    .collect(),
            };
            for local in locals {
                let atom = DefinitionAtom {
                    view: view as u32,
                    kind,
                    local,
                };
                candidates += 1;
                if predicate.matches(&self.definition_name(atom)?) {
                    self.append_entity(&mut entities, &mut result_bytes, atom.view, || {
                        self.definition_entity(atom)
                    })?;
                }
            }
        }
        self.result(
            entities,
            candidates,
            "scalar_full_definition_scan",
            None,
            coverage,
        )
    }
    pub fn owner_members(
        &self,
        owner: &EntityRef,
        kind: DefinitionKind,
        predicate: &Utf16Predicate,
    ) -> MddResult<IndexMatches> {
        Self::check_predicate(predicate)?;
        let coverage = self.require(FactLayer::Definitions)?;
        if owner.snapshot_id != self.scope.snapshot_id()
            || owner.kind != EntityKind::ClassDefinition
            || kind == DefinitionKind::Class
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "owner must be a class definition in this scope and member kind field/method",
            ));
        }
        let view = *self
            .by_occurrence
            .get(&owner.dex_occurrence_id)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.index",
                    "owner occurrence outside selection",
                )
            })?;
        self.definition_facts(view)?
            .entity(EntityKind::ClassDefinition, owner.local_index)?;
        let index = self.definitions.get_or_build(|| self.build_definitions())?;
        let candidates = index
            .owners
            .get(&(view, owner.local_index, kind))
            .map(Vec::as_slice)
            .unwrap_or_default();
        let mut entities = Vec::new();
        let mut result_bytes = 0;
        for atom in candidates {
            if predicate.matches(&self.definition_name(*atom)?) {
                self.append_entity(&mut entities, &mut result_bytes, atom.view, || {
                    self.definition_entity(*atom)
                })?;
            }
        }
        self.result(
            entities,
            candidates.len(),
            "owner_candidates_then_exact",
            Some(self.definitions.audit()?),
            coverage,
        )
    }
    /// Find directly declared fields or methods for an exact class descriptor across the selected occurrences.
    /// Duplicate definitions are retained and inheritance or runtime resolution is not inferred.
    pub fn owner_members_by_descriptor(
        &self,
        descriptor: &str,
        kind: DefinitionKind,
        predicate: &Utf16Predicate,
    ) -> MddResult<IndexMatches> {
        self.owner_members_descriptor_impl(descriptor, kind, predicate, false)
    }
    /// Full scan independent of the lazy owner index.
    pub fn owner_members_by_descriptor_scalar(
        &self,
        descriptor: &str,
        kind: DefinitionKind,
        predicate: &Utf16Predicate,
    ) -> MddResult<IndexMatches> {
        self.owner_members_descriptor_impl(descriptor, kind, predicate, true)
    }
    fn owner_members_descriptor_impl(
        &self,
        descriptor: &str,
        kind: DefinitionKind,
        predicate: &Utf16Predicate,
        scalar: bool,
    ) -> MddResult<IndexMatches> {
        Self::check_predicate(predicate)?;
        if kind == DefinitionKind::Class {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "member kind must be field or method",
            ));
        }
        if descriptor.encode_utf16().take(1_000_001).count() > 1_000_000 {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let coverage = self.require(FactLayer::Definitions)?;
        let mut entities = Vec::new();
        let mut result_bytes = 0;
        let mut candidates = 0usize;
        if scalar {
            for (view, entry) in self.views.iter().enumerate() {
                let facts = entry.definitions.ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "definitions missing",
                    )
                })?;
                let view = u32::try_from(view).map_err(|_| quota("INDEX_ENTRY_BUDGET"))?;
                for class in facts
                    .definitions()
                    .classes
                    .iter()
                    .filter(|class| class.descriptor == descriptor)
                {
                    let members: Box<dyn Iterator<Item = u32> + '_> = match kind {
                        DefinitionKind::Field => Box::new(
                            facts
                                .definitions()
                                .field_definitions
                                .iter()
                                .filter(move |item| item.class_def_idx == class.class_def_idx)
                                .map(|item| item.field_idx),
                        ),
                        DefinitionKind::Method => Box::new(
                            facts
                                .definitions()
                                .method_definitions
                                .iter()
                                .filter(move |item| item.class_def_idx == class.class_def_idx)
                                .map(|item| item.method_idx),
                        ),
                        DefinitionKind::Class => unreachable!(),
                    };
                    for local in members {
                        candidates = candidates
                            .checked_add(1)
                            .ok_or_else(|| quota("INDEX_RESULT_ENTRY_BUDGET"))?;
                        let atom = DefinitionAtom { view, kind, local };
                        if predicate.matches(&self.definition_name(atom)?) {
                            self.append_entity(&mut entities, &mut result_bytes, view, || {
                                self.definition_entity(atom)
                            })?;
                        }
                    }
                }
            }
        } else {
            let index = self.definitions.get_or_build(|| self.build_definitions())?;
            let key = (
                DefinitionKind::Class,
                descriptor.encode_utf16().collect::<Vec<_>>(),
            );
            for owner in index.names.get(&key).into_iter().flatten() {
                let facts = self.definition_facts(owner.view)?;
                let class = facts
                    .definitions()
                    .classes
                    .get(owner.local as usize)
                    .ok_or_else(|| {
                        MddError::new(
                            ErrorCode::InternalFault,
                            "facts.index",
                            "class candidate missing",
                        )
                    })?;
                if class.descriptor != descriptor {
                    continue;
                }
                for atom in index
                    .owners
                    .get(&(owner.view, owner.local, kind))
                    .into_iter()
                    .flatten()
                {
                    candidates = candidates
                        .checked_add(1)
                        .ok_or_else(|| quota("INDEX_RESULT_ENTRY_BUDGET"))?;
                    let member_class = match kind {
                        DefinitionKind::Field => facts
                            .definitions()
                            .field_references
                            .get(atom.local as usize)
                            .map(|member| member.class_idx),
                        DefinitionKind::Method => facts
                            .definitions()
                            .method_references
                            .get(atom.local as usize)
                            .map(|member| member.class_idx),
                        DefinitionKind::Class => unreachable!(),
                    }
                    .ok_or_else(|| {
                        MddError::new(
                            ErrorCode::InternalFault,
                            "facts.index",
                            "member candidate missing",
                        )
                    })?;
                    if member_class == class.class_idx
                        && predicate.matches(&self.definition_name(*atom)?)
                    {
                        self.append_entity(&mut entities, &mut result_bytes, owner.view, || {
                            self.definition_entity(*atom)
                        })?;
                    }
                }
            }
        }
        self.result(
            entities,
            candidates,
            if scalar {
                "scalar_class_descriptor_and_direct_members"
            } else {
                "class_descriptor_and_owner_candidates_then_exact"
            },
            if scalar {
                None
            } else {
                Some(self.definitions.audit()?)
            },
            coverage,
        )
    }
    pub fn retry_definition_index(&self) -> MddResult<IndexAudit> {
        self.definitions.retry_failed(|| self.build_definitions())?;
        self.definitions.audit()
    }
    pub fn retry_reference_symbol_index(&self) -> MddResult<IndexAudit> {
        self.reference_symbols
            .retry_failed(|| self.build_reference_symbols())?;
        self.reference_symbols.audit()
    }
    pub fn retry_field_reference_symbol_index(&self) -> MddResult<IndexAudit> {
        self.field_reference_symbols
            .retry_failed(|| self.build_field_reference_symbols())?;
        self.field_reference_symbols.audit()
    }
    pub fn retry_type_reference_index(&self) -> MddResult<IndexAudit> {
        self.type_references
            .retry_failed(|| self.build_type_references())?;
        self.type_references.audit()
    }
    pub fn retry_prototype_reference_index(&self) -> MddResult<IndexAudit> {
        self.prototype_references
            .retry_failed(|| self.build_prototype_references())?;
        self.prototype_references.audit()
    }
    pub fn retry_method_handle_index(&self) -> MddResult<IndexAudit> {
        self.method_handles
            .retry_failed(|| self.build_method_handles())?;
        self.method_handles.audit()
    }
    pub fn retry_caller_site_index(&self) -> MddResult<IndexAudit> {
        self.caller_sites
            .retry_failed(|| self.build_caller_sites())?;
        self.caller_sites.audit()
    }
    fn build_caller_sites(&self) -> MddResult<CallerSiteIndex> {
        self.require(FactLayer::References)?;
        let mut index = CallerSiteIndex {
            sites: BTreeMap::new(),
        };
        let mut budget = Budget::new(self.limits);
        budget.charge(0, 0)?;
        for (view, entry) in self.views.iter().enumerate() {
            let facts = entry.references.ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "references missing",
                )
            })?;
            let view = u32::try_from(view).map_err(|_| quota("INDEX_ENTRY_BUDGET"))?;
            for (ordinal, site) in facts.sites().iter().enumerate() {
                let ordinal = u32::try_from(ordinal).map_err(|_| quota("INDEX_ENTRY_BUDGET"))?;
                if site.site_ordinal != ordinal {
                    return Err(MddError::new(
                        ErrorCode::InternalFault,
                        "facts.index",
                        "validated reference site ordinal is inconsistent",
                    ));
                }
                let key = Atom {
                    view,
                    local: site.caller_method_idx,
                };
                let key_bytes = if index.sites.contains_key(&key) {
                    0
                } else {
                    64
                };
                budget.charge(1, key_bytes + 8)?;
                let postings = index.sites.entry(key).or_default();
                postings
                    .try_reserve(1)
                    .map_err(|_| quota("INDEX_ALLOCATION"))?;
                postings.push(ordinal);
            }
        }
        Ok(index)
    }
    fn build_method_handles(&self) -> MddResult<MethodHandleIndex> {
        self.require(FactLayer::References)?;
        let mut index = MethodHandleIndex {
            symbols: BTreeMap::new(),
        };
        let mut budget = Budget::new(self.limits);
        budget.charge(0, 0)?;
        for (view, entry) in self.views.iter().enumerate() {
            let facts = entry.references.ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "references missing",
                )
            })?;
            let view = u32::try_from(view).map_err(|_| quota("INDEX_ENTRY_BUDGET"))?;
            for handle in handle_metadata(facts)? {
                let target = handle_target(facts, handle)?;
                budget.charge(1, target.bytes()?)?;
                index.symbols.entry(target.owned()).or_default().push(Atom {
                    view,
                    local: handle.method_handle_idx,
                });
            }
        }
        Ok(index)
    }
    fn build_prototype_references(&self) -> MddResult<PrototypeReferenceIndex> {
        self.require(FactLayer::Metadata)?;
        let mut index = PrototypeReferenceIndex {
            descriptors: BTreeMap::new(),
        };
        let mut budget = Budget::new(self.limits);
        budget.charge(0, 0)?;
        for (view, entry) in self.views.iter().enumerate() {
            let metadata = entry.metadata.ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "metadata missing",
                )
            })?;
            let view = u32::try_from(view).map_err(|_| quota("INDEX_ENTRY_BUDGET"))?;
            for prototype in metadata.prototypes() {
                let descriptor = &prototype.data.descriptor;
                let key_bytes = if index.descriptors.contains_key(descriptor) {
                    0
                } else {
                    u64::try_from(descriptor.len())
                        .ok()
                        .and_then(|n| n.checked_add(64))
                        .ok_or_else(|| quota("INDEX_BYTE_BUDGET"))?
                };
                budget.charge(
                    1,
                    key_bytes
                        .checked_add(16)
                        .ok_or_else(|| quota("INDEX_BYTE_BUDGET"))?,
                )?;
                let atom = Atom {
                    view,
                    local: prototype.data.proto_idx,
                };
                if let Some(atoms) = index.descriptors.get_mut(descriptor) {
                    atoms.push(atom);
                } else {
                    index.descriptors.insert(descriptor.clone(), vec![atom]);
                }
            }
        }
        Ok(index)
    }
    fn build_type_references(&self) -> MddResult<TypeReferenceIndex> {
        self.require(FactLayer::Metadata)?;
        let mut index = TypeReferenceIndex {
            descriptors: BTreeMap::new(),
        };
        let mut budget = Budget::new(self.limits);
        budget.charge(0, 0)?;
        for (view, entry) in self.views.iter().enumerate() {
            let metadata = entry.metadata.ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "metadata missing",
                )
            })?;
            let view = u32::try_from(view).map_err(|_| quota("INDEX_ENTRY_BUDGET"))?;
            for dex_type in metadata.types() {
                let descriptor = &dex_type.data.descriptor;
                let key_bytes = if index.descriptors.contains_key(descriptor) {
                    0
                } else {
                    u64::try_from(descriptor.len())
                        .ok()
                        .and_then(|n| n.checked_add(64))
                        .ok_or_else(|| quota("INDEX_BYTE_BUDGET"))?
                };
                budget.charge(
                    1,
                    key_bytes
                        .checked_add(16)
                        .ok_or_else(|| quota("INDEX_BYTE_BUDGET"))?,
                )?;
                let atom = Atom {
                    view,
                    local: dex_type.data.type_idx,
                };
                if let Some(atoms) = index.descriptors.get_mut(descriptor) {
                    atoms.push(atom);
                } else {
                    index.descriptors.insert(descriptor.clone(), vec![atom]);
                }
            }
        }
        Ok(index)
    }
    fn build_field_reference_symbols(&self) -> MddResult<FieldReferenceSymbolIndex> {
        self.require(FactLayer::Definitions)?;
        let mut index = FieldReferenceSymbolIndex {
            fields: BTreeMap::new(),
        };
        let mut budget = Budget::new(self.limits);
        budget.charge(0, 0)?;
        for (view, entry) in self.views.iter().enumerate() {
            let facts = entry.definitions.ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "definitions missing",
                )
            })?;
            for reference in &facts.definitions().field_references {
                let bytes = reference
                    .class_descriptor
                    .len()
                    .checked_add(reference.field_name.len())
                    .and_then(|v| v.checked_add(reference.type_descriptor.len()))
                    .and_then(|v| v.checked_add(16))
                    .and_then(|v| u64::try_from(v).ok())
                    .ok_or_else(|| quota("INDEX_BYTE_BUDGET"))?;
                budget.charge(1, bytes)?;
                let symbol = FieldSymbol {
                    owner: reference.class_descriptor.clone(),
                    name: reference.field_name.clone(),
                    field_type: reference.type_descriptor.clone(),
                };
                index.fields.entry(symbol).or_default().push(ReferenceAtom {
                    view: u32::try_from(view).map_err(|_| quota("INDEX_ENTRY_BUDGET"))?,
                    local: reference.field_idx,
                });
            }
        }
        Ok(index)
    }
    fn build_reference_symbols(&self) -> MddResult<ReferenceSymbolIndex> {
        self.require(FactLayer::Definitions)?;
        let mut index = ReferenceSymbolIndex {
            methods: BTreeMap::new(),
        };
        let mut budget = Budget::new(self.limits);
        budget.charge(0, 0)?;
        for (view, entry) in self.views.iter().enumerate() {
            let facts = entry.definitions.ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "definitions missing",
                )
            })?;
            for reference in &facts.definitions().method_references {
                let symbol = MethodSymbol {
                    owner: reference.class_descriptor.clone(),
                    name: reference.method_name.clone(),
                    prototype: facts.metadata().prototypes()[reference.proto_idx as usize]
                        .data
                        .descriptor
                        .clone(),
                };
                budget.charge(
                    1,
                    (symbol.owner.len() + symbol.name.len() + symbol.prototype.len()) as u64 + 16,
                )?;
                index
                    .methods
                    .entry(symbol)
                    .or_default()
                    .push(ReferenceAtom {
                        view: view as u32,
                        local: reference.method_idx,
                    });
            }
        }
        Ok(index)
    }
    pub fn references_local(&self, target: &ReferenceTargetId) -> MddResult<ReferenceMatches> {
        self.require(FactLayer::References)?;
        let view = *self
            .by_occurrence
            .get(&target.dex_occurrence_id)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.index",
                    "reference target outside selected occurrences",
                )
            })?;
        let matches = self.views[view as usize]
            .references
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "references not built",
                )
            })?
            .find_target_indexed(target)?;
        self.check_site_budget(&matches.sites)?;
        Ok(matches)
    }
    fn check_site_budget(&self, sites: &[crate::references::ReferenceSiteId]) -> MddResult<()> {
        let bytes = Self::site_bytes(sites)?;
        if sites.len() as u64 > self.limits.max_result_entries
            || bytes > self.limits.max_result_bytes
        {
            return Err(quota("INDEX_RESULT_BUDGET"));
        }
        Ok(())
    }
    fn site_bytes(sites: &[crate::references::ReferenceSiteId]) -> MddResult<u64> {
        sites
            .iter()
            .try_fold(0u64, |sum, site| {
                sum.checked_add(
                    (std::mem::size_of::<crate::references::ReferenceSiteId>()
                        + site.caller_method_definition.snapshot_id.len()
                        + site.caller_method_definition.dex_occurrence_id.len())
                        as u64,
                )
            })
            .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))
    }
    fn reference_result(
        &self,
        mut sites: Vec<crate::references::ReferenceSiteId>,
        candidates: u64,
        scalar: bool,
        kind: ReferenceResultKind,
        coverage: CoverageReport,
    ) -> MddResult<ReferenceIndexMatches> {
        self.check_site_budget(&sites)?;
        sites.sort_by_key(|site| {
            (
                self.by_occurrence[&site.caller_method_definition.dex_occurrence_id],
                site.caller_method_definition.local_index,
                site.code_unit_pc,
                site.operand_ordinal,
            )
        });
        Ok(ReferenceIndexMatches {
            snapshot_id: self.scope.snapshot_id().into(),
            scope_id: self.scope.scope_id().into(),
            index_attempt: match (scalar, kind) {
                (true, _) => None,
                (false, ReferenceResultKind::Method) => Some(self.reference_symbols.audit()?),
                (false, ReferenceResultKind::Field) => Some(self.field_reference_symbols.audit()?),
                (false, ReferenceResultKind::String) => Some(self.strings.audit()?),
                (false, ReferenceResultKind::Type) => Some(self.type_references.audit()?),
                (false, ReferenceResultKind::Prototype) => Some(self.prototype_references.audit()?),
                (false, ReferenceResultKind::MethodHandle) => Some(self.method_handles.audit()?),
                (false, ReferenceResultKind::CallSiteBytes) => None,
                (false, ReferenceResultKind::Caller) => Some(self.caller_sites.audit()?),
            },
            access_path: match (scalar, kind) {
                (true, ReferenceResultKind::Method) => {
                    "scalar_encoded_method_refs_then_scalar_sites"
                }
                (false, ReferenceResultKind::Method) => {
                    "method_symbol_candidates_then_exact_ref_and_existing_postings"
                }
                (true, ReferenceResultKind::Field) => "scalar_encoded_field_refs_then_scalar_sites",
                (false, ReferenceResultKind::Field) => {
                    "field_symbol_candidates_then_exact_ref_and_existing_postings"
                }
                (true, ReferenceResultKind::String) => "scalar_utf16_strings_then_scalar_sites",
                (false, ReferenceResultKind::String) => {
                    "utf16_string_candidates_then_exact_ref_and_existing_postings"
                }
                (true, ReferenceResultKind::Type) => "scalar_type_descriptors_then_scalar_sites",
                (false, ReferenceResultKind::Type) => {
                    "type_descriptor_candidates_then_exact_ref_and_existing_postings"
                }
                (true, ReferenceResultKind::Prototype) => {
                    "scalar_prototype_descriptors_then_scalar_sites"
                }
                (false, ReferenceResultKind::Prototype) => {
                    "prototype_descriptor_candidates_then_exact_ref_and_existing_postings"
                }
                (true, ReferenceResultKind::MethodHandle) => {
                    "scalar_method_handles_then_scalar_sites"
                }
                (false, ReferenceResultKind::MethodHandle) => {
                    "method_handle_symbol_candidates_then_exact_ref_and_existing_postings"
                }
                (true, ReferenceResultKind::CallSiteBytes) => {
                    "same_dex_content_callsite_bytes_then_scalar_sites"
                }
                (false, ReferenceResultKind::CallSiteBytes) => {
                    "same_dex_content_callsite_bytes_then_existing_postings"
                }
                (true, ReferenceResultKind::Caller) => "scalar_caller_and_encoded_sites",
                (false, ReferenceResultKind::Caller) => {
                    "caller_candidates_then_exact_encoded_sites"
                }
            }
            .into(),
            candidate_reference_count: candidates,
            absence_proven_within_selected_encoded_scope: sites.is_empty(),
            covers_all_captured_sources: self.scope.covers_all_captured_sources(),
            runtime_resolution: match kind {
                ReferenceResultKind::Field => {
                    "encoded_field_operands_only;runtime_resolution_not_inferred"
                }
                ReferenceResultKind::Method => {
                    "encoded_method_operands_only;runtime_dispatch_not_inferred"
                }
                ReferenceResultKind::String => {
                    "encoded_string_operands_only;runtime_values_not_inferred"
                }
                ReferenceResultKind::Type => {
                    "encoded_type_operands_only;runtime_resolution_not_inferred"
                }
                ReferenceResultKind::Prototype => {
                    "encoded_prototype_operands_only;runtime_dispatch_not_inferred"
                }
                ReferenceResultKind::MethodHandle => {
                    "encoded_method_handle_operands_only;no_implied_call_or_field_access"
                }
                ReferenceResultKind::CallSiteBytes => {
                    "same_dex_content_and_encoded_array_bytes_only;dynamic_target_not_inferred"
                }
                ReferenceResultKind::Caller => {
                    "encoded_operands_only;runtime_resolution_not_inferred"
                }
            },
            sites,
            coverage,
        })
    }
    /// Find encoded operand sites in one same-occurrence method definition.
    /// A method operand remains an encoded reference, not inferred runtime dispatch.
    pub fn references_from_method(
        &self,
        caller: &EntityRef,
        kind: Option<TargetKind>,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_from_method_impl(caller, kind, false)
    }
    /// Full scalar site scan, independent of the caller index.
    pub fn references_from_method_scalar(
        &self,
        caller: &EntityRef,
        kind: Option<TargetKind>,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_from_method_impl(caller, kind, true)
    }
    fn references_from_method_impl(
        &self,
        caller: &EntityRef,
        kind: Option<TargetKind>,
        scalar: bool,
    ) -> MddResult<ReferenceIndexMatches> {
        if caller.snapshot_id != self.scope.snapshot_id()
            || caller.kind != EntityKind::MethodDefinition
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "caller is a foreign snapshot or not a method definition",
            ));
        }
        let coverage = self.require(FactLayer::References)?;
        let view = *self
            .by_occurrence
            .get(&caller.dex_occurrence_id)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.index",
                    "caller outside selected occurrences",
                )
            })?;
        let facts = self.views[view as usize].references.ok_or_else(|| {
            MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.index",
                "references missing",
            )
        })?;
        if facts.source().snapshot_id != caller.snapshot_id
            || facts.source().dex_occurrence_id != caller.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "foreign caller identity",
            ));
        }
        let mut scan = Budget::new(self.limits);
        scan.charge(0, 0)?;
        let mut found = false;
        for definition in &facts.definitions().definitions().method_definitions {
            scan.charge(1, 0)?;
            if definition.method_idx == caller.local_index {
                found = true;
                break;
            }
        }
        if !found {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "method definition does not exist in this occurrence",
            ));
        }
        let index = if scalar {
            None
        } else {
            Some(
                self.caller_sites
                    .get_or_build(|| self.build_caller_sites())?,
            )
        };
        let candidates: Box<dyn Iterator<Item = u32> + '_> = if let Some(index) = &index {
            Box::new(
                index
                    .sites
                    .get(&Atom {
                        view,
                        local: caller.local_index,
                    })
                    .into_iter()
                    .flatten()
                    .copied(),
            )
        } else {
            Box::new((0..facts.sites().len()).map(|ordinal| ordinal as u32))
        };
        let mut result = Vec::new();
        let mut result_bytes = 0u64;
        let mut candidate_count = 0u64;
        for ordinal in candidates {
            scan.charge(1, 0)?;
            candidate_count = candidate_count
                .checked_add(1)
                .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
            let site = facts
                .sites()
                .get(ordinal as usize)
                .filter(|site| site.site_ordinal == ordinal)
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.index",
                        "caller candidate site missing",
                    )
                })?;
            if site.caller_method_idx != caller.local_index
                || kind.is_some_and(|kind| site.target_kind != kind)
            {
                continue;
            }
            let cost = std::mem::size_of::<crate::references::ReferenceSiteId>()
                .checked_add(caller.snapshot_id.len())
                .and_then(|size| size.checked_add(caller.dex_occurrence_id.len()))
                .and_then(|size| u64::try_from(size).ok())
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            result_bytes = result_bytes
                .checked_add(cost)
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            if result.len() as u64 >= self.limits.max_result_entries
                || result_bytes > self.limits.max_result_bytes
            {
                return Err(quota("INDEX_RESULT_BUDGET"));
            }
            result
                .try_reserve(1)
                .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
            result.push(crate::references::ReferenceSiteId {
                caller_method_definition: caller.clone(),
                code_unit_pc: site.code_unit_pc,
                operand_ordinal: site.operand_ordinal,
                operand_kind: site.target_kind,
            });
        }
        self.reference_result(
            result,
            candidate_count,
            scalar,
            ReferenceResultKind::Caller,
            coverage,
        )
    }
    /// Capture full call-site encoded-array bytes with the validated DEX content identity.
    /// The key is a byte identity within identical DEX content, not cross-DEX semantic equality.
    pub fn call_site_encoded_key(
        &self,
        target: &ReferenceTargetId,
    ) -> MddResult<CallSiteEncodedKey> {
        self.require(FactLayer::References)?;
        if target.snapshot_id != self.scope.snapshot_id() || target.kind != TargetKind::CallSite {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "foreign snapshot or non-call-site target",
            ));
        }
        let view = *self
            .by_occurrence
            .get(&target.dex_occurrence_id)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.index",
                    "reference target outside selected occurrences",
                )
            })?;
        let facts = self.views[view as usize].references.ok_or_else(|| {
            MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.index",
                "references missing",
            )
        })?;
        if facts.target_id(TargetKind::CallSite, target.local_index)? != *target {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "foreign call-site target",
            ));
        }
        let bytes = call_site_array_bytes(facts, target.local_index)?;
        let needed = u64::try_from(bytes.len())
            .ok()
            .and_then(|n| n.checked_add(facts.source().content_id.len() as u64))
            .and_then(|n| n.checked_add(facts.source().snapshot_id.len() as u64))
            .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
        if needed > self.limits.max_result_bytes {
            return Err(quota("INDEX_RESULT_BYTE_BUDGET"));
        }
        let mut encoded_array = Vec::new();
        encoded_array
            .try_reserve_exact(bytes.len())
            .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
        encoded_array.extend_from_slice(bytes);
        Ok(CallSiteEncodedKey {
            snapshot_id: facts.source().snapshot_id.clone(),
            dex_content_id: facts.source().content_id.clone(),
            encoded_array,
        })
    }
    /// Search complete encoded operands with the same DEX content and full array bytes.
    /// The source-local references within the byte array are never equated across different DEX contents.
    pub fn references_to_call_site_encoded_key(
        &self,
        key: &CallSiteEncodedKey,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_call_site_encoded(key, false)
    }
    pub fn references_to_call_site_encoded_key_scalar(
        &self,
        key: &CallSiteEncodedKey,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_call_site_encoded(key, true)
    }
    fn references_to_call_site_encoded(
        &self,
        key: &CallSiteEncodedKey,
        scalar: bool,
    ) -> MddResult<ReferenceIndexMatches> {
        if key.snapshot_id != self.scope.snapshot_id() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "call-site key belongs to a different snapshot",
            ));
        }
        let coverage = self.require(FactLayer::References)?;
        if u64::try_from(key.encoded_array.len()).map_or(true, |n| n > self.limits.max_result_bytes)
        {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let mut scan = Budget::new(self.limits);
        scan.charge(0, 0)?;
        let mut result = Vec::new();
        let mut result_bytes = 0u64;
        let mut candidates = 0u64;
        for entry in &self.views {
            let facts = entry.references.ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "references missing",
                )
            })?;
            if facts.source().content_id != key.dex_content_id {
                continue;
            }
            let Some(section) = facts.call_site_metadata() else {
                if facts
                    .sites()
                    .iter()
                    .any(|site| site.target_kind == TargetKind::CallSite)
                {
                    return Err(MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "call-site operand metadata missing",
                    ));
                }
                continue;
            };
            for binding in &section.call_site_arrays {
                scan.charge(1, 0)?;
                candidates = candidates
                    .checked_add(1)
                    .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
                let bytes = call_site_array_bytes(facts, binding.call_site_idx)?;
                if bytes.len() != key.encoded_array.len() {
                    continue;
                }
                let mut equal = true;
                for (a, b) in bytes.chunks(4096).zip(key.encoded_array.chunks(4096)) {
                    scan.charge(0, a.len() as u64)?;
                    if a != b {
                        equal = false;
                        break;
                    }
                }
                if !equal {
                    continue;
                }
                let target = facts.target_id(TargetKind::CallSite, binding.call_site_idx)?;
                let matches = if scalar {
                    facts.find_target_scalar(&target)?
                } else {
                    facts.find_target_indexed(&target)?
                };
                if result
                    .len()
                    .checked_add(matches.sites.len())
                    .and_then(|n| u64::try_from(n).ok())
                    .is_none_or(|n| n > self.limits.max_result_entries)
                {
                    return Err(quota("INDEX_RESULT_ENTRY_BUDGET"));
                }
                self.check_site_budget(&matches.sites)?;
                result_bytes = result_bytes
                    .checked_add(Self::site_bytes(&matches.sites)?)
                    .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
                if result_bytes > self.limits.max_result_bytes {
                    return Err(quota("INDEX_RESULT_BYTE_BUDGET"));
                }
                result
                    .try_reserve(matches.sites.len())
                    .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
                result.extend(matches.sites);
            }
        }
        self.reference_result(
            result,
            candidates,
            scalar,
            ReferenceResultKind::CallSiteBytes,
            coverage,
        )
    }

    /// Find encoded method-handle operand sites by handle kind and complete target symbol.
    /// Handle constants do not imply a call, field access, or runtime resolution.
    pub fn references_to_method_handle_symbol(
        &self,
        symbol: &MethodHandleSymbol,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_method_handle(symbol, false)
    }
    /// Scan immutable method-handle metadata and operand facts without the candidate index.
    pub fn references_to_method_handle_symbol_scalar(
        &self,
        symbol: &MethodHandleSymbol,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_method_handle(symbol, true)
    }
    fn references_to_method_handle(
        &self,
        symbol: &MethodHandleSymbol,
        scalar: bool,
    ) -> MddResult<ReferenceIndexMatches> {
        let (kind, size, is_field) = match symbol {
            MethodHandleSymbol::Field {
                handle_kind,
                target,
            } => (
                *handle_kind,
                target
                    .owner
                    .len()
                    .saturating_add(target.name.len())
                    .saturating_add(target.field_type.len()),
                true,
            ),
            MethodHandleSymbol::Method {
                handle_kind,
                target,
            } => (
                *handle_kind,
                target
                    .owner
                    .len()
                    .saturating_add(target.name.len())
                    .saturating_add(target.prototype.len()),
                false,
            ),
        };
        if size > 16 * 1024 * 1024 {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        if (is_field && kind > 3) || (!is_field && !(4..=8).contains(&kind)) {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index",
                "invalid method-handle kind for target",
            ));
        }
        let coverage = self.require(FactLayer::References)?;
        // Metadata may legitimately be unbuilt when there are no handle operands;
        // a missing table in the presence of an operand remains an error.
        for entry in &self.views {
            let facts = entry.references.ok_or_else(|| {
                MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.index",
                    "references missing",
                )
            })?;
            handle_metadata(facts)?;
        }
        let index = if scalar {
            None
        } else {
            Some(
                self.method_handles
                    .get_or_build(|| self.build_method_handles())?,
            )
        };
        let candidates: Box<dyn Iterator<Item = Atom> + '_> = if let Some(index) = &index {
            Box::new(index.symbols.get(symbol).into_iter().flatten().copied())
        } else {
            Box::new(self.views.iter().enumerate().flat_map(|(view, entry)| {
                entry.references.into_iter().flat_map(move |facts| {
                    facts
                        .method_handle_metadata()
                        .into_iter()
                        .flatten()
                        .map(move |handle| Atom {
                            view: view as u32,
                            local: handle.method_handle_idx,
                        })
                })
            }))
        };
        let mut result = Vec::new();
        let mut result_bytes = 0u64;
        let mut candidate_count = 0u64;
        for candidate in candidates {
            candidate_count = candidate_count
                .checked_add(1)
                .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
            let facts = self.views[candidate.view as usize]
                .references
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "references missing",
                    )
                })?;
            let handle = handle_metadata(facts)?
                .get(candidate.local as usize)
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.index",
                        "method-handle candidate missing",
                    )
                })?;
            if !handle_target(facts, handle)?.matches(symbol) {
                continue;
            }
            let target = facts.target_id(TargetKind::MethodHandle, candidate.local)?;
            let matches = if scalar {
                facts.find_target_scalar(&target)?
            } else {
                facts.find_target_indexed(&target)?
            };
            if result
                .len()
                .checked_add(matches.sites.len())
                .and_then(|v| u64::try_from(v).ok())
                .is_none_or(|count| count > self.limits.max_result_entries)
            {
                return Err(quota("INDEX_RESULT_ENTRY_BUDGET"));
            }
            self.check_site_budget(&matches.sites)?;
            result_bytes = result_bytes
                .checked_add(Self::site_bytes(&matches.sites)?)
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            if result_bytes > self.limits.max_result_bytes {
                return Err(quota("INDEX_RESULT_BYTE_BUDGET"));
            }
            result
                .try_reserve(matches.sites.len())
                .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
            result.extend(matches.sites);
        }
        self.reference_result(
            result,
            candidate_count,
            scalar,
            ReferenceResultKind::MethodHandle,
            coverage,
        )
    }

    /// Search exact encoded type operands by DEX descriptor across selected occurrences.
    /// This does not infer runtime class resolution, inheritance, or assignability.
    pub fn references_to_type_descriptor(
        &self,
        descriptor: &str,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_type(descriptor, false)
    }
    /// Full metadata and encoded-site scan independent of the lazy type index.
    pub fn references_to_type_descriptor_scalar(
        &self,
        descriptor: &str,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_type(descriptor, true)
    }
    fn references_to_type(
        &self,
        descriptor: &str,
        scalar: bool,
    ) -> MddResult<ReferenceIndexMatches> {
        if descriptor.len() > 16 * 1024 * 1024 {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let coverage = self.require(FactLayer::References)?;
        self.require(FactLayer::Metadata)?;
        let index = if scalar {
            None
        } else {
            Some(
                self.type_references
                    .get_or_build(|| self.build_type_references())?,
            )
        };
        let candidates: Box<dyn Iterator<Item = Atom> + '_> = if let Some(index) = &index {
            Box::new(
                index
                    .descriptors
                    .get(descriptor)
                    .into_iter()
                    .flatten()
                    .copied(),
            )
        } else {
            Box::new(self.views.iter().enumerate().flat_map(|(view, entry)| {
                entry.metadata.into_iter().flat_map(move |metadata| {
                    metadata.types().iter().map(move |dex_type| Atom {
                        view: view as u32,
                        local: dex_type.data.type_idx,
                    })
                })
            }))
        };
        let mut result = Vec::new();
        let mut result_bytes = 0u64;
        let mut candidate_count = 0u64;
        for candidate in candidates {
            candidate_count = candidate_count
                .checked_add(1)
                .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
            let refs = self.views[candidate.view as usize]
                .references
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "references missing",
                    )
                })?;
            let dex_type = &refs.definitions().metadata().types()[candidate.local as usize];
            if dex_type.data.descriptor != descriptor {
                continue;
            }
            let target = refs.target_id(TargetKind::Type, candidate.local)?;
            let matches = if scalar {
                refs.find_target_scalar(&target)?
            } else {
                refs.find_target_indexed(&target)?
            };
            if result
                .len()
                .checked_add(matches.sites.len())
                .and_then(|v| u64::try_from(v).ok())
                .is_none_or(|count| count > self.limits.max_result_entries)
            {
                return Err(quota("INDEX_RESULT_ENTRY_BUDGET"));
            }
            self.check_site_budget(&matches.sites)?;
            result_bytes = result_bytes
                .checked_add(Self::site_bytes(&matches.sites)?)
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            if result_bytes > self.limits.max_result_bytes {
                return Err(quota("INDEX_RESULT_BYTE_BUDGET"));
            }
            result
                .try_reserve(matches.sites.len())
                .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
            result.extend(matches.sites);
        }
        self.reference_result(
            result,
            candidate_count,
            scalar,
            ReferenceResultKind::Type,
            coverage,
        )
    }

    /// Search exact encoded prototype operands by DEX descriptor across selected occurrences.
    /// This does not infer runtime dispatch or call resolution.
    pub fn references_to_prototype_descriptor(
        &self,
        descriptor: &str,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_prototype(descriptor, false)
    }
    /// Full metadata and encoded-site scan independent of the lazy prototype index.
    pub fn references_to_prototype_descriptor_scalar(
        &self,
        descriptor: &str,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_prototype(descriptor, true)
    }
    fn references_to_prototype(
        &self,
        descriptor: &str,
        scalar: bool,
    ) -> MddResult<ReferenceIndexMatches> {
        if descriptor.len() > 16 * 1024 * 1024 {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let coverage = self.require(FactLayer::References)?;
        self.require(FactLayer::Metadata)?;
        let index = if scalar {
            None
        } else {
            Some(
                self.prototype_references
                    .get_or_build(|| self.build_prototype_references())?,
            )
        };
        let candidates: Box<dyn Iterator<Item = Atom> + '_> = if let Some(index) = &index {
            Box::new(
                index
                    .descriptors
                    .get(descriptor)
                    .into_iter()
                    .flatten()
                    .copied(),
            )
        } else {
            Box::new(self.views.iter().enumerate().flat_map(|(view, entry)| {
                entry.metadata.into_iter().flat_map(move |metadata| {
                    metadata.prototypes().iter().map(move |prototype| Atom {
                        view: view as u32,
                        local: prototype.data.proto_idx,
                    })
                })
            }))
        };
        let mut result = Vec::new();
        let mut result_bytes = 0u64;
        let mut candidate_count = 0u64;
        for candidate in candidates {
            candidate_count = candidate_count
                .checked_add(1)
                .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
            let refs = self.views[candidate.view as usize]
                .references
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "references missing",
                    )
                })?;
            let prototype = &refs.definitions().metadata().prototypes()[candidate.local as usize];
            if prototype.data.descriptor != descriptor {
                continue;
            }
            let target = refs.target_id(TargetKind::Prototype, candidate.local)?;
            let matches = if scalar {
                refs.find_target_scalar(&target)?
            } else {
                refs.find_target_indexed(&target)?
            };
            if result
                .len()
                .checked_add(matches.sites.len())
                .and_then(|v| u64::try_from(v).ok())
                .is_none_or(|count| count > self.limits.max_result_entries)
            {
                return Err(quota("INDEX_RESULT_ENTRY_BUDGET"));
            }
            self.check_site_budget(&matches.sites)?;
            result_bytes = result_bytes
                .checked_add(Self::site_bytes(&matches.sites)?)
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            if result_bytes > self.limits.max_result_bytes {
                return Err(quota("INDEX_RESULT_BYTE_BUDGET"));
            }
            result
                .try_reserve(matches.sites.len())
                .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
            result.extend(matches.sites);
        }
        self.reference_result(
            result,
            candidate_count,
            scalar,
            ReferenceResultKind::Prototype,
            coverage,
        )
    }

    /// Search encoded string operand sites by exact UTF-16 code units across selected occurrences.
    /// Raw MUTF-8 byte equality is a separate predicate and is not implied by this query.
    pub fn references_to_string_utf16(&self, value: &[u16]) -> MddResult<ReferenceIndexMatches> {
        self.references_to_string(value, false)
    }
    /// Scan immutable string and reference facts without using the lazy candidate index.
    pub fn references_to_string_utf16_scalar(
        &self,
        value: &[u16],
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_string(value, true)
    }
    fn references_to_string(
        &self,
        value: &[u16],
        scalar: bool,
    ) -> MddResult<ReferenceIndexMatches> {
        if value.len() > 1_000_000 {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let coverage = self.require(FactLayer::References)?;
        self.require(FactLayer::Metadata)?;
        let index = if scalar {
            None
        } else {
            Some(self.strings.get_or_build(|| self.build_strings())?)
        };
        let candidates: Box<dyn Iterator<Item = Atom> + '_> = if let Some(index) = &index {
            Box::new(index.utf16.get(value).into_iter().flatten().copied())
        } else {
            Box::new(self.views.iter().enumerate().flat_map(|(view, entry)| {
                entry.metadata.into_iter().flat_map(move |metadata| {
                    metadata.strings().iter().map(move |string| Atom {
                        view: view as u32,
                        local: string.data.string_idx,
                    })
                })
            }))
        };
        let mut result = Vec::new();
        let mut result_bytes = 0u64;
        let mut candidate_count = 0u64;
        for candidate in candidates {
            candidate_count = candidate_count
                .checked_add(1)
                .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
            let refs = self.views[candidate.view as usize]
                .references
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "references missing",
                    )
                })?;
            let string = &refs.definitions().metadata().strings()[candidate.local as usize];
            if string.data.text.utf16_units != value {
                continue;
            }
            let target = refs.target_id(TargetKind::String, candidate.local)?;
            let matches = if scalar {
                refs.find_target_scalar(&target)?
            } else {
                refs.find_target_indexed(&target)?
            };
            if result
                .len()
                .checked_add(matches.sites.len())
                .and_then(|v| u64::try_from(v).ok())
                .is_none_or(|count| count > self.limits.max_result_entries)
            {
                return Err(quota("INDEX_RESULT_ENTRY_BUDGET"));
            }
            self.check_site_budget(&matches.sites)?;
            result_bytes = result_bytes
                .checked_add(Self::site_bytes(&matches.sites)?)
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            if result_bytes > self.limits.max_result_bytes {
                return Err(quota("INDEX_RESULT_BYTE_BUDGET"));
            }
            result
                .try_reserve(matches.sites.len())
                .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
            result.extend(matches.sites);
        }
        self.reference_result(
            result,
            candidate_count,
            scalar,
            ReferenceResultKind::String,
            coverage,
        )
    }

    /// Search encoded field operand sites in each selected DEX occurrence.
    /// This matches reference symbols exactly; it does not infer runtime resolution.
    pub fn references_to_field_symbol(
        &self,
        symbol: &FieldSymbol,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_field(symbol, false)
    }
    /// Independent full scan of encoded field references and sites, without the lazy index.
    pub fn references_to_field_symbol_scalar(
        &self,
        symbol: &FieldSymbol,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_field(symbol, true)
    }
    fn references_to_field(
        &self,
        symbol: &FieldSymbol,
        scalar: bool,
    ) -> MddResult<ReferenceIndexMatches> {
        if symbol
            .owner
            .len()
            .saturating_add(symbol.name.len())
            .saturating_add(symbol.field_type.len())
            > 16 * 1024 * 1024
        {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let coverage = self.require(FactLayer::References)?;
        let index = if scalar {
            None
        } else {
            Some(
                self.field_reference_symbols
                    .get_or_build(|| self.build_field_reference_symbols())?,
            )
        };
        let candidates: Box<dyn Iterator<Item = ReferenceAtom> + '_> = if let Some(index) = &index {
            Box::new(index.fields.get(symbol).into_iter().flatten().copied())
        } else {
            Box::new(self.views.iter().enumerate().flat_map(|(view, entry)| {
                entry.definitions.into_iter().flat_map(move |defs| {
                    defs.definitions()
                        .field_references
                        .iter()
                        .map(move |reference| ReferenceAtom {
                            view: view as u32,
                            local: reference.field_idx,
                        })
                })
            }))
        };
        let mut result = Vec::new();
        let mut result_bytes = 0u64;
        let mut candidate_count = 0u64;
        for candidate in candidates {
            candidate_count = candidate_count
                .checked_add(1)
                .ok_or_else(|| quota("INDEX_ENTRY_BUDGET"))?;
            let refs = self.views[candidate.view as usize]
                .references
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "references missing",
                    )
                })?;
            let reference =
                &refs.definitions().definitions().field_references[candidate.local as usize];
            if reference.class_descriptor != symbol.owner
                || reference.field_name != symbol.name
                || reference.type_descriptor != symbol.field_type
            {
                continue;
            }
            let target = refs.target_id(TargetKind::Field, candidate.local)?;
            let matches = if scalar {
                refs.find_target_scalar(&target)?
            } else {
                refs.find_target_indexed(&target)?
            };
            if result
                .len()
                .checked_add(matches.sites.len())
                .and_then(|v| u64::try_from(v).ok())
                .is_none_or(|count| count > self.limits.max_result_entries)
            {
                return Err(quota("INDEX_RESULT_ENTRY_BUDGET"));
            }
            self.check_site_budget(&matches.sites)?;
            result_bytes = result_bytes
                .checked_add(Self::site_bytes(&matches.sites)?)
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            if result_bytes > self.limits.max_result_bytes {
                return Err(quota("INDEX_RESULT_BYTE_BUDGET"));
            }
            result
                .try_reserve(matches.sites.len())
                .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
            result.extend(matches.sites);
        }
        self.reference_result(
            result,
            candidate_count,
            scalar,
            ReferenceResultKind::Field,
            coverage,
        )
    }

    pub fn references_to_method_symbol(
        &self,
        symbol: &MethodSymbol,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_symbol(symbol, false)
    }
    pub fn references_to_method_symbol_scalar(
        &self,
        symbol: &MethodSymbol,
    ) -> MddResult<ReferenceIndexMatches> {
        self.references_to_symbol(symbol, true)
    }
    fn references_to_symbol(
        &self,
        symbol: &MethodSymbol,
        scalar: bool,
    ) -> MddResult<ReferenceIndexMatches> {
        if symbol
            .owner
            .len()
            .saturating_add(symbol.name.len())
            .saturating_add(symbol.prototype.len())
            > 16 * 1024 * 1024
        {
            return Err(quota("INDEX_PREDICATE_BUDGET"));
        }
        let coverage = self.require(FactLayer::References)?;
        // The scalar path scans immutable definition/reference facts and does not
        // consult candidate postings or a cached index failure.
        let index = if scalar {
            None
        } else {
            Some(
                self.reference_symbols
                    .get_or_build(|| self.build_reference_symbols())?,
            )
        };
        let mut result = Vec::new();
        let mut result_bytes = 0u64;
        let candidates: Box<dyn Iterator<Item = ReferenceAtom> + '_> = if let Some(index) = &index {
            Box::new(index.methods.get(symbol).into_iter().flatten().copied())
        } else {
            Box::new(self.views.iter().enumerate().flat_map(|(view, entry)| {
                entry.definitions.into_iter().flat_map(move |defs| {
                    defs.definitions()
                        .method_references
                        .iter()
                        .map(move |reference| ReferenceAtom {
                            view: view as u32,
                            local: reference.method_idx,
                        })
                })
            }))
        };
        let mut candidate_count = 0;
        for candidate in candidates {
            candidate_count += 1;
            let refs = self.views[candidate.view as usize]
                .references
                .ok_or_else(|| {
                    MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.index",
                        "references missing",
                    )
                })?;
            let reference =
                &refs.definitions().definitions().method_references[candidate.local as usize];
            if reference.class_descriptor != symbol.owner
                || reference.method_name != symbol.name
                || refs.definitions().metadata().prototypes()[reference.proto_idx as usize]
                    .data
                    .descriptor
                    != symbol.prototype
            {
                continue;
            }
            let target = refs.target_id(TargetKind::Method, candidate.local)?;
            let matches = if scalar {
                refs.find_target_scalar(&target)?
            } else {
                refs.find_target_indexed(&target)?
            };
            if result.len() as u64 + matches.sites.len() as u64 > self.limits.max_result_entries {
                return Err(quota("INDEX_RESULT_ENTRY_BUDGET"));
            }
            self.check_site_budget(&matches.sites)?;
            result_bytes = result_bytes
                .checked_add(Self::site_bytes(&matches.sites)?)
                .ok_or_else(|| quota("INDEX_RESULT_BYTE_BUDGET"))?;
            if result_bytes > self.limits.max_result_bytes {
                return Err(quota("INDEX_RESULT_BYTE_BUDGET"));
            }
            // Charge the combined result before copying another source's sites.
            result
                .try_reserve(matches.sites.len())
                .map_err(|_| quota("INDEX_RESULT_ALLOCATION"))?;
            result.extend(matches.sites);
        }
        self.reference_result(
            result,
            candidate_count,
            scalar,
            ReferenceResultKind::Method,
            coverage,
        )
    }
}
