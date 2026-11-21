//! Native query scope binding. This does not qualify a compatibility profile.
//!
//! The catalog is constructed only from an actual immutable snapshot, its
//! selected inventories, and byte-identical captured DEX facts.
//! It does not authenticate the caller's source acquisition or prove delivery.
use super::{
    Control, ExecutionMode, FactSource, JsonBatchLimits, PendingJsonBatchDelivery, PreparedQuery,
    RelationSchema, execute_json_batches_into,
    facts::{NativeCatalog, ReferenceCatalog},
    prepare,
};
use crate::{
    budget::{OwnedBatchSender, Resource, RuntimeBudget},
    ir::{FactLayer, QueryIr, Row, Value},
};
use mdd_facts::{
    EntityKind, EntityRef,
    coverage::{CoverageLedger, CoverageReport, CoverageRequest, FactLayer as EvidenceLayer},
    indexes::{FactView, SelectedScope},
    references::ReferenceFacts,
};
use mdd_input::{
    archive::{ArchiveInventory, DexSelection},
    snapshot::Snapshot,
};
use mdd_types::{
    Coverage, ErrorCode, MddError, MddResult,
    result::{ResultIdentity, TerminalBuilder},
};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Clone, Copy, Debug)]
pub enum InputSelection {
    /// The requested scope is exactly the supplied selected input occurrences.
    SelectedInputs,
    /// Every source captured by this snapshot must have a supplied inventory.
    AllCapturedInputs,
}

#[derive(Clone, Copy, Debug)]
pub struct ScopedLimits {
    /// Maximum source, inventory, catalog, reference and selected DEX counts;
    /// each count is checked separately before constructing the selected scope.
    pub max_entries: u64,
    /// Maximum selected-scope commitment preimage length. Checked before
    /// SelectedScope construction; its other allocations are not bounded by
    /// this value. Neither this nor entry counts bound RSS or CPU.
    pub max_commitment_bytes: u64,
    /// Upper bound for comparing distinct captured-byte allocations. This is
    /// a logical byte count, not a bound on CPU, allocator overhead or RSS.
    pub max_identity_compare_bytes: u64,
}

/// Explicitly unqualified native scope preview. No compatibility or release
/// capability is admitted by this identifier.
pub const SCOPED_UNQUALIFIED_PROFILE: &str = "native-unqualified";

/// Default logical limit for the physical-code coverage pass, counting both
/// available code items and declared code offsets across selected occurrences.
/// Large scopes may opt into a different limit via `prepare_with_code_coverage_limit`.
pub const DEFAULT_COVERAGE_CODE_ENTRIES: u64 = 8_000_000;

struct EvidenceOccurrence {
    metadata: Arc<mdd_facts::MetadataFacts>,
    definitions: Option<Arc<mdd_facts::definitions::DefinitionFacts>>,
    code: Option<Arc<mdd_facts::code::CodeFacts>>,
    references: Option<Arc<ReferenceFacts>>,
}

enum ScopedBase {
    Native(NativeCatalog),
    References(ReferenceCatalog),
}
impl ScopedBase {
    fn source(&self) -> &dyn FactSource {
        match self {
            Self::Native(value) => value,
            Self::References(value) => value,
        }
    }
}

/// A sealed pairing of a built-in catalog and its actual selected inputs.
/// This proves the selected roster and native layer status, not external input
/// authorization, installation completeness, parser conformance, or delivery.
pub struct ScopedCatalog {
    base: ScopedBase,
    scope: SelectedScope,
    evidence: Vec<EvidenceOccurrence>,
}

/// Bounds for an entity-key index built from an existing sealed scope. Counts
/// and bytes are logical and do not bound allocator overhead, sorting time or RSS.
#[derive(Clone, Copy, Debug)]
pub struct EntityAuthorityLimits {
    pub max_occurrences: u64,
    pub max_definition_indices: u64,
    pub max_index_bytes: u64,
}

/// Aggregate bounds for one checked source wrapper's lifetime. These limits do
/// not bound time spent inside the wrapped provider or authenticate its facts.
#[derive(Clone, Copy, Debug)]
pub struct EntityCheckLimits {
    pub max_rows: u64,
    pub max_entity_checks: u64,
    pub max_lookup_steps: u64,
    pub max_identity_bytes: u64,
}

struct EntityOccurrence<'a> {
    metadata: &'a mdd_facts::MetadataFacts,
    definitions: Option<&'a mdd_facts::definitions::DefinitionFacts>,
    fields: Vec<u32>,
    methods: Vec<u32>,
}

/// An immutable entity-key authority derived only from a `ScopedCatalog` that
/// already binds captured snapshot, selected inventories and fact bytes.
/// It proves membership relative to that selected scope, not parser/ART
/// conformance, acquisition authorization or correctness of provider values.
pub struct ScopedEntityAuthority<'a> {
    catalog: &'a ScopedCatalog,
    occurrences: Vec<EntityOccurrence<'a>>,
}

/// Optional checked view of a generic provider. Every scanned entity and
/// explicitly validated entity is checked against an independent sealed scope;
/// arbitrary scalar values, provider code bytes and input/fact coverage are not
/// authenticated by this wrapper. Counters are cumulative for its lifetime.
pub struct EntityCheckedSource<'a, 'scope> {
    source: &'a dyn FactSource,
    source_identity: &'a str,
    authority: &'a ScopedEntityAuthority<'scope>,
    limits: EntityCheckLimits,
    rows: Cell<u64>,
    entities: Cell<u64>,
    steps: Cell<u64>,
    identity_bytes: Cell<u64>,
    runtime: Option<RuntimeBudget>,
}

fn authority_quota(message: &'static str) -> MddError {
    error(ErrorCode::QuotaExceeded, message)
}

fn authority_add(total: u64, amount: u64, limit: u64, message: &'static str) -> MddResult<u64> {
    let next = total
        .checked_add(amount)
        .ok_or_else(|| authority_quota(message))?;
    if next > limit {
        return Err(authority_quota(message));
    }
    Ok(next)
}

fn authority_indices(values: impl Iterator<Item = u32>, count: usize) -> MddResult<Vec<u32>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| authority_quota("entity authority allocation failed"))?;
    result.extend(values);
    result.sort_unstable();
    if result.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(error(
            ErrorCode::InternalFault,
            "duplicate definition entity index",
        ));
    }
    Ok(result)
}

fn error(code: ErrorCode, message: &'static str) -> MddError {
    MddError::new(code, "query.scoped", message)
}

fn add_code_coverage_entries(used: u64, items: u64, offsets: u64, limit: u64) -> MddResult<u64> {
    let next = used
        .checked_add(items)
        .and_then(|value| value.checked_add(offsets))
        .ok_or_else(|| {
            error(
                ErrorCode::QuotaExceeded,
                "code coverage entry count overflow",
            )
        })?;
    if next > limit {
        return Err(error(
            ErrorCode::QuotaExceeded,
            "code coverage entry budget exceeded",
        )
        .detail("budget", "max_coverage_code_entries")
        .detail("limit", limit.to_string())
        .detail("observed", next.to_string()));
    }
    Ok(next)
}

// Preserve SelectedScope's identity errors before applying the byte preflight.
// The caller checks source and inventory counts before building these maps.
fn validate_inventory_identities(
    snapshot: &Snapshot,
    inventories: &[&ArchiveInventory],
) -> MddResult<()> {
    let captured: BTreeMap<_, _> = snapshot
        .sources()
        .iter()
        .map(|source| (source.identity().occurrence_id.as_str(), source.identity()))
        .collect();
    let mut seen = BTreeSet::new();
    for inventory in inventories {
        let manifest = inventory.manifest();
        let source = captured
            .get(manifest.source_occurrence_id.as_str())
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.index_scope",
                    "inventory is outside snapshot",
                )
            })?;
        if source.content_id != manifest.source_content_id
            || !seen.insert(manifest.source_occurrence_id.as_str())
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index_scope",
                "inventory identity mismatch or duplicate source",
            ));
        }
    }
    Ok(())
}

// Mirror the fixed v1 framing without constructing its bytes. Inventory order
// does not affect the total length; source/order/identity validation remains
// the responsibility of SelectedScope::from_inventories.
fn preflight_commitment_bytes(
    snapshot: &Snapshot,
    inventories: &[&ArchiveInventory],
    limit: u64,
) -> MddResult<u64> {
    let quota = || {
        error(
            ErrorCode::QuotaExceeded,
            "scope commitment byte budget exceeded",
        )
    };
    let mut total = u64::try_from(b"mdd-selected-scope-v1".len()).map_err(|_| quota())?;
    let mut frame = |length: usize| -> MddResult<()> {
        let length = u64::try_from(length).map_err(|_| quota())?;
        total = total
            .checked_add(8)
            .and_then(|v| v.checked_add(length))
            .ok_or_else(quota)?;
        if total > limit {
            return Err(quota());
        }
        Ok(())
    };
    for inventory in inventories {
        let manifest = inventory.manifest();
        let policy = match manifest.selection {
            DexSelection::TopLevelClasses => "top-level-classes-v1",
            DexSelection::AllDexMembers => "all-dex-members-v1",
            DexSelection::ResourcesOnly => "resources-only-v1",
        };
        frame(8)?; // source ordinal
        frame(manifest.source_content_id.len())?;
        frame(policy.len())?;
        for dex in inventory.selected_dexes() {
            frame(dex.blob.content_id.len())?;
            frame(8)?; // archive member ordinal
            frame(8)?; // logical DEX header offset
        }
    }
    frame(snapshot.manifest().snapshot_id.len())?;
    Ok(total)
}

pub(super) fn compare_dex_bytes(
    captured: &Arc<[u8]>,
    facts: &Arc<[u8]>,
    compared: &mut u64,
    limit: u64,
) -> MddResult<()> {
    if Arc::ptr_eq(captured, facts) {
        return Ok(());
    }
    if captured.len() != facts.len() {
        return Err(error(ErrorCode::SourceChanged, "captured DEX bytes differ"));
    }
    *compared = compared
        .checked_add(u64::try_from(captured.len()).map_err(|_| {
            error(
                ErrorCode::QuotaExceeded,
                "identity comparison size overflow",
            )
        })?)
        .ok_or_else(|| {
            error(
                ErrorCode::QuotaExceeded,
                "identity comparison size overflow",
            )
        })?;
    if *compared > limit {
        return Err(error(
            ErrorCode::QuotaExceeded,
            "identity comparison byte budget exceeded",
        ));
    }
    if captured.as_ref() != facts.as_ref() {
        return Err(error(ErrorCode::SourceChanged, "captured DEX bytes differ"));
    }
    Ok(())
}

impl ScopedCatalog {
    pub fn native(
        snapshot: &Snapshot,
        inventories: &[&ArchiveInventory],
        native: NativeCatalog,
        selection: InputSelection,
        limits: ScopedLimits,
    ) -> MddResult<Self> {
        Self::build(snapshot, inventories, native, None, selection, limits)
    }

    pub fn references(
        snapshot: &Snapshot,
        inventories: &[&ArchiveInventory],
        native: NativeCatalog,
        references: Vec<Arc<ReferenceFacts>>,
        selection: InputSelection,
        limits: ScopedLimits,
    ) -> MddResult<Self> {
        Self::build(
            snapshot,
            inventories,
            native,
            Some(references),
            selection,
            limits,
        )
    }

    fn build(
        snapshot: &Snapshot,
        inventories: &[&ArchiveInventory],
        native: NativeCatalog,
        references: Option<Vec<Arc<ReferenceFacts>>>,
        selection: InputSelection,
        limits: ScopedLimits,
    ) -> MddResult<Self> {
        let quota = || {
            error(
                ErrorCode::QuotaExceeded,
                "scoped roster entry budget exceeded",
            )
        };
        let sources = u64::try_from(snapshot.sources().len()).map_err(|_| quota())?;
        let supplied = u64::try_from(inventories.len()).map_err(|_| quota())?;
        let catalog = u64::try_from(native.occurrences.len()).map_err(|_| quota())?;
        let reference_count = references.as_ref().map_or(Ok(0), |values| {
            u64::try_from(values.len()).map_err(|_| quota())
        })?;
        let selected = inventories.iter().try_fold(0u64, |total, inventory| {
            total
                .checked_add(u64::try_from(inventory.selected_dexes().len()).map_err(|_| quota())?)
                .ok_or_else(quota)
        })?;
        if [sources, supplied, catalog, selected, reference_count]
            .into_iter()
            .any(|count| count > limits.max_entries)
        {
            return Err(quota());
        }
        // Reject the empty selection with the existing scope validation error.
        if inventories.is_empty() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.index_scope",
                "explicit selected scope requires inventories; use pending while unbuilt",
            ));
        }
        validate_inventory_identities(snapshot, inventories)?;
        preflight_commitment_bytes(snapshot, inventories, limits.max_commitment_bytes)?;
        let scope = SelectedScope::from_inventories(snapshot, inventories)?;
        if matches!(selection, InputSelection::AllCapturedInputs)
            && !scope.covers_all_captured_sources()
        {
            return Err(error(
                ErrorCode::PartialInput,
                "not every captured source is selected",
            ));
        }
        if native.snapshot_id() != scope.snapshot_id() {
            return Err(error(
                ErrorCode::InvalidArgument,
                "catalog snapshot differs from scope",
            ));
        }
        let metadata: Vec<_> = native
            .occurrences
            .iter()
            .map(|item| item.metadata.as_ref())
            .collect();
        scope.commitment_preimage(
            snapshot,
            inventories,
            &metadata,
            limits.max_entries,
            limits.max_commitment_bytes,
        )?;
        let rows = scope.inventory_metadata_rows(inventories, &metadata, limits.max_entries)?;
        if rows.len() != native.occurrences.len() {
            return Err(error(
                ErrorCode::IncompleteFacts,
                "catalog occurrence count differs",
            ));
        }
        let mut compared = 0u64;
        for ((_, selected, dex, fact), occurrence) in rows.iter().zip(&native.occurrences) {
            if selected.dex_occurrence_id != occurrence.metadata.source().dex_occurrence_id
                || !std::ptr::eq(*fact, occurrence.metadata.as_ref())
            {
                return Err(error(
                    ErrorCode::InvalidArgument,
                    "catalog order or DEX facts differ",
                ));
            }
            compare_dex_bytes(
                &dex.blob.lease(),
                &occurrence.metadata.lease(),
                &mut compared,
                limits.max_identity_compare_bytes,
            )?;
        }
        let mut by_occurrence = BTreeMap::new();
        if let Some(values) = &references {
            for value in values {
                if by_occurrence
                    .insert(value.source().dex_occurrence_id.clone(), Arc::clone(value))
                    .is_some()
                {
                    return Err(error(
                        ErrorCode::InvalidArgument,
                        "duplicate reference occurrence",
                    ));
                }
            }
        }
        let evidence = native
            .occurrences
            .iter()
            .map(|item| EvidenceOccurrence {
                metadata: Arc::clone(&item.metadata),
                definitions: item.definitions.clone(),
                code: item.code.clone(),
                references: by_occurrence.remove(&item.metadata.source().dex_occurrence_id),
            })
            .collect();
        if !by_occurrence.is_empty() {
            return Err(error(
                ErrorCode::InvalidArgument,
                "reference outside selected scope",
            ));
        }
        let base = match references {
            Some(values) => ScopedBase::References(ReferenceCatalog::new_scoped_verified(
                native,
                values,
                &mut compared,
                limits.max_identity_compare_bytes,
            )?),
            None => ScopedBase::Native(native),
        };
        Ok(Self {
            base,
            scope,
            evidence,
        })
    }

    pub fn scope_id(&self) -> &str {
        self.scope.scope_id()
    }
    pub fn covers_all_captured_sources(&self) -> bool {
        self.scope.covers_all_captured_sources()
    }

    /// Build an independent entity-key index from this exact sealed selected
    /// scope. Missing definition layers remain unavailable, not empty.
    pub fn entity_authority(
        &self,
        limits: EntityAuthorityLimits,
    ) -> MddResult<ScopedEntityAuthority<'_>> {
        let occurrences = u64::try_from(self.evidence.len())
            .map_err(|_| authority_quota("entity authority occurrence count overflow"))?;
        if occurrences > limits.max_occurrences {
            return Err(authority_quota(
                "entity authority occurrence budget exceeded",
            ));
        }
        let mut definitions = 0u64;
        for item in &self.evidence {
            if let Some(facts) = &item.definitions {
                for count in [
                    facts.definitions().field_definitions.len(),
                    facts.definitions().method_definitions.len(),
                ] {
                    definitions = authority_add(
                        definitions,
                        u64::try_from(count).map_err(|_| {
                            authority_quota("entity authority definition count overflow")
                        })?,
                        limits.max_definition_indices,
                        "entity authority definition budget exceeded",
                    )?;
                }
            }
        }
        let bytes = occurrences
            .checked_mul(std::mem::size_of::<EntityOccurrence<'_>>() as u64)
            .and_then(|value| {
                definitions
                    .checked_mul(std::mem::size_of::<u32>() as u64)
                    .and_then(|size| value.checked_add(size))
            })
            .ok_or_else(|| authority_quota("entity authority byte count overflow"))?;
        if bytes > limits.max_index_bytes {
            return Err(authority_quota("entity authority byte budget exceeded"));
        }
        let mut indexed = Vec::new();
        indexed
            .try_reserve_exact(self.evidence.len())
            .map_err(|_| authority_quota("entity authority allocation failed"))?;
        for item in &self.evidence {
            let (fields, methods) = if let Some(facts) = &item.definitions {
                let data = facts.definitions();
                (
                    authority_indices(
                        data.field_definitions.iter().map(|value| value.field_idx),
                        data.field_definitions.len(),
                    )?,
                    authority_indices(
                        data.method_definitions.iter().map(|value| value.method_idx),
                        data.method_definitions.len(),
                    )?,
                )
            } else {
                (Vec::new(), Vec::new())
            };
            indexed.push(EntityOccurrence {
                metadata: item.metadata.as_ref(),
                definitions: item.definitions.as_deref(),
                fields,
                methods,
            });
        }
        indexed.sort_unstable_by(|a, b| {
            a.metadata
                .source()
                .dex_occurrence_id
                .cmp(&b.metadata.source().dex_occurrence_id)
        });
        if indexed.windows(2).any(|pair| {
            pair[0].metadata.source().dex_occurrence_id
                == pair[1].metadata.source().dex_occurrence_id
        }) {
            return Err(error(
                ErrorCode::InternalFault,
                "duplicate scoped entity occurrence",
            ));
        }
        Ok(ScopedEntityAuthority {
            catalog: self,
            occurrences: indexed,
        })
    }

    /// Build a query with coverage evaluated from the exact facts of this catalog.
    /// Annotation and resource layers are intentionally not admitted here.
    /// Physical-code coverage is bounded by `DEFAULT_COVERAGE_CODE_ENTRIES`;
    /// the limit is logical, not a bound on CPU, allocator overhead or RSS.
    pub fn prepare(&self, query: QueryIr) -> MddResult<ScopedPrepared<'_>> {
        self.prepare_with_code_coverage_limit(query, DEFAULT_COVERAGE_CODE_ENTRIES)
    }

    /// As `prepare`, with an explicit limit for available code items plus
    /// declared offsets visited by the physical-code coverage pass. A larger
    /// scope can choose a different limit without changing `ScopedLimits`.
    pub fn prepare_with_code_coverage_limit(
        &self,
        query: QueryIr,
        max_coverage_code_entries: u64,
    ) -> MddResult<ScopedPrepared<'_>> {
        let prepared = prepare(query, self.base.source())?;
        let mut requested = BTreeSet::new();
        for layer in prepared.required_layers() {
            requested.insert(match layer {
                FactLayer::Metadata => EvidenceLayer::Metadata,
                FactLayer::Structure => EvidenceLayer::Structure,
                FactLayer::CodeLayout => EvidenceLayer::AllPhysicalCode,
                FactLayer::References => EvidenceLayer::References,
                FactLayer::Annotations | FactLayer::Resources => {
                    return Err(error(
                        ErrorCode::IncompleteFacts,
                        "requested layer is not supported by scoped catalog",
                    ));
                }
            });
        }
        if requested.contains(&EvidenceLayer::AllPhysicalCode) {
            let mut used = 0u64;
            for occurrence in &self.evidence {
                let code = occurrence.code.as_ref().ok_or_else(|| {
                    error(
                        ErrorCode::IncompleteFacts,
                        "physical code facts not available",
                    )
                })?;
                let items = u64::try_from(code.items().len()).map_err(|_| {
                    error(
                        ErrorCode::QuotaExceeded,
                        "code coverage entry count overflow",
                    )
                })?;
                let offsets =
                    u64::try_from(code.declared_code_item_byte_offsets().len()).map_err(|_| {
                        error(
                            ErrorCode::QuotaExceeded,
                            "code coverage entry count overflow",
                        )
                    })?;
                used = add_code_coverage_entries(used, items, offsets, max_coverage_code_entries)?;
            }
        }
        let views: Vec<_> = self
            .evidence
            .iter()
            .map(|item| {
                let mut view = FactView::unbuilt(&item.metadata.source().dex_occurrence_id);
                if let Some(references) = &item.references {
                    view = view.with_references(references);
                }
                view = view.with_metadata(&item.metadata);
                if let Some(definitions) = &item.definitions {
                    view = view.with_definitions(definitions);
                }
                if let Some(code) = &item.code {
                    view = view.with_code(code);
                }
                view
            })
            .collect();
        let ledger = CoverageLedger::new(self.scope.clone(), &views)?;
        let request =
            CoverageRequest::for_scope(&self.scope, &requested.into_iter().collect::<Vec<_>>());
        let report = ledger.evaluate(&request)?;
        report.require_complete()?;
        if !report.issues.is_empty() {
            return Err(error(
                ErrorCode::IncompleteFacts,
                "unexpected scoped coverage issue",
            ));
        }
        let required_layers = prepared
            .required_layers()
            .iter()
            .map(|layer| {
                serde_json::to_value(layer)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .ok_or_else(|| {
                        error(ErrorCode::InternalFault, "fact layer serialization failed")
                    })
            })
            .collect::<MddResult<Vec<_>>>()?;
        let coverage = Coverage {
            scope_id: report.scope_id.clone(),
            input: report.input,
            facts: report.facts,
            required_layers,
            issues: Vec::new(),
        };
        Ok(ScopedPrepared {
            catalog: self,
            prepared,
            report,
            coverage,
        })
    }
}

fn spend_authority(
    counter: &Cell<u64>,
    amount: u64,
    limit: u64,
    message: &'static str,
) -> MddResult<()> {
    let next = authority_add(counter.get(), amount, limit, message)?;
    counter.set(next);
    Ok(())
}

fn search_step_bound(length: usize) -> u64 {
    if length == 0 {
        1
    } else {
        u64::from(usize::BITS - length.leading_zeros()) + 2
    }
}

impl<'scope> ScopedEntityAuthority<'scope> {
    /// Bind a provider to this independently captured scope. Entity-key checks
    /// are cumulative for the returned wrapper's lifetime. Provider scan,
    /// schema, explicit validation callbacks and code bytes remain trusted
    /// provider operations and are not bounded/authenticated by this wrapper.
    pub fn checked_source<'a>(
        &'a self,
        source: &'a dyn FactSource,
        limits: EntityCheckLimits,
    ) -> MddResult<EntityCheckedSource<'a, 'scope>> {
        let source_identity = source.identity();
        let source_snapshot = source.snapshot_id();
        let initial_bytes = u64::try_from(source_identity.len())
            .ok()
            .and_then(|value| value.checked_add(u64::try_from(source_snapshot.len()).ok()?))
            .ok_or_else(|| authority_quota("provider binding identity size overflow"))?;
        if initial_bytes > limits.max_identity_bytes {
            return Err(authority_quota("entity identity byte budget exceeded"));
        }
        if source_identity.is_empty()
            || source_snapshot != self.catalog.scope.snapshot_id()
            || source.catalog_epoch() != self.catalog.base.source().catalog_epoch()
        {
            return Err(error(
                ErrorCode::InvalidArgument,
                "provider and entity authority binding differ",
            ));
        }
        Ok(EntityCheckedSource {
            source,
            source_identity,
            authority: self,
            limits,
            rows: Cell::new(0),
            entities: Cell::new(0),
            steps: Cell::new(0),
            identity_bytes: Cell::new(initial_bytes),
            runtime: None,
        })
    }

    /// Bind checks to a real query runtime and prepared plan. When an observed
    /// failure precedes provider row/iterator destruction, its first lifecycle
    /// error is recorded before that destruction can trigger cancellation.
    /// Provider callbacks and bytes remain outside this authority's proof.
    fn checked_source_with_runtime<'a>(
        &'a self,
        source: &'a dyn FactSource,
        prepared: &PreparedQuery,
        runtime: &RuntimeBudget,
        limits: EntityCheckLimits,
    ) -> MddResult<EntityCheckedSource<'a, 'scope>> {
        let mut checked = self.checked_source(source, limits)?;
        let expected = prepared.runtime_binding()?;
        let actual = runtime.cancellation().binding()?;
        if prepared.source_identity != checked.source_identity
            || prepared.snapshot_id() != self.catalog.scope.snapshot_id()
            || prepared.catalog_epoch() != self.catalog.base.source().catalog_epoch()
            || runtime.cancellation().snapshot_id()? != prepared.snapshot_id()
            || runtime.cancellation().status()?.catalog_epoch != prepared.catalog_epoch()
            || runtime.cancellation().session_id()?.is_empty()
            || expected.request_key != actual.request_key
            || expected.schema_id != actual.schema_id
            || expected.semantic_version != actual.semantic_version
        {
            return Err(error(
                ErrorCode::InvalidArgument,
                "runtime and entity authority binding differ",
            ));
        }
        checked.check_provider_binding()?;
        checked.runtime = Some(runtime.clone());
        Ok(checked)
    }

    /// Execute with an authority wrapper confined to the actual query runtime.
    /// This validates entity keys, not provider facts, bytes, or input coverage.
    pub fn execute_checked(
        &self,
        prepared: &PreparedQuery,
        source: &dyn FactSource,
        mode: ExecutionMode,
        control: &mut Control<'_>,
        limits: EntityCheckLimits,
    ) -> MddResult<super::QueryOutput> {
        let runtime = control.runtime.clone().ok_or_else(|| {
            error(
                ErrorCode::InvalidArgument,
                "entity checked execution requires runtime",
            )
        })?;
        let checked = self.checked_source_with_runtime(source, prepared, &runtime, limits)?;
        super::execute(prepared, &checked, mode, control)
    }

    /// The confined wrapper cannot be reused with another query or budget.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_json_batches_checked(
        &self,
        prepared: &PreparedQuery,
        source: &dyn FactSource,
        mode: ExecutionMode,
        control: &mut Control<'_>,
        terminal: TerminalBuilder,
        sender: &OwnedBatchSender,
        batch_limits: JsonBatchLimits,
        limits: EntityCheckLimits,
    ) -> MddResult<PendingJsonBatchDelivery> {
        let runtime = control.runtime.clone().ok_or_else(|| {
            error(
                ErrorCode::InvalidArgument,
                "entity checked execution requires runtime",
            )
        })?;
        let checked = self.checked_source_with_runtime(source, prepared, &runtime, limits)?;
        execute_json_batches_into(
            prepared,
            &checked,
            mode,
            control,
            terminal,
            sender,
            batch_limits,
        )
    }
}

impl EntityCheckedSource<'_, '_> {
    fn first_failure(&self, failure: MddError) -> MddError {
        self.runtime
            .as_ref()
            .map_or(failure.clone(), |runtime| runtime.stop(failure))
    }

    // The standalone wrapper remains governed by EntityCheckLimits. A wrapper
    // confined to a query additionally charges its own checking work to that
    // query; provider callbacks and pre-binding work are outside this charge.
    fn charge_query_steps(&self, steps: u64) -> MddResult<()> {
        if let Some(runtime) = &self.runtime {
            runtime.charge(Resource::QuerySteps, steps)?;
        }
        Ok(())
    }

    fn check_provider_binding(&self) -> MddResult<()> {
        if let Some(runtime) = &self.runtime {
            runtime.checkpoint()?;
        }
        let identity = self.source.identity();
        let snapshot = self.source.snapshot_id();
        let compared = u64::try_from(identity.len())
            .ok()
            .and_then(|value| value.checked_add(u64::try_from(snapshot.len()).ok()?))
            .ok_or_else(|| authority_quota("provider binding identity size overflow"))?;
        spend_authority(
            &self.identity_bytes,
            compared,
            self.limits.max_identity_bytes,
            "entity identity byte budget exceeded",
        )?;
        self.charge_query_steps(
            compared
                .checked_add(1)
                .ok_or_else(|| authority_quota("provider binding step overflow"))?,
        )?;
        if identity != self.source_identity
            || snapshot != self.authority.catalog.scope.snapshot_id()
            || self.source.catalog_epoch() != self.authority.catalog.base.source().catalog_epoch()
        {
            return Err(error(
                ErrorCode::SourceChanged,
                "provider binding changed during entity checking",
            ));
        }
        Ok(())
    }

    fn check_entity(&self, entity: &EntityRef) -> MddResult<()> {
        spend_authority(
            &self.entities,
            1,
            self.limits.max_entity_checks,
            "entity check budget exceeded",
        )?;
        let occurrence_steps = search_step_bound(self.authority.occurrences.len());
        spend_authority(
            &self.steps,
            occurrence_steps,
            self.limits.max_lookup_steps,
            "entity lookup budget exceeded",
        )?;
        let snapshot_bytes = u64::try_from(entity.snapshot_id.len())
            .map_err(|_| authority_quota("entity identity size overflow"))?;
        let occurrence_bytes = u64::try_from(entity.dex_occurrence_id.len())
            .map_err(|_| authority_quota("entity identity size overflow"))?;
        let compared = occurrence_bytes
            .checked_mul(occurrence_steps)
            .and_then(|value| value.checked_add(snapshot_bytes))
            .ok_or_else(|| authority_quota("entity identity size overflow"))?;
        spend_authority(
            &self.identity_bytes,
            compared,
            self.limits.max_identity_bytes,
            "entity identity byte budget exceeded",
        )?;
        let query_steps = compared
            .checked_add(occurrence_steps)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| authority_quota("entity query step overflow"))?;
        self.charge_query_steps(query_steps)?;
        if entity.snapshot_id != self.authority.catalog.scope.snapshot_id() {
            return Err(error(
                ErrorCode::InvalidArgument,
                "entity snapshot differs from selected scope",
            ));
        }
        let index = self
            .authority
            .occurrences
            .binary_search_by(|item| {
                item.metadata
                    .source()
                    .dex_occurrence_id
                    .as_str()
                    .cmp(entity.dex_occurrence_id.as_str())
            })
            .map_err(|_| {
                error(
                    ErrorCode::InvalidArgument,
                    "entity occurrence is outside selected scope",
                )
            })?;
        let item = &self.authority.occurrences[index];
        let position = usize::try_from(entity.local_index).map_err(|_| {
            error(
                ErrorCode::InvalidArgument,
                "entity local index is outside selected scope",
            )
        })?;
        let present = match entity.kind {
            EntityKind::String => position < item.metadata.strings().len(),
            EntityKind::Type => position < item.metadata.types().len(),
            EntityKind::Prototype => position < item.metadata.prototypes().len(),
            _ => {
                let definitions = item
                    .definitions
                    .ok_or_else(|| {
                        error(
                            ErrorCode::IncompleteFacts,
                            "definition facts unavailable for entity",
                        )
                    })?
                    .definitions();
                match entity.kind {
                    EntityKind::ClassDefinition => position < definitions.classes.len(),
                    EntityKind::FieldReference => position < definitions.field_references.len(),
                    EntityKind::MethodReference => position < definitions.method_references.len(),
                    EntityKind::FieldDefinition => {
                        let steps = search_step_bound(item.fields.len());
                        spend_authority(
                            &self.steps,
                            steps,
                            self.limits.max_lookup_steps,
                            "entity lookup budget exceeded",
                        )?;
                        self.charge_query_steps(steps)?;
                        item.fields.binary_search(&entity.local_index).is_ok()
                    }
                    EntityKind::MethodDefinition => {
                        let steps = search_step_bound(item.methods.len());
                        spend_authority(
                            &self.steps,
                            steps,
                            self.limits.max_lookup_steps,
                            "entity lookup budget exceeded",
                        )?;
                        self.charge_query_steps(steps)?;
                        item.methods.binary_search(&entity.local_index).is_ok()
                    }
                    _ => unreachable!(),
                }
            }
        };
        if !present {
            return Err(error(
                ErrorCode::InvalidArgument,
                "entity local index is outside selected scope",
            ));
        }
        Ok(())
    }

    fn check_row(&self, row: &Row) -> MddResult<()> {
        spend_authority(
            &self.rows,
            1,
            self.limits.max_rows,
            "entity checked row budget exceeded",
        )?;
        if row.len() > 256 {
            return Err(error(
                ErrorCode::InvalidArgument,
                "entity checked row width exceeds schema limit",
            ));
        }
        self.charge_query_steps(
            u64::try_from(row.len())
                .map_err(|_| authority_quota("entity row step overflow"))?
                .checked_add(1)
                .ok_or_else(|| authority_quota("entity row step overflow"))?,
        )?;
        for value in row {
            if let Value::Entity(entity) = value {
                self.check_entity(entity)?;
            }
        }
        Ok(())
    }
}

struct EntityCheckedRows<'row, 'source, 'scope> {
    checked: &'row EntityCheckedSource<'source, 'scope>,
    inner: Option<Box<dyn Iterator<Item = MddResult<Row>> + 'row>>,
    stopped: bool,
}

impl Iterator for EntityCheckedRows<'_, '_, '_> {
    type Item = MddResult<Row>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.stopped {
            return None;
        }
        if let Err(error) = self.checked.check_provider_binding() {
            self.stopped = true;
            return Some(Err(self.checked.first_failure(error)));
        }
        match self.inner.as_mut().expect("active iterator").next() {
            Some(Err(error)) => {
                self.stopped = true;
                Some(Err(self.checked.first_failure(error)))
            }
            Some(Ok(row)) => {
                let checked = self
                    .checked
                    .check_provider_binding()
                    .and_then(|_| self.checked.check_row(&row))
                    .and_then(|_| self.checked.check_provider_binding());
                if let Err(error) = checked {
                    self.stopped = true;
                    Some(Err(self.checked.first_failure(error)))
                } else {
                    Some(Ok(row))
                }
            }
            None => {
                self.stopped = true;
                drop(self.inner.take());
                match self.checked.check_provider_binding() {
                    Ok(()) => None,
                    Err(error) => Some(Err(self.checked.first_failure(error))),
                }
            }
        }
    }
}

impl Drop for EntityCheckedRows<'_, '_, '_> {
    fn drop(&mut self) {
        let was_active = !self.stopped;
        drop(self.inner.take());
        if was_active
            && self.checked.runtime.is_some()
            && let Err(failure) = self.checked.check_provider_binding()
        {
            self.checked.first_failure(failure);
        }
    }
}

impl FactSource for EntityCheckedSource<'_, '_> {
    fn identity(&self) -> &str {
        self.source_identity
    }
    fn snapshot_id(&self) -> &str {
        self.authority.catalog.scope.snapshot_id()
    }
    fn catalog_epoch(&self) -> mdd_types::DecimalU64 {
        self.authority.catalog.base.source().catalog_epoch()
    }
    fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema> {
        self.check_provider_binding()
            .map_err(|error| self.first_failure(error))?;
        let value = self
            .source
            .relation_schema(relation)
            .map_err(|error| self.first_failure(error))?;
        self.check_provider_binding()
            .map_err(|error| self.first_failure(error))?;
        Ok(value)
    }
    fn require_layers(&self, layers: &BTreeSet<FactLayer>) -> MddResult<()> {
        self.check_provider_binding()
            .map_err(|error| self.first_failure(error))?;
        self.source
            .require_layers(layers)
            .map_err(|error| self.first_failure(error))?;
        self.check_provider_binding()
            .map_err(|error| self.first_failure(error))
    }
    fn validate_entity(&self, entity: &EntityRef) -> MddResult<()> {
        self.check_provider_binding()
            .map_err(|error| self.first_failure(error))?;
        self.check_entity(entity)
            .map_err(|error| self.first_failure(error))?;
        self.source
            .validate_entity(entity)
            .map_err(|error| self.first_failure(error))?;
        self.check_provider_binding()
            .map_err(|error| self.first_failure(error))
    }
    fn scan<'a>(
        &'a self,
        relation: &str,
    ) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>> {
        self.check_provider_binding()
            .map_err(|error| self.first_failure(error))?;
        let rows = self
            .source
            .scan(relation)
            .map_err(|error| self.first_failure(error))?;
        if let Err(error) = self.check_provider_binding() {
            // The provider owns the iterator's destructor. Record a known
            // first fault before that destructor can cancel this query.
            let first = self.first_failure(error);
            drop(rows);
            return Err(first);
        }
        Ok(Box::new(EntityCheckedRows {
            checked: self,
            inner: Some(rows),
            stopped: false,
        }))
    }
    fn read_code_bytes(&self, entity: &EntityRef) -> MddResult<Option<&[u8]>> {
        self.check_provider_binding()
            .map_err(|error| self.first_failure(error))?;
        self.check_entity(entity)
            .map_err(|error| self.first_failure(error))?;
        let value = self
            .source
            .read_code_bytes(entity)
            .map_err(|error| self.first_failure(error))?;
        self.check_provider_binding()
            .map_err(|error| self.first_failure(error))?;
        Ok(value)
    }
}

/// This private coverage is derived from the same catalog and cannot be
/// replaced by a caller-supplied complete status through the scoped entry.
pub struct ScopedPrepared<'a> {
    catalog: &'a ScopedCatalog,
    prepared: PreparedQuery,
    report: CoverageReport,
    coverage: Coverage,
}
impl ScopedPrepared<'_> {
    pub fn plan(&self) -> &PreparedQuery {
        &self.prepared
    }
    pub fn source(&self) -> &dyn FactSource {
        self.catalog.base.source()
    }
    pub fn coverage_report(&self) -> &CoverageReport {
        &self.report
    }

    /// Start the existing bounded JSON path using only derived native coverage.
    /// Caller identity/profile and the eventual receipt remain separate.
    pub fn execute_json_batches_into(
        &self,
        mode: ExecutionMode,
        control: &mut Control<'_>,
        identity: ResultIdentity,
        sender: &OwnedBatchSender,
        limits: JsonBatchLimits,
    ) -> MddResult<PendingJsonBatchDelivery> {
        let terminal = TerminalBuilder::new(identity, self.coverage.clone())?;
        if terminal.identity().sql_dialect.is_some() {
            return Err(error(
                ErrorCode::InvalidArgument,
                "typed scope does not use a SQL dialect",
            ));
        }
        if terminal.identity().profile != SCOPED_UNQUALIFIED_PROFILE {
            return Err(error(
                ErrorCode::UnsupportedCapability,
                "scoped profile is not admitted",
            ));
        }
        execute_json_batches_into(
            &self.prepared,
            self.catalog.base.source(),
            mode,
            control,
            terminal,
            sender,
            limits,
        )
    }
}

#[cfg(test)]
#[path = "scoped_tests.rs"]
mod tests;
