//! Native query scope binding. This does not qualify a compatibility profile.
//!
//! The catalog is constructed only from an actual immutable snapshot, its
//! selected inventories, and byte-identical captured DEX facts.
//! It does not authenticate the caller's source acquisition or prove delivery.
use super::{
    Control, ExecutionMode, FactSource, JsonBatchLimits, PendingJsonBatchDelivery, PreparedQuery,
    execute_json_batches_into,
    facts::{NativeCatalog, ReferenceCatalog},
    prepare,
};
use crate::{
    budget::OwnedBatchSender,
    ir::{FactLayer, QueryIr},
};
use mdd_facts::{
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
mod tests {
    use super::*;
    use crate::{
        budget::{
            BudgetLimits, BudgetPool, BudgetScope, OwnedBatchEvent, RuntimeBudget,
            bounded_owned_batch_channel,
        },
        executor::{ExecutionLimits, JsonBatchConsumerLimits, consume_json_batch},
        ir::{IR_VERSION, Node, TEXT_VERSION, Value},
    };
    use mdd_dex::strings::StringLimits;
    use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits};
    use mdd_facts::MetadataFacts;
    use mdd_facts::{code::CodeFacts, definitions::DefinitionFacts, references::ReferenceLimits};
    use mdd_input::{
        archive::{ArchiveLimits, InventoryPolicy},
        snapshot::{CaptureLimits, InputKind, InputSpec},
    };
    use mdd_session::{Lifecycle, ResourceLimits};
    use mdd_types::{Completeness, DecimalU64};
    use std::path::PathBuf;

    fn fixture() -> (
        Arc<Snapshot>,
        Vec<ArchiveInventory>,
        Vec<Arc<MetadataFacts>>,
    ) {
        let input = InputSpec {
            path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/generated/minimal-035.dex"),
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Arc::new(Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap());
        let inventories: Vec<_> = snapshot
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
            .collect();
        let metadata = inventories
            .iter()
            .map(|inventory| {
                Arc::new(
                    MetadataFacts::build(&snapshot, inventory, 0, StringLimits::default()).unwrap(),
                )
            })
            .collect();
        (snapshot, inventories, metadata)
    }

    fn native(snapshot: &Snapshot, metadata: &[Arc<MetadataFacts>]) -> NativeCatalog {
        NativeCatalog::new(
            snapshot.manifest().snapshot_id.clone(),
            DecimalU64(0),
            metadata
                .iter()
                .map(|item| super::super::facts::OccurrenceFacts {
                    metadata: Arc::clone(item),
                    definitions: None,
                    code: None,
                })
                .collect(),
        )
        .unwrap()
    }

    fn limits() -> ScopedLimits {
        ScopedLimits {
            max_entries: 16,
            max_commitment_bytes: 16384,
            max_identity_compare_bytes: 16384,
        }
    }

    #[test]
    fn scope_commitment_budget_is_checked_before_scope_construction() {
        let (snapshot, inventories, metadata) = fixture();
        for indices in [&[0usize][..], &[0usize, 1usize][..]] {
            let selected: Vec<_> = indices.iter().map(|index| &inventories[*index]).collect();
            let facts: Vec<_> = indices
                .iter()
                .map(|index| metadata[*index].as_ref())
                .collect();
            let scope = SelectedScope::from_inventories(&snapshot, &selected).unwrap();
            let bytes = scope
                .commitment_preimage(&snapshot, &selected, &facts, 16, 16384)
                .unwrap();
            let exact = u64::try_from(bytes.len()).unwrap();
            assert_eq!(
                preflight_commitment_bytes(&snapshot, &selected, exact).unwrap(),
                exact
            );
            assert_eq!(
                preflight_commitment_bytes(&snapshot, &selected, exact - 1)
                    .unwrap_err()
                    .code,
                ErrorCode::QuotaExceeded
            );
            let bound = ScopedLimits {
                max_commitment_bytes: exact - 1,
                ..limits()
            };
            let sources = indices
                .iter()
                .map(|index| Arc::clone(&metadata[*index]))
                .collect::<Vec<_>>();
            assert_eq!(
                ScopedCatalog::native(
                    &snapshot,
                    &selected,
                    native(&snapshot, &sources),
                    InputSelection::SelectedInputs,
                    bound
                )
                .err()
                .unwrap()
                .code,
                ErrorCode::QuotaExceeded
            );
        }
    }

    #[test]
    fn commitment_preflight_covers_inventory_policies_and_empty_selection() {
        let input = InputSpec {
            path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/generated/multidex-stored.apk"),
            kind: InputKind::Apk,
            expected_sha256: None,
        };
        let snapshot = Snapshot::capture(&[input], CaptureLimits::default()).unwrap();
        for (selection, policy, expected_dexes) in [
            (
                DexSelection::TopLevelClasses,
                "top-level-classes-v1",
                2usize,
            ),
            (DexSelection::AllDexMembers, "all-dex-members-v1", 2usize),
            (DexSelection::ResourcesOnly, "resources-only-v1", 0usize),
        ] {
            let inventory = ArchiveInventory::build(
                &snapshot.sources()[0],
                InventoryPolicy {
                    dex_selection: selection,
                    require_dex: false,
                    ..InventoryPolicy::default()
                },
                ArchiveLimits::default(),
            )
            .unwrap();
            assert_eq!(inventory.selected_dexes().len(), expected_dexes);
            let scope = SelectedScope::from_inventories(&snapshot, &[&inventory]).unwrap();
            let source = snapshot.sources()[0].identity();
            let mut data = b"mdd-selected-scope-v1".to_vec();
            let append = |bytes: &mut Vec<u8>, value: &[u8]| {
                bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
                bytes.extend_from_slice(value);
            };
            append(&mut data, &source.input_ordinal.0.to_le_bytes());
            append(&mut data, source.content_id.as_bytes());
            append(&mut data, policy.as_bytes());
            for dex in inventory.selected_dexes() {
                append(&mut data, dex.blob.content_id.as_bytes());
                append(
                    &mut data,
                    &dex.blob
                        .identity
                        .archive_member_ordinal
                        .map_or(u64::MAX, |v| v.0)
                        .to_le_bytes(),
                );
                append(&mut data, &dex.logical_header_byte_offset.0.to_le_bytes());
            }
            assert_eq!(mdd_types::content_id(&data), scope.scope_content_key());
            append(&mut data, snapshot.manifest().snapshot_id.as_bytes());
            assert_eq!(mdd_types::content_id(&data), scope.scope_id());
            let exact = u64::try_from(data.len()).unwrap();
            assert_eq!(
                preflight_commitment_bytes(&snapshot, &[&inventory], exact).unwrap(),
                exact
            );
            assert_eq!(
                preflight_commitment_bytes(&snapshot, &[&inventory], exact - 1)
                    .unwrap_err()
                    .code,
                ErrorCode::QuotaExceeded
            );
        }
    }

    #[test]
    fn commitment_preflight_keeps_invalid_inventory_identity_before_byte_quota() {
        let (snapshot, inventories, metadata) = fixture();
        let (_, foreign, _) = fixture();
        let bound = ScopedLimits {
            max_commitment_bytes: 1,
            ..limits()
        };
        let expected_empty = SelectedScope::from_inventories(&snapshot, &[])
            .err()
            .unwrap();
        let actual_empty = ScopedCatalog::native(
            &snapshot,
            &[],
            native(&snapshot, &metadata),
            InputSelection::SelectedInputs,
            bound,
        )
        .err()
        .unwrap();
        assert_eq!(actual_empty.code, expected_empty.code);
        assert_eq!(actual_empty.stage, expected_empty.stage);
        assert_eq!(actual_empty.message, expected_empty.message);
        for selected in [vec![&inventories[0], &inventories[0]], vec![&foreign[0]]] {
            let expected = SelectedScope::from_inventories(&snapshot, &selected)
                .err()
                .unwrap();
            assert_eq!(expected.code, ErrorCode::InvalidArgument);
            let actual = ScopedCatalog::native(
                &snapshot,
                &selected,
                native(&snapshot, &metadata),
                InputSelection::SelectedInputs,
                bound,
            )
            .err()
            .unwrap();
            assert_eq!(actual.code, expected.code);
            assert_eq!(actual.stage, expected.stage);
            assert_eq!(actual.message, expected.message);
        }
    }

    #[test]
    fn identity_comparison_rejects_different_bytes_and_enforces_budget() {
        let captured: Arc<[u8]> = Arc::from(&b"same"[..]);
        let equal: Arc<[u8]> = Arc::from(&b"same"[..]);
        let changed: Arc<[u8]> = Arc::from(&b"sAme"[..]);
        let shorter: Arc<[u8]> = Arc::from(&b"sam"[..]);
        let mut used = 0;
        compare_dex_bytes(&captured, &captured, &mut used, 0).unwrap();
        assert_eq!(used, 0);
        assert_eq!(
            compare_dex_bytes(&captured, &equal, &mut used, 3)
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        used = 0;
        assert_eq!(
            compare_dex_bytes(&captured, &changed, &mut used, 4)
                .unwrap_err()
                .code,
            ErrorCode::SourceChanged
        );
        used = 0;
        assert_eq!(
            compare_dex_bytes(&captured, &shorter, &mut used, 0)
                .unwrap_err()
                .code,
            ErrorCode::SourceChanged
        );
    }

    fn scan(snapshot: &Snapshot, relation: &str) -> QueryIr {
        QueryIr {
            schema_version: IR_VERSION.into(),
            text_semantics: TEXT_VERSION.into(),
            snapshot_id: snapshot.manifest().snapshot_id.clone(),
            catalog_epoch: DecimalU64(0),
            require_stable_order: false,
            root: Node::Scan {
                relation: relation.into(),
            },
        }
    }

    #[test]
    fn scope_rejects_missing_reordered_and_other_snapshot() {
        let (snapshot, inventories, metadata) = fixture();
        let one = [&inventories[0]];
        let all = [&inventories[0], &inventories[1]];
        let selected = ScopedCatalog::native(
            &snapshot,
            &one,
            native(&snapshot, &metadata[..1]),
            InputSelection::SelectedInputs,
            limits(),
        )
        .unwrap();
        assert!(!selected.covers_all_captured_sources());
        let low = ScopedLimits {
            max_entries: 1,
            ..limits()
        };
        assert_eq!(
            ScopedCatalog::native(
                &snapshot,
                &one,
                native(&snapshot, &metadata[..1]),
                InputSelection::SelectedInputs,
                low
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::QuotaExceeded
        );
        let plan = selected
            .prepare(scan(&snapshot, "dex_occurrences"))
            .unwrap();
        assert_eq!(plan.coverage_report().input, Completeness::Complete);
        assert!(!plan.coverage_report().covers_all_captured_sources);
        assert_eq!(plan.coverage_report().selected_dex_occurrences.len(), 1);
        assert_eq!(
            ScopedCatalog::native(
                &snapshot,
                &one,
                native(&snapshot, &metadata[..1]),
                InputSelection::AllCapturedInputs,
                limits()
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::PartialInput
        );
        assert!(
            ScopedCatalog::native(
                &snapshot,
                &one,
                native(&snapshot, &metadata),
                InputSelection::SelectedInputs,
                limits()
            )
            .is_err()
        );
        let reversed = vec![metadata[1].clone(), metadata[0].clone()];
        assert!(
            ScopedCatalog::native(
                &snapshot,
                &all,
                native(&snapshot, &reversed),
                InputSelection::AllCapturedInputs,
                limits()
            )
            .is_err()
        );
        let (other, _, _) = fixture();
        assert!(
            ScopedCatalog::native(
                &other,
                &all,
                native(&snapshot, &metadata),
                InputSelection::AllCapturedInputs,
                limits()
            )
            .is_err()
        );
        assert_eq!(
            selected
                .prepare(scan(&snapshot, "classes"))
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
    }

    #[test]
    fn same_snapshot_rebuilt_inventory_accepts_identical_dex_bytes() {
        let input = InputSpec {
            path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/generated/multidex-deflated.apk"),
            kind: InputKind::Apk,
            expected_sha256: None,
        };
        let snapshot = Snapshot::capture(&[input], CaptureLimits::default()).unwrap();
        let first = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let second = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        assert_eq!(first.selected_dexes().len(), 2);
        let mut metadata = Vec::new();
        let mut distinct = 0;
        for (i, (a, b)) in first
            .selected_dexes()
            .iter()
            .zip(second.selected_dexes())
            .enumerate()
        {
            let left = a.blob.lease();
            let right = b.blob.lease();
            assert_eq!(&*left, &*right);
            if !Arc::ptr_eq(&left, &right) {
                distinct += 1;
            }
            metadata.push(Arc::new(
                MetadataFacts::build(&snapshot, &first, i, StringLimits::default()).unwrap(),
            ));
        }
        assert_eq!(
            distinct, 2,
            "both members must use distinct decompression allocations"
        );
        let scoped = ScopedCatalog::native(
            &snapshot,
            &[&second],
            native(&snapshot, &metadata),
            InputSelection::AllCapturedInputs,
            limits(),
        );
        assert!(
            scoped.is_ok(),
            "same captured bytes must survive inventory reconstruction"
        );
        let total = second
            .selected_dexes()
            .iter()
            .map(|dex| dex.blob.lease().len() as u64)
            .sum::<u64>();
        let too_small = ScopedLimits {
            max_identity_compare_bytes: total - 1,
            ..limits()
        };
        assert_eq!(
            ScopedCatalog::native(
                &snapshot,
                &[&second],
                native(&snapshot, &metadata),
                InputSelection::AllCapturedInputs,
                too_small
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::QuotaExceeded
        );
        let exact = ScopedLimits {
            max_identity_compare_bytes: total,
            ..limits()
        };
        assert!(
            ScopedCatalog::native(
                &snapshot,
                &[&second],
                native(&snapshot, &metadata),
                InputSelection::AllCapturedInputs,
                exact
            )
            .is_ok()
        );
    }

    #[test]
    fn scoped_references_accept_rebuilt_identical_dex_under_budget() {
        let input = InputSpec {
            path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/generated/multidex-deflated.apk"),
            kind: InputKind::Apk,
            expected_sha256: None,
        };
        let snapshot = Snapshot::capture(&[input], CaptureLimits::default()).unwrap();
        let first = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let rebuilt = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        assert_eq!(first.selected_dexes().len(), 2);
        let make_facts = |inventory: &ArchiveInventory| {
            (0..inventory.selected_dexes().len())
                .map(|index| {
                    let metadata =
                        MetadataFacts::build(&snapshot, inventory, index, StringLimits::default())
                            .unwrap();
                    let definitions =
                        DefinitionFacts::build(metadata.clone(), DefinitionLimits::default())
                            .unwrap();
                    let code = CodeFacts::build_all_code_items(
                        &snapshot,
                        inventory,
                        index,
                        CodeLimits::default(),
                    )
                    .unwrap();
                    (metadata, definitions, code)
                })
                .collect::<Vec<_>>()
        };
        let native_facts = make_facts(&first);
        let rebuilt_facts = make_facts(&rebuilt);
        let references = rebuilt_facts
            .iter()
            .map(|(_, definitions, code)| {
                Arc::new(
                    ReferenceFacts::build(
                        definitions.clone(),
                        code.clone(),
                        ReferenceLimits::default(),
                    )
                    .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let make_native = || {
            NativeCatalog::new(
                snapshot.manifest().snapshot_id.clone(),
                DecimalU64(0),
                native_facts
                    .iter()
                    .map(
                        |(metadata, definitions, code)| super::super::facts::OccurrenceFacts {
                            metadata: Arc::new(metadata.clone()),
                            definitions: Some(Arc::new(definitions.clone())),
                            code: Some(Arc::new(code.clone())),
                        },
                    )
                    .collect(),
            )
            .unwrap()
        };
        for ((left, _, _), (right, _, _)) in native_facts.iter().zip(&rebuilt_facts) {
            assert!(!Arc::ptr_eq(&left.lease(), &right.lease()));
            assert_eq!(&*left.lease(), &*right.lease());
        }
        let total = rebuilt
            .selected_dexes()
            .iter()
            .map(|dex| dex.blob.lease().len() as u64)
            .sum::<u64>();
        let exact = ScopedLimits {
            max_identity_compare_bytes: total,
            ..limits()
        };
        assert_eq!(
            ReferenceCatalog::new(make_native(), references.clone())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let result = ScopedCatalog::references(
            &snapshot,
            &[&first],
            make_native(),
            references.clone(),
            InputSelection::AllCapturedInputs,
            exact,
        );
        assert!(
            result.is_ok(),
            "same captured occurrence and bytes must accept rebuilt reference facts"
        );
        assert_eq!(
            ScopedCatalog::references(
                &snapshot,
                &[&first],
                make_native(),
                references,
                InputSelection::AllCapturedInputs,
                ScopedLimits {
                    max_identity_compare_bytes: total - 1,
                    ..limits()
                }
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::QuotaExceeded
        );

        // Definitions and code may be rebuilt independently from this same
        // captured occurrence. Both distinct byte comparisons must be charged.
        let third = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let third_facts = make_facts(&third);
        let split_references: Vec<_> = rebuilt_facts
            .iter()
            .zip(&third_facts)
            .map(|((_, definitions, _), (_, _, code))| {
                assert!(!Arc::ptr_eq(&definitions.metadata().lease(), &code.lease()));
                Arc::new(
                    ReferenceFacts::build(
                        definitions.clone(),
                        code.clone(),
                        ReferenceLimits::default(),
                    )
                    .unwrap(),
                )
            })
            .collect();
        let double = total.checked_mul(2).unwrap();
        assert!(
            ScopedCatalog::references(
                &snapshot,
                &[&first],
                make_native(),
                split_references.clone(),
                InputSelection::AllCapturedInputs,
                ScopedLimits {
                    max_identity_compare_bytes: double,
                    ..limits()
                }
            )
            .is_ok()
        );
        assert_eq!(
            ScopedCatalog::references(
                &snapshot,
                &[&first],
                make_native(),
                split_references,
                InputSelection::AllCapturedInputs,
                ScopedLimits {
                    max_identity_compare_bytes: double - 1,
                    ..limits()
                }
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::QuotaExceeded
        );
    }

    #[test]
    fn scoped_code_coverage_limit_keeps_missing_layer_error() {
        let (snapshot, inventories, metadata) = fixture();
        let inv = [&inventories[0], &inventories[1]];
        let catalog = ScopedCatalog::native(
            &snapshot,
            &inv,
            native(&snapshot, &metadata),
            InputSelection::AllCapturedInputs,
            limits(),
        )
        .unwrap();
        assert_eq!(
            catalog
                .prepare_with_code_coverage_limit(scan(&snapshot, "code_items"), 0)
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
    }

    #[test]
    fn scoped_references_derive_layers_from_the_actual_facts() {
        let input = InputSpec {
            path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/references/generated/poly-custom-038.dex"),
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let inventories: Vec<_> = snapshot
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
            .collect();
        let mut occurrences = Vec::new();
        let mut references = Vec::new();
        for inventory in &inventories {
            let metadata =
                MetadataFacts::build(&snapshot, inventory, 0, StringLimits::default()).unwrap();
            let definitions =
                DefinitionFacts::build(metadata.clone(), DefinitionLimits::default()).unwrap();
            let code =
                CodeFacts::build_all_code_items(&snapshot, inventory, 0, CodeLimits::default())
                    .unwrap();
            references.push(Arc::new(
                ReferenceFacts::build(
                    definitions.clone(),
                    code.clone(),
                    ReferenceLimits::default(),
                )
                .unwrap(),
            ));
            occurrences.push(super::super::facts::OccurrenceFacts {
                metadata: Arc::new(metadata),
                definitions: Some(Arc::new(definitions)),
                code: Some(Arc::new(code)),
            });
        }
        let native = NativeCatalog::new(
            snapshot.manifest().snapshot_id.clone(),
            DecimalU64(0),
            occurrences
                .iter()
                .map(|item| super::super::facts::OccurrenceFacts {
                    metadata: Arc::clone(&item.metadata),
                    definitions: item.definitions.clone(),
                    code: item.code.clone(),
                })
                .collect(),
        )
        .unwrap();
        let inv = [&inventories[0], &inventories[1]];
        let excessive = vec![
            references[0].clone(),
            references[0].clone(),
            references[1].clone(),
        ];
        assert_eq!(
            ScopedCatalog::references(
                &snapshot,
                &inv,
                native,
                excessive,
                InputSelection::AllCapturedInputs,
                ScopedLimits {
                    max_entries: 2,
                    ..limits()
                }
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::QuotaExceeded
        );
        let native = NativeCatalog::new(
            snapshot.manifest().snapshot_id.clone(),
            DecimalU64(0),
            occurrences,
        )
        .unwrap();
        references.reverse();
        let catalog = ScopedCatalog::references(
            &snapshot,
            &inv,
            native,
            references,
            InputSelection::AllCapturedInputs,
            limits(),
        )
        .unwrap();
        // Each occurrence contributes both its available code items and the
        // physical offsets against which they are checked.
        let work: Vec<u64> = catalog
            .evidence
            .iter()
            .map(|item| {
                let code = item.code.as_ref().unwrap();
                (code.items().len() + code.declared_code_item_byte_offsets().len()) as u64
            })
            .collect();
        assert_eq!(work.len(), 2);
        assert!(work.iter().all(|value| *value > 0));
        let combined = work.iter().sum::<u64>();
        let plan = catalog
            .prepare_with_code_coverage_limit(scan(&snapshot, "reference_sites"), combined)
            .unwrap();
        assert_eq!(plan.coverage_report().facts, Completeness::Complete);
        assert_eq!(
            catalog
                .prepare_with_code_coverage_limit(scan(&snapshot, "reference_sites"), combined - 1)
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            catalog
                .prepare_with_code_coverage_limit(scan(&snapshot, "reference_sites"), work[0])
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert!(
            catalog
                .prepare_with_code_coverage_limit(scan(&snapshot, "dex_occurrences"), 0)
                .is_ok()
        );
        assert_eq!(add_code_coverage_entries(0, 0, 0, 0).unwrap(), 0);
        assert_eq!(
            add_code_coverage_entries(u64::MAX, 1, 0, u64::MAX)
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        let plan = catalog.prepare(scan(&snapshot, "reference_sites")).unwrap();
        assert_eq!(plan.coverage_report().input, Completeness::Complete);
        assert_eq!(plan.coverage_report().facts, Completeness::Complete);
        assert_eq!(plan.coverage_report().selected_dex_occurrences.len(), 2);
        assert!(
            plan.plan()
                .required_layers()
                .contains(&FactLayer::References)
        );
        assert!(!plan.coverage_report().profile_admitted);
    }

    #[test]
    fn scoped_query_uses_derived_coverage_through_json_delivery() {
        let (snapshot, inventories, metadata) = fixture();
        let inv = [&inventories[0], &inventories[1]];
        let catalog = ScopedCatalog::native(
            &snapshot,
            &inv,
            native(&snapshot, &metadata),
            InputSelection::AllCapturedInputs,
            limits(),
        )
        .unwrap();
        let plan = catalog.prepare(scan(&snapshot, "dex_occurrences")).unwrap();
        assert!(plan.coverage_report().covers_all_captured_sources);
        assert_eq!(plan.coverage_report().input, Completeness::Complete);
        assert_eq!(plan.coverage_report().facts, Completeness::Complete);
        assert!(!plan.coverage_report().profile_admitted);

        let lifecycle = Lifecycle::new(ResourceLimits::default()).unwrap();
        let snapshot_handle = lifecycle.register_snapshot(Arc::clone(&snapshot)).unwrap();
        let session = lifecycle
            .open_session(&snapshot_handle, ResourceLimits::default())
            .unwrap();
        let binding = plan.plan().runtime_binding().unwrap();
        let query = lifecycle
            .prepare_query(&session, binding.clone(), ResourceLimits::default())
            .unwrap();
        lifecycle.start_query(&session, &query, 1).unwrap();
        let cancel = lifecycle.cancellation_token(&query).unwrap();
        let budget = BudgetLimits::default();
        let pool = BudgetPool::global("scoped-test-global".into(), budget.clone())
            .unwrap()
            .child(
                cancel.worker_owner_id().unwrap(),
                BudgetScope::Worker,
                budget.clone(),
            )
            .unwrap()
            .child(session.id().into(), BudgetScope::Session, budget.clone())
            .unwrap()
            .child(query.id().into(), BudgetScope::Query, budget)
            .unwrap();
        let runtime = RuntimeBudget::new(pool, cancel).unwrap();
        let (sender, mut receiver) = bounded_owned_batch_channel(&runtime, 4).unwrap();
        let identity = ResultIdentity {
            request_id: "scoped-fixture".into(),
            operation: "query".into(),
            profile: "native-unqualified".into(),
            sql_dialect: None,
            session_id: Some(session.id().into()),
            snapshot_id: Some(snapshot.manifest().snapshot_id.clone()),
            catalog_epoch: Some(DecimalU64(0)),
            query_id: Some(query.id().into()),
            schema_id: Some(binding.schema_id),
        };
        let mut control = Control::new(ExecutionLimits::default()).with_runtime(runtime.clone());
        let mut unsupported = identity.clone();
        unsupported.profile = "mdd-native-v1".into();
        assert_eq!(
            plan.execute_json_batches_into(
                ExecutionMode::Streaming,
                &mut control,
                unsupported,
                &sender,
                JsonBatchLimits {
                    max_rows: 1,
                    max_bytes: 65536
                }
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::UnsupportedCapability
        );
        let mut empty_profile = identity.clone();
        empty_profile.profile.clear();
        assert_eq!(
            plan.execute_json_batches_into(
                ExecutionMode::Streaming,
                &mut control,
                empty_profile,
                &sender,
                JsonBatchLimits {
                    max_rows: 1,
                    max_bytes: 65536
                }
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::InvalidArgument
        );
        let mut wrong_dialect = identity.clone();
        wrong_dialect.sql_dialect = Some("not-a-typed-dialect".into());
        assert_eq!(
            plan.execute_json_batches_into(
                ExecutionMode::Streaming,
                &mut control,
                wrong_dialect,
                &sender,
                JsonBatchLimits {
                    max_rows: 1,
                    max_bytes: 65536
                }
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::InvalidArgument
        );
        let mut pending = plan
            .execute_json_batches_into(
                ExecutionMode::Streaming,
                &mut control,
                identity,
                &sender,
                JsonBatchLimits {
                    max_rows: 1,
                    max_bytes: 65536,
                },
            )
            .unwrap();
        let mut rows = Vec::new();
        loop {
            match receiver.receive().unwrap() {
                OwnedBatchEvent::Data(packet) => {
                    consume_json_batch(
                        packet,
                        &runtime,
                        plan.plan(),
                        plan.source(),
                        JsonBatchConsumerLimits {
                            max_rows: 1,
                            max_bytes: 65536,
                            max_columns: 16,
                        },
                        None,
                        |row| {
                            rows.push(row.clone());
                            Ok(())
                        },
                    )
                    .unwrap();
                }
                OwnedBatchEvent::End(result) => {
                    result.unwrap();
                    break;
                }
            }
        }
        let mut receipt = receiver.into_delivery_receipt().unwrap();
        let result = receipt.finish_json_batches(&mut pending).unwrap();
        assert!(result.is_complete_result());
        assert_eq!(result.coverage.scope_id, catalog.scope_id());
        assert_eq!(result.response.emitted_rows.0, 2);
        assert_eq!(rows.len(), 2);
        assert_ne!(rows[0][1], rows[1][1]);
        assert!(matches!(&rows[0][1], Value::Utf16(_)));
    }
}
