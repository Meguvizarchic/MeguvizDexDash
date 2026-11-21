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

struct AlteredScan<'a> {
    base: &'a dyn FactSource,
    occurrence: String,
}

struct FlipAtEof<'a> {
    base: &'a dyn FactSource,
    changed: Cell<bool>,
    emit_error: bool,
}
impl FactSource for FlipAtEof<'_> {
    fn identity(&self) -> &str {
        if self.changed.get() {
            "changed-provider"
        } else {
            self.base.identity()
        }
    }
    fn snapshot_id(&self) -> &str {
        self.base.snapshot_id()
    }
    fn catalog_epoch(&self) -> DecimalU64 {
        self.base.catalog_epoch()
    }
    fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema> {
        self.base.relation_schema(relation)
    }
    fn require_layers(&self, layers: &BTreeSet<FactLayer>) -> MddResult<()> {
        self.base.require_layers(layers)
    }
    fn validate_entity(&self, entity: &EntityRef) -> MddResult<()> {
        self.base.validate_entity(entity)
    }
    fn scan<'a>(
        &'a self,
        _relation: &str,
    ) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>> {
        Ok(Box::new(std::iter::from_fn(move || {
            self.changed.set(true);
            self.emit_error
                .then(|| Err(error(ErrorCode::QuotaExceeded, "provider original fault")))
        })))
    }
    fn read_code_bytes(&self, entity: &EntityRef) -> MddResult<Option<&[u8]>> {
        self.base.read_code_bytes(entity)
    }
}

struct FlipDuringScan<'a> {
    base: &'a dyn FactSource,
    changed: Cell<bool>,
    emit_error: bool,
}

struct DropChangesIdentity<'a>(&'a Cell<bool>);
impl Iterator for DropChangesIdentity<'_> {
    type Item = MddResult<Row>;
    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}
impl Drop for DropChangesIdentity<'_> {
    fn drop(&mut self) {
        self.0.set(true);
    }
}
struct FlipOnIteratorDrop<'a> {
    base: &'a dyn FactSource,
    changed: Cell<bool>,
}
impl FactSource for FlipOnIteratorDrop<'_> {
    fn identity(&self) -> &str {
        if self.changed.get() {
            "changed-provider"
        } else {
            self.base.identity()
        }
    }
    fn snapshot_id(&self) -> &str {
        self.base.snapshot_id()
    }
    fn catalog_epoch(&self) -> DecimalU64 {
        self.base.catalog_epoch()
    }
    fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema> {
        self.base.relation_schema(relation)
    }
    fn require_layers(&self, layers: &BTreeSet<FactLayer>) -> MddResult<()> {
        self.base.require_layers(layers)
    }
    fn validate_entity(&self, entity: &EntityRef) -> MddResult<()> {
        self.base.validate_entity(entity)
    }
    fn scan<'a>(
        &'a self,
        _relation: &str,
    ) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>> {
        Ok(Box::new(DropChangesIdentity(&self.changed)))
    }
    fn read_code_bytes(&self, entity: &EntityRef) -> MddResult<Option<&[u8]>> {
        self.base.read_code_bytes(entity)
    }
}
impl FactSource for FlipDuringScan<'_> {
    fn identity(&self) -> &str {
        if self.changed.get() {
            "changed-provider"
        } else {
            self.base.identity()
        }
    }
    fn snapshot_id(&self) -> &str {
        self.base.snapshot_id()
    }
    fn catalog_epoch(&self) -> DecimalU64 {
        self.base.catalog_epoch()
    }
    fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema> {
        self.base.relation_schema(relation)
    }
    fn require_layers(&self, layers: &BTreeSet<FactLayer>) -> MddResult<()> {
        self.base.require_layers(layers)
    }
    fn validate_entity(&self, entity: &EntityRef) -> MddResult<()> {
        self.base.validate_entity(entity)
    }
    fn scan<'a>(
        &'a self,
        _relation: &str,
    ) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>> {
        self.changed.set(true);
        if self.emit_error {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "provider scan original fault",
            ));
        }
        Ok(Box::new(std::iter::empty()))
    }
    fn read_code_bytes(&self, entity: &EntityRef) -> MddResult<Option<&[u8]>> {
        self.base.read_code_bytes(entity)
    }
}

fn authority_fixture() -> (Arc<Snapshot>, ScopedCatalog) {
    let input = InputSpec {
        path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/generated/structured-035.dex"),
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Arc::new(Snapshot::capture(&[input], CaptureLimits::default()).unwrap());
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let metadata =
        Arc::new(MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap());
    let catalog = ScopedCatalog::native(
        &snapshot,
        &[&inventory],
        native(&snapshot, &[metadata]),
        InputSelection::AllCapturedInputs,
        limits(),
    )
    .unwrap();
    (snapshot, catalog)
}

#[test]
fn checked_source_detects_change_during_scan_before_limit_zero() {
    let (snapshot, catalog) = authority_fixture();
    let authority = catalog
        .entity_authority(EntityAuthorityLimits {
            max_occurrences: 1,
            max_definition_indices: 0,
            max_index_bytes: 4096,
        })
        .unwrap();
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let source = FlipDuringScan {
            base: catalog.base.source(),
            changed: Cell::new(false),
            emit_error: false,
        };
        let checked = authority
            .checked_source(&source, entity_check_limits())
            .unwrap();
        let mut query = scan(&snapshot, "strings");
        query.root = Node::Limit {
            input: Box::new(query.root),
            offset: DecimalU64(0),
            count: DecimalU64(0),
        };
        let plan = prepare(query, &checked).unwrap();
        let failure = super::super::execute(
            &plan,
            &checked,
            mode,
            &mut Control::new(ExecutionLimits::default()),
        )
        .err()
        .unwrap();
        assert_eq!(failure.code, ErrorCode::SourceChanged);
    }
    let source = FlipDuringScan {
        base: catalog.base.source(),
        changed: Cell::new(false),
        emit_error: true,
    };
    let checked = authority
        .checked_source(&source, entity_check_limits())
        .unwrap();
    let failure = checked.scan("strings").err().unwrap();
    assert_eq!(failure.code, ErrorCode::QuotaExceeded);
    assert_eq!(failure.message, "provider scan original fault");
}

#[test]
fn checked_source_rechecks_binding_before_scan_returns() {
    let (_, catalog) = authority_fixture();
    let authority = catalog
        .entity_authority(EntityAuthorityLimits {
            max_occurrences: 1,
            max_definition_indices: 0,
            max_index_bytes: 4096,
        })
        .unwrap();
    let source = FlipDuringScan {
        base: catalog.base.source(),
        changed: Cell::new(false),
        emit_error: false,
    };
    let checked = authority
        .checked_source(&source, entity_check_limits())
        .unwrap();
    let failure = checked
        .scan("strings")
        .err()
        .expect("source change must be reported before returning iterator");
    assert_eq!(failure.code, ErrorCode::SourceChanged);
    let source = FlipDuringScan {
        base: catalog.base.source(),
        changed: Cell::new(false),
        emit_error: true,
    };
    let checked = authority
        .checked_source(&source, entity_check_limits())
        .unwrap();
    let failure = checked.scan("strings").err().unwrap();
    assert_eq!(failure.code, ErrorCode::QuotaExceeded);
    assert_eq!(failure.message, "provider scan original fault");
}

#[test]
fn checked_source_records_change_before_iterator_drop_cancels_query() {
    struct CancelOnDrop(mdd_session::cancellation::QueryCancellation);
    impl Iterator for CancelOnDrop {
        type Item = MddResult<Row>;
        fn next(&mut self) -> Option<Self::Item> {
            None
        }
    }
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.cancel().unwrap();
        }
    }
    struct ChangingSource<'a> {
        base: &'a dyn FactSource,
        changed: Cell<bool>,
        cancel: std::cell::RefCell<Option<mdd_session::cancellation::QueryCancellation>>,
    }
    impl FactSource for ChangingSource<'_> {
        fn identity(&self) -> &str {
            if self.changed.get() {
                "changed-provider"
            } else {
                self.base.identity()
            }
        }
        fn snapshot_id(&self) -> &str {
            self.base.snapshot_id()
        }
        fn catalog_epoch(&self) -> DecimalU64 {
            self.base.catalog_epoch()
        }
        fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema> {
            self.base.relation_schema(relation)
        }
        fn require_layers(&self, layers: &BTreeSet<FactLayer>) -> MddResult<()> {
            self.base.require_layers(layers)
        }
        fn validate_entity(&self, entity: &EntityRef) -> MddResult<()> {
            self.base.validate_entity(entity)
        }
        fn scan<'a>(
            &'a self,
            _relation: &str,
        ) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>> {
            self.changed.set(true);
            Ok(Box::new(CancelOnDrop(
                self.cancel.borrow().clone().unwrap(),
            )))
        }
        fn read_code_bytes(&self, entity: &EntityRef) -> MddResult<Option<&[u8]>> {
            self.base.read_code_bytes(entity)
        }
    }
    let (snapshot, catalog) = authority_fixture();
    let authority = catalog
        .entity_authority(EntityAuthorityLimits {
            max_occurrences: 1,
            max_definition_indices: 0,
            max_index_bytes: 4096,
        })
        .unwrap();
    let source = ChangingSource {
        base: catalog.base.source(),
        changed: Cell::new(false),
        cancel: std::cell::RefCell::new(None),
    };
    let checked = authority
        .checked_source(&source, entity_check_limits())
        .unwrap();
    let plan = prepare(scan(&snapshot, "strings"), &checked).unwrap();
    let lifecycle = Lifecycle::new(ResourceLimits::default()).unwrap();
    let snapshot_handle = lifecycle.register_snapshot(Arc::clone(&snapshot)).unwrap();
    let session = lifecycle
        .open_session(&snapshot_handle, ResourceLimits::default())
        .unwrap();
    let query = lifecycle
        .prepare_query(
            &session,
            plan.runtime_binding().unwrap(),
            ResourceLimits::default(),
        )
        .unwrap();
    lifecycle.start_query(&session, &query, 1).unwrap();
    let cancel = lifecycle.cancellation_token(&query).unwrap();
    *source.cancel.borrow_mut() = Some(cancel.clone());
    let limits = BudgetLimits::default();
    let pool = BudgetPool::global("entity-first-error-global".into(), limits.clone())
        .unwrap()
        .child(
            cancel.worker_owner_id().unwrap(),
            BudgetScope::Worker,
            limits.clone(),
        )
        .unwrap()
        .child(session.id().into(), BudgetScope::Session, limits.clone())
        .unwrap()
        .child(query.id().into(), BudgetScope::Query, limits)
        .unwrap();
    let runtime = RuntimeBudget::new(pool, cancel).unwrap();
    let failure = authority
        .execute_checked(
            &plan,
            &source,
            ExecutionMode::Streaming,
            &mut Control::new(ExecutionLimits::default()).with_runtime(runtime.clone()),
            entity_check_limits(),
        )
        .err()
        .unwrap();
    assert_eq!(failure.code, ErrorCode::SourceChanged);
    assert_eq!(
        runtime.cancellation().status().unwrap().error.unwrap().code,
        ErrorCode::SourceChanged
    );
}

#[test]
fn scoped_entity_authority_rejects_altered_json_batch_before_delivery() {
    let (snapshot, catalog) = authority_fixture();
    let authority = catalog
        .entity_authority(EntityAuthorityLimits {
            max_occurrences: 1,
            max_definition_indices: 0,
            max_index_bytes: 4096,
        })
        .unwrap();
    let coverage = catalog
        .prepare(scan(&snapshot, "strings"))
        .unwrap()
        .coverage
        .clone();
    for (index, mode) in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ]
    .into_iter()
    .enumerate()
    {
        let altered = AlteredScan {
            base: catalog.base.source(),
            occurrence: "missing-occurrence".into(),
        };
        let checked = authority
            .checked_source(&altered, entity_check_limits())
            .unwrap();
        let plan = prepare(scan(&snapshot, "strings"), &checked).unwrap();
        let lifecycle = Lifecycle::new(ResourceLimits::default()).unwrap();
        let snapshot_handle = lifecycle.register_snapshot(Arc::clone(&snapshot)).unwrap();
        let session = lifecycle
            .open_session(&snapshot_handle, ResourceLimits::default())
            .unwrap();
        let binding = plan.runtime_binding().unwrap();
        let query = lifecycle
            .prepare_query(&session, binding.clone(), ResourceLimits::default())
            .unwrap();
        lifecycle.start_query(&session, &query, 1).unwrap();
        let cancel = lifecycle.cancellation_token(&query).unwrap();
        let limits = BudgetLimits::default();
        let pool = BudgetPool::global(format!("entity-auth-test-{index}"), limits.clone())
            .unwrap()
            .child(
                cancel.worker_owner_id().unwrap(),
                BudgetScope::Worker,
                limits.clone(),
            )
            .unwrap()
            .child(session.id().into(), BudgetScope::Session, limits.clone())
            .unwrap()
            .child(query.id().into(), BudgetScope::Query, limits)
            .unwrap();
        let runtime = RuntimeBudget::new(pool, cancel).unwrap();
        let other_plan = prepare(scan(&snapshot, "types"), &checked).unwrap();
        assert_eq!(
            authority
                .execute_checked(
                    &other_plan,
                    &altered,
                    mode,
                    &mut Control::new(ExecutionLimits::default()).with_runtime(runtime.clone()),
                    entity_check_limits()
                )
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        assert!(runtime.cancellation().status().unwrap().error.is_none());
        let (sender, mut receiver) = bounded_owned_batch_channel(&runtime, 4).unwrap();
        let identity = ResultIdentity {
            request_id: "entity-auth-test".into(),
            operation: "query".into(),
            profile: SCOPED_UNQUALIFIED_PROFILE.into(),
            sql_dialect: None,
            session_id: Some(session.id().into()),
            snapshot_id: Some(snapshot.manifest().snapshot_id.clone()),
            catalog_epoch: Some(DecimalU64(0)),
            query_id: Some(query.id().into()),
            schema_id: Some(binding.schema_id),
        };
        let terminal = TerminalBuilder::new(identity, coverage.clone()).unwrap();
        let mut control = Control::new(ExecutionLimits::default()).with_runtime(runtime.clone());
        let mut pending = authority
            .execute_json_batches_checked(
                &plan,
                &altered,
                mode,
                &mut control,
                terminal,
                &sender,
                JsonBatchLimits {
                    max_rows: 10,
                    max_bytes: 65536,
                },
                entity_check_limits(),
            )
            .unwrap();
        match receiver.receive().unwrap() {
            OwnedBatchEvent::End(Err(error)) => {
                assert_eq!(error.code, ErrorCode::InvalidArgument)
            }
            _ => panic!("foreign occurrence must not deliver a successful batch"),
        }
        let mut receipt = receiver.into_delivery_receipt().unwrap();
        let envelope = receipt.finish_json_batches(&mut pending).unwrap();
        assert!(!envelope.is_complete_result());
        assert_eq!(envelope.error.unwrap().code, ErrorCode::InvalidArgument);
        assert!(!runtime.cancellation().status().unwrap().delivery_complete);
    }
}

#[test]
fn runtime_bound_checked_source_must_not_stop_a_different_query() {
    let (snapshot, catalog) = authority_fixture();
    let authority = catalog
        .entity_authority(EntityAuthorityLimits {
            max_occurrences: 1,
            max_definition_indices: 0,
            max_index_bytes: 4096,
        })
        .unwrap();
    let altered = AlteredScan {
        base: catalog.base.source(),
        occurrence: "missing-occurrence".into(),
    };
    let unbound = authority
        .checked_source(&altered, entity_check_limits())
        .unwrap();
    let plan = prepare(scan(&snapshot, "strings"), &unbound).unwrap();
    let lifecycle = Lifecycle::new(ResourceLimits::default()).unwrap();
    let snapshot_handle = lifecycle.register_snapshot(Arc::clone(&snapshot)).unwrap();
    let session = lifecycle
        .open_session(&snapshot_handle, ResourceLimits::default())
        .unwrap();
    let make_runtime = |label: &str| {
        let query = lifecycle
            .prepare_query(
                &session,
                plan.runtime_binding().unwrap(),
                ResourceLimits::default(),
            )
            .unwrap();
        lifecycle.start_query(&session, &query, 1).unwrap();
        let cancel = lifecycle.cancellation_token(&query).unwrap();
        let limits = BudgetLimits::default();
        let pool = BudgetPool::global(format!("runtime-swap-{label}"), limits.clone())
            .unwrap()
            .child(
                cancel.worker_owner_id().unwrap(),
                BudgetScope::Worker,
                limits.clone(),
            )
            .unwrap()
            .child(session.id().into(), BudgetScope::Session, limits.clone())
            .unwrap()
            .child(query.id().into(), BudgetScope::Query, limits)
            .unwrap();
        RuntimeBudget::new(pool, cancel).unwrap()
    };
    let runtime_a = make_runtime("a");
    let runtime_b = make_runtime("b");
    let failure = authority
        .execute_checked(
            &plan,
            &altered,
            ExecutionMode::Streaming,
            &mut Control::new(ExecutionLimits::default()).with_runtime(runtime_b.clone()),
            entity_check_limits(),
        )
        .err()
        .unwrap();
    assert_eq!(failure.code, ErrorCode::InvalidArgument);
    assert!(
        runtime_a.cancellation().status().unwrap().error.is_none(),
        "query A must not be stopped by query B"
    );
}

#[test]
fn strict_limit_drops_scan_before_return_or_json_end() {
    struct FlipRows<'a> {
        rows: Box<dyn Iterator<Item = MddResult<Row>> + 'a>,
        changed: &'a Cell<bool>,
        flip: bool,
    }
    impl Iterator for FlipRows<'_> {
        type Item = MddResult<Row>;
        fn next(&mut self) -> Option<Self::Item> {
            self.rows.next()
        }
    }
    impl Drop for FlipRows<'_> {
        fn drop(&mut self) {
            if self.flip {
                self.changed.set(true);
            }
        }
    }
    struct FlipSource<'a> {
        base: &'a dyn FactSource,
        changed: Cell<bool>,
        flip: bool,
    }
    impl FactSource for FlipSource<'_> {
        fn identity(&self) -> &str {
            if self.changed.get() {
                "changed-provider"
            } else {
                self.base.identity()
            }
        }
        fn snapshot_id(&self) -> &str {
            self.base.snapshot_id()
        }
        fn catalog_epoch(&self) -> DecimalU64 {
            self.base.catalog_epoch()
        }
        fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema> {
            self.base.relation_schema(relation)
        }
        fn require_layers(&self, layers: &BTreeSet<FactLayer>) -> MddResult<()> {
            self.base.require_layers(layers)
        }
        fn validate_entity(&self, entity: &EntityRef) -> MddResult<()> {
            self.base.validate_entity(entity)
        }
        fn scan<'a>(
            &'a self,
            relation: &str,
        ) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>> {
            Ok(Box::new(FlipRows {
                rows: self.base.scan(relation)?,
                changed: &self.changed,
                flip: self.flip,
            }))
        }
        fn read_code_bytes(&self, entity: &EntityRef) -> MddResult<Option<&[u8]>> {
            self.base.read_code_bytes(entity)
        }
    }
    let (snapshot, catalog) = authority_fixture();
    let authority = catalog
        .entity_authority(EntityAuthorityLimits {
            max_occurrences: 1,
            max_definition_indices: 0,
            max_index_bytes: 4096,
        })
        .unwrap();
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        for (json, flip) in [(false, true), (true, true), (false, false), (true, false)] {
            let source = FlipSource {
                base: catalog.base.source(),
                changed: Cell::new(false),
                flip,
            };
            let checked = authority
                .checked_source(&source, entity_check_limits())
                .unwrap();
            let mut query_ir = scan(&snapshot, "strings");
            query_ir.root = Node::Limit {
                input: Box::new(query_ir.root),
                offset: DecimalU64(0),
                count: DecimalU64(1),
            };
            let coverage = catalog.prepare(query_ir.clone()).unwrap().coverage.clone();
            let plan = prepare(query_ir, &checked).unwrap();
            let lifecycle = Lifecycle::new(ResourceLimits::default()).unwrap();
            let snapshot_handle = lifecycle.register_snapshot(Arc::clone(&snapshot)).unwrap();
            let session = lifecycle
                .open_session(&snapshot_handle, ResourceLimits::default())
                .unwrap();
            let binding = plan.runtime_binding().unwrap();
            let query = lifecycle
                .prepare_query(&session, binding.clone(), ResourceLimits::default())
                .unwrap();
            lifecycle.start_query(&session, &query, 1).unwrap();
            let cancel = lifecycle.cancellation_token(&query).unwrap();
            let limits = BudgetLimits::default();
            let pool = BudgetPool::global("strict-limit-global".into(), limits.clone())
                .unwrap()
                .child(
                    cancel.worker_owner_id().unwrap(),
                    BudgetScope::Worker,
                    limits.clone(),
                )
                .unwrap()
                .child(session.id().into(), BudgetScope::Session, limits.clone())
                .unwrap()
                .child(query.id().into(), BudgetScope::Query, limits)
                .unwrap();
            let runtime = RuntimeBudget::new(pool, cancel).unwrap();
            let mut control =
                Control::new(ExecutionLimits::default()).with_runtime(runtime.clone());
            if json {
                let (sender, mut receiver) = bounded_owned_batch_channel(&runtime, 4).unwrap();
                let identity = ResultIdentity {
                    request_id: "strict-limit".into(),
                    operation: "query".into(),
                    profile: SCOPED_UNQUALIFIED_PROFILE.into(),
                    sql_dialect: None,
                    session_id: Some(session.id().into()),
                    snapshot_id: Some(snapshot.manifest().snapshot_id.clone()),
                    catalog_epoch: Some(DecimalU64(0)),
                    query_id: Some(query.id().into()),
                    schema_id: Some(binding.schema_id),
                };
                let terminal = TerminalBuilder::new(identity, coverage).unwrap();
                let mut pending = authority
                    .execute_json_batches_checked(
                        &plan,
                        &source,
                        mode,
                        &mut control,
                        terminal,
                        &sender,
                        JsonBatchLimits {
                            max_rows: 10,
                            max_bytes: 65536,
                        },
                        entity_check_limits(),
                    )
                    .unwrap();
                loop {
                    match receiver.receive().unwrap() {
                        OwnedBatchEvent::End(Err(error)) => {
                            assert!(flip, "unexpected failure: {error:?}, mode: {mode:?}");
                            assert_eq!(error.code, ErrorCode::SourceChanged);
                            break;
                        }
                        OwnedBatchEvent::End(Ok(())) => {
                            assert!(!flip, "source change must precede successful End");
                            break;
                        }
                        OwnedBatchEvent::Data(packet) => {
                            packet.acknowledge().unwrap();
                        }
                    }
                }
                let mut receipt = receiver.into_delivery_receipt().unwrap();
                let result = receipt.finish_json_batches(&mut pending).unwrap();
                assert_eq!(result.is_complete_result(), !flip);
            } else {
                let result = authority.execute_checked(
                    &plan,
                    &source,
                    mode,
                    &mut control,
                    entity_check_limits(),
                );
                if flip {
                    assert_eq!(
                        result.err().expect("short scan drop changed identity").code,
                        ErrorCode::SourceChanged
                    );
                } else {
                    assert_eq!(result.unwrap().rows().len(), 1);
                }
            }
            let status = runtime.cancellation().status().unwrap();
            if flip {
                assert_eq!(status.error.unwrap().code, ErrorCode::SourceChanged);
            } else {
                assert!(status.error.is_none());
            }
        }
    }
}

#[test]
fn checked_source_detects_binding_change_from_eof_iterator_drop() {
    let (snapshot, catalog) = authority_fixture();
    let authority = catalog
        .entity_authority(EntityAuthorityLimits {
            max_occurrences: 1,
            max_definition_indices: 0,
            max_index_bytes: 4096,
        })
        .unwrap();
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let source = FlipOnIteratorDrop {
            base: catalog.base.source(),
            changed: Cell::new(false),
        };
        let checked = authority
            .checked_source(&source, entity_check_limits())
            .unwrap();
        let plan = prepare(scan(&snapshot, "strings"), &checked).unwrap();
        let failure = super::super::execute(
            &plan,
            &checked,
            mode,
            &mut Control::new(ExecutionLimits::default()),
        )
        .err()
        .expect("iterator drop changed provider identity");
        assert_eq!(failure.code, ErrorCode::SourceChanged);
    }
}
impl FactSource for AlteredScan<'_> {
    fn identity(&self) -> &str {
        self.base.identity()
    }
    fn snapshot_id(&self) -> &str {
        self.base.snapshot_id()
    }
    fn catalog_epoch(&self) -> DecimalU64 {
        self.base.catalog_epoch()
    }
    fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema> {
        self.base.relation_schema(relation)
    }
    fn require_layers(&self, layers: &BTreeSet<FactLayer>) -> MddResult<()> {
        self.base.require_layers(layers)
    }
    fn validate_entity(&self, entity: &EntityRef) -> MddResult<()> {
        self.base.validate_entity(entity)
    }
    fn scan<'a>(
        &'a self,
        relation: &str,
    ) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>> {
        Ok(Box::new(self.base.scan(relation)?.map(|result| {
            result.map(|mut row| {
                if let Some(Value::Entity(entity)) = row.first_mut() {
                    entity.dex_occurrence_id = self.occurrence.clone().into();
                }
                row
            })
        })))
    }
    fn read_code_bytes(&self, entity: &EntityRef) -> MddResult<Option<&[u8]>> {
        self.base.read_code_bytes(entity)
    }
}

fn entity_check_limits() -> EntityCheckLimits {
    EntityCheckLimits {
        max_rows: 1000,
        max_entity_checks: 1000,
        max_lookup_steps: 10000,
        max_identity_bytes: 1_000_000,
    }
}

#[test]
fn runtime_query_steps_bound_scoped_entity_checks() {
    let (snapshot, catalog) = authority_fixture();
    let authority = catalog
        .entity_authority(EntityAuthorityLimits {
            max_occurrences: 1,
            max_definition_indices: 0,
            max_index_bytes: 4096,
        })
        .unwrap();
    let source = catalog.base.source();
    let prepared_source = authority
        .checked_source(source, entity_check_limits())
        .unwrap();
    let plan = prepare(scan(&snapshot, "strings"), &prepared_source).unwrap();
    let lifecycle = Lifecycle::new(ResourceLimits::default()).unwrap();
    let snapshot_handle = lifecycle.register_snapshot(Arc::clone(&snapshot)).unwrap();
    let session = lifecycle
        .open_session(&snapshot_handle, ResourceLimits::default())
        .unwrap();
    let query = lifecycle
        .prepare_query(
            &session,
            plan.runtime_binding().unwrap(),
            ResourceLimits::default(),
        )
        .unwrap();
    lifecycle.start_query(&session, &query, 1).unwrap();
    let cancel = lifecycle.cancellation_token(&query).unwrap();
    let budget_limits = BudgetLimits::default().with(Resource::QuerySteps, 0);
    let pool = BudgetPool::global("entity-steps-global".into(), budget_limits.clone())
        .unwrap()
        .child(
            cancel.worker_owner_id().unwrap(),
            BudgetScope::Worker,
            budget_limits.clone(),
        )
        .unwrap()
        .child(
            session.id().into(),
            BudgetScope::Session,
            budget_limits.clone(),
        )
        .unwrap()
        .child(query.id().into(), BudgetScope::Query, budget_limits)
        .unwrap();
    let runtime = RuntimeBudget::new(pool, cancel).unwrap();
    let checked = authority
        .checked_source_with_runtime(source, &plan, &runtime, entity_check_limits())
        .unwrap();
    let entity = EntityRef {
        snapshot_id: snapshot.manifest().snapshot_id.clone().into(),
        dex_occurrence_id: authority.occurrences[0]
            .metadata
            .source()
            .dex_occurrence_id
            .clone(),
        kind: EntityKind::String,
        local_index: 0,
    };
    let failure = checked.validate_entity(&entity).unwrap_err();
    assert_eq!(failure.code, ErrorCode::QuotaExceeded);
    assert_eq!(
        runtime.cancellation().status().unwrap().error.unwrap().code,
        ErrorCode::QuotaExceeded
    );
}

#[test]
fn runtime_scoped_entity_steps_are_counted_once_and_observe_cancel() {
    let (snapshot, catalog) = authority_fixture();
    let authority = catalog
        .entity_authority(EntityAuthorityLimits {
            max_occurrences: 1,
            max_definition_indices: 0,
            max_index_bytes: 4096,
        })
        .unwrap();
    let source = catalog.base.source();
    let unbound = authority
        .checked_source(source, entity_check_limits())
        .unwrap();
    let plan = prepare(scan(&snapshot, "strings"), &unbound).unwrap();
    let lifecycle = Lifecycle::new(ResourceLimits::default()).unwrap();
    let snapshot_handle = lifecycle.register_snapshot(Arc::clone(&snapshot)).unwrap();
    let session = lifecycle
        .open_session(&snapshot_handle, ResourceLimits::default())
        .unwrap();
    let query = lifecycle
        .prepare_query(
            &session,
            plan.runtime_binding().unwrap(),
            ResourceLimits::default(),
        )
        .unwrap();
    lifecycle.start_query(&session, &query, 1).unwrap();
    let cancel = lifecycle.cancellation_token(&query).unwrap();
    let limits = BudgetLimits::default();
    let pool = BudgetPool::global("entity-steps-count-global".into(), limits.clone())
        .unwrap()
        .child(
            cancel.worker_owner_id().unwrap(),
            BudgetScope::Worker,
            limits.clone(),
        )
        .unwrap()
        .child(session.id().into(), BudgetScope::Session, limits.clone())
        .unwrap()
        .child(query.id().into(), BudgetScope::Query, limits)
        .unwrap();
    let runtime = RuntimeBudget::new(pool, cancel).unwrap();
    let checked = authority
        .checked_source_with_runtime(source, &plan, &runtime, entity_check_limits())
        .unwrap();
    let entity = EntityRef {
        snapshot_id: snapshot.manifest().snapshot_id.clone().into(),
        dex_occurrence_id: authority.occurrences[0]
            .metadata
            .source()
            .dex_occurrence_id
            .clone(),
        kind: EntityKind::String,
        local_index: 0,
    };
    checked.validate_entity(&entity).unwrap();
    let occurrence_steps = search_step_bound(authority.occurrences.len());
    let entity_steps = 1
        + occurrence_steps
        + entity.snapshot_id.len() as u64
        + entity.dex_occurrence_id.len() as u64 * occurrence_steps;
    let binding_steps = 1 + source.identity().len() as u64 + source.snapshot_id().len() as u64;
    let used = runtime.pool().usage().unwrap().used[&Resource::QuerySteps].0;
    assert_eq!(used, 2 * binding_steps + entity_steps);
    runtime.cancellation().cancel().unwrap();
    assert_eq!(
        checked.validate_entity(&entity).unwrap_err().code,
        ErrorCode::Cancelled
    );
    assert_eq!(
        runtime.pool().usage().unwrap().used[&Resource::QuerySteps].0,
        used
    );
    assert_eq!(
        runtime.cancellation().status().unwrap().error.unwrap().code,
        ErrorCode::Cancelled
    );
}

#[test]
fn scoped_entity_authority_rejects_altered_scan_and_bounds_checks() {
    let input = InputSpec {
        path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/generated/structured-035.dex"),
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let inventories: Vec<_> = snapshot
        .sources()
        .iter()
        .map(|source| {
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
                .unwrap()
        })
        .collect();
    let metadata: Vec<_> = inventories
        .iter()
        .map(|inventory| {
            Arc::new(
                MetadataFacts::build(&snapshot, inventory, 0, StringLimits::default()).unwrap(),
            )
        })
        .collect();
    assert!(!metadata[0].strings().is_empty());
    let one = [inventories.first().unwrap()];
    let catalog = ScopedCatalog::native(
        &snapshot,
        &one,
        native(&snapshot, &metadata[..1]),
        InputSelection::SelectedInputs,
        limits(),
    )
    .unwrap();
    let authority_limits = EntityAuthorityLimits {
        max_occurrences: 1,
        max_definition_indices: 0,
        max_index_bytes: 4096,
    };
    assert_eq!(
        catalog
            .entity_authority(EntityAuthorityLimits {
                max_occurrences: 0,
                ..authority_limits
            })
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        catalog
            .entity_authority(EntityAuthorityLimits {
                max_index_bytes: 0,
                ..authority_limits
            })
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    let authority = catalog.entity_authority(authority_limits).unwrap();
    let base = catalog.base.source();
    let query = scan(&snapshot, "strings");
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let checked = authority
            .checked_source(base, entity_check_limits())
            .unwrap();
        let plan = prepare(query.clone(), &checked).unwrap();
        let result = super::super::execute(
            &plan,
            &checked,
            mode,
            &mut Control::new(ExecutionLimits::default()),
        )
        .unwrap();
        assert!(!result.rows().is_empty());
        for wrong in [
            "missing-occurrence",
            metadata[1].source().dex_occurrence_id.as_str(),
        ] {
            let altered = AlteredScan {
                base,
                occurrence: wrong.into(),
            };
            let checked = authority
                .checked_source(&altered, entity_check_limits())
                .unwrap();
            let plan = prepare(query.clone(), &checked).unwrap();
            let failure = super::super::execute(
                &plan,
                &checked,
                mode,
                &mut Control::new(ExecutionLimits::default()),
            )
            .err()
            .unwrap();
            assert_eq!(failure.code, ErrorCode::InvalidArgument);
            assert_eq!(
                failure.message,
                "entity occurrence is outside selected scope"
            );
        }
    }
    let entity = EntityRef {
        snapshot_id: snapshot.manifest().snapshot_id.clone().into(),
        dex_occurrence_id: metadata[0].source().dex_occurrence_id.clone(),
        kind: EntityKind::String,
        local_index: u32::MAX,
    };
    let checked = authority
        .checked_source(base, entity_check_limits())
        .unwrap();
    assert_eq!(
        checked.validate_entity(&entity).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    let mut missing_definition = entity.clone();
    missing_definition.kind = EntityKind::MethodDefinition;
    missing_definition.local_index = 0;
    assert_eq!(
        checked
            .validate_entity(&missing_definition)
            .unwrap_err()
            .code,
        ErrorCode::IncompleteFacts
    );
    for constrained in [
        EntityCheckLimits {
            max_rows: 0,
            ..entity_check_limits()
        },
        EntityCheckLimits {
            max_entity_checks: 0,
            ..entity_check_limits()
        },
        EntityCheckLimits {
            max_lookup_steps: 0,
            ..entity_check_limits()
        },
    ] {
        let checked = authority.checked_source(base, constrained).unwrap();
        let mut rows = checked.scan("strings").unwrap();
        assert_eq!(
            rows.next().unwrap().err().unwrap().code,
            ErrorCode::QuotaExceeded
        );
    }
    assert_eq!(
        authority
            .checked_source(
                base,
                EntityCheckLimits {
                    max_identity_bytes: 0,
                    ..entity_check_limits()
                }
            )
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    for emit_error in [false, true] {
        let source = FlipAtEof {
            base,
            changed: Cell::new(false),
            emit_error,
        };
        let checked = authority
            .checked_source(&source, entity_check_limits())
            .unwrap();
        let mut rows = checked.scan("strings").unwrap();
        let failure = rows.next().unwrap().err().unwrap();
        assert_eq!(
            failure.code,
            if emit_error {
                ErrorCode::QuotaExceeded
            } else {
                ErrorCode::SourceChanged
            }
        );
        if emit_error {
            assert_eq!(failure.message, "provider original fault");
        }
        assert!(rows.next().is_none());
    }
}

#[test]
fn scoped_entity_authority_distinguishes_definitions_from_references() {
    let input = InputSpec {
        path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/definitions/generated/definitions-035.dex"),
        kind: InputKind::RawDex,
        expected_sha256: None,
    };
    let snapshot = Snapshot::capture(&[input], CaptureLimits::default()).unwrap();
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .unwrap();
    let metadata =
        Arc::new(MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap());
    let definitions =
        Arc::new(DefinitionFacts::build((*metadata).clone(), DefinitionLimits::default()).unwrap());
    let data = definitions.definitions();
    let method = data
        .method_definitions
        .first()
        .expect("fixture needs a method definition")
        .method_idx;
    let missing = data
        .method_references
        .iter()
        .map(|value| value.method_idx)
        .find(|index| {
            !data
                .method_definitions
                .iter()
                .any(|value| value.method_idx == *index)
        })
        .expect("fixture needs a reference without a definition");
    let count =
        u64::try_from(data.field_definitions.len() + data.method_definitions.len()).unwrap();
    let native = NativeCatalog::new(
        snapshot.manifest().snapshot_id.clone(),
        DecimalU64(0),
        vec![super::super::facts::OccurrenceFacts {
            metadata: Arc::clone(&metadata),
            definitions: Some(Arc::clone(&definitions)),
            code: None,
        }],
    )
    .unwrap();
    let catalog = ScopedCatalog::native(
        &snapshot,
        &[&inventory],
        native,
        InputSelection::AllCapturedInputs,
        limits(),
    )
    .unwrap();
    let bound = EntityAuthorityLimits {
        max_occurrences: 1,
        max_definition_indices: count,
        max_index_bytes: 65536,
    };
    assert_eq!(
        catalog
            .entity_authority(EntityAuthorityLimits {
                max_definition_indices: count - 1,
                ..bound
            })
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    let authority = catalog.entity_authority(bound).unwrap();
    let checked = authority
        .checked_source(catalog.base.source(), entity_check_limits())
        .unwrap();
    let entity = |kind, local_index| EntityRef {
        snapshot_id: snapshot.manifest().snapshot_id.clone().into(),
        dex_occurrence_id: metadata.source().dex_occurrence_id.clone(),
        kind,
        local_index,
    };
    checked
        .validate_entity(&entity(EntityKind::MethodDefinition, method))
        .unwrap();
    checked
        .validate_entity(&entity(EntityKind::MethodReference, missing))
        .unwrap();
    assert_eq!(
        checked
            .validate_entity(&entity(EntityKind::MethodDefinition, missing))
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
}

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
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
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
                    DefinitionFacts::build(metadata.clone(), DefinitionLimits::default()).unwrap();
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
    let snapshot = Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
    let inventories: Vec<_> = snapshot
        .sources()
        .iter()
        .map(|source| {
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
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
        let code = CodeFacts::build_all_code_items(&snapshot, inventory, 0, CodeLimits::default())
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
