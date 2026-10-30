use super::*;
use crate::{
    budget::{BudgetLimits, BudgetPool, BudgetScope, QueueEvent, RuntimeBudget, bounded_channel},
    executor::facts::{MemoryCatalog, Table},
};
use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
use mdd_session::{Lifecycle, ResourceLimits, SessionHandle, cancellation::QueryCancellation};
use mdd_types::{
    Completeness, Coverage, OperationStatus,
    result::{ResultIdentity, StreamVerifier, TerminalBuilder},
};
use std::{path::PathBuf, sync::Arc};

struct Fixture {
    lifecycle: Lifecycle,
    session: SessionHandle,
    source: MemoryCatalog,
    prepared: PreparedQuery,
    cancel: QueryCancellation,
    runtime: RuntimeBudget,
    global_budget: BudgetPool,
    worker_budget: BudgetPool,
    session_budget: BudgetPool,
}
fn setup(limits: BudgetLimits) -> Fixture {
    setup_with_rows(limits, 4)
}
fn setup_with_rows(limits: BudgetLimits, rows: u64) -> Fixture {
    setup_with_schema(
        limits,
        DataType::U64,
        (0..rows).map(|n| vec![Value::U64(DecimalU64(n))]).collect(),
    )
}
fn setup_with_schema(limits: BudgetLimits, data_type: DataType, rows: Vec<Row>) -> Fixture {
    let snapshot = Arc::new(
        Snapshot::capture(
            &[InputSpec {
                path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/fixtures/generated/minimal-035.dex"),
                kind: InputKind::RawDex,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
        )
        .unwrap(),
    );
    let snapshot_id = snapshot.manifest().snapshot_id.clone();
    let lifecycle = Lifecycle::new(ResourceLimits::default()).unwrap();
    let handle = lifecycle.register_snapshot(snapshot).unwrap();
    let session = lifecycle
        .open_session(&handle, ResourceLimits::default())
        .unwrap();
    let source = MemoryCatalog::new(
        snapshot_id.clone(),
        DecimalU64(0),
        BTreeMap::from([(
            "rows".into(),
            Table {
                columns: vec![Column {
                    id: "n".into(),
                    display_name: "n".into(),
                    data_type,
                    nullable: false,
                }],
                required_layers: vec![FactLayer::Structure],
                rows,
            },
        )]),
        BTreeSet::from([FactLayer::Structure]),
    )
    .unwrap();
    let prepared = prepare(
        QueryIr {
            schema_version: IR_VERSION.into(),
            text_semantics: TEXT_VERSION.into(),
            snapshot_id,
            catalog_epoch: DecimalU64(0),
            require_stable_order: false,
            root: Node::Scan {
                relation: "rows".into(),
            },
        },
        &source,
    )
    .unwrap();
    let query = lifecycle
        .prepare_query(
            &session,
            prepared.runtime_binding().unwrap(),
            ResourceLimits::default(),
        )
        .unwrap();
    lifecycle.start_query(&session, &query, 1).unwrap();
    let cancel = lifecycle.cancellation_token(&query).unwrap();
    let global = BudgetPool::global("g".into(), limits.clone()).unwrap();
    let worker = global
        .child(
            cancel.worker_owner_id().unwrap(),
            BudgetScope::Worker,
            limits.clone(),
        )
        .unwrap();
    let session_budget = worker
        .child(session.id().into(), BudgetScope::Session, limits.clone())
        .unwrap();
    let pool = session_budget
        .child(query.id().into(), BudgetScope::Query, limits)
        .unwrap();
    let runtime = RuntimeBudget::new(pool, cancel.clone()).unwrap();
    Fixture {
        lifecycle,
        session,
        source,
        prepared,
        cancel,
        runtime,
        global_budget: global,
        worker_budget: worker,
        session_budget,
    }
}

#[test]
fn runtime_budget_rejects_different_session_or_worker_ancestry() {
    let fixture = setup(BudgetLimits::default());
    for (worker_id, session_id) in [
        (
            fixture.cancel.worker_owner_id().unwrap(),
            "different-session".to_owned(),
        ),
        (
            "different-worker".to_owned(),
            fixture.session.id().to_owned(),
        ),
    ] {
        let limits = BudgetLimits::default();
        let global = BudgetPool::global("separate-root".into(), limits.clone()).unwrap();
        let worker = global
            .child(worker_id, BudgetScope::Worker, limits.clone())
            .unwrap();
        let session = worker
            .child(session_id, BudgetScope::Session, limits.clone())
            .unwrap();
        let pool = session
            .child(
                fixture.cancel.query_handle().id().into(),
                BudgetScope::Query,
                limits,
            )
            .unwrap();
        assert_eq!(
            RuntimeBudget::new(pool, fixture.cancel.clone())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
    }
}

#[test]
fn queue_receive_deadline_keeps_original_terminal_after_receiver_drop() {
    let limits = BudgetLimits::default().deadlines(0, 60_000).unwrap();
    let f = setup_with_rows(limits, 0);
    let (_sender, mut receiver) =
        bounded_channel::<Row>(f.runtime.pool().clone(), Some(f.cancel.clone()), 1).unwrap();
    let error = receiver.receive().err().unwrap();
    assert_eq!(error.code, ErrorCode::DeadlineExceeded);
    drop(receiver);
    let terminal = f.cancel.status().unwrap().error.unwrap();
    assert_eq!(terminal.code, ErrorCode::DeadlineExceeded);
    assert_eq!(terminal.stage, error.stage);
    assert_eq!(terminal.details, error.details);
}

#[test]
fn queue_deadline_cannot_replace_prior_cancel_or_worker_loss() {
    for worker_lost in [false, true] {
        let limits = BudgetLimits::default().deadlines(0, 60_000).unwrap();
        let f = setup_with_rows(limits, 0);
        let (_sender, mut receiver) =
            bounded_channel::<Row>(f.runtime.pool().clone(), Some(f.cancel.clone()), 1).unwrap();
        let original = if worker_lost {
            f.lifecycle.worker_lost("controlled loss").unwrap();
            ErrorCode::WorkerLost
        } else {
            f.cancel.cancel().unwrap();
            ErrorCode::Cancelled
        };
        assert_eq!(receiver.receive().err().unwrap().code, original);
        drop(receiver);
        assert_eq!(f.cancel.status().unwrap().error.unwrap().code, original);
    }
}

#[test]
fn concurrent_execution_claims_have_exactly_one_winner() {
    let fixture = setup(BudgetLimits::default());
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let barrier = Arc::clone(&barrier);
        let token = fixture.cancel.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            token.claim_execution()
        }));
    }
    barrier.wait();
    let outcomes: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome
                .as_ref()
                .is_err_and(|error| error.code == ErrorCode::InvalidArgument))
            .count(),
        1
    );
    assert!(fixture.cancel.status().unwrap().error.is_none());
}
fn terminal(f: &Fixture) -> TerminalBuilder {
    TerminalBuilder::new(
        ResultIdentity {
            request_id: "runtime-request".into(),
            operation: "query".into(),
            profile: "mdd-native-v1-unqualified".into(),
            sql_dialect: None,
            session_id: Some(f.session.id().into()),
            snapshot_id: Some(f.source.snapshot_id().into()),
            catalog_epoch: Some(DecimalU64(0)),
            query_id: Some(f.cancel.query_handle().id().into()),
            schema_id: Some(f.prepared.runtime_binding().unwrap().schema_id),
        },
        Coverage {
            scope_id: "generic-owned-test-table".into(),
            input: Completeness::Complete,
            facts: Completeness::Complete,
            required_layers: vec!["structure".into()],
            issues: Vec::new(),
        },
    )
    .unwrap()
}

#[test]
fn nonpristine_terminal_is_rejected_before_queue_claim() {
    for mutation in ["zero_batch", "nonzero_batch", "computed", "failed"] {
        let f = setup_with_rows(BudgetLimits::default(), 1);
        let (sender, mut receiver) =
            bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
        let mut builder = terminal(&f);
        match mutation {
            "zero_batch" => builder.record_batch(0, 0).unwrap(),
            "nonzero_batch" => builder.record_batch(0, 1).unwrap(),
            "computed" => builder.computation_complete(0).unwrap(),
            "failed" => {
                builder
                    .fail(
                        MddError::new(ErrorCode::InternalFault, "test", "already terminal"),
                        false,
                        None,
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let result = execute_into(
            &f.prepared,
            &f.source,
            ExecutionMode::Streaming,
            &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
            builder,
            &sender,
        );
        match result {
            Err(error) => {
                assert_eq!(error.code, ErrorCode::InvalidArgument, "{mutation}");
                assert_eq!(error.message, "TERMINAL_NOT_FRESH", "{mutation}");
            }
            Ok(mut pending) => {
                // Capture the actual old behavior rather than treating an accepted
                // nonfresh builder as a harmless test-only state.
                if let QueueEvent::Data(packet) = receiver.receive().unwrap() {
                    packet.acknowledge().unwrap();
                }
                let _ = receiver.receive().unwrap();
                let mut receipt = receiver.into_delivery_receipt().unwrap();
                let error = receipt.finish(&mut pending).unwrap_err();
                drop(pending);
                let status = f.cancel.status().unwrap();
                panic!("{mutation}: execute accepted; receipt={error:?}; lifecycle={status:?}");
            }
        }
        let status = f.cancel.status().unwrap();
        assert!(
            status.error.is_none(),
            "{mutation}: preflight poisoned the query"
        );
        let mut pending = execute_into(
            &f.prepared,
            &f.source,
            ExecutionMode::Streaming,
            &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
            terminal(&f),
            &sender,
        )
        .unwrap();
        let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
            panic!("{mutation}: fresh query lost its row")
        };
        packet.acknowledge().unwrap();
        assert!(matches!(
            receiver.receive().unwrap(),
            QueueEvent::End(Ok(()))
        ));
        let mut receipt = receiver.into_delivery_receipt().unwrap();
        assert!(receipt.finish(&mut pending).unwrap().is_complete_result());
    }
}

#[test]
fn queue_consumer_receives_original_required_facts_failure_end() {
    struct FailedSource<'a>(&'a MemoryCatalog);
    impl FactSource for FailedSource<'_> {
        fn identity(&self) -> &str {
            self.0.identity()
        }
        fn snapshot_id(&self) -> &str {
            self.0.snapshot_id()
        }
        fn catalog_epoch(&self) -> DecimalU64 {
            self.0.catalog_epoch()
        }
        fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema> {
            self.0.relation_schema(relation)
        }
        fn require_layers(&self, _: &BTreeSet<FactLayer>) -> MddResult<()> {
            Err(MddError::new(
                ErrorCode::InvalidInput,
                "facts.test",
                "required producer corrupt",
            )
            .detail("reason", "CORRUPT_FACTS"))
        }
        fn validate_entity(&self, entity: &mdd_facts::EntityRef) -> MddResult<()> {
            self.0.validate_entity(entity)
        }
        fn scan<'a>(
            &'a self,
            relation: &str,
        ) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>> {
            self.0.scan(relation)
        }
        fn read_code_bytes(&self, entity: &mdd_facts::EntityRef) -> MddResult<Option<&[u8]>> {
            self.0.read_code_bytes(entity)
        }
    }
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &FailedSource(&f.source),
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("missing original error end")
    };
    let error = end.unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert_eq!(error.details["reason"], "CORRUPT_FACTS");
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    let terminal = receipt.finish(&mut pending).unwrap();
    assert_eq!(terminal.error.unwrap().code, ErrorCode::InvalidInput);
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn queue_accounts_owned_row_capacity_separately_from_wire_length() {
    struct SparseCapacity<'a>(&'a MemoryCatalog);
    impl FactSource for SparseCapacity<'_> {
        fn identity(&self) -> &str {
            self.0.identity()
        }
        fn snapshot_id(&self) -> &str {
            self.0.snapshot_id()
        }
        fn catalog_epoch(&self) -> DecimalU64 {
            self.0.catalog_epoch()
        }
        fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema> {
            self.0.relation_schema(relation)
        }
        fn require_layers(&self, layers: &BTreeSet<FactLayer>) -> MddResult<()> {
            self.0.require_layers(layers)
        }
        fn validate_entity(&self, entity: &mdd_facts::EntityRef) -> MddResult<()> {
            self.0.validate_entity(entity)
        }
        fn scan<'a>(&'a self, _: &str) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>> {
            let mut row = Vec::with_capacity(4096);
            row.push(Value::U64(DecimalU64(1)));
            Ok(Box::new(std::iter::once(Ok(row))))
        }
        fn read_code_bytes(&self, entity: &mdd_facts::EntityRef) -> MddResult<Option<&[u8]>> {
            self.0.read_code_bytes(entity)
        }
    }
    let f = setup(BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 8192));
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &SparseCapacity(&f.source),
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("oversized live Row was admitted by tiny wire length")
    };
    assert_eq!(end.unwrap_err().code, ErrorCode::QuotaExceeded);
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    let terminal = receipt.finish(&mut pending).unwrap();
    assert_eq!(terminal.error.unwrap().code, ErrorCode::QuotaExceeded);
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn streaming_row_json_matches_fixed_serde_json_for_all_value_shapes() {
    let f = setup(BudgetLimits::default());
    let mut control = Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone());
    let entity = mdd_facts::EntityRef {
        snapshot_id: "snap\"\n雪".into(),
        dex_occurrence_id: "dex\\\0😀".into(),
        kind: mdd_facts::EntityKind::MethodDefinition,
        local_index: 42,
    };
    let mut rows = vec![
        vec![],
        vec![
            Value::Null,
            Value::Bool(false),
            Value::Bool(true),
            Value::I64(Signed64(i64::MIN)),
            Value::I64(Signed64(i64::MAX)),
            Value::U64(DecimalU64(u64::MAX)),
            Value::Utf16(vec![0, 0xd800, 0xdc00, 0xffff]),
            Value::Entity(entity),
        ],
    ];
    for n in [0usize, 1, 2, 3, 4, 5, 63, 64, 65, 4095, 4096, 4097, 65536] {
        rows.push(vec![Value::Bytes(Bytes(
            (0..n).map(|i| (i.wrapping_mul(37) % 256) as u8).collect(),
        ))]);
    }
    for row in rows {
        let baseline = serde_json::to_vec(&row).unwrap();
        let streamed = serde_json::to_vec(&StreamingRow(&row)).unwrap();
        assert_eq!(streamed, baseline);
        assert_eq!(
            count_wire_row(&row, &mut control, &f.runtime).unwrap(),
            baseline.len() as u64
        );
    }
}

#[test]
fn long_entity_text_is_chunked_without_changing_json() {
    let f = setup(BudgetLimits::default());
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = Arc::clone(&hits);
    let mut control = Control::new(ExecutionLimits::default())
        .with_runtime(f.runtime.clone())
        .with_hook(move |point| {
            if point.phase == "json_count" {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(())
        });
    let id = format!("{}😀\\\"\n{}雪", "x".repeat(1023), "y".repeat(5000));
    let row = vec![Value::Entity(mdd_facts::EntityRef {
        snapshot_id: "snapshot".into(),
        dex_occurrence_id: id.clone(),
        kind: mdd_facts::EntityKind::MethodDefinition,
        local_index: u32::MAX,
    })];
    let baseline = serde_json::to_vec(&row).unwrap();
    assert_eq!(serde_json::to_vec(&StreamingRow(&row)).unwrap(), baseline);
    assert_eq!(
        count_wire_row(&row, &mut control, &f.runtime).unwrap(),
        baseline.len() as u64
    );
    assert!(hits.load(std::sync::atomic::Ordering::SeqCst) >= id.len() / 1024);
}

#[test]
fn json_count_preserves_real_error_and_checked_overflow() {
    struct Broken;
    impl Serialize for Broken {
        fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(<S::Error as serde::ser::Error>::custom(
                "actual serializer failure",
            ))
        }
    }
    let f = setup(BudgetLimits::default());
    let mut control = Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone());
    let error = count_serialized(&Broken, &mut control, &f.runtime).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(error.details["reason"], "ROW_ENCODING");
    assert!(
        error.details["serializer_error"]
            .as_str()
            .unwrap()
            .contains("actual serializer failure")
    );
    let mut writer = RowCountWriter {
        control: &mut control,
        runtime: &f.runtime,
        count: u64::MAX,
        observed_cap: u64::MAX,
        failure: None,
    };
    assert!(writer.write_all(b"x").is_err());
    let error = writer.failure.take().unwrap();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert_eq!(error.details["reason"], "OUTPUT_SIZE_OVERFLOW");
}

#[test]
fn json_count_rechecks_released_parent_budget_and_final_charge_is_atomic() {
    let f = setup(BudgetLimits::default().with(Resource::OutputBytes, 256));
    let admission = f.session_budget.admit(Resource::OutputBytes, 256).unwrap();
    assert_eq!(
        f.runtime.pool().remaining(Resource::OutputBytes).unwrap(),
        0
    );
    admission.commit(0).unwrap();
    let mut control = Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone());
    let row = vec![Value::Bool(true)];
    let mut writer = RowCountWriter {
        control: &mut control,
        runtime: &f.runtime,
        count: 0,
        observed_cap: 0,
        failure: None,
    };
    serde_json::to_writer(&mut writer, &StreamingRow(&row)).unwrap();
    assert_eq!(writer.count, serde_json::to_vec(&row).unwrap().len() as u64);
    let exact = writer.count;
    drop(writer);
    // A different query can spend the shared budget after counting; the final charge must
    // recheck the current ancestor state rather than relying on the earlier snapshot.
    f.session_budget.charge(Resource::OutputBytes, 256).unwrap();
    let error = f.runtime.charge(Resource::OutputBytes, exact).unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert_eq!(error.details["budget"], "output_bytes");
}

#[test]
fn json_count_cancel_preserves_terminal_and_no_output_charge() {
    let f = setup_with_schema(
        BudgetLimits::default(),
        DataType::Bytes,
        vec![vec![Value::Bytes(Bytes(vec![42; 256]))]],
    );
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut hits = 0;
    let mut control = Control::new(ExecutionLimits::default())
        .with_runtime(f.runtime.clone())
        .with_hook(move |point| {
            if point.phase == "json_count" {
                hits += 1;
            }
            if hits == 3 {
                return Err(MddError::new(
                    ErrorCode::Cancelled,
                    "test.json",
                    "cancel during counting",
                ));
            }
            Ok(())
        });
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut control,
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("cancelled count returned data")
    };
    let error = end.unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert_eq!(error.stage, "test.json");
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    let result = receipt.finish(&mut pending).unwrap();
    assert_eq!(result.operation_status, OperationStatus::Cancelled);
    assert!(result.response.truncated);
    for resource in [Resource::QueryWorkspaceBytes, Resource::ResidentBytes] {
        assert_eq!(
            f.runtime
                .pool()
                .usage()
                .unwrap()
                .used
                .get(&resource)
                .map_or(0, |v| v.0),
            0
        );
    }
    assert_eq!(
        f.runtime
            .pool()
            .usage()
            .unwrap()
            .used
            .get(&Resource::OutputBytes)
            .map_or(0, |v| v.0),
        0
    );
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn low_output_fails_on_observed_prefix_and_exact_limit_delivers() {
    let row = vec![Value::Bytes(Bytes(vec![0x5a; 256]))];
    let f = setup_with_schema(
        BudgetLimits::default().with(Resource::OutputBytes, 64),
        DataType::Bytes,
        vec![row],
    );
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("over-budget output delivered a row")
    };
    let error = end.unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert_eq!(error.details["budget"], "output_bytes");
    assert_eq!(error.details["encoded_length_exact"], false);
    assert!(
        error.details["attempted_prefix_bytes"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 64
    );
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    let end = receipt.finish(&mut pending).unwrap();
    assert!(end.response.truncated);
    assert_eq!(end.error.unwrap().code, ErrorCode::QuotaExceeded);
    assert_eq!(
        f.runtime
            .pool()
            .usage()
            .unwrap()
            .used
            .get(&Resource::OutputBytes)
            .map_or(0, |v| v.0),
        0
    );

    let row = vec![Value::Bytes(Bytes(vec![1, 2, 3]))];
    let exact = serde_json::to_vec(&row).unwrap().len() as u64;
    let f = setup_with_schema(
        BudgetLimits::default().with(Resource::OutputBytes, exact),
        DataType::Bytes,
        vec![row.clone()],
    );
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
        panic!("exact limit lost row")
    };
    assert_eq!(packet.payload(), &row);
    packet.acknowledge().unwrap();
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    assert!(receipt.finish(&mut pending).unwrap().is_complete_result());
    assert_eq!(
        f.runtime
            .pool()
            .usage()
            .unwrap()
            .used
            .get(&Resource::OutputBytes)
            .unwrap()
            .0,
        exact
    );
}

#[test]
fn output_row_failure_marks_truncated_and_releases_reservation() {
    let f = setup_with_rows(BudgetLimits::default(), 1);
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut control = Control::new(ExecutionLimits::default())
        .with_runtime(f.runtime.clone())
        .with_hook(|point| {
            if point.phase == "output_row" {
                return Err(MddError::new(
                    ErrorCode::Cancelled,
                    "test.output_row",
                    "cancelled before enqueue",
                ));
            }
            Ok(())
        });
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut control,
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("uncommitted row must not be delivered");
    };
    assert_eq!(end.unwrap_err().stage, "test.output_row");
    for resource in [Resource::QueryWorkspaceBytes, Resource::ResidentBytes] {
        assert_eq!(
            f.runtime
                .pool()
                .usage()
                .unwrap()
                .used
                .get(&resource)
                .map_or(0, |v| v.0),
            0
        );
    }
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    let result = receipt.finish(&mut pending).unwrap();
    assert!(!result.is_complete_result());
    assert!(result.response.truncated);
}

#[test]
fn queued_and_current_row_reserve_before_second_json_count() {
    let row = vec![Value::Bytes(Bytes(vec![7; 1024]))];
    let resident = queued_row_resident_bytes(&row).unwrap();
    let f = setup_with_schema(
        BudgetLimits::default().with(Resource::QueryWorkspaceBytes, resident + resident / 2),
        DataType::Bytes,
        vec![row.clone(), row],
    );
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let second_count = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = Arc::clone(&second_count);
    let pool = f.runtime.pool().clone();
    let mut control = Control::new(ExecutionLimits::default())
        .with_runtime(f.runtime.clone())
        .with_hook(move |point| {
            if point.phase == "json_count"
                && pool
                    .usage()?
                    .used
                    .get(&Resource::OutputBytes)
                    .map_or(0, |v| v.0)
                    > 0
            {
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(())
        });
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut control,
        terminal(&f),
        &sender,
    )
    .unwrap();
    assert!(!second_count.load(std::sync::atomic::Ordering::SeqCst));
    let QueueEvent::Data(first) = receiver.receive().unwrap() else {
        panic!("first row must remain available");
    };
    first.acknowledge().unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("quota failure must terminate the queue");
    };
    assert_eq!(end.unwrap_err().code, ErrorCode::QuotaExceeded);
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    assert!(!receipt.finish(&mut pending).unwrap().is_complete_result());
}

#[test]
fn oversized_owned_row_is_rejected_before_json_counting() {
    let f = setup_with_schema(
        BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 8192),
        DataType::Bytes,
        vec![],
    );
    let source = SparseInner {
        source: &f.source,
        kind: SparseInnerKind::Bytes,
        capacity: 10_000,
    };
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    let mut control = Control::new(ExecutionLimits::default())
        .with_runtime(f.runtime.clone())
        .with_hook(move |point| {
            if point.phase == "json_count" {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(())
        });
    let mut pending = execute_into(
        &f.prepared,
        &source,
        ExecutionMode::Streaming,
        &mut control,
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("oversized row delivered")
    };
    let error = end.unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert_eq!(error.details["budget"], "query_workspace_bytes");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    assert!(receipt.finish(&mut pending).unwrap().response.truncated);
}

#[derive(Clone, Copy)]
enum SparseInnerKind {
    Utf16,
    Bytes,
    Entity,
}
struct SparseInner<'a> {
    source: &'a MemoryCatalog,
    kind: SparseInnerKind,
    capacity: usize,
}
impl FactSource for SparseInner<'_> {
    fn identity(&self) -> &str {
        self.source.identity()
    }
    fn snapshot_id(&self) -> &str {
        self.source.snapshot_id()
    }
    fn catalog_epoch(&self) -> DecimalU64 {
        self.source.catalog_epoch()
    }
    fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema> {
        self.source.relation_schema(relation)
    }
    fn require_layers(&self, layers: &BTreeSet<FactLayer>) -> MddResult<()> {
        self.source.require_layers(layers)
    }
    fn validate_entity(&self, entity: &mdd_facts::EntityRef) -> MddResult<()> {
        self.source.validate_entity(entity)
    }
    fn scan<'a>(&'a self, _: &str) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>> {
        let value = match self.kind {
            SparseInnerKind::Utf16 => {
                let mut v = Vec::with_capacity(self.capacity);
                v.push(65);
                Value::Utf16(v)
            }
            SparseInnerKind::Bytes => {
                let mut v = Vec::with_capacity(self.capacity);
                v.push(65);
                Value::Bytes(Bytes(v))
            }
            SparseInnerKind::Entity => {
                let mut snapshot_id = String::with_capacity(self.capacity);
                snapshot_id.push_str(self.source.snapshot_id());
                let mut dex_occurrence_id = String::with_capacity(self.capacity);
                dex_occurrence_id.push_str("source");
                Value::Entity(mdd_facts::EntityRef {
                    snapshot_id,
                    dex_occurrence_id,
                    kind: mdd_facts::EntityKind::String,
                    local_index: 0,
                })
            }
        };
        Ok(Box::new(std::iter::once(Ok(vec![value]))))
    }
    fn read_code_bytes(&self, entity: &mdd_facts::EntityRef) -> MddResult<Option<&[u8]>> {
        self.source.read_code_bytes(entity)
    }
}

#[test]
fn queue_counts_owned_text_bytes_and_entity_capacities_on_real_rows() {
    for (kind, data_type) in [
        (SparseInnerKind::Utf16, DataType::Utf16),
        (SparseInnerKind::Bytes, DataType::Bytes),
        (SparseInnerKind::Entity, DataType::Entity),
    ] {
        let f = setup_with_schema(
            BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 8192),
            data_type,
            vec![],
        );
        let source = SparseInner {
            source: &f.source,
            kind,
            capacity: 10_000,
        };
        let (sender, mut receiver) =
            bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
        let mut pending = execute_into(
            &f.prepared,
            &source,
            ExecutionMode::Streaming,
            &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
            terminal(&f),
            &sender,
        )
        .unwrap();
        let QueueEvent::End(end) = receiver.receive().unwrap() else {
            panic!("oversized inner owner was admitted")
        };
        assert_eq!(end.unwrap_err().code, ErrorCode::QuotaExceeded);
        let mut receipt = receiver.into_delivery_receipt().unwrap();
        assert_eq!(
            receipt.finish(&mut pending).unwrap().error.unwrap().code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            f.runtime
                .pool()
                .usage()
                .unwrap()
                .used
                .get(&Resource::QueryWorkspaceBytes)
                .map_or(0, |v| v.0),
            0
        );
        assert!(!f.cancel.status().unwrap().delivery_complete);
    }
}

#[test]
fn queued_row_wire_and_resident_leases_are_distinct_and_release_on_ack() {
    let f = setup_with_schema(BudgetLimits::default(), DataType::Utf16, vec![]);
    let source = SparseInner {
        source: &f.source,
        kind: SparseInnerKind::Utf16,
        capacity: 32,
    };
    let expected_wire = serde_json::to_vec(&vec![Value::Utf16(vec![65])])
        .unwrap()
        .len() as u64;
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    for pool in [
        &f.global_budget,
        &f.worker_budget,
        &f.session_budget,
        f.runtime.pool(),
    ] {
        assert_eq!(
            pool.usage()
                .unwrap()
                .used
                .get(&Resource::QueueBytes)
                .unwrap()
                .0,
            expected_wire
        );
    }
    let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
        panic!("missing row")
    };
    let Value::Utf16(text) = &packet.payload()[0] else {
        panic!("wrong value")
    };
    let resident = std::mem::size_of::<Row>()
        + packet.payload().capacity() * std::mem::size_of::<Value>()
        + text.capacity() * std::mem::size_of::<u16>();
    for pool in [
        &f.global_budget,
        &f.worker_budget,
        &f.session_budget,
        f.runtime.pool(),
    ] {
        let usage = pool.usage().unwrap();
        assert_eq!(usage.used.get(&Resource::QueueBytes).unwrap().0, 0);
        assert_eq!(
            usage.used.get(&Resource::QueryWorkspaceBytes).unwrap().0,
            resident as u64
        );
        assert_eq!(
            usage.used.get(&Resource::ResidentBytes).unwrap().0,
            resident as u64
        );
    }
    packet.acknowledge().unwrap();
    for pool in [
        &f.global_budget,
        &f.worker_budget,
        &f.session_budget,
        f.runtime.pool(),
    ] {
        assert_eq!(
            pool.usage()
                .unwrap()
                .used
                .get(&Resource::QueryWorkspaceBytes)
                .unwrap()
                .0,
            0
        );
    }
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    assert!(receipt.finish(&mut pending).unwrap().is_complete_result());
}

#[test]
fn queued_row_lease_stays_while_cancelled_consumer_still_holds_packet() {
    let f = setup_with_schema(BudgetLimits::default(), DataType::Utf16, vec![]);
    let source = SparseInner {
        source: &f.source,
        kind: SparseInnerKind::Utf16,
        capacity: 32,
    };
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let _pending = execute_into(
        &f.prepared,
        &source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
        panic!("missing row")
    };
    let held = f
        .runtime
        .pool()
        .usage()
        .unwrap()
        .used
        .get(&Resource::QueryWorkspaceBytes)
        .unwrap()
        .0;
    assert!(held > 0);
    f.cancel.cancel().unwrap();
    for pool in [
        &f.global_budget,
        &f.worker_budget,
        &f.session_budget,
        f.runtime.pool(),
    ] {
        assert_eq!(
            pool.usage()
                .unwrap()
                .used
                .get(&Resource::QueryWorkspaceBytes)
                .unwrap()
                .0,
            held
        );
    }
    drop(packet);
    for pool in [
        &f.global_budget,
        &f.worker_budget,
        &f.session_budget,
        f.runtime.pool(),
    ] {
        assert_eq!(
            pool.usage()
                .unwrap()
                .used
                .get(&Resource::QueryWorkspaceBytes)
                .unwrap()
                .0,
            0
        );
    }
    assert_eq!(
        f.cancel.status().unwrap().error.unwrap().code,
        ErrorCode::Cancelled
    );
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn cancelled_before_claim_sends_explicit_cancelled_end() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    f.cancel.cancel().unwrap();
    let error = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .err()
    .unwrap();
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert!(
        sender.finish(Ok(())).is_err(),
        "cancelled query left queue without its error End"
    );
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("cancelled query had no End")
    };
    assert_eq!(end.unwrap_err().code, ErrorCode::Cancelled);
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn queued_rows_are_not_delivery_without_consumer_acknowledgement() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    assert!(f.cancel.status().unwrap().execution_complete);
    assert!(!f.cancel.status().unwrap().delivery_complete);
    for n in 0..4 {
        let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
            panic!("missing row")
        };
        assert_eq!(packet.payload(), &vec![Value::U64(DecimalU64(n))]);
        packet.acknowledge().unwrap();
    }
    assert!(!f.cancel.status().unwrap().delivery_complete);
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    let end = receipt.finish(&mut pending).unwrap();
    assert!(end.is_complete_result());
    assert_eq!(end.response.emitted_rows.0, 4);
    assert!(f.cancel.status().unwrap().delivery_complete);
    assert!(receipt.finish(&mut pending).is_err());
}

#[test]
fn trusted_callback_cannot_complete_a_query_bound_unread_queue() {
    let f = setup(BudgetLimits::default());
    let (sender, _receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
    let terminal = execute_trusted_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        |_, row| sender.send(row.clone(), 16),
    )
    .unwrap();
    assert!(!terminal.is_complete_result());
    assert_eq!(terminal.error.unwrap().code, ErrorCode::InvalidCursor);
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn all_rows_dequeued_but_one_unacknowledged_still_cannot_complete() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
    let _pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    for _ in 0..3 {
        let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
            panic!("missing row")
        };
        packet.acknowledge().unwrap();
    }
    let QueueEvent::Data(unacknowledged) = receiver.receive().unwrap() else {
        panic!("missing final row")
    };
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    assert!(receiver.into_delivery_receipt().is_err());
    assert!(!f.cancel.status().unwrap().delivery_complete);
    drop(unacknowledged);
}

#[test]
fn empty_queue_needs_explicit_end_and_unbound_queue_cannot_prove_delivery() {
    let f = setup_with_rows(BudgetLimits::default(), 0);
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    assert!(!f.cancel.status().unwrap().delivery_complete);
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    assert!(receipt.finish(&mut pending).unwrap().is_complete_result());
    let f = setup(BudgetLimits::default());
    let (sender, _receiver) = bounded_channel(f.runtime.pool().clone(), None, 8).unwrap();
    assert!(
        execute_into(
            &f.prepared,
            &f.source,
            ExecutionMode::Streaming,
            &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
            terminal(&f),
            &sender
        )
        .is_err()
    );
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn dropped_unacknowledged_rows_and_unread_end_never_complete() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
    let _pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
        panic!("missing row")
    };
    drop(packet);
    assert!(!f.cancel.status().unwrap().delivery_complete);
    assert_eq!(
        f.cancel.status().unwrap().error.unwrap().code,
        ErrorCode::Cancelled
    );
    let f = setup_with_rows(BudgetLimits::default(), 0);
    let (sender, receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let _pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    assert!(receiver.into_delivery_receipt().is_err());
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn queue_quota_delivers_only_acknowledged_prefix_with_failure_end() {
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let f = setup(BudgetLimits::default());
        let (sender, mut receiver) =
            bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
        let mut pending = execute_into(
            &f.prepared,
            &f.source,
            mode,
            &mut Control::new(ExecutionLimits {
                max_output_rows: 2,
                ..ExecutionLimits::default()
            })
            .with_runtime(f.runtime.clone()),
            terminal(&f),
            &sender,
        )
        .unwrap();
        for _ in 0..2 {
            let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
                panic!("missing prefix")
            };
            packet.acknowledge().unwrap();
        }
        let QueueEvent::End(end) = receiver.receive().unwrap() else {
            panic!("missing error end")
        };
        assert_eq!(end.unwrap_err().code, ErrorCode::QuotaExceeded);
        let mut receipt = receiver.into_delivery_receipt().unwrap();
        let terminal = receipt.finish(&mut pending).unwrap();
        assert_eq!(terminal.error.unwrap().code, ErrorCode::QuotaExceeded);
        assert_eq!(terminal.response.emitted_rows.0, 2);
        assert!(terminal.response.truncated);
        assert!(!f.cancel.status().unwrap().delivery_complete);
    }
}

#[test]
fn queue_deadline_has_explicit_error_end_and_no_complete_success() {
    let f = setup(BudgetLimits::default().deadlines(0, 0).unwrap());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("deadline became data or EOF")
    };
    assert_eq!(end.unwrap_err().code, ErrorCode::DeadlineExceeded);
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    let terminal = receipt.finish(&mut pending).unwrap();
    assert_eq!(terminal.error.unwrap().code, ErrorCode::DeadlineExceeded);
    assert!(!terminal.execution.complete);
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn receipt_cannot_confirm_another_query() {
    fn ready(f: &Fixture) -> (PendingDelivery, crate::budget::QueueDeliveryReceipt) {
        let (sender, mut receiver) =
            bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
        let pending = execute_into(
            &f.prepared,
            &f.source,
            ExecutionMode::Streaming,
            &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
            terminal(f),
            &sender,
        )
        .unwrap();
        for _ in 0..4 {
            let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
                panic!("missing row")
            };
            packet.acknowledge().unwrap();
        }
        assert!(matches!(
            receiver.receive().unwrap(),
            QueueEvent::End(Ok(()))
        ));
        (pending, receiver.into_delivery_receipt().unwrap())
    }
    let a = setup(BudgetLimits::default());
    let b = setup(BudgetLimits::default());
    let (mut pending_a, mut receipt_a) = ready(&a);
    let (mut pending_b, mut receipt_b) = ready(&b);
    assert!(receipt_a.finish(&mut pending_b).is_err());
    assert!(
        !a.cancel.status().unwrap().delivery_complete
            && !b.cancel.status().unwrap().delivery_complete
    );
    assert!(
        receipt_a
            .finish(&mut pending_a)
            .unwrap()
            .is_complete_result()
    );
    assert!(
        receipt_b
            .finish(&mut pending_b)
            .unwrap()
            .is_complete_result()
    );
}

#[test]
fn error_receipt_requires_every_original_error_field() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel::<Row>(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let original = MddError::new(ErrorCode::InvalidInput, "facts.input", "corrupt")
        .detail("reason", "BAD_ITEM");
    sender.finish(Err(original.clone())).unwrap();
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Err(_))
    ));
    let receipt = receiver.into_delivery_receipt().unwrap();
    assert!(
        receipt
            .matches(&sender, &f.runtime, 0, Some(&original))
            .unwrap()
    );
    let mut differences = Vec::new();
    let mut changed = original.clone();
    changed.code = ErrorCode::UnsupportedQuery;
    differences.push(changed);
    let mut changed = original.clone();
    changed.stage = "other".into();
    differences.push(changed);
    let mut changed = original.clone();
    changed.message = "other".into();
    differences.push(changed);
    let mut changed = original.clone();
    changed.retryable = true;
    differences.push(changed);
    let mut changed = original.clone();
    changed.details.insert("reason".into(), "OTHER".into());
    differences.push(changed);
    for changed in differences {
        assert!(
            !receipt
                .matches(&sender, &f.runtime, 0, Some(&changed))
                .unwrap()
        );
    }
    assert!(!receipt.matches(&sender, &f.runtime, 0, None).unwrap());
}

#[test]
fn wrong_terminal_binding_does_not_poison_or_claim_the_original_queue() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
    let original = terminal(&f);
    let mut identity = original.identity().clone();
    identity.session_id = Some("different-session".into());
    let wrong = TerminalBuilder::new(identity, original.coverage().clone()).unwrap();
    let error = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        wrong,
        &sender,
    )
    .err()
    .unwrap();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(f.cancel.status().unwrap().error.is_none());
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    for _ in 0..4 {
        let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
            panic!("missing row")
        };
        packet.acknowledge().unwrap();
    }
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    assert!(receipt.finish(&mut pending).unwrap().is_complete_result());
}

#[test]
fn queue_with_real_backpressure_completes_only_after_consumer_end() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 1).unwrap();
    std::thread::scope(|scope| {
        let fixture = &f;
        let producer = scope.spawn(move || {
            execute_into(
                &fixture.prepared,
                &fixture.source,
                ExecutionMode::Streaming,
                &mut Control::new(ExecutionLimits::default()).with_runtime(fixture.runtime.clone()),
                terminal(fixture),
                &sender,
            )
            .unwrap()
        });
        for n in 0..4 {
            let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
                panic!("missing backpressured row")
            };
            assert_eq!(packet.payload(), &vec![Value::U64(DecimalU64(n))]);
            assert!(!f.cancel.status().unwrap().delivery_complete);
            packet.acknowledge().unwrap();
        }
        assert!(matches!(
            receiver.receive().unwrap(),
            QueueEvent::End(Ok(()))
        ));
        let mut pending = producer.join().unwrap();
        assert!(!f.cancel.status().unwrap().delivery_complete);
        let mut receipt = receiver.into_delivery_receipt().unwrap();
        assert!(receipt.finish(&mut pending).unwrap().is_complete_result());
    });
    assert!(f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn duplicate_end_and_out_of_order_ack_are_sticky_failures() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
    let duplicate = sender.try_clone().unwrap();
    let _pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    assert!(duplicate.finish(Ok(())).is_err());
    assert_eq!(
        f.cancel.status().unwrap().error.unwrap().code,
        ErrorCode::InvalidArgument
    );
    assert!(!f.cancel.status().unwrap().delivery_complete);
    let QueueEvent::Data(first) = receiver.receive().unwrap() else {
        panic!("missing queued row")
    };
    assert!(first.acknowledge().is_err());
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 8).unwrap();
    let _pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::Data(first) = receiver.receive().unwrap() else {
        panic!("missing first")
    };
    let QueueEvent::Data(second) = receiver.receive().unwrap() else {
        panic!("missing second")
    };
    assert_eq!(
        second.acknowledge().unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    drop(first);
    assert_eq!(
        f.cancel.status().unwrap().error.unwrap().code,
        ErrorCode::InvalidArgument
    );
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn producer_lease_drop_and_external_error_preserve_first_terminal() {
    let f = setup_with_rows(BudgetLimits::default(), 0);
    let (sender, mut receiver) =
        bounded_channel::<u8>(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let unarmed = sender.claim_producer().unwrap();
    drop(unarmed);
    assert!(f.cancel.status().unwrap().error.is_none());
    sender.send(1, 1).unwrap();
    f.cancel.mark_computed().unwrap();
    sender.finish(Ok(())).unwrap();
    let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
        panic!("row missing")
    };
    packet.acknowledge().unwrap();
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    receipt.finish_cursor().unwrap();
    f.cancel.finish_delivery().unwrap();
    assert!(f.cancel.status().unwrap().delivery_complete);

    let f = setup_with_rows(BudgetLimits::default(), 0);
    let (sender, mut receiver) =
        bounded_channel::<u8>(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut armed = sender.claim_producer().unwrap();
    armed.arm();
    drop(armed);
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("lost End missing")
    };
    assert_eq!(end.unwrap_err().code, ErrorCode::WorkerLost);
    assert_eq!(
        f.cancel.status().unwrap().error.unwrap().code,
        ErrorCode::WorkerLost
    );

    let f = setup_with_rows(BudgetLimits::default(), 0);
    let (sender, mut receiver) =
        bounded_channel::<u8>(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut armed = sender.claim_producer().unwrap();
    armed.arm();
    let original = MddError::new(ErrorCode::InvalidInput, "test.input", "source corrupt");
    sender.finish(Err(original.clone())).unwrap();
    drop(armed);
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("failed End missing")
    };
    assert_eq!(end.unwrap_err().code, ErrorCode::InvalidInput);
    let actual = f.cancel.status().unwrap().error.unwrap();
    assert_eq!(
        (actual.code, actual.stage, actual.message),
        (original.code, original.stage, original.message)
    );
}

#[test]
fn execute_into_zero_row_still_requires_end_and_receipt() {
    let f = setup_with_rows(BudgetLimits::default(), 0);
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    assert!(!f.cancel.status().unwrap().delivery_complete);
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    assert!(receipt.finish(&mut pending).unwrap().is_complete_result());
    assert!(f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn execute_into_counting_cannot_race_external_successful_end() {
    let f = setup_with_rows(BudgetLimits::default(), 1);
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let producer_sender = sender.try_clone().unwrap();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let fixture = &f;
        let producer = scope.spawn(move || {
            let mut paused = false;
            let mut control = Control::new(ExecutionLimits::default())
                .with_runtime(fixture.runtime.clone())
                .with_hook(move |point| {
                    if point.phase == "json_count" && !paused {
                        paused = true;
                        ready_tx.send(()).map_err(|_| {
                            MddError::new(ErrorCode::InternalFault, "test", "ready channel closed")
                        })?;
                        release_rx
                            .recv_timeout(std::time::Duration::from_secs(5))
                            .map_err(|_| {
                                MddError::new(
                                    ErrorCode::DeadlineExceeded,
                                    "test",
                                    "release timed out",
                                )
                            })?;
                    }
                    Ok(())
                });
            execute_into(
                &fixture.prepared,
                &fixture.source,
                ExecutionMode::Streaming,
                &mut control,
                terminal(fixture),
                &producer_sender,
            )
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let competing = execute_into(
            &f.prepared,
            &f.source,
            ExecutionMode::Streaming,
            &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
            terminal(&f),
            &sender,
        );
        assert_eq!(competing.err().unwrap().code, ErrorCode::InvalidArgument);
        assert_eq!(
            sender
                .send(vec![Value::U64(DecimalU64(7))], 1)
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert!(f.cancel.status().unwrap().error.is_none());
        let finish = sender.finish(Ok(()));
        let premature_success_end = if finish.is_ok() {
            matches!(receiver.receive().unwrap(), QueueEvent::End(Ok(())))
        } else {
            false
        };
        release_tx.send(()).unwrap();
        let result = producer.join().unwrap();
        assert!(
            !premature_success_end,
            "counting published an early successful End"
        );
        assert!(
            finish.is_err(),
            "counting allowed an external successful End"
        );
        let mut pending = result.unwrap();
        let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
            panic!("expected computed row");
        };
        packet.acknowledge().unwrap();
        assert!(matches!(
            receiver.receive().unwrap(),
            QueueEvent::End(Ok(()))
        ));
        let mut receipt = receiver.into_delivery_receipt().unwrap();
        assert!(receipt.finish(&mut pending).unwrap().is_complete_result());
    });
}

#[test]
fn execute_into_reserved_queue_quota_keeps_pending_delivery_error() {
    let f = setup_with_rows(BudgetLimits::default().with(Resource::QueueBytes, 4), 1);
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    let used = f.runtime.pool().usage().unwrap().used;
    assert!(used.get(&Resource::OutputBytes).map_or(0, |value| value.0) > 0);
    assert_eq!(
        used.get(&Resource::QueryWorkspaceBytes)
            .map_or(0, |value| value.0),
        0
    );
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("reserved queue quota produced a row");
    };
    let error = end.unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert_eq!(error.details["budget"], "queue_bytes");
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    let envelope = receipt.finish(&mut pending).unwrap();
    assert_eq!(envelope.error.unwrap().code, ErrorCode::QuotaExceeded);
    assert!(envelope.response.truncated);
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn bound_sender_cannot_mark_success_after_oversized_send() {
    let f = setup(BudgetLimits::default().with(Resource::QueueBytes, 4));
    let (sender, mut receiver) =
        bounded_channel::<u8>(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    assert_eq!(
        sender.send(7, 5).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    assert!(
        sender.finish(Ok(())).is_err(),
        "failed send accepted successful End"
    );
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("failed send did not emit an error terminal");
    };
    assert_eq!(end.unwrap_err().code, ErrorCode::QuotaExceeded);
}

#[test]
fn bound_sender_quota_is_sticky_and_cannot_be_finished_as_success() {
    let f = setup(BudgetLimits::default().with(Resource::QueueBytes, 4));
    let (sender, mut receiver) =
        bounded_channel::<u8>(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let error = sender.send(7, 5).unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert_eq!(
        f.cancel.status().unwrap().error.unwrap().code,
        ErrorCode::QuotaExceeded
    );
    assert!(sender.finish(Ok(())).is_err());
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("failed send did not emit an error terminal");
    };
    assert_eq!(end.unwrap_err().code, ErrorCode::QuotaExceeded);
    drop(receiver);
    assert_eq!(
        f.cancel.status().unwrap().error.unwrap().code,
        ErrorCode::QuotaExceeded
    );
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

fn check_bound_send_in_flight_failure(use_reserved: bool) {
    struct DropGate {
        ready: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }
    impl Drop for DropGate {
        fn drop(&mut self) {
            let _ = self.ready.send(());
            let _ = self.release.recv_timeout(std::time::Duration::from_secs(5));
        }
    }

    let f = setup(BudgetLimits::default().with(Resource::QueueBytes, 4));
    let (sender, receiver) =
        bounded_channel::<DropGate>(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let producer = sender.try_clone().unwrap();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let reservation = if use_reserved {
        Some(sender.reserve_payload(4).unwrap())
    } else {
        None
    };
    let worker = std::thread::spawn(move || {
        let payload = DropGate {
            ready: ready_tx,
            release: release_rx,
        };
        match reservation {
            Some(memory) => producer.send_reserved(payload, 5, memory),
            None => producer.send(payload, 5),
        }
    });
    ready_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    let mut receiver = Some(receiver);
    let finish = sender.finish(Ok(()));
    let mut incorrectly_completed = false;
    if finish.is_ok() {
        let mut current = receiver.take().unwrap();
        if matches!(current.receive().unwrap(), QueueEvent::End(Ok(()))) {
            let mut receipt = current.into_delivery_receipt().unwrap();
            f.cancel.mark_computed().unwrap();
            receipt.finish_cursor().unwrap();
            f.cancel.finish_delivery().unwrap();
            incorrectly_completed = f.cancel.status().unwrap().delivery_complete;
        }
    }
    release_tx.send(()).unwrap();
    let send_error = worker.join().unwrap().unwrap_err();
    assert!(
        !incorrectly_completed,
        "quota failure raced into complete delivery"
    );
    assert!(finish.is_err(), "in-flight send accepted successful End");
    assert_eq!(send_error.code, ErrorCode::QuotaExceeded);
    if use_reserved {
        // The executor, not send_reserved, publishes the explicit failure End.
        sender.finish(Err(send_error.clone())).unwrap();
    }
    let mut remaining = receiver.take().expect("failure terminal must remain");
    let QueueEvent::End(end) = remaining.receive().unwrap() else {
        panic!("quota error terminal missing");
    };
    assert_eq!(end.unwrap_err().code, ErrorCode::QuotaExceeded);
}

#[test]
fn bound_sender_in_flight_failure_cannot_race_successful_end() {
    check_bound_send_in_flight_failure(false);
}

#[test]
fn bound_reserved_sender_in_flight_failure_cannot_race_successful_end() {
    check_bound_send_in_flight_failure(true);
}

#[test]
fn bound_sender_preserves_existing_cancel_or_worker_loss() {
    for worker_loss in [false, true] {
        let f = setup(BudgetLimits::default().with(Resource::QueueBytes, 4));
        let (sender, mut receiver) =
            bounded_channel::<u8>(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
        let expected = if worker_loss {
            f.lifecycle.worker_lost("test worker lost").unwrap();
            ErrorCode::WorkerLost
        } else {
            f.cancel.cancel().unwrap();
            ErrorCode::Cancelled
        };
        assert_eq!(sender.send(7, 5).unwrap_err().code, expected);
        let QueueEvent::End(end) = receiver.receive().unwrap() else {
            panic!("previous failure was not sent as End");
        };
        assert_eq!(end.unwrap_err().code, expected);
        drop(receiver);
        assert_eq!(f.cancel.status().unwrap().error.unwrap().code, expected);
    }
}

#[test]
fn bound_sender_normal_backpressure_still_delivers_all_rows() {
    let f = setup(BudgetLimits::default().with(Resource::QueueItems, 1));
    let (sender, mut receiver) =
        bounded_channel::<u8>(f.runtime.pool().clone(), Some(f.cancel.clone()), 1).unwrap();
    sender.send(1, 4).unwrap();
    let waiting = sender.try_clone().unwrap();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        ready_tx.send(()).unwrap();
        result_tx.send(waiting.send(2, 4)).unwrap();
    });
    ready_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap();
    assert!(
        result_rx
            .recv_timeout(std::time::Duration::from_millis(20))
            .is_err()
    );
    let QueueEvent::Data(first) = receiver.receive().unwrap() else {
        panic!("first row missing");
    };
    assert_eq!(*first.payload(), 1);
    first.acknowledge().unwrap();
    result_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .unwrap()
        .unwrap();
    worker.join().unwrap();
    f.cancel.mark_computed().unwrap();
    sender.finish(Ok(())).unwrap();
    let QueueEvent::Data(second) = receiver.receive().unwrap() else {
        panic!("second row missing");
    };
    assert_eq!(*second.payload(), 2);
    second.acknowledge().unwrap();
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    receipt.finish_cursor().unwrap();
    f.cancel.finish_delivery().unwrap();
    assert!(f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn delivery_receipt_does_not_succeed_after_query_budget_deadline() {
    let limits = BudgetLimits::default().deadlines(250, 5000).unwrap();
    let f = setup_with_rows(limits, 0);
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    let wait_started = std::time::Instant::now();
    loop {
        if let Err(error) = f.runtime.pool().checkpoint() {
            assert_eq!(error.code, ErrorCode::DeadlineExceeded);
            break;
        }
        assert!(wait_started.elapsed() < std::time::Duration::from_secs(3));
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let envelope = receipt.finish(&mut pending).unwrap();
    let error = envelope.error.as_ref().expect("missing deadline terminal");
    assert_eq!(error.code, ErrorCode::DeadlineExceeded);
    assert_eq!(error.stage, "budget");
    assert_eq!(error.details["budget"], "soft_deadline_ms");
    assert!(envelope.execution.complete);
    assert!(!envelope.is_complete_result());
    let status = f.cancel.status().unwrap();
    assert!(status.execution_complete);
    assert!(!status.delivery_complete);
    assert_eq!(status.error.unwrap().code, ErrorCode::DeadlineExceeded);
}

#[test]
fn late_delivery_failures_return_coverage_and_computation_envelope() {
    for scenario in ["budget", "cancel", "worker_lost"] {
        let limits = if scenario == "budget" {
            BudgetLimits::default().deadlines(250, 5000).unwrap()
        } else {
            BudgetLimits::default()
        };
        let f = setup_with_rows(limits, 1);
        let (sender, mut receiver) =
            bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
        let mut pending = execute_into(
            &f.prepared,
            &f.source,
            ExecutionMode::Streaming,
            &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
            terminal(&f),
            &sender,
        )
        .unwrap();
        let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
            panic!("{scenario}: missing row")
        };
        packet.acknowledge().unwrap();
        assert!(matches!(
            receiver.receive().unwrap(),
            QueueEvent::End(Ok(()))
        ));
        let mut receipt = receiver.into_delivery_receipt().unwrap();
        let (expected_code, expected_stage) = match scenario {
            "budget" => {
                let started = std::time::Instant::now();
                loop {
                    if let Err(error) = f.runtime.pool().checkpoint() {
                        assert_eq!(error.code, ErrorCode::DeadlineExceeded);
                        break;
                    }
                    assert!(started.elapsed() < std::time::Duration::from_secs(3));
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                (ErrorCode::DeadlineExceeded, "budget")
            }
            "cancel" => {
                f.cancel.cancel().unwrap();
                (ErrorCode::Cancelled, "lifecycle")
            }
            "worker_lost" => {
                f.lifecycle.worker_lost("late worker loss").unwrap();
                (ErrorCode::WorkerLost, "worker")
            }
            _ => unreachable!(),
        };
        let envelope = receipt.finish(&mut pending).unwrap_or_else(|error| {
            panic!("{scenario}: late failure lost its result envelope: {error:?}")
        });
        let error = envelope.error.as_ref().expect("missing failure terminal");
        assert_eq!(error.code, expected_code, "{scenario}");
        assert_eq!(error.stage, expected_stage, "{scenario}");
        assert_eq!(
            envelope.coverage.input,
            Completeness::Complete,
            "{scenario}"
        );
        assert_eq!(
            envelope.coverage.facts,
            Completeness::Complete,
            "{scenario}"
        );
        assert!(envelope.execution.complete, "{scenario}");
        assert_eq!(envelope.response.emitted_rows.0, 1, "{scenario}");
        assert_eq!(envelope.response.total_rows.unwrap().0, 1, "{scenario}");
        assert!(!envelope.is_complete_result(), "{scenario}");
        let status = f.cancel.status().unwrap();
        assert!(status.execution_complete, "{scenario}");
        assert!(!status.delivery_complete, "{scenario}");
        assert_eq!(status.error.unwrap().code, expected_code, "{scenario}");
    }
}

#[test]
fn failed_receipt_cleanup_preserves_producer_error_after_query_release() {
    let f = setup_with_rows(BudgetLimits::default(), 1);
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits {
            max_output_rows: 0,
            ..ExecutionLimits::default()
        })
        .with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("quota failure did not produce End")
    };
    assert_eq!(end.unwrap_err().code, ErrorCode::QuotaExceeded);
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    f.lifecycle.release_query(f.cancel.query_handle()).unwrap();
    let error = receipt.finish(&mut pending).unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert!(error.details.contains_key("receipt_cleanup_error"));
    assert!(!pending.completed);
}

#[test]
fn failed_receipt_cleanup_does_not_overwrite_prior_details() {
    let f = setup_with_rows(BudgetLimits::default(), 1);
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut control = Control::new(ExecutionLimits::default())
        .with_runtime(f.runtime.clone())
        .with_hook(|point| {
            if point.phase == "output_row" {
                return Err(
                    MddError::new(ErrorCode::QuotaExceeded, "test.prior", "prior quota")
                        .detail("receipt_cleanup_error", "original")
                        .detail("receipt_cleanup_error_0", "collision"),
                );
            }
            Ok(())
        });
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut control,
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("quota failure did not produce End")
    };
    let prior = end.unwrap_err();
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    f.lifecycle.release_query(f.cancel.query_handle()).unwrap();
    let error = receipt.finish(&mut pending).unwrap_err();
    assert_eq!(error.code, prior.code);
    assert_eq!(error.stage, prior.stage);
    assert_eq!(error.message, prior.message);
    for (name, value) in &prior.details {
        assert_eq!(error.details.get(name), Some(value));
    }
    assert!(error.details["receipt_cleanup_error_1"].is_string());
    assert!(!pending.completed);
}

#[test]
fn inconsistent_terminal_count_never_fabricates_an_envelope() {
    let f = setup_with_rows(BudgetLimits::default(), 1);
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
        panic!("missing row")
    };
    packet.acknowledge().unwrap();
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    // Test-only corruption models an internal exact-count inconsistency.
    let mut inconsistent = terminal(&f);
    inconsistent.computation_complete(0).unwrap();
    pending.terminal = Some(inconsistent);
    let error = receipt.finish(&mut pending).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(error.details["actual_consumed_rows"], "1");
    let status = f.cancel.status().unwrap();
    assert_eq!(
        status.error.as_ref().unwrap().details["actual_consumed_rows"],
        "1"
    );
    assert!(!status.delivery_complete);
    assert!(!pending.completed);
}

#[test]
fn inconsistent_count_preserves_prior_quota_and_reports_consumed_rows() {
    let f = setup_with_rows(BudgetLimits::default(), 2);
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits {
            max_output_rows: 1,
            ..ExecutionLimits::default()
        })
        .with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
        panic!("missing acknowledged prefix")
    };
    packet.acknowledge().unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("missing quota End")
    };
    let prior = end.unwrap_err();
    assert_eq!(prior.code, ErrorCode::QuotaExceeded);
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    // Test-only corruption models a builder whose total contradicts consumed rows.
    let mut inconsistent = terminal(&f);
    inconsistent.computation_complete(0).unwrap();
    pending.terminal = Some(inconsistent);
    let error = receipt.finish(&mut pending).unwrap_err();
    assert_eq!(error.code, prior.code);
    assert_eq!(error.stage, prior.stage);
    assert_eq!(error.message, prior.message);
    for (name, value) in &prior.details {
        assert_eq!(error.details.get(name), Some(value));
    }
    assert_eq!(error.details["actual_consumed_rows"], "1");
    assert_eq!(f.cancel.status().unwrap().error.unwrap().code, prior.code);
    assert!(!pending.completed);
}

#[test]
fn inconsistent_count_does_not_overwrite_existing_first_error_details() {
    let f = setup_with_rows(BudgetLimits::default(), 2);
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut output_rows = 0;
    let mut control = Control::new(ExecutionLimits::default())
        .with_runtime(f.runtime.clone())
        .with_hook(move |checkpoint| {
            if checkpoint.phase == "output_row" {
                output_rows += 1;
                if output_rows == 2 {
                    return Err(MddError::new(
                        ErrorCode::QuotaExceeded,
                        "test.prior",
                        "prior quota",
                    )
                    .detail("actual_consumed_rows", "original-detail")
                    .detail("receipt_actual_consumed_rows_0", "prior-collision"));
                }
            }
            Ok(())
        });
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut control,
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
        panic!("missing acknowledged prefix")
    };
    packet.acknowledge().unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("missing prior error End")
    };
    let prior = end.unwrap_err();
    assert_eq!(prior.details["actual_consumed_rows"], "original-detail");
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    // Test-only corruption models a builder whose total contradicts consumed rows.
    let mut inconsistent = terminal(&f);
    inconsistent.computation_complete(0).unwrap();
    pending.terminal = Some(inconsistent);
    let error = receipt.finish(&mut pending).unwrap_err();
    assert_eq!(error.code, prior.code);
    assert_eq!(error.stage, prior.stage);
    assert_eq!(error.message, prior.message);
    for (name, value) in &prior.details {
        assert_eq!(error.details.get(name), Some(value));
    }
    assert_eq!(error.details["receipt_actual_consumed_rows_1"], "1");
    assert!(!pending.completed);
}

#[test]
fn delivery_receipt_preserves_existing_failure_after_budget_deadline() {
    let limits = BudgetLimits::default().deadlines(250, 5000).unwrap();
    let f = setup_with_rows(limits, 1);
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits {
            max_output_rows: 0,
            ..ExecutionLimits::default()
        })
        .with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("quota failure did not produce End")
    };
    assert_eq!(end.unwrap_err().code, ErrorCode::QuotaExceeded);
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    let wait_started = std::time::Instant::now();
    loop {
        if let Err(error) = f.runtime.pool().checkpoint() {
            assert_eq!(error.code, ErrorCode::DeadlineExceeded);
            break;
        }
        assert!(wait_started.elapsed() < std::time::Duration::from_secs(3));
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let result = receipt.finish(&mut pending).unwrap();
    assert_eq!(result.error.unwrap().code, ErrorCode::QuotaExceeded);
    assert!(!f.cancel.status().unwrap().delivery_complete);
}

#[test]
fn worker_loss_and_cancel_before_final_receipt_are_not_success() {
    let f = setup(BudgetLimits::default());
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    sender.send(vec![Value::U64(DecimalU64(1))], 16).unwrap();
    drop(sender);
    assert_eq!(
        f.cancel.status().unwrap().error.unwrap().code,
        ErrorCode::WorkerLost
    );
    let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
        panic!("missing prefix")
    };
    packet.acknowledge().unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("missing lost end")
    };
    assert_eq!(end.unwrap_err().code, ErrorCode::WorkerLost);
    drop(receiver);
    assert_eq!(
        f.cancel.status().unwrap().error.unwrap().code,
        ErrorCode::WorkerLost
    );
    assert!(!f.cancel.status().unwrap().delivery_complete);

    let f = setup_with_rows(BudgetLimits::default(), 0);
    let (sender, mut receiver) =
        bounded_channel(f.runtime.pool().clone(), Some(f.cancel.clone()), 2).unwrap();
    let mut pending = execute_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        &sender,
    )
    .unwrap();
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    f.cancel.cancel().unwrap();
    let envelope = receipt.finish(&mut pending).unwrap();
    assert_eq!(envelope.error.as_ref().unwrap().code, ErrorCode::Cancelled);
    assert!(!envelope.is_complete_result());
    assert_eq!(
        f.cancel.status().unwrap().error.unwrap().code,
        ErrorCode::Cancelled
    );
    assert!(!f.cancel.status().unwrap().delivery_complete);
}
#[test]
fn quota_after_rows_has_failure_terminal_and_preserves_real_compute_axis() {
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let f = setup(BudgetLimits::default());
        let builder = terminal(&f);
        let identity = builder.identity().clone();
        let mut receiver = StreamVerifier::new(
            identity,
            "generic-owned-test-table".into(),
            vec!["structure".into()],
        )
        .unwrap();
        let mut accepted = Vec::new();
        let mut control = Control::new(ExecutionLimits {
            max_output_rows: 2,
            ..ExecutionLimits::default()
        })
        .with_runtime(f.runtime.clone());
        let end = execute_trusted_into(
            &f.prepared,
            &f.source,
            mode,
            &mut control,
            builder,
            |sequence, row| {
                accepted.push(row.clone());
                receiver.batch(
                    sequence,
                    &f.prepared.runtime_binding().unwrap().schema_id,
                    1,
                )
            },
        )
        .unwrap();
        assert_eq!(accepted.len(), 2);
        assert_eq!(end.operation_status, OperationStatus::Error);
        assert_eq!(end.error.as_ref().unwrap().code, ErrorCode::QuotaExceeded);
        assert_eq!(end.response.emitted_rows.0, 2);
        assert!(end.response.truncated);
        assert_eq!(
            end.execution.complete,
            matches!(mode, ExecutionMode::MaterializedReference)
        );
        assert_eq!(end.coverage.facts, Completeness::Complete);
        let status = f.cancel.status().unwrap();
        assert_eq!(status.execution_complete, end.execution.complete);
        assert!(!status.delivery_complete);
        receiver.terminal(end.clone()).unwrap();
        assert_eq!(
            receiver
                .finish()
                .unwrap()
                .require_complete()
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        println!(
            "{}",
            serde_json::json!({"case":"quota-after-two-accepted-rows","mode":mode,"terminal":end,"status":status,"accepted":accepted})
        );
    }
}
#[test]
fn native_cancel_after_prefix_isolated_from_sibling_and_computed_spool_retained() {
    for mode in [
        ExecutionMode::Streaming,
        ExecutionMode::MaterializedReference,
    ] {
        let f = setup(BudgetLimits::default());
        let sibling = f
            .lifecycle
            .prepare_query(
                &f.session,
                f.prepared.runtime_binding().unwrap(),
                ResourceLimits::default(),
            )
            .unwrap();
        f.lifecycle.start_query(&f.session, &sibling, 1).unwrap();
        let mut rows = 0;
        let mut control = Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone());
        let end = execute_trusted_into(
            &f.prepared,
            &f.source,
            mode,
            &mut control,
            terminal(&f),
            |_, _| {
                rows += 1;
                f.cancel.cancel()?;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(rows, 1);
        assert_eq!(end.operation_status, OperationStatus::Cancelled);
        assert_eq!(end.response.emitted_rows.0, 1);
        assert_eq!(
            end.execution.complete,
            matches!(mode, ExecutionMode::MaterializedReference)
        );
        f.lifecycle.checkpoint(&sibling).unwrap();
        println!(
            "{}",
            serde_json::json!({"case":"native-cancel-one-query","mode":mode,"terminal":end,"sibling_active":true})
        );
    }
}
#[test]
fn zero_deadline_and_unconsumed_cursor_do_not_become_empty_success() {
    let f = setup(BudgetLimits::default().deadlines(0, 0).unwrap());
    let mut rows = 0;
    let end = execute_trusted_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        |_, _| {
            rows += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(rows, 0);
    assert_eq!(end.error.unwrap().code, ErrorCode::DeadlineExceeded);
    let f = setup(BudgetLimits::default());
    let cursor = f
        .lifecycle
        .open_cursor(&f.session, f.cancel.query_handle())
        .unwrap();
    f.lifecycle.close_cursor(&cursor).unwrap();
    let end = execute_trusted_into(
        &f.prepared,
        &f.source,
        ExecutionMode::MaterializedReference,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        |_, _| Ok(()),
    )
    .unwrap();
    assert!(end.execution.complete);
    assert_eq!(end.error.unwrap().code, ErrorCode::InvalidCursor);
    assert!(!f.cancel.status().unwrap().delivery_complete);
}
#[test]
fn computation_claim_is_atomic_and_later_attempt_cannot_fail_original() {
    let f = setup(BudgetLimits::default());
    let first = f
        .lifecycle
        .cancellation_token(f.cancel.query_handle())
        .unwrap();
    let second = f
        .lifecycle
        .cancellation_token(f.cancel.query_handle())
        .unwrap();
    first.claim_execution().unwrap();
    assert_eq!(
        second.claim_execution().err().unwrap().code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        first.status().unwrap().phase,
        mdd_session::QueryPhase::Active
    );
}

#[test]
fn runtime_owner_and_prepared_binding_are_verified_before_execution_claim() {
    let f = setup(BudgetLimits::default());
    let original = terminal(&f);
    let mut identity = original.identity().clone();
    identity.session_id = Some("another-session".into());
    let wrong = TerminalBuilder::new(identity, original.coverage().clone()).unwrap();
    let error = execute_trusted_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        wrong,
        |_, _| Ok(()),
    )
    .err()
    .unwrap();
    assert_eq!(error.details["reason"], "TERMINAL_SESSION_OWNER");
    let different_plan = prepare(
        QueryIr {
            schema_version: IR_VERSION.into(),
            text_semantics: TEXT_VERSION.into(),
            snapshot_id: f.source.snapshot_id().into(),
            catalog_epoch: DecimalU64(0),
            require_stable_order: false,
            root: Node::Limit {
                input: Box::new(Node::Scan {
                    relation: "rows".into(),
                }),
                offset: DecimalU64(0),
                count: DecimalU64(1),
            },
        },
        &f.source,
    )
    .unwrap();
    assert_eq!(
        execute(
            &different_plan,
            &f.source,
            ExecutionMode::Streaming,
            &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone())
        )
        .err()
        .unwrap()
        .details["reason"],
        "RUNTIME_QUERY_SNAPSHOT_GENERATION_OR_BINDING"
    );
    let end = execute_trusted_into(
        &f.prepared,
        &f.source,
        ExecutionMode::Streaming,
        &mut Control::new(ExecutionLimits::default()).with_runtime(f.runtime.clone()),
        terminal(&f),
        |_, _| Ok(()),
    )
    .unwrap();
    assert!(end.is_complete_result());
    assert!(f.cancel.status().unwrap().delivery_complete);
}
