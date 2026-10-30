use super::*;
use std::sync::mpsc;
use std::thread;

#[test]
fn poisoned_producer_claim_preserves_internal_fault() {
    use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
    use mdd_session::{Lifecycle, QueryBinding, ResourceLimits};
    for mode in ["tracker", "queue", "prior_cancel"] {
        let limits = ResourceLimits::default();
        let lifecycle = Lifecycle::new(limits).unwrap();
        let snapshot = Snapshot::capture(
            &[InputSpec {
                path: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/fixtures/generated/minimal-035.dex"),
                kind: InputKind::RawDex,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
        )
        .unwrap();
        let snapshot = lifecycle.register_snapshot(Arc::new(snapshot)).unwrap();
        let session = lifecycle.open_session(&snapshot, limits).unwrap();
        let query = lifecycle
            .prepare_query(
                &session,
                QueryBinding {
                    request_key: "claim-poison".into(),
                    schema_id: "rows".into(),
                    semantic_version: "v1".into(),
                },
                limits,
            )
            .unwrap();
        lifecycle.start_query(&session, &query, 1).unwrap();
        let cancel = lifecycle.cancellation_token(&query).unwrap();
        let pool = BudgetPool::global("g".into(), BudgetLimits::default())
            .unwrap()
            .child(
                cancel.worker_owner_id().unwrap(),
                BudgetScope::Worker,
                BudgetLimits::default(),
            )
            .unwrap()
            .child(
                session.id().into(),
                BudgetScope::Session,
                BudgetLimits::default(),
            )
            .unwrap()
            .child(
                query.id().into(),
                BudgetScope::Query,
                BudgetLimits::default(),
            )
            .unwrap();
        let (sender, receiver) = bounded_channel::<u8>(pool, Some(cancel.clone()), 1).unwrap();
        if mode == "prior_cancel" {
            cancel.cancel().unwrap();
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if mode == "queue" {
                    let _guard = sender.0.state.lock().unwrap();
                    panic!("injected claim queue poison");
                }
                let tracker = Arc::clone(sender.0.delivery.as_ref().unwrap());
                let _guard = tracker.state.lock().unwrap();
                panic!("injected claim tracker poison");
            }))
            .is_err()
        );
        let returned = sender.claim_producer().err().unwrap();
        drop(receiver);
        let first = cancel.status().unwrap().error.unwrap();
        assert_eq!(
            returned.code,
            if mode == "prior_cancel" {
                ErrorCode::Cancelled
            } else {
                ErrorCode::InternalFault
            }
        );
        assert_eq!(first.code, returned.code);
        assert_eq!(first.stage, returned.stage);
        assert_eq!(first.message, returned.message);
    }
}

#[test]
fn poisoned_receipt_matching_preserves_internal_fault() {
    use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
    use mdd_session::{Lifecycle, QueryBinding, ResourceLimits};
    let limits = ResourceLimits::default();
    let lifecycle = Lifecycle::new(limits).unwrap();
    let snapshot = Snapshot::capture(
        &[InputSpec {
            path: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/generated/minimal-035.dex"),
            kind: InputKind::RawDex,
            expected_sha256: None,
        }],
        CaptureLimits::default(),
    )
    .unwrap();
    let snapshot = lifecycle.register_snapshot(Arc::new(snapshot)).unwrap();
    let session = lifecycle.open_session(&snapshot, limits).unwrap();
    let query = lifecycle
        .prepare_query(
            &session,
            QueryBinding {
                request_key: "receipt-poison".into(),
                schema_id: "rows".into(),
                semantic_version: "v1".into(),
            },
            limits,
        )
        .unwrap();
    lifecycle.start_query(&session, &query, 1).unwrap();
    let cancel = lifecycle.cancellation_token(&query).unwrap();
    let pool = BudgetPool::global("g".into(), BudgetLimits::default())
        .unwrap()
        .child(
            cancel.worker_owner_id().unwrap(),
            BudgetScope::Worker,
            BudgetLimits::default(),
        )
        .unwrap()
        .child(
            session.id().into(),
            BudgetScope::Session,
            BudgetLimits::default(),
        )
        .unwrap()
        .child(
            query.id().into(),
            BudgetScope::Query,
            BudgetLimits::default(),
        )
        .unwrap();
    let runtime = RuntimeBudget::new(pool.clone(), cancel.clone()).unwrap();
    let (sender, mut receiver) = bounded_channel::<u8>(pool, Some(cancel.clone()), 1).unwrap();
    sender.finish(Ok(())).unwrap();
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    let receipt = receiver.into_delivery_receipt().unwrap();
    let tracker = Arc::clone(&receipt.tracker);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = tracker.state.lock().unwrap();
            panic!("injected receipt tracker poison");
        }))
        .is_err()
    );
    let returned = receipt.matches(&sender, &runtime, 0, None).unwrap_err();
    drop(receipt);
    let first = cancel.status().unwrap().error.unwrap();
    assert_eq!(returned.code, ErrorCode::InternalFault);
    assert_eq!(first.code, returned.code);
    assert_eq!(first.stage, returned.stage);
    assert_eq!(first.message, returned.message);
}

#[test]
fn poisoned_terminal_tracking_preserves_first_fault() {
    use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
    use mdd_session::{Lifecycle, QueryBinding, ResourceLimits};
    let mut failures = Vec::new();
    for mode in ["end", "receipt"] {
        let limits = ResourceLimits::default();
        let lifecycle = Lifecycle::new(limits).unwrap();
        let snapshot = Snapshot::capture(
            &[InputSpec {
                path: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/fixtures/generated/minimal-035.dex"),
                kind: InputKind::RawDex,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
        )
        .unwrap();
        let snapshot = lifecycle.register_snapshot(Arc::new(snapshot)).unwrap();
        let session = lifecycle.open_session(&snapshot, limits).unwrap();
        let query = lifecycle
            .prepare_query(
                &session,
                QueryBinding {
                    request_key: "terminal-poison".into(),
                    schema_id: "rows".into(),
                    semantic_version: "v1".into(),
                },
                limits,
            )
            .unwrap();
        lifecycle.start_query(&session, &query, 1).unwrap();
        let cancel = lifecycle.cancellation_token(&query).unwrap();
        let pool = BudgetPool::global("g".into(), BudgetLimits::default())
            .unwrap()
            .child(
                cancel.worker_owner_id().unwrap(),
                BudgetScope::Worker,
                BudgetLimits::default(),
            )
            .unwrap()
            .child(
                session.id().into(),
                BudgetScope::Session,
                BudgetLimits::default(),
            )
            .unwrap()
            .child(
                query.id().into(),
                BudgetScope::Query,
                BudgetLimits::default(),
            )
            .unwrap();
        let (sender, mut receiver) = bounded_channel::<u8>(pool, Some(cancel.clone()), 1).unwrap();
        sender.finish(Ok(())).unwrap();
        if mode == "receipt" {
            assert!(matches!(
                receiver.receive().unwrap(),
                QueueEvent::End(Ok(()))
            ));
        }
        let tracker = Arc::clone(sender.0.delivery.as_ref().unwrap());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = tracker.state.lock().unwrap();
                panic!("injected tracker poisoning");
            }))
            .is_err()
        );
        let returned = if mode == "end" {
            let error = receiver.receive().err().unwrap();
            drop(receiver);
            error
        } else {
            receiver.into_delivery_receipt().err().unwrap()
        };
        let first = cancel.status().unwrap().error.unwrap();
        assert_eq!(returned.code, ErrorCode::InternalFault);
        if first.code != returned.code
            || first.stage != returned.stage
            || first.message != returned.message
        {
            failures.push((mode, first.code, returned.code));
        }
    }
    assert!(failures.is_empty(), "first faults differ: {failures:?}");
}

#[test]
fn poisoned_acknowledgement_preserves_internal_fault() {
    use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
    use mdd_session::{Lifecycle, QueryBinding, ResourceLimits};
    for mode in ["poison", "overflow"] {
        let limits = ResourceLimits::default();
        let lifecycle = Lifecycle::new(limits).unwrap();
        let snapshot = Snapshot::capture(
            &[InputSpec {
                path: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/fixtures/generated/minimal-035.dex"),
                kind: InputKind::RawDex,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
        )
        .unwrap();
        let snapshot = lifecycle.register_snapshot(Arc::new(snapshot)).unwrap();
        let session = lifecycle.open_session(&snapshot, limits).unwrap();
        let query = lifecycle
            .prepare_query(
                &session,
                QueryBinding {
                    request_key: "ack-poison".into(),
                    schema_id: "rows".into(),
                    semantic_version: "v1".into(),
                },
                limits,
            )
            .unwrap();
        lifecycle.start_query(&session, &query, 1).unwrap();
        let cancel = lifecycle.cancellation_token(&query).unwrap();
        let pool = BudgetPool::global("g".into(), BudgetLimits::default())
            .unwrap()
            .child(
                cancel.worker_owner_id().unwrap(),
                BudgetScope::Worker,
                BudgetLimits::default(),
            )
            .unwrap()
            .child(
                session.id().into(),
                BudgetScope::Session,
                BudgetLimits::default(),
            )
            .unwrap()
            .child(
                query.id().into(),
                BudgetScope::Query,
                BudgetLimits::default(),
            )
            .unwrap();
        let (sender, mut receiver) = bounded_channel::<u8>(pool, Some(cancel.clone()), 1).unwrap();
        sender.send(7, 1).unwrap();
        let QueueEvent::Data(mut packet) = receiver.receive().unwrap() else {
            panic!("expected packet")
        };
        let tracker = Arc::clone(&packet.acknowledgement.as_ref().unwrap().tracker);
        if mode == "poison" {
            let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = tracker.state.lock().unwrap();
                panic!("injected tracker mutex poisoning");
            }));
            assert!(poisoned.is_err());
        } else {
            packet.acknowledgement.as_mut().unwrap().sequence = u64::MAX;
            tracker.state.lock().unwrap().acknowledged = u64::MAX;
        }
        let returned = packet.acknowledge().unwrap_err();
        assert_eq!(returned.code, ErrorCode::InternalFault);
        let first = cancel.status().unwrap().error.unwrap();
        assert_eq!(first.code, returned.code);
        assert_eq!(first.stage, returned.stage);
        assert_eq!(first.message, returned.message);
    }
}

fn tree(limits: BudgetLimits) -> (BudgetPool, BudgetPool, BudgetPool, BudgetPool) {
    let global = BudgetPool::global("global".into(), limits.clone()).unwrap();
    let worker = global
        .child("worker".into(), BudgetScope::Worker, limits.clone())
        .unwrap();
    let session = worker
        .child("session".into(), BudgetScope::Session, limits.clone())
        .unwrap();
    let query = session
        .child("query".into(), BudgetScope::Query, limits)
        .unwrap();
    (global, worker, session, query)
}
fn used(pool: &BudgetPool, resource: Resource) -> u64 {
    pool.usage().unwrap().used.get(&resource).map_or(0, |v| v.0)
}

#[test]
fn release_underflow_leaves_all_accounting_unchanged() {
    let (_, _, _, query) = tree(BudgetLimits::default());
    let mut state = query.state.lock().unwrap();
    // Explicit fault injection: this inconsistent accounting is not claimed
    // to arise from any normal producer input.
    let node = state.nodes.get_mut(&query.owner).unwrap();
    node.used.insert(Resource::QueryWorkspaceBytes, 5);
    node.used.insert(Resource::ResidentBytes, 0);
    let before: Vec<_> = BudgetPool::ancestors(&state, &query.owner)
        .iter()
        .map(|owner| state.nodes[owner].used.clone())
        .collect();
    assert_eq!(
        release(&mut state, &query, Resource::QueryWorkspaceBytes, 1)
            .unwrap_err()
            .code,
        ErrorCode::InternalFault
    );
    let after: Vec<_> = BudgetPool::ancestors(&state, &query.owner)
        .iter()
        .map(|owner| state.nodes[owner].used.clone())
        .collect();
    assert_eq!(before, after);
    assert_eq!(state.fault.as_ref().unwrap().code, ErrorCode::InternalFault);
    drop(state);
    assert_eq!(query.usage().unwrap_err().code, ErrorCode::InternalFault);
}

#[test]
fn reservation_drop_preserves_prior_fault_when_count_underflows() {
    let (_, _, _, query) = tree(BudgetLimits::default());
    let reservation = query.reserve(Resource::QueryWorkspaceBytes, 3).unwrap();
    let prior = MddError::new(
        ErrorCode::InternalFault,
        "test.first",
        "injected first fault",
    )
    .detail("origin", "prior");
    {
        let mut state = query.state.lock().unwrap();
        // Explicit internal fault injection; not a naturally observed input.
        state.live_reservations = 0;
        state.fault = Some(prior.clone());
    }
    drop(reservation);
    let state = query.state.lock().unwrap();
    let actual = state.fault.as_ref().unwrap();
    assert_eq!(actual.code, prior.code);
    assert_eq!(actual.stage, prior.stage);
    assert_eq!(actual.message, prior.message);
    assert_eq!(actual.details, prior.details);
}

#[test]
fn unbound_terminal_delivered_after_deadline_is_not_success() {
    for with_row in [false, true] {
        let limits = BudgetLimits::default().deadlines(150, 5000).unwrap();
        let (_, _, _, pool) = tree(limits);
        let (sender, mut receiver) = bounded_channel::<u8>(pool.clone(), None, 1).unwrap();
        if with_row {
            sender.send(7, 1).unwrap();
        }
        sender.finish(Ok(())).unwrap();
        let started = std::time::Instant::now();
        loop {
            if let Err(error) = pool.checkpoint() {
                assert_eq!(error.code, ErrorCode::DeadlineExceeded);
                break;
            }
            assert!(started.elapsed() < std::time::Duration::from_secs(3));
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        if with_row {
            let QueueEvent::Data(row) = receiver.receive().unwrap() else {
                panic!("the previously queued row is missing");
            };
            assert_eq!(*row.payload(), 7);
            drop(row);
        }
        let QueueEvent::End(result) = receiver.receive().unwrap() else {
            panic!("the terminal is missing");
        };
        assert_eq!(result.unwrap_err().code, ErrorCode::DeadlineExceeded);
    }
}

#[test]
fn unbound_terminal_preserves_prior_error_after_deadline() {
    let (_, _, _, pool) = tree(BudgetLimits::default().deadlines(150, 5000).unwrap());
    let (sender, mut receiver) = bounded_channel::<u8>(pool.clone(), None, 1).unwrap();
    let expected = MddError::new(ErrorCode::IncompleteFacts, "test.source", "source failed")
        .detail("source", "original");
    sender.finish(Err(expected.clone())).unwrap();
    let started = std::time::Instant::now();
    loop {
        if let Err(error) = pool.checkpoint() {
            assert_eq!(error.code, ErrorCode::DeadlineExceeded);
            break;
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let QueueEvent::End(result) = receiver.receive().unwrap() else {
        panic!("the failure terminal is missing");
    };
    let actual = result.unwrap_err();
    assert_eq!(actual.code, expected.code);
    assert_eq!(actual.stage, expected.stage);
    assert_eq!(actual.message, expected.message);
    assert_eq!(actual.details, expected.details);
}

#[test]
fn poisoned_budget_checkpoint_records_fault_and_preserves_prior_cancel() {
    use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
    use mdd_session::{Lifecycle, QueryBinding, ResourceLimits};
    use std::path::PathBuf;

    for entry in ["runtime", "receive", "finish"] {
        for prior_cancel in [false, true] {
            let limits = ResourceLimits::default();
            let lifecycle = Lifecycle::new(limits).unwrap();
            let snapshot = Snapshot::capture(
                &[InputSpec {
                    path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("../../tests/fixtures/generated/minimal-035.dex"),
                    kind: InputKind::RawDex,
                    expected_sha256: None,
                }],
                CaptureLimits::default(),
            )
            .unwrap();
            let snapshot = lifecycle.register_snapshot(Arc::new(snapshot)).unwrap();
            let session = lifecycle.open_session(&snapshot, limits).unwrap();
            let query = lifecycle
                .prepare_query(
                    &session,
                    QueryBinding {
                        request_key: "poison-test".into(),
                        schema_id: "rows".into(),
                        semantic_version: "v1".into(),
                    },
                    limits,
                )
                .unwrap();
            lifecycle.start_query(&session, &query, 1).unwrap();
            let cancel = lifecycle.cancellation_token(&query).unwrap();
            let pool = BudgetPool::global("g".into(), BudgetLimits::default())
                .unwrap()
                .child(
                    cancel.worker_owner_id().unwrap(),
                    BudgetScope::Worker,
                    BudgetLimits::default(),
                )
                .unwrap()
                .child(
                    session.id().into(),
                    BudgetScope::Session,
                    BudgetLimits::default(),
                )
                .unwrap()
                .child(
                    query.id().into(),
                    BudgetScope::Query,
                    BudgetLimits::default(),
                )
                .unwrap();
            let runtime = RuntimeBudget::new(pool.clone(), cancel.clone()).unwrap();
            let (sender, mut receiver) =
                bounded_channel::<u8>(pool.clone(), Some(cancel.clone()), 1).unwrap();
            if prior_cancel {
                cancel.cancel().unwrap();
            }
            let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = pool.state.lock().unwrap();
                panic!("controlled budget mutex poisoning");
            }));
            assert!(poisoned.is_err());
            let error = match entry {
                "receive" => receiver.receive().err().unwrap(),
                "finish" => sender.finish(Ok(())).unwrap_err(),
                _ => runtime.checkpoint().unwrap_err(),
            };
            let expected = if prior_cancel {
                ErrorCode::Cancelled
            } else {
                ErrorCode::InternalFault
            };
            assert_eq!(
                error.code, expected,
                "entry={entry} prior_cancel={prior_cancel}"
            );
            if entry == "finish" {
                let QueueEvent::End(end) = receiver.receive().unwrap() else {
                    panic!("poisoned budget did not produce an error End");
                };
                assert_eq!(end.unwrap_err().code, expected);
            }
            let first = cancel
                .status()
                .unwrap()
                .error
                .expect("missing lifecycle terminal");
            assert_eq!(first.code, error.code);
            assert_eq!(first.stage, error.stage);
            assert_eq!(first.message, error.message);
        }
    }
}
#[test]
fn queue_finish_expired_budget_unbound_still_emits_failure() {
    let (_, _, _, query) = tree(BudgetLimits::default().deadlines(0, 60_000).unwrap());
    let (sender, mut receiver) = bounded_channel::<u8>(query, None, 1).unwrap();
    let error = sender.finish(Ok(())).unwrap_err();
    assert_eq!(error.code, ErrorCode::DeadlineExceeded);
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("expired unbound queue did not publish an error End");
    };
    assert_eq!(end.unwrap_err().code, error.code);
}

#[test]
fn all_budget_dimensions_restrict_atomically_and_resident_leases_release() {
    for resource in RESOURCES {
        let (global, _, session, query) = tree(BudgetLimits::default().with(resource, 3));
        assert_eq!(query.limit(resource).unwrap(), 3);
        if resource == Resource::MemberUncompressedBytes {
            query.check_individual(resource, 3).unwrap();
            assert_eq!(
                query.check_individual(resource, 4).err().unwrap().code,
                ErrorCode::QuotaExceeded
            );
            continue;
        }
        if resource.resident() {
            let lease = query.reserve(resource, 2).unwrap();
            assert_eq!(
                query.reserve(resource, 2).err().unwrap().code,
                ErrorCode::QuotaExceeded
            );
            assert_eq!(used(&global, resource), 2);
            drop(lease);
            assert_eq!(used(&global, resource), 0);
        } else {
            query.charge(resource, 2).unwrap();
            assert_eq!(
                query.charge(resource, 2).err().unwrap().code,
                ErrorCode::QuotaExceeded
            );
            assert_eq!(used(&session, resource), 2);
            assert_eq!(used(&global, resource), 2);
        }
    }
    let (global, _, session, query) = tree(BudgetLimits::default().with(Resource::InputBytes, 3));
    let sibling = session
        .child(
            "sibling".into(),
            BudgetScope::Query,
            BudgetLimits::default(),
        )
        .unwrap();
    query.charge(Resource::InputBytes, 2).unwrap();
    assert_eq!(
        sibling.charge(Resource::InputBytes, 2).err().unwrap().code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(used(&sibling, Resource::InputBytes), 0);
    assert_eq!(used(&global, Resource::InputBytes), 2);
}
#[test]
fn shared_ready_objects_have_one_owner_and_per_object_borrow_admission() {
    let (global, worker, _, query) =
        tree(BudgetLimits::default().with(Resource::ReadyFactsBytes, 10));
    let allocation = Arc::new(vec![0u8; 6]);
    let one = worker
        .reserve_arc(&allocation, Resource::ReadyFactsBytes, 6)
        .unwrap();
    let same = worker
        .reserve_arc(&allocation, Resource::ReadyFactsBytes, 6)
        .unwrap();
    let borrowed = one.borrow_for(&query).unwrap();
    assert_eq!(used(&global, Resource::ReadyFactsBytes), 6);
    assert_eq!(used(&query, Resource::ReadyFactsBytes), 0);
    assert!(
        worker
            .reserve_arc(&allocation, Resource::ReadyFactsBytes, 5)
            .is_err()
    );
    assert_eq!(
        worker
            .reserve_arc(&Arc::new(vec![0u8; 6]), Resource::ReadyFactsBytes, 6)
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    drop(one);
    drop(same);
    assert_eq!(used(&global, Resource::ReadyFactsBytes), 6);
    drop(borrowed);
    assert_eq!(used(&global, Resource::ReadyFactsBytes), 0);
}
#[test]
fn unbound_sender_quota_remains_recoverable() {
    let (_, _, _, query) = tree(BudgetLimits::default().with(Resource::QueueBytes, 4));
    let (sender, mut receiver) = bounded_channel::<u8>(query, None, 1).unwrap();
    assert_eq!(
        sender.send(1, 5).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    sender.send(2, 4).unwrap();
    sender.finish(Ok(())).unwrap();
    let QueueEvent::Data(packet) = receiver.receive().unwrap() else {
        panic!("valid unbound retry was not delivered");
    };
    assert_eq!(*packet.payload(), 2);
    drop(packet);
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
}

#[test]
fn queue_backpressure_and_dequeued_payload_keep_memory_until_consumer_drop() {
    let (global, _, _, query) = tree(BudgetLimits::default().with(Resource::QueueItems, 1));
    let (sender, mut receiver) = bounded_channel(query, None, 1).unwrap();
    sender.send(vec![1u8; 4], 4).unwrap();
    let (ready, started) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    let handle = thread::spawn(move || {
        ready.send(()).unwrap();
        sender.send(vec![2u8; 4], 4).unwrap();
        done.send(()).unwrap();
        sender.finish(Ok(())).unwrap();
    });
    started.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(finished.recv_timeout(Duration::from_millis(10)).is_err());
    let QueueEvent::Data(first) = receiver.receive().unwrap() else {
        panic!("missing first packet");
    };
    assert_eq!(first.payload(), &vec![1u8; 4]);
    finished.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(used(&global, Resource::QueryWorkspaceBytes) >= 8);
    drop(first);
    let QueueEvent::Data(second) = receiver.receive().unwrap() else {
        panic!("missing second packet");
    };
    assert_eq!(used(&global, Resource::QueueBytes), 0);
    assert_eq!(used(&global, Resource::QueryWorkspaceBytes), 4);
    drop(second);
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    handle.join().unwrap();
    assert_eq!(used(&global, Resource::QueryWorkspaceBytes), 0);
}
#[test]
fn producer_drop_after_prefix_is_worker_lost_and_explicit_failure_stays_failure() {
    let (_, _, _, query) = tree(BudgetLimits::default());
    let (sender, mut receiver) = bounded_channel(query, None, 2).unwrap();
    sender.send(7, 4).unwrap();
    drop(sender);
    assert!(matches!(receiver.receive().unwrap(), QueueEvent::Data(_)));
    let QueueEvent::End(error) = receiver.receive().unwrap() else {
        panic!("missing failure terminal");
    };
    assert_eq!(error.err().unwrap().code, ErrorCode::WorkerLost);
    let (_, _, _, query) = tree(BudgetLimits::default());
    let (sender, mut receiver) = bounded_channel::<u8>(query, None, 1).unwrap();
    sender
        .finish(Err(MddError::new(
            ErrorCode::QuotaExceeded,
            "test",
            "actual stop",
        )))
        .unwrap();
    let QueueEvent::End(end) = receiver.receive().unwrap() else {
        panic!("missing quota terminal");
    };
    assert_eq!(end.err().unwrap().code, ErrorCode::QuotaExceeded);
    assert!(sender.finish(Ok(())).is_err());
    assert!(sender.send(1, 1).is_err());
}
#[test]
fn absolute_soft_hard_deadlines_and_large_json_limits_are_explicit() {
    let (_, _, _, soft) = tree(BudgetLimits::default().deadlines(0, 100).unwrap());
    assert_eq!(
        soft.checkpoint().err().unwrap().details["deadline_kind"],
        "soft"
    );
    assert!(!soft.hard_deadline_due().unwrap());
    let (_, _, _, hard) = tree(BudgetLimits::default().deadlines(0, 0).unwrap());
    assert!(hard.hard_deadline_due().unwrap());
    assert_eq!(
        hard.checkpoint().err().unwrap().details["supervisor_termination_required"],
        true
    );
    let value =
        serde_json::to_value(BudgetLimits::default().with(Resource::InputBytes, u64::MAX)).unwrap();
    assert_eq!(value["values"]["input_bytes"], u64::MAX.to_string());
}

#[test]
fn unbound_queue_deadline_remains_a_deadline() {
    let (_, _, _, query) = tree(BudgetLimits::default().deadlines(0, 60_000).unwrap());
    let (_sender, mut receiver) = bounded_channel::<u8>(query, None, 1).unwrap();
    assert_eq!(
        receiver.receive().err().unwrap().code,
        ErrorCode::DeadlineExceeded
    );
}

#[test]
fn owner_and_zero_byte_reservation_metadata_caps_are_actual_quota_errors() {
    let global = BudgetPool::global("owners".into(), BudgetLimits::default()).unwrap();
    let worker = global
        .child(
            "worker".into(),
            BudgetScope::Worker,
            BudgetLimits::default(),
        )
        .unwrap();
    for n in 0..9998 {
        worker
            .child(
                format!("session-{n}"),
                BudgetScope::Session,
                BudgetLimits::default(),
            )
            .unwrap();
    }
    let error = worker
        .child(
            "one-too-many".into(),
            BudgetScope::Session,
            BudgetLimits::default(),
        )
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert_eq!(error.details["budget"], "budget_owners");
    assert_eq!(error.details["limit"], "10000");
    let (_, _, _, query) = tree(BudgetLimits::default());
    let mut leases = Vec::new();
    for _ in 0..10000 {
        leases.push(query.reserve(Resource::QueueItems, 0).unwrap());
    }
    let error = query.reserve(Resource::QueueItems, 0).err().unwrap();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert_eq!(error.details["budget"], "live_reservations");
    drop(leases);
    query.reserve(Resource::QueueItems, 0).unwrap();
}

#[test]
fn pending_senders_hold_resident_admission_before_a_queue_slot() {
    let (_, _, _, query) = tree(BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 8));
    let (sender, receiver) = bounded_channel::<Vec<u8>>(query.clone(), None, 1).unwrap();
    sender.send(vec![1; 4], 4).unwrap();
    let waiting = sender.try_clone().unwrap();
    let waiting_thread = thread::spawn(move || waiting.send(vec![2; 4], 4));
    let limit = Instant::now() + Duration::from_secs(1);
    while used(&query, Resource::QueryWorkspaceBytes) != 8 && Instant::now() < limit {
        thread::sleep(Duration::from_millis(1));
    }
    let observed = used(&query, Resource::QueryWorkspaceBytes);
    let excess = sender.try_clone().unwrap();
    let (result_tx, result_rx) = mpsc::channel();
    let excess_thread = thread::spawn(move || {
        let outcome = excess.send(vec![3], 1);
        result_tx.send(outcome).unwrap();
    });
    let outcome = result_rx.recv_timeout(Duration::from_millis(200));
    drop(receiver);
    let waiting_result = waiting_thread.join().unwrap();
    excess_thread.join().unwrap();
    assert_eq!(observed, 8);
    assert_eq!(outcome.unwrap().unwrap_err().code, ErrorCode::QuotaExceeded);
    assert!(waiting_result.is_err());
    assert_eq!(used(&query, Resource::QueryWorkspaceBytes), 0);
}
