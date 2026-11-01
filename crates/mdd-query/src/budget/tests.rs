use super::*;
use std::sync::mpsc;
use std::thread;

#[test]
fn sender_drop_terminal_preserves_prior_query_failure() {
    for first in [
        MddError::new(ErrorCode::Cancelled, "test.cancel", "caller cancelled")
            .detail("reason", "explicit"),
        MddError::new(ErrorCode::QuotaExceeded, "test.quota", "budget exceeded")
            .detail("resource", "steps"),
    ] {
        let (_, _, _, _, runtime) = owned_queue_test_runtime(BudgetLimits::default());
        let (sender, mut receiver) = bounded_channel::<()>(
            runtime.pool().clone(),
            Some(runtime.cancellation().clone()),
            1,
        )
        .unwrap();
        runtime.cancellation().fail(first.clone()).unwrap();
        drop(sender);
        let QueueEvent::End(Err(actual)) = receiver.receive().unwrap() else {
            panic!("sender loss must preserve the earlier query failure")
        };
        assert_eq!(actual.code, first.code);
        assert_eq!(actual.stage, first.stage);
        assert_eq!(actual.message, first.message);
        assert_eq!(actual.retryable, first.retryable);
        assert_eq!(actual.details, first.details);
    }
}

#[test]
fn receiver_drop_releases_reentrant_payload_without_losing_first_error() {
    let (done, finished) = mpsc::channel();
    thread::spawn(move || {
        let (_, _, _, _, runtime) = owned_queue_test_runtime(BudgetLimits::default());
        let (sender, receiver) = bounded_channel::<Box<dyn Send>>(
            runtime.pool().clone(),
            Some(runtime.cancellation().clone()),
            1,
        )
        .unwrap();
        // Dropping this queued payload drops a sender for the same queue.
        sender
            .send(Box::new(sender.try_clone().unwrap()), 7)
            .unwrap();
        let first = MddError::new(ErrorCode::WorkerLost, "test.worker", "original failure");
        runtime.cancellation().fail(first.clone()).unwrap();
        drop(receiver);
        let actual = runtime.cancellation().status().unwrap().error.unwrap();
        assert_eq!(
            (actual.code, actual.stage, actual.message),
            (first.code, first.stage, first.message)
        );
        for resource in [
            Resource::QueueItems,
            Resource::QueueBytes,
            Resource::QueryWorkspaceBytes,
        ] {
            assert_eq!(used(runtime.pool(), resource), 0);
        }
        done.send(()).unwrap();
    });
    finished
        .recv_timeout(Duration::from_secs(2))
        .expect("receiver drop did not finish before deadline");
}

#[test]
fn receiver_drop_last_queued_sender_is_cancelled_not_worker_lost() {
    let (done, finished) = mpsc::channel();
    thread::spawn(move || {
        let (_, _, _, _, runtime) = owned_queue_test_runtime(BudgetLimits::default());
        let (sender, receiver) = bounded_channel::<Box<dyn Send>>(
            runtime.pool().clone(),
            Some(runtime.cancellation().clone()),
            1,
        )
        .unwrap();
        sender
            .send(Box::new(sender.try_clone().unwrap()), 7)
            .unwrap();
        // Only the queued payload still owns a sender.
        drop(sender);
        drop(receiver);
        let status = runtime.cancellation().status().unwrap();
        assert_eq!(status.error.unwrap().code, ErrorCode::Cancelled);
        assert!(!status.delivery_complete);
        assert!(runtime.cancellation().delivery_abandoned().unwrap());
        for resource in [
            Resource::QueueItems,
            Resource::QueueBytes,
            Resource::QueryWorkspaceBytes,
        ] {
            assert_eq!(used(runtime.pool(), resource), 0);
        }
        done.send(()).unwrap();
    });
    finished
        .recv_timeout(Duration::from_secs(2))
        .expect("receiver drop did not finish before deadline");
}

#[test]
fn duplicate_terminal_keeps_first_query_failure() {
    let (_, _, _, _, runtime) = owned_queue_test_runtime(BudgetLimits::default());
    let (sender, _receiver) = bounded_channel::<()>(
        runtime.pool().clone(),
        Some(runtime.cancellation().clone()),
        1,
    )
    .unwrap();
    let first = MddError::new(ErrorCode::WorkerLost, "test.worker", "worker stopped");
    sender.finish(Err(first.clone())).unwrap();
    let actual = sender.finish(Ok(())).unwrap_err();
    assert_eq!(actual.code, first.code);
    assert_eq!(actual.stage, first.stage);
    assert_eq!(actual.message, first.message);
}

#[test]
fn read_after_terminal_keeps_first_query_failure() {
    let (_, _, _, _, runtime) = owned_queue_test_runtime(BudgetLimits::default());
    let (sender, mut receiver) = bounded_channel::<()>(
        runtime.pool().clone(),
        Some(runtime.cancellation().clone()),
        1,
    )
    .unwrap();
    let first = MddError::new(ErrorCode::Cancelled, "test.cancel", "cancelled by caller");
    sender.finish(Err(first.clone())).unwrap();
    let QueueEvent::End(Err(end)) = receiver.receive().unwrap() else {
        panic!("expected the original failure terminal")
    };
    assert_eq!(end.code, first.code);
    let actual = receiver.receive().err().unwrap();
    assert_eq!(actual.code, first.code);
    assert_eq!(actual.stage, first.stage);
    assert_eq!(actual.message, first.message);
}

#[test]
fn duplicate_successful_terminal_is_still_protocol_error() {
    let (_, _, _, _, runtime) = owned_queue_test_runtime(BudgetLimits::default());
    let (sender, _receiver) = bounded_channel::<()>(
        runtime.pool().clone(),
        Some(runtime.cancellation().clone()),
        1,
    )
    .unwrap();
    sender.finish(Ok(())).unwrap();
    assert_eq!(
        sender.finish(Ok(())).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        runtime.cancellation().status().unwrap().error.unwrap().code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn duplicate_terminal_replaces_unconsumed_success_with_failure() {
    let (_, _, _, _, runtime) = owned_queue_test_runtime(BudgetLimits::default());
    let (sender, mut receiver) = bounded_channel::<()>(
        runtime.pool().clone(),
        Some(runtime.cancellation().clone()),
        1,
    )
    .unwrap();
    sender.finish(Ok(())).unwrap();
    let first = sender.finish(Ok(())).unwrap_err();
    assert_eq!(first.code, ErrorCode::InvalidArgument);
    let QueueEvent::End(Err(end)) = receiver.receive().unwrap() else {
        panic!("a protocol failure must replace an unconsumed successful terminal")
    };
    assert_eq!(end.code, first.code);
    assert_eq!(end.stage, first.stage);
    assert_eq!(end.message, first.message);
}

#[test]
fn unbound_send_after_terminal_cannot_leave_successful_end() {
    let pool = BudgetPool::global("unbound-terminal".into(), BudgetLimits::default()).unwrap();
    let (sender, mut receiver) = bounded_channel::<()>(pool, None, 1).unwrap();
    sender.finish(Ok(())).unwrap();
    assert_eq!(
        sender.send((), 0).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    let QueueEvent::End(Err(end)) = receiver.receive().unwrap() else {
        panic!("send after terminal must not leave an unconsumed successful End")
    };
    assert_eq!(end.code, ErrorCode::InvalidArgument);
}

#[test]
fn bound_send_inner_invalidates_pending_success_before_returning() {
    let (_, _, _, _, runtime) = owned_queue_test_runtime(BudgetLimits::default());
    let (sender, mut receiver) = bounded_channel::<()>(
        runtime.pool().clone(),
        Some(runtime.cancellation().clone()),
        1,
    )
    .unwrap();
    sender.finish(Ok(())).unwrap();
    let lease = sender.reserve_payload(0).unwrap();
    assert_eq!(
        sender.send_reserved_inner((), 0, lease).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    let QueueEvent::End(Err(end)) = receiver.receive().unwrap() else {
        panic!("inner send must invalidate an unconsumed successful End")
    };
    assert_eq!(end.code, ErrorCode::InvalidArgument);
}

#[test]
fn pending_success_terminal_does_not_hide_late_cancellation() {
    let (_, _, _, _, runtime) = owned_queue_test_runtime(BudgetLimits::default());
    let (sender, mut receiver) = bounded_channel::<()>(
        runtime.pool().clone(),
        Some(runtime.cancellation().clone()),
        1,
    )
    .unwrap();
    sender.finish(Ok(())).unwrap();
    runtime.cancellation().cancel().unwrap();
    let QueueEvent::End(Err(end)) = receiver.receive().unwrap() else {
        panic!("an unconsumed terminal must report the recorded cancellation")
    };
    assert_eq!(end.code, ErrorCode::Cancelled);
}

#[test]
fn pending_success_terminal_does_not_hide_late_worker_loss() {
    let (lifecycle, _, _, _, runtime) = owned_queue_test_runtime(BudgetLimits::default());
    let (sender, mut receiver) = bounded_channel::<()>(
        runtime.pool().clone(),
        Some(runtime.cancellation().clone()),
        1,
    )
    .unwrap();
    sender.finish(Ok(())).unwrap();
    lifecycle
        .worker_lost("worker was lost after producer finished")
        .unwrap();
    let QueueEvent::End(Err(end)) = receiver.receive().unwrap() else {
        panic!("an unconsumed terminal must report the recorded worker loss")
    };
    assert_eq!(end.code, ErrorCode::WorkerLost);
}

#[test]
fn protocol_fault_reports_poisoned_tracker_before_success_end() {
    let (_, _, _, _, runtime) = owned_queue_test_runtime(BudgetLimits::default());
    let (sender, mut receiver) = bounded_channel::<()>(
        runtime.pool().clone(),
        Some(runtime.cancellation().clone()),
        1,
    )
    .unwrap();
    sender.finish(Ok(())).unwrap();
    let tracker = Arc::clone(sender.0.delivery.as_ref().unwrap());
    assert!(
        thread::spawn(move || {
            let _guard = tracker.state.lock().unwrap();
            panic!("inject delivery tracker poisoning");
        })
        .join()
        .is_err()
    );
    let error = sender.finish(Ok(())).unwrap_err();
    assert_eq!(error.code, ErrorCode::InternalFault);
    assert_eq!(
        runtime.cancellation().status().unwrap().error.unwrap().code,
        ErrorCode::InternalFault
    );
    // A poisoned tracker also prevents safely delivering a terminal; it must
    // surface the first internal fault rather than a successful End.
    assert_eq!(
        receiver.receive().err().unwrap().code,
        ErrorCode::InternalFault
    );
}

#[test]
fn poisoned_tracker_preserves_recorded_worker_loss() {
    let (_, _, _, _, runtime) = owned_queue_test_runtime(BudgetLimits::default());
    let (sender, mut receiver) = bounded_channel::<()>(
        runtime.pool().clone(),
        Some(runtime.cancellation().clone()),
        1,
    )
    .unwrap();
    let first = MddError::new(ErrorCode::WorkerLost, "test.worker", "worker stopped");
    sender.finish(Err(first.clone())).unwrap();
    let tracker = Arc::clone(sender.0.delivery.as_ref().unwrap());
    assert!(
        thread::spawn(move || {
            let _guard = tracker.state.lock().unwrap();
            panic!("inject delivery tracker poisoning");
        })
        .join()
        .is_err()
    );
    let actual = sender.finish(Ok(())).unwrap_err();
    assert_eq!(actual.code, first.code);
    assert_eq!(actual.stage, first.stage);
    assert_eq!(actual.message, first.message);
    assert_eq!(
        receiver.receive().err().unwrap().code,
        ErrorCode::WorkerLost
    );
}

#[test]
fn delivered_success_cannot_be_retracted_but_receipt_is_rejected() {
    let (_, _, _, _, runtime) = owned_queue_test_runtime(BudgetLimits::default());
    let (sender, mut receiver) = bounded_channel::<()>(
        runtime.pool().clone(),
        Some(runtime.cancellation().clone()),
        1,
    )
    .unwrap();
    sender.finish(Ok(())).unwrap();
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Ok(()))
    ));
    assert_eq!(
        sender.finish(Ok(())).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    assert!(receiver.into_delivery_receipt().is_err());
    assert_eq!(
        runtime.cancellation().status().unwrap().error.unwrap().code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn late_failure_receipt_requires_exact_first_error_and_binding() {
    let (_, _, _, _, runtime) = owned_queue_test_runtime(BudgetLimits::default());
    let (sender, mut receiver) = bounded_channel::<()>(
        runtime.pool().clone(),
        Some(runtime.cancellation().clone()),
        1,
    )
    .unwrap();
    sender.finish(Ok(())).unwrap();
    runtime.cancellation().cancel().unwrap();
    let first = runtime.cancellation().status().unwrap().error.unwrap();
    assert!(matches!(
        receiver.receive().unwrap(),
        QueueEvent::End(Err(_))
    ));
    let receipt = receiver.into_delivery_receipt().unwrap();
    assert!(receipt.matches(&sender, &runtime, 0, None).unwrap());
    assert!(!receipt.matches(&sender, &runtime, 1, None).unwrap());
    let (_, _, _, _, foreign) = owned_queue_test_runtime(BudgetLimits::default());
    assert!(!receipt.matches(&sender, &foreign, 0, None).unwrap());
    let mut variants = Vec::new();
    let mut other = first.clone();
    other.code = ErrorCode::WorkerLost;
    variants.push(other);
    let mut other = first.clone();
    other.stage.push_str(".other");
    variants.push(other);
    let mut other = first.clone();
    other.message.push_str(" other");
    variants.push(other);
    let mut other = first.clone();
    other.retryable = !other.retryable;
    variants.push(other);
    variants.push(first.clone().detail("other", "value"));
    for other in variants {
        receipt.tracker.state.lock().unwrap().end_error = Some(other);
        assert!(!receipt.matches(&sender, &runtime, 0, None).unwrap());
    }
}

fn owned_queue_test_runtime(
    limits: BudgetLimits,
) -> (
    mdd_session::Lifecycle,
    mdd_session::SnapshotHandle,
    mdd_session::SessionHandle,
    mdd_session::QueryHandle,
    RuntimeBudget,
) {
    use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
    use mdd_session::{Lifecycle, QueryBinding, ResourceLimits};
    let life = Lifecycle::new(ResourceLimits::default()).unwrap();
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
    let snapshot = life.register_snapshot(Arc::new(snapshot)).unwrap();
    let session = life
        .open_session(&snapshot, ResourceLimits::default())
        .unwrap();
    let query = life
        .prepare_query(
            &session,
            QueryBinding {
                request_key: "owned-batch-queue".into(),
                schema_id: "bytes-v1".into(),
                semantic_version: "v1".into(),
            },
            ResourceLimits::default(),
        )
        .unwrap();
    life.start_query(&session, &query, 1).unwrap();
    let cancel = life.cancellation_token(&query).unwrap();
    let pool = BudgetPool::global("owned-queue-global".into(), limits.clone())
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
    (life, snapshot, session, query, runtime)
}

#[test]
fn owned_batch_queue_preserves_consumption_and_retained_budget() {
    let limits = BudgetLimits::default()
        .with(Resource::QueryWorkspaceBytes, 5)
        .with(Resource::ResidentBytes, 5)
        .with(Resource::QueueBytes, 5);
    let (life, snapshot, session, query, runtime) = owned_queue_test_runtime(limits);
    let (sender, mut receiver) = bounded_owned_batch_channel(&runtime, 1).unwrap();
    sender.send(&runtime, Box::new([1, 2, 3, 4, 5])).unwrap();
    assert_eq!(used(runtime.pool(), Resource::QueryWorkspaceBytes), 5);
    assert_eq!(used(runtime.pool(), Resource::QueueBytes), 5);
    let OwnedBatchEvent::Data(packet) = receiver.receive().unwrap() else {
        panic!("expected batch")
    };
    assert_eq!(packet.bytes(), &[1, 2, 3, 4, 5]);
    assert_eq!(used(runtime.pool(), Resource::QueueBytes), 0);
    let retained = packet.acknowledge().unwrap();
    let clone = retained.clone();
    assert_eq!(used(runtime.pool(), Resource::QueryWorkspaceBytes), 5);
    runtime.cancellation().mark_computed().unwrap();
    sender.finish(Ok(())).unwrap();
    assert!(matches!(
        receiver.receive().unwrap(),
        OwnedBatchEvent::End(Ok(()))
    ));
    let mut receipt = receiver.into_delivery_receipt().unwrap();
    assert!(receipt.confirm(&sender, &runtime, 2).is_err());
    receipt.confirm(&sender, &runtime, 1).unwrap();
    assert!(life.query_status(&query).unwrap().delivery_complete);
    life.release_query(&query).unwrap();
    life.release_session(&session).unwrap();
    life.release_snapshot(&snapshot).unwrap();
    assert_eq!(retained.bytes(), &[1, 2, 3, 4, 5]);
    drop(retained);
    assert_eq!(used(runtime.pool(), Resource::QueryWorkspaceBytes), 5);
    drop(clone);
    assert_eq!(used(runtime.pool(), Resource::QueryWorkspaceBytes), 0);
}

#[test]
fn owned_batch_producer_rejects_duplicate_reservation_identity() {
    let (life, _, _, query, runtime) = owned_queue_test_runtime(BudgetLimits::default());
    let (sender, mut receiver) = bounded_owned_batch_channel(&runtime, 1).unwrap();
    let mut producer = sender.claim_producer().unwrap();
    producer.arm();
    let reservation = sender.reserve_payload(2).unwrap();
    let error = sender
        .send_produced(
            &runtime,
            Box::new([1, 2, 3, 4]),
            vec![reservation.clone(), reservation],
            &producer,
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(!life.query_status(&query).unwrap().delivery_complete);
    assert!(matches!(
        receiver.receive().unwrap(),
        OwnedBatchEvent::End(Err(_))
    ));
}

#[test]
fn owned_batch_receipt_tracker_fault_records_query_first_error() {
    for prior_cancel in [false, true] {
        let (life, _, _, query, runtime) = owned_queue_test_runtime(BudgetLimits::default());
        let (sender, mut receiver) = bounded_owned_batch_channel(&runtime, 1).unwrap();
        sender.send(&runtime, Box::new([1])).unwrap();
        let OwnedBatchEvent::Data(packet) = receiver.receive().unwrap() else {
            panic!("missing batch")
        };
        packet.acknowledge().unwrap();
        runtime.cancellation().mark_computed().unwrap();
        sender.finish(Ok(())).unwrap();
        assert!(matches!(
            receiver.receive().unwrap(),
            OwnedBatchEvent::End(Ok(()))
        ));
        let mut receipt = receiver.into_delivery_receipt().unwrap();
        if prior_cancel {
            runtime.cancellation().cancel().unwrap();
        }
        let tracker = Arc::clone(&receipt.0.tracker);
        assert!(
            thread::spawn(move || {
                let _guard = tracker.state.lock().unwrap();
                panic!("injected tracker failure");
            })
            .join()
            .is_err()
        );
        let expected = if prior_cancel {
            ErrorCode::Cancelled
        } else {
            ErrorCode::InternalFault
        };
        assert_eq!(
            receipt.confirm(&sender, &runtime, 1).unwrap_err().code,
            expected
        );
        let status = life.query_status(&query).unwrap();
        assert_eq!(status.error.unwrap().code, expected);
        assert!(!status.delivery_complete);
    }
}

#[test]
fn owned_batch_queue_rejects_unconsumed_and_foreign_runtime() {
    let (life, _, _, query, runtime) = owned_queue_test_runtime(BudgetLimits::default());
    let (_, _, _, _, foreign) = owned_queue_test_runtime(BudgetLimits::default());
    let (sender, mut receiver) = bounded_owned_batch_channel(&runtime, 1).unwrap();
    assert_eq!(
        sender.send(&foreign, Box::new([1])).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    sender.send(&runtime, Box::new([1, 2])).unwrap();
    let OwnedBatchEvent::Data(packet) = receiver.receive().unwrap() else {
        panic!("expected batch")
    };
    drop(packet);
    assert!(!life.query_status(&query).unwrap().delivery_complete);
    assert_eq!(
        sender.finish(Ok(())).unwrap_err().code,
        ErrorCode::Cancelled
    );
    let OwnedBatchEvent::End(end) = receiver.receive().unwrap() else {
        panic!("expected error end")
    };
    assert_eq!(end.unwrap_err().code, ErrorCode::Cancelled);
    assert!(receiver.into_delivery_receipt().is_err());
    assert_eq!(used(runtime.pool(), Resource::QueryWorkspaceBytes), 0);
}

#[test]
fn owned_batch_queue_second_ack_failure_cannot_finish_delivery() {
    let (life, _, _, query, runtime) = owned_queue_test_runtime(BudgetLimits::default());
    let (sender, mut receiver) = bounded_owned_batch_channel(&runtime, 1).unwrap();
    sender.send(&runtime, Box::new([1, 2])).unwrap();
    let OwnedBatchEvent::Data(packet) = receiver.receive().unwrap() else {
        panic!("expected batch")
    };
    // Controlled tracker corruption forces failure after the lifecycle batch
    // ack but before the queue packet ack; no successful receipt may result.
    let tracker = Arc::clone(&packet.0.acknowledgement.as_ref().unwrap().tracker);
    tracker.state.lock().unwrap().acknowledged = 1;
    assert_eq!(
        packet.acknowledge().err().unwrap().code,
        ErrorCode::InvalidArgument
    );
    let status = life.query_status(&query).unwrap();
    assert!(!status.delivery_complete);
    assert_eq!(status.error.unwrap().code, ErrorCode::InvalidArgument);
    assert_eq!(
        sender.finish(Ok(())).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    assert!(matches!(
        receiver.receive().unwrap(),
        OwnedBatchEvent::End(Err(_))
    ));
    assert!(receiver.into_delivery_receipt().is_err());
    assert_eq!(used(runtime.pool(), Resource::QueryWorkspaceBytes), 0);
}

#[test]
fn owned_batch_queue_holds_backpressure_and_reports_worker_loss() {
    let limits = BudgetLimits::default()
        .with(Resource::QueueItems, 1)
        .with(Resource::QueryWorkspaceBytes, 10)
        .with(Resource::ResidentBytes, 10);
    let (life, _, _, query, runtime) = owned_queue_test_runtime(limits);
    let (sender, mut receiver) = bounded_owned_batch_channel(&runtime, 1).unwrap();
    sender.send(&runtime, Box::new([1, 2, 3, 4, 5])).unwrap();
    let worker_sender = sender.try_clone().unwrap();
    let worker_runtime = runtime.clone();
    let (done, finished) = mpsc::channel();
    let worker = thread::spawn(move || {
        done.send(worker_sender.send(&worker_runtime, Box::new([6, 7, 8, 9, 10])))
            .unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while used(runtime.pool(), Resource::QueryWorkspaceBytes) != 10 {
        assert!(
            Instant::now() < deadline,
            "second sender did not reserve its payload"
        );
        thread::yield_now();
    }
    assert!(finished.try_recv().is_err());
    let OwnedBatchEvent::Data(first) = receiver.receive().unwrap() else {
        panic!("expected first")
    };
    let first = first.acknowledge().unwrap();
    assert!(
        finished
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .is_ok()
    );
    worker.join().unwrap();
    let OwnedBatchEvent::Data(second) = receiver.receive().unwrap() else {
        panic!("expected second")
    };
    life.worker_lost("injected worker loss").unwrap();
    assert_eq!(
        second.acknowledge().err().unwrap().code,
        ErrorCode::WorkerLost
    );
    assert_eq!(
        life.query_status(&query).unwrap().error.unwrap().code,
        ErrorCode::WorkerLost
    );
    assert_eq!(first.bytes(), &[1, 2, 3, 4, 5]);
    drop(first);
    assert_eq!(used(runtime.pool(), Resource::QueryWorkspaceBytes), 0);
}

#[test]
fn deadline_is_checked_while_budget_admission_lock_is_held() {
    let pool = BudgetPool::global("deadline-atomic".into(), BudgetLimits::default()).unwrap();
    let allocation = Arc::new(vec![1u8; 8]);
    let existing = pool
        .reserve_arc(&allocation, Resource::InputResidentBytes, 8)
        .unwrap();
    let before = pool.usage().unwrap().used;

    // Hold the state lock across the point where admission waits; inject an
    // expired soft deadline before it can enter. This tests the actual public
    // admission path without relying on scheduler timings.
    let mut state = pool.lock().unwrap();
    let worker_pool = pool.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        ready_tx.send(()).unwrap();
        worker_pool.charge(Resource::QuerySteps, 1)
    });
    ready_rx.recv().unwrap();
    let now = Instant::now();
    let node = state.nodes.get_mut(&pool.owner).unwrap();
    node.soft = now;
    node.hard = now.checked_add(Duration::from_secs(1)).unwrap();
    drop(state);
    assert_eq!(
        worker.join().unwrap().unwrap_err().code,
        ErrorCode::DeadlineExceeded
    );

    assert_eq!(
        pool.reserve(Resource::QueueBytes, 1).err().unwrap().code,
        ErrorCode::DeadlineExceeded
    );
    assert_eq!(
        pool.reserve_arc(&allocation, Resource::InputResidentBytes, 8)
            .err()
            .unwrap()
            .code,
        ErrorCode::DeadlineExceeded
    );
    assert_eq!(
        pool.check_individual(Resource::MemberUncompressedBytes, 1)
            .unwrap_err()
            .code,
        ErrorCode::DeadlineExceeded
    );
    assert_eq!(
        pool.check_cumulative(Resource::OutputBytes, 1)
            .unwrap_err()
            .code,
        ErrorCode::DeadlineExceeded
    );
    assert_eq!(pool.usage().unwrap().used, before);
    drop(existing);
    assert_eq!(
        pool.usage()
            .unwrap()
            .used
            .get(&Resource::InputResidentBytes),
        Some(&DecimalU64(0))
    );
}

#[test]
fn remaining_physical_memory_respects_shared_resident_and_ancestors() {
    let limits = BudgetLimits::default()
        .with(Resource::ResidentBytes, 100)
        .with(Resource::QueryWorkspaceBytes, 90)
        .with(Resource::InputResidentBytes, 100);
    let root = BudgetPool::global("remaining-root".into(), limits.clone()).unwrap();
    let worker = root
        .child(
            "remaining-worker".into(),
            BudgetScope::Worker,
            limits.clone(),
        )
        .unwrap();
    let session = worker
        .child(
            "remaining-session".into(),
            BudgetScope::Session,
            limits.clone(),
        )
        .unwrap();
    let left = session
        .child("remaining-left".into(), BudgetScope::Query, limits.clone())
        .unwrap();
    let right = session
        .child("remaining-right".into(), BudgetScope::Query, limits)
        .unwrap();
    let input = left.reserve(Resource::InputResidentBytes, 80).unwrap();
    for resource in [
        Resource::InputResidentBytes,
        Resource::ArchiveResidentBytes,
        Resource::BuildWorkspaceBytes,
        Resource::ReadyFactsBytes,
        Resource::QueryWorkspaceBytes,
    ] {
        assert_eq!(right.remaining(resource).unwrap(), 20);
    }
    assert_eq!(
        right.remaining(Resource::QueueBytes).unwrap(),
        BudgetLimits::default().limit(Resource::QueueBytes)
    );
    assert_eq!(right.remaining(Resource::ResidentBytes).unwrap(), 20);
    assert_eq!(
        right
            .reserve(Resource::QueryWorkspaceBytes, 21)
            .err()
            .unwrap()
            .code,
        ErrorCode::QuotaExceeded
    );
    let query = right.reserve(Resource::QueryWorkspaceBytes, 20).unwrap();
    assert_eq!(left.remaining(Resource::QueryWorkspaceBytes).unwrap(), 0);
    drop(query);
    drop(input);
    assert_eq!(right.remaining(Resource::QueryWorkspaceBytes).unwrap(), 90);
    let direct = right.reserve(Resource::ResidentBytes, 25).unwrap();
    assert_eq!(left.remaining(Resource::QueryWorkspaceBytes).unwrap(), 75);
    drop(direct);
    assert_eq!(left.remaining(Resource::QueryWorkspaceBytes).unwrap(), 90);
}

#[test]
fn poisoned_bound_queue_io_preserves_first_fault() {
    use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
    use mdd_session::{Lifecycle, QueryBinding, ResourceLimits};
    for mode in [
        "receive",
        "finish",
        "receipt",
        "clone",
        "clone_overflow",
        "prior_cancel",
    ] {
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
                    request_key: "queue-poison".into(),
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
        if mode == "prior_cancel" {
            cancel.cancel().unwrap();
        }
        if mode == "receipt" {
            sender.finish(Ok(())).unwrap();
            assert!(matches!(
                receiver.receive().unwrap(),
                QueueEvent::End(Ok(()))
            ));
        }
        if mode == "clone_overflow" {
            sender.0.state.lock().unwrap().senders = usize::MAX;
        } else {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _guard = sender.0.state.lock().unwrap();
                    panic!("injected queue mutex poison");
                }))
                .is_err()
            );
        }
        let returned = match mode {
            "finish" => {
                let error = sender.finish(Ok(())).unwrap_err();
                drop(receiver);
                error
            }
            "clone" | "clone_overflow" => {
                let error = sender.try_clone().err().unwrap();
                drop(receiver);
                error
            }
            "receipt" => receiver.into_delivery_receipt().err().unwrap(),
            _ => {
                let error = receiver.receive().err().unwrap();
                drop(receiver);
                error
            }
        };
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
    for mode in ["poison", "overflow", "prior_cancel_out_of_order"] {
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
        } else if mode == "overflow" {
            packet.acknowledgement.as_mut().unwrap().sequence = u64::MAX;
            tracker.state.lock().unwrap().acknowledged = u64::MAX;
        } else {
            packet.acknowledgement.as_mut().unwrap().sequence = 1;
            cancel.cancel().unwrap();
        }
        let returned = packet.acknowledge().unwrap_err();
        assert_eq!(
            returned.code,
            if mode == "prior_cancel_out_of_order" {
                ErrorCode::Cancelled
            } else {
                ErrorCode::InternalFault
            }
        );
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
