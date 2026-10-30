use super::*;
use std::sync::mpsc;
use std::thread;

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
