use super::*;
use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec};
use std::path::PathBuf;
use std::sync::Barrier;
use std::thread;

fn snapshot() -> Arc<Snapshot> {
    Arc::new(
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
    )
}

fn binding() -> QueryBinding {
    QueryBinding {
        request_key: "request-content-hash".to_owned(),
        schema_id: "lifecycle-only-schema".to_owned(),
        semantic_version: "lifecycle-only-v1".to_owned(),
    }
}

fn runtime(limits: ResourceLimits) -> (Lifecycle, SnapshotHandle, SessionHandle) {
    let runtime = Lifecycle::new(limits).unwrap();
    let snapshot = runtime.register_snapshot(snapshot()).unwrap();
    let session = runtime.open_session(&snapshot, limits).unwrap();
    (runtime, snapshot, session)
}

fn prepare(runtime: &Lifecycle, session: &SessionHandle) -> QueryHandle {
    runtime
        .prepare_query(session, binding(), ResourceLimits::default())
        .unwrap()
}

#[test]
fn snapshot_close_and_release_preserve_existing_owned_leases() {
    let (runtime, snapshot, first) = runtime(ResourceLimits::default());
    let second = runtime
        .open_session(&snapshot, ResourceLimits::default())
        .unwrap();
    let bytes = runtime.snapshot_lease(&first).unwrap().sources()[0].lease();
    let query = prepare(&runtime, &first);
    runtime.start_query(&first, &query, 1).unwrap();
    let cursor = runtime.open_cursor(&first, &query).unwrap();
    runtime.close_snapshot(&snapshot).unwrap();
    runtime.close_snapshot(&snapshot).unwrap();
    assert_eq!(
        runtime
            .open_session(&snapshot, ResourceLimits::default())
            .unwrap_err()
            .code,
        ErrorCode::SnapshotClosed
    );
    runtime.release_snapshot(&snapshot).unwrap();
    assert!(runtime.close_snapshot(&snapshot).is_err());
    let other = prepare(&runtime, &second);
    runtime.start_query(&second, &other, 1).unwrap();
    runtime.close_session(&first).unwrap();
    runtime.close_session(&first).unwrap();
    assert_eq!(
        runtime.query_status(&query).unwrap().phase,
        QueryPhase::Cancelled
    );
    assert!(runtime.validate_cursor(&first, &query, &cursor).is_err());
    assert_eq!(
        runtime.query_status(&other).unwrap().phase,
        QueryPhase::Active
    );
    assert!(runtime.snapshot_lease(&second).is_ok());
    runtime.release_query(&query).unwrap();
    runtime.release_session(&first).unwrap();
    assert!(bytes.starts_with(b"dex\n035\0"));
    assert_eq!(
        runtime.query_snapshot_lease(&other).unwrap().sources()[0].bytes(),
        bytes.as_ref()
    );
}

#[test]
fn handles_reject_wrong_owner_parent_generation_and_released_identity() {
    let (runtime, snapshot, first) = runtime(ResourceLimits::default());
    let second = runtime
        .open_session(&snapshot, ResourceLimits::default())
        .unwrap();
    let handle = prepare(&runtime, &first);
    assert_eq!(
        runtime.start_query(&second, &handle, 1).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    let mut stale = handle.clone();
    stale.0.generation += 1;
    assert_eq!(
        runtime.query_status(&stale).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    let other = Lifecycle::new(ResourceLimits::default()).unwrap();
    assert_eq!(
        other.query_status(&handle).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    runtime.release_query(&handle).unwrap();
    assert_eq!(
        runtime.query_status(&handle).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    runtime.release_session(&first).unwrap();
    assert!(runtime.release_session(&first).is_err());
}

#[test]
fn computation_delivery_and_catalog_generations_remain_distinct() {
    let (runtime, _, session) = runtime(ResourceLimits::default());
    let old = prepare(&runtime, &session);
    runtime.queue_query(&session, &old).unwrap();
    runtime.start_query(&session, &old, 1).unwrap();
    let cursor = runtime.open_cursor(&session, &old).unwrap();
    runtime.complete_execution(&old).unwrap();
    assert!(runtime.query_status(&old).unwrap().execution_complete);
    assert!(!runtime.query_status(&old).unwrap().delivery_complete);
    assert_eq!(
        runtime.finish_delivery(&old).unwrap_err().code,
        ErrorCode::InvalidCursor
    );
    runtime.advance_catalog(&session).unwrap();
    let new = prepare(&runtime, &session);
    assert_eq!(
        runtime.query_status(&new).unwrap().catalog_epoch,
        DecimalU64(1)
    );
    assert_eq!(runtime.validate_cursor(&session, &old, &cursor).unwrap(), 0);
    assert!(runtime.validate_cursor(&session, &new, &cursor).is_err());
    runtime.cancel_query(&old).unwrap();
    let status = runtime.query_status(&old).unwrap();
    assert_eq!(status.phase, QueryPhase::Cancelled);
    assert!(status.execution_complete);
    assert!(!status.delivery_complete);
    assert_eq!(
        runtime.query_status(&new).unwrap().phase,
        QueryPhase::Prepared
    );
    assert!(runtime.finish_delivery(&old).is_err());
}

#[test]
fn buffered_output_must_be_released_before_delivery_completion() {
    let (runtime, _, session) = runtime(ResourceLimits::default());
    let query = prepare(&runtime, &session);
    runtime.start_query(&session, &query, 1).unwrap();
    runtime.reserve_buffered_bytes(&query, 16).unwrap();
    runtime.complete_execution(&query).unwrap();

    assert!(runtime.finish_delivery(&query).is_err());
    let pending = runtime.query_status(&query).unwrap();
    assert!(pending.execution_complete);
    assert!(!pending.delivery_complete);
    assert_eq!(pending.phase, QueryPhase::Active);
    runtime.release_buffered_bytes(&query, 16).unwrap();
    runtime.finish_delivery(&query).unwrap();
    assert!(runtime.query_status(&query).unwrap().delivery_complete);
}

#[test]
fn worker_loss_fails_every_unfinished_request_but_keeps_completed_terminal() {
    let (runtime, _, session) = runtime(ResourceLimits::default());
    let prepared = prepare(&runtime, &session);
    let queued = prepare(&runtime, &session);
    runtime.queue_query(&session, &queued).unwrap();
    let calculated = prepare(&runtime, &session);
    runtime.start_query(&session, &calculated, 1).unwrap();
    runtime.complete_execution(&calculated).unwrap();
    let cursor = runtime.open_cursor(&session, &calculated).unwrap();
    let finished = prepare(&runtime, &session);
    runtime.start_query(&session, &finished, 1).unwrap();
    runtime.complete_execution(&finished).unwrap();
    runtime.finish_delivery(&finished).unwrap();
    let other = Lifecycle::new(ResourceLimits::default()).unwrap();
    let failures = runtime.worker_lost("worker crashed").unwrap();
    assert_eq!(failures.len(), 3);
    for handle in [&prepared, &queued, &calculated] {
        let status = runtime.query_status(handle).unwrap();
        assert_eq!(status.phase, QueryPhase::Failed);
        assert_eq!(status.error.unwrap().code, ErrorCode::WorkerLost);
    }
    assert!(
        runtime
            .query_status(&calculated)
            .unwrap()
            .execution_complete
    );
    assert!(runtime.close_cursor(&cursor).is_ok());
    assert_eq!(
        runtime.query_status(&finished).unwrap().phase,
        QueryPhase::Completed
    );
    assert!(runtime.worker_lost("repeat").unwrap().is_empty());
    assert_eq!(
        runtime
            .prepare_query(&session, binding(), ResourceLimits::default())
            .unwrap_err()
            .code,
        ErrorCode::WorkerLost
    );
    assert!(other.register_snapshot(snapshot()).is_ok());
}

#[test]
fn terminal_queries_keep_live_buffer_accounting_until_release() {
    let limits = ResourceLimits {
        max_threads: 2,
        max_buffered_bytes: 8,
        ..ResourceLimits::default()
    };
    for close_session in [false, true] {
        let (runtime, snapshot, first) = runtime(limits);
        let second = runtime.open_session(&snapshot, limits).unwrap();
        let a = prepare(&runtime, &first);
        let b = prepare(&runtime, &second);
        runtime.start_query(&first, &a, 1).unwrap();
        runtime.start_query(&second, &b, 1).unwrap();
        let retained = Arc::new(vec![7u8; 5]);
        runtime
            .reserve_buffered_bytes(&a, retained.len() as u64)
            .unwrap();
        if close_session {
            runtime.release_session(&first).unwrap();
        } else {
            runtime.cancel_query(&a).unwrap();
        }
        assert_eq!(retained.as_slice(), &[7; 5]);
        assert_eq!(
            runtime.reserve_buffered_bytes(&b, 4).unwrap_err().code,
            ErrorCode::QuotaExceeded
        );
        assert!(runtime.release_query(&a).is_err());
        assert_eq!(
            runtime.query_status(&a).unwrap().error.unwrap().code,
            ErrorCode::Cancelled
        );
        drop(retained);
        runtime.release_buffered_bytes(&a, 5).unwrap();
        assert!(runtime.release_buffered_bytes(&a, 5).is_err());
        assert_eq!(
            runtime.query_status(&a).unwrap().error.unwrap().code,
            ErrorCode::Cancelled
        );
        runtime.release_query(&a).unwrap();
        assert!(runtime.release_query(&a).is_err());
        runtime.reserve_buffered_bytes(&b, 4).unwrap();
        runtime.release_buffered_bytes(&b, 4).unwrap();
    }
    let (runtime, _, session) = runtime(limits);
    let a = prepare(&runtime, &session);
    runtime.start_query(&session, &a, 1).unwrap();
    runtime.reserve_buffered_bytes(&a, 5).unwrap();
    runtime.worker_lost("injected worker loss").unwrap();
    assert!(runtime.release_query(&a).is_err());
    assert_eq!(
        runtime.query_status(&a).unwrap().error.unwrap().code,
        ErrorCode::WorkerLost
    );
    runtime.release_buffered_bytes(&a, 5).unwrap();
    assert!(runtime.release_buffered_bytes(&a, 5).is_err());
    assert_eq!(
        runtime.query_status(&a).unwrap().error.unwrap().code,
        ErrorCode::WorkerLost
    );
    runtime.release_query(&a).unwrap();
}

#[test]
fn owned_batch_outlives_query_session_and_releases_once() {
    let limits = ResourceLimits {
        max_threads: 2,
        max_buffered_bytes: 8,
        ..ResourceLimits::default()
    };
    let (runtime, snapshot_handle, session) = runtime(limits);
    let other_session = runtime.open_session(&snapshot_handle, limits).unwrap();
    let query = prepare(&runtime, &session);
    let other = prepare(&runtime, &other_session);
    runtime.start_query(&session, &query, 1).unwrap();
    runtime.start_query(&other_session, &other, 1).unwrap();
    let snapshot_id = runtime
        .query_snapshot_lease(&query)
        .unwrap()
        .manifest()
        .snapshot_id
        .clone();
    runtime.reserve_buffered_bytes(&query, 2).unwrap();
    let batch = runtime
        .own_batch(&query, vec![1, 2, 3, 4, 5].into_boxed_slice())
        .unwrap();
    assert_eq!(batch.snapshot_id(), snapshot_id);
    let held = batch.clone();
    assert_eq!(
        runtime.reserve_buffered_bytes(&other, 2).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    runtime.release_buffered_bytes(&query, 2).unwrap();
    runtime.release_query(&query).unwrap();
    runtime.release_session(&session).unwrap();
    runtime.release_snapshot(&snapshot_handle).unwrap();
    assert_eq!(held.bytes(), &[1, 2, 3, 4, 5]);
    assert!(runtime.query_status(&query).is_err());
    assert_eq!(
        runtime.reserve_buffered_bytes(&other, 4).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    batch.release().unwrap();
    assert_eq!(
        runtime.reserve_buffered_bytes(&other, 4).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    held.release().unwrap();
    runtime.reserve_buffered_bytes(&other, 4).unwrap();
    runtime.release_buffered_bytes(&other, 4).unwrap();
}

#[test]
fn owned_batch_release_is_independent_of_worker_and_concurrent_close() {
    let limits = ResourceLimits {
        max_threads: 2,
        max_buffered_bytes: 8,
        ..ResourceLimits::default()
    };
    let (runtime, snapshot, session) = runtime(limits);
    let other_session = runtime.open_session(&snapshot, limits).unwrap();
    let a = prepare(&runtime, &session);
    let b = prepare(&runtime, &other_session);
    runtime.start_query(&session, &a, 1).unwrap();
    runtime.start_query(&other_session, &b, 1).unwrap();
    let batch = runtime
        .own_batch(&a, vec![9u8; 5].into_boxed_slice())
        .unwrap();
    let clone = batch.clone();
    let gate = Arc::new(Barrier::new(3));
    let release_gate = Arc::clone(&gate);
    let release = thread::spawn(move || {
        release_gate.wait();
        clone.release().unwrap();
    });
    let close_gate = Arc::clone(&gate);
    let owner = runtime.clone();
    let handle = a.clone();
    let close = thread::spawn(move || {
        close_gate.wait();
        owner.release_query(&handle).unwrap();
    });
    gate.wait();
    release.join().unwrap();
    close.join().unwrap();
    assert_eq!(batch.bytes(), &[9; 5]);
    assert_eq!(
        runtime.reserve_buffered_bytes(&b, 4).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    drop(batch);
    runtime.reserve_buffered_bytes(&b, 4).unwrap();
    runtime.release_buffered_bytes(&b, 4).unwrap();

    let second = runtime
        .own_batch(&b, vec![7u8; 3].into_boxed_slice())
        .unwrap();
    runtime.worker_lost("synthetic loss").unwrap();
    runtime.release_query(&b).unwrap();
    runtime.release_session(&other_session).unwrap();
    assert_eq!(second.bytes(), &[7; 3]);
    second.release().unwrap();
}

#[test]
fn owned_batch_rejects_foreign_query_and_reports_release_fault() {
    let (runtime, _, session) = runtime(ResourceLimits::default());
    let query = prepare(&runtime, &session);
    runtime.start_query(&session, &query, 1).unwrap();
    let (foreign, _, _) = self::runtime(ResourceLimits::default());
    assert_eq!(
        foreign.own_batch(&query, Box::new([1])).err().unwrap().code,
        ErrorCode::InvalidArgument
    );
    let batch = runtime.own_batch(&query, Box::new([1])).unwrap();
    {
        let mut state = runtime.inner.lock().unwrap();
        state.batches.get_mut(batch.id()).unwrap().token.generation += 1;
    }
    assert_eq!(batch.release().unwrap_err().code, ErrorCode::InternalFault);
    let status = runtime.query_status(&query).unwrap();
    assert_eq!(status.phase, QueryPhase::Failed);
    assert_eq!(status.error.unwrap().code, ErrorCode::InternalFault);
    assert!(!status.execution_complete && !status.delivery_complete);
}

#[test]
fn batch_release_fault_does_not_hide_prior_worker_failure() {
    let (runtime, _, session) = runtime(ResourceLimits::default());
    let query = prepare(&runtime, &session);
    runtime.start_query(&session, &query, 1).unwrap();
    let cancel = runtime.cancellation_token(&query).unwrap();
    let cursor = runtime.open_cursor(&session, &query).unwrap();
    let batch = runtime.own_batch(&query, Box::new([1])).unwrap();
    let unstarted = prepare(&runtime, &session);
    let unstarted_token = runtime.cancellation_token(&unstarted).unwrap();
    runtime.worker_lost("first failure").unwrap();
    {
        let mut state = runtime.inner.lock().unwrap();
        state.batches.get_mut(batch.id()).unwrap().token.generation += 1;
    }
    assert_eq!(batch.release().unwrap_err().code, ErrorCode::InternalFault);
    let status = runtime.query_status(&query).unwrap();
    assert_eq!(status.error.unwrap().code, ErrorCode::WorkerLost);
    assert_eq!(
        cancel.status().unwrap().error.unwrap().code,
        ErrorCode::WorkerLost
    );
    assert_eq!(cancel.checkpoint().unwrap_err().code, ErrorCode::WorkerLost);
    let now = Instant::now();
    let witness = cancellation::DeliveryBudgetDeadline::new(
        now,
        now + Duration::from_secs(10),
        now + Duration::from_secs(10),
        query.id().into(),
    )
    .unwrap();
    assert_eq!(
        cancel.checkpoint_with_budget(&witness).unwrap_err().code,
        ErrorCode::WorkerLost
    );
    assert_eq!(
        cancel
            .fail(MddError::new(ErrorCode::QuotaExceeded, "test", "later"))
            .unwrap()
            .error
            .unwrap()
            .code,
        ErrorCode::WorkerLost
    );
    assert_eq!(
        cancel.binding().unwrap().request_key,
        "request-content-hash"
    );
    assert!(!cancel.snapshot_id().unwrap().is_empty());
    assert_eq!(
        cancel.finish_delivery().unwrap_err().code,
        ErrorCode::WorkerLost
    );
    assert_eq!(
        runtime
            .validate_cursor(&session, &query, &cursor)
            .unwrap_err()
            .code,
        ErrorCode::WorkerLost
    );
    assert_eq!(
        runtime.close_cursor(&cursor).unwrap_err().code,
        ErrorCode::WorkerLost
    );
    assert_eq!(
        runtime.release_cursor(&cursor).unwrap_err().code,
        ErrorCode::WorkerLost
    );
    cancel.mark_computed().unwrap();
    assert!(runtime.query_status(&query).unwrap().execution_complete);
    assert_eq!(
        unstarted_token.mark_computed().unwrap_err().code,
        ErrorCode::WorkerLost
    );
    assert!(!runtime.query_status(&unstarted).unwrap().execution_complete);
    assert_eq!(
        runtime.release_query(&query).unwrap_err().code,
        ErrorCode::WorkerLost
    );
    assert_eq!(
        runtime.batch_release_error().unwrap().unwrap().code,
        ErrorCode::InternalFault
    );
    assert_eq!(runtime.limits().unwrap_err().code, ErrorCode::InternalFault);
}

#[test]
fn batch_fault_records_first_error_and_preserves_computation() {
    let (runtime, _, session) = runtime(ResourceLimits::default());
    let active = prepare(&runtime, &session);
    runtime.start_query(&session, &active, 1).unwrap();
    let active_cancel = runtime.cancellation_token(&active).unwrap();
    let batch = runtime.own_batch(&active, Box::new([1])).unwrap();
    let pending = prepare(&runtime, &session);
    let pending_cancel = runtime.cancellation_token(&pending).unwrap();
    let completed = prepare(&runtime, &session);
    runtime.start_query(&session, &completed, 1).unwrap();
    runtime.complete_execution(&completed).unwrap();
    runtime.finish_delivery(&completed).unwrap();
    {
        let mut state = runtime.inner.lock().unwrap();
        state.batches.get_mut(batch.id()).unwrap().token.generation += 1;
    }
    assert_eq!(batch.release().unwrap_err().code, ErrorCode::InternalFault);
    let status = active_cancel.status().unwrap();
    assert_eq!(status.phase, QueryPhase::Failed);
    assert_eq!(status.error.unwrap().code, ErrorCode::InternalFault);
    assert!(!status.execution_complete);
    active_cancel.mark_computed().unwrap();
    let status = active_cancel.status().unwrap();
    assert!(status.execution_complete);
    assert!(!status.delivery_complete);
    assert_eq!(status.error.unwrap().code, ErrorCode::InternalFault);
    assert_eq!(
        pending_cancel.mark_computed().unwrap_err().code,
        ErrorCode::InternalFault
    );
    let pending_status = pending_cancel.status().unwrap();
    assert!(!pending_status.execution_complete);
    assert_eq!(pending_status.error.unwrap().code, ErrorCode::InternalFault);
    let completed_status = runtime.query_status(&completed).unwrap();
    assert_eq!(completed_status.phase, QueryPhase::Completed);
    assert!(completed_status.execution_complete && completed_status.delivery_complete);
    assert!(completed_status.error.is_none());
    assert_eq!(
        runtime.batch_release_error().unwrap().unwrap().code,
        ErrorCode::InternalFault
    );
}

#[test]
fn batch_fault_does_not_rewrite_prior_completed_query() {
    let (runtime, _, session) = runtime(ResourceLimits::default());
    let completed = prepare(&runtime, &session);
    runtime.start_query(&session, &completed, 1).unwrap();
    let completed_token = runtime.cancellation_token(&completed).unwrap();
    runtime.complete_execution(&completed).unwrap();
    runtime.finish_delivery(&completed).unwrap();
    let active = prepare(&runtime, &session);
    runtime.start_query(&session, &active, 1).unwrap();
    let batch = runtime.own_batch(&active, Box::new([1])).unwrap();
    {
        let mut state = runtime.inner.lock().unwrap();
        state.batches.get_mut(batch.id()).unwrap().token.generation += 1;
    }
    assert_eq!(batch.release().unwrap_err().code, ErrorCode::InternalFault);
    let status = completed_token
        .fail(MddError::new(ErrorCode::InvalidInput, "test", "later"))
        .unwrap();
    assert_eq!(status.phase, QueryPhase::Completed);
    assert!(status.execution_complete && status.delivery_complete);
    assert!(status.error.is_none());
    completed_token.mark_computed().unwrap();
    let status = completed_token.status().unwrap();
    assert_eq!(status.phase, QueryPhase::Completed);
    assert!(status.execution_complete && status.delivery_complete);
    assert!(status.error.is_none());
    assert_eq!(
        runtime.batch_release_error().unwrap().unwrap().code,
        ErrorCode::InternalFault
    );
}

#[test]
fn owned_batch_requires_ack_and_keeps_bytes_after_delivery() {
    let (runtime, _, session) = runtime(ResourceLimits::default());
    let query = prepare(&runtime, &session);
    runtime.start_query(&session, &query, 1).unwrap();
    let batch = runtime.own_batch(&query, Box::new([4, 5])).unwrap();
    runtime.complete_execution(&query).unwrap();
    assert_eq!(
        runtime.finish_delivery(&query).unwrap_err().code,
        ErrorCode::InvalidCursor
    );
    assert!(!runtime.query_status(&query).unwrap().delivery_complete);
    batch.acknowledge().unwrap();
    assert_eq!(
        batch.acknowledge().unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    runtime.finish_delivery(&query).unwrap();
    assert!(runtime.query_status(&query).unwrap().delivery_complete);
    runtime.release_query(&query).unwrap();
    runtime.release_session(&session).unwrap();
    assert_eq!(batch.bytes(), &[4, 5]);
    batch.release().unwrap();

    let (runtime, _, session) = self::runtime(ResourceLimits::default());
    let query = prepare(&runtime, &session);
    runtime.start_query(&session, &query, 1).unwrap();
    let batch = runtime.own_batch(&query, Box::new([])).unwrap();
    drop(batch);
    runtime.complete_execution(&query).unwrap();
    assert_eq!(
        runtime.finish_delivery(&query).unwrap_err().code,
        ErrorCode::InvalidCursor
    );
    assert!(!runtime.query_status(&query).unwrap().delivery_complete);
}

#[test]
fn owned_batch_ack_rejects_foreign_budget_witness() {
    let (runtime, _, session) = runtime(ResourceLimits::default());
    let query = prepare(&runtime, &session);
    runtime.start_query(&session, &query, 1).unwrap();
    let batch = runtime.own_batch(&query, Box::new([1])).unwrap();
    let now = Instant::now();
    let later = now.checked_add(Duration::from_secs(60)).unwrap();
    let foreign =
        cancellation::DeliveryBudgetDeadline::new(now, later, later, "foreign-query".into())
            .unwrap();
    assert_eq!(
        batch.acknowledge_with_budget(&foreign).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    runtime.worker_lost("injected loss").unwrap();
    let first = runtime.query_status(&query).unwrap().error.unwrap();
    assert_eq!(
        batch
            .acknowledge_partial_with_budget(&first, &foreign)
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        runtime.query_status(&query).unwrap().error.unwrap().code,
        ErrorCode::WorkerLost
    );
    batch.release().unwrap();
}

#[test]
fn owned_batch_partial_ack_requires_exact_existing_failure() {
    for worker_loss in [false, true] {
        let (runtime, _, session) = runtime(ResourceLimits::default());
        let query = prepare(&runtime, &session);
        runtime.start_query(&session, &query, 1).unwrap();
        let batch = runtime.own_batch(&query, Box::new([1, 2])).unwrap();
        let proposed = MddError::new(ErrorCode::Cancelled, "test", "wrong");
        assert!(batch.acknowledge_partial(&proposed).is_err());
        if worker_loss {
            runtime.worker_lost("test loss").unwrap();
        } else {
            runtime.cancel_query(&query).unwrap();
        }
        let first = runtime.query_status(&query).unwrap().error.unwrap();
        assert_eq!(batch.acknowledge().unwrap_err().code, first.code);
        assert!(batch.acknowledge_partial(&proposed).is_err());
        batch.acknowledge_partial(&first).unwrap();
        assert!(batch.acknowledge_partial(&first).is_err());
        let status = runtime.query_status(&query).unwrap();
        assert_eq!(status.error.unwrap().code, first.code);
        assert!(!status.delivery_complete);
        batch.release().unwrap();
    }
}

#[test]
fn shared_budget_reservations_and_releases_are_enforced_across_sessions() {
    let limits = ResourceLimits {
        max_threads: 2,
        max_buffered_bytes: 8,
        max_cursors: 1,
        ..ResourceLimits::default()
    };
    let (runtime, snapshot, first) = runtime(limits);
    let second = runtime.open_session(&snapshot, limits).unwrap();
    let first_query = prepare(&runtime, &first);
    let second_query = prepare(&runtime, &second);
    runtime.start_query(&first, &first_query, 2).unwrap();
    assert_eq!(
        runtime
            .start_query(&second, &second_query, 1)
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    runtime.complete_execution(&first_query).unwrap();
    runtime.start_query(&second, &second_query, 2).unwrap();
    runtime.reserve_buffered_bytes(&first_query, 5).unwrap();
    assert_eq!(
        runtime
            .reserve_buffered_bytes(&second_query, 4)
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    runtime.release_buffered_bytes(&first_query, 2).unwrap();
    runtime.reserve_buffered_bytes(&second_query, 4).unwrap();
    assert!(runtime.release_buffered_bytes(&second_query, 5).is_err());
    let cursor = runtime.open_cursor(&first, &first_query).unwrap();
    assert_eq!(
        runtime
            .open_cursor(&second, &second_query)
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    runtime.release_cursor(&cursor).unwrap();
    assert!(runtime.close_cursor(&cursor).is_err());
    assert!(runtime.open_cursor(&second, &second_query).is_ok());
    let zero = ResourceLimits {
        max_threads: 0,
        ..limits
    };
    let third = runtime.open_session(&snapshot, zero).unwrap();
    let handle = prepare(&runtime, &third);
    assert_eq!(
        runtime.start_query(&third, &handle, 1).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
}

#[test]
fn deadlines_cover_queue_time_and_zero_is_not_unlimited() {
    let (runtime, _, session) = runtime(ResourceLimits::default());
    let handle = runtime
        .prepare_query(
            &session,
            binding(),
            ResourceLimits {
                deadline_ms: 1,
                ..ResourceLimits::default()
            },
        )
        .unwrap();
    thread::sleep(Duration::from_millis(5));
    assert_eq!(
        runtime.start_query(&session, &handle, 1).unwrap_err().code,
        ErrorCode::DeadlineExceeded
    );
    assert_eq!(
        runtime.query_status(&handle).unwrap().phase,
        QueryPhase::Failed
    );
    assert_eq!(
        runtime
            .prepare_query(
                &session,
                binding(),
                ResourceLimits {
                    deadline_ms: 0,
                    ..ResourceLimits::default()
                }
            )
            .unwrap_err()
            .code,
        ErrorCode::DeadlineExceeded
    );
}

#[test]
fn abandoned_cursors_cannot_be_released_into_delivery_success() {
    let (runtime, _, session) = runtime(ResourceLimits::default());
    let abandoned = prepare(&runtime, &session);
    runtime.start_query(&session, &abandoned, 1).unwrap();
    let cursor = runtime.open_cursor(&session, &abandoned).unwrap();
    runtime.complete_execution(&abandoned).unwrap();
    runtime.release_cursor(&cursor).unwrap();
    assert_eq!(
        runtime.finish_delivery(&abandoned).unwrap_err().code,
        ErrorCode::InvalidCursor
    );
    let status = runtime.query_status(&abandoned).unwrap();
    assert_eq!(status.phase, QueryPhase::Active);
    assert!(status.execution_complete);
    assert!(!status.delivery_complete);
    runtime.cancel_query(&abandoned).unwrap();
    let consumed = prepare(&runtime, &session);
    runtime.start_query(&session, &consumed, 1).unwrap();
    let cursor = runtime.open_cursor(&session, &consumed).unwrap();
    runtime.complete_execution(&consumed).unwrap();
    runtime.finish_cursor(&session, &consumed, &cursor).unwrap();
    runtime.release_cursor(&cursor).unwrap();
    runtime.finish_delivery(&consumed).unwrap();
    assert_eq!(
        runtime.query_status(&consumed).unwrap().phase,
        QueryPhase::Completed
    );
    assert!(runtime.query_status(&consumed).unwrap().delivery_complete);
}

#[test]
fn concurrent_close_and_computation_never_reopen_a_cancelled_query() {
    let (runtime, _, session) = runtime(ResourceLimits::default());
    let handle = prepare(&runtime, &session);
    runtime.start_query(&session, &handle, 1).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let other = runtime.clone();
    let other_query = handle.clone();
    let gate = barrier.clone();
    let computation = thread::spawn(move || {
        gate.wait();
        other.complete_execution(&other_query)
    });
    barrier.wait();
    runtime.close_session(&session).unwrap();
    let completion = computation.join().unwrap();
    if let Err(error) = completion {
        assert_eq!(error.code, ErrorCode::Cancelled);
    }
    assert_eq!(
        runtime.query_status(&handle).unwrap().phase,
        QueryPhase::Cancelled
    );
    assert!(runtime.start_query(&session, &handle, 1).is_err());
    assert!(runtime.finish_delivery(&handle).is_err());
}
