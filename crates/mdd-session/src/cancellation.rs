//! Query-owned cancellation views over the existing lifecycle registry; no second registry.
use crate::{CursorHandle, Lifecycle, QueryHandle, QueryPhase, QueryStatus, SessionHandle};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde::Serialize;
use std::time::Instant;

/// Immutable deadline copied by the query runtime from its budget tree.
/// The runtime validates ownership before supplying this to delivery.
#[derive(Clone, Debug)]
pub struct DeliveryBudgetDeadline {
    started: Instant,
    soft: Instant,
    hard: Instant,
    owner: String,
}
impl DeliveryBudgetDeadline {
    pub fn new(started: Instant, soft: Instant, hard: Instant, owner: String) -> MddResult<Self> {
        if owner.is_empty() || hard < soft {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cancel.delivery_budget",
                "invalid budget deadline witness",
            ));
        }
        Ok(Self {
            started,
            soft,
            hard,
            owner,
        })
    }
    pub(crate) fn soft(&self) -> Instant {
        self.soft
    }
    pub(crate) fn owner(&self) -> &str {
        &self.owner
    }
    pub(crate) fn error_at(&self, now: Instant) -> Option<MddError> {
        if now < self.soft {
            return None;
        }
        let hard = now >= self.hard;
        Some(
            MddError::new(
                ErrorCode::DeadlineExceeded,
                "budget",
                "query deadline reached",
            )
            .detail("deadline_kind", if hard { "hard" } else { "soft" })
            .detail(
                "budget",
                if hard {
                    "hard_deadline_ms"
                } else {
                    "soft_deadline_ms"
                },
            )
            .detail(
                "limit",
                (if hard { self.hard } else { self.soft })
                    .saturating_duration_since(self.started)
                    .as_millis()
                    .to_string(),
            )
            .detail(
                "observed",
                now.saturating_duration_since(self.started)
                    .as_millis()
                    .to_string(),
            )
            .detail("owner", self.owner.clone())
            .detail("supervisor_termination_required", hard),
        )
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CancelProfile {
    name: String,
    compat_cancel_closes_dataset: bool,
}
impl CancelProfile {
    pub fn new(name: String, compat_cancel_closes_dataset: bool) -> MddResult<Self> {
        if name.is_empty() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cancel.profile",
                "empty profile",
            ));
        }
        Ok(Self {
            name,
            compat_cancel_closes_dataset,
        })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn compat_cancel_closes_dataset(&self) -> bool {
        self.compat_cancel_closes_dataset
    }
}
#[derive(Clone)]
pub struct QueryCancellation {
    lifecycle: Lifecycle,
    query: QueryHandle,
}
#[derive(Clone, Debug, Serialize)]
pub struct CancelOutcome {
    pub profile: String,
    pub compat_cancel_closes_dataset: bool,
    pub status: QueryStatus,
}
impl Lifecycle {
    pub fn cancellation_token(&self, query: &QueryHandle) -> MddResult<QueryCancellation> {
        self.lock_query_read(query)?.query(query)?;
        Ok(QueryCancellation {
            lifecycle: self.clone(),
            query: query.clone(),
        })
    }
    /// First terminal wins. An execution-complete spool retains that completion if delivery fails.
    pub fn fail_query(&self, query: &QueryHandle, error: MddError) -> MddResult<QueryStatus> {
        let mut state = self.lock_raw()?;
        let entry = state.query(query)?;
        if let Some(fault) = &state.batch_fault {
            return if entry.status.error.is_some() || entry.status.phase == QueryPhase::Completed {
                Ok(entry.status.clone())
            } else {
                Err(fault.clone())
            };
        }
        state.end_query(query.id(), error);
        Ok(state.query(query)?.status.clone())
    }
    pub fn delivery_abandoned(&self, query: &QueryHandle) -> MddResult<bool> {
        Ok(self
            .lock_query_read(query)?
            .query(query)?
            .delivery_abandoned)
    }
}
impl QueryCancellation {
    pub fn claim_execution(&self) -> MddResult<()> {
        let mut state = self.lifecycle.lock_query(&self.query)?;
        state.checkpoint(&self.query)?;
        let entry = state.query(&self.query)?;
        if entry.status.phase != QueryPhase::Active
            || entry.execution_claimed
            || entry.status.execution_complete
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cancel.claim",
                "query execution already claimed or not active",
            ));
        }
        state
            .queries
            .get_mut(self.query.id())
            .unwrap()
            .execution_claimed = true;
        Ok(())
    }
    pub fn binding(&self) -> MddResult<crate::QueryBinding> {
        Ok(self
            .lifecycle
            .lock_query_read(&self.query)?
            .query(&self.query)?
            .binding
            .clone())
    }
    pub fn snapshot_id(&self) -> MddResult<String> {
        Ok(self
            .lifecycle
            .query_snapshot_lease(&self.query)?
            .manifest()
            .snapshot_id
            .clone())
    }
    pub fn session_id(&self) -> MddResult<String> {
        Ok(self
            .lifecycle
            .lock_query_read(&self.query)?
            .query(&self.query)?
            .session_id
            .clone())
    }
    pub fn worker_owner_id(&self) -> MddResult<String> {
        Ok(self.lifecycle.lock_query_read(&self.query)?.owner.clone())
    }
    pub fn query_handle(&self) -> &QueryHandle {
        &self.query
    }
    pub fn lifecycle(&self) -> &Lifecycle {
        &self.lifecycle
    }
    pub fn status(&self) -> MddResult<QueryStatus> {
        self.lifecycle.query_status(&self.query)
    }
    pub fn checkpoint(&self) -> MddResult<()> {
        // The terminal error and active phase must be checked under one lock.
        // Otherwise cancellation between two separate reads could be reported
        // as an unrelated invalid-argument error.
        let mut state = self.lifecycle.lock_query(&self.query)?;
        state.checkpoint(&self.query)?;
        if state.query(&self.query)?.status.phase != QueryPhase::Active {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cancel.checkpoint",
                "query is not active",
            ));
        }
        Ok(())
    }
    /// Check the immutable runtime budget and lifecycle deadline at one instant.
    pub fn checkpoint_with_budget(&self, budget: &DeliveryBudgetDeadline) -> MddResult<()> {
        if budget.owner() != self.query.id() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cancel.checkpoint",
                "budget belongs to another query",
            ));
        }
        let mut state = self.lifecycle.lock_query(&self.query)?;
        state.checkpoint_delivery(&self.query, Some(budget))?;
        if state.query(&self.query)?.status.phase != QueryPhase::Active {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cancel.checkpoint",
                "query is not active",
            ));
        }
        Ok(())
    }
    /// Permit processing already-delivered partial data only while both query
    /// and budget deadlines remain open. The exact pre-existing query failure
    /// remains authoritative when either deadline has elapsed.
    pub fn checkpoint_partial_with_budget(
        &self,
        budget: &DeliveryBudgetDeadline,
        expected_error: &MddError,
    ) -> MddResult<()> {
        if budget.owner() != self.query.id() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cancel.checkpoint",
                "budget belongs to another query",
            ));
        }
        let state = self.lifecycle.lock_query_read(&self.query)?;
        let entry = state.query(&self.query)?;
        let actual = entry.status.error.as_ref().ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "cancel.checkpoint",
                "partial processing requires a query failure",
            )
        })?;
        if !matches!(
            entry.status.phase,
            QueryPhase::Failed | QueryPhase::Cancelled
        ) || entry.status.delivery_complete
            || actual.code != expected_error.code
            || actual.stage != expected_error.stage
            || actual.message != expected_error.message
            || actual.retryable != expected_error.retryable
            || actual.details != expected_error.details
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cancel.checkpoint",
                "partial processing error binding mismatch",
            ));
        }
        let now = Instant::now();
        if state.batch_fault.is_some() || now >= entry.deadline || now >= budget.soft() {
            return Err(actual.clone());
        }
        Ok(())
    }
    pub fn cancel(&self) -> MddResult<QueryStatus> {
        self.lifecycle.cancel_query(&self.query)?;
        self.status()
    }
    /// Compatibility's dataset is the owning session, never every session sharing a snapshot.
    pub fn cancel_with_profile(
        &self,
        session: &SessionHandle,
        profile: &CancelProfile,
    ) -> MddResult<CancelOutcome> {
        {
            let state = self.lifecycle.lock_query(&self.query)?;
            state.owned_query(session, &self.query)?;
        }
        if profile.compat_cancel_closes_dataset {
            self.lifecycle.close_session(session)?;
        } else {
            self.lifecycle.cancel_query(&self.query)?;
        }
        Ok(CancelOutcome {
            profile: profile.name.clone(),
            compat_cancel_closes_dataset: profile.compat_cancel_closes_dataset,
            status: self.status()?,
        })
    }
    pub fn fail(&self, error: MddError) -> MddResult<QueryStatus> {
        self.lifecycle.fail_query(&self.query, error)
    }
    pub fn mark_computed(&self) -> MddResult<()> {
        // The engine calls this only after it has actually computed the complete result.
        // A concurrent delivery cancellation must not erase that established fact.
        let mut state = self.lifecycle.lock_raw()?;
        let entry = state.query(&self.query)?;
        if !entry.execution_started {
            return Err(entry.status.error.clone().unwrap_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "cancel.computed",
                    "computation was never active",
                )
            }));
        }
        if entry.status.error.is_none()
            && !(entry.status.phase == QueryPhase::Completed && entry.status.execution_complete)
            && let Some(fault) = &state.batch_fault
        {
            return Err(fault.clone());
        }
        let entry = state.queries.get_mut(self.query.id()).unwrap();
        entry.status.execution_complete = true;
        entry.reserved_threads = 0;
        Ok(())
    }
    pub fn finish_delivery(&self) -> MddResult<()> {
        self.lifecycle.finish_delivery(&self.query)
    }
    /// Complete delivery only if the runtime's immutable budget deadline is still valid.
    pub fn finish_delivery_with_budget(&self, deadline: &DeliveryBudgetDeadline) -> MddResult<()> {
        self.lifecycle
            .finish_delivery_with_budget(&self.query, deadline)
    }
    fn owning_session(&self) -> MddResult<SessionHandle> {
        let state = self.lifecycle.lock_query_read(&self.query)?;
        let query = state.query(&self.query)?;
        let session = state.sessions.get(&query.session_id).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "cancel.delivery",
                "owning session is absent",
            )
        })?;
        Ok(SessionHandle(session.token.clone()))
    }
    /// A query-bound queue remains an unconsumed cursor until its receiver confirms delivery.
    pub fn open_delivery_cursor(&self) -> MddResult<CursorHandle> {
        self.lifecycle
            .open_cursor(&self.owning_session()?, &self.query)
    }
    pub fn finish_delivery_cursor(&self, cursor: &CursorHandle) -> MddResult<()> {
        self.lifecycle
            .finish_cursor(&self.owning_session()?, &self.query, cursor)
    }
    /// Atomically confirm this queue cursor and complete delivery under its budget deadline.
    pub fn finish_delivery_cursor_with_budget(
        &self,
        cursor: &CursorHandle,
        deadline: &DeliveryBudgetDeadline,
    ) -> MddResult<()> {
        self.lifecycle.finish_delivery_cursor_with_budget(
            &self.owning_session()?,
            &self.query,
            cursor,
            deadline,
        )
    }
    pub fn abandon_delivery_cursor(&self, cursor: &CursorHandle) -> MddResult<()> {
        self.lifecycle.close_cursor(cursor)
    }
    pub fn delivery_abandoned(&self) -> MddResult<bool> {
        self.lifecycle.delivery_abandoned(&self.query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{QueryBinding, ResourceLimits};
    use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
    use std::{path::PathBuf, sync::Arc};
    fn runtime() -> (Lifecycle, SessionHandle) {
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
        let lifecycle = Lifecycle::new(ResourceLimits {
            max_threads: 4,
            ..ResourceLimits::default()
        })
        .unwrap();
        let snapshot = lifecycle.register_snapshot(Arc::new(snapshot)).unwrap();
        let session = lifecycle
            .open_session(
                &snapshot,
                ResourceLimits {
                    max_threads: 4,
                    ..ResourceLimits::default()
                },
            )
            .unwrap();
        (lifecycle, session)
    }
    fn query(lifecycle: &Lifecycle, session: &SessionHandle) -> QueryCancellation {
        let handle = lifecycle
            .prepare_query(
                session,
                QueryBinding {
                    request_key: "request".into(),
                    schema_id: "rows".into(),
                    semantic_version: "v1".into(),
                },
                ResourceLimits::default(),
            )
            .unwrap();
        lifecycle.start_query(session, &handle, 1).unwrap();
        lifecycle.cancellation_token(&handle).unwrap()
    }
    #[test]
    fn never_started_terminal_cannot_be_marked_computed() {
        for queued in [false, true] {
            let (lifecycle, session) = runtime();
            let handle = lifecycle
                .prepare_query(
                    &session,
                    QueryBinding {
                        request_key: "request".into(),
                        schema_id: "rows".into(),
                        semantic_version: "v1".into(),
                    },
                    ResourceLimits::default(),
                )
                .unwrap();
            if queued {
                lifecycle.queue_query(&session, &handle).unwrap();
            }
            let token = lifecycle.cancellation_token(&handle).unwrap();
            token.cancel().unwrap();
            assert_eq!(
                token.mark_computed().unwrap_err().code,
                ErrorCode::Cancelled
            );
            let status = token.status().unwrap();
            assert!(!status.execution_complete);
            assert!(!status.delivery_complete);
            assert_eq!(status.error.unwrap().code, ErrorCode::Cancelled);
        }
        let (lifecycle, session) = runtime();
        let handle = lifecycle
            .prepare_query(
                &session,
                QueryBinding {
                    request_key: "request".into(),
                    schema_id: "rows".into(),
                    semantic_version: "v1".into(),
                },
                ResourceLimits::default(),
            )
            .unwrap();
        let token = lifecycle.cancellation_token(&handle).unwrap();
        lifecycle
            .worker_lost("test worker lost before start")
            .unwrap();
        assert_eq!(
            token.mark_computed().unwrap_err().code,
            ErrorCode::WorkerLost
        );
        let status = token.status().unwrap();
        assert!(!status.execution_complete);
        assert!(!status.delivery_complete);
        assert_eq!(status.error.unwrap().code, ErrorCode::WorkerLost);
        let (lifecycle, session) = runtime();
        let active = query(&lifecycle, &session);
        active.cancel().unwrap();
        active.mark_computed().unwrap();
        let status = active.status().unwrap();
        assert!(status.execution_complete);
        assert!(!status.delivery_complete);
        assert_eq!(status.error.unwrap().code, ErrorCode::Cancelled);
    }
    #[test]
    fn delivery_budget_deadline_keeps_computation_and_first_terminal() {
        use std::time::Duration;
        let now = Instant::now();
        let start = now.checked_sub(Duration::from_secs(2)).unwrap();
        let early = now.checked_sub(Duration::from_secs(1)).unwrap();
        let later = now.checked_sub(Duration::from_millis(500)).unwrap();
        let future = now.checked_add(Duration::from_secs(60)).unwrap();
        let (lifecycle, session) = runtime();
        let result = query(&lifecycle, &session);
        let witness =
            DeliveryBudgetDeadline::new(start, early, future, result.query.id().into()).unwrap();
        result.mark_computed().unwrap();
        lifecycle
            .lock()
            .unwrap()
            .queries
            .get_mut(result.query.id())
            .unwrap()
            .deadline = later;
        let error = result.finish_delivery_with_budget(&witness).unwrap_err();
        assert_eq!(error.code, ErrorCode::DeadlineExceeded);
        assert_eq!(error.stage, "budget");
        assert_eq!(error.details["deadline_kind"], "soft");
        let status = result.status().unwrap();
        assert!(status.execution_complete);
        assert!(!status.delivery_complete);
        result.cancel().unwrap();
        assert_eq!(result.status().unwrap().error.unwrap().stage, "budget");

        let (lifecycle, session) = runtime();
        let result = query(&lifecycle, &session);
        result.mark_computed().unwrap();
        lifecycle
            .lock()
            .unwrap()
            .queries
            .get_mut(result.query.id())
            .unwrap()
            .deadline = early;
        let witness =
            DeliveryBudgetDeadline::new(start, later, future, result.query.id().into()).unwrap();
        let error = result.finish_delivery_with_budget(&witness).unwrap_err();
        assert_eq!(error.code, ErrorCode::DeadlineExceeded);
        assert_eq!(error.stage, "lifecycle");

        let (lifecycle, session) = runtime();
        let result = query(&lifecycle, &session);
        result.mark_computed().unwrap();
        result.finish_delivery().unwrap();
        assert_eq!(
            result
                .finish_delivery_with_budget(&witness)
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        let witness =
            DeliveryBudgetDeadline::new(start, later, future, result.query.id().into()).unwrap();
        assert!(result.finish_delivery_with_budget(&witness).is_ok());
        assert!(result.status().unwrap().delivery_complete);
    }
    #[test]
    fn delivery_cursor_and_budget_commit_are_atomic() {
        use std::time::Duration;
        let now = Instant::now();
        let future = now.checked_add(Duration::from_secs(60)).unwrap();
        let past = now.checked_sub(Duration::from_secs(1)).unwrap();

        let (lifecycle, session) = runtime();
        let result = query(&lifecycle, &session);
        let first = result.open_delivery_cursor().unwrap();
        let second = result.open_delivery_cursor().unwrap();
        result.mark_computed().unwrap();
        let witness =
            DeliveryBudgetDeadline::new(now, future, future, result.query.id().into()).unwrap();
        let original_schema = {
            let mut state = lifecycle.lock().unwrap();
            let cursor = state.cursors.get_mut(first.id()).unwrap();
            std::mem::replace(&mut cursor.binding.schema_id, "foreign-schema".into())
        };
        assert_eq!(
            result
                .finish_delivery_cursor_with_budget(&first, &witness)
                .unwrap_err()
                .code,
            ErrorCode::InvalidCursor
        );
        lifecycle
            .lock()
            .unwrap()
            .cursors
            .get_mut(first.id())
            .unwrap()
            .binding
            .schema_id = original_schema;
        assert_eq!(
            result
                .finish_delivery_cursor_with_budget(&first, &witness)
                .unwrap_err()
                .code,
            ErrorCode::InvalidCursor
        );
        assert!(!result.status().unwrap().delivery_complete);
        result.finish_delivery_cursor(&second).unwrap();
        result
            .finish_delivery_cursor_with_budget(&first, &witness)
            .unwrap();
        assert!(result.status().unwrap().delivery_complete);

        let (lifecycle, session) = runtime();
        let result = query(&lifecycle, &session);
        let cursor = result.open_delivery_cursor().unwrap();
        result.mark_computed().unwrap();
        let expired =
            DeliveryBudgetDeadline::new(past, past, future, result.query.id().into()).unwrap();
        let error = result
            .finish_delivery_cursor_with_budget(&cursor, &expired)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::DeadlineExceeded);
        assert_eq!(error.stage, "budget");
        let status = result.status().unwrap();
        assert!(status.execution_complete);
        assert!(!status.delivery_complete);
    }
    #[test]
    fn native_query_cancel_and_explicit_dataset_profile_have_distinct_ownership() {
        let (lifecycle, session) = runtime();
        let a = query(&lifecycle, &session);
        let b = query(&lifecycle, &session);
        let native = CancelProfile::new("native-test-unqualified".into(), false).unwrap();
        let cancelled = a.cancel_with_profile(&session, &native).unwrap();
        assert!(!cancelled.compat_cancel_closes_dataset);
        assert_eq!(a.status().unwrap().phase, QueryPhase::Cancelled);
        let error = a.checkpoint().unwrap_err();
        assert_eq!(error.code, ErrorCode::Cancelled);
        assert_eq!(error.stage, "lifecycle");
        b.checkpoint().unwrap();
        let compat = CancelProfile::new("dataset-closing-test-unqualified".into(), true).unwrap();
        let outcome = b.cancel_with_profile(&session, &compat).unwrap();
        assert!(outcome.compat_cancel_closes_dataset);
        assert_eq!(b.status().unwrap().phase, QueryPhase::Cancelled);
        assert!(
            lifecycle
                .prepare_query(
                    &session,
                    QueryBinding {
                        request_key: "new".into(),
                        schema_id: "rows".into(),
                        semantic_version: "v1".into()
                    },
                    ResourceLimits::default()
                )
                .is_err()
        );
    }
    #[test]
    fn checkpoint_retains_first_terminal_and_rejects_completed_query() {
        let (lifecycle, session) = runtime();
        let expired = query(&lifecycle, &session);
        {
            let mut state = lifecycle.lock().unwrap();
            state
                .queries
                .get_mut(expired.query_handle().id())
                .unwrap()
                .deadline = std::time::Instant::now();
        }
        let first = expired.checkpoint().unwrap_err();
        assert_eq!(first.code, ErrorCode::DeadlineExceeded);
        expired.cancel().unwrap();
        let second = expired.checkpoint().unwrap_err();
        assert_eq!(second.code, first.code);
        assert_eq!(second.stage, first.stage);
        assert_eq!(second.details, first.details);

        let (lifecycle, session) = runtime();
        let lost = query(&lifecycle, &session);
        lifecycle.worker_lost("test worker lost").unwrap();
        lost.cancel().unwrap();
        let error = lost.checkpoint().unwrap_err();
        assert_eq!(error.code, ErrorCode::WorkerLost);
        assert_eq!(error.stage, "worker");

        let (lifecycle, session) = runtime();
        let finished = query(&lifecycle, &session);
        finished.mark_computed().unwrap();
        finished.finish_delivery().unwrap();
        assert_eq!(
            finished.checkpoint().unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }
    #[test]
    fn checkpoint_with_budget_preserves_first_error_and_checks_owner() {
        let (lifecycle, session) = runtime();
        let result = query(&lifecycle, &session);
        let now = Instant::now();
        let expired = DeliveryBudgetDeadline::new(now, now, now, result.query.id().into()).unwrap();
        let foreign = DeliveryBudgetDeadline::new(now, now, now, "foreign-query".into()).unwrap();
        assert_eq!(
            result.checkpoint_with_budget(&foreign).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        result.cancel().unwrap();
        let first = result.status().unwrap().error.unwrap();
        let observed = result.checkpoint_with_budget(&expired).unwrap_err();
        assert_eq!(observed.code, first.code);
        assert_eq!(observed.stage, first.stage);
        assert_eq!(observed.details, first.details);

        let (lifecycle, session) = runtime();
        let completed = query(&lifecycle, &session);
        completed.mark_computed().unwrap();
        completed.finish_delivery().unwrap();
        let expired =
            DeliveryBudgetDeadline::new(now, now, now, completed.query.id().into()).unwrap();
        assert_eq!(
            completed.checkpoint_with_budget(&expired).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        assert!(completed.status().unwrap().delivery_complete);

        let (lifecycle, session) = runtime();
        let lost = query(&lifecycle, &session);
        let expired = DeliveryBudgetDeadline::new(now, now, now, lost.query.id().into()).unwrap();
        lifecycle.worker_lost("controlled loss").unwrap();
        let error = lost.checkpoint_with_budget(&expired).unwrap_err();
        assert_eq!(error.code, ErrorCode::WorkerLost);
        assert_eq!(error.stage, "worker");
    }
    #[test]
    fn checkpoint_with_budget_equal_deadline_uses_lifecycle() {
        let (lifecycle, session) = runtime();
        let result = query(&lifecycle, &session);
        let deadline = Instant::now() - std::time::Duration::from_millis(10);
        lifecycle
            .lock()
            .unwrap()
            .queries
            .get_mut(result.query.id())
            .unwrap()
            .deadline = deadline;
        let witness = DeliveryBudgetDeadline::new(
            deadline,
            deadline,
            Instant::now() + std::time::Duration::from_secs(1),
            result.query.id().into(),
        )
        .unwrap();
        let error = result.checkpoint_with_budget(&witness).unwrap_err();
        assert_eq!(error.code, ErrorCode::DeadlineExceeded);
        assert_eq!(error.stage, "lifecycle");
        assert_eq!(error.details["budget"], "deadline_ms");
    }
    #[test]
    fn computed_spool_and_abandoned_cursor_never_become_delivery_success() {
        let (lifecycle, session) = runtime();
        let a = query(&lifecycle, &session);
        let cursor = lifecycle.open_cursor(&session, a.query_handle()).unwrap();
        a.mark_computed().unwrap();
        lifecycle.close_cursor(&cursor).unwrap();
        assert!(a.delivery_abandoned().unwrap());
        assert_eq!(
            a.finish_delivery().err().unwrap().code,
            ErrorCode::InvalidCursor
        );
        let status = a
            .fail(MddError::new(
                ErrorCode::InvalidCursor,
                "test",
                "unconsumed cursor abandoned",
            ))
            .unwrap();
        assert!(status.execution_complete);
        assert!(!status.delivery_complete);
        assert_eq!(status.phase, QueryPhase::Failed);
        a.cancel().unwrap();
        assert_eq!(
            a.status().unwrap().error.unwrap().code,
            ErrorCode::InvalidCursor
        );
    }
}
