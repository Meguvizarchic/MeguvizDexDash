//! Query-owned cancellation views over the existing lifecycle registry; no second registry.
use crate::{CursorHandle, Lifecycle, QueryHandle, QueryPhase, QueryStatus, SessionHandle};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde::Serialize;

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
        self.lock()?.query(query)?;
        Ok(QueryCancellation {
            lifecycle: self.clone(),
            query: query.clone(),
        })
    }
    /// First terminal wins. An execution-complete spool retains that completion if delivery fails.
    pub fn fail_query(&self, query: &QueryHandle, error: MddError) -> MddResult<QueryStatus> {
        let mut state = self.lock()?;
        state.query(query)?;
        state.end_query(query.id(), error);
        Ok(state.query(query)?.status.clone())
    }
    pub fn delivery_abandoned(&self, query: &QueryHandle) -> MddResult<bool> {
        Ok(self.lock()?.query(query)?.delivery_abandoned)
    }
}
impl QueryCancellation {
    pub fn claim_execution(&self) -> MddResult<()> {
        let mut state = self.lifecycle.lock()?;
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
        Ok(self.lifecycle.lock()?.query(&self.query)?.binding.clone())
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
            .lock()?
            .query(&self.query)?
            .session_id
            .clone())
    }
    pub fn worker_owner_id(&self) -> MddResult<String> {
        Ok(self.lifecycle.lock()?.owner.clone())
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
        let mut state = self.lifecycle.lock()?;
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
            let state = self.lifecycle.lock()?;
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
        let mut state = self.lifecycle.lock()?;
        let entry = state.query(&self.query)?;
        if matches!(
            entry.status.phase,
            QueryPhase::Prepared | QueryPhase::Queued
        ) {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "cancel.computed",
                "computation was never active",
            ));
        }
        let entry = state.queries.get_mut(self.query.id()).unwrap();
        entry.status.execution_complete = true;
        entry.reserved_threads = 0;
        Ok(())
    }
    pub fn finish_delivery(&self) -> MddResult<()> {
        self.lifecycle.finish_delivery(&self.query)
    }
    fn owning_session(&self) -> MddResult<SessionHandle> {
        let state = self.lifecycle.lock()?;
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
