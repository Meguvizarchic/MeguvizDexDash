//! Owned lifecycle registry. This crate does not execute queries or admit profiles.
pub mod cancellation;

use mdd_input::snapshot::Snapshot;
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult, opaque_id};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Eq, PartialEq)]
struct Token {
    owner: String,
    id: String,
    generation: u64,
}

macro_rules! handle {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name(Token);
        impl $name {
            pub fn id(&self) -> &str {
                &self.0.id
            }
            pub fn generation(&self) -> u64 {
                self.0.generation
            }
        }
    };
}
handle!(SnapshotHandle);
handle!(SessionHandle);
handle!(QueryHandle);
handle!(CursorHandle);

#[derive(Clone, Copy, Debug)]
pub struct ResourceLimits {
    pub max_threads: usize,
    pub max_sessions: usize,
    pub max_queries: usize,
    pub max_cursors: usize,
    pub max_buffered_bytes: u64,
    pub max_worker_stdout_bytes: u64,
    pub deadline_ms: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_threads: 2,
            max_sessions: 16,
            max_queries: 128,
            max_cursors: 64,
            max_buffered_bytes: 16 * 1024 * 1024,
            max_worker_stdout_bytes: 64 * 1024 * 1024,
            deadline_ms: 60_000,
        }
    }
}

impl ResourceLimits {
    pub fn restricted_by(self, other: Self) -> Self {
        Self {
            max_threads: self.max_threads.min(other.max_threads),
            max_sessions: self.max_sessions.min(other.max_sessions),
            max_queries: self.max_queries.min(other.max_queries),
            max_cursors: self.max_cursors.min(other.max_cursors),
            max_buffered_bytes: self.max_buffered_bytes.min(other.max_buffered_bytes),
            max_worker_stdout_bytes: self
                .max_worker_stdout_bytes
                .min(other.max_worker_stdout_bytes),
            deadline_ms: self.deadline_ms.min(other.deadline_ms),
        }
    }
}

#[derive(Clone, Debug)]
pub struct QueryBinding {
    pub request_key: String,
    pub schema_id: String,
    pub semantic_version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryPhase {
    Prepared,
    Queued,
    Active,
    Completed,
    Cancelled,
    Failed,
}

impl QueryPhase {
    fn terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct QueryStatus {
    pub phase: QueryPhase,
    pub execution_complete: bool,
    pub delivery_complete: bool,
    pub catalog_epoch: DecimalU64,
    pub error: Option<MddError>,
}

#[derive(Clone, Debug, Serialize)]
pub struct QueryFailure {
    pub query_id: String,
    pub error: MddError,
}

struct SnapshotEntry {
    token: Token,
    snapshot: Arc<Snapshot>,
    closed: bool,
}
struct SessionEntry {
    token: Token,
    snapshot: Arc<Snapshot>,
    snapshot_id: String,
    closed: bool,
    limits: ResourceLimits,
    catalog_epoch: u64,
}
struct QueryEntry {
    token: Token,
    session_id: String,
    snapshot: Arc<Snapshot>,
    binding: QueryBinding,
    status: QueryStatus,
    limits: ResourceLimits,
    deadline: Instant,
    reserved_threads: usize,
    buffered_bytes: u64,
    delivery_abandoned: bool,
    execution_claimed: bool,
}
struct CursorEntry {
    token: Token,
    session_id: String,
    query_id: String,
    snapshot_id: String,
    catalog_epoch: u64,
    binding: QueryBinding,
    open: bool,
    consumed: bool,
}

struct State {
    owner: String,
    next_generation: u64,
    limits: ResourceLimits,
    worker_error: Option<MddError>,
    supervisor_attached: bool,
    snapshots: HashMap<String, SnapshotEntry>,
    sessions: HashMap<String, SessionEntry>,
    queries: HashMap<String, QueryEntry>,
    cursors: HashMap<String, CursorEntry>,
}

#[derive(Clone)]
pub struct Lifecycle {
    inner: Arc<Mutex<State>>,
}

pub struct WorkerSupervisionLease {
    lifecycle: Lifecycle,
}

impl Drop for WorkerSupervisionLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.lifecycle.inner.lock() {
            state.supervisor_attached = false;
        }
    }
}

fn invalid(message: &str) -> MddError {
    MddError::new(ErrorCode::InvalidArgument, "lifecycle", message)
}

fn quota(name: &str, limit: impl ToString, observed: impl ToString) -> MddError {
    MddError::new(
        ErrorCode::QuotaExceeded,
        "lifecycle",
        "resource reservation exceeds budget",
    )
    .detail("budget", name)
    .detail("limit", limit.to_string())
    .detail("observed", observed.to_string())
}

impl State {
    fn token(&mut self, kind: &str) -> MddResult<Token> {
        let generation = self.next_generation;
        self.next_generation = generation
            .checked_add(1)
            .ok_or_else(|| invalid("handle generation exhausted"))?;
        Ok(Token {
            owner: self.owner.clone(),
            id: opaque_id(kind)?,
            generation,
        })
    }

    fn ensure_worker(&self) -> MddResult<()> {
        self.worker_error.clone().map_or(Ok(()), Err)
    }

    fn check(&self, supplied: &Token, actual: &Token) -> MddResult<()> {
        if supplied.owner != self.owner || supplied != actual {
            return Err(invalid("handle owner, generation or identity mismatch"));
        }
        Ok(())
    }

    fn snapshot(&self, handle: &SnapshotHandle) -> MddResult<&SnapshotEntry> {
        let entry = self
            .snapshots
            .get(handle.id())
            .ok_or_else(|| invalid("stale snapshot handle"))?;
        self.check(&handle.0, &entry.token)?;
        Ok(entry)
    }

    fn session(&self, handle: &SessionHandle) -> MddResult<&SessionEntry> {
        let entry = self
            .sessions
            .get(handle.id())
            .ok_or_else(|| invalid("stale session handle"))?;
        self.check(&handle.0, &entry.token)?;
        Ok(entry)
    }

    fn active_session(&self, handle: &SessionHandle) -> MddResult<&SessionEntry> {
        self.ensure_worker()?;
        let entry = self.session(handle)?;
        if entry.closed {
            return Err(invalid("session is closed"));
        }
        Ok(entry)
    }

    fn query(&self, handle: &QueryHandle) -> MddResult<&QueryEntry> {
        let entry = self
            .queries
            .get(handle.id())
            .ok_or_else(|| invalid("stale query handle"))?;
        self.check(&handle.0, &entry.token)?;
        Ok(entry)
    }

    fn owned_query(&self, session: &SessionHandle, query: &QueryHandle) -> MddResult<&QueryEntry> {
        self.active_session(session)?;
        let entry = self.query(query)?;
        if entry.session_id != session.id() {
            return Err(invalid("query belongs to another session"));
        }
        Ok(entry)
    }

    fn end_query(&mut self, id: &str, error: MddError) {
        if let Some(query) = self.queries.get_mut(id)
            && !query.status.phase.terminal()
        {
            query.status.phase = if error.code == ErrorCode::Cancelled {
                QueryPhase::Cancelled
            } else {
                QueryPhase::Failed
            };
            query.status.error = Some(error);
            query.reserved_threads = 0;
            query.buffered_bytes = 0;
        }
        for cursor in self
            .cursors
            .values_mut()
            .filter(|cursor| cursor.query_id == id)
        {
            cursor.open = false;
        }
    }

    fn checkpoint(&mut self, query: &QueryHandle) -> MddResult<()> {
        let entry = self.query(query)?;
        if let Some(error) = &entry.status.error {
            return Err(error.clone());
        }
        if entry.status.phase == QueryPhase::Completed {
            return Ok(());
        }
        if Instant::now() >= entry.deadline {
            let error = MddError::new(
                ErrorCode::DeadlineExceeded,
                "lifecycle",
                "query total deadline exceeded",
            )
            .detail("budget", "deadline_ms")
            .detail("limit", entry.limits.deadline_ms.to_string());
            self.end_query(query.id(), error.clone());
            return Err(error);
        }
        self.ensure_worker()
    }

    fn checkpoint_delivery(
        &mut self,
        query: &QueryHandle,
        budget: Option<&cancellation::DeliveryBudgetDeadline>,
    ) -> MddResult<()> {
        let entry = self.query(query)?;
        // Preserve an already recorded terminal and an already completed query.
        if entry.status.error.is_some() || entry.status.phase == QueryPhase::Completed {
            return self.checkpoint(query);
        }
        let lifecycle_deadline = entry.deadline;
        let now = Instant::now();
        if let Some(budget) = budget
            && budget.soft() < lifecycle_deadline
            && let Some(error) = budget.error_at(now)
        {
            self.end_query(query.id(), error.clone());
            return Err(error);
        }
        self.checkpoint(query)
    }
}

impl Lifecycle {
    pub fn new(limits: ResourceLimits) -> MddResult<Self> {
        Ok(Self {
            inner: Arc::new(Mutex::new(State {
                owner: opaque_id("runtime")?,
                next_generation: 0,
                limits,
                worker_error: None,
                supervisor_attached: false,
                snapshots: HashMap::new(),
                sessions: HashMap::new(),
                queries: HashMap::new(),
                cursors: HashMap::new(),
            })),
        })
    }

    fn lock(&self) -> MddResult<MutexGuard<'_, State>> {
        self.inner.lock().map_err(|_| {
            MddError::new(
                ErrorCode::InternalFault,
                "lifecycle",
                "registry mutex poisoned",
            )
        })
    }

    pub fn limits(&self) -> MddResult<ResourceLimits> {
        Ok(self.lock()?.limits)
    }

    pub fn claim_supervision(&self) -> MddResult<WorkerSupervisionLease> {
        let mut state = self.lock()?;
        state.ensure_worker()?;
        if state.supervisor_attached {
            return Err(invalid("worker already has a supervisor"));
        }
        state.supervisor_attached = true;
        Ok(WorkerSupervisionLease {
            lifecycle: self.clone(),
        })
    }

    pub fn register_snapshot(&self, snapshot: Arc<Snapshot>) -> MddResult<SnapshotHandle> {
        let mut state = self.lock()?;
        state.ensure_worker()?;
        let token = state.token("snapshot-handle")?;
        state.snapshots.insert(
            token.id.clone(),
            SnapshotEntry {
                token: token.clone(),
                snapshot,
                closed: false,
            },
        );
        Ok(SnapshotHandle(token))
    }

    pub fn close_snapshot(&self, handle: &SnapshotHandle) -> MddResult<()> {
        let mut state = self.lock()?;
        state.snapshot(handle)?;
        state.snapshots.get_mut(handle.id()).unwrap().closed = true;
        Ok(())
    }

    pub fn release_snapshot(&self, handle: &SnapshotHandle) -> MddResult<()> {
        let mut state = self.lock()?;
        state.snapshot(handle)?;
        state.snapshots.remove(handle.id());
        Ok(())
    }

    pub fn open_session(
        &self,
        snapshot: &SnapshotHandle,
        requested: ResourceLimits,
    ) -> MddResult<SessionHandle> {
        let mut state = self.lock()?;
        state.ensure_worker()?;
        let entry = state.snapshot(snapshot)?;
        if entry.closed {
            return Err(MddError::new(
                ErrorCode::SnapshotClosed,
                "lifecycle",
                "snapshot no longer accepts sessions",
            ));
        }
        let lease = Arc::clone(&entry.snapshot);
        if state.sessions.len() >= state.limits.max_sessions {
            return Err(quota(
                "max_sessions",
                state.limits.max_sessions,
                state.sessions.len() + 1,
            ));
        }
        let token = state.token("session")?;
        let limits = state.limits.restricted_by(requested);
        state.sessions.insert(
            token.id.clone(),
            SessionEntry {
                token: token.clone(),
                snapshot: lease,
                snapshot_id: snapshot.id().to_owned(),
                closed: false,
                limits,
                catalog_epoch: 0,
            },
        );
        Ok(SessionHandle(token))
    }

    pub fn session_limits(&self, session: &SessionHandle) -> MddResult<ResourceLimits> {
        Ok(self.lock()?.session(session)?.limits)
    }

    pub fn snapshot_lease(&self, session: &SessionHandle) -> MddResult<Arc<Snapshot>> {
        Ok(Arc::clone(&self.lock()?.active_session(session)?.snapshot))
    }

    pub fn close_session(&self, session: &SessionHandle) -> MddResult<()> {
        let mut state = self.lock()?;
        state.session(session)?;
        state.sessions.get_mut(session.id()).unwrap().closed = true;
        let ids: Vec<_> = state
            .queries
            .iter()
            .filter(|(_, q)| q.session_id == session.id())
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            state.end_query(
                &id,
                MddError::new(ErrorCode::Cancelled, "lifecycle", "owning session closed"),
            );
        }
        Ok(())
    }

    pub fn release_session(&self, session: &SessionHandle) -> MddResult<()> {
        self.close_session(session)?;
        let mut state = self.lock()?;
        state.session(session)?;
        state.sessions.remove(session.id());
        Ok(())
    }

    pub fn advance_catalog(&self, session: &SessionHandle) -> MddResult<u64> {
        let mut state = self.lock()?;
        let epoch = state
            .active_session(session)?
            .catalog_epoch
            .checked_add(1)
            .ok_or_else(|| invalid("catalog epoch exhausted"))?;
        state.sessions.get_mut(session.id()).unwrap().catalog_epoch = epoch;
        Ok(epoch)
    }

    pub fn prepare_query(
        &self,
        session: &SessionHandle,
        binding: QueryBinding,
        requested: ResourceLimits,
    ) -> MddResult<QueryHandle> {
        if binding.request_key.is_empty()
            || binding.schema_id.is_empty()
            || binding.semantic_version.is_empty()
        {
            return Err(invalid("query binding fields must be nonempty"));
        }
        let mut state = self.lock()?;
        let entry = state.active_session(session)?;
        let lease = Arc::clone(&entry.snapshot);
        let limits = entry.limits.restricted_by(requested);
        let epoch = entry.catalog_epoch;
        let session_count = state
            .queries
            .values()
            .filter(|query| query.session_id == session.id())
            .count();
        if state.queries.len() >= state.limits.max_queries || session_count >= limits.max_queries {
            return Err(quota(
                "max_queries",
                limits.max_queries.min(state.limits.max_queries),
                session_count + 1,
            ));
        }
        if limits.deadline_ms == 0 {
            return Err(MddError::new(
                ErrorCode::DeadlineExceeded,
                "lifecycle",
                "zero query deadline",
            ));
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(limits.deadline_ms))
            .ok_or_else(|| invalid("query deadline outside platform clock range"))?;
        let token = state.token("query")?;
        state.queries.insert(
            token.id.clone(),
            QueryEntry {
                token: token.clone(),
                session_id: session.id().to_owned(),
                snapshot: lease,
                binding,
                status: QueryStatus {
                    phase: QueryPhase::Prepared,
                    execution_complete: false,
                    delivery_complete: false,
                    catalog_epoch: DecimalU64(epoch),
                    error: None,
                },
                limits,
                deadline,
                reserved_threads: 0,
                buffered_bytes: 0,
                delivery_abandoned: false,
                execution_claimed: false,
            },
        );
        Ok(QueryHandle(token))
    }

    pub fn queue_query(&self, session: &SessionHandle, query: &QueryHandle) -> MddResult<()> {
        let mut state = self.lock()?;
        state.owned_query(session, query)?;
        state.checkpoint(query)?;
        if state.query(query)?.status.phase != QueryPhase::Prepared {
            return Err(invalid("query is not prepared"));
        }
        state.queries.get_mut(query.id()).unwrap().status.phase = QueryPhase::Queued;
        Ok(())
    }

    pub fn start_query(
        &self,
        session: &SessionHandle,
        query: &QueryHandle,
        threads: usize,
    ) -> MddResult<()> {
        let mut state = self.lock()?;
        let entry = state.owned_query(session, query)?;
        if !matches!(
            entry.status.phase,
            QueryPhase::Prepared | QueryPhase::Queued
        ) {
            return Err(invalid("query cannot be started from this phase"));
        }
        state.checkpoint(query)?;
        let entry = state.query(query)?;
        let limits = entry.limits;
        let global: usize = state
            .queries
            .values()
            .map(|query| query.reserved_threads)
            .sum();
        let own: usize = state
            .queries
            .values()
            .filter(|q| q.session_id == session.id())
            .map(|query| query.reserved_threads)
            .sum();
        let total = global
            .checked_add(threads)
            .ok_or_else(|| quota("max_threads", state.limits.max_threads, "overflow"))?;
        let session_total = own
            .checked_add(threads)
            .ok_or_else(|| quota("max_threads", limits.max_threads, "overflow"))?;
        if threads == 0 {
            return Err(invalid("query thread reservation must be positive"));
        }
        let session_limit = state.session(session)?.limits.max_threads;
        if total > state.limits.max_threads
            || session_total > session_limit
            || threads > limits.max_threads
        {
            return Err(quota("max_threads", limits.max_threads, session_total));
        }
        let entry = state.queries.get_mut(query.id()).unwrap();
        entry.reserved_threads = threads;
        entry.status.phase = QueryPhase::Active;
        Ok(())
    }

    pub fn checkpoint(&self, query: &QueryHandle) -> MddResult<()> {
        self.lock()?.checkpoint(query)
    }

    pub fn reserve_buffered_bytes(&self, query: &QueryHandle, bytes: u64) -> MddResult<()> {
        let mut state = self.lock()?;
        state.checkpoint(query)?;
        let entry = state.query(query)?;
        if entry.status.phase != QueryPhase::Active {
            return Err(invalid("query is not active"));
        }
        let total = state
            .queries
            .values()
            .try_fold(0u64, |total, q| total.checked_add(q.buffered_bytes))
            .and_then(|total| total.checked_add(bytes));
        let own = state
            .queries
            .values()
            .filter(|q| q.session_id == entry.session_id)
            .try_fold(0u64, |total, q| total.checked_add(q.buffered_bytes))
            .and_then(|n| n.checked_add(bytes));
        let query_total = entry.buffered_bytes.checked_add(bytes);
        let session_limit = state
            .sessions
            .get(&entry.session_id)
            .map_or(entry.limits.max_buffered_bytes, |session| {
                session.limits.max_buffered_bytes
            });
        if total.is_none_or(|n| n > state.limits.max_buffered_bytes)
            || own.is_none_or(|n| n > session_limit)
            || query_total.is_none_or(|n| n > entry.limits.max_buffered_bytes)
        {
            return Err(quota(
                "max_buffered_bytes",
                entry.limits.max_buffered_bytes,
                query_total.map_or("overflow".to_owned(), |n| n.to_string()),
            ));
        }
        state.queries.get_mut(query.id()).unwrap().buffered_bytes = query_total.unwrap();
        Ok(())
    }

    pub fn release_buffered_bytes(&self, query: &QueryHandle, bytes: u64) -> MddResult<()> {
        let mut state = self.lock()?;
        let remaining = state
            .query(query)?
            .buffered_bytes
            .checked_sub(bytes)
            .ok_or_else(|| invalid("cannot release unreserved buffer bytes"))?;
        state.queries.get_mut(query.id()).unwrap().buffered_bytes = remaining;
        Ok(())
    }

    pub fn complete_execution(&self, query: &QueryHandle) -> MddResult<()> {
        let mut state = self.lock()?;
        state.checkpoint(query)?;
        let entry = state.queries.get_mut(query.id()).unwrap();
        if entry.status.phase != QueryPhase::Active {
            return Err(invalid("query is not active"));
        }
        entry.status.execution_complete = true;
        entry.reserved_threads = 0;
        Ok(())
    }

    pub fn finish_delivery(&self, query: &QueryHandle) -> MddResult<()> {
        self.finish_delivery_checked(query, None)
    }

    /// Query runtimes supply their immutable budget deadline to the same delivery lock.
    pub fn finish_delivery_with_budget(
        &self,
        query: &QueryHandle,
        budget: &cancellation::DeliveryBudgetDeadline,
    ) -> MddResult<()> {
        if budget.owner() != query.id() {
            return Err(invalid("delivery budget belongs to another query"));
        }
        self.finish_delivery_checked(query, Some(budget))
    }

    fn finish_delivery_checked(
        &self,
        query: &QueryHandle,
        budget: Option<&cancellation::DeliveryBudgetDeadline>,
    ) -> MddResult<()> {
        let mut state = self.lock()?;
        state.checkpoint_delivery(query, budget)?;
        if state.query(query)?.status.phase == QueryPhase::Completed {
            return Ok(());
        }
        if !state.query(query)?.status.execution_complete {
            return Err(invalid("computation is not complete"));
        }
        if state.query(query)?.delivery_abandoned {
            return Err(MddError::new(
                ErrorCode::InvalidCursor,
                "lifecycle",
                "an unconsumed cursor was closed or released",
            ));
        }
        if state.query(query)?.buffered_bytes != 0 {
            return Err(MddError::new(
                ErrorCode::InvalidCursor,
                "lifecycle",
                "unconsumed buffered output remains",
            ));
        }
        if state
            .cursors
            .values()
            .any(|c| c.query_id == query.id() && c.open)
        {
            return Err(MddError::new(
                ErrorCode::InvalidCursor,
                "lifecycle",
                "unconsumed cursor remains",
            ));
        }
        // Cursor scanning itself may cross a deadline; decide again at commit.
        state.checkpoint_delivery(query, budget)?;
        let entry = state.queries.get_mut(query.id()).unwrap();
        entry.status.delivery_complete = true;
        entry.status.phase = QueryPhase::Completed;
        Ok(())
    }

    /// Confirm the bound queue cursor and complete delivery in one lifecycle lock.
    pub fn finish_delivery_cursor_with_budget(
        &self,
        session: &SessionHandle,
        query: &QueryHandle,
        cursor: &CursorHandle,
        budget: &cancellation::DeliveryBudgetDeadline,
    ) -> MddResult<()> {
        if budget.owner() != query.id() {
            return Err(invalid("delivery budget belongs to another query"));
        }
        let mut state = self.lock()?;
        state.owned_query(session, query)?;
        state.checkpoint_delivery(query, Some(budget))?;
        let cursor_entry = state
            .cursors
            .get(cursor.id())
            .ok_or_else(|| MddError::new(ErrorCode::InvalidCursor, "lifecycle", "stale cursor"))?;
        state.check(&cursor.0, &cursor_entry.token)?;
        let query_entry = state.query(query)?;
        if !cursor_entry.open
            || cursor_entry.query_id != query.id()
            || cursor_entry.session_id != session.id()
            || cursor_entry.snapshot_id != state.session(session)?.snapshot_id
            || cursor_entry.catalog_epoch != query_entry.status.catalog_epoch.0
            || cursor_entry.binding.request_key != query_entry.binding.request_key
            || cursor_entry.binding.schema_id != query_entry.binding.schema_id
            || cursor_entry.binding.semantic_version != query_entry.binding.semantic_version
        {
            return Err(MddError::new(
                ErrorCode::InvalidCursor,
                "lifecycle",
                "cursor binding or lifetime mismatch",
            ));
        }
        let entry = state.query(query)?;
        if !entry.status.execution_complete {
            return Err(invalid("computation is not complete"));
        }
        if entry.delivery_abandoned || entry.buffered_bytes != 0 {
            return Err(MddError::new(
                ErrorCode::InvalidCursor,
                "lifecycle",
                "unconsumed cursor or buffered output remains",
            ));
        }
        if state
            .cursors
            .iter()
            .any(|(id, other)| id != cursor.id() && other.query_id == query.id() && other.open)
        {
            return Err(MddError::new(
                ErrorCode::InvalidCursor,
                "lifecycle",
                "unconsumed cursor remains",
            ));
        }
        // Recheck after scanning, at the delivery linearization point.
        state.checkpoint_delivery(query, Some(budget))?;
        let cursor_entry = state.cursors.get_mut(cursor.id()).unwrap();
        cursor_entry.consumed = true;
        cursor_entry.open = false;
        let entry = state.queries.get_mut(query.id()).unwrap();
        entry.status.delivery_complete = true;
        entry.status.phase = QueryPhase::Completed;
        Ok(())
    }

    pub fn open_cursor(
        &self,
        session: &SessionHandle,
        query: &QueryHandle,
    ) -> MddResult<CursorHandle> {
        let mut state = self.lock()?;
        let entry = state.owned_query(session, query)?;
        if entry.status.phase != QueryPhase::Active {
            return Err(invalid("cursor requires active query"));
        }
        state.checkpoint(query)?;
        let entry = state.query(query)?;
        let binding = entry.binding.clone();
        let catalog_epoch = entry.status.catalog_epoch.0;
        let snapshot_id = state.session(session)?.snapshot_id.clone();
        let session_count = state
            .cursors
            .values()
            .filter(|c| c.session_id == session.id())
            .count();
        let query_count = state
            .cursors
            .values()
            .filter(|c| c.query_id == query.id())
            .count();
        let max = entry.limits.max_cursors;
        if state.cursors.len() >= state.limits.max_cursors
            || session_count >= state.session(session)?.limits.max_cursors
            || query_count >= max
        {
            return Err(quota("max_cursors", max, session_count + 1));
        }
        let token = state.token("cursor")?;
        state.cursors.insert(
            token.id.clone(),
            CursorEntry {
                token: token.clone(),
                session_id: session.id().to_owned(),
                query_id: query.id().to_owned(),
                snapshot_id,
                catalog_epoch,
                binding,
                open: true,
                consumed: false,
            },
        );
        Ok(CursorHandle(token))
    }

    pub fn validate_cursor(
        &self,
        session: &SessionHandle,
        query: &QueryHandle,
        cursor: &CursorHandle,
    ) -> MddResult<u64> {
        let mut state = self.lock()?;
        state.owned_query(session, query)?;
        state.checkpoint(query)?;
        let entry = state
            .cursors
            .get(cursor.id())
            .ok_or_else(|| MddError::new(ErrorCode::InvalidCursor, "lifecycle", "stale cursor"))?;
        state.check(&cursor.0, &entry.token)?;
        let query_entry = state.query(query)?;
        if !entry.open
            || entry.query_id != query.id()
            || entry.session_id != session.id()
            || entry.snapshot_id != state.session(session)?.snapshot_id
            || entry.catalog_epoch != query_entry.status.catalog_epoch.0
            || entry.binding.request_key != query_entry.binding.request_key
            || entry.binding.schema_id != query_entry.binding.schema_id
            || entry.binding.semantic_version != query_entry.binding.semantic_version
        {
            return Err(MddError::new(
                ErrorCode::InvalidCursor,
                "lifecycle",
                "cursor binding or lifetime mismatch",
            ));
        }
        Ok(entry.catalog_epoch)
    }

    pub fn close_cursor(&self, cursor: &CursorHandle) -> MddResult<()> {
        let mut state = self.lock()?;
        let entry = state
            .cursors
            .get(cursor.id())
            .ok_or_else(|| MddError::new(ErrorCode::InvalidCursor, "lifecycle", "stale cursor"))?;
        state.check(&cursor.0, &entry.token)?;
        let abandoned_query = if entry.consumed {
            None
        } else {
            Some(entry.query_id.clone())
        };
        state.cursors.get_mut(cursor.id()).unwrap().open = false;
        if let Some(id) = abandoned_query
            && let Some(query) = state.queries.get_mut(&id)
        {
            query.delivery_abandoned = true;
        }
        Ok(())
    }

    pub fn finish_cursor(
        &self,
        session: &SessionHandle,
        query: &QueryHandle,
        cursor: &CursorHandle,
    ) -> MddResult<()> {
        self.validate_cursor(session, query, cursor)?;
        let mut state = self.lock()?;
        state.owned_query(session, query)?;
        state.checkpoint(query)?;
        let entry = state
            .cursors
            .get(cursor.id())
            .ok_or_else(|| MddError::new(ErrorCode::InvalidCursor, "lifecycle", "stale cursor"))?;
        state.check(&cursor.0, &entry.token)?;
        if !entry.open || entry.query_id != query.id() {
            return Err(MddError::new(
                ErrorCode::InvalidCursor,
                "lifecycle",
                "cursor is already closed",
            ));
        }
        let entry = state.cursors.get_mut(cursor.id()).unwrap();
        entry.consumed = true;
        entry.open = false;
        Ok(())
    }

    pub fn release_cursor(&self, cursor: &CursorHandle) -> MddResult<()> {
        self.close_cursor(cursor)?;
        let mut state = self.lock()?;
        let entry = state
            .cursors
            .get(cursor.id())
            .ok_or_else(|| MddError::new(ErrorCode::InvalidCursor, "lifecycle", "stale cursor"))?;
        state.check(&cursor.0, &entry.token)?;
        state.cursors.remove(cursor.id());
        Ok(())
    }

    pub fn cancel_query(&self, query: &QueryHandle) -> MddResult<()> {
        let mut state = self.lock()?;
        state.query(query)?;
        state.end_query(
            query.id(),
            MddError::new(ErrorCode::Cancelled, "lifecycle", "query cancelled"),
        );
        Ok(())
    }

    pub fn query_status(&self, query: &QueryHandle) -> MddResult<QueryStatus> {
        Ok(self.lock()?.query(query)?.status.clone())
    }

    pub fn query_snapshot_lease(&self, query: &QueryHandle) -> MddResult<Arc<Snapshot>> {
        Ok(Arc::clone(&self.lock()?.query(query)?.snapshot))
    }

    pub fn release_query(&self, query: &QueryHandle) -> MddResult<()> {
        let mut state = self.lock()?;
        state.query(query)?;
        state.end_query(
            query.id(),
            MddError::new(ErrorCode::Cancelled, "lifecycle", "query released"),
        );
        state.queries.remove(query.id());
        state
            .cursors
            .retain(|_, cursor| cursor.query_id != query.id());
        Ok(())
    }

    pub fn fail_worker(&self, error: MddError) -> MddResult<Vec<QueryFailure>> {
        let mut state = self.lock()?;
        if state.worker_error.is_some() {
            return Ok(Vec::new());
        }
        state.worker_error = Some(error.clone());
        let unfinished: Vec<_> = state
            .queries
            .iter()
            .filter(|(_, q)| !q.status.phase.terminal())
            .map(|(id, _)| id.clone())
            .collect();
        let failures = unfinished
            .iter()
            .map(|id| QueryFailure {
                query_id: id.clone(),
                error: error.clone(),
            })
            .collect();
        for id in unfinished {
            state.end_query(&id, error.clone());
        }
        Ok(failures)
    }

    pub fn worker_lost(&self, reason: &str) -> MddResult<Vec<QueryFailure>> {
        self.fail_worker(MddError::new(ErrorCode::WorkerLost, "worker", reason))
    }
}

#[cfg(test)]
mod tests {
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
}
