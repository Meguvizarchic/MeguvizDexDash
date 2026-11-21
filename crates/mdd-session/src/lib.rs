//! Owned lifecycle registry. This crate does not execute queries or admit profiles.
pub mod cancellation;
// TEMP catalog definitions and the two paging contracts (native snapshot cursor,
// compatible-offset re-execution). The SQL layer consumes both.
pub mod catalog;
pub mod cursors;

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

/// An owned, immutable delivered batch. Clones share one reservation; the
/// last release returns it, including after the query or session is removed.
/// Retaining a batch is not by itself a delivery-completion receipt.
#[derive(Clone)]
pub struct BatchHandle(Arc<OwnedBatch>);

struct OwnedBatch {
    lifecycle: Lifecycle,
    token: Token,
    query: Token,
    snapshot: Arc<Snapshot>,
    bytes: Box<[u8]>,
    released: bool,
}

impl BatchHandle {
    pub fn id(&self) -> &str {
        &self.0.token.id
    }

    pub fn snapshot_id(&self) -> &str {
        &self.0.snapshot.manifest().snapshot_id
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0.bytes
    }

    /// Explicitly acknowledge this batch's consumption while its query is
    /// still active. Owning or dropping the handle alone is not an ack.
    pub fn acknowledge(&self) -> MddResult<()> {
        self.acknowledge_checked(None)
    }

    /// Acknowledge with the query's immutable runtime deadline witness. The
    /// caller must supply the witness belonging to this query's budget.
    pub fn acknowledge_with_budget(
        &self,
        budget: &cancellation::DeliveryBudgetDeadline,
    ) -> MddResult<()> {
        self.acknowledge_checked(Some(budget))
    }

    fn acknowledge_checked(
        &self,
        budget: Option<&cancellation::DeliveryBudgetDeadline>,
    ) -> MddResult<()> {
        let query = QueryHandle(self.0.query.clone());
        if budget.is_some_and(|value| value.owner() != query.id()) {
            return Err(invalid(
                "batch acknowledgement budget belongs to another query",
            ));
        }
        let mut state = self.0.lifecycle.lock_query(&query)?;
        let entry = state
            .batches
            .get(&self.0.token.id)
            .ok_or_else(|| invalid("stale batch handle"))?;
        state.check(&self.0.token, &entry.token)?;
        if entry.query_id != self.0.query.id {
            return Err(invalid("batch query binding mismatch"));
        }
        state.checkpoint_delivery(&query, budget)?;
        if state.query(&query)?.status.phase != QueryPhase::Active {
            return Err(invalid("query is not active"));
        }
        let entry = state.batches.get_mut(&self.0.token.id).unwrap();
        if entry.acknowledged {
            return Err(invalid("batch already acknowledged"));
        }
        entry.acknowledged = true;
        Ok(())
    }

    /// Record explicit consumption of an already-delivered partial batch after
    /// this query has failed. The caller must supply the exact recorded first
    /// error. This cannot turn the failed query into a successful delivery.
    pub fn acknowledge_partial(&self, expected_error: &MddError) -> MddResult<()> {
        self.acknowledge_partial_checked(expected_error, None)
    }

    /// Confirm a consumed partial batch while both the lifecycle and supplied
    /// query-budget deadline remain open. Any pre-existing failure is retained.
    pub fn acknowledge_partial_with_budget(
        &self,
        expected_error: &MddError,
        budget: &cancellation::DeliveryBudgetDeadline,
    ) -> MddResult<()> {
        self.acknowledge_partial_checked(expected_error, Some(budget))
    }

    fn acknowledge_partial_checked(
        &self,
        expected_error: &MddError,
        budget: Option<&cancellation::DeliveryBudgetDeadline>,
    ) -> MddResult<()> {
        let query = QueryHandle(self.0.query.clone());
        if budget.is_some_and(|value| value.owner() != query.id()) {
            return Err(invalid(
                "batch acknowledgement budget belongs to another query",
            ));
        }
        let mut state = self.0.lifecycle.lock_query_read(&query)?;
        let query_entry = state.query(&query)?;
        let actual = query_entry
            .status
            .error
            .as_ref()
            .ok_or_else(|| invalid("partial acknowledgement requires query failure"))?;
        if state.batch_fault.is_some() {
            return Err(actual.clone());
        }
        if !matches!(
            query_entry.status.phase,
            QueryPhase::Failed | QueryPhase::Cancelled
        ) || query_entry.status.delivery_complete
            || actual.code != expected_error.code
            || actual.stage != expected_error.stage
            || actual.message != expected_error.message
            || actual.retryable != expected_error.retryable
            || actual.details != expected_error.details
        {
            return Err(invalid("partial acknowledgement error binding mismatch"));
        }
        if let Some(budget) = budget {
            let now = Instant::now();
            if now >= query_entry.deadline || now >= budget.soft() {
                return Err(actual.clone());
            }
        }
        let entry = state
            .batches
            .get(&self.0.token.id)
            .ok_or_else(|| invalid("stale batch handle"))?;
        state.check(&self.0.token, &entry.token)?;
        if entry.query_id != query.id() {
            return Err(invalid("batch query binding mismatch"));
        }
        let entry = state.batches.get_mut(&self.0.token.id).unwrap();
        if entry.acknowledged {
            return Err(invalid("batch already acknowledged"));
        }
        entry.acknowledged = true;
        Ok(())
    }

    /// Release this reference. The final reference reports a registry failure;
    /// dropping instead records such a failure on the lifecycle for later calls.
    pub fn release(self) -> MddResult<()> {
        match Arc::into_inner(self.0) {
            Some(mut batch) => batch.release_reservation(),
            None => Ok(()),
        }
    }
}

impl OwnedBatch {
    fn release_reservation(&mut self) -> MddResult<()> {
        if self.released {
            return Ok(());
        }
        let mut state = self.lifecycle.inner.lock().map_err(|_| {
            MddError::new(
                ErrorCode::InternalFault,
                "lifecycle",
                "registry mutex poisoned",
            )
        })?;
        let valid = state
            .batches
            .get(&self.token.id)
            .is_some_and(|entry| entry.token == self.token && entry.token.owner == state.owner);
        if !valid {
            let error = MddError::new(
                ErrorCode::InternalFault,
                "lifecycle",
                "batch reservation identity mismatch",
            );
            state.record_batch_fault(error.clone());
            return Err(error);
        }
        let batch = state.batches.remove(&self.token.id).unwrap();
        if !batch.acknowledged
            && let Some(query) = state.queries.get_mut(&batch.query_id)
            && !query.status.phase.terminal()
        {
            query.delivery_abandoned = true;
        }
        self.released = true;
        Ok(())
    }
}

impl Drop for OwnedBatch {
    fn drop(&mut self) {
        if self.release_reservation().is_err()
            && let Ok(mut state) = self.lifecycle.inner.lock()
            && state.batch_fault.is_none()
        {
            state.record_batch_fault(MddError::new(
                ErrorCode::InternalFault,
                "lifecycle",
                "batch reservation release failed",
            ));
        }
    }
}

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
    /// Single source of truth for the session's catalog generation.
    temp: catalog::TempCatalog,
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
    execution_started: bool,
    temp_binding: Option<catalog::TempBinding>,
}
struct CursorEntry {
    token: Token,
    session_id: String,
    query_id: String,
    snapshot_id: String,
    catalog_epoch: u64,
    binding: QueryBinding,
    /// Worker that opened this cursor; a new worker generation invalidates it.
    worker_owner: String,
    worker_generation: u64,
    /// SQL-layer fingerprints. Absent on the legacy delivery cursor.
    spec: Option<cursors::CursorSpec>,
    /// First admitted page fixes the exact total (including "no exact total").
    page_total: Option<u64>,
    page_total_established: bool,
    pages: u64,
    open: bool,
    consumed: bool,
}

struct BatchEntry {
    token: Token,
    session_id: String,
    query_id: String,
    bytes: u64,
    acknowledged: bool,
}

struct State {
    owner: String,
    next_generation: u64,
    /// Worker instance generation. Unlike handle generations this only changes
    /// when the registry is reattached to a new worker, and every cursor opened
    /// before the change is rejected afterwards.
    worker_generation: u64,
    limits: ResourceLimits,
    worker_error: Option<MddError>,
    supervisor_attached: bool,
    snapshots: HashMap<String, SnapshotEntry>,
    sessions: HashMap<String, SessionEntry>,
    queries: HashMap<String, QueryEntry>,
    cursors: HashMap<String, CursorEntry>,
    batches: HashMap<String, BatchEntry>,
    batch_fault: Option<MddError>,
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
    fn record_batch_fault(&mut self, error: MddError) {
        if self.batch_fault.is_some() {
            return;
        }
        self.batch_fault = Some(error.clone());
        for query in self.queries.values_mut() {
            if !query.status.phase.terminal() {
                query.status.phase = QueryPhase::Failed;
                query.status.error = Some(error.clone());
                query.reserved_threads = 0;
            }
        }
        for cursor in self.cursors.values_mut() {
            if self
                .queries
                .get(&cursor.query_id)
                .is_some_and(|q| q.status.phase == QueryPhase::Failed)
            {
                cursor.open = false;
            }
        }
    }

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

    fn checked_buffered_add(&self, query: &QueryHandle, bytes: u64) -> MddResult<u64> {
        let entry = self.query(query)?;
        let mut total = Some(0u64);
        let mut session_total = Some(0u64);
        let mut query_total = Some(0u64);
        for other in self.queries.values() {
            total = total.and_then(|v| v.checked_add(other.buffered_bytes));
            if other.session_id == entry.session_id {
                session_total = session_total.and_then(|v| v.checked_add(other.buffered_bytes));
            }
            if other.token.id == query.id() {
                query_total = query_total.and_then(|v| v.checked_add(other.buffered_bytes));
            }
        }
        for batch in self.batches.values() {
            total = total.and_then(|v| v.checked_add(batch.bytes));
            if batch.session_id == entry.session_id {
                session_total = session_total.and_then(|v| v.checked_add(batch.bytes));
            }
            if batch.query_id == query.id() {
                query_total = query_total.and_then(|v| v.checked_add(batch.bytes));
            }
        }
        total = total.and_then(|v| v.checked_add(bytes));
        session_total = session_total.and_then(|v| v.checked_add(bytes));
        query_total = query_total.and_then(|v| v.checked_add(bytes));
        let session_limit = self
            .sessions
            .get(&entry.session_id)
            .map_or(entry.limits.max_buffered_bytes, |session| {
                session.limits.max_buffered_bytes
            });
        if total.is_none_or(|v| v > self.limits.max_buffered_bytes)
            || session_total.is_none_or(|v| v > session_limit)
            || query_total.is_none_or(|v| v > entry.limits.max_buffered_bytes)
        {
            return Err(quota(
                "max_buffered_bytes",
                entry.limits.max_buffered_bytes,
                query_total.map_or("overflow".to_owned(), |n| n.to_string()),
            ));
        }
        entry.buffered_bytes.checked_add(bytes).ok_or_else(|| {
            quota(
                "max_buffered_bytes",
                entry.limits.max_buffered_bytes,
                "overflow",
            )
        })
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
            // A consumer can still own previously delivered buffers after a
            // query or session ends. Only explicit release returns the quota.
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
        let lifecycle_limit = entry.limits.deadline_ms;
        let now = Instant::now();
        if let Some(budget) = budget
            && budget.soft() < lifecycle_deadline
            && let Some(error) = budget.error_at(now)
        {
            self.end_query(query.id(), error.clone());
            return Err(error);
        }
        if now >= lifecycle_deadline {
            let error = MddError::new(
                ErrorCode::DeadlineExceeded,
                "lifecycle",
                "query total deadline exceeded",
            )
            .detail("budget", "deadline_ms")
            .detail("limit", lifecycle_limit.to_string());
            self.end_query(query.id(), error.clone());
            return Err(error);
        }
        self.ensure_worker()
    }
}

impl Lifecycle {
    pub fn new(limits: ResourceLimits) -> MddResult<Self> {
        Ok(Self {
            inner: Arc::new(Mutex::new(State {
                owner: opaque_id("runtime")?,
                next_generation: 0,
                worker_generation: 0,
                limits,
                worker_error: None,
                supervisor_attached: false,
                snapshots: HashMap::new(),
                sessions: HashMap::new(),
                queries: HashMap::new(),
                cursors: HashMap::new(),
                batches: HashMap::new(),
                batch_fault: None,
            })),
        })
    }

    fn lock_raw(&self) -> MddResult<MutexGuard<'_, State>> {
        self.inner.lock().map_err(|_| {
            MddError::new(
                ErrorCode::InternalFault,
                "lifecycle",
                "registry mutex poisoned",
            )
        })
    }

    fn lock(&self) -> MddResult<MutexGuard<'_, State>> {
        let state = self.lock_raw()?;
        if let Some(error) = &state.batch_fault {
            return Err(error.clone());
        }
        Ok(state)
    }

    // A query's earlier terminal fault remains authoritative even when a
    // later batch cleanup makes the lifecycle registry fail closed.
    fn lock_query(&self, query: &QueryHandle) -> MddResult<MutexGuard<'_, State>> {
        let state = self.lock_raw()?;
        let entry = state.query(query)?;
        if let Some(fault) = &state.batch_fault {
            return Err(entry.status.error.clone().unwrap_or_else(|| fault.clone()));
        }
        Ok(state)
    }

    fn lock_query_read(&self, query: &QueryHandle) -> MddResult<MutexGuard<'_, State>> {
        let state = self.lock_raw()?;
        let entry = state.query(query)?;
        if entry.status.error.is_none()
            && entry.status.phase != QueryPhase::Completed
            && let Some(fault) = &state.batch_fault
        {
            return Err(fault.clone());
        }
        Ok(state)
    }

    fn lock_cursor(&self, cursor: &CursorHandle) -> MddResult<MutexGuard<'_, State>> {
        let state = self.lock_raw()?;
        let entry = state
            .cursors
            .get(cursor.id())
            .ok_or_else(|| MddError::new(ErrorCode::InvalidCursor, "lifecycle", "stale cursor"))?;
        state.check(&cursor.0, &entry.token)?;
        if let Some(fault) = &state.batch_fault {
            let prior = state
                .queries
                .get(&entry.query_id)
                .and_then(|q| q.status.error.clone());
            return Err(prior.unwrap_or_else(|| fault.clone()));
        }
        Ok(state)
    }

    /// Expose any batch reservation cleanup fault independently of a query's
    /// earlier terminal error. A poisoned registry still reports its own fault.
    pub fn batch_release_error(&self) -> MddResult<Option<MddError>> {
        Ok(self.lock_raw()?.batch_fault.clone())
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
        // A supervised worker is a new worker instance. Cursors opened by the
        // previous generation must fail explicitly rather than keep reading.
        state.worker_generation = state
            .worker_generation
            .checked_add(1)
            .ok_or_else(|| invalid("worker generation exhausted"))?;
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
                temp: catalog::TempCatalog::new(),
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
        state.active_session(session)?;
        state.sessions.get_mut(session.id()).unwrap().temp.advance()
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
        let epoch = entry.temp.epoch();
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
                execution_started: false,
                temp_binding: None,
            },
        );
        Ok(QueryHandle(token))
    }

    pub fn queue_query(&self, session: &SessionHandle, query: &QueryHandle) -> MddResult<()> {
        let mut state = self.lock_query(query)?;
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
        let mut state = self.lock_query(query)?;
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
        entry.execution_started = true;
        entry.status.phase = QueryPhase::Active;
        Ok(())
    }

    pub fn checkpoint(&self, query: &QueryHandle) -> MddResult<()> {
        self.lock_query(query)?.checkpoint(query)
    }

    pub fn reserve_buffered_bytes(&self, query: &QueryHandle, bytes: u64) -> MddResult<()> {
        let mut state = self.lock_query(query)?;
        state.checkpoint(query)?;
        let entry = state.query(query)?;
        if entry.status.phase != QueryPhase::Active {
            return Err(invalid("query is not active"));
        }
        let query_total = state.checked_buffered_add(query, bytes)?;
        state.queries.get_mut(query.id()).unwrap().buffered_bytes = query_total;
        Ok(())
    }

    /// Own delivered bytes independently of their originating query/session.
    /// The caller constructs the owned bytes; construction allocation and RSS
    /// are not covered by this logical reservation. The caller must establish
    /// that the payload belongs to this query's snapshot and delivery protocol.
    pub fn own_batch(&self, query: &QueryHandle, bytes: Box<[u8]>) -> MddResult<BatchHandle> {
        let size = u64::try_from(bytes.len()).map_err(|_| invalid("batch length overflow"))?;
        let mut state = self.lock_query(query)?;
        state.checkpoint(query)?;
        let entry = state.query(query)?;
        if entry.status.phase != QueryPhase::Active {
            return Err(invalid("query is not active"));
        }
        state.checked_buffered_add(query, size)?;
        let snapshot = Arc::clone(&entry.snapshot);
        let session_id = entry.session_id.clone();
        if state.batches.len() >= 10_000 {
            return Err(quota("max_batch_handles", 10_000, state.batches.len() + 1));
        }
        state.batches.try_reserve(1).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "lifecycle",
                "batch registry allocation failed",
            )
        })?;
        let token = state.token("batch")?;
        if state.batches.contains_key(&token.id) {
            return Err(MddError::new(
                ErrorCode::InternalFault,
                "lifecycle",
                "duplicate batch identity",
            ));
        }
        state.batches.insert(
            token.id.clone(),
            BatchEntry {
                token: token.clone(),
                session_id,
                query_id: query.id().to_owned(),
                bytes: size,
                acknowledged: false,
            },
        );
        drop(state);
        Ok(BatchHandle(Arc::new(OwnedBatch {
            lifecycle: self.clone(),
            token,
            query: query.0.clone(),
            snapshot,
            bytes,
            released: false,
        })))
    }

    /// Return a prior logical buffer reservation, including after cancellation,
    /// session closure or worker loss. This does not itself free a caller buffer.
    pub fn release_buffered_bytes(&self, query: &QueryHandle, bytes: u64) -> MddResult<()> {
        let mut state = self.lock_query(query)?;
        let remaining = state
            .query(query)?
            .buffered_bytes
            .checked_sub(bytes)
            .ok_or_else(|| invalid("cannot release unreserved buffer bytes"))?;
        state.queries.get_mut(query.id()).unwrap().buffered_bytes = remaining;
        Ok(())
    }

    pub fn complete_execution(&self, query: &QueryHandle) -> MddResult<()> {
        let mut state = self.lock_query(query)?;
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
        let mut state = self.lock_query(query)?;
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
            .batches
            .values()
            .any(|batch| batch.query_id == query.id() && !batch.acknowledged)
        {
            return Err(MddError::new(
                ErrorCode::InvalidCursor,
                "lifecycle",
                "unacknowledged batch remains",
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
        let mut state = self.lock_query(query)?;
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
        if entry.delivery_abandoned
            || entry.buffered_bytes != 0
            || state
                .batches
                .values()
                .any(|batch| batch.query_id == query.id() && !batch.acknowledged)
        {
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
        let mut state = self.lock_query(query)?;
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
        let worker_owner = state.owner.clone();
        let worker_generation = state.worker_generation;
        state.cursors.insert(
            token.id.clone(),
            CursorEntry {
                token: token.clone(),
                session_id: session.id().to_owned(),
                query_id: query.id().to_owned(),
                snapshot_id,
                catalog_epoch,
                binding,
                worker_owner,
                worker_generation,
                spec: None,
                page_total: None,
                page_total_established: false,
                pages: 0,
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
        let mut state = self.lock_query(query)?;
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
        let mut state = self.lock_cursor(cursor)?;
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
        let mut state = self.lock_query(query)?;
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
        let mut state = self.lock_cursor(cursor)?;
        let entry = state
            .cursors
            .get(cursor.id())
            .ok_or_else(|| MddError::new(ErrorCode::InvalidCursor, "lifecycle", "stale cursor"))?;
        state.check(&cursor.0, &entry.token)?;
        state.cursors.remove(cursor.id());
        Ok(())
    }

    pub fn cancel_query(&self, query: &QueryHandle) -> MddResult<()> {
        let mut state = self.lock_query(query)?;
        state.query(query)?;
        state.end_query(
            query.id(),
            MddError::new(ErrorCode::Cancelled, "lifecycle", "query cancelled"),
        );
        Ok(())
    }

    pub fn query_status(&self, query: &QueryHandle) -> MddResult<QueryStatus> {
        Ok(self.lock_query_read(query)?.query(query)?.status.clone())
    }

    pub fn query_snapshot_lease(&self, query: &QueryHandle) -> MddResult<Arc<Snapshot>> {
        Ok(Arc::clone(
            &self.lock_query_read(query)?.query(query)?.snapshot,
        ))
    }

    pub fn release_query(&self, query: &QueryHandle) -> MddResult<()> {
        let mut state = self.lock_query(query)?;
        state.query(query)?;
        state.end_query(
            query.id(),
            MddError::new(ErrorCode::Cancelled, "lifecycle", "query released"),
        );
        if state.query(query)?.buffered_bytes != 0 {
            return Err(invalid("release outstanding buffer reservations first"));
        }
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
#[path = "lib_tests.rs"]
mod tests;
