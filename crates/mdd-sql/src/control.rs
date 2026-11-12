use crate::quota;
use mdd_query::budget::{Reservation, Resource, RuntimeBudget};
use mdd_types::{ErrorCode, MddError, MddResult};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

#[derive(Clone, Copy, Debug)]
pub struct SqlLimits {
    pub max_sql_bytes: usize,
    pub max_tokens: usize,
    pub max_ast_nodes: usize,
    pub max_ast_depth: usize,
    pub max_ast_operators: usize,
    pub max_steps: u64,
    pub max_scanned_rows: u64,
    pub max_result_rows: u64,
    pub max_cell_bytes: u64,
    pub max_result_bytes: u64,
    /// Maximum aggregate generated virtual-table schema bytes for preconnection.
    /// This is a logical bound and does not cover SQLite allocator/RSS.
    pub max_vtab_schema_bytes: u64,
}
impl Default for SqlLimits {
    fn default() -> Self {
        Self {
            max_sql_bytes: 256 * 1024,
            max_tokens: 65536,
            max_ast_nodes: 32768,
            max_ast_depth: 48,
            max_ast_operators: 128,
            max_steps: 5_000_000,
            max_scanned_rows: 1_000_000,
            max_result_rows: 100_000,
            max_cell_bytes: 1024 * 1024,
            max_result_bytes: 64 * 1024 * 1024,
            max_vtab_schema_bytes: 2 * 1024 * 1024,
        }
    }
}
impl SqlLimits {
    pub fn restricted_by(self, other: Self) -> Self {
        Self {
            max_sql_bytes: self.max_sql_bytes.min(other.max_sql_bytes),
            max_tokens: self.max_tokens.min(other.max_tokens),
            max_ast_nodes: self.max_ast_nodes.min(other.max_ast_nodes),
            max_ast_depth: self.max_ast_depth.min(other.max_ast_depth),
            max_ast_operators: self.max_ast_operators.min(other.max_ast_operators),
            max_steps: self.max_steps.min(other.max_steps),
            max_scanned_rows: self.max_scanned_rows.min(other.max_scanned_rows),
            max_result_rows: self.max_result_rows.min(other.max_result_rows),
            max_cell_bytes: self.max_cell_bytes.min(other.max_cell_bytes),
            max_result_bytes: self.max_result_bytes.min(other.max_result_bytes),
            max_vtab_schema_bytes: self.max_vtab_schema_bytes.min(other.max_vtab_schema_bytes),
        }
    }
}

#[derive(Clone)]
pub struct SqlControl {
    pub(crate) inner: Arc<Inner>,
}
pub(crate) struct Inner {
    pub limits: SqlLimits,
    cancel: Arc<AtomicBool>,
    claimed: Arc<AtomicBool>,
    deadline: Option<Instant>,
    counters: Arc<Counters>,
    /// Set once a sticky error is recorded, so the hot path skips the mutex.
    failed: Arc<AtomicBool>,
    state: Arc<Mutex<State>>,
    runtime: Option<RuntimeBudget>,
}
/// Hot-path counters. `checkpoint` runs once per SQLite VM step, so the common
/// path must not take the mutex: limits are evaluated against these atomics and
/// only the sticky error path serialises on `State`.
#[derive(Default)]
struct Counters {
    steps: AtomicU64,
    scanned: AtomicU64,
    result_rows: AtomicU64,
    result_bytes: AtomicU64,
}
#[derive(Default)]
struct State {
    error: Option<MddError>,
}
impl SqlControl {
    pub fn new(limits: SqlLimits, deadline: Option<Instant>) -> Self {
        Self {
            inner: Arc::new(Inner {
                limits,
                cancel: Arc::new(AtomicBool::new(false)),
                claimed: Arc::new(AtomicBool::new(false)),
                deadline,
                counters: Arc::new(Counters::default()),
                failed: Arc::new(AtomicBool::new(false)),
                state: Arc::new(Mutex::new(State::default())),
                runtime: None,
            }),
        }
    }
    pub(crate) fn restrict(&self, limits: SqlLimits) -> Self {
        Self {
            inner: Arc::new(Inner {
                limits: self.inner.limits.restricted_by(limits),
                cancel: Arc::clone(&self.inner.cancel),
                claimed: Arc::clone(&self.inner.claimed),
                deadline: self.inner.deadline,
                counters: Arc::clone(&self.inner.counters),
                failed: Arc::clone(&self.inner.failed),
                state: Arc::clone(&self.inner.state),
                runtime: self.inner.runtime.clone(),
            }),
        }
    }
    pub fn with_runtime(&self, runtime: RuntimeBudget) -> Self {
        Self {
            inner: Arc::new(Inner {
                limits: self.inner.limits,
                cancel: Arc::clone(&self.inner.cancel),
                claimed: Arc::clone(&self.inner.claimed),
                deadline: self.inner.deadline,
                counters: Arc::clone(&self.inner.counters),
                failed: Arc::clone(&self.inner.failed),
                state: Arc::clone(&self.inner.state),
                runtime: Some(runtime),
            }),
        }
    }
    pub(crate) fn runtime(&self) -> Option<&RuntimeBudget> {
        self.inner.runtime.as_ref()
    }
    pub fn cancel(&self) -> MddResult<()> {
        self.inner.cancel.store(true, Ordering::Release);
        if let Some(runtime) = self.runtime() {
            runtime.cancellation().cancel()?;
        }
        Ok(())
    }
    pub(crate) fn error(&self) -> Option<MddError> {
        if !self.inner.failed.load(Ordering::Acquire) {
            return None;
        }
        self.inner.state.lock().ok().and_then(|s| s.error.clone())
    }
    pub(crate) fn claim(&self) -> MddResult<()> {
        if self.inner.claimed.swap(true, Ordering::AcqRel) {
            return Err(crate::invalid("SQL_CONTROL_ALREADY_BOUND"));
        }
        Ok(())
    }
    pub(crate) fn fail(&self, error: MddError) -> MddError {
        let error = self
            .runtime()
            .map_or(error.clone(), |runtime| runtime.stop(error));
        self.inner.failed.store(true, Ordering::Release);
        if let Ok(mut state) = self.inner.state.lock()
            && state.error.is_none()
        {
            state.error = Some(error.clone());
        }
        self.error().unwrap_or(error)
    }
    /// Record a sticky error. Once any error is stored every later checkpoint
    /// returns it, so the limit checks below stay equivalent to the previous
    /// lock-guarded `State` fields.
    fn sticky(&self, error: MddError) -> MddError {
        // `failed` is raised before the mutex so the hot path can stop taking
        // the lock once an error exists. A concurrent checkpoint can still see
        // `failed == true` with `state.error == None` for a few instructions.
        // That window is new for the two local-budget paths (`SQL_WORK_BUDGET`,
        // `SQL_RESULT_BUDGET`), which previously decided and recorded the error
        // inside one critical section; for the `fail()` paths
        // (cancelled/deadline/runtime) the old code already had a much wider
        // window between its error read and its counter update, so this is a
        // net reduction there. Single-threaded callers observe no difference.
        self.inner.failed.store(true, Ordering::Release);
        if let Ok(mut state) = self.inner.state.lock()
            && state.error.is_none()
        {
            state.error = Some(error.clone());
        }
        self.error().unwrap_or(error)
    }
    pub(crate) fn checkpoint(&self, steps: u64, scan: bool) -> MddResult<()> {
        if self.inner.failed.load(Ordering::Acquire)
            && let Some(error) = self.error()
        {
            return Err(error);
        }
        if self.inner.cancel.load(Ordering::Acquire) {
            return Err(self.fail(MddError::new(
                ErrorCode::Cancelled,
                "sql",
                "query cancelled",
            )));
        }
        if self
            .inner
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(self.fail(MddError::new(
                ErrorCode::DeadlineExceeded,
                "sql",
                "query deadline exceeded",
            )));
        }
        if let Some(runtime) = self.runtime() {
            runtime
                .charge(Resource::QuerySteps, steps)
                .map_err(|error| self.fail(error))?;
        }
        // Read-modify-write, not load/store: `SqlControl` is `Clone` and its
        // derived controls deliberately share these counters, so two threads may
        // admit work concurrently. A plain load/add/store would lose one update
        // and could let `max_steps` or `max_result_rows` be exceeded severalfold.
        let counters = &self.inner.counters;
        let next_steps =
            match counters
                .steps
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(steps)
                }) {
                Ok(previous) => previous.saturating_add(steps),
                Err(_) => return Err(self.sticky(quota("SQL_STEP_OVERFLOW"))),
            };
        let mut next_scanned = 0u64;
        if scan {
            next_scanned =
                match counters
                    .scanned
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                        value.checked_add(1)
                    }) {
                    Ok(previous) => previous.saturating_add(1),
                    Err(_) => return Err(self.sticky(quota("SQL_SCAN_OVERFLOW"))),
                };
        }
        if next_steps > self.inner.limits.max_steps
            || next_scanned > self.inner.limits.max_scanned_rows
        {
            return Err(self.sticky(quota("SQL_WORK_BUDGET")));
        }
        Ok(())
    }
    pub(crate) fn reserve_cursor(&self) -> MddResult<Option<Reservation>> {
        self.runtime()
            .map(|runtime| {
                runtime.checkpoint()?;
                runtime
                    .pool()
                    .reserve(Resource::Cursors, 1)
                    .map_err(|e| self.fail(e))
            })
            .transpose()
    }
    pub(crate) fn work(&self, bytes: u64) -> MddResult<()> {
        if let Some(runtime) = self.runtime() {
            runtime
                .charge(Resource::QueryWorkBytes, bytes)
                .map_err(|e| self.fail(e))?;
        }
        Ok(())
    }
    pub(crate) fn output(&self, bytes: u64) -> MddResult<()> {
        self.checkpoint(1, false)?;
        // Same read-modify-write reasoning as `checkpoint`: each field is
        // individually exact under concurrency. The two fields are not updated
        // as one critical section, so a concurrent observer can see the row
        // count of one admission with the byte count of another; both remain
        // correct running totals and neither can be undercounted.
        let counters = &self.inner.counters;
        let next_rows =
            match counters
                .result_rows
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                }) {
                Ok(previous) => previous.saturating_add(1),
                Err(_) => return Err(self.sticky(quota("SQL_ROWS_OVERFLOW"))),
            };
        let next_bytes =
            match counters
                .result_bytes
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(bytes)
                }) {
                Ok(previous) => previous.saturating_add(bytes),
                Err(_) => return Err(self.sticky(quota("SQL_BYTES_OVERFLOW"))),
            };
        if next_rows > self.inner.limits.max_result_rows
            || next_bytes > self.inner.limits.max_result_bytes
        {
            return Err(self.sticky(quota("SQL_RESULT_BUDGET")));
        }
        Ok(())
    }
}
