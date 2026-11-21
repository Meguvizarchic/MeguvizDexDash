use super::budget::{BudgetPermit, BudgetSnapshot, GlobalSchedulerBudget, PipelineStage};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduledTaskState {
    Queued,
    Running,
    Completed,
    Cancelled,
    WorkerLost,
    RejectedQuota,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FairQueueConfig {
    pub max_queued_tasks: usize,
    pub max_history_entries: usize,
}

impl Default for FairQueueConfig {
    fn default() -> Self {
        Self {
            max_queued_tasks: 64,
            max_history_entries: 256,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TaskSpec {
    pub session_id: String,
    pub stage: PipelineStage,
    pub cpu_permits: usize,
    pub memory_bytes: u64,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TaskStatusSnapshot {
    pub task_id: u64,
    pub session_id: String,
    pub stage: PipelineStage,
    pub requested_cpu: usize,
    pub requested_memory_bytes: u64,
    pub generation: u64,
    pub state: ScheduledTaskState,
    pub enqueue_ns: u64,
    pub start_ns: Option<u64>,
    pub end_ns: Option<u64>,
    pub cancel_requested_ns: Option<u64>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SchedulerSnapshot {
    pub queued_count: usize,
    pub running_count: usize,
    pub completed_count: usize,
    pub cancelled_count: usize,
    pub worker_lost_count: usize,
    pub rejected_quota_count: usize,
    pub queue_limit: usize,
    pub history_limit: usize,
    pub queue_depth_bounded: bool,
    pub history_bounded: bool,
    pub budget: BudgetSnapshot,
    pub tasks: Vec<TaskStatusSnapshot>,
}

struct TaskRecord {
    spec: TaskSpec,
    state: ScheduledTaskState,
    enqueue_ns: u64,
    start_ns: Option<u64>,
    end_ns: Option<u64>,
    cancel_requested_ns: Option<u64>,
    cancel_flag: Arc<AtomicBool>,
    reason: Option<String>,
}

impl TaskRecord {
    fn snapshot(&self, task_id: u64) -> TaskStatusSnapshot {
        TaskStatusSnapshot {
            task_id,
            session_id: self.spec.session_id.clone(),
            stage: self.spec.stage,
            requested_cpu: self.spec.cpu_permits,
            requested_memory_bytes: self.spec.memory_bytes,
            generation: self.spec.generation,
            state: self.state,
            enqueue_ns: self.enqueue_ns,
            start_ns: self.start_ns,
            end_ns: self.end_ns,
            cancel_requested_ns: self.cancel_requested_ns,
            reason: self.reason.clone(),
        }
    }
}

struct QueueInner {
    config: FairQueueConfig,
    epoch: Instant,
    next_task_id: u64,
    records: BTreeMap<u64, TaskRecord>,
    /// Fair round-robin queue of session IDs that currently have queued tasks.
    session_ring: VecDeque<String>,
    per_session_queues: BTreeMap<String, VecDeque<u64>>,
    terminal_history: VecDeque<u64>,
    counts_completed: usize,
    counts_cancelled: usize,
    counts_worker_lost: usize,
    counts_rejected_quota: usize,
}

impl QueueInner {
    fn now_ns(&self) -> u64 {
        self.epoch.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
    }

    fn queued_len(&self) -> usize {
        self.per_session_queues.values().map(VecDeque::len).sum()
    }

    fn push_terminal(&mut self, task_id: u64, state: ScheduledTaskState, reason: Option<String>) {
        let now = self.now_ns();
        if let Some(rec) = self.records.get_mut(&task_id) {
            rec.state = state;
            rec.end_ns.get_or_insert(now);
            if reason.is_some() {
                rec.reason = reason;
            }
        }
        match state {
            ScheduledTaskState::Completed => self.counts_completed += 1,
            ScheduledTaskState::Cancelled => self.counts_cancelled += 1,
            ScheduledTaskState::WorkerLost => self.counts_worker_lost += 1,
            ScheduledTaskState::RejectedQuota => self.counts_rejected_quota += 1,
            ScheduledTaskState::Queued | ScheduledTaskState::Running => {}
        }
        self.terminal_history.push_back(task_id);
        while self.terminal_history.len() > self.config.max_history_entries {
            if let Some(evicted) = self.terminal_history.pop_front() {
                self.records.remove(&evicted);
            }
        }
    }
}

#[derive(Clone)]
pub struct ScheduledTaskHandle {
    task_id: u64,
    cancel_flag: Arc<AtomicBool>,
    scheduler: FairApkScheduler,
}

impl std::fmt::Debug for ScheduledTaskHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScheduledTaskHandle")
            .field("task_id", &self.task_id)
            .finish()
    }
}

impl ScheduledTaskHandle {
    pub fn task_id(&self) -> u64 {
        self.task_id
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel_flag.load(Ordering::Acquire)
    }

    pub fn cancel_token(&self) -> &AtomicBool {
        &self.cancel_flag
    }

    pub fn cancel(&self, reason: impl Into<String>) -> bool {
        self.scheduler.cancel_task(self.task_id, &reason.into())
    }

    pub fn status(&self) -> Option<TaskStatusSnapshot> {
        self.scheduler.task_status(self.task_id)
    }
}

pub struct RunningTaskLease {
    task_id: u64,
    permit: Option<BudgetPermit>,
    cancel_flag: Arc<AtomicBool>,
    scheduler: FairApkScheduler,
    settled: bool,
}

impl RunningTaskLease {
    pub fn task_id(&self) -> u64 {
        self.task_id
    }

    pub fn cancel_flag(&self) -> &Arc<AtomicBool> {
        &self.cancel_flag
    }

    pub fn complete(mut self) -> MddResult<()> {
        self.settled = true;
        drop(self.permit.take());
        self.scheduler.finish_task(self.task_id)
    }

    pub fn cancel(mut self, reason: impl Into<String>) {
        self.settled = true;
        drop(self.permit.take());
        self.scheduler.mark_terminal(
            self.task_id,
            ScheduledTaskState::Cancelled,
            Some(reason.into()),
        );
    }

    pub fn worker_lost(mut self, reason: impl Into<String>) {
        self.settled = true;
        drop(self.permit.take());
        self.scheduler.mark_terminal(
            self.task_id,
            ScheduledTaskState::WorkerLost,
            Some(reason.into()),
        );
    }
}

impl Drop for RunningTaskLease {
    fn drop(&mut self) {
        drop(self.permit.take());
        if !self.settled {
            self.settled = true;
            let state = if self.cancel_flag.load(Ordering::Acquire) {
                ScheduledTaskState::Cancelled
            } else {
                ScheduledTaskState::WorkerLost
            };
            self.scheduler.mark_terminal(
                self.task_id,
                state,
                Some("running lease dropped without explicit completion".to_owned()),
            );
        }
    }
}

struct SchedulerState {
    budget: GlobalSchedulerBudget,
    inner: Mutex<QueueInner>,
    wakeup: Condvar,
}

/// Fair round-robin bounded scheduler over a shared `GlobalSchedulerBudget`.
#[derive(Clone)]
pub struct FairApkScheduler {
    state: Arc<SchedulerState>,
}

impl FairApkScheduler {
    pub fn new(budget: GlobalSchedulerBudget, config: FairQueueConfig) -> MddResult<Self> {
        if config.max_queued_tasks == 0 || config.max_history_entries == 0 {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "scheduler.queue",
                "scheduler queue and history bounds must be positive",
            ));
        }
        Ok(Self {
            state: Arc::new(SchedulerState {
                budget,
                inner: Mutex::new(QueueInner {
                    config,
                    epoch: Instant::now(),
                    next_task_id: 1,
                    records: BTreeMap::new(),
                    session_ring: VecDeque::new(),
                    per_session_queues: BTreeMap::new(),
                    terminal_history: VecDeque::new(),
                    counts_completed: 0,
                    counts_cancelled: 0,
                    counts_worker_lost: 0,
                    counts_rejected_quota: 0,
                }),
                wakeup: Condvar::new(),
            }),
        })
    }

    pub fn budget(&self) -> &GlobalSchedulerBudget {
        &self.state.budget
    }

    /// Submit one APK stage task. Rejects immediately with `QuotaExceeded` (without affecting healthy
    /// active tasks) if queue depth is full or task demand exceeds the global budget ceiling.
    pub fn submit(&self, spec: TaskSpec) -> MddResult<ScheduledTaskHandle> {
        if spec.session_id.is_empty() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "scheduler.queue",
                "session_id cannot be empty",
            ));
        }
        if let Err(err) = self
            .state
            .budget
            .validate_request(spec.cpu_permits, spec.memory_bytes)
        {
            let mut inner = self.state.inner.lock().expect("scheduler lock");
            let task_id = inner.next_task_id;
            inner.next_task_id += 1;
            let now = inner.now_ns();
            inner.records.insert(
                task_id,
                TaskRecord {
                    spec,
                    state: ScheduledTaskState::RejectedQuota,
                    enqueue_ns: now,
                    start_ns: None,
                    end_ns: Some(now),
                    cancel_requested_ns: None,
                    cancel_flag: Arc::new(AtomicBool::new(false)),
                    reason: Some(err.message.clone()),
                },
            );
            inner.push_terminal(
                task_id,
                ScheduledTaskState::RejectedQuota,
                Some(err.message.clone()),
            );
            return Err(err);
        }

        let mut inner = self.state.inner.lock().expect("scheduler lock");
        let task_id = inner.next_task_id;
        inner.next_task_id += 1;
        let now = inner.now_ns();
        if inner.queued_len() >= inner.config.max_queued_tasks {
            let reason = "scheduler queue depth limit exceeded";
            inner.records.insert(
                task_id,
                TaskRecord {
                    spec,
                    state: ScheduledTaskState::RejectedQuota,
                    enqueue_ns: now,
                    start_ns: None,
                    end_ns: Some(now),
                    cancel_requested_ns: None,
                    cancel_flag: Arc::new(AtomicBool::new(false)),
                    reason: Some(reason.to_owned()),
                },
            );
            inner.push_terminal(
                task_id,
                ScheduledTaskState::RejectedQuota,
                Some(reason.to_owned()),
            );
            return Err(
                MddError::new(ErrorCode::QuotaExceeded, "scheduler.queue", reason).detail(
                    "max_queued_tasks",
                    inner.config.max_queued_tasks.to_string(),
                ),
            );
        }

        let cancel_flag = Arc::new(AtomicBool::new(false));
        let session_id = spec.session_id.clone();
        inner.records.insert(
            task_id,
            TaskRecord {
                spec,
                state: ScheduledTaskState::Queued,
                enqueue_ns: now,
                start_ns: None,
                end_ns: None,
                cancel_requested_ns: None,
                cancel_flag: Arc::clone(&cancel_flag),
                reason: None,
            },
        );
        let needs_ring = inner
            .per_session_queues
            .get(&session_id)
            .is_none_or(VecDeque::is_empty);
        if needs_ring {
            inner.session_ring.push_back(session_id.clone());
        }
        inner
            .per_session_queues
            .entry(session_id)
            .or_default()
            .push_back(task_id);
        self.state.wakeup.notify_all();
        Ok(ScheduledTaskHandle {
            task_id,
            cancel_flag,
            scheduler: self.clone(),
        })
    }

    /// Wait until `task_id` reaches the head of fair round-robin dispatch AND acquires a `BudgetPermit`.
    pub fn start_task(
        &self,
        handle: &ScheduledTaskHandle,
        deadline: Option<Instant>,
    ) -> MddResult<RunningTaskLease> {
        let mut inner = self.state.inner.lock().expect("scheduler lock");
        loop {
            if handle.cancel_flag.load(Ordering::Acquire) {
                self.cancel_queued_locked(&mut inner, handle.task_id, "cancelled before dispatch");
                return Err(MddError::new(
                    ErrorCode::Cancelled,
                    "scheduler.queue",
                    "task cancelled while queued",
                ));
            }
            let Some(rec) = inner.records.get(&handle.task_id) else {
                return Err(MddError::new(
                    ErrorCode::InternalFault,
                    "scheduler.queue",
                    "unknown scheduled task handle",
                ));
            };
            if rec.state != ScheduledTaskState::Queued {
                let code = match rec.state {
                    ScheduledTaskState::Cancelled => ErrorCode::Cancelled,
                    ScheduledTaskState::WorkerLost => ErrorCode::WorkerLost,
                    ScheduledTaskState::RejectedQuota => ErrorCode::QuotaExceeded,
                    _ => ErrorCode::InvalidArgument,
                };
                return Err(MddError::new(
                    code,
                    "scheduler.queue",
                    format!("task is not queued (state: {:?})", rec.state),
                ));
            }

            // Round-robin fair head inspection: prune empty sessions and try the head session whose front task matches.
            let mut started_permit: Option<BudgetPermit> = None;
            let ring_len = inner.session_ring.len();
            for _ in 0..ring_len {
                let Some(sess) = inner.session_ring.pop_front() else {
                    break;
                };
                let front_id = inner
                    .per_session_queues
                    .get(&sess)
                    .and_then(|q| q.front().copied());
                let Some(tid) = front_id else {
                    inner.per_session_queues.remove(&sess);
                    continue;
                };
                if tid == handle.task_id {
                    let (cpu, mem, stage) = {
                        let r = &inner.records[&tid];
                        (r.spec.cpu_permits, r.spec.memory_bytes, r.spec.stage)
                    };
                    if let Some(permit) = self.state.budget.try_acquire(&sess, stage, cpu, mem)? {
                        let empty_now = if let Some(q) = inner.per_session_queues.get_mut(&sess) {
                            q.pop_front();
                            q.is_empty()
                        } else {
                            true
                        };
                        if empty_now {
                            inner.per_session_queues.remove(&sess);
                        } else {
                            inner.session_ring.push_back(sess);
                        }
                        started_permit = Some(permit);
                        break;
                    }
                }
                inner.session_ring.push_back(sess);
            }

            if let Some(permit) = started_permit {
                let now = inner.now_ns();
                if let Some(rec) = inner.records.get_mut(&handle.task_id) {
                    rec.state = ScheduledTaskState::Running;
                    rec.start_ns = Some(now);
                }
                self.state.wakeup.notify_all();
                return Ok(RunningTaskLease {
                    task_id: handle.task_id,
                    permit: Some(permit),
                    cancel_flag: Arc::clone(&handle.cancel_flag),
                    scheduler: self.clone(),
                    settled: false,
                });
            }

            let wait = match deadline {
                Some(dl) => {
                    let now = Instant::now();
                    if now >= dl {
                        self.cancel_queued_locked(
                            &mut inner,
                            handle.task_id,
                            "deadline exceeded in scheduler queue",
                        );
                        return Err(MddError::new(
                            ErrorCode::DeadlineExceeded,
                            "scheduler.queue",
                            "deadline exceeded waiting for scheduler dispatch",
                        ));
                    }
                    dl.saturating_duration_since(now)
                        .min(Duration::from_millis(15))
                }
                None => Duration::from_millis(15),
            };
            let (guard, _) = self
                .state
                .wakeup
                .wait_timeout(inner, wait)
                .expect("scheduler lock");
            inner = guard;
        }
    }

    fn cancel_queued_locked(&self, inner: &mut QueueInner, task_id: u64, reason: &str) -> bool {
        let Some(rec) = inner.records.get(&task_id) else {
            return false;
        };
        if rec.state != ScheduledTaskState::Queued {
            return false;
        }
        let session_id = rec.spec.session_id.clone();
        if let Some(q) = inner.per_session_queues.get_mut(&session_id) {
            q.retain(|&id| id != task_id);
            if q.is_empty() {
                inner.per_session_queues.remove(&session_id);
                inner.session_ring.retain(|s| s != &session_id);
            }
        }
        let now = inner.now_ns();
        if let Some(rec) = inner.records.get_mut(&task_id) {
            rec.cancel_requested_ns.get_or_insert(now);
        }
        inner.push_terminal(
            task_id,
            ScheduledTaskState::Cancelled,
            Some(reason.to_owned()),
        );
        self.state.wakeup.notify_all();
        true
    }

    pub fn cancel_task(&self, task_id: u64, reason: &str) -> bool {
        let mut inner = self.state.inner.lock().expect("scheduler lock");
        let now = inner.now_ns();
        let state = match inner.records.get_mut(&task_id) {
            Some(rec) => {
                rec.cancel_flag.store(true, Ordering::Release);
                rec.cancel_requested_ns.get_or_insert(now);
                rec.state
            }
            None => return false,
        };
        match state {
            ScheduledTaskState::Queued => self.cancel_queued_locked(&mut inner, task_id, reason),
            ScheduledTaskState::Running => {
                self.state.budget.wakeup();
                self.state.wakeup.notify_all();
                true
            }
            _ => false,
        }
    }

    /// Isolate a lost worker failure strictly to tasks running on that `(session_id, generation)` pair.
    pub fn mark_generation_worker_lost(
        &self,
        session_id: &str,
        generation: u64,
        reason: &str,
    ) -> usize {
        let mut inner = self.state.inner.lock().expect("scheduler lock");
        let affected: Vec<(u64, ScheduledTaskState)> = inner
            .records
            .iter()
            .filter(|(_, rec)| {
                rec.spec.session_id == session_id
                    && rec.spec.generation == generation
                    && matches!(
                        rec.state,
                        ScheduledTaskState::Queued | ScheduledTaskState::Running
                    )
            })
            .map(|(&id, rec)| (id, rec.state))
            .collect();
        for &(tid, st) in &affected {
            if st == ScheduledTaskState::Queued {
                self.cancel_queued_locked(&mut inner, tid, reason);
                if let Some(rec) = inner.records.get_mut(&tid)
                    && rec.state == ScheduledTaskState::Cancelled
                {
                    rec.state = ScheduledTaskState::WorkerLost;
                    inner.counts_cancelled = inner.counts_cancelled.saturating_sub(1);
                    inner.counts_worker_lost += 1;
                }
            } else {
                if let Some(rec) = inner.records.get(&tid) {
                    rec.cancel_flag.store(true, Ordering::Release);
                }
                inner.push_terminal(tid, ScheduledTaskState::WorkerLost, Some(reason.to_owned()));
            }
        }
        self.state.budget.wakeup();
        self.state.wakeup.notify_all();
        affected.len()
    }

    fn finish_task(&self, task_id: u64) -> MddResult<()> {
        let mut inner = self.state.inner.lock().expect("scheduler lock");
        let Some(rec) = inner.records.get(&task_id) else {
            return Ok(());
        };
        if rec.state != ScheduledTaskState::Running {
            return Err(MddError::new(
                ErrorCode::WorkerLost,
                "scheduler.queue",
                format!("task {task_id} was already finalized as {:?}", rec.state),
            ));
        }
        let cancelled = rec.cancel_flag.load(Ordering::Acquire);
        if cancelled {
            inner.push_terminal(
                task_id,
                ScheduledTaskState::Cancelled,
                Some("cancelled before completion".to_owned()),
            );
            self.state.wakeup.notify_all();
            return Err(MddError::new(
                ErrorCode::Cancelled,
                "scheduler.queue",
                "task cancelled prior to completion",
            ));
        }
        inner.push_terminal(task_id, ScheduledTaskState::Completed, None);
        self.state.wakeup.notify_all();
        Ok(())
    }

    fn mark_terminal(&self, task_id: u64, state: ScheduledTaskState, reason: Option<String>) {
        let mut inner = self.state.inner.lock().expect("scheduler lock");
        if let Some(rec) = inner.records.get(&task_id)
            && matches!(
                rec.state,
                ScheduledTaskState::Queued | ScheduledTaskState::Running
            )
        {
            inner.push_terminal(task_id, state, reason);
            self.state.wakeup.notify_all();
        }
    }

    pub fn task_status(&self, task_id: u64) -> Option<TaskStatusSnapshot> {
        let inner = self.state.inner.lock().expect("scheduler lock");
        inner.records.get(&task_id).map(|rec| rec.snapshot(task_id))
    }

    pub fn snapshot(&self) -> SchedulerSnapshot {
        let inner = self.state.inner.lock().expect("scheduler lock");
        let queued = inner.queued_len();
        let running = inner
            .records
            .values()
            .filter(|rec| rec.state == ScheduledTaskState::Running)
            .count();
        let tasks = inner
            .records
            .iter()
            .map(|(&id, rec)| rec.snapshot(id))
            .collect();
        SchedulerSnapshot {
            queued_count: queued,
            running_count: running,
            completed_count: inner.counts_completed,
            cancelled_count: inner.counts_cancelled,
            worker_lost_count: inner.counts_worker_lost,
            rejected_quota_count: inner.counts_rejected_quota,
            queue_limit: inner.config.max_queued_tasks,
            history_limit: inner.config.max_history_entries,
            queue_depth_bounded: queued <= inner.config.max_queued_tasks,
            history_bounded: inner.terminal_history.len() <= inner.config.max_history_entries,
            budget: self.state.budget.snapshot(),
            tasks,
        }
    }
}
