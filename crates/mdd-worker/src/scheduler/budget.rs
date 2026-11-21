use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStage {
    WorkerExecution,
    ArchiveDecompression,
    FactBuild,
    QueryExecution,
}

impl PipelineStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WorkerExecution => "worker_execution",
            Self::ArchiveDecompression => "archive_decompression",
            Self::FactBuild => "fact_build",
            Self::QueryExecution => "query_execution",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalBudgetSpec {
    pub total_cpu_permits: usize,
    pub total_memory_bytes: u64,
    pub max_concurrent_apks: usize,
}

impl GlobalBudgetSpec {
    pub fn validate(&self) -> MddResult<()> {
        if self.total_cpu_permits == 0
            || self.total_memory_bytes == 0
            || self.max_concurrent_apks == 0
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "scheduler.budget",
                "global scheduler budget ceilings must all be positive",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StageUsageSnapshot {
    pub cpu_permits: usize,
    pub peak_cpu_permits: usize,
    pub memory_bytes: DecimalU64,
    pub peak_memory_bytes: DecimalU64,
}

impl Default for StageUsageSnapshot {
    fn default() -> Self {
        Self {
            cpu_permits: 0,
            peak_cpu_permits: 0,
            memory_bytes: DecimalU64(0),
            peak_memory_bytes: DecimalU64(0),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BudgetSnapshot {
    pub total_cpu_permits: usize,
    pub used_cpu_permits: usize,
    pub peak_cpu_permits: usize,
    pub total_memory_bytes: DecimalU64,
    pub used_memory_bytes: DecimalU64,
    pub peak_memory_bytes: DecimalU64,
    pub active_apks: usize,
    pub max_concurrent_apks: usize,
    pub oversubscription_observed: bool,
    pub by_stage: BTreeMap<String, StageUsageSnapshot>,
}

#[derive(Default)]
struct StageCounters {
    cpu: usize,
    peak_cpu: usize,
    memory: u64,
    peak_memory: u64,
}

struct BudgetInner {
    spec: GlobalBudgetSpec,
    used_cpu: usize,
    peak_cpu: usize,
    used_memory: u64,
    peak_memory: u64,
    oversubscribed: bool,
    active_sessions: BTreeMap<String, usize>,
    stages: BTreeMap<PipelineStage, StageCounters>,
}

struct BudgetState {
    inner: Mutex<BudgetInner>,
    wakeup: Condvar,
}

/// Thread-safe unified CPU and memory permit pool shared by worker, decompression, fact build, and query stages.
#[derive(Clone)]
pub struct GlobalSchedulerBudget {
    state: Arc<BudgetState>,
}

impl GlobalSchedulerBudget {
    pub fn new(spec: GlobalBudgetSpec) -> MddResult<Self> {
        spec.validate()?;
        Ok(Self {
            state: Arc::new(BudgetState {
                inner: Mutex::new(BudgetInner {
                    spec,
                    used_cpu: 0,
                    peak_cpu: 0,
                    used_memory: 0,
                    peak_memory: 0,
                    oversubscribed: false,
                    active_sessions: BTreeMap::new(),
                    stages: BTreeMap::new(),
                }),
                wakeup: Condvar::new(),
            }),
        })
    }

    pub fn spec(&self) -> GlobalBudgetSpec {
        self.state.inner.lock().expect("budget lock").spec
    }

    pub fn wakeup(&self) {
        self.state.wakeup.notify_all();
    }

    /// Reject requests exceeding the global budget ceiling rather than waiting indefinitely.
    pub fn validate_request(&self, cpu_permits: usize, memory_bytes: u64) -> MddResult<()> {
        let spec = self.spec();
        if cpu_permits == 0 || memory_bytes == 0 {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "scheduler.budget",
                "task cpu_permits and memory_bytes must be positive",
            ));
        }
        if cpu_permits > spec.total_cpu_permits || memory_bytes > spec.total_memory_bytes {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "scheduler.budget",
                "task request exceeds global CPU or memory budget ceiling",
            )
            .detail("requested_cpu", cpu_permits.to_string())
            .detail("ceiling_cpu", spec.total_cpu_permits.to_string())
            .detail("requested_memory_bytes", memory_bytes.to_string())
            .detail("ceiling_memory_bytes", spec.total_memory_bytes.to_string()));
        }
        Ok(())
    }

    /// Try to acquire CPU + memory permits non-blockingly under lock.
    pub fn try_acquire(
        &self,
        session_id: &str,
        stage: PipelineStage,
        cpu_permits: usize,
        memory_bytes: u64,
    ) -> MddResult<Option<BudgetPermit>> {
        self.validate_request(cpu_permits, memory_bytes)?;
        let mut inner = self.state.inner.lock().expect("budget lock");
        Ok(Self::try_acquire_locked(
            &self.state,
            &mut inner,
            session_id,
            stage,
            cpu_permits,
            memory_bytes,
        ))
    }

    fn can_fit(
        inner: &BudgetInner,
        session_id: &str,
        cpu_permits: usize,
        memory_bytes: u64,
    ) -> bool {
        let session_active = inner.active_sessions.contains_key(session_id);
        let apk_slots_ok =
            session_active || inner.active_sessions.len() < inner.spec.max_concurrent_apks;
        apk_slots_ok
            && inner.used_cpu.saturating_add(cpu_permits) <= inner.spec.total_cpu_permits
            && inner.used_memory.saturating_add(memory_bytes) <= inner.spec.total_memory_bytes
    }

    fn try_acquire_locked(
        state: &Arc<BudgetState>,
        inner: &mut BudgetInner,
        session_id: &str,
        stage: PipelineStage,
        cpu_permits: usize,
        memory_bytes: u64,
    ) -> Option<BudgetPermit> {
        if !Self::can_fit(inner, session_id, cpu_permits, memory_bytes) {
            return None;
        }
        inner.used_cpu += cpu_permits;
        inner.used_memory += memory_bytes;
        inner.peak_cpu = inner.peak_cpu.max(inner.used_cpu);
        inner.peak_memory = inner.peak_memory.max(inner.used_memory);
        if inner.used_cpu > inner.spec.total_cpu_permits
            || inner.used_memory > inner.spec.total_memory_bytes
        {
            inner.oversubscribed = true;
        }
        *inner
            .active_sessions
            .entry(session_id.to_owned())
            .or_insert(0) += 1;
        let sc = inner.stages.entry(stage).or_default();
        sc.cpu += cpu_permits;
        sc.peak_cpu = sc.peak_cpu.max(sc.cpu);
        sc.memory += memory_bytes;
        sc.peak_memory = sc.peak_memory.max(sc.memory);
        Some(BudgetPermit {
            state: Arc::clone(state),
            session_id: session_id.to_owned(),
            stage,
            cpu_permits,
            memory_bytes,
            released: false,
        })
    }

    /// Block until permits fit within the global budget, timeout expires, or `cancelled` fires.
    pub fn acquire_with_wait(
        &self,
        session_id: &str,
        stage: PipelineStage,
        cpu_permits: usize,
        memory_bytes: u64,
        cancelled: &AtomicBool,
        deadline: Option<Instant>,
    ) -> MddResult<BudgetPermit> {
        self.validate_request(cpu_permits, memory_bytes)?;
        let mut inner = self.state.inner.lock().expect("budget lock");
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(MddError::new(
                    ErrorCode::Cancelled,
                    "scheduler.budget",
                    "cancelled while waiting for global scheduler budget",
                ));
            }
            if let Some(permit) = Self::try_acquire_locked(
                &self.state,
                &mut inner,
                session_id,
                stage,
                cpu_permits,
                memory_bytes,
            ) {
                return Ok(permit);
            }
            let wait = match deadline {
                Some(dl) => {
                    let now = Instant::now();
                    if now >= dl {
                        return Err(MddError::new(
                            ErrorCode::DeadlineExceeded,
                            "scheduler.budget",
                            "deadline exceeded while waiting for global scheduler budget",
                        ));
                    }
                    dl.saturating_duration_since(now)
                        .min(Duration::from_millis(25))
                }
                None => Duration::from_millis(25),
            };
            let (guard, _) = self
                .state
                .wakeup
                .wait_timeout(inner, wait)
                .expect("budget lock");
            inner = guard;
        }
    }

    pub fn snapshot(&self) -> BudgetSnapshot {
        let inner = self.state.inner.lock().expect("budget lock");
        let by_stage = inner
            .stages
            .iter()
            .map(|(stage, c)| {
                (
                    stage.as_str().to_owned(),
                    StageUsageSnapshot {
                        cpu_permits: c.cpu,
                        peak_cpu_permits: c.peak_cpu,
                        memory_bytes: DecimalU64(c.memory),
                        peak_memory_bytes: DecimalU64(c.peak_memory),
                    },
                )
            })
            .collect();
        BudgetSnapshot {
            total_cpu_permits: inner.spec.total_cpu_permits,
            used_cpu_permits: inner.used_cpu,
            peak_cpu_permits: inner.peak_cpu,
            total_memory_bytes: DecimalU64(inner.spec.total_memory_bytes),
            used_memory_bytes: DecimalU64(inner.used_memory),
            peak_memory_bytes: DecimalU64(inner.peak_memory),
            active_apks: inner.active_sessions.len(),
            max_concurrent_apks: inner.spec.max_concurrent_apks,
            oversubscription_observed: inner.oversubscribed,
            by_stage,
        }
    }
}

pub struct BudgetPermit {
    state: Arc<BudgetState>,
    session_id: String,
    stage: PipelineStage,
    cpu_permits: usize,
    memory_bytes: u64,
    released: bool,
}

impl BudgetPermit {
    pub fn cpu_permits(&self) -> usize {
        self.cpu_permits
    }

    pub fn memory_bytes(&self) -> u64 {
        self.memory_bytes
    }

    pub fn stage(&self) -> PipelineStage {
        self.stage
    }

    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        if let Ok(mut inner) = self.state.inner.lock() {
            inner.used_cpu = inner.used_cpu.saturating_sub(self.cpu_permits);
            inner.used_memory = inner.used_memory.saturating_sub(self.memory_bytes);
            if let Some(count) = inner.active_sessions.get_mut(&self.session_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    inner.active_sessions.remove(&self.session_id);
                }
            }
            if let Some(sc) = inner.stages.get_mut(&self.stage) {
                sc.cpu = sc.cpu.saturating_sub(self.cpu_permits);
                sc.memory = sc.memory.saturating_sub(self.memory_bytes);
            }
            self.state.wakeup.notify_all();
        }
    }
}

impl Drop for BudgetPermit {
    fn drop(&mut self) {
        self.release_inner();
    }
}
