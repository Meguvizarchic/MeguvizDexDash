//! Unified global CPU/memory budget and fair bounded APK task scheduler (MDD-064).

pub mod budget;
pub mod queue;

#[cfg(test)]
mod tests;

pub use budget::{
    BudgetPermit, BudgetSnapshot, GlobalBudgetSpec, GlobalSchedulerBudget, PipelineStage,
    StageUsageSnapshot,
};
pub use queue::{
    FairApkScheduler, FairQueueConfig, ScheduledTaskHandle, ScheduledTaskState, SchedulerSnapshot,
    TaskSpec, TaskStatusSnapshot,
};
