use super::*;
use mdd_types::ErrorCode;
use std::sync::{Arc, atomic::Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn global_budget_prevents_cpu_and_memory_oversubscription_across_stages() {
    let budget = GlobalSchedulerBudget::new(GlobalBudgetSpec {
        total_cpu_permits: 4,
        total_memory_bytes: 1024,
        max_concurrent_apks: 3,
    })
    .unwrap();

    let mut handles = Vec::new();
    for (idx, stage) in [
        PipelineStage::WorkerExecution,
        PipelineStage::ArchiveDecompression,
        PipelineStage::FactBuild,
        PipelineStage::QueryExecution,
        PipelineStage::FactBuild,
        PipelineStage::QueryExecution,
    ]
    .into_iter()
    .enumerate()
    {
        let b = budget.clone();
        handles.push(thread::spawn(move || {
            let cancel = std::sync::atomic::AtomicBool::new(false);
            let permit = b
                .acquire_with_wait(
                    &format!("apk-{}", idx % 3),
                    stage,
                    2,
                    512,
                    &cancel,
                    Some(Instant::now() + Duration::from_secs(5)),
                )
                .unwrap();
            let snap = b.snapshot();
            assert!(!snap.oversubscription_observed);
            assert!(snap.used_cpu_permits <= 4);
            assert!(snap.used_memory_bytes.0 <= 1024);
            thread::sleep(Duration::from_millis(12));
            permit.release();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let final_snap = budget.snapshot();
    assert_eq!(final_snap.used_cpu_permits, 0);
    assert_eq!(final_snap.used_memory_bytes.0, 0);
    assert!(!final_snap.oversubscription_observed);
    assert!(final_snap.peak_cpu_permits <= 4);
    assert!(final_snap.peak_memory_bytes.0 <= 1024);
}

#[test]
fn scheduler_enforces_queue_bounds_overload_isolation_cancellation_and_worker_lost() {
    let budget = GlobalSchedulerBudget::new(GlobalBudgetSpec {
        total_cpu_permits: 2,
        total_memory_bytes: 1024,
        max_concurrent_apks: 2,
    })
    .unwrap();
    let scheduler = FairApkScheduler::new(
        budget,
        FairQueueConfig {
            max_queued_tasks: 4,
            max_history_entries: 16,
        },
    )
    .unwrap();

    // Healthy APK A holds 1 slot while oversized APK O is rejected loudly without harming A.
    let h_a = scheduler
        .submit(TaskSpec {
            session_id: "apk-a".to_owned(),
            stage: PipelineStage::FactBuild,
            cpu_permits: 1,
            memory_bytes: 512,
            generation: 1,
        })
        .unwrap();
    let lease_a = scheduler.start_task(&h_a, None).unwrap();

    let err_over = scheduler
        .submit(TaskSpec {
            session_id: "apk-oversize".to_owned(),
            stage: PipelineStage::FactBuild,
            cpu_permits: 1,
            memory_bytes: 4096,
            generation: 1,
        })
        .unwrap_err();
    assert_eq!(err_over.code, ErrorCode::QuotaExceeded);
    assert_eq!(
        scheduler.task_status(h_a.task_id()).unwrap().state,
        ScheduledTaskState::Running
    );

    // Queue 4 tasks up to bound; 5th queued task hits bounded queue quota without breaking running task.
    let mut queued = Vec::new();
    for i in 0..4 {
        let h = scheduler
            .submit(TaskSpec {
                session_id: format!("apk-q{i}"),
                stage: PipelineStage::QueryExecution,
                cpu_permits: 1,
                memory_bytes: 128,
                generation: 1,
            })
            .unwrap();
        queued.push(h);
    }
    let queue_full_err = scheduler
        .submit(TaskSpec {
            session_id: "apk-overflow".to_owned(),
            stage: PipelineStage::QueryExecution,
            cpu_permits: 1,
            memory_bytes: 128,
            generation: 1,
        })
        .unwrap_err();
    assert_eq!(queue_full_err.code, ErrorCode::QuotaExceeded);

    // Fast cancellation of a queued task frees its queue slot immediately.
    let cancelled_id = queued[1].task_id();
    assert!(queued[1].cancel("user cancelled"));
    assert_eq!(
        scheduler.task_status(cancelled_id).unwrap().state,
        ScheduledTaskState::Cancelled
    );

    // Fair round-robin allows healthy queued apk-q0 while apk-b suffers isolated WorkerLost.
    let h_lost = scheduler
        .submit(TaskSpec {
            session_id: "apk-lost".to_owned(),
            stage: PipelineStage::WorkerExecution,
            cpu_permits: 1,
            memory_bytes: 128,
            generation: 7,
        })
        .unwrap();
    let lost_count = scheduler.mark_generation_worker_lost("apk-lost", 7, "worker crashed");
    assert_eq!(lost_count, 1);
    assert_eq!(
        scheduler.task_status(h_lost.task_id()).unwrap().state,
        ScheduledTaskState::WorkerLost
    );

    // Running apk-a still finishes cleanly!
    lease_a.complete().unwrap();
    assert_eq!(
        scheduler.task_status(h_a.task_id()).unwrap().state,
        ScheduledTaskState::Completed
    );

    // Cancellation while running aborts cooperatively when lease checks flag / completes with CANCELLED.
    let s2 = Arc::new(scheduler.clone());
    let h_run_cancel = queued[0].clone();
    let t_cancel = thread::spawn({
        let s2 = Arc::clone(&s2);
        let h_run_cancel = h_run_cancel.clone();
        move || {
            let lease = s2
                .start_task(&h_run_cancel, Some(Instant::now() + Duration::from_secs(2)))
                .unwrap();
            let t0 = Instant::now();
            while !lease.cancel_flag().load(Ordering::Acquire)
                && t0.elapsed() < Duration::from_secs(1)
            {
                thread::sleep(Duration::from_millis(2));
            }
            assert!(lease.cancel_flag().load(Ordering::Acquire));
            lease.cancel("cancelled during run");
        }
    });
    thread::sleep(Duration::from_millis(20));
    h_run_cancel.cancel("interrupt running");
    t_cancel.join().unwrap();
    assert_eq!(
        scheduler.task_status(h_run_cancel.task_id()).unwrap().state,
        ScheduledTaskState::Cancelled
    );

    let snap = scheduler.snapshot();
    assert!(snap.queue_depth_bounded);
    assert!(snap.history_bounded);
    assert_eq!(snap.rejected_quota_count, 2);
    assert_eq!(snap.worker_lost_count, 1);
    assert_eq!(snap.completed_count, 1);
}
