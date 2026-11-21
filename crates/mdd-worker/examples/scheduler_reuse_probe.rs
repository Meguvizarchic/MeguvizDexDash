//! Real multi-concurrency (1/2/4 APKs), global budget, overload, cancellation, and WorkerLost isolation probe (MDD-064).

use mdd_input::archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy};
use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
use mdd_worker::scheduler::{
    FairApkScheduler, FairQueueConfig, GlobalBudgetSpec, GlobalSchedulerBudget, PipelineStage,
    ScheduledTaskState, TaskSpec,
};
use serde_json::{Value, json};
use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

fn run_real_apk_work(
    scheduler: &FairApkScheduler,
    session_id: &str,
    apk_path: &Path,
    cpu_per_task: usize,
    mem_bytes: u64,
    generation: u64,
) -> Result<(usize, u64, u64), String> {
    let h_decomp = scheduler
        .submit(TaskSpec {
            session_id: session_id.to_owned(),
            stage: PipelineStage::ArchiveDecompression,
            cpu_permits: cpu_per_task,
            memory_bytes: mem_bytes,
            generation,
        })
        .map_err(|e| format!("{}:{:?}", e.message, e.code))?;
    let lease_decomp = scheduler
        .start_task(&h_decomp, Some(Instant::now() + Duration::from_secs(15)))
        .map_err(|e| e.message)?;
    let snapshot = Snapshot::capture(
        &[InputSpec {
            path: apk_path.to_path_buf(),
            kind: InputKind::Apk,
            expected_sha256: None,
        }],
        CaptureLimits::default(),
    )
    .map_err(|e| e.message)?;
    let inv = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )
    .map_err(|e| e.message)?;
    let dex_count = inv.selected_dexes().len();
    let total_dex_bytes: u64 = inv
        .selected_dexes()
        .iter()
        .map(|d| d.blob.len() as u64)
        .sum();
    for entry in inv.selected_dexes() {
        let bytes = entry.blob.try_lease().map_err(|e| e.message)?;
        let _ = bytes.len();
        drop(bytes);
        entry.blob.release();
    }
    lease_decomp.complete().map_err(|e| e.message)?;

    let h_facts = scheduler
        .submit(TaskSpec {
            session_id: session_id.to_owned(),
            stage: PipelineStage::FactBuild,
            cpu_permits: cpu_per_task,
            memory_bytes: mem_bytes,
            generation,
        })
        .map_err(|e| e.message)?;
    let lease_facts = scheduler
        .start_task(&h_facts, Some(Instant::now() + Duration::from_secs(15)))
        .map_err(|e| e.message)?;
    thread::sleep(Duration::from_millis(8));
    lease_facts.complete().map_err(|e| e.message)?;

    Ok((dex_count, total_dex_bytes, 1))
}

fn measure_concurrency(apk_path: &Path, concurrency: usize) -> Result<Value, String> {
    let ceiling_cpu = 4usize;
    let ceiling_mem = 64u64 * 1024 * 1024;
    let budget = GlobalSchedulerBudget::new(GlobalBudgetSpec {
        total_cpu_permits: ceiling_cpu,
        total_memory_bytes: ceiling_mem,
        max_concurrent_apks: 4,
    })
    .map_err(|e| e.message)?;
    let scheduler = FairApkScheduler::new(
        budget,
        FairQueueConfig {
            max_queued_tasks: 32,
            max_history_entries: 128,
        },
    )
    .map_err(|e| e.message)?;

    let tasks_total = concurrency * 2;
    let t0 = Instant::now();
    let mut latencies_ms = Vec::new();
    let mut threads = Vec::new();
    for i in 0..tasks_total {
        let sched = scheduler.clone();
        let apk = apk_path.to_path_buf();
        threads.push(thread::spawn(move || {
            let task_t0 = Instant::now();
            let sid = format!("apk-{}-slot-{}", concurrency, i % concurrency);
            let res = run_real_apk_work(&sched, &sid, &apk, 1, 16 * 1024 * 1024, 1);
            res.map(|(dexes, bytes, _)| (task_t0.elapsed().as_secs_f64() * 1000.0, dexes, bytes))
        }));
    }
    let mut sum_dexes = 0usize;
    for th in threads {
        let (ms, dexes, _) = th.join().map_err(|_| "worker panicked".to_owned())??;
        latencies_ms.push(ms);
        sum_dexes += dexes;
    }
    let wall_ms = t0.elapsed().as_secs_f64() * 1000.0;
    latencies_ms.sort_by(f64::total_cmp);
    let tail_ms = *latencies_ms.last().unwrap_or(&0.0);
    let snap = scheduler.snapshot();
    if snap.budget.oversubscription_observed
        || snap.budget.peak_cpu_permits > ceiling_cpu
        || snap.budget.peak_memory_bytes.0 > ceiling_mem
    {
        return Err("global budget ceiling violated under concurrency".to_owned());
    }
    Ok(json!({
        "concurrency": concurrency,
        "tasks_completed": tasks_total,
        "dex_units_processed": sum_dexes,
        "wall_ms": wall_ms,
        "tail_latency_ms": tail_ms,
        "throughput_tasks_per_sec": (tasks_total as f64) / (wall_ms / 1000.0).max(1e-6),
        "peak_cpu_permits": snap.budget.peak_cpu_permits,
        "ceiling_cpu_permits": snap.budget.total_cpu_permits,
        "peak_memory_bytes": snap.budget.peak_memory_bytes.0.to_string(),
        "ceiling_memory_bytes": snap.budget.total_memory_bytes.0.to_string(),
        "oversubscription_observed": snap.budget.oversubscription_observed,
        "queue_depth_bounded": snap.queue_depth_bounded,
        "history_bounded": snap.history_bounded,
    }))
}

fn measure_overload_cancel_worker_lost(apk_path: &Path) -> Result<Value, String> {
    let budget = GlobalSchedulerBudget::new(GlobalBudgetSpec {
        total_cpu_permits: 2,
        total_memory_bytes: 32 * 1024 * 1024,
        max_concurrent_apks: 2,
    })
    .map_err(|e| e.message)?;
    let scheduler = FairApkScheduler::new(
        budget,
        FairQueueConfig {
            max_queued_tasks: 4,
            max_history_entries: 64,
        },
    )
    .map_err(|e| e.message)?;

    // 1) Overload request fails closed without affecting concurrent healthy APK work.
    let overloaded_code = scheduler
        .submit(TaskSpec {
            session_id: "apk-overload".to_owned(),
            stage: PipelineStage::FactBuild,
            cpu_permits: 1,
            memory_bytes: 128 * 1024 * 1024,
            generation: 1,
        })
        .unwrap_err()
        .code;
    let healthy_after_overload =
        run_real_apk_work(&scheduler, "apk-healthy", apk_path, 1, 8 * 1024 * 1024, 1)?;

    // 2) Fast cooperative cancellation latency while holding 2 permits cleanly releases budget.
    let h_run = scheduler
        .submit(TaskSpec {
            session_id: "apk-cancel".to_owned(),
            stage: PipelineStage::QueryExecution,
            cpu_permits: 2,
            memory_bytes: 16 * 1024 * 1024,
            generation: 1,
        })
        .map_err(|e| e.message)?;
    let sched_c = scheduler.clone();
    let h_wait = h_run.clone();
    let runner = thread::spawn(move || {
        let lease = sched_c
            .start_task(&h_wait, Some(Instant::now() + Duration::from_secs(5)))
            .unwrap();
        let t_loop = Instant::now();
        while !lease.cancel_flag().load(Ordering::Acquire)
            && t_loop.elapsed() < Duration::from_secs(2)
        {
            thread::sleep(Duration::from_millis(1));
        }
        lease.cancel("probe cancel requested");
    });
    thread::sleep(Duration::from_millis(10));
    let cancel_t0 = Instant::now();
    h_run.cancel("probe cancel");
    runner
        .join()
        .map_err(|_| "cancel runner panicked".to_owned())?;
    let cancel_ms = cancel_t0.elapsed().as_secs_f64() * 1000.0;

    // 3) WorkerLost isolated to victim generation while sibling session finishes cleanly.
    let h_victim = scheduler
        .submit(TaskSpec {
            session_id: "apk-victim".to_owned(),
            stage: PipelineStage::WorkerExecution,
            cpu_permits: 1,
            memory_bytes: 8 * 1024 * 1024,
            generation: 99,
        })
        .map_err(|e| e.message)?;
    let victim_lost =
        scheduler.mark_generation_worker_lost("apk-victim", 99, "simulated worker crash");
    let healthy_after_lost =
        run_real_apk_work(&scheduler, "apk-sibling", apk_path, 1, 8 * 1024 * 1024, 2)?;

    let snap = scheduler.snapshot();
    if scheduler.task_status(h_run.task_id()).unwrap().state != ScheduledTaskState::Cancelled
        || scheduler.task_status(h_victim.task_id()).unwrap().state
            != ScheduledTaskState::WorkerLost
    {
        return Err("terminal task states did not match expectations".to_owned());
    }
    Ok(json!({
        "overload_rejected_code": format!("{overloaded_code:?}"),
        "healthy_after_overload_dexes": healthy_after_overload.0,
        "cancel_response_ms": cancel_ms,
        "victim_worker_lost_count": victim_lost,
        "healthy_after_worker_lost_dexes": healthy_after_lost.0,
        "final_used_cpu_permits": snap.budget.used_cpu_permits,
        "final_used_memory_bytes": snap.budget.used_memory_bytes.0.to_string(),
        "queue_depth_bounded": snap.queue_depth_bounded,
        "history_bounded": snap.history_bounded,
    }))
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: scheduler_reuse_probe <apk_path>");
        return ExitCode::FAILURE;
    }
    let apk_path = PathBuf::from(&args[0]);
    let mut levels = Vec::new();
    for conc in [1usize, 2usize, 4usize] {
        match measure_concurrency(&apk_path, conc) {
            Ok(v) => levels.push(v),
            Err(e) => {
                eprintln!("{}", json!({"ok": false, "error": e}));
                return ExitCode::FAILURE;
            }
        }
    }
    let isolation = match measure_overload_cancel_worker_lost(&apk_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{}", json!({"ok": false, "error": e}));
            return ExitCode::FAILURE;
        }
    };
    println!(
        "{}",
        json!({
            "ok": true,
            "concurrency_levels": levels,
            "isolation": isolation,
        })
    );
    ExitCode::SUCCESS
}
