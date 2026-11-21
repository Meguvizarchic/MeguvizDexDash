//! Real multi-worker process crash isolation, recovery re-verification, and half-frame IPC probe.

use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
use mdd_session::{Lifecycle, QueryBinding, QueryPhase, ResourceLimits};
use mdd_types::ErrorCode;
use mdd_wire::{
    Cell, ChannelKind, Column, ColumnType, Credit, FrameKind, FrameReader, FrameWriter, Header,
    Hello, ProducerStream, Schema, StreamLimits,
};
use mdd_worker::lifecycle::Supervisor;
use mdd_worker::protocol::{ClientConfig, ServeConfig, run_child, serve_rows};
use serde_json::json;
use std::env;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::Duration;

fn schema() -> Schema {
    Schema {
        schema_id: "mdd.rows.v1:fault".to_owned(),
        columns: vec![
            Column {
                ordinal: 0,
                stable_id: "seq".to_owned(),
                name: "seq".to_owned(),
                ty: ColumnType::I64,
                nullable: false,
            },
            Column {
                ordinal: 1,
                stable_id: "tag".to_owned(),
                name: "tag".to_owned(),
                ty: ColumnType::Utf8,
                nullable: false,
            },
        ],
    }
}

fn child_main(mode: &str) -> ! {
    let hello = Hello::v1(1 << 20);
    match mode {
        "worker-crash-exit" => {
            // Simulate an active worker that crashes abruptly without finishing or writing a terminal.
            let _ = std::io::stdout().write_all(b"partial-unframed-before-crash");
            let _ = std::io::stdout().flush();
            std::process::exit(137);
        }
        "worker-ok" => {
            let mut next = 0i64;
            let end = serve_rows(
                std::io::stdin(),
                std::io::stdout(),
                ServeConfig {
                    hello,
                    schema: schema(),
                    limits: StreamLimits::default(),
                    batch_rows: 4,
                    credit_wait: Duration::from_secs(5),
                },
                || {
                    if next < 6 {
                        next += 1;
                        Some(Ok(vec![Cell::I64(next), Cell::Utf8(format!("ok-{next}"))]))
                    } else {
                        None
                    }
                },
                |_| {},
            );
            std::process::exit(i32::from(end.is_err()));
        }
        "half-frame-header" => {
            // Write only 12 bytes of the 32-byte mdd-wire/1 header and exit immediately.
            let _ = std::io::stdout().write_all(&b"MDDW1\0\0\0\x00\x00\x00\x01"[..]);
            let _ = std::io::stdout().flush();
            std::process::exit(0);
        }
        "half-frame-body" => {
            let mut writer =
                FrameWriter::new(std::io::stdout(), ChannelKind::Dedicated, 1 << 20).unwrap();
            writer
                .write_frame(
                    FrameKind::Hello,
                    0,
                    &serde_json::to_vec(&hello.to_json()).unwrap(),
                )
                .unwrap();
            let mut reader = FrameReader::new(std::io::stdin());
            reader.read_frame(1 << 20).unwrap().unwrap(); // peer Hello
            reader.read_frame(1 << 20).unwrap().unwrap(); // Request
            let mut producer = ProducerStream::new(1, StreamLimits::default()).unwrap();
            writer
                .write_frame(FrameKind::Schema, 1, &producer.schema(schema()).unwrap())
                .unwrap();
            let body = producer
                .batch(&[vec![Cell::I64(1), Cell::Utf8("truncated-row".to_owned())]])
                .unwrap();
            let header = Header::new(FrameKind::Batch, 1, body.len() as u64).encode();
            let mut out = std::io::stdout();
            let _ = out.write_all(&header);
            let _ = out.write_all(&body[..body.len() / 2]);
            let _ = out.flush();
            std::process::exit(0);
        }
        _ => std::process::exit(2),
    }
}

fn spawn_child_cmd(mode: &str) -> Command {
    let exe = env::current_exe().unwrap();
    let mut cmd = Command::new(exe);
    cmd.env("MDD_FAULT_CHILD", mode);
    cmd
}

fn run_wire_ok(req_key: &str) -> Result<u64, String> {
    let outcome = run_child(
        spawn_child_cmd("worker-ok"),
        req_key.as_bytes(),
        ClientConfig {
            hello: Hello::v1(1 << 20),
            limits: StreamLimits::default(),
            queue_frames: 4,
            initial_credit: Credit {
                batches: 4,
                bytes: 1 << 20,
            },
            deadline: Duration::from_secs(10),
            exit_grace: Duration::from_secs(5),
            cancel: Arc::new(AtomicBool::new(false)),
            on_batch: None,
        },
    );
    if outcome.detached_threads != 0 {
        return Err(format!("detached_threads={}", outcome.detached_threads));
    }
    match outcome.result {
        Ok(done) => Ok(done.rows.len() as u64),
        Err(fail) => Err(format!("{:?}: {}", fail.error.kind, fail.error.message)),
    }
}

fn cmd_multi_worker_crash(input_path: PathBuf) -> Result<serde_json::Value, String> {
    let kind =
        InputKind::detect(&input_path).map_err(|e| format!("{:?}: {}", e.code, e.message))?;
    let snapshot = Snapshot::capture(
        &[InputSpec {
            path: input_path.clone(),
            kind,
            expected_sha256: None,
        }],
        CaptureLimits::default(),
    )
    .map_err(|e| format!("{:?}: {}", e.code, e.message))?;
    let captured_sha = snapshot.sources()[0]
        .identity()
        .content_id
        .strip_prefix("sha256:")
        .unwrap_or_default()
        .to_owned();
    let snap_arc = Arc::new(snapshot);

    // Worker 1 lifecycle holds 3 active in-flight queries on a dying worker process.
    let limits = ResourceLimits {
        max_queries: 16,
        max_threads: 8,
        deadline_ms: 10_000,
        ..ResourceLimits::default()
    };
    let lc_w1 = Lifecycle::new(limits).map_err(|e| e.message)?;
    let sh_w1 = lc_w1
        .register_snapshot(Arc::clone(&snap_arc))
        .map_err(|e| e.message)?;
    let sess_w1 = lc_w1.open_session(&sh_w1, limits).map_err(|e| e.message)?;
    let mut w1_queries = Vec::new();
    for tag in ["q1_a", "q1_b", "q1_c"] {
        let qh = lc_w1
            .prepare_query(
                &sess_w1,
                QueryBinding {
                    request_key: tag.to_owned(),
                    schema_id: "mdd.rows.v1:fault".to_owned(),
                    semantic_version: "1".to_owned(),
                },
                limits,
            )
            .map_err(|e| e.message)?;
        lc_w1.start_query(&sess_w1, &qh, 1).map_err(|e| e.message)?;
        w1_queries.push(qh);
    }

    // Worker 2 is an isolated separate supervisor & lifecycle with 2 concurrent queries completing cleanly.
    let lc_w2 = Lifecycle::new(limits).map_err(|e| e.message)?;
    let sh_w2 = lc_w2
        .register_snapshot(Arc::clone(&snap_arc))
        .map_err(|e| e.message)?;
    let sess_w2 = lc_w2.open_session(&sh_w2, limits).map_err(|e| e.message)?;
    let w2_thread = thread::spawn(move || -> Result<usize, String> {
        let mut ok_count = 0usize;
        for tag in ["q2_a", "q2_b"] {
            let qh = lc_w2
                .prepare_query(
                    &sess_w2,
                    QueryBinding {
                        request_key: tag.to_owned(),
                        schema_id: "mdd.rows.v1:fault".to_owned(),
                        semantic_version: "1".to_owned(),
                    },
                    limits,
                )
                .map_err(|e| e.message)?;
            lc_w2.start_query(&sess_w2, &qh, 1).map_err(|e| e.message)?;
            let rows = run_wire_ok(tag)?;
            if rows != 6 {
                return Err(format!("worker 2 query {tag} got {rows} rows"));
            }
            lc_w2.complete_execution(&qh).map_err(|e| e.message)?;
            lc_w2.finish_delivery(&qh).map_err(|e| e.message)?;
            if lc_w2.query_status(&qh).map_err(|e| e.message)?.phase == QueryPhase::Completed {
                ok_count += 1;
            }
        }
        Ok(ok_count)
    });

    // Spawn Worker 1 which crashes abruptly while holding all 3 queries on lc_w1.
    let mut sup_w1 = Supervisor::spawn(spawn_child_cmd("worker-crash-exit"), lc_w1.clone())
        .map_err(|e| format!("{:?}: {}", e.code, e.message))?;
    let term_w1 = sup_w1
        .wait_for_termination(Duration::from_secs(10))
        .map_err(|e| format!("{:?}: {}", e.code, e.message))?;
    drop(sup_w1);

    let w2_completed = w2_thread
        .join()
        .map_err(|_| "w2 thread panicked".to_owned())??;

    // Verify EVERY in-flight request on Worker 1 became WORKER_LOST (never claiming single-query loss).
    let w1_failed_ids: Vec<String> = term_w1
        .affected_requests
        .iter()
        .filter(|f| f.error.code == ErrorCode::WorkerLost)
        .map(|f| f.query_id.clone())
        .collect();
    for qh in &w1_queries {
        let st = lc_w1.query_status(qh).map_err(|e| e.message)?;
        if st.phase != QueryPhase::Failed
            || st.error.as_ref().map(|e| e.code) != Some(ErrorCode::WorkerLost)
        {
            return Err(format!(
                "w1 query {} did not enter WORKER_LOST: {st:?}",
                qh.id()
            ));
        }
    }

    // Recovery on fresh Worker 3 after re-verifying source SHA-256 identity.
    let recovery_snap = Snapshot::capture(
        &[InputSpec {
            path: input_path,
            kind,
            expected_sha256: Some(captured_sha.clone()),
        }],
        CaptureLimits::default(),
    )
    .map_err(|e| format!("recovery capture mismatch: {:?}: {}", e.code, e.message))?;
    let lc_w3 = Lifecycle::new(limits).map_err(|e| e.message)?;
    let sh_w3 = lc_w3
        .register_snapshot(Arc::new(recovery_snap))
        .map_err(|e| e.message)?;
    let sess_w3 = lc_w3.open_session(&sh_w3, limits).map_err(|e| e.message)?;
    let mut w3_recovered = 0usize;
    for tag in ["q1_a", "q1_b", "q1_c"] {
        let qh = lc_w3
            .prepare_query(
                &sess_w3,
                QueryBinding {
                    request_key: tag.to_owned(),
                    schema_id: "mdd.rows.v1:fault".to_owned(),
                    semantic_version: "1".to_owned(),
                },
                limits,
            )
            .map_err(|e| e.message)?;
        lc_w3.start_query(&sess_w3, &qh, 1).map_err(|e| e.message)?;
        let rows = run_wire_ok(tag)?;
        if rows != 6 {
            return Err(format!("recovery {tag} returned {rows} rows"));
        }
        lc_w3.complete_execution(&qh).map_err(|e| e.message)?;
        lc_w3.finish_delivery(&qh).map_err(|e| e.message)?;
        w3_recovered += 1;
    }

    Ok(json!({
        "ok": true,
        "worker1_cause": term_w1.cause,
        "worker1_error_code": term_w1.error.code.to_string(),
        "worker1_direct_child_reaped": term_w1.direct_child_reaped,
        "worker1_affected_request_count": w1_failed_ids.len(),
        "worker1_expected_affected_count": w1_queries.len(),
        "worker2_isolated_completed_count": w2_completed,
        "worker3_recovered_count": w3_recovered,
        "recovery_verified_content_sha256": captured_sha,
    }))
}

fn cmd_half_frame() -> Result<serde_json::Value, String> {
    let mut results = Vec::new();
    for mode in ["half-frame-header", "half-frame-body"] {
        let outcome = run_child(
            spawn_child_cmd(mode),
            b"probe",
            ClientConfig {
                hello: Hello::v1(1 << 20),
                limits: StreamLimits::default(),
                queue_frames: 2,
                initial_credit: Credit {
                    batches: 2,
                    bytes: 1 << 20,
                },
                deadline: Duration::from_secs(5),
                exit_grace: Duration::from_secs(5),
                cancel: Arc::new(AtomicBool::new(false)),
                on_batch: None,
            },
        );
        match outcome.result {
            Ok(done) => {
                return Err(format!(
                    "{mode} unexpectedly completed with {} rows instead of failing on half-frame",
                    done.rows.len()
                ));
            }
            Err(fail) => {
                results.push(json!({
                    "mode": mode,
                    "error_kind": format!("{:?}", fail.error.kind),
                    "message": fail.error.message,
                    "detached_threads": outcome.detached_threads,
                }));
            }
        }
    }
    Ok(json!({
        "ok": true,
        "cases": results,
    }))
}

fn cmd_session_and_catalog_faults(input_path: PathBuf) -> Result<serde_json::Value, String> {
    let kind = InputKind::detect(&input_path).map_err(|e| e.message)?;
    let snapshot = Snapshot::capture(
        &[InputSpec {
            path: input_path,
            kind,
            expected_sha256: None,
        }],
        CaptureLimits::default(),
    )
    .map_err(|e| e.message)?;
    let snap_arc = Arc::new(snapshot);
    let limits = ResourceLimits::default();
    let lc = Lifecycle::new(limits).map_err(|e| e.message)?;
    let sh = lc.register_snapshot(snap_arc).map_err(|e| e.message)?;
    let sess = lc.open_session(&sh, limits).map_err(|e| e.message)?;

    let binding = QueryBinding {
        request_key: "epoch-probe".to_owned(),
        schema_id: "mdd.rows.v1:fault".to_owned(),
        semantic_version: "1".to_owned(),
    };
    let q0 = lc
        .prepare_query(&sess, binding.clone(), limits)
        .map_err(|e| e.message)?;
    lc.start_query(&sess, &q0, 1).map_err(|e| e.message)?;
    let c0 = lc.open_cursor(&sess, &q0).map_err(|e| e.message)?;
    let e0 = lc.validate_cursor(&sess, &q0, &c0).map_err(|e| e.message)?;
    if e0 != 0 {
        return Err(format!("expected epoch 0, got {e0}"));
    }

    // Advance TEMP catalog generation epoch 0 -> 1.
    let e1 = lc.advance_catalog(&sess).map_err(|e| e.message)?;
    let q1 = lc
        .prepare_query(&sess, binding, limits)
        .map_err(|e| e.message)?;
    lc.start_query(&sess, &q1, 1).map_err(|e| e.message)?;

    // Stale cross-epoch cursor validation must fail with INVALID_CURSOR.
    let cross_epoch_err = lc
        .validate_cursor(&sess, &q1, &c0)
        .err()
        .ok_or_else(|| "stale epoch 0 cursor unexpectedly validated against epoch 1".to_owned())?;
    let c1 = lc.open_cursor(&sess, &q1).map_err(|e| e.message)?;
    let valid_e1 = lc.validate_cursor(&sess, &q1, &c1).map_err(|e| e.message)?;

    let _ = lc.finish_cursor(&sess, &q1, &c1);
    let _ = lc.close_cursor(&c0);
    let _ = lc.cancel_query(&q0);
    let _ = lc.complete_execution(&q1);
    let _ = lc.finish_delivery(&q1);

    // Close session and snapshot, then probe stale handles.
    lc.close_session(&sess).map_err(|e| e.message)?;
    let closed_session_err = lc
        .open_cursor(&sess, &q1)
        .err()
        .ok_or_else(|| "closed session allowed handle reuse".to_owned())?;
    lc.close_snapshot(&sh).map_err(|e| e.message)?;
    let closed_snap_err = lc
        .open_session(&sh, limits)
        .err()
        .ok_or_else(|| "closed snapshot allowed session creation".to_owned())?;

    Ok(json!({
        "ok": true,
        "epoch_before": e0,
        "epoch_after": e1,
        "recovered_cursor_epoch": valid_e1,
        "cross_epoch_cursor_error": cross_epoch_err.code.to_string(),
        "closed_session_error": closed_session_err.code.to_string(),
        "closed_snapshot_error": closed_snap_err.code.to_string(),
    }))
}

fn main() -> ExitCode {
    if let Ok(child_mode) = env::var("MDD_FAULT_CHILD") {
        child_main(&child_mode);
    }
    let args: Vec<String> = env::args().skip(1).collect();
    let res = match args.first().map(String::as_str) {
        Some("multi-worker-crash") => {
            let input = args
                .windows(2)
                .find(|w| w[0] == "--input")
                .map(|w| PathBuf::from(&w[1]))
                .ok_or_else(|| "missing --input".to_owned());
            input.and_then(cmd_multi_worker_crash)
        }
        Some("half-frame") => cmd_half_frame(),
        Some("session-and-catalog-faults") => {
            let input = args
                .windows(2)
                .find(|w| w[0] == "--input")
                .map(|w| PathBuf::from(&w[1]))
                .ok_or_else(|| "missing --input".to_owned());
            input.and_then(cmd_session_and_catalog_faults)
        }
        _ => Err(
            "usage: fault_supervisor_probe <multi-worker-crash --input PATH | half-frame | session-and-catalog-faults --input PATH>"
                .to_owned(),
        ),
    };
    match res {
        Ok(val) => {
            println!("{}", serde_json::to_string(&val).unwrap());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!(
                "{}",
                serde_json::to_string(&json!({"ok": false, "error": err})).unwrap()
            );
            ExitCode::FAILURE
        }
    }
}
