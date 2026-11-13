//! `mdd-wire/1` against a real child process.
//!
//! This test has its own `main` (no libtest) because the child must write nothing
//! but frames to its stdout, and libtest prints to stdout. The same executable is
//! the parent (no `MDD_WIRE_CHILD`) and the worker (`MDD_WIRE_CHILD=<mode>`).
use mdd_types::{ErrorCode, MddError};
use mdd_wire::{
    Cell, ChannelKind, Column, ColumnType, Credit, FrameKind, FrameReader, FrameWriter, Hello,
    ProducerStream, Schema, StreamLimits, WireErrorKind,
};
use mdd_worker::protocol::{ClientConfig, ClientOutcome, ServeConfig, run_child, serve_rows};
use std::io::Write;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Frames the client's bounded queue holds; the reader thread may hold one more.
const QUEUE: usize = 2;

fn schema() -> Schema {
    let column = |ordinal, id: &str, ty, nullable| Column {
        ordinal,
        stable_id: id.to_owned(),
        name: id.to_owned(),
        ty,
        nullable,
    };
    Schema {
        schema_id: "mdd.rows.v1:child".to_owned(),
        columns: vec![
            column(0, "id", ColumnType::I64, false),
            column(1, "txt", ColumnType::Utf8, true),
        ],
    }
}

fn row(id: i64, pad: usize) -> Vec<Cell> {
    vec![
        Cell::I64(id),
        if id % 5 == 0 {
            Cell::Null
        } else {
            Cell::Utf8("x".repeat(pad))
        },
    ]
}

// ---------------------------------------------------------------------------
// Child side
// ---------------------------------------------------------------------------

fn child(mode: &str) -> ! {
    let hello = Hello::v1(1 << 20);
    let rows_of = |count: i64, pad: usize| {
        let mut next = 0;
        move || {
            (next < count).then(|| {
                next += 1;
                Ok(row(next, pad))
            })
        }
    };
    match mode {
        "complete" => {
            let end = serve_rows(
                std::io::stdin(),
                std::io::stdout(),
                ServeConfig {
                    hello,
                    schema: schema(),
                    limits: StreamLimits::default(),
                    batch_rows: 8,
                    credit_wait: Duration::from_secs(10),
                },
                rows_of(50, 6),
                |_| {},
            );
            std::process::exit(i32::from(end.is_err()));
        }
        "big" | "big_stalled_consumer" => {
            // 40 KB rows, one per batch: each batch is a visible unit of progress.
            let end = serve_rows(
                std::io::stdin(),
                std::io::stdout(),
                ServeConfig {
                    hello,
                    schema: schema(),
                    limits: StreamLimits::default(),
                    batch_rows: 1,
                    credit_wait: Duration::from_secs(10),
                },
                rows_of(300, 40_000),
                |sent| eprintln!("sent {sent}"),
            );
            std::process::exit(i32::from(end.is_err()));
        }
        "wide" => {
            // 300 KB rows, eight per batch: one batch cannot fit the 1 MiB frame.
            let end = serve_rows(
                std::io::stdin(),
                std::io::stdout(),
                ServeConfig {
                    hello,
                    schema: schema(),
                    limits: StreamLimits::default(),
                    batch_rows: 8,
                    credit_wait: Duration::from_secs(10),
                },
                rows_of(20, 300_000),
                |_| {},
            );
            std::process::exit(i32::from(end.is_err()));
        }
        "cell_limit" => {
            let end = serve_rows(
                std::io::stdin(),
                std::io::stdout(),
                ServeConfig {
                    hello,
                    schema: schema(),
                    limits: StreamLimits {
                        max_cell_bytes: 10,
                        ..StreamLimits::default()
                    },
                    batch_rows: 4,
                    credit_wait: Duration::from_secs(10),
                },
                rows_of(10, 100),
                |_| {},
            );
            std::process::exit(i32::from(end.is_err()));
        }
        "deaf" => {
            // Says Hello and then never reads stdin again.
            let mut writer =
                FrameWriter::new(std::io::stdout(), ChannelKind::Dedicated, 1 << 20).unwrap();
            writer
                .write_frame(
                    FrameKind::Hello,
                    0,
                    &serde_json::to_vec(&hello.to_json()).unwrap(),
                )
                .unwrap();
            std::thread::sleep(Duration::from_secs(60));
            std::process::exit(0);
        }
        "source_error" => {
            let mut next = 0;
            let end = serve_rows(
                std::io::stdin(),
                std::io::stdout(),
                ServeConfig {
                    hello,
                    schema: schema(),
                    limits: StreamLimits::default(),
                    batch_rows: 8,
                    credit_wait: Duration::from_secs(10),
                },
                move || {
                    next += 1;
                    if next <= 20 {
                        Some(Ok(row(next, 4)))
                    } else {
                        Some(Err(MddError::new(
                            ErrorCode::QuotaExceeded,
                            "budget",
                            "row budget exhausted",
                        )
                        .detail("budget", "max_rows")))
                    }
                },
                |_| {},
            );
            std::process::exit(i32::from(end.is_err()));
        }
        "bad_hello" => {
            let mut writer =
                FrameWriter::new(std::io::stdout(), ChannelKind::Dedicated, 1 << 20).unwrap();
            writer
                .write_frame(
                    FrameKind::Hello,
                    0,
                    &serde_json::to_vec(&Hello::v1(512).to_json()).unwrap(),
                )
                .unwrap();
            std::thread::sleep(Duration::from_secs(30));
            std::process::exit(0);
        }
        "garbage" => {
            let mut out = std::io::stdout();
            out.write_all(b"starting worker, please wait...\n").unwrap();
            out.flush().unwrap();
            std::thread::sleep(Duration::from_secs(30));
            std::process::exit(0);
        }
        _ => raw(mode, hello),
    }
}

/// Modes that need to misbehave in ways `serve_rows` never would.
fn raw(mode: &str, hello: Hello) -> ! {
    let mut writer = FrameWriter::new(std::io::stdout(), ChannelKind::Dedicated, 1 << 20).unwrap();
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
    let batch = |producer: &mut ProducerStream, from: i64, to: i64| {
        let rows: Vec<Vec<Cell>> = (from..to).map(|i| row(i, 3)).collect();
        producer.batch(&rows).unwrap()
    };
    match mode {
        "no_end" => {
            writer
                .write_frame(FrameKind::Batch, 1, &batch(&mut producer, 1, 4))
                .unwrap();
            std::process::exit(0);
        }
        "exit_nonzero" => {
            writer
                .write_frame(FrameKind::Batch, 1, &batch(&mut producer, 1, 4))
                .unwrap();
            std::process::exit(23);
        }
        "truncated" => {
            let body = batch(&mut producer, 1, 4);
            let header = mdd_wire::Header::new(FrameKind::Batch, 1, body.len() as u64).encode();
            let mut out = std::io::stdout();
            out.write_all(&header).unwrap();
            out.write_all(&body[..body.len() / 2]).unwrap();
            out.flush().unwrap();
            std::process::exit(0);
        }
        "duplicate_end" | "batch_after_end" => {
            writer
                .write_frame(FrameKind::Batch, 1, &batch(&mut producer, 1, 4))
                .unwrap();
            let end = producer.end().unwrap();
            writer.write_frame(FrameKind::End, 1, &end).unwrap();
            if mode == "duplicate_end" {
                writer.write_frame(FrameKind::End, 1, &end).unwrap();
            } else {
                let stray = serde_json::to_vec(&serde_json::json!({
                    "schema_id": "mdd.rows.v1:child", "sequence": "1", "row_count": "0", "rows": []
                }))
                .unwrap();
                writer.write_frame(FrameKind::Batch, 1, &stray).unwrap();
            }
            std::process::exit(0);
        }
        "cancel_only" => {
            // Sends one batch, then ignores end of input and leaves only on a
            // Cancel frame, so a client that merely closes stdin cannot stop it.
            writer
                .write_frame(FrameKind::Batch, 1, &batch(&mut producer, 1, 4))
                .unwrap();
            loop {
                match reader.read_frame(1 << 20) {
                    Ok(Some(frame)) if frame.header.kind == FrameKind::Cancel => {
                        std::process::exit(0)
                    }
                    Ok(Some(_)) => {}
                    _ => std::thread::sleep(Duration::from_millis(50)),
                }
            }
        }
        "stall" => {
            writer
                .write_frame(FrameKind::Batch, 1, &batch(&mut producer, 1, 4))
                .unwrap();
            std::thread::sleep(Duration::from_secs(60));
            std::process::exit(0);
        }
        other => panic!("unknown child mode {other}"),
    }
}

// ---------------------------------------------------------------------------
// Parent side
// ---------------------------------------------------------------------------

fn config(deadline: Duration) -> ClientConfig {
    ClientConfig {
        hello: Hello::v1(1 << 20),
        limits: StreamLimits::default(),
        queue_frames: QUEUE,
        initial_credit: Credit {
            bytes: 1 << 20,
            batches: 4,
        },
        deadline,
        exit_grace: Duration::from_secs(5),
        cancel: Arc::new(AtomicBool::new(false)),
        on_batch: None,
    }
}

fn run(mode: &str, config: ClientConfig) -> ClientOutcome {
    run_with_body(mode, br#"{"op":"query"}"#, config)
}

fn run_with_body(mode: &str, body: &[u8], config: ClientConfig) -> ClientOutcome {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.env("MDD_WIRE_CHILD", mode);
    run_child(command, body, config)
}

fn failure_kind(outcome: &ClientOutcome) -> WireErrorKind {
    outcome
        .result
        .as_ref()
        .expect_err("expected a failure")
        .error
        .kind
}

fn sent_count(stderr: &str) -> u64 {
    stderr
        .lines()
        .filter_map(|l| l.strip_prefix("sent "))
        .filter_map(|n| n.trim().parse().ok())
        .max()
        .unwrap_or(0)
}

fn scenario(name: &str, body: impl FnOnce()) {
    if std::env::var("MDD_WIRE_ONLY").is_ok_and(|only| !name.contains(&only)) {
        return;
    }
    let started = Instant::now();
    body();
    println!("ok {name} ({} ms)", started.elapsed().as_millis());
}

fn main() {
    if let Ok(mode) = std::env::var("MDD_WIRE_CHILD") {
        child(&mode);
    }

    scenario("complete stream is verified, negotiated and reaped", || {
        let outcome = run("complete", config(Duration::from_secs(20)));
        let done = outcome.result.as_ref().expect("complete stream");
        assert_eq!(done.rows.len(), 50);
        assert_eq!(done.batches, 7);
        let expected: Vec<Vec<Cell>> = (1..=50).map(|i| row(i, 6)).collect();
        assert_eq!(done.rows, expected);
        assert_eq!(outcome.agreed.as_ref().unwrap().encoding, "json");
        assert!(outcome.exit.unwrap().success() && !outcome.killed);
        assert!(
            outcome.peak_queued_frames <= QUEUE + 1,
            "queue held {} frames",
            outcome.peak_queued_frames
        );
    });

    scenario(
        "an error after rows is a failure that keeps the worker's code",
        || {
            let outcome = run("source_error", config(Duration::from_secs(20)));
            let failure = outcome.result.as_ref().unwrap_err();
            assert_eq!(failure.error.kind, WireErrorKind::PeerError);
            assert_eq!(
                failure.rows_received, 20,
                "rows 17-20 gathered before the failing row are still delivered, then the Error"
            );
            let engine_error = mdd_worker::protocol::failure_to_mdd(failure);
            assert_eq!(engine_error.code, ErrorCode::QuotaExceeded);
            assert_eq!(engine_error.details["budget"], "max_rows");
        },
    );

    scenario(
        "a worker that exits before End is a disconnect, not a short result",
        || {
            let outcome = run("no_end", config(Duration::from_secs(20)));
            assert_eq!(failure_kind(&outcome), WireErrorKind::Disconnected);
            assert_eq!(outcome.result.as_ref().unwrap_err().rows_received, 3);
            assert_eq!(
                mdd_worker::protocol::failure_to_mdd(outcome.result.as_ref().unwrap_err()).code,
                ErrorCode::WorkerLost
            );
        },
    );

    scenario(
        "a worker killed mid-stream reports its exit status and a disconnect",
        || {
            let outcome = run("exit_nonzero", config(Duration::from_secs(20)));
            assert_eq!(failure_kind(&outcome), WireErrorKind::Disconnected);
            assert_eq!(outcome.exit.and_then(|e| e.code()), Some(23));
        },
    );

    scenario("a half frame is a truncated body", || {
        let outcome = run("truncated", config(Duration::from_secs(20)));
        assert_eq!(failure_kind(&outcome), WireErrorKind::TruncatedBody);
    });

    scenario(
        "log text on the dedicated channel is a protocol failure",
        || {
            let started = Instant::now();
            let outcome = run("garbage", config(Duration::from_secs(20)));
            assert_eq!(failure_kind(&outcome), WireErrorKind::BadMagic);
            assert!(outcome.killed && !outcome.exit.unwrap().success());
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "the sleeping worker was killed, not awaited"
            );
        },
    );

    scenario("a duplicate terminal is not ignored", || {
        let outcome = run("duplicate_end", config(Duration::from_secs(20)));
        assert_eq!(failure_kind(&outcome), WireErrorKind::FrameAfterTerminal);
    });

    scenario("a batch after End is not ignored", || {
        let outcome = run("batch_after_end", config(Duration::from_secs(20)));
        assert_eq!(failure_kind(&outcome), WireErrorKind::FrameAfterTerminal);
    });

    scenario(
        "a frame size below the minimum fails negotiation and the worker is reaped",
        || {
            let started = Instant::now();
            let outcome = run("bad_hello", config(Duration::from_secs(20)));
            assert_eq!(failure_kind(&outcome), WireErrorKind::NegotiationFailed);
            assert!(outcome.killed && started.elapsed() < Duration::from_secs(10));
        },
    );

    scenario(
        "a worker that stops talking is bounded by the deadline and killed",
        || {
            let started = Instant::now();
            let outcome = run("stall", config(Duration::from_millis(500)));
            assert_eq!(failure_kind(&outcome), WireErrorKind::DeadlineExceeded);
            assert_eq!(outcome.result.as_ref().unwrap_err().rows_received, 3);
            assert!(outcome.killed && !outcome.exit.unwrap().success());
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "took {:?}",
                started.elapsed()
            );
        },
    );

    scenario("cancel reaches a stalled worker promptly", || {
        let mut cfg = config(Duration::from_secs(60));
        let cancel = Arc::clone(&cfg.cancel);
        cfg.exit_grace = Duration::from_secs(1);
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            cancel.store(true, Ordering::SeqCst);
        });
        let started = Instant::now();
        let outcome = run("stall", cfg);
        canceller.join().unwrap();
        assert_eq!(failure_kind(&outcome), WireErrorKind::Cancelled);
        assert_eq!(
            mdd_worker::protocol::failure_to_mdd(outcome.result.as_ref().unwrap_err()).code,
            ErrorCode::Cancelled
        );
        // The stalled worker is killed, or, if the cancel landed during the
        // handshake, it dies on the unexpected Cancel by itself; either way it is
        // reaped and did not finish normally.
        assert!(!outcome.exit.unwrap().success());
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "took {:?}",
            started.elapsed()
        );
    });

    scenario("a paused consumer bounds what the worker may write", || {
        let mut cfg = config(Duration::from_secs(60));
        cfg.initial_credit = Credit {
            bytes: 1 << 20,
            batches: 2,
        };
        let seen_while_paused = Arc::new(std::sync::Mutex::new(None));
        let slot = Arc::clone(&seen_while_paused);
        cfg.on_batch = Some(Box::new(move |consumed, probe| {
            if consumed == 1 {
                // Hold the credit refill back. The worker may finish the batches it
                // already has credit for and nothing more.
                std::thread::sleep(Duration::from_millis(600));
                *slot.lock().unwrap() =
                    Some((sent_count(&probe.child_stderr()), probe.queued_frames()));
            }
        }));
        let outcome = run("big", cfg);
        let done = outcome
            .result
            .as_ref()
            .expect("the stream completes once the consumer resumes");
        assert_eq!(done.rows.len(), 300);
        let (sent, queued) = seen_while_paused.lock().unwrap().expect("the hook ran");
        assert!(
            sent <= 2,
            "the worker wrote {sent} batches against a 2 batch credit while the consumer was paused"
        );
        assert!(queued <= QUEUE + 1, "{queued} frames queued");
        assert!(
            outcome.peak_queued_frames <= QUEUE + 1,
            "peak queue {}",
            outcome.peak_queued_frames
        );
        assert_eq!(sent_count(&outcome.stderr), 300);
        assert!(outcome.exit.unwrap().success() && !outcome.killed);
    });

    scenario(
        "a consumer that never resumes ends at the deadline with the worker stopped",
        || {
            let mut cfg = config(Duration::from_millis(900));
            cfg.initial_credit = Credit {
                bytes: 1 << 20,
                batches: 2,
            };
            cfg.on_batch = Some(Box::new(|consumed, _| {
                if consumed == 1 {
                    std::thread::sleep(Duration::from_millis(1500));
                }
            }));
            let started = Instant::now();
            let outcome = run("big_stalled_consumer", cfg);
            assert_eq!(failure_kind(&outcome), WireErrorKind::DeadlineExceeded);
            // The hook outlived the deadline, so the client must not have refilled the
            // credit it had just consumed: only the initial grant went out.
            assert_eq!(
                outcome.credit_frames, 1,
                "credit was re-granted after the deadline"
            );
            // The client closes the worker's stdin and kills what is still running.
            // A worker that sees the closed pipe first stops by itself, so either
            // way it must be gone and reaped; what must never happen is more output.
            let exit = outcome.exit.expect("the worker was reaped");
            assert!(outcome.killed || exit.success(), "unexpected exit {exit:?}");
            assert!(
                sent_count(&outcome.stderr) <= 2,
                "worker wrote {} batches; stderr: {}",
                sent_count(&outcome.stderr),
                outcome.stderr
            );
            assert!(outcome.peak_queued_frames <= QUEUE + 1);
            assert!(
                started.elapsed() < Duration::from_secs(12),
                "took {:?}",
                started.elapsed()
            );
        },
    );

    scenario(
        "a worker that never reads cannot hold the client past its deadline",
        || {
            // A request far larger than a pipe buffer, to a worker that stopped
            // reading: the write blocks, the exchange must still end at the deadline.
            let big_request = vec![b'x'; 900_000];
            let started = Instant::now();
            let outcome = run_with_body("deaf", &big_request, config(Duration::from_millis(700)));
            assert_eq!(failure_kind(&outcome), WireErrorKind::DeadlineExceeded);
            assert!(outcome.killed && !outcome.exit.unwrap().success());
            assert_eq!(
                outcome.detached_threads, 0,
                "the killed worker released its pipes"
            );
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "took {:?}",
                started.elapsed()
            );
        },
    );

    scenario(
        "cancel is sent to a live worker, which stops by itself and is not killed",
        || {
            let mut cfg = config(Duration::from_secs(60));
            cfg.initial_credit = Credit {
                bytes: 1 << 20,
                batches: 2,
            };
            let cancel = Arc::clone(&cfg.cancel);
            cfg.on_batch = Some(Box::new(move |consumed, _| {
                if consumed == 1 {
                    cancel.store(true, Ordering::SeqCst);
                }
            }));
            let outcome = run("big", cfg);
            assert_eq!(failure_kind(&outcome), WireErrorKind::Cancelled);
            assert!(
                !outcome.killed,
                "the worker obeyed Cancel; stderr: {}",
                outcome.stderr
            );
            assert!(outcome.exit.unwrap().success());
            assert!(
                sent_count(&outcome.stderr) <= 2,
                "worker wrote {}",
                sent_count(&outcome.stderr)
            );
        },
    );

    scenario(
        "a worker that ignores end of input leaves only because Cancel was sent",
        || {
            let mut cfg = config(Duration::from_secs(60));
            cfg.exit_grace = Duration::from_secs(5);
            let cancel = Arc::clone(&cfg.cancel);
            cfg.on_batch = Some(Box::new(move |consumed, _| {
                if consumed == 1 {
                    cancel.store(true, Ordering::SeqCst);
                }
            }));
            let started = Instant::now();
            let outcome = run("cancel_only", cfg);
            assert_eq!(failure_kind(&outcome), WireErrorKind::Cancelled);
            assert!(!outcome.killed, "the Cancel frame did not reach the worker");
            assert!(outcome.exit.unwrap().success());
            assert!(
                started.elapsed() < Duration::from_secs(4),
                "took {:?}",
                started.elapsed()
            );
        },
    );

    scenario(
        "rows too large for one frame are split into several batches",
        || {
            let outcome = run("wide", config(Duration::from_secs(30)));
            let done = outcome.result.as_ref().expect("the stream completes");
            assert_eq!(done.rows.len(), 20);
            assert!(
                done.batches > 3,
                "eight 300 KB rows cannot fit one 1 MiB frame; got {} batches",
                done.batches
            );
            let ids: Vec<i64> = done
                .rows
                .iter()
                .map(|row| match row[0] {
                    Cell::I64(id) => id,
                    ref other => panic!("{other:?}"),
                })
                .collect();
            assert_eq!(
                ids,
                (1..=20).collect::<Vec<_>>(),
                "order and content are intact"
            );
        },
    );

    scenario(
        "a row the worker cannot encode ends in an Error terminal with the reason",
        || {
            let outcome = run("cell_limit", config(Duration::from_secs(20)));
            let failure = outcome.result.as_ref().unwrap_err();
            assert_eq!(failure.error.kind, WireErrorKind::PeerError);
            assert_eq!(failure.peer.as_ref().unwrap().code, "QUOTA_EXCEEDED");
            assert_eq!(failure.rows_received, 0);
            assert_eq!(
                mdd_worker::protocol::failure_to_mdd(failure).details["wire_error"],
                "cell_too_large"
            );
            assert!(outcome.exit.unwrap().success() && !outcome.killed);
        },
    );

    println!("all wire child scenarios passed");
}
