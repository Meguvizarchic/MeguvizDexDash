//! Producer-side behaviour, backpressure and channel guards.
use mdd_types::{ErrorCode, MddError};
use mdd_wire::{
    Cell, ChannelKind, Column, ColumnType, Credit, CreditGate, Frame, FrameKind, FrameReader,
    FrameWriter, Header, ProducerStream, ResponseStream, Schema, StreamLimits, WireErrorKind,
    check_mcp_stdout_message,
};
use serde_json::Value;
use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn schema() -> Schema {
    Schema {
        schema_id: "mdd.rows.v1:behavior".to_owned(),
        columns: vec![
            Column {
                ordinal: 0,
                stable_id: "id".to_owned(),
                name: "id".to_owned(),
                ty: ColumnType::I64,
                nullable: false,
            },
            Column {
                ordinal: 1,
                stable_id: "txt".to_owned(),
                name: "txt".to_owned(),
                ty: ColumnType::Utf8,
                nullable: true,
            },
        ],
    }
}

fn frame(kind: FrameKind, stream: u64, body: Vec<u8>) -> Frame {
    Frame {
        header: Header::new(kind, stream, body.len() as u64),
        body,
    }
}

fn row(id: i64, text: Option<&str>) -> Vec<Cell> {
    vec![
        Cell::I64(id),
        text.map_or(Cell::Null, |t| Cell::Utf8(t.to_owned())),
    ]
}

#[test]
fn a_producer_stream_is_accepted_by_a_consumer_and_returns_exactly_its_rows() {
    let mut producer = ProducerStream::new(3, StreamLimits::default()).unwrap();
    let mut consumer = ResponseStream::new(3, StreamLimits::default()).unwrap();
    let rows_a = vec![row(1, Some("a")), row(1, Some("a")), row(2, None)];
    let rows_b = vec![row(i64::MIN, Some(""))];
    for (kind, body) in [
        (FrameKind::Schema, producer.schema(schema()).unwrap()),
        (FrameKind::Batch, producer.batch(&rows_a).unwrap()),
        (FrameKind::Batch, producer.batch(&[]).unwrap()),
        (FrameKind::Batch, producer.batch(&rows_b).unwrap()),
        (FrameKind::End, producer.end().unwrap()),
    ] {
        consumer.accept(&frame(kind, 3, body)).unwrap();
    }
    let done = consumer.finish().unwrap();
    assert_eq!(done.batches, 3);
    assert_eq!(done.rows, [rows_a, rows_b].concat());
}

#[test]
fn the_producer_refuses_what_a_consumer_would_have_to_refuse() {
    let limits = StreamLimits {
        max_cell_bytes: 4,
        max_rows_per_batch: 2,
        ..StreamLimits::default()
    };
    let mut producer = ProducerStream::new(1, limits).unwrap();
    assert_eq!(
        producer.batch(&[row(1, None)]).unwrap_err().kind,
        WireErrorKind::UnexpectedFrame,
        "no batch before a schema"
    );
    producer.schema(schema()).unwrap();
    assert_eq!(
        producer.schema(schema()).unwrap_err().kind,
        WireErrorKind::UnexpectedFrame
    );
    assert_eq!(
        producer.batch(&[row(1, Some("12345"))]).unwrap_err().kind,
        WireErrorKind::CellTooLarge
    );
    assert_eq!(
        producer
            .batch(&[vec![Cell::Utf8("x".into()), Cell::Null]])
            .unwrap_err()
            .kind,
        WireErrorKind::CellTypeMismatch
    );
    assert_eq!(
        producer
            .batch(&[vec![Cell::Null, Cell::Null]])
            .unwrap_err()
            .kind,
        WireErrorKind::CellTypeMismatch,
        "NULL in a non-nullable column"
    );
    assert_eq!(
        producer
            .batch(&[row(1, None), row(2, None), row(3, None)])
            .unwrap_err()
            .kind,
        WireErrorKind::BatchTooLarge
    );
    // None of the refusals consumed a sequence number or a row.
    producer.batch(&[row(1, None)]).unwrap();
    producer.end().unwrap();
    assert_eq!(
        producer.batch(&[row(2, None)]).unwrap_err().kind,
        WireErrorKind::FrameAfterTerminal
    );
    assert_eq!(
        producer.end().unwrap_err().kind,
        WireErrorKind::FrameAfterTerminal
    );
}

#[test]
fn a_batch_over_the_frame_limit_is_refused_not_truncated() {
    let limits = StreamLimits {
        max_body_bytes: 300,
        ..StreamLimits::default()
    };
    let mut producer = ProducerStream::new(1, limits).unwrap();
    producer.schema(schema()).unwrap();
    let big: Vec<Vec<Cell>> = (0..20).map(|i| row(i, Some("padding padding"))).collect();
    assert_eq!(
        producer.batch(&big).unwrap_err().kind,
        WireErrorKind::FrameTooLarge
    );
    // The caller sends fewer rows per batch and the stream still completes.
    producer.batch(&big[..2]).unwrap();
    producer.end().unwrap();
}

#[test]
fn an_error_terminal_after_rows_is_a_failure_with_the_rows_counted() {
    let mut producer = ProducerStream::new(1, StreamLimits::default()).unwrap();
    let mut consumer = ResponseStream::new(1, StreamLimits::default()).unwrap();
    consumer
        .accept(&frame(
            FrameKind::Schema,
            1,
            producer.schema(schema()).unwrap(),
        ))
        .unwrap();
    consumer
        .accept(&frame(
            FrameKind::Batch,
            1,
            producer.batch(&[row(1, None), row(2, None)]).unwrap(),
        ))
        .unwrap();
    let error = MddError::new(ErrorCode::QuotaExceeded, "budget", "row budget exhausted")
        .detail("budget", "max_rows");
    consumer
        .accept(&frame(FrameKind::Error, 1, producer.error(&error).unwrap()))
        .unwrap();
    let failure = consumer.finish().unwrap_err();
    assert_eq!(failure.error.kind, WireErrorKind::PeerError);
    assert_eq!(failure.rows_received, 2);
    let peer = failure.peer.unwrap();
    assert_eq!(peer.to_mdd().code, ErrorCode::QuotaExceeded);
    assert_eq!(peer.to_mdd().details["budget"], "max_rows");
    assert_eq!(
        producer.error(&error).unwrap_err().kind,
        WireErrorKind::FrameAfterTerminal
    );
}

#[test]
fn a_sticky_failure_is_reported_again_instead_of_being_reinterpreted() {
    let mut producer = ProducerStream::new(1, StreamLimits::default()).unwrap();
    let mut consumer = ResponseStream::new(1, StreamLimits::default()).unwrap();
    consumer
        .accept(&frame(
            FrameKind::Schema,
            1,
            producer.schema(schema()).unwrap(),
        ))
        .unwrap();
    let good = producer.batch(&[row(1, None)]).unwrap();
    // A garbage frame breaks the stream; the valid batch that follows must not
    // revive it, and the stream cannot finish as a success.
    let broken = consumer
        .accept(&frame(FrameKind::Batch, 1, b"{".to_vec()))
        .unwrap_err();
    assert_eq!(broken.kind, WireErrorKind::MalformedBody);
    assert_eq!(
        consumer
            .accept(&frame(FrameKind::Batch, 1, good))
            .unwrap_err(),
        broken
    );
    assert_eq!(consumer.finish().unwrap_err().error, broken);
}

#[test]
fn frames_round_trip_through_a_writer_and_reader_and_only_on_the_dedicated_channel() {
    let mut writer = FrameWriter::new(Vec::new(), ChannelKind::Dedicated, 1024).unwrap();
    writer
        .write_frame(FrameKind::Request, 5, b"{\"op\":\"x\"}")
        .unwrap();
    writer.write_frame(FrameKind::Cancel, 5, b"").unwrap();
    assert_eq!(
        writer
            .write_frame(FrameKind::Batch, 5, &[0u8; 1025])
            .unwrap_err()
            .kind,
        WireErrorKind::FrameTooLarge
    );
    let bytes = writer.into_inner();
    let mut reader = FrameReader::new(Cursor::new(bytes));
    let first = reader.read_frame(1024).unwrap().unwrap();
    assert_eq!(
        (
            first.header.kind,
            first.header.stream_id,
            first.body.as_slice()
        ),
        (FrameKind::Request, 5, &b"{\"op\":\"x\"}"[..])
    );
    assert_eq!(
        reader.read_frame(1024).unwrap().unwrap().header.kind,
        FrameKind::Cancel
    );
    assert!(reader.read_frame(1024).unwrap().is_none());
    for channel in [ChannelKind::McpStdout, ChannelKind::Stderr] {
        assert_eq!(
            FrameWriter::new(Vec::new(), channel, 1024)
                .err()
                .unwrap()
                .kind,
            WireErrorKind::ChannelNotDedicated
        );
    }
}

#[test]
fn mcp_stdout_accepts_only_one_json_rpc_line() {
    assert!(check_mcp_stdout_message(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n").is_ok());
    assert!(check_mcp_stdout_message(b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}").is_ok());
    let frame_bytes = {
        let mut writer = FrameWriter::new(Vec::new(), ChannelKind::Dedicated, 1024).unwrap();
        writer.write_frame(FrameKind::Request, 1, b"{}").unwrap();
        writer.into_inner()
    };
    for (what, bytes) in [
        ("a wire frame", frame_bytes.as_slice()),
        ("plain log text", b"starting worker\n".as_slice()),
        ("invalid UTF-8", &[0x7b, 0xff, 0x7d]),
        (
            "two lines",
            b"{\"jsonrpc\":\"2.0\"}\n{\"jsonrpc\":\"2.0\"}\n".as_slice(),
        ),
        ("a JSON array", b"[1,2]\n".as_slice()),
        (
            "a JSON object that is not JSON-RPC",
            b"{\"id\":1}\n".as_slice(),
        ),
        ("the wrong version", b"{\"jsonrpc\":\"1.0\"}\n".as_slice()),
        (
            "a message with an embedded newline",
            b"{\"jsonrpc\":\"2.0\",\n\"id\":1}\n".as_slice(),
        ),
        ("an empty write", b"".as_slice()),
    ] {
        let error = check_mcp_stdout_message(bytes).expect_err(what);
        assert_eq!(error.kind, WireErrorKind::McpStdoutViolation, "{what}");
        if what == "a wire frame" {
            // Named for what it is, not just rejected as "not JSON".
            assert!(error.message.contains("wire frame"), "{}", error.message);
        }
    }
}

#[test]
fn a_producer_without_credit_waits_boundedly_and_gives_up() {
    let gate = CreditGate::new();
    let cancel = AtomicBool::new(false);
    let started = Instant::now();
    let error = gate
        .reserve(100, Duration::from_millis(60), &cancel)
        .unwrap_err();
    assert_eq!(error.kind, WireErrorKind::DeadlineExceeded);
    assert!(
        started.elapsed() >= Duration::from_millis(60)
            && started.elapsed() < Duration::from_secs(2)
    );
    assert_eq!(
        gate.remaining(),
        Credit::default(),
        "a failed wait spends nothing"
    );
    gate.grant(Credit {
        bytes: 250,
        batches: 2,
    })
    .unwrap();
    gate.reserve(100, Duration::from_millis(10), &cancel)
        .unwrap();
    gate.reserve(100, Duration::from_millis(10), &cancel)
        .unwrap();
    assert_eq!(
        gate.remaining(),
        Credit {
            bytes: 50,
            batches: 0
        }
    );
    assert_eq!(
        gate.reserve(10, Duration::from_millis(20), &cancel)
            .unwrap_err()
            .kind,
        WireErrorKind::DeadlineExceeded,
        "bytes remain but no batch credit"
    );
}

#[test]
fn cancellation_releases_a_waiting_producer_promptly() {
    let gate = Arc::new(CreditGate::new());
    let cancel = Arc::new(AtomicBool::new(false));
    let waiter = {
        let (gate, cancel) = (Arc::clone(&gate), Arc::clone(&cancel));
        std::thread::spawn(move || gate.reserve(10, Duration::from_secs(30), &cancel))
    };
    std::thread::sleep(Duration::from_millis(50));
    let cancelled_at = Instant::now();
    cancel.store(true, Ordering::SeqCst);
    gate.wake();
    let error = waiter.join().unwrap().unwrap_err();
    assert_eq!(error.kind, WireErrorKind::Cancelled);
    assert!(
        cancelled_at.elapsed() < Duration::from_secs(2),
        "the wait ended long before its 30 s bound"
    );
}

#[test]
fn a_late_grant_wakes_a_waiting_producer() {
    let gate = Arc::new(CreditGate::new());
    let cancel = Arc::new(AtomicBool::new(false));
    let waiter = {
        let (gate, cancel) = (Arc::clone(&gate), Arc::clone(&cancel));
        std::thread::spawn(move || gate.reserve(10, Duration::from_secs(30), &cancel))
    };
    std::thread::sleep(Duration::from_millis(30));
    gate.grant(Credit {
        bytes: 10,
        batches: 1,
    })
    .unwrap();
    waiter.join().unwrap().unwrap();
    assert_eq!(gate.remaining(), Credit::default());
}

#[test]
fn credit_arithmetic_refuses_overflow() {
    let gate = CreditGate::new();
    gate.grant(Credit {
        bytes: u64::MAX,
        batches: 1,
    })
    .unwrap();
    assert_eq!(
        gate.grant(Credit {
            bytes: 1,
            batches: 0
        })
        .unwrap_err()
        .kind,
        WireErrorKind::CreditExceeded
    );
}

#[test]
fn consumer_credit_is_spent_by_batches_and_refilled_by_grants() {
    let limits = StreamLimits {
        enforce_credit: true,
        ..StreamLimits::default()
    };
    let mut producer = ProducerStream::new(1, limits).unwrap();
    let mut consumer = ResponseStream::new(1, limits).unwrap();
    consumer
        .accept(&frame(
            FrameKind::Schema,
            1,
            producer.schema(schema()).unwrap(),
        ))
        .unwrap();
    let first = producer.batch(&[row(1, None)]).unwrap();
    let second = producer.batch(&[row(2, None)]).unwrap();
    let credit_body = consumer
        .grant_credit(Credit {
            bytes: first.len() as u64,
            batches: 1,
        })
        .unwrap();
    let granted: Value = serde_json::from_slice(&credit_body).unwrap();
    assert_eq!(granted["batches"], "1");
    consumer.accept(&frame(FrameKind::Batch, 1, first)).unwrap();
    assert_eq!(
        consumer
            .accept(&frame(FrameKind::Batch, 1, second))
            .unwrap_err()
            .kind,
        WireErrorKind::CreditExceeded
    );
}

#[test]
fn a_failed_write_latches_the_writer_so_no_frame_follows_a_partial_one() {
    struct FailsAfter {
        budget: usize,
        written: Vec<u8>,
    }
    impl std::io::Write for FailsAfter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.budget == 0 {
                return Err(std::io::Error::other("pipe closed"));
            }
            let count = bytes.len().min(self.budget);
            self.budget -= count;
            self.written.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    // Room for the 32 byte header and part of the body.
    let sink = FailsAfter {
        budget: 40,
        written: Vec::new(),
    };
    let mut writer = FrameWriter::new(sink, ChannelKind::Dedicated, 1024).unwrap();
    assert_eq!(
        writer
            .write_frame(FrameKind::Progress, 1, &[b'x'; 100])
            .unwrap_err()
            .kind,
        WireErrorKind::Io
    );
    let before = writer.into_inner().written.len();
    // A second writer over the same state would append; the latched one refuses.
    let sink = FailsAfter {
        budget: 40,
        written: Vec::new(),
    };
    let mut writer = FrameWriter::new(sink, ChannelKind::Dedicated, 1024).unwrap();
    let _ = writer.write_frame(FrameKind::Progress, 1, &[b'x'; 100]);
    let error = writer.write_frame(FrameKind::Cancel, 1, b"").unwrap_err();
    assert_eq!(error.kind, WireErrorKind::Io);
    assert!(error.message.contains("partial"), "{}", error.message);
    assert_eq!(
        writer.into_inner().written.len(),
        before,
        "nothing was appended after the failure"
    );
}

#[test]
fn an_unbounded_wait_is_capped_instead_of_overflowing_the_clock() {
    let gate = CreditGate::new();
    let cancel = AtomicBool::new(true);
    // Cancel is already set, so this returns at once; the point is that the
    // deadline arithmetic with Duration::MAX does not panic.
    let error = gate.reserve(1, Duration::MAX, &cancel).unwrap_err();
    assert_eq!(error.kind, WireErrorKind::Cancelled);
}

#[test]
fn a_frame_cut_short_is_a_lost_worker_like_a_vanished_one() {
    let mut reader = FrameReader::new(Cursor::new(vec![b'M', b'D']));
    let error = reader.read_frame(1024).unwrap_err();
    assert_eq!(error.kind, WireErrorKind::TruncatedHeader);
    assert_eq!(error.to_mdd().code, ErrorCode::WorkerLost);
    let mut bytes = Header::new(FrameKind::Batch, 1, 10).encode().to_vec();
    bytes.extend_from_slice(b"abc");
    let error = FrameReader::new(Cursor::new(bytes))
        .read_frame(1024)
        .unwrap_err();
    assert_eq!(error.kind, WireErrorKind::TruncatedBody);
    assert_eq!(error.to_mdd().code, ErrorCode::WorkerLost);
}

#[test]
fn hello_is_as_strict_as_every_other_body() {
    let mut hello = mdd_wire::Hello::v1(4096).to_json();
    assert!(mdd_wire::Hello::from_json(&hello).is_ok());
    hello["extra"] = serde_json::json!(1);
    assert_eq!(
        mdd_wire::Hello::from_json(&hello).unwrap_err().kind,
        WireErrorKind::MalformedBody
    );
}

#[test]
fn a_peer_cannot_overwrite_the_engines_own_error_details() {
    let mut details = serde_json::Map::new();
    details.insert("peer_code".to_owned(), serde_json::json!("QUOTA_EXCEEDED"));
    details.insert("budget".to_owned(), serde_json::json!("max_rows"));
    let peer = mdd_wire::PeerError {
        code: "WORKER_LOST".to_owned(),
        message: "gone".to_owned(),
        details,
    };
    let error = peer.to_mdd();
    assert_eq!(error.code, ErrorCode::WorkerLost);
    assert_eq!(
        error.details["peer_code"], "WORKER_LOST",
        "the engine's record wins"
    );
    assert_eq!(error.details["budget"], "max_rows");
}
