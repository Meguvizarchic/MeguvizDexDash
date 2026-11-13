//! Replays `conformance/protocol/wire-v1-cases.json`.
//!
//! The case bytes and verdicts come from an independent Python implementation of
//! the layout, the cell JSON form and the digest (`generate_wire_cases.py`). A
//! missing or empty case file is a failure, not a skip.
use mdd_wire::{
    Cell, Credit, Frame, FrameKind, FrameReader, Header, Hello, ResponseStream, StreamLimits,
    WireErrorKind, negotiate,
};
use serde_json::Value;
use std::io::Cursor;

fn cases() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/protocol/wire-v1-cases.json");
    let text = std::fs::read_to_string(&path).expect("wire-v1-cases.json must exist");
    serde_json::from_str(&text).expect("wire-v1-cases.json must be JSON")
}

fn hex_to_bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn kind_of(name: &str) -> FrameKind {
    (1..=9)
        .filter_map(FrameKind::from_u16)
        .find(|kind| kind.name() == name)
        .unwrap_or_else(|| panic!("unknown frame kind name {name}"))
}

#[test]
fn frame_cases_reach_the_recorded_verdicts() {
    let document = cases();
    let list = document["frame_cases"].as_array().unwrap();
    assert!(list.len() >= 27, "frame case set shrank: {}", list.len());
    for case in list {
        let name = case["name"].as_str().unwrap();
        let bytes = hex_to_bytes(case["hex"].as_str().unwrap());
        let max = case["max_body_bytes"].as_u64().unwrap();
        let mut reader = FrameReader::new(Cursor::new(bytes));
        let mut frames = Vec::new();
        let outcome = loop {
            match reader.read_frame(max) {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => break Ok(()),
                Err(error) => break Err(error),
            }
        };
        match (case["expect"].get("error"), outcome) {
            (Some(code), Err(error)) => {
                assert_eq!(error.kind.code(), code.as_str().unwrap(), "{name}")
            }
            (Some(code), Ok(())) => panic!("{name}: expected {code} but all frames were accepted"),
            (None, Err(error)) => panic!("{name}: unexpected {error}"),
            (None, Ok(())) => {
                let expected = case["expect"]["frames"].as_array().unwrap();
                assert_eq!(frames.len(), expected.len(), "{name}: frame count");
                for (frame, want) in frames.iter().zip(expected) {
                    assert_eq!(
                        frame.header.kind,
                        kind_of(want["kind"].as_str().unwrap()),
                        "{name}"
                    );
                    assert_eq!(
                        frame.header.stream_id,
                        want["stream_id"].as_u64().unwrap(),
                        "{name}"
                    );
                    assert_eq!(
                        frame.body,
                        hex_to_bytes(want["body_hex"].as_str().unwrap()),
                        "{name}"
                    );
                }
            }
        }
    }
}

#[test]
fn header_round_trips_and_has_the_documented_layout() {
    let header = Header::new(
        FrameKind::Batch,
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
    );
    let bytes = header.encode();
    assert_eq!(&bytes[0..4], b"MDDW");
    assert_eq!(&bytes[4..6], &1u16.to_le_bytes());
    assert_eq!(&bytes[8..10], &4u16.to_le_bytes());
    assert_eq!(&bytes[12..16], &32u32.to_le_bytes());
    assert_eq!(&bytes[16..24], &0x0102_0304_0506_0708u64.to_le_bytes());
    assert_eq!(&bytes[24..32], &0x1112_1314_1516_1718u64.to_le_bytes());
    assert_eq!(Header::decode(&bytes, u64::MAX).unwrap(), header);
}

#[test]
fn negotiation_cases_reach_the_recorded_verdicts() {
    let document = cases();
    let list = document["negotiation_cases"].as_array().unwrap();
    assert!(list.len() >= 8);
    for case in list {
        let name = case["name"].as_str().unwrap();
        let local = Hello::from_json(&case["local"]).unwrap();
        let peer = Hello::from_json(&case["peer"]).unwrap();
        match (case["expect"].get("error"), negotiate(&local, &peer)) {
            (Some(code), Err(error)) => {
                assert_eq!(error.kind.code(), code.as_str().unwrap(), "{name}")
            }
            (None, Ok(agreed)) => {
                let want = &case["expect"]["agreed"];
                assert_eq!(
                    u64::from(agreed.major),
                    want["major"].as_u64().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    u64::from(agreed.minor),
                    want["minor"].as_u64().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    agreed.max_frame_bytes,
                    want["max_frame_bytes"].as_u64().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    agreed.encoding,
                    want["encoding"].as_str().unwrap(),
                    "{name}"
                );
            }
            (want, got) => panic!("{name}: expected {want:?}, got {got:?}"),
        }
    }
}

fn limits_of(case: &Value) -> StreamLimits {
    let mut limits = StreamLimits::default();
    if let Some(over) = case.get("limits") {
        if let Some(v) = over.get("max_cell_bytes").and_then(Value::as_u64) {
            limits.max_cell_bytes = v as usize;
        }
        if let Some(v) = over.get("max_rows_per_batch").and_then(Value::as_u64) {
            limits.max_rows_per_batch = v;
        }
        if let Some(v) = over.get("max_buffered_bytes").and_then(Value::as_u64) {
            limits.max_buffered_bytes = v;
        }
        if let Some(v) = over.get("enforce_credit").and_then(Value::as_bool) {
            limits.enforce_credit = v;
        }
    }
    limits
}

#[test]
fn stream_cases_reach_the_recorded_verdicts() {
    let document = cases();
    let list = document["stream_cases"].as_array().unwrap();
    assert!(list.len() >= 60, "stream case set shrank: {}", list.len());
    let mut outcomes = std::collections::BTreeSet::new();
    for case in list {
        let name = case["name"].as_str().unwrap();
        let expect = &case["expect"];
        let stream_id = case["stream_id"].as_u64().unwrap();
        let mut stream = match ResponseStream::new(stream_id, limits_of(case)) {
            Ok(stream) => stream,
            Err(error) => {
                assert_eq!(Some(error.kind.code()), expect["error"].as_str(), "{name}");
                outcomes.insert(error.kind.code().to_owned());
                continue;
            }
        };
        for grant in case
            .get("credit_grants")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            stream
                .grant_credit(Credit {
                    bytes: grant["bytes"].as_u64().unwrap(),
                    batches: grant["batches"].as_u64().unwrap(),
                })
                .unwrap();
        }
        let mut failed_at = None;
        for (index, frame) in case["frames"].as_array().unwrap().iter().enumerate() {
            let body = frame["body_text"].as_str().unwrap().as_bytes().to_vec();
            let kind = kind_of(frame["kind"].as_str().unwrap());
            let frame = Frame {
                header: Header::new(
                    kind,
                    frame["stream_id"].as_u64().unwrap(),
                    body.len() as u64,
                ),
                body,
            };
            if let Err(error) = stream.accept(&frame) {
                failed_at = Some((index, error));
                break;
            }
        }
        match (expect.get("complete"), expect.get("error")) {
            (Some(done), None) => {
                assert!(failed_at.is_none(), "{name}: unexpected {:?}", failed_at);
                let completed = stream
                    .finish()
                    .unwrap_or_else(|failure| panic!("{name}: {failure:?}"));
                let got: Vec<Value> = completed
                    .rows
                    .iter()
                    .map(|row| Value::Array(row.iter().map(Cell::to_json).collect()))
                    .collect();
                assert_eq!(Value::Array(got), done["rows"], "{name}: rows");
                assert_eq!(
                    completed.batches,
                    done["batches"].as_u64().unwrap(),
                    "{name}: batches"
                );
                outcomes.insert("complete".to_owned());
            }
            (None, Some(code)) => {
                let code = code.as_str().unwrap();
                match expect.get("at_frame").and_then(Value::as_u64) {
                    Some(at) => {
                        let (index, error) = failed_at
                            .unwrap_or_else(|| panic!("{name}: no frame failed, expected {code}"));
                        assert_eq!((index as u64, error.kind.code()), (at, code), "{name}");
                    }
                    None => {
                        assert!(
                            failed_at.is_none(),
                            "{name}: a frame failed: {:?}",
                            failed_at
                        );
                        let failure = stream
                            .finish()
                            .expect_err(&format!("{name}: finished as a success"));
                        assert_eq!(failure.error.kind.code(), code, "{name}");
                        if let Some(rows) = expect.get("rows_received").and_then(Value::as_u64) {
                            assert_eq!(failure.rows_received, rows, "{name}: rows_received");
                        }
                        if let Some(peer) = expect.get("peer_code").and_then(Value::as_str) {
                            assert_eq!(
                                failure.peer.as_ref().map(|p| p.code.as_str()),
                                Some(peer),
                                "{name}"
                            );
                        }
                    }
                }
                outcomes.insert(code.to_owned());
            }
            _ => panic!("{name}: malformed expectation"),
        }
    }
    // The case set exercises every failure kind a consumer can reach from bytes.
    for kind in [
        WireErrorKind::SequenceGap,
        WireErrorKind::DigestMismatch,
        WireErrorKind::CountMismatch,
        WireErrorKind::Disconnected,
        WireErrorKind::PeerError,
        WireErrorKind::Cancelled,
        WireErrorKind::FrameAfterTerminal,
        WireErrorKind::CreditExceeded,
        WireErrorKind::BufferQuota,
        WireErrorKind::CellTooLarge,
        WireErrorKind::BatchTooLarge,
        WireErrorKind::RowShapeMismatch,
        WireErrorKind::CellTypeMismatch,
        WireErrorKind::SchemaInvalid,
        WireErrorKind::UnexpectedFrame,
        WireErrorKind::BadStreamId,
        WireErrorKind::MalformedBody,
    ] {
        assert!(
            outcomes.contains(kind.code()),
            "no case reaches {}",
            kind.code()
        );
    }
    assert!(outcomes.contains("complete"));
}

#[test]
fn the_rust_producer_reproduces_the_independent_implementations_bodies_and_digest() {
    use mdd_wire::{ProducerStream, Schema};
    let document = cases();
    let mut rebuilt = 0;
    for case in document["stream_cases"].as_array().unwrap() {
        if case["expect"].get("complete").is_none() || case.get("limits").is_some() {
            continue;
        }
        let name = case["name"].as_str().unwrap();
        let frames = case["frames"].as_array().unwrap();
        let body = |frame: &Value| -> Value {
            serde_json::from_str(frame["body_text"].as_str().unwrap()).unwrap()
        };
        let stream_id = case["stream_id"].as_u64().unwrap();
        let mut producer = ProducerStream::new(stream_id, StreamLimits::default()).unwrap();
        for frame in frames {
            let expected = body(frame);
            let produced = match frame["kind"].as_str().unwrap() {
                "schema" => producer
                    .schema(Schema::from_json(&expected).unwrap())
                    .unwrap(),
                "batch" => {
                    let rows: Vec<Vec<Cell>> = expected["rows"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|row| {
                            row.as_array()
                                .unwrap()
                                .iter()
                                .map(|c| Cell::from_json(c).unwrap())
                                .collect()
                        })
                        .collect();
                    producer.batch(&rows).unwrap()
                }
                "end" => producer.end().unwrap(),
                _ => continue,
            };
            let produced: Value = serde_json::from_slice(&produced).unwrap();
            assert_eq!(
                produced, expected,
                "{name}: the {} body differs from the independent one",
                frame["kind"]
            );
        }
        rebuilt += 1;
    }
    assert!(rebuilt >= 7, "only {rebuilt} complete cases were rebuilt");
}
