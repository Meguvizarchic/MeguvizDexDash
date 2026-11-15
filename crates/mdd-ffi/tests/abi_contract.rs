//! The ABI contract, exercised through the exported `extern "C"` functions.
//!
//! The handle table is process-global, so the tests take one lock and assert that
//! they leave the number of live handles where they found it: a leak in any path
//! fails the test that caused it.
use mdd_ffi::{abi::*, error::Status};
use serde_json::Value;
use std::{
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

static SERIAL: Mutex<()> = Mutex::new(());

const FIXTURE: &str = "tests/fixtures/definitions/generated/definitions-038.dex";
const CLASSES: &str = "SELECT class_def_idx,descriptor FROM native_classes ORDER BY class_def_idx";

fn st(status: Status) -> u32 {
    status as u32
}

fn root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn view(bytes: &[u8]) -> BytesView {
    BytesView {
        ptr: bytes.as_ptr(),
        len: bytes.len() as u64,
    }
}

fn text(view: BytesView) -> String {
    if view.len == 0 {
        return String::new();
    }
    // SAFETY: the views read here come from the library and are valid for the
    // moment of this call; the copy ends the borrow.
    let bytes = unsafe { std::slice::from_raw_parts(view.ptr, view.len as usize) };
    String::from_utf8(bytes.to_vec()).expect("library text is UTF-8")
}

fn live() -> u64 {
    let mut count = 0u64;
    assert_eq!(unsafe { mdd_debug_live_handles_v1(&mut count) }, 0);
    count
}

struct Guard {
    _lock: MutexGuard<'static, ()>,
    baseline: u64,
}

fn guard() -> Guard {
    let lock = SERIAL.lock().unwrap_or_else(|poison| poison.into_inner());
    Guard {
        _lock: lock,
        baseline: live(),
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            assert_eq!(live(), self.baseline, "the test leaked handles");
        }
    }
}

fn error_json(handle: u64) -> Value {
    let mut v = BytesView {
        ptr: std::ptr::null(),
        len: 0,
    };
    assert_eq!(unsafe { mdd_error_json_v1(handle, &mut v) }, 0);
    let json = serde_json::from_str(&text(v)).unwrap();
    assert_eq!(mdd_error_release(handle), 0);
    json
}

/// Expect a failing call: the status, and an error object with the engine code.
fn expect_error(status: u32, wanted: Status, error: u64) -> Value {
    assert_eq!(status, st(wanted), "status");
    assert_ne!(error, 0, "a failing call must report an error object");
    let json = error_json(error);
    assert_eq!(json["status"], st(wanted));
    json
}

fn snapshot() -> u64 {
    let request = serde_json::json!({"inputs": [{
        "path": root().join(FIXTURE).to_string_lossy(),
        "kind": "raw_dex",
    }]})
    .to_string();
    let (mut handle, mut error) = (0u64, 0u64);
    let status =
        unsafe { mdd_open_snapshot_v1(&view(request.as_bytes()), &mut handle, &mut error) };
    assert_eq!(
        status,
        0,
        "{}",
        if error != 0 {
            error_json(error).to_string()
        } else {
            String::new()
        }
    );
    assert_ne!(handle, 0);
    handle
}

fn session(snapshot: u64) -> u64 {
    let (mut handle, mut error) = (0u64, 0u64);
    let status = unsafe { mdd_open_session_v1(snapshot, &view(b""), &mut handle, &mut error) };
    assert_eq!(status, 0);
    handle
}

fn query(session: u64, sql: &str) -> (u64, u64) {
    let spec = serde_json::json!({"kind": "sql", "sql": sql}).to_string();
    let (mut prepared, mut query, mut error) = (0u64, 0u64, 0u64);
    let status =
        unsafe { mdd_prepare_query_v1(session, &view(spec.as_bytes()), &mut prepared, &mut error) };
    assert_eq!(
        status,
        0,
        "{}",
        if error != 0 {
            error_json(error).to_string()
        } else {
            String::new()
        }
    );
    let status = unsafe { mdd_start_query_v1(prepared, &view(b""), &mut query, &mut error) };
    assert_eq!(status, 0);
    (prepared, query)
}

fn next(query: u64, demand: u32) -> (u32, u64, u64) {
    let (mut event, mut error) = (0u64, 0u64);
    let status = unsafe { mdd_query_next_v1(query, demand, &mut event, &mut error) };
    (status, event, error)
}

fn kind(event: u64) -> u32 {
    let mut kind = 0u32;
    let mut error = 0u64;
    assert_eq!(
        unsafe { mdd_event_kind_v1(event, &mut kind, &mut error) },
        0
    );
    kind
}

fn terminal(event: u64) -> Value {
    let mut v = BytesView {
        ptr: std::ptr::null(),
        len: 0,
    };
    let mut error = 0u64;
    assert_eq!(
        unsafe { mdd_event_terminal_json_v1(event, &mut v, &mut error) },
        0
    );
    serde_json::from_str(&text(v)).unwrap()
}

fn batch_of(event: u64) -> u64 {
    let (mut batch, mut error) = (0u64, 0u64);
    assert_eq!(
        unsafe { mdd_event_batch_v1(event, &mut batch, &mut error) },
        0
    );
    batch
}

fn batch_json(batch: u64) -> Value {
    let mut v = BytesView {
        ptr: std::ptr::null(),
        len: 0,
    };
    let mut error = 0u64;
    assert_eq!(unsafe { mdd_batch_json_v1(batch, &mut v, &mut error) }, 0);
    serde_json::from_str(&text(v)).unwrap()
}

/// Consume a whole stream the way a well-behaved client does. Returns the rows and
/// the terminal envelope.
fn drain(query: u64, demand: u32) -> (Vec<Vec<Value>>, Value) {
    let mut rows = Vec::new();
    loop {
        let (status, event, error) = next(query, demand);
        assert_eq!(
            status,
            0,
            "{}",
            if error != 0 {
                error_json(error).to_string()
            } else {
                String::new()
            }
        );
        match kind(event) {
            EVENT_BATCH => {
                let batch = batch_of(event);
                let json = batch_json(batch);
                for row in json["rows"].as_array().unwrap() {
                    rows.push(row.as_array().unwrap().clone());
                }
                let mut error = 0u64;
                assert_eq!(unsafe { mdd_batch_ack_v1(batch, &mut error) }, 0);
                assert_eq!(mdd_event_release(event), 0);
            }
            EVENT_TERMINAL => {
                let envelope = terminal(event);
                assert_eq!(mdd_event_release(event), 0);
                return (rows, envelope);
            }
            other => panic!("unknown event kind {other}"),
        }
    }
}

fn release_all(snapshot: u64, session: u64, prepared: u64, query: u64) {
    assert_eq!(mdd_query_release(query), 0);
    assert_eq!(mdd_prepared_release(prepared), 0);
    assert_eq!(mdd_session_release(session), 0);
    assert_eq!(mdd_snapshot_release(snapshot), 0);
}

// ---- negotiation ------------------------------------------------------------------

#[test]
fn negotiation_accepts_1_0_and_refuses_other_majors_and_future_minors() {
    let _g = guard();
    let mut info = AbiInfo {
        struct_size: size_of::<AbiInfo>() as u32,
        abi_major: 0,
        abi_minor: 0,
        reserved: 7,
    };
    let mut error = 0u64;
    assert_eq!(
        unsafe { mdd_abi_negotiate_v1(1, 0, &mut info, &mut error) },
        0
    );
    assert_eq!((info.abi_major, info.abi_minor, info.reserved), (1, 0, 0));
    for (major, minor) in [(2, 0), (0, 0), (1, 1)] {
        let status = unsafe { mdd_abi_negotiate_v1(major, minor, &mut info, &mut error) };
        let json = expect_error(status, Status::AbiMismatch, error);
        assert_eq!(json["code"], "ABI_MISMATCH");
        assert_eq!(json["details"]["offered_major"], 1);
    }
    // The caller must say how big its struct is; an older, smaller struct is refused
    // rather than overrun.
    let mut small = AbiInfo {
        struct_size: 4,
        abi_major: 0,
        abi_minor: 0,
        reserved: 0,
    };
    let status = unsafe { mdd_abi_negotiate_v1(1, 0, &mut small, &mut error) };
    expect_error(status, Status::InvalidArgument, error);
    assert_eq!(
        small.abi_major, 0,
        "a refused call wrote into the caller's struct"
    );
}

#[test]
fn capabilities_name_the_profile_as_unadmitted_and_list_what_is_unsupported() {
    let _g = guard();
    let mut v = BytesView {
        ptr: std::ptr::null(),
        len: 0,
    };
    assert_eq!(
        unsafe { mdd_capabilities_json_v1(&mut v, std::ptr::null_mut()) },
        0
    );
    let json: Value = serde_json::from_str(&text(v)).unwrap();
    assert_eq!(json["profile_admitted"], false);
    assert_eq!(json["query_kinds"], serde_json::json!(["sql"]));
    assert_eq!(json["abi"]["major"], 1);
}

// ---- a full stream ----------------------------------------------------------------

#[test]
fn a_full_stream_ends_in_a_complete_terminal_with_derived_coverage() {
    let g = guard();
    let snapshot = snapshot();
    let mut manifest = BytesView {
        ptr: std::ptr::null(),
        len: 0,
    };
    let mut error = 0u64;
    assert_eq!(
        unsafe { mdd_snapshot_manifest_json_v1(snapshot, &mut manifest, &mut error) },
        0
    );
    let manifest: Value = serde_json::from_str(&text(manifest)).unwrap();
    let session = session(snapshot);
    let (prepared, query) = query(session, CLASSES);

    let (rows, envelope) = drain(query, 2);
    assert!(rows.len() >= 2, "the fixture defines several classes");
    assert_eq!(rows[0][0]["t"], "u64");
    assert_eq!(rows[0][1]["t"], "text");
    // The envelope is the verdict, and it is bound to this snapshot and query.
    assert_eq!(envelope["operation_status"], "ok", "{envelope}");
    assert_eq!(envelope["execution"]["complete"], true);
    assert_eq!(envelope["response"]["truncated"], false);
    assert_eq!(envelope["response"]["more_available"], false);
    assert_eq!(envelope["response"]["emitted_rows"], rows.len().to_string());
    assert_eq!(envelope["snapshot_id"], manifest["snapshot_id"]);
    assert_eq!(envelope["profile"], "native-unqualified");
    assert_eq!(envelope["coverage"]["input"], "complete");
    assert_eq!(envelope["coverage"]["facts"], "complete");
    assert!(
        !envelope["coverage"]["scope_id"]
            .as_str()
            .unwrap()
            .is_empty()
    );

    // After the terminal the answer does not change.
    let (status, event, _) = next(query, 1);
    assert_eq!(status, 0);
    assert_eq!(kind(event), EVENT_TERMINAL);
    assert_eq!(terminal(event), envelope);
    assert_eq!(mdd_event_release(event), 0);

    release_all(snapshot, session, prepared, query);
    assert_eq!(live(), g.baseline);
}

#[test]
fn cells_keep_null_exact_integers_and_unpaired_surrogates() {
    let _g = guard();
    let snapshot = snapshot();
    let session = session(snapshot);
    let (prepared, query) = query(
        session,
        "SELECT 9223372036854775807, NULL, '', CAST(x'EDA080' AS TEXT), x'', superclass_type_idx FROM native_classes ORDER BY class_def_idx",
    );
    let (rows, envelope) = drain(query, 100);
    assert_eq!(envelope["operation_status"], "ok", "{envelope}");
    let row = &rows[0];
    assert_eq!(
        row[0],
        serde_json::json!({"t": "i64", "v": "9223372036854775807"})
    );
    assert_eq!(row[1], serde_json::json!({"t": "null"}));
    assert_eq!(row[2], serde_json::json!({"t": "text", "v": ""}));
    // An unpaired surrogate cannot be a JSON string; it travels as UTF-16 units.
    assert_eq!(row[3], serde_json::json!({"t": "text", "units": "d800"}));
    assert_eq!(row[4], serde_json::json!({"t": "bytes", "v": ""}));
    // NULL, empty text and empty bytes are three different cells.
    assert!(rows.iter().any(|r| r[5]["t"] == "null") || rows.iter().all(|r| r[5]["t"] == "u64"));
    release_all(snapshot, session, prepared, query);
}

// ---- ownership ----------------------------------------------------------------------

#[test]
fn double_release_is_a_detected_error_for_every_handle_kind() {
    let _g = guard();
    let snapshot = snapshot();
    let session = session(snapshot);
    let (prepared, query) = query(session, CLASSES);
    let (status, event, _) = next(query, 1);
    assert_eq!(status, 0);
    let batch = batch_of(event);
    let mut retained_error = 0u64;
    assert_eq!(unsafe { mdd_batch_ack_v1(batch, &mut retained_error) }, 0);

    // Release each once, then again: the second call is INVALID_HANDLE, never a fault.
    assert_eq!(mdd_event_release(event), 0);
    assert_eq!(mdd_event_release(event), st(Status::InvalidHandle));
    // The batch's only reference belonged to the event.
    assert_eq!(mdd_batch_release(batch), st(Status::InvalidHandle));
    assert_eq!(mdd_query_release(query), 0);
    assert_eq!(mdd_query_release(query), st(Status::InvalidHandle));
    assert_eq!(mdd_prepared_release(prepared), 0);
    assert_eq!(mdd_prepared_release(prepared), st(Status::InvalidHandle));
    assert_eq!(mdd_session_release(session), 0);
    assert_eq!(mdd_session_release(session), st(Status::InvalidHandle));
    assert_eq!(mdd_snapshot_release(snapshot), 0);
    assert_eq!(mdd_snapshot_release(snapshot), st(Status::InvalidHandle));

    let mut error = 0u64;
    let status = unsafe { mdd_snapshot_close_v1(snapshot, &mut error) };
    expect_error(status, Status::InvalidHandle, error);
    // An error handle is released once like the rest.
    let status = unsafe { mdd_session_close_v1(session, &mut error) };
    assert_eq!(status, st(Status::InvalidHandle));
    assert_eq!(mdd_error_release(error), 0);
    assert_eq!(mdd_error_release(error), st(Status::InvalidHandle));
}

#[test]
fn forged_zero_and_wrong_kind_handles_are_refused_without_touching_anything() {
    let _g = guard();
    let snapshot = snapshot();
    let session = session(snapshot);
    let mut error = 0u64;
    let mut out = 0u64;
    let empty = view(b"");

    // Zero and arbitrary values.
    for forged in [
        0u64,
        1,
        u64::MAX,
        0x0100_0000_0000_0000,
        0x0200_0001_0000_0000,
    ] {
        assert_eq!(
            unsafe { mdd_session_close_v1(forged, &mut error) },
            st(Status::InvalidHandle),
            "{forged:#x}"
        );
        assert_eq!(mdd_error_release(error), 0);
        assert_eq!(
            mdd_snapshot_release(forged),
            st(Status::InvalidHandle),
            "{forged:#x}"
        );
    }
    // A live handle of the wrong kind is just as invalid: a session is not a snapshot.
    let status = unsafe { mdd_open_session_v1(session, &empty, &mut out, &mut error) };
    expect_error(status, Status::InvalidHandle, error);
    assert_eq!(out, 0);
    let status = unsafe { mdd_snapshot_close_v1(session, &mut error) };
    expect_error(status, Status::InvalidHandle, error);
    // The refusals did not disturb the real objects.
    assert_eq!(unsafe { mdd_session_close_v1(session, &mut error) }, 0);
    assert_eq!(mdd_session_release(session), 0);
    assert_eq!(mdd_snapshot_release(snapshot), 0);
}

#[test]
fn a_reused_slot_does_not_answer_to_an_old_handle() {
    let _g = guard();
    let first = snapshot();
    assert_eq!(mdd_snapshot_release(first), 0);
    // Take and give back many, so the first slot is reused with a newer generation.
    let mut seen = Vec::new();
    for _ in 0..8 {
        let next = snapshot();
        assert_ne!(next, first, "a released handle value was reissued");
        seen.push(next);
    }
    let mut error = 0u64;
    for handle in &seen {
        assert_eq!(unsafe { mdd_snapshot_close_v1(*handle, &mut error) }, 0);
    }
    assert_eq!(
        unsafe { mdd_snapshot_close_v1(first, &mut error) },
        st(Status::InvalidHandle)
    );
    assert_eq!(mdd_error_release(error), 0);
    for handle in seen {
        assert_eq!(mdd_snapshot_release(handle), 0);
    }
}

#[test]
fn null_and_misaligned_pointers_are_refused() {
    let _g = guard();
    let mut error = 0u64;
    let status =
        unsafe { mdd_open_snapshot_v1(std::ptr::null(), std::ptr::null_mut(), &mut error) };
    expect_error(status, Status::InvalidArgument, error);

    let request = view(b"{}");
    let status = unsafe { mdd_open_snapshot_v1(&request, std::ptr::null_mut(), &mut error) };
    expect_error(status, Status::InvalidArgument, error);

    // A non-empty request with a null pointer, and one past the size cap.
    let bad = BytesView {
        ptr: std::ptr::null(),
        len: 5,
    };
    let mut out = 0u64;
    let status = unsafe { mdd_open_snapshot_v1(&bad, &mut out, &mut error) };
    expect_error(status, Status::InvalidArgument, error);
    let huge = BytesView {
        ptr: b"x".as_ptr(),
        len: u64::MAX,
    };
    let status = unsafe { mdd_open_snapshot_v1(&huge, &mut out, &mut error) };
    expect_error(status, Status::InvalidArgument, error);

    // A misaligned output pointer is refused, not written through.
    let mut storage = [0u8; 16];
    let misaligned = unsafe { storage.as_mut_ptr().add(1) } as *mut u64;
    let status = unsafe { mdd_capabilities_json_v1(misaligned.cast(), &mut error) };
    expect_error(status, Status::InvalidArgument, error);
    assert_eq!(storage, [0u8; 16]);

    // Malformed JSON and unknown fields are request errors with the field named.
    let status = unsafe {
        mdd_open_snapshot_v1(&view(b"{\"inputs\":[],\"bogus\":1}"), &mut out, &mut error)
    };
    let json = expect_error(status, Status::InvalidArgument, error);
    assert!(
        json["message"].as_str().unwrap().contains("bogus"),
        "{json}"
    );
    let status = unsafe { mdd_open_snapshot_v1(&view(&[0xff, 0xfe]), &mut out, &mut error) };
    expect_error(status, Status::InvalidArgument, error);
    assert_eq!(out, 0);
}

// ---- flow control and batch lifetime --------------------------------------------------

#[test]
fn a_batch_must_be_released_before_the_next_and_acknowledged_before_the_end() {
    let _g = guard();
    let snapshot = snapshot();
    let session = session(snapshot);
    let (prepared, query) = query(session, CLASSES);

    let (status, first, _) = next(query, 1);
    assert_eq!(status, 0);
    let batch = batch_of(first);
    // Still referenced: no second batch yet, and the refusal is retryable.
    let (status, _, error) = next(query, 1);
    let json = expect_error(status, Status::OutstandingBatch, error);
    assert_eq!(json["retryable"], true);

    // Acknowledge and release; now the stream continues.
    let mut error = 0u64;
    assert_eq!(unsafe { mdd_batch_ack_v1(batch, &mut error) }, 0);
    // A second receipt for the same batch is an error.
    let status = unsafe { mdd_batch_ack_v1(batch, &mut error) };
    expect_error(status, Status::InvalidArgument, error);
    assert_eq!(mdd_event_release(first), 0);

    // This one is released WITHOUT being acknowledged.
    let (status, second, _) = next(query, 1);
    assert_eq!(status, 0);
    assert_eq!(kind(second), EVENT_BATCH);
    assert_eq!(mdd_event_release(second), 0);
    let (status, third, _) = next(query, 1);
    assert_eq!(
        status, 0,
        "the failure is reported by the stream, not by the call"
    );
    assert_eq!(kind(third), EVENT_TERMINAL);
    let envelope = terminal(third);
    assert_eq!(envelope["operation_status"], "error", "{envelope}");
    assert_eq!(envelope["error"]["code"], "INVALID_CURSOR");
    assert_eq!(mdd_event_release(third), 0);
    release_all(snapshot, session, prepared, query);
}

#[test]
fn a_retained_batch_outlives_its_event_query_session_and_snapshot() {
    let _g = guard();
    let snapshot = snapshot();
    let session = session(snapshot);
    let (prepared, query) = query(session, CLASSES);
    let (status, event, _) = next(query, 3);
    assert_eq!(status, 0);
    let batch = batch_of(event);
    assert_eq!(mdd_batch_retain(batch), 0);
    let before = batch_json(batch);

    // Release the event, then close and release everything that produced the batch.
    assert_eq!(mdd_event_release(event), 0);
    let mut error = 0u64;
    assert_eq!(unsafe { mdd_query_cancel_v1(query, &mut error) }, 0);
    assert_eq!(unsafe { mdd_session_close_v1(session, &mut error) }, 0);
    release_all(snapshot, session, prepared, query);

    // The batch is still there, byte for byte, and still counts.
    assert_eq!(batch_json(batch), before);
    let mut rows = 0u32;
    assert_eq!(
        unsafe { mdd_batch_row_count_v1(batch, &mut rows, &mut error) },
        0
    );
    assert_eq!(rows as usize, before["rows"].as_array().unwrap().len());
    assert_eq!(mdd_batch_release(batch), 0);
    assert_eq!(mdd_batch_release(batch), st(Status::InvalidHandle));
}

#[test]
fn a_borrowed_batch_handle_cannot_be_released_unless_it_was_retained() {
    let _g = guard();
    let snapshot = snapshot();
    let session = session(snapshot);
    let (prepared, query) = query(session, CLASSES);
    let (status, event, _) = next(query, 2);
    assert_eq!(status, 0);
    let batch = batch_of(event);

    // The event owns the only reference: releasing the borrowed handle is refused and
    // the batch stays readable, so the event is not left pointing at a freed batch.
    assert_eq!(mdd_batch_release(batch), st(Status::InvalidHandle));
    let before = batch_json(batch);
    assert_eq!(batch_json(batch), before);

    // After a retain the caller owns one reference of its own: that one is releasable,
    // exactly once, and the event's reference is untouched by it.
    assert_eq!(mdd_batch_retain(batch), 0);
    assert_eq!(mdd_batch_release(batch), 0);
    assert_eq!(mdd_batch_release(batch), st(Status::InvalidHandle));
    assert_eq!(batch_json(batch), before);

    let mut error = 0u64;
    assert_eq!(unsafe { mdd_batch_ack_v1(batch, &mut error) }, 0);
    assert_eq!(mdd_event_release(event), 0);
    assert_eq!(
        mdd_batch_release(batch),
        st(Status::InvalidHandle),
        "gone with the event"
    );
    release_all(snapshot, session, prepared, query);
}

// ---- close -----------------------------------------------------------------------------

#[test]
fn close_is_idempotent_refuses_new_work_and_keeps_what_exists() {
    let _g = guard();
    let snapshot = snapshot();
    let session = session(snapshot);
    let mut error = 0u64;

    assert_eq!(unsafe { mdd_snapshot_close_v1(snapshot, &mut error) }, 0);
    assert_eq!(
        unsafe { mdd_snapshot_close_v1(snapshot, &mut error) },
        0,
        "close is idempotent"
    );
    // No new session on a closed snapshot...
    let mut out = 0u64;
    let status = unsafe { mdd_open_session_v1(snapshot, &view(b""), &mut out, &mut error) };
    let json = expect_error(status, Status::Closed, error);
    assert_eq!(json["code"], "SNAPSHOT_CLOSED");
    // ...but the session that already existed keeps its lease and still works.
    let (prepared, query) = query(session, CLASSES);
    let (rows, envelope) = drain(query, 50);
    assert!(!rows.is_empty());
    assert_eq!(envelope["operation_status"], "ok");

    assert_eq!(unsafe { mdd_session_close_v1(session, &mut error) }, 0);
    assert_eq!(unsafe { mdd_session_close_v1(session, &mut error) }, 0);
    let spec = serde_json::json!({"kind": "sql", "sql": "SELECT 1"}).to_string();
    let status =
        unsafe { mdd_prepare_query_v1(session, &view(spec.as_bytes()), &mut out, &mut error) };
    expect_error(status, Status::Closed, error);
    release_all(snapshot, session, prepared, query);
}

// ---- cancellation and concurrency ----------------------------------------------------------

/// Far more work than fits in the 60 s query deadline, so only a real cancel ends it early.
const SLOW: &str = "SELECT COUNT(*) FROM native_strings a, native_strings b, native_strings c, native_strings d, native_strings e, native_strings f, native_strings g, native_strings h";

#[test]
fn cancel_before_the_first_batch_ends_in_a_cancelled_terminal_and_after_the_end_is_accepted() {
    let _g = guard();
    let snapshot = snapshot();
    let session = session(snapshot);
    let (prepared, query) = query(session, CLASSES);
    let mut error = 0u64;
    assert_eq!(unsafe { mdd_query_cancel_v1(query, &mut error) }, 0);
    let (rows, envelope) = drain(query, 10);
    assert!(rows.is_empty(), "a cancelled query delivered rows");
    assert_eq!(envelope["operation_status"], "cancelled", "{envelope}");
    assert_eq!(envelope["error"]["code"], "CANCELLED");
    // Cancelling does not downgrade the facts the session had already established.
    assert_eq!(envelope["coverage"]["facts"], "complete", "{envelope}");

    let (prepared2, query2) = self::query(session, CLASSES);
    let (_, ok) = drain(query2, 100);
    assert_eq!(ok["operation_status"], "ok");
    assert_eq!(
        unsafe { mdd_query_cancel_v1(query2, &mut error) },
        0,
        "cancel after the end is accepted"
    );
    assert_eq!(mdd_query_release(query2), 0);
    assert_eq!(mdd_prepared_release(prepared2), 0);
    release_all(snapshot, session, prepared, query);
}

#[test]
fn cancel_from_another_thread_stops_a_running_statement() {
    let _g = guard();
    let snapshot = snapshot();
    let session = session(snapshot);
    let (prepared, query) = query(session, SLOW);

    let started = Instant::now();
    let canceller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        let mut error = 0u64;
        unsafe { mdd_query_cancel_v1(query, &mut error) }
    });
    let (rows, envelope) = drain(query, 10);
    assert_eq!(canceller.join().unwrap(), 0);
    assert!(rows.is_empty());
    assert_eq!(envelope["operation_status"], "cancelled", "{envelope}");
    assert_eq!(envelope["error"]["code"], "CANCELLED");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the cancel did not stop the statement in bounded time"
    );
    release_all(snapshot, session, prepared, query);
}

#[test]
fn a_second_consumer_gets_busy_instead_of_waiting() {
    let _g = guard();
    let snapshot = snapshot();
    let session = session(snapshot);
    let (prepared, query) = query(session, SLOW);

    let consumer = std::thread::spawn(move || {
        // The first consumer: runs the statement inside `next`.
        let (status, event, _) = next(query, 10);
        (status, event)
    });
    // Wait until the first consumer is inside `next`, then try as the second.
    let mut busy = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        let (status, _, error) = next(query, 10);
        if status == st(Status::Busy) {
            busy = Some(expect_error(status, Status::Busy, error));
            break;
        }
        if error != 0 {
            assert_eq!(mdd_error_release(error), 0);
        }
    }
    let json = busy.expect("the second consumer never saw BUSY");
    assert_eq!(json["retryable"], true);
    let mut error = 0u64;
    assert_eq!(unsafe { mdd_query_cancel_v1(query, &mut error) }, 0);
    let (status, event) = consumer.join().unwrap();
    assert_eq!(status, 0);
    assert_eq!(kind(event), EVENT_TERMINAL);
    assert_eq!(terminal(event)["error"]["code"], "CANCELLED");
    assert_eq!(mdd_event_release(event), 0);
    release_all(snapshot, session, prepared, query);
}

#[test]
fn releasing_the_query_handle_while_another_thread_consumes_it_is_safe() {
    let _g = guard();
    let snapshot = snapshot();
    let session = session(snapshot);
    let (prepared, query) = query(session, SLOW);
    let consumer = std::thread::spawn(move || next(query, 10));
    std::thread::sleep(Duration::from_millis(100));
    // The operation in flight holds its own reference to the object.
    assert_eq!(mdd_query_release(query), 0);
    assert_eq!(mdd_query_release(query), st(Status::InvalidHandle));
    // Nobody can reach the query any more, so stop it through the session.
    let mut error = 0u64;
    assert_eq!(unsafe { mdd_session_close_v1(session, &mut error) }, 0);
    let (status, event, _) = consumer.join().unwrap();
    assert_eq!(status, 0);
    assert_eq!(terminal(event)["operation_status"], "cancelled");
    assert_eq!(mdd_event_release(event), 0);
    assert_eq!(mdd_prepared_release(prepared), 0);
    assert_eq!(mdd_session_release(session), 0);
    assert_eq!(mdd_snapshot_release(snapshot), 0);
}

// ---- errors and unsupported forms --------------------------------------------------------------

#[test]
fn unsupported_forms_are_refused_by_name_and_not_ignored() {
    let _g = guard();
    let snapshot = snapshot();
    let mut error = 0u64;
    let mut out = 0u64;

    let layers = view(br#"{"layers":["references"]}"#);
    let status = unsafe { mdd_open_session_v1(snapshot, &layers, &mut out, &mut error) };
    let json = expect_error(status, Status::Unsupported, error);
    assert_eq!(json["code"], "UNSUPPORTED_CAPABILITY");

    let session = session(snapshot);
    let typed = view(br#"{"kind":"typed_ir"}"#);
    let status = unsafe { mdd_prepare_query_v1(session, &typed, &mut out, &mut error) };
    let json = expect_error(status, Status::Unsupported, error);
    assert_eq!(json["code"], "UNSUPPORTED_QUERY");

    let sql = serde_json::json!({"kind": "sql", "sql": "SELECT 1"}).to_string();
    let mut prepared = 0u64;
    assert_eq!(
        unsafe { mdd_prepare_query_v1(session, &view(sql.as_bytes()), &mut prepared, &mut error) },
        0
    );
    let with_params = view(br#"{"parameters":[1]}"#);
    let status = unsafe { mdd_start_query_v1(prepared, &with_params, &mut out, &mut error) };
    expect_error(status, Status::Unsupported, error);

    // Bad SQL is a prepare error that names the stage, not a query that returns nothing.
    let bad = serde_json::json!({"kind": "sql", "sql": "SELEC nothing"}).to_string();
    let status =
        unsafe { mdd_prepare_query_v1(session, &view(bad.as_bytes()), &mut out, &mut error) };
    assert_ne!(status, 0);
    assert_ne!(error, 0);
    error_json(error);

    // demand 0 and demand above the cap are argument errors.
    let (prepared2, query) = self::query(session, CLASSES);
    for demand in [0u32, 10_001] {
        let (status, _, error) = next(query, demand);
        expect_error(status, Status::InvalidArgument, error);
    }
    assert_eq!(mdd_query_release(query), 0);
    assert_eq!(mdd_prepared_release(prepared2), 0);
    assert_eq!(mdd_prepared_release(prepared), 0);
    assert_eq!(mdd_session_release(session), 0);
    assert_eq!(mdd_snapshot_release(snapshot), 0);
}

#[test]
fn a_missing_file_is_an_input_error_with_the_engine_code() {
    let _g = guard();
    let request = serde_json::json!({"inputs": [{"path": "no/such/file.dex", "kind": "raw_dex"}]})
        .to_string();
    let (mut handle, mut error) = (0u64, 0u64);
    let status =
        unsafe { mdd_open_snapshot_v1(&view(request.as_bytes()), &mut handle, &mut error) };
    let json = expect_error(status, Status::InvalidInput, error);
    assert_eq!(handle, 0);
    assert_eq!(json["code"], "INVALID_INPUT");
}

// ---- header ---------------------------------------------------------------------------------------

#[test]
fn the_header_declares_exactly_the_exported_symbols() {
    let header = std::fs::read_to_string(root().join("include/mdd.h")).unwrap();
    let mut declared: Vec<String> = Vec::new();
    for line in header.lines() {
        let line = line.trim_start();
        if line.starts_with("uint32_t mdd_") {
            let name = line["uint32_t ".len()..].split('(').next().unwrap();
            declared.push(name.to_owned());
        }
    }
    declared.sort();
    let mut exported: Vec<String> = EXPORTED_SYMBOLS.iter().map(|s| (*s).to_owned()).collect();
    exported.sort();
    assert_eq!(declared, exported, "include/mdd.h and the exports differ");
    assert!(header.contains("#define MDD_ABI_MAJOR 1"));
    for (name, value) in [
        ("MDD_E_INVALID_HANDLE", Status::InvalidHandle),
        ("MDD_E_BUSY", Status::Busy),
        ("MDD_E_OUTSTANDING_BATCH", Status::OutstandingBatch),
        ("MDD_E_CANCELLED", Status::Cancelled),
        ("MDD_E_ABI_MISMATCH", Status::AbiMismatch),
        ("MDD_E_INTERNAL_FAULT", Status::InternalFault),
    ] {
        let line = header
            .lines()
            .find(|l| l.contains(&format!("#define {name} ")))
            .unwrap();
        assert!(line.contains(&format!("{}u", value as u32)), "{line}");
    }
}

#[test]
fn the_header_exposes_only_fixed_width_scalars_and_two_plain_structs() {
    // No pointer-typed handle, no enum, no Rust-owned type: a handle is a uint64_t and the
    // only aggregates are a (pointer, length) view and a versioned info struct.
    let header = std::fs::read_to_string(root().join("include/mdd.h")).unwrap();
    // Comments explain the rules in words; only the code lines are held to them.
    let code: Vec<&str> = header
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('*') && !line.starts_with("/*"))
        .collect();
    let typedefs: Vec<&&str> = code
        .iter()
        .filter(|line| line.starts_with("typedef "))
        .collect();
    assert!(!typedefs.is_empty());
    for line in typedefs {
        let scalar = line.starts_with("typedef uint64_t mdd_") && line.ends_with(';');
        let aggregate =
            *line == "typedef struct mdd_bytes_view {" || *line == "typedef struct mdd_abi_info {";
        assert!(
            scalar || aggregate,
            "unexpected type in the public header: {line}"
        );
    }
    let joined = code.join(
        "
",
    );
    assert!(
        !joined.contains("enum "),
        "an enum has no fixed layout across the boundary"
    );
    assert!(
        !joined.contains("free("),
        "the header must not invite callers to free library memory"
    );
    for forbidden in ["std::", "Vec<", "String", "Box<", "dyn "] {
        assert!(
            !joined.contains(forbidden),
            "Rust type `{forbidden}` in the header"
        );
    }
}
