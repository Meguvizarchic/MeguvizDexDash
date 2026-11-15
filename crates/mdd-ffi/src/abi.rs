//! The exported `mdd_*` symbols declared in `include/mdd.h`.
//!
//! Contract shared by every function (the header repeats it):
//! * Every function returns a `u32` status; zero is success. Functions that can fail
//!   with detail take an optional `out_error`; on failure it receives an error handle
//!   that the caller releases with `mdd_error_release`.
//! * Output handles are zeroed first, so a failed call never leaves a stale value.
//! * Pointers are checked for null and alignment, lengths for a hard cap. A pointer
//!   that is non-null, aligned and in range but not actually valid cannot be detected;
//!   that is the caller's contract.
//! * A Rust panic is contained at the boundary and reported as `INTERNAL_FAULT`. The
//!   object it happened in is poisoned, so its next use fails instead of running on
//!   unknown state. `panic=abort`, OOM and corrupted foreign pointers are not
//!   recoverable and are why untrusted callers use the worker instead.
//! * Views (`mdd_bytes_view`) borrow from the object they were read from and stay valid
//!   until that object's last release. The caller never frees them.
#![allow(clippy::missing_safety_doc)]
use crate::{
    engine::{self, Event, PreparedObj, QueryObj, SessionObj, SnapshotObj},
    error::{SdkError, SdkResult, Status},
    handle::{ErrorObj, EventKind, EventObj, Kind, registry},
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

/// Hard cap on a request buffer, so a bad length cannot make us read gigabytes.
const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;

pub const EVENT_BATCH: u32 = 1;
pub const EVENT_TERMINAL: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BytesView {
    pub ptr: *const u8,
    pub len: u64,
}

impl BytesView {
    fn of(bytes: &[u8]) -> Self {
        Self {
            ptr: bytes.as_ptr(),
            len: bytes.len() as u64,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AbiInfo {
    pub struct_size: u32,
    pub abi_major: u32,
    pub abi_minor: u32,
    pub reserved: u32,
}

unsafe fn put<T>(out: *mut T, value: T) -> SdkResult<()> {
    if out.is_null() || !out.is_aligned() {
        return Err(SdkError::invalid("an output pointer is null or misaligned"));
    }
    // SAFETY: non-null and aligned were just checked; validity is the caller's contract.
    unsafe { out.write(value) };
    Ok(())
}

unsafe fn input<'a>(view: *const BytesView) -> SdkResult<&'a [u8]> {
    if view.is_null() || !view.is_aligned() {
        return Err(SdkError::invalid("a request view is null or misaligned"));
    }
    // SAFETY: non-null and aligned were just checked.
    let view = unsafe { *view };
    if view.len == 0 {
        return Ok(&[]);
    }
    if view.ptr.is_null() || view.len > MAX_REQUEST_BYTES {
        return Err(SdkError::invalid(
            "a request view has a null pointer or exceeds the 16 MiB limit",
        ));
    }
    let len = usize::try_from(view.len).map_err(|_| SdkError::invalid("request too large"))?;
    // SAFETY: the pointer is non-null and the length is capped; that it addresses `len`
    // readable bytes for the duration of the call is the caller's contract.
    Ok(unsafe { std::slice::from_raw_parts(view.ptr, len) })
}

fn report(out_error: *mut u64, error: SdkError) -> u32 {
    let status = error.status as u32;
    if !out_error.is_null() && out_error.is_aligned() {
        let object = Arc::new(ErrorObj {
            status,
            json: error.to_json(),
        });
        if let Ok(handle) = registry().insert_error(object) {
            // SAFETY: non-null and aligned were checked above.
            unsafe { out_error.write(handle) };
        }
    }
    status
}

/// Run one exported function: clear `out_error`, contain panics, report errors.
fn run(out_error: *mut u64, body: impl FnOnce() -> SdkResult<()>) -> u32 {
    if !out_error.is_null() && out_error.is_aligned() {
        // SAFETY: non-null and aligned were checked.
        unsafe { out_error.write(0) };
    }
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) => Status::Ok as u32,
        Ok(Err(error)) => report(out_error, error),
        Err(_) => report(
            out_error,
            SdkError::fault("a panic was contained at the ABI boundary; the object is faulted"),
        ),
    }
}

// ---- version negotiation and capabilities --------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_abi_negotiate_v1(
    want_major: u32,
    want_min_minor: u32,
    out_info: *mut AbiInfo,
    out_error: *mut u64,
) -> u32 {
    run(out_error, || {
        if out_info.is_null() || !out_info.is_aligned() {
            return Err(SdkError::invalid("out_info is null or misaligned"));
        }
        // SAFETY: non-null and aligned were checked; the caller owns the struct.
        let size = unsafe { (*out_info).struct_size };
        if (size as usize) < size_of::<AbiInfo>() {
            return Err(SdkError::invalid(
                "out_info->struct_size must be set to sizeof(mdd_abi_info) before the call",
            ));
        }
        if want_major != engine::ABI_MAJOR || want_min_minor > engine::ABI_MINOR {
            return Err(SdkError::new(
                Status::AbiMismatch,
                "ABI_MISMATCH",
                "ffi",
                format!(
                    "requested ABI {want_major}.{want_min_minor}, this library offers {}.{}",
                    engine::ABI_MAJOR,
                    engine::ABI_MINOR
                ),
            )
            .detail("offered_major", engine::ABI_MAJOR)
            .detail("offered_minor", engine::ABI_MINOR));
        }
        // SAFETY: as above.
        unsafe {
            put(
                out_info,
                AbiInfo {
                    struct_size: size_of::<AbiInfo>() as u32,
                    abi_major: engine::ABI_MAJOR,
                    abi_minor: engine::ABI_MINOR,
                    reserved: 0,
                },
            )
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_capabilities_json_v1(
    out_view: *mut BytesView,
    out_error: *mut u64,
) -> u32 {
    run(out_error, || {
        // SAFETY: `put` checks the pointer; the JSON is a process-lifetime static.
        unsafe {
            put(
                out_view,
                BytesView::of(engine::capabilities_json().as_bytes()),
            )
        }
    })
}

// ---- snapshot ------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_open_snapshot_v1(
    request: *const BytesView,
    out_snapshot: *mut u64,
    out_error: *mut u64,
) -> u32 {
    run(out_error, || {
        // SAFETY: each pointer is checked by `put`/`input`.
        unsafe { put(out_snapshot, 0u64)? };
        let request = unsafe { input(request)? };
        let handle = registry().insert_snapshot(SnapshotObj::open(request)?)?;
        unsafe { put(out_snapshot, handle) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_snapshot_manifest_json_v1(
    snapshot: u64,
    out_view: *mut BytesView,
    out_error: *mut u64,
) -> u32 {
    run(out_error, || {
        let snapshot = registry().snapshot(snapshot)?;
        // SAFETY: `put` checks the pointer. The text lives in the snapshot object,
        // which the registry keeps until the snapshot handle is released.
        unsafe { put(out_view, BytesView::of(snapshot.manifest_json().as_bytes())) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_snapshot_close_v1(snapshot: u64, out_error: *mut u64) -> u32 {
    run(out_error, || registry().snapshot(snapshot)?.close())
}

#[unsafe(no_mangle)]
pub extern "C" fn mdd_snapshot_release(snapshot: u64) -> u32 {
    run(std::ptr::null_mut(), || {
        registry().release(snapshot, Kind::Snapshot)
    })
}

// ---- session -------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_open_session_v1(
    snapshot: u64,
    request: *const BytesView,
    out_session: *mut u64,
    out_error: *mut u64,
) -> u32 {
    run(out_error, || {
        // SAFETY: each pointer is checked by `put`/`input`.
        unsafe { put(out_session, 0u64)? };
        let request = unsafe { input(request)? };
        let snapshot = registry().snapshot(snapshot)?;
        let handle = registry().insert_session(SessionObj::open(&snapshot, request)?)?;
        unsafe { put(out_session, handle) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_session_close_v1(session: u64, out_error: *mut u64) -> u32 {
    run(out_error, || registry().session(session)?.close())
}

#[unsafe(no_mangle)]
pub extern "C" fn mdd_session_release(session: u64) -> u32 {
    run(std::ptr::null_mut(), || {
        registry().release(session, Kind::Session)
    })
}

// ---- prepared query and query ---------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_prepare_query_v1(
    session: u64,
    spec: *const BytesView,
    out_prepared: *mut u64,
    out_error: *mut u64,
) -> u32 {
    run(out_error, || {
        // SAFETY: each pointer is checked by `put`/`input`.
        unsafe { put(out_prepared, 0u64)? };
        let spec = unsafe { input(spec)? };
        let session = registry().session(session)?;
        let handle = registry().insert_prepared(PreparedObj::prepare(&session, spec)?)?;
        unsafe { put(out_prepared, handle) }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn mdd_prepared_release(prepared: u64) -> u32 {
    run(std::ptr::null_mut(), || {
        registry().release(prepared, Kind::Prepared)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_start_query_v1(
    prepared: u64,
    request: *const BytesView,
    out_query: *mut u64,
    out_error: *mut u64,
) -> u32 {
    run(out_error, || {
        // SAFETY: each pointer is checked by `put`/`input`.
        unsafe { put(out_query, 0u64)? };
        let request = unsafe { input(request)? };
        let prepared = registry().prepared(prepared)?;
        let handle = registry().insert_query(QueryObj::start(&prepared, request)?)?;
        unsafe { put(out_query, handle) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_query_next_v1(
    query: u64,
    demand_rows: u32,
    out_event: *mut u64,
    out_error: *mut u64,
) -> u32 {
    run(out_error, || {
        // SAFETY: `put` checks the pointer.
        unsafe { put(out_event, 0u64)? };
        let query = registry().query(query)?;
        let kind = match query.next(demand_rows)? {
            Event::Batch(batch) => {
                let handle = registry().insert_batch(batch)?;
                // The event owns this reference; the caller may only release what it retains.
                registry().pin(handle, Kind::Batch)?;
                EventKind::Batch(handle)
            }
            Event::Terminal(terminal) => EventKind::Terminal(terminal),
        };
        // The event owns the batch reference taken above; if the event itself cannot
        // be registered, dropping it hands that reference back.
        let event = Arc::new(EventObj { kind });
        let handle = registry().insert_event(event)?;
        unsafe { put(out_event, handle) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_query_cancel_v1(query: u64, out_error: *mut u64) -> u32 {
    run(out_error, || registry().query(query)?.cancel())
}

#[unsafe(no_mangle)]
pub extern "C" fn mdd_query_release(query: u64) -> u32 {
    run(std::ptr::null_mut(), || {
        registry().release(query, Kind::Query)
    })
}

// ---- events ----------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_event_kind_v1(
    event: u64,
    out_kind: *mut u32,
    out_error: *mut u64,
) -> u32 {
    run(out_error, || {
        let event = registry().event(event)?;
        let kind = match event.kind {
            EventKind::Batch(_) => EVENT_BATCH,
            EventKind::Terminal(_) => EVENT_TERMINAL,
        };
        // SAFETY: `put` checks the pointer.
        unsafe { put(out_kind, kind) }
    })
}

/// The batch inside a batch event. The handle is borrowed: it is valid while the
/// event is, and `mdd_batch_retain` gives the caller an independent reference.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_event_batch_v1(
    event: u64,
    out_batch: *mut u64,
    out_error: *mut u64,
) -> u32 {
    run(out_error, || {
        // SAFETY: `put` checks the pointer.
        unsafe { put(out_batch, 0u64)? };
        let event = registry().event(event)?;
        match event.kind {
            EventKind::Batch(handle) => unsafe { put(out_batch, handle) },
            EventKind::Terminal(_) => {
                Err(SdkError::invalid("this event is a terminal, not a batch"))
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_event_terminal_json_v1(
    event: u64,
    out_view: *mut BytesView,
    out_error: *mut u64,
) -> u32 {
    run(out_error, || {
        let event = registry().event(event)?;
        match &event.kind {
            // SAFETY: `put` checks the pointer. The text is owned by the terminal
            // object that the event holds, and the registry keeps the event alive.
            EventKind::Terminal(terminal) => unsafe {
                put(out_view, BytesView::of(terminal.json().as_bytes()))
            },
            EventKind::Batch(_) => Err(SdkError::invalid("this event is a batch, not a terminal")),
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn mdd_event_release(event: u64) -> u32 {
    run(std::ptr::null_mut(), || {
        registry().release(event, Kind::Event)
    })
}

// ---- batches -----------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_batch_json_v1(
    batch: u64,
    out_view: *mut BytesView,
    out_error: *mut u64,
) -> u32 {
    run(out_error, || {
        let batch = registry().batch(batch)?;
        // SAFETY: `put` checks the pointer. The bytes are owned by the batch, which the
        // registry keeps until its last reference is released.
        unsafe { put(out_view, BytesView::of(batch.bytes())) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_batch_row_count_v1(
    batch: u64,
    out_rows: *mut u32,
    out_error: *mut u64,
) -> u32 {
    run(out_error, || {
        let batch = registry().batch(batch)?;
        // SAFETY: `put` checks the pointer.
        unsafe { put(out_rows, batch.row_count()) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_batch_sequence_v1(
    batch: u64,
    out_sequence: *mut u64,
    out_error: *mut u64,
) -> u32 {
    run(out_error, || {
        let batch = registry().batch(batch)?;
        // SAFETY: `put` checks the pointer.
        unsafe { put(out_sequence, batch.sequence()) }
    })
}

/// Explicit consumption receipt. Without it the stream cannot end successfully.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_batch_ack_v1(batch: u64, out_error: *mut u64) -> u32 {
    run(out_error, || registry().batch(batch)?.acknowledge())
}

#[unsafe(no_mangle)]
pub extern "C" fn mdd_batch_retain(batch: u64) -> u32 {
    run(std::ptr::null_mut(), || {
        registry().retain(batch, Kind::Batch)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn mdd_batch_release(batch: u64) -> u32 {
    run(std::ptr::null_mut(), || {
        registry().release(batch, Kind::Batch)
    })
}

// ---- errors ------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_error_json_v1(error: u64, out_view: *mut BytesView) -> u32 {
    run(std::ptr::null_mut(), || {
        let error = registry().error(error)?;
        // SAFETY: `put` checks the pointer; the text lives in the error object.
        unsafe { put(out_view, BytesView::of(error.json.as_bytes())) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_error_status_v1(error: u64, out_status: *mut u32) -> u32 {
    run(std::ptr::null_mut(), || {
        let error = registry().error(error)?;
        // SAFETY: `put` checks the pointer.
        unsafe { put(out_status, error.status) }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn mdd_error_release(error: u64) -> u32 {
    run(std::ptr::null_mut(), || {
        registry().release(error, Kind::Error)
    })
}

/// Diagnostic: how many handles are alive. A leak check for tests and conformance,
/// not part of the stable consumer surface.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdd_debug_live_handles_v1(out_count: *mut u64) -> u32 {
    run(std::ptr::null_mut(), || {
        // SAFETY: `put` checks the pointer.
        unsafe { put(out_count, registry().live_handles() as u64) }
    })
}

/// The exported symbol names, for the test that checks the header against them.
pub const EXPORTED_SYMBOLS: &[&str] = &[
    "mdd_debug_live_handles_v1",
    "mdd_abi_negotiate_v1",
    "mdd_capabilities_json_v1",
    "mdd_open_snapshot_v1",
    "mdd_snapshot_manifest_json_v1",
    "mdd_snapshot_close_v1",
    "mdd_snapshot_release",
    "mdd_open_session_v1",
    "mdd_session_close_v1",
    "mdd_session_release",
    "mdd_prepare_query_v1",
    "mdd_prepared_release",
    "mdd_start_query_v1",
    "mdd_query_next_v1",
    "mdd_query_cancel_v1",
    "mdd_query_release",
    "mdd_event_kind_v1",
    "mdd_event_batch_v1",
    "mdd_event_terminal_json_v1",
    "mdd_event_release",
    "mdd_batch_json_v1",
    "mdd_batch_row_count_v1",
    "mdd_batch_sequence_v1",
    "mdd_batch_ack_v1",
    "mdd_batch_retain",
    "mdd_batch_release",
    "mdd_error_json_v1",
    "mdd_error_status_v1",
    "mdd_error_release",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_is_contained_and_reported_as_an_internal_fault() {
        let mut error = 0u64;
        let status = run(&mut error, || -> SdkResult<()> {
            panic!("injected for the test")
        });
        assert_eq!(status, Status::InternalFault as u32);
        assert_ne!(
            error, 0,
            "the contained panic must come back as an error object"
        );
        let object = registry().error(error).unwrap();
        assert_eq!(object.status, Status::InternalFault as u32);
        assert!(object.json.contains("INTERNAL_FAULT"), "{}", object.json);
        registry().release(error, Kind::Error).unwrap();
    }

    #[test]
    fn the_error_slot_is_cleared_on_entry_and_stays_zero_on_success() {
        let mut error = 0xdead_beef_u64;
        assert_eq!(run(&mut error, || Ok(())), 0);
        assert_eq!(error, 0);
    }
}
