/*
 * mdd.h - MeguvizDexDash C ABI, major version 1.
 *
 * This header and the JSON contracts are released together. Symbols carry the
 * prefix `mdd_`; functions whose shape may change in a later minor version carry a
 * `_vN` suffix. Nothing here exposes a Rust String, Vec, trait object, enum layout
 * or an unwinding panic.
 *
 * ---- Calling conventions ---------------------------------------------------
 *
 * Status. Every function returns a uint32_t. 0 is MDD_OK. Anything else is one of
 * the MDD_E_* values below. A successful call is NOT a successful query: the
 * verdict of a query is the terminal event (see mdd_query_next_v1).
 *
 * Errors. Functions that can fail with detail take an optional `out_error`. It is
 * set to 0 on entry and, on failure, to an error handle that the caller must
 * release with mdd_error_release. The error JSON carries the exact engine code
 * (for example "QUOTA_EXCEEDED"), the stage, a message, `retryable` and details.
 *
 * Handles. Handles are 64-bit values, not addresses. They carry a kind and a
 * generation, and every use is checked: a forged, stale, already released or
 * wrong-kind handle returns MDD_E_INVALID_HANDLE and touches no memory. Zero is
 * never valid. Releasing the same handle twice is therefore a detected error, not
 * undefined behaviour. (A pointer that is not a handle at all - an arbitrary
 * address passed where an output pointer is expected - cannot be detected.)
 *
 * Output handles are zeroed on entry, so a failed call never leaves a stale value.
 *
 * Views. A mdd_bytes_view is a length-prefixed byte range with no terminator; it
 * may contain NUL. Request views are read during the call and not kept. Views
 * returned by the library borrow from the object they were read from and stay valid
 * until that object's last release. The caller never frees them, and must not call
 * free() on anything this library returns.
 *
 * close versus release. close is run-time semantics and idempotent: it stops new
 * work on the object (and cancels the unfinished queries of a session). release is
 * memory ownership: it gives back the caller's reference. Closing a snapshot does
 * not invalidate sessions that already exist; closing a session does not invalidate
 * batches already delivered.
 *
 * ---- Threads ------------------------------------------------------------------
 *
 * Snapshots and sessions may be used from several threads. A query has exactly one
 * consumer: while one thread is inside mdd_query_next_v1, a second call on the same
 * query returns MDD_E_BUSY at once (it does not wait). mdd_query_cancel_v1 may be
 * called from any thread at any time, including while another thread is inside
 * mdd_query_next_v1. Releasing a handle that another thread is using is safe: the
 * operation in flight finishes against the object it already holds.
 *
 * ---- Panics ---------------------------------------------------------------------
 *
 * A Rust panic is contained at the boundary and reported as MDD_E_INTERNAL_FAULT;
 * the object it happened in is poisoned and fails its next use. panic=abort, running
 * out of memory and corrupted foreign pointers cannot be contained: callers that
 * need isolation from them use the worker process instead of this ABI.
 */
#ifndef MDD_H
#define MDD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MDD_ABI_MAJOR 1
#define MDD_ABI_MINOR 0

/* ---- Status codes -------------------------------------------------------------- */
#define MDD_OK                    0u
#define MDD_E_INVALID_ARGUMENT    1u  /* bad request, null/misaligned pointer, bad size */
#define MDD_E_INVALID_HANDLE      2u  /* forged, stale, released or wrong-kind handle */
#define MDD_E_CLOSED              3u  /* the snapshot or session is closed */
#define MDD_E_BUSY                4u  /* another thread is consuming this query; retry */
#define MDD_E_OUTSTANDING_BATCH   5u  /* previous batch not fully released; retry */
#define MDD_E_CANCELLED           6u
#define MDD_E_DEADLINE_EXCEEDED   7u
#define MDD_E_QUOTA_EXCEEDED      8u
#define MDD_E_UNSUPPORTED         9u  /* capability or query form not in this version */
#define MDD_E_INCOMPLETE_FACTS    10u
#define MDD_E_INVALID_INPUT       11u /* the input file cannot be captured or parsed */
#define MDD_E_ABI_MISMATCH        12u
#define MDD_E_INTERNAL_FAULT      13u /* includes a contained panic */

/* ---- Event kinds ------------------------------------------------------------------ */
#define MDD_EVENT_BATCH           1u
#define MDD_EVENT_TERMINAL        2u

/* ---- Types ------------------------------------------------------------------------- */
typedef uint64_t mdd_snapshot;
typedef uint64_t mdd_session;
typedef uint64_t mdd_prepared;
typedef uint64_t mdd_query;
typedef uint64_t mdd_event;
typedef uint64_t mdd_batch;
typedef uint64_t mdd_error;

typedef struct mdd_bytes_view {
    const uint8_t *ptr;
    uint64_t len;
} mdd_bytes_view;

typedef struct mdd_abi_info {
    uint32_t struct_size; /* caller sets sizeof(mdd_abi_info) before the call */
    uint32_t abi_major;
    uint32_t abi_minor;
    uint32_t reserved;
} mdd_abi_info;

/* ---- Version negotiation and capabilities ---------------------------------------
 * Fails with MDD_E_ABI_MISMATCH when want_major differs from the library's major
 * or want_min_minor is above the library's minor. out_info->struct_size must be set
 * by the caller. */
uint32_t mdd_abi_negotiate_v1(uint32_t want_major, uint32_t want_min_minor,
                              mdd_abi_info *out_info, mdd_error *out_error);

/* Capabilities as JSON. The view is static for the life of the process. */
uint32_t mdd_capabilities_json_v1(mdd_bytes_view *out_view, mdd_error *out_error);

/* ---- Snapshot ---------------------------------------------------------------------
 * request: {"inputs":[{"path":"...","kind":"raw_dex"|"apk"|"auto","expected_sha256":"..."}]}
 * The snapshot owns private copies of the input bytes; changing the files later does
 * not change it. Strict: no partial success. */
uint32_t mdd_open_snapshot_v1(const mdd_bytes_view *request, mdd_snapshot *out_snapshot,
                              mdd_error *out_error);
/* The manifest as JSON; the view is valid until the snapshot is released. */
uint32_t mdd_snapshot_manifest_json_v1(mdd_snapshot snapshot, mdd_bytes_view *out_view,
                                       mdd_error *out_error);
uint32_t mdd_snapshot_close_v1(mdd_snapshot snapshot, mdd_error *out_error);
uint32_t mdd_snapshot_release(mdd_snapshot snapshot);

/* ---- Session -----------------------------------------------------------------------
 * request (may be empty): {"layers":["metadata","structure"],
 *                          "limits":{"deadline_ms":N,"max_threads":N,"max_queries":N,
 *                                    "max_buffered_bytes":N}}
 * A session holds its snapshot; a snapshot stays alive until its last session is
 * released. Limits are enforced and reported, never queued: a query that cannot get a
 * thread because the session or the process is at its limit ends in a terminal with
 * code QUOTA_EXCEEDED. max_threads defaults to 2 per session, capped by the process. */
uint32_t mdd_open_session_v1(mdd_snapshot snapshot, const mdd_bytes_view *request,
                             mdd_session *out_session, mdd_error *out_error);
uint32_t mdd_session_close_v1(mdd_session session, mdd_error *out_error);
uint32_t mdd_session_release(mdd_session session);

/* ---- Prepared query and query --------------------------------------------------------
 * spec: {"kind":"sql","sql":"..."}. SQL and typed IR are alternatives; this version
 * supports SQL and answers {"kind":"typed_ir"} with MDD_E_UNSUPPORTED. */
uint32_t mdd_prepare_query_v1(mdd_session session, const mdd_bytes_view *spec,
                              mdd_prepared *out_prepared, mdd_error *out_error);
uint32_t mdd_prepared_release(mdd_prepared prepared);

/* request (may be empty): {"parameters":[],"limits":{...}}. A query can lower, never
 * raise, the limits of its session. Query parameters are not supported in this
 * version (a non-empty list is MDD_E_UNSUPPORTED). The statement runs on the thread
 * that first calls mdd_query_next_v1. */
uint32_t mdd_start_query_v1(mdd_prepared prepared, const mdd_bytes_view *request,
                            mdd_query *out_query, mdd_error *out_error);

/* The next event: a batch or the terminal. demand_rows is 1..10000.
 *
 * A call that returns MDD_OK always yields an event. The terminal event is how a
 * stream ends: never a null batch, an empty array or a plain end-of-file. The terminal
 * is the complete result envelope (JSON): operation_status, execution, response and
 * coverage. A query that failed or was cancelled ends in a terminal whose status is
 * "error"; only a terminal with "ok", complete execution, no truncation and complete
 * coverage is a complete result.
 *
 * Flow control: a batch must be acknowledged (mdd_batch_ack_v1) and every reference to
 * it released before the next one is produced. While it is still referenced the call
 * returns MDD_E_OUTSTANDING_BATCH. A batch released without an acknowledgement makes the
 * stream end in a failure terminal. After the terminal, further calls return the same
 * terminal. */
uint32_t mdd_query_next_v1(mdd_query query, uint32_t demand_rows, mdd_event *out_event,
                           mdd_error *out_error);

/* Requests cancellation of an unfinished query, or reports success if it already ended.
 * It does not promise that every thread has stopped; the stream then ends in a
 * terminal with code CANCELLED. */
uint32_t mdd_query_cancel_v1(mdd_query query, mdd_error *out_error);
uint32_t mdd_query_release(mdd_query query);

/* ---- Events ------------------------------------------------------------------------------ */
uint32_t mdd_event_kind_v1(mdd_event event, uint32_t *out_kind, mdd_error *out_error);
/* The batch of a batch event. The handle is borrowed: valid while the event is alive.
 * Call mdd_batch_retain to keep it longer. */
uint32_t mdd_event_batch_v1(mdd_event event, mdd_batch *out_batch, mdd_error *out_error);
/* The terminal envelope as JSON; the view is valid while the event is alive. */
uint32_t mdd_event_terminal_json_v1(mdd_event event, mdd_bytes_view *out_view,
                                    mdd_error *out_error);
uint32_t mdd_event_release(mdd_event event);

/* ---- Batches -------------------------------------------------------------------------------
 * JSON, schema "mdd.sdk-batch.v1": {schema, sequence, first_row, row_count, columns, rows}.
 * Cells are self-describing: {"t":"null"}, {"t":"bool","v":b}, {"t":"i64","v":"dec"},
 * {"t":"u64","v":"dec"}, {"t":"f64","bits":"hex16"}, {"t":"bytes","v":"hex"},
 * {"t":"dex_mutf8","v":"hex","utf16_units":"dec"}, {"t":"text","v":"..."} or, when the
 * text holds an unpaired surrogate, {"t":"text","units":"4 hex digits per UTF-16 unit"}.
 * 64-bit integers are decimal strings; nothing passes through a JSON number.
 *
 * A batch is an independent owned reference: it stays valid after its event, query,
 * session and snapshot are released or closed, until its last release. */
uint32_t mdd_batch_json_v1(mdd_batch batch, mdd_bytes_view *out_view, mdd_error *out_error);
uint32_t mdd_batch_row_count_v1(mdd_batch batch, uint32_t *out_rows, mdd_error *out_error);
uint32_t mdd_batch_sequence_v1(mdd_batch batch, uint64_t *out_sequence, mdd_error *out_error);
/* The consumption receipt. Required before the stream can end successfully; a second
 * acknowledgement of the same batch is an error. */
uint32_t mdd_batch_ack_v1(mdd_batch batch, mdd_error *out_error);
uint32_t mdd_batch_retain(mdd_batch batch);
uint32_t mdd_batch_release(mdd_batch batch);

/* ---- Errors ----------------------------------------------------------------------------------- */
uint32_t mdd_error_json_v1(mdd_error error, mdd_bytes_view *out_view);
uint32_t mdd_error_status_v1(mdd_error error, uint32_t *out_status);
uint32_t mdd_error_release(mdd_error error);

/* ---- Diagnostics (not part of the stable consumer surface) ---------------------------------- */
uint32_t mdd_debug_live_handles_v1(uint64_t *out_count);

#ifdef __cplusplus
}
#endif

#endif /* MDD_H */
