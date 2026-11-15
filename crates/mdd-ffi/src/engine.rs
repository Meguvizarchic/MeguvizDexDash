//! The safe core behind the C ABI: no raw pointers, no `unsafe`.
//!
//! Snapshots, sessions and queries are the lifecycle objects of `mdd-session`;
//! this layer only adds what the ABI needs on top of them: request parsing, the
//! fact layers and SQL bridge a session reads, one batch stream per query, and the
//! terminal envelope. A query runs on the thread that first calls `next`, so a
//! cancel from another thread has something to stop. Rows are computed completely
//! before the first batch leaves (the contract allows a cursor to consume an
//! already materialised result), then handed out in demand-sized owned batches.
//!
//! A batch must be acknowledged and then fully released before the stream may
//! continue. Skipping the acknowledgement is not a silent success: the stream ends
//! with a failure terminal.
use crate::{
    codec,
    error::{SdkError, SdkResult, Status},
};
use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
use mdd_facts::{DefinitionFacts, MetadataFacts, indexes::SelectedScope};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_session::{
    BatchHandle, Lifecycle, QueryBinding, QueryHandle, QueryPhase, ResourceLimits, SessionHandle,
    SnapshotHandle,
};
use mdd_sql::{
    PreparedSql, SqlBridge,
    control::{SqlControl, SqlLimits},
    dialects::SqlDialect,
    provider::metadata::{CombinedSqlProvider, DefinitionSqlProvider, MetadataSqlProvider},
    values::SqlValue,
};
use mdd_types::{
    Completeness, Coverage, DecimalU64, ErrorCode, MddError, opaque_id,
    result::{ResultIdentity, TerminalBuilder},
};
use serde::Deserialize;
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock, TryLockError, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub const ABI_MAJOR: u32 = 1;
pub const ABI_MINOR: u32 = 0;
/// Explicitly unqualified: no compatibility or release profile is admitted here.
pub const PROFILE: &str = "native-unqualified";
pub const DIALECT: &str = "native-v1";
pub const MAX_BATCH_ROWS: u32 = 10_000;
const MAX_INPUTS: usize = 64;

fn lifecycle() -> &'static Lifecycle {
    static LIFECYCLE: OnceLock<Lifecycle> = OnceLock::new();
    LIFECYCLE.get_or_init(|| {
        // The process-wide ceiling on concurrently running queries. A session still
        // defaults to two and can only lower or, up to this ceiling, raise its own.
        let cores = std::thread::available_parallelism().map_or(2, usize::from);
        Lifecycle::new(ResourceLimits {
            max_threads: cores.max(4),
            ..ResourceLimits::default()
        })
        .expect("process resource limits are valid")
    })
}

/// Lock a mutex that a panicking holder may have poisoned: the object is then
/// reported as faulted instead of being used in an unknown state.
fn lock<'a, T>(mutex: &'a Mutex<T>, what: &str) -> SdkResult<std::sync::MutexGuard<'a, T>> {
    mutex
        .lock()
        .map_err(|_| SdkError::fault(format!("{what} was poisoned by an earlier panic")))
}

fn parse<'a, T: Deserialize<'a>>(bytes: &'a [u8], what: &str) -> SdkResult<T> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| SdkError::invalid(format!("{what} is not valid UTF-8")))?;
    serde_json::from_str(text).map_err(|error| SdkError::invalid(format!("{what}: {error}")))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct LimitsRequest {
    deadline_ms: Option<u64>,
    max_threads: Option<usize>,
    max_queries: Option<usize>,
    max_buffered_bytes: Option<u64>,
}

impl LimitsRequest {
    fn resolve(&self, base: ResourceLimits) -> ResourceLimits {
        ResourceLimits {
            deadline_ms: self.deadline_ms.unwrap_or(base.deadline_ms),
            max_threads: self.max_threads.unwrap_or(base.max_threads),
            max_queries: self.max_queries.unwrap_or(base.max_queries),
            max_buffered_bytes: self.max_buffered_bytes.unwrap_or(base.max_buffered_bytes),
            ..base
        }
    }
}

// ---- capabilities -------------------------------------------------------------

pub fn capabilities_json() -> &'static str {
    static JSON: OnceLock<String> = OnceLock::new();
    JSON.get_or_init(|| {
        serde_json::json!({
            "abi": {"major": ABI_MAJOR, "minor": ABI_MINOR},
            "profile": PROFILE,
            "profile_admitted": false,
            "sql_dialect": DIALECT,
            "query_kinds": ["sql"],
            "fact_layers": ["metadata", "structure"],
            "batch_schema": codec::BATCH_SCHEMA,
            "max_batch_rows": MAX_BATCH_ROWS,
            "parameters": false,
            "temp_catalog": false,
            "unsupported": {
                "typed_ir": "UNSUPPORTED_QUERY",
                "code_layout_references_annotations_layers": "UNSUPPORTED_CAPABILITY"
            },
        })
        .to_string()
    })
}

// ---- snapshot -----------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputRequest {
    path: String,
    kind: Option<String>,
    expected_sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenSnapshotRequest {
    inputs: Vec<InputRequest>,
}

pub struct SnapshotObj {
    snapshot: Arc<Snapshot>,
    inventories: Vec<ArchiveInventory>,
    handle: SnapshotHandle,
    manifest_json: String,
    closed: AtomicBool,
}

impl SnapshotObj {
    pub fn open(request: &[u8]) -> SdkResult<Arc<Self>> {
        let request: OpenSnapshotRequest = parse(request, "open_snapshot request")?;
        if request.inputs.is_empty() || request.inputs.len() > MAX_INPUTS {
            return Err(SdkError::invalid(format!(
                "open_snapshot needs between 1 and {MAX_INPUTS} inputs"
            )));
        }
        let mut specs = Vec::with_capacity(request.inputs.len());
        for input in request.inputs {
            let path = PathBuf::from(input.path);
            let kind = match input.kind.as_deref() {
                Some("raw_dex") => InputKind::RawDex,
                Some("apk") => InputKind::Apk,
                None | Some("auto") => InputKind::detect(&path)?,
                Some(other) => {
                    return Err(SdkError::invalid(format!("unknown input kind `{other}`")));
                }
            };
            specs.push(InputSpec {
                path,
                kind,
                expected_sha256: input.expected_sha256,
            });
        }
        let snapshot = Arc::new(Snapshot::capture(&specs, CaptureLimits::default())?);
        let inventories = snapshot
            .sources()
            .iter()
            .map(|source| {
                ArchiveInventory::build(
                    source,
                    InventoryPolicy::default(),
                    ArchiveLimits::default(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let manifest_json = serde_json::to_string(snapshot.manifest())
            .map_err(|error| SdkError::fault(format!("manifest serialization: {error}")))?;
        let handle = lifecycle().register_snapshot(Arc::clone(&snapshot))?;
        Ok(Arc::new(Self {
            snapshot,
            inventories,
            handle,
            manifest_json,
            closed: AtomicBool::new(false),
        }))
    }

    pub fn manifest_json(&self) -> &str {
        &self.manifest_json
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Idempotent: stops new sessions; sessions that already exist keep their lease.
    pub fn close(&self) -> SdkResult<()> {
        if !self.closed.swap(true, Ordering::AcqRel) {
            lifecycle().close_snapshot(&self.handle)?;
        }
        Ok(())
    }
}

impl Drop for SnapshotObj {
    fn drop(&mut self) {
        let _ = lifecycle().release_snapshot(&self.handle);
    }
}

// ---- session ------------------------------------------------------------------

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct OpenSessionRequest {
    layers: Option<Vec<String>>,
    limits: Option<LimitsRequest>,
}

pub struct SessionObj {
    snapshot: Arc<SnapshotObj>,
    handle: SessionHandle,
    bridge: SqlBridge,
    scope_id: String,
    limits: ResourceLimits,
    closed: AtomicBool,
    queries: Mutex<Vec<Weak<QueryObj>>>,
}

impl SessionObj {
    pub fn open(snapshot: &Arc<SnapshotObj>, request: &[u8]) -> SdkResult<Arc<Self>> {
        if snapshot.is_closed() {
            return Err(SdkError::closed("snapshot"));
        }
        let request: OpenSessionRequest = if request.is_empty() {
            OpenSessionRequest::default()
        } else {
            parse(request, "open_session request")?
        };
        for layer in request.layers.as_deref().unwrap_or(&[]) {
            if layer != "metadata" && layer != "structure" {
                return Err(SdkError::new(
                    Status::Unsupported,
                    "UNSUPPORTED_CAPABILITY",
                    "ffi",
                    format!("fact layer `{layer}` is not available through this ABI version"),
                ));
            }
        }
        let limits = request
            .limits
            .unwrap_or_default()
            .resolve(ResourceLimits::default());

        let mut metadata = Vec::new();
        let mut definitions = Vec::new();
        for inventory in &snapshot.inventories {
            for local in 0..inventory.selected_dexes().len() {
                let facts = Arc::new(MetadataFacts::build(
                    &snapshot.snapshot,
                    inventory,
                    local,
                    StringLimits::default(),
                )?);
                definitions.push(Arc::new(DefinitionFacts::build_arc(
                    Arc::clone(&facts),
                    DefinitionLimits::default(),
                )?));
                metadata.push(facts);
            }
        }
        if metadata.is_empty() {
            return Err(SdkError::new(
                Status::InvalidInput,
                "INVALID_INPUT",
                "ffi",
                "the snapshot selects no DEX",
            ));
        }
        let inventories: Vec<&ArchiveInventory> = snapshot.inventories.iter().collect();
        let scope = SelectedScope::from_inventories(&snapshot.snapshot, &inventories)?;
        let epoch = DecimalU64(0);
        let provider = CombinedSqlProvider::new(
            Arc::new(MetadataSqlProvider::new(metadata, epoch)?),
            Arc::new(DefinitionSqlProvider::new(definitions, epoch)?),
        )?;
        let bridge = SqlBridge::new(
            Arc::new(provider),
            SqlDialect::NativeV1,
            SqlLimits::default(),
        )?;
        let handle = lifecycle().open_session(&snapshot.handle, limits)?;
        Ok(Arc::new(Self {
            snapshot: Arc::clone(snapshot),
            handle,
            bridge,
            scope_id: scope.scope_id().to_owned(),
            limits,
            closed: AtomicBool::new(false),
            queries: Mutex::new(Vec::new()),
        }))
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Idempotent: stops new queries and cancels the unfinished ones of this
    /// session. Batches already delivered stay valid until released.
    pub fn close(&self) -> SdkResult<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let live: Vec<Arc<QueryObj>> = lock(&self.queries, "session query list")?
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        for query in live {
            let _ = query.control.cancel();
        }
        lifecycle().close_session(&self.handle)?;
        Ok(())
    }
}

impl Drop for SessionObj {
    fn drop(&mut self) {
        let _ = lifecycle().release_session(&self.handle);
    }
}

// ---- prepared query -----------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuerySpec {
    kind: String,
    sql: Option<String>,
}

pub struct PreparedObj {
    session: Arc<SessionObj>,
    sql: PreparedSql,
}

impl PreparedObj {
    pub fn prepare(session: &Arc<SessionObj>, spec: &[u8]) -> SdkResult<Arc<Self>> {
        if session.is_closed() {
            return Err(SdkError::closed("session"));
        }
        let spec: QuerySpec = parse(spec, "query spec")?;
        match spec.kind.as_str() {
            "sql" => {}
            "typed_ir" => {
                return Err(SdkError::new(
                    Status::Unsupported,
                    "UNSUPPORTED_QUERY",
                    "ffi",
                    "typed IR queries are not available through this ABI version",
                ));
            }
            other => return Err(SdkError::invalid(format!("unknown query kind `{other}`"))),
        }
        let text = spec
            .sql
            .ok_or_else(|| SdkError::invalid("a sql query spec needs a `sql` string"))?;
        let sql = session.bridge.prepare(&text)?;
        Ok(Arc::new(Self {
            session: Arc::clone(session),
            sql,
        }))
    }
}

// ---- query --------------------------------------------------------------------

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct StartRequest {
    #[serde(default)]
    parameters: Vec<serde_json::Value>,
    limits: Option<LimitsRequest>,
}

pub struct BatchObj {
    handle: BatchHandle,
    rows: u32,
    sequence: u64,
    acked: Arc<AtomicBool>,
}

impl BatchObj {
    pub fn bytes(&self) -> &[u8] {
        self.handle.bytes()
    }

    pub fn row_count(&self) -> u32 {
        self.rows
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Explicit consumption receipt; a second acknowledgement is an error.
    pub fn acknowledge(&self) -> SdkResult<()> {
        self.handle.acknowledge()?;
        self.acked.store(true, Ordering::Release);
        Ok(())
    }
}

pub struct TerminalObj {
    json: String,
}

impl TerminalObj {
    pub fn json(&self) -> &str {
        &self.json
    }
}

pub enum Event {
    Batch(Arc<BatchObj>),
    Terminal(Arc<TerminalObj>),
}

struct Streaming {
    columns: Vec<String>,
    rows: Vec<Vec<SqlValue>>,
    next_row: usize,
    sequence: u64,
    builder: TerminalBuilder,
    last: Option<(Weak<BatchObj>, Arc<AtomicBool>)>,
}

enum Phase {
    Idle,
    Streaming(Box<Streaming>),
    Done(Arc<TerminalObj>),
    /// The stream could not even produce its terminal. Every later call repeats this.
    Broken(SdkError),
}

pub struct QueryObj {
    session: Arc<SessionObj>,
    prepared: Arc<PreparedObj>,
    handle: QueryHandle,
    control: SqlControl,
    state: Mutex<Phase>,
}

impl QueryObj {
    pub fn start(prepared: &Arc<PreparedObj>, request: &[u8]) -> SdkResult<Arc<Self>> {
        let session = &prepared.session;
        if session.is_closed() {
            return Err(SdkError::closed("session"));
        }
        let request: StartRequest = if request.is_empty() {
            StartRequest::default()
        } else {
            parse(request, "start_query request")?
        };
        if !request.parameters.is_empty() {
            return Err(SdkError::new(
                Status::Unsupported,
                "UNSUPPORTED_CAPABILITY",
                "ffi",
                "query parameters are not available through this ABI version",
            ));
        }
        // A query may restrict, never raise, the limits of its session.
        let requested = request.limits.unwrap_or_default().resolve(session.limits);
        let handle = lifecycle().prepare_query(
            &session.handle,
            QueryBinding {
                request_key: opaque_id("sdk-request")?,
                schema_id: "sql-result".to_owned(),
                semantic_version: "mdd.sdk.v1".to_owned(),
            },
            requested,
        )?;
        let deadline = Instant::now().checked_add(Duration::from_millis(
            requested.deadline_ms.min(session.limits.deadline_ms),
        ));
        let control = SqlControl::new(session.bridge.limits(), deadline);
        let query = Arc::new(Self {
            session: Arc::clone(session),
            prepared: Arc::clone(prepared),
            handle,
            control,
            state: Mutex::new(Phase::Idle),
        });
        let mut live = lock(&session.queries, "session query list")?;
        live.retain(|query| query.strong_count() > 0);
        live.push(Arc::downgrade(&query));
        drop(live);
        // A close that ran between the check above and the registration has already
        // drained the list, so this query would escape its cancel: look again.
        if session.is_closed() {
            let _ = query.control.cancel();
            return Err(SdkError::closed("session"));
        }
        Ok(query)
    }

    /// Accepts the cancellation of an unfinished query, or reports that it already
    /// reached a terminal state. It does not claim that every thread has stopped.
    pub fn cancel(&self) -> SdkResult<()> {
        let _ = self.control.cancel();
        match lifecycle().cancel_query(&self.handle) {
            Ok(()) => Ok(()),
            Err(error) => match lifecycle().query_status(&self.handle) {
                Ok(status)
                    if matches!(
                        status.phase,
                        QueryPhase::Completed | QueryPhase::Cancelled | QueryPhase::Failed
                    ) =>
                {
                    Ok(())
                }
                _ => Err(error.into()),
            },
        }
    }

    /// The next batch, or the terminal envelope. Only one thread may be inside this
    /// at a time; a second one gets `Busy` instead of waiting.
    pub fn next(&self, demand: u32) -> SdkResult<Event> {
        if demand == 0 || demand > MAX_BATCH_ROWS {
            return Err(SdkError::invalid(format!(
                "demand_rows must be between 1 and {MAX_BATCH_ROWS}"
            )));
        }
        let mut phase = match self.state.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => {
                return Err(SdkError::new(
                    Status::Busy,
                    "BUSY",
                    "ffi",
                    "another thread is consuming this query",
                )
                .retryable());
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(SdkError::fault("query was poisoned by an earlier panic"));
            }
        };
        if let Phase::Done(terminal) = &*phase {
            return Ok(Event::Terminal(Arc::clone(terminal)));
        }
        if let Phase::Broken(error) = &*phase {
            return Err(error.clone());
        }
        if matches!(&*phase, Phase::Idle) {
            match self.begin() {
                Ok(streaming) => *phase = Phase::Streaming(Box::new(streaming)),
                Err(error) => {
                    let error = self.reconcile(error);
                    return self.fail(&mut phase, None, error, false);
                }
            }
        }
        let Phase::Streaming(stream) = &mut *phase else {
            return Err(SdkError::fault("query is in an unknown phase"));
        };
        if let Some((weak, acked)) = &stream.last {
            if weak.upgrade().is_some() {
                return Err(SdkError::new(
                    Status::OutstandingBatch,
                    "OUTSTANDING_BATCH",
                    "ffi",
                    "the previous batch is still referenced; release it before asking for more",
                )
                .retryable());
            }
            if !acked.load(Ordering::Acquire) {
                let error = MddError::new(
                    ErrorCode::InvalidCursor,
                    "ffi",
                    "a batch was released without being acknowledged",
                );
                let stream = std::mem::replace(&mut *phase, Phase::Idle);
                let Phase::Streaming(stream) = stream else {
                    return Err(SdkError::fault("query is in an unknown phase"));
                };
                return self.fail(&mut phase, Some(*stream), error, true);
            }
        }
        if stream.next_row < stream.rows.len() {
            let start = stream.next_row;
            let end = (start + demand as usize).min(stream.rows.len());
            let bytes = codec::batch_bytes(
                &stream.columns,
                &stream.rows[start..end],
                stream.sequence,
                start as u64,
            );
            let handle = match lifecycle().own_batch(&self.handle, bytes.into_boxed_slice()) {
                Ok(handle) => handle,
                Err(error) => {
                    let stream = std::mem::replace(&mut *phase, Phase::Idle);
                    let Phase::Streaming(stream) = stream else {
                        return Err(SdkError::fault("query is in an unknown phase"));
                    };
                    return self.fail(&mut phase, Some(*stream), error, true);
                }
            };
            let rows = (end - start) as u64;
            stream
                .builder
                .record_batch(stream.sequence, rows)
                .map_err(SdkError::from)?;
            let acked = Arc::new(AtomicBool::new(false));
            let batch = Arc::new(BatchObj {
                handle,
                rows: u32::try_from(rows).map_err(|_| SdkError::fault("batch row overflow"))?,
                sequence: stream.sequence,
                acked: Arc::clone(&acked),
            });
            stream.last = Some((Arc::downgrade(&batch), acked));
            stream.sequence += 1;
            stream.next_row = end;
            return Ok(Event::Batch(batch));
        }
        // Every row was delivered: the stream may only end successfully if the core
        // agrees that every batch was acknowledged and released.
        match lifecycle().finish_delivery(&self.handle) {
            Ok(()) => {
                let envelope = stream.builder.succeed(None).map_err(SdkError::from)?;
                let terminal = self.seal(&envelope)?;
                *phase = Phase::Done(Arc::clone(&terminal));
                Ok(Event::Terminal(terminal))
            }
            Err(error) => {
                let stream = std::mem::replace(&mut *phase, Phase::Idle);
                let Phase::Streaming(stream) = stream else {
                    return Err(SdkError::fault("query is in an unknown phase"));
                };
                self.fail(&mut phase, Some(*stream), error, false)
            }
        }
    }

    /// Run the statement to completion and prepare the stream. Any failure here is
    /// reported as a failure terminal, never as an empty or partial stream.
    fn begin(&self) -> Result<Streaming, MddError> {
        lifecycle().start_query(&self.session.handle, &self.handle, 1)?;
        let result = self
            .session
            .bridge
            .execute(&self.prepared.sql, self.control.clone())?;
        lifecycle().checkpoint(&self.handle)?;
        if !result.calculation_complete() {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "ffi",
                "the statement did not finish its calculation",
            ));
        }
        let columns = result.columns().to_vec();
        let rows = result.rows().to_vec();
        lifecycle().complete_execution(&self.handle)?;
        let epoch = lifecycle().query_status(&self.handle)?.catalog_epoch;
        let mut builder =
            TerminalBuilder::new(self.identity(epoch, result.schema_id())?, self.coverage())?;
        builder.computation_complete(rows.len() as u64)?;
        Ok(Streaming {
            columns,
            rows,
            next_row: 0,
            sequence: 0,
            builder,
            last: None,
        })
    }

    /// Turn an error into the failure terminal. `stream` is the stream that was in
    /// progress, if any; without one the envelope is built from the prepared query.
    fn fail(
        &self,
        phase: &mut Phase,
        stream: Option<Streaming>,
        error: MddError,
        dropped_output: bool,
    ) -> SdkResult<Event> {
        let sealed = (|| {
            let mut builder = match stream {
                Some(stream) => stream.builder,
                None => self.bare_builder()?,
            };
            let envelope = builder
                .fail(error, dropped_output, None)
                .map_err(SdkError::from)?;
            self.seal(&envelope)
        })();
        match sealed {
            Ok(terminal) => {
                *phase = Phase::Done(Arc::clone(&terminal));
                Ok(Event::Terminal(terminal))
            }
            Err(error) => {
                *phase = Phase::Broken(error.clone());
                Err(error)
            }
        }
    }

    /// A builder for a stream that failed before it had a result. Cancellation and
    /// failure of a query do not downgrade fact coverage that the session already
    /// established, so the coverage is the same as for a success.
    fn bare_builder(&self) -> SdkResult<TerminalBuilder> {
        let epoch = lifecycle()
            .query_status(&self.handle)
            .map_or(DecimalU64(0), |status| status.catalog_epoch);
        Ok(TerminalBuilder::new(
            self.identity(epoch, "sql-result".to_owned())?,
            self.coverage(),
        )?)
    }

    fn identity(&self, epoch: DecimalU64, schema_id: String) -> Result<ResultIdentity, MddError> {
        Ok(ResultIdentity {
            request_id: opaque_id("sdk-request")?,
            operation: "query".to_owned(),
            profile: PROFILE.to_owned(),
            sql_dialect: Some(DIALECT.to_owned()),
            session_id: Some(self.session.handle.id().to_owned()),
            snapshot_id: Some(
                self.session
                    .snapshot
                    .snapshot
                    .manifest()
                    .snapshot_id
                    .clone(),
            ),
            catalog_epoch: Some(epoch),
            query_id: Some(self.handle.id().to_owned()),
            schema_id: Some(schema_id),
        })
    }

    /// Facts reach a provider only if their coverage is complete, and the scope is the
    /// one the snapshot's inventories selected, so both are derived here, not asked for.
    fn coverage(&self) -> Coverage {
        let mut required: Vec<String> = self
            .prepared
            .sql
            .required_layers()
            .iter()
            .filter_map(|layer| serde_json::to_value(layer).ok())
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect();
        required.sort();
        Coverage {
            scope_id: self.session.scope_id.clone(),
            input: Completeness::Complete,
            facts: Completeness::Complete,
            required_layers: required,
            issues: Vec::new(),
        }
    }

    /// A query that was cancelled before it ran is refused by the lifecycle with a
    /// phase error; the stream must still end as CANCELLED, which is what happened.
    fn reconcile(&self, error: MddError) -> MddError {
        // Only that one refusal is rewritten. Any other failure keeps its own code, so a
        // statement that was cancelled but failed for another reason says so.
        if error.code != ErrorCode::InvalidArgument || error.stage != "lifecycle" {
            return error;
        }
        match lifecycle().query_status(&self.handle) {
            Ok(status) if status.phase == QueryPhase::Cancelled => {
                status.error.unwrap_or_else(|| {
                    MddError::new(ErrorCode::Cancelled, "ffi", "the query was cancelled")
                })
            }
            _ => error,
        }
    }

    fn seal(&self, envelope: &impl serde::Serialize) -> SdkResult<Arc<TerminalObj>> {
        let json = serde_json::to_string(envelope)
            .map_err(|error| SdkError::fault(format!("terminal serialization: {error}")))?;
        Ok(Arc::new(TerminalObj { json }))
    }
}

impl Drop for QueryObj {
    fn drop(&mut self) {
        let _ = self.control.cancel();
        let _ = lifecycle().release_query(&self.handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn query() -> (Arc<SessionObj>, Arc<QueryObj>) {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/definitions/generated/definitions-038.dex");
        let request = serde_json::json!({"inputs": [{"path": path, "kind": "raw_dex"}]});
        let snapshot = SnapshotObj::open(request.to_string().as_bytes()).unwrap();
        let session = SessionObj::open(&snapshot, b"").unwrap();
        let spec = serde_json::json!({"kind": "sql", "sql": "SELECT 1"});
        let prepared = PreparedObj::prepare(&session, spec.to_string().as_bytes()).unwrap();
        (session, QueryObj::start(&prepared, b"").unwrap())
    }

    #[test]
    fn a_panic_inside_a_query_poisons_it_so_the_next_use_fails_instead_of_running_on() {
        let (_session, query) = query();
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _held = query.state.lock().unwrap();
            panic!("injected while the query state was held");
        }));
        let Err(error) = query.next(1) else {
            panic!("a poisoned query answered");
        };
        assert_eq!(error.status, Status::InternalFault);
        assert!(error.message.contains("poisoned"), "{error:?}");
        // Cancelling does not need the poisoned state, so it still works.
        assert!(query.cancel().is_ok());
    }

    #[test]
    fn a_poisoned_session_list_makes_close_fail_loudly() {
        let (session, _query) = query();
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _held = session.queries.lock().unwrap();
            panic!("injected while the session list was held");
        }));
        let error = session
            .close()
            .expect_err("a poisoned session closed quietly");
        assert_eq!(error.status, Status::InternalFault);
    }
}
