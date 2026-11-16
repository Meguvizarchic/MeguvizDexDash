//! The tools: their published schemas, argument checking and behaviour.
//!
//! Input and output schemas of the eight tools are the ones the reference engine
//! (A0, dexsql 0.1.0) publishes; they are embedded from `tool_schemas.json` and a
//! conformance check compares them with the recorded `tools/list`. Descriptions are
//! this server's own, because several of the reference's describe behaviour this
//! server does not have.
//!
//! A tool is registered only when it is implemented. Not registered, and refused as
//! unknown tools: `get_manifest_components`, `list_resource_files`, `read_resource`,
//! `query_resources`.
use mdd_facts::smali_required::{SmaliLimits, page_text};
use mdd_service::{
    Dataset, Dialect, InputRequest,
    decode::{self, Decoded, Selector},
    manifest::{self, ManifestFailure},
};
use mdd_session::ResourceLimits;
use mdd_sql::{
    provider::hostlab::HostLabRelation,
    temp::{MAX_NAMED_TEMP_QUERIES, NamedTempQuery, TempStatementResult},
    values::{SqlType, SqlValue},
    window::{SqlWindow, script_statements},
};
use mdd_types::{ErrorCode, MddError, opaque_id};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

const SCHEMAS: &str = include_str!("tool_schemas.json");

pub const MAX_INPUTS: usize = 64;
pub const MAX_SQL_ITEMS: usize = 16;
pub const MAX_LIMIT: u64 = 1000;
pub const DEFAULT_LIMIT: u64 = 200;
pub const MAX_WINDOW_END: u64 = 100_000;
/// The most bytes of DEX or archive input one dataset may hold (the snapshot's own cap).
pub const MAX_INPUT_BYTES_PER_DATASET: u64 = 1024 * 1024 * 1024;

/// What the server is configured with.
#[derive(Clone, Debug)]
pub struct Config {
    pub dialect: Dialect,
    /// The deadline of an operation that does not ask for a shorter one.
    pub operation_timeout_ms: u64,
    pub max_datasets: usize,
    /// The input bytes all open datasets may hold together.
    pub max_total_input_bytes: u64,
    /// A response larger than this is refused, never clipped.
    pub max_result_bytes: u64,
    pub sql_limits: mdd_sql::control::SqlLimits,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dialect: Dialect::DexSql010,
            operation_timeout_ms: 300_000,
            max_datasets: 8,
            max_total_input_bytes: 2 * 1024 * 1024 * 1024,
            max_result_bytes: 16 * 1024 * 1024,
            sql_limits: mdd_sql::control::SqlLimits::default(),
        }
    }
}

/// How a tool call failed.
#[derive(Debug)]
pub enum Failure {
    /// The arguments are not what the published schema allows: a JSON-RPC error.
    InvalidParams(String),
    /// No such tool: a JSON-RPC error.
    UnknownTool(String),
    /// The call was understood and could not be done: a tool result with `isError`.
    Execution(MddError),
}

impl From<MddError> for Failure {
    fn from(error: MddError) -> Self {
        Self::Execution(error)
    }
}

fn invalid(message: impl Into<String>) -> Failure {
    Failure::InvalidParams(message.into())
}

fn refuse(code: ErrorCode, message: &str) -> MddError {
    MddError::new(code, "mcp", message)
}

struct Entry {
    id: String,
    dataset: Arc<Dataset>,
    /// What `open_dataset` and `list_datasets` say about it, in the reference's shape.
    summary: Value,
    input_bytes: u64,
    /// The last method rendered, so paging through one long method renders it once.
    decoded: Option<(u32, u32, Arc<Decoded>)>,
}

/// The datasets this server instance minted. An identifier it did not mint, or one it
/// has closed, is refused in the same words; nothing else can name a dataset.
pub struct Registry {
    config: Config,
    open: Vec<Entry>,
}

impl Registry {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            open: Vec::new(),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    fn find(&self, id: &str) -> Result<Arc<Dataset>, MddError> {
        match self.open.iter().find(|e| e.id == id) {
            Some(entry) => Ok(Arc::clone(&entry.dataset)),
            None => Err(unknown_dataset(id)),
        }
    }

    /// Returns whether the dataset was open.
    fn close(&mut self, id: &str) -> bool {
        let Some(position) = self.open.iter().position(|e| e.id == id) else {
            return false;
        };
        self.open.remove(position);
        true
    }

    fn decode_cache(&self, id: &str) -> Option<(u32, u32, Arc<Decoded>)> {
        self.open
            .iter()
            .find(|e| e.id == id)
            .and_then(|e| e.decoded.clone())
    }

    fn set_decode_cache(&mut self, id: &str, file_id: u32, method_idx: u32, decoded: Arc<Decoded>) {
        if let Some(entry) = self.open.iter_mut().find(|e| e.id == id) {
            entry.decoded = Some((file_id, method_idx, decoded));
        }
    }

    fn open_input_bytes(&self) -> u64 {
        self.open.iter().map(|e| e.input_bytes).sum()
    }
}

/// Detail keys that carry a rendering hint from where an error is made to `error_result`.
/// They are namespaced so that no lower layer's own detail can be mistaken for one.
const HINT_KIND: &str = "mcp.kind";
const HINT_DECODE: &str = "mcp.decode";
const HINT_DATASET_ID: &str = "mcp.dataset_id";
const HINT_DATASET_CLOSED: &str = "mcp.dataset_closed";

/// A `kind` the reference spells and a client may branch on. It travels in the error's
/// details until the error is rendered, where it becomes `error.kind`.
fn with_kind(error: MddError, kind: &str) -> MddError {
    error.detail(HINT_KIND, kind)
}

/// The dataset an error belongs to; rendered beside `error`, as the reference does.
fn for_dataset(error: MddError, dataset_id: &str) -> MddError {
    error.detail(HINT_DATASET_ID, dataset_id)
}

fn unknown_dataset(id: &str) -> MddError {
    with_kind(
        refuse(
            ErrorCode::InvalidArgument,
            &format!("dataset \"{id}\" is not open; call open_dataset first"),
        ),
        "unknown_dataset",
    )
}

fn session_quota() -> MddError {
    with_kind(
        refuse(
            ErrorCode::QuotaExceeded,
            "dataset/input-byte quota exhausted; close unused datasets before opening another",
        ),
        "session_quota_exceeded",
    )
}

/// The structured content of a tool error: the reference's `{"error": {"kind", "message"}}`
/// with this engine's own fields beside them. A client written against the reference reads
/// `kind`, `message`, `statement_index` and `dataset_closed`; `code`, `stage`, `retryable` and
/// `details` say more and are never needed to understand the rest.
pub fn error_result(error: &MddError) -> Value {
    let mut details = error.details.clone();
    let kind = match details.remove(HINT_KIND) {
        Some(Value::String(kind)) => kind,
        _ => match error.code {
            ErrorCode::DeadlineExceeded => "timeout".to_owned(),
            ErrorCode::AmbiguousEntity => "ambiguous".to_owned(),
            _ if details.contains_key("statement_index") => "invalid_query".to_owned(),
            code => code.to_string().to_ascii_lowercase(),
        },
    };
    // The reference words an unknown relation as a sentence naming it.
    let message = match (
        error.message.as_str(),
        details.get("relation").and_then(Value::as_str),
    ) {
        ("UNKNOWN_RELATION", Some(name)) => format!("unknown relation `{name}`"),
        _ => error.message.clone(),
    };
    let decode_context = details.remove(HINT_DECODE).is_some();
    let decode_fields: Vec<(&str, Value)> = if decode_context {
        ["code_unit_offset", "file_id", "method_idx"]
            .into_iter()
            .map(|key| {
                let number = details
                    .remove(key)
                    .and_then(|value| value.as_str().and_then(|s| s.parse::<u64>().ok()))
                    .map_or(Value::Null, Value::from);
                (key, number)
            })
            .collect()
    } else {
        Vec::new()
    };
    let dataset_id = details.remove(HINT_DATASET_ID);
    let dataset_closed = details
        .remove(HINT_DATASET_CLOSED)
        .map(|value| value.as_str() == Some("true") || value == Value::Bool(true));
    let statement_index = details
        .get("statement_index")
        .and_then(Value::as_str)
        .and_then(|text| text.parse::<u64>().ok());
    let mut body = Map::new();
    body.insert("kind".to_owned(), json!(kind));
    body.insert("message".to_owned(), json!(message));
    if let Some(closed) = dataset_closed {
        body.insert("dataset_closed".to_owned(), json!(closed));
    }
    if let Some(index) = statement_index {
        body.insert("statement_index".to_owned(), json!(index));
    }
    for (key, value) in decode_fields {
        body.insert(key.to_owned(), value);
    }
    body.insert("code".to_owned(), json!(error.code));
    body.insert("stage".to_owned(), json!(error.stage));
    body.insert("retryable".to_owned(), json!(error.retryable));
    body.insert("details".to_owned(), Value::Object(details));
    let mut result = Map::new();
    if let Some(dataset_id) = dataset_id {
        result.insert("dataset_id".to_owned(), dataset_id);
    }
    result.insert("error".to_owned(), Value::Object(body));
    Value::Object(result)
}

// ---- definitions -------------------------------------------------------------

fn schemas() -> Value {
    serde_json::from_str(SCHEMAS).expect("the embedded tool schemas are JSON")
}

const DESCRIPTIONS: [(&str, &str); 8] = [
    (
        "open_dataset",
        "Open local DEX or APK paths as an isolated, reusable dataset. Returns its identifier, the inputs, their byte total, whether a DEX was found (`has_dex`), the indexes of archive inputs and the preparation time, plus this engine's snapshot identity. Archives without any DEX are not supported yet and are refused.",
    ),
    (
        "list_datasets",
        "List the open datasets as open_dataset described them, with the server's limits and current usage.",
    ),
    (
        "close_dataset",
        "Close a dataset and release it. A dataset that is not open, closed already or never opened here, is refused as unknown_dataset.",
    ),
    (
        "decode",
        "Show one method as smali text, named by its exact descriptor or by file_id and method_idx. A descriptor defined in several DEX files needs file_id. The text is paged by UTF-8 byte offset: continue from next_offset; start_line, end_line and total_lines count lines, total_bytes counts bytes. Mode `smali` (the default for a method) shows the text, `summary` only the method's metadata. A class selection and the `context` mode are not available yet and are refused.",
    ),
    (
        "get_manifest",
        "Read the AndroidManifest.xml of an APK input as a summary: the manifest, application and uses-sdk attributes, the target SDK, component counts and a paged list of permission elements (permission, uses-permission, uses-permission-sdk-23, uses-permission-sdk-m), in document order. `offset` and `next_offset` count permission rows, `limit` is rows per page (1..200, default 200). input_index is the position in open_dataset.inputs and is needed when several archive inputs are open. A reference the archive's resources would resolve is shown as @ and eight hex digits. The `xml` mode is not available yet and is refused.",
    ),
    (
        "list_tables",
        "List the built-in SQL tables. These are the HostLab contract relations this server implements; no dataset is needed.",
    ),
    (
        "describe_table",
        "Describe one built-in SQL table: its columns, types and the fact layers it reads. No dataset is needed.",
    ),
    (
        "query",
        "Run read-only SQL statements with exact typed cells, a row window per statement and next_offset. Use a deterministic ORDER BY when paging: the statement runs again for each page. Rows are never clipped silently: a result over the byte budget is refused. A deadline that expires closes this dataset. With `timing`, the response reports `sql_wall_ms` and `total_ms` as measured here; the phases that happen once at open_dataset (`load_inputs_ms`, `parse_ms`, `table_build_ms`, `cache_total_ms`) are reported as 0.",
    ),
];

/// The `tools/list` entries, in a fixed order.
pub fn definitions() -> Vec<Value> {
    let schemas = schemas();
    DESCRIPTIONS
        .iter()
        .map(|(name, description)| {
            let schema = &schemas[*name];
            let mut tool = Map::new();
            tool.insert("name".to_owned(), json!(name));
            tool.insert("description".to_owned(), json!(description));
            tool.insert("inputSchema".to_owned(), schema["inputSchema"].clone());
            if schema.get("outputSchema").is_some() {
                tool.insert("outputSchema".to_owned(), schema["outputSchema"].clone());
            }
            tool.insert("annotations".to_owned(), schema["annotations"].clone());
            Value::Object(tool)
        })
        .collect()
}

// ---- arguments ----------------------------------------------------------------

fn arguments<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, Failure> {
    let value = if value.is_null() { json!({}) } else { value };
    serde_json::from_value(value).map_err(|error| invalid(error.to_string()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenArgs {
    inputs: Vec<String>,
    timeout_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloseArgs {
    dataset_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DescribeArgs {
    name: String,
}

/// The tools that take no arguments ignore any that are sent, as the reference does.
#[derive(Deserialize)]
struct NoArgs {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedTemp {
    name: String,
    sql: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryArgs {
    dataset_id: String,
    sql: Vec<String>,
    limit: Option<u64>,
    #[serde(default)]
    offset: u64,
    max_bytes: Option<u64>,
    #[serde(default)]
    named_temp_queries: Vec<NamedTemp>,
    timeout_ms: Option<u64>,
    #[serde(default)]
    timing: bool,
}

/// A per-call deadline: shorter than the server's, never longer, never zero.
fn deadline(asked: Option<u64>, config: &Config) -> Result<u64, Failure> {
    match asked {
        None => Ok(config.operation_timeout_ms),
        Some(0) => Err(invalid("timeout_ms must be positive")),
        Some(ms) if ms > config.operation_timeout_ms => Err(invalid(format!(
            "timeout_ms cannot exceed the server's timeout of {} ms",
            config.operation_timeout_ms
        ))),
        Some(ms) => Ok(ms),
    }
}

enum Outcome<T> {
    Done(T),
    TimedOut,
    Panicked,
}

/// Run `work` on its own thread and wait for it, at most `ms`. A thread that outlives
/// its deadline cannot be stopped; it ends when the engine's own budgets end it, and its
/// result is dropped.
fn with_deadline<T: Send + 'static>(
    ms: u64,
    work: impl FnOnce() -> T + Send + 'static,
) -> Outcome<T> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(work());
    });
    match receiver.recv_timeout(Duration::from_millis(ms)) {
        Ok(value) => Outcome::Done(value),
        Err(mpsc::RecvTimeoutError::Timeout) => Outcome::TimedOut,
        Err(mpsc::RecvTimeoutError::Disconnected) => Outcome::Panicked,
    }
}

fn timed_out(what: &str, ms: u64) -> MddError {
    MddError::new(
        ErrorCode::DeadlineExceeded,
        "mcp",
        format!("{what} exceeded its deadline"),
    )
    .detail("deadline_ms", ms.to_string())
}

fn panicked(what: &str) -> MddError {
    MddError::new(
        ErrorCode::InternalFault,
        "mcp",
        format!("{what} stopped unexpectedly"),
    )
}

// ---- dispatch -----------------------------------------------------------------

pub fn call(registry: &mut Registry, name: &str, arguments_value: Value) -> Result<Value, Failure> {
    match name {
        "open_dataset" => open_dataset(registry, arguments(arguments_value)?),
        "list_datasets" => {
            arguments::<NoArgs>(arguments_value)?;
            Ok(list_datasets(registry))
        }
        "close_dataset" => close_dataset(registry, arguments(arguments_value)?),
        "decode" => decode_method(registry, arguments(arguments_value)?),
        "get_manifest" => get_manifest(registry, arguments(arguments_value)?),
        "list_tables" => {
            arguments::<NoArgs>(arguments_value)?;
            Ok(list_tables())
        }
        "describe_table" => describe_table(arguments(arguments_value)?),
        "query" => query(registry, arguments(arguments_value)?),
        other => Err(Failure::UnknownTool(other.to_owned())),
    }
}

// ---- lifecycle ----------------------------------------------------------------

fn open_dataset(registry: &mut Registry, args: OpenArgs) -> Result<Value, Failure> {
    if args.inputs.is_empty() || args.inputs.len() > MAX_INPUTS {
        return Err(invalid(format!(
            "inputs must hold between 1 and {MAX_INPUTS} paths"
        )));
    }
    if args.inputs.iter().any(String::is_empty) {
        return Err(invalid("an input path may not be empty"));
    }
    let ms = deadline(args.timeout_ms, &registry.config)?;
    if registry.open.len() >= registry.config.max_datasets {
        return Err(session_quota()
            .detail("budget", "max_datasets")
            .detail("limit", registry.config.max_datasets.to_string())
            .detail("observed", (registry.open.len() + 1).to_string())
            .into());
    }
    let requests: Vec<InputRequest> = args
        .inputs
        .iter()
        .map(|path| InputRequest {
            path: PathBuf::from(path),
            kind: None,
        })
        .collect();
    let dialect = registry.config.dialect;
    let sql_limits = registry.config.sql_limits;
    let limits = ResourceLimits {
        deadline_ms: registry.config.operation_timeout_ms,
        ..ResourceLimits::default()
    };
    let started = Instant::now();
    let opened = match with_deadline(ms, move || {
        Dataset::open(&requests, dialect, limits, sql_limits)
    }) {
        Outcome::Done(result) => result?,
        Outcome::TimedOut => return Err(timed_out("open_dataset", ms).into()),
        Outcome::Panicked => return Err(panicked("open_dataset").into()),
    };
    let prepare_ms = started.elapsed().as_secs_f64() * 1000.0;
    let dataset = Arc::new(opened);
    let input_bytes = dataset.input_bytes();
    if registry
        .open_input_bytes()
        .checked_add(input_bytes)
        .is_none_or(|total| total > registry.config.max_total_input_bytes)
    {
        return Err(session_quota()
            .detail("budget", "max_total_input_bytes")
            .detail("limit", registry.config.max_total_input_bytes.to_string())
            .detail("observed", input_bytes.to_string())
            .into());
    }
    let id = opaque_id("dataset")?;
    let description = dataset.description();
    let manifest = serde_json::to_value(dataset.snapshot().manifest())
        .map_err(|error| refuse(ErrorCode::InternalFault, &error.to_string()))?;
    let archive_inputs = dataset.archive_inputs();
    let mut summary = json!({
        "archive_inputs": archive_inputs,
        "dataset_id": id,
        "has_dex": true,
        "input_bytes": input_bytes,
        "inputs": args.inputs,
        "prepare_ms": prepare_ms,
    });
    registry.open.push(Entry {
        id: id.clone(),
        dataset,
        summary: summary.clone(),
        input_bytes,
        decoded: None,
    });
    let diagnostics = description["layer_issues"]
        .as_array()
        .map(|issues| {
            issues
                .iter()
                .map(|issue| {
                    json!({
                        "code": "LAYER_UNAVAILABLE",
                        "message": format!(
                            "the {} layers of {} could not be built; relations that need them are refused",
                            issue["layers"].as_str().unwrap_or("upper"),
                            issue["dex_occurrence_id"].as_str().unwrap_or("a DEX"),
                        ),
                        "detail": issue["error"],
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    // Beside the reference's fields, this engine says which snapshot the dataset reads.
    let extra = json!({
        "snapshot_id": description["snapshot_id"],
        "scope_id": description["scope_id"],
        "profile": description["profile"],
        "sql_dialect": description["sql_dialect"],
        "dex_count": description["dex_count"],
        "snapshot_manifest": manifest,
        "diagnostics": diagnostics,
    });
    if let (Value::Object(base), Value::Object(extra)) = (&mut summary, extra) {
        base.extend(extra);
    }
    Ok(summary)
}

fn list_datasets(registry: &Registry) -> Value {
    let config = &registry.config;
    json!({
        "admitted_requests": 0,
        "datasets": registry
            .open
            .iter()
            .map(|entry| {
                // The reference's six fields only: the identity fields are open_dataset's.
                let mut shown = Map::new();
                for key in ["archive_inputs", "dataset_id", "has_dex", "input_bytes", "inputs", "prepare_ms"] {
                    shown.insert(key.to_owned(), entry.summary[key].clone());
                }
                Value::Object(shown)
            })
            .collect::<Vec<_>>(),
        "limits": {
            "max_datasets": config.max_datasets,
            "max_dex_bytes": MAX_INPUT_BYTES_PER_DATASET,
            "max_input_bytes": MAX_INPUT_BYTES_PER_DATASET,
            "max_output_bytes": config.max_result_bytes,
            // Requests are served one at a time, so nothing waits beside the one running.
            "max_pending": 1,
            // No resource tool exists yet; the figure is the dataset's input cap.
            "max_resource_bytes": MAX_INPUT_BYTES_PER_DATASET,
            "max_total_input_bytes": config.max_total_input_bytes,
            "timeout_ms": config.operation_timeout_ms,
        },
        "running_requests": 0,
        "usage": {"datasets": registry.open.len(), "input_bytes": registry.open_input_bytes()},
    })
}

fn close_dataset(registry: &mut Registry, args: CloseArgs) -> Result<Value, Failure> {
    if registry.close(&args.dataset_id) {
        return Ok(json!({"closed": true, "dataset_id": args.dataset_id}));
    }
    Err(unknown_dataset(&args.dataset_id).into())
}

// ---- decode -------------------------------------------------------------------

pub const MAX_LINES: u64 = 1000;
pub const DEFAULT_LINES: u64 = 200;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodeArgs {
    dataset_id: String,
    class: Option<String>,
    file_id: Option<u32>,
    max_bytes: Option<u64>,
    max_lines: Option<u64>,
    method: Option<String>,
    method_idx: Option<u32>,
    method_limit: Option<u64>,
    #[serde(default)]
    method_offset: u64,
    mode: Option<String>,
    #[serde(default)]
    offset: u64,
    timeout_ms: Option<u64>,
}

fn decode_error(error: MddError, dataset_id: &str) -> MddError {
    for_dataset(error, dataset_id).detail(HINT_DECODE, "true")
}

/// `{0, 1}`, the way the reference lists the DEX files that define one descriptor.
fn file_id_set(ids: &[u32]) -> String {
    let inner: Vec<String> = ids.iter().map(u32::to_string).collect();
    format!("{{{}}}", inner.join(", "))
}

fn decode_method(registry: &mut Registry, args: DecodeArgs) -> Result<Value, Failure> {
    let mode = match args.mode.as_deref() {
        None | Some("smali") => "smali",
        Some("summary") => "summary",
        Some("context") => "context",
        Some(_) => return Err(invalid("mode must be summary, smali or context")),
    };
    let max_lines = args.max_lines.unwrap_or(DEFAULT_LINES);
    if !(1..=MAX_LINES).contains(&max_lines) {
        return Err(invalid(format!(
            "max_lines must be between 1 and {MAX_LINES}"
        )));
    }
    if args.method_limit.is_some_and(|n| !(1..=50).contains(&n)) {
        return Err(invalid("method_limit must be between 1 and 50"));
    }
    let ms = deadline(args.timeout_ms, &registry.config)?;
    let id = args.dataset_id.clone();
    let refuse_here = |code: ErrorCode, message: &str| decode_error(refuse(code, message), &id);
    let selectors = u8::from(args.method.is_some())
        + u8::from(args.method_idx.is_some())
        + u8::from(args.class.is_some());
    if selectors != 1 {
        return Err(refuse_here(
            ErrorCode::InvalidArgument,
            "give exactly one of method, method_idx (with file_id) or class",
        )
        .into());
    }
    if args.class.is_some() {
        return Err(with_kind(
            refuse_here(
                ErrorCode::UnsupportedCapability,
                "decode of a class is not available yet; name a method",
            ),
            "not_implemented",
        )
        .into());
    }
    if mode == "context" {
        return Err(with_kind(
            refuse_here(
                ErrorCode::UnsupportedCapability,
                "the context mode is not available yet; use smali",
            ),
            "not_implemented",
        )
        .into());
    }
    if args.method_idx.is_some() && args.file_id.is_none() {
        return Err(refuse_here(ErrorCode::InvalidArgument, "method_idx needs file_id").into());
    }
    if args.method.as_deref() == Some("") {
        return Err(refuse_here(ErrorCode::InvalidArgument, "descriptor must not be empty").into());
    }
    if mode == "summary" && args.offset != 0 {
        return Err(refuse_here(
            ErrorCode::InvalidArgument,
            "offset applies to the smali text; summary has none",
        )
        .into());
    }
    if args.method_offset != 0 {
        return Err(refuse_here(
            ErrorCode::InvalidArgument,
            "method_offset applies to a class's method list; a method has one page of methods",
        )
        .into());
    }
    let dataset = registry.find(&args.dataset_id)?;
    let cached = registry.decode_cache(&id);
    let method = args.method.clone();
    let (file_id, method_idx) = (args.file_id, args.method_idx);
    let work = move || -> Result<Arc<Decoded>, decode::Failure> {
        let selector = match (&method, method_idx) {
            (Some(descriptor), _) => Selector::Descriptor {
                descriptor,
                file_id,
            },
            (None, Some(method_idx)) => Selector::Key {
                file_id: file_id.expect("checked: method_idx comes with file_id"),
                method_idx,
            },
            (None, None) => unreachable!("checked: exactly one selector"),
        };
        let located = decode::select(&dataset, selector)?;
        if let Some((cached_file, cached_idx, decoded)) = cached
            && (cached_file, cached_idx) == (located.file_id, located.method_idx)
        {
            return Ok(decoded);
        }
        Ok(Arc::new(decode::render(
            &dataset,
            located,
            SmaliLimits::default(),
        )?))
    };
    let result = match with_deadline(ms, work) {
        Outcome::Done(result) => result,
        Outcome::TimedOut => {
            registry.close(&id);
            return Err(refuse(
                ErrorCode::DeadlineExceeded,
                "running computation was terminated and this dataset was closed; call open_dataset to use it again",
            )
            .detail("deadline_ms", ms.to_string())
            .detail("mcp.dataset_id", id.as_str())
            .detail("mcp.dataset_closed", "true")
            .into());
        }
        Outcome::Panicked => {
            registry.close(&id);
            return Err(panicked("decode")
                .detail("mcp.dataset_id", id.as_str())
                .detail("mcp.dataset_closed", "true")
                .into());
        }
    };
    let decoded = match result {
        Ok(decoded) => decoded,
        Err(decode::Failure::NotFound { what }) => {
            // The request is echoed the way the reference does, so a client can tell which of
            // its requests was not found.
            let mut error = with_kind(refuse_here(ErrorCode::InvalidArgument, &what), "not_found");
            if let Some(file_id) = args.file_id {
                error = error.detail("file_id", file_id.to_string());
            }
            if let Some(method_idx) = args.method_idx {
                error = error.detail("method_idx", method_idx.to_string());
            }
            return Err(error.into());
        }
        Err(decode::Failure::Ambiguous { file_ids }) => {
            return Err(with_kind(
                refuse_here(
                    ErrorCode::AmbiguousEntity,
                    &format!(
                        "method occurs in multiple DEX files; supply file_id from {}",
                        file_id_set(&file_ids)
                    ),
                ),
                "ambiguous",
            )
            .into());
        }
        Err(decode::Failure::Error(error)) => {
            let mut error = decode_error(error, &id);
            if let Some(file_id) = args.file_id {
                error = error.detail("file_id", file_id.to_string());
            }
            if let Some(method_idx) = args.method_idx {
                error = error.detail("method_idx", method_idx.to_string());
            }
            return Err(error.into());
        }
    };
    registry.set_decode_cache(
        &id,
        decoded.file_id,
        decoded.method_idx,
        Arc::clone(&decoded),
    );
    let rendered = &decoded.rendered;
    let mut method = json!({
        "access_flags": decoded.access_flags,
        "code_units": rendered.code_units,
        "declaration": rendered.declaration,
        "descriptor": decoded.descriptor,
        "file_id": decoded.file_id,
        "method_idx": decoded.method_idx,
        "registers": rendered.registers,
        "try_count": rendered.try_count,
    });
    if mode == "summary" {
        // The summary has no text to continue, but a client that follows `next_offset`
        // finds the key in every mode.
        if let Value::Object(fields) = &mut method {
            fields.insert("next_offset".to_owned(), Value::Null);
        }
    }
    if mode == "smali" {
        let page =
            page_text(&rendered.text, args.offset, max_lines, args.max_bytes).map_err(|error| {
                // Where the page cannot start is a range problem; a byte budget no character
                // fits in is a problem with the argument.
                let kind = if error.message.starts_with("OFFSET_") {
                    "invalid_range"
                } else {
                    "invalid_input"
                };
                with_kind(decode_error(error, &id), kind)
            })?;
        let Value::Object(fields) = &mut method else {
            unreachable!("a json object");
        };
        for (key, value) in [
            ("end_line", json!(page.end_line)),
            ("ends_mid_line", json!(page.ends_mid_line)),
            ("next_offset", json!(page.next_offset)),
            ("offset", json!(page.offset)),
            ("smali", json!(page.text)),
            ("start_line", json!(page.start_line)),
            ("starts_mid_line", json!(page.starts_mid_line)),
            ("total_bytes", json!(page.total_bytes)),
            ("total_lines", json!(page.total_lines)),
        ] {
            fields.insert(key.to_owned(), value);
        }
    }
    let output = json!({
        "dataset_id": id,
        "method_offset": 0,
        "methods": [method],
        "mode": mode,
        "next_method_offset": null,
        "total_methods": 1,
    });
    let size = serde_json::to_string(&output)
        .map_err(|error| refuse(ErrorCode::InternalFault, &error.to_string()))?
        .len() as u64;
    if size > registry.config.max_result_bytes {
        return Err(refuse(
            ErrorCode::QuotaExceeded,
            "the serialized result is over the byte budget",
        )
        .detail("budget", "max_result_bytes")
        .detail("limit", registry.config.max_result_bytes.to_string())
        .detail("observed", size.to_string())
        .into());
    }
    Ok(output)
}

// ---- get_manifest ---------------------------------------------------------------

pub const MAX_MANIFEST_LIMIT: u64 = 200;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestArgs {
    dataset_id: String,
    input_index: Option<u64>,
    limit: Option<u64>,
    max_bytes: Option<u64>,
    mode: Option<String>,
    #[serde(default)]
    offset: u64,
    timeout_ms: Option<u64>,
}

fn get_manifest(registry: &mut Registry, args: ManifestArgs) -> Result<Value, Failure> {
    match args.mode.as_deref() {
        None | Some("summary") => {}
        Some("xml") => {
            return Err(with_kind(
                refuse(
                    ErrorCode::UnsupportedCapability,
                    "the xml mode is not available yet; use summary",
                ),
                "not_implemented",
            )
            .detail("mcp.dataset_id", args.dataset_id.as_str())
            .into());
        }
        Some(_) => return Err(invalid("mode must be summary or xml")),
    }
    let limit = args.limit.unwrap_or(MAX_MANIFEST_LIMIT);
    if !(1..=MAX_MANIFEST_LIMIT).contains(&limit) {
        return Err(invalid(format!(
            "limit must be between 1 and {MAX_MANIFEST_LIMIT}"
        )));
    }
    let ms = deadline(args.timeout_ms, &registry.config)?;
    let budget = args
        .max_bytes
        .map_or(registry.config.max_result_bytes, |b| {
            b.min(registry.config.max_result_bytes)
        });
    let dataset = registry.find(&args.dataset_id)?;
    let id = args.dataset_id.clone();
    let wrong = |code: ErrorCode, message: &str, kind: &str| {
        Failure::Execution(with_kind(
            refuse(code, message).detail("mcp.dataset_id", id.as_str()),
            kind,
        ))
    };
    let archives = dataset.archive_inputs();
    let input_index = match (args.input_index, archives.as_slice()) {
        (Some(wanted), _) => usize::try_from(wanted).unwrap_or(usize::MAX),
        (None, [only]) => *only,
        (None, []) => {
            return Err(wrong(
                ErrorCode::InvalidArgument,
                "this dataset has no archive input, so it has no manifest",
                "not_archive",
            ));
        }
        (None, _) => {
            return Err(wrong(
                ErrorCode::InvalidArgument,
                "input_index is required when several archive inputs are open",
                "invalid_argument",
            ));
        }
    };
    let work = move || -> Result<manifest::Summary, ManifestFailure> {
        let document = dataset.manifest(input_index)?;
        Ok(manifest::summarize(&document)?)
    };
    let summary = match with_deadline(ms, work) {
        Outcome::Done(Ok(summary)) => summary,
        Outcome::Done(Err(ManifestFailure::NoSuchInput(message))) => {
            return Err(wrong(ErrorCode::InvalidArgument, &message, "not_archive"));
        }
        Outcome::Done(Err(ManifestFailure::Missing(message))) => {
            return Err(wrong(ErrorCode::InvalidInput, &message, "not_found"));
        }
        Outcome::Done(Err(ManifestFailure::Several(message))) => {
            return Err(wrong(ErrorCode::AmbiguousEntity, &message, "ambiguous"));
        }
        Outcome::Done(Err(ManifestFailure::Error(error))) => {
            return Err(error.detail("mcp.dataset_id", id.as_str()).into());
        }
        Outcome::TimedOut => {
            registry.close(&id);
            return Err(refuse(
                ErrorCode::DeadlineExceeded,
                "running computation was terminated and this dataset was closed; call open_dataset to use it again",
            )
            .detail("deadline_ms", ms.to_string())
            .detail("mcp.dataset_id", id.as_str())
            .detail("mcp.dataset_closed", "true")
            .into());
        }
        Outcome::Panicked => {
            registry.close(&id);
            return Err(panicked("get_manifest")
                .detail("mcp.dataset_id", id.as_str())
                .detail("mcp.dataset_closed", "true")
                .into());
        }
    };
    let total = summary.permissions.len() as u64;
    if args.offset > total {
        return Err(wrong(
            ErrorCode::InvalidArgument,
            "offset is past the last permission row",
            "invalid_range",
        ));
    }
    let end = total.min(args.offset.saturating_add(limit));
    let rows = &summary.permissions[args.offset as usize..end as usize];
    let next_offset = (end < total).then_some(end);
    let output = json!({
        "application": summary.application,
        "component_counts": summary.component_counts,
        "dataset_id": id,
        "input_index": input_index,
        "manifest": summary.manifest,
        "next_offset": next_offset,
        "offset": args.offset,
        "permissions": rows,
        "target_sdk": summary.target_sdk,
        "total_rows": total,
        "truncated": next_offset.is_some(),
        "uses_sdk": summary.uses_sdk,
    });
    let size = serde_json::to_string(&output)
        .map_err(|error| refuse(ErrorCode::InternalFault, &error.to_string()))?
        .len() as u64;
    if size > budget {
        return Err(refuse(
            ErrorCode::QuotaExceeded,
            "the serialized result is over the byte budget",
        )
        .detail("budget", "max_bytes")
        .detail("limit", budget.to_string())
        .detail("observed", size.to_string())
        .into());
    }
    Ok(output)
}

// ---- tables -------------------------------------------------------------------

fn type_name(kind: SqlType) -> &'static str {
    match kind {
        SqlType::Bool | SqlType::I64 => "int64",
        SqlType::U64 => "uint64",
        SqlType::F64 => "float64",
        SqlType::Text => "utf8",
        SqlType::Bytes => "binary",
    }
}

fn list_tables() -> Value {
    let tables: Vec<Value> = HostLabRelation::ALL
        .iter()
        .map(|relation| {
            json!({
                "name": relation.name(),
                "kind": "table",
                "column_count": relation.columns().len(),
            })
        })
        .collect();
    json!({"tables": tables})
}

fn describe_table(args: DescribeArgs) -> Result<Value, Failure> {
    let relation = HostLabRelation::ALL
        .iter()
        .copied()
        .find(|relation| relation.name().eq_ignore_ascii_case(&args.name))
        .ok_or_else(|| {
            Failure::Execution(with_kind(
                refuse(ErrorCode::InvalidArgument, "UNKNOWN_TABLE")
                    .detail("name", args.name.clone()),
                "unknown_table",
            ))
        })?;
    let columns: Vec<Value> = relation
        .columns()
        .iter()
        .map(|(name, kind, nullable)| json!({"name": name, "data_type": type_name(*kind), "nullable": nullable}))
        .collect();
    let layers: Vec<Value> = relation
        .required_layers()
        .iter()
        .filter_map(|layer| serde_json::to_value(layer).ok())
        .collect();
    Ok(json!({"name": relation.name(), "kind": "table", "columns": columns, "fact_layers": layers}))
}

// ---- query --------------------------------------------------------------------

/// One cell in the reference's `Cell` shape. A value JSON cannot carry exactly is an
/// error, never a substitute: text with an unpaired surrogate has no UTF-8 form.
fn cell(value: &SqlValue, statement: usize, column: usize) -> Result<Value, MddError> {
    let unrepresentable = |what: &str| {
        refuse(
            ErrorCode::UnsupportedCapability,
            "a cell cannot be represented in this response",
        )
        .detail("reason", what)
        .detail("statement_index", statement.to_string())
        .detail("column_index", column.to_string())
    };
    Ok(match value {
        SqlValue::Null => json!({"type": "null", "value": null}),
        // The reference tags every integer it returned as uint64 while it is not negative:
        // 3,904 recorded cells, none of them int64. A negative integer cannot be uint64.
        SqlValue::Bool(v) => json!({"type": "uint64", "value": i64::from(*v).to_string()}),
        SqlValue::I64(v) if v.0 >= 0 => json!({"type": "uint64", "value": v.0.to_string()}),
        SqlValue::I64(v) => json!({"type": "int64", "value": v.0.to_string()}),
        SqlValue::U64(v) => json!({"type": "uint64", "value": v.0.to_string()}),
        SqlValue::F64(bits) => {
            let number = f64::from_bits(bits.0);
            let value = if number.is_nan() {
                json!("NaN")
            } else if number.is_infinite() {
                json!(if number > 0.0 {
                    "Infinity"
                } else {
                    "-Infinity"
                })
            } else {
                json!(number)
            };
            json!({"type": "float64", "value": value})
        }
        SqlValue::Text(text) => match String::from_utf16(&text.utf16) {
            Ok(text) => json!({"type": "utf8", "value": text}),
            Err(_) => return Err(unrepresentable("text holds an unpaired surrogate")),
        },
        SqlValue::Bytes(bytes) => json!({"type": "binary", "value": hex(bytes)}),
        SqlValue::DexMutf8 { .. } => {
            return Err(unrepresentable(
                "a DEX string reached the response unconverted",
            ));
        }
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `(data_type, nullable)` of a result column, from the values it holds. The result
/// does not carry declared types, so a column with no value says so.
fn column_shape(rows: &[Vec<SqlValue>], column: usize) -> (&'static str, bool) {
    let mut kind: Option<&'static str> = None;
    let mut nullable = false;
    for row in rows {
        let found = match &row[column] {
            SqlValue::Null => {
                nullable = true;
                continue;
            }
            SqlValue::Bool(_) => "uint64",
            SqlValue::I64(v) if v.0 >= 0 => "uint64",
            SqlValue::I64(_) => "int64",
            SqlValue::U64(_) => "uint64",
            SqlValue::F64(_) => "float64",
            SqlValue::Text(_) | SqlValue::DexMutf8 { .. } => "utf8",
            SqlValue::Bytes(_) => "binary",
        };
        kind = match kind {
            None => Some(found),
            Some(previous) if previous == found => Some(previous),
            Some(_) => Some("mixed"),
        };
    }
    (kind.unwrap_or("unknown"), nullable)
}

fn statement_json(
    index: usize,
    sql: &str,
    result: &TempStatementResult,
) -> Result<Value, MddError> {
    match result {
        TempStatementResult::Rows(result) => {
            let window = result.window().ok_or_else(|| {
                refuse(
                    ErrorCode::InternalFault,
                    "a windowed statement reported no window",
                )
            })?;
            let columns: Vec<Value> = result
                .columns()
                .iter()
                .enumerate()
                .map(|(i, name)| {
                    let (data_type, nullable) = column_shape(result.rows(), i);
                    json!({"name": name, "data_type": data_type, "nullable": nullable})
                })
                .collect();
            let mut rows = Vec::with_capacity(result.rows().len());
            for row in result.rows() {
                let cells: Result<Vec<Value>, MddError> = row
                    .iter()
                    .enumerate()
                    .map(|(i, v)| cell(v, index, i))
                    .collect();
                rows.push(Value::Array(cells?));
            }
            Ok(json!({
                "statement_index": index,
                "sql": sql,
                "kind": "query",
                "columns": columns,
                "rows": rows,
                "total_rows": window.total_rows.unwrap_or(window.offset + window.rows),
                "truncated": window.truncated,
                "offset": window.offset,
                "next_offset": window.next_offset,
            }))
        }
        TempStatementResult::Definition(report) => Ok(json!({
            "statement_index": index,
            "sql": sql,
            "kind": report.kind,
            "columns": [],
            "rows": [],
            "total_rows": 0,
            "truncated": false,
            "offset": report.window.offset,
            "next_offset": null,
        })),
    }
}

fn query(registry: &mut Registry, args: QueryArgs) -> Result<Value, Failure> {
    let call_started = Instant::now();
    if args.sql.is_empty() || args.sql.len() > MAX_SQL_ITEMS {
        return Err(invalid(format!(
            "sql must hold between 1 and {MAX_SQL_ITEMS} statements"
        )));
    }
    let limit = args.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(invalid(format!("limit must be between 1 and {MAX_LIMIT}")));
    }
    if args
        .offset
        .checked_add(limit)
        .is_none_or(|end| end > MAX_WINDOW_END)
    {
        return Err(invalid(format!(
            "offset + limit must be at most {MAX_WINDOW_END}"
        )));
    }
    if args.named_temp_queries.len() > MAX_NAMED_TEMP_QUERIES {
        return Err(invalid(format!(
            "named_temp_queries holds at most {MAX_NAMED_TEMP_QUERIES} entries"
        )));
    }
    let ms = deadline(args.timeout_ms, &registry.config)?;
    let budget = args
        .max_bytes
        .map_or(registry.config.max_result_bytes, |b| {
            b.min(registry.config.max_result_bytes)
        });
    let dataset = registry.find(&args.dataset_id)?;
    let window = SqlWindow::new(args.offset, limit)?.counting_total();
    let id = args.dataset_id.clone();
    let work = {
        let sql = args.sql;
        let named = args.named_temp_queries;
        move || -> Result<(Vec<Value>, f64), MddError> {
            let sql_started = Instant::now();
            let items: Vec<&str> = sql.iter().map(String::as_str).collect();
            let named: Vec<NamedTempQuery<'_>> = named
                .iter()
                .map(|n| NamedTempQuery {
                    name: &n.name,
                    sql: &n.sql,
                })
                .collect();
            let texts = script_statements(&items)?;
            let results = dataset.temp().execute_call(&items, &named, Some(window))?;
            let statements = texts
                .iter()
                .zip(&results)
                .enumerate()
                .map(|(index, (text, result))| statement_json(index, text, result))
                .collect::<Result<Vec<_>, _>>()?;
            Ok((statements, sql_started.elapsed().as_secs_f64() * 1000.0))
        }
    };
    let (statements, sql_wall_ms) = match with_deadline(ms, work) {
        Outcome::Done(result) => result?,
        Outcome::TimedOut => {
            // The statement cannot be stopped, so nothing may rely on this dataset any more.
            registry.close(&id);
            return Err(refuse(
                ErrorCode::DeadlineExceeded,
                "running computation was terminated and this dataset was closed; call open_dataset to use it again",
            )
            .detail("deadline_ms", ms.to_string())
            .detail("mcp.dataset_id", id.as_str())
            .detail("mcp.dataset_closed", "true")
            .into());
        }
        Outcome::Panicked => {
            registry.close(&id);
            return Err(panicked("query")
                .detail("mcp.dataset_id", id.as_str())
                .detail("mcp.dataset_closed", "true")
                .into());
        }
    };
    let timing = if args.timing {
        // What happens once, at open_dataset, is not repeated per call and is reported as 0.
        json!({
            "cache_total_ms": 0.0,
            "load_inputs_ms": 0.0,
            "parse_ms": 0.0,
            "sql_wall_ms": sql_wall_ms,
            "table_build_ms": 0.0,
            "total_ms": call_started.elapsed().as_secs_f64() * 1000.0,
        })
    } else {
        Value::Null
    };
    let output =
        json!({"dataset_id": id, "statements": statements, "diagnostics": [], "timing": timing});
    let size = serde_json::to_string(&output)
        .map_err(|error| refuse(ErrorCode::InternalFault, &error.to_string()))?
        .len() as u64;
    if size > budget {
        return Err(refuse(
            ErrorCode::QuotaExceeded,
            "the serialized result is over the byte budget",
        )
        .detail(
            "budget",
            if args
                .max_bytes
                .is_some_and(|b| b < registry.config.max_result_bytes)
            {
                "max_bytes"
            } else {
                "max_result_bytes"
            },
        )
        .detail("limit", budget.to_string())
        .detail("observed", size.to_string())
        .into());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdd_sql::values::SqlText;
    use mdd_types::DecimalU64;

    fn text(units: Vec<u16>) -> SqlValue {
        SqlValue::Text(SqlText {
            utf16: units,
            original_mutf8: None,
        })
    }

    #[test]
    fn cells_use_the_reference_shapes_and_keep_integers_exact() {
        assert_eq!(
            cell(&SqlValue::Null, 0, 0).unwrap(),
            json!({"type":"null","value":null})
        );
        assert_eq!(
            cell(&SqlValue::U64(DecimalU64(u64::MAX)), 0, 0).unwrap(),
            json!({"type":"uint64","value":"18446744073709551615"})
        );
        assert_eq!(
            cell(&SqlValue::text("é"), 0, 0).unwrap(),
            json!({"type":"utf8","value":"é"})
        );
        assert_eq!(
            cell(&SqlValue::Bytes(vec![0, 0xAB]), 0, 0).unwrap(),
            json!({"type":"binary","value":"00ab"})
        );
        assert_eq!(
            cell(&SqlValue::Bool(true), 0, 0).unwrap(),
            json!({"type":"uint64","value":"1"})
        );
    }

    #[test]
    fn a_signed_integer_is_uint64_exactly_while_it_is_not_negative() {
        // Signed64 is private to the query crate; the wire form builds one.
        let signed = |v: i64| {
            let value: SqlValue =
                serde_json::from_value(json!({"type": "i64", "value": v.to_string()})).unwrap();
            assert!(matches!(value, SqlValue::I64(_)));
            cell(&value, 0, 0).unwrap()
        };
        assert_eq!(signed(0), json!({"type":"uint64","value":"0"}));
        assert_eq!(
            signed(i64::MAX),
            json!({"type":"uint64","value":"9223372036854775807"})
        );
        assert_eq!(signed(-1), json!({"type":"int64","value":"-1"}));
        assert_eq!(
            signed(i64::MIN),
            json!({"type":"int64","value":"-9223372036854775808"})
        );
    }

    #[test]
    fn floats_that_json_cannot_carry_are_spelled_as_the_reference_spells_them() {
        let float = |value: f64| cell(&SqlValue::F64(DecimalU64(value.to_bits())), 0, 0).unwrap();
        assert_eq!(float(f64::NAN)["value"], "NaN");
        assert_eq!(float(f64::INFINITY)["value"], "Infinity");
        assert_eq!(float(f64::NEG_INFINITY)["value"], "-Infinity");
        assert_eq!(float(1.5)["value"], 1.5);
    }

    #[test]
    fn text_that_has_no_utf8_form_is_an_error_naming_the_cell_not_a_substitute() {
        let error = cell(&text(vec![0x61, 0xd800]), 3, 2).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedCapability);
        assert_eq!(error.details["statement_index"], "3");
        assert_eq!(error.details["column_index"], "2");
        // a valid surrogate pair is fine
        assert_eq!(
            cell(&text(vec![0xd83d, 0xde00]), 0, 0).unwrap()["value"],
            "\u{1f600}"
        );
    }

    #[test]
    fn a_column_shape_comes_from_its_values_and_says_so_when_it_has_none() {
        let rows = vec![
            vec![SqlValue::Null, SqlValue::Null, SqlValue::text("a")],
            vec![
                SqlValue::U64(DecimalU64(1)),
                SqlValue::Null,
                SqlValue::Bool(true),
            ],
        ];
        assert_eq!(column_shape(&rows, 0), ("uint64", true));
        assert_eq!(column_shape(&rows, 1), ("unknown", true));
        assert_eq!(column_shape(&rows, 2), ("mixed", false));
        assert_eq!(column_shape(&[], 0), ("unknown", false));
    }

    #[test]
    fn a_deadline_is_never_longer_than_the_servers_and_never_zero() {
        let config = Config::default();
        assert_eq!(
            deadline(None, &config).unwrap(),
            config.operation_timeout_ms
        );
        assert_eq!(deadline(Some(5), &config).unwrap(), 5);
        assert_eq!(
            deadline(Some(config.operation_timeout_ms), &config).unwrap(),
            config.operation_timeout_ms,
            "asking for exactly the server's timeout is allowed"
        );
        assert!(deadline(Some(0), &config).is_err());
        assert!(deadline(Some(config.operation_timeout_ms + 1), &config).is_err());
    }

    #[test]
    fn work_that_outlives_its_deadline_is_reported_and_work_that_panics_is_too() {
        assert!(matches!(with_deadline(5_000, || 7), Outcome::Done(7)));
        let slow = with_deadline(10, || {
            thread::sleep(Duration::from_millis(500));
            1
        });
        assert!(matches!(slow, Outcome::TimedOut));
        let broken = with_deadline(5_000, || -> u8 { panic!("injected") });
        assert!(matches!(broken, Outcome::Panicked));
    }

    #[test]
    fn the_embedded_schemas_cover_exactly_the_registered_tools() {
        let definitions = definitions();
        let names: Vec<&str> = definitions
            .iter()
            .map(|d| d["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, DESCRIPTIONS.map(|(name, _)| name));
        let embedded = schemas();
        assert_eq!(embedded.as_object().unwrap().len(), DESCRIPTIONS.len());
    }

    #[test]
    fn a_dataset_that_is_not_open_is_refused_in_one_set_of_words() {
        // Never minted and closed are the same to a client: not open.
        let registry = Registry::new(Config::default());
        let error = registry.find("dataset-9").err().unwrap();
        assert_eq!(
            error.message,
            "dataset \"dataset-9\" is not open; call open_dataset first"
        );
        let rendered = error_result(&error);
        assert_eq!(rendered["error"]["kind"], "unknown_dataset");
        assert!(rendered.get("dataset_id").is_none());
        assert!(
            rendered["error"]["details"].get("kind").is_none(),
            "the kind moved out of the details"
        );
    }

    #[test]
    fn an_error_renders_the_references_fields_and_keeps_this_engines_own() {
        let timeout = timed_out("query", 7)
            .detail("mcp.dataset_id", "dataset-3")
            .detail("mcp.dataset_closed", "true");
        let rendered = error_result(&timeout);
        assert_eq!(rendered["dataset_id"], "dataset-3");
        assert_eq!(rendered["error"]["kind"], "timeout");
        assert_eq!(rendered["error"]["dataset_closed"], true);
        assert_eq!(rendered["error"]["code"], "DEADLINE_EXCEEDED");
        assert_eq!(rendered["error"]["details"]["deadline_ms"], "7");
        assert!(
            rendered["error"]["details"].get("dataset_closed").is_none()
                && rendered["error"]["details"].get("dataset_id").is_none(),
            "lifted fields are not repeated in the details"
        );

        let statement =
            refuse(ErrorCode::UnsupportedQuery, "no such table").detail("statement_index", "4");
        let rendered = error_result(&statement);
        assert_eq!(rendered["error"]["kind"], "invalid_query");
        assert_eq!(rendered["error"]["statement_index"], 4);
        assert_eq!(rendered["error"]["details"]["statement_index"], "4");

        let unknown =
            refuse(ErrorCode::InvalidArgument, "UNKNOWN_RELATION").detail("relation", "base");
        assert_eq!(
            error_result(&unknown)["error"]["message"],
            "unknown relation `base`"
        );

        let plain = refuse(ErrorCode::InvalidInput, "bad");
        let rendered = error_result(&plain);
        assert_eq!(rendered["error"]["kind"], "invalid_input");
        assert!(rendered["error"].get("dataset_closed").is_none());
        assert!(rendered["error"].get("statement_index").is_none());
        assert!(rendered.get("dataset_id").is_none());
    }

    #[test]
    fn a_detail_a_lower_layer_calls_kind_is_not_the_errors_kind() {
        // the DEX debug decoder sets a detail named "kind"; it must reach the client as a detail
        let lower = refuse(ErrorCode::InvalidInput, "BAD_DEBUG")
            .detail("kind", "position")
            .detail("dataset_id", "inner")
            .detail("dataset_closed", "true")
            .detail("file_id", "3");
        let rendered = error_result(&lower);
        assert_eq!(rendered["error"]["kind"], "invalid_input");
        assert_eq!(rendered["error"]["details"]["kind"], "position");
        assert_eq!(rendered["error"]["details"]["dataset_id"], "inner");
        assert_eq!(rendered["error"]["details"]["dataset_closed"], "true");
        assert_eq!(rendered["error"]["details"]["file_id"], "3");
        assert!(rendered.get("dataset_id").is_none());
        assert!(rendered["error"].get("dataset_closed").is_none());
        assert!(rendered["error"].get("file_id").is_none());
    }

    #[test]
    fn the_session_quota_speaks_in_the_references_words() {
        let rendered = error_result(&session_quota());
        assert_eq!(rendered["error"]["kind"], "session_quota_exceeded");
        assert_eq!(
            rendered["error"]["message"],
            "dataset/input-byte quota exhausted; close unused datasets before opening another"
        );
        assert_eq!(rendered["error"]["code"], "QUOTA_EXCEEDED");
    }
}
