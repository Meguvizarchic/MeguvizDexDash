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
use crate::resource_tools;
use mdd_facts::{
    smali,
    smali_required::{self, SmaliLimits, page_text},
};
use mdd_service::{
    Dataset, Dialect, InputRequest,
    decode::{self, Decoded, Selector},
    manifest::{self, ManifestFailure},
};
use mdd_session::ResourceLimits;
use mdd_sql::{
    dialects::SqlDialect,
    profiles::compatibility,
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

pub(crate) fn invalid(message: impl Into<String>) -> Failure {
    Failure::InvalidParams(message.into())
}

pub(crate) fn refuse(code: ErrorCode, message: &str) -> MddError {
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

    pub(crate) fn find(&self, id: &str) -> Result<Arc<Dataset>, MddError> {
        match self.open.iter().find(|e| e.id == id) {
            Some(entry) => Ok(Arc::clone(&entry.dataset)),
            None => Err(unknown_dataset(id)),
        }
    }

    /// Returns whether the dataset was open.
    pub(crate) fn close(&mut self, id: &str) -> bool {
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
pub(crate) const HINT_ARCHIVE_INPUTS: &str = "mcp.archive_inputs";

/// A `kind` the reference spells and a client may branch on. It travels in the error's
/// details until the error is rendered, where it becomes `error.kind`.
pub(crate) fn with_kind(error: MddError, kind: &str) -> MddError {
    error.detail(HINT_KIND, kind)
}

/// The dataset an error belongs to; rendered beside `error`, as the reference does.
pub(crate) fn for_dataset(error: MddError, dataset_id: &str) -> MddError {
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
    let archive_inputs = details.remove(HINT_ARCHIVE_INPUTS);
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
    if let Some(inputs) = archive_inputs {
        body.insert("archive_inputs".to_owned(), inputs);
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

const DESCRIPTIONS: [(&str, &str); 12] = [
    (
        "open_dataset",
        "Open local DEX or APK paths as an isolated, reusable dataset. Returns its identifier, the inputs, their byte total, whether a DEX was found (`has_dex`), the indexes of archive inputs and the preparation time, plus this engine's snapshot identity. An archive with resources and no DEX opens with `has_dex` false: the resource tools read it, and `query` and `decode` refuse it as no_dex.",
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
        "Show smali: of one method, named by its exact descriptor or by file_id and method_idx (a descriptor defined in several DEX files needs file_id), or of the methods of one class (`class`, with file_id when several DEX files define it). A method row has the numbers of its code item and, in the text modes, its text with annotations, parameter names and debug directives as well as instructions; `omitted` counts what the text leaves out. The text is paged by UTF-8 byte offset: continue from next_offset (on the method: with file_id and method_idx, not with the class); start_line, end_line and total_lines count lines, total_bytes counts bytes. A class is paged by method_offset and method_limit (default 20, at most 50) in method_idx order; next_method_offset is null on the last page, and its `class` object holds the class header, interfaces, class annotations and fields as one text. In the text modes of a class, max_bytes is one budget for the text of the page. Mode `summary` (the default for a class) shows only metadata, `smali` (the default for a method) the text, `context` only the method line, register line, labels and catch lines, each with its zero-based line number in the full text (`source_total_lines`); a context has its own offsets. `text_format` names the version of the text shown.",
    ),
    (
        "get_manifest",
        "Read the AndroidManifest.xml of an APK input as a summary: the manifest, application and uses-sdk attributes, the target SDK, component counts and a paged list of permission elements (permission, uses-permission, uses-permission-sdk-23, uses-permission-sdk-m), in document order. `offset` and `next_offset` count permission rows, `limit` is rows per page (1..200, default 200). input_index is the position in open_dataset.inputs and is needed when several archive inputs are open. A reference the archive's resources would resolve is shown as @ and eight hex digits. In mode `xml` the manifest is returned as XML text instead, paged by UTF-8 byte offset (`offset` and `next_offset` count bytes of the text; a page holds at most a quarter of `max_bytes`, 4096..131072, and ends on a line unless one line is longer): every namespace declaration and namespaced attribute is written, typed values are spelled out (floats, dimensions, fractions, colours, references), text nodes are kept, and a character that XML 1.0 cannot carry is written as a character reference.",
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
    (
        "get_manifest_components",
        "Page the components of the application (activity, activity-alias, service, receiver, provider) in document order: name, descriptor, enabled state, exported state, launcher flag, intent filters (actions, categories, data), metadata and, for an alias, its target activity. `exported` is what the manifest states or the platform's default gives at the target SDK (explicit, intent-filter default, provider default); it is null, with the reason `explicit_exported_required_or_target_sdk_unknown`, when a component with an intent filter has no explicit value at target SDK 31 or later or the target SDK is unknown. It is the manifest's configuration, not runtime accessibility. Filter by `kind` and `only_exported`; `offset`, `limit` (1..200) and `next_offset` count components.",
    ),
    (
        "list_resource_files",
        "List the members of an archive input, directory entries included, in name order, with size, compressed size, CRC-32 and the member's position in the archive (`entry_index`); members that share a name are all listed. `prefix` is a case-sensitive name prefix. `offset`, `limit` (1..200) and `next_offset` count members; rows are added while the answer fits `max_bytes`.",
    ),
    (
        "read_resource",
        "Read one archive member by its exact name, from the dataset's own snapshot, its size and CRC checked. Format `auto` shows Android binary XML as XML text (kind `android_xml`), UTF-8 as text (kind `text`) and anything else as lower-case hex (kind `binary`); `hex` forces the stored bytes as hex. Text is paged by UTF-8 byte offset of the text shown, hex by byte offset of the member; `max_bytes` is 4096..131072 and a page holds a quarter of it as text, an eighth as bytes. `source_bytes` is the member's size; `source` names the member and snapshot. A binary XML that does not parse is refused as invalid_xml, and can still be read as hex. Nothing is extracted to disk.",
    ),
    (
        "query_resources",
        "Query resources.arsc of an archive input: one row per resource, configuration and, for a style, array or plurals, item. The same resource in several configurations is several rows, each with its qualifier string (`configuration`, empty for the default). Filters: `resource_id`, `resource_type`, `name` (`type/name` or `package:type/name`), `configuration` (exact; empty selects the default), `contains` (case-sensitive substring of `type/name`). A reference is named, not followed. A table that does not parse is refused as invalid_resource_table; an archive without resources.arsc as not_found. `offset`, `limit` (1..200) and `next_offset` count rows.",
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

pub(crate) fn arguments<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, Failure> {
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
pub(crate) fn deadline(asked: Option<u64>, config: &Config) -> Result<u64, Failure> {
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

pub(crate) enum Outcome<T> {
    Done(T),
    TimedOut,
    Panicked,
}

/// Run `work` on its own thread and wait for it, at most `ms`. A thread that outlives
/// its deadline cannot be stopped; it ends when the engine's own budgets end it, and its
/// result is dropped.
pub(crate) fn with_deadline<T: Send + 'static>(
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

pub(crate) fn timed_out(what: &str, ms: u64) -> MddError {
    MddError::new(
        ErrorCode::DeadlineExceeded,
        "mcp",
        format!("{what} exceeded its deadline"),
    )
    .detail("deadline_ms", ms.to_string())
}

pub(crate) fn panicked(what: &str) -> MddError {
    MddError::new(
        ErrorCode::InternalFault,
        "mcp",
        format!("{what} stopped unexpectedly"),
    )
}

/// Code tools (SQL, decode) on a dataset with resources and no DEX: refused, in the reference's
/// words, never answered with an empty result.
fn require_dex(dataset: &Dataset, dataset_id: &str) -> Result<(), Failure> {
    dataset
        .require_dex()
        .map_err(|error| Failure::Execution(for_dataset(with_kind(error, "no_dex"), dataset_id)))
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
        "get_manifest_components" => resource_tools::components::get_manifest_components(
            registry,
            arguments(arguments_value)?,
        ),
        "list_resource_files" => {
            resource_tools::files::list_resource_files(registry, arguments(arguments_value)?)
        }
        "read_resource" => {
            resource_tools::read::read_resource(registry, arguments(arguments_value)?)
        }
        "query_resources" => {
            resource_tools::query::query_resources(registry, arguments(arguments_value)?)
        }
        "list_tables" => {
            arguments::<NoArgs>(arguments_value)?;
            Ok(list_tables(registry.config().dialect.sql()))
        }
        "describe_table" => {
            describe_table(registry.config().dialect.sql(), arguments(arguments_value)?)
        }
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
        "has_dex": dataset.has_dex(),
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

#[path = "tools/decode.rs"]
mod decode_tool;
#[path = "tools/manifest.rs"]
mod manifest_tool;
mod sql;

use self::{
    decode_tool::decode_method,
    manifest_tool::get_manifest,
    sql::{describe_table, list_tables, query},
};
pub use self::{
    decode_tool::{DEFAULT_LINES, DEFAULT_METHOD_LIMIT, MAX_LINES, MAX_METHOD_LIMIT},
    manifest_tool::MAX_MANIFEST_LIMIT,
};
#[cfg(test)]
use self::{
    decode_tool::{DecodeMode, omitted, summary_row, text_fields, text_of, text_page_error},
    sql::{cell, column_shape},
};

#[cfg(test)]
#[path = "tools/tests.rs"]
mod tests;
