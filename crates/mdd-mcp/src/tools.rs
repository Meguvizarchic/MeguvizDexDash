//! The tools: their published schemas, argument checking and behaviour.
//!
//! Input and output schemas of the six tools are the ones the reference engine
//! (A0, dexsql 0.1.0) publishes; they are embedded from `tool_schemas.json` and a
//! conformance check compares them with the recorded `tools/list`. Descriptions are
//! this server's own, because several of the reference's describe behaviour this
//! server does not have.
//!
//! A tool is registered only when it is implemented. Not registered, and refused as
//! unknown tools: `decode`, `get_manifest`, `get_manifest_components`,
//! `list_resource_files`, `read_resource`, `query_resources`.
use mdd_service::{Dataset, Dialect, InputRequest};
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
    collections::VecDeque,
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

const SCHEMAS: &str = include_str!("tool_schemas.json");

pub const MAX_INPUTS: usize = 64;
pub const MAX_SQL_ITEMS: usize = 16;
pub const MAX_LIMIT: u64 = 1000;
pub const DEFAULT_LIMIT: u64 = 200;
pub const MAX_WINDOW_END: u64 = 100_000;
const REMEMBERED_CLOSED: usize = 1024;

/// What the server is configured with.
#[derive(Clone, Debug)]
pub struct Config {
    pub dialect: Dialect,
    /// The deadline of an operation that does not ask for a shorter one.
    pub operation_timeout_ms: u64,
    pub max_datasets: usize,
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
    inputs: Vec<String>,
}

/// The datasets this server instance minted. An identifier it did not mint, or one it
/// has closed, is refused; nothing else can name a dataset.
pub struct Registry {
    config: Config,
    open: Vec<Entry>,
    closed: VecDeque<String>,
}

impl Registry {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            open: Vec::new(),
            closed: VecDeque::new(),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    fn find(&self, id: &str) -> Result<Arc<Dataset>, MddError> {
        if let Some(entry) = self.open.iter().find(|e| e.id == id) {
            return Ok(Arc::clone(&entry.dataset));
        }
        if self.closed.iter().any(|closed| closed == id) {
            return Err(
                refuse(ErrorCode::SnapshotClosed, "DATASET_CLOSED").detail("dataset_id", id)
            );
        }
        Err(refuse(ErrorCode::InvalidArgument, "DATASET_NOT_FOUND").detail("dataset_id", id))
    }

    /// Returns whether the dataset was open.
    fn close(&mut self, id: &str) -> bool {
        let Some(position) = self.open.iter().position(|e| e.id == id) else {
            return false;
        };
        self.open.remove(position);
        self.closed.push_back(id.to_owned());
        while self.closed.len() > REMEMBERED_CLOSED {
            self.closed.pop_front();
        }
        true
    }
}

// ---- definitions -------------------------------------------------------------

fn schemas() -> Value {
    serde_json::from_str(SCHEMAS).expect("the embedded tool schemas are JSON")
}

const DESCRIPTIONS: [(&str, &str); 6] = [
    (
        "open_dataset",
        "Open local DEX or APK paths as an isolated, reusable dataset and return its identifier, source identity and DEX roster. Archives without any DEX are not supported yet and are refused.",
    ),
    (
        "list_datasets",
        "List the open datasets with the server's quotas and current usage.",
    ),
    (
        "close_dataset",
        "Close a dataset and release it. Closing twice is allowed; later requests that name it are refused.",
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
        "Run read-only SQL statements with exact typed cells, a row window per statement and next_offset. Use a deterministic ORDER BY when paging: the statement runs again for each page. Rows are never clipped silently: a result over the byte budget is refused. A deadline that expires closes this dataset. `timing` is not supported and is refused when true.",
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
        return Err(refuse(ErrorCode::QuotaExceeded, "too many open datasets")
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
    let opened = match with_deadline(ms, move || {
        Dataset::open(&requests, dialect, limits, sql_limits)
    }) {
        Outcome::Done(result) => result?,
        Outcome::TimedOut => return Err(timed_out("open_dataset", ms).into()),
        Outcome::Panicked => return Err(panicked("open_dataset").into()),
    };
    let dataset = Arc::new(opened);
    let files = dex_files(&dataset)?;
    let id = opaque_id("dataset")?;
    let description = dataset.description();
    let manifest = serde_json::to_value(dataset.snapshot().manifest())
        .map_err(|error| refuse(ErrorCode::InternalFault, &error.to_string()))?;
    registry.open.push(Entry {
        id: id.clone(),
        dataset,
        inputs: args.inputs.clone(),
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
    Ok(json!({
        "dataset_id": id,
        "inputs": args.inputs,
        "snapshot_id": description["snapshot_id"],
        "scope_id": description["scope_id"],
        "profile": description["profile"],
        "sql_dialect": description["sql_dialect"],
        "dex_count": description["dex_count"],
        "dex_files": files,
        "snapshot_manifest": manifest,
        "diagnostics": diagnostics,
    }))
}

/// The roster HostLab reads right after opening, from the dataset's own relation.
fn dex_files(dataset: &Dataset) -> Result<Vec<Value>, Failure> {
    let result = dataset.temp().execute(
        "SELECT file_id,entry_name FROM dex_files ORDER BY file_id",
        None,
    )?;
    let TempStatementResult::Rows(rows) = result else {
        return Err(refuse(ErrorCode::InternalFault, "dex_files did not return rows").into());
    };
    rows.rows()
        .iter()
        .map(|row| {
            let file_id = match &row[0] {
                SqlValue::U64(v) => json!(v.0),
                SqlValue::I64(v) => json!(v.0),
                _ => {
                    return Err(refuse(
                        ErrorCode::InternalFault,
                        "dex_files.file_id is not an integer",
                    )
                    .into());
                }
            };
            let entry_name = match &row[1] {
                SqlValue::Null => Value::Null,
                SqlValue::Text(text) => json!(String::from_utf16(&text.utf16).map_err(|_| {
                    refuse(
                        ErrorCode::UnsupportedCapability,
                        "an entry name is not valid Unicode",
                    )
                })?),
                _ => {
                    return Err(refuse(
                        ErrorCode::InternalFault,
                        "dex_files.entry_name is not text",
                    )
                    .into());
                }
            };
            Ok(json!({"file_id": file_id, "entry_name": entry_name}))
        })
        .collect()
}

fn list_datasets(registry: &Registry) -> Value {
    let datasets: Vec<Value> = registry
        .open
        .iter()
        .map(|entry| {
            json!({
                "dataset_id": entry.id,
                "state": "open",
                "inputs": entry.inputs,
                "snapshot_id": entry.dataset.snapshot_id(),
                "dex_count": entry.dataset.dex_count(),
            })
        })
        .collect();
    json!({
        "datasets": datasets,
        "closed_datasets": registry.closed.len(),
        "quotas": {
            "max_datasets": registry.config.max_datasets,
            "max_inputs_per_dataset": MAX_INPUTS,
            "operation_timeout_ms": registry.config.operation_timeout_ms,
            "max_result_bytes": registry.config.max_result_bytes,
        },
        "usage": {"open_datasets": registry.open.len()},
    })
}

fn close_dataset(registry: &mut Registry, args: CloseArgs) -> Result<Value, Failure> {
    if registry.close(&args.dataset_id) {
        return Ok(json!({"dataset_id": args.dataset_id, "closed": true, "already_closed": false}));
    }
    if registry.closed.iter().any(|id| *id == args.dataset_id) {
        return Ok(json!({"dataset_id": args.dataset_id, "closed": true, "already_closed": true}));
    }
    Err(refuse(ErrorCode::InvalidArgument, "DATASET_NOT_FOUND")
        .detail("dataset_id", args.dataset_id)
        .into())
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
            Failure::Execution(
                refuse(ErrorCode::InvalidArgument, "UNKNOWN_TABLE")
                    .detail("name", args.name.clone()),
            )
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
        SqlValue::Bool(v) => json!({"type": "int64", "value": i64::from(*v).to_string()}),
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
            SqlValue::Bool(_) | SqlValue::I64(_) => "int64",
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
                "execute_ms": null,
                "sql_truncated": null,
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
            "execute_ms": null,
            "sql_truncated": null,
        })),
    }
}

fn query(registry: &mut Registry, args: QueryArgs) -> Result<Value, Failure> {
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
    if args.timing {
        return Err(refuse(
            ErrorCode::UnsupportedCapability,
            "timing is not supported: the phases it reports are not measured by this server",
        )
        .into());
    }
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
        move || -> Result<Vec<Value>, MddError> {
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
            texts
                .iter()
                .zip(&results)
                .enumerate()
                .map(|(index, (text, result))| statement_json(index, text, result))
                .collect()
        }
    };
    let statements = match with_deadline(ms, work) {
        Outcome::Done(result) => result?,
        Outcome::TimedOut => {
            // The statement cannot be stopped, so nothing may rely on this dataset any more.
            registry.close(&id);
            return Err(timed_out("query", ms)
                .detail("dataset_closed", "true")
                .into());
        }
        Outcome::Panicked => {
            registry.close(&id);
            return Err(panicked("query").detail("dataset_closed", "true").into());
        }
    };
    let output =
        json!({"dataset_id": id, "statements": statements, "diagnostics": [], "timing": null});
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
            json!({"type":"int64","value":"1"})
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
    fn closed_datasets_are_remembered_up_to_a_bound() {
        let mut registry = Registry::new(Config::default());
        for n in 0..REMEMBERED_CLOSED + 10 {
            registry.closed.push_back(format!("d{n}"));
            while registry.closed.len() > REMEMBERED_CLOSED {
                registry.closed.pop_front();
            }
        }
        assert_eq!(registry.closed.len(), REMEMBERED_CLOSED);
        let error = registry.find("never-minted").err().unwrap();
        assert_eq!(error.message, "DATASET_NOT_FOUND");
    }
}
