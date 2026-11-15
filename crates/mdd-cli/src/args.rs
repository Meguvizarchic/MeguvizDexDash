//! Command-line parsing. Hand written: the grammar is small, every refusal is a
//! named `INVALID_ARGUMENT`, and nothing here may accept an option it does not act on.
use crate::output::Format;
use mdd_service::{DEFAULT_BATCH_ROWS, Dialect, InputRequest, MAX_BATCH_ROWS};
use mdd_sql::control::SqlLimits;
use mdd_types::{ErrorCode, MddError, MddResult};
use std::ffi::OsString;
use std::path::PathBuf;

pub const USAGE: &str = "usage: meguvizdexdash version | capabilities | inspect-dex PATH... | inspect-apk PATH... | query --input PATH... (--sql TEXT | --sql-file PATH|-) [--dialect native-v1|dexsql-0.1.0|dexsql-0.1.1] [--format jsonl|text] [--batch-rows N] [--max-rows N] [--deadline-ms N] [SQL BUDGETS] | serve --input PATH... [--dialect NAME] [--deadline-ms N] [SQL BUDGETS]; mcp [--dialect dexsql-0.1.0|dexsql-0.1.1] [--timeout-ms N] [--max-datasets N] [--max-total-input-bytes N] [--max-result-bytes N] [SQL BUDGETS]; SQL BUDGETS: --sql-max-steps N --sql-max-scanned-rows N --sql-max-result-rows N";

pub enum Command {
    Version,
    Capabilities,
    InspectDex(Vec<OsString>),
    InspectApk(Vec<OsString>),
    Query(Box<QueryArgs>),
    Serve(Box<ServeArgs>),
    Mcp(Box<mdd_mcp::Config>),
}

pub struct DataArgs {
    pub inputs: Vec<InputRequest>,
    pub dialect: Dialect,
    pub deadline_ms: Option<u64>,
    /// The engine's own budgets, with the defaults for anything not asked for. They
    /// can be raised as well as lowered: they are limits of the caller's own process.
    pub sql_limits: SqlLimits,
}

pub enum SqlSource {
    Text(String),
    File(PathBuf),
    Stdin,
}

pub struct QueryArgs {
    pub data: DataArgs,
    pub sql: SqlSource,
    pub format: Format,
    pub batch_rows: u32,
    pub max_rows: Option<u64>,
}

pub struct ServeArgs {
    pub data: DataArgs,
}

fn bad(message: impl Into<String>) -> MddError {
    MddError::new(ErrorCode::InvalidArgument, "cli", message)
}

fn number(name: &str, value: &OsString) -> MddResult<u64> {
    let text = value
        .to_str()
        .ok_or_else(|| bad(format!("{name} must be a decimal number")))?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(format!("{name} must be a decimal number")));
    }
    text.parse::<u64>()
        .map_err(|_| bad(format!("{name} is out of range")))
}

fn text(name: &str, value: &OsString) -> MddResult<String> {
    value
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| bad(format!("{name} must be valid UTF-8")))
}

#[derive(Default)]
struct Options {
    inputs: Vec<PathBuf>,
    sql: Option<String>,
    sql_file: Option<PathBuf>,
    dialect: Option<String>,
    format: Option<String>,
    batch_rows: Option<u64>,
    max_rows: Option<u64>,
    deadline_ms: Option<u64>,
    timeout_ms: Option<u64>,
    max_datasets: Option<u64>,
    max_total_input_bytes: Option<u64>,
    max_result_bytes: Option<u64>,
    sql_max_steps: Option<u64>,
    sql_max_scanned_rows: Option<u64>,
    sql_max_result_rows: Option<u64>,
}

fn once<T>(slot: &mut Option<T>, name: &str, value: T) -> MddResult<()> {
    if slot.replace(value).is_some() {
        return Err(bad(format!("{name} was given more than once")));
    }
    Ok(())
}

fn options(rest: &[OsString], allowed: &[&str]) -> MddResult<Options> {
    let mut found = Options::default();
    let mut iter = rest.iter();
    while let Some(argument) = iter.next() {
        let name = argument
            .to_str()
            .filter(|n| n.starts_with("--"))
            .ok_or_else(|| bad("expected an option such as --input"))?;
        if !allowed.contains(&name) {
            return Err(bad(format!("option `{name}` is not available here")));
        }
        let value = iter
            .next()
            .ok_or_else(|| bad(format!("option `{name}` needs a value")))?;
        match name {
            "--input" => found.inputs.push(PathBuf::from(value)),
            "--sql" => once(&mut found.sql, name, text(name, value)?)?,
            "--sql-file" => once(&mut found.sql_file, name, PathBuf::from(value))?,
            "--dialect" => once(&mut found.dialect, name, text(name, value)?)?,
            "--format" => once(&mut found.format, name, text(name, value)?)?,
            "--batch-rows" => once(&mut found.batch_rows, name, number(name, value)?)?,
            "--max-rows" => once(&mut found.max_rows, name, number(name, value)?)?,
            "--deadline-ms" => once(&mut found.deadline_ms, name, number(name, value)?)?,
            "--timeout-ms" => once(&mut found.timeout_ms, name, number(name, value)?)?,
            "--max-datasets" => once(&mut found.max_datasets, name, number(name, value)?)?,
            "--max-total-input-bytes" => {
                once(&mut found.max_total_input_bytes, name, number(name, value)?)?;
            }
            "--max-result-bytes" => once(&mut found.max_result_bytes, name, number(name, value)?)?,
            "--sql-max-steps" => once(&mut found.sql_max_steps, name, number(name, value)?)?,
            "--sql-max-scanned-rows" => {
                once(&mut found.sql_max_scanned_rows, name, number(name, value)?)?;
            }
            "--sql-max-result-rows" => {
                once(&mut found.sql_max_result_rows, name, number(name, value)?)?;
            }
            _ => return Err(bad(format!("option `{name}` is not available here"))),
        }
    }
    Ok(found)
}

fn data(found: &mut Options) -> MddResult<DataArgs> {
    if found.inputs.is_empty() {
        return Err(bad("at least one --input is required"));
    }
    let dialect = match &found.dialect {
        Some(name) => Dialect::parse(name)?,
        None => Dialect::NativeV1,
    };
    if found.deadline_ms == Some(0) {
        return Err(bad("--deadline-ms must be positive"));
    }
    let sql_limits = sql_limits(found)?;
    Ok(DataArgs {
        inputs: std::mem::take(&mut found.inputs)
            .into_iter()
            .map(|path| InputRequest { path, kind: None })
            .collect(),
        dialect,
        deadline_ms: found.deadline_ms,
        sql_limits,
    })
}

fn sql_limits(found: &Options) -> MddResult<SqlLimits> {
    let mut sql_limits = SqlLimits::default();
    for (name, asked, slot) in [
        (
            "--sql-max-steps",
            found.sql_max_steps,
            &mut sql_limits.max_steps,
        ),
        (
            "--sql-max-scanned-rows",
            found.sql_max_scanned_rows,
            &mut sql_limits.max_scanned_rows,
        ),
        (
            "--sql-max-result-rows",
            found.sql_max_result_rows,
            &mut sql_limits.max_result_rows,
        ),
    ] {
        match asked {
            Some(0) => return Err(bad(format!("{name} must be positive"))),
            Some(value) => *slot = value,
            None => {}
        }
    }
    Ok(sql_limits)
}

fn positive(name: &str, asked: Option<u64>) -> MddResult<Option<u64>> {
    match asked {
        Some(0) => Err(bad(format!("{name} must be positive"))),
        other => Ok(other),
    }
}

fn mcp_config(found: &Options) -> MddResult<mdd_mcp::Config> {
    let mut config = mdd_mcp::Config::default();
    if let Some(name) = &found.dialect {
        config.dialect = Dialect::parse(name)?;
    }
    if config.dialect == Dialect::NativeV1 {
        return Err(MddError::new(
            ErrorCode::UnsupportedCapability,
            "cli",
            "the MCP server serves the HostLab contract relations; use dexsql-0.1.0 or dexsql-0.1.1",
        ));
    }
    if let Some(ms) = positive("--timeout-ms", found.timeout_ms)? {
        config.operation_timeout_ms = ms;
    }
    if let Some(n) = positive("--max-datasets", found.max_datasets)? {
        config.max_datasets =
            usize::try_from(n).map_err(|_| bad("--max-datasets is out of range"))?;
    }
    if let Some(n) = positive("--max-total-input-bytes", found.max_total_input_bytes)? {
        config.max_total_input_bytes = n;
    }
    if let Some(n) = positive("--max-result-bytes", found.max_result_bytes)? {
        config.max_result_bytes = n;
    }
    config.sql_limits = sql_limits(found)?;
    Ok(config)
}

pub fn parse(args: &[OsString]) -> MddResult<Command> {
    let Some((command, rest)) = args.split_first() else {
        return Err(bad(USAGE));
    };
    let command = command.to_str().unwrap_or("");
    match command {
        "version" | "--version" | "capabilities" if !rest.is_empty() => {
            Err(bad(format!("`{command}` takes no arguments")))
        }
        "version" | "--version" => Ok(Command::Version),
        "capabilities" => Ok(Command::Capabilities),
        "inspect-dex" => Ok(Command::InspectDex(rest.to_vec())),
        "inspect-apk" => Ok(Command::InspectApk(rest.to_vec())),
        "query" => {
            let mut found = options(
                rest,
                &[
                    "--input",
                    "--sql",
                    "--sql-file",
                    "--dialect",
                    "--format",
                    "--batch-rows",
                    "--max-rows",
                    "--deadline-ms",
                    "--sql-max-steps",
                    "--sql-max-scanned-rows",
                    "--sql-max-result-rows",
                ],
            )?;
            let sql = match (found.sql.take(), found.sql_file.take()) {
                (Some(_), Some(_)) => {
                    return Err(bad("give either --sql or --sql-file, not both"));
                }
                (Some(text), None) => SqlSource::Text(text),
                (None, Some(path)) if path.as_os_str() == "-" => SqlSource::Stdin,
                (None, Some(path)) => SqlSource::File(path),
                (None, None) => return Err(bad("a statement is required: --sql or --sql-file")),
            };
            let format = match &found.format {
                Some(name) => Format::parse(name)?,
                None => Format::Jsonl,
            };
            let batch_rows = match found.batch_rows {
                Some(rows) if (1..=u64::from(MAX_BATCH_ROWS)).contains(&rows) => rows as u32,
                Some(_) => {
                    return Err(bad(format!(
                        "--batch-rows must be between 1 and {MAX_BATCH_ROWS}"
                    )));
                }
                None => DEFAULT_BATCH_ROWS,
            };
            let max_rows = found.max_rows;
            Ok(Command::Query(Box::new(QueryArgs {
                data: data(&mut found)?,
                sql,
                format,
                batch_rows,
                max_rows,
            })))
        }
        "serve" => {
            let mut found = options(
                rest,
                &[
                    "--input",
                    "--dialect",
                    "--deadline-ms",
                    "--sql-max-steps",
                    "--sql-max-scanned-rows",
                    "--sql-max-result-rows",
                ],
            )?;
            Ok(Command::Serve(Box::new(ServeArgs {
                data: data(&mut found)?,
            })))
        }
        "mcp" => {
            let found = options(
                rest,
                &[
                    "--dialect",
                    "--timeout-ms",
                    "--max-datasets",
                    "--max-total-input-bytes",
                    "--max-result-bytes",
                    "--sql-max-steps",
                    "--sql-max-scanned-rows",
                    "--sql-max-result-rows",
                ],
            )?;
            Ok(Command::Mcp(Box::new(mcp_config(&found)?)))
        }
        _ => Err(bad(USAGE)),
    }
}
