//! `meguvizdexdash`: the command-line adapter over the engine.
//!
//! Exit codes are a frozen contract (see `conformance/cli`):
//!
//! | code | meaning                                                                     |
//! |------|-----------------------------------------------------------------------------|
//! | 0    | complete success: the statement ran and every row was delivered             |
//! | 1    | the statement ended in a failure terminal (error, cancel, quota, truncation) |
//! | 2    | refused before anything ran: usage, input or open error; stderr holds JSON   |
//! | 3    | internal fault or lost worker                                               |
//! | 4    | the output could not be written (closed pipe)                               |
//!
//! stdout carries results only; diagnostics and refusals go to stderr as one JSON
//! error object. After a 0 or 1 from `query`, stdout ends with a terminal envelope.
mod args;
mod commands;
mod output;
mod serve;

use args::{Command, QueryArgs, ServeArgs, SqlSource};
use mdd_input::snapshot::InputKind;
use mdd_service::Dataset;
use mdd_service::RunOptions;
use mdd_session::ResourceLimits;
use mdd_types::{ErrorCode, MddError, MddResult, OperationStatus, ResultEnvelope};
use output::{Format, JsonlSink, TextSink};
use serde_json::json;
use std::io::{self, Read, Write};

const OK: i32 = 0;
const FAILED: i32 = 1;
const REFUSED: i32 = 2;
const FAULT: i32 = 3;
const OUTPUT: i32 = 4;

/// Exit code for an error that stopped the command before a terminal existed.
fn refusal_code(error: &MddError) -> i32 {
    match error.code {
        ErrorCode::InternalFault | ErrorCode::WorkerLost => FAULT,
        _ => REFUSED,
    }
}

fn terminal_code(terminal: &ResultEnvelope) -> i32 {
    if terminal.operation_status == OperationStatus::Ok && terminal.error.is_none() {
        return OK;
    }
    match terminal.error.as_ref().map(|e| e.code) {
        Some(ErrorCode::InternalFault | ErrorCode::WorkerLost) => FAULT,
        _ => FAILED,
    }
}

fn limits(deadline_ms: Option<u64>) -> ResourceLimits {
    let base = ResourceLimits::default();
    ResourceLimits {
        deadline_ms: deadline_ms.unwrap_or(base.deadline_ms),
        ..base
    }
}

/// The engine refuses statements over 256 KiB; reading more than four times that
/// is pointless, and an unbounded read of a pipe or a huge file is a way to run out
/// of memory before the engine gets to say no.
const MAX_STATEMENT_BYTES: u64 = 1024 * 1024;

fn read_sql(source: SqlSource) -> MddResult<String> {
    let refuse = |message: String| MddError::new(ErrorCode::InvalidArgument, "cli", message);
    let bounded = |reader: &mut dyn Read| -> MddResult<String> {
        let mut bytes = Vec::new();
        reader
            .take(MAX_STATEMENT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| refuse(format!("cannot read the statement: {error}")))?;
        if bytes.len() as u64 > MAX_STATEMENT_BYTES {
            return Err(refuse(format!(
                "the statement is longer than {MAX_STATEMENT_BYTES} bytes"
            )));
        }
        String::from_utf8(bytes).map_err(|_| refuse("the statement is not valid UTF-8".to_owned()))
    };
    match source {
        SqlSource::Text(text) => Ok(text),
        SqlSource::File(path) => {
            let mut file = std::fs::File::open(&path)
                .map_err(|error| refuse(format!("cannot read the statement: {error}")))?;
            bounded(&mut file)
        }
        SqlSource::Stdin => bounded(&mut io::stdin().lock()),
    }
}

fn query(args: QueryArgs) -> MddResult<i32> {
    let sql = read_sql(args.sql)?;
    let dataset = Dataset::open(
        &args.data.inputs,
        args.data.dialect,
        limits(args.data.deadline_ms),
        args.data.sql_limits,
    )?;
    let options = RunOptions {
        batch_rows: args.batch_rows,
        max_rows: args.max_rows,
        deadline_ms: args.data.deadline_ms,
    };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    match args.format {
        Format::Jsonl => {
            if JsonlSink::opened(&mut out, &dataset.description()).is_err() {
                return Ok(OUTPUT);
            }
            let mut sink = JsonlSink {
                out: &mut out,
                id: None,
            };
            let outcome = dataset.run(&sql, &options, &mut sink)?;
            if outcome.output_lost.is_some() || sink.terminal(&outcome.terminal).is_err() {
                return Ok(OUTPUT);
            }
            Ok(terminal_code(&outcome.terminal))
        }
        Format::Text => {
            let mut sink = TextSink::new(&mut out);
            let outcome = dataset.run(&sql, &options, &mut sink)?;
            let code = terminal_code(&outcome.terminal);
            let rows = sink.row_count();
            // A table is printed only for a complete answer: half a table that
            // ends in an error would read like a result.
            if code == OK && sink.finish().is_err() {
                return Ok(OUTPUT);
            }
            match &outcome.terminal.error {
                None => eprintln!("-- {rows} row(s), complete"),
                Some(error) => eprintln!(
                    "{}",
                    serde_json::to_string(error).unwrap_or_else(|_| "{}".to_owned())
                ),
            }
            if outcome.output_lost.is_some() {
                return Ok(OUTPUT);
            }
            Ok(code)
        }
    }
}

fn serve(args: ServeArgs) -> MddResult<i32> {
    let dataset = Dataset::open(
        &args.data.inputs,
        args.data.dialect,
        limits(args.data.deadline_ms),
        args.data.sql_limits,
    )?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut out = stdout.lock();
    match serve::serve(&dataset, &mut input, &mut out) {
        Ok(()) => Ok(OK),
        Err(serve::Failure::Output) => Ok(OUTPUT),
        Err(serve::Failure::Input(error)) => Err(MddError::new(
            ErrorCode::InternalFault,
            "cli.serve",
            format!("the request stream could not be read: {error}"),
        )),
    }
}

/// The MCP server: protocol messages on stdout, nothing else. A closed stdin is a clean
/// end; stdout that cannot be written is exit 4, as for the other commands.
fn mcp(config: mdd_mcp::Config) -> MddResult<i32> {
    let mut server = mdd_mcp::Server::new(config);
    let stdin = io::stdin();
    let stdout = io::stdout();
    match mdd_mcp::run_stdio(&mut server, &mut stdin.lock(), &mut stdout.lock()) {
        Ok(()) => Ok(OK),
        Err(_) => Ok(OUTPUT),
    }
}

fn single(value: serde_json::Value) -> MddResult<i32> {
    let encoded = serde_json::to_string(&value)
        .map_err(|e| MddError::new(ErrorCode::InternalFault, "serialization", e.to_string()))?;
    if encoded.len() >= 16 * 1024 * 1024 {
        return Err(MddError::new(
            ErrorCode::QuotaExceeded,
            "serialization",
            "JSON result byte budget exceeded",
        )
        .detail("budget", "max_result_bytes")
        .detail("limit", "16777216")
        .detail("observed", (encoded.len() + 1).to_string()));
    }
    let mut out = io::stdout().lock();
    if writeln!(out, "{encoded}")
        .and_then(|()| out.flush())
        .is_err()
    {
        return Ok(OUTPUT);
    }
    Ok(OK)
}

fn run() -> MddResult<i32> {
    let argv: Vec<_> = std::env::args_os().skip(1).collect();
    match args::parse(&argv)? {
        Command::Version => single(json!({
            "product":"MeguvizDexDash", "engine_version":env!("CARGO_PKG_VERSION"),
            "build_id":commands::capabilities()["build_id"],
            "implementation_scope":"unqualified development build"
        })),
        Command::Capabilities => single(commands::capabilities()),
        Command::InspectDex(paths) => single(commands::inspect(InputKind::RawDex, &paths)?),
        Command::InspectApk(paths) => single(commands::inspect(InputKind::Apk, &paths)?),
        Command::Query(args) => query(*args),
        Command::Serve(args) => serve(*args),
        Command::Mcp(config) => mcp(*config),
    }
}

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::to_string(&error).expect("error fields serialize as JSON")
            );
            refusal_code(&error)
        }
    };
    std::process::exit(code);
}
