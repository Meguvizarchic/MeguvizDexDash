//! `serve`: one dataset, many statements, one request per input line.
//!
//! This replaces the interactive text session that a host drives with sentinel
//! queries: every request carries an `id`, and every answer is framed, so the
//! reader never has to guess where a result ends.
//!
//! Requests (one JSON object per line on stdin):
//!   {"id":"r1","sql":"SELECT ..."}      optional: batch_rows, max_rows, deadline_ms
//!   {"op":"close"}                      end the session (end of input does the same)
//!
//! Output (one JSON object per line on stdout): an `opened` line first, then for each
//! request its `batch` lines and exactly one `terminal` line. A line that cannot be
//! understood as a request gets one `rejected` line instead; nothing ran for it, and
//! the session goes on. Requests are served in order, one at a time.
use crate::output::JsonlSink;
use mdd_service::{
    DEFAULT_BATCH_ROWS, Dataset, RunOptions,
    lines::{Line, read_line},
};
use mdd_types::{ErrorCode, MddError};
use serde::Deserialize;
use std::io::{self, BufRead, Write};

pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_ID_BYTES: usize = 128;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: Option<String>,
    op: Option<String>,
    sql: Option<String>,
    batch_rows: Option<u32>,
    max_rows: Option<u64>,
    deadline_ms: Option<u64>,
}

/// How a session can end other than by `close` or end of input.
#[derive(Debug)]
pub enum Failure {
    /// stdin could not be read.
    Input(io::Error),
    /// stdout could not be written; nobody is left to tell, so nothing is kept.
    Output,
}

impl From<io::Error> for Failure {
    /// Every `?` on a write inside `serve` lands here.
    fn from(_: io::Error) -> Self {
        Self::Output
    }
}

fn rejected(out: &mut impl Write, id: Option<&str>, error: &MddError) -> io::Result<()> {
    let line = serde_json::json!({"kind": "rejected", "id": id, "error": error});
    writeln!(out, "{line}")?;
    out.flush()
}

fn invalid(message: impl Into<String>) -> MddError {
    MddError::new(ErrorCode::InvalidArgument, "cli.serve", message)
}

/// Serve until `close` or end of input.
pub fn serve(
    dataset: &Dataset,
    input: &mut impl BufRead,
    out: &mut impl Write,
) -> Result<(), Failure> {
    JsonlSink::opened(out, &dataset.description())?;
    loop {
        let bytes = match read_line(input, MAX_REQUEST_BYTES).map_err(Failure::Input)? {
            Line::Eof => return Ok(()),
            Line::TooLong => {
                rejected(
                    out,
                    None,
                    &invalid(format!(
                        "a request line may not exceed {MAX_REQUEST_BYTES} bytes"
                    )),
                )?;
                continue;
            }
            Line::Text(bytes) => bytes,
        };
        let trimmed = bytes.trim_ascii();
        if trimmed.is_empty() {
            continue;
        }
        let request: Request = match serde_json::from_slice(trimmed) {
            Ok(request) => request,
            Err(error) => {
                rejected(out, None, &invalid(format!("not a valid request: {error}")))?;
                continue;
            }
        };
        let id = request.id.as_deref();
        match request.op.as_deref() {
            Some("close") => return Ok(()),
            None | Some("query") => {}
            Some(other) => {
                rejected(out, id, &invalid(format!("unknown op `{other}`")))?;
                continue;
            }
        }
        let Some(id) = id.filter(|id| !id.is_empty() && id.len() <= MAX_ID_BYTES) else {
            rejected(
                out,
                None,
                &invalid(format!(
                    "a query needs an `id` of 1 to {MAX_ID_BYTES} bytes"
                )),
            )?;
            continue;
        };
        let Some(sql) = request.sql.as_deref() else {
            rejected(out, Some(id), &invalid("a query needs a `sql` string"))?;
            continue;
        };
        let options = RunOptions {
            batch_rows: request.batch_rows.unwrap_or(DEFAULT_BATCH_ROWS),
            max_rows: request.max_rows,
            deadline_ms: request.deadline_ms,
        };
        let mut sink = JsonlSink::new(&mut *out, Some(id))?;
        match dataset.run(sql, &options, &mut sink) {
            Ok(outcome) => {
                if outcome.output_lost.is_some() {
                    return Err(Failure::Output);
                }
                sink.terminal(&outcome.terminal)?;
            }
            Err(error) => rejected(out, Some(id), &error)?,
        }
    }
}
