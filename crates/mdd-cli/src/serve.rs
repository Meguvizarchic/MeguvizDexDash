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
use crate::{
    dataset::Dataset,
    output::JsonlSink,
    run::{DEFAULT_BATCH_ROWS, RunOptions},
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

enum Line {
    Eof,
    Text(Vec<u8>),
    TooLong,
}

/// The next line, never holding more than `MAX_REQUEST_BYTES` of it. An over-long
/// line is skipped to its end so the next request starts cleanly.
fn read_line(input: &mut impl BufRead) -> io::Result<Line> {
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let buffer = input.fill_buf()?;
        if buffer.is_empty() {
            return Ok(if too_long {
                Line::TooLong
            } else if line.is_empty() {
                Line::Eof
            } else {
                Line::Text(line)
            });
        }
        let (take, found) = match buffer.iter().position(|b| *b == b'\n') {
            Some(position) => (position + 1, true),
            None => (buffer.len(), false),
        };
        if !too_long {
            if line.len() + take > MAX_REQUEST_BYTES + 1 {
                too_long = true;
                line.clear();
            } else {
                line.extend_from_slice(&buffer[..take]);
            }
        }
        input.consume(take);
        if found {
            return Ok(if too_long {
                Line::TooLong
            } else {
                Line::Text(line)
            });
        }
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
        let bytes = match read_line(input).map_err(Failure::Input)? {
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
        let mut sink = JsonlSink {
            out: &mut *out,
            id: Some(id),
        };
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

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(bytes: &[u8]) -> Vec<String> {
        let mut input = io::Cursor::new(bytes.to_vec());
        let mut found = Vec::new();
        loop {
            match read_line(&mut input).unwrap() {
                Line::Eof => return found,
                Line::TooLong => found.push("<too long>".to_owned()),
                Line::Text(text) => found.push(String::from_utf8(text).unwrap()),
            }
        }
    }

    #[test]
    fn lines_split_on_newline_and_the_last_may_lack_one() {
        assert_eq!(lines(b"a\nbc\nd"), ["a\n", "bc\n", "d"]);
        assert!(lines(b"").is_empty());
        assert_eq!(lines(b"\n"), ["\n"]);
    }

    #[test]
    fn a_line_over_the_limit_is_skipped_to_its_end_and_the_next_one_is_clean() {
        let mut input = vec![b'x'; MAX_REQUEST_BYTES + 100];
        input.extend_from_slice(b"\nnext\n");
        assert_eq!(lines(&input), ["<too long>", "next\n"]);
    }

    #[test]
    fn a_line_of_exactly_the_limit_is_accepted() {
        let mut input = vec![b'x'; MAX_REQUEST_BYTES];
        input.push(b'\n');
        let found = lines(&input);
        assert_eq!(found.len(), 1);
        assert_ne!(found[0], "<too long>");
    }

    #[test]
    fn an_over_long_last_line_without_a_newline_is_still_reported() {
        let input = vec![b'x'; MAX_REQUEST_BYTES + 5];
        assert_eq!(lines(&input), ["<too long>"]);
    }
}
