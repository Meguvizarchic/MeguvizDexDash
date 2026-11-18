//! Exporting a whole query result.
//!
//! The engine pages a result by `offset + limit`, at most 100 000 rows. An export that must be
//! complete cannot lean on that window, so it asks for the result a page at a time through the
//! statement's own `LIMIT … OFFSET …` over a total order of all columns, counts the rows first, and
//! only keeps the file when exactly that many rows were written. A file that is not complete is
//! deleted, never left under the name the user chose.
use crate::engine::{Engine, Failure, Lease};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const DEFAULT_PAGE_ROWS: usize = 1000;
/// The engine returns at most 1000 rows per statement (the `limit` of its `query` tool).
pub const MAX_PAGE_ROWS: usize = 1000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Csv,
    Jsonl,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ExportRequest {
    pub call_id: String,
    pub handle: u64,
    pub sql: String,
    pub format: Format,
    pub path: String,
    pub page_rows: Option<usize>,
    pub deadline_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExportReport {
    pub path: String,
    pub format: Format,
    pub rows: u64,
    pub bytes: u64,
    pub columns: Vec<String>,
    pub pages: u64,
    pub sql: String,
    pub snapshot_ids: Vec<String>,
    pub elapsed_ms: u64,
    /// Always true in a report: an incomplete export is an error, not a report.
    pub complete: bool,
}

/// The one statement to export, without its trailing semicolons, or why it is not exportable.
pub fn single_statement(sql: &str) -> Result<String, Failure> {
    let bytes: Vec<char> = sql.chars().collect();
    let mut cut = 0usize; // end of the last significant character
    let mut first_word = String::new();
    let mut seen_word = false;
    let mut i = 0usize;
    let mut semicolons_after = false;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            '\'' | '"' | '`' => {
                // a quoted run; a doubled quote stays inside it
                let quote = c;
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == quote {
                        if bytes.get(i + 1) == Some(&quote) {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                if i >= bytes.len() {
                    return Err(Failure::invalid("a quoted string or name is not closed"));
                }
                if semicolons_after {
                    return Err(Failure::invalid("export takes exactly one statement"));
                }
                seen_word = true;
                i += 1;
                cut = i;
            }
            '-' if bytes.get(i + 1) == Some(&'-') => {
                while i < bytes.len() && bytes[i] != '\n' {
                    i += 1;
                }
            }
            '/' if bytes.get(i + 1) == Some(&'*') => {
                i += 2;
                loop {
                    if i + 1 >= bytes.len() {
                        return Err(Failure::invalid("a /* comment is not closed"));
                    }
                    if bytes[i] == '*' && bytes[i + 1] == '/' {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            }
            ';' => {
                semicolons_after = true;
                i += 1;
            }
            c if c.is_whitespace() => i += 1,
            c => {
                if semicolons_after {
                    return Err(Failure::invalid("export takes exactly one statement"));
                }
                if !seen_word && c.is_alphabetic() {
                    // the leading keyword
                    let mut j = i;
                    while j < bytes.len() && bytes[j].is_alphanumeric() {
                        first_word.push(bytes[j]);
                        j += 1;
                    }
                    seen_word = true;
                    i = j;
                    cut = i;
                    continue;
                }
                seen_word = true;
                i += 1;
                cut = i;
            }
        }
    }
    if !seen_word {
        return Err(Failure::invalid("the statement is empty"));
    }
    match first_word.to_ascii_lowercase().as_str() {
        "select" | "with" | "values" => {}
        other => {
            return Err(Failure::invalid(format!(
                "only a query can be exported (it starts with {other:?})"
            )));
        }
    }
    Ok(bytes[..cut].iter().collect::<String>().trim().to_owned())
}

fn count_sql(statement: &str) -> String {
    format!("SELECT count(*) FROM (\n{statement}\n)")
}

fn probe_sql(statement: &str) -> String {
    format!("SELECT * FROM (\n{statement}\n) LIMIT 1")
}

fn page_sql(statement: &str, columns: usize, rows: usize, offset: u64) -> String {
    let order: Vec<String> = (1..=columns).map(|n| n.to_string()).collect();
    format!(
        "SELECT * FROM (\n{statement}\n) ORDER BY {} LIMIT {rows} OFFSET {offset}",
        order.join(", ")
    )
}

/// The text a CSV field holds for one typed cell. NULL is an empty field with no quotes; text is
/// always quoted when it is empty, so the two stay apart.
pub fn csv_field(cell: &Value) -> String {
    let kind = cell["type"].as_str().unwrap_or("");
    let value = &cell["value"];
    let text = match (kind, value) {
        ("null", _) | (_, Value::Null) => return String::new(),
        ("binary", Value::String(hex)) => format!("0x{hex}"),
        (_, Value::String(text)) => text.clone(),
        (_, other) => other.to_string(),
    };
    let needs_quotes = text.is_empty()
        || text.contains([',', '"', '\n', '\r'])
        || text.starts_with(' ')
        || text.ends_with(' ');
    if needs_quotes {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text
    }
}

fn csv_name(name: &str) -> String {
    if name.contains([',', '"', '\n', '\r']) || name.is_empty() {
        format!("\"{}\"", name.replace('"', "\"\""))
    } else {
        name.to_owned()
    }
}

struct Sink {
    out: BufWriter<File>,
    bytes: u64,
    format: Format,
}

impl Sink {
    fn line(&mut self, text: &str) -> Result<(), Failure> {
        self.out
            .write_all(text.as_bytes())
            .and_then(|()| self.out.write_all(b"\n"))
            .map_err(|error| {
                Failure::new(
                    "EXPORT_WRITE",
                    format!("cannot write the export file: {error}"),
                )
            })?;
        self.bytes += text.len() as u64 + 1;
        Ok(())
    }

    fn row(&mut self, cells: &[Value]) -> Result<(), Failure> {
        match self.format {
            Format::Csv => {
                let fields: Vec<String> = cells.iter().map(csv_field).collect();
                self.line(&fields.join(","))
            }
            Format::Jsonl => self.line(&Value::Array(cells.to_vec()).to_string()),
        }
    }
}

fn partial_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".partial");
    path.with_file_name(name)
}

/// The statement's result, whole, in a file. `progress(done, total)` is told after every page.
pub fn export_query(
    engine: &Engine,
    lease: &Lease<'_>,
    request: &ExportRequest,
    mut progress: impl FnMut(u64, u64),
) -> Result<ExportReport, Failure> {
    let started = Instant::now();
    let statement = single_statement(&request.sql)?;
    let page_rows = request
        .page_rows
        .unwrap_or(DEFAULT_PAGE_ROWS)
        .clamp(1, MAX_PAGE_ROWS);
    let target = PathBuf::from(&request.path);
    if target.as_os_str().is_empty() || target.is_dir() {
        return Err(Failure::invalid("choose a file to write"));
    }
    let snapshot_ids: Vec<String> = engine
        .datasets()
        .into_iter()
        .filter(|d| d.handle == request.handle)
        .flat_map(|d| {
            d.summary["snapshot_manifest"]["sources"]
                .as_array()
                .map(|all| {
                    all.iter()
                        .filter_map(|s| s["occurrence_id"].as_str().map(str::to_owned))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
        .collect();

    let run = |sql: String| -> Result<Value, Failure> {
        let mut args = json!({"sql": [sql], "limit": page_rows.max(1), "offset": 0});
        if let Some(ms) = request.deadline_ms {
            args["timeout_ms"] = json!(ms);
        }
        let reply = engine.call(lease, "query", Some(request.handle), args)?;
        if !reply.ok {
            return Err(failure_of(&reply.data));
        }
        Ok(reply.data["statements"][0].clone())
    };

    // 1. how many rows the whole result has
    let counted = run(count_sql(&statement))?;
    let total: u64 = counted["rows"][0][0]["value"]
        .as_str()
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| Failure::new("EXPORT_COUNT", "the engine did not answer the row count"))?;
    // 2. the columns
    let probe = run(probe_sql(&statement))?;
    let columns: Vec<String> = probe["columns"]
        .as_array()
        .ok_or_else(|| {
            Failure::new(
                "EXPORT_COLUMNS",
                "the engine did not name the result columns",
            )
        })?
        .iter()
        .map(|c| c["name"].as_str().unwrap_or_default().to_owned())
        .collect();
    if columns.is_empty() {
        return Err(Failure::new(
            "EXPORT_COLUMNS",
            "the statement has no columns",
        ));
    }

    if let Some(parent) = target.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|error| {
            Failure::new(
                "EXPORT_WRITE",
                format!("cannot create {}: {error}", parent.display()),
            )
        })?;
    }
    let partial = partial_path(&target);
    let file = File::create(&partial).map_err(|error| {
        Failure::new(
            "EXPORT_WRITE",
            format!("cannot create {}: {error}", partial.display()),
        )
    })?;
    let mut sink = Sink {
        out: BufWriter::new(file),
        bytes: 0,
        format: request.format,
    };

    let result = (|| -> Result<(u64, u64), Failure> {
        match request.format {
            Format::Csv => sink.line(
                &columns
                    .iter()
                    .map(|c| csv_name(c))
                    .collect::<Vec<_>>()
                    .join(","),
            )?,
            Format::Jsonl => sink.line(
                &json!({"mdd_export": 1, "columns": probe["columns"], "sql": request.sql,
                        "snapshot_ids": snapshot_ids, "rows": total})
                .to_string(),
            )?,
        }
        let mut written = 0u64;
        let mut pages = 0u64;
        progress(0, total);
        while written < total {
            if lease.is_cancelled() {
                return Err(Failure::new("CANCELLED", "cancelled"));
            }
            let page = run(page_sql(&statement, columns.len(), page_rows, written))?;
            if page["truncated"].as_bool().unwrap_or(false) {
                return Err(Failure::new(
                    "EXPORT_TRUNCATED",
                    "the engine cut a page short (its result budget); export with fewer columns or smaller pages",
                ));
            }
            let rows = page["rows"].as_array().cloned().unwrap_or_default();
            if rows.is_empty() {
                return Err(Failure::new(
                    "EXPORT_SHORT",
                    format!(
                        "the engine returned no rows at offset {written} although the result has {total}"
                    ),
                ));
            }
            for row in &rows {
                let cells = row
                    .as_array()
                    .ok_or_else(|| Failure::new("EXPORT_SHAPE", "a row is not a list of cells"))?;
                if cells.len() != columns.len() {
                    return Err(Failure::new(
                        "EXPORT_SHAPE",
                        "a row has the wrong number of cells",
                    ));
                }
                sink.row(cells)?;
            }
            written += rows.len() as u64;
            pages += 1;
            progress(written.min(total), total);
        }
        if written != total {
            return Err(Failure::new(
                "EXPORT_COUNT",
                format!("wrote {written} rows but the result has {total}"),
            ));
        }
        sink.out.flush().map_err(|error| {
            Failure::new(
                "EXPORT_WRITE",
                format!("cannot write the export file: {error}"),
            )
        })?;
        Ok((written, pages))
    })();

    match result {
        Ok((rows, pages)) => {
            drop(sink.out);
            fs::rename(&partial, &target).map_err(|error| {
                let _ = fs::remove_file(&partial);
                Failure::new(
                    "EXPORT_WRITE",
                    format!("cannot place {}: {error}", target.display()),
                )
            })?;
            Ok(ExportReport {
                path: target.display().to_string(),
                format: request.format,
                rows,
                bytes: sink.bytes,
                columns,
                pages,
                sql: request.sql.clone(),
                snapshot_ids,
                elapsed_ms: started.elapsed().as_millis() as u64,
                complete: true,
            })
        }
        Err(failure) => {
            drop(sink.out);
            let _ = fs::remove_file(&partial);
            Err(failure)
        }
    }
}

pub fn failure_of(data: &Value) -> Failure {
    let error = &data["error"];
    Failure {
        code: error["code"].as_str().unwrap_or("ENGINE_ERROR").to_owned(),
        message: error["message"]
            .as_str()
            .unwrap_or("the engine reported an error")
            .to_owned(),
        engine: Some(error.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trailing_semicolon_and_comment_are_dropped_but_a_second_statement_is_refused() {
        assert_eq!(single_statement("SELECT 1;").unwrap(), "SELECT 1");
        assert_eq!(single_statement("  select 1 ;; ").unwrap(), "select 1");
        assert_eq!(
            single_statement("SELECT ';' AS semi -- tail\n;").unwrap(),
            "SELECT ';' AS semi"
        );
        assert_eq!(
            single_statement("WITH t AS (SELECT 1) SELECT * FROM t").unwrap(),
            "WITH t AS (SELECT 1) SELECT * FROM t"
        );
        assert!(single_statement("SELECT 1; SELECT 2").is_err());
        assert!(single_statement("SELECT 1; -- c\nSELECT 2").is_err());
        assert!(single_statement("   ").is_err());
        assert!(single_statement("-- only a comment").is_err());
        assert!(single_statement("DROP TABLE x").is_err());
        assert!(single_statement("SELECT 'open").is_err());
        assert!(single_statement("SELECT 1 /* open").is_err());
    }

    #[test]
    fn a_comment_inside_the_statement_stays_and_the_wrapper_closes_on_its_own_line() {
        let statement = single_statement("SELECT 1 -- note").unwrap();
        // the comment is the last thing: it is cut off, and the wrapper's ")" would not be swallowed
        assert_eq!(statement, "SELECT 1");
        let wrapped = page_sql(&statement, 2, 10, 20);
        assert_eq!(
            wrapped,
            "SELECT * FROM (\nSELECT 1\n) ORDER BY 1, 2 LIMIT 10 OFFSET 20"
        );
    }

    #[test]
    fn csv_keeps_null_empty_text_and_special_characters_apart() {
        let cell = |kind: &str, value: Value| json!({"type": kind, "value": value});
        assert_eq!(csv_field(&cell("null", Value::Null)), "");
        assert_eq!(csv_field(&cell("utf8", json!(""))), "\"\"");
        assert_eq!(csv_field(&cell("utf8", json!("a,b"))), "\"a,b\"");
        assert_eq!(
            csv_field(&cell("utf8", json!("say \"hi\""))),
            "\"say \"\"hi\"\"\""
        );
        assert_eq!(
            csv_field(&cell("utf8", json!("line\nbreak"))),
            "\"line\nbreak\""
        );
        assert_eq!(
            csv_field(&cell("uint64", json!("18446744073709551615"))),
            "18446744073709551615"
        );
        assert_eq!(csv_field(&cell("int64", json!("-5"))), "-5");
        assert_eq!(csv_field(&cell("float64", json!(1.5))), "1.5");
        assert_eq!(csv_field(&cell("float64", json!("NaN"))), "NaN");
        assert_eq!(csv_field(&cell("binary", json!("00ff"))), "0x00ff");
        assert_eq!(csv_field(&cell("utf8", json!("é中"))), "é中");
        assert_eq!(csv_field(&cell("utf8", json!(" lead"))), "\" lead\"");
        assert_eq!(csv_field(&cell("utf8", json!("trail "))), "\"trail \"");
        assert_eq!(
            csv_field(&cell("utf8", json!("carriage\rreturn"))),
            "\"carriage\rreturn\""
        );
    }
}
