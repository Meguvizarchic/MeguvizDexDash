//! Response windows over a statement's result stream.
//!
//! This is the engine side of the reference `query` tool's `limit`/`offset`: the
//! window is applied to the rows a statement produced, after any `LIMIT` or
//! `OFFSET` written in the SQL, and the SQL text is never rewritten to page. A
//! page therefore carries the statement's own metadata: the offset it started at,
//! how many rows it holds, whether more follow (`truncated`), where the next page
//! starts (`next_offset`) and, when it was counted, the exact total.
//!
//! Auto-continuation is a separate decision from a single window: a window over an
//! unordered statement is allowed (the reference returns it), but a driver that
//! walks pages must first ask [`paging_blocker`], because without a stable outer
//! `ORDER BY` two executions need not produce the same sequence.
use crate::invalid;
use mdd_types::{MddError, MddResult};
use serde::Serialize;

/// Rows per window the reference accepts (`limit`, 1 to 1000, default 200).
pub const DEFAULT_LIMIT: u64 = 200;
pub const MAX_LIMIT: u64 = 1_000;
/// `offset + limit` is at most this value in the reference tool.
pub const MAX_WINDOW_END: u64 = 100_000;
/// Statements per call in the reference tool (`sql` has 1 to 16 items).
pub const MAX_STATEMENTS: usize = 16;
/// `analysis_plan.text(task.get("sql"), 12000, "SQL")`.
pub const MAX_PAGED_SQL_CHARS: usize = 12_000;

/// A validated `(offset, limit)` window. `count_total` asks the executor to keep
/// stepping after the window so that the exact total can be reported; leaving it
/// off reports `total_rows: None` ("no exact total") instead of guessing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct SqlWindow {
    offset: u64,
    limit: u64,
    count_total: bool,
}

impl SqlWindow {
    pub fn new(offset: u64, limit: u64) -> MddResult<Self> {
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(invalid("WINDOW_LIMIT_OUT_OF_RANGE")
                .detail("limit", limit.to_string())
                .detail("maximum", MAX_LIMIT.to_string()));
        }
        if offset
            .checked_add(limit)
            .is_none_or(|end| end > MAX_WINDOW_END)
        {
            return Err(invalid("WINDOW_END_OUT_OF_RANGE")
                .detail("offset", offset.to_string())
                .detail("limit", limit.to_string())
                .detail("maximum_end", MAX_WINDOW_END.to_string()));
        }
        Ok(Self {
            offset,
            limit,
            count_total: false,
        })
    }

    /// Also count the rest of the result so `total_rows` is exact.
    pub fn counting_total(mut self) -> Self {
        self.count_total = true;
        self
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub fn counts_total(&self) -> bool {
        self.count_total
    }
}

/// What one executed window says about itself. The invariants mirror the
/// reference statement metadata the HostLab pager validates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SqlWindowReport {
    /// Rows skipped before the first returned row.
    pub offset: u64,
    /// Rows returned in this window.
    pub rows: u64,
    /// More rows exist after this window.
    pub truncated: bool,
    /// `offset + rows` when `truncated`, otherwise `None`.
    pub next_offset: Option<u64>,
    /// Exact number of rows the statement produces, when it was counted.
    pub total_rows: Option<u64>,
}

impl SqlWindowReport {
    pub(crate) fn finish(
        window: SqlWindow,
        rows: u64,
        truncated: bool,
        total_rows: Option<u64>,
    ) -> MddResult<Self> {
        let next_offset = truncated.then(|| window.offset + rows);
        if truncated && (rows == 0 || rows > window.limit) {
            return Err(internal("WINDOW_TRUNCATED_WITHOUT_ADVANCE"));
        }
        if let Some(total) = total_rows {
            let end = window.offset + rows;
            // The reference validator: rows may not overrun the total, a cursor
            // must stay inside it, and a terminal page must land exactly on it
            // (an empty page past the end is the only exception).
            let overruns = rows > 0 && end > total;
            let cursor_outside = next_offset.is_some_and(|next| next >= total);
            let terminal_mismatch =
                !truncated && !(rows == 0 && window.offset >= total) && end != total;
            if overruns || cursor_outside || terminal_mismatch {
                return Err(internal("WINDOW_TOTAL_INCONSISTENT")
                    .detail("total_rows", total.to_string())
                    .detail("offset", window.offset.to_string())
                    .detail("rows", rows.to_string()));
            }
        }
        Ok(Self {
            offset: window.offset,
            rows,
            truncated,
            next_offset,
            total_rows,
        })
    }
}

fn internal(reason: &str) -> MddError {
    MddError::new(mdd_types::ErrorCode::InternalFault, "sql.window", reason)
}

/// Why a statement must not be auto-continued across pages. The spellings are the
/// reference `analysis_paging.continuation_reason` results.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum PagingBlocker {
    VolatileOrderOrValues,
    RequiresStableOuterOrder,
}

impl PagingBlocker {
    pub fn reason(self) -> &'static str {
        match self {
            Self::VolatileOrderOrValues => "query_volatile_order_or_values",
            Self::RequiresStableOuterOrder => "query_requires_stable_outer_order",
        }
    }
}

#[derive(Debug)]
struct Token<'a> {
    text: &'a str,
    quoted: bool,
}

/// Find the end of a quoted token that starts at `start` (the delimiter), with
/// the reference regex semantics: a doubled delimiter continues the token, and if
/// the input ends first the match backs off to the most recent doubled pair; with
/// no such pair there is no match at all.
fn quoted_end(bytes: &[u8], start: usize, delimiter: u8) -> Option<usize> {
    let mut at = start + 1;
    let mut last_pair: Option<usize> = None;
    while at < bytes.len() {
        if bytes[at] == delimiter {
            if bytes.get(at + 1) == Some(&delimiter) {
                last_pair = Some(at);
                at += 2;
                continue;
            }
            return Some(at + 1);
        }
        at += 1;
    }
    last_pair.map(|pair| pair + 1)
}

/// Port of the token scan in the reference pager. Comments and string literals
/// are dropped, quoted identifiers are kept as tokens, and anything that is not a
/// token (punctuation, digits, an unterminated quote) is skipped one byte at a
/// time exactly like the regex does.
fn reference_tokens(sql: &str) -> Vec<Token<'_>> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        let next = bytes.get(at + 1).copied();
        if byte == b'-' && next == Some(b'-') {
            while at < bytes.len() && bytes[at] != b'\n' {
                at += 1;
            }
            continue;
        }
        if byte == b'/' && next == Some(b'*') {
            match sql[at + 2..].find("*/") {
                Some(close) => at += 2 + close + 2,
                None => at += 1,
            }
            continue;
        }
        match byte {
            b'\'' => match quoted_end(bytes, at, b'\'') {
                Some(end) => at = end,
                None => at += 1,
            },
            b'"' | b'`' => match quoted_end(bytes, at, byte) {
                Some(end) => {
                    tokens.push(Token {
                        text: &sql[at..end],
                        quoted: true,
                    });
                    at = end;
                }
                None => at += 1,
            },
            b'[' => match bytes[at + 1..].iter().position(|b| *b == b']') {
                Some(close) => {
                    let end = at + 1 + close + 1;
                    tokens.push(Token {
                        text: &sql[at..end],
                        quoted: true,
                    });
                    at = end;
                }
                None => at += 1,
            },
            b'(' | b')' => {
                tokens.push(Token {
                    text: &sql[at..at + 1],
                    quoted: false,
                });
                at += 1;
            }
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let mut end = at + 1;
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_')
                {
                    end += 1;
                }
                tokens.push(Token {
                    text: &sql[at..end],
                    quoted: false,
                });
                at = end;
            }
            _ => at += 1,
        }
    }
    tokens
}

/// The reference pager's volatility test for the token at `index`: a volatile
/// function call, or a bare `CURRENT_*` keyword that is not a quoted identifier.
fn volatile_at(tokens: &[Token<'_>], index: usize) -> bool {
    let token = &tokens[index];
    let word = if token.quoted {
        // `token[1:-1].upper()` in the reference; only used for the volatile
        // function names, which it compares before the `quoted` early exit.
        token.text[1..token.text.len() - 1].to_ascii_uppercase()
    } else {
        token.text.to_ascii_uppercase()
    };
    let next_is_paren = tokens.get(index + 1).is_some_and(|next| next.text == "(");
    (matches!(word.as_str(), "RANDOM" | "RANDOMBLOB" | "UUID" | "NOW") && next_is_paren)
        || (!token.quoted
            && matches!(
                word.as_str(),
                "CURRENT_TIMESTAMP" | "CURRENT_DATE" | "CURRENT_TIME"
            ))
}

/// True when the statement calls a volatile function or reads the clock, so two
/// evaluations of it need not agree. Same lexing as [`paging_blocker`].
pub fn is_volatile(sql: &str) -> bool {
    let tokens = reference_tokens(sql);
    (0..tokens.len()).any(|index| volatile_at(&tokens, index))
}

/// `Some(reason)` when a statement cannot be auto-continued across pages.
pub fn paging_blocker(sql: &str) -> Option<PagingBlocker> {
    let tokens = reference_tokens(sql);
    let mut depth: i64 = 0;
    let mut outer: Vec<String> = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if volatile_at(&tokens, index) {
            return Some(PagingBlocker::VolatileOrderOrValues);
        }
        if token.quoted {
            continue;
        }
        let word = token.text.to_ascii_uppercase();
        match token.text {
            "(" => depth += 1,
            ")" => depth -= 1,
            _ if depth == 0 => outer.push(word),
            _ => (),
        }
    }
    let ordered = outer
        .windows(2)
        .any(|pair| pair[0] == "ORDER" && pair[1] == "BY");
    if ordered {
        None
    } else {
        Some(PagingBlocker::RequiresStableOuterOrder)
    }
}

/// Split a script into statements at top-level semicolons, honouring SQLite's
/// string, quoted-identifier and comment lexing. Empty statements and fragments
/// that hold only whitespace and comments are dropped. An unterminated quote is
/// an error rather than a guess; an unterminated block comment runs to the end of
/// the script, as SQLite lexes it.
pub fn split_statements(script: &str) -> MddResult<Vec<String>> {
    let bytes = script.as_bytes();
    let mut statements = Vec::new();
    let mut start = 0;
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'-' if bytes.get(at + 1) == Some(&b'-') => {
                while at < bytes.len() && bytes[at] != b'\n' {
                    at += 1;
                }
            }
            b'/' if bytes.get(at + 1) == Some(&b'*') => match script[at + 2..].find("*/") {
                Some(close) => at += 2 + close + 2,
                None => at = bytes.len(),
            },
            quote @ (b'\'' | b'"' | b'`') => {
                at += 1;
                loop {
                    match bytes.get(at) {
                        None => return Err(invalid("UNTERMINATED_QUOTE")),
                        Some(&b) if b == quote => {
                            if bytes.get(at + 1) == Some(&quote) {
                                at += 2;
                            } else {
                                at += 1;
                                break;
                            }
                        }
                        Some(_) => at += 1,
                    }
                }
            }
            b'[' => match bytes[at + 1..].iter().position(|b| *b == b']') {
                Some(close) => at += 1 + close + 1,
                None => return Err(invalid("UNTERMINATED_BRACKET")),
            },
            b';' => {
                push_statement(&mut statements, &script[start..at]);
                at += 1;
                start = at;
            }
            _ => at += 1,
        }
    }
    push_statement(&mut statements, &script[start..]);
    Ok(statements)
}

fn push_statement(statements: &mut Vec<String>, text: &str) {
    if !is_blank_or_comment(text) {
        statements.push(text.trim().to_owned());
    }
}

/// Only whitespace and comments (an unterminated block comment included).
fn is_blank_or_comment(text: &str) -> bool {
    let mut rest = text.trim_start();
    loop {
        if let Some(after) = rest.strip_prefix("--") {
            rest = after
                .split_once('\n')
                .map_or("", |(_, tail)| tail)
                .trim_start();
        } else if let Some(after) = rest.strip_prefix("/*") {
            rest = after
                .split_once("*/")
                .map_or("", |(_, tail)| tail)
                .trim_start();
        } else {
            return rest.is_empty();
        }
    }
}

/// Total SQL bytes one `query` call may carry across all its items.
pub const MAX_SCRIPT_BYTES: usize = 64 * 1024;

/// Flatten the `sql[]` items of one call into its ordered statement list, the way
/// the reference `query` tool does: one to sixteen items, none blank, at most
/// [`MAX_SCRIPT_BYTES`] of SQL in all, and each item may itself hold several
/// statements separated by top-level semicolons. A statement's index in the
/// returned list is the index an error reports; there is no cap on the number of
/// statements an item expands to.
pub fn script_statements(items: &[&str]) -> MddResult<Vec<String>> {
    if items.is_empty()
        || items.len() > MAX_STATEMENTS
        || items.iter().any(|item| item.trim().is_empty())
    {
        return Err(invalid("STATEMENT_COUNT_OUT_OF_RANGE")
            .detail("items", items.len().to_string())
            .detail("maximum", MAX_STATEMENTS.to_string()));
    }
    let total: usize = items.iter().map(|item| item.len()).sum();
    if total > MAX_SCRIPT_BYTES {
        return Err(invalid("SQL_TOTAL_BYTES")
            .detail("bytes", total.to_string())
            .detail("maximum", MAX_SCRIPT_BYTES.to_string()));
    }
    let mut statements = Vec::new();
    for (position, item) in items.iter().enumerate() {
        match split_statements(item) {
            Ok(parts) => statements.extend(parts),
            // The reference reports a lexing failure at the *item* that holds it,
            // while an execution failure is reported at the flattened statement.
            Err(error) => return Err(error.detail("statement_index", position.to_string())),
        }
    }
    Ok(statements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_bounds_follow_the_reference_tool() {
        assert!(SqlWindow::new(0, 1).is_ok());
        assert!(SqlWindow::new(99_000, 1_000).is_ok());
        for (offset, limit) in [(0, 0), (0, 1_001), (99_001, 1_000), (u64::MAX, 1)] {
            let error = SqlWindow::new(offset, limit).unwrap_err();
            assert_eq!(error.code, mdd_types::ErrorCode::InvalidArgument);
        }
        assert!(!SqlWindow::new(0, 5).unwrap().counts_total());
        assert!(
            SqlWindow::new(0, 5)
                .unwrap()
                .counting_total()
                .counts_total()
        );
    }

    #[test]
    fn report_invariants_match_the_reference_validator() {
        let window = SqlWindow::new(2, 2).unwrap();
        // Truncated page: next offset is offset + rows.
        let page = SqlWindowReport::finish(window, 2, true, Some(5)).unwrap();
        assert_eq!(page.next_offset, Some(4));
        // Last page: no next offset, terminal count equals total.
        let last = SqlWindowReport::finish(window, 2, false, Some(4)).unwrap();
        assert_eq!(last.next_offset, None);
        // Empty page beyond the end is not an error and has no cursor.
        let beyond =
            SqlWindowReport::finish(SqlWindow::new(9, 2).unwrap(), 0, false, Some(4)).unwrap();
        assert_eq!(beyond.rows, 0);
        // A cursor that cannot advance, a total that the rows overrun, a terminal
        // count that disagrees with the total: all refused.
        assert!(SqlWindowReport::finish(window, 0, true, None).is_err());
        assert!(SqlWindowReport::finish(window, 2, true, Some(4)).is_err());
        assert!(SqlWindowReport::finish(window, 2, false, Some(7)).is_err());
        assert!(SqlWindowReport::finish(window, 2, false, Some(3)).is_err());
    }

    /// The Rust port must agree with the frozen reference function on every
    /// recorded case. The oracle is `analysis_paging.continuation_reason` run by
    /// `generate_paging_cases.py`; nothing in this test derives expected values from
    /// the Rust code. A missing or empty case file is a failure, never a skip.
    #[test]
    fn paging_blocker_matches_the_frozen_reference_on_recorded_cases() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/corpus/hostlab/paging-blocker-cases.json");
        let text = std::fs::read_to_string(&path).expect("paging blocker case file must exist");
        let document: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(document["schema_version"], "mdd.paging-blocker-cases.v1");
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/corpus/hostlab/source-8782f43/analysis_paging.py");
        let digest = mdd_types::sha256(&std::fs::read(&source).unwrap());
        assert_eq!(
            document["oracle_sha256"].as_str(),
            Some(digest.as_str()),
            "cases were recorded from a different oracle copy"
        );
        let cases = document["cases"].as_array().unwrap();
        assert!(cases.len() >= 50, "case list shrank: {}", cases.len());
        let mut seen = std::collections::BTreeSet::new();
        for case in cases {
            let sql = case["sql"].as_str().unwrap();
            let expected = case["reason"].as_str();
            let actual = paging_blocker(sql).map(PagingBlocker::reason);
            assert_eq!(actual, expected, "paging blocker differs for {sql:?}");
            seen.insert(expected.unwrap_or("none").to_string());
        }
        assert_eq!(seen.len(), 3, "the case list must exercise every outcome");
    }

    #[test]
    fn calls_are_flattened_like_the_reference_tool() {
        let two = script_statements(&["SELECT 1; SELECT 2", "SELECT 3;"]).unwrap();
        assert_eq!(two, ["SELECT 1", "SELECT 2", "SELECT 3"]);
        // No cap on what one item expands to, a cap of sixteen items, none blank.
        let many = "SELECT 1;".repeat(65);
        assert_eq!(script_statements(&[many.as_str()]).unwrap().len(), 65);
        assert!(script_statements(&["SELECT 1"; 17]).is_err());
        assert!(script_statements(&[]).is_err());
        assert!(script_statements(&["SELECT 1", "   "]).is_err());
        // An item of only semicolons is allowed beside another item and yields
        // nothing; a call that yields nothing at all is an empty answer.
        assert_eq!(script_statements(&["SELECT 1", ";"]).unwrap(), ["SELECT 1"]);
        assert!(script_statements(&[";"]).unwrap().is_empty());
        // The byte budget is over all items together.
        let big = "x".repeat(MAX_SCRIPT_BYTES / 2 + 1);
        assert!(script_statements(&[big.as_str(), big.as_str()]).is_err());
        // A lexing failure names the item that holds it, not a flattened index.
        let error = script_statements(&["SELECT 1; SELECT 2", "SELECT 'open"]).unwrap_err();
        assert_eq!(error.details["statement_index"], "1");
    }

    #[test]
    fn splitting_respects_quoting_and_comments() {
        let parts = split_statements(
            "SELECT 'a;b' AS x; -- trailing; comment\n SELECT \"c;d\" /* e; */ , [f;g] FROM t;;",
        )
        .unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "SELECT 'a;b' AS x");
        assert!(parts[1].contains("\"c;d\"") && parts[1].contains("[f;g]"));
        assert_eq!(split_statements("  ;; ").unwrap(), Vec::<String>::new());
        assert_eq!(split_statements("SELECT 1").unwrap(), ["SELECT 1"]);
        assert!(split_statements("SELECT 'open").is_err());
        assert!(split_statements("SELECT [open").is_err());
        // An unterminated block comment runs to the end; a fragment of only
        // comments is not a statement.
        assert_eq!(split_statements("SELECT 1; /* open").unwrap(), ["SELECT 1"]);
        assert_eq!(
            split_statements("-- a\n;/* b */;").unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(split_statements("SELECT /* open").unwrap().len(), 1);
        // A doubled quote stays inside the literal.
        assert_eq!(
            split_statements("SELECT 'it''s;ok'; SELECT 2")
                .unwrap()
                .len(),
            2
        );
    }
}
