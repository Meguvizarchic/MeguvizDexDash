//! The two output forms of `query` and `serve`.
//!
//! `jsonl` is the machine form: one JSON object per line, each tagged with `kind`.
//! Batches carry the `mdd.sdk-batch.v1` encoding unchanged, so no value passes through
//! a JSON number or a lossy string. `text` is the human form: an aligned table that
//! is lossy by design (see `cell_text`) and says so in the documentation, never a
//! machine interface.
use mdd_service::{Batch, Sink};
use mdd_sql::values::SqlValue;
use mdd_types::{MddError, ResultEnvelope};
use serde_json::{Value, json};
use std::io::{self, Write};

pub const STREAM_PROTOCOL: &str = "mdd.cli-stream.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    Jsonl,
    Text,
}

impl Format {
    pub fn parse(name: &str) -> Result<Self, MddError> {
        match name {
            "jsonl" => Ok(Self::Jsonl),
            "text" => Ok(Self::Text),
            other => Err(MddError::new(
                mdd_types::ErrorCode::UnsupportedCapability,
                "cli",
                format!("output format `{other}` is not available; use jsonl or text"),
            )),
        }
    }
}

fn io_error(error: serde_json::Error) -> io::Error {
    io::Error::other(error)
}

/// One JSON line. `id` echoes the request id in `serve` and is null in `query`.
pub struct JsonlSink<'a, W: Write> {
    pub out: &'a mut W,
    pub id: Option<&'a str>,
}

impl<W: Write> JsonlSink<'_, W> {
    fn id_json(&self) -> Result<String, io::Error> {
        serde_json::to_string(&self.id).map_err(io_error)
    }

    pub fn opened(out: &mut W, dataset: &Value) -> io::Result<()> {
        let line = json!({"kind": "opened", "protocol": STREAM_PROTOCOL, "dataset": dataset});
        writeln!(out, "{line}")?;
        out.flush()
    }

    pub fn terminal(&mut self, terminal: &ResultEnvelope) -> io::Result<()> {
        let id = self.id_json()?;
        let body = serde_json::to_string(terminal).map_err(io_error)?;
        writeln!(
            self.out,
            "{{\"kind\":\"terminal\",\"id\":{id},\"terminal\":{body}}}"
        )?;
        self.out.flush()
    }
}

impl<W: Write> Sink for JsonlSink<'_, W> {
    fn batch(&mut self, batch: &Batch<'_>) -> io::Result<()> {
        let id = self.id_json()?;
        self.out
            .write_all(format!("{{\"kind\":\"batch\",\"id\":{id},\"batch\":").as_bytes())?;
        self.out.write_all(batch.encoded)?;
        self.out.write_all(b"}\n")?;
        self.out.flush()
    }
}

/// An aligned table. The whole result is held until the end because column widths
/// depend on every row; the row count is bounded by the statement's own quota.
pub struct TextSink<'a, W: Write> {
    pub out: &'a mut W,
    columns: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl<'a, W: Write> TextSink<'a, W> {
    pub fn new(out: &'a mut W) -> Self {
        Self {
            out,
            columns: Vec::new(),
            rows: Vec::new(),
        }
    }

    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    pub fn finish(&mut self) -> io::Result<()> {
        if self.columns.is_empty() {
            return Ok(());
        }
        let mut widths: Vec<usize> = self.columns.iter().map(|c| c.chars().count()).collect();
        for row in &self.rows {
            for (width, cell) in widths.iter_mut().zip(row) {
                *width = (*width).max(cell.chars().count());
            }
        }
        let line = |cells: &[String]| {
            let padded: Vec<String> = cells
                .iter()
                .zip(&widths)
                .map(|(cell, width)| format!("{cell:<width$}"))
                .collect();
            format!("| {} |", padded.join(" | "))
        };
        writeln!(self.out, "{}", line(&self.columns))?;
        let rule: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
        writeln!(self.out, "|-{}-|", rule.join("-|-"))?;
        for row in &self.rows {
            writeln!(self.out, "{}", line(row))?;
        }
        self.out.flush()
    }
}

impl<W: Write> Sink for TextSink<'_, W> {
    fn batch(&mut self, batch: &Batch<'_>) -> io::Result<()> {
        if self.columns.is_empty() {
            self.columns = batch.columns.to_vec();
        }
        for row in batch.rows {
            self.rows.push(row.iter().map(cell_text).collect());
        }
        Ok(())
    }
}

/// Human rendering of one value. NULL is `NULL`, integers are decimal, a float is
/// its shortest round-trip form, bytes are `0x` hex. Text with unpaired surrogates
/// shows each as `\uXXXX`, and a DEX string that is not valid UTF-8 shows as
/// `mutf8:` hex, so a reader can tell these from ordinary text. Control characters
/// and line breaks in text are escaped so a cell stays on its line.
pub fn cell_text(value: &SqlValue) -> String {
    match value {
        SqlValue::Null => "NULL".to_owned(),
        SqlValue::Bool(v) => v.to_string(),
        SqlValue::I64(v) => v.0.to_string(),
        SqlValue::U64(v) => v.0.to_string(),
        SqlValue::F64(bits) => format!("{}", f64::from_bits(bits.0)),
        SqlValue::Bytes(bytes) => format!("0x{}", hex(bytes)),
        SqlValue::DexMutf8 { bytes, .. } => match std::str::from_utf8(bytes) {
            Ok(text) => escape(text.chars().map(Ok)),
            Err(_) => format!("mutf8:{}", hex(bytes)),
        },
        SqlValue::Text(text) => escape(
            char::decode_utf16(text.utf16.iter().copied())
                .map(|unit| unit.map_err(|error| error.unpaired_surrogate())),
        ),
    }
}

fn escape(units: impl Iterator<Item = Result<char, u16>>) -> String {
    let mut out = String::new();
    for unit in units {
        match unit {
            Ok('\n') => out.push_str("\\n"),
            Ok('\r') => out.push_str("\\r"),
            Ok('\t') => out.push_str("\\t"),
            Ok('\\') => out.push_str("\\\\"),
            Ok(c) if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            Ok(c) => out.push(c),
            Err(surrogate) => out.push_str(&format!("\\u{surrogate:04x}")),
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
    fn null_the_empty_string_and_the_word_null_stay_distinguishable_where_it_matters() {
        assert_eq!(cell_text(&SqlValue::Null), "NULL");
        assert_eq!(cell_text(&SqlValue::text("")), "");
        // The human form cannot tell the text NULL from a NULL; that is the
        // documented loss, and the reason the machine form exists.
        assert_eq!(cell_text(&SqlValue::text("NULL")), "NULL");
    }

    #[test]
    fn control_characters_and_backslashes_are_escaped_so_a_cell_stays_on_one_line() {
        assert_eq!(
            cell_text(&SqlValue::text("a\nb\tc\\d\u{1}")),
            "a\\nb\\tc\\\\d\\u0001"
        );
    }

    #[test]
    fn an_unpaired_surrogate_is_shown_as_its_unit_not_replaced() {
        assert_eq!(cell_text(&text(vec![0x61, 0xd800, 0x62])), "a\\ud800b");
        // A valid pair is one character.
        assert_eq!(cell_text(&text(vec![0xd83d, 0xde00])), "\u{1f600}");
    }

    #[test]
    fn integers_floats_and_bytes_have_one_spelling() {
        assert_eq!(
            cell_text(&SqlValue::U64(DecimalU64(u64::MAX))),
            "18446744073709551615"
        );
        assert_eq!(
            cell_text(&SqlValue::F64(DecimalU64(1.5f64.to_bits()))),
            "1.5"
        );
        assert_eq!(cell_text(&SqlValue::Bytes(vec![0, 0xff])), "0x00ff");
        assert_eq!(cell_text(&SqlValue::Bool(true)), "true");
    }

    #[test]
    fn a_dex_string_that_is_not_utf8_shows_as_hex_not_as_replacement_characters() {
        let value = SqlValue::DexMutf8 {
            bytes: vec![0xc0, 0x80],
            utf16_code_units: DecimalU64(1),
        };
        assert_eq!(cell_text(&value), "mutf8:c080");
    }
}
