//! Direct streaming JSON writer for `mdd.sdk-batch.v1` avoiding intermediate `serde_json::Value` trees.

use std::ffi::OsStr;

/// Check runtime toggle `MDD_OPT_WIRE_DIRECT_JSON` (`"0"` disables fast path; default `true`).
#[inline]
pub fn wire_direct_json_enabled() -> bool {
    std::env::var_os("MDD_OPT_WIRE_DIRECT_JSON").as_deref() != Some(OsStr::new("0"))
}

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

#[inline]
fn push_hex_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.reserve(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_LOWER[usize::from(b >> 4)]);
        out.push(HEX_LOWER[usize::from(b & 0x0f)]);
    }
}

#[inline]
fn push_u64_dec(out: &mut Vec<u8>, mut value: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    out.extend_from_slice(&buf[i..]);
}

#[inline]
fn push_i64_dec(out: &mut Vec<u8>, value: i64) {
    if value < 0 {
        out.push(b'-');
    }
    push_u64_dec(out, value.unsigned_abs());
}

#[inline]
fn push_escaped_control_or_quote(out: &mut Vec<u8>, b: u8) {
    match b {
        b'"' => out.extend_from_slice(b"\\\""),
        b'\\' => out.extend_from_slice(b"\\\\"),
        0x08 => out.extend_from_slice(b"\\b"),
        0x0c => out.extend_from_slice(b"\\f"),
        b'\n' => out.extend_from_slice(b"\\n"),
        b'\r' => out.extend_from_slice(b"\\r"),
        b'\t' => out.extend_from_slice(b"\\t"),
        b => {
            out.extend_from_slice(b"\\u00");
            out.push(HEX_LOWER[usize::from(b >> 4)]);
            out.push(HEX_LOWER[usize::from(b & 0x0f)]);
        }
    }
}

/// Write a UTF-8 string escaped as a JSON string literal (including surrounding quotes).
#[inline]
pub fn push_json_str(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    let bytes = s.as_bytes();
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b < 0x20 || b == b'"' || b == b'\\' {
            if i > start {
                out.extend_from_slice(&bytes[start..i]);
            }
            push_escaped_control_or_quote(out, b);
            start = i + 1;
        }
    }
    if start < bytes.len() {
        out.extend_from_slice(&bytes[start..]);
    }
    out.push(b'"');
}

/// Streaming writer for one `mdd.sdk-batch.v1` JSON document.
pub struct BatchJsonWriter {
    buf: Vec<u8>,
}

impl BatchJsonWriter {
    pub fn with_capacity(bytes: usize) -> Self {
        Self {
            buf: Vec::with_capacity(bytes),
        }
    }

    fn begin_batch_inner(
        columns: &[String],
        first_row: u64,
        row_count: Option<usize>,
        estimated_rows: usize,
    ) -> Self {
        let estimated =
            160 + columns.len() * 24 + estimated_rows.saturating_mul(columns.len().max(1) * 32);
        let mut writer = Self::with_capacity(estimated.min(8 * 1024 * 1024));
        writer.buf.extend_from_slice(b"{\"columns\":[");
        for (i, col) in columns.iter().enumerate() {
            if i > 0 {
                writer.buf.push(b',');
            }
            push_json_str(&mut writer.buf, col);
        }
        writer.buf.extend_from_slice(b"],\"first_row\":\"");
        push_u64_dec(&mut writer.buf, first_row);
        if let Some(count) = row_count {
            writer.buf.extend_from_slice(b"\",\"row_count\":");
            push_u64_dec(&mut writer.buf, count as u64);
            writer.buf.extend_from_slice(b",\"rows\":[");
        } else {
            writer.buf.extend_from_slice(b"\",\"rows\":[");
        }
        writer
    }

    pub fn begin_batch(
        schema: &str,
        columns: &[String],
        sequence: u64,
        first_row: u64,
        row_count: usize,
    ) -> Self {
        let _ = (schema, sequence);
        Self::begin_batch_inner(columns, first_row, Some(row_count), row_count)
    }

    /// Begin a batch whose exact `row_count` is not known until [`Self::finish_with_row_count`].
    pub fn begin_batch_deferred(
        schema: &str,
        columns: &[String],
        sequence: u64,
        first_row: u64,
        estimated_rows: usize,
    ) -> Self {
        let _ = (schema, sequence);
        Self::begin_batch_inner(columns, first_row, None, estimated_rows)
    }

    #[inline]
    pub fn begin_row(&mut self, row_idx: usize) {
        if row_idx > 0 {
            self.buf.push(b',');
        }
        self.buf.push(b'[');
    }

    #[inline]
    pub fn end_row(&mut self) {
        self.buf.push(b']');
    }

    #[inline]
    pub fn cell_sep(&mut self, col_idx: usize) {
        if col_idx > 0 {
            self.buf.push(b',');
        }
    }

    #[inline]
    pub fn write_null(&mut self) {
        self.buf.extend_from_slice(b"{\"t\":\"null\"}");
    }

    #[inline]
    pub fn write_bool(&mut self, value: bool) {
        if value {
            self.buf.extend_from_slice(b"{\"t\":\"bool\",\"v\":true}");
        } else {
            self.buf.extend_from_slice(b"{\"t\":\"bool\",\"v\":false}");
        }
    }

    #[inline]
    pub fn write_i64(&mut self, value: i64) {
        self.buf.extend_from_slice(b"{\"t\":\"i64\",\"v\":\"");
        push_i64_dec(&mut self.buf, value);
        self.buf.extend_from_slice(b"\"}");
    }

    #[inline]
    pub fn write_u64(&mut self, value: u64) {
        self.buf.extend_from_slice(b"{\"t\":\"u64\",\"v\":\"");
        push_u64_dec(&mut self.buf, value);
        self.buf.extend_from_slice(b"\"}");
    }

    #[inline]
    pub fn write_f64_bits(&mut self, bits: u64) {
        self.buf.extend_from_slice(b"{\"t\":\"f64\",\"bits\":\"");
        let be = bits.to_be_bytes();
        push_hex_bytes(&mut self.buf, &be);
        self.buf.extend_from_slice(b"\"}");
    }

    #[inline]
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(b"{\"t\":\"bytes\",\"v\":\"");
        push_hex_bytes(&mut self.buf, bytes);
        self.buf.extend_from_slice(b"\"}");
    }

    #[inline]
    pub fn write_dex_mutf8(&mut self, bytes: &[u8], utf16_units: u64) {
        self.buf
            .extend_from_slice(b"{\"t\":\"dex_mutf8\",\"utf16_units\":\"");
        push_u64_dec(&mut self.buf, utf16_units);
        self.buf.extend_from_slice(b"\",\"v\":\"");
        push_hex_bytes(&mut self.buf, bytes);
        self.buf.extend_from_slice(b"\"}");
    }

    #[inline]
    pub fn write_text_utf8(&mut self, s: &str) {
        self.buf.extend_from_slice(b"{\"t\":\"text\",\"v\":");
        push_json_str(&mut self.buf, s);
        self.buf.push(b'}');
    }

    #[inline]
    pub fn write_text_utf16(&mut self, units: &[u16]) {
        // Fast ASCII pass for non-surrogate, non-control DEX descriptors/identifiers.
        if units
            .iter()
            .all(|&u| (0x20..0x7f).contains(&u) && u != b'"' as u16 && u != b'\\' as u16)
        {
            self.buf.reserve(18 + units.len());
            self.buf.extend_from_slice(b"{\"t\":\"text\",\"v\":\"");
            for &u in units {
                self.buf.push(u as u8);
            }
            self.buf.extend_from_slice(b"\"}");
            return;
        }
        let checkpoint = self.buf.len();
        self.buf.extend_from_slice(b"{\"t\":\"text\",\"v\":\"");
        for decoded in std::char::decode_utf16(units.iter().copied()) {
            match decoded {
                Ok(ch) => push_escaped_char(&mut self.buf, ch),
                Err(_) => {
                    self.buf.truncate(checkpoint);
                    self.buf.extend_from_slice(b"{\"t\":\"text\",\"units\":\"");
                    self.buf.reserve(units.len() * 4 + 2);
                    for &u in units {
                        let be = u.to_be_bytes();
                        self.buf.push(HEX_LOWER[usize::from(be[0] >> 4)]);
                        self.buf.push(HEX_LOWER[usize::from(be[0] & 0x0f)]);
                        self.buf.push(HEX_LOWER[usize::from(be[1] >> 4)]);
                        self.buf.push(HEX_LOWER[usize::from(be[1] & 0x0f)]);
                    }
                    self.buf.extend_from_slice(b"\"}");
                    return;
                }
            }
        }
        self.buf.extend_from_slice(b"\"}");
    }

    /// Encode big-endian UTF-16 code-unit bytes directly as a `text` cell without copying to `Vec<u16>`.
    #[inline]
    pub fn write_text_utf16_be_bytes(&mut self, raw_be: &[u8]) {
        debug_assert!(raw_be.len().is_multiple_of(2));
        let pairs = raw_be.as_chunks::<2>().0;
        if pairs
            .iter()
            .all(|&[hi, lo]| hi == 0 && (0x20..0x7f).contains(&lo) && lo != b'"' && lo != b'\\')
        {
            self.buf.reserve(18 + pairs.len());
            self.buf.extend_from_slice(b"{\"t\":\"text\",\"v\":\"");
            for &[_, lo] in pairs {
                self.buf.push(lo);
            }
            self.buf.extend_from_slice(b"\"}");
            return;
        }
        let checkpoint = self.buf.len();
        self.buf.extend_from_slice(b"{\"t\":\"text\",\"v\":\"");
        for decoded in std::char::decode_utf16(pairs.iter().map(|p| u16::from_be_bytes(*p))) {
            match decoded {
                Ok(ch) => push_escaped_char(&mut self.buf, ch),
                Err(_) => {
                    self.buf.truncate(checkpoint);
                    self.buf.extend_from_slice(b"{\"t\":\"text\",\"units\":\"");
                    push_hex_bytes(&mut self.buf, raw_be);
                    self.buf.extend_from_slice(b"\"}");
                    return;
                }
            }
        }
        self.buf.extend_from_slice(b"\"}");
    }

    fn finish_inner(mut self, schema: &str, sequence: u64, row_count: Option<usize>) -> Vec<u8> {
        self.buf.extend_from_slice(b"]");
        if let Some(count) = row_count {
            self.buf.extend_from_slice(b",\"row_count\":");
            push_u64_dec(&mut self.buf, count as u64);
        }
        self.buf.extend_from_slice(b",\"schema\":");
        push_json_str(&mut self.buf, schema);
        self.buf.extend_from_slice(b",\"sequence\":\"");
        push_u64_dec(&mut self.buf, sequence);
        self.buf.extend_from_slice(b"\"}");
        self.buf
    }

    pub fn finish(self, schema: &str, sequence: u64) -> Vec<u8> {
        self.finish_inner(schema, sequence, None)
    }

    /// Finish a batch started with [`Self::begin_batch_deferred`] by writing its actual `row_count`.
    pub fn finish_with_row_count(self, schema: &str, sequence: u64, row_count: usize) -> Vec<u8> {
        self.finish_inner(schema, sequence, Some(row_count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn streaming_json_matches_serde_json_value_for_all_cell_kinds() {
        let cols = vec![
            "c_null".to_owned(),
            "c_text".to_owned(),
            "c_surr".to_owned(),
            "c_u64".to_owned(),
        ];
        let valid_u16: Vec<u16> = "Lcom/example/\"A\\B\n😀;".encode_utf16().collect();
        let surr_u16 = vec![0x61u16, 0xd800u16, 0x0062u16];
        let mut w = BatchJsonWriter::begin_batch("mdd.sdk-batch.v1", &cols, 3, 120, 2);
        w.begin_row(0);
        w.cell_sep(0);
        w.write_null();
        w.cell_sep(1);
        w.write_text_utf16(&valid_u16);
        w.cell_sep(2);
        w.write_text_utf16(&surr_u16);
        w.cell_sep(3);
        w.write_u64(u64::MAX);
        w.end_row();
        w.begin_row(1);
        w.cell_sep(0);
        w.write_bool(true);
        w.cell_sep(1);
        w.write_i64(i64::MIN);
        w.cell_sep(2);
        w.write_f64_bits(f64::NAN.to_bits());
        w.cell_sep(3);
        w.write_dex_mutf8(&[0xc0, 0x80], 1);
        w.end_row();
        let bytes = w.finish("mdd.sdk-batch.v1", 3);
        let actual: Value = serde_json::from_slice(&bytes).expect("valid json");
        let expected = json!({
            "schema": "mdd.sdk-batch.v1",
            "sequence": "3",
            "first_row": "120",
            "row_count": 2,
            "columns": cols,
            "rows": [
                [
                    {"t": "null"},
                    {"t": "text", "v": "Lcom/example/\"A\\B\n😀;"},
                    {"t": "text", "units": "0061d8000062"},
                    {"t": "u64", "v": u64::MAX.to_string()},
                ],
                [
                    {"t": "bool", "v": true},
                    {"t": "i64", "v": i64::MIN.to_string()},
                    {"t": "f64", "bits": format!("{:016x}", f64::NAN.to_bits())},
                    {"t": "dex_mutf8", "v": "c080", "utf16_units": "1"},
                ],
            ]
        });
        assert_eq!(actual, expected);
    }

    #[test]
    fn write_text_utf8_matches_write_text_utf16() {
        let samples = [
            "",
            "Lcom/example/Main;",
            "\"quoted\"\\slash\n\r\t😀",
            "\x01\x1f",
        ];
        let cols = vec!["s".to_owned()];
        for sample in samples {
            let u16s: Vec<u16> = sample.encode_utf16().collect();
            let mut w8 = BatchJsonWriter::begin_batch("mdd.sdk-batch.v1", &cols, 0, 0, 1);
            w8.begin_row(0);
            w8.write_text_utf8(sample);
            w8.end_row();
            let b8 = w8.finish("mdd.sdk-batch.v1", 0);

            let mut w16 = BatchJsonWriter::begin_batch("mdd.sdk-batch.v1", &cols, 0, 0, 1);
            w16.begin_row(0);
            w16.write_text_utf16(&u16s);
            w16.end_row();
            let b16 = w16.finish("mdd.sdk-batch.v1", 0);
            assert_eq!(b8, b16, "mismatch for {sample:?}");
        }
    }

    #[test]
    fn write_text_utf16_be_bytes_matches_write_text_utf16() {
        let utf16_cases: &[Vec<u16>] = &[
            vec![],
            "Lcom/example/Main;".encode_utf16().collect(),
            "\"quoted\"\\slash\n\r\t\u{0001}中文😀"
                .encode_utf16()
                .collect(),
            vec![0x0061, 0xd800, 0x0062],
            vec![0xd83d, 0x0021, 0xdc00],
        ];
        let cols = vec!["s".to_owned()];
        for units in utf16_cases {
            let mut be = Vec::with_capacity(units.len() * 2);
            for u in units {
                be.extend_from_slice(&u.to_be_bytes());
            }
            let mut w_be = BatchJsonWriter::begin_batch("mdd.sdk-batch.v1", &cols, 1, 7, 1);
            w_be.begin_row(0);
            w_be.write_text_utf16_be_bytes(&be);
            w_be.end_row();
            let got = w_be.finish("mdd.sdk-batch.v1", 1);

            let mut w_u16 = BatchJsonWriter::begin_batch("mdd.sdk-batch.v1", &cols, 1, 7, 1);
            w_u16.begin_row(0);
            w_u16.write_text_utf16(units);
            w_u16.end_row();
            let want = w_u16.finish("mdd.sdk-batch.v1", 1);
            assert_eq!(got, want, "mismatch for units={units:04x?}");
        }
    }

    #[test]
    fn deferred_batch_matches_eager_batch_for_full_and_partial_batches() {
        let cols = vec!["c0".to_owned(), "c1".to_owned()];
        for (seq, first_row, actual_rows, estimated_rows) in [(0, 0, 2, 2), (4, 100, 1, 8)] {
            let mut eager = BatchJsonWriter::begin_batch(
                "mdd.sdk-batch.v1",
                &cols,
                seq,
                first_row,
                actual_rows,
            );
            let mut deferred = BatchJsonWriter::begin_batch_deferred(
                "mdd.sdk-batch.v1",
                &cols,
                seq,
                first_row,
                estimated_rows,
            );
            for r in 0..actual_rows {
                for w in [&mut eager, &mut deferred] {
                    w.begin_row(r);
                    w.cell_sep(0);
                    w.write_i64(r as i64);
                    w.cell_sep(1);
                    w.write_text_utf8("Lcom/example/Row;");
                    w.end_row();
                }
            }
            let eager_json: Value =
                serde_json::from_slice(&eager.finish("mdd.sdk-batch.v1", seq)).expect("eager");
            let deferred_json: Value = serde_json::from_slice(&deferred.finish_with_row_count(
                "mdd.sdk-batch.v1",
                seq,
                actual_rows,
            ))
            .expect("deferred");
            assert_eq!(deferred_json, eager_json);
            assert_eq!(deferred_json["row_count"], json!(actual_rows));
        }
    }
}
