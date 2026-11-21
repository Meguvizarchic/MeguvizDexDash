//! Batch encoding: self-describing typed cells in JSON.
//!
//! Nothing is converted through a JSON number. 64-bit integers are decimal strings,
//! floats are their IEEE-754 bit pattern, bytes are lower-case hex, NULL is its own
//! tag, and a DEX string keeps its MUTF-8 bytes next to the UTF-16 unit count. These
//! are the `mdd-wire` cell forms. Text is the one addition: query text is a sequence
//! of UTF-16 code units that may hold unpaired surrogates, which a JSON string cannot
//! carry, so text is `{"t":"text","v":...}` when the units form valid UTF-16 and
//! `{"t":"text","units":"<4 hex digits per unit>"}` otherwise. Both forms are
//! lossless; a consumer that wants the exact units decodes `units` when it is present.
use mdd_sql::{column_store::BorrowedSqlCell, values::SqlValue};
use mdd_wire::Cell;
use mdd_wire::optimized::{BatchJsonWriter, wire_direct_json_enabled};
use serde_json::{Value, json};

pub const BATCH_SCHEMA: &str = "mdd.sdk-batch.v1";

pub fn cell_json(value: &SqlValue) -> Value {
    match value {
        SqlValue::Null => Cell::Null.to_json(),
        SqlValue::Bool(v) => Cell::Bool(*v).to_json(),
        SqlValue::I64(v) => Cell::I64(v.0).to_json(),
        SqlValue::U64(v) => Cell::U64(v.0).to_json(),
        SqlValue::F64(bits) => Cell::F64Bits(bits.0).to_json(),
        SqlValue::Bytes(bytes) => Cell::Bytes(bytes.clone()).to_json(),
        SqlValue::DexMutf8 {
            bytes,
            utf16_code_units,
        } => Cell::DexMutf8 {
            bytes: bytes.clone(),
            utf16_units: utf16_code_units.0,
        }
        .to_json(),
        SqlValue::Text(text) => match String::from_utf16(&text.utf16) {
            Ok(valid) => json!({"t": "text", "v": valid}),
            Err(_) => {
                let units: String = text
                    .utf16
                    .iter()
                    .map(|unit| format!("{unit:04x}"))
                    .collect();
                json!({"t": "text", "units": units})
            }
        },
    }
}

/// True when `MDD_OPT_WIRE_DIRECT_JSON` allows direct JSON encoding (`"0"` disables).
pub fn wire_direct_json_active() -> bool {
    wire_direct_json_enabled()
}

/// One batch: `rows` are `[first_row, first_row + rows.len())` of the result.
pub fn batch_bytes(
    columns: &[String],
    rows: &[Vec<SqlValue>],
    sequence: u64,
    first_row: u64,
) -> Vec<u8> {
    if wire_direct_json_enabled() {
        return batch_bytes_direct(columns, rows, sequence, first_row);
    }
    batch_bytes_reference(columns, rows, sequence, first_row)
}

fn batch_bytes_direct(
    columns: &[String],
    rows: &[Vec<SqlValue>],
    sequence: u64,
    first_row: u64,
) -> Vec<u8> {
    let mut writer =
        BatchJsonWriter::begin_batch(BATCH_SCHEMA, columns, sequence, first_row, rows.len());
    for (r_idx, row) in rows.iter().enumerate() {
        writer.begin_row(r_idx);
        for (c_idx, val) in row.iter().enumerate() {
            writer.cell_sep(c_idx);
            match val {
                SqlValue::Null => writer.write_null(),
                SqlValue::Bool(v) => writer.write_bool(*v),
                SqlValue::I64(v) => writer.write_i64(v.0),
                SqlValue::U64(v) => writer.write_u64(v.0),
                SqlValue::F64(bits) => writer.write_f64_bits(bits.0),
                SqlValue::Bytes(bytes) => writer.write_bytes(bytes),
                SqlValue::DexMutf8 {
                    bytes,
                    utf16_code_units,
                } => writer.write_dex_mutf8(bytes, utf16_code_units.0),
                SqlValue::Text(text) => writer.write_text_utf16(&text.utf16),
            }
        }
        writer.end_row();
    }
    writer.finish(BATCH_SCHEMA, sequence)
}

/// Streaming `mdd.sdk-batch.v1` JSON batch encoder accepting zero-copy `BorrowedSqlCell` values.
pub struct BatchStreamEncoder {
    writer: BatchJsonWriter,
    row_in_batch: usize,
    sequence: u64,
    deferred: bool,
}

impl BatchStreamEncoder {
    pub fn begin(columns: &[String], sequence: u64, first_row: u64, row_count: usize) -> Self {
        Self {
            writer: BatchJsonWriter::begin_batch(
                BATCH_SCHEMA,
                columns,
                sequence,
                first_row,
                row_count,
            ),
            row_in_batch: 0,
            sequence,
            deferred: false,
        }
    }

    /// Begin a streaming batch whose final `row_count` is emitted on [`Self::finish`].
    pub fn begin_deferred(
        columns: &[String],
        sequence: u64,
        first_row: u64,
        estimated_rows: usize,
    ) -> Self {
        Self {
            writer: BatchJsonWriter::begin_batch_deferred(
                BATCH_SCHEMA,
                columns,
                sequence,
                first_row,
                estimated_rows,
            ),
            row_in_batch: 0,
            sequence,
            deferred: true,
        }
    }

    #[inline]
    pub fn begin_row(&mut self) {
        self.writer.begin_row(self.row_in_batch);
        self.row_in_batch += 1;
    }

    #[inline]
    pub fn push_borrowed_cell(&mut self, col_idx: usize, cell: &BorrowedSqlCell<'_>) {
        self.writer.cell_sep(col_idx);
        match cell {
            BorrowedSqlCell::Null => self.writer.write_null(),
            BorrowedSqlCell::Bool(v) => self.writer.write_bool(*v),
            BorrowedSqlCell::I64(v) => self.writer.write_i64(*v),
            BorrowedSqlCell::U64(v) => self.writer.write_u64(*v),
            BorrowedSqlCell::F64Bits(bits) => self.writer.write_f64_bits(*bits),
            BorrowedSqlCell::Utf8(s) => self.writer.write_text_utf8(s),
            BorrowedSqlCell::Utf16Be(raw) => self.writer.write_text_utf16_be_bytes(raw),
            BorrowedSqlCell::Bytes(raw) => self.writer.write_bytes(raw),
            BorrowedSqlCell::DexMutf8 { bytes, utf16_units } => {
                self.writer.write_dex_mutf8(bytes, *utf16_units)
            }
            BorrowedSqlCell::Owned(val) => match val {
                SqlValue::Null => self.writer.write_null(),
                SqlValue::Bool(v) => self.writer.write_bool(*v),
                SqlValue::I64(v) => self.writer.write_i64(v.0),
                SqlValue::U64(v) => self.writer.write_u64(v.0),
                SqlValue::F64(bits) => self.writer.write_f64_bits(bits.0),
                SqlValue::Bytes(bytes) => self.writer.write_bytes(bytes),
                SqlValue::DexMutf8 {
                    bytes,
                    utf16_code_units,
                } => self.writer.write_dex_mutf8(bytes, utf16_code_units.0),
                SqlValue::Text(text) => self.writer.write_text_utf16(&text.utf16),
            },
        }
    }

    #[inline]
    pub fn end_row(&mut self) {
        self.writer.end_row();
    }

    pub fn rows_in_batch(&self) -> usize {
        self.row_in_batch
    }

    pub fn finish(self) -> Vec<u8> {
        if self.deferred {
            self.writer
                .finish_with_row_count(BATCH_SCHEMA, self.sequence, self.row_in_batch)
        } else {
            self.writer.finish(BATCH_SCHEMA, self.sequence)
        }
    }
}

fn batch_bytes_reference(
    columns: &[String],
    rows: &[Vec<SqlValue>],
    sequence: u64,
    first_row: u64,
) -> Vec<u8> {
    let cells: Vec<Vec<Value>> = rows
        .iter()
        .map(|row| row.iter().map(cell_json).collect())
        .collect();
    json!({
        "schema": BATCH_SCHEMA,
        "sequence": sequence.to_string(),
        "first_row": first_row.to_string(),
        "row_count": rows.len(),
        "columns": columns,
        "rows": cells,
    })
    .to_string()
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdd_query::ir::Signed64;
    use mdd_sql::values::SqlText;
    use mdd_types::DecimalU64;

    #[test]
    fn direct_batch_bytes_equals_reference_json_across_all_value_shapes() {
        let columns = vec![
            "c0".to_owned(),
            "c1".to_owned(),
            "c2".to_owned(),
            "c3".to_owned(),
        ];
        let rows = vec![
            vec![
                SqlValue::Null,
                SqlValue::Bool(false),
                SqlValue::I64(Signed64(i64::MIN)),
                SqlValue::U64(DecimalU64(u64::MAX)),
            ],
            vec![
                SqlValue::F64(DecimalU64((-0.0f64).to_bits())),
                SqlValue::Bytes(vec![0x00, 0xab, 0xff]),
                SqlValue::DexMutf8 {
                    bytes: vec![0x61, 0xc0, 0x80, 0x62],
                    utf16_code_units: DecimalU64(3),
                },
                SqlValue::text("Lcom/example/\"Test\"\\\n😀;"),
            ],
            vec![
                SqlValue::Text(SqlText {
                    utf16: vec![0x61, 0xd800, 0x62],
                    original_mutf8: None,
                }),
                SqlValue::Text(SqlText {
                    utf16: vec![],
                    original_mutf8: None,
                }),
                SqlValue::Bool(true),
                SqlValue::I64(Signed64(42)),
            ],
        ];
        let direct: Value =
            serde_json::from_slice(&batch_bytes_direct(&columns, &rows, 9, 100)).unwrap();
        let reference: Value =
            serde_json::from_slice(&batch_bytes_reference(&columns, &rows, 9, 100)).unwrap();
        assert_eq!(direct, reference);
    }
}
