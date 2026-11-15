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
use mdd_sql::values::SqlValue;
use mdd_wire::Cell;
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

/// One batch: `rows` are `[first_row, first_row + rows.len())` of the result.
pub fn batch_bytes(
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
