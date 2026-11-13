//! Typed cells and their strict JSON form.
//!
//! Nothing is converted through a JSON number: 64-bit integers are canonical
//! decimal strings, floats are their raw IEEE-754 bit pattern (so NaN payloads,
//! infinities and `-0.0` survive), bytes are lower-case hex, and a DEX string
//! keeps its MUTF-8 bytes next to the UTF-16 unit count. NULL is its own tag, so
//! it is never an empty string or a zero.
use crate::error::{WireError, WireErrorKind, WireResult, malformed};
use serde_json::{Map, Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ColumnType {
    Bool,
    I64,
    U64,
    F64,
    Utf8,
    Bytes,
    DexMutf8,
}

impl ColumnType {
    pub fn name(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::I64 => "i64",
            Self::U64 => "u64",
            Self::F64 => "f64",
            Self::Utf8 => "utf8",
            Self::Bytes => "bytes",
            Self::DexMutf8 => "dex_mutf8",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "bool" => Self::Bool,
            "i64" => Self::I64,
            "u64" => Self::U64,
            "f64" => Self::F64,
            "utf8" => Self::Utf8,
            "bytes" => Self::Bytes,
            "dex_mutf8" => Self::DexMutf8,
            _ => return None,
        })
    }

    /// One byte per type in the integrity digest. NULL uses 0.
    pub(crate) fn tag(self) -> u8 {
        match self {
            Self::Bool => 1,
            Self::I64 => 2,
            Self::U64 => 3,
            Self::F64 => 4,
            Self::Utf8 => 5,
            Self::Bytes => 6,
            Self::DexMutf8 => 7,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Cell {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    /// The exact IEEE-754 binary64 bit pattern.
    F64Bits(u64),
    Utf8(String),
    Bytes(Vec<u8>),
    DexMutf8 {
        bytes: Vec<u8>,
        utf16_units: u64,
    },
}

impl Cell {
    pub fn f64(value: f64) -> Self {
        Self::F64Bits(value.to_bits())
    }

    /// The column type this value belongs to; `None` for NULL.
    pub fn column_type(&self) -> Option<ColumnType> {
        Some(match self {
            Self::Null => return None,
            Self::Bool(_) => ColumnType::Bool,
            Self::I64(_) => ColumnType::I64,
            Self::U64(_) => ColumnType::U64,
            Self::F64Bits(_) => ColumnType::F64,
            Self::Utf8(_) => ColumnType::Utf8,
            Self::Bytes(_) => ColumnType::Bytes,
            Self::DexMutf8 { .. } => ColumnType::DexMutf8,
        })
    }

    /// Bytes of variable-length payload, for the per-cell hard limit.
    pub fn payload_bytes(&self) -> usize {
        match self {
            Self::Utf8(text) => text.len(),
            Self::Bytes(bytes) | Self::DexMutf8 { bytes, .. } => bytes.len(),
            // Fixed-width values carry no variable payload to limit.
            _ => 0,
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            Self::Null => json!({"t": "null"}),
            Self::Bool(value) => json!({"t": "bool", "v": value}),
            Self::I64(value) => json!({"t": "i64", "v": value.to_string()}),
            Self::U64(value) => json!({"t": "u64", "v": value.to_string()}),
            Self::F64Bits(bits) => json!({"t": "f64", "bits": format!("{bits:016x}")}),
            Self::Utf8(text) => json!({"t": "utf8", "v": text}),
            Self::Bytes(bytes) => json!({"t": "bytes", "v": hex(bytes)}),
            Self::DexMutf8 { bytes, utf16_units } => {
                json!({"t": "dex_mutf8", "v": hex(bytes), "utf16_units": utf16_units.to_string()})
            }
        }
    }

    pub fn from_json(value: &Value) -> WireResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| malformed("a cell must be a JSON object"))?;
        let tag = object
            .get("t")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("a cell needs a type tag"))?;
        let only = |allowed: &[&str]| -> WireResult<()> {
            match object.keys().find(|key| !allowed.contains(&key.as_str())) {
                Some(extra) => Err(malformed(format!(
                    "cell field `{extra}` is not part of `{tag}`"
                ))),
                None => Ok(()),
            }
        };
        let text = |key: &str| -> WireResult<&str> {
            object
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| malformed(format!("`{tag}` cell needs a string `{key}`")))
        };
        Ok(match tag {
            "null" => {
                only(&["t"])?;
                Self::Null
            }
            "bool" => {
                only(&["t", "v"])?;
                Self::Bool(
                    object
                        .get("v")
                        .and_then(Value::as_bool)
                        .ok_or_else(|| malformed("`bool` cell needs a boolean `v`"))?,
                )
            }
            "i64" => {
                only(&["t", "v"])?;
                Self::I64(canonical_decimal::<i64>(text("v")?)?)
            }
            "u64" => {
                only(&["t", "v"])?;
                Self::U64(canonical_decimal::<u64>(text("v")?)?)
            }
            "f64" => {
                only(&["t", "bits"])?;
                let bits = text("bits")?;
                if bits.len() != 16
                    || !bits
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(malformed("`f64` bits must be 16 lower-case hex digits"));
                }
                Self::F64Bits(
                    u64::from_str_radix(bits, 16)
                        .map_err(|_| malformed("`f64` bits are not hex"))?,
                )
            }
            "utf8" => {
                only(&["t", "v"])?;
                Self::Utf8(text("v")?.to_owned())
            }
            "bytes" => {
                only(&["t", "v"])?;
                Self::Bytes(unhex(text("v")?)?)
            }
            "dex_mutf8" => {
                only(&["t", "v", "utf16_units"])?;
                Self::DexMutf8 {
                    bytes: unhex(text("v")?)?,
                    utf16_units: canonical_decimal::<u64>(text("utf16_units")?)?,
                }
            }
            other => return Err(malformed(format!("cell type `{other}` is not defined"))),
        })
    }

    /// Canonical bytes covered by the integrity digest: type tag, then the value.
    /// A NULL, an empty string and a zero are three different byte strings.
    pub(crate) fn digest_bytes(&self, out: &mut Vec<u8>) {
        let length_prefixed = |out: &mut Vec<u8>, bytes: &[u8]| {
            out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            out.extend_from_slice(bytes);
        };
        match self {
            Self::Null => out.push(0),
            Self::Bool(value) => {
                out.push(ColumnType::Bool.tag());
                out.push(u8::from(*value));
            }
            Self::I64(value) => {
                out.push(ColumnType::I64.tag());
                out.extend_from_slice(&value.to_le_bytes());
            }
            Self::U64(value) => {
                out.push(ColumnType::U64.tag());
                out.extend_from_slice(&value.to_le_bytes());
            }
            Self::F64Bits(bits) => {
                out.push(ColumnType::F64.tag());
                out.extend_from_slice(&bits.to_le_bytes());
            }
            Self::Utf8(text) => {
                out.push(ColumnType::Utf8.tag());
                length_prefixed(out, text.as_bytes());
            }
            Self::Bytes(bytes) => {
                out.push(ColumnType::Bytes.tag());
                length_prefixed(out, bytes);
            }
            Self::DexMutf8 { bytes, utf16_units } => {
                out.push(ColumnType::DexMutf8.tag());
                length_prefixed(out, bytes);
                out.extend_from_slice(&utf16_units.to_le_bytes());
            }
        }
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> WireResult<Vec<u8>> {
    if !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(malformed("bytes must be even-length lower-case hex"));
    }
    (0..text.len())
        .step_by(2)
        .map(|at| {
            u8::from_str_radix(&text[at..at + 2], 16).map_err(|_| malformed("bytes are not hex"))
        })
        .collect()
}

/// A decimal string that is exactly what `to_string` would print: no `+`, no
/// leading zeros, no `-0`, no whitespace.
pub(crate) fn canonical_decimal<T: std::str::FromStr + ToString>(text: &str) -> WireResult<T> {
    let value: T = text
        .parse()
        .map_err(|_| malformed(format!("`{text}` is not a decimal integer in range")))?;
    if value.to_string() != text {
        return Err(malformed(format!(
            "`{text}` is not a canonical decimal integer"
        )));
    }
    Ok(value)
}

pub(crate) fn decimal_field(object: &Map<String, Value>, key: &str) -> WireResult<u64> {
    let text = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| malformed(format!("`{key}` must be a decimal string")))?;
    canonical_decimal::<u64>(text)
}

pub(crate) fn cell_type_error(column: &str, expected: ColumnType, got: &Cell) -> WireError {
    WireError::new(
        WireErrorKind::CellTypeMismatch,
        format!(
            "column `{column}` is {} but the cell is {}",
            expected.name(),
            got.column_type().map_or("null", ColumnType::name)
        ),
    )
}
