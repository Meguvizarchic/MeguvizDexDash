use crate::{invalid, quota};
use mdd_query::ir::Signed64;
use mdd_types::{DecimalU64, MddResult};
use rusqlite::types::{Value as SqliteValue, ValueRef};
use serde::{Deserialize, Serialize};

pub(crate) const TEXT: &[u8] = b"\0MDDTEXT1";
const UNSIGNED: &[u8] = b"\0MDDUINT1";
const FLOAT: &[u8] = b"\0MDDFLOAT1";
pub(crate) const BYTES: &[u8] = b"\0MDDBYTES1";
const MUTF8: &[u8] = b"\0MDDMUTF1";

/// Borrowed preflight for SQLite-to-Rust materialization. It validates fixed
/// carrier shape without allocating; variable text contents are checked by
/// the caller under its query work budget before materialization.
pub(crate) enum RawDecodePlan<'a> {
    Fixed,
    Utf8(&'a [u8]),
    Utf16(usize),
    Bytes(usize),
    Mutf8 { bytes: &'a [u8], units: u64 },
}

pub(crate) fn raw_decode_plan(value: ValueRef<'_>) -> MddResult<RawDecodePlan<'_>> {
    Ok(match value {
        ValueRef::Null | ValueRef::Integer(_) | ValueRef::Real(_) => RawDecodePlan::Fixed,
        ValueRef::Text(bytes) => RawDecodePlan::Utf8(bytes),
        ValueRef::Blob(bytes) => {
            if let Some(raw) = bytes.strip_prefix(TEXT) {
                if !raw.len().is_multiple_of(2) {
                    return Err(invalid("INVALID_TEXT_CARRIER"));
                }
                RawDecodePlan::Utf16(raw.len())
            } else if let Some(raw) = bytes.strip_prefix(UNSIGNED) {
                if raw.len() != 8 {
                    return Err(invalid("INVALID_U64_CARRIER"));
                }
                RawDecodePlan::Fixed
            } else if let Some(raw) = bytes.strip_prefix(FLOAT) {
                if raw.len() != 8 {
                    return Err(invalid("INVALID_F64_CARRIER"));
                }
                RawDecodePlan::Fixed
            } else if let Some(raw) = bytes.strip_prefix(BYTES) {
                RawDecodePlan::Bytes(raw.len())
            } else if let Some(raw) = bytes.strip_prefix(MUTF8) {
                let data = raw
                    .get(8..)
                    .ok_or_else(|| invalid("TRUNCATED_MUTF8_CARRIER"))?;
                let units = u64::from_be_bytes(raw[..8].try_into().unwrap());
                RawDecodePlan::Mutf8 { bytes: data, units }
            } else {
                return Err(invalid("UNTYPED_SQLITE_BLOB"));
            }
        }
    })
}

fn copy_bytes(raw: &[u8]) -> MddResult<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(raw.len())
        .map_err(|_| quota("SQL_INPUT_ALLOCATION"))?;
    bytes.extend_from_slice(raw);
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlType {
    Bool,
    I64,
    U64,
    F64,
    Text,
    Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SqlText {
    pub utf16: Vec<u16>,
    /// Original source bytes only when supplied by the validated provider.
    /// Derived expressions do not invent original-byte provenance.
    pub original_mutf8: Option<Vec<u8>>,
}
impl SqlText {
    pub fn from_utf8(value: &str) -> Self {
        Self {
            utf16: value.encode_utf16().collect(),
            original_mutf8: None,
        }
    }
    pub fn strict_utf8(&self) -> MddResult<String> {
        String::from_utf16(&self.utf16).map_err(|_| invalid("TEXT_HAS_NONSCALAR_UTF16"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SqlValue {
    Null,
    Bool(bool),
    I64(Signed64),
    U64(DecimalU64),
    /// Canonical decimal u64 stores the exact IEEE-754 bit pattern, never JSON NaN.
    F64(DecimalU64),
    Text(SqlText),
    Bytes(Vec<u8>),
    DexMutf8 {
        bytes: Vec<u8>,
        utf16_code_units: DecimalU64,
    },
}
impl SqlValue {
    pub fn text(value: &str) -> Self {
        Self::Text(SqlText::from_utf8(value))
    }
    pub fn data_type(&self) -> Option<SqlType> {
        Some(match self {
            Self::Null => return None,
            Self::Bool(_) => SqlType::Bool,
            Self::I64(_) => SqlType::I64,
            Self::U64(_) => SqlType::U64,
            Self::F64(_) => SqlType::F64,
            Self::Text(_) => SqlType::Text,
            Self::Bytes(_) | Self::DexMutf8 { .. } => SqlType::Bytes,
        })
    }
    pub fn byte_size(&self) -> u64 {
        match self {
            Self::Text(v) => {
                v.utf16.len() as u64 * 2 + v.original_mutf8.as_ref().map_or(0, |b| b.len() as u64)
            }
            Self::Bytes(v) | Self::DexMutf8 { bytes: v, .. } => v.len() as u64,
            _ => 16,
        }
    }
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) | Self::DexMutf8 { bytes, .. } => Some(bytes),
            _ => None,
        }
    }
    pub(crate) fn sqlite(&self, max_cell_bytes: u64) -> MddResult<SqliteValue> {
        if self.byte_size() > max_cell_bytes {
            return Err(quota("SQL_CELL_BYTES"));
        }
        Ok(match self {
            Self::Null => SqliteValue::Null,
            Self::Bool(v) => SqliteValue::Integer(i64::from(*v)),
            Self::I64(v) => SqliteValue::Integer(v.0),
            Self::U64(v) => {
                let mut bytes = UNSIGNED.to_vec();
                bytes.extend(v.0.to_be_bytes());
                SqliteValue::Blob(bytes)
            }
            Self::F64(bits) => {
                let mut bytes = FLOAT.to_vec();
                bytes.extend(bits.0.to_be_bytes());
                SqliteValue::Blob(bytes)
            }
            Self::Text(v) => {
                let length = v
                    .utf16
                    .len()
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(TEXT.len()))
                    .ok_or_else(|| quota("TEXT_BYTES_OVERFLOW"))?;
                let mut bytes = Vec::with_capacity(length);
                bytes.extend(TEXT);
                for unit in &v.utf16 {
                    bytes.extend(unit.to_be_bytes());
                }
                SqliteValue::Blob(bytes)
            }
            Self::Bytes(v) => {
                let mut bytes = Vec::with_capacity(BYTES.len() + v.len());
                bytes.extend(BYTES);
                bytes.extend(v);
                SqliteValue::Blob(bytes)
            }
            Self::DexMutf8 {
                bytes: raw,
                utf16_code_units,
            } => {
                validate_mutf8(raw, utf16_code_units.0)?;
                let mut bytes = Vec::with_capacity(MUTF8.len() + 8 + raw.len());
                bytes.extend(MUTF8);
                bytes.extend(utf16_code_units.0.to_be_bytes());
                bytes.extend(raw);
                SqliteValue::Blob(bytes)
            }
        })
    }
    pub(crate) fn from_sqlite(value: ValueRef<'_>) -> MddResult<Self> {
        Ok(match value {
            ValueRef::Null => Self::Null,
            ValueRef::Integer(v) => Self::I64(Signed64(v)),
            ValueRef::Real(v) => Self::F64(DecimalU64(v.to_bits())),
            ValueRef::Text(v) => {
                let text =
                    std::str::from_utf8(v).map_err(|_| invalid("INVALID_UTF8_FROM_SQLITE"))?;
                let mut utf16 = Vec::new();
                utf16
                    .try_reserve_exact(text.encode_utf16().count())
                    .map_err(|_| quota("SQL_INPUT_ALLOCATION"))?;
                utf16.extend(text.encode_utf16());
                Self::Text(SqlText {
                    utf16,
                    original_mutf8: None,
                })
            }
            ValueRef::Blob(bytes) => {
                if let Some(raw) = bytes.strip_prefix(TEXT) {
                    if !raw.len().is_multiple_of(2) {
                        return Err(invalid("INVALID_TEXT_CARRIER"));
                    }
                    let mut utf16 = Vec::new();
                    utf16
                        .try_reserve_exact(raw.len() / 2)
                        .map_err(|_| quota("SQL_INPUT_ALLOCATION"))?;
                    utf16.extend(
                        raw.as_chunks::<2>()
                            .0
                            .iter()
                            .map(|v| u16::from_be_bytes(*v)),
                    );
                    Self::Text(SqlText {
                        utf16,
                        original_mutf8: None,
                    })
                } else if let Some(raw) = bytes.strip_prefix(UNSIGNED) {
                    Self::U64(DecimalU64(u64::from_be_bytes(
                        raw.try_into().map_err(|_| invalid("INVALID_U64_CARRIER"))?,
                    )))
                } else if let Some(raw) = bytes.strip_prefix(FLOAT) {
                    Self::F64(DecimalU64(u64::from_be_bytes(
                        raw.try_into().map_err(|_| invalid("INVALID_F64_CARRIER"))?,
                    )))
                } else if let Some(raw) = bytes.strip_prefix(BYTES) {
                    Self::Bytes(copy_bytes(raw)?)
                } else if let Some(raw) = bytes.strip_prefix(MUTF8) {
                    let count = u64::from_be_bytes(
                        raw.get(..8)
                            .ok_or_else(|| invalid("TRUNCATED_MUTF8_CARRIER"))?
                            .try_into()
                            .unwrap(),
                    );
                    let data = &raw[8..];
                    validate_mutf8(data, count)?;
                    Self::DexMutf8 {
                        bytes: copy_bytes(data)?,
                        utf16_code_units: DecimalU64(count),
                    }
                } else {
                    return Err(invalid("UNTYPED_SQLITE_BLOB"));
                }
            }
        })
    }
}
pub(crate) fn validate_mutf8(bytes: &[u8], expected: u64) -> MddResult<()> {
    let mut at = 0;
    let mut count = 0u64;
    while at < bytes.len() {
        let first = bytes[at];
        let (n, mut value, min) = match first {
            1..=0x7f => (1, u32::from(first), 0),
            0xc0..=0xdf => (2, u32::from(first & 31), 0x80),
            0xe0..=0xef => (3, u32::from(first & 15), 0x800),
            _ => return Err(invalid("INVALID_DEX_MUTF8_CARRIER")),
        };
        if at + n > bytes.len() {
            return Err(invalid("TRUNCATED_DEX_MUTF8_CARRIER"));
        }
        for byte in &bytes[at + 1..at + n] {
            if byte & 0xc0 != 0x80 {
                return Err(invalid("INVALID_DEX_MUTF8_CONTINUATION"));
            }
            value = (value << 6) | u32::from(byte & 63);
        }
        if value < min && !(n == 2 && value == 0 && first == 0xc0) {
            return Err(invalid("OVERLONG_DEX_MUTF8_CARRIER"));
        }
        count += 1;
        at += n;
    }
    if count != expected {
        return Err(invalid("DEX_MUTF8_UNIT_COUNT_MISMATCH"));
    }
    Ok(())
}
