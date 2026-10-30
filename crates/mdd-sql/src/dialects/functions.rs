use crate::{
    control::SqlControl,
    dialects::SqlDialect,
    invalid, quota,
    values::{BYTES, SqlText, SqlValue},
};
use mdd_query::{budget::Reservation, ir::Signed64};
use mdd_types::{DecimalU64, MddError, MddResult};
use rusqlite::{
    Connection,
    functions::{Aggregate, Context, FunctionFlags},
    types::{ToSql, ToSqlOutput, Value as Cell},
};
use std::{borrow::Cow, cmp::Ordering};

fn integer(value: &SqlValue) -> MddResult<i128> {
    match value {
        SqlValue::I64(v) => Ok(i128::from(v.0)),
        SqlValue::U64(v) => Ok(i128::from(v.0)),
        SqlValue::Bool(v) => Ok(i128::from(*v)),
        _ => Err(invalid("INTEGER_VALUE_REQUIRED")),
    }
}
fn integer_value(value: i128, unsigned: bool) -> MddResult<SqlValue> {
    if unsigned && value >= 0 {
        return u64::try_from(value)
            .map(|v| SqlValue::U64(DecimalU64(v)))
            .map_err(|_| invalid("INTEGER_OVERFLOW"));
    }
    if let Ok(value) = i64::try_from(value) {
        Ok(SqlValue::I64(Signed64(value)))
    } else if let Ok(value) = u64::try_from(value) {
        Ok(SqlValue::U64(DecimalU64(value)))
    } else {
        Err(invalid("INTEGER_OVERFLOW"))
    }
}
fn scalar_text(value: &SqlValue, control: &SqlControl) -> MddResult<SqlText> {
    Ok(match value {
        SqlValue::Text(value) => value.clone(),
        SqlValue::I64(v) => SqlText::from_utf8(&v.0.to_string()),
        SqlValue::U64(v) => SqlText::from_utf8(&v.0.to_string()),
        SqlValue::Bool(v) => SqlText::from_utf8(if *v { "1" } else { "0" }),
        SqlValue::F64(bits) => SqlText::from_utf8(&f64::from_bits(bits.0).to_string()),
        SqlValue::DexMutf8 { bytes, .. } => decoded_text(bytes, SqlDialect::DexSql010, control)?,
        _ => return Err(invalid("TEXT_CONVERSION_TYPE")),
    })
}
fn scalar_text_cow<'a>(value: &'a SqlValue, control: &SqlControl) -> MddResult<Cow<'a, SqlText>> {
    match value {
        SqlValue::Text(text) => Ok(Cow::Borrowed(text)),
        value => Ok(Cow::Owned(scalar_text(value, control)?)),
    }
}
fn encoded_text(text: &SqlText, dialect: SqlDialect, control: &SqlControl) -> MddResult<Vec<u8>> {
    fn emit(code: u32, out: &mut Vec<u8>) {
        if code < 0x80 {
            out.push(code as u8);
        } else if code < 0x800 {
            out.extend([(0xc0 | (code >> 6)) as u8, (0x80 | (code & 63)) as u8]);
        } else if code < 0x10000 {
            out.extend([
                (0xe0 | (code >> 12)) as u8,
                (0x80 | ((code >> 6) & 63)) as u8,
                (0x80 | (code & 63)) as u8,
            ]);
        } else {
            out.extend([
                (0xf0 | (code >> 18)) as u8,
                (0x80 | ((code >> 12) & 63)) as u8,
                (0x80 | ((code >> 6) & 63)) as u8,
                (0x80 | (code & 63)) as u8,
            ]);
        }
    }
    let mut out = Vec::new();
    let mut at = 0;
    while at < text.utf16.len() {
        control.checkpoint(1, false)?;
        let value = text.utf16[at];
        if dialect != SqlDialect::NativeV1 && value == 0 {
            out.extend([0xc0, 0x80]);
        } else if dialect == SqlDialect::NativeV1
            && (0xd800..=0xdbff).contains(&value)
            && text
                .utf16
                .get(at + 1)
                .is_some_and(|v| (0xdc00..=0xdfff).contains(v))
        {
            control.checkpoint(1, false)?;
            let low = text.utf16[at + 1];
            emit(
                0x10000 + ((u32::from(value) - 0xd800) << 10) + (u32::from(low) - 0xdc00),
                &mut out,
            );
            at += 1;
        } else {
            emit(u32::from(value), &mut out);
        }
        at += 1;
    }
    Ok(out)
}
fn decoded_text(bytes: &[u8], dialect: SqlDialect, control: &SqlControl) -> MddResult<SqlText> {
    control.checkpoint(1, false)?;
    let mut units = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        control.checkpoint(1, false)?;
        let first = bytes[at];
        let (count, mut value, min) = match first {
            0..=0x7f => (1, u32::from(first), 0),
            0xc0..=0xdf => (2, u32::from(first & 31), 0x80),
            0xe0..=0xef => (3, u32::from(first & 15), 0x800),
            0xf0..=0xf4 => (4, u32::from(first & 7), 0x10000),
            _ => return Err(invalid("CAST_TEXT_BAD_ENCODING")),
        };
        if at + count > bytes.len() {
            return Err(invalid("CAST_TEXT_TRUNCATED_ENCODING"));
        }
        for byte in &bytes[at + 1..at + count] {
            if byte & 0xc0 != 0x80 {
                return Err(invalid("CAST_TEXT_BAD_CONTINUATION"));
            }
            value = (value << 6) | u32::from(byte & 63);
        }
        if value < min
            && !(dialect != SqlDialect::NativeV1 && count == 2 && value == 0 && first == 0xc0)
        {
            return Err(invalid("CAST_TEXT_OVERLONG_ENCODING"));
        }
        if value > 0x10ffff {
            return Err(invalid("CAST_TEXT_CODEPOINT_RANGE"));
        }
        if value >= 0x10000 {
            let value = value - 0x10000;
            units.extend([
                0xd800 | (value >> 10) as u16,
                0xdc00 | (value & 1023) as u16,
            ]);
        } else {
            units.push(value as u16);
        }
        at += count;
    }
    Ok(SqlText {
        utf16: units,
        original_mutf8: None,
    })
}
fn int_float_cmp(integer: i128, float: f64) -> Ordering {
    if float.is_nan() {
        return Ordering::Less;
    }
    if float == f64::INFINITY {
        return Ordering::Less;
    }
    if float == f64::NEG_INFINITY {
        return Ordering::Greater;
    }
    if integer < 0 && float >= 0.0 {
        return Ordering::Less;
    }
    if integer >= 0 && float < 0.0 {
        return Ordering::Greater;
    }
    let negative = integer < 0;
    let magnitude = integer.unsigned_abs();
    let value = float.abs();
    let order = if value >= 18446744073709551616.0 {
        Ordering::Less
    } else {
        let floor = value as u64;
        match magnitude.cmp(&u128::from(floor)) {
            Ordering::Equal if value.fract() != 0.0 => Ordering::Less,
            order => order,
        }
    };
    if negative { order.reverse() } else { order }
}
fn compare_units<T: Ord>(left: &[T], right: &[T], control: &SqlControl) -> MddResult<Ordering> {
    for (a, b) in left.iter().zip(right) {
        control.checkpoint(1, false)?;
        let order = a.cmp(b);
        if order != Ordering::Equal {
            return Ok(order);
        }
    }
    control.checkpoint(1, false)?;
    Ok(left.len().cmp(&right.len()))
}
fn compare(left: &SqlValue, right: &SqlValue, control: &SqlControl) -> MddResult<Ordering> {
    if storage_class(left) != storage_class(right) {
        return Err(MddError::new(
            mdd_types::ErrorCode::UnsupportedQuery,
            "sql.affinity",
            "MIXED_CLASS_AFFINITY_NOT_IMPLEMENTED",
        ));
    }
    if let (Some(left), Some(right)) = (left.bytes(), right.bytes()) {
        return compare_units(left, right, control);
    }
    Ok(match (left, right) {
        (SqlValue::Text(a), SqlValue::Text(b)) => {
            return compare_units(&a.utf16, &b.utf16, control);
        }
        (SqlValue::Bytes(a), SqlValue::Bytes(b)) => return compare_units(a, b, control),
        (SqlValue::F64(a), SqlValue::F64(b)) => {
            let (x, y) = (f64::from_bits(a.0), f64::from_bits(b.0));
            if x.is_nan() && y.is_nan() {
                a.0.cmp(&b.0)
            } else if x.is_nan() {
                Ordering::Greater
            } else if y.is_nan() {
                Ordering::Less
            } else {
                x.partial_cmp(&y).unwrap()
            }
        }
        (SqlValue::F64(a), b) => int_float_cmp(integer(b)?, f64::from_bits(a.0)).reverse(),
        (a, SqlValue::F64(b)) => int_float_cmp(integer(a)?, f64::from_bits(b.0)),
        (a, b) => integer(a)?.cmp(&integer(b)?),
    })
}
fn storage_class(value: &SqlValue) -> u8 {
    match value {
        SqlValue::Null => 0,
        SqlValue::Bool(_) | SqlValue::I64(_) | SqlValue::U64(_) | SqlValue::F64(_) => 1,
        SqlValue::Text(_) => 2,
        SqlValue::Bytes(_) | SqlValue::DexMutf8 { .. } => 3,
    }
}
fn compare_literal(left: &SqlValue, right: &SqlValue, control: &SqlControl) -> MddResult<Ordering> {
    let order = storage_class(left).cmp(&storage_class(right));
    if order == Ordering::Equal {
        compare(left, right, control)
    } else {
        Ok(order)
    }
}

// The AST selects this only for a TEXT-cast string literal and an i64 literal.
// Decimal formatting is bounded to 20 bytes; compare UTF-16 units without a
// full-size conversion and retain query step/cancellation checks.
fn compare_text_integer_literal(
    left: &SqlValue,
    right: &SqlValue,
    control: &SqlControl,
) -> MddResult<Ordering> {
    let (text, number, reverse) = match (left, right) {
        (SqlValue::Text(text), SqlValue::I64(number)) => (text, number, false),
        (SqlValue::I64(number), SqlValue::Text(text)) => (text, number, true),
        _ => return Err(invalid("TEXT_INTEGER_LITERAL_BINDING")),
    };
    let decimal = number.0.to_string();
    let mut units = text.utf16.iter().copied();
    let mut digits = decimal.bytes().map(u16::from);
    let order = loop {
        control.checkpoint(1, false)?;
        match (units.next(), digits.next()) {
            (Some(a), Some(b)) if a == b => (),
            (Some(a), Some(b)) => break a.cmp(&b),
            (Some(_), None) => break Ordering::Greater,
            (None, Some(_)) => break Ordering::Less,
            (None, None) => break Ordering::Equal,
        }
    };
    Ok(if reverse { order.reverse() } else { order })
}

const KEY_HEADER: &[u8] = b"\0MDDKEY1";

fn key_capacity(value: &SqlValue) -> MddResult<usize> {
    let content = match value {
        SqlValue::Text(text) => text
            .utf16
            .len()
            .checked_mul(2)
            .and_then(|n| n.checked_add(1)),
        SqlValue::Bytes(bytes) | SqlValue::DexMutf8 { bytes, .. } => bytes.len().checked_add(1),
        // Numeric keys have a tag, discriminator and at most 10 payload bytes.
        _ => Some(12),
    }
    .ok_or_else(|| quota("SQL_KEY_CAPACITY_OVERFLOW"))?;
    KEY_HEADER
        .len()
        .checked_add(content)
        .ok_or_else(|| quota("SQL_KEY_CAPACITY_OVERFLOW"))
}

fn key_workspace_amount(capacity: u64) -> MddResult<u64> {
    capacity
        .checked_mul(2)
        .and_then(|n| n.checked_add(BYTES.len() as u64))
        .ok_or_else(|| quota("SQL_KEY_WORKSPACE_OVERFLOW"))
}

fn reserve_key_workspace(value: &SqlValue, control: &SqlControl) -> MddResult<Option<Reservation>> {
    if value == &SqlValue::Null {
        return Ok(None);
    }
    let capacity =
        u64::try_from(key_capacity(value)?).map_err(|_| quota("SQL_KEY_WORKSPACE_OVERFLOW"))?;
    // Both the key Vec and the BYTES-tagged rusqlite carrier coexist while
    // preparing the callback result. SQLite's own TRANSIENT copy and sorter
    // memory are separate and are not covered by this logical reservation.
    let amount = key_workspace_amount(capacity)?;
    control
        .runtime()
        .map(|runtime| {
            runtime.checkpoint()?;
            runtime
                .pool()
                .reserve(mdd_query::budget::Resource::QueryWorkspaceBytes, amount)
                .map_err(|error| control.fail(error))
        })
        .transpose()
}

// rusqlite's sql_result keeps the returned object alive across ToSql and
// sqlite3_result_blob64(..., SQLITE_TRANSIENT()).  The lease therefore remains
// live until the copy call returns; it does not account for SQLite's copy.
struct SqlCellWithKeyLease {
    value: Cell,
    _workspace: Option<Reservation>,
}
impl ToSql for SqlCellWithKeyLease {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        self.value.to_sql()
    }
}

fn equality_key(value: &SqlValue, control: &SqlControl) -> MddResult<Vec<u8>> {
    // Canonical mathematical numeric keys: u64/i64 boundaries and exactly
    // represented float integers compare equally. IEEE payloads remain on the
    // value carrier; signed zero has one SQL equality/sort key.
    let capacity = key_capacity(value).map_err(|error| control.fail(error))?;
    let mut out = Vec::new();
    out.try_reserve_exact(capacity)
        .map_err(|_| control.fail(quota("SQL_KEY_ALLOCATION")))?;
    out.extend(KEY_HEADER);
    match value {
        SqlValue::Text(text) => {
            out.push(1);
            for unit in &text.utf16 {
                control.checkpoint(1, false)?;
                out.extend(unit.to_be_bytes());
            }
        }
        SqlValue::Bytes(bytes) | SqlValue::DexMutf8 { bytes, .. } => {
            out.push(2);
            for byte in bytes {
                control.checkpoint(1, false)?;
                out.push(*byte);
            }
        }
        value => {
            out.push(0);
            let (negative, exponent, significand, special) = match value {
                SqlValue::F64(bits) => {
                    let number = f64::from_bits(bits.0);
                    let sign = bits.0 >> 63 != 0;
                    let exponent = ((bits.0 >> 52) & 2047) as i32;
                    let fraction = bits.0 & ((1u64 << 52) - 1);
                    if number.is_nan() {
                        out.push(5);
                        out.extend(bits.0.to_be_bytes());
                        return Ok(out);
                    }
                    if number.is_infinite() {
                        (sign, 0, 0, if sign { 0 } else { 4 })
                    } else if number == 0.0 {
                        (false, 0, 0, 2)
                    } else if exponent == 0 {
                        let bit = 63 - fraction.leading_zeros();
                        (
                            sign,
                            bit as i32 - 1074,
                            fraction << (63 - bit),
                            if sign { 1 } else { 3 },
                        )
                    } else {
                        (
                            sign,
                            exponent - 1023,
                            ((1u64 << 52) | fraction) << 11,
                            if sign { 1 } else { 3 },
                        )
                    }
                }
                value => {
                    let integer = integer(value)?;
                    let magnitude = integer.unsigned_abs() as u64;
                    if magnitude == 0 {
                        (false, 0, 0, 2)
                    } else {
                        let exponent = 63 - magnitude.leading_zeros();
                        (
                            integer < 0,
                            exponent as i32,
                            magnitude << (63 - exponent),
                            if integer < 0 { 1 } else { 3 },
                        )
                    }
                }
            };
            out.push(special);
            if special == 1 || special == 3 {
                let encoded = (exponent + 2048) as u16;
                let mut payload = encoded
                    .to_be_bytes()
                    .into_iter()
                    .chain(significand.to_be_bytes())
                    .collect::<Vec<_>>();
                if negative {
                    for byte in &mut payload {
                        *byte = !*byte;
                    }
                }
                out.extend(payload);
            }
        }
    }
    Ok(out)
}
fn numeric(left: &SqlValue, right: &SqlValue, operation: &str) -> MddResult<SqlValue> {
    if matches!(left, SqlValue::Null) || matches!(right, SqlValue::Null) {
        return Ok(SqlValue::Null);
    }
    if matches!(left, SqlValue::F64(_)) || matches!(right, SqlValue::F64(_)) {
        let float = |value: &SqlValue| -> MddResult<f64> {
            if let SqlValue::F64(bits) = value {
                Ok(f64::from_bits(bits.0))
            } else {
                let number = integer(value)?;
                if number.unsigned_abs() > (1u128 << 53) {
                    return Err(invalid("INEXACT_INTEGER_FLOAT_COERCION"));
                }
                Ok(number as f64)
            }
        };
        let (a, b) = (float(left)?, float(right)?);
        if b == 0.0 && matches!(operation, "div" | "mod") {
            return Ok(SqlValue::Null);
        }
        return Ok(SqlValue::F64(DecimalU64(
            match operation {
                "add" => a + b,
                "sub" => a - b,
                "mul" => a * b,
                "div" => a / b,
                "mod" => a % b,
                _ => return Err(invalid("NUMERIC_OPERATION")),
            }
            .to_bits(),
        )));
    }
    let (a, b) = (integer(left)?, integer(right)?);
    if b == 0 && matches!(operation, "div" | "mod") {
        return Ok(SqlValue::Null);
    }
    let value = match operation {
        "add" => a.checked_add(b),
        "sub" => a.checked_sub(b),
        "mul" => a.checked_mul(b),
        "div" => a.checked_div(b),
        "mod" => a.checked_rem(b),
        _ => return Err(invalid("NUMERIC_OPERATION")),
    }
    .ok_or_else(|| invalid("INTEGER_OVERFLOW"))?;
    integer_value(
        value,
        matches!(left, SqlValue::U64(_)) || matches!(right, SqlValue::U64(_)),
    )
}

fn legacy_integer_text_candidate(
    units: impl Iterator<Item = u16>,
    control: &SqlControl,
) -> MddResult<(i64, bool)> {
    control.checkpoint(1, false)?;
    let mut units = units.peekable();
    while units
        .peek()
        .is_some_and(|unit| matches!(*unit, 9..=13 | 32))
    {
        control.checkpoint(1, false)?;
        units.next();
    }
    let mut negative = false;
    let mut signed = false;
    if let Some(sign @ (43 | 45)) = units.peek().copied() {
        control.checkpoint(1, false)?;
        units.next();
        signed = true;
        negative = sign == 45;
    }
    if !units.peek().is_some_and(|unit| matches!(*unit, 48..=57)) {
        if signed || units.peek() == Some(&46) {
            return Err(legacy_numeric_unimplemented());
        }
        return Ok((0, false));
    }
    let limit = i64::MAX as u64 + u64::from(negative);
    let mut magnitude = 0u64;
    while let Some(unit @ 48..=57) = units.peek().copied() {
        control.checkpoint(1, false)?;
        units.next();
        let digit = u64::from(unit - 48);
        if magnitude > (limit - digit) / 10 {
            return Err(legacy_numeric_unimplemented());
        }
        magnitude = magnitude * 10 + digit;
    }
    for unit in units {
        control.checkpoint(1, false)?;
        if !matches!(unit, 9..=13 | 32) {
            return Err(legacy_numeric_unimplemented());
        }
    }
    let value = if negative && magnitude == i64::MAX as u64 + 1 {
        i64::MIN
    } else if negative {
        -(magnitude as i64)
    } else {
        magnitude as i64
    };
    Ok((value, true))
}

fn legacy_numeric_unimplemented() -> MddError {
    MddError::new(
        mdd_types::ErrorCode::UnsupportedQuery,
        "sql.numeric",
        "LEGACY_TEXT_NUMERIC_COERCION_NOT_IMPLEMENTED",
    )
}

fn legacy_numeric_operand<'a>(
    value: &'a SqlValue,
    control: &SqlControl,
) -> MddResult<(Cow<'a, SqlValue>, bool)> {
    let (number, exact_integer) = match value {
        SqlValue::Text(text) => legacy_integer_text_candidate(text.utf16.iter().copied(), control)?,
        SqlValue::Bytes(bytes) | SqlValue::DexMutf8 { bytes, .. } => {
            legacy_integer_text_candidate(bytes.iter().copied().map(u16::from), control)?
        }
        _ => return Ok((Cow::Borrowed(value), false)),
    };
    Ok((Cow::Owned(SqlValue::I64(Signed64(number))), exact_integer))
}

fn legacy_exact_integer_arithmetic(
    left: &SqlValue,
    right: &SqlValue,
    operation: &str,
) -> MddResult<SqlValue> {
    let signed = |value: &SqlValue| match value {
        SqlValue::I64(value) => Ok(value.0),
        SqlValue::Bool(value) => Ok(i64::from(*value)),
        _ => Err(legacy_numeric_unimplemented()),
    };
    let (left, right) = (signed(left)?, signed(right)?);
    if right == 0 && matches!(operation, "div" | "mod") {
        return Ok(SqlValue::Null);
    }
    let value = match operation {
        "add" => left.checked_add(right),
        "sub" => left.checked_sub(right),
        "mul" => left.checked_mul(right),
        "div" => left.checked_div(right),
        "mod" => left.checked_rem(right),
        _ => return Err(invalid("NUMERIC_OPERATION")),
    }
    .ok_or_else(legacy_numeric_unimplemented)?;
    Ok(SqlValue::I64(Signed64(value)))
}
/// SQLite's integer CAST consumes an ASCII decimal prefix and saturates at
/// signed 64-bit bounds. Inspect units directly: no surrogate replacement or
/// UTF-8 display conversion can enter this numeric operation.
fn sqlite_integer_prefix(units: impl Iterator<Item = u16>, control: &SqlControl) -> MddResult<i64> {
    let mut units = units.peekable();
    let mut consumed = 0usize;
    let mut tick = || -> MddResult<()> {
        consumed += 1;
        if consumed.is_multiple_of(128) {
            control.checkpoint(1, false)?;
        }
        Ok(())
    };
    while units
        .peek()
        .is_some_and(|unit| matches!(*unit, 9..=13 | 32))
    {
        units.next();
        tick()?;
    }
    let negative = match units.peek() {
        Some(45) => {
            units.next();
            tick()?;
            true
        }
        Some(43) => {
            units.next();
            tick()?;
            false
        }
        _ => false,
    };
    let limit = (i64::MAX as u64) + u64::from(negative);
    let mut magnitude = 0u64;
    while let Some(unit @ 48..=57) = units.peek().copied() {
        units.next();
        tick()?;
        let digit = u64::from(unit - 48);
        if magnitude > (limit - digit) / 10 {
            return Ok(if negative { i64::MIN } else { i64::MAX });
        }
        magnitude = magnitude * 10 + digit;
    }
    Ok(if negative && magnitude == (i64::MAX as u64) + 1 {
        i64::MIN
    } else if negative {
        -(magnitude as i64)
    } else {
        magnitude as i64
    })
}
fn cast(
    value: SqlValue,
    target: &str,
    dialect: SqlDialect,
    control: &SqlControl,
) -> MddResult<SqlValue> {
    if value == SqlValue::Null {
        return Ok(value);
    }
    if target == "i64" && dialect != SqlDialect::NativeV1 {
        let parsed = match &value {
            SqlValue::Text(text) => {
                Some(sqlite_integer_prefix(text.utf16.iter().copied(), control)?)
            }
            SqlValue::Bytes(bytes) | SqlValue::DexMutf8 { bytes, .. } => Some(
                sqlite_integer_prefix(bytes.iter().copied().map(u16::from), control)?,
            ),
            _ => None,
        };
        if let Some(parsed) = parsed {
            return Ok(SqlValue::I64(Signed64(parsed)));
        }
    }
    Ok(match target {
        "text" => SqlValue::Text(if let SqlValue::Bytes(bytes) = value {
            decoded_text(&bytes, dialect, control)?
        } else if let SqlValue::F64(bits) = value {
            let number = f64::from_bits(bits.0);
            let text = if dialect == SqlDialect::NativeV1 {
                format!("{number:?}")
            } else {
                legacy_float_text(number)?
            };
            SqlText::from_utf8(&text)
        } else {
            scalar_text(&value, control)?
        }),
        "bytes" => match value {
            SqlValue::Bytes(_) => value,
            SqlValue::DexMutf8 { bytes, .. } => SqlValue::Bytes(bytes),
            value => SqlValue::Bytes(encoded_text(
                &scalar_text(&value, control)?,
                dialect,
                control,
            )?),
        },
        "i64" => {
            let value = if let SqlValue::Text(text) = &value {
                text.strict_utf8()?
                    .parse::<i128>()
                    .map_err(|_| invalid("INVALID_INTEGER_CAST"))?
            } else {
                integer(&value)?
            };
            SqlValue::I64(Signed64(
                i64::try_from(value).map_err(|_| invalid("INTEGER_CAST_OVERFLOW"))?,
            ))
        }
        "u64" => {
            let value = if let SqlValue::Text(text) = &value {
                text.strict_utf8()?
                    .parse::<i128>()
                    .map_err(|_| invalid("INVALID_UNSIGNED_CAST"))?
            } else {
                integer(&value)?
            };
            SqlValue::U64(DecimalU64(
                u64::try_from(value).map_err(|_| invalid("UNSIGNED_CAST_OVERFLOW"))?,
            ))
        }
        "f64" => {
            let value = if let SqlValue::F64(_) = value {
                return Ok(value);
            } else if let SqlValue::Text(text) = &value {
                text.strict_utf8()?
                    .parse::<f64>()
                    .map_err(|_| invalid("INVALID_FLOAT_CAST"))?
            } else {
                let n = integer(&value)?;
                if n.unsigned_abs() > (1u128 << 53) {
                    return Err(invalid("INEXACT_FLOAT_CAST"));
                }
                n as f64
            };
            SqlValue::F64(DecimalU64(value.to_bits()))
        }
        "bool" => SqlValue::Bool(integer(&value)? != 0),
        _ => return Err(invalid("UNKNOWN_CAST_TARGET")),
    })
}
fn legacy_float_text(value: f64) -> MddResult<String> {
    let value = if value == 0.0 { 0.0 } else { value };
    let mut buffer = [0u8; 128];
    // SAFETY: the fixed format requires exactly one promoted C double. The
    // buffer pointer/length agree; sqlite3_snprintf always NUL terminates for
    // positive capacity. No connection or source pointer crosses this call.
    unsafe {
        rusqlite::ffi::sqlite3_snprintf(
            buffer.len() as i32,
            buffer.as_mut_ptr().cast(),
            c"%!.15g".as_ptr(),
            value,
        );
    }
    let end = buffer.iter().position(|b| *b == 0).ok_or_else(|| {
        MddError::new(
            mdd_types::ErrorCode::InternalFault,
            "sql.cast",
            "SQLite float formatter did not terminate",
        )
    })?;
    std::str::from_utf8(&buffer[..end])
        .map(str::to_owned)
        .map_err(|_| {
            MddError::new(
                mdd_types::ErrorCode::InternalFault,
                "sql.cast",
                "SQLite float formatter emitted non UTF8",
            )
        })
}
fn like(
    value: &SqlText,
    pattern: &SqlText,
    escape: Option<u16>,
    dialect: SqlDialect,
    control: &SqlControl,
) -> MddResult<bool> {
    #[derive(Clone, Copy)]
    enum Token {
        Literal(u16),
        One,
        Many,
    }
    control.checkpoint(1, false)?;
    // Each pattern unit produces at most one token. Hold the conservative
    // logical allocation bound until matching ends, including error paths.
    // This does not account for SQLite or the decoded argument buffers.
    let bytes = u64::try_from(pattern.utf16.len())
        .ok()
        .and_then(|length| length.checked_mul(std::mem::size_of::<Token>() as u64))
        .ok_or_else(|| control.fail(quota("LIKE_TOKEN_WORKSPACE_OVERFLOW")))?;
    let _reservation = control
        .runtime()
        .map(|runtime| {
            runtime
                .pool()
                .reserve(mdd_query::budget::Resource::QueryWorkspaceBytes, bytes)
                .map_err(|error| control.fail(error))
        })
        .transpose()?;
    let mut tokens = Vec::new();
    tokens
        .try_reserve_exact(pattern.utf16.len())
        .map_err(|_| control.fail(quota("LIKE_TOKEN_ALLOCATION")))?;
    let mut at = 0;
    while at < pattern.utf16.len() {
        control.checkpoint(1, false)?;
        let unit = pattern.utf16[at];
        if Some(unit) == escape {
            at += 1;
            control.checkpoint(1, false)?;
            let Some(&escaped) = pattern.utf16.get(at) else {
                return if dialect == SqlDialect::NativeV1 {
                    Err(invalid("LIKE_DANGLING_ESCAPE"))
                } else {
                    Ok(false)
                };
            };
            tokens.push(Token::Literal(escaped));
        } else if unit == 37 {
            tokens.push(Token::Many);
        } else if unit == 95 && dialect == SqlDialect::NativeV1 {
            tokens.push(Token::One);
        } else {
            tokens.push(Token::Literal(unit));
        }
        at += 1;
    }
    let fold = |v: u16| {
        if dialect != SqlDialect::NativeV1 && (65..=90).contains(&v) {
            v + 32
        } else {
            v
        }
    };
    let (mut input, mut token, mut star, mut restart) = (0usize, 0usize, None, 0usize);
    while input < value.utf16.len() {
        control.checkpoint(1, false)?;
        if token < tokens.len()
            && match tokens[token] {
                Token::One => true,
                Token::Literal(v) => fold(v) == fold(value.utf16[input]),
                Token::Many => false,
            }
        {
            input += 1;
            token += 1;
        } else if token < tokens.len() && matches!(tokens[token], Token::Many) {
            star = Some(token);
            token += 1;
            restart = input;
        } else if let Some(star) = star {
            restart += 1;
            input = restart;
            token = star + 1;
        } else {
            return Ok(false);
        }
    }
    while token < tokens.len() && matches!(tokens[token], Token::Many) {
        control.checkpoint(1, false)?;
        token += 1;
    }
    Ok(token == tokens.len())
}
fn substring_range(length: usize, start: i128, count: Option<i128>) -> (usize, usize) {
    let len = length as i128;
    let offset = if start > 0 {
        start - 1
    } else if start < 0 {
        len + start
    } else {
        0
    };
    let count = count.unwrap_or(i128::from(i64::MAX));
    let (begin, end) = if count < 0 {
        (offset + count, offset)
    } else {
        (offset, offset + count - i128::from(start == 0 && count > 0))
    };
    (begin.clamp(0, len) as usize, end.clamp(0, len) as usize)
}

fn concat_capacity(
    left: usize,
    right: usize,
    unit_bytes: u64,
    max: u64,
    reason: &str,
) -> MddResult<usize> {
    let units = left.checked_add(right).ok_or_else(|| quota(reason))?;
    let bytes = u64::try_from(units)
        .ok()
        .and_then(|n| n.checked_mul(unit_bytes))
        .ok_or_else(|| quota(reason))?;
    if bytes > max {
        return Err(quota(reason));
    }
    Ok(units)
}

// Decode each ordinary byte operand independently. Inspect at most four bytes
// between checkpoints so malformed input cannot create an unbounded scan.
fn legacy_concat_units(
    value: &SqlValue,
    control: &SqlControl,
    mut emit: impl FnMut(u16) -> MddResult<()>,
) -> MddResult<()> {
    match value {
        SqlValue::Bytes(bytes) => {
            let mut at = 0;
            while at < bytes.len() {
                control.checkpoint(0, false)?;
                let end = at.saturating_add(4).min(bytes.len());
                let window = &bytes[at..end];
                let (ch, consumed) = match std::str::from_utf8(window) {
                    Ok(text) => {
                        let ch = text.chars().next().expect("nonempty window");
                        (ch, ch.len_utf8())
                    }
                    Err(error) if error.valid_up_to() > 0 => {
                        let prefix = std::str::from_utf8(&window[..error.valid_up_to()])
                            .map_err(|_| invalid("CONCAT_UTF8_VALID_PREFIX"))?;
                        let ch = prefix.chars().next().expect("nonempty valid prefix");
                        (ch, ch.len_utf8())
                    }
                    Err(error) => ('\u{fffd}', error.error_len().unwrap_or(window.len())),
                };
                control.checkpoint(consumed as u64, false)?;
                let mut buffer = [0u16; 2];
                for unit in ch.encode_utf16(&mut buffer).iter().copied() {
                    emit(unit)?;
                }
                at += consumed;
            }
        }
        SqlValue::DexMutf8 {
            bytes,
            utf16_code_units,
        } => {
            let mut at = 0;
            let mut count = 0u64;
            while at < bytes.len() {
                control.checkpoint(0, false)?;
                let first = bytes[at];
                let (size, mut unit, minimum) = match first {
                    1..=0x7f => (1, u16::from(first), 0),
                    0xc0..=0xdf => (2, u16::from(first & 31), 0x80),
                    0xe0..=0xef => (3, u16::from(first & 15), 0x800),
                    _ => return Err(invalid("INVALID_DEX_MUTF8_CARRIER")),
                };
                let end = at
                    .checked_add(size)
                    .filter(|end| *end <= bytes.len())
                    .ok_or_else(|| invalid("TRUNCATED_DEX_MUTF8_CARRIER"))?;
                for byte in &bytes[at + 1..end] {
                    if byte & 0xc0 != 0x80 {
                        return Err(invalid("INVALID_DEX_MUTF8_CONTINUATION"));
                    }
                    unit = (unit << 6) | u16::from(byte & 63);
                }
                if unit < minimum && !(size == 2 && unit == 0 && first == 0xc0) {
                    return Err(invalid("OVERLONG_DEX_MUTF8_CARRIER"));
                }
                control.checkpoint(size as u64, false)?;
                emit(unit)?;
                count = count
                    .checked_add(1)
                    .ok_or_else(|| quota("DEX_MUTF8_UNIT_COUNT_OVERFLOW"))?;
                at = end;
            }
            if count != utf16_code_units.0 {
                return Err(invalid("DEX_MUTF8_UNIT_COUNT_MISMATCH"));
            }
        }
        SqlValue::Text(text) => {
            for unit in &text.utf16 {
                control.checkpoint(1, false)?;
                emit(*unit)?;
            }
        }
        _ => {
            // Scalar numeric formatting has bounded size; do not clone a text operand.
            let text = scalar_text(value, control)?;
            for unit in text.utf16 {
                control.checkpoint(1, false)?;
                emit(unit)?;
            }
        }
    }
    Ok(())
}

fn legacy_concat(
    args: &[SqlValue],
    control: &SqlControl,
) -> MddResult<(SqlValue, Option<Reservation>)> {
    let mut count = 0usize;
    for value in args {
        legacy_concat_units(value, control, |_| {
            count = count
                .checked_add(1)
                .ok_or_else(|| quota("CONCAT_CELL_BYTES"))?;
            concat_capacity(
                count,
                0,
                2,
                control.inner.limits.max_cell_bytes,
                "CONCAT_CELL_BYTES",
            )?;
            Ok(())
        })?;
    }
    // The text vector and tagged SQLite value coexist until ToSql returns.
    // This is a logical bound; SQLite's own copies and allocator overhead are separate.
    let workspace = u64::try_from(count)
        .ok()
        .and_then(|n| n.checked_mul(4))
        .and_then(|n| n.checked_add(b"\0MDDTEXT1".len() as u64))
        .ok_or_else(|| quota("CONCAT_WORKSPACE_OVERFLOW"))?;
    let lease = control
        .runtime()
        .map(|runtime| {
            runtime
                .pool()
                .reserve(mdd_query::budget::Resource::QueryWorkspaceBytes, workspace)
                .map_err(|error| control.fail(error))
        })
        .transpose()?;
    let mut units = Vec::new();
    units
        .try_reserve_exact(count)
        .map_err(|_| control.fail(quota("CONCAT_ALLOCATION")))?;
    for value in args {
        legacy_concat_units(value, control, |unit| {
            units.push(unit);
            Ok(())
        })?;
    }
    if units.len() != count {
        return Err(invalid("CONCAT_LENGTH_CHANGED"));
    }
    Ok((
        SqlValue::Text(SqlText {
            utf16: units,
            original_mutf8: None,
        }),
        lease,
    ))
}

fn scalar(
    name: &str,
    args: &[SqlValue],
    dialect: SqlDialect,
    control: &SqlControl,
) -> MddResult<SqlValue> {
    control.checkpoint(1, false)?;
    if name == "mdd_hex" {
        let bytes: Cow<'_, [u8]> = match &args[0] {
            SqlValue::Null => Cow::Borrowed(&[]),
            SqlValue::Bytes(bytes) | SqlValue::DexMutf8 { bytes, .. } => Cow::Borrowed(bytes),
            value => Cow::Owned(encoded_text(
                &scalar_text(value, control)?,
                dialect,
                control,
            )?),
        };
        if bytes.len() as u64 > control.inner.limits.max_cell_bytes / 4 {
            return Err(quota("HEX_RESULT_CELL_BYTES"));
        }
        let capacity = bytes
            .len()
            .checked_mul(2)
            .ok_or_else(|| control.fail(quota("HEX_RESULT_CAPACITY_OVERFLOW")))?;
        let mut output = String::new();
        output
            .try_reserve_exact(capacity)
            .map_err(|_| control.fail(quota("HEX_RESULT_ALLOCATION")))?;
        const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
        for &byte in bytes.iter() {
            control.checkpoint(1, false)?;
            output.push(char::from(DIGITS[usize::from(byte >> 4)]));
            output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        // The result and argument buffers are not covered by a workspace lease.
        return Ok(SqlValue::text(&output));
    }
    if name == "mdd_key" || name == "mdd_sort_key" {
        if args[0] == SqlValue::Null {
            return Ok(SqlValue::Null);
        }
        return Ok(SqlValue::Bytes(equality_key(&args[0], control)?));
    }
    if name == "mdd_nullif" {
        if args[0] == SqlValue::Null {
            return Ok(SqlValue::Null);
        }
        if args[1] != SqlValue::Null && compare(&args[0], &args[1], control)? == Ordering::Equal {
            return Ok(SqlValue::Null);
        }
        return Ok(args[0].clone());
    }
    if args
        .iter()
        .take(if name == "mdd_like" { 2 } else { args.len() })
        .any(|value| value == &SqlValue::Null)
    {
        return Ok(SqlValue::Null);
    }
    if name == "mdd_min_scalar" || name == "mdd_max_scalar" {
        if args.len() < 2 {
            return Err(invalid("MINMAX_SCALAR_ARITY"));
        }
        let mut chosen = &args[0];
        for value in &args[1..] {
            control.checkpoint(1, false)?;
            let order = compare_literal(value, chosen, control)?;
            if (name == "mdd_min_scalar" && order == Ordering::Less)
                || (name == "mdd_max_scalar" && order == Ordering::Greater)
            {
                chosen = value;
            }
        }
        return Ok(chosen.clone());
    }
    match name {
        "mdd_substr" => {
            let start = integer(&args[1])?;
            let count = args.get(2).map(integer).transpose()?;
            if dialect == SqlDialect::NativeV1
                && let SqlValue::Bytes(bytes) = &args[0]
            {
                let (begin, end) = substring_range(bytes.len(), start, count);
                return Ok(SqlValue::Bytes(bytes[begin..end].to_vec()));
            }
            let text = match &args[0] {
                SqlValue::Bytes(bytes) => Cow::Owned(decoded_text(bytes, dialect, control)?),
                value => scalar_text_cow(value, control)?,
            };
            // The offset table holds at most one index per UTF-16 unit plus
            // the final boundary. Charge its logical capacity before it is
            // allocated and release it after the result slice is formed.
            // Decoded arguments, the result copy and SQLite buffers are not
            // covered by this reservation.
            let capacity = text
                .utf16
                .len()
                .checked_add(1)
                .ok_or_else(|| control.fail(quota("SUBSTR_OFFSETS_CAPACITY_OVERFLOW")))?;
            let bytes = u64::try_from(capacity)
                .ok()
                .and_then(|length| length.checked_mul(std::mem::size_of::<usize>() as u64))
                .ok_or_else(|| control.fail(quota("SUBSTR_OFFSETS_WORKSPACE_OVERFLOW")))?;
            let _reservation = control
                .runtime()
                .map(|runtime| {
                    runtime
                        .pool()
                        .reserve(mdd_query::budget::Resource::QueryWorkspaceBytes, bytes)
                        .map_err(|error| control.fail(error))
                })
                .transpose()?;
            let mut offsets = Vec::new();
            offsets
                .try_reserve_exact(capacity)
                .map_err(|_| control.fail(quota("SUBSTR_OFFSETS_ALLOCATION")))?;
            let mut at = 0;
            while at < text.utf16.len() {
                control.checkpoint(1, false)?;
                offsets.push(at);
                if dialect != SqlDialect::NativeV1
                    && (0xd800..=0xdbff).contains(&text.utf16[at])
                    && text
                        .utf16
                        .get(at + 1)
                        .is_some_and(|v| (0xdc00..=0xdfff).contains(v))
                {
                    control.checkpoint(1, false)?;
                    at += 2;
                } else {
                    at += 1;
                }
            }
            control.checkpoint(1, false)?;
            offsets.push(at);
            let (begin, end) = substring_range(offsets.len() - 1, start, count);
            Ok(SqlValue::Text(SqlText {
                utf16: text.utf16[offsets[begin]..offsets[end]].to_vec(),
                original_mutf8: None,
            }))
        }
        "mdd_length" => {
            let text = scalar_text_cow(&args[0], control)?;
            let units = &text.utf16;
            let mut length = units.len();
            if dialect != SqlDialect::NativeV1 {
                for pair in units.windows(2) {
                    control.checkpoint(1, false)?;
                    if (0xd800..=0xdbff).contains(&pair[0]) && (0xdc00..=0xdfff).contains(&pair[1])
                    {
                        length -= 1;
                    }
                }
                if !units.is_empty() {
                    control.checkpoint(1, false)?;
                }
            }
            Ok(SqlValue::I64(Signed64(length as i64)))
        }
        "mdd_cast" => cast(
            args[0].clone(),
            &scalar_text(&args[1], control)?.strict_utf8()?,
            dialect,
            control,
        ),
        "mdd_like" => {
            let has_escape = integer(&args[3])? != 0;
            if has_escape && args[2] == SqlValue::Null {
                return Ok(SqlValue::Null);
            }
            let value = scalar_text_cow(&args[0], control)?;
            let pattern = scalar_text_cow(&args[1], control)?;
            let escape = if !has_escape {
                None
            } else {
                let escape = scalar_text_cow(&args[2], control)?;
                if escape.utf16.len() != 1 {
                    return Err(invalid("LIKE_ESCAPE_REQUIRES_ONE_UTF16_UNIT"));
                }
                Some(escape.utf16[0])
            };
            Ok(SqlValue::Bool(like(
                &value, &pattern, escape, dialect, control,
            )?))
        }
        "mdd_concat" => {
            if let (Some(left), Some(right)) = (args[0].bytes(), args[1].bytes()) {
                let capacity = concat_capacity(
                    left.len(),
                    right.len(),
                    1,
                    control.inner.limits.max_cell_bytes,
                    "BLOB_CONCAT_CELL_BYTES",
                )?;
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(capacity)
                    .map_err(|_| control.fail(quota("BLOB_CONCAT_ALLOCATION")))?;
                for &byte in left.iter().chain(right) {
                    control.checkpoint(1, false)?;
                    bytes.push(byte);
                }
                return Ok(SqlValue::Bytes(bytes));
            }
            let left = scalar_text_cow(&args[0], control)?;
            let right = scalar_text_cow(&args[1], control)?;
            let capacity = concat_capacity(
                left.utf16.len(),
                right.utf16.len(),
                2,
                control.inner.limits.max_cell_bytes,
                "CONCAT_CELL_BYTES",
            )?;
            let mut units = Vec::new();
            units
                .try_reserve_exact(capacity)
                .map_err(|_| control.fail(quota("CONCAT_ALLOCATION")))?;
            for &unit in left.utf16.iter().chain(&right.utf16) {
                control.checkpoint(1, false)?;
                units.push(unit);
            }
            // Argument decoding, the result carrier and SQLite buffers are not
            // covered by a workspace lease here.
            Ok(SqlValue::Text(SqlText {
                utf16: units,
                original_mutf8: None,
            }))
        }
        "mdd_lower" | "mdd_upper" => {
            let mut text = scalar_text(&args[0], control)?;
            for value in &mut text.utf16 {
                control.checkpoint(1, false)?;
                if name == "mdd_lower" && (65..=90).contains(value) {
                    *value += 32;
                } else if name == "mdd_upper" && (97..=122).contains(value) {
                    *value -= 32;
                }
            }
            text.original_mutf8 = None;
            Ok(SqlValue::Text(text))
        }
        "mdd_neg" => {
            if dialect != SqlDialect::NativeV1
                && matches!(
                    args[0],
                    SqlValue::Text(_) | SqlValue::Bytes(_) | SqlValue::DexMutf8 { .. }
                )
            {
                return Err(MddError::new(
                    mdd_types::ErrorCode::UnsupportedQuery,
                    "sql.numeric",
                    "LEGACY_TEXT_NUMERIC_COERCION_NOT_IMPLEMENTED",
                ));
            }
            if let SqlValue::F64(bits) = args[0] {
                Ok(SqlValue::F64(DecimalU64(bits.0 ^ (1u64 << 63))))
            } else {
                integer_value(-integer(&args[0])?, false)
            }
        }
        "mdd_pos" => Ok(args[0].clone()),
        "mdd_eq"
        | "mdd_ne"
        | "mdd_gt"
        | "mdd_ge"
        | "mdd_lt"
        | "mdd_le"
        | "mdd_literal_eq"
        | "mdd_literal_ne"
        | "mdd_literal_gt"
        | "mdd_literal_ge"
        | "mdd_literal_lt"
        | "mdd_literal_le"
        | "mdd_text_integer_eq"
        | "mdd_text_integer_ne"
        | "mdd_text_integer_gt"
        | "mdd_text_integer_ge"
        | "mdd_text_integer_lt"
        | "mdd_text_integer_le" => {
            let (order, operator) = if let Some(operator) = name.strip_prefix("mdd_text_integer_") {
                (
                    compare_text_integer_literal(&args[0], &args[1], control)?,
                    operator,
                )
            } else if let Some(operator) = name.strip_prefix("mdd_literal_") {
                (compare_literal(&args[0], &args[1], control)?, operator)
            } else {
                (compare(&args[0], &args[1], control)?, &name[4..])
            };
            Ok(SqlValue::Bool(match operator {
                "eq" => order == Ordering::Equal,
                "ne" => order != Ordering::Equal,
                "gt" => order == Ordering::Greater,
                "ge" => order != Ordering::Less,
                "lt" => order == Ordering::Less,
                _ => order != Ordering::Greater,
            }))
        }
        "mdd_add" | "mdd_sub" | "mdd_mul" | "mdd_div" | "mdd_mod" => {
            if dialect != SqlDialect::NativeV1 {
                let (left, left_exact) = legacy_numeric_operand(&args[0], control)?;
                let (right, right_exact) = legacy_numeric_operand(&args[1], control)?;
                if left_exact || right_exact {
                    return legacy_exact_integer_arithmetic(&left, &right, &name[4..]);
                }
                return numeric(&left, &right, &name[4..]);
            }
            numeric(&args[0], &args[1], &name[4..])
        }
        _ => Err(invalid("INTERNAL_UNKNOWN_SCALAR")),
    }
}
fn failure(control: &SqlControl, error: MddError) -> rusqlite::Error {
    rusqlite::Error::UserFunctionError(Box::new(control.fail(error)))
}
fn args(context: &Context<'_>) -> MddResult<Vec<SqlValue>> {
    (0..context.len())
        .map(|i| SqlValue::from_sqlite(context.get_raw(i)))
        .collect()
}
pub(crate) fn register(
    db: &Connection,
    dialect: SqlDialect,
    control: SqlControl,
) -> rusqlite::Result<()> {
    let flags = FunctionFlags::SQLITE_UTF8
        | FunctionFlags::SQLITE_DETERMINISTIC
        | FunctionFlags::SQLITE_INNOCUOUS;
    // Return a SQLite-native value only for truth coercion. SQLite then owns
    // the AND/OR/NOT/IS TRUE and NULL rules. Lossy text here cannot enter a
    // result or comparison; non-ASCII surrogate units cannot be numeric text.
    let truth_control = control.clone();
    db.create_scalar_function("mdd_truth_input", 1, flags, move |context| {
        truth_control
            .checkpoint(1, false)
            .map_err(|e| failure(&truth_control, e))?;
        let value =
            SqlValue::from_sqlite(context.get_raw(0)).map_err(|e| failure(&truth_control, e))?;
        Ok(match value {
            SqlValue::Null => Cell::Null,
            SqlValue::Bool(v) => Cell::Integer(i64::from(v)),
            SqlValue::I64(v) => Cell::Integer(v.0),
            SqlValue::U64(v) => {
                i64::try_from(v.0).map_or_else(|_| Cell::Real(v.0 as f64), Cell::Integer)
            }
            SqlValue::F64(v) => Cell::Real(f64::from_bits(v.0)),
            SqlValue::Text(v) => Cell::Text(String::from_utf16_lossy(&v.utf16)),
            SqlValue::Bytes(v) | SqlValue::DexMutf8 { bytes: v, .. } => Cell::Blob(v),
        })
    })?;
    for (name, count) in [
        ("mdd_length", 1),
        ("mdd_substr", 2),
        ("mdd_substr", 3),
        ("mdd_hex", 1),
        ("mdd_lower", 1),
        ("mdd_upper", 1),
        ("mdd_neg", 1),
        ("mdd_pos", 1),
        ("mdd_key", 1),
        ("mdd_sort_key", 1),
        ("mdd_nullif", 2),
        ("mdd_min_scalar", -1),
        ("mdd_max_scalar", -1),
        ("mdd_eq", 2),
        ("mdd_ne", 2),
        ("mdd_gt", 2),
        ("mdd_ge", 2),
        ("mdd_lt", 2),
        ("mdd_le", 2),
        ("mdd_literal_eq", 2),
        ("mdd_literal_ne", 2),
        ("mdd_literal_gt", 2),
        ("mdd_literal_ge", 2),
        ("mdd_literal_lt", 2),
        ("mdd_literal_le", 2),
        ("mdd_text_integer_eq", 2),
        ("mdd_text_integer_ne", 2),
        ("mdd_text_integer_gt", 2),
        ("mdd_text_integer_ge", 2),
        ("mdd_text_integer_lt", 2),
        ("mdd_text_integer_le", 2),
        ("mdd_concat", 2),
        ("mdd_cast", 2),
        ("mdd_add", 2),
        ("mdd_sub", 2),
        ("mdd_mul", 2),
        ("mdd_div", 2),
        ("mdd_mod", 2),
        ("mdd_like", 4),
    ] {
        let control = control.clone();
        db.create_scalar_function(name, count, flags, move |context| {
            let values = args(context).map_err(|e| failure(&control, e))?;
            let key_workspace = if name == "mdd_key" || name == "mdd_sort_key" {
                reserve_key_workspace(&values[0], &control).map_err(|e| failure(&control, e))?
            } else {
                None
            };
            let (value, concat_workspace) = if name == "mdd_concat"
                && dialect != SqlDialect::NativeV1
                && !values.contains(&SqlValue::Null)
            {
                legacy_concat(&values, &control).map_err(|e| failure(&control, e))?
            } else {
                (
                    scalar(name, &values, dialect, &control).map_err(|e| failure(&control, e))?,
                    None,
                )
            };
            let value = value
                .sqlite(control.inner.limits.max_cell_bytes)
                .map_err(|e| failure(&control, e))?;
            Ok(SqlCellWithKeyLease {
                value,
                _workspace: key_workspace.or(concat_workspace),
            })
        })?;
    }
    for name in ["mdd_min", "mdd_max", "mdd_sum"] {
        db.create_aggregate_function(
            name,
            1,
            flags,
            AggregateValue {
                name,
                control: control.clone(),
            },
        )?;
    }
    Ok(())
}
struct AggregateValue {
    name: &'static str,
    control: SqlControl,
}
impl Aggregate<Option<SqlValue>, Cell> for AggregateValue {
    fn init(&self, _: &mut Context<'_>) -> rusqlite::Result<Option<SqlValue>> {
        Ok(None)
    }
    fn step(
        &self,
        context: &mut Context<'_>,
        state: &mut Option<SqlValue>,
    ) -> rusqlite::Result<()> {
        self.control
            .checkpoint(1, false)
            .map_err(|e| failure(&self.control, e))?;
        let value =
            SqlValue::from_sqlite(context.get_raw(0)).map_err(|e| failure(&self.control, e))?;
        if value == SqlValue::Null {
            return Ok(());
        }
        if let Some(previous) = state {
            if self.name == "mdd_sum" {
                *previous =
                    numeric(previous, &value, "add").map_err(|e| failure(&self.control, e))?;
            } else {
                let order = compare(previous, &value, &self.control)
                    .map_err(|e| failure(&self.control, e))?;
                if (self.name == "mdd_min" && order == Ordering::Greater)
                    || (self.name == "mdd_max" && order == Ordering::Less)
                {
                    *previous = value;
                }
            }
        } else {
            *state = Some(value);
        }
        Ok(())
    }
    fn finalize(
        &self,
        _: &mut Context<'_>,
        state: Option<Option<SqlValue>>,
    ) -> rusqlite::Result<Cell> {
        state
            .flatten()
            .unwrap_or(SqlValue::Null)
            .sqlite(self.control.inner.limits.max_cell_bytes)
            .map_err(|e| failure(&self.control, e))
    }
}

#[cfg(test)]
mod like_budget_tests {
    use super::*;
    use crate::control::SqlLimits;
    use mdd_types::ErrorCode;

    #[test]
    fn text_decode_obeys_step_budget_and_cancellation() {
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let limited = SqlControl::new(
                SqlLimits {
                    max_steps: 8,
                    ..SqlLimits::default()
                },
                None,
            );
            let value = SqlValue::Bytes(vec![b'A'; 256]);
            assert_eq!(
                cast(value.clone(), "text", dialect, &limited)
                    .unwrap_err()
                    .code,
                ErrorCode::QuotaExceeded
            );
            let cancelled = SqlControl::new(SqlLimits::default(), None);
            cancelled.cancel().unwrap();
            assert_eq!(
                cast(value, "text", dialect, &cancelled).unwrap_err().code,
                ErrorCode::Cancelled
            );
            let limited_mutf = SqlControl::new(
                SqlLimits {
                    max_steps: 8,
                    ..SqlLimits::default()
                },
                None,
            );
            let value = SqlValue::DexMutf8 {
                bytes: vec![b'A'; 256],
                utf16_code_units: DecimalU64(256),
            };
            assert_eq!(
                cast(value, "text", dialect, &limited_mutf)
                    .unwrap_err()
                    .code,
                ErrorCode::QuotaExceeded
            );
            let normal = SqlControl::new(SqlLimits::default(), None);
            assert_eq!(
                cast(SqlValue::Bytes(vec![0xff]), "text", dialect, &normal)
                    .unwrap_err()
                    .message,
                "CAST_TEXT_BAD_ENCODING"
            );
            let normal = SqlControl::new(SqlLimits::default(), None);
            assert_eq!(
                cast(SqlValue::Bytes(vec![0xe2, 0x82]), "text", dialect, &normal)
                    .unwrap_err()
                    .message,
                "CAST_TEXT_TRUNCATED_ENCODING"
            );
            let normal = SqlControl::new(SqlLimits::default(), None);
            let surrogate = SqlValue::DexMutf8 {
                bytes: vec![0xed, 0xa0, 0x80],
                utf16_code_units: DecimalU64(1),
            };
            assert_eq!(
                cast(surrogate, "text", dialect, &normal).unwrap(),
                SqlValue::Text(SqlText {
                    utf16: vec![0xd800],
                    original_mutf8: None,
                })
            );
        }
    }

    #[test]
    fn text_and_bytes_comparisons_account_for_work() {
        let control = SqlControl::new(SqlLimits::default(), None);
        let text = |units| {
            SqlValue::Text(SqlText {
                utf16: units,
                original_mutf8: None,
            })
        };
        assert_eq!(
            compare(&text(vec![0, 0xd800]), &text(vec![0, 0xdfff]), &control).unwrap(),
            Ordering::Less
        );
        assert_eq!(
            compare(
                &SqlValue::Bytes(vec![0, 255]),
                &SqlValue::Bytes(vec![0, 255, 0]),
                &control
            )
            .unwrap(),
            Ordering::Less
        );
        assert_eq!(
            compare_literal(&SqlValue::Bytes(vec![1]), &text(vec![49]), &control).unwrap(),
            Ordering::Greater
        );
        for value in [text(vec![65; 128]), SqlValue::Bytes(vec![65; 128])] {
            let limited = SqlControl::new(
                SqlLimits {
                    max_steps: 8,
                    ..SqlLimits::default()
                },
                None,
            );
            assert_eq!(
                compare(&value, &value, &limited).unwrap_err().code,
                ErrorCode::QuotaExceeded
            );
            let cancelled = SqlControl::new(SqlLimits::default(), None);
            cancelled.cancel().unwrap();
            assert_eq!(
                compare(&value, &value, &cancelled).unwrap_err().code,
                ErrorCode::Cancelled
            );
        }
    }

    #[test]
    fn legacy_integer_text_candidate_is_strict_and_budgeted() {
        for input in ["", " ", " \tword", "\0", "雪"] {
            let control = SqlControl::new(SqlLimits::default(), None);
            let value = SqlValue::text(input);
            assert_eq!(
                legacy_numeric_operand(&value, &control).unwrap().0.as_ref(),
                &SqlValue::I64(Signed64(0))
            );
        }
        for (input, expected) in [
            ("1", 1),
            ("+1", 1),
            (" -2 ", -2),
            ("-9223372036854775808", i64::MIN),
            ("9223372036854775807", i64::MAX),
        ] {
            let control = SqlControl::new(SqlLimits::default(), None);
            let value = SqlValue::text(input);
            let (result, exact) = legacy_numeric_operand(&value, &control).unwrap();
            assert!(exact);
            assert_eq!(result.as_ref(), &SqlValue::I64(Signed64(expected)));
        }
        for input in [
            ".5",
            "1.0",
            "1e2",
            "2x",
            "+",
            "9223372036854775808",
            "-9223372036854775809",
        ] {
            let control = SqlControl::new(SqlLimits::default(), None);
            let value = SqlValue::text(input);
            assert_eq!(
                legacy_numeric_operand(&value, &control).unwrap_err().code,
                ErrorCode::UnsupportedQuery
            );
        }
        let limited = SqlControl::new(
            SqlLimits {
                max_steps: 2,
                ..SqlLimits::default()
            },
            None,
        );
        assert_eq!(
            legacy_numeric_operand(&SqlValue::text("   x"), &limited)
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        let cancelled = SqlControl::new(SqlLimits::default(), None);
        cancelled.cancel().unwrap();
        assert_eq!(
            legacy_numeric_operand(&SqlValue::text("x"), &cancelled)
                .unwrap_err()
                .code,
            ErrorCode::Cancelled
        );
    }

    #[test]
    fn legacy_concat_lossy_decoder_agrees_with_bounded_standard_oracle() {
        let tails: &[&[u8]] = &[
            &[],
            &[0x80],
            &[0xa9],
            &[0x41],
            &[0x9f, 0x98, 0x80],
            &[0xff, 0x80],
        ];
        for first in 0u8..=u8::MAX {
            for tail in tails {
                let mut bytes = vec![first];
                bytes.extend_from_slice(tail);
                let mut actual = Vec::new();
                legacy_concat_units(
                    &SqlValue::Bytes(bytes.clone()),
                    &SqlControl::new(SqlLimits::default(), None),
                    |u| {
                        actual.push(u);
                        Ok(())
                    },
                )
                .unwrap();
                let expected: Vec<_> = String::from_utf8_lossy(&bytes).encode_utf16().collect();
                assert_eq!(actual, expected, "{bytes:?}");
            }
        }
    }

    #[test]
    fn legacy_concat_checks_steps_cell_limit_and_cancellation() {
        let values = [SqlValue::Bytes(vec![b'a'; 100]), SqlValue::text("b")];
        let limited = SqlControl::new(
            SqlLimits {
                max_steps: 16,
                ..SqlLimits::default()
            },
            None,
        );
        assert_eq!(
            legacy_concat(&values, &limited).err().unwrap().code,
            ErrorCode::QuotaExceeded
        );
        let cell = SqlControl::new(
            SqlLimits {
                max_cell_bytes: 6,
                ..SqlLimits::default()
            },
            None,
        );
        assert_eq!(
            legacy_concat(&values, &cell).err().unwrap().code,
            ErrorCode::QuotaExceeded
        );
        let cancelled = SqlControl::new(SqlLimits::default(), None);
        cancelled.cancel().unwrap();
        assert_eq!(
            legacy_concat(&values, &cancelled).err().unwrap().code,
            ErrorCode::Cancelled
        );
    }

    #[test]
    fn concat_capacity_checks_addition_multiplication_and_cell_limit() {
        assert_eq!(concat_capacity(2, 2, 2, 8, "CONCAT_CELL_BYTES").unwrap(), 4);
        for (left, right, unit, max) in [
            (usize::MAX, 1, 1, u64::MAX),
            (usize::MAX, 0, u64::MAX, u64::MAX),
            (2, 3, 2, 9),
        ] {
            let error = concat_capacity(left, right, unit, max, "CONCAT_CELL_BYTES").unwrap_err();
            assert_eq!(error.code, ErrorCode::QuotaExceeded);
        }
    }

    #[test]
    fn key_workspace_checked_amount_rejects_overflow() {
        let error = key_workspace_amount(u64::MAX).unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
        assert_eq!(key_workspace_amount(1).unwrap(), 2 + BYTES.len() as u64);
    }

    #[test]
    fn key_lease_survives_actual_rusqlite_to_sql_callback() {
        use mdd_query::budget::{BudgetLimits, BudgetPool, Resource};
        use std::sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        };

        struct ObservedCell {
            inner: SqlCellWithKeyLease,
            pool: BudgetPool,
            observed: Arc<AtomicU64>,
        }
        impl ToSql for ObservedCell {
            fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
                let used = self
                    .pool
                    .usage()
                    .unwrap()
                    .used
                    .get(&Resource::QueryWorkspaceBytes)
                    .map_or(0, |v| v.0);
                self.observed.store(used, Ordering::Release);
                self.inner.to_sql()
            }
        }

        let pool = BudgetPool::global(
            "key-to-sql-test".into(),
            BudgetLimits::default().with(Resource::QueryWorkspaceBytes, 8192),
        )
        .unwrap();
        let observed = Arc::new(AtomicU64::new(0));
        let callback_pool = pool.clone();
        let callback_observed = Arc::clone(&observed);
        let db = Connection::open_in_memory().unwrap();
        db.create_scalar_function(
            "key_lease_probe",
            0,
            FunctionFlags::SQLITE_UTF8,
            move |_| {
                let lease = callback_pool
                    .reserve(Resource::QueryWorkspaceBytes, 64)
                    .unwrap();
                Ok(ObservedCell {
                    inner: SqlCellWithKeyLease {
                        value: Cell::Blob(vec![0, 1, 0xff]),
                        _workspace: Some(lease),
                    },
                    pool: callback_pool.clone(),
                    observed: Arc::clone(&callback_observed),
                })
            },
        )
        .unwrap();
        let copied: Vec<u8> = db
            .query_row("SELECT key_lease_probe()", [], |row| row.get(0))
            .unwrap();
        assert_eq!(copied, vec![0, 1, 0xff]);
        assert_eq!(observed.load(Ordering::Acquire), 64);
        assert_eq!(
            pool.usage()
                .unwrap()
                .used
                .get(&Resource::QueryWorkspaceBytes)
                .map_or(0, |v| v.0),
            0
        );
        // The SQLite/client copy can remain alive after the Rust lease drops;
        // this test does not claim that copy is covered by the reservation.
        assert_eq!(copied, vec![0, 1, 0xff]);
    }

    #[test]
    fn scalar_minmax_comparisons_consume_step_budget() {
        let control = SqlControl::new(
            SqlLimits {
                max_steps: 2,
                ..SqlLimits::default()
            },
            None,
        );
        let arguments = vec![SqlValue::I64(Signed64(1)); 8];
        let error =
            scalar("mdd_min_scalar", &arguments, SqlDialect::NativeV1, &control).unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
    }

    #[test]
    fn empty_input_does_not_skip_long_pattern_step_budget() {
        let limits = SqlLimits {
            max_steps: 8,
            ..SqlLimits::default()
        };
        let control = SqlControl::new(limits, None);
        let value = SqlText {
            utf16: vec![],
            original_mutf8: None,
        };
        let pattern = SqlText {
            utf16: vec![u16::from(b'%'); 128],
            original_mutf8: None,
        };
        let error = like(&value, &pattern, None, SqlDialect::NativeV1, &control).unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
    }

    #[test]
    fn cancelled_empty_like_is_not_a_success() {
        let control = SqlControl::new(SqlLimits::default(), None);
        control.cancel().unwrap();
        let empty = SqlText {
            utf16: vec![],
            original_mutf8: None,
        };
        let error = like(&empty, &empty, None, SqlDialect::NativeV1, &control).unwrap_err();
        assert_eq!(error.code, ErrorCode::Cancelled);
    }

    #[test]
    fn trailing_escape_follows_selected_dialect_when_budget_sufficient() {
        let control = SqlControl::new(SqlLimits::default(), None);
        let empty = SqlText {
            utf16: vec![],
            original_mutf8: None,
        };
        let pattern = SqlText {
            utf16: vec![u16::from(b'!')],
            original_mutf8: None,
        };
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            assert!(!like(&empty, &pattern, Some(u16::from(b'!')), dialect, &control).unwrap());
        }
        let error = like(
            &empty,
            &pattern,
            Some(u16::from(b'!')),
            SqlDialect::NativeV1,
            &control,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(error.message, "LIKE_DANGLING_ESCAPE");
    }

    #[test]
    fn legacy_trailing_escape_does_not_hide_budget_or_cancel_errors() {
        let empty = SqlText {
            utf16: vec![],
            original_mutf8: None,
        };
        let pattern = SqlText {
            utf16: vec![u16::from(b'!')],
            original_mutf8: None,
        };
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let limited = SqlControl::new(
                SqlLimits {
                    max_steps: 1,
                    ..SqlLimits::default()
                },
                None,
            );
            let error =
                like(&empty, &pattern, Some(u16::from(b'!')), dialect, &limited).unwrap_err();
            assert_eq!(error.code, ErrorCode::QuotaExceeded);
            let cancelled = SqlControl::new(SqlLimits::default(), None);
            cancelled.cancel().unwrap();
            let error =
                like(&empty, &pattern, Some(u16::from(b'!')), dialect, &cancelled).unwrap_err();
            assert_eq!(error.code, ErrorCode::Cancelled);
        }
    }
}
