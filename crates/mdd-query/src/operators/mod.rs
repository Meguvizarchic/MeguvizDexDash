//! Exact native predicates and controlled comparison/sorting. No SQL or collation inference.
use crate::executor::{Control, FactSource};
use crate::ir::*;
use mdd_types::MddResult;
use std::cmp::Ordering;

/// Native UTF-16 pattern notation only, not a SQL parser/dialect admission.
/// '%' and '_' are wildcards; an explicitly selected single code unit escapes the next unit.
pub fn native_like_pattern(units: &[u16], escape: Option<u16>) -> MddResult<Vec<LikeToken>> {
    let mut tokens = Vec::new();
    let mut at = 0usize;
    while at < units.len() {
        let unit = units[at];
        at += 1;
        let token = if Some(unit) == escape {
            let escaped = *units
                .get(at)
                .ok_or_else(|| invalid("LIKE_TRAILING_ESCAPE"))?;
            at += 1;
            LikeToken::Literal(escaped)
        } else {
            match unit {
                0x25 => LikeToken::AnyMany,
                0x5f => LikeToken::AnyOne,
                v => LikeToken::Literal(v),
            }
        };
        if tokens.len() == 256 {
            return Err(invalid("LIKE_PATTERN_LIMIT"));
        }
        tokens.push(token);
    }
    Ok(tokens)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Truth {
    False,
    True,
    Unknown,
}
impl Truth {
    pub(crate) fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }
    pub(crate) fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, Self::True) => Self::True,
            _ => Self::Unknown,
        }
    }
    pub(crate) fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::True, _) | (_, Self::True) => Self::True,
            (Self::False, Self::False) => Self::False,
            _ => Self::Unknown,
        }
    }
}

pub fn expression_type(
    expr: &Expr,
    schema: &Schema,
    depth: usize,
) -> MddResult<(Option<DataType>, bool)> {
    if depth > 64 {
        return Err(invalid("EXPRESSION_DEPTH_LIMIT"));
    }
    Ok(match expr {
        Expr::Column { ordinal } => {
            let c = schema
                .get(*ordinal)
                .ok_or_else(|| invalid("COLUMN_ORDINAL"))?;
            (Some(c.data_type), c.nullable)
        }
        Expr::Literal { value } => (value.data_type(), value == &Value::Null),
        Expr::ReadCodeBytes { entity, .. } => {
            if expression_type(entity, schema, depth + 1)?.0 != Some(DataType::Entity) {
                return Err(invalid("CODE_ENTITY_TYPE"));
            }
            (Some(DataType::Bytes), true)
        }
    })
}
fn compatible(left: Option<DataType>, right: Option<DataType>) -> bool {
    left.is_none() || right.is_none() || left == right
}
pub fn check_predicate(predicate: &Predicate, schema: &Schema, depth: usize) -> MddResult<()> {
    if depth > 64 {
        return Err(invalid("PREDICATE_DEPTH_LIMIT"));
    }
    match predicate {
        Predicate::Eq { left, right } | Predicate::RawBytesEq { left, right } => {
            let a = expression_type(left, schema, 0)?.0;
            let b = expression_type(right, schema, 0)?.0;
            if !compatible(a, b) {
                return Err(invalid("COMPARISON_TYPE_MISMATCH"));
            }
            if matches!(predicate, Predicate::RawBytesEq { .. }) {
                if a.is_some_and(|v| v != DataType::Bytes)
                    || b.is_some_and(|v| v != DataType::Bytes)
                {
                    return Err(invalid("RAW_BYTES_TYPE"));
                }
            } else if a == Some(DataType::Bytes) || b == Some(DataType::Bytes) {
                return Err(invalid("USE_RAW_BYTES_EQ"));
            }
        }
        Predicate::Prefix { value, .. } | Predicate::Like { value, .. } => {
            if expression_type(value, schema, 0)?
                .0
                .is_some_and(|v| v != DataType::Utf16)
            {
                return Err(invalid("TEXT_PREDICATE_TYPE"));
            }
            if let Predicate::Like { pattern, .. } = predicate
                && pattern.len() > 256
            {
                return Err(invalid("LIKE_PATTERN_LIMIT"));
            }
        }
        Predicate::IsNull { value } => {
            expression_type(value, schema, 0)?;
        }
        Predicate::And { left, right } | Predicate::Or { left, right } => {
            check_predicate(left, schema, depth + 1)?;
            check_predicate(right, schema, depth + 1)?;
        }
        Predicate::Not { value } => check_predicate(value, schema, depth + 1)?,
    }
    Ok(())
}
pub fn expression(
    expr: &Expr,
    row: &Row,
    source: &dyn FactSource,
    control: &mut Control<'_>,
) -> MddResult<Value> {
    control.step("expression", 1)?;
    Ok(match expr {
        Expr::Column { ordinal } => row
            .get(*ordinal)
            .ok_or_else(|| invalid("COLUMN_ORDINAL"))?
            .clone(),
        Expr::Literal { value } => {
            value.validate(source.snapshot_id())?;
            value.clone()
        }
        Expr::ReadCodeBytes {
            entity,
            byte_offset,
            byte_length,
        } => {
            let value = expression(entity, row, source, control)?;
            let Value::Entity(entity) = value else {
                if value == Value::Null {
                    return Ok(Value::Null);
                }
                return Err(invalid("CODE_ENTITY_TYPE"));
            };
            let Some(raw) = source.read_code_bytes(&entity)? else {
                return Ok(Value::Null);
            };
            let offset = usize::try_from(byte_offset.0).map_err(|_| invalid("CODE_BYTE_OFFSET"))?;
            let length = match byte_length {
                Some(v) => usize::try_from(v.0).map_err(|_| invalid("CODE_BYTE_LENGTH"))?,
                None => raw
                    .len()
                    .checked_sub(offset)
                    .ok_or_else(|| invalid("CODE_BYTE_OFFSET"))?,
            };
            let end = offset
                .checked_add(length)
                .ok_or_else(|| invalid("CODE_RANGE_OVERFLOW"))?;
            let bytes = raw
                .get(offset..end)
                .ok_or_else(|| invalid("CODE_BYTE_RANGE"))?;
            control.charge_cell(bytes.len() as u64)?;
            Value::Bytes(Bytes(bytes.to_vec()))
        }
    })
}
fn equality(left: Value, right: Value) -> Truth {
    if left == Value::Null || right == Value::Null {
        Truth::Unknown
    } else if left == right {
        Truth::True
    } else {
        Truth::False
    }
}
fn like_dp(text: &[u16], pattern: &[LikeToken], control: &mut Control<'_>) -> MddResult<bool> {
    control.charge((text.len() as u64 + 1) * 2)?;
    let mut previous = vec![false; text.len() + 1];
    previous[0] = true;
    for token in pattern {
        let mut next = vec![false; text.len() + 1];
        for at in 0..=text.len() {
            control.step("like_cell", 1)?;
            next[at] = match token {
                LikeToken::AnyMany => previous[at] || (at > 0 && next[at - 1]),
                LikeToken::AnyOne => at > 0 && previous[at - 1],
                LikeToken::Literal(unit) => at > 0 && previous[at - 1] && text[at - 1] == *unit,
            };
        }
        previous = next;
    }
    Ok(previous[text.len()])
}
/// Reference-dialect LIKE matcher. Semantics and per-call `reference_like` charging
/// are identical to a recursive descent, but the backtracking stack lives on the heap
/// so a pattern up to the validated 256 tokens cannot overflow the call stack (MDD-084).
fn like_reference(
    text: &[u16],
    pattern: &[LikeToken],
    control: &mut Control<'_>,
) -> MddResult<bool> {
    // Each frame is an `AnyMany` continuation: the text/pattern position it matched at
    // and the next start offset to try. `current` is the call being entered; a produced
    // `Some(result)` unwinds, `None` means a child call was pushed and is entered next.
    let mut stack: Vec<(usize, usize, usize)> = Vec::new();
    let mut current: Option<(usize, usize)> = Some((0, 0));
    loop {
        let Some((t, p)) = current.take() else {
            return Ok(false);
        };
        control.step("reference_like", 1)?;
        let produced: Option<bool> = if p == pattern.len() {
            Some(t == text.len())
        } else {
            match pattern[p] {
                LikeToken::AnyMany => {
                    stack.push((t, p, 0));
                    current = Some((t, p + 1));
                    None
                }
                LikeToken::AnyOne => {
                    if t == text.len() {
                        Some(false)
                    } else {
                        current = Some((t + 1, p + 1));
                        None
                    }
                }
                LikeToken::Literal(unit) => {
                    if text.get(t) != Some(&unit) {
                        Some(false)
                    } else {
                        current = Some((t + 1, p + 1));
                        None
                    }
                }
            }
        };
        let Some(result) = produced else { continue };
        // A true result propagates to the root unchanged, exactly as the recursive
        // version returns `Ok(true)` up every frame without further charging.
        if result {
            return Ok(true);
        }
        // False: resume the nearest `AnyMany` with its next start, or fail closed.
        loop {
            let Some((t, p, start)) = stack.pop() else {
                return Ok(false);
            };
            let next = start + 1;
            if next <= text.len() - t {
                stack.push((t, p, next));
                current = Some((t + next, p + 1));
                break;
            }
        }
    }
}

/// The deepest nesting of `And`/`Or`/`Not` the evaluator walks. `check_predicate` refuses deeper
/// predicates when a plan is validated; the evaluator refuses them as well, so a predicate that
/// bypassed validation still cannot exhaust the call stack.
const PREDICATE_EVAL_DEPTH: usize = 64;

/// Evaluate a predicate: one step per node, the parent before its children, the left child before
/// the right, and no short-circuit (both sides are always evaluated, so a failure on either side
/// is reported).
///
/// `And`/`Or`/`Not` recurse, but only through this small frame: the evaluation of a leaf is a
/// separate function that is never inlined into it. The former evaluator kept the leaf match in the
/// recursive function itself, a frame of tens of kilobytes in a debug build, and overflowed a 1 MiB
/// stack at about ten levels of nesting (MDD-084); a frame of this size takes the validated depth of
/// 64 on any stack.
pub fn predicate(
    predicate: &Predicate,
    row: &Row,
    source: &dyn FactSource,
    control: &mut Control<'_>,
    reference: bool,
) -> MddResult<Truth> {
    predicate_at(predicate, row, source, control, reference, 0)
}

fn predicate_at(
    predicate: &Predicate,
    row: &Row,
    source: &dyn FactSource,
    control: &mut Control<'_>,
    reference: bool,
    depth: usize,
) -> MddResult<Truth> {
    if depth > PREDICATE_EVAL_DEPTH {
        return Err(invalid("PREDICATE_DEPTH_LIMIT"));
    }
    control.step("predicate", 1)?;
    match predicate {
        Predicate::And { left, right } => {
            let left = predicate_at(left, row, source, control, reference, depth + 1)?;
            let right = predicate_at(right, row, source, control, reference, depth + 1)?;
            Ok(left.and(right))
        }
        Predicate::Or { left, right } => {
            let left = predicate_at(left, row, source, control, reference, depth + 1)?;
            let right = predicate_at(right, row, source, control, reference, depth + 1)?;
            Ok(left.or(right))
        }
        Predicate::Not { value } => {
            Ok(predicate_at(value, row, source, control, reference, depth + 1)?.not())
        }
        leaf => predicate_leaf(leaf, row, source, control, reference),
    }
}
/// Truth value of a non-boolean predicate leaf. Compound `And`/`Or`/`Not` nodes are handled by
/// [`predicate_at`] and must never reach here. Kept out of line so that the recursive frame stays small.
#[inline(never)]
fn predicate_leaf(
    predicate: &Predicate,
    row: &Row,
    source: &dyn FactSource,
    control: &mut Control<'_>,
    reference: bool,
) -> MddResult<Truth> {
    Ok(match predicate {
        Predicate::Eq { left, right } | Predicate::RawBytesEq { left, right } => equality(
            expression(left, row, source, control)?,
            expression(right, row, source, control)?,
        ),
        Predicate::Prefix { value, units } => match expression(value, row, source, control)? {
            Value::Null => Truth::Unknown,
            Value::Utf16(v) => {
                if v.starts_with(units) {
                    Truth::True
                } else {
                    Truth::False
                }
            }
            _ => return Err(invalid("TEXT_PREDICATE_TYPE")),
        },
        Predicate::Like { value, pattern } => match expression(value, row, source, control)? {
            Value::Null => Truth::Unknown,
            Value::Utf16(v) => {
                let yes = if reference {
                    like_reference(&v, pattern, control)?
                } else {
                    like_dp(&v, pattern, control)?
                };
                if yes { Truth::True } else { Truth::False }
            }
            _ => return Err(invalid("TEXT_PREDICATE_TYPE")),
        },
        Predicate::IsNull { value } => {
            if expression(value, row, source, control)? == Value::Null {
                Truth::True
            } else {
                Truth::False
            }
        }
        Predicate::And { .. } | Predicate::Or { .. } | Predicate::Not { .. } => {
            return Err(invalid("PREDICATE_COMPOUND_IN_LEAF"));
        }
    })
}

pub fn compare_rows(left: &Row, right: &Row, keys: &[OrderKey]) -> Ordering {
    for key in keys {
        let (a, b) = (&left[key.ordinal], &right[key.ordinal]);
        let order = match (a, b) {
            (Value::Null, Value::Null) => Ordering::Equal,
            (Value::Null, _) => {
                if key.nulls_first {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            (_, Value::Null) => {
                if key.nulls_first {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            }
            _ => {
                if key.descending {
                    b.cmp(a)
                } else {
                    a.cmp(b)
                }
            }
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    Ordering::Equal
}
pub fn order_rows(
    rows: Vec<Row>,
    keys: &[OrderKey],
    control: &mut Control<'_>,
    reference: bool,
) -> MddResult<Vec<Row>> {
    control.charge(rows.len() as u64 * 16)?;
    let mut indices: Vec<usize> = (0..rows.len()).collect();
    if reference {
        for at in 1..indices.len() {
            let mut position = at;
            while position > 0 {
                control.step("reference_sort_compare", 1)?;
                if compare_rows(&rows[indices[position - 1]], &rows[indices[position]], keys)
                    != Ordering::Greater
                {
                    break;
                }
                indices.swap(position - 1, position);
                position -= 1;
            }
        }
    } else {
        let mut width = 1usize;
        let mut scratch = vec![0; indices.len()];
        while width < indices.len() {
            for start in (0..indices.len()).step_by(width.saturating_mul(2)) {
                let mid = (start + width).min(indices.len());
                let end = mid.saturating_add(width).min(indices.len());
                let (mut a, mut b) = (start, mid);
                for item in &mut scratch[start..end] {
                    control.step("sort_compare", 1)?;
                    if b == end
                        || (a < mid
                            && compare_rows(&rows[indices[a]], &rows[indices[b]], keys)
                                != Ordering::Greater)
                    {
                        *item = indices[a];
                        a += 1;
                    } else {
                        *item = indices[b];
                        b += 1;
                    }
                }
            }
            std::mem::swap(&mut scratch, &mut indices);
            width = width
                .checked_mul(2)
                .ok_or_else(|| invalid("SORT_WIDTH_OVERFLOW"))?;
        }
    }
    indices
        .into_iter()
        .map(|index| {
            control.charge_row(&rows[index])?;
            Ok(rows[index].clone())
        })
        .collect()
}
