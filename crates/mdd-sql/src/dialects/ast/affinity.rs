use super::*;

// Admit only the directly observed form. Derived columns, CTEs and arbitrary
// expressions need their own affinity binding; they must not inherit this rule.
pub(super) fn text_cast_string_literal(expr: &Expr) -> bool {
    match without_parentheses(expr) {
        Expr::Cast {
            expr,
            data_type: DataType::Text,
            format: None,
            ..
        } => {
            matches!(&**expr, Expr::Value(value) if matches!(value.value, Value::SingleQuotedString(_)))
        }
        _ => false,
    }
}

pub(super) fn nonnegative_i64_literal(expr: &Expr) -> bool {
    match without_parentheses(expr) {
        Expr::Value(value) => match &value.value {
            Value::Number(number, _) => {
                number.bytes().all(|b| b.is_ascii_digit()) && number.parse::<i64>().is_ok()
            }
            _ => false,
        },
        _ => false,
    }
}
pub(super) fn integer_cast_string_literal(expr: &Expr) -> bool {
    match without_parentheses(expr) {
        Expr::Cast {
            expr,
            data_type: DataType::Integer(None),
            format: None,
            ..
        } => {
            matches!(&**expr, Expr::Value(value) if matches!(value.value, Value::SingleQuotedString(_)))
        }
        _ => false,
    }
}
pub(super) fn text_cast_nonnegative_i64_literal(expr: &Expr) -> bool {
    match without_parentheses(expr) {
        Expr::Cast {
            expr,
            data_type: DataType::Text,
            format: None,
            ..
        } => nonnegative_i64_literal(expr),
        _ => false,
    }
}
// SQLite NUMERIC affinity accepts ASCII whitespace, a leading sign and
// leading zeroes for integer text. Limit this rewrite to exact i64 integers;
// decimal/exponent text and out-of-range values need separate semantics.
pub(super) fn exact_i64_text_literal(expr: &Expr) -> Option<i64> {
    let Expr::Value(value) = expr else {
        return None;
    };
    let Value::SingleQuotedString(text) = &value.value else {
        return None;
    };
    exact_i64_text(text)
}

pub(super) fn exact_i64_text(text: &str) -> Option<i64> {
    if !text.is_ascii() {
        return None;
    }
    let trimmed =
        text.trim_matches(|c| matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{000b}' | '\u{000c}'));
    let digits = trimmed
        .strip_prefix('+')
        .or_else(|| trimmed.strip_prefix('-'))
        .unwrap_or(trimmed);
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        return trimmed.parse::<i64>().ok();
    }
    exact_real_syntax_integer(trimmed)
}

// A limited part of SQLite NUMERIC affinity. SQLite's decimal parser uses a
// u64 mantissa; with at most 18 digits it does not discard significant digits.
// An exact mathematical integer below 2^53 is representable in binary64.
// Fractional, truncated-mantissa, underflow and rounded-overflow cases remain
// unsupported rather than being approximated as integers here.
pub(super) fn exact_real_syntax_integer(text: &str) -> Option<i64> {
    const EXACT_MAX: u128 = (1u128 << 53) - 1;
    let (negative, unsigned) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    let mut parts = unsigned.split(['e', 'E']);
    let mantissa = parts.next()?;
    let exponent_text = parts.next();
    if parts.next().is_some() || (exponent_text.is_none() && !mantissa.contains('.')) {
        return None;
    }
    let exponent: i32 = if let Some(exp) = exponent_text {
        let exp_digits = exp
            .strip_prefix('+')
            .or_else(|| exp.strip_prefix('-'))
            .unwrap_or(exp);
        if exp_digits.is_empty() || !exp_digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        exp.parse().ok()?
    } else {
        0
    };
    let mut coefficient = 0u128;
    let mut digits = 0u32;
    let mut fractional = 0i32;
    let mut dot = false;
    for byte in mantissa.bytes() {
        match byte {
            b'.' if !dot => dot = true,
            b'0'..=b'9' => {
                digits += 1;
                if digits > 18 {
                    return None;
                }
                coefficient = coefficient
                    .checked_mul(10)?
                    .checked_add(u128::from(byte - b'0'))?;
                if dot {
                    fractional += 1;
                }
            }
            _ => return None,
        }
    }
    if digits == 0 {
        return None;
    }
    // Exact zero is distinct from a nonzero value that underflows to zero.
    if coefficient == 0 {
        return Some(0);
    }
    let power = exponent.checked_sub(fractional)?;
    let magnitude = if power >= 0 {
        coefficient.checked_mul(10u128.checked_pow(u32::try_from(power).ok()?)?)?
    } else {
        let divisor = 10u128.checked_pow(power.unsigned_abs())?;
        if !coefficient.is_multiple_of(divisor) {
            return None;
        }
        coefficient / divisor
    };
    if magnitude > EXACT_MAX {
        return None;
    }
    let value = i64::try_from(magnitude).ok()?;
    Some(if negative { -value } else { value })
}
pub(super) fn canonical_i64_text_literal(expr: &Expr) -> Option<i64> {
    let Expr::Value(value) = expr else {
        return None;
    };
    let Value::SingleQuotedString(text) = &value.value else {
        return None;
    };
    let value = exact_i64_text_literal(expr)?;
    (value.to_string() == *text).then_some(value)
}
pub(super) fn replace_with_i64_literal(expr: &mut Expr, value: i64) {
    *expr = Expr::Value(Value::Number(value.to_string(), false).into());
}

// SQLite TEXT affinity renders an integer literal as canonical decimal text.
// Only accept syntactic integers that fit i64: real literals and integers
// beyond SQLite's signed range require a separately proven formatting rule.
pub(super) fn exact_i64_numeric_literal(mut expr: &Expr) -> Option<i64> {
    while let Expr::Nested(inner) = expr {
        expr = inner;
    }
    match expr {
        Expr::Value(value) => match &value.value {
            Value::Number(number, _) if number.bytes().all(|b| b.is_ascii_digit()) => {
                number.parse::<i64>().ok()
            }
            Value::Boolean(value) => Some(i64::from(*value)),
            _ => None,
        },
        Expr::UnaryOp { op, expr } if matches!(op, UnaryOperator::Plus | UnaryOperator::Minus) => {
            let Expr::Value(value) = expr.as_ref() else {
                return None;
            };
            let Value::Number(number, _) = &value.value else {
                return None;
            };
            if !number.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let magnitude = number.parse::<i128>().ok()?;
            let signed = if matches!(op, UnaryOperator::Minus) {
                -magnitude
            } else {
                magnitude
            };
            i64::try_from(signed).ok()
        }
        _ => None,
    }
}

// Only a bare length() call and integer/NULL literal bounds have proven
// numeric classes here. In particular, TRUE/FALSE may bind to columns and
// parameters or decimal literals require separate affinity evidence.
pub(super) fn length_with_integer_between_bounds(
    value: &Expr,
    low: &Expr,
    high: &Expr,
    max_depth: usize,
) -> bool {
    fn integer_or_null(mut expr: &Expr, max_depth: usize) -> bool {
        let mut depth = 0;
        while let Expr::Nested(inner) = expr {
            if depth >= max_depth {
                return false;
            }
            depth += 1;
            expr = inner;
        }
        match expr {
            Expr::Value(value) if matches!(value.value, Value::Null) => true,
            Expr::Value(value) if matches!(value.value, Value::Number(_, _)) => {
                exact_i64_numeric_literal(expr).is_some()
            }
            Expr::UnaryOp {
                op: UnaryOperator::Plus | UnaryOperator::Minus,
                ..
            } => exact_i64_numeric_literal(expr).is_some(),
            _ => false,
        }
    }
    let mut value = value;
    let mut depth = 0;
    while let Expr::Nested(inner) = value {
        if depth >= max_depth {
            return false;
        }
        depth += 1;
        value = inner;
    }
    matches!(value, Expr::Function(function)
        if function.name.0.len() == 1
        && function.name.0[0].as_ident().is_some_and(|name| name.value.eq_ignore_ascii_case("length"))
        && function.over.is_none()
        && function.filter.is_none()
        && matches!(&function.args, FunctionArguments::List(arguments)
            if arguments.duplicate_treatment.is_none() && arguments.clauses.is_empty()
            && matches!(arguments.args.as_slice(), [FunctionArg::Unnamed(FunctionArgExpr::Expr(_))])))
        && integer_or_null(low, max_depth)
        && integer_or_null(high, max_depth)
}
pub(super) fn direct_text_integer_affinity(
    dialect: super::SqlDialect,
    left: &Expr,
    right: &Expr,
) -> bool {
    dialect != super::SqlDialect::NativeV1
        && ((text_cast_string_literal(left) && nonnegative_i64_literal(right))
            || (nonnegative_i64_literal(left) && text_cast_string_literal(right)))
}
// A deliberately narrow affinity source: a CTE with one directly cast text
// literal and no input relation. Unproved projections remain guarded.
pub(super) fn single_literal_text_cte_column(cte: &Cte) -> Option<String> {
    if cte.query.with.is_some() || cte.query.order_by.is_some() || cte.query.limit_clause.is_some()
    {
        return None;
    }
    let SetExpr::Select(select) = cte.query.body.as_ref() else {
        return None;
    };
    if !select.from.is_empty()
        || select.selection.is_some()
        || select.having.is_some()
        || select.distinct.is_some()
        || !matches!(&select.group_by, GroupByExpr::Expressions(values, modifiers)
            if values.is_empty() && modifiers.is_empty())
        || select.projection.len() != 1
    {
        return None;
    }
    let SelectItem::ExprWithAlias { expr, alias } = &select.projection[0] else {
        return None;
    };
    if !text_cast_string_literal(expr) {
        return None;
    }
    match cte.alias.columns.as_slice() {
        [] => Some(alias.value.to_ascii_lowercase()),
        [column] => Some(column.name.value.to_ascii_lowercase()),
        _ => None,
    }
}
