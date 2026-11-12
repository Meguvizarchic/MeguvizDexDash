//! Structural AST adaptation. No SQL regular-expression substitution.
use crate::{control::SqlLimits, invalid, quota, values::SqlValue};
use mdd_query::ir::Signed64;
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use sqlparser::{
    ast::*,
    dialect::SQLiteDialect,
    parser::{Parser, ParserError},
    tokenizer::{Token, Tokenizer},
};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
};

pub(crate) struct Adapted {
    pub sql: String,
    pub parameters: Vec<SqlValue>,
    pub nodes: usize,
    pub required_relations: Vec<String>,
    pub cte_names: BTreeSet<String>,
    pub display_overrides: BTreeMap<String, String>,
}
#[derive(Clone)]
enum Dependency {
    Base(String),
    Cte(usize),
}
fn unsupported(reason: &str) -> MddError {
    MddError::new(ErrorCode::UnsupportedQuery, "sql.ast", reason)
}
fn parse_error(error: ParserError) -> MddError {
    if error == ParserError::RecursionLimitExceeded {
        quota("SQL_PARSER_DEPTH")
    } else {
        invalid(&format!("SQL_PARSE_ERROR: {error}")).detail("confirm_sqlite_syntax", true)
    }
}
fn null() -> Expr {
    Expr::Value(Value::Null.into())
}
fn take(expr: &mut Expr) -> Expr {
    std::mem::replace(expr, null())
}
fn without_parentheses(mut expr: &Expr) -> &Expr {
    while let Expr::Nested(inner) = expr {
        expr = inner;
    }
    expr
}
fn no_affinity(expr: &Expr) -> bool {
    match without_parentheses(expr) {
        Expr::Value(_) => true,
        Expr::UnaryOp {
            op: UnaryOperator::Plus | UnaryOperator::Minus,
            expr,
        } => {
            matches!(&**expr, Expr::Value(value) if matches!(value.value, Value::Number(_, _)))
        }
        _ => false,
    }
}

// Inspect the already rewritten projection, but never descend into a nested
// SELECT: an aggregate there does not make the outer SELECT an aggregate.
// Rewriting may introduce several wrappers per input node, so cap traversal
// independently rather than trusting unbounded recursion.
struct AggregateScan {
    depth_limit: usize,
    remaining: Cell<usize>,
}
impl AggregateScan {
    fn visit(&self, depth: usize) -> MddResult<()> {
        if depth > self.depth_limit {
            return Err(quota("SQL_AGGREGATE_DETECTION_DEPTH"));
        }
        let remaining = self
            .remaining
            .get()
            .checked_sub(1)
            .ok_or_else(|| quota("SQL_AGGREGATE_DETECTION_NODES"))?;
        self.remaining.set(remaining);
        Ok(())
    }
}

fn charged_compound_expression<'a>(
    mut expr: &'a Expr,
    mut depth: usize,
    budget: &AggregateScan,
) -> MddResult<&'a Expr> {
    while let Expr::Nested(inner) = expr {
        budget.visit(depth)?;
        depth = depth
            .checked_add(1)
            .ok_or_else(|| quota("SQL_AGGREGATE_DETECTION_DEPTH"))?;
        expr = inner;
    }
    budget.visit(depth)?;
    Ok(expr)
}
fn current_aggregate(expr: &Expr, depth: usize, budget: &AggregateScan) -> MddResult<bool> {
    budget.visit(depth)?;
    let child = |e: &Expr| current_aggregate(e, depth + 1, budget);
    match expr {
        Expr::Function(function) => {
            let name = function.name.0.first().and_then(|part| part.as_ident());
            if function.name.0.len() == 1
                && function.over.is_none()
                && name.is_some_and(|name| {
                    ["count", "mdd_sum", "mdd_min", "mdd_max"]
                        .iter()
                        .any(|aggregate| name.value.eq_ignore_ascii_case(aggregate))
                })
            {
                return Ok(true);
            }
            if let FunctionArguments::List(arguments) = &function.args {
                for argument in &arguments.args {
                    if let FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) = argument
                        && child(expr)?
                    {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        Expr::Nested(expr)
        | Expr::IsNull(expr)
        | Expr::IsNotNull(expr)
        | Expr::IsTrue(expr)
        | Expr::IsFalse(expr)
        | Expr::IsNotTrue(expr)
        | Expr::IsNotFalse(expr)
        | Expr::UnaryOp { expr, .. } => child(expr),
        Expr::BinaryOp { left, right, .. } => Ok(child(left)? || child(right)?),
        Expr::Between {
            expr, low, high, ..
        } => Ok(child(expr)? || child(low)? || child(high)?),
        Expr::InList { expr, list, .. } => {
            if child(expr)? {
                return Ok(true);
            }
            for value in list {
                if child(value)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Expr::InSubquery { expr, .. } => child(expr),
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            if let Some(expr) = operand
                && child(expr)?
            {
                return Ok(true);
            }
            for condition in conditions {
                if child(&condition.condition)? || child(&condition.result)? {
                    return Ok(true);
                }
            }
            if let Some(expr) = else_result
                && child(expr)?
            {
                return Ok(true);
            }
            Ok(false)
        }
        // Identifiers, literals and inner queries cannot introduce an
        // aggregate into this SELECT. All unsupported forms were rejected by
        // the expression rewriter before this inspection.
        _ => Ok(false),
    }
}

fn possible_outer_column(
    expr: &Expr,
    local: &BTreeMap<String, BTreeSet<String>>,
    depth: usize,
    budget: &AggregateScan,
) -> MddResult<bool> {
    budget.visit(depth)?;
    let child = |value: &Expr| possible_outer_column(value, local, depth + 1, budget);
    match expr {
        Expr::Identifier(id) => {
            let name = id.value.to_ascii_lowercase();
            for columns in local.values() {
                budget.visit(depth + 1)?;
                if columns.contains(&name) {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Expr::CompoundIdentifier(ids) if ids.len() == 2 => {
            budget.visit(depth + 1)?;
            Ok(!local
                .get(&ids[0].value.to_ascii_lowercase())
                .is_some_and(|columns| columns.contains(&ids[1].value.to_ascii_lowercase())))
        }
        Expr::Value(_) => Ok(false),
        Expr::Nested(expr)
        | Expr::IsNull(expr)
        | Expr::IsNotNull(expr)
        | Expr::IsTrue(expr)
        | Expr::IsFalse(expr)
        | Expr::IsNotTrue(expr)
        | Expr::IsNotFalse(expr)
        | Expr::UnaryOp { expr, .. } => child(expr),
        Expr::BinaryOp { left, right, .. } => Ok(child(left)? || child(right)?),
        Expr::Between {
            expr, low, high, ..
        } => Ok(child(expr)? || child(low)? || child(high)?),
        Expr::Function(function) => match &function.args {
            FunctionArguments::List(arguments) => {
                for arg in &arguments.args {
                    match arg {
                        FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) => {
                            if child(expr)? {
                                return Ok(true);
                            }
                        }
                        FunctionArg::Unnamed(FunctionArgExpr::Wildcard) => (),
                        _ => return Ok(true),
                    }
                }
                if let Some(filter) = &function.filter
                    && child(filter)?
                {
                    return Ok(true);
                }
                Ok(false)
            }
            _ => Ok(true),
        },
        _ => Ok(true),
    }
}

// A nested aggregate may belong to an outer SELECT when its inputs reference
// only outer columns. Rewriting that SELECT's DISTINCT into GROUP BY can
// otherwise change semantics or produce an artificial SQLite error. Inspect
// nested scopes and only proceed when aggregate inputs are demonstrably local.
fn nested_aggregate_needs_binding(
    expr: &Expr,
    schemas: &BTreeMap<String, Vec<String>>,
    ctes: &BTreeSet<String>,
    depth: usize,
    budget: &AggregateScan,
    local: Option<&BTreeMap<String, BTreeSet<String>>>,
) -> MddResult<bool> {
    budget.visit(depth)?;
    let child =
        |e: &Expr| nested_aggregate_needs_binding(e, schemas, ctes, depth + 1, budget, local);
    match expr {
        Expr::Subquery(query)
        | Expr::Exists {
            subquery: query, ..
        } => nested_query_needs_binding(query, schemas, ctes, depth + 1, budget),
        Expr::InSubquery { expr, subquery, .. } => {
            Ok(child(expr)?
                || nested_query_needs_binding(subquery, schemas, ctes, depth + 1, budget)?)
        }
        Expr::Function(function) => {
            let aggregate = function.name.0.len() == 1
                && function.over.is_none()
                && function.name.0[0].as_ident().is_some_and(|name| {
                    ["count", "mdd_sum", "mdd_min", "mdd_max"]
                        .iter()
                        .any(|a| name.value.eq_ignore_ascii_case(a))
                });
            if let FunctionArguments::List(arguments) = &function.args {
                for arg in &arguments.args {
                    if let FunctionArg::Unnamed(FunctionArgExpr::Expr(value)) = arg {
                        if aggregate
                            && let Some(local) = local
                            && possible_outer_column(value, local, depth + 1, budget)?
                        {
                            return Ok(true);
                        }
                        if child(value)? {
                            return Ok(true);
                        }
                    }
                }
            }
            if let Some(filter) = &function.filter {
                if aggregate
                    && let Some(local) = local
                    && possible_outer_column(filter, local, depth + 1, budget)?
                {
                    return Ok(true);
                }
                if child(filter)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Expr::Nested(expr)
        | Expr::IsNull(expr)
        | Expr::IsNotNull(expr)
        | Expr::IsTrue(expr)
        | Expr::IsFalse(expr)
        | Expr::IsNotTrue(expr)
        | Expr::IsNotFalse(expr)
        | Expr::UnaryOp { expr, .. } => child(expr),
        Expr::BinaryOp { left, right, .. } => Ok(child(left)? || child(right)?),
        Expr::Between {
            expr, low, high, ..
        } => Ok(child(expr)? || child(low)? || child(high)?),
        Expr::InList { expr, list, .. } => {
            if child(expr)? {
                return Ok(true);
            }
            for item in list {
                if child(item)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            if let Some(expr) = operand
                && child(expr)?
            {
                return Ok(true);
            }
            for condition in conditions {
                if child(&condition.condition)? || child(&condition.result)? {
                    return Ok(true);
                }
            }
            if let Some(expr) = else_result
                && child(expr)?
            {
                return Ok(true);
            }
            Ok(false)
        }
        _ => Ok(false),
    }
}

fn nested_query_needs_binding(
    query: &Query,
    schemas: &BTreeMap<String, Vec<String>>,
    ctes: &BTreeSet<String>,
    depth: usize,
    budget: &AggregateScan,
) -> MddResult<bool> {
    budget.visit(depth)?;
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            if nested_query_needs_binding(&cte.query, schemas, ctes, depth + 1, budget)? {
                return Ok(true);
            }
        }
    }
    if let SetExpr::Select(select) = query.body.as_ref() {
        return nested_select_needs_binding(
            select,
            query.order_by.as_ref(),
            query.limit_clause.as_ref(),
            schemas,
            ctes,
            depth + 1,
            budget,
        );
    }
    if nested_body_needs_binding(&query.body, schemas, ctes, depth + 1, budget)? {
        return Ok(true);
    }
    let local = BTreeMap::new();
    let check = |e: &Expr| {
        nested_aggregate_needs_binding(e, schemas, ctes, depth + 1, budget, Some(&local))
    };
    if let Some(order) = &query.order_by
        && let OrderByKind::Expressions(exprs) = &order.kind
    {
        for value in exprs {
            if check(&value.expr)? {
                return Ok(true);
            }
        }
    }
    if let Some(limit) = &query.limit_clause {
        match limit {
            LimitClause::LimitOffset { limit, offset, .. } => {
                if let Some(expr) = limit
                    && check(expr)?
                {
                    return Ok(true);
                }
                if let Some(offset) = offset
                    && check(&offset.value)?
                {
                    return Ok(true);
                }
            }
            LimitClause::OffsetCommaLimit { offset, limit } => {
                if check(offset)? || check(limit)? {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

fn nested_body_needs_binding(
    body: &SetExpr,
    schemas: &BTreeMap<String, Vec<String>>,
    ctes: &BTreeSet<String>,
    depth: usize,
    budget: &AggregateScan,
) -> MddResult<bool> {
    budget.visit(depth)?;
    match body {
        SetExpr::Select(select) => {
            nested_select_needs_binding(select, None, None, schemas, ctes, depth + 1, budget)
        }
        SetExpr::Query(query) => {
            nested_query_needs_binding(query, schemas, ctes, depth + 1, budget)
        }
        SetExpr::SetOperation { left, right, .. } => {
            Ok(
                nested_body_needs_binding(left, schemas, ctes, depth + 1, budget)?
                    || nested_body_needs_binding(right, schemas, ctes, depth + 1, budget)?,
            )
        }
        SetExpr::Values(values) => {
            let local = BTreeMap::new();
            for row in &values.rows {
                for value in row.iter() {
                    if nested_aggregate_needs_binding(
                        value,
                        schemas,
                        ctes,
                        depth + 1,
                        budget,
                        Some(&local),
                    )? {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        _ => Ok(true),
    }
}

fn nested_select_needs_binding(
    select: &Select,
    order_by: Option<&OrderBy>,
    limit_clause: Option<&LimitClause>,
    schemas: &BTreeMap<String, Vec<String>>,
    ctes: &BTreeSet<String>,
    depth: usize,
    budget: &AggregateScan,
) -> MddResult<bool> {
    budget.visit(depth)?;
    let mut local = BTreeMap::new();
    let add_table =
        |table: &TableFactor, local: &mut BTreeMap<String, BTreeSet<String>>| -> MddResult<()> {
            budget.visit(depth + 1)?;
            if let TableFactor::Table { name, alias, .. } = table
                && name.0.len() == 1
                && let Some(id) = name.0[0].as_ident()
            {
                let table_name = id.value.to_ascii_lowercase();
                if !ctes.contains(&table_name)
                    && let Some(columns) = schemas.get(&table_name)
                {
                    let alias_name = alias
                        .as_ref()
                        .map_or_else(|| table_name.clone(), |a| a.name.value.to_ascii_lowercase());
                    let mut normalized = BTreeSet::new();
                    for column in columns {
                        budget.visit(depth + 2)?;
                        normalized.insert(column.to_ascii_lowercase());
                    }
                    local.insert(alias_name, normalized);
                }
            }
            Ok(())
        };
    for table in &select.from {
        add_table(&table.relation, &mut local)?;
        for join in &table.joins {
            add_table(&join.relation, &mut local)?;
        }
    }
    let check = |e: &Expr| {
        nested_aggregate_needs_binding(e, schemas, ctes, depth + 1, budget, Some(&local))
    };
    let table_has_nested = |table: &TableFactor| -> MddResult<bool> {
        if let TableFactor::Derived { subquery, .. } = table {
            nested_query_needs_binding(subquery, schemas, ctes, depth + 1, budget)
        } else {
            Ok(false)
        }
    };
    for table in &select.from {
        if table_has_nested(&table.relation)? {
            return Ok(true);
        }
        for join in &table.joins {
            if table_has_nested(&join.relation)? {
                return Ok(true);
            }
            let constraint = match &join.join_operator {
                JoinOperator::Join(c)
                | JoinOperator::Inner(c)
                | JoinOperator::Left(c)
                | JoinOperator::LeftOuter(c)
                | JoinOperator::Right(c)
                | JoinOperator::RightOuter(c)
                | JoinOperator::FullOuter(c)
                | JoinOperator::CrossJoin(c) => c,
                _ => return Ok(true),
            };
            if let JoinConstraint::On(expr) = constraint
                && check(expr)?
            {
                return Ok(true);
            }
        }
    }
    for item in &select.projection {
        if let SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } = item
            && check(expr)?
        {
            return Ok(true);
        }
    }
    for expr in [&select.selection, &select.having].into_iter().flatten() {
        if check(expr)? {
            return Ok(true);
        }
    }
    if let GroupByExpr::Expressions(exprs, _) = &select.group_by {
        for expr in exprs {
            if check(expr)? {
                return Ok(true);
            }
        }
    }
    if let Some(order) = order_by
        && let OrderByKind::Expressions(exprs) = &order.kind
    {
        for value in exprs {
            if check(&value.expr)? {
                return Ok(true);
            }
        }
    }
    if let Some(limit_clause) = limit_clause {
        match limit_clause {
            LimitClause::LimitOffset { limit, offset, .. } => {
                if let Some(expr) = limit
                    && check(expr)?
                {
                    return Ok(true);
                }
                if let Some(offset) = offset
                    && check(&offset.value)?
                {
                    return Ok(true);
                }
            }
            LimitClause::OffsetCommaLimit { offset, limit } => {
                if check(offset)? || check(limit)? {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

// Admit only the directly observed form. Derived columns, CTEs and arbitrary
// expressions need their own affinity binding; they must not inherit this rule.
fn text_cast_string_literal(expr: &Expr) -> bool {
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

fn nonnegative_i64_literal(expr: &Expr) -> bool {
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
fn integer_cast_string_literal(expr: &Expr) -> bool {
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
fn text_cast_nonnegative_i64_literal(expr: &Expr) -> bool {
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
fn exact_i64_text_literal(expr: &Expr) -> Option<i64> {
    let Expr::Value(value) = expr else {
        return None;
    };
    let Value::SingleQuotedString(text) = &value.value else {
        return None;
    };
    exact_i64_text(text)
}

fn exact_i64_text(text: &str) -> Option<i64> {
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
fn exact_real_syntax_integer(text: &str) -> Option<i64> {
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
fn canonical_i64_text_literal(expr: &Expr) -> Option<i64> {
    let Expr::Value(value) = expr else {
        return None;
    };
    let Value::SingleQuotedString(text) = &value.value else {
        return None;
    };
    let value = exact_i64_text_literal(expr)?;
    (value.to_string() == *text).then_some(value)
}
fn replace_with_i64_literal(expr: &mut Expr, value: i64) {
    *expr = Expr::Value(Value::Number(value.to_string(), false).into());
}

// SQLite TEXT affinity renders an integer literal as canonical decimal text.
// Only accept syntactic integers that fit i64: real literals and integers
// beyond SQLite's signed range require a separately proven formatting rule.
fn exact_i64_numeric_literal(mut expr: &Expr) -> Option<i64> {
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
fn length_with_integer_between_bounds(
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
fn direct_text_integer_affinity(dialect: super::SqlDialect, left: &Expr, right: &Expr) -> bool {
    dialect != super::SqlDialect::NativeV1
        && ((text_cast_string_literal(left) && nonnegative_i64_literal(right))
            || (nonnegative_i64_literal(left) && text_cast_string_literal(right)))
}
// A deliberately narrow affinity source: a CTE with one directly cast text
// literal and no input relation. Unproved projections remain guarded.
fn single_literal_text_cte_column(cte: &Cte) -> Option<String> {
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
#[derive(Clone, Copy, Eq, PartialEq)]
enum InStorageClass {
    Numeric,
    Text,
    Bytes,
}

// Compound set operators execute inside SQLite, so they may only compare
// carrier representations known to agree with our logical equality. Bytes
// from a provider are not safe: Bytes and DexMutf8 share SqlType::Bytes but
// have different physical tags. F64 is not safe even within one type because
// +0 and -0 have distinct carriers but equal numeric keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompoundCarrier {
    Null,
    Integer,
    Unsigned,
    Text,
    LiteralBytes,
    Mixed(u8),
    Unknown,
}

fn merge_compound_carrier(a: CompoundCarrier, b: CompoundCarrier) -> CompoundCarrier {
    use CompoundCarrier::*;
    let mask = |value| match value {
        Null => Some(0),
        Integer => Some(1),
        Unsigned => Some(2),
        Text => Some(4),
        LiteralBytes => Some(8),
        Mixed(bits) => Some(bits),
        Unknown => None,
    };
    let Some(bits) = mask(a).zip(mask(b)).map(|(a, b)| a | b) else {
        return Unknown;
    };
    // INTEGER and U64 may be numerically equal despite different carriers.
    // The other admitted storage classes have disjoint physical tags and
    // are also distinct according to SQL's compound set equality.
    if bits & 3 == 3 {
        return Unknown;
    }
    match bits {
        0 => Null,
        1 => Integer,
        2 => Unsigned,
        4 => Text,
        8 => LiteralBytes,
        _ => Mixed(bits),
    }
}

// Only compare raw expressions whose complete structure is understood and
// contains no user placeholder. SQLite gives separate bare '?' occurrences
// distinct parameter indices, even if their supplied values happen to match.
fn stable_compound_order_expr(
    expr: &Expr,
    depth: usize,
    budget: &AggregateScan,
) -> MddResult<bool> {
    // Expr equality below is recursive; do not attempt it for a deep input.
    if depth > 64 {
        return Ok(false);
    }
    budget.visit(depth)?;
    let child = |expr: &Expr| stable_compound_order_expr(expr, depth + 1, budget);
    match expr {
        Expr::Value(value) => Ok(!matches!(
            value.value,
            Value::Placeholder(_) | Value::Boolean(_)
        )),
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => Ok(true),
        Expr::Nested(inner) => child(inner),
        Expr::UnaryOp { expr, .. } => child(expr),
        Expr::BinaryOp { left, right, .. } => Ok(child(left)? && child(right)?),
        Expr::Cast {
            expr, format: None, ..
        } => child(expr),
        Expr::Function(function)
            if function.over.is_none()
                && function.filter.is_none()
                && function.null_treatment.is_none()
                && function.within_group.is_empty()
                && matches!(function.parameters, FunctionArguments::None) =>
        {
            let FunctionArguments::List(arguments) = &function.args else {
                return Ok(false);
            };
            if !arguments.clauses.is_empty() {
                return Ok(false);
            }
            let count_wildcard = function.name.0.len() == 1
                && function.name.0[0]
                    .as_ident()
                    .is_some_and(|id| id.value.eq_ignore_ascii_case("count"))
                && arguments.duplicate_treatment.is_none()
                && arguments.args.len() == 1;
            for argument in &arguments.args {
                match argument {
                    FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) if child(expr)? => (),
                    FunctionArg::Unnamed(FunctionArgExpr::Wildcard) if count_wildcard => (),
                    _ => return Ok(false),
                }
            }
            Ok(true)
        }
        // Subqueries and other nontrivial forms retain the previous path until
        // their placeholder and scope behavior has separate proof.
        _ => Ok(false),
    }
}
// Match only the stable subset above. SQLite identifiers and function names
// are ASCII case-insensitive, while literal content and AST operators remain
// exact. No SQL text substitution or unproven source binding is performed.
fn same_compound_order_expr(
    mut left: &Expr,
    mut right: &Expr,
    mut depth: usize,
    budget: &AggregateScan,
) -> MddResult<bool> {
    while let Expr::Nested(inner) = left {
        if depth > 64 {
            return Ok(false);
        }
        budget.visit(depth)?;
        depth += 1;
        left = inner;
    }
    while let Expr::Nested(inner) = right {
        if depth > 64 {
            return Ok(false);
        }
        budget.visit(depth)?;
        depth += 1;
        right = inner;
    }
    if depth > 64 {
        return Ok(false);
    }
    budget.visit(depth)?;
    let child = |a: &Expr, b: &Expr| same_compound_order_expr(a, b, depth + 1, budget);
    match (left, right) {
        (Expr::Value(a), Expr::Value(b)) => Ok(a.value == b.value),
        (Expr::Identifier(a), Expr::Identifier(b)) => Ok(a.value.eq_ignore_ascii_case(&b.value)),
        (Expr::CompoundIdentifier(a), Expr::CompoundIdentifier(b)) => {
            if a.len() != b.len() {
                return Ok(false);
            }
            for (a, b) in a.iter().zip(b) {
                budget.visit(depth + 1)?;
                if !a.value.eq_ignore_ascii_case(&b.value) {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        (Expr::UnaryOp { op: a, expr: x }, Expr::UnaryOp { op: b, expr: y }) => {
            Ok(a == b && child(x, y)?)
        }
        (
            Expr::BinaryOp {
                left: a,
                op: x,
                right: b,
            },
            Expr::BinaryOp {
                left: c,
                op: y,
                right: d,
            },
        ) => Ok(x == y && child(a, c)? && child(b, d)?),
        (
            Expr::Cast {
                kind: a,
                expr: x,
                data_type: t,
                format: None,
            },
            Expr::Cast {
                kind: b,
                expr: y,
                data_type: u,
                format: None,
            },
        ) => Ok(a == b && t == u && child(x, y)?),
        (Expr::Function(a), Expr::Function(b)) => {
            if a.name.0.len() != b.name.0.len() || a.uses_odbc_syntax != b.uses_odbc_syntax {
                return Ok(false);
            }
            for (x, y) in a.name.0.iter().zip(&b.name.0) {
                budget.visit(depth + 1)?;
                let (Some(x), Some(y)) = (x.as_ident(), y.as_ident()) else {
                    return Ok(false);
                };
                if !x.value.eq_ignore_ascii_case(&y.value) {
                    return Ok(false);
                }
            }
            let (FunctionArguments::List(a), FunctionArguments::List(b)) = (&a.args, &b.args)
            else {
                return Ok(false);
            };
            if a.duplicate_treatment != b.duplicate_treatment || a.args.len() != b.args.len() {
                return Ok(false);
            }
            for (a, b) in a.args.iter().zip(&b.args) {
                match (a, b) {
                    (
                        FunctionArg::Unnamed(FunctionArgExpr::Expr(a)),
                        FunctionArg::Unnamed(FunctionArgExpr::Expr(b)),
                    ) if child(a, b)? => (),
                    (
                        FunctionArg::Unnamed(FunctionArgExpr::Wildcard),
                        FunctionArg::Unnamed(FunctionArgExpr::Wildcard),
                    ) => (),
                    _ => return Ok(false),
                }
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn literal_in_class(expr: &Expr) -> Option<Option<InStorageClass>> {
    match without_parentheses(expr) {
        Expr::UnaryOp {
            op: UnaryOperator::Plus | UnaryOperator::Minus,
            expr,
        } if matches!(&**expr, Expr::Value(value) if matches!(value.value, Value::Number(_, _))) => {
            Some(Some(InStorageClass::Numeric))
        }
        Expr::Value(value) => match &value.value {
            Value::Null => Some(None),
            Value::Number(_, _) | Value::Boolean(_) => Some(Some(InStorageClass::Numeric)),
            Value::SingleQuotedString(_) => Some(Some(InStorageClass::Text)),
            Value::HexStringLiteral(_) => Some(Some(InStorageClass::Bytes)),
            _ => None,
        },
        _ => None,
    }
}
fn call(name: &str, args: Vec<Expr>) -> Expr {
    Expr::Function(Function {
        name: ObjectName::from(vec![Ident::new(name)]),
        uses_odbc_syntax: false,
        parameters: FunctionArguments::None,
        args: FunctionArguments::List(FunctionArgumentList {
            duplicate_treatment: None,
            args: args
                .into_iter()
                .map(|arg| FunctionArg::Unnamed(FunctionArgExpr::Expr(arg)))
                .collect(),
            clauses: Vec::new(),
        }),
        within_group: Vec::new(),
        filter: None,
        null_treatment: None,
        over: None,
    })
}

pub(crate) fn adapt(
    sql: &str,
    limits: SqlLimits,
    parameters: &[SqlValue],
    relations: &[crate::provider::SqlRelation],
    dialect_policy: super::SqlDialect,
) -> MddResult<Adapted> {
    if sql.len() > limits.max_sql_bytes {
        return Err(quota("SQL_TEXT_BYTES"));
    }
    let dialect = SQLiteDialect {};
    let tokens = Tokenizer::new(&dialect, sql)
        .tokenize()
        .map_err(|e| invalid(&format!("SQL_TOKEN_ERROR: {e}")))?;
    if tokens.len() > limits.max_tokens || tokens.len() > limits.max_ast_nodes.saturating_mul(4) {
        return Err(quota("SQL_TOKEN_OR_NODE_PREFLIGHT"));
    }
    // A recursive parser limit alone does not bound left-associative BinaryOp
    // or UNION trees. Bound their input before any owned recursive AST exists.
    let mut nesting = 0usize;
    let mut operators = 0usize;
    for token in &tokens {
        match token {
            Token::LParen | Token::LBracket => {
                nesting += 1;
                if nesting > limits.max_ast_depth {
                    return Err(quota("SQL_LEXICAL_DEPTH"));
                }
            }
            Token::RParen | Token::RBracket => nesting = nesting.saturating_sub(1),
            Token::Whitespace(_)
            | Token::SingleQuotedString(_)
            | Token::DoubleQuotedString(_)
            | Token::Number(_, _) => (),
            Token::Word(word)
                if word.quote_style.is_none()
                    && matches!(
                        word.value.to_ascii_uppercase().as_str(),
                        "AND" | "OR" | "NOT" | "UNION" | "INTERSECT" | "EXCEPT" | "CASE"
                    ) =>
            {
                operators += 1
            }
            Token::Word(_) | Token::Comma | Token::Period | Token::SemiColon => (),
            _ => operators += 1,
        }
        if operators > limits.max_ast_operators {
            return Err(quota("SQL_FLAT_OPERATOR_BUDGET"));
        }
    }
    if limits.max_ast_depth == 0 || limits.max_ast_nodes == 0 {
        return Err(quota("SQL_AST_BUDGET"));
    }
    let mut statements = Parser::new(&dialect)
        .with_recursion_limit(limits.max_ast_depth)
        .try_with_sql(sql)
        .map_err(parse_error)?
        .parse_statements()
        .map_err(parse_error)?;
    if statements.len() != 1 {
        return Err(invalid("SQL_REQUIRES_ONE_STATEMENT"));
    }
    let Statement::Query(query) = &mut statements[0] else {
        return Err(invalid("SQL_STATEMENT_NOT_READ_ONLY_QUERY"));
    };
    let mut reserved = relations
        .iter()
        .flat_map(|r| {
            std::iter::once(r.name.to_ascii_lowercase())
                .chain(r.columns.iter().map(|c| c.name.to_ascii_lowercase()))
        })
        .collect::<BTreeSet<_>>();
    for token in &tokens {
        if let Token::Word(word) = token {
            reserved.insert(word.value.to_ascii_lowercase());
        }
    }
    let schemas = relations
        .iter()
        .map(|r| {
            (
                r.name.to_ascii_lowercase(),
                r.columns.iter().map(|c| c.name.clone()).collect(),
            )
        })
        .collect();
    let schema_types = relations
        .iter()
        .map(|r| {
            (
                r.name.to_ascii_lowercase(),
                r.columns
                    .iter()
                    .map(|c| (c.name.to_ascii_lowercase(), c.data_type))
                    .collect(),
            )
        })
        .collect();
    let mut rewrite = Rewrite {
        limits,
        aggregate_scan: AggregateScan {
            depth_limit: limits.max_ast_depth.saturating_mul(4).min(512),
            remaining: Cell::new(limits.max_ast_nodes.saturating_mul(4)),
        },
        parameters: Vec::new(),
        inputs: parameters,
        next_input: 0,
        nodes: 0,
        dependencies: Vec::new(),
        cte_scopes: Vec::new(),
        cte_names: BTreeSet::new(),
        in_scopes: Vec::new(),
        cte_definitions: Vec::new(),
        cte_direct_types: BTreeMap::new(),
        cte_literal_text_columns: BTreeMap::new(),
        cte_literal_text_scopes: Vec::new(),
        schemas,
        schema_types,
        cte_columns: BTreeMap::new(),
        reserved,
        next_symbol: 0,
        display_overrides: BTreeMap::new(),
        dialect: dialect_policy,
    };
    let dependencies = match rewrite.query(query, 1) {
        Ok(dependencies) => dependencies,
        Err(error)
            if error.details.get("confirm_sqlite_syntax")
                == Some(&serde_json::Value::Bool(true)) =>
        {
            // Only currently visible, already parsed CTE containers can be
            // considered by the read-only SQLite binding check on this path.
            let mut names = rewrite
                .cte_scopes
                .iter()
                .flat_map(|scope| scope.keys())
                .cloned()
                .collect::<BTreeSet<_>>();
            if let Some(additional) = error.details.get("visible_ctes").and_then(|v| v.as_array()) {
                names.extend(
                    additional
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_owned)),
                );
            }
            return Err(error.detail(
                "visible_ctes",
                names
                    .into_iter()
                    .map(serde_json::Value::from)
                    .collect::<Vec<_>>(),
            ));
        }
        Err(error) => return Err(error),
    };
    let required_relations = rewrite.resolve(&dependencies)?;
    if rewrite.next_input != parameters.len() {
        return Err(invalid("UNUSED_SQL_PARAMETERS"));
    }
    let Statement::Query(query) = &statements[0] else {
        return Err(invalid("INTERNAL_QUERY_KIND"));
    };
    let actual_nodes = validate_iterative(query, limits)?;
    let adapted = statements[0].to_string();
    if adapted.len() > limits.max_sql_bytes.saturating_mul(8) {
        return Err(quota("SQL_FORMATTED_BYTES"));
    }
    Ok(Adapted {
        sql: adapted,
        parameters: rewrite.parameters,
        nodes: actual_nodes,
        required_relations,
        cte_names: rewrite.cte_names,
        display_overrides: rewrite.display_overrides,
    })
}
struct Rewrite<'a> {
    limits: SqlLimits,
    // Shared across all nested queries and ordering expressions in one SQL
    // statement, including repeated projection aliases.
    aggregate_scan: AggregateScan,
    parameters: Vec<SqlValue>,
    inputs: &'a [SqlValue],
    next_input: usize,
    nodes: usize,
    dependencies: Vec<Dependency>,
    cte_scopes: Vec<BTreeMap<String, usize>>,
    cte_names: BTreeSet<String>,
    in_scopes: Vec<Option<InScope>>,
    cte_definitions: Vec<Vec<Dependency>>,
    // Only CTEs whose complete projection is direct typed columns from one
    // known base table are registered here. Unknown CTEs still shadow outer
    // sources and cannot be used to infer affinity.
    cte_direct_types: BTreeMap<usize, BTreeMap<String, crate::values::SqlType>>,
    cte_literal_text_columns: BTreeMap<usize, String>,
    cte_literal_text_scopes: Vec<Option<(String, String)>>,
    schemas: BTreeMap<String, Vec<String>>,
    schema_types: BTreeMap<String, BTreeMap<String, crate::values::SqlType>>,
    cte_columns: BTreeMap<usize, Vec<String>>,
    reserved: BTreeSet<String>,
    next_symbol: usize,
    display_overrides: BTreeMap<String, String>,
    dialect: super::SqlDialect,
}
struct InScope {
    tables: BTreeMap<String, BTreeMap<String, crate::values::SqlType>>,
    order_aliases: BTreeSet<String>,
    boolean_aliases: BTreeSet<String>,
    select_aliases: BTreeMap<String, Option<crate::values::SqlType>>,
    aliases_visible: bool,
}
impl Rewrite<'_> {
    fn single_cte_literal_text_scope(&self, select: &Select) -> Option<(String, String)> {
        if select.from.len() != 1 || !select.from[0].joins.is_empty() {
            return None;
        }
        let TableFactor::Table { name, alias, .. } = &select.from[0].relation else {
            return None;
        };
        if name.0.len() != 1
            || alias
                .as_ref()
                .is_some_and(|alias| !alias.columns.is_empty())
        {
            return None;
        }
        let name = name.0[0].as_ident()?.value.to_ascii_lowercase();
        let id = self
            .cte_scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(&name))?;
        let column = self.cte_literal_text_columns.get(id)?.clone();
        let qualifier = alias
            .as_ref()
            .map_or(name, |alias| alias.name.value.to_ascii_lowercase());
        Some((qualifier, column))
    }
    fn current_cte_literal_text_column(&self, expr: &Expr) -> bool {
        let Some(Some((qualifier, column))) = self.cte_literal_text_scopes.last() else {
            return false;
        };
        match without_parentheses(expr) {
            Expr::Identifier(id) => id.value.eq_ignore_ascii_case(column),
            Expr::CompoundIdentifier(ids) if ids.len() == 2 => {
                ids[0].value.eq_ignore_ascii_case(qualifier)
                    && ids[1].value.eq_ignore_ascii_case(column)
            }
            _ => false,
        }
    }
    fn base_in_scope(&self, select: &Select) -> Option<InScope> {
        let mut tables = BTreeMap::new();
        for from in &select.from {
            for factor in
                std::iter::once(&from.relation).chain(from.joins.iter().map(|join| &join.relation))
            {
                let TableFactor::Table { name, alias, .. } = factor else {
                    return None;
                };
                if name.0.len() != 1 || alias.as_ref().is_some_and(|a| !a.columns.is_empty()) {
                    return None;
                }
                let id = name.0[0].as_ident()?;
                let source_name = id.value.to_ascii_lowercase();
                // A visible CTE takes precedence over a same-named base table;
                // an unrelated WITH clause does not change this source's type.
                let cte = self
                    .cte_scopes
                    .iter()
                    .rev()
                    .find_map(|scope| scope.get(&source_name));
                let columns = match cte {
                    Some(id) => self.cte_direct_types.get(id)?.clone(),
                    None => self.schema_types.get(&source_name)?.clone(),
                };
                let qualifier = alias
                    .as_ref()
                    .map_or_else(|| id.value.clone(), |a| a.name.value.clone())
                    .to_ascii_lowercase();
                if tables.insert(qualifier, columns).is_some() {
                    return None;
                }
            }
        }
        let boolean_aliases = select
            .projection
            .iter()
            .filter_map(|item| match item {
                SelectItem::ExprWithAlias { alias, .. }
                    if alias.value.eq_ignore_ascii_case("true")
                        || alias.value.eq_ignore_ascii_case("false") =>
                {
                    Some(alias.value.to_ascii_lowercase())
                }
                _ => None,
            })
            .collect();
        let mut select_aliases = BTreeMap::new();
        for item in &select.projection {
            let SelectItem::ExprWithAlias { expr, alias } = item else {
                continue;
            };
            let mut expr = expr;
            while let Expr::Nested(inner) = expr {
                expr = inner;
            }
            let data_type = match expr {
                Expr::Identifier(id) => {
                    let name = id.value.to_ascii_lowercase();
                    let mut matches = tables.values().filter_map(|columns| columns.get(&name));
                    let first = matches.next().copied();
                    if matches.next().is_some() {
                        None
                    } else {
                        first
                    }
                }
                Expr::CompoundIdentifier(ids) if ids.len() == 2 => tables
                    .get(&ids[0].value.to_ascii_lowercase())
                    .and_then(|columns| columns.get(&ids[1].value.to_ascii_lowercase()))
                    .copied(),
                _ => None,
            };
            let name = alias.value.to_ascii_lowercase();
            match select_aliases.entry(name) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(data_type);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    entry.insert(None);
                }
            }
        }
        Some(InScope {
            tables,
            order_aliases: BTreeSet::new(),
            boolean_aliases,
            select_aliases,
            aliases_visible: false,
        })
    }

    fn compound_type_carrier(data_type: crate::values::SqlType) -> CompoundCarrier {
        use crate::values::SqlType;
        match data_type {
            SqlType::Bool | SqlType::I64 => CompoundCarrier::Integer,
            SqlType::U64 => CompoundCarrier::Unsigned,
            SqlType::Text => CompoundCarrier::Text,
            SqlType::F64 | SqlType::Bytes => CompoundCarrier::Unknown,
        }
    }

    // base_in_scope clones table type maps; charge their entries before that
    // clone so repeated set branches cannot multiply unmetered schema work.
    // String bytes and allocator overhead remain outside this logical bound.
    fn charge_compound_scope(&self, select: &Select, depth: usize) -> MddResult<()> {
        for from in &select.from {
            for factor in
                std::iter::once(&from.relation).chain(from.joins.iter().map(|join| &join.relation))
            {
                self.aggregate_scan.visit(depth)?;
                let TableFactor::Table { name, .. } = factor else {
                    continue;
                };
                let [part] = name.0.as_slice() else { continue };
                let Some(id) = part.as_ident() else { continue };
                let source = id.value.to_ascii_lowercase();
                let cte = self
                    .cte_scopes
                    .iter()
                    .rev()
                    .find_map(|scope| scope.get(&source));
                let columns = match cte {
                    Some(id) => self.cte_direct_types.get(id),
                    None => self.schema_types.get(&source),
                };
                if let Some(columns) = columns {
                    for _ in columns {
                        self.aggregate_scan.visit(depth + 1)?;
                    }
                }
            }
        }
        // base_in_scope also resolves each unqualified SELECT alias by
        // scanning the local tables. Charge that possible work before it runs.
        for item in &select.projection {
            if let SelectItem::ExprWithAlias { expr, .. } = item {
                self.aggregate_scan.visit(depth)?;
                let mut value = expr;
                let mut nested_depth = depth;
                while let Expr::Nested(inner) = value {
                    nested_depth = nested_depth
                        .checked_add(1)
                        .ok_or_else(|| quota("SQL_AGGREGATE_DETECTION_DEPTH"))?;
                    // Once for this preflight and once for base_in_scope's
                    // subsequent alias traversal.
                    self.aggregate_scan.visit(nested_depth)?;
                    self.aggregate_scan.visit(nested_depth)?;
                    value = inner;
                }
                if matches!(value, Expr::Identifier(_)) {
                    for from in &select.from {
                        for _ in std::iter::once(&from.relation)
                            .chain(from.joins.iter().map(|join| &join.relation))
                        {
                            self.aggregate_scan.visit(depth + 1)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn compound_expression_carrier(
        &self,
        expr: &Expr,
        scope: Option<&InScope>,
        depth: usize,
    ) -> MddResult<CompoundCarrier> {
        let expr = charged_compound_expression(expr, depth, &self.aggregate_scan)?;
        let value = match expr {
            Expr::Value(value) => match &value.value {
                Value::Null => CompoundCarrier::Null,
                Value::Number(number, _) if number.parse::<i64>().is_ok() => {
                    CompoundCarrier::Integer
                }
                Value::SingleQuotedString(_) => CompoundCarrier::Text,
                Value::HexStringLiteral(_) => CompoundCarrier::LiteralBytes,
                // TRUE/FALSE can resolve to a column; parameters and real
                // literals need their own proven carrier binding.
                _ => CompoundCarrier::Unknown,
            },
            Expr::UnaryOp { op, expr: inner }
                if matches!(op, UnaryOperator::Plus | UnaryOperator::Minus)
                    && (matches!(inner.as_ref(), Expr::Value(value)
                        if matches!(&value.value, Value::Number(number, _) if number.parse::<i64>().is_ok()))
                        || (self.dialect == super::SqlDialect::NativeV1
                            && matches!(op, UnaryOperator::Minus)
                            && exact_i64_numeric_literal(expr) == Some(i64::MIN))) =>
            {
                CompoundCarrier::Integer
            }
            Expr::Identifier(id) => {
                let Some(scope) = scope else {
                    return Ok(CompoundCarrier::Unknown);
                };
                let name = id.value.to_ascii_lowercase();
                let mut found = None;
                for columns in scope.tables.values() {
                    self.aggregate_scan.visit(depth + 1)?;
                    if let Some(value) = columns.get(&name) {
                        if found.is_some() {
                            return Ok(CompoundCarrier::Unknown);
                        }
                        found = Some(*value);
                    }
                }
                found.map_or(CompoundCarrier::Unknown, Self::compound_type_carrier)
            }
            Expr::CompoundIdentifier(ids) if ids.len() == 2 => scope
                .and_then(|scope| scope.tables.get(&ids[0].value.to_ascii_lowercase()))
                .and_then(|columns| columns.get(&ids[1].value.to_ascii_lowercase()))
                .copied()
                .map_or(CompoundCarrier::Unknown, Self::compound_type_carrier),
            Expr::Cast {
                data_type,
                format: None,
                ..
            } => match data_type {
                DataType::Text
                | DataType::Varchar(None)
                | DataType::Char(None)
                | DataType::Character(None) => CompoundCarrier::Text,
                DataType::Int(None)
                | DataType::Integer(None)
                | DataType::BigInt(None)
                | DataType::Int64
                | DataType::Boolean
                | DataType::Bool => CompoundCarrier::Integer,
                DataType::Unsigned | DataType::UnsignedInteger | DataType::BigIntUnsigned(None) => {
                    CompoundCarrier::Unsigned
                }
                DataType::Blob(None) | DataType::Binary(None) => CompoundCarrier::LiteralBytes,
                _ => CompoundCarrier::Unknown,
            },
            Expr::Function(function)
                if function.name.0.len() == 1
                    && function.name.0[0]
                        .as_ident()
                        .is_some_and(|id| id.value.eq_ignore_ascii_case("count"))
                    && function.over.is_none() =>
            {
                CompoundCarrier::Integer
            }
            Expr::Function(function)
                if function.name.0.len() == 1
                    && function.name.0[0]
                        .as_ident()
                        .is_some_and(|id| id.value.eq_ignore_ascii_case("length"))
                    && function.over.is_none()
                    && function.filter.is_none()
                    && matches!(&function.args, FunctionArguments::List(arguments)
                        if arguments.duplicate_treatment.is_none()
                        && arguments.clauses.is_empty()
                        && matches!(arguments.args.as_slice(), [FunctionArg::Unnamed(FunctionArgExpr::Expr(_))])) =>
            {
                CompoundCarrier::Integer
            }
            _ => CompoundCarrier::Unknown,
        };
        Ok(value)
    }

    fn compound_wildcard_carriers(
        &self,
        select: &Select,
        scope: Option<&InScope>,
        qualifier: Option<&ObjectName>,
        depth: usize,
    ) -> MddResult<Option<Vec<CompoundCarrier>>> {
        let Some(scope) = scope else { return Ok(None) };
        let [from] = select.from.as_slice() else {
            return Ok(None);
        };
        if !from.joins.is_empty() {
            return Ok(None);
        }
        let TableFactor::Table { name, alias, .. } = &from.relation else {
            return Ok(None);
        };
        let [part] = name.0.as_slice() else {
            return Ok(None);
        };
        let Some(id) = part.as_ident() else {
            return Ok(None);
        };
        let source = id.value.to_ascii_lowercase();
        let table = alias
            .as_ref()
            .map_or_else(|| source.clone(), |a| a.name.value.to_ascii_lowercase());
        if let Some(qualifier) = qualifier {
            let [part] = qualifier.0.as_slice() else {
                return Ok(None);
            };
            if part
                .as_ident()
                .is_none_or(|id| !id.value.eq_ignore_ascii_case(&table))
            {
                return Ok(None);
            }
        }
        let names = if let Some(id) = self.cte_scopes.iter().rev().find_map(|s| s.get(&source)) {
            self.cte_columns.get(id)
        } else {
            self.schemas.get(&source)
        };
        let (Some(names), Some(columns)) = (names, scope.tables.get(&table)) else {
            return Ok(None);
        };
        let mut result = Vec::new();
        for name in names {
            self.aggregate_scan.visit(depth)?;
            let Some(ty) = columns.get(&name.to_ascii_lowercase()).copied() else {
                return Ok(None);
            };
            result
                .try_reserve(1)
                .map_err(|_| quota("COMPOUND_CARRIER_ALLOCATION"))?;
            result.push(Self::compound_type_carrier(ty));
        }
        Ok(Some(result))
    }

    fn compound_carriers(
        &self,
        body: &SetExpr,
        depth: usize,
    ) -> MddResult<Option<Vec<CompoundCarrier>>> {
        self.aggregate_scan.visit(depth)?;
        match body {
            SetExpr::Select(select) => {
                self.charge_compound_scope(select, depth + 1)?;
                let scope = self.base_in_scope(select);
                let mut result = Vec::new();
                for item in &select.projection {
                    self.aggregate_scan.visit(depth + 1)?;
                    match item {
                        SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                            result
                                .try_reserve(1)
                                .map_err(|_| quota("COMPOUND_CARRIER_ALLOCATION"))?;
                            result.push(self.compound_expression_carrier(
                                expr,
                                scope.as_ref(),
                                depth + 2,
                            )?)
                        }
                        SelectItem::Wildcard(options)
                            if *options == WildcardAdditionalOptions::default() =>
                        {
                            let Some(values) = self.compound_wildcard_carriers(
                                select,
                                scope.as_ref(),
                                None,
                                depth + 2,
                            )?
                            else {
                                return Ok(None);
                            };
                            result
                                .try_reserve(values.len())
                                .map_err(|_| quota("COMPOUND_CARRIER_ALLOCATION"))?;
                            result.extend(values);
                        }
                        SelectItem::QualifiedWildcard(
                            SelectItemQualifiedWildcardKind::ObjectName(name),
                            options,
                        ) if *options == WildcardAdditionalOptions::default() => {
                            let Some(values) = self.compound_wildcard_carriers(
                                select,
                                scope.as_ref(),
                                Some(name),
                                depth + 2,
                            )?
                            else {
                                return Ok(None);
                            };
                            result
                                .try_reserve(values.len())
                                .map_err(|_| quota("COMPOUND_CARRIER_ALLOCATION"))?;
                            result.extend(values);
                        }
                        _ => return Ok(None),
                    }
                }
                Ok(Some(result))
            }
            SetExpr::Query(query) if query.with.is_none() => {
                self.compound_carriers(&query.body, depth + 1)
            }
            SetExpr::SetOperation { left, right, .. } => {
                let (Some(mut left), Some(right)) = (
                    self.compound_carriers(left, depth + 1)?,
                    self.compound_carriers(right, depth + 1)?,
                ) else {
                    return Ok(None);
                };
                if left.len() != right.len() {
                    return Ok(None);
                }
                for (a, b) in left.iter_mut().zip(right) {
                    *a = merge_compound_carrier(*a, b);
                }
                Ok(Some(left))
            }
            SetExpr::Values(values) => {
                let mut result: Option<Vec<CompoundCarrier>> = None;
                for row in &values.rows {
                    let mut current = Vec::new();
                    for value in row.iter() {
                        current
                            .try_reserve(1)
                            .map_err(|_| quota("COMPOUND_CARRIER_ALLOCATION"))?;
                        current.push(self.compound_expression_carrier(value, None, depth + 1)?);
                    }
                    result = match result {
                        None => Some(current),
                        Some(mut previous) if previous.len() == current.len() => {
                            for (a, b) in previous.iter_mut().zip(current) {
                                *a = merge_compound_carrier(*a, b);
                            }
                            Some(previous)
                        }
                        Some(_) => return Ok(None),
                    };
                }
                Ok(result)
            }
            _ => Ok(None),
        }
    }

    fn compound_order_matches(
        &self,
        body: &SetExpr,
        order: &Expr,
        stable_order: bool,
        depth: usize,
        found: &mut Option<usize>,
    ) -> MddResult<()> {
        if found.is_some() {
            return Ok(());
        }
        self.aggregate_scan.visit(depth)?;
        match body {
            SetExpr::Select(select) => {
                if select.projection.iter().any(|item| {
                    !matches!(
                        item,
                        SelectItem::UnnamedExpr(_) | SelectItem::ExprWithAlias { .. }
                    )
                }) {
                    match self.compound_single_wildcard_order(select, order, depth + 1)? {
                        Some(position) => {
                            *found = position;
                            return Ok(());
                        }
                        None => {
                            return Err(unsupported("COMPOUND_ORDER_WILDCARD_BINDING")
                                .detail("confirm_sqlite_syntax", true)
                                .detail("validate_bare_parameters", true));
                        }
                    }
                }
                // SQLite searches SELECT arms left to right. Within each arm,
                // an explicit alias wins before expression matching.
                if let Some(identifier) = order_identifier(order) {
                    for (index, item) in select.projection.iter().enumerate() {
                        self.aggregate_scan.visit(depth + 1)?;
                        if let SelectItem::ExprWithAlias { alias, .. } = item
                            && alias.value.eq_ignore_ascii_case(&identifier.value)
                        {
                            *found = Some(index);
                            return Ok(());
                        }
                    }
                }
                if stable_order {
                    for (index, item) in select.projection.iter().enumerate() {
                        self.aggregate_scan.visit(depth + 1)?;
                        let expr = match item {
                            SelectItem::UnnamedExpr(expr)
                            | SelectItem::ExprWithAlias { expr, .. } => expr,
                            _ => return Ok(()),
                        };
                        if stable_compound_order_expr(expr, depth + 1, &self.aggregate_scan)?
                            && (same_compound_order_expr(
                                expr,
                                order,
                                depth + 1,
                                &self.aggregate_scan,
                            )? || self.compound_same_direct_column(
                                select,
                                expr,
                                order,
                                depth + 1,
                            )?)
                        {
                            *found = Some(index);
                            return Ok(());
                        }
                    }
                }
            }
            SetExpr::Query(query) => {
                self.compound_order_matches(&query.body, order, stable_order, depth + 1, found)?
            }
            SetExpr::SetOperation { left, right, .. } => {
                self.compound_order_matches(left, order, stable_order, depth + 1, found)?;
                self.compound_order_matches(right, order, stable_order, depth + 1, found)?;
            }
            _ => (),
        }
        Ok(())
    }

    // A bare column and its qualified form are equal only if both bind to
    // the same column of one directly known table in this SELECT arm.
    fn compound_same_direct_column(
        &self,
        select: &Select,
        left: &Expr,
        right: &Expr,
        depth: usize,
    ) -> MddResult<bool> {
        self.aggregate_scan.visit(depth)?;
        let (bare, ids) = match (without_parentheses(left), without_parentheses(right)) {
            (Expr::Identifier(bare), Expr::CompoundIdentifier(ids))
            | (Expr::CompoundIdentifier(ids), Expr::Identifier(bare))
                if ids.len() == 2 =>
            {
                (bare, ids)
            }
            _ => return Ok(false),
        };
        if !bare.value.eq_ignore_ascii_case(&ids[1].value) {
            return Ok(false);
        }
        let [from] = select.from.as_slice() else {
            return Ok(false);
        };
        if !from.joins.is_empty() {
            return Ok(false);
        }
        let TableFactor::Table { name, alias, .. } = &from.relation else {
            return Ok(false);
        };
        if alias
            .as_ref()
            .is_some_and(|alias| !alias.columns.is_empty())
        {
            return Ok(false);
        }
        let [part] = name.0.as_slice() else {
            return Ok(false);
        };
        let Some(id) = part.as_ident() else {
            return Ok(false);
        };
        let source = id.value.to_ascii_lowercase();
        let table = alias
            .as_ref()
            .map_or_else(|| source.clone(), |a| a.name.value.to_ascii_lowercase());
        if !ids[0].value.eq_ignore_ascii_case(&table) {
            return Ok(false);
        }
        let cte = self
            .cte_scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(&source));
        let columns = match cte {
            Some(id) => self.cte_direct_types.get(id),
            None => self.schema_types.get(&source),
        };
        Ok(columns.is_some_and(|columns| columns.contains_key(&bare.value.to_ascii_lowercase())))
    }

    // Only expand a sole wildcard over one known base table or direct CTE.
    // Other wildcard scopes may contain an earlier match at an unknown
    // ordinal, so they must not be skipped in favor of a later SELECT arm.
    fn compound_single_wildcard_order(
        &self,
        select: &Select,
        order: &Expr,
        depth: usize,
    ) -> MddResult<Option<Option<usize>>> {
        self.aggregate_scan.visit(depth)?;
        let [projection] = select.projection.as_slice() else {
            return Ok(None);
        };
        let qualifier = match projection {
            SelectItem::Wildcard(options) if *options == WildcardAdditionalOptions::default() => {
                None
            }
            SelectItem::QualifiedWildcard(
                SelectItemQualifiedWildcardKind::ObjectName(name),
                options,
            ) if *options == WildcardAdditionalOptions::default() => Some(name),
            _ => return Ok(None),
        };
        let [from] = select.from.as_slice() else {
            return Ok(None);
        };
        if !from.joins.is_empty() {
            return Ok(None);
        }
        let TableFactor::Table { name, alias, .. } = &from.relation else {
            return Ok(None);
        };
        if alias
            .as_ref()
            .is_some_and(|alias| !alias.columns.is_empty())
        {
            return Ok(None);
        }
        let [part] = name.0.as_slice() else {
            return Ok(None);
        };
        let Some(id) = part.as_ident() else {
            return Ok(None);
        };
        let source = id.value.to_ascii_lowercase();
        let table = alias
            .as_ref()
            .map_or_else(|| source.clone(), |a| a.name.value.to_ascii_lowercase());
        if let Some(qualifier) = qualifier {
            let [part] = qualifier.0.as_slice() else {
                return Ok(None);
            };
            if part
                .as_ident()
                .is_none_or(|id| !id.value.eq_ignore_ascii_case(&table))
            {
                return Ok(None);
            }
        }
        let names = if let Some(id) = self.cte_scopes.iter().rev().find_map(|s| s.get(&source)) {
            let (Some(names), Some(types)) =
                (self.cte_columns.get(id), self.cte_direct_types.get(id))
            else {
                return Ok(None);
            };
            if names.len() != types.len() {
                return Ok(None);
            }
            Some(names)
        } else {
            self.schemas.get(&source)
        };
        let Some(names) = names else { return Ok(None) };
        let column = match without_parentheses(order) {
            Expr::Identifier(id) => Some(id.value.as_str()),
            Expr::CompoundIdentifier(ids)
                if ids.len() == 2 && ids[0].value.eq_ignore_ascii_case(&table) =>
            {
                Some(ids[1].value.as_str())
            }
            _ => None,
        };
        for (index, name) in names.iter().enumerate() {
            self.aggregate_scan.visit(depth + 1)?;
            if column.is_some_and(|column| name.eq_ignore_ascii_case(column)) {
                return Ok(Some(Some(index)));
            }
        }
        Ok(Some(None))
    }

    fn original_compound_order_positions(
        &self,
        body: &SetExpr,
        order: Option<&OrderBy>,
    ) -> MddResult<Vec<Option<usize>>> {
        let Some(OrderBy {
            kind: OrderByKind::Expressions(expressions),
            ..
        }) = order
        else {
            return Ok(Vec::new());
        };
        let mut positions = Vec::new();
        for item in expressions {
            positions
                .try_reserve(1)
                .map_err(|_| quota("COMPOUND_ORDER_PROOF_ALLOCATION"))?;
            if positional_ordinal(&item.expr)?.is_some() {
                positions.push(None);
                continue;
            }
            let stable = stable_compound_order_expr(&item.expr, 0, &self.aggregate_scan)?;
            let mut found = None;
            self.compound_order_matches(body, &item.expr, stable, 0, &mut found)?;
            positions.push(found);
        }
        Ok(positions)
    }

    // Register only a direct projection from one non-CTE physical relation.
    // Aliased columns are positional; duplicate output names are ambiguous.
    fn direct_cte_column_types(
        &self,
        cte: &Cte,
    ) -> Option<BTreeMap<String, crate::values::SqlType>> {
        if cte.query.with.is_some()
            || cte.query.order_by.is_some()
            || cte.query.limit_clause.is_some()
        {
            return None;
        }
        let SetExpr::Select(select) = cte.query.body.as_ref() else {
            return None;
        };
        if select.from.len() != 1
            || !select.from[0].joins.is_empty()
            || select.distinct.is_some()
            || select.having.is_some()
            || !matches!(&select.group_by, GroupByExpr::Expressions(values, modifiers)
                if values.is_empty() && modifiers.is_empty())
            || select.projection.is_empty()
        {
            return None;
        }
        let TableFactor::Table { name, .. } = &select.from[0].relation else {
            return None;
        };
        if name.0.len() != 1 {
            return None;
        }
        let source_name = name.0[0].as_ident()?.value.to_ascii_lowercase();
        if self
            .cte_scopes
            .iter()
            .rev()
            .any(|frame| frame.contains_key(&source_name))
        {
            return None;
        }
        let scope = self.base_in_scope(select)?;
        if scope.tables.len() != 1 {
            return None;
        }
        if !cte.alias.columns.is_empty() && cte.alias.columns.len() != select.projection.len() {
            return None;
        }
        let mut output = BTreeMap::new();
        for (ordinal, projection) in select.projection.iter().enumerate() {
            let (expr, name) = match projection {
                SelectItem::UnnamedExpr(Expr::Identifier(id)) => {
                    (Expr::Identifier(id.clone()), id.value.clone())
                }
                SelectItem::UnnamedExpr(Expr::CompoundIdentifier(ids)) if ids.len() == 2 => (
                    Expr::CompoundIdentifier(ids.clone()),
                    ids.last()?.value.clone(),
                ),
                SelectItem::ExprWithAlias { expr, alias } => (expr.clone(), alias.value.clone()),
                _ => return None,
            };
            let mut original = &expr;
            while let Expr::Nested(inner) = original {
                original = inner;
            }
            let value = match original {
                Expr::Identifier(id) => scope
                    .tables
                    .values()
                    .next()?
                    .get(&id.value.to_ascii_lowercase())?,
                Expr::CompoundIdentifier(ids) if ids.len() == 2 => scope
                    .tables
                    .get(&ids[0].value.to_ascii_lowercase())?
                    .get(&ids[1].value.to_ascii_lowercase())?,
                _ => return None,
            };
            let name = cte
                .alias
                .columns
                .get(ordinal)
                .map_or(name, |column| column.name.value.clone())
                .to_ascii_lowercase();
            if output.insert(name, *value).is_some() {
                return None;
            }
        }
        Some(output)
    }
    fn in_column_type(&self, left: &Expr) -> Option<crate::values::SqlType> {
        // Never infer a column type from a global same-name schema. Derived
        // tables and CTEs may shadow a name with different affinity.
        let mut left = left;
        while let Expr::Nested(inner) = left {
            left = inner;
        }
        for frame in self.in_scopes.iter().rev() {
            // Unknown derived/CTE scope may shadow any outer column. Do not infer past it.
            let scope = frame.as_ref()?;
            // A SELECT without FROM can still have output aliases that shadow
            // an unqualified identifier. A qualified table.column cannot bind
            // such an alias, so it can safely continue into the outer scope.
            if scope.tables.is_empty()
                && !matches!(left, Expr::CompoundIdentifier(ids) if ids.len() == 2)
            {
                return None;
            }
            match left {
                Expr::Identifier(id) => {
                    let name = id.value.to_ascii_lowercase();
                    // In a compound ORDER BY expression SQLite can resolve a
                    // bare identifier to a SELECT alias before a table column.
                    // Alias expression type is not proven by this scope map.
                    if scope.order_aliases.contains(&name) {
                        return None;
                    }
                    let mut matches = scope
                        .tables
                        .values()
                        .filter_map(|columns| columns.get(&name));
                    if let Some(data_type) = matches.next() {
                        // A nearer scope with ambiguous names never resolves to an outer one.
                        return if matches.next().is_none() {
                            Some(*data_type)
                        } else {
                            None
                        };
                    }
                    // SQLite can bind an otherwise unresolved WHERE name to
                    // this SELECT's output alias before an outer column.
                    // Alias expression affinity is not proven by this map.
                    if scope.aliases_visible
                        && let Some(data_type) = scope.select_aliases.get(&name)
                    {
                        return *data_type;
                    }
                }
                Expr::CompoundIdentifier(ids) if ids.len() == 2 => {
                    let qualifier = ids[0].value.to_ascii_lowercase();
                    if let Some(columns) = scope.tables.get(&qualifier) {
                        // An inner alias shadows the outer alias even if its column is absent.
                        return columns.get(&ids[1].value.to_ascii_lowercase()).copied();
                    }
                }
                _ => return None,
            }
        }
        None
    }

    /// Only a direct column from a single known base table is currently
    /// admitted. No derived/CTE schema or expression affinity is inferred.
    fn direct_subquery_column_type(&self, query: &Query) -> Option<crate::values::SqlType> {
        if query.with.is_some() {
            return None;
        }
        let SetExpr::Select(select) = query.body.as_ref() else {
            return None;
        };
        if select.from.len() != 1
            || !select.from[0].joins.is_empty()
            || select.having.is_some()
            || (select.distinct.is_some()
                && (!matches!(&select.distinct, Some(Distinct::Distinct))
                    || (query.limit_clause.is_some()
                        && !Self::ordered_distinct_direct_column(query, select))))
            || !matches!(&select.group_by, GroupByExpr::Expressions(values, modifiers)
                if values.is_empty() && modifiers.is_empty())
            || select.projection.len() != 1
        {
            return None;
        }
        let scope = self.base_in_scope(select)?;
        if scope.tables.len() != 1 {
            return None;
        }
        let mut expr = match &select.projection[0] {
            SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => expr,
            _ => return None,
        };
        while let Expr::Nested(inner) = expr {
            expr = inner;
        }
        match expr {
            Expr::Identifier(id) => scope
                .tables
                .values()
                .next()?
                .get(&id.value.to_ascii_lowercase())
                .copied(),
            Expr::CompoundIdentifier(ids) if ids.len() == 2 => scope
                .tables
                .get(&ids[0].value.to_ascii_lowercase())?
                .get(&ids[1].value.to_ascii_lowercase())
                .copied(),
            _ => None,
        }
    }

    /// LIMIT/OFFSET after DISTINCT is admissible only when a single ORDER BY
    /// term selects the same direct projection. This proves deterministic
    /// pagination over unique keys; unrelated ordering could change membership.
    fn ordered_distinct_direct_column(query: &Query, select: &Select) -> bool {
        if select.projection.len() != 1 {
            return false;
        }
        let (projection, alias) = match &select.projection[0] {
            SelectItem::UnnamedExpr(expr) => (expr, None),
            SelectItem::ExprWithAlias { expr, alias } => (expr, Some(alias)),
            _ => return false,
        };
        let mut projection = projection;
        while let Expr::Nested(inner) = projection {
            projection = inner;
        }
        if !matches!(
            projection,
            Expr::Identifier(_) | Expr::CompoundIdentifier(_)
        ) {
            return false;
        }
        let Some(order) = query.order_by.as_ref() else {
            return false;
        };
        if order.interpolate.is_some() {
            return false;
        }
        let OrderByKind::Expressions(expressions) = &order.kind else {
            return false;
        };
        if expressions.len() != 1 {
            return false;
        }
        let term = &expressions[0];
        if term.with_fill.is_some() || matches!(term.options.sort, Some(OrderBySort::Using(_))) {
            return false;
        }
        let mut expression = &term.expr;
        while let Expr::Nested(inner) = expression {
            expression = inner;
        }
        if let Expr::Value(value) = expression
            && matches!(&value.value, Value::Number(number, _) if number == "1")
        {
            return true;
        }
        if let Expr::Identifier(id) = expression
            && alias.is_some_and(|alias| alias.value.eq_ignore_ascii_case(&id.value))
        {
            return true;
        }
        expression == projection
    }
    fn safe_in_affinity(&self, left: &Expr, list: &[Expr]) -> bool {
        if list.is_empty() || no_affinity(left) {
            return true;
        }
        let Some(data_type) = self.in_column_type(left) else {
            return false;
        };
        let class = match data_type {
            crate::values::SqlType::Bool
            | crate::values::SqlType::I64
            | crate::values::SqlType::U64
            | crate::values::SqlType::F64 => InStorageClass::Numeric,
            crate::values::SqlType::Text => InStorageClass::Text,
            crate::values::SqlType::Bytes => InStorageClass::Bytes,
        };
        list.iter().all(|item| match literal_in_class(item) {
            Some(None) => true,
            Some(Some(candidate)) => candidate == class,
            None => false,
        })
    }
    fn legacy_numeric_in_literals(&self, left: &Expr, list: &mut [Expr]) -> bool {
        if self.dialect == super::SqlDialect::NativeV1
            || !(matches!(
                self.in_column_type(left),
                Some(crate::values::SqlType::I64 | crate::values::SqlType::U64)
            ) || integer_cast_string_literal(left))
        {
            return false;
        }
        let values: Option<Vec<Option<i64>>> = list
            .iter()
            .map(|item| {
                if let Some(value) = exact_i64_text_literal(item) {
                    Some(Some(value))
                } else if matches!(
                    literal_in_class(item),
                    Some(None) | Some(Some(InStorageClass::Numeric))
                ) {
                    Some(None)
                } else {
                    None
                }
            })
            .collect();
        let Some(values) = values else { return false };
        if !values.iter().any(Option::is_some) {
            return false;
        }
        for (item, value) in list.iter_mut().zip(values) {
            if let Some(value) = value {
                replace_with_i64_literal(item, value);
            }
        }
        true
    }
    // SQLite can resolve TRUE/FALSE as a same-named input column or SELECT
    // alias. Unknown inner scopes may shadow outer sources as well. Never
    // convert such a token to a constant until its binding is proven.
    fn boolean_token_shadowed(&self, value: bool) -> bool {
        let name = if value { "true" } else { "false" };
        self.in_scopes.iter().rev().any(|frame| match frame {
            None => true,
            Some(scope) => {
                scope.order_aliases.contains(name)
                    || scope.boolean_aliases.contains(name)
                    || scope
                        .tables
                        .values()
                        .any(|columns| columns.contains_key(name))
            }
        })
    }

    fn legacy_text_in_literals(&self, left: &Expr, list: &mut [Expr]) -> bool {
        if self.dialect == super::SqlDialect::NativeV1
            || self.in_column_type(left) != Some(crate::values::SqlType::Text)
        {
            return false;
        }
        if list.iter().any(|expr| {
            let mut expr = expr;
            while let Expr::Nested(inner) = expr {
                expr = inner;
            }
            matches!(expr, Expr::Value(value) if matches!(value.value, Value::Boolean(value) if self.boolean_token_shadowed(value)))
        }) {
            return false;
        }
        let values: Option<Vec<Option<i64>>> = list
            .iter()
            .map(|item| {
                if let Some(value) = exact_i64_numeric_literal(item) {
                    Some(Some(value))
                } else if matches!(
                    literal_in_class(item),
                    Some(None) | Some(Some(InStorageClass::Text))
                ) {
                    Some(None)
                } else {
                    None
                }
            })
            .collect();
        let Some(values) = values else { return false };
        if !values.iter().any(Option::is_some) {
            return false;
        }
        for (item, value) in list.iter_mut().zip(values) {
            if let Some(value) = value {
                *item = Expr::Value(Value::SingleQuotedString(value.to_string()).into());
            }
        }
        true
    }
    fn visit(&mut self, depth: usize) -> MddResult<()> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or_else(|| quota("SQL_AST_NODES"))?;
        if depth > self.limits.max_ast_depth || self.nodes > self.limits.max_ast_nodes {
            return Err(quota("SQL_AST_NODE_OR_DEPTH"));
        }
        Ok(())
    }
    fn bind(&mut self, value: SqlValue) -> MddResult<Expr> {
        if value.byte_size() > self.limits.max_cell_bytes {
            return Err(quota("SQL_LITERAL_CELL_BYTES"));
        }
        self.parameters.push(value);
        Ok(Expr::Value(
            Value::Placeholder(format!("?{}", self.parameters.len())).into(),
        ))
    }
    // SQLite applies an exact integer conversion to LIMIT/OFFSET values.
    // Our lossless text, float and unsigned carriers are BLOBs, which SQLite
    // would otherwise reject even for values such as '2' or 2.0. Convert only
    // directly supplied values whose integer representation is proven exact.
    fn limit_expr(&mut self, expr: &mut Expr, depth: usize) -> MddResult<()> {
        if let Expr::Nested(child) = expr {
            self.visit(depth)?;
            return self.limit_expr(child, depth + 1);
        }
        let mut parameter = false;
        let mut unary_child = false;
        let integer = match expr {
            Expr::Value(value) => match &value.value {
                Value::SingleQuotedString(text) => {
                    if text.encode_utf16().count() as u64 > self.limits.max_cell_bytes / 2 {
                        return Err(quota("SQL_LITERAL_UTF16_BEFORE_ALLOCATION"));
                    }
                    exact_i64_text(text)
                }
                Value::Number(number, _) => exact_real_syntax_integer(number),
                Value::Placeholder(name) if name == "?" => {
                    let value = self
                        .inputs
                        .get(self.next_input)
                        .ok_or_else(|| invalid("UNBOUND_SQL_PARAMETER"))?;
                    if value.byte_size() > self.limits.max_cell_bytes {
                        return Err(quota("SQL_PARAMETER_BEFORE_CLONE"));
                    }
                    parameter = true;
                    match value {
                        SqlValue::U64(value) => i64::try_from(value.0).ok(),
                        SqlValue::F64(bits) => {
                            let number = f64::from_bits(bits.0);
                            if number.is_finite()
                                && number.fract() == 0.0
                                && number >= i64::MIN as f64
                                && number < -(i64::MIN as f64)
                            {
                                Some(number as i64)
                            } else {
                                None
                            }
                        }
                        SqlValue::Text(text) if text.utf16.iter().all(|unit| *unit <= 0x7f) => {
                            let ascii: String = text
                                .utf16
                                .iter()
                                .map(|unit| char::from(*unit as u8))
                                .collect();
                            exact_i64_text(&ascii)
                        }
                        _ => None,
                    }
                }
                _ => None,
            },
            Expr::UnaryOp { op, expr: child }
                if matches!(op, UnaryOperator::Plus | UnaryOperator::Minus) =>
            {
                let Expr::Value(value) = child.as_ref() else {
                    return self.expr(expr, depth);
                };
                let Value::Number(number, _) = &value.value else {
                    return self.expr(expr, depth);
                };
                unary_child = true;
                let value = exact_real_syntax_integer(number);
                if matches!(op, UnaryOperator::Minus) {
                    value.and_then(i64::checked_neg)
                } else {
                    value
                }
            }
            _ => None,
        };
        if let Some(integer) = integer {
            self.visit(depth)?;
            if unary_child {
                self.visit(depth + 1)?;
            }
            if parameter {
                self.next_input += 1;
            }
            *expr = self.bind(SqlValue::I64(Signed64(integer)))?;
            return Ok(());
        }
        self.expr(expr, depth)
    }
    fn fresh(&mut self) -> String {
        loop {
            let symbol = format!("__mdd_internal_{}", self.next_symbol);
            self.next_symbol += 1;
            if self.reserved.insert(symbol.clone()) {
                return symbol;
            }
        }
    }
    fn query(&mut self, query: &mut Query, depth: usize) -> MddResult<Vec<Dependency>> {
        self.visit(depth)?;
        let outer = std::mem::take(&mut self.dependencies);
        let had_with = query.with.is_some();
        if !query.locks.is_empty()
            || query.fetch.is_some()
            || query.for_clause.is_some()
            || query.settings.is_some()
            || query.format_clause.is_some()
            || !query.pipe_operators.is_empty()
        {
            return Err(unsupported("QUERY_EXTENSION_NOT_IMPLEMENTED"));
        }
        if let Some(with) = &mut query.with {
            if with.recursive {
                return Err(unsupported("RECURSIVE_CTE_NOT_YET_QUALIFIED"));
            }
            let mut frame = BTreeMap::new();
            for cte in &with.cte_tables {
                let id = self.cte_definitions.len();
                self.cte_definitions.push(Vec::new());
                self.cte_names
                    .insert(cte.alias.name.value.to_ascii_lowercase());
                if frame
                    .insert(cte.alias.name.value.to_ascii_lowercase(), id)
                    .is_some()
                {
                    return Err(invalid("DUPLICATE_CTE_NAME"));
                }
            }
            self.cte_scopes.push(frame);
            for cte in &mut with.cte_tables {
                if cte.from.is_some() {
                    return Err(unsupported("CTE_FROM_EXTENSION"));
                }
                let id =
                    self.cte_scopes.last().unwrap()[&cte.alias.name.value.to_ascii_lowercase()];
                let literal_text_column = single_literal_text_cte_column(cte);
                let direct_types = self.direct_cte_column_types(cte);
                self.cte_definitions[id] = self.query(&mut cte.query, depth + 1)?;
                if let Some(columns) = direct_types {
                    self.cte_direct_types.insert(id, columns);
                }
                if let Some(column) = literal_text_column {
                    self.cte_literal_text_columns.insert(id, column);
                }
                if let Ok(names) = self.output_names(&cte.query.body) {
                    self.cte_columns.insert(
                        id,
                        if cte.alias.columns.is_empty() {
                            names
                        } else {
                            cte.alias
                                .columns
                                .iter()
                                .map(|c| c.name.value.clone())
                                .collect()
                        },
                    );
                }
            }
        }
        // ORDER BY is rewritten after body() pops the SELECT frame. Recreate
        // that exact frame from the unmodified SELECT so an inner scope cannot
        // accidentally bind a same-named outer column. Compound and derived
        // scopes remain unknown rather than exposing an outer source.
        let (mut order_scope, order_cte_scope) = match query.body.as_ref() {
            SetExpr::Select(select) => {
                let mut scope = self.base_in_scope(select);
                let aliases: BTreeSet<_> = select
                    .projection
                    .iter()
                    .filter_map(|item| {
                        match item {
                            SelectItem::ExprWithAlias { alias, .. } => {
                                Some(alias.value.to_ascii_lowercase())
                            }
                            // SQLite also exposes the expression's generated
                            // output name as an ORDER BY identifier. A simple
                            // column projection has the same binding/type.
                            SelectItem::UnnamedExpr(expr)
                                if !matches!(
                                    expr,
                                    Expr::Identifier(_) | Expr::CompoundIdentifier(_)
                                ) =>
                            {
                                Some(expr.to_string().to_ascii_lowercase())
                            }
                            _ => None,
                        }
                    })
                    .collect();
                if let Some(scope) = &mut scope {
                    scope.order_aliases = aliases.clone();
                }
                let cte_scope = if aliases.is_empty() {
                    self.single_cte_literal_text_scope(select)
                } else {
                    None
                };
                (scope, cte_scope)
            }
            _ => (None, None),
        };
        let compound_positions = if matches!(*query.body, SetExpr::SetOperation { .. }) {
            self.original_compound_order_positions(&query.body, query.order_by.as_ref())?
        } else {
            Vec::new()
        };
        let was_distinct =
            matches!(query.body.as_ref(), SetExpr::Select(select) if select.distinct.is_some());
        self.body(&mut query.body, depth + 1)?;
        let synthetic_distinct_group = was_distinct
            && matches!(query.body.as_ref(),
            SetExpr::Select(select) if matches!(&select.group_by, GroupByExpr::Expressions(values, _) if !values.is_empty()));
        if let Some(order) = &mut query.order_by {
            self.in_scopes.push(order_scope.take());
            self.cte_literal_text_scopes.push(order_cte_scope);
            if order.interpolate.is_some() {
                return Err(unsupported("ORDER_INTERPOLATE"));
            }
            let OrderByKind::Expressions(expressions) = &mut order.kind else {
                return Err(unsupported("ORDER_BY_ALL"));
            };
            for (order_index, order) in expressions.iter_mut().enumerate() {
                if order.with_fill.is_some() {
                    return Err(unsupported("ORDER_WITH_FILL"));
                }
                if !matches!(*query.body, SetExpr::SetOperation { .. }) {
                    if let Some(ordinal) = positional_ordinal(&order.expr)? {
                        order.expr = self.projection_at(&query.body, ordinal)?;
                    } else if let Some(id) = order_identifier(&order.expr)
                        && let Some(index) = self
                            .output_names(&query.body)?
                            .iter()
                            .position(|name| name.eq_ignore_ascii_case(&id.value))
                    {
                        // SQLite resolves a bare ORDER BY name against the
                        // projection before input columns. Once wrapped inside
                        // mdd_sort_key, SQLite would instead bind a conflicting
                        // input column; substitute the bound projection here.
                        order.expr = self.projection_at(&query.body, index)?;
                    } else {
                        self.expr(&mut order.expr, depth + 1)?;
                    }
                    if synthetic_distinct_group
                        && (current_aggregate(&order.expr, 0, &self.aggregate_scan)?
                            || nested_aggregate_needs_binding(
                                &order.expr,
                                &self.schemas,
                                &self.cte_names,
                                0,
                                &self.aggregate_scan,
                                None,
                            )?)
                    {
                        return Err(unsupported("DISTINCT_ORDER_AGGREGATE_BINDING")
                            .detail("confirm_sqlite_syntax", true));
                    }
                    order.expr = call("mdd_sort_key", vec![take(&mut order.expr)]);
                } else if let Some(Some(position)) = compound_positions.get(order_index) {
                    // Check the original expression and its AST budget first.
                    // Proof excludes input placeholders; literals rewritten
                    // only for this discarded expression must not leave
                    // orphan SQLite parameter slots.
                    let parameter_start = self.parameters.len();
                    let input_start = self.next_input;
                    self.expr(&mut order.expr, depth + 1)?;
                    if self.next_input != input_start {
                        return Err(invalid("INTERNAL_COMPOUND_ORDER_INPUT_CHANGED"));
                    }
                    self.parameters.truncate(parameter_start);
                    let ordinal = position
                        .checked_add(1)
                        .ok_or_else(|| quota("COMPOUND_ORDER_ORDINAL"))?;
                    order.expr = Expr::Value(Value::Number(ordinal.to_string(), false).into());
                } else if positional_ordinal(&order.expr)?.is_none() {
                    self.expr(&mut order.expr, depth + 1)?;
                }
            }
            self.cte_literal_text_scopes.pop();
            self.in_scopes.pop();
        }
        if let Some(limit) = &mut query.limit_clause {
            match limit {
                LimitClause::LimitOffset {
                    limit,
                    offset,
                    limit_by,
                } => {
                    if !limit_by.is_empty() {
                        return Err(unsupported("LIMIT_BY"));
                    }
                    if let Some(limit) = limit {
                        self.limit_expr(limit, depth + 1)?;
                    }
                    if let Some(offset) = offset {
                        self.limit_expr(&mut offset.value, depth + 1)?;
                    }
                }
                LimitClause::OffsetCommaLimit { offset, limit } => {
                    self.limit_expr(offset, depth + 1)?;
                    self.limit_expr(limit, depth + 1)?;
                }
            }
        }
        if matches!(*query.body, SetExpr::SetOperation { .. }) && query.order_by.is_some() {
            self.compound_order(query)?;
        }
        if had_with {
            self.cte_scopes.pop();
        }
        let dependencies = std::mem::replace(&mut self.dependencies, outer);
        Ok(dependencies)
    }
    fn body(&mut self, body: &mut SetExpr, depth: usize) -> MddResult<()> {
        self.visit(depth)?;
        match body {
            SetExpr::Select(select) => {
                if select.into.is_some() {
                    return Err(invalid("SELECT_INTO_FORBIDDEN"));
                }
                if !select.optimizer_hints.is_empty()
                    || select.select_modifiers.is_some()
                    || select.top.is_some()
                    || select.exclude.is_some()
                    || !select.lateral_views.is_empty()
                    || select.prewhere.is_some()
                    || !select.connect_by.is_empty()
                    || !select.cluster_by.is_empty()
                    || !select.distribute_by.is_empty()
                    || !select.sort_by.is_empty()
                    || !select.named_window.is_empty()
                    || select.qualify.is_some()
                    || select.value_table_mode.is_some()
                {
                    return Err(unsupported("SELECT_EXTENSION_NOT_IMPLEMENTED"));
                }
                let in_scope = self.base_in_scope(select);
                self.in_scopes.push(in_scope);
                let literal_text_scope = self.single_cte_literal_text_scope(select);
                self.cte_literal_text_scopes.push(literal_text_scope);
                for table in &mut select.from {
                    self.table(&mut table.relation, depth + 1)?;
                    for (join_index, join) in table.joins.iter_mut().enumerate() {
                        self.table(&mut join.relation, depth + 1)?;
                        let using_allowed = matches!(
                            join.join_operator,
                            JoinOperator::Join(_)
                                | JoinOperator::Inner(_)
                                | JoinOperator::Left(_)
                                | JoinOperator::LeftOuter(_)
                        );
                        let constraint = match &mut join.join_operator {
                            JoinOperator::Join(c)
                            | JoinOperator::Inner(c)
                            | JoinOperator::Left(c)
                            | JoinOperator::LeftOuter(c)
                            | JoinOperator::Right(c)
                            | JoinOperator::RightOuter(c)
                            | JoinOperator::FullOuter(c)
                            | JoinOperator::CrossJoin(c) => c,
                            _ => return Err(unsupported("JOIN_KIND_NOT_IMPLEMENTED")),
                        };
                        match constraint {
                            JoinConstraint::On(expr) => {
                                // SQLite permits this SELECT's output aliases
                                // in JOIN ON after real source columns have
                                // been considered. Restrict alias inference to
                                // the ON expression, not the table source.
                                if let Some(Some(scope)) = self.in_scopes.last_mut() {
                                    scope.aliases_visible = true;
                                }
                                self.expr(expr, depth + 1)?;
                                if let Some(Some(scope)) = self.in_scopes.last_mut() {
                                    scope.aliases_visible = false;
                                }
                                *expr = call("mdd_truth_input", vec![take(expr)]);
                            }
                            JoinConstraint::Using(columns) => {
                                if join_index != 0 || !using_allowed {
                                    return Err(unsupported("JOIN_USING_COMPLEX_SCOPE"));
                                }
                                self.check_using(&table.relation, &join.relation, columns)?;
                            }
                            JoinConstraint::None => (),
                            JoinConstraint::Natural => {
                                return Err(unsupported("NATURAL_JOIN_NEEDS_TYPED_BINDING"));
                            }
                        }
                    }
                }
                for projection in &mut select.projection {
                    match projection {
                        SelectItem::UnnamedExpr(expr) => {
                            let display = match &*expr {
                                Expr::Identifier(id) => id.value.clone(),
                                Expr::CompoundIdentifier(ids) => ids.last().unwrap().value.clone(),
                                // The frozen reference engine names an unaliased
                                // call after the function and every other
                                // unaliased expression `column`; SQLite then
                                // numbers repeats (`column`, `column:1`) wherever
                                // names must be unique. The native dialect keeps
                                // SQLite's own expression-text names.
                                Expr::Function(function)
                                    if self.dialect != super::SqlDialect::NativeV1 =>
                                {
                                    function
                                        .name
                                        .0
                                        .last()
                                        .and_then(|part| part.as_ident())
                                        .map_or_else(
                                            || "column".to_owned(),
                                            |ident| ident.value.to_ascii_lowercase(),
                                        )
                                }
                                _ if self.dialect != super::SqlDialect::NativeV1 => {
                                    "column".to_owned()
                                }
                                expr => expr.to_string(),
                            };
                            self.expr(expr, depth + 1)?;
                            let name = if display.contains('\0') {
                                let name = self.fresh();
                                self.display_overrides.insert(name.clone(), display);
                                name
                            } else {
                                display
                            };
                            *projection = SelectItem::ExprWithAlias {
                                expr: take(expr),
                                alias: Ident::with_quote('"', name),
                            };
                        }
                        SelectItem::ExprWithAlias { expr, .. } => self.expr(expr, depth + 1)?,
                        SelectItem::Wildcard(options)
                            if *options == WildcardAdditionalOptions::default() => {}
                        SelectItem::QualifiedWildcard(
                            SelectItemQualifiedWildcardKind::ObjectName(_),
                            options,
                        ) if *options == WildcardAdditionalOptions::default() => (),
                        _ => return Err(unsupported("SELECT_WILDCARD_EXTENSION")),
                    }
                }
                // SQLite accepts SELECT aliases in WHERE/HAVING/GROUP BY.
                // They are not visible to sibling projection expressions.
                if let Some(Some(scope)) = self.in_scopes.last_mut() {
                    scope.aliases_visible = true;
                }
                if let Some(selection) = &mut select.selection {
                    self.expr(selection, depth + 1)?;
                    *selection = call("mdd_truth_input", vec![take(selection)]);
                }
                if let Some(having) = &mut select.having {
                    self.expr(having, depth + 1)?;
                    *having = call("mdd_truth_input", vec![take(having)]);
                }
                let mut grouping = match std::mem::replace(
                    &mut select.group_by,
                    GroupByExpr::Expressions(Vec::new(), Vec::new()),
                ) {
                    GroupByExpr::Expressions(expressions, modifiers) => {
                        if !modifiers.is_empty() {
                            return Err(unsupported("GROUP_BY_MODIFIER"));
                        }
                        expressions
                    }
                    GroupByExpr::All(_) => return Err(unsupported("GROUP_BY_ALL")),
                };
                for expr in &mut grouping {
                    if let Some(ordinal) = positional_ordinal(expr)? {
                        *expr = self.select_projection_at(select, ordinal)?;
                    } else {
                        self.expr(expr, depth + 1)?;
                    }
                    *expr = call("mdd_key", vec![take(expr)]);
                }
                if let Some(Some(scope)) = self.in_scopes.last_mut() {
                    scope.aliases_visible = false;
                }
                if let Some(distinct) = &select.distinct {
                    if !matches!(distinct, Distinct::Distinct) {
                        return Err(unsupported("DISTINCT_ON"));
                    }
                    if !grouping.is_empty() {
                        return Err(unsupported("DISTINCT_AFTER_GROUP_REQUIRES_OUTER_SCOPE"));
                    }
                    // A same-level aggregate without GROUP BY yields at most
                    // one row, including when HAVING removes that row. DISTINCT
                    // is redundant. A nested SELECT's aggregate does not count.
                    let mut aggregate = false;
                    for item in &select.projection {
                        if let SelectItem::UnnamedExpr(expr)
                        | SelectItem::ExprWithAlias { expr, .. } = item
                            && current_aggregate(expr, 0, &self.aggregate_scan)?
                        {
                            aggregate = true;
                            break;
                        }
                    }
                    if let Some(selection) = &select.selection
                        && nested_aggregate_needs_binding(
                            selection,
                            &self.schemas,
                            &self.cte_names,
                            0,
                            &self.aggregate_scan,
                            None,
                        )?
                    {
                        return Err(unsupported("DISTINCT_CORRELATED_AGGREGATE_BINDING")
                            .detail("confirm_sqlite_syntax", true));
                    }
                    if !aggregate && select.having.is_some() {
                        return Err(unsupported("DISTINCT_AFTER_GROUP_REQUIRES_OUTER_SCOPE")
                            .detail("confirm_sqlite_syntax", true));
                    }
                    if !aggregate {
                        for item in &select.projection {
                            if let SelectItem::UnnamedExpr(expr)
                            | SelectItem::ExprWithAlias { expr, .. } = item
                                && nested_aggregate_needs_binding(
                                    expr,
                                    &self.schemas,
                                    &self.cte_names,
                                    0,
                                    &self.aggregate_scan,
                                    None,
                                )?
                            {
                                return Err(unsupported("DISTINCT_CORRELATED_AGGREGATE_BINDING")
                                    .detail("confirm_sqlite_syntax", true));
                            }
                        }
                        let expressions = self.select_expressions(select)?;
                        grouping = expressions
                            .into_iter()
                            .map(|expr| call("mdd_key", vec![expr]))
                            .collect();
                    }
                    select.distinct = None;
                }
                select.group_by = GroupByExpr::Expressions(grouping, Vec::new());
                self.in_scopes.pop();
                self.cte_literal_text_scopes.pop();
            }
            SetExpr::Query(query) => {
                let dependencies = self.query(query, depth + 1)?;
                self.dependencies.extend(dependencies);
            }
            SetExpr::SetOperation {
                left,
                right,
                op,
                set_quantifier,
            } => {
                // SQLite performs UNION/INTERSECT/EXCEPT equality on the raw
                // SQLite carriers. Numeric and byte carriers can differ even
                // when our logical SQL comparison says equal. Only admit a
                // set operation when each output column has a proven shared
                // equality-preserving carrier. UNION ALL does not deduplicate.
                let union_all = *op == SetOperator::Union && *set_quantifier == SetQuantifier::All;
                if !union_all {
                    let left_types = self.compound_carriers(left, depth + 1)?;
                    let right_types = self.compound_carriers(right, depth + 1)?;
                    let proven = matches!((&left_types, &right_types), (Some(left), Some(right))
                        if left.len() == right.len() && left.iter().zip(right).all(|(&a, &b)|
                            a != CompoundCarrier::Unknown && b != CompoundCarrier::Unknown
                            && merge_compound_carrier(a, b) != CompoundCarrier::Unknown));
                    if !proven {
                        return Err(unsupported("COMPOUND_SET_CARRIER_NOT_PROVEN")
                            .detail("confirm_sqlite_syntax", true)
                            .detail("validate_bare_parameters", true));
                    }
                }
                self.body(left, depth + 1)?;
                self.body(right, depth + 1)?;
            }
            SetExpr::Values(values) => {
                for row in &mut values.rows {
                    for expr in row.iter_mut() {
                        self.expr(expr, depth + 1)?;
                    }
                }
            }
            SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Delete(_) | SetExpr::Merge(_) => {
                return Err(invalid("DML_IN_QUERY_FORBIDDEN"));
            }
            _ => return Err(unsupported("QUERY_BODY_NOT_IMPLEMENTED")),
        }
        Ok(())
    }
    fn table(&mut self, table: &mut TableFactor, depth: usize) -> MddResult<()> {
        self.visit(depth)?;
        match table {
            TableFactor::Table {
                name,
                args,
                with_hints,
                version,
                with_ordinality,
                partitions,
                json_path,
                sample,
                index_hints,
                ..
            } => {
                if args.is_some()
                    || !with_hints.is_empty()
                    || version.is_some()
                    || *with_ordinality
                    || !partitions.is_empty()
                    || json_path.is_some()
                    || sample.is_some()
                    || !index_hints.is_empty()
                {
                    return Err(unsupported("TABLE_EXTENSION_NOT_IMPLEMENTED"));
                }
                if name.0.len() != 1 {
                    return Err(unsupported("DATABASE_QUALIFIED_RELATION_NOT_AVAILABLE"));
                }
                let name = name.0[0]
                    .as_ident()
                    .ok_or_else(|| unsupported("NON_IDENTIFIER_RELATION"))?
                    .value
                    .to_ascii_lowercase();
                if let Some(id) = self
                    .cte_scopes
                    .iter()
                    .rev()
                    .find_map(|scope| scope.get(&name))
                {
                    self.dependencies.push(Dependency::Cte(*id));
                } else {
                    self.dependencies.push(Dependency::Base(name));
                }
            }
            TableFactor::Derived {
                lateral,
                subquery,
                sample,
                alias,
            } => {
                if *lateral || sample.is_some() {
                    return Err(unsupported("LATERAL_OR_TABLE_SAMPLE"));
                }
                let dependencies = self.query(subquery, depth + 1)?;
                self.dependencies.extend(dependencies);
                if alias.is_none() {
                    *alias = Some(TableAlias {
                        name: Ident::with_quote('"', self.fresh()),
                        columns: Vec::new(),
                        explicit: true,
                        at: None,
                    });
                }
            }
            _ => return Err(unsupported("TABLE_FUNCTION_NOT_AVAILABLE")),
        }
        Ok(())
    }
    fn expr(&mut self, expr: &mut Expr, depth: usize) -> MddResult<()> {
        self.visit(depth)?;
        match expr {
            Expr::Identifier(_) | Expr::CompoundIdentifier(_) => return Ok(()),
            Expr::Value(value) => {
                let value = match &value.value {
                    Value::Null => return Ok(()),
                    Value::Boolean(value) => {
                        if self.boolean_token_shadowed(*value) {
                            return Err(unsupported("BOOLEAN_TOKEN_BINDING_NOT_PROVEN")
                                .detail("confirm_sqlite_syntax", true));
                        }
                        SqlValue::Bool(*value)
                    }
                    Value::SingleQuotedString(value) => {
                        if value.encode_utf16().count() as u64 > self.limits.max_cell_bytes / 2 {
                            return Err(quota("SQL_LITERAL_UTF16_BEFORE_ALLOCATION"));
                        }
                        SqlValue::text(value)
                    }
                    Value::Number(number, _) => {
                        if let Ok(value) = number.parse::<i64>() {
                            SqlValue::I64(Signed64(value))
                        } else if let Ok(value) = number.parse::<u64>() {
                            if self.dialect == super::SqlDialect::NativeV1 {
                                SqlValue::U64(DecimalU64(value))
                            } else {
                                SqlValue::F64(DecimalU64((value as f64).to_bits()))
                            }
                        } else {
                            if self.dialect == super::SqlDialect::NativeV1
                                && !number.contains(['.', 'e', 'E'])
                            {
                                return Err(invalid("INTEGER_LITERAL_OUT_OF_RANGE"));
                            }
                            SqlValue::F64(DecimalU64(
                                number
                                    .parse::<f64>()
                                    .map_err(|_| invalid("BAD_NUMERIC_LITERAL"))?
                                    .to_bits(),
                            ))
                        }
                    }
                    Value::HexStringLiteral(hex) => {
                        if !hex.len().is_multiple_of(2) {
                            return Err(invalid("ODD_HEX_LITERAL"));
                        }
                        if hex.len() as u64 / 2 > self.limits.max_cell_bytes {
                            return Err(quota("SQL_HEX_LITERAL_BEFORE_ALLOCATION"));
                        }
                        let bytes = (0..hex.len())
                            .step_by(2)
                            .map(|i| {
                                u8::from_str_radix(&hex[i..i + 2], 16)
                                    .map_err(|_| invalid("BAD_HEX_LITERAL"))
                            })
                            .collect::<MddResult<Vec<_>>>()?;
                        SqlValue::Bytes(bytes)
                    }
                    Value::Placeholder(name) => {
                        if name != "?" {
                            return Err(invalid("ONLY_POSITIONAL_BARE_PARAMETERS_SUPPORTED"));
                        }
                        let value = self
                            .inputs
                            .get(self.next_input)
                            .ok_or_else(|| invalid("UNBOUND_SQL_PARAMETER"))?;
                        if value.byte_size() > self.limits.max_cell_bytes {
                            return Err(quota("SQL_PARAMETER_BEFORE_CLONE"));
                        }
                        let value = value.clone();
                        self.next_input += 1;
                        value
                    }
                    _ => return Err(unsupported("LITERAL_KIND_NOT_IMPLEMENTED")),
                };
                *expr = self.bind(value)?;
                return Ok(());
            }
            Expr::Nested(child) | Expr::IsNull(child) | Expr::IsNotNull(child) => {
                self.expr(child, depth + 1)?
            }
            Expr::IsTrue(child) | Expr::IsNotTrue(child) => {
                if self.boolean_token_shadowed(true) {
                    return Err(unsupported("BOOLEAN_TOKEN_BINDING_NOT_PROVEN")
                        .detail("confirm_sqlite_syntax", true));
                }
                self.expr(child, depth + 1)?;
                **child = call("mdd_truth_input", vec![take(child)]);
            }
            Expr::IsFalse(child) | Expr::IsNotFalse(child) => {
                if self.boolean_token_shadowed(false) {
                    return Err(unsupported("BOOLEAN_TOKEN_BINDING_NOT_PROVEN")
                        .detail("confirm_sqlite_syntax", true));
                }
                self.expr(child, depth + 1)?;
                **child = call("mdd_truth_input", vec![take(child)]);
            }
            Expr::UnaryOp { expr: child, op } => {
                self.expr(child, depth + 1)?;
                let name = match op {
                    UnaryOperator::Minus => Some("mdd_neg"),
                    UnaryOperator::Plus => Some("mdd_pos"),
                    UnaryOperator::Not => {
                        **child = call("mdd_truth_input", vec![take(child)]);
                        None
                    }
                    _ => return Err(unsupported("UNARY_OPERATOR")),
                };
                if let Some(name) = name {
                    let child = take(child);
                    *expr = call(name, vec![child]);
                }
                return Ok(());
            }
            Expr::BinaryOp { left, op, right } => {
                // A direct numeric column supplies SQLite NUMERIC affinity to
                // a text literal on the opposite side. Reuse the restricted
                // exact conversion admitted by IN/BETWEEN; expressions,
                // non-integral or unproven numeric text keep their existing
                // guarded comparator behavior.
                if self.dialect != super::SqlDialect::NativeV1
                    && matches!(
                        op,
                        BinaryOperator::Eq
                            | BinaryOperator::NotEq
                            | BinaryOperator::Gt
                            | BinaryOperator::GtEq
                            | BinaryOperator::Lt
                            | BinaryOperator::LtEq
                    )
                {
                    if matches!(
                        self.in_column_type(left),
                        Some(crate::values::SqlType::I64 | crate::values::SqlType::U64)
                    ) {
                        if let Some(value) = exact_i64_text_literal(right) {
                            replace_with_i64_literal(right, value);
                        }
                    } else if matches!(
                        self.in_column_type(right),
                        Some(crate::values::SqlType::I64 | crate::values::SqlType::U64)
                    ) && let Some(value) = exact_i64_text_literal(left)
                    {
                        replace_with_i64_literal(left, value);
                    }
                }
                // Parameters and literal values have no SQLite affinity.
                // A column, CAST or derived expression cannot be assumed to
                // share this property; those retain the guarded comparator.
                let no_affinity = no_affinity(left) && no_affinity(right);
                let text_integer_affinity = direct_text_integer_affinity(self.dialect, left, right)
                    || (self.dialect != super::SqlDialect::NativeV1
                        && ((self.current_cte_literal_text_column(left)
                            && nonnegative_i64_literal(right))
                            || (nonnegative_i64_literal(left)
                                && self.current_cte_literal_text_column(right))));
                let numeric_cast_text_equality = self.dialect != super::SqlDialect::NativeV1
                    && matches!(op, BinaryOperator::Eq)
                    && ((text_cast_nonnegative_i64_literal(left)
                        && nonnegative_i64_literal(right))
                        || (nonnegative_i64_literal(left)
                            && text_cast_nonnegative_i64_literal(right)));
                if self.dialect != super::SqlDialect::NativeV1
                    && matches!(op, BinaryOperator::Eq | BinaryOperator::NotEq)
                {
                    if integer_cast_string_literal(left) {
                        if let Some(value) = canonical_i64_text_literal(right) {
                            replace_with_i64_literal(right, value);
                        }
                    } else if integer_cast_string_literal(right)
                        && let Some(value) = canonical_i64_text_literal(left)
                    {
                        replace_with_i64_literal(left, value);
                    }
                }
                self.expr(left, depth + 1)?;
                self.expr(right, depth + 1)?;
                let name = match op {
                    BinaryOperator::Eq if text_integer_affinity || numeric_cast_text_equality => {
                        "mdd_text_integer_eq"
                    }
                    BinaryOperator::NotEq if text_integer_affinity => "mdd_text_integer_ne",
                    BinaryOperator::Gt if text_integer_affinity => "mdd_text_integer_gt",
                    BinaryOperator::GtEq if text_integer_affinity => "mdd_text_integer_ge",
                    BinaryOperator::Lt if text_integer_affinity => "mdd_text_integer_lt",
                    BinaryOperator::LtEq if text_integer_affinity => "mdd_text_integer_le",
                    BinaryOperator::Eq if no_affinity => "mdd_literal_eq",
                    BinaryOperator::NotEq if no_affinity => "mdd_literal_ne",
                    BinaryOperator::Gt if no_affinity => "mdd_literal_gt",
                    BinaryOperator::GtEq if no_affinity => "mdd_literal_ge",
                    BinaryOperator::Lt if no_affinity => "mdd_literal_lt",
                    BinaryOperator::LtEq if no_affinity => "mdd_literal_le",
                    BinaryOperator::Eq => "mdd_eq",
                    BinaryOperator::NotEq => "mdd_ne",
                    BinaryOperator::Gt => "mdd_gt",
                    BinaryOperator::GtEq => "mdd_ge",
                    BinaryOperator::Lt => "mdd_lt",
                    BinaryOperator::LtEq => "mdd_le",
                    BinaryOperator::StringConcat => "mdd_concat",
                    BinaryOperator::Plus => "mdd_add",
                    BinaryOperator::Minus => "mdd_sub",
                    BinaryOperator::Multiply => "mdd_mul",
                    BinaryOperator::Divide => "mdd_div",
                    BinaryOperator::Modulo => "mdd_mod",
                    BinaryOperator::And | BinaryOperator::Or => {
                        **left = call("mdd_truth_input", vec![take(left)]);
                        **right = call("mdd_truth_input", vec![take(right)]);
                        return Ok(());
                    }
                    _ => return Err(unsupported("BINARY_OPERATOR_NOT_IMPLEMENTED")),
                };
                let left = take(left);
                let right = take(right);
                *expr = call(name, vec![left, right]);
                return Ok(());
            }
            Expr::Like {
                negated,
                any,
                expr: value,
                pattern,
                escape_char,
            } => {
                if *any {
                    return Err(unsupported("LIKE_ANY"));
                }
                self.expr(value, depth + 1)?;
                self.expr(pattern, depth + 1)?;
                if let Some(escape) = escape_char {
                    self.expr(escape, depth + 1)?;
                }
                // A literal TRUE/FALSE token can resolve to a same-named SQL
                // column. This is an internal flag, so bind it as a parameter.
                let has_escape = self.bind(SqlValue::Bool(escape_char.is_some()))?;
                let function = call(
                    "mdd_like",
                    vec![
                        take(value),
                        take(pattern),
                        escape_char.as_mut().map_or_else(null, |v| take(v)),
                        has_escape,
                    ],
                );
                *expr = if *negated {
                    Expr::UnaryOp {
                        op: UnaryOperator::Not,
                        expr: Box::new(function),
                    }
                } else {
                    function
                };
                return Ok(());
            }
            Expr::Cast {
                expr: child,
                data_type,
                format,
                ..
            } => {
                if format.is_some() {
                    return Err(unsupported("CAST_FORMAT"));
                }
                self.expr(child, depth + 1)?;
                let target = match data_type {
                    DataType::Text
                    | DataType::Varchar(None)
                    | DataType::Char(None)
                    | DataType::Character(None) => "text",
                    DataType::Blob(None) | DataType::Binary(None) => "bytes",
                    DataType::Int(None)
                    | DataType::Integer(None)
                    | DataType::BigInt(None)
                    | DataType::Int64 => "i64",
                    DataType::Unsigned
                    | DataType::UnsignedInteger
                    | DataType::BigIntUnsigned(None) => "u64",
                    DataType::Real | DataType::Float64 | DataType::DoublePrecision => "f64",
                    DataType::Boolean | DataType::Bool => "bool",
                    _ => return Err(unsupported("CAST_TARGET_NOT_IMPLEMENTED")),
                };
                let target = self.bind(SqlValue::text(target))?;
                *expr = call("mdd_cast", vec![take(child), target]);
                return Ok(());
            }
            Expr::InList {
                expr: child, list, ..
            } => {
                if !self.safe_in_affinity(child, list)
                    && !self.legacy_numeric_in_literals(child, list)
                    && !self.legacy_text_in_literals(child, list)
                {
                    return Err(unsupported("IN_LEFT_AFFINITY_NOT_IMPLEMENTED")
                        .detail("confirm_sqlite_syntax", true));
                }
                self.expr(child, depth + 1)?;
                **child = call("mdd_key", vec![take(child)]);
                for value in list {
                    self.expr(value, depth + 1)?;
                    *value = call("mdd_key", vec![take(value)]);
                }
            }
            Expr::Between {
                expr: child,
                low,
                high,
                negated,
            } => {
                // length() and the admitted signed literal bounds are SQLite
                // INTEGERs (or NULL), so native BETWEEN preserves their order,
                // evaluates length() once and retains SQLite short circuiting.
                let single_length = length_with_integer_between_bounds(
                    child,
                    low,
                    high,
                    self.limits.max_ast_depth.saturating_sub(depth),
                );
                // The declared numeric column supplies affinity to each bound
                // independently. Limit legacy conversion to the same exact
                // decimal forms admitted by the existing numeric IN path.
                // The value is a direct column, so its later duplication does
                // not introduce an additional effectful evaluation.
                if self.dialect != super::SqlDialect::NativeV1
                    && matches!(
                        self.in_column_type(child),
                        Some(crate::values::SqlType::I64 | crate::values::SqlType::U64)
                    )
                {
                    for bound in [&mut *low, &mut *high] {
                        if let Some(value) = exact_i64_text_literal(bound) {
                            replace_with_i64_literal(bound, value);
                        }
                    }
                }
                let low_no_affinity = no_affinity(child) && no_affinity(low);
                let high_no_affinity = no_affinity(child) && no_affinity(high);
                let low_text_integer = direct_text_integer_affinity(self.dialect, child, low);
                let high_text_integer = direct_text_integer_affinity(self.dialect, child, high);
                self.expr(child, depth + 1)?;
                if single_length {
                    for bound in [&mut *low, &mut *high] {
                        let integer = exact_i64_numeric_literal(bound);
                        let parameter = self.parameters.len();
                        // Walk the original expression first so nested nodes
                        // and depth remain accounted for before normalizing.
                        self.expr(bound, depth + 1)?;
                        if let Some(integer) = integer {
                            if self.parameters.len() != parameter + 1 {
                                return Err(invalid("INTERNAL_BETWEEN_INTEGER_PARAMETER"));
                            }
                            self.parameters[parameter] = SqlValue::I64(Signed64(integer));
                            **bound = Expr::Value(
                                Value::Placeholder(format!("?{}", parameter + 1)).into(),
                            );
                        }
                    }
                    return Ok(());
                }
                self.expr(low, depth + 1)?;
                self.expr(high, depth + 1)?;
                // Repeating a value expression is safe only for this deterministic
                // admitted expression subset. Volatile functions are rejected.
                let value = take(child);
                let lower = call(
                    if low_text_integer {
                        "mdd_text_integer_ge"
                    } else if low_no_affinity {
                        "mdd_literal_ge"
                    } else {
                        "mdd_ge"
                    },
                    vec![value.clone(), take(low)],
                );
                let upper = call(
                    if high_text_integer {
                        "mdd_text_integer_le"
                    } else if high_no_affinity {
                        "mdd_literal_le"
                    } else {
                        "mdd_le"
                    },
                    vec![value, take(high)],
                );
                let both = Expr::BinaryOp {
                    left: Box::new(lower),
                    op: BinaryOperator::And,
                    right: Box::new(upper),
                };
                *expr = if *negated {
                    Expr::UnaryOp {
                        op: UnaryOperator::Not,
                        expr: Box::new(Expr::Nested(Box::new(both))),
                    }
                } else {
                    both
                };
                return Ok(());
            }
            Expr::Case {
                operand,
                conditions,
                else_result,
                ..
            } => {
                // A simple CASE compares its operand to each WHEN with the
                // same affinity as equality. Only a proven direct numeric
                // column and the exact legacy text forms already admitted by
                // ordinary equality are safe to convert here. The operand is
                // a column, so cloning it below does not repeat an effectful
                // expression; unresolved or shadowed bindings remain guarded.
                if self.dialect != super::SqlDialect::NativeV1
                    && operand.as_ref().is_some_and(|value| {
                        matches!(
                            self.in_column_type(value),
                            Some(crate::values::SqlType::I64 | crate::values::SqlType::U64)
                        )
                    })
                {
                    for condition in conditions.iter_mut() {
                        if let Some(value) = exact_i64_text_literal(&condition.condition) {
                            replace_with_i64_literal(&mut condition.condition, value);
                        }
                    }
                }
                let comparison_kinds: Vec<(bool, bool)> = conditions
                    .iter()
                    .map(|condition| {
                        let literal = operand.as_ref().is_some_and(|value| no_affinity(value))
                            && no_affinity(&condition.condition);
                        let text_integer = operand.as_ref().is_some_and(|value| {
                            direct_text_integer_affinity(self.dialect, value, &condition.condition)
                        });
                        (literal, text_integer)
                    })
                    .collect();
                if let Some(value) = operand {
                    self.expr(value, depth + 1)?;
                }
                for condition in conditions.iter_mut() {
                    self.expr(&mut condition.condition, depth + 1)?;
                    self.expr(&mut condition.result, depth + 1)?;
                }
                if let Some(value) = operand.take() {
                    for (condition, (no_affinity, text_integer)) in
                        conditions.iter_mut().zip(comparison_kinds)
                    {
                        condition.condition = call(
                            if text_integer {
                                "mdd_text_integer_eq"
                            } else if no_affinity {
                                "mdd_literal_eq"
                            } else {
                                "mdd_eq"
                            },
                            vec![(*value).clone(), take(&mut condition.condition)],
                        );
                    }
                }
                for condition in conditions {
                    condition.condition =
                        call("mdd_truth_input", vec![take(&mut condition.condition)]);
                }
                if let Some(value) = else_result {
                    self.expr(value, depth + 1)?;
                }
            }
            Expr::Subquery(query)
            | Expr::Exists {
                subquery: query, ..
            } => {
                let dependencies = self.query(query, depth + 1)?;
                self.dependencies.extend(dependencies);
            }
            Expr::InSubquery {
                expr: child,
                subquery,
                ..
            } => {
                let left = self.in_column_type(child);
                let right = self.direct_subquery_column_type(subquery);
                use crate::values::SqlType::{Bool, Bytes, I64, Text, U64};
                // All three integral types share the exact mathematical key;
                // U64 values outside SQLite's signed range remain exact rather
                // than being converted to float. Text/numeric affinity and
                // floating-point cases still require separate proof.
                let distinct_limited = subquery.limit_clause.is_some()
                    && matches!(subquery.body.as_ref(), SetExpr::Select(select)
                        if matches!(&select.distinct, Some(Distinct::Distinct)));
                // Native text order is contractually UTF-16. Legacy DexSQL
                // supplementary-character pagination order is not yet proven;
                // SQLite BINARY gives a different result for valid text.
                let limited_type_ok = !distinct_limited
                    || (left == right
                        && !(right == Some(Text) && self.dialect != super::SqlDialect::NativeV1));
                let supported = limited_type_ok
                    && (matches!(
                        (left, right),
                        (Some(I64 | U64 | Bool), Some(I64 | U64 | Bool))
                    ) || (left == right && matches!(left, Some(Text | Bytes))));
                if !supported {
                    let ctes = subquery
                        .with
                        .as_ref()
                        .into_iter()
                        .flat_map(|with| with.cte_tables.iter())
                        .map(|cte| {
                            serde_json::Value::from(cte.alias.name.value.to_ascii_lowercase())
                        })
                        .collect::<Vec<_>>();
                    return Err(unsupported("IN_SUBQUERY_REQUIRES_TYPED_KEY_BINDING")
                        .detail("confirm_sqlite_syntax", true)
                        .detail("visible_ctes", ctes));
                }
                self.expr(child, depth + 1)?;
                **child = call("mdd_key", vec![take(child)]);
                // IN/NOT IN observes membership and NULL, not multiplicity.
                // With no LIMIT/OFFSET, ordinary DISTINCT cannot change the
                // membership result even when the subquery has ordering.
                // The order is still validated and evaluated by self.query.
                if let SetExpr::Select(select) = subquery.body.as_mut()
                    && matches!(&select.distinct, Some(Distinct::Distinct))
                    && !distinct_limited
                {
                    select.distinct = None;
                }
                let dependencies = self.query(subquery, depth + 1)?;
                self.dependencies.extend(dependencies);
                let SetExpr::Select(select) = subquery.body.as_mut() else {
                    return Err(invalid("INTERNAL_IN_SUBQUERY_BODY"));
                };
                let expression = match &mut select.projection[0] {
                    SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => expr,
                    _ => return Err(invalid("INTERNAL_IN_SUBQUERY_PROJECTION")),
                };
                *expression = call("mdd_key", vec![take(expression)]);
            }
            Expr::Substring {
                expr: value,
                substring_from,
                substring_for,
                special,
                ..
            } => {
                if !*special || substring_from.is_none() {
                    return Err(invalid("SQLITE_SUBSTRING_ARGUMENT_FORM"));
                }
                self.expr(value, depth + 1)?;
                let start = substring_from.as_mut().unwrap();
                self.expr(start, depth + 1)?;
                let mut args = vec![take(value), take(start)];
                if let Some(length) = substring_for {
                    self.expr(length, depth + 1)?;
                    args.push(take(length));
                }
                *expr = call("mdd_substr", args);
                return Ok(());
            }
            Expr::Function(function) => {
                if function.name.0.len() != 1
                    || function.over.is_some()
                    || function.null_treatment.is_some()
                    || !function.within_group.is_empty()
                    || function.uses_odbc_syntax
                    || !matches!(function.parameters, FunctionArguments::None)
                {
                    return Err(unsupported("FUNCTION_EXTENSION"));
                }
                let name = function.name.0[0]
                    .as_ident()
                    .ok_or_else(|| invalid("FUNCTION_IDENTIFIER_REQUIRED"))?
                    .value
                    .to_ascii_lowercase();
                if name == "load_extension" {
                    return Err(invalid("FUNCTION_NOT_AUTHORIZED"));
                }
                let mut replacement = match name.as_str() {
                    "length" => Some("mdd_length"),
                    "hex" => Some("mdd_hex"),
                    "lower" => Some("mdd_lower"),
                    "upper" => Some("mdd_upper"),
                    "min" => Some("mdd_min"),
                    "max" => Some("mdd_max"),
                    "sum" => Some("mdd_sum"),
                    "nullif" => Some("mdd_nullif"),
                    "count" | "coalesce" | "ifnull" => None,
                    _ => {
                        return Err(unsupported("FUNCTION_NOT_IMPLEMENTED")
                            .detail("confirm_sqlite_syntax", true));
                    }
                };
                let FunctionArguments::List(arguments) = &mut function.args else {
                    return Err(unsupported("FUNCTION_ARGUMENT_FORM"));
                };
                if arguments.args.len() >= 2 {
                    replacement = match name.as_str() {
                        "min" => Some("mdd_min_scalar"),
                        "max" => Some("mdd_max_scalar"),
                        _ => replacement,
                    };
                }
                if !arguments.clauses.is_empty() {
                    return Err(unsupported("FUNCTION_ARGUMENT_CLAUSE"));
                }
                let count_distinct = name == "count"
                    && arguments.duplicate_treatment == Some(DuplicateTreatment::Distinct);
                for argument in &mut arguments.args {
                    match argument {
                        FunctionArg::Unnamed(FunctionArgExpr::Expr(value)) => {
                            self.expr(value, depth + 1)?;
                            if count_distinct {
                                *value = call("mdd_key", vec![take(value)]);
                            }
                        }
                        FunctionArg::Unnamed(FunctionArgExpr::Wildcard)
                            if name == "count" && !count_distinct => {}
                        _ => return Err(unsupported("NAMED_OR_QUALIFIED_FUNCTION_ARGUMENT")),
                    }
                }
                if let Some(filter) = &mut function.filter {
                    self.expr(filter, depth + 1)?;
                    // Encoded lossless carriers are BLOBs to SQLite. FILTER
                    // must apply the same truth coercion as WHERE/HAVING.
                    **filter = call("mdd_truth_input", vec![take(filter)]);
                }
                if let Some(name) = replacement {
                    function.name = ObjectName::from(vec![Ident::new(name)]);
                }
            }
            _ => return Err(unsupported("EXPRESSION_KIND_NOT_IMPLEMENTED")),
        }
        Ok(())
    }
    fn resolve(&self, dependencies: &[Dependency]) -> MddResult<Vec<String>> {
        fn visit(
            dependency: &Dependency,
            definitions: &[Vec<Dependency>],
            path: &mut BTreeSet<usize>,
            out: &mut BTreeSet<String>,
            depth: usize,
            limit: usize,
        ) -> MddResult<()> {
            if depth > limit {
                return Err(quota("SQL_CTE_DEPENDENCY_DEPTH"));
            }
            match dependency {
                Dependency::Base(name) => {
                    out.insert(name.clone());
                }
                Dependency::Cte(id) => {
                    if !path.insert(*id) {
                        return Err(invalid("CYCLIC_CTE_DEPENDENCY"));
                    }
                    for child in &definitions[*id] {
                        visit(child, definitions, path, out, depth + 1, limit)?;
                    }
                    path.remove(id);
                }
            }
            Ok(())
        }
        let mut out = BTreeSet::new();
        for dependency in dependencies {
            visit(
                dependency,
                &self.cte_definitions,
                &mut BTreeSet::new(),
                &mut out,
                0,
                self.limits.max_ast_depth,
            )?;
        }
        Ok(out.into_iter().collect())
    }
    fn table_expressions(&self, table: &TableFactor) -> MddResult<Vec<Expr>> {
        let (qualifier, names) = match table {
            TableFactor::Table { name, alias, .. } => {
                let id = name
                    .0
                    .first()
                    .and_then(|n| n.as_ident())
                    .ok_or_else(|| unsupported("TABLE_NAME_SHAPE"))?;
                let name = id.value.to_ascii_lowercase();
                let names =
                    if let Some(id) = self.cte_scopes.iter().rev().find_map(|s| s.get(&name)) {
                        self.cte_columns
                            .get(id)
                            .ok_or_else(|| unsupported("FORWARD_CTE_WILDCARD_SCHEMA"))?
                    } else {
                        self.schemas
                            .get(&name)
                            .ok_or_else(|| invalid("UNKNOWN_RELATION"))?
                    };
                (
                    alias
                        .as_ref()
                        .map_or_else(|| id.clone(), |a| a.name.clone()),
                    names.clone(),
                )
            }
            TableFactor::Derived {
                subquery, alias, ..
            } => (
                alias
                    .as_ref()
                    .ok_or_else(|| invalid("DERIVED_ALIAS_MISSING"))?
                    .name
                    .clone(),
                self.output_names(&subquery.body)?,
            ),
            _ => return Err(unsupported("WILDCARD_TABLE_SHAPE")),
        };
        Ok(names
            .into_iter()
            .map(|name| {
                Expr::CompoundIdentifier(vec![qualifier.clone(), Ident::with_quote('"', name)])
            })
            .collect())
    }
    fn check_using(
        &self,
        left: &TableFactor,
        right: &TableFactor,
        columns: &[ObjectName],
    ) -> MddResult<()> {
        let types = |factor: &TableFactor| -> MddResult<&BTreeMap<String, crate::values::SqlType>> {
            let TableFactor::Table { name, .. } = factor else {
                return Err(unsupported("JOIN_USING_DERIVED_SCHEMA"));
            };
            let id = name
                .0
                .first()
                .and_then(|p| p.as_ident())
                .ok_or_else(|| invalid("TABLE_NAME_SHAPE"))?;
            let name = id.value.to_ascii_lowercase();
            if let Some(id) = self
                .cte_scopes
                .iter()
                .rev()
                .find_map(|scope| scope.get(&name))
            {
                return self.cte_direct_types.get(id).ok_or_else(|| {
                    let visible_ctes = self
                        .cte_scopes
                        .iter()
                        .flat_map(|scope| scope.keys())
                        .cloned()
                        .collect::<Vec<_>>();
                    unsupported("JOIN_USING_CTE_SCHEMA")
                        .detail("confirm_sqlite_syntax", true)
                        .detail("visible_ctes", visible_ctes)
                });
            }
            self.schema_types
                .get(&name)
                .ok_or_else(|| invalid("UNKNOWN_RELATION"))
        };
        let (left, right) = (types(left)?, types(right)?);
        let mut seen = BTreeSet::new();
        for column in columns {
            let id = column
                .0
                .first()
                .filter(|_| column.0.len() == 1)
                .and_then(|p| p.as_ident())
                .ok_or_else(|| invalid("JOIN_USING_COLUMN"))?;
            let name = id.value.to_ascii_lowercase();
            if !seen.insert(name.clone()) {
                return Err(invalid("JOIN_USING_DUPLICATE_COLUMN"));
            }
            let left = left
                .get(&name)
                .ok_or_else(|| invalid("JOIN_USING_MISSING_COLUMN"))?;
            let right = right
                .get(&name)
                .ok_or_else(|| invalid("JOIN_USING_MISSING_COLUMN"))?;
            // Same-type carriers below have bytewise equality equivalent to
            // the SQL equality used by this bridge. F64 (signed zero/NaN),
            // bytes (MUTF8 versus ordinary blob), and mixed types do not.
            if left != right
                || !matches!(
                    left,
                    crate::values::SqlType::I64
                        | crate::values::SqlType::U64
                        | crate::values::SqlType::Bool
                        | crate::values::SqlType::Text
                )
            {
                return Err(unsupported("JOIN_USING_REQUIRES_EXACT_EQUALITY"));
            }
        }
        Ok(())
    }
    fn wildcard_expressions(&self, table: &TableWithJoins) -> MddResult<Vec<Expr>> {
        let mut out = self.table_expressions(&table.relation)?;
        for join in &table.joins {
            let constraint = match &join.join_operator {
                JoinOperator::Join(c)
                | JoinOperator::Inner(c)
                | JoinOperator::Left(c)
                | JoinOperator::LeftOuter(c)
                | JoinOperator::Right(c)
                | JoinOperator::RightOuter(c)
                | JoinOperator::FullOuter(c)
                | JoinOperator::CrossJoin(c) => c,
                _ => return Err(unsupported("JOIN_KIND_NOT_IMPLEMENTED")),
            };
            let names: BTreeSet<String> = match constraint {
                JoinConstraint::Using(names) => names
                    .iter()
                    .filter_map(|name| {
                        name.0
                            .first()
                            .and_then(|p| p.as_ident())
                            .map(|id| id.value.to_ascii_lowercase())
                    })
                    .collect(),
                _ => BTreeSet::new(),
            };
            out.extend(self.table_expressions(&join.relation)?.into_iter().filter(|expr| {
                !matches!(expr, Expr::CompoundIdentifier(ids) if ids.last().is_some_and(|id| names.contains(&id.value.to_ascii_lowercase())))
            }));
        }
        Ok(out)
    }
    fn select_expressions(&self, select: &Select) -> MddResult<Vec<Expr>> {
        let mut out = Vec::new();
        for projection in &select.projection {
            match projection {
                SelectItem::ExprWithAlias { expr, .. } | SelectItem::UnnamedExpr(expr) => {
                    out.push(expr.clone())
                }
                SelectItem::Wildcard(_) => {
                    for table in &select.from {
                        out.extend(self.wildcard_expressions(table)?);
                    }
                }
                SelectItem::QualifiedWildcard(
                    SelectItemQualifiedWildcardKind::ObjectName(name),
                    _,
                ) => {
                    let qualifier = name.to_string().trim_matches('"').to_ascii_lowercase();
                    let mut found = false;
                    for table in &select.from {
                        for relation in std::iter::once(&table.relation)
                            .chain(table.joins.iter().map(|j| &j.relation))
                        {
                            let values = self.table_expressions(relation)?;
                            if values.first().is_some_and(|v|matches!(v,Expr::CompoundIdentifier(ids)if ids[0].value.eq_ignore_ascii_case(&qualifier))){out.extend(values);found=true;}
                        }
                    }
                    if !found {
                        return Err(invalid("UNKNOWN_WILDCARD_QUALIFIER"));
                    }
                }
                _ => return Err(unsupported("PROJECTION_SHAPE")),
            }
        }
        Ok(out)
    }
    fn select_projection_at(&self, select: &Select, index: usize) -> MddResult<Expr> {
        self.select_expressions(select)?
            .get(index)
            .cloned()
            .ok_or_else(|| invalid("PROJECTION_ORDINAL_OUT_OF_RANGE"))
    }
    fn projection_at(&self, body: &SetExpr, index: usize) -> MddResult<Expr> {
        match body {
            SetExpr::Select(select) => self.select_projection_at(select, index),
            SetExpr::Query(query) => self.projection_at(&query.body, index),
            _ => Err(unsupported("POSITIONAL_ORDER_BODY")),
        }
    }
    fn output_names(&self, body: &SetExpr) -> MddResult<Vec<String>> {
        match body {
            SetExpr::Select(select) => {
                let mut names = Vec::new();
                for projection in &select.projection {
                    match projection {
                        SelectItem::ExprWithAlias { alias, .. } => names.push(alias.value.clone()),
                        SelectItem::UnnamedExpr(Expr::Identifier(id)) => {
                            names.push(id.value.clone())
                        }
                        SelectItem::UnnamedExpr(Expr::CompoundIdentifier(ids)) => {
                            names.push(ids.last().unwrap().value.clone())
                        }
                        SelectItem::Wildcard(_) => {
                            for table in &select.from {
                                for expr in self.wildcard_expressions(table)? {
                                    if let Expr::CompoundIdentifier(ids) = expr {
                                        names.push(ids.last().unwrap().value.clone());
                                    } else {
                                        return Err(unsupported("WILDCARD_NAME"));
                                    }
                                }
                            }
                        }
                        SelectItem::QualifiedWildcard(
                            SelectItemQualifiedWildcardKind::ObjectName(name),
                            _,
                        ) => {
                            let target = name
                                .0
                                .last()
                                .and_then(|p| p.as_ident())
                                .ok_or_else(|| invalid("WILDCARD_QUALIFIER"))?
                                .value
                                .to_ascii_lowercase();
                            let mut found = false;
                            for table in &select.from {
                                for factor in std::iter::once(&table.relation)
                                    .chain(table.joins.iter().map(|j| &j.relation))
                                {
                                    let expressions = self.table_expressions(factor)?;
                                    if expressions.first().is_some_and(|e|matches!(e,Expr::CompoundIdentifier(ids)if ids[0].value.eq_ignore_ascii_case(&target))){for expr in expressions{if let Expr::CompoundIdentifier(ids)=expr{names.push(ids.last().unwrap().value.clone());}}found=true;}
                                }
                            }
                            if !found {
                                return Err(invalid("UNKNOWN_WILDCARD_QUALIFIER"));
                            }
                        }
                        _ => return Err(unsupported("OUTPUT_COLUMN_NAME")),
                    }
                }
                Ok(names)
            }
            SetExpr::Query(query) => self.output_names(&query.body),
            SetExpr::SetOperation { left, .. } => self.output_names(left),
            _ => Err(unsupported("OUTPUT_SCHEMA_BODY")),
        }
    }
    fn compound_order(&mut self, query: &mut Query) -> MddResult<()> {
        fn first(body: &mut SetExpr) -> MddResult<&mut Select> {
            match body {
                SetExpr::Select(select) => Ok(select),
                SetExpr::Query(query) => first(&mut query.body),
                SetExpr::SetOperation { left, .. } => first(left),
                _ => Err(unsupported("COMPOUND_FIRST_BODY")),
            }
        }
        let names = self.output_names(&query.body)?;
        let original_expressions = self.select_expressions(first(&mut query.body)?)?;
        let mut skeleton =
            Parser::parse_sql(&SQLiteDialect {}, "SELECT * FROM placeholder AS holder")
                .map_err(parse_error)?;
        let Statement::Query(mut wrapper) = skeleton.remove(0) else {
            return Err(invalid("INTERNAL_QUERY_TEMPLATE"));
        };
        let mut original = std::mem::replace(query, *wrapper.clone());
        wrapper.order_by = original.order_by.take();
        wrapper.limit_clause = original.limit_clause.take();
        let owner = Ident::with_quote('"', self.fresh());
        let internal = (0..names.len())
            .map(|_| Ident::with_quote('"', self.fresh()))
            .collect::<Vec<_>>();
        let head = first(&mut original.body)?;
        if head.having.is_some()
            || matches!(&head.group_by,GroupByExpr::Expressions(values,_)if !values.is_empty())
        {
            return Err(unsupported("COMPOUND_GROUP_ALIAS_BINDING"));
        }
        if head.projection.len() != names.len()
            || head
                .projection
                .iter()
                .any(|p| !matches!(p, SelectItem::ExprWithAlias { .. }))
        {
            return Err(unsupported("COMPOUND_WILDCARD_SCHEMA"));
        }
        for (projection, alias) in head.projection.iter_mut().zip(&internal) {
            if let SelectItem::ExprWithAlias { alias: old, .. } = projection {
                *old = alias.clone();
            }
        }
        if let Some(order) = &mut wrapper.order_by
            && let OrderByKind::Expressions(values) = &mut order.kind
        {
            for value in values {
                let position = if let Some(index) = positional_ordinal(&value.expr)? {
                    Some(index)
                } else if let Some(id) = order_identifier(&value.expr) {
                    names
                        .iter()
                        .position(|name| name.eq_ignore_ascii_case(&id.value))
                } else {
                    let expr = value.expr.to_string();
                    original_expressions
                        .iter()
                        .position(|v| v.to_string() == expr)
                }
                .ok_or_else(|| {
                    unsupported("COMPOUND_ORDER_BINDING_NOT_PROVEN")
                        .detail("confirm_sqlite_syntax", true)
                        .detail("validate_bare_parameters", true)
                })?;
                let column = internal
                    .get(position)
                    .ok_or_else(|| invalid("ORDER_ORDINAL_OUT_OF_RANGE"))?
                    .clone();
                value.expr = call(
                    "mdd_sort_key",
                    vec![Expr::CompoundIdentifier(vec![owner.clone(), column])],
                );
            }
        }
        let SetExpr::Select(select) = wrapper.body.as_mut() else {
            return Err(invalid("INTERNAL_OUTER_SELECT"));
        };
        select.projection = internal
            .iter()
            .zip(&names)
            .map(|(column, name)| SelectItem::ExprWithAlias {
                expr: Expr::CompoundIdentifier(vec![owner.clone(), column.clone()]),
                alias: Ident::with_quote('"', name),
            })
            .collect();
        select.from[0].relation = TableFactor::Derived {
            lateral: false,
            subquery: Box::new(original),
            alias: Some(TableAlias {
                name: owner,
                columns: Vec::new(),
                explicit: true,
                at: None,
            }),
            sample: None,
        };
        *query = *wrapper;
        Ok(())
    }
}
fn order_identifier(mut expression: &Expr) -> Option<&Ident> {
    while let Expr::Nested(inner) = expression {
        expression = inner;
    }
    match expression {
        Expr::Identifier(id) => Some(id),
        _ => None,
    }
}

fn positional_ordinal(mut expression: &Expr) -> MddResult<Option<usize>> {
    let mut negative = false;
    loop {
        match expression {
            Expr::Nested(inner) => expression = inner,
            Expr::UnaryOp {
                op: UnaryOperator::Plus,
                expr,
            } => expression = expr,
            Expr::UnaryOp {
                op: UnaryOperator::Minus,
                expr,
            } => {
                negative = !negative;
                expression = expr;
            }
            _ => break,
        }
    }
    if let Expr::Value(ValueWithSpan {
        value: Value::Number(number, _),
        ..
    }) = expression
    {
        // SQLite treats integer literals (including unary signs and grouping
        // parentheses) as positions. Real literals such as 1.0 or 1e0 are
        // constant expressions instead, and must not be parsed as ordinals.
        if !number.bytes().all(|byte| byte.is_ascii_digit()) {
            return Ok(None);
        }
        // SQLite only interprets integer literals that fit in signed 32-bit
        // magnitude as positional references. Larger literals remain constant
        // expressions, even if their text is numerically integral.
        let Ok(number) = number.parse::<u32>() else {
            return Ok(None);
        };
        if number > i32::MAX as u32 {
            return Ok(None);
        }
        let number = number as usize;
        if negative {
            return Err(invalid("ORDER_OR_GROUP_ORDINAL_NEGATIVE"));
        }
        if number == 0 {
            return Err(invalid("ORDER_OR_GROUP_ORDINAL_ZERO"));
        }
        Ok(Some(number - 1))
    } else {
        Ok(None)
    }
}

/// Count/check the emitted semantic tree without recursive walking. Generated
/// casts, keys and outer ordering scopes also consume the declared budget.
fn validate_iterative(query: &Query, limits: SqlLimits) -> MddResult<usize> {
    enum Node<'a> {
        Query(&'a Query),
        Body(&'a SetExpr),
        Table(&'a TableFactor),
        Expr(&'a Expr),
    }
    let mut stack = vec![(Node::Query(query), 1usize)];
    let mut count = 0usize;
    while let Some((node, depth)) = stack.pop() {
        count = count
            .checked_add(1)
            .ok_or_else(|| quota("EMITTED_AST_NODE_OVERFLOW"))?;
        if count > limits.max_ast_nodes || depth > limits.max_ast_depth {
            return Err(quota("EMITTED_AST_NODE_OR_DEPTH"));
        }
        match node {
            Node::Query(query) => {
                if let Some(with) = &query.with {
                    for cte in &with.cte_tables {
                        stack.push((Node::Query(&cte.query), depth + 1));
                    }
                }
                stack.push((Node::Body(&query.body), depth + 1));
                if let Some(order) = &query.order_by
                    && let OrderByKind::Expressions(values) = &order.kind
                {
                    for value in values {
                        stack.push((Node::Expr(&value.expr), depth + 1));
                    }
                }
                if let Some(limit) = &query.limit_clause {
                    match limit {
                        LimitClause::LimitOffset { limit, offset, .. } => {
                            if let Some(limit) = limit {
                                stack.push((Node::Expr(limit), depth + 1));
                            }
                            if let Some(offset) = offset {
                                stack.push((Node::Expr(&offset.value), depth + 1));
                            }
                        }
                        LimitClause::OffsetCommaLimit { offset, limit } => {
                            stack.push((Node::Expr(offset), depth + 1));
                            stack.push((Node::Expr(limit), depth + 1));
                        }
                    }
                }
            }
            Node::Body(body) => match body {
                SetExpr::Select(select) => {
                    for table in &select.from {
                        stack.push((Node::Table(&table.relation), depth + 1));
                        for join in &table.joins {
                            stack.push((Node::Table(&join.relation), depth + 1));
                            let constraint = match &join.join_operator {
                                JoinOperator::Join(c)
                                | JoinOperator::Inner(c)
                                | JoinOperator::Left(c)
                                | JoinOperator::LeftOuter(c)
                                | JoinOperator::Right(c)
                                | JoinOperator::RightOuter(c)
                                | JoinOperator::FullOuter(c)
                                | JoinOperator::CrossJoin(c) => c,
                                _ => return Err(invalid("INTERNAL_JOIN_KIND")),
                            };
                            if let JoinConstraint::On(expr) = constraint {
                                stack.push((Node::Expr(expr), depth + 1));
                            }
                        }
                    }
                    for projection in &select.projection {
                        match projection {
                            SelectItem::UnnamedExpr(expr)
                            | SelectItem::ExprWithAlias { expr, .. } => {
                                stack.push((Node::Expr(expr), depth + 1))
                            }
                            SelectItem::Wildcard(_)
                            | SelectItem::QualifiedWildcard(
                                SelectItemQualifiedWildcardKind::ObjectName(_),
                                _,
                            ) => (),
                            _ => return Err(invalid("INTERNAL_PROJECTION_KIND")),
                        }
                    }
                    for expr in [&select.selection, &select.having].into_iter().flatten() {
                        stack.push((Node::Expr(expr), depth + 1));
                    }
                    if let GroupByExpr::Expressions(values, _) = &select.group_by {
                        for expr in values {
                            stack.push((Node::Expr(expr), depth + 1));
                        }
                    }
                }
                SetExpr::Query(query) => stack.push((Node::Query(query), depth + 1)),
                SetExpr::SetOperation { left, right, .. } => {
                    stack.push((Node::Body(left), depth + 1));
                    stack.push((Node::Body(right), depth + 1));
                }
                SetExpr::Values(values) => {
                    for row in &values.rows {
                        for expr in row.iter() {
                            stack.push((Node::Expr(expr), depth + 1));
                        }
                    }
                }
                _ => return Err(invalid("INTERNAL_QUERY_BODY")),
            },
            Node::Table(table) => match table {
                TableFactor::Table { .. } => (),
                TableFactor::Derived { subquery, .. } => {
                    stack.push((Node::Query(subquery), depth + 1))
                }
                _ => return Err(invalid("INTERNAL_TABLE_KIND")),
            },
            Node::Expr(expr) => match expr {
                Expr::Identifier(_) | Expr::CompoundIdentifier(_) | Expr::Value(_) => (),
                Expr::Nested(child)
                | Expr::IsNull(child)
                | Expr::IsNotNull(child)
                | Expr::IsTrue(child)
                | Expr::IsFalse(child)
                | Expr::IsNotTrue(child)
                | Expr::IsNotFalse(child)
                | Expr::UnaryOp { expr: child, .. } => stack.push((Node::Expr(child), depth + 1)),
                Expr::BinaryOp { left, right, .. } => {
                    stack.push((Node::Expr(left), depth + 1));
                    stack.push((Node::Expr(right), depth + 1));
                }
                Expr::Between {
                    expr, low, high, ..
                } => {
                    stack.push((Node::Expr(expr), depth + 1));
                    stack.push((Node::Expr(low), depth + 1));
                    stack.push((Node::Expr(high), depth + 1));
                }
                Expr::InList { expr, list, .. } => {
                    stack.push((Node::Expr(expr), depth + 1));
                    for expr in list {
                        stack.push((Node::Expr(expr), depth + 1));
                    }
                }
                Expr::InSubquery { expr, subquery, .. } => {
                    stack.push((Node::Expr(expr), depth + 1));
                    stack.push((Node::Query(subquery), depth + 1));
                }
                Expr::Case {
                    operand,
                    conditions,
                    else_result,
                    ..
                } => {
                    if let Some(expr) = operand {
                        stack.push((Node::Expr(expr), depth + 1));
                    }
                    for condition in conditions {
                        stack.push((Node::Expr(&condition.condition), depth + 1));
                        stack.push((Node::Expr(&condition.result), depth + 1));
                    }
                    if let Some(expr) = else_result {
                        stack.push((Node::Expr(expr), depth + 1));
                    }
                }
                Expr::Subquery(query)
                | Expr::Exists {
                    subquery: query, ..
                } => stack.push((Node::Query(query), depth + 1)),
                Expr::Function(function) => {
                    if let FunctionArguments::List(arguments) = &function.args {
                        for arg in &arguments.args {
                            match arg {
                                FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) => {
                                    stack.push((Node::Expr(expr), depth + 1))
                                }
                                FunctionArg::Unnamed(FunctionArgExpr::Wildcard) => (),
                                _ => return Err(invalid("INTERNAL_FUNCTION_ARGUMENT")),
                            }
                        }
                    } else {
                        return Err(invalid("INTERNAL_FUNCTION_FORM"));
                    }
                    if let Some(expr) = &function.filter {
                        stack.push((Node::Expr(expr), depth + 1));
                    }
                }
                _ => return Err(invalid("INTERNAL_UNWALKED_EXPRESSION")),
            },
        }
    }
    Ok(count)
}

#[cfg(test)]
mod aggregate_scan_tests {
    use super::*;

    #[test]
    fn compound_carrier_nested_parentheses_charge_every_visit() {
        let mut expr = Expr::Value(Value::Number("1".into(), false).into());
        for _ in 0..4 {
            expr = Expr::Nested(Box::new(expr));
        }
        let budget = AggregateScan {
            depth_limit: 16,
            remaining: Cell::new(9),
        };
        assert!(charged_compound_expression(&expr, 0, &budget).is_ok());
        let error = charged_compound_expression(&expr, 0, &budget)
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
        assert_eq!(error.message, "SQL_AGGREGATE_DETECTION_NODES");
        let shallow = AggregateScan {
            depth_limit: 2,
            remaining: Cell::new(100),
        };
        let error = charged_compound_expression(&expr, 0, &shallow)
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
        assert_eq!(error.message, "SQL_AGGREGATE_DETECTION_DEPTH");
    }

    #[test]
    fn affinity_parentheses_use_bounded_stack() {
        let parse_expression = |sql: &str| {
            let mut statements = Parser::parse_sql(&SQLiteDialect {}, sql).unwrap();
            let Statement::Query(query) = statements.remove(0) else {
                panic!("expected SELECT")
            };
            let SetExpr::Select(mut select) = *query.body else {
                panic!("expected SELECT body")
            };
            let SelectItem::UnnamedExpr(expression) = select.projection.remove(0) else {
                panic!("expected projection expression")
            };
            expression
        };
        let cast_text = parse_expression("SELECT CAST('x' AS TEXT)");
        let cast_integer = parse_expression("SELECT CAST('1' AS INTEGER)");
        let cast_number = parse_expression("SELECT CAST(1 AS TEXT)");
        let result = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || {
                fn wrap(mut value: Expr) -> Expr {
                    for _ in 0..5000 {
                        value = Expr::Nested(Box::new(value));
                    }
                    value
                }
                fn release(mut value: Expr) {
                    // Avoid recursive destructor work on this deliberately deep AST.
                    while let Expr::Nested(inner) = value {
                        value = *inner;
                    }
                }
                let expr = wrap(Expr::Value(Value::Number("1".into(), false).into()));
                assert!(no_affinity(&expr));
                assert!(nonnegative_i64_literal(&expr));
                assert!(matches!(literal_in_class(&expr), Some(Some(InStorageClass::Numeric))));
                assert!(!text_cast_string_literal(&expr));
                assert!(!integer_cast_string_literal(&expr));
                assert!(!text_cast_nonnegative_i64_literal(&expr));
                release(expr);
                let expr = wrap(cast_text);
                assert!(text_cast_string_literal(&expr));
                assert!(!integer_cast_string_literal(&expr));
                release(expr);
                let expr = wrap(cast_integer);
                assert!(integer_cast_string_literal(&expr));
                assert!(!text_cast_string_literal(&expr));
                release(expr);
                let expr = wrap(cast_number);
                assert!(text_cast_nonnegative_i64_literal(&expr));
                release(expr);
                let expr = wrap(Expr::Identifier(Ident::new("bound")));
                assert!(matches!(without_parentheses(&expr), Expr::Identifier(id) if id.value == "bound"));
                release(expr);
            })
            .unwrap()
            .join();
        result.unwrap();
    }

    #[test]
    fn between_length_guard_limits_nested_preflight_without_recursion() {
        let number = || Expr::Value(Value::Number("1".into(), false).into());
        let mut value = call("length", vec![number()]);
        let mut bound = number();
        for _ in 0..5000 {
            value = Expr::Nested(Box::new(value));
            bound = Expr::Nested(Box::new(bound));
        }
        assert!(!length_with_integer_between_bounds(
            &value,
            &number(),
            &number(),
            16
        ));
        assert!(!length_with_integer_between_bounds(
            &call("length", vec![number()]),
            &bound,
            &number(),
            16
        ));
        assert_eq!(exact_i64_numeric_literal(&bound), Some(1));
        // Unwrap iteratively so dropping the fixture itself cannot recurse.
        while let Expr::Nested(inner) = value {
            value = *inner;
        }
        while let Expr::Nested(inner) = bound {
            bound = *inner;
        }
    }

    #[test]
    fn aggregate_reference_scan_obeys_depth_and_visit_budgets() {
        let mut expr = Expr::Value(Value::Number("1".into(), false).into());
        for _ in 0..10 {
            expr = Expr::Nested(Box::new(expr));
        }
        let local = BTreeMap::new();
        for budget in [
            AggregateScan {
                depth_limit: 4,
                remaining: Cell::new(100),
            },
            AggregateScan {
                depth_limit: 100,
                remaining: Cell::new(2),
            },
        ] {
            assert_eq!(
                possible_outer_column(&expr, &local, 0, &budget)
                    .unwrap_err()
                    .code,
                ErrorCode::QuotaExceeded
            );
        }
    }

    #[test]
    fn aggregate_scope_schema_columns_are_charged() {
        let statements =
            Parser::parse_sql(&SQLiteDialect {}, "SELECT COUNT(id) FROM vals").unwrap();
        let Statement::Query(query) = &statements[0] else {
            panic!("expected SELECT")
        };
        let schemas = BTreeMap::from([(
            "vals".to_string(),
            (0..20).map(|n| format!("column{n}")).collect(),
        )]);
        let budget = AggregateScan {
            depth_limit: 100,
            remaining: Cell::new(5),
        };
        let error =
            nested_query_needs_binding(query, &schemas, &BTreeSet::new(), 0, &budget).unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
        assert_eq!(error.message, "SQL_AGGREGATE_DETECTION_NODES");
    }
}
