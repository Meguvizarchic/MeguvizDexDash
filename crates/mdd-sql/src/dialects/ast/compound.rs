use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum InStorageClass {
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
pub(super) enum CompoundCarrier {
    Null,
    Integer,
    Unsigned,
    Text,
    LiteralBytes,
    Mixed(u8),
    Unknown,
}

pub(super) fn merge_compound_carrier(a: CompoundCarrier, b: CompoundCarrier) -> CompoundCarrier {
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
pub(super) fn stable_compound_order_expr(
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
pub(super) fn same_compound_order_expr(
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

pub(super) fn literal_in_class(expr: &Expr) -> Option<Option<InStorageClass>> {
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
