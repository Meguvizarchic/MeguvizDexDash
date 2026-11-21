use super::*;

pub(super) fn order_identifier(mut expression: &Expr) -> Option<&Ident> {
    while let Expr::Nested(inner) = expression {
        expression = inner;
    }
    match expression {
        Expr::Identifier(id) => Some(id),
        _ => None,
    }
}

pub(super) fn positional_ordinal(mut expression: &Expr) -> MddResult<Option<usize>> {
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
pub(super) fn validate_iterative(query: &Query, limits: SqlLimits) -> MddResult<usize> {
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
