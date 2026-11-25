use super::*;

// Inspect the already rewritten projection, but never descend into a nested
// SELECT: an aggregate there does not make the outer SELECT an aggregate.
// Rewriting may introduce several wrappers per input node, so cap traversal
// independently rather than trusting unbounded recursion.
pub(super) struct AggregateScan {
    pub(super) depth_limit: usize,
    pub(super) remaining: Cell<usize>,
}
impl AggregateScan {
    pub(super) fn visit(&self, depth: usize) -> MddResult<()> {
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

pub(super) fn charged_compound_expression<'a>(
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
pub(super) fn current_aggregate(
    expr: &Expr,
    depth: usize,
    budget: &AggregateScan,
) -> MddResult<bool> {
    budget.visit(depth)?;
    let child = |e: &Expr| current_aggregate(e, depth + 1, budget);
    match expr {
        Expr::Function(function) => {
            let name = function.name.0.first().and_then(|part| part.as_ident());
            if function.name.0.len() == 1
                && function.over.is_none()
                && name.is_some_and(|name| {
                    [
                        "count",
                        "mdd_sum",
                        "mdd_min",
                        "mdd_max",
                        "mdd_group_concat",
                        "mdd_group_concat_distinct",
                    ]
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
                for clause in &arguments.clauses {
                    if let FunctionArgumentClause::OrderBy(exprs) = clause {
                        for order in exprs {
                            if child(&order.expr)? {
                                return Ok(true);
                            }
                        }
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

pub(super) fn possible_outer_column(
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
                for clause in &arguments.clauses {
                    let FunctionArgumentClause::OrderBy(exprs) = clause else {
                        return Ok(true);
                    };
                    for order in exprs {
                        if child(&order.expr)? {
                            return Ok(true);
                        }
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
pub(super) fn nested_aggregate_needs_binding(
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
                    [
                        "count",
                        "mdd_sum",
                        "mdd_min",
                        "mdd_max",
                        "mdd_group_concat",
                        "mdd_group_concat_distinct",
                    ]
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
                for clause in &arguments.clauses {
                    if let FunctionArgumentClause::OrderBy(exprs) = clause {
                        for order in exprs {
                            if aggregate
                                && let Some(local) = local
                                && possible_outer_column(&order.expr, local, depth + 1, budget)?
                            {
                                return Ok(true);
                            }
                            if child(&order.expr)? {
                                return Ok(true);
                            }
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

pub(super) fn nested_query_needs_binding(
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

pub(super) fn nested_body_needs_binding(
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

pub(super) fn nested_select_needs_binding(
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
