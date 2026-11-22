//! Which rows of a relation a statement can use, found without changing the statement.
//!
//! A relation whose provider keeps the rows of one DEX together can be read for one DEX. The statement does not say so to
//! SQLite in a way SQLite can use: the dialect rewrites `file_id = 0` into a call of a comparison function, which the
//! virtual table is never told about. This looks at the statement as the user wrote it, before the rewrite, and finds the
//! one shape that matters and is safe to read: a relation named exactly once in the whole statement, in the `FROM` of
//! the outermost `SELECT`, whose partition column is required to equal a non-negative integer by a conjunct of that
//! `SELECT`'s `WHERE`.
//!
//! A row with another value in that column cannot be part of any row the statement outputs: the conjunct is false for it
//! however the relation is joined, and an outer join does not change that (the `WHERE` removes the row it makes up).
//! The statement still contains the condition, so a cursor that returns more rows than asked for changes nothing but the
//! time; this only chooses a smaller cursor.
use crate::{
    provider::{
        DirectCountGroupBy, DirectFilteredProjection, DirectGroupItem, DirectOrderItem,
        DirectPredicate, DirectTableProjection, EquiJoinEdge, RowFilter, SqlRelation,
    },
    values::SqlType,
};
use sqlparser::{ast::*, dialect::SQLiteDialect, parser::Parser, tokenizer::Token};
use std::collections::{BTreeMap, BTreeSet};

fn parse_single_query(sql: &str, max_ast_depth: usize) -> Option<Box<Query>> {
    let mut stmts = Parser::new(&SQLiteDialect {})
        .with_recursion_limit(max_ast_depth)
        .try_with_sql(sql)
        .ok()?
        .parse_statements()
        .ok()?;
    if stmts.len() != 1 {
        return None;
    }
    match stmts.pop()? {
        Statement::Query(root) => Some(root),
        _ => None,
    }
}

fn extract_plain_single_table<'a>(
    root: &'a Query,
    relations: &'a [SqlRelation],
    cte_names: &BTreeSet<String>,
    allow_limit: bool,
) -> Option<(&'a Select, &'a SqlRelation, String)> {
    if relations.is_empty()
        || root.with.is_some()
        || (!allow_limit && root.limit_clause.is_some())
        || root.fetch.is_some()
        || !root.locks.is_empty()
        || root.settings.is_some()
        || root.format_clause.is_some()
        || !root.pipe_operators.is_empty()
    {
        return None;
    }
    let SetExpr::Select(select) = &*root.body else {
        return None;
    };
    if select.distinct.is_some()
        || select.top.is_some()
        || select.into.is_some()
        || !select.cluster_by.is_empty()
        || !select.distribute_by.is_empty()
        || !select.sort_by.is_empty()
        || select.having.is_some()
        || !select.named_window.is_empty()
        || select.qualify.is_some()
        || !select.connect_by.is_empty()
        || select.prewhere.is_some()
        || !select.lateral_views.is_empty()
        || select.value_table_mode.is_some()
        || select.from.len() != 1
        || !select.from[0].joins.is_empty()
        || select.projection.is_empty()
    {
        return None;
    }
    let TableFactor::Table {
        name,
        alias,
        args: None,
        with_hints,
        version: None,
        with_ordinality: false,
        partitions,
        json_path: None,
        sample: None,
        index_hints,
    } = &select.from[0].relation
    else {
        return None;
    };
    if !with_hints.is_empty()
        || !partitions.is_empty()
        || !index_hints.is_empty()
        || alias.as_ref().is_some_and(|a| !a.columns.is_empty())
        || name.0.len() != 1
    {
        return None;
    }
    let rel_ident = name.0[0].as_ident()?;
    let rel_lower = rel_ident.value.to_ascii_lowercase();
    if cte_names.contains(&rel_lower) {
        return None;
    }
    let rel = relations
        .iter()
        .find(|r| r.name.eq_ignore_ascii_case(&rel_lower))?;
    let qualifier = alias
        .as_ref()
        .map_or_else(|| rel_lower, |a| a.name.value.to_ascii_lowercase());
    Some((select, rel, qualifier))
}

fn has_empty_group_by(select: &Select) -> bool {
    matches!(
        &select.group_by,
        GroupByExpr::Expressions(exprs, modifiers) if exprs.is_empty() && modifiers.is_empty()
    )
}

fn resolve_plain_col(rel: &SqlRelation, qualifier: &str, expr: &Expr) -> Option<usize> {
    match unwrap_nested(expr) {
        Expr::Identifier(id) => rel
            .columns
            .iter()
            .position(|c| c.name.eq_ignore_ascii_case(&id.value)),
        Expr::CompoundIdentifier(parts) if parts.len() == 2 => {
            if !parts[0].value.eq_ignore_ascii_case(qualifier) {
                return None;
            }
            rel.columns
                .iter()
                .position(|c| c.name.eq_ignore_ascii_case(&parts[1].value))
        }
        _ => None,
    }
}

/// Extract a sound direct single-table projection with optional ascending `U64` ORDER BY,
/// excluding wrappers, CTEs, filters, aggregates, LIMIT/OFFSET, or ambiguous aliases.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn extract_direct_projection(
    sql: &str,
    relations: &[SqlRelation],
    cte_names: &BTreeSet<String>,
    max_ast_depth: usize,
) -> Option<DirectTableProjection> {
    let root = parse_single_query(sql, max_ast_depth)?;
    extract_direct_projection_from_query(&root, relations, cte_names)
}

/// As [`extract_direct_projection`], reusing an already-parsed [`Query`] AST.
pub(crate) fn extract_direct_projection_from_query(
    root: &Query,
    relations: &[SqlRelation],
    cte_names: &BTreeSet<String>,
) -> Option<DirectTableProjection> {
    let (select, rel, qualifier) = extract_plain_single_table(root, relations, cte_names, false)?;
    if select.selection.is_some() || !has_empty_group_by(select) {
        return None;
    }

    let mut projected_columns = Vec::with_capacity(select.projection.len());
    let mut shadowed_cols = BTreeSet::new();
    for item in &select.projection {
        match item {
            SelectItem::UnnamedExpr(expr) => {
                let col_idx = resolve_plain_col(rel, &qualifier, expr)?;
                projected_columns.push((col_idx, rel.columns[col_idx].name.clone()));
            }
            SelectItem::ExprWithAlias { expr, alias } => {
                let col_idx = resolve_plain_col(rel, &qualifier, expr)?;
                if let Some(other_idx) = rel
                    .columns
                    .iter()
                    .position(|c| c.name.eq_ignore_ascii_case(&alias.value))
                    && other_idx != col_idx
                {
                    shadowed_cols.insert(other_idx);
                }
                projected_columns.push((col_idx, alias.value.clone()));
            }
            _ => return None,
        }
    }

    let order_by_u64_asc = match &root.order_by {
        None => Vec::new(),
        Some(order) => {
            if order.interpolate.is_some() {
                return None;
            }
            let OrderByKind::Expressions(exprs) = &order.kind else {
                return None;
            };
            if exprs.is_empty() || exprs.len() > 2 {
                return None;
            }
            let mut cols = Vec::with_capacity(exprs.len());
            for item in exprs {
                if item.with_fill.is_some()
                    || !matches!(item.options.sort, None | Some(OrderBySort::Asc))
                    || item.options.nulls_first.is_some()
                {
                    return None;
                }
                let ord_idx = resolve_plain_col(rel, &qualifier, &item.expr)?;
                if shadowed_cols.contains(&ord_idx)
                    && matches!(unwrap_nested(&item.expr), Expr::Identifier(_))
                {
                    return None;
                }
                let col = &rel.columns[ord_idx];
                if col.data_type != SqlType::U64 || col.nullable {
                    return None;
                }
                cols.push(ord_idx);
            }
            cols
        }
    };

    Some(DirectTableProjection {
        relation: rel.name.clone(),
        projected_columns,
        order_by_u64_asc,
    })
}

/// Extract a filtered single-table projection with conjunctive equality/`IN` predicates and
/// optional multi-column `U64`/`I64`/`Text` `ORDER BY`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn extract_direct_filtered_projection(
    sql: &str,
    relations: &[SqlRelation],
    cte_names: &BTreeSet<String>,
    max_ast_depth: usize,
) -> Option<DirectFilteredProjection> {
    let root = parse_single_query(sql, max_ast_depth)?;
    extract_direct_filtered_projection_from_query(&root, relations, cte_names)
}

/// As [`extract_direct_filtered_projection`], reusing an already-parsed [`Query`] AST.
pub(crate) fn extract_direct_filtered_projection_from_query(
    root: &Query,
    relations: &[SqlRelation],
    cte_names: &BTreeSet<String>,
) -> Option<DirectFilteredProjection> {
    let (select, rel, qualifier) = extract_plain_single_table(root, relations, cte_names, true)?;
    if !has_empty_group_by(select) {
        return None;
    }
    let selection = select.selection.as_ref()?;

    let mut projected_columns = Vec::with_capacity(select.projection.len());
    let mut alias_targets: BTreeMap<String, Option<usize>> = BTreeMap::new();
    let mut shadowed_cols = BTreeSet::new();
    let mut record_alias = |name: &str, col_idx: usize, conflicting: bool| {
        let lower = name.to_ascii_lowercase();
        if conflicting {
            alias_targets.insert(lower, None);
            return;
        }
        if let Some(prev) = alias_targets.get_mut(&lower) {
            if *prev != Some(col_idx) {
                *prev = None;
            }
        } else {
            alias_targets.insert(lower, Some(col_idx));
        }
    };
    for item in &select.projection {
        match item {
            SelectItem::UnnamedExpr(expr) => {
                // Reject outer parenthesized `(col)` so SQLite output column naming never diverges.
                if matches!(expr, Expr::Nested(_)) {
                    return None;
                }
                let col_idx = resolve_plain_col(rel, &qualifier, expr)?;
                record_alias(&rel.columns[col_idx].name, col_idx, false);
                projected_columns.push((col_idx, rel.columns[col_idx].name.clone()));
            }
            SelectItem::ExprWithAlias { expr, alias } => {
                let col_idx = resolve_plain_col(rel, &qualifier, expr)?;
                let mut shadows = false;
                if let Some(other_idx) = rel
                    .columns
                    .iter()
                    .position(|c| c.name.eq_ignore_ascii_case(&alias.value))
                    && other_idx != col_idx
                {
                    shadowed_cols.insert(other_idx);
                    shadows = true;
                }
                record_alias(&alias.value, col_idx, shadows);
                projected_columns.push((col_idx, alias.value.clone()));
            }
            _ => return None,
        }
    }

    let mut predicates = Vec::new();
    let mut pending = vec![selection];
    while let Some(expr) = pending.pop() {
        match unwrap_nested(expr) {
            Expr::BinaryOp {
                left,
                op: BinaryOperator::And,
                right,
            } => {
                pending.push(right);
                pending.push(left);
            }
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } => {
                if predicates.len() >= 32 {
                    return None;
                }
                let (col_idx, lit) = if let Some(idx) = resolve_plain_col(rel, &qualifier, left) {
                    (idx, right)
                } else {
                    let idx = resolve_plain_col(rel, &qualifier, right)?;
                    (idx, left)
                };
                let pred = match rel.columns[col_idx].data_type {
                    SqlType::U64 => DirectPredicate::EqU64(col_idx, parse_u64_lit(lit)?),
                    SqlType::Text => DirectPredicate::EqText(col_idx, parse_text_lit(lit)?),
                    _ => return None,
                };
                predicates.push(pred);
            }
            Expr::InList {
                expr: target,
                list,
                negated: false,
            } => {
                if predicates.len() >= 32 || list.is_empty() {
                    return None;
                }
                let col_idx = resolve_plain_col(rel, &qualifier, target)?;
                let pred = match rel.columns[col_idx].data_type {
                    SqlType::U64 => DirectPredicate::InU64(
                        col_idx,
                        list.iter().map(parse_u64_lit).collect::<Option<Vec<_>>>()?,
                    ),
                    SqlType::Text => DirectPredicate::InText(
                        col_idx,
                        list.iter()
                            .map(parse_text_lit)
                            .collect::<Option<Vec<_>>>()?,
                    ),
                    _ => return None,
                };
                predicates.push(pred);
            }
            _ => return None,
        }
    }
    if predicates.is_empty() {
        return None;
    }

    let order_by = match &root.order_by {
        None => Vec::new(),
        Some(order) => {
            if order.interpolate.is_some() {
                return None;
            }
            let OrderByKind::Expressions(exprs) = &order.kind else {
                return None;
            };
            if exprs.is_empty() || exprs.len() > 4 {
                return None;
            }
            let mut items = Vec::with_capacity(exprs.len());
            for item in exprs {
                if item.with_fill.is_some() || item.options.nulls_first.is_some() {
                    return None;
                }
                let descending = match item.options.sort {
                    None | Some(OrderBySort::Asc) => false,
                    Some(OrderBySort::Desc) => true,
                    Some(OrderBySort::Using(_)) => return None,
                };
                let ord_idx = match unwrap_nested(&item.expr) {
                    Expr::Identifier(id) => {
                        let lower = id.value.to_ascii_lowercase();
                        if let Some(target) = alias_targets.get(&lower) {
                            (*target)?
                        } else {
                            let idx = resolve_plain_col(rel, &qualifier, &item.expr)?;
                            if shadowed_cols.contains(&idx) {
                                return None;
                            }
                            idx
                        }
                    }
                    _ => resolve_plain_col(rel, &qualifier, &item.expr)?,
                };
                if !matches!(
                    rel.columns[ord_idx].data_type,
                    SqlType::U64 | SqlType::I64 | SqlType::Text
                ) {
                    return None;
                }
                items.push(DirectOrderItem {
                    column: ord_idx,
                    descending,
                });
            }
            items
        }
    };

    let parse_i64_nonneg = |expr: &Expr| -> Option<u64> {
        let v = parse_u64_lit(expr)?;
        i64::try_from(v).ok()?;
        Some(v)
    };
    let (limit, offset) = match &root.limit_clause {
        None => (None, 0u64),
        Some(LimitClause::LimitOffset {
            limit,
            offset,
            limit_by,
        }) => {
            if !limit_by.is_empty() {
                return None;
            }
            let limit_val = match limit {
                Some(expr) => Some(parse_i64_nonneg(expr)?),
                None => return None,
            };
            let offset_val = match offset {
                None => 0u64,
                Some(off) => parse_i64_nonneg(&off.value)?,
            };
            (limit_val, offset_val)
        }
        Some(LimitClause::OffsetCommaLimit { offset, limit }) => {
            (Some(parse_i64_nonneg(limit)?), parse_i64_nonneg(offset)?)
        }
    };

    Some(DirectFilteredProjection {
        relation: rel.name.clone(),
        projected_columns,
        predicates,
        order_by,
        limit,
        offset,
    })
}

fn is_count_star(expr: &Expr) -> bool {
    let Expr::Function(func) = unwrap_nested(expr) else {
        return false;
    };
    if func.name.0.len() != 1
        || !func.name.0[0]
            .as_ident()
            .is_some_and(|id| id.value.eq_ignore_ascii_case("count"))
        || func.filter.is_some()
        || func.over.is_some()
        || !func.within_group.is_empty()
        || func.null_treatment.is_some()
        || func.uses_odbc_syntax
        || !matches!(func.parameters, FunctionArguments::None)
    {
        return false;
    }
    let FunctionArguments::List(list) = &func.args else {
        return false;
    };
    list.duplicate_treatment.is_none()
        && list.clauses.is_empty()
        && list.args.len() == 1
        && matches!(
            &list.args[0],
            FunctionArg::Unnamed(FunctionArgExpr::Wildcard)
        )
}

/// Extract a sound single-table unfiltered `GROUP BY <cols> COUNT(*) [ORDER BY <cols> ASC]`
/// fast path, excluding wrappers, CTEs, filters, HAVING, DISTINCT, LIMIT/OFFSET, or ambiguous aliases.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn extract_direct_count_group_by(
    sql: &str,
    relations: &[SqlRelation],
    cte_names: &BTreeSet<String>,
    max_ast_depth: usize,
) -> Option<DirectCountGroupBy> {
    let root = parse_single_query(sql, max_ast_depth)?;
    extract_direct_count_group_by_from_query(&root, relations, cte_names)
}

/// As [`extract_direct_count_group_by`], reusing an already-parsed [`Query`] AST.
pub(crate) fn extract_direct_count_group_by_from_query(
    root: &Query,
    relations: &[SqlRelation],
    cte_names: &BTreeSet<String>,
) -> Option<DirectCountGroupBy> {
    let (select, rel, qualifier) = extract_plain_single_table(root, relations, cte_names, false)?;
    if select.selection.is_some() {
        return None;
    }

    let resolve_col = |expr: &Expr| resolve_plain_col(rel, &qualifier, expr);

    let GroupByExpr::Expressions(group_exprs, modifiers) = &select.group_by else {
        return None;
    };
    if !modifiers.is_empty() || group_exprs.is_empty() || group_exprs.len() > 4 {
        return None;
    }
    let mut group_columns = Vec::with_capacity(group_exprs.len());
    for g in group_exprs {
        let col_idx = resolve_col(g)?;
        if !matches!(
            rel.columns[col_idx].data_type,
            SqlType::U64 | SqlType::I64 | SqlType::Text
        ) {
            return None;
        }
        if !group_columns.contains(&col_idx) {
            group_columns.push(col_idx);
        }
    }

    let mut projections = Vec::with_capacity(select.projection.len());
    let mut shadowed_cols = BTreeSet::new();
    let mut alias_targets: BTreeMap<String, Option<usize>> = BTreeMap::new();
    for item in &select.projection {
        match item {
            SelectItem::UnnamedExpr(expr) => {
                let col_idx = resolve_col(expr)?;
                let group_pos = group_columns.iter().position(|&c| c == col_idx)?;
                projections.push(DirectGroupItem::GroupCol {
                    group_pos,
                    output_name: rel.columns[col_idx].name.clone(),
                });
            }
            SelectItem::ExprWithAlias { expr, alias } => {
                let alias_lower = alias.value.to_ascii_lowercase();
                if is_count_star(expr) {
                    if let Some(other_idx) = rel
                        .columns
                        .iter()
                        .position(|c| c.name.eq_ignore_ascii_case(&alias.value))
                    {
                        shadowed_cols.insert(other_idx);
                    }
                    alias_targets.insert(alias_lower, None);
                    projections.push(DirectGroupItem::CountStar {
                        output_name: alias.value.clone(),
                    });
                } else {
                    let col_idx = resolve_col(expr)?;
                    let group_pos = group_columns.iter().position(|&c| c == col_idx)?;
                    if let Some(other_idx) = rel
                        .columns
                        .iter()
                        .position(|c| c.name.eq_ignore_ascii_case(&alias.value))
                        && other_idx != col_idx
                    {
                        shadowed_cols.insert(other_idx);
                    }
                    alias_targets.insert(alias_lower, Some(col_idx));
                    projections.push(DirectGroupItem::GroupCol {
                        group_pos,
                        output_name: alias.value.clone(),
                    });
                }
            }
            _ => return None,
        }
    }

    let order_by_group_asc = match &root.order_by {
        None => Vec::new(),
        Some(order) => {
            if order.interpolate.is_some() {
                return None;
            }
            let OrderByKind::Expressions(exprs) = &order.kind else {
                return None;
            };
            if exprs.is_empty() || exprs.len() > 4 {
                return None;
            }
            let mut cols = Vec::with_capacity(exprs.len());
            for item in exprs {
                if item.with_fill.is_some()
                    || !matches!(item.options.sort, None | Some(OrderBySort::Asc))
                    || item.options.nulls_first.is_some()
                {
                    return None;
                }
                let ord_idx = match unwrap_nested(&item.expr) {
                    Expr::Identifier(id) => {
                        let lower = id.value.to_ascii_lowercase();
                        if let Some(target) = alias_targets.get(&lower) {
                            (*target)?
                        } else {
                            let idx = resolve_col(&item.expr)?;
                            if shadowed_cols.contains(&idx) {
                                return None;
                            }
                            idx
                        }
                    }
                    _ => resolve_col(&item.expr)?,
                };
                let group_pos = group_columns.iter().position(|&c| c == ord_idx)?;
                cols.push(group_pos);
            }
            cols
        }
    };

    Some(DirectCountGroupBy {
        relation: rel.name.clone(),
        group_columns,
        projections,
        order_by_group_asc,
    })
}

#[derive(Default, Clone, Debug)]
pub(crate) struct QueryHints {
    pub row_filters: BTreeMap<String, RowFilter>,
    pub equi_joins: Vec<EquiJoinEdge>,
}

/// Extract sound single-table candidate filters and inner equi-join edges from `root`.
/// Handles pure outer `SELECT ... FROM (<inner>) AS alias` wrappers (such as `B0Session`'s
/// shape/hex wrappers) while refusing any relation mentioned more than once or shadowed by a CTE.
pub(crate) fn query_hints(root: &Query, relations: &[SqlRelation]) -> QueryHints {
    if relations.is_empty() || has_zero_limit(root) {
        return QueryHints::default();
    }
    let schema_types: BTreeMap<String, BTreeMap<String, SqlType>> = relations
        .iter()
        .map(|rel| {
            let cols = rel
                .columns
                .iter()
                .map(|c| (c.name.to_ascii_lowercase(), c.data_type))
                .collect();
            (rel.name.to_ascii_lowercase(), cols)
        })
        .collect();

    let inner = unwrap_outer_wrapper(root);
    if has_zero_limit(inner) || inner.with.is_some() {
        return QueryHints::default();
    }
    let (table_mentions, cte_names) = count_table_mentions(root);
    let SetExpr::Select(select) = &*inner.body else {
        return QueryHints::default();
    };
    if select.from.is_empty() {
        return QueryHints::default();
    }

    let mut tables_by_qualifier: BTreeMap<String, String> = BTreeMap::new();
    let mut all_plain_factors = true;
    let mut all_inner = true;
    let mut left_outer_only = select.from.len() == 1;
    let mut leftmost_relation: Option<String> = None;

    for (from_idx, from) in select.from.iter().enumerate() {
        let mut register_factor = |factor: &TableFactor, is_leftmost: bool| {
            let TableFactor::Table {
                name,
                alias,
                args: None,
                ..
            } = factor
            else {
                all_plain_factors = false;
                return false;
            };
            if name.0.len() != 1 {
                all_plain_factors = false;
                return false;
            }
            let Some(ident) = name.0[0].as_ident() else {
                all_plain_factors = false;
                return false;
            };
            let rel_name = ident.value.to_ascii_lowercase();
            let qual = alias
                .as_ref()
                .map_or_else(|| rel_name.clone(), |a| a.name.value.to_ascii_lowercase());
            if cte_names.contains(&rel_name)
                || !schema_types.contains_key(&rel_name)
                || table_mentions.get(&rel_name) != Some(&1)
                || tables_by_qualifier.insert(qual, rel_name.clone()).is_some()
            {
                return false;
            }
            if is_leftmost {
                leftmost_relation = Some(rel_name);
            }
            true
        };

        if !register_factor(&from.relation, from_idx == 0) {
            return QueryHints::default();
        }
        for join in &from.joins {
            match &join.join_operator {
                JoinOperator::Join(c) | JoinOperator::Inner(c) | JoinOperator::CrossJoin(c) => {
                    if matches!(c, JoinConstraint::Natural) {
                        return QueryHints::default();
                    }
                }
                JoinOperator::Left(c) | JoinOperator::LeftOuter(c) => {
                    all_inner = false;
                    if matches!(c, JoinConstraint::Natural) {
                        return QueryHints::default();
                    }
                }
                _ => {
                    all_inner = false;
                    left_outer_only = false;
                }
            }
            if !register_factor(&join.relation, false) {
                return QueryHints::default();
            }
        }
    }

    if !all_inner && !left_outer_only {
        return QueryHints::default();
    }

    let only_table = if all_plain_factors && tables_by_qualifier.len() == 1 {
        tables_by_qualifier.values().next().cloned()
    } else {
        None
    };

    let ctx = ResolveCtx {
        schema_types: &schema_types,
        tables_by_qualifier: &tables_by_qualifier,
        only_table: only_table.as_deref(),
        all_plain_factors,
    };

    let mut conjunct_roots: Vec<&Expr> = Vec::new();
    if let Some(sel) = &select.selection {
        conjunct_roots.push(sel);
    }
    if all_inner {
        for from in &select.from {
            for join in &from.joins {
                let constraint = match &join.join_operator {
                    JoinOperator::Join(c) | JoinOperator::Inner(c) | JoinOperator::CrossJoin(c) => {
                        Some(c)
                    }
                    _ => None,
                };
                if let Some(JoinConstraint::On(expr)) = constraint {
                    conjunct_roots.push(expr);
                }
            }
        }
    }

    let mut pending = conjunct_roots;
    let mut per_table_filters: BTreeMap<String, Vec<RowFilter>> = BTreeMap::new();
    let mut join_pairs: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();

    while let Some(expr) = pending.pop() {
        let expr = unwrap_nested(expr);
        if let Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } = expr
        {
            pending.push(right);
            pending.push(left);
            continue;
        }
        if all_inner
            && let Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } = expr
            && let (Some((r1, c1, t1)), Some((r2, c2, t2))) =
                (ctx.resolve_col(left), ctx.resolve_col(right))
            && r1 != r2
            && t1 == t2
            && matches!(t1, SqlType::U64 | SqlType::Text)
        {
            let ((lr, lc), (rr, rc)) = if r1 < r2 {
                ((r1, c1), (r2, c2))
            } else {
                ((r2, c2), (r1, c1))
            };
            let cols = join_pairs.entry((lr, rr)).or_default();
            if !cols
                .iter()
                .any(|existing| existing == &(lc.clone(), rc.clone()))
            {
                cols.push((lc, rc));
            }
            continue;
        }
        if let Some((rel, filter)) = extract_single_table_filter(&ctx, expr, 0)
            && (all_inner || leftmost_relation.as_deref() == Some(rel.as_str()))
        {
            per_table_filters.entry(rel).or_default().push(filter);
        }
    }

    let row_filters = per_table_filters
        .into_iter()
        .map(|(rel, mut list)| {
            let combined = if list.len() == 1 {
                list.pop().unwrap()
            } else {
                RowFilter::And(list)
            };
            (rel, combined)
        })
        .collect();
    let equi_joins = if all_inner {
        join_pairs
            .into_iter()
            .map(|((left_relation, right_relation), columns)| EquiJoinEdge {
                left_relation,
                right_relation,
                columns,
            })
            .collect()
    } else {
        Vec::new()
    };
    QueryHints {
        row_filters,
        equi_joins,
    }
}

fn unwrap_nested(mut expr: &Expr) -> &Expr {
    while let Expr::Nested(inner) = expr {
        expr = inner;
    }
    expr
}

fn has_zero_limit(query: &Query) -> bool {
    match &query.limit_clause {
        Some(LimitClause::LimitOffset {
            limit: Some(limit), ..
        })
        | Some(LimitClause::OffsetCommaLimit { limit, .. }) => parse_u64_lit(limit) == Some(0),
        _ => false,
    }
}

fn unwrap_outer_wrapper(mut query: &Query) -> &Query {
    for _ in 0..8 {
        if query.with.is_some() {
            break;
        }
        let SetExpr::Select(select) = &*query.body else {
            break;
        };
        let empty_group = matches!(
            &select.group_by,
            GroupByExpr::Expressions(exprs, modifiers) if exprs.is_empty() && modifiers.is_empty()
        );
        if select.distinct.is_some()
            || select.top.is_some()
            || select.into.is_some()
            || !select.lateral_views.is_empty()
            || select.prewhere.is_some()
            || select.selection.is_some()
            || !empty_group
            || !select.cluster_by.is_empty()
            || !select.distribute_by.is_empty()
            || !select.sort_by.is_empty()
            || select.having.is_some()
            || select.qualify.is_some()
            || select.from.len() != 1
            || !select.from[0].joins.is_empty()
        {
            break;
        }
        let TableFactor::Derived {
            lateral: false,
            subquery,
            ..
        } = &select.from[0].relation
        else {
            break;
        };
        query = subquery;
    }
    query
}

fn count_table_mentions(root: &Query) -> (BTreeMap<String, usize>, BTreeSet<String>) {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut ctes: BTreeSet<String> = BTreeSet::new();
    let mut queries: Vec<&Query> = vec![root];
    let mut exprs: Vec<&Expr> = Vec::new();
    let mut set_exprs: Vec<&SetExpr> = Vec::new();

    while !queries.is_empty() || !set_exprs.is_empty() || !exprs.is_empty() {
        while let Some(q) = queries.pop() {
            if let Some(with) = &q.with {
                for cte in &with.cte_tables {
                    ctes.insert(cte.alias.name.value.to_ascii_lowercase());
                    queries.push(&cte.query);
                }
            }
            set_exprs.push(&q.body);
        }
        while let Some(se) = set_exprs.pop() {
            match se {
                SetExpr::Select(sel) => {
                    for item in &sel.projection {
                        match item {
                            SelectItem::UnnamedExpr(e)
                            | SelectItem::ExprWithAlias { expr: e, .. } => {
                                exprs.push(e);
                            }
                            _ => {}
                        }
                    }
                    if let Some(e) = &sel.selection {
                        exprs.push(e);
                    }
                    if let Some(e) = &sel.having {
                        exprs.push(e);
                    }
                    for from in &sel.from {
                        let mut factors: Vec<&TableFactor> = std::iter::once(&from.relation)
                            .chain(from.joins.iter().map(|j| &j.relation))
                            .collect();
                        for join in &from.joins {
                            let c = match &join.join_operator {
                                JoinOperator::Join(c)
                                | JoinOperator::Inner(c)
                                | JoinOperator::Left(c)
                                | JoinOperator::LeftOuter(c)
                                | JoinOperator::Right(c)
                                | JoinOperator::RightOuter(c)
                                | JoinOperator::FullOuter(c)
                                | JoinOperator::CrossJoin(c) => Some(c),
                                _ => None,
                            };
                            if let Some(JoinConstraint::On(e)) = c {
                                exprs.push(e);
                            }
                        }
                        while let Some(f) = factors.pop() {
                            match f {
                                TableFactor::Table { name, .. } => {
                                    if name.0.len() == 1
                                        && let Some(id) = name.0[0].as_ident()
                                    {
                                        *counts
                                            .entry(id.value.to_ascii_lowercase())
                                            .or_insert(0) += 1;
                                    }
                                }
                                TableFactor::Derived { subquery, .. } => queries.push(subquery),
                                TableFactor::NestedJoin {
                                    table_with_joins, ..
                                } => {
                                    factors.push(&table_with_joins.relation);
                                    for j in &table_with_joins.joins {
                                        factors.push(&j.relation);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                SetExpr::Query(q) => queries.push(q),
                SetExpr::SetOperation { left, right, .. } => {
                    set_exprs.push(left);
                    set_exprs.push(right);
                }
                _ => {}
            }
        }
        while let Some(e) = exprs.pop() {
            match e {
                Expr::Nested(inner)
                | Expr::UnaryOp { expr: inner, .. }
                | Expr::IsNull(inner)
                | Expr::IsNotNull(inner)
                | Expr::Cast { expr: inner, .. } => exprs.push(inner),
                Expr::BinaryOp { left, right, .. } => {
                    exprs.push(left);
                    exprs.push(right);
                }
                Expr::Between {
                    expr: child,
                    low,
                    high,
                    ..
                } => {
                    exprs.push(child);
                    exprs.push(low);
                    exprs.push(high);
                }
                Expr::InList {
                    expr: child, list, ..
                } => {
                    exprs.push(child);
                    exprs.extend(list.iter());
                }
                Expr::InSubquery {
                    expr: child,
                    subquery,
                    ..
                } => {
                    exprs.push(child);
                    queries.push(subquery);
                }
                Expr::Subquery(subquery) | Expr::Exists { subquery, .. } => {
                    queries.push(subquery);
                }
                Expr::Case {
                    operand,
                    conditions,
                    else_result,
                    ..
                } => {
                    if let Some(op) = operand {
                        exprs.push(op);
                    }
                    for when in conditions {
                        exprs.push(&when.condition);
                        exprs.push(&when.result);
                    }
                    if let Some(els) = else_result {
                        exprs.push(els);
                    }
                }
                Expr::Function(func) => {
                    if let FunctionArguments::List(list) = &func.args {
                        for arg in &list.args {
                            match arg {
                                FunctionArg::Unnamed(FunctionArgExpr::Expr(a))
                                | FunctionArg::Named {
                                    arg: FunctionArgExpr::Expr(a),
                                    ..
                                } => exprs.push(a),
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    (counts, ctes)
}

struct ResolveCtx<'a> {
    schema_types: &'a BTreeMap<String, BTreeMap<String, SqlType>>,
    tables_by_qualifier: &'a BTreeMap<String, String>,
    only_table: Option<&'a str>,
    all_plain_factors: bool,
}

impl ResolveCtx<'_> {
    fn resolve_col(&self, expr: &Expr) -> Option<(String, String, SqlType)> {
        match unwrap_nested(expr) {
            Expr::CompoundIdentifier(parts) if parts.len() == 2 => {
                let qual = parts[0].value.to_ascii_lowercase();
                let col = parts[1].value.to_ascii_lowercase();
                let rel = self.tables_by_qualifier.get(&qual)?.clone();
                let ty = *self.schema_types.get(&rel)?.get(&col)?;
                Some((rel, col, ty))
            }
            Expr::Identifier(ident) => {
                let col = ident.value.to_ascii_lowercase();
                if let Some(only) = self.only_table {
                    let ty = *self.schema_types.get(only)?.get(&col)?;
                    return Some((only.to_owned(), col, ty));
                }
                if !self.all_plain_factors {
                    return None;
                }
                let mut found: Option<(String, SqlType)> = None;
                for rel in self.tables_by_qualifier.values() {
                    if let Some(&ty) = self.schema_types.get(rel).and_then(|m| m.get(&col)) {
                        if found.is_some() {
                            return None;
                        }
                        found = Some((rel.clone(), ty));
                    }
                }
                found.map(|(rel, ty)| (rel, col, ty))
            }
            _ => None,
        }
    }
}

fn parse_u64_lit(expr: &Expr) -> Option<u64> {
    let Expr::Value(val) = unwrap_nested(expr) else {
        return None;
    };
    let Value::Number(text, false) = &val.value else {
        return None;
    };
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>().ok()
}

fn parse_text_lit(expr: &Expr) -> Option<String> {
    let Expr::Value(val) = unwrap_nested(expr) else {
        return None;
    };
    let Value::SingleQuotedString(text) = &val.value else {
        return None;
    };
    Some(text.clone())
}

fn flatten_bool_chain(expr: &Expr, target: BinaryOperator) -> Vec<&Expr> {
    let mut out = Vec::new();
    let mut stack = vec![expr];
    while let Some(cur) = stack.pop() {
        let cur = unwrap_nested(cur);
        if let Expr::BinaryOp { left, op, right } = cur
            && *op == target
        {
            stack.push(right);
            stack.push(left);
            continue;
        }
        out.push(cur);
    }
    out
}

const MAX_HINT_DEPTH: usize = 32;

fn extract_single_table_filter(
    ctx: &ResolveCtx<'_>,
    expr: &Expr,
    depth: usize,
) -> Option<(String, RowFilter)> {
    if depth > MAX_HINT_DEPTH {
        return None;
    }
    let expr = unwrap_nested(expr);
    match expr {
        Expr::BinaryOp {
            op: BinaryOperator::And,
            ..
        } => {
            let parts = flatten_bool_chain(expr, BinaryOperator::And);
            let mut by_rel: BTreeMap<String, Vec<RowFilter>> = BTreeMap::new();
            for part in parts {
                if let Some((rel, f)) = extract_single_table_filter(ctx, part, depth + 1) {
                    by_rel.entry(rel).or_default().push(f);
                }
            }
            if by_rel.len() != 1 {
                return None;
            }
            let (rel, mut fs) = by_rel.into_iter().next().unwrap();
            let f = if fs.len() == 1 {
                fs.pop().unwrap()
            } else {
                RowFilter::And(fs)
            };
            Some((rel, f))
        }
        Expr::BinaryOp {
            op: BinaryOperator::Or,
            ..
        } => {
            let parts = flatten_bool_chain(expr, BinaryOperator::Or);
            let mut target_rel: Option<String> = None;
            let mut filters = Vec::with_capacity(parts.len());
            for part in parts {
                let (rel, f) = extract_single_table_filter(ctx, part, depth + 1)?;
                match &target_rel {
                    Some(prev) if prev != &rel => return None,
                    None => target_rel = Some(rel),
                    _ => {}
                }
                filters.push(f);
            }
            Some((target_rel?, RowFilter::Or(filters)))
        }
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => {
            if let Some((rel, col, ty)) = ctx.resolve_col(left) {
                match ty {
                    SqlType::U64 => parse_u64_lit(right).map(|v| (rel, RowFilter::EqU64(col, v))),
                    SqlType::Text => {
                        parse_text_lit(right).map(|v| (rel, RowFilter::EqText(col, v)))
                    }
                    _ => None,
                }
            } else if let Some((rel, col, ty)) = ctx.resolve_col(right) {
                match ty {
                    SqlType::U64 => parse_u64_lit(left).map(|v| (rel, RowFilter::EqU64(col, v))),
                    SqlType::Text => parse_text_lit(left).map(|v| (rel, RowFilter::EqText(col, v))),
                    _ => None,
                }
            } else {
                None
            }
        }
        Expr::InList {
            expr: child,
            list,
            negated: false,
        } => {
            let (rel, col, ty) = ctx.resolve_col(child)?;
            match ty {
                SqlType::U64 => {
                    let vals = list.iter().map(parse_u64_lit).collect::<Option<Vec<_>>>()?;
                    Some((rel, RowFilter::InU64(col, vals)))
                }
                SqlType::Text => {
                    let vals = list
                        .iter()
                        .map(parse_text_lit)
                        .collect::<Option<Vec<_>>>()?;
                    Some((rel, RowFilter::InText(col, vals)))
                }
                _ => None,
            }
        }
        Expr::Between {
            expr: child,
            negated: false,
            low,
            high,
        } => {
            let (rel, col, ty) = ctx.resolve_col(child)?;
            if ty != SqlType::U64 {
                return None;
            }
            let lo = parse_u64_lit(low)?;
            let hi = parse_u64_lit(high)?;
            Some((rel, RowFilter::BetweenU64(col, lo, hi)))
        }
        Expr::Like {
            negated: false,
            any: false,
            expr: child,
            pattern,
            escape_char,
        } => {
            let (rel, col, ty) = ctx.resolve_col(child)?;
            if ty != SqlType::Text {
                return None;
            }
            let pat = parse_text_lit(pattern)?;
            let esc = match escape_char {
                Some(esc_expr) => {
                    let s = parse_text_lit(esc_expr)?;
                    let mut chars = s.chars();
                    let ch = chars.next()?;
                    if chars.next().is_some() || ch.len_utf16() != 1 {
                        return None;
                    }
                    Some(ch)
                }
                None => None,
            };
            let scan_opt =
                std::env::var_os("MDD_OPT_SQL_SCAN").as_deref() != Some(std::ffi::OsStr::new("0"));
            if let Some((prefix, suffix)) = extract_ascii_like_prefix_and_suffix(&pat, esc) {
                if let Some(suffix) = suffix
                    && scan_opt
                {
                    Some((rel, RowFilter::LikeAsciiPrefixSuffix(col, prefix, suffix)))
                } else {
                    Some((rel, RowFilter::LikeAsciiPrefix(col, prefix)))
                }
            } else if scan_opt && let Some(needle) = extract_ascii_like_contains(&pat, esc) {
                Some((rel, RowFilter::LikeAsciiContains(col, needle)))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn extract_ascii_like_prefix_and_suffix(
    pattern: &str,
    escape: Option<char>,
) -> Option<(String, Option<String>)> {
    let mut prefix = String::new();
    let mut suffix = String::new();
    let mut in_prefix = true;
    let mut after_percent = false;
    let mut chars = pattern.chars();
    while let Some(ch) = chars.next() {
        if Some(ch) == escape {
            let escaped = chars.next()?;
            if in_prefix {
                prefix.push(escaped);
            } else if after_percent {
                suffix.push(escaped);
            }
        } else if ch == '%' {
            in_prefix = false;
            after_percent = true;
            suffix.clear();
        } else if ch == '_' {
            in_prefix = false;
            after_percent = false;
            suffix.clear();
        } else if in_prefix {
            prefix.push(ch);
        } else if after_percent {
            suffix.push(ch);
        }
    }
    if prefix.is_empty() || !prefix.is_ascii() {
        return None;
    }
    prefix.make_ascii_lowercase();
    let suffix = if after_percent && !suffix.is_empty() && suffix.is_ascii() {
        suffix.make_ascii_lowercase();
        Some(suffix)
    } else {
        None
    };
    Some((prefix, suffix))
}

fn extract_ascii_like_contains(pattern: &str, escape: Option<char>) -> Option<String> {
    let mut chars = pattern.chars().peekable();
    let mut saw_leading = false;
    while let Some(&ch) = chars.peek() {
        if Some(ch) != escape && ch == '%' {
            saw_leading = true;
            chars.next();
        } else {
            break;
        }
    }
    if !saw_leading {
        return None;
    }
    let mut needle = String::new();
    let mut saw_trailing = false;
    while let Some(ch) = chars.next() {
        if Some(ch) == escape {
            let escaped = chars.next()?;
            if saw_trailing {
                return None;
            }
            needle.push(escaped);
        } else if ch == '_' {
            return None;
        } else if ch == '%' {
            saw_trailing = true;
        } else {
            if saw_trailing {
                return None;
            }
            needle.push(ch);
        }
    }
    if !saw_trailing || needle.is_empty() || !needle.is_ascii() {
        return None;
    }
    needle.make_ascii_lowercase();
    Some(needle)
}

/// `partition_columns` maps a relation name (lower case) to its partition column (lower case). The result maps a relation
/// name (lower case) to the value its partition column must have.
pub(crate) fn partition_hints(
    query: &Query,
    tokens: &[Token],
    partition_columns: &BTreeMap<String, String>,
) -> BTreeMap<String, u64> {
    let mut hints = BTreeMap::new();
    if partition_columns.is_empty() {
        return hints;
    }
    let SetExpr::Select(select) = &*query.body else {
        return hints;
    };
    let Some(selection) = &select.selection else {
        return hints;
    };
    // the plain tables of the outermost FROM, by the name a column is qualified with
    let mut tables: Vec<(String, String)> = Vec::new();
    for from in &select.from {
        for factor in std::iter::once(&from.relation).chain(from.joins.iter().map(|j| &j.relation))
        {
            if let TableFactor::Table {
                name,
                alias,
                args: None,
                ..
            } = factor
                && name.0.len() == 1
                && let Some(ident) = name.0[0].as_ident()
            {
                let relation = ident.value.to_ascii_lowercase();
                let qualifier = alias.as_ref().map_or_else(
                    || relation.clone(),
                    |alias| alias.name.value.to_ascii_lowercase(),
                );
                tables.push((relation, qualifier));
            }
        }
    }
    let only_table = tables.len() == 1 && select.from.len() == 1 && select.from[0].joins.is_empty();
    // the conjuncts of the WHERE, without recursion: a statement may be a long chain
    let mut pending = vec![selection];
    let mut conflicting: Vec<String> = Vec::new();
    while let Some(expr) = pending.pop() {
        match expr {
            Expr::Nested(inner) => pending.push(inner),
            Expr::BinaryOp {
                left,
                op: BinaryOperator::And,
                right,
            } => {
                pending.push(left);
                pending.push(right);
            }
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } => {
                let Some((column, value)) =
                    column_and_number(left, right).or_else(|| column_and_number(right, left))
                else {
                    continue;
                };
                let relation = match column {
                    Column::Qualified(qualifier, name) => tables
                        .iter()
                        .find(|(_, candidate)| *candidate == qualifier)
                        .map(|(relation, _)| (relation.clone(), name)),
                    Column::Bare(name) if only_table => Some((tables[0].0.clone(), name)),
                    Column::Bare(_) => None,
                };
                let Some((relation, name)) = relation else {
                    continue;
                };
                if partition_columns.get(&relation) != Some(&name) {
                    continue;
                }
                match hints.insert(relation.clone(), value) {
                    Some(previous) if previous != value => conflicting.push(relation),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    for relation in conflicting {
        hints.remove(&relation);
    }
    // the relation must be named once in the whole statement; anything else may use its other rows. A name followed by a
    // period is a qualifier of a column (`classes.file_id`), not a mention of the table.
    hints.retain(|relation, _| mentions(tokens, relation) == 1);
    hints
}

/// How many times `name` appears in the statement other than as the qualifier of a column.
fn mentions(tokens: &[Token], name: &str) -> usize {
    tokens
        .iter()
        .enumerate()
        .filter(|(at, token)| {
            matches!(token, Token::Word(word) if word.value.eq_ignore_ascii_case(name))
                && tokens[at + 1..]
                    .iter()
                    .find(|next| !matches!(next, Token::Whitespace(_)))
                    != Some(&Token::Period)
        })
        .count()
}

enum Column {
    Bare(String),
    Qualified(String, String),
}

/// `column = number` with `column` a plain (possibly qualified) name and `number` a non-negative integer literal.
fn column_and_number(column: &Expr, number: &Expr) -> Option<(Column, u64)> {
    let value = match number {
        Expr::Value(value) => match &value.value {
            Value::Number(text, false) if text.bytes().all(|b| b.is_ascii_digit()) => {
                text.parse::<u64>().ok()?
            }
            _ => return None,
        },
        _ => return None,
    };
    let column = match column {
        Expr::Identifier(ident) => Column::Bare(ident.value.to_ascii_lowercase()),
        Expr::CompoundIdentifier(parts) if parts.len() == 2 => Column::Qualified(
            parts[0].value.to_ascii_lowercase(),
            parts[1].value.to_ascii_lowercase(),
        ),
        _ => return None,
    };
    Some((column, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlparser::{ast::Statement, dialect::SQLiteDialect, parser::Parser, tokenizer::Tokenizer};

    fn hints(sql: &str) -> BTreeMap<String, u64> {
        let dialect = SQLiteDialect {};
        let tokens = Tokenizer::new(&dialect, sql).tokenize().unwrap();
        let statements = Parser::parse_sql(&dialect, sql).unwrap();
        let Statement::Query(query) = &statements[0] else {
            panic!("not a query");
        };
        let columns: BTreeMap<String, String> = ["classes", "class_methods", "method_calls"]
            .into_iter()
            .map(|name| (name.to_owned(), "file_id".to_owned()))
            .collect();
        partition_hints(query, &tokens, &columns)
    }

    fn one(relation: &str, value: u64) -> BTreeMap<String, u64> {
        BTreeMap::from([(relation.to_owned(), value)])
    }

    #[test]
    fn a_conjunct_that_requires_one_value_of_the_column_is_found() {
        for sql in [
            "SELECT * FROM classes WHERE file_id = 3",
            "SELECT * FROM classes WHERE 3 = file_id",
            "SELECT * FROM classes WHERE FILE_ID = 3 AND descriptor LIKE 'La%'",
            "SELECT * FROM classes WHERE descriptor LIKE 'La%' AND (file_id = 3)",
            "SELECT * FROM classes WHERE a = 1 AND (b = 2 AND (file_id = 3 AND c = 4))",
            "SELECT * FROM classes c WHERE c.file_id = 3",
            "SELECT * FROM classes AS c JOIN class_methods m ON m.class_idx = c.class_idx WHERE c.file_id = 3",
            "SELECT * FROM classes c LEFT JOIN class_methods m ON m.class_idx = c.class_idx WHERE c.file_id = 3 ORDER BY 1",
            "WITH x AS (SELECT 1) SELECT * FROM classes, x WHERE classes.file_id = 3",
        ] {
            assert_eq!(hints(sql), one("classes", 3), "{sql}");
        }
        assert_eq!(
            hints(
                "SELECT * FROM classes c JOIN class_methods m ON m.class_idx = c.class_idx WHERE c.file_id = 3 AND m.file_id = 3"
            ),
            BTreeMap::from([("classes".to_owned(), 3), ("class_methods".to_owned(), 3)])
        );
    }

    #[test]
    fn nothing_is_claimed_when_the_statement_could_use_other_rows() {
        for sql in [
            // not a conjunct that requires it
            "SELECT * FROM classes WHERE file_id = 3 OR descriptor = 'x'",
            "SELECT * FROM classes WHERE NOT (file_id = 3)",
            "SELECT * FROM classes WHERE file_id <> 3",
            "SELECT * FROM classes WHERE file_id >= 3",
            "SELECT * FROM classes WHERE file_id = 3 + 0",
            "SELECT * FROM classes WHERE file_id = -3",
            "SELECT * FROM classes WHERE file_id = 3.0",
            "SELECT * FROM classes WHERE file_id = '3'",
            "SELECT * FROM classes WHERE file_id = ?",
            "SELECT * FROM classes WHERE file_id = other",
            "SELECT * FROM classes WHERE file_id = 3 AND file_id = 4",
            "SELECT * FROM classes",
            // another column
            "SELECT * FROM classes WHERE class_idx = 3",
            // the relation is named more than once, so another use of it may need other rows
            "SELECT * FROM classes WHERE file_id = 3 AND class_idx IN (SELECT class_idx FROM classes)",
            "SELECT * FROM classes a JOIN classes b ON a.class_idx = b.class_idx WHERE a.file_id = 3",
            "WITH x AS (SELECT * FROM classes) SELECT * FROM classes WHERE file_id = 3",
            // the column is not the relation's
            "SELECT * FROM classes c JOIN class_methods m ON 1 = 1 WHERE file_id = 3",
            "SELECT * FROM classes c WHERE d.file_id = 3",
            // not a plain SELECT
            "SELECT * FROM classes WHERE file_id = 3 UNION SELECT * FROM classes WHERE file_id = 4",
            // the equality is inside a subquery or a derived table, not the outermost WHERE
            "SELECT * FROM (SELECT * FROM classes WHERE file_id = 3) t",
            "SELECT * FROM classes WHERE class_idx IN (SELECT 1 FROM class_methods WHERE file_id = 3)",
        ] {
            let found = hints(sql);
            assert!(found.is_empty(), "{sql}: {found:?}");
        }
    }

    #[test]
    fn query_hints_unwraps_b0_wrappers_and_extracts_filters_and_equi_joins() {
        let rels = vec![
            SqlRelation {
                name: "classes".to_owned(),
                columns: vec![
                    crate::provider::SqlColumn {
                        id: "file_id".into(),
                        name: "file_id".into(),
                        data_type: SqlType::U64,
                        nullable: false,
                    },
                    crate::provider::SqlColumn {
                        id: "class_idx".into(),
                        name: "class_idx".into(),
                        data_type: SqlType::U64,
                        nullable: false,
                    },
                    crate::provider::SqlColumn {
                        id: "descriptor".into(),
                        name: "descriptor".into(),
                        data_type: SqlType::Text,
                        nullable: false,
                    },
                ],
                required_layers: vec![],
                estimated_rows: None,
            },
            SqlRelation {
                name: "class_interfaces".to_owned(),
                columns: vec![
                    crate::provider::SqlColumn {
                        id: "file_id".into(),
                        name: "file_id".into(),
                        data_type: SqlType::U64,
                        nullable: false,
                    },
                    crate::provider::SqlColumn {
                        id: "class_idx".into(),
                        name: "class_idx".into(),
                        data_type: SqlType::U64,
                        nullable: false,
                    },
                    crate::provider::SqlColumn {
                        id: "interface_descriptor".into(),
                        name: "interface_descriptor".into(),
                        data_type: SqlType::Text,
                        nullable: false,
                    },
                ],
                required_layers: vec![],
                estimated_rows: None,
            },
        ];
        let inner = "SELECT ci.interface_descriptor,c.descriptor FROM class_interfaces ci JOIN classes c ON c.file_id=ci.file_id AND c.class_idx=ci.class_idx WHERE c.descriptor IN ('La;','Lb;') ORDER BY ci.file_id,ci.class_idx";
        let wrapped = format!(
            "SELECT CASE WHEN interface_descriptor IS NULL THEN 'N' ELSE hex(CAST(interface_descriptor AS TEXT)) END AS interface_descriptor FROM ({inner}) AS hostlab_rows"
        );
        let stmts = sqlparser::parser::Parser::parse_sql(&SQLiteDialect {}, &wrapped).unwrap();
        let sqlparser::ast::Statement::Query(q) = &stmts[0] else {
            panic!("not a query");
        };
        let extracted = query_hints(q, &rels);
        assert_eq!(
            extracted.row_filters.get("classes"),
            Some(&RowFilter::InText(
                "descriptor".to_owned(),
                vec!["La;".to_owned(), "Lb;".to_owned()]
            ))
        );
        assert_eq!(extracted.equi_joins.len(), 1);
        assert_eq!(extracted.equi_joins[0].left_relation, "class_interfaces");
        assert_eq!(extracted.equi_joins[0].right_relation, "classes");
        assert_eq!(
            extracted.equi_joins[0].columns,
            vec![
                ("file_id".to_owned(), "file_id".to_owned()),
                ("class_idx".to_owned(), "class_idx".to_owned()),
            ]
        );

        let prefix_or = "SELECT descriptor FROM classes WHERE descriptor = 'La;' OR descriptor LIKE 'Lb\\_c\\%d\\\\e%' ESCAPE '\\'";
        let stmts_p = sqlparser::parser::Parser::parse_sql(&SQLiteDialect {}, prefix_or).unwrap();
        let sqlparser::ast::Statement::Query(qp) = &stmts_p[0] else {
            panic!("not a query");
        };
        assert_eq!(
            query_hints(qp, &rels).row_filters.get("classes"),
            Some(&RowFilter::Or(vec![
                RowFilter::EqText("descriptor".to_owned(), "La;".to_owned()),
                RowFilter::LikeAsciiPrefix("descriptor".to_owned(), "lb_c%d\\e".to_owned()),
            ]))
        );

        let contains_or =
            "SELECT descriptor FROM classes WHERE descriptor = 'La;' OR descriptor LIKE '%Lb%'";
        let stmts_c = sqlparser::parser::Parser::parse_sql(&SQLiteDialect {}, contains_or).unwrap();
        let sqlparser::ast::Statement::Query(qc) = &stmts_c[0] else {
            panic!("not a query");
        };
        assert_eq!(
            query_hints(qc, &rels).row_filters.get("classes"),
            Some(&RowFilter::Or(vec![
                RowFilter::EqText("descriptor".to_owned(), "La;".to_owned()),
                RowFilter::LikeAsciiContains("descriptor".to_owned(), "lb".to_owned()),
            ]))
        );

        for unpushable in [
            "SELECT descriptor FROM classes WHERE descriptor = 'La;' OR descriptor LIKE '_Lb%'",
            "SELECT descriptor FROM classes WHERE descriptor LIKE '%'",
            "SELECT descriptor FROM classes WHERE descriptor LIKE '%a_b%'",
            "SELECT descriptor FROM classes WHERE descriptor LIKE '%a%b%'",
            "SELECT descriptor FROM classes WHERE descriptor LIKE '%\u{00e9}%'",
        ] {
            let stmts2 =
                sqlparser::parser::Parser::parse_sql(&SQLiteDialect {}, unpushable).unwrap();
            let sqlparser::ast::Statement::Query(q2) = &stmts2[0] else {
                panic!("not a query");
            };
            assert!(
                query_hints(q2, &rels).row_filters.is_empty(),
                "expected no row filter for {unpushable}"
            );
        }

        let limit_zero = "SELECT * FROM (SELECT descriptor FROM classes WHERE descriptor = 'La;') AS hostlab_shape LIMIT 0";
        let stmts_z = sqlparser::parser::Parser::parse_sql(&SQLiteDialect {}, limit_zero).unwrap();
        let sqlparser::ast::Statement::Query(qz) = &stmts_z[0] else {
            panic!("not a query");
        };
        assert!(query_hints(qz, &rels).row_filters.is_empty());

        let negated_in = "SELECT descriptor FROM classes WHERE descriptor NOT IN ('La;')";
        let stmts3 = sqlparser::parser::Parser::parse_sql(&SQLiteDialect {}, negated_in).unwrap();
        let sqlparser::ast::Statement::Query(q3) = &stmts3[0] else {
            panic!("not a query");
        };
        assert!(query_hints(q3, &rels).row_filters.is_empty());
    }

    fn bulk_test_relations() -> Vec<SqlRelation> {
        let col = |name: &str, data_type: SqlType| crate::provider::SqlColumn {
            id: name.to_owned(),
            name: name.to_owned(),
            data_type,
            nullable: false,
        };
        vec![
            SqlRelation {
                name: "dex_files".to_owned(),
                columns: vec![
                    col("file_id", SqlType::U64),
                    col("entry_name", SqlType::Text),
                ],
                required_layers: vec![],
                estimated_rows: None,
            },
            SqlRelation {
                name: "strings".to_owned(),
                columns: vec![
                    col("string_pool_id", SqlType::U64),
                    col("string_idx", SqlType::U64),
                    col("value", SqlType::Text),
                ],
                required_layers: vec![],
                estimated_rows: None,
            },
            SqlRelation {
                name: "types".to_owned(),
                columns: vec![
                    col("file_id", SqlType::U64),
                    col("type_idx", SqlType::U64),
                    col("descriptor", SqlType::Text),
                ],
                required_layers: vec![],
                estimated_rows: None,
            },
            SqlRelation {
                name: "classes".to_owned(),
                columns: vec![
                    col("file_id", SqlType::U64),
                    col("class_idx", SqlType::U64),
                    col("descriptor", SqlType::Text),
                ],
                required_layers: vec![],
                estimated_rows: None,
            },
            SqlRelation {
                name: "methods".to_owned(),
                columns: vec![
                    col("file_id", SqlType::U64),
                    col("method_idx", SqlType::U64),
                    col("class_descriptor", SqlType::Text),
                    col("name", SqlType::Text),
                    col("descriptor", SqlType::Text),
                ],
                required_layers: vec![],
                estimated_rows: None,
            },
            SqlRelation {
                name: "method_calls".to_owned(),
                columns: vec![
                    col("file_id", SqlType::U64),
                    col("class_idx", SqlType::U64),
                    col("method_idx", SqlType::U64),
                ],
                required_layers: vec![],
                estimated_rows: None,
            },
            SqlRelation {
                name: "method_strings".to_owned(),
                columns: vec![
                    col("file_id", SqlType::U64),
                    col("class_idx", SqlType::U64),
                    col("method_idx", SqlType::U64),
                ],
                required_layers: vec![],
                estimated_rows: None,
            },
        ]
    }

    #[test]
    fn direct_table_projection_extracts_bulk_and_rejects_ambiguous_or_non_asc_queries() {
        let rels = bulk_test_relations();
        let no_ctes = BTreeSet::new();

        for (sql, rel_name, cols, order) in [
            (
                "SELECT file_id,entry_name FROM dex_files ORDER BY file_id",
                "dex_files",
                vec![(0, "file_id"), (1, "entry_name")],
                vec![0],
            ),
            (
                "SELECT string_pool_id,string_idx FROM strings ORDER BY string_pool_id,string_idx",
                "strings",
                vec![(0, "string_pool_id"), (1, "string_idx")],
                vec![0, 1],
            ),
            (
                "SELECT file_id,type_idx,descriptor FROM types ORDER BY file_id,type_idx",
                "types",
                vec![(0, "file_id"), (1, "type_idx"), (2, "descriptor")],
                vec![0, 1],
            ),
            (
                "SELECT file_id,class_idx,descriptor FROM classes ORDER BY file_id,class_idx",
                "classes",
                vec![(0, "file_id"), (1, "class_idx"), (2, "descriptor")],
                vec![0, 1],
            ),
            (
                "SELECT file_id,method_idx,class_descriptor,name,descriptor FROM methods ORDER BY file_id,method_idx",
                "methods",
                vec![
                    (0, "file_id"),
                    (1, "method_idx"),
                    (2, "class_descriptor"),
                    (3, "name"),
                    (4, "descriptor"),
                ],
                vec![0, 1],
            ),
            (
                "SELECT file_id,method_idx FROM method_calls ORDER BY file_id,method_idx",
                "method_calls",
                vec![(0, "file_id"), (2, "method_idx")],
                vec![0, 2],
            ),
            (
                "SELECT file_id,method_idx FROM method_strings ORDER BY file_id,method_idx",
                "method_strings",
                vec![(0, "file_id"), (2, "method_idx")],
                vec![0, 2],
            ),
            (
                "SELECT file_id, entry_name FROM dex_files",
                "dex_files",
                vec![(0, "file_id"), (1, "entry_name")],
                vec![],
            ),
            (
                "SELECT c.file_id, c.class_idx AS cid FROM classes c ORDER BY c.file_id ASC, c.class_idx ASC",
                "classes",
                vec![(0, "file_id"), (1, "cid")],
                vec![0, 1],
            ),
        ] {
            let extracted = extract_direct_projection(sql, &rels, &no_ctes, 64)
                .unwrap_or_else(|| panic!("expected DirectTableProjection for {sql}"));
            assert_eq!(extracted.relation, rel_name, "{sql}");
            let expected_cols: Vec<(usize, String)> =
                cols.into_iter().map(|(i, n)| (i, n.to_owned())).collect();
            assert_eq!(extracted.projected_columns, expected_cols, "{sql}");
            assert_eq!(extracted.order_by_u64_asc, order, "{sql}");
        }

        for rejected in [
            "SELECT file_id, entry_name FROM dex_files ORDER BY file_id DESC",
            "SELECT file_id, entry_name FROM dex_files ORDER BY file_id NULLS FIRST",
            "SELECT file_id, entry_name FROM dex_files ORDER BY entry_name",
            "SELECT file_id, entry_name FROM dex_files WHERE file_id = 0",
            "SELECT file_id, entry_name FROM dex_files LIMIT 1",
            "SELECT DISTINCT file_id FROM dex_files",
            "SELECT a.file_id FROM dex_files a JOIN classes b ON a.file_id = b.file_id",
            "SELECT class_idx AS method_idx FROM method_calls ORDER BY method_idx",
            "SELECT * FROM dex_files ORDER BY file_id",
            "SELECT file_id FROM dex_files ORDER BY file_id, 1, 2",
        ] {
            assert!(
                extract_direct_projection(rejected, &rels, &no_ctes, 64).is_none(),
                "must refuse direct projection for {rejected}"
            );
        }

        let cte_shadow = BTreeSet::from(["dex_files".to_owned()]);
        assert!(
            extract_direct_projection("SELECT file_id FROM dex_files", &rels, &cte_shadow, 64)
                .is_none()
        );
    }

    #[test]
    fn direct_count_group_by_extractor_accepts_w04_shape_and_rejects_unsafe_shapes() {
        use crate::provider::SqlColumn;
        let rels = vec![SqlRelation {
            name: "class_methods".to_owned(),
            columns: vec![
                SqlColumn {
                    id: "file_id".into(),
                    name: "file_id".into(),
                    data_type: SqlType::U64,
                    nullable: false,
                },
                SqlColumn {
                    id: "kind".into(),
                    name: "kind".into(),
                    data_type: SqlType::Text,
                    nullable: false,
                },
                SqlColumn {
                    id: "method_name".into(),
                    name: "method_name".into(),
                    data_type: SqlType::Text,
                    nullable: false,
                },
            ],
            required_layers: vec![],
            estimated_rows: None,
        }];
        let no_ctes = BTreeSet::new();

        let w04 = "SELECT file_id, kind, COUNT(*) AS cnt FROM class_methods GROUP BY file_id, kind ORDER BY file_id, kind";
        let got = extract_direct_count_group_by(w04, &rels, &no_ctes, 64)
            .expect("must extract W04 class_methods GROUP BY plan");
        assert_eq!(got.relation, "class_methods");
        assert_eq!(got.group_columns, vec![0, 1]);
        assert_eq!(
            got.projections,
            vec![
                DirectGroupItem::GroupCol {
                    group_pos: 0,
                    output_name: "file_id".into(),
                },
                DirectGroupItem::GroupCol {
                    group_pos: 1,
                    output_name: "kind".into(),
                },
                DirectGroupItem::CountStar {
                    output_name: "cnt".into(),
                },
            ]
        );
        assert_eq!(got.order_by_group_asc, vec![0, 1]);

        let aliased = "SELECT cm.kind AS k, COUNT(*) AS total FROM class_methods cm GROUP BY cm.kind ORDER BY k ASC";
        let got_aliased = extract_direct_count_group_by(aliased, &rels, &no_ctes, 64)
            .expect("must extract aliased single group");
        assert_eq!(got_aliased.group_columns, vec![1]);
        assert_eq!(got_aliased.order_by_group_asc, vec![0]);

        for rejected in [
            "SELECT file_id, kind, COUNT(*) FROM class_methods GROUP BY file_id, kind",
            "SELECT file_id, kind, COUNT(*) AS cnt FROM class_methods WHERE file_id = 0 GROUP BY file_id, kind",
            "SELECT file_id, kind, COUNT(*) AS cnt FROM class_methods GROUP BY file_id, kind HAVING COUNT(*) > 1",
            "SELECT DISTINCT file_id, kind FROM class_methods GROUP BY file_id, kind",
            "SELECT file_id, kind, COUNT(*) AS cnt FROM class_methods GROUP BY file_id, kind LIMIT 2",
            "SELECT file_id, kind, COUNT(*) AS cnt FROM class_methods GROUP BY file_id, kind ORDER BY kind DESC",
            "SELECT file_id, COUNT(*) AS kind FROM class_methods GROUP BY file_id ORDER BY kind",
            "SELECT file_id, method_name, COUNT(*) AS cnt FROM class_methods GROUP BY file_id",
            "SELECT COUNT(*) AS cnt FROM class_methods",
            "SELECT a.file_id, COUNT(*) AS cnt FROM class_methods a JOIN class_methods b ON a.file_id = b.file_id GROUP BY a.file_id",
        ] {
            assert!(
                extract_direct_count_group_by(rejected, &rels, &no_ctes, 64).is_none(),
                "must refuse direct count group_by for {rejected}"
            );
        }

        let cte_shadow = BTreeSet::from(["class_methods".to_owned()]);
        assert!(extract_direct_count_group_by(w04, &rels, &cte_shadow, 64).is_none());
    }

    #[test]
    fn direct_filtered_projection_extractor_handles_filters_orders_aliases_and_rejections() {
        let rels = bulk_test_relations();
        let no_ctes = BTreeSet::new();

        let simple = extract_direct_filtered_projection(
            "SELECT file_id, descriptor FROM classes WHERE descriptor = 'La;' ORDER BY file_id ASC, class_idx DESC",
            &rels,
            &no_ctes,
            64,
        )
        .expect("simple WHERE = with ORDER BY");
        assert_eq!(simple.relation, "classes");
        assert_eq!(
            simple.projected_columns,
            vec![(0, "file_id".into()), (2, "descriptor".into())]
        );
        assert_eq!(
            simple.predicates,
            vec![DirectPredicate::EqText(2, "La;".into())]
        );
        assert_eq!(
            simple.order_by,
            vec![
                DirectOrderItem {
                    column: 0,
                    descending: false
                },
                DirectOrderItem {
                    column: 1,
                    descending: true
                },
            ]
        );

        let fused = extract_direct_filtered_projection(
            "SELECT m.descriptor AS d, m.file_id FROM methods m WHERE m.class_descriptor = 'La;' AND (m.name IN ('f', 'g') AND 0 = m.file_id) ORDER BY d DESC",
            &rels,
            &no_ctes,
            64,
        )
        .expect("aliased fused AND + IN + reversed u64 literal");
        assert_eq!(
            fused.predicates,
            vec![
                DirectPredicate::EqText(2, "La;".into()),
                DirectPredicate::InText(3, vec!["f".into(), "g".into()]),
                DirectPredicate::EqU64(0, 0),
            ]
        );
        assert_eq!(
            fused.order_by,
            vec![DirectOrderItem {
                column: 4,
                descending: true
            }]
        );
        assert_eq!(fused.limit, None);
        assert_eq!(fused.offset, 0);

        let lim = extract_direct_filtered_projection(
            "SELECT file_id FROM classes WHERE descriptor = 'La;' LIMIT 10",
            &rels,
            &no_ctes,
            64,
        )
        .expect("LIMIT 10");
        assert_eq!((lim.limit, lim.offset), (Some(10), 0));

        let lim_off = extract_direct_filtered_projection(
            "SELECT file_id FROM classes WHERE descriptor = 'La;' LIMIT 5 OFFSET 2",
            &rels,
            &no_ctes,
            64,
        )
        .expect("LIMIT 5 OFFSET 2");
        assert_eq!((lim_off.limit, lim_off.offset), (Some(5), 2));

        let comma_lim = extract_direct_filtered_projection(
            "SELECT file_id FROM classes WHERE descriptor = 'La;' LIMIT 2, 5",
            &rels,
            &no_ctes,
            64,
        )
        .expect("LIMIT 2, 5");
        assert_eq!((comma_lim.limit, comma_lim.offset), (Some(5), 2));

        let lim_zero = extract_direct_filtered_projection(
            "SELECT file_id FROM classes WHERE descriptor = 'La;' LIMIT 0",
            &rels,
            &no_ctes,
            64,
        )
        .expect("LIMIT 0");
        assert_eq!((lim_zero.limit, lim_zero.offset), (Some(0), 0));

        for rejected in [
            "SELECT file_id FROM classes",
            "SELECT (file_id) FROM classes WHERE file_id = 0",
            "SELECT file_id FROM classes WHERE file_id = 0 OR descriptor = 'La;'",
            "SELECT file_id FROM classes WHERE descriptor LIKE 'La%'",
            "SELECT file_id FROM classes WHERE file_id = -1",
            "SELECT file_id FROM classes WHERE descriptor = 123",
            "SELECT file_id FROM classes WHERE file_id = ?",
            "SELECT DISTINCT file_id FROM classes WHERE descriptor = 'La;'",
            "SELECT file_id FROM classes WHERE descriptor = 'La;' LIMIT -1",
            "SELECT file_id FROM classes WHERE descriptor = 'La;' LIMIT ?",
            "SELECT file_id FROM classes WHERE descriptor = 'La;' GROUP BY file_id",
            "SELECT file_id AS x, class_idx AS x FROM classes WHERE descriptor = 'La;' ORDER BY x",
            "SELECT class_idx AS file_id FROM classes WHERE descriptor = 'La;' ORDER BY file_id",
            "SELECT file_id FROM classes WHERE descriptor = 'La;' ORDER BY 1",
            "SELECT file_id FROM classes WHERE descriptor = 'La;' ORDER BY file_id NULLS LAST",
        ] {
            assert!(
                extract_direct_filtered_projection(rejected, &rels, &no_ctes, 64).is_none(),
                "must refuse direct filtered projection for {rejected}"
            );
        }

        let cte_shadow = BTreeSet::from(["classes".to_owned()]);
        assert!(
            extract_direct_filtered_projection(
                "SELECT file_id FROM classes WHERE file_id = 0",
                &rels,
                &cte_shadow,
                64
            )
            .is_none()
        );
    }
}
