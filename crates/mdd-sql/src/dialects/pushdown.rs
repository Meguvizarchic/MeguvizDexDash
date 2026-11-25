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
use super::SqlDialect;
use crate::{
    provider::{
        DirectCountGroupBy, DirectFilteredProjection, DirectGroupItem, DirectOrderItem,
        DirectPredicate, DirectTableProjection, EquiJoinEdge, RowFilter, ScanSlot, SqlRelation,
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

#[derive(Default)]
struct AliasTracker {
    alias_targets: BTreeMap<String, Option<usize>>,
    shadowed_cols: BTreeSet<usize>,
}

impl AliasTracker {
    fn record_alias(&mut self, name: &str, col_idx: usize, conflicting: bool) {
        let lower = name.to_ascii_lowercase();
        if conflicting {
            self.alias_targets.insert(lower, None);
            return;
        }
        if let Some(prev) = self.alias_targets.get_mut(&lower) {
            if *prev != Some(col_idx) {
                *prev = None;
            }
        } else {
            self.alias_targets.insert(lower, Some(col_idx));
        }
    }

    fn record_aliased_col(&mut self, rel: &SqlRelation, col_idx: usize, alias: &str) {
        let mut shadows = false;
        if let Some(other_idx) = rel
            .columns
            .iter()
            .position(|c| c.name.eq_ignore_ascii_case(alias))
            && other_idx != col_idx
        {
            self.shadowed_cols.insert(other_idx);
            shadows = true;
        }
        self.record_alias(alias, col_idx, shadows);
    }

    fn record_non_col_alias(&mut self, rel: &SqlRelation, alias: &str) {
        if let Some(other_idx) = rel
            .columns
            .iter()
            .position(|c| c.name.eq_ignore_ascii_case(alias))
        {
            self.shadowed_cols.insert(other_idx);
        }
        self.record_alias(alias, 0, true);
    }

    fn resolve_order_col(&self, rel: &SqlRelation, qualifier: &str, expr: &Expr) -> Option<usize> {
        match unwrap_nested(expr) {
            Expr::Identifier(id) => {
                let lower = id.value.to_ascii_lowercase();
                if let Some(target) = self.alias_targets.get(&lower) {
                    *target
                } else {
                    let idx = resolve_plain_col(rel, qualifier, expr)?;
                    if self.shadowed_cols.contains(&idx) {
                        return None;
                    }
                    Some(idx)
                }
            }
            _ => resolve_plain_col(rel, qualifier, expr),
        }
    }
}

const MAX_DIRECT_PRED_DEPTH: usize = 64;
const MAX_DIRECT_PRED_NODES: usize = 16_384;

fn parse_u64_lit_for_dialect(expr: &Expr, dialect: SqlDialect) -> Option<u64> {
    let v = parse_u64_lit(expr)?;
    if dialect != SqlDialect::NativeV1 && i64::try_from(v).is_err() {
        return None;
    }
    Some(v)
}

enum ExactAsciiLike {
    Prefix {
        prefix: String,
        has_ascii_alpha: bool,
    },
    PrefixSuffix {
        prefix: String,
        suffix: String,
        has_ascii_alpha: bool,
    },
    Contains {
        needle: String,
        has_ascii_alpha: bool,
    },
}

impl ExactAsciiLike {
    fn has_ascii_alpha(&self) -> bool {
        match self {
            Self::Prefix {
                has_ascii_alpha, ..
            }
            | Self::PrefixSuffix {
                has_ascii_alpha, ..
            }
            | Self::Contains {
                has_ascii_alpha, ..
            } => *has_ascii_alpha,
        }
    }

    fn into_predicate(self, col_idx: usize) -> DirectPredicate {
        match self {
            Self::Prefix { prefix, .. } => DirectPredicate::LikeAsciiPrefix(col_idx, prefix),
            Self::PrefixSuffix { prefix, suffix, .. } => {
                DirectPredicate::LikeAsciiPrefixSuffix(col_idx, prefix, suffix)
            }
            Self::Contains { needle, .. } => DirectPredicate::LikeAsciiContains(col_idx, needle),
        }
    }
}

fn extract_exact_ascii_like(pattern: &str, escape: Option<char>) -> Option<ExactAsciiLike> {
    if !pattern.is_ascii() {
        return None;
    }
    if let Some(esc) = escape
        && !esc.is_ascii()
    {
        return None;
    }
    enum Part {
        Percent,
        Lit(String),
    }
    let mut parts: Vec<Part> = Vec::new();
    let mut chars = pattern.chars();
    while let Some(ch) = chars.next() {
        if Some(ch) == escape {
            let escaped = chars.next()?;
            match parts.last_mut() {
                Some(Part::Lit(buf)) => buf.push(escaped),
                _ => parts.push(Part::Lit(String::from(escaped))),
            }
        } else if ch == '_' {
            return None;
        } else if ch == '%' {
            if !matches!(parts.last(), Some(Part::Percent)) {
                parts.push(Part::Percent);
            }
        } else {
            match parts.last_mut() {
                Some(Part::Lit(buf)) => buf.push(ch),
                _ => parts.push(Part::Lit(String::from(ch))),
            }
        }
    }
    match parts.as_slice() {
        [Part::Lit(prefix), Part::Percent] if !prefix.is_empty() => {
            let has_ascii_alpha = prefix.bytes().any(|b| b.is_ascii_alphabetic());
            Some(ExactAsciiLike::Prefix {
                prefix: prefix.to_ascii_lowercase(),
                has_ascii_alpha,
            })
        }
        [Part::Lit(prefix), Part::Percent, Part::Lit(suffix)]
            if !prefix.is_empty() && !suffix.is_empty() =>
        {
            let has_ascii_alpha = prefix.bytes().any(|b| b.is_ascii_alphabetic())
                || suffix.bytes().any(|b| b.is_ascii_alphabetic());
            Some(ExactAsciiLike::PrefixSuffix {
                prefix: prefix.to_ascii_lowercase(),
                suffix: suffix.to_ascii_lowercase(),
                has_ascii_alpha,
            })
        }
        [Part::Percent, Part::Lit(needle), Part::Percent] if !needle.is_empty() => {
            let has_ascii_alpha = needle.bytes().any(|b| b.is_ascii_alphabetic());
            Some(ExactAsciiLike::Contains {
                needle: needle.to_ascii_lowercase(),
                has_ascii_alpha,
            })
        }
        _ => None,
    }
}

fn unwrap_like_target(rel: &SqlRelation, qualifier: &str, expr: &Expr) -> Option<(usize, bool)> {
    if let Some(col_idx) = resolve_plain_col(rel, qualifier, expr) {
        return Some((col_idx, false));
    }
    let Expr::Function(func) = unwrap_nested(expr) else {
        return None;
    };
    if func.name.0.len() != 1
        || !func.name.0[0]
            .as_ident()
            .is_some_and(|id| id.value.eq_ignore_ascii_case("lower"))
        || func.filter.is_some()
        || func.over.is_some()
        || !func.within_group.is_empty()
        || func.null_treatment.is_some()
        || func.uses_odbc_syntax
        || !matches!(func.parameters, FunctionArguments::None)
    {
        return None;
    }
    let FunctionArguments::List(list) = &func.args else {
        return None;
    };
    if list.duplicate_treatment.is_none()
        && list.clauses.is_empty()
        && list.args.len() == 1
        && let FunctionArg::Unnamed(FunctionArgExpr::Expr(arg)) = &list.args[0]
        && let Some(col_idx) = resolve_plain_col(rel, qualifier, arg)
    {
        return Some((col_idx, true));
    }
    None
}

fn extract_direct_predicates(
    rel: &SqlRelation,
    qualifier: &str,
    selection: &Expr,
    dialect: SqlDialect,
) -> Option<Vec<DirectPredicate>> {
    let parts = flatten_bool_chain(selection, BinaryOperator::And);
    if parts.is_empty() {
        return None;
    }
    let mut budget = MAX_DIRECT_PRED_NODES;
    let mut predicates = Vec::with_capacity(parts.len());
    for part in parts {
        predicates.push(extract_direct_predicate_node(
            rel,
            qualifier,
            part,
            dialect,
            1,
            &mut budget,
        )?);
    }
    (!predicates.is_empty()).then_some(predicates)
}

fn extract_direct_predicate_node(
    rel: &SqlRelation,
    qualifier: &str,
    expr: &Expr,
    dialect: SqlDialect,
    depth: usize,
    budget: &mut usize,
) -> Option<DirectPredicate> {
    if depth > MAX_DIRECT_PRED_DEPTH || *budget == 0 {
        return None;
    }
    *budget -= 1;
    let expr = unwrap_nested(expr);
    match expr {
        Expr::BinaryOp {
            op: op @ (BinaryOperator::And | BinaryOperator::Or),
            ..
        } => {
            let is_or = *op == BinaryOperator::Or;
            let parts = flatten_bool_chain(
                expr,
                if is_or {
                    BinaryOperator::Or
                } else {
                    BinaryOperator::And
                },
            );
            if parts.is_empty() {
                return None;
            }
            let mut items = Vec::with_capacity(parts.len());
            for part in parts {
                items.push(extract_direct_predicate_node(
                    rel,
                    qualifier,
                    part,
                    dialect,
                    depth + 1,
                    budget,
                )?);
            }
            if items.len() == 1 {
                items.pop()
            } else if is_or {
                Some(DirectPredicate::Or(items))
            } else {
                Some(DirectPredicate::And(items))
            }
        }
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => {
            let (col_idx, lit) = if let Some(idx) = resolve_plain_col(rel, qualifier, left) {
                (idx, right)
            } else {
                let idx = resolve_plain_col(rel, qualifier, right)?;
                (idx, left)
            };
            match rel.columns[col_idx].data_type {
                SqlType::U64 => Some(DirectPredicate::EqU64(
                    col_idx,
                    parse_u64_lit_for_dialect(lit, dialect)?,
                )),
                SqlType::Text => Some(DirectPredicate::EqText(col_idx, parse_text_lit(lit)?)),
                _ => None,
            }
        }
        Expr::InList {
            expr: target,
            list,
            negated: false,
        } => {
            if list.is_empty() {
                return None;
            }
            let col_idx = resolve_plain_col(rel, qualifier, target)?;
            match rel.columns[col_idx].data_type {
                SqlType::U64 => Some(DirectPredicate::InU64(
                    col_idx,
                    list.iter()
                        .map(|e| parse_u64_lit_for_dialect(e, dialect))
                        .collect::<Option<Vec<_>>>()?,
                )),
                SqlType::Text => Some(DirectPredicate::InText(
                    col_idx,
                    list.iter()
                        .map(parse_text_lit)
                        .collect::<Option<Vec<_>>>()?,
                )),
                _ => None,
            }
        }
        Expr::Between {
            expr: target,
            negated: false,
            low,
            high,
        } => {
            let col_idx = resolve_plain_col(rel, qualifier, target)?;
            if rel.columns[col_idx].data_type != SqlType::U64 {
                return None;
            }
            let lo = parse_u64_lit_for_dialect(low, dialect)?;
            let hi = parse_u64_lit_for_dialect(high, dialect)?;
            Some(DirectPredicate::BetweenU64(col_idx, lo, hi))
        }
        Expr::Like {
            negated: false,
            any: false,
            expr: target,
            pattern,
            escape_char,
        } => {
            let (col_idx, used_lower) = unwrap_like_target(rel, qualifier, target)?;
            if rel.columns[col_idx].data_type != SqlType::Text {
                return None;
            }
            let pat = parse_text_lit(pattern)?;
            let escape = match escape_char {
                Some(esc_expr) => {
                    let s = parse_text_lit(esc_expr)?;
                    let mut chars = s.chars();
                    let ch = chars.next()?;
                    if chars.next().is_some() || !ch.is_ascii() {
                        return None;
                    }
                    Some(ch)
                }
                None => None,
            };
            let extracted = extract_exact_ascii_like(&pat, escape)?;
            // NativeV1 LIKE is case-sensitive, and SQLite's lower() differs from ASCII-only folding.
            if dialect == SqlDialect::NativeV1 && (used_lower || extracted.has_ascii_alpha()) {
                return None;
            }
            Some(extracted.into_predicate(col_idx))
        }
        _ => None,
    }
}

/// Extract a filtered single-table projection with boolean predicate trees (`=`, `IN`,
/// `BETWEEN`, exact ASCII `LIKE`, `AND`, `OR`) and optional multi-column `U64`/`I64`/`Text` `ORDER BY`.
#[cfg(test)]
pub(crate) fn extract_direct_filtered_projection_with_dialect(
    sql: &str,
    relations: &[SqlRelation],
    cte_names: &BTreeSet<String>,
    max_ast_depth: usize,
    dialect: SqlDialect,
) -> Option<DirectFilteredProjection> {
    let root = parse_single_query(sql, max_ast_depth)?;
    extract_direct_filtered_projection_from_query(&root, relations, cte_names, dialect)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn extract_direct_filtered_projection(
    sql: &str,
    relations: &[SqlRelation],
    cte_names: &BTreeSet<String>,
    max_ast_depth: usize,
) -> Option<DirectFilteredProjection> {
    let root = parse_single_query(sql, max_ast_depth)?;
    extract_direct_filtered_projection_from_query(
        &root,
        relations,
        cte_names,
        SqlDialect::DexSql011,
    )
}

/// As [`extract_direct_filtered_projection`], reusing an already-parsed [`Query`] AST.
pub(crate) fn extract_direct_filtered_projection_from_query(
    root: &Query,
    relations: &[SqlRelation],
    cte_names: &BTreeSet<String>,
    dialect: SqlDialect,
) -> Option<DirectFilteredProjection> {
    let (select, rel, qualifier) = extract_plain_single_table(root, relations, cte_names, true)?;
    if !has_empty_group_by(select) {
        return None;
    }
    let selection = select.selection.as_ref()?;

    let mut projected_columns = Vec::with_capacity(select.projection.len());
    let mut aliases = AliasTracker::default();
    for item in &select.projection {
        match item {
            SelectItem::UnnamedExpr(expr) => {
                // Reject outer parenthesized `(col)` so SQLite output column naming never diverges.
                if matches!(expr, Expr::Nested(_)) {
                    return None;
                }
                let col_idx = resolve_plain_col(rel, &qualifier, expr)?;
                aliases.record_alias(&rel.columns[col_idx].name, col_idx, false);
                projected_columns.push((col_idx, rel.columns[col_idx].name.clone()));
            }
            SelectItem::ExprWithAlias { expr, alias } => {
                let col_idx = resolve_plain_col(rel, &qualifier, expr)?;
                aliases.record_aliased_col(rel, col_idx, &alias.value);
                projected_columns.push((col_idx, alias.value.clone()));
            }
            _ => return None,
        }
    }

    let predicates = extract_direct_predicates(rel, &qualifier, selection, dialect)?;

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
                let ord_idx = aliases.resolve_order_col(rel, &qualifier, &item.expr)?;
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
            let limit_val = Some(parse_i64_nonneg(limit.as_ref()?)?);
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

/// Extract a sound single-table `GROUP BY <cols> COUNT(*) [WHERE ...] [ORDER BY <cols> ASC]`
/// fast path, excluding wrappers, CTEs, HAVING, DISTINCT, LIMIT/OFFSET, or ambiguous aliases.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn extract_direct_count_group_by(
    sql: &str,
    relations: &[SqlRelation],
    cte_names: &BTreeSet<String>,
    max_ast_depth: usize,
) -> Option<DirectCountGroupBy> {
    let root = parse_single_query(sql, max_ast_depth)?;
    extract_direct_count_group_by_from_query(&root, relations, cte_names, SqlDialect::DexSql011)
}

#[cfg(test)]
pub(crate) fn extract_direct_count_group_by_with_dialect(
    sql: &str,
    relations: &[SqlRelation],
    cte_names: &BTreeSet<String>,
    max_ast_depth: usize,
    dialect: SqlDialect,
) -> Option<DirectCountGroupBy> {
    let root = parse_single_query(sql, max_ast_depth)?;
    extract_direct_count_group_by_from_query(&root, relations, cte_names, dialect)
}

/// As [`extract_direct_count_group_by`], reusing an already-parsed [`Query`] AST.
pub(crate) fn extract_direct_count_group_by_from_query(
    root: &Query,
    relations: &[SqlRelation],
    cte_names: &BTreeSet<String>,
    dialect: SqlDialect,
) -> Option<DirectCountGroupBy> {
    let (select, rel, qualifier) = extract_plain_single_table(root, relations, cte_names, false)?;
    let predicates = match &select.selection {
        None => Vec::new(),
        Some(selection) => extract_direct_predicates(rel, &qualifier, selection, dialect)?,
    };

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
    let mut aliases = AliasTracker::default();
    for item in &select.projection {
        match item {
            SelectItem::UnnamedExpr(expr) => {
                // Reject outer parenthesized `(col)` so SQLite output column naming never diverges.
                if matches!(expr, Expr::Nested(_)) {
                    return None;
                }
                let col_idx = resolve_col(expr)?;
                let group_pos = group_columns.iter().position(|&c| c == col_idx)?;
                aliases.record_alias(&rel.columns[col_idx].name, col_idx, false);
                projections.push(DirectGroupItem::GroupCol {
                    group_pos,
                    output_name: rel.columns[col_idx].name.clone(),
                });
            }
            SelectItem::ExprWithAlias { expr, alias } => {
                if is_count_star(expr) {
                    aliases.record_non_col_alias(rel, &alias.value);
                    projections.push(DirectGroupItem::CountStar {
                        output_name: alias.value.clone(),
                    });
                } else {
                    let col_idx = resolve_col(expr)?;
                    let group_pos = group_columns.iter().position(|&c| c == col_idx)?;
                    aliases.record_aliased_col(rel, col_idx, &alias.value);
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
                let ord_idx = aliases.resolve_order_col(rel, &qualifier, &item.expr)?;
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
        predicates,
        order_by_group_asc,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum QueryStep {
    Cte(usize),
    DerivedFrom(usize),
    DerivedJoin(usize, usize),
    NestedQuery,
    SetLeft,
    SetRight,
    SelectionSubquery(usize),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SlotTarget {
    pub path: Vec<QueryStep>,
    pub from_idx: usize,
    pub join_idx: Option<usize>,
    pub base_relation: String,
    pub slot_name: String,
}

#[derive(Default, Clone, Debug)]
pub(crate) struct QueryHints {
    pub row_filters: BTreeMap<String, RowFilter>,
    pub equi_joins: Vec<EquiJoinEdge>,
    pub scan_slots: Vec<ScanSlot>,
    pub slot_targets: Vec<SlotTarget>,
}

/// Extract sound single-table candidate filters, per-occurrence synthetic scan slots (for
/// repeated base relations), and inner/CTE/LEFT-JOIN equi-join edges from `root`.
/// Handles nested derived wrappers (e.g. `B0Session`), `WITH` CTEs, set operations, and
/// `WHERE` subqueries while refusing recursive CTEs, outer `LIMIT 0`, ambiguous/duplicate
/// qualifiers, and unsafe `OR`/`LEFT JOIN` filter placements.
#[cfg(test)]
pub(crate) fn query_hints(root: &Query, relations: &[SqlRelation]) -> QueryHints {
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
    query_hints_with_options(
        root,
        relations,
        &schema_types,
        &BTreeSet::new(),
        &BTreeSet::new(),
        true,
    )
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn query_hints_with_types(
    root: &Query,
    relations: &[SqlRelation],
    schema_types: &BTreeMap<String, BTreeMap<String, SqlType>>,
) -> QueryHints {
    query_hints_with_options(
        root,
        relations,
        schema_types,
        &BTreeSet::new(),
        &BTreeSet::new(),
        true,
    )
}

pub(crate) fn query_hints_with_options(
    root: &Query,
    relations: &[SqlRelation],
    schema_types: &BTreeMap<String, BTreeMap<String, SqlType>>,
    reserved: &BTreeSet<String>,
    reserved_base: &BTreeSet<String>,
    allow_synthetic_slots: bool,
) -> QueryHints {
    if relations.is_empty() || has_zero_limit(root) {
        return QueryHints::default();
    }

    let (table_mentions, _ctes, sql_identifiers) = count_table_mentions(root);
    let mut state = HintExtractState {
        schema_types,
        table_mentions: &table_mentions,
        reserved,
        reserved_base,
        sql_identifiers: &sql_identifiers,
        allow_synthetic_slots,
        path: Vec::new(),
        visible_ctes: Vec::new(),
        next_slot_id: 0,
        per_key_filters: BTreeMap::new(),
        slot_targets_by_name: BTreeMap::new(),
        join_pairs: BTreeMap::new(),
    };
    state.visit_query(root, 0);

    let mut used_keys: BTreeSet<String> = state.per_key_filters.keys().cloned().collect();
    for (left_key, right_key, _) in state.join_pairs.keys() {
        used_keys.insert(left_key.clone());
        used_keys.insert(right_key.clone());
    }
    state
        .slot_targets_by_name
        .retain(|slot_name, _| used_keys.contains(slot_name));

    let mut row_filters: BTreeMap<String, RowFilter> = BTreeMap::new();
    let mut slot_filters: BTreeMap<String, RowFilter> = BTreeMap::new();
    for (key, mut list) in state.per_key_filters {
        if list.is_empty() {
            continue;
        }
        let combined = if list.len() == 1 {
            list.pop().unwrap()
        } else {
            RowFilter::And(list)
        };
        if state.slot_targets_by_name.contains_key(&key) {
            slot_filters.insert(key, combined);
        } else {
            row_filters.insert(key, combined);
        }
    }

    let mut scan_slots = Vec::with_capacity(state.slot_targets_by_name.len());
    let mut slot_targets = Vec::with_capacity(state.slot_targets_by_name.len());
    for (slot_name, target) in state.slot_targets_by_name {
        let row_filter = slot_filters.remove(&slot_name);
        scan_slots.push(ScanSlot {
            slot_name,
            base_relation: target.base_relation.clone(),
            row_filter,
        });
        slot_targets.push(target);
    }

    let equi_joins = state
        .join_pairs
        .into_iter()
        .map(
            |((left_relation, right_relation, bidirectional), columns)| EquiJoinEdge {
                left_relation,
                right_relation,
                columns,
                bidirectional,
            },
        )
        .collect();

    QueryHints {
        row_filters,
        equi_joins,
        scan_slots,
        slot_targets,
    }
}

/// Apply generated synthetic scan slot names to the post-rewrite AST so each repeated base
/// relation occurrence points at its dedicated eponymous virtual table while preserving
/// qualifier names and `materialize_joined_base_table` derived wrappers.
pub(crate) fn apply_scan_slots(root: &mut Query, hints: &mut QueryHints) {
    if hints.slot_targets.is_empty() {
        return;
    }
    let mut applied: BTreeSet<String> = BTreeSet::new();
    for target in &hints.slot_targets {
        if apply_one_scan_slot(root, target) {
            applied.insert(target.slot_name.clone());
        }
    }
    if applied.len() != hints.scan_slots.len() {
        hints
            .scan_slots
            .retain(|slot| applied.contains(&slot.slot_name));
        hints
            .slot_targets
            .retain(|t| applied.contains(&t.slot_name));
        hints.equi_joins.retain(|edge| {
            (!edge.left_relation.starts_with("__mdd_scan_")
                || applied.contains(&edge.left_relation))
                && (!edge.right_relation.starts_with("__mdd_scan_")
                    || applied.contains(&edge.right_relation))
        });
    }
}

type CteDirectMap = BTreeMap<String, (String, String, SqlType)>;

struct HintExtractState<'a> {
    schema_types: &'a BTreeMap<String, BTreeMap<String, SqlType>>,
    table_mentions: &'a BTreeMap<String, usize>,
    reserved: &'a BTreeSet<String>,
    reserved_base: &'a BTreeSet<String>,
    sql_identifiers: &'a BTreeSet<String>,
    allow_synthetic_slots: bool,
    path: Vec<QueryStep>,
    visible_ctes: Vec<BTreeMap<String, Option<CteDirectMap>>>,
    next_slot_id: usize,
    per_key_filters: BTreeMap<String, Vec<RowFilter>>,
    slot_targets_by_name: BTreeMap<String, SlotTarget>,
    join_pairs: BTreeMap<(String, String, bool), Vec<(String, String)>>,
}

impl<'a> HintExtractState<'a> {
    fn is_cte_shadowed(&self, rel_lower: &str) -> Option<Option<&CteDirectMap>> {
        self.visible_ctes
            .iter()
            .rev()
            .find_map(|frame| frame.get(rel_lower).map(|opt| opt.as_ref()))
    }

    fn alloc_slot_name(&mut self) -> String {
        loop {
            let candidate = format!("__mdd_scan_{}", self.next_slot_id);
            self.next_slot_id += 1;
            if !self.reserved.contains(&candidate)
                && !self.reserved_base.contains(&candidate)
                && !self.sql_identifiers.contains(&candidate)
                && !self.slot_targets_by_name.contains_key(&candidate)
            {
                return candidate;
            }
        }
    }

    fn add_filter(&mut self, slot_key: String, filter: RowFilter) {
        self.per_key_filters
            .entry(slot_key)
            .or_default()
            .push(filter);
    }

    fn add_join_edge(
        &mut self,
        left_key: String,
        left_col: String,
        right_key: String,
        right_col: String,
        bidirectional: bool,
    ) {
        if left_key == right_key {
            return;
        }
        let (lk, lc, rk, rc) = if bidirectional && right_key < left_key {
            (right_key, right_col, left_key, left_col)
        } else {
            (left_key, left_col, right_key, right_col)
        };
        let cols = self.join_pairs.entry((lk, rk, bidirectional)).or_default();
        if !cols
            .iter()
            .any(|existing| existing == &(lc.clone(), rc.clone()))
        {
            cols.push((lc, rc));
        }
    }

    fn visit_query(&mut self, query: &Query, depth: usize) {
        if depth > MAX_HINT_DEPTH || has_zero_limit(query) {
            return;
        }
        let has_with = if let Some(with) = &query.with {
            if with.recursive {
                return;
            }
            self.visible_ctes.push(BTreeMap::new());
            for (idx, cte) in with.cte_tables.iter().enumerate() {
                self.path.push(QueryStep::Cte(idx));
                let cte_map = self.visit_cte_query(cte, depth + 1);
                self.path.pop();
                let name = cte.alias.name.value.to_ascii_lowercase();
                if let Some(frame) = self.visible_ctes.last_mut() {
                    frame.insert(name, cte_map);
                }
            }
            true
        } else {
            false
        };
        self.visit_set_expr(&query.body, depth + 1);
        if has_with {
            self.visible_ctes.pop();
        }
    }

    fn visit_cte_query(&mut self, cte: &Cte, depth: usize) -> Option<CteDirectMap> {
        let query = &cte.query;
        if depth > MAX_HINT_DEPTH || has_zero_limit(query) {
            return None;
        }
        if let Some(with) = &query.with {
            if with.recursive {
                return None;
            }
            self.visible_ctes.push(BTreeMap::new());
            for (idx, nested) in with.cte_tables.iter().enumerate() {
                self.path.push(QueryStep::Cte(idx));
                let nested_map = self.visit_cte_query(nested, depth + 1);
                self.path.pop();
                let name = nested.alias.name.value.to_ascii_lowercase();
                if let Some(frame) = self.visible_ctes.last_mut() {
                    frame.insert(name, nested_map);
                }
            }
        }
        let col_aliases = if cte.alias.columns.is_empty() {
            None
        } else {
            Some(cte.alias.columns.as_slice())
        };
        let out = self.visit_set_expr_for_cte(&query.body, depth + 1, col_aliases);
        if query.with.is_some() {
            self.visible_ctes.pop();
        }
        out
    }

    fn visit_set_expr(&mut self, body: &SetExpr, depth: usize) {
        if depth > MAX_HINT_DEPTH {
            return;
        }
        match body {
            SetExpr::Select(select) => {
                let _ = self.visit_select(select, depth + 1, None);
            }
            SetExpr::Query(inner) => {
                self.path.push(QueryStep::NestedQuery);
                self.visit_query(inner, depth + 1);
                self.path.pop();
            }
            SetExpr::SetOperation { left, right, .. } => {
                self.path.push(QueryStep::SetLeft);
                self.visit_set_expr(left, depth + 1);
                self.path.pop();
                self.path.push(QueryStep::SetRight);
                self.visit_set_expr(right, depth + 1);
                self.path.pop();
            }
            _ => {}
        }
    }

    fn visit_set_expr_for_cte(
        &mut self,
        body: &SetExpr,
        depth: usize,
        col_aliases: Option<&[TableAliasColumnDef]>,
    ) -> Option<CteDirectMap> {
        if depth > MAX_HINT_DEPTH {
            return None;
        }
        match body {
            SetExpr::Select(select) => {
                let alias_slice = col_aliases.unwrap_or(&[]);
                let capture = Some(alias_slice);
                self.visit_select(select, depth + 1, capture)
            }
            SetExpr::Query(inner) => {
                self.path.push(QueryStep::NestedQuery);
                self.visit_query(inner, depth + 1);
                self.path.pop();
                None
            }
            SetExpr::SetOperation { left, right, .. } => {
                self.path.push(QueryStep::SetLeft);
                self.visit_set_expr(left, depth + 1);
                self.path.pop();
                self.path.push(QueryStep::SetRight);
                self.visit_set_expr(right, depth + 1);
                self.path.pop();
                None
            }
            _ => None,
        }
    }

    fn visit_select(
        &mut self,
        select: &Select,
        depth: usize,
        cte_col_aliases: Option<&[TableAliasColumnDef]>,
    ) -> Option<CteDirectMap> {
        if depth > MAX_HINT_DEPTH {
            return None;
        }

        // Step A: descend into Derived tables and WHERE subqueries before touching the current SELECT.
        for (from_idx, from) in select.from.iter().enumerate() {
            if let TableFactor::Derived {
                lateral: false,
                subquery,
                ..
            } = &from.relation
            {
                self.path.push(QueryStep::DerivedFrom(from_idx));
                self.visit_query(subquery, depth + 1);
                self.path.pop();
            }
            for (join_idx, join) in from.joins.iter().enumerate() {
                if let TableFactor::Derived {
                    lateral: false,
                    subquery,
                    ..
                } = &join.relation
                {
                    self.path.push(QueryStep::DerivedJoin(from_idx, join_idx));
                    self.visit_query(subquery, depth + 1);
                    self.path.pop();
                }
            }
        }
        if let Some(selection) = &select.selection {
            let mut subqueries = Vec::new();
            collect_selection_subqueries(selection, 0, &mut subqueries);
            for (ordinal, subquery) in subqueries.into_iter().enumerate() {
                self.path.push(QueryStep::SelectionSubquery(ordinal));
                self.visit_query(subquery, depth + 1);
                self.path.pop();
            }
        }

        // Step B: validate FROM list & join operators before allocating any slot names.
        if select.from.is_empty() {
            return None;
        }
        let multi_from = select.from.len() > 1;
        for from in &select.from {
            for join in &from.joins {
                match &join.join_operator {
                    JoinOperator::Join(c) | JoinOperator::Inner(c) | JoinOperator::CrossJoin(c) => {
                        if matches!(c, JoinConstraint::Natural) {
                            return None;
                        }
                    }
                    JoinOperator::Left(c) | JoinOperator::LeftOuter(c) => {
                        if multi_from || matches!(c, JoinConstraint::Natural) {
                            return None;
                        }
                    }
                    _ => return None,
                }
            }
        }

        // Step C: pre-validate factors and detect duplicate qualifiers before slot allocation.
        #[derive(Clone)]
        enum PreFactor<'b> {
            Base {
                qual: String,
                from_idx: usize,
                join_idx: Option<usize>,
                base_rel: String,
                needs_slot: bool,
            },
            Cte {
                qual: String,
                map: &'b CteDirectMap,
            },
            Opaque {
                qual: Option<String>,
            },
        }
        let mut pre_factors: Vec<PreFactor<'_>> = Vec::new();
        let mut seen_quals: BTreeSet<String> = BTreeSet::new();

        for (from_idx, from) in select.from.iter().enumerate() {
            let factors = std::iter::once((None, &from.relation)).chain(
                from.joins
                    .iter()
                    .enumerate()
                    .map(|(j, join)| (Some(j), &join.relation)),
            );
            for (join_idx, factor) in factors {
                let pre = match factor {
                    TableFactor::Table {
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
                    } if with_hints.is_empty()
                        && partitions.is_empty()
                        && index_hints.is_empty()
                        && name.0.len() == 1 =>
                    {
                        let Some(ident) = name.0[0].as_ident() else {
                            return None;
                        };
                        let rel_lower = ident.value.to_ascii_lowercase();
                        let qual = alias.as_ref().map_or_else(
                            || rel_lower.clone(),
                            |a| a.name.value.to_ascii_lowercase(),
                        );
                        if alias.as_ref().is_some_and(|a| !a.columns.is_empty()) {
                            PreFactor::Opaque { qual: Some(qual) }
                        } else if let Some(cte_opt) = self.is_cte_shadowed(&rel_lower) {
                            if let Some(map) = cte_opt {
                                PreFactor::Cte { qual, map }
                            } else {
                                PreFactor::Opaque { qual: Some(qual) }
                            }
                        } else if self.schema_types.contains_key(&rel_lower) {
                            let mentions =
                                self.table_mentions.get(&rel_lower).copied().unwrap_or(0);
                            if mentions == 1 {
                                PreFactor::Base {
                                    qual,
                                    from_idx,
                                    join_idx,
                                    base_rel: rel_lower,
                                    needs_slot: false,
                                }
                            } else if mentions > 1 && self.allow_synthetic_slots {
                                PreFactor::Base {
                                    qual,
                                    from_idx,
                                    join_idx,
                                    base_rel: rel_lower,
                                    needs_slot: true,
                                }
                            } else {
                                PreFactor::Opaque { qual: Some(qual) }
                            }
                        } else {
                            PreFactor::Opaque { qual: Some(qual) }
                        }
                    }
                    TableFactor::Derived { alias, .. } => PreFactor::Opaque {
                        qual: alias.as_ref().map(|a| a.name.value.to_ascii_lowercase()),
                    },
                    _ => return None,
                };
                if let Some(q) = match &pre {
                    PreFactor::Base { qual, .. } | PreFactor::Cte { qual, .. } => Some(qual),
                    PreFactor::Opaque { qual } => qual.as_ref(),
                } && !seen_quals.insert(q.clone())
                {
                    return None;
                }
                pre_factors.push(pre);
            }
        }

        // Step D: materialize FactorInfo map (allocating synthetic slots only now).
        let mut factors_by_qual: BTreeMap<String, FactorInfo> = BTreeMap::new();
        let mut ordered_quals: Vec<Option<String>> = Vec::with_capacity(pre_factors.len());
        let mut all_plain_base = true;
        for pre in pre_factors {
            match pre {
                PreFactor::Base {
                    qual,
                    from_idx,
                    join_idx,
                    base_rel,
                    needs_slot,
                } => {
                    let slot_key = if needs_slot {
                        let slot_name = self.alloc_slot_name();
                        self.slot_targets_by_name.insert(
                            slot_name.clone(),
                            SlotTarget {
                                path: self.path.clone(),
                                from_idx,
                                join_idx,
                                base_relation: base_rel.clone(),
                                slot_name: slot_name.clone(),
                            },
                        );
                        slot_name
                    } else {
                        base_rel.clone()
                    };
                    ordered_quals.push(Some(qual.clone()));
                    factors_by_qual.insert(qual, FactorInfo::Base { slot_key, base_rel });
                }
                PreFactor::Cte { qual, map } => {
                    all_plain_base = false;
                    ordered_quals.push(Some(qual.clone()));
                    factors_by_qual.insert(qual, FactorInfo::Cte(map.clone()));
                }
                PreFactor::Opaque { qual } => {
                    all_plain_base = false;
                    if let Some(q) = qual {
                        ordered_quals.push(Some(q.clone()));
                        factors_by_qual.insert(q, FactorInfo::Opaque);
                    } else {
                        ordered_quals.push(None);
                    }
                }
            }
        }

        let mut inner_core_quals: BTreeSet<String> = BTreeSet::new();
        let mut available_left_quals: BTreeSet<String> = BTreeSet::new();
        let mut inner_on_exprs: Vec<&Expr> = Vec::new();
        let mut left_join_ons: Vec<(String, BTreeSet<String>, &Expr)> = Vec::new();
        let mut factor_cursor = 0usize;
        let mut seen_left_join = false;

        for from in &select.from {
            if let Some(q) = ordered_quals.get(factor_cursor).and_then(Option::as_ref) {
                inner_core_quals.insert(q.clone());
                available_left_quals.insert(q.clone());
            }
            factor_cursor += 1;
            for join in &from.joins {
                let join_qual_opt = ordered_quals
                    .get(factor_cursor)
                    .and_then(Option::as_ref)
                    .cloned();
                factor_cursor += 1;
                match &join.join_operator {
                    JoinOperator::Join(c) | JoinOperator::Inner(c) | JoinOperator::CrossJoin(c) => {
                        if !seen_left_join {
                            if let Some(q) = &join_qual_opt {
                                inner_core_quals.insert(q.clone());
                            }
                            if let JoinConstraint::On(expr) = c {
                                inner_on_exprs.push(expr);
                            }
                        }
                        if let Some(q) = join_qual_opt {
                            available_left_quals.insert(q);
                        }
                    }
                    JoinOperator::Left(c) | JoinOperator::LeftOuter(c) => {
                        seen_left_join = true;
                        if let (Some(q), JoinConstraint::On(expr)) = (&join_qual_opt, c) {
                            left_join_ons.push((q.clone(), available_left_quals.clone(), expr));
                        }
                        if let Some(q) = join_qual_opt {
                            available_left_quals.insert(q);
                        }
                    }
                    _ => {}
                }
            }
        }

        let only_qual = (all_plain_base && factors_by_qual.len() == 1)
            .then(|| factors_by_qual.keys().next().cloned())
            .flatten();
        let ctx = ResolveCtx {
            schema_types: self.schema_types,
            factors_by_qual: &factors_by_qual,
            only_qual: only_qual.as_deref(),
            all_plain_base,
        };

        let mut pending: Vec<&Expr> = Vec::new();
        if let Some(sel) = &select.selection {
            pending.push(sel);
        }
        pending.extend(inner_on_exprs);

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
            if let Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } = expr
                && let (Some(c1), Some(c2)) = (ctx.resolve_col(left), ctx.resolve_col(right))
                && c1.sql_type() == c2.sql_type()
                && matches!(c1.sql_type(), SqlType::U64 | SqlType::Text)
            {
                match (c1, c2) {
                    (
                        ResolvedCol::Base {
                            qual: q1,
                            slot_key: s1,
                            col: col1,
                            ..
                        },
                        ResolvedCol::Base {
                            qual: q2,
                            slot_key: s2,
                            col: col2,
                            ..
                        },
                    ) if inner_core_quals.contains(&q1) && inner_core_quals.contains(&q2) => {
                        self.add_join_edge(s1, col1, s2, col2, true);
                        continue;
                    }
                    (
                        ResolvedCol::CteDirect {
                            qual: q_cte,
                            src_slot,
                            src_col,
                            ..
                        },
                        ResolvedCol::Base {
                            qual: q_base,
                            slot_key: dst_slot,
                            col: dst_col,
                            ..
                        },
                    )
                    | (
                        ResolvedCol::Base {
                            qual: q_base,
                            slot_key: dst_slot,
                            col: dst_col,
                            ..
                        },
                        ResolvedCol::CteDirect {
                            qual: q_cte,
                            src_slot,
                            src_col,
                            ..
                        },
                    ) if inner_core_quals.contains(&q_cte)
                        && inner_core_quals.contains(&q_base) =>
                    {
                        self.add_join_edge(src_slot, src_col, dst_slot, dst_col, false);
                        continue;
                    }
                    _ => {}
                }
            }
            if let Some((qual, filter)) = extract_single_table_filter(&ctx, expr, 0)
                && inner_core_quals.contains(&qual)
                && let Some(FactorInfo::Base { slot_key, .. }) = factors_by_qual.get(&qual)
            {
                self.add_filter(slot_key.clone(), filter);
            }
        }

        for (join_qual, left_quals, on_expr) in left_join_ons {
            let Some(FactorInfo::Base {
                slot_key: rhs_slot, ..
            }) = factors_by_qual.get(&join_qual)
            else {
                continue;
            };
            let mut on_pending = vec![on_expr];
            while let Some(expr) = on_pending.pop() {
                let expr = unwrap_nested(expr);
                if let Expr::BinaryOp {
                    left,
                    op: BinaryOperator::And,
                    right,
                } = expr
                {
                    on_pending.push(right);
                    on_pending.push(left);
                    continue;
                }
                if let Expr::BinaryOp {
                    left,
                    op: BinaryOperator::Eq,
                    right,
                } = expr
                    && let (Some(c1), Some(c2)) = (ctx.resolve_col(left), ctx.resolve_col(right))
                    && c1.sql_type() == c2.sql_type()
                    && matches!(c1.sql_type(), SqlType::U64 | SqlType::Text)
                {
                    let pair = match (&c1, &c2) {
                        (
                            ResolvedCol::Base {
                                qual: rq, col: rc, ..
                            },
                            lhs,
                        ) if rq == &join_qual && left_quals.contains(lhs.qual()) => {
                            Some((lhs.slot_key(), lhs.col_name(), rc.clone()))
                        }
                        (
                            lhs,
                            ResolvedCol::Base {
                                qual: rq, col: rc, ..
                            },
                        ) if rq == &join_qual && left_quals.contains(lhs.qual()) => {
                            Some((lhs.slot_key(), lhs.col_name(), rc.clone()))
                        }
                        _ => None,
                    };
                    if let Some((src_slot, src_col, dst_col)) = pair {
                        self.add_join_edge(
                            src_slot.to_owned(),
                            src_col.to_owned(),
                            rhs_slot.clone(),
                            dst_col,
                            false,
                        );
                        continue;
                    }
                }
                if let Some((qual, filter)) = extract_single_table_filter(&ctx, expr, 0)
                    && qual == join_qual
                {
                    self.add_filter(rhs_slot.clone(), filter);
                }
            }
        }

        // Compute CteDirectMap only when building a CTE whose outputs come directly
        // from unambiguous column projections of inner_core factors without GROUP BY/HAVING.
        let alias_defs = cte_col_aliases?;
        if select.having.is_some() || !has_empty_group_by(select) || select.projection.is_empty() {
            return None;
        }
        if !alias_defs.is_empty() && alias_defs.len() != select.projection.len() {
            return None;
        }
        let mut by_name: BTreeMap<String, Option<(String, String, SqlType)>> = BTreeMap::new();
        for (ordinal, item) in select.projection.iter().enumerate() {
            let (expr, default_name) = match item {
                SelectItem::UnnamedExpr(e) => match unwrap_nested(e) {
                    Expr::Identifier(id) => (e, Some(id.value.to_ascii_lowercase())),
                    Expr::CompoundIdentifier(parts) if parts.len() == 2 => {
                        (e, Some(parts[1].value.to_ascii_lowercase()))
                    }
                    _ => (e, None),
                },
                SelectItem::ExprWithAlias { expr, alias } => {
                    (expr, Some(alias.value.to_ascii_lowercase()))
                }
                SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(_, _) => return None,
                _ => return None,
            };
            let out_name = if let Some(col_def) = alias_defs.get(ordinal) {
                col_def.name.value.to_ascii_lowercase()
            } else if let Some(name) = default_name {
                name
            } else {
                continue;
            };
            let resolved = ctx
                .resolve_col(expr)
                .filter(|col| inner_core_quals.contains(col.qual()))
                .map(|col| {
                    (
                        col.slot_key().to_owned(),
                        col.col_name().to_owned(),
                        col.sql_type(),
                    )
                });
            match by_name.entry(out_name) {
                std::collections::btree_map::Entry::Vacant(v) => {
                    v.insert(resolved);
                }
                std::collections::btree_map::Entry::Occupied(mut o) => {
                    // Duplicate output names are ambiguous in callers; drop mapping.
                    o.insert(None);
                }
            }
        }
        let map: CteDirectMap = by_name
            .into_iter()
            .filter_map(|(k, v)| v.map(|entry| (k, entry)))
            .collect();
        (!map.is_empty()).then_some(map)
    }
}

fn unwrap_mdd_truth_input(expr: &Expr) -> Option<&Expr> {
    let Expr::Function(func) = expr else {
        return None;
    };
    if func.name.0.len() != 1
        || func.name.0[0]
            .as_ident()
            .is_none_or(|id| !id.value.eq_ignore_ascii_case("mdd_truth_input"))
    {
        return None;
    }
    let FunctionArguments::List(list) = &func.args else {
        return None;
    };
    if list.args.len() != 1 {
        return None;
    }
    let FunctionArg::Unnamed(FunctionArgExpr::Expr(inner)) = &list.args[0] else {
        return None;
    };
    Some(inner)
}

fn unwrap_mdd_truth_input_mut(expr: &mut Expr) -> Option<&mut Expr> {
    let is_truth_wrapper = match expr {
        Expr::Function(func)
            if func.name.0.len() == 1
                && func.name.0[0]
                    .as_ident()
                    .is_some_and(|id| id.value.eq_ignore_ascii_case("mdd_truth_input")) =>
        {
            matches!(&func.args, FunctionArguments::List(list) if list.args.len() == 1 && matches!(list.args[0], FunctionArg::Unnamed(FunctionArgExpr::Expr(_))))
        }
        _ => false,
    };
    if !is_truth_wrapper {
        return None;
    }
    let Expr::Function(func) = expr else {
        unreachable!();
    };
    let FunctionArguments::List(list) = &mut func.args else {
        unreachable!();
    };
    let FunctionArg::Unnamed(FunctionArgExpr::Expr(inner)) = &mut list.args[0] else {
        unreachable!();
    };
    Some(inner)
}

fn collect_selection_subqueries<'a>(expr: &'a Expr, depth: usize, out: &mut Vec<&'a Query>) {
    let mut stack = vec![(expr, depth)];
    while let Some((cur, d)) = stack.pop() {
        if d > MAX_HINT_DEPTH {
            continue;
        }
        let mut node = unwrap_nested(cur);
        while let Some(inner) = unwrap_mdd_truth_input(node) {
            node = unwrap_nested(inner);
        }
        match node {
            Expr::BinaryOp {
                left,
                op: BinaryOperator::And | BinaryOperator::Or,
                right,
            } => {
                stack.push((right, d + 1));
                stack.push((left, d + 1));
            }
            Expr::UnaryOp {
                op: UnaryOperator::Not,
                expr: inner,
            } => stack.push((inner, d + 1)),
            Expr::InSubquery { subquery, .. }
            | Expr::Exists { subquery, .. }
            | Expr::Subquery(subquery) => out.push(subquery),
            _ => {}
        }
    }
}

fn selection_subquery_mut(expr: &mut Expr, target_ordinal: usize) -> Option<&mut Query> {
    let mut stack: Vec<(&mut Expr, usize)> = vec![(expr, 0)];
    let mut seen = 0usize;
    while let Some((cur, d)) = stack.pop() {
        if d > MAX_HINT_DEPTH {
            continue;
        }
        let mut node = cur;
        loop {
            let is_nested = matches!(node, Expr::Nested(_));
            if is_nested {
                let Expr::Nested(inner) = node else {
                    unreachable!();
                };
                node = inner;
                continue;
            }
            if unwrap_mdd_truth_input(node).is_some() {
                node = unwrap_mdd_truth_input_mut(node).expect("validated truth wrapper");
                continue;
            }
            break;
        }
        match node {
            Expr::BinaryOp {
                left,
                op: BinaryOperator::And | BinaryOperator::Or,
                right,
            } => {
                stack.push((right, d + 1));
                stack.push((left, d + 1));
            }
            Expr::UnaryOp {
                op: UnaryOperator::Not,
                expr: inner,
            } => stack.push((inner, d + 1)),
            Expr::InSubquery { subquery, .. }
            | Expr::Exists { subquery, .. }
            | Expr::Subquery(subquery) => {
                if seen == target_ordinal {
                    return Some(subquery);
                }
                seen += 1;
            }
            _ => {}
        }
    }
    None
}

enum AstNodeMut<'a> {
    Query(&'a mut Query),
    SetExpr(&'a mut SetExpr),
}

impl<'a> AstNodeMut<'a> {
    fn select_mut(self) -> Option<&'a mut Select> {
        match self {
            Self::Query(q) => match q.body.as_mut() {
                SetExpr::Select(sel) => Some(sel),
                _ => None,
            },
            Self::SetExpr(se) => match se {
                SetExpr::Select(sel) => Some(sel),
                _ => None,
            },
        }
    }
}

fn is_compound_order_wrapper(query: &Query) -> bool {
    if query.with.is_some() {
        return false;
    }
    matches!(
        &*query.body,
        SetExpr::Select(sel)
            if sel.from.len() == 1
                && sel.from[0].joins.is_empty()
                && matches!(
                    &sel.from[0].relation,
                    TableFactor::Derived { subquery, .. }
                        if matches!(&*subquery.body, SetExpr::SetOperation { .. })
                )
    )
}

fn unwrap_compound_order_wrapper_mut(query: &mut Query) -> &mut Query {
    let SetExpr::Select(sel) = &mut *query.body else {
        unreachable!("validated compound_order wrapper body");
    };
    let TableFactor::Derived { subquery, .. } = &mut sel.from[0].relation else {
        unreachable!("validated compound_order wrapper derived");
    };
    subquery
}

fn apply_one_scan_slot(root: &mut Query, target: &SlotTarget) -> bool {
    let mut cur = AstNodeMut::Query(root);
    for step in &target.path {
        if matches!(
            step,
            QueryStep::Cte(_) | QueryStep::SetLeft | QueryStep::SetRight
        ) && let AstNodeMut::Query(q) = cur
        {
            cur = if is_compound_order_wrapper(q) {
                AstNodeMut::Query(unwrap_compound_order_wrapper_mut(q))
            } else {
                AstNodeMut::Query(q)
            };
        }
        cur = match step {
            QueryStep::Cte(idx) => {
                let AstNodeMut::Query(q) = cur else {
                    return false;
                };
                let Some(with) = q.with.as_mut() else {
                    return false;
                };
                let Some(cte) = with.cte_tables.get_mut(*idx) else {
                    return false;
                };
                AstNodeMut::Query(&mut cte.query)
            }
            QueryStep::NestedQuery => {
                let se = match cur {
                    AstNodeMut::Query(q) => q.body.as_mut(),
                    AstNodeMut::SetExpr(se) => se,
                };
                let SetExpr::Query(inner) = se else {
                    return false;
                };
                AstNodeMut::Query(inner)
            }
            QueryStep::SetLeft => {
                let se = match cur {
                    AstNodeMut::Query(q) => q.body.as_mut(),
                    AstNodeMut::SetExpr(se) => se,
                };
                let SetExpr::SetOperation { left, .. } = se else {
                    return false;
                };
                AstNodeMut::SetExpr(left)
            }
            QueryStep::SetRight => {
                let se = match cur {
                    AstNodeMut::Query(q) => q.body.as_mut(),
                    AstNodeMut::SetExpr(se) => se,
                };
                let SetExpr::SetOperation { right, .. } = se else {
                    return false;
                };
                AstNodeMut::SetExpr(right)
            }
            QueryStep::DerivedFrom(from_idx) => {
                let Some(sel) = cur.select_mut() else {
                    return false;
                };
                let Some(from) = sel.from.get_mut(*from_idx) else {
                    return false;
                };
                let TableFactor::Derived { subquery, .. } = &mut from.relation else {
                    return false;
                };
                AstNodeMut::Query(subquery)
            }
            QueryStep::DerivedJoin(from_idx, join_idx) => {
                let Some(sel) = cur.select_mut() else {
                    return false;
                };
                let Some(from) = sel.from.get_mut(*from_idx) else {
                    return false;
                };
                let Some(join) = from.joins.get_mut(*join_idx) else {
                    return false;
                };
                let TableFactor::Derived { subquery, .. } = &mut join.relation else {
                    return false;
                };
                AstNodeMut::Query(subquery)
            }
            QueryStep::SelectionSubquery(ordinal) => {
                let Some(sel) = cur.select_mut() else {
                    return false;
                };
                let Some(selection) = sel.selection.as_mut() else {
                    return false;
                };
                let Some(subquery) = selection_subquery_mut(selection, *ordinal) else {
                    return false;
                };
                AstNodeMut::Query(subquery)
            }
        };
    }

    let Some(select) = cur.select_mut() else {
        return false;
    };
    let Some(from) = select.from.get_mut(target.from_idx) else {
        return false;
    };
    let factor = match target.join_idx {
        None => &mut from.relation,
        Some(join_idx) => {
            let Some(join) = from.joins.get_mut(join_idx) else {
                return false;
            };
            &mut join.relation
        }
    };
    rewrite_factor_to_slot(factor, &target.base_relation, &target.slot_name)
}

fn rewrite_factor_to_slot(factor: &mut TableFactor, base_relation: &str, slot_name: &str) -> bool {
    match factor {
        TableFactor::Table { name, alias, .. } if name.0.len() == 1 => {
            let Some(orig_ident) = name.0[0].as_ident().cloned() else {
                return false;
            };
            if !orig_ident.value.eq_ignore_ascii_case(base_relation) {
                return false;
            }
            *name = ObjectName::from(vec![Ident::with_quote('"', slot_name)]);
            if alias.is_none() {
                *alias = Some(TableAlias {
                    name: orig_ident,
                    columns: Vec::new(),
                    explicit: true,
                    at: None,
                });
            }
            true
        }
        // `materialize_joined_base_table` wraps `join.relation` as `(SELECT * FROM <tbl> LIMIT -1) AS <alias>`.
        TableFactor::Derived { subquery, .. } => {
            let SetExpr::Select(inner) = subquery.body.as_mut() else {
                return false;
            };
            if inner.from.len() != 1 || !inner.from[0].joins.is_empty() {
                return false;
            }
            let TableFactor::Table { name, .. } = &mut inner.from[0].relation else {
                return false;
            };
            if name.0.len() != 1 {
                return false;
            }
            let Some(orig_ident) = name.0[0].as_ident() else {
                return false;
            };
            if !orig_ident.value.eq_ignore_ascii_case(base_relation) {
                return false;
            }
            *name = ObjectName::from(vec![Ident::with_quote('"', slot_name)]);
            true
        }
        _ => false,
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

fn count_table_mentions(
    root: &Query,
) -> (BTreeMap<String, usize>, BTreeSet<String>, BTreeSet<String>) {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut ctes: BTreeSet<String> = BTreeSet::new();
    let mut identifiers: BTreeSet<String> = BTreeSet::new();
    let mut queries: Vec<&Query> = vec![root];
    let mut exprs: Vec<&Expr> = Vec::new();
    let mut set_exprs: Vec<&SetExpr> = Vec::new();

    let mut record_alias = |alias: &TableAlias| {
        identifiers.insert(alias.name.value.to_ascii_lowercase());
        for col in &alias.columns {
            identifiers.insert(col.name.value.to_ascii_lowercase());
        }
    };

    while !queries.is_empty() || !set_exprs.is_empty() || !exprs.is_empty() {
        while let Some(q) = queries.pop() {
            if let Some(with) = &q.with {
                for cte in &with.cte_tables {
                    ctes.insert(cte.alias.name.value.to_ascii_lowercase());
                    record_alias(&cte.alias);
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
                            SelectItem::UnnamedExpr(e) => exprs.push(e),
                            SelectItem::ExprWithAlias { expr: e, alias } => {
                                identifiers.insert(alias.value.to_ascii_lowercase());
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
                                TableFactor::Table { name, alias, .. } => {
                                    if let Some(alias) = alias {
                                        record_alias(alias);
                                    }
                                    if name.0.len() == 1
                                        && let Some(id) = name.0[0].as_ident()
                                    {
                                        let lower = id.value.to_ascii_lowercase();
                                        identifiers.insert(lower.clone());
                                        *counts.entry(lower).or_insert(0) += 1;
                                    }
                                }
                                TableFactor::Derived {
                                    subquery, alias, ..
                                } => {
                                    if let Some(alias) = alias {
                                        record_alias(alias);
                                    }
                                    queries.push(subquery);
                                }
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
                Expr::Identifier(id) => {
                    identifiers.insert(id.value.to_ascii_lowercase());
                }
                Expr::CompoundIdentifier(parts) => {
                    for part in parts {
                        identifiers.insert(part.value.to_ascii_lowercase());
                    }
                }
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
                        for clause in &list.clauses {
                            if let FunctionArgumentClause::OrderBy(order_exprs) = clause {
                                for order in order_exprs {
                                    exprs.push(&order.expr);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    (counts, ctes, identifiers)
}

#[derive(Clone)]
enum FactorInfo {
    Base { slot_key: String, base_rel: String },
    Cte(CteDirectMap),
    Opaque,
}

#[derive(Clone)]
enum ResolvedCol {
    Base {
        qual: String,
        slot_key: String,
        col: String,
        ty: SqlType,
    },
    CteDirect {
        qual: String,
        src_slot: String,
        src_col: String,
        ty: SqlType,
    },
}

impl ResolvedCol {
    fn qual(&self) -> &str {
        match self {
            Self::Base { qual, .. } | Self::CteDirect { qual, .. } => qual,
        }
    }

    fn slot_key(&self) -> &str {
        match self {
            Self::Base { slot_key, .. } => slot_key,
            Self::CteDirect { src_slot, .. } => src_slot,
        }
    }

    fn col_name(&self) -> &str {
        match self {
            Self::Base { col, .. } => col,
            Self::CteDirect { src_col, .. } => src_col,
        }
    }

    fn sql_type(&self) -> SqlType {
        match self {
            Self::Base { ty, .. } | Self::CteDirect { ty, .. } => *ty,
        }
    }
}

struct ResolveCtx<'a> {
    schema_types: &'a BTreeMap<String, BTreeMap<String, SqlType>>,
    factors_by_qual: &'a BTreeMap<String, FactorInfo>,
    only_qual: Option<&'a str>,
    all_plain_base: bool,
}

impl ResolveCtx<'_> {
    fn resolve_in_factor(&self, qual: &str, info: &FactorInfo, col: &str) -> Option<ResolvedCol> {
        match info {
            FactorInfo::Base { slot_key, base_rel } => {
                let ty = *self.schema_types.get(base_rel)?.get(col)?;
                Some(ResolvedCol::Base {
                    qual: qual.to_owned(),
                    slot_key: slot_key.clone(),
                    col: col.to_owned(),
                    ty,
                })
            }
            FactorInfo::Cte(map) => {
                let (src_slot, src_col, ty) = map.get(col)?;
                Some(ResolvedCol::CteDirect {
                    qual: qual.to_owned(),
                    src_slot: src_slot.clone(),
                    src_col: src_col.clone(),
                    ty: *ty,
                })
            }
            FactorInfo::Opaque => None,
        }
    }

    fn resolve_col(&self, expr: &Expr) -> Option<ResolvedCol> {
        match unwrap_nested(expr) {
            Expr::CompoundIdentifier(parts) if parts.len() == 2 => {
                let qual = parts[0].value.to_ascii_lowercase();
                let col = parts[1].value.to_ascii_lowercase();
                let info = self.factors_by_qual.get(&qual)?;
                self.resolve_in_factor(&qual, info, &col)
            }
            Expr::Identifier(ident) => {
                let col = ident.value.to_ascii_lowercase();
                if let Some(only) = self.only_qual {
                    let info = self.factors_by_qual.get(only)?;
                    return self.resolve_in_factor(only, info, &col);
                }
                if !self.all_plain_base {
                    return None;
                }
                let mut found: Option<ResolvedCol> = None;
                for (qual, info) in self.factors_by_qual {
                    if let Some(resolved) = self.resolve_in_factor(qual, info, &col) {
                        if found.is_some() {
                            return None;
                        }
                        found = Some(resolved);
                    }
                }
                found
            }
            _ => None,
        }
    }

    fn resolve_base_for_filter(&self, expr: &Expr) -> Option<(String, String, SqlType)> {
        match self.resolve_col(expr)? {
            ResolvedCol::Base { qual, col, ty, .. } => Some((qual, col, ty)),
            ResolvedCol::CteDirect { .. } => None,
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
            if let Some((rel, col, ty)) = ctx.resolve_base_for_filter(left) {
                match ty {
                    SqlType::U64 => parse_u64_lit(right).map(|v| (rel, RowFilter::EqU64(col, v))),
                    SqlType::Text => {
                        parse_text_lit(right).map(|v| (rel, RowFilter::EqText(col, v)))
                    }
                    _ => None,
                }
            } else if let Some((rel, col, ty)) = ctx.resolve_base_for_filter(right) {
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
            let (rel, col, ty) = ctx.resolve_base_for_filter(child)?;
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
            let (rel, col, ty) = ctx.resolve_base_for_filter(child)?;
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
            let (rel, col, ty) = ctx.resolve_base_for_filter(child)?;
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
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn partition_hints(
    query: &Query,
    tokens: &[Token],
    partition_columns: &BTreeMap<String, String>,
) -> BTreeMap<String, u64> {
    let mut hints = raw_partition_hints(query, partition_columns);
    // the relation must be named once in the whole statement; anything else may use its other rows. A name followed by a
    // period is a qualifier of a column (`classes.file_id`), not a mention of the table.
    hints.retain(|relation, _| mentions(tokens, relation) == 1);
    hints
}

/// As [`partition_hints`], using precomputed non-qualifier word counts per lowercased partition relation name.
pub(crate) fn partition_hints_with_counts(
    query: &Query,
    mention_counts: &BTreeMap<String, usize>,
    partition_columns: &BTreeMap<String, String>,
) -> BTreeMap<String, u64> {
    let mut hints = raw_partition_hints(query, partition_columns);
    hints.retain(|relation, _| mention_counts.get(relation).copied().unwrap_or(0) == 1);
    hints
}

fn raw_partition_hints(
    query: &Query,
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
    hints
}

/// How many times `name` appears in the statement other than as the qualifier of a column.
#[cfg_attr(not(test), allow(dead_code))]
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

        let filtered = extract_direct_count_group_by(
            "SELECT file_id, kind, COUNT(*) AS cnt FROM class_methods WHERE file_id = 0 AND kind LIKE 'v%' GROUP BY file_id, kind ORDER BY file_id, kind",
            &rels,
            &no_ctes,
            64,
        )
        .expect("must extract filtered class_methods GROUP BY plan");
        assert_eq!(
            filtered.predicates,
            vec![
                DirectPredicate::EqU64(0, 0),
                DirectPredicate::LikeAsciiPrefix(1, "v".into()),
            ]
        );
        assert_eq!(filtered.order_by_group_asc, vec![0, 1]);

        let text_group = extract_direct_count_group_by(
            "SELECT kind, COUNT(*) AS cnt FROM class_methods WHERE file_id BETWEEN 1 AND 3 AND (kind = 'direct' OR kind LIKE '%\\_v%' ESCAPE '\\') GROUP BY kind ORDER BY kind ASC",
            &rels,
            &no_ctes,
            64,
        )
        .expect("must extract filtered Text GROUP BY with ORDER BY");
        assert_eq!(text_group.group_columns, vec![1]);
        assert_eq!(text_group.order_by_group_asc, vec![0]);
        assert_eq!(
            text_group.predicates,
            vec![
                DirectPredicate::BetweenU64(0, 1, 3),
                DirectPredicate::Or(vec![
                    DirectPredicate::EqText(1, "direct".into()),
                    DirectPredicate::LikeAsciiContains(1, "_v".into()),
                ]),
            ]
        );

        assert!(
            extract_direct_count_group_by_with_dialect(
                "SELECT kind, COUNT(*) AS cnt FROM class_methods WHERE kind LIKE 'd%' GROUP BY kind",
                &rels,
                &no_ctes,
                64,
                SqlDialect::NativeV1,
            )
            .is_none(),
            "NativeV1 alphabetic LIKE must fall back in GROUP BY"
        );

        for rejected in [
            "SELECT file_id, kind, COUNT(*) FROM class_methods GROUP BY file_id, kind",
            "SELECT (file_id), kind, COUNT(*) AS cnt FROM class_methods GROUP BY file_id, kind",
            "SELECT file_id, kind, COUNT(*) AS cnt FROM class_methods WHERE kind LIKE 'v_' GROUP BY file_id, kind",
            "SELECT file_id, kind, COUNT(*) AS cnt FROM class_methods WHERE file_id != 0 GROUP BY file_id, kind",
            "SELECT file_id, kind, COUNT(*) AS cnt FROM class_methods GROUP BY file_id, kind HAVING COUNT(*) > 1",
            "SELECT DISTINCT file_id, kind FROM class_methods GROUP BY file_id, kind",
            "SELECT file_id, kind, COUNT(*) AS cnt FROM class_methods GROUP BY file_id, kind LIMIT 2",
            "SELECT file_id, kind, COUNT(*) AS cnt FROM class_methods GROUP BY file_id, kind ORDER BY kind DESC",
            "SELECT file_id, COUNT(*) AS kind FROM class_methods GROUP BY file_id ORDER BY kind",
            "SELECT file_id AS x, kind AS x, COUNT(*) AS cnt FROM class_methods GROUP BY file_id, kind ORDER BY x",
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

        let like_or = extract_direct_filtered_projection(
            "SELECT file_id FROM classes WHERE file_id = 0 OR descriptor LIKE 'La%'",
            &rels,
            &no_ctes,
            64,
        )
        .expect("OR + exact LIKE prefix");
        assert_eq!(
            like_or.predicates,
            vec![DirectPredicate::Or(vec![
                DirectPredicate::EqU64(0, 0),
                DirectPredicate::LikeAsciiPrefix(2, "la".into()),
            ])]
        );

        let between_like_variants = extract_direct_filtered_projection(
            "SELECT file_id FROM classes WHERE (file_id BETWEEN 1 AND 5 AND lower(descriptor) LIKE 'La%%;') OR (class_idx BETWEEN 10 AND 2 AND descriptor LIKE '%%Init%%' AND descriptor LIKE 'La\\_%' ESCAPE '\\')",
            &rels,
            &no_ctes,
            64,
        )
        .expect("BETWEEN + LIKE PrefixSuffix/Contains/lower/ESCAPE + nested AND inside OR");
        assert_eq!(
            between_like_variants.predicates,
            vec![DirectPredicate::Or(vec![
                DirectPredicate::And(vec![
                    DirectPredicate::BetweenU64(0, 1, 5),
                    DirectPredicate::LikeAsciiPrefixSuffix(2, "la".into(), ";".into()),
                ]),
                DirectPredicate::And(vec![
                    DirectPredicate::BetweenU64(1, 10, 2),
                    DirectPredicate::LikeAsciiContains(2, "init".into()),
                    DirectPredicate::LikeAsciiPrefix(2, "la_".into()),
                ]),
            ])]
        );

        let mut many_or_clauses = Vec::with_capacity(120);
        for idx in 0..120 {
            many_or_clauses.push(format!("descriptor LIKE 'Lp{idx:03}%'"));
        }
        let many_or_sql = format!(
            "SELECT file_id FROM classes WHERE {}",
            many_or_clauses.join(" OR ")
        );
        let many_or = extract_direct_filtered_projection(&many_or_sql, &rels, &no_ctes, 64)
            .expect("120-branch flat OR chain must flatten cleanly");
        match many_or.predicates.as_slice() {
            [DirectPredicate::Or(branches)] => assert_eq!(branches.len(), 120),
            other => panic!("expected flattened Or(120), got {other:?}"),
        }

        // NativeV1 allows non-alphabetic ASCII LIKE, but refuses alphabetic LIKE and lower(...) LIKE.
        let native_num_like = extract_direct_filtered_projection_with_dialect(
            "SELECT file_id FROM classes WHERE descriptor LIKE '123%'",
            &rels,
            &no_ctes,
            64,
            SqlDialect::NativeV1,
        )
        .expect("NativeV1 non-alpha ASCII LIKE prefix");
        assert_eq!(
            native_num_like.predicates,
            vec![DirectPredicate::LikeAsciiPrefix(2, "123".into())]
        );
        for native_rejected in [
            "SELECT file_id FROM classes WHERE descriptor LIKE 'La%'",
            "SELECT file_id FROM classes WHERE lower(descriptor) LIKE '123%'",
            "SELECT file_id FROM classes WHERE lower(descriptor) LIKE 'la%'",
        ] {
            assert!(
                extract_direct_filtered_projection_with_dialect(
                    native_rejected,
                    &rels,
                    &no_ctes,
                    64,
                    SqlDialect::NativeV1,
                )
                .is_none(),
                "NativeV1 must refuse {native_rejected}"
            );
        }

        let u64_above_i64_max = format!(
            "SELECT file_id FROM classes WHERE file_id = {}",
            i64::MAX as u64 + 1
        );
        assert!(
            extract_direct_filtered_projection_with_dialect(
                &u64_above_i64_max,
                &rels,
                &no_ctes,
                64,
                SqlDialect::DexSql011,
            )
            .is_none(),
            "DexSql011 must fall back on u64 literals > i64::MAX"
        );
        assert!(
            extract_direct_filtered_projection_with_dialect(
                &u64_above_i64_max,
                &rels,
                &no_ctes,
                64,
                SqlDialect::NativeV1,
            )
            .is_some(),
            "NativeV1 accepts full u64 range"
        );

        for rejected in [
            "SELECT file_id FROM classes",
            "SELECT (file_id) FROM classes WHERE file_id = 0",
            "SELECT file_id FROM classes WHERE NOT (file_id = 0)",
            "SELECT file_id FROM classes WHERE file_id NOT BETWEEN 1 AND 5",
            "SELECT file_id FROM classes WHERE file_id BETWEEN -1 AND 5",
            "SELECT file_id FROM classes WHERE file_id BETWEEN 1 AND class_idx",
            "SELECT file_id FROM classes WHERE descriptor BETWEEN 'a' AND 'z'",
            "SELECT file_id FROM classes WHERE descriptor NOT LIKE 'La%'",
            "SELECT file_id FROM classes WHERE descriptor LIKE 'La_'",
            "SELECT file_id FROM classes WHERE descriptor LIKE '%La'",
            "SELECT file_id FROM classes WHERE descriptor LIKE 'La'",
            "SELECT file_id FROM classes WHERE descriptor LIKE '%'",
            "SELECT file_id FROM classes WHERE descriptor LIKE 'La%b%'",
            "SELECT file_id FROM classes WHERE descriptor LIKE '%a%b%'",
            "SELECT file_id FROM classes WHERE descriptor LIKE 'é%'",
            "SELECT file_id FROM classes WHERE descriptor LIKE 'La\\' ESCAPE '\\'",
            "SELECT file_id FROM classes WHERE descriptor LIKE 'La%' ESCAPE ''",
            "SELECT file_id FROM classes WHERE descriptor LIKE 'La%' ESCAPE 'ab'",
            "SELECT file_id FROM classes WHERE descriptor LIKE 'La%' ESCAPE 'é'",
            "SELECT file_id FROM classes WHERE file_id LIKE '1%'",
            "SELECT file_id FROM classes WHERE lower(descriptor, 'x') LIKE 'la%'",
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

    #[test]
    fn query_hints_supports_self_join_cte_left_join_and_collision_safety() {
        let col = |name: &str, data_type: SqlType| crate::provider::SqlColumn {
            id: name.to_owned(),
            name: name.to_owned(),
            data_type,
            nullable: false,
        };
        let rels = vec![
            SqlRelation {
                name: "method_strings".to_owned(),
                columns: vec![
                    col("method", SqlType::Text),
                    col("value", SqlType::Text),
                    col("file_id", SqlType::U64),
                ],
                required_layers: vec![],
                estimated_rows: None,
            },
            SqlRelation {
                name: "class_methods".to_owned(),
                columns: vec![
                    col("file_id", SqlType::U64),
                    col("class_idx", SqlType::U64),
                    col("class_descriptor", SqlType::Text),
                    col("method_descriptor", SqlType::Text),
                    col("access_flags", SqlType::U64),
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
                name: "class_fields".to_owned(),
                columns: vec![
                    col("file_id", SqlType::U64),
                    col("class_idx", SqlType::U64),
                    col("class_descriptor", SqlType::Text),
                    col("field_idx", SqlType::U64),
                ],
                required_layers: vec![],
                estimated_rows: None,
            },
            SqlRelation {
                name: "fields".to_owned(),
                columns: vec![
                    col("file_id", SqlType::U64),
                    col("field_idx", SqlType::U64),
                    col("descriptor", SqlType::Text),
                ],
                required_layers: vec![],
                estimated_rows: None,
            },
        ];
        let parse_q = |sql: &str| {
            let mut stmts = sqlparser::parser::Parser::parse_sql(&SQLiteDialect {}, sql).unwrap();
            let Statement::Query(q) = stmts.remove(0) else {
                panic!("expected Query for {sql}");
            };
            *q
        };

        // 1. 3-way self-join on method_strings joined with class_methods.
        let holder_sql = "SELECT DISTINCT ms1.method, cm.class_descriptor, cm.access_flags \
            FROM method_strings ms1 \
            JOIN method_strings ms2 ON ms1.method = ms2.method \
            JOIN method_strings ms3 ON ms1.method = ms3.method \
            JOIN class_methods cm ON ms1.method = cm.method_descriptor \
            WHERE ms1.value = 'AlphaTag' \
              AND ms2.value = 'BetaTag' \
              AND ms3.value = 'GammaTag' \
            ORDER BY ms1.method";
        let q_holder = parse_q(holder_sql);
        let hints_holder = query_hints(&q_holder, &rels);
        assert!(hints_holder.row_filters.is_empty());
        assert_eq!(hints_holder.scan_slots.len(), 3);
        assert_eq!(
            hints_holder.scan_slots,
            vec![
                ScanSlot {
                    slot_name: "__mdd_scan_0".to_owned(),
                    base_relation: "method_strings".to_owned(),
                    row_filter: Some(RowFilter::EqText("value".to_owned(), "AlphaTag".to_owned())),
                },
                ScanSlot {
                    slot_name: "__mdd_scan_1".to_owned(),
                    base_relation: "method_strings".to_owned(),
                    row_filter: Some(RowFilter::EqText("value".to_owned(), "BetaTag".to_owned())),
                },
                ScanSlot {
                    slot_name: "__mdd_scan_2".to_owned(),
                    base_relation: "method_strings".to_owned(),
                    row_filter: Some(RowFilter::EqText("value".to_owned(), "GammaTag".to_owned())),
                },
            ]
        );
        assert_eq!(
            hints_holder.equi_joins,
            vec![
                EquiJoinEdge {
                    left_relation: "__mdd_scan_0".to_owned(),
                    right_relation: "__mdd_scan_1".to_owned(),
                    columns: vec![("method".to_owned(), "method".to_owned())],
                    bidirectional: true,
                },
                EquiJoinEdge {
                    left_relation: "__mdd_scan_0".to_owned(),
                    right_relation: "__mdd_scan_2".to_owned(),
                    columns: vec![("method".to_owned(), "method".to_owned())],
                    bidirectional: true,
                },
                EquiJoinEdge {
                    left_relation: "__mdd_scan_0".to_owned(),
                    right_relation: "class_methods".to_owned(),
                    columns: vec![("method".to_owned(), "method_descriptor".to_owned())],
                    bidirectional: true,
                },
            ]
        );
        let adapted = crate::dialects::ast::adapt(
            holder_sql,
            crate::control::SqlLimits::default(),
            &[],
            &rels,
            SqlDialect::DexSql011,
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(
            adapted.sql.contains("\"__mdd_scan_0\" ms1"),
            "{}",
            adapted.sql
        );
        assert!(
            adapted.sql.contains("\"__mdd_scan_1\" ms2"),
            "{}",
            adapted.sql
        );
        assert!(
            adapted.sql.contains("\"__mdd_scan_2\" ms3"),
            "{}",
            adapted.sql
        );
        assert!(adapted.sql.contains("class_methods cm"), "{}", adapted.sql);

        // 2. CTE targets joined with class_fields and fields (both composite and class_descriptor keys).
        let cte_sql = "WITH targets AS (SELECT c.file_id, c.class_idx, c.descriptor FROM classes c WHERE c.descriptor IN ('La;', 'Lb;')) \
            SELECT t.descriptor, f.descriptor FROM class_fields cf \
            JOIN fields f ON f.file_id = cf.file_id AND f.field_idx = cf.field_idx \
            JOIN targets t ON cf.class_descriptor = t.descriptor";
        let hints_cte = query_hints(&parse_q(cte_sql), &rels);
        assert!(hints_cte.scan_slots.is_empty());
        assert_eq!(
            hints_cte.row_filters.get("classes"),
            Some(&RowFilter::InText(
                "descriptor".to_owned(),
                vec!["La;".to_owned(), "Lb;".to_owned()]
            ))
        );
        assert!(hints_cte.equi_joins.contains(&EquiJoinEdge {
            left_relation: "classes".to_owned(),
            right_relation: "class_fields".to_owned(),
            columns: vec![("descriptor".to_owned(), "class_descriptor".to_owned())],
            bidirectional: false,
        }));
        assert!(hints_cte.equi_joins.contains(&EquiJoinEdge {
            left_relation: "class_fields".to_owned(),
            right_relation: "fields".to_owned(),
            columns: vec![
                ("file_id".to_owned(), "file_id".to_owned()),
                ("field_idx".to_owned(), "field_idx".to_owned()),
            ],
            bidirectional: true,
        }));

        // 3. Negative soundness: cross-alias OR must not push filters onto either slot.
        let cross_or = "SELECT ms1.method FROM method_strings ms1 \
            JOIN method_strings ms2 ON ms1.method = ms2.method \
            WHERE ms1.value = 'A' OR ms2.value = 'B'";
        let hints_or = query_hints(&parse_q(cross_or), &rels);
        assert!(hints_or.row_filters.is_empty());
        assert!(
            hints_or
                .scan_slots
                .iter()
                .all(|slot| slot.row_filter.is_none())
        );

        // 4. Negative soundness: LEFT JOIN filter placement and unidirectional semi-join edge.
        let left_self = "SELECT a.descriptor, b.descriptor FROM classes a \
            LEFT JOIN classes b ON a.class_idx = b.class_idx AND a.file_id = 0 AND b.file_id = 1 \
            WHERE a.descriptor = 'La;' AND b.descriptor = 'Lb;'";
        let hints_left = query_hints(&parse_q(left_self), &rels);
        assert_eq!(
            hints_left.scan_slots,
            vec![
                ScanSlot {
                    slot_name: "__mdd_scan_0".to_owned(),
                    base_relation: "classes".to_owned(),
                    row_filter: Some(RowFilter::EqText("descriptor".to_owned(), "La;".to_owned())),
                },
                ScanSlot {
                    slot_name: "__mdd_scan_1".to_owned(),
                    base_relation: "classes".to_owned(),
                    row_filter: Some(RowFilter::EqU64("file_id".to_owned(), 1)),
                },
            ]
        );
        assert_eq!(
            hints_left.equi_joins,
            vec![EquiJoinEdge {
                left_relation: "__mdd_scan_0".to_owned(),
                right_relation: "__mdd_scan_1".to_owned(),
                columns: vec![("class_idx".to_owned(), "class_idx".to_owned())],
                bidirectional: false,
            }]
        );

        // 5. Negative soundness: WITH RECURSIVE returns empty hints.
        let rec_sql = "WITH RECURSIVE r(x) AS (SELECT file_id FROM classes UNION ALL SELECT x FROM r WHERE x < 1) \
            SELECT * FROM r";
        let hints_rec = query_hints(&parse_q(rec_sql), &rels);
        assert!(hints_rec.row_filters.is_empty());
        assert!(hints_rec.scan_slots.is_empty());
        assert!(hints_rec.equi_joins.is_empty());

        // 6. Negative soundness: CTE shadowing a base table hides base relation filter.
        let shadow_sql = "WITH classes AS (SELECT method AS descriptor FROM method_strings WHERE value = 'X') \
            SELECT descriptor FROM classes WHERE descriptor = 'La;'";
        let hints_shadow = query_hints(&parse_q(shadow_sql), &rels);
        assert!(!hints_shadow.row_filters.contains_key("classes"));
        assert_eq!(
            hints_shadow.row_filters.get("method_strings"),
            Some(&RowFilter::EqText("value".to_owned(), "X".to_owned()))
        );
        assert!(hints_shadow.scan_slots.is_empty());

        // 7. Collision avoidance when caller already uses identifier `__mdd_scan_0`.
        let collide_sql = "SELECT __mdd_scan_0.method FROM method_strings __mdd_scan_0 \
            JOIN method_strings ms2 ON __mdd_scan_0.method = ms2.method \
            WHERE __mdd_scan_0.value = 'A' AND ms2.value = 'B'";
        let hints_collide = query_hints(&parse_q(collide_sql), &rels);
        assert_eq!(hints_collide.scan_slots.len(), 2);
        assert!(
            hints_collide
                .scan_slots
                .iter()
                .all(|slot| slot.slot_name != "__mdd_scan_0"),
            "{:?}",
            hints_collide.scan_slots
        );
    }
}
