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
    provider::{EquiJoinEdge, RowFilter, SqlRelation},
    values::SqlType,
};
use sqlparser::{ast::*, tokenizer::Token};
use std::collections::{BTreeMap, BTreeSet};

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
            let prefix = extract_ascii_like_prefix(&pat, esc)?;
            Some((rel, RowFilter::LikeAsciiPrefix(col, prefix)))
        }
        _ => None,
    }
}

fn extract_ascii_like_prefix(pattern: &str, escape: Option<char>) -> Option<String> {
    let mut prefix = String::new();
    let mut chars = pattern.chars();
    while let Some(ch) = chars.next() {
        if Some(ch) == escape {
            let escaped = chars.next()?;
            prefix.push(escaped);
        } else if ch == '%' || ch == '_' {
            break;
        } else {
            prefix.push(ch);
        }
    }
    if prefix.is_empty() || !prefix.is_ascii() {
        return None;
    }
    prefix.make_ascii_lowercase();
    Some(prefix)
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

        let unsafe_or =
            "SELECT descriptor FROM classes WHERE descriptor = 'La;' OR descriptor LIKE '%Lb%'";
        let stmts2 = sqlparser::parser::Parser::parse_sql(&SQLiteDialect {}, unsafe_or).unwrap();
        let sqlparser::ast::Statement::Query(q2) = &stmts2[0] else {
            panic!("not a query");
        };
        assert!(query_hints(q2, &rels).row_filters.is_empty());

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
}
