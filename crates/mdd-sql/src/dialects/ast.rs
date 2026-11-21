//! Structural AST adaptation. No SQL regular-expression substitution.
use super::SqlDialect;
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
    /// Relation (lower case) to the value its partition column must have for a row to matter to the statement.
    pub partition_hints: BTreeMap<String, u64>,
    pub row_filters: BTreeMap<String, crate::provider::RowFilter>,
    pub equi_joins: Vec<crate::provider::EquiJoinEdge>,
}
#[derive(Clone)]
enum Dependency {
    Base(String),
    Cte(usize),
}
fn unsupported(reason: &str) -> MddError {
    MddError::new(ErrorCode::UnsupportedQuery, "sql.ast", reason)
}
/// MDD-084: the AST rewrite (`Rewrite::expr`/`query`) and the sqlparser `Display`
/// formatting are recursive descent. In a debug build their frames overflow a default
/// 1 MiB thread stack at roughly ten levels of boolean nesting, far below the validated
/// `max_ast_depth`. The rewrite therefore runs on a stack proven sufficient for the
/// absolute depth cap below, and that cap is aligned with the native evaluator's 64 so
/// validation never admits a depth the rewrite cannot safely traverse.
const AST_REWRITE_STACK_BYTES: usize = 16 * 1024 * 1024;
const MAX_AST_REWRITE_DEPTH: usize = 64;
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

mod affinity;
mod binding;
mod compound;
mod rewrite;
mod validate;
use self::{affinity::*, binding::*, compound::*, validate::*};

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
    partition_columns: &BTreeMap<String, String>,
) -> MddResult<Adapted> {
    adapt_with_mode(
        sql,
        limits,
        parameters,
        relations,
        dialect_policy,
        partition_columns,
        crate::column_store::sql_fast_udf_enabled(),
    )
}

#[cfg(test)]
pub(super) fn adapt_with_fast_udf(
    sql: &str,
    limits: SqlLimits,
    parameters: &[SqlValue],
    relations: &[crate::provider::SqlRelation],
    dialect_policy: super::SqlDialect,
    partition_columns: &BTreeMap<String, String>,
    fast_udf: bool,
) -> MddResult<Adapted> {
    adapt_with_mode(
        sql,
        limits,
        parameters,
        relations,
        dialect_policy,
        partition_columns,
        fast_udf,
    )
}

struct AstRequest {
    sql: String,
    limits: SqlLimits,
    parameters: Vec<SqlValue>,
    relations: Vec<crate::provider::SqlRelation>,
    dialect_policy: super::SqlDialect,
    partition_columns: BTreeMap<String, String>,
    fast_udf: bool,
    reply: std::sync::mpsc::SyncSender<MddResult<Adapted>>,
}

struct AstWorker {
    tx: std::sync::mpsc::SyncSender<AstRequest>,
}

fn adapt_with_mode(
    sql: &str,
    limits: SqlLimits,
    parameters: &[SqlValue],
    relations: &[crate::provider::SqlRelation],
    dialect_policy: super::SqlDialect,
    partition_columns: &BTreeMap<String, String>,
    fast_udf: bool,
) -> MddResult<Adapted> {
    // MDD-084: run the recursive AST rewrite on a stack proven sufficient for the
    // validated depth (see AST_REWRITE_STACK_BYTES). A persistent worker thread reuses
    // that stack across statements so simple queries avoid per-statement OS thread creation,
    // and any spawn failure or worker panic remains a fail-closed internal fault.
    static AST_WORKER: std::sync::OnceLock<std::sync::Mutex<Option<AstWorker>>> =
        std::sync::OnceLock::new();
    let slot = AST_WORKER.get_or_init(|| std::sync::Mutex::new(None));
    let mut guard = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_none() {
        let (tx, rx) = std::sync::mpsc::sync_channel::<AstRequest>(0);
        std::thread::Builder::new()
            .name("mdd-ast-rewrite".to_owned())
            .stack_size(AST_REWRITE_STACK_BYTES)
            .spawn(move || {
                while let Ok(req) = rx.recv() {
                    let result = adapt_on_stack(
                        &req.sql,
                        req.limits,
                        &req.parameters,
                        &req.relations,
                        req.dialect_policy,
                        &req.partition_columns,
                        req.fast_udf,
                    );
                    let _ = req.reply.send(result);
                }
            })
            .map(|_handle| {
                *guard = Some(AstWorker { tx });
            })
            .map_err(|_| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "sql.ast",
                    "AST rewrite thread could not be started",
                )
            })?;
    }
    let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel::<MddResult<Adapted>>(1);
    let req = AstRequest {
        sql: sql.to_owned(),
        limits,
        parameters: parameters.to_vec(),
        relations: relations.to_vec(),
        dialect_policy,
        partition_columns: partition_columns.clone(),
        fast_udf,
        reply: reply_tx,
    };
    let tx = guard
        .as_ref()
        .expect("AST worker initialized immediately above")
        .tx
        .clone();
    if tx.send(req).is_err() {
        *guard = None;
        return Err(MddError::new(
            ErrorCode::InternalFault,
            "sql.ast",
            "AST rewrite thread panicked",
        ));
    }
    match reply_rx.recv() {
        Ok(result) => result,
        Err(_) => {
            *guard = None;
            Err(MddError::new(
                ErrorCode::InternalFault,
                "sql.ast",
                "AST rewrite thread panicked",
            ))
        }
    }
}
fn adapt_on_stack(
    sql: &str,
    limits: SqlLimits,
    parameters: &[SqlValue],
    relations: &[crate::provider::SqlRelation],
    dialect_policy: super::SqlDialect,
    partition_columns: &BTreeMap<String, String>,
    fast_udf: bool,
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
    // read before the rewrite turns `file_id = 0` into a function call
    let partition_hints = super::pushdown::partition_hints(query, &tokens, partition_columns);
    let query_hints = super::pushdown::query_hints(query, relations);
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
        fast_udf,
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
        partition_hints,
        row_filters: query_hints.row_filters,
        equi_joins: query_hints.equi_joins,
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
    fast_udf: bool,
}
struct InScope {
    tables: BTreeMap<String, BTreeMap<String, crate::values::SqlType>>,
    order_aliases: BTreeSet<String>,
    boolean_aliases: BTreeSet<String>,
    select_aliases: BTreeMap<String, Option<crate::values::SqlType>>,
    aliases_visible: bool,
}

#[cfg(test)]
#[path = "ast/tests.rs"]
mod tests;
