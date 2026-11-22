//! Structural AST adaptation. No SQL regular-expression substitution.
use super::SqlDialect;
use crate::{control::SqlLimits, invalid, quota, values::SqlValue};
use mdd_query::ir::Signed64;
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use sqlparser::{
    ast::*,
    dialect::SQLiteDialect,
    parser::{Parser, ParserError},
    tokenizer::{Token, TokenWithSpan, Tokenizer},
};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub(crate) struct PreparedSchema {
    pub relations: Arc<[crate::provider::SqlRelation]>,
    pub partition_columns: BTreeMap<String, String>,
    pub schemas: BTreeMap<String, Vec<String>>,
    pub schema_types: BTreeMap<String, BTreeMap<String, crate::values::SqlType>>,
    pub reserved_base: BTreeSet<String>,
}

impl PreparedSchema {
    pub(crate) fn new(
        relations: Vec<crate::provider::SqlRelation>,
        partition_columns: BTreeMap<String, String>,
    ) -> Self {
        let mut schemas = BTreeMap::new();
        let mut schema_types = BTreeMap::new();
        let mut reserved_base = BTreeSet::new();
        for r in &relations {
            let rel_key = r.name.to_ascii_lowercase();
            reserved_base.insert(rel_key.clone());
            let mut col_names = Vec::with_capacity(r.columns.len());
            let mut col_types = BTreeMap::new();
            for c in &r.columns {
                let col_key = c.name.to_ascii_lowercase();
                reserved_base.insert(col_key.clone());
                col_names.push(c.name.clone());
                col_types.insert(col_key, c.data_type);
            }
            schemas.insert(rel_key.clone(), col_names);
            schema_types.insert(rel_key, col_types);
        }
        Self {
            relations: relations.into(),
            partition_columns,
            schemas,
            schema_types,
            reserved_base,
        }
    }
}

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
    pub direct_projection: Option<crate::provider::DirectTableProjection>,
    pub direct_filtered_projection: Option<crate::provider::DirectFilteredProjection>,
    pub direct_count_group_by: Option<crate::provider::DirectCountGroupBy>,
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

#[cfg(test)]
pub(crate) fn adapt(
    sql: &str,
    limits: SqlLimits,
    parameters: &[SqlValue],
    relations: &[crate::provider::SqlRelation],
    dialect_policy: super::SqlDialect,
    partition_columns: &BTreeMap<String, String>,
) -> MddResult<Adapted> {
    let schema = Arc::new(PreparedSchema::new(
        relations.to_vec(),
        partition_columns.clone(),
    ));
    adapt_with_schema(sql, limits, parameters, &schema, dialect_policy)
}

pub(crate) fn adapt_with_schema(
    sql: &str,
    limits: SqlLimits,
    parameters: &[SqlValue],
    schema: &Arc<PreparedSchema>,
    dialect_policy: super::SqlDialect,
) -> MddResult<Adapted> {
    adapt_with_mode(
        sql,
        limits,
        parameters,
        schema,
        dialect_policy,
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
    let schema = Arc::new(PreparedSchema::new(
        relations.to_vec(),
        partition_columns.clone(),
    ));
    adapt_with_mode(sql, limits, parameters, &schema, dialect_policy, fast_udf)
}

const MAX_SHALLOW_SQL_BYTES: usize = 4096;
const MAX_SHALLOW_TOKENS: usize = 256;
const MAX_SHALLOW_NESTING: usize = 8;
const MAX_SHALLOW_OPERATORS: usize = 32;

struct PreparedTokens {
    tokens: Vec<TokenWithSpan>,
    reserved: BTreeSet<String>,
    partition_mentions: BTreeMap<String, usize>,
    is_shallow: bool,
}

fn is_flat_operator_keyword(word: &str) -> bool {
    word.eq_ignore_ascii_case("AND")
        || word.eq_ignore_ascii_case("OR")
        || word.eq_ignore_ascii_case("NOT")
        || word.eq_ignore_ascii_case("UNION")
        || word.eq_ignore_ascii_case("INTERSECT")
        || word.eq_ignore_ascii_case("EXCEPT")
        || word.eq_ignore_ascii_case("CASE")
}

fn scan_word_metadata(
    tokens: &[TokenWithSpan],
    schema: &PreparedSchema,
) -> (BTreeSet<String>, BTreeMap<String, usize>) {
    let mut reserved = BTreeSet::new();
    let mut partition_mentions = BTreeMap::new();
    let check_partitions = !schema.partition_columns.is_empty();
    for (at, tws) in tokens.iter().enumerate() {
        let Token::Word(word) = &tws.token else {
            continue;
        };
        let lower = word.value.to_ascii_lowercase();
        if check_partitions
            && schema.partition_columns.contains_key(&lower)
            && !matches!(
                tokens[at + 1..]
                    .iter()
                    .find(|next| !matches!(next.token, Token::Whitespace(_)))
                    .map(|next| &next.token),
                Some(Token::Period)
            )
        {
            *partition_mentions.entry(lower.clone()).or_insert(0) += 1;
        }
        if !schema.reserved_base.contains(&lower) {
            reserved.insert(lower);
        }
    }
    (reserved, partition_mentions)
}

fn preflight_tokenize(
    sql: &str,
    limits: SqlLimits,
    schema: &PreparedSchema,
) -> MddResult<PreparedTokens> {
    if sql.len() > limits.max_sql_bytes {
        return Err(quota("SQL_TEXT_BYTES"));
    }
    let dialect = SQLiteDialect {};
    let tokens = Tokenizer::new(&dialect, sql)
        .tokenize_with_location()
        .map_err(|e| invalid(&format!("SQL_TOKEN_ERROR: {e}")))?;
    if tokens.len() > limits.max_tokens || tokens.len() > limits.max_ast_nodes.saturating_mul(4) {
        return Err(quota("SQL_TOKEN_OR_NODE_PREFLIGHT"));
    }
    // A recursive parser limit alone does not bound left-associative BinaryOp
    // or UNION trees. Bound their input before any owned recursive AST exists.
    let mut nesting = 0usize;
    let mut max_nesting = 0usize;
    let mut operators = 0usize;
    for tws in &tokens {
        match &tws.token {
            Token::LParen | Token::LBracket => {
                nesting += 1;
                if nesting > limits.max_ast_depth {
                    return Err(quota("SQL_LEXICAL_DEPTH"));
                }
                max_nesting = max_nesting.max(nesting);
            }
            Token::RParen | Token::RBracket => nesting = nesting.saturating_sub(1),
            Token::Whitespace(_)
            | Token::SingleQuotedString(_)
            | Token::DoubleQuotedString(_)
            | Token::Number(_, _) => (),
            Token::Word(word)
                if word.quote_style.is_none() && is_flat_operator_keyword(&word.value) =>
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
    let is_shallow = sql.len() <= MAX_SHALLOW_SQL_BYTES
        && tokens.len() <= MAX_SHALLOW_TOKENS
        && max_nesting <= MAX_SHALLOW_NESTING
        && operators <= MAX_SHALLOW_OPERATORS;
    let (reserved, partition_mentions) = scan_word_metadata(&tokens, schema);
    Ok(PreparedTokens {
        tokens,
        reserved,
        partition_mentions,
        is_shallow,
    })
}

struct AstRequest {
    pre: PreparedTokens,
    limits: SqlLimits,
    parameters: Vec<SqlValue>,
    schema: Arc<PreparedSchema>,
    dialect_policy: super::SqlDialect,
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
    schema: &Arc<PreparedSchema>,
    dialect_policy: super::SqlDialect,
    fast_udf: bool,
) -> MddResult<Adapted> {
    let pre = preflight_tokenize(sql, limits, schema)?;
    if pre.is_shallow {
        return adapt_on_tokens(pre, limits, parameters, schema, dialect_policy, fast_udf);
    }

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
                    let result = adapt_on_tokens(
                        req.pre,
                        req.limits,
                        &req.parameters,
                        &req.schema,
                        req.dialect_policy,
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
        pre,
        limits,
        parameters: parameters.to_vec(),
        schema: Arc::clone(schema),
        dialect_policy,
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
fn adapt_on_tokens(
    pre: PreparedTokens,
    limits: SqlLimits,
    parameters: &[SqlValue],
    schema: &PreparedSchema,
    dialect_policy: super::SqlDialect,
    fast_udf: bool,
) -> MddResult<Adapted> {
    let PreparedTokens {
        tokens,
        reserved,
        partition_mentions,
        is_shallow: _,
    } = pre;
    let dialect = SQLiteDialect {};
    let mut statements = Parser::new(&dialect)
        .with_recursion_limit(limits.max_ast_depth)
        .with_tokens_with_locations(tokens)
        .parse_statements()
        .map_err(parse_error)?;
    if statements.len() != 1 {
        return Err(invalid("SQL_REQUIRES_ONE_STATEMENT"));
    }
    let Statement::Query(query) = &mut statements[0] else {
        return Err(invalid("SQL_STATEMENT_NOT_READ_ONLY_QUERY"));
    };
    // read before the rewrite turns `file_id = 0` into a function call
    let partition_hints = super::pushdown::partition_hints_with_counts(
        query,
        &partition_mentions,
        &schema.partition_columns,
    );
    let query_hints =
        super::pushdown::query_hints_with_types(query, &schema.relations, &schema.schema_types);
    let empty_ctes = BTreeSet::new();
    let direct_projection = super::pushdown::extract_direct_projection_from_query(
        query,
        &schema.relations,
        &empty_ctes,
    );
    let direct_filtered_projection = if direct_projection.is_none() {
        super::pushdown::extract_direct_filtered_projection_from_query(
            query,
            &schema.relations,
            &empty_ctes,
            dialect_policy,
        )
    } else {
        None
    };
    let direct_count_group_by =
        if direct_projection.is_none() && direct_filtered_projection.is_none() {
            super::pushdown::extract_direct_count_group_by_from_query(
                query,
                &schema.relations,
                &empty_ctes,
                dialect_policy,
            )
        } else {
            None
        };
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
        schemas: &schema.schemas,
        schema_types: &schema.schema_types,
        cte_columns: BTreeMap::new(),
        reserved_base: &schema.reserved_base,
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
        direct_projection,
        direct_filtered_projection,
        direct_count_group_by,
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
    schemas: &'a BTreeMap<String, Vec<String>>,
    schema_types: &'a BTreeMap<String, BTreeMap<String, crate::values::SqlType>>,
    cte_columns: BTreeMap<usize, Vec<String>>,
    reserved_base: &'a BTreeSet<String>,
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
