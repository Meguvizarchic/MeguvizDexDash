//! Session TEMP statements over the read-only bridge.
//!
//! `CREATE [TEMP] TABLE|VIEW [IF NOT EXISTS] name AS <query>` and
//! `DROP TABLE|VIEW [IF EXISTS] name` change the session's TEMP catalog; every
//! other statement must be a plain query. A definition is a *query*, never a
//! stored result: the catalog keeps its normalized text, its fingerprint and the
//! TEMP names it reads, and a statement that reads it is expanded into ordinary
//! CTEs at prepare time against the catalog as it is then. Nothing is
//! materialized, which is also what the frozen reference engine does (a TABLE
//! defined over another TABLE sees that table's later redefinition).
//!
//! Three consequences follow from expanding at prepare time:
//!
//! * a prepared statement, and a native cursor over it, keeps the definitions it
//!   was expanded with when the catalog changes afterwards;
//! * the cursor/page source identity carries the digest of exactly those
//!   definitions ([`PreparedSql::temp_fingerprint`]), so a compatible-offset
//!   re-execution after a redefinition is refused as `source_changed` instead of
//!   stitching rows of two different definitions into one sequence;
//! * a body with a volatile function is refused, because two evaluations of it
//!   would disagree where a materialized table would not.
//!
//! The catalog itself (`mdd_session::catalog`) never parses SQL; this module
//! supplies it with names, dependencies and hashes.
use crate::{
    SqlBridge, SqlResult,
    bridge::PreparedSql,
    control::{SqlControl, SqlLimits},
    invalid, quota,
    window::{SqlWindow, SqlWindowReport, is_volatile, script_statements},
};
use mdd_session::{
    Lifecycle, SessionHandle,
    catalog::{CreateTempDefinition, TempCatalogChange, TempKind, TempMaterialization},
};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use sqlparser::{
    ast::{ObjectType, Query, Statement},
    dialect::SQLiteDialect,
    keywords::Keyword,
    parser::{Parser, ParserError},
    tokenizer::{Token, Tokenizer},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

/// Statement kind reported for every `CREATE`, including views: the reference
/// engine does not distinguish them there.
pub const KIND_CREATE: &str = "create_temp_table";
/// Statement kind reported for every `DROP`.
pub const KIND_DROP: &str = "drop_definition";

/// Named temporary queries one `query` call may carry in the reference tool.
pub const MAX_NAMED_TEMP_QUERIES: usize = 16;

/// One `named_temp_queries` entry of a call.
#[derive(Clone, Copy, Debug)]
pub struct NamedTempQuery<'a> {
    pub name: &'a str,
    pub sql: &'a str,
}

/// A name for a named temporary query: a plain ASCII identifier that is not an
/// SQL keyword, folded to lower case. Anything else is refused as invalid input
/// without a statement index, like the reference.
fn named_identifier(name: &str) -> MddResult<String> {
    let plain = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && name.len() <= 128;
    let keyword = Tokenizer::new(&SQLiteDialect {}, name)
        .tokenize()
        .ok()
        .and_then(|tokens| {
            tokens.into_iter().find_map(|token| match token {
                Token::Word(word) => Some(word.keyword != Keyword::NoKeyword),
                _ => None,
            })
        })
        .unwrap_or(true);
    if !plain || keyword {
        return Err(invalid("INVALID_TEMP_TABLE_NAME").detail("name", name.to_owned()));
    }
    Ok(name.to_ascii_lowercase())
}

fn unsupported(reason: &str) -> MddError {
    MddError::new(ErrorCode::UnsupportedQuery, "sql.temp", reason)
}

fn parse_error(error: ParserError) -> MddError {
    if error == ParserError::RecursionLimitExceeded {
        quota("SQL_PARSER_DEPTH")
    } else {
        invalid(&format!("SQL_PARSE_ERROR: {error}"))
    }
}

/// What a statement asks for, after parsing.
enum Parsed {
    Query(Box<Query>),
    Create {
        name: String,
        kind: TempKind,
        if_not_exists: bool,
        query: Box<Query>,
    },
    Drop {
        name: String,
        kind: TempKind,
        if_exists: bool,
    },
}

fn parse_statement(sql: &str, limits: SqlLimits) -> MddResult<Parsed> {
    if sql.len() > limits.max_sql_bytes {
        return Err(quota("SQL_TEXT_BYTES"));
    }
    let dialect = SQLiteDialect {};
    let tokens = Tokenizer::new(&dialect, sql)
        .tokenize()
        .map_err(|error| invalid(&format!("SQL_TOKEN_ERROR: {error}")))?;
    if tokens.len() > limits.max_tokens {
        return Err(quota("SQL_TOKEN_OR_NODE_PREFLIGHT"));
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
    let statement = statements.remove(0);
    match &statement {
        Statement::Query(_) => {
            let Statement::Query(query) = statement else {
                unreachable!("matched above")
            };
            Ok(Parsed::Query(query))
        }
        Statement::CreateTable(create) => {
            // Only the temporary `AS <query>` form is inside the profile.
            let (Some(query), true) = (create.query.clone(), create.temporary) else {
                return Err(unsupported(
                    "only CREATE TEMP TABLE name AS query is inside the TEMP subset",
                ));
            };
            let name = simple_name(&create.name)?;
            // Every option the parser accepted that this module does not model
            // changes the printed statement, so comparing against the canonical
            // print refuses it instead of silently dropping it.
            let canonical = format!(
                "CREATE TEMPORARY TABLE {}{} AS {query}",
                if create.if_not_exists {
                    "IF NOT EXISTS "
                } else {
                    ""
                },
                create.name
            );
            if statement.to_string() != canonical {
                return Err(unsupported(
                    "CREATE TEMP TABLE options beyond `AS query` are outside the TEMP subset",
                ));
            }
            Ok(Parsed::Create {
                name,
                kind: TempKind::Table,
                if_not_exists: create.if_not_exists,
                query,
            })
        }
        Statement::CreateView(view) => {
            let name = simple_name(&view.name)?;
            let canonical = format!(
                "CREATE {}VIEW {}{} AS {}",
                if view.temporary { "TEMPORARY " } else { "" },
                if view.if_not_exists {
                    "IF NOT EXISTS "
                } else {
                    ""
                },
                view.name,
                view.query
            );
            if statement.to_string() != canonical {
                return Err(unsupported(
                    "CREATE VIEW options beyond `AS query` are outside the TEMP subset",
                ));
            }
            Ok(Parsed::Create {
                name,
                kind: TempKind::View,
                if_not_exists: view.if_not_exists,
                query: view.query.clone(),
            })
        }
        Statement::Drop {
            object_type,
            if_exists,
            names,
            ..
        } => {
            let kind = match object_type {
                ObjectType::Table => TempKind::Table,
                ObjectType::View => TempKind::View,
                _ => return Err(unsupported("only DROP TABLE and DROP VIEW are supported")),
            };
            let [only] = names.as_slice() else {
                return Err(unsupported("DROP takes exactly one name"));
            };
            let name = simple_name(only)?;
            let canonical = format!(
                "DROP {} {}{only}",
                kind.keyword(),
                if *if_exists { "IF EXISTS " } else { "" }
            );
            if statement.to_string() != canonical {
                return Err(unsupported(
                    "DROP options beyond the name are outside the TEMP subset",
                ));
            }
            Ok(Parsed::Drop {
                name,
                kind,
                if_exists: *if_exists,
            })
        }
        _ => Err(invalid("SQL_STATEMENT_NOT_READ_ONLY_QUERY")),
    }
}

/// A single unquoted identifier, folded to lower case like the reference engine.
fn simple_name(name: &sqlparser::ast::ObjectName) -> MddResult<String> {
    let [part] = name.0.as_slice() else {
        return Err(unsupported("TEMP names must not be qualified"));
    };
    let ident = part
        .as_ident()
        .ok_or_else(|| unsupported("TEMP names must be simple identifiers"))?;
    let value = &ident.value;
    let simple = ident.quote_style.is_none()
        && value
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && value.len() <= 128;
    if !simple {
        return Err(unsupported("TEMP names must be simple identifiers"));
    }
    Ok(value.to_ascii_lowercase())
}

/// Every identifier-like word of `sql`, lower-cased, ignoring string literals and
/// comments and the alias that follows `AS`. This is a superset of the relation
/// names the statement reads: a column that shares a name with a TEMP definition
/// is included too. A superset is the safe direction here, because a missed name
/// could let a provider relation of the same name answer in place of the TEMP
/// definition, while an extra name only adds an unused CTE.
fn identifier_words(sql: &str, limits: SqlLimits) -> MddResult<BTreeSet<String>> {
    let dialect = SQLiteDialect {};
    let tokens = Tokenizer::new(&dialect, sql)
        .tokenize()
        .map_err(|error| invalid(&format!("SQL_TOKEN_ERROR: {error}")))?;
    if tokens.len() > limits.max_tokens {
        return Err(quota("SQL_TOKEN_OR_NODE_PREFLIGHT"));
    }
    let mut words = BTreeSet::new();
    let mut previous_as = false;
    for token in &tokens {
        match token {
            Token::Whitespace(_) => continue,
            Token::Word(word) => {
                if !previous_as {
                    words.insert(word.value.to_ascii_lowercase());
                }
                previous_as = word.quote_style.is_none() && word.keyword == Keyword::AS;
            }
            _ => previous_as = false,
        }
    }
    Ok(words)
}

/// The outcome of one statement.
#[derive(Debug)]
pub enum TempStatementResult {
    /// A query: the (possibly windowed) rows.
    Rows(Box<SqlResult>),
    /// A catalog change. The window echoes the request's offset like the
    /// reference engine does, with no rows.
    Definition(DefinitionReport),
}

#[derive(Debug)]
pub struct DefinitionReport {
    pub kind: &'static str,
    pub change: TempCatalogChange,
    pub window: SqlWindowReport,
}

/// A query prepared against the catalog as it was when `prepare` ran.
pub struct TempQuery {
    prepared: PreparedSql,
    temp_names: Vec<String>,
    catalog_epoch: DecimalU64,
}

impl TempQuery {
    pub fn prepared(&self) -> &PreparedSql {
        &self.prepared
    }
    pub fn into_prepared(self) -> PreparedSql {
        self.prepared
    }
    /// TEMP definitions the statement reads, transitively and sorted. Pass them to
    /// `Lifecycle::bind_query_temp` so the query's catalog binding is stored.
    pub fn temp_names(&self) -> &[String] {
        &self.temp_names
    }
    /// Catalog epoch observed while expanding, as a decimal string on the wire.
    pub fn catalog_epoch(&self) -> DecimalU64 {
        self.catalog_epoch
    }
}

struct StoredBody {
    definition_hash: String,
    /// Normalized (AST-printed) text of the defining query.
    query_sql: String,
    /// [`identifier_words`] of `query_sql`, computed once at creation.
    words: BTreeSet<String>,
}

/// One session's TEMP statements. Cheap to build; holds no result data.
pub struct TempSqlSession {
    lifecycle: Arc<Lifecycle>,
    session: SessionHandle,
    bridge: SqlBridge,
    bodies: Mutex<BTreeMap<String, StoredBody>>,
}

impl TempSqlSession {
    /// Bind a bridge to a lifecycle session. The bridge's provider must read the
    /// snapshot the session pinned: the TEMP catalog epochs, cursor bindings and
    /// page source identities are recorded under the session, so a bridge over any
    /// other snapshot would answer from facts the session never admitted.
    pub fn new(
        lifecycle: Arc<Lifecycle>,
        session: SessionHandle,
        bridge: SqlBridge,
    ) -> MddResult<Self> {
        let pinned = lifecycle.snapshot_lease(&session)?;
        let provider = bridge.provider_binding();
        if pinned.manifest().snapshot_id != provider.snapshot_id {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "sql.temp",
                "bridge provider reads a different snapshot than the session pinned",
            )
            .detail("session_snapshot_id", pinned.manifest().snapshot_id.clone())
            .detail("provider_snapshot_id", provider.snapshot_id.clone()));
        }
        Ok(Self {
            lifecycle,
            session,
            bridge,
            bodies: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn bridge(&self) -> &SqlBridge {
        &self.bridge
    }

    pub fn catalog_epoch(&self) -> MddResult<DecimalU64> {
        self.lifecycle.temp_catalog_epoch(&self.session)
    }

    fn bodies(&self) -> MddResult<std::sync::MutexGuard<'_, BTreeMap<String, StoredBody>>> {
        self.bodies.lock().map_err(|_| {
            MddError::new(ErrorCode::InternalFault, "sql.temp", "TEMP bodies poisoned")
        })
    }

    /// Prepare a plain query, expanding every TEMP definition it reads.
    pub fn prepare(&self, sql: &str) -> MddResult<TempQuery> {
        let Parsed::Query(query) = parse_statement(sql, self.bridge.limits())? else {
            return Err(invalid("SQL_STATEMENT_NOT_READ_ONLY_QUERY"));
        };
        let bodies = self.bodies()?;
        self.prepare_locked(sql, query, &bodies)
    }

    fn prepare_locked(
        &self,
        sql: &str,
        query: Box<Query>,
        bodies: &BTreeMap<String, StoredBody>,
    ) -> MddResult<TempQuery> {
        let epoch = self.lifecycle.temp_catalog_epoch(&self.session)?;
        let (expanded, names) = self.expand(sql, query, bodies)?;
        let mut prepared = self.bridge.prepare(&expanded)?;
        if !names.is_empty() {
            let digest = names
                .iter()
                .map(|name| format!("{name}={}", bodies[name].definition_hash))
                .collect::<Vec<_>>()
                .join(";");
            prepared = prepared.with_temp_fingerprint(mdd_types::sha256(
                format!("mdd.sql.temp-binding.v1|{digest}").as_bytes(),
            ));
        }
        Ok(TempQuery {
            prepared,
            temp_names: names,
            catalog_epoch: epoch,
        })
    }

    /// Prepend the CTEs for the TEMP definitions `query` reads, dependencies
    /// first. Returns the statement text to prepare and the definition names.
    fn expand(
        &self,
        sql: &str,
        mut query: Box<Query>,
        bodies: &BTreeMap<String, StoredBody>,
    ) -> MddResult<(String, Vec<String>)> {
        let limits = self.bridge.limits();
        let own_ctes: BTreeSet<String> = query
            .with
            .as_ref()
            .map(|with| {
                with.cte_tables
                    .iter()
                    .map(|cte| cte.alias.name.value.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default();
        let seeds: Vec<String> = identifier_words(sql, limits)?
            .into_iter()
            .filter(|word| bodies.contains_key(word) && !own_ctes.contains(word))
            .collect();
        if seeds.is_empty() {
            return Ok((sql.to_owned(), Vec::new()));
        }
        // Depth-first, dependencies before dependents. A cycle can only appear
        // through a name that shadowed a provider relation after the definition
        // that reads it was made; refuse it rather than loop.
        let mut order = Vec::new();
        let mut done = BTreeSet::new();
        let mut visiting = Vec::new();
        for seed in &seeds {
            self.visit(seed, bodies, &mut visiting, &mut done, &mut order)?;
        }
        let list = order
            .iter()
            .map(|name| format!("{name} AS ({})", bodies[name].query_sql))
            .collect::<Vec<_>>()
            .join(", ");
        let Parsed::Query(synthetic) =
            parse_statement(&format!("WITH {list} SELECT 1"), unbounded(limits))?
        else {
            return Err(MddError::new(
                ErrorCode::InternalFault,
                "sql.temp",
                "TEMP expansion did not parse as a query",
            ));
        };
        let injected = synthetic.with.ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "sql.temp",
                "TEMP expansion lost its WITH clause",
            )
        })?;
        match query.with.as_mut() {
            // The caller's own `WITH [RECURSIVE]` keeps its flavour; the injected
            // definitions are plain CTEs placed first.
            Some(with) => {
                with.cte_tables.splice(0..0, injected.cte_tables);
            }
            None => query.with = Some(injected),
        }
        let mut names = order;
        names.sort();
        Ok((Statement::Query(query).to_string(), names))
    }

    fn visit(
        &self,
        name: &str,
        bodies: &BTreeMap<String, StoredBody>,
        visiting: &mut Vec<String>,
        done: &mut BTreeSet<String>,
        order: &mut Vec<String>,
    ) -> MddResult<()> {
        if done.contains(name) {
            return Ok(());
        }
        if visiting.iter().any(|open| open == name) {
            let mut path = visiting.clone();
            path.push(name.to_owned());
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "sql.temp",
                "TEMP definitions read each other in a cycle",
            )
            .detail("temp_error", "cycle")
            .detail("path", path.join(" -> ")));
        }
        let body = &bodies[name];
        visiting.push(name.to_owned());
        for word in &body.words {
            if bodies.contains_key(word) {
                self.visit(word, bodies, visiting, done, order)?;
            }
        }
        visiting.pop();
        done.insert(name.to_owned());
        order.push(name.to_owned());
        Ok(())
    }

    /// Run one statement. A query returns its rows (windowed when `window` is
    /// given); a definition changes the catalog and returns the change.
    pub fn execute(&self, sql: &str, window: Option<SqlWindow>) -> MddResult<TempStatementResult> {
        let limits = self.bridge.limits();
        match parse_statement(sql, limits)? {
            Parsed::Query(query) => {
                let prepared = {
                    let bodies = self.bodies()?;
                    self.prepare_locked(sql, query, &bodies)?.into_prepared()
                };
                let control = SqlControl::new(limits, None);
                let result = match window {
                    Some(window) => self.bridge.execute_window(&prepared, control, window)?,
                    None => self.bridge.execute(&prepared, control)?,
                };
                Ok(TempStatementResult::Rows(Box::new(result)))
            }
            Parsed::Create {
                name,
                kind,
                if_not_exists,
                query,
            } => {
                let change = self.create(&name, kind, if_not_exists, &query)?;
                Ok(TempStatementResult::Definition(report(
                    KIND_CREATE,
                    change,
                    window,
                )))
            }
            Parsed::Drop {
                name,
                kind,
                if_exists,
            } => {
                let mut bodies = self.bodies()?;
                let change =
                    self.lifecycle
                        .temp_catalog_drop(&self.session, &name, kind, if_exists)?;
                if matches!(change, TempCatalogChange::Dropped { .. }) {
                    bodies.remove(&name);
                }
                Ok(TempStatementResult::Definition(report(
                    KIND_DROP, change, window,
                )))
            }
        }
    }

    /// Run the `sql[]` items of one call like the reference `query` tool: one to
    /// sixteen items, each possibly a script of several statements (see
    /// [`script_statements`]), the same window on each statement's own result.
    ///
    /// Statements run in order and a failure stops the list and names its index,
    /// but catalog changes made by earlier statements stay, exactly as in the
    /// reference engine; a read-only list therefore stays all-or-nothing in
    /// effect while a list that defines something does not roll back.
    pub fn execute_batch(
        &self,
        items: &[&str],
        window: Option<SqlWindow>,
    ) -> MddResult<Vec<TempStatementResult>> {
        let statements = script_statements(items)?;
        let mut results = Vec::with_capacity(statements.len());
        for (index, sql) in statements.iter().enumerate() {
            match self.execute(sql, window) {
                Ok(result) => results.push(result),
                Err(error) => return Err(error.detail("statement_index", index.to_string())),
            }
        }
        Ok(results)
    }

    /// A whole `query` call: `named_temp_queries` first, then the `sql[]` items.
    ///
    /// A named temporary query is a lazy named `SELECT` definition kept in the
    /// session like a TEMP table: the reference engine registers it as a TABLE
    /// (so `DROP TABLE name` removes it and `DROP VIEW name` is refused), replaces
    /// an earlier definition of the same name silently, and processes the list in
    /// order, so a definition may read an earlier one but not a later one. Each
    /// body is exactly one query. The call shape (item count, blank items, byte
    /// budget, at most [`MAX_NAMED_TEMP_QUERIES`] definitions) is checked before
    /// anything changes; after that, definitions already made stay even when a
    /// later definition or statement fails, as with ordinary statements.
    pub fn execute_call(
        &self,
        items: &[&str],
        named: &[NamedTempQuery<'_>],
        window: Option<SqlWindow>,
    ) -> MddResult<Vec<TempStatementResult>> {
        if named.len() > MAX_NAMED_TEMP_QUERIES {
            return Err(invalid("NAMED_TEMP_QUERY_COUNT_OUT_OF_RANGE")
                .detail("named_temp_queries", named.len().to_string())
                .detail("maximum", MAX_NAMED_TEMP_QUERIES.to_string()));
        }
        script_statements(items)?;
        for definition in named {
            let name = named_identifier(definition.name)?;
            let Parsed::Query(query) = parse_statement(definition.sql, self.bridge.limits())?
            else {
                return Err(
                    unsupported("a named temporary query body must be a read-only query")
                        .detail("relation", name),
                );
            };
            // The reference reports a body that fails to bind at statement 0.
            self.create(&name, TempKind::Table, false, &query)
                .map_err(|error| error.detail("statement_index", "0"))?;
        }
        self.execute_batch(items, window)
    }

    fn create(
        &self,
        name: &str,
        kind: TempKind,
        if_not_exists: bool,
        query: &Query,
    ) -> MddResult<TempCatalogChange> {
        let query_sql = query.to_string();
        let definition_hash = mdd_types::sha256(
            format!("mdd.sql.temp-definition.v1|{}|{query_sql}", kind.keyword()).as_bytes(),
        );
        let mut bodies = self.bodies()?;
        // An existing name under IF NOT EXISTS ignores the whole new body, even
        // one that would not have been valid.
        if if_not_exists && bodies.contains_key(name) {
            return self.lifecycle.temp_catalog_create(
                &self.session,
                CreateTempDefinition {
                    name: name.to_owned(),
                    kind,
                    definition_hash,
                    dependencies: Vec::new(),
                    materialization: late_bound(&mdd_types::sha256(b"unchanged")),
                },
                true,
            );
        }
        if is_volatile(&query_sql) {
            return Err(unsupported(
                "a TEMP definition with a volatile function would not equal a stored result",
            )
            .detail("temp_error", "volatile_definition")
            .detail("relation", name.to_owned()));
        }
        // Validate before anything changes: the body must prepare against the
        // catalog as it is, and the catalog must accept its dependencies.
        let words = identifier_words(&query_sql, self.bridge.limits())?;
        let dependencies: Vec<String> = words
            .iter()
            .filter(|word| bodies.contains_key(*word))
            .cloned()
            .collect();
        let probe: Box<Query> = Box::new(query.clone());
        self.prepare_locked(&query_sql, probe, &bodies)?;
        let change = self.lifecycle.temp_catalog_create(
            &self.session,
            CreateTempDefinition {
                name: name.to_owned(),
                kind,
                definition_hash: definition_hash.clone(),
                dependencies,
                materialization: late_bound(&definition_hash),
            },
            if_not_exists,
        )?;
        if !matches!(change, TempCatalogChange::Unchanged { .. }) {
            bodies.insert(
                name.to_owned(),
                StoredBody {
                    definition_hash,
                    query_sql,
                    words,
                },
            );
        }
        Ok(change)
    }
}

fn late_bound(definition_hash: &str) -> TempMaterialization {
    TempMaterialization::Injected {
        handle: format!("late-bound:{definition_hash}"),
    }
}

fn report(
    kind: &'static str,
    change: TempCatalogChange,
    window: Option<SqlWindow>,
) -> DefinitionReport {
    DefinitionReport {
        kind,
        change,
        window: SqlWindowReport {
            offset: window.map_or(0, |window| window.offset()),
            rows: 0,
            truncated: false,
            next_offset: None,
            total_rows: Some(0),
        },
    }
}

/// Limits for text this module builds itself from already-admitted definitions.
fn unbounded(limits: SqlLimits) -> SqlLimits {
    SqlLimits {
        max_sql_bytes: limits.max_sql_bytes.saturating_mul(8),
        max_tokens: limits.max_tokens.saturating_mul(8),
        ..limits
    }
}
