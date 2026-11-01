use crate::{
    control::{SqlControl, SqlLimits},
    dialects::SqlDialect,
    invalid,
    provider::{SqlBinding, SqlFactProvider, SqlRelation},
    quota, sqlite_error,
    values::SqlValue,
    virtual_tables::{self, Source},
};
use mdd_query::ir::FactLayer;
use mdd_types::{ErrorCode, MddError, MddResult};
use rusqlite::{
    Connection,
    config::DbConfig,
    hooks::{AuthAction, AuthContext, Authorization},
    limits::Limit,
};
use serde::Serialize;
use std::{collections::BTreeSet, sync::Arc};

pub struct SqlBridge {
    provider: Arc<dyn SqlFactProvider>,
    dialect: SqlDialect,
    limits: SqlLimits,
}
pub struct PreparedSql {
    binding: SqlBinding,
    sql: String,
    adapted_sql: String,
    parameters: Vec<SqlValue>,
    ast_nodes: usize,
    required_relations: Vec<String>,
    cte_names: BTreeSet<String>,
    required_layers: Vec<FactLayer>,
    relations: Vec<SqlRelation>,
    provider: Arc<dyn SqlFactProvider>,
    dialect: SqlDialect,
    limits: SqlLimits,
    display_overrides: std::collections::BTreeMap<String, String>,
    execution_binding: Option<crate::runtime::SqlExecutionBinding>,
}
/// An immutable calculated result. The query's logical result-workspace
/// reservation stays live until this object is dropped. Transport copies and
/// SQLite's own internal allocations need separate admission.
/// ```compile_fail
/// fn remove_rows(mut result: mdd_sql::SqlResult) { result.rows.clear(); }
/// ```
#[derive(Debug, Serialize)]
pub struct SqlResult {
    binding: SqlBinding,
    dialect: SqlDialect,
    columns: Vec<String>,
    rows: Vec<Vec<SqlValue>>,
    calculation_complete: bool,
    profiles_admitted: Vec<String>,
    sqlite_version: String,
    optimizer: OptimizerPolicy,
    required_relations: Vec<String>,
    required_layers: Vec<FactLayer>,
    ast_nodes: usize,
    execution_binding: Option<crate::runtime::SqlExecutionBinding>,
    #[serde(skip)]
    _result_memory: ResultMemory,
}
impl SqlResult {
    pub fn binding(&self) -> &SqlBinding {
        &self.binding
    }
    pub fn columns(&self) -> &[String] {
        &self.columns
    }
    pub fn rows(&self) -> &[Vec<SqlValue>] {
        &self.rows
    }
    pub fn calculation_complete(&self) -> bool {
        self.calculation_complete
    }
    pub fn execution_binding(&self) -> Option<&crate::runtime::SqlExecutionBinding> {
        self.execution_binding.as_ref()
    }
}
#[derive(Default)]
struct ResultMemory {
    reservations: Vec<mdd_query::budget::Reservation>,
    unused: u64,
}
impl std::fmt::Debug for ResultMemory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResultMemory")
            .field("reservations", &self.reservations.len())
            .field("unused", &self.unused)
            .finish()
    }
}
impl ResultMemory {
    fn admit(&mut self, control: &SqlControl, bytes: u64) -> MddResult<()> {
        let Some(runtime) = control.runtime() else {
            return Ok(());
        };
        if bytes <= self.unused {
            self.unused -= bytes;
            return Ok(());
        }
        let needed = bytes - self.unused;
        let preferred = needed.max(4096);
        runtime.checkpoint()?;
        let pool = runtime.pool();
        let reserve = pool
            .reserve(mdd_query::budget::Resource::QueryWorkspaceBytes, preferred)
            .or_else(|error| {
                if error.code == ErrorCode::QuotaExceeded && preferred != needed {
                    pool.reserve(mdd_query::budget::Resource::QueryWorkspaceBytes, needed)
                } else {
                    Err(error)
                }
            })
            .map_err(|error| control.fail(error))?;
        self.unused = reserve.amount() - needed;
        self.reservations.push(reserve);
        Ok(())
    }
}
fn result_metadata_bytes(
    prepared: &PreparedSql,
    statement: &rusqlite::Statement<'_>,
) -> MddResult<u64> {
    let count = statement.column_count();
    let entries = count
        .checked_add(prepared.required_relations.len())
        .ok_or_else(|| quota("SQL_RESULT_METADATA_OVERFLOW"))?;
    let layer_bytes = prepared
        .required_layers
        .len()
        .checked_mul(std::mem::size_of::<FactLayer>())
        .and_then(|v| v.checked_mul(2))
        .ok_or_else(|| quota("SQL_RESULT_METADATA_OVERFLOW"))?;
    let mut bytes = (std::mem::size_of::<SqlResult>() as u64)
        .checked_add(
            (entries as u64)
                .checked_mul((std::mem::size_of::<String>() * 2) as u64)
                .ok_or_else(|| quota("SQL_RESULT_METADATA_OVERFLOW"))?,
        )
        .and_then(|v| v.checked_add(layer_bytes as u64))
        .ok_or_else(|| quota("SQL_RESULT_METADATA_OVERFLOW"))?;
    let mut add_text = |text: &str| -> MddResult<()> {
        let cost = (text.len() as u64)
            .checked_mul(2)
            .ok_or_else(|| quota("SQL_RESULT_METADATA_OVERFLOW"))?;
        bytes = bytes
            .checked_add(cost)
            .ok_or_else(|| quota("SQL_RESULT_METADATA_OVERFLOW"))?;
        Ok(())
    };
    add_text(&prepared.binding.provider_identity)?;
    add_text(&prepared.binding.snapshot_id)?;
    add_text(rusqlite::version())?;
    for name in &prepared.required_relations {
        add_text(name)?;
    }
    if let Some(binding) = &prepared.execution_binding {
        for value in [
            &binding.schema_version,
            &binding.worker_owner_id,
            &binding.session_id,
            &binding.query_id,
            &binding.snapshot_id,
            &binding.provider_identity,
            &binding.request_key,
            &binding.schema_id,
            &binding.semantic_version,
        ] {
            add_text(value)?;
        }
    }
    for ordinal in 0..count {
        let name = statement.column_name(ordinal).map_err(sqlite_error)?;
        add_text(
            prepared
                .display_overrides
                .get(name)
                .map_or(name, String::as_str),
        )?;
    }
    Ok(bytes)
}

/// Only bounds the temporary Rust schema/warmup buffers; SQLite's internal
/// schema allocations and allocator overhead are not part of this lease.
struct SchemaBounds {
    ddl: u64,
    warmup: u64,
    workspace: u64,
}
fn quoted_identifier_bytes(value: &str, control: &SqlControl, cap: u64) -> MddResult<u64> {
    let bytes = u64::try_from(value.len()).map_err(|_| quota("VTAB_SCHEMA_SIZE_OVERFLOW"))?;
    if value.is_empty() {
        return Err(invalid("INVALID_SQL_IDENTIFIER"));
    }
    if bytes > cap {
        return Err(quota("VTAB_SCHEMA_BYTE_BUDGET"));
    }
    let mut quoted = bytes
        .checked_add(2)
        .ok_or_else(|| quota("VTAB_SCHEMA_SIZE_OVERFLOW"))?;
    for chunk in value.as_bytes().chunks(4096) {
        control.checkpoint(chunk.len() as u64, false)?;
        if chunk.contains(&0) {
            return Err(invalid("INVALID_SQL_IDENTIFIER"));
        }
        let extra = chunk.iter().filter(|byte| **byte == b'"').count() as u64;
        quoted = quoted
            .checked_add(extra)
            .ok_or_else(|| quota("VTAB_SCHEMA_SIZE_OVERFLOW"))?;
        if quoted > cap {
            return Err(quota("VTAB_SCHEMA_BYTE_BUDGET"));
        }
    }
    Ok(quoted)
}
fn schema_bounds(
    relation: &SqlRelation,
    control: &SqlControl,
    cap: u64,
) -> MddResult<SchemaBounds> {
    let name = quoted_identifier_bytes(&relation.name, control, cap)?;
    let warmup = ("SELECT * FROM ".len() as u64)
        .checked_add(name)
        .and_then(|n| n.checked_add(" LIMIT 0".len() as u64))
        .ok_or_else(|| quota("VTAB_SCHEMA_SIZE_OVERFLOW"))?;
    let mut ddl = ("CREATE TABLE x(".len() + 1) as u64;
    for (index, column) in relation.columns.iter().enumerate() {
        control.checkpoint(1, false)?;
        let quoted = quoted_identifier_bytes(&column.name, control, cap)?;
        let kind = match column.data_type {
            crate::values::SqlType::Bool | crate::values::SqlType::I64 => 7,
            _ => 4,
        };
        ddl = ddl
            .checked_add(quoted)
            .and_then(|n| n.checked_add(1 + kind + u64::from(index != 0)))
            .ok_or_else(|| quota("VTAB_SCHEMA_SIZE_OVERFLOW"))?;
        if ddl > cap {
            return Err(quota("VTAB_SCHEMA_BYTE_BUDGET"));
        }
    }
    let slots = u64::try_from(relation.columns.len())
        .ok()
        .and_then(|n| n.checked_mul(std::mem::size_of::<String>() as u64))
        .ok_or_else(|| quota("VTAB_SCHEMA_SIZE_OVERFLOW"))?;
    // xConnect temporarily owns per-column strings, joined/schema strings and
    // the warmup statement. This is a conservative logical Rust-buffer bound.
    let workspace = ddl
        .checked_mul(3)
        .and_then(|n| n.checked_add(slots))
        .and_then(|n| n.checked_add(warmup))
        .and_then(|n| n.checked_add(128))
        .ok_or_else(|| quota("VTAB_SCHEMA_SIZE_OVERFLOW"))?;
    Ok(SchemaBounds {
        ddl,
        warmup,
        workspace,
    })
}

struct RestoreSqliteLength<'a> {
    db: &'a Connection,
    original: i32,
    restored: bool,
}
impl RestoreSqliteLength<'_> {
    fn restore(&mut self) -> MddResult<()> {
        self.db
            .set_limit(Limit::SQLITE_LIMIT_LENGTH, self.original)
            .map_err(sqlite_error)?;
        if self
            .db
            .limit(Limit::SQLITE_LIMIT_LENGTH)
            .map_err(sqlite_error)?
            != self.original
        {
            return Err(MddError::new(
                ErrorCode::InternalFault,
                "sql.schema",
                "SQLite length limit restoration mismatch",
            ));
        }
        self.restored = true;
        Ok(())
    }
}
impl Drop for RestoreSqliteLength<'_> {
    fn drop(&mut self) {
        if !self.restored {
            // Emergency unwind safeguard; ordinary return paths report restoration errors.
            let _ = self.db.set_limit(Limit::SQLITE_LIMIT_LENGTH, self.original);
        }
    }
}

// Preserve the original lifecycle failure while reporting any failure to
// restore SQLite's value limit on the returned error. The recorded first error
// remains unchanged, and an existing restoration detail is never overwritten.
fn fail_preserving_restore_detail(control: &SqlControl, error: MddError) -> MddError {
    let restore = error.details.get("sqlite_length_restore_error").cloned();
    let first = control.fail(error);
    match restore {
        Some(detail) if !first.details.contains_key("sqlite_length_restore_error") => {
            first.detail("sqlite_length_restore_error", detail)
        }
        _ => first,
    }
}

fn find_required_relation<'a>(
    prepared: &'a PreparedSql,
    required: &str,
    control: &SqlControl,
) -> MddResult<&'a SqlRelation> {
    for relation in &prepared.relations {
        control.checkpoint(1, false)?;
        if relation.name.len() == required.len() {
            let bytes =
                u64::try_from(required.len()).map_err(|_| quota("VTAB_SCHEMA_SIZE_OVERFLOW"))?;
            control.checkpoint(bytes, false)?;
            if relation.name.eq_ignore_ascii_case(required) {
                return Ok(relation);
            }
        }
    }
    Err(invalid("REQUIRED_RELATION_MISSING"))
}

fn preconnect_required_schemas(
    db: &Connection,
    prepared: &PreparedSql,
    control: &SqlControl,
) -> MddResult<()> {
    let original = db.limit(Limit::SQLITE_LIMIT_LENGTH).map_err(sqlite_error)?;
    let sql_limit = u64::try_from(
        db.limit(Limit::SQLITE_LIMIT_SQL_LENGTH)
            .map_err(sqlite_error)?,
    )
    .map_err(|_| invalid("INVALID_SQLITE_SQL_LIMIT"))?;
    let cap = control.inner.limits.max_vtab_schema_bytes.min(sql_limit);
    // The isolated preconnect is useful only when a higher bounded limit can
    // be used. Do not assume DDL byte length predicts SQLite parser workspace.
    if cap <= original as u64 {
        return Ok(());
    }
    let mut total = 0u64;
    let mut work = 0u64;
    let mut max_workspace = 0u64;
    for required in &prepared.required_relations {
        control.checkpoint(1, false)?;
        let relation = find_required_relation(prepared, required, control)?;
        let bounds = schema_bounds(relation, control, cap)?;
        total = total
            .checked_add(bounds.ddl)
            .and_then(|n| n.checked_add(bounds.warmup))
            .ok_or_else(|| quota("VTAB_SCHEMA_SIZE_OVERFLOW"))?;
        if total > cap || bounds.warmup > sql_limit {
            return Err(quota("VTAB_SCHEMA_BYTE_BUDGET"));
        }
        work = work
            .checked_add(bounds.workspace)
            .ok_or_else(|| quota("VTAB_SCHEMA_SIZE_OVERFLOW"))?;
        max_workspace = max_workspace.max(bounds.workspace);
    }
    if max_workspace == 0 {
        return Ok(());
    }
    control.work(work)?;
    let _workspace = control
        .runtime()
        .map(|runtime| {
            runtime
                .pool()
                .reserve(
                    mdd_query::budget::Resource::QueryWorkspaceBytes,
                    max_workspace,
                )
                .map_err(|error| control.fail(error))
        })
        .transpose()?;
    let mut restore = RestoreSqliteLength {
        db,
        original,
        restored: false,
    };
    let result = (|| {
        let raised = i32::try_from(cap).map_err(|_| quota("VTAB_SCHEMA_SIZE_OVERFLOW"))?;
        db.set_limit(Limit::SQLITE_LIMIT_LENGTH, raised)
            .map_err(sqlite_error)?;
        if db.limit(Limit::SQLITE_LIMIT_LENGTH).map_err(sqlite_error)? < raised {
            return Err(quota("VTAB_SCHEMA_SQLITE_LIMIT"));
        }
        for required in &prepared.required_relations {
            control.checkpoint(1, false)?;
            let relation = find_required_relation(prepared, required, control)?;
            let bounds = schema_bounds(relation, control, cap)?;
            let capacity =
                usize::try_from(bounds.warmup).map_err(|_| quota("VTAB_SCHEMA_SIZE_OVERFLOW"))?;
            let mut sql = String::new();
            sql.try_reserve_exact(capacity)
                .map_err(|_| quota("VTAB_SCHEMA_ALLOCATION"))?;
            sql.push_str("SELECT * FROM \"");
            for ch in relation.name.chars() {
                control.checkpoint(1, false)?;
                if ch == '"' {
                    sql.push('"');
                }
                sql.push(ch);
            }
            sql.push_str("\" LIMIT 0");
            if sql.len() != capacity {
                return Err(invalid("VTAB_SCHEMA_LENGTH_CHANGED"));
            }
            let statement = db
                .prepare(&sql)
                .map_err(|error| control.error().unwrap_or_else(|| sqlite_error(error)))?;
            if !statement.readonly() {
                return Err(invalid("VTAB_SCHEMA_NOT_READONLY"));
            }
            // Deliberately do not step: no xOpen, cursor, or provider fact scan.
            drop(statement);
        }
        Ok(())
    })();
    // Resolve the original control error before adding restoration details;
    // otherwise a later control lookup could discard those details.
    let result = result.map_err(|error| control.error().unwrap_or(error));
    let restored = restore.restore();
    match (result, restored) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(restore_error)) => {
            if error.details.contains_key("sqlite_length_restore_error") {
                Err(error)
            } else {
                Err(error.detail("sqlite_length_restore_error", restore_error.to_string()))
            }
        }
    }
}
#[derive(Debug, Serialize)]
pub struct OptimizerPolicy {
    pub omit: bool,
    pub order_by_consumed: bool,
    pub limit_offset_pushdown: bool,
    pub in_pushdown: bool,
}
impl PreparedSql {
    pub fn binding(&self) -> &SqlBinding {
        &self.binding
    }
    pub fn sql(&self) -> &str {
        &self.sql
    }
    pub fn required_relations(&self) -> &[String] {
        &self.required_relations
    }
    pub fn required_layers(&self) -> &[FactLayer] {
        &self.required_layers
    }
    pub fn runtime_query_binding(&self) -> MddResult<mdd_session::QueryBinding> {
        let request=serde_json::to_vec(&serde_json::json!({"binding":self.binding,"sql":self.sql,"parameters":self.parameters,"dialect":self.dialect})).map_err(|_|invalid("SQL_REQUEST_BINDING_ENCODING"))?;
        let schema=serde_json::to_vec(&serde_json::json!({"codec":"mdd.sql.dynamic-values.v1","relations":self.relations,"projection_plan":self.adapted_sql,"display_names":self.display_overrides})).map_err(|_|invalid("SQL_SCHEMA_BINDING_ENCODING"))?;
        Ok(mdd_session::QueryBinding {
            request_key: mdd_types::sha256(&request),
            schema_id: format!("mdd.sql.dynamic-rows.v1:{}", mdd_types::sha256(&schema)),
            semantic_version: format!("mdd.sql.ast.v2;mdd.sql.values.v1;{:?}", self.dialect),
        })
    }
    pub fn bind_runtime(mut self, runtime: &mdd_query::budget::RuntimeBudget) -> MddResult<Self> {
        if self.execution_binding.is_some() {
            return Err(invalid("SQL_PREPARED_ALREADY_RUNTIME_BOUND"));
        }
        self.execution_binding = Some(crate::runtime::SqlExecutionBinding::capture(
            runtime,
            &self.binding,
            &self.runtime_query_binding()?,
        )?);
        Ok(self)
    }
    /// Execute the pinned generation. Higher session/worker APIs must validate
    /// their owner/query lease before invoking this low-level method.
    pub fn execute(&self, control: SqlControl) -> MddResult<SqlResult> {
        SqlBridge::new(Arc::clone(&self.provider), self.dialect, self.limits)?
            .execute(self, control)
    }
}
impl SqlBridge {
    pub fn binding(&self) -> &SqlBinding {
        self.provider.binding()
    }
    pub fn new(
        provider: Arc<dyn SqlFactProvider>,
        dialect: SqlDialect,
        limits: SqlLimits,
    ) -> MddResult<Self> {
        let binding = provider.binding();
        if binding.provider_identity.is_empty() || binding.snapshot_id.is_empty() {
            return Err(invalid("EMPTY_SQL_BINDING"));
        }
        Ok(Self {
            provider,
            dialect,
            limits,
        })
    }
    pub fn prepare(&self, sql: &str) -> MddResult<PreparedSql> {
        self.prepare_with_parameters(sql, &[])
    }
    pub fn prepare_with_parameters(
        &self,
        sql: &str,
        parameters: &[SqlValue],
    ) -> MddResult<PreparedSql> {
        let relations = self.provider.relations()?;
        let mut names = BTreeSet::new();
        for relation in &relations {
            if relation.name.is_empty()
                || relation.name.contains('\0')
                || !names.insert(relation.name.to_ascii_lowercase())
                || relation.columns.is_empty()
            {
                return Err(invalid("PROVIDER_RELATION_SCHEMA"));
            }
            let mut columns = BTreeSet::new();
            for column in &relation.columns {
                if column.name.is_empty()
                    || column.name.contains('\0')
                    || !columns.insert(column.name.to_ascii_lowercase())
                {
                    return Err(invalid("PROVIDER_COLUMN_SCHEMA"));
                }
            }
        }
        let adapted = match crate::dialects::ast::adapt(
            sql,
            self.limits,
            parameters,
            &relations,
            self.dialect,
        ) {
            Ok(adapted) => adapted,
            Err(error)
                if error.details.get("confirm_sqlite_syntax")
                    == Some(&serde_json::Value::Bool(true)) =>
            {
                let visible_ctes = error
                    .details
                    .get("visible_ctes")
                    .and_then(|value| value.as_array())
                    .map(|names| {
                        names
                            .iter()
                            .filter_map(|name| name.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default();
                if let Some(cause) = self.original_binding_error(sql, &relations, &visible_ctes)? {
                    return Err(cause.detail("ast_error", error.message));
                }
                return Err(MddError::new(ErrorCode::UnsupportedQuery,"sql.ast","SQLite accepts this read-only syntax but the AST adapter does not yet implement it").detail("ast_error",error.message));
            }
            Err(error) => return Err(error),
        };
        for required in &adapted.required_relations {
            if !relations
                .iter()
                .any(|r| r.name.eq_ignore_ascii_case(required))
            {
                return Err(invalid("UNKNOWN_RELATION").detail("relation", required.clone()));
            }
        }
        let required_layers = relations
            .iter()
            .filter(|r| {
                adapted
                    .required_relations
                    .iter()
                    .any(|name| r.name.eq_ignore_ascii_case(name))
            })
            .flat_map(|r| r.required_layers.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(PreparedSql {
            binding: self.provider.binding().clone(),
            sql: sql.to_owned(),
            adapted_sql: adapted.sql,
            parameters: adapted.parameters,
            ast_nodes: adapted.nodes,
            required_relations: adapted.required_relations,
            cte_names: adapted.cte_names,
            required_layers,
            relations,
            provider: Arc::clone(&self.provider),
            dialect: self.dialect,
            limits: self.limits,
            display_overrides: adapted.display_overrides,
            execution_binding: None,
        })
    }
    pub fn execute(&self, prepared: &PreparedSql, control: SqlControl) -> MddResult<SqlResult> {
        if self.provider.binding() != &prepared.binding
            || self.provider.binding() != prepared.provider.binding()
            || self.dialect != prepared.dialect
        {
            return Err(invalid("SQL_PREPARED_GENERATION_OR_DIALECT_CHANGED"));
        }
        let control = control.restrict(self.limits.restricted_by(prepared.limits));
        match (&prepared.execution_binding, control.runtime()) {
            (None, None) => (),
            (Some(expected), Some(runtime)) => {
                let actual = crate::runtime::SqlExecutionBinding::capture(
                    runtime,
                    &prepared.binding,
                    &prepared.runtime_query_binding()?,
                )?;
                if &actual != expected {
                    return Err(invalid("SQL_RUNTIME_OWNER_MISMATCH"));
                }
            }
            _ => {
                return Err(invalid(
                    "SQL_RUNTIME_BINDING_REQUIRED_ON_BOTH_PREPARED_AND_CONTROL",
                ));
            }
        }
        control.claim()?;
        if let Some(runtime) = control.runtime() {
            runtime.cancellation().claim_execution()?;
        }
        let result = self
            .execute_inner(prepared, control.clone())
            .map_err(|error| fail_preserving_restore_detail(&control, error))?;
        if let Some(runtime) = control.runtime() {
            runtime.cancellation().mark_computed()?;
            if let Some(error) = runtime.cancellation().status()?.error {
                return Err(error
                    .detail("execution_complete", true)
                    .detail("total_rows", result.rows.len().to_string()));
            }
        }
        Ok(result)
    }
    fn execute_inner(&self, prepared: &PreparedSql, control: SqlControl) -> MddResult<SqlResult> {
        control.checkpoint(1, false)?;
        // Scope admission is independent of SQLite short-circuit execution.
        // LIMIT 0 / WHERE false must not turn an unbuilt required layer into
        // an empty successful answer; unused registered relations stay unbuilt.
        for name in &prepared.required_relations {
            prepared.provider.require_relation(name)?;
        }
        let db = Connection::open_in_memory().map_err(sqlite_error)?;
        // SAFETY: the connection is exclusively owned here, has no statements
        // or callbacks in flight, and remains alive throughout this C call.
        // rusqlite's wrapper is feature-gated; enabling extensions is not needed.
        let extension_rc = unsafe { rusqlite::ffi::sqlite3_enable_load_extension(db.handle(), 0) };
        if extension_rc != rusqlite::ffi::SQLITE_OK {
            return Err(sqlite_error(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(extension_rc),
                None,
            )));
        }
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(sqlite_error)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)
            .map_err(sqlite_error)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)
            .map_err(sqlite_error)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)
            .map_err(sqlite_error)?;
        db.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)
            .map_err(sqlite_error)?;
        db.set_limit(Limit::SQLITE_LIMIT_WORKER_THREADS, 0)
            .map_err(sqlite_error)?;
        db.set_limit(
            Limit::SQLITE_LIMIT_SQL_LENGTH,
            i32::try_from(self.limits.max_sql_bytes.saturating_mul(8)).unwrap_or(i32::MAX),
        )
        .map_err(sqlite_error)?;
        db.set_limit(
            Limit::SQLITE_LIMIT_LENGTH,
            i32::try_from(control.inner.limits.max_cell_bytes.saturating_add(64))
                .unwrap_or(i32::MAX),
        )
        .map_err(sqlite_error)?;
        db.set_limit(
            Limit::SQLITE_LIMIT_EXPR_DEPTH,
            i32::try_from(self.limits.max_ast_depth).unwrap_or(i32::MAX),
        )
        .map_err(sqlite_error)?;
        for relation in &prepared.relations {
            virtual_tables::register(
                &db,
                Arc::new(Source {
                    provider: Arc::clone(&prepared.provider),
                    relation: relation.clone(),
                    binding: prepared.binding.clone(),
                    control: control.clone(),
                }),
            )
            .map_err(sqlite_error)?;
        }
        crate::dialects::functions::register(&db, prepared.dialect, control.clone())
            .map_err(sqlite_error)?;
        let names = prepared
            .relations
            .iter()
            .map(|r| r.name.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        let ctes = prepared.cte_names.clone();
        db.authorizer(Some(move |context: AuthContext<'_>| match context.action {
            AuthAction::Select | AuthAction::Recursive => Authorization::Allow,
            AuthAction::Read { table_name, .. }
                if names.contains(&table_name.to_ascii_lowercase()) =>
            {
                Authorization::Allow
            }
            AuthAction::Read {
                table_name,
                column_name,
            } if context.database_name.is_none()
                && column_name.is_empty()
                && ctes.contains(&table_name.to_ascii_lowercase()) =>
            {
                // SQLite has bound this to an in-memory CTE container. Actual
                // database reads still require an admitted provider relation.
                Authorization::Allow
            }
            AuthAction::Function { function_name }
                if [
                    "count",
                    "coalesce",
                    "ifnull",
                    "mdd_nullif",
                    "mdd_sum",
                    "mdd_min",
                    "mdd_max",
                    "mdd_min_scalar",
                    "mdd_max_scalar",
                    "mdd_length",
                    "mdd_substr",
                    "mdd_hex",
                    "mdd_lower",
                    "mdd_upper",
                    "mdd_eq",
                    "mdd_ne",
                    "mdd_gt",
                    "mdd_ge",
                    "mdd_lt",
                    "mdd_le",
                    "mdd_literal_eq",
                    "mdd_literal_ne",
                    "mdd_literal_gt",
                    "mdd_literal_ge",
                    "mdd_literal_lt",
                    "mdd_literal_le",
                    "mdd_text_integer_eq",
                    "mdd_text_integer_ne",
                    "mdd_text_integer_gt",
                    "mdd_text_integer_ge",
                    "mdd_text_integer_lt",
                    "mdd_text_integer_le",
                    "mdd_concat",
                    "mdd_cast",
                    "mdd_add",
                    "mdd_sub",
                    "mdd_mul",
                    "mdd_div",
                    "mdd_mod",
                    "mdd_neg",
                    "mdd_pos",
                    "mdd_key",
                    "mdd_sort_key",
                    "mdd_like",
                    "mdd_truth_input",
                ]
                .iter()
                .any(|f| f.eq_ignore_ascii_case(function_name)) =>
            {
                Authorization::Allow
            }
            _ => Authorization::Deny,
        }))
        .map_err(sqlite_error)?;
        let progress = control.clone();
        db.progress_handler(1, Some(move || progress.checkpoint(1, false).is_err()))
            .map_err(sqlite_error)?;
        // A tiny data-cell limit must not prevent SQLite from declaring an
        // already-admitted relation's schema. Only generated metadata-only
        // statements run here; the original length limit is restored before
        // preparing any user statement.
        preconnect_required_schemas(&db, prepared, &control)?;
        let result = (|| {
            let mut statement = db.prepare(&prepared.adapted_sql).map_err(sqlite_error)?;
            if !statement.readonly() {
                return Err(invalid("SQLITE_STATEMENT_NOT_READONLY"));
            }
            let mut result_memory = ResultMemory::default();
            result_memory.admit(&control, result_metadata_bytes(prepared, &statement)?)?;
            let count = statement.column_count();
            let mut columns = Vec::new();
            columns
                .try_reserve_exact(count)
                .map_err(|_| quota("SQL_RESULT_ALLOCATION"))?;
            for ordinal in 0..count {
                let name = statement.column_name(ordinal).map_err(sqlite_error)?;
                columns.push(
                    prepared
                        .display_overrides
                        .get(name)
                        .map_or_else(|| name.to_owned(), Clone::clone),
                );
            }
            let parameters = prepared
                .parameters
                .iter()
                .map(|v| v.sqlite(control.inner.limits.max_cell_bytes))
                .collect::<MddResult<Vec<_>>>()?;
            let mut cursor = statement
                .query(rusqlite::params_from_iter(parameters))
                .map_err(sqlite_error)?;
            let mut rows = Vec::new();
            while let Some(row) = cursor.next().map_err(sqlite_error)? {
                control.checkpoint(1, false)?;
                // Admit a conservative logical bound before any owned output
                // allocation. SQLite's internal buffers are explicitly outside
                // this result-only reservation.
                let mut reserved_bytes = (count as u64)
                    .checked_mul(std::mem::size_of::<SqlValue>() as u64)
                    .and_then(|v| v.checked_mul(2))
                    .and_then(|v| v.checked_add((std::mem::size_of::<Vec<SqlValue>>() * 2) as u64))
                    .ok_or_else(|| quota("SQL_RESULT_WORKSPACE_OVERFLOW"))?;
                for ordinal in 0..count {
                    let value = row.get_ref(ordinal).map_err(sqlite_error)?;
                    let extra = match value {
                        rusqlite::types::ValueRef::Text(v) => (v.len() as u64).checked_mul(2),
                        rusqlite::types::ValueRef::Blob(v) => Some(v.len() as u64),
                        _ => Some(0),
                    }
                    .ok_or_else(|| quota("SQL_RESULT_WORKSPACE_OVERFLOW"))?;
                    reserved_bytes = reserved_bytes
                        .checked_add(extra)
                        .ok_or_else(|| quota("SQL_RESULT_WORKSPACE_OVERFLOW"))?;
                }
                result_memory.admit(&control, reserved_bytes)?;
                rows.try_reserve(1)
                    .map_err(|_| quota("SQL_RESULT_ALLOCATION"))?;
                let mut values = Vec::new();
                values
                    .try_reserve_exact(count)
                    .map_err(|_| quota("SQL_RESULT_ALLOCATION"))?;
                let mut bytes = 0u64;
                for ordinal in 0..count {
                    let value_ref = row.get_ref(ordinal).map_err(sqlite_error)?;
                    // Text UTF-8 may expand to two bytes per code unit. Charge
                    // conservatively before allocating an owned result value.
                    let work = match value_ref {
                        rusqlite::types::ValueRef::Text(v) => (v.len() as u64).checked_mul(2),
                        rusqlite::types::ValueRef::Blob(v) => Some(v.len() as u64),
                        _ => Some(16),
                    }
                    .ok_or_else(|| quota("SQL_RESULT_WORK_OVERFLOW"))?;
                    control.work(work)?;
                    let value = SqlValue::from_sqlite(value_ref)?;
                    let size = value.byte_size();
                    if size > control.inner.limits.max_cell_bytes {
                        return Err(quota("SQL_RESULT_CELL_BYTES"));
                    }
                    bytes = bytes
                        .checked_add(size)
                        .ok_or_else(|| quota("SQL_RESULT_BYTES_OVERFLOW"))?;
                    values.push(value);
                }
                control.output(bytes)?;
                rows.push(values);
            }
            if prepared.provider.binding() != &prepared.binding {
                return Err(invalid("SQL_GENERATION_CHANGED_BEFORE_END"));
            }
            control.checkpoint(1, false)?;
            Ok(SqlResult {
                binding: prepared.binding.clone(),
                dialect: prepared.dialect,
                columns,
                rows,
                calculation_complete: true,
                profiles_admitted: Vec::new(),
                sqlite_version: rusqlite::version().to_owned(),
                optimizer: OptimizerPolicy {
                    omit: false,
                    order_by_consumed: false,
                    limit_offset_pushdown: false,
                    in_pushdown: false,
                },
                required_relations: prepared.required_relations.clone(),
                required_layers: prepared.required_layers.clone(),
                ast_nodes: prepared.ast_nodes,
                execution_binding: prepared.execution_binding.clone(),
                _result_memory: result_memory,
            })
        })();
        result.map_err(|error| control.error().unwrap_or(error))
    }
    pub fn query(&self, sql: &str) -> MddResult<SqlResult> {
        let prepared = self.prepare(sql)?;
        self.execute(&prepared, SqlControl::new(self.limits, None))
    }
    /// Only prepare, never step a statement or open facts. This separates a
    /// real syntax/binding error from a gap in the additional AST frontend.
    fn original_binding_error(
        &self,
        sql: &str,
        relations: &[SqlRelation],
        visible_ctes: &BTreeSet<String>,
    ) -> MddResult<Option<MddError>> {
        let db = Connection::open_in_memory().map_err(sqlite_error)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
            .map_err(sqlite_error)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)
            .map_err(sqlite_error)?;
        db.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)
            .map_err(sqlite_error)?;
        let control = SqlControl::new(self.limits, None);
        for relation in relations {
            virtual_tables::register(
                &db,
                Arc::new(Source {
                    provider: Arc::clone(&self.provider),
                    relation: relation.clone(),
                    binding: self.provider.binding().clone(),
                    control: control.clone(),
                }),
            )
            .map_err(sqlite_error)?;
        }
        let names = relations
            .iter()
            .map(|r| r.name.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        let ctes = visible_ctes.clone();
        db.authorizer(Some(move |context: AuthContext<'_>| match context.action {
            AuthAction::Select | AuthAction::Recursive => Authorization::Allow,
            AuthAction::Read { table_name, .. }
                if names.contains(&table_name.to_ascii_lowercase()) =>
            {
                Authorization::Allow
            }
            AuthAction::Read {
                table_name,
                column_name,
            } if context.database_name.is_none()
                && column_name.is_empty()
                && ctes.contains(&table_name.to_ascii_lowercase()) =>
            {
                // SQLite emits this read for a visible in-memory CTE container,
                // not for a main, temp or attached database table.
                Authorization::Allow
            }
            AuthAction::Function { function_name }
                if !["load_extension", "readfile", "writefile"]
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(function_name)) =>
            {
                Authorization::Allow
            }
            _ => Authorization::Deny,
        }))
        .map_err(sqlite_error)?;
        match db.prepare(sql) {
            Ok(statement) => {
                if statement.readonly() {
                    Ok(None)
                } else {
                    Ok(Some(invalid("STATEMENT_NOT_READ_ONLY")))
                }
            }
            Err(error) => {
                let error = control.error().unwrap_or_else(|| sqlite_error(error));
                if matches!(
                    error.code,
                    ErrorCode::QuotaExceeded
                        | ErrorCode::UnavailableBackend
                        | ErrorCode::InternalFault
                ) {
                    Err(error)
                } else {
                    Ok(Some(error))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        provider::{SqlColumn, SqlFactCursor, SqlRow},
        values::{SqlType, SqlValue},
    };
    use mdd_types::{DecimalU64, ErrorCode};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Provider {
        binding: SqlBinding,
        opens: AtomicUsize,
    }
    struct Cursor {
        provider: Arc<Provider>,
        position: u32,
    }
    impl SqlFactCursor for Cursor {
        fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
            let _lease = &self.provider;
            self.position += 1;
            Ok((self.position <= 3).then(|| {
                vec![
                    SqlValue::U64(DecimalU64(u64::from(self.position))),
                    SqlValue::text("a\0b"),
                ]
            }))
        }
    }
    impl SqlFactProvider for Provider {
        fn binding(&self) -> &SqlBinding {
            &self.binding
        }
        fn relations(&self) -> MddResult<Vec<SqlRelation>> {
            Ok(vec![SqlRelation {
                name: "facts".into(),
                columns: vec![
                    SqlColumn {
                        id: "id".into(),
                        name: "id".into(),
                        data_type: SqlType::U64,
                        nullable: false,
                    },
                    SqlColumn {
                        id: "value".into(),
                        name: "value".into(),
                        data_type: SqlType::Text,
                        nullable: false,
                    },
                ],
                required_layers: vec![],
                estimated_rows: Some(DecimalU64(3)),
            }])
        }
        fn require_relation(&self, _: &str) -> MddResult<()> {
            Ok(())
        }
        fn open_cursor(
            self: Arc<Self>,
            _: &str,
            _: SqlControl,
        ) -> MddResult<Box<dyn SqlFactCursor>> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Cursor {
                provider: self,
                position: 0,
            }))
        }
    }
    fn bridge() -> (Arc<Provider>, SqlBridge) {
        let provider = Arc::new(Provider {
            binding: SqlBinding {
                provider_identity: "tiny".into(),
                snapshot_id: "tiny-snapshot".into(),
                catalog_epoch: DecimalU64(0),
            },
            opens: AtomicUsize::new(0),
        });
        let bridge =
            SqlBridge::new(provider.clone(), SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        (provider, bridge)
    }
    fn schema_test_connection(prepared: &PreparedSql, control: &SqlControl) -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0).unwrap();
        db.set_limit(Limit::SQLITE_LIMIT_LENGTH, 65).unwrap();
        for relation in &prepared.relations {
            virtual_tables::register(
                &db,
                Arc::new(Source {
                    provider: Arc::clone(&prepared.provider),
                    relation: relation.clone(),
                    binding: prepared.binding.clone(),
                    control: control.clone(),
                }),
            )
            .unwrap();
        }
        db.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Select => Authorization::Allow,
            AuthAction::Read { table_name, .. }
                if table_name.eq_ignore_ascii_case("facts")
                    || table_name.eq_ignore_ascii_case("vals") =>
            {
                Authorization::Allow
            }
            _ => Authorization::Deny,
        }))
        .unwrap();
        db
    }

    #[test]
    fn schema_prewarm_preserves_limits_and_never_opens_facts() {
        use crate::virtual_tables::{TEST_CONNECTS, TEST_OPENS};
        let (provider, bridge) = bridge();
        let mut prepared = bridge.prepare("SELECT id FROM facts").unwrap();
        let mut unused = prepared.relations[0].clone();
        unused.name = "unused".into();
        prepared.relations.push(unused);
        let control = SqlControl::new(SqlLimits::default(), None);
        let db = schema_test_connection(&prepared, &control);
        TEST_CONNECTS.with(|count| count.set(0));
        TEST_OPENS.with(|count| count.set(0));
        preconnect_required_schemas(&db, &prepared, &control).unwrap();
        assert_eq!(db.limit(Limit::SQLITE_LIMIT_LENGTH).unwrap(), 65);
        assert_eq!(TEST_CONNECTS.with(|count| count.get()), 1);
        assert_eq!(TEST_OPENS.with(|count| count.get()), 0);
        assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
        assert!(db.prepare("SELECT name FROM sqlite_master").is_err());
        assert!(
            db.execute("ATTACH DATABASE ':memory:' AS extra", [])
                .is_err()
        );
        assert!(db.execute("DELETE FROM facts", []).is_err());
    }

    #[test]
    fn schema_prewarm_failure_restores_original_length_without_opening_facts() {
        use crate::virtual_tables::{TEST_CONNECTS, TEST_OPENS};
        let provider = Arc::new(RowsProvider {
            binding: SqlBinding {
                provider_identity: "wide".into(),
                snapshot_id: "wide-snapshot".into(),
                catalog_epoch: DecimalU64(0),
            },
            rows: vec![],
            columns: (0..2001)
                .map(|i| SqlColumn {
                    id: format!("c{i}"),
                    name: format!("c{i}"),
                    data_type: SqlType::I64,
                    nullable: false,
                })
                .collect(),
        });
        let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        let prepared = bridge.prepare("SELECT c0 FROM vals").unwrap();
        let control = SqlControl::new(SqlLimits::default(), None);
        let db = schema_test_connection(&prepared, &control);
        TEST_CONNECTS.with(|count| count.set(0));
        TEST_OPENS.with(|count| count.set(0));
        let error = preconnect_required_schemas(&db, &prepared, &control).unwrap_err();
        assert!(
            error.message.contains("constructor") || error.message.contains("columns"),
            "{error:?}"
        );
        assert_eq!(TEST_CONNECTS.with(|count| count.get()), 1);
        assert_eq!(TEST_OPENS.with(|count| count.get()), 0);
        assert_eq!(db.limit(Limit::SQLITE_LIMIT_LENGTH).unwrap(), 65);
        assert!(db.prepare("SELECT name FROM sqlite_master").is_err());
        assert!(
            db.execute("ATTACH DATABASE ':memory:' AS extra", [])
                .is_err()
        );
    }

    #[test]
    fn schema_prewarm_cap_and_cancellation_leave_original_length() {
        use crate::virtual_tables::{TEST_CONNECTS, TEST_OPENS};
        let (_, bridge) = bridge();
        let prepared = bridge.prepare("SELECT id FROM facts").unwrap();
        for (limits, cancelled, expected) in [
            (
                SqlLimits {
                    max_vtab_schema_bytes: 66,
                    ..SqlLimits::default()
                },
                false,
                ErrorCode::QuotaExceeded,
            ),
            (SqlLimits::default(), true, ErrorCode::Cancelled),
        ] {
            let control = SqlControl::new(limits, None);
            let db = schema_test_connection(&prepared, &control);
            if cancelled {
                control.cancel().unwrap();
            }
            TEST_CONNECTS.with(|count| count.set(0));
            TEST_OPENS.with(|count| count.set(0));
            assert_eq!(
                preconnect_required_schemas(&db, &prepared, &control)
                    .unwrap_err()
                    .code,
                expected
            );
            assert_eq!(db.limit(Limit::SQLITE_LIMIT_LENGTH).unwrap(), 65);
            assert_eq!(TEST_CONNECTS.with(|count| count.get()), 0);
            assert_eq!(TEST_OPENS.with(|count| count.get()), 0);
        }
    }

    #[test]
    fn reported_restore_failure_preserves_first_error_and_existing_details() {
        let control = SqlControl::new(SqlLimits::default(), None);
        let first =
            MddError::new(ErrorCode::Cancelled, "first", "cancelled").detail("origin", "kept");
        control.fail(first.clone());
        // Inject only the secondary reporting error; this does not simulate a SQLite restoration.
        let returned = fail_preserving_restore_detail(
            &control,
            MddError::new(ErrorCode::InternalFault, "later", "later error")
                .detail("sqlite_length_restore_error", "restore failed"),
        );
        assert_eq!(returned.code, first.code);
        assert_eq!(returned.stage, first.stage);
        assert_eq!(returned.message, first.message);
        assert_eq!(returned.details.get("origin"), first.details.get("origin"));
        assert_eq!(
            returned.details["sqlite_length_restore_error"],
            "restore failed"
        );
        assert!(
            !control
                .error()
                .unwrap()
                .details
                .contains_key("sqlite_length_restore_error")
        );
    }

    #[test]
    fn not_between_keeps_both_comparisons_inside_not() {
        let (provider, _) = bridge();
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            let prepared = bridge
                .prepare("SELECT id FROM facts WHERE id NOT BETWEEN 1 AND 2 ORDER BY id")
                .unwrap();
            let result = prepared
                .execute(SqlControl::new(SqlLimits::default(), None))
                .unwrap();
            assert_eq!(
                result.rows(),
                &[vec![SqlValue::U64(DecimalU64(3))]],
                "{dialect:?}: {}",
                prepared.adapted_sql
            );
        }
    }

    #[test]
    fn not_between_preserves_null_boundaries_and_duplicate_rows() {
        use mdd_query::ir::Signed64;
        let provider = Arc::new(RowsProvider {
            binding: SqlBinding {
                provider_identity: "not-between-boundaries".into(),
                snapshot_id: "not-between-snapshot".into(),
                catalog_epoch: DecimalU64(0),
            },
            rows: [None, Some(-1), Some(0), Some(1), Some(8), Some(9), Some(9)]
                .into_iter()
                .map(|value| vec![value.map_or(SqlValue::Null, |n| SqlValue::I64(Signed64(n)))])
                .collect(),
            columns: vec![SqlColumn {
                id: "id".into(),
                name: "id".into(),
                data_type: SqlType::I64,
                nullable: true,
            }],
        });
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            let result = bridge
                .query("SELECT id FROM vals WHERE id NOT BETWEEN 0 AND 8 ORDER BY id")
                .unwrap();
            assert_eq!(
                result.rows(),
                &[
                    vec![SqlValue::I64(Signed64(-1))],
                    vec![SqlValue::I64(Signed64(9))],
                    vec![SqlValue::I64(Signed64(9))],
                ],
                "{dialect:?}"
            );
            let result = bridge.query("SELECT 3 NOT BETWEEN NULL AND 2,1 NOT BETWEEN NULL AND 2,0 NOT BETWEEN 1 AND NULL,1 NOT BETWEEN 0 AND NULL,NULL NOT BETWEEN 0 AND 2,1 NOT BETWEEN 1 AND 2,3 NOT BETWEEN 1 AND 2").unwrap();
            assert_eq!(
                result.rows()[0],
                vec![
                    SqlValue::I64(Signed64(1)),
                    SqlValue::Null,
                    SqlValue::I64(Signed64(1)),
                    SqlValue::Null,
                    SqlValue::Null,
                    SqlValue::I64(Signed64(0)),
                    SqlValue::I64(Signed64(1)),
                ],
                "{dialect:?}"
            );
            let error = bridge
                .query("SELECT missing NOT BETWEEN 0 AND 8 FROM vals")
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidArgument, "{dialect:?}");
        }
    }

    #[test]
    fn legacy_numeric_column_between_converts_exact_text_bounds() {
        use mdd_query::ir::Signed64;
        let values = [None, Some(-1), Some(0), Some(1), Some(8), Some(9), Some(9)];
        let provider = Arc::new(RowsProvider {
            binding: SqlBinding {
                provider_identity: "between-text-affinity".into(),
                snapshot_id: "between-text-snapshot".into(),
                catalog_epoch: DecimalU64(0),
            },
            rows: values
                .iter()
                .map(|value| vec![value.map_or(SqlValue::Null, |n| SqlValue::I64(Signed64(n)))])
                .collect(),
            columns: vec![SqlColumn {
                id: "id".into(),
                name: "id".into(),
                data_type: SqlType::I64,
                nullable: true,
            }],
        });
        let sqlite = rusqlite::Connection::open_in_memory().unwrap();
        sqlite.execute_batch("CREATE TABLE vals(id INTEGER); INSERT INTO vals VALUES(NULL),(-1),(0),(1),(8),(9),(9)").unwrap();
        let cases = [
            "SELECT id,id BETWEEN ' +01 ' AND '8e0' FROM vals ORDER BY id",
            "SELECT id,id NOT BETWEEN ' +01 ' AND '8e0' FROM vals ORDER BY id",
            "SELECT id,id BETWEEN NULL AND '8.0' FROM vals ORDER BY id",
            "SELECT id,id BETWEEN '-1' AND NULL FROM vals ORDER BY id",
            "SELECT v.id FROM vals v WHERE v.id BETWEEN '0' AND 8 ORDER BY v.id",
        ];
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for sql in cases {
                let mut statement = sqlite.prepare(sql).unwrap();
                let width = statement.column_count();
                let expected = statement
                    .query_map([], |row| {
                        (0..width)
                            .map(|index| {
                                row.get::<_, Option<i64>>(index).map(|value| {
                                    value.map_or(SqlValue::Null, |n| SqlValue::I64(Signed64(n)))
                                })
                            })
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert_eq!(
                    bridge.query(sql).unwrap().rows(),
                    expected,
                    "{dialect:?}: {sql}"
                );
            }
            assert_eq!(
                bridge
                    .query("SELECT missing BETWEEN '0' AND '1' FROM vals")
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidArgument
            );
            assert_eq!(
                bridge
                    .query("SELECT id BETWEEN '0.5' AND '1' FROM vals")
                    .unwrap_err()
                    .code,
                ErrorCode::UnsupportedQuery
            );
        }
        let native = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        assert_eq!(
            native
                .query("SELECT id BETWEEN '1' AND '8' FROM vals")
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedQuery
        );
    }

    #[test]
    fn literal_between_and_simple_case_preserve_storage_class_rules() {
        let (provider, _) = bridge();
        let sqlite = rusqlite::Connection::open_in_memory().unwrap();
        let cases = [
            "SELECT 2 BETWEEN '1' AND 'z'",
            "SELECT 2 NOT BETWEEN '1' AND 'z'",
            "SELECT '2' BETWEEN 1 AND 'z'",
            "SELECT 2 BETWEEN NULL AND 'z'",
            "SELECT 2 NOT BETWEEN NULL AND 'z'",
            "SELECT CASE 2 WHEN '2' THEN 1 WHEN 2 THEN 3 ELSE 4 END",
            "SELECT CASE 'a' WHEN 1 THEN 0 WHEN 'a' THEN 2 ELSE 3 END",
            "SELECT CASE NULL WHEN NULL THEN 1 ELSE 4 END",
        ];
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for sql in cases {
                let expected: Option<i64> = sqlite.query_row(sql, [], |row| row.get(0)).unwrap();
                let result = bridge.query(sql).unwrap();
                let actual = match &result.rows()[0][0] {
                    SqlValue::Null => None,
                    SqlValue::I64(value) => Some(value.0),
                    SqlValue::U64(value) => Some(i64::try_from(value.0).unwrap()),
                    other => panic!("unexpected result {other:?}"),
                };
                assert_eq!(actual, expected, "{dialect:?}: {sql}");
            }
        }
    }

    #[test]
    fn legacy_integer_column_in_accepts_exact_decimal_text() {
        use mdd_query::ir::Signed64;
        let (provider, native) = bridge();
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            let result = bridge.query("SELECT id IN ('1'), id NOT IN ('1'), id IN ('1',NULL), id NOT IN ('2',NULL), id IN ('-1') FROM facts WHERE id=1").unwrap();
            assert_eq!(
                result.rows()[0],
                vec![
                    SqlValue::I64(Signed64(1)),
                    SqlValue::I64(Signed64(0)),
                    SqlValue::I64(Signed64(1)),
                    SqlValue::Null,
                    SqlValue::I64(Signed64(0)),
                ]
            );
            for sql in [
                "SELECT id IN ('9223372036854775808') FROM facts",
                "SELECT id IN ('1.0') FROM facts",
                "WITH x AS (SELECT '1' AS id) SELECT id IN ('1') FROM x",
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap_err().code,
                    ErrorCode::UnsupportedQuery,
                    "{sql}"
                );
            }
            assert_eq!(
                bridge
                    .query("SELECT missing IN ('1') FROM facts")
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidArgument
            );
            assert_eq!(
                bridge.query("SELECT 1 IN ('1')").unwrap().rows()[0][0],
                SqlValue::I64(Signed64(0))
            );
        }
        assert_eq!(
            native
                .query("SELECT id IN ('1') FROM facts")
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedQuery
        );
    }

    #[test]
    fn unrelated_cte_does_not_hide_direct_base_table_in_scope() {
        use mdd_query::ir::Signed64;
        let (provider, _) = bridge();
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for sql in [
                "WITH marker AS (SELECT 1 AS n) SELECT f.id FROM facts AS f WHERE f.id IN (1,2) ORDER BY f.id",
                "WITH marker AS (SELECT 1 AS n), q AS (SELECT id FROM facts WHERE id IN (1,2)) SELECT id FROM q ORDER BY id",
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap().rows(),
                    &[
                        vec![SqlValue::U64(DecimalU64(1))],
                        vec![SqlValue::U64(DecimalU64(2))]
                    ],
                    "{dialect:?}: {sql}"
                );
            }
            for sql in [
                "WITH FaCtS AS (SELECT '1' AS id) SELECT id IN (1) FROM facts",
                "WITH facts AS (SELECT '1' AS id), q AS (SELECT id IN (1) AS v FROM FaCtS) SELECT v FROM q",
                "WITH marker AS (SELECT 1 AS n) SELECT d.id IN (1) FROM (SELECT '1' AS id) AS d",
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap_err().code,
                    ErrorCode::UnsupportedQuery,
                    "{dialect:?}: {sql}"
                );
            }
            for sql in [
                "WITH marker AS (SELECT 1 AS n) SELECT missing IN (1) FROM facts",
                "WITH marker AS (SELECT 1 AS n) SELECT id IN (1) FROM facts a JOIN facts b ON a.id=b.id",
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap_err().code,
                    ErrorCode::InvalidArgument,
                    "{dialect:?}: {sql}"
                );
            }
            assert_eq!(bridge.query("WITH RECURSIVE q(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM q WHERE n<3) SELECT n FROM q").unwrap_err().code, ErrorCode::UnsupportedQuery);
            if dialect != SqlDialect::NativeV1 {
                let rows = bridge
                    .query(
                        "WITH marker AS (SELECT 1 AS n) SELECT id IN ('1') FROM facts WHERE id=1",
                    )
                    .unwrap();
                assert_eq!(rows.rows()[0][0], SqlValue::I64(Signed64(1)));
            }
        }
    }

    #[test]
    fn correlated_in_resolves_only_proven_outer_scopes_and_respects_shadowing() {
        let (provider, _) = bridge();
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            let rows = |sql: &str| {
                bridge
                    .query(sql)
                    .unwrap()
                    .rows()
                    .iter()
                    .map(|row| row[0].clone())
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                rows(
                    "SELECT o.id FROM facts o WHERE EXISTS (SELECT 1 FROM facts i WHERE o.id IN (1,3) AND i.id=1) ORDER BY o.id"
                ),
                vec![SqlValue::U64(DecimalU64(1)), SqlValue::U64(DecimalU64(3))],
                "{dialect:?}"
            );
            for predicate in ["o.id IN (1)", "id IN (1)"] {
                let sql = format!(
                    "SELECT o.id FROM facts o WHERE EXISTS (SELECT 1 FROM facts o WHERE {predicate}) ORDER BY o.id"
                );
                assert_eq!(
                    rows(&sql),
                    vec![
                        SqlValue::U64(DecimalU64(1)),
                        SqlValue::U64(DecimalU64(2)),
                        SqlValue::U64(DecimalU64(3))
                    ],
                    "{dialect:?}: {sql}"
                );
            }
            for sql in [
                "SELECT o.id FROM facts o WHERE EXISTS (SELECT 1 FROM (SELECT 1 AS id) d WHERE o.id IN (1))",
                "WITH d AS (SELECT 1 AS id) SELECT o.id FROM facts o WHERE EXISTS (SELECT 1 FROM d WHERE o.id IN (1))",
            ] {
                let error = bridge.query(sql).unwrap_err();
                assert_eq!(
                    error.code,
                    ErrorCode::UnsupportedQuery,
                    "{dialect:?}: {sql}: {error:?}"
                );
            }
            for sql in [
                "SELECT o.id FROM facts o WHERE EXISTS (SELECT 1 FROM facts i JOIN facts j ON i.id=j.id WHERE id IN (1))",
                "SELECT o.id FROM facts o WHERE EXISTS (SELECT 1 FROM facts i WHERE o.missing IN (1))",
                "SELECT o.id FROM facts o WHERE EXISTS (SELECT 1 FROM facts i WHERE missing_alias.id IN (1))",
                "WITH d AS (SELECT 1 AS id) SELECT o.id FROM facts o WHERE EXISTS (SELECT 1 FROM d WHERE o.id IN (1) AND missing=1)",
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap_err().code,
                    ErrorCode::InvalidArgument,
                    "{dialect:?}: {sql}"
                );
            }
            // Even a same-named CTE hint cannot authorize a real internal table,
            // a write, or database attachment during read-only preflight.
            let relations = provider.relations().unwrap();
            let hints = BTreeSet::from(["sqlite_master".to_owned()]);
            for sql in [
                "SELECT name FROM sqlite_master",
                "DELETE FROM facts",
                "ATTACH DATABASE ':memory:' AS other",
            ] {
                assert!(
                    bridge
                        .original_binding_error(sql, &relations, &hints)
                        .unwrap()
                        .is_some(),
                    "{dialect:?}: {sql}"
                );
            }
        }
    }

    #[test]
    fn visible_cte_container_is_readable_without_authorizing_real_tables_or_writes() {
        let (provider, _) = bridge();
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for sql in [
                "WITH d AS (SELECT 1 AS id) SELECT COUNT(*) AS n FROM d",
                "WITH a AS (SELECT 1 AS id), d AS (SELECT id FROM a) SELECT COUNT(*) AS n FROM d",
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap().rows()[0][0],
                    SqlValue::I64(mdd_query::ir::Signed64(1)),
                    "{dialect:?}: {sql}"
                );
            }
            for sql in [
                "SELECT name FROM sqlite_master",
                "SELECT name FROM main.sqlite_master",
                "DELETE FROM facts",
                "ATTACH DATABASE ':memory:' AS other",
            ] {
                assert!(bridge.query(sql).is_err(), "{dialect:?}: {sql}");
            }
        }
    }

    #[test]
    fn unsupported_function_in_visible_cte_keeps_real_binding_errors() {
        let (provider, _) = bridge();
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            let sql = "WITH d AS (SELECT 1 AS id) SELECT ABS(1) FROM d";
            assert_eq!(
                bridge.query(sql).unwrap_err().code,
                ErrorCode::UnsupportedQuery,
                "{dialect:?}: {sql}"
            );
            for sql in [
                "WITH d AS (SELECT 1 AS id) SELECT ABS(1) FROM d WHERE missing=1",
                "WITH d AS (SELECT 1 AS id) SELECT load_extension('x') FROM d",
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap_err().code,
                    ErrorCode::InvalidArgument,
                    "{dialect:?}: {sql}"
                );
            }
            // Database-qualified relations are a genuine unsupported feature;
            // rejecting them must not be confused with a missing-column error.
            assert_eq!(
                bridge
                    .query("SELECT ABS(1) FROM main.sqlite_master")
                    .unwrap_err()
                    .code,
                ErrorCode::UnsupportedQuery
            );
        }
    }

    #[test]
    fn legacy_integer_cast_literal_in_uses_numeric_affinity() {
        use mdd_query::ir::Signed64;
        let (provider, native) = bridge();
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            let result = bridge.query("SELECT CAST('01' AS INTEGER) IN ('1'), CAST('01' AS INTEGER) NOT IN ('1'), CAST('01' AS INTEGER) IN ('2', NULL)").unwrap();
            assert_eq!(
                result.rows()[0],
                vec![
                    SqlValue::I64(Signed64(1)),
                    SqlValue::I64(Signed64(0)),
                    SqlValue::Null
                ]
            );
            for sql in [
                "SELECT CAST('01'||'' AS INTEGER) IN ('1')",
                "SELECT CAST('01' AS BIGINT) IN ('1')",
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap_err().code,
                    ErrorCode::UnsupportedQuery,
                    "{sql}"
                );
            }
        }
        assert_eq!(
            native
                .query("SELECT CAST('01' AS INTEGER) IN ('1')")
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedQuery
        );
    }

    #[test]
    fn legacy_integer_in_text_affinity_matches_sqlite_for_exact_decimal_forms() {
        let (provider, native) = bridge();
        let sqlite = rusqlite::Connection::open_in_memory().unwrap();
        sqlite
            .execute_batch("CREATE TABLE facts(id INTEGER); INSERT INTO facts VALUES(1),(2),(3);")
            .unwrap();
        let cases = [
            "SELECT id IN ('01','+1','  +0001  '),id NOT IN ('-0001',NULL),id IN ('-0',' +2 ') FROM facts ORDER BY id",
            "SELECT CAST('-01' AS INTEGER) IN (' -0001 '),CAST('0' AS INTEGER) IN ('-0'),CAST('3' AS INTEGER) IN ('+0003',NULL)",
            "SELECT CAST('-9223372036854775808' AS INTEGER) IN (' -009223372036854775808 '),CAST('1' AS INTEGER) IN ('\t+001\n')",
            "SELECT f.id FROM facts f WHERE EXISTS (SELECT 1 FROM facts g WHERE f.id IN ('+001','002') AND g.id=f.id) ORDER BY f.id",
        ];
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for sql in cases {
                let mut stmt = sqlite.prepare(sql).unwrap();
                let width = stmt.column_count();
                let expected = stmt
                    .query_map([], |row| {
                        (0..width)
                            .map(|i| row.get::<_, Option<i64>>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let actual = bridge
                    .query(sql)
                    .unwrap()
                    .rows()
                    .iter()
                    .map(|row| {
                        row.iter()
                            .map(|cell| match cell {
                                SqlValue::Null => None,
                                SqlValue::I64(value) => Some(value.0),
                                SqlValue::U64(value) => Some(i64::try_from(value.0).unwrap()),
                                value => panic!("unexpected {value:?}"),
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                assert_eq!(actual, expected, "{dialect:?}: {sql}");
            }
            for sql in [
                "SELECT id IN ('1.5') FROM facts",
                "SELECT id IN ('1e-999') FROM facts",
                "SELECT id IN ('9223372036854775808') FROM facts",
                "SELECT id IN ('-9223372036854775809') FROM facts",
                "SELECT id IN ('0x1') FROM facts",
                "SELECT id IN ('　1') FROM facts",
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap_err().code,
                    ErrorCode::UnsupportedQuery,
                    "{sql}"
                );
            }
            assert_eq!(
                bridge
                    .query("SELECT missing IN ('01') FROM facts")
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidArgument
            );
        }
        assert_eq!(
            native
                .query("SELECT id IN ('01') FROM facts")
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedQuery
        );
    }

    #[test]
    fn legacy_integer_in_exact_real_syntax_text_matches_sqlite() {
        let (provider, native) = bridge();
        let sqlite = rusqlite::Connection::open_in_memory().unwrap();
        sqlite
            .execute_batch("CREATE TABLE facts(id INTEGER); INSERT INTO facts VALUES(1),(2),(3);")
            .unwrap();
        let cases = [
            "SELECT id IN ('1.0','+2e0',NULL),id NOT IN ('3.00',NULL) FROM facts ORDER BY id",
            "SELECT id FROM facts WHERE id IN ('.1e1','20e-1','30.0e-1') ORDER BY id",
            "SELECT CAST('0' AS INTEGER) IN (' -0.0e999 '), CAST('-12' AS INTEGER) IN ('-1.20e1')",
            "SELECT CAST('9007199254740991' AS INTEGER) IN ('9007199254740991.0'), CAST('123456789012345' AS INTEGER) IN ('123456789.012345e6')",
            "SELECT CAST('9007199254740991' AS INTEGER) IN ('90071992547409910.0e-1'), CAST('0' AS INTEGER) IN ('-0.000e-999')",
            "SELECT f.id FROM facts f WHERE EXISTS (SELECT 1 FROM facts g WHERE f.id IN ('01.0','2e0') AND g.id=f.id) ORDER BY f.id",
        ];
        // SQLite rounds this 18-digit fractional decimal to the adjacent
        // integer and underflows nonzero 1e-999 to zero. Neither is an exact
        // decimal integer, so the candidate must not silently rewrite them.
        let rounded: i64 = sqlite
            .query_row(
                "SELECT CAST('9007199254740991' AS INTEGER) IN ('90071992547409909.0e-1')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let underflow: i64 = sqlite
            .query_row("SELECT CAST('0' AS INTEGER) IN ('1e-999')", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!((rounded, underflow), (1, 1));
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for sql in cases {
                let mut stmt = sqlite.prepare(sql).unwrap();
                let width = stmt.column_count();
                let expected = stmt
                    .query_map([], |row| {
                        (0..width)
                            .map(|i| row.get::<_, Option<i64>>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let actual = bridge
                    .query(sql)
                    .unwrap()
                    .rows()
                    .iter()
                    .map(|row| {
                        row.iter()
                            .map(|cell| match cell {
                                SqlValue::Null => None,
                                SqlValue::I64(value) => Some(value.0),
                                SqlValue::U64(value) => Some(i64::try_from(value.0).unwrap()),
                                value => panic!("unexpected {value:?}"),
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                assert_eq!(actual, expected, "{dialect:?}: {sql}");
            }
            for sql in [
                "SELECT id IN ('1.5') FROM facts",
                "SELECT id IN ('1e-999') FROM facts",
                "SELECT id IN ('9007199254740992.0') FROM facts",
                "SELECT id IN ('9007199254740993.0') FROM facts",
                "SELECT id IN ('90071992547409909.0e-1') FROM facts",
                "SELECT id IN ('1.000000000000000001') FROM facts",
                "SELECT id IN ('1e999') FROM facts",
                "SELECT id IN ('1e') FROM facts",
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap_err().code,
                    ErrorCode::UnsupportedQuery,
                    "{sql}"
                );
            }
            assert_eq!(
                bridge
                    .query("SELECT missing IN ('1.0') FROM facts")
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidArgument
            );
        }
        assert_eq!(
            native
                .query("SELECT id IN ('1.0') FROM facts")
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedQuery
        );
    }

    #[test]
    fn legacy_integer_cast_literal_equality_uses_numeric_affinity() {
        use mdd_query::ir::Signed64;
        let (provider, native) = bridge();
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            let result = bridge.query("SELECT CAST('01' AS INTEGER)='1', '1'=CAST('01' AS INTEGER), CAST('01' AS INTEGER)<>'1', CAST('bad' AS INTEGER)='1', CAST('01' AS INTEGER)=NULL").unwrap();
            assert_eq!(
                result.rows()[0],
                vec![
                    SqlValue::I64(Signed64(1)),
                    SqlValue::I64(Signed64(1)),
                    SqlValue::I64(Signed64(0)),
                    SqlValue::I64(Signed64(0)),
                    SqlValue::Null
                ]
            );
            for sql in [
                "SELECT CAST('01' AS INTEGER)='01'",
                "SELECT CAST('01'||'' AS INTEGER)='1'",
                "SELECT CAST('01' AS BIGINT)='1'",
                "SELECT CAST('01' AS INTEGER)>'1'",
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap_err().code,
                    ErrorCode::UnsupportedQuery,
                    "{sql}"
                );
            }
        }
        assert_eq!(
            native
                .query("SELECT CAST('01' AS INTEGER)='1'")
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedQuery
        );
    }

    #[test]
    fn legacy_numeric_literal_cast_to_text_equality_is_bounded() {
        use mdd_query::ir::Signed64;
        let (provider, native) = bridge();
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            let result = bridge.query("SELECT CAST(1 AS TEXT)=1, 1=CAST(1 AS TEXT), CAST(10 AS TEXT)=1, CAST(1 AS TEXT)=NULL").unwrap();
            assert_eq!(
                result.rows()[0],
                vec![
                    SqlValue::I64(Signed64(1)),
                    SqlValue::I64(Signed64(1)),
                    SqlValue::I64(Signed64(0)),
                    SqlValue::Null
                ]
            );
            for sql in [
                "SELECT CAST(1 AS TEXT)<>1",
                "SELECT CAST(1 AS VARCHAR)=1",
                "SELECT CAST(1+0 AS TEXT)=1",
                "SELECT CAST(1 AS TEXT)=1.0",
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap_err().code,
                    ErrorCode::UnsupportedQuery,
                    "{sql}"
                );
            }
        }
        assert_eq!(
            native.query("SELECT CAST(1 AS TEXT)=1").unwrap_err().code,
            ErrorCode::UnsupportedQuery
        );
    }

    #[test]
    fn legacy_literal_text_affinity_in_between_and_simple_case() {
        let (provider, native) = bridge();
        let sqlite = rusqlite::Connection::open_in_memory().unwrap();
        let cases = [
            "SELECT CAST('10' AS TEXT) BETWEEN 1 AND 2",
            "SELECT CAST('10' AS TEXT) NOT BETWEEN 1 AND 2",
            "SELECT 1 BETWEEN CAST('1' AS TEXT) AND 3",
            "SELECT 2 BETWEEN 1 AND CAST('10' AS TEXT)",
            "SELECT CASE CAST('1' AS TEXT) WHEN 1 THEN 8 ELSE 9 END",
            "SELECT CASE 1 WHEN CAST('1' AS TEXT) THEN 8 ELSE 9 END",
            "SELECT CASE CAST('01' AS TEXT) WHEN 1 THEN 8 ELSE 9 END",
        ];
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for sql in cases {
                let expected: i64 = sqlite.query_row(sql, [], |row| row.get(0)).unwrap();
                let result = bridge.query(sql).unwrap();
                let actual = match &result.rows()[0][0] {
                    SqlValue::I64(value) => value.0,
                    SqlValue::U64(value) => i64::try_from(value.0).unwrap(),
                    other => panic!("unexpected result {other:?}"),
                };
                assert_eq!(actual, expected, "{dialect:?}: {sql}");
            }
        }
        for sql in [
            "SELECT CAST('10' AS TEXT) BETWEEN 1 AND 2",
            "SELECT CASE CAST('1' AS TEXT) WHEN 1 THEN 8 ELSE 9 END",
        ] {
            assert_eq!(
                native.query(sql).unwrap_err().code,
                ErrorCode::UnsupportedQuery
            );
        }
    }

    #[test]
    fn min_max_multi_argument_scalar_does_not_become_aggregate() {
        let (_, bridge) = bridge();
        let value = bridge
            .query("SELECT min(1,2) AS lo,max(1,2) AS hi")
            .unwrap();
        assert_eq!(value.columns(), &["lo", "hi"]);
        assert_eq!(
            value.rows()[0],
            vec![
                SqlValue::I64(mdd_query::ir::Signed64(1)),
                SqlValue::I64(mdd_query::ir::Signed64(2))
            ]
        );
        let aggregate = bridge.query("SELECT min(id),max(id) FROM facts").unwrap();
        assert_eq!(aggregate.rows().len(), 1);
        assert_eq!(
            aggregate.rows()[0],
            vec![SqlValue::U64(DecimalU64(1)), SqlValue::U64(DecimalU64(3))]
        );
        let result = bridge
            .query("SELECT min(NULL,1),max('x',NULL,'y'),min(1,'0'),max(1,'0'),min('z',X'00'),max('z',X'00'),min('a','B'),max('a','B')")
            .unwrap();
        assert_eq!(
            result.rows()[0],
            vec![
                SqlValue::Null,
                SqlValue::Null,
                SqlValue::I64(mdd_query::ir::Signed64(1)),
                SqlValue::text("0"),
                SqlValue::text("z"),
                SqlValue::Bytes(vec![0]),
                SqlValue::text("B"),
                SqlValue::text("a"),
            ]
        );
        let result = bridge
            .query("SELECT min(id,2),max(id,2) FROM facts ORDER BY id")
            .unwrap();
        let numeric = |v: &SqlValue| match v {
            SqlValue::I64(n) => i128::from(n.0),
            SqlValue::U64(n) => i128::from(n.0),
            other => panic!("unexpected min/max value: {other:?}"),
        };
        let rows: Vec<Vec<_>> = result
            .rows()
            .iter()
            .map(|r| r.iter().map(numeric).collect())
            .collect();
        assert_eq!(rows, vec![vec![1, 2], vec![2, 2], vec![2, 3]]);
        assert_eq!(
            bridge.query("SELECT min()").unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        for sql in [
            "SELECT min('a' COLLATE NOCASE,'B')",
            "SELECT min('a','B' COLLATE NOCASE)",
            "SELECT max('a' COLLATE BINARY,'B' COLLATE NOCASE)",
            "WITH t AS (SELECT 'a' COLLATE NOCASE AS c) SELECT min(c,'B') FROM t",
        ] {
            assert_eq!(
                bridge.query(sql).unwrap_err().code,
                ErrorCode::UnsupportedQuery,
                "{sql}"
            );
        }
    }
    #[test]
    fn large_negative_group_constant_is_not_position() {
        let (_, bridge) = bridge();
        let result = bridge
            .query("SELECT COUNT(*) AS n FROM facts GROUP BY (-2147483648)")
            .unwrap();
        assert_eq!(
            result.rows()[0][0],
            SqlValue::I64(mdd_query::ir::Signed64(3))
        );
    }
    #[test]
    fn grouped_parenthesized_position_preserves_nulls_and_multiplicity() {
        let (_, bridge) = bridge();
        let numeric = |value: &SqlValue| match value {
            SqlValue::Null => None,
            SqlValue::I64(value) => Some(i128::from(value.0)),
            SqlValue::U64(value) => Some(i128::from(value.0)),
            other => panic!("unexpected value: {other:?}"),
        };
        let queries = [
            (
                "SELECT id%2 AS parity,COUNT(*) AS n FROM facts GROUP BY ((1)) ORDER BY parity",
                vec![vec![Some(0), Some(1)], vec![Some(1), Some(2)]],
            ),
            (
                "SELECT id%2 AS parity,COUNT(*) AS n FROM facts GROUP BY (+1) ORDER BY parity",
                vec![vec![Some(0), Some(1)], vec![Some(1), Some(2)]],
            ),
            (
                "SELECT COUNT(*) AS n FROM facts GROUP BY (1.0)",
                vec![vec![Some(3)]],
            ),
            (
                "SELECT COUNT(*) AS n FROM facts GROUP BY (2147483648)",
                vec![vec![Some(3)]],
            ),
            (
                "SELECT COUNT(*) AS n FROM facts GROUP BY (-2147483648)",
                vec![vec![Some(3)]],
            ),
            (
                "SELECT id%2 AS parity,COUNT(*) AS n FROM facts GROUP BY (1) HAVING n>1 ORDER BY parity",
                vec![vec![Some(1), Some(2)]],
            ),
            (
                "SELECT CASE WHEN id=1 THEN NULL ELSE 1 END AS k,COUNT(*) AS n FROM facts GROUP BY (1) ORDER BY k",
                vec![vec![None, Some(1)], vec![Some(1), Some(2)]],
            ),
            (
                "SELECT id%2 AS id,COUNT(*) AS n FROM facts GROUP BY id ORDER BY id",
                vec![
                    vec![Some(0), Some(1)],
                    vec![Some(1), Some(1)],
                    vec![Some(1), Some(1)],
                ],
            ),
        ];
        for (sql, expected) in queries {
            let result = bridge.query(sql).unwrap();
            let rows: Vec<Vec<_>> = result
                .rows()
                .iter()
                .map(|r| r.iter().map(numeric).collect())
                .collect();
            assert_eq!(rows, expected, "{sql}");
        }
        for sql in [
            "SELECT id FROM facts GROUP BY (0)",
            "SELECT id FROM facts GROUP BY ((2))",
            "SELECT id FROM facts GROUP BY (-1)",
            "SELECT id FROM facts GROUP BY (2147483647)",
            "SELECT id FROM facts ORDER BY (-1)",
        ] {
            assert_eq!(
                bridge.query(sql).unwrap_err().code,
                ErrorCode::InvalidArgument,
                "{sql}"
            );
        }
    }
    #[test]
    fn order_by_projection_alias_beats_same_named_source_column() {
        let (_, bridge) = bridge();
        let numeric = |value: &SqlValue| match value {
            SqlValue::Null => None,
            SqlValue::I64(value) => Some(i128::from(value.0)),
            SqlValue::U64(value) => Some(i128::from(value.0)),
            other => panic!("unexpected value: {other:?}"),
        };
        let queries = [
            (
                "SELECT 4-id AS id FROM facts ORDER BY id",
                vec![vec![Some(1)], vec![Some(2)], vec![Some(3)]],
            ),
            (
                "SELECT 4-id AS id FROM facts ORDER BY ((id))",
                vec![vec![Some(1)], vec![Some(2)], vec![Some(3)]],
            ),
            (
                "SELECT 4-id AS id FROM facts ORDER BY 1",
                vec![vec![Some(1)], vec![Some(2)], vec![Some(3)]],
            ),
            (
                "SELECT 4-id AS id FROM facts ORDER BY (1)",
                vec![vec![Some(1)], vec![Some(2)], vec![Some(3)]],
            ),
            (
                "SELECT 4-id AS id FROM facts ORDER BY (+1)",
                vec![vec![Some(1)], vec![Some(2)], vec![Some(3)]],
            ),
            (
                "SELECT id AS x,4-id AS x FROM facts ORDER BY x",
                vec![
                    vec![Some(1), Some(3)],
                    vec![Some(2), Some(2)],
                    vec![Some(3), Some(1)],
                ],
            ),
            (
                "SELECT CASE WHEN id=2 THEN NULL ELSE 4-id END AS id FROM facts ORDER BY id",
                vec![vec![None], vec![Some(1)], vec![Some(3)]],
            ),
            (
                "SELECT 4-id AS id, id AS x FROM facts ORDER BY id, x",
                vec![
                    vec![Some(1), Some(3)],
                    vec![Some(2), Some(2)],
                    vec![Some(3), Some(1)],
                ],
            ),
            (
                "SELECT CASE WHEN id=2 THEN NULL ELSE 4-id END AS id FROM facts ORDER BY id DESC NULLS LAST",
                vec![vec![Some(3)], vec![Some(1)], vec![None]],
            ),
        ];
        for (sql, expected) in queries {
            let output = bridge.query(sql).unwrap();
            let rows: Vec<Vec<_>> = output
                .rows()
                .iter()
                .map(|row| row.iter().map(numeric).collect())
                .collect();
            assert_eq!(rows, expected, "{sql}");
        }
        let wildcard_first = bridge
            .query("SELECT *,4-id AS id FROM facts ORDER BY id")
            .unwrap();
        assert_eq!(
            wildcard_first
                .rows()
                .iter()
                .map(|r| numeric(&r[0]))
                .collect::<Vec<_>>(),
            vec![Some(1), Some(2), Some(3)]
        );
        let explicit_first = bridge
            .query("SELECT 4-id AS id,* FROM facts ORDER BY id")
            .unwrap();
        assert_eq!(
            explicit_first
                .rows()
                .iter()
                .map(|r| numeric(&r[1]))
                .collect::<Vec<_>>(),
            vec![Some(3), Some(2), Some(1)]
        );
        assert_eq!(
            bridge
                .query("SELECT id FROM facts ORDER BY absent")
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }
    #[test]
    fn owned_cursor_is_lazy_and_preserves_multiplicity_and_nul() {
        let (provider, bridge) = bridge();
        let prepared = bridge
            .prepare("SELECT id,value FROM facts ORDER BY id")
            .unwrap();
        assert_eq!(provider.opens.load(Ordering::SeqCst), 0);
        let output = bridge
            .execute(&prepared, SqlControl::new(SqlLimits::default(), None))
            .unwrap();
        assert_eq!(output.rows.len(), 3);
        assert_eq!(output.rows[0][1], SqlValue::text("a\0b"));
        assert!(output.profiles_admitted.is_empty());
        assert_eq!(provider.opens.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn using_join_same_carrier_retains_sqlite_merged_wildcard_shape() {
        let (_, bridge) = bridge();
        let out = bridge
            .query("SELECT * FROM facts a JOIN facts b USING(id) ORDER BY 1")
            .unwrap();
        assert_eq!(out.columns, vec!["id", "value", "value"]);
        assert_eq!(out.rows.len(), 3);
        assert!(out.rows.iter().all(|row| row.len() == 3));
        let distinct = bridge
            .query("SELECT DISTINCT * FROM facts a JOIN facts b USING(id)")
            .unwrap();
        assert_eq!(distinct.rows.len(), 3);
        assert!(distinct.rows.iter().all(|row| row.len() == 3));
        let out = bridge
            .query("SELECT a.id FROM facts a LEFT JOIN facts b USING(id) ORDER BY a.id")
            .unwrap();
        assert_eq!(out.rows.len(), 3);
        assert_eq!(
            bridge
                .query("SELECT * FROM facts a JOIN facts b USING(no_such_column)")
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }
    #[test]
    fn legacy_direct_cte_text_literal_preserves_affinity() {
        let (provider, native) = bridge();
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for (sql, expected) in [
                (
                    "WITH t AS (SELECT CAST('1' AS TEXT) AS x) SELECT x=1 FROM t",
                    1,
                ),
                (
                    "WITH t AS (SELECT CAST('10' AS TEXT) AS x) SELECT t.x>2 FROM t",
                    0,
                ),
                (
                    "WITH t(y) AS (SELECT CAST('1' AS TEXT) AS x) SELECT 1=y FROM t",
                    1,
                ),
                (
                    "WITH t AS (SELECT CAST('1' AS TEXT) AS x) SELECT x<>1 FROM t",
                    0,
                ),
            ] {
                let rows = bridge.query(sql).unwrap().rows;
                assert_eq!(
                    rows,
                    vec![vec![SqlValue::I64(mdd_query::ir::Signed64(expected))]],
                    "{dialect:?}: {sql}"
                );
            }
            for sql in [
                "WITH t AS (SELECT CAST('1' AS TEXT) AS x, 2 AS y) SELECT x=1 FROM t",
                "WITH t AS (SELECT CAST('1' AS TEXT) AS x) SELECT x=1 FROM (SELECT x FROM t) d",
                "WITH t AS (SELECT CAST('1' AS TEXT) AS x) SELECT x=1.0 FROM t",
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap_err().code,
                    ErrorCode::UnsupportedQuery,
                    "{dialect:?}: {sql}"
                );
            }
        }
        assert_eq!(
            native
                .query("WITH t AS (SELECT CAST('1' AS TEXT) AS x) SELECT x=1 FROM t")
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedQuery
        );
    }
    #[test]
    fn literal_mixed_class_comparisons_preserve_sqlite_rank_without_guessing_affinity() {
        let (provider, _) = bridge();
        let cases = [
            ("SELECT 1='1' AS v", Some(0)),
            ("SELECT 1<'a' AS v", Some(1)),
            ("SELECT 'a'<X'00' AS v", Some(1)),
            ("SELECT 1<>X'31' AS v", Some(1)),
            ("SELECT 1.0='1.0' AS v", Some(0)),
            ("SELECT -1<'1' AS v", Some(1)),
            ("SELECT NULL=1 AS v", None),
        ];
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for (sql, expected) in cases {
                let result = bridge.query(sql).unwrap();
                let expected = expected.map_or(SqlValue::Null, |value| {
                    SqlValue::I64(mdd_query::ir::Signed64(value))
                });
                assert_eq!(result.rows()[0][0], expected, "{dialect:?}: {sql}");
            }
            let prepared = bridge
                .prepare_with_parameters("SELECT 1=? AS v", &[SqlValue::text("1")])
                .unwrap();
            let result = prepared
                .execute(SqlControl::new(SqlLimits::default(), None))
                .unwrap();
            assert_eq!(
                result.rows()[0][0],
                SqlValue::I64(mdd_query::ir::Signed64(0))
            );
            if dialect == SqlDialect::NativeV1 {
                assert_eq!(
                    bridge.query("SELECT CAST('1' AS TEXT)=1").unwrap_err().code,
                    ErrorCode::UnsupportedQuery
                );
            } else {
                let cast_result = bridge
                    .query("SELECT CAST('1' AS TEXT)=1,1=CAST('1' AS TEXT),CAST('10' AS TEXT)<2")
                    .unwrap();
                assert_eq!(
                    cast_result.rows()[0],
                    vec![
                        SqlValue::I64(mdd_query::ir::Signed64(1)),
                        SqlValue::I64(mdd_query::ir::Signed64(1)),
                        SqlValue::I64(mdd_query::ir::Signed64(1)),
                    ]
                );
                for sql in [
                    "SELECT CAST('1' AS VARCHAR)=1",
                    "SELECT CAST('1' AS TEXT)=1.0",
                    "SELECT CAST('1'||'' AS TEXT)=1",
                ] {
                    assert_eq!(
                        bridge.query(sql).unwrap_err().code,
                        ErrorCode::UnsupportedQuery,
                        "{sql}"
                    );
                }
            }
            if dialect == SqlDialect::NativeV1 {
                assert_eq!(
                    bridge
                        .query("WITH t AS (SELECT CAST('1' AS TEXT) AS x) SELECT x=1 FROM t")
                        .unwrap_err()
                        .code,
                    ErrorCode::UnsupportedQuery
                );
                assert_eq!(
                    bridge.query("SELECT 1+'a'").unwrap_err().code,
                    ErrorCode::InvalidArgument
                );
                assert_eq!(
                    bridge
                        .query("SELECT CAST('bad' AS INTEGER)")
                        .unwrap_err()
                        .code,
                    ErrorCode::InvalidArgument
                );
            } else {
                assert_eq!(
                    bridge
                        .query("WITH t AS (SELECT CAST('1' AS TEXT) AS x) SELECT x=1 FROM t")
                        .unwrap()
                        .rows()[0][0],
                    SqlValue::I64(mdd_query::ir::Signed64(1))
                );
                assert_eq!(
                    bridge.query("SELECT 1+'a'").unwrap().rows()[0][0],
                    SqlValue::I64(mdd_query::ir::Signed64(1))
                );
                assert_eq!(
                    bridge.query("SELECT 1+'2'").unwrap().rows()[0][0],
                    SqlValue::I64(mdd_query::ir::Signed64(3))
                );
            }
        }
    }
    #[test]
    fn legacy_arithmetic_handles_non_numeric_text_and_bytes_without_hiding_other_cases() {
        let (provider, _) = bridge();
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            let result = bridge
                .query("SELECT 1+'a',1-' x',2*X'61',2/'a',2%'a',NULL+'a'")
                .unwrap();
            assert_eq!(
                result.rows()[0],
                vec![
                    SqlValue::I64(mdd_query::ir::Signed64(1)),
                    SqlValue::I64(mdd_query::ir::Signed64(1)),
                    SqlValue::I64(mdd_query::ir::Signed64(0)),
                    SqlValue::Null,
                    SqlValue::Null,
                    SqlValue::Null,
                ],
                "{dialect:?}"
            );
            assert_eq!(
                bridge.query("SELECT 1+'2.5'").unwrap_err().code,
                ErrorCode::UnsupportedQuery
            );
        }
    }

    #[test]
    fn legacy_strict_integer_text_arithmetic_preserves_unimplemented_edges() {
        let (provider, _) = bridge();
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            let result = bridge
                .query("SELECT 1+' +2 ', ' -5 '*2, X'33'+2, '4'/2, '3'%0")
                .unwrap();
            assert_eq!(
                result.rows()[0],
                vec![
                    SqlValue::I64(mdd_query::ir::Signed64(3)),
                    SqlValue::I64(mdd_query::ir::Signed64(-10)),
                    SqlValue::I64(mdd_query::ir::Signed64(5)),
                    SqlValue::I64(mdd_query::ir::Signed64(2)),
                    SqlValue::Null,
                ]
            );
            for sql in [
                "SELECT 1+'2.5'",
                "SELECT 1+'2x'",
                "SELECT 1+'9223372036854775808'",
                "SELECT 1+'9223372036854775807'",
                "SELECT 1.0+'2'",
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap_err().code,
                    ErrorCode::UnsupportedQuery,
                    "{sql}"
                );
            }
        }
    }
    #[test]
    fn legacy_integer_cast_matches_sqlite_prefix_and_saturation_without_lossy_text() {
        let (provider, _) = bridge();
        let sqlite = rusqlite::Connection::open_in_memory().unwrap();
        let inputs: &[&[u8]] = &[
            b"",
            b"bad",
            b"123tail",
            b"  +00012tail",
            b"-5.9",
            b"1e5",
            b".5",
            b"0x10",
            b"++1",
            b"  -12 ",
            b"12\0tail",
            b"\0-8",
            b"9223372036854775807",
            b"9223372036854775808",
            b"-9223372036854775808",
            b"-9223372036854775809",
            b"9999999999999999999999999999999999",
            b"-9999999999999999999999999999999999",
            b"000000000000000000000000000000012",
            b"\x09\x0a\x0b\x0c\x0d +7x",
            b"12\xff3",
            b"\xff1",
        ];
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for input in inputs {
                let expected: i64 = sqlite
                    .query_row("SELECT CAST(?1 AS INTEGER)", [*input], |row| row.get(0))
                    .unwrap();
                let mut values = vec![SqlValue::Bytes(input.to_vec())];
                if let Ok(text) = std::str::from_utf8(input) {
                    values.push(SqlValue::text(text));
                }
                for value in values {
                    let prepared = bridge
                        .prepare_with_parameters("SELECT CAST(? AS INTEGER)", &[value])
                        .unwrap();
                    let result = prepared
                        .execute(SqlControl::new(SqlLimits::default(), None))
                        .unwrap();
                    assert_eq!(
                        result.rows()[0][0],
                        SqlValue::I64(mdd_query::ir::Signed64(expected)),
                        "{dialect:?}: {input:?}"
                    );
                }
            }
            for (units, expected) in [
                (vec![0xd800], 0),
                (vec![0x31, 0xd800, 0x39], 1),
                (vec![0xdc00], 0),
            ] {
                let value = SqlValue::Text(crate::values::SqlText {
                    utf16: units,
                    original_mutf8: None,
                });
                let prepared = bridge
                    .prepare_with_parameters("SELECT CAST(? AS INTEGER)", &[value])
                    .unwrap();
                let result = prepared
                    .execute(SqlControl::new(SqlLimits::default(), None))
                    .unwrap();
                assert_eq!(
                    result.rows()[0][0],
                    SqlValue::I64(mdd_query::ir::Signed64(expected))
                );
            }
            assert_eq!(
                bridge.query("SELECT CAST(NULL AS INTEGER)").unwrap().rows()[0][0],
                SqlValue::Null
            );
        }
    }
    #[test]
    fn legacy_integer_cast_long_prefix_respects_query_budget() {
        let (provider, _) = bridge();
        let bridge = SqlBridge::new(provider, SqlDialect::DexSql010, SqlLimits::default()).unwrap();
        let prepared = bridge
            .prepare_with_parameters(
                "SELECT CAST(? AS INTEGER)",
                &[SqlValue::text(&"0".repeat(50_000))],
            )
            .unwrap();
        let limits = SqlLimits {
            max_steps: 64,
            ..SqlLimits::default()
        };
        assert_eq!(
            prepared
                .execute(SqlControl::new(limits, None))
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    #[test]
    fn long_sql_comparisons_are_bounded_in_scalar_and_aggregate_paths() {
        let (provider, _) = bridge();
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for value in [
                SqlValue::text(&"x".repeat(2000)),
                SqlValue::Bytes(vec![b'x'; 2000]),
            ] {
                for sql in [
                    "SELECT ? = ?",
                    "SELECT NULLIF(?,?)",
                    "SELECT min(?,?)",
                    "SELECT min(v) FROM (SELECT ? AS v UNION ALL SELECT ? AS v)",
                ] {
                    let prepared = bridge
                        .prepare_with_parameters(sql, &[value.clone(), value.clone()])
                        .unwrap();
                    let limits = SqlLimits {
                        max_steps: 64,
                        ..SqlLimits::default()
                    };
                    assert_eq!(
                        prepared
                            .execute(SqlControl::new(limits, None))
                            .unwrap_err()
                            .code,
                        ErrorCode::QuotaExceeded,
                        "{dialect:?}: {sql}"
                    );
                }
            }
        }
    }
    #[test]
    fn sql_text_decode_quota_propagates_through_bridge() {
        let (provider, _) = bridge();
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            let limits = SqlLimits {
                max_steps: 64,
                ..SqlLimits::default()
            };
            let short = bridge
                .prepare_with_parameters(
                    "SELECT CAST(? AS TEXT)",
                    &[SqlValue::Bytes(vec![b'A'; 2])],
                )
                .unwrap();
            assert_eq!(
                short
                    .execute(SqlControl::new(limits.clone(), None))
                    .unwrap()
                    .rows()[0][0],
                SqlValue::text("AA"),
                "{dialect:?}"
            );
            for value in [
                SqlValue::Bytes(vec![b'A'; 2000]),
                SqlValue::DexMutf8 {
                    bytes: vec![b'A'; 2000],
                    utf16_code_units: DecimalU64(2000),
                },
            ] {
                let prepared = bridge
                    .prepare_with_parameters("SELECT CAST(? AS TEXT)", &[value])
                    .unwrap();
                assert_eq!(
                    prepared
                        .execute(SqlControl::new(limits.clone(), None))
                        .unwrap_err()
                        .code,
                    ErrorCode::QuotaExceeded,
                    "{dialect:?}"
                );
            }
        }
    }
    #[test]
    fn substring_retains_policy_units_and_bounded_negative_indices() {
        let (provider, native) = bridge();
        let expected = vec![
            SqlValue::text("bcd"),
            SqlValue::text("de"),
            SqlValue::text("bc"),
            SqlValue::text("\0B"),
            SqlValue::text("😀"),
            SqlValue::Null,
            SqlValue::text("B"),
            SqlValue::text("bcd"),
        ];
        let query = "SELECT substr('abcdef',2,3), substr('abcdef',-3,2), substr('abcdef',4,-2), substr('A\0B',2,2), substr('😀A',1,1), substr(NULL,1,2), substr(x'414243',2,1), substring('abcdef',2,3)";
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            assert_eq!(bridge.query(query).unwrap().rows[0], expected);
        }
        let output = native.query("SELECT substr('😀A',1,1), substr(x'414243',2,1), substr('abcdef',0,2), substr('abcdef',-9,7), substr('abcdef',9,-3), substr('abcdef',3)").unwrap();
        assert_eq!(
            output.rows[0],
            vec![
                SqlValue::Text(crate::values::SqlText {
                    utf16: vec![0xd83d],
                    original_mutf8: None
                }),
                SqlValue::Bytes(vec![b'B']),
                SqlValue::text("a"),
                SqlValue::text("abcd"),
                SqlValue::text("f"),
                SqlValue::text("cdef"),
            ]
        );
    }
    #[test]
    fn sql_authority_and_real_errors_are_not_success_or_unsupported() {
        let (_, bridge) = bridge();
        for sql in [
            "DELETE FROM facts",
            "ATTACH ':memory:' AS other",
            "PRAGMA user_version",
            "CREATE TEMP TABLE x AS SELECT 1",
            "SELECT load_extension('x')",
            "SELECT * FROM sqlite_master",
            "SELECT * FROM missing",
            "SELECT 1; SELECT 2",
            "SELECT (",
            "SELECT absent FROM facts",
        ] {
            let error = bridge.query(sql).unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidArgument, "{sql}: {error}");
        }
    }
    #[test]
    fn work_cancel_deadline_and_zero_result_budget_are_real_errors() {
        let (_, bridge) = bridge();
        let prepared = bridge.prepare("SELECT * FROM facts").unwrap();
        let cancelled = SqlControl::new(SqlLimits::default(), None);
        cancelled.cancel().unwrap();
        assert_eq!(
            bridge.execute(&prepared, cancelled).unwrap_err().code,
            ErrorCode::Cancelled
        );
        let deadline = SqlControl::new(SqlLimits::default(), Some(std::time::Instant::now()));
        assert_eq!(
            bridge.execute(&prepared, deadline).unwrap_err().code,
            ErrorCode::DeadlineExceeded
        );
        let limits = SqlLimits {
            max_result_rows: 0,
            ..SqlLimits::default()
        };
        assert_eq!(
            bridge
                .execute(&prepared, SqlControl::new(limits, None))
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    #[test]
    fn lossless_text_adapters_close_nul_surrogate_and_utf16_order_cases() {
        let (_, bridge) = bridge();
        let output=bridge.query("SELECT length('A\0B') AS n,hex(CAST('A\0B' AS BLOB)) AS h,length('😀') AS supplementary").unwrap();
        assert_eq!(
            output.rows[0],
            vec![
                SqlValue::I64(mdd_query::ir::Signed64(3)),
                SqlValue::text("410042"),
                SqlValue::I64(mdd_query::ir::Signed64(2))
            ]
        );
        let output = bridge.query("SELECT CAST(x'EDA080' AS TEXT) AS v").unwrap();
        assert_eq!(
            output.rows[0][0],
            SqlValue::Text(crate::values::SqlText {
                utf16: vec![0xd800],
                original_mutf8: None
            })
        );
        let output = bridge
            .query("SELECT '😀' AS v UNION ALL SELECT '\u{e000}' AS v ORDER BY v")
            .unwrap();
        assert_eq!(
            output.rows,
            vec![vec![SqlValue::text("😀")], vec![SqlValue::text("\u{e000}")]]
        );
    }
    #[test]
    fn like_policies_and_escaped_patterns_are_distinct() {
        let (provider, native) = bridge();
        let legacy = SqlBridge::new(provider, SqlDialect::DexSql010, SqlLimits::default()).unwrap();
        let sql = "SELECT 'axb' LIKE 'a_b' AS wildcard,'ABC' LIKE 'abc' AS ascii_case,'a_b' LIKE 'a\\_b' ESCAPE '\\' AS escaped";
        let flags = |output: SqlResult| {
            output.rows[0]
                .iter()
                .map(|v| {
                    if let SqlValue::I64(v) = v {
                        v.0
                    } else {
                        panic!("boolean callback result")
                    }
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(flags(native.query(sql).unwrap()), vec![1, 0, 1]);
        assert_eq!(flags(legacy.query(sql).unwrap()), vec![0, 1, 1]);
        let output=legacy.query("SELECT length('😀') AS n,hex(CAST('A\0B' AS TEXT)) AS h,hex(CAST('😀' AS TEXT)) AS s").unwrap();
        assert_eq!(
            output.rows[0],
            vec![
                SqlValue::I64(mdd_query::ir::Signed64(1)),
                SqlValue::text("41C08042"),
                SqlValue::text("EDA0BDEDB880")
            ]
        );
    }
    #[test]
    fn legacy_like_dangling_escape_matches_fixed_engines() {
        let (provider, native) = bridge();
        let sql = r"SELECT 'abc' LIKE 'abc\' ESCAPE '\' AS l, 'abc' NOT LIKE 'abc\' ESCAPE '\' AS n, 'a_b' LIKE 'a\_b' ESCAPE '\' AS ordinary, NULL LIKE 'abc\' ESCAPE '\' AS null_value";
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            assert_eq!(
                bridge.query(sql).unwrap().rows,
                vec![vec![
                    SqlValue::I64(mdd_query::ir::Signed64(0)),
                    SqlValue::I64(mdd_query::ir::Signed64(1)),
                    SqlValue::I64(mdd_query::ir::Signed64(1)),
                    SqlValue::Null,
                ]]
            );
        }
        assert_eq!(
            native.query(sql).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }
    struct Unbuilt {
        inner: Arc<Provider>,
        required: AtomicUsize,
    }
    impl SqlFactProvider for Unbuilt {
        fn binding(&self) -> &SqlBinding {
            &self.inner.binding
        }
        fn relations(&self) -> MddResult<Vec<SqlRelation>> {
            self.inner.relations()
        }
        fn require_relation(&self, _: &str) -> MddResult<()> {
            self.required.fetch_add(1, Ordering::SeqCst);
            Err(mdd_types::MddError::new(
                ErrorCode::IncompleteFacts,
                "test.layer",
                "structure is unbuilt",
            ))
        }
        fn open_cursor(
            self: Arc<Self>,
            _: &str,
            _: SqlControl,
        ) -> MddResult<Box<dyn SqlFactCursor>> {
            panic!("required layer must fail before cursor")
        }
    }
    #[test]
    fn short_circuit_cannot_skip_required_layers_and_unused_cte_does_not_build_them() {
        let (provider, _) = bridge();
        let source = Arc::new(Unbuilt {
            inner: provider,
            required: AtomicUsize::new(0),
        });
        let bridge =
            SqlBridge::new(source.clone(), SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        for sql in [
            "SELECT * FROM facts LIMIT 0",
            "SELECT * FROM facts WHERE 0",
            "WITH x AS (SELECT * FROM facts) SELECT * FROM x LIMIT 0",
        ] {
            let prepared = bridge.prepare(sql).unwrap();
            assert_eq!(prepared.required_relations(), ["facts"]);
            assert_eq!(
                bridge
                    .execute(&prepared, SqlControl::new(SqlLimits::default(), None))
                    .unwrap_err()
                    .code,
                ErrorCode::IncompleteFacts
            );
        }
        let count = source.required.load(Ordering::SeqCst);
        assert_eq!(
            bridge
                .query("WITH unused AS (SELECT * FROM facts) SELECT 1 AS n")
                .unwrap()
                .rows
                .len(),
            1
        );
        assert_eq!(source.required.load(Ordering::SeqCst), count);
        assert_eq!(
            bridge.query("SELECT 1 AS n").unwrap().required_relations,
            Vec::<String>::new()
        );
    }
    struct RowsProvider {
        binding: SqlBinding,
        rows: Vec<SqlRow>,
        columns: Vec<SqlColumn>,
    }
    struct RowsCursor {
        provider: Arc<RowsProvider>,
        position: usize,
    }
    impl SqlFactCursor for RowsCursor {
        fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
            let result = self.provider.rows.get(self.position).cloned();
            self.position += 1;
            Ok(result)
        }
    }
    impl SqlFactProvider for RowsProvider {
        fn binding(&self) -> &SqlBinding {
            &self.binding
        }
        fn relations(&self) -> MddResult<Vec<SqlRelation>> {
            Ok(vec![SqlRelation {
                name: "vals".into(),
                columns: self.columns.clone(),
                required_layers: vec![],
                estimated_rows: Some(DecimalU64(self.rows.len() as u64)),
            }])
        }
        fn require_relation(&self, _: &str) -> MddResult<()> {
            Ok(())
        }
        fn open_cursor(
            self: Arc<Self>,
            _: &str,
            _: SqlControl,
        ) -> MddResult<Box<dyn SqlFactCursor>> {
            Ok(Box::new(RowsCursor {
                provider: self,
                position: 0,
            }))
        }
    }

    fn like_shadow_fixture() -> (Arc<RowsProvider>, rusqlite::Connection) {
        use mdd_query::ir::Signed64;
        let provider = Arc::new(RowsProvider {
            binding: SqlBinding {
                provider_identity: "like-shadow".into(),
                snapshot_id: "like-shadow-snapshot".into(),
                catalog_epoch: DecimalU64(0),
            },
            columns: vec![
                SqlColumn {
                    id: "txt".into(),
                    name: "txt".into(),
                    data_type: SqlType::Text,
                    nullable: false,
                },
                SqlColumn {
                    id: "true".into(),
                    name: "true".into(),
                    data_type: SqlType::I64,
                    nullable: false,
                },
                SqlColumn {
                    id: "false".into(),
                    name: "false".into(),
                    data_type: SqlType::I64,
                    nullable: false,
                },
            ],
            rows: vec![vec![
                SqlValue::text("a_b"),
                SqlValue::I64(Signed64(0)),
                SqlValue::I64(Signed64(1)),
            ]],
        });
        let sqlite = rusqlite::Connection::open_in_memory().unwrap();
        sqlite.execute_batch("CREATE TABLE vals(txt TEXT, \"true\" INTEGER, \"false\" INTEGER); INSERT INTO vals VALUES ('a_b',0,1);").unwrap();
        (provider, sqlite)
    }

    #[test]
    fn like_without_escape_internal_flag_ignores_false_column() {
        use mdd_query::ir::Signed64;
        let (provider, sqlite) = like_shadow_fixture();
        let sql = "SELECT txt LIKE 'a_b' FROM vals";
        let expected: i64 = sqlite.query_row(sql, [], |row| row.get(0)).unwrap();
        assert_eq!(expected, 1);
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            assert_eq!(
                bridge.query(sql).unwrap().rows()[0][0],
                SqlValue::I64(Signed64(expected)),
                "{dialect:?}"
            );
        }
    }

    #[test]
    fn like_with_escape_internal_flag_ignores_true_column() {
        use mdd_query::ir::Signed64;
        let (provider, sqlite) = like_shadow_fixture();
        let sql = "SELECT txt LIKE 'a\\_b' ESCAPE '\\' FROM vals";
        let expected: i64 = sqlite.query_row(sql, [], |row| row.get(0)).unwrap();
        assert_eq!(expected, 1);
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            assert_eq!(
                bridge.query(sql).unwrap().rows()[0][0],
                SqlValue::I64(Signed64(expected)),
                "{dialect:?}"
            );
        }
    }

    #[test]
    fn is_boolean_predicates_respect_text_column_shadowing() {
        use mdd_query::ir::Signed64;
        let provider = Arc::new(RowsProvider {
            binding: SqlBinding {
                provider_identity: "is-bool-text-shadow".into(),
                snapshot_id: "is-bool-text-shadow-snapshot".into(),
                catalog_epoch: DecimalU64(0),
            },
            columns: ["id", "true", "false"]
                .into_iter()
                .map(|name| SqlColumn {
                    id: name.into(),
                    name: name.into(),
                    data_type: SqlType::Text,
                    nullable: false,
                })
                .collect(),
            rows: vec![vec![SqlValue::text("abc"); 3]],
        });
        let sqlite = rusqlite::Connection::open_in_memory().unwrap();
        sqlite.execute_batch("CREATE TABLE vals(id TEXT, \"true\" TEXT, \"false\" TEXT); INSERT INTO vals VALUES('abc','abc','abc')").unwrap();
        let sql = "SELECT id IS TRUE,id IS NOT TRUE,id IS FALSE,id IS NOT FALSE FROM vals";
        let expected = sqlite
            .query_row(sql, [], |row| {
                (0..4)
                    .map(|i| row.get::<_, i64>(i))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap();
        assert_eq!(expected, [1, 0, 1, 0]);
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for query in [
                sql,
                "SELECT id IS TRUE FROM vals",
                "SELECT id IS NOT TRUE FROM vals",
                "SELECT id IS FALSE FROM vals",
                "SELECT id IS NOT FALSE FROM vals",
                "SELECT (SELECT id IS TRUE) FROM vals",
            ] {
                sqlite.prepare(query).unwrap();
                assert_eq!(
                    bridge.query(query).unwrap_err().code,
                    ErrorCode::UnsupportedQuery,
                    "{dialect:?}: {query}"
                );
            }
            assert_eq!(
                bridge
                    .query("SELECT missing.x IS TRUE FROM vals")
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidArgument
            );
            let ordinary = bridge
                .query("SELECT 2 IS TRUE,2 IS NOT TRUE,0 IS FALSE,NULL IS FALSE")
                .unwrap();
            assert_eq!(
                ordinary.rows()[0],
                vec![
                    SqlValue::I64(Signed64(1)),
                    SqlValue::I64(Signed64(0)),
                    SqlValue::I64(Signed64(1)),
                    SqlValue::I64(Signed64(0))
                ]
            );
        }
        let (plain, _) = bridge();
        sqlite
            .execute_batch("CREATE TABLE facts(id INTEGER); INSERT INTO facts VALUES(2)")
            .unwrap();
        for alias in [
            "SELECT id AS \"true\" FROM facts WHERE id IS TRUE",
            "SELECT id AS \"false\" FROM facts WHERE id IS FALSE",
        ] {
            assert_eq!(
                sqlite
                    .prepare(alias)
                    .unwrap()
                    .query_map([], |row| row.get::<_, i64>(0))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap(),
                vec![2]
            );
            for dialect in [
                SqlDialect::NativeV1,
                SqlDialect::DexSql010,
                SqlDialect::DexSql011,
            ] {
                let bridge = SqlBridge::new(plain.clone(), dialect, SqlLimits::default()).unwrap();
                assert_eq!(
                    bridge.query(alias).unwrap_err().code,
                    ErrorCode::UnsupportedQuery
                );
            }
        }
    }

    #[test]
    fn is_boolean_predicates_respect_same_named_columns() {
        use mdd_query::ir::Signed64;
        let provider = Arc::new(RowsProvider {
            binding: SqlBinding {
                provider_identity: "is-bool-shadow".into(),
                snapshot_id: "is-bool-shadow-snapshot".into(),
                catalog_epoch: DecimalU64(0),
            },
            columns: ["id", "true", "false"]
                .into_iter()
                .map(|name| SqlColumn {
                    id: name.into(),
                    name: name.into(),
                    data_type: SqlType::I64,
                    nullable: false,
                })
                .collect(),
            rows: vec![vec![SqlValue::I64(Signed64(2)); 3]],
        });
        let sqlite = rusqlite::Connection::open_in_memory().unwrap();
        sqlite.execute_batch("CREATE TABLE vals(id INTEGER, \"true\" INTEGER, \"false\" INTEGER); INSERT INTO vals VALUES(2,2,2)").unwrap();
        let sql = "SELECT id IS TRUE,id IS NOT TRUE,id IS FALSE,id IS NOT FALSE FROM vals";
        let expected = sqlite
            .query_row(sql, [], |row| {
                (0..4)
                    .map(|i| row.get::<_, i64>(i))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap();
        assert_eq!(expected, [1, 0, 1, 0]);
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            assert_eq!(
                bridge.query(sql).unwrap_err().code,
                ErrorCode::UnsupportedQuery
            );
        }
    }

    #[test]
    fn boolean_tokens_respect_shadowing_in_general_expressions() {
        use mdd_query::ir::Signed64;
        let provider = Arc::new(RowsProvider {
            binding: SqlBinding {
                provider_identity: "general-boolean-shadow".into(),
                snapshot_id: "general-boolean-shadow-snapshot".into(),
                catalog_epoch: DecimalU64(0),
            },
            columns: vec![
                SqlColumn {
                    id: "id".into(),
                    name: "id".into(),
                    data_type: SqlType::I64,
                    nullable: false,
                },
                SqlColumn {
                    id: "true".into(),
                    name: "true".into(),
                    data_type: SqlType::I64,
                    nullable: false,
                },
            ],
            rows: vec![vec![SqlValue::I64(Signed64(0)), SqlValue::I64(Signed64(0))]],
        });
        let sqlite = rusqlite::Connection::open_in_memory().unwrap();
        sqlite
            .execute_batch(
                "CREATE TABLE vals(id INTEGER, \"true\" INTEGER); INSERT INTO vals VALUES (0,0);",
            )
            .unwrap();
        let sql = "SELECT id IN (TRUE,NULL) FROM vals";
        let expected: i64 = sqlite.query_row(sql, [], |row| row.get(0)).unwrap();
        assert_eq!(expected, 1);
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for query in [
                sql,
                "SELECT TRUE FROM vals",
                "SELECT id FROM vals WHERE id=TRUE",
                "SELECT id FROM vals ORDER BY TRUE",
                "WITH c AS (SELECT id AS \"true\" FROM vals) SELECT TRUE FROM c",
                "SELECT (SELECT TRUE) FROM vals",
                "SELECT (SELECT TRUE FROM (SELECT 1) AS d) FROM vals",
            ] {
                sqlite.prepare(query).unwrap();
                assert_eq!(
                    bridge.query(query).unwrap_err().code,
                    ErrorCode::UnsupportedQuery,
                    "{dialect:?}: {query}"
                );
            }
            assert_eq!(
                bridge
                    .query("SELECT missing.x, TRUE FROM vals")
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidArgument
            );
            let ordinary = bridge.query("SELECT TRUE,FALSE,0 IN (FALSE,NULL)").unwrap();
            assert_eq!(
                ordinary.rows()[0],
                vec![
                    SqlValue::I64(Signed64(1)),
                    SqlValue::I64(Signed64(0)),
                    SqlValue::I64(Signed64(1))
                ]
            );
        }
        let (unshadowed_provider, _) = bridge();
        sqlite
            .execute_batch("CREATE TABLE facts(id INTEGER); INSERT INTO facts VALUES(0)")
            .unwrap();
        let alias = "SELECT id AS \"true\" FROM facts WHERE id IN (TRUE,NULL)";
        assert_eq!(
            sqlite
                .prepare(alias)
                .unwrap()
                .query_map([], |row| row.get::<_, i64>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap(),
            vec![0]
        );
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge =
                SqlBridge::new(unshadowed_provider.clone(), dialect, SqlLimits::default()).unwrap();
            assert_eq!(
                bridge.query(alias).unwrap_err().code,
                ErrorCode::UnsupportedQuery
            );
        }
    }

    #[test]
    fn legacy_text_in_boolean_token_respects_column_shadowing() {
        use mdd_query::ir::Signed64;
        let provider = Arc::new(RowsProvider {
            binding: SqlBinding {
                provider_identity: "boolean-shadow".into(),
                snapshot_id: "boolean-shadow-snapshot".into(),
                catalog_epoch: DecimalU64(0),
            },
            columns: vec![
                SqlColumn {
                    id: "txt".into(),
                    name: "txt".into(),
                    data_type: SqlType::Text,
                    nullable: false,
                },
                SqlColumn {
                    id: "true".into(),
                    name: "true".into(),
                    data_type: SqlType::I64,
                    nullable: false,
                },
                SqlColumn {
                    id: "false".into(),
                    name: "false".into(),
                    data_type: SqlType::I64,
                    nullable: false,
                },
            ],
            rows: vec![vec![
                SqlValue::text("0"),
                SqlValue::I64(Signed64(0)),
                SqlValue::I64(Signed64(1)),
            ]],
        });
        let sqlite = rusqlite::Connection::open_in_memory().unwrap();
        sqlite.execute_batch("CREATE TABLE vals(txt TEXT, \"true\" INTEGER, \"false\" INTEGER); INSERT INTO vals VALUES ('0',0,1);").unwrap();
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for sql in [
                "SELECT txt IN (TRUE,NULL) FROM vals",
                "SELECT txt IN (FALSE,NULL) FROM vals",
                "SELECT a.txt IN (TRUE,NULL) FROM vals a",
                "WITH d AS (SELECT txt,\"true\" FROM vals) SELECT txt IN (TRUE,NULL) FROM d",
                "WITH c(v) AS (SELECT txt FROM vals) SELECT (SELECT v IN (TRUE,NULL) FROM c) FROM vals a",
                "SELECT (SELECT a.txt IN (TRUE,NULL) FROM (SELECT 1) AS d) FROM vals a",
            ] {
                sqlite.prepare(sql).unwrap();
                assert_eq!(
                    bridge.query(sql).unwrap_err().code,
                    ErrorCode::UnsupportedQuery,
                    "{dialect:?}: {sql}"
                );
            }
            let result = bridge.query("SELECT txt IN (0,NULL) FROM vals").unwrap();
            assert_eq!(result.rows()[0][0], SqlValue::I64(Signed64(1)));
            assert_eq!(
                bridge
                    .query("SELECT missing.txt IN (TRUE,NULL) FROM vals")
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidArgument
            );
        }
    }

    #[test]
    fn legacy_text_column_in_integer_literals_matches_sqlite_affinity() {
        use mdd_query::ir::Signed64;
        let values = [
            Some("1"),
            Some("01"),
            Some("-2"),
            Some("3"),
            Some("0"),
            Some("-9223372036854775808"),
            None,
            Some("1"),
        ];
        let provider = Arc::new(RowsProvider {
            binding: SqlBinding {
                provider_identity: "text-in-affinity".into(),
                snapshot_id: "text-in-affinity-snapshot".into(),
                catalog_epoch: DecimalU64(0),
            },
            columns: vec![
                SqlColumn {
                    id: "id".into(),
                    name: "id".into(),
                    data_type: SqlType::I64,
                    nullable: false,
                },
                SqlColumn {
                    id: "txt".into(),
                    name: "txt".into(),
                    data_type: SqlType::Text,
                    nullable: true,
                },
            ],
            rows: values
                .iter()
                .enumerate()
                .map(|(i, value)| {
                    vec![
                        SqlValue::I64(Signed64(i as i64)),
                        value.map_or(SqlValue::Null, SqlValue::text),
                    ]
                })
                .collect(),
        });
        let sqlite = rusqlite::Connection::open_in_memory().unwrap();
        sqlite
            .execute_batch("CREATE TABLE vals(id INTEGER, txt TEXT)")
            .unwrap();
        for (i, value) in values.iter().enumerate() {
            sqlite
                .execute(
                    "INSERT INTO vals VALUES (?1,?2)",
                    rusqlite::params![i as i64, value],
                )
                .unwrap();
        }
        let cases = [
            "SELECT txt IN (1,-2,+3,TRUE,NULL),txt NOT IN (1,-2,+3,TRUE,NULL) FROM vals ORDER BY id",
            "SELECT txt IN ('01',1,1,NULL),txt NOT IN (0,0) FROM vals ORDER BY id",
            "SELECT txt IN (-9223372036854775808,0),txt NOT IN (-9223372036854775808,0) FROM vals ORDER BY id",
            "WITH c(v,n) AS (SELECT txt,id FROM vals) SELECT v IN (1,-2),v NOT IN (1,NULL) FROM c ORDER BY n",
            "SELECT a.txt IN (1,2) FROM vals a WHERE EXISTS (SELECT 1 FROM vals b WHERE b.id=a.id) ORDER BY a.id",
        ];
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for sql in cases {
                let mut stmt = sqlite.prepare(sql).unwrap();
                let width = stmt.column_count();
                let expected = stmt
                    .query_map([], |row| {
                        (0..width)
                            .map(|i| row.get::<_, Option<i64>>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let actual = bridge
                    .query(sql)
                    .unwrap()
                    .rows()
                    .iter()
                    .map(|row| {
                        row.iter()
                            .map(|cell| match cell {
                                SqlValue::Null => None,
                                SqlValue::I64(value) => Some(value.0),
                                SqlValue::U64(value) => Some(i64::try_from(value.0).unwrap()),
                                value => panic!("unexpected {value:?}"),
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                assert_eq!(actual, expected, "{dialect:?}: {sql}");
            }
            // SQLite may resolve TRUE in WHERE to a SELECT alias, even when
            // no input column has that name. Do not substitute constant 1.
            let alias = "SELECT txt AS \"true\" FROM vals WHERE txt IN (TRUE,NULL)";
            let count: i64 = sqlite
                .query_row(&format!("SELECT COUNT(*) FROM ({alias})"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 7);
            assert_eq!(
                bridge.query(alias).unwrap_err().code,
                ErrorCode::UnsupportedQuery
            );
            for sql in [
                "SELECT txt IN (1.0) FROM vals",
                "SELECT txt IN (1e0) FROM vals",
                "SELECT txt IN (9223372036854775808) FROM vals",
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap_err().code,
                    ErrorCode::UnsupportedQuery,
                    "{sql}"
                );
            }
            assert_eq!(
                bridge
                    .query("SELECT missing IN (1) FROM vals")
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidArgument
            );
        }
        let native = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        assert_eq!(
            native
                .query("SELECT txt IN (1) FROM vals")
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedQuery
        );
    }

    #[test]
    fn ordered_distinct_limited_text_compares_sqlite_supplementary_order() {
        let values = ["\u{e000}", "\u{10000}"];
        let provider = Arc::new(RowsProvider {
            binding: SqlBinding {
                provider_identity: "ordered-distinct-text".into(),
                snapshot_id: "ordered-distinct-text-snapshot".into(),
                catalog_epoch: DecimalU64(0),
            },
            columns: vec![
                SqlColumn {
                    id: "lhs".into(),
                    name: "lhs".into(),
                    data_type: SqlType::Text,
                    nullable: false,
                },
                SqlColumn {
                    id: "rhs".into(),
                    name: "rhs".into(),
                    data_type: SqlType::Text,
                    nullable: false,
                },
            ],
            rows: values
                .iter()
                .map(|value| vec![SqlValue::text(value), SqlValue::text(value)])
                .collect(),
        });
        let sqlite = rusqlite::Connection::open_in_memory().unwrap();
        sqlite
            .execute_batch("CREATE TABLE vals(lhs TEXT,rhs TEXT);")
            .unwrap();
        for value in values {
            sqlite
                .execute("INSERT INTO vals VALUES (?1,?1)", [value])
                .unwrap();
        }
        let sql =
            "SELECT lhs,lhs IN (SELECT DISTINCT rhs FROM vals ORDER BY rhs LIMIT 1) FROM vals";
        let mut expected: Vec<(String, i64)> = sqlite
            .prepare(sql)
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        expected.sort();
        assert_eq!(
            expected,
            vec![("\u{e000}".into(), 1), ("\u{10000}".into(), 0)]
        );
        let native =
            SqlBridge::new(provider.clone(), SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        let mut actual: Vec<(String, i64)> = native
            .query(sql)
            .unwrap()
            .rows()
            .iter()
            .map(|row| match (&row[0], &row[1]) {
                (SqlValue::Text(text), SqlValue::I64(value)) => {
                    (text.strict_utf8().unwrap(), value.0)
                }
                _ => panic!("unexpected row: {row:?}"),
            })
            .collect();
        actual.sort();
        assert_eq!(
            actual,
            vec![("\u{e000}".into(), 0), ("\u{10000}".into(), 1)]
        );
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            assert_eq!(
                bridge.query(sql).unwrap_err().code,
                ErrorCode::UnsupportedQuery
            );
        }
    }

    #[test]
    fn in_subquery_same_typed_columns_preserves_null_duplicates_and_binding_errors() {
        use mdd_query::ir::Signed64;
        let pairs = [
            (None, Some(1)),
            (Some(1), Some(1)),
            (Some(2), None),
            (Some(2), Some(2)),
            (Some(3), Some(2)),
        ];
        let provider = Arc::new(RowsProvider {
            binding: SqlBinding {
                provider_identity: "in-subquery".into(),
                snapshot_id: "in-subquery-snapshot".into(),
                catalog_epoch: DecimalU64(0),
            },
            columns: vec![
                SqlColumn {
                    id: "lhs".into(),
                    name: "lhs".into(),
                    data_type: SqlType::I64,
                    nullable: true,
                },
                SqlColumn {
                    id: "rhs".into(),
                    name: "rhs".into(),
                    data_type: SqlType::I64,
                    nullable: true,
                },
                SqlColumn {
                    id: "txt".into(),
                    name: "txt".into(),
                    data_type: SqlType::Text,
                    nullable: false,
                },
            ],
            rows: pairs
                .into_iter()
                .map(|(a, b)| {
                    vec![
                        a.map_or(SqlValue::Null, |v| SqlValue::I64(Signed64(v))),
                        b.map_or(SqlValue::Null, |v| SqlValue::I64(Signed64(v))),
                        SqlValue::text("1"),
                    ]
                })
                .collect(),
        });
        let sqlite = rusqlite::Connection::open_in_memory().unwrap();
        sqlite.execute_batch("CREATE TABLE vals(lhs INTEGER,rhs INTEGER,txt TEXT); INSERT INTO vals VALUES(NULL,1,'1'),(1,1,'1'),(2,NULL,'1'),(2,2,'1'),(3,2,'1');").unwrap();
        let queries = [
            "SELECT lhs,lhs IN (SELECT rhs FROM vals),lhs NOT IN (SELECT rhs FROM vals) FROM vals ORDER BY lhs",
            "SELECT lhs,lhs IN (SELECT rhs FROM vals LIMIT 0),lhs NOT IN (SELECT rhs FROM vals LIMIT 0) FROM vals ORDER BY lhs",
            "SELECT a.lhs,a.lhs IN (SELECT b.rhs FROM vals b) FROM vals a ORDER BY a.lhs",
            "SELECT a.lhs,a.lhs IN (SELECT b.rhs FROM vals b WHERE b.rhs IS NOT NULL) FROM vals a ORDER BY a.lhs",
            "SELECT a.lhs,a.lhs IN (SELECT b.rhs FROM vals b WHERE b.rhs=a.lhs) FROM vals a ORDER BY a.lhs",
            "SELECT a.lhs,EXISTS (SELECT 1 FROM vals a WHERE a.lhs IN (SELECT c.rhs FROM vals c)) FROM vals a ORDER BY a.lhs",
            "SELECT lhs,lhs IN (SELECT DISTINCT rhs FROM vals),lhs NOT IN (SELECT DISTINCT rhs FROM vals) FROM vals ORDER BY lhs",
            "SELECT a.lhs,a.lhs IN (SELECT DISTINCT b.rhs FROM vals b WHERE b.rhs=a.lhs) FROM vals a ORDER BY a.lhs",
            "SELECT lhs,lhs IN (SELECT rhs FROM vals ORDER BY rhs DESC LIMIT 1),lhs NOT IN (SELECT rhs FROM vals ORDER BY rhs DESC LIMIT 1) FROM vals ORDER BY lhs",
            "SELECT lhs,lhs IN (SELECT rhs AS x FROM vals ORDER BY x LIMIT 2 OFFSET 1) FROM vals ORDER BY lhs",
            "SELECT lhs,lhs IN (SELECT rhs FROM vals ORDER BY 1 DESC LIMIT 1 OFFSET 1) FROM vals ORDER BY lhs",
            "SELECT a.lhs,a.lhs IN (SELECT b.rhs FROM vals b WHERE b.rhs<=a.lhs ORDER BY b.rhs DESC LIMIT 1 OFFSET 1) FROM vals a ORDER BY a.lhs",
            "SELECT lhs,lhs IN (SELECT DISTINCT rhs FROM vals ORDER BY rhs DESC),lhs NOT IN (SELECT DISTINCT rhs FROM vals ORDER BY rhs DESC) FROM vals ORDER BY lhs",
            "SELECT lhs,lhs IN (SELECT DISTINCT rhs FROM vals ORDER BY rhs LIMIT 1),lhs NOT IN (SELECT DISTINCT rhs FROM vals ORDER BY rhs LIMIT 1) FROM vals ORDER BY lhs",
            "SELECT lhs,lhs IN (SELECT DISTINCT rhs FROM vals ORDER BY rhs DESC LIMIT 1 OFFSET 1) FROM vals ORDER BY lhs",
            "SELECT lhs,lhs IN (SELECT DISTINCT rhs AS x FROM vals ORDER BY x DESC LIMIT 2 OFFSET 1) FROM vals ORDER BY lhs",
            "SELECT lhs,lhs IN (SELECT DISTINCT rhs AS lhs FROM vals ORDER BY lhs DESC LIMIT 1 OFFSET 1) FROM vals ORDER BY lhs",
            "SELECT lhs,lhs IN (SELECT DISTINCT rhs FROM vals ORDER BY 1 ASC NULLS LAST LIMIT 2 OFFSET 1) FROM vals ORDER BY lhs",
            "SELECT a.lhs,a.lhs IN (SELECT DISTINCT b.rhs FROM vals b WHERE b.rhs<=a.lhs ORDER BY b.rhs DESC LIMIT 1) FROM vals a ORDER BY a.lhs",
            "SELECT lhs,lhs IN (SELECT DISTINCT rhs FROM vals ORDER BY rhs LIMIT 0),lhs NOT IN (SELECT DISTINCT rhs FROM vals ORDER BY rhs LIMIT 0) FROM vals ORDER BY lhs",
            "WITH d AS (SELECT rhs FROM vals) SELECT lhs,lhs IN (SELECT rhs FROM d),lhs NOT IN (SELECT rhs FROM d) FROM vals ORDER BY lhs",
            "WITH d AS (SELECT lhs,rhs FROM vals) SELECT lhs,lhs IN (SELECT DISTINCT rhs FROM d ORDER BY rhs DESC LIMIT 1 OFFSET 1) FROM d ORDER BY lhs",
            "WITH d(a,b) AS (SELECT rhs,lhs FROM vals) SELECT b,b IN (SELECT a FROM d) FROM d ORDER BY b",
            "WITH d(a,b) AS (SELECT rhs,lhs FROM vals) SELECT v.lhs,v.lhs IN (SELECT d.a FROM d WHERE d.b=v.lhs) FROM vals v ORDER BY v.lhs",
            "WITH d AS (SELECT lhs AS rhs,rhs AS lhs FROM vals) SELECT d.lhs,d.lhs IN (SELECT v.rhs FROM vals v) FROM d ORDER BY d.lhs",
            "WITH d AS (SELECT rhs AS x FROM vals) SELECT lhs,lhs IN (SELECT x FROM d WHERE EXISTS (WITH d AS (SELECT lhs AS x FROM vals) SELECT 1 FROM d WHERE d.x=1)) FROM vals ORDER BY lhs",
        ];
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for sql in queries {
                let mut statement = sqlite.prepare(sql).unwrap();
                let width = statement.column_count();
                let expected = statement
                    .query_map([], |row| {
                        (0..width)
                            .map(|i| row.get::<_, Option<i64>>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let actual = bridge
                    .query(sql)
                    .unwrap()
                    .rows()
                    .iter()
                    .map(|row| {
                        row.iter()
                            .map(|value| match value {
                                SqlValue::Null => None,
                                SqlValue::I64(v) => Some(v.0),
                                _ => panic!("unexpected SQL cell: {value:?}"),
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                assert_eq!(actual, expected, "{dialect:?}: {sql}");
            }
            for sql in [
                "SELECT lhs IN (SELECT missing FROM vals) FROM vals",
                "SELECT lhs IN (SELECT rhs FROM absent) FROM vals",
                "SELECT lhs IN (SELECT DISTINCT missing FROM vals) FROM vals",
                "SELECT lhs IN (SELECT DISTINCT rhs FROM vals ORDER BY missing LIMIT 1) FROM vals",
                "SELECT lhs IN (SELECT rhs FROM vals ORDER BY missing LIMIT 1) FROM vals",
                "WITH d AS (SELECT rhs FROM vals) SELECT lhs IN (SELECT missing FROM d) FROM vals",
                "WITH d AS (SELECT rhs FROM vals) SELECT lhs IN (SELECT missing.rhs FROM d) FROM vals",
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap_err().code,
                    ErrorCode::InvalidArgument,
                    "{dialect:?}: {sql}"
                );
            }
            assert_eq!(
                bridge
                    .query("SELECT lhs IN (SELECT txt FROM vals) FROM vals")
                    .unwrap_err()
                    .code,
                ErrorCode::UnsupportedQuery
            );
            for sql in [
                "WITH vals(lhs,rhs) AS (SELECT 1,1) SELECT lhs IN (SELECT rhs FROM vals) FROM vals",
                "WITH d(x,x) AS (SELECT rhs,txt FROM vals) SELECT lhs IN (SELECT x FROM d) FROM vals",
            ] {
                assert!(sqlite.prepare(sql).is_ok(), "SQLite rejected: {sql}");
            }
            for sql in [
                "SELECT lhs IN (SELECT DISTINCT rhs FROM vals LIMIT 1) FROM vals",
                "SELECT lhs IN (SELECT DISTINCT rhs FROM vals ORDER BY lhs LIMIT 1) FROM vals",
                "SELECT lhs IN (SELECT DISTINCT rhs FROM vals ORDER BY rhs,lhs LIMIT 1) FROM vals",
                "SELECT lhs IN (SELECT DISTINCT txt FROM vals ORDER BY txt LIMIT 1) FROM vals",
                "WITH d AS (SELECT rhs+0 AS x FROM vals) SELECT lhs IN (SELECT DISTINCT x FROM d ORDER BY x LIMIT 1) FROM vals",
                "WITH d AS (SELECT rhs+0 AS x FROM vals) SELECT lhs IN (SELECT x FROM d) FROM vals",
                "WITH vals(lhs,rhs) AS (SELECT 1,1) SELECT lhs IN (SELECT rhs FROM vals) FROM vals",
                "WITH d(x,x) AS (SELECT rhs,txt FROM vals) SELECT lhs IN (SELECT x FROM d) FROM vals",
                "SELECT lhs IN (WITH d AS (SELECT rhs FROM vals) SELECT rhs FROM d) FROM vals",
                "SELECT lhs IN (SELECT rhs FROM (WITH d AS (SELECT rhs FROM vals) SELECT rhs FROM d) AS z) FROM vals",
                "SELECT lhs IN (SELECT n FROM (WITH d AS (SELECT rhs FROM vals) SELECT COUNT(*) AS n FROM d) AS z) FROM vals",
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap_err().code,
                    ErrorCode::UnsupportedQuery,
                    "{dialect:?}: {sql}"
                );
            }
            assert_eq!(bridge.query("SELECT lhs IN (WITH d AS (SELECT missing FROM vals) SELECT rhs FROM d) FROM vals").unwrap_err().code,
                       ErrorCode::InvalidArgument, "{dialect:?}");
            assert_eq!(bridge.query("SELECT lhs IN (SELECT n FROM (WITH d AS (SELECT missing FROM vals) SELECT COUNT(*) AS n FROM d) AS z) FROM vals").unwrap_err().code,
                       ErrorCode::InvalidArgument, "{dialect:?}");
        }
        let numeric = numeric_bridge();
        let text = |units: Vec<u16>| {
            SqlValue::Text(crate::values::SqlText {
                utf16: units,
                original_mutf8: None,
            })
        };
        let text_provider = Arc::new(RowsProvider {
            binding: SqlBinding {
                provider_identity: "in-text".into(),
                snapshot_id: "in-text-snapshot".into(),
                catalog_epoch: DecimalU64(0),
            },
            columns: vec![
                SqlColumn {
                    id: "l".into(),
                    name: "l".into(),
                    data_type: SqlType::Text,
                    nullable: true,
                },
                SqlColumn {
                    id: "r".into(),
                    name: "r".into(),
                    data_type: SqlType::Text,
                    nullable: true,
                },
            ],
            rows: vec![
                vec![SqlValue::Null, SqlValue::Null],
                vec![text(vec![65, 0, 66]), text(vec![65, 0, 66])],
                vec![text(vec![0xd800]), text(vec![0xd800])],
                vec![text(vec![65, 0, 66]), SqlValue::text("q")],
                vec![SqlValue::text("Q"), SqlValue::text("q")],
            ],
        });
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge =
                SqlBridge::new(numeric.provider.clone(), dialect, SqlLimits::default()).unwrap();
            let rows = bridge
                .query("SELECT u IN (SELECT u FROM vals),u NOT IN (SELECT u FROM vals) FROM vals")
                .unwrap();
            let cte_rows = bridge
                .query("WITH d(v) AS (SELECT u FROM vals) SELECT u IN (SELECT v FROM d),u NOT IN (SELECT v FROM d) FROM vals")
                .unwrap();
            assert_eq!(cte_rows.rows(), rows.rows());
            let distinct = bridge
                .query("SELECT u IN (SELECT DISTINCT u FROM vals),u NOT IN (SELECT DISTINCT u FROM vals) FROM vals")
                .unwrap();
            assert_eq!(rows.rows(), distinct.rows());
            assert_eq!(rows.rows().len(), 7);
            assert!(
                rows.rows()
                    .iter()
                    .all(|row| row == &[SqlValue::I64(Signed64(1)), SqlValue::I64(Signed64(0))])
            );
            let ordered = bridge
                .query("SELECT u,u IN (SELECT u FROM vals ORDER BY u DESC LIMIT 1 OFFSET 1) FROM vals ORDER BY u")
                .unwrap();
            assert_eq!(ordered.rows().len(), 7);
            for row in ordered.rows() {
                let SqlValue::U64(DecimalU64(value)) = row[0] else {
                    panic!("unexpected unsigned value: {row:?}");
                };
                assert_eq!(
                    row[1],
                    SqlValue::I64(Signed64(i64::from(value == (1u64 << 63))))
                );
            }
            assert_eq!(
                bridge
                    .query("SELECT u IN (SELECT f FROM vals) FROM vals")
                    .unwrap_err()
                    .code,
                ErrorCode::UnsupportedQuery
            );
            let bridge =
                SqlBridge::new(text_provider.clone(), dialect, SqlLimits::default()).unwrap();
            let rows = bridge
                .query("SELECT l IN (SELECT r FROM vals) FROM vals ORDER BY l")
                .unwrap();
            let distinct = bridge
                .query("SELECT l IN (SELECT DISTINCT r FROM vals) FROM vals ORDER BY l")
                .unwrap();
            assert_eq!(rows.rows(), distinct.rows());
            assert_eq!(
                rows.rows(),
                &[
                    vec![SqlValue::Null],
                    vec![SqlValue::I64(Signed64(1))],
                    vec![SqlValue::I64(Signed64(1))],
                    vec![SqlValue::Null],
                    vec![SqlValue::I64(Signed64(1))],
                ]
            );
            let ordered = bridge
                .query(
                    "SELECT l IN (SELECT r FROM vals ORDER BY r DESC LIMIT 1) FROM vals ORDER BY l",
                )
                .unwrap();
            assert_eq!(
                ordered.rows(),
                &[
                    vec![SqlValue::Null],
                    vec![SqlValue::I64(Signed64(0))],
                    vec![SqlValue::I64(Signed64(0))],
                    vec![SqlValue::I64(Signed64(0))],
                    vec![SqlValue::I64(Signed64(1))],
                ]
            );
            let plain = bridge.query("SELECT l IN (SELECT r FROM vals),l NOT IN (SELECT r FROM vals) FROM vals ORDER BY l").unwrap();
            let cte = bridge.query("WITH d(v) AS (SELECT r FROM vals) SELECT l IN (SELECT v FROM d),l NOT IN (SELECT v FROM d) FROM vals ORDER BY l").unwrap();
            assert_eq!(cte.rows(), plain.rows());
        }
    }
    #[test]
    fn mixed_integral_in_subquery_uses_exact_numeric_keys() {
        use mdd_query::ir::Signed64;
        let provider = Arc::new(RowsProvider {
            binding: SqlBinding {
                provider_identity: "mixed-integral-in".into(),
                snapshot_id: "mixed-integral-snapshot".into(),
                catalog_epoch: DecimalU64(0),
            },
            columns: [
                ("id", SqlType::I64, false),
                ("i", SqlType::I64, true),
                ("u", SqlType::U64, true),
                ("b", SqlType::Bool, true),
            ]
            .into_iter()
            .map(|(name, data_type, nullable)| SqlColumn {
                id: name.into(),
                name: name.into(),
                data_type,
                nullable,
            })
            .collect(),
            rows: vec![
                vec![
                    SqlValue::I64(Signed64(0)),
                    SqlValue::I64(Signed64(-1)),
                    SqlValue::U64(DecimalU64(0)),
                    SqlValue::Bool(false),
                ],
                vec![
                    SqlValue::I64(Signed64(1)),
                    SqlValue::I64(Signed64(0)),
                    SqlValue::U64(DecimalU64(1)),
                    SqlValue::Bool(true),
                ],
                vec![
                    SqlValue::I64(Signed64(2)),
                    SqlValue::I64(Signed64(1)),
                    SqlValue::U64(DecimalU64(2)),
                    SqlValue::Null,
                ],
                vec![
                    SqlValue::I64(Signed64(3)),
                    SqlValue::I64(Signed64(2)),
                    SqlValue::U64(DecimalU64(i64::MAX as u64)),
                    SqlValue::Bool(false),
                ],
                vec![
                    SqlValue::I64(Signed64(4)),
                    SqlValue::I64(Signed64(i64::MAX)),
                    SqlValue::Null,
                    SqlValue::Bool(true),
                ],
                vec![
                    SqlValue::I64(Signed64(5)),
                    SqlValue::Null,
                    SqlValue::U64(DecimalU64(1u64 << 63)),
                    SqlValue::Null,
                ],
                vec![
                    SqlValue::I64(Signed64(6)),
                    SqlValue::I64(Signed64(1)),
                    SqlValue::U64(DecimalU64(u64::MAX)),
                    SqlValue::Bool(true),
                ],
            ],
        });
        // SQLite's native INTEGER covers only the signed range. Exclude the
        // last two rows here; wider U64 semantics are checked separately.
        let sqlite = rusqlite::Connection::open_in_memory().unwrap();
        sqlite.execute_batch("CREATE TABLE vals(id INTEGER,i INTEGER,u INTEGER,b INTEGER); INSERT INTO vals VALUES(0,-1,0,0),(1,0,1,1),(2,1,2,NULL),(3,2,9223372036854775807,0),(4,9223372036854775807,NULL,1);").unwrap();
        let queries = [
            "SELECT id,i IN (SELECT u FROM vals WHERE id<5),i NOT IN (SELECT u FROM vals WHERE id<5) FROM vals WHERE id<5 ORDER BY id",
            "SELECT id,u IN (SELECT i FROM vals WHERE id<5),u NOT IN (SELECT i FROM vals WHERE id<5) FROM vals WHERE id<5 ORDER BY id",
            "SELECT id,b IN (SELECT i FROM vals WHERE id<5),i IN (SELECT b FROM vals WHERE id<5) FROM vals WHERE id<5 ORDER BY id",
            "SELECT id,u IN (SELECT b FROM vals WHERE id<5),b NOT IN (SELECT u FROM vals WHERE id<5) FROM vals WHERE id<5 ORDER BY id",
            "SELECT a.id,a.i IN (SELECT b.u FROM vals b WHERE b.id=a.id) FROM vals a WHERE a.id<5 ORDER BY a.id",
            "SELECT id,i IN (SELECT b FROM vals WHERE id<5 ORDER BY b DESC LIMIT 2),i NOT IN (SELECT b FROM vals WHERE id<5 ORDER BY b DESC LIMIT 2) FROM vals WHERE id<5 ORDER BY id",
            "WITH d(v) AS (SELECT b FROM vals WHERE id<5) SELECT id,i IN (SELECT v FROM d) FROM vals WHERE id<5 ORDER BY id",
            "SELECT id,i IN (SELECT u FROM vals WHERE id<0),i NOT IN (SELECT u FROM vals WHERE id<0) FROM vals WHERE id<5 ORDER BY id",
        ];
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for sql in queries {
                let mut stmt = sqlite.prepare(sql).unwrap();
                let width = stmt.column_count();
                let expected = stmt
                    .query_map([], |row| {
                        (0..width)
                            .map(|i| row.get::<_, Option<i64>>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let actual: Vec<Vec<Option<i64>>> = bridge
                    .query(sql)
                    .unwrap()
                    .rows()
                    .iter()
                    .map(|row| {
                        row.iter()
                            .map(|value| match value {
                                SqlValue::Null => None,
                                SqlValue::I64(value) => Some(value.0),
                                value => panic!("unexpected result: {value:?}"),
                            })
                            .collect()
                    })
                    .collect();
                assert_eq!(actual, expected, "{dialect:?}: {sql}");
            }
            for (sql, expected) in [
                (
                    "SELECT i IN (SELECT u FROM vals WHERE id=5) FROM vals WHERE id=4",
                    0,
                ),
                (
                    "SELECT u IN (SELECT i FROM vals WHERE id=4) FROM vals WHERE id=5",
                    0,
                ),
                (
                    "SELECT u IN (SELECT i FROM vals WHERE id=4) FROM vals WHERE id=3",
                    1,
                ),
                (
                    "SELECT u IN (SELECT i FROM vals WHERE id=0) FROM vals WHERE id=6",
                    0,
                ),
                (
                    "SELECT u IN (SELECT b FROM vals WHERE id<5 AND b IS NOT NULL) FROM vals WHERE id=6",
                    0,
                ),
            ] {
                assert_eq!(
                    bridge.query(sql).unwrap().rows(),
                    &[vec![SqlValue::I64(Signed64(expected))]],
                    "{dialect:?}: {sql}"
                );
            }
        }
    }

    #[test]
    fn order_in_subquery_respects_current_scope_and_unknown_shadow() {
        use mdd_query::ir::Signed64;
        let provider = Arc::new(RowsProvider {
            binding: SqlBinding {
                provider_identity: "order-scope".into(),
                snapshot_id: "order-scope-snapshot".into(),
                catalog_epoch: DecimalU64(0),
            },
            columns: vec![
                SqlColumn {
                    id: "lhs".into(),
                    name: "lhs".into(),
                    data_type: SqlType::I64,
                    nullable: false,
                },
                SqlColumn {
                    id: "rhs".into(),
                    name: "rhs".into(),
                    data_type: SqlType::I64,
                    nullable: false,
                },
                SqlColumn {
                    id: "txt".into(),
                    name: "txt".into(),
                    data_type: SqlType::Text,
                    nullable: false,
                },
            ],
            rows: vec![
                vec![
                    SqlValue::I64(Signed64(0)),
                    SqlValue::I64(Signed64(1)),
                    SqlValue::text("0"),
                ],
                vec![
                    SqlValue::I64(Signed64(1)),
                    SqlValue::I64(Signed64(1)),
                    SqlValue::text("1"),
                ],
            ],
        });
        let sqlite = rusqlite::Connection::open_in_memory().unwrap();
        sqlite.execute_batch("CREATE TABLE vals(lhs INTEGER,rhs INTEGER,txt TEXT); INSERT INTO vals VALUES(0,1,'0'),(1,1,'1');").unwrap();
        let shadow = "SELECT (WITH d AS (SELECT txt AS lhs FROM vals) SELECT lhs FROM d ORDER BY lhs IN (SELECT rhs FROM vals) DESC, lhs ASC LIMIT 1) FROM vals LIMIT 1";
        let expected: String = sqlite.query_row(shadow, [], |row| row.get(0)).unwrap();
        assert_eq!(expected, "1");
        let alias_shadow = "SELECT txt AS lhs FROM vals ORDER BY lhs IN (SELECT rhs FROM vals) DESC, txt ASC LIMIT 1";
        let expected: String = sqlite
            .query_row(alias_shadow, [], |row| row.get(0))
            .unwrap();
        assert_eq!(expected, "1");
        let valid =
            "SELECT txt FROM vals ORDER BY vals.lhs IN (SELECT rhs FROM vals) DESC, vals.lhs";
        let expected: Vec<String> = sqlite
            .prepare(valid)
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            assert_eq!(
                bridge.query(shadow).unwrap_err().code,
                ErrorCode::UnsupportedQuery
            );
            assert_eq!(
                bridge.query(alias_shadow).unwrap_err().code,
                ErrorCode::UnsupportedQuery
            );
            let actual: Vec<String> = bridge
                .query(valid)
                .unwrap()
                .rows()
                .iter()
                .map(|row| match &row[0] {
                    SqlValue::Text(value) => value.strict_utf8().unwrap(),
                    value => panic!("unexpected value: {value:?}"),
                })
                .collect();
            assert_eq!(actual, expected, "{dialect:?}");
        }
    }
    #[test]
    fn in_subquery_bytes_and_bool_match_sqlite_with_null_and_duplicates() {
        use mdd_query::ir::Signed64;
        let values: Vec<(Option<Vec<u8>>, Option<Vec<u8>>, Option<bool>, Option<bool>)> = vec![
            (None, None, None, None),
            (Some(vec![]), Some(vec![0]), Some(false), Some(true)),
            (Some(vec![0]), Some(vec![]), Some(true), Some(false)),
            (Some(vec![0]), Some(vec![0]), Some(true), Some(true)),
            (
                Some(vec![0xc0, 0x80]),
                Some(vec![0xc0, 0x80]),
                Some(false),
                Some(false),
            ),
            (Some(vec![0xff]), None, None, Some(false)),
        ];
        let sqlite = rusqlite::Connection::open_in_memory().unwrap();
        sqlite
            .execute_batch("CREATE TABLE vals(id INTEGER,l BLOB,r BLOB,bl INTEGER,br INTEGER)")
            .unwrap();
        let columns = [
            ("id", SqlType::I64),
            ("l", SqlType::Bytes),
            ("r", SqlType::Bytes),
            ("bl", SqlType::Bool),
            ("br", SqlType::Bool),
        ]
        .into_iter()
        .map(|(name, data_type)| SqlColumn {
            id: name.into(),
            name: name.into(),
            data_type,
            nullable: name != "id",
        })
        .collect();
        let mut rows = Vec::new();
        for (id, (l, r, bl, br)) in values.iter().enumerate() {
            sqlite
                .execute(
                    "INSERT INTO vals VALUES (?1,?2,?3,?4,?5)",
                    rusqlite::params![id as i64, l, r, bl, br],
                )
                .unwrap();
            let left = if id == 4 {
                SqlValue::DexMutf8 {
                    bytes: vec![0xc0, 0x80],
                    utf16_code_units: DecimalU64(1),
                }
            } else {
                l.clone().map_or(SqlValue::Null, SqlValue::Bytes)
            };
            rows.push(vec![
                SqlValue::I64(Signed64(id as i64)),
                left,
                r.clone().map_or(SqlValue::Null, SqlValue::Bytes),
                bl.map_or(SqlValue::Null, SqlValue::Bool),
                br.map_or(SqlValue::Null, SqlValue::Bool),
            ]);
        }
        let provider = Arc::new(RowsProvider {
            binding: SqlBinding {
                provider_identity: "in-bytes-bool".into(),
                snapshot_id: "in-bytes-bool-snapshot".into(),
                catalog_epoch: DecimalU64(0),
            },
            columns,
            rows,
        });
        let queries = [
            "SELECT id,l IN (SELECT r FROM vals),l NOT IN (SELECT r FROM vals) FROM vals ORDER BY id",
            "SELECT id,bl IN (SELECT br FROM vals),bl NOT IN (SELECT br FROM vals) FROM vals ORDER BY id",
            "SELECT id,l IN (SELECT DISTINCT r FROM vals),bl NOT IN (SELECT DISTINCT br FROM vals) FROM vals ORDER BY id",
            "SELECT id,l IN (SELECT DISTINCT r FROM vals ORDER BY r DESC LIMIT 2 OFFSET 1),bl NOT IN (SELECT DISTINCT br FROM vals ORDER BY br ASC LIMIT 2 OFFSET 1) FROM vals ORDER BY id",
            "SELECT id,l NOT IN (SELECT DISTINCT r FROM vals ORDER BY 1 ASC NULLS LAST LIMIT 1),bl IN (SELECT DISTINCT br FROM vals ORDER BY br DESC LIMIT 1) FROM vals ORDER BY id",
            "SELECT id,l IN (SELECT r FROM vals LIMIT 0),bl NOT IN (SELECT br FROM vals LIMIT 0) FROM vals ORDER BY id",
            "SELECT a.id,a.l IN (SELECT b.r FROM vals b WHERE b.id=a.id),a.bl IN (SELECT b.br FROM vals b WHERE b.id=a.id) FROM vals a ORDER BY a.id",
            "SELECT a.id,a.l IN (SELECT b.r FROM vals b WHERE b.r IS NOT NULL),a.bl NOT IN (SELECT b.br FROM vals b WHERE b.br IS NOT NULL) FROM vals a ORDER BY a.id",
        ];
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for sql in queries {
                let expected = sqlite
                    .prepare(sql)
                    .unwrap()
                    .query_map([], |row| {
                        (0..3)
                            .map(|i| row.get::<_, Option<i64>>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let result = bridge.query(sql).unwrap();
                let actual: Vec<Vec<Option<i64>>> = result
                    .rows()
                    .iter()
                    .map(|row| {
                        row.iter()
                            .map(|cell| match cell {
                                SqlValue::Null => None,
                                SqlValue::I64(v) => Some(v.0),
                                _ => panic!("unexpected cell: {cell:?}"),
                            })
                            .collect()
                    })
                    .collect();
                assert_eq!(actual, expected, "{dialect:?}: {sql}");
            }
            assert_eq!(
                bridge
                    .query("SELECT l IN (SELECT br FROM vals) FROM vals")
                    .unwrap_err()
                    .code,
                ErrorCode::UnsupportedQuery
            );
            assert_eq!(
                bridge
                    .query("SELECT l IN (SELECT missing FROM vals) FROM vals")
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidArgument
            );
        }
    }

    fn numeric_bridge() -> SqlBridge {
        let unsigned = [
            1,
            i64::MAX as u64,
            (i64::MAX as u64) + 1,
            u64::MAX,
            (1u64 << 53) + 1,
            1u64 << 53,
            0,
        ];
        let floats = [
            Some((-2.0f64).to_bits()),
            Some(f64::NEG_INFINITY.to_bits()),
            Some(0.0f64.to_bits()),
            Some((-0.0f64).to_bits()),
            Some(0x7ff8000000000042),
            Some(f64::INFINITY.to_bits()),
            None,
        ];
        let rows = unsigned
            .into_iter()
            .zip(floats)
            .map(|(u, f)| {
                vec![
                    SqlValue::U64(DecimalU64(u)),
                    f.map_or(SqlValue::Null, |bits| SqlValue::F64(DecimalU64(bits))),
                ]
            })
            .collect();
        let provider = Arc::new(RowsProvider {
            binding: SqlBinding {
                provider_identity: "numeric-hand-vectors".into(),
                snapshot_id: "numeric-test-scope".into(),
                catalog_epoch: DecimalU64(0),
            },
            rows,
            columns: vec![
                SqlColumn {
                    id: "u".into(),
                    name: "u".into(),
                    data_type: SqlType::U64,
                    nullable: false,
                },
                SqlColumn {
                    id: "f".into(),
                    name: "f".into(),
                    data_type: SqlType::F64,
                    nullable: true,
                },
            ],
        });
        SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap()
    }
    #[test]
    fn native_u64_direct_case_union_and_numeric_edges_remain_lossless() {
        let bridge = numeric_bridge();
        for sql in [
            "SELECT u FROM vals ORDER BY u",
            "SELECT u FROM vals ORDER BY 1",
        ] {
            let rows = bridge.query(sql).unwrap().rows;
            let actual = rows
                .into_iter()
                .map(|row| {
                    if let SqlValue::U64(v) = row[0] {
                        v.0
                    } else {
                        panic!("U64 logical type lost")
                    }
                })
                .collect::<Vec<_>>();
            assert_eq!(
                actual,
                vec![
                    0,
                    1,
                    1u64 << 53,
                    (1u64 << 53) + 1,
                    i64::MAX as u64,
                    (i64::MAX as u64) + 1,
                    u64::MAX
                ]
            );
        }
        let rows=bridge.query("SELECT CASE WHEN u>0 THEN u ELSE CAST(0 AS UNSIGNED) END AS c FROM vals ORDER BY u").unwrap().rows;
        assert!(rows.iter().all(|row| matches!(row[0], SqlValue::U64(_))));
        let result=bridge.query("SELECT CAST(18446744073709551615 AS UNSIGNED) AS u UNION ALL SELECT CAST(1 AS UNSIGNED) AS u ORDER BY u").unwrap();
        assert_eq!(
            result.rows,
            vec![
                vec![SqlValue::U64(DecimalU64(1))],
                vec![SqlValue::U64(DecimalU64(u64::MAX))]
            ]
        );
        let result=bridge.query("SELECT u=9007199254740992.0 AS eq,u IN (9007199254740992.0) AS member FROM vals WHERE u=9007199254740993").unwrap();
        assert_eq!(
            result.rows,
            vec![vec![
                SqlValue::I64(mdd_query::ir::Signed64(0)),
                SqlValue::I64(mdd_query::ir::Signed64(0))
            ]]
        );
        let count = bridge.query("SELECT COUNT(*) AS n FROM vals").unwrap();
        assert_eq!(
            count.rows,
            vec![vec![SqlValue::I64(mdd_query::ir::Signed64(7))]]
        );
    }
    #[test]
    fn f64_sort_group_distinct_and_aggregates_do_not_use_blob_bit_order() {
        let bridge = numeric_bridge();
        let result = bridge.query("SELECT f FROM vals ORDER BY f").unwrap();
        assert_eq!(result.rows[0], vec![SqlValue::Null]);
        assert_eq!(
            result.rows[1],
            vec![SqlValue::F64(DecimalU64(f64::NEG_INFINITY.to_bits()))]
        );
        assert_eq!(
            result.rows[2],
            vec![SqlValue::F64(DecimalU64((-2.0f64).to_bits()))]
        );
        assert_eq!(
            result.rows.last().unwrap(),
            &vec![SqlValue::F64(DecimalU64(0x7ff8000000000042))]
        );
        let count = bridge
            .query("SELECT COUNT(DISTINCT f) AS n FROM vals")
            .unwrap();
        assert_eq!(
            count.rows,
            vec![vec![SqlValue::I64(mdd_query::ir::Signed64(5))]]
        );
        let rows = bridge
            .query("SELECT DISTINCT f FROM vals ORDER BY f")
            .unwrap()
            .rows;
        assert_eq!(rows.len(), 6);
        let result = bridge
            .query("SELECT MIN(f) AS lo,MAX(f) AS hi FROM vals")
            .unwrap();
        assert_eq!(
            result.rows[0],
            vec![
                SqlValue::F64(DecimalU64(f64::NEG_INFINITY.to_bits())),
                SqlValue::F64(DecimalU64(0x7ff8000000000042))
            ]
        );
    }
    #[test]
    fn legacy_concat_matches_fixed_engine_observations() {
        let (provider, _) = bridge();
        let cases = [
            (
                "SELECT x'410042'||x'43',hex(x'410042'||x'43')",
                Some("A\0BC"),
                "41C0804243",
            ),
            (
                "SELECT x'C3'||x'A9',hex(x'C3'||x'A9')",
                Some("��"),
                "EFBFBDEFBFBD",
            ),
            (
                "SELECT x'F09F'||x'9880',hex(x'F09F'||x'9880')",
                Some("���"),
                "EFBFBDEFBFBDEFBFBD",
            ),
            (
                "SELECT x'E282'||x'41',hex(x'E282'||x'41')",
                Some("�A"),
                "EFBFBD41",
            ),
            (
                "SELECT x'C080'||x'41',hex(x'C080'||x'41')",
                Some("��A"),
                "EFBFBDEFBFBD41",
            ),
            ("SELECT x'41'||'B',hex(x'41'||'B')", Some("AB"), "4142"),
            ("SELECT 'B'||x'41',hex('B'||x'41')", Some("BA"), "4241"),
            ("SELECT NULL||x'41',hex(NULL||x'41')", None, ""),
        ];
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            for (sql, text, bytes) in cases {
                assert_eq!(
                    bridge.query(sql).unwrap().rows()[0],
                    vec![
                        text.map_or(SqlValue::Null, SqlValue::text),
                        SqlValue::text(bytes)
                    ],
                    "{dialect:?}: {sql}"
                );
            }
            let source = SqlValue::DexMutf8 {
                bytes: vec![0xed, 0xa0, 0x80],
                utf16_code_units: DecimalU64(1),
            };
            let prepared = bridge
                .prepare_with_parameters("SELECT ?||x'41'", &[source])
                .unwrap();
            let output = bridge
                .execute(&prepared, SqlControl::new(SqlLimits::default(), None))
                .unwrap();
            assert_eq!(
                output.rows()[0][0],
                SqlValue::Text(crate::values::SqlText {
                    utf16: vec![0xd800, 65],
                    original_mutf8: None
                })
            );
        }
    }

    #[test]
    fn legacy_concat_bridge_budget_and_cancellation_are_errors() {
        let (provider, _) = bridge();
        for dialect in [SqlDialect::DexSql010, SqlDialect::DexSql011] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            let prepared = bridge
                .prepare_with_parameters(
                    "SELECT ?||?",
                    &[SqlValue::Bytes(vec![b'a'; 1000]), SqlValue::text("b")],
                )
                .unwrap();
            let low = SqlControl::new(
                SqlLimits {
                    max_steps: 32,
                    ..SqlLimits::default()
                },
                None,
            );
            assert_eq!(
                bridge.execute(&prepared, low).unwrap_err().code,
                ErrorCode::QuotaExceeded
            );
            let cancelled = SqlControl::new(SqlLimits::default(), None);
            cancelled.cancel().unwrap();
            assert_eq!(
                bridge.execute(&prepared, cancelled).unwrap_err().code,
                ErrorCode::Cancelled
            );
            let small = bridge
                .prepare_with_parameters(
                    "SELECT ?||?",
                    &[SqlValue::Bytes(vec![b'a'; 2]), SqlValue::text("bc")],
                )
                .unwrap();
            let cell = SqlControl::new(
                SqlLimits {
                    max_cell_bytes: 6,
                    ..SqlLimits::default()
                },
                None,
            );
            assert_eq!(
                bridge.execute(&small, cell).unwrap_err().code,
                ErrorCode::QuotaExceeded
            );
        }
    }

    #[test]
    fn blob_magic_is_never_an_internal_text_and_controls_cannot_be_rebound() {
        let (_, bridge) = bridge();
        let expected = vec![0, 77, 68, 68, 84, 69, 88, 84, 49, 0, 65];
        let rows = bridge
            .query("SELECT X'004D444454455854310041' AS b")
            .unwrap()
            .rows;
        assert_eq!(rows[0][0], SqlValue::Bytes(expected.clone()));
        let rows=bridge.query("WITH x AS (SELECT X'004D4444'||X'54455854310041' AS b) SELECT CASE WHEN 1 THEN b ELSE X'00' END AS b FROM x").unwrap().rows;
        assert_eq!(rows[0][0], SqlValue::Bytes(expected));
        let rows = bridge
            .query("SELECT 'a' LIKE 'a' ESCAPE NULL AS n")
            .unwrap()
            .rows;
        assert_eq!(rows, vec![vec![SqlValue::Null]]);
        let prepared = bridge.prepare("SELECT 1 AS n").unwrap();
        let old = SqlControl::new(SqlLimits::default(), None);
        bridge.execute(&prepared, old.clone()).unwrap();
        old.cancel().unwrap();
        assert_eq!(
            bridge.execute(&prepared, old).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        assert!(
            bridge
                .execute(&prepared, SqlControl::new(SqlLimits::default(), None))
                .is_ok()
        );
    }
}
