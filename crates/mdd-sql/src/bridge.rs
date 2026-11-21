use crate::window::{SqlWindow, SqlWindowReport};
use crate::{
    control::{SqlControl, SqlLimits},
    dialects::SqlDialect,
    invalid,
    provider::{
        CompatibilityBlock, CompatibilityProfile, CompatibilityProfileRegistry, SqlBinding,
        SqlFactProvider, SqlRelation,
    },
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
    /// Declared compatibility scope, when the caller opted into profile
    /// blocking. Absent for development probes and native-only use.
    profile: Option<CompatibilityProfile>,
    /// Registry that must outlive a single query for a block to be enforced.
    profiles: Option<Arc<CompatibilityProfileRegistry>>,
}
pub struct PreparedSql {
    binding: SqlBinding,
    /// Digest of the session TEMP definitions this statement was expanded with,
    /// so a cursor or page cannot be stitched across a redefinition.
    temp_fingerprint: Option<String>,
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
    /// Relation (lower case) to the value of its partition column that the statement requires.
    partition_hints: std::collections::BTreeMap<String, u64>,
    execution_binding: Option<crate::runtime::SqlExecutionBinding>,
    profile: Option<CompatibilityProfile>,
    profiles: Option<Arc<CompatibilityProfileRegistry>>,
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
    /// Present when the statement ran through a response window.
    window: Option<SqlWindowReport>,
    #[serde(skip)]
    _result_memory: ResultMemory,
}
impl SqlResult {
    /// Identity of the result's column list, in projection order and without
    /// merging duplicate names. A page of the same statement must repeat it.
    pub fn schema_id(&self) -> String {
        let names = serde_json::to_string(&self.columns).unwrap_or_default();
        format!("mdd.rows.v1:{}", mdd_types::sha256(names.as_bytes()))
    }
    /// The window this result covers, when it was executed through one.
    pub fn window(&self) -> Option<&SqlWindowReport> {
        self.window.as_ref()
    }
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
    /// Next chunk to request once the current `unused` balance is spent.
    ///
    /// Live reservations are bounded by the pool (10,000 tickets), so one
    /// 4 KiB ticket per row would exhaust the metadata budget for results
    /// above ~40 MiB even when `QueryWorkspaceBytes` still has headroom.
    /// Chunks grow geometrically from `RESULT_CHUNK_MIN` to
    /// `RESULT_CHUNK_MAX`, keeping the ticket count logarithmic in the
    /// result size while `used` still matches the exact bytes admitted.
    next_chunk: u64,
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
const RESULT_CHUNK_MIN: u64 = 4096;
const RESULT_CHUNK_MAX: u64 = 8 * 1024 * 1024;
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
        if self.next_chunk == 0 {
            self.next_chunk = RESULT_CHUNK_MIN;
        }
        let preferred = needed.max(self.next_chunk);
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
        self.next_chunk = self.next_chunk.saturating_mul(2).min(RESULT_CHUNK_MAX);
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
    /// Bind the TEMP definitions this statement was expanded with into its source
    /// identity. Two statements with the same text but different TEMP bodies then
    /// get different cursor specs.
    pub(crate) fn with_temp_fingerprint(mut self, fingerprint: String) -> Self {
        self.temp_fingerprint = Some(fingerprint);
        self
    }
    /// Identity of the statement for cursor and page binding. The AST fingerprint
    /// hashes the adapted statement the AST frontend produced (not the caller's
    /// spelling), the parameter fingerprint hashes the parameter *types* only, and
    /// the source fingerprint hashes the immutable snapshot the facts came from
    /// plus the digest of any TEMP definitions the statement was expanded with.
    pub fn cursor_spec(&self) -> MddResult<mdd_session::cursors::CursorSpec> {
        let parameter_types = self
            .parameters
            .iter()
            .map(SqlValue::kind_name)
            .collect::<Vec<_>>()
            .join(",");
        mdd_session::cursors::CursorSpec::new(
            mdd_types::sha256(format!("mdd.sql.ast.v1|{}", self.adapted_sql).as_bytes()),
            mdd_types::sha256(format!("mdd.sql.parameters.v1|{parameter_types}").as_bytes()),
            mdd_types::sha256(
                match &self.temp_fingerprint {
                    Some(temp) => {
                        format!("mdd.sql.source.v1|{}|temp:{temp}", self.binding.snapshot_id)
                    }
                    None => format!("mdd.sql.source.v1|{}", self.binding.snapshot_id),
                }
                .as_bytes(),
            ),
        )
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
        let mut bridge = SqlBridge::new(Arc::clone(&self.provider), self.dialect, self.limits)?;
        bridge.profile = self.profile.clone();
        bridge.profiles = self.profiles.clone();
        bridge.execute(self, control)
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
            profile: None,
            profiles: None,
        })
    }
    /// Declare the compatibility profile this bridge serves and the registry
    /// that must enforce its blocks. This method grants no admission: it only
    /// names the scope so a real gap can be attributed to it and retained.
    ///
    /// The registry is caller-owned and must outlive individual queries for a
    /// block to survive past the failing call.
    pub fn for_compatibility_profile(
        mut self,
        profile: CompatibilityProfile,
        registry: Arc<CompatibilityProfileRegistry>,
    ) -> MddResult<Self> {
        if profile.dialect != self.dialect {
            return Err(invalid("COMPATIBILITY_PROFILE_DIALECT_MISMATCH"));
        }
        if self.profile.is_some() {
            return Err(invalid("COMPATIBILITY_PROFILE_ALREADY_BOUND"));
        }
        self.profile = Some(profile);
        self.profiles = Some(registry);
        Ok(self)
    }
    /// The declared compatibility profile, if any. Present does not mean
    /// admitted; use the registry to learn whether it is blocked.
    pub fn compatibility_profile(&self) -> Option<&CompatibilityProfile> {
        self.profile.as_ref()
    }
    /// Fail closed when this bridge's profile already carries a compatibility
    /// block. The returned error keeps the original counterexample so a caller
    /// can never confuse "profile withdrawn" with "this query is unsupported".
    fn blocked_profile_error(&self, stage: &str) -> Option<MddError> {
        let profile = self.profile.as_ref()?;
        let block = self.profiles.as_ref()?.block_for(profile)?;
        Some(
            MddError::new(
                ErrorCode::UnsupportedCapability,
                "sql.profile",
                "compatibility profile is blocked by a preserved counterexample",
            )
            .detail("profile", block.profile)
            .detail("sql_dialect", format!("{:?}", block.dialect))
            .detail("blocked_at_stage", block.stage)
            .detail("blocked_query", block.sql)
            .detail("blocked_query_sha256", block.sql_sha256)
            .detail("blocked_error_code", block.code.to_string())
            .detail("blocked_error_message", block.message)
            .detail("requested_stage", stage),
        )
    }
    /// Turn a real `UNSUPPORTED_QUERY` into a profile block. Every other error
    /// class is returned unchanged: input errors, quota, cancellation and
    /// provider faults say nothing about compatibility coverage.
    fn record_compatibility_failure(&self, stage: &str, sql: &str, error: MddError) -> MddError {
        if error.code != ErrorCode::UnsupportedQuery {
            return error;
        }
        let (Some(profile), Some(registry)) = (self.profile.as_ref(), self.profiles.as_ref())
        else {
            return error;
        };
        let block = CompatibilityBlock {
            profile: profile.name.clone(),
            dialect: profile.dialect,
            stage: stage.to_owned(),
            code: error.code,
            message: error.message.clone(),
            sql: sql.to_owned(),
            sql_sha256: mdd_types::sha256(sql.as_bytes()),
        };
        let first = registry.block(block);
        error
            .detail("compatibility_profile", profile.name.clone())
            .detail("profile_blocked", true)
            .detail("profile_block_first", first)
    }
    pub fn prepare(&self, sql: &str) -> MddResult<PreparedSql> {
        self.prepare_with_parameters(sql, &[])
    }
    /// Limits this bridge enforces on SQL text, results and work.
    pub fn limits(&self) -> SqlLimits {
        self.limits
    }
    /// The provider generation every statement of this bridge is bound to.
    pub fn provider_binding(&self) -> &SqlBinding {
        self.provider.binding()
    }
    /// The provider itself, for callers that read a relation's rows without going through a statement.
    pub fn provider(&self) -> &Arc<dyn SqlFactProvider> {
        &self.provider
    }
    pub fn prepare_with_parameters(
        &self,
        sql: &str,
        parameters: &[SqlValue],
    ) -> MddResult<PreparedSql> {
        // A blocked profile must not be answered at all: report the preserved
        // counterexample instead of re-running the gap in a new shape.
        if let Some(error) = self.blocked_profile_error("prepare") {
            return Err(error);
        }
        match self.prepare_inner(sql, parameters) {
            Ok(prepared) => Ok(prepared),
            Err(error) => Err(self.record_compatibility_failure("prepare", sql, error)),
        }
    }
    fn prepare_inner(&self, sql: &str, parameters: &[SqlValue]) -> MddResult<PreparedSql> {
        // A frozen relation the dialect does not advertise is not in the schema the statement is bound against.
        let relations = crate::profiles::compatibility::visible_relations(
            self.provider.relations()?,
            self.dialect,
        );
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
        let partition_columns: std::collections::BTreeMap<String, String> = relations
            .iter()
            .filter_map(|relation| {
                let column = self.provider.partition_column(&relation.name)?;
                Some((
                    relation.name.to_ascii_lowercase(),
                    column.to_ascii_lowercase(),
                ))
            })
            .collect();
        let adapted = match crate::dialects::ast::adapt(
            sql,
            self.limits,
            parameters,
            &relations,
            self.dialect,
            &partition_columns,
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
                let check_parameters = (error.details.get("validate_bare_parameters")
                    == Some(&serde_json::Value::Bool(true)))
                .then_some(parameters.len());
                if let Some(cause) =
                    self.original_binding_error(sql, &relations, &visible_ctes, check_parameters)?
                {
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
            temp_fingerprint: None,
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
            partition_hints: adapted.partition_hints,
            execution_binding: None,
            profile: self.profile.clone(),
            profiles: self.profiles.clone(),
        })
    }
    pub fn execute(&self, prepared: &PreparedSql, control: SqlControl) -> MddResult<SqlResult> {
        self.execute_windowed(prepared, control, None)
    }
    /// Execute and return only the rows of `window`, applied after any `LIMIT` or
    /// `OFFSET` in the statement itself. The statement text is not rewritten.
    pub fn execute_window(
        &self,
        prepared: &PreparedSql,
        control: SqlControl,
        window: SqlWindow,
    ) -> MddResult<SqlResult> {
        self.execute_windowed(prepared, control, Some(window))
    }
    fn execute_windowed(
        &self,
        prepared: &PreparedSql,
        control: SqlControl,
        window: Option<SqlWindow>,
    ) -> MddResult<SqlResult> {
        if self.provider.binding() != &prepared.binding
            || self.provider.binding() != prepared.provider.binding()
            || self.dialect != prepared.dialect
        {
            return Err(invalid("SQL_PREPARED_GENERATION_OR_DIALECT_CHANGED"));
        }
        // The bridge executing a statement must belong to the same profile
        // scope the statement was prepared under. Without this, an undeclared
        // bridge could run a statement whose profile has since been blocked,
        // and a bridge declaring a different profile would charge another
        // profile's incompatibility counterexample.
        let same_profile_scope = self.profile == prepared.profile
            && match (&self.profiles, &prepared.profiles) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            };
        if !same_profile_scope {
            return Err(invalid("SQL_PREPARED_PROFILE_SCOPE_MISMATCH"));
        }
        // The block is re-checked at execute: a query prepared under a healthy
        // profile must not run after another query withdrew that profile.
        if let Some(error) = self.blocked_profile_error("execute") {
            return Err(error);
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
            .execute_inner(prepared, control.clone(), window)
            .map_err(|error| fail_preserving_restore_detail(&control, error))
            .map_err(|error| self.record_compatibility_failure("execute", &prepared.sql, error))?;
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
    fn execute_inner(
        &self,
        prepared: &PreparedSql,
        control: SqlControl,
        window: Option<SqlWindow>,
    ) -> MddResult<SqlResult> {
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
                    partition_key: prepared
                        .partition_hints
                        .get(&relation.name.to_ascii_lowercase())
                        .copied(),
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
                let shown = prepared
                    .display_overrides
                    .get(name)
                    .map_or_else(|| name.to_owned(), Clone::clone);
                // The frozen reference engine reports result column names folded
                // to ASCII lower case (aliases, bare identifiers and CTE column
                // lists alike; non-ASCII letters are left alone). The native
                // dialect keeps SQLite's own spelling.
                columns.push(if prepared.dialect == SqlDialect::NativeV1 {
                    shown
                } else {
                    shown.to_ascii_lowercase()
                });
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
            let (mut skipped, mut more) = (0u64, false);
            let mut counted_after = 0u64;
            while let Some(row) = cursor.next().map_err(sqlite_error)? {
                control.checkpoint(1, false)?;
                if let Some(window) = window {
                    if skipped < window.offset() {
                        skipped += 1;
                        continue;
                    }
                    if rows.len() as u64 == window.limit() {
                        // One row past the window proves a next page exists.
                        more = true;
                        if !window.counts_total() {
                            break;
                        }
                        counted_after += 1;
                        continue;
                    }
                }
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
            let window_report = match window {
                Some(window) => {
                    let taken = rows.len() as u64;
                    // Counted only when the whole result was stepped: either the
                    // window reached the end, or the tail was counted on purpose.
                    let total =
                        (!more || window.counts_total()).then(|| skipped + taken + counted_after);
                    Some(SqlWindowReport::finish(window, taken, more, total)?)
                }
                None => None,
            };
            Ok(SqlResult {
                binding: prepared.binding.clone(),
                dialect: prepared.dialect,
                columns,
                rows,
                calculation_complete: true,
                profiles_admitted: Vec::new(),
                sqlite_version: rusqlite::version().to_owned(),
                optimizer: {
                    let policy = virtual_tables::VTB_POLICY;
                    OptimizerPolicy {
                        omit: policy.omit,
                        order_by_consumed: policy.order_by_consumed,
                        limit_offset_pushdown: policy.limit_offset_pushdown,
                        in_pushdown: policy.in_pushdown,
                    }
                },
                required_relations: prepared.required_relations.clone(),
                required_layers: prepared.required_layers.clone(),
                ast_nodes: prepared.ast_nodes,
                execution_binding: prepared.execution_binding.clone(),
                window: window_report,
                _result_memory: result_memory,
            })
        })();
        result.map_err(|error| control.error().unwrap_or(error))
    }
    pub fn query(&self, sql: &str) -> MddResult<SqlResult> {
        let prepared = self.prepare(sql)?;
        self.execute(&prepared, SqlControl::new(self.limits, None))
    }
    /// Prepare `sql`, run it and return only the rows of `window`.
    pub fn query_window(&self, sql: &str, window: SqlWindow) -> MddResult<SqlResult> {
        let prepared = self.prepare(sql)?;
        self.execute_window(&prepared, SqlControl::new(self.limits, None), window)
    }
    /// Run the `sql[]` items of one call the way the reference `query` tool does:
    /// one to sixteen items, each possibly a script of several statements (see
    /// [`crate::window::script_statements`]), executed in order with the same
    /// window applied to each statement's own result. The call is all or nothing:
    /// the first failing statement fails it, naming its index in the flattened
    /// list, and no later statement runs, so a trailing marker statement can only
    /// be returned if every statement before it completed. This entry point is
    /// read-only; session TEMP statements go through `temp::TempSqlSession`.
    pub fn query_batch(
        &self,
        items: &[&str],
        window: Option<SqlWindow>,
    ) -> MddResult<Vec<SqlResult>> {
        let statements = crate::window::script_statements(items)?;
        let mut results = Vec::with_capacity(statements.len());
        for (index, sql) in statements.iter().enumerate() {
            let run = || {
                let prepared = self.prepare(sql)?;
                self.execute_windowed(&prepared, SqlControl::new(self.limits, None), window)
            };
            match run() {
                Ok(result) => results.push(result),
                Err(error) => return Err(error.detail("statement_index", index.to_string())),
            }
        }
        Ok(results)
    }
    /// Only prepare, never step a statement or open facts. This separates a
    /// real syntax/binding error from a gap in the additional AST frontend.
    fn original_binding_error(
        &self,
        sql: &str,
        relations: &[SqlRelation],
        visible_ctes: &BTreeSet<String>,
        supplied_parameters: Option<usize>,
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
                    partition_key: None,
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
                if !statement.readonly() {
                    return Ok(Some(invalid("STATEMENT_NOT_READ_ONLY")));
                }
                if let Some(supplied) = supplied_parameters {
                    let count = statement.parameter_count();
                    // A bare '?' uses one SQL token per parameter. A larger
                    // SQLite index count than the admitted token budget must
                    // therefore come from a named/numbered placeholder; do
                    // not walk a sparse attacker-selected index range.
                    if count > self.limits.max_tokens {
                        return Ok(Some(invalid("ONLY_POSITIONAL_BARE_PARAMETERS_SUPPORTED")));
                    }
                    // Avoid scanning sparse numbered placeholders when the
                    // caller did not supply that many values. Once counts
                    // agree, name inspection is bounded by supplied input.
                    if supplied < count {
                        return Ok(Some(invalid("UNBOUND_SQL_PARAMETER")));
                    }
                    if supplied > count {
                        return Ok(Some(invalid("UNUSED_SQL_PARAMETERS")));
                    }
                    for index in 1..=count {
                        if statement.parameter_name(index).is_some() {
                            return Ok(Some(invalid("ONLY_POSITIONAL_BARE_PARAMETERS_SUPPORTED")));
                        }
                    }
                }
                Ok(None)
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
#[path = "bridge_tests.rs"]
mod tests;
