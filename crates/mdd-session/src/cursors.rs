//! Cursor identity, page-continuation and compatible-offset contracts.
//!
//! Two paging modes exist and must never share one token:
//!
//! * [`CursorMode::NativeSnapshot`] — one execution with a spooled result. The
//!   opaque cursor binds snapshot, session, catalog generation, query identity,
//!   schema, worker owner and worker generation, keeping the execution and its
//!   TEMP generation alive across pages.
//! * [`CursorMode::CompatOffset`] — every page re-executes the query. It is
//!   admitted by [`Lifecycle::open_compat_offset`] and never produces a cursor
//!   token; it exposes an explicit `next_offset` instead.
//!
//! Both modes reject pages that mix a relational `LIMIT`/`OFFSET` with response
//! paging, and both reject a page whose source differs from the first page even
//! when the SQL, row count and column schema are unchanged.

use crate::{CursorHandle, Lifecycle, QueryHandle, QueryPhase, SessionHandle};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use serde::Serialize;

/// Paging mode. Also the capability name reported to callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorMode {
    /// One execution, page-by-page delivery from a retained result.
    NativeSnapshot,
    /// One re-execution per page, addressed by an explicit offset.
    CompatOffset,
}

impl CursorMode {
    pub fn capability(self) -> &'static str {
        match self {
            Self::NativeSnapshot => "native_snapshot_cursor",
            Self::CompatOffset => "compat_offset_reexecution",
        }
    }
}

/// Immutable fingerprints a caller must supply for a paginated cursor. The
/// session layer never parses SQL, so the SQL layer computes these and the
/// catalog layer binds them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CursorSpec {
    /// Fingerprint of the normalized AST (not the raw SQL text).
    pub ast_fingerprint: String,
    /// Fingerprint of the bound parameter types only (not the values).
    pub parameter_types_fingerprint: String,
    /// Fingerprint of the source the result was produced from.
    pub source_fingerprint: String,
}

impl CursorSpec {
    pub fn new(
        ast_fingerprint: impl Into<String>,
        parameter_types_fingerprint: impl Into<String>,
        source_fingerprint: impl Into<String>,
    ) -> MddResult<Self> {
        let spec = Self {
            ast_fingerprint: ast_fingerprint.into(),
            parameter_types_fingerprint: parameter_types_fingerprint.into(),
            source_fingerprint: source_fingerprint.into(),
        };
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> MddResult<()> {
        for (field, value) in [
            ("ast_fingerprint", &self.ast_fingerprint),
            (
                "parameter_types_fingerprint",
                &self.parameter_types_fingerprint,
            ),
            ("source_fingerprint", &self.source_fingerprint),
        ] {
            if !is_fingerprint(value) {
                return Err(invalid(format!(
                    "cursor {field} must be a lowercase SHA-256 hex digest"
                )));
            }
        }
        Ok(())
    }
}

/// Every identity component a native cursor binds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CursorBinding {
    pub session_id: String,
    pub query_id: String,
    pub snapshot_id: String,
    pub catalog_epoch: DecimalU64,
    pub worker_owner: String,
    pub worker_generation: DecimalU64,
    pub request_key: String,
    pub schema_id: String,
    pub semantic_version: String,
    pub ast_fingerprint: String,
    pub parameter_types_fingerprint: String,
    pub source_fingerprint: String,
    pub mode: CursorMode,
}

/// What one delivered page claims about itself. The first page establishes the
/// claim; every later page must repeat it exactly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageClaim {
    pub schema_id: String,
    pub total_rows: Option<u64>,
    pub source_fingerprint: String,
}

/// Shape of a paging request as the transport received it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageRequestShape {
    pub mode: CursorMode,
    pub page_limit: u64,
    pub continuation: Option<String>,
    pub offset: Option<u64>,
    /// `LIMIT` written in the relation text (SQL `LIMIT`), not the API page limit.
    pub relation_limit: Option<u64>,
    /// `OFFSET` written in the relation text, not a compatible-offset request.
    pub relation_offset: Option<u64>,
}

impl PageRequestShape {
    /// A relational `LIMIT`/`OFFSET` is a relation operator that already bounds
    /// the result. Paging the response of such a relation would either re-apply
    /// the bound on every page or silently drop rows, so the mixture is refused
    /// instead of being guessed. Materialize once and page the spool instead.
    fn check(&self, max_page_rows: u64) -> MddResult<()> {
        if self.page_limit == 0 {
            return Err(page_error("page_limit_zero", "page limit must be positive"));
        }
        if self.page_limit > max_page_rows {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "cursor.page",
                "page limit exceeds the configured maximum",
            )
            .detail("budget", "max_page_rows")
            .detail("limit", max_page_rows.to_string())
            .detail("observed", self.page_limit.to_string()));
        }
        if self.relation_limit.is_some() || self.relation_offset.is_some() {
            return Err(page_error(
                "response_paging_over_relation_limit",
                "response paging cannot be combined with a relational LIMIT or OFFSET",
            )
            .detail("relation_limit", option_text(self.relation_limit))
            .detail("relation_offset", option_text(self.relation_offset)));
        }
        match (self.continuation.as_deref(), self.offset) {
            (Some(_), Some(_)) => Err(page_error(
                "ambiguous_continuation",
                "request carries both a cursor token and an explicit offset",
            )),
            (Some(token), None) => {
                if self.mode != CursorMode::NativeSnapshot {
                    return Err(page_error(
                        "native_cursor_under_compat_offset",
                        "a native cursor token cannot continue a compatible-offset sequence",
                    ));
                }
                if token.is_empty() {
                    return Err(page_error("empty_continuation", "cursor token is empty"));
                }
                Ok(())
            }
            (None, Some(_)) => {
                if self.mode != CursorMode::CompatOffset {
                    return Err(page_error(
                        "compat_offset_under_native_cursor",
                        "an explicit offset cannot continue a native snapshot cursor",
                    ));
                }
                Ok(())
            }
            (None, None) => Ok(()),
        }
    }
}

/// Paging budget for compatible-offset re-execution. Re-execution is unbounded
/// work by construction, so the number of executions, the rows accepted and the
/// page size are all bounded explicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompatOffsetContract {
    pub max_page_rows: u64,
    pub max_executions: u64,
    pub max_rows: u64,
}

impl CompatOffsetContract {
    pub fn new(max_page_rows: u64, max_executions: u64, max_rows: u64) -> MddResult<Self> {
        if max_page_rows == 0 || max_executions == 0 || max_rows == 0 {
            return Err(invalid(
                "compatible-offset contract limits must be positive",
            ));
        }
        if max_rows < max_page_rows {
            return Err(invalid(
                "compatible-offset max_rows cannot be below max_page_rows",
            ));
        }
        Ok(Self {
            max_page_rows,
            max_executions,
            max_rows,
        })
    }
}

impl Default for CompatOffsetContract {
    fn default() -> Self {
        Self {
            max_page_rows: 1_000,
            max_executions: 64,
            max_rows: 100_000,
        }
    }
}

/// One re-execution request: the server tells the client which offset and limit
/// to send next instead of handing out a cursor token.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CompatOffsetPageRequest {
    pub offset: DecimalU64,
    pub limit: DecimalU64,
}

/// What the re-executed page reports back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatOffsetPage {
    pub offset: u64,
    pub limit: u64,
    pub rows: u64,
    pub schema_id: String,
    pub total_rows: Option<u64>,
    pub source_fingerprint: String,
    pub catalog_epoch: DecimalU64,
    /// The re-executed statement still matches the admitted SQL/AST.
    pub sql_matches: bool,
    pub relation_limit: Option<u64>,
    pub relation_offset: Option<u64>,
    /// `limit + 1` lookahead proved there is no further row.
    pub lookahead_exhausted: bool,
}

/// Admission of one compatible-offset page. Never contains a cursor token.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CompatOffsetAdmission {
    pub pages: DecimalU64,
    pub reexecutions: DecimalU64,
    pub rows: DecimalU64,
    pub more_available: bool,
    pub next_offset: Option<DecimalU64>,
    pub catalog_epochs_observed: Vec<DecimalU64>,
}

impl CompatOffsetAdmission {
    pub fn metadata(&self) -> MddResult<PageResponseMetadata> {
        PageResponseMetadata::compat(self.next_offset, self.more_available)
    }
}

/// Per-paging-sequence state for compatible offsets. Unlike a native cursor it
/// may observe a new catalog generation on later requests; it refuses a page
/// whose schema, total or source changed instead.
#[derive(Clone, Debug)]
pub struct CompatOffsetState {
    contract: CompatOffsetContract,
    session_id: String,
    query_id: String,
    snapshot_id: String,
    schema_id: String,
    source_fingerprint: String,
    total_rows: Option<u64>,
    /// The first admitted page fixes the exact total (including "not exact").
    total_established: bool,
    next_offset: u64,
    executions: u64,
    rows: u64,
    pages: u64,
    epochs: Vec<DecimalU64>,
    done: bool,
}

impl CompatOffsetState {
    pub fn contract(&self) -> CompatOffsetContract {
        self.contract
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn query_id(&self) -> &str {
        &self.query_id
    }

    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    pub fn reexecutions(&self) -> u64 {
        self.executions
    }

    pub fn admitted_rows(&self) -> u64 {
        self.rows
    }

    /// Next request the client must issue, or `None` once the sequence ended.
    ///
    /// A sequence that stopped because the row budget ran out while the last page
    /// still reported more rows is an error, not an ending: `None` would let a
    /// driver loop mistake a truncated result for a complete one.
    pub fn next_request(&self) -> MddResult<Option<CompatOffsetPageRequest>> {
        if self.done {
            return Ok(None);
        }
        let budget_left = self.contract.max_rows.saturating_sub(self.rows);
        if budget_left == 0 {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "cursor.offset",
                "compatible-offset row budget exhausted before the sequence ended",
            )
            .detail("budget", "max_rows")
            .detail("limit", self.contract.max_rows.to_string())
            .detail("observed", self.rows.to_string()));
        }
        let mut limit = self.contract.max_page_rows.min(budget_left);
        if self.total_established
            && let Some(total) = self.total_rows
        {
            limit = limit.min(total.saturating_sub(self.next_offset));
        }
        if limit == 0 {
            return Ok(None);
        }
        Ok(Some(CompatOffsetPageRequest {
            offset: DecimalU64(self.next_offset),
            limit: DecimalU64(limit),
        }))
    }

    pub fn admit(&mut self, page: CompatOffsetPage) -> MddResult<CompatOffsetAdmission> {
        if self.done {
            return Err(page_error(
                "offset_sequence_complete",
                "compatible-offset sequence already ended",
            ));
        }
        if page.offset != self.next_offset {
            return Err(page_error(
                "query_page_identity_or_limit_mismatch",
                "compatible-offset page does not continue the admitted offset",
            )
            .detail("expected_offset", self.next_offset.to_string())
            .detail("observed_offset", page.offset.to_string()));
        }
        if page.limit == 0 || page.limit > self.contract.max_page_rows {
            return Err(page_error(
                "query_page_identity_or_limit_mismatch",
                "compatible-offset page limit is outside the admitted range",
            )
            .detail("limit", page.limit.to_string())
            .detail("max_page_rows", self.contract.max_page_rows.to_string()));
        }
        if page.rows > page.limit {
            return Err(page_error(
                "query_page_identity_or_limit_mismatch",
                "page returned more rows than it requested",
            )
            .detail("rows", page.rows.to_string())
            .detail("limit", page.limit.to_string()));
        }
        if !page.sql_matches {
            return Err(page_error(
                "query_page_identity_or_limit_mismatch",
                "re-executed statement does not match the admitted query",
            ));
        }
        if page.relation_limit.is_some() || page.relation_offset.is_some() {
            return Err(page_error(
                "response_paging_over_relation_limit",
                "compatible-offset paging cannot be combined with a relational LIMIT or OFFSET",
            )
            .detail("relation_limit", option_text(page.relation_limit))
            .detail("relation_offset", option_text(page.relation_offset)));
        }
        if page.schema_id != self.schema_id
            || (self.total_established && page.total_rows != self.total_rows)
        {
            return Err(page_error(
                "query_schema_or_total_changed",
                "page schema or exact total changed between re-executions",
            )
            .detail("expected_schema_id", self.schema_id.clone())
            .detail("observed_schema_id", page.schema_id.clone())
            .detail("expected_total", option_text(self.total_rows))
            .detail("observed_total", option_text(page.total_rows)));
        }
        if page.source_fingerprint != self.source_fingerprint {
            return Err(page_error(
                "source_changed",
                "page source differs even though SQL, schema and row count match",
            )
            .detail("source_fingerprint", self.source_fingerprint.clone())
            .detail("observed_fingerprint", page.source_fingerprint.clone()));
        }
        if page.rows < page.limit && !page.lookahead_exhausted {
            return Err(page_error(
                "lookahead_required",
                "a short page must prove the lookahead row is absent",
            )
            .detail("rows", page.rows.to_string())
            .detail("limit", page.limit.to_string()));
        }
        let executions = self
            .executions
            .checked_add(1)
            .ok_or_else(|| page_error("execution_count_overflow", "re-execution count overflow"))?;
        if executions > self.contract.max_executions {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "cursor.offset",
                "compatible-offset re-execution budget exhausted",
            )
            .detail("budget", "max_executions")
            .detail("limit", self.contract.max_executions.to_string())
            .detail("observed", executions.to_string()));
        }
        let rows = self
            .rows
            .checked_add(page.rows)
            .ok_or_else(|| page_error("row_count_overflow", "accepted row count overflow"))?;
        if rows > self.contract.max_rows {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "cursor.offset",
                "compatible-offset row budget exhausted",
            )
            .detail("budget", "max_rows")
            .detail("limit", self.contract.max_rows.to_string())
            .detail("observed", rows.to_string()));
        }
        let next_offset = self
            .next_offset
            .checked_add(page.rows)
            .ok_or_else(|| page_error("offset_overflow", "next offset overflow"))?;
        // The first page fixes the exact total, so it is held to the claim it
        // makes itself; later pages are held to the established one.
        let known_total = if self.total_established {
            self.total_rows
        } else {
            page.total_rows
        };
        let ends_here = page.rows < page.limit || page.lookahead_exhausted;
        if let Some(total) = known_total {
            // Rows past the total, an end before the total, or a lookahead row
            // that exists after the total was reached: the page and the total
            // cannot both be true, so neither is admitted.
            let contradicts = next_offset > total
                || (ends_here && next_offset != total)
                || (!ends_here && next_offset == total);
            if contradicts {
                return Err(page_error(
                    "total_conflicts_with_page",
                    "page rows and lookahead contradict the exact total",
                )
                .detail("exact_total", total.to_string())
                .detail("next_offset", next_offset.to_string())
                .detail("rows", page.rows.to_string())
                .detail("limit", page.limit.to_string())
                .detail("lookahead_exhausted", page.lookahead_exhausted.to_string()));
            }
        }
        let more_available = !ends_here;
        self.executions = executions;
        self.rows = rows;
        self.pages += 1;
        self.next_offset = next_offset;
        self.done = !more_available;
        if !self.total_established {
            self.total_rows = page.total_rows;
            self.total_established = true;
        }
        self.epochs.push(page.catalog_epoch);
        Ok(CompatOffsetAdmission {
            pages: DecimalU64(self.pages),
            reexecutions: DecimalU64(self.executions),
            rows: DecimalU64(self.rows),
            more_available,
            next_offset: more_available.then_some(DecimalU64(next_offset)),
            catalog_epochs_observed: self.epochs.clone(),
        })
    }
}

/// Response-side paging metadata. Exactly one of `next_cursor` and
/// `next_offset` may be present, so a compatible-offset response can never be
/// mistaken for a native cursor response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PageResponseMetadata {
    pub mode: CursorMode,
    pub more_available: bool,
    pub next_cursor: Option<String>,
    pub next_offset: Option<DecimalU64>,
}

impl PageResponseMetadata {
    pub fn native(next_cursor: String, more_available: bool) -> MddResult<Self> {
        if next_cursor.is_empty() {
            return Err(invalid("native page cursor token must be nonempty"));
        }
        let metadata = Self {
            mode: CursorMode::NativeSnapshot,
            more_available,
            next_cursor: Some(next_cursor),
            next_offset: None,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    /// Final native page: the exact total has been delivered, so there is no
    /// continuation. The mode stays native and never becomes compatible offset.
    pub fn native_complete() -> MddResult<Self> {
        let metadata = Self {
            mode: CursorMode::NativeSnapshot,
            more_available: false,
            next_cursor: None,
            next_offset: None,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    pub fn compat(next_offset: Option<DecimalU64>, more_available: bool) -> MddResult<Self> {
        let metadata = Self {
            mode: CursorMode::CompatOffset,
            more_available,
            next_cursor: None,
            next_offset,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    pub fn validate(&self) -> MddResult<()> {
        if self.next_cursor.is_some() && self.next_offset.is_some() {
            return Err(page_error(
                "paging_mode_conflict",
                "response carries both a cursor token and an explicit offset",
            ));
        }
        match self.mode {
            CursorMode::NativeSnapshot => {
                if self.next_offset.is_some() {
                    return Err(page_error(
                        "compat_offset_under_native_cursor",
                        "native paging never reports an explicit offset",
                    ));
                }
            }
            CursorMode::CompatOffset => {
                if self.next_cursor.is_some() {
                    return Err(page_error(
                        "native_cursor_under_compat_offset",
                        "compatible-offset paging never returns a cursor token",
                    ));
                }
            }
        }
        let continued = self.next_cursor.is_some() || self.next_offset.is_some();
        if self.more_available != continued {
            return Err(page_error(
                "paging_more_available_mismatch",
                "more_available must match the presence of a continuation",
            )
            .detail("more_available", self.more_available.to_string())
            .detail("continuation", continued.to_string()));
        }
        Ok(())
    }

    /// Build a native page envelope through the production terminal path and
    /// report exactly the metadata that was emitted. The transport owns the
    /// opaque, integrity-protected cursor token; this function only refuses an
    /// empty one and proves the envelope and metadata never disagree.
    pub fn native_page(
        builder: &mdd_types::result::TerminalBuilder,
        page_rows: u64,
        cursor_token: &str,
    ) -> MddResult<(mdd_types::ResultEnvelope, Self)> {
        if cursor_token.is_empty() {
            return Err(invalid("native page cursor token must be nonempty"));
        }
        let envelope = builder.page(page_rows, cursor_token.to_owned(), None)?;
        let metadata = Self::native(cursor_token.to_owned(), true)?;
        // `mdd.result.v1` has no offset field at all, so a native page envelope
        // cannot carry a compatible-offset continuation by construction.
        if envelope.response.next_cursor.as_deref() != Some(cursor_token)
            || envelope.response.more_available != metadata.more_available
        {
            return Err(page_error(
                "paging_metadata_mismatch",
                "emitted page envelope disagrees with its paging metadata",
            ));
        }
        Ok((envelope, metadata))
    }
}

fn is_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn option_text<T: ToString>(value: Option<T>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| value.to_string())
}

fn invalid(message: impl Into<String>) -> MddError {
    MddError::new(ErrorCode::InvalidArgument, "cursor", message)
}

fn page_error(page_error: &str, message: impl Into<String>) -> MddError {
    MddError::new(ErrorCode::InvalidCursor, "cursor.page", message).detail("page_error", page_error)
}

impl Lifecycle {
    /// Reject a paging request that mixes modes or mixes response paging with a
    /// relational `LIMIT`/`OFFSET`.
    pub fn validate_page_request(
        &self,
        shape: &PageRequestShape,
        max_page_rows: u64,
    ) -> MddResult<()> {
        let _guard = self.lock()?;
        shape.check(max_page_rows)
    }

    /// Open a native snapshot cursor that additionally binds the SQL-layer AST
    /// and parameter-type fingerprints.
    pub fn open_cursor_with_spec(
        &self,
        session: &SessionHandle,
        query: &QueryHandle,
        spec: CursorSpec,
    ) -> MddResult<CursorHandle> {
        spec.validate()?;
        let mut state = self.lock_query(query)?;
        let entry = state.owned_query(session, query)?;
        if entry.status.phase != QueryPhase::Active {
            return Err(invalid("cursor requires active query"));
        }
        state.checkpoint(query)?;
        let (binding, catalog_epoch, snapshot_id, worker_owner, worker_generation) = {
            let entry = state.query(query)?;
            (
                entry.binding.clone(),
                entry.status.catalog_epoch,
                state.session(session)?.snapshot_id.clone(),
                state.owner.clone(),
                state.worker_generation,
            )
        };
        let session_count = state
            .cursors
            .values()
            .filter(|cursor| cursor.session_id == session.id())
            .count();
        let query_count = state
            .cursors
            .values()
            .filter(|cursor| cursor.query_id == query.id())
            .count();
        let max = state.query(query)?.limits.max_cursors;
        if state.cursors.len() >= state.limits.max_cursors
            || session_count >= state.session(session)?.limits.max_cursors
            || query_count >= max
        {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "cursor",
                "resource reservation exceeds budget",
            )
            .detail("budget", "max_cursors")
            .detail("limit", max.to_string())
            .detail("observed", (session_count + 1).to_string()));
        }
        let token = state.token("cursor")?;
        state.cursors.insert(
            token.id.clone(),
            crate::CursorEntry {
                token: token.clone(),
                session_id: session.id().to_owned(),
                query_id: query.id().to_owned(),
                snapshot_id,
                catalog_epoch: catalog_epoch.0,
                binding,
                worker_owner,
                worker_generation,
                spec: Some(spec),
                page_total: None,
                page_total_established: false,
                pages: 0,
                open: true,
                consumed: false,
            },
        );
        Ok(CursorHandle(token))
    }

    /// Validate every bound component of a paginated native cursor and return
    /// the binding the caller must echo back to the client.
    pub fn cursor_binding(
        &self,
        session: &SessionHandle,
        query: &QueryHandle,
        cursor: &CursorHandle,
    ) -> MddResult<CursorBinding> {
        let mut state = self.lock_query(query)?;
        state.owned_query(session, query)?;
        state.checkpoint(query)?;
        let entry = state
            .cursors
            .get(cursor.id())
            .ok_or_else(|| page_error("stale_cursor", "stale cursor"))?;
        state.check(&cursor.0, &entry.token)?;
        let query_entry = state.query(query)?;
        let snapshot_id = state.session(session)?.snapshot_id.clone();
        if !entry.open
            || entry.query_id != query.id()
            || entry.session_id != session.id()
            || entry.snapshot_id != snapshot_id
            || entry.catalog_epoch != query_entry.status.catalog_epoch.0
            || entry.binding.request_key != query_entry.binding.request_key
            || entry.binding.schema_id != query_entry.binding.schema_id
            || entry.binding.semantic_version != query_entry.binding.semantic_version
        {
            return Err(page_error(
                "cursor_binding_mismatch",
                "cursor binding or lifetime mismatch",
            ));
        }
        if entry.worker_owner != state.owner || entry.worker_generation != state.worker_generation {
            return Err(page_error(
                "worker_generation_changed",
                "cursor was opened by a different worker generation",
            )
            .detail("worker_generation", entry.worker_generation.to_string())
            .detail(
                "current_worker_generation",
                state.worker_generation.to_string(),
            ));
        }
        let spec = entry.spec.clone().ok_or_else(|| {
            page_error(
                "cursor_binding_incomplete",
                "cursor was opened without AST/parameter/source fingerprints",
            )
        })?;
        Ok(CursorBinding {
            session_id: entry.session_id.clone(),
            query_id: entry.query_id.clone(),
            snapshot_id: entry.snapshot_id.clone(),
            catalog_epoch: DecimalU64(entry.catalog_epoch),
            worker_owner: entry.worker_owner.clone(),
            worker_generation: DecimalU64(entry.worker_generation),
            request_key: entry.binding.request_key.clone(),
            schema_id: entry.binding.schema_id.clone(),
            semantic_version: entry.binding.semantic_version.clone(),
            ast_fingerprint: spec.ast_fingerprint,
            parameter_types_fingerprint: spec.parameter_types_fingerprint,
            source_fingerprint: spec.source_fingerprint,
            mode: CursorMode::NativeSnapshot,
        })
    }

    /// Admit one page against a native cursor. The first call fixes the exact
    /// total and source; later calls must repeat them, so a query that keeps the
    /// same SQL, row count and schema but reads a different source cannot be
    /// stitched into the same page sequence.
    pub fn validate_page_continuation(
        &self,
        session: &SessionHandle,
        query: &QueryHandle,
        cursor: &CursorHandle,
        claim: &PageClaim,
    ) -> MddResult<CursorBinding> {
        let binding = self.cursor_binding(session, query, cursor)?;
        if binding.mode != CursorMode::NativeSnapshot {
            return Err(page_error(
                "native_cursor_under_compat_offset",
                "only a native snapshot cursor can continue a page sequence",
            ));
        }
        if claim.schema_id != binding.schema_id {
            return Err(page_error(
                "query_schema_or_total_changed",
                "page schema does not match the cursor's bound schema",
            )
            .detail("schema_id", binding.schema_id.clone())
            .detail("observed_schema_id", claim.schema_id.clone()));
        }
        if claim.source_fingerprint != binding.source_fingerprint {
            return Err(page_error(
                "source_changed",
                "page source differs even though SQL, schema and row count match",
            )
            .detail("source_fingerprint", binding.source_fingerprint.clone())
            .detail("observed_fingerprint", claim.source_fingerprint.clone()));
        }
        let mut state = self.lock_query(query)?;
        let entry = state
            .cursors
            .get(cursor.id())
            .ok_or_else(|| page_error("stale_cursor", "stale cursor"))?;
        if entry.page_total_established && claim.total_rows != entry.page_total {
            return Err(page_error(
                "query_schema_or_total_changed",
                "page total changed between pages of one cursor",
            )
            .detail("total_rows", option_text(entry.page_total))
            .detail("observed_total", option_text(claim.total_rows)));
        }
        let entry = state.cursors.get_mut(cursor.id()).unwrap();
        if !entry.page_total_established {
            entry.page_total = claim.total_rows;
            entry.page_total_established = true;
        }
        entry.pages = entry.pages.saturating_add(1);
        Ok(binding)
    }

    /// Pages admitted on this cursor so far, for transport diagnostics.
    pub fn cursor_page_count(&self, cursor: &CursorHandle) -> MddResult<u64> {
        let state = self.lock_cursor(cursor)?;
        let entry = state
            .cursors
            .get(cursor.id())
            .ok_or_else(|| page_error("stale_cursor", "stale cursor"))?;
        Ok(entry.pages)
    }

    /// Native cursors must be opened with SQL-layer fingerprints; the legacy
    /// delivery cursor (no fingerprints) is rejected for paged responses.
    pub fn validate_paged_cursor(
        &self,
        session: &SessionHandle,
        cursor: &CursorHandle,
    ) -> MddResult<()> {
        let state = self.lock_query_read_by_cursor(cursor)?;
        let entry = state
            .cursors
            .get(cursor.id())
            .ok_or_else(|| page_error("stale_cursor", "stale cursor"))?;
        state.check(&cursor.0, &entry.token)?;
        if entry.session_id != session.id() {
            return Err(page_error(
                "cursor_binding_mismatch",
                "cursor belongs to another session",
            ));
        }
        if entry.spec.is_none() {
            return Err(page_error(
                "cursor_binding_incomplete",
                "cursor was opened without AST/parameter/source fingerprints",
            ));
        }
        Ok(())
    }

    /// Start a compatible-offset sequence bound to this query's identity. No
    /// cursor token is allocated: each page is a fresh request with an explicit
    /// offset.
    pub fn open_compat_offset(
        &self,
        session: &SessionHandle,
        query: &QueryHandle,
        spec: &CursorSpec,
        contract: CompatOffsetContract,
    ) -> MddResult<CompatOffsetState> {
        spec.validate()?;
        let mut state = self.lock_query(query)?;
        let entry = state.owned_query(session, query)?;
        if !matches!(
            entry.status.phase,
            QueryPhase::Prepared | QueryPhase::Active
        ) {
            return Err(invalid(
                "compatible offset requires a prepared or active query",
            ));
        }
        state.checkpoint(query)?;
        let (schema_id, snapshot_id) = {
            let entry = state.query(query)?;
            (
                entry.binding.schema_id.clone(),
                state.session(session)?.snapshot_id.clone(),
            )
        };
        Ok(CompatOffsetState {
            contract,
            session_id: session.id().to_owned(),
            query_id: query.id().to_owned(),
            snapshot_id,
            schema_id,
            source_fingerprint: spec.source_fingerprint.clone(),
            total_rows: None,
            total_established: false,
            next_offset: 0,
            executions: 0,
            rows: 0,
            pages: 0,
            epochs: Vec::new(),
            done: false,
        })
    }
}

impl Lifecycle {
    fn lock_query_read_by_cursor(
        &self,
        cursor: &CursorHandle,
    ) -> MddResult<std::sync::MutexGuard<'_, crate::State>> {
        let state = self.lock_raw()?;
        state
            .cursors
            .get(cursor.id())
            .ok_or_else(|| page_error("stale_cursor", "stale cursor"))?;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Lifecycle, QueryBinding, ResourceLimits};
    use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
    use std::path::PathBuf;
    use std::sync::Arc;

    fn snapshot() -> Arc<Snapshot> {
        Arc::new(
            Snapshot::capture(
                &[InputSpec {
                    path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("../../tests/fixtures/generated/minimal-035.dex"),
                    kind: InputKind::RawDex,
                    expected_sha256: None,
                }],
                CaptureLimits::default(),
            )
            .unwrap(),
        )
    }

    fn binding() -> QueryBinding {
        QueryBinding {
            request_key: "request-content-hash".to_owned(),
            schema_id: "mdd.rows.v1:page-schema".to_owned(),
            semantic_version: "cursor-v1".to_owned(),
        }
    }

    fn runtime() -> (Lifecycle, SessionHandle, QueryHandle) {
        let runtime = Lifecycle::new(ResourceLimits::default()).unwrap();
        let snapshot = runtime.register_snapshot(snapshot()).unwrap();
        let session = runtime
            .open_session(&snapshot, ResourceLimits::default())
            .unwrap();
        let query = runtime
            .prepare_query(&session, binding(), ResourceLimits::default())
            .unwrap();
        runtime.start_query(&session, &query, 1).unwrap();
        (runtime, session, query)
    }

    fn spec(source: &str) -> CursorSpec {
        CursorSpec::new(
            mdd_types::sha256(b"normalized-ast"),
            mdd_types::sha256(b"parameter-types"),
            source,
        )
        .unwrap()
    }

    fn claim(total: Option<u64>, source: &str) -> PageClaim {
        PageClaim {
            schema_id: "mdd.rows.v1:page-schema".to_owned(),
            total_rows: total,
            source_fingerprint: source.to_owned(),
        }
    }

    #[test]
    fn native_cursor_binds_every_identity_component() {
        let (runtime, session, query) = runtime();
        let cursor = runtime
            .open_cursor_with_spec(&session, &query, spec(&mdd_types::sha256(b"source-a")))
            .unwrap();
        let binding = runtime.cursor_binding(&session, &query, &cursor).unwrap();
        assert_eq!(binding.session_id, session.id());
        assert_eq!(binding.query_id, query.id());
        assert!(!binding.snapshot_id.is_empty());
        assert_eq!(binding.catalog_epoch, DecimalU64(0));
        assert_eq!(
            binding.worker_owner,
            runtime.inner.lock().unwrap().owner,
            "the cursor binds the registry's own worker owner"
        );
        assert_eq!(binding.worker_generation, DecimalU64(0));
        assert_eq!(binding.request_key, "request-content-hash");
        assert_eq!(binding.schema_id, "mdd.rows.v1:page-schema");
        assert_eq!(binding.semantic_version, "cursor-v1");
        assert_eq!(binding.mode, CursorMode::NativeSnapshot);
        assert_eq!(binding.source_fingerprint, mdd_types::sha256(b"source-a"));
        assert_eq!(
            binding.ast_fingerprint,
            mdd_types::sha256(b"normalized-ast")
        );
        assert_eq!(
            binding.parameter_types_fingerprint,
            mdd_types::sha256(b"parameter-types")
        );
        // A cursor opened without fingerprints cannot enter the paged path.
        let legacy = runtime.open_cursor(&session, &query).unwrap();
        let error = runtime
            .validate_paged_cursor(&session, &legacy)
            .unwrap_err();
        assert_eq!(error.details["page_error"], "cursor_binding_incomplete");
        assert!(runtime.validate_paged_cursor(&session, &cursor).is_ok());
    }

    #[test]
    fn native_page_envelope_and_metadata_agree() {
        use mdd_types::result::{ResultIdentity, TerminalBuilder};
        use mdd_types::{Completeness, Coverage};

        let identity = ResultIdentity {
            request_id: "page-request".into(),
            operation: "query".into(),
            profile: "native-unqualified".into(),
            sql_dialect: None,
            session_id: Some("session".into()),
            snapshot_id: Some("snapshot".into()),
            catalog_epoch: Some(DecimalU64(0)),
            query_id: Some("query".into()),
            schema_id: Some("mdd.rows.v1:page-schema".into()),
        };
        let coverage = Coverage {
            scope_id: "scope".into(),
            input: Completeness::Complete,
            facts: Completeness::Complete,
            required_layers: vec!["structure".into()],
            issues: Vec::new(),
        };
        let mut builder = TerminalBuilder::new(identity, coverage).unwrap();
        builder.computation_complete(2).unwrap();
        builder.record_batch(0, 1).unwrap();
        // The first page continues, so more_available is true and the token is
        // carried by the envelope itself.
        let (envelope, metadata) =
            PageResponseMetadata::native_page(&builder, 1, "opaque-cursor-token").unwrap();
        assert_eq!(metadata.mode, CursorMode::NativeSnapshot);
        assert!(metadata.more_available);
        assert_eq!(
            envelope.response.next_cursor.as_deref(),
            Some("opaque-cursor-token")
        );
        assert!(envelope.response.more_available);
        assert_eq!(envelope.response.emitted_rows, DecimalU64(1));
        envelope.validate().unwrap();
        // An empty token never becomes a page.
        assert_eq!(
            PageResponseMetadata::native_page(&builder, 1, "")
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        // Delivering every row makes page() refuse to claim a continuation.
        builder.record_batch(1, 1).unwrap();
        assert_eq!(
            PageResponseMetadata::native_page(&builder, 1, "opaque-cursor-token")
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        // The terminal metadata for a finished native sequence is still native.
        let done = PageResponseMetadata::native_complete().unwrap();
        assert_eq!(done.mode, CursorMode::NativeSnapshot);
        assert!(done.next_cursor.is_none() && done.next_offset.is_none());
        assert!(!done.more_available);
        builder.succeed(None).unwrap();
        assert!(PageResponseMetadata::native_page(&builder, 1, "token").is_err());
    }

    #[test]
    fn forged_worker_generation_is_rejected() {
        let (runtime, session, query) = runtime();
        let cursor = runtime
            .open_cursor_with_spec(&session, &query, spec(&mdd_types::sha256(b"source-a")))
            .unwrap();
        assert!(runtime.cursor_binding(&session, &query, &cursor).is_ok());
        {
            let mut state = runtime.inner.lock().unwrap();
            let entry = state.cursors.get_mut(cursor.id()).unwrap();
            entry.worker_generation += 1;
        }
        let error = runtime
            .cursor_binding(&session, &query, &cursor)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidCursor);
        assert_eq!(error.details["page_error"], "worker_generation_changed");
    }

    #[test]
    fn a_new_worker_generation_invalidates_older_cursors() {
        let (runtime, session, query) = runtime();
        let source = mdd_types::sha256(b"source-a");
        let cursor = runtime
            .open_cursor_with_spec(&session, &query, spec(&source))
            .unwrap();
        let before = runtime.cursor_binding(&session, &query, &cursor).unwrap();
        assert_eq!(before.worker_generation, DecimalU64(0));
        // Attaching a supervisor means a new worker instance owns the registry.
        let lease = runtime.claim_supervision().unwrap();
        let error = runtime
            .cursor_binding(&session, &query, &cursor)
            .unwrap_err();
        assert_eq!(error.details["page_error"], "worker_generation_changed");
        assert_eq!(error.details["worker_generation"], "0");
        assert_eq!(error.details["current_worker_generation"], "1");
        // A cursor opened under the new generation is accepted.
        let fresh = runtime
            .open_cursor_with_spec(&session, &query, spec(&source))
            .unwrap();
        let after = runtime.cursor_binding(&session, &query, &fresh).unwrap();
        assert_eq!(after.worker_generation, DecimalU64(1));
        assert_eq!(after.worker_owner, before.worker_owner);
        drop(lease);
        // Dropping the lease does not revive the older cursor; the generation
        // only moves forward.
        assert_eq!(
            runtime
                .cursor_binding(&session, &query, &cursor)
                .unwrap_err()
                .details["page_error"],
            "worker_generation_changed"
        );
    }

    #[test]
    fn cursor_requires_a_complete_fingerprint_spec() {
        let error = CursorSpec::new(
            "not-a-hash",
            mdd_types::sha256(b"p"),
            mdd_types::sha256(b"s"),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("ast_fingerprint"));
        let error = CursorSpec::new(
            mdd_types::sha256(b"a"),
            mdd_types::sha256(b"p").to_uppercase(),
            mdd_types::sha256(b"s"),
        )
        .unwrap_err();
        assert!(error.message.contains("parameter_types_fingerprint"));
    }

    #[test]
    fn same_sql_same_schema_different_source_cannot_be_stitched() {
        let (runtime, session, query) = runtime();
        let first = mdd_types::sha256(b"source-a");
        let cursor = runtime
            .open_cursor_with_spec(&session, &query, spec(&first))
            .unwrap();
        // Page 1 establishes the claim.
        runtime
            .validate_page_continuation(&session, &query, &cursor, &claim(Some(2), &first))
            .unwrap();
        // Page 2 keeps SQL, row count and schema identical but reads another source.
        let error = runtime
            .validate_page_continuation(
                &session,
                &query,
                &cursor,
                &claim(Some(2), &mdd_types::sha256(b"source-b")),
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidCursor);
        assert_eq!(error.details["page_error"], "source_changed");
        assert_eq!(error.details["source_fingerprint"], first);
        // The counterexample above is exactly what must not silently merge: the
        // accepted claim is unchanged and a repeat of page 2 with the original
        // source still works.
        runtime
            .validate_page_continuation(&session, &query, &cursor, &claim(Some(2), &first))
            .unwrap();
    }

    #[test]
    fn changed_schema_or_total_between_pages_is_rejected() {
        let (runtime, session, query) = runtime();
        let source = mdd_types::sha256(b"source-a");
        let cursor = runtime
            .open_cursor_with_spec(&session, &query, spec(&source))
            .unwrap();
        runtime
            .validate_page_continuation(&session, &query, &cursor, &claim(Some(4), &source))
            .unwrap();
        let mut different_total = claim(Some(5), &source);
        let error = runtime
            .validate_page_continuation(&session, &query, &cursor, &different_total)
            .unwrap_err();
        assert_eq!(error.details["page_error"], "query_schema_or_total_changed");
        different_total.total_rows = None;
        let error = runtime
            .validate_page_continuation(&session, &query, &cursor, &different_total)
            .unwrap_err();
        assert_eq!(error.details["page_error"], "query_schema_or_total_changed");
        let mut different_schema = claim(Some(4), &source);
        different_schema.schema_id = "mdd.rows.v1:other".to_owned();
        let error = runtime
            .validate_page_continuation(&session, &query, &cursor, &different_schema)
            .unwrap_err();
        assert_eq!(error.details["page_error"], "query_schema_or_total_changed");
        // Only the first accepted page counted; the three rejections above did not.
        assert_eq!(runtime.cursor_page_count(&cursor).unwrap(), 1);
        runtime
            .validate_page_continuation(&session, &query, &cursor, &claim(Some(4), &source))
            .unwrap();
        assert_eq!(runtime.cursor_page_count(&cursor).unwrap(), 2);
    }

    #[test]
    fn inexact_total_is_also_fixed_by_the_first_page() {
        let (runtime, session, query) = runtime();
        let source = mdd_types::sha256(b"source-a");
        let cursor = runtime
            .open_cursor_with_spec(&session, &query, spec(&source))
            .unwrap();
        // First page declares no exact total; a later page cannot invent one.
        runtime
            .validate_page_continuation(&session, &query, &cursor, &claim(None, &source))
            .unwrap();
        let error = runtime
            .validate_page_continuation(&session, &query, &cursor, &claim(Some(2), &source))
            .unwrap_err();
        assert_eq!(error.details["page_error"], "query_schema_or_total_changed");
        assert_eq!(error.details["total_rows"], "none");
    }

    #[test]
    fn response_paging_over_a_relational_limit_is_rejected() {
        let (runtime, _, _) = runtime();
        let max = 100;
        let native = PageRequestShape {
            mode: CursorMode::NativeSnapshot,
            page_limit: 10,
            continuation: None,
            offset: None,
            relation_limit: Some(100),
            relation_offset: None,
        };
        let error = runtime.validate_page_request(&native, max).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidCursor);
        assert_eq!(
            error.details["page_error"],
            "response_paging_over_relation_limit"
        );
        let offset_first_page = PageRequestShape {
            mode: CursorMode::CompatOffset,
            relation_offset: Some(5),
            relation_limit: None,
            ..native.clone()
        };
        let error = runtime
            .validate_page_request(&offset_first_page, max)
            .unwrap_err();
        assert_eq!(
            error.details["page_error"],
            "response_paging_over_relation_limit"
        );
        // Without a relational LIMIT/OFFSET the same shape is admissible.
        let clean = PageRequestShape {
            relation_limit: None,
            relation_offset: None,
            ..native
        };
        runtime.validate_page_request(&clean, max).unwrap();
    }

    #[test]
    fn paging_modes_never_share_a_token() {
        let (runtime, _, _) = runtime();
        let max = 100;
        let native_with_offset = PageRequestShape {
            mode: CursorMode::NativeSnapshot,
            page_limit: 10,
            continuation: None,
            offset: Some(10),
            relation_limit: None,
            relation_offset: None,
        };
        let error = runtime
            .validate_page_request(&native_with_offset, max)
            .unwrap_err();
        assert_eq!(
            error.details["page_error"],
            "compat_offset_under_native_cursor"
        );
        let compat_with_cursor = PageRequestShape {
            mode: CursorMode::CompatOffset,
            continuation: Some("cursor-token".into()),
            offset: None,
            ..native_with_offset
        };
        let error = runtime
            .validate_page_request(&compat_with_cursor, max)
            .unwrap_err();
        assert_eq!(
            error.details["page_error"],
            "native_cursor_under_compat_offset"
        );
        let both = PageRequestShape {
            continuation: Some("cursor-token".into()),
            offset: Some(10),
            ..compat_with_cursor
        };
        let error = runtime.validate_page_request(&both, max).unwrap_err();
        assert_eq!(error.details["page_error"], "ambiguous_continuation");
        let zero = PageRequestShape {
            page_limit: 0,
            ..native_with_offset
        };
        assert_eq!(
            runtime
                .validate_page_request(&zero, max)
                .unwrap_err()
                .details["page_error"],
            "page_limit_zero"
        );
        let oversized = PageRequestShape {
            page_limit: 101,
            ..zero
        };
        assert_eq!(
            runtime
                .validate_page_request(&oversized, max)
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        // A response can never carry both continuation forms.
        assert_eq!(
            PageResponseMetadata::compat(Some(DecimalU64(10)), true)
                .unwrap()
                .next_cursor,
            None
        );
        let mut forged = PageResponseMetadata::compat(Some(DecimalU64(10)), true).unwrap();
        forged.next_cursor = Some("cursor-token".into());
        assert_eq!(
            forged.validate().unwrap_err().details["page_error"],
            "paging_mode_conflict"
        );
        let mut native = PageResponseMetadata::native("cursor-token".into(), true).unwrap();
        native.more_available = false;
        assert_eq!(
            native.validate().unwrap_err().details["page_error"],
            "paging_more_available_mismatch"
        );
    }

    #[test]
    fn compat_offset_walks_pages_with_lookahead_and_no_cursor() {
        let (runtime, session, query) = runtime();
        let source = mdd_types::sha256(b"source-a");
        let mut offset = runtime
            .open_compat_offset(
                &session,
                &query,
                &spec(&source),
                CompatOffsetContract::new(2, 8, 10).unwrap(),
            )
            .unwrap();
        assert_eq!(offset.session_id(), session.id());
        assert_eq!(offset.query_id(), query.id());
        let first = offset.next_request().unwrap().unwrap();
        assert_eq!(first.offset, DecimalU64(0));
        assert_eq!(first.limit, DecimalU64(2));
        let admitted = offset
            .admit(CompatOffsetPage {
                offset: 0,
                limit: 2,
                rows: 2,
                schema_id: "mdd.rows.v1:page-schema".into(),
                total_rows: Some(3),
                source_fingerprint: source.clone(),
                catalog_epoch: DecimalU64(0),
                sql_matches: true,
                relation_limit: None,
                relation_offset: None,
                lookahead_exhausted: false,
            })
            .unwrap();
        assert!(admitted.more_available);
        assert_eq!(admitted.next_offset, Some(DecimalU64(2)));
        assert_eq!(admitted.reexecutions, DecimalU64(1));
        let metadata = admitted.metadata().unwrap();
        assert_eq!(metadata.mode, CursorMode::CompatOffset);
        assert_eq!(metadata.next_cursor, None);
        assert_eq!(metadata.next_offset, Some(DecimalU64(2)));
        assert_eq!(
            offset.next_request().unwrap().unwrap().offset,
            DecimalU64(2)
        );
        // The final page proves the lookahead row is absent.
        let admitted = offset
            .admit(CompatOffsetPage {
                offset: 2,
                limit: 1,
                rows: 1,
                schema_id: "mdd.rows.v1:page-schema".into(),
                total_rows: Some(3),
                source_fingerprint: source.clone(),
                catalog_epoch: DecimalU64(0),
                sql_matches: true,
                relation_limit: None,
                relation_offset: None,
                lookahead_exhausted: true,
            })
            .unwrap();
        assert!(!admitted.more_available);
        assert_eq!(admitted.next_offset, None);
        assert!(offset.is_done());
        assert!(offset.next_request().unwrap().is_none());
        assert_eq!(
            offset
                .admit(CompatOffsetPage {
                    offset: 3,
                    limit: 1,
                    rows: 0,
                    schema_id: "mdd.rows.v1:page-schema".into(),
                    total_rows: Some(3),
                    source_fingerprint: source.clone(),
                    catalog_epoch: DecimalU64(0),
                    sql_matches: true,
                    relation_limit: None,
                    relation_offset: None,
                    lookahead_exhausted: true,
                })
                .unwrap_err()
                .details["page_error"],
            "offset_sequence_complete"
        );
    }

    #[test]
    fn compat_offset_rejects_offset_gaps_source_change_and_missing_lookahead() {
        let (runtime, session, query) = runtime();
        let source = mdd_types::sha256(b"source-a");
        let mut offset = runtime
            .open_compat_offset(
                &session,
                &query,
                &spec(&source),
                CompatOffsetContract::new(4, 8, 16).unwrap(),
            )
            .unwrap();
        let page = |offset_value: u64, rows: u64, source: &str| CompatOffsetPage {
            offset: offset_value,
            limit: 4,
            rows,
            schema_id: "mdd.rows.v1:page-schema".into(),
            total_rows: Some(8),
            source_fingerprint: source.to_owned(),
            catalog_epoch: DecimalU64(0),
            sql_matches: true,
            relation_limit: None,
            relation_offset: None,
            lookahead_exhausted: false,
        };
        // Skipping ahead is not a continuation.
        let error = offset.admit(page(4, 4, &source)).unwrap_err();
        assert_eq!(
            error.details["page_error"],
            "query_page_identity_or_limit_mismatch"
        );
        // Same SQL, same row count, different source.
        let error = offset
            .admit(page(0, 4, &mdd_types::sha256(b"source-b")))
            .unwrap_err();
        assert_eq!(error.details["page_error"], "source_changed");
        // A short page without a lookahead probe cannot claim exhaustion.
        let error = offset.admit(page(0, 3, &source)).unwrap_err();
        assert_eq!(error.details["page_error"], "lookahead_required");
        // Relational LIMIT is a relation operator, never compatible-offset paging.
        let mut mixed = page(0, 4, &source);
        mixed.relation_limit = Some(100);
        let error = offset.admit(mixed).unwrap_err();
        assert_eq!(
            error.details["page_error"],
            "response_paging_over_relation_limit"
        );
        // Nothing above was admitted.
        assert_eq!(offset.reexecutions(), 0);
        assert_eq!(offset.admitted_rows(), 0);
        // The valid page still works afterwards.
        offset.admit(page(0, 4, &source)).unwrap();
        assert_eq!(offset.reexecutions(), 1);
    }

    #[test]
    fn compat_offset_budget_and_epoch_observation_are_explicit() {
        let (runtime, session, query) = runtime();
        let source = mdd_types::sha256(b"source-a");
        let mut offset = runtime
            .open_compat_offset(
                &session,
                &query,
                &spec(&source),
                CompatOffsetContract::new(1, 2, 8).unwrap(),
            )
            .unwrap();
        let page = |offset_value: u64, epoch: u64| CompatOffsetPage {
            offset: offset_value,
            limit: 1,
            rows: 1,
            schema_id: "mdd.rows.v1:page-schema".into(),
            total_rows: None,
            source_fingerprint: source.clone(),
            catalog_epoch: DecimalU64(epoch),
            sql_matches: true,
            relation_limit: None,
            relation_offset: None,
            lookahead_exhausted: false,
        };
        // Compatible offset may observe a new catalog generation per request.
        let first = offset.admit(page(0, 0)).unwrap();
        assert_eq!(first.catalog_epochs_observed, vec![DecimalU64(0)]);
        let second = offset.admit(page(1, 1)).unwrap();
        assert_eq!(
            second.catalog_epochs_observed,
            vec![DecimalU64(0), DecimalU64(1)]
        );
        // The third execution exceeds max_executions and is refused.
        let error = offset.admit(page(2, 2)).unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
        assert_eq!(error.details["budget"], "max_executions");
        assert_eq!(offset.admitted_rows(), 2);
    }

    fn offset_page(
        offset: u64,
        limit: u64,
        rows: u64,
        total: Option<u64>,
        lookahead_exhausted: bool,
        source: &str,
    ) -> CompatOffsetPage {
        CompatOffsetPage {
            offset,
            limit,
            rows,
            schema_id: "mdd.rows.v1:page-schema".into(),
            total_rows: total,
            source_fingerprint: source.to_owned(),
            catalog_epoch: DecimalU64(0),
            sql_matches: true,
            relation_limit: None,
            relation_offset: None,
            lookahead_exhausted,
        }
    }

    fn compat(contract: CompatOffsetContract) -> (CompatOffsetState, String) {
        let (runtime, session, query) = runtime();
        let source = mdd_types::sha256(b"source-a");
        let state = runtime
            .open_compat_offset(&session, &query, &spec(&source), contract)
            .unwrap();
        (state, source)
    }

    #[test]
    fn an_exact_total_that_the_first_page_reaches_ends_the_sequence() {
        let (mut state, source) = compat(CompatOffsetContract::new(3, 8, 10).unwrap());
        // Consistent claims: three rows, exact total three, lookahead proves the end.
        let admitted = state
            .admit(offset_page(0, 3, 3, Some(3), true, &source))
            .unwrap();
        assert!(!admitted.more_available);
        assert_eq!(admitted.next_offset, None);
        assert!(state.is_done());

        // The same page whose lookahead row exists contradicts the exact total.
        // The first page used to be accepted with a phantom continuation at
        // offset 3, because the total was only consulted from the second page on.
        let (mut state, source) = compat(CompatOffsetContract::new(3, 8, 10).unwrap());
        let error = state
            .admit(offset_page(0, 3, 3, Some(3), false, &source))
            .unwrap_err();
        assert_eq!(error.details["page_error"], "total_conflicts_with_page");
        assert_eq!(state.reexecutions(), 0, "a rejected page is not admitted");
        assert!(!state.is_done());
    }

    #[test]
    fn pages_that_disagree_with_the_exact_total_are_rejected() {
        // More rows than the exact total allows.
        let (mut state, source) = compat(CompatOffsetContract::new(3, 8, 10).unwrap());
        let error = state
            .admit(offset_page(0, 3, 3, Some(2), true, &source))
            .unwrap_err();
        assert_eq!(error.details["page_error"], "total_conflicts_with_page");

        // The lookahead claims the end while the exact total says more rows exist.
        let (mut state, source) = compat(CompatOffsetContract::new(4, 8, 16).unwrap());
        let error = state
            .admit(offset_page(0, 4, 4, Some(10), true, &source))
            .unwrap_err();
        assert_eq!(error.details["page_error"], "total_conflicts_with_page");

        // A short page that stops before the exact total.
        let (mut state, source) = compat(CompatOffsetContract::new(4, 8, 16).unwrap());
        let error = state
            .admit(offset_page(0, 4, 3, Some(10), true, &source))
            .unwrap_err();
        assert_eq!(error.details["page_error"], "total_conflicts_with_page");

        // Later pages are held to the total fixed by the first one: reaching it
        // while the lookahead row still exists is a contradiction, not an end.
        let (mut state, source) = compat(CompatOffsetContract::new(4, 8, 16).unwrap());
        state
            .admit(offset_page(0, 4, 4, Some(8), false, &source))
            .unwrap();
        let error = state
            .admit(offset_page(4, 4, 4, Some(8), false, &source))
            .unwrap_err();
        assert_eq!(error.details["page_error"], "total_conflicts_with_page");
        assert_eq!(
            state.admitted_rows(),
            4,
            "the contradicting page was refused"
        );
        let admitted = state
            .admit(offset_page(4, 4, 4, Some(8), true, &source))
            .unwrap();
        assert!(!admitted.more_available);
        assert!(state.is_done());
    }

    #[test]
    fn exhausting_the_row_budget_is_reported_not_presented_as_the_end() {
        let (mut state, source) = compat(CompatOffsetContract::new(2, 8, 2).unwrap());
        let admitted = state
            .admit(offset_page(0, 2, 2, None, false, &source))
            .unwrap();
        // The page says more rows may exist, so the sequence is not complete.
        assert!(admitted.more_available);
        assert!(!state.is_done());
        // `Ok(None)` would let a driver loop treat this as a finished sequence
        // and silently truncate the result.
        let error = state.next_request().unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
        assert_eq!(error.details["budget"], "max_rows");
    }
}
