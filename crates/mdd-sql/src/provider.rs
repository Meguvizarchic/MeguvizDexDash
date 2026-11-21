use crate::control::SqlControl;
use crate::{
    dialects::SqlDialect,
    invalid,
    values::{SqlType, SqlValue},
};
use mdd_query::ir::FactLayer;
use mdd_types::{DecimalU64, ErrorCode, MddResult};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
pub mod hostlab;
pub mod metadata;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SqlBinding {
    pub provider_identity: String,
    pub snapshot_id: String,
    pub catalog_epoch: DecimalU64,
}
/// One declared compatibility profile: the frozen profile identifier from the
/// compatibility ledger plus the SQL text policy used to serve it.
///
/// Creating this value admits nothing. It only names the scope a query runs in
/// so that a later compatibility failure can be attributed and blocked. Any
/// positive admission decision belongs to the profile qualification task and to
/// `compatibility/ledger.json`, never to this crate.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct CompatibilityProfile {
    pub name: String,
    pub dialect: SqlDialect,
}
impl CompatibilityProfile {
    pub fn new(name: impl Into<String>, dialect: SqlDialect) -> MddResult<Self> {
        let name = name.into();
        if name.is_empty() || name.contains('\0') {
            return Err(invalid("EMPTY_COMPATIBILITY_PROFILE"));
        }
        Ok(Self { name, dialect })
    }
}

/// Concrete, preserved evidence that one profile is no longer usable.
///
/// Only a real `UNSUPPORTED_QUERY` produced by the bridge creates a block.
/// Syntax/binding errors, quota, cancellation, deadline and provider failures
/// are not compatibility gaps; blocking on them would withdraw a profile for
/// reasons unrelated to semantic coverage, so they are deliberately excluded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompatibilityBlock {
    /// Profile name copied from [`CompatibilityProfile`].
    pub profile: String,
    pub dialect: SqlDialect,
    /// Bridge entry point that observed the gap: `prepare` or `execute`.
    pub stage: String,
    pub code: ErrorCode,
    pub message: String,
    /// The exact failing statement. This is the counterexample; it is kept
    /// verbatim (bounded by the SQL byte limit that admitted it).
    pub sql: String,
    pub sql_sha256: String,
}

/// Explicit, caller-owned register of blocked compatibility profiles.
///
/// The registry records losses only; it has no "admit" operation. The first
/// counterexample per `(profile, dialect)` is retained, and any later query
/// under that profile fails closed with `UNSUPPORTED_CAPABILITY` carrying that
/// counterexample instead of being answered as if the profile were still whole.
///
/// Locality is deliberate: a block is enforced only for bridges constructed
/// with the same registry, so a compatibility loss cannot silently leak into an
/// unrelated provider, snapshot or development probe. A qualification runner
/// shares one registry across the bridges of one profile run; the block then
/// outlives the individual query that discovered it.
#[derive(Default)]
pub struct CompatibilityProfileRegistry {
    blocks: Mutex<BTreeMap<CompatibilityProfile, CompatibilityBlock>>,
}
impl std::fmt::Debug for CompatibilityProfileRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompatibilityProfileRegistry")
            .field("blocked", &self.blocked_count())
            .finish()
    }
}
impl CompatibilityProfileRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock without treating poisoning as "no blocks": a panic elsewhere must
    /// not turn an unavailable profile back into a usable one.
    fn guard(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<CompatibilityProfile, CompatibilityBlock>> {
        self.blocks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Record `block` unless this profile already has one. Returns true only
    /// when this call was the one that blocked the profile, so callers can mark
    /// exactly the counterexample that caused the transition.
    pub fn block(&self, block: CompatibilityBlock) -> bool {
        let key = CompatibilityProfile {
            name: block.profile.clone(),
            dialect: block.dialect,
        };
        let mut blocks = self.guard();
        if blocks.contains_key(&key) {
            return false;
        }
        blocks.insert(key, block);
        true
    }

    /// The preserved counterexample for `profile`, if that profile is blocked.
    pub fn block_for(&self, profile: &CompatibilityProfile) -> Option<CompatibilityBlock> {
        self.guard().get(profile).cloned()
    }

    pub fn is_blocked(&self, profile: &CompatibilityProfile) -> bool {
        self.guard().contains_key(profile)
    }

    /// Every block, ordered by profile name then dialect.
    pub fn blocks(&self) -> Vec<CompatibilityBlock> {
        self.guard().values().cloned().collect()
    }

    /// Blocked profile names, sorted and deduplicated.
    pub fn blocked_profiles(&self) -> Vec<String> {
        let mut names = self
            .guard()
            .keys()
            .map(|profile| profile.name.clone())
            .collect::<Vec<_>>();
        names.dedup();
        names
    }

    pub fn blocked_count(&self) -> usize {
        self.guard().len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SqlColumn {
    pub id: String,
    pub name: String,
    pub data_type: SqlType,
    pub nullable: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SqlRelation {
    pub name: String,
    pub columns: Vec<SqlColumn>,
    pub required_layers: Vec<FactLayer>,
    pub estimated_rows: Option<DecimalU64>,
}
pub type SqlRow = Vec<SqlValue>;

/// Sound monotonic predicate tree extracted for candidate-row indexing on a single relation.
/// Column names are normalized to ASCII lower case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RowFilter {
    EqU64(String, u64),
    InU64(String, Vec<u64>),
    BetweenU64(String, u64, u64),
    EqText(String, String),
    InText(String, Vec<String>),
    /// ASCII case-insensitive literal prefix extracted from `LIKE '...' [ESCAPE '...']` before any wildcard.
    LikeAsciiPrefix(String, String),
    /// Non-overlapping ASCII case-insensitive literal `(column, lower_prefix, lower_suffix)` from `LIKE 'pre%suf'`.
    LikeAsciiPrefixSuffix(String, String, String),
    /// ASCII case-insensitive substring literal `(column, lower_needle)` from `LIKE '%needle%'`.
    LikeAsciiContains(String, String),
    And(Vec<RowFilter>),
    Or(Vec<RowFilter>),
}

/// Equality join edge across two base relations (`INNER JOIN` / comma join `ON` conjuncts).
/// Both relation names and column names are normalized to ASCII lower case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EquiJoinEdge {
    pub left_relation: String,
    pub right_relation: String,
    pub columns: Vec<(String, String)>,
}

/// Direct single-table projection descriptor eligible to bypass SQLite VM overhead when unbounded/unfiltered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectTableProjection {
    pub relation: String,
    pub projected_columns: Vec<(usize, String)>,
    pub order_by_u64_asc: Vec<usize>,
}

/// Output projection item for an unfiltered single-table `GROUP BY ... COUNT(*)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectGroupItem {
    GroupCol {
        group_pos: usize,
        output_name: String,
    },
    CountStar {
        output_name: String,
    },
}

/// Direct single-table unfiltered `GROUP BY <1..=4 direct cols> [ORDER BY ...]` plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectCountGroupBy {
    pub relation: String,
    pub group_columns: Vec<usize>,
    pub projections: Vec<DirectGroupItem>,
    pub order_by_group_asc: Vec<usize>,
}

/// Candidate row selection passed from query planning to a virtual table scan.
#[derive(Clone, Debug)]
pub enum PlannedScan {
    All {
        estimated_rows: Option<u64>,
    },
    Partition {
        key: u64,
        estimated_rows: Option<u64>,
    },
    Rows(Arc<[u32]>),
}

impl PlannedScan {
    pub fn estimated_rows(&self) -> Option<u64> {
        match self {
            Self::All { estimated_rows } | Self::Partition { estimated_rows, .. } => {
                *estimated_rows
            }
            Self::Rows(rows) => Some(rows.len() as u64),
        }
    }
}

/// Provider owns one immutable source generation. Opening a cursor may build
/// required facts, but schema/optimizer callbacks must never do so.
pub trait SqlFactProvider: Send + Sync {
    fn binding(&self) -> &SqlBinding;
    fn relations(&self) -> MddResult<Vec<SqlRelation>>;
    fn require_relation(&self, relation: &str) -> MddResult<()>;
    fn open_cursor(
        self: Arc<Self>,
        relation: &str,
        control: SqlControl,
    ) -> MddResult<Box<dyn SqlFactCursor>>;
    /// The column of `relation` whose value picks one contiguous group of its rows (for the HostLab relations, `file_id`:
    /// the rows of a DEX are stored together), if the provider can read just that group. `None` for a provider that
    /// cannot. Metadata only, like the rest of the optimizer's questions.
    fn partition_column(&self, _relation: &str) -> Option<&'static str> {
        None
    }
    /// `open_cursor`, for a statement that cannot use any row whose partition column is not `key`. The cursor may return
    /// only those rows or all of them: the statement filters either way, so the answer is the same and only the time
    /// differs. The default returns all of them.
    fn open_cursor_for_partition(
        self: Arc<Self>,
        relation: &str,
        control: SqlControl,
        _key: u64,
    ) -> MddResult<Box<dyn SqlFactCursor>> {
        self.open_cursor(relation, control)
    }

    /// Sound candidate scans for the required relations, combining single-table predicates,
    /// equi-join edges, and partition hints. Every returned scan must contain a superset of
    /// matching rows; the SQL engine still evaluates the full query predicate on them.
    fn plan_scans(
        &self,
        _required_relations: &[String],
        _row_filters: &BTreeMap<String, RowFilter>,
        _equi_joins: &[EquiJoinEdge],
        partition_hints: &BTreeMap<String, u64>,
    ) -> MddResult<BTreeMap<String, PlannedScan>> {
        Ok(partition_hints
            .iter()
            .map(|(relation, key)| {
                (
                    relation.clone(),
                    PlannedScan::Partition {
                        key: *key,
                        estimated_rows: None,
                    },
                )
            })
            .collect())
    }

    /// Open a cursor restricted to the candidate set in `scan`.
    fn open_planned_cursor(
        self: Arc<Self>,
        relation: &str,
        control: SqlControl,
        scan: &PlannedScan,
    ) -> MddResult<Box<dyn SqlFactCursor>> {
        match scan {
            PlannedScan::All { .. } | PlannedScan::Rows(_) => self.open_cursor(relation, control),
            PlannedScan::Partition { key, .. } => {
                self.open_cursor_for_partition(relation, control, *key)
            }
        }
    }

    /// Optional fast path for unfiltered single-table projections ordered by ascending U64 keys.
    fn try_direct_projection(
        &self,
        _projection: &DirectTableProjection,
        _control: &SqlControl,
    ) -> Option<MddResult<Vec<SqlRow>>> {
        None
    }

    /// Optional zero-row-materialization streaming fast path for direct table projections.
    fn try_stream_direct_projection(
        &self,
        _projection: &DirectTableProjection,
        _control: &SqlControl,
        _consumer: &mut dyn crate::column_store::DirectCellRowConsumer,
    ) -> MddResult<bool> {
        Ok(false)
    }

    /// Optional fast path for unfiltered single-table `GROUP BY ... COUNT(*)`.
    fn try_direct_count_group_by(
        &self,
        _plan: &DirectCountGroupBy,
        _control: &SqlControl,
    ) -> Option<MddResult<Vec<SqlRow>>> {
        None
    }
}
/// Own the Arc and ordinal/iterator state. No self-referential borrowed scan.
pub trait SqlFactCursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>>;
    /// A cursor that can be read cell by cell, without building the rest of the row, says so here. The default is a
    /// cursor that only hands out whole rows.
    fn positioned(&mut self) -> Option<&mut dyn PositionedCursor> {
        None
    }
    /// `positioned`, to read a cell while the cursor is only borrowed.
    fn positioned_ref(&self) -> Option<&dyn PositionedCursor> {
        None
    }
}
/// A cursor that stands on a row and gives a column of it when asked. A statement that reads two columns of a
/// ten-column row builds two cells.
pub trait PositionedCursor {
    /// Move to the next row; `false` when there is none. Each row counts against the statement's budget as `next_row`'s
    /// does.
    fn advance(&mut self) -> MddResult<bool>;
    /// The cell of `column` in the row the cursor stands on.
    fn value(&self, column: usize) -> MddResult<SqlValue>;
    /// Optional fast encoding directly to `rusqlite::types::Value` without constructing an intermediate `SqlValue`.
    fn sqlite_value(
        &self,
        _column: usize,
        _max_cell_bytes: u64,
    ) -> Option<MddResult<rusqlite::types::Value>> {
        None
    }
    /// Optional zero-heap stack write directly into SQLite `Context` for bounded cells.
    fn set_sqlite_column(
        &self,
        _column: usize,
        _max_cell_bytes: u64,
        _context: &mut rusqlite::vtab::Context,
    ) -> Option<MddResult<rusqlite::Result<()>>> {
        None
    }
    /// An upper bound on the size of any cell the cursor will give. A caller that limits the size of a cell and finds the
    /// bound within the limit need not look at each cell.
    fn max_cell_bytes(&self) -> u64;
}

pub(crate) fn validate_row(row: &SqlRow, columns: &[SqlColumn]) -> MddResult<()> {
    if row.len() != columns.len() {
        return Err(invalid("PROVIDER_ROW_WIDTH"));
    }
    for (value, column) in row.iter().zip(columns) {
        if value == &SqlValue::Null {
            if !column.nullable {
                return Err(invalid("PROVIDER_UNEXPECTED_NULL"));
            }
        } else if value.data_type() != Some(column.data_type) {
            return Err(invalid("PROVIDER_ROW_TYPE"));
        }
    }
    Ok(())
}
