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
}
/// Own the Arc and ordinal/iterator state. No self-referential borrowed scan.
pub trait SqlFactCursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>>;
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
