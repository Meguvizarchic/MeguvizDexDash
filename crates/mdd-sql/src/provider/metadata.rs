//! Native metadata relations read by occurrence and ordinal from immutable facts.
//! No legacy table projection or row-table ETL is implied.
use super::*;
use crate::{quota, values::SqlText};
use mdd_facts::{MetadataFacts, definitions::DefinitionFacts, metadata::StringFact};
use mdd_types::{Completeness, ErrorCode, MddError, opaque_id};
use std::collections::BTreeSet;

mod annotations;
mod code;
mod combined;
mod definitions;
mod meta;
mod references;

#[cfg(test)]
use self::code::code_bytes;
use self::{
    annotations::AnnotationRelation, code::CodeRelation, meta::MetadataRelation,
    references::is_reference_relation,
};
pub use self::{
    annotations::AnnotationSqlProvider, code::CodeSqlProvider, combined::CombinedSqlProvider,
    definitions::DefinitionSqlProvider, meta::MetadataSqlProvider,
    references::ReferenceSqlProvider,
};

///
/// Step accounting stays cell-granular: the total charged steps per cell are
/// exactly `2 × codepoints`, identical to the previous per-character form, but
/// they are charged in two calls instead of `2 × codepoints` calls. Every text
/// cell of every scanned row passes through here, so the per-character form
/// made the budget mutex plus `BudgetPool::charge` the dominant cost of a full
/// scan. Aborting at cell granularity is strictly conservative: the cell has
/// not been produced either way.
fn scalar_text(value: &str, control: &SqlControl) -> MddResult<SqlValue> {
    let mut count = 0usize;
    let mut char_count = 0u64;
    for ch in value.chars() {
        char_count += 1;
        count = count
            .checked_add(ch.len_utf16())
            .ok_or_else(|| quota("METADATA_SQL_CELL_OVERFLOW"))?;
    }
    control.checkpoint(char_count, false)?;
    let bytes = u64::try_from(count)
        .ok()
        .and_then(|n| n.checked_mul(2))
        .ok_or_else(|| quota("METADATA_SQL_CELL_OVERFLOW"))?;
    if bytes > control.inner.limits.max_cell_bytes {
        return Err(quota("METADATA_SQL_CELL_BYTES_BEFORE_CLONE"));
    }
    control.work(bytes)?;
    let mut units = Vec::new();
    units
        .try_reserve_exact(count)
        .map_err(|_| quota("METADATA_SQL_ALLOCATION"))?;
    for ch in value.chars() {
        let mut buf = [0u16; 2];
        units.extend_from_slice(ch.encode_utf16(&mut buf));
    }
    control.checkpoint(char_count, false)?;
    Ok(SqlValue::Text(SqlText {
        utf16: units,
        original_mutf8: None,
    }))
}

/// Preserve both UTF-16 and the original MUTF-8 bytes for a validated string fact.
fn source_text(fact: &StringFact, control: &SqlControl) -> MddResult<(SqlValue, SqlValue)> {
    let units = &fact.data.text.utf16_units;
    let raw = &fact.data.text.raw_mutf8;
    let raw_len = u64::try_from(raw.len()).map_err(|_| quota("METADATA_SQL_CELL_OVERFLOW"))?;
    let unit_len = u64::try_from(units.len())
        .ok()
        .and_then(|n| n.checked_mul(2))
        .ok_or_else(|| quota("METADATA_SQL_CELL_OVERFLOW"))?;
    let text_size = unit_len
        .checked_add(raw_len)
        .ok_or_else(|| quota("METADATA_SQL_CELL_OVERFLOW"))?;
    if text_size > control.inner.limits.max_cell_bytes
        || raw_len > control.inner.limits.max_cell_bytes
    {
        return Err(quota("METADATA_SQL_CELL_BYTES_BEFORE_CLONE"));
    }
    control.work(
        text_size
            .checked_add(raw_len)
            .ok_or_else(|| quota("METADATA_SQL_ROW_BYTES_OVERFLOW"))?,
    )?;
    let mut copied_units = Vec::new();
    let mut original = Vec::new();
    let mut raw_value = Vec::new();
    copied_units
        .try_reserve_exact(units.len())
        .map_err(|_| quota("METADATA_SQL_ALLOCATION"))?;
    original
        .try_reserve_exact(raw.len())
        .map_err(|_| quota("METADATA_SQL_ALLOCATION"))?;
    raw_value
        .try_reserve_exact(raw.len())
        .map_err(|_| quota("METADATA_SQL_ALLOCATION"))?;
    for chunk in units.chunks(4096) {
        control.checkpoint(1, false)?;
        copied_units.extend_from_slice(chunk);
    }
    for chunk in raw.chunks(4096) {
        control.checkpoint(1, false)?;
        original.extend_from_slice(chunk);
        raw_value.extend_from_slice(chunk);
    }
    Ok((
        SqlValue::Text(SqlText {
            utf16: copied_units,
            original_mutf8: Some(original),
        }),
        SqlValue::DexMutf8 {
            bytes: raw_value,
            utf16_code_units: DecimalU64(units.len() as u64),
        },
    ))
}

#[cfg(test)]
#[path = "metadata/tests.rs"]
mod tests;
