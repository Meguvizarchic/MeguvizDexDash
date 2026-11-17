//! Row projections of the public relations beyond the seventeen HostLab contract names (MDD-070).
//!
//! Every function here reads a validated fact object and the bytes that object was built from; none of them
//! parses a DEX again. A relation is answered only when the layer that proves it is complete: the caller (the
//! SQL provider) refuses an absent or incomplete layer before it asks for rows, and each projection also checks
//! the completeness flag itself, so an unbuilt layer is never an empty table.
//!
//! `file_id` is the caller's catalog coordinate, as in every other row API of this crate.
pub mod annotations;
pub mod code;
pub mod debug;
pub mod tables;
pub mod values;

#[cfg(test)]
mod tests;

use crate::metadata::MetadataFacts;
use mdd_types::{Completeness, ErrorCode, MddError, MddResult};

/// A little-endian word at a byte offset of the validated DEX, or an internal fault: the offsets used here come
/// from the validated header and map, so a failed read means a fact object disagrees with its own bytes.
pub(crate) fn word32(bytes: &[u8], offset: u64, what: &'static str) -> MddResult<u32> {
    let fault = || {
        MddError::new(
            ErrorCode::InternalFault,
            "facts.public_relations",
            "a validated offset lies outside the DEX bytes",
        )
        .detail("item", what)
        .detail("byte_offset", offset.to_string())
    };
    let start = usize::try_from(offset).map_err(|_| fault())?;
    let end = start.checked_add(4).ok_or_else(fault)?;
    let slice = bytes.get(start..end).ok_or_else(fault)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub(crate) fn word16(bytes: &[u8], offset: u64, what: &'static str) -> MddResult<u16> {
    let fault = || {
        MddError::new(
            ErrorCode::InternalFault,
            "facts.public_relations",
            "a validated offset lies outside the DEX bytes",
        )
        .detail("item", what)
        .detail("byte_offset", offset.to_string())
    };
    let start = usize::try_from(offset).map_err(|_| fault())?;
    let end = start.checked_add(2).ok_or_else(fault)?;
    let slice = bytes.get(start..end).ok_or_else(fault)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

pub(crate) fn to_u32(value: u64, what: &'static str) -> MddResult<u32> {
    u32::try_from(value).map_err(|_| {
        MddError::new(
            ErrorCode::InternalFault,
            "facts.public_relations",
            "a validated value exceeds UInt32",
        )
        .detail("item", what)
    })
}

pub(crate) fn require_metadata(metadata: &MetadataFacts, relation: &'static str) -> MddResult<()> {
    if metadata.metadata_coverage() != Completeness::Complete {
        return Err(MddError::new(
            ErrorCode::IncompleteFacts,
            "facts.public_relations",
            "complete metadata is required",
        )
        .detail("relation", relation));
    }
    Ok(())
}

pub(crate) fn row_budget(count: usize, relation: &'static str) -> MddResult<()> {
    // The same ceiling the definition layer applies to its own tables.
    const MAX_ROWS: usize = 16 * 1024 * 1024;
    if count > MAX_ROWS {
        return Err(MddError::new(
            ErrorCode::QuotaExceeded,
            "facts.public_relations",
            "relation row budget exceeded",
        )
        .detail("relation", relation)
        .detail("reason", "PUBLIC_RELATION_ROW_BUDGET"));
    }
    Ok(())
}
