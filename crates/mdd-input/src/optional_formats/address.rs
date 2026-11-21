//! Strongly typed address spaces for optional multi-header formats (DEX `041`, etc.).
//!
//! `ContainerOffset`, `LogicalHeaderOffset`, and `CodeUnitPc` are distinct newtypes so offsets
//! relative to a physical container are never confused with header-relative offsets or PCs.

use mdd_types::{ErrorCode, MddError, MddResult};
use serde::{Deserialize, Serialize};

/// Byte offset from the start of a physical container (`0` of the physical file/blob).
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
pub struct ContainerOffset(pub u64);

/// Byte offset relative to a logical DEX header inside a container.
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
pub struct LogicalHeaderOffset(pub u64);

/// 16-bit code-unit program counter inside a Dalvik method body.
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
pub struct CodeUnitPc(pub u32);

impl ContainerOffset {
    pub fn checked_add(self, len: u64, stage: &str) -> MddResult<Self> {
        self.0.checked_add(len).map(Self).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidInput,
                stage,
                "container offset arithmetic overflow",
            )
            .detail("container_offset", self.0.to_string())
            .detail("length", len.to_string())
        })
    }

    pub fn from_u32(raw: u32) -> Self {
        Self(u64::from(raw))
    }

    pub fn to_logical(self, base: Self, stage: &str) -> MddResult<LogicalHeaderOffset> {
        self.0
            .checked_sub(base.0)
            .map(LogicalHeaderOffset)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidInput,
                    stage,
                    "container offset precedes logical header base",
                )
                .detail("container_offset", self.0.to_string())
                .detail("header_base", base.0.to_string())
            })
    }

    pub fn slice<'a>(self, container: &'a [u8], length: u64, stage: &str) -> MddResult<&'a [u8]> {
        let end = self.checked_add(length, stage)?.0;
        let total = container.len() as u64;
        if end > total {
            return Err(MddError::new(
                ErrorCode::InvalidInput,
                stage,
                "container range exceeds physical container bytes",
            )
            .detail("container_offset", self.0.to_string())
            .detail("length", length.to_string())
            .detail("container_bytes", total.to_string()));
        }
        let start_u = usize::try_from(self.0).map_err(|_| {
            MddError::new(ErrorCode::InvalidInput, stage, "offset exceeds host usize")
        })?;
        let end_u = usize::try_from(end)
            .map_err(|_| MddError::new(ErrorCode::InvalidInput, stage, "end exceeds host usize"))?;
        Ok(&container[start_u..end_u])
    }

    pub fn read_u32(self, container: &[u8], stage: &str) -> MddResult<u32> {
        let s = self.slice(container, 4, stage)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
}

impl LogicalHeaderOffset {
    pub fn resolve_in_container(
        self,
        base: ContainerOffset,
        stage: &str,
    ) -> MddResult<ContainerOffset> {
        base.checked_add(self.0, stage)
    }
}
