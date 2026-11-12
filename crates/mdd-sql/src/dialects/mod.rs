//! Versioned text policies. A policy enum does not imply profile admission.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlDialect {
    NativeV1,
    DexSql010,
    DexSql011,
}
pub(crate) mod ast;
pub(crate) mod functions;
