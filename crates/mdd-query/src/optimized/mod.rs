//! Opt-in and toggleable query hot-path helpers (`MDD-061`).
//!
//! Every helper here is strictly backend/domain-neutral and semantically
//! identical to its scalar reference counterpart.

pub mod compiled_like;
pub mod prefix_set;
pub mod schema_memo;

pub use compiled_like::{CompiledLike, LikeCompileError, LikeFlavor, LikeShape};
pub use prefix_set::{
    AsciiPrefixSet, matches_ascii_ci_prefix, matches_ascii_ci_prefix_suffix,
    matches_utf16_ascii_ci_prefix, matches_utf16_ascii_ci_prefix_suffix,
};
pub use schema_memo::SchemaMemo;
