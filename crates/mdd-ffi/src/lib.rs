//! Stable C ABI (major 1) over the generic core.
//!
//! `engine` is the safe core and can be tested without any pointer. `handle`
//! turns its objects into generation-tagged 64-bit handles. `abi` exports the
//! `mdd_*` symbols declared in `include/mdd.h`.
pub mod abi;
pub mod codec;
pub mod engine;
pub mod error;
pub mod handle;
