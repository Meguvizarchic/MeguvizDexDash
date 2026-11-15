//! What the command line and the MCP server share: an opened input set with its SQL
//! session (`dataset`) and the execution of one statement against it (`run`).
//!
//! Neither adapter has a parser, a fact builder or a result envelope of its own; both
//! read the same facts through this crate, so they cannot disagree about what a
//! statement means or how it ends.
pub mod dataset;
pub mod decode;
pub mod lines;
pub mod manifest;
pub mod run;

pub use dataset::{Dataset, Dialect, InputRequest, LayerIssue};
pub use run::{Batch, DEFAULT_BATCH_ROWS, MAX_BATCH_ROWS, Outcome, RunOptions, Sink};
