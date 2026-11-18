//! An MCP server on stdio over the MeguvizDexDash facts.
//!
//! This is the adapter, not an engine: datasets and statements come from
//! `mdd-service`, which reads the same fact layers as the command line. The server
//! speaks JSON-RPC 2.0 with one message per line, serves requests one at a time, and
//! writes nothing but protocol messages to stdout.
//!
//! Tools offered: `open_dataset`, `list_datasets`, `close_dataset`, `list_tables`,
//! `describe_table`, `query`, `decode`, `get_manifest`, `get_manifest_components`,
//! `list_resource_files`, `read_resource` and `query_resources`. Anything else is not listed
//! and is refused by name; a tool is registered only when it is implemented (see `tools`).
pub mod protocol;
pub mod resource_tools;
pub mod server;
pub mod tools;

pub use server::{Config, Server, run_stdio};
