//! Which byte stream a writer is attached to, and the guard for MCP stdout.
//!
//! MCP stdout carries MCP JSON messages and nothing else; binary frames, logs and
//! progress text live on the dedicated worker channel and stderr.
use crate::error::{WireError, WireErrorKind, WireResult};
use crate::frame::MAGIC;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelKind {
    /// The pipe or socket between the façade and a local worker.
    Dedicated,
    McpStdout,
    Stderr,
}

impl ChannelKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Dedicated => "the dedicated worker channel",
            Self::McpStdout => "MCP stdout",
            Self::Stderr => "stderr",
        }
    }
}

/// Accept only one complete MCP JSON-RPC message per write: UTF-8, a single JSON
/// object with `"jsonrpc":"2.0"`, no embedded line breaks (one trailing `\n` is
/// the message delimiter), and never a wire frame.
pub fn check_mcp_stdout_message(bytes: &[u8]) -> WireResult<()> {
    let violation = |why: &str| Err(WireError::new(WireErrorKind::McpStdoutViolation, why));
    if bytes.starts_with(&MAGIC) {
        return violation("a wire frame must not be written to MCP stdout");
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return violation("MCP stdout accepts UTF-8 text only");
    };
    let body = text.strip_suffix('\n').unwrap_or(text);
    if body.contains(['\n', '\r']) {
        return violation("an MCP message is exactly one line");
    }
    let Ok(Value::Object(object)) = serde_json::from_str::<Value>(body) else {
        return violation("an MCP message is one JSON object");
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return violation("an MCP message carries \"jsonrpc\":\"2.0\"");
    }
    Ok(())
}
