//! The request loop: protocol state, dispatch and the stdio driver.
use crate::{
    protocol::{self, Message},
    tools::{self, Failure, Registry},
};
use mdd_service::lines::{Line, read_line};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};

pub use crate::tools::Config;

/// The largest message accepted. A larger line is refused and skipped.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

const INSTRUCTIONS: &str = "Tools: open_dataset, list_datasets, close_dataset, list_tables, describe_table, query. \
decode, get_manifest and the resource tools are not implemented and are not listed. \
Requests are served one at a time. A query that outlives its deadline closes its dataset.";

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    /// No `initialize` yet.
    Fresh,
    /// `initialize` was answered.
    Initialized,
}

pub struct Server {
    registry: Registry,
    phase: Phase,
}

impl Server {
    pub fn new(config: Config) -> Self {
        Self {
            registry: Registry::new(config),
            phase: Phase::Fresh,
        }
    }

    /// Answer one decoded message. `None` for a notification or a response.
    pub fn handle(&mut self, value: &Value) -> Option<Value> {
        match protocol::parse(value) {
            Err(response) => Some(response),
            Ok(Message::Notification { .. } | Message::Response) => None,
            Ok(Message::Request { id, method, params }) => Some(self.request(&id, &method, params)),
        }
    }

    fn request(&mut self, id: &Value, method: &str, params: Value) -> Value {
        if method == "ping" {
            return protocol::result(id, json!({}));
        }
        if method == "initialize" {
            return self.initialize(id, &params);
        }
        if self.phase == Phase::Fresh {
            return protocol::error(
                id,
                protocol::INVALID_REQUEST,
                "the session has not been initialized; send `initialize` first",
                None,
            );
        }
        match method {
            "tools/list" => {
                if params.get("cursor").is_some_and(|c| !c.is_null()) {
                    return protocol::error(
                        id,
                        protocol::INVALID_PARAMS,
                        "the tool list has a single page",
                        None,
                    );
                }
                protocol::result(id, json!({"tools": tools::definitions()}))
            }
            "tools/call" => self.call(id, &params),
            other => protocol::error(
                id,
                protocol::METHOD_NOT_FOUND,
                format!("method `{other}` is not supported"),
                None,
            ),
        }
    }

    fn initialize(&mut self, id: &Value, params: &Value) -> Value {
        if self.phase != Phase::Fresh {
            return protocol::error(
                id,
                protocol::INVALID_REQUEST,
                "the session is already initialized",
                None,
            );
        }
        let Some(asked) = params.get("protocolVersion").and_then(Value::as_str) else {
            return protocol::error(
                id,
                protocol::INVALID_PARAMS,
                "`protocolVersion` is required",
                None,
            );
        };
        let version = protocol::SUPPORTED_VERSIONS
            .iter()
            .find(|supported| **supported == asked)
            .unwrap_or(&protocol::SUPPORTED_VERSIONS[0]);
        self.phase = Phase::Initialized;
        protocol::result(
            id,
            json!({
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {
                    "name": "meguvizdexdash",
                    "title": "MeguvizDexDash",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "instructions": INSTRUCTIONS,
            }),
        )
    }

    fn call(&mut self, id: &Value, params: &Value) -> Value {
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return protocol::error(id, protocol::INVALID_PARAMS, "`name` is required", None);
        };
        let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
        if !arguments.is_null() && !arguments.is_object() {
            return protocol::error(
                id,
                protocol::INVALID_PARAMS,
                "`arguments` must be an object",
                None,
            );
        }
        match tools::call(&mut self.registry, name, arguments) {
            Ok(structured) => tool_result(id, structured, false),
            Err(Failure::InvalidParams(message)) => {
                protocol::error(id, protocol::INVALID_PARAMS, message, None)
            }
            Err(Failure::UnknownTool(name)) => protocol::error(
                id,
                protocol::INVALID_PARAMS,
                format!("unknown tool `{name}`"),
                None,
            ),
            Err(Failure::Execution(error)) => {
                let body = serde_json::to_value(&error).unwrap_or(Value::Null);
                tool_result(id, json!({"error": body}), true)
            }
        }
    }
}

/// A tool result: the structured content, and the same JSON as text for clients that
/// read only `content`.
fn tool_result(id: &Value, structured: Value, is_error: bool) -> Value {
    let text = serde_json::to_string(&structured).unwrap_or_else(|_| "{}".to_owned());
    protocol::result(
        id,
        json!({
            "content": [{"type": "text", "text": text}],
            "structuredContent": structured,
            "isError": is_error,
        }),
    )
}

/// Serve until the input ends. Only protocol messages are written to `out`. An `Err`
/// is a failure to write.
pub fn run_stdio(
    server: &mut Server,
    input: &mut impl BufRead,
    out: &mut impl Write,
) -> io::Result<()> {
    loop {
        let bytes = match read_line(input, MAX_MESSAGE_BYTES)? {
            Line::Eof => return Ok(()),
            Line::TooLong => {
                let response = protocol::error(
                    &Value::Null,
                    protocol::INVALID_REQUEST,
                    format!("a message may not exceed {MAX_MESSAGE_BYTES} bytes"),
                    None,
                );
                write_line(out, &response)?;
                continue;
            }
            Line::Text(bytes) => bytes,
        };
        let trimmed = bytes.trim_ascii();
        if trimmed.is_empty() {
            continue;
        }
        let response = match serde_json::from_slice::<Value>(trimmed) {
            Ok(value) => server.handle(&value),
            Err(error) => Some(protocol::error(
                &Value::Null,
                protocol::PARSE_ERROR,
                format!("not valid JSON: {error}"),
                None,
            )),
        };
        if let Some(response) = response {
            write_line(out, &response)?;
        }
    }
}

fn write_line(out: &mut impl Write, value: &Value) -> io::Result<()> {
    writeln!(out, "{value}")?;
    out.flush()
}
