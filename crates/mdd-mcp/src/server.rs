//! The request loop: protocol state, dispatch and the stdio driver.
use crate::{
    protocol::{self, Message},
    tools::{self, CallResult, Failure, Registry},
};
use mdd_service::lines::{Line, read_line};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};

pub use crate::tools::Config;

/// The largest message accepted. A larger line is refused and skipped.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

const INSTRUCTIONS: &str = "Tools: open_dataset, list_datasets, close_dataset, list_tables, describe_table, query, decode, \
get_manifest, get_manifest_components, list_resource_files, read_resource, query_resources. \
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

enum ServerReply {
    Json(Value),
    ToolRaw {
        id: Value,
        structured_json: String,
        is_error: bool,
    },
}

impl ServerReply {
    fn into_value(self) -> Value {
        match self {
            Self::Json(value) => value,
            Self::ToolRaw {
                id,
                structured_json,
                is_error,
            } => {
                let structured: Value = serde_json::from_str(&structured_json)
                    .unwrap_or_else(|_| Value::Object(serde_json::Map::new()));
                protocol::result(
                    &id,
                    json!({
                        "content": [{"type": "text", "text": structured_json}],
                        "structuredContent": structured,
                        "isError": is_error,
                    }),
                )
            }
        }
    }
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
        self.handle_fast(value).map(ServerReply::into_value)
    }

    fn handle_fast(&mut self, value: &Value) -> Option<ServerReply> {
        match protocol::parse(value) {
            Err(response) => Some(ServerReply::Json(response)),
            Ok(Message::Notification { .. } | Message::Response) => None,
            Ok(Message::Request { id, method, params }) => Some(self.request(&id, &method, params)),
        }
    }

    fn request(&mut self, id: &Value, method: &str, params: Value) -> ServerReply {
        if method == "ping" {
            return ServerReply::Json(protocol::result(id, json!({})));
        }
        if method == "initialize" {
            return ServerReply::Json(self.initialize(id, &params));
        }
        if self.phase == Phase::Fresh {
            return ServerReply::Json(protocol::error(
                id,
                protocol::INVALID_REQUEST,
                "the session has not been initialized; send `initialize` first",
                None,
            ));
        }
        match method {
            "tools/list" => {
                if params.get("cursor").is_some_and(|c| !c.is_null()) {
                    return ServerReply::Json(protocol::error(
                        id,
                        protocol::INVALID_PARAMS,
                        "the tool list has a single page",
                        None,
                    ));
                }
                ServerReply::Json(protocol::result(id, json!({"tools": tools::definitions()})))
            }
            "tools/call" => self.call(id, &params),
            other => ServerReply::Json(protocol::error(
                id,
                protocol::METHOD_NOT_FOUND,
                format!("method `{other}` is not supported"),
                None,
            )),
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

    fn call(&mut self, id: &Value, params: &Value) -> ServerReply {
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return ServerReply::Json(protocol::error(
                id,
                protocol::INVALID_PARAMS,
                "`name` is required",
                None,
            ));
        };
        let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
        if !arguments.is_null() && !arguments.is_object() {
            return ServerReply::Json(protocol::error(
                id,
                protocol::INVALID_PARAMS,
                "`arguments` must be an object",
                None,
            ));
        }
        match tools::call_fast(&mut self.registry, name, arguments) {
            Ok(CallResult::Value(structured)) => {
                ServerReply::Json(tool_result(id, structured, false))
            }
            Ok(CallResult::Serialized(structured_json)) => ServerReply::ToolRaw {
                id: id.clone(),
                structured_json,
                is_error: false,
            },
            Err(Failure::InvalidParams(message)) => {
                ServerReply::Json(protocol::error(id, protocol::INVALID_PARAMS, message, None))
            }
            Err(Failure::UnknownTool(name)) => ServerReply::Json(protocol::error(
                id,
                protocol::INVALID_PARAMS,
                format!("unknown tool `{name}`"),
                None,
            )),
            Err(Failure::Execution(error)) => {
                ServerReply::Json(tool_result(id, tools::error_result(&error), true))
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
    let mut line_buf = Vec::with_capacity(4096);
    loop {
        let bytes = match read_line(input, MAX_MESSAGE_BYTES)? {
            Line::Eof => return Ok(()),
            Line::TooLong => {
                let response = ServerReply::Json(protocol::error(
                    &Value::Null,
                    protocol::INVALID_REQUEST,
                    format!("a message may not exceed {MAX_MESSAGE_BYTES} bytes"),
                    None,
                ));
                write_reply(out, &mut line_buf, &response)?;
                continue;
            }
            Line::Text(bytes) => bytes,
        };
        let trimmed = bytes.trim_ascii();
        if trimmed.is_empty() {
            continue;
        }
        let response = match serde_json::from_slice::<Value>(trimmed) {
            Ok(value) => server.handle_fast(&value),
            Err(error) => Some(ServerReply::Json(protocol::error(
                &Value::Null,
                protocol::PARSE_ERROR,
                format!("not valid JSON: {error}"),
                None,
            ))),
        };
        if let Some(response) = response {
            write_reply(out, &mut line_buf, &response)?;
        }
    }
}

fn write_reply(out: &mut impl Write, buf: &mut Vec<u8>, reply: &ServerReply) -> io::Result<()> {
    buf.clear();
    match reply {
        ServerReply::Json(value) => {
            serde_json::to_writer(&mut *buf, value).map_err(io::Error::other)?;
            buf.push(b'\n');
        }
        ServerReply::ToolRaw {
            id,
            structured_json,
            is_error,
        } => {
            buf.reserve(structured_json.len().saturating_mul(2).saturating_add(160));
            buf.extend_from_slice(br#"{"id":"#);
            serde_json::to_writer(&mut *buf, id).map_err(io::Error::other)?;
            buf.extend_from_slice(br#","jsonrpc":"2.0","result":{"content":[{"text":"#);
            serde_json::to_writer(&mut *buf, structured_json).map_err(io::Error::other)?;
            buf.extend_from_slice(br#","type":"text"}],"isError":"#);
            buf.extend_from_slice(if *is_error { b"true" } else { b"false" });
            buf.extend_from_slice(br#","structuredContent":"#);
            buf.extend_from_slice(structured_json.as_bytes());
            buf.extend_from_slice(b"}}\n");
        }
    }
    out.write_all(buf)?;
    out.flush()
}

#[cfg(test)]
mod reply_tests {
    use super::*;

    #[test]
    fn write_reply_tool_raw_matches_tool_result_wire_bytes() {
        let structured = json!({
            "a": 1,
            "b": ["quote\"here", "line1\nline2", true, null]
        });
        let structured_json = serde_json::to_string(&structured).unwrap();
        for (id, is_error) in [(json!(7), false), (json!("req-9\"x"), true)] {
            let expected = serde_json::to_string(&tool_result(&id, structured.clone(), is_error))
                .unwrap()
                + "\n";
            let reply = ServerReply::ToolRaw {
                id,
                structured_json: structured_json.clone(),
                is_error,
            };
            let mut buf = Vec::new();
            let mut out = Vec::new();
            write_reply(&mut out, &mut buf, &reply).unwrap();
            assert_eq!(String::from_utf8(out).unwrap(), expected);
        }
    }
}
