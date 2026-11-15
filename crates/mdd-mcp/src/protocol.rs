//! JSON-RPC 2.0 framing for MCP: what a message is, and how to answer one.
use serde_json::{Map, Value, json};

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;

/// MCP protocol revisions this server answers, newest first. A client that asks for
/// one of them gets it back; any other request is answered with the newest.
pub const SUPPORTED_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

pub fn result(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

pub fn error(id: &Value, code: i64, message: impl Into<String>, data: Option<Value>) -> Value {
    let mut error = Map::new();
    error.insert("code".to_owned(), json!(code));
    error.insert("message".to_owned(), Value::String(message.into()));
    if let Some(data) = data {
        error.insert("data".to_owned(), data);
    }
    json!({"jsonrpc": "2.0", "id": id, "error": Value::Object(error)})
}

/// One incoming message, validated as far as framing goes.
pub enum Message {
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    Notification {
        method: String,
    },
    /// A response from the peer. This server sends no requests, so there is nothing to match it to.
    Response,
}

/// Parse one decoded JSON value. `Err` is the error response to send; its id is null
/// when the message had no usable one.
pub fn parse(value: &Value) -> Result<Message, Value> {
    let object = value.as_object().ok_or_else(|| {
        error(
            &Value::Null,
            INVALID_REQUEST,
            "a message must be a JSON object; batches are not supported",
            None,
        )
    })?;
    let id = match object.get("id") {
        None => None,
        Some(id) if id.is_string() || id.is_i64() || id.is_u64() => Some(id.clone()),
        Some(_) => {
            return Err(error(
                &Value::Null,
                INVALID_REQUEST,
                "an id must be a string or an integer",
                None,
            ));
        }
    };
    let reply_id = id.clone().unwrap_or(Value::Null);
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(error(
            &reply_id,
            INVALID_REQUEST,
            "`jsonrpc` must be \"2.0\"",
            None,
        ));
    }
    let Some(method) = object.get("method") else {
        if object.contains_key("result") || object.contains_key("error") {
            return Ok(Message::Response);
        }
        return Err(error(
            &reply_id,
            INVALID_REQUEST,
            "`method` is missing",
            None,
        ));
    };
    let Some(method) = method.as_str() else {
        return Err(error(
            &reply_id,
            INVALID_REQUEST,
            "`method` must be a string",
            None,
        ));
    };
    let params = match object.get("params") {
        None | Some(Value::Null) => Value::Object(Map::new()),
        Some(params) if params.is_object() => params.clone(),
        Some(_) => {
            return Err(error(
                &reply_id,
                INVALID_PARAMS,
                "`params` must be an object",
                None,
            ));
        }
    };
    Ok(match id {
        Some(id) => Message::Request {
            id,
            method: method.to_owned(),
            params,
        },
        None => Message::Notification {
            method: method.to_owned(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejected(value: Value) -> Value {
        match parse(&value) {
            Err(response) => response,
            Ok(_) => panic!("accepted {value}"),
        }
    }

    #[test]
    fn a_request_with_an_id_and_a_notification_without_one_are_told_apart() {
        let request = json!({"jsonrpc":"2.0","id":7,"method":"ping"});
        assert!(matches!(parse(&request), Ok(Message::Request { .. })));
        let note = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        assert!(matches!(parse(&note), Ok(Message::Notification { .. })));
    }

    #[test]
    fn ids_other_than_strings_and_integers_are_refused_with_a_null_id() {
        for id in [json!(null), json!(1.5), json!(true), json!([1]), json!({})] {
            let response = rejected(json!({"jsonrpc":"2.0","id":id,"method":"ping"}));
            assert_eq!(response["error"]["code"], INVALID_REQUEST);
            assert!(response["id"].is_null());
        }
    }

    #[test]
    fn malformed_messages_are_refused_and_keep_their_id_when_it_was_usable() {
        assert_eq!(rejected(json!([1]))["error"]["code"], INVALID_REQUEST);
        assert_eq!(rejected(json!("x"))["error"]["code"], INVALID_REQUEST);
        let wrong_version = rejected(json!({"jsonrpc":"1.0","id":3,"method":"ping"}));
        assert_eq!(wrong_version["id"], 3);
        let no_method = rejected(json!({"jsonrpc":"2.0","id":4}));
        assert_eq!(no_method["id"], 4);
        let bad_method = rejected(json!({"jsonrpc":"2.0","id":5,"method":9}));
        assert_eq!(bad_method["error"]["code"], INVALID_REQUEST);
        let bad_params = rejected(json!({"jsonrpc":"2.0","id":6,"method":"x","params":[1]}));
        assert_eq!(bad_params["error"]["code"], INVALID_PARAMS);
    }

    #[test]
    fn a_response_from_the_peer_is_recognised_and_needs_no_answer() {
        let response = json!({"jsonrpc":"2.0","id":1,"result":{}});
        assert!(matches!(parse(&response), Ok(Message::Response)));
    }
}
