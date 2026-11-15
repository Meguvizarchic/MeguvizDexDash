//! The MCP server as a process: JSON-RPC over stdio, datasets, quotas and errors.
//!
//! Each test starts the real `meguvizdexdash mcp`, so what is checked is what an MCP
//! client sees on the wire.
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

const BIN: &str = env!("CARGO_BIN_EXE_meguvizdexdash");

fn fixture(relative: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
        .to_string_lossy()
        .into_owned()
}

fn dex() -> String {
    fixture("tests/fixtures/definitions/generated/definitions-038.dex")
}

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Mcp {
    fn start(args: &[&str]) -> Self {
        let mut child = Command::new(BIN)
            .arg("mcp")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the server starts");
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
            next_id: 0,
        }
    }

    fn ready(args: &[&str]) -> Self {
        let mut server = Self::start(args);
        let reply = server.request(
            "initialize",
            json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}),
        );
        assert!(reply["result"]["protocolVersion"].is_string(), "{reply}");
        server.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        server
    }

    fn send(&mut self, message: &Value) {
        self.send_raw(message.to_string().as_bytes());
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        stdin.write_all(bytes).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    fn read(&mut self) -> Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "the server closed stdout");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("stdout is not JSON: {line:?}: {e}"))
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        let reply = self.read();
        assert_eq!(reply["id"], id, "{reply}");
        assert_eq!(reply["jsonrpc"], "2.0");
        reply
    }

    /// The tool's structured content and whether it is an error. Panics on a JSON-RPC error.
    fn tool(&mut self, name: &str, arguments: Value) -> (Value, bool) {
        let reply = self.request("tools/call", json!({"name":name,"arguments":arguments}));
        let result = &reply["result"];
        assert!(result.is_object(), "{reply}");
        let text: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(
            text, result["structuredContent"],
            "text and structured content differ"
        );
        (
            result["structuredContent"].clone(),
            result["isError"].as_bool().unwrap(),
        )
    }

    /// The JSON-RPC error code of a call that the protocol refused.
    fn refused(&mut self, name: &str, arguments: Value) -> i64 {
        let reply = self.request("tools/call", json!({"name":name,"arguments":arguments}));
        reply["error"]["code"]
            .as_i64()
            .unwrap_or_else(|| panic!("not refused: {reply}"))
    }

    fn open(&mut self) -> String {
        let (opened, error) = self.tool("open_dataset", json!({"inputs":[dex()]}));
        assert!(!error, "{opened}");
        opened["dataset_id"].as_str().unwrap().to_owned()
    }

    fn finish(mut self) -> (Option<i32>, String) {
        drop(self.stdin.take());
        let mut rest = String::new();
        let _ = self.stdout.read_line(&mut rest);
        let status = self.child.wait().unwrap();
        let mut err = String::new();
        std::io::Read::read_to_string(self.child.stderr.as_mut().unwrap(), &mut err).unwrap();
        (status.code(), err)
    }
}

const TYPES: &str = "SELECT type_idx FROM types ORDER BY type_idx";

// ---- the session -------------------------------------------------------------

#[test]
fn the_session_must_be_initialized_before_tools_and_may_be_initialized_once() {
    let mut server = Mcp::start(&[]);
    assert!(
        server.request("ping", json!({}))["result"].is_object(),
        "ping needs no session"
    );
    let early = server.request("tools/list", json!({}));
    assert_eq!(early["error"]["code"], -32600, "{early}");
    let first = server.request(
        "initialize",
        json!({"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}),
    );
    assert_eq!(
        first["result"]["protocolVersion"], "2025-03-26",
        "a supported revision is echoed"
    );
    assert_eq!(first["result"]["serverInfo"]["name"], "meguvizdexdash");
    assert_eq!(
        first["result"]["capabilities"]["tools"]["listChanged"],
        false
    );
    assert!(first["result"]["capabilities"].get("resources").is_none());
    let second = server.request("initialize", json!({"protocolVersion":"2025-03-26"}));
    assert_eq!(second["error"]["code"], -32600);
    let (code, err) = server.finish();
    assert_eq!(code, Some(0));
    assert!(err.is_empty(), "{err}");
}

#[test]
fn an_unknown_protocol_revision_is_answered_with_the_newest() {
    let mut server = Mcp::start(&[]);
    let reply = server.request("initialize", json!({"protocolVersion":"1999-01-01"}));
    assert_eq!(reply["result"]["protocolVersion"], "2025-06-18");
}

#[test]
fn only_protocol_messages_reach_stdout_and_bad_lines_do_not_end_the_session() {
    let mut server = Mcp::ready(&[]);
    server.send_raw(b"this is not json");
    assert_eq!(server.read()["error"]["code"], -32700);
    server.send_raw(b"[1,2]");
    assert_eq!(server.read()["error"]["code"], -32600);
    server.send(&json!({"jsonrpc":"2.0","id":null,"method":"ping"}));
    let bad_id = server.read();
    assert_eq!(bad_id["error"]["code"], -32600);
    assert!(bad_id["id"].is_null());
    let unknown = server.request("resources/list", json!({}));
    assert_eq!(
        unknown["error"]["code"], -32601,
        "resources are not offered"
    );
    let alive = server.request("ping", json!({}));
    assert!(alive["result"].is_object());
    let (code, err) = server.finish();
    assert_eq!(code, Some(0));
    assert!(err.is_empty(), "{err}");
}

#[test]
fn a_message_over_the_size_limit_is_refused_and_skipped() {
    let mut server = Mcp::ready(&[]);
    server.send_raw(&vec![b'x'; 4 * 1024 * 1024 + 64]);
    assert_eq!(server.read()["error"]["code"], -32600);
    assert!(server.request("ping", json!({}))["result"].is_object());
}

// ---- tools/list ---------------------------------------------------------------

#[test]
fn exactly_the_implemented_tools_are_listed_with_their_published_schemas() {
    let mut server = Mcp::ready(&[]);
    let tools = server.request("tools/list", json!({}))["result"]["tools"].clone();
    let names: Vec<&str> = tools
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "open_dataset",
            "list_datasets",
            "close_dataset",
            "list_tables",
            "describe_table",
            "query"
        ]
    );
    for tool in tools.as_array().unwrap() {
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert!(tool["annotations"]["readOnlyHint"].is_boolean());
        assert!(!tool["description"].as_str().unwrap().is_empty());
    }
    let query = tools
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "query")
        .unwrap();
    assert_eq!(query["outputSchema"]["title"], "QueryOutput");
    for absent in [
        "decode",
        "get_manifest",
        "get_manifest_components",
        "list_resource_files",
        "read_resource",
        "query_resources",
    ] {
        assert!(
            !names.contains(&absent),
            "{absent} is not implemented and must not be listed"
        );
        assert_eq!(
            server.refused(absent, json!({})),
            -32602,
            "{absent} is refused as an unknown tool"
        );
    }
}

// ---- argument checking ---------------------------------------------------------

#[test]
fn arguments_that_break_the_published_schema_are_protocol_errors() {
    let mut server = Mcp::ready(&[]);
    let id = server.open();
    let cases: Vec<(&str, Value)> = vec![
        ("open_dataset", json!({})),
        ("open_dataset", json!({"inputs":[]})),
        (
            "open_dataset",
            json!({"inputs":(0..65).map(|i| format!("f{i}")).collect::<Vec<_>>()}),
        ),
        ("open_dataset", json!({"inputs":[""]})),
        ("open_dataset", json!({"inputs":["x"],"timeout_ms":0})),
        (
            "open_dataset",
            json!({"inputs":["x"],"timeout_ms":999_999_999}),
        ),
        ("open_dataset", json!({"inputs":["x"],"surprise":1})),
        ("open_dataset", json!({"inputs":"x"})),
        ("close_dataset", json!({})),
        ("describe_table", json!({"name":5})),
        ("list_tables", json!({"extra":1})),
        ("query", json!({"dataset_id":id,"sql":[]})),
        (
            "query",
            json!({"dataset_id":id,"sql":(0..17).map(|_| "SELECT 1").collect::<Vec<_>>()}),
        ),
        (
            "query",
            json!({"dataset_id":id,"sql":["SELECT 1"],"limit":0}),
        ),
        (
            "query",
            json!({"dataset_id":id,"sql":["SELECT 1"],"limit":1001}),
        ),
        (
            "query",
            json!({"dataset_id":id,"sql":["SELECT 1"],"limit":1000,"offset":99_001}),
        ),
        (
            "query",
            json!({"dataset_id":id,"sql":["SELECT 1"],"offset":-1}),
        ),
        (
            "query",
            json!({"dataset_id":id,"sql":["SELECT 1"],"timeout_ms":0}),
        ),
        ("query", json!({"sql":["SELECT 1"]})),
    ];
    for (name, arguments) in cases {
        assert_eq!(
            server.refused(name, arguments.clone()),
            -32602,
            "{name} {arguments}"
        );
    }
    let reply = server.request("tools/call", json!({"name":"query","arguments":[1]}));
    assert_eq!(reply["error"]["code"], -32602);
    let reply = server.request("tools/call", json!({"arguments":{}}));
    assert_eq!(reply["error"]["code"], -32602);
}

// ---- lifecycle ------------------------------------------------------------------

#[test]
fn opening_a_dataset_names_its_source_and_roster() {
    let mut server = Mcp::ready(&[]);
    let (opened, error) = server.tool("open_dataset", json!({"inputs":[dex()]}));
    assert!(!error, "{opened}");
    assert!(
        opened["dataset_id"]
            .as_str()
            .unwrap()
            .starts_with("dataset-")
    );
    assert_eq!(opened["dex_count"], 1);
    assert_eq!(
        opened["dex_files"],
        json!([{"file_id":0,"entry_name":"definitions-038.dex"}])
    );
    assert_eq!(opened["sql_dialect"], "dexsql-0.1.0");
    assert!(
        opened["snapshot_id"]
            .as_str()
            .unwrap()
            .starts_with("snapshot-")
    );
    assert!(opened["scope_id"].as_str().unwrap().starts_with("sha256:"));
    let source = &opened["snapshot_manifest"];
    assert!(
        source.is_object(),
        "the source identity is part of the answer"
    );
    assert_eq!(opened["diagnostics"], json!([]));
}

#[test]
fn a_layer_that_cannot_be_built_is_a_diagnostic_and_its_relations_refuse() {
    let mut server = Mcp::ready(&[]);
    let broken = fixture("tests/fixtures/instructions/generated/bad-reserved-opcode.dex");
    let (opened, error) = server.tool("open_dataset", json!({"inputs":[broken]}));
    assert!(!error);
    assert_eq!(opened["diagnostics"][0]["code"], "LAYER_UNAVAILABLE");
    let id = opened["dataset_id"].as_str().unwrap();
    let (result, error) = server.tool(
        "query",
        json!({"dataset_id":id,"sql":["SELECT * FROM method_calls"]}),
    );
    assert!(error, "{result}");
    assert_eq!(result["error"]["code"], "INCOMPLETE_FACTS");
    let (types, error) = server.tool(
        "query",
        json!({"dataset_id":id,"sql":["SELECT file_id FROM dex_files"]}),
    );
    assert!(!error, "the intact structure layer still answers: {types}");
}

#[test]
fn an_input_that_cannot_be_opened_is_a_tool_error_naming_the_cause() {
    let mut server = Mcp::ready(&[]);
    let (result, error) = server.tool("open_dataset", json!({"inputs":["no-such-file.dex"]}));
    assert!(error);
    assert_eq!(result["error"]["code"], "INVALID_INPUT");
    let (listed, _) = server.tool("list_datasets", json!({}));
    assert_eq!(
        listed["usage"]["open_datasets"], 0,
        "a failed open leaves nothing behind"
    );
}

#[test]
fn closing_releases_a_dataset_and_later_requests_that_name_it_are_refused() {
    let mut server = Mcp::ready(&[]);
    let id = server.open();
    let (listed, _) = server.tool("list_datasets", json!({}));
    assert_eq!(listed["datasets"][0]["dataset_id"], id);
    assert_eq!(listed["usage"]["open_datasets"], 1);
    assert_eq!(listed["quotas"]["max_datasets"], 8);

    let (closed, error) = server.tool("close_dataset", json!({"dataset_id":id}));
    assert!(!error);
    assert_eq!(closed["already_closed"], false);
    let (again, error) = server.tool("close_dataset", json!({"dataset_id":id}));
    assert!(!error);
    assert_eq!(again["already_closed"], true, "closing twice is allowed");

    let (refused, error) = server.tool("query", json!({"dataset_id":id,"sql":["SELECT 1"]}));
    assert!(error);
    assert_eq!(refused["error"]["message"], "DATASET_CLOSED");

    let (unknown, error) = server.tool(
        "close_dataset",
        json!({"dataset_id":"dataset-not-minted-here"}),
    );
    assert!(error);
    assert_eq!(unknown["error"]["message"], "DATASET_NOT_FOUND");
    let (unknown, error) = server.tool(
        "query",
        json!({"dataset_id":"dataset-not-minted-here","sql":["SELECT 1"]}),
    );
    assert!(error);
    assert_eq!(unknown["error"]["message"], "DATASET_NOT_FOUND");
    let (listed, _) = server.tool("list_datasets", json!({}));
    assert_eq!(listed["usage"]["open_datasets"], 0);
    assert_eq!(listed["closed_datasets"], 1);
}

#[test]
fn the_dataset_quota_is_enforced_and_closing_frees_a_slot() {
    let mut server = Mcp::ready(&["--max-datasets", "2"]);
    let first = server.open();
    let _second = server.open();
    let (refused, error) = server.tool("open_dataset", json!({"inputs":[dex()]}));
    assert!(error);
    assert_eq!(refused["error"]["code"], "QUOTA_EXCEEDED");
    assert_eq!(refused["error"]["details"]["budget"], "max_datasets");
    server.tool("close_dataset", json!({"dataset_id":first}));
    let (opened, error) = server.tool("open_dataset", json!({"inputs":[dex()]}));
    assert!(!error, "{opened}");
}

#[test]
fn datasets_are_isolated_from_each_other() {
    let mut server = Mcp::ready(&[]);
    let a = server.open();
    let b = server.open();
    let (made, error) = server.tool(
        "query",
        json!({"dataset_id":a,"sql":["CREATE TEMP TABLE mine AS SELECT type_idx FROM types"]}),
    );
    assert!(!error, "{made}");
    let (read, error) = server.tool(
        "query",
        json!({"dataset_id":a,"sql":["SELECT COUNT(*) AS n FROM mine"]}),
    );
    assert!(
        !error,
        "a TEMP definition persists in its own dataset: {read}"
    );
    let (other, error) = server.tool(
        "query",
        json!({"dataset_id":b,"sql":["SELECT COUNT(*) AS n FROM mine"]}),
    );
    assert!(error, "the other dataset must not see it: {other}");
}

// ---- tables ---------------------------------------------------------------------

#[test]
fn the_built_in_tables_are_listed_and_described_without_a_dataset() {
    let mut server = Mcp::ready(&[]);
    let (listed, error) = server.tool("list_tables", json!({}));
    assert!(!error);
    let names: Vec<&str> = listed["tables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 17);
    assert!(names.contains(&"dex_files") && names.contains(&"method_calls"));
    let (described, error) = server.tool("describe_table", json!({"name":"Methods"}));
    assert!(!error, "names are case-insensitive: {described}");
    assert_eq!(described["name"], "methods");
    assert_eq!(described["columns"].as_array().unwrap().len(), 14);
    assert_eq!(described["columns"][0]["name"], "file_id");
    let (unknown, error) = server.tool("describe_table", json!({"name":"no_such_table"}));
    assert!(error);
    assert_eq!(unknown["error"]["message"], "UNKNOWN_TABLE");
}

// ---- query ----------------------------------------------------------------------

#[test]
fn query_pages_with_limit_and_offset_and_reports_the_window() {
    let mut server = Mcp::ready(&[]);
    let id = server.open();
    let (first, error) = server.tool("query", json!({"dataset_id":id,"sql":[TYPES],"limit":4}));
    assert!(!error);
    let s = &first["statements"][0];
    assert_eq!(
        (
            s["offset"].as_u64(),
            s["next_offset"].as_u64(),
            s["truncated"].as_bool()
        ),
        (Some(0), Some(4), Some(true))
    );
    assert_eq!(s["total_rows"], 9);
    assert_eq!(s["rows"].as_array().unwrap().len(), 4);
    assert_eq!(s["rows"][0][0], json!({"type":"uint64","value":"0"}));
    let (last, _) = server.tool(
        "query",
        json!({"dataset_id":id,"sql":[TYPES],"limit":4,"offset":8}),
    );
    let s = &last["statements"][0];
    assert_eq!(
        (
            s["rows"].as_array().unwrap().len(),
            s["truncated"].as_bool(),
            s["next_offset"].is_null()
        ),
        (1, Some(false), true)
    );
    assert_eq!(first["diagnostics"], json!([]));
}

#[test]
fn several_statements_answer_in_order_and_a_failure_names_its_index() {
    let mut server = Mcp::ready(&[]);
    let id = server.open();
    let (ok, error) = server.tool(
        "query",
        json!({"dataset_id":id,"sql":["SELECT 1 AS a","SELECT 2 AS b; SELECT 3 AS c"]}),
    );
    assert!(!error);
    let indexes: Vec<u64> = ok["statements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["statement_index"].as_u64().unwrap())
        .collect();
    assert_eq!(indexes, [0, 1, 2]);
    let (failed, error) = server.tool(
        "query",
        json!({"dataset_id":id,"sql":["SELECT 1","SELECT 2 FROM nope"]}),
    );
    assert!(error);
    assert_eq!(failed["error"]["details"]["statement_index"], "1");
}

#[test]
fn named_temp_queries_are_retained_in_the_dataset() {
    let mut server = Mcp::ready(&[]);
    let id = server.open();
    let (made, error) = server.tool(
        "query",
        json!({"dataset_id":id,"sql":["SELECT COUNT(*) AS n FROM kept"],"named_temp_queries":[{"name":"kept","sql":"SELECT type_idx FROM types"}]}),
    );
    assert!(!error, "{made}");
    assert_eq!(
        made["statements"][0]["rows"][0][0],
        json!({"type":"int64","value":"9"})
    );
    let (later, error) = server.tool(
        "query",
        json!({"dataset_id":id,"sql":["SELECT COUNT(*) AS n FROM kept"]}),
    );
    assert!(!error, "a named query stays until DROP or close: {later}");
}

#[test]
fn a_result_over_the_byte_budget_is_refused_never_clipped() {
    let mut server = Mcp::ready(&[]);
    let id = server.open();
    let (refused, error) = server.tool(
        "query",
        json!({"dataset_id":id,"sql":[TYPES],"max_bytes":100}),
    );
    assert!(error);
    assert_eq!(refused["error"]["code"], "QUOTA_EXCEEDED");
    assert_eq!(refused["error"]["details"]["budget"], "max_bytes");
    assert!(refused.get("statements").is_none());
    let (fine, error) = server.tool(
        "query",
        json!({"dataset_id":id,"sql":[TYPES],"max_bytes":1_000_000}),
    );
    assert!(!error, "{fine}");
}

#[test]
fn an_option_the_server_does_not_implement_is_refused_not_ignored() {
    let mut server = Mcp::ready(&[]);
    let id = server.open();
    let (refused, error) = server.tool(
        "query",
        json!({"dataset_id":id,"sql":["SELECT 1"],"timing":true}),
    );
    assert!(error);
    assert_eq!(refused["error"]["code"], "UNSUPPORTED_CAPABILITY");
    let (fine, error) = server.tool(
        "query",
        json!({"dataset_id":id,"sql":["SELECT 1"],"timing":false}),
    );
    assert!(!error);
    assert!(fine["timing"].is_null());
}

#[test]
fn a_query_that_outlives_its_deadline_closes_its_dataset_and_only_that_one() {
    let mut server = Mcp::ready(&[]);
    let slow = server.open();
    let other = server.open();
    let (late, error) = server.tool(
        "query",
        json!({"dataset_id":slow,"timeout_ms":1,
               "sql":["SELECT a.type_idx FROM types a, types b, types c, types d, types e"]}),
    );
    assert!(error);
    assert_eq!(late["error"]["code"], "DEADLINE_EXCEEDED");
    assert_eq!(late["error"]["details"]["dataset_closed"], "true");
    let (after, error) = server.tool("query", json!({"dataset_id":slow,"sql":["SELECT 1"]}));
    assert!(error);
    assert_eq!(after["error"]["message"], "DATASET_CLOSED");
    let (fine, error) = server.tool("query", json!({"dataset_id":other,"sql":["SELECT 1"]}));
    assert!(!error, "the other dataset is untouched: {fine}");
}

// ---- the ends of the pipe --------------------------------------------------------

#[test]
fn a_closed_stdin_is_a_clean_end_and_a_closed_stdout_is_exit_four() {
    let (code, err) = Mcp::ready(&[]).finish();
    assert_eq!((code, err.as_str()), (Some(0), ""));

    let mut server = Mcp::start(&[]);
    let stdout = std::mem::replace(
        &mut server.stdout,
        BufReader::new(
            Command::new(BIN)
                .arg("version")
                .stdout(Stdio::piped())
                .spawn()
                .unwrap()
                .stdout
                .take()
                .unwrap(),
        ),
    );
    drop(stdout);
    server.send(&json!({"jsonrpc":"2.0","id":1,"method":"ping"}));
    let status = server.child.wait().unwrap();
    assert_eq!(status.code(), Some(4));
}

#[test]
fn the_server_does_not_run_without_a_contract_dialect() {
    let output = Command::new(BIN)
        .args(["mcp", "--dialect", "native-v1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["code"], "UNSUPPORTED_CAPABILITY");
    for bad in [
        ["--max-datasets", "0"],
        ["--timeout-ms", "0"],
        ["--bogus", "1"],
    ] {
        let output = Command::new(BIN).arg("mcp").args(bad).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{bad:?}");
        assert!(output.stdout.is_empty());
    }
}
