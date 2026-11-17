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
            "decode",
            "get_manifest",
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
    // A tool that takes no arguments ignores what is added to it, as the reference does.
    for name in ["list_tables", "list_datasets"] {
        let (reply, error) = server.tool(name, json!({"extra":1}));
        assert!(!error, "{name}: {reply}");
    }
    let reply = server.request("tools/call", json!({"name":"query","arguments":[1]}));
    assert_eq!(reply["error"]["code"], -32602);
    let reply = server.request("tools/call", json!({"arguments":{}}));
    assert_eq!(reply["error"]["code"], -32602);
}

// ---- lifecycle ------------------------------------------------------------------

#[test]
fn opening_a_dataset_answers_in_the_references_shape_and_names_its_source() {
    let mut server = Mcp::ready(&[]);
    let (opened, error) = server.tool("open_dataset", json!({"inputs":[dex()]}));
    assert!(!error, "{opened}");
    assert!(
        opened["dataset_id"]
            .as_str()
            .unwrap()
            .starts_with("dataset-")
    );
    // The six fields the reference answers with, as it answers with them.
    assert_eq!(opened["archive_inputs"], json!([]));
    assert_eq!(
        opened["has_dex"], true,
        "HostLab refuses a dataset that does not say it has a DEX"
    );
    assert_eq!(
        opened["input_bytes"],
        std::fs::metadata(dex()).unwrap().len()
    );
    assert_eq!(opened["inputs"], json!([dex()]));
    assert!(opened["prepare_ms"].as_f64().unwrap() >= 0.0);
    assert!(
        opened.get("dex_files").is_none(),
        "the roster is a SQL question: SELECT file_id,entry_name FROM dex_files"
    );
    // Beside them, this engine's own identity fields.
    assert_eq!(opened["dex_count"], 1);
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
        listed["usage"]["datasets"], 0,
        "a failed open leaves nothing behind"
    );
}

#[test]
fn closing_releases_a_dataset_and_later_requests_that_name_it_are_refused() {
    let mut server = Mcp::ready(&[]);
    let id = server.open();
    let (listed, _) = server.tool("list_datasets", json!({}));
    assert_eq!(listed["datasets"][0]["dataset_id"], id);
    assert_eq!(listed["usage"]["datasets"], 1);
    assert_eq!(
        listed["usage"]["input_bytes"],
        std::fs::metadata(dex()).unwrap().len()
    );
    assert_eq!(listed["limits"]["max_datasets"], 8);

    let (closed, error) = server.tool("close_dataset", json!({"dataset_id":id}));
    assert!(!error);
    assert_eq!(closed, json!({"closed": true, "dataset_id": id}));

    // Closed, never minted here, and closed twice are one answer in the reference's words.
    let not_open = |id: &str| format!("dataset \"{id}\" is not open; call open_dataset first");
    let (again, error) = server.tool("close_dataset", json!({"dataset_id":id}));
    assert!(error, "closing twice is refused: {again}");
    assert_eq!(again["error"]["kind"], "unknown_dataset");
    assert_eq!(again["error"]["message"], not_open(&id));
    let (refused, error) = server.tool("query", json!({"dataset_id":id,"sql":["SELECT 1"]}));
    assert!(error);
    assert_eq!(refused["error"]["kind"], "unknown_dataset");
    assert_eq!(refused["error"]["message"], not_open(&id));

    let (unknown, error) = server.tool(
        "close_dataset",
        json!({"dataset_id":"dataset-not-minted-here"}),
    );
    assert!(error);
    assert_eq!(unknown["error"]["kind"], "unknown_dataset");
    assert_eq!(
        unknown["error"]["message"],
        not_open("dataset-not-minted-here")
    );
    let (unknown, error) = server.tool(
        "query",
        json!({"dataset_id":"dataset-not-minted-here","sql":["SELECT 1"]}),
    );
    assert!(error);
    assert_eq!(unknown["error"]["kind"], "unknown_dataset");
    let (listed, _) = server.tool("list_datasets", json!({}));
    assert_eq!(listed["usage"]["datasets"], 0);
    assert_eq!(listed["datasets"], json!([]));
}

#[test]
fn listing_answers_with_the_references_fields_and_no_others_per_dataset() {
    let mut server = Mcp::ready(&[]);
    let id = server.open();
    let (listed, error) = server.tool("list_datasets", json!({}));
    assert!(!error);
    let keys = |value: &Value| -> Vec<String> {
        let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        keys
    };
    assert_eq!(
        keys(&listed),
        [
            "admitted_requests",
            "datasets",
            "limits",
            "running_requests",
            "usage"
        ]
    );
    assert_eq!(
        keys(&listed["limits"]),
        [
            "max_datasets",
            "max_dex_bytes",
            "max_input_bytes",
            "max_output_bytes",
            "max_pending",
            "max_resource_bytes",
            "max_total_input_bytes",
            "timeout_ms"
        ]
    );
    assert_eq!(keys(&listed["usage"]), ["datasets", "input_bytes"]);
    assert_eq!(
        keys(&listed["datasets"][0]),
        [
            "archive_inputs",
            "dataset_id",
            "has_dex",
            "input_bytes",
            "inputs",
            "prepare_ms"
        ],
        "a listed dataset is described as open_dataset described it"
    );
    assert_eq!(listed["datasets"][0]["dataset_id"], id);
    assert_eq!(listed["running_requests"], 0);
}

#[test]
fn the_total_input_byte_quota_is_enforced_like_the_dataset_quota() {
    let size = std::fs::metadata(dex()).unwrap().len();
    let mut server = Mcp::ready(&["--max-total-input-bytes", &(size * 2 - 1).to_string()]);
    let first = server.open();
    let (refused, error) = server.tool("open_dataset", json!({"inputs":[dex()]}));
    assert!(error, "{refused}");
    assert_eq!(refused["error"]["kind"], "session_quota_exceeded");
    assert_eq!(
        refused["error"]["details"]["budget"],
        "max_total_input_bytes"
    );
    let (listed, _) = server.tool("list_datasets", json!({}));
    assert_eq!(
        listed["usage"]["datasets"], 1,
        "a refused open leaves nothing behind"
    );
    server.tool("close_dataset", json!({"dataset_id":first}));
    let (opened, error) = server.tool("open_dataset", json!({"inputs":[dex()]}));
    assert!(!error, "closing frees the bytes: {opened}");
}

#[test]
fn the_dataset_quota_is_enforced_and_closing_frees_a_slot() {
    let mut server = Mcp::ready(&["--max-datasets", "2"]);
    let first = server.open();
    let _second = server.open();
    let (refused, error) = server.tool("open_dataset", json!({"inputs":[dex()]}));
    assert!(error);
    assert_eq!(refused["error"]["code"], "QUOTA_EXCEEDED");
    assert_eq!(refused["error"]["kind"], "session_quota_exceeded");
    assert_eq!(
        refused["error"]["message"],
        "dataset/input-byte quota exhausted; close unused datasets before opening another",
        "the reference's words"
    );
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
    // All fifty-six relations of the frozen manifest, in its order.
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/manifests/relations.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let frozen: Vec<&str> = manifest["relations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|relation| relation["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, frozen);
    assert_eq!(names.len(), 56);
    assert!(names.contains(&"dex_files") && names.contains(&"method_calls"));
    let (described, error) = server.tool("describe_table", json!({"name":"debug_opcodes"}));
    assert!(!error, "{described}");
    assert_eq!(described["columns"].as_array().unwrap().len(), 18);
    let (described, error) = server.tool("describe_table", json!({"name":"Methods"}));
    assert!(!error, "names are case-insensitive: {described}");
    assert_eq!(described["name"], "methods");
    assert_eq!(described["columns"].as_array().unwrap().len(), 14);
    assert_eq!(described["columns"][0]["name"], "file_id");
    let (unknown, error) = server.tool("describe_table", json!({"name":"no_such_table"}));
    assert!(error);
    assert_eq!(unknown["error"]["message"], "UNKNOWN_TABLE");
}

#[test]
fn both_compatibility_dialects_list_and_describe_the_same_fifty_six_tables() {
    let mut lists = Vec::new();
    for dialect in ["dexsql-0.1.0", "dexsql-0.1.1"] {
        let mut server = Mcp::ready(&["--dialect", dialect]);
        let (listed, error) = server.tool("list_tables", json!({}));
        assert!(!error, "{dialect}: {listed}");
        let tables = listed["tables"].as_array().unwrap().clone();
        assert_eq!(tables.len(), 56, "{dialect}");
        for table in &tables {
            let name = table["name"].as_str().unwrap();
            let (described, error) = server.tool("describe_table", json!({"name": name}));
            assert!(!error, "{dialect} {name}: {described}");
            assert_eq!(
                described["columns"].as_array().unwrap().len() as u64,
                table["column_count"].as_u64().unwrap(),
                "{dialect} {name}"
            );
        }
        lists.push(tables);
    }
    assert_eq!(lists[0], lists[1]);
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
    assert_eq!(failed["error"]["statement_index"], 1);
    assert_eq!(failed["error"]["kind"], "invalid_query");
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
        json!({"type":"uint64","value":"9"}),
        "COUNT(*) is uint64 in the reference's recordings"
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
fn timing_is_reported_when_asked_for_and_absent_otherwise() {
    // HostLab passes timing=true on every statement; refusing it would refuse HostLab.
    let mut server = Mcp::ready(&[]);
    let id = server.open();
    let (timed, error) = server.tool(
        "query",
        json!({"dataset_id":id,"sql":["SELECT 1"],"timing":true}),
    );
    assert!(!error, "{timed}");
    let timing = timed["timing"].as_object().expect("timing is an object");
    let mut keys: Vec<&str> = timing.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "cache_total_ms",
            "load_inputs_ms",
            "parse_ms",
            "sql_wall_ms",
            "table_build_ms",
            "total_ms"
        ]
    );
    assert!(
        timing
            .values()
            .all(|v| v.as_f64().is_some_and(|n| n >= 0.0))
    );
    assert!(timing["total_ms"].as_f64() >= timing["sql_wall_ms"].as_f64());
    for once_at_open in [
        "load_inputs_ms",
        "parse_ms",
        "table_build_ms",
        "cache_total_ms",
    ] {
        assert_eq!(timing[once_at_open], 0.0, "{once_at_open}");
    }
    let (plain, error) = server.tool(
        "query",
        json!({"dataset_id":id,"sql":["SELECT 1"],"timing":false}),
    );
    assert!(!error);
    assert!(plain["timing"].is_null());
    let (omitted, _) = server.tool("query", json!({"dataset_id":id,"sql":["SELECT 1"]}));
    assert!(omitted["timing"].is_null());
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
    assert_eq!(late["error"]["kind"], "timeout");
    assert_eq!(
        late["error"]["dataset_closed"], true,
        "HostLab reads error.dataset_closed"
    );
    assert_eq!(late["dataset_id"], slow);
    let (after, error) = server.tool("query", json!({"dataset_id":slow,"sql":["SELECT 1"]}));
    assert!(error);
    assert_eq!(after["error"]["kind"], "unknown_dataset");
    let (fine, error) = server.tool("query", json!({"dataset_id":other,"sql":["SELECT 1"]}));
    assert!(!error, "the other dataset is untouched: {fine}");
}

// ---- decode ----------------------------------------------------------------------

fn decode_fixture(name: &str) -> String {
    fixture(&format!("tests/fixtures/decode/generated/{name}"))
}

fn open_decode(server: &mut Mcp, names: &[&str]) -> String {
    let inputs: Vec<String> = names.iter().map(|n| decode_fixture(n)).collect();
    let (opened, error) = server.tool("open_dataset", json!({ "inputs": inputs }));
    assert!(!error, "{opened}");
    opened["dataset_id"].as_str().unwrap().to_owned()
}

#[test]
fn decode_shows_a_method_as_smali_with_its_numbers_and_one_page() {
    let mut server = Mcp::ready(&[]);
    let id = open_decode(&mut server, &["decode-all.dex"]);
    let (reply, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"method":"Ldecode/T;->params_instance(IJLjava/lang/String;)I"}),
    );
    assert!(!error, "{reply}");
    assert_eq!(reply["mode"], "smali");
    assert_eq!(
        (
            reply["total_methods"].as_u64(),
            reply["method_offset"].as_u64()
        ),
        (Some(1), Some(0))
    );
    assert!(reply["next_method_offset"].is_null());
    let method = &reply["methods"][0];
    let text = ".method public params_instance(IJLjava/lang/String;)I\n    .registers 7\n\n    move v0, v1\n    move-wide p0, p1\n    move-object p2, p4\n    invoke-virtual {p0, p3}, Ldecode/Other;->poke(I)V\n    return v0\n.end method\n";
    assert_eq!(method["smali"], text);
    assert_eq!(
        method["declaration"],
        ".method public params_instance(IJLjava/lang/String;)I"
    );
    assert_eq!(
        method["descriptor"],
        "Ldecode/T;->params_instance(IJLjava/lang/String;)I"
    );
    assert_eq!(
        (method["file_id"].as_u64(), method["registers"].as_u64()),
        (Some(0), Some(7))
    );
    assert_eq!(
        (
            method["access_flags"].as_u64(),
            method["try_count"].as_u64()
        ),
        (Some(1), Some(0))
    );
    assert_eq!(method["total_bytes"], text.len());
    assert_eq!(
        (
            method["total_lines"].as_u64(),
            method["start_line"].as_u64(),
            method["end_line"].as_u64()
        ),
        (Some(9), Some(0), Some(9))
    );
    assert_eq!(
        (
            method["offset"].as_u64(),
            method["starts_mid_line"].as_bool(),
            method["ends_mid_line"].as_bool()
        ),
        (Some(0), Some(false), Some(false))
    );
    assert!(method["next_offset"].is_null());
}

#[test]
fn decode_pages_by_utf8_byte_offset_and_lines_apart() {
    let mut server = Mcp::ready(&[]);
    let id = open_decode(&mut server, &["decode-all.dex"]);
    let (first, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"method":"Ldecode/T;->long_body()V","max_lines":100}),
    );
    assert!(!error, "{first}");
    let page = &first["methods"][0];
    assert_eq!(page["smali"].as_str().unwrap().matches('\n').count(), 100);
    assert_eq!(
        (page["start_line"].as_u64(), page["end_line"].as_u64()),
        (Some(0), Some(100))
    );
    assert_eq!(page["total_lines"], 1505);
    let next = page["next_offset"].as_u64().unwrap();
    assert_eq!(
        next as usize,
        page["smali"].as_str().unwrap().len(),
        "bytes, not lines"
    );
    let (second, _) = server.tool(
        "decode",
        json!({"dataset_id":id,"method":"Ldecode/T;->long_body()V","max_lines":100,"offset":next}),
    );
    let page = &second["methods"][0];
    assert_eq!(
        (page["offset"].as_u64(), page["start_line"].as_u64()),
        (Some(next), Some(100))
    );
    assert_eq!(page["starts_mid_line"], false);
    let (cut, _) = server.tool(
        "decode",
        json!({"dataset_id":id,"method":"Ldecode/T;->long_body()V","max_bytes":10}),
    );
    let page = &cut["methods"][0];
    assert_eq!(page["smali"], ".method pu");
    assert_eq!(
        (
            page["ends_mid_line"].as_bool(),
            page["next_offset"].as_u64()
        ),
        (Some(true), Some(10))
    );
}

#[test]
fn a_descriptor_in_two_dex_files_is_ambiguous_until_file_id_says_which() {
    let mut server = Mcp::ready(&[]);
    let id = open_decode(&mut server, &["decode-all.dex", "decode-v035.dex"]);
    let (ambiguous, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"method":"Ldecode/T;->op_00()V"}),
    );
    assert!(error);
    assert_eq!(ambiguous["dataset_id"], id);
    assert_eq!(ambiguous["error"]["kind"], "ambiguous");
    assert_eq!(
        ambiguous["error"]["message"],
        "method occurs in multiple DEX files; supply file_id from {0, 1}"
    );
    for key in ["file_id", "method_idx", "code_unit_offset"] {
        assert!(ambiguous["error"][key].is_null(), "{key}");
    }
    for file_id in [0, 1] {
        let (one, error) = server.tool(
            "decode",
            json!({"dataset_id":id,"method":"Ldecode/T;->op_00()V","file_id":file_id}),
        );
        assert!(!error, "{one}");
        assert_eq!(one["methods"][0]["file_id"], file_id);
    }
    let (by_key, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"file_id":1,"method_idx":0}),
    );
    assert!(!error, "{by_key}");
    assert_eq!(by_key["methods"][0]["file_id"], 1);
}

#[test]
fn decode_refuses_what_it_cannot_show_and_says_why() {
    let mut server = Mcp::ready(&[]);
    let id = open_decode(&mut server, &["decode-all.dex"]);
    let cases = [
        (json!({"method":"Ldecode/Other;->work()V"}), "not_found"),
        (json!({"method":"Ldecode/T;->nothing()V"}), "not_found"),
        (json!({"file_id":7,"method_idx":0}), "not_found"),
        (json!({}), "invalid_argument"),
        (
            json!({"method":"Ldecode/T;->op_00()V","class":"Ldecode/T;"}),
            "invalid_argument",
        ),
        (json!({"method_idx":0}), "invalid_argument"),
        (json!({"class":"Lnope/Nope;"}), "not_found"),
        (json!({"class":"Ldecode/Other;"}), "not_found"),
        (json!({"class":""}), "invalid_argument"),
        (json!({"class":"Ldecode/T;","offset":5}), "invalid_argument"),
        (
            json!({"class":"Ldecode/T;","mode":"context","method_offset":239}),
            "invalid_range",
        ),
        (
            json!({"method":"Ldecode/T;->op_00()V","offset":10_000}),
            "invalid_range",
        ),
    ];
    for (mut arguments, kind) in cases {
        arguments["dataset_id"] = json!(id);
        let (reply, error) = server.tool("decode", arguments.clone());
        assert!(error, "{arguments} {reply}");
        assert_eq!(reply["error"]["kind"], kind, "{arguments} {reply}");
        assert_eq!(reply["dataset_id"], id);
    }
    // The request is echoed in the error, so a client can tell which of its requests was not found.
    let (missing, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"file_id":7,"method_idx":12345}),
    );
    assert!(error);
    assert_eq!(missing["error"]["file_id"], 7, "{missing}");
    assert_eq!(missing["error"]["method_idx"], 12345, "{missing}");
    // An empty descriptor is a bad argument, not a method that is missing.
    let (empty, error) = server.tool("decode", json!({"dataset_id":id,"method":""}));
    assert!(error);
    assert_eq!(empty["error"]["kind"], "invalid_argument", "{empty}");
    assert!(
        empty["error"]["message"]
            .as_str()
            .unwrap()
            .contains("empty"),
        "{empty}"
    );
    for arguments in [
        json!({"dataset_id":id,"method":"Ldecode/T;->op_00()V","max_lines":0}),
        json!({"dataset_id":id,"method":"Ldecode/T;->op_00()V","max_lines":1001}),
        json!({"dataset_id":id,"method":"Ldecode/T;->op_00()V","mode":"dex"}),
        json!({"dataset_id":id,"method":"Ldecode/T;->op_00()V","method_limit":51}),
        json!({"dataset_id":id,"method":"Ldecode/T;->op_00()V","compact":true}),
        json!({"dataset_id":id,"method":7}),
    ] {
        assert_eq!(
            server.refused("decode", arguments.clone()),
            -32602,
            "{arguments}"
        );
    }
    let (unknown, error) = server.tool(
        "decode",
        json!({"dataset_id":"dataset-nobody","method":"Ldecode/T;->op_00()V"}),
    );
    assert!(error);
    assert_eq!(unknown["error"]["kind"], "unknown_dataset");
}

#[test]
fn decode_summary_has_the_numbers_and_no_text() {
    let mut server = Mcp::ready(&[]);
    let id = open_decode(&mut server, &["decode-all.dex"]);
    let (reply, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"method":"Ldecode/T;->try_catch()V","mode":"summary"}),
    );
    assert!(!error, "{reply}");
    assert_eq!(reply["mode"], "summary");
    let method = &reply["methods"][0];
    assert_eq!(
        (method["registers"].as_u64(), method["try_count"].as_u64()),
        (Some(3), Some(2))
    );
    assert_eq!(method["code_units"], 14);
    assert!(method.get("smali").is_none() || method["smali"].is_null());
    // The summary has no text to continue; the key is there and empty, as in the smali mode.
    assert_eq!(method["next_offset"], Value::Null);
}

fn class_fixture(name: &str) -> String {
    fixture(&format!("tests/fixtures/{name}"))
}

/// Every page of a class, by `next_method_offset`, until it is null.
fn class_walk(server: &mut Mcp, id: &str, extra: Value, limit: u64) -> Vec<Value> {
    let mut pages = Vec::new();
    let mut offset = 0u64;
    // 238 methods at a limit of at least 1: a pager that does not end is a failure, not a hang
    for _ in 0..300 {
        let mut arguments = json!({"dataset_id":id,"class":"Ldecode/T;","method_offset":offset,"method_limit":limit});
        for (key, value) in extra.as_object().unwrap() {
            arguments[key] = value.clone();
        }
        let (reply, error) = server.tool("decode", arguments);
        assert!(!error, "{reply}");
        let next = reply["next_method_offset"].as_u64();
        pages.push(reply);
        match next {
            Some(next) => {
                assert!(next > offset, "a page that does not advance");
                offset = next;
            }
            None => return pages,
        }
    }
    panic!("the class walk did not end");
}

#[test]
fn a_class_is_listed_by_method_idx_in_pages_that_end() {
    let mut server = Mcp::ready(&[]);
    let id = open_decode(&mut server, &["decode-all.dex"]);
    // the default is a summary of 20 methods
    let (first, error) = server.tool("decode", json!({"dataset_id":id,"class":"Ldecode/T;"}));
    assert!(!error, "{first}");
    assert_eq!(first["mode"], "summary");
    assert_eq!(first["methods"].as_array().unwrap().len(), 20);
    assert_eq!(
        (
            first["method_offset"].as_u64(),
            first["next_method_offset"].as_u64(),
            first["total_methods"].as_u64()
        ),
        (Some(0), Some(20), Some(238))
    );
    assert!(first["text_format"].is_null());
    for method in first["methods"].as_array().unwrap() {
        assert!(method["next_offset"].is_null());
        assert!(method.get("smali").is_none());
    }
    // every page, at several limits: the methods are all there, once, in method_idx order
    for limit in [1u64, 7, 20, 50] {
        let pages = class_walk(&mut server, &id, json!({}), limit);
        let mut seen = Vec::new();
        for page in &pages {
            assert_eq!(page["total_methods"], 238);
            for method in page["methods"].as_array().unwrap() {
                seen.push(method["method_idx"].as_u64().unwrap());
            }
        }
        assert_eq!(seen.len(), 238, "limit {limit}");
        assert!(
            seen.windows(2).all(|pair| pair[0] < pair[1]),
            "limit {limit}: not in method_idx order"
        );
        assert_eq!(pages.last().unwrap()["next_method_offset"], Value::Null);
        assert_eq!(pages.len() as u64, 238u64.div_ceil(limit), "limit {limit}");
    }
    // the end: an offset equal to the total is an empty last page, one past it is a range error
    let (end, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"class":"Ldecode/T;","method_offset":238}),
    );
    assert!(!error, "{end}");
    assert_eq!(end["methods"].as_array().unwrap().len(), 0);
    assert_eq!(end["next_method_offset"], Value::Null);
    let (past, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"class":"Ldecode/T;","method_offset":239}),
    );
    assert!(error);
    assert_eq!(past["error"]["kind"], "invalid_range");
}

#[test]
fn a_class_that_two_dex_files_define_needs_the_file_id() {
    let mut server = Mcp::ready(&[]);
    let id = open_decode(&mut server, &["decode-all.dex", "decode-v035.dex"]);
    let (both, error) = server.tool("decode", json!({"dataset_id":id,"class":"Ldecode/T;"}));
    assert!(error);
    assert_eq!(both["error"]["kind"], "ambiguous");
    assert_eq!(
        both["error"]["message"],
        "class occurs in multiple DEX files; supply file_id from {0, 1}"
    );
    for (file_id, total) in [(0u64, 238u64), (1, 2)] {
        let (one, error) = server.tool(
            "decode",
            json!({"dataset_id":id,"class":"Ldecode/T;","file_id":file_id}),
        );
        assert!(!error, "{one}");
        assert_eq!(one["total_methods"], total);
        assert!(
            one["methods"]
                .as_array()
                .unwrap()
                .iter()
                .all(|m| m["file_id"] == file_id)
        );
    }
    let (missing, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"class":"Ldecode/T;","file_id":9}),
    );
    assert!(error);
    assert_eq!(missing["error"]["kind"], "not_found");
    assert_eq!(missing["error"]["file_id"], 9);
}

#[test]
fn the_text_of_a_class_page_continues_on_its_method_never_on_the_class() {
    let mut server = Mcp::ready(&[]);
    let id = open_decode(&mut server, &["decode-all.dex"]);
    let (page, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"class":"Ldecode/T;","mode":"smali","method_offset":11,"method_limit":1,"max_lines":10}),
    );
    assert!(!error, "{page}");
    let long = &page["methods"][0];
    assert_eq!(long["descriptor"], "Ldecode/T;->long_body()V");
    assert_eq!(long["end_line"], 10);
    let next = long["next_offset"]
        .as_u64()
        .expect("the method has more text");
    assert!(page["next_method_offset"].as_u64() == Some(12), "{page}");
    // a class selector with an offset is refused: the offset belongs to a method
    let (refused, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"class":"Ldecode/T;","mode":"smali","offset":next}),
    );
    assert!(error);
    assert_eq!(refused["error"]["kind"], "invalid_argument");
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap()
            .contains("file_id and method_idx")
    );
    // the same offset on the method itself continues the text exactly where the class page stopped
    let mut whole = long["smali"].as_str().unwrap().to_owned();
    let mut offset = next;
    let mut first_rest = None;
    for _ in 0..10 {
        let (rest, error) = server.tool(
            "decode",
            json!({"dataset_id":id,"file_id":long["file_id"],"method_idx":long["method_idx"],"offset":offset,"max_lines":1000}),
        );
        assert!(!error, "{rest}");
        let row = &rest["methods"][0];
        first_rest.get_or_insert_with(|| row["start_line"].clone());
        whole.push_str(row["smali"].as_str().unwrap());
        match row["next_offset"].as_u64() {
            Some(more) => offset = more,
            None => break,
        }
    }
    let mut single_text = String::new();
    let mut offset = 0u64;
    for _ in 0..10 {
        let (single, error) = server.tool(
            "decode",
            json!({"dataset_id":id,"method":"Ldecode/T;->long_body()V","offset":offset,"max_lines":1000}),
        );
        assert!(!error);
        single_text.push_str(single["methods"][0]["smali"].as_str().unwrap());
        match single["methods"][0]["next_offset"].as_u64() {
            Some(more) => offset = more,
            None => break,
        }
    }
    assert_eq!(whole, single_text);
    assert_eq!(
        first_rest.unwrap(),
        10,
        "lines are counted in the whole text"
    );
}

#[test]
fn a_byte_budget_on_a_class_page_is_one_budget_for_all_its_text() {
    let mut server = Mcp::ready(&[]);
    let id = open_decode(&mut server, &["decode-all.dex"]);
    let (page, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"class":"Ldecode/T;","mode":"smali","method_offset":8,"method_limit":50,"max_lines":1000,"max_bytes":900}),
    );
    assert!(!error, "{page}");
    let methods = page["methods"].as_array().unwrap();
    let bytes: usize = methods
        .iter()
        .map(|m| m["smali"].as_str().unwrap().len())
        .sum();
    assert!(bytes <= 900, "{bytes}");
    assert!(methods.len() >= 2 && methods.len() < 50);
    // the method the budget ended in is cut and says where it goes on; the others are whole
    let (last, rest) = methods.split_last().unwrap();
    assert!(rest.iter().all(|m| m["next_offset"].is_null()));
    assert!(
        last["next_offset"].as_u64().is_some() || bytes + 1 > 900 - 4,
        "{last}"
    );
    assert_eq!(
        page["next_method_offset"].as_u64(),
        Some(8 + methods.len() as u64),
        "the cut method counts as shown; the rest is the next page"
    );
    // a budget no character of the first method fits in is an error, not an empty page
    let (none, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"class":"Ldecode/T;","mode":"smali","max_bytes":0}),
    );
    assert!(error, "{none}");
}

#[test]
fn a_byte_budget_on_a_class_summary_counts_the_serialized_rows_and_ends_the_page_before_the_one_that_passes_it()
 {
    let mut server = Mcp::ready(&[]);
    let id = open_decode(&mut server, &["decode-all.dex"]);
    let (page, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"class":"Ldecode/T;","method_limit":50,"max_bytes":600}),
    );
    assert!(!error, "{page}");
    let rows = page["methods"].as_array().unwrap();
    let bytes: usize = rows.iter().map(|row| row.to_string().len()).sum();
    assert!(bytes <= 600, "{bytes} bytes of rows");
    assert!(rows.len() > 1 && rows.len() < 50, "{} rows", rows.len());
    assert_eq!(page["next_method_offset"].as_u64(), Some(rows.len() as u64));
    // the next row would have passed the budget
    let (more, _) = server.tool(
        "decode",
        json!({"dataset_id":id,"class":"Ldecode/T;","method_offset":rows.len(),"method_limit":1}),
    );
    let next_row = more["methods"][0].to_string().len();
    assert!(bytes + next_row > 600, "{bytes} + {next_row}");
    // a budget smaller than one row still shows that row, and the page advances
    let (one, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"class":"Ldecode/T;","max_bytes":1}),
    );
    assert!(!error, "{one}");
    assert_eq!(one["methods"].as_array().unwrap().len(), 1);
    assert_eq!(one["next_method_offset"], 1);
}

#[test]
fn the_context_names_the_lines_of_the_full_text_and_pages_on_its_own() {
    let mut server = Mcp::ready(&[]);
    let id = open_decode(&mut server, &["decode-all.dex"]);
    for descriptor in [
        "Ldecode/T;->switch_packed()V",
        "Ldecode/T;->try_catch()V",
        "Ldecode/T;->branches()V",
        "Ldecode/T;->abstract_one(I)I",
    ] {
        let (full, error) = server.tool(
            "decode",
            json!({"dataset_id":id,"method":descriptor,"max_lines":1000}),
        );
        assert!(!error, "{full}");
        let full_text = full["methods"][0]["smali"].as_str().unwrap();
        let full_lines: Vec<&str> = full_text.split_terminator('\n').collect();
        let (view, error) = server.tool(
            "decode",
            json!({"dataset_id":id,"method":descriptor,"mode":"context","max_lines":1000}),
        );
        assert!(!error, "{view}");
        assert_eq!(view["mode"], "context");
        assert_eq!(view["text_format"], "mdd.smali-context.v1");
        let row = &view["methods"][0];
        // the numbers count lines of the full text: the full text's line count is named, apart
        assert_eq!(row["source_total_lines"], full_lines.len());
        let text = row["smali"].as_str().unwrap();
        let mut lines = text.split_terminator('\n');
        assert_eq!(
            lines.next().unwrap(),
            "# Original zero-based smali line numbers; labels retain method-relative code-unit offsets."
        );
        let mut count = 0;
        for entry in lines {
            let (number, line) = entry
                .strip_prefix("line ")
                .and_then(|rest| rest.split_once(": "))
                .unwrap_or_else(|| panic!("{entry}"));
            let number: usize = number.parse().unwrap();
            assert_eq!(full_lines[number], line, "{descriptor} line {number}");
            let word = line.trim_start();
            assert!(
                word.starts_with(':')
                    || [".method", ".registers", ".catch"]
                        .iter()
                        .any(|w| word.starts_with(w)),
                "{entry}"
            );
            count += 1;
        }
        assert!(count >= 1);
        // the view has its own bytes and lines
        assert_eq!(row["total_bytes"], text.len());
        assert_eq!(row["total_lines"], count + 1);
        assert_ne!(row["total_bytes"], full["methods"][0]["total_bytes"]);
    }
    // an offset into the view is an offset into the view: it does not continue the full text
    let (view, _) = server.tool(
        "decode",
        json!({"dataset_id":id,"method":"Ldecode/T;->switch_packed()V","mode":"context","max_lines":1}),
    );
    let next = view["methods"][0]["next_offset"].as_u64().unwrap();
    let (second, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"method":"Ldecode/T;->switch_packed()V","mode":"context","offset":next,"max_lines":1}),
    );
    assert!(!error, "{second}");
    assert!(
        second["methods"][0]["smali"]
            .as_str()
            .unwrap()
            .starts_with("line 0: .method")
    );
    assert_eq!(second["methods"][0]["start_line"], 1);
}

#[test]
fn a_class_with_annotations_fields_and_debug_info_is_shown_with_all_of_them() {
    let mut server = Mcp::ready(&[]);
    let (opened, error) = server.tool(
        "open_dataset",
        json!({"inputs":[decode_fixture("decode-class.dex")]}),
    );
    assert!(!error, "{opened}");
    assert_eq!(opened["diagnostics"], json!([]));
    let id = opened["dataset_id"].as_str().unwrap();
    let (class, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"class":"Ldecode/K;","mode":"smali","max_lines":1000}),
    );
    assert!(!error, "{class}");
    assert_eq!(class["text_format"], "mdd.smali.v1");
    let header = &class["class"];
    assert_eq!(header["declaration"], ".class public final Ldecode/K;");
    assert_eq!(header["superclass"], "Ljava/lang/Object;");
    assert_eq!(header["source_file"], "K.java");
    assert_eq!(
        header["interfaces"],
        json!(["Ldecode/Marker;", "Ljava/lang/Runnable;"])
    );
    assert_eq!(
        (
            header["static_fields"].as_u64(),
            header["instance_fields"].as_u64()
        ),
        (Some(12), Some(2))
    );
    assert_eq!(header["truncated"], false);
    let text = header["smali"].as_str().unwrap();
    for wanted in [
        ".source \"K.java\"\n",
        ".implements Ldecode/Marker;\n.implements Ljava/lang/Runnable;\n",
        ".annotation runtime Ldecode/Ann;\n    count = 0x3\n    k = \"kk\"\n.end annotation\n",
        ".field public static final a_int:I = 0x1\n",
        ".field private static b_str:Ljava/lang/String; = \"s\\\"q\\n\"\n",
        ".field static c_long:J = -0x2L\n",
        ".field static d_double:D = 2.5\n",
        ".field static e_float:F = 0.1f\n",
        ".field static g_byte:B = -0x1t\n",
        ".field static h_short:S = -0x12cs\n",
        ".field static i_char:C = 'A'\n",
        ".field static j_type:Ljava/lang/Class; = Ljava/lang/String;\n",
        ".field static k_null:Ljava/lang/Object; = null\n",
        ".field static z_none:I\n",
        ".field private volatile transient n_annotated:Ljava/lang/String;\n    .annotation build Ldecode/Ann;\n        count = 0x7ft\n        k = {}\n    .end annotation\n.end field\n",
    ] {
        assert!(text.contains(wanted), "{wanted:?} is not in {text}");
    }
    assert_eq!(header["total_bytes"], text.len());
    // the methods of the class, in method_idx order, with what their facts say
    let by_name = |name: &str| {
        class["methods"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["descriptor"] == format!("Ldecode/K;->{name}"))
            .unwrap_or_else(|| panic!("{name}: {class}"))
    };
    let f = by_name("f(IJLjava/lang/String;)V");
    let f_text = f["smali"].as_str().unwrap();
    for wanted in [
        "    .param p0, \"count\"\n    .param p3, \"label\"\n",
        "    .prologue\n    .line 10\n    .local v0, \"x\":I\n    const/4 v0, 0x1\n",
        "    .local v1, \"y\":Ljava/lang/String;, \"TT;\"\n",
        "    .end local v0\n    .restart local v0\n    invoke-static {p0}, Ldecode/K;->g(I)V\n",
        "    .epilogue\n    return-void\n    .end local v1\n.end method\n",
    ] {
        assert!(f_text.contains(wanted), "{wanted:?} is not in {f_text}");
    }
    // two events the text cannot place and one position that is no source line are counted
    assert_eq!(
        f["omitted"],
        json!({"debug_events_not_at_an_instruction": 1, "positions_not_source_lines": 1})
    );
    // an instance method: p0 is `this`, so the first parameter is p1 and the long that follows starts at p2
    let h = by_name("h(IJ)V")["smali"].as_str().unwrap().to_owned();
    assert!(
        h.contains("    .param p1, \"x\"\n    .param p2, \"y\"\n        .annotation runtime Ldecode/Ann;\n        .end annotation\n    .end param\n"),
        "{h}"
    );
    assert!(
        h.contains("    .local p1, \"x\":I\n    .local p2, \"y\":J\n    .line 40\n    nop\n    .end local p1\n    return-void\n"),
        "{h}"
    );
    assert!(
        !h.contains("p0"),
        "p0 is this and no parameter is called that: {h}"
    );
    // the pc-to-pc pattern writes no line
    let r8 = by_name("r8()V");
    assert!(!r8["smali"].as_str().unwrap().contains(".line"));
    assert_eq!(r8["omitted"], json!({"positions_not_source_lines": 3}));
    // a method annotation and a parameter annotation
    let g = by_name("g(I)V")["smali"].as_str().unwrap().to_owned();
    assert!(g.contains("    .param p0\n        .annotation runtime Ldecode/Ann;\n        .end annotation\n    .end param\n"), "{g}");
    assert!(g.contains("    .annotation runtime Ldecode/Ann;\n        k = {\n            \"a\",\n            \"b\"\n        }\n    .end annotation\n"), "{g}");
    // the class text is one page: small max_lines says it is cut
    let (cut, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"class":"Ldecode/K;","mode":"smali","max_lines":5,"method_limit":1}),
    );
    assert!(!error, "{cut}");
    assert_eq!(cut["class"]["truncated"], true);
    assert_eq!(cut["class"]["end_line"], 5);
    assert_eq!(cut["class"]["total_lines"], 32);
    // a later page of the methods does not repeat the class text
    let (later, _) = server.tool(
        "decode",
        json!({"dataset_id":id,"class":"Ldecode/K;","mode":"smali","method_offset":1}),
    );
    assert!(later["class"].get("smali").is_none());
    assert_eq!(later["class"]["descriptor"], "Ldecode/K;");
    // the summary mode has the class's facts and no text
    let (summary, _) = server.tool("decode", json!({"dataset_id":id,"class":"Ldecode/K;"}));
    assert!(summary["class"].get("smali").is_none());
    assert!(summary["text_format"].is_null());
}

#[test]
fn every_kind_of_annotation_value_is_written_as_the_format_says() {
    let mut server = Mcp::ready(&[]);
    let (opened, error) = server.tool(
        "open_dataset",
        json!({"inputs":[class_fixture("annotations/generated/annotations-038.dex")]}),
    );
    assert!(!error, "{opened}");
    let id = opened["dataset_id"].as_str().unwrap();
    let (class, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"class":"Lfixture/A;","mode":"smali","max_lines":1000}),
    );
    assert!(!error, "{class}");
    let text = class["class"]["smali"].as_str().unwrap();
    for wanted in [
        "    a_byte = -0x80t\n",
        "    b_short = -0x8000s\n",
        "    c_char = '\\uffff'\n",
        "    d_int = -0x80000000\n",
        "    e_long = -0x8000000000000000L\n",
        "    f_float = 1.0f\n",
        "    g_double = 1.0\n",
        "    h_string = \"hello\"\n",
        "    i_type = Ljava/lang/String;\n",
        "    j_field = Lfixture/A;->f:Ljava/util/List;\n",
        "    k_method = Lfixture/A;->m(Ljava/util/List;I)Ljava/util/List;\n",
        "    l_enum = .enum Lfixture/Enum;->E:Lfixture/Enum;\n",
        "    m_method_type = (Ljava/util/List;I)Ljava/util/List;\n",
        "    n_method_handle = method_handle_0\n",
        "    o_array = {\n        \"z\",\n        \"a\",\n        \"z\"\n    }\n",
        "    p_annotation = .subannotation Lfixture/Nested;\n        value = 0x7\n    .end subannotation\n",
        "    q_null = null\n",
        "    r_boolean_false = false\n    s_boolean_true = true\n",
        "    t_nan_float = NaNf\n    u_nan_double = NaN\n    v_infinity_float = Infinityf\n    w_infinity_double = Infinity\n    x_negative_zero = -0.0f\n",
    ] {
        assert!(text.contains(wanted), "{wanted:?} is not in {text}");
    }
    // the same annotations belong to the parameter whose slot holds them, and the empty slot writes nothing
    let m = &class["methods"][0];
    assert_eq!(
        m["descriptor"],
        "Lfixture/A;->m(Ljava/util/List;I)Ljava/util/List;"
    );
    let m_text = m["smali"].as_str().unwrap();
    assert!(m_text.contains("    .param p0\n        .annotation runtime Lfixture/Values;\n"));
    assert!(!m_text.contains(".param p1"), "{m_text}");
}

#[test]
fn a_fault_in_the_references_layer_does_not_take_every_method_body_with_it() {
    let mut server = Mcp::ready(&[]);
    let (opened, error) = server.tool(
        "open_dataset",
        json!({"inputs":[decode_fixture("decode-bad-invoke.dex")]}),
    );
    assert!(!error, "{opened}");
    assert_eq!(opened["diagnostics"][0]["code"], "LAYER_UNAVAILABLE");
    let id = opened["dataset_id"].as_str().unwrap();
    let (reply, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"method":"Ldecode/T;->good()V"}),
    );
    assert!(!error, "the instructions decode on their own: {reply}");
    assert!(
        reply["methods"][0]["smali"]
            .as_str()
            .unwrap()
            .contains("const-string v0, \"fine\"")
    );
    let (calls, error) = server.tool(
        "query",
        json!({"dataset_id":id,"sql":["SELECT * FROM method_calls"]}),
    );
    assert!(
        error,
        "the relation that needs the references still refuses: {calls}"
    );
    assert_eq!(calls["error"]["code"], "INCOMPLETE_FACTS");
}

#[test]
fn a_dataset_decodes_from_its_snapshot_after_the_source_is_gone() {
    let mut server = Mcp::ready(&[]);
    let copy = std::env::temp_dir().join(format!("mdd-decode-{}.dex", std::process::id()));
    std::fs::copy(decode_fixture("decode-v035.dex"), &copy).unwrap();
    let (opened, error) = server.tool("open_dataset", json!({"inputs":[copy.to_string_lossy()]}));
    assert!(!error, "{opened}");
    let id = opened["dataset_id"].as_str().unwrap().to_owned();
    std::fs::remove_file(&copy).unwrap();
    let (reply, error) = server.tool(
        "decode",
        json!({"dataset_id":id,"method":"Ldecode/T;->only_here()V"}),
    );
    assert!(!error, "{reply}");
    assert!(
        reply["methods"][0]["smali"]
            .as_str()
            .unwrap()
            .contains("const-string v0, \"old\"")
    );
}

// ---- get_manifest ----------------------------------------------------------------

fn permission_row(kind: &str) -> Value {
    json!({"attributes": {"android:name": "p.permission"}, "kind": kind})
}

#[test]
fn the_manifest_summary_shows_what_the_archive_says_in_the_references_shape() {
    let mut server = Mcp::ready(&[]);
    let (opened, error) = server.tool(
        "open_dataset",
        json!({"inputs":[decode_fixture("manifest-small.apk")]}),
    );
    assert!(!error, "{opened}");
    assert_eq!(opened["archive_inputs"], json!([0]));
    let id = opened["dataset_id"].as_str().unwrap();
    let (reply, error) = server.tool("get_manifest", json!({"dataset_id":id}));
    assert!(!error, "{reply}");
    // written by hand from the manifest the fixture encodes
    assert_eq!(
        reply,
        json!({
            "application": {},
            "component_counts": {"activity":1,"activity-alias":1,"provider":1,"receiver":1,"service":1},
            "dataset_id": id,
            "input_index": 0,
            "manifest": {"android:versionCode":"7","android:versionName":"7.2","package":"example.test"},
            "next_offset": null,
            "offset": 0,
            "permissions": [
                permission_row("uses-permission"),
                permission_row("uses-permission"),
                permission_row("permission"),
            ],
            "target_sdk": 35,
            "total_rows": 3,
            "truncated": false,
            "uses_sdk": {"android:minSdkVersion":"21","android:targetSdkVersion":"35"},
        })
    );
}

#[test]
fn permissions_page_by_rows_and_the_rest_of_the_summary_repeats_unchanged() {
    let mut server = Mcp::ready(&[]);
    let (opened, _) = server.tool(
        "open_dataset",
        json!({"inputs":[decode_fixture("manifest-small.apk")]}),
    );
    let id = opened["dataset_id"].as_str().unwrap();
    let (first, error) = server.tool("get_manifest", json!({"dataset_id":id,"limit":2}));
    assert!(!error, "{first}");
    assert_eq!(first["permissions"].as_array().unwrap().len(), 2);
    assert_eq!(
        (
            first["offset"].as_u64(),
            first["next_offset"].as_u64(),
            first["truncated"].as_bool(),
            first["total_rows"].as_u64()
        ),
        (Some(0), Some(2), Some(true), Some(3))
    );
    let (second, error) = server.tool(
        "get_manifest",
        json!({"dataset_id":id,"limit":2,"offset":2}),
    );
    assert!(!error, "{second}");
    assert_eq!(second["permissions"], json!([permission_row("permission")]));
    assert_eq!(
        (second["offset"].as_u64(), second["truncated"].as_bool()),
        (Some(2), Some(false))
    );
    assert!(second["next_offset"].is_null());
    for key in [
        "manifest",
        "application",
        "uses_sdk",
        "component_counts",
        "target_sdk",
        "total_rows",
    ] {
        assert_eq!(first[key], second[key], "{key} is the same on every page");
    }
    let (end, error) = server.tool("get_manifest", json!({"dataset_id":id,"offset":3}));
    assert!(!error, "an offset at the end is an empty page: {end}");
    assert_eq!(end["permissions"], json!([]));
    assert!(end["next_offset"].is_null());
    let (past, error) = server.tool("get_manifest", json!({"dataset_id":id,"offset":4}));
    assert!(error);
    assert_eq!(past["error"]["kind"], "invalid_range");
}

#[test]
fn the_manifest_tool_says_why_it_cannot_answer() {
    let mut server = Mcp::ready(&[]);
    let archive = decode_fixture("manifest-small.apk");
    let dex = decode_fixture("decode-v035.dex");
    let (two, _) = server.tool(
        "open_dataset",
        json!({"inputs":[archive, decode_fixture("manifest-small.apk"), dex]}),
    );
    let id = two["dataset_id"].as_str().unwrap();
    assert_eq!(two["archive_inputs"], json!([0, 1]));
    let (several, error) = server.tool("get_manifest", json!({"dataset_id":id}));
    assert!(error);
    assert_eq!(several["error"]["kind"], "invalid_argument");
    assert!(
        several["error"]["message"]
            .as_str()
            .unwrap()
            .contains("input_index")
    );
    let (chosen, error) = server.tool("get_manifest", json!({"dataset_id":id,"input_index":1}));
    assert!(!error, "{chosen}");
    assert_eq!(chosen["input_index"], 1);
    for wrong in [2, 9] {
        let (reply, error) =
            server.tool("get_manifest", json!({"dataset_id":id,"input_index":wrong}));
        assert!(error, "input {wrong} is not an archive");
        assert_eq!(reply["error"]["kind"], "not_archive");
    }

    let (plain, _) = server.tool(
        "open_dataset",
        json!({"inputs":[decode_fixture("decode-v035.dex")]}),
    );
    let (reply, error) = server.tool("get_manifest", json!({"dataset_id":plain["dataset_id"]}));
    assert!(error);
    assert_eq!(reply["error"]["kind"], "not_archive");

    let (bare, _) = server.tool(
        "open_dataset",
        json!({"inputs":[decode_fixture("no-manifest.apk")]}),
    );
    let (reply, error) = server.tool("get_manifest", json!({"dataset_id":bare["dataset_id"]}));
    assert!(error);
    assert_eq!(reply["error"]["kind"], "not_found");

    let (xml, error) = server.tool(
        "get_manifest",
        json!({"dataset_id":id,"input_index":0,"mode":"xml"}),
    );
    assert!(error);
    assert_eq!(xml["error"]["kind"], "not_implemented");
    for arguments in [
        json!({"dataset_id":id,"limit":0}),
        json!({"dataset_id":id,"limit":201}),
        json!({"dataset_id":id,"mode":"json"}),
        json!({"dataset_id":id,"compact":true}),
        json!({"dataset_id":id,"offset":-1}),
        json!({"limit":1}),
    ] {
        assert_eq!(
            server.refused("get_manifest", arguments.clone()),
            -32602,
            "{arguments}"
        );
    }
    let (unknown, error) = server.tool("get_manifest", json!({"dataset_id":"dataset-nobody"}));
    assert!(error);
    assert_eq!(unknown["error"]["kind"], "unknown_dataset");
}

#[test]
fn a_result_over_the_byte_budget_is_refused_for_the_manifest_too() {
    let mut server = Mcp::ready(&[]);
    let (opened, _) = server.tool(
        "open_dataset",
        json!({"inputs":[decode_fixture("manifest-small.apk")]}),
    );
    let (refused, error) = server.tool(
        "get_manifest",
        json!({"dataset_id":opened["dataset_id"],"max_bytes":100}),
    );
    assert!(error);
    assert_eq!(refused["error"]["code"], "QUOTA_EXCEEDED");
    assert!(refused.get("permissions").is_none());
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
    // The server learns that nobody reads its stdout only when a write fails, and a write fails
    // only once every copy of the read end is closed. Tests run in parallel threads of one process,
    // and a thread that forks to start its own server holds a copy of this pipe until its exec: a
    // ping that lands in that window is written without error, the server goes back to reading
    // stdin, and a single ping then waits for ever (seen on Linux, a few runs in a hundred). So
    // ping until the server exits, within a bound.
    let ping = format!("{}\n", json!({"jsonrpc":"2.0","id":1,"method":"ping"}));
    let mut status = None;
    for _ in 0..200 {
        if let Some(stdin) = server.stdin.as_mut() {
            let _ = stdin.write_all(ping.as_bytes());
            let _ = stdin.flush();
        }
        if let Some(done) = server.child.try_wait().unwrap() {
            status = Some(done);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = server.child.kill();
    let status = status.expect("the server did not exit after its stdout was closed");
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
