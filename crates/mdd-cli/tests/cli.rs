//! The actual `meguvizdexdash` process: exit codes, stream separation and framing.
//!
//! Every test starts the real binary, so what is checked is what a shell, a script
//! or a host process sees, not an internal function.
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Command, Stdio},
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

struct Run {
    code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Run {
    fn lines(&self) -> Vec<Value> {
        String::from_utf8(self.stdout.clone())
            .expect("stdout is UTF-8")
            .lines()
            .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{line}: {e}")))
            .collect()
    }

    fn kinds(&self) -> Vec<String> {
        self.lines()
            .iter()
            .map(|line| line["kind"].as_str().unwrap().to_owned())
            .collect()
    }

    fn terminal(&self) -> Value {
        let lines = self.lines();
        let last = lines.last().expect("stdout has lines");
        assert_eq!(last["kind"], "terminal", "stdout must end in a terminal");
        last["terminal"].clone()
    }

    fn batches(&self) -> Vec<Value> {
        self.lines()
            .into_iter()
            .filter(|line| line["kind"] == "batch")
            .map(|line| line["batch"].clone())
            .collect()
    }

    fn error(&self) -> Value {
        let text = String::from_utf8(self.stderr.clone()).unwrap();
        serde_json::from_str(text.trim()).unwrap_or_else(|e| panic!("stderr {text:?}: {e}"))
    }
}

fn run(args: &[&str], stdin: &[u8]) -> Run {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary starts");
    let mut input = child.stdin.take().unwrap();
    let bytes = stdin.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = input.write_all(&bytes);
    });
    let output = child.wait_with_output().expect("the binary finishes");
    writer.join().unwrap();
    Run {
        code: output.status.code().expect("the binary exits normally"),
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

fn query(extra: &[&str]) -> Run {
    let dex = dex();
    let mut args = vec!["query", "--input", dex.as_str()];
    args.extend_from_slice(extra);
    run(&args, b"")
}

const TYPES: &str = "SELECT type_idx FROM types ORDER BY type_idx";

fn total_types() -> u64 {
    let r = query(&["--dialect", "dexsql-0.1.0", "--sql", TYPES]);
    r.terminal()["response"]["emitted_rows"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

// ---- success, empty, batching ----------------------------------------------

#[test]
fn a_complete_query_ends_in_an_ok_terminal_with_exit_zero_and_a_clean_stderr() {
    let r = query(&["--sql", "SELECT 1 AS one, 'x' AS s"]);
    assert_eq!(r.code, 0);
    assert!(
        r.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(r.kinds(), ["opened", "batch", "terminal"]);
    let lines = r.lines();
    assert_eq!(lines[0]["protocol"], "mdd.cli-stream.v1");
    assert_eq!(lines[1]["batch"]["schema"], "mdd.sdk-batch.v1");
    assert_eq!(
        lines[1]["batch"]["rows"][0][0],
        serde_json::json!({"t":"i64","v":"1"})
    );
    let terminal = r.terminal();
    assert_eq!(terminal["operation_status"], "ok");
    assert_eq!(terminal["execution"]["complete"], true);
    assert_eq!(terminal["response"]["truncated"], false);
    assert_eq!(terminal["response"]["emitted_rows"], "1");
    assert!(terminal["error"].is_null());
}

#[test]
fn the_dialect_that_was_asked_for_is_the_one_that_answers() {
    for (asked, profile) in [
        ("native-v1", "native-unqualified"),
        ("dexsql-0.1.0", "hostlab-contract-unqualified"),
        ("dexsql-0.1.1", "hostlab-contract-unqualified"),
    ] {
        let r = query(&["--dialect", asked, "--sql", "SELECT 1 AS one"]);
        assert_eq!(r.code, 0, "{asked}");
        assert_eq!(r.lines()[0]["dataset"]["sql_dialect"], asked);
        let terminal = r.terminal();
        assert_eq!(terminal["sql_dialect"], asked);
        assert_eq!(terminal["profile"], profile);
        assert_eq!(r.lines()[0]["dataset"]["profile"], profile);
    }
}

#[test]
fn an_empty_result_is_a_complete_success_with_no_batch() {
    let r = query(&[
        "--dialect",
        "dexsql-0.1.0",
        "--sql",
        "SELECT type_idx FROM types WHERE type_idx < 0",
    ]);
    assert_eq!(r.code, 0);
    assert_eq!(r.kinds(), ["opened", "terminal"]);
    let terminal = r.terminal();
    assert_eq!(terminal["response"]["emitted_rows"], "0");
    assert_eq!(terminal["response"]["total_rows"], "0");
    assert_eq!(terminal["response"]["total_rows_exact"], true);
    assert_eq!(terminal["response"]["truncated"], false);
    assert_eq!(
        terminal["data"]["columns"],
        serde_json::json!(["type_idx"]),
        "an empty result has no batch, so the terminal names the columns"
    );
}

#[test]
fn batches_are_numbered_from_zero_and_add_up_to_the_terminal_row_count() {
    let total = total_types();
    assert!(total >= 4, "the fixture must have several types");
    let r = query(&[
        "--dialect",
        "dexsql-0.1.0",
        "--batch-rows",
        "3",
        "--sql",
        TYPES,
    ]);
    assert_eq!(r.code, 0);
    let batches = r.batches();
    assert_eq!(batches.len() as u64, total.div_ceil(3));
    let mut next_row = 0u64;
    for (sequence, batch) in batches.iter().enumerate() {
        assert_eq!(batch["sequence"], sequence.to_string());
        assert_eq!(batch["first_row"], next_row.to_string());
        let rows = batch["row_count"].as_u64().unwrap();
        assert_eq!(batch["rows"].as_array().unwrap().len() as u64, rows);
        assert!((1..=3).contains(&rows));
        next_row += rows;
    }
    assert_eq!(next_row, total);
    assert_eq!(r.terminal()["response"]["emitted_rows"], total.to_string());
}

// ---- failure terminals ------------------------------------------------------

#[test]
fn a_row_limit_ends_in_a_truncated_failure_never_a_success() {
    let total = total_types();
    assert!(total > 2);
    let r = query(&[
        "--dialect",
        "dexsql-0.1.0",
        "--batch-rows",
        "1",
        "--max-rows",
        "2",
        "--sql",
        TYPES,
    ]);
    assert_eq!(r.code, 1);
    let delivered: u64 = r
        .batches()
        .iter()
        .map(|b| b["row_count"].as_u64().unwrap())
        .sum();
    assert_eq!(delivered, 2, "exactly the allowed rows were written");
    let terminal = r.terminal();
    assert_eq!(terminal["operation_status"], "error");
    assert_eq!(terminal["error"]["code"], "QUOTA_EXCEEDED");
    assert_eq!(terminal["error"]["details"]["budget"], "max_rows");
    assert_eq!(terminal["response"]["truncated"], true);
    assert_eq!(terminal["response"]["emitted_rows"], "2");
    assert_eq!(
        terminal["execution"]["complete"], true,
        "the computation finished"
    );
    assert!(r.stderr.is_empty());
}

const BIG: &str = "SELECT a.type_idx FROM types a, types b, types c, types d, types e, types f";

#[test]
fn the_default_sql_budget_refuses_a_result_that_is_too_large_instead_of_cutting_it() {
    let r = query(&["--dialect", "dexsql-0.1.0", "--sql", BIG]);
    assert_eq!(r.code, 1);
    assert!(r.batches().is_empty());
    assert_eq!(r.terminal()["error"]["code"], "QUOTA_EXCEEDED");
    assert_eq!(r.terminal()["error"]["message"], "SQL_RESULT_BUDGET");
}

#[test]
fn raising_the_sql_budgets_lets_the_same_statement_through_and_lowering_them_stops_a_small_one() {
    let raised = query(&[
        "--dialect",
        "dexsql-0.1.0",
        "--batch-rows",
        "10000",
        "--sql-max-result-rows",
        "600000",
        "--sql-max-scanned-rows",
        "100000000",
        "--sql-max-steps",
        "1000000000",
        "--sql",
        BIG,
    ]);
    assert_eq!(raised.code, 0, "{}", raised.terminal()["error"]);
    assert_eq!(raised.terminal()["response"]["emitted_rows"], "531441");

    let lowered = query(&[
        "--dialect",
        "dexsql-0.1.0",
        "--sql-max-result-rows",
        "2",
        "--sql",
        TYPES,
    ]);
    assert_eq!(lowered.code, 1);
    assert_eq!(lowered.terminal()["error"]["message"], "SQL_RESULT_BUDGET");
}

#[test]
fn a_sql_budget_must_be_a_positive_number() {
    for (flag, value) in [
        ("--sql-max-steps", "0"),
        ("--sql-max-scanned-rows", "0"),
        ("--sql-max-result-rows", "-5"),
        ("--sql-max-result-rows", "many"),
    ] {
        let r = query(&[flag, value, "--sql", "SELECT 1"]);
        assert_eq!(r.code, 2, "{flag} {value}");
        assert!(r.stdout.is_empty());
        assert_eq!(r.error()["code"], "INVALID_ARGUMENT");
    }
}

#[test]
fn a_statement_that_outlives_its_deadline_ends_in_a_deadline_terminal_with_no_rows() {
    let r = query(&[
        "--dialect",
        "dexsql-0.1.0",
        "--deadline-ms",
        "1",
        "--sql",
        "SELECT a.type_idx FROM types a, types b, types c, types d, types e",
    ]);
    assert_eq!(r.code, 1);
    assert!(
        r.batches().is_empty(),
        "a late answer must not be delivered"
    );
    let terminal = r.terminal();
    assert_eq!(terminal["error"]["code"], "DEADLINE_EXCEEDED");
    assert_eq!(terminal["response"]["emitted_rows"], "0");
}

#[test]
fn a_statement_the_engine_refuses_is_a_failure_terminal_on_stdout_with_exit_one() {
    let r = query(&[
        "--dialect",
        "dexsql-0.1.0",
        "--sql",
        "SELECT * FROM no_such_relation",
    ]);
    assert_eq!(r.code, 1);
    assert_eq!(r.kinds(), ["opened", "terminal"]);
    let terminal = r.terminal();
    assert_eq!(terminal["operation_status"], "error");
    assert!(terminal["error"]["code"].is_string());
    assert_eq!(terminal["response"]["emitted_rows"], "0");
    assert!(
        r.stderr.is_empty(),
        "the error is in the terminal, not on stderr"
    );
}

#[test]
fn a_relation_the_dialect_does_not_have_is_an_error_not_an_empty_table() {
    let r = query(&[
        "--dialect",
        "native-v1",
        "--sql",
        "SELECT * FROM method_calls",
    ]);
    assert_eq!(r.code, 1, "{}", String::from_utf8_lossy(&r.stdout));
    assert!(r.batches().is_empty());
    let terminal = r.terminal();
    assert_eq!(terminal["operation_status"], "error");
    assert_eq!(terminal["error"]["message"], "UNKNOWN_RELATION");
}

#[test]
fn a_layer_that_cannot_be_built_is_named_and_its_relations_refuse_instead_of_answering_empty() {
    // The code item of this DEX uses a reserved opcode, so the code, reference and
    // annotation layers cannot be built. The structure layer still can.
    let broken = fixture("tests/fixtures/instructions/generated/bad-reserved-opcode.dex");
    let common = [
        "query",
        "--input",
        broken.as_str(),
        "--dialect",
        "dexsql-0.1.0",
        "--sql",
    ];
    let run_sql = |sql: &str| {
        let mut args = common.to_vec();
        args.push(sql);
        run(&args, b"")
    };

    let types = run_sql("SELECT type_idx FROM types");
    assert_eq!(types.code, 0, "the structure layer is intact");
    let opened = &types.lines()[0]["dataset"];
    let issues = opened["layer_issues"].as_array().unwrap();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0]["layers"], "code,references,annotations");
    assert_eq!(issues[0]["error"]["code"], "INVALID_INPUT");

    for relation in ["code_items", "method_calls", "method_strings"] {
        let r = run_sql(&format!("SELECT * FROM {relation}"));
        assert_eq!(r.code, 1, "{relation}");
        assert!(r.batches().is_empty(), "{relation} answered with rows");
        assert_eq!(
            r.terminal()["error"]["code"],
            "INCOMPLETE_FACTS",
            "{relation}"
        );
    }
}

// ---- refusals before anything runs -----------------------------------------

#[test]
fn a_refusal_has_an_empty_stdout_a_json_error_on_stderr_and_exit_two() {
    let dex = dex();
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec!["unknown-command"], "INVALID_ARGUMENT"),
        (vec![], "INVALID_ARGUMENT"),
        (vec!["version", "extra"], "INVALID_ARGUMENT"),
        (vec!["query", "--sql", "SELECT 1"], "INVALID_ARGUMENT"),
        (vec!["query", "--input", dex.as_str()], "INVALID_ARGUMENT"),
        (
            vec![
                "query",
                "--input",
                dex.as_str(),
                "--sql",
                "SELECT 1",
                "--sql-file",
                "x",
            ],
            "INVALID_ARGUMENT",
        ),
        (
            vec![
                "query",
                "--input",
                dex.as_str(),
                "--sql",
                "SELECT 1",
                "--sql",
                "SELECT 2",
            ],
            "INVALID_ARGUMENT",
        ),
        (
            vec![
                "query",
                "--input",
                dex.as_str(),
                "--sql",
                "SELECT 1",
                "--dialect",
                "sqlite",
            ],
            "INVALID_ARGUMENT",
        ),
        (
            vec![
                "query",
                "--input",
                dex.as_str(),
                "--sql",
                "SELECT 1",
                "--batch-rows",
                "0",
            ],
            "INVALID_ARGUMENT",
        ),
        (
            vec![
                "query",
                "--input",
                dex.as_str(),
                "--sql",
                "SELECT 1",
                "--max-rows",
                "-1",
            ],
            "INVALID_ARGUMENT",
        ),
        (
            vec![
                "query",
                "--input",
                dex.as_str(),
                "--sql",
                "SELECT 1",
                "--deadline-ms",
                "0",
            ],
            "INVALID_ARGUMENT",
        ),
        (
            vec![
                "query",
                "--input",
                dex.as_str(),
                "--sql",
                "SELECT 1",
                "--bogus",
                "1",
            ],
            "INVALID_ARGUMENT",
        ),
        (
            vec![
                "query",
                "--input",
                dex.as_str(),
                "--sql",
                "SELECT 1",
                "--input",
            ],
            "INVALID_ARGUMENT",
        ),
        (
            vec![
                "query",
                "--input",
                dex.as_str(),
                "--sql",
                "SELECT 1",
                "--format",
                "dexsql-table",
            ],
            "UNSUPPORTED_CAPABILITY",
        ),
        (
            vec!["query", "--input", "no-such-file.dex", "--sql", "SELECT 1"],
            "INVALID_INPUT",
        ),
        (vec!["serve"], "INVALID_ARGUMENT"),
        (
            vec!["serve", "--input", dex.as_str(), "--sql", "SELECT 1"],
            "INVALID_ARGUMENT",
        ),
    ];
    for (args, code) in cases {
        let r = run(&args, b"");
        assert_eq!(r.code, 2, "{args:?}");
        assert!(r.stdout.is_empty(), "{args:?} wrote to stdout");
        assert_eq!(r.error()["code"], code, "{args:?}");
    }
}

#[test]
fn a_statement_over_the_read_bound_is_refused_not_slurped() {
    let dex = dex();
    let huge = vec![b'x'; 1024 * 1024 + 16];
    let r = run(&["query", "--input", &dex, "--sql-file", "-"], &huge);
    assert_eq!(r.code, 2);
    assert!(r.stdout.is_empty());
    assert_eq!(r.error()["code"], "INVALID_ARGUMENT");
}

#[test]
fn a_statement_can_come_from_a_file() {
    let dex = dex();
    let path = std::env::temp_dir().join(format!("mdd-cli-statement-{}.sql", std::process::id()));
    std::fs::write(&path, "SELECT 5 AS five").unwrap();
    let r = run(
        &[
            "query",
            "--input",
            &dex,
            "--sql-file",
            path.to_str().unwrap(),
        ],
        b"",
    );
    std::fs::remove_file(&path).ok();
    assert_eq!(r.code, 0);
    assert_eq!(
        r.batches()[0]["rows"][0][0],
        serde_json::json!({"t":"i64","v":"5"})
    );
}

#[test]
fn a_statement_can_come_from_stdin() {
    let dex = dex();
    let r = run(
        &["query", "--input", &dex, "--sql-file", "-"],
        b"SELECT 41 + 1 AS n",
    );
    assert_eq!(r.code, 0);
    assert_eq!(
        r.batches()[0]["rows"][0][0],
        serde_json::json!({"t":"i64","v":"42"})
    );
}

// ---- human output -----------------------------------------------------------

#[test]
fn text_output_is_a_table_on_stdout_and_the_summary_is_on_stderr() {
    let r = query(&["--format", "text", "--sql", "SELECT 1 AS one, NULL AS gap"]);
    assert_eq!(r.code, 0);
    let out = String::from_utf8(r.stdout).unwrap();
    assert!(out.starts_with("| one | gap  |"), "{out}");
    assert!(out.contains("| 1   | NULL |"), "{out}");
    assert!(
        String::from_utf8(r.stderr)
            .unwrap()
            .contains("1 row(s), complete")
    );
}

#[test]
fn text_output_of_a_failed_statement_prints_no_table_and_exits_one() {
    let r = query(&[
        "--format",
        "text",
        "--dialect",
        "dexsql-0.1.0",
        "--max-rows",
        "1",
        "--sql",
        TYPES,
    ]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.is_empty(), "a half table would read like a result");
    assert_eq!(r.error()["code"], "QUOTA_EXCEEDED");
}

// ---- serve ------------------------------------------------------------------

fn requests(lines: &[&str]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for line in lines {
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
    }
    bytes
}

fn serve(lines: &[&str]) -> Run {
    let dex = dex();
    run(
        &["serve", "--input", &dex, "--dialect", "dexsql-0.1.0"],
        &requests(lines),
    )
}

#[test]
fn serve_answers_requests_in_order_and_each_ends_in_exactly_one_terminal() {
    let r = serve(&[
        r#"{"id":"a","sql":"SELECT type_idx FROM types ORDER BY type_idx","batch_rows":2}"#,
        r#"{"id":"b","sql":"SELECT 1 AS one"}"#,
        r#"{"op":"close"}"#,
        r#"{"id":"never","sql":"SELECT 2"}"#,
    ]);
    assert_eq!(r.code, 0);
    assert!(r.stderr.is_empty());
    let lines = r.lines();
    assert_eq!(lines[0]["kind"], "opened");
    let mut terminals = Vec::new();
    let mut open: Option<String> = None;
    for line in &lines[1..] {
        let id = line["id"].as_str().unwrap().to_owned();
        match line["kind"].as_str().unwrap() {
            "batch" => {
                assert!(open.is_none() || open.as_deref() == Some(id.as_str()));
                open = Some(id);
            }
            "terminal" => {
                assert!(open.is_none() || open.as_deref() == Some(id.as_str()));
                open = None;
                assert_eq!(line["terminal"]["operation_status"], "ok");
                terminals.push(id);
            }
            other => panic!("unexpected line kind {other}"),
        }
    }
    assert_eq!(
        terminals,
        ["a", "b"],
        "close ended the session before `never`"
    );
}

#[test]
fn a_failed_request_does_not_end_the_session() {
    let r = serve(&[
        r#"{"id":"bad","sql":"SELECT * FROM no_such_relation"}"#,
        r#"{"id":"good","sql":"SELECT 7 AS seven"}"#,
    ]);
    assert_eq!(
        r.code, 0,
        "failures are in terminals; the session itself was fine"
    );
    let terminals: Vec<Value> = r
        .lines()
        .into_iter()
        .filter(|line| line["kind"] == "terminal")
        .collect();
    assert_eq!(terminals.len(), 2);
    assert_eq!(terminals[0]["id"], "bad");
    assert_eq!(terminals[0]["terminal"]["operation_status"], "error");
    assert_eq!(terminals[1]["id"], "good");
    assert_eq!(terminals[1]["terminal"]["operation_status"], "ok");
}

#[test]
fn lines_that_are_not_requests_are_rejected_one_by_one_and_nothing_runs() {
    let long = format!(r#"{{"id":"x","sql":"{}"}}"#, "A".repeat(1024 * 1024 + 8));
    let r = serve(&[
        "not json",
        r#"{"id":"a","sql":"SELECT 1","surprise":true}"#,
        r#"{"sql":"SELECT 1"}"#,
        r#"{"id":"","sql":"SELECT 1"}"#,
        r#"{"id":"a"}"#,
        r#"{"id":"a","op":"drop","sql":"SELECT 1"}"#,
        &long,
        r#"{"id":"ok","sql":"SELECT 1"}"#,
    ]);
    assert_eq!(r.code, 0);
    let lines = r.lines();
    let rejected = lines.iter().filter(|l| l["kind"] == "rejected").count();
    assert_eq!(rejected, 7);
    for line in lines.iter().filter(|l| l["kind"] == "rejected") {
        assert_eq!(line["error"]["code"], "INVALID_ARGUMENT");
    }
    let last = lines.last().unwrap();
    assert_eq!(
        (last["kind"].as_str(), last["id"].as_str()),
        (Some("terminal"), Some("ok"))
    );
}

#[test]
fn per_request_options_are_checked_and_a_bad_one_fails_that_request_only() {
    let r = serve(&[
        r#"{"id":"zero","sql":"SELECT 1","batch_rows":0}"#,
        r#"{"id":"huge","sql":"SELECT 1","batch_rows":10001}"#,
        r#"{"id":"over","sql":"SELECT 1","deadline_ms":999999999}"#,
        r#"{"id":"none","sql":"SELECT 1","deadline_ms":0}"#,
        r#"{"id":"cap","sql":"SELECT type_idx FROM types ORDER BY type_idx","batch_rows":1,"max_rows":1}"#,
        r#"{"id":"fine","sql":"SELECT 1"}"#,
    ]);
    assert_eq!(r.code, 0);
    let terminals: Vec<Value> = r
        .lines()
        .into_iter()
        .filter(|line| line["kind"] == "terminal")
        .collect();
    let verdicts: Vec<(&str, &str)> = terminals
        .iter()
        .map(|t| {
            (
                t["id"].as_str().unwrap(),
                t["terminal"]["error"]["code"].as_str().unwrap_or("ok"),
            )
        })
        .collect();
    assert_eq!(
        verdicts,
        [
            ("zero", "INVALID_ARGUMENT"),
            ("huge", "INVALID_ARGUMENT"),
            ("over", "INVALID_ARGUMENT"),
            ("none", "INVALID_ARGUMENT"),
            ("cap", "QUOTA_EXCEEDED"),
            ("fine", "ok")
        ]
    );
    assert_eq!(terminals[4]["terminal"]["response"]["truncated"], true);
}

#[test]
fn a_request_can_shorten_the_deadline_of_its_own_statement() {
    let r = serve(&[
        r#"{"id":"slow","sql":"SELECT a.type_idx FROM types a, types b, types c, types d, types e","deadline_ms":1}"#,
        r#"{"id":"after","sql":"SELECT 1"}"#,
    ]);
    assert_eq!(r.code, 0);
    let terminals: Vec<Value> = r
        .lines()
        .into_iter()
        .filter(|line| line["kind"] == "terminal")
        .collect();
    assert_eq!(
        terminals[0]["terminal"]["error"]["code"],
        "DEADLINE_EXCEEDED"
    );
    assert_eq!(
        terminals[1]["terminal"]["operation_status"], "ok",
        "the next request has the full ceiling"
    );
}

#[test]
fn a_request_without_a_trailing_newline_at_end_of_input_is_still_answered() {
    let dex = dex();
    let r = run(
        &["serve", "--input", &dex],
        br#"{"id":"last","sql":"SELECT 1"}"#,
    );
    assert_eq!(r.code, 0);
    assert_eq!(r.terminal()["operation_status"], "ok");
}

// ---- the reader goes away ---------------------------------------------------

#[test]
fn a_closed_output_pipe_ends_the_command_with_exit_four() {
    let dex = dex();
    let mut child = Command::new(BIN)
        .args([
            "query",
            "--input",
            &dex,
            "--dialect",
            "dexsql-0.1.0",
            "--batch-rows",
            "50",
            "--sql",
            "SELECT a.type_idx, b.type_idx, c.type_idx FROM types a, types b, types c",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut first = String::new();
    reader.read_line(&mut first).unwrap();
    assert!(first.contains("\"opened\""));
    drop(reader);
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
