//! The shell against the real `meguvizdexdash mcp` process: no stand-in engine anywhere.
//! Build the engine first (`cargo build -p mdd-cli` in the repository root) or set MDD_ENGINE.
use mdd_desktop::api::{self, CallRequest};
use mdd_desktop::engine::{Engine, Settings, locate_binary};
use mdd_desktop::export::{ExportRequest, Format};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn fixture(relative: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(relative)
        .canonicalize()
        .unwrap_or_else(|e| panic!("fixture {relative}: {e}"))
        .display()
        .to_string()
        .trim_start_matches(r"\\?\")
        .to_owned()
}

fn settings() -> Settings {
    Settings {
        sql_max_steps: Some(4_000_000_000),
        sql_max_scanned_rows: Some(50_000_000),
        ..Settings::default()
    }
}

fn engine() -> Arc<Engine> {
    let binary = locate_binary();
    assert!(
        binary.is_file(),
        "the engine binary is missing at {}: run `cargo build -p mdd-cli` in the repository root",
        binary.display()
    );
    Arc::new(Engine::new(binary, settings()))
}

fn wait_until_busy(engine: &Engine) {
    let begun = Instant::now();
    while engine.busy().is_none() {
        assert!(
            begun.elapsed() < Duration::from_secs(20),
            "the call never took the engine's slot"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn call_id(label: &str) -> String {
    format!("test-{label}")
}

fn open(engine: &Engine, name: &str) -> u64 {
    let reply = api::open_inputs(engine, &call_id("open"), vec![fixture(name)]);
    assert!(reply.ok, "{}", reply.data);
    reply.data["handle"].as_u64().unwrap()
}

fn query(engine: &Engine, handle: u64, sql: &str) -> mdd_desktop::engine::Reply {
    api::call(
        engine,
        CallRequest {
            call_id: call_id("query"),
            tool: "query".to_owned(),
            handle: Some(handle),
            args: json!({"sql": [sql], "limit": 50}),
            deadline_ms: Some(60_000),
        },
    )
}

const SMALL: &str = "decode/generated/manifest-small.apk";
/// A fourteen-fold cross join of the fixture's six strings: 6^14 rows, far more work than any test waits
/// for, so only the shell's cancel or deadline ends it early.
const HEAVY: &str = "SELECT count(*) FROM strings a, strings b, strings c, strings d, strings e, strings f, strings g, strings h, strings i, strings j, strings k, strings l, strings m, strings n";

#[test]
fn an_input_opens_and_a_query_pages_through_the_shells_handle() {
    let engine = engine();
    let handle = open(&engine, SMALL);
    let state = api::engine_state(&engine);
    assert_eq!(state["datasets"][0]["handle"], handle);
    assert_eq!(state["datasets"][0]["live"], true);
    let reply = query(&engine, handle, "SELECT count(*) AS n FROM methods");
    assert!(reply.ok, "{}", reply.data);
    assert_eq!(reply.data["statements"][0]["columns"][0]["name"], "n");
    // the window never sees (or may set) the engine's dataset id
    let refused = api::call(
        &engine,
        CallRequest {
            call_id: call_id("raw-id"),
            tool: "list_tables".to_owned(),
            handle: None,
            args: json!({"dataset_id": "dataset-x"}),
            deadline_ms: None,
        },
    );
    assert!(!refused.ok);
    assert_eq!(refused.data["error"]["code"], "INVALID_ARGUMENT");
    let unknown = api::call(
        &engine,
        CallRequest {
            call_id: call_id("unknown"),
            tool: "run_shell".to_owned(),
            handle: None,
            args: json!({}),
            deadline_ms: None,
        },
    );
    assert_eq!(unknown.data["error"]["code"], "UNKNOWN_TOOL");
    let missing = api::call(
        &engine,
        CallRequest {
            call_id: call_id("handle"),
            tool: "query".to_owned(),
            handle: Some(999),
            args: json!({"sql": ["SELECT 1"]}),
            deadline_ms: None,
        },
    );
    assert_eq!(missing.data["error"]["code"], "UNKNOWN_HANDLE");
    engine.stop();
}

#[test]
fn an_input_that_is_not_there_or_not_a_dex_is_refused_and_nothing_is_remembered() {
    let engine = engine();
    let missing = std::env::temp_dir().join("mdd-desktop-no-such-file.apk");
    let gone = api::open_inputs(
        &engine,
        &call_id("gone"),
        vec![missing.display().to_string()],
    );
    assert!(!gone.ok);
    assert_eq!(gone.data["error"]["code"], "INPUT_NOT_FOUND");
    let not_dex = api::open_inputs(&engine, &call_id("text"), vec![fixture("../../README.md")]);
    assert!(!not_dex.ok, "{}", not_dex.data);
    assert!(
        api::engine_state(&engine)["datasets"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    engine.stop();
}

#[test]
fn one_request_at_a_time_and_the_second_is_told_what_is_running() {
    let engine = engine();
    let handle = open(&engine, SMALL);
    let background = {
        let engine = engine.clone();
        thread::spawn(move || query(&engine, handle, HEAVY))
    };
    // wait until the heavy query holds the slot
    let begun = Instant::now();
    while engine.busy().is_none() {
        assert!(
            begun.elapsed() < Duration::from_secs(10),
            "the heavy query never started"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let second = api::call(
        &engine,
        CallRequest {
            call_id: call_id("second"),
            tool: "list_tables".to_owned(),
            handle: None,
            args: json!({}),
            deadline_ms: None,
        },
    );
    assert!(!second.ok);
    assert_eq!(second.data["error"]["code"], "ENGINE_BUSY");
    assert!(
        second.data["error"]["message"]
            .as_str()
            .unwrap()
            .contains("SELECT"),
        "{}",
        second.data
    );
    assert!(engine.cancel(&call_id("query")));
    let first = background.join().unwrap();
    assert_eq!(first.data["error"]["code"], "CANCELLED", "{}", first.data);
    engine.stop();
}

#[test]
fn cancelling_ends_the_process_quickly_and_the_next_call_reopens_the_input() {
    let engine = engine();
    let handle = open(&engine, SMALL);
    let before = query(&engine, handle, "SELECT count(*) FROM methods");
    assert!(before.ok);
    let background = {
        let engine = engine.clone();
        thread::spawn(move || query(&engine, handle, HEAVY))
    };
    wait_until_busy(&engine);
    thread::sleep(Duration::from_millis(300)); // let the engine really be inside the statement
    let asked = Instant::now();
    assert!(engine.cancel(&call_id("query")));
    let reply = background.join().unwrap();
    let took = asked.elapsed();
    assert_eq!(reply.data["error"]["code"], "CANCELLED", "{}", reply.data);
    assert!(took < Duration::from_secs(2), "the cancel took {took:?}");
    assert!(!engine.running(), "the engine process is gone");
    assert!(engine.busy().is_none(), "the slot is free");
    let state = api::engine_state(&engine);
    assert_eq!(
        state["datasets"][0]["live"], false,
        "the dataset is remembered, not live"
    );
    // the same handle works again: the input is opened anew on demand
    let after = query(&engine, handle, "SELECT count(*) FROM methods");
    assert!(after.ok, "{}", after.data);
    assert!(after.started_engine || engine.running());
    assert_eq!(
        before.data["statements"][0]["rows"],
        after.data["statements"][0]["rows"]
    );
    assert_eq!(api::engine_state(&engine)["datasets"][0]["live"], true);
    engine.stop();
}

#[test]
fn a_query_past_its_deadline_is_reported_and_the_dataset_comes_back_on_the_next_call() {
    let engine = engine();
    let handle = open(&engine, SMALL);
    let reply = api::call(
        &engine,
        CallRequest {
            call_id: call_id("deadline"),
            tool: "query".to_owned(),
            handle: Some(handle),
            args: json!({"sql": [HEAVY], "timeout_ms": 300}),
            deadline_ms: None,
        },
    );
    assert!(!reply.ok);
    assert_eq!(
        reply.data["error"]["code"], "DEADLINE_EXCEEDED",
        "{}",
        reply.data
    );
    // whichever side ended the dataset, the handle is usable again
    let again = query(&engine, handle, "SELECT count(*) FROM types");
    assert!(again.ok, "{}", again.data);
    engine.stop();
}

#[test]
fn an_engine_that_cannot_start_is_a_named_error_not_a_hang() {
    let engine = Engine::new(
        std::env::temp_dir().join("mdd-desktop-no-such-engine.exe"),
        Settings::default(),
    );
    let reply = api::open_inputs(&engine, &call_id("nobin"), vec![fixture(SMALL)]);
    assert!(!reply.ok);
    assert_eq!(
        reply.data["error"]["code"], "ENGINE_NOT_FOUND",
        "{}",
        reply.data
    );
}

#[test]
fn changing_the_settings_restarts_the_engine_and_keeps_the_inputs() {
    let engine = engine();
    let handle = open(&engine, SMALL);
    let mut changed = engine.settings();
    changed.dialect = "dexsql-0.1.1".to_owned();
    assert_eq!(api::configure(&engine, changed)["ok"], true);
    assert!(!engine.running());
    let reply = query(&engine, handle, "SELECT count(*) FROM methods");
    assert!(reply.ok, "{}", reply.data);
    let mut bad = engine.settings();
    bad.dialect = "native-v1".to_owned();
    assert_eq!(api::configure(&engine, bad)["ok"], false);
    engine.stop();
}

fn export_request(handle: u64, sql: &str, format: Format, path: &Path) -> ExportRequest {
    ExportRequest {
        call_id: call_id("export"),
        handle,
        sql: sql.to_owned(),
        format,
        path: path.display().to_string(),
        page_rows: Some(2),
        deadline_ms: Some(60_000),
    }
}

fn temp_file(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mdd-desktop-tests-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

/// A folder that belongs to this test run and holds one file, so that treating it as a file is visible.
fn private_folder(name: &str) -> PathBuf {
    let folder = temp_file(name);
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("keep.txt"), b"kept").unwrap();
    folder
}

#[test]
fn an_export_writes_every_row_in_pages_and_the_count_matches_the_query() {
    let engine = engine();
    let handle = open(&engine, SMALL);
    let counted = query(&engine, handle, "SELECT count(*) FROM strings");
    let total: usize = counted.data["statements"][0]["rows"][0][0]["value"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        total > 4,
        "the fixture must need several pages, has {total} strings"
    );

    let csv = temp_file("strings.csv");
    let mut ticks = Vec::new();
    let report = api::export(
        &engine,
        export_request(
            handle,
            "SELECT string_idx, value FROM strings;",
            Format::Csv,
            &csv,
        ),
        |done, all| ticks.push((done, all)),
    )
    .unwrap();
    assert_eq!(report.rows as usize, total);
    assert!(report.complete);
    assert!(report.pages > 1);
    assert_eq!(ticks.first(), Some(&(0, total as u64)));
    assert_eq!(ticks.last(), Some(&(total as u64, total as u64)));
    let text = std::fs::read_to_string(&csv).unwrap();
    assert_eq!(text.lines().next().unwrap(), "string_idx,value");
    // every string index appears exactly once: paging dropped and doubled nothing
    let mut seen: Vec<u64> = text
        .lines()
        .skip(1)
        .filter_map(|l| l.split(',').next()?.parse().ok())
        .collect();
    assert_eq!(seen.len(), total);
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), total);

    let jsonl = temp_file("strings.jsonl");
    let report = api::export(
        &engine,
        export_request(
            handle,
            "SELECT string_idx, value FROM strings",
            Format::Jsonl,
            &jsonl,
        ),
        |_, _| {},
    )
    .unwrap();
    let lines: Vec<Value> = std::fs::read_to_string(&jsonl)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), total + 1);
    assert_eq!(lines[0]["mdd_export"], 1);
    assert_eq!(lines[0]["rows"], total);
    assert!(!report.snapshot_ids.is_empty());
    assert!(lines[1].is_array());
    engine.stop();
}

#[test]
fn an_export_that_cannot_finish_leaves_no_file_behind() {
    let engine = engine();
    let handle = open(&engine, SMALL);
    // a statement the wrapper cannot take
    let target = temp_file("never.csv");
    let _ = std::fs::remove_file(&target);
    let refused = api::export(
        &engine,
        export_request(handle, "SELECT 1; SELECT 2", Format::Csv, &target),
        |_, _| {},
    );
    assert_eq!(refused.unwrap_err().code, "INVALID_ARGUMENT");
    assert!(!target.exists());

    // a cancelled export: the first page is already written when the cancel arrives
    let big = temp_file("cancelled.csv");
    let _ = std::fs::remove_file(&big);
    let worker = {
        let engine = engine.clone();
        let big = big.clone();
        thread::spawn(move || {
            let mut request = export_request(
                handle,
                "SELECT a.string_idx AS a, b.string_idx AS b, c.string_idx AS c, d.string_idx AS d, e.string_idx AS e, f.string_idx AS f FROM strings a, strings b, strings c, strings d, strings e, strings f",
                Format::Csv,
                &big,
            );
            request.page_rows = Some(1);
            api::export(&engine, request, |_, _| {})
        })
    };
    let begun = Instant::now();
    while !partial_exists(&big) {
        assert!(
            begun.elapsed() < Duration::from_secs(30),
            "the export never wrote a page"
        );
        thread::sleep(Duration::from_millis(20));
    }
    assert!(engine.cancel(&call_id("export")));
    let outcome = worker.join().unwrap();
    assert_eq!(outcome.unwrap_err().code, "CANCELLED");
    assert!(!big.exists());
    assert!(!partial_exists(&big), "the half-written file is removed");
    engine.stop();
}

fn partial_exists(path: &Path) -> bool {
    let mut name = path.file_name().unwrap().to_os_string();
    name.push(".partial");
    path.with_file_name(name).exists()
}

#[test]
fn what_the_window_polls_does_not_wait_for_a_running_query() {
    let engine = engine();
    let handle = open(&engine, SMALL);
    let background = {
        let engine = engine.clone();
        thread::spawn(move || query(&engine, handle, HEAVY))
    };
    wait_until_busy(&engine);
    thread::sleep(Duration::from_millis(200)); // the engine is inside the statement now
    // polled from another thread, so that a poll that waits for the query fails the test instead of hanging it
    let (sender, receiver) = std::sync::mpsc::channel();
    {
        let engine = engine.clone();
        thread::spawn(move || {
            let asked = Instant::now();
            let state = api::engine_state(&engine);
            let tools = engine.tools();
            let cancel_flag = engine.cancel(&call_id("nothing-with-this-id"));
            let _ = sender.send((state, tools, cancel_flag, asked.elapsed()));
        });
    }
    let (state, tools, cancel_flag, took) = receiver
        .recv_timeout(Duration::from_secs(3))
        .unwrap_or_else(|_| panic!("polling the engine's state waited for the running query"));
    assert!(took < Duration::from_millis(500), "polling took {took:?}");
    assert_eq!(state["running"], true);
    assert_eq!(state["busy"]["call_id"], call_id("query"));
    assert_eq!(
        tools.len(),
        12,
        "the tools stay listed while the engine is busy: {tools:?}"
    );
    assert!(!cancel_flag);
    assert!(engine.cancel(&call_id("query")));
    assert_eq!(
        background.join().unwrap().data["error"]["code"],
        "CANCELLED"
    );
    engine.stop();
}

#[test]
fn stopping_or_reconfiguring_while_a_query_runs_ends_it_instead_of_waiting_for_it() {
    let engine = engine();
    let handle = open(&engine, SMALL);
    let background = {
        let engine = engine.clone();
        thread::spawn(move || query(&engine, handle, HEAVY))
    };
    wait_until_busy(&engine);
    thread::sleep(Duration::from_millis(200));
    let asked = Instant::now();
    let mut changed = engine.settings();
    changed.timeout_ms = 120_000;
    assert_eq!(api::configure(&engine, changed)["ok"], true);
    let took = asked.elapsed();
    assert!(took < Duration::from_secs(2), "configure waited {took:?}");
    assert_eq!(
        background.join().unwrap().data["error"]["code"],
        "CANCELLED"
    );
    assert!(!engine.running());
    assert!(engine.tools().is_empty());
    engine.stop();
}

#[test]
fn settings_are_checked_before_they_reach_the_engine() {
    let ok = Settings::default();
    assert!(ok.check().is_ok());
    let bad = |change: &dyn Fn(&mut Settings)| {
        let mut settings = Settings::default();
        change(&mut settings);
        settings.check().unwrap_err().code
    };
    assert_eq!(bad(&|s| s.timeout_ms = 0), "INVALID_ARGUMENT");
    assert_eq!(bad(&|s| s.sql_max_steps = Some(0)), "INVALID_ARGUMENT");
    assert_eq!(
        bad(&|s| s.sql_max_scanned_rows = Some(0)),
        "INVALID_ARGUMENT"
    );
    assert_eq!(
        bad(&|s| s.sql_max_result_rows = Some(0)),
        "INVALID_ARGUMENT"
    );
    assert_eq!(
        bad(&|s| s.dialect = "native-v1".to_owned()),
        "INVALID_ARGUMENT"
    );
    for good in [Some(1), Some(5_000_000), None] {
        let settings = Settings {
            sql_max_steps: good,
            sql_max_scanned_rows: good,
            sql_max_result_rows: good,
            ..Settings::default()
        };
        assert!(settings.check().is_ok(), "{good:?}");
    }
}

#[test]
fn a_folder_and_an_empty_list_are_not_inputs() {
    let engine = engine();
    let folder = api::open_inputs(
        &engine,
        &call_id("folder"),
        vec![private_folder("input-is-a-folder").display().to_string()],
    );
    assert_eq!(
        folder.data["error"]["code"], "INPUT_NOT_FOUND",
        "{}",
        folder.data
    );
    assert!(
        folder.data["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not a file")
    );
    let none = api::open_inputs(&engine, &call_id("none"), Vec::new());
    assert_eq!(none.data["error"]["code"], "INVALID_ARGUMENT");
    assert!(
        api::engine_state(&engine)["datasets"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    engine.stop();
}

#[test]
fn a_page_size_the_engine_would_refuse_is_brought_into_range() {
    let engine = engine();
    let handle = open(&engine, SMALL);
    for (page_rows, expect_pages) in [(Some(0), 6u64), (Some(5000), 1), (None, 1)] {
        let target = temp_file(&format!(
            "clamped-{}.csv",
            page_rows.map_or("default".to_owned(), |n| n.to_string())
        ));
        let mut request = export_request(
            handle,
            "SELECT string_idx FROM strings",
            Format::Csv,
            &target,
        );
        request.page_rows = page_rows;
        let report = api::export(&engine, request, |_, _| {})
            .unwrap_or_else(|f| panic!("{page_rows:?}: {f}"));
        assert_eq!(report.rows, 6, "{page_rows:?}");
        assert_eq!(report.pages, expect_pages, "{page_rows:?}");
    }
    engine.stop();
}

#[test]
fn an_export_cannot_be_aimed_at_a_folder_or_at_nothing() {
    let engine = engine();
    let handle = open(&engine, SMALL);
    // The folder is the test's own, with something in it: a variant of the code that accepted a folder
    // would replace it, and that must never be a folder the machine shares (the system temp dir).
    let folder = private_folder("export-target-folder");
    let at_folder = api::export(
        &engine,
        export_request(handle, "SELECT 1", Format::Csv, &folder),
        |_, _| {},
    );
    assert_eq!(at_folder.unwrap_err().code, "INVALID_ARGUMENT");
    assert!(folder.is_dir(), "the folder is still a folder");
    assert_eq!(
        std::fs::read(folder.join("keep.txt")).unwrap(),
        b"kept",
        "what was in the folder is untouched"
    );
    let nothing = api::export(
        &engine,
        export_request(handle, "SELECT 1", Format::Csv, Path::new("")),
        |_, _| {},
    );
    assert_eq!(nothing.unwrap_err().code, "INVALID_ARGUMENT");
    engine.stop();
}
