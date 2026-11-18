//! The comparison against the real engine, on the three tiny DEX files of tests/fixtures/desktop.
use mdd_desktop::api;
use mdd_desktop::diff::{DiffRequest, DiffStore, PageQuery, SmaliDiffRequest, run_diff};
use mdd_desktop::engine::{Engine, Settings, locate_binary};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/desktop/generated")
        .join(name)
        .canonicalize()
        .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
        .display()
        .to_string()
        .trim_start_matches(r"\\?\")
        .to_owned()
}

fn engine() -> Arc<Engine> {
    let binary = locate_binary();
    assert!(
        binary.is_file(),
        "the engine binary is missing at {}: run `cargo build -p mdd-cli` in the repository root",
        binary.display()
    );
    Arc::new(Engine::new(
        binary,
        Settings {
            sql_max_steps: Some(500_000_000),
            sql_max_scanned_rows: Some(50_000_000),
            ..Settings::default()
        },
    ))
}

fn open(engine: &Engine, names: &[&str]) -> u64 {
    let reply = api::open_inputs(engine, "open", names.iter().map(|n| fixture(n)).collect());
    assert!(reply.ok, "{}", reply.data);
    reply.data["handle"].as_u64().unwrap()
}

fn run(engine: &Engine, store: &DiffStore, a: u64, b: u64, prefix: &str) -> Value {
    let reply = api::diff_run(
        engine,
        store,
        DiffRequest {
            call_id: "diff".into(),
            handle_a: a,
            handle_b: b,
            prefix: prefix.into(),
            deadline_ms: Some(60_000),
        },
        |_, _| {},
    );
    assert!(reply.ok, "{}", reply.data);
    reply.data
}

fn entries(store: &DiffStore, id: u64, kind: &str) -> Vec<Value> {
    let reply = api::diff_page(
        store,
        PageQuery {
            diff_id: id,
            kind: kind.into(),
            status: String::new(),
            contains: String::new(),
            offset: 0,
            limit: Some(100),
        },
    );
    assert!(reply.ok, "{}", reply.data);
    reply.data["entries"].as_array().unwrap().clone()
}

fn status(entries: &[Value], key: &str) -> String {
    entries
        .iter()
        .find(|e| e["key"] == key)
        .unwrap_or_else(|| panic!("no entry {key} in {entries:?}"))["status"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn a_against_b_names_every_difference_and_does_not_claim_equal_operands() {
    let engine = engine();
    let store = DiffStore::default();
    let a = open(&engine, &["a.dex"]);
    let b = open(&engine, &["b.dex", "c.dex"]);
    let result = run(&engine, &store, a, b, "");
    let id = result["diff_id"].as_u64().unwrap();
    assert_eq!(result["summary"]["complete"], true);
    assert_eq!(result["summary"]["rows"]["a"]["methods"], 4);
    assert_eq!(result["summary"]["rows"]["b"]["methods"], 5);

    let classes = entries(&store, id, "class");
    assert_eq!(status(&classes, "Ldemo/A;"), "facts_equal");
    assert_eq!(status(&classes, "Ldemo/C;"), "only_b");

    let methods = entries(&store, id, "method");
    assert_eq!(status(&methods, "Ldemo/A;->same()V"), "opcodes_equal");
    assert_eq!(
        status(&methods, "Ldemo/A;->ops()V"),
        "opcodes_equal",
        "equal opcodes, different operand: the list cannot tell"
    );
    assert_eq!(status(&methods, "Ldemo/A;->body()V"), "opcodes_differ");
    assert_eq!(status(&methods, "Ldemo/A;->gone()V"), "only_a");
    assert_eq!(status(&methods, "Ldemo/A;->added()V"), "only_b");
    assert_eq!(status(&methods, "Ldemo/C;->only()V"), "only_b");
    let ops = methods
        .iter()
        .find(|e| e["key"] == "Ldemo/A;->ops()V")
        .unwrap();
    assert!(ops["notes"][0].as_str().unwrap().contains("操作数"));
    // the occurrences carry the DEX member each came from
    assert_eq!(ops["a"][0]["entry"], "a.dex");
    assert_eq!(
        result["summary"]["differences"], 5,
        "one class and four methods"
    );

    // the smali comparison is where equal operands are proven or refuted
    let pair = |name: &str| -> (u64, u64) {
        let m = methods
            .iter()
            .find(|e| e["key"] == format!("Ldemo/A;->{name}()V"))
            .unwrap();
        (
            m["a"][0]["index"].as_u64().unwrap(),
            m["b"][0]["index"].as_u64().unwrap(),
        )
    };
    let smali = |name: &str| {
        let (ia, ib) = pair(name);
        let reply = api::diff_smali(
            &engine,
            SmaliDiffRequest {
                call_id: "smali".into(),
                handle_a: a,
                file_id_a: 0,
                method_idx_a: ia,
                handle_b: b,
                file_id_b: 0,
                method_idx_b: ib,
                deadline_ms: Some(60_000),
            },
        );
        assert!(reply.ok, "{}", reply.data);
        reply.data
    };
    let same = smali("same");
    assert_eq!(same["identical"], true);
    assert_eq!(same["added"], 0);
    let different = smali("ops");
    assert_eq!(different["identical"], false);
    assert_eq!(different["added"], 1);
    assert_eq!(different["removed"], 1);
    let text: Vec<String> = different["lines"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["op"] != "=")
        .map(|l| {
            format!(
                "{}{}",
                l["op"].as_str().unwrap(),
                l["text"].as_str().unwrap().trim()
            )
        })
        .collect();
    assert!(
        text.iter()
            .any(|l| l.starts_with('-') && l.contains("alpha")),
        "{text:?}"
    );
    assert!(
        text.iter()
            .any(|l| l.starts_with('+') && l.contains("beta")),
        "{text:?}"
    );
    engine.stop();
}

#[test]
fn the_same_input_twice_has_no_differences_and_says_it_looked_at_every_row() {
    let engine = engine();
    let store = DiffStore::default();
    let a = open(&engine, &["a.dex"]);
    let again = open(&engine, &["a.dex"]);
    let result = run(&engine, &store, a, again, "");
    assert_eq!(result["summary"]["differences"], 0);
    assert_eq!(result["summary"]["complete"], true);
    assert_eq!(
        result["summary"]["rows"]["a"],
        result["summary"]["rows"]["b"]
    );
    assert!(
        result["summary"]["rows"]["a"]["methods"].as_u64().unwrap() > 0,
        "an empty side must not read as agreement"
    );
    // the content ids of the two sides are the same bytes
    assert_eq!(
        result["sides"][0]["content_ids"],
        result["sides"][1]["content_ids"]
    );
    assert_ne!(
        result["sides"][0]["snapshot_ids"],
        result["sides"][1]["snapshot_ids"]
    );
    engine.stop();
}

#[test]
fn a_definition_that_occurs_twice_is_kept_as_two_and_the_counts_are_the_difference() {
    let engine = engine();
    let store = DiffStore::default();
    let once = open(&engine, &["a.dex"]);
    let twice = open(&engine, &["a.dex", "a.dex"]);
    let result = run(&engine, &store, once, twice, "");
    let id = result["diff_id"].as_u64().unwrap();
    assert_eq!(result["summary"]["rows"]["b"]["methods"], 8);
    let classes = entries(&store, id, "class");
    assert_eq!(status(&classes, "Ldemo/A;"), "count_differs");
    let methods = entries(&store, id, "method");
    assert!(
        methods.iter().all(|m| m["status"] == "count_differs"),
        "{methods:?}"
    );
    let a_class = classes.iter().find(|e| e["key"] == "Ldemo/A;").unwrap();
    assert_eq!(a_class["a"].as_array().unwrap().len(), 1);
    assert_eq!(a_class["b"].as_array().unwrap().len(), 2);
    engine.stop();
}

#[test]
fn a_prefix_narrows_both_sides_and_an_empty_scope_is_not_agreement_by_accident() {
    let engine = engine();
    let store = DiffStore::default();
    let a = open(&engine, &["a.dex"]);
    let b = open(&engine, &["b.dex", "c.dex"]);
    let result = run(&engine, &store, a, b, "Ldemo/C");
    let id = result["diff_id"].as_u64().unwrap();
    assert_eq!(result["summary"]["rows"]["a"]["classes"], 0);
    assert_eq!(result["summary"]["rows"]["b"]["classes"], 1);
    let classes = entries(&store, id, "class");
    assert_eq!(classes.len(), 1);
    assert_eq!(status(&classes, "Ldemo/C;"), "only_b");
    // a prefix that matches nothing on either side loads nothing and the report says so
    let none = run(&engine, &store, a, b, "Lnothing/");
    assert_eq!(
        none["summary"]["rows"]["a"],
        json!({"classes": 0, "methods": 0})
    );
    assert_eq!(none["summary"]["entries"], 0);
    engine.stop();
}

#[test]
fn comparing_an_input_set_with_itself_or_with_a_closed_one_is_refused() {
    let engine = engine();
    let store = DiffStore::default();
    let a = open(&engine, &["a.dex"]);
    let request = |a, b| DiffRequest {
        call_id: "diff".into(),
        handle_a: a,
        handle_b: b,
        prefix: String::new(),
        deadline_ms: None,
    };
    let same = api::diff_run(&engine, &store, request(a, a), |_, _| {});
    assert_eq!(same.data["error"]["code"], "INVALID_ARGUMENT");
    let gone = api::diff_run(&engine, &store, request(a, 999), |_, _| {});
    assert_eq!(gone.data["error"]["code"], "UNKNOWN_HANDLE");
    engine.stop();
}

#[test]
fn a_cancelled_comparison_stops_and_stores_nothing() {
    let engine = engine();
    let store = DiffStore::default();
    let a = open(&engine, &["a.dex"]);
    let b = open(&engine, &["b.dex"]);
    let lease = engine.lease("cancel-me", "compare", None).unwrap();
    assert!(engine.cancel("cancel-me"));
    let request = DiffRequest {
        call_id: "cancel-me".into(),
        handle_a: a,
        handle_b: b,
        prefix: String::new(),
        deadline_ms: None,
    };
    let outcome = run_diff(&engine, &lease, &request, |_, _| {});
    assert_eq!(outcome.unwrap_err().code, "CANCELLED");
    drop(lease);
    assert!(
        api::diff_page(
            &store,
            PageQuery {
                diff_id: 1,
                kind: String::new(),
                status: String::new(),
                contains: String::new(),
                offset: 0,
                limit: None
            }
        )
        .data["error"]["code"]
            == "UNKNOWN_DIFF"
    );
    engine.stop();
}
