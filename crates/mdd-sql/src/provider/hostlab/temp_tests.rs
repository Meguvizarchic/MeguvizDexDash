//! Session TEMP statements, windowed paging and cursor identity, replayed against
//! recorded frozen-A0 behaviour (`conformance/session/catalog-and-paging.json`)
//! and against the real session lifecycle.
//!
//! The A0 side of every comparison was recorded by
//! `conformance/session/generate_catalog_golden.py` from the reference backend;
//! nothing here derives an expected value from the engine under test.
use super::tests::{REFERENCE_A0_SHA256, open, read_json, strings_of};
use crate::{
    SqlBridge, SqlResult,
    dialects::SqlDialect,
    temp::{TempSqlSession, TempStatementResult},
    window::SqlWindow,
};
use mdd_input::snapshot::InputKind;
use mdd_session::{Lifecycle, ResourceLimits, SessionHandle};
use std::{collections::BTreeMap, sync::Arc};

const GOLDEN: &str = "conformance/session/catalog-and-paging.json";

/// Steps where the engine knowingly answers differently from A0, keyed
/// `scenario#step_index`, each with the reason. Anything else that differs fails.
const DECLARED_DIVERGENCES: &[(&str, &str)] = &[];

/// One engine under test: a lifecycle plus the sessions a scenario names.
struct Engine {
    lifecycle: Arc<Lifecycle>,
    sessions: BTreeMap<String, TempSqlSession>,
    handles: BTreeMap<String, SessionHandle>,
}

fn engine(inputs: &[&str], names: &[&str]) -> Engine {
    let pairs: Vec<(&str, InputKind)> = inputs.iter().map(|p| (*p, InputKind::RawDex)).collect();
    let harness = open(&pairs);
    let lifecycle = Arc::new(Lifecycle::new(ResourceLimits::default()).unwrap());
    // The session pins the snapshot the provider reads: the same capture.
    let snapshot = lifecycle.register_snapshot(harness.snapshot()).unwrap();
    let mut sessions = BTreeMap::new();
    let mut handles = BTreeMap::new();
    for name in names {
        let handle = lifecycle
            .open_session(&snapshot, ResourceLimits::default())
            .unwrap();
        // Every session reads the same immutable facts through its own bridge.
        let bridge: SqlBridge = harness.bridge(SqlDialect::DexSql011);
        sessions.insert(
            (*name).to_owned(),
            TempSqlSession::new(Arc::clone(&lifecycle), handle.clone(), bridge).unwrap(),
        );
        handles.insert((*name).to_owned(), handle);
    }
    Engine {
        lifecycle,
        sessions,
        handles,
    }
}

fn rows_record(result: &SqlResult) -> serde_json::Value {
    let window = result.window().expect("a windowed call reports its window");
    serde_json::json!({
        "kind": "query",
        "columns": result.columns(),
        "rows": result
            .rows()
            .iter()
            .map(|row| row.iter().map(super::tests::canonical_cell).collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        "offset": window.offset,
        "next_offset": window.next_offset,
        "truncated": window.truncated,
        "total_rows": window.total_rows,
    })
}

fn engine_record(result: &TempStatementResult) -> serde_json::Value {
    match result {
        TempStatementResult::Rows(result) => rows_record(result),
        TempStatementResult::Definition(report) => serde_json::json!({
            "kind": report.kind,
            "columns": Vec::<String>::new(),
            "rows": Vec::<Vec<String>>::new(),
            "offset": report.window.offset,
            "next_offset": report.window.next_offset,
            "truncated": report.window.truncated,
            "total_rows": report.window.total_rows,
        }),
    }
}

/// What the engine answered for one recorded step, in the golden's shape.
fn run_step(engine: &Engine, step: &serde_json::Value) -> serde_json::Value {
    let session = &engine.sessions[step["session"].as_str().unwrap()];
    let statements = strings_of(&step["statements"]);
    let outcome = SqlWindow::new(
        step["offset"].as_u64().unwrap(),
        step["limit"].as_u64().unwrap(),
    )
    .and_then(|window| session.execute_batch(&statements, Some(window.counting_total())));
    match outcome {
        Ok(results) => serde_json::json!({
            "statements": results.iter().map(engine_record).collect::<Vec<_>>()
        }),
        Err(error) => serde_json::json!({
            "error": {
                "statement_index": error
                    .details
                    .get("statement_index")
                    .and_then(|index| index.as_str())
                    .and_then(|index| index.parse::<u64>().ok()),
            }
        }),
    }
}

/// Compare an engine step to the A0 record: both fail at the same statement
/// index, or every statement record is equal.
fn step_difference(actual: &serde_json::Value, expected: &serde_json::Value) -> Option<String> {
    match (actual.get("error"), expected.get("error")) {
        (Some(a), Some(e)) => (a["statement_index"] != e["statement_index"]).then(|| {
            format!(
                "failed at statement {} but A0 failed at {}",
                a["statement_index"], e["statement_index"]
            )
        }),
        (Some(a), None) => Some(format!("engine refused ({a}) where A0 answered")),
        (None, Some(e)) => Some(format!("engine answered where A0 refused ({e})")),
        (None, None) => {
            let (a, e) = (
                actual["statements"].as_array().unwrap(),
                expected["statements"].as_array().unwrap(),
            );
            if a.len() != e.len() {
                return Some(format!("{} statement results != {}", a.len(), e.len()));
            }
            for (index, (a, e)) in a.iter().zip(e).enumerate() {
                for field in [
                    "kind",
                    "columns",
                    "offset",
                    "next_offset",
                    "truncated",
                    "total_rows",
                    "rows",
                ] {
                    if a[field] != e[field] {
                        return Some(format!(
                            "statement {index} {field}: {} != {}",
                            a[field], e[field]
                        ));
                    }
                }
            }
            None
        }
    }
}

#[test]
fn temp_scenarios_match_the_recorded_a0_behaviour() {
    let golden = read_json(GOLDEN);
    assert_eq!(golden["schema_version"], "mdd.catalog-and-paging.v1");
    assert_eq!(golden["a0_sha256"], REFERENCE_A0_SHA256);
    let inputs: Vec<&str> = strings_of(&golden["inputs"]);
    let scenarios = golden["scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 22, "scenario set shrank");
    let mut compared = 0usize;
    let mut divergent = Vec::new();
    for scenario in scenarios {
        let name = scenario["name"].as_str().unwrap();
        let steps = scenario["steps"].as_array().unwrap();
        let mut sessions: Vec<&str> = steps
            .iter()
            .map(|step| step["session"].as_str().unwrap())
            .collect();
        sessions.sort_unstable();
        sessions.dedup();
        let engine = engine(&inputs, &sessions);
        for (index, step) in steps.iter().enumerate() {
            let actual = run_step(&engine, step);
            if let Some(difference) = step_difference(&actual, &step["a0"]) {
                eprintln!("{name}#{index} {:?}: {difference}", step["statements"]);
                divergent.push(format!("{name}#{index}"));
            }
            compared += 1;
        }
    }
    assert!(compared >= 158, "only {compared} steps compared");
    let mut declared: Vec<String> = DECLARED_DIVERGENCES
        .iter()
        .map(|(key, _)| (*key).to_owned())
        .collect();
    declared.sort();
    divergent.sort();
    assert_eq!(
        divergent, declared,
        "steps whose engine answer differs from A0 changed: fix them or declare them with a reason"
    );
}

// ---------------------------------------------------------------------------
// Lifecycle integration: cursor identity, compatible-offset sequences and the
// TEMP binding, driven by real SQL results instead of hand-built claims.
// ---------------------------------------------------------------------------

use crate::values::SqlValue;
use mdd_session::{
    QueryBinding, QueryHandle,
    cursors::{CompatOffsetContract, CompatOffsetPage, CursorMode, PageClaim},
};

const BASE_INPUT: &str = "tests/fixtures/definitions/generated/definitions-035.dex";
const PAGE_BEFORE: &str = "CREATE TEMP TABLE page_base AS SELECT 1 AS id,'before' AS tag \
    UNION ALL SELECT 2,'before' UNION ALL SELECT 3,'before' UNION ALL SELECT 4,'before'";
const PAGE_AFTER: &str = "CREATE TEMP TABLE page_base AS SELECT 1 AS id,'after' AS tag \
    UNION ALL SELECT 2,'after' UNION ALL SELECT 3,'after' UNION ALL SELECT 4,'after'";
const PAGE_SHORTER: &str =
    "CREATE TEMP TABLE page_base AS SELECT 1 AS id,'x' AS tag UNION ALL SELECT 2,'x'";
const PAGE_SELECT: &str = "SELECT id,tag FROM page_base ORDER BY id";

fn define(session: &TempSqlSession, sql: &str) {
    session
        .execute(sql, None)
        .unwrap_or_else(|error| panic!("{sql}: {error:?}"));
}

fn cells(row: &[SqlValue]) -> Vec<String> {
    row.iter().map(super::tests::canonical_cell).collect()
}

fn lifecycle_query(
    engine: &Engine,
    name: &str,
    schema_id: &str,
    request_key: &str,
) -> (SessionHandle, QueryHandle) {
    let session = engine.handles[name].clone();
    let query = engine
        .lifecycle
        .prepare_query(
            &session,
            QueryBinding {
                request_key: request_key.to_owned(),
                schema_id: schema_id.to_owned(),
                semantic_version: "mdd.sql.v1".to_owned(),
            },
            ResourceLimits::default(),
        )
        .unwrap();
    (session, query)
}

fn window(offset: u64, limit: u64) -> SqlWindow {
    SqlWindow::new(offset, limit).unwrap().counting_total()
}

fn run_rows(session: &TempSqlSession, sql: &str, window: SqlWindow) -> SqlResult {
    match session.execute(sql, Some(window)).unwrap() {
        TempStatementResult::Rows(result) => *result,
        TempStatementResult::Definition(_) => panic!("{sql} is not a query"),
    }
}

/// The compatible-offset page the SQL layer reports for one re-execution.
fn compat_page(
    prepared: &crate::PreparedSql,
    first_ast: &str,
    result: &SqlResult,
    limit: u64,
    epoch: mdd_types::DecimalU64,
) -> CompatOffsetPage {
    let window = result.window().unwrap();
    let spec = prepared.cursor_spec().unwrap();
    CompatOffsetPage {
        offset: window.offset,
        limit,
        rows: result.rows().len() as u64,
        schema_id: result.schema_id(),
        total_rows: window.total_rows,
        source_fingerprint: spec.source_fingerprint,
        catalog_epoch: epoch,
        sql_matches: spec.ast_fingerprint == first_ast,
        lookahead_exhausted: !window.truncated,
    }
}

#[test]
fn a_compatible_offset_sequence_over_a_definition_completes_and_counts_its_reexecutions() {
    let engine = engine(&[BASE_INPUT], &["a"]);
    let session = &engine.sessions["a"];
    define(session, PAGE_BEFORE);
    let first = run_rows(session, PAGE_SELECT, window(0, 2));
    let (handle, query) = lifecycle_query(&engine, "a", &first.schema_id(), "page-walk");
    let prepared = session.prepare(PAGE_SELECT).unwrap();
    let spec = prepared.prepared().cursor_spec().unwrap();
    let mut state = engine
        .lifecycle
        .open_compat_offset(&handle, &query, &spec, CompatOffsetContract::default())
        .unwrap();
    let mut seen = Vec::new();
    while let Some(request) = state.next_request().unwrap() {
        let prepared = session.prepare(PAGE_SELECT).unwrap();
        let result = run_rows(session, PAGE_SELECT, window(request.offset.0, 2));
        let page = compat_page(
            prepared.prepared(),
            &spec.ast_fingerprint,
            &result,
            2,
            session.catalog_epoch().unwrap(),
        );
        let admission = state.admit(page).unwrap();
        seen.extend(result.rows().iter().map(|row| cells(row)));
        // The admission and the SQL layer's own window agree on the continuation.
        assert_eq!(
            admission.next_offset.map(|offset| offset.0),
            result.window().unwrap().next_offset
        );
        assert!(admission.metadata().unwrap().next_cursor.is_none());
    }
    assert_eq!(seen.len(), 4);
    assert!(state.is_done());
    assert_eq!(state.admitted_rows(), 4);
    assert_eq!(state.reexecutions(), 2, "one execution per page, no cursor");
}

#[test]
fn a_redefinition_between_pages_is_refused_instead_of_stitching_two_definitions() {
    // The reference engine answers page 2 from the new definition (recorded in
    // `paging_across_a_redefinition`): rows 1-2 say "before", rows 3-4 say
    // "after". The engine refuses that sequence: the page's source identity
    // carries the definitions it was expanded with.
    let engine = engine(&[BASE_INPUT], &["a"]);
    let session = &engine.sessions["a"];
    define(session, PAGE_BEFORE);
    let first = run_rows(session, PAGE_SELECT, window(0, 2));
    let (handle, query) = lifecycle_query(&engine, "a", &first.schema_id(), "page-redefine");
    let prepared = session.prepare(PAGE_SELECT).unwrap();
    let spec = prepared.prepared().cursor_spec().unwrap();
    let mut state = engine
        .lifecycle
        .open_compat_offset(&handle, &query, &spec, CompatOffsetContract::default())
        .unwrap();
    let epoch_before = session.catalog_epoch().unwrap();
    state
        .admit(compat_page(
            prepared.prepared(),
            &spec.ast_fingerprint,
            &first,
            2,
            epoch_before,
        ))
        .unwrap();

    define(session, PAGE_AFTER);
    assert_ne!(session.catalog_epoch().unwrap(), epoch_before);
    let again = session.prepare(PAGE_SELECT).unwrap();
    let second = run_rows(session, PAGE_SELECT, window(2, 2));
    // Same SQL, same schema, same row count: only the source differs.
    assert_eq!(second.schema_id(), first.schema_id());
    assert_eq!(second.window().unwrap().total_rows, Some(4));
    assert_eq!(
        again.prepared().cursor_spec().unwrap().ast_fingerprint,
        spec.ast_fingerprint
    );
    let error = state
        .admit(compat_page(
            again.prepared(),
            &spec.ast_fingerprint,
            &second,
            2,
            session.catalog_epoch().unwrap(),
        ))
        .unwrap_err();
    assert_eq!(error.details["page_error"], "source_changed");
    // Nothing of the refused page was admitted.
    assert_eq!(state.admitted_rows(), 2);
    assert!(!state.is_done());
}

#[test]
fn a_changed_row_count_under_the_same_statement_shape_is_refused_as_a_changed_total() {
    // Literals are bound as parameters, so `< 4` and `< 3` expand to the same
    // statement shape; only the page total and the definition hash differ.
    const FOUR: &str = "CREATE TEMP TABLE page_base AS SELECT string_idx AS id,'x' AS tag FROM strings WHERE string_idx < 4";
    const THREE: &str = "CREATE TEMP TABLE page_base AS SELECT string_idx AS id,'x' AS tag FROM strings WHERE string_idx < 3";
    let engine = engine(&[BASE_INPUT], &["a"]);
    let session = &engine.sessions["a"];
    define(session, FOUR);
    let first = run_rows(session, PAGE_SELECT, window(0, 2));
    assert_eq!(first.window().unwrap().total_rows, Some(4));
    let (handle, query) = lifecycle_query(&engine, "a", &first.schema_id(), "page-total");
    let prepared = session.prepare(PAGE_SELECT).unwrap();
    let spec = prepared.prepared().cursor_spec().unwrap();
    let mut state = engine
        .lifecycle
        .open_compat_offset(&handle, &query, &spec, CompatOffsetContract::default())
        .unwrap();
    let epoch = session.catalog_epoch().unwrap();
    state
        .admit(compat_page(
            prepared.prepared(),
            &spec.ast_fingerprint,
            &first,
            2,
            epoch,
        ))
        .unwrap();
    define(session, THREE);
    let again = session.prepare(PAGE_SELECT).unwrap();
    assert_eq!(
        again.prepared().cursor_spec().unwrap().ast_fingerprint,
        spec.ast_fingerprint,
        "same statement shape"
    );
    let second = run_rows(session, PAGE_SELECT, window(2, 2));
    assert_eq!(second.window().unwrap().total_rows, Some(3));
    let error = state
        .admit(compat_page(
            again.prepared(),
            &spec.ast_fingerprint,
            &second,
            2,
            session.catalog_epoch().unwrap(),
        ))
        .unwrap_err();
    assert_eq!(error.details["page_error"], "query_schema_or_total_changed");
    assert_eq!(state.admitted_rows(), 2);
}

#[test]
fn a_changed_definition_shape_between_pages_is_refused_as_a_different_statement() {
    let engine = engine(&[BASE_INPUT], &["a"]);
    let session = &engine.sessions["a"];
    define(session, PAGE_BEFORE);
    let first = run_rows(session, PAGE_SELECT, window(0, 2));
    let (handle, query) = lifecycle_query(&engine, "a", &first.schema_id(), "page-shape");
    let prepared = session.prepare(PAGE_SELECT).unwrap();
    let spec = prepared.prepared().cursor_spec().unwrap();
    let mut state = engine
        .lifecycle
        .open_compat_offset(&handle, &query, &spec, CompatOffsetContract::default())
        .unwrap();
    let epoch = session.catalog_epoch().unwrap();
    state
        .admit(compat_page(
            prepared.prepared(),
            &spec.ast_fingerprint,
            &first,
            2,
            epoch,
        ))
        .unwrap();
    define(session, PAGE_SHORTER);
    let again = session.prepare(PAGE_SELECT).unwrap();
    assert_ne!(
        again.prepared().cursor_spec().unwrap().ast_fingerprint,
        spec.ast_fingerprint,
        "the expanded statement now has fewer UNION branches"
    );
    let second = run_rows(session, PAGE_SELECT, window(2, 2));
    assert_eq!(
        second.rows().len(),
        0,
        "the shorter definition has no row 3"
    );
    let error = state
        .admit(compat_page(
            again.prepared(),
            &spec.ast_fingerprint,
            &second,
            2,
            session.catalog_epoch().unwrap(),
        ))
        .unwrap_err();
    assert_eq!(
        error.details["page_error"],
        "query_page_identity_or_limit_mismatch"
    );
}

#[test]
fn a_native_cursor_keeps_the_definition_it_was_prepared_with() {
    let engine = engine(&[BASE_INPUT], &["a"]);
    let session = &engine.sessions["a"];
    define(session, PAGE_BEFORE);
    let prepared = session.prepare(PAGE_SELECT).unwrap();
    assert_eq!(prepared.temp_names(), ["page_base"]);
    // One execution, retained: native paging never re-executes.
    let retained = run_rows(session, PAGE_SELECT, window(0, 1000));
    assert_eq!(retained.window().unwrap().total_rows, Some(4));
    let spec = prepared.prepared().cursor_spec().unwrap();
    let (handle, query) = lifecycle_query(&engine, "a", &retained.schema_id(), "native-walk");
    let binding = engine
        .lifecycle
        .bind_query_temp(&handle, &query, prepared.temp_names())
        .unwrap();
    assert_eq!(binding.catalog_epoch, prepared.catalog_epoch());
    assert_eq!(binding.relations.len(), 1);
    // The epoch is a decimal string on the wire, never a JSON number.
    assert_eq!(
        serde_json::to_value(prepared.catalog_epoch()).unwrap(),
        serde_json::Value::String(prepared.catalog_epoch().0.to_string())
    );
    engine.lifecycle.start_query(&handle, &query, 1).unwrap();
    let cursor = engine
        .lifecycle
        .open_cursor_with_spec(&handle, &query, spec.clone())
        .unwrap();
    let claim = PageClaim {
        schema_id: retained.schema_id(),
        total_rows: retained.window().unwrap().total_rows,
        source_fingerprint: spec.source_fingerprint.clone(),
    };
    let binding_before = engine
        .lifecycle
        .validate_page_continuation(&handle, &query, &cursor, &claim)
        .unwrap();
    assert_eq!(binding_before.mode, CursorMode::NativeSnapshot);
    assert_eq!(binding_before.ast_fingerprint, spec.ast_fingerprint);
    assert_eq!(binding_before.source_fingerprint, spec.source_fingerprint);

    // The catalog changes under the running query.
    define(session, PAGE_AFTER);
    assert!(session.catalog_epoch().unwrap().0 > binding.catalog_epoch.0);
    // The stored TEMP binding still resolves at the query's own generation,
    let verified = engine.lifecycle.verify_query_temp_binding(&query).unwrap();
    assert_eq!(verified, binding);
    // the cursor still validates against the identity it was opened with,
    let binding_after = engine
        .lifecycle
        .validate_page_continuation(&handle, &query, &cursor, &claim)
        .unwrap();
    assert_eq!(binding_after.catalog_epoch, binding_before.catalog_epoch);
    // and re-running the prepared statement still reads the old definition.
    let control = crate::control::SqlControl::new(session.bridge().limits(), None);
    let old = session
        .bridge()
        .execute(prepared.prepared(), control)
        .unwrap();
    assert_eq!(old.rows().len(), 4);
    assert!(
        old.rows()
            .iter()
            .all(|row| cells(row)[1] == "t:6265666f7265")
    );
    // A query prepared now reads the new definition and gets a different source
    // identity, so its page cannot continue the old cursor.
    let fresh = session.prepare(PAGE_SELECT).unwrap();
    let fresh_spec = fresh.prepared().cursor_spec().unwrap();
    assert_eq!(fresh_spec.ast_fingerprint, spec.ast_fingerprint);
    assert_ne!(fresh_spec.source_fingerprint, spec.source_fingerprint);
    let stitched = PageClaim {
        source_fingerprint: fresh_spec.source_fingerprint,
        ..claim
    };
    let error = engine
        .lifecycle
        .validate_page_continuation(&handle, &query, &cursor, &stitched)
        .unwrap_err();
    assert_eq!(error.details["page_error"], "source_changed");
}

#[test]
fn definitions_and_bindings_do_not_cross_sessions() {
    let engine = engine(&[BASE_INPUT], &["a", "b"]);
    let (a, b) = (&engine.sessions["a"], &engine.sessions["b"]);
    define(a, PAGE_BEFORE);
    assert!(b.prepare(PAGE_SELECT).is_err(), "b has no page_base");
    define(b, PAGE_AFTER);
    let in_a = a.prepare(PAGE_SELECT).unwrap();
    let in_b = b.prepare(PAGE_SELECT).unwrap();
    assert_ne!(
        in_a.prepared().cursor_spec().unwrap().source_fingerprint,
        in_b.prepared().cursor_spec().unwrap().source_fingerprint,
        "same text over different definitions is a different source"
    );
    // The lifecycle binding is per session as well: a name only `a` defined
    // cannot be bound for a query of session `b`.
    define(a, "CREATE TEMP TABLE only_a AS SELECT 1 AS x");
    let schema = run_rows(a, "SELECT x FROM only_a", window(0, 5)).schema_id();
    let (handle_b, query_b) = lifecycle_query(&engine, "b", &schema, "cross-session");
    let error = engine
        .lifecycle
        .bind_query_temp(&handle_b, &query_b, &["only_a".to_owned()])
        .unwrap_err();
    assert_eq!(error.details["temp_error"], "unknown_relation");
    // And a query handle of session a is not usable through session b's handle.
    let (_, query_a) = lifecycle_query(&engine, "a", &schema, "cross-session-a");
    assert!(
        engine
            .lifecycle
            .bind_query_temp(&handle_b, &query_a, &["only_a".to_owned()])
            .is_err()
    );
}

#[test]
fn volatile_definitions_and_unreadable_bodies_are_refused_without_a_catalog_change() {
    let engine = engine(&[BASE_INPUT], &["a"]);
    let session = &engine.sessions["a"];
    let epoch = session.catalog_epoch().unwrap();
    for sql in [
        "CREATE TEMP TABLE r AS SELECT random() AS r1",
        "CREATE TEMP TABLE r AS SELECT CURRENT_TIMESTAMP AS ts",
        "CREATE TEMP VIEW r AS SELECT now() AS ts",
        "CREATE TEMP TABLE r AS SELECT * FROM no_such_relation",
        "CREATE TEMP TABLE r AS SELECT nonsense FROM",
    ] {
        let error = session.execute(sql, None).unwrap_err();
        assert!(
            matches!(
                error.code,
                mdd_types::ErrorCode::UnsupportedQuery | mdd_types::ErrorCode::InvalidArgument
            ),
            "{sql}: {error:?}"
        );
        assert_eq!(
            session.catalog_epoch().unwrap(),
            epoch,
            "{sql} changed the catalog"
        );
    }
    let error = session
        .execute("CREATE TEMP TABLE r AS SELECT random() AS r1", None)
        .unwrap_err();
    assert_eq!(error.details["temp_error"], "volatile_definition");
    assert!(session.prepare("SELECT * FROM r").is_err());
}

#[test]
fn a_name_that_is_only_an_output_alias_is_not_a_dependency() {
    // `AS n` is an output alias, not a read of the definition `n`. Treating it
    // as one would report a dependency cycle for a legal redefinition.
    let engine = engine(&[BASE_INPUT], &["a"]);
    let session = &engine.sessions["a"];
    define(session, "CREATE TEMP TABLE n AS SELECT 1 AS id");
    define(session, "CREATE TEMP TABLE m AS SELECT 2 AS n");
    let m = engine
        .lifecycle
        .temp_catalog_resolve(&engine.handles["a"], "m")
        .unwrap()
        .unwrap();
    assert!(m.dependencies.is_empty(), "{:?}", m.dependencies);
    define(session, "CREATE TEMP TABLE n AS SELECT 5 AS n");
    let rows = run_rows(session, "SELECT n FROM n", window(0, 5));
    assert_eq!(cells(&rows.rows()[0]), ["i:5"]);
    // A real self-read is still a cycle.
    let error = session
        .execute("CREATE TEMP TABLE n AS SELECT id FROM n", None)
        .unwrap_err();
    assert_eq!(error.details["temp_error"], "cycle");
}

#[test]
fn a_bridge_over_another_snapshot_is_refused_at_construction() {
    // The session pins definitions-035; the bridge reads classic-035. Statements
    // would be answered from facts the session never admitted.
    let engine = engine(&[BASE_INPUT], &["a"]);
    let other = open(&[(
        "tests/fixtures/references/generated/classic-035.dex",
        InputKind::RawDex,
    )]);
    let error = TempSqlSession::new(
        Arc::clone(&engine.lifecycle),
        engine.handles["a"].clone(),
        other.bridge(SqlDialect::DexSql011),
    )
    .err()
    .expect("a bridge over a different snapshot must be refused");
    assert_eq!(error.code, mdd_types::ErrorCode::InvalidArgument);
    assert!(error.details.contains_key("session_snapshot_id"));
    assert_ne!(
        error.details["session_snapshot_id"],
        error.details["provider_snapshot_id"]
    );
}
