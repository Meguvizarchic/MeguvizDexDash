//! MDD-035 combination counterexamples: paging, cancellation, TEMP definitions and
//! unbuilt layers, each pair exercised together rather than one axis at a time.
//!
//! Each axis already has its own tests (A0 replay for TEMP and paging, the
//! cancellation tests, the coverage ledger). What those cannot show is that one
//! failure mode does not turn into another: a cancelled page must not look like an
//! empty or finished one, a cancelled read must not disturb a TEMP definition, and
//! an unbuilt layer must not become an empty page just because the window starts
//! past the end. Expected values come from an unwindowed run of the same bridge or
//! from the recorded frozen-A0 corpus, never from the windowed path under test.
use super::tests::{open, read_json};
use crate::{
    SqlBridge,
    control::SqlControl,
    dialects::SqlDialect,
    temp::{TempSqlSession, TempStatementResult},
    window::SqlWindow,
};
use mdd_input::snapshot::InputKind;
use mdd_session::{Lifecycle, ResourceLimits};
use mdd_types::ErrorCode;
use std::{collections::BTreeSet, sync::Arc};

const WALK: &str =
    "SELECT string_pool_id,string_idx FROM strings ORDER BY string_pool_id,string_idx";
/// Inside the window bound (`offset + limit <= 100_000`) and far beyond the data.
const FAR_PAST_THE_DATA: u64 = 99_990;
const NEEDS_REFERENCES: &str =
    "SELECT file_id,method_idx,callee FROM method_calls ORDER BY file_id,method_idx,callee";

/// The same multi-DEX inputs the frozen A0 corpus is recorded against.
fn corpus_inputs() -> Vec<String> {
    read_json("conformance/corpus/hostlab/required-variants.json")["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| path.as_str().unwrap().to_owned())
        .collect()
}

fn corpus_harness() -> super::tests::Harness {
    let inputs = corpus_inputs();
    let pairs: Vec<(&str, InputKind)> = inputs
        .iter()
        .map(|path| (path.as_str(), InputKind::RawDex))
        .collect();
    open(&pairs)
}

fn cancelled(bridge: &SqlBridge) -> SqlControl {
    let control = SqlControl::new(bridge.limits(), None);
    control.cancel().unwrap();
    control
}

#[test]
fn a_cancelled_page_is_an_error_and_the_walk_resumes_with_identical_rows() {
    let bridge = corpus_harness().bridge(SqlDialect::DexSql011);
    let all = bridge.query(WALK).unwrap();
    let expected = all.rows().to_vec();
    assert!(expected.len() > 21, "the walk must span several pages");
    let prepared = bridge.prepare(WALK).unwrap();

    let limit = 7;
    let mut offset = 0;
    let mut walked = Vec::new();
    let mut cancelled_pages = 0;
    loop {
        let window = || SqlWindow::new(offset, limit).unwrap().counting_total();
        // The same page, cancelled before it starts: an error, never rows and never
        // a window report that says the walk is finished.
        let error = bridge
            .execute_window(&prepared, cancelled(&bridge), window())
            .expect_err("a cancelled page must not answer");
        assert_eq!(error.code, ErrorCode::Cancelled, "{error:?}");
        cancelled_pages += 1;
        // The retry of that very page is unaffected by the earlier cancellation.
        let page = bridge
            .execute_window(&prepared, SqlControl::new(bridge.limits(), None), window())
            .unwrap();
        assert!(page.calculation_complete());
        let report = page.window().unwrap();
        assert_eq!(report.total_rows, Some(expected.len() as u64));
        assert_eq!(report.offset, offset);
        walked.extend(page.rows().iter().cloned());
        match report.next_offset {
            Some(next) => {
                assert!(next > offset, "a walk must advance");
                offset = next;
            }
            None => break,
        }
    }
    assert_eq!(
        walked, expected,
        "pages after cancellations lost or repeated rows"
    );
    assert!(cancelled_pages >= 4);
}

#[test]
fn a_cancelled_read_of_a_temp_definition_changes_neither_the_catalog_nor_the_rows() {
    let harness = corpus_harness();
    let lifecycle = Arc::new(Lifecycle::new(ResourceLimits::default()).unwrap());
    let snapshot = lifecycle.register_snapshot(harness.snapshot()).unwrap();
    let handle = lifecycle
        .open_session(&snapshot, ResourceLimits::default())
        .unwrap();
    let session = TempSqlSession::new(
        Arc::clone(&lifecycle),
        handle,
        harness.bridge(SqlDialect::DexSql011),
    )
    .unwrap();
    session
        .execute(
            "CREATE TEMP VIEW pool_strings AS SELECT string_pool_id,string_idx FROM strings",
            None,
        )
        .unwrap();
    let read =
        "SELECT string_pool_id,string_idx FROM pool_strings ORDER BY string_pool_id,string_idx";
    let epoch = session.catalog_epoch().unwrap();

    let rows = |result: TempStatementResult| match result {
        TempStatementResult::Rows(result) => result,
        other => panic!("a query answered with a definition: {other:?}"),
    };
    let expected = rows(session.execute(read, None).unwrap()).rows().to_vec();
    assert!(expected.len() > 14);

    let query = session.prepare(read).unwrap();
    for offset in [0, 7, 10_000] {
        let error = session
            .bridge()
            .execute_window(
                query.prepared(),
                cancelled(session.bridge()),
                SqlWindow::new(offset, 7).unwrap(),
            )
            .expect_err("a cancelled read must not answer");
        assert_eq!(
            error.code,
            ErrorCode::Cancelled,
            "offset {offset}: {error:?}"
        );
        assert_eq!(
            session.catalog_epoch().unwrap(),
            epoch,
            "a cancelled read moved the TEMP catalog"
        );
    }

    // The definition is intact and pages exactly as an unwindowed read does.
    let mut walked = Vec::new();
    let mut offset = 0;
    loop {
        let page = rows(
            session
                .execute(
                    read,
                    Some(SqlWindow::new(offset, 7).unwrap().counting_total()),
                )
                .unwrap(),
        );
        walked.extend(page.rows().iter().cloned());
        match page.window().unwrap().next_offset {
            Some(next) => offset = next,
            None => break,
        }
    }
    assert_eq!(walked, expected);
    assert_eq!(session.catalog_epoch().unwrap(), epoch);
}

#[test]
fn an_unbuilt_layer_is_an_error_under_every_window_and_never_an_empty_page() {
    let harness = corpus_harness();
    let bridge = harness.bridge_with_layers(SqlDialect::DexSql011, false, false, false);

    let mut verdicts = BTreeSet::new();
    for window in [
        None,
        Some((0, 10)),
        Some((5, 10)),
        Some((FAR_PAST_THE_DATA, 10)),
    ] {
        let outcome = match window {
            None => bridge.query(NEEDS_REFERENCES),
            Some((offset, limit)) => bridge.query_window(
                NEEDS_REFERENCES,
                SqlWindow::new(offset, limit).unwrap().counting_total(),
            ),
        };
        let error = outcome.expect_err(&format!(
            "window {window:?}: an unbuilt references layer answered, so it read as zero rows"
        ));
        verdicts.insert((error.code.to_string(), error.stage.clone()));
    }
    assert_eq!(
        verdicts.len(),
        1,
        "the window changed the verdict for an unbuilt layer: {verdicts:?}"
    );

    // Control: a relation the built layers prove still answers under the same windows,
    // so the refusals above are about the layer and not about windows in general.
    let proven = bridge
        .query_window(WALK, SqlWindow::new(0, 10).unwrap().counting_total())
        .unwrap();
    assert!(!proven.rows().is_empty());
    let past_end = bridge
        .query_window(
            WALK,
            SqlWindow::new(FAR_PAST_THE_DATA, 10)
                .unwrap()
                .counting_total(),
        )
        .unwrap();
    assert!(past_end.rows().is_empty());
    assert!(past_end.window().unwrap().total_rows.is_some_and(|n| n > 0));
}
