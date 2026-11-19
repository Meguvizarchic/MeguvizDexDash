//! Does the column store keep a relation's rows, and what does it cost? Development probe, not a product tool.
//!
//! `store_probe INPUT RELATION...` opens the input in the DexSQL 0.1.0 dialect, and for each relation reads every row
//! from the provider into a column store, then reads the provider a second time and compares it with the store row for
//! row. It prints rows, bytes per row, the size of the store and of the shared dictionary, and the time of each pass.
//! Exits 1 on the first difference.
use mdd_service::{Dataset, Dialect, InputRequest};
use mdd_session::ResourceLimits;
use mdd_sql::{
    column_store::{RelationStoreBuilder, TextDict},
    control::{SqlControl, SqlLimits},
    provider::SqlFactCursor,
};
use serde_json::json;
use std::{path::PathBuf, process::ExitCode, sync::Arc, time::Instant};

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let path = PathBuf::from(
        arguments
            .next()
            .expect("usage: store_probe INPUT RELATION..."),
    );
    let relations: Vec<String> = arguments
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let limits = SqlLimits {
        max_steps: u64::MAX,
        max_scanned_rows: u64::MAX,
        max_result_rows: u64::MAX,
        ..SqlLimits::default()
    };
    let dataset = Dataset::open(
        &[InputRequest { path, kind: None }],
        Dialect::DexSql010,
        ResourceLimits::default(),
        limits,
    )
    .expect("open");
    let provider = Arc::clone(dataset.bridge().expect("bridge").provider());
    let schema = provider.relations().expect("relations");
    let dict = TextDict::new();
    for name in &relations {
        let relation = schema.iter().find(|r| &r.name == name).expect("relation");
        let control = || SqlControl::new(limits, None);
        let started = Instant::now();
        let mut builder = RelationStoreBuilder::new(&relation.columns, Arc::clone(&dict));
        let mut cursor = Arc::clone(&provider)
            .open_cursor(name, control())
            .expect("cursor");
        let mut cells = 0u64;
        while let Some(row) = cursor.next_row().expect("row") {
            cells += row.len() as u64;
            builder.push(&row).expect("push");
        }
        let store = builder.finish();
        dict.shrink_to_fit();
        let build = started.elapsed();

        let started = Instant::now();
        let mut original = Arc::clone(&provider)
            .open_cursor(name, control())
            .expect("cursor");
        let mut stored = store.cursor(control());
        let mut compared = 0u64;
        loop {
            let (left, right) = (
                original.next_row().expect("row"),
                stored.next_row().expect("row"),
            );
            if left != right {
                println!(
                    "{}",
                    json!({"relation": name, "row": compared, "result": "DIFFERENT"})
                );
                return ExitCode::FAILURE;
            }
            if left.is_none() {
                break;
            }
            compared += 1;
        }
        let both = started.elapsed();

        let started = Instant::now();
        let mut again = store.cursor(control());
        while again.next_row().expect("row").is_some() {}
        let store_scan = started.elapsed();
        let started = Instant::now();
        let mut again = Arc::clone(&provider)
            .open_cursor(name, control())
            .expect("cursor");
        while again.next_row().expect("row").is_some() {}
        let provider_scan = started.elapsed();

        println!(
            "{}",
            json!({"relation": name, "rows": store.rows(), "columns": relation.columns.len(), "cells": cells,
                   "store_mib": (store.bytes_used() as f64 / 1048576.0 * 100.0).round() / 100.0,
                   "bytes_per_row": if store.rows() == 0 { 0.0 } else { (store.bytes_used() as f64 / store.rows() as f64 * 10.0).round() / 10.0 },
                   "dictionary_entries_so_far": dict.len(),
                   "dictionary_mib_so_far": (dict.bytes_used() as f64 / 1048576.0 * 100.0).round() / 100.0,
                   "compared_equal_rows": compared, "result": "equal",
                   "ms": {"build_from_provider": build.as_millis() as u64, "compare_pass": both.as_millis() as u64,
                          "scan_store": store_scan.as_millis() as u64, "scan_provider": provider_scan.as_millis() as u64}})
        );
    }
    let kinds = dict.kinds();
    println!(
        "{}",
        json!({"dictionary": {"entries": dict.len(), "heap_mib": (dict.bytes_used() as f64 / 1048576.0 * 10.0).round() / 10.0,
                              "kinds": {"utf8": kinds[0], "utf16_text": kinds[1], "bytes": kinds[2], "dex_mutf8": kinds[3],
                                        "member": kinds[4], "hex": kinds[5]},
                              "note": "kinds are (entries, arena bytes)"}})
    );
    ExitCode::SUCCESS
}
