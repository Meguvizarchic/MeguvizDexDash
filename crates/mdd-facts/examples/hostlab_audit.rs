//! HostLab structural-audit skeleton runner.
//!
//! Usage:
//! `cargo run --offline -p mdd-facts --example hostlab_audit -- app.apk CATALOG.json [EXPECTED_SHA256]`
//!
//! `CATALOG.json` is the operator supplied payload (shape in
//! `mdd_facts::hostlab::catalog`): it names classes of the analysed application,
//! so it is not stored in this repository.
//!
//! This is the migration instrument for MDD-051. It prints the `RuleRun`
//! alongside per-occurrence coverage so a reviewer can see which layers were
//! actually built. It never claims an admitted profile: `admitted` is `false`
//! and any pending rule is reported as `NOT_IMPLEMENTED`.
use mdd_facts::hostlab::{
    NativeLayers, NativeSession,
    catalog::{CATALOG_SCHEMA, HostlabCatalog},
};
use mdd_facts::session::FactsLimits;
use mdd_types::{ErrorCode, MddError, MddResult};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Instant,
};

fn usage() -> MddError {
    MddError::new(
        ErrorCode::InvalidArgument,
        "hostlab_audit",
        "usage: hostlab_audit INPUT.(apk|dex) CATALOG.json [EXPECTED_SHA256]",
    )
}

fn catalog_error(reason: &str) -> MddError {
    MddError::new(ErrorCode::InvalidArgument, "hostlab_audit", reason)
}

/// Read the catalog file; `HostlabCatalog::new` validates what was read.
fn load_catalog(path: &Path) -> MddResult<HostlabCatalog> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        catalog_error("catalog file cannot be read").detail("cause", error.to_string())
    })?;
    let document: serde_json::Value = serde_json::from_str(&text).map_err(|error| {
        catalog_error("catalog file is not valid JSON").detail("cause", error.to_string())
    })?;
    if document["schema_version"] != CATALOG_SCHEMA {
        return Err(catalog_error("catalog schema_version is not supported")
            .detail("expected", CATALOG_SCHEMA));
    }
    let text_field = |key: &str| -> MddResult<String> {
        document[key].as_str().map(str::to_owned).ok_or_else(|| {
            catalog_error("catalog field is missing or not text").detail("field", key)
        })
    };
    let mut lists = BTreeMap::new();
    for (key, value) in document["lists"]
        .as_object()
        .ok_or_else(|| catalog_error("catalog lists must be an object"))?
    {
        let values = value
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .map(|item| item.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or_else(|| {
                catalog_error("catalog list must be an array of text").detail("list", key.clone())
            })?;
        lists.insert(key.clone(), values);
    }
    let mut constants = BTreeMap::new();
    for (key, value) in document["constants"]
        .as_object()
        .ok_or_else(|| catalog_error("catalog constants must be an object"))?
    {
        let value = value.as_str().ok_or_else(|| {
            catalog_error("catalog constant must be text").detail("constant", key.clone())
        })?;
        constants.insert(key.clone(), value.to_owned());
    }
    HostlabCatalog::new(
        text_field("id")?,
        text_field("reference_commit")?,
        text_field("java_reference_sha256")?,
        lists,
        constants,
    )
}

fn run() -> MddResult<serde_json::Value> {
    let mut args = std::env::args_os().skip(1);
    let path = PathBuf::from(args.next().ok_or_else(usage)?);
    let catalog = load_catalog(Path::new(&args.next().ok_or_else(usage)?))?;
    let expected = args
        .next()
        .map(|value| {
            value.into_string().map_err(|_| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "hostlab_audit",
                    "expected SHA-256 must be ASCII",
                )
            })
        })
        .transpose()?;

    let started = Instant::now();
    let mut session = match &expected {
        Some(sha256) => NativeSession::open_verified(&path, sha256, FactsLimits::default())?,
        None => NativeSession::open_with(&path, FactsLimits::default())?,
    };
    let opened = started.elapsed();
    session.prepare(NativeLayers::STRUCTURAL)?;
    let prepared = started.elapsed();
    let class_count = session.class_count()?;
    let coverage = session.coverage();
    let hostlab_file_ids = session.hostlab_file_ids()?;
    let run = session.run_rules(&catalog)?;
    let finished = started.elapsed();

    Ok(serde_json::json!({
        "input": path.display().to_string(),
        "catalog": catalog.id,
        "admitted": run.admitted,
        "complete": run.complete,
        "class_count": class_count,
        "features": run.features,
        "discoveries": run.discoveries,
        "implemented": run.implemented,
        "pending": run.pending,
        "semantic_divergence_ids": run.semantic_divergences.iter().map(|item| item.id).collect::<Vec<_>>(),
        "coverage": coverage,
        "hostlab_file_id_by_dex_ordinal": hostlab_file_ids,
        "elapsed_ms": {
            "open": opened.as_secs_f64()*1000.0,
            "prepare": prepared.as_secs_f64()*1000.0,
            "rules": (finished - prepared).as_secs_f64()*1000.0,
            "total": finished.as_secs_f64()*1000.0,
        },
    }))
}

fn main() -> ExitCode {
    match run() {
        Ok(value) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&value).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&error).unwrap_or_default()
            );
            ExitCode::FAILURE
        }
    }
}
