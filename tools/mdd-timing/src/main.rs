//! Stage-timing probe for the MeguvizDexDash fact pipeline.
//!
//! Reports wall-clock milliseconds for capture, inventory, and each per-DEX fact
//! layer so optimisation work is attributed to a measured stage instead of a guess.
//! This is a development instrument: it never claims product performance
//! qualification and it never replaces a paired A0/A1/A2 trial.
use mdd_dex::{
    annotations::AnnotationLimits, definitions::DefinitionLimits, instructions::CodeLimits,
    strings::StringLimits,
};
use mdd_facts::{
    MetadataFacts,
    annotations::AnnotationFacts,
    code::CodeFacts,
    definitions::DefinitionFacts,
    references::{ReferenceFacts, ReferenceLimits},
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
};

/// One measured stage. `index` is the logical DEX occurrence within the source.
struct Sample {
    stage: &'static str,
    elapsed: Duration,
    note: Option<String>,
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn usage() -> MddError {
    MddError::new(
        ErrorCode::InvalidArgument,
        "timing",
        "usage: mdd-timing INPUT [--repeat N] [--skip facts|code|references]",
    )
}

fn parse_arguments() -> MddResult<(PathBuf, usize, Vec<String>)> {
    let mut arguments = std::env::args_os().skip(1);
    let path = arguments.next().map(PathBuf::from).ok_or_else(usage)?;
    let mut repeat = 1usize;
    let mut skip = Vec::new();
    while let Some(argument) = arguments.next() {
        let text = argument
            .to_str()
            .ok_or_else(|| usage().detail("reason", "argument is not valid UTF-8"))?;
        match text {
            "--repeat" => {
                let value = arguments.next().ok_or_else(usage)?;
                repeat = value
                    .to_str()
                    .and_then(|value| value.parse::<usize>().ok())
                    .filter(|value| *value > 0)
                    .ok_or_else(|| {
                        usage().detail("reason", "--repeat requires a positive integer")
                    })?;
            }
            "--skip" => {
                let value = arguments.next().ok_or_else(usage)?;
                let text = value.to_str().ok_or_else(usage)?;
                skip.push(text.to_owned());
            }
            other => {
                return Err(usage().detail("reason", format!("unknown option {other}")));
            }
        }
    }
    Ok((path, repeat, skip))
}

fn run_once(path: &Path, skip: &[String], samples: &mut Vec<Sample>) -> MddResult<Value> {
    let skipped = |name: &str| skip.iter().any(|value| value == name);
    let kind = if path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("dex"))
    {
        InputKind::RawDex
    } else {
        InputKind::Apk
    };

    let started = Instant::now();
    let snapshot = Snapshot::capture(
        &[InputSpec {
            path: path.to_path_buf(),
            kind,
            expected_sha256: None,
        }],
        CaptureLimits::default(),
    )?;
    let capture = started.elapsed();
    samples.push(Sample {
        stage: "capture",
        elapsed: capture,
        note: Some(format!(
            "{} source(s), {} captured bytes",
            snapshot.sources().len(),
            snapshot.manifest().captured_input_bytes.0
        )),
    });

    let started = Instant::now();
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )?;
    let inventory_elapsed = started.elapsed();
    let selected = inventory.selected_dexes().len();
    let decompressed: u64 = inventory
        .selected_dexes()
        .iter()
        .map(|dex| dex.blob.bytes().len() as u64)
        .sum();
    samples.push(Sample {
        stage: "inventory+selected_dex_read",
        elapsed: inventory_elapsed,
        note: Some(format!(
            "{selected} selected DEX, {decompressed} decompressed bytes, {} members",
            inventory.manifest().members.len()
        )),
    });

    let mut per_dex = Vec::new();
    for index in 0..selected {
        let occurrence = inventory.selected_dexes()[index].dex_occurrence_id.clone();

        let started = Instant::now();
        let metadata = MetadataFacts::build(&snapshot, &inventory, index, StringLimits::default())?;
        samples.push(Sample {
            stage: "metadata",
            elapsed: started.elapsed(),
            note: None,
        });

        let started = Instant::now();
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default())?;
        samples.push(Sample {
            stage: "definitions",
            elapsed: started.elapsed(),
            note: None,
        });

        if skipped("code") {
            per_dex.push(json!({"occurrence": occurrence, "code": "skipped"}));
            continue;
        }

        let started = Instant::now();
        let code =
            CodeFacts::build_all_code_items(&snapshot, &inventory, index, CodeLimits::default())?;
        let code_elapsed = started.elapsed();
        samples.push(Sample {
            stage: "code",
            elapsed: code_elapsed,
            note: None,
        });

        if skipped("references") {
            per_dex.push(json!({"occurrence": occurrence, "references": "skipped"}));
            continue;
        }

        let started = Instant::now();
        let references = ReferenceFacts::build(definitions, code, ReferenceLimits::default())?;
        let reference_elapsed = started.elapsed();
        samples.push(Sample {
            stage: "references",
            elapsed: reference_elapsed,
            note: None,
        });

        if skipped("annotations") {
            per_dex.push(json!({"occurrence": occurrence, "annotations": "skipped"}));
            continue;
        }

        // AnnotationFacts consumes the definition facts, so re-derive them from
        // the already validated metadata rather than rebuilding the world.
        let started = Instant::now();
        let _ = AnnotationFacts::build(
            references.definitions().clone(),
            AnnotationLimits::default(),
        )?;
        samples.push(Sample {
            stage: "annotations",
            elapsed: started.elapsed(),
            note: None,
        });

        per_dex.push(json!({
            "occurrence": occurrence,
            "code_ms": millis(code_elapsed),
            "references_ms": millis(reference_elapsed),
        }));
    }

    Ok(json!({ "dex": per_dex }))
}

fn report(path: &Path, repeat: usize, samples: &[Sample], runs: &[Value]) -> Value {
    let mut stages: Vec<Value> = Vec::new();
    let mut names: Vec<&'static str> = samples.iter().map(|sample| sample.stage).collect();
    names.sort_unstable();
    names.dedup();
    for name in names {
        let values: Vec<f64> = samples
            .iter()
            .filter(|sample| sample.stage == name)
            .map(|sample| millis(sample.elapsed))
            .collect();
        if values.is_empty() {
            continue;
        }
        let total: f64 = values.iter().sum();
        let max = values.iter().copied().fold(f64::MIN, f64::max);
        let min = values.iter().copied().fold(f64::MAX, f64::min);
        stages.push(json!({
            "stage": name,
            "calls": values.len(),
            "total_ms": total,
            "mean_ms": total / values.len() as f64,
            "min_ms": min,
            "max_ms": max,
            "note": samples.iter().find(|s| s.stage == name).and_then(|s| s.note.clone()),
            "per_call_ms": values.iter().map(|value| (value * 1000.0).round() / 1000.0).collect::<Vec<_>>(),
        }));
    }
    let total_ms: f64 = stages
        .iter()
        .filter_map(|stage| stage["total_ms"].as_f64())
        .sum();
    json!({
        "schema_version": "mdd.timing.v1",
        "input": path.display().to_string(),
        "repeat": repeat,
        "note": "development stage attribution only; not a performance qualification and not an A0/A1/A2 paired trial",
        "stages": stages,
        "sum_of_stages_ms": total_ms,
        "per_run": runs,
    })
}

fn run() -> MddResult<Value> {
    let (path, repeat, skip) = parse_arguments()?;
    let mut samples = Vec::new();
    let mut runs = Vec::new();
    for _ in 0..repeat {
        runs.push(run_once(&path, &skip, &mut samples)?);
    }
    Ok(report(&path, repeat, &samples, &runs))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_aggregates_each_stage_once() {
        let samples = vec![
            Sample {
                stage: "capture",
                elapsed: Duration::from_millis(10),
                note: None,
            },
            Sample {
                stage: "metadata",
                elapsed: Duration::from_millis(30),
                note: None,
            },
            Sample {
                stage: "metadata",
                elapsed: Duration::from_millis(50),
                note: None,
            },
        ];
        let report = report(&PathBuf::from("input.apk"), 1, &samples, &[]);
        let stages = report["stages"].as_array().unwrap();
        let metadata = stages
            .iter()
            .find(|stage| stage["stage"] == "metadata")
            .unwrap();
        assert_eq!(metadata["calls"], 2);
        assert_eq!(metadata["mean_ms"], 40.0);
        assert_eq!(metadata["total_ms"], 80.0);
    }
}
