//! Stage-timing probe for the DEX-parallel fact pipeline.
//!
//! Emits the same `mdd.timing.v1` stage attribution as `tools/mdd-timing`, so a
//! serial run of this example is directly comparable with the pre-change
//! `mdd-timing` binary and with a parallel run of this same binary.
//!
//! Additional fields beyond `mdd.timing.v1`:
//!
//! * `mode` (`serial`/`parallel`) and `threads` (effective worker count),
//! * `fact_wall_ms` (capture/inventory excluded) per repeat,
//! * `consistency` (opt-in `--digest`) with one digest per DEX occurrence so a
//!   serial run and a parallel run can be compared byte-for-byte.
//!
//! This is a development instrument: it never claims product performance
//! qualification and never replaces a paired A0/A1/A2 trial.
use mdd_facts::pipeline::{FactsPipeline, PipelineConfig};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
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
        "usage: parallel_pipeline INPUT [--repeat N] [--threads N] [--serial] [--digest] \
         [--digest-limit N]",
    )
}

struct Options {
    path: PathBuf,
    repeat: usize,
    threads: Option<usize>,
    max_in_flight: Option<usize>,
    serial: bool,
    digest: bool,
    digest_limit: Option<usize>,
}

fn parse_arguments() -> MddResult<Options> {
    let mut arguments = std::env::args_os().skip(1);
    let path = arguments.next().map(PathBuf::from).ok_or_else(usage)?;
    let mut options = Options {
        path,
        repeat: 1,
        threads: None,
        max_in_flight: None,
        serial: false,
        digest: false,
        digest_limit: None,
    };
    while let Some(argument) = arguments.next() {
        let text = argument
            .to_str()
            .ok_or_else(|| usage().detail("reason", "argument is not valid UTF-8"))?;
        match text {
            "--repeat" => {
                options.repeat = positive(&mut arguments, "--repeat")?;
            }
            "--threads" => {
                options.threads = Some(positive(&mut arguments, "--threads")?);
            }
            "--max-in-flight" => {
                options.max_in_flight = Some(positive(&mut arguments, "--max-in-flight")?);
            }
            "--serial" => options.serial = true,
            "--digest" => options.digest = true,
            "--digest-limit" => {
                options.digest_limit = Some(positive(&mut arguments, "--digest-limit")?);
            }
            other => {
                return Err(usage().detail("reason", format!("unknown option {other}")));
            }
        }
    }
    Ok(options)
}

fn positive(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> MddResult<usize> {
    arguments
        .next()
        .and_then(|value| value.to_str().and_then(|text| text.parse::<usize>().ok()))
        .ok_or_else(|| usage().detail("reason", format!("{name} requires a positive integer")))
}

/// Digest a fact layer through its own JSON projection.
///
/// `ReferenceFacts` keeps a `BTreeMap<(TargetKind, u32), Vec<u32>>` lookup
/// index whose tuple keys are not JSON object keys, so it is projected field by
/// field from its public getters instead of being serialized whole.
///
/// `snapshot_id` is a per-process random opaque id that is embedded in every
/// fact identity, so it is replaced with a fixed token before hashing. Without
/// that substitution two runs of the same binary would never share a digest;
/// every other byte, including occurrence ids and content ids, is compared
/// verbatim.
struct Digester<'a> {
    snapshot_id: &'a str,
}

impl Digester<'_> {
    fn bytes<T: serde::Serialize>(&self, value: &T) -> MddResult<String> {
        let encoded = serde_json::to_vec(value).map_err(|error| {
            MddError::new(
                ErrorCode::InternalFault,
                "timing.digest",
                "fact layer is not serializable",
            )
            .detail("reason", error.to_string())
        })?;
        Ok(mdd_types::sha256(
            String::from_utf8_lossy(&encoded)
                .replace(self.snapshot_id, "<snapshot>")
                .as_bytes(),
        ))
    }

    fn references(&self, facts: &mdd_facts::references::ReferenceFacts) -> MddResult<String> {
        self.bytes(&json!({
            "sites": facts.sites(),
            "dynamic_calls": facts.dynamic_calls(),
            "coverage": facts.coverage(),
            "usage": facts.usage(),
            "call_site_metadata": facts.call_site_metadata(),
            "method_handle_metadata": facts.method_handle_metadata(),
        }))
    }
}

fn run_once(options: &Options, samples: &mut Vec<Sample>) -> MddResult<Value> {
    let kind = if options
        .path
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
            path: options.path.clone(),
            kind,
            expected_sha256: None,
        }],
        CaptureLimits::default(),
    )?;
    samples.push(Sample {
        stage: "capture",
        elapsed: started.elapsed(),
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
    let selected = inventory.selected_dexes().len();
    let decompressed: u64 = inventory
        .selected_dexes()
        .iter()
        .map(|dex| dex.blob.bytes().len() as u64)
        .sum();
    samples.push(Sample {
        stage: "inventory+selected_dex_read",
        elapsed: started.elapsed(),
        note: Some(format!(
            "{selected} selected DEX, {decompressed} decompressed bytes, {} members",
            inventory.manifest().members.len()
        )),
    });

    let pipeline = FactsPipeline::from_snapshot(snapshot, inventory, Default::default())?;
    let config = PipelineConfig {
        threads: if options.serial {
            Some(1)
        } else {
            options.threads
        },
        max_in_flight: options.max_in_flight,
    };

    // Stream one occurrence at a time so peak memory stays bounded by the
    // delivery window instead of the whole input. Digests are accumulated, facts
    // are dropped as soon as the visitor returns.
    let snapshot_id = pipeline.snapshot().manifest().snapshot_id.clone();
    let digester = Digester {
        snapshot_id: &snapshot_id,
    };
    let mut per_dex = Vec::with_capacity(pipeline.dex_count());
    let mut digests = Vec::new();
    let mut digest_all = String::new();
    let digest_limit = options.digest_limit.unwrap_or(usize::MAX);
    let started = Instant::now();
    let summary = pipeline.for_each(config, |index, facts, timing| {
        for (stage, elapsed) in [
            ("metadata", timing.metadata),
            ("definitions", timing.definitions),
            ("code", timing.code),
            ("annotations", timing.annotations),
            ("references", timing.references),
        ] {
            samples.push(Sample {
                stage,
                elapsed,
                note: None,
            });
        }
        per_dex.push(json!({
            "index": index,
            "occurrence": facts.occurrence,
            "code_ms": millis(timing.code),
            "references_ms": millis(timing.references),
            "build_ms": millis(timing.build),
        }));
        if options.digest && digests.len() < digest_limit {
            let layers = [
                digester.bytes(facts.metadata.as_ref())?,
                digester.bytes(facts.definitions.as_ref())?,
                digester.bytes(facts.code.as_ref())?,
                digester.references(facts.references.as_ref())?,
                digester.bytes(facts.annotations.as_ref())?,
            ];
            let joined = layers.concat();
            let combined = mdd_types::sha256(joined.as_bytes());
            digest_all.push_str(&combined);
            digests.push(json!({
                "occurrence": facts.occurrence,
                "metadata": layers[0],
                "definitions": layers[1],
                "code": layers[2],
                "references": layers[3],
                "annotations": layers[4],
                "combined": combined,
            }));
        }
        Ok(())
    })?;
    let fact_wall = started.elapsed();
    let threads = summary.threads;
    debug_assert_eq!(summary.dexes, pipeline.dex_count());

    let consistency = if options.digest {
        json!({
            "dex_count": pipeline.dex_count(),
            "digested": digests.len(),
            "combined_sha256": mdd_types::sha256(digest_all.as_bytes()),
            "per_dex": digests,
        })
    } else {
        Value::Null
    };

    Ok(json!({
        "threads": threads,
        "fact_wall_ms": millis(fact_wall),
        "dex": per_dex,
        "consistency": consistency,
    }))
}

fn report(options: &Options, threads: usize, samples: &[Sample], runs: &[Value]) -> Value {
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
    let serial_stage_total: f64 = stages
        .iter()
        .filter(|stage| stage["stage"] != "capture")
        .filter(|stage| stage["stage"] != "inventory+selected_dex_read")
        .filter_map(|stage| stage["total_ms"].as_f64())
        .sum();
    let total_ms: f64 = stages
        .iter()
        .filter_map(|stage| stage["total_ms"].as_f64())
        .sum();
    json!({
        "schema_version": "mdd.timing.v1",
        "input": options.path.display().to_string(),
        "repeat": options.repeat,
        "mode": if options.serial { "serial" } else { "parallel" },
        "threads": threads,
        "note": "development stage attribution only; not a performance qualification and not an A0/A1/A2 paired trial",
        "stages": stages,
        "sum_of_stages_ms": total_ms,
        "sum_of_per_occurrence_stage_ms": serial_stage_total,
        "per_run": runs,
    })
}

fn run() -> MddResult<Value> {
    let options = parse_arguments()?;
    let mut samples = Vec::new();
    let mut runs = Vec::new();
    for _ in 0..options.repeat {
        runs.push(run_once(&options, &mut samples)?);
    }
    let threads = runs
        .first()
        .and_then(|value| value["threads"].as_u64())
        .unwrap_or(0) as usize;
    Ok(report(&options, threads, &samples, &runs))
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

    fn options() -> Options {
        Options {
            path: PathBuf::from("input.apk"),
            repeat: 1,
            threads: None,
            max_in_flight: None,
            serial: true,
            digest: false,
            digest_limit: None,
        }
    }

    #[test]
    fn report_keeps_mdd_timing_v1_fields() {
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
        let report = report(&options(), 1, &samples, &[]);
        assert_eq!(report["schema_version"], "mdd.timing.v1");
        assert_eq!(report["mode"], "serial");
        assert_eq!(report["threads"], 1);
        let stages = report["stages"].as_array().unwrap();
        let metadata = stages
            .iter()
            .find(|stage| stage["stage"] == "metadata")
            .unwrap();
        assert_eq!(metadata["calls"], 2);
        assert_eq!(metadata["total_ms"], 80.0);
        assert_eq!(report["sum_of_stages_ms"], 90.0);
        // Capture is not a fact stage and must not inflate the occurrence sum.
        assert_eq!(report["sum_of_per_occurrence_stage_ms"], 80.0);
    }

    #[test]
    fn layer_digest_is_stable_and_distinguishes_values() {
        let digester = Digester {
            snapshot_id: "snapshot-deadbeef",
        };
        let first = digester.bytes(&json!({"a": 1, "b": [1, 2]})).unwrap();
        let second = digester.bytes(&json!({"a": 1, "b": [1, 2]})).unwrap();
        let changed = digester.bytes(&json!({"a": 2, "b": [1, 2]})).unwrap();
        assert_eq!(first, second);
        assert_ne!(first, changed);
        // A per-process snapshot id must not leak into the digest.
        let other = Digester {
            snapshot_id: "snapshot-cafebabe",
        };
        assert_eq!(
            digester
                .bytes(&json!({"source": "snapshot-deadbeef:source:0"}))
                .unwrap(),
            other
                .bytes(&json!({"source": "snapshot-cafebabe:source:0"}))
                .unwrap()
        );
    }
}
