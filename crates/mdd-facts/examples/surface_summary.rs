//! Emit the HostLab `native_surface` record set for one APK or raw DEX.
//!
//! ```text
//! surface_summary INPUT [--families FILE.json] [--timing]
//! ```
//!
//! `--families FILE.json` installs the reference `surface_workers.FAMILIES`
//! prefixes read from `FILE.json` together with the exact classifier, so the
//! output can be diffed field by field against a retained HostLab evidence file.
//! Without it nothing is classified, which is the generic-core behaviour. The
//! prefixes name packages of the analysed application, so they are not stored in
//! this repository; the file shape is:
//!
//! ```json
//! { "schema_version": "mdd.surface-families.v1",
//!   "families": [["<key>", ["<descriptor prefix>"]]],
//!   "extra_filter_prefixes": ["..."],
//!   "comment_ui_prefix": "...", "comment_compose_prefix": "...",
//!   "dynamic_other_prefix": "...", "legacy_dynamic_prefix": "..." }
//! ```
use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
use mdd_facts::{
    MetadataFacts,
    definitions::DefinitionFacts,
    surface::{
        FamilyClassifier, SurfaceLimits, SurfaceReport, build_report, dex_file_order,
        resource_fingerprints, scan_dex,
    },
};
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use std::{
    path::PathBuf,
    process::ExitCode,
    time::{Duration, Instant},
};

/// Reference family table, read from the operator supplied file.
struct ReferenceTable {
    families: Vec<(String, Vec<String>)>,
    extra_filter_prefixes: Vec<String>,
    comment_ui_prefix: String,
    comment_compose_prefix: String,
    dynamic_other_prefix: String,
    legacy_dynamic_prefix: String,
}

fn table_error(reason: &str) -> MddError {
    MddError::new(ErrorCode::InvalidArgument, "example", reason)
}

impl ReferenceTable {
    fn load(path: &std::path::Path) -> MddResult<Self> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            table_error("families file cannot be read").detail("cause", error.to_string())
        })?;
        let document: serde_json::Value = serde_json::from_str(&text).map_err(|error| {
            table_error("families file is not valid JSON").detail("cause", error.to_string())
        })?;
        if document["schema_version"] != "mdd.surface-families.v1" {
            return Err(table_error("families file schema_version is not supported"));
        }
        let text_array = |value: &serde_json::Value, what: &str| -> MddResult<Vec<String>> {
            value
                .as_array()
                .and_then(|items| {
                    items
                        .iter()
                        .map(|item| item.as_str().map(str::to_owned))
                        .collect::<Option<Vec<_>>>()
                })
                .ok_or_else(|| {
                    table_error("families file field must be an array of text")
                        .detail("field", what)
                })
        };
        let text_field = |key: &str| -> MddResult<String> {
            document[key]
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| table_error("families file field is missing").detail("field", key))
        };
        let mut families = Vec::new();
        for entry in document["families"]
            .as_array()
            .ok_or_else(|| table_error("families must be an array"))?
        {
            let key = entry[0]
                .as_str()
                .ok_or_else(|| table_error("family key must be text"))?;
            families.push((key.to_owned(), text_array(&entry[1], key)?));
        }
        Ok(Self {
            families,
            extra_filter_prefixes: text_array(
                &document["extra_filter_prefixes"],
                "extra_filter_prefixes",
            )?,
            comment_ui_prefix: text_field("comment_ui_prefix")?,
            comment_compose_prefix: text_field("comment_compose_prefix")?,
            dynamic_other_prefix: text_field("dynamic_other_prefix")?,
            legacy_dynamic_prefix: text_field("legacy_dynamic_prefix")?,
        })
    }
}

/// `surface_workers.family`, case-sensitive, in declaration order.
struct ReferenceFamilies(ReferenceTable);

impl FamilyClassifier for ReferenceFamilies {
    fn family(&self, class_descriptor: &str) -> Option<String> {
        let table = &self.0;
        for (key, prefixes) in &table.families {
            if prefixes
                .iter()
                .any(|prefix| class_descriptor.starts_with(prefix.as_str()))
            {
                return Some(key.clone());
            }
        }
        if class_descriptor.starts_with(table.comment_ui_prefix.as_str()) {
            let parts: Vec<&str> = class_descriptor.split('/').collect();
            return Some(format!(
                "comment_other_ui:{}",
                if parts.len() > 6 { parts[5] } else { "(root)" }
            ));
        }
        if class_descriptor.starts_with(table.comment_compose_prefix.as_str()) {
            return Some("comment_other_compose".to_owned());
        }
        if class_descriptor.starts_with(table.dynamic_other_prefix.as_str()) {
            let parts: Vec<&str> = class_descriptor.split('/').collect();
            return Some(format!(
                "dynamic_other:{}",
                if parts.len() > 4 { parts[3] } else { "(root)" }
            ));
        }
        let lowered = class_descriptor.to_ascii_lowercase();
        if class_descriptor.starts_with(table.legacy_dynamic_prefix.as_str())
            && ["dynamic", "following", "feed"]
                .iter()
                .any(|needle| lowered.contains(needle))
        {
            return Some("dynamic_other_legacy".to_owned());
        }
        None
    }

    fn known_families(&self) -> Vec<String> {
        // `summarize` seeds one row per static family key. The `*_other*` keys are
        // input-dependent and only appear when a class matches them.
        self.0.families.iter().map(|(key, _)| key.clone()).collect()
    }
}

struct EmptyFamilies;

impl FamilyClassifier for EmptyFamilies {
    fn family(&self, _class_descriptor: &str) -> Option<String> {
        None
    }
}

fn usage() -> MddError {
    MddError::new(
        ErrorCode::InvalidArgument,
        "example",
        "usage: surface_summary INPUT [--families FILE.json] [--timing]",
    )
}

struct Options {
    path: PathBuf,
    families: Option<PathBuf>,
}

fn parse_arguments() -> MddResult<Options> {
    let mut arguments = std::env::args_os().skip(1);
    let path = PathBuf::from(arguments.next().ok_or_else(usage)?);
    let mut families = None;
    while let Some(argument) = arguments.next() {
        let text = argument.to_str().ok_or_else(usage)?;
        match text {
            "--families" => {
                families = Some(PathBuf::from(arguments.next().ok_or_else(usage)?));
            }
            // `main` inspects argv for this switch, so it is accepted here and
            // ignored: the option list stays in one place.
            "--timing" => (),
            other => return Err(usage().detail("reason", format!("unknown option {other}"))),
        }
    }
    Ok(Options { path, families })
}

fn millis(duration: Duration) -> f64 {
    (duration.as_secs_f64() * 1_000_000.0).round() / 1_000.0
}

fn run() -> MddResult<(SurfaceReport, serde_json::Value)> {
    let options = parse_arguments()?;
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
    let capture = started.elapsed();

    let started = Instant::now();
    let inventory = ArchiveInventory::build(
        &snapshot.sources()[0],
        InventoryPolicy::default(),
        ArchiveLimits::default(),
    )?;
    let inventory_elapsed = started.elapsed();

    let order = dex_file_order(&inventory)?;
    let extra_filter_prefixes: Vec<String>;
    let classifier: Box<dyn FamilyClassifier> = match &options.families {
        Some(path) => {
            let table = ReferenceTable::load(path)?;
            extra_filter_prefixes = table.extra_filter_prefixes.clone();
            Box::new(ReferenceFamilies(table))
        }
        None => {
            extra_filter_prefixes = Vec::new();
            Box::new(EmptyFamilies)
        }
    };
    let limits = SurfaceLimits::default();

    // Facts are built per DEX exactly as the reference issues one scan per file,
    // and the surface pass then reuses the same immutable definitions.
    let mut scans = Vec::with_capacity(order.len());
    let mut metadata_ms = 0.0;
    let mut definitions_ms = 0.0;
    let mut scan_ms = 0.0;
    let mut metadata_builds = Vec::new();
    let mut definition_builds = Vec::new();
    for file in &order {
        let started = Instant::now();
        let metadata = MetadataFacts::build(
            &snapshot,
            &inventory,
            file.dex_index,
            StringLimits::default(),
        )?;
        let elapsed = millis(started.elapsed());
        metadata_builds.push(elapsed);
        metadata_ms += elapsed;
        let started = Instant::now();
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default())?;
        let elapsed = millis(started.elapsed());
        definition_builds.push(elapsed);
        definitions_ms += elapsed;

        let started = Instant::now();
        let scan = scan_dex(&definitions, classifier.as_ref(), file.file_id, limits)?;
        scans.push(scan);
        scan_ms += millis(started.elapsed());
    }

    let started = Instant::now();
    let resources = resource_fingerprints(&inventory, limits)?;
    let resource_ms = millis(started.elapsed());
    let surface_only_ms = scan_ms + resource_ms;
    let facts_plus_surface_ms = metadata_ms + definitions_ms + surface_only_ms;

    let mut report = build_report(&scans, classifier.as_ref(), resources)?;
    report.dex_files = order.clone();
    let totals = serde_json::json!({
        "dex_files": scans.len(),
        "family_classes": scans.iter().map(|scan| scan.family_classes).sum::<u64>(),
        "family_fields": scans.iter().map(|scan| scan.family_fields).sum::<u64>(),
        "family_methods": scans.iter().map(|scan| scan.family_methods).sum::<u64>(),
        "hashed_code_bytes": scans.iter().map(|scan| scan.hashed_code_bytes).sum::<u64>(),
        "resource_members": report.resource_fingerprints.len(),
        "families": report.families.len(),
        "unknown_families": report.unknown_families.len(),
        "compose_methods": report.families.values().map(|row| row.compose_methods).sum::<u64>(),
    });
    let timing = serde_json::json!({
        "capture_ms": millis(capture),
        "inventory_ms": millis(inventory_elapsed),
        "metadata_ms": metadata_builds,
        "definitions_ms": definition_builds,
        "metadata_total_ms": metadata_ms,
        "definitions_total_ms": definitions_ms,
        "surface_scan_ms": scan_ms,
        "resources_ms": resource_ms,
        "surface_only_ms": surface_only_ms,
        "facts_plus_surface_ms": facts_plus_surface_ms,
        "boundary": "surface_only_ms = scan_dex over every DEX + resource_fingerprints over the captured inventory, same snapshot; facts_plus_surface_ms additionally includes metadata+definitions, which the reference already paid inside its DexSQL index build",
        "rules": if options.families.is_some() { "reference" } else { "empty" },
        "reference_extra_filter_prefixes_documented_only": extra_filter_prefixes,
    });
    Ok((
        report,
        serde_json::json!({"totals": totals, "timing": timing}),
    ))
}

fn main() -> ExitCode {
    let timing = std::env::args_os().any(|argument| argument == "--timing");
    match run() {
        Ok((report, extra)) => {
            if timing {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "class_records": report.class_records.len(),
                        "report": {
                            "families": report.families,
                            "unknown_families": report.unknown_families,
                            "unproduced_fields": report.unproduced_fields,
                            "profile_admitted": report.profile_admitted,
                        },
                        "class_record_digest": digest_records(&report),
                        "measurement": extra,
                    }))
                    .unwrap_or_default()
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "scope": report.scope,
                        "dex_files": report.dex_files,
                        "class_records": report.class_records,
                        "families": report.families,
                        "unknown_families": report.unknown_families,
                        "resource_fingerprints": report.resource_fingerprints,
                        "resource_members_skipped_non_utf8": report
                            .resource_members_skipped_non_utf8,
                        "unproduced_fields": report.unproduced_fields,
                        "profile_admitted": report.profile_admitted,
                    }))
                    .unwrap_or_default()
                );
            }
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

/// Multiset digest of the class records, matching the retained evidence
/// certificate: `sha256(json.dumps(sorted(per-record json), sort_keys=True))`.
fn digest_records(report: &SurfaceReport) -> String {
    let mut encoded: Vec<String> = report
        .class_records
        .iter()
        .map(|record| {
            serde_json::to_string(&serde_json::json!({
                "class": record.class,
                "compose_signatures": record.compose_signatures,
                "family": record.family,
                "fields": record.fields,
                "file_id": record.file_id,
                "method_bodies_sha256": record.method_bodies_sha256,
                "methods": record.methods,
                "superclass": record.superclass,
            }))
            .unwrap_or_default()
        })
        .collect();
    encoded.sort();
    mdd_types::sha256(format!("[{}]", encoded.join(", ")).as_bytes())
}
