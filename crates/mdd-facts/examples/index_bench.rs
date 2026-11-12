//! Index-layer amplification probe.
//!
//! Measures the cost of the lazy candidate indexes in `mdd_facts::indexes`
//! against a real input: first build of a single index, a multi-index query
//! mix, the same mix through the single-pass `prepare_indexes` entry point,
//! and how often the coverage ledger is evaluated.
//!
//! Usage: `cargo run --release -p mdd-facts --example index_bench -- app.apk [--repeat N]`
//!
//! This is a development instrument. It does not claim performance
//! qualification and it is not a paired A0/A1/A2 trial.
use mdd_dex::{
    annotations::AnnotationLimits, definitions::DefinitionLimits, instructions::CodeLimits,
    strings::StringLimits,
};
use mdd_facts::{
    MetadataFacts,
    annotations::AnnotationFacts,
    code::CodeFacts,
    definitions::DefinitionFacts,
    indexes::{FactView, IndexLimits, SelectedScope, SnapshotFactIndex, Utf16Predicate},
    metadata::{EntityKind, EntityRef},
    references::{FieldSymbol, MethodSymbol, ReferenceFacts, ReferenceLimits},
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

fn usage() -> MddError {
    MddError::new(
        ErrorCode::InvalidArgument,
        "index_bench",
        "usage: index_bench INPUT.(apk|dex) [--repeat N]",
    )
}

struct Data {
    snapshot: Snapshot,
    inventories: Vec<ArchiveInventory>,
    codes: Vec<CodeFacts>,
    references: Vec<ReferenceFacts>,
    annotations: Vec<AnnotationFacts>,
}

fn load(path: &Path) -> MddResult<Data> {
    let kind = if path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("dex"))
    {
        InputKind::RawDex
    } else {
        InputKind::Apk
    };
    let snapshot = Snapshot::capture(
        &[InputSpec {
            path: path.to_path_buf(),
            kind,
            expected_sha256: None,
        }],
        CaptureLimits::default(),
    )?;
    let inventories = snapshot
        .sources()
        .iter()
        .map(|source| {
            ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())
        })
        .collect::<MddResult<Vec<_>>>()?;
    let mut codes = Vec::new();
    let mut references = Vec::new();
    let mut annotations = Vec::new();
    for inventory in &inventories {
        for index in 0..inventory.selected_dexes().len() {
            let metadata =
                MetadataFacts::build(&snapshot, inventory, index, StringLimits::default())?;
            let definition = DefinitionFacts::build(metadata, DefinitionLimits::default())?;
            let code = CodeFacts::build_all_code_items(
                &snapshot,
                inventory,
                index,
                CodeLimits::default(),
            )?;
            annotations.push(AnnotationFacts::build(
                definition.clone(),
                AnnotationLimits::default(),
            )?);
            references.push(ReferenceFacts::build(
                definition,
                code.clone(),
                ReferenceLimits::default(),
            )?);
            codes.push(code);
        }
    }
    Ok(Data {
        snapshot,
        inventories,
        codes,
        references,
        annotations,
    })
}

fn views(data: &Data) -> Vec<FactView<'_>> {
    data.references
        .iter()
        .enumerate()
        .map(|(index, references)| {
            FactView::unbuilt(&references.source().dex_occurrence_id)
                .with_annotations(&data.annotations[index])
                .with_references(references)
                .with_code(&data.codes[index])
        })
        .collect()
}

fn scope(data: &Data) -> SelectedScope {
    SelectedScope::from_inventories(&data.snapshot, &data.inventories.iter().collect::<Vec<_>>())
        .unwrap()
}

/// Pre-resolved query targets, so no case spends time inventing symbols.
struct Ctx {
    caller: EntityRef,
    method: MethodSymbol,
    field: FieldSymbol,
    type_descriptor: String,
    prototype_descriptor: String,
    string_units: Vec<u16>,
    annotation_units: Vec<u16>,
    class_descriptor: Vec<u16>,
}

fn context(data: &Data) -> Ctx {
    let first = &data.references[0];
    let definitions = first.definitions();
    let method_reference = &definitions.definitions().method_references[0];
    let prototype = &definitions.metadata().prototypes()[method_reference.proto_idx as usize];
    let field_reference = &definitions.definitions().field_references[0];
    let caller_local = first
        .sites()
        .iter()
        .map(|site| site.caller_method_idx)
        .min()
        .unwrap_or(0);
    let string_units = definitions
        .metadata()
        .strings()
        .iter()
        .map(|string| &string.data.text.utf16_units)
        .find(|units| !units.is_empty())
        .cloned()
        .unwrap_or_default();
    let annotation_units = data
        .annotations
        .iter()
        .flat_map(|facts| facts.data().annotation_items.iter())
        .find_map(|item| {
            definitions
                .metadata()
                .types()
                .get(item.type_idx as usize)
                .and_then(|ty| {
                    definitions
                        .metadata()
                        .strings()
                        .get(ty.descriptor_string.local_index as usize)
                })
                .map(|string| string.data.text.utf16_units.clone())
        })
        .unwrap_or_else(|| "Ldalvik/annotation/Signature;".encode_utf16().collect());
    Ctx {
        caller: EntityRef {
            snapshot_id: first.source().snapshot_id.clone(),
            dex_occurrence_id: first.source().dex_occurrence_id.clone(),
            kind: EntityKind::MethodDefinition,
            local_index: caller_local,
        },
        method: MethodSymbol {
            owner: method_reference.class_descriptor.clone(),
            name: method_reference.method_name.clone(),
            prototype: prototype.data.descriptor.clone(),
        },
        field: FieldSymbol {
            owner: field_reference.class_descriptor.clone(),
            name: field_reference.field_name.clone(),
            field_type: field_reference.type_descriptor.clone(),
        },
        type_descriptor: definitions.metadata().types()[0].data.descriptor.clone(),
        prototype_descriptor: definitions.metadata().prototypes()[0]
            .data
            .descriptor
            .clone(),
        string_units,
        annotation_units,
        class_descriptor: definitions.definitions().classes[0]
            .descriptor
            .encode_utf16()
            .collect(),
    }
}

type Query = fn(&SnapshotFactIndex<'_>, &Ctx) -> MddResult<()>;

fn query_strings(index: &SnapshotFactIndex<'_>, _ctx: &Ctx) -> MddResult<()> {
    index
        .strings_indexed(&Utf16Predicate::Equal(
            "app_name".encode_utf16().collect::<Vec<_>>(),
        ))
        .map(|_| ())
}

fn query_definitions(index: &SnapshotFactIndex<'_>, ctx: &Ctx) -> MddResult<()> {
    index.classes_exact(&ctx.class_descriptor).map(|_| ())
}

fn query_reference_symbols(index: &SnapshotFactIndex<'_>, ctx: &Ctx) -> MddResult<()> {
    index.references_to_method_symbol(&ctx.method).map(|_| ())
}

fn query_field_reference_symbols(index: &SnapshotFactIndex<'_>, ctx: &Ctx) -> MddResult<()> {
    index.references_to_field_symbol(&ctx.field).map(|_| ())
}

fn query_type_references(index: &SnapshotFactIndex<'_>, ctx: &Ctx) -> MddResult<()> {
    index
        .references_to_type_descriptor(&ctx.type_descriptor)
        .map(|_| ())
}

fn query_prototype_references(index: &SnapshotFactIndex<'_>, ctx: &Ctx) -> MddResult<()> {
    index
        .references_to_prototype_descriptor(&ctx.prototype_descriptor)
        .map(|_| ())
}

fn query_method_handles(index: &SnapshotFactIndex<'_>, ctx: &Ctx) -> MddResult<()> {
    index
        .references_to_method_handle_symbol(&mdd_facts::indexes::MethodHandleSymbol::Method {
            handle_kind: 6,
            target: ctx.method.clone(),
        })
        .map(|_| ())
}

fn query_caller_sites(index: &SnapshotFactIndex<'_>, ctx: &Ctx) -> MddResult<()> {
    index.references_from_method(&ctx.caller, None).map(|_| ())
}

fn query_string_references(index: &SnapshotFactIndex<'_>, ctx: &Ctx) -> MddResult<()> {
    index
        .references_to_string_utf16(&ctx.string_units)
        .map(|_| ())
}

fn query_annotation_types(index: &SnapshotFactIndex<'_>, ctx: &Ctx) -> MddResult<()> {
    index
        .annotation_owners_by_type(&ctx.annotation_units)
        .map(|_| ())
}

/// One named measurement.
struct Case {
    name: &'static str,
    indexes: u64,
    queries: &'static [Query],
}

const SINGLE: [Case; 9] = [
    Case {
        name: "strings",
        indexes: 1,
        queries: &[query_strings],
    },
    Case {
        name: "definitions",
        indexes: 1,
        queries: &[query_definitions],
    },
    Case {
        name: "reference_symbols",
        indexes: 1,
        queries: &[query_reference_symbols],
    },
    Case {
        name: "field_reference_symbols",
        indexes: 1,
        queries: &[query_field_reference_symbols],
    },
    Case {
        name: "type_references",
        indexes: 1,
        queries: &[query_type_references],
    },
    Case {
        name: "prototype_references",
        indexes: 1,
        queries: &[query_prototype_references],
    },
    Case {
        name: "method_handles",
        indexes: 1,
        queries: &[query_method_handles],
    },
    Case {
        name: "caller_sites",
        indexes: 1,
        queries: &[query_caller_sites],
    },
    Case {
        name: "annotation_types",
        indexes: 1,
        queries: &[query_annotation_types],
    },
];

const MIX: [Case; 3] = [
    Case {
        name: "mix3",
        indexes: 3,
        queries: &[query_strings, query_definitions, query_type_references],
    },
    Case {
        name: "mix5",
        indexes: 5,
        queries: &[
            query_strings,
            query_definitions,
            query_type_references,
            query_prototype_references,
            query_string_references,
        ],
    },
    Case {
        name: "mix9",
        indexes: 9,
        queries: &[
            query_strings,
            query_definitions,
            query_reference_symbols,
            query_field_reference_symbols,
            query_type_references,
            query_prototype_references,
            query_method_handles,
            query_caller_sites,
            query_annotation_types,
        ],
    },
];

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|left, right| left.partial_cmp(right).unwrap());
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    }
}

fn spread(values: &[f64]) -> (f64, f64) {
    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    (min, max)
}

fn run_case(
    case: &Case,
    selected: &SelectedScope,
    views: &[FactView<'_>],
    ctx: &Ctx,
    repeat: usize,
) -> MddResult<Value> {
    let mut samples = Vec::with_capacity(repeat);
    let mut evaluations = 0u64;
    let mut traversals = 0u64;
    for _ in 0..repeat {
        let index = SnapshotFactIndex::new(selected.clone(), views, IndexLimits::default())?;
        let before_evaluations = index.coverage_evaluations();
        let before_traversals = index.index_traversals();
        let started = Instant::now();
        for query in case.queries {
            (query)(&index, ctx)?;
        }
        samples.push(millis(started.elapsed()));
        evaluations = index.coverage_evaluations() - before_evaluations;
        traversals = index.index_traversals() - before_traversals;
    }
    let (min, max) = spread(&samples);
    Ok(json!({
        "case": case.name,
        "indexes_requested": case.indexes,
        "median_ms": median(samples.clone()),
        "min_ms": min,
        "max_ms": max,
        "samples_ms": samples,
        "ledger_evaluations": evaluations,
        "index_traversals": traversals,
    }))
}

fn run(path: &Path, repeat: usize) -> MddResult<Value> {
    let started = Instant::now();
    let data = load(path)?;
    let setup = millis(started.elapsed());
    let views = views(&data);
    let selected = scope(&data);
    let ctx = context(&data);

    let mut rows = Vec::new();
    for case in SINGLE.iter().chain(MIX.iter()) {
        rows.push(run_case(case, &selected, &views, &ctx, repeat)?);
    }

    // Raw cost of one coverage evaluate against the same ledger, for attribution.
    let mut coverage_samples = Vec::with_capacity(repeat);
    for _ in 0..repeat {
        let index = SnapshotFactIndex::new(selected.clone(), &views, IndexLimits::default())?;
        let request = mdd_facts::coverage::CoverageRequest::for_scope(
            index.scope(),
            &[mdd_facts::coverage::FactLayer::References],
        );
        let started = Instant::now();
        let _ = index.coverage(&request)?;
        coverage_samples.push(millis(started.elapsed()));
    }

    Ok(json!({
        "operation_status": "ok",
        "input": path.display().to_string(),
        "dex_count": data.references.len(),
        "fact_setup_ms": setup,
        "repeat": repeat,
        "cases": rows,
        "cold_coverage_evaluate": {
            "median_ms": median(coverage_samples.clone()),
            "samples_ms": coverage_samples,
        },
        "qualification": "development index probe only; not a performance or profile qualification",
    }))
}

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let Some(path) = arguments.next().map(PathBuf::from) else {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    };
    let mut repeat = 5usize;
    while let Some(argument) = arguments.next() {
        let Some(text) = argument.to_str() else {
            eprintln!("{}", usage());
            return ExitCode::from(2);
        };
        match text {
            "--repeat" => {
                let Some(value) = arguments.next().and_then(|value| {
                    value
                        .to_str()
                        .and_then(|text| text.parse::<usize>().ok())
                        .filter(|value| *value > 0)
                }) else {
                    eprintln!("{}", usage());
                    return ExitCode::from(2);
                };
                repeat = value;
            }
            other => {
                eprintln!(
                    "{}",
                    usage().detail("reason", format!("unknown option {other}"))
                );
                return ExitCode::from(2);
            }
        }
    }
    match run(&path, repeat) {
        Ok(value) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&value).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
