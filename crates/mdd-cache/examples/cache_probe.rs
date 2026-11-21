//! End-to-end probe comparing uncached `mdd_service::Dataset` queries against persisted
//! `mdd-index/1` caches across cold, warm, invalidated, corrupted-repair, and bypass paths.

use mdd_cache::dependency_tracking::{
    ContentCacheRecord, ContentObjectReuseIndex, IncrementalDependencyBoundary,
    LogicalOccurrenceRef, TargetMemberSpec, WorkloadUnitSummary,
    evaluate_default_conservative_gate, shared_container_dependency,
    validate_negative_finding_reuse,
};
use mdd_cache::facts_codec::{
    CachedCell, CachedFactsPayload, CachedRawCodeMethod, CachedRelationTable,
    NegativeFindingRecord, SnapshotAndInventorySection,
};
use mdd_cache::format::verify_and_decode_image;
use mdd_cache::key::{CacheMode, FactCacheKeySpec, SemanticsIdentity};
use mdd_cache::store::{CacheOpenPolicy, CacheStore};
use mdd_facts::coverage::NonScalarTextPolicy;
use mdd_input::archive::{ArchiveInventory, InventoryPolicy};
use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
use mdd_service::{Batch, Dataset, Dialect, InputRequest, RunOptions, Sink};
use mdd_session::ResourceLimits;
use mdd_sql::control::SqlLimits;
use mdd_sql::values::SqlValue;
use mdd_types::{Completeness, Coverage, DecimalU64, ErrorCode, Execution, Response, sha256};
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

const CONTRACT_TABLES: &[&str] = &[
    "dex_files",
    "strings",
    "types",
    "methods",
    "classes",
    "class_interfaces",
    "class_fields",
    "class_methods",
    "code_items",
    "annotation_directory_entries",
    "annotation_set_entries",
    "annotations",
    "annotation_elements",
    "method_strings",
    "method_calls",
    "method_field_accesses",
    "method_used_types",
];

struct CollectingSink {
    columns: Vec<String>,
    rows: Vec<Vec<CachedCell>>,
}

impl CollectingSink {
    fn new() -> Self {
        Self {
            columns: Vec::new(),
            rows: Vec::new(),
        }
    }
}

fn convert_sql_value(value: &SqlValue) -> CachedCell {
    match value {
        SqlValue::Null => CachedCell::Null,
        SqlValue::Bool(v) => CachedCell::Bool(*v),
        SqlValue::I64(v) => CachedCell::I64(v.0),
        SqlValue::U64(v) => CachedCell::U64(*v),
        SqlValue::F64(v) => CachedCell::F64Bits(*v),
        SqlValue::Text(t) => match t.strict_utf8() {
            Ok(utf8) if t.original_mutf8.is_none() => CachedCell::Utf8(utf8),
            _ => CachedCell::Utf16 {
                units: t.utf16.clone(),
                original_mutf8: t.original_mutf8.clone(),
            },
        },
        SqlValue::Bytes(b) => CachedCell::Bytes(b.clone()),
        SqlValue::DexMutf8 {
            bytes,
            utf16_code_units,
        } => CachedCell::DexMutf8 {
            bytes: bytes.clone(),
            utf16_code_units: *utf16_code_units,
        },
    }
}

impl Sink for CollectingSink {
    fn batch(&mut self, batch: &Batch<'_>) -> io::Result<()> {
        if self.columns.is_empty() {
            self.columns = batch.columns.to_vec();
        }
        for row in batch.rows {
            self.rows.push(row.iter().map(convert_sql_value).collect());
        }
        Ok(())
    }
}

fn query_all_tables(input_paths: &[PathBuf]) -> Result<Vec<CachedRelationTable>, String> {
    let requests: Vec<InputRequest> = input_paths
        .iter()
        .map(|p| InputRequest {
            path: p.clone(),
            kind: None,
        })
        .collect();
    let limits = ResourceLimits::default();
    let sql_limits = SqlLimits {
        max_steps: 50_000_000,
        max_scanned_rows: 10_000_000,
        max_result_rows: 2_000_000,
        ..SqlLimits::default()
    };
    let dataset = Dataset::open_with_non_scalar_policy(
        &requests,
        Dialect::DexSql011,
        limits,
        sql_limits,
        NonScalarTextPolicy::LossyReplacement,
    )
    .map_err(|e| format!("{:?}: {}", e.code, e.message))?;

    let options = RunOptions {
        batch_rows: 4096,
        max_rows: None,
        deadline_ms: None,
    };
    let mut tables = Vec::with_capacity(CONTRACT_TABLES.len());
    for table in CONTRACT_TABLES {
        let mut sink = CollectingSink::new();
        let sql = format!("SELECT * FROM {table}");
        let outcome = dataset
            .run(&sql, &options, &mut sink)
            .map_err(|e| format!("{table}: {:?}: {}", e.code, e.message))?;
        if let Some(err) = outcome.terminal.error {
            return Err(format!("{table}: {:?}: {}", err.code, err.message));
        }
        let cols = if sink.columns.is_empty() {
            vec!["empty".to_owned()]
        } else {
            sink.columns
        };
        let table_obj = if sink.rows.is_empty() && cols == vec!["empty"] {
            CachedRelationTable::from_rows(*table, Vec::new(), Vec::new())
        } else {
            CachedRelationTable::from_rows(*table, cols, sink.rows)
        }
        .map_err(|e| format!("{table}: {}", e.message))?;
        tables.push(table_obj);
    }
    Ok(tables)
}

fn collect_inputs(
    paths: &[PathBuf],
) -> Result<(Snapshot, Vec<ArchiveInventory>, Vec<InputSpec>), String> {
    let mut specs = Vec::with_capacity(paths.len());
    for p in paths {
        let kind = InputKind::detect(p).map_err(|e| format!("{:?}: {}", e.code, e.message))?;
        specs.push(InputSpec {
            path: p.clone(),
            kind,
            expected_sha256: None,
        });
    }
    let snapshot = Snapshot::capture(&specs, CaptureLimits::default())
        .map_err(|e| format!("{:?}: {}", e.code, e.message))?;
    let mut inventories = Vec::with_capacity(snapshot.sources().len());
    for source in snapshot.sources() {
        let inv = ArchiveInventory::build(
            source,
            InventoryPolicy {
                require_dex: false,
                hold_dex_bytes: false,
                ..Default::default()
            },
            Default::default(),
        )
        .map_err(|e| format!("{:?}: {}", e.code, e.message))?;
        inventories.push(inv);
    }
    Ok((snapshot, inventories, specs))
}

fn build_facts_for_sources(
    snapshot: &Snapshot,
    inventories: &[ArchiveInventory],
    input_paths: &[PathBuf],
) -> Result<
    (
        SnapshotAndInventorySection,
        Vec<CachedRawCodeMethod>,
        Vec<CachedRelationTable>,
    ),
    String,
> {
    let mut all_summaries = Vec::new();
    let mut reuse_map = mdd_cache::OccurrenceReuseMap::default();
    let mut all_raw = Vec::new();
    let mut global_file_id = 0u32;

    for (src, inv) in snapshot.sources().iter().zip(inventories.iter()) {
        if inv.selected_dexes().is_empty() {
            continue;
        }
        // Build a single-source snapshot view matching the captured source occurrence.
        let single_spec = vec![InputSpec {
            path: input_paths[src.identity().input_ordinal.0 as usize].clone(),
            kind: src.kind(),
            expected_sha256: None,
        }];
        let _ = single_spec;
        // Build facts directly using FactsPipeline on per-source single snapshot:
        // preserve the exact captured bytes and occurrence ordinal.
        let mut dex_facts = Vec::new();
        for (local_idx, cand) in inv.selected_dexes().iter().enumerate() {
            let meta = std::sync::Arc::new(
                mdd_facts::MetadataFacts::build(snapshot, inv, local_idx, Default::default())
                    .map_err(|e| format!("{:?}: {}", e.code, e.message))?,
            );
            let defs = std::sync::Arc::new(
                mdd_facts::DefinitionFacts::build_arc(
                    std::sync::Arc::clone(&meta),
                    Default::default(),
                )
                .map_err(|e| format!("{:?}: {}", e.code, e.message))?,
            );
            let code = std::sync::Arc::new(
                mdd_facts::CodeFacts::build_all_code_items(
                    snapshot,
                    inv,
                    local_idx,
                    Default::default(),
                )
                .map_err(|e| format!("{:?}: {}", e.code, e.message))?,
            );
            let anns = std::sync::Arc::new(
                mdd_facts::annotations::AnnotationFacts::build_arc(
                    std::sync::Arc::clone(&defs),
                    Default::default(),
                )
                .map_err(|e| format!("{:?}: {}", e.code, e.message))?,
            );
            let refs = std::sync::Arc::new(
                mdd_facts::ReferenceFacts::build_arc(
                    std::sync::Arc::clone(&defs),
                    std::sync::Arc::clone(&code),
                    Default::default(),
                )
                .map_err(|e| format!("{:?}: {}", e.code, e.message))?,
            );
            dex_facts.push(mdd_facts::DexFacts {
                index: local_idx,
                occurrence: cand.dex_occurrence_id.clone(),
                metadata: meta,
                definitions: defs,
                code,
                annotations: anns,
                references: refs,
            });
        }
        let (mut sec, mut raw) = CachedFactsPayload::build_core_sections(
            snapshot,
            std::slice::from_ref(inv),
            &dex_facts,
        )
        .map_err(|e| format!("{:?}: {}", e.code, e.message))?;
        for s in &mut sec.occurrence_summaries {
            s.file_id = global_file_id;
            s.string_pool_id = global_file_id;
            global_file_id += 1;
        }
        let occ_base = global_file_id - (sec.occurrence_summaries.len() as u32);
        for m in &mut raw {
            m.file_id += occ_base;
        }
        for (idx, occ) in sec.occurrence_summaries.iter().enumerate() {
            let _ = idx;
            reuse_map.record(
                occ.content_id.clone(),
                occ.byte_length.0,
                mdd_cache::dependency_tracking::LogicalOccurrenceRef {
                    file_id: occ.file_id,
                    dex_occurrence_id: occ.dex_occurrence_id.clone(),
                    source_occurrence_id: occ.source_occurrence_id.clone(),
                    member_name: occ.member_name.clone(),
                    logical_header_offset: occ.logical_header_offset,
                },
            );
        }
        all_summaries.extend(sec.occurrence_summaries);
        all_raw.extend(raw);
    }

    let tables = query_all_tables(input_paths)?;
    let section = SnapshotAndInventorySection {
        snapshot_content_key: snapshot.manifest().snapshot_content_key.clone(),
        capture_policy: snapshot.manifest().capture_policy.clone(),
        occurrence_summaries: all_summaries,
        occurrence_reuse_map: reuse_map,
    };
    Ok((section, all_raw, tables))
}

fn complete_envelope_parts(scope_id: &str) -> (Coverage, Execution, Response) {
    (
        Coverage {
            scope_id: scope_id.to_owned(),
            input: Completeness::Complete,
            facts: Completeness::Complete,
            required_layers: vec![
                "inventory".to_owned(),
                "metadata".to_owned(),
                "definitions".to_owned(),
                "code".to_owned(),
                "references".to_owned(),
                "annotations".to_owned(),
            ],
            issues: vec![],
        },
        Execution { complete: true },
        Response {
            schema_id: Some("mdd.cache.relations.v1".to_owned()),
            emitted_rows: DecimalU64(0),
            total_rows: None,
            total_rows_exact: false,
            more_available: false,
            truncated: false,
            next_cursor: None,
        },
    )
}

fn cmd_run(args: &[String]) -> Result<serde_json::Value, String> {
    let mut cache_dir: Option<PathBuf> = None;
    let mut mode = CacheMode::Standalone;
    let mut policy = CacheOpenPolicy::ReadWrite;
    let mut inputs: Vec<PathBuf> = Vec::new();
    let mut index_file_override: Option<PathBuf> = None;
    let mut hold_ms: u64 = 0;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cache-dir" => {
                i += 1;
                cache_dir = Some(PathBuf::from(
                    args.get(i).ok_or("missing --cache-dir value")?,
                ));
            }
            "--mode" => {
                i += 1;
                mode = match args.get(i).map(String::as_str) {
                    Some("standalone") => CacheMode::Standalone,
                    Some("thin") => CacheMode::Thin,
                    other => return Err(format!("invalid mode: {other:?}")),
                };
            }
            "--policy" => {
                i += 1;
                policy = match args.get(i).map(String::as_str) {
                    Some("read-write") => CacheOpenPolicy::ReadWrite,
                    Some("cache-only") => CacheOpenPolicy::CacheOnly,
                    Some("bypass") => CacheOpenPolicy::Bypass,
                    other => return Err(format!("invalid policy: {other:?}")),
                };
            }
            "--input" => {
                i += 1;
                inputs.push(PathBuf::from(args.get(i).ok_or("missing --input value")?));
            }
            "--index-file" => {
                i += 1;
                index_file_override = Some(PathBuf::from(
                    args.get(i).ok_or("missing --index-file value")?,
                ));
            }
            "--hold-ms" => {
                i += 1;
                hold_ms = args
                    .get(i)
                    .ok_or("missing --hold-ms value")?
                    .parse::<u64>()
                    .map_err(|e| e.to_string())?;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }

    let cache_dir = cache_dir.ok_or("missing --cache-dir")?;
    let store = CacheStore::new(&cache_dir).map_err(|e| format!("{:?}: {}", e.code, e.message))?;

    if let Some(index_path) = index_file_override {
        let source_bytes: Option<Vec<Vec<u8>>> = if inputs.is_empty() {
            None
        } else {
            let mut bufs = Vec::with_capacity(inputs.len());
            for p in &inputs {
                bufs.push(fs::read(p).map_err(|e| e.to_string())?);
            }
            Some(bufs)
        };
        let loaded = store
            .open_verified_file(&index_path, None, source_bytes.as_deref())
            .map_err(|e| format!("{}:{}", e.code, e.message))?;
        let table_digests: BTreeMap<String, String> = loaded
            .payload
            .tables
            .iter()
            .map(|t| (t.name.clone(), t.table_sha256.clone()))
            .collect();
        return Ok(json!({
            "ok": true,
            "action": "verify-index-file",
            "canonical_cache_key": loaded.manifest.canonical_cache_key,
            "mode": loaded.manifest.mode,
            "runtime_snapshot_id": loaded.runtime_snapshot_id,
            "table_digests": table_digests,
            "occurrences": loaded.payload.snapshot_and_inventory.occurrence_summaries.len(),
            "verified_blobs": loaded.verified_source_blobs.len(),
        }));
    }

    if inputs.is_empty() {
        return Err("at least one --input is required".to_owned());
    }
    let (snapshot, inventories, specs) = collect_inputs(&inputs)?;
    let semantics = SemanticsIdentity::default();
    let key_spec =
        FactCacheKeySpec::from_snapshot_and_inventories(&snapshot, &inventories, semantics.clone())
            .map_err(|e| format!("{}:{}", e.code, e.message))?;

    let mut build_invoked = false;
    let (report, loaded) = store
        .open_or_build(&key_spec, mode, policy, &specs, &semantics, |snap, invs| {
            build_invoked = true;
            if hold_ms > 0 {
                thread::sleep(Duration::from_millis(hold_ms));
            }
            let (sec, raw, tables) = build_facts_for_sources(snap, invs, &inputs)
                .map_err(|msg| mdd_types::MddError::new(ErrorCode::InternalFault, "probe", msg))?;
            let payload = CachedFactsPayload {
                snapshot_and_inventory: sec,
                tables,
                raw_code_methods: raw,
                negative_findings: Vec::new(),
            };
            let (cov, exec, resp) = complete_envelope_parts("scope-cache-probe");
            Ok((payload, cov, exec, resp))
        })
        .map_err(|e| format!("{}:{}", e.code, e.message))?;

    let table_digests: BTreeMap<String, (u64, String)> = loaded
        .payload
        .tables
        .iter()
        .map(|t| (t.name.clone(), (t.row_count.0, t.table_sha256.clone())))
        .collect();
    let overall_tables_sha =
        sha256(&serde_json::to_vec(&loaded.payload.tables).map_err(|e| e.to_string())?);
    let raw_sha =
        sha256(&serde_json::to_vec(&loaded.payload.raw_code_methods).map_err(|e| e.to_string())?);

    Ok(json!({
        "ok": true,
        "report": report,
        "build_fn_invoked": build_invoked,
        "table_digests": table_digests,
        "overall_tables_sha256": overall_tables_sha,
        "raw_code_methods_sha256": raw_sha,
        "occurrence_summaries": loaded.payload.snapshot_and_inventory.occurrence_summaries,
        "occurrence_reuse_map": loaded.payload.snapshot_and_inventory.occurrence_reuse_map,
        "verified_blob_digests": loaded.verified_source_blobs.iter().map(|(k, v)| (k.clone(), sha256(v))).collect::<BTreeMap<_, _>>(),
        "section_table_sha256": loaded.manifest.section_table_sha256,
    }))
}

fn cmd_verify_file(args: &[String]) -> Result<serde_json::Value, String> {
    let mut cache_dir: Option<PathBuf> = None;
    let mut file_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cache-dir" => {
                i += 1;
                cache_dir = Some(PathBuf::from(args.get(i).ok_or("missing --cache-dir")?));
            }
            "--file" => {
                i += 1;
                file_path = Some(PathBuf::from(args.get(i).ok_or("missing --file")?));
            }
            other => return Err(format!("unknown arg {other}")),
        }
        i += 1;
    }
    let file_path = file_path.ok_or("missing --file")?;
    let cache_dir =
        cache_dir.unwrap_or_else(|| file_path.parent().unwrap_or(Path::new(".")).to_path_buf());
    let store = CacheStore::new(cache_dir).map_err(|e| format!("{}:{}", e.code, e.message))?;
    match store.open_verified_file(&file_path, None, None) {
        Ok(loaded) => Ok(json!({
            "ok": true,
            "canonical_cache_key": loaded.manifest.canonical_cache_key,
            "section_count": loaded.manifest.sections.len(),
        })),
        Err(err) => Ok(json!({
            "ok": false,
            "error_code": err.code.to_string(),
            "reason": err.details.get("reason").and_then(|v| v.as_str()),
            "message": err.message,
        })),
    }
}

fn cmd_inspect_header(args: &[String]) -> Result<serde_json::Value, String> {
    let path = PathBuf::from(args.first().ok_or("usage: inspect-header <file>")?);
    let bytes = fs::read(&path).map_err(|e| e.to_string())?;
    let verified =
        verify_and_decode_image(&bytes).map_err(|e| format!("{}:{}", e.code, e.message))?;
    Ok(json!({
        "ok": true,
        "header": {
            "major": verified.header.major,
            "minor": verified.header.minor,
            "header_bytes": verified.header.header_bytes,
            "section_count": verified.header.section_count,
            "endian": verified.header.endian,
            "manifest_offset": verified.header.manifest_offset,
            "manifest_bytes": verified.header.manifest_bytes,
            "section_table_offset": verified.header.section_table_offset,
        },
        "section_table_sha256": verified.manifest.section_table_sha256,
        "mode": verified.manifest.mode,
    }))
}

struct BuiltMemberTelemetry {
    spec: TargetMemberSpec,
    build_elapsed_ns: u64,
    outbound_ref_edges: u64,
    hierarchy_edges: u64,
    constant_pool_refs: u64,
}

fn build_member_telemetry(
    snapshot: &Snapshot,
    inventories: &[ArchiveInventory],
) -> Result<Vec<BuiltMemberTelemetry>, String> {
    let mut out = Vec::new();
    let mut global_file_id = 0u32;
    for inv in inventories {
        for (local_idx, cand) in inv.selected_dexes().iter().enumerate() {
            let start = Instant::now();
            let meta = std::sync::Arc::new(
                mdd_facts::MetadataFacts::build(snapshot, inv, local_idx, Default::default())
                    .map_err(|e| format!("{:?}: {}", e.code, e.message))?,
            );
            let defs = std::sync::Arc::new(
                mdd_facts::DefinitionFacts::build_arc(
                    std::sync::Arc::clone(&meta),
                    Default::default(),
                )
                .map_err(|e| format!("{:?}: {}", e.code, e.message))?,
            );
            let code = std::sync::Arc::new(
                mdd_facts::CodeFacts::build_all_code_items(
                    snapshot,
                    inv,
                    local_idx,
                    Default::default(),
                )
                .map_err(|e| format!("{:?}: {}", e.code, e.message))?,
            );
            let _anns = mdd_facts::annotations::AnnotationFacts::build_arc(
                std::sync::Arc::clone(&defs),
                Default::default(),
            )
            .map_err(|e| format!("{:?}: {}", e.code, e.message))?;
            let refs = mdd_facts::ReferenceFacts::build_arc(
                std::sync::Arc::clone(&defs),
                std::sync::Arc::clone(&code),
                Default::default(),
            )
            .map_err(|e| format!("{:?}: {}", e.code, e.message))?;
            let elapsed_ns = start.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;

            let header = meta.header();
            let _ = header;
            let workload = WorkloadUnitSummary {
                member_bytes: DecimalU64(cand.blob.len() as u64),
                string_count: meta.strings().len() as u32,
                type_count: meta.types().len() as u32,
                proto_count: meta.prototypes().len() as u32,
                field_count: defs.definitions().field_references.len() as u32,
                method_count: defs.definitions().method_references.len() as u32,
                class_count: defs.definitions().classes.len() as u32,
                code_item_count: code.items().len() as u32,
            };
            let hierarchy_edges: u64 = defs
                .definitions()
                .classes
                .iter()
                .filter(|cls| cls.superclass_idx.is_some())
                .count() as u64
                + defs.definitions().interfaces.len() as u64;
            let outbound_ref_edges = refs.sites().len() as u64;
            let constant_pool_refs = u64::from(workload.string_count)
                + u64::from(workload.type_count)
                + u64::from(workload.field_count)
                + u64::from(workload.method_count);

            let spec = TargetMemberSpec {
                occurrence: LogicalOccurrenceRef {
                    file_id: global_file_id,
                    dex_occurrence_id: cand.dex_occurrence_id.clone(),
                    source_occurrence_id: meta.source().source_occurrence_id.clone(),
                    member_name: cand.blob.identity.name_utf8.clone(),
                    logical_header_offset: cand.logical_header_byte_offset,
                },
                content_id: meta.source().content_id.clone(),
                workload,
                container_dependency: None,
            };
            global_file_id += 1;
            out.push(BuiltMemberTelemetry {
                spec,
                build_elapsed_ns: elapsed_ns,
                outbound_ref_edges,
                hierarchy_edges,
                constant_pool_refs,
            });
        }
    }
    Ok(out)
}

fn cmd_content_reuse_suite(args: &[String]) -> Result<serde_json::Value, String> {
    let mut baselines: Vec<PathBuf> = Vec::new();
    let mut targets: Vec<PathBuf> = Vec::new();
    let mut task_id = "mdd064-reuse-eval".to_owned();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--baseline" => {
                i += 1;
                baselines.push(PathBuf::from(args.get(i).ok_or("missing --baseline")?));
            }
            "--target" => {
                i += 1;
                targets.push(PathBuf::from(args.get(i).ok_or("missing --target")?));
            }
            "--task-id" => {
                i += 1;
                task_id = args.get(i).ok_or("missing --task-id")?.clone();
            }
            other => return Err(format!("unknown arg {other}")),
        }
        i += 1;
    }
    if baselines.is_empty() || targets.is_empty() {
        return Err("usage: content-reuse-suite --baseline <path> --target <path>".to_owned());
    }

    let (base_snap, base_invs, _) = collect_inputs(&baselines)?;
    let base_members = build_member_telemetry(&base_snap, &base_invs)?;

    let (tgt_snap, tgt_invs, _) = collect_inputs(&targets)?;
    let tgt_members = build_member_telemetry(&tgt_snap, &tgt_invs)?;
    let tgt_tables = query_all_tables(&targets)?;
    let dex_files_row_count = tgt_tables
        .iter()
        .find(|t| t.name == "dex_files")
        .map_or(0u64, |t| t.row_count.0);

    let semantics = SemanticsIdentity::default();
    let sem_digest =
        sha256(&serde_json::to_vec(&semantics).map_err(|e| format!("semantics serialize: {e}"))?);
    let (cov, exec, resp) = complete_envelope_parts("mdd064-baseline-cache");

    let mut reuse_index = ContentObjectReuseIndex::new();
    for member in &base_members {
        reuse_index
            .register_verified(
                &cov,
                &exec,
                &resp,
                None,
                ContentCacheRecord {
                    semantics_digest: sem_digest.clone(),
                    content_id: member.spec.content_id.clone(),
                    workload: member.spec.workload.clone(),
                    container_dependency: None,
                    persisted_scope_id: "mdd064-baseline-cache".to_owned(),
                },
            )
            .map_err(|e| format!("{}:{}", e.code, e.message))?;
    }

    let target_specs: Vec<TargetMemberSpec> = tgt_members.iter().map(|m| m.spec.clone()).collect();
    let report = reuse_index
        .evaluate_target(&task_id, &sem_digest, &target_specs)
        .map_err(|e| format!("{}:{}", e.code, e.message))?;

    let full_cold_build_ns: u64 = tgt_members.iter().map(|m| m.build_elapsed_ns).sum();
    let rebuilt_only_ns: u64 = tgt_members
        .iter()
        .zip(report.decisions.iter())
        .filter(|(_, d)| !d.reused)
        .map(|(m, _)| m.build_elapsed_ns)
        .sum();
    let wall_time_saving_ratio = if full_cold_build_ns == 0 {
        0.0
    } else {
        (full_cold_build_ns.saturating_sub(rebuilt_only_ns) as f64) / (full_cold_build_ns as f64)
    };

    // Container invalidation & incomplete negative-finding guard probes.
    let mut container_probe_index = ContentObjectReuseIndex::new();
    let dep_v1 =
        shared_container_dependency("dex-041-container", b"hdr+tail-v1", 0, 128, b"tail-v1");
    let dep_v2 =
        shared_container_dependency("dex-041-container", b"hdr+tail-v2", 0, 128, b"tail-v2");
    container_probe_index
        .register_verified(
            &cov,
            &exec,
            &resp,
            None,
            ContentCacheRecord {
                semantics_digest: sem_digest.clone(),
                content_id: "sha256:container-slice".to_owned(),
                workload: WorkloadUnitSummary::default(),
                container_dependency: Some(dep_v1),
                persisted_scope_id: "container-probe".to_owned(),
            },
        )
        .map_err(|e| format!("{}:{}", e.code, e.message))?;
    let container_invalidation_report = container_probe_index
        .evaluate_target(
            "container-invalidation-probe",
            &sem_digest,
            &[TargetMemberSpec {
                occurrence: LogicalOccurrenceRef {
                    file_id: 0,
                    dex_occurrence_id: "occ:container:0".to_owned(),
                    source_occurrence_id: "src:container:0".to_owned(),
                    member_name: Some("classes.dex".to_owned()),
                    logical_header_offset: DecimalU64(128),
                },
                content_id: "sha256:container-slice".to_owned(),
                workload: WorkloadUnitSummary::default(),
                container_dependency: Some(dep_v2),
            }],
        )
        .map_err(|e| format!("{}:{}", e.code, e.message))?;

    let partial_neg_eligibility = validate_negative_finding_reuse(
        &cov,
        &exec,
        &resp,
        None,
        &[
            "inventory".to_owned(),
            "metadata".to_owned(),
            "references".to_owned(),
        ],
        &NegativeFindingRecord {
            scope_id: "neg-partial-layer".to_owned(),
            canonical_cache_key: "neg-key".to_owned(),
            predicate_id: "pred-missing-layer".to_owned(),
            covered_layers: vec!["inventory".to_owned(), "metadata".to_owned()],
            matched_count: DecimalU64(0),
            verified_complete: true,
        },
    );

    let fine_grained_gate = evaluate_default_conservative_gate(IncrementalDependencyBoundary {
        candidate_id: task_id,
        touched_method_count: DecimalU64(
            tgt_members
                .iter()
                .map(|m| u64::from(m.spec.workload.method_count))
                .sum(),
        ),
        outbound_method_ref_edges: DecimalU64(
            tgt_members.iter().map(|m| m.outbound_ref_edges).sum(),
        ),
        hierarchy_override_edges: DecimalU64(tgt_members.iter().map(|m| m.hierarchy_edges).sum()),
        negative_query_dependencies: 1,
        constant_pool_references: DecimalU64(
            tgt_members.iter().map(|m| m.constant_pool_refs).sum(),
        ),
        optional_dex041_container_present: false,
        shared_container_dependency: None,
    });

    Ok(json!({
        "ok": true,
        "dex_files_row_count": dex_files_row_count,
        "physical_dedup_preserves_all_logical_sources":
            (dex_files_row_count as usize) == report.occurrence_reuse_map.total_logical_occurrences(),
        "report": report,
        "timing": {
            "full_cold_build_ns": full_cold_build_ns,
            "incremental_rebuilt_only_ns": rebuilt_only_ns,
            "realized_wall_time_saving_ratio": wall_time_saving_ratio,
        },
        "shared_container_invalidation_verified":
            container_invalidation_report
                .decisions
                .first()
                .is_some_and(|d| !d.reused),
        "shared_container_invalidation_reason":
            container_invalidation_report.decisions.first().map(|d| d.reason),
        "partial_negative_finding_guard": partial_neg_eligibility,
        "fine_grained_incremental_gate": fine_grained_gate,
    }))
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let res = match args.first().map(String::as_str) {
        Some("run") => cmd_run(&args[1..]),
        Some("verify-file") => cmd_verify_file(&args[1..]),
        Some("inspect-header") => cmd_inspect_header(&args[1..]),
        Some("content-reuse-suite") => cmd_content_reuse_suite(&args[1..]),
        _ => Err(
            "usage: cache_probe <run|verify-file|inspect-header|content-reuse-suite> ..."
                .to_owned(),
        ),
    };
    match res {
        Ok(val) => {
            println!("{}", serde_json::to_string(&val).unwrap());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!(
                "{}",
                serde_json::to_string(&json!({"ok": false, "error": err})).unwrap()
            );
            ExitCode::FAILURE
        }
    }
}
