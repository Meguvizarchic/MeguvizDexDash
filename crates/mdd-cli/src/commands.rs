//! The commands that need no SQL session: capabilities and header inspection.
use mdd_input::{
    archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
    snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
};
use mdd_types::{
    Completeness, Coverage, DecimalU64, ErrorCode, Execution, MddError, OperationStatus, Response,
    ResultEnvelope,
};
use serde_json::{Value, json};

pub fn capabilities() -> Value {
    let mut limits = serde_json::Map::new();
    for (name, unit) in [
        ("max_input_bytes", "bytes"),
        ("max_archive_members", "count"),
        ("max_member_uncompressed_bytes", "bytes"),
        ("max_total_uncompressed_bytes", "bytes"),
        ("max_fact_rows", "count"),
        ("max_build_memory_bytes", "bytes"),
        ("max_resident_facts_bytes", "bytes"),
        ("max_query_workspace_bytes", "bytes"),
        ("max_result_bytes", "bytes"),
        ("max_buffered_bytes", "bytes"),
        ("max_cursors", "count"),
        ("max_spool_bytes", "bytes"),
        ("max_threads", "threads"),
        ("deadline_ms", "milliseconds"),
    ] {
        limits.insert(
            name.to_owned(),
            json!({"value":null, "unit":unit,
            "scope":"worker", "enforcement":"unavailable"}),
        );
    }
    for (name, value) in [
        ("max_input_bytes", CaptureLimits::default().max_input_bytes),
        (
            "max_archive_members",
            ArchiveLimits::default().max_members as u64,
        ),
        (
            "max_member_uncompressed_bytes",
            ArchiveLimits::default().max_member_bytes,
        ),
        (
            "max_total_uncompressed_bytes",
            ArchiveLimits::default().max_total_uncompressed_bytes,
        ),
        ("max_fact_rows", 256),
        ("max_result_bytes", 16 * 1024 * 1024),
        ("max_threads", 1),
    ] {
        let unit = limits[name]["unit"].clone();
        limits.insert(
            name.to_owned(),
            json!({"value":value.to_string(),"unit":unit,
            "scope":"worker","enforcement":"soft"}),
        );
    }
    json!({
        "schema_version":"mdd.capabilities.v1", "product":"MeguvizDexDash",
        "engine_version":env!("CARGO_PKG_VERSION"),
        "build_id":format!("source-sha256:{}",env!("MDD_SOURCE_SHA256")),
        "fact_schema_id":"mdd.facts.unimplemented.v1",
        "relation_schema_hash":mdd_types::sha256(b"[]"),
        "profiles":[{"name":"mdd-native-v1","admitted":false,"conformance_manifest_sha256":null},
            {"name":"mdd-header-inspection-dev-v1","admitted":false,"conformance_manifest_sha256":null}],
        "sql_dialects":[
            {"name":"native-v1","revision":"1","features":["layers:metadata,structure"]},
            {"name":"dexsql-0.1.0","revision":"0.1.0","features":["hostlab-contract-relations"]},
            {"name":"dexsql-0.1.1","revision":"0.1.1","features":["hostlab-contract-relations"]}],
        "capabilities":[{"name":"result-contract","version":"1","available":true},
            {"name":"inspect-dex-header","version":"1","available":true},
            {"name":"cli-query","version":"1","available":true},
            {"name":"cli-serve","version":"1","available":true},
            {"name":"cli-text-output","version":"1","available":true},
            {"name":"dexsql-table-output","version":"1","available":false},
            {"name":"typed-ir-query","version":"1","available":false},
            {"name":"query-parameters","version":"1","available":false}],
        "input_formats":[{"kind":"dex-header","versions":["035","037","038","039","040"],"available":true},
            {"kind":"apk-zip","versions":["stored","deflated","zip64-single-disk"],"available":true}],
        "transports":[{"name":"cli-json","version":"1","result_encodings":["json"]},
            {"name":"cli-jsonl-stream","version":"1","result_encodings":["json"]},
            {"name":"cli-text","version":"1","result_encodings":["text"]}],
        "semantics":{"pagination_modes":[],"native_cancel_scope":"query","compat_cancel_closes_dataset":false},
        "effective_limits":limits,"providers":[]
    })
}

pub fn inspect(kind: InputKind, paths: &[std::ffi::OsString]) -> Result<Value, MddError> {
    if paths.is_empty() {
        return Err(MddError::new(
            ErrorCode::InvalidArgument,
            "cli",
            "inspect requires at least one path",
        ));
    }
    let inputs: Vec<_> = paths
        .iter()
        .map(|path| InputSpec {
            path: path.into(),
            kind,
            expected_sha256: None,
        })
        .collect();
    let snapshot = Snapshot::capture(&inputs, CaptureLimits::default())?;
    let mut inventories = Vec::new();
    let mut rows = Vec::new();
    let mut remaining = ArchiveLimits::default().max_total_uncompressed_bytes;
    for source in snapshot.sources() {
        let limits = ArchiveLimits {
            max_total_uncompressed_bytes: remaining,
            ..ArchiveLimits::default()
        };
        let inventory = ArchiveInventory::build(source, InventoryPolicy::default(), limits)?;
        remaining = remaining
            .checked_sub(inventory.manifest().declared_uncompressed_bytes.0)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "inventory",
                    "total archive byte budget exceeded",
                )
            })?;
        for candidate in inventory.selected_dexes() {
            if rows.len() >= 256 {
                return Err(MddError::new(
                    ErrorCode::QuotaExceeded,
                    "inspect",
                    "header row budget exceeded",
                )
                .detail("budget", "max_fact_rows")
                .detail("limit", "256"));
            }
            let header = mdd_dex::validate_header(candidate.blob.bytes()).map_err(|error| {
                error
                    .detail("snapshot_id", snapshot.manifest().snapshot_id.clone())
                    .detail("dex_occurrence_id", candidate.dex_occurrence_id.clone())
                    .detail("content_id", candidate.blob.content_id.clone())
            })?;
            rows.push(json!({"dex_occurrence_id":candidate.dex_occurrence_id,
                "physical_dex_id":candidate.physical_dex_id,
                "logical_header_byte_offset":candidate.logical_header_byte_offset,
                "member":candidate.blob.identity,"content_id":candidate.blob.content_id,
                "header":header}));
        }
        inventories.push(serde_json::to_value(inventory.manifest()).map_err(|error| {
            MddError::new(ErrorCode::InternalFault, "inspect", error.to_string())
        })?);
    }
    let count = DecimalU64(rows.len() as u64);
    let scope_id = mdd_types::opaque_id("scope-header-inventory")?;
    let data = json!({"rows":rows,"snapshot_manifest":snapshot.manifest(),"inventories":inventories,
        "scope_manifest":{"scope_id":scope_id,"selection":"top-level-classes-or-raw",
            "required_layers":["inventory","dex_header"],"full_dex_validation_required":false,
            "signature_verification":"SHA-1 over captured DEX bytes 32..file_size; source identity uses SHA-256",
            "profile_qualification":"unadmitted development inspection"}});
    let envelope = ResultEnvelope {
        schema_version: "mdd.result.v1".to_owned(),
        request_id: mdd_types::opaque_id("request")?,
        operation: "inspect_dex_headers".to_owned(),
        profile: "mdd-header-inspection-dev-v1".to_owned(),
        sql_dialect: None,
        session_id: None,
        snapshot_id: Some(snapshot.manifest().snapshot_id.clone()),
        catalog_epoch: None,
        query_id: None,
        operation_status: OperationStatus::Ok,
        coverage: Coverage {
            scope_id,
            input: Completeness::Complete,
            facts: Completeness::Complete,
            required_layers: vec!["inventory".to_owned(), "dex_header".to_owned()],
            issues: vec![],
        },
        execution: Execution { complete: true },
        response: Response {
            schema_id: Some("mdd.rows.dex-headers.v1".to_owned()),
            emitted_rows: count,
            total_rows: Some(count),
            total_rows_exact: true,
            more_available: false,
            truncated: false,
            next_cursor: None,
        },
        data: data.as_object().cloned(),
        error: None,
        warnings: vec![],
    };
    envelope.validate()?;
    serde_json::to_value(envelope)
        .map_err(|error| MddError::new(ErrorCode::InternalFault, "inspect", error.to_string()))
}
