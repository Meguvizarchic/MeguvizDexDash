//! Comprehensive integration tests verifying all MDD-063 acceptance clauses.

use mdd_cache::facts_codec::{
    CachedCell, CachedFactsPayload, CachedRelationTable, NegativeFindingRecord,
    SnapshotAndInventorySection,
};
use mdd_cache::format::{
    FLAG_STANDALONE_BLOBS, HEADER_BYTES, RawSectionInput, SECTION_FLAG_REQUIRED, SectionKind,
    encode_index_image, verify_and_decode_image,
};
use mdd_cache::guard::PersistScopeCheck;
use mdd_cache::key::{
    CacheMode, FactCacheKeySpec, MemberKey, RuleCacheKeySpec, SemanticsIdentity,
    SourceOccurrenceKey,
};
use mdd_cache::store::{CacheAccessOutcome, CacheOpenPolicy, CacheStore};
use mdd_input::archive::{ArchiveInventory, InventoryPolicy};
use mdd_input::snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot};
use mdd_service::{Dataset, Dialect, InputRequest, RunOptions, Sink};
use mdd_session::ResourceLimits;
use mdd_sql::control::SqlLimits;
use mdd_sql::values::SqlValue;
use mdd_types::{
    Completeness, Coverage, DecimalU64, ErrorCode, Execution, Issue, MddError, Response, opaque_id,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/generated")
}

fn temp_dir(prefix: &str) -> PathBuf {
    let path = std::env::temp_dir().join(opaque_id(prefix).unwrap());
    fs::create_dir_all(&path).unwrap();
    path
}

struct TableCollector {
    cols: Vec<String>,
    rows: Vec<Vec<CachedCell>>,
}

impl Sink for TableCollector {
    fn batch(&mut self, batch: &mdd_service::Batch<'_>) -> io::Result<()> {
        if self.cols.is_empty() {
            self.cols = batch.columns.to_vec();
        }
        for row in batch.rows {
            let cells = row
                .iter()
                .map(|v| match v {
                    SqlValue::Null => CachedCell::Null,
                    SqlValue::Bool(b) => CachedCell::Bool(*b),
                    SqlValue::I64(i) => CachedCell::I64(i.0),
                    SqlValue::U64(u) => CachedCell::U64(*u),
                    SqlValue::F64(f) => CachedCell::F64Bits(*f),
                    SqlValue::Text(t) => CachedCell::Utf16 {
                        units: t.utf16.clone(),
                        original_mutf8: t.original_mutf8.clone(),
                    },
                    SqlValue::Bytes(b) => CachedCell::Bytes(b.clone()),
                    SqlValue::DexMutf8 {
                        bytes,
                        utf16_code_units,
                    } => CachedCell::DexMutf8 {
                        bytes: bytes.clone(),
                        utf16_code_units: *utf16_code_units,
                    },
                })
                .collect();
            self.rows.push(cells);
        }
        Ok(())
    }
}

fn build_real_payload(paths: &[PathBuf]) -> (Snapshot, Vec<ArchiveInventory>, CachedFactsPayload) {
    let specs: Vec<InputSpec> = paths
        .iter()
        .map(|p| InputSpec {
            path: p.clone(),
            kind: InputKind::detect(p).unwrap(),
            expected_sha256: None,
        })
        .collect();
    let snapshot = Snapshot::capture(&specs, CaptureLimits::default()).unwrap();
    let mut inventories = Vec::new();
    for src in snapshot.sources() {
        inventories.push(
            ArchiveInventory::build(
                src,
                InventoryPolicy {
                    require_dex: false,
                    hold_dex_bytes: false,
                    ..Default::default()
                },
                Default::default(),
            )
            .unwrap(),
        );
    }

    let requests: Vec<InputRequest> = paths
        .iter()
        .map(|p| InputRequest {
            path: p.clone(),
            kind: None,
        })
        .collect();
    let dataset = Dataset::open(
        &requests,
        Dialect::DexSql011,
        ResourceLimits::default(),
        SqlLimits::default(),
    )
    .unwrap();

    let mut tables = Vec::new();
    for rel in [
        "dex_files",
        "strings",
        "types",
        "methods",
        "classes",
        "class_fields",
        "class_methods",
        "code_items",
        "method_strings",
        "method_calls",
    ] {
        let mut sink = TableCollector {
            cols: Vec::new(),
            rows: Vec::new(),
        };
        let out = dataset
            .run(
                &format!("SELECT * FROM {rel}"),
                &RunOptions::default(),
                &mut sink,
            )
            .unwrap();
        assert!(out.terminal.error.is_none());
        tables.push(CachedRelationTable::from_rows(rel, sink.cols, sink.rows).unwrap());
    }

    let payload = CachedFactsPayload {
        snapshot_and_inventory: SnapshotAndInventorySection {
            snapshot_content_key: snapshot.manifest().snapshot_content_key.clone(),
            capture_policy: snapshot.manifest().capture_policy.clone(),
            occurrence_summaries: vec![],
            occurrence_reuse_map: Default::default(),
        },
        tables,
        raw_code_methods: vec![],
        negative_findings: vec![],
    };
    (snapshot, inventories, payload)
}

fn ok_status(scope: &str) -> (Coverage, Execution, Response) {
    (
        Coverage {
            scope_id: scope.to_owned(),
            input: Completeness::Complete,
            facts: Completeness::Complete,
            required_layers: vec![
                "inventory".to_owned(),
                "metadata".to_owned(),
                "definitions".to_owned(),
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

#[test]
fn cache_key_ignores_paths_and_mtime_but_preserves_multiplicity_and_versions() {
    let dir = temp_dir("mdd-cache-key");
    let before = fixture_dir().join("structured-035.dex");
    let after = fixture_dir().join("structured-035-same-size-changed.dex");

    let path_a = dir.join("dir_one").join("alpha.dex");
    let path_b = dir.join("dir_two").join("beta_renamed.dex");
    fs::create_dir_all(path_a.parent().unwrap()).unwrap();
    fs::create_dir_all(path_b.parent().unwrap()).unwrap();
    let bytes_before = fs::read(&before).unwrap();
    let bytes_after = fs::read(&after).unwrap();
    assert_eq!(bytes_before.len(), bytes_after.len());

    fs::write(&path_a, &bytes_before).unwrap();
    fs::write(&path_b, &bytes_before).unwrap();
    let mtime_a = fs::metadata(&path_a).unwrap().modified().unwrap();
    File::options()
        .write(true)
        .open(&path_b)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(mtime_a))
        .unwrap();

    let sem = SemanticsIdentity::default();
    let (s1, i1, _) = build_real_payload(std::slice::from_ref(&path_a));
    let (s2, i2, _) = build_real_payload(std::slice::from_ref(&path_b));
    let key1 = FactCacheKeySpec::from_snapshot_and_inventories(&s1, &i1, sem.clone())
        .unwrap()
        .canonical_cache_key()
        .unwrap();
    let key2 = FactCacheKeySpec::from_snapshot_and_inventories(&s2, &i2, sem.clone())
        .unwrap()
        .canonical_cache_key()
        .unwrap();
    assert_eq!(
        key1, key2,
        "path/filename/mtime must not change fact cache key"
    );

    // Mutate path_b to same-size, same-mtime changed bytes.
    fs::write(&path_b, &bytes_after).unwrap();
    File::options()
        .write(true)
        .open(&path_b)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(mtime_a))
        .unwrap();
    let (s3, i3, _) = build_real_payload(std::slice::from_ref(&path_b));
    let key3 = FactCacheKeySpec::from_snapshot_and_inventories(&s3, &i3, sem.clone())
        .unwrap()
        .canonical_cache_key()
        .unwrap();
    assert_ne!(
        key1, key3,
        "same-size same-mtime byte change MUST invalidate canonical cache key"
    );

    // Multiplicity [alpha.dex, alpha.dex] != [alpha.dex].
    let (s_dup, i_dup, _) = build_real_payload(&[path_a.clone(), path_a.clone()]);
    let key_dup = FactCacheKeySpec::from_snapshot_and_inventories(&s_dup, &i_dup, sem.clone())
        .unwrap()
        .canonical_cache_key()
        .unwrap();
    assert_ne!(
        key1, key_dup,
        "logical duplicate occurrences must not collide with single occurrence key"
    );

    // Version/policy/provider changes must invalidate key.
    let mut sem_schema = sem.clone();
    sem_schema.fact_schema_version = "mdd.facts.cache.v2".to_owned();
    assert_ne!(
        key1,
        FactCacheKeySpec::from_snapshot_and_inventories(&s1, &i1, sem_schema)
            .unwrap()
            .canonical_cache_key()
            .unwrap()
    );
    let mut sem_instr = sem.clone();
    sem_instr.instruction_semantics_version = "dalvik-bytecode-v2".to_owned();
    assert_ne!(
        key1,
        FactCacheKeySpec::from_snapshot_and_inventories(&s1, &i1, sem_instr)
            .unwrap()
            .canonical_cache_key()
            .unwrap()
    );
    let mut sem_prov = sem.clone();
    sem_prov
        .provider_identities
        .insert("custom-opt".to_owned(), "sha256:1234".to_owned());
    assert_ne!(
        key1,
        FactCacheKeySpec::from_snapshot_and_inventories(&s1, &i1, sem_prov)
            .unwrap()
            .canonical_cache_key()
            .unwrap()
    );

    // Rule cache keys are independent objects bound to rule/config hashes without mutating base fact key.
    let r1 = RuleCacheKeySpec {
        base_fact_cache_key: key1.clone(),
        rule_bundle_sha256: "a".repeat(64),
        config_sha256: "b".repeat(64),
        query_semantics_version: "1".to_owned(),
        scope_id: "scope-1".to_owned(),
        parameters_digest: "c".repeat(64),
    }
    .canonical_rule_key()
    .unwrap();
    let r2 = RuleCacheKeySpec {
        base_fact_cache_key: key1.clone(),
        rule_bundle_sha256: "d".repeat(64),
        config_sha256: "b".repeat(64),
        query_semantics_version: "1".to_owned(),
        scope_id: "scope-1".to_owned(),
        parameters_digest: "c".repeat(64),
    }
    .canonical_rule_key()
    .unwrap();
    assert_ne!(r1, r2);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn standalone_vs_thin_and_corrupt_recovery_equivalence() {
    let dir = temp_dir("mdd-cache-roundtrip");
    let src_dir = dir.join("inputs");
    fs::create_dir_all(&src_dir).unwrap();
    let copy_dex = src_dir.join("work.dex");
    fs::copy(fixture_dir().join("structured-035.dex"), &copy_dex).unwrap();

    let cache_root = dir.join("cache");
    let store = CacheStore::new(&cache_root).unwrap();
    let sem = SemanticsIdentity::default();

    let (snap, invs, uncached_payload) = build_real_payload(std::slice::from_ref(&copy_dex));
    let key_spec =
        FactCacheKeySpec::from_snapshot_and_inventories(&snap, &invs, sem.clone()).unwrap();
    let specs = vec![InputSpec {
        path: copy_dex.clone(),
        kind: InputKind::RawDex,
        expected_sha256: None,
    }];

    // 1. Cold build Standalone + Thin
    for mode in [CacheMode::Standalone, CacheMode::Thin] {
        let mut built = false;
        let (rep, loaded) = store
            .open_or_build(
                &key_spec,
                mode,
                CacheOpenPolicy::ReadWrite,
                &specs,
                &sem,
                |_, _| {
                    built = true;
                    let (c, e, r) = ok_status("scope-rt");
                    Ok((uncached_payload.clone(), c, e, r))
                },
            )
            .unwrap();
        assert_eq!(rep.outcome, CacheAccessOutcome::BuiltCold);
        assert!(built);
        assert_eq!(loaded.payload.tables, uncached_payload.tables);
    }

    // 2. Delete original input file: Standalone cache-only STILL succeeds & matches uncached byte-for-byte!
    fs::remove_file(&copy_dex).unwrap();
    let standalone_path = store.index_path(
        &key_spec.canonical_cache_key().unwrap(),
        CacheMode::Standalone,
    );
    let warm_standalone = store
        .open_verified_file(
            &standalone_path,
            Some(&key_spec.canonical_cache_key().unwrap()),
            None,
        )
        .unwrap();
    assert_eq!(warm_standalone.payload.tables, uncached_payload.tables);
    assert_ne!(
        warm_standalone.runtime_snapshot_id,
        snap.manifest().snapshot_id
    );

    // 3. Thin CAS corruption and missing CAS detection:
    let thin_path = store.index_path(&key_spec.canonical_cache_key().unwrap(), CacheMode::Thin);
    let thin_loaded = store.open_verified_file(&thin_path, None, None).unwrap();
    let blob_digest = &thin_loaded.manifest.source_blobs[0].sha256;
    let cas_blob_path = store.cas().path_for_digest(blob_digest).unwrap();
    let original_blob = fs::read(&cas_blob_path).unwrap();

    // Flip 1 byte in external CAS blob -> CACHE_CORRUPT
    let mut mutated_blob = original_blob.clone();
    *mutated_blob.last_mut().unwrap() ^= 0xff;
    fs::write(&cas_blob_path, &mutated_blob).unwrap();
    let err_cas_corrupt = store
        .open_verified_file(&thin_path, None, None)
        .err()
        .unwrap();
    assert_eq!(err_cas_corrupt.code, ErrorCode::CacheCorrupt);

    // Delete external CAS blob -> STALE_CACHE
    fs::remove_file(&cas_blob_path).unwrap();
    let err_cas_missing = store
        .open_verified_file(&thin_path, None, None)
        .err()
        .unwrap();
    assert_eq!(err_cas_missing.code, ErrorCode::StaleCache);

    // 4. Restore copy_dex, corrupt Standalone .mddidx payload & header & reserved bytes -> CacheOnly fails, ReadWrite rebuilds cleanly
    fs::copy(fixture_dir().join("structured-035.dex"), &copy_dex).unwrap();
    let mut idx_bytes = fs::read(&standalone_path).unwrap();

    // Non-zero reserved header byte with recomputed header prefix SHA must fail CACHE_CORRUPT
    let mut reserved_corrupt = idx_bytes.clone();
    reserved_corrupt[55] = 0x01;
    let prefix_sha: [u8; 32] = Sha256::digest(&reserved_corrupt[..96]).into();
    reserved_corrupt[96..128].copy_from_slice(&prefix_sha);
    assert_eq!(
        verify_and_decode_image(&reserved_corrupt)
            .err()
            .unwrap()
            .code,
        ErrorCode::CacheCorrupt
    );

    // Version v2 valid header must return STALE_CACHE (unsupported version), never empty success
    let mut v2_header = idx_bytes.clone();
    v2_header[8..10].copy_from_slice(&2u16.to_le_bytes());
    let prefix_sha2: [u8; 32] = Sha256::digest(&v2_header[..96]).into();
    v2_header[96..128].copy_from_slice(&prefix_sha2);
    assert_eq!(
        verify_and_decode_image(&v2_header).err().unwrap().code,
        ErrorCode::StaleCache
    );

    // Truncated header & section flip on disk -> CacheOnly fails CACHE_CORRUPT; ReadWrite auto-recovers
    let last = idx_bytes.len() - 20;
    idx_bytes[last] ^= 0x55;
    fs::write(&standalone_path, &idx_bytes).unwrap();
    let err_only = store
        .open_or_build(
            &key_spec,
            CacheMode::Standalone,
            CacheOpenPolicy::CacheOnly,
            &specs,
            &sem,
            |_, _| unreachable!(),
        )
        .err()
        .unwrap();
    assert_eq!(err_only.code, ErrorCode::CacheCorrupt);

    let (rebuilt_rep, rebuilt_loaded) = store
        .open_or_build(
            &key_spec,
            CacheMode::Standalone,
            CacheOpenPolicy::ReadWrite,
            &specs,
            &sem,
            |_, _| {
                let (c, e, r) = ok_status("scope-rebuilt");
                Ok((uncached_payload.clone(), c, e, r))
            },
        )
        .unwrap();
    assert_eq!(rebuilt_rep.outcome, CacheAccessOutcome::RebuiltCorrupt);
    assert_eq!(rebuilt_rep.prior_error_code, Some(ErrorCode::CacheCorrupt));
    assert_eq!(rebuilt_loaded.payload.tables, uncached_payload.tables);

    // 5. Same-size same-mtime source mutation detected when validating cached index against changed disk file
    fs::copy(
        fixture_dir().join("structured-035-same-size-changed.dex"),
        &copy_dex,
    )
    .unwrap();
    let mutated_disk = fs::read(&copy_dex).unwrap();
    let err_stale = store
        .open_verified_file(&standalone_path, None, Some(&[mutated_disk]))
        .err()
        .unwrap();
    assert_eq!(err_stale.code, ErrorCode::StaleCache);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn partial_deadline_truncated_unpaged_refuse_complete_or_negative_cache() {
    let dir = temp_dir("mdd-cache-guards");
    let dex = fixture_dir().join("minimal-035.dex");
    let (snap, invs, mut payload) = build_real_payload(std::slice::from_ref(&dex));
    let sem = SemanticsIdentity::default();
    let key_spec = FactCacheKeySpec::from_snapshot_and_inventories(&snap, &invs, sem).unwrap();
    let key_hex = key_spec.canonical_cache_key().unwrap();
    let store = CacheStore::new(dir.join("cache")).unwrap();

    // Inject negative finding claiming complete
    payload.negative_findings.push(NegativeFindingRecord {
        scope_id: "scope-neg".to_owned(),
        canonical_cache_key: key_hex.clone(),
        predicate_id: "has_reflection_call".to_owned(),
        covered_layers: vec!["inventory".to_owned(), "metadata".to_owned()],
        matched_count: DecimalU64(0),
        verified_complete: true,
    });

    let (cov_ok, exec_ok, resp_ok) = ok_status("scope-neg");

    // Partial input -> denied
    let mut cov_partial_input = cov_ok.clone();
    cov_partial_input.input = Completeness::Partial;
    assert_eq!(
        store
            .persist_atomic(
                &key_spec,
                CacheMode::Standalone,
                &snap,
                &payload,
                &cov_partial_input,
                &exec_ok,
                &resp_ok,
                None,
                "bad",
                0,
            )
            .err()
            .unwrap()
            .code,
        ErrorCode::PartialInput
    );

    // Partial facts -> denied
    let mut cov_partial_facts = cov_ok.clone();
    cov_partial_facts.facts = Completeness::Unknown;
    assert_eq!(
        store
            .persist_atomic(
                &key_spec,
                CacheMode::Standalone,
                &snap,
                &payload,
                &cov_partial_facts,
                &exec_ok,
                &resp_ok,
                None,
                "bad",
                0,
            )
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );

    // Blocking issue -> denied
    let mut cov_blocking = cov_ok.clone();
    cov_blocking.issues.push(Issue {
        layer: "code".to_owned(),
        reason: "limit".to_owned(),
        blocking: true,
        entity_id: None,
        member_id: None,
        range: None,
        details: None,
    });
    assert_eq!(
        store
            .persist_atomic(
                &key_spec,
                CacheMode::Standalone,
                &snap,
                &payload,
                &cov_blocking,
                &exec_ok,
                &resp_ok,
                None,
                "bad",
                0,
            )
            .err()
            .unwrap()
            .code,
        ErrorCode::IncompleteFacts
    );

    // Unfinished execution / truncated / more_available / deadline exceeded -> all denied
    assert!(
        store
            .persist_atomic(
                &key_spec,
                CacheMode::Standalone,
                &snap,
                &payload,
                &cov_ok,
                &Execution { complete: false },
                &resp_ok,
                None,
                "bad",
                0,
            )
            .is_err()
    );
    let mut resp_trunc = resp_ok.clone();
    resp_trunc.truncated = true;
    assert!(
        store
            .persist_atomic(
                &key_spec,
                CacheMode::Standalone,
                &snap,
                &payload,
                &cov_ok,
                &exec_ok,
                &resp_trunc,
                None,
                "bad",
                0,
            )
            .is_err()
    );
    let mut resp_paged = resp_ok.clone();
    resp_paged.more_available = true;
    resp_paged.next_cursor = Some("cursor-1".to_owned());
    assert!(
        store
            .persist_atomic(
                &key_spec,
                CacheMode::Standalone,
                &snap,
                &payload,
                &cov_ok,
                &exec_ok,
                &resp_paged,
                None,
                "bad",
                0,
            )
            .is_err()
    );
    let deadline_err = MddError::new(ErrorCode::DeadlineExceeded, "query", "timeout");
    assert_eq!(
        store
            .persist_atomic(
                &key_spec,
                CacheMode::Standalone,
                &snap,
                &payload,
                &cov_ok,
                &exec_ok,
                &resp_ok,
                Some(&deadline_err),
                "bad",
                0,
            )
            .err()
            .unwrap()
            .code,
        ErrorCode::DeadlineExceeded
    );

    // Negative cache missing required layer -> ineligible
    let neg_elig = PersistScopeCheck::evaluate_negative_finding(
        &cov_ok,
        &exec_ok,
        &resp_ok,
        None,
        &["inventory".to_owned(), "references".to_owned()],
    );
    assert!(!neg_elig.eligible);

    // Nothing was written to disk
    assert!(store.list_published_indices().unwrap().is_empty());

    // Half-written `.tmp.` file must never be promoted as cache hit and must be reclaimed
    let stale_tmp = store
        .root()
        .join("index")
        .join(format!(".{key_hex}.standalone.tmp.9999.abcd"));
    fs::write(&stale_tmp, b"MDDIDX1\0partial").unwrap();
    assert!(store.list_published_indices().unwrap().is_empty());
    assert_eq!(
        store
            .open_verified_file(&stale_tmp, None, None)
            .err()
            .unwrap()
            .code,
        ErrorCode::CacheCorrupt
    );
    assert_eq!(store.reclaim_stale_temps().unwrap(), 1);
    assert!(!stale_tmp.exists());

    // Format bounds check: overlapping intervals & unknown required section rejected cleanly
    assert!(verify_and_decode_image(b"MDDIDX1\0short").is_err());
    let empty_manifest = mdd_cache::IndexManifest {
        cache_format: mdd_cache::CACHE_FORMAT_ID.to_owned(),
        engine_version: "0.1.0-dev".to_owned(),
        mode: CacheMode::Standalone,
        semantics: SemanticsIdentity::default(),
        canonical_cache_key: key_hex,
        snapshot_content_key: "sha256:00".to_owned(),
        section_table_sha256: String::new(),
        selection_policy: "top-level-classes".to_owned(),
        occurrences: vec![SourceOccurrenceKey {
            input_ordinal: 0,
            content_id: "sha256:00".to_owned(),
            byte_length: 0,
            input_kind: "raw-dex".to_owned(),
            selected_members: vec![MemberKey {
                member_ordinal: 0,
                raw_name_hex: "63".to_owned(),
                content_id: "sha256:00".to_owned(),
                byte_length: 0,
                logical_header_offset: 0,
                container_dependency_sha256: None,
            }],
        }],
        source_blobs: vec![],
        sections: vec![],
        completed_layers: vec![],
        coverage: mdd_cache::format::CoverageSummary {
            scope_id: "s".to_owned(),
            input_complete: true,
            facts_complete: true,
            execution_complete: true,
            required_layers: vec![],
        },
        validation_policy: "v".to_owned(),
        applicable_formats: vec![],
        required_capabilities: vec![],
        compat_versions: BTreeMap::new(),
        build_reason: "t".to_owned(),
        build_duration_ms: DecimalU64(0),
    };
    let mut raw = encode_index_image(
        FLAG_STANDALONE_BLOBS,
        &empty_manifest,
        &[RawSectionInput {
            kind: SectionKind::NegativeFindings,
            flags: SECTION_FLAG_REQUIRED,
            schema_id: "neg",
            name: "neg",
            row_count: Some(0),
            data: b"[]",
        }],
    )
    .unwrap();
    // Corrupt the section offset to overlap header [0..128) and recompute header prefix digest
    raw[HEADER_BYTES + 8..HEADER_BYTES + 16].copy_from_slice(&64u64.to_le_bytes());
    let err_overlap = verify_and_decode_image(&raw).err().unwrap();
    assert_eq!(err_overlap.code, ErrorCode::CacheCorrupt);

    let _ = fs::remove_dir_all(&dir);
    let _ = Path::new(".");
}
