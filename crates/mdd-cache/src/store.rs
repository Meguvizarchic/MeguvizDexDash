//! Atomic `mdd-index/1` publication, concurrency locking, corruption isolation & recovery.

use crate::cas::CasStore;
use crate::facts_codec::{
    CachedFactsPayload, CachedRawCodeMethod, CachedRelationTable, NegativeFindingRecord,
    SnapshotAndInventorySection,
};
use crate::format::{
    CACHE_FORMAT_ID, CoverageSummary, FLAG_STANDALONE_BLOBS, FLAG_THIN_EXTERNAL_CAS, IndexManifest,
    RawSectionInput, SECTION_FLAG_REQUIRED, SectionKind, SourceBlobRef, encode_index_image,
    verify_and_decode_image,
};
use crate::guard::PersistScopeCheck;
use crate::key::{CacheMode, FactCacheKeySpec, SemanticsIdentity};
use mdd_input::{
    archive::ArchiveInventory,
    snapshot::{CaptureLimits, InputSpec, Snapshot},
};
use mdd_types::{
    Coverage, DecimalU64, ErrorCode, Execution, MddError, MddResult, Response, opaque_id, sha256,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheOpenPolicy {
    ReadWrite,
    CacheOnly,
    Bypass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheAccessOutcome {
    HitWarm,
    BuiltCold,
    RebuiltCorrupt,
    RebuiltStale,
    Bypassed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CacheAccessReport {
    pub outcome: CacheAccessOutcome,
    pub canonical_cache_key: String,
    pub mode: CacheMode,
    pub index_path: String,
    pub reason: String,
    pub prior_error_code: Option<ErrorCode>,
    pub elapsed_ms: DecimalU64,
    pub source_blobs_reused: usize,
    pub runtime_snapshot_id: String,
}

#[derive(Clone, Debug)]
pub struct LoadedCache {
    pub manifest: IndexManifest,
    pub payload: CachedFactsPayload,
    /// Verified captured source bytes keyed by `content_id` (`sha256:<hex>`).
    pub verified_source_blobs: BTreeMap<String, Vec<u8>>,
    /// Fresh runtime snapshot identifier minted at open time (never reused across processes).
    pub runtime_snapshot_id: String,
}

#[derive(Clone, Debug)]
pub struct CacheStore {
    root: PathBuf,
    cas: CasStore,
}

struct FileLockGuard {
    lock_path: PathBuf,
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

impl CacheStore {
    pub fn new(root: impl AsRef<Path>) -> MddResult<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("index")).map_err(|error| {
            MddError::new(ErrorCode::InternalFault, "cache.store", error.to_string())
        })?;
        fs::create_dir_all(root.join("locks")).map_err(|error| {
            MddError::new(ErrorCode::InternalFault, "cache.store", error.to_string())
        })?;
        let cas = CasStore::new(&root);
        Ok(Self { root, cas })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn cas(&self) -> &CasStore {
        &self.cas
    }

    pub fn index_path(&self, canonical_cache_key: &str, mode: CacheMode) -> PathBuf {
        self.root
            .join("index")
            .join(format!("{canonical_cache_key}.{}.mddidx", mode.as_str()))
    }

    fn lock_path(&self, canonical_cache_key: &str, mode: CacheMode) -> PathBuf {
        self.root
            .join("locks")
            .join(format!("{canonical_cache_key}.{}.lock", mode.as_str()))
    }

    fn acquire_lock(
        &self,
        canonical_cache_key: &str,
        mode: CacheMode,
        timeout: Duration,
    ) -> MddResult<FileLockGuard> {
        let lock_path = self.lock_path(canonical_cache_key, mode);
        let started = Instant::now();
        loop {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(mut file) => {
                    let _ = writeln!(file, "pid={}", std::process::id());
                    let _ = file.sync_all();
                    return Ok(FileLockGuard { lock_path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if started.elapsed() >= timeout {
                        return Err(MddError::new(
                            ErrorCode::DeadlineExceeded,
                            "cache.lock",
                            format!(
                                "timed out waiting for cache build lock {}",
                                lock_path.display()
                            ),
                        ));
                    }
                    thread::sleep(Duration::from_millis(15));
                }
                Err(error) => {
                    return Err(MddError::new(
                        ErrorCode::InternalFault,
                        "cache.lock",
                        error.to_string(),
                    ));
                }
            }
        }
    }

    /// Reclaim stale crash temporary files (`*.tmp.*`) without ever promoting them as cache hits.
    pub fn reclaim_stale_temps(&self) -> MddResult<usize> {
        let mut removed = 0usize;
        let index_dir = self.root.join("index");
        if index_dir.is_dir() {
            for entry in fs::read_dir(&index_dir).map_err(|error| {
                MddError::new(ErrorCode::InternalFault, "cache.store", error.to_string())
            })? {
                let entry = entry.map_err(|error| {
                    MddError::new(ErrorCode::InternalFault, "cache.store", error.to_string())
                })?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.contains(".tmp.") && fs::remove_file(entry.path()).is_ok() {
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }

    /// List published `.mddidx` candidates (strictly ignoring `.tmp.*`, `.lock`, `.corrupt.*`).
    pub fn list_published_indices(&self) -> MddResult<Vec<PathBuf>> {
        let mut out = Vec::new();
        let index_dir = self.root.join("index");
        if !index_dir.is_dir() {
            return Ok(out);
        }
        for entry in fs::read_dir(&index_dir).map_err(|error| {
            MddError::new(ErrorCode::InternalFault, "cache.store", error.to_string())
        })? {
            let entry = entry.map_err(|error| {
                MddError::new(ErrorCode::InternalFault, "cache.store", error.to_string())
            })?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".mddidx")
                && !name.starts_with('.')
                && !name.contains(".tmp.")
                && !name.contains(".corrupt.")
                && path.is_file()
            {
                out.push(path);
            }
        }
        out.sort();
        Ok(out)
    }

    /// Open and fully verify an existing `.mddidx` file against optional expected source specs and
    /// expected canonical key.
    pub fn open_verified_file(
        &self,
        path: &Path,
        expected_key: Option<&str>,
        expected_sources: Option<&[Vec<u8>]>,
    ) -> MddResult<LoadedCache> {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.contains(".tmp.") {
            return Err(MddError::new(
                ErrorCode::CacheCorrupt,
                "cache.store",
                "refusing to treat incomplete temporary file as cache hit",
            )
            .detail("reason", "TEMP_FILE_IGNORED"));
        }
        if !path.is_file() {
            return Err(MddError::new(
                ErrorCode::StaleCache,
                "cache.store",
                format!("cache index missing: {}", path.display()),
            )
            .detail("reason", "INDEX_MISSING"));
        }
        let bytes = fs::read(path).map_err(|error| {
            MddError::new(ErrorCode::CacheCorrupt, "cache.store", error.to_string())
        })?;
        let verified = verify_and_decode_image(&bytes)?;

        if let Some(expected) = expected_key
            && verified.manifest.canonical_cache_key != expected
        {
            return Err(MddError::new(
                ErrorCode::StaleCache,
                "cache.store",
                "cache index key disagrees with current input/semantic key",
            )
            .detail("reason", "KEY_MISMATCH")
            .detail("cached_key", verified.manifest.canonical_cache_key.clone())
            .detail("expected_key", expected.to_owned()));
        }

        if let Some(actual_inputs) = expected_sources {
            if actual_inputs.len() != verified.manifest.occurrences.len() {
                return Err(MddError::new(
                    ErrorCode::StaleCache,
                    "cache.store",
                    "cache occurrence count disagrees with current inputs",
                )
                .detail("reason", "OCCURRENCE_COUNT_MISMATCH"));
            }
            for (ordinal, (actual_bytes, cached_occ)) in actual_inputs
                .iter()
                .zip(verified.manifest.occurrences.iter())
                .enumerate()
            {
                let actual_id = format!("sha256:{}", sha256(actual_bytes));
                if actual_bytes.len() as u64 != cached_occ.byte_length
                    || actual_id != cached_occ.content_id
                {
                    return Err(MddError::new(
                        ErrorCode::StaleCache,
                        "cache.store",
                        format!("input occurrence {ordinal} content digest changed"),
                    )
                    .detail("reason", "SOURCE_CONTENT_CHANGED"));
                }
            }
        }

        let mut snap_inv: Option<SnapshotAndInventorySection> = None;
        let mut tables: Vec<CachedRelationTable> = Vec::new();
        let mut raw_code_methods: Vec<CachedRawCodeMethod> = Vec::new();
        let mut negative_findings: Vec<NegativeFindingRecord> = Vec::new();
        let mut embedded_blobs: Vec<&[u8]> = Vec::new();

        for sec in &verified.sections {
            match sec.kind {
                SectionKind::SnapshotAndInventory => {
                    let parsed: SnapshotAndInventorySection = serde_json::from_slice(sec.bytes)
                        .map_err(|error| {
                            MddError::new(ErrorCode::CacheCorrupt, "cache.store", error.to_string())
                        })?;
                    snap_inv = Some(parsed);
                }
                SectionKind::RelationRows => {
                    let parsed: Vec<CachedRelationTable> = serde_json::from_slice(sec.bytes)
                        .map_err(|error| {
                            MddError::new(ErrorCode::CacheCorrupt, "cache.store", error.to_string())
                        })?;
                    tables.extend(parsed);
                }
                SectionKind::RawCodeEvidence => {
                    let parsed: Vec<CachedRawCodeMethod> = serde_json::from_slice(sec.bytes)
                        .map_err(|error| {
                            MddError::new(ErrorCode::CacheCorrupt, "cache.store", error.to_string())
                        })?;
                    raw_code_methods.extend(parsed);
                }
                SectionKind::EmbeddedSourceBlob => {
                    embedded_blobs.push(sec.bytes);
                }
                SectionKind::NegativeFindings => {
                    let parsed: Vec<NegativeFindingRecord> = serde_json::from_slice(sec.bytes)
                        .map_err(|error| {
                            MddError::new(ErrorCode::CacheCorrupt, "cache.store", error.to_string())
                        })?;
                    negative_findings.extend(parsed);
                }
            }
        }

        let snap_inv = snap_inv.ok_or_else(|| {
            MddError::new(
                ErrorCode::CacheCorrupt,
                "cache.store",
                "missing SnapshotAndInventory section",
            )
        })?;
        let payload = CachedFactsPayload {
            snapshot_and_inventory: snap_inv,
            tables,
            raw_code_methods,
            negative_findings,
        };
        payload.verify()?;

        let mut verified_source_blobs = BTreeMap::new();
        for blob_ref in &verified.manifest.source_blobs {
            let data = if blob_ref.embedded {
                let idx = blob_ref.embedded_section_ordinal.ok_or_else(|| {
                    MddError::new(
                        ErrorCode::CacheCorrupt,
                        "cache.store",
                        "standalone source blob missing embedded section ordinal",
                    )
                })? as usize;
                let slice = embedded_blobs.get(idx).ok_or_else(|| {
                    MddError::new(
                        ErrorCode::CacheCorrupt,
                        "cache.store",
                        "embedded section ordinal out of range",
                    )
                })?;
                CasStore::verify_digest_slice(slice, &blob_ref.sha256, blob_ref.byte_length.0)?;
                slice.to_vec()
            } else {
                self.cas
                    .get_verified(&blob_ref.sha256, blob_ref.byte_length.0)?
            };
            verified_source_blobs.insert(blob_ref.content_id.clone(), data);
        }

        Ok(LoadedCache {
            manifest: verified.manifest,
            payload,
            verified_source_blobs,
            runtime_snapshot_id: opaque_id("snapshot")?,
        })
    }

    /// Persist a verified, complete cache entry atomically via lockfile -> private `.tmp` ->
    /// self-verify -> `sync_all` -> atomic rename.
    ///
    /// Refuses to write if `coverage`/`execution`/`response` show partial, truncated, paged,
    /// or errored state.
    #[allow(clippy::too_many_arguments)]
    pub fn persist_atomic(
        &self,
        key_spec: &FactCacheKeySpec,
        mode: CacheMode,
        snapshot: &Snapshot,
        payload: &CachedFactsPayload,
        coverage: &Coverage,
        execution: &Execution,
        response: &Response,
        operation_error: Option<&MddError>,
        build_reason: &str,
        build_duration_ms: u64,
    ) -> MddResult<(PathBuf, IndexManifest, usize)> {
        let canonical_key = key_spec.canonical_cache_key()?;
        let lock = self.acquire_lock(&canonical_key, mode, Duration::from_secs(15))?;
        self.persist_atomic_locked(
            &lock,
            key_spec,
            mode,
            snapshot,
            payload,
            coverage,
            execution,
            response,
            operation_error,
            build_reason,
            build_duration_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_atomic_locked(
        &self,
        _lock: &FileLockGuard,
        key_spec: &FactCacheKeySpec,
        mode: CacheMode,
        snapshot: &Snapshot,
        payload: &CachedFactsPayload,
        coverage: &Coverage,
        execution: &Execution,
        response: &Response,
        operation_error: Option<&MddError>,
        build_reason: &str,
        build_duration_ms: u64,
    ) -> MddResult<(PathBuf, IndexManifest, usize)> {
        PersistScopeCheck::from_envelope_parts(coverage, execution, response, operation_error)?;
        payload.verify()?;

        let canonical_key = key_spec.canonical_cache_key()?;
        let target_path = self.index_path(&canonical_key, mode);

        let mut source_blobs = Vec::new();
        let mut unique_blobs: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for src in snapshot.sources() {
            unique_blobs
                .entry(src.identity().content_id.clone())
                .or_insert_with(|| src.bytes().to_vec());
        }

        let mut embedded_buffers: Vec<Vec<u8>> = Vec::new();
        let mut reused_cas = 0usize;
        for (content_id, bytes) in &unique_blobs {
            let digest = sha256(bytes);
            match mode {
                CacheMode::Standalone => {
                    let ordinal = u32::try_from(embedded_buffers.len()).map_err(|_| {
                        MddError::new(
                            ErrorCode::QuotaExceeded,
                            "cache.store",
                            "too many embedded blobs",
                        )
                    })?;
                    embedded_buffers.push(bytes.clone());
                    source_blobs.push(SourceBlobRef {
                        content_id: content_id.clone(),
                        sha256: digest,
                        byte_length: DecimalU64(bytes.len() as u64),
                        embedded: true,
                        embedded_section_ordinal: Some(ordinal),
                        cas_relative_path: None,
                    });
                }
                CacheMode::Thin => {
                    let (cas_digest, rel_path, reused) = self.cas.put_verified(bytes)?;
                    if reused {
                        reused_cas += 1;
                    }
                    source_blobs.push(SourceBlobRef {
                        content_id: content_id.clone(),
                        sha256: cas_digest,
                        byte_length: DecimalU64(bytes.len() as u64),
                        embedded: false,
                        embedded_section_ordinal: None,
                        cas_relative_path: Some(rel_path),
                    });
                }
            }
        }

        let snap_inv_bytes = serde_json::to_vec(&payload.snapshot_and_inventory)
            .map_err(|e| MddError::new(ErrorCode::InternalFault, "cache.store", e.to_string()))?;
        let tables_bytes = serde_json::to_vec(&payload.tables)
            .map_err(|e| MddError::new(ErrorCode::InternalFault, "cache.store", e.to_string()))?;
        let raw_bytes = serde_json::to_vec(&payload.raw_code_methods)
            .map_err(|e| MddError::new(ErrorCode::InternalFault, "cache.store", e.to_string()))?;
        let neg_bytes = serde_json::to_vec(&payload.negative_findings)
            .map_err(|e| MddError::new(ErrorCode::InternalFault, "cache.store", e.to_string()))?;

        let table_rows_total: u64 = payload.tables.iter().map(|t| t.row_count.0).sum();
        let mut raw_sections = vec![
            RawSectionInput {
                kind: SectionKind::SnapshotAndInventory,
                flags: SECTION_FLAG_REQUIRED,
                schema_id: "mdd.cache.snapshot_inventory.v1",
                name: "snapshot_and_inventory",
                row_count: Some(payload.snapshot_and_inventory.occurrence_summaries.len() as u64),
                data: &snap_inv_bytes,
            },
            RawSectionInput {
                kind: SectionKind::RelationRows,
                flags: SECTION_FLAG_REQUIRED,
                schema_id: "mdd.cache.relations.v1",
                name: "relation_rows",
                row_count: Some(table_rows_total),
                data: &tables_bytes,
            },
            RawSectionInput {
                kind: SectionKind::RawCodeEvidence,
                flags: SECTION_FLAG_REQUIRED,
                schema_id: "mdd.cache.raw_code_evidence.v1",
                name: "raw_code_evidence",
                row_count: Some(payload.raw_code_methods.len() as u64),
                data: &raw_bytes,
            },
            RawSectionInput {
                kind: SectionKind::NegativeFindings,
                flags: SECTION_FLAG_REQUIRED,
                schema_id: "mdd.cache.negative_findings.v1",
                name: "negative_findings",
                row_count: Some(payload.negative_findings.len() as u64),
                data: &neg_bytes,
            },
        ];
        for blob in &embedded_buffers {
            raw_sections.push(RawSectionInput {
                kind: SectionKind::EmbeddedSourceBlob,
                flags: SECTION_FLAG_REQUIRED,
                schema_id: "mdd.cache.source_blob.v1",
                name: "embedded_source_blob",
                row_count: Some(1),
                data: blob,
            });
        }

        let mut compat_versions = BTreeMap::new();
        compat_versions.insert(
            "fact_schema".to_owned(),
            key_spec.semantics.fact_schema_version.clone(),
        );
        compat_versions.insert(
            "parser_semantics".to_owned(),
            key_spec.semantics.parser_semantics_version.clone(),
        );
        compat_versions.insert(
            "text_semantics".to_owned(),
            key_spec.semantics.text_semantics_version.clone(),
        );
        compat_versions.insert(
            "instruction_semantics".to_owned(),
            key_spec.semantics.instruction_semantics_version.clone(),
        );

        let manifest_template = IndexManifest {
            cache_format: CACHE_FORMAT_ID.to_owned(),
            engine_version: env!("CARGO_PKG_VERSION").to_owned(),
            mode,
            semantics: key_spec.semantics.clone(),
            canonical_cache_key: canonical_key.clone(),
            snapshot_content_key: snapshot.manifest().snapshot_content_key.clone(),
            section_table_sha256: String::new(),
            selection_policy: key_spec.semantics.selection_policy.clone(),
            occurrences: key_spec.occurrences.clone(),
            source_blobs,
            sections: Vec::new(),
            completed_layers: coverage.required_layers.clone(),
            coverage: CoverageSummary {
                scope_id: coverage.scope_id.clone(),
                input_complete: true,
                facts_complete: true,
                execution_complete: true,
                required_layers: coverage.required_layers.clone(),
            },
            validation_policy: key_spec.semantics.validator_policy.clone(),
            applicable_formats: vec!["standard-dex".to_owned(), "apk-zip".to_owned()],
            required_capabilities: vec!["facts.metadata".to_owned(), "facts.complete".to_owned()],
            compat_versions,
            build_reason: build_reason.to_owned(),
            build_duration_ms: DecimalU64(build_duration_ms),
        };

        let header_flags = match mode {
            CacheMode::Standalone => FLAG_STANDALONE_BLOBS,
            CacheMode::Thin => FLAG_THIN_EXTERNAL_CAS,
        };
        let image = encode_index_image(header_flags, &manifest_template, &raw_sections)?;
        let published_manifest = verify_and_decode_image(&image)?.manifest;

        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce)
            .map_err(|e| MddError::new(ErrorCode::InternalFault, "cache.store", e.to_string()))?;
        let nonce_hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let temp_path = self.root.join("index").join(format!(
            ".{canonical_key}.{}.tmp.{}.{nonce_hex}",
            mode.as_str(),
            std::process::id()
        ));

        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .map_err(|error| {
                    MddError::new(ErrorCode::InternalFault, "cache.store", error.to_string())
                })?;
            if let Err(error) = file.write_all(&image).and_then(|_| file.sync_all()) {
                drop(file);
                let _ = fs::remove_file(&temp_path);
                return Err(MddError::new(
                    ErrorCode::InternalFault,
                    "cache.store",
                    error.to_string(),
                ));
            }
        }

        // Verify written staging file bytes from disk before atomic publish.
        let temp_disk_bytes = fs::read(&temp_path).map_err(|error| {
            let _ = fs::remove_file(&temp_path);
            MddError::new(ErrorCode::InternalFault, "cache.store", error.to_string())
        })?;
        let staged = match verify_and_decode_image(&temp_disk_bytes) {
            Ok(verified) => verified,
            Err(error) => {
                let _ = fs::remove_file(&temp_path);
                return Err(error);
            }
        };
        if staged.manifest.canonical_cache_key != canonical_key {
            let _ = fs::remove_file(&temp_path);
            return Err(MddError::new(
                ErrorCode::InternalFault,
                "cache.store",
                "staged index canonical key mismatch",
            ));
        }

        if target_path.exists() {
            // Quarantine existing target (if corrupt/stale) before replace to avoid half-state on Windows.
            let quarantine = target_path.with_extension(format!("mddidx.corrupt.{nonce_hex}"));
            let _ = fs::rename(&target_path, &quarantine);
            match fs::rename(&temp_path, &target_path) {
                Ok(()) => {
                    let _ = fs::remove_file(&quarantine);
                }
                Err(error) => {
                    let _ = fs::rename(&quarantine, &target_path);
                    let _ = fs::remove_file(&temp_path);
                    return Err(MddError::new(
                        ErrorCode::InternalFault,
                        "cache.store",
                        error.to_string(),
                    ));
                }
            }
        } else {
            fs::rename(&temp_path, &target_path).map_err(|error| {
                let _ = fs::remove_file(&temp_path);
                MddError::new(ErrorCode::InternalFault, "cache.store", error.to_string())
            })?;
        }

        Ok((target_path, published_manifest, reused_cas))
    }

    /// Coordinate read/build/recover across policies (`ReadWrite`, `CacheOnly`, `Bypass`).
    /// Note that `build_fn` is only invoked when cache miss, corruption, or staleness occurs.
    #[allow(clippy::too_many_arguments)]
    pub fn open_or_build<F>(
        &self,
        key_spec: &FactCacheKeySpec,
        mode: CacheMode,
        policy: CacheOpenPolicy,
        inputs: &[InputSpec],
        semantics: &SemanticsIdentity,
        mut build_fn: F,
    ) -> MddResult<(CacheAccessReport, LoadedCache)>
    where
        F: FnMut(
            &Snapshot,
            &[ArchiveInventory],
        ) -> MddResult<(CachedFactsPayload, Coverage, Execution, Response)>,
    {
        let _ = semantics;
        let started = Instant::now();
        let canonical_key = key_spec.canonical_cache_key()?;
        let index_path = self.index_path(&canonical_key, mode);
        let _ = self.reclaim_stale_temps();

        if policy == CacheOpenPolicy::Bypass {
            let snapshot = Snapshot::capture(inputs, CaptureLimits::default())?;
            let inventories = build_inventories(&snapshot)?;
            let (payload, coverage, execution, response) = build_fn(&snapshot, &inventories)?;
            PersistScopeCheck::from_envelope_parts(&coverage, &execution, &response, None)?;
            let loaded = LoadedCache {
                manifest: synthetic_manifest(key_spec, mode, &snapshot, &coverage)?,
                payload,
                verified_source_blobs: collect_source_blobs(&snapshot),
                runtime_snapshot_id: snapshot.manifest().snapshot_id.clone(),
            };
            let elapsed_ms = started.elapsed().as_millis() as u64;
            return Ok((
                CacheAccessReport {
                    outcome: CacheAccessOutcome::Bypassed,
                    canonical_cache_key: canonical_key,
                    mode,
                    index_path: index_path.to_string_lossy().into_owned(),
                    reason: "cache_bypass_policy".to_owned(),
                    prior_error_code: None,
                    elapsed_ms: DecimalU64(elapsed_ms),
                    source_blobs_reused: 0,
                    runtime_snapshot_id: loaded.runtime_snapshot_id.clone(),
                },
                loaded,
            ));
        }

        match self.open_verified_file(&index_path, Some(&canonical_key), None) {
            Ok(loaded) => {
                let elapsed_ms = started.elapsed().as_millis() as u64;
                Ok((
                    CacheAccessReport {
                        outcome: CacheAccessOutcome::HitWarm,
                        canonical_cache_key: canonical_key,
                        mode,
                        index_path: index_path.to_string_lossy().into_owned(),
                        reason: "warm_hit_verified".to_owned(),
                        prior_error_code: None,
                        elapsed_ms: DecimalU64(elapsed_ms),
                        source_blobs_reused: loaded.verified_source_blobs.len(),
                        runtime_snapshot_id: loaded.runtime_snapshot_id.clone(),
                    },
                    loaded,
                ))
            }
            Err(probe_err) => {
                if policy == CacheOpenPolicy::CacheOnly {
                    return Err(probe_err);
                }

                // Serialize concurrent builders for the same canonical key and double-check
                // whether an earlier lock holder already finished publishing it.
                let _build_guard =
                    self.acquire_lock(&canonical_key, mode, Duration::from_secs(15))?;
                if let Ok(loaded) = self.open_verified_file(&index_path, Some(&canonical_key), None)
                {
                    let elapsed_ms = started.elapsed().as_millis() as u64;
                    return Ok((
                        CacheAccessReport {
                            outcome: CacheAccessOutcome::HitWarm,
                            canonical_cache_key: canonical_key,
                            mode,
                            index_path: index_path.to_string_lossy().into_owned(),
                            reason: "warm_hit_after_lock_wait".to_owned(),
                            prior_error_code: Some(probe_err.code),
                            elapsed_ms: DecimalU64(elapsed_ms),
                            source_blobs_reused: loaded.verified_source_blobs.len(),
                            runtime_snapshot_id: loaded.runtime_snapshot_id.clone(),
                        },
                        loaded,
                    ));
                }

                let index_existed = index_path.exists();
                let (outcome, prior_error_code, reason) = if !index_existed {
                    (CacheAccessOutcome::BuiltCold, None, "cold_build".to_owned())
                } else if probe_err.code == ErrorCode::CacheCorrupt {
                    (
                        CacheAccessOutcome::RebuiltCorrupt,
                        Some(probe_err.code),
                        format!("rebuilt_after_corruption: {}", probe_err.message),
                    )
                } else {
                    (
                        CacheAccessOutcome::RebuiltStale,
                        Some(probe_err.code),
                        format!("rebuilt_after_stale: {}", probe_err.message),
                    )
                };

                let snapshot = Snapshot::capture(inputs, CaptureLimits::default())?;
                let inventories = build_inventories(&snapshot)?;
                let (payload, coverage, execution, response) = build_fn(&snapshot, &inventories)?;
                let build_ms = started.elapsed().as_millis() as u64;
                let (published_path, _, reused_cas) = self.persist_atomic_locked(
                    &_build_guard,
                    key_spec,
                    mode,
                    &snapshot,
                    &payload,
                    &coverage,
                    &execution,
                    &response,
                    None,
                    &reason,
                    build_ms,
                )?;
                drop(_build_guard);
                let loaded =
                    self.open_verified_file(&published_path, Some(&canonical_key), None)?;
                let elapsed_ms = started.elapsed().as_millis() as u64;
                Ok((
                    CacheAccessReport {
                        outcome,
                        canonical_cache_key: canonical_key,
                        mode,
                        index_path: published_path.to_string_lossy().into_owned(),
                        reason,
                        prior_error_code,
                        elapsed_ms: DecimalU64(elapsed_ms),
                        source_blobs_reused: reused_cas,
                        runtime_snapshot_id: loaded.runtime_snapshot_id.clone(),
                    },
                    loaded,
                ))
            }
        }
    }
}

fn build_inventories(snapshot: &Snapshot) -> MddResult<Vec<ArchiveInventory>> {
    let mut out = Vec::with_capacity(snapshot.sources().len());
    for source in snapshot.sources() {
        out.push(ArchiveInventory::build(
            source,
            mdd_input::archive::InventoryPolicy {
                require_dex: false,
                hold_dex_bytes: false,
                ..Default::default()
            },
            Default::default(),
        )?);
    }
    Ok(out)
}

fn collect_source_blobs(snapshot: &Snapshot) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for src in snapshot.sources() {
        out.entry(src.identity().content_id.clone())
            .or_insert_with(|| src.bytes().to_vec());
    }
    out
}

fn synthetic_manifest(
    key_spec: &FactCacheKeySpec,
    mode: CacheMode,
    snapshot: &Snapshot,
    coverage: &Coverage,
) -> MddResult<IndexManifest> {
    let mut compat = BTreeMap::new();
    compat.insert(
        "fact_schema".to_owned(),
        key_spec.semantics.fact_schema_version.clone(),
    );
    Ok(IndexManifest {
        cache_format: CACHE_FORMAT_ID.to_owned(),
        engine_version: env!("CARGO_PKG_VERSION").to_owned(),
        mode,
        semantics: key_spec.semantics.clone(),
        canonical_cache_key: key_spec.canonical_cache_key()?,
        snapshot_content_key: snapshot.manifest().snapshot_content_key.clone(),
        section_table_sha256: sha256(b""),
        selection_policy: key_spec.semantics.selection_policy.clone(),
        occurrences: key_spec.occurrences.clone(),
        source_blobs: Vec::new(),
        sections: Vec::new(),
        completed_layers: coverage.required_layers.clone(),
        coverage: CoverageSummary {
            scope_id: coverage.scope_id.clone(),
            input_complete: true,
            facts_complete: true,
            execution_complete: true,
            required_layers: coverage.required_layers.clone(),
        },
        validation_policy: key_spec.semantics.validator_policy.clone(),
        applicable_formats: vec!["standard-dex".to_owned(), "apk-zip".to_owned()],
        required_capabilities: vec!["facts.metadata".to_owned()],
        compat_versions: compat,
        build_reason: "bypass".to_owned(),
        build_duration_ms: DecimalU64(0),
    })
}
