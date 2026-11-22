use mdd_types::source_identity::SourceIdentity;
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult, content_id, opaque_id};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, btree_map::Entry as BTreeEntry},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

const SPILL_THRESHOLD_BYTES: u64 = 16 * 1024 * 1024;
const STREAM_CHUNK_BYTES: usize = 65536;

fn spill_snapshot_enabled() -> bool {
    std::env::var_os("MDD_OPT_SPILL_SNAPSHOT").as_deref() != Some(std::ffi::OsStr::new("0"))
}

#[derive(Clone, Copy, Debug)]
pub enum InputKind {
    RawDex,
    Apk,
}

impl InputKind {
    fn name(self) -> &'static str {
        match self {
            Self::RawDex => "raw-dex",
            Self::Apk => "apk-zip",
        }
    }
    /// Whether `bytes` starts with the magic this kind requires.
    ///
    /// Capture uses the same predicate, so detection and validation can never
    /// disagree about what a well-formed input looks like.
    fn matches_magic(self, bytes: &[u8]) -> bool {
        match self {
            Self::RawDex => bytes.starts_with(b"dex\n"),
            Self::Apk => {
                bytes.starts_with(b"PK\x03\x04")
                    || bytes.starts_with(b"PK\x05\x06")
                    || bytes.starts_with(b"PK\x06\x06")
            }
        }
    }
    /// Detect the input kind from its leading bytes.
    ///
    /// Callers previously guessed from the file extension, which mislabels
    /// extensionless or renamed inputs; the magic prefix is the same evidence
    /// `capture` validates, so detection and capture stay consistent.
    pub fn detect(path: &Path) -> MddResult<Self> {
        let mut header = [0u8; 8];
        let count = {
            let mut file = File::open(path).map_err(|error| {
                MddError::new(ErrorCode::InvalidInput, "capture", error.to_string())
            })?;
            file.read(&mut header).map_err(|error| {
                MddError::new(ErrorCode::InvalidInput, "capture", error.to_string())
            })?
        };
        let magic = &header[..count];
        for kind in [Self::RawDex, Self::Apk] {
            if kind.matches_magic(magic) {
                return Ok(kind);
            }
        }
        // Same code and stage `capture` reports for a magic mismatch, so the two
        // entry points cannot disagree about the same bytes.
        Err(MddError::new(
            ErrorCode::InvalidInput,
            "capture",
            "input magic does not match any supported kind",
        )
        .detail("input_coverage", "none"))
    }
}

#[derive(Clone, Debug)]
pub struct InputSpec {
    pub path: PathBuf,
    pub kind: InputKind,
    pub expected_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct CaptureLimits {
    pub max_input_bytes: u64,
    pub max_sources: usize,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 1024 * 1024 * 1024,
            max_sources: 256,
        }
    }
}

struct TempFileHandle {
    #[cfg(any(unix, windows))]
    file: Option<File>,
    #[cfg(not(any(unix, windows)))]
    file: Option<std::sync::Mutex<File>>,
    path: Option<PathBuf>,
}

impl TempFileHandle {
    fn create_in(dir: &Path) -> MddResult<Self> {
        for _ in 0..8 {
            let path = dir.join(format!("{}.tmp", opaque_id("mdd-snapshot")?));
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                options.share_mode(0);
            }
            match options.open(&path) {
                Ok(file) => return Self::finish(file, path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(MddError::new(
                        ErrorCode::InternalFault,
                        "capture",
                        format!("failed to create snapshot spill file: {error}"),
                    ));
                }
            }
        }
        Err(MddError::new(
            ErrorCode::InternalFault,
            "capture",
            "failed to allocate unique snapshot spill file",
        ))
    }

    #[cfg(unix)]
    fn finish(file: File, path: PathBuf) -> MddResult<Self> {
        // Unlink immediately on Unix while keeping the fd so no directory entry lingers.
        let unlinked = std::fs::remove_file(&path).is_ok();
        Ok(Self {
            file: Some(file),
            path: if unlinked { None } else { Some(path) },
        })
    }

    #[cfg(windows)]
    fn finish(file: File, path: PathBuf) -> MddResult<Self> {
        Ok(Self {
            file: Some(file),
            path: Some(path),
        })
    }

    #[cfg(not(any(unix, windows)))]
    fn finish(file: File, path: PathBuf) -> MddResult<Self> {
        Ok(Self {
            file: Some(std::sync::Mutex::new(file)),
            path: Some(path),
        })
    }

    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        #[cfg(any(unix, windows))]
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("spilled snapshot handle closed"))?;
        #[cfg(not(any(unix, windows)))]
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("spilled snapshot handle closed"))?
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        file.write_all(bytes)
    }

    #[cfg(unix)]
    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> MddResult<()> {
        use std::os::unix::fs::FileExt;
        let file = self.file.as_ref().ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "snapshot.read",
                "spilled snapshot handle closed",
            )
        })?;
        let mut filled = 0usize;
        while filled < dst.len() {
            let pos = offset.checked_add(filled as u64).ok_or_else(|| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "snapshot.read",
                    "spilled source read offset overflow",
                )
            })?;
            match file.read_at(&mut dst[filled..], pos) {
                Ok(0) => {
                    return Err(MddError::new(
                        ErrorCode::InternalFault,
                        "snapshot.read",
                        "spilled source temporary file ended unexpectedly",
                    ));
                }
                Ok(n) => filled += n,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(MddError::new(
                        ErrorCode::InternalFault,
                        "snapshot.read",
                        error.to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> MddResult<()> {
        use std::os::windows::fs::FileExt;
        let file = self.file.as_ref().ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "snapshot.read",
                "spilled snapshot handle closed",
            )
        })?;
        let mut filled = 0usize;
        while filled < dst.len() {
            let pos = offset.checked_add(filled as u64).ok_or_else(|| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "snapshot.read",
                    "spilled source read offset overflow",
                )
            })?;
            match file.seek_read(&mut dst[filled..], pos) {
                Ok(0) => {
                    return Err(MddError::new(
                        ErrorCode::InternalFault,
                        "snapshot.read",
                        "spilled source temporary file ended unexpectedly",
                    ));
                }
                Ok(n) => filled += n,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(MddError::new(
                        ErrorCode::InternalFault,
                        "snapshot.read",
                        error.to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> MddResult<()> {
        use std::io::{Seek, SeekFrom};
        let lock = self.file.as_ref().ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "snapshot.read",
                "spilled snapshot handle closed",
            )
        })?;
        let mut file = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        file.seek(SeekFrom::Start(offset)).map_err(|error| {
            MddError::new(ErrorCode::InternalFault, "snapshot.read", error.to_string())
        })?;
        file.read_exact(dst).map_err(|error| {
            MddError::new(ErrorCode::InternalFault, "snapshot.read", error.to_string())
        })
    }
}

impl Drop for TempFileHandle {
    fn drop(&mut self) {
        // Close the file handle before unlinking so Windows does not reject deletion.
        drop(self.file.take());
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

struct SpilledFile {
    handle: TempFileHandle,
    len: u64,
    bytes_cache: OnceLock<Arc<[u8]>>,
}

impl SpilledFile {
    fn lease_arc(&self) -> &Arc<[u8]> {
        self.bytes_cache.get_or_init(|| {
            let len = usize::try_from(self.len)
                .expect("spilled captured source exceeds host address space");
            let mut buf = Vec::new();
            buf.try_reserve_exact(len)
                .expect("failed to allocate memory for spilled captured source");
            buf.resize(len, 0);
            self.handle
                .read_exact_at(0, &mut buf)
                .expect("spilled captured source temporary file could not be read");
            Arc::from(buf)
        })
    }

    fn bytes(&self) -> &[u8] {
        self.lease_arc()
    }
}

#[derive(Clone)]
enum SourceBacking {
    InMemory(Arc<[u8]>),
    Spilled(Arc<SpilledFile>),
}

fn copy_slice_range(bytes: &[u8], offset: u64, dst: &mut [u8]) -> MddResult<()> {
    let start = usize::try_from(offset).map_err(|_| {
        MddError::new(
            ErrorCode::InvalidInput,
            "snapshot.read",
            "read offset exceeds host address range",
        )
    })?;
    let stop = start.checked_add(dst.len()).ok_or_else(|| {
        MddError::new(
            ErrorCode::InvalidInput,
            "snapshot.read",
            "captured source read range overflow",
        )
    })?;
    let slice = bytes.get(start..stop).ok_or_else(|| {
        MddError::new(
            ErrorCode::InvalidInput,
            "snapshot.read",
            "read range exceeds captured source",
        )
    })?;
    dst.copy_from_slice(slice);
    Ok(())
}

#[derive(Clone)]
pub struct CapturedSource {
    identity: SourceIdentity,
    kind: InputKind,
    backing: SourceBacking,
}

impl CapturedSource {
    pub fn identity(&self) -> &SourceIdentity {
        &self.identity
    }
    pub fn kind(&self) -> InputKind {
        self.kind
    }
    pub fn byte_length(&self) -> u64 {
        self.identity.byte_length.0
    }
    pub fn try_bytes(&self) -> Option<&[u8]> {
        match &self.backing {
            SourceBacking::InMemory(bytes) => Some(bytes),
            SourceBacking::Spilled(spilled) => spilled.bytes_cache.get().map(AsRef::as_ref),
        }
    }
    pub fn read_range(&self, offset: u64, len: usize) -> MddResult<Vec<u8>> {
        let total = self.byte_length();
        let end = u64::try_from(len)
            .ok()
            .and_then(|n| offset.checked_add(n))
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidInput,
                    "snapshot.read",
                    "captured source read range overflow",
                )
            })?;
        if end > total {
            return Err(MddError::new(
                ErrorCode::InvalidInput,
                "snapshot.read",
                "read range exceeds captured source",
            ));
        }
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        out.try_reserve_exact(len).map_err(|error| {
            MddError::new(ErrorCode::QuotaExceeded, "snapshot.read", error.to_string())
        })?;
        out.resize(len, 0);
        self.read_exact_into(offset, &mut out)?;
        Ok(out)
    }
    pub(crate) fn read_exact_into(&self, offset: u64, dst: &mut [u8]) -> MddResult<()> {
        let total = self.byte_length();
        let end = u64::try_from(dst.len())
            .ok()
            .and_then(|n| offset.checked_add(n))
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidInput,
                    "snapshot.read",
                    "captured source read range overflow",
                )
            })?;
        if end > total {
            return Err(MddError::new(
                ErrorCode::InvalidInput,
                "snapshot.read",
                "read range exceeds captured source",
            ));
        }
        if dst.is_empty() {
            return Ok(());
        }
        match &self.backing {
            SourceBacking::InMemory(bytes) => copy_slice_range(bytes, offset, dst),
            SourceBacking::Spilled(spilled) => {
                if let Some(bytes) = spilled.bytes_cache.get() {
                    copy_slice_range(bytes, offset, dst)
                } else {
                    spilled.handle.read_exact_at(offset, dst)
                }
            }
        }
    }
    pub fn bytes(&self) -> &[u8] {
        match &self.backing {
            SourceBacking::InMemory(bytes) => bytes,
            SourceBacking::Spilled(spilled) => spilled.bytes(),
        }
    }
    pub fn lease(&self) -> Arc<[u8]> {
        match &self.backing {
            SourceBacking::InMemory(bytes) => Arc::clone(bytes),
            SourceBacking::Spilled(spilled) => Arc::clone(spilled.lease_arc()),
        }
    }
}

enum CaptureStream {
    Memory(Vec<u8>),
    PendingSpill,
    Spilled(TempFileHandle),
}

fn read_chunk(file: &mut File, buffer: &mut [u8]) -> std::io::Result<usize> {
    loop {
        match file.read(buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

fn spill_io_error(error: std::io::Error, ordinal: usize) -> MddError {
    MddError::new(ErrorCode::InternalFault, "capture", error.to_string())
        .detail("input_ordinal", ordinal.to_string())
}

#[derive(Clone, Serialize)]
pub struct SnapshotManifest {
    pub schema_version: String,
    pub snapshot_id: String,
    pub snapshot_content_key: String,
    pub capture_policy: String,
    pub sources: Vec<SourceIdentity>,
    pub captured_input_bytes: DecimalU64,
    pub scope: String,
}

pub struct Snapshot {
    manifest: SnapshotManifest,
    sources: Vec<CapturedSource>,
}

impl Snapshot {
    pub fn capture(inputs: &[InputSpec], limits: CaptureLimits) -> MddResult<Self> {
        let spill_threshold = spill_snapshot_enabled().then_some(SPILL_THRESHOLD_BYTES);
        Self::capture_inner(inputs, limits, spill_threshold, None)
    }

    #[cfg(test)]
    pub(crate) fn capture_with_spill_threshold(
        inputs: &[InputSpec],
        limits: CaptureLimits,
        spill_threshold: Option<u64>,
    ) -> MddResult<Self> {
        Self::capture_inner(inputs, limits, spill_threshold, None)
    }

    #[cfg(test)]
    fn capture_with_spill_threshold_in_dir(
        inputs: &[InputSpec],
        limits: CaptureLimits,
        spill_threshold: Option<u64>,
        spill_dir: &Path,
    ) -> MddResult<Self> {
        Self::capture_inner(inputs, limits, spill_threshold, Some(spill_dir))
    }

    fn capture_inner(
        inputs: &[InputSpec],
        limits: CaptureLimits,
        spill_threshold: Option<u64>,
        spill_dir: Option<&Path>,
    ) -> MddResult<Self> {
        if inputs.is_empty() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "capture",
                "input list is empty",
            ));
        }
        if inputs.len() > limits.max_sources {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "capture",
                "source count exceeds budget",
            )
            .detail("budget", "max_sources")
            .detail("limit", limits.max_sources.to_string()));
        }
        let snapshot_id = opaque_id("snapshot")?;
        let mut sources = Vec::new();
        let mut content: BTreeMap<String, SourceBacking> = BTreeMap::new();
        let mut total = 0u64;
        let default_spill_dir = spill_dir.is_none().then(std::env::temp_dir);
        let active_spill_dir = spill_dir.unwrap_or_else(|| {
            default_spill_dir
                .as_deref()
                .expect("default spill dir populated")
        });
        let mut buffer = [0u8; STREAM_CHUNK_BYTES];
        for (ordinal, input) in inputs.iter().enumerate() {
            if let Some(expected) = &input.expected_sha256
                && (expected.len() != 64
                    || !expected
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "capture",
                    "expected SHA-256 must be lowercase 64-digit hex",
                ));
            }
            let io_error = |error: std::io::Error| {
                MddError::new(ErrorCode::InvalidInput, "capture", error.to_string())
                    .detail("input_ordinal", ordinal.to_string())
            };
            let mut file = File::open(&input.path).map_err(io_error)?;
            // Reserve from the file length hint but never beyond the remaining byte
            // budget: the declared length is untrusted and must not drive allocation.
            let hint = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
            let remaining_budget = limits.max_input_bytes.saturating_sub(total);
            let allow_spill = match input.kind {
                InputKind::Apk => spill_threshold,
                InputKind::RawDex => None,
            };
            let mut stream = if allow_spill
                .is_some_and(|threshold| hint >= threshold && remaining_budget >= threshold)
            {
                CaptureStream::PendingSpill
            } else {
                let mut reserve = hint.min(remaining_budget).min(usize::MAX as u64);
                if let Some(threshold) = allow_spill {
                    reserve = reserve.min(threshold);
                }
                let mut bytes = Vec::new();
                bytes.try_reserve(reserve as usize).map_err(|error| {
                    MddError::new(ErrorCode::QuotaExceeded, "capture", error.to_string())
                        .detail("input_ordinal", ordinal.to_string())
                })?;
                CaptureStream::Memory(bytes)
            };
            let mut source_len = 0u64;
            let mut header = [0u8; 8];
            let mut header_len = 0usize;
            let mut hasher = Sha256::new();
            loop {
                let count = read_chunk(&mut file, &mut buffer).map_err(io_error)?;
                if count == 0 {
                    break;
                }
                total = total.checked_add(count as u64).ok_or_else(|| {
                    MddError::new(ErrorCode::QuotaExceeded, "capture", "input length overflow")
                })?;
                if total > limits.max_input_bytes {
                    return Err(MddError::new(
                        ErrorCode::QuotaExceeded,
                        "capture",
                        "input byte budget exceeded",
                    )
                    .detail("budget", "max_input_bytes")
                    .detail("limit", limits.max_input_bytes.to_string())
                    .detail("observed", total.to_string())
                    .detail("input_ordinal", ordinal.to_string()));
                }
                source_len = source_len.checked_add(count as u64).ok_or_else(|| {
                    MddError::new(ErrorCode::QuotaExceeded, "capture", "input length overflow")
                })?;
                if header_len < header.len() {
                    let take = (header.len() - header_len).min(count);
                    header[header_len..header_len + take].copy_from_slice(&buffer[..take]);
                    header_len += take;
                }
                hasher.update(&buffer[..count]);
                match &mut stream {
                    CaptureStream::PendingSpill => {
                        let mut temp = TempFileHandle::create_in(active_spill_dir)?;
                        temp.write_all(&buffer[..count])
                            .map_err(|e| spill_io_error(e, ordinal))?;
                        stream = CaptureStream::Spilled(temp);
                    }
                    CaptureStream::Spilled(temp) => {
                        temp.write_all(&buffer[..count])
                            .map_err(|e| spill_io_error(e, ordinal))?;
                    }
                    CaptureStream::Memory(bytes) => {
                        if allow_spill.is_some_and(|threshold| source_len >= threshold) {
                            let mut temp = TempFileHandle::create_in(active_spill_dir)?;
                            temp.write_all(bytes)
                                .map_err(|e| spill_io_error(e, ordinal))?;
                            temp.write_all(&buffer[..count])
                                .map_err(|e| spill_io_error(e, ordinal))?;
                            stream = CaptureStream::Spilled(temp);
                        } else {
                            bytes.try_reserve(count).map_err(|error| {
                                MddError::new(
                                    ErrorCode::QuotaExceeded,
                                    "capture",
                                    error.to_string(),
                                )
                            })?;
                            bytes.extend_from_slice(&buffer[..count]);
                        }
                    }
                }
            }
            let correct_magic = input.kind.matches_magic(&header[..header_len]);
            if !correct_magic {
                return Err(MddError::new(
                    ErrorCode::InvalidInput,
                    "capture",
                    "input magic does not match declared kind",
                )
                .detail("input_ordinal", ordinal.to_string()));
            }
            let digest: String = hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            if input
                .expected_sha256
                .as_ref()
                .is_some_and(|expected| *expected != digest)
            {
                return Err(MddError::new(
                    ErrorCode::SourceChanged,
                    "capture",
                    "captured content differs from expected SHA-256",
                )
                .detail("actual_sha256", digest)
                .detail("input_ordinal", ordinal.to_string()));
            }
            // `content_id` is exactly `sha256:<digest>`; reuse the digest above
            // instead of hashing the same captured bytes a second time.
            let id = format!("sha256:{digest}");
            let candidate_backing = match stream {
                CaptureStream::Memory(bytes) => SourceBacking::InMemory(Arc::from(bytes)),
                CaptureStream::PendingSpill => SourceBacking::InMemory(Arc::from([])),
                CaptureStream::Spilled(temp) => {
                    if allow_spill.is_some_and(|threshold| source_len < threshold) {
                        let len = usize::try_from(source_len).map_err(|_| {
                            MddError::new(
                                ErrorCode::QuotaExceeded,
                                "capture",
                                "captured source exceeds host address space",
                            )
                        })?;
                        let mut bytes = Vec::new();
                        bytes.try_reserve_exact(len).map_err(|error| {
                            MddError::new(ErrorCode::QuotaExceeded, "capture", error.to_string())
                        })?;
                        bytes.resize(len, 0);
                        temp.read_exact_at(0, &mut bytes)?;
                        drop(temp);
                        SourceBacking::InMemory(Arc::from(bytes))
                    } else {
                        SourceBacking::Spilled(Arc::new(SpilledFile {
                            handle: temp,
                            len: source_len,
                            bytes_cache: OnceLock::new(),
                        }))
                    }
                }
            };
            let backing = match content.entry(id.clone()) {
                BTreeEntry::Occupied(entry) => entry.get().clone(),
                BTreeEntry::Vacant(entry) => entry.insert(candidate_backing).clone(),
            };
            sources.push(CapturedSource {
                identity: SourceIdentity {
                    occurrence_id: format!("{snapshot_id}:source:{ordinal}"),
                    input_ordinal: DecimalU64(ordinal as u64),
                    content_id: id,
                    byte_length: DecimalU64(source_len),
                    input_kind: input.kind.name().to_owned(),
                    origin_display: input.path.to_str().map(str::to_owned),
                },
                kind: input.kind,
                backing,
            });
        }
        let identities: Vec<_> = sources.iter().map(|s| s.identity.clone()).collect();
        let key_items: Vec<_> = identities
            .iter()
            .map(|s| (&s.content_id, &s.input_kind))
            .collect();
        let key = serde_json::to_vec(&("capture-owned-v1", &key_items)).map_err(|error| {
            MddError::new(ErrorCode::InternalFault, "capture", error.to_string())
        })?;
        Ok(Self {
            manifest: SnapshotManifest {
                schema_version: "mdd.snapshot.capture.v1".to_owned(), snapshot_id,
                snapshot_content_key: content_id(&key), capture_policy: "owned-captured-bytes-v1".to_owned(),
                sources: identities, captured_input_bytes: DecimalU64(total),
                scope: "owned source capture only; member inventory and DEX facts require separate validation".to_owned(),
            }, sources,
        })
    }

    pub fn manifest(&self) -> &SnapshotManifest {
        &self.manifest
    }
    pub fn sources(&self) -> &[CapturedSource] {
        &self.sources
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdd_types::sha256;
    use std::fs;

    struct TestDir(PathBuf);

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(opaque_id("mdd-test").unwrap());
        fs::create_dir(&path).unwrap();
        path
    }

    fn synthetic_apk(payload_size: usize) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            writer
                .start_file(
                    "classes.dex",
                    zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Stored),
                )
                .unwrap();
            let dex = include_bytes!("../../../../tests/fixtures/generated/minimal-035.dex");
            writer.write_all(dex).unwrap();
            writer
                .start_file(
                    "assets/blob.bin",
                    zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Stored),
                )
                .unwrap();
            let payload: Vec<u8> = (0..payload_size)
                .map(|i| ((i.wrapping_mul(2654435761)) >> 16) as u8)
                .collect();
            writer.write_all(&payload).unwrap();
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn spec(path: PathBuf) -> InputSpec {
        InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        }
    }

    #[test]
    fn capture_retains_generation_and_occurrences() {
        let dir = directory();
        let path = dir.join("source.dex");
        let original = include_bytes!("../../../../tests/fixtures/generated/minimal-035.dex");
        fs::write(&path, original).unwrap();
        let snapshot = Snapshot::capture(
            &[spec(path.clone()), spec(path.clone())],
            CaptureLimits::default(),
        )
        .unwrap();
        assert_eq!(snapshot.sources().len(), 2);
        assert_ne!(
            snapshot.sources()[0].identity().occurrence_id,
            snapshot.sources()[1].identity().occurrence_id
        );
        assert!(Arc::ptr_eq(
            &snapshot.sources()[0].lease(),
            &snapshot.sources()[1].lease()
        ));
        let lease = snapshot.sources()[0].lease();
        let modified = vec![b'x'; original.len()];
        let times = fs::metadata(&path).unwrap();
        fs::write(&path, modified).unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(times.modified().unwrap()))
            .unwrap();
        fs::rename(&path, dir.join("renamed.dex")).unwrap();
        fs::remove_file(dir.join("renamed.dex")).unwrap();
        fs::write(&path, b"replacement").unwrap();
        assert_eq!(snapshot.sources()[0].bytes(), original);
        assert_eq!(snapshot.sources()[1].bytes(), original);
        assert_eq!(lease.as_ref(), original);
        drop(snapshot);
        assert_eq!(lease.as_ref(), original);
    }

    #[test]
    fn source_expected_hash_and_zero_budget_fail_closed() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/generated/minimal-035.dex");
        let mut input = spec(path);
        input.expected_sha256 = Some("0".repeat(64));
        assert_eq!(
            Snapshot::capture(std::slice::from_ref(&input), CaptureLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::SourceChanged
        );
        input.expected_sha256 = None;
        assert_eq!(
            Snapshot::capture(
                &[input],
                CaptureLimits {
                    max_input_bytes: 0,
                    max_sources: 1
                }
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            Snapshot::capture(&[], CaptureLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn captured_content_id_is_the_single_sha256_of_the_captured_bytes() {
        // `content_id` must stay byte-identical to `sha256:` + `sha256(bytes)` now
        // that capture reuses one digest for both the expectation check and the id.
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/generated/minimal-035.dex");
        let snapshot = Snapshot::capture(&[spec(path)], CaptureLimits::default()).expect("capture");
        let source = &snapshot.sources()[0];
        assert_eq!(source.identity().content_id, content_id(source.bytes()));
        assert_eq!(
            source.identity().content_id,
            format!("sha256:{}", sha256(source.bytes()))
        );
        assert_eq!(
            source.identity().byte_length,
            DecimalU64(source.bytes().len() as u64)
        );
    }

    #[test]
    fn length_hint_cannot_exceed_the_remaining_byte_budget() {
        // The file is far larger than the budget; the reservation must be clamped
        // by the budget rather than by the untrusted metadata length.
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/generated/minimal-035.dex");
        let error = Snapshot::capture(
            &[spec(path)],
            CaptureLimits {
                max_input_bytes: 64,
                max_sources: 1,
            },
        )
        .err()
        .expect("budget");
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
        assert_eq!(error.stage, "capture");
        assert_eq!(error.details["budget"], "max_input_bytes");
        assert_eq!(error.details["limit"], "64");
    }

    #[test]
    fn spilled_apk_matches_in_memory_and_survives_source_mutation() {
        let dir = TestDir(directory());
        let path = dir.0.join("large.apk");
        let apk = synthetic_apk(210_000);
        fs::write(&path, &apk).unwrap();
        let input = InputSpec {
            path: path.clone(),
            kind: InputKind::Apk,
            expected_sha256: Some(sha256(&apk)),
        };
        let in_mem = Snapshot::capture_with_spill_threshold(
            std::slice::from_ref(&input),
            CaptureLimits::default(),
            None,
        )
        .unwrap();
        let spilled = Snapshot::capture_with_spill_threshold(
            &[input],
            CaptureLimits::default(),
            Some(64 * 1024),
        )
        .unwrap();

        assert_eq!(
            in_mem.manifest().snapshot_content_key,
            spilled.manifest().snapshot_content_key
        );
        assert_eq!(
            in_mem.manifest().captured_input_bytes,
            spilled.manifest().captured_input_bytes
        );
        assert_eq!(
            in_mem.manifest().capture_policy,
            spilled.manifest().capture_policy
        );
        assert_eq!(spilled.manifest().capture_policy, "owned-captured-bytes-v1");

        let mem_src = &in_mem.sources()[0];
        let spill_src = &spilled.sources()[0];
        assert_eq!(
            mem_src.identity().content_id,
            spill_src.identity().content_id
        );
        assert_eq!(
            mem_src.identity().byte_length,
            spill_src.identity().byte_length
        );
        assert_eq!(mem_src.byte_length(), apk.len() as u64);
        assert_eq!(spill_src.byte_length(), apk.len() as u64);
        assert!(mem_src.try_bytes().is_some());
        assert!(spill_src.try_bytes().is_none());

        // Rewrite with same size and restored mtime, then delete original file.
        let times = fs::metadata(&path).unwrap();
        fs::write(&path, vec![b'z'; apk.len()]).unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(times.modified().unwrap()))
            .unwrap();
        fs::remove_file(&path).unwrap();

        // Range reads across chunk boundaries match identically without materializing try_bytes().
        for &(offset, len) in &[
            (0u64, 0usize),
            (0, 64),
            (65_535, 2),
            (65_536, 65_537),
            ((apk.len() - 37) as u64, 37),
            (apk.len() as u64, 0),
            (0, apk.len()),
        ] {
            let expected = &apk[offset as usize..offset as usize + len];
            assert_eq!(mem_src.read_range(offset, len).unwrap(), expected);
            assert_eq!(spill_src.read_range(offset, len).unwrap(), expected);
        }
        assert!(spill_src.try_bytes().is_none());
        assert_eq!(
            spill_src.read_range(apk.len() as u64, 1).unwrap_err().code,
            ErrorCode::InvalidInput
        );
        assert_eq!(
            spill_src.read_range(u64::MAX, 1).unwrap_err().code,
            ErrorCode::InvalidInput
        );

        // Lazy fallback materializes once and shares the Arc<[u8]>.
        assert_eq!(spill_src.bytes(), apk.as_slice());
        assert!(spill_src.try_bytes().is_some());
        assert!(Arc::ptr_eq(&spill_src.lease(), &spill_src.lease()));
    }

    #[test]
    fn raw_dex_and_disabled_spill_stay_in_memory() {
        let dir = TestDir(directory());
        let dex_path = dir.0.join("sample.dex");
        let dex = include_bytes!("../../../../tests/fixtures/generated/minimal-035.dex");
        fs::write(&dex_path, dex).unwrap();
        let raw_snap = Snapshot::capture_with_spill_threshold(
            &[InputSpec {
                path: dex_path,
                kind: InputKind::RawDex,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
            Some(1),
        )
        .unwrap();
        assert!(raw_snap.sources()[0].try_bytes().is_some());

        let apk_path = dir.0.join("sample.apk");
        let apk = synthetic_apk(100_000);
        fs::write(&apk_path, &apk).unwrap();
        let no_spill_snap = Snapshot::capture_with_spill_threshold(
            &[InputSpec {
                path: apk_path,
                kind: InputKind::Apk,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
            None,
        )
        .unwrap();
        assert!(no_spill_snap.sources()[0].try_bytes().is_some());
    }

    #[test]
    fn spilled_concurrent_read_range_is_thread_safe() {
        let dir = TestDir(directory());
        let path = dir.0.join("concurrent.apk");
        let apk = synthetic_apk(250_000);
        fs::write(&path, &apk).unwrap();
        let snapshot = Snapshot::capture_with_spill_threshold(
            &[InputSpec {
                path,
                kind: InputKind::Apk,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
            Some(64 * 1024),
        )
        .unwrap();
        let source = &snapshot.sources()[0];
        assert!(source.try_bytes().is_none());

        std::thread::scope(|scope| {
            for worker in 0..8usize {
                let expected = &apk;
                scope.spawn(move || {
                    for step in 0..32usize {
                        let start =
                            ((worker * 13_107 + step * 4_099) % (expected.len() - 512)) as u64;
                        let len = 257 + ((worker + step) % 1024);
                        let chunk = source.read_range(start, len).unwrap();
                        assert_eq!(
                            chunk.as_slice(),
                            &expected[start as usize..start as usize + len]
                        );
                    }
                });
            }
        });
        assert!(source.try_bytes().is_none());
    }

    #[test]
    fn spilled_error_paths_and_drop_leave_zero_leftover_temp_files() {
        let work_dir = TestDir(directory());
        let spill_dir = TestDir(directory());
        let apk_path = work_dir.0.join("valid.apk");
        let apk = synthetic_apk(180_000);
        fs::write(&apk_path, &apk).unwrap();

        let bad_magic_path = work_dir.0.join("bad_magic.apk");
        let mut bad_magic = vec![b'X'; 180_000];
        bad_magic[..4].copy_from_slice(b"NOPE");
        fs::write(&bad_magic_path, &bad_magic).unwrap();

        let count_spill_entries = || fs::read_dir(&spill_dir.0).unwrap().count();

        // 1. QuotaExceeded mid-stream after spill started.
        let err = Snapshot::capture_with_spill_threshold_in_dir(
            &[InputSpec {
                path: apk_path.clone(),
                kind: InputKind::Apk,
                expected_sha256: None,
            }],
            CaptureLimits {
                max_input_bytes: 100_000,
                max_sources: 4,
            },
            Some(32 * 1024),
            &spill_dir.0,
        )
        .err()
        .unwrap();
        assert_eq!(err.code, ErrorCode::QuotaExceeded);
        assert_eq!(count_spill_entries(), 0);

        // 2. InvalidInput magic mismatch after spill.
        let err = Snapshot::capture_with_spill_threshold_in_dir(
            &[InputSpec {
                path: bad_magic_path,
                kind: InputKind::Apk,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
            Some(32 * 1024),
            &spill_dir.0,
        )
        .err()
        .unwrap();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert_eq!(count_spill_entries(), 0);

        // 3. SourceChanged SHA-256 mismatch after spill.
        let err = Snapshot::capture_with_spill_threshold_in_dir(
            &[InputSpec {
                path: apk_path.clone(),
                kind: InputKind::Apk,
                expected_sha256: Some("0".repeat(64)),
            }],
            CaptureLimits::default(),
            Some(32 * 1024),
            &spill_dir.0,
        )
        .err()
        .unwrap();
        assert_eq!(err.code, ErrorCode::SourceChanged);
        assert_eq!(count_spill_entries(), 0);

        // 4. Multi-source capture where source 0 succeeds and source 1 fails cleans both.
        let err = Snapshot::capture_with_spill_threshold_in_dir(
            &[
                InputSpec {
                    path: apk_path.clone(),
                    kind: InputKind::Apk,
                    expected_sha256: None,
                },
                InputSpec {
                    path: apk_path.clone(),
                    kind: InputKind::Apk,
                    expected_sha256: Some("f".repeat(64)),
                },
            ],
            CaptureLimits::default(),
            Some(32 * 1024),
            &spill_dir.0,
        )
        .err()
        .unwrap();
        assert_eq!(err.code, ErrorCode::SourceChanged);
        assert_eq!(count_spill_entries(), 0);

        // 5. Duplicate valid spilled inputs share one spill file, and drop removes it.
        let snap = Snapshot::capture_with_spill_threshold_in_dir(
            &[
                InputSpec {
                    path: apk_path.clone(),
                    kind: InputKind::Apk,
                    expected_sha256: None,
                },
                InputSpec {
                    path: apk_path,
                    kind: InputKind::Apk,
                    expected_sha256: None,
                },
            ],
            CaptureLimits::default(),
            Some(32 * 1024),
            &spill_dir.0,
        )
        .unwrap();
        #[cfg(unix)]
        assert_eq!(count_spill_entries(), 0);
        #[cfg(not(unix))]
        assert_eq!(count_spill_entries(), 1);
        let cloned_source = snap.sources()[0].clone();
        drop(snap);
        assert_eq!(cloned_source.read_range(0, 4).unwrap(), b"PK\x03\x04");
        drop(cloned_source);
        assert_eq!(count_spill_entries(), 0);
    }
}
