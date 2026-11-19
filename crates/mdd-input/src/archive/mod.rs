use crate::snapshot::{CapturedSource, InputKind};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult, content_id};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    sync::{Arc, Mutex},
};

mod central;
mod zip64;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DexSelection {
    TopLevelClasses,
    AllDexMembers,
    ResourcesOnly,
}

#[derive(Clone, Copy, Debug)]
pub struct InventoryPolicy {
    pub dex_selection: DexSelection,
    pub reject_duplicate_selected_names: bool,
    pub require_dex: bool,
    /// Keep the decompressed bytes of every selected DEX for as long as the inventory lives. Without it a selected DEX of
    /// an archive is read, checked and let go at build, and decompressed again from the captured archive whenever
    /// something leases its bytes; the copy lives as long as a holder of the lease does. The archive's own bytes are held
    /// either way, so the choice is memory (all the DEX at once, a quarter to a half of the archive again) against the
    /// time to decompress a DEX each time it is needed.
    ///
    /// Whoever leases a DEX of an inventory that does not hold them lets the inventory's copy go with
    /// `MemberBlob::release` when it has taken what it needs, or the copy stays for as long as the inventory lives.
    pub hold_dex_bytes: bool,
}

impl InventoryPolicy {
    /// Reuse the inventory selector when admitting expansion before allocation.
    pub fn selects(&self, raw_name: &[u8]) -> bool {
        selected_name(raw_name, self.dex_selection)
    }
}

impl Default for InventoryPolicy {
    fn default() -> Self {
        Self {
            dex_selection: DexSelection::TopLevelClasses,
            reject_duplicate_selected_names: true,
            require_dex: true,
            hold_dex_bytes: true,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ArchiveLimits {
    pub max_members: usize,
    pub max_directory_bytes: u64,
    pub max_member_bytes: u64,
    pub max_total_uncompressed_bytes: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_members: 100000,
            max_directory_bytes: 64 * 1024 * 1024,
            max_member_bytes: 512 * 1024 * 1024,
            max_total_uncompressed_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct MemberIdentity {
    pub member_id: String,
    pub source_occurrence_id: String,
    pub input_ordinal: DecimalU64,
    pub archive_member_ordinal: Option<DecimalU64>,
    pub raw_name: Vec<u8>,
    pub name_utf8: Option<String>,
    pub declared_size: DecimalU64,
    pub compressed_size: DecimalU64,
    pub compressed_byte_offset: DecimalU64,
    pub crc32: Option<u32>,
    pub compression: String,
    pub is_directory: bool,
    pub selected_dex: bool,
}

#[derive(Clone, Serialize)]
pub struct MemberBlob {
    pub identity: MemberIdentity,
    pub content_id: String,
    #[serde(skip)]
    len: usize,
    #[serde(skip)]
    bytes: BlobBytes,
}

/// The bytes of a member: held, or decompressed from the captured archive when someone asks.
#[derive(Clone)]
enum BlobBytes {
    Held(Arc<[u8]>),
    Lazy(Arc<LazyBytes>),
}

struct LazyBytes {
    /// The bytes read for the leases that are out, so that everyone who asks meanwhile gets the same allocation; dropped by
    /// `MemberBlob::release`. It is a strong reference on purpose: a weak one would keep the whole allocation (the bytes
    /// are stored inline with the counts) until the last weak reference went, whoever dropped the last lease.
    cache: Mutex<Option<Arc<[u8]>>>,
    content_id: String,
    reader: MemberReader,
}

impl LazyBytes {
    fn get(&self) -> MddResult<Arc<[u8]>> {
        // One reader at a time: two threads that want the same member wait for one decompression and share its result.
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(bytes) = cache.as_ref() {
            return Ok(Arc::clone(bytes));
        }
        let bytes: Arc<[u8]> = Arc::from(self.reader.read()?);
        if content_id(&bytes) != self.content_id {
            return Err(MddError::new(
                ErrorCode::InternalFault,
                "archive.member_bytes",
                "member bytes read again differ from the identity they were first read under",
            ));
        }
        *cache = Some(Arc::clone(&bytes));
        Ok(bytes)
    }
}

impl MemberBlob {
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// The member's bytes. For a member the inventory did not hold (`InventoryPolicy::hold_dex_bytes` off) they are
    /// decompressed from the archive unless a lease is out already (see `release`); use `try_lease` where a failure can be
    /// reported.
    ///
    /// # Panics
    /// If the member cannot be read again: it was read and checked when the inventory was built, from bytes that cannot
    /// change since, so that is a broken invariant (or an allocation that fails), not an input error.
    pub fn lease(&self) -> Arc<[u8]> {
        match self.try_lease() {
            Ok(bytes) => bytes,
            Err(error) => panic!(
                "member {} was read at inventory build but cannot be read again: {error:?}",
                self.identity.member_id
            ),
        }
    }
    pub fn try_lease(&self) -> MddResult<Arc<[u8]>> {
        match &self.bytes {
            BlobBytes::Held(bytes) => Ok(Arc::clone(bytes)),
            BlobBytes::Lazy(lazy) => lazy.get(),
        }
    }
    /// The bytes if they are held: always for a member the inventory held, and for one it did not from the first lease until
    /// `release`. Never reads the archive.
    pub fn held_lease(&self) -> Option<Arc<[u8]>> {
        match &self.bytes {
            BlobBytes::Held(bytes) => Some(Arc::clone(bytes)),
            BlobBytes::Lazy(lazy) => lazy
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        }
    }
    /// Let go of the bytes a member the inventory did not hold was read into. Leases already given stay valid and keep the
    /// bytes alive; the next lease reads the member again. Does nothing for a member the inventory holds.
    pub fn release(&self) {
        if let BlobBytes::Lazy(lazy) = &self.bytes {
            lazy.cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
        }
    }
    /// Whether the bytes are held by the blob itself, not read on demand.
    pub fn is_held(&self) -> bool {
        matches!(self.bytes, BlobBytes::Held(_))
    }
}

/// Everything needed to decompress one archive member again.
#[derive(Clone)]
struct MemberReader {
    source: CapturedSource,
    entry: central::Entry,
    directory_start: usize,
    limits: ArchiveLimits,
    member_id: String,
}

#[derive(Clone, Serialize)]
pub struct DexCandidate {
    pub physical_dex_id: String,
    pub dex_occurrence_id: String,
    pub logical_header_byte_offset: DecimalU64,
    pub detected_version: String,
    pub qualification: String,
    pub blob: MemberBlob,
}

#[derive(Clone, Serialize)]
pub struct InventoryManifest {
    pub schema_version: String,
    pub source_occurrence_id: String,
    pub source_content_id: String,
    pub selection: DexSelection,
    pub members: Vec<MemberIdentity>,
    pub declared_uncompressed_bytes: DecimalU64,
    pub directory_complete: bool,
    pub selected_dex_bytes_complete: bool,
    pub resource_byte_validation: String,
    pub dex_fact_validation: String,
}

pub struct ArchiveInventory {
    source: CapturedSource,
    manifest: InventoryManifest,
    entries: Vec<central::Entry>,
    directory_start: usize,
    selected: Vec<DexCandidate>,
    /// `member_id` to position in `manifest.members` (parallel to `entries`), so
    /// repeated resource reads stay O(log n) instead of rescanning every member.
    member_index: BTreeMap<String, usize>,
    limits: ArchiveLimits,
}

fn selected_name(raw: &[u8], selection: DexSelection) -> bool {
    match selection {
        DexSelection::ResourcesOnly => false,
        DexSelection::AllDexMembers => raw.ends_with(b".dex") && !raw.ends_with(b"/"),
        DexSelection::TopLevelClasses => raw
            .strip_prefix(b"classes")
            .and_then(|n| n.strip_suffix(b".dex"))
            .is_some_and(|n| n.iter().all(u8::is_ascii_digit)),
    }
}

impl ArchiveInventory {
    pub fn build(
        source: &CapturedSource,
        policy: InventoryPolicy,
        limits: ArchiveLimits,
    ) -> MddResult<Self> {
        let context = |error: MddError| {
            error
                .detail(
                    "source_occurrence_id",
                    source.identity().occurrence_id.clone(),
                )
                .detail("input_coverage", "partial")
        };
        let mut entries = Vec::new();
        let mut directory_start = 0;
        let mut members = Vec::new();
        let mut total = 0u64;
        match source.kind() {
            InputKind::RawDex => {
                if matches!(policy.dex_selection, DexSelection::ResourcesOnly) {
                    return Err(context(MddError::new(
                        ErrorCode::InvalidArgument,
                        "archive.selection",
                        "resources-only profile requires an archive",
                    )));
                }
                total = source.bytes().len() as u64;
                if limits.max_members == 0
                    || total > limits.max_member_bytes
                    || total > limits.max_total_uncompressed_bytes
                {
                    return Err(context(MddError::new(
                        ErrorCode::QuotaExceeded,
                        "archive.budget",
                        "raw DEX exceeds member or byte budget",
                    )));
                }
                members.push(MemberIdentity {
                    member_id: format!("{}:raw", source.identity().occurrence_id),
                    source_occurrence_id: source.identity().occurrence_id.clone(),
                    input_ordinal: source.identity().input_ordinal,
                    archive_member_ordinal: None,
                    raw_name: Vec::new(),
                    name_utf8: None,
                    declared_size: DecimalU64(total),
                    compressed_size: DecimalU64(total),
                    compressed_byte_offset: DecimalU64(0),
                    crc32: None,
                    compression: "raw".into(),
                    is_directory: false,
                    selected_dex: true,
                });
            }
            InputKind::Apk => {
                (entries, directory_start) =
                    central::scan(source.bytes(), &limits).map_err(context)?;
                for entry in &entries {
                    total = total.checked_add(entry.size).ok_or_else(|| {
                        context(MddError::new(
                            ErrorCode::QuotaExceeded,
                            "archive.budget",
                            "uncompressed byte sum overflow",
                        ))
                    })?;
                    if entry.size > limits.max_member_bytes
                        || total > limits.max_total_uncompressed_bytes
                    {
                        return Err(context(
                            MddError::new(
                                ErrorCode::QuotaExceeded,
                                "archive.budget",
                                "declared uncompressed bytes exceed budget",
                            )
                            .detail("member_ordinal", entry.ordinal.to_string())
                            .detail("member_bytes", entry.size.to_string())
                            .detail("total_bytes", total.to_string()),
                        ));
                    }
                    members.push(MemberIdentity {
                        member_id: format!(
                            "{}:member:{}",
                            source.identity().occurrence_id,
                            entry.ordinal
                        ),
                        source_occurrence_id: source.identity().occurrence_id.clone(),
                        input_ordinal: source.identity().input_ordinal,
                        archive_member_ordinal: Some(DecimalU64(entry.ordinal as u64)),
                        raw_name: entry.raw_name.clone(),
                        name_utf8: String::from_utf8(entry.raw_name.clone()).ok(),
                        declared_size: DecimalU64(entry.size),
                        compressed_size: DecimalU64(entry.compressed_size),
                        compressed_byte_offset: DecimalU64(entry.data_start as u64),
                        crc32: Some(entry.crc32),
                        compression: match entry.method {
                            0 => "stored".into(),
                            8 => "deflated".into(),
                            n => format!("unsupported:{n}"),
                        },
                        is_directory: entry.raw_name.ends_with(b"/"),
                        selected_dex: selected_name(&entry.raw_name, policy.dex_selection),
                    });
                }
            }
        }
        let mut unique = BTreeSet::new();
        for member in members.iter().filter(|m| m.selected_dex) {
            if policy.reject_duplicate_selected_names && !unique.insert(member.raw_name.clone()) {
                return Err(context(
                    MddError::new(
                        ErrorCode::AmbiguousEntity,
                        "archive.selection",
                        "duplicate selected member name",
                    )
                    .detail("member_id", member.member_id.clone())
                    .detail("member_count", members.len().to_string()),
                ));
            }
        }
        let member_index = members
            .iter()
            .enumerate()
            .map(|(position, member)| (member.member_id.clone(), position))
            .collect();
        let mut result = Self {
            source: source.clone(),
            manifest: InventoryManifest {
                schema_version: "mdd.archive-inventory.v1".into(),
                source_occurrence_id: source.identity().occurrence_id.clone(),
                source_content_id: source.identity().content_id.clone(),
                selection: policy.dex_selection,
                members,
                declared_uncompressed_bytes: DecimalU64(total),
                directory_complete: true,
                selected_dex_bytes_complete: false,
                resource_byte_validation:
                    "lazy; each read checks size and CRC before returning bytes".into(),
                dex_fact_validation:
                    "unvalidated; inventory/magic do not qualify DEX headers, structure or code"
                        .into(),
            },
            entries,
            directory_start,
            selected: Vec::new(),
            member_index,
            limits,
        };
        let selected_ids: Vec<_> = result
            .manifest
            .members
            .iter()
            .filter(|m| m.selected_dex)
            .map(|m| m.member_id.clone())
            .collect();
        if policy.require_dex && selected_ids.is_empty() {
            return Err(context(MddError::new(
                ErrorCode::PartialInput,
                "archive.selection",
                "required DEX selection is empty",
            )));
        }
        for id in selected_ids {
            let mut blob = result.read_member(&id).map_err(context)?;
            let lease = blob.lease();
            let bytes: &[u8] = &lease;
            if bytes.len() < 8
                || &bytes[..4] != b"dex\n"
                || bytes[7] != 0
                || !bytes[4..7].iter().all(u8::is_ascii_digit)
            {
                return Err(context(
                    MddError::new(
                        ErrorCode::InvalidInput,
                        "archive.selected_dex_magic",
                        "selected DEX member has invalid magic",
                    )
                    .detail("member_id", id),
                ));
            }
            let version = std::str::from_utf8(&bytes[4..7])
                .map_err(|_| {
                    context(MddError::new(
                        ErrorCode::InvalidInput,
                        "archive.selected_dex_magic",
                        "invalid version digits",
                    ))
                })?
                .to_owned();
            if !matches!(version.as_str(), "035" | "037" | "038" | "039" | "040") {
                return Err(context(
                    MddError::new(
                        ErrorCode::UnsupportedCapability,
                        "archive.dex_layout",
                        "logical layout for this DEX version is not qualified",
                    )
                    .detail("member_id", id)
                    .detail("detected_version", version),
                ));
            }
            drop(lease);
            if !policy.hold_dex_bytes
                && !matches!(result.source.kind(), InputKind::RawDex)
                && let Some(index) = result.member_index.get(&id).copied()
            {
                // Checked once, above; from here on the member is decompressed again when something leases it.
                blob = blob.released(MemberReader {
                    source: result.source.clone(),
                    entry: result.entries[index].clone(),
                    directory_start: result.directory_start,
                    limits: result.limits,
                    member_id: id.clone(),
                });
            }
            result.selected.push(DexCandidate {
                physical_dex_id: format!("{}:physical-dex:0", blob.content_id),
                dex_occurrence_id: format!("{id}:dex:header:0"),
                logical_header_byte_offset: DecimalU64(0),
                detected_version: version,
                qualification: "single-header candidate only; requires independent DEX validation"
                    .into(),
                blob,
            });
        }
        result.manifest.selected_dex_bytes_complete = true;
        Ok(result)
    }

    pub fn manifest(&self) -> &InventoryManifest {
        &self.manifest
    }
    pub fn selected_dexes(&self) -> &[DexCandidate] {
        &self.selected
    }

    pub fn read_member(&self, member_id: &str) -> MddResult<MemberBlob> {
        if let Some(candidate) = self
            .selected
            .iter()
            .find(|d| d.blob.identity.member_id == member_id)
        {
            return Ok(candidate.blob.clone());
        }
        let index = *self.member_index.get(member_id).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "archive.member",
                "member identity does not belong to this captured source",
            )
        })?;
        let identity = self.manifest.members[index].clone();
        if matches!(self.source.kind(), InputKind::RawDex) {
            return Ok(MemberBlob {
                identity,
                content_id: self.source.identity().content_id.clone(),
                len: self.source.bytes().len(),
                bytes: BlobBytes::Held(self.source.lease()),
            });
        }
        let reader = MemberReader {
            source: self.source.clone(),
            entry: self.entries[index].clone(),
            directory_start: self.directory_start,
            limits: self.limits,
            member_id: member_id.to_owned(),
        };
        let output = reader.read()?;
        Ok(MemberBlob {
            identity,
            content_id: content_id(&output),
            len: output.len(),
            bytes: BlobBytes::Held(Arc::from(output)),
        })
    }
}

impl MemberBlob {
    /// The same member, its bytes let go and read again from `reader` when asked for.
    fn released(self, reader: MemberReader) -> Self {
        Self {
            bytes: BlobBytes::Lazy(Arc::new(LazyBytes {
                cache: Mutex::new(None),
                content_id: self.content_id.clone(),
                reader,
            })),
            ..self
        }
    }
}

impl MemberReader {
    /// The member's decompressed bytes, checked against its declared size and CRC.
    fn read(&self) -> MddResult<Vec<u8>> {
        let entry = &self.entry;
        let member_id = self.member_id.as_str();
        let context = |e: MddError| {
            e.detail(
                "source_occurrence_id",
                self.source.identity().occurrence_id.clone(),
            )
            .detail("member_id", member_id.to_owned())
            .detail("member_ordinal", entry.ordinal.to_string())
            .detail("input_coverage", "partial")
        };
        if entry.flags & 1 != 0 || !matches!(entry.method, 0 | 8) {
            return Err(context(MddError::new(
                ErrorCode::UnsupportedCapability,
                "archive.member",
                "encrypted or unsupported compression member is not qualified",
            )));
        }
        // Reject a hostile declared size before it can drive an allocation. The
        // directory scan already applies these limits to every member; this keeps
        // read-time allocation bounded even if an inventory is reused with a
        // tighter limit.
        let declared = usize::try_from(entry.size)
            .ok()
            .filter(|size| {
                (*size as u64) <= self.limits.max_member_bytes
                    && (*size as u64) <= self.limits.max_total_uncompressed_bytes
            })
            .ok_or_else(|| {
                context(
                    MddError::new(
                        ErrorCode::QuotaExceeded,
                        "archive.budget",
                        "declared member size exceeds budget before allocation",
                    )
                    .detail("member_bytes", entry.size.to_string())
                    .detail("limit", self.limits.max_member_bytes.to_string()),
                )
            })?;
        let view = central::MemberView::new(self.source.bytes(), self.directory_start, entry)
            .map_err(context)?;
        let mut archive = zip::ZipArchive::new(view).map_err(|e| {
            context(MddError::new(
                ErrorCode::InvalidInput,
                "archive.member",
                e.to_string(),
            ))
        })?;
        let mut file = archive.by_index(0).map_err(|e| {
            context(MddError::new(
                ErrorCode::InvalidInput,
                "archive.member",
                e.to_string(),
            ))
        })?;
        // Reserve lazily. The declared size is attacker-controlled, so an eager
        // `try_reserve_exact(declared)` turns a lying header into real committed
        // memory: a 126-byte APK declaring 512 MiB commits ~514 MiB before the
        // member fails its length check. Reserve only a bounded window up front
        // and let the vector grow geometrically as real bytes arrive, so a
        // corrupt header costs at most the window rather than its declaration.
        const EAGER_WINDOW: usize = 4 * 1024 * 1024;
        let mut output: Vec<u8> = Vec::new();
        output
            .try_reserve_exact(declared.min(EAGER_WINDOW))
            .map_err(|e| {
                context(MddError::new(
                    ErrorCode::QuotaExceeded,
                    "archive.budget",
                    e.to_string(),
                ))
            })?;
        let mut buffer = [0u8; 65536];
        loop {
            let count = file.read(&mut buffer).map_err(|e| {
                context(
                    MddError::new(
                        ErrorCode::InvalidInput,
                        "archive.member_bytes",
                        e.to_string(),
                    )
                    .detail("reason", "CRC_OR_DECOMPRESSION_FAILURE"),
                )
            })?;
            if count == 0 {
                break;
            }
            let len = output.len() as u64 + count as u64;
            if len > self.limits.max_member_bytes || len > self.limits.max_total_uncompressed_bytes
            {
                return Err(context(MddError::new(
                    ErrorCode::QuotaExceeded,
                    "archive.budget",
                    "actual decompressed output exceeds budget",
                )));
            }
            if len > entry.size {
                return Err(context(MddError::new(
                    ErrorCode::InvalidInput,
                    "archive.member_bytes",
                    "decompressed output exceeds declared member size",
                )));
            }
            output.try_reserve(count).map_err(|e| {
                context(MddError::new(
                    ErrorCode::QuotaExceeded,
                    "archive.budget",
                    e.to_string(),
                ))
            })?;
            output.extend_from_slice(&buffer[..count]);
        }
        if output.len() as u64 != entry.size {
            return Err(context(MddError::new(
                ErrorCode::InvalidInput,
                "archive.member_bytes",
                "actual decompressed length differs from declared size",
            )));
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod zip64_tests;
