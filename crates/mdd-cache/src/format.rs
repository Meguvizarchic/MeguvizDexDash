//! Binary `mdd-index/1` format encoding, a priori bounds checking, and strict SHA-256
//! verification across header, manifest, descriptor table, and section payloads.

use crate::key::{CacheMode, SemanticsIdentity, SourceOccurrenceKey};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult, sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const CACHE_FORMAT_ID: &str = "mdd-index/1";
pub const MAGIC: &[u8; 8] = b"MDDIDX1\0";
pub const FORMAT_MAJOR: u16 = 1;
pub const FORMAT_MINOR: u16 = 0;
pub const HEADER_BYTES: usize = 128;
pub const SECTION_DESCRIPTOR_BYTES: usize = 64;
pub const ENDIAN_LITTLE: u8 = 1;

pub const FLAG_STANDALONE_BLOBS: u64 = 1 << 0;
pub const FLAG_THIN_EXTERNAL_CAS: u64 = 1 << 1;
pub const KNOWN_HEADER_FLAGS: u64 = FLAG_STANDALONE_BLOBS | FLAG_THIN_EXTERNAL_CAS;

pub const SECTION_FLAG_REQUIRED: u32 = 1 << 0;
pub const KNOWN_SECTION_FLAGS: u32 = SECTION_FLAG_REQUIRED;

pub const MAX_SECTION_COUNT: u32 = 4096;
pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_SECTION_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[repr(u32)]
pub enum SectionKind {
    SnapshotAndInventory = 1,
    RelationRows = 2,
    RawCodeEvidence = 3,
    EmbeddedSourceBlob = 4,
    NegativeFindings = 5,
}

impl SectionKind {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::SnapshotAndInventory),
            2 => Some(Self::RelationRows),
            3 => Some(Self::RawCodeEvidence),
            4 => Some(Self::EmbeddedSourceBlob),
            5 => Some(Self::NegativeFindings),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexHeader {
    pub major: u16,
    pub minor: u16,
    pub header_bytes: u32,
    pub flags: u64,
    pub manifest_offset: u64,
    pub manifest_bytes: u64,
    pub section_table_offset: u64,
    pub section_count: u32,
    pub endian: u8,
    pub reserved: [u8; 11],
    pub manifest_sha256: [u8; 32],
    pub header_prefix_sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SectionDescriptor {
    pub kind: u32,
    pub flags: u32,
    pub offset: u64,
    pub stored_bytes: u64,
    pub logical_bytes: u64,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSectionMeta {
    pub kind: u32,
    pub name: String,
    pub flags: u32,
    pub offset: DecimalU64,
    pub stored_bytes: DecimalU64,
    pub logical_bytes: DecimalU64,
    pub sha256: String,
    pub row_count: Option<DecimalU64>,
    pub schema_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBlobRef {
    pub content_id: String,
    pub sha256: String,
    pub byte_length: DecimalU64,
    pub embedded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedded_section_ordinal: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cas_relative_path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageSummary {
    pub scope_id: String,
    pub input_complete: bool,
    pub facts_complete: bool,
    pub execution_complete: bool,
    pub required_layers: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexManifest {
    pub cache_format: String,
    pub engine_version: String,
    pub mode: CacheMode,
    pub semantics: SemanticsIdentity,
    pub canonical_cache_key: String,
    pub snapshot_content_key: String,
    pub section_table_sha256: String,
    pub selection_policy: String,
    pub occurrences: Vec<SourceOccurrenceKey>,
    pub source_blobs: Vec<SourceBlobRef>,
    pub sections: Vec<ManifestSectionMeta>,
    pub completed_layers: Vec<String>,
    pub coverage: CoverageSummary,
    pub validation_policy: String,
    pub applicable_formats: Vec<String>,
    pub required_capabilities: Vec<String>,
    pub compat_versions: BTreeMap<String, String>,
    pub build_reason: String,
    pub build_duration_ms: DecimalU64,
}

pub struct RawSectionInput<'a> {
    pub kind: SectionKind,
    pub flags: u32,
    pub schema_id: &'a str,
    pub name: &'a str,
    pub row_count: Option<u64>,
    pub data: &'a [u8],
}

pub struct DecodedSection<'a> {
    pub descriptor: SectionDescriptor,
    pub kind: SectionKind,
    pub bytes: &'a [u8],
}

pub struct VerifiedIndex<'a> {
    pub header: IndexHeader,
    pub descriptors: Vec<SectionDescriptor>,
    pub manifest: IndexManifest,
    pub manifest_raw: &'a [u8],
    pub sections: Vec<DecodedSection<'a>>,
}

fn corrupt(reason: &str, detail: impl Into<String>) -> MddError {
    MddError::new(ErrorCode::CacheCorrupt, "cache.format", detail)
        .detail("reason", reason.to_owned())
}

fn stale(reason: &str, detail: impl Into<String>) -> MddError {
    MddError::new(ErrorCode::StaleCache, "cache.format", detail).detail("reason", reason.to_owned())
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_u16(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}

fn read_u32(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

fn read_u64(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
        bytes[off + 5],
        bytes[off + 6],
        bytes[off + 7],
    ])
}

/// Encode a complete `mdd-index/1` image, filling in `section_table_sha256`, section payload
/// digests, `manifest_sha256`, and the 96-byte header digest cleanly.
pub fn encode_index_image(
    flags: u64,
    manifest_template: &IndexManifest,
    sections: &[RawSectionInput<'_>],
) -> MddResult<Vec<u8>> {
    if (flags & !KNOWN_HEADER_FLAGS) != 0 {
        return Err(MddError::new(
            ErrorCode::InvalidArgument,
            "cache.format",
            "unknown header flags requested for mdd-index/1 encoding",
        ));
    }
    if sections.len() > MAX_SECTION_COUNT as usize {
        return Err(MddError::new(
            ErrorCode::QuotaExceeded,
            "cache.format",
            "section count exceeds MAX_SECTION_COUNT",
        ));
    }

    let section_table_offset = HEADER_BYTES as u64;
    let table_bytes_len = (sections.len() as u64)
        .checked_mul(SECTION_DESCRIPTOR_BYTES as u64)
        .ok_or_else(|| corrupt("ARITHMETIC_OVERFLOW", "section table length overflow"))?;
    let mut cursor = section_table_offset
        .checked_add(table_bytes_len)
        .ok_or_else(|| corrupt("ARITHMETIC_OVERFLOW", "section data offset overflow"))?;

    let mut descriptors = Vec::with_capacity(sections.len());
    let mut section_metas = Vec::with_capacity(sections.len());
    let mut table_bytes = Vec::with_capacity(table_bytes_len as usize);

    for sec in sections {
        let len = sec.data.len() as u64;
        if len > MAX_SECTION_BYTES {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "cache.format",
                "section exceeds MAX_SECTION_BYTES",
            ));
        }
        let digest: [u8; 32] = Sha256::digest(sec.data).into();
        let desc = SectionDescriptor {
            kind: sec.kind as u32,
            flags: sec.flags,
            offset: cursor,
            stored_bytes: len,
            logical_bytes: len,
            sha256: digest,
        };
        table_bytes.extend_from_slice(&desc.kind.to_le_bytes());
        table_bytes.extend_from_slice(&desc.flags.to_le_bytes());
        table_bytes.extend_from_slice(&desc.offset.to_le_bytes());
        table_bytes.extend_from_slice(&desc.stored_bytes.to_le_bytes());
        table_bytes.extend_from_slice(&desc.logical_bytes.to_le_bytes());
        table_bytes.extend_from_slice(&desc.sha256);

        section_metas.push(ManifestSectionMeta {
            kind: sec.kind as u32,
            name: sec.name.to_owned(),
            flags: sec.flags,
            offset: DecimalU64(cursor),
            stored_bytes: DecimalU64(len),
            logical_bytes: DecimalU64(len),
            sha256: hex32(&digest),
            row_count: sec.row_count.map(DecimalU64),
            schema_id: sec.schema_id.to_owned(),
        });

        descriptors.push(desc);
        cursor = cursor
            .checked_add(len)
            .ok_or_else(|| corrupt("ARITHMETIC_OVERFLOW", "section payload end overflow"))?;
    }

    let mut manifest = manifest_template.clone();
    manifest.section_table_sha256 = sha256(&table_bytes);
    manifest.sections = section_metas;
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|error| {
        MddError::new(ErrorCode::InternalFault, "cache.format", error.to_string())
    })?;
    if manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(MddError::new(
            ErrorCode::QuotaExceeded,
            "cache.format",
            "manifest exceeds MAX_MANIFEST_BYTES",
        ));
    }
    let manifest_offset = cursor;
    let manifest_len = manifest_bytes.len() as u64;
    let manifest_digest: [u8; 32] = Sha256::digest(&manifest_bytes).into();
    let total_bytes = manifest_offset
        .checked_add(manifest_len)
        .ok_or_else(|| corrupt("ARITHMETIC_OVERFLOW", "total image size overflow"))?;

    let mut header_buf = [0u8; HEADER_BYTES];
    header_buf[0..8].copy_from_slice(MAGIC);
    header_buf[8..10].copy_from_slice(&FORMAT_MAJOR.to_le_bytes());
    header_buf[10..12].copy_from_slice(&FORMAT_MINOR.to_le_bytes());
    header_buf[12..16].copy_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
    header_buf[16..24].copy_from_slice(&flags.to_le_bytes());
    header_buf[24..32].copy_from_slice(&manifest_offset.to_le_bytes());
    header_buf[32..40].copy_from_slice(&manifest_len.to_le_bytes());
    header_buf[40..48].copy_from_slice(&section_table_offset.to_le_bytes());
    header_buf[48..52].copy_from_slice(&(descriptors.len() as u32).to_le_bytes());
    header_buf[52] = ENDIAN_LITTLE;
    header_buf[53..64].fill(0);
    header_buf[64..96].copy_from_slice(&manifest_digest);
    let prefix_digest: [u8; 32] = Sha256::digest(&header_buf[0..96]).into();
    header_buf[96..128].copy_from_slice(&prefix_digest);

    let total_usize = usize::try_from(total_bytes)
        .map_err(|_| corrupt("IMAGE_TOO_LARGE", "cache image exceeds host usize"))?;
    let mut out = Vec::with_capacity(total_usize);
    out.extend_from_slice(&header_buf);
    out.extend_from_slice(&table_bytes);
    for sec in sections {
        out.extend_from_slice(sec.data);
    }
    out.extend_from_slice(&manifest_bytes);
    Ok(out)
}

/// Strictly parse and cryptographically verify an `mdd-index/1` image in memory.
pub fn verify_and_decode_image<'a>(bytes: &'a [u8]) -> MddResult<VerifiedIndex<'a>> {
    let file_len = bytes.len() as u64;
    if bytes.len() < HEADER_BYTES {
        return Err(corrupt(
            "TRUNCATED_HEADER",
            format!(
                "cache file truncated ({} < {HEADER_BYTES} bytes)",
                bytes.len()
            ),
        ));
    }
    if &bytes[0..8] != MAGIC {
        return Err(corrupt("INVALID_MAGIC", "cache magic is not MDDIDX1\\0"));
    }

    let expected_prefix: [u8; 32] = Sha256::digest(&bytes[0..96]).into();
    let mut actual_prefix = [0u8; 32];
    actual_prefix.copy_from_slice(&bytes[96..128]);
    if expected_prefix != actual_prefix {
        return Err(corrupt(
            "HEADER_CHECKSUM_MISMATCH",
            "header prefix SHA-256 verification failed",
        ));
    }

    let major = read_u16(bytes, 8);
    let minor = read_u16(bytes, 10);
    let header_bytes = read_u32(bytes, 12);
    let flags = read_u64(bytes, 16);
    let manifest_offset = read_u64(bytes, 24);
    let manifest_bytes = read_u64(bytes, 32);
    let section_table_offset = read_u64(bytes, 40);
    let section_count = read_u32(bytes, 48);
    let endian = bytes[52];
    let mut reserved = [0u8; 11];
    reserved.copy_from_slice(&bytes[53..64]);
    let mut manifest_sha256 = [0u8; 32];
    manifest_sha256.copy_from_slice(&bytes[64..96]);

    if reserved.iter().any(|b| *b != 0) {
        return Err(corrupt(
            "NONZERO_RESERVED_HEADER",
            "mdd-index/1 reserved header bytes must be zero",
        ));
    }
    if endian != ENDIAN_LITTLE {
        return Err(corrupt(
            "INVALID_ENDIAN",
            format!("unsupported or corrupt endian marker: {endian}"),
        ));
    }
    if header_bytes != HEADER_BYTES as u32 {
        return Err(corrupt(
            "INVALID_HEADER_BYTES",
            format!("unexpected header_bytes {header_bytes}"),
        ));
    }
    if major != FORMAT_MAJOR {
        return Err(stale(
            "UNSUPPORTED_CACHE_VERSION",
            format!(
                "cache major version {major}.{minor} is unsupported (expected {FORMAT_MAJOR}.x)"
            ),
        ));
    }
    if (flags & !KNOWN_HEADER_FLAGS) != 0 {
        return Err(stale(
            "UNKNOWN_HEADER_FLAGS",
            format!("cache contains unsupported header flags {flags:#x}"),
        ));
    }
    if section_count > MAX_SECTION_COUNT {
        return Err(corrupt(
            "EXCESSIVE_SECTION_COUNT",
            format!("section count {section_count} exceeds {MAX_SECTION_COUNT}"),
        ));
    }
    if manifest_bytes == 0 || manifest_bytes > MAX_MANIFEST_BYTES {
        return Err(corrupt(
            "INVALID_MANIFEST_LENGTH",
            format!("manifest_bytes {manifest_bytes} out of valid bounds"),
        ));
    }

    let table_len = (section_count as u64)
        .checked_mul(SECTION_DESCRIPTOR_BYTES as u64)
        .ok_or_else(|| {
            corrupt(
                "SECTION_TABLE_OVERFLOW",
                "section table byte length overflow",
            )
        })?;
    let table_end = section_table_offset
        .checked_add(table_len)
        .ok_or_else(|| corrupt("SECTION_TABLE_OVERFLOW", "section table end overflow"))?;
    let manifest_end = manifest_offset
        .checked_add(manifest_bytes)
        .ok_or_else(|| corrupt("MANIFEST_RANGE_OVERFLOW", "manifest end overflow"))?;

    if table_end > file_len || manifest_end > file_len {
        return Err(corrupt(
            "TRUNCATED_STRUCTURE_RANGE",
            "section table or manifest extends past end of cache file",
        ));
    }

    let table_slice = &bytes[section_table_offset as usize..table_end as usize];
    let mut intervals: Vec<(u64, u64, &str)> = Vec::with_capacity(section_count as usize + 3);
    intervals.push((0, HEADER_BYTES as u64, "header"));
    if table_len > 0 {
        intervals.push((section_table_offset, table_end, "section_table"));
    }
    intervals.push((manifest_offset, manifest_end, "manifest"));

    let mut descriptors = Vec::with_capacity(section_count as usize);
    for idx in 0..section_count as usize {
        let off = idx * SECTION_DESCRIPTOR_BYTES;
        let rec = &table_slice[off..off + SECTION_DESCRIPTOR_BYTES];
        let kind = read_u32(rec, 0);
        let sec_flags = read_u32(rec, 4);
        let offset = read_u64(rec, 8);
        let stored_bytes = read_u64(rec, 16);
        let logical_bytes = read_u64(rec, 24);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&rec[32..64]);

        if stored_bytes > MAX_SECTION_BYTES || logical_bytes > MAX_SECTION_BYTES {
            return Err(corrupt(
                "SECTION_SIZE_LIMIT",
                format!("section {idx} exceeds MAX_SECTION_BYTES"),
            ));
        }
        let sec_end = offset
            .checked_add(stored_bytes)
            .ok_or_else(|| corrupt("SECTION_RANGE_OVERFLOW", "section end overflow"))?;
        if sec_end > file_len {
            return Err(corrupt(
                "TRUNCATED_SECTION",
                format!("section {idx} extends beyond EOF"),
            ));
        }
        if stored_bytes > 0 {
            intervals.push((offset, sec_end, "section_payload"));
        } else if offset > file_len {
            return Err(corrupt(
                "INVALID_ZERO_LEN_SECTION_OFFSET",
                "zero-length section offset past EOF",
            ));
        }
        descriptors.push(SectionDescriptor {
            kind,
            flags: sec_flags,
            offset,
            stored_bytes,
            logical_bytes,
            sha256: digest,
        });
    }

    intervals.sort_by_key(|item| (item.0, item.1));
    for pair in intervals.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(corrupt(
                "OVERLAPPING_INTERVALS",
                format!(
                    "{} [{}..{}) overlaps {} [{}..{})",
                    pair[0].2, pair[0].0, pair[0].1, pair[1].2, pair[1].0, pair[1].1
                ),
            ));
        }
    }

    let manifest_raw = &bytes[manifest_offset as usize..manifest_end as usize];
    let actual_manifest_digest: [u8; 32] = Sha256::digest(manifest_raw).into();
    if actual_manifest_digest != manifest_sha256 {
        return Err(corrupt(
            "MANIFEST_DIGEST_MISMATCH",
            "raw manifest bytes SHA-256 mismatch",
        ));
    }

    let manifest: IndexManifest = serde_json::from_slice(manifest_raw).map_err(|error| {
        corrupt(
            "INVALID_MANIFEST_JSON",
            format!("manifest JSON parse failed: {error}"),
        )
    })?;
    if manifest.cache_format != CACHE_FORMAT_ID {
        return Err(stale(
            "CACHE_FORMAT_MISMATCH",
            format!(
                "unexpected manifest cache_format `{}`",
                manifest.cache_format
            ),
        ));
    }
    let actual_table_sha = sha256(table_slice);
    if actual_table_sha != manifest.section_table_sha256 {
        return Err(corrupt(
            "SECTION_TABLE_DIGEST_MISMATCH",
            "section descriptor table SHA-256 disagrees with manifest section_table_sha256",
        ));
    }
    if manifest.sections.len() != descriptors.len() {
        return Err(corrupt(
            "MANIFEST_SECTION_COUNT_MISMATCH",
            "manifest section count disagrees with binary section_count",
        ));
    }

    let mut decoded_sections = Vec::with_capacity(descriptors.len());
    for (idx, (desc, meta)) in descriptors.iter().zip(manifest.sections.iter()).enumerate() {
        if meta.kind != desc.kind
            || meta.flags != desc.flags
            || meta.offset.0 != desc.offset
            || meta.stored_bytes.0 != desc.stored_bytes
            || meta.logical_bytes.0 != desc.logical_bytes
            || meta.sha256 != hex32(&desc.sha256)
        {
            return Err(corrupt(
                "MANIFEST_DESCRIPTOR_MISMATCH",
                format!("manifest descriptor {idx} disagrees with binary descriptor"),
            ));
        }
        let kind = match SectionKind::from_u32(desc.kind) {
            Some(kind) => kind,
            None => {
                return Err(stale(
                    "UNKNOWN_SECTION_KIND",
                    format!("unsupported section kind {} at index {idx}", desc.kind),
                ));
            }
        };
        if (desc.flags & !KNOWN_SECTION_FLAGS) != 0 {
            return Err(stale(
                "UNKNOWN_SECTION_FLAGS",
                format!("unsupported section flags {:#x} at index {idx}", desc.flags),
            ));
        }
        if desc.stored_bytes != desc.logical_bytes {
            return Err(stale(
                "UNSUPPORTED_SECTION_CODEC",
                format!("unsupported compressed section codec at index {idx}"),
            ));
        }
        let payload = &bytes[desc.offset as usize..(desc.offset + desc.stored_bytes) as usize];
        let payload_digest: [u8; 32] = Sha256::digest(payload).into();
        if payload_digest != desc.sha256 {
            return Err(corrupt(
                "SECTION_PAYLOAD_DIGEST_MISMATCH",
                format!("section {idx} ({:?}) payload SHA-256 mismatch", kind),
            ));
        }
        decoded_sections.push(DecodedSection {
            descriptor: desc.clone(),
            kind,
            bytes: payload,
        });
    }

    Ok(VerifiedIndex {
        header: IndexHeader {
            major,
            minor,
            header_bytes,
            flags,
            manifest_offset,
            manifest_bytes,
            section_table_offset,
            section_count,
            endian,
            reserved,
            manifest_sha256,
            header_prefix_sha256: actual_prefix,
        },
        descriptors,
        manifest,
        manifest_raw,
        sections: decoded_sections,
    })
}
