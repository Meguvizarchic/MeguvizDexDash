//! Dedicated DEX `041` physical container validator and multi-logical-DEX string/header extractor.
//!
//! Strictly separated from `crates/mdd-dex/src/header.rs` so standard `035–040` validation is
//! never numerically widened. All container-level addresses use [`ContainerOffset`] explicitly.

use super::address::ContainerOffset;
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult, sha256};
use serde::{Deserialize, Serialize};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use std::collections::BTreeSet;

pub const DEX_041_MAGIC: &[u8; 8] = b"dex\n041\0";
pub const DEX_041_HEADER_SIZE: u32 = 120;
pub const ENDIAN_CONSTANT: u32 = 0x12345678;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Dex041StringEntry {
    pub logical_dex_ordinal: u32,
    pub local_string_idx: u32,
    pub data_container_offset: ContainerOffset,
    pub declared_utf16_length: u32,
    pub shared_across_dexes: bool,
    pub in_shared_tail_region: bool,
    pub value: String,
    pub raw_mutf8_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LogicalDex041 {
    pub logical_dex_ordinal: u32,
    pub header_offset: ContainerOffset,
    pub file_size: u32,
    pub container_size: u32,
    pub checksum: u32,
    pub signature_sha1: String,
    pub string_count: u32,
    pub string_ids_off: ContainerOffset,
    pub strings: Vec<Dex041StringEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Dex041ContainerReport {
    pub container_format: String,
    pub physical_container_sha256: String,
    pub physical_container_bytes: DecimalU64,
    pub logical_dex_count: u32,
    pub shared_tail_start: ContainerOffset,
    pub shared_tail_bytes: DecimalU64,
    pub shared_ranges_sha256: String,
    pub total_logical_string_occurrences: u64,
    pub physical_shared_string_offsets: u64,
    pub logical_dexes: Vec<LogicalDex041>,
}

fn invalid(reason: &str, msg: impl Into<String>, offset: ContainerOffset) -> MddError {
    MddError::new(ErrorCode::InvalidInput, "optional.dex041", msg)
        .detail("reason", reason.to_owned())
        .detail("container_offset", offset.0.to_string())
}

fn adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in bytes.chunks(5552) {
        for byte in chunk {
            a += u32::from(*byte);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

fn read_uleb128_bounded(bytes: &[u8], start: ContainerOffset, end: u64) -> MddResult<(u32, u64)> {
    let mut val = 0u32;
    for i in 0..5u64 {
        let pos = start.checked_add(i, "optional.dex041")?;
        if pos.0 >= end {
            return Err(invalid(
                "TRUNCATED_ULEB128",
                "truncated string utf16 length",
                pos,
            ));
        }
        let b = pos.slice(bytes, 1, "optional.dex041")?[0];
        if i == 4 && (b & 0xf0) != 0 {
            return Err(invalid("ULEB128_OVERFLOW", "uleb128 exceeds 32 bits", pos));
        }
        val |= u32::from(b & 0x7f) << (i * 7);
        if (b & 0x80) == 0 {
            return Ok((val, i + 1));
        }
    }
    Err(invalid(
        "ULEB128_OVERFLOW",
        "uleb128 exceeds 5 bytes",
        start,
    ))
}

fn decode_mutf8(raw: &[u8], expected_utf16_len: u32, at: ContainerOffset) -> MddResult<String> {
    let mut units = Vec::with_capacity(expected_utf16_len as usize);
    let mut i = 0usize;
    while i < raw.len() {
        let b0 = raw[i];
        if b0 < 0x80 {
            if b0 == 0 {
                return Err(invalid(
                    "EMBEDDED_RAW_NUL",
                    "unescaped NUL inside MUTF-8",
                    at,
                ));
            }
            units.push(u16::from(b0));
            i += 1;
        } else if (b0 & 0xe0) == 0xc0 {
            let Some(&b1) = raw.get(i + 1) else {
                return Err(invalid("TRUNCATED_MUTF8", "truncated 2-byte MUTF-8", at));
            };
            if (b1 & 0xc0) != 0x80 {
                return Err(invalid("INVALID_MUTF8", "bad 2-byte continuation", at));
            }
            if b0 == 0xc0 && b1 == 0x80 {
                units.push(0);
            } else {
                let cp = ((u16::from(b0 & 0x1f)) << 6) | u16::from(b1 & 0x3f);
                if cp < 0x80 {
                    return Err(invalid("OVERLONG_MUTF8", "overlong 2-byte MUTF-8", at));
                }
                units.push(cp);
            }
            i += 2;
        } else if (b0 & 0xf0) == 0xe0 {
            let (Some(&b1), Some(&b2)) = (raw.get(i + 1), raw.get(i + 2)) else {
                return Err(invalid("TRUNCATED_MUTF8", "truncated 3-byte MUTF-8", at));
            };
            if (b1 & 0xc0) != 0x80 || (b2 & 0xc0) != 0x80 {
                return Err(invalid("INVALID_MUTF8", "bad 3-byte continuation", at));
            }
            let cp = ((u16::from(b0 & 0x0f)) << 12)
                | ((u16::from(b1 & 0x3f)) << 6)
                | u16::from(b2 & 0x3f);
            if cp < 0x800 {
                return Err(invalid("OVERLONG_MUTF8", "overlong 3-byte MUTF-8", at));
            }
            units.push(cp);
            i += 3;
        } else {
            return Err(invalid(
                "INVALID_MUTF8_LEAD",
                "disallowed 4-byte or invalid MUTF-8 lead",
                at,
            ));
        }
    }
    if units.len() != expected_utf16_len as usize {
        return Err(invalid(
            "UTF16_LEN_MISMATCH",
            format!(
                "decoded UTF-16 length {} disagrees with declared {expected_utf16_len}",
                units.len()
            ),
            at,
        ));
    }
    String::from_utf16(&units)
        .map_err(|_| invalid("NONSCALAR_UTF16", "unpaired surrogate in 041 string", at))
}

struct ParsedHeaderRaw {
    header_offset: ContainerOffset,
    file_size: u32,
    container_size: u32,
    checksum: u32,
    signature_sha1: String,
    string_count: u32,
    string_ids_off: ContainerOffset,
    map_off: ContainerOffset,
}

fn parse_one_header(container: &[u8], cursor: ContainerOffset) -> MddResult<ParsedHeaderRaw> {
    let hdr = cursor.slice(container, u64::from(DEX_041_HEADER_SIZE), "optional.dex041")?;
    if &hdr[0..4] == b"dex\n" && &hdr[0..8] != DEX_041_MAGIC {
        return Err(MddError::new(
            ErrorCode::UnsupportedCapability,
            "optional.dex041",
            format!(
                "mixed DEX version inside container: expected 041, found `{}`",
                String::from_utf8_lossy(&hdr[4..7])
            ),
        )
        .detail("reason", "MIXED_CONTAINER_DEX_VERSION")
        .detail("container_offset", cursor.0.to_string()));
    }
    if &hdr[0..8] != DEX_041_MAGIC {
        return Err(invalid(
            "INVALID_041_MAGIC",
            "expected dex\\n041\\0 logical header magic",
            cursor,
        ));
    }
    let header_size = u32::from_le_bytes([hdr[36], hdr[37], hdr[38], hdr[39]]);
    if header_size != DEX_041_HEADER_SIZE {
        return Err(invalid(
            "INVALID_041_HEADER_SIZE",
            format!("041 header_size must be 120, found {header_size}"),
            cursor,
        ));
    }
    let endian = u32::from_le_bytes([hdr[40], hdr[41], hdr[42], hdr[43]]);
    if endian != ENDIAN_CONSTANT {
        return Err(invalid(
            "INVALID_ENDIAN_TAG",
            format!("unsupported or invalid endian tag {endian:#x}"),
            cursor,
        ));
    }
    let file_size = u32::from_le_bytes([hdr[32], hdr[33], hdr[34], hdr[35]]);
    let container_size = u32::from_le_bytes([hdr[112], hdr[113], hdr[114], hdr[115]]);
    let header_offset_declared = u32::from_le_bytes([hdr[116], hdr[117], hdr[118], hdr[119]]);

    if file_size < DEX_041_HEADER_SIZE {
        return Err(invalid(
            "ZERO_PROGRESS_OR_TINY_FILE_SIZE",
            format!("041 file_size {file_size} < 120"),
            cursor,
        ));
    }
    if u64::from(header_offset_declared) != cursor.0 {
        return Err(invalid(
            "HEADER_OFFSET_MISMATCH",
            format!(
                "declared header_offset {} differs from physical cursor {}",
                header_offset_declared, cursor.0
            ),
            cursor,
        ));
    }
    if u64::from(container_size) != container.len() as u64 {
        return Err(invalid(
            "CONTAINER_SIZE_MISMATCH",
            format!(
                "declared container_size {} differs from actual physical container length {}",
                container_size,
                container.len()
            ),
            cursor,
        ));
    }
    let end = cursor.checked_add(u64::from(file_size), "optional.dex041")?;
    if end.0 > u64::from(container_size) {
        return Err(invalid(
            "LOGICAL_DEX_PAST_CONTAINER_END",
            "logical DEX file_size exceeds physical container_size",
            cursor,
        ));
    }

    let logical_slice = cursor.slice(container, u64::from(file_size), "optional.dex041")?;
    let declared_checksum = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    let computed_checksum = adler32(&logical_slice[12..]);
    if declared_checksum != computed_checksum {
        return Err(invalid(
            "CHECKSUM_MISMATCH",
            "041 logical DEX Adler32 checksum mismatch",
            cursor,
        ));
    }
    let computed_sha1 = Sha1::digest(&logical_slice[32..]);
    if computed_sha1.as_slice() != &hdr[12..32] {
        return Err(invalid(
            "SIGNATURE_SHA1_MISMATCH",
            "041 logical DEX SHA-1 signature mismatch",
            cursor,
        ));
    }
    let signature_sha1: String = hdr[12..32].iter().map(|b| format!("{b:02x}")).collect();
    let map_off = u32::from_le_bytes([hdr[52], hdr[53], hdr[54], hdr[55]]);
    let string_count = u32::from_le_bytes([hdr[56], hdr[57], hdr[58], hdr[59]]);
    let string_ids_off = u32::from_le_bytes([hdr[60], hdr[61], hdr[62], hdr[63]]);

    Ok(ParsedHeaderRaw {
        header_offset: cursor,
        file_size,
        container_size,
        checksum: declared_checksum,
        signature_sha1,
        string_count,
        string_ids_off: ContainerOffset::from_u32(string_ids_off),
        map_off: ContainerOffset::from_u32(map_off),
    })
}

/// Validate and inspect a DEX `041` physical container strictly using `ContainerOffset` semantics.
///
/// Rejects truncated shared tail regions, out-of-bounds references, offsets pointing into any
/// logical 120B header, mixed DEX versions, zero-progress loops, and unrecognized trailing bytes.
pub fn validate_and_extract_dex041_container(container: &[u8]) -> MddResult<Dex041ContainerReport> {
    if container.len() < DEX_041_HEADER_SIZE as usize {
        return Err(invalid(
            "TRUNCATED_CONTAINER",
            "input smaller than minimum 120B DEX 041 header",
            ContainerOffset(0),
        ));
    }

    let mut headers = Vec::new();
    let mut header_ranges = Vec::new();
    let mut cursor = ContainerOffset(0);
    let container_len = container.len() as u64;

    loop {
        if cursor.0 >= container_len {
            break;
        }
        if container_len - cursor.0 < u64::from(DEX_041_HEADER_SIZE) {
            break;
        }
        let maybe_magic = cursor.slice(container, 4, "optional.dex041")?;
        if maybe_magic != b"dex\n" {
            break;
        }
        let raw = parse_one_header(container, cursor)?;
        let hdr_start = raw.header_offset.0;
        let hdr_end = hdr_start + u64::from(DEX_041_HEADER_SIZE);
        header_ranges.push((hdr_start, hdr_end));
        let next = raw
            .header_offset
            .checked_add(u64::from(raw.file_size), "optional.dex041")?;
        if next <= cursor {
            return Err(invalid(
                "ZERO_PROGRESS_LOOP",
                "logical DEX advancement did not make forward progress",
                cursor,
            ));
        }
        headers.push(raw);
        cursor = next;
    }

    if headers.is_empty() {
        return Err(invalid(
            "NO_LOGICAL_DEX_FOUND",
            "container contains no valid DEX 041 header at offset 0",
            ContainerOffset(0),
        ));
    }

    let shared_tail_start = cursor;
    let shared_tail_bytes = container_len - shared_tail_start.0;
    let over_any_header = |start: u64, end: u64| -> bool {
        header_ranges
            .iter()
            .any(|(hs, he)| start < *he && end > *hs)
    };

    // Track byte coverage in the forward-shared tail region so unrecognized trailing data fails closed.
    let mut tail_covered = vec![false; shared_tail_bytes as usize];
    let mut all_offset_ref_counts: std::collections::BTreeMap<u64, u32> =
        std::collections::BTreeMap::new();
    let mut parsed_str_items: Vec<(u32, u32, ContainerOffset, u32, String, String)> = Vec::new();

    for (ord, hdr) in headers.iter().enumerate() {
        let ord_u32 = ord as u32;
        if hdr.map_off.0 != 0 {
            if !hdr.map_off.0.is_multiple_of(4) {
                return Err(invalid(
                    "UNALIGNED_MAP_OFF",
                    "map_off must be 4-byte aligned",
                    hdr.map_off,
                ));
            }
            let map_count = hdr.map_off.read_u32(container, "optional.dex041")?;
            let map_len = 4u64 + u64::from(map_count) * 12;
            let _ = hdr.map_off.slice(container, map_len, "optional.dex041")?;
            if over_any_header(hdr.map_off.0, hdr.map_off.0 + map_len) {
                return Err(invalid(
                    "MAP_OVERLAPS_HEADER",
                    "map_list overlaps a logical 041 header",
                    hdr.map_off,
                ));
            }
        }

        if hdr.string_count > 0 {
            if !hdr.string_ids_off.0.is_multiple_of(4) {
                return Err(invalid(
                    "UNALIGNED_STRING_IDS",
                    "string_ids_off must be 4-byte aligned",
                    hdr.string_ids_off,
                ));
            }
            let ids_len = u64::from(hdr.string_count) * 4;
            let ids_end = hdr
                .string_ids_off
                .checked_add(ids_len, "optional.dex041")?
                .0;
            let logical_end = hdr.header_offset.0 + u64::from(hdr.file_size);
            if hdr.string_ids_off.0 < hdr.header_offset.0 + u64::from(DEX_041_HEADER_SIZE)
                || ids_end > logical_end
            {
                return Err(invalid(
                    "STRING_IDS_OUTSIDE_LOGICAL_DEX",
                    "string_ids array must lie within its logical DEX span",
                    hdr.string_ids_off,
                ));
            }
            for s_idx in 0..hdr.string_count {
                let entry_off = hdr
                    .string_ids_off
                    .checked_add(u64::from(s_idx) * 4, "optional.dex041")?;
                let data_off_u32 = entry_off.read_u32(container, "optional.dex041")?;
                let data_off = ContainerOffset::from_u32(data_off_u32);
                if data_off.0 >= container_len {
                    return Err(invalid(
                        "STRING_DATA_OUT_OF_CONTAINER",
                        "string_data_off exceeds container bounds",
                        data_off,
                    ));
                }
                if over_any_header(data_off.0, data_off.0 + 1) {
                    return Err(invalid(
                        "STRING_DATA_POINTS_INTO_HEADER",
                        "string_data_off points inside a 120B logical DEX header",
                        data_off,
                    ));
                }

                let (declared_utf16, uleb_len) =
                    read_uleb128_bounded(container, data_off, container_len)?;
                let mut nul_pos = None;
                let str_start = data_off.0 + uleb_len;
                for pos in str_start..container_len {
                    if container[pos as usize] == 0 {
                        nul_pos = Some(pos);
                        break;
                    }
                }
                let nul_pos = nul_pos.ok_or_else(|| {
                    invalid(
                        "TRUNCATED_SHARED_STRING_DATA",
                        "unterminated string_data item inside 041 container",
                        data_off,
                    )
                })?;
                let item_end = nul_pos + 1;
                if over_any_header(data_off.0, item_end) {
                    return Err(invalid(
                        "STRING_DATA_OVERLAPS_HEADER",
                        "string_data item overlaps a logical 041 header",
                        data_off,
                    ));
                }
                let raw_mutf8 = &container[str_start as usize..nul_pos as usize];
                let decoded = decode_mutf8(raw_mutf8, declared_utf16, data_off)?;
                let raw_hash = sha256(raw_mutf8);

                *all_offset_ref_counts.entry(data_off.0).or_insert(0) += 1;

                // Mark covered bytes inside shared tail region.
                if item_end > shared_tail_start.0 {
                    if data_off.0 < shared_tail_start.0 {
                        return Err(invalid(
                            "STRING_SPANS_TAIL_BOUNDARY",
                            "string_data crosses shared tail boundary illegally",
                            data_off,
                        ));
                    }
                    let rel_s = (data_off.0 - shared_tail_start.0) as usize;
                    let rel_e = (item_end - shared_tail_start.0) as usize;
                    for b in &mut tail_covered[rel_s..rel_e] {
                        *b = true;
                    }
                }
                parsed_str_items.push((
                    ord_u32,
                    s_idx,
                    data_off,
                    declared_utf16,
                    decoded,
                    raw_hash,
                ));
            }
        }
    }

    // Check for unrecognized / unreferenced bytes in the shared tail region (fail closed, never ignore!).
    let uncovered_tail = tail_covered
        .iter()
        .enumerate()
        .find(|(_, covered)| !**covered);
    if let Some((rel_idx, _)) = uncovered_tail {
        let bad_off = ContainerOffset(shared_tail_start.0 + rel_idx as u64);
        return Err(invalid(
            "UNRECOGNIZED_TRAILING_CONTAINER_DATA",
            "041 shared tail contains unreferenced or unrecognized trailing bytes",
            bad_off,
        ));
    }

    let mut logical_dexes: Vec<LogicalDex041> = headers
        .into_iter()
        .enumerate()
        .map(|(ord, h)| LogicalDex041 {
            logical_dex_ordinal: ord as u32,
            header_offset: h.header_offset,
            file_size: h.file_size,
            container_size: h.container_size,
            checksum: h.checksum,
            signature_sha1: h.signature_sha1,
            string_count: h.string_count,
            string_ids_off: h.string_ids_off,
            strings: Vec::new(),
        })
        .collect();

    let mut shared_offsets_set = BTreeSet::new();
    for (ord, s_idx, data_off, declared_utf16, val, raw_hash) in parsed_str_items {
        let count = all_offset_ref_counts.get(&data_off.0).copied().unwrap_or(1);
        if count > 1 {
            shared_offsets_set.insert(data_off.0);
        }
        logical_dexes[ord as usize].strings.push(Dex041StringEntry {
            logical_dex_ordinal: ord,
            local_string_idx: s_idx,
            data_container_offset: data_off,
            declared_utf16_length: declared_utf16,
            shared_across_dexes: count > 1,
            in_shared_tail_region: data_off.0 >= shared_tail_start.0,
            value: val,
            raw_mutf8_sha256: raw_hash,
        });
    }

    let total_logical_strings = logical_dexes.iter().map(|d| d.strings.len() as u64).sum();
    let tail_slice = &container[shared_tail_start.0 as usize..];
    let mut shared_hasher = Sha256::new();
    shared_hasher.update(b"mdd-dex041-shared/1\0");
    shared_hasher.update(shared_tail_start.0.to_le_bytes());
    shared_hasher.update(tail_slice);
    let shared_ranges_sha256: String = shared_hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    Ok(Dex041ContainerReport {
        container_format: "dex-041-container".to_owned(),
        physical_container_sha256: sha256(container),
        physical_container_bytes: DecimalU64(container_len),
        logical_dex_count: logical_dexes.len() as u32,
        shared_tail_start,
        shared_tail_bytes: DecimalU64(shared_tail_bytes),
        shared_ranges_sha256,
        total_logical_string_occurrences: total_logical_strings,
        physical_shared_string_offsets: shared_offsets_set.len() as u64,
        logical_dexes,
    })
}
