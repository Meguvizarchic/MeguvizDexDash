use super::central::{SourceBytes, checked, invalid, u16_at, u32_at};
use mdd_types::{ErrorCode, MddError, MddResult};

pub(super) struct Directory {
    pub count: u64,
    pub start: u64,
    pub size: u64,
    pub tail_start: usize,
}
pub(super) struct MemberSizes {
    pub size: u64,
    pub compressed: u64,
    pub offset: u64,
    pub disk: u32,
    pub zip64: bool,
}

pub(super) fn u64_at(bytes: &[u8], offset: usize) -> MddResult<u64> {
    let b = checked(bytes, offset, 8)?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

pub(super) fn host(value: u64) -> MddResult<usize> {
    usize::try_from(value).map_err(|_| invalid("ZIP64 value exceeds host address range"))
}

fn quota(message: &str, value: u64, limit: u64) -> MddError {
    MddError::new(ErrorCode::QuotaExceeded, "archive.directory", message)
        .detail("declared", value.to_string())
        .detail("limit", limit.to_string())
}

pub(super) fn directory(
    source: &SourceBytes<'_>,
    end: usize,
    max_members: usize,
    max_metadata: u64,
) -> MddResult<Directory> {
    let eocd_cow = source.read_cow(end as u64, 22)?;
    let eocd = &*eocd_cow;
    let disk = u16_at(eocd, 4)?;
    let cd_disk = u16_at(eocd, 6)?;
    let on_disk = u16_at(eocd, 8)?;
    let count = u16_at(eocd, 10)?;
    let size = u32_at(eocd, 12)?;
    let start = u32_at(eocd, 16)?;
    let locator = if let Some(at) = end.checked_sub(20) {
        let loc = source.read_cow(at as u64, 20)?;
        if &loc[..4] == b"PK\x06\x07" {
            Some((at, loc))
        } else {
            None
        }
    } else {
        None
    };
    let result = if let Some((locator, loc_cow)) = locator {
        let loc = &*loc_cow;
        let locator_disk = u32_at(loc, 4)?;
        let disks = u32_at(loc, 16)?;
        if disks == 0 {
            return Err(invalid("ZIP64 locator declares zero disks"));
        }
        if locator_disk != 0 || disks != 1 {
            return Err(MddError::new(
                ErrorCode::UnsupportedCapability,
                "archive.directory",
                "multi-volume ZIP64 is not qualified",
            ));
        }
        let record = host(u64_at(loc, 8)?)?;
        if &*source.read_cow(record as u64, 4)? != b"PK\x06\x06" {
            return Err(invalid("ZIP64 locator does not identify an end record"));
        }
        let rem_off = (record as u64)
            .checked_add(4)
            .ok_or_else(|| invalid("ZIP range overflow"))?;
        let remaining = u64_at(&source.read_cow(rem_off, 8)?, 0)?;
        if remaining < 44 {
            return Err(invalid("ZIP64 end record is shorter than fixed fields"));
        }
        let length = remaining
            .checked_add(12)
            .ok_or_else(|| invalid("ZIP64 end record length overflow"))?;
        if length > max_metadata {
            return Err(quota(
                "ZIP64 end metadata exceeds budget",
                length,
                max_metadata,
            ));
        }
        let record_end = (record as u64)
            .checked_add(length)
            .ok_or_else(|| invalid("ZIP64 end record offset overflow"))?;
        if record_end != locator as u64 {
            return Err(invalid("ZIP64 end record does not end at its locator"));
        }
        source.check_range(record, host(length)?)?;
        let rec_cow = source.read_cow(record as u64, 56)?;
        let rec = &*rec_cow;
        if u16_at(rec, 14)? < 45 {
            return Err(invalid("ZIP64 end record requires version 4.5 or later"));
        }
        let disk64 = u32_at(rec, 16)?;
        let cd_disk64 = u32_at(rec, 20)?;
        if disk64 != 0 || cd_disk64 != 0 {
            return Err(MddError::new(
                ErrorCode::UnsupportedCapability,
                "archive.directory",
                "multi-volume ZIP64 is not qualified",
            ));
        }
        let on_disk64 = u64_at(rec, 24)?;
        let count64 = u64_at(rec, 32)?;
        let size64 = u64_at(rec, 40)?;
        let start64 = u64_at(rec, 48)?;
        if on_disk64 != count64 {
            return Err(invalid("single-volume ZIP64 member counts disagree"));
        }
        for (legacy, sentinel, value) in [
            (u64::from(disk), u64::from(u16::MAX), u64::from(disk64)),
            (
                u64::from(cd_disk),
                u64::from(u16::MAX),
                u64::from(cd_disk64),
            ),
            (u64::from(on_disk), u64::from(u16::MAX), on_disk64),
            (u64::from(count), u64::from(u16::MAX), count64),
            (u64::from(size), u64::from(u32::MAX), size64),
            (u64::from(start), u64::from(u32::MAX), start64),
        ] {
            if legacy != sentinel && legacy != value {
                return Err(invalid("legacy and ZIP64 end fields disagree"));
            }
        }
        Directory {
            count: count64,
            start: start64,
            size: size64,
            tail_start: record,
        }
    } else {
        if size == u32::MAX || start == u32::MAX || disk == u16::MAX || cd_disk == u16::MAX {
            return Err(invalid("ZIP64 end sentinel has no locator"));
        }
        if disk != 0 || cd_disk != 0 {
            return Err(MddError::new(
                ErrorCode::UnsupportedCapability,
                "archive.directory",
                "multi-volume ZIP is not qualified",
            ));
        }
        if count != on_disk {
            return Err(invalid("single-volume member counts disagree"));
        }
        Directory {
            count: u64::from(count),
            start: u64::from(start),
            size: u64::from(size),
            tail_start: end,
        }
    };
    if result.count > max_members as u64 {
        return Err(quota(
            "member count exceeds budget",
            result.count,
            max_members as u64,
        ));
    }
    if result.size > max_metadata {
        return Err(quota(
            "central directory bytes exceed metadata budget",
            result.size,
            max_metadata,
        ));
    }
    if result
        .count
        .checked_mul(46)
        .is_none_or(|minimum| minimum > result.size)
    {
        return Err(invalid(
            "central directory is too short for its declared member count",
        ));
    }
    if result.start.checked_add(result.size) != Some(result.tail_start as u64) {
        return Err(invalid(
            "central directory range does not end at end records",
        ));
    }
    source.check_range(host(result.start)?, host(result.size)?)?;
    Ok(result)
}

pub(super) fn extra_payload(extra: &[u8], local_padding: bool) -> MddResult<Option<&[u8]>> {
    let mut position = 0;
    let mut found = None;
    while position < extra.len() {
        if local_padding
            && extra.len() - position < 4
            && extra[position..].iter().all(|value| *value == 0)
        {
            break;
        }
        let kind = u16_at(extra, position)?;
        let size = usize::from(u16_at(extra, position + 2)?);
        let start = position
            .checked_add(4)
            .ok_or_else(|| invalid("extra field offset overflow"))?;
        let data = checked(extra, start, size)?;
        if kind == 1 {
            if found.is_some() {
                return Err(invalid("duplicate ZIP64 extra information"));
            }
            found = Some(data);
        }
        position = start
            .checked_add(size)
            .ok_or_else(|| invalid("extra field length overflow"))?;
    }
    Ok(found)
}

pub(super) fn central_sizes(
    extra: &[u8],
    size32: u32,
    compressed32: u32,
    offset32: u32,
    disk16: u16,
) -> MddResult<MemberSizes> {
    let payload = extra_payload(extra, false)?;
    let needed = [
        size32 == u32::MAX,
        compressed32 == u32::MAX,
        offset32 == u32::MAX,
    ];
    let required =
        needed.iter().filter(|v| **v).count() * 8 + if disk16 == u16::MAX { 4 } else { 0 };
    let raw = payload.unwrap_or_default();
    if raw.len() != required {
        return Err(invalid(
            "ZIP64 central extra length does not match sentinel fields",
        ));
    }
    let mut at = 0;
    let mut values = [
        u64::from(size32),
        u64::from(compressed32),
        u64::from(offset32),
    ];
    for index in 0..3 {
        if needed[index] {
            values[index] = u64_at(raw, at)?;
            at += 8;
        }
    }
    let disk = if disk16 == u16::MAX {
        u32_at(raw, at)?
    } else {
        u32::from(disk16)
    };
    Ok(MemberSizes {
        size: values[0],
        compressed: values[1],
        offset: values[2],
        disk,
        zip64: required != 0,
    })
}

pub(super) fn local_sizes(
    extra: &[u8],
    size32: u32,
    compressed32: u32,
) -> MddResult<(u64, u64, bool)> {
    let payload = extra_payload(extra, true)?;
    if size32 == u32::MAX || compressed32 == u32::MAX {
        if size32 != u32::MAX || compressed32 != u32::MAX || payload.is_none_or(|p| p.len() != 16) {
            return Err(invalid("ZIP64 local extra must contain both size fields"));
        }
        let raw = payload.unwrap();
        return Ok((u64_at(raw, 0)?, u64_at(raw, 8)?, true));
    }
    if payload.is_some_and(|p| !p.is_empty()) {
        return Err(invalid(
            "ZIP64 local size information has no size sentinels",
        ));
    }
    Ok((u64::from(size32), u64::from(compressed32), false))
}

pub(super) fn tail(
    directory_start: u64,
    central_length: u64,
    force_zip64: bool,
) -> MddResult<Vec<u8>> {
    let record = directory_start
        .checked_add(central_length)
        .ok_or_else(|| invalid("member view directory offset overflow"))?;
    let wide = force_zip64
        || directory_start >= u64::from(u32::MAX)
        || central_length >= u64::from(u32::MAX);
    record
        .checked_add(if wide { 98 } else { 22 })
        .ok_or_else(|| invalid("member view stream length overflow"))?;
    if wide {
        let mut out = vec![0u8; 98];
        out[..4].copy_from_slice(b"PK\x06\x06");
        out[4..12].copy_from_slice(&44u64.to_le_bytes());
        out[12..14].copy_from_slice(&45u16.to_le_bytes());
        out[14..16].copy_from_slice(&45u16.to_le_bytes());
        out[24..32].copy_from_slice(&1u64.to_le_bytes());
        out[32..40].copy_from_slice(&1u64.to_le_bytes());
        out[40..48].copy_from_slice(&central_length.to_le_bytes());
        out[48..56].copy_from_slice(&directory_start.to_le_bytes());
        out[56..60].copy_from_slice(b"PK\x06\x07");
        out[64..72].copy_from_slice(&record.to_le_bytes());
        out[72..76].copy_from_slice(&1u32.to_le_bytes());
        out[76..80].copy_from_slice(b"PK\x05\x06");
        out[84..88].fill(0xff);
        out[88..96].fill(0xff);
        Ok(out)
    } else {
        let mut out = vec![0u8; 22];
        out[..4].copy_from_slice(b"PK\x05\x06");
        out[8..10].copy_from_slice(&1u16.to_le_bytes());
        out[10..12].copy_from_slice(&1u16.to_le_bytes());
        out[12..16].copy_from_slice(&(central_length as u32).to_le_bytes());
        out[16..20].copy_from_slice(&(directory_start as u32).to_le_bytes());
        Ok(out)
    }
}
