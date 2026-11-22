use crate::snapshot::CapturedSource;
use mdd_types::{ErrorCode, MddError, MddResult};
use std::io::{self, Read, Seek, SeekFrom};
use std::ops::Deref;

const WINDOW_CAP: usize = 65536;

pub(super) enum CowSlice<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl Deref for CowSlice<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum SourceBytes<'a> {
    Slice(&'a [u8]),
    Spilled(&'a CapturedSource),
}

impl<'a> SourceBytes<'a> {
    pub(super) fn from_source(source: &'a CapturedSource) -> Self {
        match source.try_bytes() {
            Some(bytes) => Self::Slice(bytes),
            None => Self::Spilled(source),
        }
    }

    pub(super) fn len_u64(self) -> u64 {
        match self {
            Self::Slice(bytes) => bytes.len() as u64,
            Self::Spilled(source) => source.byte_length(),
        }
    }

    pub(super) fn check_range(self, offset: usize, len: usize) -> MddResult<()> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| invalid("ZIP range overflow"))?;
        if (end as u64) > self.len_u64() {
            return Err(invalid("ZIP range exceeds captured source"));
        }
        Ok(())
    }

    pub(super) fn read_cow(self, offset: u64, len: usize) -> MddResult<CowSlice<'a>> {
        match self {
            Self::Slice(bytes) => {
                let start = usize::try_from(offset).map_err(|_| invalid("ZIP range overflow"))?;
                Ok(CowSlice::Borrowed(checked(bytes, start, len)?))
            }
            Self::Spilled(source) => {
                let end = u64::try_from(len)
                    .ok()
                    .and_then(|n| offset.checked_add(n))
                    .ok_or_else(|| invalid("ZIP range overflow"))?;
                if end > source.byte_length() {
                    return Err(invalid("ZIP range exceeds captured source"));
                }
                if len == 0 {
                    return Ok(CowSlice::Borrowed(&[]));
                }
                let mut out = Vec::new();
                out.try_reserve_exact(len).map_err(|e| {
                    MddError::new(ErrorCode::QuotaExceeded, "archive.directory", e.to_string())
                })?;
                out.resize(len, 0);
                source.read_exact_into(offset, &mut out)?;
                Ok(CowSlice::Owned(out))
            }
        }
    }
}

enum LocalReader<'a> {
    Slice(&'a [u8]),
    Spilled {
        source: &'a CapturedSource,
        total_len: u64,
        window: Vec<u8>,
        window_start: u64,
        window_len: usize,
        scratch: Vec<u8>,
    },
}

impl<'a> LocalReader<'a> {
    fn new(source_bytes: SourceBytes<'a>) -> Self {
        match source_bytes {
            SourceBytes::Slice(bytes) => Self::Slice(bytes),
            SourceBytes::Spilled(source) => Self::Spilled {
                source,
                total_len: source.byte_length(),
                window: Vec::new(),
                window_start: 0,
                window_len: 0,
                scratch: Vec::new(),
            },
        }
    }

    fn read_slice(&mut self, offset: usize, len: usize) -> MddResult<&[u8]> {
        match self {
            Self::Slice(bytes) => checked(bytes, offset, len),
            Self::Spilled {
                source,
                total_len,
                window,
                window_start,
                window_len,
                scratch,
            } => {
                let end = offset
                    .checked_add(len)
                    .ok_or_else(|| invalid("ZIP range overflow"))?;
                let offset_u64 = offset as u64;
                let end_u64 = end as u64;
                if end_u64 > *total_len {
                    return Err(invalid("ZIP range exceeds captured source"));
                }
                if len == 0 {
                    return Ok(&[]);
                }
                if len <= WINDOW_CAP {
                    let in_window = offset_u64 >= *window_start
                        && end_u64 <= *window_start + (*window_len as u64);
                    if !in_window {
                        let fill = (*total_len - offset_u64).min(WINDOW_CAP as u64) as usize;
                        if window.capacity() < WINDOW_CAP {
                            window.clear();
                            window.try_reserve_exact(WINDOW_CAP).map_err(|e| {
                                MddError::new(
                                    ErrorCode::QuotaExceeded,
                                    "archive.directory",
                                    e.to_string(),
                                )
                            })?;
                        }
                        window.resize(fill, 0);
                        source.read_exact_into(offset_u64, &mut window[..fill])?;
                        *window_start = offset_u64;
                        *window_len = fill;
                    }
                    let rel = (offset_u64 - *window_start) as usize;
                    return Ok(&window[rel..rel + len]);
                }
                scratch.clear();
                if scratch.capacity() < len {
                    scratch.try_reserve_exact(len).map_err(|e| {
                        MddError::new(ErrorCode::QuotaExceeded, "archive.directory", e.to_string())
                    })?;
                }
                scratch.resize(len, 0);
                source.read_exact_into(offset_u64, &mut scratch[..len])?;
                Ok(&scratch[..len])
            }
        }
    }
}

#[derive(Clone)]
pub(super) struct Entry {
    pub ordinal: usize,
    pub raw_name: Vec<u8>,
    pub flags: u16,
    pub method: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub size: u64,
    pub data_start: usize,
    local_start: usize,
    physical_end: usize,
    pub central_start: usize,
    pub central_end: usize,
    pub uses_zip64: bool,
}

pub(super) fn invalid(message: &str) -> MddError {
    MddError::new(ErrorCode::InvalidInput, "archive.directory", message)
}

pub(super) fn checked(bytes: &[u8], offset: usize, len: usize) -> MddResult<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| invalid("ZIP range overflow"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| invalid("ZIP range exceeds captured source"))
}

pub(super) fn u16_at(bytes: &[u8], offset: usize) -> MddResult<u16> {
    let value = checked(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

pub(super) fn u32_at(bytes: &[u8], offset: usize) -> MddResult<u32> {
    let value = checked(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

pub(super) fn descriptor_end(
    bytes: &[u8],
    start: usize,
    bound: usize,
    crc: u32,
    compressed: u64,
    size: u64,
    wide: bool,
) -> MddResult<usize> {
    let width = if wide { 20 } else { 12 };
    let mut candidates = Vec::new();
    for signature in [false, true] {
        let skip = if signature { 4 } else { 0 };
        let Some(end) = start.checked_add(skip + width) else {
            continue;
        };
        if end > bound {
            continue;
        }
        if signature && checked(bytes, start, 4)? != b"PK\x07\x08" {
            continue;
        }
        let at = start + skip;
        let (actual_compressed, actual_size) = if wide {
            (
                super::zip64::u64_at(bytes, at + 4)?,
                super::zip64::u64_at(bytes, at + 12)?,
            )
        } else {
            (
                u64::from(u32_at(bytes, at + 4)?),
                u64::from(u32_at(bytes, at + 8)?),
            )
        };
        if u32_at(bytes, at)? == crc && actual_compressed == compressed && actual_size == size {
            candidates.push(end);
        }
    }
    match candidates.as_slice() {
        [end] => Ok(*end),
        [] => Err(invalid("data descriptor disagrees with central member")),
        _ => Err(invalid(
            "data descriptor signature interpretation is ambiguous",
        )),
    }
}

pub(super) fn scan(
    source: &CapturedSource,
    limits: &super::ArchiveLimits,
) -> MddResult<(Vec<Entry>, usize)> {
    let source_bytes = SourceBytes::from_source(source);
    let file_len = source_bytes.len_u64();
    if file_len < 22 {
        return Err(invalid("truncated ZIP end record"));
    }
    let first = file_len.saturating_sub(22 + u64::from(u16::MAX));
    let tail_len = usize::try_from(file_len - first)
        .map_err(|_| invalid("ZIP tail exceeds host address range"))?;
    let tail = source_bytes.read_cow(first, tail_len)?;
    let tail_bytes = &*tail;
    let rel_end = (0..=tail_bytes.len() - 22)
        .rev()
        .find(|&offset| {
            tail_bytes.get(offset..offset + 4) == Some(b"PK\x05\x06")
                && u16_at(tail_bytes, offset + 20)
                    .is_ok_and(|n| offset + 22 + usize::from(n) == tail_bytes.len())
        })
        .ok_or_else(|| invalid("ZIP end record missing or comment length invalid"))?;
    let end = super::zip64::host(first + rel_end as u64)?;
    let directory = super::zip64::directory(
        &source_bytes,
        end,
        limits.max_members,
        limits.max_directory_bytes,
    )?;
    let central_start = super::zip64::host(directory.start)?;
    let central_size = super::zip64::host(directory.size)?;
    let central_end = central_start
        .checked_add(central_size)
        .ok_or_else(|| invalid("central directory length overflow"))?;
    let count = super::zip64::host(directory.count)?;
    let cd_cow = source_bytes.read_cow(central_start as u64, central_size)?;
    let cd = &*cd_cow;
    let mut local_reader = LocalReader::new(source_bytes);
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|e| MddError::new(ErrorCode::QuotaExceeded, "archive.directory", e.to_string()))?;
    let mut pos = central_start;
    let mut total = 0u64;
    for ordinal in 0..count {
        let rel = pos - central_start;
        let fixed = checked(cd, rel, 46)?;
        if &fixed[..4] != b"PK\x01\x02" {
            return Err(invalid("invalid central member header")
                .detail("member_ordinal", ordinal.to_string()));
        }
        let name_len = usize::from(u16_at(cd, rel + 28)?);
        let extra_len = usize::from(u16_at(cd, rel + 30)?);
        let comment_len = usize::from(u16_at(cd, rel + 32)?);
        let record_len = 46usize
            .checked_add(name_len)
            .and_then(|n| n.checked_add(extra_len))
            .and_then(|n| n.checked_add(comment_len))
            .ok_or_else(|| invalid("member header length overflow"))?;
        let record_end = pos
            .checked_add(record_len)
            .ok_or_else(|| invalid("member header offset overflow"))?;
        if record_end > central_end {
            return Err(invalid("member header crosses central directory"));
        }
        checked(cd, rel, record_len)?;
        let central_version = u16_at(cd, rel + 6)?;
        let flags = u16_at(cd, rel + 8)?;
        let method = u16_at(cd, rel + 10)?;
        let crc32 = u32_at(cd, rel + 16)?;
        if flags & (1 | 0x40 | 0x2000) != 0 {
            return Err(MddError::new(
                ErrorCode::UnsupportedCapability,
                "archive.directory",
                "encrypted ZIP members are not qualified",
            ));
        }
        let extra = checked(cd, rel + 46 + name_len, extra_len)?;
        let resolved = super::zip64::central_sizes(
            extra,
            u32_at(cd, rel + 24)?,
            u32_at(cd, rel + 20)?,
            u32_at(cd, rel + 42)?,
            u16_at(cd, rel + 34)?,
        )?;
        if resolved.disk != 0 {
            return Err(MddError::new(
                ErrorCode::UnsupportedCapability,
                "archive.directory",
                "multi-volume ZIP member is not qualified",
            ));
        }
        total = total.checked_add(resolved.size).ok_or_else(|| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "archive.budget",
                "uncompressed byte sum overflow",
            )
        })?;
        if resolved.size > limits.max_member_bytes || total > limits.max_total_uncompressed_bytes {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "archive.budget",
                "declared uncompressed bytes exceed budget",
            )
            .detail("member_ordinal", ordinal.to_string())
            .detail("member_bytes", resolved.size.to_string())
            .detail("total_bytes", total.to_string()));
        }
        let raw_name = checked(cd, rel + 46, name_len)?.to_vec();
        let local = super::zip64::host(resolved.offset)?;
        let (
            local_version,
            local_flags,
            local_method,
            local_crc,
            local_compressed32,
            local_size32,
            local_name_len,
            local_extra_len,
        ) = {
            let local_fixed = local_reader.read_slice(local, 30)?;
            if &local_fixed[..4] != b"PK\x03\x04" {
                return Err(invalid("invalid local member header"));
            }
            (
                u16_at(local_fixed, 4)?,
                u16_at(local_fixed, 6)?,
                u16_at(local_fixed, 8)?,
                u32_at(local_fixed, 14)?,
                u32_at(local_fixed, 18)?,
                u32_at(local_fixed, 22)?,
                usize::from(u16_at(local_fixed, 26)?),
                usize::from(u16_at(local_fixed, 28)?),
            )
        };
        if local_flags != flags || local_method != method {
            return Err(invalid("local and central member identities disagree"));
        }
        let local_name_start = local
            .checked_add(30)
            .ok_or_else(|| invalid("ZIP range overflow"))?;
        if local_reader.read_slice(local_name_start, local_name_len)? != raw_name.as_slice() {
            return Err(invalid("local and central member identities disagree"));
        }
        let local_extra_start = local_name_start
            .checked_add(local_name_len)
            .ok_or_else(|| invalid("local extra offset overflow"))?;
        let (local_size, local_compressed, local_zip64) = {
            let local_extra = local_reader.read_slice(local_extra_start, local_extra_len)?;
            super::zip64::local_sizes(local_extra, local_size32, local_compressed32)?
        };
        let uses_zip64 = resolved.zip64 || local_zip64;
        if (local_zip64 && local_version < 45) || (uses_zip64 && central_version < 45) {
            return Err(invalid("ZIP64 member requires version 4.5 or later"));
        }
        if flags & 8 == 0 {
            if local_crc != crc32
                || local_size != resolved.size
                || local_compressed != resolved.compressed
            {
                return Err(invalid("local and central sizes or CRC disagree"));
            }
        } else if (local_crc != 0 && local_crc != crc32)
            || (local_size != 0 && local_size != resolved.size)
            || (local_compressed != 0 && local_compressed != resolved.compressed)
        {
            return Err(invalid(
                "descriptor local placeholders disagree with central member",
            ));
        }
        if method == 0 && resolved.size != resolved.compressed {
            return Err(invalid(
                "stored member compressed and original sizes disagree",
            ));
        }
        let data_start = local_extra_start
            .checked_add(local_extra_len)
            .ok_or_else(|| invalid("local data offset overflow"))?;
        let data_end64 = (data_start as u64)
            .checked_add(resolved.compressed)
            .ok_or_else(|| invalid("member compressed range overflow"))?;
        let data_end = super::zip64::host(data_end64)?;
        if data_end > central_start || local >= central_start {
            return Err(invalid("member data overlaps central directory"));
        }
        source_bytes.check_range(data_start, super::zip64::host(resolved.compressed)?)?;
        let physical_end = if flags & 8 != 0 {
            let avail = central_start.saturating_sub(data_end).min(24);
            let desc_slice = local_reader.read_slice(data_end, avail)?;
            let desc_rel = descriptor_end(
                desc_slice,
                0,
                avail,
                crc32,
                resolved.compressed,
                resolved.size,
                uses_zip64,
            )?;
            data_end + desc_rel
        } else {
            data_end
        };
        entries.push(Entry {
            ordinal,
            raw_name,
            flags,
            method,
            crc32,
            compressed_size: resolved.compressed,
            size: resolved.size,
            data_start,
            local_start: local,
            physical_end,
            central_start: pos,
            central_end: record_end,
            uses_zip64,
        });
        pos = record_end;
    }
    if pos != central_end {
        let rel = pos - central_start;
        if checked(cd, rel, 4)? != b"PK\x05\x05"
            || pos.checked_add(6 + usize::from(u16_at(cd, rel + 4)?)) != Some(central_end)
        {
            return Err(invalid("central directory count or byte length disagrees"));
        }
    }
    let mut intervals: Vec<_> = entries
        .iter()
        .map(|e| (e.local_start, e.physical_end))
        .collect();
    intervals.sort_unstable();
    for pair in intervals.windows(2) {
        if pair[0].1 > pair[1].0 && pair[0] != pair[1] {
            return Err(invalid("physical member ranges partially overlap"));
        }
    }
    Ok((entries, central_start))
}

enum PrefixSource<'a> {
    Slice(&'a [u8]),
    Spilled {
        source: &'a CapturedSource,
        len: usize,
        window: Vec<u8>,
        window_start: u64,
        window_len: usize,
    },
}

enum CentralBytes<'a> {
    Slice(&'a [u8]),
    Owned(Vec<u8>),
}

impl CentralBytes<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Slice(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }
}

// zip 8.6 deduplicates names before by_index. Keep the original central ordinal,
// and expose one original central record at a time without copying compressed data.
pub(super) struct MemberView<'a> {
    prefix: PrefixSource<'a>,
    central: CentralBytes<'a>,
    end: Vec<u8>,
    position: u64,
}

impl<'a> MemberView<'a> {
    pub fn new(
        source: &'a CapturedSource,
        directory_start: usize,
        entry: &Entry,
    ) -> MddResult<Self> {
        let central_len = entry
            .central_end
            .checked_sub(entry.central_start)
            .ok_or_else(|| invalid("central entry range overflow"))?;
        let (prefix, central) = if let Some(bytes) = source.try_bytes() {
            let prefix = checked(bytes, 0, directory_start)?;
            let central = checked(bytes, entry.central_start, central_len)?;
            (PrefixSource::Slice(prefix), CentralBytes::Slice(central))
        } else {
            let total = source.byte_length();
            if (directory_start as u64) > total || (entry.central_end as u64) > total {
                return Err(invalid("ZIP range exceeds captured source"));
            }
            let central = source.read_range(entry.central_start as u64, central_len)?;
            (
                PrefixSource::Spilled {
                    source,
                    len: directory_start,
                    window: Vec::new(),
                    window_start: 0,
                    window_len: 0,
                },
                CentralBytes::Owned(central),
            )
        };
        let end = super::zip64::tail(
            directory_start as u64,
            central.as_slice().len() as u64,
            entry.uses_zip64,
        )?;
        Ok(Self {
            prefix,
            central,
            end,
            position: 0,
        })
    }

    fn prefix_len(&self) -> usize {
        match &self.prefix {
            PrefixSource::Slice(bytes) => bytes.len(),
            PrefixSource::Spilled { len, .. } => *len,
        }
    }

    fn len(&self) -> u64 {
        (self.prefix_len() as u64)
            + (self.central.as_slice().len() as u64)
            + (self.end.len() as u64)
    }
}

impl Read for MemberView<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let total_len = self.len();
        let prefix_len = self.prefix_len() as u64;
        let central_end = prefix_len + self.central.as_slice().len() as u64;
        let mut count = 0;
        while count < buffer.len() && self.position < total_len {
            if self.position < prefix_len {
                let n = (prefix_len - self.position).min((buffer.len() - count) as u64) as usize;
                match &mut self.prefix {
                    PrefixSource::Slice(prefix) => {
                        let pos = self.position as usize;
                        buffer[count..count + n].copy_from_slice(&prefix[pos..pos + n]);
                    }
                    PrefixSource::Spilled {
                        source,
                        window,
                        window_start,
                        window_len,
                        ..
                    } => {
                        let pos_u64 = self.position;
                        if n >= WINDOW_CAP {
                            source
                                .read_exact_into(pos_u64, &mut buffer[count..count + n])
                                .map_err(|error| io::Error::other(error.to_string()))?;
                        } else {
                            let end_u64 = pos_u64 + n as u64;
                            let in_window = pos_u64 >= *window_start
                                && end_u64 <= *window_start + (*window_len as u64);
                            if !in_window {
                                let fill = (prefix_len - pos_u64).min(WINDOW_CAP as u64) as usize;
                                if window.capacity() < WINDOW_CAP {
                                    window.clear();
                                    window
                                        .try_reserve_exact(WINDOW_CAP)
                                        .map_err(|error| io::Error::other(error.to_string()))?;
                                }
                                window.resize(fill, 0);
                                source
                                    .read_exact_into(pos_u64, &mut window[..fill])
                                    .map_err(|error| io::Error::other(error.to_string()))?;
                                *window_start = pos_u64;
                                *window_len = fill;
                            }
                            let rel = (pos_u64 - *window_start) as usize;
                            buffer[count..count + n].copy_from_slice(&window[rel..rel + n]);
                        }
                    }
                }
                count += n;
                self.position += n as u64;
                continue;
            }
            let part = if self.position < central_end {
                let rel = (self.position - prefix_len) as usize;
                &self.central.as_slice()[rel..]
            } else {
                let rel = (self.position - central_end) as usize;
                &self.end[rel..]
            };
            let n = part.len().min(buffer.len() - count);
            buffer[count..count + n].copy_from_slice(&part[..n]);
            count += n;
            self.position += n as u64;
        }
        Ok(count)
    }
}

impl Seek for MemberView<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let next = match from {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(n) => self.len() as i128 + n as i128,
            SeekFrom::Current(n) => self.position as i128 + n as i128,
        };
        self.position = u64::try_from(next)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid member view seek"))?;
        Ok(self.position)
    }
}
