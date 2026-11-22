//! A compact, immutable store for the rows of one relation, and the text dictionary its columns share.
//!
//! A relation is produced row by row as `SqlRow` (`Vec<SqlValue>`): every cell owns its heap data, a text cell owns a
//! UTF-16 vector, and a relation of millions of rows costs several times the size of what it says. This store keeps the
//! same rows as columns:
//!
//! * a boolean, integer or floating point column is cut into chunks of `CHUNK` rows; a chunk stores the difference of each
//!   value from the chunk's smallest in the narrowest of 0, 1, 2, 4 or 8 bytes that holds the chunk's range, so a column of
//!   file ids costs nothing and a column of class indexes costs four bytes a row at most;
//! * a text or bytes column stores a 4-byte id into a `TextDict`, which holds every distinct value of the dataset once,
//!   shared by all columns and relations;
//! * NULL is a bitmap per chunk, present only for chunks that have one.
//!
//! The store changes the representation and nothing else: `StoreCursor` hands back, row for row, exactly the `SqlRow`
//! the builder was given (same variants, same UTF-16 units, same original MUTF-8 bytes, same order). A text value that
//! is a legal non-scalar UTF-16 string is kept as such, not rewritten.
use crate::{
    control::SqlControl,
    provider::{
        PlannedScan, PositionedCursor, RowFilter, SqlColumn, SqlFactCursor, SqlRow, validate_row,
    },
    values::{SqlText, SqlType, SqlValue},
};
use mdd_query::ir::Signed64;
use mdd_query::optimized::{
    AsciiPrefixSet, matches_ascii_ci_prefix_suffix, matches_utf16_ascii_ci_prefix_suffix,
};
use mdd_types::{DecimalU64, MddResult};
use std::{
    collections::{BTreeMap, HashMap},
    ops::ControlFlow,
    sync::{Arc, Mutex, OnceLock, RwLock},
};

/// Rows per chunk. Large enough that the per-chunk header is nothing, small enough that one outlier does not widen a
/// whole column.
pub const CHUNK: usize = 1 << 16;

// ---- the text dictionary --------------------------------------------------------------------------------------------

const TAG_UTF8: u8 = 0;
const TAG_TEXT: u8 = 1;
const TAG_BYTES: u8 = 2;
const TAG_MUTF8: u8 = 3;
/// `head->middle` + `tail`: three ids of plain UTF-8 entries.
const TAG_MEMBER: u8 = 4;
/// Lower-case hexadecimal pairs separated by single spaces, kept as the bytes they spell.
const TAG_HEX: u8 = 5;

/// Texts shorter than this are stored whole; splitting them would cost more than it saves.
const MIN_SPLIT: usize = 24;

/// Hash of an entry: eight bytes at a time, then mixed so that both the low bits (the slot) and the high bits (the shard)
/// are good. Entries are compared byte for byte after the hash, so a collision costs time and never an answer.
fn hash_entry(bytes: &[u8]) -> u64 {
    const K: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut hash = (bytes.len() as u64).wrapping_mul(K);
    let (words, rest) = bytes.as_chunks::<8>();
    for word in words {
        hash = (hash ^ u64::from_le_bytes(*word)).wrapping_mul(K);
        hash ^= hash >> 29;
    }
    if !rest.is_empty() {
        let mut raw = [0u8; 8];
        raw[..rest.len()].copy_from_slice(rest);
        hash = (hash ^ u64::from_le_bytes(raw)).wrapping_mul(K);
        hash ^= hash >> 29;
    }
    hash ^= hash >> 32;
    hash = hash.wrapping_mul(0xD6E8_FEB8_6659_FD93);
    hash ^ (hash >> 32)
}

/// Borrowed cell representation avoiding `SqlValue`/`String`/`Vec<u16>` heap copies during streaming projection.
#[derive(Debug)]
pub enum BorrowedSqlCell<'a> {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    F64Bits(u64),
    Utf8(&'a str),
    Utf16Be(&'a [u8]),
    Bytes(&'a [u8]),
    DexMutf8 { bytes: &'a [u8], utf16_units: u64 },
    Owned(SqlValue),
}

fn borrowed_cell_byte_size_and_work(cell: &BorrowedSqlCell<'_>) -> (u64, u64) {
    match cell {
        BorrowedSqlCell::Null
        | BorrowedSqlCell::Bool(_)
        | BorrowedSqlCell::I64(_)
        | BorrowedSqlCell::U64(_)
        | BorrowedSqlCell::F64Bits(_) => (16, 16),
        BorrowedSqlCell::Utf8(s) => {
            let utf16_units = if s.is_ascii() {
                s.len() as u64
            } else {
                s.encode_utf16().count() as u64
            };
            (utf16_units.saturating_mul(2), utf16_units.saturating_mul(4))
        }
        BorrowedSqlCell::Utf16Be(raw) => (raw.len() as u64, (raw.len() as u64).saturating_mul(2)),
        BorrowedSqlCell::Bytes(raw) | BorrowedSqlCell::DexMutf8 { bytes: raw, .. } => {
            (raw.len() as u64, (raw.len() as u64).saturating_mul(2))
        }
        BorrowedSqlCell::Owned(v) => {
            let size = v.byte_size();
            let work = match v {
                SqlValue::Text(text) => (text.utf16.len() as u64).saturating_mul(4),
                SqlValue::Bytes(raw) | SqlValue::DexMutf8 { bytes: raw, .. } => {
                    (raw.len() as u64).saturating_mul(2)
                }
                _ => 16,
            };
            (size, work)
        }
    }
}

/// Stream callback trait used by `RelationStore::stream_projected_ordered` and `SqlBridge`.
pub trait DirectCellRowConsumer {
    fn on_columns(&mut self, _columns: &[String]) -> MddResult<()> {
        Ok(())
    }
    fn on_start(&mut self, row_count: u64) -> MddResult<()>;
    fn begin_row(&mut self) -> MddResult<()>;
    fn push_cell(&mut self, col_idx: usize, cell: &BorrowedSqlCell<'_>) -> MddResult<()>;
    fn end_row(&mut self) -> MddResult<()>;
    fn on_finish(&mut self) -> MddResult<()>;
}

const NONE: u32 = u32::MAX;

/// The dictionary is cut into this many shards by the hash of the entry, each behind a lock of its own, so threads that
/// fill different relations meet only when they happen to look at the same shard.
const SHARDS: usize = 16;

fn shard_of(hash: u64) -> usize {
    (hash >> 60) as usize
}

/// An id is the position in the shard times the number of shards plus the shard, so the ids of a dictionary that grew
/// evenly stay as small as if it were one table.
fn compose(shard: usize, local: u32) -> u32 {
    (local << SHARDS.trailing_zeros()) | shard as u32
}

fn split(id: u32) -> (usize, u32) {
    ((id as usize) & (SHARDS - 1), id >> SHARDS.trailing_zeros())
}

struct Shard {
    /// Every entry, back to back: a tag byte and the payload (see `encode`).
    arena: Vec<u8>,
    /// Start of entry `local` in `arena`; the entry ends where the next one starts.
    starts: Vec<u32>,
    /// Open-addressing table of entry positions, `NONE` for an empty slot; its length is a power of two and at least
    /// twice the number of entries.
    slots: Vec<u32>,
}

impl Default for Shard {
    fn default() -> Self {
        Self {
            arena: Vec::new(),
            starts: Vec::new(),
            slots: vec![NONE; 1024],
        }
    }
}

/// The distinct text and byte values of a dataset, each stored once. Append-only: an id never changes meaning.
///
/// Three lossless shortcuts keep it small without knowing what a column means: a text that spells hexadecimal bytes is
/// stored as those bytes; a text of the form `head->name(rest` (a member descriptor) is stored as three shared pieces, so
/// the class descriptor, the name and the prototype are each kept once however many members use them; scalar text is
/// stored as UTF-8, a third of the size of its UTF-16 form.
///
/// Many threads may intern at once. The bytes of an entry are worked out before any lock is taken; a value that is in
/// the dictionary already (nearly every one, after the first DEX) is found under a read lock.
pub struct TextDict {
    shards: [RwLock<Shard>; SHARDS],
}

impl Default for TextDict {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| RwLock::new(Shard::default())),
        }
    }
}

fn is_spaced_hex(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 2 || bytes.len() % 3 != 2 {
        return false;
    }
    bytes.chunks(3).all(|group| {
        let digits = &group[..2];
        digits
            .iter()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            && (group.len() == 2 || group[2] == b' ')
    })
}

fn nibble(digit: u8) -> u8 {
    if digit <= b'9' {
        digit - b'0'
    } else {
        digit - b'a' + 10
    }
}

/// The three pieces of a member descriptor, or `None` when `text` is not one: everything before the first `->`, the
/// name up to the first `(` or `:`, and the rest from there. Joined again as `head + "->" + name + rest` they give back
/// `text` exactly.
fn split_member(text: &str) -> Option<(&str, &str, &str)> {
    if text.len() < MIN_SPLIT {
        return None;
    }
    let arrow = text.find("->")?;
    let (head, after) = (&text[..arrow], &text[arrow + 2..]);
    let cut = after.find(['(', ':']).unwrap_or(after.len());
    Some((head, &after[..cut], &after[cut..]))
}

impl Shard {
    fn entry(&self, local: u32) -> &[u8] {
        let start = self.starts[local as usize] as usize;
        let end = self
            .starts
            .get(local as usize + 1)
            .map_or(self.arena.len(), |next| *next as usize);
        &self.arena[start..end]
    }

    /// The position of the entry with exactly these bytes, or the empty slot where it belongs.
    fn find(&self, entry: &[u8], hash: u64) -> Result<u32, usize> {
        let mask = self.slots.len() - 1;
        let mut at = hash as usize & mask;
        loop {
            match self.slots[at] {
                NONE => return Err(at),
                local if self.entry(local) == entry => return Ok(local),
                _ => at = (at + 1) & mask,
            }
        }
    }

    fn grow(&mut self) {
        let wanted = (self.slots.len() * 2).max(1024);
        self.slots = vec![NONE; wanted];
        let mask = wanted - 1;
        for local in 0..self.starts.len() as u32 {
            let mut at = hash_entry(self.entry(local)) as usize & mask;
            while self.slots[at] != NONE {
                at = (at + 1) & mask;
            }
            self.slots[at] = local;
        }
    }

    /// Append an entry that `find` said is not here, at the slot `find` returned.
    fn insert(&mut self, entry: &[u8], slot: usize) -> u32 {
        let local = u32::try_from(self.starts.len()).expect("fewer than 2^28 distinct values");
        debug_assert!(local < (1 << (32 - SHARDS.trailing_zeros())));
        let start = u32::try_from(self.arena.len()).expect("a dictionary shard under 4 GiB");
        if self.starts.len() == self.starts.capacity() {
            self.starts
                .reserve_exact((self.starts.len() / 4).clamp(4096, 131_072));
        }
        self.starts.push(start);
        if self.arena.len().saturating_add(entry.len()) > self.arena.capacity() {
            let growth = entry
                .len()
                .max((self.arena.len() / 4).clamp(64 * 1024, 2 * 1024 * 1024));
            self.arena.reserve_exact(growth);
        }
        self.arena.extend_from_slice(entry);
        self.slots[slot] = local;
        if self.starts.len() * 2 > self.slots.len() {
            self.grow();
        }
        local
    }
}

fn with_tagged_entry<R>(tag: u8, payload: &[u8], f: impl FnOnce(&[u8]) -> R) -> R {
    const STACK: usize = 256;
    if payload.len() < STACK {
        let mut entry = [0u8; STACK];
        entry[0] = tag;
        entry[1..=payload.len()].copy_from_slice(payload);
        f(&entry[..=payload.len()])
    } else {
        let mut entry = Vec::with_capacity(1 + payload.len());
        entry.push(tag);
        entry.extend_from_slice(payload);
        f(&entry)
    }
}

fn decode_spaced_hex(utf8: &str) -> Vec<u8> {
    let mut entry = Vec::with_capacity(utf8.len() / 3 + 1);
    entry.extend(
        utf8.as_bytes()
            .chunks(3)
            .map(|group| nibble(group[0]) << 4 | nibble(group[1])),
    );
    entry
}

#[inline]
pub(crate) fn sql_scan_opt_enabled() -> bool {
    std::env::var_os("MDD_OPT_SQL_SCAN").as_deref() != Some(std::ffi::OsStr::new("0"))
}

#[inline]
pub(crate) fn sql_fast_udf_enabled() -> bool {
    std::env::var_os("MDD_OPT_SQL_FAST_UDF").as_deref() != Some(std::ffi::OsStr::new("0"))
}

#[inline]
fn encode_utf8_as_text_blob(bytes: &[u8], out: &mut Vec<u8>) {
    if bytes.is_ascii() {
        out.reserve(bytes.len() * 2);
        for &b in bytes {
            out.push(0);
            out.push(b);
        }
        return;
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        for u in s.encode_utf16() {
            out.extend_from_slice(&u.to_be_bytes());
        }
    }
}

#[inline]
fn utf8_utf16_bytes(bytes: &[u8]) -> Option<u64> {
    if bytes.is_ascii() {
        return Some((bytes.len() as u64).saturating_mul(2));
    }
    let s = std::str::from_utf8(bytes).ok()?;
    Some((s.encode_utf16().count() as u64).saturating_mul(2))
}

#[inline]
fn member_head_matches_or_needs_full(head: &[u8], prefix: &[u8]) -> Option<bool> {
    if head.is_empty() {
        return None;
    }
    if head.len() >= prefix.len() {
        Some(head[..prefix.len()].eq_ignore_ascii_case(prefix))
    } else if prefix[..head.len()].eq_ignore_ascii_case(head) {
        None
    } else {
        Some(false)
    }
}

impl TextDict {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn lookup_entry(&self, entry: &[u8]) -> Option<u32> {
        let hash = hash_entry(entry);
        let shard_at = shard_of(hash);
        self.shards[shard_at]
            .read()
            .expect("dictionary lock")
            .find(entry, hash)
            .ok()
            .map(|local| compose(shard_at, local))
    }

    fn lookup_tagged(&self, tag: u8, payload: &[u8]) -> Option<u32> {
        with_tagged_entry(tag, payload, |entry| self.lookup_entry(entry))
    }

    /// Look up the dictionary id of a scalar text without mutating the dictionary.
    pub fn lookup_str(&self, utf8: &str) -> Option<u32> {
        if is_spaced_hex(utf8) {
            let entry = decode_spaced_hex(utf8);
            return self.lookup_tagged(TAG_HEX, &entry);
        }
        if let Some((head, name, rest)) = split_member(utf8) {
            let mut payload = [0u8; 12];
            for (n, part) in [head, name, rest].into_iter().enumerate() {
                let id = self.lookup_tagged(TAG_UTF8, part.as_bytes())?;
                payload[n * 4..n * 4 + 4].copy_from_slice(&id.to_le_bytes());
            }
            return self.lookup_tagged(TAG_MEMBER, &payload);
        }
        self.lookup_tagged(TAG_UTF8, utf8.as_bytes())
    }

    #[inline]
    fn contains_ascii_ci(haystack: &[u8], lower_needle: &[u8]) -> bool {
        let n = lower_needle.len();
        if n == 0 {
            return true;
        }
        if haystack.len() < n {
            return false;
        }
        let first = lower_needle[0];
        for i in 0..=haystack.len() - n {
            if haystack[i].to_ascii_lowercase() == first
                && haystack[i..i + n].eq_ignore_ascii_case(lower_needle)
            {
                return true;
            }
        }
        false
    }

    #[inline]
    fn contains_any_ascii_ci(haystack: &[u8], lower_needles: &[&[u8]]) -> bool {
        lower_needles
            .iter()
            .any(|needle| Self::contains_ascii_ci(haystack, needle))
    }

    #[inline]
    fn contains_utf16_ascii_ci(units: &[u16], lower_needle: &[u8]) -> bool {
        let n = lower_needle.len();
        if n == 0 {
            return true;
        }
        if units.len() < n {
            return false;
        }
        let first = lower_needle[0];
        for i in 0..=units.len() - n {
            let u0 = units[i];
            if u0 <= 0x7F
                && (u0 as u8).to_ascii_lowercase() == first
                && units[i..i + n]
                    .iter()
                    .zip(lower_needle)
                    .all(|(&u, &b)| u <= 0x7F && (u as u8).to_ascii_lowercase() == b)
            {
                return true;
            }
        }
        false
    }

    /// Filter dictionary ids in `keys` whose text matches at least one ASCII lowercase prefix
    /// case-insensitively (`like` ASCII folding). Sound superset: any non-text entry is included.
    pub(crate) fn filter_ids_by_ascii_prefixes_ci(
        &self,
        keys: IndexKeysRef<'_>,
        lower_prefixes: &[&[u8]],
    ) -> Vec<u32> {
        self.filter_ids_by_ascii_filters_ci(keys, lower_prefixes, &[], &[])
    }

    /// Filter dictionary ids in `keys` matching any ASCII prefix, `(prefix, suffix)` pair, OR substring needle.
    pub(crate) fn filter_ids_by_ascii_filters_ci(
        &self,
        keys: IndexKeysRef<'_>,
        lower_prefixes: &[&[u8]],
        lower_pairs: &[(&[u8], &[u8])],
        lower_contains: &[&[u8]],
    ) -> Vec<u32> {
        if !sql_scan_opt_enabled() && lower_pairs.is_empty() && lower_contains.is_empty() {
            return self.filter_ids_by_ascii_prefixes_ci_legacy(keys, lower_prefixes);
        }
        if (lower_prefixes.is_empty() && lower_pairs.is_empty() && lower_contains.is_empty())
            || keys.is_empty()
        {
            return Vec::new();
        }
        let prefix_set = AsciiPrefixSet::new(lower_prefixes);
        let pair_pref_slices: Vec<&[u8]> = lower_pairs.iter().map(|(p, _)| *p).collect();
        let pair_prefix_set = AsciiPrefixSet::new(&pair_pref_slices);
        let min_pair_len = lower_pairs
            .iter()
            .map(|(p, s)| p.len().saturating_add(s.len()))
            .min()
            .unwrap_or(usize::MAX);
        let min_prefix_len = prefix_set.min_len();

        let mut buckets: [Vec<u32>; SHARDS] = std::array::from_fn(|_| Vec::new());
        match keys {
            IndexKeysRef::U32(ids) => {
                for &id in ids {
                    let (shard_idx, local) = split(id);
                    buckets[shard_idx].push(local);
                }
            }
            IndexKeysRef::U64(ids) => {
                for &key in ids {
                    let Ok(id) = u32::try_from(key) else {
                        continue;
                    };
                    let (shard_idx, local) = split(id);
                    buckets[shard_idx].push(local);
                }
            }
        }
        let mut matched = Vec::new();
        let mut member_candidates: Vec<(u32, u32, u32, u32)> = Vec::new();
        let mut fallback_ids = Vec::new();
        for (shard_idx, locals) in buckets.into_iter().enumerate() {
            if locals.is_empty() {
                continue;
            }
            let shard = self.shards[shard_idx].read().expect("dictionary lock");
            for local in locals {
                let entry = shard.entry(local);
                let id = compose(shard_idx, local);
                match entry.first().copied() {
                    Some(TAG_UTF8) => {
                        let payload = &entry[1..];
                        if prefix_set.matches_utf8(payload)
                            || (payload.len() >= min_pair_len
                                && pair_prefix_set.matches_utf8(payload)
                                && lower_pairs
                                    .iter()
                                    .any(|(p, s)| matches_ascii_ci_prefix_suffix(payload, p, s)))
                            || Self::contains_any_ascii_ci(payload, lower_contains)
                        {
                            matched.push(id);
                        }
                    }
                    Some(TAG_MEMBER) if entry.len() >= 13 => {
                        let head = u32::from_le_bytes(entry[1..5].try_into().unwrap());
                        let name = u32::from_le_bytes(entry[5..9].try_into().unwrap());
                        let rest = u32::from_le_bytes(entry[9..13].try_into().unwrap());
                        member_candidates.push((id, head, name, rest));
                    }
                    Some(_) => fallback_ids.push(id),
                    None => {}
                }
            }
        }

        // Batch `head_id` / `rest_id` (and `contains` part flags) by shard to avoid repeated per-member locking.
        if !member_candidates.is_empty() {
            let mut contains_candidates: Vec<(u32, u32, u32, u32)> = Vec::new();
            if lower_prefixes.is_empty() && lower_pairs.is_empty() {
                contains_candidates = member_candidates;
            } else {
                #[derive(Clone, Copy)]
                enum HeadDecision {
                    Miss,
                    Hit,
                    Fallback,
                    NeedSuffixMask(u64),
                    NeedSuffixMany,
                }
                let mut head_map: HashMap<u32, HeadDecision> = HashMap::new();
                let mut head_buckets: [Vec<(u32, u32)>; SHARDS] =
                    std::array::from_fn(|_| Vec::new());
                for &(_, head_id, _, _) in &member_candidates {
                    if let std::collections::hash_map::Entry::Vacant(v) = head_map.entry(head_id) {
                        v.insert(HeadDecision::Miss);
                        let (shard_idx, local) = split(head_id);
                        head_buckets[shard_idx].push((head_id, local));
                    }
                }
                let can_bitmask = lower_pairs.len() <= 64;
                let eval_head = |entry: &[u8]| -> HeadDecision {
                    if entry.first().copied() != Some(TAG_UTF8) {
                        return HeadDecision::Fallback;
                    }
                    let head = &entry[1..];
                    if head.is_empty() || prefix_set.matches_all() {
                        return if prefix_set.matches_all() {
                            HeadDecision::Hit
                        } else {
                            HeadDecision::Fallback
                        };
                    }
                    if prefix_set.matches_utf8(head) {
                        return HeadDecision::Hit;
                    }
                    for p in prefix_set.minimal_prefixes() {
                        if head.len() < p.len() && p[..head.len()].eq_ignore_ascii_case(head) {
                            return HeadDecision::Fallback;
                        }
                    }
                    if lower_pairs.is_empty() {
                        return HeadDecision::Miss;
                    }
                    let mut mask = 0u64;
                    let mut any_match = false;
                    for (idx, (p, _)) in lower_pairs.iter().enumerate() {
                        match member_head_matches_or_needs_full(head, p) {
                            None => return HeadDecision::Fallback,
                            Some(true) => {
                                any_match = true;
                                if can_bitmask {
                                    mask |= 1u64 << idx;
                                }
                            }
                            Some(false) => {}
                        }
                    }
                    if !any_match {
                        HeadDecision::Miss
                    } else if can_bitmask {
                        HeadDecision::NeedSuffixMask(mask)
                    } else {
                        HeadDecision::NeedSuffixMany
                    }
                };
                for (shard_idx, items) in head_buckets.into_iter().enumerate() {
                    if items.is_empty() {
                        continue;
                    }
                    let shard = self.shards[shard_idx].read().expect("dictionary lock");
                    for (head_id, local) in items {
                        head_map.insert(head_id, eval_head(shard.entry(local)));
                    }
                }

                type RestBucketItem = (u32, u32, u32, u32, u64);
                let mut rest_buckets: [Vec<RestBucketItem>; SHARDS] =
                    std::array::from_fn(|_| Vec::new());
                let mut many_candidates: Vec<(u32, u32, u32, u32)> = Vec::new();
                for (member_id, head_id, name_id, rest_id) in member_candidates {
                    match head_map
                        .get(&head_id)
                        .copied()
                        .unwrap_or(HeadDecision::Miss)
                    {
                        HeadDecision::Miss => {
                            if !lower_contains.is_empty() {
                                contains_candidates.push((member_id, head_id, name_id, rest_id));
                            }
                        }
                        HeadDecision::Hit => matched.push(member_id),
                        HeadDecision::Fallback => fallback_ids.push(member_id),
                        HeadDecision::NeedSuffixMask(mask) => {
                            let (shard_idx, _) = split(rest_id);
                            rest_buckets[shard_idx]
                                .push((member_id, head_id, name_id, rest_id, mask));
                        }
                        HeadDecision::NeedSuffixMany => {
                            many_candidates.push((member_id, head_id, name_id, rest_id));
                        }
                    }
                }
                for (shard_idx, items) in rest_buckets.into_iter().enumerate() {
                    if items.is_empty() {
                        continue;
                    }
                    let shard = self.shards[shard_idx].read().expect("dictionary lock");
                    for (member_id, head_id, name_id, rest_id, mask) in items {
                        let (_, local) = split(rest_id);
                        let entry = shard.entry(local);
                        if entry.first().copied() != Some(TAG_UTF8) {
                            fallback_ids.push(member_id);
                            continue;
                        }
                        let rest = &entry[1..];
                        let mut m = mask;
                        let mut suffix_verdict = 0u8; // 0=miss, 1=hit, 2=fallback
                        while m != 0 {
                            let idx = m.trailing_zeros() as usize;
                            m &= m - 1;
                            let (_, s) = lower_pairs[idx];
                            if rest.len() < s.len() {
                                suffix_verdict = 2;
                            } else if rest[rest.len() - s.len()..].eq_ignore_ascii_case(s) {
                                suffix_verdict = 1;
                                break;
                            }
                        }
                        match suffix_verdict {
                            1 => matched.push(member_id),
                            2 => fallback_ids.push(member_id),
                            _ => {
                                if !lower_contains.is_empty() {
                                    contains_candidates
                                        .push((member_id, head_id, name_id, rest_id));
                                }
                            }
                        }
                    }
                }
                for (member_id, head_id, name_id, rest_id) in many_candidates {
                    let mut suffix_verdict = 0u8;
                    let head_match_flags: Vec<bool> = self.with_entry(head_id, |entry| {
                        let head = &entry[1..];
                        lower_pairs
                            .iter()
                            .map(|(p, _)| {
                                head.len() >= p.len() && head[..p.len()].eq_ignore_ascii_case(p)
                            })
                            .collect()
                    });
                    self.with_entry(rest_id, |entry| {
                        if entry.first().copied() != Some(TAG_UTF8) {
                            suffix_verdict = 2;
                            return;
                        }
                        let rest = &entry[1..];
                        for ((_, s), matched_head) in lower_pairs.iter().zip(&head_match_flags) {
                            if !*matched_head {
                                continue;
                            }
                            if rest.len() < s.len() {
                                suffix_verdict = 2;
                                return;
                            }
                            if rest[rest.len() - s.len()..].eq_ignore_ascii_case(s) {
                                suffix_verdict = 1;
                                return;
                            }
                        }
                    });
                    match suffix_verdict {
                        1 => matched.push(member_id),
                        2 => fallback_ids.push(member_id),
                        _ => {
                            if !lower_contains.is_empty() {
                                contains_candidates.push((member_id, head_id, name_id, rest_id));
                            }
                        }
                    }
                }
            }

            if !contains_candidates.is_empty() {
                const PART_NON_UTF8: u8 = 1 << 0;
                const PART_CONTAINS_HIT: u8 = 1 << 1;
                const PART_FIRST_IN_TAIL: u8 = 1 << 2;
                let arrow_cross_possible = lower_contains
                    .iter()
                    .any(|needle| needle.iter().any(|&b| b == b'-' || b == b'>'));
                let mut part_flags: HashMap<u32, u8> = HashMap::new();
                let mut part_buckets: [Vec<(u32, u32)>; SHARDS] =
                    std::array::from_fn(|_| Vec::new());
                for &(_, head_id, name_id, rest_id) in &contains_candidates {
                    for part_id in [head_id, name_id, rest_id] {
                        if let std::collections::hash_map::Entry::Vacant(v) =
                            part_flags.entry(part_id)
                        {
                            v.insert(0);
                            let (shard_idx, local) = split(part_id);
                            part_buckets[shard_idx].push((part_id, local));
                        }
                    }
                }
                for (shard_idx, items) in part_buckets.into_iter().enumerate() {
                    if items.is_empty() {
                        continue;
                    }
                    let shard = self.shards[shard_idx].read().expect("dictionary lock");
                    for (part_id, local) in items {
                        let entry = shard.entry(local);
                        let flags = if entry.first().copied() != Some(TAG_UTF8) {
                            PART_NON_UTF8
                        } else {
                            let payload = &entry[1..];
                            let mut f = 0u8;
                            if Self::contains_any_ascii_ci(payload, lower_contains) {
                                f |= PART_CONTAINS_HIT;
                            }
                            if let Some(&first_raw) = payload.first() {
                                let first_lc = first_raw.to_ascii_lowercase();
                                if lower_contains
                                    .iter()
                                    .any(|n| n.len() >= 2 && n[1..].contains(&first_lc))
                                {
                                    f |= PART_FIRST_IN_TAIL;
                                }
                            }
                            f
                        };
                        part_flags.insert(part_id, flags);
                    }
                }
                for (member_id, head_id, name_id, rest_id) in contains_candidates {
                    let hf = part_flags.get(&head_id).copied().unwrap_or(PART_NON_UTF8);
                    let nf = part_flags.get(&name_id).copied().unwrap_or(PART_NON_UTF8);
                    let rf = part_flags.get(&rest_id).copied().unwrap_or(PART_NON_UTF8);
                    if (hf | nf | rf) & PART_NON_UTF8 != 0 {
                        fallback_ids.push(member_id);
                    } else if (hf | nf | rf) & PART_CONTAINS_HIT != 0 {
                        matched.push(member_id);
                    } else if arrow_cross_possible || (rf & PART_FIRST_IN_TAIL) != 0 {
                        fallback_ids.push(member_id);
                    }
                }
            }
        }

        for id in fallback_ids {
            match self.get(id) {
                SqlValue::Text(text) => {
                    let units = &text.utf16;
                    if (units.len() >= min_prefix_len && prefix_set.matches_utf16(units))
                        || (units.len() >= min_pair_len
                            && lower_pairs
                                .iter()
                                .any(|(p, s)| matches_utf16_ascii_ci_prefix_suffix(units, p, s)))
                        || lower_contains
                            .iter()
                            .any(|needle| Self::contains_utf16_ascii_ci(units, needle))
                    {
                        matched.push(id);
                    }
                }
                _ => matched.push(id),
            }
        }
        matched
    }

    fn filter_ids_by_ascii_prefixes_ci_legacy(
        &self,
        keys: IndexKeysRef<'_>,
        lower_prefixes: &[&[u8]],
    ) -> Vec<u32> {
        let Some(min_len) = lower_prefixes.iter().map(|p| p.len()).min() else {
            return Vec::new();
        };
        if keys.is_empty() {
            return Vec::new();
        }
        let mut buckets: [Vec<u32>; SHARDS] = std::array::from_fn(|_| Vec::new());
        match keys {
            IndexKeysRef::U32(ids) => {
                for &id in ids {
                    let (shard_idx, local) = split(id);
                    buckets[shard_idx].push(local);
                }
            }
            IndexKeysRef::U64(ids) => {
                for &key in ids {
                    let Ok(id) = u32::try_from(key) else {
                        continue;
                    };
                    let (shard_idx, local) = split(id);
                    buckets[shard_idx].push(local);
                }
            }
        }
        let mut matched = Vec::new();
        let mut fallback_ids = Vec::new();
        for (shard_idx, locals) in buckets.into_iter().enumerate() {
            if locals.is_empty() {
                continue;
            }
            let shard = self.shards[shard_idx].read().expect("dictionary lock");
            for local in locals {
                let entry = shard.entry(local);
                match entry.first().copied() {
                    Some(TAG_UTF8) => {
                        let payload = &entry[1..];
                        if payload.len() >= min_len
                            && lower_prefixes.iter().any(|p| {
                                payload.len() >= p.len()
                                    && payload[..p.len()].eq_ignore_ascii_case(p)
                            })
                        {
                            matched.push(compose(shard_idx, local));
                        }
                    }
                    Some(_) => fallback_ids.push(compose(shard_idx, local)),
                    None => {}
                }
            }
        }
        for id in fallback_ids {
            match self.get(id) {
                SqlValue::Text(text) => {
                    let units = &text.utf16;
                    if units.len() >= min_len
                        && lower_prefixes.iter().any(|p| {
                            units.len() >= p.len()
                                && units[..p.len()].iter().zip(*p).all(|(&u, &b)| {
                                    u <= 0x7F && (u as u8).to_ascii_lowercase() == b
                                })
                        })
                    {
                        matched.push(id);
                    }
                }
                _ => matched.push(id),
            }
        }
        matched
    }

    /// The id of the entry with exactly these bytes, adding it when it is new.
    fn intern_entry(&self, entry: &[u8]) -> u32 {
        let hash = hash_entry(entry);
        let shard_at = shard_of(hash);
        if let Ok(local) = self.shards[shard_at]
            .read()
            .expect("dictionary lock")
            .find(entry, hash)
        {
            return compose(shard_at, local);
        }
        let mut shard = self.shards[shard_at].write().expect("dictionary lock");
        // another thread may have added it between the two locks
        let local = match shard.find(entry, hash) {
            Ok(local) => local,
            Err(slot) => shard.insert(entry, slot),
        };
        compose(shard_at, local)
    }

    /// An entry made of a tag and a payload, without allocating for the usual short ones.
    fn intern_tagged(&self, tag: u8, payload: &[u8]) -> u32 {
        with_tagged_entry(tag, payload, |entry| self.intern_entry(entry))
    }

    /// Intern a `head->name{rest}` member descriptor reusing pre-interned `head_id` and `name_id` when
    /// `full` parses to those exact leading components.
    pub fn intern_member_with_ids(
        &self,
        full: &str,
        head: &str,
        name: &str,
        head_id: u32,
        name_id: u32,
    ) -> u32 {
        if full.len() >= MIN_SPLIT
            && !is_spaced_hex(full)
            && let Some((parsed_head, parsed_name, rest)) = split_member(full)
            && parsed_head == head
            && parsed_name == name
        {
            let utf8_part_id = |part: &str, candidate_id: u32| -> u32 {
                if !is_spaced_hex(part) && split_member(part).is_none() {
                    candidate_id
                } else {
                    self.intern_tagged(TAG_UTF8, part.as_bytes())
                }
            };
            let mut payload = [0u8; 12];
            let h_id = utf8_part_id(head, head_id);
            let n_id = utf8_part_id(name, name_id);
            let rest_id = self.intern_tagged(TAG_UTF8, rest.as_bytes());
            payload[0..4].copy_from_slice(&h_id.to_le_bytes());
            payload[4..8].copy_from_slice(&n_id.to_le_bytes());
            payload[8..12].copy_from_slice(&rest_id.to_le_bytes());
            return self.intern_tagged(TAG_MEMBER, &payload);
        }
        self.intern_str(full)
    }

    /// Intern spaced-hex bytes directly as `TAG_HEX` without allocating an intermediate `"aa bb cc"` string.
    /// An empty byte slice formats as `""`, so it uses `TAG_UTF8` to share the same dictionary id as `intern_str("")`.
    pub fn intern_spaced_hex_bytes(&self, raw: &[u8]) -> u32 {
        if raw.is_empty() {
            return self.intern_tagged(TAG_UTF8, b"");
        }
        self.intern_tagged(TAG_HEX, raw)
    }

    /// The id of a scalar text, adding it when it is new: the id `intern` gives the `SqlValue::Text` made from it.
    pub fn intern_str(&self, utf8: &str) -> u32 {
        if is_spaced_hex(utf8) {
            let entry = decode_spaced_hex(utf8);
            return self.intern_tagged(TAG_HEX, &entry);
        }
        if let Some((head, name, rest)) = split_member(utf8) {
            let mut payload = [0u8; 12];
            for (n, part) in [head, name, rest].into_iter().enumerate() {
                let id = self.intern_tagged(TAG_UTF8, part.as_bytes());
                payload[n * 4..n * 4 + 4].copy_from_slice(&id.to_le_bytes());
            }
            return self.intern_tagged(TAG_MEMBER, &payload);
        }
        self.intern_tagged(TAG_UTF8, utf8.as_bytes())
    }

    /// The id of `value`, adding it when it is new. `None` for a value that is not text or bytes.
    pub fn intern(&self, value: &SqlValue) -> Option<u32> {
        Some(match value {
            SqlValue::Text(text) => {
                if text.original_mutf8.is_none()
                    && let Ok(utf8) = String::from_utf16(&text.utf16)
                {
                    return Some(self.intern_str(&utf8));
                }
                let mut entry = Vec::with_capacity(6 + text.utf16.len() * 2);
                entry.extend_from_slice(&(text.utf16.len() as u32).to_le_bytes());
                for unit in &text.utf16 {
                    entry.extend_from_slice(&unit.to_le_bytes());
                }
                match &text.original_mutf8 {
                    None => entry.push(0),
                    Some(bytes) => {
                        entry.push(1);
                        entry.extend_from_slice(bytes);
                    }
                }
                self.intern_tagged(TAG_TEXT, &entry)
            }
            SqlValue::Bytes(bytes) => self.intern_tagged(TAG_BYTES, bytes),
            SqlValue::DexMutf8 {
                bytes,
                utf16_code_units,
            } => {
                let mut entry = Vec::with_capacity(8 + bytes.len());
                entry.extend_from_slice(&utf16_code_units.0.to_le_bytes());
                entry.extend_from_slice(bytes);
                self.intern_tagged(TAG_MUTF8, &entry)
            }
            _ => return None,
        })
    }

    /// Run `f` on the bytes of entry `id` while its shard is read-locked.
    fn with_entry<R>(&self, id: u32, f: impl FnOnce(&[u8]) -> R) -> R {
        let (shard, local) = split(id);
        let shard = self.shards[shard].read().expect("dictionary lock");
        f(shard.entry(local))
    }

    fn text_of(&self, id: u32) -> String {
        self.with_entry(id, |entry| {
            debug_assert_eq!(entry[0], TAG_UTF8, "a member piece is plain UTF-8");
            String::from_utf8(entry[1..].to_vec()).expect("a UTF-8 entry holds UTF-8")
        })
    }

    fn copy_utf8_raw_into(&self, id: u32, dst: &mut [u8], pos: &mut usize) -> bool {
        self.with_entry(id, |entry| {
            if entry.first().copied() != Some(TAG_UTF8) {
                return false;
            }
            let payload = &entry[1..];
            let Some(end) = pos.checked_add(payload.len()) else {
                return false;
            };
            if end > dst.len() {
                return false;
            }
            dst[*pos..end].copy_from_slice(payload);
            *pos = end;
            true
        })
    }

    /// Borrow `TAG_UTF8` directly or format short `TAG_MEMBER` into a stack buffer before calling `f`;
    /// falls back to `BorrowedSqlCell::Owned` for other tags or oversized members.
    pub fn with_borrowed_cell<R>(&self, id: u32, f: impl FnOnce(BorrowedSqlCell<'_>) -> R) -> R {
        let (tag, member) = {
            let (shard_idx, local) = split(id);
            let shard = self.shards[shard_idx].read().expect("dictionary lock");
            let entry = shard.entry(local);
            let tag = entry[0];
            if tag == TAG_UTF8 {
                let s = std::str::from_utf8(&entry[1..]).expect("a UTF-8 entry holds UTF-8");
                return f(BorrowedSqlCell::Utf8(s));
            }
            let member = (tag == TAG_MEMBER && entry.len() >= 13).then(|| {
                let part =
                    |n: usize| u32::from_le_bytes(entry[1 + n * 4..5 + n * 4].try_into().unwrap());
                [part(0), part(1), part(2)]
            });
            (tag, member)
        };
        if let Some([head_id, name_id, rest_id]) = member {
            let mut stack = [0u8; 512];
            let mut pos = 0usize;
            if self.copy_utf8_raw_into(head_id, &mut stack, &mut pos)
                && pos + 2 <= stack.len()
                && {
                    stack[pos..pos + 2].copy_from_slice(b"->");
                    pos += 2;
                    true
                }
                && self.copy_utf8_raw_into(name_id, &mut stack, &mut pos)
                && self.copy_utf8_raw_into(rest_id, &mut stack, &mut pos)
            {
                let s = std::str::from_utf8(&stack[..pos]).expect("a UTF-8 entry holds UTF-8");
                return f(BorrowedSqlCell::Utf8(s));
            }
        }
        let _ = tag;
        f(BorrowedSqlCell::Owned(self.get(id)))
    }

    fn copy_utf8_to_stack(&self, id: u32, stack: &mut [u8; 512]) -> Option<usize> {
        let member = {
            let (shard_idx, local) = split(id);
            let shard = self.shards[shard_idx].read().expect("dictionary lock");
            let entry = shard.entry(local);
            let tag = entry[0];
            if tag == TAG_UTF8 {
                let payload = &entry[1..];
                if payload.len() <= stack.len() {
                    stack[..payload.len()].copy_from_slice(payload);
                    return Some(payload.len());
                }
                return None;
            }
            if tag == TAG_MEMBER && entry.len() >= 13 {
                let part =
                    |n: usize| u32::from_le_bytes(entry[1 + n * 4..5 + n * 4].try_into().unwrap());
                Some([part(0), part(1), part(2)])
            } else {
                None
            }
        }?;
        let [head_id, name_id, rest_id] = member;
        let mut pos = 0usize;
        if self.copy_utf8_raw_into(head_id, stack, &mut pos)
            && pos + 2 <= stack.len()
            && {
                stack[pos..pos + 2].copy_from_slice(b"->");
                pos += 2;
                true
            }
            && self.copy_utf8_raw_into(name_id, stack, &mut pos)
            && self.copy_utf8_raw_into(rest_id, stack, &mut pos)
        {
            Some(pos)
        } else {
            None
        }
    }

    /// Compare two dictionary entries in exact UTF-16 code-unit order without heap allocation for
    /// standard scalar/member texts up to 512 UTF-8 bytes.
    pub(crate) fn cmp_text_ids(&self, left_id: u32, right_id: u32) -> std::cmp::Ordering {
        if left_id == right_id {
            return std::cmp::Ordering::Equal;
        }
        let mut buf_l = [0u8; 512];
        let mut buf_r = [0u8; 512];
        if let (Some(len_l), Some(len_r)) = (
            self.copy_utf8_to_stack(left_id, &mut buf_l),
            self.copy_utf8_to_stack(right_id, &mut buf_r),
        ) {
            let l = &buf_l[..len_l];
            let r = &buf_r[..len_r];
            if l.is_ascii() && r.is_ascii() {
                return l.cmp(r);
            }
            let ls = std::str::from_utf8(l).expect("a UTF-8 entry holds UTF-8");
            let rs = std::str::from_utf8(r).expect("a UTF-8 entry holds UTF-8");
            return ls.encode_utf16().cmp(rs.encode_utf16());
        }
        RelationStore::cmp_same_type_sql_values(&self.get(left_id), &self.get(right_id))
    }

    pub fn get(&self, id: u32) -> SqlValue {
        // a member's pieces live in other shards: copy what is needed out of this one before looking at them
        let (tag, member) = self.with_entry(id, |entry| {
            let member = (entry[0] == TAG_MEMBER).then(|| {
                let part =
                    |n: usize| u32::from_le_bytes(entry[1 + n * 4..5 + n * 4].try_into().unwrap());
                [part(0), part(1), part(2)]
            });
            (entry[0], member)
        });
        if let Some([head, name, rest]) = member {
            let (head, name, rest) = (self.text_of(head), self.text_of(name), self.text_of(rest));
            let mut text = String::with_capacity(head.len() + 2 + name.len() + rest.len());
            text.push_str(&head);
            text.push_str("->");
            text.push_str(&name);
            text.push_str(&rest);
            return SqlValue::Text(SqlText::from_utf8(&text));
        }
        self.with_entry(id, |entry| match tag {
            TAG_UTF8 => SqlValue::Text(SqlText::from_utf8(
                std::str::from_utf8(&entry[1..]).expect("a UTF-8 entry holds UTF-8"),
            )),
            TAG_HEX => {
                const DIGITS: &[u8; 16] = b"0123456789abcdef";
                let mut text = String::with_capacity(entry.len() * 3);
                for (n, byte) in entry[1..].iter().enumerate() {
                    if n != 0 {
                        text.push(' ');
                    }
                    text.push(char::from(DIGITS[usize::from(byte >> 4)]));
                    text.push(char::from(DIGITS[usize::from(byte & 15)]));
                }
                SqlValue::Text(SqlText::from_utf8(&text))
            }
            TAG_TEXT => {
                let units = u32::from_le_bytes(entry[1..5].try_into().unwrap()) as usize;
                let end = 5 + units * 2;
                let utf16 = entry[5..end]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_le_bytes(*pair))
                    .collect();
                let original_mutf8 = (entry[end] == 1).then(|| entry[end + 1..].to_vec());
                SqlValue::Text(SqlText {
                    utf16,
                    original_mutf8,
                })
            }
            TAG_BYTES => SqlValue::Bytes(entry[1..].to_vec()),
            TAG_MUTF8 => SqlValue::DexMutf8 {
                utf16_code_units: DecimalU64(u64::from_le_bytes(entry[1..9].try_into().unwrap())),
                bytes: entry[9..].to_vec(),
            },
            tag => unreachable!("unknown dictionary tag {tag}"),
        })
    }

    /// Encode `TAG_UTF8` or `TAG_MEMBER` into reusable caller buffer `out` as a SQLite `TEXT` carrier
    /// without intermediate `String`/`SqlText` buffers. Returns `Some(Ok(utf16_bytes))` on success,
    /// `Some(Err(..))` on quota failure, or `None` for non-UTF8/fallback dictionary tags.
    pub(crate) fn encode_sqlite_text_into(
        &self,
        id: u32,
        max_cell_bytes: u64,
        out: &mut Vec<u8>,
    ) -> Option<MddResult<u64>> {
        enum EncodedOrMember {
            Member([u32; 3]),
            Done(MddResult<u64>),
            NonText,
        }
        match self.with_entry(id, |entry| match entry.first().copied() {
            Some(TAG_UTF8) => {
                let payload = &entry[1..];
                let Some(text_bytes) = utf8_utf16_bytes(payload) else {
                    return EncodedOrMember::NonText;
                };
                if text_bytes > max_cell_bytes {
                    return EncodedOrMember::Done(Err(crate::quota("SQL_CELL_BYTES")));
                }
                let total_cap = crate::values::TEXT
                    .len()
                    .saturating_add(text_bytes as usize);
                out.clear();
                if out.try_reserve(total_cap).is_err() {
                    return EncodedOrMember::Done(Err(crate::quota("SQL_OUTPUT_ALLOCATION")));
                }
                out.extend_from_slice(crate::values::TEXT);
                encode_utf8_as_text_blob(payload, out);
                EncodedOrMember::Done(Ok(text_bytes))
            }
            Some(TAG_MEMBER) if entry.len() >= 13 => {
                let part =
                    |n: usize| u32::from_le_bytes(entry[1 + n * 4..5 + n * 4].try_into().unwrap());
                EncodedOrMember::Member([part(0), part(1), part(2)])
            }
            _ => EncodedOrMember::NonText,
        }) {
            EncodedOrMember::Done(res) => Some(res),
            EncodedOrMember::NonText => None,
            EncodedOrMember::Member([head_id, name_id, rest_id]) => {
                let head_bytes = self.utf8_byte_len(head_id)?;
                let name_bytes = self.utf8_byte_len(name_id)?;
                let rest_bytes = self.utf8_byte_len(rest_id)?;
                let total_text_bytes = head_bytes
                    .saturating_add(4)
                    .saturating_add(name_bytes)
                    .saturating_add(rest_bytes);
                if total_text_bytes > max_cell_bytes {
                    return Some(Err(crate::quota("SQL_CELL_BYTES")));
                }
                let total_cap = crate::values::TEXT
                    .len()
                    .saturating_add(total_text_bytes as usize);
                out.clear();
                if out.try_reserve(total_cap).is_err() {
                    return Some(Err(crate::quota("SQL_OUTPUT_ALLOCATION")));
                }
                out.extend_from_slice(crate::values::TEXT);
                self.with_entry(head_id, |e| encode_utf8_as_text_blob(&e[1..], out));
                out.extend_from_slice(&[0, b'-', 0, b'>']);
                self.with_entry(name_id, |e| encode_utf8_as_text_blob(&e[1..], out));
                self.with_entry(rest_id, |e| encode_utf8_as_text_blob(&e[1..], out));
                Some(Ok(total_text_bytes))
            }
        }
    }

    /// Encode `TAG_UTF8` or `TAG_MEMBER` directly into a SQLite `TEXT` carrier `Value::Blob` without
    /// constructing intermediate `String` / `SqlText` buffers. Returns `None` for other tags so the
    /// general `get(id).sqlite(max_cell_bytes)` path runs identically.
    pub(crate) fn sqlite_text_value(
        &self,
        id: u32,
        max_cell_bytes: u64,
    ) -> Option<MddResult<rusqlite::types::Value>> {
        let mut out = Vec::new();
        Some(
            self.encode_sqlite_text_into(id, max_cell_bytes, &mut out)?
                .map(|_| rusqlite::types::Value::Blob(out)),
        )
    }

    fn utf8_byte_len(&self, id: u32) -> Option<u64> {
        self.with_entry(id, |entry| {
            (entry.first().copied() == Some(TAG_UTF8))
                .then(|| utf8_utf16_bytes(&entry[1..]))
                .flatten()
        })
    }

    /// Number of entries, pieces of member descriptors included.
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.read().expect("dictionary lock").starts.len())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes this dictionary holds on the heap (capacity, not just length).
    pub fn bytes_used(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                let shard = shard.read().expect("dictionary lock");
                shard.arena.capacity() + shard.starts.capacity() * 4 + shard.slots.capacity() * 4
            })
            .sum()
    }

    /// Give back the room a growing vector reserved and does not use. Call it when a group of relations is built;
    /// the dictionary stays usable and grows again if more is interned.
    pub fn shrink_to_fit(&self) {
        for shard in &self.shards {
            let mut shard = shard.write().expect("dictionary lock");
            shard.arena.shrink_to_fit();
            shard.starts.shrink_to_fit();
        }
    }

    /// Entries and arena bytes by kind, in the order plain UTF-8, UTF-16 text, bytes, DEX MUTF-8, member, hex.
    pub fn kinds(&self) -> [(usize, usize); 6] {
        let mut kinds = [(0usize, 0usize); 6];
        for shard in &self.shards {
            let shard = shard.read().expect("dictionary lock");
            for local in 0..shard.starts.len() as u32 {
                let entry = shard.entry(local);
                let slot = &mut kinds[usize::from(entry[0])];
                slot.0 += 1;
                slot.1 += entry.len();
            }
        }
        kinds
    }
}

// ---- derived columns ------------------------------------------------------------------------------------------------

/// What a derived column reads from the reference tables of its row's DEX: the text of a method, a field or a type that the
/// row names by its index in that DEX.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Derive {
    MethodClass,
    MethodName,
    MethodDescriptor,
    FieldClass,
    FieldName,
    FieldDescriptor,
    FieldType,
    TypeDescriptor,
    TypeName,
}

/// A column that is not stored: its value in a row is the text `derive` names for the index in the column `index_column`,
/// taken from the reference table of the DEX that the row's partition column names.
///
/// A relation that repeats, in every one of millions of rows, the class, name and descriptor of a method that the DEX
/// lists once would keep each of them as a dictionary id in every row. The row needs only the index.
#[derive(Clone, Copy, Debug)]
pub struct DerivedColumn {
    pub column: usize,
    pub index_column: usize,
    pub derive: Derive,
}

/// The texts that the references of one DEX name, as dictionary ids, by the index the DEX gives each reference.
/// Stored in SoA layout so derived filters scan contiguous 4-byte dictionary-id arrays for the queried attribute.
#[derive(Default)]
pub struct RefTable {
    /// Per method reference: class descriptor, name, descriptor.
    pub method_class: Vec<u32>,
    pub method_name: Vec<u32>,
    pub method_desc: Vec<u32>,
    /// Per field reference: class descriptor, name, descriptor, type descriptor.
    pub field_class: Vec<u32>,
    pub field_name: Vec<u32>,
    pub field_desc: Vec<u32>,
    pub field_type: Vec<u32>,
    /// Per type: descriptor, Java name.
    pub type_desc: Vec<u32>,
    pub type_name: Vec<u32>,
    /// True when every `method_class` and `field_class` entry also appears in `type_desc` (true for valid DEX pools).
    pub type_desc_covers_member_classes: bool,
}

impl RefTable {
    pub(crate) fn slice(&self, derive: Derive) -> &[u32] {
        match derive {
            Derive::MethodClass => &self.method_class,
            Derive::MethodName => &self.method_name,
            Derive::MethodDescriptor => &self.method_desc,
            Derive::FieldClass => &self.field_class,
            Derive::FieldName => &self.field_name,
            Derive::FieldDescriptor => &self.field_desc,
            Derive::FieldType => &self.field_type,
            Derive::TypeDescriptor => &self.type_desc,
            Derive::TypeName => &self.type_name,
        }
    }

    fn id(&self, derive: Derive, index: u64) -> Option<u32> {
        let at = usize::try_from(index).ok()?;
        self.slice(derive).get(at).copied()
    }

    /// Bytes this table holds on the heap.
    pub fn bytes_used(&self) -> usize {
        (self.method_class.capacity()
            + self.method_name.capacity()
            + self.method_desc.capacity()
            + self.field_class.capacity()
            + self.field_name.capacity()
            + self.field_desc.capacity()
            + self.field_type.capacity()
            + self.type_desc.capacity()
            + self.type_name.capacity())
            * std::mem::size_of::<u32>()
    }

    pub fn shrink_to_fit(&mut self) {
        self.method_class.shrink_to_fit();
        self.method_name.shrink_to_fit();
        self.method_desc.shrink_to_fit();
        self.field_class.shrink_to_fit();
        self.field_name.shrink_to_fit();
        self.field_desc.shrink_to_fit();
        self.field_type.shrink_to_fit();
        self.type_desc.shrink_to_fit();
        self.type_name.shrink_to_fit();
    }
}

// ---- integer columns ------------------------------------------------------------------------------------------------

/// How a chunk keeps its values. Both store, for every value, its difference from the chunk's smallest in the
/// narrowest width that holds the chunk's range.
enum Payload {
    /// One entry per row.
    Plain { width: u8, data: Box<[u8]> },
    /// One entry per run of equal values: `ends[i]` is the row, within the chunk, at which run `i` stops. Chosen when it
    /// is clearly smaller, which is what a column that repeats the caller of every call row looks like.
    Runs {
        width: u8,
        values: Box<[u8]>,
        ends: Box<[u32]>,
    },
}

struct Chunk {
    base: u64,
    payload: Payload,
    /// One bit per row, set for NULL; absent when the chunk has none.
    nulls: Option<Box<[u64]>>,
}

impl Chunk {
    #[inline]
    fn payload_width(&self) -> u8 {
        match &self.payload {
            Payload::Plain { width, .. } | Payload::Runs { width, .. } => *width,
        }
    }
}

#[inline]
fn width_max_delta(width: u8) -> u64 {
    match width {
        0 => 0,
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        _ => u64::MAX,
    }
}

#[inline]
fn push_non_null_range(
    nulls: Option<&[u64]>,
    row_base: u32,
    range: std::ops::Range<usize>,
    out: &mut Vec<u32>,
) {
    if let Some(bits) = nulls {
        for at in range {
            if (bits[at >> 6] >> (at & 63)) & 1 == 0 {
                out.push(row_base + at as u32);
            }
        }
    } else {
        out.extend((row_base + range.start as u32)..(row_base + range.end as u32));
    }
}

#[inline]
fn scan_plain_deltas<P: Fn(u64) -> bool>(
    width: u8,
    data: &[u8],
    nulls: Option<&[u64]>,
    row_base: u32,
    range: std::ops::Range<usize>,
    out: &mut Vec<u32>,
    pred: P,
) {
    let start = range.start;
    match width {
        0 => {
            if pred(0) {
                push_non_null_range(nulls, row_base, range, out);
            }
        }
        1 => {
            if let Some(bits) = nulls {
                for (i, &b) in data[range].iter().enumerate() {
                    let at = start + i;
                    if (bits[at >> 6] >> (at & 63)) & 1 == 0 && pred(u64::from(b)) {
                        out.push(row_base + at as u32);
                    }
                }
            } else {
                for (i, &b) in data[range].iter().enumerate() {
                    if pred(u64::from(b)) {
                        out.push(row_base + (start + i) as u32);
                    }
                }
            }
        }
        2 => {
            let (chunks, _) = data[range.start * 2..range.end * 2].as_chunks::<2>();
            if let Some(bits) = nulls {
                for (i, &raw) in chunks.iter().enumerate() {
                    let at = start + i;
                    if (bits[at >> 6] >> (at & 63)) & 1 == 0
                        && pred(u64::from(u16::from_le_bytes(raw)))
                    {
                        out.push(row_base + at as u32);
                    }
                }
            } else {
                for (i, &raw) in chunks.iter().enumerate() {
                    if pred(u64::from(u16::from_le_bytes(raw))) {
                        out.push(row_base + (start + i) as u32);
                    }
                }
            }
        }
        4 => {
            let (chunks, _) = data[range.start * 4..range.end * 4].as_chunks::<4>();
            if let Some(bits) = nulls {
                for (i, &raw) in chunks.iter().enumerate() {
                    let at = start + i;
                    if (bits[at >> 6] >> (at & 63)) & 1 == 0
                        && pred(u64::from(u32::from_le_bytes(raw)))
                    {
                        out.push(row_base + at as u32);
                    }
                }
            } else {
                for (i, &raw) in chunks.iter().enumerate() {
                    if pred(u64::from(u32::from_le_bytes(raw))) {
                        out.push(row_base + (start + i) as u32);
                    }
                }
            }
        }
        _ => {
            let (chunks, _) = data[range.start * 8..range.end * 8].as_chunks::<8>();
            if let Some(bits) = nulls {
                for (i, &raw) in chunks.iter().enumerate() {
                    let at = start + i;
                    if (bits[at >> 6] >> (at & 63)) & 1 == 0 && pred(u64::from_le_bytes(raw)) {
                        out.push(row_base + at as u32);
                    }
                }
            } else {
                for (i, &raw) in chunks.iter().enumerate() {
                    if pred(u64::from_le_bytes(raw)) {
                        out.push(row_base + (start + i) as u32);
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Order {
    Signed,
    Unsigned,
}

impl Order {
    fn less(self, a: u64, b: u64) -> bool {
        match self {
            Self::Signed => (a as i64) < (b as i64),
            Self::Unsigned => a < b,
        }
    }
}

fn read_width(data: &[u8], index: usize, width: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw[..width].copy_from_slice(&data[index * width..(index + 1) * width]);
    u64::from_le_bytes(raw)
}

struct IntColumn {
    order: Order,
    sealed: Vec<Chunk>,
    staging: Vec<u64>,
    staging_nulls: Option<Vec<bool>>,
}

impl IntColumn {
    fn new(order: Order) -> Self {
        Self {
            order,
            sealed: Vec::new(),
            staging: Vec::new(),
            staging_nulls: None,
        }
    }

    fn push(&mut self, value: Option<u64>) {
        match value {
            Some(v) => {
                if let Some(nulls) = &mut self.staging_nulls {
                    nulls.push(false);
                }
                self.staging.push(v);
            }
            None => {
                let len = self.staging.len();
                let nulls = self.staging_nulls.get_or_insert_with(|| vec![false; len]);
                nulls.push(true);
                self.staging.push(0);
            }
        }
        if self.staging.len() == CHUNK {
            self.seal();
        }
    }

    fn seal(&mut self) {
        if self.staging.is_empty() {
            return;
        }
        let is_null =
            |row: usize| -> bool { self.staging_nulls.as_ref().is_some_and(|nulls| nulls[row]) };
        let (mut low, mut high) = (None::<u64>, None::<u64>);
        if let Some(nulls) = &self.staging_nulls {
            for (&value, &null) in self.staging.iter().zip(nulls) {
                if null {
                    continue;
                }
                if low.is_none_or(|l| self.order.less(value, l)) {
                    low = Some(value);
                }
                if high.is_none_or(|h| self.order.less(h, value)) {
                    high = Some(value);
                }
            }
        } else {
            for &value in &self.staging {
                if low.is_none_or(|l| self.order.less(value, l)) {
                    low = Some(value);
                }
                if high.is_none_or(|h| self.order.less(h, value)) {
                    high = Some(value);
                }
            }
        }
        let base = low.unwrap_or(0);
        let span = high.unwrap_or(0).wrapping_sub(base);
        let width: u8 = match span {
            0 => 0,
            1..=0xff => 1,
            0x100..=0xffff => 2,
            0x1_0000..=0xffff_ffff => 4,
            _ => 8,
        };
        // A NULL row holds a placeholder that matches its neighbour, so it never starts a run of its own.
        let delta_at = |row: usize| -> u64 {
            if is_null(row) {
                0
            } else {
                self.staging[row].wrapping_sub(base)
            }
        };
        let rows = self.staging.len();
        let wide = usize::from(width);
        let plain_size = rows * wide;
        let payload = if wide == 0 {
            Payload::Plain {
                width: 0,
                data: Box::new([]),
            }
        } else {
            let max_winning_runs = (plain_size * 3).saturating_sub(1) / ((wide + 4) * 4);
            let mut ends: Vec<u32> = Vec::new();
            let mut values: Vec<u64> = Vec::new();
            let mut exceeded = false;
            for row in 0..rows {
                let delta = if is_null(row) && row > 0 {
                    *values.last().unwrap_or(&0)
                } else {
                    delta_at(row)
                };
                if values.last() == Some(&delta) && !ends.is_empty() {
                    *ends.last_mut().unwrap() = row as u32 + 1;
                } else {
                    if values.len() >= max_winning_runs {
                        exceeded = true;
                        break;
                    }
                    values.push(delta);
                    ends.push(row as u32 + 1);
                }
            }
            if !exceeded && values.len() * (wide + 4) * 4 < plain_size * 3 {
                let mut bytes = Vec::with_capacity(values.len() * wide);
                for value in &values {
                    bytes.extend_from_slice(&value.to_le_bytes()[..wide]);
                }
                Payload::Runs {
                    width,
                    values: bytes.into_boxed_slice(),
                    ends: ends.into_boxed_slice(),
                }
            } else {
                let mut bytes = Vec::with_capacity(plain_size);
                for row in 0..rows {
                    bytes.extend_from_slice(&delta_at(row).to_le_bytes()[..wide]);
                }
                Payload::Plain {
                    width,
                    data: bytes.into_boxed_slice(),
                }
            }
        };
        let nulls = self
            .staging_nulls
            .as_ref()
            .filter(|nulls| nulls.iter().any(|n| *n))
            .map(|nulls| {
                let mut bits = vec![0u64; rows.div_ceil(64)];
                for (row, null) in nulls.iter().enumerate() {
                    if *null {
                        bits[row / 64] |= 1 << (row % 64);
                    }
                }
                bits.into_boxed_slice()
            });
        self.sealed.push(Chunk {
            base,
            payload,
            nulls,
        });
        self.staging = Vec::new();
        self.staging_nulls = None;
    }

    /// Whether every non-null value in this sealed unsigned column fits in `u32`.
    fn fits_u32_fast(&self) -> bool {
        if self.order != Order::Unsigned || !self.staging.is_empty() {
            return false;
        }
        for chunk in &self.sealed {
            match &chunk.payload {
                Payload::Plain { width, data } => match *width {
                    0 => {
                        if chunk.base > u64::from(u32::MAX) {
                            return false;
                        }
                    }
                    1 => {
                        if chunk.base > u64::from(u32::MAX) - 0xff {
                            return false;
                        }
                    }
                    2 => {
                        if chunk.base > u64::from(u32::MAX) - 0xffff {
                            return false;
                        }
                    }
                    4 => {
                        if chunk.base > u64::from(u32::MAX) {
                            return false;
                        }
                        if chunk.base > 0 {
                            let max_delta = u64::from(u32::MAX) - chunk.base;
                            if !data
                                .as_chunks::<4>()
                                .0
                                .iter()
                                .all(|raw| u64::from(u32::from_le_bytes(*raw)) <= max_delta)
                            {
                                return false;
                            }
                        }
                    }
                    _ => return false,
                },
                Payload::Runs { width, values, .. } => match *width {
                    0 => {
                        if chunk.base > u64::from(u32::MAX) {
                            return false;
                        }
                    }
                    1 => {
                        if chunk.base > u64::from(u32::MAX) - 0xff {
                            return false;
                        }
                    }
                    2 => {
                        if chunk.base > u64::from(u32::MAX) - 0xffff {
                            return false;
                        }
                    }
                    4 => {
                        if chunk.base > u64::from(u32::MAX) {
                            return false;
                        }
                        if chunk.base > 0 {
                            let max_delta = u64::from(u32::MAX) - chunk.base;
                            if !values
                                .as_chunks::<4>()
                                .0
                                .iter()
                                .all(|raw| u64::from(u32::from_le_bytes(*raw)) <= max_delta)
                            {
                                return false;
                            }
                        }
                    }
                    _ => return false,
                },
            }
        }
        true
    }

    /// The value of row `row`, or `None` for NULL. `hint` is the run the previous call of a front-to-back scan ended in;
    /// pass the same variable on every call of one scan and a run is found without a search.
    fn get(&self, row: u64, hint: &mut usize) -> Option<u64> {
        let chunk = &self.sealed[(row / CHUNK as u64) as usize];
        let at = (row % CHUNK as u64) as usize;
        if let Some(bits) = &chunk.nulls
            && bits[at / 64] >> (at % 64) & 1 == 1
        {
            return None;
        }
        let delta = match &chunk.payload {
            Payload::Plain { width, data } => read_width(data, at, usize::from(*width)),
            Payload::Runs {
                width,
                values,
                ends,
            } => {
                let in_hint = *hint < ends.len()
                    && at < ends[*hint] as usize
                    && (*hint == 0 || at >= ends[*hint - 1] as usize);
                if !in_hint {
                    *hint = ends.partition_point(|end| (*end as usize) <= at);
                }
                read_width(values, *hint, usize::from(*width))
            }
        };
        Some(chunk.base.wrapping_add(delta))
    }

    /// Append local row indices in `start..end` whose non-null value equals any entry in `targets`.
    fn collect_matching_in_range(&self, start: u64, end: u64, targets: &[u64], out: &mut Vec<u32>) {
        if start >= end || targets.is_empty() {
            return;
        }
        if !self.staging.is_empty() {
            let mut hint = 0usize;
            for row in start..end {
                if let Some(val) = self.get(row, &mut hint)
                    && targets.contains(&val)
                {
                    out.push(row as u32);
                }
            }
            return;
        }
        let first_chunk = (start / CHUNK as u64) as usize;
        let last_chunk = ((end - 1) / CHUNK as u64) as usize;
        let mut deltas_buf = Vec::new();
        for (offset, chunk) in self.sealed[first_chunk..=last_chunk].iter().enumerate() {
            let chunk_idx = first_chunk + offset;
            let chunk_start = (chunk_idx as u64) * (CHUNK as u64);
            let c_lo = start.saturating_sub(chunk_start) as usize;
            let c_hi = (end - chunk_start).min(CHUNK as u64) as usize;
            let row_base = chunk_start as u32;
            let max_delta = width_max_delta(chunk.payload_width());
            let mut single_delta = None;
            if targets.len() == 1 {
                let delta = targets[0].wrapping_sub(chunk.base);
                if delta > max_delta {
                    continue;
                }
                single_delta = Some(delta);
            } else {
                deltas_buf.clear();
                for &target in targets {
                    let delta = target.wrapping_sub(chunk.base);
                    if delta <= max_delta && !deltas_buf.contains(&delta) {
                        deltas_buf.push(delta);
                    }
                }
                if deltas_buf.is_empty() {
                    continue;
                }
                if deltas_buf.len() == 1 {
                    single_delta = Some(deltas_buf[0]);
                }
            }
            match &chunk.payload {
                Payload::Plain { width, data } => {
                    if let Some(target_delta) = single_delta {
                        scan_plain_deltas(
                            *width,
                            data,
                            chunk.nulls.as_deref(),
                            row_base,
                            c_lo..c_hi,
                            out,
                            |delta| delta == target_delta,
                        );
                    } else {
                        scan_plain_deltas(
                            *width,
                            data,
                            chunk.nulls.as_deref(),
                            row_base,
                            c_lo..c_hi,
                            out,
                            |delta| deltas_buf.contains(&delta),
                        );
                    }
                }
                Payload::Runs {
                    width,
                    values,
                    ends,
                } => {
                    let wide = usize::from(*width);
                    let nulls = chunk.nulls.as_deref();
                    let mut run = ends.partition_point(|&e| (e as usize) <= c_lo);
                    while run < ends.len() {
                        let prev_end = if run == 0 { 0 } else { ends[run - 1] as usize };
                        if prev_end >= c_hi {
                            break;
                        }
                        let r_start = c_lo.max(prev_end);
                        let r_end = c_hi.min(ends[run] as usize);
                        let delta = read_width(values, run, wide);
                        let matched = single_delta
                            .map_or_else(|| deltas_buf.contains(&delta), |d| delta == d);
                        if matched {
                            push_non_null_range(nulls, row_base, r_start..r_end, out);
                        }
                        run += 1;
                    }
                }
            }
        }
    }

    /// Append local row indices in `start..end` whose non-null value is `<= max_val` and has its bit set in `bitset`.
    fn collect_matching_bitset_in_range(
        &self,
        start: u64,
        end: u64,
        bitset: &[u64],
        max_val: u64,
        out: &mut Vec<u32>,
    ) {
        if start >= end || bitset.is_empty() {
            return;
        }
        let has_val = |val: u64| -> bool {
            val <= max_val && ((bitset[(val >> 6) as usize] >> (val & 63)) & 1 != 0)
        };
        if !self.staging.is_empty() {
            let mut hint = 0usize;
            for row in start..end {
                if let Some(val) = self.get(row, &mut hint)
                    && has_val(val)
                {
                    out.push(row as u32);
                }
            }
            return;
        }
        let first_chunk = (start / CHUNK as u64) as usize;
        let last_chunk = ((end - 1) / CHUNK as u64) as usize;
        for (offset, chunk) in self.sealed[first_chunk..=last_chunk].iter().enumerate() {
            if self.order == Order::Unsigned && chunk.base > max_val {
                continue;
            }
            let chunk_idx = first_chunk + offset;
            let chunk_start = (chunk_idx as u64) * (CHUNK as u64);
            let c_lo = start.saturating_sub(chunk_start) as usize;
            let c_hi = (end - chunk_start).min(CHUNK as u64) as usize;
            let row_base = chunk_start as u32;
            let base = chunk.base;
            match &chunk.payload {
                Payload::Plain { width, data } => {
                    scan_plain_deltas(
                        *width,
                        data,
                        chunk.nulls.as_deref(),
                        row_base,
                        c_lo..c_hi,
                        out,
                        |delta| has_val(base.wrapping_add(delta)),
                    );
                }
                Payload::Runs {
                    width,
                    values,
                    ends,
                } => {
                    let wide = usize::from(*width);
                    let nulls = chunk.nulls.as_deref();
                    let mut run = ends.partition_point(|&e| (e as usize) <= c_lo);
                    while run < ends.len() {
                        let prev_end = if run == 0 { 0 } else { ends[run - 1] as usize };
                        if prev_end >= c_hi {
                            break;
                        }
                        let r_start = c_lo.max(prev_end);
                        let r_end = c_hi.min(ends[run] as usize);
                        let val = base.wrapping_add(read_width(values, run, wide));
                        if has_val(val) {
                            push_non_null_range(nulls, row_base, r_start..r_end, out);
                        }
                        run += 1;
                    }
                }
            }
        }
    }

    fn bytes_used(&self) -> usize {
        self.sealed
            .iter()
            .map(|c| {
                std::mem::size_of::<Chunk>()
                    + match &c.payload {
                        Payload::Plain { data, .. } => data.len(),
                        Payload::Runs { values, ends, .. } => values.len() + ends.len() * 4,
                    }
                    + c.nulls.as_ref().map_or(0, |n| n.len() * 8)
            })
            .sum::<usize>()
            + self.staging.capacity() * 8
            + self.staging_nulls.as_ref().map_or(0, Vec::capacity)
    }
}

// ---- a relation -------------------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Kind {
    Bool,
    I64,
    U64,
    F64,
    /// Text, or bytes, or DEX MUTF-8: an id into the dictionary.
    Dict,
}

struct Column {
    kind: Kind,
    ints: IntColumn,
    /// True if any text entry in this column was stored as `TAG_TEXT` (non-scalar UTF-16 or raw MUTF-8).
    has_tagged_text: bool,
}

pub(crate) enum IndexKeysRef<'a> {
    U32(&'a [u32]),
    U64(&'a [u64]),
}

impl IndexKeysRef<'_> {
    fn is_empty(&self) -> bool {
        match self {
            Self::U32(s) => s.is_empty(),
            Self::U64(s) => s.is_empty(),
        }
    }
}

enum IndexKeys {
    U32(Vec<u32>),
    U64(Vec<u64>),
}

/// Compact CSR inverted index for one indexable column of a `RelationStore`.
struct ColumnIndex {
    keys: IndexKeys,
    offsets: Vec<u32>,
    row_ids: Vec<u32>,
}

impl ColumnIndex {
    fn from_packed_u32(mut packed: Vec<u64>) -> Self {
        packed.sort_unstable();
        let mut keys = Vec::new();
        let mut offsets = Vec::with_capacity(packed.len().min(64) + 1);
        offsets.push(0);
        let mut row_ids = Vec::with_capacity(packed.len());
        for entry in packed {
            let key = (entry >> 32) as u32;
            let row = entry as u32;
            if keys.last().copied() != Some(key) {
                if !keys.is_empty() {
                    offsets.push(row_ids.len() as u32);
                }
                keys.push(key);
            }
            row_ids.push(row);
        }
        if !keys.is_empty() {
            offsets.push(row_ids.len() as u32);
        }
        keys.shrink_to_fit();
        offsets.shrink_to_fit();
        row_ids.shrink_to_fit();
        Self {
            keys: IndexKeys::U32(keys),
            offsets,
            row_ids,
        }
    }

    fn from_pairs(mut pairs: Vec<(u64, u32)>) -> Self {
        pairs.sort_unstable();
        let mut keys = Vec::new();
        let mut offsets = Vec::with_capacity(pairs.len().min(64) + 1);
        offsets.push(0);
        let mut row_ids = Vec::with_capacity(pairs.len());
        for (key, row) in pairs {
            if keys.last().copied() != Some(key) {
                if !keys.is_empty() {
                    offsets.push(row_ids.len() as u32);
                }
                keys.push(key);
            }
            row_ids.push(row);
        }
        if !keys.is_empty() {
            offsets.push(row_ids.len() as u32);
        }
        keys.shrink_to_fit();
        offsets.shrink_to_fit();
        row_ids.shrink_to_fit();
        Self {
            keys: IndexKeys::U64(keys),
            offsets,
            row_ids,
        }
    }

    fn keys(&self) -> IndexKeysRef<'_> {
        match &self.keys {
            IndexKeys::U32(keys) => IndexKeysRef::U32(keys),
            IndexKeys::U64(keys) => IndexKeysRef::U64(keys),
        }
    }

    fn bytes_used(&self) -> usize {
        let keys_bytes = match &self.keys {
            IndexKeys::U32(keys) => keys.capacity() * std::mem::size_of::<u32>(),
            IndexKeys::U64(keys) => keys.capacity() * std::mem::size_of::<u64>(),
        };
        keys_bytes
            + self.offsets.capacity() * std::mem::size_of::<u32>()
            + self.row_ids.capacity() * std::mem::size_of::<u32>()
    }

    fn rows_for_key(&self, key: u64, range: Option<(u32, u32)>) -> &[u32] {
        let at = match &self.keys {
            IndexKeys::U32(keys) => {
                let Ok(k) = u32::try_from(key) else {
                    return &[];
                };
                match keys.binary_search(&k) {
                    Ok(at) => at,
                    Err(_) => return &[],
                }
            }
            IndexKeys::U64(keys) => match keys.binary_search(&key) {
                Ok(at) => at,
                Err(_) => return &[],
            },
        };
        let slice = &self.row_ids[self.offsets[at] as usize..self.offsets[at + 1] as usize];
        narrow_slice(slice, range)
    }

    fn rows_in_range(
        &self,
        low: u64,
        high: u64,
        range: Option<(u32, u32)>,
        max_rows: usize,
    ) -> Option<Vec<u32>> {
        if low > high {
            return Some(Vec::new());
        }
        let (start, end) = match &self.keys {
            IndexKeys::U32(keys) => {
                if low > u64::from(u32::MAX) {
                    return Some(Vec::new());
                }
                let lo = low as u32;
                let hi = high.min(u64::from(u32::MAX)) as u32;
                let start = keys.partition_point(|&k| k < lo);
                let end = keys.partition_point(|&k| k <= hi);
                (start, end)
            }
            IndexKeys::U64(keys) => {
                let start = keys.partition_point(|&k| k < low);
                let end = keys.partition_point(|&k| k <= high);
                (start, end)
            }
        };
        if start >= end {
            return Some(Vec::new());
        }
        let total = (self.offsets[end] - self.offsets[start]) as usize;
        if total > max_rows && range.is_none() {
            return None;
        }
        let mut out = Vec::new();
        for at in start..end {
            let slice = narrow_slice(
                &self.row_ids[self.offsets[at] as usize..self.offsets[at + 1] as usize],
                range,
            );
            if out.len().saturating_add(slice.len()) > max_rows {
                return None;
            }
            out.extend_from_slice(slice);
        }
        out.sort_unstable();
        Some(out)
    }
}

fn narrow_slice(slice: &[u32], range: Option<(u32, u32)>) -> &[u32] {
    let Some((lo, hi)) = range else {
        return slice;
    };
    if lo >= hi || slice.is_empty() {
        return &[];
    }
    let start = slice.partition_point(|&r| r < lo);
    let end = start + slice[start..].partition_point(|&r| r < hi);
    &slice[start..end]
}

fn intersect_into(dst: &mut Vec<u32>, src: &[u32]) {
    if src.is_empty() || dst.is_empty() {
        dst.clear();
        return;
    }
    if src.len() > dst.len().saturating_mul(8) {
        dst.retain(|row| src.binary_search(row).is_ok());
        return;
    }
    let (mut i, mut j, mut write) = (0usize, 0usize, 0usize);
    while i < dst.len() && j < src.len() {
        match dst[i].cmp(&src[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                dst[write] = dst[i];
                write += 1;
                i += 1;
                j += 1;
            }
        }
    }
    dst.truncate(write);
}

pub enum ExactRowSet<'a> {
    Range(u64, u64),
    Slice(&'a [u32]),
    Owned(Vec<u32>),
}

impl ExactRowSet<'_> {
    pub fn len(&self) -> usize {
        match self {
            Self::Range(start, end) => end.saturating_sub(*start) as usize,
            Self::Slice(s) => s.len(),
            Self::Owned(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Clone, Copy)]
enum SortCellKey {
    Null,
    U64(u64),
    I64(i64),
    Dict(u32),
}

enum RowPiece<'p> {
    Slice(&'p [u32]),
    Owned(Vec<u32>),
}

impl RowPiece<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Slice(s) => s.len(),
            Self::Owned(v) => v.len(),
        }
    }
    fn as_slice(&self) -> &[u32] {
        match self {
            Self::Slice(s) => s,
            Self::Owned(v) => v,
        }
    }
    fn into_vec(self) -> Vec<u32> {
        match self {
            Self::Slice(s) => s.to_vec(),
            Self::Owned(v) => v,
        }
    }
}

fn intersect_row_pieces(mut pieces: Vec<RowPiece<'_>>) -> Option<RowPiece<'_>> {
    if pieces.iter().any(|p| p.len() == 0) {
        return Some(RowPiece::Owned(Vec::new()));
    }
    if pieces.is_empty() {
        return None;
    }
    if pieces.len() == 1 {
        return Some(pieces.pop().unwrap());
    }
    pieces.sort_by_key(RowPiece::len);
    let mut iter = pieces.into_iter();
    let mut acc = iter.next().unwrap().into_vec();
    for piece in iter {
        intersect_into(&mut acc, piece.as_slice());
        if acc.is_empty() {
            break;
        }
    }
    Some(RowPiece::Owned(acc))
}

enum EvalScan<'a> {
    All {
        range: Option<(u64, u64)>,
        partition_key: Option<u64>,
    },
    Slice(&'a [u32]),
    Owned(Vec<u32>),
}

type OwnedPrefixSuffixPair = (Box<[u8]>, Box<[u8]>);

#[derive(Clone)]
enum CachedFilterMatch {
    /// Sorted full-store row ids matching the filter (capped at <= `MAX_CACHED_ENTRY_ROWS`).
    Rows(Arc<[u32]>),
    /// Fallback dictionary ids when full-store row union exceeds the per-entry cap.
    Ids(Arc<[u32]>),
}

type FilterIdCacheEntry = (usize, FilterCacheKey, CachedFilterMatch);

#[derive(Default)]
struct FilterCacheState {
    entries: Vec<FilterIdCacheEntry>,
    cached_rows_total: usize,
}

#[derive(Clone, Eq, PartialEq)]
struct FilterCacheKey {
    prefixes: Vec<Box<[u8]>>,
    pairs: Vec<OwnedPrefixSuffixPair>,
    contains: Vec<Box<[u8]>>,
}

const MAX_FILTER_ID_CACHE: usize = 64;
const MAX_CACHED_ENTRY_ROWS: usize = 2_000_000;
const MAX_CACHED_FILTER_ROWS: usize = 4_000_000;

impl FilterCacheState {
    fn insert(&mut self, col_idx: usize, key: FilterCacheKey, value: CachedFilterMatch) {
        if let Some(pos) = self
            .entries
            .iter()
            .position(|(c, k, _)| *c == col_idx && *k == key)
        {
            let (_, _, old) = self.entries.remove(pos);
            if let CachedFilterMatch::Rows(rows) = old {
                self.cached_rows_total = self.cached_rows_total.saturating_sub(rows.len());
            }
        }
        let added_rows = match &value {
            CachedFilterMatch::Rows(rows) => rows.len(),
            CachedFilterMatch::Ids(_) => 0,
        };
        while !self.entries.is_empty()
            && (self.entries.len() >= MAX_FILTER_ID_CACHE
                || (added_rows > 0
                    && self.cached_rows_total.saturating_add(added_rows) > MAX_CACHED_FILTER_ROWS))
        {
            let (_, _, evicted) = self.entries.remove(0);
            if let CachedFilterMatch::Rows(rows) = evicted {
                self.cached_rows_total = self.cached_rows_total.saturating_sub(rows.len());
            }
        }
        self.cached_rows_total = self.cached_rows_total.saturating_add(added_rows);
        self.entries.push((col_idx, key, value));
    }
}

/// The rows of one relation, immutable. Build with `RelationStoreBuilder`, read with `cursor`.
pub struct RelationStore {
    columns: Vec<Column>,
    names: Vec<String>,
    /// Per column, how it is derived when it is not stored (its `Column` then holds no rows).
    derived: Vec<Option<DerivedColumn>>,
    /// The reference table of each DEX, by the value of the partition column, for the derived columns.
    tables: BTreeMap<u64, Arc<RefTable>>,
    /// Dense direct lookup by small contiguous partition keys (`file_id < 4096`) to avoid `BTreeMap` lookups on hot scans.
    dense_tables: Box<[Option<Arc<RefTable>>]>,
    /// The partition column, which says whose table a row's derived values come from.
    partition_column: Option<usize>,
    types: Vec<SqlType>,
    rows: u64,
    dict: Arc<TextDict>,
    /// The groups of rows that share a value of the partition column, in order of that value, when every row is in one.
    partitions: Option<Vec<Partition>>,
    /// An upper bound on the size of a cell, in bytes.
    max_cell_bytes: u64,
    /// Lazy CSR column indexes, initialized on first filtered lookup of an indexable column.
    indexes: Vec<OnceLock<Option<ColumnIndex>>>,
    /// Per-column count of filtered `EqText`/`InText` lookups before deciding to materialize a full CSR index.
    eq_probe_hits: Vec<std::sync::atomic::AtomicU8>,
    /// Bounded cache of matching row slices / dictionary ids per `(column_index, normalized_filter)` to avoid repeated scans.
    filter_id_cache: Mutex<FilterCacheState>,
}

/// The rows `start..end` of a store, which all have the partition column `key`.
#[derive(Clone, Copy, Debug)]
struct Partition {
    key: u64,
    start: u64,
    end: u64,
}

impl RelationStore {
    #[inline]
    fn table_for(&self, file: u64) -> Option<&RefTable> {
        if let Ok(at) = usize::try_from(file)
            && let Some(slot) = self.dense_tables.get(at)
        {
            return slot.as_deref();
        }
        self.tables.get(&file).map(Arc::as_ref)
    }

    pub fn rows(&self) -> u64 {
        self.rows
    }

    pub fn max_cell_bytes(&self) -> u64 {
        self.max_cell_bytes
    }

    /// Visit row indices in optional ascending `U64` order, matching SQLite stable tie breaking.
    fn for_each_ordered_row(
        &self,
        projected_columns: &[(usize, String)],
        order_by_u64_asc: &[usize],
        mut visit: impl FnMut(u64) -> MddResult<()>,
    ) -> MddResult<()> {
        if order_by_u64_asc.len() > 2 {
            return Err(crate::invalid("DIRECT_PROJECTION_ORDER_ARITY"));
        }
        for &(col_idx, _) in projected_columns {
            if col_idx >= self.columns.len() {
                return Err(crate::invalid("CURSOR_COORDINATE"));
            }
        }
        for &ord_col in order_by_u64_asc {
            if !self.is_indexable_u64(ord_col) {
                return Err(crate::invalid("DIRECT_PROJECTION_ORDER_COLUMN"));
            }
        }
        if self.rows == 0 {
            return Ok(());
        }
        if self.rows > u64::from(u32::MAX) {
            return Err(crate::quota("SQL_WORK_BUDGET"));
        }
        let n = self.rows as usize;
        match order_by_u64_asc {
            [] => {
                for row in 0..self.rows {
                    visit(row)?;
                }
            }
            [c0] => {
                let col0 = &self.columns[*c0].ints;
                let mut h0 = 0usize;
                let mut monotonic = true;
                let mut prev = 0u64;
                for row in 0..self.rows {
                    let k = col0
                        .get(row, &mut h0)
                        .ok_or_else(|| crate::invalid("DIRECT_PROJECTION_NULL_KEY"))?;
                    if row > 0 && k < prev {
                        monotonic = false;
                        break;
                    }
                    prev = k;
                }
                if monotonic {
                    for row in 0..self.rows {
                        visit(row)?;
                    }
                } else {
                    let mut keyed: Vec<(u64, u32)> = Vec::new();
                    keyed
                        .try_reserve_exact(n)
                        .map_err(|_| crate::quota("SQL_RESULT_ALLOCATION"))?;
                    let mut h = 0usize;
                    for row in 0..self.rows {
                        let k = col0
                            .get(row, &mut h)
                            .ok_or_else(|| crate::invalid("DIRECT_PROJECTION_NULL_KEY"))?;
                        keyed.push((k, row as u32));
                    }
                    keyed.sort_by_key(|&(k, _)| k);
                    for (_, row) in keyed {
                        visit(u64::from(row))?;
                    }
                }
            }
            [c0, c1] => {
                let col0 = &self.columns[*c0].ints;
                let col1 = &self.columns[*c1].ints;
                let mut h0 = 0usize;
                let mut h1 = 0usize;
                let mut monotonic = true;
                let mut prev = (0u64, 0u64);
                let mut max0 = 0u64;
                let mut max1 = 0u64;
                let mut break_row = 0u64;
                for row in 0..self.rows {
                    let k0 = col0
                        .get(row, &mut h0)
                        .ok_or_else(|| crate::invalid("DIRECT_PROJECTION_NULL_KEY"))?;
                    let k1 = col1
                        .get(row, &mut h1)
                        .ok_or_else(|| crate::invalid("DIRECT_PROJECTION_NULL_KEY"))?;
                    max0 = max0.max(k0);
                    max1 = max1.max(k1);
                    if row > 0 && (k0, k1) < prev {
                        monotonic = false;
                        break_row = row + 1;
                        break;
                    }
                    prev = (k0, k1);
                }
                if monotonic {
                    for row in 0..self.rows {
                        visit(row)?;
                    }
                } else {
                    let mut max_hi0 = max0;
                    let mut max_hi1 = max1;
                    if max_hi0 <= u64::from(u32::MAX) && max_hi1 <= u64::from(u32::MAX) {
                        for row in break_row..self.rows {
                            let k0 = col0
                                .get(row, &mut h0)
                                .ok_or_else(|| crate::invalid("DIRECT_PROJECTION_NULL_KEY"))?;
                            let k1 = col1
                                .get(row, &mut h1)
                                .ok_or_else(|| crate::invalid("DIRECT_PROJECTION_NULL_KEY"))?;
                            max_hi0 = max_hi0.max(k0);
                            max_hi1 = max_hi1.max(k1);
                            if max_hi0 > u64::from(u32::MAX) || max_hi1 > u64::from(u32::MAX) {
                                break;
                            }
                        }
                    }
                    if max_hi0 <= u64::from(u32::MAX) && max_hi1 <= u64::from(u32::MAX) {
                        let mut keyed: Vec<(u64, u32)> = Vec::new();
                        keyed
                            .try_reserve_exact(n)
                            .map_err(|_| crate::quota("SQL_RESULT_ALLOCATION"))?;
                        h0 = 0;
                        h1 = 0;
                        for row in 0..self.rows {
                            let k0 = col0
                                .get(row, &mut h0)
                                .ok_or_else(|| crate::invalid("DIRECT_PROJECTION_NULL_KEY"))?;
                            let k1 = col1
                                .get(row, &mut h1)
                                .ok_or_else(|| crate::invalid("DIRECT_PROJECTION_NULL_KEY"))?;
                            keyed.push(((k0 << 32) | k1, row as u32));
                        }
                        keyed.sort_by_key(|&(k, _)| k);
                        for (_, row) in keyed {
                            visit(u64::from(row))?;
                        }
                    } else {
                        let mut keyed: Vec<(u64, u64, u32)> = Vec::new();
                        keyed
                            .try_reserve_exact(n)
                            .map_err(|_| crate::quota("SQL_RESULT_ALLOCATION"))?;
                        h0 = 0;
                        h1 = 0;
                        for row in 0..self.rows {
                            let k0 = col0
                                .get(row, &mut h0)
                                .ok_or_else(|| crate::invalid("DIRECT_PROJECTION_NULL_KEY"))?;
                            let k1 = col1
                                .get(row, &mut h1)
                                .ok_or_else(|| crate::invalid("DIRECT_PROJECTION_NULL_KEY"))?;
                            keyed.push((k0, k1, row as u32));
                        }
                        keyed.sort_by_key(|&(k0, k1, _)| (k0, k1));
                        for (_, _, row) in keyed {
                            visit(u64::from(row))?;
                        }
                    }
                }
            }
            _ => unreachable!("checked arity <= 2"),
        }
        Ok(())
    }

    fn visit_borrowed_cell_at<R>(
        &self,
        column: usize,
        row: u64,
        hints: &[std::cell::Cell<usize>],
        f: impl FnOnce(BorrowedSqlCell<'_>) -> MddResult<R>,
    ) -> MddResult<R> {
        if let Some(Some(derived)) = self.derived.get(column) {
            let missing = || crate::invalid("STORE_DERIVED_REFERENCE_MISSING");
            let read = |at: usize| -> MddResult<u64> {
                let hint = hints.get(at).ok_or_else(missing)?;
                let mut run = hint.get();
                let raw = self.columns[at].ints.get(row, &mut run);
                hint.set(run);
                raw.ok_or_else(missing)
            };
            let file = read(self.partition_column.ok_or_else(missing)?)?;
            let index = read(derived.index_column)?;
            let id = self
                .table_for(file)
                .and_then(|table| table.id(derived.derive, index))
                .ok_or_else(missing)?;
            return self.dict.with_borrowed_cell(id, f);
        }
        let hint = hints
            .get(column)
            .ok_or_else(|| crate::invalid("CURSOR_COORDINATE"))?;
        let mut run = hint.get();
        let raw = self.columns[column].ints.get(row, &mut run);
        hint.set(run);
        let Some(raw) = raw else {
            return f(BorrowedSqlCell::Null);
        };
        match self.columns[column].kind {
            Kind::Bool => f(BorrowedSqlCell::Bool(raw != 0)),
            Kind::I64 => f(BorrowedSqlCell::I64(raw as i64)),
            Kind::U64 => f(BorrowedSqlCell::U64(raw)),
            Kind::F64 => f(BorrowedSqlCell::F64Bits(raw)),
            Kind::Dict => self.dict.with_borrowed_cell(raw as u32, f),
        }
    }

    fn scan_derived_group(
        &self,
        index_column: usize,
        predicates: &[(Derive, &[u32])],
        narrow: Option<(u32, u32)>,
    ) -> Option<Vec<u32>> {
        let partitions = self.partitions.as_ref()?;
        if predicates.is_empty() || self.derived.get(index_column).copied().flatten().is_some() {
            return None;
        }
        if predicates.iter().any(|(_, ids)| ids.is_empty()) {
            return Some(Vec::new());
        }
        let (lo, hi) = narrow.map_or((0u64, self.rows), |(a, b)| {
            (u64::from(a).min(self.rows), u64::from(b).min(self.rows))
        });
        if lo >= hi {
            return Some(Vec::new());
        }
        let derive_priority = |derive: Derive| -> u8 {
            match derive {
                Derive::MethodDescriptor | Derive::FieldDescriptor | Derive::TypeDescriptor => 0,
                Derive::MethodClass | Derive::FieldClass => 1,
                Derive::MethodName | Derive::FieldName | Derive::FieldType | Derive::TypeName => 2,
            }
        };
        let (primary_pos, _) = predicates
            .iter()
            .enumerate()
            .min_by_key(|(_, (d, ids))| (derive_priority(*d), ids.len()))?;
        let (primary_derive, primary_ids) = predicates[primary_pos];
        let class_filter: Option<&[u32]> = predicates
            .iter()
            .find(|(d, _)| matches!(d, Derive::MethodClass | Derive::FieldClass))
            .map(|(_, ids)| *ids);
        let ints = &self.columns.get(index_column)?.ints;
        let mut matched = Vec::new();
        let mut local_indices: Vec<u64> = Vec::new();
        let mut bitset: Vec<u64> = Vec::new();
        for part in partitions {
            let s = part.start.max(lo);
            let e = part.end.min(hi);
            if s >= e {
                continue;
            }
            let table = self.table_for(part.key)?;
            if table.type_desc_covers_member_classes
                && let Some(class_ids) = class_filter
            {
                let any_class = if class_ids.len() == 1 {
                    table.type_desc.contains(&class_ids[0])
                } else {
                    table.type_desc.iter().any(|id| class_ids.contains(id))
                };
                if !any_class {
                    continue;
                }
            }
            let primary_slice = table.slice(primary_derive);
            local_indices.clear();
            let matches_secondary = |idx: usize| -> bool {
                predicates.iter().enumerate().all(|(i, &(d, ids))| {
                    if i == primary_pos {
                        return true;
                    }
                    table.slice(d).get(idx).is_some_and(|v| ids.contains(v))
                })
            };
            if primary_ids.len() == 1 {
                let target = primary_ids[0];
                for (idx, &val) in primary_slice.iter().enumerate() {
                    if val == target && (predicates.len() == 1 || matches_secondary(idx)) {
                        local_indices.push(idx as u64);
                    }
                }
            } else {
                for (idx, &val) in primary_slice.iter().enumerate() {
                    if primary_ids.contains(&val)
                        && (predicates.len() == 1 || matches_secondary(idx))
                    {
                        local_indices.push(idx as u64);
                    }
                }
            }
            if local_indices.is_empty() {
                continue;
            }
            if local_indices.len() <= 8 {
                ints.collect_matching_in_range(s, e, &local_indices, &mut matched);
            } else {
                let words = primary_slice.len().div_ceil(64);
                bitset.clear();
                bitset.resize(words, 0);
                for &idx in &local_indices {
                    let i = idx as usize;
                    bitset[i >> 6] |= 1u64 << (i & 63);
                }
                let max_val = (primary_slice.len() - 1) as u64;
                ints.collect_matching_bitset_in_range(s, e, &bitset, max_val, &mut matched);
            }
        }
        Some(matched)
    }

    fn scan_text_ids(
        &self,
        column: usize,
        target_ids: &[u32],
        narrow: Option<(u32, u32)>,
    ) -> Option<Vec<u32>> {
        if !self.is_indexable_text(column) {
            return None;
        }
        if target_ids.is_empty() {
            return Some(Vec::new());
        }
        let (lo, hi) = narrow.map_or((0u64, self.rows), |(a, b)| {
            (u64::from(a).min(self.rows), u64::from(b).min(self.rows))
        });
        if lo >= hi {
            return Some(Vec::new());
        }
        if let Some(derived) = self.derived[column] {
            if self.partitions.is_some() {
                return self.scan_derived_group(
                    derived.index_column,
                    &[(derived.derive, target_ids)],
                    narrow,
                );
            }
            let part_col = self.partition_column?;
            let mut idx_hint = 0usize;
            let mut part_hint = 0usize;
            let mut last_file: Option<u64> = None;
            let mut last_table: Option<&RefTable> = None;
            let mut matched = Vec::new();
            for row in lo..hi {
                let file = self.columns[part_col].ints.get(row, &mut part_hint)?;
                if last_file != Some(file) {
                    last_table = self.table_for(file);
                    last_file = Some(file);
                }
                let table = last_table?;
                let Some(index) = self.columns[derived.index_column]
                    .ints
                    .get(row, &mut idx_hint)
                else {
                    continue;
                };
                if let Some(id) = table.id(derived.derive, index)
                    && target_ids.contains(&id)
                {
                    matched.push(row as u32);
                }
            }
            return Some(matched);
        }
        let targets: Vec<u64> = target_ids.iter().map(|&id| u64::from(id)).collect();
        let mut matched = Vec::new();
        self.columns[column]
            .ints
            .collect_matching_in_range(lo, hi, &targets, &mut matched);
        Some(matched)
    }

    /// Aggregate `COUNT(*)` over 1..=4 direct columns (`I64|U64|Text` without tagged/derived
    /// representation) matching SQLite ordering and all `SqlControl` work/result budgets.
    pub fn direct_count_group_by(
        &self,
        plan: &crate::provider::DirectCountGroupBy,
        control: &SqlControl,
    ) -> Option<MddResult<Vec<SqlRow>>> {
        let n_groups = plan.group_columns.len();
        if n_groups == 0 || n_groups > 4 {
            return None;
        }
        for &col in &plan.group_columns {
            let column = self.columns.get(col)?;
            let ty = *self.types.get(col)?;
            if self.derived.get(col).copied().flatten().is_some() {
                return None;
            }
            let eligible = matches!(column.kind, Kind::I64 | Kind::U64)
                || (matches!(column.kind, Kind::Dict)
                    && ty == SqlType::Text
                    && !column.has_tagged_text);
            if !eligible {
                return None;
            }
        }
        for item in &plan.projections {
            if let crate::provider::DirectGroupItem::GroupCol { group_pos, .. } = item
                && *group_pos >= n_groups
            {
                return None;
            }
        }
        if plan.order_by_group_asc.iter().any(|&p| p >= n_groups) {
            return None;
        }
        if let Err(err) = control.checkpoint(1, false) {
            return Some(Err(err));
        }
        if self.rows == 0 {
            return Some(Ok(Vec::new()));
        }

        let mut counts: HashMap<[Option<u64>; 4], u64> = HashMap::new();
        let mut hints = [0usize; 4];
        for row in 0..self.rows {
            if let Err(err) = control.checkpoint(1, true) {
                return Some(Err(err));
            }
            let mut key = [None; 4];
            for (slot, (&col, hint)) in key
                .iter_mut()
                .zip(plan.group_columns.iter().zip(hints.iter_mut()))
            {
                *slot = self.columns[col].ints.get(row, hint);
            }
            *counts.entry(key).or_insert(0) += 1;
        }

        let max_cell_bytes = control.inner.limits.max_cell_bytes;
        let mut groups: Vec<(Vec<SqlValue>, i64)> = Vec::with_capacity(counts.len());
        for (key_raw, raw_cnt) in counts {
            let Ok(cnt) = i64::try_from(raw_cnt) else {
                return Some(Err(crate::quota("SQL_RESULT_INT_OVERFLOW")));
            };
            let mut decoded = Vec::with_capacity(n_groups);
            for (&raw, &col) in key_raw.iter().zip(&plan.group_columns) {
                let value = match raw {
                    None => SqlValue::Null,
                    Some(v) => match self.columns[col].kind {
                        Kind::I64 => SqlValue::I64(Signed64(v as i64)),
                        Kind::U64 => SqlValue::U64(DecimalU64(v)),
                        Kind::Dict => self.dict.get(v as u32),
                        Kind::Bool | Kind::F64 => return None,
                    },
                };
                if value.byte_size() > max_cell_bytes {
                    return Some(Err(crate::quota("SQL_RESULT_CELL_BYTES")));
                }
                decoded.push(value);
            }
            groups.push((decoded, cnt));
        }

        groups.sort_by(|(a, _), (b, _)| {
            for &pos in &plan.order_by_group_asc {
                let ord = RelationStore::cmp_same_type_sql_values(&a[pos], &b[pos]);
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
            for pos in 0..n_groups {
                let ord = RelationStore::cmp_same_type_sql_values(&a[pos], &b[pos]);
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
            std::cmp::Ordering::Equal
        });

        let mut out = Vec::new();
        if out.try_reserve_exact(groups.len()).is_err() {
            return Some(Err(crate::quota("SQL_RESULT_ALLOCATION")));
        }
        for (decoded, cnt) in groups {
            let mut row_vals = Vec::new();
            if row_vals.try_reserve_exact(plan.projections.len()).is_err() {
                return Some(Err(crate::quota("SQL_RESULT_ALLOCATION")));
            }
            let mut row_bytes = 0u64;
            for item in &plan.projections {
                let val = match item {
                    crate::provider::DirectGroupItem::GroupCol { group_pos, .. } => {
                        decoded[*group_pos].clone()
                    }
                    crate::provider::DirectGroupItem::CountStar { .. } => {
                        SqlValue::I64(Signed64(cnt))
                    }
                };
                let size = val.byte_size();
                if size > max_cell_bytes {
                    return Some(Err(crate::quota("SQL_RESULT_CELL_BYTES")));
                }
                let work = match &val {
                    SqlValue::Text(text) => (text.utf16.len() as u64).saturating_mul(4),
                    SqlValue::Bytes(raw) | SqlValue::DexMutf8 { bytes: raw, .. } => {
                        (raw.len() as u64).saturating_mul(2)
                    }
                    _ => 16,
                };
                if let Err(err) = control.work(work) {
                    return Some(Err(err));
                }
                let Some(next_bytes) = row_bytes.checked_add(size) else {
                    return Some(Err(crate::quota("SQL_RESULT_BYTES_OVERFLOW")));
                };
                row_bytes = next_bytes;
                row_vals.push(val);
            }
            if let Err(err) = control.output(row_bytes) {
                return Some(Err(err));
            }
            out.push(row_vals);
        }
        Some(Ok(out))
    }

    /// Look up the exact sorted row set matching `predicates` (`AND`-conjoined).
    ///
    /// Returns `None` if any predicate cannot be resolved with 100% precision or when
    /// `bump_probe_hits == false` would require building an uncached CSR index.
    pub fn exact_lookup_rows(
        &self,
        predicates: &[crate::provider::DirectPredicate],
        bump_probe_hits: bool,
    ) -> Option<ExactRowSet<'_>> {
        use crate::provider::DirectPredicate;
        use std::sync::atomic::Ordering::Relaxed;

        if self.rows > u64::from(u32::MAX) {
            return None;
        }
        for pred in predicates {
            match pred {
                DirectPredicate::EqU64(col, _) | DirectPredicate::InU64(col, _) => {
                    if *col >= self.columns.len()
                        || (!self.is_partition_column(*col) && !self.is_indexable_u64(*col))
                    {
                        return None;
                    }
                }
                DirectPredicate::EqText(col, _) | DirectPredicate::InText(col, _) => {
                    if *col >= self.columns.len() || !self.is_indexable_text(*col) {
                        return None;
                    }
                }
            }
        }
        if self.rows == 0 {
            return Some(ExactRowSet::Owned(Vec::new()));
        }

        let mut range: Option<(u64, u64)> = None;
        let mut consumed = vec![false; predicates.len()];
        for (i, pred) in predicates.iter().enumerate() {
            if let DirectPredicate::EqU64(col, val) = pred
                && self.is_partition_column(*col)
            {
                let (start, end) = self.range_of(*val)?;
                range = Some(match range {
                    Some((lo, hi)) => (lo.max(start), hi.min(end)),
                    None => (start, end),
                });
                if let Some((lo, hi)) = range
                    && lo >= hi
                {
                    return Some(ExactRowSet::Owned(Vec::new()));
                }
                consumed[i] = true;
            }
        }
        let narrow =
            range.and_then(|(s, e)| Some((u32::try_from(s).ok()?, u32::try_from(e).ok()?)));
        let (scan_lo, scan_hi) = range.unwrap_or((0, self.rows));

        let mut resolved_ids: Vec<Option<Vec<u32>>> = vec![None; predicates.len()];
        for (i, pred) in predicates.iter().enumerate() {
            match pred {
                DirectPredicate::EqText(_, val) => {
                    let Some(id) = self.dict.lookup_str(val) else {
                        return Some(ExactRowSet::Owned(Vec::new()));
                    };
                    resolved_ids[i] = Some(vec![id]);
                }
                DirectPredicate::InText(_, vals) => {
                    if vals.is_empty() {
                        return Some(ExactRowSet::Owned(Vec::new()));
                    }
                    let mut ids = Vec::with_capacity(vals.len());
                    for val in vals {
                        if let Some(id) = self.dict.lookup_str(val)
                            && !ids.contains(&id)
                        {
                            ids.push(id);
                        }
                    }
                    if ids.is_empty() {
                        return Some(ExactRowSet::Owned(Vec::new()));
                    }
                    resolved_ids[i] = Some(ids);
                }
                _ => {}
            }
        }

        let mut pieces: Vec<RowPiece<'_>> = Vec::new();
        if self.partitions.is_some() {
            struct DerivedPred<'a> {
                pred_idx: usize,
                col: usize,
                derive: Derive,
                ids: &'a [u32],
            }
            let mut by_idx_col: BTreeMap<usize, Vec<DerivedPred<'_>>> = BTreeMap::new();
            for (i, pred) in predicates.iter().enumerate() {
                if consumed[i] {
                    continue;
                }
                let col = match pred {
                    DirectPredicate::EqText(col, _) | DirectPredicate::InText(col, _) => *col,
                    _ => continue,
                };
                if let Some(derived) = self.derived[col]
                    && self.indexes[col].get().is_none()
                    && let Some(ids) = resolved_ids[i].as_deref()
                    && ids.len() <= 8
                {
                    by_idx_col
                        .entry(derived.index_column)
                        .or_default()
                        .push(DerivedPred {
                            pred_idx: i,
                            col,
                            derive: derived.derive,
                            ids,
                        });
                }
            }
            for (index_column, group) in by_idx_col {
                let first_probe_any = !bump_probe_hits
                    || group
                        .iter()
                        .any(|g| self.eq_probe_hits[g.col].load(Relaxed) == 0);
                if first_probe_any {
                    let group_preds: Vec<(Derive, &[u32])> =
                        group.iter().map(|g| (g.derive, g.ids)).collect();
                    if let Some(rows) = self.scan_derived_group(index_column, &group_preds, narrow)
                    {
                        if bump_probe_hits {
                            for g in &group {
                                let _ = self.eq_probe_hits[g.col]
                                    .compare_exchange(0, 1, Relaxed, Relaxed);
                            }
                        }
                        for g in &group {
                            consumed[g.pred_idx] = true;
                        }
                        if rows.is_empty() {
                            return Some(ExactRowSet::Owned(Vec::new()));
                        }
                        pieces.push(RowPiece::Owned(rows));
                    }
                }
            }
        }

        for (i, pred) in predicates.iter().enumerate() {
            if consumed[i] {
                continue;
            }
            match pred {
                DirectPredicate::EqU64(col, val) => {
                    if !bump_probe_hits && self.indexes[*col].get().is_none() {
                        let mut rows = Vec::new();
                        self.columns[*col].ints.collect_matching_in_range(
                            scan_lo,
                            scan_hi,
                            &[*val],
                            &mut rows,
                        );
                        if rows.is_empty() {
                            return Some(ExactRowSet::Owned(Vec::new()));
                        }
                        pieces.push(RowPiece::Owned(rows));
                    } else {
                        let index = self.column_index(*col)?;
                        let slice = index.rows_for_key(*val, narrow);
                        if slice.is_empty() {
                            return Some(ExactRowSet::Owned(Vec::new()));
                        }
                        pieces.push(RowPiece::Slice(slice));
                    }
                }
                DirectPredicate::InU64(col, vals) => {
                    if vals.is_empty() {
                        return Some(ExactRowSet::Owned(Vec::new()));
                    }
                    if self.is_partition_column(*col) {
                        let mut spans = Vec::new();
                        let mut total = 0u64;
                        for val in vals {
                            let (mut s, mut e) = self.range_of(*val)?;
                            s = s.max(scan_lo);
                            e = e.min(scan_hi);
                            if s < e {
                                total = total.saturating_add(e - s);
                                if total > 65_536 {
                                    return None;
                                }
                                spans.push((s, e));
                            }
                        }
                        let mut rows = Vec::with_capacity(total as usize);
                        for (s, e) in spans {
                            for row in s..e {
                                rows.push(row as u32);
                            }
                        }
                        rows.sort_unstable();
                        rows.dedup();
                        if rows.is_empty() {
                            return Some(ExactRowSet::Owned(Vec::new()));
                        }
                        pieces.push(RowPiece::Owned(rows));
                    } else if !bump_probe_hits && self.indexes[*col].get().is_none() {
                        let mut rows = Vec::new();
                        self.columns[*col]
                            .ints
                            .collect_matching_in_range(scan_lo, scan_hi, vals, &mut rows);
                        if rows.is_empty() {
                            return Some(ExactRowSet::Owned(Vec::new()));
                        }
                        pieces.push(RowPiece::Owned(rows));
                    } else {
                        let index = self.column_index(*col)?;
                        let mut rows = Vec::new();
                        for val in vals {
                            rows.extend_from_slice(index.rows_for_key(*val, narrow));
                        }
                        rows.sort_unstable();
                        rows.dedup();
                        if rows.is_empty() {
                            return Some(ExactRowSet::Owned(Vec::new()));
                        }
                        pieces.push(RowPiece::Owned(rows));
                    }
                }
                DirectPredicate::EqText(col, _) | DirectPredicate::InText(col, _) => {
                    let ids = resolved_ids[i].as_deref()?;
                    let try_scan = self.indexes[*col].get().is_none()
                        && ids.len() <= 8
                        && (!bump_probe_hits
                            || self.eq_probe_hits[*col]
                                .compare_exchange(0, 1, Relaxed, Relaxed)
                                .is_ok());
                    if try_scan && let Some(rows) = self.scan_text_ids(*col, ids, narrow) {
                        if rows.is_empty() {
                            return Some(ExactRowSet::Owned(Vec::new()));
                        }
                        pieces.push(RowPiece::Owned(rows));
                        continue;
                    }
                    if !bump_probe_hits && self.indexes[*col].get().is_none() {
                        return None;
                    }
                    let index = self.column_index(*col)?;
                    if ids.len() == 1 {
                        let slice = index.rows_for_key(u64::from(ids[0]), narrow);
                        if slice.is_empty() {
                            return Some(ExactRowSet::Owned(Vec::new()));
                        }
                        pieces.push(RowPiece::Slice(slice));
                    } else {
                        let mut rows = Vec::new();
                        for &id in ids {
                            rows.extend_from_slice(index.rows_for_key(u64::from(id), narrow));
                        }
                        rows.sort_unstable();
                        rows.dedup();
                        if rows.is_empty() {
                            return Some(ExactRowSet::Owned(Vec::new()));
                        }
                        pieces.push(RowPiece::Owned(rows));
                    }
                }
            }
        }

        if pieces.is_empty() {
            return if scan_lo >= scan_hi {
                Some(ExactRowSet::Owned(Vec::new()))
            } else {
                Some(ExactRowSet::Range(scan_lo, scan_hi))
            };
        }
        match intersect_row_pieces(pieces)? {
            RowPiece::Slice(s) => Some(ExactRowSet::Slice(s)),
            RowPiece::Owned(v) => Some(ExactRowSet::Owned(v)),
        }
    }

    fn sort_key_cell(
        &self,
        column: usize,
        row: u64,
        hints: &[std::cell::Cell<usize>],
    ) -> MddResult<SortCellKey> {
        if let Some(Some(derived)) = self.derived.get(column) {
            let missing = || crate::invalid("STORE_DERIVED_REFERENCE_MISSING");
            let read = |at: usize| -> MddResult<u64> {
                let hint = hints.get(at).ok_or_else(missing)?;
                let mut run = hint.get();
                let raw = self.columns[at].ints.get(row, &mut run);
                hint.set(run);
                raw.ok_or_else(missing)
            };
            let file = read(self.partition_column.ok_or_else(missing)?)?;
            let index = read(derived.index_column)?;
            let id = self
                .table_for(file)
                .and_then(|table| table.id(derived.derive, index))
                .ok_or_else(missing)?;
            return Ok(SortCellKey::Dict(id));
        }
        let hint = hints
            .get(column)
            .ok_or_else(|| crate::invalid("CURSOR_COORDINATE"))?;
        let mut run = hint.get();
        let raw = self.columns[column].ints.get(row, &mut run);
        hint.set(run);
        let Some(raw) = raw else {
            return Ok(SortCellKey::Null);
        };
        Ok(match self.columns[column].kind {
            Kind::U64 => SortCellKey::U64(raw),
            Kind::I64 => SortCellKey::I64(raw as i64),
            Kind::Dict => SortCellKey::Dict(raw as u32),
            Kind::Bool | Kind::F64 => return Err(crate::invalid("DIRECT_FILTERED_ORDER_COLUMN")),
        })
    }

    fn cmp_sort_key(
        &self,
        left: SortCellKey,
        right: SortCellKey,
        desc: bool,
    ) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        let asc = match (left, right) {
            (SortCellKey::Null, SortCellKey::Null) => Ordering::Equal,
            (SortCellKey::Null, _) => Ordering::Less,
            (_, SortCellKey::Null) => Ordering::Greater,
            (SortCellKey::U64(a), SortCellKey::U64(b)) => a.cmp(&b),
            (SortCellKey::I64(a), SortCellKey::I64(b)) => a.cmp(&b),
            (SortCellKey::Dict(a), SortCellKey::Dict(b)) => self.dict.cmp_text_ids(a, b),
            _ => Ordering::Equal,
        };
        if desc { asc.reverse() } else { asc }
    }

    fn cmp_sort_row(
        &self,
        left: &[SortCellKey; 4],
        right: &[SortCellKey; 4],
        order_by: &[crate::provider::DirectOrderItem],
    ) -> std::cmp::Ordering {
        for (i, item) in order_by.iter().enumerate() {
            let ord = self.cmp_sort_key(left[i], right[i], item.descending);
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }
        }
        std::cmp::Ordering::Equal
    }

    fn materialize_direct_row(
        &self,
        projected_columns: &[(usize, String)],
        row: u64,
        hints: &[std::cell::Cell<usize>],
        max_cell_bytes: u64,
        control: &SqlControl,
    ) -> MddResult<SqlRow> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(projected_columns.len())
            .map_err(|_| crate::quota("SQL_RESULT_ALLOCATION"))?;
        let mut bytes = 0u64;
        for &(col_idx, _) in projected_columns {
            let value = self.cell_at(col_idx, row, hints)?;
            let size = value.byte_size();
            if size > max_cell_bytes {
                return Err(crate::quota("SQL_RESULT_CELL_BYTES"));
            }
            let work = match &value {
                SqlValue::Text(text) => (text.utf16.len() as u64).saturating_mul(4),
                SqlValue::Bytes(raw) | SqlValue::DexMutf8 { bytes: raw, .. } => {
                    (raw.len() as u64).saturating_mul(2)
                }
                _ => 16,
            };
            control.work(work)?;
            bytes = bytes
                .checked_add(size)
                .ok_or_else(|| crate::quota("SQL_RESULT_BYTES_OVERFLOW"))?;
            values.push(value);
        }
        control.output(bytes)?;
        Ok(values)
    }

    /// Execute a filtered single-table projection directly against columnar storage and SoA
    /// `RefTable`s without opening an in-memory SQLite connection.
    pub fn direct_filtered_projection(
        &self,
        plan: &crate::provider::DirectFilteredProjection,
        control: &SqlControl,
        window: Option<crate::window::SqlWindow>,
    ) -> Option<MddResult<(Vec<SqlRow>, Option<crate::window::SqlWindowReport>)>> {
        if !sql_scan_opt_enabled()
            || control.runtime().is_some()
            || self.max_cell_bytes > control.inner.limits.max_cell_bytes
            || plan.order_by.len() > 4
        {
            return None;
        }
        for &(col_idx, _) in &plan.projected_columns {
            if col_idx >= self.columns.len() {
                return None;
            }
        }
        for item in &plan.order_by {
            let ty = *self.types.get(item.column)?;
            if !matches!(ty, SqlType::U64 | SqlType::I64 | SqlType::Text) {
                return None;
            }
        }

        let matched = self.exact_lookup_rows(&plan.predicates, true)?;
        let total_count = matched.len() as u64;
        let sql_start = plan.offset.min(total_count);
        let sql_end = match plan.limit {
            Some(lim) => sql_start.saturating_add(lim).min(total_count),
            None => total_count,
        };
        let sql_total = sql_end - sql_start;
        if sql_total > 0 && !plan.order_by.is_empty() && total_count > 65_536 {
            return None;
        }

        Some((|| {
            control.checkpoint(1, false)?;
            let max_cell_bytes = control.inner.limits.max_cell_bytes;
            let compute_window =
                |total: u64| -> MddResult<(usize, usize, Option<crate::window::SqlWindowReport>)> {
                    match window {
                        None => Ok((0, total as usize, None)),
                        Some(w) => {
                            let start = w.offset().min(total);
                            let end = w.offset().saturating_add(w.limit()).min(total);
                            let count = end - start;
                            let truncated = end < total;
                            let total_rows = w.counts_total().then_some(total);
                            let report = crate::window::SqlWindowReport::finish(
                                w, count, truncated, total_rows,
                            )?;
                            Ok((start as usize, end as usize, Some(report)))
                        }
                    }
                };

            if sql_total == 0 {
                let (_, _, report) = compute_window(0)?;
                return Ok((Vec::new(), report));
            }

            let hints = vec![std::cell::Cell::new(0); self.columns.len()];
            if !plan.order_by.is_empty() && total_count > 1 {
                let n = total_count as usize;
                let rows = match matched {
                    ExactRowSet::Range(lo, hi) => {
                        let mut v = Vec::new();
                        v.try_reserve_exact(n)
                            .map_err(|_| crate::quota("SQL_RESULT_ALLOCATION"))?;
                        for r in lo..hi {
                            v.push(r as u32);
                        }
                        v
                    }
                    ExactRowSet::Slice(s) => {
                        let mut v = Vec::new();
                        v.try_reserve_exact(n)
                            .map_err(|_| crate::quota("SQL_RESULT_ALLOCATION"))?;
                        v.extend_from_slice(s);
                        v
                    }
                    ExactRowSet::Owned(v) => v,
                };
                for _ in 0..rows.len() {
                    control.checkpoint(1, true)?;
                }
                let mut keys: Vec<[SortCellKey; 4]> = Vec::new();
                keys.try_reserve_exact(n)
                    .map_err(|_| crate::quota("SQL_RESULT_ALLOCATION"))?;
                let mut already_sorted = true;
                for (idx, &row) in rows.iter().enumerate() {
                    let mut row_keys = [SortCellKey::Null; 4];
                    for (slot, item) in row_keys.iter_mut().zip(&plan.order_by) {
                        *slot = self.sort_key_cell(item.column, u64::from(row), &hints)?;
                    }
                    if idx > 0
                        && already_sorted
                        && self.cmp_sort_row(&keys[idx - 1], &row_keys, &plan.order_by)
                            == std::cmp::Ordering::Greater
                    {
                        already_sorted = false;
                    }
                    keys.push(row_keys);
                }
                let (w_start, w_end, report) = compute_window(sql_total)?;
                let abs_start = (sql_start as usize) + w_start;
                let abs_end = (sql_start as usize) + w_end;
                let mut out = Vec::new();
                out.try_reserve_exact(abs_end.saturating_sub(abs_start))
                    .map_err(|_| crate::quota("SQL_RESULT_ALLOCATION"))?;
                if already_sorted {
                    for &row in &rows[abs_start..abs_end] {
                        out.push(self.materialize_direct_row(
                            &plan.projected_columns,
                            u64::from(row),
                            &hints,
                            max_cell_bytes,
                            control,
                        )?);
                    }
                } else {
                    control.work((n as u64).saturating_mul(16))?;
                    let mut order: Vec<usize> = Vec::new();
                    order
                        .try_reserve_exact(n)
                        .map_err(|_| crate::quota("SQL_RESULT_ALLOCATION"))?;
                    order.extend(0..n);
                    order.sort_by(|&a, &b| {
                        let ord = self.cmp_sort_row(&keys[a], &keys[b], &plan.order_by);
                        if ord != std::cmp::Ordering::Equal {
                            ord
                        } else {
                            rows[a].cmp(&rows[b])
                        }
                    });
                    for &idx in &order[abs_start..abs_end] {
                        out.push(self.materialize_direct_row(
                            &plan.projected_columns,
                            u64::from(rows[idx]),
                            &hints,
                            max_cell_bytes,
                            control,
                        )?);
                    }
                }
                return Ok((out, report));
            }

            let scanned = match window {
                Some(w) if !w.counts_total() => sql_start.saturating_add(
                    w.offset()
                        .saturating_add(w.limit())
                        .saturating_add(1)
                        .min(sql_total),
                ),
                _ => sql_end,
            };
            for _ in 0..scanned {
                control.checkpoint(1, true)?;
            }
            let (w_start, w_end, report) = compute_window(sql_total)?;
            let abs_start = (sql_start as usize) + w_start;
            let abs_end = (sql_start as usize) + w_end;
            let mut out = Vec::new();
            out.try_reserve_exact(abs_end.saturating_sub(abs_start))
                .map_err(|_| crate::quota("SQL_RESULT_ALLOCATION"))?;
            match matched {
                ExactRowSet::Range(lo, _) => {
                    let row_start = lo + abs_start as u64;
                    let row_end = lo + abs_end as u64;
                    for row in row_start..row_end {
                        out.push(self.materialize_direct_row(
                            &plan.projected_columns,
                            row,
                            &hints,
                            max_cell_bytes,
                            control,
                        )?);
                    }
                }
                ExactRowSet::Slice(slice) => {
                    for &row in &slice[abs_start..abs_end] {
                        out.push(self.materialize_direct_row(
                            &plan.projected_columns,
                            u64::from(row),
                            &hints,
                            max_cell_bytes,
                            control,
                        )?);
                    }
                }
                ExactRowSet::Owned(rows) => {
                    for &row in &rows[abs_start..abs_end] {
                        out.push(self.materialize_direct_row(
                            &plan.projected_columns,
                            u64::from(row),
                            &hints,
                            max_cell_bytes,
                            control,
                        )?);
                    }
                }
            }
            Ok((out, report))
        })())
    }

    fn cmp_same_type_sql_values(a: &SqlValue, b: &SqlValue) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match (a, b) {
            (SqlValue::Null, SqlValue::Null) => Ordering::Equal,
            (SqlValue::Null, _) => Ordering::Less,
            (_, SqlValue::Null) => Ordering::Greater,
            (SqlValue::I64(x), SqlValue::I64(y)) => x.0.cmp(&y.0),
            (SqlValue::U64(x), SqlValue::U64(y)) => x.0.cmp(&y.0),
            (SqlValue::Text(x), SqlValue::Text(y)) => x.utf16.cmp(&y.utf16),
            _ => Ordering::Equal,
        }
    }

    /// Materialize a single-table projection directly in optional ascending `U64` order, matching
    /// SQLite stable row-order tie breaking and all `SqlControl` budgets identically.
    pub fn project_ordered(
        &self,
        projected_columns: &[(usize, String)],
        order_by_u64_asc: &[usize],
        control: &SqlControl,
    ) -> MddResult<Vec<SqlRow>> {
        control.checkpoint(1, false)?;
        if self.rows == 0 {
            for &(col_idx, _) in projected_columns {
                if col_idx >= self.columns.len() {
                    return Err(crate::invalid("CURSOR_COORDINATE"));
                }
            }
            for &ord_col in order_by_u64_asc {
                if order_by_u64_asc.len() > 2 || !self.is_indexable_u64(ord_col) {
                    return Err(crate::invalid("DIRECT_PROJECTION_ORDER_COLUMN"));
                }
            }
            return Ok(Vec::new());
        }
        let max_cell_bytes = control.inner.limits.max_cell_bytes;
        let initial_cap = (self.rows as usize)
            .min(usize::try_from(control.inner.limits.max_result_rows).unwrap_or(usize::MAX))
            .min(65_536);
        let mut out = Vec::new();
        out.try_reserve_exact(initial_cap)
            .map_err(|_| crate::quota("SQL_RESULT_ALLOCATION"))?;
        let hints = vec![std::cell::Cell::new(0); self.columns.len()];

        self.for_each_ordered_row(projected_columns, order_by_u64_asc, |row| {
            control.checkpoint(1, true)?;
            let mut values = Vec::new();
            values
                .try_reserve_exact(projected_columns.len())
                .map_err(|_| crate::quota("SQL_RESULT_ALLOCATION"))?;
            let mut bytes = 0u64;
            for &(col_idx, _) in projected_columns {
                let value = self.cell_at(col_idx, row, &hints)?;
                let size = value.byte_size();
                if size > max_cell_bytes {
                    return Err(crate::quota("SQL_RESULT_CELL_BYTES"));
                }
                let work = match &value {
                    SqlValue::Text(text) => (text.utf16.len() as u64).saturating_mul(4),
                    SqlValue::Bytes(raw) | SqlValue::DexMutf8 { bytes: raw, .. } => {
                        (raw.len() as u64).saturating_mul(2)
                    }
                    _ => 16,
                };
                control.work(work)?;
                bytes = bytes
                    .checked_add(size)
                    .ok_or_else(|| crate::quota("SQL_RESULT_BYTES_OVERFLOW"))?;
                values.push(value);
            }
            control.output(bytes)?;
            out.push(values);
            Ok(())
        })?;
        Ok(out)
    }

    /// Stream an ordered single-table projection without intermediate `SqlRow` or `Vec<u16>` heap copies.
    ///
    /// Returns `Ok(false)` without invoking `consumer` if `self.rows == 0` or conservative/exact
    /// quota pre-checks cannot guarantee zero-failure delivery before batch 0.
    pub fn stream_projected_ordered(
        &self,
        projected_columns: &[(usize, String)],
        order_by_u64_asc: &[usize],
        control: &SqlControl,
        consumer: &mut dyn DirectCellRowConsumer,
    ) -> MddResult<bool> {
        if control.runtime().is_some()
            || !sql_scan_opt_enabled()
            || self.rows == 0
            || self.rows > u64::from(u32::MAX)
            || order_by_u64_asc.len() > 2
            || self.max_cell_bytes > control.inner.limits.max_cell_bytes
        {
            return Ok(false);
        }
        for &(col_idx, _) in projected_columns {
            if col_idx >= self.columns.len() {
                return Ok(false);
            }
        }
        for &ord_col in order_by_u64_asc {
            if !self.is_indexable_u64(ord_col) {
                return Ok(false);
            }
        }
        let (rem_steps, rem_scanned, rem_rows, rem_bytes, max_cell_bytes) =
            control.remaining_streaming_budgets()?;
        let steps_needed = self.rows.saturating_mul(2).saturating_add(3);
        if self.rows > rem_rows
            || self.rows > rem_scanned
            || steps_needed > rem_steps
            || projected_columns.is_empty()
        {
            return Ok(false);
        }

        let has_varlen = projected_columns.iter().any(|&(col_idx, _)| {
            self.derived.get(col_idx).copied().flatten().is_some()
                || matches!(self.columns[col_idx].kind, Kind::Dict)
        });
        let conservative_max_bytes = if has_varlen {
            self.rows
                .saturating_mul(projected_columns.len() as u64)
                .saturating_mul(self.max_cell_bytes.max(16))
        } else {
            self.rows
                .saturating_mul(projected_columns.len() as u64)
                .saturating_mul(16)
        };
        if conservative_max_bytes > rem_bytes {
            // Exact cheap pass over rows without allocating to verify actual result bytes fit.
            let pre_hints = vec![std::cell::Cell::new(0); self.columns.len()];
            let mut actual_total = 0u64;
            for row in 0..self.rows {
                for &(col_idx, _) in projected_columns {
                    let size = self.visit_borrowed_cell_at(col_idx, row, &pre_hints, |cell| {
                        Ok(borrowed_cell_byte_size_and_work(&cell).0)
                    })?;
                    if size > max_cell_bytes {
                        return Ok(false);
                    }
                    actual_total = actual_total.saturating_add(size);
                    if actual_total > rem_bytes {
                        return Ok(false);
                    }
                }
            }
        }

        control.checkpoint(1, false)?;
        consumer.on_start(self.rows)?;
        let hints = vec![std::cell::Cell::new(0); self.columns.len()];
        self.for_each_ordered_row(projected_columns, order_by_u64_asc, |row| {
            control.checkpoint(1, true)?;
            consumer.begin_row()?;
            let mut bytes = 0u64;
            for (out_idx, &(col_idx, _)) in projected_columns.iter().enumerate() {
                self.visit_borrowed_cell_at(col_idx, row, &hints, |cell| {
                    let (size, work) = borrowed_cell_byte_size_and_work(&cell);
                    if size > max_cell_bytes {
                        return Err(crate::quota("SQL_RESULT_CELL_BYTES"));
                    }
                    control.work(work)?;
                    bytes = bytes
                        .checked_add(size)
                        .ok_or_else(|| crate::quota("SQL_RESULT_BYTES_OVERFLOW"))?;
                    consumer.push_cell(out_idx, &cell)
                })?;
            }
            control.output(bytes)?;
            consumer.end_row()
        })?;
        control.checkpoint(1, false)?;
        consumer.on_finish()?;
        Ok(true)
    }

    /// Bytes held on the heap by the columns and any initialized column indexes, not counting the shared dictionary.
    pub fn bytes_used(&self) -> usize {
        let cols: usize = self.columns.iter().map(|c| c.ints.bytes_used()).sum();
        let indexes: usize = self
            .indexes
            .iter()
            .filter_map(|slot| slot.get().and_then(Option::as_ref))
            .map(ColumnIndex::bytes_used)
            .sum();
        cols + indexes
    }

    pub fn column_by_name(&self, name: &str) -> Option<usize> {
        self.names.iter().position(|n| n.eq_ignore_ascii_case(name))
    }

    pub fn column_type(&self, column: usize) -> Option<SqlType> {
        self.types.get(column).copied()
    }

    pub fn u64_cell(&self, column: usize, row: u64) -> Option<Option<u64>> {
        let col = self.columns.get(column)?;
        if !matches!(col.kind, Kind::U64) || self.derived.get(column).copied().flatten().is_some() {
            return None;
        }
        let mut hint = 0usize;
        Some(col.ints.get(row, &mut hint))
    }

    pub fn text_cell(&self, column: usize, row: u64) -> Option<Option<String>> {
        match self.cell(column, row).ok()? {
            SqlValue::Null => Some(None),
            SqlValue::Text(text) => text.strict_utf8().ok().map(Some),
            _ => None,
        }
    }

    pub fn scan_len(&self, scan: &PlannedScan) -> u64 {
        match scan {
            PlannedScan::All { .. } => self.rows,
            PlannedScan::Partition { key, .. } => {
                self.range_of(*key).map_or(self.rows, |(s, e)| e - s)
            }
            PlannedScan::Rows(rows) => rows.len() as u64,
        }
    }

    pub fn for_each_scan_row(
        &self,
        scan: &PlannedScan,
        mut visit: impl FnMut(u64) -> ControlFlow<()>,
    ) {
        match scan {
            PlannedScan::All { .. } => {
                for row in 0..self.rows {
                    if visit(row).is_break() {
                        break;
                    }
                }
            }
            PlannedScan::Partition { key, .. } => {
                let (start, end) = self.range_of(*key).unwrap_or((0, self.rows));
                for row in start..end {
                    if visit(row).is_break() {
                        break;
                    }
                }
            }
            PlannedScan::Rows(rows) => {
                for &row in rows.iter() {
                    if visit(u64::from(row)).is_break() {
                        break;
                    }
                }
            }
        }
    }

    fn is_partition_column(&self, column: usize) -> bool {
        self.partition_column == Some(column) && self.partitions.is_some()
    }

    fn is_indexable_u64(&self, column: usize) -> bool {
        self.rows <= u64::from(u32::MAX)
            && self.derived.get(column).copied().flatten().is_none()
            && matches!(self.columns.get(column).map(|c| c.kind), Some(Kind::U64))
    }

    fn is_indexable_text(&self, column: usize) -> bool {
        self.rows <= u64::from(u32::MAX)
            && self.types.get(column) == Some(&SqlType::Text)
            && (self.derived.get(column).copied().flatten().is_some()
                || self
                    .columns
                    .get(column)
                    .is_some_and(|c| matches!(c.kind, Kind::Dict) && !c.has_tagged_text))
    }

    fn column_index(&self, column: usize) -> Option<&ColumnIndex> {
        if self.rows > u64::from(u32::MAX) || column >= self.columns.len() {
            return None;
        }
        self.indexes[column]
            .get_or_init(|| {
                if let Some(derived) = self.derived[column] {
                    let part_col = self.partition_column?;
                    let mut packed = Vec::with_capacity(self.rows as usize);
                    let mut idx_hint = 0usize;
                    if let Some(partitions) = &self.partitions {
                        for part in partitions {
                            if part.start == part.end {
                                continue;
                            }
                            let table = self.table_for(part.key)?;
                            for row in part.start..part.end {
                                let index = self.columns[derived.index_column]
                                    .ints
                                    .get(row, &mut idx_hint)?;
                                if let Some(id) = table.id(derived.derive, index) {
                                    packed.push((u64::from(id) << 32) | row);
                                }
                            }
                        }
                    } else {
                        let mut part_hint = 0usize;
                        let mut last_file: Option<u64> = None;
                        let mut last_table: Option<&RefTable> = None;
                        for row in 0..self.rows {
                            let file = self.columns[part_col].ints.get(row, &mut part_hint)?;
                            if last_file != Some(file) {
                                last_table = self.table_for(file);
                                last_file = Some(file);
                            }
                            let table = last_table?;
                            let index = self.columns[derived.index_column]
                                .ints
                                .get(row, &mut idx_hint)?;
                            if let Some(id) = table.id(derived.derive, index) {
                                packed.push((u64::from(id) << 32) | row);
                            }
                        }
                    }
                    return Some(ColumnIndex::from_packed_u32(packed));
                }
                if !self.is_indexable_u64(column) && !self.is_indexable_text(column) {
                    return None;
                }
                let ints = &self.columns[column].ints;
                if matches!(self.columns[column].kind, Kind::Dict) || ints.fits_u32_fast() {
                    let mut packed = Vec::with_capacity(self.rows as usize);
                    let mut hint = 0usize;
                    for row in 0..self.rows {
                        if let Some(raw) = ints.get(row, &mut hint) {
                            debug_assert!(raw <= u64::from(u32::MAX));
                            packed.push((raw << 32) | row);
                        }
                    }
                    Some(ColumnIndex::from_packed_u32(packed))
                } else {
                    let mut pairs = Vec::with_capacity(self.rows as usize);
                    let mut hint = 0usize;
                    for row in 0..self.rows {
                        if let Some(raw) = ints.get(row, &mut hint) {
                            pairs.push((raw, row as u32));
                        }
                    }
                    Some(ColumnIndex::from_pairs(pairs))
                }
            })
            .as_ref()
    }

    pub fn plan_filter(&self, filter: &RowFilter) -> PlannedScan {
        match self.eval_filter(filter, None, None) {
            EvalScan::Owned(rows) => PlannedScan::Rows(Arc::from(rows)),
            EvalScan::Slice(slice) => PlannedScan::Rows(Arc::from(slice)),
            EvalScan::All {
                range: Some((start, end)),
                partition_key,
            } => {
                if start >= end {
                    PlannedScan::Rows(Arc::from([]))
                } else if let Some(key) = partition_key {
                    PlannedScan::Partition {
                        key,
                        estimated_rows: Some(end - start),
                    }
                } else {
                    PlannedScan::All {
                        estimated_rows: Some(self.rows),
                    }
                }
            }
            EvalScan::All { .. } => PlannedScan::All {
                estimated_rows: Some(self.rows),
            },
        }
    }

    pub fn intersect_scans(&self, current: &PlannedScan, other: &PlannedScan) -> PlannedScan {
        match (current, other) {
            (PlannedScan::All { .. }, _) => other.clone(),
            (_, PlannedScan::All { .. }) => current.clone(),
            (PlannedScan::Partition { key: k1, .. }, PlannedScan::Partition { key: k2, .. }) => {
                if k1 == k2 {
                    current.clone()
                } else {
                    PlannedScan::Rows(Arc::from([]))
                }
            }
            (PlannedScan::Partition { key, .. }, PlannedScan::Rows(rows))
            | (PlannedScan::Rows(rows), PlannedScan::Partition { key, .. }) => {
                let Some((start, end)) = self.range_of(*key) else {
                    return PlannedScan::Rows(Arc::clone(rows));
                };
                if let (Ok(lo), Ok(hi)) = (u32::try_from(start), u32::try_from(end)) {
                    PlannedScan::Rows(Arc::from(narrow_slice(rows, Some((lo, hi)))))
                } else {
                    PlannedScan::Rows(Arc::clone(rows))
                }
            }
            (PlannedScan::Rows(left), PlannedScan::Rows(right)) => {
                let (mut base, probe) = if left.len() <= right.len() {
                    (left.to_vec(), right.as_ref())
                } else {
                    (right.to_vec(), left.as_ref())
                };
                intersect_into(&mut base, probe);
                PlannedScan::Rows(Arc::from(base))
            }
        }
    }

    fn eval_filter<'a>(
        &'a self,
        filter: &RowFilter,
        enclosing_range: Option<(u64, u64)>,
        enclosing_partition: Option<u64>,
    ) -> EvalScan<'a> {
        let narrow = enclosing_range
            .and_then(|(s, e)| Some((u32::try_from(s).ok()?, u32::try_from(e).ok()?)));
        match filter {
            RowFilter::EqU64(col, val) => {
                let Some(at) = self.column_by_name(col) else {
                    return EvalScan::All {
                        range: enclosing_range,
                        partition_key: enclosing_partition,
                    };
                };
                if self.is_partition_column(at) {
                    let Some((start, end)) = self.range_of(*val) else {
                        return EvalScan::All {
                            range: enclosing_range,
                            partition_key: enclosing_partition,
                        };
                    };
                    if let Some((e_start, e_end)) = enclosing_range {
                        let lo = start.max(e_start);
                        let hi = end.min(e_end);
                        if lo >= hi {
                            return EvalScan::Owned(Vec::new());
                        }
                        return EvalScan::All {
                            range: Some((lo, hi)),
                            partition_key: if enclosing_partition == Some(*val)
                                || (lo == start && hi == end)
                            {
                                Some(*val)
                            } else {
                                enclosing_partition
                            },
                        };
                    }
                    return EvalScan::All {
                        range: Some((start, end)),
                        partition_key: Some(*val),
                    };
                }
                if !self.is_indexable_u64(at) {
                    return EvalScan::All {
                        range: enclosing_range,
                        partition_key: enclosing_partition,
                    };
                }
                let Some(index) = self.column_index(at) else {
                    return EvalScan::All {
                        range: enclosing_range,
                        partition_key: enclosing_partition,
                    };
                };
                EvalScan::Slice(index.rows_for_key(*val, narrow))
            }
            RowFilter::InU64(col, vals) => {
                let Some(at) = self.column_by_name(col) else {
                    return EvalScan::All {
                        range: enclosing_range,
                        partition_key: enclosing_partition,
                    };
                };
                if vals.is_empty() {
                    return EvalScan::Owned(Vec::new());
                }
                if self.is_partition_column(at) {
                    let mut spans = Vec::new();
                    for val in vals {
                        let Some((mut start, mut end)) = self.range_of(*val) else {
                            return EvalScan::All {
                                range: enclosing_range,
                                partition_key: enclosing_partition,
                            };
                        };
                        if let Some((lo, hi)) = enclosing_range {
                            start = start.max(lo);
                            end = end.min(hi);
                        }
                        if start < end {
                            spans.push((start, end));
                        }
                    }
                    let total: u64 = spans.iter().map(|(s, e)| e - s).sum();
                    if total > self.rows / 2 || total > u64::from(u32::MAX) {
                        return EvalScan::All {
                            range: enclosing_range,
                            partition_key: enclosing_partition,
                        };
                    }
                    let mut rows = Vec::with_capacity(total as usize);
                    for (start, end) in spans {
                        for row in start..end {
                            rows.push(row as u32);
                        }
                    }
                    rows.sort_unstable();
                    rows.dedup();
                    return EvalScan::Owned(rows);
                }
                if !self.is_indexable_u64(at) {
                    return EvalScan::All {
                        range: enclosing_range,
                        partition_key: enclosing_partition,
                    };
                }
                let Some(index) = self.column_index(at) else {
                    return EvalScan::All {
                        range: enclosing_range,
                        partition_key: enclosing_partition,
                    };
                };
                let mut rows = Vec::new();
                for val in vals {
                    rows.extend_from_slice(index.rows_for_key(*val, narrow));
                }
                rows.sort_unstable();
                rows.dedup();
                EvalScan::Owned(rows)
            }
            RowFilter::BetweenU64(col, low, high) => {
                if low > high {
                    return EvalScan::Owned(Vec::new());
                }
                let Some(at) = self.column_by_name(col) else {
                    return EvalScan::All {
                        range: enclosing_range,
                        partition_key: enclosing_partition,
                    };
                };
                if !self.is_indexable_u64(at) {
                    return EvalScan::All {
                        range: enclosing_range,
                        partition_key: enclosing_partition,
                    };
                }
                let Some(index) = self.column_index(at) else {
                    return EvalScan::All {
                        range: enclosing_range,
                        partition_key: enclosing_partition,
                    };
                };
                let span_limit = match narrow {
                    Some((lo, hi)) => (hi - lo) as usize / 2 + 64,
                    None => (self.rows as usize) / 2,
                };
                match index.rows_in_range(*low, *high, narrow, span_limit) {
                    Some(rows) => EvalScan::Owned(rows),
                    None => EvalScan::All {
                        range: enclosing_range,
                        partition_key: enclosing_partition,
                    },
                }
            }
            RowFilter::EqText(col, val) => {
                let Some(at) = self.column_by_name(col) else {
                    return EvalScan::All {
                        range: enclosing_range,
                        partition_key: enclosing_partition,
                    };
                };
                if !self.is_indexable_text(at) {
                    return EvalScan::All {
                        range: enclosing_range,
                        partition_key: enclosing_partition,
                    };
                }
                let Some(id) = self.dict.lookup_str(val) else {
                    return EvalScan::Owned(Vec::new());
                };
                if sql_scan_opt_enabled()
                    && self.indexes[at].get().is_none()
                    && self.eq_probe_hits[at]
                        .compare_exchange(
                            0,
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                            std::sync::atomic::Ordering::Relaxed,
                        )
                        .is_ok()
                    && let Some(rows) = self.scan_text_ids(at, &[id], narrow)
                {
                    return EvalScan::Owned(rows);
                }
                let Some(index) = self.column_index(at) else {
                    return EvalScan::All {
                        range: enclosing_range,
                        partition_key: enclosing_partition,
                    };
                };
                EvalScan::Slice(index.rows_for_key(u64::from(id), narrow))
            }
            RowFilter::InText(col, vals) => {
                let Some(at) = self.column_by_name(col) else {
                    return EvalScan::All {
                        range: enclosing_range,
                        partition_key: enclosing_partition,
                    };
                };
                if vals.is_empty() {
                    return EvalScan::Owned(Vec::new());
                }
                if !self.is_indexable_text(at) {
                    return EvalScan::All {
                        range: enclosing_range,
                        partition_key: enclosing_partition,
                    };
                }
                let ids: Vec<u32> = vals
                    .iter()
                    .filter_map(|val| self.dict.lookup_str(val))
                    .collect();
                if ids.is_empty() {
                    return EvalScan::Owned(Vec::new());
                }
                if sql_scan_opt_enabled()
                    && self.indexes[at].get().is_none()
                    && ids.len() <= 8
                    && self.eq_probe_hits[at]
                        .compare_exchange(
                            0,
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                            std::sync::atomic::Ordering::Relaxed,
                        )
                        .is_ok()
                    && let Some(rows) = self.scan_text_ids(at, &ids, narrow)
                {
                    return EvalScan::Owned(rows);
                }
                let Some(index) = self.column_index(at) else {
                    return EvalScan::All {
                        range: enclosing_range,
                        partition_key: enclosing_partition,
                    };
                };
                let mut rows = Vec::new();
                for id in ids {
                    rows.extend_from_slice(index.rows_for_key(u64::from(id), narrow));
                }
                rows.sort_unstable();
                rows.dedup();
                EvalScan::Owned(rows)
            }
            RowFilter::LikeAsciiPrefix(col, prefix) => self.eval_like_ascii_filters(
                col,
                &[prefix.as_bytes()],
                &[],
                &[],
                enclosing_range,
                enclosing_partition,
            ),
            RowFilter::LikeAsciiPrefixSuffix(col, prefix, suffix) => self.eval_like_ascii_filters(
                col,
                &[],
                &[(prefix.as_bytes(), suffix.as_bytes())],
                &[],
                enclosing_range,
                enclosing_partition,
            ),
            RowFilter::LikeAsciiContains(col, needle) => self.eval_like_ascii_filters(
                col,
                &[],
                &[],
                &[needle.as_bytes()],
                enclosing_range,
                enclosing_partition,
            ),
            RowFilter::And(children) => {
                let mut range = enclosing_range;
                let mut part_key = enclosing_partition;
                for child in children {
                    if let RowFilter::EqU64(col, val) = child
                        && self
                            .column_by_name(col)
                            .is_some_and(|at| self.is_partition_column(at))
                        && let Some((start, end)) = self.range_of(*val)
                    {
                        range = Some(match range {
                            Some((lo, hi)) => (lo.max(start), hi.min(end)),
                            None => {
                                part_key = Some(*val);
                                (start, end)
                            }
                        });
                        if let Some((lo, hi)) = range
                            && lo >= hi
                        {
                            return EvalScan::Owned(Vec::new());
                        }
                    }
                }
                let narrow =
                    range.and_then(|(s, e)| Some((u32::try_from(s).ok()?, u32::try_from(e).ok()?)));
                let mut consumed = vec![false; children.len()];
                let mut pieces: Vec<RowPiece<'_>> = Vec::new();

                if sql_scan_opt_enabled() && self.partitions.is_some() {
                    use std::sync::atomic::Ordering::Relaxed;
                    struct DerivedCand {
                        child_idx: usize,
                        col: usize,
                        derive: Derive,
                        ids: Vec<u32>,
                    }
                    let mut by_idx_col: BTreeMap<usize, Vec<DerivedCand>> = BTreeMap::new();
                    for (idx, child) in children.iter().enumerate() {
                        match child {
                            RowFilter::EqText(col, val) => {
                                if let Some(at) = self.column_by_name(col)
                                    && self.is_indexable_text(at)
                                    && let Some(derived) = self.derived[at]
                                {
                                    let Some(id) = self.dict.lookup_str(val) else {
                                        return EvalScan::Owned(Vec::new());
                                    };
                                    if self.indexes[at].get().is_none() {
                                        by_idx_col.entry(derived.index_column).or_default().push(
                                            DerivedCand {
                                                child_idx: idx,
                                                col: at,
                                                derive: derived.derive,
                                                ids: vec![id],
                                            },
                                        );
                                    }
                                }
                            }
                            RowFilter::InText(col, vals) => {
                                if let Some(at) = self.column_by_name(col)
                                    && self.is_indexable_text(at)
                                    && let Some(derived) = self.derived[at]
                                {
                                    if vals.is_empty() {
                                        return EvalScan::Owned(Vec::new());
                                    }
                                    let mut ids = Vec::with_capacity(vals.len());
                                    for val in vals {
                                        if let Some(id) = self.dict.lookup_str(val)
                                            && !ids.contains(&id)
                                        {
                                            ids.push(id);
                                        }
                                    }
                                    if ids.is_empty() {
                                        return EvalScan::Owned(Vec::new());
                                    }
                                    if ids.len() <= 8 && self.indexes[at].get().is_none() {
                                        by_idx_col.entry(derived.index_column).or_default().push(
                                            DerivedCand {
                                                child_idx: idx,
                                                col: at,
                                                derive: derived.derive,
                                                ids,
                                            },
                                        );
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    for (index_column, group) in by_idx_col {
                        if group.len() >= 2
                            && group
                                .iter()
                                .any(|c| self.eq_probe_hits[c.col].load(Relaxed) == 0)
                        {
                            let preds: Vec<(Derive, &[u32])> =
                                group.iter().map(|c| (c.derive, c.ids.as_slice())).collect();
                            if let Some(rows) =
                                self.scan_derived_group(index_column, &preds, narrow)
                            {
                                for c in &group {
                                    consumed[c.child_idx] = true;
                                    let _ = self.eq_probe_hits[c.col]
                                        .compare_exchange(0, 1, Relaxed, Relaxed);
                                }
                                if rows.is_empty() {
                                    return EvalScan::Owned(Vec::new());
                                }
                                pieces.push(RowPiece::Owned(rows));
                            }
                        }
                    }
                }

                for (idx, child) in children.iter().enumerate() {
                    if consumed[idx] {
                        continue;
                    }
                    match self.eval_filter(child, range, part_key) {
                        EvalScan::All {
                            range: r,
                            partition_key: k,
                        } => {
                            if let Some((lo, hi)) = r {
                                range = Some(match range {
                                    Some((a, b)) => (a.max(lo), b.min(hi)),
                                    None => {
                                        part_key = k;
                                        (lo, hi)
                                    }
                                });
                                if let Some((a, b)) = range
                                    && a >= b
                                {
                                    return EvalScan::Owned(Vec::new());
                                }
                            }
                        }
                        EvalScan::Slice(s) => {
                            if s.is_empty() {
                                return EvalScan::Owned(Vec::new());
                            }
                            pieces.push(RowPiece::Slice(s));
                        }
                        EvalScan::Owned(v) => {
                            if v.is_empty() {
                                return EvalScan::Owned(Vec::new());
                            }
                            pieces.push(RowPiece::Owned(v));
                        }
                    }
                }
                match intersect_row_pieces(pieces) {
                    None => EvalScan::All {
                        range,
                        partition_key: part_key,
                    },
                    Some(RowPiece::Slice(s)) => EvalScan::Slice(s),
                    Some(RowPiece::Owned(v)) => EvalScan::Owned(v),
                }
            }
            RowFilter::Or(children) => {
                if children.is_empty() {
                    return EvalScan::Owned(Vec::new());
                }
                let scan_opt = sql_scan_opt_enabled();
                let mut prefix_groups: BTreeMap<&str, Vec<&[u8]>> = BTreeMap::new();
                type BorrowedPairList<'b> = Vec<(&'b [u8], &'b [u8])>;
                let mut pair_groups: BTreeMap<&str, BorrowedPairList<'_>> = BTreeMap::new();
                let mut contains_groups: BTreeMap<&str, Vec<&[u8]>> = BTreeMap::new();
                let mut combined = Vec::new();
                let mut pending: Vec<&RowFilter> = children.iter().rev().collect();
                while let Some(child) = pending.pop() {
                    if scan_opt && let RowFilter::Or(nested) = child {
                        for item in nested.iter().rev() {
                            pending.push(item);
                        }
                        continue;
                    }
                    match child {
                        RowFilter::LikeAsciiPrefix(col, prefix) => {
                            prefix_groups
                                .entry(col.as_str())
                                .or_default()
                                .push(prefix.as_bytes());
                            continue;
                        }
                        RowFilter::LikeAsciiPrefixSuffix(col, prefix, suffix) => {
                            pair_groups
                                .entry(col.as_str())
                                .or_default()
                                .push((prefix.as_bytes(), suffix.as_bytes()));
                            continue;
                        }
                        RowFilter::LikeAsciiContains(col, needle) => {
                            contains_groups
                                .entry(col.as_str())
                                .or_default()
                                .push(needle.as_bytes());
                            continue;
                        }
                        _ => {}
                    }
                    match self.eval_filter(child, enclosing_range, enclosing_partition) {
                        EvalScan::All { .. } => {
                            return EvalScan::All {
                                range: enclosing_range,
                                partition_key: enclosing_partition,
                            };
                        }
                        EvalScan::Slice(s) => combined.extend_from_slice(s),
                        EvalScan::Owned(v) => combined.extend(v),
                    }
                }
                let cols: Vec<&str> = prefix_groups
                    .keys()
                    .chain(pair_groups.keys())
                    .chain(contains_groups.keys())
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect();
                for col in cols {
                    let prefixes = prefix_groups.remove(col).unwrap_or_default();
                    let pairs = pair_groups.remove(col).unwrap_or_default();
                    let contains = contains_groups.remove(col).unwrap_or_default();
                    match self.eval_like_ascii_filters(
                        col,
                        &prefixes,
                        &pairs,
                        &contains,
                        enclosing_range,
                        enclosing_partition,
                    ) {
                        EvalScan::All { .. } => {
                            return EvalScan::All {
                                range: enclosing_range,
                                partition_key: enclosing_partition,
                            };
                        }
                        EvalScan::Slice(s) => combined.extend_from_slice(s),
                        EvalScan::Owned(v) => combined.extend(v),
                    }
                }
                combined.sort_unstable();
                combined.dedup();
                EvalScan::Owned(combined)
            }
        }
    }

    fn eval_like_ascii_filters<'a>(
        &'a self,
        col: &str,
        lower_prefixes: &[&[u8]],
        lower_pairs: &[(&[u8], &[u8])],
        lower_contains: &[&[u8]],
        enclosing_range: Option<(u64, u64)>,
        enclosing_partition: Option<u64>,
    ) -> EvalScan<'a> {
        let Some(at) = self.column_by_name(col) else {
            return EvalScan::All {
                range: enclosing_range,
                partition_key: enclosing_partition,
            };
        };
        if !self.is_indexable_text(at) {
            return EvalScan::All {
                range: enclosing_range,
                partition_key: enclosing_partition,
            };
        }
        let Some(index) = self.column_index(at) else {
            return EvalScan::All {
                range: enclosing_range,
                partition_key: enclosing_partition,
            };
        };
        let narrow = enclosing_range
            .and_then(|(s, e)| Some((u32::try_from(s).ok()?, u32::try_from(e).ok()?)));

        let merge_ids = |ids: &[u32]| -> EvalScan<'a> {
            if ids.is_empty() {
                return EvalScan::Owned(Vec::new());
            }
            if ids.len() == 1 {
                return EvalScan::Slice(index.rows_for_key(u64::from(ids[0]), narrow));
            }
            let mut slices = Vec::with_capacity(ids.len());
            let mut total = 0usize;
            for &id in ids {
                let slice = index.rows_for_key(u64::from(id), narrow);
                if !slice.is_empty() {
                    total += slice.len();
                    slices.push(slice);
                }
            }
            let mut rows = Vec::with_capacity(total);
            for slice in slices {
                rows.extend_from_slice(slice);
            }
            rows.sort_unstable();
            EvalScan::Owned(rows)
        };

        let scan_opt = sql_scan_opt_enabled();
        if scan_opt {
            let mut norm_prefixes: Vec<Box<[u8]>> = lower_prefixes
                .iter()
                .map(|p| p.to_vec().into_boxed_slice())
                .collect();
            norm_prefixes.sort();
            norm_prefixes.dedup();
            let mut norm_pairs: Vec<OwnedPrefixSuffixPair> = lower_pairs
                .iter()
                .map(|(p, s)| (p.to_vec().into_boxed_slice(), s.to_vec().into_boxed_slice()))
                .collect();
            norm_pairs.sort();
            norm_pairs.dedup();
            let mut norm_contains: Vec<Box<[u8]>> = lower_contains
                .iter()
                .map(|n| n.to_vec().into_boxed_slice())
                .collect();
            norm_contains.sort();
            norm_contains.dedup();
            let cache_key = FilterCacheKey {
                prefixes: norm_prefixes,
                pairs: norm_pairs,
                contains: norm_contains,
            };
            let hit = self.filter_id_cache.lock().ok().and_then(|mut guard| {
                let pos = guard
                    .entries
                    .iter()
                    .position(|(col_idx, k, _)| *col_idx == at && *k == cache_key)?;
                let entry = guard.entries.remove(pos);
                let cached = entry.2.clone();
                guard.entries.push(entry);
                Some(cached)
            });
            match hit {
                Some(CachedFilterMatch::Rows(all_rows)) => {
                    return EvalScan::Owned(narrow_slice(&all_rows, narrow).to_vec());
                }
                Some(CachedFilterMatch::Ids(ids)) => {
                    return merge_ids(&ids);
                }
                None => {
                    let computed: Arc<[u32]> = Arc::from(self.dict.filter_ids_by_ascii_filters_ci(
                        index.keys(),
                        lower_prefixes,
                        lower_pairs,
                        lower_contains,
                    ));
                    if computed.is_empty() {
                        if let Ok(mut guard) = self.filter_id_cache.lock() {
                            guard.insert(at, cache_key, CachedFilterMatch::Rows(Arc::from([])));
                        }
                        return EvalScan::Owned(Vec::new());
                    }
                    if computed.len() == 1 {
                        if let Ok(mut guard) = self.filter_id_cache.lock() {
                            guard.insert(
                                at,
                                cache_key,
                                CachedFilterMatch::Ids(Arc::clone(&computed)),
                            );
                        }
                        return EvalScan::Slice(index.rows_for_key(u64::from(computed[0]), narrow));
                    }
                    let mut full_slices = Vec::with_capacity(computed.len());
                    let mut full_total = 0usize;
                    for &id in computed.iter() {
                        let slice = index.rows_for_key(u64::from(id), None);
                        if !slice.is_empty() {
                            full_total = full_total.saturating_add(slice.len());
                            full_slices.push(slice);
                        }
                    }
                    if full_total == 0 {
                        if let Ok(mut guard) = self.filter_id_cache.lock() {
                            guard.insert(at, cache_key, CachedFilterMatch::Rows(Arc::from([])));
                        }
                        return EvalScan::Owned(Vec::new());
                    }
                    if full_total <= MAX_CACHED_ENTRY_ROWS {
                        let mut all_rows = Vec::with_capacity(full_total);
                        for slice in full_slices {
                            all_rows.extend_from_slice(slice);
                        }
                        all_rows.sort_unstable();
                        let arc_rows: Arc<[u32]> = Arc::from(all_rows);
                        if let Ok(mut guard) = self.filter_id_cache.lock() {
                            guard.insert(
                                at,
                                cache_key,
                                CachedFilterMatch::Rows(Arc::clone(&arc_rows)),
                            );
                        }
                        return EvalScan::Owned(narrow_slice(&arc_rows, narrow).to_vec());
                    }
                    if let Ok(mut guard) = self.filter_id_cache.lock() {
                        guard.insert(at, cache_key, CachedFilterMatch::Ids(Arc::clone(&computed)));
                    }
                    return merge_ids(&computed);
                }
            }
        }
        let ids = if lower_pairs.is_empty() && lower_contains.is_empty() {
            self.dict
                .filter_ids_by_ascii_prefixes_ci(index.keys(), lower_prefixes)
        } else {
            self.dict.filter_ids_by_ascii_filters_ci(
                index.keys(),
                lower_prefixes,
                lower_pairs,
                lower_contains,
            )
        };
        merge_ids(&ids)
    }

    pub fn cursor_for_scan(
        self: &Arc<Self>,
        scan: &PlannedScan,
        control: SqlControl,
    ) -> StoreCursor {
        match scan {
            PlannedScan::All { .. } => self.cursor_over(0, self.rows, control),
            PlannedScan::Partition { key, .. } => self.cursor_for_partition(*key, control),
            PlannedScan::Rows(rows) => StoreCursor {
                store: Arc::clone(self),
                mode: CursorMode::Rows {
                    rows: Arc::clone(rows),
                    at: 0,
                },
                current: 0,
                hints: vec![std::cell::Cell::new(0); self.columns.len()],
                text_cache: std::cell::RefCell::new((u32::MAX, 0, Vec::new())),
                fast_udf: sql_fast_udf_enabled(),
                control,
            },
        }
    }

    /// Bytes of each column, in schema order; a derived column holds none.
    pub fn column_bytes(&self) -> Vec<usize> {
        self.columns.iter().map(|c| c.ints.bytes_used()).collect()
    }

    /// The reference tables the derived columns read, which stores of the same DEX share.
    pub fn tables(&self) -> impl Iterator<Item = &Arc<RefTable>> {
        self.tables.values()
    }

    pub fn cursor(self: &Arc<Self>, control: SqlControl) -> StoreCursor {
        self.cursor_over(0, self.rows, control)
    }

    /// A cursor over the rows whose partition column is `key`, when the store knows where they are (it was built one
    /// partition after another, and every row of a partition has the key of it); over every row when it does not.
    pub fn cursor_for_partition(self: &Arc<Self>, key: u64, control: SqlControl) -> StoreCursor {
        match self.range_of(key) {
            Some((start, end)) => self.cursor_over(start, end, control),
            None => self.cursor_over(0, self.rows, control),
        }
    }

    fn cursor_over(self: &Arc<Self>, start: u64, end: u64, control: SqlControl) -> StoreCursor {
        StoreCursor {
            store: Arc::clone(self),
            mode: CursorMode::Range { next: start, end },
            current: start,
            hints: vec![std::cell::Cell::new(0); self.columns.len()],
            text_cache: std::cell::RefCell::new((u32::MAX, 0, Vec::new())),
            fast_udf: sql_fast_udf_enabled(),
            control,
        }
    }

    /// The rows `start..end` that have `key` in the partition column, or `None` when the store does not know.
    pub fn range_of(&self, key: u64) -> Option<(u64, u64)> {
        let partitions = self.partitions.as_ref()?;
        Some(
            partitions
                .binary_search_by_key(&key, |partition| partition.key)
                .map_or((0, 0), |at| (partitions[at].start, partitions[at].end)),
        )
    }

    /// The value of one cell. `column` and `row` must be in range.
    pub fn cell(&self, column: usize, row: u64) -> MddResult<SqlValue> {
        let hints = vec![std::cell::Cell::new(0); self.columns.len()];
        self.cell_at(column, row, &hints)
    }

    /// The value of one cell, derived or stored. `hints` is the cursor's, one run per column (see `IntColumn::get`).
    fn cell_at(
        &self,
        column: usize,
        row: u64,
        hints: &[std::cell::Cell<usize>],
    ) -> MddResult<SqlValue> {
        let Some(Some(derived)) = self.derived.get(column) else {
            let hint = hints
                .get(column)
                .ok_or_else(|| crate::invalid("CURSOR_COORDINATE"))?;
            let mut run = hint.get();
            let value = self.cell_with(column, row, &mut run);
            hint.set(run);
            return Ok(value);
        };
        let missing = || crate::invalid("STORE_DERIVED_REFERENCE_MISSING");
        let read = |at: usize| -> MddResult<u64> {
            let hint = hints.get(at).ok_or_else(missing)?;
            let mut run = hint.get();
            let raw = self.columns[at].ints.get(row, &mut run);
            hint.set(run);
            raw.ok_or_else(missing)
        };
        let file = read(self.partition_column.ok_or_else(missing)?)?;
        let index = read(derived.index_column)?;
        let id = self
            .table_for(file)
            .and_then(|table| table.id(derived.derive, index))
            .ok_or_else(missing)?;
        Ok(self.dict.get(id))
    }

    fn cell_with(&self, column: usize, row: u64, hint: &mut usize) -> SqlValue {
        let Some(raw) = self.columns[column].ints.get(row, hint) else {
            return SqlValue::Null;
        };
        match self.columns[column].kind {
            Kind::Bool => SqlValue::Bool(raw != 0),
            Kind::I64 => SqlValue::I64(Signed64(raw as i64)),
            Kind::U64 => SqlValue::U64(DecimalU64(raw)),
            Kind::F64 => SqlValue::F64(DecimalU64(raw)),
            Kind::Dict => self.dict.get(raw as u32),
        }
    }

    pub fn column_types(&self) -> &[SqlType] {
        &self.types
    }
}

/// One cell of a row handed over without building a `SqlValue`: what the relations that fill the biggest stores need.
/// `Str` is what `SqlValue::Text(SqlText::from_utf8(..))` is, without the UTF-16 copy.
#[derive(Clone, Copy, Debug)]
pub enum Cell<'a> {
    Null,
    I64(i64),
    U64(u64),
    F64(u64),
    Str(&'a str),
    SpacedHexBytes(&'a [u8]),
}

/// Where the rows of a relation go as they are produced, one at a time, so the rows of a DEX are never all alive at once.
pub trait RowSink {
    fn row(&mut self, row: SqlRow) -> MddResult<()>;
    fn cells(&mut self, cells: &[Cell<'_>]) -> MddResult<()>;
}

impl RowSink for RelationStoreBuilder {
    fn row(&mut self, row: SqlRow) -> MddResult<()> {
        self.push(&row)
    }

    fn cells(&mut self, cells: &[Cell<'_>]) -> MddResult<()> {
        self.push_cells(cells)
    }
}

pub struct RelationStoreBuilder {
    schema: Vec<SqlColumn>,
    columns: Vec<Column>,
    derived: Vec<Option<DerivedColumn>>,
    tables: BTreeMap<u64, Arc<RefTable>>,
    rows: u64,
    dict: Arc<TextDict>,
    /// The column that picks a partition: `file_id`, when the relation has one of unsigned integers.
    partition_column: Option<usize>,
    partitions: Vec<Partition>,
    /// Still true while every row went into the partition it was started in and the keys only grew.
    partitioned: bool,
    max_cell_bytes: u64,
}

impl RelationStoreBuilder {
    pub fn new(schema: &[SqlColumn], dict: Arc<TextDict>) -> Self {
        Self::with_derived(schema, dict, &[])
    }

    /// As `new`, with some columns not stored: their values are read from the reference table of the row's DEX (see
    /// `DerivedColumn`). Rows are still given with every cell; the derived ones are not kept, and a build with debug
    /// assertions checks each against the table. Needs a partition column and a table for every partition
    /// (`set_table`); a text column that is nullable cannot be derived.
    pub fn with_derived(
        schema: &[SqlColumn],
        dict: Arc<TextDict>,
        derived: &[DerivedColumn],
    ) -> Self {
        let columns = schema
            .iter()
            .map(|column| {
                let (kind, order) = match column.data_type {
                    SqlType::Bool => (Kind::Bool, Order::Unsigned),
                    SqlType::I64 => (Kind::I64, Order::Signed),
                    SqlType::U64 => (Kind::U64, Order::Unsigned),
                    SqlType::F64 => (Kind::F64, Order::Unsigned),
                    SqlType::Text | SqlType::Bytes => (Kind::Dict, Order::Unsigned),
                };
                Column {
                    kind,
                    ints: IntColumn::new(order),
                    has_tagged_text: false,
                }
            })
            .collect();
        let partition_column = schema
            .iter()
            .position(|column| column.name == "file_id" && column.data_type == SqlType::U64);
        let mut by_column: Vec<Option<DerivedColumn>> = vec![None; schema.len()];
        for derived in derived {
            let usable = partition_column.is_some()
                && derived.column < schema.len()
                && derived.index_column < schema.len()
                && schema[derived.column].data_type == SqlType::Text
                && !schema[derived.column].nullable
                && schema[derived.index_column].data_type == SqlType::U64
                && by_column[derived.index_column].is_none();
            if usable {
                by_column[derived.column] = Some(*derived);
            }
        }
        Self {
            schema: schema.to_vec(),
            columns,
            derived: by_column,
            tables: BTreeMap::new(),
            rows: 0,
            dict,
            partition_column,
            partitions: Vec::new(),
            partitioned: partition_column.is_some(),
            max_cell_bytes: 16,
        }
    }

    /// The rows from here on, until the next call, have `key` in the partition column. A row that is not in the
    /// partition it was added to, or a key that does not grow, makes the store unpartitioned: it is still correct, and
    /// a cursor for a key reads every row.
    pub fn begin_partition(&mut self, key: u64) {
        if self.partition_column.is_none() {
            return;
        }
        if let Some(last) = self.partitions.last_mut() {
            last.end = self.rows;
            if key <= last.key {
                self.partitioned = false;
            }
        }
        self.partitions.push(Partition {
            key,
            start: self.rows,
            end: self.rows,
        });
    }

    /// The reference table of the partition begun last: what its derived columns are read from. A builder with derived
    /// columns refuses a row whose partition has none.
    pub fn set_table(&mut self, table: Arc<RefTable>) {
        if let Some(partition) = self.partitions.last() {
            self.tables.insert(partition.key, table);
        }
    }

    /// Whether some column is derived, so that `set_table` is needed.
    pub fn has_derived(&self) -> bool {
        self.derived.iter().any(Option::is_some)
    }

    /// Rows added so far.
    pub fn rows(&self) -> u64 {
        self.rows
    }

    /// The table a row being added reads its derived columns from, and the partition key it is added under.
    fn current_table(&self) -> MddResult<&Arc<RefTable>> {
        self.partitions
            .last()
            .and_then(|partition| self.tables.get(&partition.key))
            .ok_or_else(|| crate::invalid("STORE_DERIVED_TABLE_MISSING"))
    }

    /// A build with debug assertions holds every derived cell of a row to the table: the text the producer gave is the
    /// text the table names. A release build trusts the producer, which is what the tests of the producers check.
    #[cfg(debug_assertions)]
    fn check_derived(&self, at: usize, index: Option<u64>, given: &SqlValue) -> MddResult<()> {
        let Some(derived) = self.derived[at] else {
            return Ok(());
        };
        let id = index
            .and_then(|index| self.current_table().ok()?.id(derived.derive, index))
            .ok_or_else(|| crate::invalid("STORE_DERIVED_REFERENCE_MISSING"))?;
        let from_table = self.dict.get(id);
        if &from_table != given {
            return Err(crate::invalid("STORE_DERIVED_VALUE_DIFFERS"));
        }
        Ok(())
    }

    /// Add one row. The row is checked against the schema as a cursor's row would be.
    pub fn push(&mut self, row: &SqlRow) -> MddResult<()> {
        validate_row(row, &self.schema)?;
        if self.has_derived() {
            self.current_table()?;
        }
        for at in 0..self.columns.len() {
            if self.derived[at].is_some() {
                #[cfg(debug_assertions)]
                {
                    let index = self.derived[at].and_then(|d| match &row[d.index_column] {
                        SqlValue::U64(v) => Some(v.0),
                        _ => None,
                    });
                    self.check_derived(at, index, &row[at])?;
                }
                self.max_cell_bytes = self.max_cell_bytes.max(row[at].byte_size());
            }
        }
        for (at, (value, column)) in row.iter().zip(&mut self.columns).enumerate() {
            if self.derived[at].is_some() {
                continue;
            }
            self.max_cell_bytes = self.max_cell_bytes.max(value.byte_size());
            let raw = match (value, column.kind) {
                (SqlValue::Null, _) => None,
                (SqlValue::Bool(v), Kind::Bool) => Some(u64::from(*v)),
                (SqlValue::I64(v), Kind::I64) => Some(v.0 as u64),
                (SqlValue::U64(v), Kind::U64) => Some(v.0),
                (SqlValue::F64(v), Kind::F64) => Some(v.0),
                (_, Kind::Dict) => {
                    if let SqlValue::Text(text) = value
                        && (text.original_mutf8.is_some()
                            || String::from_utf16(&text.utf16).is_err())
                    {
                        column.has_tagged_text = true;
                    }
                    Some(u64::from(
                        self.dict
                            .intern(value)
                            .ok_or_else(|| crate::invalid("STORE_CELL_TYPE"))?,
                    ))
                }
                _ => return Err(crate::invalid("STORE_CELL_TYPE")),
            };
            if self.partition_column == Some(at)
                && self.partitions.last().map(|partition| partition.key) != raw
            {
                self.partitioned = false;
            }
            column.ints.push(raw);
        }
        self.rows += 1;
        Ok(())
    }

    /// Add one row given as cells. It is held to the schema as `push` holds a `SqlRow`: a NULL only where the column
    /// allows one, text only in a text column, numbers only in the kind of column that holds them.
    pub fn push_cells(&mut self, cells: &[Cell<'_>]) -> MddResult<()> {
        if cells.len() != self.columns.len() {
            return Err(crate::invalid("PROVIDER_ROW_WIDTH"));
        }
        if self.has_derived() {
            self.current_table()?;
            for at in 0..cells.len() {
                let Some(derived) = self.derived[at] else {
                    continue;
                };
                // held to the schema as a stored text cell is
                let Cell::Str(text) = cells[at] else {
                    return Err(crate::invalid("PROVIDER_ROW_TYPE"));
                };
                let index = match cells[derived.index_column] {
                    Cell::U64(index) => Some(index),
                    _ => None,
                };
                #[cfg(debug_assertions)]
                self.check_derived(at, index, &SqlValue::text(text))?;
                #[cfg(not(debug_assertions))]
                let _ = index;
                self.max_cell_bytes = self.max_cell_bytes.max(2 * text.len() as u64);
            }
        }
        for (at, ((cell, column), schema)) in cells
            .iter()
            .zip(&mut self.columns)
            .zip(&self.schema)
            .enumerate()
        {
            if self.derived[at].is_some() {
                continue;
            }
            match cell {
                Cell::Str(text) => {
                    self.max_cell_bytes = self.max_cell_bytes.max(2 * text.len() as u64);
                }
                Cell::SpacedHexBytes(raw) if !raw.is_empty() => {
                    self.max_cell_bytes = self.max_cell_bytes.max(2 * (3 * raw.len() as u64 - 1));
                }
                _ => {}
            }
            let raw = match (cell, column.kind) {
                (Cell::Null, _) if schema.nullable => None,
                (Cell::Null, _) => return Err(crate::invalid("PROVIDER_UNEXPECTED_NULL")),
                (Cell::I64(value), Kind::I64) => Some(*value as u64),
                (Cell::U64(value), Kind::U64) => Some(*value),
                (Cell::F64(bits), Kind::F64) => Some(*bits),
                (Cell::Str(text), Kind::Dict) if schema.data_type == SqlType::Text => {
                    Some(u64::from(self.dict.intern_str(text)))
                }
                (Cell::SpacedHexBytes(raw), Kind::Dict) if schema.data_type == SqlType::Text => {
                    Some(u64::from(self.dict.intern_spaced_hex_bytes(raw)))
                }
                _ => return Err(crate::invalid("PROVIDER_ROW_TYPE")),
            };
            if self.partition_column == Some(at)
                && self.partitions.last().map(|partition| partition.key) != raw
            {
                self.partitioned = false;
            }
            column.ints.push(raw);
        }
        self.rows += 1;
        Ok(())
    }

    pub fn finish(mut self) -> Arc<RelationStore> {
        for column in &mut self.columns {
            column.ints.seal();
            column.ints.sealed.shrink_to_fit();
        }
        if let Some(last) = self.partitions.last_mut() {
            last.end = self.rows;
        }
        // every row must be in a partition, and the partitions must cover the rows exactly once
        let covered: u64 = self.partitions.iter().map(|p| p.end - p.start).sum();
        let partitions = (self.partitioned && covered == self.rows).then(|| {
            self.partitions.shrink_to_fit();
            self.partitions
        });
        let names = self
            .schema
            .iter()
            .map(|c| c.name.to_ascii_lowercase())
            .collect();
        let indexes = (0..self.columns.len()).map(|_| OnceLock::new()).collect();
        let eq_probe_hits = (0..self.columns.len())
            .map(|_| std::sync::atomic::AtomicU8::new(0))
            .collect();
        let dense_tables = match self.tables.last_key_value() {
            Some((&max_key, _)) if max_key < 4096 => {
                let mut slots = vec![None; max_key as usize + 1];
                for (&key, table) in &self.tables {
                    slots[key as usize] = Some(Arc::clone(table));
                }
                slots.into_boxed_slice()
            }
            _ => Box::new([]),
        };
        Arc::new(RelationStore {
            types: self.schema.iter().map(|c| c.data_type).collect(),
            names,
            columns: self.columns,
            derived: self.derived,
            tables: self.tables,
            dense_tables,
            partition_column: self.partition_column,
            rows: self.rows,
            dict: self.dict,
            partitions,
            max_cell_bytes: self.max_cell_bytes,
            indexes,
            eq_probe_hits,
            filter_id_cache: Mutex::new(FilterCacheState::default()),
        })
    }
}

enum CursorMode {
    Range { next: u64, end: u64 },
    Rows { rows: Arc<[u32]>, at: usize },
}

/// Reads a store (or a planned subset of its rows) front to back, one `SqlRow` at a time, as a provider cursor.
pub struct StoreCursor {
    store: Arc<RelationStore>,
    mode: CursorMode,
    current: u64,
    /// Per column, the run the last cell came from (see `IntColumn::get`).
    hints: Vec<std::cell::Cell<usize>>,
    /// Single-slot reusable encoded UTF-16 carrier cache `(dict_id, utf16_bytes, buf)`.
    text_cache: std::cell::RefCell<(u32, u64, Vec<u8>)>,
    fast_udf: bool,
    control: SqlControl,
}

impl StoreCursor {
    fn set_sqlite_dict_text(
        &self,
        id: u32,
        max_cell_bytes: u64,
        context: &mut rusqlite::vtab::Context,
    ) -> Option<MddResult<rusqlite::Result<()>>> {
        {
            let mut cache = self.text_cache.borrow_mut();
            let (cached_id, cached_bytes, buf) = &mut *cache;
            if *cached_id == id && !buf.is_empty() {
                if *cached_bytes > max_cell_bytes {
                    return Some(Err(crate::quota("SQL_CELL_BYTES")));
                }
                let slice: &[u8] = &buf[..];
                return Some(Ok(context.set_result(&slice)));
            }
            if let Some(encoded) = self
                .store
                .dict
                .encode_sqlite_text_into(id, max_cell_bytes, buf)
            {
                return match encoded {
                    Ok(text_bytes) => {
                        *cached_id = id;
                        *cached_bytes = text_bytes;
                        let slice: &[u8] = &buf[..];
                        Some(Ok(context.set_result(&slice)))
                    }
                    Err(err) => {
                        *cached_id = u32::MAX;
                        buf.clear();
                        Some(Err(err))
                    }
                };
            }
            *cached_id = u32::MAX;
            buf.clear();
        }
        self.store
            .dict
            .sqlite_text_value(id, max_cell_bytes)
            .map(|res| res.map(|val| context.set_result(&val)))
    }
}

impl SqlFactCursor for StoreCursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
        if !self.advance()? {
            return Ok(None);
        }
        Ok(Some(
            (0..self.hints.len())
                .map(|column| self.value(column))
                .collect::<MddResult<_>>()?,
        ))
    }

    fn positioned(&mut self) -> Option<&mut dyn PositionedCursor> {
        Some(self)
    }

    fn positioned_ref(&self) -> Option<&dyn PositionedCursor> {
        Some(self)
    }
}

impl PositionedCursor for StoreCursor {
    fn advance(&mut self) -> MddResult<bool> {
        let row = match &mut self.mode {
            CursorMode::Range { next, end } => {
                if *next >= *end {
                    return Ok(false);
                }
                let row = *next;
                *next += 1;
                row
            }
            CursorMode::Rows { rows, at } => {
                let Some(&row) = rows.get(*at) else {
                    return Ok(false);
                };
                *at += 1;
                u64::from(row)
            }
        };
        self.control.checkpoint(1, true)?;
        self.current = row;
        Ok(true)
    }

    fn value(&self, column: usize) -> MddResult<SqlValue> {
        self.store.cell_at(column, self.current, &self.hints)
    }

    fn sqlite_value(
        &self,
        column: usize,
        max_cell_bytes: u64,
    ) -> Option<MddResult<rusqlite::types::Value>> {
        if !self.fast_udf {
            return None;
        }
        let col_count = self.store.columns.len();
        if column >= col_count {
            return None;
        }
        if let Some(Some(derived)) = self.store.derived.get(column) {
            let part_col = self.store.partition_column?;
            let read = |at: usize| -> Option<u64> {
                let hint = self.hints.get(at)?;
                let mut run = hint.get();
                let raw = self.store.columns[at].ints.get(self.current, &mut run);
                hint.set(run);
                raw
            };
            let file = read(part_col)?;
            let index = read(derived.index_column)?;
            let id = self.store.table_for(file)?.id(derived.derive, index)?;
            return self.store.dict.sqlite_text_value(id, max_cell_bytes);
        }
        let hint = self.hints.get(column)?;
        let mut run = hint.get();
        let raw = self.store.columns[column].ints.get(self.current, &mut run);
        hint.set(run);
        let Some(raw) = raw else {
            return Some(Ok(rusqlite::types::Value::Null));
        };
        match self.store.columns[column].kind {
            Kind::Bool => Some(Ok(rusqlite::types::Value::Integer(i64::from(raw != 0)))),
            Kind::I64 => Some(Ok(rusqlite::types::Value::Integer(raw as i64))),
            Kind::U64 => {
                if 16 > max_cell_bytes {
                    return Some(Err(crate::quota("SQL_CELL_BYTES")));
                }
                let mut bytes = Vec::with_capacity(crate::values::UNSIGNED.len() + 8);
                bytes.extend_from_slice(crate::values::UNSIGNED);
                bytes.extend_from_slice(&raw.to_be_bytes());
                Some(Ok(rusqlite::types::Value::Blob(bytes)))
            }
            Kind::Dict => self
                .store
                .dict
                .sqlite_text_value(raw as u32, max_cell_bytes),
            Kind::F64 => None,
        }
    }

    fn set_sqlite_column(
        &self,
        column: usize,
        max_cell_bytes: u64,
        context: &mut rusqlite::vtab::Context,
    ) -> Option<MddResult<rusqlite::Result<()>>> {
        if !self.fast_udf {
            return None;
        }
        let col_count = self.store.columns.len();
        if column >= col_count {
            return None;
        }
        if let Some(Some(derived)) = self.store.derived.get(column) {
            let part_col = self.store.partition_column?;
            let read = |at: usize| -> Option<u64> {
                let hint = self.hints.get(at)?;
                let mut run = hint.get();
                let raw = self.store.columns[at].ints.get(self.current, &mut run);
                hint.set(run);
                raw
            };
            let file = read(part_col)?;
            let index = read(derived.index_column)?;
            let id = self.store.table_for(file)?.id(derived.derive, index)?;
            return self.set_sqlite_dict_text(id, max_cell_bytes, context);
        }
        let hint = self.hints.get(column)?;
        let mut run = hint.get();
        let raw = self.store.columns[column].ints.get(self.current, &mut run);
        hint.set(run);
        let Some(raw) = raw else {
            return Some(Ok(context.set_result(&rusqlite::types::Null)));
        };
        match self.store.columns[column].kind {
            Kind::Bool => Some(Ok(context.set_result(&i64::from(raw != 0)))),
            Kind::I64 => Some(Ok(context.set_result(&(raw as i64)))),
            Kind::U64 => {
                if 16 > max_cell_bytes {
                    return Some(Err(crate::quota("SQL_CELL_BYTES")));
                }
                let mut buf = [0u8; 17];
                buf[..crate::values::UNSIGNED.len()].copy_from_slice(crate::values::UNSIGNED);
                buf[crate::values::UNSIGNED.len()..].copy_from_slice(&raw.to_be_bytes());
                let slice: &[u8] = &buf[..];
                Some(Ok(context.set_result(&slice)))
            }
            Kind::Dict => self.set_sqlite_dict_text(raw as u32, max_cell_bytes, context),
            Kind::F64 => None,
        }
    }

    fn max_cell_bytes(&self) -> u64 {
        self.store.max_cell_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::SqlLimits;

    fn column(name: &str, data_type: SqlType, nullable: bool) -> SqlColumn {
        SqlColumn {
            id: name.to_owned(),
            name: name.to_owned(),
            data_type,
            nullable,
        }
    }

    fn schema() -> Vec<SqlColumn> {
        vec![
            column("flag", SqlType::Bool, true),
            column("small", SqlType::I64, true),
            column("big", SqlType::U64, false),
            column("real", SqlType::F64, true),
            column("name", SqlType::Text, true),
            column("blob", SqlType::Bytes, true),
        ]
    }

    fn control() -> SqlControl {
        SqlControl::new(SqlLimits::default(), None)
    }

    fn read_all(store: &Arc<RelationStore>) -> Vec<SqlRow> {
        let mut cursor = store.cursor(control());
        let mut rows = Vec::new();
        while let Some(row) = cursor.next_row().unwrap() {
            rows.push(row);
        }
        rows
    }

    fn text(units: &[u16], original: Option<&[u8]>) -> SqlValue {
        SqlValue::Text(SqlText {
            utf16: units.to_vec(),
            original_mutf8: original.map(<[u8]>::to_vec),
        })
    }

    #[test]
    fn every_kind_of_cell_reads_back_exactly() {
        let rows: Vec<SqlRow> = vec![
            vec![
                SqlValue::Bool(true),
                SqlValue::I64(Signed64(-5)),
                SqlValue::U64(DecimalU64(u64::MAX)),
                SqlValue::F64(DecimalU64(f64::NAN.to_bits())),
                SqlValue::text("Lcom/example/A;"),
                SqlValue::Bytes(vec![0, 1, 255]),
            ],
            vec![
                SqlValue::Null,
                SqlValue::I64(Signed64(i64::MIN)),
                SqlValue::U64(DecimalU64(0)),
                SqlValue::Null,
                SqlValue::Null,
                SqlValue::Null,
            ],
            vec![
                SqlValue::Bool(false),
                SqlValue::I64(Signed64(i64::MAX)),
                SqlValue::U64(DecimalU64(7)),
                SqlValue::F64(DecimalU64((-0.0f64).to_bits())),
                // a legal non-scalar string: a lone surrogate, with its original MUTF-8 bytes
                text(&[0x61, 0xd800, 0x62], Some(&[0x61, 0xed, 0xa0, 0x80, 0x62])),
                SqlValue::DexMutf8 {
                    bytes: vec![0x61, 0xc0, 0x80],
                    utf16_code_units: DecimalU64(2),
                },
            ],
            vec![
                SqlValue::Bool(true),
                SqlValue::I64(Signed64(0)),
                SqlValue::U64(DecimalU64(1)),
                SqlValue::F64(DecimalU64(1.5f64.to_bits())),
                // scalar text that also keeps original bytes must not collapse to the plain form
                text(
                    &"é".encode_utf16().collect::<Vec<_>>(),
                    Some("é".as_bytes()),
                ),
                SqlValue::Bytes(Vec::new()),
            ],
            vec![
                SqlValue::Bool(true),
                SqlValue::I64(Signed64(0)),
                SqlValue::U64(DecimalU64(1)),
                SqlValue::F64(DecimalU64(1.5f64.to_bits())),
                SqlValue::text(""),
                SqlValue::Bytes(Vec::new()),
            ],
        ];
        let dict = TextDict::new();
        let mut builder = RelationStoreBuilder::new(&schema(), dict);
        for row in &rows {
            builder.push(row).unwrap();
        }
        let store = builder.finish();
        assert_eq!(store.rows(), rows.len() as u64);
        assert_eq!(read_all(&store), rows);
    }

    #[test]
    fn a_text_with_original_bytes_and_the_same_text_without_stay_two_values() {
        let plain = SqlValue::text("é");
        let kept = text(
            &"é".encode_utf16().collect::<Vec<_>>(),
            Some("é".as_bytes()),
        );
        let dict = TextDict::new();
        let a = dict.intern(&plain).unwrap();
        let b = dict.intern(&kept).unwrap();
        assert_ne!(a, b);
        assert_eq!(dict.get(a), plain);
        assert_eq!(dict.get(b), kept);
        assert_eq!(
            dict.intern(&plain),
            Some(a),
            "the same value has the same id"
        );
        assert_eq!(dict.len(), 2);
    }

    #[test]
    fn a_dictionary_does_not_confuse_values_that_share_a_hash_or_a_prefix() {
        let dict = TextDict::new();
        let mut ids = Vec::new();
        let values: Vec<SqlValue> = (0..5000)
            .map(|n| SqlValue::text(&format!("L{n};")))
            .chain((0..50).map(|n| SqlValue::Bytes(vec![n as u8; n])))
            .collect();
        for value in &values {
            ids.push(dict.intern(value).unwrap());
        }
        for (value, id) in values.iter().zip(&ids) {
            assert_eq!(&dict.get(*id), value);
            assert_eq!(dict.intern(value), Some(*id));
        }
        let mut distinct = ids.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            values.len(),
            "every value here is different, so every id is"
        );
        assert!(dict.intern(&SqlValue::Null).is_none());
    }

    #[test]
    fn rows_given_as_cells_are_the_rows_given_as_values() {
        let schema = vec![
            column("file", SqlType::U64, false),
            column("name", SqlType::Text, false),
            column("kind", SqlType::Text, true),
            column("idx", SqlType::U64, false),
        ];
        let names = [
            "Lpkg/Outer$Inner;->method(II)Ljava/lang/String;",
            "plain text",
            "de ad be ef",
            "",
            "Lpkg/Other;->field:I",
        ];
        let dict = TextDict::new();
        let (mut by_value, mut by_cell) = (
            RelationStoreBuilder::new(&schema, Arc::clone(&dict)),
            RelationStoreBuilder::new(&schema, Arc::clone(&dict)),
        );
        for n in 0..5_000usize {
            let name = names[n % names.len()];
            let kind = (n % 3 != 0).then_some("get");
            by_value
                .push(&vec![
                    SqlValue::U64(DecimalU64(3)),
                    SqlValue::text(name),
                    kind.map_or(SqlValue::Null, SqlValue::text),
                    SqlValue::U64(DecimalU64(n as u64)),
                ])
                .unwrap();
            by_cell
                .push_cells(&[
                    Cell::U64(3),
                    Cell::Str(name),
                    kind.map_or(Cell::Null, Cell::Str),
                    Cell::U64(n as u64),
                ])
                .unwrap();
        }
        let (a, b) = (by_value.finish(), by_cell.finish());
        assert_eq!(read_all(&a), read_all(&b));
        // the same text has the same id however it came in, so the second builder added nothing: the member descriptor
        // (its entry and three pieces), the plain text, the hex bytes, the empty text, the short descriptor and "get"
        assert_eq!(dict.len(), 4 + 1 + 1 + 1 + 1 + 1);
        // what the schema forbids is refused by the cell path as by the value path
        let mut strict = RelationStoreBuilder::new(&schema, dict);
        let refused = [
            [Cell::U64(1), Cell::Null, Cell::Null, Cell::U64(1)],
            [Cell::Str("x"), Cell::Str("x"), Cell::Null, Cell::U64(1)],
            [Cell::U64(1), Cell::U64(1), Cell::Null, Cell::U64(1)],
            [Cell::U64(1), Cell::Str("x"), Cell::Null, Cell::Null],
        ];
        for cells in &refused {
            assert!(strict.push_cells(cells).is_err(), "{cells:?}");
        }
        assert!(strict.push_cells(&[Cell::U64(1)]).is_err());

        // `Cell::SpacedHexBytes` matches stringified spaced-hex cells (including empty `&[]` -> `""`)
        let hex_dict = TextDict::new();
        let mut by_hex_str = RelationStoreBuilder::new(&schema, Arc::clone(&hex_dict));
        let mut by_hex_bytes = RelationStoreBuilder::new(&schema, Arc::clone(&hex_dict));
        for (idx, (text_val, raw_bytes)) in [
            ("de ad be ef", &[0xdeu8, 0xad, 0xbe, 0xef][..]),
            ("", &[][..]),
            ("00", &[0x00u8][..]),
        ]
        .into_iter()
        .enumerate()
        {
            by_hex_str
                .push_cells(&[
                    Cell::U64(1),
                    Cell::Str(text_val),
                    Cell::Null,
                    Cell::U64(idx as u64),
                ])
                .unwrap();
            by_hex_bytes
                .push_cells(&[
                    Cell::U64(1),
                    Cell::SpacedHexBytes(raw_bytes),
                    Cell::Null,
                    Cell::U64(idx as u64),
                ])
                .unwrap();
        }
        let dict_len_before = hex_dict.len();
        let (hex_a, hex_b) = (by_hex_str.finish(), by_hex_bytes.finish());
        assert_eq!(read_all(&hex_a), read_all(&hex_b));
        assert_eq!(hex_dict.len(), dict_len_before);
        assert_eq!(hex_a.max_cell_bytes(), hex_b.max_cell_bytes());
    }

    #[test]
    fn derived_columns_are_read_from_the_table_of_their_rows_dex() {
        let schema = vec![
            column("file_id", SqlType::U64, false),
            column("method_idx", SqlType::U64, false),
            column("method_name", SqlType::Text, false),
            column("method_class", SqlType::Text, false),
            column("note", SqlType::Text, true),
        ];
        let dict = TextDict::new();
        // two DEX that give the same index different methods
        let table = |names: &[(&str, &str)]| {
            let mut method_class = Vec::with_capacity(names.len());
            let mut method_name = Vec::with_capacity(names.len());
            let mut method_desc = Vec::with_capacity(names.len());
            for (class, name) in names {
                method_class.push(dict.intern_str(class));
                method_name.push(dict.intern_str(name));
                method_desc.push(dict.intern_str(&format!("{class}->{name}()V")));
            }
            Arc::new(RefTable {
                method_class,
                method_name,
                method_desc,
                ..RefTable::default()
            })
        };
        let first = table(&[("La;", "run"), ("La;", "stop"), ("Lb;", "run")]);
        let second = table(&[("Lc;", "go")]);
        let derived = [
            DerivedColumn {
                column: 2,
                index_column: 1,
                derive: Derive::MethodName,
            },
            DerivedColumn {
                column: 3,
                index_column: 1,
                derive: Derive::MethodClass,
            },
        ];
        let mut builder = RelationStoreBuilder::with_derived(&schema, Arc::clone(&dict), &derived);
        assert!(builder.has_derived());
        // no table for the partition: the row is refused
        builder.begin_partition(0);
        assert!(
            builder
                .push_cells(&[
                    Cell::U64(0),
                    Cell::U64(0),
                    Cell::Str("run"),
                    Cell::Str("La;"),
                    Cell::Null
                ])
                .is_err()
        );
        builder.set_table(Arc::clone(&first));
        let mut expected = Vec::new();
        for (file, rows) in [
            (
                0u64,
                vec![
                    (0u64, "run", "La;"),
                    (2, "run", "Lb;"),
                    (1, "stop", "La;"),
                    (0, "run", "La;"),
                ],
            ),
            (1, vec![(0, "go", "Lc;")]),
        ] {
            if file == 1 {
                builder.begin_partition(1);
                builder.set_table(Arc::clone(&second));
            }
            for (index, name, class) in rows {
                let note = (index != 1).then_some("n");
                builder
                    .push_cells(&[
                        Cell::U64(file),
                        Cell::U64(index),
                        Cell::Str(name),
                        Cell::Str(class),
                        note.map_or(Cell::Null, Cell::Str),
                    ])
                    .unwrap();
                expected.push(vec![
                    SqlValue::U64(DecimalU64(file)),
                    SqlValue::U64(DecimalU64(index)),
                    SqlValue::text(name),
                    SqlValue::text(class),
                    note.map_or(SqlValue::Null, SqlValue::text),
                ]);
            }
        }
        let store = builder.finish();
        assert_eq!(read_all(&store), expected);
        assert_eq!(store.rows(), 5);
        // the derived columns hold no rows of their own
        let bytes = store.column_bytes();
        assert_eq!(bytes[2], 0);
        assert_eq!(bytes[3], 0);
        assert!(bytes[1] > 0);
        // a partition reads its own rows with its own table
        let mut cursor = store.cursor_for_partition(1, control());
        let only = cursor.next_row().unwrap().unwrap();
        assert_eq!(only[2], SqlValue::text("go"));
        assert!(cursor.next_row().unwrap().is_none());
        // a cursor positioned on a row reads one cell at a time with the same values
        let mut cursor = store.cursor(control());
        let mut positioned = Vec::new();
        while PositionedCursor::advance(&mut cursor).unwrap() {
            positioned.push(
                (0..5)
                    .map(|c| PositionedCursor::value(&cursor, c).unwrap())
                    .collect::<Vec<_>>(),
            );
        }
        assert_eq!(positioned, expected);
    }

    /// With debug assertions a derived cell that is not what the table says is refused; the tests of the providers rely on it
    /// to prove that every derived value is the value the stored column would have held.
    #[cfg(debug_assertions)]
    #[test]
    fn a_derived_cell_that_differs_from_the_table_is_refused() {
        let schema = vec![
            column("file_id", SqlType::U64, false),
            column("method_idx", SqlType::U64, false),
            column("method_name", SqlType::Text, false),
        ];
        let dict = TextDict::new();
        let table = Arc::new(RefTable {
            method_class: vec![dict.intern_str("La;")],
            method_name: vec![dict.intern_str("run")],
            method_desc: vec![dict.intern_str("La;->run()V")],
            ..RefTable::default()
        });
        let mut builder = RelationStoreBuilder::with_derived(
            &schema,
            dict,
            &[DerivedColumn {
                column: 2,
                index_column: 1,
                derive: Derive::MethodName,
            }],
        );
        builder.begin_partition(0);
        builder.set_table(table);
        assert!(
            builder
                .push_cells(&[Cell::U64(0), Cell::U64(0), Cell::Str("walk")])
                .is_err()
        );
        assert!(
            builder
                .push_cells(&[Cell::U64(0), Cell::U64(7), Cell::Str("run")])
                .is_err(),
            "an index the table does not have"
        );
        assert!(
            builder
                .push_cells(&[Cell::U64(0), Cell::U64(0), Cell::Str("run")])
                .is_ok()
        );
    }

    #[test]
    fn many_rows_across_chunks_and_widths_read_back_in_order() {
        let schema = vec![
            column("file", SqlType::U64, false),
            column("index", SqlType::I64, false),
            column("wide", SqlType::U64, true),
            column("name", SqlType::Text, false),
        ];
        let total = CHUNK * 2 + 1234;
        let dict = TextDict::new();
        let mut builder = RelationStoreBuilder::new(&schema, dict);
        let make = |n: usize| -> SqlRow {
            vec![
                SqlValue::U64(DecimalU64(7)),
                SqlValue::I64(Signed64(n as i64 - 100_000)),
                // the second chunk needs 8 bytes, the others fewer, and a few rows are NULL
                if n.is_multiple_of(997) {
                    SqlValue::Null
                } else if (CHUNK..2 * CHUNK).contains(&n) {
                    SqlValue::U64(DecimalU64(u64::MAX - n as u64))
                } else {
                    SqlValue::U64(DecimalU64(n as u64 % 300))
                },
                SqlValue::text(&format!("name-{}", n % 1000)),
            ]
        };
        for n in 0..total {
            builder.push(&make(n)).unwrap();
        }
        let store = builder.finish();
        assert_eq!(store.rows(), total as u64);
        let rows = read_all(&store);
        assert_eq!(rows.len(), total);
        for (n, row) in rows.iter().enumerate() {
            assert_eq!(row, &make(n), "row {n}");
        }
        // The point of the store: far below what the rows themselves weigh.
        let naive = total * (4 * std::mem::size_of::<SqlValue>() + 24);
        assert!(
            store.bytes_used() * 4 < naive,
            "{} bytes for {} rows",
            store.bytes_used(),
            total
        );
    }

    #[test]
    fn a_row_that_does_not_fit_the_schema_is_refused_and_not_stored() {
        let dict = TextDict::new();
        let mut builder = RelationStoreBuilder::new(&schema(), dict);
        let short: SqlRow = vec![SqlValue::Null];
        assert!(builder.push(&short).is_err());
        let wrong_type: SqlRow = vec![
            SqlValue::text("not a bool"),
            SqlValue::Null,
            SqlValue::U64(DecimalU64(1)),
            SqlValue::Null,
            SqlValue::Null,
            SqlValue::Null,
        ];
        assert!(builder.push(&wrong_type).is_err());
        let null_in_required: SqlRow = vec![
            SqlValue::Null,
            SqlValue::Null,
            SqlValue::Null,
            SqlValue::Null,
            SqlValue::Null,
            SqlValue::Null,
        ];
        assert!(builder.push(&null_in_required).is_err());
        assert_eq!(builder.finish().rows(), 0);
    }

    #[test]
    fn member_descriptors_hex_and_their_near_misses_all_read_back_exactly() {
        let long = "Lcom/example/deeply/nested/Holder;";
        let texts = [
            // member descriptors: a method, a field, one without a prototype, one with two arrows
            format!("{long}->run(ILjava/lang/String;)V"),
            format!("{long}->count:I"),
            format!("{long}->justAName"),
            format!("{long}->a->b(I)V"),
            format!("->{long}(I)V"),
            format!("{long}->(I)V"),
            format!("{long}->name("),
            // too short to be split, with an arrow
            "a->b(I)V".to_owned(),
            // hexadecimal text and what only resembles it
            "0e".to_owned(),
            "0e 12 6e 5b".to_owned(),
            "0E 12".to_owned(),
            "0e  12".to_owned(),
            "0e 1".to_owned(),
            " 0e".to_owned(),
            "0e 12 ".to_owned(),
            "zz zz".to_owned(),
            "0e-12".to_owned(),
            String::new(),
            "plain text".to_owned(),
            "é -> ü(".to_owned(),
        ];
        let dict = TextDict::new();
        let ids: Vec<u32> = texts
            .iter()
            .map(|t| dict.intern(&SqlValue::text(t)).unwrap())
            .collect();
        for (text, id) in texts.iter().zip(&ids) {
            assert_eq!(dict.get(*id), SqlValue::text(text), "{text:?}");
            assert_eq!(
                dict.intern(&SqlValue::text(text)),
                Some(*id),
                "{text:?} is found again, not added again"
            );
        }
        let mut distinct = ids.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), texts.len());
    }

    #[test]
    fn members_of_one_class_share_their_class_name_and_prototype_entries() {
        let dict = TextDict::new();
        let class = "Lcom/example/deeply/nested/Holder;";
        for n in 0..1000 {
            dict.intern(&SqlValue::text(&format!("{class}->method{}(II)V", n % 50)));
            dict.intern(&SqlValue::text(&format!("{class}->field{}:I", n % 20)));
        }
        // 50 methods + 20 fields, each one a member entry, plus the shared pieces:
        // one class, 50 + 20 names, the two prototype tails.
        assert_eq!(dict.len(), 70 + 1 + 70 + 2);
    }

    #[test]
    fn threads_that_intern_the_same_values_get_the_same_ids() {
        let dict = TextDict::new();
        let values: Vec<SqlValue> = (0..4_000)
            .flat_map(|n| {
                [
                    SqlValue::text(&format!("Lpkg/Class{};->method{}(II)V", n % 97, n)),
                    SqlValue::text(&format!("plain text {n}")),
                    SqlValue::Bytes(vec![n as u8, (n >> 8) as u8, 7]),
                ]
            })
            .collect();
        let per_thread: Vec<Vec<u32>> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|worker| {
                    let (dict, values) = (&dict, &values);
                    scope.spawn(move || {
                        // every thread walks the values from its own start, so they meet on the same entries
                        let offset = worker * values.len() / 8;
                        let mut ids = vec![0; values.len()];
                        for step in 0..values.len() {
                            let at = (offset + step) % values.len();
                            ids[at] = dict.intern(&values[at]).unwrap();
                        }
                        ids
                    })
                })
                .collect();
            workers.into_iter().map(|w| w.join().unwrap()).collect()
        });
        for ids in &per_thread[1..] {
            assert_eq!(ids, &per_thread[0]);
        }
        for (value, id) in values.iter().zip(&per_thread[0]) {
            assert_eq!(&dict.get(*id), value);
        }
        let distinct: std::collections::HashSet<u32> = per_thread[0].iter().copied().collect();
        assert_eq!(distinct.len(), values.len());
    }

    #[test]
    fn a_dictionary_that_grows_past_its_first_table_keeps_every_id() {
        let dict = TextDict::new();
        let ids: Vec<u32> = (0..60_000)
            .map(|n| {
                dict.intern(&SqlValue::text(&format!("string number {n}")))
                    .unwrap()
            })
            .collect();
        let distinct: std::collections::HashSet<u32> = ids.iter().copied().collect();
        assert_eq!(distinct.len(), 60_000, "every value has an id of its own");
        // the shards grow evenly, so the ids stay close to the number of entries and fit the width they would in one table
        let largest = ids.iter().copied().max().unwrap();
        assert!(largest < 70_000, "the largest id is {largest}");
        for (n, id) in ids.iter().enumerate() {
            assert_eq!(dict.get(*id), SqlValue::text(&format!("string number {n}")));
        }
        assert_eq!(
            dict.intern(&SqlValue::text("string number 31337")),
            Some(ids[31337])
        );
        assert_eq!(dict.len(), 60_000);
    }

    #[test]
    fn columns_that_repeat_runs_of_values_are_stored_as_runs_and_read_back_exactly() {
        let schema = vec![
            column("caller", SqlType::U64, true),
            column("callee", SqlType::U64, false),
            column("signed", SqlType::I64, false),
            column("name", SqlType::Text, true),
        ];
        let dict = TextDict::new();
        let mut builder = RelationStoreBuilder::new(&schema, dict);
        let total = CHUNK + CHUNK / 2 + 77;
        // every caller makes 1..=9 calls in a row; NULLs sit inside runs, at their edges and alone
        let make = |n: usize| -> SqlRow {
            let caller = n / 5;
            vec![
                if n.is_multiple_of(41) {
                    SqlValue::Null
                } else {
                    SqlValue::U64(DecimalU64(caller as u64 * 3 + 1_000_000))
                },
                SqlValue::U64(DecimalU64((n * 7919 % 100_003) as u64)),
                SqlValue::I64(Signed64(-(caller as i64) - 5)),
                if n.is_multiple_of(53) {
                    SqlValue::Null
                } else {
                    SqlValue::text(&format!("Lcom/example/Holder{};->run(I)V", caller % 300))
                },
            ]
        };
        for n in 0..total {
            builder.push(&make(n)).unwrap();
        }
        let store = builder.finish();
        let rows = read_all(&store);
        assert_eq!(rows.len(), total);
        for (n, row) in rows.iter().enumerate() {
            assert_eq!(row, &make(n), "row {n}");
        }
        // the runs make the three repeating columns much smaller than one entry per row
        let plain = total * (4 + 4 + 4 + 4);
        assert!(
            store.bytes_used() * 2 < plain,
            "{} bytes for {} rows",
            store.bytes_used(),
            total
        );
    }

    #[test]
    fn a_column_that_never_repeats_stays_plain_and_a_constant_column_costs_nothing() {
        let schema = vec![
            column("distinct", SqlType::U64, false),
            column("constant", SqlType::U64, false),
        ];
        let dict = TextDict::new();
        let mut builder = RelationStoreBuilder::new(&schema, dict);
        for n in 0..CHUNK {
            builder
                .push(&vec![
                    SqlValue::U64(DecimalU64(n as u64 * 3)),
                    SqlValue::U64(DecimalU64(9)),
                ])
                .unwrap();
        }
        let store = builder.finish();
        assert_eq!(read_all(&store).len(), CHUNK);
        // 4 bytes a row for the distinct column (range just under 2^18), none for the constant one
        assert!(store.bytes_used() < CHUNK * 4 + 1024);
        assert!(store.bytes_used() > CHUNK * 2);
    }

    #[test]
    fn an_empty_relation_and_a_cancelled_scan_behave_as_cursors_do() {
        let dict = TextDict::new();
        let empty = RelationStoreBuilder::new(&schema(), Arc::clone(&dict)).finish();
        assert!(read_all(&empty).is_empty());

        let mut builder = RelationStoreBuilder::new(&schema(), dict);
        builder
            .push(&vec![
                SqlValue::Null,
                SqlValue::Null,
                SqlValue::U64(DecimalU64(1)),
                SqlValue::Null,
                SqlValue::Null,
                SqlValue::Null,
            ])
            .unwrap();
        let store = builder.finish();
        let cancelled = control();
        cancelled.cancel().unwrap();
        let mut cursor = store.cursor(cancelled);
        assert!(
            cursor.next_row().is_err(),
            "a cancelled scan stops at its first row"
        );
    }

    #[test]
    fn dict_lookup_and_column_index_plan_sound_candidate_scans() {
        let dict = TextDict::new();
        let schema = vec![
            column("file_id", SqlType::U64, false),
            column("idx", SqlType::U64, false),
            column("descriptor", SqlType::Text, false),
        ];
        let mut builder = RelationStoreBuilder::new(&schema, Arc::clone(&dict));
        for file_id in 0..3u64 {
            builder.begin_partition(file_id);
            for idx in 0..10u64 {
                let text = if file_id == 1 && idx == 4 {
                    "Lcom/example/A;->run(II)V".to_owned()
                } else if file_id == 2 && idx == 7 {
                    "0a 1b ff".to_owned()
                } else {
                    format!("Lpkg/C{}_{};", file_id, idx)
                };
                builder
                    .push(&vec![
                        SqlValue::U64(DecimalU64(file_id)),
                        SqlValue::U64(DecimalU64(idx)),
                        SqlValue::text(&text),
                    ])
                    .unwrap();
            }
        }
        let store = builder.finish();
        let before_len = dict.len();
        assert!(dict.lookup_str("Lpkg/DoesNotExist;").is_none());
        assert_eq!(dict.len(), before_len, "lookup_str must never insert");
        assert!(dict.lookup_str("Lcom/example/A;->run(II)V").is_some());
        assert!(dict.lookup_str("0a 1b ff").is_some());

        let filter = RowFilter::Or(vec![
            RowFilter::And(vec![
                RowFilter::EqU64("file_id".to_owned(), 1),
                RowFilter::EqText(
                    "descriptor".to_owned(),
                    "Lcom/example/A;->run(II)V".to_owned(),
                ),
            ]),
            RowFilter::And(vec![
                RowFilter::EqU64("file_id".to_owned(), 2),
                RowFilter::InU64("idx".to_owned(), vec![7, 99]),
            ]),
        ]);
        let scan = store.plan_filter(&filter);
        let PlannedScan::Rows(ref row_ids) = scan else {
            panic!("expected PlannedScan::Rows, got {scan:?}");
        };
        assert_eq!(row_ids.len(), 2);
        let mut cursor = store.cursor_for_scan(&scan, control());
        let mut seen = Vec::new();
        while let Some(row) = cursor.next_row().unwrap() {
            seen.push((row[0].clone(), row[1].clone(), row[2].clone()));
        }
        assert_eq!(
            seen,
            vec![
                (
                    SqlValue::U64(DecimalU64(1)),
                    SqlValue::U64(DecimalU64(4)),
                    SqlValue::text("Lcom/example/A;->run(II)V"),
                ),
                (
                    SqlValue::U64(DecimalU64(2)),
                    SqlValue::U64(DecimalU64(7)),
                    SqlValue::text("0a 1b ff"),
                ),
            ]
        );

        let inverted = store.plan_filter(&RowFilter::BetweenU64("idx".to_owned(), 8, 2));
        assert_eq!(store.scan_len(&inverted), 0);
    }

    #[test]
    fn tagged_non_scalar_text_falls_back_to_all_soundly() {
        let dict = TextDict::new();
        let schema = vec![column("value", SqlType::Text, false)];
        let mut builder = RelationStoreBuilder::new(&schema, dict);
        builder.push(&vec![SqlValue::text("plain")]).unwrap();
        builder
            .push(&vec![text(&[0xd800], Some(&[0xed, 0xa0, 0x80]))])
            .unwrap();
        let store = builder.finish();
        let scan = store.plan_filter(&RowFilter::EqText("value".to_owned(), "plain".to_owned()));
        assert!(matches!(scan, PlannedScan::All { .. }));
    }

    #[test]
    fn dict_prefix_filtering_and_batched_or_like_prefix_scans() {
        let dict = TextDict::new();
        let schema = vec![
            column("file_id", SqlType::U64, false),
            column("descriptor", SqlType::Text, false),
        ];
        let mut builder = RelationStoreBuilder::new(&schema, dict);
        for (file_id, items) in [
            (
                0u64,
                vec![
                    "Lcom/Alpha/Cls;",
                    "Lkntr/beta/View;",
                    "Lcom/other/Miss;",
                    "Lpkg/LongName;->memberCall(I)V",
                ],
            ),
            (
                1u64,
                vec!["Lcom/alpha/Sub;", "Ltv/danmaku/Main;", "Lorg/Other;"],
            ),
        ] {
            builder.begin_partition(file_id);
            for item in items {
                builder
                    .push(&vec![
                        SqlValue::U64(DecimalU64(file_id)),
                        SqlValue::text(item),
                    ])
                    .unwrap();
            }
        }
        let store = builder.finish();
        let filter = RowFilter::And(vec![
            RowFilter::EqU64("file_id".to_owned(), 1),
            RowFilter::Or(vec![
                RowFilter::LikeAsciiPrefix("descriptor".to_owned(), "lcom/alpha/".to_owned()),
                RowFilter::InText(
                    "descriptor".to_owned(),
                    vec!["Ltv/danmaku/Main;".to_owned(), "Lmissing/Type;".to_owned()],
                ),
            ]),
        ]);
        let scan = store.plan_filter(&filter);
        let PlannedScan::Rows(ref row_ids) = scan else {
            panic!("expected PlannedScan::Rows, got {scan:?}");
        };
        assert_eq!(row_ids.len(), 2);
        let member_scan = store.plan_filter(&RowFilter::LikeAsciiPrefix(
            "descriptor".to_owned(),
            "lpkg/long".to_owned(),
        ));
        assert_eq!(store.scan_len(&member_scan), 1);

        let suffix_filter = RowFilter::LikeAsciiPrefixSuffix(
            "descriptor".to_owned(),
            "lcom/alpha/".to_owned(),
            "sub;".to_owned(),
        );
        let suffix_scan = store.plan_filter(&suffix_filter);
        let PlannedScan::Rows(ref suffix_rows) = suffix_scan else {
            panic!("expected PlannedScan::Rows");
        };
        assert_eq!(suffix_rows.as_ref(), &[4]);
        // Repeated lookup hits bounded filter_id_cache cleanly and returns identical rows.
        let PlannedScan::Rows(ref cached_rows) = store.plan_filter(&filter) else {
            panic!("expected PlannedScan::Rows");
        };
        assert_eq!(cached_rows.as_ref(), row_ids.as_ref());
        let PlannedScan::Rows(ref cached_suffix) = store.plan_filter(&suffix_filter) else {
            panic!("expected PlannedScan::Rows");
        };
        assert_eq!(cached_suffix.as_ref(), suffix_rows.as_ref());
    }

    #[test]
    fn intern_member_with_ids_keeps_utf8_tags_for_hex_like_member_parts() {
        let dict = TextDict::default();
        let head = "Lfixture/AnnotationCarrier;";
        let name = "ab";
        let full = "Lfixture/AnnotationCarrier;->ab(I)V";
        let head_id = dict.intern_str(head);
        let name_id = dict.intern_str(name);
        let reused_id = dict.intern_member_with_ids(full, head, name, head_id, name_id);
        let plain_id = dict.intern_str(full);
        assert_eq!(reused_id, plain_id);
        assert_eq!(dict.get(reused_id), SqlValue::text(full));
    }

    #[test]
    fn like_ascii_contains_narrows_utf8_member_cross_seam_and_mutf8_safely() {
        let mut store = RelationStoreBuilder::new(
            &[
                crate::provider::SqlColumn {
                    id: "descriptor".into(),
                    name: "descriptor".into(),
                    data_type: SqlType::Text,
                    nullable: false,
                },
                crate::provider::SqlColumn {
                    id: "file_id".into(),
                    name: "file_id".into(),
                    data_type: SqlType::U64,
                    nullable: false,
                },
            ],
            Arc::new(TextDict::default()),
        );
        store.begin_partition(0);
        let samples = [
            "Lcom/example/Net;->openHttpURLConnection(I)V",
            "Ljava/lang/String;->valueOf(I)Ljava/lang/String;",
            "Lorg/app/PlainTextHolder;",
            "Lcom/seam/Holder;->onCreate(Landroid/os/Bundle;)V",
            // Spaced-hex scalar text is interned as TAG_HEX while keeping has_tagged_text == false,
            // exercising the fallback_ids decode path inside filter_ids_by_ascii_filters_ci.
            "aa bb cc dd",
        ];
        for (i, s) in samples.iter().enumerate() {
            store
                .row(vec![SqlValue::text(s), SqlValue::U64(DecimalU64(i as u64))])
                .unwrap();
        }
        let store = store.finish();

        // Substring inside member name/rest (case-insensitive) hits row 0.
        let scan1 = store.plan_filter(&RowFilter::LikeAsciiContains(
            "descriptor".into(),
            "httpurlconnection".into(),
        ));
        let PlannedScan::Rows(ref r1) = scan1 else {
            panic!("expected PlannedScan::Rows, got {scan1:?}");
        };
        assert_eq!(r1.as_ref(), &[0]);

        // Cross-arrow seam ("holder;->on") hits row 3, while "holder->on" (missing ';') misses cleanly.
        let scan2 = store.plan_filter(&RowFilter::LikeAsciiContains(
            "descriptor".into(),
            "holder;->on".into(),
        ));
        let PlannedScan::Rows(ref r2) = scan2 else {
            panic!("expected PlannedScan::Rows, got {scan2:?}");
        };
        assert_eq!(r2.as_ref(), &[3]);
        let scan2_miss = store.plan_filter(&RowFilter::LikeAsciiContains(
            "descriptor".into(),
            "holder->on".into(),
        ));
        let PlannedScan::Rows(ref r2_miss) = scan2_miss else {
            panic!("expected PlannedScan::Rows, got {scan2_miss:?}");
        };
        assert!(r2_miss.is_empty());

        // Cross-paren seam ("oncreate(") hits row 3.
        let scan3 = store.plan_filter(&RowFilter::LikeAsciiContains(
            "descriptor".into(),
            "oncreate(".into(),
        ));
        let PlannedScan::Rows(ref r3) = scan3 else {
            panic!("expected PlannedScan::Rows, got {scan3:?}");
        };
        assert_eq!(r3.as_ref(), &[3]);

        // TAG_HEX scalar text fallback hit ("bb cc") hits row 4.
        let scan4 = store.plan_filter(&RowFilter::LikeAsciiContains(
            "descriptor".into(),
            "bb cc".into(),
        ));
        let PlannedScan::Rows(ref r4) = scan4 else {
            panic!("expected PlannedScan::Rows, got {scan4:?}");
        };
        assert_eq!(r4.as_ref(), &[4]);

        // Plain TAG_UTF8 substring hit + combined OR filter with LikeAsciiPrefix + cache hit.
        let scan_or = store.plan_filter(&RowFilter::Or(vec![
            RowFilter::LikeAsciiPrefix("descriptor".into(), "Ljava/lang/".into()),
            RowFilter::LikeAsciiContains("descriptor".into(), "plaintextholder".into()),
        ]));
        let PlannedScan::Rows(ref r_or) = scan_or else {
            panic!("expected PlannedScan::Rows, got {scan_or:?}");
        };
        assert_eq!(r_or.as_ref(), &[1, 2]);

        // Second lookup exercises filter_id_cache identically.
        let scan_or_cached = store.plan_filter(&RowFilter::Or(vec![
            RowFilter::LikeAsciiPrefix("descriptor".into(), "Ljava/lang/".into()),
            RowFilter::LikeAsciiContains("descriptor".into(), "plaintextholder".into()),
        ]));
        let PlannedScan::Rows(ref r_cached) = scan_or_cached else {
            panic!("expected PlannedScan::Rows");
        };
        assert_eq!(r_cached.as_ref(), r_or.as_ref());

        // Direct TextDict test: TAG_MUTF8 is conservatively retained and unpaired-surrogate TAG_TEXT
        // is filtered accurately via UTF-16 fallback.
        let dict = TextDict::default();
        let id_utf8 = dict.intern(&SqlValue::text("Lplain/Class;")).unwrap();
        let id_mutf8 = dict
            .intern(&SqlValue::DexMutf8 {
                bytes: vec![0x61, 0xc0, 0x80, 0x62],
                utf16_code_units: DecimalU64(3),
            })
            .unwrap();
        let id_surr_hit = dict
            .intern(&SqlValue::Text(SqlText {
                utf16: vec![
                    0xd800,
                    u16::from(b'H'),
                    u16::from(b't'),
                    u16::from(b'T'),
                    u16::from(b'p'),
                ],
                original_mutf8: None,
            }))
            .unwrap();
        let id_surr_miss = dict
            .intern(&SqlValue::Text(SqlText {
                utf16: vec![0xd800, u16::from(b'x'), u16::from(b'y')],
                original_mutf8: None,
            }))
            .unwrap();
        let got = dict.filter_ids_by_ascii_filters_ci(
            IndexKeysRef::U32(&[id_utf8, id_mutf8, id_surr_hit, id_surr_miss]),
            &[],
            &[],
            &[b"http"],
        );
        assert!(got.contains(&id_mutf8));
        assert!(got.contains(&id_surr_hit));
        assert!(!got.contains(&id_utf8));
        assert!(!got.contains(&id_surr_miss));

        // Unpaired-surrogate text in a SqlType::Text store sets has_tagged_text, causing plan_filter
        // to conservatively return PlannedScan::All.
        let mut tagged_store = RelationStoreBuilder::new(
            &[crate::provider::SqlColumn {
                id: "descriptor".into(),
                name: "descriptor".into(),
                data_type: SqlType::Text,
                nullable: false,
            }],
            Arc::new(TextDict::default()),
        );
        tagged_store.begin_partition(0);
        tagged_store
            .row(vec![SqlValue::Text(SqlText {
                utf16: vec![0xd800, u16::from(b'a')],
                original_mutf8: None,
            })])
            .unwrap();
        let tagged_store = tagged_store.finish();
        assert!(matches!(
            tagged_store.plan_filter(&RowFilter::LikeAsciiContains(
                "descriptor".into(),
                "a".into(),
            )),
            PlannedScan::All { .. }
        ));
    }

    #[test]
    fn first_probe_linear_scan_avoids_csr_index_until_second_probe_direct_and_derived() {
        let dict = Arc::new(TextDict::default());
        // Direct store + derived store sharing one RefTable for partition 0.
        let mut direct_b = RelationStoreBuilder::new(
            &[
                column("file_id", SqlType::U64, false),
                column("name", SqlType::Text, false),
            ],
            Arc::clone(&dict),
        );
        direct_b.begin_partition(0);
        for val in ["alpha", "NewPipe", "beta", "NewPipe"] {
            direct_b
                .row(vec![SqlValue::U64(DecimalU64(0)), SqlValue::text(val)])
                .unwrap();
        }
        let direct = direct_b.finish();
        assert!(direct.indexes[1].get().is_none());

        // 1st probe uses linear scan and leaves CSR index unbuilt.
        let p1 = direct.plan_filter(&RowFilter::EqText("name".into(), "NewPipe".into()));
        assert!(direct.indexes[1].get().is_none());
        let PlannedScan::Rows(r1) = p1 else {
            panic!("expected Rows from 1st EqText probe");
        };
        assert_eq!(r1.as_ref(), &[1, 3]);

        // 2nd probe populates CSR index and returns identical rows.
        let p2 = direct.plan_filter(&RowFilter::InText(
            "name".into(),
            vec!["alpha".into(), "NewPipe".into()],
        ));
        assert!(direct.indexes[1].get().is_some());
        let PlannedScan::Rows(r2) = p2 else {
            panic!("expected Rows from 2nd InText probe");
        };
        assert_eq!(r2.as_ref(), &[0, 1, 3]);

        // Derived text column: 1st probe leaves index unbuilt, 2nd builds it; both agree.
        let table = Arc::new(RefTable {
            method_class: vec![dict.intern_str("La;"), dict.intern_str("Lb;")],
            method_name: vec![dict.intern_str("onCreate"), dict.intern_str("onDestroy")],
            method_desc: vec![dict.intern_str("()V"), dict.intern_str("()V")],
            ..RefTable::default()
        });
        let derived_cols = [DerivedColumn {
            column: 2,
            index_column: 1,
            derive: Derive::MethodName,
        }];
        let mut derived_b = RelationStoreBuilder::with_derived(
            &[
                column("file_id", SqlType::U64, false),
                column("method_idx", SqlType::U64, false),
                column("name", SqlType::Text, false),
            ],
            Arc::clone(&dict),
            &derived_cols,
        );
        derived_b.begin_partition(0);
        derived_b.set_table(table);
        for (m_idx, name) in [(0u64, "onCreate"), (1, "onDestroy"), (0, "onCreate")] {
            derived_b
                .row(vec![
                    SqlValue::U64(DecimalU64(0)),
                    SqlValue::U64(DecimalU64(m_idx)),
                    SqlValue::text(name),
                ])
                .unwrap();
        }
        let derived_store = derived_b.finish();
        assert!(derived_store.indexes[2].get().is_none());
        let d1 = derived_store.plan_filter(&RowFilter::EqText("name".into(), "onCreate".into()));
        assert!(derived_store.indexes[2].get().is_none());
        let PlannedScan::Rows(dr1) = d1 else {
            panic!("expected Rows from 1st derived probe");
        };
        assert_eq!(dr1.as_ref(), &[0, 2]);
        let d2 = derived_store.plan_filter(&RowFilter::InText(
            "name".into(),
            vec!["onDestroy".into(), "onCreate".into()],
        ));
        assert!(derived_store.indexes[2].get().is_some());
        let PlannedScan::Rows(dr2) = d2 else {
            panic!("expected Rows from 2nd derived probe");
        };
        assert_eq!(dr2.as_ref(), &[0, 1, 2]);
    }

    #[test]
    fn direct_count_group_by_handles_nulls_ordering_empty_and_quotas() {
        let dict = Arc::new(TextDict::default());
        let mut builder = RelationStoreBuilder::new(
            &[
                column("file_id", SqlType::U64, false),
                column("kind", SqlType::Text, true),
            ],
            Arc::clone(&dict),
        );
        builder.begin_partition(0);
        for (fid, kind) in [
            (2u64, Some("virtual")),
            (0, Some("virtual")),
            (0, None),
            (0, Some("direct")),
            (0, Some("virtual")),
            (2, Some("virtual")),
        ] {
            builder
                .row(vec![
                    SqlValue::U64(DecimalU64(fid)),
                    kind.map_or(SqlValue::Null, SqlValue::text),
                ])
                .unwrap();
        }
        let store = builder.finish();

        let plan = crate::provider::DirectCountGroupBy {
            relation: "class_methods".into(),
            group_columns: vec![0, 1],
            projections: vec![
                crate::provider::DirectGroupItem::GroupCol {
                    group_pos: 0,
                    output_name: "file_id".into(),
                },
                crate::provider::DirectGroupItem::GroupCol {
                    group_pos: 1,
                    output_name: "kind".into(),
                },
                crate::provider::DirectGroupItem::CountStar {
                    output_name: "cnt".into(),
                },
            ],
            order_by_group_asc: vec![0, 1],
        };
        let rows = store
            .direct_count_group_by(&plan, &control())
            .expect("eligible direct group by")
            .expect("ok rows");
        assert_eq!(
            rows,
            vec![
                vec![
                    SqlValue::U64(DecimalU64(0)),
                    SqlValue::Null,
                    SqlValue::I64(Signed64(1))
                ],
                vec![
                    SqlValue::U64(DecimalU64(0)),
                    SqlValue::text("direct"),
                    SqlValue::I64(Signed64(1))
                ],
                vec![
                    SqlValue::U64(DecimalU64(0)),
                    SqlValue::text("virtual"),
                    SqlValue::I64(Signed64(2))
                ],
                vec![
                    SqlValue::U64(DecimalU64(2)),
                    SqlValue::text("virtual"),
                    SqlValue::I64(Signed64(2))
                ],
            ]
        );

        // Empty store with GROUP BY returns 0 groups.
        let empty = RelationStoreBuilder::new(
            &[
                column("file_id", SqlType::U64, false),
                column("kind", SqlType::Text, false),
            ],
            Arc::clone(&dict),
        )
        .finish();
        assert_eq!(
            empty
                .direct_count_group_by(&plan, &control())
                .unwrap()
                .unwrap(),
            Vec::<SqlRow>::new()
        );

        // Result row limit quota is enforced faithfully.
        let small_quota = SqlControl::new(
            SqlLimits {
                max_result_rows: 2,
                ..SqlLimits::default()
            },
            None,
        );
        assert!(
            store
                .direct_count_group_by(&plan, &small_quota)
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn int_column_collect_matching_covers_all_widths_runs_nulls_and_bitset() {
        // Test width 0, 1, 2, 4, 8 plain chunks and Runs chunks, plus subranges and NULLs.
        type IntMatchCase = (u64, Vec<Option<u64>>, u64, u64, Vec<u64>, Vec<u32>);
        let plain_cases: Vec<IntMatchCase> = vec![
            // width 0 (constant chunk with NULL at row 2)
            (
                0,
                vec![Some(42), Some(42), None, Some(42), Some(42)],
                1,
                5,
                vec![42],
                vec![1, 3, 4],
            ),
            // width 1
            (
                1,
                vec![Some(10), None, Some(25), Some(10), Some(200)],
                0,
                5,
                vec![10, 200],
                vec![0, 3, 4],
            ),
            // width 2
            (
                2,
                vec![Some(100), Some(5000), Some(5000), Some(100)],
                0,
                4,
                vec![5000],
                vec![1, 2],
            ),
            // width 4
            (
                4,
                vec![Some(10), Some(100_000), Some(200_000), Some(100_000)],
                1,
                4,
                vec![10, 100_000],
                vec![1, 3],
            ),
            // width 8
            (
                8,
                vec![Some(5), Some(u64::MAX - 3), Some(7), Some(u64::MAX - 3)],
                0,
                4,
                vec![u64::MAX - 3],
                vec![1, 3],
            ),
        ];
        for (expected_width, values, lo, hi, targets, want) in plain_cases {
            let mut col = IntColumn::new(Order::Unsigned);
            for val in values {
                col.push(val);
            }
            col.seal();
            assert!(
                matches!(col.sealed[0].payload, Payload::Plain { width, .. } if u64::from(width) == expected_width)
            );
            let mut out = Vec::new();
            col.collect_matching_in_range(lo, hi, &targets, &mut out);
            assert_eq!(out, want, "width {expected_width}");
        }

        // Explicitly force Payload::Runs on chunk size 200 with NULLs and subrange slicing.
        let mut runs_col = IntColumn::new(Order::Unsigned);
        for i in 0..200u64 {
            if i == 50 || i == 120 {
                runs_col.push(None);
            } else if (40..70).contains(&i) {
                runs_col.push(Some(7));
            } else if (110..130).contains(&i) {
                runs_col.push(Some(9));
            } else {
                runs_col.push(Some(3));
            }
        }
        runs_col.seal();
        assert!(matches!(runs_col.sealed[0].payload, Payload::Runs { .. }));
        let mut out_runs = Vec::new();
        runs_col.collect_matching_in_range(48, 122, &[7, 9], &mut out_runs);
        let mut expected_runs: Vec<u32> = (48..70).filter(|&i| i != 50).collect();
        expected_runs.extend((110..122).filter(|&i| i != 120));
        assert_eq!(out_runs, expected_runs);

        // Bitset path (> 8 distinct targets) across Plain and Runs chunks + NULL filtering.
        let mut bit_col = IntColumn::new(Order::Unsigned);
        for i in 0..64u64 {
            bit_col.push(if i == 12 { None } else { Some(i % 20) });
        }
        bit_col.seal();
        let bitset = [((1u64 << 2) | (1u64 << 10) | (1u64 << 12) | (1u64 << 19))];
        let mut bit_out = Vec::new();
        bit_col.collect_matching_bitset_in_range(0, 64, &bitset, 19, &mut bit_out);
        let want_bits: Vec<u32> = (0..64u32)
            .filter(|&i| i != 12 && matches!(i % 20, 2 | 10 | 12 | 19))
            .collect();
        assert_eq!(bit_out, want_bits);
    }

    #[test]
    fn fused_derived_and_respects_type_desc_flag_and_bitset_threshold() {
        let dict = Arc::new(TextDict::default());
        // Partition 0 omits La; from type_desc with type_desc_covers_member_classes=true (never matches La;).
        // Partition 1 includes La; and > 8 distinct local field_idx entries matching f1 -> exercises bitset path.
        let cls_a = dict.intern_str("La;");
        let cls_b = dict.intern_str("Lb;");
        let f_keep = dict.intern_str("keep");
        let f_other = dict.intern_str("other");
        let desc_keep = dict.intern_str("I");

        let t0 = Arc::new(RefTable {
            field_class: vec![cls_b],
            field_name: vec![f_keep],
            field_desc: vec![desc_keep],
            field_type: vec![desc_keep],
            type_desc: vec![cls_b],
            type_name: vec![dict.intern_str("b")],
            type_desc_covers_member_classes: true,
            ..RefTable::default()
        });
        let mut t1 = RefTable {
            type_desc: vec![cls_a, cls_b],
            type_name: vec![dict.intern_str("a"), dict.intern_str("b")],
            type_desc_covers_member_classes: true,
            ..RefTable::default()
        };
        for i in 0..12 {
            t1.field_class.push(if i % 2 == 0 { cls_a } else { cls_b });
            t1.field_name
                .push(if i < 10 || i == 11 { f_keep } else { f_other });
            t1.field_desc.push(desc_keep);
            t1.field_type.push(desc_keep);
        }
        let t1 = Arc::new(t1);

        let schema_cols = [
            column("file_id", SqlType::U64, false),
            column("field_idx", SqlType::U64, false),
            column("class_descriptor", SqlType::Text, false),
            column("field_name", SqlType::Text, false),
        ];
        let derived_cols = [
            DerivedColumn {
                column: 2,
                index_column: 1,
                derive: Derive::FieldClass,
            },
            DerivedColumn {
                column: 3,
                index_column: 1,
                derive: Derive::FieldName,
            },
        ];
        let mut b =
            RelationStoreBuilder::with_derived(&schema_cols, Arc::clone(&dict), &derived_cols);
        b.begin_partition(0);
        b.set_table(t0);
        b.push_cells(&[
            Cell::U64(0),
            Cell::U64(0),
            Cell::Str("Lb;"),
            Cell::Str("keep"),
        ])
        .unwrap();
        b.begin_partition(1);
        b.set_table(t1);
        // Add all 12 entries twice so > 8 local indices trigger bitset.
        for i in 0..12usize {
            let cls = if i % 2 == 0 { "La;" } else { "Lb;" };
            let nm = if i < 10 || i == 11 { "keep" } else { "other" };
            b.push_cells(&[
                Cell::U64(1),
                Cell::U64(i as u64),
                Cell::Str(cls),
                Cell::Str(nm),
            ])
            .unwrap();
        }
        let store = b.finish();

        // Fused RowFilter::And leaves both CSR indexes unbuilt while finding exact rows.
        let filter = RowFilter::And(vec![
            RowFilter::EqText("class_descriptor".into(), "La;".into()),
            RowFilter::EqText("field_name".into(), "keep".into()),
        ]);
        let PlannedScan::Rows(rows) = store.plan_filter(&filter) else {
            panic!("expected Rows");
        };
        // Partition 0 row 0 is Lb; Partition 1 rows map to indices 0..12 -> row = 1 + i.
        // Matching i: even (cls=La;) and i < 10 => i in {0, 2, 4, 6, 8} => rows {1, 3, 5, 7, 9}.
        assert_eq!(rows.as_ref(), &[1, 3, 5, 7, 9]);
        assert!(store.indexes[2].get().is_none());
        assert!(store.indexes[3].get().is_none());

        // Single derived predicate with > 8 matching local indices ("keep" -> i in 0..10, 11 -> 11 local indices > 8).
        let single_many = store.exact_lookup_rows(
            &[crate::provider::DirectPredicate::EqText(3, "keep".into())],
            false,
        );
        let Some(ExactRowSet::Owned(many_rows)) = single_many else {
            panic!("expected Owned rows for unindexed >8 bitset lookup");
        };
        let mut expected_keep: Vec<u32> = vec![0];
        expected_keep.extend((0..12u32).filter(|&i| i < 10 || i == 11).map(|i| 1 + i));
        assert_eq!(many_rows, expected_keep);
        assert!(store.indexes[3].get().is_none());

        // Synthetic table with type_desc_covers_member_classes=false must NOT skip a partition whose type_desc lacks cls_a.
        let mut b2 =
            RelationStoreBuilder::with_derived(&schema_cols, Arc::clone(&dict), &derived_cols);
        b2.begin_partition(0);
        b2.set_table(Arc::new(RefTable {
            field_class: vec![cls_a],
            field_name: vec![f_keep],
            field_desc: vec![desc_keep],
            field_type: vec![desc_keep],
            type_desc: Vec::new(),
            type_name: Vec::new(),
            type_desc_covers_member_classes: false,
            ..RefTable::default()
        }));
        b2.push_cells(&[
            Cell::U64(0),
            Cell::U64(0),
            Cell::Str("La;"),
            Cell::Str("keep"),
        ])
        .unwrap();
        let store2 = b2.finish();
        let Some(ExactRowSet::Owned(unskipped)) = store2.exact_lookup_rows(
            &[
                crate::provider::DirectPredicate::EqText(2, "La;".into()),
                crate::provider::DirectPredicate::EqText(3, "keep".into()),
            ],
            false,
        ) else {
            panic!("expected Owned rows");
        };
        assert_eq!(unskipped, vec![0]);
    }

    #[test]
    fn direct_filtered_projection_orders_utf16_nulls_and_windows_accurately() {
        let dict = Arc::new(TextDict::default());
        let mut b = RelationStoreBuilder::new(
            &[
                column("file_id", SqlType::U64, false),
                column("label", SqlType::Text, true),
                column("score", SqlType::I64, true),
            ],
            Arc::clone(&dict),
        );
        b.begin_partition(0);
        // U+10000 encodes to UTF-16 surrogates [0xD800, 0xDC00] < U+E000 [0xE000], whereas in UTF-8
        // U+10000 (0xF0 0x90 0x80 0x80) > U+E000 (0xEE 0x80 0x80). Sort MUST follow UTF-16!
        let suppl = "\u{10000}";
        let bmp_high = "\u{E000}";
        for (label, score) in [
            (Some(bmp_high), Some(10i64)),
            (None, Some(30)),
            (Some(suppl), Some(-5)),
            (Some(suppl), Some(20)),
        ] {
            b.row(vec![
                SqlValue::U64(DecimalU64(0)),
                label.map_or(SqlValue::Null, SqlValue::text),
                score.map_or(SqlValue::Null, |v| SqlValue::I64(Signed64(v))),
            ])
            .unwrap();
        }
        let store = b.finish();

        // ASC sort: NULL first, then U+10000 (sorted by score ASC: -5 then 20), then U+E000.
        let plan_asc = crate::provider::DirectFilteredProjection {
            relation: "t".into(),
            projected_columns: vec![(1, "label".into()), (2, "score".into())],
            predicates: vec![crate::provider::DirectPredicate::EqU64(0, 0)],
            order_by: vec![
                crate::provider::DirectOrderItem {
                    column: 1,
                    descending: false,
                },
                crate::provider::DirectOrderItem {
                    column: 2,
                    descending: false,
                },
            ],
            limit: None,
            offset: 0,
        };
        let win = crate::window::SqlWindow::new(1, 2)
            .unwrap()
            .counting_total();
        let (rows, report) = store
            .direct_filtered_projection(&plan_asc, &control(), Some(win))
            .unwrap()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                vec![SqlValue::text(suppl), SqlValue::I64(Signed64(-5))],
                vec![SqlValue::text(suppl), SqlValue::I64(Signed64(20))],
            ]
        );
        let report = report.unwrap();
        assert_eq!(report.offset, 1);
        assert_eq!(report.rows, 2);
        assert!(report.truncated);
        assert_eq!(report.next_offset, Some(3));
        assert_eq!(report.total_rows, Some(4));

        // DESC sort: U+E000, U+10000 (20), U+10000 (-5), NULL last.
        let plan_desc = crate::provider::DirectFilteredProjection {
            order_by: vec![
                crate::provider::DirectOrderItem {
                    column: 1,
                    descending: true,
                },
                crate::provider::DirectOrderItem {
                    column: 2,
                    descending: true,
                },
            ],
            ..plan_asc.clone()
        };
        let (rows_desc, _) = store
            .direct_filtered_projection(&plan_desc, &control(), None)
            .unwrap()
            .unwrap();
        assert_eq!(
            rows_desc,
            vec![
                vec![SqlValue::text(bmp_high), SqlValue::I64(Signed64(10))],
                vec![SqlValue::text(suppl), SqlValue::I64(Signed64(20))],
                vec![SqlValue::text(suppl), SqlValue::I64(Signed64(-5))],
                vec![SqlValue::Null, SqlValue::I64(Signed64(30))],
            ]
        );

        // Empty result under counting_total window.
        let plan_empty = crate::provider::DirectFilteredProjection {
            predicates: vec![crate::provider::DirectPredicate::EqU64(0, 99)],
            ..plan_asc
        };
        let (empty_rows, empty_rep) = store
            .direct_filtered_projection(
                &plan_empty,
                &control(),
                Some(
                    crate::window::SqlWindow::new(0, 10)
                        .unwrap()
                        .counting_total(),
                ),
            )
            .unwrap()
            .unwrap();
        assert!(empty_rows.is_empty());
        let empty_rep = empty_rep.unwrap();
        assert!(!empty_rep.truncated);
        assert_eq!(empty_rep.total_rows, Some(0));

        // SQL LIMIT/OFFSET combined with SqlWindow slices the post-LIMIT statement result.
        let plan_lim = crate::provider::DirectFilteredProjection {
            limit: Some(2),
            offset: 1,
            ..plan_asc.clone()
        };
        let (lim_rows, lim_rep) = store
            .direct_filtered_projection(
                &plan_lim,
                &control(),
                Some(
                    crate::window::SqlWindow::new(0, 1)
                        .unwrap()
                        .counting_total(),
                ),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            lim_rows,
            vec![vec![SqlValue::text(suppl), SqlValue::I64(Signed64(-5))]]
        );
        let lim_rep = lim_rep.unwrap();
        assert!(lim_rep.truncated);
        assert_eq!(lim_rep.next_offset, Some(1));
        assert_eq!(lim_rep.total_rows, Some(2));

        let plan_zero = crate::provider::DirectFilteredProjection {
            limit: Some(0),
            offset: 0,
            ..plan_asc
        };
        let (zero_rows, zero_rep) = store
            .direct_filtered_projection(
                &plan_zero,
                &control(),
                Some(
                    crate::window::SqlWindow::new(0, 10)
                        .unwrap()
                        .counting_total(),
                ),
            )
            .unwrap()
            .unwrap();
        assert!(zero_rows.is_empty());
        let zero_rep = zero_rep.unwrap();
        assert!(!zero_rep.truncated);
        assert_eq!(zero_rep.total_rows, Some(0));
    }
}
