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
    provider::{PositionedCursor, SqlColumn, SqlFactCursor, SqlRow, validate_row},
    values::{SqlText, SqlType, SqlValue},
};
use mdd_query::ir::Signed64;
use mdd_types::{DecimalU64, MddResult};
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
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
        self.starts.push(start);
        self.arena.extend_from_slice(entry);
        self.slots[slot] = local;
        if self.starts.len() * 2 > self.slots.len() {
            self.grow();
        }
        local
    }
}

impl TextDict {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
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
        const STACK: usize = 256;
        if payload.len() < STACK {
            let mut entry = [0u8; STACK];
            entry[0] = tag;
            entry[1..=payload.len()].copy_from_slice(payload);
            self.intern_entry(&entry[..=payload.len()])
        } else {
            let mut entry = Vec::with_capacity(1 + payload.len());
            entry.push(tag);
            entry.extend_from_slice(payload);
            self.intern_entry(&entry)
        }
    }

    /// The id of a scalar text, adding it when it is new: the id `intern` gives the `SqlValue::Text` made from it.
    pub fn intern_str(&self, utf8: &str) -> u32 {
        if is_spaced_hex(utf8) {
            let mut entry = Vec::with_capacity(utf8.len() / 3 + 1);
            entry.extend(
                utf8.as_bytes()
                    .chunks(3)
                    .map(|group| nibble(group[0]) << 4 | nibble(group[1])),
            );
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
#[derive(Default)]
pub struct RefTable {
    /// Per method reference: class descriptor, name, descriptor.
    pub methods: Vec<[u32; 3]>,
    /// Per field reference: class descriptor, name, descriptor, type descriptor.
    pub fields: Vec<[u32; 4]>,
    /// Per type: descriptor, Java name.
    pub types: Vec<[u32; 2]>,
}

impl RefTable {
    fn id(&self, derive: Derive, index: u64) -> Option<u32> {
        let at = usize::try_from(index).ok()?;
        match derive {
            Derive::MethodClass => self.methods.get(at).map(|m| m[0]),
            Derive::MethodName => self.methods.get(at).map(|m| m[1]),
            Derive::MethodDescriptor => self.methods.get(at).map(|m| m[2]),
            Derive::FieldClass => self.fields.get(at).map(|f| f[0]),
            Derive::FieldName => self.fields.get(at).map(|f| f[1]),
            Derive::FieldDescriptor => self.fields.get(at).map(|f| f[2]),
            Derive::FieldType => self.fields.get(at).map(|f| f[3]),
            Derive::TypeDescriptor => self.types.get(at).map(|t| t[0]),
            Derive::TypeName => self.types.get(at).map(|t| t[1]),
        }
    }

    /// Bytes this table holds on the heap.
    pub fn bytes_used(&self) -> usize {
        self.methods.capacity() * 12 + self.fields.capacity() * 16 + self.types.capacity() * 8
    }

    pub fn shrink_to_fit(&mut self) {
        self.methods.shrink_to_fit();
        self.fields.shrink_to_fit();
        self.types.shrink_to_fit();
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
    staging_nulls: Vec<bool>,
}

impl IntColumn {
    fn new(order: Order) -> Self {
        Self {
            order,
            sealed: Vec::new(),
            staging: Vec::new(),
            staging_nulls: Vec::new(),
        }
    }

    fn push(&mut self, value: Option<u64>) {
        self.staging.push(value.unwrap_or(0));
        self.staging_nulls.push(value.is_none());
        if self.staging.len() == CHUNK {
            self.seal();
        }
    }

    fn seal(&mut self) {
        if self.staging.is_empty() {
            return;
        }
        let present = || {
            self.staging
                .iter()
                .zip(&self.staging_nulls)
                .filter(|(_, null)| !**null)
                .map(|(value, _)| *value)
        };
        let (mut low, mut high) = (None::<u64>, None::<u64>);
        for value in present() {
            if low.is_none_or(|l| self.order.less(value, l)) {
                low = Some(value);
            }
            if high.is_none_or(|h| self.order.less(h, value)) {
                high = Some(value);
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
            if self.staging_nulls[row] {
                0
            } else {
                self.staging[row].wrapping_sub(base)
            }
        };
        let rows = self.staging.len();
        let mut ends: Vec<u32> = Vec::new();
        let mut values: Vec<u64> = Vec::new();
        for row in 0..rows {
            let delta = if self.staging_nulls[row] && row > 0 {
                *values.last().unwrap_or(&0)
            } else {
                delta_at(row)
            };
            if values.last() == Some(&delta) && !ends.is_empty() {
                *ends.last_mut().unwrap() = row as u32 + 1;
            } else {
                values.push(delta);
                ends.push(row as u32 + 1);
            }
        }
        let wide = usize::from(width);
        let plain_size = rows * wide;
        let runs_size = values.len() * (wide + 4);
        let payload = if wide > 0 && runs_size * 4 < plain_size * 3 {
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
        };
        let nulls = self.staging_nulls.iter().any(|n| *n).then(|| {
            let mut bits = vec![0u64; rows.div_ceil(64)];
            for (row, null) in self.staging_nulls.iter().enumerate() {
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
        self.staging_nulls = Vec::new();
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
            + self.staging_nulls.capacity()
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
}

/// The rows of one relation, immutable. Build with `RelationStoreBuilder`, read with `cursor`.
pub struct RelationStore {
    columns: Vec<Column>,
    /// Per column, how it is derived when it is not stored (its `Column` then holds no rows).
    derived: Vec<Option<DerivedColumn>>,
    /// The reference table of each DEX, by the value of the partition column, for the derived columns.
    tables: BTreeMap<u64, Arc<RefTable>>,
    /// The partition column, which says whose table a row's derived values come from.
    partition_column: Option<usize>,
    types: Vec<SqlType>,
    rows: u64,
    dict: Arc<TextDict>,
    /// The groups of rows that share a value of the partition column, in order of that value, when every row is in one.
    partitions: Option<Vec<Partition>>,
    /// An upper bound on the size of a cell, in bytes.
    max_cell_bytes: u64,
}

/// The rows `start..end` of a store, which all have the partition column `key`.
#[derive(Clone, Copy, Debug)]
struct Partition {
    key: u64,
    start: u64,
    end: u64,
}

impl RelationStore {
    pub fn rows(&self) -> u64 {
        self.rows
    }

    /// Bytes held on the heap by the columns, not counting the shared dictionary.
    pub fn bytes_used(&self) -> usize {
        self.columns.iter().map(|c| c.ints.bytes_used()).sum()
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
            next: start,
            current: start,
            end,
            hints: vec![std::cell::Cell::new(0); self.columns.len()],
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
            .tables
            .get(&file)
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
    U64(u64),
    Str(&'a str),
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
                (_, Kind::Dict) => Some(u64::from(
                    self.dict
                        .intern(value)
                        .ok_or_else(|| crate::invalid("STORE_CELL_TYPE"))?,
                )),
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
            if let Cell::Str(text) = cell {
                self.max_cell_bytes = self.max_cell_bytes.max(2 * text.len() as u64);
            }
            let raw = match (cell, column.kind) {
                (Cell::Null, _) if schema.nullable => None,
                (Cell::Null, _) => return Err(crate::invalid("PROVIDER_UNEXPECTED_NULL")),
                (Cell::U64(value), Kind::U64) => Some(*value),
                (Cell::Str(text), Kind::Dict) if schema.data_type == SqlType::Text => {
                    Some(u64::from(self.dict.intern_str(text)))
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
        }
        if let Some(last) = self.partitions.last_mut() {
            last.end = self.rows;
        }
        // every row must be in a partition, and the partitions must cover the rows exactly once
        let covered: u64 = self.partitions.iter().map(|p| p.end - p.start).sum();
        let partitions = (self.partitioned && covered == self.rows).then_some(self.partitions);
        Arc::new(RelationStore {
            types: self.schema.iter().map(|c| c.data_type).collect(),
            columns: self.columns,
            derived: self.derived,
            tables: self.tables,
            partition_column: self.partition_column,
            rows: self.rows,
            dict: self.dict,
            partitions,
            max_cell_bytes: self.max_cell_bytes,
        })
    }
}

/// Reads a store front to back, one `SqlRow` at a time, as a provider cursor.
pub struct StoreCursor {
    store: Arc<RelationStore>,
    /// The row the next `advance` or `next_row` moves to, and the row the cursor stands on.
    next: u64,
    current: u64,
    /// The cursor stops before this row.
    end: u64,
    /// Per column, the run the last cell came from (see `IntColumn::get`).
    hints: Vec<std::cell::Cell<usize>>,
    control: SqlControl,
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
        if self.next >= self.end {
            return Ok(false);
        }
        self.control.checkpoint(1, true)?;
        self.current = self.next;
        self.next += 1;
        Ok(true)
    }

    fn value(&self, column: usize) -> MddResult<SqlValue> {
        self.store.cell_at(column, self.current, &self.hints)
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
            Arc::new(RefTable {
                methods: names
                    .iter()
                    .map(|(class, name)| {
                        [
                            dict.intern_str(class),
                            dict.intern_str(name),
                            dict.intern_str(&format!("{class}->{name}()V")),
                        ]
                    })
                    .collect(),
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
            methods: vec![[
                dict.intern_str("La;"),
                dict.intern_str("run"),
                dict.intern_str("La;->run()V"),
            ]],
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
}
