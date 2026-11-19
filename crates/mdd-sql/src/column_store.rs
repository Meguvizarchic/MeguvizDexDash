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
    provider::{SqlColumn, SqlFactCursor, SqlRow, validate_row},
    values::{SqlText, SqlType, SqlValue},
};
use mdd_query::ir::Signed64;
use mdd_types::{DecimalU64, MddResult};
use std::sync::{Arc, RwLock};

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

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

const NONE: u32 = u32::MAX;

struct DictInner {
    /// Every entry, back to back: a tag byte and the payload (see `encode`).
    arena: Vec<u8>,
    /// Start of entry `id` in `arena`; the entry ends where the next one starts.
    starts: Vec<u32>,
    /// Open-addressing table of entry ids, `NONE` for an empty slot; its length is a power of two and at least
    /// twice the number of entries.
    slots: Vec<u32>,
}

impl Default for DictInner {
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
#[derive(Default)]
pub struct TextDict {
    inner: RwLock<DictInner>,
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

impl DictInner {
    fn entry(&self, id: u32) -> &[u8] {
        let start = self.starts[id as usize] as usize;
        let end = self
            .starts
            .get(id as usize + 1)
            .map_or(self.arena.len(), |next| *next as usize);
        &self.arena[start..end]
    }

    fn find(&self, entry: &[u8], hash: u64) -> Result<u32, usize> {
        let mask = self.slots.len() - 1;
        let mut at = hash as usize & mask;
        loop {
            match self.slots[at] {
                NONE => return Err(at),
                id if self.entry(id) == entry => return Ok(id),
                _ => at = (at + 1) & mask,
            }
        }
    }

    fn grow(&mut self) {
        let wanted = (self.slots.len() * 2).max(1024);
        self.slots = vec![NONE; wanted];
        let mask = wanted - 1;
        for id in 0..self.starts.len() as u32 {
            let mut at = fnv1a(self.entry(id)) as usize & mask;
            while self.slots[at] != NONE {
                at = (at + 1) & mask;
            }
            self.slots[at] = id;
        }
    }

    /// The id of the entry with exactly these bytes, adding it when it is new.
    fn add(&mut self, entry: &[u8]) -> u32 {
        let hash = fnv1a(entry);
        match self.find(entry, hash) {
            Ok(id) => id,
            Err(slot) => {
                let id = u32::try_from(self.starts.len()).expect("fewer than 2^32 distinct values");
                let start = u32::try_from(self.arena.len()).expect("a dictionary under 4 GiB");
                self.starts.push(start);
                self.arena.extend_from_slice(entry);
                self.slots[slot] = id;
                if self.starts.len() * 2 > self.slots.len() {
                    self.grow();
                }
                id
            }
        }
    }

    fn add_utf8(&mut self, text: &str) -> u32 {
        let mut entry = Vec::with_capacity(1 + text.len());
        entry.push(TAG_UTF8);
        entry.extend_from_slice(text.as_bytes());
        self.add(&entry)
    }

    fn text_of(&self, id: u32) -> String {
        let entry = self.entry(id);
        debug_assert_eq!(entry[0], TAG_UTF8, "a member piece is plain UTF-8");
        String::from_utf8(entry[1..].to_vec()).expect("a UTF-8 entry holds UTF-8")
    }

    fn intern(&mut self, value: &SqlValue) -> Option<u32> {
        Some(match value {
            SqlValue::Text(text) => {
                if text.original_mutf8.is_none()
                    && let Ok(utf8) = String::from_utf16(&text.utf16)
                {
                    if is_spaced_hex(&utf8) {
                        let mut entry = Vec::with_capacity(1 + utf8.len() / 3 + 1);
                        entry.push(TAG_HEX);
                        entry.extend(
                            utf8.as_bytes()
                                .chunks(3)
                                .map(|group| nibble(group[0]) << 4 | nibble(group[1])),
                        );
                        return Some(self.add(&entry));
                    }
                    if let Some((head, name, rest)) = split_member(&utf8) {
                        let mut entry = vec![TAG_MEMBER];
                        for part in [head, name, rest] {
                            let id = self.add_utf8(part);
                            entry.extend_from_slice(&id.to_le_bytes());
                        }
                        return Some(self.add(&entry));
                    }
                    return Some(self.add_utf8(&utf8));
                }
                let mut entry = vec![TAG_TEXT];
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
                self.add(&entry)
            }
            SqlValue::Bytes(bytes) => {
                let mut entry = Vec::with_capacity(1 + bytes.len());
                entry.push(TAG_BYTES);
                entry.extend_from_slice(bytes);
                self.add(&entry)
            }
            SqlValue::DexMutf8 {
                bytes,
                utf16_code_units,
            } => {
                let mut entry = Vec::with_capacity(9 + bytes.len());
                entry.push(TAG_MUTF8);
                entry.extend_from_slice(&utf16_code_units.0.to_le_bytes());
                entry.extend_from_slice(bytes);
                self.add(&entry)
            }
            _ => return None,
        })
    }

    fn value(&self, id: u32) -> SqlValue {
        let entry = self.entry(id);
        match entry[0] {
            TAG_UTF8 => SqlValue::Text(SqlText::from_utf8(
                std::str::from_utf8(&entry[1..]).expect("a UTF-8 entry holds UTF-8"),
            )),
            TAG_MEMBER => {
                let part =
                    |n: usize| u32::from_le_bytes(entry[1 + n * 4..5 + n * 4].try_into().unwrap());
                let (head, name, rest) = (
                    self.text_of(part(0)),
                    self.text_of(part(1)),
                    self.text_of(part(2)),
                );
                let mut text = String::with_capacity(head.len() + 2 + name.len() + rest.len());
                text.push_str(&head);
                text.push_str("->");
                text.push_str(&name);
                text.push_str(&rest);
                SqlValue::Text(SqlText::from_utf8(&text))
            }
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
        }
    }
}

impl TextDict {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The id of `value`, adding it when it is new. `None` for a value that is not text or bytes.
    pub fn intern(&self, value: &SqlValue) -> Option<u32> {
        self.inner.write().expect("dictionary lock").intern(value)
    }

    pub fn get(&self, id: u32) -> SqlValue {
        self.inner.read().expect("dictionary lock").value(id)
    }

    /// Number of entries, pieces of member descriptors included.
    pub fn len(&self) -> usize {
        self.inner.read().expect("dictionary lock").starts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes this dictionary holds on the heap (capacity, not just length).
    pub fn bytes_used(&self) -> usize {
        let inner = self.inner.read().expect("dictionary lock");
        inner.arena.capacity() + inner.starts.capacity() * 4 + inner.slots.capacity() * 4
    }

    /// Give back the room a growing vector reserved and does not use. Call it when a group of relations is built;
    /// the dictionary stays usable and grows again if more is interned.
    pub fn shrink_to_fit(&self) {
        let mut inner = self.inner.write().expect("dictionary lock");
        inner.arena.shrink_to_fit();
        inner.starts.shrink_to_fit();
    }

    /// Entries and arena bytes by kind, in the order plain UTF-8, UTF-16 text, bytes, DEX MUTF-8, member, hex.
    pub fn kinds(&self) -> [(usize, usize); 6] {
        let inner = self.inner.read().expect("dictionary lock");
        let mut kinds = [(0usize, 0usize); 6];
        for id in 0..inner.starts.len() as u32 {
            let entry = inner.entry(id);
            let slot = &mut kinds[usize::from(entry[0])];
            slot.0 += 1;
            slot.1 += entry.len();
        }
        kinds
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
    types: Vec<SqlType>,
    rows: u64,
    dict: Arc<TextDict>,
}

impl RelationStore {
    pub fn rows(&self) -> u64 {
        self.rows
    }

    /// Bytes held on the heap by the columns, not counting the shared dictionary.
    pub fn bytes_used(&self) -> usize {
        self.columns.iter().map(|c| c.ints.bytes_used()).sum()
    }

    pub fn cursor(self: &Arc<Self>, control: SqlControl) -> StoreCursor {
        StoreCursor {
            store: Arc::clone(self),
            next: 0,
            hints: vec![0; self.columns.len()],
            control,
        }
    }

    /// The value of one cell. `column` and `row` must be in range.
    pub fn cell(&self, column: usize, row: u64) -> SqlValue {
        self.cell_with(column, row, &mut 0)
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

pub struct RelationStoreBuilder {
    schema: Vec<SqlColumn>,
    columns: Vec<Column>,
    rows: u64,
    dict: Arc<TextDict>,
}

impl RelationStoreBuilder {
    pub fn new(schema: &[SqlColumn], dict: Arc<TextDict>) -> Self {
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
        Self {
            schema: schema.to_vec(),
            columns,
            rows: 0,
            dict,
        }
    }

    /// Add one row. The row is checked against the schema as a cursor's row would be.
    pub fn push(&mut self, row: &SqlRow) -> MddResult<()> {
        validate_row(row, &self.schema)?;
        for (value, column) in row.iter().zip(&mut self.columns) {
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
            column.ints.push(raw);
        }
        self.rows += 1;
        Ok(())
    }

    pub fn finish(mut self) -> Arc<RelationStore> {
        for column in &mut self.columns {
            column.ints.seal();
        }
        Arc::new(RelationStore {
            types: self.schema.iter().map(|c| c.data_type).collect(),
            columns: self.columns,
            rows: self.rows,
            dict: self.dict,
        })
    }
}

/// Reads a store front to back, one `SqlRow` at a time, as a provider cursor.
pub struct StoreCursor {
    store: Arc<RelationStore>,
    next: u64,
    /// Per column, the run the last cell came from (see `IntColumn::get`).
    hints: Vec<usize>,
    control: SqlControl,
}

impl SqlFactCursor for StoreCursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
        if self.next >= self.store.rows {
            return Ok(None);
        }
        self.control.checkpoint(1, true)?;
        let store = &self.store;
        let next = self.next;
        let row = self
            .hints
            .iter_mut()
            .enumerate()
            .map(|(column, hint)| store.cell_with(column, next, hint))
            .collect();
        self.next += 1;
        Ok(Some(row))
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
    fn a_dictionary_that_grows_past_its_first_table_keeps_every_id() {
        let dict = TextDict::new();
        let ids: Vec<u32> = (0..60_000)
            .map(|n| {
                dict.intern(&SqlValue::text(&format!("string number {n}")))
                    .unwrap()
            })
            .collect();
        for (n, id) in ids.iter().enumerate() {
            assert_eq!(*id as usize, n);
            assert_eq!(dict.get(*id), SqlValue::text(&format!("string number {n}")));
        }
        assert_eq!(
            dict.intern(&SqlValue::text("string number 31337")),
            Some(31337)
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
