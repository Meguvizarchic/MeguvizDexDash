//! `resources.arsc`: the compiled resource table, read strictly into rows.
//!
//! One row is one (resource, configuration) pair: a plain entry holds one value, a map
//! entry (a style, an array, plurals) holds a parent and a list of named values. Nothing is
//! merged across configurations, so `string/app_name` in the default, `en` and `zh-rCN`
//! configurations is three rows with their own values and their own qualifier strings.
//!
//! Strictness: every chunk must lie inside its parent, every offset inside its chunk, every
//! string and key index inside its pool. A table that fails this is refused whole; it is
//! never read as far as it goes. The one thing skipped is a chunk type this reader does not
//! know (the table says how long it is), and the count of those is kept in
//! `skipped_chunks` so a consumer can tell a complete read from a partial one.
use super::config::Configuration;
use crate::manifest::{ManifestLimits, PoolString, parse_string_pool};
use mdd_types::{ErrorCode, MddError, MddResult};
use std::collections::BTreeMap;

const TABLE: u16 = 0x0002;
const POOL: u16 = 0x0001;
const PACKAGE: u16 = 0x0200;
const TYPE: u16 = 0x0201;
const TYPE_SPEC: u16 = 0x0202;
const NO_ENTRY: u32 = 0xffff_ffff;
const NO_ENTRY_16: u16 = 0xffff;

const ENTRY_COMPLEX: u16 = 0x0001;
const ENTRY_COMPACT: u16 = 0x0008;
const TYPE_SPARSE: u8 = 0x01;
const TYPE_OFFSET16: u8 = 0x02;

#[derive(Clone, Copy, Debug)]
pub struct TableLimits {
    pub max_bytes: usize,
    pub max_packages: usize,
    pub max_entries: usize,
    pub max_map_items: usize,
    pub max_strings: usize,
    pub max_string_units: usize,
}

impl Default for TableLimits {
    fn default() -> Self {
        Self {
            max_bytes: 256 * 1024 * 1024,
            max_packages: 64,
            max_entries: 4_000_000,
            max_map_items: 8_000_000,
            max_strings: 4_000_000,
            max_string_units: 256 * 1024 * 1024,
        }
    }
}

/// A compiled value: `Res_value`'s type and data word.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Value {
    pub data_type: u8,
    pub data: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapItem {
    /// The attribute (or, in an array, `0x01000000 + index`) the item is for.
    pub name: u32,
    pub value: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EntryValue {
    Simple(Value),
    Map { parent: u32, items: Vec<MapItem> },
}

#[derive(Clone, Debug)]
pub struct TableEntry {
    pub package: usize,
    pub resource_id: u32,
    pub type_index: usize,
    pub key_index: usize,
    pub config_index: usize,
    pub flags: u16,
    pub value: EntryValue,
}

#[derive(Clone, Debug)]
pub struct Package {
    pub id: u32,
    pub name: String,
    pub type_names: Vec<String>,
    pub key_names: Vec<String>,
    pub configs: Vec<Configuration>,
}

#[derive(Debug)]
pub struct ResourceTable {
    values: Vec<PoolString>,
    packages: Vec<Package>,
    entries: Vec<TableEntry>,
    by_id: BTreeMap<u32, usize>,
    map_items: usize,
    skipped_chunks: u32,
}

fn invalid(message: &str) -> MddError {
    MddError::new(ErrorCode::InvalidInput, "resources.table", message)
}
fn quota(message: &str) -> MddError {
    MddError::new(ErrorCode::QuotaExceeded, "resources.table", message)
}

fn u8_at(bytes: &[u8], at: usize) -> MddResult<u8> {
    bytes
        .get(at)
        .copied()
        .ok_or_else(|| invalid("a field lies past the end of its chunk"))
}
fn u16_at(bytes: &[u8], at: usize) -> MddResult<u16> {
    bytes
        .get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| invalid("a field lies past the end of its chunk"))
}
fn u32_at(bytes: &[u8], at: usize) -> MddResult<u32> {
    bytes
        .get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| invalid("a field lies past the end of its chunk"))
}

/// The chunk at `at` in `bytes`: its type, header size and the slice it spans.
fn chunk_at(bytes: &[u8], at: usize) -> MddResult<(u16, usize, &[u8])> {
    let kind = u16_at(bytes, at)?;
    let header = usize::from(u16_at(bytes, at + 2)?);
    let size = u32_at(bytes, at + 4)? as usize;
    if header < 8 || size < header || !header.is_multiple_of(4) || !size.is_multiple_of(4) {
        return Err(invalid("a chunk has a bad header size, size or alignment")
            .detail("chunk_type", u32::from(kind)));
    }
    let end = at
        .checked_add(size)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| invalid("a chunk reaches past the end of its parent"))?;
    Ok((kind, header, &bytes[at..end]))
}

fn pool_limits(limits: &TableLimits) -> ManifestLimits {
    ManifestLimits {
        max_strings: limits.max_strings,
        max_string_units: limits.max_string_units,
        max_events: limits.max_map_items,
        ..ManifestLimits::default()
    }
}

fn utf16_name(bytes: &[u8]) -> MddResult<String> {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes(*b))
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16(&units).map_err(|_| invalid("a package name is not valid UTF-16"))
}

fn pool_strings(chunk: &[u8], base: usize, limits: &TableLimits) -> MddResult<Vec<PoolString>> {
    parse_string_pool(chunk, base, pool_limits(limits))
}

fn pool_text(strings: Vec<PoolString>, what: &str) -> MddResult<Vec<String>> {
    strings
        .into_iter()
        .map(|s| {
            s.value.text.ok_or_else(|| {
                invalid("a type or key name has an unpaired surrogate")
                    .detail("pool", what.to_owned())
            })
        })
        .collect()
}

impl ResourceTable {
    pub fn parse(bytes: &[u8], limits: TableLimits) -> MddResult<Self> {
        if bytes.len() > limits.max_bytes {
            return Err(quota("the resource table exceeds the byte budget"));
        }
        let (kind, header, whole) = chunk_at(bytes, 0)?;
        if kind != TABLE || header < 12 || whole.len() != bytes.len() {
            return Err(invalid("not a resource table, or its size field is wrong")
                .detail("chunk_type", u32::from(kind)));
        }
        let declared_packages = u32_at(whole, 8)? as usize;
        let mut table = ResourceTable {
            values: Vec::new(),
            packages: Vec::new(),
            entries: Vec::new(),
            by_id: BTreeMap::new(),
            map_items: 0,
            skipped_chunks: 0,
        };
        let mut have_pool = false;
        let mut at = header;
        while at < whole.len() {
            let (kind, _, chunk) = chunk_at(whole, at)?;
            match kind {
                POOL if !have_pool => {
                    table.values = pool_strings(chunk, at, &limits)?;
                    have_pool = true;
                }
                POOL => return Err(invalid("a second global string pool")),
                PACKAGE => {
                    if table.packages.len() >= limits.max_packages {
                        return Err(quota("too many packages"));
                    }
                    table.parse_package(chunk, at, &limits)?;
                }
                _ => table.skipped_chunks += 1,
            }
            at += chunk.len();
        }
        if !have_pool {
            return Err(invalid("the resource table has no global string pool"));
        }
        if declared_packages != table.packages.len() {
            return Err(
                invalid("the package count does not match the packages present")
                    .detail("declared", declared_packages.to_string())
                    .detail("found", table.packages.len().to_string()),
            );
        }
        // The configurations of one resource follow each other by their qualifier string, the default
        // first; equal qualifiers keep their order in the file.
        let qualifiers: Vec<Vec<String>> = table
            .packages
            .iter()
            .map(|p| p.configs.iter().map(Configuration::qualifier).collect())
            .collect();
        table.entries.sort_by(|a, b| {
            (a.package, a.resource_id)
                .cmp(&(b.package, b.resource_id))
                .then_with(|| {
                    qualifiers[a.package][a.config_index]
                        .cmp(&qualifiers[b.package][b.config_index])
                })
        });
        for (position, entry) in table.entries.iter().enumerate() {
            table.by_id.entry(entry.resource_id).or_insert(position);
        }
        table.check_strings()?;
        Ok(table)
    }

    fn check_strings(&self) -> MddResult<()> {
        let limit = self.values.len();
        for entry in &self.entries {
            let check = |value: &Value| {
                if value.data_type == super::value::data_type::STRING
                    && value.data as usize >= limit
                {
                    return Err(
                        invalid("a string value points outside the global string pool")
                            .detail("resource_id", format!("0x{:08x}", entry.resource_id)),
                    );
                }
                Ok(())
            };
            match &entry.value {
                EntryValue::Simple(value) => check(value)?,
                EntryValue::Map { items, .. } => {
                    for item in items {
                        check(&item.value)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn parse_package(&mut self, chunk: &[u8], base: usize, limits: &TableLimits) -> MddResult<()> {
        let header = usize::from(u16_at(chunk, 2)?);
        if header < 284 {
            return Err(invalid("a package header is too small"));
        }
        let id = u32_at(chunk, 8)?;
        let name = utf16_name(
            chunk
                .get(12..268)
                .ok_or_else(|| invalid("a package header is too small"))?,
        )?;
        let pool_at = |offset: u32| -> MddResult<Vec<String>> {
            let at = offset as usize;
            if at < header || at >= chunk.len() {
                return Err(invalid("a package pool offset is outside the package"));
            }
            let (kind, _, pool) = chunk_at(chunk, at)?;
            if kind != POOL {
                return Err(invalid(
                    "a package pool offset does not point at a string pool",
                ));
            }
            pool_text(pool_strings(pool, base + at, limits)?, "package")
        };
        let type_names = pool_at(u32_at(chunk, 268)?)?;
        let key_names = pool_at(u32_at(chunk, 276)?)?;
        let type_id_offset = if header >= 288 {
            u32_at(chunk, 284)? as usize
        } else {
            0
        };
        let package = self.packages.len();
        self.packages.push(Package {
            id,
            name,
            type_names,
            key_names,
            configs: Vec::new(),
        });
        let mut at = header;
        while at < chunk.len() {
            let (kind, _, sub) = chunk_at(chunk, at)?;
            match kind {
                TYPE => self.parse_type(package, id, type_id_offset, sub, limits)?,
                TYPE_SPEC | POOL => {}
                _ => self.skipped_chunks += 1,
            }
            at += sub.len();
        }
        Ok(())
    }

    fn parse_type(
        &mut self,
        package: usize,
        package_id: u32,
        type_id_offset: usize,
        chunk: &[u8],
        limits: &TableLimits,
    ) -> MddResult<()> {
        let header = usize::from(u16_at(chunk, 2)?);
        let type_id = usize::from(u8_at(chunk, 8)?);
        let flags = u8_at(chunk, 9)?;
        let count = u32_at(chunk, 12)? as usize;
        let entries_start = u32_at(chunk, 16)? as usize;
        if type_id == 0 || header < 24 || entries_start > chunk.len() || entries_start < header {
            return Err(invalid("a type chunk has a bad id, header or entry start"));
        }
        let config = Configuration::parse(
            chunk
                .get(20..header)
                .ok_or_else(|| invalid("a type chunk is shorter than its header"))?,
        )?;
        let type_index = type_id
            .checked_sub(1 + type_id_offset)
            .filter(|i| *i < self.packages[package].type_names.len())
            .ok_or_else(|| invalid("a type id has no name in the package's type pool"))?;
        // Where each present entry is: (entry index, byte offset from entries_start).
        let slot_width = if flags & TYPE_OFFSET16 != 0 && flags & TYPE_SPARSE == 0 {
            2
        } else {
            4
        };
        let table_end = count
            .checked_mul(slot_width)
            .and_then(|n| n.checked_add(header))
            .filter(|end| *end <= chunk.len())
            .ok_or_else(|| invalid("a type chunk's entry table does not fit in the chunk"))?;
        if table_end > entries_start {
            return Err(invalid("a type chunk's entry table overlaps its entries"));
        }
        if self.entries.len().saturating_add(count) > limits.max_entries {
            return Err(quota("the resource table has too many entries"));
        }
        let mut slots: Vec<(usize, usize)> = Vec::new();
        for position in 0..count {
            let at = header + position * slot_width;
            if flags & TYPE_SPARSE != 0 {
                let word = u32_at(chunk, at)?;
                slots.push(((word & 0xffff) as usize, ((word >> 16) as usize) * 4));
            } else if flags & TYPE_OFFSET16 != 0 {
                let offset = u16_at(chunk, at)?;
                if offset != NO_ENTRY_16 {
                    slots.push((position, usize::from(offset) * 4));
                }
            } else {
                let offset = u32_at(chunk, at)?;
                if offset != NO_ENTRY {
                    slots.push((position, offset as usize));
                }
            }
        }
        let config_index = self.packages[package].configs.len();
        self.packages[package].configs.push(config);
        let key_count = self.packages[package].key_names.len();
        for (index, offset) in slots {
            if index > 0xffff {
                return Err(invalid("an entry index does not fit a resource id"));
            }
            let at = entries_start
                .checked_add(offset)
                .filter(|at| at + 8 <= chunk.len())
                .ok_or_else(|| invalid("an entry lies outside its type chunk"))?;
            let size = usize::from(u16_at(chunk, at)?);
            let entry_flags = u16_at(chunk, at + 2)?;
            let key = u32_at(chunk, at + 4)? as usize;
            if entry_flags & ENTRY_COMPACT != 0 {
                return Err(MddError::new(
                    ErrorCode::UnsupportedCapability,
                    "resources.table",
                    "a compact resource entry is not read yet",
                ));
            }
            if key >= key_count {
                return Err(invalid("an entry's key is outside the key pool"));
            }
            let value = if entry_flags & ENTRY_COMPLEX != 0 {
                if size < 16 {
                    return Err(invalid("a map entry is smaller than its header"));
                }
                let parent = u32_at(chunk, at + 8)?;
                let item_count = u32_at(chunk, at + 12)? as usize;
                let first = at + size;
                if first
                    .checked_add(item_count.saturating_mul(12))
                    .is_none_or(|end| end > chunk.len())
                {
                    return Err(invalid("a map entry's items do not fit in the chunk"));
                }
                self.map_items = self.map_items.saturating_add(item_count);
                if self.map_items > limits.max_map_items {
                    return Err(quota("the resource table has too many map items"));
                }
                let mut items = Vec::with_capacity(item_count);
                for item in 0..item_count {
                    let p = first + item * 12;
                    items.push(MapItem {
                        name: u32_at(chunk, p)?,
                        value: read_value(chunk, p + 4)?,
                    });
                }
                EntryValue::Map { parent, items }
            } else {
                if size < 8 {
                    return Err(invalid("an entry is smaller than its header"));
                }
                EntryValue::Simple(read_value(chunk, at + size)?)
            };
            self.entries.push(TableEntry {
                package,
                resource_id: (package_id << 24) | ((type_id as u32) << 16) | index as u32,
                type_index,
                key_index: key,
                config_index,
                flags: entry_flags,
                value,
            });
        }
        Ok(())
    }

    pub fn packages(&self) -> &[Package] {
        &self.packages
    }

    pub fn entries(&self) -> &[TableEntry] {
        &self.entries
    }

    /// Chunks of a type this reader does not know, which it passed over by their size.
    pub fn skipped_chunks(&self) -> u32 {
        self.skipped_chunks
    }

    pub fn string(&self, index: u32) -> Option<&PoolString> {
        self.values.get(index as usize)
    }

    pub fn type_name(&self, entry: &TableEntry) -> &str {
        &self.packages[entry.package].type_names[entry.type_index]
    }

    pub fn key_name(&self, entry: &TableEntry) -> &str {
        &self.packages[entry.package].key_names[entry.key_index]
    }

    pub fn config(&self, entry: &TableEntry) -> &Configuration {
        &self.packages[entry.package].configs[entry.config_index]
    }

    /// `type/key`, the way a query names a resource inside its package.
    pub fn local_name(&self, entry: &TableEntry) -> String {
        format!("{}/{}", self.type_name(entry), self.key_name(entry))
    }

    /// `package:type/key` of the resource with this id, when the table defines it.
    pub fn qualified_name(&self, resource_id: u32) -> Option<String> {
        let entry = &self.entries[*self.by_id.get(&resource_id)?];
        Some(format!(
            "{}:{}",
            self.packages[entry.package].name,
            self.local_name(entry)
        ))
    }
}

fn read_value(chunk: &[u8], at: usize) -> MddResult<Value> {
    let size = u16_at(chunk, at)?;
    if size < 8 || u8_at(chunk, at + 2)? != 0 {
        return Err(invalid(
            "a value has a bad size or a non-zero reserved byte",
        ));
    }
    Ok(Value {
        data_type: u8_at(chunk, at + 3)?,
        data: u32_at(chunk, at + 4)?,
    })
}
