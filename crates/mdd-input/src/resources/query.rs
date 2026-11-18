//! Questions put to a resource table: which (resource, configuration, value) rows match.
//!
//! A row is one value. A plain entry gives one row; a map entry (style, array, plurals)
//! gives one row per item, each carrying the entry's item count, the item's position, its
//! attribute id and the entry's parent. A reference is named, never followed: the row of
//! `@example.test:color/accent` says which resource it points at and stops there.
use super::{
    arsc::{EntryValue, MapItem, ResourceTable, TableEntry, Value},
    value::{ReferenceStyle, data_type, spell},
};
use mdd_types::{ErrorCode, MddError, MddResult};

/// What a query selects by. Every given field must match; a field left `None` matches all.
/// `configuration: Some("")` selects the default configuration only.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    pub resource_id: Option<u32>,
    pub resource_type: Option<String>,
    /// `type/key`, or `package:type/key` to also name the package.
    pub name: Option<String>,
    pub configuration: Option<String>,
    /// A substring of the resource's `type/key` name.
    pub contains: Option<String>,
}

/// Where a row is in the table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RowKey {
    pub entry: usize,
    pub item: Option<usize>,
}

/// The map-entry part of a row: how many items the entry has and its parent, and, when the row is
/// one of the items, which one. A map entry without items is one row with none of these item fields
/// and no value: it exists, and says that it is empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemInfo {
    pub count: usize,
    pub index: Option<usize>,
    pub name_id: Option<u32>,
    /// `package:type/key` of the item's attribute, when the table defines it.
    pub name: Option<String>,
    pub parent_id: u32,
}

#[derive(Clone, Debug)]
pub struct Row<'a> {
    pub entry: &'a TableEntry,
    pub package: &'a str,
    pub name: String,
    pub configuration: String,
    /// `None` for a map entry without items.
    pub value: Option<Value>,
    pub item: Option<ItemInfo>,
}

impl ResourceTable {
    fn matches(&self, entry: &TableEntry, filter: &Filter, configuration: &str) -> bool {
        if filter.resource_id.is_some_and(|id| id != entry.resource_id) {
            return false;
        }
        if filter
            .resource_type
            .as_deref()
            .is_some_and(|t| t != self.type_name(entry))
        {
            return false;
        }
        if let Some(wanted) = filter.name.as_deref() {
            let package = &self.packages()[entry.package].name;
            let local = self.local_name(entry);
            let hit = match wanted.split_once(':') {
                Some((qualifier, rest)) => qualifier == package && rest == local,
                None => wanted == local,
            };
            if !hit {
                return false;
            }
        }
        if filter
            .configuration
            .as_deref()
            .is_some_and(|c| c != configuration)
        {
            return false;
        }
        if filter
            .contains
            .as_deref()
            .is_some_and(|needle| !self.local_name(entry).contains(needle))
        {
            return false;
        }
        true
    }

    /// The keys of every row the filter selects, in table order.
    pub fn query(&self, filter: &Filter) -> Vec<RowKey> {
        let mut keys = Vec::new();
        for (index, entry) in self.entries().iter().enumerate() {
            let configuration = self.config(entry).qualifier();
            if !self.matches(entry, filter, &configuration) {
                continue;
            }
            match &entry.value {
                EntryValue::Simple(_) => keys.push(RowKey {
                    entry: index,
                    item: None,
                }),
                EntryValue::Map { items, .. } if items.is_empty() => keys.push(RowKey {
                    entry: index,
                    item: None,
                }),
                EntryValue::Map { items, .. } => {
                    keys.extend((0..items.len()).map(|item| RowKey {
                        entry: index,
                        item: Some(item),
                    }));
                }
            }
        }
        keys
    }

    pub fn row(&self, key: RowKey) -> Row<'_> {
        let entry = &self.entries()[key.entry];
        let (value, item) = match (&entry.value, key.item) {
            (EntryValue::Simple(value), _) => (Some(*value), None),
            (EntryValue::Map { parent, items }, Some(index)) => {
                let MapItem { name, value } = items[index];
                (
                    Some(value),
                    Some(ItemInfo {
                        count: items.len(),
                        index: Some(index),
                        name_id: Some(name),
                        name: self.qualified_name(name),
                        parent_id: *parent,
                    }),
                )
            }
            (EntryValue::Map { parent, items }, None) => (
                None,
                Some(ItemInfo {
                    count: items.len(),
                    index: None,
                    name_id: None,
                    name: None,
                    parent_id: *parent,
                }),
            ),
        };
        Row {
            entry,
            package: &self.packages()[entry.package].name,
            name: self.local_name(entry),
            configuration: self.config(entry).qualifier(),
            value,
            item,
        }
    }

    /// A value as the table view spells it: a string as its text, a reference by the name
    /// of the resource it points at when the table defines that resource, any other value
    /// as `value::spell` writes it.
    pub fn value_text(&self, value: Value) -> MddResult<String> {
        use data_type::*;
        match value.data_type {
            STRING => {
                let pooled = self.string(value.data).ok_or_else(|| {
                    MddError::new(
                        ErrorCode::InvalidInput,
                        "resources.table",
                        "a string value points outside the global string pool",
                    )
                })?;
                pooled.value.text.clone().ok_or_else(|| {
                    MddError::new(
                        ErrorCode::UnsupportedCapability,
                        "resources.table",
                        "a string value has an unpaired surrogate and cannot be shown as text",
                    )
                    .detail("string_index", value.data.to_string())
                })
            }
            REFERENCE | DYNAMIC_REFERENCE => Ok(self
                .qualified_name(value.data)
                .map(|name| format!("@{name}"))
                .unwrap_or_else(|| {
                    spell(value.data_type, value.data, ReferenceStyle::Prefixed)
                        .expect("a reference has a spelling")
                })),
            ATTRIBUTE | DYNAMIC_ATTRIBUTE => Ok(self
                .qualified_name(value.data)
                .map(|name| format!("?{name}"))
                .unwrap_or_else(|| {
                    spell(value.data_type, value.data, ReferenceStyle::Prefixed)
                        .expect("an attribute reference has a spelling")
                })),
            other => Ok(spell(other, value.data, ReferenceStyle::Prefixed)
                .expect("only a string has no spelling")),
        }
    }
}
