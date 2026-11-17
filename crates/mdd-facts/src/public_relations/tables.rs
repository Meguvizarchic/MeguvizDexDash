//! The header, index and definition tables of one DEX: map_items, id_items, type_ids, type_lists,
//! type_list_entries, proto_ids, protos, proto_params, field_ids, fields, method_ids, class_defs, class_data_items.
//!
//! Row order is the physical order of the table (the map for `map_items`, the index for the id tables, the
//! offset for the lists, the class definition order for `class_defs` and `class_data_items`). `proto_params`
//! is ordered by prototype and then by parameter position. A relation read without `ORDER BY` has no
//! promised order; this is the order the engine keeps stable.
use super::{require_metadata, row_budget, to_u32, word16, word32};
use crate::definitions::DefinitionFacts;
use crate::metadata::MetadataFacts;
use mdd_dex::types::type_list_item_starts;
use mdd_types::{Completeness, ErrorCode, MddError, MddResult};

const NO_INDEX: u32 = 0xFFFF_FFFF;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MapItemRow {
    pub file_id: u32,
    pub ordinal: u32,
    pub type_code: u32,
    pub size: u32,
    pub offset: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdItemRow {
    pub file_id: u32,
    pub item_type_code: u32,
    pub idx: u32,
    pub item_off: u64,
    pub item_end_off: u64,
    /// The offset an id item holds: the string data of a string id, the encoded array of a call site id.
    /// The other id items hold indexes, not offsets, and carry none.
    pub data_off: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypeIdRow {
    pub file_id: u32,
    pub type_idx: u32,
    pub descriptor_idx: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypeListRow {
    pub file_id: u32,
    pub type_list_off: u64,
    pub type_list_end_off: u64,
    pub size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypeListEntryRow {
    pub file_id: u32,
    pub type_list_off: u64,
    pub ordinal: u32,
    pub type_idx: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtoIdRow {
    pub file_id: u32,
    pub proto_idx: u32,
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtoRow {
    pub file_id: u32,
    pub proto_idx: u32,
    pub shorty_idx: u32,
    pub shorty: String,
    pub return_type_idx: u32,
    pub return_descriptor: String,
    pub parameters_off: u32,
    pub param_count: u32,
    /// The parameter descriptors in order, joined by a comma (the encoding `methods.param_descriptors` uses).
    pub param_descriptors: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtoParamRow {
    pub file_id: u32,
    pub proto_idx: u32,
    pub ordinal: u32,
    pub type_idx: u32,
    pub descriptor: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldIdRow {
    pub file_id: u32,
    pub field_idx: u32,
    pub class_idx: u32,
    pub type_idx: u32,
    pub name_idx: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldRow {
    pub file_id: u32,
    pub field_idx: u32,
    pub class_idx: u32,
    pub class_descriptor: String,
    pub type_idx: u32,
    pub type_descriptor: String,
    pub name: String,
    pub descriptor: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodIdRow {
    pub file_id: u32,
    pub method_idx: u32,
    pub class_idx: u32,
    pub proto_idx: u32,
    pub name_idx: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassDefRow {
    pub file_id: u32,
    pub class_def_idx: u32,
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: Option<u32>,
    pub interfaces_off: u32,
    pub source_file_idx: Option<u32>,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassDataItemRow {
    pub file_id: u32,
    pub class_idx: u32,
    pub class_data_off: u64,
    pub class_data_end_off: u64,
    pub static_fields_size: u32,
    pub instance_fields_size: u32,
    pub direct_methods_size: u32,
    pub virtual_methods_size: u32,
}

fn fixed_table(header: &mdd_dex::DexHeader, name: &'static str) -> MddResult<(u32, u64)> {
    let table = header
        .tables
        .iter()
        .find(|table| table.name == name)
        .ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.public_relations",
                "validated header is missing a standard table",
            )
            .detail("table", name)
        })?;
    Ok((table.count, table.range.byte_offset.0))
}

impl MetadataFacts {
    /// `map_items`: the validated map list in file order.
    pub fn map_item_rows(&self, file_id: u32) -> MddResult<Vec<MapItemRow>> {
        require_metadata(self, "map_items")?;
        let map = &self.header().map;
        row_budget(map.len(), "map_items")?;
        map.iter()
            .enumerate()
            .map(|(ordinal, item)| {
                Ok(MapItemRow {
                    file_id,
                    ordinal: to_u32(ordinal as u64, "map ordinal")?,
                    type_code: u32::from(item.type_code),
                    size: item.count,
                    offset: item.byte_offset.0,
                })
            })
            .collect()
    }

    /// `id_items`: every item of the six fixed id tables, then the call site ids and method handles the map
    /// lists, with the physical range of each item.
    pub fn id_item_rows(&self, file_id: u32) -> MddResult<Vec<IdItemRow>> {
        require_metadata(self, "id_items")?;
        let header = self.header();
        let bytes = self.bytes();
        // (map type code, item size, offset word holds an offset of data)
        const KINDS: [(u16, u64, bool); 8] = [
            (0x0001, 4, true),
            (0x0002, 4, false),
            (0x0003, 12, false),
            (0x0004, 8, false),
            (0x0005, 8, false),
            (0x0006, 32, false),
            (0x0007, 4, true),
            (0x0008, 8, false),
        ];
        let mut rows = Vec::new();
        for (code, size, holds_offset) in KINDS {
            let (count, start) = if code <= 0x0006 {
                let name = match code {
                    0x0001 => "string_ids",
                    0x0002 => "type_ids",
                    0x0003 => "proto_ids",
                    0x0004 => "field_ids",
                    0x0005 => "method_ids",
                    _ => "class_defs",
                };
                fixed_table(header, name)?
            } else {
                header
                    .map
                    .iter()
                    .find(|item| item.type_code == code)
                    .map_or((0, 0), |item| (item.count, item.byte_offset.0))
            };
            row_budget(rows.len().saturating_add(count as usize), "id_items")?;
            for idx in 0..count {
                let item_off = start + u64::from(idx) * size;
                rows.push(IdItemRow {
                    file_id,
                    item_type_code: u32::from(code),
                    idx,
                    item_off,
                    item_end_off: item_off + size,
                    data_off: if holds_offset {
                        Some(word32(bytes, item_off, "id item")?)
                    } else {
                        None
                    },
                });
            }
        }
        Ok(rows)
    }

    /// `type_ids`: the descriptor string of every type.
    pub fn type_id_rows(&self, file_id: u32) -> MddResult<Vec<TypeIdRow>> {
        require_metadata(self, "type_ids")?;
        row_budget(self.types().len(), "type_ids")?;
        Ok(self
            .types()
            .iter()
            .map(|fact| TypeIdRow {
                file_id,
                type_idx: fact.data.type_idx,
                descriptor_idx: fact.data.descriptor_string_idx,
            })
            .collect())
    }

    /// The physical type lists, in offset order, with their parameter type indexes.
    fn physical_type_lists(&self) -> MddResult<Vec<(u64, Vec<u32>)>> {
        let bytes = self.bytes();
        let starts = type_list_item_starts(bytes, self.header())?;
        let mut lists = Vec::new();
        lists
            .try_reserve_exact(starts.len())
            .map_err(|_| quota("type_lists"))?;
        for start in starts {
            let size = word32(bytes, start, "type list size")?;
            let mut entries = Vec::new();
            entries
                .try_reserve_exact(size as usize)
                .map_err(|_| quota("type_list_entries"))?;
            for ordinal in 0..u64::from(size) {
                entries.push(u32::from(word16(
                    bytes,
                    start + 4 + ordinal * 2,
                    "type list entry",
                )?));
            }
            lists.push((start, entries));
        }
        Ok(lists)
    }

    /// `type_lists`: every type list of the map's type_list section, referenced or not.
    pub fn type_list_rows(&self, file_id: u32) -> MddResult<Vec<TypeListRow>> {
        require_metadata(self, "type_lists")?;
        self.physical_type_lists()?
            .into_iter()
            .map(|(start, entries)| {
                let size = to_u32(entries.len() as u64, "type list size")?;
                Ok(TypeListRow {
                    file_id,
                    type_list_off: start,
                    type_list_end_off: start + 4 + 2 * u64::from(size),
                    size,
                })
            })
            .collect()
    }

    /// `type_list_entries`: the members of every physical type list, in list and position order.
    pub fn type_list_entry_rows(&self, file_id: u32) -> MddResult<Vec<TypeListEntryRow>> {
        require_metadata(self, "type_list_entries")?;
        let mut rows = Vec::new();
        for (start, entries) in self.physical_type_lists()? {
            row_budget(
                rows.len().saturating_add(entries.len()),
                "type_list_entries",
            )?;
            for (ordinal, type_idx) in entries.into_iter().enumerate() {
                rows.push(TypeListEntryRow {
                    file_id,
                    type_list_off: start,
                    ordinal: to_u32(ordinal as u64, "type list position")?,
                    type_idx,
                });
            }
        }
        Ok(rows)
    }

    /// `proto_ids`: the raw words of every prototype id; an absent parameter list is the encoded zero.
    pub fn proto_id_rows(&self, file_id: u32) -> MddResult<Vec<ProtoIdRow>> {
        require_metadata(self, "proto_ids")?;
        row_budget(self.prototypes().len(), "proto_ids")?;
        self.prototypes()
            .iter()
            .map(|fact| {
                Ok(ProtoIdRow {
                    file_id,
                    proto_idx: fact.data.proto_idx,
                    shorty_idx: fact.data.shorty_string_idx,
                    return_type_idx: fact.data.return_type_idx,
                    parameters_off: fact
                        .data
                        .parameters_byte_offset
                        .map_or(Ok(0), |offset| to_u32(offset.0, "parameters_off"))?,
                })
            })
            .collect()
    }

    fn type_descriptor(&self, type_idx: u32) -> MddResult<&str> {
        self.types()
            .get(type_idx as usize)
            .map(|fact| fact.data.descriptor.as_str())
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "facts.public_relations",
                    "a validated type index is outside the type table",
                )
                .detail("type_idx", u64::from(type_idx))
            })
    }

    /// `protos`: each prototype with its shorty, return type and parameter descriptors spelled out.
    pub fn proto_rows(&self, file_id: u32) -> MddResult<Vec<ProtoRow>> {
        require_metadata(self, "protos")?;
        row_budget(self.prototypes().len(), "protos")?;
        self.prototypes()
            .iter()
            .map(|fact| {
                let mut joined = String::new();
                for (position, type_idx) in fact.data.parameter_type_indices.iter().enumerate() {
                    if position > 0 {
                        joined.push(',');
                    }
                    joined.push_str(self.type_descriptor(*type_idx)?);
                }
                Ok(ProtoRow {
                    file_id,
                    proto_idx: fact.data.proto_idx,
                    shorty_idx: fact.data.shorty_string_idx,
                    shorty: fact.data.shorty.clone(),
                    return_type_idx: fact.data.return_type_idx,
                    return_descriptor: self.type_descriptor(fact.data.return_type_idx)?.to_owned(),
                    parameters_off: fact
                        .data
                        .parameters_byte_offset
                        .map_or(Ok(0), |offset| to_u32(offset.0, "parameters_off"))?,
                    param_count: to_u32(
                        fact.data.parameter_type_indices.len() as u64,
                        "param_count",
                    )?,
                    param_descriptors: joined,
                })
            })
            .collect()
    }

    /// `proto_params`: the parameters of every prototype, one row each, even when two prototypes share a list.
    pub fn proto_param_rows(&self, file_id: u32) -> MddResult<Vec<ProtoParamRow>> {
        require_metadata(self, "proto_params")?;
        let total = self.prototypes().iter().fold(0usize, |sum, fact| {
            sum.saturating_add(fact.data.parameter_type_indices.len())
        });
        row_budget(total, "proto_params")?;
        let mut rows = Vec::with_capacity(total);
        for fact in self.prototypes() {
            for (ordinal, type_idx) in fact.data.parameter_type_indices.iter().enumerate() {
                rows.push(ProtoParamRow {
                    file_id,
                    proto_idx: fact.data.proto_idx,
                    ordinal: to_u32(ordinal as u64, "parameter position")?,
                    type_idx: *type_idx,
                    descriptor: self.type_descriptor(*type_idx)?.to_owned(),
                });
            }
        }
        Ok(rows)
    }
}

fn quota(relation: &'static str) -> MddError {
    MddError::new(
        ErrorCode::QuotaExceeded,
        "facts.public_relations",
        "relation row allocation failed",
    )
    .detail("relation", relation)
}

impl DefinitionFacts {
    fn require_definitions(&self, relation: &'static str) -> MddResult<()> {
        require_metadata(self.metadata(), relation)?;
        if self.definition_coverage() != Completeness::Complete {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.public_relations",
                "complete definition facts are required",
            )
            .detail("relation", relation));
        }
        Ok(())
    }

    /// `field_ids`: the four words of every field id.
    pub fn field_id_rows(&self, file_id: u32) -> MddResult<Vec<FieldIdRow>> {
        self.require_definitions("field_ids")?;
        let fields = &self.definitions().field_references;
        row_budget(fields.len(), "field_ids")?;
        Ok(fields
            .iter()
            .map(|field| FieldIdRow {
                file_id,
                field_idx: field.field_idx,
                class_idx: field.class_idx,
                type_idx: field.type_idx,
                name_idx: field.name_idx,
            })
            .collect())
    }

    /// `fields`: every field id with its class, type, name and full descriptor spelled out.
    pub fn field_rows(&self, file_id: u32) -> MddResult<Vec<FieldRow>> {
        self.require_definitions("fields")?;
        let fields = &self.definitions().field_references;
        row_budget(fields.len(), "fields")?;
        Ok(fields
            .iter()
            .map(|field| FieldRow {
                file_id,
                field_idx: field.field_idx,
                class_idx: field.class_idx,
                class_descriptor: field.class_descriptor.clone(),
                type_idx: field.type_idx,
                type_descriptor: field.type_descriptor.clone(),
                name: field.field_name.clone(),
                descriptor: field.descriptor.clone(),
            })
            .collect())
    }

    /// `method_ids`: the words of every method id.
    pub fn method_id_rows(&self, file_id: u32) -> MddResult<Vec<MethodIdRow>> {
        self.require_definitions("method_ids")?;
        let methods = &self.definitions().method_references;
        row_budget(methods.len(), "method_ids")?;
        Ok(methods
            .iter()
            .map(|method| MethodIdRow {
                file_id,
                method_idx: method.method_idx,
                class_idx: method.class_idx,
                proto_idx: method.proto_idx,
                name_idx: method.name_idx,
            })
            .collect())
    }

    /// `class_defs`: the eight words of every class definition, as stored: an absent superclass or source file is
    /// NULL, an absent interface list, annotation directory, class data or static value array is the encoded zero.
    pub fn class_def_rows(&self, file_id: u32) -> MddResult<Vec<ClassDefRow>> {
        self.require_definitions("class_defs")?;
        let (count, start) = fixed_table(self.metadata().header(), "class_defs")?;
        let classes = &self.definitions().classes;
        if usize::try_from(count).ok() != Some(classes.len()) {
            return Err(MddError::new(
                ErrorCode::InternalFault,
                "facts.public_relations",
                "the class definition facts disagree with the class_defs table",
            ));
        }
        row_budget(classes.len(), "class_defs")?;
        let bytes = self.bytes();
        let optional = |word: u32| (word != NO_INDEX).then_some(word);
        classes
            .iter()
            .map(|class| {
                let at = start + u64::from(class.class_def_idx) * 32;
                Ok(ClassDefRow {
                    file_id,
                    class_def_idx: class.class_def_idx,
                    class_idx: word32(bytes, at, "class_idx")?,
                    access_flags: word32(bytes, at + 4, "access_flags")?,
                    superclass_idx: optional(word32(bytes, at + 8, "superclass_idx")?),
                    interfaces_off: word32(bytes, at + 12, "interfaces_off")?,
                    source_file_idx: optional(word32(bytes, at + 16, "source_file_idx")?),
                    annotations_off: word32(bytes, at + 20, "annotations_off")?,
                    class_data_off: word32(bytes, at + 24, "class_data_off")?,
                    static_values_off: word32(bytes, at + 28, "static_values_off")?,
                })
            })
            .collect()
    }

    /// `class_data_items`: the class data of every class that has one, in class definition order, with its
    /// physical range and the four member counts it declares.
    pub fn class_data_item_rows(&self, file_id: u32) -> MddResult<Vec<ClassDataItemRow>> {
        self.require_definitions("class_data_items")?;
        let classes = &self.definitions().classes;
        row_budget(classes.len(), "class_data_items")?;
        Ok(classes
            .iter()
            .filter_map(|class| {
                class
                    .class_data_range
                    .as_ref()
                    .map(|range| ClassDataItemRow {
                        file_id,
                        class_idx: class.class_idx,
                        class_data_off: range.byte_offset.0,
                        class_data_end_off: range.byte_offset.0 + range.byte_length.0,
                        static_fields_size: class.static_fields_count,
                        instance_fields_size: class.instance_fields_count,
                        direct_methods_size: class.direct_methods_count,
                        virtual_methods_size: class.virtual_methods_count,
                    })
            })
            .collect())
    }
}
