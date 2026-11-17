//! The encoded-value relations: method_handles, call_sites, call_site_args, encoded_arrays,
//! encoded_array_values, encoded_array_owners, class_static_values, and the hidden-API flags.
//!
//! `encoded_arrays` lists every encoded array item of the DEX, whether or not anything refers to it. An array is
//! owned by a call site (the arrays the `call_site_ids` table points at) or by a class (its static values);
//! an array nothing refers to has no owner row.
use super::{row_budget, to_u32};
use crate::annotations::AnnotationFacts;
use crate::definitions::DefinitionFacts;
use mdd_dex::annotations::{AnnotationLimits, EncodedValue, read_method_handle_section};
use mdd_dex::definitions::FieldKind;
use mdd_types::{Completeness, ErrorCode, MddError, MddResult};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodHandleRow {
    pub file_id: u32,
    pub method_handle_idx: u32,
    pub method_handle_type: u32,
    pub member_idx: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallSiteRow {
    pub file_id: u32,
    pub call_site_idx: u32,
    pub call_site_off: u32,
    pub value_count: u32,
    pub method_handle_idx: Option<u32>,
    pub method_name_idx: Option<u32>,
    pub proto_idx: Option<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CallSiteArgRow {
    pub file_id: u32,
    pub call_site_idx: u32,
    pub call_site_off: u32,
    pub ordinal: u32,
    pub value_kind: &'static str,
    pub value_index: Option<u32>,
    pub value_i64: Option<String>,
    pub value_f64: Option<f64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedArrayRow {
    pub file_id: u32,
    pub encoded_array_idx: u32,
    pub encoded_array_off: u32,
    pub encoded_array_end_off: u64,
    pub value_count: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EncodedArrayValueRow {
    pub file_id: u32,
    pub encoded_array_off: u32,
    pub depth: u32,
    pub ordinal: u32,
    pub name_idx: Option<u32>,
    pub value_off: u64,
    pub value_end_off: u64,
    pub value_kind: &'static str,
    pub value_index: Option<u32>,
    pub value_i64: Option<String>,
    pub value_f64: Option<f64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedArrayOwnerRow {
    pub file_id: u32,
    pub encoded_array_off: u32,
    pub owner_kind: &'static str,
    pub owner_idx: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ClassStaticValueRow {
    pub file_id: u32,
    pub class_idx: u32,
    pub static_values_off: u32,
    pub ordinal: u32,
    pub field_idx: Option<u32>,
    pub value_kind: &'static str,
    pub value_index: Option<u32>,
    pub value_i64: Option<String>,
    pub value_f64: Option<f64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HiddenApiFlagRow {
    pub file_id: u32,
    pub class_idx: u32,
    pub ordinal: u32,
    pub member_kind: &'static str,
    pub member_idx: u32,
    pub flag: u32,
}

fn float_of(value: &EncodedValue) -> Option<f64> {
    value.value_f64.map(|exact| exact.as_f64())
}

impl AnnotationFacts {
    fn require_arrays(&self, relation: &'static str) -> MddResult<()> {
        if self.annotation_coverage() != Completeness::Complete {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.public_relations",
                "complete annotation facts are required",
            )
            .detail("relation", relation));
        }
        Ok(())
    }

    /// The nodes of one encoded array in document order: the top-level values and, after each, its nested ones.
    fn array_nodes(&self, array_index: usize) -> MddResult<Vec<&EncodedValue>> {
        let data = self.data();
        let array = data.encoded_arrays.get(array_index).ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.public_relations",
                "an encoded array index lies outside the array table",
            )
        })?;
        let missing = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.public_relations",
                "an encoded array refers to a value node the facts do not hold",
            )
        };
        let mut nodes = Vec::new();
        let mut pending: Vec<u32> = array.elements.iter().rev().copied().collect();
        while let Some(node_id) = pending.pop() {
            let value = data.values.get(node_id as usize).ok_or_else(missing)?;
            if value.node_id != node_id {
                return Err(missing());
            }
            nodes.push(value);
            pending.extend(value.children.iter().rev().copied());
        }
        Ok(nodes)
    }

    /// `encoded_arrays`: every encoded array item, in offset order, with the number of its top-level values.
    pub fn encoded_array_rows(&self, file_id: u32) -> MddResult<Vec<EncodedArrayRow>> {
        self.require_arrays("encoded_arrays")?;
        let arrays = &self.data().encoded_arrays;
        row_budget(arrays.len(), "encoded_arrays")?;
        arrays
            .iter()
            .enumerate()
            .map(|(index, array)| {
                Ok(EncodedArrayRow {
                    file_id,
                    encoded_array_idx: to_u32(index as u64, "encoded array index")?,
                    encoded_array_off: array.byte_offset,
                    encoded_array_end_off: array.encoded_range.byte_offset.0
                        + array.encoded_range.byte_length.0,
                    value_count: to_u32(array.elements.len() as u64, "encoded array size")?,
                })
            })
            .collect()
    }

    /// `encoded_array_values`: every value node of every encoded array, nested ones included.
    pub fn encoded_array_value_rows(&self, file_id: u32) -> MddResult<Vec<EncodedArrayValueRow>> {
        self.require_arrays("encoded_array_values")?;
        let mut rows = Vec::new();
        for (index, array) in self.data().encoded_arrays.iter().enumerate() {
            for value in self.array_nodes(index)? {
                row_budget(rows.len().saturating_add(1), "encoded_array_values")?;
                rows.push(EncodedArrayValueRow {
                    file_id,
                    encoded_array_off: array.byte_offset,
                    depth: value.depth,
                    ordinal: value.ordinal,
                    name_idx: value.name_idx,
                    value_off: value.encoded_range.byte_offset.0,
                    value_end_off: value.encoded_range.byte_offset.0
                        + value.encoded_range.byte_length.0,
                    value_kind: value.kind.as_str(),
                    value_index: value.value_index,
                    value_i64: value.value_i64.clone(),
                    value_f64: float_of(value),
                });
            }
        }
        Ok(rows)
    }

    /// `encoded_array_owners`: the call site or the class each array belongs to.
    pub fn encoded_array_owner_rows(&self, file_id: u32) -> MddResult<Vec<EncodedArrayOwnerRow>> {
        self.require_arrays("encoded_array_owners")?;
        let data = self.data();
        let mut rows = Vec::new();
        for array in &data.encoded_arrays {
            for call_site in data
                .call_site_arrays
                .iter()
                .filter(|site| site.encoded_array_byte_offset == array.byte_offset)
            {
                rows.push(EncodedArrayOwnerRow {
                    file_id,
                    encoded_array_off: array.byte_offset,
                    owner_kind: "call_site",
                    owner_idx: call_site.call_site_idx,
                });
            }
            for class in self
                .definitions()
                .definitions()
                .classes
                .iter()
                .filter(|class| {
                    class
                        .static_values_byte_offset
                        .is_some_and(|offset| offset.0 == u64::from(array.byte_offset))
                })
            {
                rows.push(EncodedArrayOwnerRow {
                    file_id,
                    encoded_array_off: array.byte_offset,
                    owner_kind: "class_static_values",
                    owner_idx: class.class_idx,
                });
            }
            row_budget(rows.len(), "encoded_array_owners")?;
        }
        Ok(rows)
    }

    /// `call_sites`: every call site id, with the three values its array must start with (the bootstrap method
    /// handle, the call site name and the method type); NULL where the array holds fewer or others.
    pub fn call_site_rows(&self, file_id: u32) -> MddResult<Vec<CallSiteRow>> {
        self.require_arrays("call_sites")?;
        let data = self.data();
        row_budget(data.call_site_arrays.len(), "call_sites")?;
        data.call_site_arrays
            .iter()
            .map(|site| {
                let array = data
                    .encoded_arrays
                    .get(site.encoded_array_index as usize)
                    .ok_or_else(|| {
                        MddError::new(
                            ErrorCode::InternalFault,
                            "facts.public_relations",
                            "a call site refers to an encoded array the facts do not hold",
                        )
                    })?;
                Ok(CallSiteRow {
                    file_id,
                    call_site_idx: site.call_site_idx,
                    call_site_off: site.encoded_array_byte_offset,
                    value_count: to_u32(array.elements.len() as u64, "call site value count")?,
                    method_handle_idx: Some(site.bootstrap_method_handle_idx),
                    method_name_idx: Some(site.name_string_idx),
                    proto_idx: Some(site.method_type_idx),
                })
            })
            .collect()
    }

    /// `call_site_args`: the top-level values of every call site array, in order.
    pub fn call_site_arg_rows(&self, file_id: u32) -> MddResult<Vec<CallSiteArgRow>> {
        self.require_arrays("call_site_args")?;
        let data = self.data();
        let mut rows = Vec::new();
        for site in &data.call_site_arrays {
            for (ordinal, node_id) in data
                .encoded_arrays
                .get(site.encoded_array_index as usize)
                .map(|array| array.elements.as_slice())
                .unwrap_or_default()
                .iter()
                .enumerate()
            {
                let value = data.values.get(*node_id as usize).ok_or_else(|| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.public_relations",
                        "a call site refers to a value node the facts do not hold",
                    )
                })?;
                row_budget(rows.len().saturating_add(1), "call_site_args")?;
                rows.push(CallSiteArgRow {
                    file_id,
                    call_site_idx: site.call_site_idx,
                    call_site_off: site.encoded_array_byte_offset,
                    ordinal: to_u32(ordinal as u64, "call site argument position")?,
                    value_kind: value.kind.as_str(),
                    value_index: value.value_index,
                    value_i64: value.value_i64.clone(),
                    value_f64: float_of(value),
                });
            }
        }
        Ok(rows)
    }

    /// `class_static_values`: the initial value of the static fields of every class that has a static value
    /// array, one row per top-level value; the field is the static field at the same position.
    pub fn class_static_value_rows(&self, file_id: u32) -> MddResult<Vec<ClassStaticValueRow>> {
        self.require_arrays("class_static_values")?;
        let data = self.data();
        let definitions = self.definitions().definitions();
        let by_offset: BTreeMap<u32, usize> = data
            .encoded_arrays
            .iter()
            .enumerate()
            .map(|(index, array)| (array.byte_offset, index))
            .collect();
        let mut rows = Vec::new();
        for class in &definitions.classes {
            let Some(offset) = class.static_values_byte_offset else {
                continue;
            };
            let off = to_u32(offset.0, "static_values_off")?;
            let array_index = *by_offset.get(&off).ok_or_else(|| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "facts.public_relations",
                    "a class refers to a static value array the facts do not hold",
                )
            })?;
            let static_fields: Vec<u32> = definitions
                .field_definitions
                .iter()
                .filter(|field| {
                    field.class_def_idx == class.class_def_idx && field.kind == FieldKind::Static
                })
                .map(|field| field.field_idx)
                .collect();
            for (ordinal, node_id) in data.encoded_arrays[array_index].elements.iter().enumerate() {
                let value = data.values.get(*node_id as usize).ok_or_else(|| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.public_relations",
                        "a static value array refers to a value node the facts do not hold",
                    )
                })?;
                row_budget(rows.len().saturating_add(1), "class_static_values")?;
                rows.push(ClassStaticValueRow {
                    file_id,
                    class_idx: class.class_idx,
                    static_values_off: off,
                    ordinal: to_u32(ordinal as u64, "static value position")?,
                    field_idx: static_fields.get(ordinal).copied(),
                    value_kind: value.kind.as_str(),
                    value_index: value.value_index,
                    value_i64: value.value_i64.clone(),
                    value_f64: float_of(value),
                });
            }
        }
        Ok(rows)
    }
}

impl DefinitionFacts {
    /// `method_handles`: the kind and the field or method of every method handle.
    pub fn method_handle_rows(&self, file_id: u32) -> MddResult<Vec<MethodHandleRow>> {
        super::require_metadata(self.metadata(), "method_handles")?;
        let section = read_method_handle_section(
            self.bytes(),
            self.metadata().header(),
            self.definitions(),
            AnnotationLimits::default(),
        )?;
        row_budget(section.targets.len(), "method_handles")?;
        Ok(section
            .targets
            .iter()
            .map(|target| MethodHandleRow {
                file_id,
                method_handle_idx: target.method_handle_idx,
                method_handle_type: u32::from(target.handle_kind),
                member_idx: target.target_index,
            })
            .collect())
    }

    /// `hiddenapi_flags`: the hidden API flag of every member of every class that has flags in the
    /// `hiddenapi_class_data` section, fields (static, then instance) before methods (direct, then virtual).
    pub fn hiddenapi_flag_rows(&self, file_id: u32) -> MddResult<Vec<HiddenApiFlagRow>> {
        super::require_metadata(self.metadata(), "hiddenapi_flags")?;
        let header = self.metadata().header();
        let Some(position) = header.map.iter().position(|item| item.type_code == 0xf000) else {
            return Ok(Vec::new());
        };
        let bytes = self.bytes();
        let start = header.map[position].byte_offset.0;
        let end = header.map.get(position + 1).map_or(
            header.data_range.byte_offset.0 + header.data_range.byte_length.0,
            |item| item.byte_offset.0,
        );
        let invalid = |reason: &'static str, at: u64| {
            MddError::new(
                ErrorCode::InvalidInput,
                "facts.public_relations.hiddenapi",
                "the hidden API class data is malformed",
            )
            .detail("reason", reason)
            .detail("byte_offset", at.to_string())
        };
        let classes = &self.definitions().classes;
        let table = 4 + 4 * classes.len() as u64;
        let size = u64::from(super::word32(bytes, start, "hiddenapi size")?);
        if size < table || start.checked_add(size).is_none_or(|last| last > end) {
            return Err(invalid("HIDDENAPI_SIZE", start));
        }
        let section_end = start + size;
        let mut rows = Vec::new();
        for class in classes {
            let at = start + 4 + 4 * u64::from(class.class_def_idx);
            let relative = u64::from(super::word32(bytes, at, "hiddenapi class offset")?);
            if relative == 0 {
                continue;
            }
            if relative < table || relative >= size {
                return Err(invalid("HIDDENAPI_CLASS_OFFSET", at));
            }
            let mut cursor = start + relative;
            let fields = self
                .definitions()
                .field_definitions
                .iter()
                .filter(|field| field.class_def_idx == class.class_def_idx)
                .map(|field| ("field", field.field_idx));
            let methods = self
                .definitions()
                .method_definitions
                .iter()
                .filter(|method| method.class_def_idx == class.class_def_idx)
                .map(|method| ("method", method.method_idx));
            for (ordinal, (member_kind, member_idx)) in fields.chain(methods).enumerate() {
                let flag = read_uleb128(bytes, &mut cursor, section_end)
                    .ok_or_else(|| invalid("HIDDENAPI_FLAGS", cursor))?;
                row_budget(rows.len().saturating_add(1), "hiddenapi_flags")?;
                rows.push(HiddenApiFlagRow {
                    file_id,
                    class_idx: class.class_idx,
                    ordinal: to_u32(ordinal as u64, "hiddenapi position")?,
                    member_kind,
                    member_idx,
                    flag,
                });
            }
        }
        Ok(rows)
    }
}

/// An unsigned LEB128 of at most five bytes that stays below `limit`, or `None`.
fn read_uleb128(bytes: &[u8], cursor: &mut u64, limit: u64) -> Option<u32> {
    let mut value = 0u64;
    for shift in (0..35).step_by(7) {
        if *cursor >= limit {
            return None;
        }
        let byte = *bytes.get(usize::try_from(*cursor).ok()?)?;
        *cursor += 1;
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return u32::try_from(value).ok();
        }
    }
    None
}

/// The value and the cursor after it, for the unit tests of the reader.
#[cfg(test)]
pub(crate) fn read_uleb128_for_tests(bytes: &[u8], limit: u64) -> Option<(u32, u64)> {
    let mut cursor = 0u64;
    read_uleb128(bytes, &mut cursor, limit).map(|value| (value, cursor))
}
