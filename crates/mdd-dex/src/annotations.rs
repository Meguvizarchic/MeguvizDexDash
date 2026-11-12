//! Complete physical annotation/value item traversal over the held DEX bytes.
use crate::{
    DexHeader, DexRange,
    checked_reader::{CheckedReader, invalid},
    definitions::{DefinitionMetadata, DexDefinitions},
    strings::read_uleb128,
    types::parse_type_descriptor,
};
use mdd_types::{Completeness, DecimalU64, ErrorCode, MddError, MddResult};
use serde::{Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug)]
pub struct AnnotationLimits {
    pub max_depth: u32,
    pub max_items: u64,
    pub max_nodes: u64,
    pub max_rows: u64,
    pub max_decoded_bytes: u64,
}
impl Default for AnnotationLimits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_items: 4_000_000,
            max_nodes: 8_000_000,
            max_rows: 16_000_000,
            max_decoded_bytes: 512 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EncodedKind {
    Byte,
    Short,
    Char,
    Int,
    Long,
    Float,
    Double,
    MethodType,
    MethodHandle,
    String,
    Type,
    Field,
    Method,
    Enum,
    Array,
    Annotation,
    Null,
    Boolean,
}
impl EncodedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Byte => "byte",
            Self::Short => "short",
            Self::Char => "char",
            Self::Int => "int",
            Self::Long => "long",
            Self::Float => "float",
            Self::Double => "double",
            Self::MethodType => "method_type",
            Self::MethodHandle => "method_handle",
            Self::String => "string",
            Self::Type => "type",
            Self::Field => "field",
            Self::Method => "method",
            Self::Enum => "enum",
            Self::Array => "array",
            Self::Annotation => "annotation",
            Self::Null => "null",
            Self::Boolean => "boolean",
        }
    }
}

/// Projection preserves legal JSON for nonfinite values; bits are also retained on each node.
#[derive(Clone, Copy, Debug)]
pub struct ExactFloat {
    pub bit_width: u8,
    pub bits: u64,
}
impl ExactFloat {
    pub fn as_f64(self) -> f64 {
        if self.bit_width == 32 {
            f64::from(f32::from_bits(self.bits as u32))
        } else {
            f64::from_bits(self.bits)
        }
    }
}
impl Serialize for ExactFloat {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = self.as_f64();
        if value.is_nan() {
            serializer.serialize_str("NaN")
        } else if value == f64::INFINITY {
            serializer.serialize_str("Infinity")
        } else if value == f64::NEG_INFINITY {
            serializer.serialize_str("-Infinity")
        } else {
            serializer.serialize_f64(value)
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct EncodedValue {
    pub node_id: u32,
    pub annotation_byte_offset: Option<u32>,
    pub depth: u32,
    pub ordinal: u32,
    pub name_idx: Option<u32>,
    pub kind: EncodedKind,
    pub value_arg: u8,
    pub encoded_range: DexRange,
    pub raw_scalar_payload: Vec<u8>,
    pub value_index: Option<u32>,
    pub value_i64: Option<String>,
    pub float_bits: Option<DecimalU64>,
    pub float_bit_width: Option<u8>,
    pub value_f64: Option<ExactFloat>,
    pub children: Vec<u32>,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationItem {
    pub byte_offset: u32,
    pub visibility: u8,
    pub type_idx: u32,
    pub elements: Vec<u32>,
    pub encoded_range: DexRange,
}
#[derive(Clone, Debug, Serialize)]
pub struct EncodedArrayItem {
    pub byte_offset: u32,
    pub elements: Vec<u32>,
    pub encoded_range: DexRange,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationSet {
    pub byte_offset: u32,
    pub annotation_offsets: Vec<u32>,
    pub encoded_range: DexRange,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationSetRefList {
    pub byte_offset: u32,
    pub annotation_set_offsets: Vec<Option<u32>>,
    pub encoded_range: DexRange,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnotationOwnerKind {
    Class,
    Field,
    Method,
    Parameter,
}
#[derive(Clone, Debug, Serialize)]
pub struct DirectoryEntry {
    pub kind: AnnotationOwnerKind,
    pub local_index: u32,
    pub target_byte_offset: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationDirectory {
    pub byte_offset: u32,
    pub class_annotation_set_offset: Option<u32>,
    pub fields_size: u32,
    pub methods_size: u32,
    pub parameters_size: u32,
    pub entries: Vec<DirectoryEntry>,
    pub inferred_class_idx: Option<u32>,
    pub encoded_range: DexRange,
}
#[derive(Clone, Debug, Serialize)]
pub struct DirectoryBinding {
    pub class_def_idx: u32,
    pub class_idx: u32,
    pub directory_byte_offset: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationOwnerBinding {
    pub class_def_idx: u32,
    pub class_idx: u32,
    pub kind: AnnotationOwnerKind,
    pub local_index: u32,
    pub parameter_ordinal: Option<u32>,
    pub annotation_set_offset: Option<u32>,
    pub prototype_parameter_count: Option<u32>,
    pub parameter_position_in_prototype: Option<bool>,
}
#[derive(Clone, Debug, Serialize)]
pub struct ParameterListBinding {
    pub class_def_idx: u32,
    pub method_idx: u32,
    pub ref_list_byte_offset: u32,
    pub encoded_slot_count: u32,
    pub prototype_parameter_count: u32,
    pub encoded_slots_complete: bool,
    pub prototype_position_coverage: Completeness,
}
#[derive(Clone, Debug, Serialize)]
pub struct CallSiteArrayBinding {
    pub call_site_idx: u32,
    pub encoded_array_byte_offset: u32,
    pub encoded_array_index: u32,
    pub bootstrap_method_handle_idx: u32,
    pub name_string_idx: u32,
    pub method_type_idx: u32,
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct AnnotationUsage {
    pub physical_items: u64,
    pub value_nodes: u64,
    pub relation_rows: u64,
    pub decoded_bytes: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct DexAnnotations {
    pub annotation_items: Vec<AnnotationItem>,
    pub encoded_arrays: Vec<EncodedArrayItem>,
    pub sets: Vec<AnnotationSet>,
    pub ref_lists: Vec<AnnotationSetRefList>,
    pub directories: Vec<AnnotationDirectory>,
    pub directory_bindings: Vec<DirectoryBinding>,
    pub owner_bindings: Vec<AnnotationOwnerBinding>,
    pub parameter_lists: Vec<ParameterListBinding>,
    pub call_site_arrays: Vec<CallSiteArrayBinding>,
    pub values: Vec<EncodedValue>,
    pub usage: AnnotationUsage,
    pub validated_scope: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct MethodHandleTarget {
    pub method_handle_idx: u32,
    pub handle_kind: u16,
    pub target_kind: EncodedKind,
    pub target_index: u32,
    pub encoded_range: DexRange,
}
#[derive(Clone, Debug, Serialize)]
pub struct MethodHandleSection {
    pub targets: Vec<MethodHandleTarget>,
    pub usage: AnnotationUsage,
}
#[derive(Clone, Debug, Serialize)]
pub struct EncodedArraySection {
    pub arrays: Vec<EncodedArrayItem>,
    pub values: Vec<EncodedValue>,
    pub call_site_arrays: Vec<CallSiteArrayBinding>,
    pub method_handles: Vec<MethodHandleTarget>,
    pub usage: AnnotationUsage,
    pub validated_scope: String,
}

fn failure(reason: &str, offset: u64, length: u64) -> MddError {
    invalid(reason, "dex.annotations", offset, length)
}
fn quota(reason: &str, offset: u64, length: u64) -> MddError {
    let mut error = failure(reason, offset, length);
    error.code = ErrorCode::QuotaExceeded;
    error
}
fn span(offset: u64, length: u64) -> DexRange {
    DexRange {
        byte_offset: DecimalU64(offset),
        byte_length: DecimalU64(length),
    }
}
fn offset32(offset: u64) -> MddResult<u32> {
    u32::try_from(offset).map_err(|_| failure("ANNOTATION_OFFSET_OVERFLOW", offset, 0))
}
fn section(header: &DexHeader, kind: u16) -> Option<(u64, u64, u32)> {
    header
        .map
        .iter()
        .position(|item| item.type_code == kind)
        .map(|i| {
            (
                header.map[i].byte_offset.0,
                header.map.get(i + 1).map_or(
                    header.data_range.byte_offset.0 + header.data_range.byte_length.0,
                    |item| item.byte_offset.0,
                ),
                header.map[i].count,
            )
        })
}
struct Budget {
    limits: AnnotationLimits,
    used: AnnotationUsage,
}
impl Budget {
    fn bytes(&mut self, count: u64, at: u64) -> MddResult<()> {
        self.used.decoded_bytes = self
            .used
            .decoded_bytes
            .checked_add(count)
            .ok_or_else(|| quota("ANNOTATION_BYTE_BUDGET", at, count))?;
        if self.used.decoded_bytes > self.limits.max_decoded_bytes {
            return Err(quota("ANNOTATION_BYTE_BUDGET", at, count));
        }
        Ok(())
    }
    fn rows(&mut self, count: u64, at: u64) -> MddResult<()> {
        self.used.relation_rows = self
            .used
            .relation_rows
            .checked_add(count)
            .ok_or_else(|| quota("ANNOTATION_ROW_BUDGET", at, count))?;
        if self.used.relation_rows > self.limits.max_rows {
            return Err(quota("ANNOTATION_ROW_BUDGET", at, count));
        }
        self.bytes(count * 8, at)
    }
    fn item(&mut self, at: u64) -> MddResult<()> {
        self.used.physical_items += 1;
        if self.used.physical_items > self.limits.max_items {
            return Err(quota("ANNOTATION_ITEM_BUDGET", at, 1));
        }
        self.bytes(64, at)
    }
    fn node(&mut self, at: u64, depth: u32) -> MddResult<()> {
        if depth > self.limits.max_depth {
            return Err(quota("ANNOTATION_DEPTH_BUDGET", at, 1));
        }
        self.used.value_nodes += 1;
        if self.used.value_nodes > self.limits.max_nodes {
            return Err(quota("ANNOTATION_NODE_BUDGET", at, 1));
        }
        self.bytes(std::mem::size_of::<EncodedValue>() as u64, at)?;
        self.rows(1, at)
    }
    fn children(&mut self, count: u32, at: u64) -> MddResult<()> {
        if u64::from(count) > self.limits.max_nodes.saturating_sub(self.used.value_nodes) {
            return Err(quota("ANNOTATION_NODE_BUDGET", at, u64::from(count)));
        }
        self.bytes(u64::from(count) * 4, at)
    }
}
struct Cursor<'a> {
    reader: CheckedReader<'a>,
    at: u64,
    end: u64,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], at: u64, end: u64) -> Self {
        Self {
            reader: CheckedReader::new(bytes),
            at,
            end,
        }
    }
    fn take(&mut self, length: u64) -> MddResult<&'a [u8]> {
        if self.at.checked_add(length).is_none_or(|end| end > self.end) {
            return Err(failure("TRUNCATED_ANNOTATION_ITEM", self.at, length));
        }
        let value = self.reader.range(self.at, length)?;
        self.at += length;
        Ok(value)
    }
    fn byte(&mut self) -> MddResult<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> MddResult<u32> {
        let v = self.take(4)?;
        Ok(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
    }
    fn uleb(&mut self) -> MddResult<u32> {
        let (n, len) = read_uleb128(self.reader.range(0, self.reader.len())?, self.at, self.end)?;
        self.at += len;
        Ok(n)
    }
    fn align4(&mut self) -> MddResult<()> {
        let next = self
            .at
            .checked_add(3)
            .map(|v| v & !3)
            .ok_or_else(|| failure("ANNOTATION_ALIGNMENT_OVERFLOW", self.at, 4))?;
        if self.take(next - self.at)?.iter().any(|v| *v != 0) {
            return Err(failure("ANNOTATION_PADDING", self.at, 0));
        }
        Ok(())
    }
}

struct Parser<'a, M> {
    header: &'a DexHeader,
    pools: &'a M,
    definitions: &'a DexDefinitions,
    budget: Budget,
    values: Vec<EncodedValue>,
    validated_names: BTreeSet<u32>,
}
impl<M: DefinitionMetadata> Parser<'_, M> {
    fn class_type(&self, index: u32, at: u64) -> MddResult<()> {
        let item = self
            .pools
            .dex_type(index)
            .ok_or_else(|| failure("ANNOTATION_TYPE_INDEX", at, 1))?;
        if item.shape.shorty != 'L' || item.shape.array_dimensions != 0 {
            return Err(failure("ANNOTATION_TYPE_NOT_CLASS", at, 1));
        }
        Ok(())
    }
    fn name(&mut self, index: u32, at: u64) -> MddResult<()> {
        if self.validated_names.contains(&index) {
            return Ok(());
        }
        let item = self
            .pools
            .string(index)
            .ok_or_else(|| failure("ANNOTATION_NAME_INDEX", at, 1))?;
        let text = item
            .text
            .strict_utf8()
            .map_err(|_| failure("ANNOTATION_NAME_NON_SCALAR", at, 1))?;
        let simple = text
            .strip_prefix('<')
            .and_then(|v| v.strip_suffix('>'))
            .unwrap_or(&text);
        if simple.contains('/')
            || parse_type_descriptor(&format!("L{simple};"), &self.header.version, false).is_err()
        {
            return Err(failure("ANNOTATION_NAME_SYNTAX", at, 1));
        }
        self.validated_names.insert(index);
        Ok(())
    }
    fn annotation_elements(
        &mut self,
        c: &mut Cursor<'_>,
        depth: u32,
        root: Option<u32>,
    ) -> MddResult<(u32, Vec<u32>)> {
        let at = c.at;
        let ty = c.uleb()?;
        self.class_type(ty, at)?;
        let count = c.uleb()?;
        self.budget.children(count, c.at)?;
        let mut elements = Vec::new();
        elements
            .try_reserve_exact(count as usize)
            .map_err(|_| quota("ANNOTATION_ALLOCATION", c.at, u64::from(count)))?;
        let mut previous = None;
        for ordinal in 0..count {
            let at = c.at;
            let name = c.uleb()?;
            self.name(name, at)?;
            if previous.is_some_and(|value| value >= name) {
                return Err(failure("ANNOTATION_ELEMENT_ORDER", at, c.at - at));
            }
            elements.push(self.value(c, depth, ordinal, Some(name), root)?);
            previous = Some(name);
        }
        Ok((ty, elements))
    }
    fn array_elements(
        &mut self,
        c: &mut Cursor<'_>,
        depth: u32,
        root: Option<u32>,
    ) -> MddResult<Vec<u32>> {
        let count = c.uleb()?;
        self.budget.children(count, c.at)?;
        let mut elements = Vec::new();
        elements
            .try_reserve_exact(count as usize)
            .map_err(|_| quota("ANNOTATION_ALLOCATION", c.at, u64::from(count)))?;
        for ordinal in 0..count {
            elements.push(self.value(c, depth, ordinal, None, root)?);
        }
        Ok(elements)
    }
    fn reference(&self, kind: EncodedKind, index: u32, at: u64) -> MddResult<()> {
        let valid = match kind {
            EncodedKind::String => self.pools.string(index).is_some(),
            EncodedKind::Type => self.pools.dex_type(index).is_some(),
            EncodedKind::Field | EncodedKind::Enum => self
                .definitions
                .field_references
                .get(index as usize)
                .is_some(),
            EncodedKind::Method => self
                .definitions
                .method_references
                .get(index as usize)
                .is_some(),
            EncodedKind::MethodType => self.pools.prototype(index).is_some(),
            EncodedKind::MethodHandle => {
                section(self.header, 8).is_some_and(|(_, _, count)| index < count)
            }
            _ => false,
        };
        if !valid {
            return Err(failure("ENCODED_VALUE_INDEX", at, 1)
                .detail("value_kind", kind.as_str())
                .detail("value_index", u64::from(index)));
        }
        Ok(())
    }
    fn value(
        &mut self,
        c: &mut Cursor<'_>,
        depth: u32,
        ordinal: u32,
        name: Option<u32>,
        root: Option<u32>,
    ) -> MddResult<u32> {
        let at = c.at;
        self.budget.node(at, depth)?;
        let byte = c.byte()?;
        let tag = byte & 31;
        let arg = byte >> 5;
        let kind = match tag {
            0 => EncodedKind::Byte,
            2 => EncodedKind::Short,
            3 => EncodedKind::Char,
            4 => EncodedKind::Int,
            6 => EncodedKind::Long,
            0x10 => EncodedKind::Float,
            0x11 => EncodedKind::Double,
            0x15 => EncodedKind::MethodType,
            0x16 => EncodedKind::MethodHandle,
            0x17 => EncodedKind::String,
            0x18 => EncodedKind::Type,
            0x19 => EncodedKind::Field,
            0x1a => EncodedKind::Method,
            0x1b => EncodedKind::Enum,
            0x1c => EncodedKind::Array,
            0x1d => EncodedKind::Annotation,
            0x1e => EncodedKind::Null,
            0x1f => EncodedKind::Boolean,
            _ => {
                return Err(
                    failure("UNKNOWN_ENCODED_VALUE_TAG", at, 1).detail("tag", u64::from(tag))
                );
            }
        };
        if matches!(kind, EncodedKind::MethodType | EncodedKind::MethodHandle)
            && self.header.version.as_str() < "038"
        {
            return Err(failure("ENCODED_VALUE_VERSION", at, 1));
        }
        let max_arg = match kind {
            EncodedKind::Byte
            | EncodedKind::Array
            | EncodedKind::Annotation
            | EncodedKind::Null => 0,
            EncodedKind::Short | EncodedKind::Char | EncodedKind::Boolean => 1,
            EncodedKind::Long | EncodedKind::Double => 7,
            _ => 3,
        };
        if arg > max_arg {
            return Err(failure("ENCODED_VALUE_ARG", at, 1));
        }
        let node_id = u32::try_from(self.values.len())
            .map_err(|_| quota("ANNOTATION_NODE_ID_BUDGET", at, 1))?;
        self.values
            .try_reserve(1)
            .map_err(|_| quota("ANNOTATION_ALLOCATION", at, 1))?;
        self.values.push(EncodedValue {
            node_id,
            annotation_byte_offset: root,
            depth,
            ordinal,
            name_idx: name,
            kind,
            value_arg: arg,
            encoded_range: span(at, 0),
            raw_scalar_payload: Vec::new(),
            value_index: None,
            value_i64: None,
            float_bits: None,
            float_bit_width: None,
            value_f64: None,
            children: Vec::new(),
        });
        let mut payload = Vec::new();
        let mut index = None;
        let mut integer = None;
        let mut floating = None;
        let mut children = Vec::new();
        match kind {
            EncodedKind::Array => {
                children = self.array_elements(c, depth + 1, root)?;
            }
            EncodedKind::Annotation => {
                let (ty, elements) = self.annotation_elements(c, depth + 1, root)?;
                index = Some(ty);
                children = elements;
            }
            EncodedKind::Null => {}
            EncodedKind::Boolean => {
                integer = Some(arg.to_string());
            }
            _ => {
                let size = u64::from(arg) + 1;
                self.budget.bytes(size, at)?;
                payload = c.take(size)?.to_vec();
                let mut bits = 0u64;
                for (ordinal, byte) in payload.iter().enumerate() {
                    bits |= u64::from(*byte) << (ordinal * 8);
                }
                match kind {
                    EncodedKind::Byte
                    | EncodedKind::Short
                    | EncodedKind::Int
                    | EncodedKind::Long => {
                        let width = payload.len() * 8;
                        let signed = if width == 64 {
                            bits as i64
                        } else {
                            ((bits << (64 - width)) as i64) >> (64 - width)
                        };
                        integer = Some(signed.to_string());
                    }
                    EncodedKind::Char => {
                        integer = Some(bits.to_string());
                    }
                    EncodedKind::Float | EncodedKind::Double => {
                        let width = if kind == EncodedKind::Float { 32 } else { 64 };
                        bits <<= width - payload.len() * 8;
                        floating = Some(ExactFloat {
                            bit_width: width as u8,
                            bits,
                        });
                    }
                    _ => {
                        let target = u32::try_from(bits)
                            .map_err(|_| failure("ENCODED_VALUE_INDEX_OVERFLOW", at, size))?;
                        self.reference(kind, target, at)?;
                        index = Some(target);
                    }
                }
            }
        }
        self.values[node_id as usize] = EncodedValue {
            node_id,
            annotation_byte_offset: root,
            depth,
            ordinal,
            name_idx: name,
            kind,
            value_arg: arg,
            encoded_range: span(at, c.at - at),
            raw_scalar_payload: payload,
            value_index: index,
            value_i64: integer,
            float_bits: floating.map(|value| DecimalU64(value.bits)),
            float_bit_width: floating.map(|value| value.bit_width),
            value_f64: floating,
            children,
        };
        Ok(node_id)
    }
}

fn start_index<T>(items: &[T], offset: impl Fn(&T) -> u32) -> BTreeMap<u32, usize> {
    items
        .iter()
        .enumerate()
        .map(|(i, item)| (offset(item), i))
        .collect()
}

fn validate_limits(limits: AnnotationLimits) -> MddResult<()> {
    if limits.max_depth > 256
        || limits.max_nodes > u64::from(u32::MAX)
        || limits.max_rows > u64::MAX / 256
    {
        return Err(MddError::new(
            ErrorCode::InvalidArgument,
            "dex.annotations",
            "annotation limits exceed implementation address/depth bounds",
        ));
    }
    Ok(())
}
fn walk_encoded_arrays<M: DefinitionMetadata>(
    p: &mut Parser<'_, M>,
    bytes: &[u8],
) -> MddResult<Vec<EncodedArrayItem>> {
    let mut arrays = Vec::new();
    if let Some((start, end, count)) = section(p.header, 0x2005) {
        let mut c = Cursor::new(bytes, start, end);
        for _ in 0..count {
            let at = c.at;
            p.budget.item(at)?;
            let elements = p.array_elements(&mut c, 0, None)?;
            arrays.push(EncodedArrayItem {
                byte_offset: offset32(at)?,
                elements,
                encoded_range: span(at, c.at - at),
            });
        }
    }
    Ok(arrays)
}
fn validate_static_array_starts(
    definitions: &DexDefinitions,
    arrays: &[EncodedArrayItem],
    by_offset: &BTreeMap<u32, usize>,
) -> MddResult<()> {
    for class in &definitions.classes {
        if let Some(offset) = class.static_values_byte_offset {
            let array = by_offset
                .get(&offset32(offset.0)?)
                .map(|index| &arrays[*index])
                .ok_or_else(|| failure("ENCODED_ARRAY_NOT_ITEM_START", offset.0, 1))?;
            if array.elements.len() as u64 > u64::from(class.static_fields_count) {
                return Err(failure(
                    "STATIC_VALUE_COUNT",
                    offset.0,
                    array.encoded_range.byte_length.0,
                ));
            }
        }
    }
    Ok(())
}
fn validate_call_site_arrays<M: DefinitionMetadata>(
    p: &mut Parser<'_, M>,
    bytes: &[u8],
    arrays: &[EncodedArrayItem],
    by_offset: &BTreeMap<u32, usize>,
) -> MddResult<Vec<CallSiteArrayBinding>> {
    let mut result = Vec::new();
    if let Some((start, _, count)) = section(p.header, 7) {
        let reader = CheckedReader::new(bytes);
        for index in 0..count {
            let at = start + u64::from(index) * 4;
            let offset = reader.u32(at)?;
            let array_index = *by_offset
                .get(&offset)
                .ok_or_else(|| failure("CALL_SITE_ARRAY_NOT_ITEM_START", u64::from(offset), 1))?;
            let array = &arrays[array_index];
            if array.elements.len() < 3 {
                return Err(failure(
                    "CALL_SITE_MINIMUM_ARITY",
                    u64::from(offset),
                    array.encoded_range.byte_length.0,
                ));
            }
            let mut indices = [0u32; 3];
            for (position, expected) in [
                EncodedKind::MethodHandle,
                EncodedKind::String,
                EncodedKind::MethodType,
            ]
            .iter()
            .enumerate()
            {
                let node = &p.values[array.elements[position] as usize];
                if node.kind != *expected {
                    return Err(failure(
                        "CALL_SITE_ENCODED_PREFIX",
                        node.encoded_range.byte_offset.0,
                        node.encoded_range.byte_length.0,
                    )
                    .detail("position", position.to_string())
                    .detail("expected", expected.as_str()));
                }
                indices[position] = node.value_index.ok_or_else(|| {
                    failure(
                        "CALL_SITE_PREFIX_INDEX",
                        node.encoded_range.byte_offset.0,
                        node.encoded_range.byte_length.0,
                    )
                })?;
            }
            p.budget.rows(1, at)?;
            p.budget
                .bytes(std::mem::size_of::<CallSiteArrayBinding>() as u64, at)?;
            result.push(CallSiteArrayBinding {
                call_site_idx: index,
                encoded_array_byte_offset: offset,
                encoded_array_index: array_index as u32,
                bootstrap_method_handle_idx: indices[0],
                name_string_idx: indices[1],
                method_type_idx: indices[2],
            });
        }
    }
    Ok(result)
}
fn walk_method_handles(
    bytes: &[u8],
    header: &DexHeader,
    definitions: &DexDefinitions,
    budget: &mut Budget,
) -> MddResult<Vec<MethodHandleTarget>> {
    let mut result = Vec::new();
    if let Some((start, end, count)) = section(header, 8) {
        let mut c = Cursor::new(bytes, start, end);
        for index in 0..count {
            let at = c.at;
            budget.item(at)?;
            budget.rows(1, at)?;
            let raw = c.take(8)?;
            let kind = u16::from_le_bytes([raw[0], raw[1]]);
            let target = u32::from(u16::from_le_bytes([raw[4], raw[5]]));
            if kind > 8 || raw[2..4] != [0, 0] || raw[6..8] != [0, 0] {
                return Err(failure("METHOD_HANDLE_ENCODING", at, 8));
            }
            let target_kind = if kind <= 3 {
                EncodedKind::Field
            } else {
                EncodedKind::Method
            };
            let exists = if kind <= 3 {
                definitions.field_references.get(target as usize).is_some()
            } else {
                definitions.method_references.get(target as usize).is_some()
            };
            if !exists {
                return Err(failure("METHOD_HANDLE_TARGET_INDEX", at + 4, 2));
            }
            budget.bytes(std::mem::size_of::<MethodHandleTarget>() as u64, at)?;
            result.push(MethodHandleTarget {
                method_handle_idx: index,
                handle_kind: kind,
                target_kind,
                target_index: target,
                encoded_range: span(at, 8),
            });
        }
    }
    Ok(result)
}

/// Fixed method-handle facts only; does not require annotation or encoded-array consumers.
pub fn read_method_handle_section(
    bytes: &[u8],
    header: &DexHeader,
    definitions: &DexDefinitions,
    limits: AnnotationLimits,
) -> MddResult<MethodHandleSection> {
    validate_limits(limits)?;
    let mut budget = Budget {
        limits,
        used: AnnotationUsage::default(),
    };
    let targets = walk_method_handles(bytes, header, definitions, &mut budget)?;
    Ok(MethodHandleSection {
        targets,
        usage: budget.used,
    })
}
/// Physical encoded arrays/handles/call-site prefixes only. Unrelated annotation
/// directories, sets and annotation_item data are deliberately outside this scope.
pub fn read_encoded_array_section<M: DefinitionMetadata>(
    bytes: &[u8],
    header: &DexHeader,
    pools: &M,
    definitions: &DexDefinitions,
    limits: AnnotationLimits,
) -> MddResult<EncodedArraySection> {
    validate_limits(limits)?;
    let mut p = Parser {
        header,
        pools,
        definitions,
        budget: Budget {
            limits,
            used: AnnotationUsage::default(),
        },
        values: Vec::new(),
        validated_names: BTreeSet::new(),
    };
    let arrays = walk_encoded_arrays(&mut p, bytes)?;
    let by_offset = start_index(&arrays, |item| item.byte_offset);
    validate_static_array_starts(definitions, &arrays, &by_offset)?;
    let method_handles = walk_method_handles(bytes, header, definitions, &mut p.budget)?;
    let call_site_arrays = validate_call_site_arrays(&mut p, bytes, &arrays, &by_offset)?;
    Ok(EncodedArraySection{arrays,values:p.values,method_handles,call_site_arrays,usage:p.budget.used,validated_scope:"physical-encoded-arrays-handles-call-site-prefix-v1; excludes unrelated annotation items and runtime bootstrap resolution".into()})
}

pub fn read_annotations<M: DefinitionMetadata>(
    bytes: &[u8],
    header: &DexHeader,
    pools: &M,
    definitions: &DexDefinitions,
    limits: AnnotationLimits,
) -> MddResult<DexAnnotations> {
    validate_limits(limits)?;
    let mut p = Parser {
        header,
        pools,
        definitions,
        budget: Budget {
            limits,
            used: AnnotationUsage::default(),
        },
        values: Vec::new(),
        validated_names: BTreeSet::new(),
    };
    let mut annotation_items = Vec::new();
    let mut sets = Vec::new();
    let mut ref_lists = Vec::new();
    let mut directories = Vec::new();
    if let Some((start, end, count)) = section(header, 0x2004) {
        let mut c = Cursor::new(bytes, start, end);
        for _ in 0..count {
            let at = c.at;
            p.budget.item(at)?;
            let off = offset32(at)?;
            let visibility = c.byte()?;
            if visibility > 2 {
                return Err(failure("ANNOTATION_VISIBILITY", at, 1));
            }
            let (type_idx, elements) = p.annotation_elements(&mut c, 0, Some(off))?;
            annotation_items.push(AnnotationItem {
                byte_offset: off,
                visibility,
                type_idx,
                elements,
                encoded_range: span(at, c.at - at),
            });
        }
    }
    let encoded_arrays = walk_encoded_arrays(&mut p, bytes)?;
    let annotations_by_offset = start_index(&annotation_items, |item| item.byte_offset);
    if let Some((start, end, count)) = section(header, 0x1003) {
        let mut c = Cursor::new(bytes, start, end);
        for _ in 0..count {
            c.align4()?;
            let at = c.at;
            p.budget.item(at)?;
            let n = c.u32()?;
            p.budget.rows(u64::from(n), at)?;
            let mut offsets = Vec::new();
            let mut previous = None;
            for _ in 0..n {
                let target = c.u32()?;
                let item = annotations_by_offset
                    .get(&target)
                    .map(|i| &annotation_items[*i])
                    .ok_or_else(|| failure("ANNOTATION_NOT_ITEM_START", u64::from(target), 1))?;
                if previous.is_some_and(|ty| ty >= item.type_idx) {
                    return Err(failure("ANNOTATION_SET_TYPE_ORDER", at, c.at - at));
                }
                previous = Some(item.type_idx);
                offsets.push(target);
            }
            sets.push(AnnotationSet {
                byte_offset: offset32(at)?,
                annotation_offsets: offsets,
                encoded_range: span(at, c.at - at),
            });
        }
    }
    let sets_by_offset = start_index(&sets, |item| item.byte_offset);
    if let Some((start, end, count)) = section(header, 0x1002) {
        let mut c = Cursor::new(bytes, start, end);
        for _ in 0..count {
            c.align4()?;
            let at = c.at;
            p.budget.item(at)?;
            let n = c.u32()?;
            p.budget.rows(u64::from(n), at)?;
            let mut offsets = Vec::new();
            for _ in 0..n {
                let target = c.u32()?;
                if target != 0 && !sets_by_offset.contains_key(&target) {
                    return Err(failure(
                        "ANNOTATION_SET_NOT_ITEM_START",
                        u64::from(target),
                        4,
                    ));
                }
                offsets.push((target != 0).then_some(target));
            }
            ref_lists.push(AnnotationSetRefList {
                byte_offset: offset32(at)?,
                annotation_set_offsets: offsets,
                encoded_range: span(at, c.at - at),
            });
        }
    }
    let refs_by_offset = start_index(&ref_lists, |item| item.byte_offset);
    if let Some((start, end, count)) = section(header, 0x2006) {
        let mut c = Cursor::new(bytes, start, end);
        for _ in 0..count {
            c.align4()?;
            let at = c.at;
            p.budget.item(at)?;
            let class_set = c.u32()?;
            if class_set != 0 && !sets_by_offset.contains_key(&class_set) {
                return Err(failure(
                    "ANNOTATION_SET_NOT_ITEM_START",
                    u64::from(class_set),
                    4,
                ));
            }
            let fields = c.u32()?;
            let methods = c.u32()?;
            let parameters = c.u32()?;
            let n = u64::from(fields) + u64::from(methods) + u64::from(parameters);
            p.budget.rows(n, at)?;
            let mut entries = Vec::new();
            let mut owner = None;
            for (kind, count) in [
                (AnnotationOwnerKind::Field, fields),
                (AnnotationOwnerKind::Method, methods),
                (AnnotationOwnerKind::Parameter, parameters),
            ] {
                let mut previous = None;
                for _ in 0..count {
                    let position = c.at;
                    let index = c.u32()?;
                    let target = c.u32()?;
                    if previous.is_some_and(|value| value >= index) {
                        return Err(failure("ANNOTATION_DIRECTORY_ORDER", position, 8));
                    }
                    let class = if kind == AnnotationOwnerKind::Field {
                        definitions
                            .field_references
                            .get(index as usize)
                            .map(|r| r.class_idx)
                    } else {
                        definitions
                            .method_references
                            .get(index as usize)
                            .map(|r| r.class_idx)
                    }
                    .ok_or_else(|| failure("ANNOTATION_OWNER_INDEX", position, 4))?;
                    if owner.is_some_and(|old| old != class) {
                        return Err(failure("ANNOTATION_DIRECTORY_OWNER", position, 8));
                    }
                    owner = Some(class);
                    let valid = if kind == AnnotationOwnerKind::Parameter {
                        refs_by_offset.contains_key(&target)
                    } else {
                        sets_by_offset.contains_key(&target)
                    };
                    if !valid {
                        return Err(failure(
                            if kind == AnnotationOwnerKind::Parameter {
                                "ANNOTATION_REF_LIST_NOT_ITEM_START"
                            } else {
                                "ANNOTATION_SET_NOT_ITEM_START"
                            },
                            u64::from(target),
                            4,
                        ));
                    }
                    entries.push(DirectoryEntry {
                        kind,
                        local_index: index,
                        target_byte_offset: target,
                    });
                    previous = Some(index);
                }
            }
            directories.push(AnnotationDirectory {
                byte_offset: offset32(at)?,
                class_annotation_set_offset: (class_set != 0).then_some(class_set),
                fields_size: fields,
                methods_size: methods,
                parameters_size: parameters,
                entries,
                inferred_class_idx: owner,
                encoded_range: span(at, c.at - at),
            });
        }
    }
    let directories_by_offset = start_index(&directories, |item| item.byte_offset);
    let arrays_by_offset = start_index(&encoded_arrays, |item| item.byte_offset);
    validate_static_array_starts(definitions, &encoded_arrays, &arrays_by_offset)?;
    let mut directory_bindings = Vec::new();
    let mut owner_bindings = Vec::new();
    let mut parameter_lists = Vec::new();
    for class in &definitions.classes {
        let Some(offset) = class.annotations_byte_offset else {
            continue;
        };
        let offset = offset32(offset.0)?;
        let directory = directories_by_offset
            .get(&offset)
            .map(|i| &directories[*i])
            .ok_or_else(|| failure("ANNOTATION_DIRECTORY_NOT_ITEM_START", u64::from(offset), 16))?;
        if directory
            .inferred_class_idx
            .is_some_and(|owner| owner != class.class_idx)
        {
            return Err(failure("ANNOTATION_CLASS_OWNER", u64::from(offset), 16));
        }
        p.budget.rows(1, u64::from(offset))?;
        directory_bindings.push(DirectoryBinding {
            class_def_idx: class.class_def_idx,
            class_idx: class.class_idx,
            directory_byte_offset: offset,
        });
        if let Some(set) = directory.class_annotation_set_offset {
            p.budget.rows(1, u64::from(offset))?;
            owner_bindings.push(AnnotationOwnerBinding {
                class_def_idx: class.class_def_idx,
                class_idx: class.class_idx,
                kind: AnnotationOwnerKind::Class,
                local_index: class.class_def_idx,
                parameter_ordinal: None,
                annotation_set_offset: Some(set),
                prototype_parameter_count: None,
                parameter_position_in_prototype: None,
            });
        }
        for entry in &directory.entries {
            if entry.kind == AnnotationOwnerKind::Parameter {
                let method = &definitions.method_references[entry.local_index as usize];
                let proto = pools
                    .prototype(method.proto_idx)
                    .ok_or_else(|| failure("ANNOTATION_PARAMETER_PROTO", u64::from(offset), 16))?;
                let list = &ref_lists[refs_by_offset[&entry.target_byte_offset]];
                let position_complete =
                    list.annotation_set_offsets.len() == proto.parameter_type_indices.len();
                p.budget.rows(1, u64::from(list.byte_offset))?;
                parameter_lists.push(ParameterListBinding {
                    class_def_idx: class.class_def_idx,
                    method_idx: entry.local_index,
                    ref_list_byte_offset: list.byte_offset,
                    encoded_slot_count: list.annotation_set_offsets.len() as u32,
                    prototype_parameter_count: proto.parameter_type_indices.len() as u32,
                    encoded_slots_complete: true,
                    prototype_position_coverage: if position_complete {
                        Completeness::Complete
                    } else {
                        Completeness::Unknown
                    },
                });
                p.budget.rows(
                    list.annotation_set_offsets.len() as u64,
                    u64::from(list.byte_offset),
                )?;
                for (ordinal, set) in list.annotation_set_offsets.iter().enumerate() {
                    owner_bindings.push(AnnotationOwnerBinding {
                        class_def_idx: class.class_def_idx,
                        class_idx: class.class_idx,
                        kind: entry.kind,
                        local_index: entry.local_index,
                        parameter_ordinal: Some(ordinal as u32),
                        annotation_set_offset: *set,
                        prototype_parameter_count: Some(proto.parameter_type_indices.len() as u32),
                        parameter_position_in_prototype: position_complete
                            .then_some(ordinal < proto.parameter_type_indices.len()),
                    });
                }
            } else {
                p.budget.rows(1, u64::from(offset))?;
                owner_bindings.push(AnnotationOwnerBinding {
                    class_def_idx: class.class_def_idx,
                    class_idx: class.class_idx,
                    kind: entry.kind,
                    local_index: entry.local_index,
                    parameter_ordinal: None,
                    annotation_set_offset: Some(entry.target_byte_offset),
                    prototype_parameter_count: None,
                    parameter_position_in_prototype: None,
                });
            }
        }
    }
    let call_site_arrays =
        validate_call_site_arrays(&mut p, bytes, &encoded_arrays, &arrays_by_offset)?;
    Ok(DexAnnotations{annotation_items,encoded_arrays,sets,ref_lists,directories,directory_bindings,owner_bindings,parameter_lists,call_site_arrays,values:p.values,usage:p.budget.used,validated_scope:"physical-annotations-encoded-values-v1; call-site encoded prefix validated; static-value type compatibility, complete prototype-position coverage and runtime bootstrap semantics remain separate".into()})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        definitions::{DefinitionLimits, DefinitionPools, read_definitions},
        strings::{StringLimits, read_string_pool},
        types::read_types_and_prototypes,
        validate_header,
    };
    fn parse(bytes: &[u8], limits: AnnotationLimits) -> MddResult<DexAnnotations> {
        let header = validate_header(bytes)?;
        let strings = read_string_pool(bytes, &header, StringLimits::default())?;
        let (types, prototypes) = read_types_and_prototypes(bytes, &header, &strings)?;
        let pools = DefinitionPools {
            strings: &strings,
            types: &types,
            prototypes: &prototypes,
        };
        let defs = read_definitions(bytes, &header, &pools, DefinitionLimits::default())?;
        read_annotations(bytes, &header, &pools, &defs, limits)
    }
    #[test]
    fn full_physical_annotations_preserve_types_bits_and_local_positions() {
        let bytes =
            include_bytes!("../../../tests/fixtures/annotations/generated/annotations-038.dex");
        let facts = parse(bytes, AnnotationLimits::default()).unwrap();
        assert_eq!(facts.annotation_items.len(), 4);
        assert_eq!(facts.directories.len(), 1);
        assert_eq!(facts.sets.len(), 4);
        assert_eq!(facts.ref_lists.len(), 1);
        assert_eq!(facts.values.len(), 44);
        let float = facts
            .values
            .iter()
            .find(|value| value.float_bits == Some(DecimalU64(0x7fc01234)))
            .unwrap();
        assert_eq!(serde_json::to_string(&float.value_f64).unwrap(), "\"NaN\"");
        assert!(
            facts
                .values
                .iter()
                .any(|value| value.value_i64.as_deref() == Some("-9223372036854775808"))
        );
        assert_eq!(
            facts
                .owner_bindings
                .iter()
                .filter(|owner| owner.kind == AnnotationOwnerKind::Parameter
                    && owner.annotation_set_offset.is_none())
                .count(),
            2
        );
        assert!(
            facts
                .owner_bindings
                .iter()
                .filter(|owner| owner.kind == AnnotationOwnerKind::Parameter)
                .all(|owner| owner.parameter_position_in_prototype == Some(true))
        );
    }
    #[test]
    fn parameter_lists_preserve_encoded_slots_without_inventing_nulls() {
        let facts = parse(
            include_bytes!("../../../tests/fixtures/annotations/generated/bad-parameter-arity.dex"),
            AnnotationLimits::default(),
        )
        .unwrap();
        assert_eq!(facts.ref_lists[0].annotation_set_offsets.len(), 1);
        assert_eq!(
            facts
                .owner_bindings
                .iter()
                .filter(|owner| owner.kind == AnnotationOwnerKind::Parameter)
                .count(),
            2
        );
        assert!(
            facts
                .parameter_lists
                .iter()
                .all(|binding| binding.encoded_slots_complete
                    && binding.encoded_slot_count == 1
                    && binding.prototype_parameter_count == 2
                    && binding.prototype_position_coverage == Completeness::Unknown)
        );
    }
    #[test]
    fn short_parameter_list_does_not_claim_known_prototype_positions() {
        let facts = parse(
            include_bytes!("../../../tests/fixtures/annotations/generated/bad-parameter-arity.dex"),
            AnnotationLimits::default(),
        )
        .unwrap();
        let parameters: Vec<_> = facts
            .owner_bindings
            .iter()
            .filter(|owner| owner.kind == AnnotationOwnerKind::Parameter)
            .collect();
        assert_eq!(parameters.len(), 2);
        assert!(
            parameters
                .iter()
                .all(|owner| owner.parameter_ordinal == Some(0))
        );
        assert!(
            parameters
                .iter()
                .all(|owner| owner.parameter_position_in_prototype.is_none())
        );
        assert!(
            facts
                .parameter_lists
                .iter()
                .all(|binding| binding.prototype_position_coverage == Completeness::Unknown)
        );
    }
    #[test]
    fn parameter_position_known_iff_list_matches_prototype_across_all_fixtures() {
        // Positional binding itself is an ART implementation fact, not an
        // inference: `art::annotations::GetAnnotationForMethodParameter` indexes
        // `annotation_set_ref_list.list_[parameter_idx]` directly, so slot `i`
        // is parameter `i`. This test only asserts the derived invariant the
        // reader exposes, across every retained parameter fixture, so a
        // regression in any single fixture cannot hide behind an empty loop.
        let fixtures: [(&[u8], &str); 7] = [
            (
                include_bytes!(
                    "../../../tests/fixtures/annotations/generated/parameter-empty-nonzero-proto.dex"
                ),
                "parameter-empty-nonzero-proto",
            ),
            (
                include_bytes!(
                    "../../../tests/fixtures/annotations/generated/parameter-empty-zero-proto.dex"
                ),
                "parameter-empty-zero-proto",
            ),
            (
                include_bytes!(
                    "../../../tests/fixtures/annotations/generated/parameter-long-nonzero-proto.dex"
                ),
                "parameter-long-nonzero-proto",
            ),
            (
                include_bytes!(
                    "../../../tests/fixtures/annotations/generated/parameter-orphan-empty-no-binding.dex"
                ),
                "parameter-orphan-empty-no-binding",
            ),
            (
                include_bytes!(
                    "../../../tests/fixtures/annotations/generated/parameter-shared-empty-set.dex"
                ),
                "parameter-shared-empty-set",
            ),
            (
                include_bytes!(
                    "../../../tests/fixtures/annotations/generated/parameter-shared-signature.dex"
                ),
                "parameter-shared-signature",
            ),
            (
                include_bytes!(
                    "../../../tests/fixtures/annotations/generated/parameter-shared-signature-complete.dex"
                ),
                "parameter-shared-signature-complete",
            ),
        ];
        let mut observed_complete = 0usize;
        let mut observed_unknown = 0usize;
        let mut observed_unbound = 0usize;
        for (bytes, name) in fixtures {
            let facts = parse(bytes, AnnotationLimits::default()).expect(name);
            if facts.parameter_lists.is_empty() {
                // A physically present ref-list with no directory binding is a
                // legitimate orphan; it must not be reported as a known list.
                observed_unbound += 1;
                assert!(
                    facts
                        .owner_bindings
                        .iter()
                        .all(|owner| owner.kind != AnnotationOwnerKind::Parameter
                            || owner.parameter_position_in_prototype.is_none()),
                    "{name}: unbound ref-list produced known parameter positions"
                );
                continue;
            }
            for binding in &facts.parameter_lists {
                let equal = binding.encoded_slot_count as usize
                    == binding.prototype_parameter_count as usize;
                let expected = if equal {
                    Completeness::Complete
                } else {
                    Completeness::Unknown
                };
                assert_eq!(
                    binding.prototype_position_coverage, expected,
                    "{name}: coverage must follow slot/prototype equality"
                );
                if equal {
                    observed_complete += 1;
                } else {
                    observed_unknown += 1;
                }
                let owners: Vec<_> = facts
                    .owner_bindings
                    .iter()
                    .filter(|owner| {
                        owner.kind == AnnotationOwnerKind::Parameter
                            && owner.local_index == binding.method_idx
                    })
                    .collect();
                assert_eq!(
                    owners.len(),
                    binding.encoded_slot_count as usize,
                    "{name}: every encoded slot owns exactly one parameter binding"
                );
                for owner in owners {
                    // Known positions exist only when the encoded list length
                    // matches the prototype; otherwise every slot is Unknown.
                    assert_eq!(
                        owner.parameter_position_in_prototype.is_some(),
                        equal,
                        "{name}: known position exposed for an incomplete list"
                    );
                    if let Some(known) = owner.parameter_position_in_prototype {
                        let ordinal = owner.parameter_ordinal.expect("slot ordinal");
                        assert!(
                            known
                                && (ordinal as usize) < binding.prototype_parameter_count as usize,
                            "{name}: known position outside the prototype"
                        );
                    }
                }
            }
        }
        assert!(observed_complete > 0, "no complete list fixture observed");
        assert!(observed_unknown > 0, "no unknown list fixture observed");
        assert!(observed_unbound > 0, "no unbound ref-list fixture observed");
    }
    #[test]
    fn parameter_list_physical_counts_do_not_invent_positions() {
        let cases: [(&[u8], usize, usize, usize, Completeness); 4] = [
            (
                include_bytes!(
                    "../../../tests/fixtures/annotations/generated/parameter-empty-nonzero-proto.dex"
                ),
                0,
                2,
                2,
                Completeness::Unknown,
            ),
            (
                include_bytes!(
                    "../../../tests/fixtures/annotations/generated/parameter-long-nonzero-proto.dex"
                ),
                3,
                2,
                2,
                Completeness::Unknown,
            ),
            (
                include_bytes!(
                    "../../../tests/fixtures/annotations/generated/parameter-empty-zero-proto.dex"
                ),
                0,
                0,
                2,
                Completeness::Complete,
            ),
            (
                include_bytes!(
                    "../../../tests/fixtures/annotations/generated/parameter-orphan-empty-no-binding.dex"
                ),
                0,
                0,
                0,
                Completeness::Unknown,
            ),
        ];
        for (bytes, slot_count, proto_count, binding_count, coverage) in cases {
            let facts = parse(bytes, AnnotationLimits::default()).unwrap();
            assert_eq!(facts.ref_lists.len(), 1);
            let list = &facts.ref_lists[0];
            assert_eq!(list.annotation_set_offsets.len(), slot_count);
            let start = list.byte_offset as usize;
            assert_eq!(
                u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap()) as usize,
                slot_count
            );
            assert_eq!(facts.parameter_lists.len(), binding_count);
            for binding in &facts.parameter_lists {
                assert!(binding.encoded_slots_complete);
                assert_eq!(binding.ref_list_byte_offset, list.byte_offset);
                assert_eq!(binding.encoded_slot_count as usize, slot_count);
                assert_eq!(binding.prototype_parameter_count as usize, proto_count);
                assert_eq!(binding.prototype_position_coverage, coverage);
            }
            let owners: Vec<_> = facts
                .owner_bindings
                .iter()
                .filter(|owner| owner.kind == AnnotationOwnerKind::Parameter)
                .collect();
            assert_eq!(owners.len(), slot_count * binding_count);
            for (owner_index, owner) in owners.iter().enumerate() {
                let ordinal = owner_index % slot_count;
                assert_eq!(owner.parameter_ordinal, Some(ordinal as u32));
                assert_eq!(
                    owner.annotation_set_offset,
                    list.annotation_set_offsets[ordinal]
                );
                assert_eq!(owner.parameter_position_in_prototype, None);
            }
            if slot_count == 3 {
                assert_eq!(list.annotation_set_offsets[1], None);
                assert_eq!(
                    list.annotation_set_offsets[0],
                    list.annotation_set_offsets[2]
                );
                assert!(list.annotation_set_offsets[0].is_some());
            }
        }
    }
    #[test]
    fn depth_nodes_and_bytes_fail_closed() {
        let bytes =
            include_bytes!("../../../tests/fixtures/annotations/generated/annotations-038.dex");
        for limits in [
            AnnotationLimits {
                max_depth: 0,
                ..AnnotationLimits::default()
            },
            AnnotationLimits {
                max_nodes: 0,
                ..AnnotationLimits::default()
            },
            AnnotationLimits {
                max_decoded_bytes: 0,
                ..AnnotationLimits::default()
            },
            AnnotationLimits {
                max_items: 0,
                ..AnnotationLimits::default()
            },
            AnnotationLimits {
                max_rows: 0,
                ..AnnotationLimits::default()
            },
        ] {
            assert_eq!(
                parse(bytes, limits).unwrap_err().code,
                ErrorCode::QuotaExceeded
            );
        }
    }

    #[test]
    fn every_physical_fixture_matches_independent_sdk_classification() {
        let manifest: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/annotations/manifest.json"
        ))
        .unwrap();
        let mut accepted = 0;
        let mut rejected = 0;
        for fixture in manifest["files"].as_array().unwrap() {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(fixture["path"].as_str().unwrap());
            let bytes = std::fs::read(path).unwrap();
            let result = parse(&bytes, AnnotationLimits::default());
            if fixture["expected"].as_str().unwrap().starts_with("valid_") {
                let data = result.unwrap_or_else(|error| panic!("{}: {error}", fixture["path"]));
                assert!(data.usage.physical_items > 0);
                accepted += 1;
            } else {
                let error = result.unwrap_err();
                assert_eq!(
                    error.code,
                    ErrorCode::InvalidInput,
                    "{}: {error}",
                    fixture["path"]
                );
                assert!(error.details.contains_key("byte_offset"));
                rejected += 1;
            }
        }
        assert_eq!((accepted, rejected), (13, 29));
    }

    #[test]
    fn embedded_value_components_enforce_progress_depth_and_nodes() {
        let bytes =
            include_bytes!("../../../tests/fixtures/annotations/generated/annotations-038.dex");
        let header = validate_header(bytes).unwrap();
        let strings = read_string_pool(bytes, &header, StringLimits::default()).unwrap();
        let (types, prototypes) = read_types_and_prototypes(bytes, &header, &strings).unwrap();
        let pools = DefinitionPools {
            strings: &strings,
            types: &types,
            prototypes: &prototypes,
        };
        let definitions =
            read_definitions(bytes, &header, &pools, DefinitionLimits::default()).unwrap();
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/annotations/component-vectors.json"
        ))
        .unwrap();
        for vector in vectors["vectors"].as_array().unwrap() {
            let hex = vector["hex"].as_str().unwrap();
            let raw = hex
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect::<Vec<_>>();
            let limits = AnnotationLimits {
                max_depth: vector["max_depth"].as_u64().unwrap_or(64) as u32,
                max_nodes: vector["max_nodes"].as_u64().unwrap_or(1000),
                ..AnnotationLimits::default()
            };
            let mut vector_header = header.clone();
            if let Some(version) = vector["version"].as_str() {
                vector_header.version = version.to_owned();
            }
            let mut parser = Parser {
                header: &vector_header,
                pools: &pools,
                definitions: &definitions,
                budget: Budget {
                    limits,
                    used: AnnotationUsage::default(),
                },
                values: Vec::new(),
                validated_names: BTreeSet::new(),
            };
            let mut cursor = Cursor::new(&raw, 0, raw.len() as u64);
            let result = parser.value(&mut cursor, 0, 0, None, None);
            if vector.get("reason").is_some() {
                let error = result.unwrap_err();
                let quota_case = vector["reason"].as_str().unwrap().contains("budget");
                assert_eq!(
                    error.code,
                    if quota_case {
                        ErrorCode::QuotaExceeded
                    } else {
                        ErrorCode::InvalidInput
                    },
                    "{}",
                    vector["id"]
                );
            } else {
                let id = result.unwrap();
                assert_eq!(
                    parser.values[id as usize].kind.as_str(),
                    vector["expected_kind"].as_str().unwrap()
                );
                assert_eq!(cursor.at, raw.len() as u64);
            }
        }
    }
}
