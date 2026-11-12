//! Encoded definitions over the same validated bytes and metadata pools.
use crate::{
    DexHeader, DexRange,
    checked_reader::{CheckedReader, invalid},
    strings::{DexString, DexText, read_uleb128},
    types::{DexPrototype, DexType, name_character, type_list_item_starts},
};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub trait DefinitionMetadata {
    fn string(&self, index: u32) -> Option<&DexString>;
    fn dex_type(&self, index: u32) -> Option<&DexType>;
    fn prototype(&self, index: u32) -> Option<&DexPrototype>;
}

pub struct DefinitionPools<'a> {
    pub strings: &'a [DexString],
    pub types: &'a [DexType],
    pub prototypes: &'a [DexPrototype],
}
impl DefinitionMetadata for DefinitionPools<'_> {
    fn string(&self, index: u32) -> Option<&DexString> {
        self.strings.get(index as usize)
    }
    fn dex_type(&self, index: u32) -> Option<&DexType> {
        self.types.get(index as usize)
    }
    fn prototype(&self, index: u32) -> Option<&DexPrototype> {
        self.prototypes.get(index as usize)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DefinitionLimits {
    pub max_rows: u64,
    pub max_text_bytes: u64,
}
impl Default for DefinitionLimits {
    fn default() -> Self {
        Self {
            max_rows: 16 * 1024 * 1024,
            max_text_bytes: 512 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Static,
    Instance,
}
impl FieldKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Instance => "instance",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodKind {
    Direct,
    Virtual,
}
impl MethodKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Virtual => "virtual",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldReference {
    pub field_idx: u32,
    pub class_idx: u32,
    pub type_idx: u32,
    pub name_idx: u32,
    pub class_descriptor: String,
    pub field_name: String,
    pub type_descriptor: String,
    pub descriptor: String,
    pub encoded_range: DexRange,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MethodReference {
    pub method_idx: u32,
    pub class_idx: u32,
    pub proto_idx: u32,
    pub name_idx: u32,
    pub class_descriptor: String,
    pub method_name: String,
    pub descriptor: String,
    pub return_descriptor: String,
    pub parameter_descriptors: Vec<String>,
    pub encoded_range: DexRange,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClassDefinition {
    pub class_def_idx: u32,
    pub class_idx: u32,
    pub descriptor: String,
    pub access_flags: u32,
    pub superclass_idx: Option<u32>,
    pub superclass_descriptor: Option<String>,
    pub source_file_idx: Option<u32>,
    pub source_file: Option<DexText>,
    pub annotations_byte_offset: Option<DecimalU64>,
    pub static_values_byte_offset: Option<DecimalU64>,
    pub class_data_range: Option<DexRange>,
    pub static_fields_count: u32,
    pub instance_fields_count: u32,
    pub direct_methods_count: u32,
    pub virtual_methods_count: u32,
    pub encoded_range: DexRange,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterfaceDefinition {
    pub class_def_idx: u32,
    pub class_idx: u32,
    pub ordinal: u32,
    pub interface_type_idx: u32,
    pub interface_descriptor: String,
    pub encoded_range: DexRange,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldDefinition {
    pub class_def_idx: u32,
    pub class_idx: u32,
    pub field_idx: u32,
    pub kind: FieldKind,
    pub ordinal: u32,
    pub access_flags: u32,
    pub encoded_range: DexRange,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum MethodBody {
    Abstract,
    Native,
    Present {
        code_byte_offset: DecimalU64,
        declared_insns_size: u32,
    },
}
impl MethodBody {
    pub fn state(&self) -> &'static str {
        match self {
            Self::Abstract => "abstract",
            Self::Native => "native",
            Self::Present { .. } => "present",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MethodDefinition {
    pub class_def_idx: u32,
    pub class_idx: u32,
    pub method_idx: u32,
    pub kind: MethodKind,
    pub ordinal: u32,
    pub access_flags: u32,
    pub body: MethodBody,
    pub encoded_range: DexRange,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DexDefinitions {
    pub field_references: Vec<FieldReference>,
    pub method_references: Vec<MethodReference>,
    pub classes: Vec<ClassDefinition>,
    pub interfaces: Vec<InterfaceDefinition>,
    pub field_definitions: Vec<FieldDefinition>,
    pub method_definitions: Vec<MethodDefinition>,
    pub validated_scope: String,
    pub unbuilt_layers: Vec<String>,
}

fn failure(reason: &str, offset: u64, length: u64) -> MddError {
    invalid(reason, "dex.definitions", offset, length)
}
fn range(offset: u64, length: u64) -> DexRange {
    DexRange {
        byte_offset: DecimalU64(offset),
        byte_length: DecimalU64(length),
    }
}
struct Budget {
    rows: u64,
    text: u64,
}
impl Budget {
    fn rows(&mut self, count: u64, at: u64) -> MddResult<()> {
        self.rows = self.rows.checked_sub(count).ok_or_else(|| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "dex.definitions",
                "definition row budget exceeded",
            )
            .detail("byte_offset", at.to_string())
            .detail("reason", "DEFINITION_ROW_BUDGET")
        })?;
        Ok(())
    }
    fn text(&mut self, count: usize, at: u64) -> MddResult<()> {
        self.text = self.text.checked_sub(count as u64).ok_or_else(|| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "dex.definitions",
                "definition text budget exceeded",
            )
            .detail("byte_offset", at.to_string())
            .detail("reason", "DEFINITION_TEXT_BUDGET")
        })?;
        Ok(())
    }
}
fn section(header: &DexHeader, kind: u16) -> Option<(u64, u64, u32)> {
    header
        .map
        .iter()
        .position(|m| m.type_code == kind)
        .map(|i| {
            (
                header.map[i].byte_offset.0,
                header.map.get(i + 1).map_or(
                    header.data_range.byte_offset.0 + header.data_range.byte_length.0,
                    |m| m.byte_offset.0,
                ),
                header.map[i].count,
            )
        })
}
fn section_range(
    header: &DexHeader,
    kind: u16,
    offset: u64,
    length: u64,
) -> MddResult<(u64, u64, u32)> {
    let (start, end, count) = section(header, kind).ok_or_else(|| {
        failure("MISSING_DEFINITION_SECTION", offset, length).detail("map_type", u64::from(kind))
    })?;
    if offset < start || offset.checked_add(length).is_none_or(|last| last > end) {
        return Err(failure("DEFINITION_OUTSIDE_SECTION", offset, length)
            .detail("map_type", u64::from(kind)));
    }
    Ok((start, end, count))
}
fn class_type<M: DefinitionMetadata>(
    pools: &M,
    index: u32,
    at: u64,
    arrays: bool,
) -> MddResult<&DexType> {
    let ty = pools
        .dex_type(index)
        .ok_or_else(|| failure("TYPE_INDEX_OUT_OF_RANGE", at, 4))?;
    if ty.shape.shorty != 'L' || (!arrays && ty.shape.array_dimensions != 0) {
        return Err(failure("INVALID_DEFINING_TYPE", at, 4).detail("type_idx", u64::from(index)));
    }
    Ok(ty)
}
/// Validate an identifier without materialising a `String`.
/// Accepts the optional `<...>` special-name wrapper exactly like the textual
/// check, and applies the same DEX class-name character rules, including
/// surrogate pairs for supplementary characters.
fn valid_member_text(text: &crate::strings::DexText, spaces_allowed: bool) -> bool {
    let units = &text.utf16_units;
    // The `<...>` wrapper must be balanced: the previous implementation stripped
    // `<` only together with a matching `>`, so a lone leading `<` stayed part of
    // the name and failed the character rules. Skipping `<` unconditionally would
    // silently admit malformed names such as `<init` or `<foo`.
    let wrapped = units.first() == Some(&u16::from(b'<')) && units.last() == Some(&u16::from(b'>'));
    let start = usize::from(wrapped);
    let end = units.len() - usize::from(wrapped);
    if end <= start {
        return false;
    }
    for ch in char::decode_utf16(units[start..end].iter().copied()) {
        let Ok(ch) = ch else {
            return false;
        };
        if ch == '/' || !name_character(ch, spaces_allowed) {
            return false;
        }
    }
    true
}

fn member_name<M: DefinitionMetadata>(
    pools: &M,
    index: u32,
    at: u64,
    version: &str,
) -> MddResult<String> {
    let text = pools
        .string(index)
        .ok_or_else(|| failure("MEMBER_NAME_INDEX_OUT_OF_RANGE", at, 4))?;
    if !valid_member_text(&text.text, version >= "040") {
        // Keep the original error split: non-scalar text is a distinct reason.
        return Err(if text.text.strict_utf8().is_err() {
            failure("NON_SCALAR_MEMBER_NAME", at, 4)
        } else {
            failure("INVALID_MEMBER_NAME", at, 4)
        });
    }
    text.text
        .strict_utf8()
        .map_err(|_| failure("NON_SCALAR_MEMBER_NAME", at, 4))
}

/// Mark one field_id as defined. Returns true when it was already defined.
fn defined_field_set(bits: &mut [u8], index: u32) -> bool {
    let Some(slot) = bits.get_mut(index as usize / 8) else {
        return true;
    };
    let mask = 1u8 << (index % 8);
    let seen = *slot & mask != 0;
    *slot |= mask;
    seen
}

/// Mark one method_id as defined. Returns true when it was already defined.
fn defined_method_set(bits: &mut [u8], index: u32) -> bool {
    let Some(slot) = bits.get_mut(index as usize / 8) else {
        return true;
    };
    let mask = 1u8 << (index % 8);
    let seen = *slot & mask != 0;
    *slot |= mask;
    seen
}

struct Encoded<'a> {
    bytes: &'a [u8],
    cursor: u64,
    end: u64,
}
impl Encoded<'_> {
    fn read(&mut self) -> MddResult<u32> {
        let (n, len) = read_uleb128(self.bytes, self.cursor, self.end)?;
        self.cursor = self
            .cursor
            .checked_add(len)
            .ok_or_else(|| failure("ENCODED_OFFSET_OVERFLOW", self.cursor, len))?;
        Ok(n)
    }
}

fn class_data_starts(
    bytes: &[u8],
    header: &DexHeader,
    max_rows: u64,
    fields: &[FieldReference],
    methods: &[MethodReference],
    declared_classes: &[Option<u32>],
) -> MddResult<Vec<(u64, u64, [u32; 4])>> {
    let Some((start, end, count)) = section(header, 0x2000) else {
        return Ok(Vec::new());
    };
    let mut budget = Budget {
        rows: max_rows,
        text: 0,
    };
    budget.rows(u64::from(count), start)?;
    let mut encoded = Encoded {
        bytes,
        cursor: start,
        end,
    };
    let mut items = Vec::new();
    items
        .try_reserve_exact(count as usize)
        .map_err(|_| failure("CLASS_DATA_ALLOCATION_BUDGET", start, u64::from(count)))?;
    for _ in 0..count {
        let at = encoded.cursor;
        let counts = [
            encoded.read()?,
            encoded.read()?,
            encoded.read()?,
            encoded.read()?,
        ];
        let field_count = u64::from(counts[0]) + u64::from(counts[1]);
        let method_count = u64::from(counts[2]) + u64::from(counts[3]);
        budget.rows(field_count + method_count, at)?;
        let minimum = field_count * 2 + method_count * 3;
        if encoded
            .cursor
            .checked_add(minimum)
            .is_none_or(|last| last > end)
        {
            return Err(failure(
                "TRUNCATED_CLASS_DATA_LAYOUT",
                at,
                end.saturating_sub(at),
            ));
        }
        let mut owner = None;
        // Both encoded lists are strictly increasing by construction (a zero
        // delta is rejected), so cross-list duplicates are found by binary
        // searching the already-decoded static run instead of allocating a set
        // per class.
        let mut static_indices = Vec::new();
        for (kind, count) in [
            (FieldKind::Static, counts[0]),
            (FieldKind::Instance, counts[1]),
        ] {
            let mut previous = 0u32;
            for ordinal in 0..count {
                let at = encoded.cursor;
                let delta = encoded.read()?;
                let flags = encoded.read()?;
                if ordinal > 0 && delta == 0 {
                    return Err(failure("DUPLICATE_FIELD_INDEX", at, encoded.cursor - at));
                }
                let index = previous
                    .checked_add(delta)
                    .ok_or_else(|| failure("FIELD_DELTA_OVERFLOW", at, encoded.cursor - at))?;
                let reference = fields
                    .get(index as usize)
                    .ok_or_else(|| failure("FIELD_INDEX_OUT_OF_RANGE", at, encoded.cursor - at))?;
                if kind == FieldKind::Instance && static_indices.binary_search(&index).is_ok() {
                    return Err(failure(
                        "DUPLICATE_FIELD_DEFINITION",
                        at,
                        encoded.cursor - at,
                    ));
                }
                if kind == FieldKind::Static {
                    static_indices.push(index);
                }
                if (flags & 8 != 0) != (kind == FieldKind::Static) {
                    return Err(failure(
                        "FIELD_KIND_FLAGS_MISMATCH",
                        at,
                        encoded.cursor - at,
                    ));
                }
                if owner.is_some_and(|value| value != reference.class_idx) {
                    return Err(failure("FIELD_OWNER_MISMATCH", at, encoded.cursor - at));
                }
                owner = Some(reference.class_idx);
                previous = index;
            }
        }
        let mut direct_indices = Vec::new();
        for (kind, count) in [
            (MethodKind::Direct, counts[2]),
            (MethodKind::Virtual, counts[3]),
        ] {
            let mut previous = 0u32;
            for ordinal in 0..count {
                let at = encoded.cursor;
                let delta = encoded.read()?;
                let flags = encoded.read()?;
                let code = u64::from(encoded.read()?);
                if ordinal > 0 && delta == 0 {
                    return Err(failure("DUPLICATE_METHOD_INDEX", at, encoded.cursor - at));
                }
                let index = previous
                    .checked_add(delta)
                    .ok_or_else(|| failure("METHOD_DELTA_OVERFLOW", at, encoded.cursor - at))?;
                let reference = methods
                    .get(index as usize)
                    .ok_or_else(|| failure("METHOD_INDEX_OUT_OF_RANGE", at, encoded.cursor - at))?;
                if direct_indices.last() == Some(&index)
                    || (kind == MethodKind::Virtual && direct_indices.binary_search(&index).is_ok())
                {
                    return Err(failure(
                        "DUPLICATE_METHOD_DEFINITION",
                        at,
                        encoded.cursor - at,
                    ));
                }
                if kind == MethodKind::Direct {
                    direct_indices.push(index);
                }
                if (flags & (8 | 2 | 0x10000) != 0) != (kind == MethodKind::Direct) {
                    return Err(failure(
                        "METHOD_KIND_FLAGS_MISMATCH",
                        at,
                        encoded.cursor - at,
                    ));
                }
                if owner.is_some_and(|value| value != reference.class_idx) {
                    return Err(failure("METHOD_OWNER_MISMATCH", at, encoded.cursor - at));
                }
                let abstract_method = flags & 0x400 != 0;
                let native_method = flags & 0x100 != 0;
                if abstract_method && native_method {
                    return Err(failure("CONFLICTING_METHOD_FLAGS", at, encoded.cursor - at));
                }
                if (abstract_method || native_method) && code != 0 {
                    return Err(failure(
                        "NATIVE_OR_ABSTRACT_HAS_CODE",
                        at,
                        encoded.cursor - at,
                    ));
                }
                if !abstract_method && !native_method {
                    if code == 0 {
                        return Err(failure(
                            "CONCRETE_METHOD_MISSING_CODE",
                            at,
                            encoded.cursor - at,
                        ));
                    }
                    if !code.is_multiple_of(4) {
                        return Err(failure("UNALIGNED_METHOD_CODE", code, 16));
                    }
                    section_range(header, 0x2001, code, 16)?;
                    CheckedReader::new(bytes).range(code, 16)?;
                }
                owner = Some(reference.class_idx);
                previous = index;
            }
        }
        if owner.is_some_and(|index| {
            declared_classes
                .get(index as usize)
                .copied()
                .flatten()
                .is_none()
        }) {
            return Err(failure(
                "NONEMPTY_CLASS_DATA_NO_DECLARING_CLASS",
                at,
                encoded.cursor - at,
            ));
        }
        items.push((at, encoded.cursor, counts));
    }
    Ok(items)
}

pub fn read_definitions<M: DefinitionMetadata>(
    bytes: &[u8],
    header: &DexHeader,
    pools: &M,
    limits: DefinitionLimits,
) -> MddResult<DexDefinitions> {
    let reader = CheckedReader::new(bytes);
    let mut budget = Budget {
        rows: limits.max_rows,
        text: limits.max_text_bytes,
    };
    let table = |name: &str| {
        header
            .tables
            .iter()
            .find(|t| t.name == name)
            .ok_or_else(|| failure("MISSING_DEFINITION_TABLE", 0, 0))
    };
    let fields = table("field_ids")?;
    let methods = table("method_ids")?;
    let classes = table("class_defs")?;
    budget.rows(
        u64::from(fields.count) + u64::from(methods.count) + u64::from(classes.count),
        0,
    )?;
    let physical_type_lists = type_list_item_starts(bytes, header)?;
    let mut field_references = Vec::new();
    field_references
        .try_reserve_exact(fields.count as usize)
        .map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "dex.definitions",
                "field reference allocation failed",
            )
        })?;
    let mut previous = None;
    for field_idx in 0..fields.count {
        let at = fields.range.byte_offset.0 + u64::from(field_idx) * 8;
        let class_idx = u32::from(reader.u16(at)?);
        let type_idx = u32::from(reader.u16(at + 2)?);
        let name_idx = reader.u32(at + 4)?;
        let key = (class_idx, name_idx, type_idx);
        if previous.is_some_and(|p| p >= key) {
            return Err(failure("FIELD_IDS_NOT_STRICT_ORDER", at, 8));
        }
        previous = Some(key);
        let owner = class_type(pools, class_idx, at, false)?;
        let ty = pools
            .dex_type(type_idx)
            .ok_or_else(|| failure("FIELD_TYPE_INDEX_OUT_OF_RANGE", at + 2, 2))?;
        if ty.shape.is_void {
            return Err(failure("VOID_FIELD_TYPE", at + 2, 2));
        }
        let name = member_name(pools, name_idx, at + 4, &header.version)?;
        budget.text(
            2 * (owner.descriptor.len() + name.len() + ty.descriptor.len()) + 3,
            at,
        )?;
        // Build the joined descriptor with one exact reservation: `format!` may
        // allocate through the formatting machinery and grow once.
        let mut descriptor =
            String::with_capacity(owner.descriptor.len() + name.len() + ty.descriptor.len() + 3);
        descriptor.push_str(&owner.descriptor);
        descriptor.push_str("->");
        descriptor.push_str(&name);
        descriptor.push(':');
        descriptor.push_str(&ty.descriptor);
        field_references.push(FieldReference {
            field_idx,
            class_idx,
            type_idx,
            name_idx,
            class_descriptor: owner.descriptor.clone(),
            field_name: name,
            type_descriptor: ty.descriptor.clone(),
            descriptor,
            encoded_range: range(at, 8),
        });
    }
    let mut method_references = Vec::new();
    method_references
        .try_reserve_exact(methods.count as usize)
        .map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "dex.definitions",
                "method reference allocation failed",
            )
        })?;
    let mut previous = None;
    for method_idx in 0..methods.count {
        let at = methods.range.byte_offset.0 + u64::from(method_idx) * 8;
        let class_idx = u32::from(reader.u16(at)?);
        let proto_idx = u32::from(reader.u16(at + 2)?);
        let name_idx = reader.u32(at + 4)?;
        let key = (class_idx, name_idx, proto_idx);
        if previous.is_some_and(|p| p >= key) {
            return Err(failure("METHOD_IDS_NOT_STRICT_ORDER", at, 8));
        }
        previous = Some(key);
        let owner = class_type(pools, class_idx, at, true)?;
        let proto = pools
            .prototype(proto_idx)
            .ok_or_else(|| failure("METHOD_PROTO_INDEX_OUT_OF_RANGE", at + 2, 2))?;
        let result = pools
            .dex_type(proto.return_type_idx)
            .ok_or_else(|| failure("METHOD_RETURN_TYPE_OUT_OF_RANGE", at + 2, 2))?;
        let name = member_name(pools, name_idx, at + 4, &header.version)?;
        let mut parameters = Vec::new();
        parameters
            .try_reserve_exact(proto.parameter_type_indices.len())
            .map_err(|_| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "dex.definitions",
                    "method parameter allocation failed",
                )
            })?;
        budget.rows(proto.parameter_type_indices.len() as u64, at)?;
        budget.text(
            2 * owner.descriptor.len()
                + 2 * name.len()
                + proto.descriptor.len()
                + 2
                + result.descriptor.len(),
            at,
        )?;
        for index in &proto.parameter_type_indices {
            let ty = pools
                .dex_type(*index)
                .ok_or_else(|| failure("METHOD_PARAMETER_TYPE_OUT_OF_RANGE", at, 8))?;
            budget.text(ty.descriptor.len(), at)?;
            parameters.push(ty.descriptor.clone());
        }
        let mut descriptor =
            String::with_capacity(owner.descriptor.len() + name.len() + proto.descriptor.len() + 2);
        descriptor.push_str(&owner.descriptor);
        descriptor.push_str("->");
        descriptor.push_str(&name);
        descriptor.push_str(&proto.descriptor);
        method_references.push(MethodReference {
            method_idx,
            class_idx,
            proto_idx,
            name_idx,
            class_descriptor: owner.descriptor.clone(),
            method_name: name,
            descriptor,
            return_descriptor: result.descriptor.clone(),
            parameter_descriptors: parameters,
            encoded_range: range(at, 8),
        });
    }
    let mut class_definitions = Vec::new();
    class_definitions
        .try_reserve_exact(classes.count as usize)
        .map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "dex.definitions",
                "class definition allocation failed",
            )
        })?;
    let mut interfaces = Vec::new();
    // Dense type_idx -> class_def_idx table replaces the ordered map so the
    // duplicate check, the dependency order check and the class-data owner
    // check are all one indexed lookup instead of a tree traversal.
    let type_count = header
        .tables
        .iter()
        .find(|table| table.name == "type_ids")
        .map_or(0u32, |table| table.count);
    let mut positions: Vec<Option<u32>> = Vec::new();
    positions
        .try_reserve_exact(type_count as usize)
        .map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "dex.definitions",
                "class position index allocation failed",
            )
        })?;
    positions.resize(type_count as usize, None);
    let mut class_data_offsets = Vec::new();
    for class_def_idx in 0..classes.count {
        let at = classes.range.byte_offset.0 + u64::from(class_def_idx) * 32;
        let class_idx = reader.u32(at)?;
        let ty = class_type(pools, class_idx, at, false)?;
        let slot = positions
            .get_mut(class_idx as usize)
            .ok_or_else(|| failure("TYPE_INDEX_OUT_OF_RANGE", at, 4))?;
        if slot.replace(class_def_idx).is_some() {
            return Err(failure("DUPLICATE_CLASS_DEFINITION", at, 32)
                .detail("class_idx", u64::from(class_idx)));
        }
        let flags = reader.u32(at + 4)?;
        let superclass = reader.u32(at + 8)?;
        let interfaces_off = reader.u32(at + 12)?;
        let source_file_idx = reader.u32(at + 16)?;
        let annotations_off = reader.u32(at + 20)?;
        let class_data_off = reader.u32(at + 24)?;
        let static_values_off = reader.u32(at + 28)?;
        let superclass_idx = (superclass != u32::MAX).then_some(superclass);
        let superclass_type = superclass_idx
            .map(|i| class_type(pools, i, at + 8, false))
            .transpose()?;
        let source_file_idx = (source_file_idx != u32::MAX).then_some(source_file_idx);
        let source_text = source_file_idx
            .map(|i| {
                pools
                    .string(i)
                    .map(|s| &s.text)
                    .ok_or_else(|| failure("SOURCE_FILE_INDEX_OUT_OF_RANGE", at + 16, 4))
            })
            .transpose()?;
        budget.text(
            ty.descriptor.len()
                + superclass_type.map_or(0, |t| t.descriptor.len())
                + source_text.map_or(0, |s| s.raw_mutf8.len() + s.utf16_units.len() * 2),
            at,
        )?;
        let superclass_descriptor = superclass_type.map(|t| t.descriptor.clone());
        let source_file = source_text.cloned();
        if interfaces_off != 0 {
            let offset = u64::from(interfaces_off);
            section_range(header, 0x1001, offset, 4)?;
            if physical_type_lists.binary_search(&offset).is_err() {
                return Err(failure("INTERFACE_LIST_NOT_ITEM_START", offset, 4));
            }
            if !offset.is_multiple_of(4) {
                return Err(failure("UNALIGNED_INTERFACE_LIST", offset, 4));
            }
            let count = reader.u32(offset)?;
            budget.rows(u64::from(count), offset)?;
            reader.array(offset + 4, u64::from(count), 2)?;
            section_range(header, 0x1001, offset, 4 + u64::from(count) * 2)?;
            let mut seen = BTreeSet::new();
            for ordinal in 0..count {
                let item = offset + 4 + u64::from(ordinal) * 2;
                let index = u32::from(reader.u16(item)?);
                if !seen.insert(index) {
                    return Err(failure("DUPLICATE_INTERFACE", item, 2));
                }
                let interface = class_type(pools, index, item, false)?;
                budget.text(interface.descriptor.len(), item)?;
                interfaces.push(InterfaceDefinition {
                    class_def_idx,
                    class_idx,
                    ordinal,
                    interface_type_idx: index,
                    interface_descriptor: interface.descriptor.clone(),
                    encoded_range: range(item, 2),
                });
            }
        }
        class_data_offsets.push(class_data_off);
        class_definitions.push(ClassDefinition {
            class_def_idx,
            class_idx,
            descriptor: ty.descriptor.clone(),
            access_flags: flags,
            superclass_idx,
            superclass_descriptor,
            source_file_idx,
            source_file,
            annotations_byte_offset: (annotations_off != 0)
                .then_some(DecimalU64(u64::from(annotations_off))),
            static_values_byte_offset: (static_values_off != 0)
                .then_some(DecimalU64(u64::from(static_values_off))),
            class_data_range: None,
            static_fields_count: 0,
            instance_fields_count: 0,
            direct_methods_count: 0,
            virtual_methods_count: 0,
            encoded_range: range(at, 32),
        });
    }
    let mut interface_cursor = 0;
    for class in &class_definitions {
        let first = interface_cursor;
        while interfaces
            .get(interface_cursor)
            .is_some_and(|i| i.class_def_idx == class.class_def_idx)
        {
            interface_cursor += 1;
        }
        for dependency in class.superclass_idx.into_iter().chain(
            interfaces[first..interface_cursor]
                .iter()
                .map(|i| i.interface_type_idx),
        ) {
            if positions
                .get(dependency as usize)
                .copied()
                .flatten()
                .is_some_and(|position| position >= class.class_def_idx)
            {
                return Err(failure(
                    "CLASS_DEPENDENCY_ORDER",
                    class.encoded_range.byte_offset.0,
                    32,
                )
                .detail("class_idx", u64::from(class.class_idx))
                .detail("dependency_type_idx", u64::from(dependency)));
            }
        }
    }
    let physical_class_data = class_data_starts(
        bytes,
        header,
        limits.max_rows,
        &field_references,
        &method_references,
        &positions,
    )?;
    // The walk above already produced every item start and record count in
    // physical order, so the later pass looks items up in a sorted slice rather
    // than re-decoding counts and rebuilding a map.
    let mut field_definitions = Vec::new();
    field_definitions
        .try_reserve_exact(field_references.len())
        .map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "dex.definitions",
                "field definition allocation failed",
            )
        })?;
    let mut method_definitions = Vec::new();
    method_definitions
        .try_reserve_exact(method_references.len())
        .map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "dex.definitions",
                "method definition allocation failed",
            )
        })?;
    // One bit per field_id/method_id replaces a node-allocating ordered set:
    // definition identity is the id-table index, so membership is exact.
    let mut defined_fields = vec![0u8; field_references.len().div_ceil(8)];
    let mut defined_methods = vec![0u8; method_references.len().div_ceil(8)];
    let mut used_offsets = BTreeSet::new();
    let mut spans = Vec::new();
    for (class, offset) in class_definitions.iter_mut().zip(class_data_offsets) {
        if offset == 0 {
            continue;
        }
        let offset = u64::from(offset);
        let Ok(item) = physical_class_data.binary_search_by_key(&offset, |item| item.0) else {
            return Err(failure("CLASS_DATA_NOT_ITEM_START", offset, 4));
        };
        let counts = physical_class_data[item].2;
        let repeated_offset = !used_offsets.insert(offset);
        let (_, end, count) = section_range(header, 0x2000, offset, 4)?;
        if used_offsets.len() as u64 > u64::from(count) {
            return Err(failure("CLASS_DATA_MAP_COUNT_MISMATCH", offset, 4));
        }
        let mut encoded = Encoded {
            bytes,
            cursor: offset,
            end,
        };
        let _ = [
            encoded.read()?,
            encoded.read()?,
            encoded.read()?,
            encoded.read()?,
        ];
        if repeated_offset && counts.iter().any(|n| *n != 0) {
            return Err(failure(
                "SHARED_CLASS_DATA",
                offset,
                encoded.cursor - offset,
            ));
        }
        budget.rows(counts.iter().map(|n| u64::from(*n)).sum(), offset)?;
        class.static_fields_count = counts[0];
        class.instance_fields_count = counts[1];
        class.direct_methods_count = counts[2];
        class.virtual_methods_count = counts[3];
        for (kind, count) in [
            (FieldKind::Static, counts[0]),
            (FieldKind::Instance, counts[1]),
        ] {
            let mut previous = 0u32;
            for ordinal in 0..count {
                let at = encoded.cursor;
                let delta = encoded.read()?;
                let flags = encoded.read()?;
                if ordinal > 0 && delta == 0 {
                    return Err(failure("DUPLICATE_FIELD_INDEX", at, encoded.cursor - at));
                }
                let field_idx = previous
                    .checked_add(delta)
                    .ok_or_else(|| failure("FIELD_DELTA_OVERFLOW", at, encoded.cursor - at))?;
                let reference = field_references
                    .get(field_idx as usize)
                    .ok_or_else(|| failure("FIELD_INDEX_OUT_OF_RANGE", at, encoded.cursor - at))?;
                if reference.class_idx != class.class_idx {
                    return Err(failure("FIELD_OWNER_MISMATCH", at, encoded.cursor - at));
                }
                if defined_field_set(&mut defined_fields, field_idx) {
                    return Err(failure(
                        "DUPLICATE_FIELD_DEFINITION",
                        at,
                        encoded.cursor - at,
                    ));
                }
                if (flags & 8 != 0) != (kind == FieldKind::Static) {
                    return Err(failure(
                        "FIELD_KIND_FLAGS_MISMATCH",
                        at,
                        encoded.cursor - at,
                    ));
                }
                field_definitions.push(FieldDefinition {
                    class_def_idx: class.class_def_idx,
                    class_idx: class.class_idx,
                    field_idx,
                    kind,
                    ordinal,
                    access_flags: flags,
                    encoded_range: range(at, encoded.cursor - at),
                });
                previous = field_idx;
            }
        }
        for (kind, count) in [
            (MethodKind::Direct, counts[2]),
            (MethodKind::Virtual, counts[3]),
        ] {
            let mut previous = 0u32;
            for ordinal in 0..count {
                let at = encoded.cursor;
                let delta = encoded.read()?;
                let flags = encoded.read()?;
                let code_off = encoded.read()?;
                if ordinal > 0 && delta == 0 {
                    return Err(failure("DUPLICATE_METHOD_INDEX", at, encoded.cursor - at));
                }
                let method_idx = previous
                    .checked_add(delta)
                    .ok_or_else(|| failure("METHOD_DELTA_OVERFLOW", at, encoded.cursor - at))?;
                let reference = method_references
                    .get(method_idx as usize)
                    .ok_or_else(|| failure("METHOD_INDEX_OUT_OF_RANGE", at, encoded.cursor - at))?;
                if reference.class_idx != class.class_idx {
                    return Err(failure("METHOD_OWNER_MISMATCH", at, encoded.cursor - at));
                }
                if defined_method_set(&mut defined_methods, method_idx) {
                    return Err(failure(
                        "DUPLICATE_METHOD_DEFINITION",
                        at,
                        encoded.cursor - at,
                    ));
                }
                if (flags & (8 | 2 | 0x10000) != 0) != (kind == MethodKind::Direct) {
                    return Err(failure(
                        "METHOD_KIND_FLAGS_MISMATCH",
                        at,
                        encoded.cursor - at,
                    ));
                }
                let abstract_method = flags & 0x400 != 0;
                let native_method = flags & 0x100 != 0;
                if abstract_method && native_method {
                    return Err(failure("CONFLICTING_METHOD_FLAGS", at, encoded.cursor - at));
                }
                if (abstract_method || native_method) && code_off != 0 {
                    return Err(failure(
                        "NATIVE_OR_ABSTRACT_HAS_CODE",
                        at,
                        encoded.cursor - at,
                    ));
                }
                let body = if abstract_method {
                    MethodBody::Abstract
                } else if native_method {
                    MethodBody::Native
                } else {
                    if code_off == 0 {
                        return Err(failure(
                            "CONCRETE_METHOD_MISSING_CODE",
                            at,
                            encoded.cursor - at,
                        ));
                    }
                    let code = u64::from(code_off);
                    if !code.is_multiple_of(4) {
                        return Err(failure("UNALIGNED_METHOD_CODE", code, 16));
                    }
                    section_range(header, 0x2001, code, 16)?;
                    reader.range(code, 16)?;
                    MethodBody::Present {
                        code_byte_offset: DecimalU64(code),
                        declared_insns_size: reader.u32(code + 12)?,
                    }
                };
                method_definitions.push(MethodDefinition {
                    class_def_idx: class.class_def_idx,
                    class_idx: class.class_idx,
                    method_idx,
                    kind,
                    ordinal,
                    access_flags: flags,
                    body,
                    encoded_range: range(at, encoded.cursor - at),
                });
                previous = method_idx;
            }
        }
        class.class_data_range = Some(range(offset, encoded.cursor - offset));
        spans.push((offset, encoded.cursor));
    }
    spans.sort_unstable();
    if let Some(pair) = spans.windows(2).find(|p| p[0].1 > p[1].0 && p[0] != p[1]) {
        return Err(failure(
            "OVERLAPPING_CLASS_DATA",
            pair[1].0,
            pair[1].1 - pair[1].0,
        ));
    }
    Ok(DexDefinitions {
        field_references,
        method_references,
        classes: class_definitions,
        interfaces,
        field_definitions,
        method_definitions,
        validated_scope: "class-field-method-reference-and-definition-layout-v1".into(),
        unbuilt_layers: [
            "annotations",
            "static_initial_values",
            "code_layout",
            "references",
            "derived_analysis",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        strings::{StringLimits, read_string_pool},
        types::read_types_and_prototypes,
        validate_header,
    };
    use serde_json::{Value, json};
    use std::{fs, path::PathBuf};
    fn fixture(name: &str) -> Vec<u8> {
        fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/definitions/generated")
                .join(format!("{name}.dex")),
        )
        .unwrap()
    }
    fn decode(bytes: &[u8], limits: DefinitionLimits) -> MddResult<DexDefinitions> {
        let header = validate_header(bytes)?;
        let strings = read_string_pool(bytes, &header, StringLimits::default())?;
        let (types, prototypes) = read_types_and_prototypes(bytes, &header, &strings)?;
        read_definitions(
            bytes,
            &header,
            &DefinitionPools {
                strings: &strings,
                types: &types,
                prototypes: &prototypes,
            },
            limits,
        )
    }
    #[test]
    fn definitions_match_hand_semantic_expectations() {
        let expected: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/definitions/expected.json"
        ))
        .unwrap();
        let expected = &expected["definitions-035"];
        let d = decode(&fixture("definitions-035"), DefinitionLimits::default()).unwrap();
        assert_eq!(d.classes.len(), 4);
        assert_eq!(d.field_references.len(), 6);
        assert_eq!(d.field_definitions.len(), 5);
        assert_eq!(d.method_references.len(), 13);
        assert_eq!(d.method_definitions.len(), 10);
        assert_eq!(
            json!(d.classes.iter().map(|c| &c.descriptor).collect::<Vec<_>>()),
            expected["class_order"]
        );
        let mut fields: Vec<_> = d
            .field_definitions
            .iter()
            .map(|f| {
                json!([
                    d.field_references[f.field_idx as usize].descriptor,
                    f.kind.as_str(),
                    f.ordinal,
                    f.access_flags
                ])
            })
            .collect();
        fields.sort_by_key(|v| v[0].as_str().unwrap().to_owned());
        assert_eq!(json!(fields), expected["fields"]);
        let mut methods: Vec<_> = d
            .method_definitions
            .iter()
            .map(|m| {
                json!([
                    d.method_references[m.method_idx as usize].descriptor,
                    m.kind.as_str(),
                    m.ordinal,
                    m.access_flags,
                    m.body.state()
                ])
            })
            .collect();
        methods.sort_by_key(|v| v[0].as_str().unwrap().to_owned());
        assert_eq!(json!(methods), expected["methods"]);
        let interface_rows: Vec<_> = d
            .interfaces
            .iter()
            .map(|i| {
                json!([
                    d.classes[i.class_def_idx as usize].descriptor,
                    i.ordinal,
                    i.interface_descriptor
                ])
            })
            .collect();
        assert_eq!(json!(interface_rows), expected["interfaces"]);
        let supers: Vec<_> = d
            .classes
            .iter()
            .map(|c| json!([c.descriptor, c.superclass_descriptor]))
            .collect();
        assert_eq!(json!(supers), expected["superclasses"]);
        assert!(
            d.method_references
                .iter()
                .any(|r| r.class_descriptor.starts_with('['))
        );
        let only_fields: Vec<_> = d
            .field_references
            .iter()
            .filter(|r| {
                !d.field_definitions
                    .iter()
                    .any(|f| f.field_idx == r.field_idx)
            })
            .map(|r| r.descriptor.clone())
            .collect();
        assert_eq!(json!(only_fields), expected["reference_only_fields"]);
        let only_methods: Vec<_> = d
            .method_references
            .iter()
            .filter(|r| {
                !d.method_definitions
                    .iter()
                    .any(|f| f.method_idx == r.method_idx)
            })
            .map(|r| r.descriptor.clone())
            .collect();
        assert_eq!(json!(only_methods), expected["reference_only_methods"]);
        println!("MDD_DEFINITIONS {}", serde_json::to_string(&d).unwrap());
    }
    #[test]
    fn invalid_delta_owner_body_and_duplicate_layout_are_located() {
        let manifest: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/definitions/manifest.json"
        ))
        .unwrap();
        for case in manifest["files"].as_array().unwrap().iter().filter(|c| {
            c["expected"]
                .as_str()
                .unwrap()
                .bytes()
                .next()
                .unwrap()
                .is_ascii_uppercase()
        }) {
            let error = decode(
                &fixture(case["id"].as_str().unwrap()),
                DefinitionLimits::default(),
            )
            .err()
            .unwrap();
            assert_eq!(error.code, ErrorCode::InvalidInput, "{case}");
            assert_eq!(error.details["reason"], case["expected"], "{error:?}");
            assert!(error.details.contains_key("byte_offset"));
        }
    }
    #[test]
    fn present_zero_insns_is_not_no_body_and_empty_class_data_is_explicit() {
        let d = decode(&fixture("zero-insns-present"), DefinitionLimits::default()).unwrap();
        let member = d
            .method_references
            .iter()
            .find(|m| m.method_name == "privateCall")
            .unwrap();
        let def = d
            .method_definitions
            .iter()
            .find(|m| m.method_idx == member.method_idx)
            .unwrap();
        assert!(matches!(
            def.body,
            MethodBody::Present {
                declared_insns_size: 0,
                ..
            }
        ));
        let d = decode(&fixture("empty-class-data"), DefinitionLimits::default()).unwrap();
        let class = &d.classes[0];
        assert!(class.class_data_range.is_some());
        assert_eq!(class.direct_methods_count + class.virtual_methods_count, 0);
        assert_eq!(
            decode(
                &fixture("definitions-035"),
                DefinitionLimits {
                    max_rows: 0,
                    ..DefinitionLimits::default()
                }
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            decode(
                &fixture("definitions-035"),
                DefinitionLimits {
                    max_text_bytes: 0,
                    ..DefinitionLimits::default()
                }
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::QuotaExceeded
        );
    }
    #[test]
    fn standard_versions_and_lossless_source_file_keep_definition_semantics() {
        for version in ["035", "037", "038", "039", "040"] {
            let d = decode(
                &fixture(&format!("definitions-{version}")),
                DefinitionLimits::default(),
            )
            .unwrap();
            assert_eq!(d.classes.len(), 4);
            assert_eq!(d.field_definitions.len(), 5);
            assert_eq!(d.method_definitions.len(), 10);
        }
        let d = decode(
            &fixture("source-file-surrogate"),
            DefinitionLimits::default(),
        )
        .unwrap();
        let text = d
            .classes
            .iter()
            .find(|c| c.descriptor == "Lfixture/Base;")
            .unwrap()
            .source_file
            .as_ref()
            .unwrap();
        assert_eq!(text.utf16_units, [0xd800]);
        assert!(text.strict_utf8().is_err());
        let d = decode(
            &fixture("shared-empty-class-data"),
            DefinitionLimits::default(),
        )
        .unwrap();
        assert_eq!(
            d.classes[0].class_data_range.as_ref().unwrap().byte_offset,
            d.classes[1].class_data_range.as_ref().unwrap().byte_offset
        );
        assert_ne!(d.classes[0].class_idx, d.classes[1].class_idx);
        let d = decode(&fixture("nullable-root-class"), DefinitionLimits::default()).unwrap();
        assert_eq!(d.classes[0].descriptor, "Ljava/lang/Object;");
        assert!(d.classes[0].superclass_idx.is_none());
        assert!(d.classes[0].source_file.is_none());
        assert!(d.classes[0].class_data_range.is_none());
        let d = decode(
            &fixture("virtual-native-no-body"),
            DefinitionLimits::default(),
        )
        .unwrap();
        let member = d
            .method_references
            .iter()
            .find(|m| m.method_name == "virtualCall")
            .unwrap();
        let method = d
            .method_definitions
            .iter()
            .find(|m| m.method_idx == member.method_idx)
            .unwrap();
        assert_eq!(method.kind, MethodKind::Virtual);
        assert!(matches!(method.body, MethodBody::Native));
    }
    #[test]
    fn physical_orphan_probe_reports_real_acceptance() {
        let names = [
            "orphan-empty",
            "orphan-field-valid",
            "orphan-field-defined-owner",
            "orphan-field-index",
            "orphan-field-flags",
            "orphan-method-valid",
            "orphan-method-defined-owner",
            "orphan-method-index",
            "orphan-method-delta",
            "orphan-method-kind",
        ];
        let observed: Vec<_> = names
            .into_iter()
            .map(|name| {
                let result = decode(&fixture(name), DefinitionLimits::default());
                json!({"fixture": name, "accepted": result.is_ok(), "error": result.err()})
            })
            .collect();
        println!(
            "MDD_ORPHAN_PROBE {}",
            serde_json::to_string(&observed).unwrap()
        );
        assert_eq!(
            observed
                .iter()
                .find(|r| r["fixture"] == "orphan-field-index")
                .unwrap()["accepted"],
            false
        );
    }
}
