//! Immutable source-bound annotation relations and ordered Signature fragments.
use crate::{
    definitions::DefinitionFacts,
    metadata::{EntityKind, EntityRef, MetadataSource},
};
use mdd_dex::annotations::{
    AnnotationItem, AnnotationLimits, AnnotationOwnerBinding, AnnotationOwnerKind, AnnotationSet,
    AnnotationSetRefList, CallSiteArrayBinding, DexAnnotations, EncodedArrayItem, EncodedKind,
    EncodedValue, ExactFloat, ParameterListBinding, read_annotations,
};
use mdd_dex::{
    definitions::{ClassDefinition, FieldKind, MethodDefinition, MethodKind, MethodReference},
    types::{DexPrototype, DexType},
};
use mdd_types::{Completeness, ErrorCode, MddError, MddResult, content_id};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AnnotationRef {
    pub snapshot_id: String,
    pub dex_occurrence_id: String,
    pub annotation_byte_offset: u32,
}

/// Physical collection identity; set items and set-reference lists are distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnotationCollectionKind {
    Set,
    SetRefList,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AnnotationCollectionRef {
    pub snapshot_id: String,
    pub dex_occurrence_id: String,
    pub byte_offset: u32,
    pub kind: AnnotationCollectionKind,
}
/// Borrowed physical collection and its exact bytes; no owner or parameter
/// position semantics are inferred from a reference-list slot.
pub enum AnnotationCollectionView<'a> {
    Set {
        source: &'a MetadataSource,
        item: &'a AnnotationSet,
        raw_encoded: &'a [u8],
    },
    SetRefList {
        source: &'a MetadataSource,
        item: &'a AnnotationSetRefList,
        raw_encoded: &'a [u8],
    },
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationOwnerRef {
    pub kind: AnnotationOwnerKind,
    pub reference: EntityRef,
    pub definition: Option<EntityRef>,
    pub parameter_ordinal: Option<u32>,
}

/// Physical encoded-array identity within a captured DEX occurrence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EncodedArrayRef {
    pub snapshot_id: String,
    pub dex_occurrence_id: String,
    pub byte_offset: u32,
}

/// Physical array and value nodes, including nested values. No ownership,
/// field assignment, or runtime call-site semantics are inferred.
pub struct EncodedArrayView<'a> {
    pub source: &'a MetadataSource,
    pub array: &'a EncodedArrayItem,
    pub raw_encoded: &'a [u8],
    pub values: Vec<EncodedArrayValueFact<'a>>,
}
pub struct EncodedArrayValueFact<'a> {
    pub value: &'a EncodedValue,
    pub raw_encoded: &'a [u8],
}

/// A value-node identity bound to one physical array in one DEX occurrence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EncodedArrayValueRef {
    pub array: EncodedArrayRef,
    pub node_id: u32,
}

pub struct EncodedArrayValueView<'a> {
    pub source: &'a MetadataSource,
    pub array: &'a EncodedArrayItem,
    pub value: &'a EncodedValue,
    pub raw_encoded: &'a [u8],
}

/// A physical reference to an encoded array in the same DEX occurrence.
/// Static values describe only an encoded class binding; no field assignment,
/// type compatibility, or runtime bootstrap behavior is inferred.
pub enum EncodedArrayBinding<'a> {
    StaticValues(&'a ClassDefinition),
    CallSite(&'a CallSiteArrayBinding),
}

pub struct EncodedArrayBindings<'a> {
    pub source: &'a MetadataSource,
    pub array: &'a EncodedArrayItem,
    /// Classes appear in class-definition order, followed by call-site order.
    /// Each physical reference is retained even when multiple refer to one item.
    pub bindings: Vec<EncodedArrayBinding<'a>>,
}

/// Identity of an encoded call_site_id within a captured DEX occurrence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EncodedCallSiteRef {
    pub snapshot_id: String,
    pub dex_occurrence_id: String,
    pub call_site_idx: u32,
}

/// One encoded call-site binding and its physical array. Bootstrap resolution
/// and the runtime callee remain unknown.
pub struct EncodedCallSiteView<'a> {
    pub source: &'a MetadataSource,
    pub binding: &'a CallSiteArrayBinding,
    pub array: &'a EncodedArrayItem,
    pub raw_encoded: &'a [u8],
}

/// Logical entry-visit and result bounds for a physical annotation value view.
/// These do not represent allocation, byte-scan, cancellation, or RSS limits.
#[derive(Clone, Copy, Debug)]
pub struct AnnotationValueViewLimits {
    pub max_scanned_entries: u64,
    pub max_values: u64,
}
impl Default for AnnotationValueViewLimits {
    fn default() -> Self {
        Self {
            max_scanned_entries: 32_000_000,
            max_values: 8_000_000,
        }
    }
}

/// One physical value node in an immutable annotation item. `raw_encoded`
/// includes the value header and its full validated encoded payload; children
/// retain their own entries and ranges. `kind` determines NULL semantics.
pub struct AnnotationValueFact<'a> {
    pub source: &'a MetadataSource,
    pub annotation: &'a AnnotationItem,
    pub value: &'a EncodedValue,
    pub raw_encoded: &'a [u8],
}

/// Bounds for reverse physical annotation-owner lookup. They count logical
/// visits and returned entries, not bytes, allocator overhead, or RSS.
#[derive(Clone, Copy, Debug)]
pub struct AnnotationOwnerViewLimits {
    pub max_scanned_entries: u64,
    pub max_matches: u64,
}
impl Default for AnnotationOwnerViewLimits {
    fn default() -> Self {
        Self {
            max_scanned_entries: 32_000_000,
            max_matches: 4_000_000,
        }
    }
}

/// Logical scan and result bounds for borrowed owner-signature lookup.
/// These do not bound allocation, elapsed time, cancellation, or process RSS.
#[derive(Clone, Copy, Debug)]
pub struct SignatureViewLimits {
    pub max_scanned_entries: u64,
    pub max_matches: u64,
}
impl Default for SignatureViewLimits {
    fn default() -> Self {
        Self {
            max_scanned_entries: 32_000_000,
            max_matches: 4_000_000,
        }
    }
}

/// One encoded owner/set/item occurrence within one DEX occurrence. Parameter
/// ordinals are encoded slots; `owner.parameter_position_in_prototype` retains
/// whether that slot is proven to correspond to a prototype position.
pub struct AnnotationOwnerFact<'a> {
    pub source: &'a MetadataSource,
    pub owner: &'a AnnotationOwnerBinding,
    pub set: &'a AnnotationSet,
    pub annotation: &'a AnnotationItem,
    pub set_ordinal: u32,
}

/// One encoded owner binding and its physical annotation entries. An absent
/// set is an explicit zero offset; a present set can contain no entries.
/// Parameter ordinals refer only to encoded slots, not necessarily prototype
/// positions. An absent binding does not prove runtime annotation absence.
pub struct OwnerAnnotationFacts<'a> {
    pub source: &'a MetadataSource,
    pub owner: &'a AnnotationOwnerBinding,
    pub set: Option<&'a AnnotationSet>,
    pub annotations: Vec<AnnotationOwnerFact<'a>>,
}

/// Logical limits for a single method's borrowed parameter view, not an RSS bound.
#[derive(Clone, Copy, Debug)]
pub struct ParameterViewLimits {
    pub max_scan_entries: u64,
    pub max_parameters: u64,
}
impl Default for ParameterViewLimits {
    fn default() -> Self {
        Self {
            max_scan_entries: 16_000_000,
            max_parameters: 1_000_000,
        }
    }
}

/// Physical annotation encoding for one proven prototype position in this DEX occurrence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterAnnotationEncoding {
    /// No parameter annotation list was encoded for this method in this occurrence.
    NoEncodedList,
    /// An encoded list explicitly contains the zero annotation-set offset.
    ExplicitZeroSlot,
    /// An encoded list names a validated physical annotation-set start.
    SetOffset(u32),
}
pub struct ParameterFact<'a> {
    pub ordinal: u32,
    pub parameter_type: &'a DexType,
    pub annotation_encoding: ParameterAnnotationEncoding,
}
/// Borrowed, same-occurrence parameter facts. No raw text encoding or inferred
/// annotations in another DEX are implied by this view.
pub struct MethodParameterFacts<'a> {
    facts: &'a AnnotationFacts,
    pub method_reference: &'a MethodReference,
    pub definition: Option<&'a MethodDefinition>,
    pub prototype: &'a DexPrototype,
    pub encoded_list: Option<&'a AnnotationSetRefList>,
}

/// An encoded method-to-list binding and physical bytes from one DEX occurrence.
/// Slots are physical list positions, not necessarily prototype positions;
/// consult `binding.prototype_position_coverage` before interpreting them.
pub struct EncodedParameterListFact<'a> {
    pub source: &'a MetadataSource,
    pub method_reference: &'a MethodReference,
    pub definition: Option<&'a MethodDefinition>,
    pub binding: &'a ParameterListBinding,
    pub list: &'a AnnotationSetRefList,
    pub raw_encoded: &'a [u8],
}

/// One encoded list slot, not a proven prototype parameter position.
/// `set == None` is an explicit zero offset; a present empty set remains
/// `Some` and is not collapsed into an empty or missing list.
pub struct EncodedParameterSlotFact<'a> {
    pub ordinal: u32,
    pub set: Option<&'a AnnotationSet>,
}

/// Borrowed slots for one physical method-to-list binding in one occurrence.
/// The binding's coverage must be consulted before interpreting positions.
pub struct EncodedParameterSlots<'a> {
    pub source: &'a MetadataSource,
    pub binding: &'a ParameterListBinding,
    pub list: &'a AnnotationSetRefList,
    sets: &'a [AnnotationSet],
    bytes: &'a [u8],
}

impl<'a> EncodedParameterSlots<'a> {
    /// Iterate encoded slots in order, retaining duplicates and explicit zeros.
    /// The construction bound applies to each complete iterator pass.
    pub fn iter(&self) -> impl Iterator<Item = MddResult<EncodedParameterSlotFact<'a>>> + '_ {
        self.list
            .annotation_set_offsets
            .iter()
            .enumerate()
            .map(move |(ordinal, offset)| {
                let broken = || {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.parameters",
                        "validated parameter set identity is inconsistent",
                    )
                };
                let set = match offset {
                    None => None,
                    Some(offset) => {
                        let mut matches = self.sets.iter().filter(|set| set.byte_offset == *offset);
                        let set = matches.next().ok_or_else(broken)?;
                        if matches.next().is_some()
                            || set.encoded_range.byte_offset.0 != u64::from(*offset)
                        {
                            return Err(broken());
                        }
                        let start = usize::try_from(set.encoded_range.byte_offset.0)
                            .map_err(|_| broken())?;
                        let end = set
                            .encoded_range
                            .byte_offset
                            .0
                            .checked_add(set.encoded_range.byte_length.0)
                            .and_then(|value| usize::try_from(value).ok())
                            .ok_or_else(broken)?;
                        if self.bytes.get(start..end).is_none() {
                            return Err(broken());
                        }
                        Some(set)
                    }
                };
                Ok(EncodedParameterSlotFact {
                    ordinal: u32::try_from(ordinal).map_err(|_| broken())?,
                    set,
                })
            })
    }
}
impl<'a> MethodParameterFacts<'a> {
    pub fn source(&self) -> &'a MetadataSource {
        self.facts.source()
    }

    /// Iterate proven prototype positions in their original order.
    pub fn iter(&self) -> impl Iterator<Item = MddResult<ParameterFact<'a>>> + '_ {
        let facts: &'a AnnotationFacts = self.facts;
        let encoded_list = self.encoded_list;
        self.prototype
            .parameter_type_indices
            .iter()
            .enumerate()
            .map(move |(ordinal, index)| {
                let parameter_type = facts
                    .definitions
                    .metadata()
                    .types()
                    .get(*index as usize)
                    .map(|fact| &fact.data)
                    .ok_or_else(|| {
                        MddError::new(
                            ErrorCode::InternalFault,
                            "facts.parameters",
                            "validated parameter type is missing",
                        )
                    })?;
                let annotation_encoding = match encoded_list {
                    None => ParameterAnnotationEncoding::NoEncodedList,
                    Some(list) => {
                        match list.annotation_set_offsets.get(ordinal).ok_or_else(|| {
                            MddError::new(
                                ErrorCode::InternalFault,
                                "facts.parameters",
                                "validated parameter slot is missing",
                            )
                        })? {
                            None => ParameterAnnotationEncoding::ExplicitZeroSlot,
                            Some(offset) => ParameterAnnotationEncoding::SetOffset(*offset),
                        }
                    }
                };
                Ok(ParameterFact {
                    ordinal: u32::try_from(ordinal).map_err(|_| {
                        MddError::new(
                            ErrorCode::QuotaExceeded,
                            "facts.parameters",
                            "parameter ordinal overflow",
                        )
                    })?,
                    parameter_type,
                    annotation_encoding,
                })
            })
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct SignatureFact {
    pub annotation: AnnotationRef,
    pub owner: AnnotationOwnerRef,
    pub string_pool_id: String,
    pub parts: Vec<EntityRef>,
    pub utf16_units: Vec<u16>,
}

/// Interpretation of a Signature owner's encoded parameter slot. Unknown
/// never implies that the slot ordinal is a proven prototype position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureParameterPosition {
    NotParameter,
    Known { ordinal: u32 },
    Unknown { encoded_slot: u32 },
}

/// Separate logical limits for identity validation, physical owner lookup,
/// and method-to-list resolution. These are not allocation, CPU, or RSS limits.
#[derive(Clone, Copy, Debug)]
pub struct SignaturePositionLimits {
    pub max_signatures: u64,
    /// Maximum logical bytes examined while comparing Signature identities and
    /// contents; this is not allocator overhead, CPU time, or process RSS.
    pub max_identity_bytes: u64,
    pub owners: AnnotationOwnerViewLimits,
    pub parameters: ParameterViewLimits,
}

impl Default for SignaturePositionLimits {
    fn default() -> Self {
        Self {
            max_signatures: 4_000_000,
            max_identity_bytes: 128 * 1024 * 1024,
            owners: AnnotationOwnerViewLimits::default(),
            parameters: ParameterViewLimits::default(),
        }
    }
}

impl SignatureFact {
    pub fn strict_utf8(&self) -> Result<String, std::string::FromUtf16Error> {
        String::from_utf16(&self.utf16_units)
    }
}

// read_annotations walks each physical section in strictly increasing offset
// order, including empty and unreferenced items. These searches reuse those
// validated starts without allocating a second offset index.
fn physical_annotation_set(data: &DexAnnotations, offset: u32) -> MddResult<&AnnotationSet> {
    data.sets
        .binary_search_by_key(&offset, |item| item.byte_offset)
        .ok()
        .and_then(|index| data.sets.get(index))
        .ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.annotations",
                "validated annotation set start is missing",
            )
        })
}

fn physical_annotation_item(data: &DexAnnotations, offset: u32) -> MddResult<&AnnotationItem> {
    data.annotation_items
        .binary_search_by_key(&offset, |item| item.byte_offset)
        .ok()
        .and_then(|index| data.annotation_items.get(index))
        .ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.annotations",
                "validated annotation item start is missing",
            )
        })
}

// read_annotations validates that every set entry points to a physical item
// and that their type indices are strictly increasing. Search those validated
// entries without building a per-owner index or coalescing shared owners.
fn physical_annotation_of_type<'a>(
    data: &'a DexAnnotations,
    set: &AnnotationSet,
    type_idx: u32,
) -> MddResult<Option<&'a AnnotationItem>> {
    let mut start = 0usize;
    let mut end = set.annotation_offsets.len();
    while start < end {
        let middle = start + (end - start) / 2;
        let item = physical_annotation_item(data, set.annotation_offsets[middle])?;
        if item.type_idx < type_idx {
            start = middle + 1;
        } else {
            end = middle;
        }
    }
    let Some(&offset) = set.annotation_offsets.get(start) else {
        return Ok(None);
    };
    let item = physical_annotation_item(data, offset)?;
    Ok((item.type_idx == type_idx).then_some(item))
}

#[derive(Clone, Serialize)]
/// Validated annotation facts expose only read-only getters.
/// ```compile_fail
/// fn alter(mut facts: mdd_facts::annotations::AnnotationFacts) { facts.data.values.clear(); }
/// ```
pub struct AnnotationFacts {
    definitions: DefinitionFacts,
    data: DexAnnotations,
    signatures: Vec<SignatureFact>,
    completed_layers: Vec<String>,
    unbuilt_layers: Vec<String>,
    annotation_coverage: Completeness,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnotationRelation {
    Directories,
    DirectoryEntries,
    SetEntries,
    SetRefs,
    Annotations,
    Elements,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationDirectoryRow {
    pub file_id: u32,
    pub class_idx: u32,
    pub annotations_off: u32,
    pub class_annotations_off: Option<u32>,
    pub fields_size: u32,
    pub methods_size: u32,
    pub parameters_size: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationDirectoryEntryRow {
    pub file_id: u32,
    pub class_idx: u32,
    pub annotations_off: u32,
    pub entry_kind: String,
    pub entry_idx: u32,
    pub annotation_set_off: Option<u32>,
    pub annotation_set_ref_list_off: Option<u32>,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationSetEntryRow {
    pub file_id: u32,
    pub annotation_set_off: u32,
    pub ordinal: u32,
    pub annotation_off: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationSetRefRow {
    pub file_id: u32,
    pub annotation_set_ref_list_off: u32,
    pub ordinal: u32,
    pub annotation_set_off: Option<u32>,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationRow {
    pub file_id: u32,
    pub annotation_off: u32,
    pub visibility: u32,
    pub type_idx: u32,
    pub element_count: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct AnnotationElementRow {
    pub file_id: u32,
    pub annotation_off: u32,
    pub depth: u32,
    pub ordinal: u32,
    pub name_idx: Option<u32>,
    pub value_off: u32,
    pub value_end_off: u32,
    pub value_kind: String,
    pub value_index: Option<u32>,
    pub value_i64: Option<String>,
    pub value_f64: Option<ExactFloat>,
}

fn invalid_definition_layout() -> MddError {
    MddError::new(
        ErrorCode::InternalFault,
        "facts.annotations",
        "validated Signature owner definition layout is inconsistent",
    )
}

// The DEX parser emits class groups in class_def order and each of the two
// encoded member lists in strictly increasing index order. Verify this once
// before using binary search; never treat corrupted layout as a missing owner.
fn validate_owner_groups<T>(
    classes: &[ClassDefinition],
    members: &[T],
    counts: impl Fn(&ClassDefinition) -> (u32, u32),
    identity: impl Fn(&T) -> (u32, u32, bool, u32, u32),
) -> MddResult<()> {
    let mut cursor = 0usize;
    for (class_index, class) in classes.iter().enumerate() {
        if u32::try_from(class_index).ok() != Some(class.class_def_idx) {
            return Err(invalid_definition_layout());
        }
        let (first, second) = counts(class);
        for (is_first, count) in [(true, first), (false, second)] {
            let end = cursor
                .checked_add(usize::try_from(count).map_err(|_| invalid_definition_layout())?)
                .ok_or_else(invalid_definition_layout)?;
            let slice = members
                .get(cursor..end)
                .ok_or_else(invalid_definition_layout)?;
            let mut previous = None;
            for (ordinal, member) in slice.iter().enumerate() {
                let (class_def, class_idx, actual_first, actual_ordinal, index) = identity(member);
                if class_def != class.class_def_idx
                    || class_idx != class.class_idx
                    || actual_first != is_first
                    || u32::try_from(ordinal).ok() != Some(actual_ordinal)
                    || previous.is_some_and(|prior| prior >= index)
                {
                    return Err(invalid_definition_layout());
                }
                previous = Some(index);
            }
            cursor = end;
        }
    }
    if cursor != members.len() {
        return Err(invalid_definition_layout());
    }
    Ok(())
}

fn validate_owner_definition_layout(definitions: &DefinitionFacts) -> MddResult<()> {
    let data = &definitions.definitions;
    validate_owner_groups(
        &data.classes,
        &data.field_definitions,
        |class| (class.static_fields_count, class.instance_fields_count),
        |field| {
            (
                field.class_def_idx,
                field.class_idx,
                field.kind == FieldKind::Static,
                field.ordinal,
                field.field_idx,
            )
        },
    )?;
    validate_owner_groups(
        &data.classes,
        &data.method_definitions,
        |class| (class.direct_methods_count, class.virtual_methods_count),
        |method| {
            (
                method.class_def_idx,
                method.class_idx,
                method.kind == MethodKind::Direct,
                method.ordinal,
                method.method_idx,
            )
        },
    )
}

fn owner_has_definition(
    definitions: &DefinitionFacts,
    owner: &AnnotationOwnerBinding,
) -> MddResult<bool> {
    let data = &definitions.definitions;
    let class = data
        .classes
        .get(owner.class_def_idx as usize)
        .ok_or_else(invalid_definition_layout)?;
    if class.class_def_idx != owner.class_def_idx || class.class_idx != owner.class_idx {
        return Err(invalid_definition_layout());
    }
    match owner.kind {
        AnnotationOwnerKind::Class => {
            if owner.local_index != owner.class_def_idx {
                return Err(invalid_definition_layout());
            }
            Ok(true)
        }
        AnnotationOwnerKind::Field => {
            if data
                .field_references
                .get(owner.local_index as usize)
                .map(|r| r.class_idx)
                != Some(owner.class_idx)
            {
                return Err(invalid_definition_layout());
            }
            let members = &data.field_definitions;
            let first = members.partition_point(|f| f.class_def_idx < owner.class_def_idx);
            let middle = first
                .checked_add(class.static_fields_count as usize)
                .ok_or_else(invalid_definition_layout)?;
            let end = middle
                .checked_add(class.instance_fields_count as usize)
                .ok_or_else(invalid_definition_layout)?;
            let static_fields = members
                .get(first..middle)
                .ok_or_else(invalid_definition_layout)?;
            let instance_fields = members
                .get(middle..end)
                .ok_or_else(invalid_definition_layout)?;
            Ok(static_fields
                .binary_search_by_key(&owner.local_index, |f| f.field_idx)
                .is_ok()
                || instance_fields
                    .binary_search_by_key(&owner.local_index, |f| f.field_idx)
                    .is_ok())
        }
        _ => {
            if data
                .method_references
                .get(owner.local_index as usize)
                .map(|r| r.class_idx)
                != Some(owner.class_idx)
            {
                return Err(invalid_definition_layout());
            }
            let members = &data.method_definitions;
            let first = members.partition_point(|m| m.class_def_idx < owner.class_def_idx);
            let middle = first
                .checked_add(class.direct_methods_count as usize)
                .ok_or_else(invalid_definition_layout)?;
            let end = middle
                .checked_add(class.virtual_methods_count as usize)
                .ok_or_else(invalid_definition_layout)?;
            let direct = members
                .get(first..middle)
                .ok_or_else(invalid_definition_layout)?;
            let virtuals = members
                .get(middle..end)
                .ok_or_else(invalid_definition_layout)?;
            Ok(direct
                .binary_search_by_key(&owner.local_index, |m| m.method_idx)
                .is_ok()
                || virtuals
                    .binary_search_by_key(&owner.local_index, |m| m.method_idx)
                    .is_ok())
        }
    }
}

fn owner_ref(
    definitions: &DefinitionFacts,
    owner: &AnnotationOwnerBinding,
    has_definition: bool,
) -> MddResult<AnnotationOwnerRef> {
    let kind = match owner.kind {
        AnnotationOwnerKind::Class => EntityKind::ClassDefinition,
        AnnotationOwnerKind::Field => EntityKind::FieldReference,
        _ => EntityKind::MethodReference,
    };
    let reference = definitions.entity(kind, owner.local_index)?;
    let definition = match owner.kind {
        AnnotationOwnerKind::Class => Some(reference.clone()),
        AnnotationOwnerKind::Field => has_definition.then(|| EntityRef {
            kind: EntityKind::FieldDefinition,
            ..reference.clone()
        }),
        _ => has_definition.then(|| EntityRef {
            kind: EntityKind::MethodDefinition,
            ..reference.clone()
        }),
    };
    Ok(AnnotationOwnerRef {
        kind: owner.kind,
        reference,
        definition,
        parameter_ordinal: owner.parameter_ordinal,
    })
}

impl AnnotationFacts {
    pub fn build(definitions: DefinitionFacts, limits: AnnotationLimits) -> MddResult<Self> {
        let source = &definitions.metadata.source;
        let bind = |error: MddError| {
            error
                .detail("snapshot_id", source.snapshot_id.clone())
                .detail("dex_occurrence_id", source.dex_occurrence_id.clone())
                .detail("member_id", source.member_id.clone())
                .detail("content_id", source.content_id.clone())
        };
        if definitions.definition_coverage != Completeness::Complete {
            return Err(bind(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.annotations",
                "complete validated definitions required",
            )));
        }
        if content_id(definitions.bytes()) != source.content_id {
            return Err(bind(MddError::new(
                ErrorCode::InternalFault,
                "facts.annotations",
                "held bytes differ from captured source",
            )));
        }
        let data = read_annotations(
            definitions.bytes(),
            &definitions.metadata.header,
            definitions.metadata.as_ref(),
            &definitions.definitions,
            limits,
        )
        .map_err(bind)?;
        let mut signatures = Vec::new();
        let mut remaining = limits
            .max_decoded_bytes
            .saturating_sub(data.usage.decoded_bytes);
        let mut owner_layout_validated = false;
        let signature_type = definitions
            .metadata
            .types
            .iter()
            .find(|item| item.data.descriptor == "Ldalvik/annotation/Signature;")
            .map(|item| item.data.type_idx);
        for owner in &data.owner_bindings {
            let Some(signature_type) = signature_type else {
                break;
            };
            let Some(set) = owner.annotation_set_offset else {
                continue;
            };
            let set = physical_annotation_set(&data, set).map_err(bind)?;
            if let Some(item) =
                physical_annotation_of_type(&data, set, signature_type).map_err(bind)?
            {
                let offset = item.byte_offset;
                let invalid = || {
                    bind(MddError::new(ErrorCode::InvalidInput,"facts.annotations","Signature requires one named value containing an array of string references").detail("reason","SIGNATURE_SHAPE").detail("byte_offset",offset.to_string()))
                };
                if item.elements.len() != 1 {
                    return Err(invalid());
                }
                let value = &data.values[item.elements[0] as usize];
                // The required ASCII name is exactly five UTF-16 units.
                // Comparing the captured units avoids allocating a UTF-8
                // copy of an arbitrarily long or invalid-surrogate name.
                let name_matches = value
                    .name_idx
                    .and_then(|index| definitions.metadata.strings.get(index as usize))
                    .is_some_and(|item| {
                        item.data.text.utf16_units.as_slice() == [0x76, 0x61, 0x6c, 0x75, 0x65]
                    });
                if !name_matches || value.kind != EncodedKind::Array {
                    return Err(invalid());
                }
                let mut total_units = 0u64;
                for node_id in &value.children {
                    let part = &data.values[*node_id as usize];
                    if part.kind != EncodedKind::String {
                        return Err(invalid());
                    }
                    let index = part.value_index.ok_or_else(invalid)?;
                    total_units = total_units
                        .checked_add(
                            definitions.metadata.strings[index as usize]
                                .data
                                .text
                                .utf16_units
                                .len() as u64,
                        )
                        .ok_or_else(|| {
                            bind(MddError::new(
                                ErrorCode::QuotaExceeded,
                                "facts.annotations",
                                "Signature size overflow",
                            ))
                        })?;
                }
                let size_overflow = || {
                    bind(MddError::new(
                        ErrorCode::QuotaExceeded,
                        "facts.annotations",
                        "Signature allocation size overflow",
                    ))
                };
                if !owner_layout_validated {
                    validate_owner_definition_layout(&definitions).map_err(bind)?;
                    owner_layout_validated = true;
                }
                let has_definition = owner_has_definition(&definitions, owner).map_err(bind)?;
                let identity_bytes = u64::try_from(source.snapshot_id.len())
                    .ok()
                    .and_then(|size| {
                        size.checked_add(u64::try_from(source.dex_occurrence_id.len()).ok()?)
                    })
                    .and_then(|size| size.checked_add(32))
                    .ok_or_else(size_overflow)?;
                let identity_count = u64::try_from(value.children.len())
                    .ok()
                    .and_then(|count| count.checked_add(2))
                    .and_then(|count| count.checked_add(u64::from(has_definition)))
                    .ok_or_else(size_overflow)?;
                let cost = total_units
                    .checked_mul(2)
                    .and_then(|size| size.checked_add(identity_count.checked_mul(identity_bytes)?))
                    .and_then(|size| {
                        size.checked_add(
                            u64::try_from(definitions.metadata.string_pool.string_pool_id.len())
                                .ok()?,
                        )
                    })
                    .ok_or_else(size_overflow)?;
                remaining = remaining.checked_sub(cost).ok_or_else(|| {
                    bind(
                        MddError::new(
                            ErrorCode::QuotaExceeded,
                            "facts.annotations",
                            "Signature expansion exceeds annotation byte budget",
                        )
                        .detail("reason", "SIGNATURE_BYTE_BUDGET"),
                    )
                })?;
                signatures.try_reserve(1).map_err(|_| {
                    bind(MddError::new(
                        ErrorCode::QuotaExceeded,
                        "facts.annotations",
                        "Signature list allocation failed",
                    ))
                })?;
                let mut units = Vec::new();
                units
                    .try_reserve_exact(usize::try_from(total_units).map_err(|_| size_overflow())?)
                    .map_err(|_| {
                        bind(MddError::new(
                            ErrorCode::QuotaExceeded,
                            "facts.annotations",
                            "Signature allocation failed",
                        ))
                    })?;
                let mut parts = Vec::new();
                parts.try_reserve_exact(value.children.len()).map_err(|_| {
                    bind(MddError::new(
                        ErrorCode::QuotaExceeded,
                        "facts.annotations",
                        "Signature reference allocation failed",
                    ))
                })?;
                for node_id in &value.children {
                    let index = data.values[*node_id as usize]
                        .value_index
                        .ok_or_else(invalid)?;
                    units.extend_from_slice(
                        &definitions.metadata.strings[index as usize]
                            .data
                            .text
                            .utf16_units,
                    );
                    parts.push(
                        definitions
                            .metadata
                            .entity(EntityKind::String, index)
                            .map_err(bind)?,
                    );
                }
                signatures.push(SignatureFact {
                    annotation: AnnotationRef {
                        snapshot_id: source.snapshot_id.clone(),
                        dex_occurrence_id: source.dex_occurrence_id.clone(),
                        annotation_byte_offset: offset,
                    },
                    owner: owner_ref(&definitions, owner, has_definition).map_err(bind)?,
                    string_pool_id: definitions.metadata.string_pool.string_pool_id.clone(),
                    parts,
                    utf16_units: units,
                });
            }
        }
        let mut completed_layers = definitions.completed_layers.clone();
        completed_layers.extend([
            "annotations".into(),
            "encoded_values".into(),
            "signature_fragments".into(),
        ]);
        let mut unbuilt_layers: Vec<_> = definitions
            .unbuilt_layers
            .iter()
            .filter(|layer| layer.as_str() != "annotations")
            .cloned()
            .collect();
        if data
            .parameter_lists
            .iter()
            .any(|binding| binding.prototype_position_coverage != Completeness::Complete)
        {
            unbuilt_layers.push("prototype_parameter_annotation_positions".into());
        }
        Ok(Self {
            definitions,
            data,
            signatures,
            completed_layers,
            unbuilt_layers,
            annotation_coverage: Completeness::Complete,
        })
    }
    pub fn definitions(&self) -> &DefinitionFacts {
        &self.definitions
    }
    pub fn source(&self) -> &MetadataSource {
        self.definitions.metadata.source()
    }
    /// Resolve a physically validated collection start in this exact occurrence.
    /// Limits bound the selected kind's physical item count and selected slot
    /// count, not bytes scanned, CPU, allocation or RSS. Empty and orphan
    /// physical collections remain valid; `None` slots are preserved.
    pub fn collection_by_ref(
        &self,
        reference: &AnnotationCollectionRef,
        max_physical_items: u64,
        max_slots: u64,
    ) -> MddResult<AnnotationCollectionView<'_>> {
        let source = self.source();
        if reference.snapshot_id != source.snapshot_id
            || reference.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.annotation_collections",
                "collection belongs to another snapshot or occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.annotation_collections",
                "complete metadata, definitions and annotations are required",
            ));
        }
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.annotation_collections",
                "collection entry budget exceeded",
            )
        };
        let invalid = || {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.annotation_collections",
                "collection offset is not a physical item start",
            )
        };
        let broken = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.annotation_collections",
                "validated collection is inconsistent",
            )
        };
        let raw = |offset: u32, length: u64, start: u64| -> MddResult<&[u8]> {
            if start != u64::from(offset) {
                return Err(broken());
            }
            let end = start.checked_add(length).ok_or_else(broken)?;
            let begin = usize::try_from(start).map_err(|_| broken())?;
            let end = usize::try_from(end).map_err(|_| broken())?;
            self.bytes().get(begin..end).ok_or_else(broken)
        };
        match reference.kind {
            AnnotationCollectionKind::Set => {
                if u64::try_from(self.data.sets.len()).map_err(|_| quota())? > max_physical_items {
                    return Err(quota());
                }
                let mut found = self
                    .data
                    .sets
                    .iter()
                    .filter(|v| v.byte_offset == reference.byte_offset);
                let item = found.next().ok_or_else(invalid)?;
                if found.next().is_some() {
                    return Err(broken());
                }
                if u64::try_from(item.annotation_offsets.len()).map_err(|_| quota())? > max_slots {
                    return Err(quota());
                }
                let raw_encoded = raw(
                    item.byte_offset,
                    item.encoded_range.byte_length.0,
                    item.encoded_range.byte_offset.0,
                )?;
                Ok(AnnotationCollectionView::Set {
                    source,
                    item,
                    raw_encoded,
                })
            }
            AnnotationCollectionKind::SetRefList => {
                if u64::try_from(self.data.ref_lists.len()).map_err(|_| quota())?
                    > max_physical_items
                {
                    return Err(quota());
                }
                let mut found = self
                    .data
                    .ref_lists
                    .iter()
                    .filter(|v| v.byte_offset == reference.byte_offset);
                let item = found.next().ok_or_else(invalid)?;
                if found.next().is_some() {
                    return Err(broken());
                }
                if u64::try_from(item.annotation_set_offsets.len()).map_err(|_| quota())?
                    > max_slots
                {
                    return Err(quota());
                }
                let raw_encoded = raw(
                    item.byte_offset,
                    item.encoded_range.byte_length.0,
                    item.encoded_range.byte_offset.0,
                )?;
                Ok(AnnotationCollectionView::SetRefList {
                    source,
                    item,
                    raw_encoded,
                })
            }
        }
    }
    /// Resolve a single encoded owner binding to its physical annotation items.
    /// `parameter_slot` selects an encoded method-parameter slot; `None` selects
    /// class, field, or method annotations themselves. For a parameter slot,
    /// consult `owner.parameter_position_in_prototype` before interpreting it as
    /// a prototype position. `None` means no matching encoded owner binding in
    /// this occurrence; use `method_encoded_parameter_list` when a caller must
    /// distinguish an absent list from a present list without that slot.
    ///
    /// The limits cover logical scans and returned entries, not allocation
    /// overhead, CPU time or RSS. Empty sets and explicit zero slots remain
    /// distinct, and repeated physical entries are never deduplicated.
    pub fn owner_annotation_facts(
        &self,
        owner: &EntityRef,
        parameter_slot: Option<u32>,
        limits: AnnotationOwnerViewLimits,
    ) -> MddResult<Option<OwnerAnnotationFacts<'_>>> {
        let source = self.source();
        if owner.snapshot_id != source.snapshot_id
            || owner.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.owner_annotations",
                "owner belongs to another snapshot or occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.owner_annotations",
                "complete metadata, definitions and annotations are required",
            ));
        }
        let definitions = self.definitions.definitions();
        let (kind, definition_scan) = match (owner.kind, parameter_slot) {
            (EntityKind::ClassDefinition, None) => (AnnotationOwnerKind::Class, 0),
            (EntityKind::FieldReference, None) => (AnnotationOwnerKind::Field, 0),
            (EntityKind::FieldDefinition, None) => (
                AnnotationOwnerKind::Field,
                definitions.field_definitions.len(),
            ),
            (EntityKind::MethodReference, None) => (AnnotationOwnerKind::Method, 0),
            (EntityKind::MethodDefinition, None) => (
                AnnotationOwnerKind::Method,
                definitions.method_definitions.len(),
            ),
            (EntityKind::MethodReference, Some(_)) => (AnnotationOwnerKind::Parameter, 0),
            (EntityKind::MethodDefinition, Some(_)) => (
                AnnotationOwnerKind::Parameter,
                definitions.method_definitions.len(),
            ),
            _ => {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.owner_annotations",
                    "owner kind and parameter slot are incompatible",
                ));
            }
        };
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.owner_annotations",
                "owner annotation view budget exceeded",
            )
        };
        let broken = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.owner_annotations",
                "validated owner annotation facts are inconsistent",
            )
        };
        let in_captured_bytes = |offset: u64, length: u64| -> bool {
            let Some(end) = offset.checked_add(length) else {
                return false;
            };
            let (Ok(start), Ok(end)) = (usize::try_from(offset), usize::try_from(end)) else {
                return false;
            };
            self.bytes().get(start..end).is_some()
        };
        let mut visits = u64::try_from(definition_scan).map_err(|_| quota())?;
        if visits > limits.max_scanned_entries {
            return Err(quota());
        }
        self.definitions.entity(owner.kind, owner.local_index)?;
        let mut tick = || -> MddResult<()> {
            visits = visits.checked_add(1).ok_or_else(quota)?;
            if visits > limits.max_scanned_entries {
                return Err(quota());
            }
            Ok(())
        };
        let mut binding = None;
        for candidate in &self.data.owner_bindings {
            tick()?;
            if candidate.kind == kind
                && candidate.local_index == owner.local_index
                && candidate.parameter_ordinal == parameter_slot
                && binding.replace(candidate).is_some()
            {
                return Err(broken());
            }
        }
        let Some(binding) = binding else {
            return Ok(None);
        };
        let Some(offset) = binding.annotation_set_offset else {
            if kind != AnnotationOwnerKind::Parameter {
                return Err(broken());
            }
            return Ok(Some(OwnerAnnotationFacts {
                source,
                owner: binding,
                set: None,
                annotations: Vec::new(),
            }));
        };
        let mut selected = None;
        for set in &self.data.sets {
            tick()?;
            if set.byte_offset == offset && selected.replace(set).is_some() {
                return Err(broken());
            }
        }
        let set = selected.ok_or_else(broken)?;
        if set.encoded_range.byte_offset.0 != u64::from(offset)
            || !in_captured_bytes(
                set.encoded_range.byte_offset.0,
                set.encoded_range.byte_length.0,
            )
        {
            return Err(broken());
        }
        let mut annotations = Vec::new();
        for (ordinal, offset) in set.annotation_offsets.iter().enumerate() {
            tick()?;
            let mut item = None;
            for candidate in &self.data.annotation_items {
                tick()?;
                if candidate.byte_offset == *offset && item.replace(candidate).is_some() {
                    return Err(broken());
                }
            }
            let item = item.ok_or_else(broken)?;
            if item.encoded_range.byte_offset.0 != u64::from(*offset)
                || !in_captured_bytes(
                    item.encoded_range.byte_offset.0,
                    item.encoded_range.byte_length.0,
                )
            {
                return Err(broken());
            }
            if u64::try_from(annotations.len()).map_err(|_| quota())? >= limits.max_matches {
                return Err(quota());
            }
            annotations.try_reserve(1).map_err(|_| quota())?;
            annotations.push(AnnotationOwnerFact {
                source,
                owner: binding,
                set,
                annotation: item,
                set_ordinal: u32::try_from(ordinal).map_err(|_| quota())?,
            });
        }
        Ok(Some(OwnerAnnotationFacts {
            source,
            owner: binding,
            set: Some(set),
            annotations,
        }))
    }

    /// Reverse lookup of one validated physical item across encoded owners in
    /// this DEX occurrence. An empty result proves only that this item has no
    /// encoded owner in these complete facts, not absence from other inputs.
    /// Orphan items and empty sets remain valid. Shared sets yield one result
    /// per owner and per encoded item occurrence; no semantic inheritance or
    /// prototype-position completeness is inferred.
    pub fn annotation_owner_facts(
        &self,
        annotation: &AnnotationRef,
        limits: AnnotationOwnerViewLimits,
    ) -> MddResult<Vec<AnnotationOwnerFact<'_>>> {
        let source = self.source();
        if annotation.snapshot_id != source.snapshot_id
            || annotation.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.annotation_owners",
                "annotation belongs to another snapshot or occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.annotation_owners",
                "complete metadata, definitions and annotations are required",
            ));
        }
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.annotation_owners",
                "annotation owner view budget exceeded",
            )
        };
        let broken = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.annotation_owners",
                "validated annotation owner facts are inconsistent",
            )
        };
        let mut visits = 0u64;
        let mut tick = || -> MddResult<()> {
            visits = visits.checked_add(1).ok_or_else(quota)?;
            if visits > limits.max_scanned_entries {
                return Err(quota());
            }
            Ok(())
        };
        let mut item = None;
        for candidate in &self.data.annotation_items {
            tick()?;
            if candidate.byte_offset == annotation.annotation_byte_offset
                && item.replace(candidate).is_some()
            {
                return Err(broken());
            }
        }
        let item = item.ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.annotation_owners",
                "annotation offset is not a physical item start",
            )
        })?;
        if item.encoded_range.byte_offset.0 != u64::from(item.byte_offset) {
            return Err(broken());
        }
        let mut matches = Vec::new();
        for owner in &self.data.owner_bindings {
            tick()?;
            let Some(offset) = owner.annotation_set_offset else {
                continue;
            };
            let mut selected = None;
            for set in &self.data.sets {
                tick()?;
                if set.byte_offset == offset && selected.replace(set).is_some() {
                    return Err(broken());
                }
            }
            let set = selected.ok_or_else(broken)?;
            if set.encoded_range.byte_offset.0 != u64::from(set.byte_offset) {
                return Err(broken());
            }
            for (ordinal, entry) in set.annotation_offsets.iter().enumerate() {
                tick()?;
                if *entry == item.byte_offset {
                    if u64::try_from(matches.len()).map_err(|_| quota())? >= limits.max_matches {
                        return Err(quota());
                    }
                    let set_ordinal = u32::try_from(ordinal).map_err(|_| quota())?;
                    matches.try_reserve(1).map_err(|_| quota())?;
                    matches.push(AnnotationOwnerFact {
                        source,
                        owner,
                        set,
                        annotation: item,
                        set_ordinal,
                    });
                }
            }
        }
        Ok(matches)
    }
    /// Iterate physical value nodes for one exact annotation item in parser order.
    /// The caller must consume the iterator and handle each error before calling
    /// the result complete. This does not infer an annotation owner or profile.
    pub fn annotation_value_facts(
        &self,
        annotation: &AnnotationRef,
        limits: AnnotationValueViewLimits,
    ) -> MddResult<impl Iterator<Item = MddResult<AnnotationValueFact<'_>>> + '_> {
        let source = self.source();
        if annotation.snapshot_id != source.snapshot_id
            || annotation.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.annotation_values",
                "annotation belongs to another snapshot or occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.annotation_values",
                "complete metadata, definitions and annotations are required",
            ));
        }
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.annotation_values",
                "annotation value view entry budget exceeded",
            )
        };
        let items = u64::try_from(self.data.annotation_items.len()).map_err(|_| quota())?;
        if items > limits.max_scanned_entries {
            return Err(quota());
        }
        let mut found = self
            .data
            .annotation_items
            .iter()
            .filter(|item| item.byte_offset == annotation.annotation_byte_offset);
        let item = found.next().ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.annotation_values",
                "annotation offset is not a physical item start",
            )
        })?;
        let inconsistent = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.annotation_values",
                "validated annotation values are inconsistent",
            )
        };
        if found.next().is_some() || item.encoded_range.byte_offset.0 != u64::from(item.byte_offset)
        {
            return Err(inconsistent());
        }
        let visits = u64::try_from(self.data.values.len())
            .ok()
            .and_then(|count| count.checked_mul(2))
            .and_then(|count| count.checked_add(items))
            .and_then(|count| count.checked_add(item.elements.len() as u64))
            .ok_or_else(quota)?;
        if visits > limits.max_scanned_entries {
            return Err(quota());
        }
        for (ordinal, node_id) in item.elements.iter().enumerate() {
            let value = self
                .data
                .values
                .get(*node_id as usize)
                .ok_or_else(inconsistent)?;
            if value.node_id != *node_id
                || value.annotation_byte_offset != Some(item.byte_offset)
                || value.depth != 0
                || u32::try_from(ordinal).ok() != Some(value.ordinal)
            {
                return Err(inconsistent());
            }
        }
        let count = u64::try_from(
            self.data
                .values
                .iter()
                .filter(|value| value.annotation_byte_offset == Some(item.byte_offset))
                .count(),
        )
        .map_err(|_| quota())?;
        if count > limits.max_values {
            return Err(quota());
        }
        if count < item.elements.len() as u64 {
            return Err(inconsistent());
        }
        let item_start = item.encoded_range.byte_offset.0;
        let item_end = item_start
            .checked_add(item.encoded_range.byte_length.0)
            .ok_or_else(inconsistent)?;
        if item.encoded_range.byte_length.0 == 0
            || usize::try_from(item_end).map_or(true, |end| end > self.bytes().len())
        {
            return Err(inconsistent());
        }
        Ok(self
            .data
            .values
            .iter()
            .enumerate()
            .filter(move |(_, value)| value.annotation_byte_offset == Some(item.byte_offset))
            .map(move |(ordinal, value)| {
                let start = value.encoded_range.byte_offset.0;
                let end = start
                    .checked_add(value.encoded_range.byte_length.0)
                    .ok_or_else(inconsistent)?;
                if u32::try_from(ordinal).ok() != Some(value.node_id)
                    || value.encoded_range.byte_length.0 == 0
                    || start < item_start
                    || end > item_end
                {
                    return Err(inconsistent());
                }
                let start = usize::try_from(start).map_err(|_| inconsistent())?;
                let end = usize::try_from(end).map_err(|_| inconsistent())?;
                let raw_encoded = self.bytes().get(start..end).ok_or_else(inconsistent)?;
                Ok(AnnotationValueFact {
                    source,
                    annotation: item,
                    value,
                    raw_encoded,
                })
            }))
    }
    /// Resolve one encoded call_site_id without scanning all bindings. A
    /// missing index returns None only for complete facts in this occurrence.
    /// The limits count two logical lookups and one returned binding, not CPU,
    /// bytes, allocation, cancellation or RSS.
    pub fn encoded_call_site(
        &self,
        reference: &EncodedCallSiteRef,
        limits: AnnotationOwnerViewLimits,
    ) -> MddResult<Option<EncodedCallSiteView<'_>>> {
        let stage = "facts.encoded_call_site";
        let source = self.source();
        if reference.snapshot_id != source.snapshot_id
            || reference.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                stage,
                "call site belongs to another snapshot or occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                stage,
                "complete metadata, definitions and annotations are required",
            ));
        }
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                stage,
                "call-site view budget exceeded",
            )
        };
        let inconsistent = || {
            MddError::new(
                ErrorCode::InternalFault,
                stage,
                "validated call-site binding is inconsistent",
            )
        };
        if limits.max_scanned_entries < 1 {
            return Err(quota());
        }
        let Some(binding) = usize::try_from(reference.call_site_idx)
            .ok()
            .and_then(|index| self.data.call_site_arrays.get(index))
        else {
            return Ok(None);
        };
        if limits.max_scanned_entries < 2 || limits.max_matches < 1 {
            return Err(quota());
        }
        if binding.call_site_idx != reference.call_site_idx {
            return Err(inconsistent());
        }
        let array = usize::try_from(binding.encoded_array_index)
            .ok()
            .and_then(|index| self.data.encoded_arrays.get(index))
            .ok_or_else(inconsistent)?;
        if array.byte_offset != binding.encoded_array_byte_offset
            || array.encoded_range.byte_offset.0 != u64::from(array.byte_offset)
            || array.encoded_range.byte_length.0 == 0
        {
            return Err(inconsistent());
        }
        let start =
            usize::try_from(array.encoded_range.byte_offset.0).map_err(|_| inconsistent())?;
        let length =
            usize::try_from(array.encoded_range.byte_length.0).map_err(|_| inconsistent())?;
        let end = start.checked_add(length).ok_or_else(inconsistent)?;
        let raw_encoded = self.bytes().get(start..end).ok_or_else(inconsistent)?;
        Ok(Some(EncodedCallSiteView {
            source,
            binding,
            array,
            raw_encoded,
        }))
    }
    /// Return encoded references to one physical array without deduplicating
    /// classes or call sites. An empty result means this complete occurrence
    /// contains no such encoded bindings; it makes no runtime claim.
    /// Limits count scanned entries and returned bindings, not bytes or RSS.
    pub fn encoded_array_bindings(
        &self,
        reference: &EncodedArrayRef,
        limits: AnnotationOwnerViewLimits,
    ) -> MddResult<EncodedArrayBindings<'_>> {
        let stage = "facts.encoded_array_bindings";
        let source = self.source();
        if reference.snapshot_id != source.snapshot_id
            || reference.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                stage,
                "array belongs to another snapshot or occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                stage,
                "complete metadata, definitions and annotations are required",
            ));
        }
        let quota = || MddError::new(ErrorCode::QuotaExceeded, stage, "binding budget exceeded");
        let inconsistent = || {
            MddError::new(
                ErrorCode::InternalFault,
                stage,
                "validated array binding is inconsistent",
            )
        };
        let classes = &self.definitions.definitions.classes;
        let call_sites = &self.data.call_site_arrays;
        let arrays = &self.data.encoded_arrays;
        let visits = u64::try_from(arrays.len())
            .ok()
            .and_then(|n| n.checked_add(u64::try_from(classes.len()).ok()?))
            .and_then(|n| n.checked_add(u64::try_from(call_sites.len()).ok()?))
            .ok_or_else(quota)?;
        if visits > limits.max_scanned_entries {
            return Err(quota());
        }
        let mut matching = arrays
            .iter()
            .enumerate()
            .filter(|(_, array)| array.byte_offset == reference.byte_offset);
        let (array_index, array) = matching.next().ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                stage,
                "array offset is not a physical item start",
            )
        })?;
        if matching.next().is_some()
            || array.encoded_range.byte_offset.0 != u64::from(array.byte_offset)
        {
            return Err(inconsistent());
        }
        let mut bindings = Vec::new();
        for (index, class) in classes.iter().enumerate() {
            if class
                .static_values_byte_offset
                .is_some_and(|offset| offset.0 == u64::from(array.byte_offset))
            {
                if u32::try_from(index).ok() != Some(class.class_def_idx) {
                    return Err(inconsistent());
                }
                if u64::try_from(bindings.len()).map_err(|_| quota())? >= limits.max_matches {
                    return Err(quota());
                }
                bindings.try_reserve(1).map_err(|_| quota())?;
                bindings.push(EncodedArrayBinding::StaticValues(class));
            }
        }
        for (index, binding) in call_sites.iter().enumerate() {
            if binding.encoded_array_byte_offset == array.byte_offset {
                if u32::try_from(index).ok() != Some(binding.call_site_idx)
                    || usize::try_from(binding.encoded_array_index).ok() != Some(array_index)
                {
                    return Err(inconsistent());
                }
                if u64::try_from(bindings.len()).map_err(|_| quota())? >= limits.max_matches {
                    return Err(quota());
                }
                bindings.try_reserve(1).map_err(|_| quota())?;
                bindings.push(EncodedArrayBinding::CallSite(binding));
            }
        }
        Ok(EncodedArrayBindings {
            source,
            array,
            bindings,
        })
    }
    /// Resolve one node without materializing the complete array value view.
    /// `None` means the node is not present in this physical array, including
    /// when the same node ID refers to a value in another array. Limits count
    /// scanned physical arrays and a node lookup, not CPU, bytes or RSS.
    pub fn encoded_array_value(
        &self,
        reference: &EncodedArrayValueRef,
        limits: AnnotationValueViewLimits,
    ) -> MddResult<Option<EncodedArrayValueView<'_>>> {
        let stage = "facts.encoded_array_value";
        let source = self.source();
        if reference.array.snapshot_id != source.snapshot_id
            || reference.array.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                stage,
                "array belongs to another snapshot or occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                stage,
                "complete metadata, definitions and annotations are required",
            ));
        }
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                stage,
                "array value budget exceeded",
            )
        };
        let inconsistent = || {
            MddError::new(
                ErrorCode::InternalFault,
                stage,
                "validated encoded array value is inconsistent",
            )
        };
        let visits = u64::try_from(self.data.encoded_arrays.len())
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or_else(quota)?;
        if visits > limits.max_scanned_entries {
            return Err(quota());
        }
        let mut matches = self
            .data
            .encoded_arrays
            .iter()
            .filter(|array| array.byte_offset == reference.array.byte_offset);
        let array = matches.next().ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                stage,
                "array offset is not a physical item start",
            )
        })?;
        if matches.next().is_some()
            || array.encoded_range.byte_offset.0 != u64::from(array.byte_offset)
        {
            return Err(inconsistent());
        }
        let start = array.encoded_range.byte_offset.0;
        let end = start
            .checked_add(array.encoded_range.byte_length.0)
            .ok_or_else(inconsistent)?;
        if start == end
            || usize::try_from(end)
                .ok()
                .is_none_or(|end| end > self.bytes().len())
        {
            return Err(inconsistent());
        }
        let Some(value) = usize::try_from(reference.node_id)
            .ok()
            .and_then(|id| self.data.values.get(id))
        else {
            return Ok(None);
        };
        if value.node_id != reference.node_id {
            return Err(inconsistent());
        }
        let value_start = value.encoded_range.byte_offset.0;
        if value_start <= start || value_start >= end {
            return Ok(None);
        }
        let value_end = value_start
            .checked_add(value.encoded_range.byte_length.0)
            .ok_or_else(inconsistent)?;
        if value.annotation_byte_offset.is_some() || value_start == value_end || value_end > end {
            return Err(inconsistent());
        }
        if limits.max_values == 0 {
            return Err(quota());
        }
        let raw_encoded = self
            .bytes()
            .get(
                usize::try_from(value_start).map_err(|_| inconsistent())?
                    ..usize::try_from(value_end).map_err(|_| inconsistent())?,
            )
            .ok_or_else(inconsistent)?;
        Ok(Some(EncodedArrayValueView {
            source,
            array,
            value,
            raw_encoded,
        }))
    }

    /// Resolve a physically walked encoded-array item and its value nodes.
    /// Limits bound logical visits and returned nodes, not memory or CPU time.
    /// Shared references do not duplicate the physical item in this view.
    pub fn encoded_array_view(
        &self,
        reference: &EncodedArrayRef,
        limits: AnnotationValueViewLimits,
    ) -> MddResult<EncodedArrayView<'_>> {
        let stage = "facts.encoded_array";
        let source = self.source();
        if reference.snapshot_id != source.snapshot_id
            || reference.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                stage,
                "array belongs to another snapshot or occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                stage,
                "complete metadata, definitions and annotations are required",
            ));
        }
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                stage,
                "encoded array view entry budget exceeded",
            )
        };
        let inconsistent = || {
            MddError::new(
                ErrorCode::InternalFault,
                stage,
                "validated encoded array is inconsistent",
            )
        };
        let arrays = u64::try_from(self.data.encoded_arrays.len()).map_err(|_| quota())?;
        if arrays > limits.max_scanned_entries {
            return Err(quota());
        }
        let mut matches = self
            .data
            .encoded_arrays
            .iter()
            .filter(|array| array.byte_offset == reference.byte_offset);
        let array = matches.next().ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                stage,
                "array offset is not a physical item start",
            )
        })?;
        if matches.next().is_some()
            || array.encoded_range.byte_offset.0 != u64::from(array.byte_offset)
        {
            return Err(inconsistent());
        }
        let visits = u64::try_from(self.data.values.len())
            .ok()
            .and_then(|v| v.checked_mul(2))
            .and_then(|v| v.checked_add(arrays))
            .and_then(|v| v.checked_add(u64::try_from(array.elements.len()).ok()?))
            .ok_or_else(quota)?;
        if visits > limits.max_scanned_entries {
            return Err(quota());
        }
        let start = array.encoded_range.byte_offset.0;
        let end = start
            .checked_add(array.encoded_range.byte_length.0)
            .ok_or_else(inconsistent)?;
        if start == end {
            return Err(inconsistent());
        }
        let start_usize = usize::try_from(start).map_err(|_| inconsistent())?;
        let end_usize = usize::try_from(end).map_err(|_| inconsistent())?;
        let raw_encoded = self
            .bytes()
            .get(start_usize..end_usize)
            .ok_or_else(inconsistent)?;
        for (ordinal, id) in array.elements.iter().enumerate() {
            let node = self
                .data
                .values
                .get(*id as usize)
                .ok_or_else(inconsistent)?;
            if node.node_id != *id
                || node.annotation_byte_offset.is_some()
                || node.depth != 0
                || node.name_idx.is_some()
                || u32::try_from(ordinal).ok() != Some(node.ordinal)
                || node.encoded_range.byte_offset.0 <= start
                || node.encoded_range.byte_offset.0 >= end
            {
                return Err(inconsistent());
            }
        }
        let in_array = |node: &&EncodedValue| {
            node.annotation_byte_offset.is_none()
                && node.encoded_range.byte_offset.0 > start
                && node.encoded_range.byte_offset.0 < end
        };
        let count = self.data.values.iter().filter(in_array).count();
        if u64::try_from(count).map_err(|_| quota())? > limits.max_values {
            return Err(quota());
        }
        if count < array.elements.len() {
            return Err(inconsistent());
        }
        let mut values = Vec::new();
        values.try_reserve_exact(count).map_err(|_| quota())?;
        for (ordinal, value) in self
            .data
            .values
            .iter()
            .enumerate()
            .filter(|(_, value)| in_array(value))
        {
            let value_start = value.encoded_range.byte_offset.0;
            let value_end = value_start
                .checked_add(value.encoded_range.byte_length.0)
                .ok_or_else(inconsistent)?;
            if u32::try_from(ordinal).ok() != Some(value.node_id)
                || value_start == value_end
                || value_end > end
            {
                return Err(inconsistent());
            }
            let raw = self
                .bytes()
                .get(
                    usize::try_from(value_start).map_err(|_| inconsistent())?
                        ..usize::try_from(value_end).map_err(|_| inconsistent())?,
                )
                .ok_or_else(inconsistent)?;
            values.push(EncodedArrayValueFact {
                value,
                raw_encoded: raw,
            });
        }
        Ok(EncodedArrayView {
            source,
            array,
            raw_encoded,
            values,
        })
    }
    /// Resolve the physical encoded parameter-annotation list for one method.
    /// `None` means no such binding was encoded in this complete DEX occurrence;
    /// it does not prove absence from another source or at runtime. A present list
    /// can have unknown prototype-position coverage and is never padded.
    /// Limits bound logical scan entries and encoded slots, not CPU or RSS.
    pub fn method_encoded_parameter_list(
        &self,
        method: &EntityRef,
        limits: ParameterViewLimits,
    ) -> MddResult<Option<EncodedParameterListFact<'_>>> {
        let source = self.source();
        if method.snapshot_id != source.snapshot_id
            || method.dex_occurrence_id != source.dex_occurrence_id
            || !matches!(
                method.kind,
                EntityKind::MethodReference | EntityKind::MethodDefinition
            )
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.parameters",
                "method is foreign or has the wrong identity kind",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.parameters",
                "complete metadata, definitions and annotations are required",
            ));
        }
        let defs = self.definitions.definitions();
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.parameters",
                "encoded parameter list budget exceeded",
            )
        };
        let broken = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.parameters",
                "validated parameter list is inconsistent",
            )
        };
        let scans = [
            defs.method_definitions.len(),
            self.data.parameter_lists.len(),
            self.data.ref_lists.len(),
        ]
        .into_iter()
        .try_fold(0u64, |total, len| {
            u64::try_from(len).ok().and_then(|n| total.checked_add(n))
        })
        .ok_or_else(quota)?;
        if scans > limits.max_scan_entries {
            return Err(quota());
        }
        let reference = defs
            .method_references
            .get(method.local_index as usize)
            .filter(|r| r.method_idx == method.local_index)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.parameters",
                    "method reference does not exist in this occurrence",
                )
            })?;
        let mut definitions = defs
            .method_definitions
            .iter()
            .filter(|d| d.method_idx == method.local_index);
        let definition = definitions.next();
        if definitions.next().is_some() {
            return Err(broken());
        }
        if method.kind == EntityKind::MethodDefinition && definition.is_none() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.parameters",
                "method definition does not exist in this occurrence",
            ));
        }
        let mut bindings = self
            .data
            .parameter_lists
            .iter()
            .filter(|b| b.method_idx == method.local_index);
        let Some(binding) = bindings.next() else {
            return Ok(None);
        };
        if bindings.next().is_some() {
            return Err(broken());
        }
        if !binding.encoded_slots_complete {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.parameters",
                "encoded parameter slots are incomplete",
            ));
        }
        let mut lists = self
            .data
            .ref_lists
            .iter()
            .filter(|list| list.byte_offset == binding.ref_list_byte_offset);
        let list = lists.next().ok_or_else(broken)?;
        if lists.next().is_some()
            || u64::try_from(list.annotation_set_offsets.len()).map_err(|_| quota())?
                != u64::from(binding.encoded_slot_count)
            || list.encoded_range.byte_offset.0 != u64::from(list.byte_offset)
        {
            return Err(broken());
        }
        if u64::from(binding.encoded_slot_count) > limits.max_parameters {
            return Err(quota());
        }
        let start = usize::try_from(list.encoded_range.byte_offset.0).map_err(|_| broken())?;
        let end = list
            .encoded_range
            .byte_offset
            .0
            .checked_add(list.encoded_range.byte_length.0)
            .and_then(|v| usize::try_from(v).ok())
            .ok_or_else(broken)?;
        let raw_encoded = self.bytes().get(start..end).ok_or_else(broken)?;
        Ok(Some(EncodedParameterListFact {
            source,
            method_reference: reference,
            definition,
            binding,
            list,
            raw_encoded,
        }))
    }

    /// Resolve the encoded slots for a method without inventing prototype
    /// positions. `None` means no encoded binding; `Some` may contain zero
    /// slots. `max_set_visits` bounds physical set entries scanned per complete
    /// iterator pass, separately from the method/list and slot limits. These
    /// are logical bounds and do not bound CPU, allocator overhead, or RSS.
    pub fn method_encoded_parameter_slots(
        &self,
        method: &EntityRef,
        limits: ParameterViewLimits,
        max_set_visits: u64,
    ) -> MddResult<Option<EncodedParameterSlots<'_>>> {
        let Some(encoded) = self.method_encoded_parameter_list(method, limits)? else {
            return Ok(None);
        };
        let nonzero = u64::try_from(
            encoded
                .list
                .annotation_set_offsets
                .iter()
                .filter(|offset| offset.is_some())
                .count(),
        )
        .map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.parameters",
                "set scan overflow",
            )
        })?;
        let visits = nonzero
            .checked_mul(u64::try_from(self.data.sets.len()).map_err(|_| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.parameters",
                    "set scan overflow",
                )
            })?)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.parameters",
                    "set scan overflow",
                )
            })?;
        if visits > max_set_visits {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.parameters",
                "parameter set scan budget exceeded",
            ));
        }
        Ok(Some(EncodedParameterSlots {
            source: encoded.source,
            binding: encoded.binding,
            list: encoded.list,
            sets: &self.data.sets,
            bytes: self.bytes(),
        }))
    }

    /// Bind one method to proven prototype positions and physical annotation slots.
    /// A short or otherwise unmapped list is not padded and is reported incomplete.
    pub fn method_parameter_facts(
        &self,
        method: &EntityRef,
        limits: ParameterViewLimits,
    ) -> MddResult<MethodParameterFacts<'_>> {
        let source = self.source();
        if method.snapshot_id != source.snapshot_id
            || method.dex_occurrence_id != source.dex_occurrence_id
            || !matches!(
                method.kind,
                EntityKind::MethodReference | EntityKind::MethodDefinition
            )
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.parameters",
                "method is foreign or has the wrong identity kind",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.parameters",
                "complete metadata, definitions and annotations are required",
            ));
        }
        let definitions = self.definitions.definitions();
        let scan_count = [
            definitions.method_definitions.len(),
            self.data.parameter_lists.len(),
            self.data.ref_lists.len(),
        ]
        .into_iter()
        .try_fold(0u64, |total, len| {
            u64::try_from(len)
                .ok()
                .and_then(|len| total.checked_add(len))
        })
        .ok_or_else(|| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.parameters",
                "parameter view scan budget overflow",
            )
        })?;
        if scan_count > limits.max_scan_entries {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.parameters",
                "parameter view scan budget exceeded",
            ));
        }
        let broken = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.parameters",
                "validated parameter facts are inconsistent",
            )
        };
        let reference = definitions
            .method_references
            .get(method.local_index as usize)
            .filter(|reference| reference.method_idx == method.local_index)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.parameters",
                    "method reference does not exist in this occurrence",
                )
            })?;
        let mut matches = definitions
            .method_definitions
            .iter()
            .filter(|entry| entry.method_idx == method.local_index);
        let definition = matches.next();
        if matches.next().is_some() {
            return Err(broken());
        }
        if method.kind == EntityKind::MethodDefinition && definition.is_none() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.parameters",
                "method definition does not exist in this occurrence",
            ));
        }
        let prototype = self
            .definitions
            .metadata()
            .prototypes()
            .get(reference.proto_idx as usize)
            .map(|fact| &fact.data)
            .filter(|prototype| prototype.proto_idx == reference.proto_idx)
            .ok_or_else(broken)?;
        let count = u64::try_from(prototype.parameter_type_indices.len()).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.parameters",
                "parameter count overflow",
            )
        })?;
        if count > limits.max_parameters || count > u64::from(u32::MAX) {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.parameters",
                "parameter count budget exceeded",
            ));
        }
        for index in &prototype.parameter_type_indices {
            if !self
                .definitions
                .metadata()
                .types()
                .get(*index as usize)
                .is_some_and(|fact| fact.data.type_idx == *index)
            {
                return Err(broken());
            }
        }
        let mut bindings = self
            .data
            .parameter_lists
            .iter()
            .filter(|binding| binding.method_idx == method.local_index);
        let binding = bindings.next();
        if bindings.next().is_some() {
            return Err(broken());
        }
        let encoded_list = if let Some(binding) = binding {
            if !binding.encoded_slots_complete
                || binding.prototype_position_coverage != Completeness::Complete
            {
                return Err(MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.parameters",
                    "prototype positions for encoded annotation slots are not complete",
                )
                .detail("required_layer", "prototype_parameter_annotation_positions"));
            }
            if u64::from(binding.prototype_parameter_count) != count
                || u64::from(binding.encoded_slot_count) != count
            {
                return Err(broken());
            }
            let mut lists = self
                .data
                .ref_lists
                .iter()
                .filter(|list| list.byte_offset == binding.ref_list_byte_offset);
            let list = lists.next().ok_or_else(broken)?;
            if lists.next().is_some()
                || list.annotation_set_offsets.len() != prototype.parameter_type_indices.len()
            {
                return Err(broken());
            }
            Some(list)
        } else {
            None
        };
        Ok(MethodParameterFacts {
            facts: self,
            method_reference: reference,
            definition,
            prototype,
            encoded_list,
        })
    }
    pub fn data(&self) -> &DexAnnotations {
        &self.data
    }
    pub fn signatures(&self) -> &[SignatureFact] {
        &self.signatures
    }

    /// Resolve one borrowed Signature owner's parameter-position status without
    /// treating an encoded slot as a proven prototype position. The Signature
    /// must match a stored Signature's stable source identity and full content;
    /// an equivalent clone is accepted, while a foreign or changed value is
    /// rejected. Repeated Signature occurrences remain separate.
    pub fn signature_parameter_position(
        &self,
        signature: &SignatureFact,
        limits: SignaturePositionLimits,
    ) -> MddResult<SignatureParameterPosition> {
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.signatures",
                "signature identity scan budget exceeded",
            )
        };
        let broken = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.signatures",
                "signature owner and parameter list are inconsistent",
            )
        };
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.signatures",
                "complete metadata, definitions and annotations are required",
            ));
        }
        if u64::try_from(self.signatures.len()).map_err(|_| quota())? > limits.max_signatures {
            return Err(quota());
        }
        // Compare against the immutable stored facts rather than accepting the
        // caller's fields as evidence. Bound variable-width comparisons before
        // touching the corresponding contents, including every part identity.
        let mut examined = 0u64;
        let mut account = |amount: u64| -> MddResult<()> {
            examined = examined.checked_add(amount).ok_or_else(quota)?;
            if examined > limits.max_identity_bytes {
                return Err(quota());
            }
            Ok(())
        };
        let mut account_signature = |item: &SignatureFact| -> MddResult<()> {
            account(128)?;
            account(
                u64::try_from(item.utf16_units.len())
                    .map_err(|_| quota())?
                    .checked_mul(2)
                    .ok_or_else(quota)?,
            )?;
            account(
                u64::try_from(item.parts.len())
                    .map_err(|_| quota())?
                    .checked_mul(32)
                    .ok_or_else(quota)?,
            )?;
            for text in [
                &item.annotation.snapshot_id,
                &item.annotation.dex_occurrence_id,
                &item.owner.reference.snapshot_id,
                &item.owner.reference.dex_occurrence_id,
                &item.string_pool_id,
            ] {
                account(u64::try_from(text.len()).map_err(|_| quota())?)?;
            }
            if let Some(definition) = &item.owner.definition {
                account(u64::try_from(definition.snapshot_id.len()).map_err(|_| quota())?)?;
                account(u64::try_from(definition.dex_occurrence_id.len()).map_err(|_| quota())?)?;
            }
            for part in &item.parts {
                account(u64::try_from(part.snapshot_id.len()).map_err(|_| quota())?)?;
                account(u64::try_from(part.dex_occurrence_id.len()).map_err(|_| quota())?)?;
            }
            Ok(())
        };
        account_signature(signature)?;
        let mut found = false;
        for item in &self.signatures {
            account_signature(item)?;
            if item.annotation == signature.annotation
                && item.owner.kind == signature.owner.kind
                && item.owner.reference == signature.owner.reference
                && item.owner.definition == signature.owner.definition
                && item.owner.parameter_ordinal == signature.owner.parameter_ordinal
                && item.string_pool_id == signature.string_pool_id
                && item.parts == signature.parts
                && item.utf16_units == signature.utf16_units
            {
                found = true;
                break;
            }
        }
        if !found {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.signatures",
                "signature does not match this occurrence",
            ));
        }
        if signature.owner.kind != AnnotationOwnerKind::Parameter {
            if signature.owner.parameter_ordinal.is_some() {
                return Err(broken());
            }
            return Ok(SignatureParameterPosition::NotParameter);
        }
        if signature.owner.reference.kind != EntityKind::MethodReference {
            return Err(broken());
        }
        let slot = signature.owner.parameter_ordinal.ok_or_else(broken)?;
        let owners = self.annotation_owner_facts(&signature.annotation, limits.owners)?;
        let mut matches = owners.iter().filter(|item| {
            item.owner.kind == AnnotationOwnerKind::Parameter
                && item.owner.local_index == signature.owner.reference.local_index
                && item.owner.parameter_ordinal == Some(slot)
        });
        let owner = matches.next().ok_or_else(broken)?;
        if matches.next().is_some() {
            return Err(broken());
        }
        let encoded = self
            .method_encoded_parameter_list(&signature.owner.reference, limits.parameters)?
            .ok_or_else(broken)?;
        if encoded.binding.class_def_idx != owner.owner.class_def_idx
            || encoded.list.annotation_set_offsets.get(slot as usize)
                != Some(&owner.owner.annotation_set_offset)
            || owner.owner.prototype_parameter_count
                != Some(encoded.binding.prototype_parameter_count)
        {
            return Err(broken());
        }
        match encoded.binding.prototype_position_coverage {
            Completeness::Complete
                if slot < encoded.binding.prototype_parameter_count
                    && owner.owner.parameter_position_in_prototype == Some(true) =>
            {
                Ok(SignatureParameterPosition::Known { ordinal: slot })
            }
            Completeness::Unknown if owner.owner.parameter_position_in_prototype.is_none() => {
                Ok(SignatureParameterPosition::Unknown { encoded_slot: slot })
            }
            Completeness::Partial => Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.signatures",
                "prototype parameter-position coverage is incomplete",
            )),
            _ => Err(broken()),
        }
    }

    /// Borrow every encoded class, field, or method Signature for an exact
    /// owner in this DEX occurrence. Method and parameter annotations remain
    /// separate: parameter slots are intentionally not selected here. Repeated
    /// signatures retain their encoded order and are not collapsed to one value.
    ///
    /// An empty iterator means no matching Signature in the complete annotation
    /// facts for this occurrence only; it does not assert runtime absence,
    /// inheritance, or the absence of annotations in another source.
    /// `max_scanned_entries` bounds logical visits, including both passes and
    /// definition identity validation, not allocation, CPU time, or RSS.
    pub fn owner_signatures(
        &self,
        owner: &EntityRef,
        limits: SignatureViewLimits,
    ) -> MddResult<impl Iterator<Item = &SignatureFact> + '_> {
        let source = self.source();
        if owner.snapshot_id != source.snapshot_id
            || owner.dex_occurrence_id != source.dex_occurrence_id
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.signatures",
                "owner belongs to another snapshot or DEX occurrence",
            ));
        }
        if self.annotation_coverage != Completeness::Complete
            || self.definitions.definition_coverage() != Completeness::Complete
            || self.definitions.metadata().metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.signatures",
                "complete metadata, definitions and annotations are required",
            ));
        }
        let (kind, definition_scan) = match owner.kind {
            EntityKind::ClassDefinition => (AnnotationOwnerKind::Class, 0usize),
            EntityKind::FieldReference => (AnnotationOwnerKind::Field, 0),
            EntityKind::FieldDefinition => (
                AnnotationOwnerKind::Field,
                self.definitions.definitions().field_definitions.len(),
            ),
            EntityKind::MethodReference => (AnnotationOwnerKind::Method, 0),
            EntityKind::MethodDefinition => (
                AnnotationOwnerKind::Method,
                self.definitions.definitions().method_definitions.len(),
            ),
            _ => {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.signatures",
                    "owner must be a class, field, or method entity",
                ));
            }
        };
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.signatures",
                "signature owner view budget exceeded",
            )
        };
        let visits = u64::try_from(self.signatures.len())
            .ok()
            .and_then(|count| count.checked_mul(2))
            .and_then(|count| u64::try_from(definition_scan).ok()?.checked_add(count))
            .ok_or_else(quota)?;
        if visits > limits.max_scanned_entries {
            return Err(quota());
        }
        // Validate the exact requested identity, including definition/reference
        // distinction, before returning an empty result.
        self.definitions.entity(owner.kind, owner.local_index)?;
        let local_index = owner.local_index;
        let matches = move |fact: &&SignatureFact| {
            fact.owner.kind == kind
                && fact.owner.reference.local_index == local_index
                && fact.owner.parameter_ordinal.is_none()
        };
        let count =
            u64::try_from(self.signatures.iter().filter(matches).count()).map_err(|_| quota())?;
        if count > limits.max_matches {
            return Err(quota());
        }
        Ok(self.signatures.iter().filter(matches))
    }
    pub fn completed_layers(&self) -> &[String] {
        &self.completed_layers
    }
    pub fn unbuilt_layers(&self) -> &[String] {
        &self.unbuilt_layers
    }
    pub fn annotation_coverage(&self) -> Completeness {
        self.annotation_coverage
    }
    pub fn require_complete_parameter_positions(&self) -> MddResult<()> {
        if self
            .data
            .parameter_lists
            .iter()
            .any(|binding| binding.prototype_position_coverage != Completeness::Complete)
        {
            return Err(MddError::new(ErrorCode::IncompleteFacts,"facts.annotations","encoded parameter slots are complete, but complete prototype-position coverage is not established")
                .detail("required_layer","prototype_parameter_annotation_positions").detail("snapshot_id",self.source().snapshot_id.clone()).detail("dex_occurrence_id",self.source().dex_occurrence_id.clone()));
        }
        Ok(())
    }
    pub fn bytes(&self) -> &[u8] {
        self.definitions.bytes()
    }
    pub fn require_relation_columns(
        &self,
        relation: AnnotationRelation,
        columns: &[&str],
    ) -> MddResult<()> {
        let available: &[&str] = match relation {
            AnnotationRelation::Directories => &[
                "file_id",
                "class_idx",
                "annotations_off",
                "class_annotations_off",
                "fields_size",
                "methods_size",
                "parameters_size",
            ],
            AnnotationRelation::DirectoryEntries => &[
                "file_id",
                "class_idx",
                "annotations_off",
                "entry_kind",
                "entry_idx",
                "annotation_set_off",
                "annotation_set_ref_list_off",
            ],
            AnnotationRelation::SetEntries => {
                &["file_id", "annotation_set_off", "ordinal", "annotation_off"]
            }
            AnnotationRelation::SetRefs => &[
                "file_id",
                "annotation_set_ref_list_off",
                "ordinal",
                "annotation_set_off",
            ],
            AnnotationRelation::Annotations => &[
                "file_id",
                "annotation_off",
                "visibility",
                "type_idx",
                "element_count",
            ],
            AnnotationRelation::Elements => &[
                "file_id",
                "annotation_off",
                "depth",
                "ordinal",
                "name_idx",
                "value_off",
                "value_end_off",
                "value_kind",
                "value_index",
                "value_i64",
                "value_f64",
            ],
        };
        for column in columns {
            if *column != "*" && !available.contains(column) {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.annotations",
                    "unknown annotation relation column",
                )
                .detail("column", (*column).to_owned()));
            }
        }
        Ok(())
    }
    pub fn directory_rows(&self, file_id: u32) -> Vec<AnnotationDirectoryRow> {
        let items: BTreeMap<_, _> = self
            .data
            .directories
            .iter()
            .map(|item| (item.byte_offset, item))
            .collect();
        self.data
            .directory_bindings
            .iter()
            .map(|binding| {
                let item = items[&binding.directory_byte_offset];
                AnnotationDirectoryRow {
                    file_id,
                    class_idx: binding.class_idx,
                    annotations_off: item.byte_offset,
                    class_annotations_off: item.class_annotation_set_offset,
                    fields_size: item.fields_size,
                    methods_size: item.methods_size,
                    parameters_size: item.parameters_size,
                }
            })
            .collect()
    }
    pub fn directory_entry_rows(&self, file_id: u32) -> Vec<AnnotationDirectoryEntryRow> {
        let items: BTreeMap<_, _> = self
            .data
            .directories
            .iter()
            .map(|item| (item.byte_offset, item))
            .collect();
        self.data
            .directory_bindings
            .iter()
            .flat_map(|binding| {
                items[&binding.directory_byte_offset]
                    .entries
                    .iter()
                    .map(move |entry| AnnotationDirectoryEntryRow {
                        file_id,
                        class_idx: binding.class_idx,
                        annotations_off: binding.directory_byte_offset,
                        entry_kind: match entry.kind {
                            AnnotationOwnerKind::Field => "field",
                            AnnotationOwnerKind::Method => "method",
                            AnnotationOwnerKind::Parameter => "parameter",
                            AnnotationOwnerKind::Class => "class",
                        }
                        .into(),
                        entry_idx: entry.local_index,
                        annotation_set_off: (entry.kind != AnnotationOwnerKind::Parameter)
                            .then_some(entry.target_byte_offset),
                        annotation_set_ref_list_off: (entry.kind == AnnotationOwnerKind::Parameter)
                            .then_some(entry.target_byte_offset),
                    })
            })
            .collect()
    }
    pub fn set_entry_rows(&self, file_id: u32) -> Vec<AnnotationSetEntryRow> {
        self.data
            .sets
            .iter()
            .flat_map(|set| {
                set.annotation_offsets
                    .iter()
                    .enumerate()
                    .map(move |(ordinal, offset)| AnnotationSetEntryRow {
                        file_id,
                        annotation_set_off: set.byte_offset,
                        ordinal: ordinal as u32,
                        annotation_off: *offset,
                    })
            })
            .collect()
    }
    pub fn set_ref_rows(&self, file_id: u32) -> Vec<AnnotationSetRefRow> {
        self.data
            .ref_lists
            .iter()
            .flat_map(|list| {
                list.annotation_set_offsets
                    .iter()
                    .enumerate()
                    .map(move |(ordinal, offset)| AnnotationSetRefRow {
                        file_id,
                        annotation_set_ref_list_off: list.byte_offset,
                        ordinal: ordinal as u32,
                        annotation_set_off: *offset,
                    })
            })
            .collect()
    }
    /// Offsets of the annotation sets and annotation items that a class
    /// annotation directory reaches, directly or through a parameter
    /// reference list.
    ///
    /// The physical row producers above enumerate every legal item in the
    /// section, including legal items that nothing references. The frozen
    /// HostLab backend enumerates only what a class-bound directory reaches, so
    /// the SQL projections use the `reachable_*` producers below. The fact layer
    /// itself keeps the unreferenced items.
    fn reachable_offsets(&self) -> (BTreeSet<u32>, BTreeSet<u32>) {
        let directories: BTreeMap<_, _> = self
            .data
            .directories
            .iter()
            .map(|item| (item.byte_offset, item))
            .collect();
        let ref_lists: BTreeMap<_, _> = self
            .data
            .ref_lists
            .iter()
            .map(|list| (list.byte_offset, list))
            .collect();
        let mut sets = BTreeSet::new();
        for binding in &self.data.directory_bindings {
            let Some(directory) = directories.get(&binding.directory_byte_offset) else {
                continue;
            };
            sets.extend(directory.class_annotation_set_offset);
            for entry in &directory.entries {
                if entry.kind == AnnotationOwnerKind::Parameter {
                    if let Some(list) = ref_lists.get(&entry.target_byte_offset) {
                        sets.extend(list.annotation_set_offsets.iter().flatten().copied());
                    }
                } else {
                    sets.insert(entry.target_byte_offset);
                }
            }
        }
        let annotations = self
            .data
            .sets
            .iter()
            .filter(|set| sets.contains(&set.byte_offset))
            .flat_map(|set| set.annotation_offsets.iter().copied())
            .collect();
        (sets, annotations)
    }
    /// `annotation_set_entries` rows of the sets a class directory reaches.
    pub fn reachable_set_entry_rows(&self, file_id: u32) -> Vec<AnnotationSetEntryRow> {
        let (sets, _) = self.reachable_offsets();
        self.set_entry_rows(file_id)
            .into_iter()
            .filter(|row| sets.contains(&row.annotation_set_off))
            .collect()
    }
    /// `annotations` rows of the items a reachable set contains.
    pub fn reachable_annotation_rows(&self, file_id: u32) -> Vec<AnnotationRow> {
        let (_, annotations) = self.reachable_offsets();
        self.annotation_rows(file_id)
            .into_iter()
            .filter(|row| annotations.contains(&row.annotation_off))
            .collect()
    }
    /// `annotation_elements` rows whose root annotation is reachable.
    pub fn reachable_element_rows(&self, file_id: u32) -> Vec<AnnotationElementRow> {
        let (_, annotations) = self.reachable_offsets();
        self.element_rows(file_id)
            .into_iter()
            .filter(|row| annotations.contains(&row.annotation_off))
            .collect()
    }
    pub fn annotation_rows(&self, file_id: u32) -> Vec<AnnotationRow> {
        self.data
            .annotation_items
            .iter()
            .map(|item| AnnotationRow {
                file_id,
                annotation_off: item.byte_offset,
                visibility: u32::from(item.visibility),
                type_idx: item.type_idx,
                element_count: item.elements.len() as u32,
            })
            .collect()
    }
    pub fn element_rows(&self, file_id: u32) -> Vec<AnnotationElementRow> {
        self.data
            .values
            .iter()
            .filter_map(|item| {
                item.annotation_byte_offset
                    .map(|root| AnnotationElementRow {
                        file_id,
                        annotation_off: root,
                        depth: item.depth,
                        ordinal: item.ordinal,
                        name_idx: item.name_idx,
                        value_off: item.encoded_range.byte_offset.0 as u32,
                        value_end_off: (item.encoded_range.byte_offset.0
                            + item.encoded_range.byte_length.0)
                            as u32,
                        value_kind: item.kind.as_str().into(),
                        value_index: item.value_index,
                        value_i64: item.value_i64.clone(),
                        value_f64: item.value_f64,
                    })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MetadataFacts;
    use mdd_dex::{definitions::DefinitionLimits, strings::StringLimits};
    use mdd_input::{
        archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
        snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
    };
    use mdd_types::DecimalU64;
    use std::path::PathBuf;
    fn build(path: &str) -> AnnotationFacts {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path);
        let snapshot = Snapshot::capture(
            &[InputSpec {
                path,
                kind: InputKind::RawDex,
                expected_sha256: None,
            }],
            CaptureLimits::default(),
        )
        .unwrap();
        let inventory = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let definitions = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
        AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap()
    }
    #[test]
    fn signature_physical_search_keeps_shared_empty_and_orphan_items() {
        for path in [
            "tests/fixtures/annotations/generated/parameter-shared-signature.dex",
            "tests/fixtures/annotations/generated/parameter-shared-empty-set.dex",
            "tests/fixtures/annotations/generated/valid-orphan-annotation.dex",
        ] {
            let facts = build(path);
            let data = &facts.data;
            assert!(
                data.sets
                    .windows(2)
                    .all(|items| items[0].byte_offset < items[1].byte_offset)
            );
            assert!(
                data.annotation_items
                    .windows(2)
                    .all(|items| items[0].byte_offset < items[1].byte_offset)
            );
            for item in &data.sets {
                assert!(std::ptr::eq(
                    physical_annotation_set(data, item.byte_offset).unwrap(),
                    item
                ));
                for offset in &item.annotation_offsets {
                    let expected = data
                        .annotation_items
                        .iter()
                        .find(|item| item.byte_offset == *offset)
                        .unwrap();
                    assert!(std::ptr::eq(
                        physical_annotation_item(data, *offset).unwrap(),
                        expected
                    ));
                }
            }
            for item in &data.annotation_items {
                assert!(std::ptr::eq(
                    physical_annotation_item(data, item.byte_offset).unwrap(),
                    item
                ));
            }
            assert_eq!(
                physical_annotation_set(data, u32::MAX).unwrap_err().code,
                ErrorCode::InternalFault
            );
            assert_eq!(
                physical_annotation_item(data, u32::MAX).unwrap_err().code,
                ErrorCode::InternalFault
            );
        }
    }
    #[test]
    fn signature_type_search_matches_linear_physical_sets() {
        for path in [
            "tests/fixtures/annotations/generated/parameter-shared-signature.dex",
            "tests/fixtures/annotations/generated/parameter-shared-empty-set.dex",
            "tests/fixtures/annotations/generated/valid-orphan-annotation.dex",
        ] {
            let facts = build(path);
            let data = &facts.data;
            for set in &data.sets {
                for target in facts
                    .definitions
                    .metadata
                    .types
                    .iter()
                    .map(|item| item.data.type_idx)
                    .chain(std::iter::once(u32::MAX))
                {
                    let expected = set
                        .annotation_offsets
                        .iter()
                        .map(|offset| physical_annotation_item(data, *offset).unwrap())
                        .find(|item| item.type_idx == target)
                        .map(|item| item.byte_offset);
                    let actual = physical_annotation_of_type(data, set, target)
                        .unwrap()
                        .map(|item| item.byte_offset);
                    assert_eq!(actual, expected, "{path}: type {target}");
                }
            }
        }
        let facts = build("tests/fixtures/annotations/generated/parameter-shared-signature.dex");
        let data = &facts.data;
        let mut bad = data
            .sets
            .iter()
            .find(|set| !set.annotation_offsets.is_empty())
            .unwrap()
            .clone();
        bad.annotation_offsets[0] = u32::MAX;
        assert_eq!(
            physical_annotation_of_type(data, &bad, 0).unwrap_err().code,
            ErrorCode::InternalFault
        );
    }
    #[test]
    fn signature_absent_preserves_shared_empty_and_orphan_sets() {
        let facts =
            build("artifacts/mdd-022/signature-type-search-20261101/no-signature-shared-empty.dex");
        assert!(
            facts
                .definitions
                .metadata
                .types
                .iter()
                .all(|item| { item.data.descriptor != "Ldalvik/annotation/Signature;" })
        );
        assert!(facts.signatures().is_empty());
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/annotations/parameter-shared-empty-set.json"
        ))
        .unwrap();
        let empty = expected["empty_set_offset"].as_u64().unwrap() as u32;
        let orphan = expected["orphan_set_offset"].as_u64().unwrap() as u32;
        assert!(
            physical_annotation_set(&facts.data, empty)
                .unwrap()
                .annotation_offsets
                .is_empty()
        );
        assert!(
            physical_annotation_set(&facts.data, orphan)
                .unwrap()
                .annotation_offsets
                .is_empty()
        );
        assert_eq!(
            facts
                .data
                .owner_bindings
                .iter()
                .filter(|owner| {
                    owner.kind == AnnotationOwnerKind::Parameter
                        && owner.annotation_set_offset == Some(empty)
                })
                .count(),
            4
        );
        assert!(
            !facts
                .data
                .owner_bindings
                .iter()
                .any(|owner| { owner.annotation_set_offset == Some(orphan) })
        );
    }
    #[test]
    fn signature_name_matches_utf16_units_without_losing_errors() {
        let base = "artifacts/mdd-022/signature-name-units-20261101/";
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../artifacts/mdd-022/signature-name-units-20261101/fixture.json"
        ))
        .unwrap();
        let signature_offset = expected["signature_byte_offset"].as_u64().unwrap();
        let valid = build(&format!("{base}valid.dex"));
        assert_eq!(valid.signatures().len(), 4);
        for name in ["long-name.dex", "surrogate-name.dex"] {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(base)
                .join(name);
            let snapshot = Snapshot::capture(
                &[InputSpec {
                    path,
                    kind: InputKind::RawDex,
                    expected_sha256: None,
                }],
                CaptureLimits::default(),
            )
            .unwrap();
            let inventory = ArchiveInventory::build(
                &snapshot.sources()[0],
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let metadata =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            if name == "surrogate-name.dex" {
                let index = expected["name_string_index"].as_u64().unwrap() as usize;
                assert_eq!(
                    metadata.strings[index].data.text.utf16_units,
                    [0x76, 0xd800, 0x65]
                );
                assert_eq!(
                    metadata.strings[index].data.text.raw_mutf8,
                    [0x76, 0xed, 0xa0, 0x80, 0x65]
                );
                assert!(metadata.strings[index].data.text.strict_utf8().is_err());
            } else {
                let index = expected["long_name_string_index"].as_u64().unwrap() as usize;
                assert_eq!(
                    metadata.strings[index].data.text.strict_utf8().unwrap(),
                    "v_infinity_float"
                );
            }
            let definitions =
                DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
            let source = definitions.metadata.source().clone();
            let error = match AnnotationFacts::build(definitions, AnnotationLimits::default()) {
                Ok(_) => panic!("invalid Signature name was accepted"),
                Err(error) => error,
            };
            assert_eq!(error.code, ErrorCode::InvalidInput, "{name}");
            let (reason, stage, offset) = if name == "surrogate-name.dex" {
                // The physical annotation reader rejects a non-scalar name
                // before Signature expansion; do not reclassify that error.
                (
                    "ANNOTATION_NAME_NON_SCALAR",
                    "dex.annotations",
                    signature_offset + 3,
                )
            } else {
                ("SIGNATURE_SHAPE", "facts.annotations", signature_offset)
            };
            assert_eq!(error.stage, stage);
            assert_eq!(
                error.details.get("reason").and_then(|value| value.as_str()),
                Some(reason)
            );
            assert_eq!(
                error
                    .details
                    .get("snapshot_id")
                    .and_then(|value| value.as_str()),
                Some(source.snapshot_id.as_str())
            );
            assert_eq!(
                error
                    .details
                    .get("dex_occurrence_id")
                    .and_then(|value| value.as_str()),
                Some(source.dex_occurrence_id.as_str())
            );
            assert_eq!(
                error
                    .details
                    .get("member_id")
                    .and_then(|value| value.as_str()),
                Some(source.member_id.as_str())
            );
            assert_eq!(
                error
                    .details
                    .get("content_id")
                    .and_then(|value| value.as_str()),
                Some(source.content_id.as_str())
            );
            assert_eq!(
                error
                    .details
                    .get("byte_offset")
                    .and_then(|value| value.as_str()),
                Some(offset.to_string().as_str())
            );
        }
    }
    #[test]
    fn signature_owner_lookup_keeps_member_kinds_and_rejects_bad_layout() {
        let facts = build("artifacts/mdd-022/signature-owner-layout-20261101/mixed-members.dex");
        let definitions = &facts.definitions;
        validate_owner_definition_layout(definitions).unwrap();
        assert_eq!(definitions.definitions.classes[0].static_fields_count, 1);
        assert_eq!(definitions.definitions.classes[0].instance_fields_count, 1);
        assert_eq!(definitions.definitions.classes[0].direct_methods_count, 1);
        assert_eq!(definitions.definitions.classes[0].virtual_methods_count, 1);
        let mut field_count = 0;
        let mut method_count = 0;
        for owner in &facts.data.owner_bindings {
            let expected = match owner.kind {
                AnnotationOwnerKind::Class => true,
                AnnotationOwnerKind::Field => {
                    field_count += 1;
                    definitions
                        .definitions
                        .field_definitions
                        .iter()
                        .any(|item| item.field_idx == owner.local_index)
                }
                _ => {
                    method_count += 1;
                    definitions
                        .definitions
                        .method_definitions
                        .iter()
                        .any(|item| item.method_idx == owner.local_index)
                }
            };
            let actual = owner_has_definition(definitions, owner).unwrap();
            assert_eq!(actual, expected);
            let projected = owner_ref(definitions, owner, actual).unwrap();
            if let Some(definition) = projected.definition {
                assert_eq!(
                    definition,
                    definitions
                        .entity(definition.kind, owner.local_index)
                        .unwrap()
                );
                assert_eq!(definition.snapshot_id, facts.source().snapshot_id);
                assert_eq!(
                    definition.dex_occurrence_id,
                    facts.source().dex_occurrence_id
                );
            }
        }
        assert!(field_count >= 2 && method_count >= 2);

        // Simulated partial definition lists preserve reference-only members;
        // the original physical fixture above always contains all four kinds.
        let mut reference_only = definitions.clone();
        reference_only.definitions.field_definitions.remove(1);
        reference_only.definitions.classes[0].instance_fields_count = 0;
        reference_only.definitions.method_definitions.remove(1);
        reference_only.definitions.classes[0].virtual_methods_count = 0;
        validate_owner_definition_layout(&reference_only).unwrap();
        for owner in &facts.data.owner_bindings {
            if owner.local_index == 1 && owner.kind != AnnotationOwnerKind::Class {
                assert!(!owner_has_definition(&reference_only, owner).unwrap());
                assert!(
                    owner_ref(&reference_only, owner, false)
                        .unwrap()
                        .definition
                        .is_none()
                );
            }
        }

        // Synthetic in-memory identities stress interleaved index domains:
        // the two individual lists are sorted, but their concatenation is not.
        let mut interleaved = definitions.clone();
        let field_static = interleaved.definitions.field_definitions[0].clone();
        let field_instance = interleaved.definitions.field_definitions[1].clone();
        let method_direct = interleaved.definitions.method_definitions[0].clone();
        let method_virtual = interleaved.definitions.method_definitions[1].clone();
        interleaved.definitions.classes[0].static_fields_count = 2;
        interleaved.definitions.classes[0].instance_fields_count = 2;
        interleaved.definitions.classes[0].direct_methods_count = 2;
        interleaved.definitions.classes[0].virtual_methods_count = 2;
        interleaved.definitions.field_definitions =
            [(0, 0, true), (3, 1, true), (1, 0, false), (2, 1, false)]
                .into_iter()
                .map(|(index, ordinal, first)| {
                    let mut item = if first {
                        field_static.clone()
                    } else {
                        field_instance.clone()
                    };
                    item.field_idx = index;
                    item.ordinal = ordinal;
                    item
                })
                .collect();
        interleaved.definitions.method_definitions =
            [(0, 0, true), (3, 1, true), (1, 0, false), (2, 1, false)]
                .into_iter()
                .map(|(index, ordinal, first)| {
                    let mut item = if first {
                        method_direct.clone()
                    } else {
                        method_virtual.clone()
                    };
                    item.method_idx = index;
                    item.ordinal = ordinal;
                    item
                })
                .collect();
        let field_reference = interleaved.definitions.field_references[0].clone();
        let method_reference = interleaved.definitions.method_references[0].clone();
        interleaved.definitions.field_references = (0..5)
            .map(|index| {
                let mut item = field_reference.clone();
                item.field_idx = index;
                item
            })
            .collect();
        interleaved.definitions.method_references = (0..5)
            .map(|index| {
                let mut item = method_reference.clone();
                item.method_idx = index;
                item
            })
            .collect();
        validate_owner_definition_layout(&interleaved).unwrap();
        let field_owner = facts
            .data
            .owner_bindings
            .iter()
            .find(|owner| owner.kind == AnnotationOwnerKind::Field)
            .unwrap();
        let method_owner = facts
            .data
            .owner_bindings
            .iter()
            .find(|owner| owner.kind == AnnotationOwnerKind::Parameter)
            .unwrap();
        for owner in [field_owner, method_owner] {
            for index in 0..5 {
                let mut candidate = owner.clone();
                candidate.local_index = index;
                let expected = index < 4;
                assert_eq!(
                    owner_has_definition(&interleaved, &candidate).unwrap(),
                    expected
                );
                assert_eq!(
                    owner_ref(&interleaved, &candidate, expected)
                        .unwrap()
                        .definition
                        .is_some(),
                    expected
                );
            }
        }
        let mut empty = definitions.clone();
        empty.definitions.classes.clear();
        empty.definitions.field_definitions.clear();
        empty.definitions.method_definitions.clear();
        validate_owner_definition_layout(&empty).unwrap();
        assert_eq!(
            owner_has_definition(&empty, field_owner).unwrap_err().code,
            ErrorCode::InternalFault
        );

        let mut broken = definitions.clone();
        broken.definitions.field_definitions.swap(0, 1);
        assert_eq!(
            validate_owner_definition_layout(&broken).unwrap_err().code,
            ErrorCode::InternalFault
        );
        let mut foreign = facts.data.owner_bindings[0].clone();
        foreign.class_idx = u32::MAX;
        assert_eq!(
            owner_has_definition(definitions, &foreign)
                .unwrap_err()
                .code,
            ErrorCode::InternalFault
        );
    }

    #[test]
    fn signature_expansion_charges_every_retained_owner_identity() {
        let facts = build("tests/fixtures/annotations/generated/parameter-shared-signature.dex");
        let source = facts.source();
        let identity_bytes =
            (source.snapshot_id.len() + source.dex_occurrence_id.len() + 32) as u64;
        let mut old_total = facts.data.usage.decoded_bytes;
        let mut missing_identities = 0u64;
        for signature in facts.signatures() {
            old_total += (signature.utf16_units.len() as u64) * 2
                + (signature.parts.len() as u64) * identity_bytes
                + 2 * identity_bytes
                + signature.string_pool_id.len() as u64;
            missing_identities += u64::from(signature.owner.definition.is_some());
        }
        assert!(
            missing_identities > 0,
            "fixture must retain owner definitions"
        );
        let exact_total = old_total + missing_identities * identity_bytes;
        let limited = AnnotationLimits {
            max_decoded_bytes: exact_total - 1,
            ..AnnotationLimits::default()
        };
        let failure = AnnotationFacts::build(facts.definitions.clone(), limited)
            .err()
            .expect("missing identity budget must not be admitted");
        assert_eq!(failure.code, ErrorCode::QuotaExceeded);
        assert_eq!(
            failure
                .details
                .get("reason")
                .and_then(|value| value.as_str()),
            Some("SIGNATURE_BYTE_BUDGET")
        );
        let exact = AnnotationFacts::build(
            facts.definitions.clone(),
            AnnotationLimits {
                max_decoded_bytes: exact_total,
                ..limited
            },
        )
        .unwrap();
        assert_eq!(exact.signatures.len(), facts.signatures.len());
    }
    #[test]
    fn physical_collection_views_preserve_bytes_nulls_and_scope() {
        let facts = build("tests/fixtures/annotations/generated/annotations-038.dex");
        let make = |kind, byte_offset| AnnotationCollectionRef {
            snapshot_id: facts.source().snapshot_id.clone(),
            dex_occurrence_id: facts.source().dex_occurrence_id.clone(),
            byte_offset,
            kind,
        };
        for set in &facts.data.sets {
            let reference = make(AnnotationCollectionKind::Set, set.byte_offset);
            let AnnotationCollectionView::Set {
                source,
                item,
                raw_encoded,
            } = facts
                .collection_by_ref(
                    &reference,
                    facts.data.sets.len() as u64,
                    set.annotation_offsets.len() as u64,
                )
                .unwrap()
            else {
                panic!("unexpected collection kind")
            };
            assert_eq!(source.dex_occurrence_id, facts.source().dex_occurrence_id);
            assert_eq!(raw_encoded.len(), 4 + item.annotation_offsets.len() * 4);
            assert_eq!(
                u32::from_le_bytes(raw_encoded[..4].try_into().unwrap()) as usize,
                item.annotation_offsets.len()
            );
            // The 4-byte framing here is len-validated above, so `chunks_exact`
            // expresses the intent more directly than `as_chunks`.
            #[allow(clippy::chunks_exact_to_as_chunks)]
            for (slot, expected) in raw_encoded[4..]
                .chunks_exact(4)
                .zip(&item.annotation_offsets)
            {
                assert_eq!(u32::from_le_bytes(slot.try_into().unwrap()), *expected);
            }
        }
        let mut saw_null = false;
        for list in &facts.data.ref_lists {
            let reference = make(AnnotationCollectionKind::SetRefList, list.byte_offset);
            let AnnotationCollectionView::SetRefList {
                item, raw_encoded, ..
            } = facts
                .collection_by_ref(
                    &reference,
                    facts.data.ref_lists.len() as u64,
                    list.annotation_set_offsets.len() as u64,
                )
                .unwrap()
            else {
                panic!("unexpected collection kind")
            };
            assert_eq!(raw_encoded.len(), 4 + item.annotation_set_offsets.len() * 4);
            assert_eq!(
                u32::from_le_bytes(raw_encoded[..4].try_into().unwrap()) as usize,
                item.annotation_set_offsets.len()
            );
            #[allow(clippy::chunks_exact_to_as_chunks)]
            for (slot, expected) in raw_encoded[4..]
                .chunks_exact(4)
                .zip(&item.annotation_set_offsets)
            {
                let raw = u32::from_le_bytes(slot.try_into().unwrap());
                assert_eq!((raw != 0).then_some(raw), *expected);
                saw_null |= expected.is_none();
            }
        }
        assert!(saw_null, "fixture must contain an encoded null slot");
        let nonempty_set = facts
            .data
            .sets
            .iter()
            .find(|v| !v.annotation_offsets.is_empty())
            .unwrap();
        let set_limited = make(AnnotationCollectionKind::Set, nonempty_set.byte_offset);
        assert_eq!(
            facts
                .collection_by_ref(
                    &set_limited,
                    u64::MAX,
                    nonempty_set.annotation_offsets.len() as u64 - 1
                )
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        let nonempty_list = facts
            .data
            .ref_lists
            .iter()
            .find(|v| !v.annotation_set_offsets.is_empty())
            .unwrap();
        let list_limited = make(
            AnnotationCollectionKind::SetRefList,
            nonempty_list.byte_offset,
        );
        assert_eq!(
            facts
                .collection_by_ref(
                    &list_limited,
                    u64::MAX,
                    nonempty_list.annotation_set_offsets.len() as u64 - 1
                )
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        let orphan = build("tests/fixtures/annotations/generated/valid-orphan-empty-set.dex");
        let empty = orphan
            .data
            .sets
            .iter()
            .find(|set| {
                set.annotation_offsets.is_empty()
                    && !orphan
                        .data
                        .owner_bindings
                        .iter()
                        .any(|owner| owner.annotation_set_offset == Some(set.byte_offset))
            })
            .expect("fixture must include an unowned empty set");
        let orphan_ref = AnnotationCollectionRef {
            snapshot_id: orphan.source().snapshot_id.clone(),
            dex_occurrence_id: orphan.source().dex_occurrence_id.clone(),
            byte_offset: empty.byte_offset,
            kind: AnnotationCollectionKind::Set,
        };
        let AnnotationCollectionView::Set {
            item, raw_encoded, ..
        } = orphan
            .collection_by_ref(&orphan_ref, orphan.data.sets.len() as u64, 0)
            .unwrap()
        else {
            panic!("unexpected orphan collection kind")
        };
        assert!(item.annotation_offsets.is_empty());
        assert_eq!(raw_encoded, [0, 0, 0, 0]);
        let set = &facts.data.sets[0];
        let reference = make(AnnotationCollectionKind::Set, set.byte_offset);
        assert_eq!(
            facts
                .collection_by_ref(&reference, 0, u64::MAX)
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        let foreign = AnnotationCollectionRef {
            snapshot_id: "other".into(),
            ..reference.clone()
        };
        assert_eq!(
            facts
                .collection_by_ref(&foreign, u64::MAX, u64::MAX)
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let fake = AnnotationCollectionRef {
            byte_offset: set.byte_offset + 1,
            ..reference.clone()
        };
        assert_eq!(
            facts
                .collection_by_ref(&fake, u64::MAX, u64::MAX)
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let mut partial = facts.clone();
        partial.annotation_coverage = Completeness::Partial;
        assert_eq!(
            partial
                .collection_by_ref(&reference, u64::MAX, u64::MAX)
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        let mut duplicate = facts.clone();
        duplicate.data.sets.push(set.clone());
        assert_eq!(
            duplicate
                .collection_by_ref(&reference, u64::MAX, u64::MAX)
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalFault
        );
    }

    #[test]
    fn owner_annotation_view_preserves_slots_sets_and_occurrences() {
        let input = InputSpec {
            path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/annotations/generated/parameter-shared-signature.dex"),
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let occurrences: Vec<_> = snapshot
            .sources()
            .iter()
            .map(|source| {
                let inventory = ArchiveInventory::build(
                    source,
                    InventoryPolicy::default(),
                    ArchiveLimits::default(),
                )
                .unwrap();
                let metadata =
                    MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default())
                        .unwrap();
                let definitions =
                    DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
                AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap()
            })
            .collect();
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/annotations/parameter-shared-signature.json"
        ))
        .unwrap();
        let expected_set = expected["parameter_set_offset"].as_u64().unwrap() as u32;
        let expected_item = expected["signature_offset"].as_u64().unwrap() as u32;
        for facts in &occurrences {
            for method_index in [0, 1] {
                let method = facts
                    .definitions()
                    .entity(EntityKind::MethodReference, method_index)
                    .unwrap();
                for slot in [0, 2] {
                    let view = facts
                        .owner_annotation_facts(
                            &method,
                            Some(slot),
                            AnnotationOwnerViewLimits::default(),
                        )
                        .unwrap()
                        .unwrap();
                    assert_eq!(
                        view.source.dex_occurrence_id,
                        facts.source().dex_occurrence_id
                    );
                    assert_eq!(view.owner.parameter_ordinal, Some(slot));
                    assert_eq!(view.owner.parameter_position_in_prototype, None);
                    assert_eq!(view.set.unwrap().byte_offset, expected_set);
                    assert_eq!(view.annotations.len(), 1);
                    assert_eq!(view.annotations[0].annotation.byte_offset, expected_item);
                    assert_eq!(view.annotations[0].set_ordinal, 0);
                }
                let zero = facts
                    .owner_annotation_facts(&method, Some(1), AnnotationOwnerViewLimits::default())
                    .unwrap()
                    .unwrap();
                assert!(zero.set.is_none());
                assert!(zero.annotations.is_empty());
                assert!(
                    facts
                        .owner_annotation_facts(
                            &method,
                            Some(3),
                            AnnotationOwnerViewLimits::default()
                        )
                        .unwrap()
                        .is_none()
                );
                assert_eq!(
                    facts
                        .owner_annotation_facts(
                            &method,
                            Some(0),
                            AnnotationOwnerViewLimits {
                                max_scanned_entries: u64::MAX,
                                max_matches: 0,
                            }
                        )
                        .err()
                        .unwrap()
                        .code,
                    ErrorCode::QuotaExceeded
                );
                assert_eq!(
                    facts
                        .owner_annotation_facts(
                            &method,
                            Some(0),
                            AnnotationOwnerViewLimits {
                                max_scanned_entries: 0,
                                max_matches: u64::MAX,
                            }
                        )
                        .err()
                        .unwrap()
                        .code,
                    ErrorCode::QuotaExceeded
                );
            }
            let method = facts
                .definitions()
                .entity(EntityKind::MethodReference, 0)
                .unwrap();
            let direct = facts
                .owner_annotation_facts(&method, None, AnnotationOwnerViewLimits::default())
                .unwrap()
                .unwrap();
            assert_eq!(direct.owner.kind, AnnotationOwnerKind::Method);
            assert_eq!(direct.annotations.len(), 1);
            assert_eq!(direct.annotations[0].annotation.byte_offset, expected_item);
        }
        let foreign = occurrences[1]
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        assert_eq!(
            occurrences[0]
                .owner_annotation_facts(&foreign, Some(0), AnnotationOwnerViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );

        let mut broken = occurrences[0].clone();
        let method = broken
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        broken
            .data
            .sets
            .iter_mut()
            .find(|set| set.byte_offset == expected_set)
            .unwrap()
            .encoded_range
            .byte_length = DecimalU64(u64::MAX);
        assert_eq!(
            broken
                .owner_annotation_facts(&method, Some(0), AnnotationOwnerViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalFault
        );
        let mut broken = occurrences[0].clone();
        broken
            .data
            .annotation_items
            .iter_mut()
            .find(|item| item.byte_offset == expected_item)
            .unwrap()
            .encoded_range
            .byte_length = DecimalU64(u64::MAX);
        assert_eq!(
            broken
                .owner_annotation_facts(&method, Some(0), AnnotationOwnerViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalFault
        );

        let facts = build("tests/fixtures/annotations/generated/parameter-shared-empty-set.dex");
        let method = facts
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        let empty = facts
            .owner_annotation_facts(&method, Some(0), AnnotationOwnerViewLimits::default())
            .unwrap()
            .unwrap();
        assert!(empty.set.is_some());
        assert!(empty.annotations.is_empty());
        let zero = facts
            .owner_annotation_facts(&method, Some(1), AnnotationOwnerViewLimits::default())
            .unwrap()
            .unwrap();
        assert!(zero.set.is_none());
        let mut partial = facts.clone();
        partial.annotation_coverage = Completeness::Unknown;
        assert_eq!(
            partial
                .owner_annotation_facts(&method, Some(0), AnnotationOwnerViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
    }

    #[test]
    fn annotation_owner_view_preserves_shared_sets_slots_and_scope() {
        let facts = build("tests/fixtures/annotations/generated/annotations-038.dex");
        let reference = |offset| AnnotationRef {
            snapshot_id: facts.source().snapshot_id.clone(),
            dex_occurrence_id: facts.source().dex_occurrence_id.clone(),
            annotation_byte_offset: offset,
        };
        // The independent fixture lists set 1164 for two distinct fields,
        // both pointing to physical annotation 1120 at ordinal zero.
        let fields = facts
            .annotation_owner_facts(&reference(1120), AnnotationOwnerViewLimits::default())
            .unwrap();
        let got = fields
            .iter()
            .map(|fact| {
                (
                    fact.owner.kind,
                    fact.owner.local_index,
                    fact.set.byte_offset,
                    fact.set_ordinal,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            got,
            vec![
                (AnnotationOwnerKind::Field, 0, 1164, 0),
                (AnnotationOwnerKind::Field, 1, 1164, 0)
            ]
        );
        assert!(fields.iter().all(|fact| fact.source.dex_occurrence_id
            == facts.source().dex_occurrence_id
            && fact.annotation.byte_offset == 1120));

        // 1012 occurs once in the class set and once in the parameter set;
        // that parameter set is referenced by two methods at encoded slot 0.
        let owners = facts
            .annotation_owner_facts(&reference(1012), AnnotationOwnerViewLimits::default())
            .unwrap();
        let got = owners
            .iter()
            .map(|fact| {
                (
                    fact.owner.kind,
                    fact.owner.local_index,
                    fact.owner.parameter_ordinal,
                    fact.set.byte_offset,
                    fact.set_ordinal,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].0, AnnotationOwnerKind::Class);
        assert_eq!((got[0].3, got[0].4), (1152, 1));
        assert_eq!(
            got[1],
            (AnnotationOwnerKind::Parameter, 0, Some(0), 1180, 0)
        );
        assert_eq!(
            got[2],
            (AnnotationOwnerKind::Parameter, 1, Some(0), 1180, 0)
        );

        let visits = facts.data.annotation_items.len() as u64
            + facts.data.owner_bindings.len() as u64
            + facts
                .data
                .owner_bindings
                .iter()
                .filter_map(|owner| owner.annotation_set_offset)
                .map(|offset| {
                    facts.data.sets.len() as u64
                        + facts
                            .data
                            .sets
                            .iter()
                            .find(|set| set.byte_offset == offset)
                            .unwrap()
                            .annotation_offsets
                            .len() as u64
                })
                .sum::<u64>();
        assert_eq!(
            facts
                .annotation_owner_facts(
                    &reference(1012),
                    AnnotationOwnerViewLimits {
                        max_scanned_entries: visits,
                        max_matches: 3
                    }
                )
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            facts
                .annotation_owner_facts(
                    &reference(1012),
                    AnnotationOwnerViewLimits {
                        max_scanned_entries: visits - 1,
                        max_matches: 3
                    }
                )
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            facts
                .annotation_owner_facts(
                    &reference(1012),
                    AnnotationOwnerViewLimits {
                        max_scanned_entries: visits,
                        max_matches: 2
                    }
                )
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            facts
                .annotation_owner_facts(&reference(1013), AnnotationOwnerViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let mut foreign = reference(1012);
        foreign.dex_occurrence_id = "foreign".into();
        assert_eq!(
            facts
                .annotation_owner_facts(&foreign, AnnotationOwnerViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let mut partial = facts.clone();
        partial.annotation_coverage = Completeness::Partial;
        assert_eq!(
            partial
                .annotation_owner_facts(&reference(1012), AnnotationOwnerViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        // Injected inconsistent state must be an internal error, never empty success.
        let mut broken = facts.clone();
        broken.data.owner_bindings[0].annotation_set_offset = Some(u32::MAX);
        assert_eq!(
            broken
                .annotation_owner_facts(&reference(1012), AnnotationOwnerViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalFault
        );
        let mut orphan = facts.clone();
        orphan.data.owner_bindings.clear();
        assert!(
            orphan
                .annotation_owner_facts(&reference(1012), AnnotationOwnerViewLimits::default())
                .unwrap()
                .is_empty()
        );

        // Two captured occurrences of the same physical bytes remain distinct.
        let input = InputSpec {
            path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/annotations/generated/annotations-038.dex"),
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let occurrences: Vec<_> = snapshot
            .sources()
            .iter()
            .map(|source| {
                let inventory = ArchiveInventory::build(
                    source,
                    InventoryPolicy::default(),
                    ArchiveLimits::default(),
                )
                .unwrap();
                let metadata =
                    MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default())
                        .unwrap();
                let definitions =
                    DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
                AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap()
            })
            .collect();
        assert_ne!(
            occurrences[0].source().dex_occurrence_id,
            occurrences[1].source().dex_occurrence_id
        );
        let from_second = AnnotationRef {
            snapshot_id: snapshot.manifest().snapshot_id.clone(),
            dex_occurrence_id: occurrences[1].source().dex_occurrence_id.clone(),
            annotation_byte_offset: 1120,
        };
        assert_eq!(
            occurrences[1]
                .annotation_owner_facts(&from_second, AnnotationOwnerViewLimits::default())
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            occurrences[0]
                .annotation_owner_facts(&from_second, AnnotationOwnerViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
    }
    #[test]
    fn shared_call_sites_retain_independent_identity_and_physical_bytes() {
        let facts = build("artifacts/mdd-022/shared-callsite-view-20261101/shared.dex");
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../artifacts/mdd-022/shared-callsite-view-20261101/fixture.json"
        ))
        .unwrap();
        let array_offset = fixture["array_offset"].as_u64().unwrap() as u32;
        let section_offset = fixture["call_site_ids_offset"].as_u64().unwrap() as usize;
        let make = |call_site_idx| EncodedCallSiteRef {
            snapshot_id: facts.source().snapshot_id.clone(),
            dex_occurrence_id: facts.source().dex_occurrence_id.clone(),
            call_site_idx,
        };
        let limits = AnnotationOwnerViewLimits {
            max_scanned_entries: 2,
            max_matches: 1,
        };
        for index in 0..2 {
            let view = facts
                .encoded_call_site(&make(index), limits)
                .unwrap()
                .unwrap();
            assert_eq!(
                view.source.dex_occurrence_id,
                facts.source().dex_occurrence_id
            );
            assert_eq!(view.binding.call_site_idx, index);
            assert_eq!(view.array.byte_offset, array_offset);
            let at = section_offset + 4 * index as usize;
            assert_eq!(&facts.bytes()[at..at + 4], &array_offset.to_le_bytes());
            assert_eq!(view.raw_encoded.len(), 7);
            assert_eq!(view.raw_encoded[0], 3);
            assert_eq!(view.raw_encoded[1], 0x16);
            assert_eq!(view.raw_encoded[3], 0x17);
            assert_eq!(view.raw_encoded[5], 0x15);
            assert_eq!(
                view.binding.bootstrap_method_handle_idx,
                u32::from(view.raw_encoded[2])
            );
            assert_eq!(view.binding.name_string_idx, u32::from(view.raw_encoded[4]));
            assert_eq!(view.binding.method_type_idx, u32::from(view.raw_encoded[6]));
        }
        let array_ref = EncodedArrayRef {
            snapshot_id: facts.source().snapshot_id.clone(),
            dex_occurrence_id: facts.source().dex_occurrence_id.clone(),
            byte_offset: array_offset,
        };
        let reverse = facts
            .encoded_array_bindings(&array_ref, AnnotationOwnerViewLimits::default())
            .unwrap();
        let indices: Vec<_> = reverse
            .bindings
            .iter()
            .map(|binding| match binding {
                EncodedArrayBinding::CallSite(call) => call.call_site_idx,
                _ => panic!("unexpected static array binding"),
            })
            .collect();
        assert_eq!(indices, [0, 1]);
        assert!(facts.encoded_call_site(&make(2), limits).unwrap().is_none());
        for invalid_limits in [
            AnnotationOwnerViewLimits {
                max_scanned_entries: 1,
                max_matches: 1,
            },
            AnnotationOwnerViewLimits {
                max_scanned_entries: 2,
                max_matches: 0,
            },
        ] {
            assert_eq!(
                facts
                    .encoded_call_site(&make(0), invalid_limits)
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
        }
        let mut foreign = make(0);
        foreign.dex_occurrence_id = "foreign".into();
        assert_eq!(
            facts
                .encoded_call_site(&foreign, limits)
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let mut partial = facts.clone();
        partial.annotation_coverage = Completeness::Partial;
        assert_eq!(
            partial
                .encoded_call_site(&make(2), limits)
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        let mut corrupted = facts.clone();
        corrupted.data.call_site_arrays[1].encoded_array_index = u32::MAX;
        assert_eq!(
            corrupted
                .encoded_call_site(&make(1), limits)
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalFault
        );
    }
    #[test]
    fn nested_annotation_in_array_keeps_tree_and_cross_array_identity() {
        let facts = build("artifacts/mdd-022/nested-annotation-array-20261101/nested.dex");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../artifacts/mdd-022/nested-annotation-array-20261101/fixture.json"
        ))
        .unwrap();
        let make = |field: &str| EncodedArrayRef {
            snapshot_id: facts.source().snapshot_id.clone(),
            dex_occurrence_id: facts.source().dex_occurrence_id.clone(),
            byte_offset: expected[field].as_u64().unwrap() as u32,
        };
        let first = make("first_array_offset");
        let second = make("second_array_offset");
        let limits = AnnotationValueViewLimits::default();
        let first_view = facts.encoded_array_view(&first, limits).unwrap();
        let view = facts.encoded_array_view(&second, limits).unwrap();
        let ty = expected["nested_type_index"].as_u64().unwrap() as u8;
        let name = expected["element_name_index"].as_u64().unwrap() as u8;
        assert_eq!(first_view.raw_encoded, &[1, 0x04, 0x2a]);
        assert_eq!(
            view.raw_encoded,
            &[1, 0x1d, ty, 1, name, 0x1c, 2, 0x1e, 0x3f]
        );
        assert_eq!(view.values.len(), 4);
        let root = &view.values[0];
        let nested = &view.values[1];
        let null = &view.values[2];
        let boolean = &view.values[3];
        assert_eq!(root.value.kind, EncodedKind::Annotation);
        assert_eq!(root.value.value_index, Some(u32::from(ty)));
        assert_eq!(root.value.depth, 0);
        assert_eq!(root.value.children, vec![nested.value.node_id]);
        assert_eq!(root.raw_encoded, &view.raw_encoded[1..]);
        assert_eq!(nested.value.kind, EncodedKind::Array);
        assert_eq!(nested.value.name_idx, Some(u32::from(name)));
        assert_eq!(nested.value.depth, 1);
        assert_eq!(
            nested.value.children,
            vec![null.value.node_id, boolean.value.node_id]
        );
        assert_eq!(nested.raw_encoded, &[0x1c, 2, 0x1e, 0x3f]);
        assert_eq!(null.value.kind, EncodedKind::Null);
        assert_eq!(null.value.depth, 2);
        assert_eq!(null.raw_encoded, &[0x1e]);
        assert_eq!(boolean.value.kind, EncodedKind::Boolean);
        assert_eq!(boolean.value.depth, 2);
        assert_eq!(boolean.value.ordinal, 1);
        assert_eq!(boolean.value.value_i64.as_deref(), Some("1"));
        assert_eq!(boolean.raw_encoded, &[0x3f]);
        let ref_for = |array: EncodedArrayRef, node_id| EncodedArrayValueRef { array, node_id };
        let nested_ref = ref_for(second.clone(), nested.value.node_id);
        let direct = facts
            .encoded_array_value(&nested_ref, limits)
            .unwrap()
            .unwrap();
        assert_eq!(direct.raw_encoded, nested.raw_encoded);
        assert!(
            facts
                .encoded_array_value(&ref_for(first.clone(), nested.value.node_id), limits)
                .unwrap()
                .is_none()
        );
        assert!(
            facts
                .encoded_array_value(&ref_for(second, first_view.values[0].value.node_id), limits)
                .unwrap()
                .is_none()
        );
        assert_eq!(first_view.values[0].value.value_i64.as_deref(), Some("42"));
    }
    #[test]
    fn nested_array_direct_value_is_source_bound_and_preserves_raw_tree() {
        let facts = build("artifacts/mdd-022/nested-array-direct-20261101/nested.dex");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../artifacts/mdd-022/nested-array-direct-20261101/fixture.json"
        ))
        .unwrap();
        let array_ref = EncodedArrayRef {
            snapshot_id: facts.source().snapshot_id.clone(),
            dex_occurrence_id: facts.source().dex_occurrence_id.clone(),
            byte_offset: expected["array_offset"].as_u64().unwrap() as u32,
        };
        let all = facts
            .encoded_array_view(&array_ref, AnnotationValueViewLimits::default())
            .unwrap();
        assert_eq!(all.raw_encoded, &[1, 0x1c, 1, 0x1e]);
        assert_eq!(all.values.len(), 2);
        let parent_id = all.array.elements[0];
        let parent_ref = EncodedArrayValueRef {
            array: array_ref.clone(),
            node_id: parent_id,
        };
        let parent = facts
            .encoded_array_value(&parent_ref, AnnotationValueViewLimits::default())
            .unwrap()
            .unwrap();
        assert_eq!(parent.source.dex_occurrence_id, array_ref.dex_occurrence_id);
        assert_eq!(parent.value.kind, EncodedKind::Array);
        assert_eq!(parent.value.depth, 0);
        assert_eq!(parent.raw_encoded, &[0x1c, 1, 0x1e]);
        assert_eq!(parent.value.children.len(), 1);
        let child_ref = EncodedArrayValueRef {
            array: array_ref.clone(),
            node_id: parent.value.children[0],
        };
        let child = facts
            .encoded_array_value(&child_ref, AnnotationValueViewLimits::default())
            .unwrap()
            .unwrap();
        assert_eq!(child.value.kind, EncodedKind::Null);
        assert_eq!(child.value.depth, 1);
        assert_eq!(child.value.ordinal, 0);
        assert_eq!(child.raw_encoded, &[0x1e]);
        assert_eq!(all.values[1].value.node_id, child.value.node_id);
        let visits = facts.data.encoded_arrays.len() as u64 + 1;
        for limits in [
            AnnotationValueViewLimits {
                max_scanned_entries: visits - 1,
                max_values: 1,
            },
            AnnotationValueViewLimits {
                max_scanned_entries: visits,
                max_values: 0,
            },
        ] {
            assert_eq!(
                facts
                    .encoded_array_value(&child_ref, limits)
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
        }
        assert!(
            facts
                .encoded_array_value(
                    &child_ref,
                    AnnotationValueViewLimits {
                        max_scanned_entries: visits,
                        max_values: 1
                    }
                )
                .unwrap()
                .is_some()
        );
        let mut bad = child_ref.clone();
        bad.array.byte_offset += 1;
        assert_eq!(
            facts
                .encoded_array_value(&bad, AnnotationValueViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        bad = child_ref.clone();
        bad.array.dex_occurrence_id = "foreign".into();
        assert_eq!(
            facts
                .encoded_array_value(&bad, AnnotationValueViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        bad = child_ref.clone();
        bad.node_id = u32::MAX;
        assert!(
            facts
                .encoded_array_value(&bad, AnnotationValueViewLimits::default())
                .unwrap()
                .is_none()
        );
        bad.node_id = facts
            .data
            .values
            .iter()
            .find(|v| v.annotation_byte_offset.is_some())
            .unwrap()
            .node_id;
        assert!(
            facts
                .encoded_array_value(&bad, AnnotationValueViewLimits::default())
                .unwrap()
                .is_none()
        );
        let mut partial = facts.clone();
        partial.annotation_coverage = Completeness::Partial;
        assert_eq!(
            partial
                .encoded_array_value(&child_ref, AnnotationValueViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        let mut corrupted = facts.clone();
        corrupted.data.values[child_ref.node_id as usize]
            .encoded_range
            .byte_length
            .0 = 2;
        assert_eq!(
            corrupted
                .encoded_array_value(&child_ref, AnnotationValueViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalFault
        );
    }

    #[test]
    fn encoded_array_bindings_keep_shared_classes_call_sites_and_orphans() {
        let facts = build("artifacts/mdd-022/array-bindings-20261101/shared-static-empty.dex");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../artifacts/mdd-022/array-bindings-20261101/fixture.json"
        ))
        .unwrap();
        let offset = expected["array_offset"].as_u64().unwrap() as u32;
        let reference = EncodedArrayRef {
            snapshot_id: facts.source().snapshot_id.clone(),
            dex_occurrence_id: facts.source().dex_occurrence_id.clone(),
            byte_offset: offset,
        };
        let result = facts
            .encoded_array_bindings(&reference, AnnotationOwnerViewLimits::default())
            .unwrap();
        assert_eq!(result.source.dex_occurrence_id, reference.dex_occurrence_id);
        assert_eq!(result.array.byte_offset, offset);
        assert_eq!(result.bindings.len(), 2);
        for (ordinal, binding) in result.bindings.iter().enumerate() {
            let EncodedArrayBinding::StaticValues(class) = binding else {
                panic!("expected class binding")
            };
            assert_eq!(class.class_def_idx, ordinal as u32);
            let at = class.encoded_range.byte_offset.0 as usize + 28;
            assert_eq!(&facts.bytes()[at..at + 4], &offset.to_le_bytes());
        }
        let visits = facts.data.encoded_arrays.len() as u64
            + facts.definitions.definitions.classes.len() as u64
            + facts.data.call_site_arrays.len() as u64;
        for limits in [
            AnnotationOwnerViewLimits {
                max_scanned_entries: visits - 1,
                max_matches: 2,
            },
            AnnotationOwnerViewLimits {
                max_scanned_entries: visits,
                max_matches: 1,
            },
        ] {
            assert_eq!(
                facts
                    .encoded_array_bindings(&reference, limits)
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
        }
        let result = facts
            .encoded_array_bindings(
                &reference,
                AnnotationOwnerViewLimits {
                    max_scanned_entries: visits,
                    max_matches: 2,
                },
            )
            .unwrap();
        assert_eq!(result.bindings.len(), 2);
        let mut bad = reference.clone();
        bad.dex_occurrence_id = "foreign".into();
        assert_eq!(
            facts
                .encoded_array_bindings(&bad, AnnotationOwnerViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        bad = reference.clone();
        bad.byte_offset += 2;
        assert_eq!(
            facts
                .encoded_array_bindings(&bad, AnnotationOwnerViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let mut incomplete = facts.clone();
        incomplete.annotation_coverage = Completeness::Partial;
        assert_eq!(
            incomplete
                .encoded_array_bindings(&reference, AnnotationOwnerViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );

        let orphan = build("tests/fixtures/annotations/generated/valid-orphan-arrays.dex");
        let orphan_ref = EncodedArrayRef {
            snapshot_id: orphan.source().snapshot_id.clone(),
            dex_occurrence_id: orphan.source().dex_occurrence_id.clone(),
            byte_offset: orphan.data.encoded_arrays[0].byte_offset,
        };
        assert!(
            orphan
                .encoded_array_bindings(&orphan_ref, AnnotationOwnerViewLimits::default())
                .unwrap()
                .bindings
                .is_empty()
        );

        let call = build("tests/fixtures/annotations/generated/valid-call-site-array.dex");
        let call_ref = EncodedArrayRef {
            snapshot_id: call.source().snapshot_id.clone(),
            dex_occurrence_id: call.source().dex_occurrence_id.clone(),
            byte_offset: call.data.encoded_arrays[0].byte_offset,
        };
        let result = call
            .encoded_array_bindings(&call_ref, AnnotationOwnerViewLimits::default())
            .unwrap();
        let [EncodedArrayBinding::CallSite(binding)] = result.bindings.as_slice() else {
            panic!("expected call site")
        };
        assert_eq!(binding.call_site_idx, 0);
        assert_eq!(binding.encoded_array_byte_offset, call_ref.byte_offset);
        let mut corrupted = call.clone();
        corrupted.data.call_site_arrays[0].encoded_array_index = u32::MAX;
        assert_eq!(
            corrupted
                .encoded_array_bindings(&call_ref, AnnotationOwnerViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalFault
        );
    }
    #[test]
    fn encoded_array_view_retains_physical_items_and_enforces_scope() {
        let facts = build("tests/fixtures/annotations/generated/valid-orphan-arrays.dex");
        assert_eq!(facts.data.encoded_arrays.len(), 2);
        let reference = |offset| EncodedArrayRef {
            snapshot_id: facts.source().snapshot_id.clone(),
            dex_occurrence_id: facts.source().dex_occurrence_id.clone(),
            byte_offset: offset,
        };
        let empty = reference(facts.data.encoded_arrays[0].byte_offset);
        let populated = reference(facts.data.encoded_arrays[1].byte_offset);
        let view = facts
            .encoded_array_view(&empty, AnnotationValueViewLimits::default())
            .unwrap();
        assert_eq!(view.raw_encoded, &[0]);
        assert!(view.values.is_empty());
        let view = facts
            .encoded_array_view(&populated, AnnotationValueViewLimits::default())
            .unwrap();
        assert_eq!(view.source.dex_occurrence_id, populated.dex_occurrence_id);
        assert_eq!(view.raw_encoded.len(), 3);
        assert_eq!(view.raw_encoded[0..2], [1, 0x17]);
        assert_eq!(view.values.len(), 1);
        assert_eq!(view.values[0].value.kind, EncodedKind::String);
        assert_eq!(view.values[0].raw_encoded, &view.raw_encoded[1..]);
        let visits =
            facts.data.encoded_arrays.len() as u64 + 2 * facts.data.values.len() as u64 + 1;
        assert_eq!(
            facts
                .encoded_array_view(
                    &populated,
                    AnnotationValueViewLimits {
                        max_scanned_entries: visits - 1,
                        max_values: 1
                    }
                )
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            facts
                .encoded_array_view(
                    &populated,
                    AnnotationValueViewLimits {
                        max_scanned_entries: visits,
                        max_values: 0
                    }
                )
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            facts
                .encoded_array_view(
                    &populated,
                    AnnotationValueViewLimits {
                        max_scanned_entries: visits,
                        max_values: 1
                    }
                )
                .unwrap()
                .values
                .len(),
            1
        );
        let mut invalid = populated.clone();
        invalid.byte_offset += 1;
        assert_eq!(
            facts
                .encoded_array_view(&invalid, AnnotationValueViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        invalid = populated.clone();
        invalid.dex_occurrence_id = "foreign".into();
        assert_eq!(
            facts
                .encoded_array_view(&invalid, AnnotationValueViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let mut partial = facts.clone();
        partial.annotation_coverage = Completeness::Partial;
        assert_eq!(
            partial
                .encoded_array_view(&populated, AnnotationValueViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        let mut corrupted = facts.clone();
        let root = corrupted.data.encoded_arrays[1].elements[0] as usize;
        corrupted.data.values[root].ordinal = 42;
        assert_eq!(
            corrupted
                .encoded_array_view(&populated, AnnotationValueViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalFault
        );

        let call = build("tests/fixtures/annotations/generated/valid-call-site-array.dex");
        let item = &call.data.encoded_arrays[0];
        let reference = EncodedArrayRef {
            snapshot_id: call.source().snapshot_id.clone(),
            dex_occurrence_id: call.source().dex_occurrence_id.clone(),
            byte_offset: item.byte_offset,
        };
        let view = call
            .encoded_array_view(&reference, AnnotationValueViewLimits::default())
            .unwrap();
        assert_eq!(view.raw_encoded[0], 3);
        assert_eq!(
            view.values
                .iter()
                .map(|value| value.value.kind)
                .collect::<Vec<_>>(),
            vec![
                EncodedKind::MethodHandle,
                EncodedKind::String,
                EncodedKind::MethodType
            ]
        );
        assert_eq!(
            call.data.call_site_arrays[0].encoded_array_byte_offset,
            view.array.byte_offset
        );
    }
    #[test]
    fn annotation_value_view_preserves_raw_nodes_scope_and_budgets() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/annotations/generated/annotations-038.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let mut facts = Vec::new();
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let metadata =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            let definitions =
                DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
            facts.push(AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap());
        }
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/annotations/oracle-results.json"
        ))
        .unwrap();
        let expected = oracle["positive"]["annotation_elements"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["annotation_off"].as_u64() == Some(1012))
            .collect::<Vec<_>>();
        assert!(!expected.is_empty());
        let mut occurrences = Vec::new();
        for item in &facts {
            let annotation = AnnotationRef {
                snapshot_id: snapshot.manifest().snapshot_id.clone(),
                dex_occurrence_id: item.source().dex_occurrence_id.clone(),
                annotation_byte_offset: 1012,
            };
            let values = item
                .annotation_value_facts(&annotation, AnnotationValueViewLimits::default())
                .unwrap()
                .collect::<MddResult<Vec<_>>>()
                .unwrap();
            assert_eq!(values.len(), expected.len());
            for (actual, reference) in values.iter().zip(&expected) {
                assert_eq!(
                    actual.source.dex_occurrence_id,
                    annotation.dex_occurrence_id
                );
                assert_eq!(actual.annotation.byte_offset, 1012);
                assert_eq!(
                    u64::from(actual.value.depth),
                    reference["depth"].as_u64().unwrap()
                );
                assert_eq!(
                    u64::from(actual.value.ordinal),
                    reference["ordinal"].as_u64().unwrap()
                );
                assert_eq!(
                    actual.value.kind.as_str(),
                    reference["value_kind"].as_str().unwrap()
                );
                assert_eq!(
                    actual.value.value_index.map(u64::from),
                    reference["value_index"].as_u64()
                );
                let start = reference["value_off"].as_u64().unwrap() as usize;
                let end = reference["value_end_off"].as_u64().unwrap() as usize;
                assert_eq!(actual.raw_encoded, &item.bytes()[start..end]);
            }
            assert!(
                values
                    .iter()
                    .any(|node| node.value.kind == EncodedKind::Null && node.raw_encoded == [0x1e])
            );
            assert!(
                values
                    .iter()
                    .any(|node| node.value.kind == EncodedKind::Float
                        && node.value.float_bit_width == Some(32)
                        && node.value.float_bits == Some(DecimalU64(0x8000_0000)))
            );
            let root = item
                .data
                .annotation_items
                .iter()
                .find(|node| node.byte_offset == 1012)
                .unwrap();
            let visits = item.data.annotation_items.len() as u64
                + 2 * item.data.values.len() as u64
                + root.elements.len() as u64;
            assert_eq!(
                item.annotation_value_facts(
                    &annotation,
                    AnnotationValueViewLimits {
                        max_scanned_entries: visits - 1,
                        ..AnnotationValueViewLimits::default()
                    }
                )
                .err()
                .unwrap()
                .code,
                ErrorCode::QuotaExceeded
            );
            assert_eq!(
                item.annotation_value_facts(
                    &annotation,
                    AnnotationValueViewLimits {
                        max_scanned_entries: visits,
                        max_values: expected.len() as u64,
                    }
                )
                .unwrap()
                .count(),
                expected.len()
            );
            assert_eq!(
                item.annotation_value_facts(
                    &annotation,
                    AnnotationValueViewLimits {
                        max_values: expected.len() as u64 - 1,
                        ..AnnotationValueViewLimits::default()
                    }
                )
                .err()
                .unwrap()
                .code,
                ErrorCode::QuotaExceeded
            );
            let mut interior = annotation.clone();
            interior.annotation_byte_offset += 1;
            assert_eq!(
                item.annotation_value_facts(&interior, AnnotationValueViewLimits::default())
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::InvalidArgument
            );
            let mut foreign = annotation.clone();
            foreign.snapshot_id = "other".into();
            assert_eq!(
                item.annotation_value_facts(&foreign, AnnotationValueViewLimits::default())
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::InvalidArgument
            );
            let mut partial = item.clone();
            partial.annotation_coverage = Completeness::Partial;
            assert_eq!(
                partial
                    .annotation_value_facts(&annotation, AnnotationValueViewLimits::default())
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::IncompleteFacts
            );
            let mut corrupt = item.clone();
            let node = corrupt
                .data
                .values
                .iter_mut()
                .find(|node| node.annotation_byte_offset == Some(1012))
                .unwrap();
            node.encoded_range.byte_offset = DecimalU64(1011);
            assert_eq!(
                corrupt
                    .annotation_value_facts(&annotation, AnnotationValueViewLimits::default())
                    .unwrap()
                    .next()
                    .unwrap()
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::InternalFault
            );
            occurrences.push(annotation.dex_occurrence_id);
        }
        assert_ne!(occurrences[0], occurrences[1]);
        let cross = AnnotationRef {
            snapshot_id: facts[0].source().snapshot_id.clone(),
            dex_occurrence_id: facts[1].source().dex_occurrence_id.clone(),
            annotation_byte_offset: 1012,
        };
        assert_eq!(
            facts[0]
                .annotation_value_facts(&cross, AnnotationValueViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
    }
    #[test]
    fn encoded_parameter_list_retains_unknown_positions_and_physical_bytes() {
        let short = build("tests/fixtures/annotations/generated/bad-parameter-arity.dex");
        let method = short
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        let view = short
            .method_encoded_parameter_list(&method, ParameterViewLimits::default())
            .unwrap()
            .unwrap();
        assert_eq!(
            view.source.dex_occurrence_id,
            short.source().dex_occurrence_id
        );
        assert_eq!(
            view.binding.prototype_position_coverage,
            Completeness::Unknown
        );
        assert_eq!(view.binding.prototype_parameter_count, 2);
        assert_eq!(view.binding.encoded_slot_count, 1);
        assert_eq!(view.list.annotation_set_offsets.len(), 1);
        let raw = view.raw_encoded;
        assert_eq!(raw.len(), 8);
        assert_eq!(u32::from_le_bytes(raw[0..4].try_into().unwrap()), 1);
        let encoded_set = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        assert_eq!(
            view.list.annotation_set_offsets[0],
            (encoded_set != 0).then_some(encoded_set)
        );
        assert_eq!(
            short
                .method_parameter_facts(&method, ParameterViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        for limits in [
            ParameterViewLimits {
                max_scan_entries: 0,
                ..ParameterViewLimits::default()
            },
            ParameterViewLimits {
                max_parameters: 0,
                ..ParameterViewLimits::default()
            },
        ] {
            assert_eq!(
                short
                    .method_encoded_parameter_list(&method, limits)
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
        }
        let mut partial = short.clone();
        partial.annotation_coverage = Completeness::Unknown;
        assert_eq!(
            partial
                .method_encoded_parameter_list(&method, ParameterViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        let mut incomplete_slots = short.clone();
        incomplete_slots.data.parameter_lists[0].encoded_slots_complete = false;
        assert_eq!(
            incomplete_slots
                .method_encoded_parameter_list(&method, ParameterViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        let mut duplicate = short.clone();
        duplicate
            .data
            .parameter_lists
            .push(duplicate.data.parameter_lists[0].clone());
        assert_eq!(
            duplicate
                .method_encoded_parameter_list(&method, ParameterViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalFault
        );
        let other = build("tests/fixtures/annotations/generated/bad-parameter-arity.dex");
        let foreign = other
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        assert_eq!(
            short
                .method_encoded_parameter_list(&foreign, ParameterViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let plain = build("tests/fixtures/definitions/generated/definitions-035.dex");
        let external = plain
            .definitions()
            .definitions()
            .method_references
            .iter()
            .find(|m| m.method_name == "externalCall")
            .unwrap();
        let unbound = plain
            .definitions()
            .entity(EntityKind::MethodReference, external.method_idx)
            .unwrap();
        assert!(
            plain
                .method_encoded_parameter_list(&unbound, ParameterViewLimits::default())
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn method_parameter_view_distinguishes_missing_list_zero_slot_and_unknown_position() {
        let facts = build("tests/fixtures/annotations/generated/annotations-038.dex");
        let reference = facts
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        let definition = facts
            .definitions()
            .entity(EntityKind::MethodDefinition, 0)
            .unwrap();
        for method in [&reference, &definition] {
            let view = facts
                .method_parameter_facts(method, ParameterViewLimits::default())
                .unwrap();
            assert_eq!(view.source().snapshot_id, facts.source().snapshot_id);
            assert_eq!(
                view.source().dex_occurrence_id,
                facts.source().dex_occurrence_id
            );
            assert_eq!(view.source().content_id, facts.source().content_id);
            assert!(view.definition.is_some());
            assert!(view.encoded_list.is_some());
            let parameters = view.iter().collect::<MddResult<Vec<_>>>().unwrap();
            assert_eq!(parameters.len(), 2);
            assert_eq!(parameters[0].ordinal, 0);
            assert_eq!(parameters[0].parameter_type.descriptor, "Ljava/util/List;");
            assert!(
                matches!(parameters[0].annotation_encoding, ParameterAnnotationEncoding::SetOffset(offset) if offset > 0)
            );
            assert_eq!(parameters[1].ordinal, 1);
            assert_eq!(parameters[1].parameter_type.descriptor, "I");
            assert_eq!(
                parameters[1].annotation_encoding,
                ParameterAnnotationEncoding::ExplicitZeroSlot
            );
        }
        let no_list = build("tests/fixtures/definitions/generated/definitions-035.dex");
        let external = no_list
            .definitions()
            .definitions()
            .method_references
            .iter()
            .find(|method| method.method_name == "externalCall")
            .unwrap();
        let method = no_list
            .definitions()
            .entity(EntityKind::MethodReference, external.method_idx)
            .unwrap();
        let view = no_list
            .method_parameter_facts(&method, ParameterViewLimits::default())
            .unwrap();
        assert!(view.definition.is_none());
        assert!(view.encoded_list.is_none());
        let parameters = view.iter().collect::<MddResult<Vec<_>>>().unwrap();
        assert_eq!(parameters.len(), 1);
        assert_eq!(
            parameters[0].annotation_encoding,
            ParameterAnnotationEncoding::NoEncodedList
        );
        let short = build("tests/fixtures/annotations/generated/bad-parameter-arity.dex");
        let short_method = short
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        let error = short
            .method_parameter_facts(&short_method, ParameterViewLimits::default())
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::IncompleteFacts);
        assert_eq!(
            error.details["required_layer"],
            "prototype_parameter_annotation_positions"
        );
        for limits in [
            ParameterViewLimits {
                max_scan_entries: 0,
                ..ParameterViewLimits::default()
            },
            ParameterViewLimits {
                max_parameters: 0,
                ..ParameterViewLimits::default()
            },
        ] {
            assert_eq!(
                facts
                    .method_parameter_facts(&reference, limits)
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::QuotaExceeded
            );
        }
        let mut incomplete = facts.clone();
        incomplete.annotation_coverage = Completeness::Unknown;
        assert_eq!(
            incomplete
                .method_parameter_facts(&reference, ParameterViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        let mut inconsistent = facts.clone();
        inconsistent.data.parameter_lists[0].prototype_parameter_count += 1;
        assert_eq!(
            inconsistent
                .method_parameter_facts(&reference, ParameterViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalFault
        );
        let other = build("tests/fixtures/annotations/generated/annotations-038.dex");
        let foreign = other
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        assert_eq!(
            facts
                .method_parameter_facts(&foreign, ParameterViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let wrong_kind = facts
            .definitions()
            .entity(EntityKind::FieldReference, 0)
            .unwrap();
        assert_eq!(
            facts
                .method_parameter_facts(&wrong_kind, ParameterViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/annotations/generated/annotations-038.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let repeated: Vec<_> = snapshot
            .sources()
            .iter()
            .map(|source| {
                let inventory = ArchiveInventory::build(
                    source,
                    InventoryPolicy::default(),
                    ArchiveLimits::default(),
                )
                .unwrap();
                let metadata =
                    MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default())
                        .unwrap();
                let definitions =
                    DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
                AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap()
            })
            .collect();
        assert_eq!(
            repeated[0].source().snapshot_id,
            repeated[1].source().snapshot_id
        );
        assert_eq!(
            repeated[0].source().content_id,
            repeated[1].source().content_id
        );
        assert_ne!(
            repeated[0].source().dex_occurrence_id,
            repeated[1].source().dex_occurrence_id
        );
        let other_occurrence = repeated[1]
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        assert_eq!(
            repeated[0]
                .method_parameter_facts(&other_occurrence, ParameterViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
    }
    fn canonical(rows: &serde_json::Value) -> Vec<String> {
        let mut values = rows
            .as_array()
            .unwrap()
            .iter()
            .map(|row| serde_json::to_string(row).unwrap())
            .collect::<Vec<_>>();
        values.sort();
        values
    }
    /// Legal items nothing references stay facts, but the SQL projections only
    /// see what a class-bound directory reaches (the frozen backend does the
    /// same). The expected counts are the frozen backend's own row counts on
    /// these fixtures (`artifacts/mdd-032-audit/a0-differential-20261112/`).
    #[test]
    fn unreferenced_items_stay_facts_but_are_not_reachable() {
        // (fixture, physical sets/annotations/elements, reachable sets/annotations/elements)
        let cases: [(&str, [usize; 3], [usize; 3]); 3] = [
            ("valid-orphan-annotation.dex", [5, 5, 44], [5, 4, 44]),
            ("valid-shared-empty-directory.dex", [5, 4, 44], [0, 0, 0]),
            ("valid-shared-empty-set.dex", [5, 4, 44], [4, 3, 40]),
        ];
        for (name, physical, reachable) in cases {
            let facts = build(&format!("tests/fixtures/annotations/generated/{name}"));
            assert_eq!(
                [
                    facts.set_entry_rows(0).len(),
                    facts.annotation_rows(0).len(),
                    facts.element_rows(0).len()
                ],
                physical,
                "{name}: the fact layer keeps every legal item"
            );
            assert_eq!(
                [
                    facts.reachable_set_entry_rows(0).len(),
                    facts.reachable_annotation_rows(0).len(),
                    facts.reachable_element_rows(0).len()
                ],
                reachable,
                "{name}: only directory-reachable items are projected"
            );
        }
    }
    #[test]
    fn six_full_relations_equal_independent_oracle_and_reference() {
        let facts = build("tests/fixtures/annotations/generated/annotations-038.dex");
        let reference: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/annotations/oracle-results.json"
        ))
        .unwrap();
        let data = &reference["positive"];
        for (name, native) in [
            (
                "annotation_directories",
                serde_json::to_value(facts.directory_rows(0)).unwrap(),
            ),
            (
                "annotation_directory_entries",
                serde_json::to_value(facts.directory_entry_rows(0)).unwrap(),
            ),
            (
                "annotation_set_entries",
                serde_json::to_value(facts.set_entry_rows(0)).unwrap(),
            ),
            (
                "annotation_set_refs",
                serde_json::to_value(facts.set_ref_rows(0)).unwrap(),
            ),
            (
                "annotations",
                serde_json::to_value(facts.annotation_rows(0)).unwrap(),
            ),
            (
                "annotation_elements",
                serde_json::to_value(facts.element_rows(0)).unwrap(),
            ),
        ] {
            assert_eq!(canonical(&native), canonical(&data[name]), "{name}");
        }
        assert!(
            facts
                .require_relation_columns(AnnotationRelation::Elements, &["*"])
                .is_ok()
        );
        assert_eq!(
            facts
                .require_relation_columns(AnnotationRelation::Elements, &["value_i65"])
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }
    #[test]
    fn signature_parts_keep_array_order_pool_and_owner_source() {
        let facts = build("tests/fixtures/annotations/generated/annotations-038.dex");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/annotations/expected.json"
        ))
        .unwrap();
        assert_eq!(facts.signatures.len(), 4);
        for signature in &facts.signatures {
            let key = match signature.owner.kind {
                AnnotationOwnerKind::Class => "class".to_owned(),
                AnnotationOwnerKind::Field => {
                    format!("field:{}", signature.owner.reference.local_index)
                }
                AnnotationOwnerKind::Method => {
                    format!("method:{}", signature.owner.reference.local_index)
                }
                AnnotationOwnerKind::Parameter => {
                    panic!("fixture parameter has Values, not Signature")
                }
            };
            assert_eq!(
                signature.strict_utf8().unwrap(),
                expected["signatures"][key].as_str().unwrap()
            );
            assert_eq!(
                signature.string_pool_id,
                facts.definitions.metadata.string_pool.string_pool_id
            );
            assert!(
                signature
                    .parts
                    .iter()
                    .all(|part| part.snapshot_id == facts.source().snapshot_id
                        && part.dex_occurrence_id == facts.source().dex_occurrence_id
                        && part.kind == EntityKind::String)
            );
        }
        let other = build("tests/fixtures/annotations/generated/annotations-038.dex");
        assert_ne!(facts.signatures[0].parts[0], other.signatures[0].parts[0]);
        assert_eq!(
            facts.signatures[0].string_pool_id,
            other.signatures[0].string_pool_id
        );
        assert_eq!(facts.annotation_coverage, Completeness::Complete);
        assert!(
            facts
                .unbuilt_layers
                .iter()
                .any(|layer| layer == "code_layout")
        );
    }

    #[test]
    fn owner_signature_view_preserves_reference_definition_and_occurrence() {
        let facts = build("tests/fixtures/annotations/generated/annotations-038.dex");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/annotations/expected.json"
        ))
        .unwrap();
        for signature in facts.signatures() {
            let expected_key = match signature.owner.kind {
                AnnotationOwnerKind::Class => "class".to_owned(),
                AnnotationOwnerKind::Field => {
                    format!("field:{}", signature.owner.reference.local_index)
                }
                AnnotationOwnerKind::Method => {
                    format!("method:{}", signature.owner.reference.local_index)
                }
                AnnotationOwnerKind::Parameter => panic!("fixture has no parameter Signature"),
            };
            for owner in std::iter::once(&signature.owner.reference)
                .chain(signature.owner.definition.as_ref())
            {
                let got = facts
                    .owner_signatures(owner, SignatureViewLimits::default())
                    .unwrap()
                    .collect::<Vec<_>>();
                assert_eq!(got.len(), 1);
                assert_eq!(
                    got[0].strict_utf8().unwrap(),
                    expected["signatures"][&expected_key].as_str().unwrap()
                );
                assert_eq!(got[0].annotation, signature.annotation);
                assert_eq!(got[0].parts, signature.parts);
                assert_eq!(got[0].string_pool_id, signature.string_pool_id);
            }
        }
        let owner = facts.signatures()[0].owner.reference.clone();
        let limits = SignatureViewLimits {
            max_scanned_entries: 2 * facts.signatures().len() as u64,
            max_matches: 1,
        };
        assert_eq!(facts.owner_signatures(&owner, limits).unwrap().count(), 1);
        assert_eq!(
            facts
                .owner_signatures(
                    &owner,
                    SignatureViewLimits {
                        max_scanned_entries: limits.max_scanned_entries - 1,
                        ..limits
                    },
                )
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            facts
                .owner_signatures(
                    &owner,
                    SignatureViewLimits {
                        max_matches: 0,
                        ..limits
                    }
                )
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        let other = build("tests/fixtures/annotations/generated/annotations-038.dex");
        let foreign = other.signatures()[0].owner.reference.clone();
        assert_eq!(
            facts.owner_signatures(&foreign, limits).err().unwrap().code,
            ErrorCode::InvalidArgument
        );
        let mut invalid_owner = owner.clone();
        invalid_owner.local_index = u32::MAX;
        assert_eq!(
            facts
                .owner_signatures(&invalid_owner, limits)
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        invalid_owner.local_index = 0;
        invalid_owner.kind = EntityKind::String;
        assert_eq!(
            facts
                .owner_signatures(&invalid_owner, limits)
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let plain = build("tests/fixtures/definitions/generated/definitions-035.dex");
        let unannotated = plain
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        assert_eq!(
            plain
                .owner_signatures(&unannotated, SignatureViewLimits::default())
                .unwrap()
                .count(),
            0
        );
        let mut partial = facts.clone();
        partial.annotation_coverage = Completeness::Partial;
        assert_eq!(
            partial.owner_signatures(&owner, limits).err().unwrap().code,
            ErrorCode::IncompleteFacts
        );
        let mut repeated = facts.clone();
        repeated.signatures.push(repeated.signatures[0].clone());
        let repeated_view = repeated
            .owner_signatures(&owner, SignatureViewLimits::default())
            .unwrap()
            .collect::<Vec<_>>();
        assert_eq!(repeated_view.len(), 2);
        assert_eq!(repeated_view[0].annotation, repeated_view[1].annotation);
        assert_eq!(repeated_view[0].parts, repeated_view[1].parts);

        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/annotations/generated/annotations-038.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let mut pair = Vec::new();
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let metadata =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            let definitions =
                DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
            pair.push(AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap());
        }
        let first = &pair[0].signatures()[0].owner.reference;
        let second = &pair[1].signatures()[0].owner.reference;
        assert_eq!(first.snapshot_id, second.snapshot_id);
        assert_ne!(first.dex_occurrence_id, second.dex_occurrence_id);
        assert_eq!(
            pair[0]
                .owner_signatures(first, SignatureViewLimits::default())
                .unwrap()
                .count(),
            1
        );
        assert_eq!(
            pair[1]
                .owner_signatures(second, SignatureViewLimits::default())
                .unwrap()
                .count(),
            1
        );
        assert_eq!(
            pair[0]
                .owner_signatures(second, SignatureViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn same_snapshot_duplicate_occurrences_keep_distinct_annotation_refs() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/annotations/generated/annotations-038.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let mut facts = Vec::new();
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let metadata =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            let definitions =
                DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
            facts.push(AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap());
        }
        assert_eq!(facts[0].source().snapshot_id, facts[1].source().snapshot_id);
        assert_ne!(
            facts[0].signatures()[0].annotation,
            facts[1].signatures()[0].annotation
        );
        assert_ne!(
            facts[0].signatures()[0].parts[0],
            facts[1].signatures()[0].parts[0]
        );
        assert_eq!(
            facts[0].signatures()[0].string_pool_id,
            facts[1].signatures()[0].string_pool_id
        );
        drop(snapshot);
        assert_eq!(facts[0].bytes(), facts[1].bytes());
    }

    #[test]
    fn short_parameter_lists_have_explicit_unknown_prototype_coverage() {
        let facts = build("tests/fixtures/annotations/generated/bad-parameter-arity.dex");
        assert_eq!(facts.annotation_coverage(), Completeness::Complete);
        assert_eq!(facts.set_ref_rows(0).len(), 1);
        let error = facts.require_complete_parameter_positions().unwrap_err();
        assert_eq!(error.code, ErrorCode::IncompleteFacts);
        assert_eq!(
            error.details["required_layer"],
            "prototype_parameter_annotation_positions"
        );
        assert!(
            facts
                .unbuilt_layers()
                .iter()
                .any(|layer| layer == "prototype_parameter_annotation_positions")
        );
    }

    #[test]
    fn empty_and_long_encoded_lists_are_not_inferred_as_complete_positions() {
        for (path, expected_slots) in [
            (
                "tests/fixtures/annotations/generated/parameter-empty-nonzero-proto.dex",
                0usize,
            ),
            (
                "tests/fixtures/annotations/generated/parameter-long-nonzero-proto.dex",
                3usize,
            ),
        ] {
            let facts = build(path);
            let method = facts
                .definitions()
                .entity(EntityKind::MethodReference, 0)
                .unwrap();
            let list = facts
                .method_encoded_parameter_list(&method, ParameterViewLimits::default())
                .unwrap()
                .expect("an encoded list exists, even when its length is zero");
            assert_eq!(
                list.binding.prototype_position_coverage,
                Completeness::Unknown
            );
            assert_eq!(list.binding.prototype_parameter_count, 2);
            assert_eq!(list.list.annotation_set_offsets.len(), expected_slots);
            assert_eq!(list.raw_encoded.len(), 4 + expected_slots * 4);
            assert_eq!(
                u32::from_le_bytes(list.raw_encoded[..4].try_into().unwrap()) as usize,
                expected_slots
            );
            assert_eq!(
                facts
                    .method_parameter_facts(&method, ParameterViewLimits::default())
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::IncompleteFacts
            );
            assert_eq!(
                facts
                    .require_complete_parameter_positions()
                    .unwrap_err()
                    .code,
                ErrorCode::IncompleteFacts
            );
            if expected_slots == 3 {
                assert_eq!(list.list.annotation_set_offsets[1], None);
                assert_eq!(
                    list.list.annotation_set_offsets[0],
                    list.list.annotation_set_offsets[2]
                );
                assert!(list.list.annotation_set_offsets[0].is_some());
            }
        }
    }

    #[test]
    fn empty_parameter_list_and_absent_binding_remain_distinct() {
        let explicit = build("tests/fixtures/annotations/generated/parameter-empty-zero-proto.dex");
        let absent =
            build("tests/fixtures/annotations/generated/parameter-orphan-empty-no-binding.dex");
        for (facts, has_binding) in [(&explicit, true), (&absent, false)] {
            let method = facts
                .definitions()
                .entity(EntityKind::MethodReference, 0)
                .unwrap();
            let encoded = facts
                .method_encoded_parameter_list(&method, ParameterViewLimits::default())
                .unwrap();
            assert_eq!(encoded.is_some(), has_binding);
            if let Some(encoded) = encoded {
                assert_eq!(
                    encoded.binding.prototype_position_coverage,
                    Completeness::Complete
                );
                assert_eq!(encoded.raw_encoded, &[0, 0, 0, 0]);
            }
            let view = facts
                .method_parameter_facts(&method, ParameterViewLimits::default())
                .unwrap();
            assert_eq!(view.encoded_list.is_some(), has_binding);
            assert_eq!(view.iter().count(), 0);
            facts.require_complete_parameter_positions().unwrap();
            // Physical empty list can be an orphan; absence of an owner binding
            // must not make the parser reject the valid physical item.
            assert_eq!(facts.data.ref_lists.len(), 1);
            assert!(facts.data.ref_lists[0].annotation_set_offsets.is_empty());
        }
    }

    #[test]
    fn long_parameter_lists_keep_duplicate_source_occurrences_distinct() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/annotations/generated/parameter-long-nonzero-proto.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let mut pair = Vec::new();
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let metadata =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            let definitions =
                DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
            pair.push(AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap());
        }
        let first = pair[0]
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        let second = pair[1]
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        assert_eq!(first.snapshot_id, second.snapshot_id);
        assert_ne!(first.dex_occurrence_id, second.dex_occurrence_id);
        let left = pair[0]
            .method_encoded_parameter_list(&first, ParameterViewLimits::default())
            .unwrap()
            .unwrap();
        let right = pair[1]
            .method_encoded_parameter_list(&second, ParameterViewLimits::default())
            .unwrap()
            .unwrap();
        assert_eq!(left.raw_encoded, right.raw_encoded);
        assert_ne!(
            left.source.dex_occurrence_id,
            right.source.dex_occurrence_id
        );
        assert_eq!(
            left.binding.prototype_position_coverage,
            Completeness::Unknown
        );
        assert_eq!(
            right.binding.prototype_position_coverage,
            Completeness::Unknown
        );
        assert_eq!(
            pair[0]
                .method_encoded_parameter_list(&second, ParameterViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn shared_parameter_signature_keeps_method_and_unknown_encoded_slots_distinct() {
        let facts = build("tests/fixtures/annotations/generated/parameter-shared-signature.dex");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/annotations/parameter-shared-signature.json"
        ))
        .unwrap();
        let signature_offset = expected["signature_offset"].as_u64().unwrap() as u32;
        let shared: Vec<_> = facts
            .signatures()
            .iter()
            .filter(|signature| signature.annotation.annotation_byte_offset == signature_offset)
            .collect();
        // One method-level annotation plus two encoded slots on each method.
        assert_eq!(shared.len(), 5);
        let mut parameter_owners = Vec::new();
        let mut method_owners = Vec::new();
        for signature in &shared {
            let fragments: Vec<_> = signature
                .parts
                .iter()
                .map(|part| {
                    let string =
                        &facts.definitions().metadata().strings()[part.local_index as usize];
                    assert_eq!(string.entity, *part);
                    string.data.text.strict_utf8().unwrap()
                })
                .collect();
            let expected_fragments: Vec<_> = expected["fragments"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect();
            assert_eq!(fragments, expected_fragments);
            assert_eq!(
                signature.strict_utf8().unwrap(),
                expected_fragments.concat()
            );
            assert_eq!(signature.annotation.snapshot_id, facts.source().snapshot_id);
            assert_eq!(
                signature.annotation.dex_occurrence_id,
                facts.source().dex_occurrence_id
            );
            match signature.owner.kind {
                AnnotationOwnerKind::Parameter => parameter_owners.push((
                    signature.owner.reference.local_index,
                    signature.owner.parameter_ordinal.unwrap(),
                )),
                AnnotationOwnerKind::Method => method_owners.push((
                    signature.owner.reference.local_index,
                    signature.owner.parameter_ordinal,
                )),
                _ => panic!("unexpected owner for shared Signature item"),
            }
        }
        parameter_owners.sort_unstable();
        assert_eq!(parameter_owners, vec![(0, 0), (0, 2), (1, 0), (1, 2)]);
        assert_eq!(method_owners, vec![(0, None)]);
        for method_idx in [0, 1] {
            let method = facts
                .definitions()
                .entity(EntityKind::MethodReference, method_idx)
                .unwrap();
            let list = facts
                .method_encoded_parameter_list(&method, ParameterViewLimits::default())
                .unwrap()
                .unwrap();
            assert_eq!(
                list.binding.prototype_position_coverage,
                Completeness::Unknown
            );
            assert_eq!(
                facts
                    .method_parameter_facts(&method, ParameterViewLimits::default())
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::IncompleteFacts
            );
            let method_only: Vec<_> = facts
                .owner_signatures(&method, SignatureViewLimits::default())
                .unwrap()
                .collect();
            assert_eq!(method_only.len(), usize::from(method_idx == 0));
            assert!(
                method_only
                    .iter()
                    .all(|item| item.owner.kind == AnnotationOwnerKind::Method)
            );
        }
        assert!(
            facts
                .data()
                .owner_bindings
                .iter()
                .filter(|owner| owner.kind == AnnotationOwnerKind::Parameter)
                .all(|owner| owner.parameter_position_in_prototype.is_none())
        );
    }

    #[test]
    fn signature_parameter_position_distinguishes_unknown_and_proven_slots() {
        let unknown = build("tests/fixtures/annotations/generated/parameter-shared-signature.dex");
        let complete =
            build("tests/fixtures/annotations/generated/parameter-shared-signature-complete.dex");
        let mut counts = [0usize; 2];
        for (facts, expected_unknown) in [(&unknown, true), (&complete, false)] {
            for signature in facts.signatures() {
                let position = facts
                    .signature_parameter_position(signature, SignaturePositionLimits::default())
                    .unwrap();
                if signature.owner.kind == AnnotationOwnerKind::Parameter {
                    let slot = signature.owner.parameter_ordinal.unwrap();
                    if expected_unknown {
                        assert_eq!(
                            position,
                            SignatureParameterPosition::Unknown { encoded_slot: slot }
                        );
                        counts[0] += 1;
                    } else {
                        assert_eq!(
                            position,
                            SignatureParameterPosition::Known { ordinal: slot }
                        );
                        counts[1] += 1;
                    }
                } else {
                    assert_eq!(position, SignatureParameterPosition::NotParameter);
                }
            }
        }
        assert_eq!(counts, [4, 2]);
        let signature = unknown
            .signatures()
            .iter()
            .find(|value| value.owner.kind == AnnotationOwnerKind::Parameter)
            .unwrap();
        assert_eq!(
            unknown
                .signature_parameter_position(
                    signature,
                    SignaturePositionLimits {
                        max_signatures: 0,
                        ..SignaturePositionLimits::default()
                    }
                )
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            unknown
                .signature_parameter_position(
                    signature,
                    SignaturePositionLimits {
                        owners: AnnotationOwnerViewLimits {
                            max_scanned_entries: 0,
                            ..AnnotationOwnerViewLimits::default()
                        },
                        ..SignaturePositionLimits::default()
                    }
                )
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        let mut clone = signature.clone();
        assert_eq!(
            unknown
                .signature_parameter_position(&clone, SignaturePositionLimits::default())
                .unwrap(),
            SignatureParameterPosition::Unknown {
                encoded_slot: signature.owner.parameter_ordinal.unwrap()
            }
        );
        assert_eq!(
            unknown
                .signature_parameter_position(
                    &clone,
                    SignaturePositionLimits {
                        max_identity_bytes: 0,
                        ..SignaturePositionLimits::default()
                    }
                )
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
        clone.utf16_units.push(0);
        assert_eq!(
            unknown
                .signature_parameter_position(&clone, SignaturePositionLimits::default())
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        let foreign = build("tests/fixtures/annotations/generated/parameter-shared-signature.dex");
        let foreign_signature = foreign
            .signatures()
            .iter()
            .find(|value| value.owner.kind == AnnotationOwnerKind::Parameter)
            .unwrap();
        assert_ne!(
            signature.annotation.snapshot_id,
            foreign_signature.annotation.snapshot_id
        );
        assert_eq!(
            unknown
                .signature_parameter_position(foreign_signature, SignaturePositionLimits::default())
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        let mut inconsistent = unknown.clone();
        let owner = inconsistent
            .data
            .owner_bindings
            .iter_mut()
            .find(|owner| {
                owner.kind == AnnotationOwnerKind::Parameter
                    && owner.local_index == signature.owner.reference.local_index
                    && owner.parameter_ordinal == signature.owner.parameter_ordinal
            })
            .unwrap();
        owner.parameter_position_in_prototype = Some(true);
        let inconsistent_signature = inconsistent
            .signatures()
            .iter()
            .find(|value| {
                value.owner.kind == AnnotationOwnerKind::Parameter
                    && value.owner.reference.local_index == signature.owner.reference.local_index
                    && value.owner.parameter_ordinal == signature.owner.parameter_ordinal
            })
            .unwrap();
        assert_eq!(
            inconsistent
                .signature_parameter_position(
                    inconsistent_signature,
                    SignaturePositionLimits::default()
                )
                .unwrap_err()
                .code,
            ErrorCode::InternalFault
        );
    }

    #[test]
    fn encoded_parameter_slots_preserve_zero_shared_and_absent_lists() {
        let facts = build("tests/fixtures/annotations/generated/parameter-long-nonzero-proto.dex");
        let method = facts
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        let visits = u64::try_from(facts.data.sets.len()).unwrap() * 2;
        let view = facts
            .method_encoded_parameter_slots(&method, ParameterViewLimits::default(), visits)
            .unwrap()
            .unwrap();
        assert_eq!(
            view.binding.prototype_position_coverage,
            Completeness::Unknown
        );
        let slots = view.iter().collect::<MddResult<Vec<_>>>().unwrap();
        assert_eq!(
            slots.iter().map(|slot| slot.ordinal).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert!(slots[1].set.is_none());
        let first = slots[0].set.unwrap();
        let last = slots[2].set.unwrap();
        assert!(std::ptr::eq(first, last));
        let raw = &facts.bytes()[view.list.byte_offset as usize..];
        assert_eq!(u32::from_le_bytes(raw[0..4].try_into().unwrap()), 3);
        assert_eq!(
            u32::from_le_bytes(raw[4..8].try_into().unwrap()),
            first.byte_offset
        );
        assert_eq!(u32::from_le_bytes(raw[8..12].try_into().unwrap()), 0);
        assert_eq!(
            u32::from_le_bytes(raw[12..16].try_into().unwrap()),
            last.byte_offset
        );
        assert_eq!(
            facts
                .method_encoded_parameter_slots(&method, ParameterViewLimits::default(), visits - 1)
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            facts
                .method_parameter_facts(&method, ParameterViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );

        let empty = build("tests/fixtures/annotations/generated/parameter-empty-zero-proto.dex");
        let empty_method = empty
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        let empty_slots = empty
            .method_encoded_parameter_slots(&empty_method, ParameterViewLimits::default(), 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            empty_slots.binding.prototype_position_coverage,
            Completeness::Complete
        );
        assert_eq!(empty_slots.iter().count(), 0);
        let absent =
            build("tests/fixtures/annotations/generated/parameter-orphan-empty-no-binding.dex");
        let absent_method = absent
            .definitions()
            .entity(EntityKind::MethodReference, 0)
            .unwrap();
        assert!(
            absent
                .method_encoded_parameter_slots(&absent_method, ParameterViewLimits::default(), 0)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            facts
                .method_encoded_parameter_slots(
                    &absent_method,
                    ParameterViewLimits::default(),
                    visits
                )
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );

        // Explicitly injected dangling set identity must fail rather than look empty.
        let mut broken = facts.clone();
        broken
            .data
            .sets
            .retain(|set| set.byte_offset != first.byte_offset);
        let invalid = broken
            .method_encoded_parameter_slots(&method, ParameterViewLimits::default(), u64::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(
            invalid.iter().next().unwrap().err().unwrap().code,
            ErrorCode::InternalFault
        );
    }

    #[test]
    fn encoded_slots_distinguish_shared_physical_empty_set_zero_and_orphan() {
        let facts = build("tests/fixtures/annotations/generated/parameter-shared-empty-set.dex");
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/annotations/parameter-shared-empty-set.json"
        ))
        .unwrap();
        let empty_offset = expected["empty_set_offset"].as_u64().unwrap() as u32;
        let orphan_offset = expected["orphan_set_offset"].as_u64().unwrap() as u32;
        assert_ne!(empty_offset, orphan_offset);
        assert_eq!(
            &facts.bytes()[empty_offset as usize..empty_offset as usize + 4],
            &[0, 0, 0, 0]
        );
        assert_eq!(
            &facts.bytes()[orphan_offset as usize..orphan_offset as usize + 4],
            &[0, 0, 0, 0]
        );
        let mut previous_set = None;
        for method_idx in [0, 1] {
            let method = facts
                .definitions()
                .entity(EntityKind::MethodReference, method_idx)
                .unwrap();
            let budget = u64::try_from(facts.data.sets.len()).unwrap() * 2;
            let view = facts
                .method_encoded_parameter_slots(&method, ParameterViewLimits::default(), budget)
                .unwrap()
                .unwrap();
            assert_eq!(
                view.binding.prototype_position_coverage,
                Completeness::Unknown
            );
            let slots = view.iter().collect::<MddResult<Vec<_>>>().unwrap();
            assert_eq!(
                slots.iter().map(|slot| slot.ordinal).collect::<Vec<_>>(),
                [0, 1, 2]
            );
            let set = slots[0]
                .set
                .expect("nonzero offset must resolve to a physical set");
            assert_eq!(set.byte_offset, empty_offset);
            assert!(set.annotation_offsets.is_empty());
            assert!(slots[1].set.is_none());
            assert!(std::ptr::eq(set, slots[2].set.unwrap()));
            if let Some(previous) = previous_set {
                assert!(std::ptr::eq(previous, set));
            }
            previous_set = Some(set);
            assert_eq!(
                facts
                    .method_parameter_facts(&method, ParameterViewLimits::default())
                    .err()
                    .unwrap()
                    .code,
                ErrorCode::IncompleteFacts
            );
        }
        let matching = facts
            .data
            .owner_bindings
            .iter()
            .filter(|owner| {
                owner.kind == AnnotationOwnerKind::Parameter
                    && owner.annotation_set_offset == Some(empty_offset)
            })
            .count();
        assert_eq!(matching, 4);
        assert!(
            !facts
                .data
                .owner_bindings
                .iter()
                .any(|owner| owner.annotation_set_offset == Some(orphan_offset))
        );
        assert!(
            !facts
                .data
                .ref_lists
                .iter()
                .flat_map(|list| list.annotation_set_offsets.iter())
                .any(|offset| *offset == Some(orphan_offset))
        );
        let reference = AnnotationCollectionRef {
            snapshot_id: facts.source().snapshot_id.clone(),
            dex_occurrence_id: facts.source().dex_occurrence_id.clone(),
            byte_offset: orphan_offset,
            kind: AnnotationCollectionKind::Set,
        };
        let AnnotationCollectionView::Set {
            item, raw_encoded, ..
        } = facts
            .collection_by_ref(&reference, facts.data.sets.len() as u64, 0)
            .unwrap()
        else {
            panic!("orphan collection is not a set")
        };
        assert!(item.annotation_offsets.is_empty());
        assert_eq!(raw_encoded, &[0, 0, 0, 0]);
    }
}
