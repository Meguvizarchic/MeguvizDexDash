//! Immutable source-bound annotation relations and ordered Signature fragments.
use crate::{
    definitions::DefinitionFacts,
    metadata::{EntityKind, EntityRef, MetadataSource, SharedId},
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
    pub snapshot_id: SharedId,
    pub dex_occurrence_id: SharedId,
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
    pub snapshot_id: SharedId,
    pub dex_occurrence_id: SharedId,
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
    /// Shared with the definition layer the facts were built from, not a copy of it: a session that keeps both
    /// would otherwise hold every definition table twice.
    definitions: std::sync::Arc<DefinitionFacts>,
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
        Self::build_arc(std::sync::Arc::new(definitions), limits)
    }

    /// As `build`, over definitions that the caller already shares (a session holds them for its other layers).
    pub fn build_arc(
        definitions: std::sync::Arc<DefinitionFacts>,
        limits: AnnotationLimits,
    ) -> MddResult<Self> {
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
}

mod parameters;
mod rows;
pub use rows::ReachableElementRef;
mod views;

#[cfg(test)]
#[path = "annotations/tests.rs"]
mod tests;
