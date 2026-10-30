//! Immutable source-bound annotation relations and ordered Signature fragments.
use crate::{
    definitions::DefinitionFacts,
    metadata::{EntityKind, EntityRef, MetadataSource},
};
use mdd_dex::annotations::{
    AnnotationItem, AnnotationLimits, AnnotationOwnerBinding, AnnotationOwnerKind, AnnotationSet,
    AnnotationSetRefList, DexAnnotations, EncodedKind, EncodedValue, ExactFloat,
    ParameterListBinding, read_annotations,
};
use mdd_dex::{
    definitions::{MethodDefinition, MethodReference},
    types::{DexPrototype, DexType},
};
use mdd_types::{Completeness, ErrorCode, MddError, MddResult, content_id};
use serde::Serialize;
use std::collections::BTreeMap;

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
impl SignatureFact {
    pub fn strict_utf8(&self) -> Result<String, std::string::FromUtf16Error> {
        String::from_utf16(&self.utf16_units)
    }
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

fn owner_ref(
    definitions: &DefinitionFacts,
    owner: &AnnotationOwnerBinding,
) -> MddResult<AnnotationOwnerRef> {
    let kind = match owner.kind {
        AnnotationOwnerKind::Class => EntityKind::ClassDefinition,
        AnnotationOwnerKind::Field => EntityKind::FieldReference,
        _ => EntityKind::MethodReference,
    };
    let reference = definitions.entity(kind, owner.local_index)?;
    let definition = match owner.kind {
        AnnotationOwnerKind::Class => Some(reference.clone()),
        AnnotationOwnerKind::Field => definitions
            .definitions
            .field_definitions
            .iter()
            .any(|field| field.field_idx == owner.local_index)
            .then(|| definitions.entity(EntityKind::FieldDefinition, owner.local_index))
            .transpose()?,
        _ => definitions
            .definitions
            .method_definitions
            .iter()
            .any(|method| method.method_idx == owner.local_index)
            .then(|| definitions.entity(EntityKind::MethodDefinition, owner.local_index))
            .transpose()?,
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
            &definitions.metadata,
            &definitions.definitions,
            limits,
        )
        .map_err(bind)?;
        let sets: BTreeMap<_, _> = data
            .sets
            .iter()
            .map(|item| (item.byte_offset, item))
            .collect();
        let items: BTreeMap<_, _> = data
            .annotation_items
            .iter()
            .map(|item| (item.byte_offset, item))
            .collect();
        let mut signatures = Vec::new();
        let mut remaining = limits
            .max_decoded_bytes
            .saturating_sub(data.usage.decoded_bytes);
        for owner in &data.owner_bindings {
            let Some(set) = owner.annotation_set_offset else {
                continue;
            };
            for offset in &sets[&set].annotation_offsets {
                let item = items[offset];
                if definitions.metadata.types[item.type_idx as usize]
                    .data
                    .descriptor
                    != "Ldalvik/annotation/Signature;"
                {
                    continue;
                }
                let invalid = || {
                    bind(MddError::new(ErrorCode::InvalidInput,"facts.annotations","Signature requires one named value containing an array of string references").detail("reason","SIGNATURE_SHAPE").detail("byte_offset",offset.to_string()))
                };
                if item.elements.len() != 1 {
                    return Err(invalid());
                }
                let value = &data.values[item.elements[0] as usize];
                let name = value
                    .name_idx
                    .and_then(|index| definitions.metadata.strings.get(index as usize))
                    .and_then(|item| item.data.text.strict_utf8().ok());
                if name.as_deref() != Some("value") || value.kind != EncodedKind::Array {
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
                let identity_bytes =
                    (source.snapshot_id.len() + source.dex_occurrence_id.len() + 32) as u64;
                let cost = total_units
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(value.children.len() as u64 * identity_bytes))
                    .and_then(|n| {
                        n.checked_add(
                            2 * identity_bytes
                                + definitions.metadata.string_pool.string_pool_id.len() as u64,
                        )
                    })
                    .ok_or_else(|| {
                        bind(MddError::new(
                            ErrorCode::QuotaExceeded,
                            "facts.annotations",
                            "Signature allocation size overflow",
                        ))
                    })?;
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
                let mut units = Vec::new();
                units.try_reserve_exact(total_units as usize).map_err(|_| {
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
                        annotation_byte_offset: *offset,
                    },
                    owner: owner_ref(&definitions, owner).map_err(bind)?,
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
            if candidate.byte_offset == annotation.annotation_byte_offset {
                if item.replace(candidate).is_some() {
                    return Err(broken());
                }
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
}
