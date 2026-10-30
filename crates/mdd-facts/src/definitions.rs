//! Source-bound definition facts. Unbuilt code columns never masquerade as NULL.
use crate::metadata::{EntityKind, EntityRef, MetadataFacts, MetadataSource, TypeFact};
use mdd_dex::{
    definitions::{
        ClassDefinition, DefinitionLimits, DefinitionMetadata, DexDefinitions, FieldDefinition,
        FieldReference, InterfaceDefinition, MethodDefinition, MethodReference, read_definitions,
    },
    strings::DexString,
    types::{DexPrototype, DexType},
};
use mdd_types::{Completeness, ErrorCode, MddError, MddResult, content_id};
use serde::Serialize;

impl DefinitionMetadata for MetadataFacts {
    fn string(&self, index: u32) -> Option<&DexString> {
        self.strings.get(index as usize).map(|f| &f.data)
    }
    fn dex_type(&self, index: u32) -> Option<&DexType> {
        self.types.get(index as usize).map(|f| &f.data)
    }
    fn prototype(&self, index: u32) -> Option<&DexPrototype> {
        self.prototypes.get(index as usize).map(|f| &f.data)
    }
}

#[derive(Clone, Serialize)]
pub struct DefinitionFacts {
    pub(crate) metadata: MetadataFacts,
    pub(crate) definitions: DexDefinitions,
    pub(crate) definition_coverage: Completeness,
    pub(crate) completed_layers: Vec<String>,
    pub(crate) unbuilt_layers: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefinitionRelation {
    Classes,
    ClassInterfaces,
    ClassFields,
    ClassMethods,
    Methods,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClassFieldRow {
    pub file_id: u32,
    pub class_idx: u32,
    pub class_descriptor: String,
    pub field_idx: u32,
    pub field_name: String,
    pub field_descriptor: String,
    pub kind: String,
    pub access_flags: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct ClassMethodRow {
    pub file_id: u32,
    pub class_idx: u32,
    pub class_descriptor: String,
    pub method_idx: u32,
    pub method_name: String,
    pub method_descriptor: String,
    pub kind: String,
    pub access_flags: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct ClassInterfaceRow {
    pub file_id: u32,
    pub class_idx: u32,
    pub ordinal: u32,
    pub interface_type_idx: u32,
    pub interface_descriptor: String,
}

/// Logical iteration limits; the borrowed class view allocates no owner index.
#[derive(Clone, Copy, Debug)]
pub struct ClassViewLimits {
    pub max_classes: u64,
    pub max_interfaces: u64,
}
impl Default for ClassViewLimits {
    fn default() -> Self {
        Self {
            max_classes: 4_000_000,
            max_interfaces: 16_000_000,
        }
    }
}

/// Direct facts for one class definition in one immutable DEX occurrence.
/// Absence of superclass or source file is the encoded NO_INDEX, not an unbuilt layer.
/// Interface entries are direct declarations; no inheritance closure is inferred.
pub struct ClassFactView<'a> {
    pub source: &'a MetadataSource,
    pub definition: &'a ClassDefinition,
    pub class_type: &'a DexType,
    pub superclass: Option<&'a DexType>,
    pub source_file: Option<&'a DexString>,
    pub interfaces: &'a [InterfaceDefinition],
}
pub struct ClassFactViews<'a> {
    facts: &'a DefinitionFacts,
}
impl<'a> ClassFactViews<'a> {
    /// Iterate DEX class_def order with directly declared interfaces in ordinal order.
    pub fn iter(&self) -> impl Iterator<Item = MddResult<ClassFactView<'a>>> + '_ {
        let facts = self.facts;
        facts.definitions.classes.iter().map(move |class| {
            let type_at = |idx: u32| {
                facts
                    .metadata
                    .types()
                    .get(idx as usize)
                    .map(|v| &v.data)
                    .ok_or_else(|| {
                        MddError::new(
                            ErrorCode::InternalFault,
                            "facts.classes",
                            "validated class type is missing",
                        )
                    })
            };
            let class_type = type_at(class.class_idx)?;
            let superclass = class.superclass_idx.map(type_at).transpose()?;
            let source_file = class
                .source_file_idx
                .map(|idx| {
                    facts
                        .metadata
                        .strings()
                        .get(idx as usize)
                        .map(|v| &v.data)
                        .ok_or_else(|| {
                            MddError::new(
                                ErrorCode::InternalFault,
                                "facts.classes",
                                "validated source file is missing",
                            )
                        })
                })
                .transpose()?;
            let all = &facts.definitions.interfaces;
            let first = all.partition_point(|item| item.class_def_idx < class.class_def_idx);
            let last = all.partition_point(|item| item.class_def_idx <= class.class_def_idx);
            Ok(ClassFactView {
                source: facts.metadata.source(),
                definition: class,
                class_type,
                superclass,
                source_file,
                interfaces: &all[first..last],
            })
        })
    }
}

/// Limits for the borrowed method-reference-to-definition join, not a total RSS bound.
#[derive(Clone, Copy, Debug)]
pub struct MethodViewLimits {
    pub max_definition_entries: u64,
    pub max_index_bytes: u64,
}
impl Default for MethodViewLimits {
    fn default() -> Self {
        Self {
            max_definition_entries: 4_000_000,
            max_index_bytes: 256 * 1024 * 1024,
        }
    }
}

/// One method_id and its same-occurrence prototype and optional real definition.
/// `definition == None` means this is reference-only because the definition layer is complete.
/// This view intentionally has no code-layout or annotation fields: they are not NULL defaults.
pub struct MethodFactView<'a> {
    pub source: &'a MetadataSource,
    pub reference: &'a MethodReference,
    pub prototype: &'a DexPrototype,
    pub definition: Option<&'a MethodDefinition>,
}
pub struct MethodFactViews<'a> {
    facts: &'a DefinitionFacts,
    definitions: Vec<&'a MethodDefinition>,
}

/// Per-method parameter cardinality limit; this is not a CPU or RSS bound.
#[derive(Clone, Copy, Debug)]
pub struct PrototypeParameterLimits {
    pub max_parameters: u64,
}
impl Default for PrototypeParameterLimits {
    fn default() -> Self {
        Self {
            max_parameters: 1_000_000,
        }
    }
}

/// One declared prototype position and its exact same-occurrence type identity.
pub struct PrototypeParameterType<'a> {
    pub ordinal: u32,
    pub type_fact: &'a TypeFact,
}

/// Type facts alone do not imply anything about parameter annotations or runtime values.
pub struct MethodPrototypeParameters<'a> {
    pub source: &'a MetadataSource,
    pub reference: &'a MethodReference,
    pub prototype: &'a DexPrototype,
    pub definition: Option<&'a MethodDefinition>,
    metadata: &'a MetadataFacts,
}

/// Limits for one comma-separated parameter descriptor projection. These are
/// logical input and output limits, not allocator, RSS or deadline guarantees.
#[derive(Clone, Copy, Debug)]
pub struct ParameterDescriptorLimits {
    pub max_parameters: u64,
    pub max_raw_bytes: u64,
    pub max_utf16_units: u64,
}
impl Default for ParameterDescriptorLimits {
    fn default() -> Self {
        Self {
            max_parameters: 1_000_000,
            max_raw_bytes: 16 * 1024 * 1024,
            max_utf16_units: 16 * 1024 * 1024,
        }
    }
}

/// Comma-separated descriptor data in both original byte and UTF-16 forms.
/// This is not a UTF-8 string: MUTF-8 encodes supplementary characters as
/// surrogate pairs. The selected method/source remain on the originating view.
#[derive(Debug, Eq, PartialEq)]
pub struct ParameterDescriptorText {
    pub raw_mutf8: Vec<u8>,
    pub utf16_units: Vec<u16>,
}
impl<'a> MethodPrototypeParameters<'a> {
    /// Each iteration preserves prototype order and repeated type identities.
    pub fn iter(
        &self,
    ) -> impl ExactSizeIterator<Item = MddResult<PrototypeParameterType<'a>>> + '_ {
        self.prototype
            .parameter_type_indices
            .iter()
            .enumerate()
            .map(|(ordinal, index)| {
                let fact = self.metadata.types().get(*index as usize).ok_or_else(|| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.method_parameters",
                        "validated parameter type is missing",
                    )
                })?;
                let ordinal = u32::try_from(ordinal).map_err(|_| {
                    MddError::new(
                        ErrorCode::QuotaExceeded,
                        "facts.method_parameters",
                        "parameter ordinal overflow",
                    )
                })?;
                Ok(PrototypeParameterType {
                    ordinal,
                    type_fact: fact,
                })
            })
    }

    /// Construct two lossless forms using the validated descriptor strings.
    /// Empty parameter lists yield two empty values, including for references
    /// without a definition. No annotation or compatibility qualification is
    /// inferred from this native projection.
    pub fn descriptor_text(
        &self,
        limits: ParameterDescriptorLimits,
    ) -> MddResult<ParameterDescriptorText> {
        let quota = || {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.method_parameters",
                "parameter descriptor projection budget exceeded",
            )
        };
        let broken = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.method_parameters",
                "validated descriptor string is inconsistent",
            )
        };
        let count =
            u64::try_from(self.prototype.parameter_type_indices.len()).map_err(|_| quota())?;
        if count > limits.max_parameters {
            return Err(quota());
        }
        let descriptor = |index: u32| -> MddResult<&DexString> {
            let ty = self
                .metadata
                .types()
                .get(index as usize)
                .filter(|v| {
                    v.data.type_idx == index
                        && v.entity.kind == EntityKind::Type
                        && v.entity.local_index == index
                        && v.entity.snapshot_id == self.source.snapshot_id
                        && v.entity.dex_occurrence_id == self.source.dex_occurrence_id
                })
                .ok_or_else(broken)?;
            let string_index = ty.data.descriptor_string_idx;
            let string = self
                .metadata
                .strings()
                .get(string_index as usize)
                .filter(|v| {
                    v.data.string_idx == string_index
                        && v.entity.kind == EntityKind::String
                        && v.entity.local_index == string_index
                        && v.entity.snapshot_id == self.source.snapshot_id
                        && v.entity.dex_occurrence_id == self.source.dex_occurrence_id
                        && ty.descriptor_string == v.entity
                })
                .ok_or_else(broken)?;
            if !string.data.text.declared_length_verified
                || usize::try_from(string.data.text.declared_utf16_length).ok()
                    != Some(string.data.text.utf16_units.len())
                || !ty.data.descriptor.encode_utf16().eq(string
                    .data
                    .text
                    .utf16_units
                    .iter()
                    .copied())
            {
                return Err(broken());
            }
            Ok(&string.data)
        };
        let mut bytes = count.saturating_sub(1);
        let mut units = count.saturating_sub(1);
        for &index in &self.prototype.parameter_type_indices {
            let text = &descriptor(index)?.text;
            bytes = bytes
                .checked_add(u64::try_from(text.raw_mutf8.len()).map_err(|_| quota())?)
                .ok_or_else(quota)?;
            units = units
                .checked_add(u64::try_from(text.utf16_units.len()).map_err(|_| quota())?)
                .ok_or_else(quota)?;
            if bytes > limits.max_raw_bytes || units > limits.max_utf16_units {
                return Err(quota());
            }
        }
        if bytes > limits.max_raw_bytes || units > limits.max_utf16_units {
            return Err(quota());
        }
        let mut raw_mutf8 = Vec::new();
        let mut utf16_units = Vec::new();
        raw_mutf8
            .try_reserve_exact(usize::try_from(bytes).map_err(|_| quota())?)
            .map_err(|_| quota())?;
        utf16_units
            .try_reserve_exact(usize::try_from(units).map_err(|_| quota())?)
            .map_err(|_| quota())?;
        for (ordinal, &index) in self.prototype.parameter_type_indices.iter().enumerate() {
            if ordinal != 0 {
                raw_mutf8.push(b',');
                utf16_units.push(u16::from(b','));
            }
            let text = &descriptor(index)?.text;
            raw_mutf8.extend_from_slice(&text.raw_mutf8);
            utf16_units.extend_from_slice(&text.utf16_units);
        }
        Ok(ParameterDescriptorText {
            raw_mutf8,
            utf16_units,
        })
    }
}

/// Limits for the borrowed field-reference-to-definition join, not a total RSS bound.
#[derive(Clone, Copy, Debug)]
pub struct FieldViewLimits {
    pub max_definition_entries: u64,
    pub max_index_bytes: u64,
}
impl Default for FieldViewLimits {
    fn default() -> Self {
        Self {
            max_definition_entries: 4_000_000,
            max_index_bytes: 256 * 1024 * 1024,
        }
    }
}

/// One field_id and its same-occurrence type and optional real definition.
/// `definition == None` is reference-only within this complete definition layer.
/// Initial values and annotations are not part of this view and are never filled as NULL.
pub struct FieldFactView<'a> {
    pub source: &'a MetadataSource,
    pub reference: &'a FieldReference,
    pub field_type: &'a DexType,
    pub definition: Option<&'a FieldDefinition>,
}
pub struct FieldFactViews<'a> {
    facts: &'a DefinitionFacts,
    definitions: Vec<&'a FieldDefinition>,
}
impl<'a> FieldFactViews<'a> {
    /// Resolve one exact same-occurrence field identity without scanning all references.
    /// A definition identity must actually have a definition in the validated layer.
    pub fn get(&self, entity: &EntityRef) -> MddResult<FieldFactView<'a>> {
        let source = self.facts.metadata.source();
        let invalid = || {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.fields",
                "invalid or foreign field identity",
            )
        };
        if entity.snapshot_id != source.snapshot_id
            || entity.dex_occurrence_id != source.dex_occurrence_id
            || !matches!(
                entity.kind,
                EntityKind::FieldReference | EntityKind::FieldDefinition
            )
        {
            return Err(invalid());
        }
        let reference = self
            .facts
            .definitions
            .field_references
            .get(entity.local_index as usize)
            .filter(|r| r.field_idx == entity.local_index)
            .ok_or_else(invalid)?;
        let definition = self
            .definitions
            .binary_search_by_key(&entity.local_index, |d| d.field_idx)
            .ok()
            .map(|index| self.definitions[index]);
        if entity.kind == EntityKind::FieldDefinition && definition.is_none() {
            return Err(invalid());
        }
        let field_type = self
            .facts
            .metadata
            .types()
            .get(reference.type_idx as usize)
            .filter(|item| item.data.type_idx == reference.type_idx)
            .map(|item| &item.data)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "facts.fields",
                    "validated field type is missing",
                )
            })?;
        Ok(FieldFactView {
            source,
            reference,
            field_type,
            definition,
        })
    }
    /// Iterate every encoded field reference in DEX field-id order without copying values.
    pub fn iter(&self) -> impl Iterator<Item = MddResult<FieldFactView<'a>>> + '_ {
        self.facts
            .definitions
            .field_references
            .iter()
            .map(|reference| {
                let field_type = self
                    .facts
                    .metadata
                    .types()
                    .get(reference.type_idx as usize)
                    .map(|item| &item.data)
                    .ok_or_else(|| {
                        MddError::new(
                            ErrorCode::InternalFault,
                            "facts.fields",
                            "validated field type is missing",
                        )
                    })?;
                let definition = self
                    .definitions
                    .binary_search_by_key(&reference.field_idx, |definition| definition.field_idx)
                    .ok()
                    .map(|index| self.definitions[index]);
                Ok(FieldFactView {
                    source: self.facts.metadata.source(),
                    reference,
                    field_type,
                    definition,
                })
            })
    }
}
impl<'a> MethodFactViews<'a> {
    /// Resolve one exact same-occurrence method reference or definition identity.
    pub fn get(&self, entity: &EntityRef) -> MddResult<MethodFactView<'a>> {
        let source = self.facts.metadata.source();
        let invalid = || {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.methods",
                "invalid or foreign method identity",
            )
        };
        if entity.snapshot_id != source.snapshot_id
            || entity.dex_occurrence_id != source.dex_occurrence_id
            || !matches!(
                entity.kind,
                EntityKind::MethodReference | EntityKind::MethodDefinition
            )
        {
            return Err(invalid());
        }
        let reference = self
            .facts
            .definitions
            .method_references
            .get(entity.local_index as usize)
            .filter(|r| r.method_idx == entity.local_index)
            .ok_or_else(invalid)?;
        let definition = self
            .definitions
            .binary_search_by_key(&entity.local_index, |d| d.method_idx)
            .ok()
            .map(|index| self.definitions[index]);
        if entity.kind == EntityKind::MethodDefinition && definition.is_none() {
            return Err(invalid());
        }
        let prototype = self
            .facts
            .metadata
            .prototypes()
            .get(reference.proto_idx as usize)
            .filter(|item| item.data.proto_idx == reference.proto_idx)
            .map(|item| &item.data)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "facts.methods",
                    "validated method prototype is missing",
                )
            })?;
        Ok(MethodFactView {
            source,
            reference,
            prototype,
            definition,
        })
    }
    /// Read prototype parameter types without requiring annotations or code.
    /// Definition identities must name an actual definition in this occurrence;
    /// reference identities may describe a reference-only method.
    pub fn parameter_types(
        &self,
        method: &EntityRef,
        limits: PrototypeParameterLimits,
    ) -> MddResult<MethodPrototypeParameters<'a>> {
        let source = self.facts.metadata.source();
        if method.snapshot_id != source.snapshot_id
            || method.dex_occurrence_id != source.dex_occurrence_id
            || !matches!(
                method.kind,
                EntityKind::MethodReference | EntityKind::MethodDefinition
            )
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.method_parameters",
                "foreign or invalid method identity",
            ));
        }
        let reference = self
            .facts
            .definitions
            .method_references
            .get(method.local_index as usize)
            .filter(|entry| entry.method_idx == method.local_index)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.method_parameters",
                    "method reference is missing",
                )
            })?;
        let definition = self
            .definitions
            .binary_search_by_key(&method.local_index, |entry| entry.method_idx)
            .ok()
            .map(|index| self.definitions[index]);
        if method.kind == EntityKind::MethodDefinition && definition.is_none() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.method_parameters",
                "method definition is missing",
            ));
        }
        let broken = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.method_parameters",
                "validated method prototype is inconsistent",
            )
        };
        if definition.is_some_and(|entry| entry.class_idx != reference.class_idx) {
            return Err(broken());
        }
        let prototype = self
            .facts
            .metadata
            .prototypes()
            .get(reference.proto_idx as usize)
            .filter(|entry| {
                entry.data.proto_idx == reference.proto_idx
                    && entry.entity.kind == EntityKind::Prototype
                    && entry.entity.local_index == reference.proto_idx
                    && entry.entity.snapshot_id == source.snapshot_id
                    && entry.entity.dex_occurrence_id == source.dex_occurrence_id
            })
            .map(|entry| &entry.data)
            .ok_or_else(broken)?;
        let count = u64::try_from(prototype.parameter_type_indices.len()).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.method_parameters",
                "parameter count overflow",
            )
        })?;
        if count > limits.max_parameters || count > u64::from(u32::MAX) {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.method_parameters",
                "parameter count budget exceeded",
            ));
        }
        if reference.parameter_descriptors.len() != prototype.parameter_type_indices.len() {
            return Err(broken());
        }
        for (index, expected) in prototype
            .parameter_type_indices
            .iter()
            .zip(&reference.parameter_descriptors)
        {
            let fact = self
                .facts
                .metadata
                .types()
                .get(*index as usize)
                .ok_or_else(broken)?;
            if fact.data.type_idx != *index
                || fact.data.descriptor != *expected
                || fact.entity.kind != EntityKind::Type
                || fact.entity.local_index != *index
                || fact.entity.snapshot_id != source.snapshot_id
                || fact.entity.dex_occurrence_id != source.dex_occurrence_id
            {
                return Err(broken());
            }
        }
        Ok(MethodPrototypeParameters {
            source,
            reference,
            prototype,
            definition,
            metadata: &self.facts.metadata,
        })
    }

    /// Iterate every encoded method reference in DEX method-id order without copying values.
    pub fn iter(&self) -> impl Iterator<Item = MddResult<MethodFactView<'a>>> + '_ {
        self.facts
            .definitions
            .method_references
            .iter()
            .map(|reference| {
                let prototype = self
                    .facts
                    .metadata
                    .prototypes()
                    .get(reference.proto_idx as usize)
                    .map(|item| &item.data)
                    .ok_or_else(|| {
                        MddError::new(
                            ErrorCode::InternalFault,
                            "facts.methods",
                            "validated method prototype is missing",
                        )
                    })?;
                let definition = self
                    .definitions
                    .binary_search_by_key(&reference.method_idx, |definition| definition.method_idx)
                    .ok()
                    .map(|index| self.definitions[index]);
                Ok(MethodFactView {
                    source: self.facts.metadata.source(),
                    reference,
                    prototype,
                    definition,
                })
            })
    }
}

impl DefinitionFacts {
    /// Validate a direct borrowed class view without allocating or merging occurrences.
    pub fn class_fact_views(&self, limits: ClassViewLimits) -> MddResult<ClassFactViews<'_>> {
        if self.definition_coverage != Completeness::Complete
            || self.metadata.metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.classes",
                "complete metadata and definitions are required",
            ));
        }
        let classes = &self.definitions.classes;
        let interfaces = &self.definitions.interfaces;
        if u64::try_from(classes.len()).map_or(true, |n| n > limits.max_classes)
            || u64::try_from(interfaces.len()).map_or(true, |n| n > limits.max_interfaces)
        {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.classes",
                "class view row budget exceeded",
            ));
        }
        let broken = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.classes",
                "validated class data is inconsistent",
            )
        };
        let mut cursor = 0usize;
        for (index, class) in classes.iter().enumerate() {
            if u32::try_from(index).ok() != Some(class.class_def_idx) {
                return Err(broken());
            }
            let class_type = self
                .metadata
                .types()
                .get(class.class_idx as usize)
                .ok_or_else(broken)?;
            if class_type.data.type_idx != class.class_idx
                || class_type.data.descriptor != class.descriptor
            {
                return Err(broken());
            }
            match (class.superclass_idx, class.superclass_descriptor.as_ref()) {
                (None, None) => (),
                (Some(idx), Some(descriptor)) => {
                    let actual = self.metadata.types().get(idx as usize).ok_or_else(broken)?;
                    if actual.data.type_idx != idx || actual.data.descriptor != *descriptor {
                        return Err(broken());
                    }
                }
                _ => return Err(broken()),
            }
            match (class.source_file_idx, class.source_file.as_ref()) {
                (None, None) => (),
                (Some(idx), Some(text)) => {
                    let actual = self
                        .metadata
                        .strings()
                        .get(idx as usize)
                        .ok_or_else(broken)?;
                    if actual.data.string_idx != idx
                        || !actual.data.text.equals_raw(text)
                        || !actual.data.text.equals_utf16(text)
                    {
                        return Err(broken());
                    }
                }
                _ => return Err(broken()),
            }
            let start = cursor;
            while let Some(interface) = interfaces
                .get(cursor)
                .filter(|i| i.class_def_idx == class.class_def_idx)
            {
                if interface.class_idx != class.class_idx
                    || u32::try_from(cursor - start).ok() != Some(interface.ordinal)
                {
                    return Err(broken());
                }
                let actual = self
                    .metadata
                    .types()
                    .get(interface.interface_type_idx as usize)
                    .ok_or_else(broken)?;
                if actual.data.type_idx != interface.interface_type_idx
                    || actual.data.descriptor != interface.interface_descriptor
                {
                    return Err(broken());
                }
                cursor += 1;
            }
        }
        if cursor != interfaces.len() {
            return Err(broken());
        }
        Ok(ClassFactViews { facts: self })
    }
    /// Build a bounded join for all field IDs in this immutable DEX occurrence.
    pub fn field_fact_views(&self, limits: FieldViewLimits) -> MddResult<FieldFactViews<'_>> {
        if self.definition_coverage != Completeness::Complete
            || self.metadata.metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.fields",
                "complete metadata and definitions are required",
            ));
        }
        let count = self.definitions.field_definitions.len();
        let count_u64 = u64::try_from(count).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.fields",
                "field definition count overflow",
            )
        })?;
        let bytes = count_u64
            .checked_mul(std::mem::size_of::<&FieldDefinition>() as u64)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.fields",
                    "field join byte overflow",
                )
            })?;
        if count_u64 > limits.max_definition_entries || bytes > limits.max_index_bytes {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.fields",
                "field join index budget exceeded",
            ));
        }
        let mut definitions = Vec::new();
        definitions.try_reserve_exact(count).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.fields",
                "field join allocation failed",
            )
        })?;
        definitions.extend(self.definitions.field_definitions.iter());
        definitions.sort_unstable_by_key(|definition| definition.field_idx);
        if definitions
            .windows(2)
            .any(|pair| pair[0].field_idx == pair[1].field_idx)
        {
            return Err(MddError::new(
                ErrorCode::InternalFault,
                "facts.fields",
                "duplicate field definition identity",
            ));
        }
        Ok(FieldFactViews {
            facts: self,
            definitions,
        })
    }
    /// Build a bounded join for all method IDs in this immutable DEX occurrence.
    pub fn method_fact_views(&self, limits: MethodViewLimits) -> MddResult<MethodFactViews<'_>> {
        if self.definition_coverage != Completeness::Complete
            || self.metadata.metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.methods",
                "complete metadata and definitions are required",
            ));
        }
        let count = self.definitions.method_definitions.len();
        let count_u64 = u64::try_from(count).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.methods",
                "method definition count overflow",
            )
        })?;
        let bytes = count_u64
            .checked_mul(std::mem::size_of::<&MethodDefinition>() as u64)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.methods",
                    "method join byte overflow",
                )
            })?;
        if count_u64 > limits.max_definition_entries || bytes > limits.max_index_bytes {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.methods",
                "method join index budget exceeded",
            ));
        }
        let mut definitions = Vec::new();
        definitions.try_reserve_exact(count).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.methods",
                "method join allocation failed",
            )
        })?;
        definitions.extend(self.definitions.method_definitions.iter());
        definitions.sort_unstable_by_key(|definition| definition.method_idx);
        if definitions
            .windows(2)
            .any(|pair| pair[0].method_idx == pair[1].method_idx)
        {
            return Err(MddError::new(
                ErrorCode::InternalFault,
                "facts.methods",
                "duplicate method definition identity",
            ));
        }
        Ok(MethodFactViews {
            facts: self,
            definitions,
        })
    }
    pub fn metadata(&self) -> &MetadataFacts {
        &self.metadata
    }
    pub fn definitions(&self) -> &DexDefinitions {
        &self.definitions
    }
    pub fn definition_coverage(&self) -> Completeness {
        self.definition_coverage
    }
    pub fn completed_layers(&self) -> &[String] {
        &self.completed_layers
    }
    pub fn unbuilt_layers(&self) -> &[String] {
        &self.unbuilt_layers
    }
    pub fn build(metadata: MetadataFacts, limits: DefinitionLimits) -> MddResult<Self> {
        let source = &metadata.source;
        let bind = |error: MddError| {
            error
                .detail("snapshot_id", source.snapshot_id.clone())
                .detail("dex_occurrence_id", source.dex_occurrence_id.clone())
                .detail("member_id", source.member_id.clone())
                .detail("content_id", source.content_id.clone())
        };
        if metadata.metadata_coverage != Completeness::Complete {
            return Err(bind(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.definitions",
                "validated metadata is required before definition construction",
            )));
        }
        if content_id(metadata.bytes()) != source.content_id {
            return Err(bind(MddError::new(
                ErrorCode::InternalFault,
                "facts.definitions",
                "held bytes do not match metadata content identity",
            )));
        }
        let definitions = read_definitions(metadata.bytes(), &metadata.header, &metadata, limits)
            .map_err(bind)?;
        let mut completed_layers = metadata.completed_layers.clone();
        completed_layers.push("definitions".into());
        let mut unbuilt_layers: Vec<_> = metadata
            .unbuilt_layers
            .iter()
            .filter(|l| l.as_str() != "definitions")
            .cloned()
            .collect();
        for layer in &definitions.unbuilt_layers {
            if !unbuilt_layers.contains(layer) {
                unbuilt_layers.push(layer.clone());
            }
        }
        Ok(Self {
            metadata,
            definitions,
            definition_coverage: Completeness::Complete,
            completed_layers,
            unbuilt_layers,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        self.metadata.bytes()
    }

    pub fn entity(&self, kind: EntityKind, local_index: u32) -> MddResult<EntityRef> {
        let exists = match kind {
            EntityKind::ClassDefinition => {
                self.definitions.classes.get(local_index as usize).is_some()
            }
            EntityKind::FieldReference => self
                .definitions
                .field_references
                .get(local_index as usize)
                .is_some(),
            EntityKind::MethodReference => self
                .definitions
                .method_references
                .get(local_index as usize)
                .is_some(),
            EntityKind::FieldDefinition => self
                .definitions
                .field_definitions
                .iter()
                .any(|d| d.field_idx == local_index),
            EntityKind::MethodDefinition => self
                .definitions
                .method_definitions
                .iter()
                .any(|d| d.method_idx == local_index),
            _ => false,
        };
        if !exists {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.definitions",
                "definition entity kind/index does not exist in this occurrence",
            ));
        }
        Ok(EntityRef {
            snapshot_id: self.metadata.source.snapshot_id.clone(),
            dex_occurrence_id: self.metadata.source.dex_occurrence_id.clone(),
            kind,
            local_index,
        })
    }

    pub fn require_relation_columns(
        &self,
        relation: DefinitionRelation,
        columns: &[&str],
    ) -> MddResult<()> {
        let available: &[&str] = match relation {
            DefinitionRelation::Classes => &[
                "file_id",
                "class_def_idx",
                "class_idx",
                "descriptor",
                "access_flags",
                "superclass_descriptor",
                "interface_count",
                "source_file",
            ],
            DefinitionRelation::ClassInterfaces => &[
                "file_id",
                "class_idx",
                "ordinal",
                "interface_type_idx",
                "interface_descriptor",
            ],
            DefinitionRelation::ClassFields => &[
                "file_id",
                "class_idx",
                "class_descriptor",
                "field_idx",
                "field_name",
                "field_descriptor",
                "kind",
                "access_flags",
            ],
            DefinitionRelation::ClassMethods => &[
                "file_id",
                "class_idx",
                "class_descriptor",
                "method_idx",
                "method_name",
                "method_descriptor",
                "kind",
                "access_flags",
            ],
            DefinitionRelation::Methods => &[
                "file_id",
                "method_idx",
                "class_idx",
                "class_descriptor",
                "proto_idx",
                "name",
                "descriptor",
                "return_descriptor",
                "param_count",
                "access_flags",
                "method_kind",
            ],
        };
        for column in columns {
            if relation == DefinitionRelation::Methods
                && ["opcode_count", "opcode_hex", "*"].contains(column)
            {
                return Err(MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.definitions",
                    "complete methods columns require code_layout facts",
                )
                .detail("required_layer", "code_layout")
                .detail("column", (*column).to_owned()));
            }
            if relation == DefinitionRelation::Methods && *column == "param_descriptors" {
                return Err(MddError::new(ErrorCode::IncompleteFacts, "facts.definitions", "native parameter descriptors are exact; compatibility text encoding is not qualified")
                    .detail("required_layer", "compatibility_text_profile"));
            }
            if *column != "*" && !available.contains(column) {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.definitions",
                    "unknown definition relation column",
                )
                .detail("column", (*column).to_owned()));
            }
        }
        Ok(())
    }

    pub fn class_field_rows(&self, file_id: u32) -> Vec<ClassFieldRow> {
        self.definitions
            .field_definitions
            .iter()
            .map(|d| {
                let r = &self.definitions.field_references[d.field_idx as usize];
                ClassFieldRow {
                    file_id,
                    class_idx: d.class_idx,
                    class_descriptor: r.class_descriptor.clone(),
                    field_idx: d.field_idx,
                    field_name: r.field_name.clone(),
                    field_descriptor: r.descriptor.clone(),
                    kind: d.kind.as_str().into(),
                    access_flags: d.access_flags,
                }
            })
            .collect()
    }
    pub fn class_method_rows(&self, file_id: u32) -> Vec<ClassMethodRow> {
        self.definitions
            .method_definitions
            .iter()
            .map(|d| {
                let r = &self.definitions.method_references[d.method_idx as usize];
                ClassMethodRow {
                    file_id,
                    class_idx: d.class_idx,
                    class_descriptor: r.class_descriptor.clone(),
                    method_idx: d.method_idx,
                    method_name: r.method_name.clone(),
                    method_descriptor: r.descriptor.clone(),
                    kind: d.kind.as_str().into(),
                    access_flags: d.access_flags,
                }
            })
            .collect()
    }
    pub fn class_interface_rows(&self, file_id: u32) -> Vec<ClassInterfaceRow> {
        self.definitions
            .interfaces
            .iter()
            .map(|d| ClassInterfaceRow {
                file_id,
                class_idx: d.class_idx,
                ordinal: d.ordinal,
                interface_type_idx: d.interface_type_idx,
                interface_descriptor: d.interface_descriptor.clone(),
            })
            .collect()
    }
}

pub struct ClassMatch<'a> {
    pub facts: &'a DefinitionFacts,
    pub class: &'a ClassDefinition,
}
/// Resolution only within the complete `DefinitionFacts` explicitly supplied by the caller.
/// `Missing` does not establish that any unprovided input or DEX occurrence lacks the class.
/// Use `SnapshotFactIndex::classes_exact` for selected-scope and coverage evidence.
pub enum ClassResolution<'a> {
    Missing,
    Unique(ClassMatch<'a>),
    Ambiguous(Vec<ClassMatch<'a>>),
}
pub fn resolve_class<'a>(
    facts: &'a [DefinitionFacts],
    descriptor: &str,
) -> MddResult<ClassResolution<'a>> {
    let first = facts.first().ok_or_else(|| {
        MddError::new(
            ErrorCode::IncompleteFacts,
            "facts.definitions",
            "no definition facts were provided",
        )
    })?;
    if facts
        .iter()
        .any(|f| f.metadata.source.snapshot_id != first.metadata.source.snapshot_id)
    {
        return Err(MddError::new(
            ErrorCode::InvalidArgument,
            "facts.definitions",
            "a definition lookup cannot combine different snapshots",
        ));
    }
    let mut occurrences = std::collections::BTreeSet::new();
    for entry in facts {
        if entry.metadata.metadata_coverage() != Completeness::Complete
            || entry.definition_coverage != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.definitions",
                "provided definition or metadata facts are incomplete",
            ));
        }
        if !occurrences.insert(&entry.metadata.source.dex_occurrence_id) {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.definitions",
                "the same DEX occurrence was provided more than once",
            ));
        }
    }
    let mut matches: Vec<_> = facts
        .iter()
        .flat_map(|facts| {
            facts
                .definitions
                .classes
                .iter()
                .filter(move |c| c.descriptor == descriptor)
                .map(move |class| ClassMatch { facts, class })
        })
        .collect();
    Ok(match matches.len() {
        0 => ClassResolution::Missing,
        1 => ClassResolution::Unique(matches.remove(0)),
        _ => ClassResolution::Ambiguous(matches),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdd_dex::strings::StringLimits;
    use mdd_input::{
        archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
        snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
    };
    use serde_json::Value;
    use std::path::PathBuf;
    fn build_two() -> Vec<DefinitionFacts> {
        build_named("definitions-035.dex")
    }
    fn build_named(name: &str) -> Vec<DefinitionFacts> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/definitions/generated")
            .join(name);
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        snapshot
            .sources()
            .iter()
            .map(|source| {
                let inventory = ArchiveInventory::build(
                    source,
                    InventoryPolicy::default(),
                    ArchiveLimits::default(),
                )
                .unwrap();
                DefinitionFacts::build(
                    MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default())
                        .unwrap(),
                    DefinitionLimits::default(),
                )
                .unwrap()
            })
            .collect()
    }
    #[test]
    fn prototype_parameter_types_preserve_identity_without_annotations() {
        let facts = build_two();
        for fact in &facts {
            assert!(
                fact.unbuilt_layers()
                    .iter()
                    .any(|layer| layer == "annotations")
            );
            let views = fact.method_fact_views(MethodViewLimits::default()).unwrap();
            for name in ["staticCall", "externalCall"] {
                let reference = fact
                    .definitions()
                    .method_references
                    .iter()
                    .find(|reference| reference.method_name == name)
                    .unwrap();
                let id = fact
                    .entity(EntityKind::MethodReference, reference.method_idx)
                    .unwrap();
                let params = views
                    .parameter_types(&id, PrototypeParameterLimits::default())
                    .unwrap();
                assert_eq!(
                    params.source.dex_occurrence_id,
                    fact.metadata().source().dex_occurrence_id
                );
                assert_eq!(params.definition.is_none(), name == "externalCall");
                let types = params.iter().collect::<MddResult<Vec<_>>>().unwrap();
                assert_eq!(types.len(), 1);
                assert_eq!(types[0].ordinal, 0);
                assert_eq!(types[0].type_fact.data.descriptor, "I");
                assert_eq!(
                    types[0].type_fact.entity.dex_occurrence_id,
                    id.dex_occurrence_id
                );
                assert_eq!(
                    views
                        .parameter_types(&id, PrototypeParameterLimits { max_parameters: 0 })
                        .err()
                        .unwrap()
                        .code,
                    ErrorCode::QuotaExceeded
                );
                if name == "externalCall" {
                    let forged = EntityRef {
                        kind: EntityKind::MethodDefinition,
                        ..id.clone()
                    };
                    assert_eq!(
                        views
                            .parameter_types(&forged, PrototypeParameterLimits::default())
                            .err()
                            .unwrap()
                            .code,
                        ErrorCode::InvalidArgument
                    );
                }
            }
            let reference = fact
                .definitions()
                .method_references
                .iter()
                .find(|reference| reference.method_name == "virtualCall")
                .unwrap();
            let id = fact
                .entity(EntityKind::MethodDefinition, reference.method_idx)
                .unwrap();
            let empty = views
                .parameter_types(&id, PrototypeParameterLimits { max_parameters: 0 })
                .unwrap();
            assert_eq!(empty.iter().count(), 0);
        }
        let other = facts[1]
            .definitions()
            .method_references
            .iter()
            .find(|reference| reference.method_name == "staticCall")
            .unwrap();
        let foreign = facts[1]
            .entity(EntityKind::MethodReference, other.method_idx)
            .unwrap();
        let views = facts[0]
            .method_fact_views(MethodViewLimits::default())
            .unwrap();
        assert_eq!(
            views
                .parameter_types(&foreign, PrototypeParameterLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );

        let mut corrupted = facts[0].clone();
        let reference = corrupted
            .definitions
            .method_references
            .iter_mut()
            .find(|reference| reference.method_name == "staticCall")
            .unwrap();
        reference.parameter_descriptors[0] = "J".into();
        let index = reference.method_idx;
        let views = corrupted
            .method_fact_views(MethodViewLimits::default())
            .unwrap();
        let id = corrupted
            .entity(EntityKind::MethodReference, index)
            .unwrap();
        assert_eq!(
            views
                .parameter_types(&id, PrototypeParameterLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalFault
        );

        // A second physical fixture has two differently typed parameters;
        // only metadata and definitions are built, not annotation facts.
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/annotations/generated/annotations-038.dex");
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
        let facts = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
        let reference = facts
            .definitions()
            .method_references
            .iter()
            .find(|reference| reference.method_name == "m")
            .unwrap();
        let id = facts
            .entity(EntityKind::MethodReference, reference.method_idx)
            .unwrap();
        let views = facts
            .method_fact_views(MethodViewLimits::default())
            .unwrap();
        let params = views
            .parameter_types(&id, PrototypeParameterLimits::default())
            .unwrap();
        let values = params
            .iter()
            .map(|value| value.unwrap().type_fact.data.descriptor.as_str())
            .collect::<Vec<_>>();
        assert_eq!(values, ["Ljava/util/List;", "I"]);
    }
    #[test]
    fn borrowed_class_views_preserve_occurrences_direct_interfaces_and_lossless_source() {
        let facts = build_two();
        for fact in &facts {
            let view = fact.class_fact_views(ClassViewLimits::default()).unwrap();
            let rows = view.iter().collect::<MddResult<Vec<_>>>().unwrap();
            assert_eq!(rows.len(), fact.definitions().classes.len());
            assert!(rows.iter().enumerate().all(|(index, row)| {
                row.definition.class_def_idx as usize == index
                    && row.source.dex_occurrence_id == fact.metadata().source().dex_occurrence_id
                    && row.class_type.type_idx == row.definition.class_idx
                    && row.class_type.descriptor == row.definition.descriptor
            }));
            let base = rows
                .iter()
                .find(|row| row.definition.descriptor == "Lfixture/Base;")
                .unwrap();
            assert_eq!(base.superclass.unwrap().descriptor, "Ljava/lang/Object;");
            assert_eq!(
                base.source_file.unwrap().text.strict_utf8().unwrap(),
                "Base.java"
            );
            assert_eq!(base.interfaces.len(), 1);
            assert_eq!(base.interfaces[0].ordinal, 0);
            assert_eq!(base.interfaces[0].interface_descriptor, "Lfixture/I1;");
            let child = rows
                .iter()
                .find(|row| row.definition.descriptor == "Lfixture/Child;")
                .unwrap();
            assert!(child.interfaces.is_empty());
        }
        assert_eq!(
            facts[0].metadata().source().snapshot_id,
            facts[1].metadata().source().snapshot_id
        );
        assert_ne!(
            facts[0].metadata().source().dex_occurrence_id,
            facts[1].metadata().source().dex_occurrence_id
        );
        let surrogate = build_named("source-file-surrogate.dex");
        let view = surrogate[0]
            .class_fact_views(ClassViewLimits::default())
            .unwrap();
        let base = view
            .iter()
            .find_map(|row| {
                let row = row.unwrap();
                (row.definition.descriptor == "Lfixture/Base;").then_some(row)
            })
            .unwrap();
        assert_eq!(base.source_file.unwrap().text.utf16_units, [0xd800]);
        assert_eq!(base.source_file.unwrap().text.raw_mutf8, [0xed, 0xa0, 0x80]);
        let root = build_named("nullable-root-class.dex");
        let view = root[0]
            .class_fact_views(ClassViewLimits::default())
            .unwrap();
        let object = view
            .iter()
            .find_map(|row| {
                let row = row.unwrap();
                (row.definition.descriptor == "Ljava/lang/Object;").then_some(row)
            })
            .unwrap();
        assert!(
            object.superclass.is_none()
                && object.source_file.is_none()
                && object.interfaces.is_empty()
        );
        for limits in [
            ClassViewLimits {
                max_classes: 0,
                ..ClassViewLimits::default()
            },
            ClassViewLimits {
                max_interfaces: 0,
                ..ClassViewLimits::default()
            },
        ] {
            assert_eq!(
                facts[0].class_fact_views(limits).err().unwrap().code,
                ErrorCode::QuotaExceeded
            );
        }
        let mut incomplete = facts[0].clone();
        incomplete.definition_coverage = Completeness::Partial;
        assert_eq!(
            incomplete
                .class_fact_views(ClassViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        let mut malformed = facts[0].clone();
        malformed.definitions.interfaces[0].ordinal = 1;
        assert_eq!(
            malformed
                .class_fact_views(ClassViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalFault
        );
    }
    #[test]
    fn direct_member_lookup_matches_iteration_and_binds_occurrence() {
        let facts = build_two();
        for fact in &facts {
            let fields = fact.field_fact_views(FieldViewLimits::default()).unwrap();
            for row in fields.iter() {
                let row = row.unwrap();
                let id = fact
                    .entity(EntityKind::FieldReference, row.reference.field_idx)
                    .unwrap();
                let found = fields.get(&id).unwrap();
                assert_eq!(found.reference.field_idx, row.reference.field_idx);
                assert_eq!(
                    found.definition.map(|d| d.field_idx),
                    row.definition.map(|d| d.field_idx)
                );
                let definition_id = EntityRef {
                    kind: EntityKind::FieldDefinition,
                    ..id.clone()
                };
                assert_eq!(fields.get(&definition_id).is_ok(), row.definition.is_some());
                let foreign = EntityRef {
                    dex_occurrence_id: "foreign".into(),
                    ..id
                };
                assert_eq!(
                    fields.get(&foreign).err().unwrap().code,
                    ErrorCode::InvalidArgument
                );
            }
            let methods = fact.method_fact_views(MethodViewLimits::default()).unwrap();
            for row in methods.iter() {
                let row = row.unwrap();
                let id = fact
                    .entity(EntityKind::MethodReference, row.reference.method_idx)
                    .unwrap();
                let found = methods.get(&id).unwrap();
                assert_eq!(found.reference.method_idx, row.reference.method_idx);
                assert_eq!(
                    found.definition.map(|d| d.method_idx),
                    row.definition.map(|d| d.method_idx)
                );
                let definition_id = EntityRef {
                    kind: EntityKind::MethodDefinition,
                    ..id.clone()
                };
                assert_eq!(
                    methods.get(&definition_id).is_ok(),
                    row.definition.is_some()
                );
                let foreign = EntityRef {
                    snapshot_id: "foreign".into(),
                    ..id
                };
                assert_eq!(
                    methods.get(&foreign).err().unwrap().code,
                    ErrorCode::InvalidArgument
                );
            }
        }
        let fields = facts[0]
            .field_fact_views(FieldViewLimits::default())
            .unwrap();
        let wrong = EntityRef {
            snapshot_id: facts[0].metadata.source.snapshot_id.clone(),
            dex_occurrence_id: facts[0].metadata.source.dex_occurrence_id.clone(),
            kind: EntityKind::MethodReference,
            local_index: 0,
        };
        assert_eq!(
            fields.get(&wrong).err().unwrap().code,
            ErrorCode::InvalidArgument
        );
        let missing = EntityRef {
            kind: EntityKind::FieldReference,
            local_index: u32::MAX,
            ..wrong
        };
        assert_eq!(
            fields.get(&missing).err().unwrap().code,
            ErrorCode::InvalidArgument
        );
    }
    #[test]
    fn borrowed_field_views_distinguish_reference_static_and_instance() {
        use mdd_dex::definitions::FieldKind;
        let facts = build_two();
        for fact in &facts {
            let view = fact.field_fact_views(FieldViewLimits::default()).unwrap();
            let rows = view.iter().collect::<MddResult<Vec<_>>>().unwrap();
            assert_eq!(rows.len(), fact.definitions().field_references.len());
            assert!(
                rows.windows(2)
                    .all(|r| r[0].reference.field_idx < r[1].reference.field_idx)
            );
            assert!(rows.iter().all(|r| {
                r.source.dex_occurrence_id == fact.metadata().source().dex_occurrence_id
                    && r.field_type.type_idx == r.reference.type_idx
                    && r.field_type.descriptor == r.reference.type_descriptor
            }));
            let external = rows
                .iter()
                .find(|r| r.reference.field_name == "outside")
                .unwrap();
            assert!(external.definition.is_none());
            let static_field = rows
                .iter()
                .find(|r| r.reference.field_name == "sValue")
                .unwrap();
            assert_eq!(static_field.definition.unwrap().kind, FieldKind::Static);
            let instance = rows
                .iter()
                .find(|r| r.reference.field_name == "iValue")
                .unwrap();
            assert_eq!(instance.definition.unwrap().kind, FieldKind::Instance);
            for row in rows.iter().filter_map(|r| r.definition.map(|d| (r, d))) {
                assert_eq!(row.0.reference.field_idx, row.1.field_idx);
                assert_eq!(row.0.reference.class_idx, row.1.class_idx);
            }
        }
        assert_eq!(
            facts[0].metadata().source().snapshot_id,
            facts[1].metadata().source().snapshot_id
        );
        assert_ne!(
            facts[0].metadata().source().dex_occurrence_id,
            facts[1].metadata().source().dex_occurrence_id
        );
        for limits in [
            FieldViewLimits {
                max_definition_entries: 0,
                ..FieldViewLimits::default()
            },
            FieldViewLimits {
                max_index_bytes: 0,
                ..FieldViewLimits::default()
            },
        ] {
            assert_eq!(
                facts[0].field_fact_views(limits).err().unwrap().code,
                ErrorCode::QuotaExceeded
            );
        }
        let mut incomplete = facts[0].clone();
        incomplete.definition_coverage = Completeness::Partial;
        assert_eq!(
            incomplete
                .field_fact_views(FieldViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        let mut duplicate = facts[0].clone();
        duplicate
            .definitions
            .field_definitions
            .push(duplicate.definitions.field_definitions[0].clone());
        assert_eq!(
            duplicate
                .field_fact_views(FieldViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InternalFault
        );
    }
    #[test]
    fn borrowed_method_views_distinguish_reference_native_abstract_and_present() {
        use mdd_dex::definitions::MethodBody;
        let facts = build_two();
        for fact in &facts {
            let view = fact.method_fact_views(MethodViewLimits::default()).unwrap();
            let rows = view.iter().collect::<MddResult<Vec<_>>>().unwrap();
            assert_eq!(rows.len(), fact.definitions().method_references.len());
            assert!(
                rows.windows(2)
                    .all(|r| r[0].reference.method_idx < r[1].reference.method_idx)
            );
            assert!(rows.iter().all(|r| r.source.dex_occurrence_id
                == fact.metadata().source().dex_occurrence_id
                && r.prototype.proto_idx == r.reference.proto_idx));
            let external = rows
                .iter()
                .find(|r| r.reference.method_name == "externalCall")
                .unwrap();
            assert!(external.definition.is_none());
            let native = rows
                .iter()
                .find(|r| r.reference.method_name == "nativeCall")
                .unwrap();
            assert!(matches!(
                native.definition.unwrap().body,
                MethodBody::Native
            ));
            let abstract_method = rows
                .iter()
                .find(|r| r.reference.method_name == "abstractCall")
                .unwrap();
            assert!(matches!(
                abstract_method.definition.unwrap().body,
                MethodBody::Abstract
            ));
            let present = rows
                .iter()
                .find(|r| r.reference.method_name == "virtualCall")
                .unwrap();
            assert!(matches!(
                present.definition.unwrap().body,
                MethodBody::Present { .. }
            ));
            let parameterized = rows
                .iter()
                .find(|r| r.reference.method_name == "staticCall")
                .unwrap();
            assert_eq!(parameterized.reference.parameter_descriptors, ["I"]);
            assert_eq!(parameterized.reference.return_descriptor, "I");
            assert_eq!(
                present.prototype.parameter_type_indices,
                fact.metadata().prototypes()[present.reference.proto_idx as usize]
                    .data
                    .parameter_type_indices
            );
            assert!(
                fact.require_relation_columns(DefinitionRelation::Methods, &["opcode_hex"])
                    .is_err()
            );
            assert!(
                fact.require_relation_columns(DefinitionRelation::Methods, &["param_descriptors"])
                    .is_err()
            );
        }
        assert_eq!(
            facts[0].metadata().source().snapshot_id,
            facts[1].metadata().source().snapshot_id
        );
        assert_ne!(
            facts[0].metadata().source().dex_occurrence_id,
            facts[1].metadata().source().dex_occurrence_id
        );
        for limits in [
            MethodViewLimits {
                max_definition_entries: 0,
                ..MethodViewLimits::default()
            },
            MethodViewLimits {
                max_index_bytes: 0,
                ..MethodViewLimits::default()
            },
        ] {
            assert_eq!(
                facts[0].method_fact_views(limits).err().unwrap().code,
                ErrorCode::QuotaExceeded
            );
        }
        let mut incomplete = facts[0].clone();
        incomplete.definition_coverage = Completeness::Partial;
        assert_eq!(
            incomplete
                .method_fact_views(MethodViewLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
    }

    #[test]
    fn class_lookup_rejects_unbuilt_partial_and_duplicate_occurrences() {
        let error = match resolve_class(&[], "Lfixture/Base;") {
            Err(error) => error,
            _ => panic!("unprovided facts must not prove absence"),
        };
        assert_eq!(error.code, ErrorCode::IncompleteFacts);

        let facts = build_two();
        let mut partial = facts[0].clone();
        partial.definition_coverage = Completeness::Partial;
        let error = match resolve_class(&[partial], "Lfixture/Base;") {
            Err(error) => error,
            _ => panic!("partial definitions must not prove a class result"),
        };
        assert_eq!(error.code, ErrorCode::IncompleteFacts);
        let duplicate = vec![facts[0].clone(), facts[0].clone()];
        let error = match resolve_class(&duplicate, "Lfixture/Base;") {
            Err(error) => error,
            _ => panic!("one occurrence must not be counted twice"),
        };
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(matches!(
            resolve_class(&facts[..1], "Lfixture/Absent;").unwrap(),
            ClassResolution::Missing
        ));
        assert!(matches!(
            resolve_class(&facts, "Lfixture/Base;").unwrap(),
            ClassResolution::Ambiguous(ref matches) if matches.len() == 2
        ));
    }

    #[test]
    fn occurrences_and_reference_definition_kinds_remain_distinct() {
        let facts = build_two();
        match resolve_class(&facts, "Lfixture/Base;").unwrap() {
            ClassResolution::Ambiguous(rows) => {
                assert_eq!(rows.len(), 2);
                assert_ne!(
                    rows[0].facts.metadata.source.dex_occurrence_id,
                    rows[1].facts.metadata.source.dex_occurrence_id
                );
            }
            _ => panic!("same descriptor from two occurrences must remain ambiguous"),
        }
        let first = &facts[0];
        assert!(first.entity(EntityKind::ClassDefinition, 0).is_ok());
        assert!(
            first
                .entity(
                    EntityKind::ClassDefinition,
                    first.definitions.classes[0].class_idx
                )
                .is_err()
        );
        let method = first.definitions.method_definitions[0].method_idx;
        assert_ne!(
            first.entity(EntityKind::MethodReference, method).unwrap(),
            first.entity(EntityKind::MethodDefinition, method).unwrap()
        );
        let external = first
            .definitions
            .method_references
            .iter()
            .find(|r| r.method_name == "externalCall")
            .unwrap();
        assert!(
            first
                .entity(EntityKind::MethodReference, external.method_idx)
                .is_ok()
        );
        assert!(
            first
                .entity(EntityKind::MethodDefinition, external.method_idx)
                .is_err()
        );
        assert!(!first.bytes().is_empty());
        assert!(first.completed_layers.iter().any(|s| s == "definitions"));
        assert!(first.unbuilt_layers.iter().any(|s| s == "code_layout"));
        assert_eq!(
            first
                .require_relation_columns(DefinitionRelation::Methods, &["opcode_count"])
                .unwrap_err()
                .code,
            ErrorCode::IncompleteFacts
        );
        assert_eq!(
            first
                .require_relation_columns(DefinitionRelation::Methods, &["*"])
                .unwrap_err()
                .code,
            ErrorCode::IncompleteFacts
        );
        assert_eq!(
            first
                .require_relation_columns(DefinitionRelation::Methods, &["opcod_count"])
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert!(
            first
                .require_relation_columns(
                    DefinitionRelation::Methods,
                    &[
                        "file_id",
                        "method_idx",
                        "class_descriptor",
                        "return_descriptor"
                    ]
                )
                .is_ok()
        );
        let mut mixed = build_two();
        let other = build_two().remove(0);
        mixed.push(other);
        assert!(resolve_class(&mixed, "Lfixture/Base;").is_err());
    }
    #[test]
    fn wildcard_definition_columns_match_frozen_reference_schema() {
        let facts = build_two();
        let first = &facts[0];
        let schema: Value = serde_json::from_str(include_str!(
            "../../../conformance/manifests/relations.json"
        ))
        .unwrap();
        let field = serde_json::to_value(&first.class_field_rows(7)[0]).unwrap();
        let method = serde_json::to_value(&first.class_method_rows(7)[0]).unwrap();
        for (relation, row) in [("class_fields", field), ("class_methods", method)] {
            let expected = schema["relations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["name"] == relation)
                .unwrap();
            assert_eq!(row.as_object().unwrap().len(), 8);
            for column in expected["columns"].as_array().unwrap() {
                assert!(row.get(column["name"].as_str().unwrap()).is_some());
            }
            let relation = if relation == "class_fields" {
                DefinitionRelation::ClassFields
            } else {
                DefinitionRelation::ClassMethods
            };
            assert_eq!(row["file_id"], 7);
            assert!(first.require_relation_columns(relation, &["*"]).is_ok());
        }
        assert_eq!(first.class_interface_rows(7).len(), 2);
    }
}
