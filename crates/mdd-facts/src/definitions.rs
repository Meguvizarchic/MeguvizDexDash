//! Source-bound definition facts. Unbuilt code columns never masquerade as NULL.
use crate::metadata::{EntityKind, EntityRef, MetadataFacts, MetadataSource, TypeFact};
use mdd_dex::{
    definitions::{
        ClassDefinition, DefinitionLimits, DefinitionMetadata, DexDefinitions, FieldDefinition,
        FieldKind, FieldReference, InterfaceDefinition, MethodDefinition, MethodKind,
        MethodReference, read_definitions,
    },
    strings::DexString,
    types::{DexPrototype, DexType},
};
use mdd_types::{Completeness, ErrorCode, MddError, MddResult, content_id};
use serde::Serialize;
use std::sync::Arc;

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
    pub(crate) metadata: Arc<MetadataFacts>,
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
/// A `class_fields` row whose text is borrowed from the facts, without its `file_id`: what `for_each_class_field` hands out.
#[derive(Clone, Copy, Debug)]
pub struct ClassFieldRef<'a> {
    pub class_idx: u32,
    pub class_descriptor: &'a str,
    pub field_idx: u32,
    pub field_name: &'a str,
    pub field_descriptor: &'a str,
    pub kind: &'static str,
    pub access_flags: u32,
}
/// A `class_methods` row whose text is borrowed from the facts, without its `file_id`: what `for_each_class_method` hands out.
#[derive(Clone, Copy, Debug)]
pub struct ClassMethodRef<'a> {
    pub class_idx: u32,
    pub class_descriptor: &'a str,
    pub method_idx: u32,
    pub method_name: &'a str,
    pub method_descriptor: &'a str,
    pub kind: &'static str,
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

/// One `methods` row: one encoded method_id with its same-occurrence prototype
/// identity plus the optional real definition. Reference-only members carry a
/// genuine NULL `access_flags`/`method_kind`; they are not an unbuilt layer.
///
/// `param_descriptors` is the comma-separated UTF-8 rendering of the exact
/// ordered native parameter descriptor vector. The vector is a native atom; the
/// comma join is a compatibility text encoding (see
/// [`PARAM_DESCRIPTOR_ENCODING`]) that is total here because every validated
/// descriptor is scalar UTF-8: a non-scalar descriptor is refused while reading
/// types, before any row exists.
///
/// `opcode_count` and `opcode_hex` are not projected here: they need the
/// code-layout layer that this object does not hold. Assemble the complete
/// `methods` relation through
/// [`crate::code::MethodCodeFactViews::method_rows`], which joins these fields
/// with the exact decoded opcode sequence. Requesting either column from
/// [`DefinitionFacts::require_relation_columns`] returns `IncompleteFacts`
/// rather than a fabricated value.
#[derive(Clone, Debug, Serialize)]
pub struct MethodRow {
    pub file_id: u32,
    pub method_idx: u32,
    pub class_idx: u32,
    pub class_descriptor: String,
    pub proto_idx: u32,
    pub name: String,
    pub descriptor: String,
    pub return_descriptor: String,
    pub param_count: u32,
    pub param_descriptors: String,
    pub access_flags: Option<u32>,
    pub method_kind: Option<String>,
}

/// The compatibility text encoding of `methods.param_descriptors`: the exact
/// ordered prototype parameter descriptors joined by `,` with no surrounding
/// whitespace. Empty parameter lists encode as the empty string. This is not a
/// native atom by itself; the native atom is the ordered descriptor vector.
pub const PARAM_DESCRIPTOR_ENCODING: &str = "comma-separated-utf8-v1";

impl MethodRow {
    /// Assembled column names in contract order.
    pub const COLUMNS: &[&str] = &[
        "file_id",
        "method_idx",
        "class_idx",
        "class_descriptor",
        "proto_idx",
        "name",
        "descriptor",
        "return_descriptor",
        "param_count",
        "param_descriptors",
        "access_flags",
        "method_kind",
    ];
}

/// One `classes` row: one encoded class_def with its declared interfaces and
/// optional superclass/source file. `superclass_descriptor` and `source_file`
/// are the encoded NO_INDEX, not an unbuilt layer.
#[derive(Clone, Debug, Serialize)]
pub struct ClassRow {
    pub file_id: u32,
    pub class_def_idx: u32,
    pub class_idx: u32,
    pub descriptor: String,
    pub access_flags: u32,
    pub superclass_descriptor: Option<String>,
    pub interface_count: u32,
    pub source_file: Option<String>,
}

impl ClassRow {
    /// Assembled column names in contract order.
    pub const COLUMNS: &[&str] = &[
        "file_id",
        "class_def_idx",
        "class_idx",
        "descriptor",
        "access_flags",
        "superclass_descriptor",
        "interface_count",
        "source_file",
    ];
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
/// Direct encoded member definitions, not inherited members or all references.
pub struct ClassMemberFacts<'a> {
    pub source: &'a MetadataSource,
    pub class: &'a ClassDefinition,
    pub fields: &'a [FieldDefinition],
    pub methods: &'a [MethodDefinition],
}
impl<'a> ClassFactViews<'a> {
    /// Resolve class-owned definitions from the complete source, retaining
    /// encoded order and kind/ordinal. The limit bounds the total input member
    /// entries, not individual visits, CPU steps, allocation, or RSS.
    pub fn members(
        &self,
        entity: &EntityRef,
        max_member_entries: u64,
    ) -> MddResult<ClassMemberFacts<'a>> {
        let class = self.get(entity)?.definition;
        let fields = &self.facts.definitions.field_definitions;
        let methods = &self.facts.definitions.method_definitions;
        let count = u64::try_from(fields.len())
            .ok()
            .and_then(|n| {
                u64::try_from(methods.len())
                    .ok()
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.class_members",
                    "member count budget overflow",
                )
            })?;
        if count > max_member_entries {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.class_members",
                "member count budget exceeded",
            ));
        }
        let broken = || {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.class_members",
                "validated member ordering or ownership is inconsistent",
            )
        };
        if fields
            .windows(2)
            .any(|w| w[0].class_def_idx > w[1].class_def_idx)
            || methods
                .windows(2)
                .any(|w| w[0].class_def_idx > w[1].class_def_idx)
        {
            return Err(broken());
        }
        let f0 = fields.partition_point(|f| f.class_def_idx < class.class_def_idx);
        let f1 = fields.partition_point(|f| f.class_def_idx <= class.class_def_idx);
        let m0 = methods.partition_point(|m| m.class_def_idx < class.class_def_idx);
        let m1 = methods.partition_point(|m| m.class_def_idx <= class.class_def_idx);
        let (selected_fields, selected_methods) = (&fields[f0..f1], &methods[m0..m1]);
        if selected_fields
            .iter()
            .any(|f| f.class_idx != class.class_idx)
            || selected_methods
                .iter()
                .any(|m| m.class_idx != class.class_idx)
            || u64::try_from(selected_fields.len()).ok()
                != Some(
                    u64::from(class.static_fields_count) + u64::from(class.instance_fields_count),
                )
            || u64::try_from(selected_methods.len()).ok()
                != Some(
                    u64::from(class.direct_methods_count) + u64::from(class.virtual_methods_count),
                )
        {
            return Err(broken());
        }
        for (i, field) in selected_fields.iter().enumerate() {
            let pos = u64::try_from(i).map_err(|_| broken())?;
            let static_count = u64::from(class.static_fields_count);
            let (kind, ordinal) = if pos < static_count {
                (FieldKind::Static, pos)
            } else {
                (FieldKind::Instance, pos - static_count)
            };
            if field.kind != kind || u64::from(field.ordinal) != ordinal {
                return Err(broken());
            }
        }
        for (i, method) in selected_methods.iter().enumerate() {
            let pos = u64::try_from(i).map_err(|_| broken())?;
            let direct_count = u64::from(class.direct_methods_count);
            let (kind, ordinal) = if pos < direct_count {
                (MethodKind::Direct, pos)
            } else {
                (MethodKind::Virtual, pos - direct_count)
            };
            if method.kind != kind || u64::from(method.ordinal) != ordinal {
                return Err(broken());
            }
        }
        Ok(ClassMemberFacts {
            source: self.facts.metadata.source(),
            class,
            fields: selected_fields,
            methods: selected_methods,
        })
    }
    /// Resolve a class definition within this exact snapshot and DEX occurrence.
    /// The local index is a class_def index, not a type index.
    pub fn get(&self, entity: &EntityRef) -> MddResult<ClassFactView<'a>> {
        let source = self.facts.metadata.source();
        let invalid = || {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.classes",
                "invalid or foreign class definition identity",
            )
        };
        if entity.snapshot_id != source.snapshot_id
            || entity.dex_occurrence_id != source.dex_occurrence_id
            || entity.kind != EntityKind::ClassDefinition
        {
            return Err(invalid());
        }
        let class = self
            .facts
            .definitions
            .classes
            .get(entity.local_index as usize)
            .filter(|class| class.class_def_idx == entity.local_index)
            .ok_or_else(invalid)?;
        self.view(class)
    }
    /// Iterate DEX class_def order with directly declared interfaces in ordinal order.
    pub fn iter(&self) -> impl Iterator<Item = MddResult<ClassFactView<'a>>> + '_ {
        self.facts
            .definitions
            .classes
            .iter()
            .map(move |class| self.view(class))
    }
    fn view(&self, class: &'a ClassDefinition) -> MddResult<ClassFactView<'a>> {
        let facts = self.facts;
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

    /// Number of encoded method references this join covers, for callers that
    /// pre-size their own row vector.
    pub(crate) fn method_count(&self) -> usize {
        self.facts.definitions.method_references.len()
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
        Self::build_arc(Arc::new(metadata), limits)
    }

    /// Build from an already-shared metadata lease so a facade can hand the same
    /// metadata to several fact layers without deep-copying the string, type and
    /// prototype tables.
    pub fn build_arc(metadata: Arc<MetadataFacts>, limits: DefinitionLimits) -> MddResult<Self> {
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
        let definitions = read_definitions(
            metadata.bytes(),
            &metadata.header,
            metadata.as_ref(),
            limits,
        )
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
                "param_descriptors",
                "access_flags",
                "method_kind",
            ],
        };
        for column in columns {
            if relation == DefinitionRelation::Methods
                && ["opcode_count", "opcode_hex"].contains(column)
            {
                return Err(MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.definitions",
                    "methods opcode columns require the code_layout layer held by MethodCodeFactViews",
                )
                .detail("required_layer", "code_layout")
                .detail("column", (*column).to_owned())
                .detail("assembled_by", "MethodCodeFactViews::method_rows"));
            }
            if relation == DefinitionRelation::Methods && *column == "*" {
                return Err(MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.definitions",
                    "methods wildcard includes code_layout opcode columns; use MethodCodeFactViews::method_rows",
                )
                .detail("required_layer", "code_layout")
                .detail("unavailable_columns", "opcode_count,opcode_hex")
                .detail("assembled_by", "MethodCodeFactViews::method_rows"));
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

    /// The rows of `class_field_rows`, each handed to `each` as it is made and not kept.
    pub fn for_each_class_field(
        &self,
        each: &mut dyn FnMut(&ClassFieldRef<'_>) -> MddResult<()>,
    ) -> MddResult<()> {
        for d in &self.definitions.field_definitions {
            let r = &self.definitions.field_references[d.field_idx as usize];
            each(&ClassFieldRef {
                class_idx: d.class_idx,
                class_descriptor: &r.class_descriptor,
                field_idx: d.field_idx,
                field_name: &r.field_name,
                field_descriptor: &r.descriptor,
                kind: d.kind.as_str(),
                access_flags: d.access_flags,
            })?;
        }
        Ok(())
    }
    /// The rows of `class_method_rows`, each handed to `each` as it is made and not kept.
    pub fn for_each_class_method(
        &self,
        each: &mut dyn FnMut(&ClassMethodRef<'_>) -> MddResult<()>,
    ) -> MddResult<()> {
        for d in &self.definitions.method_definitions {
            let r = &self.definitions.method_references[d.method_idx as usize];
            each(&ClassMethodRef {
                class_idx: d.class_idx,
                class_descriptor: &r.class_descriptor,
                method_idx: d.method_idx,
                method_name: &r.method_name,
                method_descriptor: &r.descriptor,
                kind: d.kind.as_str(),
                access_flags: d.access_flags,
            })?;
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

    /// Project every encoded method_id in DEX order, joining the optional real
    /// definition. Reference-only rows keep their identity and carry NULL
    /// definition columns; they are never dropped or filled with a default.
    ///
    /// `param_descriptors` is the exact ordered native parameter descriptor
    /// vector joined by `,` ([`PARAM_DESCRIPTOR_ENCODING`]). The join is total
    /// here because every validated descriptor is scalar UTF-8: a non-scalar
    /// descriptor is rejected while reading types, so no row can carry a
    /// descriptor that needs a lossy rendering.
    pub fn method_rows(&self, file_id: u32) -> MddResult<Vec<MethodRow>> {
        self.require_relation_columns(DefinitionRelation::Methods, MethodRow::COLUMNS)?;
        let views = self.method_fact_views(MethodViewLimits::default())?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.definitions.method_references.len())
            .map_err(|_| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.methods",
                    "method row allocation failed",
                )
            })?;
        for view in views.iter() {
            let view = view?;
            let reference = view.reference;
            let param_count =
                u32::try_from(reference.parameter_descriptors.len()).map_err(|_| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "facts.methods",
                        "validated parameter count exceeds UInt32",
                    )
                    .detail("method_idx", u64::from(reference.method_idx))
                })?;
            rows.push(MethodRow {
                file_id,
                method_idx: reference.method_idx,
                class_idx: reference.class_idx,
                class_descriptor: reference.class_descriptor.clone(),
                proto_idx: reference.proto_idx,
                name: reference.method_name.clone(),
                descriptor: reference.descriptor.clone(),
                return_descriptor: reference.return_descriptor.clone(),
                param_count,
                param_descriptors: parameter_descriptors_text(&reference.parameter_descriptors)?,
                access_flags: view.definition.map(|definition| definition.access_flags),
                method_kind: view
                    .definition
                    .map(|definition| definition.kind.as_str().to_owned()),
            });
        }
        Ok(rows)
    }

    /// Project every encoded class_def in class_def order with its declared
    /// interface count. `source_file` uses the lossless strict UTF-8 rendering
    /// of the same-occurrence `DexText`; a legal non-scalar value is rejected
    /// rather than converted lossily.
    pub fn class_rows(&self, file_id: u32) -> MddResult<Vec<ClassRow>> {
        self.require_relation_columns(DefinitionRelation::Classes, ClassRow::COLUMNS)?;
        if self.definition_coverage != Completeness::Complete
            || self.metadata.metadata_coverage() != Completeness::Complete
        {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.classes",
                "complete metadata and definitions are required",
            ));
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.definitions.classes.len())
            .map_err(|_| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "facts.classes",
                    "class row allocation failed",
                )
            })?;
        // One pass over the interfaces instead of one pass for each class.
        let mut interface_counts: std::collections::HashMap<u32, usize> =
            std::collections::HashMap::new();
        for interface in &self.definitions.interfaces {
            *interface_counts.entry(interface.class_def_idx).or_default() += 1;
        }
        for class in &self.definitions.classes {
            let interface_count = u32::try_from(
                interface_counts
                    .get(&class.class_def_idx)
                    .copied()
                    .unwrap_or(0),
            )
            .map_err(|_| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "facts.classes",
                    "validated interface count exceeds UInt32",
                )
                .detail("class_def_idx", u64::from(class.class_def_idx))
            })?;
            let source_file = match &class.source_file {
                Some(text) => Some(text.strict_utf8().map_err(|_| {
                    MddError::new(
                        ErrorCode::UnsupportedQuery,
                        "facts.classes",
                        "plain UTF8 relation cannot losslessly represent a legal non-scalar source file name",
                    )
                    .detail("reason", "NON_SCALAR_TEXT_PROJECTION")
                    .detail("class_def_idx", u64::from(class.class_def_idx))
                    .detail(
                        "snapshot_id",
                        self.metadata.source.snapshot_id.clone(),
                    )
                    .detail(
                        "dex_occurrence_id",
                        self.metadata.source.dex_occurrence_id.clone(),
                    )
                })?),
                None => None,
            };
            rows.push(ClassRow {
                file_id,
                class_def_idx: class.class_def_idx,
                class_idx: class.class_idx,
                descriptor: class.descriptor.clone(),
                access_flags: class.access_flags,
                superclass_descriptor: class.superclass_descriptor.clone(),
                interface_count,
                source_file,
            });
        }
        Ok(rows)
    }
}

/// Render one exact ordered parameter descriptor vector as
/// [`PARAM_DESCRIPTOR_ENCODING`]. The result is one allocation grown only by the
/// already-validated descriptor bytes plus one separator each.
pub(crate) fn parameter_descriptors_text(descriptors: &[String]) -> MddResult<String> {
    let quota = || {
        MddError::new(
            ErrorCode::QuotaExceeded,
            "facts.methods",
            "parameter descriptor text allocation failed",
        )
    };
    let total = descriptors
        .iter()
        .try_fold(descriptors.len().saturating_sub(1), |total, descriptor| {
            total.checked_add(descriptor.len())
        })
        .ok_or_else(quota)?;
    let mut text = String::new();
    text.try_reserve_exact(total).map_err(|_| quota())?;
    for (ordinal, descriptor) in descriptors.iter().enumerate() {
        if ordinal != 0 {
            text.push(',');
        }
        text.push_str(descriptor);
    }
    Ok(text)
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
#[path = "definitions_tests.rs"]
mod tests;
