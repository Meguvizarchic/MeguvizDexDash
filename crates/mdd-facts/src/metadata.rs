use mdd_dex::{
    DexHeader,
    strings::{DexString, StringLimits, read_string_pool},
    types::{DexPrototype, DexType, parse_type_descriptor, read_types_and_prototypes},
    validate_header,
};
use mdd_input::{
    archive::{ArchiveInventory, MemberBlob},
    snapshot::Snapshot,
};
use mdd_types::{Completeness, DecimalU64, ErrorCode, MddError, MddResult, content_id};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    String,
    Type,
    Prototype,
    ClassDefinition,
    FieldReference,
    FieldDefinition,
    MethodReference,
    MethodDefinition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityRef {
    pub snapshot_id: String,
    pub dex_occurrence_id: String,
    pub kind: EntityKind,
    pub local_index: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetadataSource {
    pub snapshot_id: String,
    pub dex_occurrence_id: String,
    pub physical_dex_id: String,
    pub member_id: String,
    pub source_occurrence_id: String,
    pub content_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StringPoolIdentity {
    pub string_pool_id: String,
    pub physical_dex_id: String,
    pub content_id: String,
    pub string_ids_byte_offset: mdd_types::DecimalU64,
    pub string_count: u32,
    pub dex_occurrence_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StringFact {
    pub entity: EntityRef,
    pub string_pool_id: String,
    pub data: DexString,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TypeFact {
    pub entity: EntityRef,
    pub descriptor_string: EntityRef,
    pub data: DexType,
}

/// Logical UTF-8 byte limits for a single rendered type name, not RSS or a deadline.
#[derive(Clone, Copy, Debug)]
pub struct TypeNameLimits {
    pub max_descriptor_bytes: u64,
    pub max_output_bytes: u64,
}
impl Default for TypeNameLimits {
    fn default() -> Self {
        Self {
            max_descriptor_bytes: 1024 * 1024,
            max_output_bytes: 1024 * 1024,
        }
    }
}

/// A derived display name tied to the same validated type and source occurrence.
/// The original descriptor and string-pool fact remain available unchanged.
#[derive(Debug)]
pub struct JavaTypeName<'a> {
    pub source: &'a MetadataSource,
    pub entity: &'a EntityRef,
    pub value: String,
}

fn java_type_name_value(
    descriptor: &str,
    version: &str,
    limits: TypeNameLimits,
) -> MddResult<String> {
    let quota = || {
        MddError::new(
            ErrorCode::QuotaExceeded,
            "facts.type_name",
            "type name byte budget exceeded",
        )
    };
    let descriptor_bytes = u64::try_from(descriptor.len()).map_err(|_| quota())?;
    if descriptor_bytes > limits.max_descriptor_bytes {
        return Err(quota());
    }
    // Reuse the actual DEX grammar, including version-specific name rules and
    // the 255-dimension limit; never replace invalid text or guess a name.
    let shape = parse_type_descriptor(descriptor, version, true)?;
    let rest = &descriptor[usize::from(shape.array_dimensions)..];
    let primitive = match rest {
        "Z" => Some("boolean"),
        "B" => Some("byte"),
        "S" => Some("short"),
        "C" => Some("char"),
        "I" => Some("int"),
        "J" => Some("long"),
        "F" => Some("float"),
        "D" => Some("double"),
        "V" => Some("void"),
        _ => None,
    };
    let base = if let Some(name) = primitive {
        name
    } else {
        rest.strip_prefix('L')
            .and_then(|value| value.strip_suffix(';'))
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "facts.type_name",
                    "validated type shape is inconsistent",
                )
            })?
    };
    let output_len = u64::try_from(base.len())
        .ok()
        .and_then(|bytes| bytes.checked_add(u64::from(shape.array_dimensions).checked_mul(2)?))
        .ok_or_else(quota)?;
    if output_len > limits.max_output_bytes {
        return Err(quota());
    }
    let mut value = String::new();
    value
        .try_reserve_exact(usize::try_from(output_len).map_err(|_| quota())?)
        .map_err(|_| quota())?;
    if primitive.is_some() {
        value.push_str(base);
    } else {
        for ch in base.chars() {
            value.push(if ch == '/' { '.' } else { ch });
        }
    }
    for _ in 0..shape.array_dimensions {
        value.push_str("[]");
    }
    Ok(value)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrototypeFact {
    pub entity: EntityRef,
    pub shorty_string: EntityRef,
    pub return_type: EntityRef,
    pub parameter_types: Vec<EntityRef>,
    pub data: DexPrototype,
}

#[derive(Clone, Serialize)]
/// Validated metadata is read-only outside the facts crate.
/// ```compile_fail
/// fn alter(mut facts: mdd_facts::MetadataFacts) { facts.strings.clear(); }
/// ```
pub struct MetadataFacts {
    pub(crate) source: MetadataSource,
    pub(crate) header: DexHeader,
    pub(crate) string_pool: StringPoolIdentity,
    pub(crate) strings: Vec<StringFact>,
    pub(crate) types: Vec<TypeFact>,
    pub(crate) prototypes: Vec<PrototypeFact>,
    pub(crate) metadata_coverage: Completeness,
    pub(crate) completed_layers: Vec<String>,
    pub(crate) unbuilt_layers: Vec<String>,
    #[serde(skip)]
    blob: MemberBlob,
}

impl MetadataFacts {
    /// Render one validated type descriptor without losing source identity.
    /// This is a generic display value, not a legacy SQL relation admission.
    pub fn java_type_name(
        &self,
        type_ref: &EntityRef,
        limits: TypeNameLimits,
    ) -> MddResult<JavaTypeName<'_>> {
        if self.metadata_coverage != Completeness::Complete {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.type_name",
                "complete type metadata is required",
            ));
        }
        if type_ref.snapshot_id != self.source.snapshot_id
            || type_ref.dex_occurrence_id != self.source.dex_occurrence_id
            || type_ref.kind != EntityKind::Type
        {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.type_name",
                "type is foreign or has the wrong identity kind",
            ));
        }
        let fact = self
            .types
            .get(type_ref.local_index as usize)
            .filter(|fact| fact.entity == *type_ref && fact.data.type_idx == type_ref.local_index)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.type_name",
                    "type is outside this occurrence",
                )
            })?;
        Ok(JavaTypeName {
            source: &self.source,
            entity: &fact.entity,
            value: java_type_name_value(&fact.data.descriptor, &self.header.version, limits)?,
        })
    }
    pub fn source(&self) -> &MetadataSource {
        &self.source
    }
    pub fn header(&self) -> &DexHeader {
        &self.header
    }
    pub fn string_pool(&self) -> &StringPoolIdentity {
        &self.string_pool
    }
    pub fn strings(&self) -> &[StringFact] {
        &self.strings
    }
    pub fn types(&self) -> &[TypeFact] {
        &self.types
    }
    pub fn prototypes(&self) -> &[PrototypeFact] {
        &self.prototypes
    }
    pub fn metadata_coverage(&self) -> Completeness {
        self.metadata_coverage
    }
    pub fn completed_layers(&self) -> &[String] {
        &self.completed_layers
    }
    pub fn unbuilt_layers(&self) -> &[String] {
        &self.unbuilt_layers
    }
    pub fn build(
        snapshot: &Snapshot,
        inventory: &ArchiveInventory,
        dex_index: usize,
        limits: StringLimits,
    ) -> MddResult<Self> {
        let source_manifest = snapshot
            .manifest()
            .sources
            .iter()
            .find(|source| {
                source.occurrence_id == inventory.manifest().source_occurrence_id
                    && source.content_id == inventory.manifest().source_content_id
            })
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::InvalidArgument,
                    "facts.metadata",
                    "inventory does not belong to snapshot",
                )
            })?;
        let candidate = inventory.selected_dexes().get(dex_index).ok_or_else(|| {
            MddError::new(
                ErrorCode::InvalidArgument,
                "facts.metadata",
                "DEX occurrence index is outside inventory",
            )
        })?;
        let source = MetadataSource {
            snapshot_id: snapshot.manifest().snapshot_id.clone(),
            dex_occurrence_id: candidate.dex_occurrence_id.clone(),
            physical_dex_id: candidate.physical_dex_id.clone(),
            member_id: candidate.blob.identity.member_id.clone(),
            source_occurrence_id: source_manifest.occurrence_id.clone(),
            content_id: candidate.blob.content_id.clone(),
        };
        let bind = |error: MddError| {
            error
                .detail("snapshot_id", source.snapshot_id.clone())
                .detail("dex_occurrence_id", source.dex_occurrence_id.clone())
                .detail("member_id", source.member_id.clone())
                .detail("content_id", source.content_id.clone())
        };
        if candidate.logical_header_byte_offset.0 != 0
            || candidate.blob.identity.source_occurrence_id != source_manifest.occurrence_id
        {
            return Err(bind(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.metadata",
                "unsupported logical offset or mismatched occurrence",
            )));
        }
        if content_id(candidate.blob.bytes()) != source.content_id {
            return Err(bind(MddError::new(
                ErrorCode::InternalFault,
                "facts.metadata",
                "held blob differs from captured content identity",
            )));
        }
        let header = validate_header(candidate.blob.bytes()).map_err(bind)?;
        let pool = read_string_pool(candidate.blob.bytes(), &header, limits).map_err(bind)?;
        let (types, prototypes) =
            read_types_and_prototypes(candidate.blob.bytes(), &header, &pool).map_err(bind)?;
        let string_table = header
            .tables
            .iter()
            .find(|table| table.name == "string_ids")
            .ok_or_else(|| {
                bind(MddError::new(
                    ErrorCode::InternalFault,
                    "facts.metadata",
                    "validated header lacks string table",
                ))
            })?;
        let string_pool = StringPoolIdentity {
            string_pool_id: format!(
                "{}:string-pool:{}:{}",
                source.physical_dex_id, string_table.range.byte_offset.0, string_table.count
            ),
            physical_dex_id: source.physical_dex_id.clone(),
            content_id: source.content_id.clone(),
            string_ids_byte_offset: string_table.range.byte_offset,
            string_count: string_table.count,
            dex_occurrence_id: source.dex_occurrence_id.clone(),
        };
        let entity = |kind, local_index| EntityRef {
            snapshot_id: source.snapshot_id.clone(),
            dex_occurrence_id: source.dex_occurrence_id.clone(),
            kind,
            local_index,
        };
        let strings = pool
            .into_iter()
            .map(|data| StringFact {
                entity: entity(EntityKind::String, data.string_idx),
                string_pool_id: string_pool.string_pool_id.clone(),
                data,
            })
            .collect();
        let types = types
            .into_iter()
            .map(|data| TypeFact {
                entity: entity(EntityKind::Type, data.type_idx),
                descriptor_string: entity(EntityKind::String, data.descriptor_string_idx),
                data,
            })
            .collect();
        let prototypes = prototypes
            .into_iter()
            .map(|data| PrototypeFact {
                entity: entity(EntityKind::Prototype, data.proto_idx),
                shorty_string: entity(EntityKind::String, data.shorty_string_idx),
                return_type: entity(EntityKind::Type, data.return_type_idx),
                parameter_types: data
                    .parameter_type_indices
                    .iter()
                    .map(|index| entity(EntityKind::Type, *index))
                    .collect(),
                data,
            })
            .collect();
        Ok(Self {
            source,
            header,
            string_pool,
            strings,
            types,
            prototypes,
            metadata_coverage: Completeness::Complete,
            completed_layers: ["strings", "types", "prototypes"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            unbuilt_layers: [
                "definitions",
                "annotations",
                "code_layout",
                "references",
                "resources",
                "derived_analysis",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            blob: candidate.blob.clone(),
        })
    }

    pub fn bytes(&self) -> &[u8] {
        self.blob.bytes()
    }
    pub fn lease(&self) -> Arc<[u8]> {
        self.blob.lease()
    }

    pub fn entity(&self, kind: EntityKind, local_index: u32) -> MddResult<EntityRef> {
        let count = match kind {
            EntityKind::String => self.strings.len(),
            EntityKind::Type => self.types.len(),
            EntityKind::Prototype => self.prototypes.len(),
            EntityKind::ClassDefinition
            | EntityKind::FieldReference
            | EntityKind::FieldDefinition
            | EntityKind::MethodReference
            | EntityKind::MethodDefinition => {
                return Err(MddError::new(
                    ErrorCode::IncompleteFacts,
                    "facts.metadata",
                    "requested entity kind belongs to an unbuilt definition layer",
                )
                .detail("snapshot_id", self.source.snapshot_id.clone())
                .detail("dex_occurrence_id", self.source.dex_occurrence_id.clone()));
            }
        };
        if local_index as usize >= count {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "facts.metadata",
                "local entity index is outside completed scope",
            )
            .detail("snapshot_id", self.source.snapshot_id.clone())
            .detail("dex_occurrence_id", self.source.dex_occurrence_id.clone()));
        }
        Ok(EntityRef {
            snapshot_id: self.source.snapshot_id.clone(),
            dex_occurrence_id: self.source.dex_occurrence_id.clone(),
            kind,
            local_index,
        })
    }
}

/// Compatibility relation names whose columns the metadata layer can project.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataRelation {
    DexFiles,
    Strings,
    Types,
}

/// One `dex_files` row bound to this validated DEX occurrence.
///
/// `file_id` and `string_pool_id` are caller-supplied catalog coordinates, the
/// same convention as every other fact row API in this crate: the fact layer
/// holds an opaque string-pool identity (`StringPoolIdentity::string_pool_id`
/// is a `String`), not a UInt32 catalog number.
///
/// `source_path` and `entry_name` are provenance values owned by the snapshot
/// and archive inventory layers, so this metadata-only row deliberately omits
/// them; the complete 28-column row is
/// [`ScopeDexFileRow`] via `SelectedScope::dex_file_rows`.
///
/// `endian_tag`, `link_size`, `link_off` and `map_off` are the validated raw
/// little-endian header words at byte offsets 40/44/48/52 of the same DEX
/// occurrence, so an absent link section projects as the encoded zero word
/// rather than being inferred from `DexHeader::link_range`.
#[derive(Clone, Debug, Serialize)]
pub struct DexFileRow {
    pub file_id: u32,
    pub string_pool_id: u32,
    pub byte_len: u64,
    pub dex_version: String,
    pub checksum: u32,
    pub signature_hex: String,
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_count: u32,
    pub string_ids_off: u32,
    pub type_count: u32,
    pub type_ids_off: u32,
    pub proto_count: u32,
    pub proto_ids_off: u32,
    pub field_count: u32,
    pub field_ids_off: u32,
    pub method_count: u32,
    pub method_ids_off: u32,
    pub class_count: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

impl DexFileRow {
    /// Assembled column names in contract order.
    pub const COLUMNS: &[&str] = &[
        "file_id",
        "string_pool_id",
        "byte_len",
        "dex_version",
        "checksum",
        "signature_hex",
        "file_size",
        "header_size",
        "endian_tag",
        "link_size",
        "link_off",
        "map_off",
        "string_count",
        "string_ids_off",
        "type_count",
        "type_ids_off",
        "proto_count",
        "proto_ids_off",
        "field_count",
        "field_ids_off",
        "method_count",
        "method_ids_off",
        "class_count",
        "class_defs_off",
        "data_size",
        "data_off",
    ];
}

/// One `strings` row. `value` is the lossless strict UTF-8 rendering of the
/// same-occurrence `DexText`; a legal non-scalar DEX string is rejected instead
/// of being replaced by a lossy placeholder.
#[derive(Clone, Debug, Serialize)]
pub struct StringRow {
    pub file_id: u32,
    pub string_pool_id: u32,
    pub string_idx: u32,
    pub value: String,
}

impl StringRow {
    /// Assembled column names in contract order.
    pub const COLUMNS: &[&str] = &["string_pool_id", "string_idx", "value"];
}

/// One `types` row; `java_name` is the exact descriptor-derived display name
/// from [`MetadataFacts::java_type_name`], not a compatibility formatter.
#[derive(Clone, Debug, Serialize)]
pub struct TypeRow {
    pub file_id: u32,
    pub type_idx: u32,
    pub descriptor: String,
    pub java_name: String,
}

impl TypeRow {
    /// Assembled column names in contract order.
    pub const COLUMNS: &[&str] = &["file_id", "type_idx", "descriptor", "java_name"];
}

fn header_word(bytes: &[u8], offset: u32, column: &str) -> MddResult<u32> {
    let start = usize::try_from(offset).map_err(|_| {
        MddError::new(
            ErrorCode::InternalFault,
            "facts.metadata.dex_files",
            "header word offset overflow",
        )
        .detail("column", column)
    })?;
    let end = start.checked_add(4).ok_or_else(|| {
        MddError::new(
            ErrorCode::InternalFault,
            "facts.metadata.dex_files",
            "header word range overflow",
        )
        .detail("column", column)
    })?;
    let raw = bytes.get(start..end).ok_or_else(|| {
        MddError::new(
            ErrorCode::InternalFault,
            "facts.metadata.dex_files",
            "validated DEX header is shorter than the standard 112 bytes",
        )
        .detail("column", column)
        .detail("byte_offset", offset.to_string())
        .detail("byte_length", "4")
    })?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn table_word(header: &DexHeader, name: &str) -> MddResult<(u32, u32)> {
    let column = name;
    let table = header
        .tables
        .iter()
        .find(|table| table.name == name)
        .ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.metadata.dex_files",
                "validated header is missing a standard table",
            )
            .detail("table", name)
        })?;
    let offset = u32::try_from(table.range.byte_offset.0).map_err(|_| {
        MddError::new(
            ErrorCode::InternalFault,
            "facts.metadata.dex_files",
            "validated table offset exceeds UInt32",
        )
        .detail("table", column)
    })?;
    Ok((table.count, offset))
}

fn u32_decimal(value: DecimalU64, column: &str) -> MddResult<u32> {
    u32::try_from(value.0).map_err(|_| {
        MddError::new(
            ErrorCode::InternalFault,
            "facts.metadata.dex_files",
            "validated header value exceeds UInt32",
        )
        .detail("column", column)
    })
}

impl MetadataFacts {
    /// Gate a requested metadata relation column list before projection.
    ///
    /// `*` selects the assembled column set of the relation. `dex_files` has no
    /// `*` form here because `source_path` and `entry_name` are snapshot/archive
    /// provenance owned by the selected scope, not by this fact object. The error
    /// names them and the provider that does assemble them instead of silently
    /// narrowing the request.
    pub fn require_relation_columns(
        &self,
        relation: MetadataRelation,
        columns: &[&str],
    ) -> MddResult<()> {
        let available: &[&str] = match relation {
            MetadataRelation::DexFiles => DexFileRow::COLUMNS,
            MetadataRelation::Strings => StringRow::COLUMNS,
            MetadataRelation::Types => TypeRow::COLUMNS,
        };
        for column in columns {
            if *column == "*" {
                if relation == MetadataRelation::DexFiles {
                    return Err(MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.metadata.dex_files",
                        "dex_files provenance columns are owned by the selected scope",
                    )
                    .detail("unassembled_columns", "source_path,entry_name")
                    .detail("required_layer", "input_inventory")
                    .detail("assembled_by", "SelectedScope::dex_file_rows"));
                }
                continue;
            }
            if !available.contains(column) {
                let error = match (relation, *column) {
                    (MetadataRelation::DexFiles, "source_path" | "entry_name") => MddError::new(
                        ErrorCode::IncompleteFacts,
                        "facts.metadata.dex_files",
                        "source provenance is owned by the snapshot/archive inventory, not by metadata facts",
                    )
                    .detail("column", (*column).to_owned())
                    .detail("required_layer", "input_inventory")
                    .detail("assembled_by", "SelectedScope::dex_file_rows"),
                    _ => MddError::new(
                        ErrorCode::InvalidArgument,
                        "facts.metadata.projection",
                        "unknown metadata relation column",
                    )
                    .detail("column", (*column).to_owned()),
                };
                return Err(error);
            }
        }
        Ok(())
    }

    fn require_complete_metadata(&self) -> MddResult<()> {
        if self.metadata_coverage != Completeness::Complete {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.metadata.projection",
                "complete metadata is required",
            ));
        }
        Ok(())
    }

    /// Project the header/table atoms of this one validated DEX occurrence.
    pub fn dex_file_rows(&self, file_id: u32, string_pool_id: u32) -> MddResult<Vec<DexFileRow>> {
        self.require_relation_columns(MetadataRelation::DexFiles, DexFileRow::COLUMNS)?;
        self.require_complete_metadata()?;
        let header = self.header();
        let bytes = self.bytes();
        let (string_count, string_ids_off) = table_word(header, "string_ids")?;
        let (type_count, type_ids_off) = table_word(header, "type_ids")?;
        let (proto_count, proto_ids_off) = table_word(header, "proto_ids")?;
        let (field_count, field_ids_off) = table_word(header, "field_ids")?;
        let (method_count, method_ids_off) = table_word(header, "method_ids")?;
        let (class_count, class_defs_off) = table_word(header, "class_defs")?;
        let byte_len = u64::try_from(bytes.len()).map_err(|_| {
            MddError::new(
                ErrorCode::InternalFault,
                "facts.metadata.dex_files",
                "DEX byte length exceeds UInt64",
            )
        })?;
        Ok(vec![DexFileRow {
            file_id,
            string_pool_id,
            byte_len,
            dex_version: header.version.clone(),
            checksum: header.declared_checksum,
            signature_hex: header.declared_signature_sha1.clone(),
            file_size: u32_decimal(header.file_size, "file_size")?,
            header_size: u32_decimal(header.header_range.byte_length, "header_size")?,
            endian_tag: header_word(bytes, 40, "endian_tag")?,
            link_size: header_word(bytes, 44, "link_size")?,
            link_off: header_word(bytes, 48, "link_off")?,
            map_off: header_word(bytes, 52, "map_off")?,
            string_count,
            string_ids_off,
            type_count,
            type_ids_off,
            proto_count,
            proto_ids_off,
            field_count,
            field_ids_off,
            method_count,
            method_ids_off,
            class_count,
            class_defs_off,
            data_size: u32_decimal(header.data_range.byte_length, "data_size")?,
            data_off: u32_decimal(header.data_range.byte_offset, "data_off")?,
        }])
    }

    /// Project every validated string in DEX order, including repeated values.
    /// `string_pool_id` is a caller-supplied catalog coordinate; the native
    /// pool identity stays available as `StringPoolIdentity::string_pool_id`.
    pub fn string_rows(&self, file_id: u32, string_pool_id: u32) -> MddResult<Vec<StringRow>> {
        self.require_relation_columns(MetadataRelation::Strings, StringRow::COLUMNS)?;
        self.require_complete_metadata()?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.strings.len()).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.metadata.strings",
                "string row allocation failed",
            )
        })?;
        for (ordinal, fact) in self.strings.iter().enumerate() {
            let inconsistent = || {
                MddError::new(
                    ErrorCode::InternalFault,
                    "facts.metadata.strings",
                    "validated string identity is inconsistent",
                )
            };
            if u32::try_from(ordinal).ok() != Some(fact.data.string_idx)
                || fact.data.string_idx != fact.entity.local_index
                || fact.entity.kind != EntityKind::String
                || fact.string_pool_id != self.string_pool.string_pool_id
            {
                return Err(inconsistent());
            }
            let value = fact.data.text.strict_utf8().map_err(|_| {
                MddError::new(
                    ErrorCode::UnsupportedQuery,
                    "facts.metadata.strings",
                    "plain UTF8 relation cannot losslessly represent a legal non-scalar DEX string",
                )
                .detail("reason", "NON_SCALAR_TEXT_PROJECTION")
                .detail("string_idx", u64::from(fact.data.string_idx))
                .detail("snapshot_id", self.source.snapshot_id.clone())
                .detail("dex_occurrence_id", self.source.dex_occurrence_id.clone())
                .detail("string_pool_id", self.string_pool.string_pool_id.clone())
                .detail(
                    "byte_offset",
                    fact.data.text.raw_range.byte_offset.0.to_string(),
                )
            })?;
            rows.push(StringRow {
                file_id,
                string_pool_id,
                string_idx: fact.data.string_idx,
                value,
            });
        }
        Ok(rows)
    }

    /// Project every validated type descriptor and its exact display name.
    pub fn type_rows(&self, file_id: u32) -> MddResult<Vec<TypeRow>> {
        self.require_relation_columns(MetadataRelation::Types, TypeRow::COLUMNS)?;
        self.require_complete_metadata()?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.types.len()).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "facts.metadata.types",
                "type row allocation failed",
            )
        })?;
        for fact in &self.types {
            if fact.data.type_idx != fact.entity.local_index || fact.entity.kind != EntityKind::Type
            {
                return Err(MddError::new(
                    ErrorCode::InternalFault,
                    "facts.metadata.types",
                    "validated type identity is inconsistent",
                ));
            }
            let java_name = self.java_type_name(&fact.entity, TypeNameLimits::default())?;
            rows.push(TypeRow {
                file_id,
                type_idx: fact.data.type_idx,
                descriptor: fact.data.descriptor.clone(),
                java_name: java_name.value,
            });
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdd_input::{
        archive::{ArchiveLimits, InventoryPolicy},
        snapshot::{CaptureLimits, InputKind, InputSpec},
    };
    use serde_json::Value;
    use std::path::PathBuf;

    #[test]
    fn java_type_names_are_bounded_and_bound_to_occurrences() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/references/generated/type-names-035.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let inventories: Vec<_> = snapshot
            .sources()
            .iter()
            .map(|source| {
                ArchiveInventory::build(
                    source,
                    InventoryPolicy::default(),
                    ArchiveLimits::default(),
                )
                .unwrap()
            })
            .collect();
        let left =
            MetadataFacts::build(&snapshot, &inventories[0], 0, StringLimits::default()).unwrap();
        let right =
            MetadataFacts::build(&snapshot, &inventories[1], 0, StringLimits::default()).unwrap();
        // These seven values are also observed in the fixed A0 fixture record.
        for (descriptor, expected) in [
            ("I", "int"),
            ("Lfixture/A;", "fixture.A"),
            ("Lfixture/External;", "fixture.External"),
            ("Ljava/lang/Object;", "java.lang.Object"),
            ("Ljava/lang/String;", "java.lang.String"),
            ("V", "void"),
            ("[I", "int[]"),
        ] {
            let fact = left
                .types()
                .iter()
                .find(|fact| fact.data.descriptor == descriptor)
                .unwrap();
            let rendered = left
                .java_type_name(&fact.entity, TypeNameLimits::default())
                .unwrap();
            assert_eq!(rendered.value, expected);
            assert_eq!(rendered.entity, &fact.entity);
            assert_eq!(
                rendered.source.dex_occurrence_id,
                left.source().dex_occurrence_id
            );
            assert_eq!(fact.data.descriptor, descriptor);
            let other = &right.types()[fact.entity.local_index as usize];
            assert_eq!(
                left.java_type_name(&other.entity, TypeNameLimits::default())
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidArgument
            );
        }
        for (descriptor, expected) in [
            ("Z", "boolean"),
            ("B", "byte"),
            ("S", "short"),
            ("C", "char"),
            ("J", "long"),
            ("F", "float"),
            ("D", "double"),
            ("[[Lpkg/Outer$Inner;", "pkg.Outer$Inner[][]"),
            ("Lpkg/雪;", "pkg.雪"),
        ] {
            assert_eq!(
                java_type_name_value(descriptor, "035", TypeNameLimits::default()).unwrap(),
                expected
            );
        }
        let output = java_type_name_value(
            "[[I",
            "035",
            TypeNameLimits {
                max_descriptor_bytes: 3,
                max_output_bytes: 7,
            },
        )
        .unwrap();
        assert_eq!(output, "int[][]");
        assert_eq!(
            java_type_name_value(
                "[[I",
                "035",
                TypeNameLimits {
                    max_descriptor_bytes: 3,
                    max_output_bytes: 6
                }
            )
            .unwrap_err()
            .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            java_type_name_value(
                "[[I",
                "035",
                TypeNameLimits {
                    max_descriptor_bytes: 2,
                    max_output_bytes: 100
                }
            )
            .unwrap_err()
            .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            java_type_name_value("[V", "035", TypeNameLimits::default())
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput
        );
        assert_eq!(
            java_type_name_value(
                &format!("{}I", "[".repeat(256)),
                "035",
                TypeNameLimits::default()
            )
            .unwrap_err()
            .code,
            ErrorCode::InvalidInput
        );
        let mut incomplete = left.clone();
        incomplete.metadata_coverage = Completeness::Partial;
        assert_eq!(
            incomplete
                .java_type_name(&left.types()[0].entity, TypeNameLimits::default())
                .unwrap_err()
                .code,
            ErrorCode::IncompleteFacts
        );
        assert_eq!(
            left.java_type_name(&left.strings()[0].entity, TypeNameLimits::default())
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn duplicate_content_occurrences_keep_distinct_refs_and_owned_leases() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/generated/structured-035.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let first = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let second = ArchiveInventory::build(
            &snapshot.sources()[1],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let left = MetadataFacts::build(&snapshot, &first, 0, StringLimits::default()).unwrap();
        let right = MetadataFacts::build(&snapshot, &second, 0, StringLimits::default()).unwrap();
        assert_eq!(left.source.content_id, right.source.content_id);
        assert_eq!(
            left.string_pool.string_pool_id,
            right.string_pool.string_pool_id
        );
        assert_ne!(left.strings[0].entity, right.strings[0].entity);
        assert_ne!(left.types[0].entity, right.types[0].entity);
        assert_eq!(left.types[0].descriptor_string, left.strings[0].entity);
        assert_eq!(left.prototypes[0].return_type, left.types[2].entity);
        assert_eq!(
            left.string_pool.string_pool_id,
            format!("{}:string-pool:112:7", left.source.physical_dex_id)
        );
        let lease = left.lease();
        drop(first);
        drop(second);
        drop(snapshot);
        assert_eq!(left.bytes(), right.bytes());
        assert_eq!(lease.as_ref(), left.bytes());
        assert_eq!(
            left.unbuilt_layers,
            [
                "definitions",
                "annotations",
                "code_layout",
                "references",
                "resources",
                "derived_analysis"
            ]
        );
        assert!(left.entity(EntityKind::String, 7).is_err());
    }

    #[test]
    fn unrelated_snapshot_inventory_and_zero_quota_fail_closed() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/generated/structured-035.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let a = Snapshot::capture(std::slice::from_ref(&input), CaptureLimits::default()).unwrap();
        let b = Snapshot::capture(&[input], CaptureLimits::default()).unwrap();
        let inventory = ArchiveInventory::build(
            &a.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        assert_eq!(
            MetadataFacts::build(&b, &inventory, 0, StringLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let error = MetadataFacts::build(
            &a,
            &inventory,
            0,
            StringLimits {
                max_strings: 0,
                ..StringLimits::default()
            },
        )
        .err()
        .unwrap();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
        assert_eq!(error.details["snapshot_id"], a.manifest().snapshot_id);
        assert!(error.details.contains_key("content_id"));
    }

    #[test]
    fn same_archive_duplicate_dexes_retain_independent_local_indices() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/generated/duplicate-content.apk");
        let snapshot = Snapshot::capture(
            &[InputSpec {
                path,
                kind: InputKind::Apk,
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
        assert_eq!(inventory.selected_dexes().len(), 2);
        let a = MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let b = MetadataFacts::build(&snapshot, &inventory, 1, StringLimits::default()).unwrap();
        assert_eq!(a.source.source_occurrence_id, b.source.source_occurrence_id);
        assert_ne!(a.source.member_id, b.source.member_id);
        assert_eq!(a.string_pool.string_pool_id, b.string_pool.string_pool_id);
        assert_ne!(a.strings[0].entity, b.strings[0].entity);
        assert_eq!(
            a.strings[0].entity.local_index,
            b.strings[0].entity.local_index
        );
        assert_eq!(
            a.types[0].descriptor_string.dex_occurrence_id,
            a.source.dex_occurrence_id
        );
        assert_eq!(
            b.types[0].descriptor_string.dex_occurrence_id,
            b.source.dex_occurrence_id
        );
    }

    fn build_one(name: &str) -> MetadataFacts {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/references/generated")
            .join(name);
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let inventory = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap()
    }

    fn adler32(bytes: &[u8]) -> u32 {
        let (mut a, mut b) = (1u32, 0u32);
        for chunk in bytes.chunks(5552) {
            for value in chunk {
                a += u32::from(*value);
                b += a;
            }
            a %= 65521;
            b %= 65521;
        }
        (b << 16) | a
    }

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        out
    }

    #[test]
    fn dex_file_rows_project_validated_raw_header_words() {
        let name = "classic-035.dex";
        let facts = build_one(name);
        let raw = std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/references/generated")
                .join(name),
        )
        .unwrap();
        let word = |offset: usize| u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap());
        assert_eq!(raw.len(), facts.bytes().len());
        let rows = facts.dex_file_rows(7, 9).unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.file_id, 7);
        assert_eq!(row.string_pool_id, 9);
        assert_eq!(row.byte_len, raw.len() as u64);
        assert_eq!(
            row.dex_version,
            String::from_utf8(raw[4..7].to_vec()).unwrap()
        );
        assert_eq!(row.checksum, adler32(&raw[12..]));
        assert_eq!(row.signature_hex, hex_lower(&raw[12..32]));
        assert_eq!(row.file_size, word(32));
        assert_eq!(row.header_size, word(36));
        assert_eq!(row.endian_tag, word(40));
        assert_eq!(row.link_size, word(44));
        assert_eq!(row.link_off, word(48));
        assert_eq!(row.map_off, word(52));
        assert_eq!(row.string_count, word(56));
        assert_eq!(row.string_ids_off, word(60));
        assert_eq!(row.type_count, word(64));
        assert_eq!(row.type_ids_off, word(68));
        assert_eq!(row.proto_count, word(72));
        assert_eq!(row.proto_ids_off, word(76));
        assert_eq!(row.field_count, word(80));
        assert_eq!(row.field_ids_off, word(84));
        assert_eq!(row.method_count, word(88));
        assert_eq!(row.method_ids_off, word(92));
        assert_eq!(row.class_count, word(96));
        assert_eq!(row.class_defs_off, word(100));
        assert_eq!(row.data_size, word(104));
        assert_eq!(row.data_off, word(108));
        // The raw link words are retained even when no link section exists, so
        // an absent section must project as its encoded zero rather than NULL.
        assert_eq!((row.link_size, row.link_off), (word(44), word(48)));
        assert_eq!(row.endian_tag, 0x1234_5678);
        // The table atoms must agree with the header facts that were built from
        // the same occurrence, not with a second parse.
        assert_eq!(row.string_count, facts.string_pool().string_count);
        assert_eq!(
            row.string_ids_off,
            facts.string_pool().string_ids_byte_offset.0 as u32
        );
        assert_eq!(
            row.header_size,
            facts.header().header_range.byte_length.0 as u32
        );
        assert_eq!(row.data_off, facts.header().data_range.byte_offset.0 as u32);
        assert_eq!(
            row.data_size,
            facts.header().data_range.byte_length.0 as u32
        );
    }

    #[test]
    fn dex_file_relation_rejects_provenance_columns_and_star() {
        let facts = build_one("classic-035.dex");
        for column in ["source_path", "entry_name"] {
            let error = facts
                .require_relation_columns(MetadataRelation::DexFiles, &[column])
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::IncompleteFacts, "{column}");
            assert_eq!(
                error
                    .details
                    .get("required_layer")
                    .and_then(|value| value.as_str()),
                Some("input_inventory"),
                "{column}"
            );
        }
        let error = facts
            .require_relation_columns(MetadataRelation::DexFiles, &["*"])
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::IncompleteFacts);
        assert!(
            facts
                .require_relation_columns(MetadataRelation::DexFiles, DexFileRow::COLUMNS)
                .is_ok()
        );
    }

    #[test]
    fn string_rows_preserve_dex_order_and_lossless_text() {
        let facts = build_one("classic-035.dex");
        let rows = facts.string_rows(3, 4).unwrap();
        assert_eq!(rows.len(), facts.strings().len());
        for (ordinal, row) in rows.iter().enumerate() {
            assert_eq!(row.file_id, 3);
            assert_eq!(row.string_pool_id, 4);
            assert_eq!(row.string_idx, u32::try_from(ordinal).unwrap());
            let fact = &facts.strings()[ordinal];
            assert_eq!(row.string_idx, fact.data.string_idx);
            assert_eq!(
                row.value,
                fact.data.text.strict_utf8().unwrap(),
                "row {ordinal} must be the exact validated text"
            );
        }
        assert!(rows.iter().any(|row| row.value == "Lfixture/A;"));
        assert!(
            facts
                .require_relation_columns(MetadataRelation::Strings, &["*"])
                .is_ok()
        );
    }

    #[test]
    fn type_rows_use_exact_descriptor_display_names() {
        let facts = build_one("type-names-035.dex");
        let rows = facts.type_rows(5).unwrap();
        assert_eq!(rows.len(), facts.types().len());
        for (ordinal, row) in rows.iter().enumerate() {
            assert_eq!(row.file_id, 5);
            assert_eq!(row.type_idx, u32::try_from(ordinal).unwrap());
            let fact = &facts.types()[ordinal];
            assert_eq!(row.type_idx, fact.data.type_idx);
            assert_eq!(row.descriptor, fact.data.descriptor);
            let expected = facts
                .java_type_name(&fact.entity, TypeNameLimits::default())
                .unwrap();
            assert_eq!(row.java_name, expected.value);
        }
        let named = rows
            .iter()
            .find(|row| row.descriptor == "Lfixture/A;")
            .unwrap();
        assert_eq!(named.java_name, "fixture.A");
    }

    fn contract() -> Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/manifests/relations.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn contract_entry(contract: &Value, relation: &str) -> Value {
        contract["relations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == relation)
            .unwrap_or_else(|| panic!("contract relation {relation} missing"))
            .clone()
    }

    /// Assert that one assembled relation projects exactly its declared column
    /// set with the contract's data type and nullability, and that the only
    /// unprojected columns are the documented fact-layer gaps.
    fn assert_contract_projection(
        relation: &str,
        columns: &[&str],
        unassembled: &[&str],
        rows: &[Value],
    ) {
        let entry = contract_entry(&contract(), relation);
        let specs = entry["columns"].as_array().unwrap();
        let contract_names = specs
            .iter()
            .map(|spec| spec["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        for column in columns {
            assert!(
                contract_names.contains(column),
                "{relation}.{column} is not a contract column"
            );
        }
        let extra = columns
            .iter()
            .filter(|column| !contract_names.contains(column))
            .collect::<Vec<_>>();
        assert!(extra.is_empty(), "{relation} projects non-contract columns");
        let mut expected_unassembled = contract_names
            .iter()
            .filter(|name| !columns.contains(name))
            .copied()
            .collect::<Vec<_>>();
        expected_unassembled.sort_unstable();
        let mut unassembled = unassembled.to_vec();
        unassembled.sort_unstable();
        assert_eq!(
            expected_unassembled, unassembled,
            "{relation}: unassembled column set differs from the documented gap"
        );
        for row in rows {
            for spec in specs {
                let name = spec["name"].as_str().unwrap();
                if !columns.contains(&name) {
                    assert!(
                        row.get(name).is_none(),
                        "{relation}.{name} must not be projected"
                    );
                    continue;
                }
                let value = &row[name];
                let nullable = spec["nullable"].as_bool().unwrap();
                if value.is_null() {
                    assert!(
                        nullable,
                        "{relation}.{name}: NULL for a non-nullable column"
                    );
                    continue;
                }
                match spec["data_type"].as_str().unwrap() {
                    "UInt32" | "UInt64" => assert!(
                        value.is_u64(),
                        "{relation}.{name}: expected an unsigned integer, got {value}"
                    ),
                    "Utf8" | "Utf8View" => assert!(
                        value.is_string(),
                        "{relation}.{name}: expected text, got {value}"
                    ),
                    other => panic!("unhandled contract data type {other}"),
                }
            }
        }
    }

    #[test]
    fn relation_projections_match_contract_columns_types_and_nullability() {
        use crate::code::{CodeItemRow, CodeRelation, MethodCodeFactViews, MethodCodeViewLimits};
        use crate::definitions::{ClassRow, DefinitionRelation, MethodRow};
        use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits};

        // dex_files / strings / types come from one metadata occurrence.
        let metadata = build_one("classic-035.dex");
        let dex_rows = serde_json::to_value(metadata.dex_file_rows(0, 0).unwrap()).unwrap();
        assert_contract_projection(
            "dex_files",
            DexFileRow::COLUMNS,
            &["source_path", "entry_name"],
            dex_rows.as_array().unwrap(),
        );
        let string_rows = serde_json::to_value(metadata.string_rows(0, 0).unwrap()).unwrap();
        assert_contract_projection(
            "strings",
            StringRow::COLUMNS,
            &[],
            string_rows.as_array().unwrap(),
        );
        let metadata = build_one("type-names-035.dex");
        let type_rows = serde_json::to_value(metadata.type_rows(0).unwrap()).unwrap();
        assert_contract_projection(
            "types",
            TypeRow::COLUMNS,
            &[],
            type_rows.as_array().unwrap(),
        );

        // methods / classes / code_items need definitions and code facts.
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let inventory = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let definitions =
            crate::definitions::DefinitionFacts::build(metadata, DefinitionLimits::default())
                .unwrap();
        let code = crate::code::CodeFacts::build_all_code_items(
            &snapshot,
            &inventory,
            0,
            CodeLimits::default(),
        )
        .unwrap();
        let method_rows = serde_json::to_value(definitions.method_rows(0).unwrap()).unwrap();
        assert_contract_projection(
            "methods",
            MethodRow::COLUMNS,
            &["opcode_count", "opcode_hex"],
            method_rows.as_array().unwrap(),
        );
        let class_rows = serde_json::to_value(definitions.class_rows(0).unwrap()).unwrap();
        assert_contract_projection(
            "classes",
            ClassRow::COLUMNS,
            &[],
            class_rows.as_array().unwrap(),
        );
        let views =
            MethodCodeFactViews::build(&definitions, &code, MethodCodeViewLimits::default())
                .unwrap();
        views
            .require_relation_columns(CodeRelation::CodeItems, CodeItemRow::COLUMNS)
            .unwrap();
        // The code-joined projection covers all 14 `methods` columns.
        let joined_methods = serde_json::to_value(views.method_rows(0).unwrap()).unwrap();
        assert_contract_projection(
            "methods",
            crate::code::MethodCodeRow::COLUMNS,
            &[],
            joined_methods.as_array().unwrap(),
        );
        let code_rows = serde_json::to_value(views.code_item_rows(0).unwrap()).unwrap();
        assert_contract_projection(
            "code_items",
            CodeItemRow::COLUMNS,
            &[],
            code_rows.as_array().unwrap(),
        );
        assert!(
            definitions
                .require_relation_columns(DefinitionRelation::Classes, ClassRow::COLUMNS)
                .is_ok()
        );
    }

    #[test]
    fn method_relation_keeps_restricted_columns_rejected() {
        use crate::definitions::DefinitionRelation;
        use mdd_dex::definitions::DefinitionLimits;
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let inventory = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let metadata =
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
        let definitions =
            crate::definitions::DefinitionFacts::build(metadata, DefinitionLimits::default())
                .unwrap();
        // `param_descriptors` is assembled by the definition layer; only the two
        // code-layout opcode columns stay rejected there.
        assert!(
            definitions
                .require_relation_columns(DefinitionRelation::Methods, &["param_descriptors"])
                .is_ok()
        );
        for column in ["opcode_count", "opcode_hex"] {
            let error = definitions
                .require_relation_columns(DefinitionRelation::Methods, &[column])
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::IncompleteFacts, "{column}");
            assert_eq!(
                error
                    .details
                    .get("required_layer")
                    .and_then(|value| value.as_str()),
                Some("code_layout"),
                "{column}"
            );
        }
        // A restricted column must never be silently included by a star request.
        assert!(
            definitions
                .require_relation_columns(DefinitionRelation::Methods, &["*"])
                .is_err()
        );
    }
}
