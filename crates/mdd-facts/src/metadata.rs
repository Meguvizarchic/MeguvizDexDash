use mdd_dex::{
    DexHeader,
    strings::{DexString, StringLimits, read_string_pool},
    types::{DexPrototype, DexType, parse_type_descriptor, read_types_and_prototypes},
    validate_header,
};
use mdd_input::{archive::ArchiveInventory, snapshot::Snapshot};
pub use mdd_types::SharedId;
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
    pub snapshot_id: SharedId,
    pub dex_occurrence_id: SharedId,
    pub kind: EntityKind,
    pub local_index: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetadataSource {
    pub snapshot_id: SharedId,
    pub dex_occurrence_id: SharedId,
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
    pub string_pool_id: SharedId,
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
    /// The DEX bytes the facts were read from, leased from the inventory's blob: the facts keep them alive for as long as
    /// they live, and an inventory that does not hold its DEX reads them again only when no facts hold them.
    #[serde(skip)]
    bytes: Arc<[u8]>,
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
            snapshot_id: snapshot.manifest().snapshot_id.as_str().into(),
            dex_occurrence_id: candidate.dex_occurrence_id.as_str().into(),
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
        let bytes = candidate.blob.try_lease().map_err(bind)?;
        if content_id(&bytes) != source.content_id {
            return Err(bind(MddError::new(
                ErrorCode::InternalFault,
                "facts.metadata",
                "held blob differs from captured content identity",
            )));
        }
        let header = validate_header(&bytes).map_err(bind)?;
        let pool = read_string_pool(&bytes, &header, limits).map_err(bind)?;
        let (types, prototypes) =
            read_types_and_prototypes(&bytes, &header, &pool).map_err(bind)?;
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
            dex_occurrence_id: source.dex_occurrence_id.to_string(),
        };
        let entity = |kind, local_index| EntityRef {
            snapshot_id: source.snapshot_id.clone(),
            dex_occurrence_id: source.dex_occurrence_id.clone(),
            kind,
            local_index,
        };
        let pool_id = SharedId::from(&string_pool.string_pool_id);
        let strings = pool
            .into_iter()
            .map(|data| StringFact {
                entity: entity(EntityKind::String, data.string_idx),
                string_pool_id: pool_id.clone(),
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
            bytes,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn lease(&self) -> Arc<[u8]> {
        Arc::clone(&self.bytes)
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
#[path = "metadata_tests.rs"]
mod tests;
