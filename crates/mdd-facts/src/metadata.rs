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
use mdd_types::{Completeness, ErrorCode, MddError, MddResult, content_id};
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

#[cfg(test)]
mod tests {
    use super::*;
    use mdd_input::{
        archive::{ArchiveLimits, InventoryPolicy},
        snapshot::{CaptureLimits, InputKind, InputSpec},
    };
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
}
