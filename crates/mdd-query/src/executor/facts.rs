//! Shared read-only facts provider. No SQL compatibility columns or business classification.
use super::{FactSource, RelationSchema};
use crate::ir::*;
use mdd_dex::definitions::MethodBody;
use mdd_facts::{
    EntityKind, EntityRef, MetadataFacts, MetadataSource, code::CodeFacts,
    definitions::DefinitionFacts,
};
use mdd_types::{Completeness, DecimalU64, ErrorCode, MddError, MddResult, opaque_id};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

fn incomplete(layer: FactLayer) -> MddError {
    MddError::new(
        ErrorCode::IncompleteFacts,
        "query.facts",
        "required fact layer has not been completely built for this catalog scope",
    )
    .detail(
        "required_layer",
        serde_json::to_value(layer).expect("enum serializes"),
    )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Table {
    pub columns: Schema,
    pub required_layers: Vec<FactLayer>,
    pub rows: Vec<Row>,
}
/// Generic SDK/test tables, distinct from validated DEX facts. Construction validates every row.
pub struct MemoryCatalog {
    identity: String,
    snapshot: String,
    epoch: DecimalU64,
    tables: BTreeMap<String, Table>,
    ready: BTreeSet<FactLayer>,
    code: BTreeMap<String, Option<Vec<u8>>>,
}
impl MemoryCatalog {
    pub fn new(
        snapshot: String,
        epoch: DecimalU64,
        tables: BTreeMap<String, Table>,
        ready: BTreeSet<FactLayer>,
    ) -> MddResult<Self> {
        if snapshot.is_empty() {
            return Err(invalid("EMPTY_SNAPSHOT"));
        }
        for table in tables.values() {
            validate_schema(&table.columns)?;
            for row in &table.rows {
                validate_row(row, &table.columns, &snapshot)?;
            }
        }
        Ok(Self {
            identity: opaque_id("query-catalog")?,
            snapshot,
            epoch,
            tables,
            ready,
            code: BTreeMap::new(),
        })
    }
    pub fn with_code(mut self, values: Vec<(EntityRef, Option<Vec<u8>>)>) -> MddResult<Self> {
        for (entity, bytes) in values {
            Value::Entity(entity.clone()).validate(&self.snapshot)?;
            if entity.kind != EntityKind::MethodDefinition {
                return Err(invalid("CODE_DEFINITION_REQUIRED"));
            }
            let key = serde_json::to_string(&entity).map_err(|_| invalid("ENTITY_ENCODING"))?;
            if self.code.insert(key, bytes).is_some() {
                return Err(invalid("DUPLICATE_CODE_DEFINITION"));
            }
        }
        Ok(self)
    }
}
impl FactSource for MemoryCatalog {
    fn identity(&self) -> &str {
        &self.identity
    }
    fn snapshot_id(&self) -> &str {
        &self.snapshot
    }
    fn catalog_epoch(&self) -> DecimalU64 {
        self.epoch
    }
    fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema> {
        let table = self
            .tables
            .get(relation)
            .ok_or_else(|| invalid("UNKNOWN_RELATION"))?;
        Ok(RelationSchema {
            columns: table.columns.clone(),
            required_layers: table.required_layers.clone(),
        })
    }
    fn require_layers(&self, layers: &BTreeSet<FactLayer>) -> MddResult<()> {
        for layer in layers {
            if !self.ready.contains(layer) {
                return Err(incomplete(*layer));
            }
        }
        Ok(())
    }
    fn scan<'a>(
        &'a self,
        relation: &str,
    ) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>> {
        let table = self
            .tables
            .get(relation)
            .ok_or_else(|| invalid("UNKNOWN_RELATION"))?;
        Ok(Box::new(table.rows.iter().cloned().map(Ok)))
    }
    fn validate_entity(&self, entity: &EntityRef) -> MddResult<()> {
        Value::Entity(entity.clone()).validate(&self.snapshot)?;
        let present = self.tables.values().any(|table| {
            table
                .rows
                .iter()
                .any(|row| row.iter().any(|v| v == &Value::Entity(entity.clone())))
        });
        let key = serde_json::to_string(entity).map_err(|_| invalid("ENTITY_ENCODING"))?;
        if present || self.code.contains_key(&key) {
            Ok(())
        } else {
            Err(invalid("ENTITY_OUTSIDE_CATALOG"))
        }
    }
    fn read_code_bytes(&self, entity: &EntityRef) -> MddResult<Option<&[u8]>> {
        Value::Entity(entity.clone()).validate(&self.snapshot)?;
        let key = serde_json::to_string(entity).map_err(|_| invalid("ENTITY_ENCODING"))?;
        self.code
            .get(&key)
            .map(|v| v.as_deref())
            .ok_or_else(|| invalid("UNKNOWN_CODE_DEFINITION"))
    }
}

pub struct OccurrenceFacts {
    pub metadata: Arc<MetadataFacts>,
    pub definitions: Option<Arc<DefinitionFacts>>,
    pub code: Option<Arc<CodeFacts>>,
}
pub struct NativeCatalog {
    identity: String,
    snapshot: String,
    epoch: DecimalU64,
    pub(super) occurrences: Vec<OccurrenceFacts>,
}
fn same(a: &MetadataSource, b: &MetadataSource) -> bool {
    a.snapshot_id == b.snapshot_id
        && a.dex_occurrence_id == b.dex_occurrence_id
        && a.content_id == b.content_id
        && a.physical_dex_id == b.physical_dex_id
        && a.member_id == b.member_id
        && a.source_occurrence_id == b.source_occurrence_id
}
impl NativeCatalog {
    pub fn new(
        snapshot: String,
        epoch: DecimalU64,
        occurrences: Vec<OccurrenceFacts>,
    ) -> MddResult<Self> {
        if snapshot.is_empty() || occurrences.is_empty() {
            return Err(invalid("NATIVE_SCOPE_MUST_BE_EXPLICIT_NONEMPTY"));
        }
        let mut seen = BTreeSet::new();
        for occurrence in &occurrences {
            let metadata = &occurrence.metadata;
            if metadata.source().snapshot_id != snapshot
                || !seen.insert(metadata.source().dex_occurrence_id.clone())
                || metadata.metadata_coverage() != Completeness::Complete
            {
                return Err(invalid("NATIVE_METADATA_SOURCE_OR_COVERAGE"));
            }
            if let Some(definitions) = &occurrence.definitions
                && (!same(metadata.source(), definitions.metadata().source())
                    || !Arc::ptr_eq(&metadata.lease(), &definitions.metadata().lease())
                    || definitions.definition_coverage() != Completeness::Complete)
            {
                return Err(invalid("NATIVE_DEFINITION_SOURCE_OR_COVERAGE"));
            }
            if let Some(code) = &occurrence.code
                && (!same(metadata.source(), code.source())
                    || !Arc::ptr_eq(&metadata.lease(), &code.lease())
                    || code.code_layout_coverage() != Completeness::Complete
                    || code.scope() != "complete-declared-code-map-v1")
            {
                return Err(invalid("NATIVE_CODE_SOURCE_OR_COMPLETE_MAP_REQUIRED"));
            }
        }
        Ok(Self {
            identity: opaque_id("query-native-catalog")?,
            snapshot,
            epoch,
            occurrences,
        })
    }
}
fn column(id: &str, ty: DataType, nullable: bool) -> Column {
    Column {
        id: id.into(),
        display_name: id.into(),
        data_type: ty,
        nullable,
    }
}
fn schema(relation: &str) -> MddResult<RelationSchema> {
    use DataType::*;
    let (columns, layer) = match relation {
        "dex_occurrences" => (
            vec![
                column("snapshot_id", Utf16, false),
                column("dex_occurrence_id", Utf16, false),
                column("physical_dex_id", Utf16, false),
                column("member_id", Utf16, false),
                column("source_occurrence_id", Utf16, false),
                column("content_id", Utf16, false),
            ],
            FactLayer::Metadata,
        ),
        "string_pools" => (
            vec![
                column("dex_occurrence_id", Utf16, false),
                column("string_pool_id", Utf16, false),
                column("physical_dex_id", Utf16, false),
                column("content_id", Utf16, false),
                column("string_ids_byte_offset", U64, false),
                column("string_count", U64, false),
            ],
            FactLayer::Metadata,
        ),
        "strings" => (
            vec![
                column("entity", Entity, false),
                column("local_index", U64, false),
                column("string_pool_id", Utf16, false),
                column("utf16", Utf16, false),
                column("raw_mutf8", Bytes, false),
            ],
            FactLayer::Metadata,
        ),
        "types" => (
            vec![
                column("entity", Entity, false),
                column("local_index", U64, false),
                column("descriptor", Utf16, false),
                column("descriptor_string", Entity, false),
            ],
            FactLayer::Metadata,
        ),
        "prototypes" => (
            vec![
                column("entity", Entity, false),
                column("local_index", U64, false),
                column("descriptor", Utf16, false),
                column("return_type", Entity, false),
                column("parameter_count", U64, false),
            ],
            FactLayer::Metadata,
        ),
        "prototype_parameters" => (
            vec![
                column("prototype", Entity, false),
                column("ordinal", U64, false),
                column("parameter_type", Entity, false),
            ],
            FactLayer::Metadata,
        ),
        "classes" => (
            vec![
                column("entity", Entity, false),
                column("class_def_idx", U64, false),
                column("type", Entity, false),
                column("descriptor", Utf16, false),
                column("superclass", Entity, true),
                column("source_file", Utf16, true),
            ],
            FactLayer::Structure,
        ),
        "class_definition_details" => (
            vec![
                column("class_definition", Entity, false),
                column("access_flags", U64, false),
                column("annotations_offset", U64, true),
                column("static_values_offset", U64, true),
                column("class_data_offset", U64, true),
                column("class_data_length", U64, true),
                column("static_fields_count", U64, false),
                column("instance_fields_count", U64, false),
                column("direct_methods_count", U64, false),
                column("virtual_methods_count", U64, false),
                column("encoded_offset", U64, false),
                column("encoded_length", U64, false),
            ],
            FactLayer::Structure,
        ),
        "class_interfaces" => (
            vec![
                column("class_definition", Entity, false),
                column("ordinal", U64, false),
                column("interface_type", Entity, false),
            ],
            FactLayer::Structure,
        ),
        "fields" => (
            vec![
                column("entity", Entity, false),
                column("local_index", U64, false),
                column("owner", Entity, false),
                column("name", Utf16, false),
                column("field_type", Entity, false),
                column("descriptor", Utf16, false),
            ],
            FactLayer::Structure,
        ),
        "methods" => (
            vec![
                column("entity", Entity, false),
                column("local_index", U64, false),
                column("owner", Entity, false),
                column("name", Utf16, false),
                column("prototype", Entity, false),
                column("descriptor", Utf16, false),
            ],
            FactLayer::Structure,
        ),
        "field_definitions" => (
            vec![
                column("entity", Entity, false),
                column("reference", Entity, false),
                column("class_definition", Entity, false),
                column("access_flags", U64, false),
                column("kind", Utf16, false),
                column("ordinal", U64, false),
            ],
            FactLayer::Structure,
        ),
        "method_definitions" => (
            vec![
                column("entity", Entity, false),
                column("reference", Entity, false),
                column("class_definition", Entity, false),
                column("access_flags", U64, false),
                column("kind", Utf16, false),
                column("body_state", Utf16, false),
            ],
            FactLayer::Structure,
        ),
        "class_method_members" => (
            vec![
                column("class_definition", Entity, false),
                column("method_definition", Entity, false),
                column("kind", Utf16, false),
                column("ordinal", U64, false),
            ],
            FactLayer::Structure,
        ),
        "class_field_members" => (
            vec![
                column("class_definition", Entity, false),
                column("field_definition", Entity, false),
                column("kind", Utf16, false),
                column("ordinal", U64, false),
            ],
            FactLayer::Structure,
        ),
        "code_items" => (
            vec![
                column("dex_occurrence_id", Utf16, false),
                column("code_item_id", Utf16, false),
                column("physical_dex_id", Utf16, false),
                column("code_offset", U64, false),
                column("code_length", U64, false),
                column("insns_offset", U64, false),
                column("insns_length", U64, false),
                column("registers_size", U64, false),
                column("ins_size", U64, false),
                column("outs_size", U64, false),
                column("insns_size_code_units", U64, false),
                column("debug_info_offset", U64, true),
            ],
            FactLayer::CodeLayout,
        ),
        _ => return Err(invalid("UNKNOWN_RELATION")),
    };
    Ok(RelationSchema {
        columns,
        required_layers: vec![layer],
    })
}
fn entity(source: &MetadataSource, kind: EntityKind, index: u32) -> Value {
    Value::Entity(EntityRef {
        snapshot_id: source.snapshot_id.clone(),
        dex_occurrence_id: source.dex_occurrence_id.clone(),
        kind,
        local_index: index,
    })
}
fn number(value: u32) -> Value {
    Value::U64(DecimalU64(u64::from(value)))
}
fn rows<'a>(
    o: &'a OccurrenceFacts,
    relation: &str,
) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>> {
    let metadata = &o.metadata;
    let source = metadata.source();
    match relation {
        "dex_occurrences" => {
            return Ok(Box::new(std::iter::once(Ok(vec![
                Value::text(&source.snapshot_id),
                Value::text(&source.dex_occurrence_id),
                Value::text(&source.physical_dex_id),
                Value::text(&source.member_id),
                Value::text(&source.source_occurrence_id),
                Value::text(&source.content_id),
            ]))));
        }
        "string_pools" => {
            let pool = metadata.string_pool();
            return Ok(Box::new(std::iter::once(Ok(vec![
                Value::text(&pool.dex_occurrence_id),
                Value::text(&pool.string_pool_id),
                Value::text(&pool.physical_dex_id),
                Value::text(&pool.content_id),
                Value::U64(pool.string_ids_byte_offset),
                number(pool.string_count),
            ]))));
        }
        "strings" => {
            return Ok(Box::new(metadata.strings().iter().map(|v| {
                Ok(vec![
                    Value::Entity(v.entity.clone()),
                    number(v.data.string_idx),
                    Value::text(&v.string_pool_id),
                    Value::Utf16(v.data.text.utf16_units.clone()),
                    Value::Bytes(Bytes(v.data.text.raw_mutf8.clone())),
                ])
            })));
        }
        "types" => {
            return Ok(Box::new(metadata.types().iter().map(|v| {
                Ok(vec![
                    Value::Entity(v.entity.clone()),
                    number(v.data.type_idx),
                    Value::text(&v.data.descriptor),
                    Value::Entity(v.descriptor_string.clone()),
                ])
            })));
        }
        "prototypes" => {
            return Ok(Box::new(metadata.prototypes().iter().map(|v| {
                Ok(vec![
                    Value::Entity(v.entity.clone()),
                    number(v.data.proto_idx),
                    Value::text(&v.data.descriptor),
                    Value::Entity(v.return_type.clone()),
                    Value::U64(DecimalU64(v.parameter_types.len() as u64)),
                ])
            })));
        }
        "prototype_parameters" => {
            return Ok(Box::new(metadata.prototypes().iter().flat_map(
                |prototype| {
                    prototype
                        .parameter_types
                        .iter()
                        .enumerate()
                        .map(move |(ordinal, parameter)| {
                            Ok(vec![
                                Value::Entity(prototype.entity.clone()),
                                Value::U64(DecimalU64(ordinal as u64)),
                                Value::Entity(parameter.clone()),
                            ])
                        })
                },
            )));
        }
        "code_items" => {
            let code = o
                .code
                .as_ref()
                .ok_or_else(|| incomplete(FactLayer::CodeLayout))?;
            return Ok(Box::new(code.items().iter().map(|item| {
                let value = item.data();
                Ok(vec![
                    Value::text(&source.dex_occurrence_id),
                    Value::text(item.code_item_id()),
                    Value::text(&source.physical_dex_id),
                    Value::U64(value.raw_range.byte_offset),
                    Value::U64(value.raw_range.byte_length),
                    Value::U64(value.insns_range.byte_offset),
                    Value::U64(value.insns_range.byte_length),
                    number(u32::from(value.registers_size)),
                    number(u32::from(value.ins_size)),
                    number(u32::from(value.outs_size)),
                    number(value.insns_size_code_units),
                    value.debug_info_byte_offset.map_or(Value::Null, Value::U64),
                ])
            })));
        }
        _ => (),
    }
    let definitions = o
        .definitions
        .as_ref()
        .ok_or_else(|| incomplete(FactLayer::Structure))?
        .definitions();
    Ok(match relation {
        "class_definition_details" => Box::new(definitions.classes.iter().map(|v| {
            let range = v.class_data_range.as_ref();
            Ok(vec![
                entity(source, EntityKind::ClassDefinition, v.class_def_idx),
                number(v.access_flags),
                v.annotations_byte_offset.map_or(Value::Null, Value::U64),
                v.static_values_byte_offset.map_or(Value::Null, Value::U64),
                range.map_or(Value::Null, |r| Value::U64(r.byte_offset)),
                range.map_or(Value::Null, |r| Value::U64(r.byte_length)),
                number(v.static_fields_count),
                number(v.instance_fields_count),
                number(v.direct_methods_count),
                number(v.virtual_methods_count),
                Value::U64(v.encoded_range.byte_offset),
                Value::U64(v.encoded_range.byte_length),
            ])
        })),
        "classes" => Box::new(definitions.classes.iter().map(|v| {
            Ok(vec![
                entity(source, EntityKind::ClassDefinition, v.class_def_idx),
                number(v.class_def_idx),
                entity(source, EntityKind::Type, v.class_idx),
                Value::text(&v.descriptor),
                v.superclass_idx
                    .map_or(Value::Null, |i| entity(source, EntityKind::Type, i)),
                v.source_file
                    .as_ref()
                    .map_or(Value::Null, |v| Value::Utf16(v.utf16_units.clone())),
            ])
        })),
        "class_interfaces" => Box::new(definitions.interfaces.iter().map(|v| {
            Ok(vec![
                entity(source, EntityKind::ClassDefinition, v.class_def_idx),
                number(v.ordinal),
                entity(source, EntityKind::Type, v.interface_type_idx),
            ])
        })),
        "fields" => Box::new(definitions.field_references.iter().map(|v| {
            Ok(vec![
                entity(source, EntityKind::FieldReference, v.field_idx),
                number(v.field_idx),
                entity(source, EntityKind::Type, v.class_idx),
                Value::text(&v.field_name),
                entity(source, EntityKind::Type, v.type_idx),
                Value::text(&v.descriptor),
            ])
        })),
        "methods" => Box::new(definitions.method_references.iter().map(|v| {
            Ok(vec![
                entity(source, EntityKind::MethodReference, v.method_idx),
                number(v.method_idx),
                entity(source, EntityKind::Type, v.class_idx),
                Value::text(&v.method_name),
                entity(source, EntityKind::Prototype, v.proto_idx),
                Value::text(&v.descriptor),
            ])
        })),
        "field_definitions" => Box::new(definitions.field_definitions.iter().map(|v| {
            Ok(vec![
                entity(source, EntityKind::FieldDefinition, v.field_idx),
                entity(source, EntityKind::FieldReference, v.field_idx),
                entity(source, EntityKind::ClassDefinition, v.class_def_idx),
                number(v.access_flags),
                Value::text(v.kind.as_str()),
                number(v.ordinal),
            ])
        })),
        "method_definitions" => Box::new(definitions.method_definitions.iter().map(|v| {
            Ok(vec![
                entity(source, EntityKind::MethodDefinition, v.method_idx),
                entity(source, EntityKind::MethodReference, v.method_idx),
                entity(source, EntityKind::ClassDefinition, v.class_def_idx),
                number(v.access_flags),
                Value::text(v.kind.as_str()),
                Value::text(v.body.state()),
            ])
        })),
        "class_method_members" => Box::new(definitions.method_definitions.iter().map(|v| {
            Ok(vec![
                entity(source, EntityKind::ClassDefinition, v.class_def_idx),
                entity(source, EntityKind::MethodDefinition, v.method_idx),
                Value::text(v.kind.as_str()),
                number(v.ordinal),
            ])
        })),
        "class_field_members" => Box::new(definitions.field_definitions.iter().map(|v| {
            Ok(vec![
                entity(source, EntityKind::ClassDefinition, v.class_def_idx),
                entity(source, EntityKind::FieldDefinition, v.field_idx),
                Value::text(v.kind.as_str()),
                number(v.ordinal),
            ])
        })),
        _ => return Err(invalid("UNKNOWN_RELATION")),
    })
}
impl FactSource for NativeCatalog {
    fn identity(&self) -> &str {
        &self.identity
    }
    fn snapshot_id(&self) -> &str {
        &self.snapshot
    }
    fn catalog_epoch(&self) -> DecimalU64 {
        self.epoch
    }
    fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema> {
        schema(relation)
    }
    fn validate_entity(&self, entity: &EntityRef) -> MddResult<()> {
        Value::Entity(entity.clone()).validate(&self.snapshot)?;
        let occurrence = self
            .occurrences
            .iter()
            .find(|v| v.metadata.source().dex_occurrence_id == entity.dex_occurrence_id)
            .ok_or_else(|| invalid("ENTITY_OUTSIDE_CATALOG"))?;
        match entity.kind {
            EntityKind::String | EntityKind::Type | EntityKind::Prototype => {
                occurrence
                    .metadata
                    .entity(entity.kind, entity.local_index)?;
            }
            _ => {
                occurrence
                    .definitions
                    .as_ref()
                    .ok_or_else(|| incomplete(FactLayer::Structure))?
                    .entity(entity.kind, entity.local_index)?;
            }
        }
        Ok(())
    }
    fn require_layers(&self, layers: &BTreeSet<FactLayer>) -> MddResult<()> {
        for layer in layers {
            match layer {
                FactLayer::Metadata => (),
                FactLayer::Structure
                    if self.occurrences.iter().all(|v| v.definitions.is_some()) => {}
                FactLayer::CodeLayout if self.occurrences.iter().all(|v| v.code.is_some()) => {}
                _ => return Err(incomplete(*layer)),
            }
        }
        Ok(())
    }
    fn scan<'a>(
        &'a self,
        relation: &str,
    ) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>> {
        let info = schema(relation)?;
        self.require_layers(&info.required_layers.into_iter().collect())?;
        let iterators = self
            .occurrences
            .iter()
            .map(|o| rows(o, relation))
            .collect::<MddResult<Vec<_>>>()?;
        Ok(Box::new(iterators.into_iter().flatten()))
    }
    fn read_code_bytes(&self, entity_ref: &EntityRef) -> MddResult<Option<&[u8]>> {
        Value::Entity(entity_ref.clone()).validate(&self.snapshot)?;
        if entity_ref.kind != EntityKind::MethodDefinition {
            return Err(invalid("CODE_DEFINITION_REQUIRED"));
        }
        let occurrence = self
            .occurrences
            .iter()
            .find(|v| v.metadata.source().dex_occurrence_id == entity_ref.dex_occurrence_id)
            .ok_or_else(|| invalid("UNKNOWN_DEX_OCCURRENCE"))?;
        let definitions = occurrence
            .definitions
            .as_ref()
            .ok_or_else(|| incomplete(FactLayer::Structure))?;
        let method = definitions
            .definitions()
            .method_definitions
            .iter()
            .find(|v| v.method_idx == entity_ref.local_index)
            .ok_or_else(|| invalid("UNKNOWN_METHOD_DEFINITION"))?;
        match &method.body {
            MethodBody::Abstract | MethodBody::Native => Ok(None),
            MethodBody::Present {
                code_byte_offset,
                declared_insns_size,
            } => {
                let code = occurrence
                    .code
                    .as_ref()
                    .ok_or_else(|| incomplete(FactLayer::CodeLayout))?;
                let ordinal = code
                    .items()
                    .iter()
                    .position(|v| v.data().raw_range.byte_offset == *code_byte_offset)
                    .ok_or_else(|| invalid("METHOD_CODE_ITEM_NOT_PRESENT"))?;
                if code.items()[ordinal].data().insns_size_code_units != *declared_insns_size {
                    return Err(invalid("METHOD_CODE_LENGTH_MISMATCH"));
                }
                code.raw_insns(ordinal).map(Some)
            }
        }
    }
}
