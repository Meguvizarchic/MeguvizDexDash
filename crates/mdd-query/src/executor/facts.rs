//! Shared read-only facts provider. No SQL compatibility columns or business classification.
use super::{FactSource, RelationSchema};
use crate::ir::*;
use mdd_dex::definitions::MethodBody;
use mdd_facts::{
    EntityKind, EntityRef, MetadataFacts, MetadataSource,
    annotations::AnnotationFacts,
    code::CodeFacts,
    definitions::DefinitionFacts,
    references::{ReferenceFacts, TargetKind},
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

/// Typed view combining a native catalog with complete encoded-reference facts.
/// Occurrence order comes from the native catalog, not the supplied vector.
/// Encoded references do not resolve dispatch or dynamic runtime targets.
pub struct ReferenceCatalog {
    identity: String,
    native: NativeCatalog,
    references: Vec<Arc<ReferenceFacts>>,
}

/// Typed annotations over either a native or reference-backed catalog.
/// The supplied occurrences are explicit and do not by themselves certify
/// that every input in the captured snapshot was selected. Parameter slots in
/// signature relations are encoded slots, not proven prototype positions.
pub struct AnnotationCatalog {
    identity: String,
    base: AnnotationBase,
    annotations: Vec<Arc<AnnotationFacts>>,
}

enum AnnotationBase {
    Native(NativeCatalog),
    References(ReferenceCatalog),
}

impl AnnotationBase {
    fn native(&self) -> &NativeCatalog {
        match self {
            Self::Native(base) => base,
            Self::References(base) => &base.native,
        }
    }

    fn source(&self) -> &dyn FactSource {
        match self {
            Self::Native(base) => base,
            Self::References(base) => base,
        }
    }
}

impl AnnotationCatalog {
    pub fn new(native: NativeCatalog, annotations: Vec<Arc<AnnotationFacts>>) -> MddResult<Self> {
        Self::build(AnnotationBase::Native(native), annotations)
    }

    pub fn with_references(
        references: ReferenceCatalog,
        annotations: Vec<Arc<AnnotationFacts>>,
    ) -> MddResult<Self> {
        Self::build(AnnotationBase::References(references), annotations)
    }

    fn build(base: AnnotationBase, annotations: Vec<Arc<AnnotationFacts>>) -> MddResult<Self> {
        if annotations.len() != base.native().occurrences.len() {
            return Err(incomplete(FactLayer::Annotations));
        }
        let mut by_occurrence = BTreeMap::new();
        for facts in annotations {
            if facts.annotation_coverage() != Completeness::Complete
                || facts.definitions().definition_coverage() != Completeness::Complete
                || facts.definitions().metadata().metadata_coverage() != Completeness::Complete
            {
                return Err(incomplete(FactLayer::Annotations));
            }
            if by_occurrence
                .insert(facts.source().dex_occurrence_id.clone(), facts)
                .is_some()
            {
                return Err(invalid("DUPLICATE_ANNOTATION_OCCURRENCE"));
            }
        }
        let mut ordered = Vec::with_capacity(base.native().occurrences.len());
        for occurrence in &base.native().occurrences {
            let facts = by_occurrence
                .remove(&occurrence.metadata.source().dex_occurrence_id)
                .ok_or_else(|| incomplete(FactLayer::Annotations))?;
            if !same(occurrence.metadata.source(), facts.source())
                || !Arc::ptr_eq(
                    &occurrence.metadata.lease(),
                    &facts.definitions().metadata().lease(),
                )
            {
                return Err(invalid("NATIVE_ANNOTATION_SOURCE_OR_LEASE"));
            }
            ordered.push(facts);
        }
        if !by_occurrence.is_empty() {
            return Err(invalid("ANNOTATION_OUTSIDE_CATALOG"));
        }
        Ok(Self {
            identity: opaque_id("query-annotation-catalog")?,
            base,
            annotations: ordered,
        })
    }
}
impl ReferenceCatalog {
    pub fn new(native: NativeCatalog, references: Vec<Arc<ReferenceFacts>>) -> MddResult<Self> {
        Self::build(native, references, None)
    }

    /// Scoped catalogs supply the already-used comparison counter and bound.
    /// The ordinary public constructor retains its strict same-lease contract.
    pub(super) fn new_scoped_verified(
        native: NativeCatalog,
        references: Vec<Arc<ReferenceFacts>>,
        compared: &mut u64,
        limit: u64,
    ) -> MddResult<Self> {
        Self::build(native, references, Some((compared, limit)))
    }

    fn build(
        native: NativeCatalog,
        references: Vec<Arc<ReferenceFacts>>,
        mut compare: Option<(&mut u64, u64)>,
    ) -> MddResult<Self> {
        if references.len() != native.occurrences.len() {
            return Err(incomplete(FactLayer::References));
        }
        let mut by_occurrence = BTreeMap::new();
        for facts in references {
            facts.require_complete()?;
            if by_occurrence
                .insert(facts.source().dex_occurrence_id.clone(), facts)
                .is_some()
            {
                return Err(invalid("DUPLICATE_REFERENCE_OCCURRENCE"));
            }
        }
        let mut ordered = Vec::with_capacity(native.occurrences.len());
        for occurrence in &native.occurrences {
            let facts = by_occurrence
                .remove(&occurrence.metadata.source().dex_occurrence_id)
                .ok_or_else(|| incomplete(FactLayer::References))?;
            if !same(occurrence.metadata.source(), facts.source())
                || !same(occurrence.metadata.source(), facts.code().source())
            {
                return Err(invalid("NATIVE_REFERENCE_SOURCE_OR_LEASE"));
            }
            let native_bytes = occurrence.metadata.lease();
            let reference_bytes = facts.definitions().metadata().lease();
            let code_bytes = facts.code().lease();
            if let Some((compared, limit)) = compare.as_mut() {
                super::scoped::compare_dex_bytes(
                    &native_bytes,
                    &reference_bytes,
                    compared,
                    *limit,
                )?;
                // Definitions and code commonly share a captured allocation;
                // a second byte comparison is necessary only when they do not.
                if !Arc::ptr_eq(&reference_bytes, &code_bytes) {
                    super::scoped::compare_dex_bytes(&native_bytes, &code_bytes, compared, *limit)?;
                }
            } else if !Arc::ptr_eq(&native_bytes, &reference_bytes)
                || !Arc::ptr_eq(&native_bytes, &code_bytes)
            {
                return Err(invalid("NATIVE_REFERENCE_SOURCE_OR_LEASE"));
            }
            ordered.push(facts);
        }
        if !by_occurrence.is_empty() {
            return Err(invalid("REFERENCE_OUTSIDE_CATALOG"));
        }
        Ok(Self {
            identity: opaque_id("query-reference-catalog")?,
            native,
            references: ordered,
        })
    }

    /// Query encoded method-target invoke sites by exact UTF-16 descriptor.
    /// Distinct source occurrences and repeated call sites remain distinct.
    /// This does not resolve runtime dispatch, CallSite-targeted invoke-custom,
    /// inheritance, or the legacy HostLab table shape. It uses scan/filter/join,
    /// not an indexed access path, and does not promise a stable row order.
    pub fn method_call_query(&self, descriptor: &[u16]) -> MddResult<QueryIr> {
        if descriptor.len() > 1_000_000 {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "query.facts",
                "method descriptor predicate exceeds construction limit",
            ));
        }
        let mut value = Vec::new();
        value.try_reserve_exact(descriptor.len()).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "query.facts",
                "method descriptor predicate allocation failed",
            )
        })?;
        value.extend_from_slice(descriptor);
        let sites = Node::Filter {
            input: Box::new(Node::Scan {
                relation: "reference_sites".into(),
            }),
            predicate: Predicate::And {
                left: Box::new(Predicate::Eq {
                    left: Expr::Column { ordinal: 6 },
                    right: Expr::Literal {
                        value: Value::text("method"),
                    },
                }),
                right: Box::new(Predicate::Not {
                    value: Box::new(Predicate::IsNull {
                        value: Expr::Column { ordinal: 10 },
                    }),
                }),
            },
        };
        let joined = Node::EquiJoin {
            left: Box::new(sites),
            right: Box::new(Node::Scan {
                relation: "methods".into(),
            }),
            left_keys: vec![8],
            right_keys: vec![0],
            kind: JoinKind::Inner,
        };
        let matched = Node::Filter {
            input: Box::new(joined),
            predicate: Predicate::Eq {
                left: Expr::Column { ordinal: 16 },
                right: Expr::Literal {
                    value: Value::Utf16(value),
                },
            },
        };
        let columns = [
            ("dex_occurrence_id", DataType::Utf16, false, 0),
            ("site_ordinal", DataType::U64, false, 1),
            ("caller", DataType::Entity, false, 2),
            ("code_unit_pc", DataType::U64, false, 3),
            ("instruction_ordinal", DataType::U64, false, 4),
            ("operand_ordinal", DataType::U64, false, 5),
            ("opcode", DataType::U64, false, 9),
            ("invoke_kind", DataType::Utf16, true, 10),
            ("callee", DataType::Entity, false, 11),
            ("callee_owner", DataType::Entity, false, 13),
            ("callee_name", DataType::Utf16, false, 14),
            ("callee_prototype", DataType::Entity, false, 15),
            ("callee_descriptor", DataType::Utf16, false, 16),
        ]
        .into_iter()
        .map(|(name, data_type, nullable, ordinal)| Projection {
            column: column(name, data_type, nullable),
            expression: Expr::Column { ordinal },
        })
        .collect();
        Ok(QueryIr {
            schema_version: IR_VERSION.into(),
            text_semantics: TEXT_VERSION.into(),
            snapshot_id: self.native.snapshot_id().to_owned(),
            catalog_epoch: self.native.catalog_epoch(),
            require_stable_order: false,
            root: Node::Project {
                input: Box::new(matched),
                columns,
            },
        })
    }

    /// Query encoded type-reference sites by an exact UTF-16 descriptor.
    /// Source occurrences and operand sites are retained without deduplication.
    /// This does not resolve runtime types or guarantee a stable row order. It
    /// uses scan/filter/join rather than an indexed access path, and does not
    /// promise the legacy HostLab table shape.
    pub fn type_reference_query(&self, descriptor: &[u16]) -> MddResult<QueryIr> {
        if descriptor.len() > 1_000_000 {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "query.facts",
                "type descriptor predicate exceeds construction limit",
            ));
        }
        let mut value = Vec::new();
        value.try_reserve_exact(descriptor.len()).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "query.facts",
                "type descriptor predicate allocation failed",
            )
        })?;
        value.extend_from_slice(descriptor);
        let sites = Node::Filter {
            input: Box::new(Node::Scan {
                relation: "reference_sites".into(),
            }),
            predicate: Predicate::Eq {
                left: Expr::Column { ordinal: 6 },
                right: Expr::Literal {
                    value: Value::text("type"),
                },
            },
        };
        let joined = Node::EquiJoin {
            left: Box::new(sites),
            right: Box::new(Node::Scan {
                relation: "types".into(),
            }),
            left_keys: vec![8],
            right_keys: vec![0],
            kind: JoinKind::Inner,
        };
        let matched = Node::Filter {
            input: Box::new(joined),
            predicate: Predicate::Eq {
                left: Expr::Column { ordinal: 13 },
                right: Expr::Literal {
                    value: Value::Utf16(value),
                },
            },
        };
        let columns = [
            ("dex_occurrence_id", DataType::Utf16, 0),
            ("site_ordinal", DataType::U64, 1),
            ("caller", DataType::Entity, 2),
            ("code_unit_pc", DataType::U64, 3),
            ("instruction_ordinal", DataType::U64, 4),
            ("operand_ordinal", DataType::U64, 5),
            ("opcode", DataType::U64, 9),
            ("type", DataType::Entity, 11),
            ("descriptor", DataType::Utf16, 13),
            ("descriptor_string", DataType::Entity, 14),
        ]
        .into_iter()
        .map(|(name, data_type, ordinal)| Projection {
            column: column(name, data_type, false),
            expression: Expr::Column { ordinal },
        })
        .collect();
        Ok(QueryIr {
            schema_version: IR_VERSION.into(),
            text_semantics: TEXT_VERSION.into(),
            snapshot_id: self.native.snapshot_id().to_owned(),
            catalog_epoch: self.native.catalog_epoch(),
            require_stable_order: false,
            root: Node::Project {
                input: Box::new(matched),
                columns,
            },
        })
    }

    /// Query encoded field-reference sites by an exact UTF-16 descriptor.
    /// Each source occurrence and operand site is retained. The opcode is the
    /// encoded instruction, not a claim about runtime field access or dispatch.
    /// This uses scan/filter/join, not an index, and does not promise row order
    /// or a legacy HostLab table shape.
    pub fn field_reference_query(&self, descriptor: &[u16]) -> MddResult<QueryIr> {
        if descriptor.len() > 1_000_000 {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "query.facts",
                "field descriptor predicate exceeds construction limit",
            ));
        }
        let mut value = Vec::new();
        value.try_reserve_exact(descriptor.len()).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "query.facts",
                "field descriptor predicate allocation failed",
            )
        })?;
        value.extend_from_slice(descriptor);
        let sites = Node::Filter {
            input: Box::new(Node::Scan {
                relation: "reference_sites".into(),
            }),
            predicate: Predicate::Eq {
                left: Expr::Column { ordinal: 6 },
                right: Expr::Literal {
                    value: Value::text("field"),
                },
            },
        };
        let joined = Node::EquiJoin {
            left: Box::new(sites),
            right: Box::new(Node::Scan {
                relation: "fields".into(),
            }),
            left_keys: vec![8],
            right_keys: vec![0],
            kind: JoinKind::Inner,
        };
        let matched = Node::Filter {
            input: Box::new(joined),
            predicate: Predicate::Eq {
                left: Expr::Column { ordinal: 16 },
                right: Expr::Literal {
                    value: Value::Utf16(value),
                },
            },
        };
        let columns = [
            ("dex_occurrence_id", DataType::Utf16, 0),
            ("site_ordinal", DataType::U64, 1),
            ("caller", DataType::Entity, 2),
            ("code_unit_pc", DataType::U64, 3),
            ("instruction_ordinal", DataType::U64, 4),
            ("operand_ordinal", DataType::U64, 5),
            ("opcode", DataType::U64, 9),
            ("field", DataType::Entity, 11),
            ("field_owner", DataType::Entity, 13),
            ("field_name", DataType::Utf16, 14),
            ("field_type", DataType::Entity, 15),
            ("field_descriptor", DataType::Utf16, 16),
        ]
        .into_iter()
        .map(|(name, data_type, ordinal)| Projection {
            column: column(name, data_type, false),
            expression: Expr::Column { ordinal },
        })
        .collect();
        Ok(QueryIr {
            schema_version: IR_VERSION.into(),
            text_semantics: TEXT_VERSION.into(),
            snapshot_id: self.native.snapshot_id().to_owned(),
            catalog_epoch: self.native.catalog_epoch(),
            require_stable_order: false,
            root: Node::Project {
                input: Box::new(matched),
                columns,
            },
        })
    }

    /// Construct a typed exact-string reference query for this catalog.
    /// UTF-16 code units are compared without normalization or lossy decoding.
    /// Every encoded operand occurrence is retained; this is not an index
    /// pushdown or a promise of the legacy HostLab table shape. The query uses
    /// the existing executor budgets and requires complete reference facts.
    pub fn string_reference_query(&self, units: &[u16]) -> MddResult<QueryIr> {
        if units.len() > 1_000_000 {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "query.facts",
                "string predicate exceeds construction limit",
            ));
        }
        let mut value = Vec::new();
        value.try_reserve_exact(units.len()).map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "query.facts",
                "string predicate allocation failed",
            )
        })?;
        value.extend_from_slice(units);
        let sites = Node::Filter {
            input: Box::new(Node::Scan {
                relation: "reference_sites".into(),
            }),
            predicate: Predicate::Eq {
                left: Expr::Column { ordinal: 6 },
                right: Expr::Literal {
                    value: Value::text("string"),
                },
            },
        };
        let strings = Node::Scan {
            relation: "strings".into(),
        };
        let joined = Node::EquiJoin {
            left: Box::new(sites),
            right: Box::new(strings),
            left_keys: vec![8],
            right_keys: vec![0],
            kind: JoinKind::Inner,
        };
        let matched = Node::Filter {
            input: Box::new(joined),
            predicate: Predicate::Eq {
                left: Expr::Column { ordinal: 14 },
                right: Expr::Literal {
                    value: Value::Utf16(value),
                },
            },
        };
        let columns = [
            ("dex_occurrence_id", DataType::Utf16, 0),
            ("site_ordinal", DataType::U64, 1),
            ("caller", DataType::Entity, 2),
            ("code_unit_pc", DataType::U64, 3),
            ("instruction_ordinal", DataType::U64, 4),
            ("operand_ordinal", DataType::U64, 5),
            ("opcode", DataType::U64, 9),
            ("string_entity", DataType::Entity, 11),
            ("string_pool_id", DataType::Utf16, 13),
            ("utf16", DataType::Utf16, 14),
            ("raw_mutf8", DataType::Bytes, 15),
        ]
        .into_iter()
        .map(|(name, data_type, ordinal)| Projection {
            column: column(name, data_type, false),
            expression: Expr::Column { ordinal },
        })
        .collect();
        Ok(QueryIr {
            schema_version: IR_VERSION.into(),
            text_semantics: TEXT_VERSION.into(),
            snapshot_id: self.native.snapshot_id().to_owned(),
            catalog_epoch: self.native.catalog_epoch(),
            require_stable_order: false,
            root: Node::Project {
                input: Box::new(matched),
                columns,
            },
        })
    }
}

fn reference_schema() -> RelationSchema {
    use DataType::*;
    RelationSchema {
        columns: vec![
            column("dex_occurrence_id", Utf16, false),
            column("site_ordinal", U64, false),
            column("caller", Entity, false),
            column("code_unit_pc", U64, false),
            column("instruction_ordinal", U64, false),
            column("operand_ordinal", U64, false),
            column("target_kind", Utf16, false),
            column("target_local_index", U64, false),
            // CallSite and MethodHandle have no EntityKind today. The kind and
            // local index remain present; NULL here means no entity encoding.
            column("target_entity", Entity, true),
            column("opcode", U64, false),
            column("invoke_kind", Utf16, true),
        ],
        required_layers: vec![
            FactLayer::Metadata,
            FactLayer::Structure,
            FactLayer::CodeLayout,
            FactLayer::References,
        ],
    }
}
impl FactSource for ReferenceCatalog {
    fn identity(&self) -> &str {
        &self.identity
    }
    fn snapshot_id(&self) -> &str {
        self.native.snapshot_id()
    }
    fn catalog_epoch(&self) -> DecimalU64 {
        self.native.catalog_epoch()
    }
    fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema> {
        if relation == "reference_sites" {
            Ok(reference_schema())
        } else {
            self.native.relation_schema(relation)
        }
    }
    fn require_layers(&self, layers: &BTreeSet<FactLayer>) -> MddResult<()> {
        if layers.contains(&FactLayer::References) {
            for facts in &self.references {
                facts.require_complete()?;
            }
        }
        let native_layers = layers
            .iter()
            .copied()
            .filter(|layer| *layer != FactLayer::References)
            .collect();
        self.native.require_layers(&native_layers)
    }
    fn validate_entity(&self, value: &EntityRef) -> MddResult<()> {
        self.native.validate_entity(value)
    }
    fn scan<'a>(
        &'a self,
        relation: &str,
    ) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>> {
        if relation != "reference_sites" {
            return self.native.scan(relation);
        }
        self.require_layers(&reference_schema().required_layers.into_iter().collect())?;
        Ok(Box::new(self.references.iter().flat_map(|facts| {
            let source = facts.source();
            facts.sites().iter().map(move |site| {
                use mdd_dex::instructions::InvokeKind;
                let (kind, entity_kind) = match site.target_kind {
                    TargetKind::String => ("string", Some(EntityKind::String)),
                    TargetKind::Type => ("type", Some(EntityKind::Type)),
                    TargetKind::Field => ("field", Some(EntityKind::FieldReference)),
                    TargetKind::Method => ("method", Some(EntityKind::MethodReference)),
                    TargetKind::Prototype => ("prototype", Some(EntityKind::Prototype)),
                    TargetKind::CallSite => ("call_site", None),
                    TargetKind::MethodHandle => ("method_handle", None),
                };
                let invoke = site.invoke_kind.as_ref().map(|value| match value {
                    InvokeKind::Ordinary => "ordinary",
                    InvokeKind::OrdinaryRange => "ordinary_range",
                    InvokeKind::Polymorphic => "polymorphic",
                    InvokeKind::PolymorphicRange => "polymorphic_range",
                    InvokeKind::Custom => "custom",
                    InvokeKind::CustomRange => "custom_range",
                });
                Ok(vec![
                    Value::text(&source.dex_occurrence_id),
                    number(site.site_ordinal),
                    entity(source, EntityKind::MethodDefinition, site.caller_method_idx),
                    number(site.code_unit_pc),
                    number(site.instruction_ordinal),
                    number(site.operand_ordinal),
                    Value::text(kind),
                    number(site.target_local_index),
                    entity_kind.map_or(Value::Null, |kind| {
                        entity(source, kind, site.target_local_index)
                    }),
                    number(u32::from(site.opcode)),
                    invoke.map_or(Value::Null, Value::text),
                ])
            })
        })))
    }
    fn read_code_bytes(&self, value: &EntityRef) -> MddResult<Option<&[u8]>> {
        self.native.read_code_bytes(value)
    }
}

fn annotation_schema(relation: &str) -> Option<RelationSchema> {
    use DataType::*;
    let columns = match relation {
        "annotation_signatures" => vec![
            column("dex_occurrence_id", Utf16, false),
            column("signature_ordinal", U64, false),
            column("annotation_offset", U64, false),
            column("owner_kind", Utf16, false),
            column("owner_reference", Entity, false),
            column("owner_definition", Entity, true),
            column("encoded_parameter_slot", U64, true),
            column("string_pool_id", Utf16, false),
            column("utf16", Utf16, false),
            column("fragment_count", U64, false),
        ],
        "annotation_signature_fragments" => vec![
            column("dex_occurrence_id", Utf16, false),
            column("signature_ordinal", U64, false),
            column("annotation_offset", U64, false),
            column("owner_reference", Entity, false),
            column("encoded_parameter_slot", U64, true),
            column("fragment_ordinal", U64, false),
            column("string_entity", Entity, false),
            column("utf16", Utf16, false),
            column("raw_mutf8", Bytes, false),
        ],
        "annotation_items" => vec![
            column("dex_occurrence_id", Utf16, false),
            column("annotation_offset", U64, false),
            column("visibility", U64, false),
            column("annotation_type", Entity, false),
            column("element_count", U64, false),
            column("encoded_offset", U64, false),
            column("encoded_length", U64, false),
        ],
        "annotation_owners" => vec![
            column("dex_occurrence_id", Utf16, false),
            column("class_definition", Entity, false),
            column("owner_kind", Utf16, false),
            column("owner_reference", Entity, false),
            column("encoded_parameter_slot", U64, true),
            column("annotation_set_offset", U64, true),
            column("prototype_parameter_count", U64, true),
            column("prototype_position_coverage", Utf16, false),
        ],
        "annotation_sets" => vec![
            column("dex_occurrence_id", Utf16, false),
            column("annotation_set_offset", U64, false),
            column("entry_count", U64, false),
            column("encoded_length", U64, false),
        ],
        "annotation_set_entries" => vec![
            column("dex_occurrence_id", Utf16, false),
            column("annotation_set_offset", U64, false),
            column("ordinal", U64, false),
            column("annotation_offset", U64, false),
        ],
        "annotation_values" => vec![
            column("dex_occurrence_id", Utf16, false),
            column("node_id", U64, false),
            column("annotation_offset", U64, true),
            column("depth", U64, false),
            column("ordinal", U64, false),
            column("name_index", U64, true),
            column("value_kind", Utf16, false),
            column("value_arg", U64, false),
            column("value_index", U64, true),
            column("value_string", Entity, true),
            column("value_integer", Utf16, true),
            column("float_bits", U64, true),
            column("float_bit_width", U64, true),
            column("encoded_offset", U64, false),
            column("encoded_length", U64, false),
            column("raw_scalar_payload", Bytes, false),
            column("child_count", U64, false),
        ],
        _ => return None,
    };
    Some(RelationSchema {
        columns,
        required_layers: vec![
            FactLayer::Metadata,
            FactLayer::Structure,
            FactLayer::Annotations,
        ],
    })
}

fn signature_ordinal(value: usize) -> MddResult<Value> {
    Ok(Value::U64(DecimalU64(u64::try_from(value).map_err(
        |_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "query.facts",
                "signature ordinal overflow",
            )
        },
    )?)))
}

impl FactSource for AnnotationCatalog {
    fn identity(&self) -> &str {
        &self.identity
    }
    fn snapshot_id(&self) -> &str {
        self.base.source().snapshot_id()
    }
    fn catalog_epoch(&self) -> DecimalU64 {
        self.base.source().catalog_epoch()
    }
    fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema> {
        match annotation_schema(relation) {
            Some(schema) => Ok(schema),
            None => self.base.source().relation_schema(relation),
        }
    }
    fn require_layers(&self, layers: &BTreeSet<FactLayer>) -> MddResult<()> {
        if layers.contains(&FactLayer::Annotations)
            && self
                .annotations
                .iter()
                .any(|facts| facts.annotation_coverage() != Completeness::Complete)
        {
            return Err(incomplete(FactLayer::Annotations));
        }
        let base_layers = layers
            .iter()
            .copied()
            .filter(|layer| *layer != FactLayer::Annotations)
            .collect();
        self.base.source().require_layers(&base_layers)
    }
    fn validate_entity(&self, entity_ref: &EntityRef) -> MddResult<()> {
        self.base.source().validate_entity(entity_ref)
    }
    fn scan<'a>(
        &'a self,
        relation: &str,
    ) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>> {
        let Some(schema) = annotation_schema(relation) else {
            return self.base.source().scan(relation);
        };
        self.require_layers(&schema.required_layers.into_iter().collect())?;
        if relation == "annotation_owners" {
            return Ok(Box::new(self.annotations.iter().flat_map(|facts| {
                facts.data().owner_bindings.iter().map(move |owner| {
                    use mdd_dex::annotations::AnnotationOwnerKind;
                    let (kind, reference_kind) = match owner.kind {
                        AnnotationOwnerKind::Class => ("class", EntityKind::ClassDefinition),
                        AnnotationOwnerKind::Field => ("field", EntityKind::FieldReference),
                        AnnotationOwnerKind::Method => ("method", EntityKind::MethodReference),
                        AnnotationOwnerKind::Parameter => {
                            ("parameter", EntityKind::MethodReference)
                        }
                    };
                    let definitions = facts.definitions();
                    // The raw relation exposes encoded slots and an explicit
                    // mapping state; it does not certify prototype positions.
                    let coverage = match (owner.kind, owner.parameter_position_in_prototype) {
                        (AnnotationOwnerKind::Parameter, Some(true)) => "complete",
                        (AnnotationOwnerKind::Parameter, None) => "unknown",
                        (AnnotationOwnerKind::Parameter, Some(false)) => {
                            return Err(MddError::new(
                                ErrorCode::InternalFault,
                                "query.facts",
                                "invalid proven parameter position",
                            ));
                        }
                        (_, None) => "not_applicable",
                        (_, Some(_)) => {
                            return Err(MddError::new(
                                ErrorCode::InternalFault,
                                "query.facts",
                                "unexpected parameter position on non-parameter owner",
                            ));
                        }
                    };
                    Ok(vec![
                        Value::text(&facts.source().dex_occurrence_id),
                        Value::Entity(
                            definitions.entity(EntityKind::ClassDefinition, owner.class_def_idx)?,
                        ),
                        Value::text(kind),
                        Value::Entity(definitions.entity(reference_kind, owner.local_index)?),
                        owner.parameter_ordinal.map_or(Value::Null, number),
                        owner.annotation_set_offset.map_or(Value::Null, number),
                        owner.prototype_parameter_count.map_or(Value::Null, number),
                        Value::text(coverage),
                    ])
                })
            })));
        }
        if relation == "annotation_sets" {
            return Ok(Box::new(self.annotations.iter().flat_map(|facts| {
                facts.data().sets.iter().map(move |set| {
                    Ok(vec![
                        Value::text(&facts.source().dex_occurrence_id),
                        number(set.byte_offset),
                        signature_ordinal(set.annotation_offsets.len())?,
                        Value::U64(set.encoded_range.byte_length),
                    ])
                })
            })));
        }
        if relation == "annotation_set_entries" {
            return Ok(Box::new(self.annotations.iter().flat_map(|facts| {
                facts.data().sets.iter().flat_map(move |set| {
                    set.annotation_offsets
                        .iter()
                        .enumerate()
                        .map(move |(ordinal, offset)| {
                            Ok(vec![
                                Value::text(&facts.source().dex_occurrence_id),
                                number(set.byte_offset),
                                signature_ordinal(ordinal)?,
                                number(*offset),
                            ])
                        })
                })
            })));
        }
        if relation == "annotation_items" {
            return Ok(Box::new(self.annotations.iter().flat_map(|facts| {
                facts.data().annotation_items.iter().map(move |item| {
                    let source = facts.source();
                    let annotation_type = facts
                        .definitions()
                        .metadata()
                        .entity(EntityKind::Type, item.type_idx)?;
                    Ok(vec![
                        Value::text(&source.dex_occurrence_id),
                        number(item.byte_offset),
                        number(u32::from(item.visibility)),
                        Value::Entity(annotation_type),
                        signature_ordinal(item.elements.len())?,
                        Value::U64(item.encoded_range.byte_offset),
                        Value::U64(item.encoded_range.byte_length),
                    ])
                })
            })));
        }
        if relation == "annotation_values" {
            return Ok(Box::new(self.annotations.iter().flat_map(|facts| {
                facts
                    .data()
                    .values
                    .iter()
                    .enumerate()
                    .map(move |(ordinal, value)| {
                        use mdd_dex::annotations::EncodedKind;
                        if usize::try_from(value.node_id).ok() != Some(ordinal) {
                            return Err(MddError::new(
                                ErrorCode::InternalFault,
                                "query.facts",
                                "annotation value node identity is inconsistent",
                            ));
                        }
                        let string = if value.kind == EncodedKind::String {
                            let index = value.value_index.ok_or_else(|| {
                                MddError::new(
                                    ErrorCode::InternalFault,
                                    "query.facts",
                                    "annotation string reference is missing",
                                )
                            })?;
                            Value::Entity(
                                facts
                                    .definitions()
                                    .metadata()
                                    .entity(EntityKind::String, index)?,
                            )
                        } else {
                            Value::Null
                        };
                        Ok(vec![
                            Value::text(&facts.source().dex_occurrence_id),
                            number(value.node_id),
                            value.annotation_byte_offset.map_or(Value::Null, number),
                            number(value.depth),
                            number(value.ordinal),
                            value.name_idx.map_or(Value::Null, number),
                            Value::text(value.kind.as_str()),
                            number(u32::from(value.value_arg)),
                            value.value_index.map_or(Value::Null, number),
                            string,
                            value.value_i64.as_deref().map_or(Value::Null, Value::text),
                            value.float_bits.map_or(Value::Null, Value::U64),
                            value
                                .float_bit_width
                                .map_or(Value::Null, |v| number(u32::from(v))),
                            Value::U64(value.encoded_range.byte_offset),
                            Value::U64(value.encoded_range.byte_length),
                            Value::Bytes(Bytes(value.raw_scalar_payload.clone())),
                            signature_ordinal(value.children.len())?,
                        ])
                    })
            })));
        }
        if relation == "annotation_signatures" {
            return Ok(Box::new(self.annotations.iter().flat_map(|facts| {
                facts
                    .signatures()
                    .iter()
                    .enumerate()
                    .map(move |(ordinal, signature)| {
                        use mdd_dex::annotations::AnnotationOwnerKind;
                        let kind = match signature.owner.kind {
                            AnnotationOwnerKind::Class => "class",
                            AnnotationOwnerKind::Field => "field",
                            AnnotationOwnerKind::Method => "method",
                            AnnotationOwnerKind::Parameter => "parameter",
                        };
                        Ok(vec![
                            Value::text(&facts.source().dex_occurrence_id),
                            signature_ordinal(ordinal)?,
                            number(signature.annotation.annotation_byte_offset),
                            Value::text(kind),
                            Value::Entity(signature.owner.reference.clone()),
                            signature
                                .owner
                                .definition
                                .clone()
                                .map_or(Value::Null, Value::Entity),
                            signature
                                .owner
                                .parameter_ordinal
                                .map_or(Value::Null, number),
                            Value::text(&signature.string_pool_id),
                            Value::Utf16(signature.utf16_units.clone()),
                            signature_ordinal(signature.parts.len())?,
                        ])
                    })
            })));
        }
        Ok(Box::new(self.annotations.iter().flat_map(|facts| {
            facts
                .signatures()
                .iter()
                .enumerate()
                .flat_map(move |(ordinal, signature)| {
                    signature
                        .parts
                        .iter()
                        .enumerate()
                        .map(move |(part_ordinal, part)| {
                            let string = facts
                                .definitions()
                                .metadata()
                                .strings()
                                .get(part.local_index as usize)
                                .filter(|string| string.entity == *part)
                                .ok_or_else(|| {
                                    MddError::new(
                                        ErrorCode::InternalFault,
                                        "query.facts",
                                        "signature fragment identity is inconsistent",
                                    )
                                })?;
                            Ok(vec![
                                Value::text(&facts.source().dex_occurrence_id),
                                signature_ordinal(ordinal)?,
                                number(signature.annotation.annotation_byte_offset),
                                Value::Entity(signature.owner.reference.clone()),
                                signature
                                    .owner
                                    .parameter_ordinal
                                    .map_or(Value::Null, number),
                                signature_ordinal(part_ordinal)?,
                                Value::Entity(part.clone()),
                                Value::Utf16(string.data.text.utf16_units.clone()),
                                Value::Bytes(Bytes(string.data.text.raw_mutf8.clone())),
                            ])
                        })
                })
        })))
    }
    fn read_code_bytes(&self, entity_ref: &EntityRef) -> MddResult<Option<&[u8]>> {
        self.base.source().read_code_bytes(entity_ref)
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
