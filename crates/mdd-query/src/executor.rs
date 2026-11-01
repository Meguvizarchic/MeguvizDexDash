//! Immutable-provider execution with typed prepare, explicit work checkpoints and bag semantics.
use crate::budget::{
    BoundedSender, OwnedBatchPacket, OwnedBatchReceipt, OwnedBatchSender, QueueDeliveryReceipt,
    Reservation, Resource, RetainedOwnedBatch, RuntimeBudget,
};
use crate::ir::*;
use crate::operators::{self, Truth};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, Write},
};

pub mod facts;
#[cfg(test)]
mod runtime_tests;
pub mod scoped;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
pub struct RelationSchema {
    pub columns: Schema,
    pub required_layers: Vec<FactLayer>,
}
/// Implementations must expose one immutable generation for the lifetime of their borrows.
/// The built-in catalogs own validated rows/facts; no file is reopened during execution.
pub trait FactSource {
    fn identity(&self) -> &str;
    fn snapshot_id(&self) -> &str;
    fn catalog_epoch(&self) -> DecimalU64;
    fn relation_schema(&self, relation: &str) -> MddResult<RelationSchema>;
    fn require_layers(&self, layers: &BTreeSet<FactLayer>) -> MddResult<()>;
    fn validate_entity(&self, entity: &mdd_facts::EntityRef) -> MddResult<()>;
    fn scan<'a>(
        &'a self,
        relation: &str,
    ) -> MddResult<Box<dyn Iterator<Item = MddResult<Row>> + 'a>>;
    /// None means a definition known to have no body; missing/unbuilt facts are errors.
    fn read_code_bytes(&self, entity: &mdd_facts::EntityRef) -> MddResult<Option<&[u8]>>;
}

#[derive(Clone, Copy, Debug)]
pub struct ExecutionLimits {
    pub max_steps: u64,
    pub max_output_rows: u64,
    pub max_buffered_bytes: u64,
    pub max_cell_bytes: u64,
}
impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            max_steps: 1_000_000,
            max_output_rows: 100_000,
            max_buffered_bytes: 64 * 1024 * 1024,
            max_cell_bytes: 1024 * 1024,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Checkpoint {
    pub phase: &'static str,
    pub steps: DecimalU64,
    pub admitted_buffer_bytes: DecimalU64,
}
type CheckHook<'a> = dyn FnMut(&Checkpoint) -> MddResult<()> + 'a;
pub struct Control<'a> {
    limits: ExecutionLimits,
    steps: u64,
    buffered: u64,
    scanned: u64,
    hook: Option<Box<CheckHook<'a>>>,
    runtime: Option<RuntimeBudget>,
}
impl<'a> Control<'a> {
    pub fn new(limits: ExecutionLimits) -> Self {
        Self {
            limits,
            steps: 0,
            buffered: 0,
            scanned: 0,
            hook: None,
            runtime: None,
        }
    }
    pub fn with_hook(mut self, hook: impl FnMut(&Checkpoint) -> MddResult<()> + 'a) -> Self {
        self.hook = Some(Box::new(hook));
        self
    }
    pub fn with_runtime(mut self, runtime: RuntimeBudget) -> Self {
        self.runtime = Some(runtime);
        self
    }
    fn stop(&self, error: MddError) -> MddError {
        self.runtime
            .as_ref()
            .map_or(error.clone(), |runtime| runtime.stop(error))
    }
    pub fn step(&mut self, phase: &'static str, amount: u64) -> MddResult<()> {
        self.steps = self
            .steps
            .checked_add(amount)
            .ok_or_else(|| quota("STEP_OVERFLOW"))?;
        if self.steps > self.limits.max_steps {
            return Err(self.stop(
                quota("MAX_STEPS")
                    .detail("budget", "query_steps")
                    .detail("limit", self.limits.max_steps.to_string())
                    .detail("observed", self.steps.to_string()),
            ));
        }
        if let Some(runtime) = &self.runtime {
            runtime.charge(Resource::QuerySteps, amount)?;
        }
        if let Some(hook) = &mut self.hook {
            hook(&Checkpoint {
                phase,
                steps: DecimalU64(self.steps),
                admitted_buffer_bytes: DecimalU64(self.buffered),
            })?;
        }
        Ok(())
    }
    pub fn charge(&mut self, bytes: u64) -> MddResult<()> {
        self.buffered = self
            .buffered
            .checked_add(bytes)
            .ok_or_else(|| quota("BUFFER_OVERFLOW"))?;
        if self.buffered > self.limits.max_buffered_bytes {
            return Err(self.stop(
                quota("MAX_BUFFERED_BYTES")
                    .detail("budget", "query_work_bytes")
                    .detail("limit", self.limits.max_buffered_bytes.to_string())
                    .detail("observed", self.buffered.to_string()),
            ));
        }
        if let Some(runtime) = &self.runtime {
            runtime.charge(Resource::QueryWorkBytes, bytes)?;
        }
        self.step("buffer_admission", 1)
    }
    pub fn charge_cell(&mut self, bytes: u64) -> MddResult<()> {
        if bytes > self.limits.max_cell_bytes {
            return Err(self.stop(
                quota("MAX_CELL_BYTES")
                    .detail("budget", "cell_bytes")
                    .detail("limit", self.limits.max_cell_bytes.to_string())
                    .detail("observed", bytes.to_string()),
            ));
        }
        self.charge(bytes)
    }
    pub fn charge_row(&mut self, row: &Row) -> MddResult<()> {
        self.charge(
            (std::mem::size_of::<Row>() as u64)
                .checked_add(row.len() as u64 * std::mem::size_of::<Value>() as u64)
                .ok_or_else(|| quota("ROW_SIZE_OVERFLOW"))?,
        )?;
        for cell in row {
            self.charge_cell(cell.byte_size())?;
        }
        Ok(())
    }
    fn scanned(&mut self) -> MddResult<()> {
        self.scanned = self
            .scanned
            .checked_add(1)
            .ok_or_else(|| quota("SCAN_OVERFLOW"))?;
        self.step("scan_row", 1)
    }
}
fn quota(reason: &str) -> MddError {
    MddError::new(ErrorCode::QuotaExceeded, "query.execute", reason).detail("reason", reason)
}

#[derive(Clone, Debug, Serialize)]
pub struct NodePlan {
    pub node_id: DecimalU64,
    pub operator: String,
    pub input_schemas: Vec<Schema>,
    pub output_schema: Schema,
    pub required_layers: Vec<FactLayer>,
    pub text_semantics: String,
    pub candidate_access: String,
    pub deterministic_order: bool,
}
/// Prepared plans cannot have their checked schema or required layers altered by an SDK caller.
/// ```compile_fail
/// fn forge(mut plan: mdd_query::executor::PreparedQuery) { plan.required_layers.clear(); }
/// ```
#[derive(Clone, Serialize)]
pub struct PreparedQuery {
    query: QueryIr,
    source_identity: String,
    output_schema: Schema,
    required_layers: BTreeSet<FactLayer>,
    nodes: Vec<NodePlan>,
}
impl PreparedQuery {
    pub fn runtime_binding(&self) -> MddResult<mdd_session::QueryBinding> {
        let request = serde_json::to_vec(
            &serde_json::json!({"source_identity":self.source_identity,"query":self.query}),
        )
        .map_err(|_| invalid("QUERY_BINDING_ENCODING"))?;
        let schema = serde_json::to_vec(&self.output_schema)
            .map_err(|_| invalid("SCHEMA_BINDING_ENCODING"))?;
        Ok(mdd_session::QueryBinding {
            request_key: mdd_types::sha256(&request),
            schema_id: format!("mdd.rows.v1:{}", mdd_types::sha256(&schema)),
            semantic_version: format!("{IR_VERSION};{TEXT_VERSION}"),
        })
    }
    pub fn schema(&self) -> &Schema {
        &self.output_schema
    }
    pub fn nodes(&self) -> &[NodePlan] {
        &self.nodes
    }
    pub fn required_layers(&self) -> &BTreeSet<FactLayer> {
        &self.required_layers
    }
    pub fn snapshot_id(&self) -> &str {
        &self.query.snapshot_id
    }
    pub fn catalog_epoch(&self) -> DecimalU64 {
        self.query.catalog_epoch
    }
}
fn expr_layers(
    expr: &Expr,
    layers: &mut BTreeSet<FactLayer>,
    source: &dyn FactSource,
    depth: usize,
) -> MddResult<()> {
    if depth > 64 {
        return Err(invalid("EXPRESSION_DEPTH_LIMIT"));
    }
    match expr {
        Expr::Column { .. } => (),
        Expr::Literal { value } => {
            value.validate(source.snapshot_id())?;
            if let Value::Entity(entity) = value {
                source.validate_entity(entity)?;
            }
            if value.byte_size() > 1024 * 1024 {
                return Err(invalid("LITERAL_CELL_LIMIT"));
            }
        }
        Expr::ReadCodeBytes {
            entity,
            byte_offset,
            byte_length,
        } => {
            if let Some(length) = byte_length {
                byte_offset
                    .0
                    .checked_add(length.0)
                    .ok_or_else(|| invalid("CODE_RANGE_OVERFLOW"))?;
            }
            if let Expr::Literal {
                value: Value::Entity(entity),
            } = entity.as_ref()
                && entity.kind != mdd_facts::EntityKind::MethodDefinition
            {
                return Err(invalid("CODE_DEFINITION_REQUIRED"));
            }
            layers.insert(FactLayer::CodeLayout);
            layers.insert(FactLayer::Structure);
            expr_layers(entity, layers, source, depth + 1)?;
        }
    }
    Ok(())
}
fn predicate_layers(
    p: &Predicate,
    layers: &mut BTreeSet<FactLayer>,
    source: &dyn FactSource,
    depth: usize,
) -> MddResult<()> {
    if depth > 64 {
        return Err(invalid("PREDICATE_DEPTH_LIMIT"));
    }
    match p {
        Predicate::Eq { left, right } | Predicate::RawBytesEq { left, right } => {
            expr_layers(left, layers, source, 0)?;
            expr_layers(right, layers, source, 0)?;
        }
        Predicate::Prefix { value, .. }
        | Predicate::Like { value, .. }
        | Predicate::IsNull { value } => expr_layers(value, layers, source, 0)?,
        Predicate::And { left, right } | Predicate::Or { left, right } => {
            predicate_layers(left, layers, source, depth + 1)?;
            predicate_layers(right, layers, source, depth + 1)?;
        }
        Predicate::Not { value } => predicate_layers(value, layers, source, depth + 1)?,
    }
    Ok(())
}
struct Checked {
    schema: Schema,
    layers: BTreeSet<FactLayer>,
    ordered: bool,
}
struct Preparer<'a> {
    source: &'a dyn FactSource,
    nodes: Vec<NodePlan>,
    visited: usize,
}
impl Preparer<'_> {
    fn node(&mut self, node: &Node, depth: usize) -> MddResult<Checked> {
        self.visited += 1;
        if self.visited > 1024 || depth > 64 {
            return Err(invalid("PLAN_SIZE_LIMIT"));
        }
        let mut inputs = Vec::new();
        let mut layers = BTreeSet::new();
        let mut ordered = false;
        let (schema, op, access) = match node {
            Node::Scan { relation } => {
                let s = self.source.relation_schema(relation)?;
                layers.extend(s.required_layers);
                (s.columns, "scan", "full_scan")
            }
            Node::SelectIds {
                input,
                ordinal,
                ids,
            } => {
                let s = self.node(input, depth + 1)?;
                let c = s
                    .schema
                    .get(*ordinal)
                    .ok_or_else(|| invalid("COLUMN_ORDINAL"))?;
                if !matches!(
                    c.data_type,
                    DataType::I64 | DataType::U64 | DataType::Entity
                ) {
                    return Err(invalid("ID_COLUMN_TYPE"));
                }
                if ids.len() > 4096 {
                    return Err(invalid("ID_SET_LIMIT"));
                }
                for id in ids {
                    id.validate(self.source.snapshot_id())?;
                    if let Value::Entity(entity) = id {
                        self.source.validate_entity(entity)?;
                    }
                    if id.data_type() != Some(c.data_type) {
                        return Err(invalid("ID_SET_TYPE"));
                    }
                }
                inputs.push(s.schema.clone());
                layers = s.layers;
                ordered = s.ordered;
                (s.schema, "select_ids", "full_scan_then_exact_membership")
            }
            Node::Filter { input, predicate } => {
                let s = self.node(input, depth + 1)?;
                operators::check_predicate(predicate, &s.schema, 0)?;
                layers = s.layers;
                predicate_layers(predicate, &mut layers, self.source, 0)?;
                ordered = s.ordered;
                inputs.push(s.schema.clone());
                (s.schema, "filter", "exact_predicate_no_index_omit")
            }
            Node::Project { input, columns } => {
                let s = self.node(input, depth + 1)?;
                ordered = s.ordered;
                layers = s.layers;
                let mut output = Vec::new();
                for projection in columns {
                    let (data_type, nullable) =
                        operators::expression_type(&projection.expression, &s.schema, 0)?;
                    if data_type.is_some_and(|v| v != projection.column.data_type)
                        || nullable && !projection.column.nullable
                    {
                        return Err(invalid("PROJECTION_TYPE_OR_NULLABILITY"));
                    }
                    expr_layers(&projection.expression, &mut layers, self.source, 0)?;
                    output.push(projection.column.clone());
                }
                inputs.push(s.schema);
                (output, "project", "ordinal_projection")
            }
            Node::EquiJoin {
                left,
                right,
                left_keys,
                right_keys,
                kind,
            } => {
                let a = self.node(left, depth + 1)?;
                let b = self.node(right, depth + 1)?;
                if left_keys.is_empty() || left_keys.len() != right_keys.len() {
                    return Err(invalid("JOIN_KEYS"));
                }
                for (left, right) in left_keys.iter().zip(right_keys) {
                    if a.schema
                        .get(*left)
                        .ok_or_else(|| invalid("JOIN_KEY_ORDINAL"))?
                        .data_type
                        != b.schema
                            .get(*right)
                            .ok_or_else(|| invalid("JOIN_KEY_ORDINAL"))?
                            .data_type
                    {
                        return Err(invalid("JOIN_KEY_TYPE"));
                    }
                }
                layers.extend(a.layers);
                layers.extend(b.layers);
                let mut output = a.schema.clone();
                let mut ids: BTreeSet<String> = output.iter().map(|v| v.id.clone()).collect();
                for mut column in b.schema.clone() {
                    while ids.contains(&column.id) {
                        column.id = format!("right.{}", column.id);
                    }
                    ids.insert(column.id.clone());
                    if *kind == JoinKind::Left {
                        column.nullable = true;
                    }
                    output.push(column);
                }
                inputs.extend([a.schema, b.schema]);
                (
                    output,
                    "equi_join",
                    "hash_candidates_then_exact_keys;reference_nested_loop",
                )
            }
            Node::Aggregate {
                input,
                group_by,
                aggregates,
            } => {
                let s = self.node(input, depth + 1)?;
                layers = s.layers;
                let mut output = Vec::new();
                if aggregates.is_empty() {
                    return Err(invalid("EMPTY_AGGREGATES"));
                }
                for ordinal in group_by {
                    output.push(
                        s.schema
                            .get(*ordinal)
                            .ok_or_else(|| invalid("GROUP_ORDINAL"))?
                            .clone(),
                    );
                }
                for aggregate in aggregates {
                    let t = aggregate
                        .ordinal
                        .map(|v| s.schema.get(v).ok_or_else(|| invalid("AGGREGATE_ORDINAL")))
                        .transpose()?;
                    let (data_type, nullable) = match aggregate.kind {
                        AggregateKind::CountStar => {
                            if t.is_some() {
                                return Err(invalid("COUNT_STAR_ORDINAL"));
                            }
                            (DataType::U64, false)
                        }
                        AggregateKind::Count => {
                            if t.is_none() {
                                return Err(invalid("COUNT_ORDINAL_REQUIRED"));
                            }
                            (DataType::U64, false)
                        }
                        AggregateKind::Sum => {
                            let dtype = t.ok_or_else(|| invalid("SUM_ORDINAL_REQUIRED"))?.data_type;
                            if !matches!(dtype, DataType::I64 | DataType::U64) {
                                return Err(invalid("SUM_NUMERIC_TYPE"));
                            }
                            (dtype, true)
                        }
                        AggregateKind::Min | AggregateKind::Max => (
                            t.ok_or_else(|| invalid("AGGREGATE_ORDINAL_REQUIRED"))?
                                .data_type,
                            true,
                        ),
                    };
                    if aggregate.column.data_type != data_type
                        || aggregate.column.nullable != nullable
                    {
                        return Err(invalid("AGGREGATE_OUTPUT_TYPE"));
                    }
                    output.push(aggregate.column.clone());
                }
                inputs.push(s.schema);
                (output, "aggregate", "group_bag_preserve_multiplicity")
            }
            Node::Order { input, keys } => {
                let s = self.node(input, depth + 1)?;
                if keys.is_empty() {
                    return Err(invalid("EMPTY_ORDER_KEYS"));
                }
                let mut ordinals = BTreeSet::new();
                for key in keys {
                    if key.ordinal >= s.schema.len() || !ordinals.insert(key.ordinal) {
                        return Err(invalid("ORDER_KEY_ORDINAL"));
                    }
                }
                ordered = ordinals.len() == s.schema.len();
                layers = s.layers;
                inputs.push(s.schema.clone());
                (
                    s.schema,
                    "order",
                    "controlled_stable_merge;reference_insertion",
                )
            }
            Node::Limit {
                input,
                offset,
                count,
            } => {
                offset
                    .0
                    .checked_add(count.0)
                    .ok_or_else(|| invalid("LIMIT_RANGE_OVERFLOW"))?;
                let s = self.node(input, depth + 1)?;
                ordered = s.ordered;
                layers = s.layers;
                inputs.push(s.schema.clone());
                (s.schema, "limit", "relation_limit_not_response_paging")
            }
        };
        validate_schema(&schema)?;
        self.nodes.push(NodePlan {
            node_id: DecimalU64(self.nodes.len() as u64),
            operator: op.into(),
            input_schemas: inputs,
            output_schema: schema.clone(),
            required_layers: layers.iter().copied().collect(),
            text_semantics: TEXT_VERSION.into(),
            candidate_access: access.into(),
            deterministic_order: ordered,
        });
        Ok(Checked {
            schema,
            layers,
            ordered,
        })
    }
}
pub fn prepare(query: QueryIr, source: &dyn FactSource) -> MddResult<PreparedQuery> {
    if query.schema_version != IR_VERSION || query.text_semantics != TEXT_VERSION {
        return Err(invalid("IR_OR_TEXT_VERSION"));
    }
    if query.snapshot_id != source.snapshot_id() || query.catalog_epoch != source.catalog_epoch() {
        return Err(invalid("SNAPSHOT_OR_CATALOG_GENERATION"));
    }
    let mut preparer = Preparer {
        source,
        nodes: Vec::new(),
        visited: 0,
    };
    let checked = preparer.node(&query.root, 0)?;
    if query.require_stable_order && !checked.ordered {
        return Err(invalid("TOTAL_ORDER_REQUIRED"));
    }
    source.require_layers(&checked.layers)?;
    Ok(PreparedQuery {
        query,
        source_identity: source.identity().into(),
        output_schema: checked.schema,
        required_layers: checked.layers,
        nodes: preparer.nodes,
    })
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    Streaming,
    MaterializedReference,
}
/// Complete query output owns an immutable result. Delivery status belongs to the later transport.
/// ```compile_fail
/// fn forge(mut output: mdd_query::executor::QueryOutput) { output.rows.clear(); }
/// ```
#[derive(Serialize)]
pub struct QueryOutput {
    snapshot_id: String,
    catalog_epoch: DecimalU64,
    schema: Schema,
    rows: Vec<Row>,
    mode: ExecutionMode,
    execution_complete: bool,
    steps: DecimalU64,
    scanned_rows: DecimalU64,
    admitted_buffer_bytes: DecimalU64,
    ordering: &'static str,
}
impl QueryOutput {
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }
    pub fn schema(&self) -> &Schema {
        &self.schema
    }
    pub fn execution_complete(&self) -> bool {
        self.execution_complete
    }
}

enum Cursor<'a> {
    Scan {
        rows: Box<dyn Iterator<Item = MddResult<Row>> + 'a>,
        schema: Schema,
    },
    Select {
        input: Box<Cursor<'a>>,
        ordinal: usize,
        ids: BTreeSet<Value>,
    },
    Filter {
        input: Box<Cursor<'a>>,
        predicate: &'a Predicate,
    },
    Project {
        input: Box<Cursor<'a>>,
        columns: &'a [Projection],
    },
    Join {
        left: Box<Cursor<'a>>,
        right: BTreeMap<Vec<Value>, Vec<Row>>,
        left_keys: &'a [usize],
        right_width: usize,
        kind: JoinKind,
        pending: std::vec::IntoIter<Row>,
    },
    Limit {
        input: Box<Cursor<'a>>,
        offset: u64,
        remaining: u64,
    },
    Rows(std::vec::IntoIter<Row>),
}
fn key(row: &Row, ordinals: &[usize]) -> Vec<Value> {
    ordinals.iter().map(|i| row[*i].clone()).collect()
}
fn null_key(key: &[Value]) -> bool {
    key.contains(&Value::Null)
}

/// Logical bytes owned by a queued Row, including spare capacity. This is not allocator
/// overhead or an operating-system RSS measurement; the provider has already produced it.
fn queued_row_resident_bytes(row: &Row) -> MddResult<u64> {
    fn count(value: usize) -> MddResult<u64> {
        u64::try_from(value).map_err(|_| quota("QUEUE_ROW_SIZE_OVERFLOW"))
    }
    fn add(total: u64, value: u64) -> MddResult<u64> {
        total
            .checked_add(value)
            .ok_or_else(|| quota("QUEUE_ROW_SIZE_OVERFLOW"))
    }
    let slots = count(row.capacity())?
        .checked_mul(count(std::mem::size_of::<Value>())?)
        .ok_or_else(|| quota("QUEUE_ROW_SIZE_OVERFLOW"))?;
    let mut total = add(count(std::mem::size_of::<Row>())?, slots)?;
    for value in row {
        let inner = match value {
            Value::Utf16(text) => count(text.capacity())?
                .checked_mul(count(std::mem::size_of::<u16>())?)
                .ok_or_else(|| quota("QUEUE_ROW_SIZE_OVERFLOW"))?,
            Value::Bytes(bytes) => count(bytes.0.capacity())?,
            Value::Entity(entity) => add(
                count(entity.snapshot_id.capacity())?,
                count(entity.dex_occurrence_id.capacity())?,
            )?,
            Value::Null | Value::Bool(_) | Value::I64(_) | Value::U64(_) => 0,
        };
        total = add(total, inner)?;
    }
    Ok(total)
}

// Only the fixed serde_json writer path is qualified here. Other serializers may choose
// to allocate when they implement `collect_str`; the public Value serializer is unchanged.
struct StreamingBase64<'a>(&'a [u8]);
impl fmt::Display for StreamingBase64<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for block in self.0.chunks(3) {
            let bits = (u32::from(block[0]) << 16)
                | (u32::from(*block.get(1).unwrap_or(&0)) << 8)
                | u32::from(*block.get(2).unwrap_or(&0));
            let quad = [
                ALPHABET[((bits >> 18) & 63) as usize],
                ALPHABET[((bits >> 12) & 63) as usize],
                if block.len() > 1 {
                    ALPHABET[((bits >> 6) & 63) as usize]
                } else {
                    b'='
                },
                if block.len() > 2 {
                    ALPHABET[(bits & 63) as usize]
                } else {
                    b'='
                },
            ];
            formatter.write_str(std::str::from_utf8(&quad).map_err(|_| fmt::Error)?)?;
        }
        Ok(())
    }
}
struct StreamingBytes<'a>(&'a [u8]);
impl Serialize for StreamingBytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&StreamingBase64(self.0))
    }
}
struct StreamingText<'a>(&'a str);
impl fmt::Display for StreamingText<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut start = 0;
        while start < self.0.len() {
            let mut end = start.saturating_add(1024).min(self.0.len());
            while !self.0.is_char_boundary(end) {
                end -= 1;
            }
            formatter.write_str(&self.0[start..end])?;
            start = end;
        }
        Ok(())
    }
}
impl Serialize for StreamingText<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
struct StreamingEntity<'a>(&'a mdd_facts::EntityRef);
impl Serialize for StreamingEntity<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut entity = serializer.serialize_struct("EntityRef", 4)?;
        entity.serialize_field("snapshot_id", &StreamingText(&self.0.snapshot_id))?;
        entity.serialize_field(
            "dex_occurrence_id",
            &StreamingText(&self.0.dex_occurrence_id),
        )?;
        entity.serialize_field("kind", &self.0.kind)?;
        entity.serialize_field("local_index", &self.0.local_index)?;
        entity.end()
    }
}
struct StreamingValue<'a>(&'a Value);
impl Serialize for StreamingValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Bytes(bytes) => {
                let mut value = serializer.serialize_struct("Value", 2)?;
                value.serialize_field("type", "bytes")?;
                value.serialize_field("value", &StreamingBytes(&bytes.0))?;
                value.end()
            }
            Value::Entity(entity) => {
                let mut value = serializer.serialize_struct("Value", 2)?;
                value.serialize_field("type", "entity")?;
                value.serialize_field("value", &StreamingEntity(entity))?;
                value.end()
            }
            value => value.serialize(serializer),
        }
    }
}
struct StreamingRow<'a>(&'a [Value]);
impl Serialize for StreamingRow<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for value in self.0 {
            sequence.serialize_element(&StreamingValue(value))?;
        }
        sequence.end()
    }
}

struct RowCountWriter<'a, 'control> {
    control: &'a mut Control<'control>,
    runtime: &'a RuntimeBudget,
    count: u64,
    observed_cap: u64,
    failure: Option<MddError>,
}
impl Write for RowCountWriter<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let attempt = (|| {
            self.control.step("json_count", 1)?;
            let amount = u64::try_from(bytes.len()).map_err(|_| quota("OUTPUT_SIZE_OVERFLOW"))?;
            let next = self
                .count
                .checked_add(amount)
                .ok_or_else(|| quota("OUTPUT_SIZE_OVERFLOW"))?;
            if next > self.observed_cap {
                // `remaining` is only a snapshot. A concurrent Admission may release its
                // reservation, so recheck under the budget lock before reporting quota.
                self.runtime
                    .pool()
                    .check_cumulative(Resource::OutputBytes, next)
                    .map_err(|error| {
                        error
                            .detail("encoded_prefix_bytes", self.count.to_string())
                            .detail("attempted_prefix_bytes", next.to_string())
                            .detail("encoded_length_exact", false)
                    })?;
                self.observed_cap = next;
            }
            self.count = next;
            Ok::<(), MddError>(())
        })();
        if let Err(error) = attempt {
            self.failure = Some(error);
            return Err(io::Error::other("bounded JSON count stopped"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn count_serialized<T: Serialize>(
    value: &T,
    control: &mut Control<'_>,
    runtime: &RuntimeBudget,
) -> MddResult<u64> {
    let cap = runtime.pool().remaining(Resource::OutputBytes)?;
    let mut writer = RowCountWriter {
        control,
        runtime,
        count: 0,
        observed_cap: cap,
        failure: None,
    };
    let result = serde_json::to_writer(&mut writer, value);
    if let Some(error) = writer.failure.take() {
        return Err(error);
    }
    result
        .map_err(|error| invalid("ROW_ENCODING").detail("serializer_error", error.to_string()))?;
    Ok(writer.count)
}

fn count_wire_row(row: &Row, control: &mut Control<'_>, runtime: &RuntimeBudget) -> MddResult<u64> {
    count_serialized(&StreamingRow(row), control, runtime)
}
impl Cursor<'_> {
    fn next(
        &mut self,
        source: &dyn FactSource,
        control: &mut Control<'_>,
    ) -> MddResult<Option<Row>> {
        control.step("operator_next", 1)?;
        match self {
            Self::Scan { rows, schema } => {
                if let Some(row) = rows.next() {
                    let row = row?;
                    validate_row(&row, schema, source.snapshot_id())?;
                    control.scanned()?;
                    control.charge_row(&row)?;
                    Ok(Some(row))
                } else {
                    Ok(None)
                }
            }
            Self::Select {
                input,
                ordinal,
                ids,
            } => {
                while let Some(row) = input.next(source, control)? {
                    control.step("id_membership", 1)?;
                    if ids.contains(&row[*ordinal]) {
                        return Ok(Some(row));
                    }
                }
                Ok(None)
            }
            Self::Filter { input, predicate } => {
                while let Some(row) = input.next(source, control)? {
                    if operators::predicate(predicate, &row, source, control, false)? == Truth::True
                    {
                        return Ok(Some(row));
                    }
                }
                Ok(None)
            }
            Self::Project { input, columns } => {
                let Some(row) = input.next(source, control)? else {
                    return Ok(None);
                };
                let result = columns
                    .iter()
                    .map(|p| operators::expression(&p.expression, &row, source, control))
                    .collect::<MddResult<Row>>()?;
                control.charge_row(&result)?;
                Ok(Some(result))
            }
            Self::Limit {
                input,
                offset,
                remaining,
            } => {
                if *remaining == 0 {
                    return Ok(None);
                }
                while *offset > 0 {
                    if input.next(source, control)?.is_none() {
                        *remaining = 0;
                        return Ok(None);
                    }
                    *offset -= 1;
                }
                let row = input.next(source, control)?;
                if row.is_some() {
                    *remaining -= 1;
                }
                Ok(row)
            }
            Self::Rows(rows) => Ok(rows.next()),
            Self::Join {
                left,
                right,
                left_keys,
                right_width,
                kind,
                pending,
            } => loop {
                if let Some(row) = pending.next() {
                    return Ok(Some(row));
                }
                let Some(row) = left.next(source, control)? else {
                    return Ok(None);
                };
                let keys = key(&row, left_keys);
                let matches = if null_key(&keys) {
                    None
                } else {
                    right.get(&keys)
                };
                let mut values = Vec::new();
                if let Some(matches) = matches {
                    for r in matches {
                        control.step("join_match", 1)?;
                        let mut joined = row.clone();
                        joined.extend(r.clone());
                        control.charge_row(&joined)?;
                        values.push(joined);
                    }
                } else if *kind == JoinKind::Left {
                    let mut joined = row;
                    joined.extend(std::iter::repeat_n(Value::Null, *right_width));
                    control.charge_row(&joined)?;
                    values.push(joined);
                }
                *pending = values.into_iter();
            },
        }
    }
}
fn collect(
    cursor: &mut Cursor<'_>,
    source: &dyn FactSource,
    control: &mut Control<'_>,
) -> MddResult<Vec<Row>> {
    let mut rows = Vec::new();
    while let Some(row) = cursor.next(source, control)? {
        rows.push(row);
    }
    Ok(rows)
}

fn aggregate_values(
    rows: &[&Row],
    aggregates: &[Aggregate],
    control: &mut Control<'_>,
) -> MddResult<Row> {
    let mut output = Vec::new();
    for aggregate in aggregates {
        let mut count = 0u64;
        let mut value = Value::Null;
        for row in rows {
            control.step("aggregate_value", 1)?;
            let item = aggregate.ordinal.map(|i| &row[i]);
            match aggregate.kind {
                AggregateKind::CountStar => {
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| invalid("COUNT_OVERFLOW"))?;
                }
                AggregateKind::Count => {
                    if item != Some(&Value::Null) {
                        count = count
                            .checked_add(1)
                            .ok_or_else(|| invalid("COUNT_OVERFLOW"))?;
                    }
                }
                AggregateKind::Sum => {
                    let Some(item) = item else {
                        return Err(invalid("SUM_ORDINAL_REQUIRED"));
                    };
                    if item == &Value::Null {
                        continue;
                    }
                    value = match (&value, item) {
                        (Value::Null, v) => v.clone(),
                        (Value::I64(a), Value::I64(b)) => Value::I64(Signed64(
                            a.0.checked_add(b.0)
                                .ok_or_else(|| invalid("SUM_OVERFLOW"))?,
                        )),
                        (Value::U64(a), Value::U64(b)) => Value::U64(DecimalU64(
                            a.0.checked_add(b.0)
                                .ok_or_else(|| invalid("SUM_OVERFLOW"))?,
                        )),
                        _ => return Err(invalid("SUM_NUMERIC_TYPE")),
                    };
                }
                AggregateKind::Min | AggregateKind::Max => {
                    let Some(item) = item else {
                        return Err(invalid("AGGREGATE_ORDINAL_REQUIRED"));
                    };
                    if item == &Value::Null {
                        continue;
                    }
                    if value == Value::Null
                        || (aggregate.kind == AggregateKind::Min && item < &value)
                        || (aggregate.kind == AggregateKind::Max && item > &value)
                    {
                        value = item.clone();
                    }
                }
            }
        }
        output.push(
            if matches!(
                aggregate.kind,
                AggregateKind::Count | AggregateKind::CountStar
            ) {
                Value::U64(DecimalU64(count))
            } else {
                value
            },
        );
    }
    Ok(output)
}
fn aggregate(
    rows: Vec<Row>,
    group_by: &[usize],
    aggregates: &[Aggregate],
    control: &mut Control<'_>,
    reference: bool,
) -> MddResult<Vec<Row>> {
    let mut groups: Vec<(Vec<Value>, Vec<&Row>)> = Vec::new();
    if reference {
        for row in &rows {
            let k = key(row, group_by);
            let mut index = None;
            for (at, (known, _)) in groups.iter().enumerate() {
                control.step("reference_group_compare", 1)?;
                if *known == k {
                    index = Some(at);
                    break;
                }
            }
            match index {
                Some(i) => groups[i].1.push(row),
                None => groups.push((k, vec![row])),
            }
        }
        groups.sort_by(|a, b| a.0.cmp(&b.0));
    } else {
        let mut map: BTreeMap<Vec<Value>, Vec<&Row>> = BTreeMap::new();
        for row in &rows {
            control.step("group_candidate", 1)?;
            map.entry(key(row, group_by)).or_default().push(row);
        }
        groups.extend(map);
    }
    if group_by.is_empty() && groups.is_empty() {
        groups.push((Vec::new(), Vec::new()));
    }
    let mut output = Vec::new();
    for (mut group, rows) in groups {
        group.extend(aggregate_values(&rows, aggregates, control)?);
        control.charge_row(&group)?;
        output.push(group);
    }
    Ok(output)
}
fn cursor<'a>(
    node: &'a Node,
    source: &'a dyn FactSource,
    control: &mut Control<'_>,
) -> MddResult<Cursor<'a>> {
    Ok(match node {
        Node::Scan { relation } => Cursor::Scan {
            rows: source.scan(relation)?,
            schema: source.relation_schema(relation)?.columns,
        },
        Node::SelectIds {
            input,
            ordinal,
            ids,
        } => Cursor::Select {
            input: Box::new(cursor(input, source, control)?),
            ordinal: *ordinal,
            ids: ids.iter().cloned().collect(),
        },
        Node::Filter { input, predicate } => Cursor::Filter {
            input: Box::new(cursor(input, source, control)?),
            predicate,
        },
        Node::Project { input, columns } => Cursor::Project {
            input: Box::new(cursor(input, source, control)?),
            columns,
        },
        Node::Limit {
            input,
            offset,
            count,
        } => Cursor::Limit {
            input: Box::new(cursor(input, source, control)?),
            offset: offset.0,
            remaining: count.0,
        },
        Node::Order { input, keys } => {
            let rows = collect(&mut cursor(input, source, control)?, source, control)?;
            Cursor::Rows(operators::order_rows(rows, keys, control, false)?.into_iter())
        }
        Node::Aggregate {
            input,
            group_by,
            aggregates,
        } => {
            let rows = collect(&mut cursor(input, source, control)?, source, control)?;
            Cursor::Rows(aggregate(rows, group_by, aggregates, control, false)?.into_iter())
        }
        Node::EquiJoin {
            left,
            right,
            left_keys,
            right_keys,
            kind,
        } => {
            let mut groups: BTreeMap<Vec<Value>, Vec<Row>> = BTreeMap::new();
            let mut right = cursor(right, source, control)?;
            let mut width = None;
            while let Some(row) = right.next(source, control)? {
                width = Some(row.len());
                let key = key(&row, right_keys);
                if !null_key(&key) {
                    control.charge_row(&key)?;
                    groups.entry(key).or_default().push(row);
                }
            }
            let right_width = match width {
                Some(v) => v,
                None => {
                    let mut p = Preparer {
                        source,
                        nodes: Vec::new(),
                        visited: 0,
                    };
                    p.node(
                        match node {
                            Node::EquiJoin { right, .. } => right,
                            _ => unreachable!(),
                        },
                        0,
                    )?
                    .schema
                    .len()
                }
            };
            Cursor::Join {
                left: Box::new(cursor(left, source, control)?),
                right: groups,
                left_keys,
                right_width,
                kind: *kind,
                pending: Vec::new().into_iter(),
            }
        }
    })
}
fn reference(
    node: &Node,
    source: &dyn FactSource,
    control: &mut Control<'_>,
) -> MddResult<Vec<Row>> {
    control.step("reference_node", 1)?;
    match node {
        Node::Scan { relation } => {
            let schema = source.relation_schema(relation)?.columns;
            let mut rows = Vec::new();
            for row in source.scan(relation)? {
                let row = row?;
                validate_row(&row, &schema, source.snapshot_id())?;
                control.scanned()?;
                control.charge_row(&row)?;
                rows.push(row);
            }
            Ok(rows)
        }
        Node::SelectIds {
            input,
            ordinal,
            ids,
        } => {
            let mut out = Vec::new();
            for row in reference(input, source, control)? {
                let mut found = false;
                for id in ids {
                    control.step("reference_membership", 1)?;
                    if row[*ordinal] == *id {
                        found = true;
                        break;
                    }
                }
                if found {
                    out.push(row);
                }
            }
            Ok(out)
        }
        Node::Filter { input, predicate } => {
            let mut out = Vec::new();
            for row in reference(input, source, control)? {
                if operators::predicate(predicate, &row, source, control, true)? == Truth::True {
                    out.push(row);
                }
            }
            Ok(out)
        }
        Node::Project { input, columns } => {
            let mut out = Vec::new();
            for row in reference(input, source, control)? {
                let row = columns
                    .iter()
                    .map(|p| operators::expression(&p.expression, &row, source, control))
                    .collect::<MddResult<Row>>()?;
                control.charge_row(&row)?;
                out.push(row);
            }
            Ok(out)
        }
        Node::Order { input, keys } => {
            operators::order_rows(reference(input, source, control)?, keys, control, true)
        }
        Node::Aggregate {
            input,
            group_by,
            aggregates,
        } => aggregate(
            reference(input, source, control)?,
            group_by,
            aggregates,
            control,
            true,
        ),
        Node::Limit {
            input,
            offset,
            count,
        } => {
            let rows = reference(input, source, control)?;
            Ok(rows
                .into_iter()
                .skip(usize::try_from(offset.0).unwrap_or(usize::MAX))
                .take(usize::try_from(count.0).unwrap_or(usize::MAX))
                .collect())
        }
        Node::EquiJoin {
            left,
            right,
            left_keys,
            right_keys,
            kind,
        } => {
            let left = reference(left, source, control)?;
            let right_rows = reference(right, source, control)?;
            let mut p = Preparer {
                source,
                nodes: Vec::new(),
                visited: 0,
            };
            let width = p.node(right, 0)?.schema.len();
            let mut out = Vec::new();
            for left in left {
                let mut matched = false;
                for right in &right_rows {
                    control.step("reference_join_pair", 1)?;
                    let mut equal = true;
                    for (a, b) in left_keys.iter().zip(right_keys) {
                        if left[*a] == Value::Null
                            || right[*b] == Value::Null
                            || left[*a] != right[*b]
                        {
                            equal = false;
                            break;
                        }
                    }
                    if equal {
                        matched = true;
                        let mut row = left.clone();
                        row.extend(right.clone());
                        control.charge_row(&row)?;
                        out.push(row);
                    }
                }
                if !matched && *kind == JoinKind::Left {
                    let mut row = left;
                    row.extend(std::iter::repeat_n(Value::Null, width));
                    control.charge_row(&row)?;
                    out.push(row);
                }
            }
            Ok(out)
        }
    }
}
fn execute_materialized_sdk(
    prepared: &PreparedQuery,
    source: &dyn FactSource,
    mode: ExecutionMode,
    control: &mut Control<'_>,
) -> MddResult<QueryOutput> {
    let bound = || {
        prepared.source_identity == source.identity()
            && prepared.query.snapshot_id == source.snapshot_id()
            && prepared.query.catalog_epoch == source.catalog_epoch()
    };
    if !bound() {
        return Err(invalid("PREPARED_SOURCE_OR_GENERATION_CHANGED"));
    }
    source.require_layers(&prepared.required_layers)?;
    control.step("execute_start", 1)?;
    let rows = match mode {
        ExecutionMode::Streaming => collect(
            &mut cursor(&prepared.query.root, source, control)?,
            source,
            control,
        )?,
        ExecutionMode::MaterializedReference => reference(&prepared.query.root, source, control)?,
    };
    if rows.len() as u64 > control.limits.max_output_rows {
        return Err(quota("MAX_OUTPUT_ROWS")
            .detail("budget", "output_rows")
            .detail("limit", control.limits.max_output_rows.to_string())
            .detail("observed", rows.len().to_string()));
    }
    for row in &rows {
        validate_row(row, &prepared.output_schema, source.snapshot_id())?;
        control.step("output_row", 1)?;
    }
    if !bound() {
        return Err(invalid("PREPARED_SOURCE_OR_GENERATION_CHANGED"));
    }
    control.step("execution_complete", 1)?;
    Ok(QueryOutput {
        snapshot_id: source.snapshot_id().into(),
        catalog_epoch: source.catalog_epoch(),
        schema: prepared.output_schema.clone(),
        rows,
        mode,
        execution_complete: true,
        steps: DecimalU64(control.steps),
        scanned_rows: DecimalU64(control.scanned),
        admitted_buffer_bytes: DecimalU64(control.buffered),
        ordering: if prepared.nodes.last().is_some_and(|n| n.deterministic_order) {
            "total_native_order"
        } else {
            "unspecified"
        },
    })
}

fn runtime_begin(prepared: &PreparedQuery, control: &Control<'_>) -> MddResult<()> {
    if let Some(runtime) = &control.runtime {
        let cancel = runtime.cancellation();
        let binding = cancel.binding()?;
        let expected = prepared.runtime_binding()?;
        if cancel.snapshot_id()? != prepared.snapshot_id()
            || cancel.status()?.catalog_epoch != prepared.catalog_epoch()
            || binding.request_key != expected.request_key
            || binding.schema_id != expected.schema_id
            || binding.semantic_version != expected.semantic_version
        {
            return Err(invalid("RUNTIME_QUERY_SNAPSHOT_GENERATION_OR_BINDING"));
        }
        cancel.claim_execution()?;
    }
    Ok(())
}
pub fn execute(
    prepared: &PreparedQuery,
    source: &dyn FactSource,
    mode: ExecutionMode,
    control: &mut Control<'_>,
) -> MddResult<QueryOutput> {
    runtime_begin(prepared, control)?;
    let result = execute_materialized_sdk(prepared, source, mode, control)
        .map_err(|error| control.stop(error))?;
    if let Some(runtime) = &control.runtime {
        runtime.cancellation().mark_computed()?;
        if let Some(error) = runtime.cancellation().status()?.error {
            return Err(error
                .detail("execution_complete", true)
                .detail("total_rows", result.rows.len().to_string()));
        }
    }
    Ok(result)
}

/// Test-only synchronous consumer for existing internal coverage. Production callers use the
/// query-bound queue and a receiver-issued delivery receipt.
#[cfg(test)]
fn execute_trusted_into(
    prepared: &PreparedQuery,
    source: &dyn FactSource,
    mode: ExecutionMode,
    control: &mut Control<'_>,
    mut terminal: mdd_types::result::TerminalBuilder,
    mut sink: impl FnMut(u64, &Row) -> MddResult<()>,
) -> MddResult<mdd_types::ResultEnvelope> {
    let binding = prepared.runtime_binding()?;
    let identity = terminal.identity();
    let mut expected: Vec<String> = prepared
        .required_layers
        .iter()
        .map(|layer| {
            serde_json::to_value(layer)
                .expect("enum serializes")
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    expected.sort();
    let mut actual = terminal.coverage().required_layers.clone();
    actual.sort();
    if identity.snapshot_id.as_deref() != Some(prepared.snapshot_id())
        || identity.catalog_epoch != Some(prepared.catalog_epoch())
        || identity.schema_id.as_deref() != Some(binding.schema_id.as_str())
        || actual != expected
    {
        return Err(invalid("TERMINAL_PLAN_BINDING"));
    }
    if prepared.source_identity != source.identity() {
        return Err(invalid("PREPARED_SOURCE_OR_GENERATION_CHANGED"));
    }
    if let Some(runtime) = &control.runtime {
        if identity.query_id.as_deref() != Some(runtime.cancellation().query_handle().id()) {
            return Err(invalid("TERMINAL_QUERY_ID"));
        }
        if identity.session_id.as_deref() != Some(runtime.cancellation().session_id()?.as_str()) {
            return Err(invalid("TERMINAL_SESSION_OWNER"));
        }
    }
    source.require_layers(&prepared.required_layers)?;
    runtime_begin(prepared, control)?;
    let runtime = control.runtime.clone();
    let mut dropped = false;
    let result = (|| {
        control.step("execute_start", 1)?;
        let mut input = match mode {
            ExecutionMode::Streaming => cursor(&prepared.query.root, source, control)?,
            ExecutionMode::MaterializedReference => {
                Cursor::Rows(reference(&prepared.query.root, source, control)?.into_iter())
            }
        };
        if let Cursor::Rows(rows) = &input {
            terminal.computation_complete(rows.len() as u64)?;
            if let Some(runtime) = &runtime {
                runtime.cancellation().mark_computed()?;
            }
        }
        let mut produced = 0u64;
        while let Some(row) = input.next(source, control)? {
            validate_row(&row, &prepared.output_schema, source.snapshot_id())?;
            if produced >= control.limits.max_output_rows {
                dropped = true;
                return Err(quota("MAX_OUTPUT_ROWS")
                    .detail("budget", "output_rows")
                    .detail("limit", control.limits.max_output_rows.to_string())
                    .detail(
                        "observed",
                        produced
                            .checked_add(1)
                            .map_or("overflow".into(), |n| n.to_string()),
                    ));
            }
            let encoded = serde_json::to_vec(&row).map_err(|_| invalid("ROW_ENCODING"))?;
            if let Some(runtime) = &runtime
                && let Err(error) = runtime.charge(Resource::OutputBytes, encoded.len() as u64)
            {
                dropped = true;
                return Err(error);
            }
            control.step("output_row", 1)?;
            if let Err(error) = sink(produced, &row) {
                dropped = true;
                return Err(error);
            }
            terminal.record_batch(produced, 1)?;
            produced = produced
                .checked_add(1)
                .ok_or_else(|| quota("OUTPUT_ROW_OVERFLOW"))?;
        }
        if !terminal.execution_complete() {
            terminal.computation_complete(produced)?;
            if let Some(runtime) = &runtime {
                runtime.cancellation().mark_computed()?;
            }
        }
        if let Some(runtime) = &runtime {
            runtime.cancellation().finish_delivery()?;
        }
        Ok::<_, MddError>(())
    })();
    match result {
        Ok(()) => terminal.succeed(None),
        Err(error) => terminal.fail(control.stop(error), dropped, None),
    }
}

/// Producer result: success is provisional until a bound receiver consumes every packet and End.
pub struct PendingDelivery {
    terminal: Option<mdd_types::result::TerminalBuilder>,
    runtime: RuntimeBudget,
    sender: BoundedSender<Row>,
    produced: u64,
    error: Option<MddError>,
    dropped: bool,
    completed: bool,
}

impl Drop for PendingDelivery {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.runtime.stop(MddError::new(
                ErrorCode::WorkerLost,
                "query.delivery",
                "producer dropped pending delivery before consumer confirmation",
            ));
        }
    }
}

impl QueueDeliveryReceipt {
    fn with_consumed_count(error: MddError, count: u64) -> MddError {
        let value = count.to_string();
        match error.details.get("actual_consumed_rows") {
            None => return error.detail("actual_consumed_rows", value),
            Some(existing) if existing.as_str() == Some(value.as_str()) => return error,
            Some(_) => (),
        }
        // A prior error may already use our conventional detail name. Never
        // overwrite it: at most details.len()+1 checked candidates are needed.
        // If arithmetic cannot be represented, preserve the original error
        // without claiming the additional observation was recorded. This is
        // not a claim that the allocator can recover from process OOM.
        let Some(attempts) = error.details.len().checked_add(1) else {
            return error;
        };
        for ordinal in 0..attempts {
            let name = format!("receipt_actual_consumed_rows_{ordinal}");
            if !error.details.contains_key(&name) {
                return error.detail(name, value);
            }
        }
        error
    }

    fn with_cleanup_error(error: MddError, cleanup: &MddError) -> MddError {
        let value = format!("{cleanup:?}");
        match error.details.get("receipt_cleanup_error") {
            None => return error.detail("receipt_cleanup_error", value),
            Some(existing) if existing.as_str() == Some(value.as_str()) => return error,
            Some(_) => (),
        }
        let Some(attempts) = error.details.len().checked_add(1) else {
            return error;
        };
        for ordinal in 0..attempts {
            let name = format!("receipt_cleanup_error_{ordinal}");
            if !error.details.contains_key(&name) {
                return error.detail(name, value);
            }
        }
        error
    }

    fn finish_late_failure(
        &mut self,
        pending: &mut PendingDelivery,
        terminal: &mut mdd_types::result::TerminalBuilder,
        error: MddError,
    ) -> MddResult<mdd_types::ResultEnvelope> {
        let first = pending.runtime.stop(error);
        if let Err(cleanup) = self.finish_failed() {
            return Err(Self::with_cleanup_error(first, &cleanup));
        }
        let envelope = terminal.fail(first, pending.dropped, None)?;
        pending.completed = true;
        Ok(envelope)
    }

    /// The consumer receives the final envelope only after all packets, explicit End, and the
    /// lifecycle cursor have been confirmed for this exact queue and query.
    pub fn finish(
        &mut self,
        pending: &mut PendingDelivery,
    ) -> MddResult<mdd_types::ResultEnvelope> {
        if !self.matches(
            &pending.sender,
            &pending.runtime,
            pending.produced,
            pending.error.as_ref(),
        )? {
            return Err(invalid("DELIVERY_RECEIPT_QUEUE_OR_QUERY_MISMATCH"));
        }
        let delivery_deadline = if pending.error.is_none() {
            Some(pending.runtime.pool().delivery_deadline())
        } else {
            None
        };
        let mut terminal = pending
            .terminal
            .take()
            .ok_or_else(|| invalid("DELIVERY_ALREADY_FINALIZED"))?;
        if pending.produced != 0 {
            if let Err(error) = terminal.record_batch(0, pending.produced) {
                // The builder rejected this count. Do not manufacture an
                // envelope whose emitted count would omit consumed packets.
                let first = pending
                    .runtime
                    .stop(error.detail("actual_consumed_rows", pending.produced.to_string()));
                let first = Self::with_consumed_count(first, pending.produced);
                return match self.finish_failed() {
                    Ok(()) => Err(first),
                    Err(cleanup) => Err(Self::with_cleanup_error(first, &cleanup)),
                };
            }
        }
        if let Some(error) = pending.error.take() {
            if let Err(cleanup) = self.finish_failed() {
                // This error was recorded by the producer before the End.
                // The query may already have been explicitly released, so a
                // fresh lifecycle lookup must not replace its original cause.
                return Err(Self::with_cleanup_error(error, &cleanup));
            }
            let envelope = terminal.fail(error, pending.dropped, None)?;
            pending.completed = true;
            return Ok(envelope);
        }
        let deadline = match delivery_deadline.unwrap() {
            Ok(deadline) => deadline,
            Err(error) => return self.finish_late_failure(pending, &mut terminal, error),
        };
        if let Err(error) = terminal.validate_success() {
            return self.finish_late_failure(pending, &mut terminal, error);
        }
        if let Err(error) = self.finish_cursor_with_budget(&deadline) {
            return self.finish_late_failure(pending, &mut terminal, error);
        }
        // validate_success used the same immutable builder and data=None before
        // the atomic lifecycle commit; no successful envelope is exposed early.
        let envelope = terminal.succeed(None)?;
        pending.completed = true;
        Ok(envelope)
    }
}

/// Queue production does not assert response delivery. The bound receiver must explicitly
/// acknowledge every row, consume End and exchange its receipt for the final envelope.
///
/// The former unverified callback is not part of the production API:
/// ```compile_fail
/// use mdd_query::executor::execute_trusted_into;
/// ```
/// Limits for the structured JSON byte-batch producer. Each emitted batch is
/// one JSON array of complete typed rows; an empty result emits no data batch.
#[derive(Clone, Copy, Debug)]
pub struct JsonBatchLimits {
    pub max_rows: u64,
    pub max_bytes: u64,
}

/// Logical bounds applied before and during JSON batch consumption. These do
/// not bound parser allocations, allocator overhead, callback work or RSS.
#[derive(Clone, Copy, Debug)]
pub struct JsonBatchConsumerLimits {
    pub max_bytes: u64,
    pub max_rows: u64,
    pub max_columns: u64,
}

/// A fully processed packet and its retained immutable bytes. This is not the
/// final query receipt; all packets and End must still be consumed.
pub struct ConsumedJsonBatch {
    pub rows: u64,
    pub retained: RetainedOwnedBatch,
}

struct JsonRowSeed<'a> {
    width: usize,
    allowed: bool,
    failure: &'a mut Option<MddError>,
}
impl<'de> serde::de::DeserializeSeed<'de> for JsonRowSeed<'_> {
    type Value = Row;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Row, D::Error> {
        use serde::de::Error as _;
        if !self.allowed {
            *self.failure = Some(quota("JSON_CONSUMER_ROW_LIMIT"));
            return Err(D::Error::custom("JSON batch row limit"));
        }
        struct RowVisitor<'a>(JsonRowSeed<'a>);
        impl<'de> serde::de::Visitor<'de> for RowVisitor<'_> {
            type Value = Row;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a typed row array")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Row, A::Error> {
                use serde::de::Error as _;
                let mut row = Vec::new();
                if row.try_reserve_exact(self.0.width).is_err() {
                    *self.0.failure = Some(quota("JSON_CONSUMER_ROW_ALLOCATION"));
                    return Err(A::Error::custom("row allocation"));
                }
                for _ in 0..self.0.width {
                    let Some(value) = seq.next_element::<Value>()? else {
                        *self.0.failure = Some(invalid("ROW_WIDTH_MISMATCH"));
                        return Err(A::Error::custom("row width"));
                    };
                    row.push(value);
                }
                if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    *self.0.failure = Some(invalid("ROW_WIDTH_MISMATCH"));
                    return Err(A::Error::custom("row width"));
                }
                Ok(row)
            }
        }
        deserializer.deserialize_seq(RowVisitor(self))
    }
}

struct JsonRowsSeed<'a, F> {
    runtime: &'a RuntimeBudget,
    prepared: &'a PreparedQuery,
    source: &'a dyn FactSource,
    limits: JsonBatchConsumerLimits,
    partial: Option<&'a MddError>,
    consume: &'a mut F,
    failure: &'a mut Option<MddError>,
    count: &'a mut u64,
}
impl<'de, F> serde::de::DeserializeSeed<'de> for JsonRowsSeed<'_, F>
where
    F: FnMut(&Row) -> MddResult<()>,
{
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        struct RowsVisitor<'a, F>(JsonRowsSeed<'a, F>);
        impl<'de, F> serde::de::Visitor<'de> for RowsVisitor<'_, F>
        where
            F: FnMut(&Row) -> MddResult<()>,
        {
            type Value = ();
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an array of typed rows")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
                use serde::de::Error as _;
                loop {
                    if let Err(error) = json_consumer_checkpoint(self.0.runtime, self.0.partial) {
                        *self.0.failure = Some(error);
                        return Err(A::Error::custom("JSON batch consumer stopped"));
                    }
                    let Some(row) = seq.next_element_seed(JsonRowSeed {
                        width: self.0.prepared.output_schema.len(),
                        allowed: *self.0.count < self.0.limits.max_rows,
                        failure: &mut *self.0.failure,
                    })?
                    else {
                        break;
                    };
                    let result = (|| {
                        json_consumer_checkpoint(self.0.runtime, self.0.partial)?;
                        validate_row(
                            &row,
                            &self.0.prepared.output_schema,
                            self.0.prepared.snapshot_id(),
                        )?;
                        for cell in &row {
                            if let Value::Entity(entity) = cell {
                                self.0.source.validate_entity(entity)?;
                            }
                        }
                        (self.0.consume)(&row)?;
                        json_consumer_checkpoint(self.0.runtime, self.0.partial)
                    })();
                    if let Err(error) = result {
                        *self.0.failure = Some(error);
                        return Err(A::Error::custom("JSON batch consumer stopped"));
                    }
                    *self.0.count += 1;
                }
                Ok(())
            }
        }
        deserializer.deserialize_seq(RowsVisitor(self))
    }
}

// A failed query may still deliver already-produced partial batches. Its first
// fault remains authoritative, while the budget's own deadline continues to
// bound consumer work. A callback already invoked cannot be rolled back.
fn json_consumer_checkpoint(runtime: &RuntimeBudget, partial: Option<&MddError>) -> MddResult<()> {
    if let Some(error) = partial {
        let deadline = runtime
            .pool()
            .delivery_deadline()
            .map_err(|failure| runtime.stop(failure))?;
        runtime
            .cancellation()
            .checkpoint_partial_with_budget(&deadline, error)
    } else {
        runtime.checkpoint()
    }
}

/// Decode and process one query-bound JSON batch, acknowledging it only after
/// the complete packet is validated and every callback returns success.
/// Callbacks already run before a later error are not rolled back; the packet
/// remains unacknowledged and cannot count toward complete delivery. The
/// caller's explicit callback success is an assertion of consumption. For an
/// already failed query, `partial_error` must be its exact recorded first error.
/// The expected runtime must be independently supplied by the caller. A
/// generic sender can provide arbitrary valid rows; this function does not
/// authenticate producer output, input coverage or the final result receipt.
pub fn consume_json_batch<F>(
    packet: OwnedBatchPacket,
    expected_runtime: &RuntimeBudget,
    prepared: &PreparedQuery,
    source: &dyn FactSource,
    limits: JsonBatchConsumerLimits,
    partial_error: Option<&MddError>,
    mut consume: F,
) -> MddResult<ConsumedJsonBatch>
where
    F: FnMut(&Row) -> MddResult<()>,
{
    let process = (|| {
        let (binding, snapshot, epoch) = packet.query_binding(expected_runtime)?;
        let expected = prepared.runtime_binding()?;
        if binding.request_key != expected.request_key
            || binding.schema_id != expected.schema_id
            || binding.semantic_version != expected.semantic_version
            || snapshot != prepared.snapshot_id()
            || epoch != prepared.catalog_epoch()
            || source.identity() != prepared.source_identity
            || source.snapshot_id() != prepared.snapshot_id()
            || source.catalog_epoch() != prepared.catalog_epoch()
        {
            return Err(invalid("JSON_CONSUMER_BINDING_MISMATCH"));
        }
        packet.check_sequence()?;
        if u64::try_from(packet.bytes().len()).map_err(|_| quota("JSON_CONSUMER_BYTE_LIMIT"))?
            > limits.max_bytes
            || u64::try_from(prepared.output_schema.len())
                .map_err(|_| quota("JSON_CONSUMER_COLUMN_LIMIT"))?
                > limits.max_columns
        {
            return Err(quota("JSON_CONSUMER_LIMIT"));
        }
        source.require_layers(&prepared.required_layers)?;
        if let Some(error) = partial_error {
            packet.check_partial_error(error)?;
        }
        json_consumer_checkpoint(expected_runtime, partial_error)?;
        let mut count = 0;
        let mut failure = None;
        let mut decoder = serde_json::Deserializer::from_slice(packet.bytes());
        let result = serde::de::DeserializeSeed::deserialize(
            JsonRowsSeed {
                runtime: expected_runtime,
                prepared,
                source,
                limits,
                partial: partial_error,
                consume: &mut consume,
                failure: &mut failure,
                count: &mut count,
            },
            &mut decoder,
        );
        if let Some(error) = failure {
            return Err(error);
        }
        result.map_err(|e| {
            invalid("JSON_CONSUMER_DECODE")
                .detail("line", e.line())
                .detail("column", e.column())
        })?;
        decoder.end().map_err(|e| {
            invalid("JSON_CONSUMER_TRAILING_DATA")
                .detail("line", e.line())
                .detail("column", e.column())
        })?;
        json_consumer_checkpoint(expected_runtime, partial_error)?;
        Ok(count)
    })();
    let count = match process {
        Ok(count) => count,
        Err(error) => return Err(packet.reject(error)),
    };
    let retained = match partial_error {
        Some(error) => packet.acknowledge_partial(error)?,
        None => packet.acknowledge()?,
    };
    Ok(ConsumedJsonBatch {
        rows: count,
        retained,
    })
}

struct JsonBatchAssembly {
    bytes: Vec<u8>,
    reservations: Vec<Reservation>,
    rows: u64,
}

struct JsonBatchWriter<'a, 'control> {
    bytes: &'a mut Vec<u8>,
    control: &'a mut Control<'control>,
    end: usize,
    failure: Option<MddError>,
}
impl Write for JsonBatchWriter<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let result = (|| {
            self.control.step("json_batch_write", 1)?;
            let end = self
                .bytes
                .len()
                .checked_add(bytes.len())
                .ok_or_else(|| quota("JSON_BATCH_SIZE_OVERFLOW"))?;
            if end > self.end {
                return Err(invalid("JSON_BATCH_COUNT_MISMATCH"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok::<(), MddError>(())
        })();
        if let Err(error) = result {
            self.failure = Some(error);
            return Err(io::Error::other("bounded JSON batch write stopped"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Producer state remains provisional until the matching receiver explicitly
/// acknowledges each batch and End and exchanges its receipt for an envelope.
pub struct PendingJsonBatchDelivery {
    terminal: Option<mdd_types::result::TerminalBuilder>,
    runtime: RuntimeBudget,
    sender: OwnedBatchSender,
    produced_rows: u64,
    produced_batches: u64,
    error: Option<MddError>,
    dropped: bool,
    completed: bool,
}
impl Drop for PendingJsonBatchDelivery {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.runtime.stop(MddError::new(
                ErrorCode::WorkerLost,
                "query.delivery",
                "producer dropped pending JSON batch delivery before confirmation",
            ));
        }
    }
}
impl OwnedBatchReceipt {
    /// Finalize only the exact queue/query after all batches and End were consumed.
    pub fn finish_json_batches(
        &mut self,
        pending: &mut PendingJsonBatchDelivery,
    ) -> MddResult<mdd_types::ResultEnvelope> {
        if !self.matches_pending(
            &pending.sender,
            &pending.runtime,
            pending.produced_batches,
            pending.error.as_ref(),
        )? {
            return Err(invalid("DELIVERY_RECEIPT_QUEUE_OR_QUERY_MISMATCH"));
        }
        let deadline = if pending.error.is_none() {
            Some(pending.runtime.pool().delivery_deadline())
        } else {
            None
        };
        let mut terminal = pending
            .terminal
            .take()
            .ok_or_else(|| invalid("DELIVERY_ALREADY_FINALIZED"))?;
        if pending.produced_rows != 0
            && let Err(error) = terminal.record_batch(0, pending.produced_rows)
        {
            let first = pending
                .runtime
                .stop(error.detail("actual_consumed_rows", pending.produced_rows.to_string()));
            let first = QueueDeliveryReceipt::with_consumed_count(first, pending.produced_rows);
            return match self.finish_failed() {
                Ok(()) => Err(first),
                Err(cleanup) => Err(QueueDeliveryReceipt::with_cleanup_error(first, &cleanup)),
            };
        }
        if let Some(error) = pending.error.take() {
            if let Err(cleanup) = self.finish_failed() {
                return Err(QueueDeliveryReceipt::with_cleanup_error(error, &cleanup));
            }
            let envelope = terminal.fail(error, pending.dropped, None)?;
            pending.completed = true;
            return Ok(envelope);
        }
        let complete = (|| {
            let deadline = deadline.unwrap()?;
            terminal.validate_success()?;
            self.finish_cursor_with_budget(&deadline)?;
            terminal.succeed(None)
        })();
        match complete {
            Ok(envelope) => {
                pending.completed = true;
                Ok(envelope)
            }
            Err(error) => {
                let first = pending.runtime.stop(error);
                if let Err(cleanup) = self.finish_failed() {
                    return Err(QueueDeliveryReceipt::with_cleanup_error(first, &cleanup));
                }
                let envelope = terminal.fail(first, pending.dropped, None)?;
                pending.completed = true;
                Ok(envelope)
            }
        }
    }
}

/// Execute a typed query into bounded structured JSON row batches. Limits bound
/// encoded bytes and rows per batch; allocator overhead and RSS are not bounded.
/// The producer/consumer must run concurrently if the queue can fill.
pub fn execute_json_batches_into(
    prepared: &PreparedQuery,
    source: &dyn FactSource,
    mode: ExecutionMode,
    control: &mut Control<'_>,
    mut terminal: mdd_types::result::TerminalBuilder,
    sender: &OwnedBatchSender,
    limits: JsonBatchLimits,
) -> MddResult<PendingJsonBatchDelivery> {
    if limits.max_rows == 0 || limits.max_bytes < 2 {
        return Err(invalid("INVALID_JSON_BATCH_LIMITS"));
    }
    let runtime = control
        .runtime
        .clone()
        .ok_or_else(|| invalid("DELIVERY_REQUIRES_QUERY_RUNTIME"))?;
    if !sender.matches_runtime(&runtime) {
        return Err(invalid("DELIVERY_QUEUE_RUNTIME_MISMATCH"));
    }
    if !terminal.is_pristine() {
        return Err(invalid("TERMINAL_NOT_FRESH"));
    }
    let binding = prepared.runtime_binding()?;
    let identity = terminal.identity();
    let mut expected: Vec<String> = prepared
        .required_layers
        .iter()
        .map(|layer| {
            serde_json::to_value(layer)
                .expect("enum serializes")
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    expected.sort();
    let mut actual = terminal.coverage().required_layers.clone();
    actual.sort();
    if identity.snapshot_id.as_deref() != Some(prepared.snapshot_id())
        || identity.catalog_epoch != Some(prepared.catalog_epoch())
        || identity.schema_id.as_deref() != Some(binding.schema_id.as_str())
        || identity.query_id.as_deref() != Some(runtime.cancellation().query_handle().id())
        || identity.session_id.as_deref() != Some(runtime.cancellation().session_id()?.as_str())
        || actual != expected
    {
        return Err(invalid("TERMINAL_PLAN_OR_QUERY_BINDING"));
    }
    if prepared.source_identity != source.identity() {
        return Err(invalid("PREPARED_SOURCE_OR_GENERATION_CHANGED"));
    }
    let sender = sender.try_clone()?;
    let mut producer = sender.claim_producer()?;
    if let Err(error) = runtime_begin(prepared, control) {
        if let Ok(status) = runtime.cancellation().status()
            && let Some(original) = status.error
        {
            let _ = sender.finish_produced(&mut producer, Err(original.clone()));
            return Err(original);
        }
        return Err(error);
    }
    producer.arm();
    let mut emitted_rows = 0u64;
    let mut batches = 0u64;
    let mut seen_rows = 0u64;
    let mut batch: Option<JsonBatchAssembly> = None;
    let mut dropped = false;
    let result = (|| {
        source.require_layers(&prepared.required_layers)?;
        control.step("execute_start", 1)?;
        let mut input = match mode {
            ExecutionMode::Streaming => cursor(&prepared.query.root, source, control)?,
            ExecutionMode::MaterializedReference => {
                Cursor::Rows(reference(&prepared.query.root, source, control)?.into_iter())
            }
        };
        if let Cursor::Rows(rows) = &input {
            terminal.computation_complete(rows.len() as u64)?;
            runtime.cancellation().mark_computed()?;
        }
        loop {
            // Once an operator is asked for another row, a failure may have
            // withheld output. EOF explicitly clears this provisional flag.
            dropped = true;
            let Some(row) = input.next(source, control)? else {
                dropped = false;
                break;
            };
            validate_row(&row, &prepared.output_schema, source.snapshot_id())?;
            if seen_rows >= control.limits.max_output_rows {
                dropped = true;
                return Err(quota("MAX_OUTPUT_ROWS")
                    .detail("budget", "output_rows")
                    .detail("limit", control.limits.max_output_rows.to_string()));
            }
            let row_memory = sender.reserve_payload(queued_row_resident_bytes(&row)?)?;
            let row_bytes = count_wire_row(&row, control, &runtime)?;
            if row_bytes
                .checked_add(2)
                .is_none_or(|v| v > limits.max_bytes)
            {
                dropped = true;
                return Err(quota("JSON_BATCH_SINGLE_ROW_TOO_LARGE"));
            }
            let should_flush = batch.as_ref().is_some_and(|b| {
                b.rows >= limits.max_rows
                    || u64::try_from(b.bytes.len())
                        .ok()
                        .and_then(|n| n.checked_add(1))
                        .and_then(|n| n.checked_add(row_bytes))
                        .and_then(|n| n.checked_add(1))
                        .is_none_or(|n| n > limits.max_bytes)
            });
            if should_flush {
                let mut value = batch.take().unwrap();
                value.bytes.push(b']');
                let n = value.rows;
                if let Err(error) = sender.send_produced(
                    &runtime,
                    value.bytes.into_boxed_slice(),
                    value.reservations,
                    &producer,
                ) {
                    dropped = true;
                    return Err(error);
                }
                emitted_rows = emitted_rows
                    .checked_add(n)
                    .ok_or_else(|| quota("OUTPUT_ROW_OVERFLOW"))?;
                batches = batches
                    .checked_add(1)
                    .ok_or_else(|| quota("OUTPUT_BATCH_OVERFLOW"))?;
            }
            let first = batch.is_none();
            let extra = row_bytes
                .checked_add(if first { 2 } else { 1 })
                .ok_or_else(|| quota("JSON_BATCH_SIZE_OVERFLOW"))?;
            let reservation = sender.reserve_payload(extra)?;
            runtime.charge(Resource::OutputBytes, extra)?;
            let value = batch.get_or_insert_with(|| JsonBatchAssembly {
                bytes: Vec::new(),
                reservations: Vec::new(),
                rows: 0,
            });
            let extra_usize =
                usize::try_from(extra).map_err(|_| quota("JSON_BATCH_SIZE_OVERFLOW"))?;
            // The closing bracket is reserved logically from the first row,
            // but it is not in Vec::len() until flush; retain capacity for it.
            let capacity_extra = extra_usize
                .checked_add(usize::from(!first))
                .ok_or_else(|| quota("JSON_BATCH_SIZE_OVERFLOW"))?;
            value
                .bytes
                .try_reserve_exact(capacity_extra)
                .map_err(|_| quota("JSON_BATCH_ALLOCATION"))?;
            value
                .reservations
                .try_reserve(1)
                .map_err(|_| quota("JSON_BATCH_ALLOCATION"))?;
            value.reservations.push(reservation);
            value.bytes.push(if first { b'[' } else { b',' });
            let expected_end = value
                .bytes
                .len()
                .checked_add(
                    usize::try_from(row_bytes).map_err(|_| quota("JSON_BATCH_SIZE_OVERFLOW"))?,
                )
                .ok_or_else(|| quota("JSON_BATCH_SIZE_OVERFLOW"))?;
            let mut writer = JsonBatchWriter {
                bytes: &mut value.bytes,
                control,
                end: expected_end,
                failure: None,
            };
            let serialized = serde_json::to_writer(&mut writer, &StreamingRow(&row));
            if let Some(error) = writer.failure.take() {
                dropped = true;
                return Err(error);
            }
            serialized.map_err(|error| {
                invalid("ROW_ENCODING").detail("serializer_error", error.to_string())
            })?;
            if writer.bytes.len() != expected_end {
                dropped = true;
                return Err(invalid("JSON_BATCH_COUNT_MISMATCH"));
            }
            value.rows += 1;
            seen_rows = seen_rows
                .checked_add(1)
                .ok_or_else(|| quota("OUTPUT_ROW_OVERFLOW"))?;
            control.step("output_row", 1)?;
            dropped = false;
            drop(row_memory);
        }
        // Destroy short-circuited scans before publishing a successful end.
        // A checked source may record a failure during iterator destruction.
        drop(input);
        if let Some(error) = runtime.cancellation().status()?.error {
            return Err(error);
        }
        if !terminal.execution_complete() {
            terminal.computation_complete(seen_rows)?;
            runtime.cancellation().mark_computed()?;
        }
        if let Some(mut value) = batch.take() {
            value.bytes.push(b']');
            let n = value.rows;
            if let Err(error) = sender.send_produced(
                &runtime,
                value.bytes.into_boxed_slice(),
                value.reservations,
                &producer,
            ) {
                dropped = true;
                return Err(error);
            }
            emitted_rows = emitted_rows
                .checked_add(n)
                .ok_or_else(|| quota("OUTPUT_ROW_OVERFLOW"))?;
            batches = batches
                .checked_add(1)
                .ok_or_else(|| quota("OUTPUT_BATCH_OVERFLOW"))?;
        }
        sender.finish_produced(&mut producer, Ok(()))?;
        Ok::<(), MddError>(())
    })();
    let error = match result {
        Ok(()) => None,
        Err(error) => {
            if batch.as_ref().is_some_and(|b| b.rows != 0) {
                dropped = true;
            }
            let error = control.stop(error);
            if sender
                .finish_produced(&mut producer, Err(error.clone()))
                .is_err()
            {
                return Err(error);
            }
            Some(error)
        }
    };
    Ok(PendingJsonBatchDelivery {
        terminal: Some(terminal),
        runtime,
        sender,
        produced_rows: emitted_rows,
        produced_batches: batches,
        error,
        dropped,
        completed: false,
    })
}

pub fn execute_into(
    prepared: &PreparedQuery,
    source: &dyn FactSource,
    mode: ExecutionMode,
    control: &mut Control<'_>,
    mut terminal: mdd_types::result::TerminalBuilder,
    sender: &BoundedSender<Row>,
) -> MddResult<PendingDelivery> {
    let runtime = control
        .runtime
        .clone()
        .ok_or_else(|| invalid("DELIVERY_REQUIRES_QUERY_RUNTIME"))?;
    if !sender.matches_runtime(&runtime) {
        return Err(invalid("DELIVERY_QUEUE_RUNTIME_MISMATCH"));
    }
    if !terminal.is_pristine() {
        return Err(invalid("TERMINAL_NOT_FRESH"));
    }
    let binding = prepared.runtime_binding()?;
    let identity = terminal.identity();
    let mut expected: Vec<String> = prepared
        .required_layers
        .iter()
        .map(|layer| {
            serde_json::to_value(layer)
                .expect("enum serializes")
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    expected.sort();
    let mut actual = terminal.coverage().required_layers.clone();
    actual.sort();
    if identity.snapshot_id.as_deref() != Some(prepared.snapshot_id())
        || identity.catalog_epoch != Some(prepared.catalog_epoch())
        || identity.schema_id.as_deref() != Some(binding.schema_id.as_str())
        || identity.query_id.as_deref() != Some(runtime.cancellation().query_handle().id())
        || identity.session_id.as_deref() != Some(runtime.cancellation().session_id()?.as_str())
        || actual != expected
    {
        return Err(invalid("TERMINAL_PLAN_OR_QUERY_BINDING"));
    }
    if prepared.source_identity != source.identity() {
        return Err(invalid("PREPARED_SOURCE_OR_GENERATION_CHANGED"));
    }
    // Keep the caller's sender alive on preflight/claim failure; otherwise dropping the last
    // sender would overwrite a binding error with a synthetic worker-loss terminal.
    let sender = sender.try_clone()?;
    // Claim this queue before the lifecycle execution claim: external senders
    // cannot publish a success terminal during provider or JSON work.
    let mut producer = sender.claim_producer()?;
    if let Err(error) = runtime_begin(prepared, control) {
        // API misuse must not poison a running query; an already-terminal query, however,
        // must expose its original cancellation/deadline/error as an explicit queue End.
        if let Ok(status) = runtime.cancellation().status()
            && let Some(original) = status.error
        {
            let _ = sender.finish_produced(&mut producer, Err(original.clone()));
            return Err(original);
        }
        return Err(error);
    }
    producer.arm();
    let mut dropped = false;
    let mut produced = 0u64;
    let result = (|| {
        source.require_layers(&prepared.required_layers)?;
        control.step("execute_start", 1)?;
        let mut input = match mode {
            ExecutionMode::Streaming => cursor(&prepared.query.root, source, control)?,
            ExecutionMode::MaterializedReference => {
                Cursor::Rows(reference(&prepared.query.root, source, control)?.into_iter())
            }
        };
        if let Cursor::Rows(rows) = &input {
            terminal.computation_complete(rows.len() as u64)?;
            runtime.cancellation().mark_computed()?;
        }
        while let Some(row) = input.next(source, control)? {
            validate_row(&row, &prepared.output_schema, source.snapshot_id())?;
            if produced >= control.limits.max_output_rows {
                dropped = true;
                return Err(quota("MAX_OUTPUT_ROWS")
                    .detail("budget", "output_rows")
                    .detail("limit", control.limits.max_output_rows.to_string()));
            }
            let resident_bytes = match queued_row_resident_bytes(&row) {
                Ok(value) => value,
                Err(error) => {
                    dropped = true;
                    return Err(error);
                }
            };
            if let Err(error) = runtime.checkpoint() {
                dropped = true;
                return Err(error);
            }
            let memory = match sender.reserve_payload(resident_bytes) {
                Ok(memory) => memory,
                Err(error) => {
                    dropped = true;
                    return Err(error);
                }
            };
            let wire_bytes = match count_wire_row(&row, control, &runtime) {
                Ok(value) => value,
                Err(error) => {
                    dropped = true;
                    return Err(error);
                }
            };
            if let Err(error) = runtime.charge(Resource::OutputBytes, wire_bytes) {
                dropped = true;
                return Err(error);
            }
            if let Err(error) = control.step("output_row", 1) {
                dropped = true;
                return Err(error);
            }
            if let Err(error) = sender.send_reserved_produced(row, wire_bytes, memory, &producer) {
                dropped = true;
                return Err(error);
            }
            produced = produced
                .checked_add(1)
                .ok_or_else(|| quota("OUTPUT_ROW_OVERFLOW"))?;
        }
        if !terminal.execution_complete() {
            terminal.computation_complete(produced)?;
            runtime.cancellation().mark_computed()?;
        }
        sender.finish_produced(&mut producer, Ok(()))?;
        Ok::<(), MddError>(())
    })();
    match result {
        Ok(()) => Ok(PendingDelivery {
            terminal: Some(terminal),
            runtime,
            sender,
            produced,
            error: None,
            dropped: false,
            completed: false,
        }),
        Err(error) => {
            let error = control.stop(error);
            if sender
                .finish_produced(&mut producer, Err(error.clone()))
                .is_err()
            {
                return Err(error);
            }
            Ok(PendingDelivery {
                terminal: Some(terminal),
                runtime,
                sender,
                produced,
                error: Some(error),
                dropped,
                completed: false,
            })
        }
    }
}
