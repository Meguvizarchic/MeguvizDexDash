//! Native metadata relations read by occurrence and ordinal from immutable facts.
//! No legacy table projection or row-table ETL is implied.
use super::*;
use crate::{quota, values::SqlText};
use mdd_facts::{MetadataFacts, definitions::DefinitionFacts, metadata::StringFact};
use mdd_types::{Completeness, ErrorCode, MddError, opaque_id};
use std::collections::BTreeSet;

pub struct MetadataSqlProvider {
    binding: SqlBinding,
    occurrences: Vec<Arc<MetadataFacts>>,
}
impl MetadataSqlProvider {
    pub fn new(occurrences: Vec<Arc<MetadataFacts>>, epoch: DecimalU64) -> MddResult<Self> {
        let snapshot = occurrences
            .first()
            .ok_or_else(|| invalid("METADATA_SCOPE_MUST_BE_EXPLICIT"))?
            .source()
            .snapshot_id
            .clone();
        let mut seen = BTreeSet::new();
        for facts in &occurrences {
            if facts.source().snapshot_id != snapshot
                || !seen.insert(facts.source().dex_occurrence_id.clone())
                || facts.metadata_coverage() != Completeness::Complete
            {
                return Err(invalid("METADATA_PROVIDER_SOURCE_OR_COVERAGE"));
            }
        }
        Ok(Self {
            binding: SqlBinding {
                provider_identity: opaque_id("sql-metadata-provider")?,
                snapshot_id: snapshot,
                catalog_epoch: epoch,
            },
            occurrences,
        })
    }
    pub fn occurrence_count(&self) -> usize {
        self.occurrences.len()
    }
}
struct MetadataCursor {
    provider: Arc<MetadataSqlProvider>,
    occurrence: usize,
    ordinal: usize,
    parameter: usize,
    relation: MetadataRelation,
    control: SqlControl,
}
#[derive(Clone, Copy)]
enum MetadataRelation {
    DexOccurrences,
    StringPools,
    Strings,
    Types,
    Prototypes,
    PrototypeParameters,
}
impl MetadataRelation {
    fn parse(name: &str) -> MddResult<Self> {
        if name.eq_ignore_ascii_case("native_dex_occurrences") {
            Ok(Self::DexOccurrences)
        } else if name.eq_ignore_ascii_case("native_string_pools") {
            Ok(Self::StringPools)
        } else if name.eq_ignore_ascii_case("native_strings") {
            Ok(Self::Strings)
        } else if name.eq_ignore_ascii_case("native_types") {
            Ok(Self::Types)
        } else if name.eq_ignore_ascii_case("native_prototypes") {
            Ok(Self::Prototypes)
        } else if name.eq_ignore_ascii_case("native_prototype_parameters") {
            Ok(Self::PrototypeParameters)
        } else {
            Err(MddError::new(
                ErrorCode::InvalidArgument,
                "sql.metadata",
                "unknown relation",
            ))
        }
    }
}

/// Construct scalar UTF-16 text only after checked cell and cumulative work admission.
fn scalar_text(value: &str, control: &SqlControl) -> MddResult<SqlValue> {
    let mut count = 0usize;
    for ch in value.chars() {
        control.checkpoint(1, false)?;
        count = count
            .checked_add(ch.len_utf16())
            .ok_or_else(|| quota("METADATA_SQL_CELL_OVERFLOW"))?;
    }
    let bytes = u64::try_from(count)
        .ok()
        .and_then(|n| n.checked_mul(2))
        .ok_or_else(|| quota("METADATA_SQL_CELL_OVERFLOW"))?;
    if bytes > control.inner.limits.max_cell_bytes {
        return Err(quota("METADATA_SQL_CELL_BYTES_BEFORE_CLONE"));
    }
    control.work(bytes)?;
    let mut units = Vec::new();
    units
        .try_reserve_exact(count)
        .map_err(|_| quota("METADATA_SQL_ALLOCATION"))?;
    for ch in value.chars() {
        control.checkpoint(1, false)?;
        let mut buf = [0u16; 2];
        units.extend_from_slice(ch.encode_utf16(&mut buf));
    }
    Ok(SqlValue::Text(SqlText {
        utf16: units,
        original_mutf8: None,
    }))
}

/// Preserve both UTF-16 and the original MUTF-8 bytes for a validated string fact.
fn source_text(fact: &StringFact, control: &SqlControl) -> MddResult<(SqlValue, SqlValue)> {
    let units = &fact.data.text.utf16_units;
    let raw = &fact.data.text.raw_mutf8;
    let raw_len = u64::try_from(raw.len()).map_err(|_| quota("METADATA_SQL_CELL_OVERFLOW"))?;
    let unit_len = u64::try_from(units.len())
        .ok()
        .and_then(|n| n.checked_mul(2))
        .ok_or_else(|| quota("METADATA_SQL_CELL_OVERFLOW"))?;
    let text_size = unit_len
        .checked_add(raw_len)
        .ok_or_else(|| quota("METADATA_SQL_CELL_OVERFLOW"))?;
    if text_size > control.inner.limits.max_cell_bytes
        || raw_len > control.inner.limits.max_cell_bytes
    {
        return Err(quota("METADATA_SQL_CELL_BYTES_BEFORE_CLONE"));
    }
    control.work(
        text_size
            .checked_add(raw_len)
            .ok_or_else(|| quota("METADATA_SQL_ROW_BYTES_OVERFLOW"))?,
    )?;
    let mut copied_units = Vec::new();
    let mut original = Vec::new();
    let mut raw_value = Vec::new();
    copied_units
        .try_reserve_exact(units.len())
        .map_err(|_| quota("METADATA_SQL_ALLOCATION"))?;
    original
        .try_reserve_exact(raw.len())
        .map_err(|_| quota("METADATA_SQL_ALLOCATION"))?;
    raw_value
        .try_reserve_exact(raw.len())
        .map_err(|_| quota("METADATA_SQL_ALLOCATION"))?;
    for chunk in units.chunks(4096) {
        control.checkpoint(1, false)?;
        copied_units.extend_from_slice(chunk);
    }
    for chunk in raw.chunks(4096) {
        control.checkpoint(1, false)?;
        original.extend_from_slice(chunk);
        raw_value.extend_from_slice(chunk);
    }
    Ok((
        SqlValue::Text(SqlText {
            utf16: copied_units,
            original_mutf8: Some(original),
        }),
        SqlValue::DexMutf8 {
            bytes: raw_value,
            utf16_code_units: DecimalU64(units.len() as u64),
        },
    ))
}
impl SqlFactCursor for MetadataCursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
        while let Some(facts) = self.provider.occurrences.get(self.occurrence) {
            self.control.checkpoint(1, false)?;
            match self.relation {
                MetadataRelation::DexOccurrences => {
                    if self.ordinal == 0 {
                        let source = facts.source();
                        self.control.work(96)?;
                        let row = vec![
                            scalar_text(&source.snapshot_id, &self.control)?,
                            scalar_text(&source.dex_occurrence_id, &self.control)?,
                            scalar_text(&source.physical_dex_id, &self.control)?,
                            scalar_text(&source.member_id, &self.control)?,
                            scalar_text(&source.source_occurrence_id, &self.control)?,
                            scalar_text(&source.content_id, &self.control)?,
                        ];
                        self.ordinal = 1;
                        return Ok(Some(row));
                    }
                }
                MetadataRelation::StringPools => {
                    if self.ordinal == 0 {
                        let pool = facts.string_pool();
                        self.control.work(96)?;
                        let row = vec![
                            scalar_text(&pool.dex_occurrence_id, &self.control)?,
                            scalar_text(&pool.string_pool_id, &self.control)?,
                            scalar_text(&pool.physical_dex_id, &self.control)?,
                            scalar_text(&pool.content_id, &self.control)?,
                            SqlValue::U64(pool.string_ids_byte_offset),
                            SqlValue::U64(DecimalU64(u64::from(pool.string_count))),
                        ];
                        self.ordinal = 1;
                        return Ok(Some(row));
                    }
                }
                MetadataRelation::Strings => {
                    if let Some(string) = facts.strings().get(self.ordinal) {
                        let text_bytes = (string.data.text.utf16_units.len() as u64)
                            .checked_mul(2)
                            .and_then(|v| v.checked_add(string.data.text.raw_mutf8.len() as u64))
                            .ok_or_else(|| quota("METADATA_SQL_CELL_OVERFLOW"))?;
                        if text_bytes > self.control.inner.limits.max_cell_bytes {
                            return Err(quota("METADATA_SQL_CELL_BYTES_BEFORE_CLONE"));
                        }
                        // Account for both copies of raw MUTF-8, UTF-16 and the two
                        // source identifiers before constructing the owned row.
                        let id_bytes = facts
                            .source()
                            .dex_occurrence_id
                            .len()
                            .checked_add(string.string_pool_id.len())
                            .and_then(|v| v.checked_mul(2))
                            .and_then(|v| u64::try_from(v).ok())
                            .ok_or_else(|| quota("METADATA_SQL_ROW_BYTES_OVERFLOW"))?;
                        let work_bytes = text_bytes
                            .checked_add(string.data.text.raw_mutf8.len() as u64)
                            .and_then(|v| v.checked_add(id_bytes))
                            .and_then(|v| v.checked_add(16))
                            .ok_or_else(|| quota("METADATA_SQL_ROW_BYTES_OVERFLOW"))?;
                        self.control.work(work_bytes)?;
                        self.ordinal += 1;
                        return Ok(Some(vec![
                            SqlValue::text(&facts.source().dex_occurrence_id),
                            SqlValue::text(&string.string_pool_id),
                            SqlValue::U64(DecimalU64(u64::from(string.data.string_idx))),
                            SqlValue::Text(SqlText {
                                utf16: string.data.text.utf16_units.clone(),
                                original_mutf8: Some(string.data.text.raw_mutf8.clone()),
                            }),
                            SqlValue::DexMutf8 {
                                bytes: string.data.text.raw_mutf8.clone(),
                                utf16_code_units: DecimalU64(
                                    string.data.text.utf16_units.len() as u64
                                ),
                            },
                        ]));
                    }
                }
                MetadataRelation::Types => {
                    if let Some(item) = facts.types().get(self.ordinal) {
                        let string = facts
                            .strings()
                            .get(item.data.descriptor_string_idx as usize)
                            .filter(|string| {
                                string.data.string_idx == item.data.descriptor_string_idx
                            })
                            .ok_or_else(|| {
                                MddError::new(
                                    ErrorCode::InternalFault,
                                    "sql.metadata",
                                    "validated descriptor string missing",
                                )
                            })?;
                        self.control.work(32)?;
                        let occurrence =
                            scalar_text(&facts.source().dex_occurrence_id, &self.control)?;
                        let (descriptor, raw) = source_text(string, &self.control)?;
                        self.ordinal += 1;
                        return Ok(Some(vec![
                            occurrence,
                            SqlValue::U64(DecimalU64(u64::from(item.data.type_idx))),
                            SqlValue::U64(DecimalU64(u64::from(item.data.descriptor_string_idx))),
                            descriptor,
                            raw,
                        ]));
                    }
                }
                MetadataRelation::Prototypes => {
                    if let Some(item) = facts.prototypes().get(self.ordinal) {
                        let shorty = facts
                            .strings()
                            .get(item.data.shorty_string_idx as usize)
                            .filter(|string| string.data.string_idx == item.data.shorty_string_idx)
                            .ok_or_else(|| {
                                MddError::new(
                                    ErrorCode::InternalFault,
                                    "sql.metadata",
                                    "validated shorty string missing",
                                )
                            })?;
                        self.control.work(80)?;
                        let occurrence =
                            scalar_text(&facts.source().dex_occurrence_id, &self.control)?;
                        let (shorty_text, shorty_raw) = source_text(shorty, &self.control)?;
                        let descriptor = scalar_text(&item.data.descriptor, &self.control)?;
                        let count = u64::try_from(item.data.parameter_type_indices.len())
                            .map_err(|_| quota("METADATA_SQL_ROWS_OVERFLOW"))?;
                        self.ordinal += 1;
                        return Ok(Some(vec![
                            occurrence,
                            SqlValue::U64(DecimalU64(u64::from(item.data.proto_idx))),
                            SqlValue::U64(DecimalU64(u64::from(item.data.shorty_string_idx))),
                            shorty_text,
                            shorty_raw,
                            SqlValue::U64(DecimalU64(u64::from(item.data.return_type_idx))),
                            item.data
                                .parameters_byte_offset
                                .map_or(SqlValue::Null, SqlValue::U64),
                            SqlValue::U64(DecimalU64(count)),
                            descriptor,
                        ]));
                    }
                }
                MetadataRelation::PrototypeParameters => {
                    if let Some(item) = facts.prototypes().get(self.ordinal) {
                        if let Some(type_idx) = item.data.parameter_type_indices.get(self.parameter)
                        {
                            let ordinal = u64::try_from(self.parameter)
                                .map_err(|_| quota("METADATA_SQL_ROWS_OVERFLOW"))?;
                            self.control.work(48)?;
                            let occurrence =
                                scalar_text(&facts.source().dex_occurrence_id, &self.control)?;
                            self.parameter += 1;
                            return Ok(Some(vec![
                                occurrence,
                                SqlValue::U64(DecimalU64(u64::from(item.data.proto_idx))),
                                SqlValue::U64(DecimalU64(ordinal)),
                                SqlValue::U64(DecimalU64(u64::from(*type_idx))),
                            ]));
                        }
                        self.ordinal += 1;
                        self.parameter = 0;
                        continue;
                    }
                }
            }
            self.occurrence += 1;
            self.ordinal = 0;
            self.parameter = 0;
        }
        Ok(None)
    }
}
impl SqlFactProvider for MetadataSqlProvider {
    fn binding(&self) -> &SqlBinding {
        &self.binding
    }
    fn relations(&self) -> MddResult<Vec<SqlRelation>> {
        fn relation(
            name: &str,
            columns: &[(&str, SqlType, bool)],
            count: Option<u64>,
        ) -> SqlRelation {
            SqlRelation {
                name: name.into(),
                columns: columns
                    .iter()
                    .map(|(name, data_type, nullable)| SqlColumn {
                        id: (*name).into(),
                        name: (*name).into(),
                        data_type: *data_type,
                        nullable: *nullable,
                    })
                    .collect(),
                required_layers: vec![FactLayer::Metadata],
                estimated_rows: count.map(DecimalU64),
            }
        }
        let (strings, types, prototypes) = self
            .occurrences
            .iter()
            .try_fold((0u64, 0u64, 0u64), |(s, t, p), facts| {
                Some((
                    s.checked_add(u64::try_from(facts.strings().len()).ok()?)?,
                    t.checked_add(u64::try_from(facts.types().len()).ok()?)?,
                    p.checked_add(u64::try_from(facts.prototypes().len()).ok()?)?,
                ))
            })
            .ok_or_else(|| quota("METADATA_SQL_ROWS_OVERFLOW"))?;
        Ok(vec![
            relation(
                "native_string_pools",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("string_pool_id", SqlType::Text, false),
                    ("physical_dex_id", SqlType::Text, false),
                    ("content_id", SqlType::Text, false),
                    ("string_ids_byte_offset", SqlType::U64, false),
                    ("string_count", SqlType::U64, false),
                ],
                Some(
                    u64::try_from(self.occurrences.len())
                        .map_err(|_| quota("METADATA_SQL_ROWS_OVERFLOW"))?,
                ),
            ),
            relation(
                "native_dex_occurrences",
                &[
                    ("snapshot_id", SqlType::Text, false),
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("physical_dex_id", SqlType::Text, false),
                    ("member_id", SqlType::Text, false),
                    ("source_occurrence_id", SqlType::Text, false),
                    ("content_id", SqlType::Text, false),
                ],
                Some(
                    u64::try_from(self.occurrences.len())
                        .map_err(|_| quota("METADATA_SQL_ROWS_OVERFLOW"))?,
                ),
            ),
            relation(
                "native_strings",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("string_pool_id", SqlType::Text, false),
                    ("string_idx", SqlType::U64, false),
                    ("value", SqlType::Text, false),
                    ("raw_mutf8", SqlType::Bytes, false),
                ],
                Some(strings),
            ),
            relation(
                "native_types",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("type_idx", SqlType::U64, false),
                    ("descriptor_string_idx", SqlType::U64, false),
                    ("descriptor", SqlType::Text, false),
                    ("descriptor_mutf8", SqlType::Bytes, false),
                ],
                Some(types),
            ),
            relation(
                "native_prototypes",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("proto_idx", SqlType::U64, false),
                    ("shorty_string_idx", SqlType::U64, false),
                    ("shorty", SqlType::Text, false),
                    ("shorty_mutf8", SqlType::Bytes, false),
                    ("return_type_idx", SqlType::U64, false),
                    ("parameters_byte_offset", SqlType::U64, true),
                    ("parameter_count", SqlType::U64, false),
                    ("descriptor", SqlType::Text, false),
                ],
                Some(prototypes),
            ),
            // Counting parameters here would scan every prototype during optimizer setup.
            relation(
                "native_prototype_parameters",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("proto_idx", SqlType::U64, false),
                    ("ordinal", SqlType::U64, false),
                    ("type_idx", SqlType::U64, false),
                ],
                None,
            ),
        ])
    }
    fn require_relation(&self, relation: &str) -> MddResult<()> {
        MetadataRelation::parse(relation).map(|_| ())
    }
    fn open_cursor(
        self: Arc<Self>,
        relation: &str,
        control: SqlControl,
    ) -> MddResult<Box<dyn SqlFactCursor>> {
        let relation = MetadataRelation::parse(relation)?;
        Ok(Box::new(MetadataCursor {
            provider: self,
            occurrence: 0,
            ordinal: 0,
            parameter: 0,
            relation,
            control,
        }))
    }
}

/// Direct native definition facts from one explicit snapshot scope. This does
/// not implement the legacy HostLab table layout or infer inherited members.
pub struct DefinitionSqlProvider {
    binding: SqlBinding,
    occurrences: Vec<Arc<DefinitionFacts>>,
}
impl DefinitionSqlProvider {
    pub fn new(occurrences: Vec<Arc<DefinitionFacts>>, epoch: DecimalU64) -> MddResult<Self> {
        let snapshot = occurrences
            .first()
            .ok_or_else(|| invalid("DEFINITION_SCOPE_MUST_BE_EXPLICIT"))?
            .metadata()
            .source()
            .snapshot_id
            .clone();
        let mut seen = BTreeSet::new();
        for facts in &occurrences {
            let source = facts.metadata().source();
            if source.snapshot_id != snapshot || !seen.insert(source.dex_occurrence_id.clone()) {
                return Err(invalid("DEFINITION_PROVIDER_SOURCE"));
            }
            if facts.metadata().metadata_coverage() != Completeness::Complete
                || facts.definition_coverage() != Completeness::Complete
            {
                return Err(MddError::new(
                    ErrorCode::IncompleteFacts,
                    "sql.definitions",
                    "complete metadata and definition facts are required",
                ));
            }
        }
        Ok(Self {
            binding: SqlBinding {
                provider_identity: opaque_id("sql-definition-provider")?,
                snapshot_id: snapshot,
                catalog_epoch: epoch,
            },
            occurrences,
        })
    }
}

#[derive(Clone, Copy)]
enum DefinitionRelation {
    Classes,
    ClassDetails,
    Interfaces,
    MethodReferences,
    MethodDefinitions,
    FieldReferences,
    FieldDefinitions,
}
impl DefinitionRelation {
    fn parse(name: &str) -> MddResult<Self> {
        if name.eq_ignore_ascii_case("native_classes") {
            Ok(Self::Classes)
        } else if name.eq_ignore_ascii_case("native_class_definition_details") {
            Ok(Self::ClassDetails)
        } else if name.eq_ignore_ascii_case("native_class_interfaces") {
            Ok(Self::Interfaces)
        } else if name.eq_ignore_ascii_case("native_method_references") {
            Ok(Self::MethodReferences)
        } else if name.eq_ignore_ascii_case("native_method_definitions") {
            Ok(Self::MethodDefinitions)
        } else if name.eq_ignore_ascii_case("native_field_references") {
            Ok(Self::FieldReferences)
        } else if name.eq_ignore_ascii_case("native_field_definitions") {
            Ok(Self::FieldDefinitions)
        } else {
            Err(invalid("UNKNOWN_DEFINITION_RELATION"))
        }
    }
}
fn definition_name_text(
    facts: &DefinitionFacts,
    index: u32,
    control: &SqlControl,
) -> MddResult<(SqlValue, SqlValue)> {
    let string = facts
        .metadata()
        .strings()
        .get(index as usize)
        .filter(|item| item.data.string_idx == index)
        .ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "sql.definitions",
                "validated name is missing",
            )
        })?;
    source_text(string, control)
}
struct DefinitionCursor {
    provider: Arc<DefinitionSqlProvider>,
    relation: DefinitionRelation,
    occurrence: usize,
    ordinal: usize,
    control: SqlControl,
}
fn definition_type_text(
    facts: &DefinitionFacts,
    index: u32,
    control: &SqlControl,
) -> MddResult<(SqlValue, SqlValue)> {
    let metadata = facts.metadata();
    let ty = metadata
        .types()
        .get(index as usize)
        .filter(|item| item.data.type_idx == index)
        .ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "sql.definitions",
                "validated type is missing",
            )
        })?;
    let string = metadata
        .strings()
        .get(ty.data.descriptor_string_idx as usize)
        .filter(|item| item.data.string_idx == ty.data.descriptor_string_idx)
        .ok_or_else(|| {
            MddError::new(
                ErrorCode::InternalFault,
                "sql.definitions",
                "validated descriptor is missing",
            )
        })?;
    source_text(string, control)
}
impl SqlFactCursor for DefinitionCursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
        while let Some(facts) = self.provider.occurrences.get(self.occurrence) {
            self.control.checkpoint(1, false)?;
            let metadata = facts.metadata();
            let source = metadata.source();
            let row = match self.relation {
                DefinitionRelation::ClassDetails => {
                    let Some(class) = facts.definitions().classes.get(self.ordinal) else {
                        self.occurrence += 1;
                        self.ordinal = 0;
                        continue;
                    };
                    self.control.work(160)?;
                    let range = class.class_data_range.as_ref();
                    vec![
                        scalar_text(&source.dex_occurrence_id, &self.control)?,
                        SqlValue::U64(DecimalU64(class.class_def_idx.into())),
                        SqlValue::U64(DecimalU64(class.access_flags.into())),
                        class
                            .annotations_byte_offset
                            .map_or(SqlValue::Null, SqlValue::U64),
                        class
                            .static_values_byte_offset
                            .map_or(SqlValue::Null, SqlValue::U64),
                        range.map_or(SqlValue::Null, |r| SqlValue::U64(r.byte_offset)),
                        range.map_or(SqlValue::Null, |r| SqlValue::U64(r.byte_length)),
                        SqlValue::U64(DecimalU64(class.static_fields_count.into())),
                        SqlValue::U64(DecimalU64(class.instance_fields_count.into())),
                        SqlValue::U64(DecimalU64(class.direct_methods_count.into())),
                        SqlValue::U64(DecimalU64(class.virtual_methods_count.into())),
                        SqlValue::U64(class.encoded_range.byte_offset),
                        SqlValue::U64(class.encoded_range.byte_length),
                    ]
                }
                DefinitionRelation::Classes => {
                    let Some(class) = facts.definitions().classes.get(self.ordinal) else {
                        self.occurrence += 1;
                        self.ordinal = 0;
                        continue;
                    };
                    self.control.work(160)?;
                    let occurrence = scalar_text(&source.dex_occurrence_id, &self.control)?;
                    let (descriptor, raw) =
                        definition_type_text(facts, class.class_idx, &self.control)?;
                    let (source_file, source_raw) = match class.source_file_idx {
                        None => (SqlValue::Null, SqlValue::Null),
                        Some(index) => {
                            let string = metadata
                                .strings()
                                .get(index as usize)
                                .filter(|item| item.data.string_idx == index)
                                .ok_or_else(|| {
                                    MddError::new(
                                        ErrorCode::InternalFault,
                                        "sql.definitions",
                                        "validated source file is missing",
                                    )
                                })?;
                            source_text(string, &self.control)?
                        }
                    };
                    vec![
                        occurrence,
                        SqlValue::U64(DecimalU64(u64::from(class.class_def_idx))),
                        SqlValue::U64(DecimalU64(u64::from(class.class_idx))),
                        descriptor,
                        raw,
                        SqlValue::U64(DecimalU64(u64::from(class.access_flags))),
                        class
                            .superclass_idx
                            .map_or(SqlValue::Null, |v| SqlValue::U64(DecimalU64(u64::from(v)))),
                        class
                            .source_file_idx
                            .map_or(SqlValue::Null, |v| SqlValue::U64(DecimalU64(u64::from(v)))),
                        source_file,
                        source_raw,
                    ]
                }
                DefinitionRelation::Interfaces => {
                    let Some(interface) = facts.definitions().interfaces.get(self.ordinal) else {
                        self.occurrence += 1;
                        self.ordinal = 0;
                        continue;
                    };
                    self.control.work(112)?;
                    let occurrence = scalar_text(&source.dex_occurrence_id, &self.control)?;
                    let (descriptor, raw) =
                        definition_type_text(facts, interface.interface_type_idx, &self.control)?;
                    vec![
                        occurrence,
                        SqlValue::U64(DecimalU64(u64::from(interface.class_def_idx))),
                        SqlValue::U64(DecimalU64(u64::from(interface.class_idx))),
                        SqlValue::U64(DecimalU64(u64::from(interface.ordinal))),
                        SqlValue::U64(DecimalU64(u64::from(interface.interface_type_idx))),
                        descriptor,
                        raw,
                    ]
                }
                DefinitionRelation::MethodReferences => {
                    let Some(method) = facts.definitions().method_references.get(self.ordinal)
                    else {
                        self.occurrence += 1;
                        self.ordinal = 0;
                        continue;
                    };
                    self.control.work(128)?;
                    let occurrence = scalar_text(&source.dex_occurrence_id, &self.control)?;
                    let (class, class_raw) =
                        definition_type_text(facts, method.class_idx, &self.control)?;
                    let (name, name_raw) =
                        definition_name_text(facts, method.name_idx, &self.control)?;
                    vec![
                        occurrence,
                        SqlValue::U64(DecimalU64(method.method_idx.into())),
                        SqlValue::U64(DecimalU64(method.class_idx.into())),
                        class,
                        class_raw,
                        SqlValue::U64(DecimalU64(method.proto_idx.into())),
                        SqlValue::U64(DecimalU64(method.name_idx.into())),
                        name,
                        name_raw,
                    ]
                }
                DefinitionRelation::MethodDefinitions => {
                    let Some(method) = facts.definitions().method_definitions.get(self.ordinal)
                    else {
                        self.occurrence += 1;
                        self.ordinal = 0;
                        continue;
                    };
                    self.control.work(128)?;
                    let (offset, insns) = match method.body {
                        mdd_facts::MethodBody::Present {
                            code_byte_offset,
                            declared_insns_size,
                        } => (
                            SqlValue::U64(code_byte_offset),
                            SqlValue::U64(DecimalU64(declared_insns_size.into())),
                        ),
                        _ => (SqlValue::Null, SqlValue::Null),
                    };
                    vec![
                        scalar_text(&source.dex_occurrence_id, &self.control)?,
                        SqlValue::U64(DecimalU64(method.class_def_idx.into())),
                        SqlValue::U64(DecimalU64(method.class_idx.into())),
                        SqlValue::U64(DecimalU64(method.method_idx.into())),
                        scalar_text(method.kind.as_str(), &self.control)?,
                        SqlValue::U64(DecimalU64(method.ordinal.into())),
                        SqlValue::U64(DecimalU64(method.access_flags.into())),
                        scalar_text(method.body.state(), &self.control)?,
                        offset,
                        insns,
                    ]
                }
                DefinitionRelation::FieldReferences => {
                    let Some(field) = facts.definitions().field_references.get(self.ordinal) else {
                        self.occurrence += 1;
                        self.ordinal = 0;
                        continue;
                    };
                    self.control.work(144)?;
                    let occurrence = scalar_text(&source.dex_occurrence_id, &self.control)?;
                    let (class, class_raw) =
                        definition_type_text(facts, field.class_idx, &self.control)?;
                    let (ty, ty_raw) = definition_type_text(facts, field.type_idx, &self.control)?;
                    let (name, name_raw) =
                        definition_name_text(facts, field.name_idx, &self.control)?;
                    vec![
                        occurrence,
                        SqlValue::U64(DecimalU64(field.field_idx.into())),
                        SqlValue::U64(DecimalU64(field.class_idx.into())),
                        class,
                        class_raw,
                        SqlValue::U64(DecimalU64(field.type_idx.into())),
                        ty,
                        ty_raw,
                        SqlValue::U64(DecimalU64(field.name_idx.into())),
                        name,
                        name_raw,
                    ]
                }
                DefinitionRelation::FieldDefinitions => {
                    let Some(field) = facts.definitions().field_definitions.get(self.ordinal)
                    else {
                        self.occurrence += 1;
                        self.ordinal = 0;
                        continue;
                    };
                    self.control.work(96)?;
                    vec![
                        scalar_text(&source.dex_occurrence_id, &self.control)?,
                        SqlValue::U64(DecimalU64(field.class_def_idx.into())),
                        SqlValue::U64(DecimalU64(field.class_idx.into())),
                        SqlValue::U64(DecimalU64(field.field_idx.into())),
                        scalar_text(field.kind.as_str(), &self.control)?,
                        SqlValue::U64(DecimalU64(field.ordinal.into())),
                        SqlValue::U64(DecimalU64(field.access_flags.into())),
                    ]
                }
            };
            self.ordinal += 1;
            return Ok(Some(row));
        }
        Ok(None)
    }
}
impl SqlFactProvider for DefinitionSqlProvider {
    fn binding(&self) -> &SqlBinding {
        &self.binding
    }
    fn relations(&self) -> MddResult<Vec<SqlRelation>> {
        let (classes, interfaces, method_refs, method_defs, field_refs, field_defs) = self
            .occurrences
            .iter()
            .try_fold(
                (0u64, 0u64, 0u64, 0u64, 0u64, 0u64),
                |(c, i, mr, md, fr, fd), facts| {
                    Some((
                        c.checked_add(u64::try_from(facts.definitions().classes.len()).ok()?)?,
                        i.checked_add(u64::try_from(facts.definitions().interfaces.len()).ok()?)?,
                        mr.checked_add(
                            u64::try_from(facts.definitions().method_references.len()).ok()?,
                        )?,
                        md.checked_add(
                            u64::try_from(facts.definitions().method_definitions.len()).ok()?,
                        )?,
                        fr.checked_add(
                            u64::try_from(facts.definitions().field_references.len()).ok()?,
                        )?,
                        fd.checked_add(
                            u64::try_from(facts.definitions().field_definitions.len()).ok()?,
                        )?,
                    ))
                },
            )
            .ok_or_else(|| quota("DEFINITION_SQL_ROWS_OVERFLOW"))?;
        let relation = |name: &str, columns: &[(&str, SqlType, bool)], count| SqlRelation {
            name: name.into(),
            columns: columns
                .iter()
                .map(|(name, data_type, nullable)| SqlColumn {
                    id: (*name).into(),
                    name: (*name).into(),
                    data_type: *data_type,
                    nullable: *nullable,
                })
                .collect(),
            required_layers: vec![FactLayer::Metadata, FactLayer::Structure],
            estimated_rows: Some(DecimalU64(count)),
        };
        Ok(vec![
            // These are the offsets declared by class_def. A present annotation
            // or static-values offset is not proof of a validated item start.
            relation(
                "native_class_definition_details",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("class_def_idx", SqlType::U64, false),
                    ("access_flags", SqlType::U64, false),
                    ("annotations_offset", SqlType::U64, true),
                    ("static_values_offset", SqlType::U64, true),
                    ("class_data_offset", SqlType::U64, true),
                    ("class_data_length", SqlType::U64, true),
                    ("static_fields_count", SqlType::U64, false),
                    ("instance_fields_count", SqlType::U64, false),
                    ("direct_methods_count", SqlType::U64, false),
                    ("virtual_methods_count", SqlType::U64, false),
                    ("encoded_offset", SqlType::U64, false),
                    ("encoded_length", SqlType::U64, false),
                ],
                classes,
            ),
            relation(
                "native_classes",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("class_def_idx", SqlType::U64, false),
                    ("type_idx", SqlType::U64, false),
                    ("descriptor", SqlType::Text, false),
                    ("descriptor_mutf8", SqlType::Bytes, false),
                    ("access_flags", SqlType::U64, false),
                    ("superclass_type_idx", SqlType::U64, true),
                    ("source_file_string_idx", SqlType::U64, true),
                    ("source_file", SqlType::Text, true),
                    ("source_file_mutf8", SqlType::Bytes, true),
                ],
                classes,
            ),
            relation(
                "native_class_interfaces",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("class_def_idx", SqlType::U64, false),
                    ("class_type_idx", SqlType::U64, false),
                    ("ordinal", SqlType::U64, false),
                    ("interface_type_idx", SqlType::U64, false),
                    ("descriptor", SqlType::Text, false),
                    ("descriptor_mutf8", SqlType::Bytes, false),
                ],
                interfaces,
            ),
            relation(
                "native_method_references",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("method_idx", SqlType::U64, false),
                    ("class_type_idx", SqlType::U64, false),
                    ("class_descriptor", SqlType::Text, false),
                    ("class_descriptor_mutf8", SqlType::Bytes, false),
                    ("prototype_idx", SqlType::U64, false),
                    ("name_idx", SqlType::U64, false),
                    ("name", SqlType::Text, false),
                    ("name_mutf8", SqlType::Bytes, false),
                ],
                method_refs,
            ),
            relation(
                "native_method_definitions",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("class_def_idx", SqlType::U64, false),
                    ("class_type_idx", SqlType::U64, false),
                    ("method_idx", SqlType::U64, false),
                    ("kind", SqlType::Text, false),
                    ("ordinal", SqlType::U64, false),
                    ("access_flags", SqlType::U64, false),
                    ("body_state", SqlType::Text, false),
                    ("code_byte_offset", SqlType::U64, true),
                    ("declared_insns_size", SqlType::U64, true),
                ],
                method_defs,
            ),
            relation(
                "native_field_references",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("field_idx", SqlType::U64, false),
                    ("class_type_idx", SqlType::U64, false),
                    ("class_descriptor", SqlType::Text, false),
                    ("class_descriptor_mutf8", SqlType::Bytes, false),
                    ("field_type_idx", SqlType::U64, false),
                    ("type_descriptor", SqlType::Text, false),
                    ("type_descriptor_mutf8", SqlType::Bytes, false),
                    ("name_idx", SqlType::U64, false),
                    ("name", SqlType::Text, false),
                    ("name_mutf8", SqlType::Bytes, false),
                ],
                field_refs,
            ),
            relation(
                "native_field_definitions",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("class_def_idx", SqlType::U64, false),
                    ("class_type_idx", SqlType::U64, false),
                    ("field_idx", SqlType::U64, false),
                    ("kind", SqlType::Text, false),
                    ("ordinal", SqlType::U64, false),
                    ("access_flags", SqlType::U64, false),
                ],
                field_defs,
            ),
        ])
    }
    fn require_relation(&self, relation: &str) -> MddResult<()> {
        DefinitionRelation::parse(relation).map(|_| ())
    }
    fn open_cursor(
        self: Arc<Self>,
        relation: &str,
        control: SqlControl,
    ) -> MddResult<Box<dyn SqlFactCursor>> {
        Ok(Box::new(DefinitionCursor {
            provider: self,
            relation: DefinitionRelation::parse(relation)?,
            occurrence: 0,
            ordinal: 0,
            control,
        }))
    }
}

/// Combines already-built metadata and definitions without copying or ETL.
/// Both sides must describe exactly the same selected DEX occurrences.
pub struct CombinedSqlProvider {
    binding: SqlBinding,
    metadata: Arc<MetadataSqlProvider>,
    definitions: Arc<DefinitionSqlProvider>,
    references: Option<Arc<ReferenceSqlProvider>>,
    code: Option<Arc<CodeSqlProvider>>,
    annotations: Option<Arc<AnnotationSqlProvider>>,
}
impl CombinedSqlProvider {
    pub fn new(
        metadata: Arc<MetadataSqlProvider>,
        definitions: Arc<DefinitionSqlProvider>,
    ) -> MddResult<Self> {
        if metadata.binding.snapshot_id != definitions.binding.snapshot_id
            || metadata.binding.catalog_epoch != definitions.binding.catalog_epoch
        {
            return Err(invalid("COMBINED_PROVIDER_GENERATION"));
        }
        let metadata_sources: BTreeSet<_> = metadata
            .occurrences
            .iter()
            .map(|f| &f.source().dex_occurrence_id)
            .collect();
        let definition_sources: BTreeSet<_> = definitions
            .occurrences
            .iter()
            .map(|f| &f.metadata().source().dex_occurrence_id)
            .collect();
        if metadata_sources != definition_sources {
            return Err(invalid("COMBINED_PROVIDER_SCOPE"));
        }
        Ok(Self {
            binding: SqlBinding {
                provider_identity: opaque_id("sql-combined-provider")?,
                snapshot_id: metadata.binding.snapshot_id.clone(),
                catalog_epoch: metadata.binding.catalog_epoch,
            },
            metadata,
            definitions,
            references: None,
            code: None,
            annotations: None,
        })
    }

    /// Attach complete encoded reference sites for precisely the same selected
    /// occurrences and catalog generation. No legacy call-graph semantics are inferred.
    pub fn with_references(mut self, references: Arc<ReferenceSqlProvider>) -> MddResult<Self> {
        if self.references.is_some() {
            return Err(invalid("COMBINED_PROVIDER_REFERENCES_ALREADY_BOUND"));
        }
        if self.binding.snapshot_id != references.binding.snapshot_id
            || self.binding.catalog_epoch != references.binding.catalog_epoch
        {
            return Err(invalid("COMBINED_PROVIDER_GENERATION"));
        }
        let metadata_sources: BTreeSet<_> = self
            .metadata
            .occurrences
            .iter()
            .map(|facts| &facts.source().dex_occurrence_id)
            .collect();
        let reference_sources: BTreeSet<_> = references
            .occurrences
            .iter()
            .map(|facts| &facts.source().dex_occurrence_id)
            .collect();
        if metadata_sources != reference_sources {
            return Err(invalid("COMBINED_PROVIDER_SCOPE"));
        }
        for facts in &references.occurrences {
            facts.require_complete()?;
        }
        self.references = Some(references);
        Ok(self)
    }

    /// Attach complete physical code items for the same selected occurrences.
    /// Physical items do not by themselves establish method ownership.
    pub fn with_code(mut self, code: Arc<CodeSqlProvider>) -> MddResult<Self> {
        if self.code.is_some() {
            return Err(invalid("COMBINED_PROVIDER_CODE_ALREADY_BOUND"));
        }
        if self.binding.snapshot_id != code.binding.snapshot_id
            || self.binding.catalog_epoch != code.binding.catalog_epoch
        {
            return Err(invalid("COMBINED_PROVIDER_GENERATION"));
        }
        let metadata_sources: BTreeSet<_> = self
            .metadata
            .occurrences
            .iter()
            .map(|facts| &facts.source().dex_occurrence_id)
            .collect();
        let code_sources: BTreeSet<_> = code
            .occurrences
            .iter()
            .map(|facts| &facts.source().dex_occurrence_id)
            .collect();
        if metadata_sources != code_sources {
            return Err(invalid("COMBINED_PROVIDER_SCOPE"));
        }
        self.code = Some(code);
        Ok(self)
    }

    /// Bind encoded annotation facts for exactly the same selected sources.
    pub fn with_annotations(mut self, annotations: Arc<AnnotationSqlProvider>) -> MddResult<Self> {
        if self.annotations.is_some() {
            return Err(invalid("COMBINED_PROVIDER_ANNOTATIONS_ALREADY_BOUND"));
        }
        if self.binding.snapshot_id != annotations.binding.snapshot_id
            || self.binding.catalog_epoch != annotations.binding.catalog_epoch
        {
            return Err(invalid("COMBINED_PROVIDER_GENERATION"));
        }
        let expected: BTreeSet<_> = self
            .metadata
            .occurrences
            .iter()
            .map(|f| &f.source().dex_occurrence_id)
            .collect();
        let actual: BTreeSet<_> = annotations
            .occurrences
            .iter()
            .map(|f| &f.source().dex_occurrence_id)
            .collect();
        if expected != actual {
            return Err(invalid("COMBINED_PROVIDER_SCOPE"));
        }
        self.annotations = Some(annotations);
        Ok(self)
    }
}
impl SqlFactProvider for CombinedSqlProvider {
    fn binding(&self) -> &SqlBinding {
        &self.binding
    }
    fn relations(&self) -> MddResult<Vec<SqlRelation>> {
        let mut relations = self.metadata.relations()?;
        relations.extend(self.definitions.relations()?);
        if let Some(references) = &self.references {
            relations.extend(references.relations()?);
        }
        if let Some(code) = &self.code {
            relations.extend(code.relations()?);
        }
        if let Some(annotations) = &self.annotations {
            relations.extend(annotations.relations()?);
        }
        let mut names = BTreeSet::new();
        if relations
            .iter()
            .any(|r| !names.insert(r.name.to_ascii_lowercase()))
        {
            return Err(invalid("COMBINED_PROVIDER_DUPLICATE_RELATION"));
        }
        Ok(relations)
    }
    fn require_relation(&self, relation: &str) -> MddResult<()> {
        if MetadataRelation::parse(relation).is_ok() {
            self.metadata.require_relation(relation)
        } else if AnnotationRelation::parse(relation).is_some() {
            self.annotations
                .as_ref()
                .ok_or_else(|| invalid("UNKNOWN_ANNOTATION_RELATION"))?
                .require_relation(relation)
        } else if CodeRelation::parse(relation).is_ok() {
            self.code
                .as_ref()
                .ok_or_else(|| invalid("UNKNOWN_CODE_RELATION"))?
                .require_relation(relation)
        } else if is_reference_relation(relation) {
            self.references
                .as_ref()
                .ok_or_else(|| invalid("UNKNOWN_REFERENCE_RELATION"))?
                .require_relation(relation)
        } else {
            self.definitions.require_relation(relation)
        }
    }
    fn open_cursor(
        self: Arc<Self>,
        relation: &str,
        control: SqlControl,
    ) -> MddResult<Box<dyn SqlFactCursor>> {
        if MetadataRelation::parse(relation).is_ok() {
            Arc::clone(&self.metadata).open_cursor(relation, control)
        } else if AnnotationRelation::parse(relation).is_some() {
            Arc::clone(
                self.annotations
                    .as_ref()
                    .ok_or_else(|| invalid("UNKNOWN_ANNOTATION_RELATION"))?,
            )
            .open_cursor(relation, control)
        } else if CodeRelation::parse(relation).is_ok() {
            Arc::clone(
                self.code
                    .as_ref()
                    .ok_or_else(|| invalid("UNKNOWN_CODE_RELATION"))?,
            )
            .open_cursor(relation, control)
        } else if is_reference_relation(relation) {
            Arc::clone(
                self.references
                    .as_ref()
                    .ok_or_else(|| invalid("UNKNOWN_REFERENCE_RELATION"))?,
            )
            .open_cursor(relation, control)
        } else {
            Arc::clone(&self.definitions).open_cursor(relation, control)
        }
    }
}

/// Source-bound encoded annotation facts. Encoded parameter slots do not by
/// themselves establish complete prototype-position coverage.
pub struct AnnotationSqlProvider {
    binding: SqlBinding,
    occurrences: Vec<Arc<mdd_facts::annotations::AnnotationFacts>>,
}
impl AnnotationSqlProvider {
    pub fn new(
        occurrences: Vec<Arc<mdd_facts::annotations::AnnotationFacts>>,
        epoch: DecimalU64,
    ) -> MddResult<Self> {
        let snapshot = occurrences
            .first()
            .ok_or_else(|| invalid("ANNOTATION_SCOPE_MUST_BE_EXPLICIT"))?
            .source()
            .snapshot_id
            .clone();
        let mut seen = BTreeSet::new();
        for facts in &occurrences {
            if facts.source().snapshot_id != snapshot
                || !seen.insert(&facts.source().dex_occurrence_id)
            {
                return Err(invalid("ANNOTATION_PROVIDER_SOURCE"));
            }
            if facts.annotation_coverage() != Completeness::Complete
                || facts.definitions().definition_coverage() != Completeness::Complete
                || facts.definitions().metadata().metadata_coverage() != Completeness::Complete
            {
                return Err(MddError::new(
                    ErrorCode::IncompleteFacts,
                    "sql.annotations",
                    "complete selected annotation facts are required",
                ));
            }
        }
        Ok(Self {
            binding: SqlBinding {
                provider_identity: opaque_id("sql-annotation-provider")?,
                snapshot_id: snapshot,
                catalog_epoch: epoch,
            },
            occurrences,
        })
    }
}
#[derive(Clone, Copy)]
enum AnnotationRelation {
    Items,
    Values,
    Owners,
    Sets,
    SetEntries,
    RefLists,
    RefEntries,
    ParameterLists,
    Directories,
    DirectoryEntries,
    DirectoryBindings,
}
impl AnnotationRelation {
    fn parse(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("native_annotation_items") {
            Some(Self::Items)
        } else if name.eq_ignore_ascii_case("native_encoded_value_nodes") {
            Some(Self::Values)
        } else if name.eq_ignore_ascii_case("native_annotation_owners") {
            Some(Self::Owners)
        } else if name.eq_ignore_ascii_case("native_annotation_sets") {
            Some(Self::Sets)
        } else if name.eq_ignore_ascii_case("native_annotation_set_entries") {
            Some(Self::SetEntries)
        } else if name.eq_ignore_ascii_case("native_annotation_ref_lists") {
            Some(Self::RefLists)
        } else if name.eq_ignore_ascii_case("native_annotation_ref_entries") {
            Some(Self::RefEntries)
        } else if name.eq_ignore_ascii_case("native_annotation_parameter_lists") {
            Some(Self::ParameterLists)
        } else if name.eq_ignore_ascii_case("native_annotation_directories") {
            Some(Self::Directories)
        } else if name.eq_ignore_ascii_case("native_annotation_directory_entries") {
            Some(Self::DirectoryEntries)
        } else if name.eq_ignore_ascii_case("native_annotation_directory_bindings") {
            Some(Self::DirectoryBindings)
        } else {
            None
        }
    }
}
struct AnnotationCursor {
    provider: Arc<AnnotationSqlProvider>,
    relation: AnnotationRelation,
    occurrence: usize,
    ordinal: usize,
    entry_ordinal: usize,
    control: SqlControl,
}
impl SqlFactCursor for AnnotationCursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
        use mdd_facts::AnnotationOwnerKind;
        let u = |v: u64| SqlValue::U64(DecimalU64(v));
        let optional = |v: Option<u32>| v.map_or(SqlValue::Null, |n| u(n.into()));
        while let Some(facts) = self.provider.occurrences.get(self.occurrence) {
            self.control.checkpoint(1, false)?;
            let data = facts.data();
            let occurrence = || scalar_text(&facts.source().dex_occurrence_id, &self.control);
            // Nested physical relationships use an independent cursor per set/list.
            // Empty containers produce no entry rows but retain their header rows.
            if matches!(
                self.relation,
                AnnotationRelation::SetEntries | AnnotationRelation::RefEntries
            ) {
                let (offset, length, entry) = match self.relation {
                    AnnotationRelation::SetEntries => match data.sets.get(self.ordinal) {
                        Some(set) => (
                            set.byte_offset,
                            set.annotation_offsets.len(),
                            set.annotation_offsets
                                .get(self.entry_ordinal)
                                .copied()
                                .map(Some),
                        ),
                        None => {
                            self.occurrence += 1;
                            self.ordinal = 0;
                            self.entry_ordinal = 0;
                            continue;
                        }
                    },
                    AnnotationRelation::RefEntries => match data.ref_lists.get(self.ordinal) {
                        Some(list) => (
                            list.byte_offset,
                            list.annotation_set_offsets.len(),
                            list.annotation_set_offsets.get(self.entry_ordinal).copied(),
                        ),
                        None => {
                            self.occurrence += 1;
                            self.ordinal = 0;
                            self.entry_ordinal = 0;
                            continue;
                        }
                    },
                    _ => unreachable!(),
                };
                if self.entry_ordinal >= length {
                    self.ordinal += 1;
                    self.entry_ordinal = 0;
                    continue;
                }
                let entry = entry.ok_or_else(|| {
                    MddError::new(
                        ErrorCode::InternalFault,
                        "sql.annotations",
                        "validated annotation entry missing",
                    )
                })?;
                let ordinal = u64::try_from(self.entry_ordinal)
                    .map_err(|_| quota("ANNOTATION_SQL_ROWS_OVERFLOW"))?;
                self.control.work(64)?;
                let row = vec![occurrence()?, u(offset.into()), u(ordinal), optional(entry)];
                self.entry_ordinal += 1;
                return Ok(Some(row));
            }
            if matches!(self.relation, AnnotationRelation::DirectoryEntries) {
                let Some(directory) = data.directories.get(self.ordinal) else {
                    self.occurrence += 1;
                    self.ordinal = 0;
                    self.entry_ordinal = 0;
                    continue;
                };
                let Some(entry) = directory.entries.get(self.entry_ordinal) else {
                    self.ordinal += 1;
                    self.entry_ordinal = 0;
                    continue;
                };
                let kind = match entry.kind {
                    AnnotationOwnerKind::Field => "field",
                    AnnotationOwnerKind::Method => "method",
                    AnnotationOwnerKind::Parameter => "parameter",
                    AnnotationOwnerKind::Class => {
                        return Err(MddError::new(
                            ErrorCode::InternalFault,
                            "sql.annotations",
                            "invalid directory entry kind",
                        ));
                    }
                };
                let ordinal = u64::try_from(self.entry_ordinal)
                    .map_err(|_| quota("ANNOTATION_SQL_ROWS_OVERFLOW"))?;
                self.control.work(80)?;
                let row = vec![
                    occurrence()?,
                    u(directory.byte_offset.into()),
                    u(ordinal),
                    scalar_text(kind, &self.control)?,
                    u(entry.local_index.into()),
                    u(entry.target_byte_offset.into()),
                ];
                self.entry_ordinal += 1;
                return Ok(Some(row));
            }
            let row = match self.relation {
                AnnotationRelation::Items => {
                    let Some(item) = data.annotation_items.get(self.ordinal) else {
                        self.occurrence += 1;
                        self.ordinal = 0;
                        continue;
                    };
                    self.control.work(96)?;
                    vec![
                        occurrence()?,
                        u(item.byte_offset.into()),
                        u(item.visibility.into()),
                        u(item.type_idx.into()),
                        u(u64::try_from(item.elements.len())
                            .map_err(|_| quota("ANNOTATION_SQL_ROWS_OVERFLOW"))?),
                        SqlValue::U64(item.encoded_range.byte_length),
                    ]
                }
                AnnotationRelation::Values => {
                    let Some(value) = data.values.get(self.ordinal) else {
                        self.occurrence += 1;
                        self.ordinal = 0;
                        continue;
                    };
                    self.control.work(160)?;
                    let integer = value
                        .value_i64
                        .as_ref()
                        .map(|v| scalar_text(v, &self.control))
                        .transpose()?
                        .unwrap_or(SqlValue::Null);
                    vec![
                        occurrence()?,
                        u(value.node_id.into()),
                        optional(value.annotation_byte_offset),
                        u(value.depth.into()),
                        u(value.ordinal.into()),
                        optional(value.name_idx),
                        scalar_text(value.kind.as_str(), &self.control)?,
                        u(value.value_arg.into()),
                        SqlValue::U64(value.encoded_range.byte_offset),
                        SqlValue::U64(value.encoded_range.byte_length),
                        optional(value.value_index),
                        integer,
                        value.float_bits.map_or(SqlValue::Null, SqlValue::U64),
                        value
                            .float_bit_width
                            .map_or(SqlValue::Null, |width| u(width.into())),
                    ]
                }
                AnnotationRelation::Owners => {
                    let Some(owner) = data.owner_bindings.get(self.ordinal) else {
                        self.occurrence += 1;
                        self.ordinal = 0;
                        continue;
                    };
                    self.control.work(112)?;
                    let kind = match owner.kind {
                        AnnotationOwnerKind::Class => "class",
                        AnnotationOwnerKind::Field => "field",
                        AnnotationOwnerKind::Method => "method",
                        AnnotationOwnerKind::Parameter => "parameter",
                    };
                    vec![
                        occurrence()?,
                        u(owner.class_def_idx.into()),
                        u(owner.class_idx.into()),
                        scalar_text(kind, &self.control)?,
                        u(owner.local_index.into()),
                        optional(owner.parameter_ordinal),
                        optional(owner.annotation_set_offset),
                        optional(owner.prototype_parameter_count),
                        owner
                            .parameter_position_in_prototype
                            .map_or(SqlValue::Null, SqlValue::Bool),
                    ]
                }
                AnnotationRelation::Sets => {
                    let Some(set) = data.sets.get(self.ordinal) else {
                        self.occurrence += 1;
                        self.ordinal = 0;
                        continue;
                    };
                    self.control.work(64)?;
                    vec![
                        occurrence()?,
                        u(set.byte_offset.into()),
                        u(u64::try_from(set.annotation_offsets.len())
                            .map_err(|_| quota("ANNOTATION_SQL_ROWS_OVERFLOW"))?),
                        SqlValue::U64(set.encoded_range.byte_length),
                    ]
                }
                AnnotationRelation::RefLists => {
                    let Some(list) = data.ref_lists.get(self.ordinal) else {
                        self.occurrence += 1;
                        self.ordinal = 0;
                        continue;
                    };
                    self.control.work(64)?;
                    vec![
                        occurrence()?,
                        u(list.byte_offset.into()),
                        u(u64::try_from(list.annotation_set_offsets.len())
                            .map_err(|_| quota("ANNOTATION_SQL_ROWS_OVERFLOW"))?),
                        SqlValue::U64(list.encoded_range.byte_length),
                    ]
                }
                AnnotationRelation::ParameterLists => {
                    let Some(list) = data.parameter_lists.get(self.ordinal) else {
                        self.occurrence += 1;
                        self.ordinal = 0;
                        continue;
                    };
                    self.control.work(96)?;
                    let coverage = match list.prototype_position_coverage {
                        Completeness::Complete => "complete",
                        Completeness::Partial => "partial",
                        Completeness::Unknown => "unknown",
                    };
                    vec![
                        occurrence()?,
                        u(list.class_def_idx.into()),
                        u(list.method_idx.into()),
                        u(list.ref_list_byte_offset.into()),
                        u(list.encoded_slot_count.into()),
                        u(list.prototype_parameter_count.into()),
                        SqlValue::Bool(list.encoded_slots_complete),
                        scalar_text(coverage, &self.control)?,
                    ]
                }
                AnnotationRelation::Directories => {
                    let Some(directory) = data.directories.get(self.ordinal) else {
                        self.occurrence += 1;
                        self.ordinal = 0;
                        continue;
                    };
                    self.control.work(88)?;
                    vec![
                        occurrence()?,
                        u(directory.byte_offset.into()),
                        optional(directory.class_annotation_set_offset),
                        u(directory.fields_size.into()),
                        u(directory.methods_size.into()),
                        u(directory.parameters_size.into()),
                        SqlValue::U64(directory.encoded_range.byte_length),
                    ]
                }
                AnnotationRelation::DirectoryBindings => {
                    let Some(binding) = data.directory_bindings.get(self.ordinal) else {
                        self.occurrence += 1;
                        self.ordinal = 0;
                        continue;
                    };
                    self.control.work(64)?;
                    vec![
                        occurrence()?,
                        u(binding.class_def_idx.into()),
                        u(binding.class_idx.into()),
                        u(binding.directory_byte_offset.into()),
                    ]
                }
                AnnotationRelation::SetEntries
                | AnnotationRelation::RefEntries
                | AnnotationRelation::DirectoryEntries => unreachable!(),
            };
            self.ordinal += 1;
            return Ok(Some(row));
        }
        Ok(None)
    }
}
impl SqlFactProvider for AnnotationSqlProvider {
    fn binding(&self) -> &SqlBinding {
        &self.binding
    }
    fn relations(&self) -> MddResult<Vec<SqlRelation>> {
        type Specification = (
            &'static str,
            &'static [(&'static str, SqlType, bool)],
            AnnotationRelation,
        );
        let specifications: [Specification; 11] = [
            (
                "native_annotation_items",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("annotation_byte_offset", SqlType::U64, false),
                    ("visibility", SqlType::U64, false),
                    ("type_idx", SqlType::U64, false),
                    ("element_count", SqlType::U64, false),
                    ("encoded_byte_length", SqlType::U64, false),
                ],
                AnnotationRelation::Items,
            ),
            (
                "native_encoded_value_nodes",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("node_id", SqlType::U64, false),
                    ("annotation_byte_offset", SqlType::U64, true),
                    ("depth", SqlType::U64, false),
                    ("ordinal", SqlType::U64, false),
                    ("name_idx", SqlType::U64, true),
                    ("kind", SqlType::Text, false),
                    ("value_arg", SqlType::U64, false),
                    ("value_byte_offset", SqlType::U64, false),
                    ("value_byte_length", SqlType::U64, false),
                    ("value_index", SqlType::U64, true),
                    ("value_i64", SqlType::Text, true),
                    ("float_bits", SqlType::U64, true),
                    ("float_bit_width", SqlType::U64, true),
                ],
                AnnotationRelation::Values,
            ),
            (
                "native_annotation_owners",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("class_def_idx", SqlType::U64, false),
                    ("class_type_idx", SqlType::U64, false),
                    ("kind", SqlType::Text, false),
                    ("local_index", SqlType::U64, false),
                    ("parameter_ordinal", SqlType::U64, true),
                    ("annotation_set_offset", SqlType::U64, true),
                    ("prototype_parameter_count", SqlType::U64, true),
                    ("parameter_position_in_prototype", SqlType::Bool, true),
                ],
                AnnotationRelation::Owners,
            ),
            (
                "native_annotation_sets",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("set_byte_offset", SqlType::U64, false),
                    ("entry_count", SqlType::U64, false),
                    ("encoded_byte_length", SqlType::U64, false),
                ],
                AnnotationRelation::Sets,
            ),
            (
                "native_annotation_set_entries",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("set_byte_offset", SqlType::U64, false),
                    ("ordinal", SqlType::U64, false),
                    ("annotation_byte_offset", SqlType::U64, false),
                ],
                AnnotationRelation::SetEntries,
            ),
            (
                "native_annotation_ref_lists",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("ref_list_byte_offset", SqlType::U64, false),
                    ("entry_count", SqlType::U64, false),
                    ("encoded_byte_length", SqlType::U64, false),
                ],
                AnnotationRelation::RefLists,
            ),
            (
                "native_annotation_ref_entries",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("ref_list_byte_offset", SqlType::U64, false),
                    ("ordinal", SqlType::U64, false),
                    ("set_byte_offset", SqlType::U64, true),
                ],
                AnnotationRelation::RefEntries,
            ),
            (
                "native_annotation_parameter_lists",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("class_def_idx", SqlType::U64, false),
                    ("method_idx", SqlType::U64, false),
                    ("ref_list_byte_offset", SqlType::U64, false),
                    ("encoded_slot_count", SqlType::U64, false),
                    ("prototype_parameter_count", SqlType::U64, false),
                    ("encoded_slots_complete", SqlType::Bool, false),
                    ("prototype_position_coverage", SqlType::Text, false),
                ],
                AnnotationRelation::ParameterLists,
            ),
            (
                "native_annotation_directories",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("directory_byte_offset", SqlType::U64, false),
                    ("class_annotation_set_offset", SqlType::U64, true),
                    ("fields_count", SqlType::U64, false),
                    ("methods_count", SqlType::U64, false),
                    ("parameters_count", SqlType::U64, false),
                    ("encoded_byte_length", SqlType::U64, false),
                ],
                AnnotationRelation::Directories,
            ),
            (
                "native_annotation_directory_entries",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("directory_byte_offset", SqlType::U64, false),
                    ("ordinal", SqlType::U64, false),
                    ("kind", SqlType::Text, false),
                    ("local_index", SqlType::U64, false),
                    ("target_byte_offset", SqlType::U64, false),
                ],
                AnnotationRelation::DirectoryEntries,
            ),
            (
                "native_annotation_directory_bindings",
                &[
                    ("dex_occurrence_id", SqlType::Text, false),
                    ("class_def_idx", SqlType::U64, false),
                    ("class_idx", SqlType::U64, false),
                    ("directory_byte_offset", SqlType::U64, false),
                ],
                AnnotationRelation::DirectoryBindings,
            ),
        ];
        specifications
            .into_iter()
            .map(|(name, cols, relation)| {
                let count = self
                    .occurrences
                    .iter()
                    .try_fold(0u64, |total, facts| {
                        let data = facts.data();
                        let n = match relation {
                            AnnotationRelation::Items => data.annotation_items.len(),
                            AnnotationRelation::Values => data.values.len(),
                            AnnotationRelation::Owners => data.owner_bindings.len(),
                            AnnotationRelation::Sets => data.sets.len(),
                            AnnotationRelation::RefLists => data.ref_lists.len(),
                            AnnotationRelation::ParameterLists => data.parameter_lists.len(),
                            AnnotationRelation::Directories => data.directories.len(),
                            AnnotationRelation::DirectoryBindings => data.directory_bindings.len(),
                            AnnotationRelation::DirectoryEntries => data
                                .directories
                                .iter()
                                .try_fold(0usize, |n, d| n.checked_add(d.entries.len()))?,
                            AnnotationRelation::SetEntries => {
                                data.sets.iter().try_fold(0usize, |n, s| {
                                    n.checked_add(s.annotation_offsets.len())
                                })?
                            }
                            AnnotationRelation::RefEntries => {
                                data.ref_lists.iter().try_fold(0usize, |n, l| {
                                    n.checked_add(l.annotation_set_offsets.len())
                                })?
                            }
                        };
                        total.checked_add(u64::try_from(n).ok()?)
                    })
                    .ok_or_else(|| quota("ANNOTATION_SQL_ROWS_OVERFLOW"))?;
                Ok(SqlRelation {
                    name: name.into(),
                    columns: cols
                        .iter()
                        .map(|(name, data_type, nullable)| SqlColumn {
                            id: (*name).into(),
                            name: (*name).into(),
                            data_type: *data_type,
                            nullable: *nullable,
                        })
                        .collect(),
                    required_layers: vec![
                        FactLayer::Metadata,
                        FactLayer::Structure,
                        FactLayer::Annotations,
                    ],
                    estimated_rows: Some(DecimalU64(count)),
                })
            })
            .collect()
    }
    fn require_relation(&self, relation: &str) -> MddResult<()> {
        if AnnotationRelation::parse(relation).is_none() {
            return Err(invalid("UNKNOWN_ANNOTATION_RELATION"));
        }
        for facts in &self.occurrences {
            if facts.annotation_coverage() != Completeness::Complete {
                return Err(MddError::new(
                    ErrorCode::IncompleteFacts,
                    "sql.annotations",
                    "annotation facts are incomplete",
                ));
            }
        }
        Ok(())
    }
    fn open_cursor(
        self: Arc<Self>,
        relation: &str,
        control: SqlControl,
    ) -> MddResult<Box<dyn SqlFactCursor>> {
        self.require_relation(relation)?;
        let relation = AnnotationRelation::parse(relation)
            .ok_or_else(|| invalid("UNKNOWN_ANNOTATION_RELATION"))?;
        Ok(Box::new(AnnotationCursor {
            provider: self,
            relation,
            occurrence: 0,
            ordinal: 0,
            entry_ordinal: 0,
            control,
        }))
    }
}

/// Physical code items for explicit complete DEX occurrence scopes. This does
/// not establish method ownership, inferred dispatch, or legacy compatibility.
pub struct CodeSqlProvider {
    binding: SqlBinding,
    occurrences: Vec<Arc<mdd_facts::code::CodeFacts>>,
}
impl CodeSqlProvider {
    pub fn new(
        occurrences: Vec<Arc<mdd_facts::code::CodeFacts>>,
        epoch: DecimalU64,
    ) -> MddResult<Self> {
        let snapshot = occurrences
            .first()
            .ok_or_else(|| invalid("CODE_SCOPE_MUST_BE_EXPLICIT"))?
            .source()
            .snapshot_id
            .clone();
        let mut seen = BTreeSet::new();
        for facts in &occurrences {
            if facts.source().snapshot_id != snapshot
                || !seen.insert(&facts.source().dex_occurrence_id)
            {
                return Err(invalid("CODE_PROVIDER_SOURCE"));
            }
            if facts.scope() != "complete-declared-code-map-v1"
                || facts.code_layout_coverage() != Completeness::Complete
                || facts.items().len() != facts.declared_map_code_item_count() as usize
            {
                return Err(MddError::new(
                    ErrorCode::IncompleteFacts,
                    "sql.code",
                    "complete physical code item map is required",
                ));
            }
        }
        Ok(Self {
            binding: SqlBinding {
                provider_identity: opaque_id("sql-code-provider")?,
                snapshot_id: snapshot,
                catalog_epoch: epoch,
            },
            occurrences,
        })
    }
}
struct CodeCursor {
    provider: Arc<CodeSqlProvider>,
    occurrence: usize,
    ordinal: usize,
    nested: usize,
    pair: usize,
    relation: CodeRelation,
    control: SqlControl,
}
#[derive(Clone, Copy)]
enum CodeRelation {
    Items,
    Bytes,
    Tries,
    Handlers,
    Catches,
}
impl CodeRelation {
    fn parse(name: &str) -> MddResult<Self> {
        if name.eq_ignore_ascii_case("native_code_items") {
            Ok(Self::Items)
        } else if name.eq_ignore_ascii_case("native_code_bytes") {
            Ok(Self::Bytes)
        } else if name.eq_ignore_ascii_case("native_code_tries") {
            Ok(Self::Tries)
        } else if name.eq_ignore_ascii_case("native_code_handlers") {
            Ok(Self::Handlers)
        } else if name.eq_ignore_ascii_case("native_code_catches") {
            Ok(Self::Catches)
        } else {
            Err(invalid("UNKNOWN_CODE_RELATION"))
        }
    }
}
// The cell limit and work counter do not reserve the owned Vec, SQLite's
// copies, allocator overhead, or RSS. Those require separate admission.
fn code_bytes(value: &[u8], control: &SqlControl) -> MddResult<SqlValue> {
    let len = u64::try_from(value.len()).map_err(|_| quota("CODE_SQL_CELL_OVERFLOW"))?;
    if len > control.inner.limits.max_cell_bytes {
        return Err(quota("CODE_SQL_CELL_BYTES"));
    }
    control.work(len)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(value.len())
        .map_err(|_| quota("CODE_SQL_ALLOCATION"))?;
    for chunk in value.chunks(4096) {
        control.checkpoint(1, false)?;
        result.extend_from_slice(chunk);
    }
    Ok(SqlValue::Bytes(result))
}
impl SqlFactCursor for CodeCursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
        while let Some(facts) = self.provider.occurrences.get(self.occurrence) {
            self.control.checkpoint(1, false)?;
            if let Some(item) = facts.items().get(self.ordinal) {
                self.control.work(128)?;
                let code = item.data();
                let occurrence = || scalar_text(&facts.source().dex_occurrence_id, &self.control);
                let u = |n| SqlValue::U64(DecimalU64(n));
                let row = if matches!(self.relation, CodeRelation::Bytes) {
                    vec![
                        occurrence()?,
                        SqlValue::U64(code.raw_range.byte_offset),
                        code_bytes(facts.raw_insns(self.ordinal)?, &self.control)?,
                        code_bytes(facts.raw_code_item(self.ordinal)?, &self.control)?,
                    ]
                } else if matches!(self.relation, CodeRelation::Items) {
                    vec![
                        occurrence()?,
                        scalar_text(item.code_item_id(), &self.control)?,
                        SqlValue::U64(code.raw_range.byte_offset),
                        SqlValue::U64(code.raw_range.byte_length),
                        SqlValue::U64(code.insns_range.byte_offset),
                        SqlValue::U64(code.insns_range.byte_length),
                        u(u64::from(code.registers_size)),
                        u(u64::from(code.ins_size)),
                        u(u64::from(code.outs_size)),
                        u(u64::from(code.insns_size_code_units)),
                        u(code.tries.len() as u64),
                        code.debug_info_byte_offset
                            .map_or(SqlValue::Null, SqlValue::U64),
                    ]
                } else {
                    match self.relation {
                        CodeRelation::Tries => {
                            let Some(entry) = code.tries.get(self.nested) else {
                                self.ordinal += 1;
                                self.nested = 0;
                                continue;
                            };
                            let ordinal = u64::try_from(self.nested)
                                .map_err(|_| quota("CODE_SQL_ROWS_OVERFLOW"))?;
                            let row = vec![
                                occurrence()?,
                                SqlValue::U64(code.raw_range.byte_offset),
                                u(ordinal),
                                SqlValue::U64(entry.byte_offset),
                                u(entry.start_code_unit.into()),
                                u(entry.code_unit_count.into()),
                                u(entry.handler_relative_byte_offset.into()),
                            ];
                            self.nested += 1;
                            return Ok(Some(row));
                        }
                        CodeRelation::Handlers => {
                            let Some(handler) = code.handlers.get(self.nested) else {
                                self.ordinal += 1;
                                self.nested = 0;
                                continue;
                            };
                            let ordinal = u64::try_from(self.nested)
                                .map_err(|_| quota("CODE_SQL_ROWS_OVERFLOW"))?;
                            let count = u64::try_from(handler.typed_catches.len())
                                .map_err(|_| quota("CODE_SQL_ROWS_OVERFLOW"))?;
                            let row = vec![
                                occurrence()?,
                                SqlValue::U64(code.raw_range.byte_offset),
                                u(ordinal),
                                SqlValue::U64(handler.byte_offset),
                                u(handler.relative_byte_offset.into()),
                                u(count),
                                handler
                                    .catch_all_address_code_units
                                    .map_or(SqlValue::Null, |n| u(n.into())),
                                SqlValue::U64(handler.raw_range.byte_length),
                            ];
                            self.nested += 1;
                            return Ok(Some(row));
                        }
                        CodeRelation::Catches => {
                            let Some(handler) = code.handlers.get(self.nested) else {
                                self.ordinal += 1;
                                self.nested = 0;
                                self.pair = 0;
                                continue;
                            };
                            let Some(catch) = handler.typed_catches.get(self.pair) else {
                                self.nested += 1;
                                self.pair = 0;
                                continue;
                            };
                            let handler_ordinal = u64::try_from(self.nested)
                                .map_err(|_| quota("CODE_SQL_ROWS_OVERFLOW"))?;
                            let catch_ordinal = u64::try_from(self.pair)
                                .map_err(|_| quota("CODE_SQL_ROWS_OVERFLOW"))?;
                            let row = vec![
                                occurrence()?,
                                SqlValue::U64(code.raw_range.byte_offset),
                                u(handler_ordinal),
                                u(catch_ordinal),
                                u(catch.type_idx.into()),
                                u(catch.address_code_units.into()),
                            ];
                            self.pair += 1;
                            return Ok(Some(row));
                        }
                        _ => unreachable!(),
                    }
                };
                self.ordinal += 1;
                return Ok(Some(row));
            }
            self.occurrence += 1;
            self.ordinal = 0;
            self.nested = 0;
            self.pair = 0;
        }
        Ok(None)
    }
}
impl SqlFactProvider for CodeSqlProvider {
    fn binding(&self) -> &SqlBinding {
        &self.binding
    }
    fn relations(&self) -> MddResult<Vec<SqlRelation>> {
        let count = self
            .occurrences
            .iter()
            .try_fold(0u64, |n, f| {
                n.checked_add(u64::try_from(f.items().len()).ok()?)
            })
            .ok_or_else(|| quota("CODE_SQL_ROWS_OVERFLOW"))?;
        let metadata = [
            ("dex_occurrence_id", SqlType::Text, false),
            ("code_item_id", SqlType::Text, false),
            ("code_byte_offset", SqlType::U64, false),
            ("code_byte_length", SqlType::U64, false),
            ("insns_byte_offset", SqlType::U64, false),
            ("insns_byte_length", SqlType::U64, false),
            ("registers_size", SqlType::U64, false),
            ("ins_size", SqlType::U64, false),
            ("outs_size", SqlType::U64, false),
            ("insns_size_code_units", SqlType::U64, false),
            ("tries_count", SqlType::U64, false),
            ("debug_info_byte_offset", SqlType::U64, true),
        ];
        let bytes = [
            ("dex_occurrence_id", SqlType::Text, false),
            ("code_byte_offset", SqlType::U64, false),
            ("insns_raw", SqlType::Bytes, false),
            ("code_item_raw", SqlType::Bytes, false),
        ];
        let tries = [
            ("dex_occurrence_id", SqlType::Text, false),
            ("code_byte_offset", SqlType::U64, false),
            ("try_ordinal", SqlType::U64, false),
            ("try_byte_offset", SqlType::U64, false),
            ("start_code_unit", SqlType::U64, false),
            ("code_unit_count", SqlType::U64, false),
            ("handler_relative_byte_offset", SqlType::U64, false),
        ];
        let handlers = [
            ("dex_occurrence_id", SqlType::Text, false),
            ("code_byte_offset", SqlType::U64, false),
            ("handler_ordinal", SqlType::U64, false),
            ("handler_byte_offset", SqlType::U64, false),
            ("relative_byte_offset", SqlType::U64, false),
            ("typed_catch_count", SqlType::U64, false),
            ("catch_all_address_code_units", SqlType::U64, true),
            ("handler_byte_length", SqlType::U64, false),
        ];
        let catches = [
            ("dex_occurrence_id", SqlType::Text, false),
            ("code_byte_offset", SqlType::U64, false),
            ("handler_ordinal", SqlType::U64, false),
            ("catch_ordinal", SqlType::U64, false),
            ("type_idx", SqlType::U64, false),
            ("address_code_units", SqlType::U64, false),
        ];
        let relation = |name: &str, cols: &[(&str, SqlType, bool)], estimated_rows| SqlRelation {
            name: name.into(),
            columns: cols
                .iter()
                .map(|(name, data_type, nullable)| SqlColumn {
                    id: (*name).into(),
                    name: (*name).into(),
                    data_type: *data_type,
                    nullable: *nullable,
                })
                .collect(),
            required_layers: vec![FactLayer::CodeLayout],
            estimated_rows,
        };
        Ok(vec![
            relation("native_code_items", &metadata, Some(DecimalU64(count))),
            relation("native_code_bytes", &bytes, Some(DecimalU64(count))),
            relation("native_code_tries", &tries, None),
            relation("native_code_handlers", &handlers, None),
            relation("native_code_catches", &catches, None),
        ])
    }
    fn require_relation(&self, relation: &str) -> MddResult<()> {
        CodeRelation::parse(relation).map(|_| ())
    }
    fn open_cursor(
        self: Arc<Self>,
        relation: &str,
        control: SqlControl,
    ) -> MddResult<Box<dyn SqlFactCursor>> {
        self.require_relation(relation)?;
        let relation = CodeRelation::parse(relation)?;
        Ok(Box::new(CodeCursor {
            provider: self,
            occurrence: 0,
            ordinal: 0,
            nested: 0,
            pair: 0,
            relation,
            control,
        }))
    }
}

/// Encoded reference sites for an explicit, complete set of DEX occurrences.
/// This does not infer runtime dispatch or legacy method-call rows.
pub struct ReferenceSqlProvider {
    binding: SqlBinding,
    occurrences: Vec<Arc<mdd_facts::references::ReferenceFacts>>,
}
fn is_reference_relation(name: &str) -> bool {
    name.eq_ignore_ascii_case("native_reference_sites")
        || name.eq_ignore_ascii_case("native_method_call_sites")
        || name.eq_ignore_ascii_case("native_dynamic_call_sites")
}
impl ReferenceSqlProvider {
    pub fn new(
        occurrences: Vec<Arc<mdd_facts::references::ReferenceFacts>>,
        epoch: DecimalU64,
    ) -> MddResult<Self> {
        let snapshot = occurrences
            .first()
            .ok_or_else(|| invalid("REFERENCE_SCOPE_MUST_BE_EXPLICIT"))?
            .source()
            .snapshot_id
            .clone();
        let mut seen = BTreeSet::new();
        for facts in &occurrences {
            if facts.source().snapshot_id != snapshot
                || !seen.insert(&facts.source().dex_occurrence_id)
            {
                return Err(invalid("REFERENCE_PROVIDER_SOURCE"));
            }
            facts.require_complete()?;
        }
        Ok(Self {
            binding: SqlBinding {
                provider_identity: opaque_id("sql-reference-provider")?,
                snapshot_id: snapshot,
                catalog_epoch: epoch,
            },
            occurrences,
        })
    }
}
struct ReferenceCursor {
    provider: Arc<ReferenceSqlProvider>,
    occurrence: usize,
    ordinal: usize,
    method_calls_only: bool,
    control: SqlControl,
}

/// One row per encoded invoke-custom call-site operand; bootstrap metadata
/// describes static input and is not the runtime dispatch target.
struct DynamicReferenceCursor {
    provider: Arc<ReferenceSqlProvider>,
    occurrence: usize,
    ordinal: usize,
    control: SqlControl,
}
impl SqlFactCursor for DynamicReferenceCursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
        use mdd_facts::InvokeKind;
        use mdd_facts::references::TargetKind;
        while let Some(facts) = self.provider.occurrences.get(self.occurrence) {
            self.control.checkpoint(1, false)?;
            if let Some(call) = facts.dynamic_calls().get(self.ordinal) {
                self.control.work(160)?;
                let site = facts
                    .sites()
                    .get(call.site_ordinal as usize)
                    .ok_or_else(|| {
                        MddError::new(
                            ErrorCode::InternalFault,
                            "sql.references",
                            "dynamic call site missing",
                        )
                    })?;
                if site.site_ordinal != call.site_ordinal
                    || site.target_kind != TargetKind::CallSite
                    || site.target_local_index != call.call_site_idx
                    || !matches!(
                        site.invoke_kind.as_ref(),
                        Some(InvokeKind::Custom | InvokeKind::CustomRange)
                    )
                {
                    return Err(MddError::new(
                        ErrorCode::InternalFault,
                        "sql.references",
                        "dynamic call site identity mismatch",
                    ));
                }
                let number = |n: u32| SqlValue::U64(DecimalU64(u64::from(n)));
                let row = vec![
                    scalar_text(&facts.source().dex_occurrence_id, &self.control)?,
                    number(call.site_ordinal),
                    number(site.caller_method_idx),
                    number(site.code_unit_pc),
                    number(site.operand_ordinal),
                    number(call.call_site_idx),
                    number(call.bootstrap_method_handle_idx),
                    scalar_text(call.bootstrap_target_kind.as_str(), &self.control)?,
                    number(call.bootstrap_target_index),
                    number(call.method_type_idx),
                    number(call.name_string_idx),
                    scalar_text(call.runtime_target_status, &self.control)?,
                ];
                self.ordinal += 1;
                return Ok(Some(row));
            }
            self.occurrence += 1;
            self.ordinal = 0;
        }
        Ok(None)
    }
}
impl SqlFactCursor for ReferenceCursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
        use mdd_facts::InvokeKind;
        use mdd_facts::references::TargetKind;
        while let Some(facts) = self.provider.occurrences.get(self.occurrence) {
            self.control.checkpoint(1, false)?;
            if let Some(site) = facts.sites().get(self.ordinal) {
                self.control.work(200)?;
                if self.method_calls_only
                    && (site.target_kind != TargetKind::Method || site.invoke_kind.is_none())
                {
                    self.ordinal += 1;
                    continue;
                }
                let target_kind = match site.target_kind {
                    TargetKind::String => "string",
                    TargetKind::Type => "type",
                    TargetKind::Field => "field",
                    TargetKind::Method => "method",
                    TargetKind::Prototype => "prototype",
                    TargetKind::CallSite => "call_site",
                    TargetKind::MethodHandle => "method_handle",
                };
                let invoke = match site.invoke_kind.as_ref() {
                    None => SqlValue::Null,
                    Some(kind) => scalar_text(
                        match kind {
                            InvokeKind::Ordinary => "ordinary",
                            InvokeKind::OrdinaryRange => "ordinary_range",
                            InvokeKind::Polymorphic => "polymorphic",
                            InvokeKind::PolymorphicRange => "polymorphic_range",
                            InvokeKind::Custom => "custom",
                            InvokeKind::CustomRange => "custom_range",
                        },
                        &self.control,
                    )?,
                };
                let u = |n: u64| SqlValue::U64(DecimalU64(n));
                let row = vec![
                    scalar_text(&facts.source().dex_occurrence_id, &self.control)?,
                    u(site.site_ordinal.into()),
                    u(site.caller_method_idx.into()),
                    u(site.class_def_idx.into()),
                    u(site.class_idx.into()),
                    SqlValue::U64(site.code_item_byte_offset),
                    u(site.code_unit_pc.into()),
                    u(site.instruction_ordinal.into()),
                    u(site.operand_ordinal.into()),
                    scalar_text(target_kind, &self.control)?,
                    u(site.target_local_index.into()),
                    u(site.opcode.into()),
                    scalar_text(&site.mnemonic, &self.control)?,
                    invoke,
                    SqlValue::U64(site.instruction_range.byte_offset),
                    SqlValue::U64(site.instruction_range.byte_length),
                    SqlValue::U64(site.operand_range.byte_offset),
                    SqlValue::U64(site.operand_range.byte_length),
                ];
                self.ordinal += 1;
                return Ok(Some(row));
            }
            self.occurrence += 1;
            self.ordinal = 0;
        }
        Ok(None)
    }
}
impl SqlFactProvider for ReferenceSqlProvider {
    fn binding(&self) -> &SqlBinding {
        &self.binding
    }
    fn relations(&self) -> MddResult<Vec<SqlRelation>> {
        let columns = [
            ("dex_occurrence_id", SqlType::Text, false),
            ("site_ordinal", SqlType::U64, false),
            ("caller_method_idx", SqlType::U64, false),
            ("class_def_idx", SqlType::U64, false),
            ("class_idx", SqlType::U64, false),
            ("code_item_byte_offset", SqlType::U64, false),
            ("code_unit_pc", SqlType::U64, false),
            ("instruction_ordinal", SqlType::U64, false),
            ("operand_ordinal", SqlType::U64, false),
            ("target_kind", SqlType::Text, false),
            ("target_local_index", SqlType::U64, false),
            ("opcode", SqlType::U64, false),
            ("mnemonic", SqlType::Text, false),
            ("invoke_kind", SqlType::Text, true),
            ("instruction_byte_offset", SqlType::U64, false),
            ("instruction_byte_length", SqlType::U64, false),
            ("operand_byte_offset", SqlType::U64, false),
            ("operand_byte_length", SqlType::U64, false),
        ];
        let count = self
            .occurrences
            .iter()
            .try_fold(0u64, |total, facts| {
                total.checked_add(u64::try_from(facts.sites().len()).ok()?)
            })
            .ok_or_else(|| quota("REFERENCE_SQL_ROWS_OVERFLOW"))?;
        let make_relation = |name: &str, method_calls_only: bool| SqlRelation {
            name: name.into(),
            columns: columns
                .iter()
                .map(|(name, data_type, nullable)| SqlColumn {
                    id: (*name).into(),
                    name: (*name).into(),
                    data_type: *data_type,
                    nullable: *nullable && !(method_calls_only && *name == "invoke_kind"),
                })
                .collect(),
            required_layers: vec![
                FactLayer::Metadata,
                FactLayer::Structure,
                FactLayer::CodeLayout,
                FactLayer::References,
            ],
            estimated_rows: Some(DecimalU64(count)),
        };
        // The total site count is an upper bound for the filtered relation.
        let dynamic_count = self
            .occurrences
            .iter()
            .try_fold(0u64, |total, facts| {
                total.checked_add(u64::try_from(facts.dynamic_calls().len()).ok()?)
            })
            .ok_or_else(|| quota("REFERENCE_SQL_ROWS_OVERFLOW"))?;
        let dynamic_columns = [
            ("dex_occurrence_id", SqlType::Text),
            ("site_ordinal", SqlType::U64),
            ("caller_method_idx", SqlType::U64),
            ("code_unit_pc", SqlType::U64),
            ("operand_ordinal", SqlType::U64),
            ("call_site_idx", SqlType::U64),
            ("bootstrap_method_handle_idx", SqlType::U64),
            ("bootstrap_target_kind", SqlType::Text),
            ("bootstrap_target_index", SqlType::U64),
            ("method_type_idx", SqlType::U64),
            ("name_string_idx", SqlType::U64),
            ("runtime_target_status", SqlType::Text),
        ];
        Ok(vec![
            make_relation("native_reference_sites", false),
            make_relation("native_method_call_sites", true),
            SqlRelation {
                name: "native_dynamic_call_sites".into(),
                columns: dynamic_columns
                    .iter()
                    .map(|(name, data_type)| SqlColumn {
                        id: (*name).into(),
                        name: (*name).into(),
                        data_type: *data_type,
                        nullable: false,
                    })
                    .collect(),
                required_layers: vec![
                    FactLayer::Metadata,
                    FactLayer::Structure,
                    FactLayer::CodeLayout,
                    FactLayer::References,
                ],
                estimated_rows: Some(DecimalU64(dynamic_count)),
            },
        ])
    }
    fn require_relation(&self, relation: &str) -> MddResult<()> {
        if !is_reference_relation(relation) {
            return Err(invalid("UNKNOWN_REFERENCE_RELATION"));
        }
        for facts in &self.occurrences {
            facts.require_complete()?;
        }
        Ok(())
    }
    fn open_cursor(
        self: Arc<Self>,
        relation: &str,
        control: SqlControl,
    ) -> MddResult<Box<dyn SqlFactCursor>> {
        self.require_relation(relation)?;
        if relation.eq_ignore_ascii_case("native_dynamic_call_sites") {
            return Ok(Box::new(DynamicReferenceCursor {
                provider: self,
                occurrence: 0,
                ordinal: 0,
                control,
            }));
        }
        Ok(Box::new(ReferenceCursor {
            provider: self,
            occurrence: 0,
            ordinal: 0,
            method_calls_only: relation.eq_ignore_ascii_case("native_method_call_sites"),
            control,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SqlBridge, control::SqlLimits, dialects::SqlDialect};
    use mdd_dex::strings::StringLimits;
    use mdd_input::{
        archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
        snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
    };
    #[test]
    fn annotation_directories_preserve_physical_entries_and_shared_bindings() {
        use mdd_dex::{annotations::AnnotationLimits, definitions::DefinitionLimits};
        use mdd_facts::{annotations::AnnotationFacts, definitions::DefinitionFacts};
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/annotations/generated");
        let specs = [
            "annotations-038.dex",
            "annotations-038.dex",
            "valid-orphan-empty-directory.dex",
            "valid-orphan-known-directory.dex",
            "valid-shared-empty-directory.dex",
        ]
        .into_iter()
        .map(|name| InputSpec {
            path: root.join(name),
            kind: InputKind::RawDex,
            expected_sha256: None,
        })
        .collect::<Vec<_>>();
        let snapshot = Snapshot::capture(&specs, CaptureLimits::default()).unwrap();
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
            facts.push(Arc::new(
                AnnotationFacts::build(definitions, AnnotationLimits::default()).unwrap(),
            ));
        }
        let bridge = SqlBridge::new(
            Arc::new(AnnotationSqlProvider::new(facts.clone(), DecimalU64(0)).unwrap()),
            SqlDialect::NativeV1,
            SqlLimits::default(),
        )
        .unwrap();
        let mut expected: [Vec<Vec<String>>; 3] = Default::default();
        let mut shared = false;
        for (fact, spec) in facts.iter().zip(&specs) {
            let bytes = std::fs::read(&spec.path).unwrap();
            let read = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            let source = &fact.source().dex_occurrence_id;
            for directory in &fact.data().directories {
                let at = directory.byte_offset as usize;
                let class_offset = read(at);
                let field = read(at + 4);
                let method = read(at + 8);
                let parameter = read(at + 12);
                let count = field as usize + method as usize + parameter as usize;
                assert_eq!(count, directory.entries.len());
                let nullable = if class_offset == 0 {
                    "<NULL>".into()
                } else {
                    class_offset.to_string()
                };
                expected[0].push(vec![
                    source.clone(),
                    directory.byte_offset.to_string(),
                    nullable,
                    field.to_string(),
                    method.to_string(),
                    parameter.to_string(),
                    (16 + 8 * count).to_string(),
                ]);
                for i in 0..count {
                    let kind = if i < field as usize {
                        "field"
                    } else if i < (field + method) as usize {
                        "method"
                    } else {
                        "parameter"
                    };
                    expected[1].push(vec![
                        source.clone(),
                        directory.byte_offset.to_string(),
                        i.to_string(),
                        kind.into(),
                        read(at + 16 + i * 8).to_string(),
                        read(at + 20 + i * 8).to_string(),
                    ]);
                }
            }
            let class_count = read(0x60) as usize;
            let class_offset = read(0x64) as usize;
            let mut offsets = std::collections::BTreeMap::new();
            for i in 0..class_count {
                let at = class_offset + i * 32;
                let directory = read(at + 20);
                if directory != 0 {
                    *offsets.entry(directory).or_insert(0usize) += 1;
                    expected[2].push(vec![
                        source.clone(),
                        i.to_string(),
                        read(at).to_string(),
                        directory.to_string(),
                    ]);
                }
            }
            shared |= offsets.values().any(|count| *count > 1);
        }
        assert!(shared, "shared directory fixture not exercised");
        assert!(expected[0].iter().any(|row| row[2] == "<NULL>"));
        assert!(expected[1].iter().any(|row| row[3] == "parameter"));
        for (i, name) in [
            "native_annotation_directories",
            "native_annotation_directory_entries",
            "native_annotation_directory_bindings",
        ]
        .iter()
        .enumerate()
        {
            let result = bridge.query(&format!("SELECT * FROM {name}")).unwrap();
            let mut actual = result
                .rows()
                .iter()
                .map(|row| {
                    row.iter()
                        .map(|value| match value {
                            SqlValue::Null => "<NULL>".to_owned(),
                            SqlValue::U64(n) => n.0.to_string(),
                            SqlValue::I64(n) => n.0.to_string(),
                            SqlValue::Text(v) => v.strict_utf8().unwrap(),
                            other => panic!("unexpected value: {other:?}"),
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            actual.sort();
            expected[i].sort();
            assert_eq!(actual, expected[i], "{name}");
        }
    }
    #[test]
    fn annotation_sets_and_ref_lists_preserve_physical_entries_and_empty_headers() {
        use mdd_dex::{annotations::AnnotationLimits, definitions::DefinitionLimits};
        use mdd_facts::{annotations::AnnotationFacts, definitions::DefinitionFacts};
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/annotations/generated");
        let specs = [
            "annotations-038.dex",
            "annotations-038.dex",
            "valid-orphan-empty-set.dex",
            "valid-orphan-empty-ref-list.dex",
            "bad-parameter-arity.dex",
            "bad-parameter-arity.dex",
        ]
        .into_iter()
        .map(|name| InputSpec {
            path: root.join(name),
            kind: InputKind::RawDex,
            expected_sha256: None,
        })
        .collect::<Vec<_>>();
        let snapshot = Snapshot::capture(&specs, CaptureLimits::default()).unwrap();
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
            let defs = DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap();
            facts.push(Arc::new(
                AnnotationFacts::build(defs, AnnotationLimits::default()).unwrap(),
            ));
        }
        let provider = Arc::new(AnnotationSqlProvider::new(facts.clone(), DecimalU64(0)).unwrap());
        let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        let mut expected: [Vec<Vec<String>>; 5] = Default::default();
        for (fact, spec) in facts.iter().zip(&specs) {
            // Independent raw little-endian decode of the physical containers;
            // start-offset validation remains the parser's separate responsibility.
            let bytes = std::fs::read(&spec.path).unwrap();
            let read_u32 = |offset: usize| -> u32 {
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
            };
            let source = &fact.source().dex_occurrence_id;
            for set in &fact.data().sets {
                let start = set.byte_offset as usize;
                assert_eq!(read_u32(start) as usize, set.annotation_offsets.len());
                for (ordinal, value) in set.annotation_offsets.iter().enumerate() {
                    assert_eq!(read_u32(start + 4 + ordinal * 4), *value);
                }
                expected[0].push(vec![
                    source.clone(),
                    set.byte_offset.to_string(),
                    set.annotation_offsets.len().to_string(),
                    set.encoded_range.byte_length.0.to_string(),
                ]);
                for (ordinal, offset) in set.annotation_offsets.iter().enumerate() {
                    expected[1].push(vec![
                        source.clone(),
                        set.byte_offset.to_string(),
                        ordinal.to_string(),
                        offset.to_string(),
                    ]);
                }
            }
            for list in &fact.data().ref_lists {
                let start = list.byte_offset as usize;
                assert_eq!(read_u32(start) as usize, list.annotation_set_offsets.len());
                for (ordinal, value) in list.annotation_set_offsets.iter().enumerate() {
                    assert_eq!(read_u32(start + 4 + ordinal * 4), value.unwrap_or(0));
                }
                expected[2].push(vec![
                    source.clone(),
                    list.byte_offset.to_string(),
                    list.annotation_set_offsets.len().to_string(),
                    list.encoded_range.byte_length.0.to_string(),
                ]);
                for (ordinal, offset) in list.annotation_set_offsets.iter().enumerate() {
                    expected[3].push(vec![
                        source.clone(),
                        list.byte_offset.to_string(),
                        ordinal.to_string(),
                        offset.map_or("<NULL>".to_owned(), |v| v.to_string()),
                    ]);
                }
            }
            for list in &fact.data().parameter_lists {
                let coverage = match list.prototype_position_coverage {
                    Completeness::Complete => "complete",
                    Completeness::Partial => "partial",
                    Completeness::Unknown => "unknown",
                };
                expected[4].push(vec![
                    source.clone(),
                    list.class_def_idx.to_string(),
                    list.method_idx.to_string(),
                    list.ref_list_byte_offset.to_string(),
                    list.encoded_slot_count.to_string(),
                    list.prototype_parameter_count.to_string(),
                    u8::from(list.encoded_slots_complete).to_string(),
                    coverage.into(),
                ]);
            }
        }
        assert!(
            expected[0].iter().any(|r| r[2] == "0"),
            "physical empty set fixture missing"
        );
        assert!(
            expected[2].iter().any(|r| r[2] == "0"),
            "physical empty ref-list fixture missing"
        );
        assert!(
            expected[3].iter().any(|r| r[3] == "<NULL>"),
            "encoded null slot fixture missing"
        );
        assert!(
            expected[4].iter().any(|r| r[7] != "complete"),
            "unknown parameter coverage fixture missing"
        );
        let short_source = &facts.last().unwrap().source().dex_occurrence_id;
        let owners = bridge.query("SELECT dex_occurrence_id,kind,parameter_ordinal,parameter_position_in_prototype FROM native_annotation_owners").unwrap();
        let short_owners: Vec<_> = owners.rows().iter().filter(|row| {
            matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == *short_source)
                && matches!(&row[1], SqlValue::Text(text) if text.strict_utf8().unwrap() == "parameter")
        }).collect();
        assert_eq!(short_owners.len(), 2);
        for row in short_owners {
            assert_eq!(row[2], SqlValue::U64(DecimalU64(0)));
            // NULL denotes unproven position; the parameter-list relation
            // below separately exposes the authoritative Unknown coverage.
            assert_eq!(row[3], SqlValue::Null);
        }
        let lists = bridge.query("SELECT dex_occurrence_id,prototype_position_coverage FROM native_annotation_parameter_lists").unwrap();
        let short_lists: Vec<_> = lists.rows().iter().filter(|row| {
            matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == *short_source)
        }).collect();
        assert_eq!(short_lists.len(), 2);
        assert!(short_lists.iter().all(|row| matches!(&row[1], SqlValue::Text(text) if text.strict_utf8().unwrap() == "unknown")));
        // Coverage must be associated through all source-local keys; NULL
        // alone is not a proof of an absent or mapped prototype parameter.
        let short_sources: std::collections::BTreeSet<_> = facts[facts.len() - 2..]
            .iter()
            .map(|f| f.source().dex_occurrence_id.clone())
            .collect();
        assert_eq!(short_sources.len(), 2);
        let joined = bridge.query("SELECT o.dex_occurrence_id,o.class_def_idx,o.local_index,o.kind,o.parameter_ordinal,o.parameter_position_in_prototype,p.dex_occurrence_id,p.class_def_idx,p.method_idx,p.prototype_position_coverage FROM native_annotation_owners o JOIN native_annotation_parameter_lists p ON o.dex_occurrence_id=p.dex_occurrence_id AND o.class_def_idx=p.class_def_idx AND o.local_index=p.method_idx").unwrap();
        let mut matches =
            std::collections::BTreeMap::<String, std::collections::BTreeSet<u64>>::new();
        for row in joined.rows() {
            let SqlValue::Text(source) = &row[0] else {
                panic!("missing occurrence")
            };
            let source = source.strict_utf8().unwrap();
            if !short_sources.contains(&source)
                || !matches!(&row[3], SqlValue::Text(text) if text.strict_utf8().unwrap() == "parameter")
            {
                continue;
            }
            assert_eq!(row[0], row[6]);
            assert_eq!(row[1], row[7]);
            assert_eq!(row[2], row[8]);
            assert_eq!(row[4], SqlValue::U64(DecimalU64(0)));
            assert_eq!(row[5], SqlValue::Null);
            assert!(
                matches!(&row[9], SqlValue::Text(text) if text.strict_utf8().unwrap() == "unknown")
            );
            let SqlValue::U64(DecimalU64(method)) = row[2] else {
                panic!("missing method")
            };
            assert!(matches.entry(source).or_default().insert(method));
        }
        assert_eq!(matches.len(), 2);
        assert!(
            matches
                .values()
                .all(|methods| methods == &std::collections::BTreeSet::from([0, 1]))
        );
        for (index, name) in [
            "native_annotation_sets",
            "native_annotation_set_entries",
            "native_annotation_ref_lists",
            "native_annotation_ref_entries",
            "native_annotation_parameter_lists",
        ]
        .iter()
        .enumerate()
        {
            let result = bridge.query(&format!("SELECT * FROM {name}")).unwrap();
            let mut actual = result
                .rows()
                .iter()
                .map(|row| {
                    row.iter()
                        .map(|value| match value {
                            SqlValue::Null => "<NULL>".to_owned(),
                            SqlValue::U64(n) => n.0.to_string(),
                            SqlValue::I64(n) => n.0.to_string(),
                            SqlValue::Bool(v) => u8::from(*v).to_string(),
                            SqlValue::Text(text) => text.strict_utf8().unwrap(),
                            other => panic!("unexpected cell: {other:?}"),
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            actual.sort();
            expected[index].sort();
            assert_eq!(actual, expected[index], "{name}");
        }
    }
    #[test]
    fn native_annotations_preserve_occurrences_values_and_owner_slots() {
        use mdd_dex::{annotations::AnnotationLimits, definitions::DefinitionLimits};
        use mdd_facts::{annotations::AnnotationFacts, definitions::DefinitionFacts};
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/annotations/generated/annotations-038.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let mut metas = Vec::new();
        let mut defs = Vec::new();
        let mut facts = Vec::new();
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let meta =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            let definition =
                DefinitionFacts::build(meta.clone(), DefinitionLimits::default()).unwrap();
            facts.push(Arc::new(
                AnnotationFacts::build(definition.clone(), AnnotationLimits::default()).unwrap(),
            ));
            metas.push(Arc::new(meta));
            defs.push(Arc::new(definition));
        }
        let annotations =
            Arc::new(AnnotationSqlProvider::new(facts.clone(), DecimalU64(4)).unwrap());
        let make_combined = || {
            CombinedSqlProvider::new(
                Arc::new(MetadataSqlProvider::new(metas.clone(), DecimalU64(4)).unwrap()),
                Arc::new(DefinitionSqlProvider::new(defs.clone(), DecimalU64(4)).unwrap()),
            )
            .unwrap()
        };
        let provider = Arc::new(
            make_combined()
                .with_annotations(annotations.clone())
                .unwrap(),
        );
        let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        for (table, expected) in [
            (
                "native_annotation_items",
                facts
                    .iter()
                    .map(|f| f.data().annotation_items.len())
                    .sum::<usize>(),
            ),
            (
                "native_encoded_value_nodes",
                facts.iter().map(|f| f.data().values.len()).sum::<usize>(),
            ),
            (
                "native_annotation_owners",
                facts
                    .iter()
                    .map(|f| f.data().owner_bindings.len())
                    .sum::<usize>(),
            ),
        ] {
            let result = bridge.query(&format!("SELECT * FROM {table}")).unwrap();
            assert_eq!(result.rows().len(), expected, "{table}");
        }
        let values = bridge.query("SELECT dex_occurrence_id,node_id,annotation_byte_offset,float_bits,float_bit_width FROM native_encoded_value_nodes").unwrap();
        let mut observed = BTreeSet::new();
        for row in values.rows() {
            let SqlValue::Text(source) = &row[0] else {
                panic!("source type")
            };
            let SqlValue::U64(node) = row[1] else {
                panic!("node type")
            };
            let selected = facts
                .iter()
                .find(|f| f.source().dex_occurrence_id == source.strict_utf8().unwrap())
                .unwrap();
            let expected = &selected.data().values[node.0 as usize];
            assert_eq!(
                row[2],
                expected
                    .annotation_byte_offset
                    .map_or(SqlValue::Null, |v| SqlValue::U64(DecimalU64(v.into())))
            );
            assert_eq!(
                row[3],
                expected.float_bits.map_or(SqlValue::Null, SqlValue::U64)
            );
            assert_eq!(
                row[4],
                expected
                    .float_bit_width
                    .map_or(SqlValue::Null, |v| SqlValue::U64(DecimalU64(v.into())))
            );
            assert!(observed.insert((source.strict_utf8().unwrap(), node.0)));
        }
        let owners = bridge.query("SELECT dex_occurrence_id,kind,local_index,parameter_ordinal,annotation_set_offset,parameter_position_in_prototype FROM native_annotation_owners").unwrap();
        assert!(!owners.rows().is_empty());
        assert!(owners.rows().iter().any(|row| row[3] != SqlValue::Null));
        let mut actual_owners = owners
            .rows()
            .iter()
            .map(|row| {
                let SqlValue::Text(source) = &row[0] else {
                    panic!("owner source type")
                };
                let SqlValue::Text(kind) = &row[1] else {
                    panic!("owner kind type")
                };
                let SqlValue::U64(index) = row[2] else {
                    panic!("owner index type")
                };
                let numeric = |v: &SqlValue| match v {
                    SqlValue::Null => None,
                    SqlValue::U64(n) => Some(n.0),
                    _ => panic!("owner optional type"),
                };
                let position = match &row[5] {
                    SqlValue::Null => None,
                    SqlValue::Bool(v) => Some(*v),
                    SqlValue::I64(v) if v.0 == 0 || v.0 == 1 => Some(v.0 == 1),
                    _ => panic!("owner position type"),
                };
                (
                    source.strict_utf8().unwrap(),
                    kind.strict_utf8().unwrap(),
                    index.0,
                    numeric(&row[3]),
                    numeric(&row[4]),
                    position,
                )
            })
            .collect::<Vec<_>>();
        let mut expected_owners = Vec::new();
        for fact in &facts {
            for owner in &fact.data().owner_bindings {
                let kind = match owner.kind {
                    mdd_dex::annotations::AnnotationOwnerKind::Class => "class",
                    mdd_dex::annotations::AnnotationOwnerKind::Field => "field",
                    mdd_dex::annotations::AnnotationOwnerKind::Method => "method",
                    mdd_dex::annotations::AnnotationOwnerKind::Parameter => "parameter",
                };
                expected_owners.push((
                    fact.source().dex_occurrence_id.clone(),
                    kind.to_string(),
                    owner.local_index.into(),
                    owner.parameter_ordinal.map(u64::from),
                    owner.annotation_set_offset.map(u64::from),
                    owner.parameter_position_in_prototype,
                ));
            }
        }
        actual_owners.sort();
        expected_owners.sort();
        assert_eq!(actual_owners, expected_owners);
        let partial =
            Arc::new(AnnotationSqlProvider::new(vec![facts[0].clone()], DecimalU64(4)).unwrap());
        assert!(make_combined().with_annotations(partial).is_err());
        assert!(
            AnnotationSqlProvider::new(vec![facts[0].clone(), facts[0].clone()], DecimalU64(4))
                .is_err()
        );
        let wrong_epoch = Arc::new(AnnotationSqlProvider::new(facts, DecimalU64(5)).unwrap());
        assert!(make_combined().with_annotations(wrong_epoch).is_err());
    }
    #[test]
    fn combined_references_and_code_preserve_shared_owners_and_occurrences() {
        use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits};
        use mdd_facts::{
            code::CodeFacts,
            references::{ReferenceFacts, ReferenceLimits},
        };
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/references/generated/shared-code-035.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let (mut metas, mut definitions, mut codes, mut references) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let meta =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            let defs = DefinitionFacts::build(meta.clone(), DefinitionLimits::default()).unwrap();
            let code =
                CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
                    .unwrap();
            let refs =
                ReferenceFacts::build(defs.clone(), code.clone(), ReferenceLimits::default())
                    .unwrap();
            metas.push(Arc::new(meta));
            definitions.push(Arc::new(defs));
            codes.push(Arc::new(code));
            references.push(Arc::new(refs));
        }
        let mut expected = Vec::new();
        for (refs, code) in references.iter().zip(&codes) {
            for site in refs.sites() {
                let index = code
                    .items()
                    .iter()
                    .position(|item| {
                        item.data().raw_range.byte_offset == site.code_item_byte_offset
                    })
                    .unwrap();
                expected.push((
                    refs.source().dex_occurrence_id.clone(),
                    u64::from(site.caller_method_idx),
                    site.code_item_byte_offset.0,
                    u64::from(site.code_unit_pc),
                    u64::from(site.operand_ordinal),
                    code.raw_insns(index).unwrap().to_vec(),
                ));
            }
        }
        expected.sort();
        assert!(!expected.is_empty());
        assert_ne!(
            references[0].source().dex_occurrence_id,
            references[1].source().dex_occurrence_id
        );
        let callers: std::collections::BTreeSet<_> = expected.iter().map(|item| item.1).collect();
        assert!(
            callers.len() >= 2,
            "fixture must exercise shared-body owners"
        );
        for reverse in [false, true] {
            let combined = CombinedSqlProvider::new(
                Arc::new(MetadataSqlProvider::new(metas.clone(), DecimalU64(7)).unwrap()),
                Arc::new(DefinitionSqlProvider::new(definitions.clone(), DecimalU64(7)).unwrap()),
            )
            .unwrap();
            let code = Arc::new(CodeSqlProvider::new(codes.clone(), DecimalU64(7)).unwrap());
            let refs =
                Arc::new(ReferenceSqlProvider::new(references.clone(), DecimalU64(7)).unwrap());
            let combined = if reverse {
                combined
                    .with_references(refs)
                    .unwrap()
                    .with_code(code)
                    .unwrap()
            } else {
                combined
                    .with_code(code)
                    .unwrap()
                    .with_references(refs)
                    .unwrap()
            };
            let bridge = SqlBridge::new(
                Arc::new(combined),
                SqlDialect::NativeV1,
                SqlLimits::default(),
            )
            .unwrap();
            let result = bridge.query("SELECT r.dex_occurrence_id,r.caller_method_idx,r.code_item_byte_offset,r.code_unit_pc,r.operand_ordinal,b.insns_raw FROM native_reference_sites r JOIN native_method_definitions m ON r.dex_occurrence_id=m.dex_occurrence_id AND r.caller_method_idx=m.method_idx AND r.code_item_byte_offset=m.code_byte_offset JOIN native_code_bytes b ON r.dex_occurrence_id=b.dex_occurrence_id AND r.code_item_byte_offset=b.code_byte_offset").unwrap();
            let mut actual: Vec<_> = result
                .rows()
                .iter()
                .map(
                    |row| match (&row[0], &row[1], &row[2], &row[3], &row[4], &row[5]) {
                        (
                            SqlValue::Text(source),
                            SqlValue::U64(caller),
                            SqlValue::U64(offset),
                            SqlValue::U64(pc),
                            SqlValue::U64(ordinal),
                            SqlValue::Bytes(bytes),
                        ) => (
                            source.strict_utf8().unwrap(),
                            caller.0,
                            offset.0,
                            pc.0,
                            ordinal.0,
                            bytes.clone(),
                        ),
                        _ => panic!("unexpected result type"),
                    },
                )
                .collect();
            actual.sort();
            assert_eq!(actual, expected);
        }
    }
    #[test]
    fn combined_code_items_require_same_scope_and_keep_shared_owners() {
        use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits};
        use mdd_facts::code::CodeFacts;
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/references/generated/shared-code-035.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input.clone()], CaptureLimits::default()).unwrap();
        let (mut metas, mut defs, mut codes) = (Vec::new(), Vec::new(), Vec::new());
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let metadata =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            defs.push(Arc::new(
                DefinitionFacts::build(metadata.clone(), DefinitionLimits::default()).unwrap(),
            ));
            metas.push(Arc::new(metadata));
            codes.push(Arc::new(
                CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
                    .unwrap(),
            ));
        }
        let base = || {
            CombinedSqlProvider::new(
                Arc::new(MetadataSqlProvider::new(metas.clone(), DecimalU64(7)).unwrap()),
                Arc::new(DefinitionSqlProvider::new(defs.clone(), DecimalU64(7)).unwrap()),
            )
            .unwrap()
        };
        let partial =
            Arc::new(CodeSqlProvider::new(vec![codes[0].clone()], DecimalU64(7)).unwrap());
        assert_eq!(
            base().with_code(partial).err().unwrap().code,
            ErrorCode::InvalidArgument
        );
        let wrong_epoch = Arc::new(CodeSqlProvider::new(codes.clone(), DecimalU64(8)).unwrap());
        assert_eq!(
            base().with_code(wrong_epoch).err().unwrap().code,
            ErrorCode::InvalidArgument
        );
        let other = Snapshot::capture(&[input], CaptureLimits::default()).unwrap();
        let inv = ArchiveInventory::build(
            &other.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let foreign = Arc::new(
            CodeSqlProvider::new(
                vec![Arc::new(
                    CodeFacts::build_all_code_items(&other, &inv, 0, CodeLimits::default())
                        .unwrap(),
                )],
                DecimalU64(7),
            )
            .unwrap(),
        );
        assert_eq!(
            base().with_code(foreign).err().unwrap().code,
            ErrorCode::InvalidArgument
        );
        let code = Arc::new(CodeSqlProvider::new(codes.clone(), DecimalU64(7)).unwrap());
        assert_eq!(
            base()
                .with_code(code.clone())
                .unwrap()
                .with_code(code.clone())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let bridge = SqlBridge::new(
            Arc::new(base().with_code(code).unwrap()),
            SqlDialect::NativeV1,
            SqlLimits::default(),
        )
        .unwrap();
        let result = bridge.query("SELECT m.dex_occurrence_id,m.method_idx,c.code_byte_offset,b.insns_raw FROM native_method_definitions m JOIN native_code_items c ON m.dex_occurrence_id=c.dex_occurrence_id AND m.code_byte_offset=c.code_byte_offset JOIN native_code_bytes b ON c.dex_occurrence_id=b.dex_occurrence_id AND c.code_byte_offset=b.code_byte_offset").unwrap();
        let mut expected = Vec::new();
        for (definitions, facts) in defs.iter().zip(&codes) {
            for method in &definitions.definitions().method_definitions {
                if let mdd_dex::definitions::MethodBody::Present {
                    code_byte_offset, ..
                } = method.body
                {
                    let ordinal = facts
                        .items()
                        .iter()
                        .position(|item| item.data().raw_range.byte_offset == code_byte_offset)
                        .unwrap();
                    expected.push((
                        facts.source().dex_occurrence_id.clone(),
                        u64::from(method.method_idx),
                        code_byte_offset.0,
                        facts.raw_insns(ordinal).unwrap().to_vec(),
                    ));
                }
            }
        }
        let actual: Vec<_> = result
            .rows()
            .iter()
            .map(|row| match (&row[0], &row[1], &row[2], &row[3]) {
                (
                    SqlValue::Text(source),
                    SqlValue::U64(method),
                    SqlValue::U64(offset),
                    SqlValue::Bytes(bytes),
                ) => (
                    source.strict_utf8().unwrap(),
                    method.0,
                    offset.0,
                    bytes.clone(),
                ),
                _ => panic!("unexpected joined row"),
            })
            .collect();
        let mut actual = actual;
        actual.sort();
        expected.sort();
        assert!(!expected.is_empty());
        assert_eq!(actual, expected);
    }
    #[test]
    fn native_code_try_handlers_preserve_physical_offsets_and_catches() {
        use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits};
        use mdd_facts::code::CodeFacts;
        fn row_for<'a>(rows: &'a [Vec<SqlValue>], id: &str) -> &'a [SqlValue] {
            rows.iter()
                .find(|row| matches!(&row[0], SqlValue::Text(s) if s.strict_utf8().unwrap() == id))
                .unwrap()
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for (path, typed) in [
            (
                "tests/fixtures/owned_try/generated/owned-try-even.dex",
                false,
            ),
            (
                "tests/fixtures/owned_try/generated/owned-try-odd.dex",
                false,
            ),
            (
                "artifacts/mdd-031-audit/native-code-handlers-20261030/typed-catch.dex",
                true,
            ),
        ] {
            let path = root.join(path);
            let raw = std::fs::read(&path).unwrap();
            let words = u32::from_le_bytes(raw[248..252].try_into().unwrap()) as usize;
            let tries_offset = 252 + words * 2 + (words % 2) * 2;
            let start = u32::from_le_bytes(raw[tries_offset..tries_offset + 4].try_into().unwrap());
            let units =
                u16::from_le_bytes(raw[tries_offset + 4..tries_offset + 6].try_into().unwrap());
            let handler_rel =
                u16::from_le_bytes(raw[tries_offset + 6..tries_offset + 8].try_into().unwrap());
            let handlers_offset = tries_offset + 8;
            assert_eq!(raw[handlers_offset], 1); // one handler in the independent fixture
            assert_eq!(handler_rel, 1);
            let encoded = if typed {
                &[1u8, 1, 0, 2][..]
            } else {
                &[1u8, 0, 2][..]
            };
            assert_eq!(
                &raw[handlers_offset..handlers_offset + encoded.len()],
                encoded
            );
            let spec = InputSpec {
                path,
                kind: InputKind::RawDex,
                expected_sha256: None,
            };
            let snapshot =
                Snapshot::capture(&[spec.clone(), spec], CaptureLimits::default()).unwrap();
            let mut codes = Vec::new();
            let mut metas = Vec::new();
            let mut defs = Vec::new();
            for source in snapshot.sources() {
                let inventory = ArchiveInventory::build(
                    source,
                    InventoryPolicy::default(),
                    ArchiveLimits::default(),
                )
                .unwrap();
                let metadata =
                    MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default())
                        .unwrap();
                defs.push(Arc::new(
                    DefinitionFacts::build(metadata.clone(), DefinitionLimits::default()).unwrap(),
                ));
                metas.push(Arc::new(metadata));
                codes.push(Arc::new(
                    CodeFacts::build_all_code_items(
                        &snapshot,
                        &inventory,
                        0,
                        CodeLimits::default(),
                    )
                    .unwrap(),
                ));
            }
            let code_provider =
                Arc::new(CodeSqlProvider::new(codes.clone(), DecimalU64(1)).unwrap());
            let bridge = SqlBridge::new(
                code_provider.clone(),
                SqlDialect::NativeV1,
                SqlLimits::default(),
            )
            .unwrap();
            let combined = SqlBridge::new(
                Arc::new(
                    CombinedSqlProvider::new(
                        Arc::new(MetadataSqlProvider::new(metas, DecimalU64(1)).unwrap()),
                        Arc::new(DefinitionSqlProvider::new(defs, DecimalU64(1)).unwrap()),
                    )
                    .unwrap()
                    .with_code(code_provider)
                    .unwrap(),
                ),
                SqlDialect::NativeV1,
                SqlLimits::default(),
            )
            .unwrap();
            let tries = bridge.query("SELECT dex_occurrence_id,code_byte_offset,try_ordinal,try_byte_offset,start_code_unit,code_unit_count,handler_relative_byte_offset FROM native_code_tries").unwrap();
            let handlers = bridge.query("SELECT dex_occurrence_id,code_byte_offset,handler_ordinal,handler_byte_offset,relative_byte_offset,typed_catch_count,catch_all_address_code_units,handler_byte_length FROM native_code_handlers").unwrap();
            let catches = bridge.query("SELECT dex_occurrence_id,code_byte_offset,handler_ordinal,catch_ordinal,type_idx,address_code_units FROM native_code_catches").unwrap();
            assert_eq!(tries.rows().len(), 2);
            assert_eq!(handlers.rows().len(), 2);
            assert_eq!(catches.rows().len(), if typed { 2 } else { 0 });
            for table in [
                "native_code_tries",
                "native_code_handlers",
                "native_code_catches",
            ] {
                let query = format!("SELECT * FROM {table}");
                let direct = bridge.query(&query).unwrap();
                let via_combined = combined.query(&query).unwrap();
                assert_eq!(direct.rows().len(), via_combined.rows().len());
                for facts in &codes {
                    let id = &facts.source().dex_occurrence_id;
                    if direct.rows().iter().any(|row| matches!(&row[0], SqlValue::Text(s) if s.strict_utf8().unwrap() == *id)) {
                        assert_eq!(row_for(direct.rows(), id), row_for(via_combined.rows(), id));
                    }
                }
            }
            let u = |v| SqlValue::U64(DecimalU64(v));
            for facts in &codes {
                let id = &facts.source().dex_occurrence_id;
                assert_eq!(
                    &row_for(tries.rows(), id)[1..],
                    &[
                        u(236),
                        u(0),
                        u(tries_offset as u64),
                        u(start.into()),
                        u(units.into()),
                        u(handler_rel.into())
                    ]
                );
                assert_eq!(
                    &row_for(handlers.rows(), id)[1..],
                    &[
                        u(236),
                        u(0),
                        u((handlers_offset + 1) as u64),
                        u(1),
                        u(u64::from(typed)),
                        if typed { SqlValue::Null } else { u(2) },
                        u((encoded.len() - 1) as u64)
                    ]
                );
                if typed {
                    assert_eq!(
                        &row_for(catches.rows(), id)[1..],
                        &[u(236), u(0), u(0), u(0), u(2)]
                    );
                }
            }
        }
    }

    #[test]
    fn native_code_items_preserve_physical_bytes_and_scope() {
        use mdd_dex::instructions::CodeLimits;
        use mdd_facts::code::CodeFacts;
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/references/generated/shared-code-035.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let mut codes = Vec::new();
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            codes.push(Arc::new(
                CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
                    .unwrap(),
            ));
        }
        let expected: usize = codes.iter().map(|c| c.items().len()).sum();
        assert!(expected > 0);
        let provider = Arc::new(CodeSqlProvider::new(codes.clone(), DecimalU64(1)).unwrap());
        let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        let result = bridge.query("SELECT dex_occurrence_id,code_byte_offset,insns_raw,code_item_raw FROM native_code_bytes").unwrap();
        assert_eq!(result.rows().len(), expected);
        for (facts, rows) in codes
            .iter()
            .zip(result.rows().chunks(codes[0].items().len()))
        {
            for (index, row) in rows.iter().enumerate() {
                assert!(
                    matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == facts.source().dex_occurrence_id)
                );
                assert!(
                    matches!(&row[1], SqlValue::U64(offset) if *offset == facts.items()[index].data().raw_range.byte_offset)
                );
                assert!(
                    matches!(&row[2], SqlValue::Bytes(raw) if raw == facts.raw_insns(index).unwrap())
                );
                assert!(
                    matches!(&row[3], SqlValue::Bytes(raw) if raw == facts.raw_code_item(index).unwrap())
                );
            }
        }
        assert!(
            CodeSqlProvider::new(vec![codes[0].clone(), codes[0].clone()], DecimalU64(1)).is_err()
        );
        let inventory = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let partial =
            CodeFacts::build_offsets(&snapshot, &inventory, 0, &[], CodeLimits::default()).unwrap();
        let error = match CodeSqlProvider::new(vec![Arc::new(partial)], DecimalU64(1)) {
            Err(error) => error,
            Ok(_) => panic!("partial code admitted"),
        };
        assert_eq!(error.code, ErrorCode::IncompleteFacts);
        let low = SqlControl::new(
            SqlLimits {
                max_cell_bytes: 2,
                ..SqlLimits::default()
            },
            None,
        );
        assert_eq!(
            code_bytes(&[1, 2, 3], &low).unwrap_err().code,
            ErrorCode::QuotaExceeded
        );
    }
    #[test]
    fn combined_reference_sites_join_only_matching_occurrences() {
        use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits};
        use mdd_facts::{
            code::CodeFacts,
            references::{ReferenceFacts, ReferenceLimits},
        };
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/references/generated/poly-custom-038.dex");
        let spec = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[spec.clone(), spec.clone()], CaptureLimits::default()).unwrap();
        let (mut metas, mut defs, mut refs) = (Vec::new(), Vec::new(), Vec::new());
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
                DefinitionFacts::build(metadata.clone(), DefinitionLimits::default()).unwrap();
            let code =
                CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
                    .unwrap();
            refs.push(Arc::new(
                ReferenceFacts::build(definitions.clone(), code, ReferenceLimits::default())
                    .unwrap(),
            ));
            defs.push(Arc::new(definitions));
            metas.push(Arc::new(metadata));
        }
        let make_combined = || {
            CombinedSqlProvider::new(
                Arc::new(MetadataSqlProvider::new(metas.clone(), DecimalU64(7)).unwrap()),
                Arc::new(DefinitionSqlProvider::new(defs.clone(), DecimalU64(7)).unwrap()),
            )
            .unwrap()
        };
        let partial =
            Arc::new(ReferenceSqlProvider::new(vec![refs[0].clone()], DecimalU64(7)).unwrap());
        assert_eq!(
            make_combined().with_references(partial).err().unwrap().code,
            ErrorCode::InvalidArgument
        );
        let first_inventory = ArchiveInventory::build(
            &snapshot.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let partial_code =
            CodeFacts::build_offsets(&snapshot, &first_inventory, 0, &[], CodeLimits::default())
                .unwrap();
        let partial_refs = Arc::new(
            ReferenceFacts::build((*defs[0]).clone(), partial_code, ReferenceLimits::default())
                .unwrap(),
        );
        assert_eq!(
            ReferenceSqlProvider::new(vec![partial_refs], DecimalU64(7))
                .err()
                .unwrap()
                .code,
            ErrorCode::IncompleteFacts
        );
        let foreign_epoch =
            Arc::new(ReferenceSqlProvider::new(refs.clone(), DecimalU64(8)).unwrap());
        assert_eq!(
            make_combined()
                .with_references(foreign_epoch)
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let other = Snapshot::capture(&[spec], CaptureLimits::default()).unwrap();
        let other_inventory = ArchiveInventory::build(
            &other.sources()[0],
            InventoryPolicy::default(),
            ArchiveLimits::default(),
        )
        .unwrap();
        let other_meta =
            MetadataFacts::build(&other, &other_inventory, 0, StringLimits::default()).unwrap();
        let other_defs = DefinitionFacts::build(other_meta, DefinitionLimits::default()).unwrap();
        let other_code =
            CodeFacts::build_all_code_items(&other, &other_inventory, 0, CodeLimits::default())
                .unwrap();
        let other_refs = Arc::new(
            ReferenceFacts::build(other_defs, other_code, ReferenceLimits::default()).unwrap(),
        );
        let other_provider =
            Arc::new(ReferenceSqlProvider::new(vec![other_refs], DecimalU64(7)).unwrap());
        assert_ne!(
            other_provider.binding.snapshot_id,
            snapshot.manifest().snapshot_id
        );
        assert_eq!(
            make_combined()
                .with_references(other_provider)
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
        let full = Arc::new(ReferenceSqlProvider::new(refs.clone(), DecimalU64(7)).unwrap());
        let combined = make_combined().with_references(full.clone()).unwrap();
        assert_eq!(
            combined.with_references(full.clone()).err().unwrap().code,
            ErrorCode::InvalidArgument
        );
        let combined = Arc::new(make_combined().with_references(full).unwrap());
        let bridge = SqlBridge::new(combined, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        let dynamic = bridge.query("SELECT d.dex_occurrence_id,d.site_ordinal FROM native_dynamic_call_sites d JOIN native_reference_sites r ON d.dex_occurrence_id=r.dex_occurrence_id AND d.site_ordinal=r.site_ordinal").unwrap();
        assert_eq!(dynamic.rows().len(), 4);
        let call_rows = bridge
            .query("SELECT dex_occurrence_id,site_ordinal FROM native_method_call_sites")
            .unwrap();
        let expected_call_count = refs
            .iter()
            .flat_map(|r| r.sites())
            .filter(|site| {
                site.target_kind == mdd_facts::references::TargetKind::Method
                    && site.invoke_kind.is_some()
            })
            .count();
        assert!(expected_call_count > 0);
        assert_eq!(call_rows.rows().len(), expected_call_count);
        let result = bridge.query("SELECT s.dex_occurrence_id,s.site_ordinal FROM native_reference_sites s JOIN native_method_references m ON s.dex_occurrence_id=m.dex_occurrence_id AND s.caller_method_idx=m.method_idx").unwrap();
        let actual: BTreeSet<_> = result
            .rows()
            .iter()
            .map(|row| match (&row[0], &row[1]) {
                (SqlValue::Text(source), SqlValue::U64(ordinal)) => {
                    (source.strict_utf8().unwrap(), ordinal.0)
                }
                _ => panic!("unexpected joined identity"),
            })
            .collect();
        let expected: BTreeSet<_> = refs
            .iter()
            .flat_map(|facts| {
                facts.sites().iter().map(move |site| {
                    (
                        facts.source().dex_occurrence_id.clone(),
                        u64::from(site.site_ordinal),
                    )
                })
            })
            .collect();
        assert!(!expected.is_empty());
        assert_eq!(result.rows().len(), expected.len());
        assert_eq!(actual, expected);
    }
    #[test]
    fn native_reference_sites_keep_operand_and_occurrence_identity() {
        use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits};
        use mdd_facts::{
            code::CodeFacts,
            references::{ReferenceFacts, ReferenceLimits},
        };
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/references/generated/poly-custom-038.dex");
        let spec = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot = Snapshot::capture(&[spec.clone(), spec], CaptureLimits::default()).unwrap();
        let mut sources = Vec::new();
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
            let code =
                CodeFacts::build_all_code_items(&snapshot, &inventory, 0, CodeLimits::default())
                    .unwrap();
            sources.push(Arc::new(
                ReferenceFacts::build(definitions, code, ReferenceLimits::default()).unwrap(),
            ));
        }
        assert!(!sources[0].sites().is_empty());
        assert!(
            ReferenceSqlProvider::new(vec![sources[0].clone(), sources[0].clone()], DecimalU64(0))
                .is_err()
        );
        let provider = Arc::new(ReferenceSqlProvider::new(sources.clone(), DecimalU64(0)).unwrap());
        let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        let result = bridge.query("SELECT dex_occurrence_id,site_ordinal,caller_method_idx,code_unit_pc,operand_ordinal,target_kind,target_local_index,opcode,instruction_byte_offset,operand_byte_offset FROM native_reference_sites").unwrap();
        let expected: Vec<_> = sources
            .iter()
            .flat_map(|source| {
                source
                    .sites()
                    .iter()
                    .map(move |site| (source.source().dex_occurrence_id.clone(), site))
            })
            .collect();
        assert_eq!(result.rows().len(), expected.len());
        for (row, (source, site)) in result.rows().iter().zip(expected) {
            assert!(
                matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == source)
            );
            for (index, expected) in [
                (1, site.site_ordinal as u64),
                (2, site.caller_method_idx as u64),
                (3, site.code_unit_pc as u64),
                (4, site.operand_ordinal as u64),
                (6, site.target_local_index as u64),
                (7, site.opcode as u64),
                (8, site.instruction_range.byte_offset.0),
                (9, site.operand_range.byte_offset.0),
            ] {
                assert_eq!(row[index], SqlValue::U64(DecimalU64(expected)));
            }
        }
        assert_ne!(
            sources[0].source().dex_occurrence_id,
            sources[1].source().dex_occurrence_id
        );
        let calls = bridge.query("SELECT dex_occurrence_id,site_ordinal,caller_method_idx,code_unit_pc,operand_ordinal,target_local_index,invoke_kind FROM native_method_call_sites").unwrap();
        let expected_calls: Vec<_> = sources
            .iter()
            .flat_map(|source| {
                source
                    .sites()
                    .iter()
                    .filter(|site| {
                        site.target_kind == mdd_facts::references::TargetKind::Method
                            && site.invoke_kind.is_some()
                    })
                    .map(move |site| (source.source().dex_occurrence_id.as_str(), site))
            })
            .collect();
        // The retained independent fixture oracle has six call rows per occurrence.
        assert_eq!(expected_calls.len(), 12);
        assert_eq!(calls.rows().len(), expected_calls.len());
        let mut oracle_targets = std::collections::BTreeMap::<String, Vec<u64>>::new();
        for (row, (source, site)) in calls.rows().iter().zip(expected_calls) {
            assert!(
                matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == source)
            );
            for (index, expected) in [
                (1, site.site_ordinal as u64),
                (2, site.caller_method_idx as u64),
                (3, site.code_unit_pc as u64),
                (4, site.operand_ordinal as u64),
                (5, site.target_local_index as u64),
            ] {
                assert_eq!(row[index], SqlValue::U64(DecimalU64(expected)));
            }
            assert!(matches!(&row[6], SqlValue::Text(_)));
            oracle_targets
                .entry(source.to_owned())
                .or_default()
                .push(site.target_local_index as u64);
        }
        assert_eq!(oracle_targets.len(), 2);
        for targets in oracle_targets.values_mut() {
            targets.sort_unstable();
            assert_eq!(targets, &[2, 4, 4, 4, 5, 5]);
        }
        let dynamic = bridge.query("SELECT dex_occurrence_id,site_ordinal,caller_method_idx,code_unit_pc,operand_ordinal,call_site_idx,bootstrap_method_handle_idx,bootstrap_target_kind,bootstrap_target_index,method_type_idx,name_string_idx,runtime_target_status FROM native_dynamic_call_sites").unwrap();
        assert_eq!(dynamic.rows().len(), 4);
        let mut pcs = std::collections::BTreeMap::<String, Vec<u64>>::new();
        for row in dynamic.rows() {
            let SqlValue::Text(source) = &row[0] else {
                panic!("missing source")
            };
            let source = source.strict_utf8().unwrap();
            let facts = sources
                .iter()
                .find(|facts| facts.source().dex_occurrence_id == source)
                .unwrap();
            let SqlValue::U64(DecimalU64(site_ordinal)) = row[1] else {
                panic!("missing ordinal")
            };
            let call = facts
                .dynamic_calls()
                .iter()
                .find(|call| u64::from(call.site_ordinal) == site_ordinal)
                .unwrap();
            let site = &facts.sites()[call.site_ordinal as usize];
            for (index, expected) in [
                (2, site.caller_method_idx),
                (3, site.code_unit_pc),
                (4, site.operand_ordinal),
                (5, call.call_site_idx),
                (6, call.bootstrap_method_handle_idx),
                (8, call.bootstrap_target_index),
                (9, call.method_type_idx),
                (10, call.name_string_idx),
            ] {
                assert_eq!(row[index], SqlValue::U64(DecimalU64(u64::from(expected))));
            }
            assert!(
                matches!(&row[7], SqlValue::Text(value) if value.strict_utf8().unwrap() == call.bootstrap_target_kind.as_str())
            );
            assert!(
                matches!(&row[11], SqlValue::Text(value) if value.strict_utf8().unwrap() == call.runtime_target_status)
            );
            assert_eq!(site.caller_method_idx, 0);
            assert_eq!(call.call_site_idx, 0);
            pcs.entry(source)
                .or_default()
                .push(u64::from(site.code_unit_pc));
        }
        assert_eq!(pcs.len(), 2);
        for offsets in pcs.values_mut() {
            offsets.sort_unstable();
            assert_eq!(offsets, &[34, 37]); // retained independent fixture oracle
        }
        let joined = bridge.query("SELECT d.dex_occurrence_id,d.site_ordinal FROM native_dynamic_call_sites d JOIN native_reference_sites r ON d.dex_occurrence_id=r.dex_occurrence_id AND d.site_ordinal=r.site_ordinal").unwrap();
        assert_eq!(joined.rows().len(), 4);
    }
    #[test]
    fn native_string_pools_bind_each_occurrence_without_cross_source_duplication() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
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
            facts.push(Arc::new(
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap(),
            ));
        }
        assert_ne!(
            facts[0].source().dex_occurrence_id,
            facts[1].source().dex_occurrence_id
        );
        assert_eq!(
            facts[0].string_pool().string_pool_id,
            facts[1].string_pool().string_pool_id
        );
        let provider = Arc::new(MetadataSqlProvider::new(facts.clone(), DecimalU64(0)).unwrap());
        let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        let pools = bridge.query("SELECT dex_occurrence_id,string_pool_id,physical_dex_id,content_id,string_ids_byte_offset,string_count FROM native_string_pools").unwrap();
        assert_eq!(pools.rows().len(), facts.len());
        for (row, fact) in pools.rows().iter().zip(&facts) {
            let pool = fact.string_pool();
            for (index, expected) in [
                (0, &pool.dex_occurrence_id),
                (1, &pool.string_pool_id),
                (2, &pool.physical_dex_id),
                (3, &pool.content_id),
            ] {
                assert!(
                    matches!(&row[index], SqlValue::Text(text) if text.strict_utf8().unwrap() == *expected)
                );
            }
            assert_eq!(row[4], SqlValue::U64(pool.string_ids_byte_offset));
            assert_eq!(
                row[5],
                SqlValue::U64(DecimalU64(u64::from(pool.string_count)))
            );
        }
        let joined = bridge.query("SELECT p.dex_occurrence_id,p.string_pool_id,s.string_idx FROM native_string_pools p JOIN native_strings s ON p.dex_occurrence_id=s.dex_occurrence_id AND p.string_pool_id=s.string_pool_id").unwrap();
        let mut expected = BTreeSet::new();
        for fact in &facts {
            for string in fact.strings() {
                expected.insert((
                    fact.source().dex_occurrence_id.clone(),
                    string.string_pool_id.clone(),
                    u64::from(string.data.string_idx),
                ));
            }
        }
        let actual: BTreeSet<_> = joined
            .rows()
            .iter()
            .map(|row| {
                let text = |index| match &row[index] {
                    SqlValue::Text(value) => value.strict_utf8().unwrap(),
                    _ => panic!("unexpected identity"),
                };
                let index = match &row[2] {
                    SqlValue::U64(value) => value.0,
                    _ => panic!("unexpected index"),
                };
                (text(0), text(1), index)
            })
            .collect();
        assert_eq!(joined.rows().len(), expected.len());
        assert_eq!(actual, expected);
    }
    #[test]
    fn native_dex_occurrences_preserve_source_identities() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let mut facts = Vec::new();
        let mut expected = BTreeSet::new();
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let metadata =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            let id = metadata.source();
            expected.insert(vec![
                id.snapshot_id.clone(),
                id.dex_occurrence_id.clone(),
                id.physical_dex_id.clone(),
                id.member_id.clone(),
                id.source_occurrence_id.clone(),
                id.content_id.clone(),
            ]);
            facts.push(Arc::new(metadata));
        }
        assert_eq!(expected.len(), 2);
        let provider = Arc::new(MetadataSqlProvider::new(facts, DecimalU64(0)).unwrap());
        let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        let rows = bridge.query("SELECT snapshot_id,dex_occurrence_id,physical_dex_id,member_id,source_occurrence_id,content_id FROM native_dex_occurrences").unwrap();
        let actual = rows
            .rows()
            .iter()
            .map(|row| {
                row.iter()
                    .map(|cell| match cell {
                        SqlValue::Text(text) => text.strict_utf8().unwrap(),
                        _ => panic!("unexpected source identity cell"),
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
        let left = actual.iter().next().unwrap();
        let right = actual.iter().nth(1).unwrap();
        assert_ne!(left[1], right[1]);
        assert_eq!(left[2], right[2]);
        assert_eq!(left[5], right[5]);
    }
    #[test]
    fn combined_metadata_definitions_join_same_occurrences() {
        use mdd_dex::definitions::DefinitionLimits;
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let mut metas = Vec::new();
        let mut defs = Vec::new();
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let meta =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            defs.push(Arc::new(
                DefinitionFacts::build(meta.clone(), DefinitionLimits::default()).unwrap(),
            ));
            metas.push(Arc::new(meta));
        }
        let meta = Arc::new(MetadataSqlProvider::new(metas.clone(), DecimalU64(3)).unwrap());
        let definitions =
            Arc::new(DefinitionSqlProvider::new(defs.clone(), DecimalU64(3)).unwrap());
        let combined = Arc::new(CombinedSqlProvider::new(meta, definitions).unwrap());
        let bridge = SqlBridge::new(combined, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        let result = bridge.query("SELECT r.dex_occurrence_id,r.method_idx,p.proto_idx FROM native_method_references r JOIN native_prototypes p ON r.dex_occurrence_id=p.dex_occurrence_id AND r.prototype_idx=p.proto_idx").unwrap();
        let expected: usize = defs
            .iter()
            .map(|f| f.definitions().method_references.len())
            .sum();
        assert_eq!(result.rows().len(), expected);
        let partial =
            Arc::new(MetadataSqlProvider::new(vec![metas[0].clone()], DecimalU64(3)).unwrap());
        let both = Arc::new(DefinitionSqlProvider::new(defs.clone(), DecimalU64(3)).unwrap());
        assert!(CombinedSqlProvider::new(partial, both).is_err());
        let mismatch = Arc::new(MetadataSqlProvider::new(metas, DecimalU64(4)).unwrap());
        let both = Arc::new(DefinitionSqlProvider::new(defs, DecimalU64(3)).unwrap());
        assert!(CombinedSqlProvider::new(mismatch, both).is_err());
    }
    #[test]
    fn native_member_relations_keep_references_definitions_and_sources_distinct() {
        use mdd_dex::definitions::{DefinitionLimits, MethodBody};
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let path = root.join("tests/fixtures/definitions/generated/definitions-035.dex");
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
            facts.push(Arc::new(
                DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap(),
            ));
        }
        let bridge = SqlBridge::new(
            Arc::new(DefinitionSqlProvider::new(facts.clone(), DecimalU64(0)).unwrap()),
            SqlDialect::NativeV1,
            SqlLimits::default(),
        )
        .unwrap();
        let method_refs = bridge.query("SELECT dex_occurrence_id,method_idx,class_type_idx,class_descriptor,class_descriptor_mutf8,prototype_idx,name_idx,name,name_mutf8 FROM native_method_references").unwrap();
        let method_defs = bridge.query("SELECT dex_occurrence_id,class_def_idx,class_type_idx,method_idx,kind,ordinal,access_flags,body_state,code_byte_offset,declared_insns_size FROM native_method_definitions").unwrap();
        let field_refs = bridge.query("SELECT dex_occurrence_id,field_idx,class_type_idx,class_descriptor,class_descriptor_mutf8,field_type_idx,type_descriptor,type_descriptor_mutf8,name_idx,name,name_mutf8 FROM native_field_references").unwrap();
        let field_defs = bridge.query("SELECT dex_occurrence_id,class_def_idx,class_type_idx,field_idx,kind,ordinal,access_flags FROM native_field_definitions").unwrap();
        let as_u64 = |v: u32| SqlValue::U64(DecimalU64(u64::from(v)));
        let text = |v: &SqlValue| match v {
            SqlValue::Text(v) => v.strict_utf8().unwrap(),
            other => panic!("expected text: {other:?}"),
        };
        let mut saw_reference_only = false;
        let mut states = BTreeSet::new();
        for f in &facts {
            let source = &f.metadata().source().dex_occurrence_id;
            let mrefs: Vec<_> = method_refs
                .rows()
                .iter()
                .filter(|row| text(&row[0]) == *source)
                .collect();
            let mdefs: Vec<_> = method_defs
                .rows()
                .iter()
                .filter(|row| text(&row[0]) == *source)
                .collect();
            let frefs: Vec<_> = field_refs
                .rows()
                .iter()
                .filter(|row| text(&row[0]) == *source)
                .collect();
            let fdefs: Vec<_> = field_defs
                .rows()
                .iter()
                .filter(|row| text(&row[0]) == *source)
                .collect();
            assert_eq!(mrefs.len(), f.definitions().method_references.len());
            assert_eq!(mdefs.len(), f.definitions().method_definitions.len());
            assert_eq!(frefs.len(), f.definitions().field_references.len());
            assert_eq!(fdefs.len(), f.definitions().field_definitions.len());
            for (row, reference) in mrefs.iter().zip(&f.definitions().method_references) {
                assert_eq!(row[1], as_u64(reference.method_idx));
                assert_eq!(row[2], as_u64(reference.class_idx));
                assert_eq!(row[5], as_u64(reference.proto_idx));
                assert_eq!(row[6], as_u64(reference.name_idx));
                assert_eq!(text(&row[7]), reference.method_name);
                let name = &f.metadata().strings()[reference.name_idx as usize]
                    .data
                    .text;
                assert!(
                    matches!(&row[8], SqlValue::DexMutf8 { bytes, .. } if bytes == &name.raw_mutf8)
                );
                if !f
                    .definitions()
                    .method_definitions
                    .iter()
                    .any(|d| d.method_idx == reference.method_idx)
                {
                    saw_reference_only = true;
                }
            }
            for (row, definition) in mdefs.iter().zip(&f.definitions().method_definitions) {
                assert_eq!(row[1], as_u64(definition.class_def_idx));
                assert_eq!(row[2], as_u64(definition.class_idx));
                assert_eq!(row[3], as_u64(definition.method_idx));
                assert_eq!(text(&row[4]), definition.kind.as_str());
                assert_eq!(row[5], as_u64(definition.ordinal));
                assert_eq!(row[6], as_u64(definition.access_flags));
                assert_eq!(text(&row[7]), definition.body.state());
                states.insert(definition.body.state());
                match &definition.body {
                    MethodBody::Present {
                        code_byte_offset,
                        declared_insns_size,
                    } => {
                        assert_eq!(row[8], SqlValue::U64(*code_byte_offset));
                        assert_eq!(row[9], as_u64(*declared_insns_size));
                    }
                    _ => assert_eq!((&row[8], &row[9]), (&SqlValue::Null, &SqlValue::Null)),
                }
            }
            for (row, reference) in frefs.iter().zip(&f.definitions().field_references) {
                assert_eq!(row[1], as_u64(reference.field_idx));
                assert_eq!(row[2], as_u64(reference.class_idx));
                assert_eq!(row[5], as_u64(reference.type_idx));
                assert_eq!(row[8], as_u64(reference.name_idx));
                assert_eq!(text(&row[9]), reference.field_name);
                let name = &f.metadata().strings()[reference.name_idx as usize]
                    .data
                    .text;
                assert!(
                    matches!(&row[10], SqlValue::DexMutf8 { bytes, .. } if bytes == &name.raw_mutf8)
                );
            }
            for (row, definition) in fdefs.iter().zip(&f.definitions().field_definitions) {
                assert_eq!(row[1], as_u64(definition.class_def_idx));
                assert_eq!(row[2], as_u64(definition.class_idx));
                assert_eq!(row[3], as_u64(definition.field_idx));
                assert_eq!(text(&row[4]), definition.kind.as_str());
                assert_eq!(row[5], as_u64(definition.ordinal));
                assert_eq!(row[6], as_u64(definition.access_flags));
            }
        }
        assert_ne!(
            facts[0].metadata().source().dex_occurrence_id,
            facts[1].metadata().source().dex_occurrence_id
        );
        assert!(saw_reference_only);
        assert!(
            states.contains("native") && states.contains("abstract") && states.contains("present")
        );
        let joined = bridge.query("SELECT r.dex_occurrence_id,r.method_idx,d.method_idx,d.body_state FROM native_method_references r LEFT JOIN native_method_definitions d ON r.dex_occurrence_id=d.dex_occurrence_id AND r.method_idx=d.method_idx").unwrap();
        assert_eq!(joined.rows().len(), method_refs.rows().len());
        for row in joined.rows() {
            let source = text(&row[0]);
            let occurrence = facts
                .iter()
                .find(|facts| facts.metadata().source().dex_occurrence_id == source)
                .unwrap();
            let definition = occurrence
                .definitions()
                .method_definitions
                .iter()
                .find(|d| as_u64(d.method_idx) == row[1]);
            match definition {
                Some(definition) => {
                    assert_eq!(row[2], row[1]);
                    assert_eq!(text(&row[3]), definition.body.state());
                }
                None => assert_eq!((&row[2], &row[3]), (&SqlValue::Null, &SqlValue::Null)),
            }
        }
        let joined_fields = bridge.query("SELECT r.dex_occurrence_id,r.field_idx,d.field_idx FROM native_field_references r LEFT JOIN native_field_definitions d ON r.dex_occurrence_id=d.dex_occurrence_id AND r.field_idx=d.field_idx").unwrap();
        assert_eq!(joined_fields.rows().len(), field_refs.rows().len());
        for row in joined_fields.rows() {
            let source = text(&row[0]);
            let occurrence = facts
                .iter()
                .find(|facts| facts.metadata().source().dex_occurrence_id == source)
                .unwrap();
            if occurrence
                .definitions()
                .field_definitions
                .iter()
                .any(|d| as_u64(d.field_idx) == row[1])
            {
                assert_eq!(row[2], row[1]);
            } else {
                assert_eq!(row[2], SqlValue::Null);
            }
        }
        let small = SqlBridge::new(
            Arc::new(DefinitionSqlProvider::new(facts, DecimalU64(0)).unwrap()),
            SqlDialect::NativeV1,
            SqlLimits {
                max_cell_bytes: 1,
                ..SqlLimits::default()
            },
        )
        .unwrap();
        assert_eq!(
            small
                .query("SELECT name FROM native_method_references")
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    #[test]
    fn native_class_definition_details_preserve_raw_offsets_and_sources() {
        use mdd_dex::definitions::DefinitionLimits;
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/definitions/generated");
        let inputs = [
            "definitions-035.dex",
            "definitions-035.dex",
            "nullable-root-class.dex",
            "empty-class-data.dex",
        ]
        .map(|name| InputSpec {
            path: root.join(name),
            kind: InputKind::RawDex,
            expected_sha256: None,
        });
        let snapshot = Snapshot::capture(&inputs, CaptureLimits::default()).unwrap();
        let mut occurrences = Vec::new();
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let metadata =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            occurrences.push(Arc::new(
                DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap(),
            ));
        }
        let bridge = SqlBridge::new(
            Arc::new(DefinitionSqlProvider::new(occurrences.clone(), DecimalU64(0)).unwrap()),
            SqlDialect::NativeV1,
            SqlLimits::default(),
        )
        .unwrap();
        let result = bridge.query("SELECT dex_occurrence_id,class_def_idx,access_flags,annotations_offset,static_values_offset,class_data_offset,class_data_length,static_fields_count,instance_fields_count,direct_methods_count,virtual_methods_count,encoded_offset,encoded_length FROM native_class_definition_details").unwrap();
        let expected_count: usize = occurrences
            .iter()
            .map(|facts| facts.definitions().classes.len())
            .sum();
        assert_eq!(result.rows().len(), expected_count);
        let u64_value = |v: u64| SqlValue::U64(DecimalU64(v));
        let mut saw_absent_data = false;
        let mut saw_empty_data = false;
        for (facts, input) in occurrences.iter().zip(&inputs) {
            let bytes = std::fs::read(&input.path).unwrap();
            let read_u32 =
                |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            let class_defs_offset = read_u32(0x64) as usize;
            let source = &facts.metadata().source().dex_occurrence_id;
            for class in &facts.definitions().classes {
                let row = result.rows().iter().find(|row| {
                    matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == *source)
                        && row[1] == u64_value(class.class_def_idx.into())
                }).unwrap();
                let at = class_defs_offset + class.class_def_idx as usize * 32;
                let nullable_offset = |value: u32| {
                    if value == 0 {
                        SqlValue::Null
                    } else {
                        u64_value(value.into())
                    }
                };
                assert_eq!(row[2], u64_value(read_u32(at + 4).into()));
                assert_eq!(row[3], nullable_offset(read_u32(at + 20)));
                assert_eq!(row[4], nullable_offset(read_u32(at + 28)));
                let data_offset = read_u32(at + 24);
                assert_eq!(row[5], nullable_offset(data_offset));
                assert_eq!(row[11], u64_value(at as u64));
                assert_eq!(row[12], u64_value(32));
                let mut counts = [0u32; 4];
                if data_offset != 0 {
                    let mut cursor = data_offset as usize;
                    for count in &mut counts {
                        let mut terminated = false;
                        for shift in (0..35).step_by(7) {
                            let byte = bytes[cursor];
                            cursor += 1;
                            *count |= u32::from(byte & 0x7f) << shift;
                            if byte & 0x80 == 0 {
                                terminated = true;
                                break;
                            }
                        }
                        assert!(terminated);
                    }
                    assert_eq!(
                        row[6],
                        SqlValue::U64(class.class_data_range.as_ref().unwrap().byte_length)
                    );
                    saw_empty_data |= counts == [0; 4];
                } else {
                    assert_eq!(row[6], SqlValue::Null);
                    saw_absent_data = true;
                }
                for (i, count) in counts.into_iter().enumerate() {
                    assert_eq!(row[7 + i], u64_value(count.into()));
                }
            }
        }
        assert_ne!(
            occurrences[0].metadata().source().dex_occurrence_id,
            occurrences[1].metadata().source().dex_occurrence_id
        );
        assert!(saw_absent_data && saw_empty_data);
    }
    #[test]
    fn native_class_interface_join_keeps_distinct_occurrences() {
        use mdd_dex::definitions::DefinitionLimits;
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
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
            facts.push(Arc::new(
                DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap(),
            ));
        }
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/definitions/expected.json"
        ))
        .unwrap();
        let mut expected = Vec::new();
        for item in &facts {
            let occurrence = item.metadata().source().dex_occurrence_id.clone();
            for triple in oracle["definitions-035"]["interfaces"].as_array().unwrap() {
                expected.push((
                    occurrence.clone(),
                    triple[0].as_str().unwrap().to_owned(),
                    triple[2].as_str().unwrap().to_owned(),
                    triple[1].as_u64().unwrap(),
                ));
            }
        }
        expected.sort();
        assert_eq!(expected.len(), 4);
        assert_ne!(
            facts[0].metadata().source().dex_occurrence_id,
            facts[1].metadata().source().dex_occurrence_id
        );
        let provider = Arc::new(DefinitionSqlProvider::new(facts, DecimalU64(0)).unwrap());
        let sql = "SELECT i.dex_occurrence_id,c.descriptor,i.descriptor,i.ordinal FROM native_class_interfaces i JOIN native_classes c ON c.dex_occurrence_id=i.dex_occurrence_id AND c.type_idx=i.class_type_idx WHERE c.descriptor IN ('Lfixture/I1;','Lfixture/Base;') ORDER BY i.dex_occurrence_id,i.class_type_idx,i.ordinal";
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            let result = bridge.query(sql).unwrap();
            let mut actual = result
                .rows()
                .iter()
                .map(|row| {
                    let text = |value: &SqlValue| match value {
                        SqlValue::Text(value) => value.strict_utf8().unwrap(),
                        other => panic!("unexpected text: {other:?}"),
                    };
                    let SqlValue::U64(DecimalU64(ordinal)) = row[3] else {
                        panic!("unexpected interface ordinal: {:?}", row[3]);
                    };
                    (text(&row[0]), text(&row[1]), text(&row[2]), ordinal)
                })
                .collect::<Vec<_>>();
            actual.sort();
            assert_eq!(actual, expected, "{dialect:?}");
        }
    }
    #[test]
    fn native_return_discovery_keeps_occurrences_and_distinct_classes() {
        use mdd_dex::definitions::DefinitionLimits;
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let mut metadata = Vec::new();
        let mut definitions = Vec::new();
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let facts =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            definitions.push(Arc::new(
                DefinitionFacts::build(facts.clone(), DefinitionLimits::default()).unwrap(),
            ));
            metadata.push(Arc::new(facts));
        }
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/definitions/expected.json"
        ))
        .unwrap();
        let mut expected_methods = Vec::new();
        let mut expected_classes = std::collections::BTreeSet::new();
        for method in oracle["definitions-035"]["methods"].as_array().unwrap() {
            let descriptor = method[0].as_str().unwrap();
            if descriptor.ends_with(")I") {
                let (owner, name_and_proto) = descriptor.split_once("->").unwrap();
                let name = name_and_proto.split_once('(').unwrap().0;
                expected_classes.insert(owner.to_owned());
                for item in &metadata {
                    expected_methods.push((
                        item.source().dex_occurrence_id.clone(),
                        owner.to_owned(),
                        name.to_owned(),
                    ));
                }
            }
        }
        expected_methods.sort();
        assert_eq!(expected_methods.len(), 4);
        let meta = Arc::new(MetadataSqlProvider::new(metadata, DecimalU64(0)).unwrap());
        let defs = Arc::new(DefinitionSqlProvider::new(definitions, DecimalU64(0)).unwrap());
        let provider = Arc::new(CombinedSqlProvider::new(meta, defs).unwrap());
        let join = " FROM native_method_definitions d JOIN native_method_references m ON d.dex_occurrence_id=m.dex_occurrence_id AND d.method_idx=m.method_idx JOIN native_prototypes p ON m.dex_occurrence_id=p.dex_occurrence_id AND m.prototype_idx=p.proto_idx JOIN native_types t ON p.dex_occurrence_id=t.dex_occurrence_id AND p.return_type_idx=t.type_idx";
        let text = |value: &SqlValue| match value {
            SqlValue::Text(value) => value.strict_utf8().unwrap(),
            other => panic!("unexpected text: {other:?}"),
        };
        for dialect in [
            SqlDialect::NativeV1,
            SqlDialect::DexSql010,
            SqlDialect::DexSql011,
        ] {
            let bridge = SqlBridge::new(provider.clone(), dialect, SqlLimits::default()).unwrap();
            let sql = format!(
                "SELECT d.dex_occurrence_id,m.dex_occurrence_id,p.dex_occurrence_id,t.dex_occurrence_id,m.class_descriptor,m.name{join} WHERE t.descriptor='I'"
            );
            let result = bridge.query(&sql).unwrap();
            let mut actual = Vec::new();
            for row in result.rows() {
                let occurrence = text(&row[0]);
                for source in &row[1..4] {
                    assert_eq!(text(source), occurrence, "cross-source join in {dialect:?}");
                }
                actual.push((occurrence, text(&row[4]), text(&row[5])));
            }
            actual.sort();
            assert_eq!(actual, expected_methods, "{dialect:?}");
            let distinct = bridge.query(&format!("SELECT DISTINCT m.class_descriptor{join} WHERE t.descriptor='I' ORDER BY m.class_descriptor")).unwrap();
            let classes = distinct
                .rows()
                .iter()
                .map(|row| text(&row[0]))
                .collect::<Vec<_>>();
            assert_eq!(
                classes,
                expected_classes.iter().cloned().collect::<Vec<_>>(),
                "{dialect:?}"
            );
            let outer = "SELECT d.dex_occurrence_id,t.descriptor FROM native_method_definitions d LEFT JOIN native_types t ON d.dex_occurrence_id=t.dex_occurrence_id AND d.class_type_idx=t.type_idx AND t.descriptor='Lfixture/Missing;' WHERE t.descriptor IS NULL";
            let rows = bridge.query(outer).unwrap();
            assert_eq!(rows.rows().len(), 20, "{dialect:?}");
            assert!(rows.rows().iter().all(|row| row[1] == SqlValue::Null));
        }
    }
    #[test]
    fn native_class_relations_preserve_sources_nulls_and_interfaces() {
        use mdd_dex::definitions::DefinitionLimits;
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let inputs = [
            "tests/fixtures/definitions/generated/definitions-035.dex",
            "tests/fixtures/definitions/generated/definitions-035.dex",
            "tests/fixtures/class_source_boundary/generated/null-source.dex",
            "tests/fixtures/class_source_boundary/generated/empty-source.dex",
            "tests/fixtures/class_source_boundary/generated/surrogate-source.dex",
            "tests/fixtures/class_source_boundary/generated/root-empty-source.dex",
        ]
        .map(|path| InputSpec {
            path: root.join(path),
            kind: InputKind::RawDex,
            expected_sha256: None,
        });
        let snapshot = Snapshot::capture(&inputs, CaptureLimits::default()).unwrap();
        let mut occurrences = Vec::new();
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            let metadata =
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap();
            occurrences.push(Arc::new(
                DefinitionFacts::build(metadata, DefinitionLimits::default()).unwrap(),
            ));
        }
        let duplicate = DefinitionSqlProvider::new(
            vec![occurrences[0].clone(), occurrences[0].clone()],
            DecimalU64(0),
        );
        assert!(matches!(duplicate, Err(error) if error.code == ErrorCode::InvalidArgument));
        let source_ids: Vec<_> = occurrences
            .iter()
            .map(|facts| facts.metadata().source().dex_occurrence_id.clone())
            .collect();
        let classes: usize = occurrences
            .iter()
            .map(|facts| facts.definitions().classes.len())
            .sum();
        let interfaces: usize = occurrences
            .iter()
            .map(|facts| facts.definitions().interfaces.len())
            .sum();
        let provider =
            Arc::new(DefinitionSqlProvider::new(occurrences.clone(), DecimalU64(0)).unwrap());
        let bridge =
            SqlBridge::new(provider.clone(), SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        let result = bridge.query("SELECT dex_occurrence_id,class_def_idx,type_idx,descriptor,descriptor_mutf8,access_flags,superclass_type_idx,source_file_string_idx,source_file,source_file_mutf8 FROM native_classes").unwrap();
        assert_eq!(result.rows().len(), classes);
        for (index, facts) in occurrences.iter().enumerate() {
            for class in &facts.definitions().classes {
                let row = result.rows().iter().find(|row| matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == source_ids[index])
                    && row[1] == SqlValue::U64(DecimalU64(u64::from(class.class_def_idx)))).unwrap();
                assert_eq!(
                    row[2],
                    SqlValue::U64(DecimalU64(u64::from(class.class_idx)))
                );
                assert!(
                    matches!(&row[3], SqlValue::Text(text) if text.strict_utf8().unwrap() == class.descriptor)
                );
                assert_eq!(
                    row[5],
                    SqlValue::U64(DecimalU64(u64::from(class.access_flags)))
                );
                assert_eq!(
                    row[6],
                    class
                        .superclass_idx
                        .map_or(SqlValue::Null, |v| SqlValue::U64(DecimalU64(u64::from(v))))
                );
                match class.source_file_idx {
                    None => assert_eq!(
                        (&row[7], &row[8], &row[9]),
                        (&SqlValue::Null, &SqlValue::Null, &SqlValue::Null)
                    ),
                    Some(idx) => {
                        let text = &facts.metadata().strings()[idx as usize].data.text;
                        assert_eq!(row[7], SqlValue::U64(DecimalU64(u64::from(idx))));
                        assert!(
                            matches!(&row[8], SqlValue::Text(value) if value.utf16 == text.utf16_units)
                        );
                        assert!(
                            matches!(&row[9], SqlValue::DexMutf8 {bytes, utf16_code_units} if *bytes == text.raw_mutf8 && utf16_code_units.0 == text.utf16_units.len() as u64)
                        );
                    }
                }
            }
        }
        assert_ne!(source_ids[0], source_ids[1]);
        let boundary = |index: usize| {
            result.rows().iter().find(|row| matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == source_ids[index])).unwrap()
        };
        assert_eq!(boundary(2)[8], SqlValue::Null);
        assert!(matches!(&boundary(3)[8], SqlValue::Text(text) if text.utf16.is_empty()));
        assert!(matches!(&boundary(4)[8], SqlValue::Text(text) if text.utf16 == [0xd800]));
        assert!(
            matches!(&boundary(4)[9], SqlValue::DexMutf8 {bytes, ..} if *bytes == [0xed,0xa0,0x80])
        );
        assert_eq!(boundary(5)[6], SqlValue::Null);
        let interfaces_result = bridge.query("SELECT dex_occurrence_id,class_def_idx,class_type_idx,ordinal,interface_type_idx,descriptor,descriptor_mutf8 FROM native_class_interfaces").unwrap();
        assert_eq!(interfaces_result.rows().len(), interfaces);
        assert!(interfaces >= 2);
        for facts in &occurrences[..2] {
            let source_id = &facts.metadata().source().dex_occurrence_id;
            assert!(interfaces_result.rows().iter().any(|row| matches!(&row[0], SqlValue::Text(text) if text.strict_utf8().unwrap() == *source_id)
                && row[3] == SqlValue::U64(DecimalU64(0))
                && matches!(&row[5], SqlValue::Text(text) if text.strict_utf8().unwrap() == "Lfixture/I1;")));
        }
        let limits = SqlLimits {
            max_cell_bytes: 1,
            ..SqlLimits::default()
        };
        let small = SqlBridge::new(provider, SqlDialect::NativeV1, limits).unwrap();
        assert_eq!(
            small
                .query("SELECT descriptor FROM native_classes")
                .unwrap_err()
                .code,
            ErrorCode::QuotaExceeded
        );
    }
    #[test]
    fn real_metadata_same_snapshot_duplicates_and_lossless_values() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/references/generated/nonscalar-string-035.dex");
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
            facts.push(Arc::new(
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap(),
            ));
        }
        let strings = facts[0].strings().len();
        let source_id = snapshot.manifest().snapshot_id.clone();
        let provider = Arc::new(MetadataSqlProvider::new(facts, DecimalU64(0)).unwrap());
        assert_eq!(provider.occurrence_count(), 2);
        drop(snapshot);
        let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        let result=bridge.query("SELECT dex_occurrence_id,string_idx,value,raw_mutf8 FROM native_strings ORDER BY dex_occurrence_id,string_idx").unwrap();
        assert_eq!(result.binding().snapshot_id, source_id);
        assert_eq!(result.rows().len(), strings * 2);
        assert_ne!(result.rows()[0][0], result.rows()[strings][0]);
        assert!(
            result
                .rows()
                .iter()
                .any(|row| matches!(&row[2],SqlValue::Text(text) if text.strict_utf8().is_err()))
        );
        let count = bridge.query("SELECT COUNT(*) AS n FROM native_strings WHERE value = ?");
        assert!(count.is_err());
    }

    #[test]
    fn native_types_and_prototypes_preserve_occurrences_and_parameter_order() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let snapshot_id = snapshot.manifest().snapshot_id.clone();
        let mut occurrences = Vec::new();
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            occurrences.push(Arc::new(
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap(),
            ));
        }
        let type_count = occurrences[0].types().len();
        let prototype_count = occurrences[0].prototypes().len();
        let provider = Arc::new(MetadataSqlProvider::new(occurrences, DecimalU64(0)).unwrap());
        drop(snapshot);
        let bridge =
            SqlBridge::new(provider.clone(), SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        let types = bridge.query("SELECT dex_occurrence_id,type_idx,descriptor,descriptor_mutf8 FROM native_types ORDER BY dex_occurrence_id,type_idx").unwrap();
        assert_eq!(types.binding().snapshot_id, snapshot_id);
        assert_eq!(types.rows().len(), 2 * type_count);
        let mut source_ids = BTreeSet::new();
        let mut int_types = BTreeSet::new();
        for row in types.rows() {
            let (
                SqlValue::Text(source),
                SqlValue::U64(index),
                SqlValue::Text(descriptor),
                SqlValue::DexMutf8 { bytes, .. },
            ) = (&row[0], &row[1], &row[2], &row[3])
            else {
                panic!("unexpected native type row")
            };
            let source = source.strict_utf8().unwrap();
            source_ids.insert(source.clone());
            if descriptor.utf16 == [u16::from(b'I')] {
                assert_eq!(bytes, b"I");
                int_types.insert((source, index.0));
            }
        }
        assert_eq!(source_ids.len(), 2);
        assert_eq!(int_types.len(), 2);

        let prototypes = bridge.query("SELECT dex_occurrence_id,proto_idx,parameters_byte_offset,parameter_count,descriptor FROM native_prototypes ORDER BY dex_occurrence_id,proto_idx").unwrap();
        assert_eq!(prototypes.rows().len(), 2 * prototype_count);
        let mut one_parameter = BTreeSet::new();
        let mut no_parameter_sources = BTreeSet::new();
        for row in prototypes.rows() {
            let (
                SqlValue::Text(source),
                SqlValue::U64(index),
                _,
                SqlValue::U64(count),
                SqlValue::Text(descriptor),
            ) = (&row[0], &row[1], &row[2], &row[3], &row[4])
            else {
                panic!("unexpected prototype row")
            };
            let source = source.strict_utf8().unwrap();
            match descriptor.strict_utf8().unwrap().as_str() {
                "()V" => {
                    assert_eq!(count.0, 0);
                    assert_eq!(row[2], SqlValue::Null);
                    no_parameter_sources.insert(source);
                }
                "(I)I" => {
                    assert_eq!(count.0, 1);
                    assert!(matches!(row[2], SqlValue::U64(_)));
                    one_parameter.insert((source, index.0));
                }
                _ => (),
            }
        }
        assert_eq!(no_parameter_sources, source_ids);
        assert_eq!(one_parameter.len(), 2);
        let parameters = bridge.query("SELECT dex_occurrence_id,proto_idx,ordinal,type_idx FROM native_prototype_parameters ORDER BY dex_occurrence_id,proto_idx,ordinal").unwrap();
        let mut matched = BTreeSet::new();
        for row in parameters.rows() {
            let (
                SqlValue::Text(source),
                SqlValue::U64(proto),
                SqlValue::U64(ordinal),
                SqlValue::U64(kind),
            ) = (&row[0], &row[1], &row[2], &row[3])
            else {
                panic!("unexpected parameter row")
            };
            let source = source.strict_utf8().unwrap();
            if one_parameter.contains(&(source.clone(), proto.0)) {
                assert_eq!(ordinal.0, 0);
                assert!(int_types.contains(&(source.clone(), kind.0)));
                matched.insert((source, proto.0));
            }
        }
        assert_eq!(matched, one_parameter);
        // Exercise the fact cursor directly: with a one-byte SQLite length
        // limit, SQLite can reject virtual-table construction before xFilter.
        // That separate bridge error classification remains unqualified.
        let mut cursor = Arc::clone(&provider)
            .open_cursor(
                "native_types",
                SqlControl::new(
                    SqlLimits {
                        max_cell_bytes: 1,
                        ..SqlLimits::default()
                    },
                    None,
                ),
            )
            .unwrap();
        let error = cursor.next_row().unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded, "{error:?}");
        drop(cursor);
        // Actual bridge must also preserve the quota error under the same
        // one-byte cell limit, rather than fail during virtual-table declaration.
        let limited = SqlBridge::new(
            provider,
            SqlDialect::NativeV1,
            SqlLimits {
                max_cell_bytes: 1,
                ..SqlLimits::default()
            },
        )
        .unwrap();
        let error = limited
            .query("SELECT descriptor FROM native_types")
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded, "{error:?}");
    }

    #[test]
    fn schema_only_prepare_reuses_eponymous_connection_after_restoring_cell_limit() {
        use crate::virtual_tables::{self, Source, TEST_CONNECTS, TEST_OPENS};
        use rusqlite::{
            Connection,
            hooks::{AuthAction, AuthContext, Authorization},
            limits::Limit,
        };

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/definitions/generated/definitions-035.dex");
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
        let facts = Arc::new(
            MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap(),
        );
        let provider = Arc::new(MetadataSqlProvider::new(vec![facts], DecimalU64(0)).unwrap());
        let relation = provider
            .relations()
            .unwrap()
            .into_iter()
            .find(|r| r.name == "native_types")
            .unwrap();
        let binding = provider.binding().clone();
        let control = SqlControl::new(
            SqlLimits {
                max_cell_bytes: 1,
                ..SqlLimits::default()
            },
            None,
        );
        let db = Connection::open_in_memory().unwrap();
        db.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0).unwrap();
        virtual_tables::register(
            &db,
            Arc::new(Source {
                provider,
                relation,
                binding,
                control: control.clone(),
            }),
        )
        .unwrap();
        db.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Select => Authorization::Allow,
            AuthAction::Read { table_name, .. }
                if table_name.eq_ignore_ascii_case("native_types") =>
            {
                Authorization::Allow
            }
            _ => Authorization::Deny,
        }))
        .unwrap();
        TEST_CONNECTS.with(|count| count.set(0));
        TEST_OPENS.with(|count| count.set(0));
        let warmup = db
            .prepare("SELECT * FROM \"native_types\" LIMIT 0")
            .unwrap();
        assert!(warmup.readonly());
        drop(warmup);
        assert_eq!(TEST_CONNECTS.with(|count| count.get()), 1);
        assert_eq!(TEST_OPENS.with(|count| count.get()), 0);
        db.set_limit(Limit::SQLITE_LIMIT_LENGTH, 65).unwrap();
        assert_eq!(db.limit(Limit::SQLITE_LIMIT_LENGTH).unwrap(), 65);
        let mut statement = db.prepare("SELECT descriptor FROM native_types").unwrap();
        assert!(statement.readonly());
        assert_eq!(
            TEST_CONNECTS.with(|count| count.get()),
            1,
            "SQLite reconnected the virtual table"
        );
        assert_eq!(TEST_OPENS.with(|count| count.get()), 0);
        let mut rows = statement.query([]).unwrap();
        assert!(
            rows.next().is_err(),
            "one-byte value budget unexpectedly returned a row"
        );
        assert_eq!(control.error().unwrap().code, ErrorCode::QuotaExceeded);
        assert_eq!(db.limit(Limit::SQLITE_LIMIT_LENGTH).unwrap(), 65);
        assert!(TEST_OPENS.with(|count| count.get()) > 0);
        drop(rows);
        drop(statement);
        assert!(db.prepare("SELECT name FROM sqlite_master").is_err());
        assert!(
            db.execute("ATTACH DATABASE ':memory:' AS other", [])
                .is_err()
        );
    }
}
