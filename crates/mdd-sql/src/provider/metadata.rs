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
    Strings,
    Types,
    Prototypes,
    PrototypeParameters,
}
impl MetadataRelation {
    fn parse(name: &str) -> MddResult<Self> {
        if name.eq_ignore_ascii_case("native_dex_occurrences") {
            Ok(Self::DexOccurrences)
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
                        mdd_dex::definitions::MethodBody::Present {
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
        } else if relation.eq_ignore_ascii_case("native_reference_sites") {
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
        } else if relation.eq_ignore_ascii_case("native_reference_sites") {
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
    bytes: bool,
    control: SqlControl,
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
                let occurrence = scalar_text(&facts.source().dex_occurrence_id, &self.control)?;
                let row = if self.bytes {
                    vec![
                        occurrence,
                        SqlValue::U64(code.raw_range.byte_offset),
                        code_bytes(facts.raw_insns(self.ordinal)?, &self.control)?,
                        code_bytes(facts.raw_code_item(self.ordinal)?, &self.control)?,
                    ]
                } else {
                    let u = |n| SqlValue::U64(DecimalU64(n));
                    vec![
                        occurrence,
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
                };
                self.ordinal += 1;
                return Ok(Some(row));
            }
            self.occurrence += 1;
            self.ordinal = 0;
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
        let relation = |name: &str, cols: &[(&str, SqlType, bool)]| SqlRelation {
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
            estimated_rows: Some(DecimalU64(count)),
        };
        Ok(vec![
            relation("native_code_items", &metadata),
            relation("native_code_bytes", &bytes),
        ])
    }
    fn require_relation(&self, relation: &str) -> MddResult<()> {
        if relation.eq_ignore_ascii_case("native_code_items")
            || relation.eq_ignore_ascii_case("native_code_bytes")
        {
            Ok(())
        } else {
            Err(invalid("UNKNOWN_CODE_RELATION"))
        }
    }
    fn open_cursor(
        self: Arc<Self>,
        relation: &str,
        control: SqlControl,
    ) -> MddResult<Box<dyn SqlFactCursor>> {
        self.require_relation(relation)?;
        let bytes = relation.eq_ignore_ascii_case("native_code_bytes");
        Ok(Box::new(CodeCursor {
            provider: self,
            occurrence: 0,
            ordinal: 0,
            bytes,
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
    control: SqlControl,
}
impl SqlFactCursor for ReferenceCursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
        use mdd_dex::instructions::InvokeKind;
        use mdd_facts::references::TargetKind;
        while let Some(facts) = self.provider.occurrences.get(self.occurrence) {
            self.control.checkpoint(1, false)?;
            if let Some(site) = facts.sites().get(self.ordinal) {
                self.control.work(200)?;
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
        Ok(vec![SqlRelation {
            name: "native_reference_sites".into(),
            columns: columns
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
                FactLayer::CodeLayout,
                FactLayer::References,
            ],
            estimated_rows: Some(DecimalU64(count)),
        }])
    }
    fn require_relation(&self, relation: &str) -> MddResult<()> {
        if !relation.eq_ignore_ascii_case("native_reference_sites") {
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
        Ok(Box::new(ReferenceCursor {
            provider: self,
            occurrence: 0,
            ordinal: 0,
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
