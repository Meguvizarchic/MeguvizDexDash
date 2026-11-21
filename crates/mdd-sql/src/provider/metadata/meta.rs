use super::*;

pub struct MetadataSqlProvider {
    pub(super) binding: SqlBinding,
    pub(super) occurrences: Vec<Arc<MetadataFacts>>,
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
                snapshot_id: snapshot.to_string(),
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
pub(super) enum MetadataRelation {
    DexOccurrences,
    StringPools,
    Strings,
    Types,
    Prototypes,
    PrototypeParameters,
}
impl MetadataRelation {
    pub(super) fn parse(name: &str) -> MddResult<Self> {
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
