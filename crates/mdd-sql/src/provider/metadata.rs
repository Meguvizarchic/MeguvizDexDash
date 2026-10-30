//! Native metadata relations read by occurrence and ordinal from immutable facts.
//! No legacy table projection or row-table ETL is implied.
use super::*;
use crate::{quota, values::SqlText};
use mdd_facts::{MetadataFacts, metadata::StringFact};
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
    Strings,
    Types,
    Prototypes,
    PrototypeParameters,
}
impl MetadataRelation {
    fn parse(name: &str) -> MddResult<Self> {
        if name.eq_ignore_ascii_case("native_strings") {
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
