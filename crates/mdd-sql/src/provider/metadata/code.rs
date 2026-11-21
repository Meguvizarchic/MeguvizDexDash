use super::*;

/// Physical code items for explicit complete DEX occurrence scopes. This does
/// not establish method ownership, inferred dispatch, or legacy compatibility.
pub struct CodeSqlProvider {
    pub(super) binding: SqlBinding,
    pub(super) occurrences: Vec<Arc<mdd_facts::code::CodeFacts>>,
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
                snapshot_id: snapshot.to_string(),
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
pub(super) enum CodeRelation {
    Items,
    Bytes,
    Tries,
    Handlers,
    Catches,
}
impl CodeRelation {
    pub(super) fn parse(name: &str) -> MddResult<Self> {
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
pub(super) fn code_bytes(value: &[u8], control: &SqlControl) -> MddResult<SqlValue> {
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
