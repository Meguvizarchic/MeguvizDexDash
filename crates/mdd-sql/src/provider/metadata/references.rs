use super::*;

/// Encoded reference sites for an explicit, complete set of DEX occurrences.
/// This does not infer runtime dispatch or legacy method-call rows.
pub struct ReferenceSqlProvider {
    pub(super) binding: SqlBinding,
    pub(super) occurrences: Vec<Arc<mdd_facts::references::ReferenceFacts>>,
}
pub(super) fn is_reference_relation(name: &str) -> bool {
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
                snapshot_id: snapshot.to_string(),
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
                    scalar_text(site.mnemonic, &self.control)?,
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
