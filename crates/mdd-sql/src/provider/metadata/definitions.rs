use super::*;

/// Direct native definition facts from one explicit snapshot scope. This does
/// not implement the legacy HostLab table layout or infer inherited members.
pub struct DefinitionSqlProvider {
    pub(super) binding: SqlBinding,
    pub(super) occurrences: Vec<Arc<DefinitionFacts>>,
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
                snapshot_id: snapshot.to_string(),
                catalog_epoch: epoch,
            },
            occurrences,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) enum DefinitionRelation {
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
