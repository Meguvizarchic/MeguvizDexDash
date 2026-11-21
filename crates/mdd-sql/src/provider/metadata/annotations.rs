use super::*;

/// Source-bound encoded annotation facts. Encoded parameter slots do not by
/// themselves establish complete prototype-position coverage.
pub struct AnnotationSqlProvider {
    pub(super) binding: SqlBinding,
    pub(super) occurrences: Vec<Arc<mdd_facts::annotations::AnnotationFacts>>,
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
                snapshot_id: snapshot.to_string(),
                catalog_epoch: epoch,
            },
            occurrences,
        })
    }
}
#[derive(Clone, Copy)]
pub(super) enum AnnotationRelation {
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
    pub(super) fn parse(name: &str) -> Option<Self> {
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
/// One declared column of an annotation relation: name, SQL type, nullable.
type AnnotationColumnSpec = (&'static str, SqlType, bool);
/// One declared annotation relation: name, columns, and the fact relation it reads.
type AnnotationRelationSpec = (
    &'static str,
    &'static [AnnotationColumnSpec],
    AnnotationRelation,
);

impl SqlFactProvider for AnnotationSqlProvider {
    fn binding(&self) -> &SqlBinding {
        &self.binding
    }
    fn relations(&self) -> MddResult<Vec<SqlRelation>> {
        let specifications: [AnnotationRelationSpec; 11] = [
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
