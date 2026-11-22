//! The rows of one DEX handed to a store one at a time.
//!
//! `occurrence_rows` makes every row of a relation for one DEX before anyone sees the first: for the biggest relations of
//! a large DEX that is a million rows, each cell a UTF-16 copy of text the facts hold already, several hundred megabytes
//! alive for as long as it takes to read them. Here a relation either hands its rows over as it makes them
//! (the call, field-access, type-use and string-use relations, and the methods, class-method and class-field ones, which are
//! most of the rows of an archive, borrow their text from the facts and copy none of it) or, for the smaller ones, is made
//! as before and handed over row by row.
//!
//! The rows are the same ones: a cell is the same text, number or NULL as in `occurrence_rows`, in the same order, and the
//! work charged to the control adds up to the same total.
use super::*;
use crate::column_store::{Cell, RowSink};

impl HostLabSqlProvider {
    pub(super) fn occurrence_into_with_views<'a>(
        &self,
        relation: ContractRelation,
        occurrence: &'a HostLabOccurrence,
        control: &SqlControl,
        sink: &mut dyn RowSink,
        shared_views: Option<&std::sync::OnceLock<MddResult<MethodCodeFactViews<'a>>>>,
        stream_extra: bool,
    ) -> MddResult<()> {
        let file_id = u64::from(occurrence.file_id);
        let ContractRelation::Required(required) = relation else {
            let ContractRelation::Public(public) = relation else {
                unreachable!("a contract relation is required or public")
            };
            for row in self.public_occurrence_rows(public, occurrence, control)? {
                sink.row(row)?;
            }
            return Ok(());
        };
        let local_views: std::sync::OnceLock<MddResult<MethodCodeFactViews<'a>>> =
            std::sync::OnceLock::new();
        let method_code_views = || -> MddResult<&MethodCodeFactViews<'a>> {
            let cell = shared_views.unwrap_or(&local_views);
            cell.get_or_init(|| {
                MethodCodeFactViews::build(
                    occurrence.definitions()?,
                    occurrence.code()?,
                    MethodCodeViewLimits::default(),
                )
            })
            .as_ref()
            .map_err(Clone::clone)
        };
        match required {
            HostLabRelation::Strings if stream_extra => {
                let pool_id = occurrence.string_pool_id;
                occurrence.facts.metadata.for_each_string_row_with_policy(
                    pool_id,
                    self.non_scalar_text_policy,
                    &mut |pool_id, string_idx, value| {
                        control.work(64)?;
                        sink.cells(&[
                            Cell::U64(u64::from(pool_id)),
                            Cell::U64(u64::from(string_idx)),
                            Cell::Str(value),
                        ])
                    },
                )
            }
            HostLabRelation::Types if stream_extra => occurrence.facts.metadata.for_each_type_row(
                &mut |type_idx, descriptor, java_name| {
                    control.work(96)?;
                    sink.cells(&[
                        Cell::U64(file_id),
                        Cell::U64(u64::from(type_idx)),
                        Cell::Str(descriptor),
                        Cell::Str(java_name),
                    ])
                },
            ),
            HostLabRelation::Classes if stream_extra => occurrence
                .definitions()?
                .for_each_class_row_with_policy(self.non_scalar_text_policy, &mut |row| {
                    control.work(96)?;
                    sink.cells(&[
                        Cell::U64(file_id),
                        Cell::U64(u64::from(row.class_def_idx)),
                        Cell::U64(u64::from(row.class_idx)),
                        Cell::Str(row.descriptor),
                        Cell::U64(u64::from(row.access_flags)),
                        row.superclass_descriptor.map_or(Cell::Null, Cell::Str),
                        Cell::U64(u64::from(row.interface_count)),
                        row.source_file.map_or(Cell::Null, Cell::Str),
                    ])
                }),
            HostLabRelation::ClassInterfaces if stream_extra => {
                for row in &occurrence.definitions()?.definitions().interfaces {
                    control.work(64)?;
                    sink.cells(&[
                        Cell::U64(file_id),
                        Cell::U64(u64::from(row.class_idx)),
                        Cell::U64(u64::from(row.ordinal)),
                        Cell::U64(u64::from(row.interface_type_idx)),
                        Cell::Str(&row.interface_descriptor),
                    ])?;
                }
                Ok(())
            }
            HostLabRelation::CodeItems if stream_extra => {
                let views = method_code_views()?;
                views.for_each_code_item_row(&mut |row| {
                    control.work(96)?;
                    sink.cells(&[
                        Cell::U64(file_id),
                        Cell::U64(u64::from(row.method_idx)),
                        Cell::U64(u64::from(row.code_off)),
                        Cell::U64(u64::from(row.registers_size)),
                        Cell::U64(u64::from(row.ins_size)),
                        Cell::U64(u64::from(row.outs_size)),
                        Cell::U64(u64::from(row.tries_size)),
                        Cell::U64(u64::from(row.debug_info_off)),
                        Cell::U64(u64::from(row.insns_size)),
                        Cell::U64(u64::from(row.insns_off)),
                        row.tries_off
                            .map_or(Cell::Null, |v| Cell::U64(u64::from(v))),
                        row.handlers_off
                            .map_or(Cell::Null, |v| Cell::U64(u64::from(v))),
                    ])
                })
            }
            HostLabRelation::AnnotationDirectoryEntries if stream_extra => {
                occurrence.annotations()?.for_each_directory_entry_row(
                    &mut |class_idx,
                          annotations_off,
                          entry_kind,
                          entry_idx,
                          annotation_set_off,
                          annotation_set_ref_list_off| {
                        control.work(96)?;
                        sink.cells(&[
                            Cell::U64(file_id),
                            Cell::U64(u64::from(class_idx)),
                            Cell::U64(u64::from(annotations_off)),
                            Cell::Str(entry_kind),
                            Cell::U64(u64::from(entry_idx)),
                            annotation_set_off.map_or(Cell::Null, |v| Cell::U64(u64::from(v))),
                            annotation_set_ref_list_off
                                .map_or(Cell::Null, |v| Cell::U64(u64::from(v))),
                        ])
                    },
                )
            }
            HostLabRelation::AnnotationSetEntries if stream_extra => {
                occurrence.annotations()?.for_each_reachable_set_entry_row(
                    &mut |annotation_set_off, ordinal, annotation_off| {
                        control.work(64)?;
                        sink.cells(&[
                            Cell::U64(file_id),
                            Cell::U64(u64::from(annotation_set_off)),
                            Cell::U64(u64::from(ordinal)),
                            Cell::U64(u64::from(annotation_off)),
                        ])
                    },
                )
            }
            HostLabRelation::Annotations if stream_extra => {
                occurrence.annotations()?.for_each_reachable_annotation_row(
                    &mut |annotation_off, visibility, type_idx, element_count| {
                        control.work(64)?;
                        sink.cells(&[
                            Cell::U64(file_id),
                            Cell::U64(u64::from(annotation_off)),
                            Cell::U64(u64::from(visibility)),
                            Cell::U64(u64::from(type_idx)),
                            Cell::U64(u64::from(element_count)),
                        ])
                    },
                )
            }
            HostLabRelation::AnnotationElements if stream_extra => occurrence
                .annotations()?
                .for_each_reachable_element_row(&mut |row| {
                    control.work(128)?;
                    let value_i64 = match row.value_i64 {
                        None => Cell::Null,
                        Some(raw_text) => raw_text.parse::<i64>().map(Cell::I64).map_err(|_| {
                            MddError::new(
                                ErrorCode::InternalFault,
                                "sql.hostlab",
                                "encoded integer value is not a canonical i64 decimal",
                            )
                            .detail("value", raw_text.to_owned())
                        })?,
                    };
                    let value_f64 = row
                        .value_f64
                        .map_or(Cell::Null, |value| Cell::F64(value.as_f64().to_bits()));
                    sink.cells(&[
                        Cell::U64(file_id),
                        Cell::U64(u64::from(row.annotation_off)),
                        Cell::U64(u64::from(row.depth)),
                        Cell::U64(u64::from(row.ordinal)),
                        row.name_idx.map_or(Cell::Null, |v| Cell::U64(u64::from(v))),
                        Cell::U64(u64::from(row.value_off)),
                        Cell::U64(u64::from(row.value_end_off)),
                        Cell::Str(row.value_kind),
                        row.value_index
                            .map_or(Cell::Null, |v| Cell::U64(u64::from(v))),
                        value_i64,
                        value_f64,
                    ])
                }),
            HostLabRelation::Methods => {
                let views = method_code_views()?;
                views.for_each_method_row_compact(&mut |row| {
                    control.work(192)?;
                    sink.cells(&[
                        Cell::U64(file_id),
                        Cell::U64(u64::from(row.method_idx)),
                        Cell::U64(u64::from(row.class_idx)),
                        Cell::Str(row.class_descriptor),
                        Cell::U64(u64::from(row.proto_idx)),
                        Cell::Str(row.name),
                        Cell::Str(row.descriptor),
                        Cell::Str(row.return_descriptor),
                        Cell::U64(u64::from(row.param_count)),
                        Cell::Str(row.param_descriptors),
                        row.access_flags
                            .map_or(Cell::Null, |v| Cell::U64(u64::from(v))),
                        row.opcode_count
                            .map_or(Cell::Null, |v| Cell::U64(u64::from(v))),
                        row.opcode_bytes.map_or(Cell::Null, Cell::SpacedHexBytes),
                        row.method_kind.map_or(Cell::Null, Cell::Str),
                    ])
                })
            }
            HostLabRelation::ClassFields => {
                occurrence.definitions()?.for_each_class_field(&mut |row| {
                    control.work(96)?;
                    sink.cells(&[
                        Cell::U64(file_id),
                        Cell::U64(u64::from(row.class_idx)),
                        Cell::Str(row.class_descriptor),
                        Cell::U64(u64::from(row.field_idx)),
                        Cell::Str(row.field_name),
                        Cell::Str(row.field_descriptor),
                        Cell::Str(row.kind),
                        Cell::U64(u64::from(row.access_flags)),
                    ])
                })
            }
            HostLabRelation::ClassMethods => {
                occurrence.definitions()?.for_each_class_method(&mut |row| {
                    control.work(96)?;
                    sink.cells(&[
                        Cell::U64(file_id),
                        Cell::U64(u64::from(row.class_idx)),
                        Cell::Str(row.class_descriptor),
                        Cell::U64(u64::from(row.method_idx)),
                        Cell::Str(row.method_name),
                        Cell::Str(row.method_descriptor),
                        Cell::Str(row.kind),
                        Cell::U64(u64::from(row.access_flags)),
                    ])
                })
            }
            HostLabRelation::MethodStrings => occurrence
                .references()?
                .for_each_method_string_with_policy(self.non_scalar_text_policy, &mut |row| {
                    control.work(128)?;
                    sink.cells(&[
                        Cell::Str(row.method),
                        Cell::Str(row.method_class),
                        Cell::Str(row.method_name),
                        Cell::Str(row.value),
                        Cell::U64(file_id),
                        Cell::U64(u64::from(row.class_idx)),
                        Cell::U64(u64::from(row.method_idx)),
                        Cell::U64(u64::from(row.string_idx)),
                    ])
                }),
            HostLabRelation::MethodCalls => {
                occurrence.references()?.for_each_method_call(&mut |row| {
                    control.work(160)?;
                    sink.cells(&[
                        Cell::Str(row.method),
                        Cell::Str(row.method_class),
                        Cell::Str(row.method_name),
                        Cell::Str(row.callee),
                        Cell::Str(row.callee_class),
                        Cell::Str(row.callee_name),
                        Cell::U64(file_id),
                        Cell::U64(u64::from(row.class_idx)),
                        Cell::U64(u64::from(row.method_idx)),
                        Cell::U64(u64::from(row.callee_method_idx)),
                    ])
                })
            }
            HostLabRelation::MethodFieldAccesses => {
                occurrence.references()?.for_each_method_field(&mut |row| {
                    control.work(192)?;
                    sink.cells(&[
                        Cell::Str(row.method),
                        Cell::Str(row.method_class),
                        Cell::Str(row.method_name),
                        Cell::Str(row.field),
                        Cell::Str(row.field_class),
                        Cell::Str(row.field_name),
                        Cell::Str(row.field_type),
                        row.using_type.map_or(Cell::Null, Cell::Str),
                        Cell::U64(file_id),
                        Cell::U64(u64::from(row.class_idx)),
                        Cell::U64(u64::from(row.method_idx)),
                        Cell::U64(u64::from(row.field_idx)),
                    ])
                })
            }
            HostLabRelation::MethodUsedTypes => {
                occurrence.references()?.for_each_method_type(&mut |row| {
                    control.work(160)?;
                    sink.cells(&[
                        Cell::Str(row.method),
                        Cell::Str(row.method_class),
                        Cell::Str(row.method_name),
                        Cell::Str(row.type_descriptor),
                        Cell::Str(row.type_name),
                        Cell::U64(file_id),
                        Cell::U64(u64::from(row.class_idx)),
                        Cell::U64(u64::from(row.method_idx)),
                        Cell::U64(u64::from(row.type_idx)),
                    ])
                })
            }
            other => {
                for row in self.occurrence_rows(other, occurrence, control)? {
                    sink.row(row)?;
                }
                Ok(())
            }
        }
    }
}
