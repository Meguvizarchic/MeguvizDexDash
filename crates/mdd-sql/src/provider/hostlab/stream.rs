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
    pub(super) fn occurrence_into(
        &self,
        relation: ContractRelation,
        occurrence: &HostLabOccurrence,
        control: &SqlControl,
        sink: &mut dyn RowSink,
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
        match required {
            HostLabRelation::Methods => {
                let views = MethodCodeFactViews::build(
                    occurrence.definitions()?,
                    occurrence.code()?,
                    MethodCodeViewLimits::default(),
                )?;
                views.for_each_method_row(&mut |row| {
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
                        row.opcode_hex.map_or(Cell::Null, Cell::Str),
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
            HostLabRelation::MethodStrings => {
                occurrence.references()?.for_each_method_string(&mut |row| {
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
                })
            }
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
