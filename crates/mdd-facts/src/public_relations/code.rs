//! The method-bound code relations: method_opcodes, class_data_methods, try_items, catch_handlers, method_refs,
//! method_numbers, method_using_numbers.
//!
//! A relation bound to a method follows `code_items`: one row group per method that owns a present body, in
//! `method_idx` order, and a body shared by several methods is expanded once per owning method. A code item no
//! method declares is not a row of any of them.
use super::{require_metadata, row_budget, to_u32};
use crate::code::{MethodCodeBody, MethodCodeFactViews};
use crate::definitions::DefinitionFacts;
use crate::references::{ReferenceFacts, TargetKind};
use mdd_dex::{definitions::MethodReference, instructions::InvokeKind};
use mdd_types::{Completeness, ErrorCode, MddError, MddResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodOpcodeRow {
    pub file_id: u32,
    pub method_idx: u32,
    pub opcode_count: Option<u32>,
    pub opcode_hex: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassDataMethodRow {
    pub file_id: u32,
    pub class_idx: u32,
    pub method_idx: u32,
    pub access_flags: u32,
    pub kind: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TryItemRow {
    pub file_id: u32,
    pub method_idx: u32,
    pub try_idx: u32,
    pub start_addr: u32,
    pub insn_count: u32,
    /// The offset of the handler from the start of the code item's handler list, as the try item stores it.
    pub handler_off: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatchHandlerRow {
    pub file_id: u32,
    pub method_idx: u32,
    pub handler_idx: u32,
    pub handler_off: u32,
    pub ordinal: u32,
    pub type_idx: Option<u32>,
    pub addr: u32,
    pub is_catch_all: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodRefRow {
    pub file_id: u32,
    pub class_idx: u32,
    pub method_idx: u32,
    pub index_kind: &'static str,
    pub index: u32,
    pub using_type: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MethodNumberRow {
    pub file_id: u32,
    pub class_idx: u32,
    pub method_idx: u32,
    pub opcode: u32,
    pub number_type: &'static str,
    pub long_value: i64,
    pub double_value: Option<f64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MethodUsingNumberRow {
    pub method: String,
    pub method_class: String,
    pub method_name: String,
    pub number_type: &'static str,
    pub long_value: i64,
    pub double_value: Option<f64>,
    pub opcode: u32,
    pub file_id: u32,
    pub class_idx: u32,
    pub method_idx: u32,
}

impl DefinitionFacts {
    /// `class_data_methods`: every method a class data item declares, direct methods then virtual methods of a
    /// class, with its access flags and kind.
    pub fn class_data_method_rows(&self, file_id: u32) -> MddResult<Vec<ClassDataMethodRow>> {
        require_metadata(self.metadata(), "class_data_methods")?;
        if self.definition_coverage() != Completeness::Complete {
            return Err(MddError::new(
                ErrorCode::IncompleteFacts,
                "facts.public_relations",
                "complete definition facts are required",
            )
            .detail("relation", "class_data_methods"));
        }
        let methods = &self.definitions().method_definitions;
        row_budget(methods.len(), "class_data_methods")?;
        Ok(methods
            .iter()
            .map(|method| ClassDataMethodRow {
                file_id,
                class_idx: method.class_idx,
                method_idx: method.method_idx,
                access_flags: method.access_flags,
                kind: method.kind.as_str(),
            })
            .collect())
    }
}

/// The scalar type name the reference gives a literal, by the opcode that carries it: the width of the encoded
/// operand for the `const` family, the kind of the encoded constant for the wide ones.
fn number_type(opcode: u8) -> Option<(&'static str, NumberView)> {
    Some(match opcode {
        0x12 => ("byte", NumberView::Plain),
        0x13 => ("short", NumberView::Plain),
        0x14 | 0x15 => ("float", NumberView::Float32),
        0x16 => ("short", NumberView::Plain),
        0x17 => ("int", NumberView::Float32),
        0x18 => ("long", NumberView::Float64),
        0x19 => ("double", NumberView::Float64),
        0xd0..=0xd7 => ("short", NumberView::Plain),
        0xd8..=0xe2 => ("byte", NumberView::Plain),
        _ => return None,
    })
}

/// How a literal is also read as a floating point number: not at all, as the bits of a 32-bit float, or as the
/// bits of a 64-bit double.
#[derive(Clone, Copy)]
enum NumberView {
    Plain,
    Float32,
    Float64,
}

impl<'a> MethodCodeFactViews<'a> {
    /// `method_opcodes`: the opcode count and the opcode text of every method id; NULL only for a method that
    /// has no definition.
    pub fn method_opcode_rows(&self, file_id: u32) -> MddResult<Vec<MethodOpcodeRow>> {
        Ok(self
            .method_rows(file_id)?
            .into_iter()
            .map(|row| MethodOpcodeRow {
                file_id: row.file_id,
                method_idx: row.method_idx,
                opcode_count: row.opcode_count,
                opcode_hex: row.opcode_hex,
            })
            .collect())
    }

    /// `try_items`: the try blocks of every method-owned present body.
    pub fn try_item_rows(&self, file_id: u32) -> MddResult<Vec<TryItemRow>> {
        let mut rows = Vec::new();
        for view in self.iter() {
            let view = view?;
            let MethodCodeBody::Present { code, .. } = view.body else {
                continue;
            };
            let method_idx = view.method.reference.method_idx;
            for (try_idx, item) in code.data().tries.iter().enumerate() {
                row_budget(rows.len().saturating_add(1), "try_items")?;
                rows.push(TryItemRow {
                    file_id,
                    method_idx,
                    try_idx: to_u32(try_idx as u64, "try index")?,
                    start_addr: item.start_code_unit,
                    insn_count: u32::from(item.code_unit_count),
                    handler_off: u32::from(item.handler_relative_byte_offset),
                });
            }
        }
        Ok(rows)
    }

    /// `catch_handlers`: the typed catches of every handler of a method-owned present body, in order, then its
    /// catch-all (no type, `is_catch_all` set) when it has one.
    pub fn catch_handler_rows(&self, file_id: u32) -> MddResult<Vec<CatchHandlerRow>> {
        let mut rows = Vec::new();
        for view in self.iter() {
            let view = view?;
            let MethodCodeBody::Present { code, .. } = view.body else {
                continue;
            };
            let method_idx = view.method.reference.method_idx;
            for (handler_idx, handler) in code.data().handlers.iter().enumerate() {
                let handler_idx = to_u32(handler_idx as u64, "handler index")?;
                let mut ordinal = 0u32;
                for pair in &handler.typed_catches {
                    row_budget(rows.len().saturating_add(1), "catch_handlers")?;
                    rows.push(CatchHandlerRow {
                        file_id,
                        method_idx,
                        handler_idx,
                        handler_off: handler.relative_byte_offset,
                        ordinal,
                        type_idx: Some(pair.type_idx),
                        addr: pair.address_code_units,
                        is_catch_all: false,
                    });
                    ordinal += 1;
                }
                if let Some(addr) = handler.catch_all_address_code_units {
                    row_budget(rows.len().saturating_add(1), "catch_handlers")?;
                    rows.push(CatchHandlerRow {
                        file_id,
                        method_idx,
                        handler_idx,
                        handler_off: handler.relative_byte_offset,
                        ordinal,
                        type_idx: None,
                        addr,
                        is_catch_all: true,
                    });
                }
            }
        }
        Ok(rows)
    }

    /// Visit every numeric literal an instruction of a method-owned present body carries, with the method it
    /// belongs to, the opcode, the type name and the value read as an integer and, where the reference gives one,
    /// as a floating point number.
    fn for_each_number(
        &self,
        relation: &'static str,
        mut visit: impl FnMut(&MethodReference, u8, &'static str, i64, Option<f64>),
    ) -> MddResult<()> {
        let mut seen = 0usize;
        for view in self.iter() {
            let view = view?;
            let MethodCodeBody::Present { code, .. } = view.body else {
                continue;
            };
            for instruction in &code.data().instructions {
                let Some(literal) = &instruction.literal else {
                    continue;
                };
                let Some((name, how)) = number_type(instruction.opcode) else {
                    continue;
                };
                seen += 1;
                row_budget(seen, relation)?;
                // The literal as the instruction means it: the `high16` forms are already shifted into place, so
                // the bit pattern read as a floating point number is that of the value, not that of the field.
                let value = literal.signed_decimal.as_i64();
                let double_value = match how {
                    NumberView::Plain => None,
                    NumberView::Float32 => Some(f64::from(f32::from_bits(value as u32))),
                    NumberView::Float64 => Some(f64::from_bits(value as u64)),
                };
                visit(
                    view.method.reference,
                    instruction.opcode,
                    name,
                    value,
                    double_value,
                );
            }
        }
        Ok(())
    }

    /// `method_numbers`: every numeric literal an instruction of a method-owned present body carries.
    pub fn method_number_rows(&self, file_id: u32) -> MddResult<Vec<MethodNumberRow>> {
        let mut rows = Vec::new();
        self.for_each_number(
            "method_numbers",
            |method, opcode, name, long_value, double_value| {
                rows.push(MethodNumberRow {
                    file_id,
                    class_idx: method.class_idx,
                    method_idx: method.method_idx,
                    opcode: u32::from(opcode),
                    number_type: name,
                    long_value,
                    double_value,
                });
            },
        )?;
        Ok(rows)
    }

    /// `method_using_numbers`: `method_numbers` with the method spelled out.
    pub fn method_using_number_rows(&self, file_id: u32) -> MddResult<Vec<MethodUsingNumberRow>> {
        let mut rows = Vec::new();
        self.for_each_number(
            "method_using_numbers",
            |method, opcode, name, long_value, double_value| {
                rows.push(MethodUsingNumberRow {
                    method: method.descriptor.clone(),
                    method_class: method.class_descriptor.clone(),
                    method_name: method.method_name.clone(),
                    number_type: name,
                    long_value,
                    double_value,
                    opcode: u32::from(opcode),
                    file_id,
                    class_idx: method.class_idx,
                    method_idx: method.method_idx,
                });
            },
        )?;
        Ok(rows)
    }
}

impl ReferenceFacts {
    /// `method_refs`: every encoded reference operand of every method, with the kind of table it indexes. A field
    /// access also says whether it reads or writes.
    pub fn method_ref_rows(&self, file_id: u32) -> MddResult<Vec<MethodRefRow>> {
        self.require_complete()?;
        row_budget(self.sites().len(), "method_refs")?;
        Ok(self
            .sites()
            .iter()
            .filter(|site| {
                // An invoke-polymorphic names its prototype as a second operand. The reference lists the method
                // operand of such an instruction and not its prototype; so does this relation.
                !(site.target_kind == TargetKind::Prototype
                    && matches!(
                        site.invoke_kind,
                        Some(InvokeKind::Polymorphic | InvokeKind::PolymorphicRange)
                    ))
            })
            .map(|site| MethodRefRow {
                file_id,
                class_idx: site.class_idx,
                method_idx: site.caller_method_idx,
                index_kind: match site.target_kind {
                    TargetKind::String => "string",
                    TargetKind::Type => "type",
                    TargetKind::Field => "field",
                    TargetKind::Method => "method",
                    TargetKind::Prototype => "proto",
                    TargetKind::CallSite => "call_site",
                    TargetKind::MethodHandle => "method_handle",
                },
                index: site.target_local_index,
                using_type: if site.target_kind != TargetKind::Field {
                    None
                } else if site.mnemonic.starts_with("iget") || site.mnemonic.starts_with("sget") {
                    Some("get")
                } else if site.mnemonic.starts_with("iput") || site.mnemonic.starts_with("sput") {
                    Some("put")
                } else {
                    None
                },
            })
            .collect())
    }
}
