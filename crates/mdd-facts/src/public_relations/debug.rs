//! The debug relations: debug_info, debug_parameters, debug_positions, debug_locals, debug_opcodes.
//!
//! They follow `code_items`: one group per method that owns a present body with a debug program, in `method_idx`
//! order, and a program shared by several methods is expanded once per owning method. A program is read as the
//! complete physical byte stream: every opcode is a row of `debug_opcodes`, the closing END_SEQUENCE included,
//! whether or not its address lies inside the method.
use super::{row_budget, to_u32};
use crate::code::{MethodCodeBody, MethodCodeFactViews};
use mdd_dex::instructions::{DebugEvent, DebugInfo};
use mdd_types::MddResult;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebugInfoRow {
    pub file_id: u32,
    pub method_idx: u32,
    pub debug_info_off: u32,
    pub line_start: u32,
    pub parameters_size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebugParameterRow {
    pub file_id: u32,
    pub method_idx: u32,
    pub debug_info_off: u32,
    pub ordinal: u32,
    pub name_idx: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebugPositionRow {
    pub file_id: u32,
    pub method_idx: u32,
    pub debug_info_off: u32,
    pub ordinal: u32,
    pub address: u32,
    pub line: i64,
    pub source_file_idx: Option<u32>,
    pub prologue_end: bool,
    pub epilogue_begin: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebugLocalRow {
    pub file_id: u32,
    pub method_idx: u32,
    pub debug_info_off: u32,
    pub ordinal: u32,
    pub address: u32,
    pub event: &'static str,
    pub register_num: u32,
    pub name_idx: Option<u32>,
    pub type_idx: Option<u32>,
    pub signature_idx: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebugOpcodeRow {
    pub file_id: u32,
    pub method_idx: u32,
    pub debug_info_off: u32,
    pub ordinal: u32,
    pub opcode_off: u64,
    pub opcode_end_off: u64,
    pub opcode: u32,
    pub address: u32,
    pub line: i64,
    pub address_diff: Option<u32>,
    pub line_diff: Option<i64>,
    pub register_num: Option<u32>,
    pub name_idx: Option<u32>,
    pub type_idx: Option<u32>,
    pub signature_idx: Option<u32>,
    pub source_file_idx: Option<u32>,
    pub emits_position: bool,
    pub emits_local: bool,
}

/// What a register holds as a local variable, as the program has declared it so far: the name, type and
/// signature of its last start, which an end or a restart refers to.
#[derive(Clone, Copy, Default)]
struct Local {
    name_idx: Option<u32>,
    type_idx: Option<u32>,
    signature_idx: Option<u32>,
}

const END_SEQUENCE: u8 = 0;
const ADVANCE_PC: u8 = 1;
const ADVANCE_LINE: u8 = 2;
const START_LOCAL: u8 = 3;
const START_LOCAL_EXTENDED: u8 = 4;
const END_LOCAL: u8 = 5;
const RESTART_LOCAL: u8 = 6;
const SET_PROLOGUE_END: u8 = 7;
const SET_EPILOGUE_BEGIN: u8 = 8;
const FIRST_SPECIAL: u8 = 10;

fn is_local(opcode: u8) -> bool {
    matches!(
        opcode,
        START_LOCAL | START_LOCAL_EXTENDED | END_LOCAL | RESTART_LOCAL
    )
}

impl<'a> MethodCodeFactViews<'a> {
    /// Visit the debug program of every method-owned present body: the method, the program and the offset the
    /// code item names it by.
    fn for_each_debug_program(
        &self,
        mut visit: impl FnMut(u32, u32, &DebugInfo) -> MddResult<()>,
    ) -> MddResult<()> {
        let mut reader = self.code_reader();
        for view in self.iter() {
            let view = view?;
            let MethodCodeBody::Present { code, .. } = view.body else {
                continue;
            };
            // The debug program is decoded from the DEX bytes when the facts are compact.
            let item = reader.fact(code)?;
            let data: &mdd_dex::instructions::CodeItem = &item;
            let (Some(debug), Some(offset)) = (&data.debug_info, data.debug_info_byte_offset)
            else {
                continue;
            };
            visit(
                view.method.reference.method_idx,
                to_u32(offset.0, "debug_info_off")?,
                debug,
            )?;
        }
        Ok(())
    }

    /// `debug_info`: the header of every debug program: its first line and its parameter count.
    pub fn debug_info_rows(&self, file_id: u32) -> MddResult<Vec<DebugInfoRow>> {
        let mut rows = Vec::new();
        self.for_each_debug_program(|method_idx, debug_info_off, debug| {
            row_budget(rows.len().saturating_add(1), "debug_info")?;
            rows.push(DebugInfoRow {
                file_id,
                method_idx,
                debug_info_off,
                line_start: debug.initial_line,
                parameters_size: to_u32(
                    debug.parameter_name_indices.len() as u64,
                    "parameters_size",
                )?,
            });
            Ok(())
        })?;
        Ok(rows)
    }

    /// `debug_parameters`: the name of each parameter the program declares; NULL for an unnamed one.
    pub fn debug_parameter_rows(&self, file_id: u32) -> MddResult<Vec<DebugParameterRow>> {
        let mut rows = Vec::new();
        self.for_each_debug_program(|method_idx, debug_info_off, debug| {
            for (ordinal, name_idx) in debug.parameter_name_indices.iter().enumerate() {
                row_budget(rows.len().saturating_add(1), "debug_parameters")?;
                rows.push(DebugParameterRow {
                    file_id,
                    method_idx,
                    debug_info_off,
                    ordinal: to_u32(ordinal as u64, "parameter position")?,
                    name_idx: *name_idx,
                });
            }
            Ok(())
        })?;
        Ok(rows)
    }

    /// `debug_positions`: every position the program emits, with the source file in force and whether a
    /// prologue-end or an epilogue-begin marker preceded it.
    pub fn debug_position_rows(&self, file_id: u32) -> MddResult<Vec<DebugPositionRow>> {
        let mut rows = Vec::new();
        self.for_each_debug_program(|method_idx, debug_info_off, debug| {
            let mut source_file_idx = None;
            let (mut prologue_end, mut epilogue_begin) = (false, false);
            let mut ordinal = 0u32;
            for event in debug.events.iter() {
                match event.opcode {
                    SET_PROLOGUE_END => prologue_end = true,
                    SET_EPILOGUE_BEGIN => epilogue_begin = true,
                    9 => source_file_idx = event.file_idx,
                    _ => {}
                }
                if event.emits_position {
                    row_budget(rows.len().saturating_add(1), "debug_positions")?;
                    rows.push(DebugPositionRow {
                        file_id,
                        method_idx,
                        debug_info_off,
                        ordinal,
                        address: event.address_code_units,
                        line: event.encoded_line_decimal.as_i64(),
                        source_file_idx,
                        prologue_end,
                        epilogue_begin,
                    });
                    ordinal += 1;
                    prologue_end = false;
                    epilogue_begin = false;
                }
            }
            Ok(())
        })?;
        Ok(rows)
    }

    /// `debug_locals`: every local variable event: a start, a start with a signature, an end, a restart. An end
    /// or a restart carries the name, type and signature its register was started with.
    pub fn debug_local_rows(&self, file_id: u32) -> MddResult<Vec<DebugLocalRow>> {
        let mut rows = Vec::new();
        self.for_each_debug_program(|method_idx, debug_info_off, debug| {
            let mut locals: BTreeMap<u16, Local> = BTreeMap::new();
            let mut ordinal = 0u32;
            for event in debug.events.iter() {
                if !is_local(event.opcode) {
                    continue;
                }
                let register = event.register.unwrap_or_default();
                let local = resolve_local(&mut locals, &event);
                row_budget(rows.len().saturating_add(1), "debug_locals")?;
                rows.push(DebugLocalRow {
                    file_id,
                    method_idx,
                    debug_info_off,
                    ordinal,
                    address: event.address_code_units,
                    event: match event.opcode {
                        START_LOCAL => "start_local",
                        START_LOCAL_EXTENDED => "start_local_extended",
                        END_LOCAL => "end_local",
                        _ => "restart_local",
                    },
                    register_num: u32::from(register),
                    name_idx: local.name_idx,
                    type_idx: local.type_idx,
                    signature_idx: local.signature_idx,
                });
                ordinal += 1;
            }
            Ok(())
        })?;
        Ok(rows)
    }

    /// `debug_opcodes`: every opcode of every debug program, END_SEQUENCE included, with the address and the line
    /// in force after it and what it changed.
    pub fn debug_opcode_rows(&self, file_id: u32) -> MddResult<Vec<DebugOpcodeRow>> {
        let mut rows = Vec::new();
        self.for_each_debug_program(|method_idx, debug_info_off, debug| {
            let events: Vec<DebugEvent> = debug.events.iter().collect();
            let mut locals: BTreeMap<u16, Local> = BTreeMap::new();
            let (mut address, mut line) = (0u32, i64::from(debug.initial_line));
            for (ordinal, event) in events.iter().enumerate() {
                let end = events.get(ordinal + 1).map_or(
                    debug.raw_range.byte_offset.0 + debug.raw_range.byte_length.0,
                    |next| next.byte_offset.0,
                );
                let now_line = event.encoded_line_decimal.as_i64();
                let moves_pc = event.opcode == ADVANCE_PC || event.opcode >= FIRST_SPECIAL;
                let moves_line = event.opcode == ADVANCE_LINE || event.opcode >= FIRST_SPECIAL;
                let local = is_local(event.opcode).then(|| resolve_local(&mut locals, event));
                row_budget(rows.len().saturating_add(1), "debug_opcodes")?;
                rows.push(DebugOpcodeRow {
                    file_id,
                    method_idx,
                    debug_info_off,
                    ordinal: to_u32(ordinal as u64, "opcode position")?,
                    opcode_off: event.byte_offset.0,
                    opcode_end_off: end,
                    opcode: u32::from(event.opcode),
                    address: event.address_code_units,
                    line: now_line,
                    address_diff: moves_pc.then(|| event.address_code_units.wrapping_sub(address)),
                    line_diff: moves_line.then(|| now_line - line),
                    register_num: event.register.map(u32::from),
                    name_idx: local.and_then(|local| local.name_idx),
                    type_idx: local.and_then(|local| local.type_idx),
                    signature_idx: local.and_then(|local| local.signature_idx),
                    source_file_idx: event.file_idx,
                    emits_position: event.emits_position,
                    emits_local: is_local(event.opcode),
                });
                address = event.address_code_units;
                line = now_line;
                if event.opcode == END_SEQUENCE {
                    break;
                }
            }
            Ok(())
        })?;
        Ok(rows)
    }
}

/// The name, type and signature a local event shows: those it declares itself (a start), or those its register
/// was last started with (an end or a restart).
fn resolve_local(locals: &mut BTreeMap<u16, Local>, event: &DebugEvent) -> Local {
    let register = event.register.unwrap_or_default();
    match event.opcode {
        START_LOCAL | START_LOCAL_EXTENDED => {
            let local = Local {
                name_idx: event.name_idx,
                type_idx: event.type_idx,
                signature_idx: event.signature_idx,
            };
            locals.insert(register, local);
            local
        }
        _ => locals.get(&register).copied().unwrap_or_default(),
    }
}
