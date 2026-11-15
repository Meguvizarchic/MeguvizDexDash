//! What each Dalvik opcode does to control flow and to registers.
//!
//! This is the knowledge the CFG and the def-use pass stand on, so it is checked
//! against an independent source: the tests parse AOSP's `dex_instruction_list.h`
//! (kept under artifacts/mdd-023/aosp-reference/) and compare, for all 256 opcodes,
//! the flow class, whether the instruction may throw, and how many register operands
//! it has and which of them are wide. The roles (which operand is written, which is
//! read) are not in AOSP's table and are covered by hand-written fixtures.

/// How control leaves an instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Flow {
    /// Falls through to the next instruction.
    Next,
    /// Always jumps.
    Goto,
    /// Jumps or falls through.
    Conditional,
    /// Jumps to one of the payload's targets or falls through (the default).
    Switch,
    /// Leaves the method normally.
    Return,
    /// `throw`: never falls through.
    Throw,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Def,
    Use,
    /// Read, then written (the `/2addr` forms).
    DefUse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Slot {
    pub role: Role,
    /// A 64-bit value in a register pair `vN, vN+1`.
    pub wide: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct OpInfo {
    pub flow: Flow,
    /// May raise an exception, so a handler of an enclosing try may be entered.
    pub may_throw: bool,
    /// Register operands in encoding order (`A`, `B`, `C`).
    pub slots: [Option<Slot>; 3],
    /// Reads every register the instruction lists (the invoke family and
    /// `filled-new-array`).
    pub variadic_uses: bool,
    /// Leaves a value for the following `move-result*`.
    pub sets_result: bool,
    /// Consumes the value left by the preceding instruction.
    pub reads_result: bool,
    /// Consumes the exception the handler was entered with.
    pub reads_exception: bool,
}

const fn slot(role: Role, wide: bool) -> Option<Slot> {
    Some(Slot { role, wide })
}

const D: Role = Role::Def;
const U: Role = Role::Use;

/// `None` for opcodes the DEX format leaves unused or reserved: no arm below names them.
pub fn info(opcode: u8) -> Option<OpInfo> {
    let flow = match opcode {
        0x0e..=0x11 => Flow::Return,
        0x27 => Flow::Throw,
        0x28..=0x2a => Flow::Goto,
        0x2b | 0x2c => Flow::Switch,
        0x32..=0x3d => Flow::Conditional,
        _ => Flow::Next,
    };
    // Instructions with a kThrow flag in AOSP's table.
    let may_throw = matches!(opcode,
        0x1a..=0x27
        | 0x44..=0x72
        | 0x74..=0x78
        | 0x93 | 0x94 | 0x9e | 0x9f
        | 0xb3 | 0xb4 | 0xbe | 0xbf
        | 0xd3 | 0xd4 | 0xdb | 0xdc
        | 0xfa..=0xff);
    let variadic = matches!(opcode, 0x24 | 0x25 | 0x6e..=0x72 | 0x74..=0x78 | 0xfa..=0xfd);
    let none = [None, None, None];
    let slots: [Option<Slot>; 3] = match opcode {
        0x00 | 0x0e | 0x28..=0x2a => none,
        // move, move/from16, move/16 and their -object forms
        0x01..=0x03 | 0x07..=0x09 => [slot(D, false), slot(U, false), None],
        0x04..=0x06 => [slot(D, true), slot(U, true), None],
        0x0a | 0x0c | 0x0d => [slot(D, false), None, None],
        0x0b => [slot(D, true), None, None],
        0x0f | 0x11 => [slot(U, false), None, None],
        0x10 => [slot(U, true), None, None],
        0x12..=0x15 | 0x1a..=0x1c | 0x22 | 0xfe | 0xff => [slot(D, false), None, None],
        0x16..=0x19 => [slot(D, true), None, None],
        0x1d | 0x1e | 0x1f | 0x26 | 0x27 | 0x2b | 0x2c => [slot(U, false), None, None],
        0x20 | 0x21 | 0x23 => [slot(D, false), slot(U, false), None],
        0x24 | 0x25 | 0x6e..=0x72 | 0x74..=0x78 | 0xfa..=0xfd => none,
        // cmpl-float, cmpg-float
        0x2d | 0x2e => [slot(D, false), slot(U, false), slot(U, false)],
        // cmpl-double, cmpg-double
        0x2f | 0x30 => [slot(D, false), slot(U, true), slot(U, true)],
        // cmp-long
        0x31 => [slot(D, false), slot(U, true), slot(U, true)],
        0x32..=0x37 => [slot(U, false), slot(U, false), None],
        0x38..=0x3d => [slot(U, false), None, None],
        // aget, aget-object, -boolean, -byte, -char, -short
        0x44 | 0x46..=0x4a => [slot(D, false), slot(U, false), slot(U, false)],
        0x45 => [slot(D, true), slot(U, false), slot(U, false)],
        0x4b | 0x4d..=0x51 => [slot(U, false), slot(U, false), slot(U, false)],
        0x4c => [slot(U, true), slot(U, false), slot(U, false)],
        0x52 | 0x54..=0x58 => [slot(D, false), slot(U, false), None],
        0x53 => [slot(D, true), slot(U, false), None],
        0x59 | 0x5b..=0x5f => [slot(U, false), slot(U, false), None],
        0x5a => [slot(U, true), slot(U, false), None],
        0x60 | 0x62..=0x66 => [slot(D, false), None, None],
        0x61 => [slot(D, true), None, None],
        0x67 | 0x69..=0x6d => [slot(U, false), None, None],
        0x68 => [slot(U, true), None, None],
        // unary operations: neg, not, conversions
        0x7b | 0x7c | 0x7f | 0x82 | 0x87 | 0x8d..=0x8f => [slot(D, false), slot(U, false), None],
        0x7d | 0x7e | 0x80 | 0x86 | 0x8b => [slot(D, true), slot(U, true), None],
        0x81 | 0x83 | 0x88 | 0x89 => [slot(D, true), slot(U, false), None],
        0x84 | 0x85 | 0x8a | 0x8c => [slot(D, false), slot(U, true), None],
        // binary operations: int and float are narrow, long and double wide, and the
        // shift count of a long shift is narrow.
        0x90..=0x9a | 0xa6..=0xaa => [slot(D, false), slot(U, false), slot(U, false)],
        0x9b..=0xa2 | 0xab..=0xaf => [slot(D, true), slot(U, true), slot(U, true)],
        0xa3..=0xa5 => [slot(D, true), slot(U, true), slot(U, false)],
        // the /2addr forms: A is read, then written
        0xb0..=0xba | 0xc6..=0xca => [slot(Role::DefUse, false), slot(U, false), None],
        0xbb..=0xc2 | 0xcb..=0xcf => [slot(Role::DefUse, true), slot(U, true), None],
        0xc3..=0xc5 => [slot(Role::DefUse, true), slot(U, false), None],
        0xd0..=0xe2 => [slot(D, false), slot(U, false), None],
        _ => return None,
    };
    Some(OpInfo {
        flow,
        may_throw,
        slots,
        variadic_uses: variadic,
        sets_result: variadic,
        reads_result: matches!(opcode, 0x0a..=0x0c),
        reads_exception: opcode == 0x0d,
    })
}
