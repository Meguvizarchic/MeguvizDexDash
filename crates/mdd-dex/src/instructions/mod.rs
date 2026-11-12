//! Bounded standard code_item and instruction layout decoding over held bytes.
//! This layer does not perform ART type-flow verification or infer dispatch.
use crate::{
    DexHeader, DexRange,
    checked_reader::{CheckedReader, invalid},
    strings::{read_sleb128, read_uleb128},
};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

mod debug;
mod decode;
mod opcodes;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug)]
pub struct CodeLimits {
    pub debug_policy: DebugPolicy,
    pub max_code_items: u32,
    pub max_total_code_units: u64,
    pub max_instructions: u64,
    pub max_payload_elements: u64,
    pub max_switch_targets: u64,
    pub max_catch_pairs: u64,
    pub max_debug_operations: u64,
}

impl Default for CodeLimits {
    fn default() -> Self {
        Self {
            debug_policy: DebugPolicy::EncodedFactsV1,
            max_code_items: 4_000_000,
            max_total_code_units: 128 * 1024 * 1024,
            max_instructions: 128 * 1024 * 1024,
            max_payload_elements: 16 * 1024 * 1024,
            max_switch_targets: 16 * 1024 * 1024,
            max_catch_pairs: 16 * 1024 * 1024,
            max_debug_operations: 16 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceKind {
    String,
    Type,
    Field,
    Method,
    Prototype,
    CallSite,
    MethodHandle,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReferenceOperand {
    pub kind: ReferenceKind,
    pub local_index: u32,
    pub raw_range: DexRange,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum InvokeKind {
    Ordinary,
    OrdinaryRange,
    Polymorphic,
    PolymorphicRange,
    Custom,
    CustomRange,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterRange {
    pub first: u16,
    pub word_count: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiteralValue {
    pub signed_decimal: SignedDecimal,
    pub encoded_bits: DecimalU64,
    pub encoded_width_bits: u8,
}

/// Register operands of one instruction.
///
/// Almost every DEX instruction addresses at most five registers, so the common
/// case is stored inline and costs no heap allocation. The `3rc`/`4rcc` range
/// formats may legitimately address more (bounded only by `registers_size`), so
/// the tail spills into a `Vec` instead of losing those operands. The JSON form
/// is unchanged: still a plain array of register indices.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Registers {
    inline: [u16; 5],
    /// Inline count, saturated at 5. Once saturated, further operands go to `extra`.
    len: u8,
    extra: Vec<u16>,
}

impl Registers {
    pub fn len(&self) -> usize {
        if self.len < 5 {
            self.len as usize
        } else {
            5 + self.extra.len()
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn iter(&self) -> impl Iterator<Item = u16> + '_ {
        self.inline
            .iter()
            .take(self.len.min(5) as usize)
            .copied()
            .chain(self.extra.iter().copied())
    }
    fn push(&mut self, value: u16) {
        if self.len < 5 {
            self.inline[self.len as usize] = value;
            self.len += 1;
        } else {
            self.extra.push(value);
        }
    }
    fn extend(&mut self, values: [u16; 2]) {
        self.push(values[0]);
        self.push(values[1]);
    }
    fn extend_three(&mut self, values: [u16; 3]) {
        self.push(values[0]);
        self.push(values[1]);
        self.push(values[2]);
    }
}

impl From<&[u16]> for Registers {
    fn from(values: &[u16]) -> Self {
        let mut registers = Self::default();
        for value in values {
            registers.push(*value);
        }
        registers
    }
}

impl Serialize for Registers {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for value in self.iter() {
            seq.serialize_element(&value)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Registers {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{SeqAccess, Visitor};
        use std::fmt;

        struct RegistersVisitor;
        impl<'de> Visitor<'de> for RegistersVisitor {
            type Value = Registers;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a sequence of register indices")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut registers = Registers::default();
                while let Some(value) = seq.next_element::<u16>()? {
                    registers.push(value);
                }
                Ok(registers)
            }
        }
        deserializer.deserialize_seq(RegistersVisitor)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Instruction {
    pub opcode: u8,
    /// Borrowed from the static opcode table; serializes as a plain string.
    pub mnemonic: Cow<'static, str>,
    /// Borrowed from the static opcode table; serializes as a plain string.
    pub format: Cow<'static, str>,
    pub byte_offset: DecimalU64,
    pub code_unit_offset: u32,
    pub instruction_ordinal: u32,
    pub width_code_units: u8,
    pub registers: Registers,
    pub register_range: Option<RegisterRange>,
    pub references: Vec<ReferenceOperand>,
    pub literal: Option<LiteralValue>,
    pub branch_offset_code_units: Option<i32>,
    pub branch_target_code_units: Option<u32>,
    pub payload_target_code_units: Option<u32>,
    pub invoke_kind: Option<InvokeKind>,
    pub raw_range: DexRange,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PayloadData {
    PackedSwitch {
        first_key: i32,
        relative_targets: Vec<i32>,
    },
    SparseSwitch {
        keys: Vec<i32>,
        relative_targets: Vec<i32>,
    },
    FillArray {
        element_width_bytes: u16,
        element_count: u32,
        data_range: DexRange,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payload {
    pub code_unit_offset: u32,
    pub width_code_units: u32,
    pub raw_range: DexRange,
    pub data: PayloadData,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwitchTargets {
    pub instruction_code_unit_offset: u32,
    pub payload_code_unit_offset: u32,
    pub target_code_units: Vec<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatchPair {
    pub type_idx: u32,
    pub address_code_units: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatchHandler {
    pub byte_offset: DecimalU64,
    pub relative_byte_offset: u32,
    pub typed_catches: Vec<CatchPair>,
    pub catch_all_address_code_units: Option<u32>,
    pub raw_range: DexRange,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TryItem {
    pub byte_offset: DecimalU64,
    pub start_code_unit: u32,
    pub code_unit_count: u16,
    pub handler_relative_byte_offset: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugRepresentation {
    EventProgram,
    PcToPcPattern,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DebugPolicy {
    #[serde(rename = "mdd-debug-encoded-v1")]
    EncodedFactsV1,
    #[serde(rename = "mdd-debug-source-lines-strict-v1")]
    StrictSourceLinesV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceLineKind {
    NotAPosition,
    PositiveEncodedLine,
    UnknownNonPositive,
    PcSurrogate,
    OutsideCodeContext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugAddressScope {
    InsideCodeUnits,
    AtCodeEnd,
    BeyondCodeEnd,
}

/// Decoded debug line kept as an integer.
///
/// The previous representation materialized one `String` per debug event, which
/// for a large APK is millions of allocations. The encoded form is still emitted
/// as the same canonical decimal string, and only digits plus an optional leading
/// minus are accepted so a re-read cannot accept a non-canonical spelling that the
/// old `line.to_string()` could never produce.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SignedDecimal(pub i64);

impl Serialize for SignedDecimal {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(StackDecimal::new(self.0).as_str())
    }
}

impl<'de> Deserialize<'de> for SignedDecimal {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Cow::<'de, str>::deserialize(deserializer)?;
        let value = text.parse::<i64>().map_err(serde::de::Error::custom)?;
        // Reject the alternative spellings `+1`, `-0` and leading zeroes; the
        // integer round trip produces exactly one spelling.
        if StackDecimal::new(value).as_str() != text {
            return Err(serde::de::Error::custom(
                "expected canonical decimal i64 string",
            ));
        }
        Ok(Self(value))
    }
}

impl SignedDecimal {
    pub fn as_i64(self) -> i64 {
        self.0
    }
}

/// Canonical decimal rendering of an `i64` in a stack buffer, so the encoders can
/// emit the retained text form without allocating one `String` per debug event.
/// `-9223372036854775808` is the longest possible output at twenty bytes.
struct StackDecimal {
    bytes: [u8; 20],
    start: usize,
}

impl StackDecimal {
    fn new(value: i64) -> Self {
        let mut bytes = [0u8; 20];
        let (negative, magnitude) = if value < 0 {
            (true, value.unsigned_abs())
        } else {
            (false, value as u64)
        };
        let mut at = bytes.len();
        let mut rest = magnitude;
        loop {
            at -= 1;
            bytes[at] = b'0' + (rest % 10) as u8;
            rest /= 10;
            if rest == 0 {
                break;
            }
        }
        if negative {
            at -= 1;
            bytes[at] = b'-';
        }
        Self { bytes, start: at }
    }

    fn as_str(&self) -> &str {
        // Only ASCII digits and an optional leading minus sign are written.
        std::str::from_utf8(&self.bytes[self.start..]).unwrap_or_default()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DebugEvent {
    pub byte_offset: DecimalU64,
    pub opcode: u8,
    pub address_code_units: u32,
    /// Canonical decimal string form of the running encoded line.
    pub encoded_line_decimal: SignedDecimal,
    pub source_line: Option<DecimalU64>,
    pub source_line_usable: bool,
    pub source_line_kind: SourceLineKind,
    pub register: Option<u16>,
    pub name_idx: Option<u32>,
    pub type_idx: Option<u32>,
    pub signature_idx: Option<u32>,
    pub file_idx: Option<u32>,
    pub emits_position: bool,
    pub code_item_address_scope: DebugAddressScope,
}

/// One code item's view of a debug program's events.
///
/// A debug program is typically named by tens of code items and only a handful
/// of distinct code sizes occur per program, so storing a projected
/// `Vec<DebugEvent>` per code item is almost entirely duplicate data: one
/// physical program is decoded once, then re-expanded 15-20 times. `Shared` keeps
/// the single decoded program behind an `Arc` and projects each event against the
/// referring item's `size` on demand; `Owned` covers the rare program that failed
/// its program-level decode and had to be re-walked for this item alone.
///
/// `Index<usize>` is deliberately not implemented: a shared view has no address
/// for `&DebugEvent`, so `get(i)` returns a value instead.
#[derive(Clone, Debug)]
pub enum DebugEvents {
    Shared(SharedDebugEvents),
    Owned(Vec<DebugEvent>),
}

#[derive(Clone, Debug)]
pub struct SharedDebugEvents {
    program: std::sync::Arc<debug::DebugProgram>,
    size: u32,
}

impl DebugEvents {
    pub fn len(&self) -> usize {
        match self {
            Self::Shared(shared) => shared.program.len(),
            Self::Owned(events) => events.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Project one event onto the referring code item.
    pub fn get(&self, index: usize) -> Option<DebugEvent> {
        match self {
            Self::Shared(shared) => {
                (index < shared.program.len()).then(|| shared.program.event_at(shared.size, index))
            }
            Self::Owned(events) => events.get(index).cloned(),
        }
    }

    /// Every event projected onto the referring code item, in encoded order.
    pub fn iter(&self) -> DebugEventsIter<'_> {
        DebugEventsIter {
            events: self,
            index: 0,
        }
    }
}

impl SharedDebugEvents {
    /// The decoded program this view projects, for sharing assertions.
    ///
    /// Returns the `Arc` erased to `Arc<()>`'s address identity through
    /// `program_id`, so the internal program type stays private.
    pub fn program_id(&self) -> usize {
        std::sync::Arc::as_ptr(&self.program) as usize
    }

    pub fn code_item_size(&self) -> u32 {
        self.size
    }
}

pub struct DebugEventsIter<'a> {
    events: &'a DebugEvents,
    index: usize,
}

impl Iterator for DebugEventsIter<'_> {
    type Item = DebugEvent;
    fn next(&mut self) -> Option<DebugEvent> {
        let event = self.events.get(self.index)?;
        self.index += 1;
        Some(event)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.events.len().saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for DebugEventsIter<'_> {}

/// A `Vec<DebugEvent>` for deserialized input and `Shared` for anything decoded
/// here, so `DebugEvents` can be read back but never silently claims sharing.
impl From<Vec<DebugEvent>> for DebugEvents {
    fn from(events: Vec<DebugEvent>) -> Self {
        Self::Owned(events)
    }
}

/// Hand-written so a shared view streams the projected events instead of
/// serializing the `Arc<DebugProgram>`'s internal representation. The field order
/// matches the previous derived output byte for byte.
impl Serialize for DebugEvents {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        match self {
            Self::Shared(shared) => {
                for index in 0..shared.program.len() {
                    seq.serialize_element(&shared.program.event_at(shared.size, index))?;
                }
            }
            Self::Owned(events) => {
                for event in events {
                    seq.serialize_element(event)?;
                }
            }
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for DebugEvents {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::<DebugEvent>::deserialize(deserializer).map(Self::Owned)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DebugInfo {
    pub raw_range: DexRange,
    pub initial_line: u32,
    pub parameter_name_indices: std::sync::Arc<[Option<u32>]>,
    pub events: DebugEvents,
    pub representation: DebugRepresentation,
    pub referring_code_unit_length: u32,
    pub raw_position_count: DecimalU64,
    pub applicable_method_position_count: DecimalU64,
    pub usable_method_source_position_count: DecimalU64,
    pub unusable_method_source_position_count: DecimalU64,
    pub debug_policy: DebugPolicy,
    pub strict_positive_line_policy_satisfied: bool,
    pub validation_scope: String,
}

impl DebugInfo {
    /// A borrowed method view; the complete physical program remains in events.
    pub fn method_positions(&self) -> impl Iterator<Item = DebugEvent> + '_ {
        self.events.iter().filter(|event| {
            event.emits_position
                && event.code_item_address_scope == DebugAddressScope::InsideCodeUnits
        })
    }

    pub fn usable_source_positions(&self) -> impl Iterator<Item = DebugEvent> + '_ {
        self.events.iter().filter(|event| event.source_line_usable)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeItem {
    pub raw_range: DexRange,
    pub insns_range: DexRange,
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub insns_size_code_units: u32,
    pub debug_info_byte_offset: Option<DecimalU64>,
    pub instructions: Vec<Instruction>,
    pub payloads: Vec<Payload>,
    pub switch_targets: Vec<SwitchTargets>,
    pub tries: Vec<TryItem>,
    pub handlers: Vec<CatchHandler>,
    /// Shared per physical program and referring code size. `Arc` because many
    /// code items name one debug program and only a few distinct code sizes occur
    /// per program, so the projected event sequence is stored once instead of
    /// once per code item.
    pub debug_info: Option<std::sync::Arc<DebugInfo>>,
    pub validation_scope: String,
    pub full_art_verification_complete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeSection {
    pub declared_code_item_count: u32,
    pub declared_code_item_byte_offsets: Vec<DecimalU64>,
    pub items: Vec<CodeItem>,
    pub scope: String,
    pub completed_layers: Vec<String>,
    pub full_dex_validation_complete: bool,
}

struct Opcode {
    name: &'static str,
    format: &'static str,
    index: &'static str,
    wide_mask: u8,
    nonzero_args: bool,
    reserved: bool,
    min_version: u16,
}

/// Borrowed mnemonic for an opcode byte.
///
/// The table is `'static`, so downstream fact layers can reference the name
/// without cloning a `String` per encoded instruction.
pub fn opcode_mnemonic(opcode: u8) -> &'static str {
    opcodes::OPCODES[usize::from(opcode)].name
}

#[derive(Clone, Copy)]
struct Counts {
    strings: u32,
    types: u32,
    fields: u32,
    methods: u32,
    prototypes: u32,
    call_sites: u32,
    handles: u32,
}

#[derive(Clone, Copy)]
struct DecodeContext {
    base: u64,
    registers: u16,
    outs: u16,
    counts: Counts,
    version: u16,
    limits: CodeLimits,
}

impl Counts {
    fn from_header(header: &DexHeader) -> Self {
        let fixed = |name: &str| {
            header
                .tables
                .iter()
                .find(|t| t.name == name)
                .map_or(0, |t| t.count)
        };
        let map = |kind| {
            header
                .map
                .iter()
                .find(|m| m.type_code == kind)
                .map_or(0, |m| m.count)
        };
        Self {
            strings: fixed("string_ids"),
            types: fixed("type_ids"),
            fields: fixed("field_ids"),
            methods: fixed("method_ids"),
            prototypes: fixed("proto_ids"),
            call_sites: map(7),
            handles: map(8),
        }
    }

    fn limit(self, kind: &ReferenceKind) -> u32 {
        match kind {
            ReferenceKind::String => self.strings,
            ReferenceKind::Type => self.types,
            ReferenceKind::Field => self.fields,
            ReferenceKind::Method => self.methods,
            ReferenceKind::Prototype => self.prototypes,
            ReferenceKind::CallSite => self.call_sites,
            ReferenceKind::MethodHandle => self.handles,
        }
    }
}

#[derive(Default)]
struct Used {
    units: u64,
    instructions: u64,
    payload_elements: u64,
    switch_targets: u64,
    catch_pairs: u64,
    debug_operations: u64,
}

fn fail(reason: &str, offset: u64, length: u64) -> MddError {
    invalid(reason, "dex.code_layout", offset, length)
        .detail("facts_layer", "code_layout")
        .detail("facts_coverage", "partial")
}

fn range(offset: u64, length: u64) -> DexRange {
    DexRange {
        byte_offset: DecimalU64(offset),
        byte_length: DecimalU64(length),
    }
}

fn charge(counter: &mut u64, amount: u64, maximum: u64, name: &str, offset: u64) -> MddResult<()> {
    let total = counter
        .checked_add(amount)
        .ok_or_else(|| fail("CODE_BUDGET_OVERFLOW", offset, 0))?;
    if total > maximum {
        let mut error = fail("CODE_BUDGET_EXCEEDED", offset, 0);
        error.code = ErrorCode::QuotaExceeded;
        return Err(error
            .detail("budget", name)
            .detail("limit", maximum.to_string())
            .detail("observed", total.to_string()));
    }
    *counter = total;
    Ok(())
}

fn section(header: &DexHeader, kind: u16) -> Option<(u64, u64, u32)> {
    let item = header.map.iter().find(|m| m.type_code == kind)?;
    let end = header
        .map
        .iter()
        .filter(|m| m.byte_offset.0 > item.byte_offset.0)
        .map(|m| m.byte_offset.0)
        .min()
        .unwrap_or(header.file_size.0);
    Some((item.byte_offset.0, end, item.count))
}

fn bounded_range<'a>(
    reader: CheckedReader<'a>,
    offset: u64,
    length: u64,
    start: u64,
    end: u64,
) -> MddResult<&'a [u8]> {
    if offset < start || offset.checked_add(length).is_none_or(|value| value > end) {
        return Err(fail("CODE_SECTION_RANGE", offset, length)
            .detail("section_start", start.to_string())
            .detail("section_end", end.to_string()));
    }
    reader.range(offset, length)
}

fn leb_u(bytes: &[u8], at: &mut u64, end: u64) -> MddResult<u32> {
    let (value, count) =
        read_uleb128(bytes, *at, end).map_err(|e| e.detail("facts_layer", "code_layout"))?;
    *at += count;
    Ok(value)
}

fn leb_s(bytes: &[u8], at: &mut u64, end: u64) -> MddResult<i32> {
    let (value, count) =
        read_sleb128(bytes, *at, end).map_err(|e| e.detail("facts_layer", "code_layout"))?;
    *at += count;
    Ok(value)
}

fn valid_target(target: i64, size: u32, starts: &BTreeSet<u32>, at: u64) -> MddResult<u32> {
    let target = u32::try_from(target).map_err(|_| fail("BRANCH_TARGET_RANGE", at, 0))?;
    if target >= size || !starts.contains(&target) {
        return Err(fail("TARGET_NOT_EXECUTABLE_BOUNDARY", at, 0)
            .detail("target_code_units", u64::from(target)));
    }
    Ok(target)
}

/// Programs decoded during one `read_code_section` call, indexed by their position
/// in the ordered physical debug-item start list. The cache is per call on purpose:
/// it depends on the held bytes and the shared table counts, so it must never be
/// reused across DEX occurrences or snapshots. Entries are filled lazily and only
/// for programs that decoded successfully, keeping a failing program on the
/// single-item path where the item-dependent error order is preserved.
struct DebugPrograms {
    starts: Vec<u64>,
    decoded: Vec<Option<debug::ProgramSlot>>,
}

impl DebugPrograms {
    fn new(starts: Vec<u64>) -> Self {
        let decoded = starts.iter().map(|_| None).collect();
        Self { starts, decoded }
    }

    /// Resolve one program, decoding it at most once per `read_code_section` call.
    /// Returns `None` when the program failed to decode: that failure is item
    /// independent only up to the register bound, so the caller must re-walk it
    /// per item to keep the interleaved error order of the original decoder.
    fn slot(
        &mut self,
        bytes: &[u8],
        header: &DexHeader,
        counts: Counts,
        offset: u64,
        index: usize,
    ) -> Option<&mut debug::ProgramSlot> {
        if self.decoded[index].is_none() {
            // A decode error is not cached: a different code item naming the same
            // offset can legitimately report a register error before the parse
            // error this attempt surfaced, and only the item-aware walk knows
            // which one comes first.
            let program = debug::parse_program(bytes, header, offset, counts).ok()?;
            self.decoded[index] = Some(debug::ProgramSlot::new(std::sync::Arc::new(program)));
        }
        self.decoded[index].as_mut()
    }
}

fn parse_item(
    bytes: &[u8],
    header: &DexHeader,
    offset: u64,
    limits: CodeLimits,
    used: &mut Used,
    debug_programs: &mut DebugPrograms,
) -> MddResult<CodeItem> {
    let reader = CheckedReader::new(bytes);
    let (start, end, _) =
        section(header, 0x2001).ok_or_else(|| fail("MISSING_CODE_SECTION", offset, 16))?;
    if !offset.is_multiple_of(4) {
        return Err(fail("CODE_ITEM_ALIGNMENT", offset, 16));
    }
    bounded_range(reader, offset, 16, start, end)?;
    let registers = reader.u16(offset)?;
    let ins = reader.u16(offset + 2)?;
    let outs = reader.u16(offset + 4)?;
    let tries_count = reader.u16(offset + 6)?;
    let debug_offset = reader.u32(offset + 8)?;
    let size = reader.u32(offset + 12)?;
    if ins > registers {
        return Err(fail("INS_EXCEEDS_REGISTERS", offset + 2, 2));
    }
    if outs > 5 && outs > registers {
        return Err(fail("OUTS_EXCEEDS_REGISTER_LAYOUT", offset + 4, 2));
    }
    charge(
        &mut used.units,
        u64::from(size),
        limits.max_total_code_units,
        "max_total_code_units",
        offset,
    )?;
    let insns_at = offset + 16;
    let insns_length = u64::from(size) * 2;
    bounded_range(reader, insns_at, insns_length, start, end)?;
    let units: Vec<u16> = reader
        .range(insns_at, insns_length)?
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    let counts = Counts::from_header(header);
    let version = header
        .version
        .parse::<u16>()
        .map_err(|_| fail("INVALID_VERSION_CONTEXT", offset, 0))?;
    let (instructions, payloads, switch_targets) = decode::decode(
        &units,
        DecodeContext {
            base: insns_at,
            registers,
            outs,
            counts,
            version,
            limits,
        },
        used,
    )?;
    let starts: BTreeSet<u32> = instructions.iter().map(|i| i.code_unit_offset).collect();
    let mut at = insns_at + insns_length;
    let mut tries = Vec::new();
    let mut handlers = Vec::new();
    if tries_count > 0 {
        if size % 2 != 0 {
            bounded_range(reader, at, 2, start, end)?;
            if reader.u16(at)? != 0 {
                return Err(fail("NONZERO_TRY_PADDING", at, 2));
            }
            at += 2;
        }
        bounded_range(reader, at, u64::from(tries_count) * 8, start, end)?;
        let mut previous_end = 0u32;
        for _ in 0..tries_count {
            let begin = reader.u32(at)?;
            let length = reader.u16(at + 4)?;
            let handler = reader.u16(at + 6)?;
            let stop = begin
                .checked_add(u32::from(length))
                .ok_or_else(|| fail("TRY_RANGE_OVERFLOW", at, 8))?;
            if length == 0 || begin < previous_end || stop > size || !starts.contains(&begin) {
                return Err(fail("INVALID_TRY_RANGE_OR_ORDER", at, 8));
            }
            tries.push(TryItem {
                byte_offset: DecimalU64(at),
                start_code_unit: begin,
                code_unit_count: length,
                handler_relative_byte_offset: handler,
            });
            previous_end = stop;
            at += 8;
        }
        let list_start = at;
        let handler_count = leb_u(bytes, &mut at, end)?;
        // One budget charge per handler prevents zero-catch handlers evading
        // the quota. Catch-all and typed pairs are charged separately below.
        charge(
            &mut used.catch_pairs,
            u64::from(handler_count),
            limits.max_catch_pairs,
            "max_catch_pairs",
            at,
        )?;
        for _ in 0..handler_count {
            let handler_start = at;
            let size_signed = leb_s(bytes, &mut at, end)?;
            let typed_count = size_signed.unsigned_abs();
            charge(
                &mut used.catch_pairs,
                u64::from(typed_count),
                limits.max_catch_pairs,
                "max_catch_pairs",
                handler_start,
            )?;
            let mut typed_catches = Vec::new();
            let mut types = BTreeSet::new();
            for _ in 0..typed_count {
                let type_idx = leb_u(bytes, &mut at, end)?;
                let target = leb_u(bytes, &mut at, end)?;
                if type_idx >= counts.types || !types.insert(type_idx) {
                    return Err(fail(
                        "INVALID_CATCH_TYPE",
                        handler_start,
                        at - handler_start,
                    ));
                }
                valid_target(i64::from(target), size, &starts, handler_start)?;
                typed_catches.push(CatchPair {
                    type_idx,
                    address_code_units: target,
                });
            }
            let catch_all = if size_signed <= 0 {
                charge(
                    &mut used.catch_pairs,
                    1,
                    limits.max_catch_pairs,
                    "max_catch_pairs",
                    at,
                )?;
                let target = leb_u(bytes, &mut at, end)?;
                Some(valid_target(i64::from(target), size, &starts, at)?)
            } else {
                None
            };
            handlers.push(CatchHandler {
                byte_offset: DecimalU64(handler_start),
                relative_byte_offset: u32::try_from(handler_start - list_start)
                    .map_err(|_| fail("HANDLER_OFFSET_OVERFLOW", handler_start, 0))?,
                typed_catches,
                catch_all_address_code_units: catch_all,
                raw_range: range(handler_start, at - handler_start),
            });
        }
        let offsets: BTreeSet<_> = handlers.iter().map(|h| h.relative_byte_offset).collect();
        if tries
            .iter()
            .any(|item| !offsets.contains(&u32::from(item.handler_relative_byte_offset)))
        {
            return Err(fail(
                "TRY_HANDLER_OFFSET_NOT_HANDLER_START",
                list_start,
                at - list_start,
            ));
        }
    }
    let debug_info = if debug_offset == 0 {
        None
    } else {
        let Some(index) = debug_programs
            .starts
            .binary_search(&u64::from(debug_offset))
            .ok()
        else {
            return Err(fail(
                "DEBUG_OFFSET_NOT_ITEM_START",
                u64::from(debug_offset),
                0,
            ));
        };
        let context = debug::DebugContext {
            registers,
            size,
            counts,
            limits,
        };
        Some(
            match debug_programs.slot(bytes, header, counts, u64::from(debug_offset), index) {
                Some(slot) => slot.materialize(context, used)?,
                // The program does not fit this item's registers, or does not
                // decode at all: re-walk it here so charging and the first error
                // stay in the original interleaved order.
                None => debug::parse(bytes, header, u64::from(debug_offset), context, used)?,
            },
        )
    };
    Ok(CodeItem { raw_range:range(offset,at-offset),insns_range:range(insns_at,insns_length),
        registers_size:registers,ins_size:ins,outs_size:outs,insns_size_code_units:size,
        debug_info_byte_offset:if debug_offset==0 {None} else {Some(DecimalU64(u64::from(debug_offset)))},
        instructions,payloads,switch_targets,tries,handlers,debug_info,
        validation_scope:"standard-code-layout-operands-targets-attached-debug-v1; excludes ART type flow, method/prototype binding and inferred dispatch".to_owned(),
        full_art_verification_complete:false })
}

/// Enumerate every declared map code_item, including items unreferenced by methods.
/// Debug coverage concerns attached debug_info, not every orphan debug section item.
pub fn read_code_section(
    bytes: &[u8],
    header: &DexHeader,
    limits: CodeLimits,
) -> MddResult<CodeSection> {
    let Some((start, end, count)) = section(header, 0x2001) else {
        return Ok(CodeSection {
            declared_code_item_count: 0,
            declared_code_item_byte_offsets: Vec::new(),
            items: Vec::new(),
            scope: "complete-declared-code-map-v1".to_owned(),
            completed_layers: vec!["code_layout".to_owned()],
            full_dex_validation_complete: false,
        });
    };
    if count > limits.max_code_items {
        return Err(quota_items(start, u64::from(count), limits.max_code_items));
    }
    let mut used = Used::default();
    let debug_starts = debug::item_starts(bytes, header, limits, &mut used)?;
    // Every debug item consumes at least one byte and starts are appended in walk
    // order, so the list is sorted and unique; direct indexing is therefore valid.
    debug_assert!(debug_starts.windows(2).all(|pair| pair[0] < pair[1]));
    let mut debug_programs = DebugPrograms::new(debug_starts);
    let mut items = Vec::new();
    let mut at = start;
    for _ in 0..count {
        at = at
            .checked_add(3)
            .map(|n| n & !3)
            .ok_or_else(|| fail("CODE_ALIGNMENT_OVERFLOW", at, 0))?;
        let item = parse_item(bytes, header, at, limits, &mut used, &mut debug_programs).map_err(
            |error| {
                let mut error = error.detail("code_item_byte_offset", at.to_string());
                if let Ok(debug_offset) = CheckedReader::new(bytes).u32(at + 8) {
                    error = error.detail("debug_info_byte_offset", debug_offset.to_string());
                }
                error
            },
        )?;
        let next = item.raw_range.byte_offset.0 + item.raw_range.byte_length.0;
        if next <= at || next > end {
            return Err(fail("CODE_SECTION_PROGRESS", at, next.saturating_sub(at)));
        }
        at = next;
        items.push(item);
    }
    Ok(CodeSection {
        declared_code_item_count: count,
        declared_code_item_byte_offsets: items
            .iter()
            .map(|item| item.raw_range.byte_offset)
            .collect(),
        items,
        scope: "complete-declared-code-map-v1".to_owned(),
        completed_layers: vec!["code_layout".to_owned()],
        full_dex_validation_complete: false,
    })
}

fn quota_items(at: u64, count: u64, limit: u32) -> MddError {
    let mut error = fail("CODE_ITEM_COUNT_BUDGET", at, 0);
    error.code = ErrorCode::QuotaExceeded;
    error
        .detail("budget", "max_code_items")
        .detail("limit", limit.to_string())
        .detail("observed", count.to_string())
}

/// Validate map membership by complete enumeration, then project explicit offsets.
/// Input order and duplicates are retained; this result declares the narrower scope.
pub fn read_code_offsets(
    bytes: &[u8],
    header: &DexHeader,
    offsets: &[u32],
    limits: CodeLimits,
) -> MddResult<CodeSection> {
    if offsets.len() as u64 > u64::from(limits.max_code_items) {
        return Err(quota_items(0, offsets.len() as u64, limits.max_code_items));
    }
    let mut section = read_code_section(bytes, header, limits)?;
    let by_offset: BTreeMap<_, _> = section
        .items
        .into_iter()
        .map(|item| (item.raw_range.byte_offset.0, item))
        .collect();
    let mut items = Vec::new();
    let mut projected = Used::default();
    for offset in offsets {
        let item = by_offset
            .get(&u64::from(*offset))
            .ok_or_else(|| fail("OFFSET_NOT_DECLARED_CODE_ITEM", u64::from(*offset), 0))?;
        charge_projection(item, &mut projected, limits)?;
        items.push(item.clone());
    }
    section.items = items;
    section.scope = "explicit-code-offsets-v1; full map validated before projection".to_owned();
    Ok(section)
}

fn charge_projection(item: &CodeItem, used: &mut Used, limits: CodeLimits) -> MddResult<()> {
    let at = item.raw_range.byte_offset.0;
    charge(
        &mut used.units,
        u64::from(item.insns_size_code_units),
        limits.max_total_code_units,
        "max_total_code_units",
        at,
    )?;
    charge(
        &mut used.instructions,
        item.instructions.len() as u64,
        limits.max_instructions,
        "max_instructions",
        at,
    )?;
    for payload in &item.payloads {
        let count = match &payload.data {
            PayloadData::PackedSwitch {
                relative_targets, ..
            }
            | PayloadData::SparseSwitch {
                relative_targets, ..
            } => relative_targets.len() as u64,
            PayloadData::FillArray { element_count, .. } => u64::from(*element_count),
        };
        charge(
            &mut used.payload_elements,
            count,
            limits.max_payload_elements,
            "max_payload_elements",
            at,
        )?;
    }
    for targets in &item.switch_targets {
        charge(
            &mut used.switch_targets,
            targets.target_code_units.len() as u64,
            limits.max_switch_targets,
            "max_switch_targets",
            at,
        )?;
    }
    for handler in &item.handlers {
        charge(
            &mut used.catch_pairs,
            1 + handler.typed_catches.len() as u64
                + u64::from(handler.catch_all_address_code_units.is_some()),
            limits.max_catch_pairs,
            "max_catch_pairs",
            at,
        )?;
    }
    if let Some(debug) = &item.debug_info {
        charge(
            &mut used.debug_operations,
            debug.parameter_name_indices.len() as u64 + debug.events.len() as u64,
            limits.max_debug_operations,
            "max_debug_operations",
            at,
        )?;
    }
    Ok(())
}
