use super::*;
use std::sync::Arc;

pub(super) struct DebugContext {
    pub registers: u16,
    pub size: u32,
    pub counts: Counts,
    pub limits: CodeLimits,
}

/// Item-scoped work that a program-level walk cannot perform: per-event quota
/// charging and the register bound both depend on the referring code item rather
/// than on the debug bytes alone. The single-item path runs it while decoding;
/// every reused program replays it with the same first-error order, so the
/// reported error and its offsets stay identical to the unmemoized decoder.
struct ItemWork<'a> {
    registers: u16,
    limits: CodeLimits,
    used: &'a mut Used,
}

impl ItemWork<'_> {
    fn charge_parameters(&mut self, parameters: u32, at: u64) -> MddResult<()> {
        charge(
            &mut self.used.debug_operations,
            u64::from(parameters),
            self.limits.max_debug_operations,
            "max_debug_operations",
            at,
        )
    }

    fn charge_event(&mut self, at: u64) -> MddResult<()> {
        charge(
            &mut self.used.debug_operations,
            1,
            self.limits.max_debug_operations,
            "max_debug_operations",
            at,
        )
    }

    /// The check the encoded parser performs right after the register LEB. The
    /// value is only cast after the bound is established, exactly like the
    /// original decoder, so a value above `u16::MAX` is still reported as an
    /// out-of-range register instead of silently truncating.
    fn register(&self, value: u32, at: u64, length: u64) -> MddResult<u32> {
        if value >= u32::from(self.registers) {
            return Err(fail("DEBUG_REGISTER_OUT_OF_RANGE", at, length));
        }
        Ok(value)
    }

    /// Replay this item's quota and register checks for one shared program.
    ///
    /// The incremental decoder charges the parameter block, then for each event
    /// charges one operation and bound-checks that event's register. Both halves
    /// are monotone, so the first failure of each is found arithmetically or by a
    /// binary search instead of by walking every event again: the charge counter
    /// fails at the event `max - charged` positions in, and the running register
    /// maximum fails at the first bound it exceeds. The earlier event index wins,
    /// and a tie goes to the charge because it is evaluated before the register
    /// check at that event.
    fn replay(&mut self, program: &DebugProgram) -> MddResult<()> {
        let maximum = self.limits.max_debug_operations;
        let parameters = u64::from(program.parameter_count);
        let total = self
            .used
            .debug_operations
            .checked_add(parameters)
            .ok_or_else(|| fail("CODE_BUDGET_OVERFLOW", program.parameters_charge_at, 0))?;
        if total > maximum {
            return Err(quota_exceeded(
                "max_debug_operations",
                maximum,
                total,
                program.parameters_charge_at,
            ));
        }
        let count = program.events.len() as u64;
        let room = maximum - total;
        let quota_at = (count > room).then_some(room as usize);
        let bound = program
            .register_bounds
            .partition_point(|entry| entry.running_max < u32::from(self.registers));
        let register_at = (bound < program.register_bounds.len())
            .then(|| program.register_bounds[bound].event_index);
        let first_register_violation = |register: usize| {
            let event = &program.events[register];
            let operand = event
                .register
                .as_ref()
                .expect("a register bound is recorded for this event");
            fail(
                "DEBUG_REGISTER_OUT_OF_RANGE",
                event.byte_offset,
                u64::from(operand.length),
            )
        };
        match (quota_at, register_at) {
            (Some(quota), Some(register)) if register < quota => {
                Err(first_register_violation(register))
            }
            (Some(quota), _) => {
                let event = &program.events[quota];
                // `charge` adds before comparing, so a counter already at the
                // limit reports the overflow instead of the exceeded budget.
                if maximum == u64::MAX {
                    return Err(fail("CODE_BUDGET_OVERFLOW", event.byte_offset, 0));
                }
                Err(quota_exceeded(
                    "max_debug_operations",
                    maximum,
                    maximum + 1,
                    event.byte_offset,
                ))
            }
            (None, Some(register)) => Err(first_register_violation(register)),
            (None, None) => {
                self.used.debug_operations = total + count;
                Ok(())
            }
        }
    }
}

/// One physical debug_info program. Every field is a function of the debug bytes
/// and the shared table counts, so a single `read_code_section` call decodes it
/// once and shares it with all code items naming the same offset.
///
/// The code-item-dependent projections (`code_item_address_scope`, usable counts,
/// `outside_code`) are deliberately absent. They are derived per code item from
/// its `size`, so one program keeps a single event sequence instead of one copy
/// per referring code item. `position_addresses`, `positive_prefix`,
/// `register_bounds` and `code_end_checks` are the monotone indexes that make
/// those per-item derivations logarithmic rather than another full event scan.
#[derive(Debug)]
pub(super) struct DebugProgram {
    initial_line: u32,
    parameter_count: u32,
    parameters_charge_at: u64,
    parameter_name_indices: Arc<[Option<u32>]>,
    events: Vec<ProgramEvent>,
    pc_to_pc: bool,
    invalid_source_line: Option<u64>,
    raw_range: DexRange,
    /// Emitted position addresses in event order. `pc` only advances, so the
    /// sequence is non-decreasing and the positions inside a code size are a
    /// prefix.
    position_addresses: Vec<u32>,
    /// `positive_prefix[i]` counts the first `i` emitted positions whose encoded
    /// line is positive; its length is `position_addresses.len() + 1`.
    positive_prefix: Vec<u32>,
    /// Register operands in event order with the running maximum. The running
    /// maximum is non-decreasing, so the first operand a code item's `registers`
    /// bound rejects is a binary search instead of an event scan.
    register_bounds: Vec<RegisterBound>,
    /// Events whose running pc is compared against the code item's size, in
    /// event order. Their addresses only advance, so the first event past a given
    /// size is a binary search as well.
    code_end_checks: Vec<CodeEndCheck>,
}

/// A register operand whose bound is only known per code item. `length` retains
/// the exact error span the interleaved decoder reported (`opcode byte + register
/// LEB`) so a rejected item still fails with identical offsets.
#[derive(Debug)]
struct DecodedRegister {
    value: u32,
    length: u8,
}

/// One decoded event without any code-item projection. `checks_code_end` records
/// the opcode branches whose running pc is compared against the item's code size.
#[derive(Debug)]
struct ProgramEvent {
    byte_offset: u64,
    opcode: u8,
    address_code_units: u32,
    line: i64,
    register: Option<DecodedRegister>,
    name_idx: Option<u32>,
    type_idx: Option<u32>,
    signature_idx: Option<u32>,
    file_idx: Option<u32>,
    emits_position: bool,
    checks_code_end: bool,
}

/// One register operand plus the largest operand value seen up to it.
#[derive(Debug)]
struct RegisterBound {
    running_max: u32,
    event_index: usize,
}

/// One `checks_code_end` event with its running pc, in event order.
#[derive(Debug)]
struct CodeEndCheck {
    address_code_units: u32,
    byte_offset: u64,
}

impl DebugProgram {
    /// Emitted position count; independent of the referring code item's size.
    fn raw_position_count(&self) -> u64 {
        self.position_addresses.len() as u64
    }

    /// Emitted positions whose address is inside the item's code units.
    fn applicable_position_count(&self, size: u32) -> u64 {
        self.position_addresses
            .partition_point(|address| *address < size) as u64
    }

    /// Usable source positions among the first `applicable` emitted positions.
    /// The pc-to-pc pattern never yields a usable line, matching the per-event
    /// classification exactly.
    fn usable_source_position_count(&self, applicable: u64) -> u64 {
        if self.pc_to_pc {
            return 0;
        }
        u64::from(self.positive_prefix[applicable as usize])
    }

    /// First `checks_code_end` event whose running pc is past `size`.
    fn outside_code(&self, size: u32) -> Option<u64> {
        let at = self
            .code_end_checks
            .partition_point(|check| check.address_code_units <= size);
        self.code_end_checks.get(at).map(|check| check.byte_offset)
    }

    /// Number of decoded events in this program.
    pub(super) fn len(&self) -> usize {
        self.events.len()
    }

    /// One event projected onto a code item of `size` code units.
    ///
    /// This is the single definition of the item-dependent fields, used both by
    /// the borrowed iterator and by serialization, so the emitted JSON cannot
    /// drift from the shared program.
    pub(super) fn event_at(&self, size: u32, index: usize) -> DebugEvent {
        let event = &self.events[index];
        let scope = if event.address_code_units < size {
            DebugAddressScope::InsideCodeUnits
        } else if event.address_code_units == size {
            DebugAddressScope::AtCodeEnd
        } else {
            DebugAddressScope::BeyondCodeEnd
        };
        let kind = if !event.emits_position {
            SourceLineKind::NotAPosition
        } else if self.pc_to_pc {
            SourceLineKind::PcSurrogate
        } else if event.line <= 0 {
            SourceLineKind::UnknownNonPositive
        } else if scope != DebugAddressScope::InsideCodeUnits {
            SourceLineKind::OutsideCodeContext
        } else {
            SourceLineKind::PositiveEncodedLine
        };
        let usable = kind == SourceLineKind::PositiveEncodedLine;
        DebugEvent {
            byte_offset: DecimalU64(event.byte_offset),
            opcode: event.opcode,
            address_code_units: event.address_code_units,
            encoded_line_decimal: SignedDecimal(event.line),
            // `PositiveEncodedLine` implies `0 < line <= u32::MAX`, which the walk
            // already bounded, so this widening conversion is exact.
            source_line: usable.then_some(DecimalU64(event.line as u64)),
            source_line_usable: usable,
            source_line_kind: kind,
            // Every view is only built after all operands passed this item's
            // bound, so the narrowing cast is exact.
            register: event.register.as_ref().map(|operand| operand.value as u16),
            name_idx: event.name_idx,
            type_idx: event.type_idx,
            signature_idx: event.signature_idx,
            file_idx: event.file_idx,
            emits_position: event.emits_position,
            code_item_address_scope: scope,
        }
    }
}

/// Materialize an owned event vector. Only the failed-program path needs this:
/// a memoized program keeps its events in the shared `DebugProgram` and projects
/// them on demand, so a successful attach allocates no event storage at all.
fn owned_events(program: &DebugProgram, size: u32) -> DebugEvents {
    #[cfg(test)]
    events_materialize_count::bump();
    DebugEvents::Owned(
        (0..program.events.len())
            .map(|index| program.event_at(size, index))
            .collect(),
    )
}

/// Test-only observation of how many owned event vectors were built.
///
/// Sharing is invisible in the output, so this counter is the only guard against
/// a future refactor quietly materializing one event sequence per code item
/// again. A shared attach must leave it untouched.
#[cfg(test)]
// Sits next to `owned_events`, which is the only caller, rather than at the end
// of the file.
#[allow(clippy::items_after_test_module)]
pub(super) mod events_materialize_count {
    thread_local! {
        static COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }
    pub fn bump() {
        COUNT.with(|count| count.set(count.get() + 1));
    }
    pub fn get() -> u64 {
        COUNT.with(|count| count.get())
    }
    pub fn reset() {
        COUNT.with(|count| count.set(0));
    }
}

/// Walk each declared variable-length debug item once. Mere containment in the
/// debug section does not prove that a reference names an actual item start.
/// Offsets are visited in increasing order and every item consumes at least its
/// terminator byte, so the returned starts are sorted and unique; callers use the
/// position for direct cache indexing instead of a hash lookup.
pub(super) fn item_starts(
    bytes: &[u8],
    header: &DexHeader,
    limits: CodeLimits,
    used: &mut Used,
) -> MddResult<Vec<u64>> {
    let Some((start, end, count)) = section(header, 0x2003) else {
        return Ok(Vec::new());
    };
    let reader = CheckedReader::new(bytes);
    let counts = Counts::from_header(header);
    let mut at = start;
    let mut starts = Vec::new();
    for _ in 0..count {
        bounded_range(reader, at, 1, start, end)?;
        starts.push(at);
        leb_u(bytes, &mut at, end)?;
        let parameters = leb_u(bytes, &mut at, end)?;
        if parameters > 65536 {
            return Err(fail("DEBUG_PARAMETER_COUNT_EXCEEDS_FORMAT", at, 0));
        }
        charge(
            &mut used.debug_operations,
            u64::from(parameters),
            limits.max_debug_operations,
            "max_debug_operations",
            at,
        )?;
        for _ in 0..parameters {
            optional_index(bytes, &mut at, end, counts.strings, "parameter_name")?;
        }
        loop {
            charge(
                &mut used.debug_operations,
                1,
                limits.max_debug_operations,
                "max_debug_operations",
                at,
            )?;
            bounded_range(reader, at, 1, start, end)?;
            let opcode = reader.range(at, 1)?[0];
            at += 1;
            match opcode {
                0 => break,
                1 | 5 | 6 => {
                    leb_u(bytes, &mut at, end)?;
                }
                2 => {
                    leb_s(bytes, &mut at, end)?;
                }
                3 | 4 => {
                    leb_u(bytes, &mut at, end)?;
                    optional_index(bytes, &mut at, end, counts.strings, "local_name")?;
                    optional_index(bytes, &mut at, end, counts.types, "local_type")?;
                    if opcode == 4 {
                        optional_index(bytes, &mut at, end, counts.strings, "local_signature")?;
                    }
                }
                9 => {
                    optional_index(bytes, &mut at, end, counts.strings, "source_file")?;
                }
                _ => (),
            }
        }
    }
    Ok(starts)
}

fn optional_index(
    bytes: &[u8],
    at: &mut u64,
    end: u64,
    count: u32,
    kind: &str,
) -> MddResult<Option<u32>> {
    let value = leb_u(bytes, at, end)?;
    if value == 0 {
        return Ok(None);
    }
    let index = value - 1;
    if index >= count {
        return Err(fail("DEBUG_INDEX_OUT_OF_RANGE", *at, 0)
            .detail("kind", kind)
            .detail("index", u64::from(index)));
    }
    Ok(Some(index))
}

/// Decode one physical program with no item-scoped charge or bound check. Only a
/// successful decode is memoized: a failing program is re-walked per code item
/// by `parse`, because which error surfaces first depends on that item's
/// `registers` (the register bound is interleaved with later parse errors).
pub(super) fn parse_program(
    bytes: &[u8],
    header: &DexHeader,
    offset: u64,
    counts: Counts,
) -> MddResult<DebugProgram> {
    #[cfg(test)]
    program_decode_count::bump();
    walk(bytes, header, offset, counts, None)
}

/// Test-only observation of how many times a physical debug program was decoded.
///
/// Correctness is unchanged by memoization, so no output assertion can tell
/// whether the cache is alive; this counter is the only guard against a future
/// refactor silently decoding one program per code item again.
#[cfg(test)]
// Sits next to `parse_program`, which is the only caller, rather than at the
// end of the file.
#[allow(clippy::items_after_test_module)]
pub(super) mod program_decode_count {
    thread_local! {
        static COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }
    pub fn bump() {
        COUNT.with(|count| count.set(count.get() + 1));
    }
    pub fn get() -> u64 {
        COUNT.with(|count| count.get())
    }
    pub fn reset() {
        COUNT.with(|count| count.set(0));
    }
}

/// Single-item path, used when the program itself failed to decode. It performs
/// the charging and the register bound inside the walk so the interleaved order
/// of the unmemoized decoder is preserved.
pub(super) fn parse(
    bytes: &[u8],
    header: &DexHeader,
    offset: u64,
    context: DebugContext,
    used: &mut Used,
) -> MddResult<Arc<DebugInfo>> {
    let DebugContext {
        registers,
        size,
        counts,
        limits,
    } = context;
    let mut work = ItemWork {
        registers,
        limits,
        used,
    };
    let program = walk(bytes, header, offset, counts, Some(&mut work))?;
    let events = owned_events(&program, size);
    let mut view = build_view(&Arc::new(program), size, limits)?;
    // The walk already charged and bound-checked every event, so this path only
    // needs to swap in the owned sequence it just built.
    Arc::get_mut(&mut view)
        .expect("a freshly built view is uniquely owned")
        .events = events;
    Ok(view)
}

/// One successfully decoded program plus the item-dependent views derived from it.
///
/// A view is a function of the program and the referring code item's `size`, and
/// `size` is the only item input to every projected field. Two code items with
/// equal `size` therefore share one `Arc<DebugInfo>` instead of each allocating
/// its own copy of the whole event sequence. A program is typically named by tens
/// of code items but only a handful of distinct sizes, so the view list stays
/// short and a linear scan beats hashing.
pub(super) struct ProgramSlot {
    program: Arc<DebugProgram>,
    views: Vec<(u32, Arc<DebugInfo>)>,
}

impl ProgramSlot {
    pub(super) fn new(program: Arc<DebugProgram>) -> Self {
        Self {
            program,
            views: Vec::new(),
        }
    }

    /// Replay this item's quota/register checks, then return its size-specific
    /// view, building it at most once per distinct `size`.
    ///
    /// The replay runs on every attach, including a view cache hit: the charges
    /// belong to each referring code item, so skipping them would silently move
    /// or drop a `max_debug_operations` failure.
    pub(super) fn materialize(
        &mut self,
        context: DebugContext,
        used: &mut Used,
    ) -> MddResult<Arc<DebugInfo>> {
        let DebugContext {
            registers,
            size,
            limits,
            ..
        } = context;
        ItemWork {
            registers,
            limits,
            used,
        }
        .replay(&self.program)?;
        if let Some((_, view)) = self.views.iter().find(|(cached, _)| *cached == size) {
            return Ok(Arc::clone(view));
        }
        // A view rejected by the strict policy is never cached, and the failure
        // propagates out of `read_code_section`, so no later item can hit it.
        let view = build_view(&self.program, size, limits)?;
        self.views.push((size, Arc::clone(&view)));
        Ok(view)
    }
}

fn walk(
    bytes: &[u8],
    header: &DexHeader,
    offset: u64,
    counts: Counts,
    mut item: Option<&mut ItemWork<'_>>,
) -> MddResult<DebugProgram> {
    let (start, end, _) =
        section(header, 0x2003).ok_or_else(|| fail("MISSING_DEBUG_INFO_SECTION", offset, 0))?;
    let reader = CheckedReader::new(bytes);
    bounded_range(reader, offset, 1, start, end)?;
    let mut at = offset;
    let initial_line = leb_u(bytes, &mut at, end)?;
    let mut line = i64::from(initial_line);
    let mut invalid_source_line = if line < 1 { Some(offset) } else { None };
    let parameters = leb_u(bytes, &mut at, end)?;
    if parameters > 65536 {
        return Err(fail("DEBUG_PARAMETER_COUNT_EXCEEDS_FORMAT", at, 0));
    }
    let parameters_charge_at = at;
    if let Some(work) = item.as_deref_mut() {
        work.charge_parameters(parameters, at)?;
    }
    let mut names = Vec::new();
    for _ in 0..parameters {
        names.push(optional_index(
            bytes,
            &mut at,
            end,
            counts.strings,
            "parameter_name",
        )?);
    }
    let mut events = Vec::new();
    let mut pc = 0u32;
    loop {
        if let Some(work) = item.as_deref_mut() {
            work.charge_event(at)?;
        }
        bounded_range(reader, at, 1, start, end)?;
        let event_at = at;
        let opcode = reader.range(at, 1)?[0];
        at += 1;
        let mut register = None;
        let mut name = None;
        let mut type_idx = None;
        let mut signature = None;
        let mut file = None;
        let mut position = false;
        let mut checks_code_end = false;
        match opcode {
            0 => (),
            1 => {
                let amount = leb_u(bytes, &mut at, end)?;
                pc = pc
                    .checked_add(amount)
                    .ok_or_else(|| fail("DEBUG_PC_OVERFLOW", event_at, at - event_at))?;
                checks_code_end = true;
            }
            2 => {
                let delta = leb_s(bytes, &mut at, end)?;
                line = line
                    .checked_add(i64::from(delta))
                    .ok_or_else(|| fail("DEBUG_LINE_OVERFLOW", event_at, at - event_at))?;
            }
            3 | 4 => {
                let reg = leb_u(bytes, &mut at, end)?;
                let length = u8::try_from(at - event_at).unwrap_or(u8::MAX);
                register = Some(match item.as_deref_mut() {
                    Some(work) => DecodedRegister {
                        value: work.register(reg, event_at, u64::from(length))?,
                        length,
                    },
                    None => DecodedRegister { value: reg, length },
                });
                name = optional_index(bytes, &mut at, end, counts.strings, "local_name")?;
                type_idx = optional_index(bytes, &mut at, end, counts.types, "local_type")?;
                if opcode == 4 {
                    signature =
                        optional_index(bytes, &mut at, end, counts.strings, "local_signature")?;
                }
            }
            5 | 6 => {
                let reg = leb_u(bytes, &mut at, end)?;
                let length = u8::try_from(at - event_at).unwrap_or(u8::MAX);
                register = Some(match item.as_deref_mut() {
                    Some(work) => DecodedRegister {
                        value: work.register(reg, event_at, u64::from(length))?,
                        length,
                    },
                    None => DecodedRegister { value: reg, length },
                });
            }
            7 | 8 => (),
            9 => {
                file = optional_index(bytes, &mut at, end, counts.strings, "source_file")?;
            }
            _ => {
                let adjusted = u32::from(opcode) - 10;
                pc = pc
                    .checked_add(adjusted / 15)
                    .ok_or_else(|| fail("DEBUG_PC_OVERFLOW", event_at, 1))?;
                line = line
                    .checked_add(-4 + i64::from(adjusted % 15))
                    .ok_or_else(|| fail("DEBUG_LINE_OVERFLOW", event_at, 1))?;
                checks_code_end = true;
                position = true;
            }
        }
        if line < 1 {
            invalid_source_line.get_or_insert(event_at);
        }
        if line > i64::from(u32::MAX) || line < i64::from(i32::MIN) {
            return Err(fail("DEBUG_LINE_OVERFLOW", event_at, at - event_at));
        }
        events.push(ProgramEvent {
            byte_offset: event_at,
            opcode,
            address_code_units: pc,
            line,
            register,
            name_idx: name,
            type_idx,
            signature_idx: signature,
            file_idx: file,
            emits_position: position,
            checks_code_end,
        });
        if opcode == 0 {
            break;
        }
    }
    // R8 writes one zero-change position followed by (PC+1,line+1) positions,
    // with unnamed parameters. The whole physical item can be shared by shorter
    // methods. Recognition describes this encoding, not the APK's producer.
    let pc_to_pc = initial_line <= 1
        && names.iter().all(Option::is_none)
        && events.len() >= 2
        && events[0].opcode == 0x0e
        && events.last().is_some_and(|event| event.opcode == 0)
        && events[1..events.len() - 1]
            .iter()
            .all(|event| event.opcode == 0x1e);
    let mut position_addresses = Vec::new();
    let mut positive_prefix = vec![0u32];
    let mut register_bounds = Vec::new();
    let mut code_end_checks = Vec::new();
    let mut positive = 0u32;
    let mut running_max = 0u32;
    for (event_index, event) in events.iter().enumerate() {
        if event.emits_position {
            position_addresses.push(event.address_code_units);
            if event.line > 0 {
                positive += 1;
            }
            positive_prefix.push(positive);
        }
        if let Some(register) = &event.register {
            running_max = running_max.max(register.value);
            register_bounds.push(RegisterBound {
                running_max,
                event_index,
            });
        }
        if event.checks_code_end {
            code_end_checks.push(CodeEndCheck {
                address_code_units: event.address_code_units,
                byte_offset: event.byte_offset,
            });
        }
    }
    Ok(DebugProgram {
        initial_line,
        parameter_count: parameters,
        parameters_charge_at,
        parameter_name_indices: names.into(),
        events,
        pc_to_pc,
        invalid_source_line,
        raw_range: range(offset, at - offset),
        position_addresses,
        positive_prefix,
        register_bounds,
        code_end_checks,
    })
}

/// Build one code item's view of a shared program. `size` is the only item input
/// to every projected field, and the physical events stay behind the shared
/// `Arc`, so this allocates only the item-dependent aggregates.
///
/// The strict-policy order is fixed: pc-to-pc surrogate, then a non-positive
/// encoded line, then a position past the item's code end.
fn build_view(
    program: &Arc<DebugProgram>,
    size: u32,
    limits: CodeLimits,
) -> MddResult<Arc<DebugInfo>> {
    if limits.debug_policy == DebugPolicy::StrictSourceLinesV1 {
        let semantic_error = |reason: &str, at: u64| {
            let mut error = fail(reason, at, 0);
            error.code = ErrorCode::IncompleteFacts;
            error.stage = "debug.source_line_policy".to_owned();
            error
                .detail("required_layer", "source_positions")
                .detail("facts_layer", "source_positions")
                .detail("input_coverage", "unknown")
                .detail("debug_policy", "mdd-debug-source-lines-strict-v1")
                .detail("encoded_debug_complete", true)
                .detail("current_code_item_layout_complete", true)
        };
        if program.pc_to_pc {
            return Err(semantic_error(
                "DEBUG_PC_SURROGATE_REQUIRES_SOURCE_MAPPING",
                program.raw_range.byte_offset.0,
            ));
        }
        if let Some(at) = program.invalid_source_line {
            return Err(semantic_error("DEBUG_LINE_LESS_THAN_ONE", at));
        }
        if let Some(at) = program.outside_code(size) {
            return Err(semantic_error("DEBUG_PC_OUTSIDE_CODE", at));
        }
    }
    let raw_positions = program.raw_position_count();
    let applicable = program.applicable_position_count(size);
    let usable = program.usable_source_position_count(applicable);
    Ok(Arc::new(DebugInfo {
        raw_range: program.raw_range.clone(),
        initial_line: program.initial_line,
        parameter_name_indices: Arc::clone(&program.parameter_name_indices),
        events: DebugEvents::Shared(SharedDebugEvents {
            program: Arc::clone(program),
            size,
        }),
        representation: if program.pc_to_pc {
            DebugRepresentation::PcToPcPattern
        } else {
            DebugRepresentation::EventProgram
        },
        referring_code_unit_length: size,
        raw_position_count: DecimalU64(raw_positions),
        applicable_method_position_count: DecimalU64(applicable),
        usable_method_source_position_count: DecimalU64(usable),
        unusable_method_source_position_count: DecimalU64(applicable - usable),
        debug_policy: limits.debug_policy,
        strict_positive_line_policy_satisfied: limits.debug_policy
            == DebugPolicy::StrictSourceLinesV1,
        validation_scope:"complete bounded physical debug program; pc-to-pc encoding retains shared suffix with explicit code-range tags; borrowed method view is address < code size; parameter/prototype and local lifetimes require method binding".to_owned(),
    }))
}

/// The quota error `charge` produces when a budget is exceeded.
fn quota_exceeded(name: &str, limit: u64, observed: u64, at: u64) -> MddError {
    let mut error = fail("CODE_BUDGET_EXCEEDED", at, 0);
    error.code = ErrorCode::QuotaExceeded;
    error
        .detail("budget", name)
        .detail("limit", limit.to_string())
        .detail("observed", observed.to_string())
}
