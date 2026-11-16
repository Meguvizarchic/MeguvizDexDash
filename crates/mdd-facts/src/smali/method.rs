//! A method with everything its facts say: the instruction text of `smali_required` plus
//! parameter names, annotations and debug directives, written where `mdd.smali.v1` puts them.
//!
//! ```text
//! .method public static f(IJ)V
//!     .registers 6
//!     .param p0, "count"                 <- a parameter that has a debug name or annotations
//!     .param p1
//!         .annotation runtime Lpkg/A;
//!         .end annotation
//!     .end param
//!     .annotation runtime Lpkg/B;        <- the method's own annotations
//!     .end annotation
//!
//!     :try_start_0                       <- labels first, then the debug lines of the address
//!     .prologue
//!     .line 12
//!     .local v0, "x":I
//!     invoke-static {}, Lpkg/C;->d()V
//!     .end local v0
//! .end method
//! ```
//!
//! `pK` names the register the parameter starts in: 0 for the first parameter of a static
//! method, 1 for that of an instance method (`p0` is `this`), and a `long` or `double` takes
//! two. A debug line is written for each event of the debug program that is one, in the order of
//! the program, at the address the program reaches:
//!
//! | event | line |
//! | --- | --- |
//! | prologue end, epilogue begin | `.prologue`, `.epilogue` |
//! | position | `.line N`, only when N is a source line (see below) |
//! | start local | `.local rX, "name":Ltype;`, with `, "signature"` when it has one; a missing name or type is `null` |
//! | end local, restart local | `.end local rX`, `.restart local rX` |
//! | set file | `.source "name"`, or `.source null` |
//!
//! A position is a source line only when the program gives it a positive line inside the code and
//! is not the pc-to-pc pattern that stores a code address in the line slot (R8): those are facts
//! of the debug layer, and writing them as `.line` would present an address as a source line.
//! An event that is at no instruction start, or lies past the code, is not written; the report
//! counts what was left out.
use super::{annotation::AnnotationIndex, annotation::ParameterSlots, value::ValueContext};
use crate::{
    annotations::AnnotationFacts,
    smali_required::{MethodExtras, MethodView, RenderedMethod, SmaliLimits, render_method_with},
};
use mdd_dex::{
    annotations::DexAnnotations,
    instructions::{DebugAddressScope, DebugEvent},
};
use mdd_types::MddResult;
use std::collections::{BTreeMap, BTreeSet};

/// Which families of lines a text carries beside the instructions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmaliOptions {
    /// `.annotation` blocks of the method and of its parameters.
    pub annotations: bool,
    /// `.param` lines for parameter names.
    pub parameters: bool,
    /// Debug directives.
    pub debug: bool,
}

impl Default for SmaliOptions {
    /// `mdd.smali.v1` is the text with all three.
    fn default() -> Self {
        Self {
            annotations: true,
            parameters: true,
            debug: true,
        }
    }
}

impl SmaliOptions {
    /// The instruction text alone, as the first renderer wrote it.
    pub const INSTRUCTIONS_ONLY: Self = Self {
        annotations: false,
        parameters: false,
        debug: false,
    };
}

/// What a method's lines were built from.
pub struct FullMethodView<'a> {
    pub method: MethodView<'a>,
    /// The annotation layer of the same DEX and its index; `None` when that layer could not be
    /// built, in which case a method shows no annotations and the report says so.
    pub annotations: Option<(&'a AnnotationFacts, &'a AnnotationIndex)>,
}

/// What was left out of a method's text, and why.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExtrasReport {
    /// Debug events with a directive that were not written: at no instruction start or past the
    /// end of the code.
    pub debug_events_unplaced: u32,
    /// Position events that were not written because their line is not a source line.
    pub positions_not_source_lines: u32,
    /// Parameter annotation slots that cannot be tied to prototype positions.
    pub parameter_annotation_slots_unplaced: u32,
    /// The annotation layer was needed and is not built.
    pub annotation_layer_missing: bool,
}

/// A rendered method and what its text leaves out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FullMethod {
    pub rendered: RenderedMethod,
    pub report: ExtrasReport,
}

fn width_of(descriptor: &str) -> u32 {
    if descriptor == "J" || descriptor == "D" {
        2
    } else {
        1
    }
}

/// One text, rendered in full.
pub fn render_method_full(
    view: &FullMethodView<'_>,
    limits: SmaliLimits,
    options: SmaliOptions,
) -> MddResult<FullMethod> {
    let (extras, report) = build_extras(view, options)?;
    let rendered = render_method_with(&view.method, limits, &extras)?;
    Ok(FullMethod { rendered, report })
}

fn build_extras(
    view: &FullMethodView<'_>,
    options: SmaliOptions,
) -> MddResult<(MethodExtras, ExtrasReport)> {
    let method = &view.method;
    let definition = method.definition;
    let reference = &method.definitions.method_references[definition.method_idx as usize];
    let mut extras = MethodExtras::default();
    let mut report = ExtrasReport::default();

    let is_static = definition.access_flags & 0x8 != 0;
    let mut starts = Vec::with_capacity(reference.parameter_descriptors.len());
    let mut next = u32::from(!is_static);
    for descriptor in &reference.parameter_descriptors {
        starts.push(next);
        next += width_of(descriptor);
    }

    let names: Vec<Option<String>> = if options.parameters {
        let debug_names = method
            .code
            .and_then(|code| code.debug_info.as_ref())
            .map(|debug| debug.parameter_name_indices.clone());
        (0..reference.parameter_descriptors.len())
            .map(|position| {
                debug_names
                    .as_ref()
                    .and_then(|indices| indices.get(position).copied().flatten())
                    .map(|index| {
                        let context = ValueContext {
                            metadata: method.metadata,
                            definitions: method.definitions,
                            values: &[],
                        };
                        context.string_literal(index)
                    })
                    .transpose()
            })
            .collect::<MddResult<_>>()?
    } else {
        vec![None; reference.parameter_descriptors.len()]
    };

    let mut annotated: Option<(&AnnotationFacts, &AnnotationIndex)> = view.annotations;
    if options.annotations && annotated.is_none() {
        report.annotation_layer_missing = true;
    }
    if !options.annotations {
        annotated = None;
    }

    let mut slots: Vec<Option<u32>> = vec![None; reference.parameter_descriptors.len()];
    if let Some((facts, index)) = annotated
        && let Some(placed) = index.parameter_slots(
            definition.class_def_idx,
            definition.method_idx,
            reference.parameter_descriptors.len(),
        )
    {
        let _ = facts;
        match placed {
            ParameterSlots::Placed(found) => slots = found,
            ParameterSlots::Unplaced { slots: left_out } => {
                report.parameter_annotation_slots_unplaced = left_out as u32;
            }
        }
    }

    for position in 0..reference.parameter_descriptors.len() {
        let name = names[position].as_ref();
        let mut blocks = String::new();
        let mut count = 0;
        if let (Some((facts, index)), Some(set)) = (annotated, slots[position]) {
            let data = facts.data();
            let context = value_context(method, data);
            count = index.write_set(&mut blocks, data, &context, set, 8)?;
        }
        if name.is_none() && count == 0 {
            continue;
        }
        let mut line = format!("    .param p{}", starts[position]);
        if let Some(name) = name {
            line.push_str(", ");
            line.push_str(name);
        }
        extras.header.push(line);
        if count > 0 {
            extras
                .header
                .extend(blocks.split_terminator('\n').map(str::to_owned));
            extras.header.push("    .end param".to_owned());
        }
    }

    if let Some((facts, index)) = annotated
        && let Some(set) = index.method_set(definition.class_def_idx, definition.method_idx)
    {
        let data = facts.data();
        let context = value_context(method, data);
        extras
            .header
            .extend(index.set_lines(data, &context, set, 4)?);
    }

    if options.debug
        && let Some(code) = method.code
        && let Some(debug) = code.debug_info.as_ref()
    {
        let instruction_starts: BTreeSet<u32> = code
            .instructions
            .iter()
            .map(|i| i.code_unit_offset)
            .collect();
        let first_parameter = code.registers_size.saturating_sub(code.ins_size);
        let register = |number: u16| {
            if number >= first_parameter {
                format!("p{}", number - first_parameter)
            } else {
                format!("v{number}")
            }
        };
        let context = ValueContext {
            metadata: method.metadata,
            definitions: method.definitions,
            values: &[],
        };
        let (placed, unplaced, not_lines) = place_events(
            debug.events.iter(),
            &instruction_starts,
            code.insns_size_code_units,
            |event| debug_line(event, &context, &register),
        )?;
        report.debug_events_unplaced += unplaced;
        report.positions_not_source_lines += not_lines;
        extras.at_address = placed;
    }
    Ok((extras, report))
}

fn value_context<'a>(method: &MethodView<'a>, data: &'a DexAnnotations) -> ValueContext<'a> {
    ValueContext {
        metadata: method.metadata,
        definitions: method.definitions,
        values: &data.values,
    }
}

/// Put the lines of debug events at the addresses they belong to.
///
/// `text` gives the directive of an event: `Ok(None)` for an event that writes nothing at all
/// (advance pc, advance line, end of sequence) and `Err` for an event whose names the pools do
/// not hold. A position that is not a source line writes nothing and is counted apart. An
/// event at an address that is no instruction start, or past the end of the code, is counted as
/// unplaced; one at the end of the code goes to the key `insns_size`.
///
/// Returns the lines by address, the unplaced count and the not-a-source-line count.
pub(crate) fn place_events(
    events: impl Iterator<Item = DebugEvent>,
    instruction_starts: &BTreeSet<u32>,
    insns_size: u32,
    mut text: impl FnMut(&DebugEvent) -> MddResult<EventLine>,
) -> MddResult<(BTreeMap<u32, Vec<String>>, u32, u32)> {
    let mut placed: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    let (mut unplaced, mut not_lines) = (0u32, 0u32);
    for event in events {
        let line = match text(&event)? {
            EventLine::Nothing => continue,
            EventLine::NotASourceLine => {
                not_lines += 1;
                continue;
            }
            EventLine::Directive(line) => line,
        };
        let key = match event.code_item_address_scope {
            DebugAddressScope::InsideCodeUnits
                if instruction_starts.contains(&event.address_code_units) =>
            {
                event.address_code_units
            }
            DebugAddressScope::AtCodeEnd => insns_size,
            _ => {
                unplaced += 1;
                continue;
            }
        };
        placed.entry(key).or_default().push(format!("    {line}"));
    }
    Ok((placed, unplaced, not_lines))
}

/// What one debug event writes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EventLine {
    /// The event moves the program's state and writes no directive.
    Nothing,
    /// A position whose line is not a source line.
    NotASourceLine,
    Directive(String),
}

/// The directive of one debug event.
fn debug_line(
    event: &DebugEvent,
    context: &ValueContext<'_>,
    register: &impl Fn(u16) -> String,
) -> MddResult<EventLine> {
    let need_register = || {
        event.register.ok_or_else(|| {
            mdd_types::MddError::new(
                mdd_types::ErrorCode::InternalFault,
                "facts.smali",
                "a debug event that names a register has none",
            )
        })
    };
    Ok(EventLine::Directive(match event.opcode {
        0..=2 => return Ok(EventLine::Nothing),
        3 | 4 => {
            let name = match event.name_idx {
                Some(index) => context.string_literal(index)?,
                None => "null".to_owned(),
            };
            let ty = match event.type_idx {
                Some(index) => context
                    .metadata
                    .types
                    .get(index as usize)
                    .map(|fact| fact.data.descriptor.clone())
                    .ok_or_else(|| {
                        mdd_types::MddError::new(
                            mdd_types::ErrorCode::InternalFault,
                            "facts.smali",
                            "a local names a type the facts do not hold",
                        )
                    })?,
                None => "null".to_owned(),
            };
            let mut line = format!(".local {}, {name}:{ty}", register(need_register()?));
            if let Some(index) = event.signature_idx {
                line.push_str(", ");
                line.push_str(&context.string_literal(index)?);
            }
            line
        }
        5 => format!(".end local {}", register(need_register()?)),
        6 => format!(".restart local {}", register(need_register()?)),
        7 => ".prologue".to_owned(),
        8 => ".epilogue".to_owned(),
        9 => match event.file_idx {
            Some(index) => format!(".source {}", context.string_literal(index)?),
            None => ".source null".to_owned(),
        },
        _ => match event.source_line {
            Some(line) if event.source_line_usable => format!(".line {}", line.0),
            _ => return Ok(EventLine::NotASourceLine),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdd_dex::instructions::{SignedDecimal, SourceLineKind};
    use mdd_types::DecimalU64;

    fn event(opcode: u8, address: u32, scope: DebugAddressScope, line: Option<u64>) -> DebugEvent {
        DebugEvent {
            byte_offset: DecimalU64(0),
            opcode,
            address_code_units: address,
            encoded_line_decimal: SignedDecimal(line.map_or(-1, |l| l as i64)),
            source_line: line.map(DecimalU64),
            source_line_usable: line.is_some(),
            source_line_kind: SourceLineKind::PositiveEncodedLine,
            register: None,
            name_idx: None,
            type_idx: None,
            signature_idx: None,
            file_idx: None,
            emits_position: opcode >= 10,
            code_item_address_scope: scope,
        }
    }

    fn lines(opcode: u8, event: &DebugEvent) -> MddResult<EventLine> {
        Ok(match opcode {
            0..=2 => EventLine::Nothing,
            7 => EventLine::Directive(".prologue".to_owned()),
            _ if event.source_line_usable => {
                EventLine::Directive(format!(".line {}", event.source_line.unwrap().0))
            }
            _ => EventLine::NotASourceLine,
        })
    }

    #[test]
    fn events_go_to_the_instruction_they_are_at_in_the_order_of_the_program() {
        use DebugAddressScope::{AtCodeEnd, BeyondCodeEnd, InsideCodeUnits};
        let starts: BTreeSet<u32> = [0, 1, 3].into();
        let events = vec![
            event(7, 0, InsideCodeUnits, None),
            event(0x0e, 0, InsideCodeUnits, Some(10)),
            event(0x1e, 1, InsideCodeUnits, Some(11)),
            // inside the instruction at 3 (units 3..=5): at no instruction start
            event(0x1e, 4, InsideCodeUnits, Some(12)),
            // not a source line
            event(0x0e, 3, InsideCodeUnits, None),
            event(1, 3, InsideCodeUnits, None),
            event(0x0e, 6, AtCodeEnd, Some(13)),
            event(0x0e, 9, BeyondCodeEnd, Some(14)),
            event(0, 9, BeyondCodeEnd, None),
        ];
        let (placed, unplaced, not_lines) =
            place_events(events.iter().cloned(), &starts, 6, |e| lines(e.opcode, e)).unwrap();
        assert_eq!(placed[&0], ["    .prologue", "    .line 10"]);
        assert_eq!(placed[&1], ["    .line 11"]);
        assert_eq!(
            placed[&6],
            ["    .line 13"],
            "the end of the code has its own key"
        );
        assert_eq!(placed.len(), 3, "{placed:?}");
        assert_eq!(unplaced, 2, "one inside an instruction, one past the code");
        assert_eq!(not_lines, 1);
    }

    #[test]
    fn a_failing_event_fails_the_method_instead_of_being_skipped() {
        let starts: BTreeSet<u32> = [0].into();
        let events = vec![event(0x0e, 0, DebugAddressScope::InsideCodeUnits, Some(1))];
        let error = place_events(events.into_iter(), &starts, 1, |_| {
            Err(mdd_types::MddError::new(
                mdd_types::ErrorCode::InternalFault,
                "test",
                "boom",
            ))
        });
        assert!(error.is_err());
    }

    #[test]
    fn parameter_registers_start_after_this_and_a_wide_parameter_takes_two() {
        assert_eq!(width_of("J"), 2);
        assert_eq!(width_of("D"), 2);
        assert_eq!(width_of("I"), 1);
        assert_eq!(width_of("[J"), 1, "an array of longs is one reference");
        assert_eq!(width_of("Ljava/lang/Long;"), 1);
    }

    #[test]
    fn the_default_options_write_all_three_families_and_the_first_text_has_none() {
        assert_eq!(
            SmaliOptions::default(),
            SmaliOptions {
                annotations: true,
                parameters: true,
                debug: true
            }
        );
        assert_eq!(
            SmaliOptions::INSTRUCTIONS_ONLY,
            SmaliOptions {
                annotations: false,
                parameters: false,
                debug: false
            }
        );
    }
}
