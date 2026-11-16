use super::{
    Labels, MethodExtras, MethodView, RenderedMethod, fault, hex_signed, push_string_literal,
};
use mdd_dex::{
    definitions::{MethodBody, MethodReference},
    instructions::{
        CatchHandler, CodeItem, Instruction, Payload, PayloadData, ReferenceKind, ReferenceOperand,
        TryItem,
    },
};
use mdd_types::{ErrorCode, MddError, MddResult};
use std::fmt::Write as _;

/// What one rendering may cost.
#[derive(Clone, Copy, Debug)]
pub struct SmaliLimits {
    pub max_text_bytes: u64,
}

impl Default for SmaliLimits {
    fn default() -> Self {
        Self {
            max_text_bytes: 64 * 1024 * 1024,
        }
    }
}

const FLAG_WORDS: [(u32, &str); 14] = [
    (0x1, "public"),
    (0x2, "private"),
    (0x4, "protected"),
    (0x8, "static"),
    (0x10, "final"),
    (0x20, "synchronized"),
    (0x40, "bridge"),
    (0x80, "varargs"),
    (0x100, "native"),
    (0x400, "abstract"),
    (0x800, "strictfp"),
    (0x1000, "synthetic"),
    (0x10000, "constructor"),
    (0x20000, "declared-synchronized"),
];

/// The method access flags as smali words, in the order the format prescribes. Bits
/// that have no word (for example 0x200, an interface bit that a method cannot carry)
/// are not printed; the numeric flags stay available beside the text.
pub fn access_flag_words(flags: u32) -> Vec<&'static str> {
    FLAG_WORDS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, word)| *word)
        .collect()
}

struct Context<'a> {
    view: &'a MethodView<'a>,
    code: &'a CodeItem,
    first_parameter: u16,
}

impl Context<'_> {
    fn register(&self, number: u16) -> String {
        if number >= self.first_parameter {
            format!("p{}", number - self.first_parameter)
        } else {
            format!("v{number}")
        }
    }

    fn reference(&self, operand: &ReferenceOperand) -> MddResult<String> {
        let index = operand.local_index as usize;
        let definitions = self.view.definitions;
        let metadata = self.view.metadata;
        let missing = |what: &str| {
            fault(&format!(
                "an instruction refers to a {what} the facts do not hold"
            ))
        };
        Ok(match operand.kind {
            ReferenceKind::String => {
                let string = metadata
                    .strings
                    .get(index)
                    .ok_or_else(|| missing("string"))?;
                let mut out = String::new();
                push_string_literal(&mut out, &string.data.text.utf16_units);
                out
            }
            ReferenceKind::Type => metadata
                .types
                .get(index)
                .ok_or_else(|| missing("type"))?
                .data
                .descriptor
                .clone(),
            ReferenceKind::Field => {
                let field = definitions
                    .field_references
                    .get(index)
                    .ok_or_else(|| missing("field"))?;
                format!(
                    "{}->{}:{}",
                    field.class_descriptor, field.field_name, field.type_descriptor
                )
            }
            ReferenceKind::Method => {
                let method = definitions
                    .method_references
                    .get(index)
                    .ok_or_else(|| missing("method"))?;
                format!(
                    "{}->{}({}){}",
                    method.class_descriptor,
                    method.method_name,
                    method.parameter_descriptors.concat(),
                    method.return_descriptor
                )
            }
            ReferenceKind::Prototype => metadata
                .prototypes
                .get(index)
                .ok_or_else(|| missing("prototype"))?
                .data
                .descriptor
                .clone(),
            ReferenceKind::CallSite => format!("call_site_{index}"),
            ReferenceKind::MethodHandle => format!("method_handle_{index}"),
        })
    }

    fn register_list(&self, instruction: &Instruction) -> String {
        match &instruction.register_range {
            Some(range) if range.word_count == 0 => "{}".to_owned(),
            Some(range) => format!(
                "{{{} .. {}}}",
                self.register(range.first),
                self.register(range.first + (range.word_count - 1))
            ),
            None => format!(
                "{{{}}}",
                instruction
                    .registers
                    .iter()
                    .map(|r| self.register(r))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

fn goto_or_cond(opcode: u8) -> &'static str {
    match opcode {
        0x28..=0x2a => "goto_",
        _ => "cond_",
    }
}

fn payload_label_prefix(data: &PayloadData) -> &'static str {
    match data {
        PayloadData::PackedSwitch { .. } => "pswitch_data_",
        PayloadData::SparseSwitch { .. } => "sswitch_data_",
        PayloadData::FillArray { .. } => "array_",
    }
}

fn collect_labels(code: &CodeItem) -> MddResult<Labels> {
    let mut labels = Labels::default();
    for instruction in &code.instructions {
        if let Some(target) = instruction.branch_target_code_units {
            labels.add(target, goto_or_cond(instruction.opcode));
        }
    }
    for payload in &code.payloads {
        labels.add(
            payload.code_unit_offset,
            payload_label_prefix(&payload.data),
        );
    }
    for switch in &code.switch_targets {
        let owner = code
            .instructions
            .iter()
            .find(|i| i.code_unit_offset == switch.instruction_code_unit_offset)
            .ok_or_else(|| fault("a switch table names an instruction that is not there"))?;
        let prefix = match owner.opcode {
            0x2b => "pswitch_",
            0x2c => "sswitch_",
            _ => {
                return Err(fault(
                    "a switch table belongs to an instruction that is not a switch",
                ));
            }
        };
        for target in &switch.target_code_units {
            labels.add(*target, prefix);
        }
    }
    for item in &code.tries {
        labels.add(item.start_code_unit, "try_start_");
        labels.add(
            item.start_code_unit + u32::from(item.code_unit_count),
            "try_end_",
        );
        let handler = handler_of(code, item.handler_relative_byte_offset)?;
        for pair in &handler.typed_catches {
            labels.add(pair.address_code_units, "catch_");
        }
        if let Some(address) = handler.catch_all_address_code_units {
            labels.add(address, "catchall_");
        }
    }
    Ok(labels)
}

fn handler_of(code: &CodeItem, relative: u16) -> MddResult<&CatchHandler> {
    code.handlers
        .iter()
        .find(|h| h.relative_byte_offset == u32::from(relative))
        .ok_or_else(|| fault("a try item names a handler that is not there"))
}

fn operands(
    context: &Context<'_>,
    instruction: &Instruction,
    switch_label: impl Fn(u32) -> String,
) -> MddResult<String> {
    let reg = |slot: usize| -> MddResult<String> {
        instruction
            .registers
            .iter()
            .nth(slot)
            .map(|r| context.register(r))
            .ok_or_else(|| fault("an instruction has fewer registers than its format says"))
    };
    let literal = || -> MddResult<String> {
        let literal = instruction
            .literal
            .as_ref()
            .ok_or_else(|| fault("an instruction has no literal its format needs"))?;
        let mut text = hex_signed(literal.signed_decimal.as_i64());
        if instruction.mnemonic.starts_with("const-wide") {
            text.push('L');
        }
        Ok(text)
    };
    let branch = || -> MddResult<String> {
        let target = instruction
            .branch_target_code_units
            .ok_or_else(|| fault("a branch has no target"))?;
        Ok(format!(":{}{target:x}", goto_or_cond(instruction.opcode)))
    };
    let first_reference = || -> MddResult<String> {
        context.reference(
            instruction
                .references
                .first()
                .ok_or_else(|| fault("an instruction has no reference its format needs"))?,
        )
    };
    let second_reference = || -> MddResult<String> {
        context.reference(
            instruction
                .references
                .get(1)
                .ok_or_else(|| fault("a polymorphic call has no prototype"))?,
        )
    };
    let payload_target = || -> MddResult<String> {
        let target = instruction
            .payload_target_code_units
            .ok_or_else(|| fault("a payload instruction has no payload"))?;
        Ok(switch_label(target))
    };
    Ok(match &*instruction.format {
        "10x" => String::new(),
        "12x" | "22x" | "32x" => format!("{}, {}", reg(0)?, reg(1)?),
        "11n" | "21s" | "21h" | "31i" | "51l" => format!("{}, {}", reg(0)?, literal()?),
        "11x" => reg(0)?,
        "10t" | "20t" | "30t" => branch()?,
        "21t" => format!("{}, {}", reg(0)?, branch()?),
        "21c" | "31c" => format!("{}, {}", reg(0)?, first_reference()?),
        "23x" => format!("{}, {}, {}", reg(0)?, reg(1)?, reg(2)?),
        "22b" | "22s" => format!("{}, {}, {}", reg(0)?, reg(1)?, literal()?),
        "22t" => format!("{}, {}, {}", reg(0)?, reg(1)?, branch()?),
        "22c" => format!("{}, {}, {}", reg(0)?, reg(1)?, first_reference()?),
        "31t" => format!("{}, {}", reg(0)?, payload_target()?),
        "35c" | "3rc" => format!(
            "{}, {}",
            context.register_list(instruction),
            first_reference()?
        ),
        "45cc" | "4rcc" => format!(
            "{}, {}, {}",
            context.register_list(instruction),
            first_reference()?,
            second_reference()?
        ),
        other => {
            return Err(
                fault("an instruction has a format the renderer does not know")
                    .detail("format", other.to_owned()),
            );
        }
    })
}

fn element(bytes: &[u8], width: usize) -> String {
    let mut raw = [0u8; 8];
    raw[..width].copy_from_slice(bytes);
    let value = match width {
        1 => i64::from(raw[0] as i8),
        2 => i64::from(i16::from_le_bytes([raw[0], raw[1]])),
        4 => i64::from(i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])),
        _ => i64::from_le_bytes(raw),
    };
    let suffix = match width {
        1 => "t",
        2 => "s",
        8 => "L",
        _ => "",
    };
    format!("{}{suffix}", hex_signed(value))
}

fn write_payload(
    out: &mut String,
    payload: &Payload,
    code: &CodeItem,
    bytes: &[u8],
) -> MddResult<()> {
    match &payload.data {
        PayloadData::PackedSwitch {
            first_key,
            relative_targets: _,
        } => {
            let table = code
                .switch_targets
                .iter()
                .find(|s| s.payload_code_unit_offset == payload.code_unit_offset);
            let _ = writeln!(
                out,
                "    .packed-switch {}",
                hex_signed(i64::from(*first_key))
            );
            if let Some(table) = table {
                for target in &table.target_code_units {
                    let _ = writeln!(out, "        :pswitch_{target:x}");
                }
            }
            out.push_str("    .end packed-switch\n");
        }
        PayloadData::SparseSwitch {
            keys,
            relative_targets: _,
        } => {
            let table = code
                .switch_targets
                .iter()
                .find(|s| s.payload_code_unit_offset == payload.code_unit_offset);
            out.push_str("    .sparse-switch\n");
            if let Some(table) = table {
                for (key, target) in keys.iter().zip(&table.target_code_units) {
                    let _ = writeln!(
                        out,
                        "        {} -> :sswitch_{target:x}",
                        hex_signed(i64::from(*key))
                    );
                }
            }
            out.push_str("    .end sparse-switch\n");
        }
        PayloadData::FillArray {
            element_width_bytes,
            element_count,
            data_range,
        } => {
            let width = usize::from(*element_width_bytes);
            let start = usize::try_from(data_range.byte_offset.0)
                .map_err(|_| fault("an array payload lies outside the file"))?;
            let length = usize::try_from(data_range.byte_length.0)
                .map_err(|_| fault("an array payload lies outside the file"))?;
            let data = start
                .checked_add(length)
                .and_then(|end| bytes.get(start..end))
                .ok_or_else(|| fault("an array payload lies outside the file"))?;
            let _ = writeln!(out, "    .array-data {width}");
            for chunk in data.chunks_exact(width).take(*element_count as usize) {
                let _ = writeln!(out, "        {}", element(chunk, width));
            }
            out.push_str("    .end array-data\n");
        }
    }
    Ok(())
}

fn push_lines(text: &mut String, lines: &[String]) {
    for line in lines {
        text.push_str(line);
        text.push('\n');
    }
}

fn too_large(limit: u64) -> MddError {
    MddError::new(
        ErrorCode::QuotaExceeded,
        "facts.smali",
        "the rendered text is over the byte budget",
    )
    .detail("budget", "max_text_bytes")
    .detail("limit", limit.to_string())
}

/// The `.method ...` line of a method, without its newline.
pub fn method_declaration(reference: &MethodReference, access_flags: u32) -> String {
    let mut declaration = String::from(".method");
    for word in access_flag_words(access_flags) {
        declaration.push(' ');
        declaration.push_str(word);
    }
    let _ = write!(
        declaration,
        " {}({}){}",
        reference.method_name,
        reference.parameter_descriptors.concat(),
        reference.return_descriptor
    );
    declaration
}

/// Render one defined method. A method with a body must come with its code.
pub fn render_method(view: &MethodView<'_>, limits: SmaliLimits) -> MddResult<RenderedMethod> {
    render_method_with(view, limits, &MethodExtras::default())
}

/// Render one defined method with the lines a caller adds (see [`MethodExtras`]). With no
/// extras the text is exactly what [`render_method`] gives; a line the text has no place
/// for is a fault, never a silent drop.
pub fn render_method_with(
    view: &MethodView<'_>,
    limits: SmaliLimits,
    extras: &MethodExtras,
) -> MddResult<RenderedMethod> {
    let definition = view.definition;
    let reference = view
        .definitions
        .method_references
        .get(definition.method_idx as usize)
        .ok_or_else(|| fault("a method definition has no method reference"))?;
    let declaration = method_declaration(reference, definition.access_flags);
    let mut text = String::new();
    text.push_str(&declaration);
    text.push('\n');
    let has_body = matches!(definition.body, MethodBody::Present { .. });
    let Some(code) = view.code.filter(|_| has_body) else {
        if has_body {
            return Err(fault("a method with a body was given no code"));
        }
        if !extras.at_address.is_empty() {
            return Err(fault(
                "a method without code was given lines for a code address",
            ));
        }
        push_lines(&mut text, &extras.header);
        text.push_str(".end method\n");
        return Ok(RenderedMethod {
            declaration,
            text,
            registers: None,
            code_units: None,
            try_count: None,
        });
    };
    let first_parameter = code
        .registers_size
        .checked_sub(code.ins_size)
        .ok_or_else(|| fault("a code item has more incoming than total registers"))?;
    let context = Context {
        view,
        code,
        first_parameter,
    };
    let _ = writeln!(text, "    .registers {}", code.registers_size);
    push_lines(&mut text, &extras.header);
    text.push('\n');

    let labels = collect_labels(code)?;
    let bytes = view.metadata.bytes();
    let mut instructions = code.instructions.iter().peekable();
    let mut payloads = code.payloads.iter().peekable();
    let mut pending = labels.at.iter().peekable();
    let end_address = code.insns_size_code_units;
    let mut placed = 0usize;
    loop {
        let next_instruction = instructions.peek().map(|i| i.code_unit_offset);
        let next_payload = payloads.peek().map(|p| p.code_unit_offset);
        let address = match (next_instruction, next_payload) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => end_address,
        };
        while let Some((at, names)) = pending.next_if(|(at, _)| **at <= address) {
            if *at < address {
                return Err(fault("a label points into the middle of an instruction"));
            }
            for name in names {
                let _ = writeln!(text, "    :{name}");
            }
        }
        for item in &code.tries {
            if item.start_code_unit + u32::from(item.code_unit_count) == address {
                write_catches(&mut text, &context, item)?;
            }
        }
        if (next_instruction == Some(address) || address == end_address)
            && let Some(lines) = extras.at_address.get(&address)
        {
            push_lines(&mut text, lines);
            placed += 1;
        }
        if text.len() as u64 > limits.max_text_bytes {
            return Err(too_large(limits.max_text_bytes));
        }
        if address == end_address && next_instruction.is_none() && next_payload.is_none() {
            break;
        }
        if next_instruction == Some(address) {
            let instruction = instructions.next().expect("peeked");
            let switch_label = |target: u32| -> String {
                let prefix = match instruction.opcode {
                    0x26 => "array_",
                    0x2b => "pswitch_data_",
                    _ => "sswitch_data_",
                };
                format!(":{prefix}{target:x}")
            };
            let rendered = operands(&context, instruction, switch_label)?;
            if rendered.is_empty() {
                let _ = writeln!(text, "    {}", instruction.mnemonic);
            } else {
                let _ = writeln!(text, "    {} {rendered}", instruction.mnemonic);
            }
        } else {
            let payload = payloads.next().expect("peeked");
            write_payload(&mut text, payload, code, bytes)?;
        }
    }
    if pending.next().is_some() {
        return Err(fault("a label points past the end of the code"));
    }
    if placed != extras.at_address.len() {
        return Err(fault(
            "lines were given for a code address that is not where an instruction starts or the code ends",
        ));
    }
    text.push_str(".end method\n");
    if text.len() as u64 > limits.max_text_bytes {
        return Err(too_large(limits.max_text_bytes));
    }
    Ok(RenderedMethod {
        declaration,
        text,
        registers: Some(code.registers_size),
        code_units: Some(code.insns_size_code_units),
        try_count: Some(
            u16::try_from(code.tries.len()).map_err(|_| fault("a code item has too many tries"))?,
        ),
    })
}

/// The `.catch` lines of one try item: typed catches in the order the handler lists them,
/// then the catch-all. They follow the `:try_end_` label of the item.
fn write_catches(text: &mut String, context: &Context<'_>, item: &TryItem) -> MddResult<()> {
    let start = item.start_code_unit;
    let end = start + u32::from(item.code_unit_count);
    let handler = handler_of(context.code, item.handler_relative_byte_offset)?;
    for pair in &handler.typed_catches {
        let descriptor = &context
            .view
            .metadata
            .types
            .get(pair.type_idx as usize)
            .ok_or_else(|| fault("a catch names a type the facts do not hold"))?
            .data
            .descriptor;
        let _ = writeln!(
            text,
            "    .catch {descriptor} {{:try_start_{start:x} .. :try_end_{end:x}}} :catch_{:x}",
            pair.address_code_units
        );
    }
    if let Some(address) = handler.catch_all_address_code_units {
        let _ = writeln!(
            text,
            "    .catchall {{:try_start_{start:x} .. :try_end_{end:x}}} :catchall_{address:x}"
        );
    }
    Ok(())
}
