use super::*;

fn words(units: &[u16], pc: usize, count: usize, base: u64) -> MddResult<&[u16]> {
    let end = pc
        .checked_add(count)
        .ok_or_else(|| fail("INSTRUCTION_WIDTH_OVERFLOW", base, 0))?;
    units.get(pc..end).ok_or_else(|| {
        fail(
            "TRUNCATED_INSTRUCTION_OR_PAYLOAD",
            base + pc as u64 * 2,
            count as u64 * 2,
        )
    })
}

fn u32_words(lo: u16, hi: u16) -> u32 {
    u32::from(lo) | (u32::from(hi) << 16)
}

fn literal(value: i64, bits: u64, width: u8) -> Option<LiteralValue> {
    Some(LiteralValue {
        signed_decimal: SignedDecimal(value),
        encoded_bits: DecimalU64(bits),
        encoded_width_bits: width,
    })
}

fn payload(
    units: &[u16],
    pc: usize,
    base: u64,
    limits: CodeLimits,
    used: &mut Used,
) -> MddResult<Payload> {
    let at = base + pc as u64 * 2;
    if !pc.is_multiple_of(2) {
        return Err(fail("PAYLOAD_ALIGNMENT", at, 2));
    }
    let header = words(units, pc, 2, base)?;
    let (width, data) = match header[0] {
        0x0100 => {
            let count = usize::from(header[1]);
            charge(
                &mut used.payload_elements,
                count as u64,
                limits.max_payload_elements,
                "max_payload_elements",
                at,
            )?;
            let width = 4 + count * 2;
            let values = words(units, pc, width, base)?;
            let first = u32_words(values[2], values[3]) as i32;
            if count > 0 && i64::from(first) + (count - 1) as i64 > i64::from(i32::MAX) {
                return Err(fail("PACKED_SWITCH_KEY_OVERFLOW", at, width as u64 * 2));
            }
            let targets = values[4..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|v| u32_words(v[0], v[1]) as i32)
                .collect();
            (
                width,
                PayloadData::PackedSwitch {
                    first_key: first,
                    relative_targets: targets,
                },
            )
        }
        0x0200 => {
            let count = usize::from(header[1]);
            charge(
                &mut used.payload_elements,
                count as u64,
                limits.max_payload_elements,
                "max_payload_elements",
                at,
            )?;
            let width = 2 + count * 4;
            let values = words(units, pc, width, base)?;
            let keys: Vec<_> = values[2..2 + count * 2]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|v| u32_words(v[0], v[1]) as i32)
                .collect();
            if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(fail("SPARSE_SWITCH_KEYS_NOT_STRICT", at, width as u64 * 2));
            }
            let targets = values[2 + count * 2..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|v| u32_words(v[0], v[1]) as i32)
                .collect();
            (
                width,
                PayloadData::SparseSwitch {
                    keys,
                    relative_targets: targets,
                },
            )
        }
        0x0300 => {
            let header = words(units, pc, 4, base)?;
            let element_width = header[1];
            if !matches!(element_width, 1 | 2 | 4 | 8) {
                return Err(fail("ARRAY_PAYLOAD_ELEMENT_WIDTH", at + 2, 2));
            }
            let count = u32_words(header[2], header[3]);
            charge(
                &mut used.payload_elements,
                u64::from(count),
                limits.max_payload_elements,
                "max_payload_elements",
                at,
            )?;
            let bytes = u64::from(count)
                .checked_mul(u64::from(element_width))
                .ok_or_else(|| fail("ARRAY_PAYLOAD_LENGTH_OVERFLOW", at, 8))?;
            let width = 4 + usize::try_from(bytes.div_ceil(2))
                .map_err(|_| fail("ARRAY_PAYLOAD_HOST_RANGE", at, 8))?;
            words(units, pc, width, base)?;
            (
                width,
                PayloadData::FillArray {
                    element_width_bytes: element_width,
                    element_count: count,
                    data_range: range(at + 8, bytes),
                },
            )
        }
        _ => return Err(fail("UNKNOWN_PAYLOAD_IDENTIFIER", at, 2)),
    };
    Ok(Payload {
        code_unit_offset: pc as u32,
        width_code_units: u32::try_from(width)
            .map_err(|_| fail("PAYLOAD_WIDTH_OVERFLOW", at, 0))?,
        raw_range: range(at, width as u64 * 2),
        data,
    })
}

fn reference(
    info: &Opcode,
    index: u32,
    second: Option<u32>,
    counts: Counts,
    at: u64,
) -> MddResult<Vec<ReferenceOperand>> {
    let kind = match info.index {
        "kIndexNone" => return Ok(Vec::new()),
        "kIndexStringRef" => ReferenceKind::String,
        "kIndexTypeRef" => ReferenceKind::Type,
        "kIndexFieldRef" => ReferenceKind::Field,
        "kIndexMethodRef" | "kIndexMethodAndProtoRef" => ReferenceKind::Method,
        "kIndexProtoRef" => ReferenceKind::Prototype,
        "kIndexCallSiteRef" => ReferenceKind::CallSite,
        "kIndexMethodHandleRef" => ReferenceKind::MethodHandle,
        _ => return Err(fail("UNRECOGNIZED_OPCODE_INDEX_KIND", at, 0)),
    };
    let mut refs = vec![ReferenceOperand {
        kind,
        local_index: index,
        raw_range: DexRange {
            byte_offset: DecimalU64(at + 2),
            byte_length: DecimalU64(if info.format == "31c" { 4 } else { 2 }),
        },
    }];
    if info.index == "kIndexMethodAndProtoRef" {
        refs.push(ReferenceOperand {
            kind: ReferenceKind::Prototype,
            local_index: second.ok_or_else(|| fail("POLYMORPHIC_PROTO_MISSING", at, 0))?,
            raw_range: DexRange {
                byte_offset: DecimalU64(at + 6),
                byte_length: DecimalU64(2),
            },
        });
    }
    for operand in &refs {
        if operand.local_index >= counts.limit(&operand.kind) {
            return Err(fail("INSTRUCTION_REFERENCE_OUT_OF_RANGE", at, 0)
                .detail("reference_kind", format!("{:?}", operand.kind))
                .detail("local_index", u64::from(operand.local_index))
                .detail("table_count", u64::from(counts.limit(&operand.kind))));
        }
    }
    Ok(refs)
}

fn instruction(
    units: &[u16],
    pc: usize,
    context: DecodeContext,
    ordinal: u32,
) -> MddResult<Instruction> {
    let DecodeContext {
        base,
        registers,
        outs,
        counts,
        version,
        ..
    } = context;
    let word = units[pc];
    let opcode = word as u8;
    let info = &opcodes::OPCODES[usize::from(opcode)];
    let at = base + pc as u64 * 2;
    if info.reserved {
        return Err(fail("RESERVED_OPCODE", at, 2).detail("opcode", u64::from(opcode)));
    }
    if version < info.min_version {
        return Err(
            fail("OPCODE_NOT_ALLOWED_IN_DEX_VERSION", at, 2).detail("opcode", u64::from(opcode))
        );
    }
    let width = match info.format {
        "10x" | "12x" | "11n" | "11x" | "10t" => 1,
        "20t" | "22x" | "21t" | "21s" | "21h" | "21c" | "23x" | "22b" | "22t" | "22s" | "22c" => 2,
        "32x" | "30t" | "31t" | "31i" | "31c" | "35c" | "3rc" => 3,
        "45cc" | "4rcc" => 4,
        "51l" => 5,
        _ => return Err(fail("UNKNOWN_INSTRUCTION_FORMAT", at, 2)),
    };
    let data = words(units, pc, width, base)?;
    let high = word >> 8;
    if matches!(info.format, "10x" | "20t" | "30t" | "32x") && high != 0 {
        return Err(fail("NONZERO_UNUSED_OPCODE_BITS", at, 2));
    }
    let mut regs = Registers::default();
    let mut reg_range = None;
    let mut literal_value = None;
    let mut branch = None;
    let mut index = 0u32;
    let mut second = None;
    match info.format {
        "10x" => (),
        "12x" => regs.extend([high & 15, high >> 4]),
        "11n" => {
            regs.push(high & 15);
            literal_value = literal(
                i64::from(((high >> 4) as i8) << 4 >> 4),
                u64::from(high >> 4),
                4,
            );
        }
        "11x" => regs.push(high),
        "10t" => branch = Some(i32::from(high as u8 as i8)),
        "20t" => branch = Some(i32::from(data[1] as i16)),
        "22x" => regs.extend([high, data[1]]),
        "21t" => {
            regs.push(high);
            branch = Some(i32::from(data[1] as i16));
        }
        "21s" => {
            regs.push(high);
            literal_value = literal(i64::from(data[1] as i16), u64::from(data[1]), 16);
        }
        "21h" => {
            regs.push(high);
            let value = if opcode == 0x19 {
                ((u64::from(data[1])) << 48) as i64
            } else {
                i64::from((u32::from(data[1]) << 16) as i32)
            };
            literal_value = literal(value, u64::from(data[1]), 16);
        }
        "21c" => {
            regs.push(high);
            index = u32::from(data[1]);
        }
        "23x" => regs.extend_three([high, data[1] & 255, data[1] >> 8]),
        "22b" => {
            regs.extend([high, data[1] & 255]);
            literal_value = literal(
                i64::from((data[1] >> 8) as u8 as i8),
                u64::from(data[1] >> 8),
                8,
            );
        }
        "22t" => {
            regs.extend([high & 15, high >> 4]);
            branch = Some(i32::from(data[1] as i16));
        }
        "22s" => {
            regs.extend([high & 15, high >> 4]);
            literal_value = literal(i64::from(data[1] as i16), u64::from(data[1]), 16);
        }
        "22c" => {
            regs.extend([high & 15, high >> 4]);
            index = u32::from(data[1]);
        }
        "32x" => regs.extend([data[1], data[2]]),
        "30t" => branch = Some(u32_words(data[1], data[2]) as i32),
        "31t" => {
            regs.push(high);
            branch = Some(u32_words(data[1], data[2]) as i32);
        }
        "31i" => {
            regs.push(high);
            let bits = u32_words(data[1], data[2]);
            literal_value = literal(i64::from(bits as i32), u64::from(bits), 32);
        }
        "31c" => {
            regs.push(high);
            index = u32_words(data[1], data[2]);
        }
        "35c" | "45cc" => {
            let count = high >> 4;
            if count > 5 || (info.nonzero_args && count == 0) {
                return Err(fail("INVALID_INVOKE_REGISTER_COUNT", at, width as u64 * 2));
            }
            let all = [
                data[2] & 15,
                (data[2] >> 4) & 15,
                (data[2] >> 8) & 15,
                data[2] >> 12,
                high & 15,
            ];
            for value in all.iter().take(usize::from(count)) {
                regs.push(*value);
            }
            index = u32::from(data[1]);
            if width == 4 {
                second = Some(u32::from(data[3]));
            }
        }
        "3rc" | "4rcc" => {
            let count = high;
            let first = data[2];
            if (info.nonzero_args && count == 0)
                || u32::from(first) + u32::from(count) > u32::from(registers)
            {
                return Err(fail("REGISTER_RANGE_OUT_OF_BOUNDS", at, width as u64 * 2));
            }
            for n in 0..count {
                regs.push(first + n);
            }
            reg_range = Some(RegisterRange {
                first,
                word_count: count,
            });
            index = u32::from(data[1]);
            if width == 4 {
                second = Some(u32::from(data[3]));
            }
        }
        "51l" => {
            regs.push(high);
            let bits = u64::from(data[1])
                | (u64::from(data[2]) << 16)
                | (u64::from(data[3]) << 32)
                | (u64::from(data[4]) << 48);
            literal_value = literal(bits as i64, bits, 64);
        }
        _ => return Err(fail("UNKNOWN_INSTRUCTION_FORMAT", at, 2)),
    }
    for (slot, reg) in regs.iter().enumerate() {
        let wide = slot < 3 && (info.wide_mask & (1 << slot)) != 0;
        if u32::from(reg) + u32::from(wide) >= u32::from(registers) {
            return Err(fail("REGISTER_OPERAND_OUT_OF_RANGE", at, width as u64 * 2)
                .detail("register", u64::from(reg))
                .detail("wide", wide));
        }
    }
    let invoke = match opcode {
        0x6e..=0x72 => Some(InvokeKind::Ordinary),
        0x74..=0x78 => Some(InvokeKind::OrdinaryRange),
        0xfa => Some(InvokeKind::Polymorphic),
        0xfb => Some(InvokeKind::PolymorphicRange),
        0xfc => Some(InvokeKind::Custom),
        0xfd => Some(InvokeKind::CustomRange),
        _ => None,
    };
    if invoke.is_some() && regs.len() > usize::from(outs) {
        return Err(fail("INVOKE_WORD_COUNT_EXCEEDS_OUTS", at, width as u64 * 2));
    }
    if branch == Some(0) && matches!(opcode, 0x28 | 0x29 | 0x32..=0x3d) {
        return Err(fail("ZERO_BRANCH_OFFSET", at, width as u64 * 2));
    }
    let refs = reference(info, index, second, counts, at)?;
    Ok(Instruction {
        opcode,
        // Both names are borrowed from the static table, so decoding a code item
        // no longer allocates two strings per instruction.
        mnemonic: Cow::Borrowed(info.name),
        format: Cow::Borrowed(info.format),
        byte_offset: DecimalU64(at),
        code_unit_offset: pc as u32,
        instruction_ordinal: ordinal,
        width_code_units: width as u8,
        registers: regs,
        register_range: reg_range,
        references: refs,
        literal: literal_value,
        branch_offset_code_units: branch,
        branch_target_code_units: None,
        payload_target_code_units: None,
        invoke_kind: invoke,
        raw_range: range(at, width as u64 * 2),
    })
}

type Decoded = (Vec<Instruction>, Vec<Payload>, Vec<SwitchTargets>);

pub(super) fn decode(units: &[u16], context: DecodeContext, used: &mut Used) -> MddResult<Decoded> {
    let DecodeContext { base, limits, .. } = context;
    let mut pc = 0usize;
    let mut instructions = Vec::new();
    let mut payloads = Vec::new();
    while pc < units.len() {
        if units[pc] & 255 == 0 && units[pc] != 0 {
            let item = payload(units, pc, base, limits, used)?;
            pc += item.width_code_units as usize;
            payloads.push(item);
        } else {
            charge(
                &mut used.instructions,
                1,
                limits.max_instructions,
                "max_instructions",
                base + pc as u64 * 2,
            )?;
            let ordinal = u32::try_from(instructions.len())
                .map_err(|_| fail("INSTRUCTION_ORDINAL_OVERFLOW", base, 0))?;
            let item = instruction(units, pc, context, ordinal)?;
            pc += usize::from(item.width_code_units);
            instructions.push(item);
        }
    }
    let starts: BTreeSet<u32> = instructions.iter().map(|i| i.code_unit_offset).collect();
    let payload_map: BTreeMap<_, _> = payloads.iter().map(|p| (p.code_unit_offset, p)).collect();
    let mut switches = Vec::new();
    let size = units.len() as u32;
    for item in &mut instructions {
        if let Some(relative) = item.branch_offset_code_units {
            let target = i64::from(item.code_unit_offset) + i64::from(relative);
            if matches!(item.opcode, 0x26 | 0x2b | 0x2c) {
                let target = u32::try_from(target)
                    .map_err(|_| fail("PAYLOAD_TARGET_RANGE", item.byte_offset.0, 0))?;
                let data = payload_map
                    .get(&target)
                    .ok_or_else(|| fail("PAYLOAD_TARGET_NOT_PAYLOAD", item.byte_offset.0, 0))?;
                item.payload_target_code_units = Some(target);
                let relatives = match (&data.data, item.opcode) {
                    (PayloadData::FillArray { .. }, 0x26) => None,
                    (
                        PayloadData::PackedSwitch {
                            relative_targets, ..
                        },
                        0x2b,
                    )
                    | (
                        PayloadData::SparseSwitch {
                            relative_targets, ..
                        },
                        0x2c,
                    ) => Some(relative_targets),
                    _ => return Err(fail("PAYLOAD_KIND_MISMATCH", item.byte_offset.0, 0)),
                };
                if let Some(relatives) = relatives {
                    charge(
                        &mut used.switch_targets,
                        relatives.len() as u64,
                        limits.max_switch_targets,
                        "max_switch_targets",
                        item.byte_offset.0,
                    )?;
                    let mut targets = Vec::new();
                    for offset in relatives {
                        targets.push(valid_target(
                            i64::from(item.code_unit_offset) + i64::from(*offset),
                            size,
                            &starts,
                            item.byte_offset.0,
                        )?);
                    }
                    switches.push(SwitchTargets {
                        instruction_code_unit_offset: item.code_unit_offset,
                        payload_code_unit_offset: target,
                        target_code_units: targets,
                    });
                }
            } else {
                item.branch_target_code_units =
                    Some(valid_target(target, size, &starts, item.byte_offset.0)?);
            }
        }
    }
    Ok((instructions, payloads, switches))
}
