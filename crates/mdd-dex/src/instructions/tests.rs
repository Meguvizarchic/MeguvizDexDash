use super::*;
use serde_json::Value;
use sha1::{Digest, Sha1};

fn counts() -> Counts {
    Counts {
        strings: 16,
        types: 16,
        fields: 16,
        methods: 16,
        prototypes: 16,
        call_sites: 16,
        handles: 16,
    }
}

fn fragment(
    words: &[u16],
    registers: u16,
    outs: u16,
    version: u16,
) -> MddResult<(Vec<Instruction>, Vec<Payload>, Vec<SwitchTargets>)> {
    decode::decode(
        words,
        DecodeContext {
            base: 128,
            registers,
            outs,
            counts: counts(),
            version,
            limits: CodeLimits::default(),
        },
        &mut Used::default(),
    )
}

/// Render one retained encoded line through `Serialize`, so assertions keep
/// checking the emitted canonical decimal text rather than only the integer.
fn encoded_text(event: DebugEvent) -> String {
    serde_json::to_value(event.encoded_line_decimal)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/instructions/generated")
            .join(name),
    )
    .unwrap()
}

fn parse_file(bytes: &[u8]) -> MddResult<CodeSection> {
    parse_file_policy(bytes, DebugPolicy::EncodedFactsV1)
}

fn parse_file_policy(bytes: &[u8], policy: DebugPolicy) -> MddResult<CodeSection> {
    let header = crate::validate_header(bytes)?;
    read_code_section(
        bytes,
        &header,
        CodeLimits {
            debug_policy: policy,
            ..CodeLimits::default()
        },
    )
}

fn resign(bytes: &mut [u8]) {
    let hash = Sha1::digest(&bytes[32..]);
    bytes[12..32].copy_from_slice(&hash);
    let (mut a, mut b) = (1u32, 0u32);
    for value in &bytes[12..] {
        a = (a + u32::from(*value)) % 65521;
        b = (b + a) % 65521;
    }
    bytes[8..12].copy_from_slice(&((b << 16) | a).to_le_bytes());
}

#[test]
fn every_active_opcode_and_format_is_actually_decoded_and_reserved_items_fail() {
    let data: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/instructions/generated/all-opcodes.json"
    ))
    .unwrap();
    let vectors = data["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 224);
    let mut formats = BTreeSet::new();
    for vector in vectors {
        let words: Vec<_> = vector["words"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap() as u16)
            .collect();
        let (instructions, _, _) = fragment(&words, 512, 255, 40)
            .unwrap_or_else(|error| panic!("opcode {}: {error}", vector["opcode"]));
        let first = &instructions[0];
        assert_eq!(u64::from(first.opcode), vector["opcode"].as_u64().unwrap());
        assert_eq!(first.mnemonic, vector["mnemonic"].as_str().unwrap());
        assert_eq!(first.format, vector["format"].as_str().unwrap());
        assert_eq!(
            u64::from(first.width_code_units),
            vector["expected_first_width"].as_u64().unwrap()
        );
        assert_eq!(first.instruction_ordinal, 0);
        assert_eq!(first.byte_offset, DecimalU64(128));
        formats.insert(first.format.clone());
    }
    assert_eq!(formats.len(), 26);
    let reserved: Vec<_> = opcodes::OPCODES
        .iter()
        .enumerate()
        .filter(|(_, i)| i.reserved)
        .collect();
    assert_eq!(reserved.len(), 32);
    for (opcode, _) in reserved {
        let error = fragment(&[opcode as u16, 0x000e], 16, 16, 40).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidInput);
        assert_eq!(error.details["reason"], "RESERVED_OPCODE");
    }
}

#[test]
fn hand_expected_operands_literals_ranges_and_dynamic_invokes_remain_distinct() {
    let data: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/instructions/generated/manual-expectations.json"
    ))
    .unwrap();
    for vector in data["vectors"].as_array().unwrap() {
        let words: Vec<_> = vector["words"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap() as u16)
            .collect();
        let (instructions, _, _) = fragment(&words, 512, 255, 40).unwrap();
        let item = &instructions[0];
        let expected: Vec<_> = vector["registers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap() as u16)
            .collect();
        assert_eq!(
            item.registers,
            Registers::from(expected.as_slice()),
            "{}",
            vector["id"]
        );
        if let Some(literal) = vector.get("literal") {
            assert_eq!(
                item.literal.as_ref().unwrap().signed_decimal,
                SignedDecimal(literal.as_str().unwrap().parse::<i64>().unwrap())
            );
        }
        for (field, kind) in [
            ("method_idx", ReferenceKind::Method),
            ("prototype_idx", ReferenceKind::Prototype),
            ("call_site_idx", ReferenceKind::CallSite),
        ] {
            if let Some(index) = vector.get(field) {
                assert!(
                    item.references
                        .iter()
                        .any(|r| r.kind == kind
                            && u64::from(r.local_index) == index.as_u64().unwrap())
                );
            }
        }
        if vector["id"] == "custom-not-ordinary" {
            assert_eq!(item.invoke_kind, Some(InvokeKind::Custom));
            assert!(
                !item
                    .references
                    .iter()
                    .any(|r| r.kind == ReferenceKind::Method)
            );
        }
    }
    let (ordinary, _, _) = fragment(&[0x106e, 3, 0, 0x000e], 16, 8, 40).unwrap();
    let (range, _, _) = fragment(&[0x0174, 3, 0, 0x000e], 16, 8, 40).unwrap();
    let (poly, _, _) = fragment(&[0x10fa, 3, 0, 4, 0x000e], 16, 8, 40).unwrap();
    let (custom, _, _) = fragment(&[0x01fd, 3, 0, 0x000e], 16, 8, 40).unwrap();
    assert_eq!(ordinary[0].invoke_kind, Some(InvokeKind::Ordinary));
    assert_eq!(range[0].invoke_kind, Some(InvokeKind::OrdinaryRange));
    assert_eq!(poly[0].references.len(), 2);
    assert_eq!(custom[0].invoke_kind, Some(InvokeKind::CustomRange));
    assert_eq!(custom[0].references[0].kind, ReferenceKind::CallSite);
    assert_eq!(
        ordinary[0].references[0].raw_range.byte_offset.0,
        ordinary[0].byte_offset.0 + 2
    );
    assert_eq!(ordinary[0].references[0].raw_range.byte_length.0, 2);
    assert_eq!(
        poly[0].references[1].raw_range.byte_offset.0,
        poly[0].byte_offset.0 + 6
    );
    assert_eq!(poly[0].references[1].raw_range.byte_length.0, 2);
    let (jumbo, _, _) = fragment(&[0x001b, 7, 0, 0x000e], 16, 8, 40).unwrap();
    assert_eq!(
        jumbo[0].references[0].raw_range.byte_offset.0,
        jumbo[0].byte_offset.0 + 2
    );
    assert_eq!(jumbo[0].references[0].raw_range.byte_length.0, 4);
    let (poly_range, _, _) = fragment(&[0x01fb, 3, 0, 4, 0x000e], 16, 8, 40).unwrap();
    assert_eq!(
        poly_range[0].references[1].raw_range.byte_offset.0,
        poly_range[0].byte_offset.0 + 6
    );
}

#[test]
fn malformed_width_register_wide_range_branch_payload_and_index_cases_fail() {
    let cases: Vec<(&[u16], u16, u16)> = vec![
        (&[0x0090], 16, 16),
        (&[0x010e], 16, 16),
        (&[0x1001, 0x000e], 1, 16),
        (&[0x0116, 0, 0x000e], 2, 16),
        (&[0x0274, 0, 0xffff, 0x000e], u16::MAX, 16),
        (&[0x606e, 0, 0, 0x000e], 16, 16),
        (&[0x006e, 0, 0, 0x000e], 16, 16),
        (&[0x106e, 0, 0, 0x000e], 16, 0),
        (&[0x0228, 0x0014, 0, 0, 0x000e], 16, 16),
        (&[0x7f28], 16, 16),
        (&[0x000e, 0x0300, 1, 1, 0, 0], 16, 16),
        (&[0x0026, 3, 0, 0x000e], 16, 16),
        (&[0x002b, 4, 0, 0x000e, 0x0300, 1, 1, 0, 0], 16, 16),
        (
            &[0x002c, 4, 0, 0x000e, 0x0200, 2, 3, 0, 1, 0, 3, 0, 3, 0],
            16,
            16,
        ),
        (&[0x000e, 0, 0x0300, 3, 1, 0, 0], 16, 16),
        (&[0x0428, 0x000e, 0, 0, 0x0300, 1, 1, 0, 0], 16, 16),
        (&[0x0400], 16, 16),
    ];
    for (words, registers, outs) in cases {
        let error = fragment(words, registers, outs, 40).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidInput, "{words:?}: {error}");
        assert_eq!(error.details["facts_layer"], "code_layout");
    }
    for words in [
        &[0x001a, 16, 0x000e][..],
        &[0x001c, 16, 0x000e],
        &[0x0052, 16, 0x000e],
        &[0x106e, 16, 0, 0x000e],
        &[0x00ff, 16, 0x000e],
        &[0x10fc, 16, 0, 0x000e],
        &[0x00fe, 16, 0x000e],
    ] {
        assert_eq!(
            fragment(words, 16, 16, 40).unwrap_err().details["reason"],
            "INSTRUCTION_REFERENCE_OUT_OF_RANGE"
        );
    }
    assert!(fragment(&[0x10fa, 0, 0, 0, 0x000e], 16, 16, 37).is_err());
    assert!(fragment(&[0x00fe, 0, 0x000e], 16, 16, 38).is_err());
    for version in [35, 37, 38, 39, 40] {
        assert!(fragment(&[0x000e], 0, 0, version).is_ok());
    }
}

#[test]
fn full_map_includes_unreferenced_code_and_offsets_have_explicit_narrow_scope() {
    let bytes = fixture("unreferenced-two-code.dex");
    let header = crate::validate_header(&bytes).unwrap();
    let all = read_code_section(&bytes, &header, CodeLimits::default()).unwrap();
    assert_eq!(all.declared_code_item_count, 2);
    assert_eq!(all.items.len(), 2);
    assert_eq!(all.items[0].raw_range.byte_offset, DecimalU64(112));
    assert_eq!(all.items[1].raw_range.byte_offset, DecimalU64(132));
    assert!(all.items[1].debug_info.is_some());
    let selected =
        read_code_offsets(&bytes, &header, &[132, 112, 132], CodeLimits::default()).unwrap();
    assert!(selected.scope.starts_with("explicit-code-offsets"));
    assert_eq!(
        selected
            .items
            .iter()
            .map(|i| i.raw_range.byte_offset.0)
            .collect::<Vec<_>>(),
        [132, 112, 132]
    );
    assert!(read_code_offsets(&bytes, &header, &[114], CodeLimits::default()).is_err());
    assert!(!all.full_dex_validation_complete);
    for version in [b"035", b"037", b"038", b"039", b"040"] {
        let mut variant = bytes.clone();
        variant[4..7].copy_from_slice(version);
        resign(&mut variant);
        let parsed = parse_file(&variant).unwrap();
        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.items[0].insns_range.byte_length, DecimalU64(2));
    }
    for version in [b"036", b"041"] {
        let mut variant = bytes.clone();
        variant[4..7].copy_from_slice(version);
        resign(&mut variant);
        assert_eq!(
            parse_file(&variant).unwrap_err().code,
            ErrorCode::UnsupportedCapability
        );
    }
    for name in ["bad-reserved-opcode.dex", "bad-truncated-wide.dex"] {
        assert_eq!(
            parse_file(&fixture(name)).unwrap_err().code,
            ErrorCode::InvalidInput
        );
    }
}

#[test]
fn payload_units_raw_ranges_targets_and_repetition_are_exact() {
    let packed = parse_file(&fixture("packed-switch.dex")).unwrap();
    let item = &packed.items[0];
    assert_eq!(item.insns_size_code_units, 10);
    assert_eq!(item.instructions.len(), 2);
    assert_eq!(item.payloads[0].code_unit_offset, 4);
    assert_eq!(item.payloads[0].width_code_units, 6);
    assert_eq!(item.switch_targets[0].target_code_units, [3]);
    assert_eq!(item.instructions[1].instruction_ordinal, 1);
    assert_eq!(item.instructions[1].code_unit_offset, 3);
    assert_eq!(item.instructions[1].byte_offset, DecimalU64(134));
    let sparse = parse_file(&fixture("sparse-switch.dex")).unwrap();
    assert_eq!(sparse.items[0].switch_targets[0].target_code_units, [3, 3]);
    let array = parse_file(&fixture("fill-array.dex")).unwrap();
    if let PayloadData::FillArray {
        element_count,
        data_range,
        ..
    } = &array.items[0].payloads[0].data
    {
        assert_eq!(*element_count, 3);
        assert_eq!(data_range.byte_length, DecimalU64(3));
        assert_eq!(
            &fixture("fill-array.dex")
                [data_range.byte_offset.0 as usize..(data_range.byte_offset.0 + 3) as usize],
            &[1, 2, 3]
        );
    } else {
        panic!("wrong payload type");
    }
    let (_, _, switches) = fragment(
        &[0, 0, 0x002b, 4, 0, 0x000e, 0x0100, 1, 0, 0, 3, 0],
        16,
        16,
        40,
    )
    .unwrap();
    assert_eq!(switches[0].target_code_units, [5]);
    let (backward, _, _) = fragment(&[0, 0, 0xfe28], 16, 16, 40).unwrap();
    assert_eq!(backward[2].branch_target_code_units, Some(0));
}

#[test]
fn tries_padding_handler_origin_and_catch_all_targets_are_bounded() {
    let original = fixture("try-catch-all.dex");
    let section = parse_file(&original).unwrap();
    let item = &section.items[0];
    assert_eq!(item.tries[0].start_code_unit, 0);
    assert_eq!(item.handlers[0].relative_byte_offset, 1);
    assert_eq!(item.handlers[0].catch_all_address_code_units, Some(1));
    assert_eq!(item.insns_range.byte_length, DecimalU64(6));
    assert_eq!(item.raw_range.byte_length, DecimalU64(35));
    for (offset, value) in [(134, 1u8), (142, 0), (140, 4), (146, 3)] {
        let mut bytes = original.clone();
        bytes[offset] = value;
        resign(&mut bytes);
        assert!(crate::validate_header(&bytes).is_ok());
        assert!(parse_file(&bytes).is_err(), "mutant at {offset}");
    }
}

#[test]
fn debug_all_opcodes_no_index_and_pc_line_register_failures_are_visible() {
    let original = fixture("all-debug-opcodes.dex");
    let section = parse_file(&original).unwrap();
    let debug = section.items[0].debug_info.as_ref().unwrap();
    assert_eq!(debug.initial_line, 2);
    assert!(debug.parameter_name_indices.is_empty());
    let ops: BTreeSet<_> = debug.events.iter().map(|e| e.opcode).collect();
    for op in 0..=9 {
        assert!(ops.contains(&op));
    }
    assert!(
        debug
            .events
            .iter()
            .any(|e| e.emits_position && e.address_code_units == 0 && encoded_text(e) == "1")
    );
    assert!(
        debug
            .events
            .iter()
            .filter(|e| matches!(e.opcode, 3 | 4))
            .all(|e| e.name_idx.is_none() && e.type_idx.is_none())
    );
    let at = debug.raw_range.byte_offset.0 as usize;
    for (relative, value) in [(7usize, 1u8), (3, 2), (8, 1)] {
        let mut bytes = original.clone();
        bytes[at + relative] = value;
        resign(&mut bytes);
        assert!(crate::validate_header(&bytes).is_ok());
        if relative == 3 {
            assert!(parse_file(&bytes).is_ok());
            assert_eq!(
                parse_file_policy(&bytes, DebugPolicy::StrictSourceLinesV1)
                    .unwrap_err()
                    .code,
                ErrorCode::IncompleteFacts
            );
        } else {
            assert!(parse_file(&bytes).is_err(), "debug mutant {relative}");
        }
    }
    let header = crate::validate_header(&original).unwrap();
    let limits = CodeLimits {
        max_debug_operations: 0,
        ..CodeLimits::default()
    };
    assert_eq!(
        read_code_section(&original, &header, limits)
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
}

#[test]
fn limits_are_cumulative_and_zero_never_means_unlimited() {
    let bytes = fixture("unreferenced-two-code.dex");
    let header = crate::validate_header(&bytes).unwrap();
    for limits in [
        CodeLimits {
            max_code_items: 1,
            ..CodeLimits::default()
        },
        CodeLimits {
            max_total_code_units: 1,
            ..CodeLimits::default()
        },
        CodeLimits {
            max_instructions: 1,
            ..CodeLimits::default()
        },
    ] {
        assert_eq!(
            read_code_section(&bytes, &header, limits).unwrap_err().code,
            ErrorCode::QuotaExceeded
        );
    }
    let bytes = fixture("try-catch-all.dex");
    let header = crate::validate_header(&bytes).unwrap();
    assert_eq!(
        read_code_section(
            &bytes,
            &header,
            CodeLimits {
                max_catch_pairs: 0,
                ..CodeLimits::default()
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::QuotaExceeded
    );
    let bytes = fixture("packed-switch.dex");
    let header = crate::validate_header(&bytes).unwrap();
    assert_eq!(
        read_code_section(
            &bytes,
            &header,
            CodeLimits {
                max_payload_elements: 0,
                ..CodeLimits::default()
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::QuotaExceeded
    );
}

#[test]
fn shared_payload_expansion_and_duplicate_offset_projection_each_consume_budget() {
    let words = [
        0x002b, 8, 0, 0x002b, 5, 0, 0x000e, 0x000e, 0x0100, 1, 0, 0, 3, 0,
    ];
    let limits = CodeLimits {
        max_payload_elements: 1,
        max_switch_targets: 1,
        ..CodeLimits::default()
    };
    let error = decode::decode(
        &words,
        DecodeContext {
            base: 128,
            registers: 1,
            outs: 0,
            counts: counts(),
            version: 40,
            limits,
        },
        &mut Used::default(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert_eq!(error.details["budget"], "max_switch_targets");
    assert_eq!(error.details["observed"], "2");
    let bytes = fixture("unreferenced-two-code.dex");
    let header = crate::validate_header(&bytes).unwrap();
    for limits in [
        CodeLimits {
            max_code_items: 3,
            max_total_code_units: 2,
            ..CodeLimits::default()
        },
        CodeLimits {
            max_code_items: 3,
            max_instructions: 2,
            ..CodeLimits::default()
        },
    ] {
        let error = read_code_offsets(&bytes, &header, &[112, 112, 112], limits).unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
        assert_eq!(error.details["observed"], "3");
    }
}

#[test]
fn debug_references_must_name_physical_item_starts_and_outs_layout_is_checked() {
    let mut bytes = fixture("unreferenced-two-code.dex");
    bytes[140..144].copy_from_slice(&151u32.to_le_bytes());
    resign(&mut bytes);
    let header = crate::validate_header(&bytes).unwrap();
    let error = read_code_section(&bytes, &header, CodeLimits::default()).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert_eq!(error.details["reason"], "DEBUG_OFFSET_NOT_ITEM_START");
    assert_eq!(error.details["code_item_byte_offset"], "132");
    assert_eq!(error.details["debug_info_byte_offset"], "151");
    let mut bytes = fixture("unreferenced-two-code.dex");
    bytes[116..118].copy_from_slice(&6u16.to_le_bytes());
    resign(&mut bytes);
    assert_eq!(
        parse_file(&bytes).unwrap_err().details["reason"],
        "OUTS_EXCEEDS_REGISTER_LAYOUT"
    );
    bytes[116..118].copy_from_slice(&5u16.to_le_bytes());
    resign(&mut bytes);
    assert!(parse_file(&bytes).is_ok());
    for opcode in [0x0025, 0x0077, 0x00fd] {
        assert_eq!(
            fragment(&[opcode, 0, 0xffff, 0x000e], 0, 0, 40)
                .unwrap_err()
                .details["reason"],
            "REGISTER_RANGE_OUT_OF_BOUNDS"
        );
        assert!(fragment(&[opcode, 0, 0, 0x000e], 0, 0, 40).is_ok());
    }
}

#[test]
fn debug_state_only_operations_and_try_ends_preserve_format_permitted_positions() {
    for opcode in [7, 8, 9] {
        let section =
            parse_file(&fixture(&format!("debug-intermediate-state-{opcode}.dex"))).unwrap();
        let events = &section.items[0].debug_info.as_ref().unwrap().events;
        assert!(
            events
                .iter()
                .any(|e| e.opcode == opcode && e.address_code_units == 1 && !e.emits_position)
        );
        assert!(
            events
                .iter()
                .any(|e| e.emits_position && e.address_code_units == 3 && encoded_text(e) == "1")
        );
    }
    let section = parse_file(&fixture("try-end-inside-instruction.dex")).unwrap();
    assert_eq!(section.items[0].instructions[0].width_code_units, 3);
    assert_eq!(section.items[0].tries[0].code_unit_count, 1);
    for name in [
        "bad-debug-initial-zero.dex",
        "bad-debug-advance-zero.dex",
        "bad-debug-special-negative.dex",
    ] {
        let bytes = fixture(name);
        assert!(parse_file(&bytes).is_ok());
        let error = parse_file_policy(&bytes, DebugPolicy::StrictSourceLinesV1).unwrap_err();
        assert_eq!(error.code, ErrorCode::IncompleteFacts);
        assert_eq!(
            error.details["reason"], "DEBUG_LINE_LESS_THAN_ONE",
            "{name}"
        );
    }
    assert!(parse_file(&fixture("bad-debug-missing-end.dex")).is_err());
}

#[test]
fn shared_pc_to_pc_pattern_keeps_complete_raw_events_and_explicit_method_projection() {
    for base in [0, 1] {
        let bytes = fixture(&format!("pc-to-pc-shared-base-{base}.dex"));
        let section = parse_file(&bytes).unwrap();
        assert_eq!(section.items.len(), 2);
        let short = section.items[0].debug_info.as_ref().unwrap();
        let longer = section.items[1].debug_info.as_ref().unwrap();
        assert!(matches!(
            short.representation,
            DebugRepresentation::PcToPcPattern
        ));
        assert_eq!(short.raw_range.byte_offset, longer.raw_range.byte_offset);
        assert_eq!(short.raw_range.byte_length, longer.raw_range.byte_length);
        assert_eq!(short.events.len(), 7);
        assert_eq!(longer.events.len(), 7);
        assert_eq!(short.raw_position_count, DecimalU64(6));
        assert_eq!(short.applicable_method_position_count, DecimalU64(1));
        assert_eq!(longer.applicable_method_position_count, DecimalU64(4));
        assert_eq!(
            short
                .method_positions()
                .map(|e| e.address_code_units)
                .collect::<Vec<_>>(),
            [0]
        );
        assert_eq!(
            longer
                .method_positions()
                .map(|e| e.address_code_units)
                .collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        assert_eq!(
            short.events.get(0).unwrap().code_item_address_scope,
            DebugAddressScope::InsideCodeUnits
        );
        assert_eq!(
            short.events.get(1).unwrap().code_item_address_scope,
            DebugAddressScope::AtCodeEnd
        );
        assert_eq!(
            short.events.get(2).unwrap().code_item_address_scope,
            DebugAddressScope::BeyondCodeEnd
        );
        assert_eq!(short.events.get(5).unwrap().address_code_units, 5);
        assert_eq!(
            encoded_text(short.events.get(5).unwrap()),
            (5 + base).to_string()
        );
        let header = crate::validate_header(&bytes).unwrap();
        let error = read_code_section(
            &bytes,
            &header,
            CodeLimits {
                max_debug_operations: 10,
                ..CodeLimits::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::QuotaExceeded);
    }
    let wide = parse_file(&fixture("debug-line-u32max.dex")).unwrap();
    assert_eq!(
        encoded_text(
            wide.items[0]
                .debug_info
                .as_ref()
                .unwrap()
                .events
                .get(0)
                .unwrap()
        ),
        "4294967295"
    );
    for (name, reason) in [
        ("bad-debug-line-overflow.dex", "DEBUG_LINE_OVERFLOW"),
        (
            "bad-debug-parameter-count.dex",
            "DEBUG_PARAMETER_COUNT_EXCEEDS_FORMAT",
        ),
    ] {
        assert_eq!(
            parse_file(&fixture(name)).unwrap_err().details["reason"],
            reason
        );
    }
    let bytes = fixture("bad-debug-nonpattern-shared-suffix.dex");
    assert!(parse_file(&bytes).is_ok());
    assert_eq!(
        parse_file_policy(&bytes, DebugPolicy::StrictSourceLinesV1)
            .unwrap_err()
            .code,
        ErrorCode::IncompleteFacts
    );
}

#[test]
fn encoded_unknown_source_lines_are_retained_and_strict_source_policy_still_fails() {
    let bytes = fixture("debug-observed-zero-source-line.dex");
    let section = parse_file(&bytes).unwrap();
    let debug = section.items[0].debug_info.as_ref().unwrap();
    assert_eq!(debug.debug_policy, DebugPolicy::EncodedFactsV1);
    assert!(!debug.strict_positive_line_policy_satisfied);
    let zero = debug
        .events
        .iter()
        .find(|event| event.emits_position && event.address_code_units == 18)
        .unwrap();
    assert_eq!(encoded_text(zero.clone()), "0");
    assert_eq!(zero.source_line, None);
    assert!(!zero.source_line_usable);
    assert_eq!(zero.source_line_kind, SourceLineKind::UnknownNonPositive);
    let restored = debug
        .events
        .iter()
        .find(|event| event.emits_position && event.address_code_units == 34)
        .unwrap();
    assert_eq!(encoded_text(restored.clone()), "32");
    assert_eq!(restored.source_line, Some(DecimalU64(32)));
    assert!(restored.source_line_usable);
    assert_eq!(debug.unusable_method_source_position_count, DecimalU64(1));
    assert_eq!(debug.method_positions().count(), 12);
    assert_eq!(debug.usable_source_positions().count(), 11);
    let error = parse_file_policy(&bytes, DebugPolicy::StrictSourceLinesV1).unwrap_err();
    assert_eq!(error.code, ErrorCode::IncompleteFacts);
    assert_eq!(error.stage, "debug.source_line_policy");
    assert_eq!(error.details["encoded_debug_complete"], true);
    assert_eq!(error.details["facts_layer"], "source_positions");
    for base in [0, 1] {
        let bytes = fixture(&format!("pc-to-pc-shared-base-{base}.dex"));
        let parsed = parse_file(&bytes).unwrap();
        let debug = parsed.items[0].debug_info.as_ref().unwrap();
        assert!(
            debug
                .events
                .iter()
                .filter(|event| event.emits_position)
                .all(|event| !event.source_line_usable
                    && event.source_line.is_none()
                    && event.source_line_kind == SourceLineKind::PcSurrogate)
        );
        assert_eq!(
            parse_file_policy(&bytes, DebugPolicy::StrictSourceLinesV1)
                .unwrap_err()
                .code,
            ErrorCode::IncompleteFacts
        );
    }
    let positive = fixture("all-debug-opcodes.dex");
    let strict = parse_file_policy(&positive, DebugPolicy::StrictSourceLinesV1).unwrap();
    assert!(
        strict.items[0]
            .debug_info
            .as_ref()
            .unwrap()
            .strict_positive_line_policy_satisfied
    );
}

/// Build a minimal valid DEX where every code item names one shared debug program.
///
/// The layout mirrors `tests/fixtures/instructions/generate.py`: code items at
/// 112, the debug program after them, then a map list. Building the fixture in the
/// test keeps an editorial fixture change from silently weakening the memoization
/// checks below. The fixture declares no string_ids, so the debug program must not
/// carry named parameters; the position opcode `0x1e` still advances pc and line.
fn synthetic_dex(items: &[(u16, Vec<u16>)], debug: &[u8]) -> Vec<u8> {
    let mut offsets = Vec::new();
    let mut at = 112usize;
    for (_, units) in items {
        while !at.is_multiple_of(4) {
            at += 1;
        }
        offsets.push(at);
        at += 16 + units.len() * 2;
    }
    let debug_offset = at;
    let mut body: Vec<u8> = Vec::new();
    for ((registers, units), offset) in items.iter().zip(&offsets) {
        while 112 + body.len() < *offset {
            body.push(0);
        }
        assert_eq!(112 + body.len(), *offset);
        body.extend_from_slice(&registers.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&(debug_offset as u32).to_le_bytes());
        body.extend_from_slice(&(units.len() as u32).to_le_bytes());
        for unit in units {
            body.extend_from_slice(&unit.to_le_bytes());
        }
    }
    while 112 + body.len() < debug_offset {
        body.push(0);
    }
    body.extend_from_slice(debug);
    while !(112 + body.len()).is_multiple_of(4) {
        body.push(0);
    }
    let map_at = 112 + body.len();
    let entries = [
        (0u16, 1u32, 0u32),
        (0x2001, items.len() as u32, offsets[0] as u32),
        (0x2003, 1, debug_offset as u32),
        (0x1000, 1, map_at as u32),
    ];
    body.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (kind, count, offset) in entries {
        body.extend_from_slice(&kind.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&count.to_le_bytes());
        body.extend_from_slice(&offset.to_le_bytes());
    }
    let mut bytes = vec![0u8; 112];
    bytes.extend_from_slice(&body);
    bytes[..8].copy_from_slice(b"dex\n040\0");
    let file_size = bytes.len() as u32;
    bytes[32..36].copy_from_slice(&file_size.to_le_bytes());
    bytes[36..40].copy_from_slice(&112u32.to_le_bytes());
    bytes[40..44].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    bytes[52..56].copy_from_slice(&(map_at as u32).to_le_bytes());
    let data_size = (file_size - 112) as u32;
    bytes[104..108].copy_from_slice(&data_size.to_le_bytes());
    bytes[108..112].copy_from_slice(&112u32.to_le_bytes());
    resign(&mut bytes);
    bytes
}

#[test]
fn shared_debug_program_is_decoded_once_and_reprojected_per_code_item() {
    // One program, three code items with different register counts and code
    // sizes. The program is decoded once; size-dependent projections stay item
    // scoped. The leading `0x1e` keeps the program out of the pc-to-pc pattern,
    // so the ordinary encoded-line classification applies.
    let debug = [1u8, 0, 0x1e, 0x1e, 0x1e, 0];
    let bytes = synthetic_dex(
        &[
            (1, vec![0x000e]),
            (3, vec![0x000e, 0x000e]),
            (4, vec![0x0014, 0, 0, 0x000e]),
        ],
        &debug,
    );
    let header = crate::validate_header(&bytes).unwrap();
    super::debug::program_decode_count::reset();
    let section = read_code_section(&bytes, &header, CodeLimits::default()).unwrap();
    // Three code items name the same physical program, so it must be decoded
    // exactly once. Without this assertion the memoization could be deleted and
    // every output check above would still pass.
    assert_eq!(super::debug::program_decode_count::get(), 1);
    assert_eq!(section.items.len(), 3);
    let debug_a = section.items[0].debug_info.as_ref().unwrap();
    let debug_b = section.items[1].debug_info.as_ref().unwrap();
    let debug_c = section.items[2].debug_info.as_ref().unwrap();
    for debug in [debug_a, debug_b, debug_c] {
        assert_eq!(debug.events.len(), 4);
        assert_eq!(debug.raw_range.byte_offset, debug_a.raw_range.byte_offset);
        assert_eq!(debug.raw_range.byte_length, debug_a.raw_range.byte_length);
        assert_eq!(debug.initial_line, 1);
        assert!(debug.parameter_name_indices.is_empty());
        assert!(matches!(
            debug.representation,
            DebugRepresentation::EventProgram
        ));
        assert_eq!(debug.raw_position_count, DecimalU64(3));
    }
    // Sizes 1, 2 and 4 keep each item's own address scopes and usable counts.
    assert_eq!(debug_a.referring_code_unit_length, 1);
    assert_eq!(debug_b.referring_code_unit_length, 2);
    assert_eq!(debug_c.referring_code_unit_length, 4);
    let scopes = |debug: &DebugInfo| {
        debug
            .events
            .iter()
            .map(|event| event.code_item_address_scope)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        scopes(debug_a),
        [
            DebugAddressScope::AtCodeEnd,
            DebugAddressScope::BeyondCodeEnd,
            DebugAddressScope::BeyondCodeEnd,
            DebugAddressScope::BeyondCodeEnd,
        ]
    );
    assert_eq!(
        scopes(debug_b),
        [
            DebugAddressScope::InsideCodeUnits,
            DebugAddressScope::AtCodeEnd,
            DebugAddressScope::BeyondCodeEnd,
            DebugAddressScope::BeyondCodeEnd,
        ]
    );
    assert_eq!(scopes(debug_c), [DebugAddressScope::InsideCodeUnits; 4]);
    assert_eq!(debug_a.applicable_method_position_count, DecimalU64(0));
    assert_eq!(debug_b.applicable_method_position_count, DecimalU64(1));
    assert_eq!(debug_c.applicable_method_position_count, DecimalU64(3));
    assert_eq!(debug_c.usable_method_source_position_count, DecimalU64(3));
    assert_eq!(debug_b.usable_method_source_position_count, DecimalU64(1));
    assert_eq!(debug_a.usable_method_source_position_count, DecimalU64(0));
    assert_eq!(debug_a.unusable_method_source_position_count, DecimalU64(0));
    // `DEBUG_PC_OUTSIDE_CODE` depends on the item's size even though pc comes from
    // the shared program, so a code unit still outside the item fails the policy.
    // The memo is per `read_code_section` call, so this fresh call decodes once.
    super::debug::program_decode_count::reset();
    let error = read_code_section(
        &bytes,
        &header,
        CodeLimits {
            debug_policy: DebugPolicy::StrictSourceLinesV1,
            ..CodeLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::IncompleteFacts);
    assert_eq!(error.details["reason"], "DEBUG_PC_OUTSIDE_CODE");
    // One decode for this call too, even though it aborts on the first item.
    assert_eq!(super::debug::program_decode_count::get(), 1);
    assert_eq!(
        error.details["byte_offset"],
        debug_a.events.get(1).unwrap().byte_offset.0.to_string()
    );
}

#[test]
fn reused_debug_program_still_reports_the_first_register_violation_per_item() {
    // Register 2 is declared by the program and rejected by the item that only
    // declares one register. The span still covers opcode byte plus register LEB.
    let debug = [1u8, 0, 5, 2, 0];
    let bytes = synthetic_dex(&[(1, vec![0x000e])], &debug);
    let header = crate::validate_header(&bytes).unwrap();
    let error = read_code_section(&bytes, &header, CodeLimits::default()).unwrap_err();
    assert_eq!(error.details["reason"], "DEBUG_REGISTER_OUT_OF_RANGE");
    assert_eq!(error.details["byte_length"], "2");
    assert_eq!(error.details["code_item_byte_offset"], "112");
    // The same program parses once the item declares enough registers, and the
    // second item proves the program was reusable rather than rejected outright.
    let widened = synthetic_dex(&[(4, vec![0x000e]), (4, vec![0x000e])], &debug);
    let header = crate::validate_header(&widened).unwrap();
    let parsed = read_code_section(&widened, &header, CodeLimits::default()).unwrap();
    assert_eq!(parsed.items.len(), 2);
    for item in &parsed.items {
        let debug = item.debug_info.as_ref().unwrap();
        assert_eq!(debug.events.len(), 2);
        assert_eq!(debug.events.get(0).unwrap().register, Some(2));
        assert!(!debug.events.get(0).unwrap().emits_position);
    }
}

#[test]
fn shared_debug_events_project_per_code_item_without_copying_the_program() {
    // Three items share one program. Every item must reference the same decoded
    // program (so the event sequence is stored once) while still observing its own
    // size-dependent projection. Without the sharing assertion a future refactor
    // could decode or store one sequence per code item and every output check
    // would still pass.
    let debug = [1u8, 0, 0x1e, 0x1e, 0x1e, 0];
    let short = vec![0x000e];
    let long = vec![0x0014, 0, 0, 0x000e];
    let bytes = synthetic_dex(&[(2, short.clone()), (2, long.clone()), (2, short)], &debug);
    let header = crate::validate_header(&bytes).unwrap();
    super::debug::events_materialize_count::reset();
    let section = read_code_section(&bytes, &header, CodeLimits::default()).unwrap();
    assert_eq!(section.items.len(), 3);
    // A successful attach never builds an owned vector: the events stay in the
    // shared program and are projected on demand.
    assert_eq!(super::debug::events_materialize_count::get(), 0);

    let a = section.items[0].debug_info.as_ref().unwrap();
    let b = section.items[1].debug_info.as_ref().unwrap();
    let c = section.items[2].debug_info.as_ref().unwrap();
    let program_of = |debug: &DebugInfo| match &debug.events {
        DebugEvents::Shared(shared) => shared.program_id(),
        DebugEvents::Owned(_) => panic!("a memoized program must stay shared"),
    };
    assert_eq!(program_of(a), program_of(b));
    assert_eq!(program_of(a), program_of(c));
    // All three still see the same complete physical program.
    for debug in [a, b, c] {
        assert_eq!(debug.events.len(), 4);
        assert_eq!(debug.raw_position_count, DecimalU64(3));
    }
    // Sharing must not collapse genuinely different projections: the same events
    // are classified against each item's own code size.
    assert_eq!(a.referring_code_unit_length, 1);
    assert_eq!(b.referring_code_unit_length, 4);
    assert_eq!(
        a.events
            .iter()
            .map(|event| event.code_item_address_scope)
            .collect::<Vec<_>>(),
        [
            DebugAddressScope::AtCodeEnd,
            DebugAddressScope::BeyondCodeEnd,
            DebugAddressScope::BeyondCodeEnd,
            DebugAddressScope::BeyondCodeEnd,
        ]
    );
    // The four-code-unit item contains all three emitted positions.
    assert_eq!(
        b.events
            .iter()
            .map(|event| event.code_item_address_scope)
            .collect::<Vec<_>>(),
        [DebugAddressScope::InsideCodeUnits; 4]
    );
    assert_eq!(b.applicable_method_position_count, DecimalU64(3));
    assert_eq!(b.usable_method_source_position_count, DecimalU64(3));
    // Item C has the same size as A, so its projection must match A's exactly
    // while still sharing one program.
    assert_eq!(
        c.events
            .iter()
            .map(|event| event.code_item_address_scope)
            .collect::<Vec<_>>(),
        a.events
            .iter()
            .map(|event| event.code_item_address_scope)
            .collect::<Vec<_>>()
    );
    assert_eq!(c.applicable_method_position_count, DecimalU64(0));
    assert_eq!(a.applicable_method_position_count, DecimalU64(0));
}

#[test]
fn reused_debug_program_replays_debug_operation_charges_per_code_item() {
    // Three items share one program worth four operations (no parameters, four
    // events). The physical scan charges four once; every item then replays four.
    // A budget admitting the scan plus two replays must fail on the third item,
    // which only holds if cache hits keep charging instead of skipping the work.
    let debug = [1u8, 0, 0x1e, 0x1e, 0x1e, 0];
    let units = vec![0x0014, 0, 0, 0x000e];
    let bytes = synthetic_dex(
        &[(2, units.clone()), (2, units.clone()), (2, units)],
        &debug,
    );
    let header = crate::validate_header(&bytes).unwrap();
    let per_item = 4u64;
    let limit = per_item * 3;
    let error = read_code_section(
        &bytes,
        &header,
        CodeLimits {
            max_debug_operations: limit,
            ..CodeLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert_eq!(error.details["budget"], "max_debug_operations");
    assert_eq!(error.details["observed"], (limit + 1).to_string());
    // A budget covering the scan and all three replays succeeds.
    let exact = read_code_section(
        &bytes,
        &header,
        CodeLimits {
            max_debug_operations: per_item * 4,
            ..CodeLimits::default()
        },
    )
    .unwrap();
    assert_eq!(exact.items.len(), 3);
}

#[test]
fn signed_decimal_round_trips_the_canonical_text_form_only() {
    for value in [
        0i64,
        1,
        -1,
        32,
        -4,
        i64::from(u32::MAX),
        i64::from(i32::MIN),
        // The stack buffer is sized for `i64::MIN`'s 20-character form, so the
        // extreme values are exactly the ones that would catch an off-by-one.
        i64::MIN,
        i64::MAX,
    ] {
        let text = serde_json::to_string(&SignedDecimal(value)).unwrap();
        assert_eq!(text, format!("\"{value}\""), "{value}");
        let restored: SignedDecimal = serde_json::from_str(&text).unwrap();
        assert_eq!(restored, SignedDecimal(value));
    }
    for rejected in [
        "\"+1\"", "\"-0\"", "\"01\"", "\"\"", "\"1.0\"", "\" 1\"", "1",
    ] {
        assert!(
            serde_json::from_str::<SignedDecimal>(rejected).is_err(),
            "{rejected} must be rejected"
        );
    }
}

#[test]
fn shared_debug_program_never_reuses_a_failed_decode_across_items() {
    // Two code items name one program: initial line at u32::MAX, a register
    // event, then a line delta that overflows. Item A (1 register) must report
    // the register error; item B (4 registers) must reach the line overflow.
    // Caching the failed decode per offset would hand B item A's error, so the
    // cache only stores successful programs and both items re-walk the original
    // interleaved path.
    let mut debug = vec![0xFFu8, 0xFF, 0xFF, 0xFF, 0x0F, 0, 5, 2, 2, 1, 0];
    let mixed = synthetic_dex(&[(1, vec![0x000e]), (4, vec![0x000e])], &debug);
    let header = crate::validate_header(&mixed).unwrap();
    let error = read_code_section(&mixed, &header, CodeLimits::default()).unwrap_err();
    assert_eq!(error.details["reason"], "DEBUG_REGISTER_OUT_OF_RANGE");
    assert_eq!(error.details["code_item_byte_offset"], "112");

    // Reversing the item order exposes the other error first, proving the result
    // follows the item, not a cached per-offset outcome.
    let reversed = synthetic_dex(&[(4, vec![0x000e]), (1, vec![0x000e])], &debug);
    let header = crate::validate_header(&reversed).unwrap();
    let error = read_code_section(&reversed, &header, CodeLimits::default()).unwrap_err();
    assert_eq!(error.details["reason"], "DEBUG_LINE_OVERFLOW");
    assert_eq!(error.details["code_item_byte_offset"], "112");

    // With both items wide enough the line overflow is the only failure, so the
    // program is reported as a program-level error rather than a register one.
    debug[6] = 2;
    let wide = synthetic_dex(&[(4, vec![0x000e]), (4, vec![0x000e])], &debug);
    let header = crate::validate_header(&wide).unwrap();
    let error = read_code_section(&wide, &header, CodeLimits::default()).unwrap_err();
    assert_eq!(error.details["reason"], "DEBUG_LINE_OVERFLOW");
}

#[test]
fn instruction_names_are_borrowed_from_the_static_table() {
    let (instructions, _, _) = fragment(&[0x000e, 0x000e], 16, 16, 40).unwrap();
    for instruction in &instructions {
        assert!(matches!(instruction.mnemonic, Cow::Borrowed(_)));
        assert!(matches!(instruction.format, Cow::Borrowed(_)));
        assert_eq!(instruction.mnemonic.as_ref(), "return-void");
    }
    // Serialization still emits plain strings, not a borrow-shaped object.
    let value = serde_json::to_value(&instructions[0]).unwrap();
    assert_eq!(value["mnemonic"], "return-void");
    assert_eq!(value["format"], "10x");
}

/// `method_field_accesses.using_type` is NULL only for a field-referencing opcode
/// that is neither a get nor a put. This proves there is none: every opcode whose
/// index operand is a field reference is one of the four instance/static
/// get/put families, so the NULL branch of the relation cannot be reached from any
/// instruction this decoder accepts.
#[test]
fn every_field_referencing_opcode_is_a_get_or_a_put() {
    let field_opcodes: Vec<&str> = opcodes::OPCODES
        .iter()
        .filter(|info| info.index == "kIndexFieldRef")
        .map(|info| info.name)
        .collect();
    // 14 instance and 14 static accessors in the DEX instruction set.
    assert_eq!(field_opcodes.len(), 28, "{field_opcodes:?}");
    for name in field_opcodes {
        assert!(
            ["iget", "iput", "sget", "sput"]
                .iter()
                .any(|prefix| name.starts_with(prefix)),
            "{name} references a field but is neither a get nor a put"
        );
    }
    // The converse holds too: no get/put-named opcode skips the field index, so
    // the relation's prefix test sees every one of them.
    for info in opcodes::OPCODES.iter().filter(|info| !info.reserved) {
        let accessor = ["iget", "iput", "sget", "sput"]
            .iter()
            .any(|prefix| info.name.starts_with(prefix));
        assert_eq!(accessor, info.index == "kIndexFieldRef", "{}", info.name);
    }
}
