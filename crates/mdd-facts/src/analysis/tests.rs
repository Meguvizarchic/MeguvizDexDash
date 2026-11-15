//! Tests of the analysis module.
//!
//! The hand fixtures in conformance/analysis/soundness-cases.json are small programs
//! written with labels instead of offsets, each with the result written out by hand.
//! A mini assembler turns them into code units, a synthetic DEX wraps those, and the
//! *real* decoder produces the `CodeItem` the analysis reads - so nothing here feeds the
//! analysis a structure the decoder would not. An independent Python implementation
//! (conformance/analysis/oracle.py) re-derives the same results from the same programs.
use super::*;
use super::{
    cfg::{EdgeKind, Target},
    defuse::Reg,
};
use mdd_dex::instructions::{CodeItem, CodeLimits, read_code_section};
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;

// ---- a mini assembler -----------------------------------------------------------

/// Assembled code units, label positions, tries and the raw handler list.
pub(super) struct Assembled {
    pub units: Vec<u16>,
    pub labels: BTreeMap<String, u32>,
    pub tries: Vec<(u32, u16, u16)>,
    pub handlers: Vec<u8>,
    pub types: u32,
    pub methods: u32,
}

fn int(value: &Value) -> i64 {
    value
        .as_i64()
        .unwrap_or_else(|| panic!("integer expected, got {value}"))
}

fn text(value: &Value) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("string expected, got {value}"))
}

fn reg4(a: i64, b: i64) -> u16 {
    ((a & 15) | ((b & 15) << 4)) as u16
}

/// Width in code units of one op of the program.
fn width(op: &[Value]) -> u32 {
    match text(&op[0]) {
        "label" => 0,
        "nop" | "move" | "move-wide" | "move-object" | "move-result" | "move-result-wide"
        | "move-result-object" | "move-exception" | "return-void" | "return" | "return-wide"
        | "return-object" | "throw" | "const/4" | "neg-int" | "int-to-long" | "array-length"
        | "monitor-enter" | "add-int/2addr" | "add-long/2addr" => 1,
        "const/16" | "goto" | "if-eqz" | "if-nez" | "if-eq" | "if-ne" | "if-lt" | "add-int"
        | "sub-int" | "div-int" | "add-long" | "aget" | "add-int/lit8" => 2,
        "packed-switch" | "sparse-switch" | "invoke-static" | "invoke-virtual" => 3,
        other => panic!("unknown op {other}"),
    }
}

pub(super) fn assemble(program: &[Value], tries: &[Value], types: u32, methods: u32) -> Assembled {
    // Pass 1: positions. Payloads sit where the program puts them, aligned to 4 bytes.
    let mut labels: BTreeMap<String, u32> = BTreeMap::new();
    let mut at = 0u32;
    let mut layout: Vec<(u32, &[Value])> = Vec::new();
    for op in program {
        let op = op.as_array().expect("an op is an array");
        match text(&op[0]) {
            "label" => {
                labels.insert(text(&op[1]).to_owned(), at);
            }
            "packed-payload" | "sparse-payload" => {
                if at % 2 == 1 {
                    layout.push((at, &[]));
                    at += 1;
                }
                layout.push((at, op));
                at += if text(&op[0]) == "packed-payload" {
                    4 + 2 * op[3].as_array().unwrap().len() as u32
                } else {
                    2 + 4 * op[2].as_array().unwrap().len() as u32
                };
            }
            _ => {
                layout.push((at, op));
                at += width(op);
            }
        }
    }
    let target = |label: &Value| -> u32 {
        *labels
            .get(text(label))
            .unwrap_or_else(|| panic!("unknown label {label}"))
    };
    let rel = |pc: u32, label: &Value| -> i64 { i64::from(target(label)) - i64::from(pc) };
    // Pass 2: encode.
    let mut units: Vec<u16> = Vec::new();
    for (pc, op) in layout {
        if op.is_empty() {
            units.push(0); // alignment nop
            continue;
        }
        let a = |i: usize| int(&op[i]);
        let encoded: Vec<u16> = match text(&op[0]) {
            "nop" => vec![0x0000],
            "const/4" => vec![0x12 | (reg4(a(1), a(2)) << 8)],
            "const/16" => vec![0x13 | ((a(1) as u16) << 8), a(2) as u16],
            "move" => vec![0x01 | (reg4(a(1), a(2)) << 8)],
            "move-wide" => vec![0x04 | (reg4(a(1), a(2)) << 8)],
            "move-object" => vec![0x07 | (reg4(a(1), a(2)) << 8)],
            "move-result" => vec![0x0a | ((a(1) as u16) << 8)],
            "move-result-wide" => vec![0x0b | ((a(1) as u16) << 8)],
            "move-result-object" => vec![0x0c | ((a(1) as u16) << 8)],
            "move-exception" => vec![0x0d | ((a(1) as u16) << 8)],
            "return-void" => vec![0x000e],
            "return" => vec![0x0f | ((a(1) as u16) << 8)],
            "return-wide" => vec![0x10 | ((a(1) as u16) << 8)],
            "return-object" => vec![0x11 | ((a(1) as u16) << 8)],
            "throw" => vec![0x27 | ((a(1) as u16) << 8)],
            "monitor-enter" => vec![0x1d | ((a(1) as u16) << 8)],
            "goto" => vec![0x29, rel(pc, &op[1]) as i16 as u16],
            "if-eqz" => vec![0x38 | ((a(1) as u16) << 8), rel(pc, &op[2]) as i16 as u16],
            "if-nez" => vec![0x39 | ((a(1) as u16) << 8), rel(pc, &op[2]) as i16 as u16],
            "if-eq" => vec![
                0x32 | (reg4(a(1), a(2)) << 8),
                rel(pc, &op[3]) as i16 as u16,
            ],
            "if-ne" => vec![
                0x33 | (reg4(a(1), a(2)) << 8),
                rel(pc, &op[3]) as i16 as u16,
            ],
            "if-lt" => vec![
                0x34 | (reg4(a(1), a(2)) << 8),
                rel(pc, &op[3]) as i16 as u16,
            ],
            "packed-switch" | "sparse-switch" => {
                let code = if text(&op[0]) == "packed-switch" {
                    0x2b
                } else {
                    0x2c
                };
                let offset = rel(pc, &op[2]) as i32 as u32;
                vec![
                    code | ((a(1) as u16) << 8),
                    offset as u16,
                    (offset >> 16) as u16,
                ]
            }
            "invoke-static" | "invoke-virtual" => {
                // ["invoke-static", [argument registers], method index]
                let code: u16 = if text(&op[0]) == "invoke-static" {
                    0x71
                } else {
                    0x6e
                };
                let regs: Vec<u16> = op[1]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| int(r) as u16)
                    .collect();
                let get = |n: usize| regs.get(n).copied().unwrap_or(0) & 15;
                vec![
                    code | (((regs.len() as u16) << 4 | get(4)) << 8),
                    int(&op[2]) as u16,
                    get(0) | (get(1) << 4) | (get(2) << 8) | (get(3) << 12),
                ]
            }
            "neg-int" => vec![0x7b | (reg4(a(1), a(2)) << 8)],
            "int-to-long" => vec![0x81 | (reg4(a(1), a(2)) << 8)],
            "array-length" => vec![0x21 | (reg4(a(1), a(2)) << 8)],
            "add-int/2addr" => vec![0xb0 | (reg4(a(1), a(2)) << 8)],
            "add-long/2addr" => vec![0xbb | (reg4(a(1), a(2)) << 8)],
            "add-int" => vec![
                0x90 | ((a(1) as u16) << 8),
                (a(2) as u16) | ((a(3) as u16) << 8),
            ],
            "sub-int" => vec![
                0x91 | ((a(1) as u16) << 8),
                (a(2) as u16) | ((a(3) as u16) << 8),
            ],
            "div-int" => vec![
                0x93 | ((a(1) as u16) << 8),
                (a(2) as u16) | ((a(3) as u16) << 8),
            ],
            "add-long" => vec![
                0x9b | ((a(1) as u16) << 8),
                (a(2) as u16) | ((a(3) as u16) << 8),
            ],
            "aget" => vec![
                0x44 | ((a(1) as u16) << 8),
                (a(2) as u16) | ((a(3) as u16) << 8),
            ],
            "add-int/lit8" => vec![
                0xd8 | ((a(1) as u16) << 8),
                (a(2) as u16) | (((a(3) as i8) as u8 as u16) << 8),
            ],
            "packed-payload" => {
                // ["packed-payload", switch label, first key, [target labels]]
                let base = target(&op[1]);
                let targets = op[3].as_array().unwrap();
                let mut words = vec![0x0100, targets.len() as u16];
                let first = a(2) as i32 as u32;
                words.extend([first as u16, (first >> 16) as u16]);
                for label in targets {
                    let delta = (i64::from(target(label)) - i64::from(base)) as i32 as u32;
                    words.extend([delta as u16, (delta >> 16) as u16]);
                }
                words
            }
            "sparse-payload" => {
                // ["sparse-payload", switch label, [[key, target label]...]]
                let base = target(&op[1]);
                let pairs = op[2].as_array().unwrap();
                let mut words = vec![0x0200, pairs.len() as u16];
                for pair in pairs {
                    let key = int(&pair[0]) as i32 as u32;
                    words.extend([key as u16, (key >> 16) as u16]);
                }
                for pair in pairs {
                    let delta = (i64::from(target(&pair[1])) - i64::from(base)) as i32 as u32;
                    words.extend([delta as u16, (delta >> 16) as u16]);
                }
                words
            }
            other => panic!("unknown op {other}"),
        };
        assert_eq!(
            units.len() as u32,
            pc,
            "layout drifted before {}",
            text(&op[0])
        );
        units.extend(encoded);
    }

    // Tries: {"from": label, "to": label, "catches": [[type_idx, label]...], "catch_all": label?}
    let mut raw: Vec<u8> = Vec::new();
    let uleb = |out: &mut Vec<u8>, mut value: u32| loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    };
    let sleb = |out: &mut Vec<u8>, mut value: i32| loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        if done {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    };
    uleb(&mut raw, tries.len() as u32);
    let mut try_items = Vec::new();
    for item in tries {
        let from = target(&item["from"]);
        let to = target(&item["to"]);
        let handler_offset = raw.len() as u16;
        let catches = item["catches"].as_array().cloned().unwrap_or_default();
        let catch_all = item.get("catch_all").filter(|v| !v.is_null());
        let size = catches.len() as i32;
        sleb(&mut raw, if catch_all.is_some() { -size } else { size });
        for pair in &catches {
            uleb(&mut raw, int(&pair[0]) as u32);
            uleb(&mut raw, target(&pair[1]));
        }
        if let Some(label) = catch_all {
            uleb(&mut raw, target(label));
        }
        try_items.push((from, (to - from) as u16, handler_offset));
    }
    Assembled {
        units,
        labels,
        tries: try_items,
        handlers: if tries.is_empty() { Vec::new() } else { raw },
        types,
        methods,
    }
}

// ---- a synthetic DEX around one method, decoded by the real decoder --------------

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

pub(super) fn dex_for(method: &Assembled, registers: u16, ins: u16, outs: u16) -> Vec<u8> {
    // Layout: header | string_ids | type_ids | proto_ids | method_ids | data. The index
    // tables are as small as the method allows (one empty string, one type, one
    // prototype); only their sizes matter to the decoder's range checks.
    let methods = method.methods;
    let tables = method.types > 0 || methods > 0;
    let types = if tables { method.types.max(1) } else { 0 };
    let string_ids = 112usize;
    let type_table = string_ids + 4;
    let proto_table = type_table + 4 * types as usize;
    let method_table = proto_table + if methods > 0 { 12 } else { 0 };
    let data_off = if tables {
        method_table + 8 * methods as usize
    } else {
        112
    };
    let mut at = data_off + if tables { 2 } else { 0 };
    while !at.is_multiple_of(4) {
        at += 1;
    }
    let code_at = at;
    let mut body: Vec<u8> = vec![0; code_at - 112];
    body.extend(registers.to_le_bytes());
    body.extend(ins.to_le_bytes());
    body.extend(outs.to_le_bytes());
    body.extend((method.tries.len() as u16).to_le_bytes());
    body.extend(0u32.to_le_bytes());
    body.extend((method.units.len() as u32).to_le_bytes());
    for unit in &method.units {
        body.extend(unit.to_le_bytes());
    }
    if !method.tries.is_empty() {
        if method.units.len() % 2 == 1 {
            body.extend(0u16.to_le_bytes());
        }
        for (start, count, handler) in &method.tries {
            body.extend(start.to_le_bytes());
            body.extend(count.to_le_bytes());
            body.extend(handler.to_le_bytes());
        }
        body.extend(&method.handlers);
    }
    while !(112 + body.len()).is_multiple_of(4) {
        body.push(0);
    }
    let map_at = 112 + body.len();
    let mut entries: Vec<(u16, u32, u32)> = vec![(0, 1, 0)];
    if tables {
        entries.push((0x0001, 1, string_ids as u32));
        entries.push((0x0002, types, type_table as u32));
        if methods > 0 {
            entries.push((0x0003, 1, proto_table as u32));
            entries.push((0x0005, methods, method_table as u32));
        }
        entries.push((0x2002, 1, data_off as u32));
    }
    entries.push((0x2001, 1, code_at as u32));
    entries.push((0x1000, 1, map_at as u32));
    body.extend((entries.len() as u32).to_le_bytes());
    for (kind, count, offset) in entries {
        body.extend(kind.to_le_bytes());
        body.extend(0u16.to_le_bytes());
        body.extend(count.to_le_bytes());
        body.extend(offset.to_le_bytes());
    }
    let mut bytes = vec![0u8; 112];
    bytes.extend_from_slice(&body);
    bytes[..8].copy_from_slice(b"dex\n040\0");
    let file_size = bytes.len() as u32;
    bytes[32..36].copy_from_slice(&file_size.to_le_bytes());
    bytes[36..40].copy_from_slice(&112u32.to_le_bytes());
    bytes[40..44].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    bytes[52..56].copy_from_slice(&(map_at as u32).to_le_bytes());
    if tables {
        let put = |bytes: &mut [u8], at: usize, value: u32| {
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        };
        put(&mut bytes, 56, 1);
        put(&mut bytes, 60, string_ids as u32);
        put(&mut bytes, string_ids, data_off as u32);
        put(&mut bytes, 64, types);
        put(&mut bytes, 68, type_table as u32);
        if methods > 0 {
            put(&mut bytes, 72, 1);
            put(&mut bytes, 76, proto_table as u32);
            put(&mut bytes, 88, methods);
            put(&mut bytes, 92, method_table as u32);
        }
    }
    // The data section starts after the tables: a table may not lie inside it.
    let data_size = file_size - data_off as u32;
    bytes[104..108].copy_from_slice(&data_size.to_le_bytes());
    bytes[108..112].copy_from_slice(&(data_off as u32).to_le_bytes());
    resign(&mut bytes);
    bytes
}

pub(super) fn decode(method: &Assembled, registers: u16, ins: u16, outs: u16) -> CodeItem {
    let bytes = dex_for(method, registers, ins, outs);
    let header = mdd_dex::validate_header(&bytes).expect("the synthetic DEX header is valid");
    let mut section = read_code_section(&bytes, &header, CodeLimits::default())
        .expect("the real decoder accepts the hand-assembled method");
    section.items.remove(0)
}

fn run(program: Value) -> (Assembled, CodeItem) {
    let program = program.as_array().unwrap().clone();
    let assembled = assemble(&program, &[], 0, 0);
    let item = decode(&assembled, 8, 1, 0);
    (assembled, item)
}

#[test]
fn the_assembler_and_the_synthetic_dex_decode_to_the_expected_instructions() {
    let (assembled, item) = run(serde_json::json!([
        ["const/4", 0, 1],
        ["if-eqz", 0, "end"],
        ["nop"],
        ["label", "end"],
        ["return-void"]
    ]));
    assert_eq!(assembled.labels["end"], 4);
    let mnemonics: Vec<_> = item
        .instructions
        .iter()
        .map(|i| i.mnemonic.to_string())
        .collect();
    assert_eq!(mnemonics, ["const/4", "if-eqz", "nop", "return-void"]);
    assert_eq!(item.instructions[1].branch_target_code_units, Some(4));
}

// ---- normalisation: results as label-based text, the form the fixtures are written in

fn label_of(labels: &BTreeMap<String, u32>, offset: u32) -> String {
    labels
        .iter()
        .filter(|(_, at)| **at == offset)
        .map(|(name, _)| name.clone())
        .min()
        .unwrap_or_else(|| format!("@{offset}"))
}

fn reg_text(reg: Reg) -> String {
    match reg {
        Reg::V(n) => format!("v{n}"),
        Reg::Result => "result".to_owned(),
        Reg::Exception => "exception".to_owned(),
    }
}

fn sorted_rows(mut rows: Vec<Value>) -> Vec<Value> {
    rows.sort_by_key(|row| row.to_string());
    rows
}

pub(super) fn normalize(labels: &BTreeMap<String, u32>, analysis: &MethodAnalysis) -> Value {
    use super::{cfg::Certainty, defuse::DefSite};
    let cfg = analysis.cfg.complete().expect("the CFG completes");
    let def_use = analysis.def_use.complete().expect("def-use completes");
    let name = |offset: u32| label_of(labels, offset);
    let blocks: Vec<Value> = cfg
        .blocks
        .iter()
        .map(|b| Value::from(name(b.start)))
        .collect();
    let edges = sorted_rows(
        cfg.edges
            .iter()
            .map(|edge| {
                let to = match edge.to {
                    Target::Block(id) => name(cfg.block(id).start),
                    Target::ReturnExit => "return".to_owned(),
                    Target::ExceptionExit => "exception_exit".to_owned(),
                };
                let kind = match edge.kind {
                    EdgeKind::Fallthrough => "fallthrough".to_owned(),
                    EdgeKind::Branch => "branch".to_owned(),
                    EdgeKind::SwitchCase { key } => format!("switch:{key}"),
                    EdgeKind::Exception { type_idx: Some(t) } => format!("exception:{t}"),
                    EdgeKind::Exception { type_idx: None } => "exception:any".to_owned(),
                    EdgeKind::Return => "return".to_owned(),
                    EdgeKind::ExceptionExit => "exception_exit".to_owned(),
                };
                let certainty = match edge.certainty {
                    Certainty::Definite => "definite",
                    Certainty::Possible => "possible",
                };
                serde_json::json!([name(cfg.block(edge.from).start), to, kind, certainty])
            })
            .collect(),
    );
    let unreachable = sorted_rows(
        cfg.unreachable_blocks()
            .map(|b| Value::from(name(b.start)))
            .collect(),
    );
    let issues = sorted_rows(
        cfg.issues
            .iter()
            .map(|i| {
                let kind = serde_json::to_value(i.kind).unwrap();
                serde_json::json!([kind, name(i.at)])
            })
            .collect(),
    );
    let def_key = |id| {
        let def = def_use.def(id);
        match def.site {
            DefSite::Entry => format!("entry:{}", reg_text(def.reg)),
            DefSite::Instruction { at } => format!("{}:{}", name(at), reg_text(def.reg)),
            DefSite::Handler { at } => format!("handler:{}", name(at)),
        }
    };
    let uses = sorted_rows(
        def_use
            .uses
            .iter()
            .map(|u| {
                let mut reaching: Vec<String> = u.reaching.iter().map(|d| def_key(*d)).collect();
                reaching.sort();
                serde_json::json!([name(u.at), reg_text(u.reg), reaching, u.may_be_undefined])
            })
            .collect(),
    );
    serde_json::json!({
        "blocks": blocks, "edges": edges, "unreachable": unreachable,
        "issues": issues, "uses": uses,
    })
}

pub(super) fn normalize_expected(expect: &Value) -> Value {
    let list = |key: &str| expect[key].as_array().cloned().unwrap_or_default();
    serde_json::json!({
        "blocks": list("blocks"),
        "edges": sorted_rows(list("edges")),
        "unreachable": sorted_rows(list("unreachable")),
        "issues": sorted_rows(list("issues")),
        "uses": sorted_rows(list("uses")),
    })
}

fn cases() -> Value {
    serde_json::from_str(include_str!(
        "../../../../conformance/analysis/soundness-cases.json"
    ))
    .unwrap()
}

fn analyze_case(case: &Value) -> (BTreeMap<String, u32>, MethodAnalysis, CodeItem) {
    let program = case["program"].as_array().unwrap();
    let tries = case["tries"].as_array().unwrap();
    let methods = case.get("methods").and_then(Value::as_u64).unwrap_or(0) as u32;
    let assembled = assemble(
        program,
        tries,
        case["types"].as_u64().unwrap() as u32,
        methods,
    );
    let item = decode(
        &assembled,
        case["registers"].as_u64().unwrap() as u16,
        case["ins"].as_u64().unwrap() as u16,
        case["outs"].as_u64().unwrap() as u16,
    );
    let analysis = analyze(&item, &Environment::none(), &AnalysisBudget::default());
    (assembled.labels, analysis, item)
}

#[test]
fn every_hand_fixture_matches_its_hand_derived_expectation() {
    let document = cases();
    assert_eq!(document["analysis_version"], ANALYSIS_VERSION);
    assert_eq!(document["scope"], SCOPE);
    let cases = document["cases"].as_array().unwrap();
    assert!(
        cases.len() >= 14,
        "the fixture set shrank to {}",
        cases.len()
    );
    let mut wrong = Vec::new();
    for case in cases {
        let (labels, analysis, _) = analyze_case(case);
        let got = normalize(&labels, &analysis);
        let want = normalize_expected(&case["expect"]);
        for key in ["blocks", "edges", "unreachable", "issues", "uses"] {
            if got[key] != want[key] {
                wrong.push(format!(
                    "{} / {key}\n  got:  {}\n  want: {}",
                    case["name"].as_str().unwrap(),
                    got[key],
                    want[key]
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "\n{}", wrong.join("\n"));
}

// ---- the opcode table against AOSP

#[test]
fn the_opcode_table_agrees_with_aosp_for_all_256_opcodes() {
    use super::opcodes::{Flow, info};
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/mdd-023/aosp-reference/dex_instruction_list.h");
    let source = std::fs::read_to_string(path).unwrap();
    let mut seen = 0usize;
    let mut wrong: Vec<String> = Vec::new();
    for line in source.lines() {
        let line = line.trim();
        let Some(body) = line.strip_prefix("V(") else {
            continue;
        };
        let body = body.trim_end_matches('\\').trim().trim_end_matches(')');
        let fields: Vec<&str> = body.split(',').map(str::trim).collect();
        if fields.len() < 8 {
            continue;
        }
        let opcode = u8::from_str_radix(fields[0].trim_start_matches("0x"), 16).unwrap();
        let name = fields[2].trim_matches('"');
        let flags: Vec<&str> = fields[5].split('|').map(str::trim).collect();
        let verify: Vec<&str> = fields[7].split('|').map(str::trim).collect();
        seen += 1;
        let unused = fields[1].starts_with("UNUSED_");
        let ours = info(opcode);
        if unused {
            if ours.is_some() {
                wrong.push(format!("{opcode:#04x} {name}: AOSP leaves it unused"));
            }
            continue;
        }
        let Some(ours) = ours else {
            wrong.push(format!("{opcode:#04x} {name}: missing from the table"));
            continue;
        };
        let has = |flag: &str| flags.contains(&flag);
        let flow = if has("kReturn") {
            Flow::Return
        } else if has("kSwitch") {
            Flow::Switch
        } else if has("kBranch") && has("kUnconditional") {
            Flow::Goto
        } else if has("kBranch") {
            Flow::Conditional
        } else if has("kThrow") && !has("kContinue") {
            Flow::Throw
        } else {
            Flow::Next
        };
        if ours.flow != flow {
            wrong.push(format!(
                "{opcode:#04x} {name}: flow {:?}, AOSP {flow:?}",
                ours.flow
            ));
        }
        if ours.may_throw != has("kThrow") {
            wrong.push(format!(
                "{opcode:#04x} {name}: may_throw {}, AOSP {}",
                ours.may_throw,
                has("kThrow")
            ));
        }
        let variadic = verify.iter().any(|f| f.starts_with("kVerifyVarArg"));
        if ours.variadic_uses != variadic {
            wrong.push(format!(
                "{opcode:#04x} {name}: variadic {}, AOSP {variadic}",
                ours.variadic_uses
            ));
        }
        for (slot, (plain, wide)) in [
            ("kVerifyRegA", "kVerifyRegAWide"),
            ("kVerifyRegB", "kVerifyRegBWide"),
            ("kVerifyRegC", "kVerifyRegCWide"),
        ]
        .into_iter()
        .enumerate()
        {
            let want = if verify.contains(&wide) {
                Some(true)
            } else if verify.contains(&plain) {
                Some(false)
            } else {
                None
            };
            let got = ours.slots[slot].map(|s| s.wide);
            if got != want {
                wrong.push(format!(
                    "{opcode:#04x} {name}: slot {slot} {got:?}, AOSP {want:?}"
                ));
            }
        }
    }
    assert_eq!(seen, 256, "the AOSP list should name every opcode");
    assert!(wrong.is_empty(), "\n{}", wrong.join("\n"));
}

// ---- reachability: yes, no, and unknown

fn case_named(name: &str) -> (BTreeMap<String, u32>, MethodAnalysis, CodeItem) {
    let document = cases();
    let case = document["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no fixture named {name}"));
    analyze_case(case)
}

fn ad_hoc(program: Value, tries: Value) -> (BTreeMap<String, u32>, MethodAnalysis, CodeItem) {
    let assembled = assemble(program.as_array().unwrap(), tries.as_array().unwrap(), 0, 0);
    let item = decode(&assembled, 6, 1, 0);
    let analysis = analyze(&item, &Environment::none(), &AnalysisBudget::default());
    (assembled.labels, analysis, item)
}

#[test]
fn reachability_says_yes_certainly_yes_maybe_and_a_proven_no() {
    let (l, a, _) = case_named("diamond");
    // Every way out of the first block is a condition: reachable, but not for certain.
    assert!(matches!(
        a.reaches(l["e"], l["join"]),
        Reach::Yes { certain: false, .. }
    ));
    // The other arm falls straight into the join.
    assert!(matches!(
        a.reaches(l["other"], l["join"]),
        Reach::Yes { certain: true, .. }
    ));
    // Later in the same block needs no edge at all.
    assert!(matches!(
        a.reaches(l["e"], l["t"]),
        Reach::Yes { certain: true, .. }
    ));
    // Nothing leads back, and nothing leads between the arms: proven, the graph is whole.
    assert_eq!(a.reaches(l["join"], l["e"]), Reach::No);
    assert_eq!(a.reaches(l["l"], l["other"]), Reach::No);
    assert_eq!(a.reaches(l["t"], l["e"]), Reach::No);

    let (l, a, _) = case_named("loop");
    assert!(matches!(
        a.reaches(l["cmp"], l["head"]),
        Reach::Yes { certain: false, .. }
    ));
    assert_eq!(a.reaches(l["done"], l["head"]), Reach::No);

    // A witness names the blocks it goes through.
    let (l, a, _) = case_named("packed-switch");
    let Reach::Yes { via, .. } = a.reaches(l["e"], l["end"]) else {
        panic!("the join is reachable");
    };
    assert_eq!(via.first(), Some(&l["e"]));
    assert_eq!(via.last(), Some(&l["end"]));
}

#[test]
fn an_exception_edge_is_only_usable_from_the_throwing_instruction_onward() {
    let (l, a, _) = ad_hoc(
        serde_json::json!([
            ["label", "e"],
            ["const/4", 0, 4],
            ["label", "ts"],
            ["div-int", 1, 0, 5],
            ["label", "after"],
            ["add-int/lit8", 2, 1, 1],
            ["label", "te"],
            ["return", 2],
            ["label", "h"],
            ["move-exception", 3],
            ["label", "hr"],
            ["return-object", 3]
        ]),
        serde_json::json!([{"from": "ts", "to": "te", "catches": [], "catch_all": "h"}]),
    );
    // div-int may throw into the handler; the add after it cannot.
    assert!(matches!(
        a.reaches(l["ts"], l["h"]),
        Reach::Yes { certain: false, .. }
    ));
    assert_eq!(a.reaches(l["after"], l["h"]), Reach::No);
    assert_eq!(a.reaches(l["te"], l["h"]), Reach::No);
}

#[test]
fn no_path_is_refused_when_the_graph_left_something_out() {
    // `far` runs off the end of the code, so the CFG is not well formed: "no path from `a`
    // to `far`" can no longer be called a proof, whatever the edges say.
    let (l, a, _) = ad_hoc(
        serde_json::json!([
            ["label", "e"],
            ["if-eqz", 5, "far"],
            ["label", "a"],
            ["return-void"],
            ["label", "far"],
            ["const/4", 0, 1],
            ["label", "end"]
        ]),
        serde_json::json!([]),
    );
    assert!(!a.cfg.complete().unwrap().well_formed());
    let Reach::Unknown { causes } = a.reaches(l["a"], l["far"]) else {
        panic!("a graph with an issue must not prove absence");
    };
    assert!(causes.iter().any(|c| matches!(
        c,
        super::reach::UnknownCause::CfgNotWellFormed {
            issue: IssueKind::FallthroughPastEnd,
            ..
        }
    )));
    // A path that does exist is still reported.
    assert!(matches!(a.reaches(l["e"], l["far"]), Reach::Yes { .. }));
}

#[test]
fn an_offset_that_is_not_an_instruction_is_unknown_not_no() {
    let (l, a, _) = case_named("diamond");
    for bad in [10_000u32, l["join"] + 1] {
        let answer = a.reaches(l["e"], bad);
        assert!(
            matches!(&answer, Reach::Unknown { causes } if causes.iter().any(|c| matches!(c, super::reach::UnknownCause::NotAnInstruction { .. }))),
            "{bad}: {answer:?}"
        );
    }
}

// ---- budgets interrupt, they do not truncate

#[test]
fn a_budget_interruption_is_reported_and_leaves_no_partial_facts() {
    let (_, full, item) = case_named("diamond");
    let cfg_budget = |f: fn(&mut AnalysisBudget)| {
        let mut budget = AnalysisBudget::default();
        f(&mut budget);
        analyze(&item, &Environment::none(), &budget)
    };
    for (name, run) in [
        ("instructions", cfg_budget(|b| b.max_instructions = 1)),
        ("blocks", cfg_budget(|b| b.max_blocks = 1)),
        ("edges", cfg_budget(|b| b.max_edges = 1)),
    ] {
        assert_eq!(
            run.cfg.incomplete().map(
                |i| matches!(i, Incomplete::BudgetExceeded { resource, .. } if *resource == name)
            ),
            Some(true),
            "{name}: {:?}",
            run.cfg
        );
        // Nothing downstream is built on an interrupted graph.
        assert!(run.def_use.incomplete().is_some() && run.call_sites.incomplete().is_some());
        assert!(matches!(run.reaches(0, 0), Reach::Unknown { .. }));
    }
    // An interrupted dataflow keeps the CFG and drops the chains.
    let short = cfg_budget(|b| b.max_dataflow_steps = 1);
    assert!(short.cfg.complete().is_some());
    assert!(matches!(
        short.def_use.incomplete(),
        Some(Incomplete::BudgetExceeded {
            resource: "dataflow_steps",
            ..
        })
    ));
    assert!(short.def_use.complete().is_none());

    // More budget never loses a fact: there is a least sufficient budget, below it the
    // stage is incomplete, and at or above it the result is the full one.
    let least = (1u64..)
        .find(|n| cfg_budget_steps(&item, *n).def_use.complete().is_some())
        .unwrap();
    assert!(least > 1);
    assert!(
        cfg_budget_steps(&item, least - 1)
            .def_use
            .complete()
            .is_none()
    );
    for extra in [0, 1, 10, 1000] {
        assert_eq!(cfg_budget_steps(&item, least + extra).def_use, full.def_use);
    }
}

fn cfg_budget_steps(item: &CodeItem, steps: u64) -> MethodAnalysis {
    let budget = AnalysisBudget {
        max_dataflow_steps: steps,
        ..AnalysisBudget::default()
    };
    analyze(item, &Environment::none(), &budget)
}

// ---- metamorphic relations over the hand fixtures

/// Register operand positions per op, so a program can be renamed mechanically.
fn register_args(op: &str) -> &'static [usize] {
    match op {
        "const/4" | "const/16" | "move-result" | "move-result-wide" | "move-result-object"
        | "move-exception" | "return" | "return-wide" | "return-object" | "throw"
        | "monitor-enter" | "if-eqz" | "if-nez" | "packed-switch" | "sparse-switch" => &[1],
        "move" | "move-wide" | "move-object" | "neg-int" | "int-to-long" | "array-length"
        | "add-int/2addr" | "add-long/2addr" | "if-eq" | "if-ne" | "if-lt" | "add-int/lit8" => {
            &[1, 2]
        }
        "add-int" | "sub-int" | "div-int" | "add-long" | "aget" => &[1, 2, 3],
        // the invoke ops keep their registers in a list, handled apart
        _ => &[],
    }
}

/// The parameter register stays put; the rest rotate among v0..v4 (a wide pair stays a
/// pair: v2,v3 becomes v3,v4).
fn rotate(register: i64) -> i64 {
    if register == 5 { 5 } else { (register + 1) % 5 }
}

fn rename_program(program: &[Value]) -> Vec<Value> {
    program
        .iter()
        .map(|op| {
            let mut op = op.as_array().unwrap().clone();
            let name = op[0].as_str().unwrap().to_owned();
            if name.starts_with("invoke-") {
                let rotated: Vec<Value> = op[1]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| Value::from(rotate(r.as_i64().unwrap())))
                    .collect();
                op[1] = Value::Array(rotated);
            }
            for position in register_args(&name) {
                if let Some(value) = op.get(*position).and_then(Value::as_i64) {
                    op[*position] = Value::from(rotate(value));
                }
            }
            Value::Array(op)
        })
        .collect()
}

fn rename_reg(text: &str) -> String {
    match text.strip_prefix('v').and_then(|n| n.parse::<i64>().ok()) {
        Some(n) => format!("v{}", rotate(n)),
        None => text.to_owned(),
    }
}

fn rename_key(key: &str) -> String {
    match key.rsplit_once(':') {
        Some((site, reg)) if site != "handler" => format!("{site}:{}", rename_reg(reg)),
        _ => key.to_owned(),
    }
}

fn run_program(case: &Value, program: Vec<Value>) -> Value {
    let tries = case["tries"].as_array().unwrap();
    let methods = case.get("methods").and_then(Value::as_u64).unwrap_or(0) as u32;
    let assembled = assemble(
        &program,
        tries,
        case["types"].as_u64().unwrap() as u32,
        methods,
    );
    let item = decode(
        &assembled,
        case["registers"].as_u64().unwrap() as u16,
        case["ins"].as_u64().unwrap() as u16,
        case["outs"].as_u64().unwrap() as u16,
    );
    let analysis = analyze(&item, &Environment::none(), &AnalysisBudget::default());
    normalize(&assembled.labels, &analysis)
}

#[test]
fn renaming_registers_renames_the_chains_and_changes_nothing_else() {
    for case in cases()["cases"].as_array().unwrap() {
        let program = case["program"].as_array().unwrap().clone();
        let original = run_program(case, program.clone());
        let renamed = run_program(case, rename_program(&program));
        for key in ["blocks", "edges", "unreachable", "issues"] {
            assert_eq!(original[key], renamed[key], "{} / {key}", case["name"]);
        }
        let expected_uses = sorted_rows(
            original["uses"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| {
                    let reaching: Vec<String> = u[2]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|k| rename_key(k.as_str().unwrap()))
                        .collect();
                    let mut reaching = reaching;
                    reaching.sort();
                    serde_json::json!([u[0], rename_reg(u[1].as_str().unwrap()), reaching, u[3]])
                })
                .collect(),
        );
        assert_eq!(
            Value::from(expected_uses),
            renamed["uses"],
            "{} / uses",
            case["name"]
        );
    }
}

#[test]
fn a_leading_trampoline_adds_one_block_and_one_edge_and_changes_nothing_else() {
    for case in cases()["cases"].as_array().unwrap() {
        let program = case["program"].as_array().unwrap().clone();
        let first_label = program
            .iter()
            .find(|op| op[0] == "label")
            .map(|op| op[1].as_str().unwrap().to_owned())
            .unwrap();
        let original = run_program(case, program.clone());
        let mut shifted = vec![
            serde_json::json!(["label", "aa_pre"]),
            serde_json::json!(["goto", first_label]),
        ];
        shifted.extend(program);
        let moved = run_program(case, shifted);
        // The same facts, with every offset shifted by two.
        assert_eq!(moved["uses"], original["uses"], "{} / uses", case["name"]);
        assert_eq!(
            moved["unreachable"], original["unreachable"],
            "{} / unreachable",
            case["name"]
        );
        assert_eq!(
            moved["issues"], original["issues"],
            "{} / issues",
            case["name"]
        );
        let mut blocks = vec![Value::from("aa_pre")];
        blocks.extend(original["blocks"].as_array().unwrap().clone());
        assert_eq!(
            moved["blocks"],
            Value::from(blocks),
            "{} / blocks",
            case["name"]
        );
        let mut edges = original["edges"].as_array().unwrap().clone();
        edges.push(serde_json::json!([
            "aa_pre",
            first_label,
            "branch",
            "definite"
        ]));
        assert_eq!(
            moved["edges"],
            Value::from(sorted_rows(edges)),
            "{} / edges",
            case["name"]
        );
    }
}

#[test]
fn dead_code_appended_at_the_end_never_changes_what_the_reachable_part_says() {
    for case in cases()["cases"].as_array().unwrap() {
        let program = case["program"].as_array().unwrap().clone();
        let has_payload = program
            .iter()
            .any(|op| op[0].as_str().unwrap().contains("payload"));
        let expects_issue = !case["expect"]["issues"].as_array().unwrap().is_empty();
        if has_payload || expects_issue {
            continue; // the end of these programs is not a plain stop
        }
        let original = run_program(case, program.clone());
        let mut extended = program;
        extended.extend([
            serde_json::json!(["label", "zz_dead"]),
            serde_json::json!(["const/4", 4, 1]),
            serde_json::json!(["return-void"]),
        ]);
        let grown = run_program(case, extended);
        assert_eq!(grown["uses"], original["uses"], "{} / uses", case["name"]);
        assert_eq!(
            grown["issues"], original["issues"],
            "{} / issues",
            case["name"]
        );
        let mut unreachable = original["unreachable"].as_array().unwrap().clone();
        unreachable.push(Value::from("zz_dead"));
        assert_eq!(
            grown["unreachable"],
            Value::from(sorted_rows(unreachable)),
            "{} / unreachable",
            case["name"]
        );
        let mut edges = original["edges"].as_array().unwrap().clone();
        edges.push(serde_json::json!([
            "zz_dead", "return", "return", "definite"
        ]));
        assert_eq!(
            grown["edges"],
            Value::from(sorted_rows(edges)),
            "{} / edges",
            case["name"]
        );
    }
}

// ---- calls, on real code

fn real_items(path: &str) -> Vec<CodeItem> {
    let bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path),
    )
    .unwrap();
    let header = mdd_dex::validate_header(&bytes).unwrap();
    read_code_section(&bytes, &header, CodeLimits::default())
        .unwrap()
        .items
}

#[test]
fn calls_are_classified_and_none_is_resolved_to_a_callee() {
    use super::calls::{CallTarget, Resolution, UnknownReason};
    let mut seen = BTreeMap::new();
    for item in real_items("tests/fixtures/references/generated/poly-custom-038.dex") {
        let analysis = analyze(&item, &Environment::none(), &AnalysisBudget::default());
        for site in analysis.call_sites.complete().expect("call sites classify") {
            let key = (site.opcode, format!("{:?}", site.resolution));
            seen.insert(key, site.clone());
            // An unknown site must say so; a dispatching one is not "the named method".
            match (site.target, site.resolution) {
                (CallTarget::Custom { .. }, r) => {
                    assert_eq!(r, Resolution::Unknown(UnknownReason::CustomBootstrap))
                }
                (CallTarget::Polymorphic { .. }, r) => {
                    assert_eq!(r, Resolution::Unknown(UnknownReason::PolymorphicSignature))
                }
                (CallTarget::Method { .. }, Resolution::Unknown(_)) => {
                    panic!("no environment, nothing hidden")
                }
                (CallTarget::Method { .. }, _) => {}
            }
        }
    }
    let kinds: std::collections::BTreeSet<String> = seen
        .values()
        .map(|s| {
            format!("{:?}", s.resolution)
                .split('(')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert!(
        kinds.len() >= 2,
        "the fixture should hold both named and unknown calls"
    );
    assert!(
        seen.values()
            .any(|s| matches!(s.target, CallTarget::Custom { .. })),
        "the fixture should hold an invoke-custom"
    );
    assert!(
        seen.values()
            .any(|s| matches!(s.target, CallTarget::Polymorphic { .. })),
        "the fixture should hold an invoke-polymorphic"
    );
    // The virtual and interface forms are dispatch-dependent, never "the named method".
    for site in seen
        .values()
        .filter(|s| matches!(s.opcode, 0x6e | 0x6f | 0x72 | 0x74 | 0x75 | 0x78))
    {
        assert_eq!(site.resolution, Resolution::DispatchUnresolved);
    }
    for site in seen
        .values()
        .filter(|s| matches!(s.opcode, 0x70 | 0x71 | 0x76 | 0x77))
    {
        assert_eq!(site.resolution, Resolution::NamedOnly);
    }
}

#[test]
fn reflection_and_loaders_hide_the_target_whatever_the_opcode_says() {
    use super::calls::{Resolution, UnknownReason};
    use mdd_dex::definitions::MethodReference;
    let reference = |idx: u32, class: &str, name: &str| MethodReference {
        method_idx: idx,
        class_idx: 0,
        proto_idx: 0,
        name_idx: 0,
        class_descriptor: class.to_owned(),
        method_name: name.to_owned(),
        descriptor: String::new(),
        return_descriptor: String::new(),
        parameter_descriptors: Vec::new(),
        encoded_range: mdd_dex::DexRange {
            byte_offset: mdd_types::DecimalU64(0),
            byte_length: mdd_types::DecimalU64(0),
        },
    };
    let environment = Environment::from_method_references(&[
        reference(1, "Ljava/lang/reflect/Method;", "invoke"),
        reference(2, "Ldalvik/system/DexClassLoader;", "<init>"),
        reference(3, "Ljava/lang/String;", "length"),
    ]);
    assert!(environment.names_checked());
    assert!(!Environment::none().names_checked());

    // Mark the method of a real invoke and watch the classification follow.
    let item = real_items("tests/fixtures/references/generated/poly-custom-038.dex")
        .into_iter()
        .find(|item| {
            item.instructions
                .iter()
                .any(|i| matches!(i.opcode, 0x6e..=0x72))
        })
        .expect("an ordinary invoke exists");
    let plain = analyze(&item, &Environment::none(), &AnalysisBudget::default());
    let site = plain
        .call_sites
        .complete()
        .unwrap()
        .iter()
        .find(|s| matches!(s.opcode, 0x6e..=0x72))
        .unwrap()
        .clone();
    let idx = site.named_method().unwrap();
    for reason in [
        UnknownReason::ReflectiveInvocation,
        UnknownReason::DynamicClassLoading,
    ] {
        let hidden = analyze(
            &item,
            &Environment::none().with(idx, reason),
            &AnalysisBudget::default(),
        );
        let found = hidden
            .call_sites
            .complete()
            .unwrap()
            .iter()
            .find(|s| s.at == site.at)
            .unwrap();
        assert_eq!(found.resolution, Resolution::Unknown(reason));
        assert!(found.is_unknown());
    }
}

// ---- invariants over every real code item in the repository's fixtures

fn fixture_dex_files() -> Vec<std::path::PathBuf> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let mut found = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "dex") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

#[test]
fn every_real_code_item_yields_a_consistent_cfg_and_chains() {
    let (mut files, mut items, mut blocks_total) = (0usize, 0usize, 0usize);
    for path in fixture_dex_files() {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(header) = mdd_dex::validate_header(&bytes) else {
            continue;
        };
        let Ok(section) = read_code_section(&bytes, &header, CodeLimits::default()) else {
            continue; // fixtures that the decoder refuses are the decoder's tests
        };
        files += 1;
        for item in &section.items {
            items += 1;
            let analysis = analyze(item, &Environment::none(), &AnalysisBudget::default());
            let Some(cfg) = analysis.cfg.complete() else {
                // Nothing may be silently skipped: an item the analysis cannot take must say why.
                assert!(analysis.cfg.incomplete().is_some());
                continue;
            };
            blocks_total += cfg.blocks.len();
            // The blocks partition the instructions: each exactly once, in order.
            let covered: usize = cfg.blocks.iter().map(|b| b.instruction_count).sum();
            assert_eq!(covered, item.instructions.len(), "{}", path.display());
            let mut next = 0usize;
            for block in &cfg.blocks {
                assert_eq!(block.first_instruction, next, "{}", path.display());
                next += block.instruction_count;
                assert_eq!(
                    block.start,
                    item.instructions[block.first_instruction].code_unit_offset
                );
            }
            assert!(
                cfg.blocks[0].reachable
                    && cfg.blocks[0].start == item.instructions[0].code_unit_offset
            );
            for edge in &cfg.edges {
                assert!((edge.from.0 as usize) < cfg.blocks.len());
                if let Target::Block(to) = edge.to {
                    assert!((to.0 as usize) < cfg.blocks.len());
                }
                assert!(cfg.block(edge.from).start <= edge.source_offset);
                assert!(edge.source_offset < cfg.block(edge.from).end);
            }
            // Every reachable block that falls through has its edge or an issue.
            let def_use = analysis
                .def_use
                .complete()
                .expect("def-use completes on real code");
            for (index, def) in def_use.defs.iter().enumerate() {
                assert_eq!(def.id.0 as usize, index);
            }
            for used in &def_use.uses {
                assert!(
                    used.reaching
                        .iter()
                        .all(|d| (d.0 as usize) < def_use.defs.len())
                );
                assert!(
                    used.reaching.windows(2).all(|w| w[0] < w[1]),
                    "sorted and distinct"
                );
                assert!(
                    !used.reaching.is_empty() || used.may_be_undefined,
                    "a use with no definition must be flagged"
                );
            }
        }
    }
    assert!(
        files >= 3 && items >= 20 && blocks_total >= 20,
        "vacuous: {files} files, {items} items, {blocks_total} blocks"
    );
}

#[test]
fn hand_assembled_calls_are_classified_by_opcode_and_by_try_membership() {
    use super::calls::{CallTarget, Resolution};
    let assembled = assemble(
        serde_json::json!([
            ["label", "e"],
            ["const/4", 0, 1],
            ["label", "s"],
            ["invoke-static", [0], 0],
            ["label", "ts"],
            ["invoke-virtual", [0], 1],
            ["label", "te"],
            ["return-void"],
            ["label", "h"],
            ["move-exception", 2],
            ["label", "hr"],
            ["return-void"]
        ])
        .as_array()
        .unwrap(),
        serde_json::json!([{"from": "ts", "to": "te", "catches": [], "catch_all": "h"}])
            .as_array()
            .unwrap(),
        0,
        2,
    );
    let item = decode(&assembled, 6, 1, 1);
    let analysis = analyze(&item, &Environment::none(), &AnalysisBudget::default());
    let sites = analysis.call_sites.complete().unwrap();
    assert_eq!(sites.len(), 2);

    let static_call = &sites[0];
    assert_eq!(static_call.at, assembled.labels["s"]);
    assert_eq!(static_call.target, CallTarget::Method { method_idx: 0 });
    assert_eq!(static_call.resolution, Resolution::NamedOnly);
    assert!(!static_call.in_try);

    // A virtual call is decided by its receiver: it names method 1 and is not method 1.
    let virtual_call = &sites[1];
    assert_eq!(virtual_call.at, assembled.labels["ts"]);
    assert_eq!(virtual_call.named_method(), Some(1));
    assert_eq!(virtual_call.resolution, Resolution::DispatchUnresolved);
    assert!(
        virtual_call.in_try,
        "an exception of the callee may enter the handler here"
    );
    assert!(!virtual_call.is_unknown());
}

#[test]
fn blocks_trace_back_to_dex_offsets_and_to_source_lines() {
    let (mut checked_blocks, mut lines_seen) = (0usize, 0usize);
    for path in fixture_dex_files() {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(header) = mdd_dex::validate_header(&bytes) else {
            continue;
        };
        let Ok(section) = read_code_section(&bytes, &header, CodeLimits::default()) else {
            continue;
        };
        for item in &section.items {
            let analysis = analyze(item, &Environment::none(), &AnalysisBudget::default());
            let Some(cfg) = analysis.cfg.complete() else {
                continue;
            };
            // The positions the debug info gives, taken straight from its events.
            let mut positions: Vec<(u32, u64)> =
                item.debug_info.as_ref().map_or_else(Vec::new, |debug| {
                    debug
                        .usable_source_positions()
                        .filter_map(|e| e.source_line.map(|l| (e.address_code_units, l.0)))
                        .collect()
                });
            positions.sort_by_key(|(address, _)| *address);
            for block in &cfg.blocks {
                checked_blocks += 1;
                let first = &item.instructions[block.first_instruction];
                // Code unit offset, file offset and the instruction itself agree.
                assert_eq!(block.start, first.code_unit_offset);
                assert_eq!(block.byte_offset, first.byte_offset.0);
                assert_eq!(
                    block.byte_offset,
                    item.insns_range.byte_offset.0 + 2 * u64::from(block.start)
                );
                let expected = positions
                    .iter()
                    .rev()
                    .find(|(a, _)| *a <= block.start)
                    .map(|(_, l)| *l);
                assert_eq!(block.source_line, expected, "block at {}", block.start);
                assert_eq!(cfg.source_line_at(block.start), expected);
                lines_seen += usize::from(expected.is_some());
            }
        }
    }
    assert!(checked_blocks >= 20, "vacuous: {checked_blocks} blocks");
    assert!(
        lines_seen >= 1,
        "no fixture block carries a source line, so lines were never checked"
    );
}

#[test]
fn a_result_carries_its_version_scope_assumptions_and_status() {
    let (_, analysis, _) = case_named("diamond");
    assert_eq!(analysis.version, ANALYSIS_VERSION);
    assert_eq!(analysis.scope, SCOPE);
    assert!(analysis.assumptions.len() >= 4);
    assert!(
        analysis
            .assumptions
            .iter()
            .any(|a| a.contains("handler types are not matched")),
        "the exception-edge over-approximation must be stated"
    );
    let json = serde_json::to_value(&analysis).unwrap();
    for key in [
        "version",
        "scope",
        "assumptions",
        "cfg",
        "def_use",
        "call_sites",
    ] {
        assert!(
            json.get(key).is_some(),
            "{key} missing from the serialised result"
        );
    }
    assert_eq!(json["cfg"]["status"], "complete");
    // An interrupted stage says so in the same place instead of being absent or empty.
    let (_, _, item) = case_named("diamond");
    let short = cfg_budget_steps(&item, 1);
    let json = serde_json::to_value(&short).unwrap();
    assert_eq!(json["def_use"]["status"], "incomplete");
    assert_eq!(json["def_use"]["value"]["reason"], "budget_exceeded");
}

#[test]
fn nothing_outside_the_analysis_module_depends_on_it() {
    // The analysis is optional: the ordinary pipeline, the session facade and the SQL and
    // typed query layers must keep working without it, so none of them may call into it.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut offenders = Vec::new();
    let mut stack = vec![root.join("crates")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.ends_with("target") || path.ends_with("analysis") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                if text.contains("mdd_facts::analysis") || text.contains("crate::analysis") {
                    offenders.push(path.display().to_string());
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "optional analysis used by: {offenders:?}"
    );
}

#[test]
fn register_roles_follow_the_opcode_family_for_every_opcode() {
    use super::opcodes::{Role, info};
    // The roles are not in AOSP's table, but the opcode names say them: a move, const,
    // aget, iget, sget, conversion or arithmetic result is written; a return, throw,
    // monitor, aput, iput, sput, branch or switch operand is read; a /2addr form reads
    // then writes its first operand; every other register operand is only read.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/mdd-023/aosp-reference/dex_instruction_list.h");
    let source = std::fs::read_to_string(path).unwrap();
    let writes = [
        "move",
        "const",
        "aget",
        "iget",
        "sget",
        "new-",
        "instance-of",
        "array-length",
        "cmp",
        "neg-",
        "not-",
        "int-to",
        "long-to",
        "float-to",
        "double-to",
        "rsub-",
        "add-",
        "sub-",
        "mul-",
        "div-",
        "rem-",
        "and-",
        "or-",
        "xor-",
        "shl-",
        "shr-",
        "ushr-",
    ];
    let reads = [
        "return",
        "throw",
        "monitor",
        "aput",
        "iput",
        "sput",
        "if-",
        "packed-switch",
        "sparse-switch",
        "fill-array-data",
        "check-cast",
    ];
    let (mut checked, mut wrong) = (0usize, Vec::new());
    for line in source.lines() {
        let Some(body) = line.trim().strip_prefix("V(") else {
            continue;
        };
        let fields: Vec<&str> = body.split(',').map(str::trim).collect();
        if fields.len() < 8 || fields[1].starts_with("UNUSED_") {
            continue;
        }
        let opcode = u8::from_str_radix(fields[0].trim_start_matches("0x"), 16).unwrap();
        let name = fields[2].trim_matches('"');
        let Some(ours) = info(opcode) else { continue };
        let Some(first) = ours.slots[0] else { continue };
        let expected = if name.ends_with("/2addr") {
            Role::DefUse
        } else if reads.iter().any(|p| name.starts_with(p)) {
            Role::Use
        } else if writes.iter().any(|p| name.starts_with(p)) {
            Role::Def
        } else {
            wrong.push(format!("{opcode:#04x} {name}: no family names this opcode"));
            continue;
        };
        checked += 1;
        if first.role != expected {
            wrong.push(format!(
                "{opcode:#04x} {name}: first operand {:?}, family says {expected:?}",
                first.role
            ));
        }
        for (slot, later) in ours.slots.iter().enumerate().skip(1) {
            if let Some(later) = later
                && later.role != Role::Use
            {
                wrong.push(format!(
                    "{opcode:#04x} {name}: slot {slot} is {:?}, only reads are allowed",
                    later.role
                ));
            }
        }
        // Wide results of the move-result forms and results of invokes are written, never read.
        if matches!(opcode, 0x0a..=0x0d) && first.role != Role::Def {
            wrong.push(format!("{opcode:#04x} {name}: must write its register"));
        }
    }
    assert!(checked >= 150, "vacuous: only {checked} opcodes checked");
    assert!(wrong.is_empty(), "\n{}", wrong.join("\n"));
}

#[test]
fn a_path_that_loops_back_through_the_start_block_is_found_not_denied() {
    // Block `b` holds the only instruction that can throw, and `a` sits after it. From `a`
    // the handler can be reached only by going round the loop to `b` and throwing there;
    // the exception edge itself leaves from before `a`. Searching only the edges after
    // `from` and never re-entering the block would call this "no path".
    let (l, a, _) = ad_hoc(
        serde_json::json!([
            ["label", "e"],
            ["const/4", 0, 4],
            ["label", "b"],
            ["div-int", 1, 0, 5],
            ["label", "a"],
            ["add-int/lit8", 2, 1, 1],
            ["label", "c"],
            ["if-eqz", 2, "b"],
            ["label", "d"],
            ["return-void"],
            ["label", "h"],
            ["move-exception", 3],
            ["label", "hr"],
            ["return-void"]
        ]),
        serde_json::json!([{"from": "b", "to": "d", "catches": [], "catch_all": "h"}]),
    );
    let answer = a.reaches(l["a"], l["h"]);
    assert!(
        matches!(answer, Reach::Yes { certain: false, .. }),
        "the handler is reachable through the loop: {answer:?}"
    );
    // After the last thing that can throw, with no way back into the try, it is not.
    assert_eq!(a.reaches(l["d"], l["h"]), Reach::No);
}

#[test]
fn the_result_says_whether_method_names_were_consulted_for_calls() {
    let (_, without, item) = case_named("invoke-then-move-result");
    assert!(!without.call_names_checked, "no names were given");
    assert!(without.call_sites.complete().is_some());
    let with = analyze(
        &item,
        &Environment::from_method_references(&[]),
        &AnalysisBudget::default(),
    );
    assert!(with.call_names_checked);
    assert_eq!(
        serde_json::to_value(&with).unwrap()["call_names_checked"],
        true
    );
}
