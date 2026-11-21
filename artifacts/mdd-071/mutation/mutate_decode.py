#!/usr/bin/env python3
"""Mutation check for MDD-071: the complete decode (classes, the three modes, annotations, debug lines, fields, context, paging).

Uses tools/mutation_harness.py with only the decode/smali sources, fixtures and suites.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))

import mutation_harness as H  # noqa: E402

PY = H.PY
FACTS = "crates/mdd-facts/src/"
SMALI = FACTS + "smali/"
CONTEXT, VALUE, ANNOTATION, METHOD, CLASS = (SMALI + n for n in ("context.rs", "value.rs", "annotation.rs", "method.rs", "class.rs"))
CORE = FACTS + "smali_required/render.rs"
MCP = "crates/mdd-mcp/src/"
SERVICE = "crates/mdd-service/src/"
TOOLS, DECODE, DATASET, LAYERS = MCP + "tools.rs", SERVICE + "decode.rs", SERVICE + "dataset.rs", SERVICE + "layers.rs"
TOOLS_DECODE, TOOLS_MANIFEST, TOOLS_SQL = MCP + "tools/decode.rs", MCP + "tools/manifest.rs", MCP + "tools/sql.rs"

SOURCES = [
    SMALI + "mod.rs", CONTEXT, VALUE, ANNOTATION, METHOD, CLASS,
    FACTS + "smali_required/mod.rs", CORE, FACTS + "smali_required/tests.rs",
    DECODE, DATASET, LAYERS, SERVICE + "lib.rs",
    TOOLS, TOOLS_DECODE, TOOLS_MANIFEST, TOOLS_SQL, MCP + "server.rs", MCP + "protocol.rs", MCP + "lib.rs", MCP + "tool_schemas.json",
    "crates/mdd-cli/tests/mcp.rs",
    "conformance/mcp/mcp_client.py",
    "conformance/decode/oracle.py", "conformance/decode/oracle_class.py",
    "conformance/decode/run_decode_conformance.py", "conformance/decode/hand-expected.txt",
    "conformance/decode/run_decode_full.py", "conformance/decode/test_decode_full.py",
    "conformance/decode/hand-expected-class.txt", "conformance/decode/build_decode_contract.py",
    "conformance/mcp/decode-full-contract.json",
    "conformance/decode/a0_cases.py", "conformance/decode/a0_replay.py", "conformance/decode/test_a0_replay.py",
    "conformance/decode/a0-golden.json",
    "tests/fixtures/decode/generate.py", "tests/fixtures/decode/manifest.json",
    "tests/fixtures/decode/generate_class.py", "tests/fixtures/decode/class-manifest.json",
]

FIXTURES = [
    "tests/fixtures/decode/generated/decode-all.dex",
    "tests/fixtures/decode/generated/decode-v035.dex",
    "tests/fixtures/decode/generated/decode-bad-invoke.dex",
    "tests/fixtures/decode/generated/decode-class.dex",
    "tests/fixtures/decode/generated/manifest-small.apk",
    "tests/fixtures/decode/generated/no-manifest.apk",
    "tests/fixtures/annotations/generated/annotations-038.dex",
]

MUTANTS = [
    # ---- the context view
    ("context: exception-table lines are not kept", CONTEXT, [('const METHOD_ANCHORS: [&str; 3] = [".method", ".registers", ".catch"];', 'const METHOD_ANCHORS: [&str; 3] = [".method", ".registers", ".catchx"];')]),
    ("context: labels are not kept", CONTEXT, [("trimmed.starts_with(':') || words", "words")]),
    ("context: numbers start at one", CONTEXT, [("for (number, line) in text.split_terminator('\\n').enumerate() {", "for (number, line) in text.split_terminator('\\n').enumerate().map(|(n, l)| (n + 1, l)) {")]),
    ("context: the register line is not kept", CONTEXT, [('[".method", ".registers", ".catch"]', '[".method", ".catch", ".catch"]')]),
    ("context: the class view drops fields", CONTEXT, [('[".class", ".super", ".source", ".implements", ".field"]', '[".class", ".super", ".source", ".implements", ".fieldx"]')]),
    # ---- values
    ("value: a byte has the suffix of a short", VALUE, [("                out.push_str(&signed_hex(number()?)?);\n                out.push('t');", "                out.push_str(&signed_hex(number()?)?);\n                out.push('s');")]),
    ("value: a long has no suffix", VALUE, [("                out.push_str(&signed_hex(number()?)?);\n                out.push('L');", "                out.push_str(&signed_hex(number()?)?);")]),
    ("value: a float has no suffix", VALUE, [('(f64::from(f32::from_bits(bits as u32)), "f")', '(f64::from(f32::from_bits(bits as u32)), "")')]),
    ("value: plain decimals go one exponent further", VALUE, [("let body = if (-4..16).contains(&exponent) {", "let body = if (-4..17).contains(&exponent) {")]),
    ("value: a boolean is inverted", VALUE, [('out.push_str(if number()? == "0" { "false" } else { "true" })', 'out.push_str(if number()? == "0" { "true" } else { "false" })')]),
    ("value: an enum is not marked", VALUE, [('out.push_str(".enum ");', 'out.push_str("");')]),
    ("value: the last element of an array has a comma", VALUE, [("if position != last {", "if true {")]),
    ("value: a method handle index is off by one", VALUE, [('let _ = write!(out, "method_handle_{}", self.index(node)?);', 'let _ = write!(out, "method_handle_{}", self.index(node)? + 1);')]),
    ("value: a nested annotation loses its end", VALUE, [('out.push_str(".end subannotation");', 'out.push_str(".end annotation");')]),
    ("value: an empty array is not written as braces", VALUE, [('out.push_str("{}");', 'out.push_str("{ }");')]),
    # ---- annotations
    ("annotation: a runtime annotation is called build", ANNOTATION, [('1 => "runtime",', '1 => "build",')]),
    ("annotation: parameter slots are placed when fewer than the parameters", ANNOTATION, [("slots.len() == prototype_parameters && encoded == prototype_parameters", "slots.len() <= prototype_parameters")]),
    ("annotation: a set shows only its first item", ANNOTATION, [("for offset in &set.annotation_offsets {", "for offset in set.annotation_offsets.iter().take(1) {")]),
    # ---- the method text
    ("method: the first parameter of an instance method is p0", METHOD, [("let mut next = u32::from(!is_static);", "let mut next = 0;")]),
    ("method: a wide parameter takes one register", METHOD, [("    if descriptor == \"J\" || descriptor == \"D\" {\n        2", "    if descriptor == \"J\" || descriptor == \"D\" {\n        1")]),
    ("method: a parameter without a name or annotations is listed", METHOD, [("if name.is_none() && count == 0 {", "if false {")]),
    ("method: the method's own annotations are not written", METHOD, [(".extend(index.set_lines(data, &context, set, 4)?);", ".extend(Vec::<String>::new());")]),
    ("method: the prologue directive is misspelled", METHOD, [('7 => ".prologue".to_owned(),\n        8', '7 => ".prolog".to_owned(),\n        8')]),
    ("method: a local with a signature loses its comma", METHOD, [('                line.push_str(", ");\n                line.push_str(&context.string_literal(index)?);', '                line.push(\' \');\n                line.push_str(&context.string_literal(index)?);')]),
    ("method: a position that is no source line is written", METHOD, [("Some(line) if event.source_line_usable => format!", "Some(line) => format!")]),
    ("method: an event at the end of the code is lost", METHOD, [("            DebugAddressScope::AtCodeEnd => insns_size,\n", "")]),
    ("method: an event inside an instruction is placed at it", METHOD, [("                if instruction_starts.contains(&event.address_code_units) =>", "                if true =>")]),
    ("method: parameter registers are numbered from the wrong first parameter", METHOD, [("let first_parameter = code.registers_size.saturating_sub(code.ins_size);", "let first_parameter = code.registers_size;")]),
    ("method: end local is written as restart", METHOD, [('5 => format!(".end local {}", register(need_register()?)),', '5 => format!(".restart local {}", register(need_register()?)),')]),
    # ---- the class text
    ("class: a static value goes to the next field", CLASS, [("if with_values && let Some(node) = array.get(position) {", "if with_values && let Some(node) = array.get(position + 1) {")]),
    ("class: interfaces are in no order", CLASS, [("    interfaces.sort_by_key(|row| row.ordinal);\n", "    interfaces.reverse();\n")]),
    ("class: an interface is not called one", CLASS, [('(0x200, "interface"),', '(0x200, "iface"),')]),
    ("class: a field's annotations are not closed", CLASS, [('text.push_str(".end field\\n");', "")]),
    ("class: the superclass is not written", CLASS, [('let _ = writeln!(text, ".super {superclass}");', "let _ = superclass;")]),
    ("class: static fields come after instance fields", CLASS, [("for (rows, with_values) in [(&statics, true), (&instances, false)] {", "for (rows, with_values) in [(&instances, false), (&statics, true)] {")]),
    ("class: the source file is not written", CLASS, [('text.push_str(".source ");', 'text.push_str("");')]),
    # ---- the hook in the instruction renderer
    ("core: the extra header lines go before the register line", CORE, [('let _ = writeln!(text, "    .registers {}", code.registers_size);\n    push_lines(&mut text, &extras.header);', 'push_lines(&mut text, &extras.header);\n    let _ = writeln!(text, "    .registers {}", code.registers_size);')]),
    ("core: a line for an address that is no instruction is accepted", CORE, [("    if placed != extras.at_address.len() {", "    if false {")]),
    ("core: the extra lines of an address come after its instruction", CORE, [("        if (next_instruction == Some(address) || address == end_address)\n            && let Some(lines) = extras.at_address.get(&address)", "        if (next_instruction == Some(address) && false || address == end_address)\n            && let Some(lines) = extras.at_address.get(&address)")]),
    # ---- the service
    ("service: the methods of a class are in file order", DECODE, [("            positions.sort_by_key(|&position| defs.method_definitions[position].method_idx);\n", "")]),
    ("service: method_offset equal to the total is a range error", DECODE, [("    if offset > total {", "    if offset >= total {")]),
    ("service: a class in two files picks the first", DECODE, [("        [(file_id, class)] => Ok(LocatedClass {", "        [(file_id, class), ..] => Ok(LocatedClass {")]),
    ("service: a page has one method too many", DECODE, [("let end = start.saturating_add(usize::try_from(limit).unwrap_or(usize::MAX));", "let end = start.saturating_add(usize::try_from(limit).unwrap_or(usize::MAX)).saturating_add(1);")]),
    ("service: a summary row takes the incoming registers", DECODE, [("registers: code.map(|c| c.registers_size),", "registers: code.map(|c| c.ins_size),")]),
    ("service: a method text is rendered without its annotation layer", DECODE, [("        annotations: occurrence\n            .annotations\n            .as_deref()\n            .zip(index.annotation_index.as_ref()),\n    };\n    let full = render_method_full", "        annotations: None,\n    };\n    let full = render_method_full")]),
    ("service: a class text is rendered without its annotation layer", DECODE, [("        annotations: occurrence\n            .annotations\n            .as_deref()\n            .zip(index.annotation_index.as_ref()),\n    };\n    render_class(", "        annotations: None,\n    };\n    render_class(")]),
    ("service: the facts decode renders from lose the annotation layer", LAYERS, [("            annotations: annotations.ok(),", "            annotations: annotations.ok().and(None),")]),
    # ---- the tool
    ("tool: a class defaults to the smali mode", TOOLS_DECODE, [("let mode = requested.unwrap_or(if args.class.is_some() {\n        DecodeMode::Summary", "let mode = requested.unwrap_or(if args.class.is_some() {\n        DecodeMode::Smali")]),
    ("tool: a class page accepts a text offset", TOOLS_DECODE, [("        if args.offset != 0 {\n            return Err(refuse_here(ErrorCode::InvalidArgument, CLASS_TEXT_PAGE).into());", "        if false {\n            return Err(refuse_here(ErrorCode::InvalidArgument, CLASS_TEXT_PAGE).into());")]),
    ("tool: the default method_limit is 21", TOOLS_DECODE, [("pub const DEFAULT_METHOD_LIMIT: u64 = 20;", "pub const DEFAULT_METHOD_LIMIT: u64 = 21;")]),
    ("tool: the last page names a continuation", TOOLS_DECODE, [("(next_method_offset < page.total_methods).then_some(next_method_offset)", "Some(next_method_offset)")]),
    ("tool: the byte budget of a class page is not spent", TOOLS_DECODE, [("                *left -= text_page.text.len() as u64;", "                let _ = left;")]),
    ("tool: a used-up budget fails the page instead of ending it", TOOLS_DECODE, [('Err(error) if error.message == "MAX_BYTES_TOO_SMALL" && !rows.is_empty() => break,', 'Err(error) if error.message == "MAX_BYTES_TOO_SMALL" && false => break,')]),
    ("tool: every page of a class repeats the class text", TOOLS_DECODE, [("let class_text = if mode != DecodeMode::Summary && method_offset == 0 {", "let class_text = if mode != DecodeMode::Summary {")]),
    ("tool: a context names the wrong line count of the full text", TOOLS_DECODE, [("source_lines: Some(full.split_terminator('\\n').count() as u64),", "source_lines: Some(full.split_terminator('\\n').count() as u64 + 1),")]),
    ("tool: a context is labelled with the smali format", TOOLS_DECODE, [("Self::Context => Some(smali::CONTEXT_FORMAT),", "Self::Context => Some(smali::SMALI_FORMAT),")]),
    ("tool: a method row hides what its text leaves out", TOOLS_DECODE, [("        fields.extend(text_fields(&page, shown.source_lines));\n        if let Some(left_out) = omitted(&decoded.report) {", "        fields.extend(text_fields(&page, shown.source_lines));\n        if let Some(left_out) = omitted(&decoded.report).filter(|_| false) {")]),
    ("tool: a class row hides what its text leaves out", TOOLS_DECODE, [("                fields.extend(text_fields(&text_page, shown.source_lines));\n                if let Some(left_out) = omitted(&decoded.report) {", "                fields.extend(text_fields(&text_page, shown.source_lines));\n                if let Some(left_out) = omitted(&decoded.report).filter(|_| false) {")]),
    ("tool: an offset past the methods is not a range error", TOOLS_DECODE, [('(error.message == decode::METHOD_OFFSET_PAST_END).then_some("invalid_range")', '(error.message == decode::METHOD_OFFSET_PAST_END).then_some("invalid_input")')]),
    ("tool: an ambiguous class is worded as a method", TOOLS_DECODE, [('"class occurs in multiple DEX files; supply file_id from {}",', '"method occurs in multiple DEX files; supply file_id from {}",')]),
    ("tool: a class that is not found does not echo its file_id", TOOLS_DECODE, [("            if let Some(file_id) = args.file_id {\n                error = error.detail(\"file_id\", file_id.to_string());\n            }\n            return Err(error.into());\n        }\n        Err(decode::Failure::Ambiguous { file_ids }) => {\n            return Err(with_kind(\n                decode_error(", "            return Err(error.into());\n        }\n        Err(decode::Failure::Ambiguous { file_ids }) => {\n            return Err(with_kind(\n                decode_error(")]),
    ("tool: a class page does not say the class text is cut", TOOLS_DECODE, [('("truncated", json!(truncated)),', '("truncated", json!(false)),')]),
    ("tool: a summary of a class is limited by its text budget in the wrong unit", TOOLS_DECODE, [("let size = row.to_string().len() as u64;", "let size = 1;")]),
]

_DEADLINE = """        Outcome::TimedOut => {
            registry.close(&id);
            return Err(refuse(
                ErrorCode::DeadlineExceeded,
                "running computation was terminated and this dataset was closed; call open_dataset to use it again",
            )
            .detail("deadline_ms", ms.to_string())
            .detail("mcp.dataset_id", id.as_str())
            .detail("mcp.dataset_closed", "true")
            .into());
        }
        Outcome::Panicked => {
            registry.close(&id);
            return Err(panicked("decode")
                .detail("mcp.dataset_id", id.as_str())
                .detail("mcp.dataset_closed", "true")
                .into());
        }
    };
"""
_WITHOUT_TIMEOUT_CLOSE = _DEADLINE.replace("        Outcome::TimedOut => {\n            registry.close(&id);\n", "        Outcome::TimedOut => {\n", 1)
assert _WITHOUT_TIMEOUT_CLOSE != _DEADLINE

MUTANTS += [
    ("tool: an empty descriptor is looked up instead of refused", TOOLS_DECODE,
     [('    if args.method.as_deref() == Some("") || args.class.as_deref() == Some("") {', "    if false {")]),
    ("tool: a text offset past the text is not called a range error", TOOLS_DECODE,
     [('    let kind = if error.message.starts_with("OFFSET_") {\n        "invalid_range"', '    let kind = if error.message.starts_with("OFFSET_") {\n        "invalid_offset"')]),
    ("tool: a method decode deadline leaves the dataset open", TOOLS_DECODE,
     [(_DEADLINE + "    let decoded = match result {", _WITHOUT_TIMEOUT_CLOSE + "    let decoded = match result {")]),
    ("tool: a class decode deadline leaves the dataset open", TOOLS_DECODE,
     [(_DEADLINE + "    let ClassAnswer {", _WITHOUT_TIMEOUT_CLOSE + "    let ClassAnswer {")]),
]

SUITE = H.MutationSuite(
    name="MDD-071",
    sources=SOURCES,
    fixtures=FIXTURES,
    unit_suites=[
        ("unit", [*H.CARGO, "-p", "mdd-mcp", "-p", "mdd-service", "--lib", *H.TAIL]),
        ("smali", [*H.CARGO, "-p", "mdd-facts", "--lib", "smali", *H.TAIL]),
        ("process", [*H.CARGO, "-p", "mdd-cli", "--test", "mcp", *H.TAIL]),
    ],
    replays=[
        ("decode", [PY, "-I", "conformance/decode/run_decode_conformance.py"]),
        ("reference answers", [PY, "-I", "conformance/decode/a0_replay.py"]),
        ("full decode", [PY, "-I", "conformance/decode/run_decode_full.py"]),
        ("decode contract", [PY, "-I", "conformance/decode/build_decode_contract.py", "--check"]),
    ],
    controls=[
        [PY, "-I", "conformance/decode/test_a0_replay.py"],
        [PY, "-I", "conformance/decode/test_decode_full.py"],
    ],
    mutants=MUTANTS,
)
base = SUITE


def sources_sha256() -> str:
    return SUITE.sources_sha256()


if __name__ == "__main__":
    sys.exit(SUITE.main())
