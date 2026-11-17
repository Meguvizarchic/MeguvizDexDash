#!/usr/bin/env python3
"""Mutation check for MDD-071: the complete decode (classes, the three modes, annotations, debug lines, fields, context, paging).

It uses the machinery of artifacts/mdd-042/mutation/mutate_mcp.py (one source file edited in place per mutant, the suites run,
the original bytes written back in a finally block, commands with time limits, parts, assembly) with this task's mutants,
sources and suites. A mutant is killed when the Rust unit tests (mdd-mcp, mdd-service, the smali modules of mdd-facts), the MCP
process tests, or any replay or conformance run fails: the reference replay, the decode conformance of MDD-042, the full decode
conformance, the contract check and the A0 query/lifecycle/manifest replays.

Usage: the same as mutate_mcp.py
  mutate_decode.py                     every mutant, then the clean-tree check
  mutate_decode.py --part K/N          the mutants whose position is K-1 modulo N
  mutate_decode.py --clean-only        only the clean-tree check and the hash
  mutate_decode.py --assemble FILE...  merge the parts and the clean-tree output
  mutate_decode.py --anchors           only say which mutants' anchors are not unique in their file (no build, no run)
  mutate_decode.py NAME...             only the mutants whose name contains one of the words
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("mutate_mcp", ROOT / "artifacts/mdd-042/mutation/mutate_mcp.py")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

PY = base.PY
FACTS = "crates/mdd-facts/src/"
SMALI = FACTS + "smali/"
CONTEXT, VALUE, ANNOTATION, METHOD, CLASS = (SMALI + n for n in ("context.rs", "value.rs", "annotation.rs", "method.rs", "class.rs"))
CORE = FACTS + "smali_required/render.rs"
TOOLS, DECODE, DATASET = base.TOOLS, base.DECODE, base.DATASET

# the smali modules of mdd-facts: both directories (the filter matches smali:: and smali_required::)
base.UNIT_SMALI = [*base.CARGO, "-p", "mdd-facts", "--lib", "smali", *base.TAIL]
base.REPLAYS = [
    *base.REPLAYS,
    ("full decode", [PY, "-I", "conformance/decode/run_decode_full.py"]),
    ("decode contract", [PY, "-I", "conformance/decode/build_decode_contract.py", "--check"]),
]
base.CONTROLS = [*base.CONTROLS, [PY, "-I", "conformance/decode/test_decode_full.py"]]
base.SOURCES = [
    *base.SOURCES,
    SMALI + "mod.rs", CONTEXT, VALUE, ANNOTATION, METHOD, CLASS,
    "conformance/decode/oracle_class.py", "conformance/decode/run_decode_full.py", "conformance/decode/test_decode_full.py",
    "conformance/decode/hand-expected-class.txt", "conformance/decode/build_decode_contract.py", "conformance/mcp/decode-full-contract.json",
    "tests/fixtures/decode/generate_class.py", "tests/fixtures/decode/class-manifest.json",
]
base.FIXTURES = [*base.FIXTURES, "tests/fixtures/decode/generated/decode-class.dex", "tests/fixtures/annotations/generated/annotations-038.dex"]

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
    # No engine input tells this one from the original: the debug layer fills `source_line` only for a usable position, so the guard
    # repeats what `Some(line)` already says. It is a defence against an event built another way, and the unit test
    # `only_a_position_the_debug_layer_calls_usable_is_written_as_a_line` builds exactly such an event.
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
    ("service: annotations wait for the references layer", DATASET, [("let kept_annotations = annotation_layer.as_ref().ok().map(Arc::clone);", "let kept_annotations = upper_result.as_ref().ok().and_then(|_| annotation_layer.as_ref().ok().map(Arc::clone));")]),
    # ---- the tool
    ("tool: a class defaults to the smali mode", TOOLS, [("let mode = requested.unwrap_or(if args.class.is_some() {\n        DecodeMode::Summary", "let mode = requested.unwrap_or(if args.class.is_some() {\n        DecodeMode::Smali")]),
    ("tool: a class page accepts a text offset", TOOLS, [("        if args.offset != 0 {\n            return Err(refuse_here(ErrorCode::InvalidArgument, CLASS_TEXT_PAGE).into());", "        if false {\n            return Err(refuse_here(ErrorCode::InvalidArgument, CLASS_TEXT_PAGE).into());")]),
    ("tool: the default method_limit is 21", TOOLS, [("pub const DEFAULT_METHOD_LIMIT: u64 = 20;", "pub const DEFAULT_METHOD_LIMIT: u64 = 21;")]),
    ("tool: the last page names a continuation", TOOLS, [("(next_method_offset < page.total_methods).then_some(next_method_offset)", "Some(next_method_offset)")]),
    ("tool: the byte budget of a class page is not spent", TOOLS, [("                *left -= text_page.text.len() as u64;", "                let _ = left;")]),
    ("tool: a used-up budget fails the page instead of ending it", TOOLS, [('Err(error) if error.message == "MAX_BYTES_TOO_SMALL" && !rows.is_empty() => break,', 'Err(error) if error.message == "MAX_BYTES_TOO_SMALL" && false => break,')]),
    ("tool: every page of a class repeats the class text", TOOLS, [("let class_text = if mode != DecodeMode::Summary && method_offset == 0 {", "let class_text = if mode != DecodeMode::Summary {")]),
    ("tool: a context names the wrong line count of the full text", TOOLS, [("source_lines: Some(full.split_terminator('\\n').count() as u64),", "source_lines: Some(full.split_terminator('\\n').count() as u64 + 1),")]),
    ("tool: a context is labelled with the smali format", TOOLS, [("Self::Context => Some(smali::CONTEXT_FORMAT),", "Self::Context => Some(smali::SMALI_FORMAT),")]),
    ("tool: a method row hides what its text leaves out", TOOLS, [("        fields.extend(text_fields(&page, shown.source_lines));\n        if let Some(left_out) = omitted(&decoded.report) {", "        fields.extend(text_fields(&page, shown.source_lines));\n        if let Some(left_out) = omitted(&decoded.report).filter(|_| false) {")]),
    ("tool: a class row hides what its text leaves out", TOOLS, [("                fields.extend(text_fields(&text_page, shown.source_lines));\n                if let Some(left_out) = omitted(&decoded.report) {", "                fields.extend(text_fields(&text_page, shown.source_lines));\n                if let Some(left_out) = omitted(&decoded.report).filter(|_| false) {")]),
    ("tool: an offset past the methods is not a range error", TOOLS, [('(error.message == decode::METHOD_OFFSET_PAST_END).then_some("invalid_range")', '(error.message == decode::METHOD_OFFSET_PAST_END).then_some("invalid_input")')]),
    ("tool: an ambiguous class is worded as a method", TOOLS, [('"class occurs in multiple DEX files; supply file_id from {}",', '"method occurs in multiple DEX files; supply file_id from {}",')]),
    ("tool: a class that is not found does not echo its file_id", TOOLS, [("            if let Some(file_id) = args.file_id {\n                error = error.detail(\"file_id\", file_id.to_string());\n            }\n            return Err(error.into());\n        }\n        Err(decode::Failure::Ambiguous { file_ids }) => {\n            return Err(with_kind(\n                decode_error(", "            return Err(error.into());\n        }\n        Err(decode::Failure::Ambiguous { file_ids }) => {\n            return Err(with_kind(\n                decode_error(")]),
    ("tool: a class page does not say the class text is cut", TOOLS, [('("truncated", json!(truncated)),', '("truncated", json!(false)),')]),
    ("tool: a summary of a class is limited by its text budget in the wrong unit", TOOLS, [("let size = row.to_string().len() as u64;", "let size = 1;")]),
]

# The deadline handling of a decode is written twice (a method, a class): the same block, told apart by what follows it.
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
    # the three MDD-042 mutants whose anchors this task moved, and their twins in the class flow
    ("tool: an empty descriptor is looked up instead of refused", TOOLS,
     [('    if args.method.as_deref() == Some("") || args.class.as_deref() == Some("") {', "    if false {")]),
    ("tool: a text offset past the text is not called a range error", TOOLS,
     [('    let kind = if error.message.starts_with("OFFSET_") {\n        "invalid_range"', '    let kind = if error.message.starts_with("OFFSET_") {\n        "invalid_offset"')]),
    ("tool: a method decode deadline leaves the dataset open", TOOLS,
     [(_DEADLINE + "    let decoded = match result {", _WITHOUT_TIMEOUT_CLOSE + "    let decoded = match result {")]),
    ("tool: a class decode deadline leaves the dataset open", TOOLS,
     [(_DEADLINE + "    let ClassAnswer {", _WITHOUT_TIMEOUT_CLOSE + "    let ClassAnswer {")]),
]

base.MUTANTS = MUTANTS


def anchors() -> int:
    """Which anchors are not unique in their file (no build, no run)."""
    bad = 0
    for name, relative, edits in MUTANTS:
        text = (ROOT / relative).read_text(encoding="utf-8")
        for old, _new in edits:
            count = text.count(old)
            if count != 1:
                bad += 1
                print(f"ANCHOR {count}x  {name}  [{relative}]")
    print(f"{len(MUTANTS)} mutants, {bad} anchors that are not unique")
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--anchors"]:
        sys.exit(anchors())
    sys.exit(base.main())
