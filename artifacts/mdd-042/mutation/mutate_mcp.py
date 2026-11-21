#!/usr/bin/env python3
"""Mutation check for the MDD-042 MCP server: lifecycle, tables, query, decode, get_manifest.

Usage: python -I artifacts/mdd-042/mutation/mutate_mcp.py

Uses tools/mutation_harness.py with only the MCP/service/smali_required sources,
fixtures and replays relevant to MDD-042.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))

import mutation_harness as H  # noqa: E402

PY = H.PY
MCP = "crates/mdd-mcp/src/"
TOOLS, SERVER, PROTOCOL = MCP + "tools.rs", MCP + "server.rs", MCP + "protocol.rs"
TOOLS_DECODE, TOOLS_MANIFEST, TOOLS_SQL = MCP + "tools/decode.rs", MCP + "tools/manifest.rs", MCP + "tools/sql.rs"
SERVICE = "crates/mdd-service/src/"
INPUT = "crates/mdd-input/src/resources/"
FRAMEWORK, VALUE = INPUT + "framework.rs", INPUT + "value.rs"
DECODE, DATASET, MANIFEST = SERVICE + "decode.rs", SERVICE + "dataset.rs", SERVICE + "manifest.rs"
LAYERS = SERVICE + "layers.rs"
SMALI = "crates/mdd-facts/src/smali_required/"
RENDER, PAGES = SMALI + "render.rs", SMALI + "mod.rs"

SOURCES = [
    TOOLS, TOOLS_DECODE, TOOLS_MANIFEST, TOOLS_SQL, SERVER, PROTOCOL, MCP + "lib.rs", MCP + "tool_schemas.json", "crates/mdd-cli/tests/mcp.rs",
    DECODE, DATASET, LAYERS, MANIFEST, SERVICE + "lib.rs", RENDER, PAGES, SMALI + "tests.rs", FRAMEWORK, VALUE,
    "conformance/mcp/mcp_client.py", "conformance/mcp/golden_replay.py", "conformance/mcp/test_golden_replay.py",
    "conformance/mcp/lifecycle_replay.py", "conformance/mcp/manifest_replay.py", "conformance/mcp/test_replays.py",
    "conformance/mcp/tiny_dex.py", "conformance/decode/oracle.py", "conformance/decode/run_decode_conformance.py",
    "conformance/decode/hand-expected.txt", "tests/fixtures/decode/generate.py", "tests/fixtures/decode/manifest.json",
    "conformance/decode/a0_cases.py", "conformance/decode/a0_replay.py", "conformance/decode/test_a0_replay.py",
    "conformance/decode/a0-golden.json",
    "conformance/corpus/hostlab/required-variants.json",
    "conformance/corpus/hostlab/expected-results/hostlab-a0-golden.json",
    "conformance/manifests/tools-and-options.json", "conformance/dex/instruction-matrix.json",
    "evidence/compatibility/0.1.0/mcp-records.json",
    "artifacts/mdd-025/manifest/a0/summary-pages.json", "artifacts/mdd-025/manifest/a0/open.json",
    "artifacts/mdd-025/manifest/a0/close.json",
]

FIXTURES = [
    "tests/fixtures/definitions/generated/definitions-038.dex",
    "tests/fixtures/definitions/generated/definitions-035.dex",
    "tests/fixtures/references/generated/classic-035.dex",
    "tests/fixtures/annotations/generated/annotations-038.dex",
    "tests/fixtures/instructions/generated/bad-reserved-opcode.dex",
    "tests/fixtures/decode/generated/decode-all.dex",
    "tests/fixtures/decode/generated/decode-v035.dex",
    "tests/fixtures/decode/generated/decode-bad-invoke.dex",
    "tests/fixtures/decode/generated/manifest-small.apk",
    "tests/fixtures/decode/generated/no-manifest.apk",
]

MUTANTS = [
    # ---- lifecycle, quotas, errors
    ("the dataset quota admits one more", TOOLS,
     [("    if registry.open.len() >= registry.config.max_datasets {", "    if registry.open.len() > registry.config.max_datasets {")]),
    ("the total input byte quota is not enforced", TOOLS,
     [(".is_none_or(|total| total > registry.config.max_total_input_bytes)", ".is_none_or(|_total| false)")]),
    ("closing a dataset does not release it", TOOLS, [("        self.open.remove(position);\n", "        let _ = position;\n")]),
    ("a dataset that is not open is reported in other words", TOOLS,
     [(r'''is not open; call open_dataset first"),''', r'''is closed"),''')]),
    ("open_dataset says the input has no DEX", TOOLS, [('        "has_dex": dataset.has_dex(),', '        "has_dex": false,')]),
    ("open_dataset forgets the archive inputs", TOOLS, [('        "archive_inputs": archive_inputs,', '        "archive_inputs": json!([]),')]),
    ("open_dataset reports no input bytes", TOOLS, [('        "input_bytes": input_bytes,', '        "input_bytes": 0,')]),
    ("layer diagnostics are dropped from open_dataset", TOOLS, [('        "diagnostics": diagnostics,', '        "diagnostics": json!([]),')]),
    ("list_datasets leaves a limit out", TOOLS, [('            "max_resource_bytes": MAX_INPUT_BYTES_PER_DATASET,\n', "")]),
    ("a dataset closed by its deadline stays open (query)", TOOLS_SQL,
     [("            // The statement cannot be stopped, so nothing may rely on this dataset any more.\n            registry.close(&id);\n", "")]),
    ("the byte budget of query is not enforced", TOOLS_SQL,
     [('''    if size > budget {
        return Err(refuse(
            ErrorCode::QuotaExceeded,
            "the serialized result is over the byte budget",
        )
        .detail(
            "budget",''', '''    if false && size > budget {
        return Err(refuse(
            ErrorCode::QuotaExceeded,
            "the serialized result is over the byte budget",
        )
        .detail(
            "budget",''')]),
    ("windows do not count the total", TOOLS_SQL,
     [("    let window = SqlWindow::new(args.offset, limit)?.counting_total();", "    let window = SqlWindow::new(args.offset, limit)?;")]),
    ("a limit of zero passes the argument check", TOOLS_SQL,
     [("    if !(1..=MAX_LIMIT).contains(&limit) {", "    if !(0..=MAX_LIMIT).contains(&limit) {")]),
    ("timing is accepted and ignored", TOOLS_SQL, [("    let timing = if args.timing {", "    let timing = if false && args.timing {")]),
    ("a non-negative integer is reported as int64", TOOLS_SQL,
     [('''        SqlValue::I64(v) if v.0 >= 0 => json!({"type": "uint64", "value": v.0.to_string()}),''',
       '''        SqlValue::I64(v) if v.0 >= 0 => json!({"type": "int64", "value": v.0.to_string()}),''')]),
    ("a negative integer is reported as uint64", TOOLS_SQL,
     [('''        SqlValue::I64(v) => json!({"type": "int64", "value": v.0.to_string()}),''',
       '''        SqlValue::I64(v) => json!({"type": "uint64", "value": v.0.to_string()}),''')]),
    ("an unsigned integer is reported as signed", TOOLS_SQL,
     [('        SqlValue::U64(v) => json!({"type": "uint64", "value": v.0.to_string()}),',
       '        SqlValue::U64(v) => json!({"type": "int64", "value": v.0.to_string()}),')]),
    ("text with an unpaired surrogate is quietly repaired", TOOLS_SQL,
     [('            Err(_) => return Err(unrepresentable("text holds an unpaired surrogate")),',
       '            Err(_) => json!({"type": "utf8", "value": String::from_utf16_lossy(&text.utf16)}),')]),
    ("a dataset_closed error does not say so", TOOLS,
     [('''        .map(|value| value.as_str() == Some("true") || value == Value::Bool(true));''', '''        .map(|_| false);''')]),
    ("a statement error loses its index", TOOLS,
     [('''        .and_then(|text| text.parse::<u64>().ok());''', '''        .and_then(|_| None::<u64>);''')]),
    ("an unknown relation is worded as a code", TOOLS,
     [('''        ("UNKNOWN_RELATION", Some(name)) => format!("unknown relation `{name}`"),''',
       '''        ("UNKNOWN_RELATION", Some(_)) => error.message.clone(),''')]),
    ("a shorter deadline than the server's is refused", TOOLS,
     [("        Some(ms) if ms > config.operation_timeout_ms => Err(invalid(", "        Some(ms) if ms >= config.operation_timeout_ms => Err(invalid(")]),
    # ---- protocol
    ("initialize may be sent twice", SERVER, [("        if self.phase != Phase::Fresh {", "        if false && self.phase != Phase::Fresh {")]),
    ("tools can be used before initialize", SERVER, [("        if self.phase == Phase::Fresh {", "        if false && self.phase == Phase::Fresh {")]),
    ("a notification is answered", SERVER,
     [("            Ok(Message::Notification { .. } | Message::Response) => None,", "            Ok(Message::Notification { .. } | Message::Response) => Some(json!({})),")]),
    ("an unsupported revision is echoed back", SERVER, [("            .unwrap_or(&protocol::SUPPORTED_VERSIONS[0]);", "            .unwrap_or(&asked);")]),
    ("a null id is accepted", PROTOCOL,
     [("        Some(id) if id.is_string() || id.is_i64() || id.is_u64() => Some(id.clone()),",
       "        Some(id) if id.is_string() || id.is_i64() || id.is_u64() || id.is_null() => Some(id.clone()),")]),
    # ---- decode: selection, cache, layers
    ("a descriptor in two DEX files picks the first", DECODE, [("                [(file_id, position)] => {", "                [(file_id, position), ..] => {")]),
    ("the decode cache answers for another method", TOOLS_DECODE,
     [("            && (cached_file, cached_idx) == (located.file_id, located.method_idx)", "            && true")]),
    ("the code layer is lost when another layer fails", LAYERS,
     [("            code: compact_code.ok(),", "            code: compact_code.ok().and(None),")]),
    # ---- decode and get_manifest: what a client reads when a request fails or has no text
    ("a summary has no next_offset", TOOLS_DECODE,
     [('            fields.insert("next_offset".to_owned(), Value::Null);', '            let _ = &fields;')]),
    ("a method that is not found does not echo the request", TOOLS_DECODE,
     [('''"not_found");
            if let Some(file_id) = args.file_id {''', '''"not_found");
            if let Some(file_id) = args.file_id.filter(|_| false) {''')]),
    ("an empty descriptor is looked up instead of refused", TOOLS_DECODE,
     [('    if args.method.as_deref() == Some("") || args.class.as_deref() == Some("") {', '    if false {')]),
    ("an offset past the text is not called a range error", TOOLS_DECODE,
     [('''        "invalid_range"
    } else {
        "invalid_input"''', '''        "invalid_offset"
    } else {
        "invalid_input"''')]),
    ("a tool without arguments refuses the extra ones", TOOLS,
     [('''/// The tools that take no arguments ignore any that are sent, as the reference does.
#[derive(Deserialize)]
struct NoArgs {}''', '''#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoArgs {}''')]),
    ("a decode deadline leaves the dataset open", TOOLS_DECODE,
     [('''        )?))
    };
    let result = match with_deadline(ms, work) {
        Outcome::Done(result) => result,
        Outcome::TimedOut => {
            registry.close(&id);''', '''        )?))
    };
    let result = match with_deadline(ms, work) {
        Outcome::Done(result) => result,
        Outcome::TimedOut => {''')]),
    # ---- decode: the renderer
    ("parameter registers print as locals", RENDER, [("        if number >= self.first_parameter {", "        if false && number >= self.first_parameter {")]),
    ("a negative literal loses its sign", PAGES, [('        format!("-0x{:x}", value.unsigned_abs())', '        format!("0x{:x}", value.unsigned_abs())')]),
    ("a wide literal loses its L", RENDER, [('        if instruction.mnemonic.starts_with("const-wide") {', '        if false && instruction.mnemonic.starts_with("const-wide") {')]),
    ("goto and conditional labels are swapped", RENDER, [('        0x28..=0x2a => "goto_",', '        0x28..=0x2a => "cond_",')]),
    ("a try ends one unit late", RENDER,
     [('''            item.start_code_unit + u32::from(item.code_unit_count),
            "try_end_",''', '''            item.start_code_unit + u32::from(item.code_unit_count) + 1,
            "try_end_",''')]),
    ("the catch-all directive is dropped", RENDER,
     [("    if let Some(address) = handler.catch_all_address_code_units {\n        let _ = writeln!(", "    if let Some(address) = None::<u32> {\n        let _ = writeln!(")]),
    ("a byte array element loses its t", RENDER, [('        1 => "t",', '        1 => "",')]),
    ("a quote is not escaped in a string", PAGES, [(r'''            0x27 => out.push_str("\\'"),''', r'''            0x27 => out.push('\''),''')]),
    ("a backslash is not escaped in a string", PAGES, [(r'''            0x5c => out.push_str("\\\\"),''', r'''            0x5c => out.push('\\'),''')]),
    # ---- decode: paging
    ("a page holds one line too many", PAGES, [("    while end < total && taken < max_lines {", "    while end < total && taken <= max_lines {")]),
    ("the last page still names a continuation", PAGES, [("        next_offset: (end < total).then_some(end as u64),", "        next_offset: Some(end as u64),")]),
    ("a page never admits to starting mid-line", PAGES, [("    let starts_mid_line = start > 0 && bytes[start - 1] != b'\\n';", "    let starts_mid_line = false;")]),
    ("a cut may land inside a character", PAGES, [("                while stop > end && !text.is_char_boundary(stop) {", "                while false && stop > end && !text.is_char_boundary(stop) {")]),
    # ---- get_manifest
    ("a permission element is not listed", MANIFEST, [('const PERMISSION_ELEMENTS: [&str; 4] = [\n    "permission",', 'const PERMISSION_ELEMENTS: [&str; 4] = [\n    "permissionx",')]),
    ("a signature protection level is named otherwise", FRAMEWORK, [('    (2, "signature"),', '    (2, "signatureOrSystem"),')]),
    ("an unresolved reference is not marked", VALUE, [('ReferenceStyle::Compact => (format!("@{data:08x}"), format!("?{data:08x}")),', 'ReferenceStyle::Compact => (format!("?{data:08x}"), format!("@{data:08x}")),')]),
    ("a manifest page is one row too long", TOOLS_MANIFEST, [("    let end = total.min(args.offset.saturating_add(limit));", "    let end = total.min(args.offset.saturating_add(limit + 1));")]),
    ("the last manifest page names a continuation", TOOLS_MANIFEST, [("    let next_offset = (end < total).then_some(end);", "    let next_offset = Some(end);")]),
    ("a manifest page never says it is cut", TOOLS_MANIFEST, [('        "truncated": next_offset.is_some(),', '        "truncated": false,')]),
    ("the byte budget of get_manifest is not enforced", TOOLS_MANIFEST,
     [('''    if size > budget {
        return Err(refuse(
            ErrorCode::QuotaExceeded,
            "the serialized result is over the byte budget",
        )
        .detail("budget", "max_bytes")''', '''    if false && size > budget {
        return Err(refuse(
            ErrorCode::QuotaExceeded,
            "the serialized result is over the byte budget",
        )
        .detail("budget", "max_bytes")''')]),
    ("the xml mode answers with the summary", TOOLS_MANIFEST, [('        Some("xml") => return get_manifest_xml(registry, args),', '        Some("xml") => {}')]),
]

SUITE = H.MutationSuite(
    name="MDD-042",
    sources=SOURCES,
    fixtures=FIXTURES,
    unit_suites=[
        ("unit", [*H.CARGO, "-p", "mdd-mcp", "-p", "mdd-service", "-p", "mdd-input", "--lib", *H.TAIL]),
        ("smali", [*H.CARGO, "-p", "mdd-facts", "--lib", "smali_required", *H.TAIL]),
        ("process", [*H.CARGO, "-p", "mdd-cli", "--test", "mcp", *H.TAIL]),
    ],
    replays=[
        ("golden", [PY, "-I", "conformance/mcp/golden_replay.py"]),
        ("lifecycle", [PY, "-I", "conformance/mcp/lifecycle_replay.py"]),
        ("decode", [PY, "-I", "conformance/decode/run_decode_conformance.py"]),
        ("manifest", [PY, "-I", "conformance/mcp/manifest_replay.py"]),
        ("reference answers", [PY, "-I", "conformance/decode/a0_replay.py"]),
    ],
    controls=[
        [PY, "-I", "conformance/mcp/test_golden_replay.py"],
        [PY, "-I", "conformance/mcp/test_replays.py"],
        [PY, "-I", "conformance/decode/test_a0_replay.py"],
    ],
    mutants=MUTANTS,
    extra_clean_lines=lambda: [
        f"public APK present for the manifest replay: {(ROOT / 'artifacts/local/inputs/NewPipe_v0.28.6.apk').exists()}"
    ],
)


def sources_sha256() -> str:
    return SUITE.sources_sha256()


if __name__ == "__main__":
    sys.exit(SUITE.main())
