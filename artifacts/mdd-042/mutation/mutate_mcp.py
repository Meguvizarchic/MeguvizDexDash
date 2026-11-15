#!/usr/bin/env python3
"""Mutation check for the MDD-042 MCP server: lifecycle, tables, query, decode, get_manifest.

Usage: python -I artifacts/mdd-042/mutation/mutate_mcp.py

Each mutant edits one source file in place. The Rust unit tests (mdd-mcp, mdd-service and the
smali renderer of mdd-facts) and the MCP process tests of mdd-cli run first; if they pass,
the binary is rebuilt and the replays run against it: the frozen A0 query recordings, the
recorded lifecycle and decode sessions, the decode conformance (independent renderer and
hand-written texts) and the recorded NewPipe manifest summary. A mutant that does not build is
an ERROR, not a kill, and the line says which suite killed it. The original bytes are held in
memory and written back in a finally block. The last lines carry a hash of the sources, tests,
replay scripts, fixtures and recordings they read, so a recorded result can be told from a
stale one.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PYTHON = ROOT / ".venv" / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
PY = str(PYTHON if PYTHON.exists() else sys.executable)
CARGO = ["cargo", "test", "--offline", "--locked"]
UNIT_MCP = [*CARGO, "-p", "mdd-mcp", "-p", "mdd-service", "--lib"]
UNIT_SMALI = [*CARGO, "-p", "mdd-facts", "--lib", "smali_required"]
PROCESS = [*CARGO, "-p", "mdd-cli", "--test", "mcp"]
BUILD = ["cargo", "build", "--offline", "--locked", "-p", "mdd-cli"]
REPLAYS = [
    ("golden", [PY, "-I", "conformance/mcp/golden_replay.py"]),
    ("lifecycle", [PY, "-I", "conformance/mcp/lifecycle_replay.py"]),
    ("decode", [PY, "-I", "conformance/decode/run_decode_conformance.py"]),
    ("manifest", [PY, "-I", "conformance/mcp/manifest_replay.py"]),
]
CONTROLS = [
    [PY, "-I", "conformance/mcp/test_golden_replay.py"],
    [PY, "-I", "conformance/mcp/test_replays.py"],
]

MCP = "crates/mdd-mcp/src/"
TOOLS, SERVER, PROTOCOL = MCP + "tools.rs", MCP + "server.rs", MCP + "protocol.rs"
SERVICE = "crates/mdd-service/src/"
DECODE, DATASET, MANIFEST = SERVICE + "decode.rs", SERVICE + "dataset.rs", SERVICE + "manifest.rs"
SMALI = "crates/mdd-facts/src/smali_required/"
RENDER, PAGES = SMALI + "render.rs", SMALI + "mod.rs"

SOURCES = [
    TOOLS, SERVER, PROTOCOL, MCP + "lib.rs", MCP + "tool_schemas.json", "crates/mdd-cli/tests/mcp.rs",
    DECODE, DATASET, MANIFEST, SERVICE + "lib.rs", RENDER, PAGES, SMALI + "tests.rs",
    "conformance/mcp/mcp_client.py", "conformance/mcp/golden_replay.py", "conformance/mcp/test_golden_replay.py",
    "conformance/mcp/lifecycle_replay.py", "conformance/mcp/manifest_replay.py", "conformance/mcp/test_replays.py",
    "conformance/mcp/tiny_dex.py", "conformance/decode/oracle.py", "conformance/decode/run_decode_conformance.py",
    "conformance/decode/hand-expected.txt", "tests/fixtures/decode/generate.py", "tests/fixtures/decode/manifest.json",
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

# (name, file, [(old, new)]); the anchors are raw strings so the Rust escapes stay as written
MUTANTS = [
    # ---- lifecycle, quotas, errors
    ("the dataset quota admits one more", TOOLS,
     [("    if registry.open.len() >= registry.config.max_datasets {", "    if registry.open.len() > registry.config.max_datasets {")]),
    ("the total input byte quota is not enforced", TOOLS,
     [(".is_none_or(|total| total > registry.config.max_total_input_bytes)", ".is_none_or(|_total| false)")]),
    ("closing a dataset does not release it", TOOLS, [("        self.open.remove(position);\n", "        let _ = position;\n")]),
    ("a dataset that is not open is reported in other words", TOOLS,
     [(r'''is not open; call open_dataset first"),''', r'''is closed"),''')]),
    ("open_dataset says the input has no DEX", TOOLS, [('        "has_dex": true,', '        "has_dex": false,')]),
    ("open_dataset forgets the archive inputs", TOOLS, [('        "archive_inputs": archive_inputs,', '        "archive_inputs": json!([]),')]),
    ("open_dataset reports no input bytes", TOOLS, [('        "input_bytes": input_bytes,', '        "input_bytes": 0,')]),
    ("layer diagnostics are dropped from open_dataset", TOOLS, [('        "diagnostics": diagnostics,', '        "diagnostics": json!([]),')]),
    ("list_datasets leaves a limit out", TOOLS, [('            "max_resource_bytes": MAX_INPUT_BYTES_PER_DATASET,\n', "")]),
    ("a dataset closed by its deadline stays open (query)", TOOLS,
     [("            // The statement cannot be stopped, so nothing may rely on this dataset any more.\n            registry.close(&id);\n", "")]),
    ("the byte budget of query is not enforced", TOOLS,
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
    ("windows do not count the total", TOOLS,
     [("    let window = SqlWindow::new(args.offset, limit)?.counting_total();", "    let window = SqlWindow::new(args.offset, limit)?;")]),
    ("a limit of zero passes the argument check", TOOLS,
     [("    if !(1..=MAX_LIMIT).contains(&limit) {", "    if !(0..=MAX_LIMIT).contains(&limit) {")]),
    ("timing is accepted and ignored", TOOLS, [("    let timing = if args.timing {", "    let timing = if false && args.timing {")]),
    ("a non-negative integer is reported as int64", TOOLS,
     [('''        SqlValue::I64(v) if v.0 >= 0 => json!({"type": "uint64", "value": v.0.to_string()}),''',
       '''        SqlValue::I64(v) if v.0 >= 0 => json!({"type": "int64", "value": v.0.to_string()}),''')]),
    ("a negative integer is reported as uint64", TOOLS,
     [('''        SqlValue::I64(v) => json!({"type": "int64", "value": v.0.to_string()}),''',
       '''        SqlValue::I64(v) => json!({"type": "uint64", "value": v.0.to_string()}),''')]),
    ("an unsigned integer is reported as signed", TOOLS,
     [('        SqlValue::U64(v) => json!({"type": "uint64", "value": v.0.to_string()}),',
       '        SqlValue::U64(v) => json!({"type": "int64", "value": v.0.to_string()}),')]),
    ("text with an unpaired surrogate is quietly repaired", TOOLS,
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
    ("the decode cache answers for another method", TOOLS,
     [("            && (cached_file, cached_idx) == (located.file_id, located.method_idx)", "            && true")]),
    ("the code layer is lost when another layer fails", DATASET,
     [("                let kept_code = code.as_ref().ok().cloned();", "                let kept_code: Option<Arc<CodeFacts>> = None;")]),
    ("a decode deadline leaves the dataset open", TOOLS,
     [('''        Outcome::TimedOut => {
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
            return Err(panicked("decode")''', '''        Outcome::TimedOut => {
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
            return Err(panicked("decode")''')]),
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
    ("a signature protection level is named otherwise", MANIFEST, [('        ("protectionLevel", 2) => Some("signature"),', '        ("protectionLevel", 2) => Some("signatureOrSystem"),')]),
    ("an unresolved reference is not marked", MANIFEST, [("                    if *attribute { '?' } else { '@' }", "                    if *attribute { '@' } else { '?' }")]),
    ("a manifest page is one row too long", TOOLS, [("    let end = total.min(args.offset.saturating_add(limit));", "    let end = total.min(args.offset.saturating_add(limit + 1));")]),
    ("the last manifest page names a continuation", TOOLS, [("    let next_offset = (end < total).then_some(end);", "    let next_offset = Some(end);")]),
    ("a manifest page never says it is cut", TOOLS, [('        "truncated": next_offset.is_some(),', '        "truncated": false,')]),
    ("the byte budget of get_manifest is not enforced", TOOLS,
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
    ("the xml mode answers with the summary", TOOLS, [('        Some("xml") => {\n            return Err(with_kind(', '        Some("xml") if false => {\n            return Err(with_kind(')]),
]


def hash_files(relatives) -> bytes:
    digest = hashlib.sha256()
    for relative in relatives:
        digest.update(relative.encode())
        digest.update((ROOT / relative).read_bytes())
    return digest.digest()


def sources_sha256() -> str:
    digest = hashlib.sha256()
    digest.update(hash_files(SOURCES))
    digest.update(hash_files(FIXTURES))
    return digest.hexdigest()


def run(command: list[str]) -> int:
    return subprocess.run(command, cwd=ROOT, capture_output=True, timeout=3600, check=False).returncode


def suite_verdict() -> tuple[str, bool]:
    """(the suite that failed or 'none', whether it builds)"""
    unit = [UNIT_MCP, UNIT_SMALI]
    if any(run([*c, "--no-run"]) != 0 for c in [UNIT_MCP, UNIT_SMALI, PROCESS]):
        return "none", False
    for name, command in (("unit", UNIT_MCP), ("smali", UNIT_SMALI), ("process", PROCESS)):
        if run(command) != 0:
            return name, True
    if run(BUILD) != 0:
        return "none", False
    for name, command in REPLAYS:
        if run(command) != 0:
            return name + " replay", True
    del unit
    return "none", True


def one(name: str, relative: str, edits: list[tuple[str, str]]) -> bool:
    path = ROOT / relative
    original = path.read_bytes()
    text = original.decode("utf-8")
    for old, _new in edits:
        if text.count(old) != 1:
            print(f"SKIPPED  {name}: anchor not unique in {relative} ({text.count(old)})", flush=True)
            return False
    mutated = text
    for old, new in edits:
        mutated = mutated.replace(old, new, 1)
    try:
        path.write_bytes(mutated.encode("utf-8"))
        killer, builds = suite_verdict()
    finally:
        path.write_bytes(original)
    if path.read_bytes() != original:
        print(f"RESTORE FAILED for {relative}")
        raise SystemExit(2)
    verdict = "ERROR" if not builds else "KILLED" if killer != "none" else "SURVIVED"
    suffix = f" [{killer}]" if verdict == "KILLED" else ""
    print(f"{verdict:9}{name}{suffix}", flush=True)
    return verdict == "KILLED"


def main() -> int:
    only = sys.argv[1:]
    ok = True
    for name, relative, edits in MUTANTS:
        if only and not any(part in name for part in only):
            continue
        ok = one(name, relative, edits) and ok
    clean = all(run(c) == 0 for c in (UNIT_MCP, UNIT_SMALI, PROCESS, BUILD, *[c for _n, c in REPLAYS], *CONTROLS))
    print("restored tree passes the unit and process tests, the replays and their controls:", clean)
    apk = (ROOT / "artifacts/local/inputs/NewPipe_v0.28.6.apk").exists()
    print("public APK present for the manifest replay:", apk)
    print("sources sha256:", sources_sha256())
    return 0 if ok and clean else 1


if __name__ == "__main__":
    sys.exit(main())
