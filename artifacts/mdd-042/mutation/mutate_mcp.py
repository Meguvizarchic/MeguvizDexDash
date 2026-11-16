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

Usage:
  mutate_mcp.py                     every mutant, then the clean-tree check (about an hour on one machine; four minutes in four parts on Actions)
  mutate_mcp.py --part K/N          the mutants whose position is K-1 modulo N (run N of them in parallel)
  mutate_mcp.py --clean-only        only the clean-tree check and the hash
  mutate_mcp.py --assemble FILE...  merge the outputs of the parts and the clean-tree check into one
                                    result in mutant order, and fail unless every mutant appears once
  mutate_mcp.py NAME...             only the mutants whose name contains one of the words

Every command has its own time limit. A command that outlives it is killed together with the
processes it started and the mutant gets the verdict TIMEOUT (with the tail of the command's
output on stderr); that is neither a kill nor a survivor, and the check fails. MUTATION_DIAGNOSE=1
runs the Rust suites one test at a time with their output shown, so a hang names its test.
"""
from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PYTHON = ROOT / ".venv" / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
PY = str(PYTHON if PYTHON.exists() else sys.executable)
DIAGNOSE = os.environ.get("MUTATION_DIAGNOSE") == "1"
CARGO = ["cargo", "test", "--offline", "--locked"]
# one test at a time, output shown: the last "test x ..." line without a result names a hang
TAIL = ["--", "--test-threads=1", "--nocapture"] if DIAGNOSE else []
UNIT_MCP = [*CARGO, "-p", "mdd-mcp", "-p", "mdd-service", "--lib", *TAIL]
UNIT_SMALI = [*CARGO, "-p", "mdd-facts", "--lib", "smali_required", *TAIL]
PROCESS = [*CARGO, "-p", "mdd-cli", "--test", "mcp", *TAIL]
# minutes a command may take; the whole process suite takes seconds and a replay under a minute
LIMITS = {"cargo": 15 * 60, "python": 10 * 60}
TIMEOUT = -9999
BUILD = ["cargo", "build", "--offline", "--locked", "-p", "mdd-cli"]
REPLAYS = [
    ("golden", [PY, "-I", "conformance/mcp/golden_replay.py"]),
    ("lifecycle", [PY, "-I", "conformance/mcp/lifecycle_replay.py"]),
    ("decode", [PY, "-I", "conformance/decode/run_decode_conformance.py"]),
    ("manifest", [PY, "-I", "conformance/mcp/manifest_replay.py"]),
    ("reference answers", [PY, "-I", "conformance/decode/a0_replay.py"]),
]
CONTROLS = [
    [PY, "-I", "conformance/mcp/test_golden_replay.py"],
    [PY, "-I", "conformance/mcp/test_replays.py"],
    [PY, "-I", "conformance/decode/test_a0_replay.py"],
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
    # ---- decode and get_manifest: what a client reads when a request fails or has no text
    ("a summary has no next_offset", TOOLS,
     [('            fields.insert("next_offset".to_owned(), Value::Null);', '            let _ = &fields;')]),
    ("a method that is not found does not echo the request", TOOLS,
     [('''"not_found");
            if let Some(file_id) = args.file_id {''', '''"not_found");
            if let Some(file_id) = args.file_id.filter(|_| false) {''')]),
    ("an empty descriptor is looked up instead of refused", TOOLS,
     [('    if args.method.as_deref() == Some("") || args.class.as_deref() == Some("") {', '    if false {')]),
    ("an offset past the text is not called a range error", TOOLS,
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
    ("a decode deadline leaves the dataset open", TOOLS,
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


LAST_OUTPUT = ""


def kill_tree(process: subprocess.Popen) -> None:
    """End the command and everything it started: a hung test leaves its server behind."""
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True, check=False)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def run(command: list[str]) -> int:
    """The exit code, or TIMEOUT. The output of the last command is kept in LAST_OUTPUT."""
    global LAST_OUTPUT
    limit = LIMITS["cargo" if command[0] == "cargo" else "python"]
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=(os.name != "nt"))
    try:
        output, _ = process.communicate(timeout=limit)
    except subprocess.TimeoutExpired:
        kill_tree(process)
        try:
            output, _ = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            output = b""
        LAST_OUTPUT = output.decode("utf-8", "replace")
        print(f"# TIMEOUT after {limit} s: {' '.join(command)}", file=sys.stderr, flush=True)
        print(LAST_OUTPUT[-4000:], file=sys.stderr, flush=True)
        return TIMEOUT
    LAST_OUTPUT = output.decode("utf-8", "replace")
    return process.returncode


def suite_verdict() -> tuple[str, bool]:
    """(the suite that failed, or 'none'; whether it builds). A suite that timed out is 'TIMEOUT: <name>'."""
    for command in (UNIT_MCP, UNIT_SMALI, PROCESS):
        head = command[:command.index("--")] if "--" in command else command
        code = run([*head, "--no-run"])
        if code == TIMEOUT:
            return "TIMEOUT: build", True
        if code != 0:
            return "none", False
    for name, command in (("unit", UNIT_MCP), ("smali", UNIT_SMALI), ("process", PROCESS)):
        code = run(command)
        if code == TIMEOUT:
            return f"TIMEOUT: {name}", True
        if code != 0:
            return name, True
    code = run(BUILD)
    if code == TIMEOUT:
        return "TIMEOUT: binary build", True
    if code != 0:
        return "none", False
    for name, command in REPLAYS:
        code = run(command)
        if code == TIMEOUT:
            return f"TIMEOUT: {name} replay", True
        if code != 0:
            return name + " replay", True
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
    if killer.startswith("TIMEOUT"):
        print(f"TIMEOUT  {name} [{killer[len('TIMEOUT: '):]}]", flush=True)
        return False
    verdict = "ERROR" if not builds else "KILLED" if killer != "none" else "SURVIVED"
    suffix = f" [{killer}]" if verdict == "KILLED" else ""
    print(f"{verdict:9}{name}{suffix}", flush=True)
    return verdict == "KILLED"


def clean_tree() -> bool:
    """The unmutated tree passes every suite and the negative controls; prints the lines the result carries."""
    commands = (UNIT_MCP, UNIT_SMALI, PROCESS, BUILD, *[c for _n, c in REPLAYS], *CONTROLS)
    clean = True
    for command in commands:
        code = run(command)
        if code != 0:
            clean = False
            print("# the clean tree failed:", " ".join(command), "->", "TIMEOUT" if code == TIMEOUT else code, flush=True)
            print(LAST_OUTPUT[-2000:], file=sys.stderr, flush=True)
    print("restored tree passes the unit and process tests, the replays and their controls:", clean)
    apk = (ROOT / "artifacts/local/inputs/NewPipe_v0.28.6.apk").exists()
    print("public APK present for the manifest replay:", apk)
    print("sources sha256:", sources_sha256())
    return clean


VERDICTS = ("KILLED", "SURVIVED", "ERROR", "SKIPPED", "TIMEOUT")


def assemble(files: list[str]) -> int:
    """Merge part outputs (mutants) and the clean-tree output into one result, in mutant order."""
    by_name: dict[str, list[str]] = {}
    tail: list[str] = []
    for file in files:
        for line in Path(file).read_text(encoding="utf-8").splitlines():
            word = line.split(" ", 1)[0]
            if word in VERDICTS:
                known = [name for name, _r, _e in MUTANTS if line[len(word):].strip().startswith(name)]
                if known:
                    by_name.setdefault(max(known, key=len), []).append(line)
            elif line.startswith(("restored tree", "public APK", "sources sha256")):
                tail.append(line)
    problems = [name for name, _r, _e in MUTANTS if len(by_name.get(name, [])) != 1]
    for name in problems:
        print(f"# {name}: {len(by_name.get(name, []))} verdicts", file=sys.stderr)
    for name, _r, _e in MUTANTS:
        for line in by_name.get(name, [])[:1]:
            print(line)
    for line in tail:
        print(line)
    hashes = {line for line in tail if line.startswith("sources sha256")}
    if len(hashes) != 1 or any(h != "sources sha256: " + sources_sha256() for h in hashes):
        print("# the parts do not agree with this checkout's sources", file=sys.stderr)
        return 1
    return 1 if problems else 0


def main() -> int:
    args = sys.argv[1:]
    if args[:1] == ["--assemble"]:
        return assemble(args[1:])
    if args[:1] == ["--clean-only"]:
        return 0 if clean_tree() else 1
    part = None
    if args[:1] == ["--part"]:
        k, n = (int(x) for x in args[1].split("/"))
        assert 1 <= k <= n
        part, args = (k, n), args[2:]
    ok = True
    for position, (name, relative, edits) in enumerate(MUTANTS):
        if part and position % part[1] != part[0] - 1:
            continue
        if args and not any(word in name for word in args):
            continue
        ok = one(name, relative, edits) and ok
    if part or args:
        return 0 if ok else 1
    return 0 if clean_tree() and ok else 1


if __name__ == "__main__":
    sys.exit(main())
