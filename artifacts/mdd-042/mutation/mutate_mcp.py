#!/usr/bin/env python3
"""Mutation check for the MDD-042 MCP server (lifecycle, tables and query tools).

Usage: python -I artifacts/mdd-042/mutation/mutate_mcp.py

Each mutant edits one source file in place. The Rust tests of mdd-mcp and the MCP process
tests of mdd-cli run first; if they pass, the binary is rebuilt and the replay of the frozen
A0 recordings runs against it. A mutant that does not build is an ERROR, not a kill, and the
line says which suite killed it. The original bytes are held in memory and written back in a
finally block. The last line carries a hash of the sources, tests, replay scripts and the
fixtures and recordings they read, so a recorded result can be told from a stale one.
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
RUST = ["cargo", "test", "--offline", "--locked", "-p", "mdd-mcp", "-p", "mdd-cli", "--test", "mcp", "--lib"]
UNIT = ["cargo", "test", "--offline", "--locked", "-p", "mdd-mcp", "--lib"]
PROCESS = ["cargo", "test", "--offline", "--locked", "-p", "mdd-cli", "--test", "mcp"]
BUILD = ["cargo", "build", "--offline", "--locked", "-p", "mdd-cli"]
REPLAY = [PY, "-I", "conformance/mcp/golden_replay.py"]
CONTROLS = [PY, "-I", "conformance/mcp/test_golden_replay.py"]

SRC = "crates/mdd-mcp/src/"
TOOLS, SERVER, PROTOCOL = SRC + "tools.rs", SRC + "server.rs", SRC + "protocol.rs"

SOURCES = [
    TOOLS, SERVER, PROTOCOL, SRC + "lib.rs", SRC + "tool_schemas.json", "crates/mdd-cli/tests/mcp.rs",
    "conformance/mcp/mcp_client.py", "conformance/mcp/golden_replay.py", "conformance/mcp/test_golden_replay.py",
    "conformance/corpus/hostlab/required-variants.json",
    "conformance/corpus/hostlab/expected-results/hostlab-a0-golden.json",
    "conformance/manifests/tools-and-options.json",
]
FIXTURES = [
    "tests/fixtures/definitions/generated/definitions-038.dex",
    "tests/fixtures/definitions/generated/definitions-035.dex",
    "tests/fixtures/references/generated/classic-035.dex",
    "tests/fixtures/annotations/generated/annotations-038.dex",
    "tests/fixtures/instructions/generated/bad-reserved-opcode.dex",
]

# (name, file, [(old, new)])
MUTANTS = [
    ("the dataset quota admits one more", TOOLS,
     [("    if registry.open.len() >= registry.config.max_datasets {", "    if registry.open.len() > registry.config.max_datasets {")]),
    ("a closed dataset is reported as never minted", TOOLS,
     [("        if self.closed.iter().any(|closed| closed == id) {", "        if false && self.closed.iter().any(|closed| closed == id) {")]),
    ("a query that outlives its deadline leaves its dataset open", TOOLS,
     [("            // The statement cannot be stopped, so nothing may rely on this dataset any more.\n            registry.close(&id);\n", "")]),
    ("the byte budget is not enforced", TOOLS,
     [("    if size > budget {", "    if false && size > budget {")]),
    ("windows do not count the total", TOOLS,
     [("    let window = SqlWindow::new(args.offset, limit)?.counting_total();", "    let window = SqlWindow::new(args.offset, limit)?;")]),
    ("a limit of zero passes the argument check", TOOLS,
     [("    if !(1..=MAX_LIMIT).contains(&limit) {", "    if !(0..=MAX_LIMIT).contains(&limit) {")]),
    ("an unsigned integer is reported as signed", TOOLS,
     [("        SqlValue::U64(v) => json!({\"type\": \"uint64\", \"value\": v.0.to_string()}),",
       "        SqlValue::U64(v) => json!({\"type\": \"int64\", \"value\": v.0.to_string()}),")]),
    ("text with an unpaired surrogate is quietly repaired", TOOLS,
     [("            Err(_) => return Err(unrepresentable(\"text holds an unpaired surrogate\")),",
       "            Err(_) => json!({\"type\": \"utf8\", \"value\": String::from_utf16_lossy(&text.utf16)}),")]),
    ("the timing option is accepted and ignored", TOOLS,
     [("    if args.timing {", "    if false && args.timing {")]),
    ("layer diagnostics are dropped from open_dataset", TOOLS,
     [("        \"diagnostics\": diagnostics,", "        \"diagnostics\": json!([]),")]),
    ("closing twice does not say it was already closed", TOOLS,
     [("Ok(json!({\"dataset_id\": args.dataset_id, \"closed\": true, \"already_closed\": true}))",
       "Ok(json!({\"dataset_id\": args.dataset_id, \"closed\": true, \"already_closed\": false}))")]),
    ("a shorter deadline than the server's is refused", TOOLS,
     [("        Some(ms) if ms > config.operation_timeout_ms => Err(invalid(", "        Some(ms) if ms >= config.operation_timeout_ms => Err(invalid(")]),
    ("initialize may be sent twice", SERVER,
     [("        if self.phase != Phase::Fresh {", "        if false && self.phase != Phase::Fresh {")]),
    ("tools can be used before initialize", SERVER,
     [("        if self.phase == Phase::Fresh {", "        if false && self.phase == Phase::Fresh {")]),
    ("a notification is answered", SERVER,
     [("            Ok(Message::Notification { .. } | Message::Response) => None,", "            Ok(Message::Notification { .. } | Message::Response) => Some(json!({})),")]),
    ("an unsupported revision is echoed back", SERVER,
     [("            .unwrap_or(&protocol::SUPPORTED_VERSIONS[0]);", "            .unwrap_or(&asked);")]),
    ("a null id is accepted", PROTOCOL,
     [("        Some(id) if id.is_string() || id.is_i64() || id.is_u64() => Some(id.clone()),",
       "        Some(id) if id.is_string() || id.is_i64() || id.is_u64() || id.is_null() => Some(id.clone()),")]),
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
    return subprocess.run(command, cwd=ROOT, capture_output=True, timeout=1800, check=False).returncode


def suite_verdict() -> tuple[str, bool]:
    """('rust'|'replay'|'none', builds)"""
    if run([*UNIT, "--no-run"]) != 0 or run([*PROCESS, "--no-run"]) != 0:
        return "none", False
    if run(UNIT) != 0 or run(PROCESS) != 0:
        return "rust", True
    if run(BUILD) != 0:
        return "none", False
    if run(REPLAY) != 0:
        return "replay", True
    return "none", True


def one(name: str, relative: str, edits: list[tuple[str, str]]) -> bool:
    path = ROOT / relative
    original = path.read_bytes()
    text = original.decode("utf-8")
    for old, _new in edits:
        if text.count(old) != 1:
            print(f"SKIPPED  {name}: anchor not unique in {relative} ({text.count(old)})")
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
    print(f"{verdict:9}{name}{suffix}")
    return verdict == "KILLED"


def main() -> int:
    ok = True
    for name, relative, edits in MUTANTS:
        ok = one(name, relative, edits) and ok
    clean = (run(UNIT) == 0 and run(PROCESS) == 0 and run(BUILD) == 0 and run(REPLAY) == 0 and run(CONTROLS) == 0)
    print("restored tree passes the MCP tests, the A0 replay and its controls:", clean)
    print("sources sha256:", sources_sha256())
    return 0 if ok and clean else 1


if __name__ == "__main__":
    sys.exit(main())
