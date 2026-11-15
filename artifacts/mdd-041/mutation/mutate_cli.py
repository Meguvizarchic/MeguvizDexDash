#!/usr/bin/env python3
"""Mutation check for the MDD-041 command line.

Usage: python -I artifacts/mdd-041/mutation/mutate_cli.py

Each mutant edits one source file in place, then the Rust tests of mdd-cli run; if they
pass, the binary is rebuilt and the frozen cases of conformance/cli run against it. A
mutant that does not build is an ERROR, not a kill, and the line says which suite killed
it. The original bytes are held in memory and written back in a finally block. The last
line carries a hash of the sources, tests, frozen cases and the B0 adapter, so a recorded
result can be told from a stale one.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PYTHON = ROOT / ".venv" / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
RUST = ["cargo", "test", "--offline", "--locked", "-p", "mdd-cli", "-p", "mdd-service", "--lib", "--bins", "--test", "cli"]
BUILD = ["cargo", "build", "--offline", "--locked", "-p", "mdd-cli"]
CASES = [str(PYTHON if PYTHON.exists() else sys.executable), "-I", "conformance/cli/cli_cases.py"]
CONTROLS = [str(PYTHON if PYTHON.exists() else sys.executable), "-I", "conformance/cli/test_cli_cases.py"]

SRC = "crates/mdd-cli/src/"
SERVICE = "crates/mdd-service/src/"
MAIN, SERVE, ARGS, OUTPUT = (SRC + n for n in ("main.rs", "serve.rs", "args.rs", "output.rs"))
RUN, DATASET, LINES = (SERVICE + n for n in ("run.rs", "dataset.rs", "lines.rs"))

SOURCES = [
    MAIN, RUN, SERVE, ARGS, OUTPUT, DATASET, LINES, SRC + "commands.rs", SERVICE + "lib.rs", "crates/mdd-cli/tests/cli.rs",
    "conformance/cli/command-and-output-cases.json", "conformance/cli/cli_cases.py",
    "conformance/cli/test_cli_cases.py", "benchmarks/hostlab-b0-pipeline.py",
    "benchmarks/workloads/b0-bulk-statements.json",
]

# (name, file, [(old, new)])
MUTANTS = [
    ("the row limit lets one extra row through", RUN,
     [("            if start as u64 >= allowed {", "            if start as u64 > allowed {")]),
    ("a batch is never acknowledged", RUN,
     [("            handle.acknowledge()?;\n", "")]),
    ("batch sequence numbers do not advance", RUN,
     [("            sequence += 1;\n", "")]),
    ("every batch claims to start at row zero", RUN,
     [("codec::batch_bytes(&columns, chunk, sequence, start as u64)", "codec::batch_bytes(&columns, chunk, sequence, 0)")]),
    ("an empty result does not name its columns", RUN,
     [("builder.succeed(self.data())", "builder.succeed(None)")]),
    ("a request deadline is ignored", RUN,
     [("            Some(ms) => Ok(ResourceLimits {\n                deadline_ms: ms,",
       "            Some(ms) => Ok(ResourceLimits {\n                deadline_ms: base.deadline_ms,")]),
    ("a request may raise the deadline above the ceiling", RUN,
     [("            Some(ms) if ms > base.deadline_ms => Err(", "            Some(ms) if false && ms > base.deadline_ms => Err(")]),
    ("every terminal exits zero", MAIN,
     [("    if terminal.operation_status == OperationStatus::Ok && terminal.error.is_none() {",
       "    if true || terminal.operation_status == OperationStatus::Ok {")]),
    ("a refusal exits one instead of two", MAIN,
     [("        _ => REFUSED,\n    }\n}\n\nfn terminal_code", "        _ => FAILED,\n    }\n}\n\nfn terminal_code")]),
    ("a half table is printed for a failed statement", MAIN,
     [("            if code == OK && sink.finish().is_err() {", "            if sink.finish().is_err() {")]),
    ("a closed pipe is reported as a failed statement", MAIN,
     [("            if outcome.output_lost.is_some() || sink.terminal(&outcome.terminal).is_err() {\n                return Ok(OUTPUT);",
       "            if outcome.output_lost.is_some() || sink.terminal(&outcome.terminal).is_err() {\n                return Ok(FAILED);")]),
    ("close does not end the session", SERVE,
     [("            Some(\"close\") => return Ok(()),", "            Some(\"close\") => continue,")]),
    ("an over-long request is accepted", LINES,
     [("            if line.len() + take > max_bytes + 1 {", "            if line.len() + take > max_bytes * 2 {")]),
    ("a request that is not JSON ends the session", SERVE,
     [("                rejected(out, None, &invalid(format!(\"not a valid request: {error}\")))?;\n                continue;",
       "                rejected(out, None, &invalid(format!(\"not a valid request: {error}\")))?;\n                return Ok(());")]),
    ("a repeated option is accepted", ARGS,
     [("    if slot.replace(value).is_some() {", "    if slot.replace(value).is_some() && false {")]),
    ("zero is an acceptable batch size on the command line", ARGS,
     [("Some(rows) if (1..=u64::from(MAX_BATCH_ROWS)).contains(&rows) => rows as u32,",
       "Some(rows) if (0..=u64::from(MAX_BATCH_ROWS)).contains(&rows) => rows as u32,")]),
    ("dexsql-0.1.0 is read as dexsql-0.1.1", DATASET,
     [("\"dexsql-0.1.0\" => Ok(Self::DexSql010),", "\"dexsql-0.1.0\" => Ok(Self::DexSql011),")]),
    ("a stream line loses the request id", OUTPUT,
     [("        serde_json::to_string(&self.id).map_err(io_error)", "        serde_json::to_string(&None::<&str>).map_err(io_error)")]),
    ("a newline in text is printed raw", OUTPUT,
     [("            Ok('\\n') => out.push_str(\"\\\\n\"),", "            Ok('\\n') => out.push('\\n'),")]),
    ("the SQL budgets asked for are dropped for the contract dialects", DATASET,
     [("        let bridge = SqlBridge::new(Arc::new(provider), dialect.sql(), sql_limits)?;",
       "        let bridge = SqlBridge::new(Arc::new(provider), dialect.sql(), SqlLimits::default())?;")]),
    ("a failed layer is reported under the wrong name", DATASET,
     [("                            layers: \"code,references,annotations\",", "                            layers: \"\",")]),
]


def fixtures_digest() -> bytes:
    digest = hashlib.sha256()
    for relative in ("definitions/generated/definitions-038.dex", "instructions/generated/bad-reserved-opcode.dex",
                     "generated/multidex-stored.apk"):
        path = ROOT / "tests" / "fixtures" / relative
        digest.update(relative.encode())
        digest.update(path.read_bytes())
    return digest.digest()


def sources_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCES:
        digest.update((ROOT / relative).read_bytes())
    digest.update(fixtures_digest())
    return digest.hexdigest()


def run(command: list[str]) -> int:
    return subprocess.run(command, cwd=ROOT, capture_output=True, timeout=1800, check=False).returncode


def suite_verdict() -> tuple[str, bool]:
    """('rust'|'cases'|'none', builds)"""
    if run([*RUST, "--no-run"]) != 0:
        return "none", False
    if run(RUST) != 0:
        return "rust", True
    if run(BUILD) != 0:
        return "none", False
    if run(CASES) != 0:
        return "cases", True
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
    clean = run(RUST) == 0 and run(BUILD) == 0 and run(CASES) == 0 and run(CONTROLS) == 0
    print("restored tree passes the CLI tests, the frozen cases and their controls:", clean)
    print("sources sha256:", sources_sha256())
    return 0 if ok and clean else 1


if __name__ == "__main__":
    sys.exit(main())
