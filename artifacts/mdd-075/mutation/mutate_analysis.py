#!/usr/bin/env python3
"""Mutation check for the MDD-075 analysis (CFG, def-use, calls, reachability).

Usage: python -I artifacts/mdd-075/mutation/mutate_analysis.py

Each mutant edits one source file in place and runs the Rust analysis tests and, where
the mutant could be caught by it, the independent oracle. A mutant that does not build
is an ERROR, not a kill. The original bytes are held in memory and written back in a
finally block. The last line carries the hash of the analysis sources, the opcode
reference they are checked against, and every test and fixture, so a recorded result can
be told from a stale one.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RUST = ["cargo", "test", "--offline", "--locked", "-p", "mdd-facts", "--lib", "analysis"]
ORACLE = [sys.executable, "-I", "conformance/analysis/oracle.py"]

BASE = "crates/mdd-facts/src/analysis/"
CFG, DEFUSE, REACH, CALLS, OPCODES = (BASE + n for n in ("cfg.rs", "defuse.rs", "reach.rs", "calls.rs", "opcodes.rs"))

SOURCES = [
    BASE + "mod.rs", CFG, DEFUSE, REACH, CALLS, OPCODES, BASE + "tests.rs",
    "conformance/analysis/soundness-cases.json", "conformance/analysis/oracle.py",
    "artifacts/mdd-023/aosp-reference/dex_instruction_list.h",
]

# (name, expected, file, [(old, new)])
MUTANTS = [
    ("an uncaught exception no longer leaves the method", "killed", CFG,
     [("        if !caught_all {", "        if false {")]),
    ("fall-through issues are kept for dead blocks", "killed", CFG,
     [("        if reached[block.0 as usize] {", "        if true {")]),
    ("a try range no longer ends a block", "killed", CFG,
     [("        for boundary in [start, end] {", "        for boundary in [start] {")]),
    ("packed switch keys are off by one", "killed", CFG,
     [(".map(|n| (i64::from(*first_key) + n) as i32)", ".map(|n| (i64::from(*first_key) + n + 1) as i32)")]),
    ("a handler gets no state from the throwing instruction", "killed", DEFUSE,
     [("            if info(instruction.opcode).is_some_and(|i| i.may_throw) {",
       "            if false && info(instruction.opcode).is_some_and(|i| i.may_throw) {")]),
    ("a wide operand is treated as one register", "killed", DEFUSE,
     [("            let pair: Vec<Reg> = if slot.wide {", "            let pair: Vec<Reg> = if false && slot.wide {")]),
    ("move-result does not read the invoke's result", "killed", DEFUSE,
     [("    if inf.reads_result {", "    if false && inf.reads_result {")]),
    ("the dataflow budget is not enforced", "killed", DEFUSE,
     [("            if steps > budget.max_dataflow_steps {", "            if false && steps > budget.max_dataflow_steps {")]),
    ("a use is recorded once per mention", "killed", DEFUSE,
     [("            let distinct: BTreeSet<Reg> = all[position].uses.iter().copied().collect();",
       "            let distinct: Vec<Reg> = all[position].uses.clone();")]),
    ("no path is proven even when the graph is not well formed", "killed", REACH,
     [("        if !cfg.well_formed() {", "        if false && !cfg.well_formed() {")]),
    ("an exception edge is usable from before its throwing instruction", "killed", REACH,
     [("            if restricted && edge.source_offset < from {",
       "            if false && restricted && edge.source_offset < from {")]),
    ("the search cannot go round a loop back into the start block", "killed", REACH,
     [("            let next: Node = (to, false);", "            let next: Node = (to, true);")]),
    ("every path is reported as certain", "killed", REACH,
     [("            if definite_only && edge.certainty != Certainty::Definite {", "            if false {")]),
    ("a virtual call is reported as the named method", "killed", CALLS,
     [("                    _ => Resolution::DispatchUnresolved,", "                    _ => Resolution::NamedOnly,")]),
    ("div-int is taken not to throw", "killed", OPCODES,
     [("        | 0x93 | 0x94 | 0x9e | 0x9f", "        | 0x94 | 0x9e | 0x9f")]),
]


def fixtures_digest() -> bytes:
    """Hash of every .dex fixture the real-data tests iterate over."""
    digest = hashlib.sha256()
    for path in sorted((ROOT / "tests/fixtures").rglob("*.dex")):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.digest()


def run(command: list[str]) -> int:
    done = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=1800, check=False)
    return done.returncode


def sources_sha256() -> str:
    digest = hashlib.sha256()
    for relative in SOURCES:
        digest.update((ROOT / relative).read_bytes())
    digest.update(fixtures_digest())
    return digest.hexdigest()


def one(name: str, expected: str, relative: str, edits: list[tuple[str, str]]) -> bool:
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
        builds = run([*RUST, "--no-run"]) == 0
        failed = builds and run(RUST) != 0
    finally:
        path.write_bytes(original)
    if path.read_bytes() != original:
        print(f"RESTORE FAILED for {relative}")
        raise SystemExit(2)
    verdict = "ERROR" if not builds else "KILLED" if failed else "SURVIVED"
    unexpected = verdict.lower() != expected
    print(f"{verdict:9}{name}" + (f"  (UNEXPECTED, wanted {expected})" if unexpected else ""))
    return not unexpected


def main() -> int:
    ok = True
    for name, expected, relative, edits in MUTANTS:
        ok = one(name, expected, relative, edits) and ok
    clean = run(RUST) == 0 and run(ORACLE) == 0
    print("restored tree passes the analysis tests and the oracle:", clean)
    print("sources sha256:", sources_sha256())
    return 0 if ok and clean else 1


if __name__ == "__main__":
    sys.exit(main())
