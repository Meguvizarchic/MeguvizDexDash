#!/usr/bin/env python3
"""Mutation check for the C ABI and the Python SDK (MDD-043).

Usage: python -I artifacts/mdd-043/mutation/mutate_abi.py

Each mutant edits one source file in place and runs the tests that should notice. A
mutant that does not build or parse is an ERROR, not a kill. Original bytes are held in
memory and written back in a finally block. Rust mutants run first; the library is then
rebuilt from clean sources before the Python mutants, which run against that library.
The last line carries the hash of every test source, so a recorded result can be told
from a stale one.
"""
from __future__ import annotations

import ast
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RUST = ["cargo", "test", "--offline", "--locked", "-p", "mdd-ffi"]
PYTHON = [sys.executable, "-I", "-m", "unittest", "discover", "-s", "python/tests", "-t", "python"]
OWNERSHIP = [sys.executable, "-I", "conformance/abi/ownership_cases.py"]
BUILD = ["cargo", "build", "--offline", "--locked", "-p", "mdd-ffi"]

# The tests and the sources they test: a change to either makes the record stale.
TEST_SOURCES = [
    "crates/mdd-ffi/tests/abi_contract.rs",
    "python/tests/test_sdk.py",
    "conformance/abi/ownership-cases.json",
    "conformance/abi/ownership_cases.py",
    "include/mdd.h",
    "crates/mdd-ffi/src/abi.rs",
    "crates/mdd-ffi/src/codec.rs",
    "crates/mdd-ffi/src/engine.rs",
    "crates/mdd-ffi/src/error.rs",
    "crates/mdd-ffi/src/handle.rs",
    "python/mdd/_cells.py",
    "python/mdd/_ffi.py",
    "python/mdd/core.py",
    "python/mdd/errors.py",
]

HANDLE = "crates/mdd-ffi/src/handle.rs"
ENGINE = "crates/mdd-ffi/src/engine.rs"
ABI = "crates/mdd-ffi/src/abi.rs"
CODEC = "crates/mdd-ffi/src/codec.rs"
CORE = "python/mdd/core.py"
CELLS = "python/mdd/_cells.py"

# (name, expected, command(s), file, [(old, new)])
RUST_MUTANTS = [
    ("a stale handle is accepted when its slot was reused (generation unchecked)", "killed", [RUST], HANDLE,
     [("Some(entry) if slot.generation == generation => Ok(entry.object.clone()),",
       "Some(entry) => Ok(entry.object.clone()),")]),
    ("the caller can release the reference an event owns (no pinning)", "killed", [RUST, OWNERSHIP], HANDLE,
     [("                    } else if entry.refs <= entry.pinned {", "                    } else if false && entry.refs <= entry.pinned {")]),
    ("release does not check the handle kind", "killed", [RUST, OWNERSHIP], HANDLE,
     [("        if kind != want {\n            return Err(stale(want));\n        }\n        let removed = {",
       "        let removed = {")]),
    ("acknowledge no longer reaches the core", "killed", [RUST], ENGINE,
     [("        self.handle.acknowledge()?;\n        self.acked.store(true, Ordering::Release);",
       "        self.acked.store(true, Ordering::Release);")]),
    ("an outstanding batch no longer blocks the next one", "killed", [RUST], ENGINE,
     [("            if weak.upgrade().is_some() {", "            if false && weak.upgrade().is_some() {")]),
    ("a second consumer is reported as CLOSED instead of BUSY", "killed", [RUST], ENGINE,
     [("                    Status::Busy,\n                    \"BUSY\",", "                    Status::Closed,\n                    \"BUSY\",")]),
    ("a query cancelled before it ran ends as INVALID_ARGUMENT, not CANCELLED", "killed", [RUST], ENGINE,
     [("                    let error = self.reconcile(error);\n", "")]),
    ("a failure terminal downgrades the facts coverage", "killed", [RUST], ENGINE,
     [("            facts: Completeness::Complete,\n            required_layers: required,",
       "            facts: Completeness::Partial,\n            required_layers: required,")]),
    ("cancel no longer stops the running statement", "killed", [RUST], ENGINE,
     [("    pub fn cancel(&self) -> SdkResult<()> {\n        let _ = self.control.cancel();",
       "    pub fn cancel(&self) -> SdkResult<()> {")]),
    ("a Rust panic is no longer contained at the boundary", "killed", [RUST], ABI,
     [("catch_unwind(AssertUnwindSafe(body))", "Ok::<SdkResult<()>, Box<dyn std::any::Any + Send>>(body())")]),
    ("text with an unpaired surrogate is made lossy", "killed", [RUST], CODEC,
     [("match String::from_utf16(&text.utf16) {",
       "match String::from_utf16(&text.utf16).or_else(|_| Ok::<String, ()>(String::from_utf16_lossy(&text.utf16))) {")]),
]

PYTHON_MUTANTS = [
    ("a closed object no longer refuses use", "killed", [PYTHON], CORE,
     [("        if self.closed:\n            raise errors.Closed(", "        if False:\n            raise errors.Closed(")]),
    ("a cancelled or failed terminal counts as a complete result", "killed", [PYTHON], CORE,
     [("    return (terminal.get(\"operation_status\") == \"ok\"", "    return True or (terminal.get(\"operation_status\") == \"ok\"")]),
    ("batches are not acknowledged", "killed", [PYTHON], CORE,
     [("                    lib.call(\"mdd_batch_ack_v1\", handle.value)\n", "")]),
    ("64-bit integers are decoded through a float", "killed", [PYTHON], CELLS,
     [("        return int(cell[\"v\"])", "        return float(cell[\"v\"])")]),
    ("unpaired surrogates are dropped when text is decoded", "killed", [PYTHON], CELLS,
     [("bytes.fromhex(cell[\"units\"]).decode(\"utf-16-be\", \"surrogatepass\")",
       "bytes.fromhex(cell[\"units\"]).decode(\"utf-16-be\", \"ignore\")")]),
]


def run(command: list[str]) -> int:
    done = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=1800, check=False)
    return done.returncode


def tests_sha256() -> str:
    digest = hashlib.sha256()
    for relative in TEST_SOURCES:
        digest.update((ROOT / relative).read_bytes())
    return digest.hexdigest()


def one(name: str, expected: str, commands: list[list[str]], relative: str, edits: list[tuple[str, str]]) -> bool:
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
        if relative.endswith(".py"):
            try:
                ast.parse(mutated)
                builds = True
            except SyntaxError:
                builds = False
        else:
            builds = run([*RUST, "--no-run"]) == 0
        failed = builds and any(run(command) != 0 for command in commands)
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
    for mutant in RUST_MUTANTS:
        ok = one(*mutant) and ok
    # The library on disk must come from clean sources before the Python mutants.
    clean = run(BUILD) == 0
    for mutant in PYTHON_MUTANTS:
        ok = one(*mutant) and ok
    clean = clean and run(BUILD) == 0 and run(RUST) == 0 and run(PYTHON) == 0 and run(OWNERSHIP) == 0
    print("restored tree passes every test set:", clean)
    print("tests sha256:", tests_sha256())
    return 0 if ok and clean else 1


if __name__ == "__main__":
    sys.exit(main())
