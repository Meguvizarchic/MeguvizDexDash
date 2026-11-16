#!/usr/bin/env python3
"""Mutation check for the C ABI and the Python SDK (MDD-043).

Usage: python -I artifacts/mdd-043/mutation/mutate_abi.py

Each mutant edits one source file in place and runs the tests that should notice. A
mutant that does not build or parse is an ERROR, not a kill. Original bytes are held in
memory and written back in a finally block. Rust mutants run first; the library is then
rebuilt from clean sources before the Python mutants, which run against that library.
The last line carries the hash of every test source, so a recorded result can be told
from a stale one.

Every command has a time limit and is ended, with the processes it started, when it passes
it; the mutant then gets the verdict TIMEOUT, which is neither a kill nor a survivor. The
check takes a while (a Rust build per Rust mutant), so it runs in a GitHub workflow
(.github/workflows/mutation-abi.yml), not on a developer machine.
"""
from __future__ import annotations

import ast
import hashlib
import os
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RUST = ["cargo", "test", "--offline", "--locked", "-p", "mdd-ffi"]
PYTHON = [sys.executable, "-I", "-m", "unittest", "discover", "-s", "python/tests", "-t", "python"]
OWNERSHIP = [sys.executable, "-I", "conformance/abi/ownership_cases.py"]
# the library, and the worker binary that the SDK's worker transport starts
BUILD = ["cargo", "build", "--offline", "--locked", "-p", "mdd-ffi", "-p", "mdd-cli"]
LIMIT = 900
TIMEOUT = -9999

# The tests and the sources they test: a change to either makes the record stale.
TEST_SOURCES = [
    "crates/mdd-ffi/tests/abi_contract.rs",
    "python/tests/test_sdk.py",
    "python/tests/test_worker.py",
    "python/tests/stub_worker.py",
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
    "python/mdd/worker.py",
]

HANDLE = "crates/mdd-ffi/src/handle.rs"
ENGINE = "crates/mdd-ffi/src/engine.rs"
ABI = "crates/mdd-ffi/src/abi.rs"
CODEC = "crates/mdd-ffi/src/codec.rs"
CORE = "python/mdd/core.py"
CELLS = "python/mdd/_cells.py"
WORKER = "python/mdd/worker.py"

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


PYTHON_MUTANTS += [
    ("a worker whose output ends is not reported as lost", "killed", [PYTHON], WORKER,
     [(r"""raise self._lost("its output ended before the answer did", during=during)""",
       r"""raise errors.Closed("ended", code="SNAPSHOT_CLOSED", stage="sdk.worker")""")]),
    ("a line cut short is skipped instead of reported", "killed", [PYTHON], WORKER,
     [(r"""raise self._lost("its output stopped in the middle of a line", during=during, partial=data)""", "continue")]),
    ("a silent worker is never ended at the caller's deadline", "killed", [PYTHON], WORKER,
     [("                if deadline is not None and time.monotonic() >= deadline:", "                if False:")]),
    ("batches out of order are accepted", "killed", [PYTHON], WORKER,
     [("                if sequence != next_sequence or first_row != next_row:", "                if False:")]),
    ("an answer for another request is accepted", "killed", [PYTHON], WORKER,
     [("                if message.get(\"id\") != self.id:", "                if False:")]),
    ("a line over the limit is not refused", "killed", [PYTHON], WORKER,
     [(r"""            if len(line) > limit and not line.endswith(b"\n"):""", "            if False:")]),
    ("delivered rows are not counted in the loss report", "killed", [PYTHON], WORKER,
     [("                worker._delivered[\"rows\"] += len(rows)", "                worker._delivered[\"rows\"] += 0")]),
    ("a refusal to start is reported as a loss", "killed", [PYTHON], WORKER,
     [("        if exit_code not in (1, 2):", "        if True:")]),
    ("a failure terminal is not raised", "killed", [PYTHON], WORKER,
     [("        if terminal is not None and terminal.get(\"operation_status\") != \"ok\":", "        if False:")]),
    ("an incomplete result is returned", "killed", [PYTHON], WORKER,
     [("        if not result.is_complete:", "        if False:")]),
    ("a second query is accepted while one is open", "killed", [PYTHON], WORKER,
     [("        if not self._busy.acquire(blocking=False):", "        if False:")]),
    ("an abandoned query leaves the worker running out of step", "killed", [PYTHON], WORKER,
     [("        if not ended and worker._dead is None and not worker._closing:", "        if False:")]),
    ("cancel does not end the worker", "killed", [PYTHON], WORKER,
     [("        if worker._dead is None and not worker._closing:\n            worker._die(errors.Cancelled(\"the query was cancelled", "        if False:\n            worker._die(errors.Cancelled(\"the query was cancelled")]),
    ("a worker that outstays its grace period is not killed", "killed", [PYTHON], WORKER,
     [("    if process.poll() is not None:\n        return\n", "    return\n")]),
    ("a dropped worker is not reaped", "killed", [PYTHON], WORKER,
     [("        self._finalizer = weakref.finalize(self, _reap, self._process, self._stop, grace)", "        self._finalizer = weakref.finalize(self, lambda: None)")]),
    ("a worker's output pipes are never closed", "killed", [PYTHON], WORKER,
     [("        if stream is not None:\n            stream.close()", "        if False:\n            stream.close()")]),
]


def run(command: list[str]) -> int:
    """The exit code, or TIMEOUT after LIMIT seconds (the command and what it started are ended)."""
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=(os.name != "nt"))
    try:
        process.communicate(timeout=LIMIT)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True, check=False)
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            pass
        print("# TIMEOUT:", " ".join(command), file=sys.stderr, flush=True)
        return TIMEOUT
    return process.returncode


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
        codes = []
        for command in commands:
            if not builds:
                break
            codes.append(run(command))
            if codes[-1] != 0:
                break
        timed_out = TIMEOUT in codes
        failed = builds and any(code != 0 for code in codes)
    finally:
        path.write_bytes(original)
    if path.read_bytes() != original:
        print(f"RESTORE FAILED for {relative}")
        raise SystemExit(2)
    verdict = "ERROR" if not builds else "TIMEOUT" if timed_out else "KILLED" if failed else "SURVIVED"
    unexpected = verdict.lower() != expected
    print(f"{verdict:9}{name}" + (f"  (UNEXPECTED, wanted {expected})" if unexpected else ""), flush=True)
    return not unexpected


def main() -> int:
    flags = set(sys.argv[1:])
    ok = True
    if "--python-only" not in flags:
        for mutant in RUST_MUTANTS:
            ok = one(*mutant) and ok
    # The library on disk must come from clean sources before the Python mutants.
    clean = run(BUILD) == 0
    if "--rust-only" not in flags:
        for mutant in PYTHON_MUTANTS:
            ok = one(*mutant) and ok
    if flags:
        return 0 if ok and clean else 1
    clean = clean and run(BUILD) == 0 and run(RUST) == 0 and run(PYTHON) == 0 and run(OWNERSHIP) == 0
    print("restored tree passes every test set:", clean)
    print("tests sha256:", tests_sha256())
    return 0 if ok and clean else 1


if __name__ == "__main__":
    sys.exit(main())
