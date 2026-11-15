#!/usr/bin/env python3
"""Mutation check for the MDD-035 cross-path and combination tests.

Usage: python -I artifacts/mdd-035/mutation/mutate_query_paths.py

Each mutant edits one engine source file in place, runs the named test command and
records whether it failed (KILLED) or still passed (SURVIVED). The original bytes are
held in memory and written back in a finally block, so uncommitted work in the same
file is never lost. A mutant that survives is reported, not hidden.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CROSS = ["cargo", "test", "--offline", "--locked", "-p", "mdd-sql", "--test", "cross_path_equivalence"]
COMBO = ["cargo", "test", "--offline", "--locked", "-p", "mdd-sql", "--lib", "combo_tests"]

HOSTLAB = "crates/mdd-sql/src/provider/hostlab.rs"
REQUIRE_COVERAGE = "    fn require_coverage(&self, relation: HostLabRelation) -> MddResult<()> {\n"
REQUIRE_LAYER = "    fn require_layer(&self, relation: HostLabRelation) -> MddResult<()> {\n"

# (name, expected, command, file, [(old, new), ...])
MUTANTS = [
    (
        "typed IR orders text by UTF-8 bytes instead of UTF-16 code units",
        "killed",
        CROSS,
        "crates/mdd-query/src/ir/mod.rs",
        [(
            "(Self::Utf16(a), Self::Utf16(b)) => a.cmp(b),",
            "(Self::Utf16(a), Self::Utf16(b)) => String::from_utf16_lossy(a).cmp(&String::from_utf16_lossy(b)),",
        )],
    ),
    (
        "typed IR entity order ignores the DEX occurrence, so joins and groups merge occurrences",
        "killed",
        CROSS,
        "crates/mdd-query/src/ir/mod.rs",
        [
            ("&a.dex_occurrence_id,\n                kind(a.kind),", "&a.snapshot_id,\n                kind(a.kind),"),
            ("&b.dex_occurrence_id,\n                    kind(b.kind),", "&b.snapshot_id,\n                    kind(b.kind),"),
        ],
    ),
    (
        "SQL bridge writes text units little-endian, so byte order is no longer unit order",
        "killed",
        CROSS,
        "crates/mdd-sql/src/values.rs",
        [(
            "                for unit in &v.utf16 {\n                    bytes.extend(unit.to_be_bytes());",
            "                for unit in &v.utf16 {\n                    bytes.extend(unit.to_le_bytes());",
        )],
    ),
    (
        "cancel() no longer sets the cancellation flag",
        "killed",
        COMBO,
        "crates/mdd-sql/src/control.rs",
        [(
            "        self.inner.cancel.store(true, Ordering::Release);\n        if let Some(runtime) = self.runtime() {\n            runtime.cancellation().cancel()?;",
            "        if let Some(runtime) = self.runtime() {\n            runtime.cancellation().cancel()?;",
        )],
    ),
    (
        "next_offset skips one row",
        "killed",
        COMBO,
        "crates/mdd-sql/src/window.rs",
        [("truncated.then(|| window.offset + rows)", "truncated.then(|| window.offset + rows + 1)")],
    ),
    (
        "coverage ledger and require_layer both bypassed (a third guard, the fact accessor, remains)",
        "survived",
        COMBO,
        HOSTLAB,
        [
            (REQUIRE_COVERAGE, REQUIRE_COVERAGE + "        if true { return Ok(()); }\n"),
            (REQUIRE_LAYER, REQUIRE_LAYER + "        if true { return Ok(()); }\n"),
        ],
    ),
]


TEST_SOURCES = [
    "crates/mdd-sql/tests/cross_path_equivalence.rs",
    "crates/mdd-sql/src/provider/hostlab/combo_tests.rs",
]


def tests_sha256() -> str:
    digest = hashlib.sha256()
    for relative in TEST_SOURCES:
        digest.update((ROOT / relative).read_bytes())
    return digest.hexdigest()


def run(command: list[str]) -> int:
    done = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=1800, check=False)
    return done.returncode


def main() -> int:
    problems = 0
    for name, expected, command, relative, edits in MUTANTS:
        path = ROOT / relative
        original = path.read_bytes()
        text = original.decode("utf-8")
        for old, _new in edits:
            if text.count(old) != 1:
                print(f"SKIPPED  {name}: anchor not unique in {relative} ({text.count(old)})")
                problems += 1
                break
        else:
            mutated = text
            for old, new in edits:
                mutated = mutated.replace(old, new, 1)
            try:
                path.write_bytes(mutated.encode("utf-8"))
                builds = run(command + ["--no-run"]) == 0
                failed = builds and run(command) != 0
            finally:
                path.write_bytes(original)
            verdict = "ERROR" if not builds else "KILLED" if failed else "SURVIVED"
            note = "" if verdict.lower() == expected else f"  (UNEXPECTED, wanted {expected})"
            print(f"{verdict:9}{name}{note}")
            if verdict.lower() != expected:
                problems += 1
        if path.read_bytes() != original:
            print(f"RESTORE FAILED for {relative}")
            return 2
    clean = run(COMBO) == 0 and run(CROSS) == 0
    print("restored tree passes both test sets:", clean)
    print("tests sha256:", tests_sha256())
    return 0 if clean and not problems else 1


if __name__ == "__main__":
    sys.exit(main())
