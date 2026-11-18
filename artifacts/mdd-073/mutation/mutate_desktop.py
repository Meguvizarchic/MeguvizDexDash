#!/usr/bin/env python3
"""Mutation check for MDD-073: small faults in the desktop workbench's logic, one at a time, each of which the
tests must catch.

What is mutated: the supervisor of the engine process (apps/desktop/src/engine.rs), the complete export
(export.rs), the comparison of two input sets (diff.rs) and the front end's pure functions (ui/lib/*.js).
What kills a mutant: the Rust unit tests and the process tests against the real engine (`cargo test` in
apps/desktop), or the front-end tests (`node --test ui-tests`). A mutant that hangs the suite is killed too (the
suite has a time limit). The real-window user flows are NOT part of this check (too slow per mutant); they have
their own record.

    python artifacts/mdd-073/mutation/mutate_desktop.py                 every mutant, then the clean tree
    python artifacts/mdd-073/mutation/mutate_desktop.py --anchors       only check that every anchor is unique
    python artifacts/mdd-073/mutation/mutate_desktop.py --clean-only    only the clean-tree run and the hashes
    python artifacts/mdd-073/mutation/mutate_desktop.py WORD...         only the mutants whose name has a word
    --out FILE                                                          where the results go

Needs the engine built first (`cargo build -p mdd-cli`). The original bytes of every edited file are written back
in a finally block. The result binds to the sha256 of every source and test file it ran against.
"""
from __future__ import annotations

import glob
import hashlib
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DESKTOP = ROOT / "apps" / "desktop"
WINDOWS = os.name == "nt"
RS = "apps/desktop/src/"
JS = "apps/desktop/ui/lib/"
CARGO = ["cargo", "test", "--locked", "--", "--test-threads=3"]
NODE = ["node", "--test", *sorted(glob.glob(str(DESKTOP / "ui-tests" / "*.test.mjs")))]
RUST_LIMIT = 300
NODE_LIMIT = 60

# (name, file, [(old, new)] or [(old, new, nth)]): an anchor without nth must occur exactly once in its file
MUTANTS = [
    # ---- engine.rs: the supervisor of the engine process
    ("engine: the poll interval makes a cancel wait seconds", RS + "engine.rs", [("const POLL: Duration = Duration::from_millis(20);", "const POLL: Duration = Duration::from_millis(20_000);")]),
    ("engine: the second dialect is not served", RS + "engine.rs", [('["dexsql-0.1.0", "dexsql-0.1.1"]', '["dexsql-0.1.0", "dexsql-0.1.2"]')]),
    ("engine: a zero setting is accepted", RS + "engine.rs", [("if value == 0 {", "if value == 1 {")]),
    ("engine: cancel stops whatever is running, whatever the id", RS + "engine.rs", [("Some(slot) if slot.call_id == call_id => {", "Some(slot) => {")]),
    ("engine: the busy error has another code", RS + "engine.rs", [('code: "ENGINE_BUSY".to_owned(),', 'code: "BUSY".to_owned(),')]),
    ("engine: stopping does not ask a running call to stop", RS + "engine.rs", [("""        if let Some(slot) = lock(&self.busy).as_ref() {
            slot.cancel.store(true, Ordering::SeqCst);
        }
        if let Some(session) = lock(&self.session).take() {""", """        if let Some(session) = lock(&self.session).take() {""")]),
    ("engine: any tool name is passed to the engine", RS + "engine.rs", [("if !session.tools.iter().any(|t| t == tool_name) {", "if false {")]),
    ("engine: the window may set the engine's dataset id", RS + "engine.rs", [('if object.contains_key("dataset_id") {', "if false {")]),
    ("engine: a cancelled call leaves the process running", RS + "engine.rs", [('"CANCELLED" | "DEADLINE_EXCEEDED" | "ENGINE_LOST" | "ENGINE_PROTOCOL"', '"DEADLINE_EXCEEDED" | "ENGINE_LOST" | "ENGINE_PROTOCOL"')]),
    ("engine: a folder is accepted as an input", RS + "engine.rs", [("if !meta.is_file() {", "if meta.is_file() {")]),
    ("engine: an empty input list is accepted", RS + "engine.rs", [("if inputs.is_empty() {", "if false {")]),
    ("engine: a dataset closed by a deadline is not forgotten", RS + "engine.rs", [('matches!(code, "DEADLINE_EXCEEDED" | "SNAPSHOT_CLOSED" | "NOT_FOUND")', 'matches!(code, "SNAPSHOT_CLOSED" | "NOT_FOUND")')]),
    ("engine: running() says the opposite", RS + "engine.rs", [("lock(&self.view).running", "!lock(&self.view).running")]),
    # ---- export.rs: the complete export
    ("export: a page may be larger than the engine serves", RS + "export.rs", [("pub const MAX_PAGE_ROWS: usize = 1000;", "pub const MAX_PAGE_ROWS: usize = 5000;")]),
    ("export: a page of zero rows is asked for", RS + "export.rs", [(".clamp(1, MAX_PAGE_ROWS)", ".clamp(0, MAX_PAGE_ROWS)")]),
    ("export: empty text is not quoted", RS + "export.rs", [("let needs_quotes = text.is_empty()", "let needs_quotes = false")]),
    ("export: a leading space is not quoted", RS + "export.rs", [("|| text.starts_with(' ')", "|| false")]),
    ("export: binary has no 0x", RS + "export.rs", [('("binary", Value::String(hex)) => format!("0x{hex}"),', '("binary", Value::String(hex)) => format!("{hex}"),')]),
    ("export: the page statement has no total order", RS + "export.rs", [(") ORDER BY {} LIMIT {rows} OFFSET {offset}", ") LIMIT {rows} OFFSET {offset}{}")]),
    ("export: WITH is not a query", RS + "export.rs", [('"select" | "with" | "values" => {}', '"select" | "values" => {}')]),
    ("export: a second statement is not noticed", RS + "export.rs", [("semicolons_after = true;", "semicolons_after = false;")]),
    ("export: a failed export keeps its half-written file", RS + "export.rs", [("""            drop(sink.out);
            let _ = fs::remove_file(&partial);
            Err(failure)""", """            drop(sink.out);
            Err(failure)""")]),
    ("export: a folder is accepted as the target", RS + "export.rs", [("if target.as_os_str().is_empty() || target.is_dir() {", "if target.as_os_str().is_empty() {")]),
    # ---- diff.rs: the comparison
    ("diff: a page is larger than the engine serves", RS + "diff.rs", [("const PAGE_ROWS: u64 = 1000;", "const PAGE_ROWS: u64 = 1001;")]),
    ("diff: the store keeps one comparison too many", RS + "diff.rs", [("const STORE_CAPACITY: usize = 3;", "const STORE_CAPACITY: usize = 4;")]),
    ("diff: no smali difference is tolerated", RS + "diff.rs", [("const MAX_EDIT_DISTANCE: usize = 1500;", "const MAX_EDIT_DISTANCE: usize = 0;")]),
    ("diff: equal class facts are a difference", RS + "diff.rs", [("Self::OpcodesEqual | Self::NoCodeBoth | Self::FactsEqual", "Self::OpcodesEqual | Self::NoCodeBoth")]),
    ("diff: the engine window is one row wider", RS + "diff.rs", [("if total > ENGINE_WINDOW_ROWS {", "if total > ENGINE_WINDOW_ROWS + 1 {")]),
    ("diff: a repeated class row is accepted", RS + "diff.rs", [("if !class_keys.insert((file_id, def_idx)) {", "if !{ class_keys.insert((file_id, def_idx)); true } {")]),
    ("diff: a repeated method row is accepted", RS + "diff.rs", [("if !method_keys.insert((file_id, method_idx)) {", "if !{ method_keys.insert((file_id, method_idx)); true } {")]),
    ("diff: a long opcode list is no code", RS + "diff.rs", [("Some(if hex.is_empty() {", "Some(if hex.len() > 100 {")]),
    ("diff: an input set is compared with itself", RS + "diff.rs", [("if request.handle_a == request.handle_b {", "if false {")]),
    ("diff: a class defined twice against once is not a count difference", RS + "diff.rs", [("} else if left.len() != right.len() {", "} else if left.len() > right.len() {", 1)]),
    ("diff: a method defined once against twice is not a count difference", RS + "diff.rs", [("} else if left.len() != right.len() {", "} else if left.len() > right.len() {", 2)]),
    ("diff: class facts are never equal", RS + "diff.rs", [("if l == r {\n            Status::FactsEqual", "if l != r {\n            Status::FactsEqual")]),
    ("diff: opcode lists are never equal", RS + "diff.rs", [("if l == r {\n            if l.iter().all(", "if l != r {\n            if l.iter().all(")]),
    ("diff: code against no code reads as different opcodes", RS + "diff.rs", [("} else if no_code_count(&l) != no_code_count(&r) {", "} else if no_code_count(&l) == no_code_count(&r) {")]),
    ("diff: agreements count as differences", RS + "diff.rs", [("filter(|e| !e.status.is_agreement()).count();", "filter(|e| e.status.is_agreement()).count();")]),
    ("diff: the edit script skips a step", RS + "diff.rs", [("            k += 2;", "            k += 1;")]),
    ("diff: the trailing common lines are misplaced", RS + "diff.rs", [("script.extend((0..suffix).map(|i| (Op::Equal, a.len() - suffix + i)));", "script.extend((0..suffix).map(|_| (Op::Equal, a.len() - suffix)));")]),
    ("diff: identical smali is never called identical", RS + "diff.rs", [("let identical = left == right;", "let identical = false;")]),
    ("diff: an inserted line shows the old text", RS + "diff.rs", [("Op::Insert => b[*index],", "Op::Insert => a[*index],")]),
    ("diff: a prefix is not escaped", RS + "diff.rs", [("if matches!(c, '\\\\' | '%' | '_') {", "if matches!(c, '\\\\' | '%') {")]),
    ("diff: a quote in a prefix is not doubled", RS + "diff.rs", [("pattern.replace('\\'', \"''\")", "pattern.replace('\\'', \"\")")]),
    ("diff: references are compared as methods", RS + "diff.rs", [('std::iter::once("access_flags IS NOT NULL".to_owned())', 'std::iter::once("access_flags IS NULL".to_owned())')]),
    # ---- the front end's pure functions
    ("js cells: an empty string looks like nothing", JS + "cells.js", [("if (cell.value === '') return '“”';", "")]),
    ("js cells: binary has no 0x", JS + "cells.js", [("return `0x${cell.value}`;", "return `${cell.value}`;")]),
    ("js sql: a quote is not doubled", JS + "sql.js", [("replaceAll(\"'\", \"''\")", "replaceAll(\"'\", \"\\\\'\")")]),
    ("js sql: a backslash in LIKE text is not escaped", JS + "sql.js", [("replace(/[\\\\%_]/g,", "replace(/[%_]/g,")]),
    ("js sql: a comment hides ORDER BY from nobody", JS + "sql.js", [(".replace(/--[^\\n]*/g, ' ')", "")]),
    ("js sql: blank space is kept after a statement", JS + "sql.js", [("replace(/[;\\s]+$/u, '')", "replace(/;+$/u, '')")]),
    ("js pager: an absent next_offset is more rows", JS + "pager.js", [("{ offset = 0, rows = 0, nextOffset = null,", "{ offset = 0, rows = 0, nextOffset = undefined,")]),
    ("js pager: a next_offset of zero is no more rows", JS + "pager.js", [("const more = nextOffset !== null;", "const more = Boolean(nextOffset);")]),
    ("js pager: an empty later page is an empty result", JS + "pager.js", [("if (rows === 0 && offset === 0) {", "if (rows === 0) {")]),
    ("js smali: an escaped quote ends a string", JS + "smali.js", [('const STRING = /"(?:[^"\\\\]|\\\\.)*"/g;', 'const STRING = /"[^"]*"/g;')]),
    ("js smali: a field is a method", JS + "smali.js", [("if (member && member.includes('(')) {", "if (member) {")]),
    ("js smali: a directive is found anywhere", JS + "smali.js", [("/^\\s*(\\.[a-z-]+)/.exec(line)", "/\\s*(\\.[a-z-]+)/.exec(line)")]),
    ("js errors: every quota error is a budget error", JS + "errors.js", [("hint = message === BUDGET", "hint = true")]),
    ("js format: 1024 bytes is still bytes", JS + "format.js", [("if (value < 1024) return", "if (value <= 1024) return")]),
    ("js diff: no code on both sides is a difference", JS + "diff.js", [("export const AGREEMENTS = ['opcodes_equal', 'no_code_both', 'facts_equal'];", "export const AGREEMENTS = ['opcodes_equal', 'facts_equal'];")]),
    ("js diff: context stops one line early", JS + "diff.js", [("j <= Math.min(lines.length - 1, i + context)", "j < Math.min(lines.length - 1, i + context)")]),
    ("js availability: an empty list greys every view out", JS + "availability.js", [("listed.length === 0", "listed.length === -1")]),
    ("js availability: a failed start leaves the views usable", JS + "availability.js", [("const startFailed = info.start?.ok === false;", "const startFailed = false;")]),
    ("js availability: a stale list rescues a failed start", JS + "availability.js", [("const listed = startFailed ? [] : (tools ?? []);", "const listed = tools ?? [];")]),
    ("js availability: the tools that are listed are the ones reported missing", JS + "availability.js", [("needs.filter((tool) => !listed.includes(tool))", "needs.filter((tool) => listed.includes(tool))")]),
    ("js availability: a view is available whatever is missing", JS + "availability.js", [("available: missing.length === 0", "available: true")]),
    ("js availability: no information yet disables the views", JS + "availability.js", [("if (!info) return { available: true, missing: [] };", "if (!info) return { available: false, missing: [] };")]),
    ("js availability: a busy reply replaces what was known", JS + "availability.js", [("return busy && previous ? previous : next;", "return next;")]),
    ("js availability: every failed start counts as busy", JS + "availability.js", [("const busy = next?.start?.ok === false && next.start.error?.code === 'ENGINE_BUSY';", "const busy = next?.start?.ok === false;")]),
    ("js availability: a busy reply is dropped when nothing was known", JS + "availability.js", [("return busy && previous ? previous : next;", "return busy ? previous : next;")]),
]

TEST_FILES = [
    "apps/desktop/tests/engine.rs", "apps/desktop/tests/diff.rs", "apps/desktop/Cargo.toml", "apps/desktop/Cargo.lock",
    "tests/fixtures/desktop/generate.py",
    *[str(Path(p).relative_to(ROOT)).replace("\\", "/") for p in sorted(glob.glob(str(DESKTOP / "ui-tests" / "*.test.mjs")))],
]


def sources() -> list[str]:
    files = {m[1] for m in MUTANTS}
    files |= {str(Path(p).relative_to(ROOT)).replace("\\", "/") for p in glob.glob(str(DESKTOP / "src" / "*.rs"))}
    files |= {str(Path(p).relative_to(ROOT)).replace("\\", "/") for p in glob.glob(str(DESKTOP / "ui" / "lib" / "*.js"))}
    return sorted(files | set(TEST_FILES))


def sources_hash() -> str:
    digest = hashlib.sha256()
    for name in sources():
        digest.update(name.encode() + b"\0" + (ROOT / name).read_bytes() + b"\0")
    return digest.hexdigest()


def edit(text: str, edits: list) -> str:
    for item in edits:
        old, new = item[0], item[1]
        nth = item[2] if len(item) > 2 else None
        found = text.count(old)
        if nth is None:
            if found != 1:
                raise ValueError(f"anchor occurs {found} times, not once: {old[:70]!r}")
            text = text.replace(old, new, 1)
        else:
            if found < nth:
                raise ValueError(f"anchor occurs {found} times, wanted occurrence {nth}: {old[:70]!r}")
            at = -1
            for _ in range(nth):
                at = text.index(old, at + 1)
            text = text[:at] + new + text[at + len(old):]
    return text


def kill_engines() -> None:
    if WINDOWS:
        subprocess.run(["taskkill", "/F", "/IM", "meguvizdexdash.exe"], capture_output=True, check=False)
    else:
        subprocess.run(["pkill", "-x", "meguvizdexdash"], capture_output=True, check=False)


SCRATCH = ROOT / "artifacts" / "local" / "mutation-tmp"


def scratch_env() -> dict:
    """The suites run with their own temp directory: a variant of the code that mishandles a path must only be
    able to damage this folder, never the machine's shared temp directory (which one of the first runs of
    this check did put at risk: a variant that accepted a folder as an export target aimed at it)."""
    SCRATCH.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    for name in ("TEMP", "TMP", "TMPDIR"):
        env[name] = str(SCRATCH)
    return env


def failing_tests(output: str) -> list[str]:
    names = re.findall(r"^test (\S+) \.\.\. FAILED$", output, re.M)
    names += [m.strip() for m in re.findall(r"^\s*✖ (.+?)(?: \([\d.]+ms\))?$", output, re.M) if not m.startswith("failing tests")]
    return sorted(set(names))


def run(command: list[str], cwd: Path, limit: int) -> tuple[int | None, str]:
    started = time.time()
    try:
        done = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=limit, check=False, env=scratch_env())
        return done.returncode, done.stdout + done.stderr
    except subprocess.TimeoutExpired as expired:
        kill_engines()
        out = (expired.stdout or b"")
        out = out.decode("utf-8", "replace") if isinstance(out, bytes) else out
        return None, f"TIMEOUT after {time.time() - started:.0f}s\n{out[-400:]}"


def suite_for(file: str) -> tuple[list[str], Path, int]:
    return (NODE, DESKTOP, NODE_LIMIT) if file.endswith(".js") else (CARGO, DESKTOP, RUST_LIMIT)


def check_anchors() -> list[str]:
    bad = []
    for name, file, edits in MUTANTS:
        try:
            edit((ROOT / file).read_text(encoding="utf-8"), edits)
        except ValueError as error:
            bad.append(f"{name}: {error}")
    return bad


def main() -> int:
    args = sys.argv[1:]
    out = Path(args[args.index("--out") + 1]) if "--out" in args else None
    value_of_out = args[args.index("--out") + 1] if "--out" in args else None
    words = [a for a in args if not a.startswith("--") and a != value_of_out]
    if "--anchors" in args:
        bad = check_anchors()
        print("\n".join(bad) if bad else f"all {len(MUTANTS)} anchors are as asked")
        return 1 if bad else 0
    lines: list[str] = []

    def say(text: str) -> None:
        print(text, flush=True)
        lines.append(text)

    bad = check_anchors()
    if bad:
        print("\n".join(bad))
        return 2
    chosen = [m for m in MUTANTS if not words or any(w in m[0] for w in words)]
    survivors, invalid, killed, unattributed = [], [], 0, []

    def clean_tree(title: str) -> bool:
        say(title)
        ok = True
        for label, command, limit in (("cargo test", CARGO, RUST_LIMIT), ("node --test", NODE, NODE_LIMIT)):
            code, output = run(command, DESKTOP, limit)
            say(f"  {label}: {'passes' if code == 0 else 'FAILS'}")
            if code != 0:
                say("    failing: " + (", ".join(failing_tests(output)) or output[-300:].replace("\n", " ")))
            ok &= code == 0
        return ok

    # The clean tree comes first: a variant is only 'killed' by a suite that is known to pass without it.
    if not clean_tree("clean tree, before the variants:"):
        say("the suites fail without any variant: nothing below would mean anything, so no variant was run")
        shutil.rmtree(SCRATCH, ignore_errors=True)
        return 2
    if "--clean-only" not in args:
        for name, file, edits in chosen:
            path = ROOT / file
            original = path.read_bytes()
            try:
                path.write_text(edit(original.decode("utf-8"), edits), encoding="utf-8", newline="\n")
                command, cwd, limit = suite_for(file)
                code, output = run(command, cwd, limit)
            finally:
                path.write_bytes(original)
            if code is not None and ("could not compile" in output or "error[E" in output or "SyntaxError" in output):
                invalid.append(name)
                say(f"INVALID   {name}: does not compile/parse")
            elif code == 0:
                survivors.append(name)
                say(f"SURVIVED  {name}")
            elif code is None:
                killed += 1
                say(f"killed    {name} (hung: time limit)")
            else:
                by = failing_tests(output)
                if not by:
                    # a failure that no named test explains (a crash, a harness problem) is not a kill
                    unattributed.append(name)
                    say(f"UNATTRIBUTED {name}: the suite failed but no test is named as failing")
                else:
                    killed += 1
                    say(f"killed    {name}  [{', '.join(by[:3])}{', ...' if len(by) > 3 else ''}]")
    say("")
    clean_ok = clean_tree("clean tree, after the variants (the sources were restored):")
    shutil.rmtree(SCRATCH, ignore_errors=True)
    say("")
    say(f"mutants: {len(chosen)}  killed: {killed}  survived: {len(survivors)}  invalid: {len(invalid)}")
    if unattributed:
        say("unattributed: " + "; ".join(unattributed))
    say(f"sources sha256: {sources_hash()}")
    say(f"files hashed: {len(sources())}")
    if survivors:
        say("survivors: " + "; ".join(survivors))
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return 0 if clean_ok and not survivors and not invalid and not unattributed else 1


if __name__ == "__main__":
    sys.exit(main())
