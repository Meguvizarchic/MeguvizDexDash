#!/usr/bin/env python3
"""Shared mutation-testing engine and evidence verifier for MeguvizDexDash.

Each task-specific mutation script defines only the sources, fixtures, test suites,
replays, controls and mutants that belong to its own boundary, instead of inheriting
unrelated tasks' files and replays.
"""
from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
PY = str(PYTHON if PYTHON.exists() else sys.executable)
BINARY = "target/debug/meguvizdexdash" + (".exe" if os.name == "nt" else "")
DIAGNOSE = os.environ.get("MUTATION_DIAGNOSE") == "1"
CARGO = ["cargo", "test", "--offline", "--locked"]
TAIL = ["--", "--test-threads=1", "--nocapture"] if DIAGNOSE else []
BUILD_CLI = ["cargo", "build", "--offline", "--locked", "-p", "mdd-cli"]

LIMITS = {"cargo": 15 * 60, "python": 10 * 60}
TIMEOUT = -9999
VERDICTS = ("KILLED", "SURVIVED", "ERROR", "SKIPPED", "TIMEOUT")


@dataclass
class MutationSuite:
    name: str
    sources: list[str]
    mutants: list[tuple[str, str, list[tuple[str, str]]]]
    unit_suites: list[tuple[str, list[str]]]
    fixtures: list[str] = field(default_factory=list)
    build_commands: list[list[str]] = field(default_factory=lambda: [list(BUILD_CLI)])
    replays: list[tuple[str, list[str]]] = field(default_factory=list)
    controls: list[list[str]] = field(default_factory=list)
    extra_clean_lines: Callable[[], list[str]] | None = None
    last_output: str = field(default="", init=False, repr=False)

    def hash_files(self, relatives: list[str]) -> bytes:
        digest = hashlib.sha256()
        for relative in relatives:
            digest.update(relative.encode())
            digest.update((ROOT / relative).read_bytes())
        return digest.digest()

    def sources_sha256(self) -> str:
        digest = hashlib.sha256()
        digest.update(self.hash_files(self.sources))
        digest.update(self.hash_files(self.fixtures))
        return digest.hexdigest()

    def missing_paths(self) -> list[str]:
        return [p for p in (*self.sources, *self.fixtures) if not (ROOT / p).is_file()]

    def anchors(self, *, quiet: bool = False) -> int:
        """Return 0 iff every mutant anchor matches its target file exactly once."""
        bad = 0
        for name, relative, edits in self.mutants:
            path = ROOT / relative
            if not path.is_file():
                bad += 1
                print(f"MISSING  {name}  [{relative}]")
                continue
            text = path.read_text(encoding="utf-8")
            for old, _new in edits:
                count = text.count(old)
                if count != 1:
                    bad += 1
                    print(f"ANCHOR {count}x  {name}  [{relative}]")
        if not quiet or bad:
            print(f"{self.name}: {len(self.mutants)} mutants, {bad} anchors that are not unique")
        return 1 if bad else 0

    def _kill_tree(self, process: subprocess.Popen) -> None:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True, check=False)
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def _run(self, command: list[str]) -> int:
        limit = LIMITS["cargo" if command[0] == "cargo" else "python"]
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=(os.name != "nt"),
        )
        try:
            output, _ = process.communicate(timeout=limit)
        except subprocess.TimeoutExpired:
            self._kill_tree(process)
            try:
                output, _ = process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                output = b""
            self.last_output = output.decode("utf-8", "replace")
            print(f"# TIMEOUT after {limit} s: {' '.join(command)}", file=sys.stderr, flush=True)
            print(self.last_output[-4000:], file=sys.stderr, flush=True)
            return TIMEOUT
        self.last_output = output.decode("utf-8", "replace")
        return process.returncode

    def suite_verdict(self) -> tuple[str, bool]:
        """Return (killer_tag_or_'none', builds_cleanly)."""
        for _tag, command in self.unit_suites:
            if command[0] == "cargo":
                head = command[: command.index("--")] if "--" in command else command
                code = self._run([*head, "--no-run"])
                if code == TIMEOUT:
                    return "TIMEOUT: build", True
                if code != 0:
                    return "none", False
        for tag, command in self.unit_suites:
            code = self._run(command)
            if code == TIMEOUT:
                return f"TIMEOUT: {tag}", True
            if code != 0:
                return tag, True
        for command in self.build_commands:
            code = self._run(command)
            if code == TIMEOUT:
                return "TIMEOUT: binary build", True
            if code != 0:
                return "none", False
        for tag, command in self.replays:
            code = self._run(command)
            if code == TIMEOUT:
                return f"TIMEOUT: {tag} replay", True
            if code != 0:
                return tag + " replay", True
        return "none", True

    def one(self, name: str, relative: str, edits: list[tuple[str, str]]) -> bool:
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
            killer, builds = self.suite_verdict()
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

    def clean_tree(self) -> bool:
        commands = [
            *(cmd for _tag, cmd in self.unit_suites),
            *self.build_commands,
            *(cmd for _tag, cmd in self.replays),
            *self.controls,
        ]
        clean = True
        for command in commands:
            code = self._run(command)
            if code != 0:
                clean = False
                print("# the clean tree failed:", " ".join(command), "->", "TIMEOUT" if code == TIMEOUT else code, flush=True)
                print(self.last_output[-2000:], file=sys.stderr, flush=True)
        print("restored tree passes the unit and process tests, the replays and their controls:", clean)
        if self.extra_clean_lines is not None:
            for line in self.extra_clean_lines():
                print(line)
        print("sources sha256:", self.sources_sha256())
        return clean

    def assemble(self, files: list[str]) -> int:
        by_name: dict[str, list[str]] = {}
        tail: list[str] = []
        for file in files:
            for line in Path(file).read_text(encoding="utf-8").splitlines():
                word = line.split(" ", 1)[0]
                if word in VERDICTS:
                    known = [name for name, _r, _e in self.mutants if line[len(word) :].strip().startswith(name)]
                    if known:
                        by_name.setdefault(max(known, key=len), []).append(line)
                elif line.startswith(("restored tree", "public APK", "sources sha256")):
                    tail.append(line)
        problems = [name for name, _r, _e in self.mutants if len(by_name.get(name, [])) != 1]
        for name in problems:
            print(f"# {name}: {len(by_name.get(name, []))} verdicts", file=sys.stderr)
        for name, _r, _e in self.mutants:
            for line in by_name.get(name, [])[:1]:
                print(line)
        for line in tail:
            print(line)
        hashes = {line for line in tail if line.startswith("sources sha256")}
        if len(hashes) != 1 or any(h != "sources sha256: " + self.sources_sha256() for h in hashes):
            print("# the parts do not agree with this checkout's sources", file=sys.stderr)
            return 1
        return 1 if problems else 0

    def main(self, argv: list[str] | None = None) -> int:
        args = sys.argv[1:] if argv is None else list(argv)
        if args[:1] == ["--anchors"]:
            return self.anchors()
        if args[:1] == ["--assemble"]:
            return self.assemble(args[1:])
        if args[:1] == ["--clean-only"]:
            return 0 if self.clean_tree() else 1
        part = None
        if args[:1] == ["--part"]:
            k, n = (int(x) for x in args[1].split("/"))
            if not (1 <= k <= n):
                raise SystemExit(f"invalid --part {args[1]}")
            part, args = (k, n), args[2:]
        ok = True
        for position, (name, relative, edits) in enumerate(self.mutants):
            if part and position % part[1] != part[0] - 1:
                continue
            if args and not any(word in name for word in args):
                continue
            ok = self.one(name, relative, edits) and ok
        if part or args:
            return 0 if ok else 1
        return 0 if self.clean_tree() and ok else 1


def summarize_results(suite: MutationSuite, mutation_rel: str, script_rel: str) -> dict:
    path = ROOT / mutation_rel
    if not path.is_file():
        return {
            "file": mutation_rel,
            "script": script_rel,
            "present": False,
            "current": False,
            "mutants": len(suite.mutants),
            "status": f"not run yet; no result is claimed",
        }
    lines = path.read_text(encoding="utf-8").splitlines()
    recorded = [line.split(":", 1)[1].strip() for line in lines if line.startswith("sources sha256:")]
    return {
        "file": mutation_rel,
        "script": script_rel,
        "present": True,
        "current": recorded == [suite.sources_sha256()],
        "mutants": len(suite.mutants),
        "killed": sum(1 for line in lines if line.startswith("KILLED")),
        "survived": [line[len("SURVIVED") :].strip() for line in lines if line.startswith("SURVIVED")],
        "errors": sum(1 for line in lines if line.startswith(("ERROR", "TIMEOUT"))),
        "skipped": sum(1 for line in lines if line.startswith("SKIPPED")),
        "restored_tree_passes": any("passes the unit and process tests, the replays and their controls: True" in line for line in lines),
    }


def check_evidence(
    record_rel: str,
    suite: MutationSuite,
    mutation_rel: str,
    script_rel: str,
    *,
    strict_provenance: bool = False,
) -> list[str]:
    """Verify a committed conformance record and its mutation anchors/results.

    Default mode validates:
      1) all referenced input paths exist on disk;
      2) committed mutation results (when present) passed with 0 survivors/errors/skips;
      3) all mutant anchors match the current source files uniquely (catches refactoring drift).
    When strict_provenance=True, also requires exact sha256 equality against the committed snapshot.
    """
    import json

    issues: list[str] = []
    record = json.loads((ROOT / record_rel).read_text(encoding="utf-8"))
    for path, digest in record.get("inputs_sha256", {}).items():
        target = ROOT / path
        if not target.is_file():
            issues.append(f"MISSING_INPUT: {path}")
        elif strict_provenance and hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            issues.append(f"STALE_HASH: {path}")

    for missing in suite.missing_paths():
        issues.append(f"MISSING_SUITE_PATH: {missing}")

    if suite.anchors(quiet=True) != 0:
        issues.append(f"BROKEN_MUTATION_ANCHORS: {script_rel}")

    summary = summarize_results(suite, mutation_rel, script_rel)
    if summary["present"]:
        if summary["survived"]:
            issues.append(f"MUTATION_SURVIVED: {mutation_rel}: {summary['survived']}")
        if summary["errors"] or summary["skipped"] or not summary["restored_tree_passes"]:
            issues.append(
                f"MUTATION_INCOMPLETE: {mutation_rel} (errors={summary['errors']}, "
                f"skipped={summary['skipped']}, restored={summary['restored_tree_passes']})"
            )
        if summary["killed"] != len(suite.mutants):
            issues.append(f"MUTATION_COUNT_MISMATCH: {mutation_rel} ({summary['killed']} != {len(suite.mutants)})")
        if strict_provenance and not summary["current"]:
            issues.append(f"STALE_MUTATION_HASH: {mutation_rel}")
    return issues
