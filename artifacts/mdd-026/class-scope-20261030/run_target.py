#!/usr/bin/env python3
"""Record two local scoped-class checks; never a full fact qualification."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TARGETS = {
    "legacy": "class_lookup_rejects_unbuilt_partial_and_duplicate_occurrences",
    "scoped": "exact_class_lookup_exposes_scope_and_rejects_unbuilt_coverage",
}


def sources():
    paths = [ROOT / "Cargo.lock", ROOT / "Cargo.toml",
             ROOT / "tests/fixtures/definitions/generated/definitions-035.dex",
             ROOT / "tests/fixtures/references/generated/defined-field-035.dex"]
    for name in ("mdd-facts", "mdd-dex", "mdd-input", "mdd-types"):
        paths.extend(p for p in (ROOT / "crates" / name).rglob("*")
                     if p.is_file() and (p.suffix == ".rs" or p.name == "Cargo.toml"))
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(paths)}


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in TARGETS:
        raise ValueError("expected legacy or scoped")
    name = sys.argv[1]
    output = HERE / name
    output.mkdir(exist_ok=False)
    before = sources()
    argv = ["cargo", "test", "-p", "mdd-facts", "--locked", "--offline", "--jobs", "1",
            TARGETS[name], "--", "--nocapture"]
    started = datetime.now(timezone.utc).isoformat()
    try:
        run = subprocess.run(argv, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=300, check=False)
        stdout, stderr, code, timed_out = run.stdout, run.stderr, run.returncode, False
    except subprocess.TimeoutExpired as error:
        stdout, stderr, code, timed_out = error.stdout or b"", error.stderr or b"", None, True
    (output / "stdout.txt").write_bytes(stdout)
    (output / "stderr.txt").write_bytes(stderr)
    after = sources()
    record = {"command": argv, "started_utc": started,
              "finished_utc": datetime.now(timezone.utc).isoformat(), "exit_code": code,
              "timed_out": timed_out, "source_sha256": before, "source_unchanged": before == after,
              "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
              "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
              "scope": "local selected-scope class checks; not full facts or profile qualification"}
    (output / "record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"case": name, "exit_code": code, "source_unchanged": before == after}))
    return 0 if code == 0 and before == after else 1


if __name__ == "__main__":
    raise SystemExit(main())
