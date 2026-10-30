#!/usr/bin/env python3
"""Record one targeted SQLite schema-preparation experiment, not qualification."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent / "probe"


def source_hashes():
    files = [ROOT / "Cargo.lock", ROOT / "Cargo.toml",
             ROOT / "tests/fixtures/definitions/generated/definitions-035.dex"]
    files += sorted(p for p in (ROOT / "crates").rglob("*")
                    if p.is_file() and (p.suffix == ".rs" or p.name == "Cargo.toml"))
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in files}


def main():
    OUT.mkdir(parents=True, exist_ok=False)
    before = source_hashes()
    command = ["cargo", "test", "-p", "mdd-sql", "--locked", "--offline", "--jobs", "1",
               "schema_only_prepare_reuses_eponymous_connection_after_restoring_cell_limit",
               "--", "--nocapture", "--test-threads", "1"]
    started = datetime.now(timezone.utc).isoformat()
    try:
        result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=300, check=False)
        stdout, stderr, code, timeout = result.stdout, result.stderr, result.returncode, False
    except subprocess.TimeoutExpired as error:
        stdout, stderr, code, timeout = error.stdout or b"", error.stderr or b"", None, True
    (OUT / "stdout.txt").write_bytes(stdout)
    (OUT / "stderr.txt").write_bytes(stderr)
    record = {"command": command, "started_utc": started,
              "finished_utc": datetime.now(timezone.utc).isoformat(),
              "exit_code": code, "timed_out": timeout,
              "source_sha256": before, "source_unchanged": source_hashes() == before,
              "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
              "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
              "scope": "isolated metadata-only SQLite experiment; no production change or profile qualification"}
    (OUT / "record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"exit_code": code, "timed_out": timeout,
                      "source_unchanged": record["source_unchanged"]}))
    return 0 if code == 0 and record["source_unchanged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
