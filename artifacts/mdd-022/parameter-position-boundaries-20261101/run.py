#!/usr/bin/env python3
"""Record targeted parameter-list boundary checks; not full qualification."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = Path(__file__).resolve().parent / "run1"
RAW = ROOT / "artifacts/local/parameter-position-boundaries-20261101/run1"
FILES = [
    "Cargo.lock", "Cargo.toml", "rust-toolchain.toml",
    "crates/mdd-dex/src/annotations.rs", "crates/mdd-facts/src/annotations.rs",
    "crates/mdd-facts/src/definitions.rs", "crates/mdd-facts/src/metadata.rs",
    "tests/fixtures/annotations/generate.py",
    "tests/fixtures/annotations/generate_parameter_positions.py",
    "tests/fixtures/annotations/parameter-position-fixtures.json",
    "tests/fixtures/annotations/generated/annotations-038.dex",
    *["tests/fixtures/annotations/generated/" + name for name in (
        "parameter-empty-nonzero-proto.dex", "parameter-long-nonzero-proto.dex",
        "parameter-empty-zero-proto.dex", "parameter-orphan-empty-no-binding.dex")],
]
COMMANDS = [
    ["python", "-B", "-O", "tests/fixtures/annotations/generate_parameter_positions.py", "--check"],
    ["cargo", "test", "-p", "mdd-dex", "--locked", "--offline", "--jobs", "1",
     "parameter_list_physical_counts_do_not_invent_positions", "--", "--nocapture"],
    *[["cargo", "test", "-p", "mdd-facts", "--locked", "--offline", "--jobs", "1", name,
       "--", "--nocapture"] for name in (
       "empty_and_long_encoded_lists_are_not_inferred_as_complete_positions",
       "empty_parameter_list_and_absent_binding_remain_distinct",
       "long_parameter_lists_keep_duplicate_source_occurrences_distinct")],
]


def hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in FILES}


def utc():
    return datetime.now(timezone.utc).isoformat()


def main():
    OUTPUT.mkdir(exist_ok=False)
    RAW.mkdir(parents=True, exist_ok=False)
    record = {"started_utc": utc(), "source_before": hashes(), "runs": [],
              "scope": "synthetic physical parameter lists and duplicate occurrences; no ART, full format or task qualification"}
    try:
        for index, command in enumerate(COMMANDS):
            start = utc()
            try:
                result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=300, check=False)
                stdout, stderr = result.stdout, result.stderr
                entry = {"command": command, "started_utc": start, "finished_utc": utc(),
                         "exit_code": result.returncode}
            except subprocess.TimeoutExpired as error:
                stdout, stderr = error.stdout or b"", error.stderr or b""
                entry = {"command": command, "started_utc": start, "finished_utc": utc(),
                         "exit_code": None, "failure": "timeout"}
            except OSError as error:
                stdout, stderr = b"", str(error).encode("utf-8", "backslashreplace")
                entry = {"command": command, "started_utc": start, "finished_utc": utc(),
                         "exit_code": None, "failure": "launch_error"}
            for suffix, raw in (("stdout", stdout), ("stderr", stderr)):
                (RAW / f"{index}.{suffix}").write_bytes(raw)
                redacted = raw.replace(str(ROOT).encode(), b"<workspace>")
                (OUTPUT / f"{index}.{suffix}").write_bytes(redacted)
                entry[f"raw_{suffix}_sha256"] = hashlib.sha256(raw).hexdigest()
            record["runs"].append(entry)
    finally:
        record["source_after"] = hashes()
        record["finished_utc"] = utc()
        record["redaction"] = "workspace path replaced in logs; raw outputs retained in ignored local directory"
        (OUTPUT / "record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    if record["source_before"] != record["source_after"] or any(r["exit_code"] != 0 for r in record["runs"]):
        raise SystemExit(1)
    print(json.dumps({"status": "passed", "commands": len(record["runs"])}))


if __name__ == "__main__":
    main()
