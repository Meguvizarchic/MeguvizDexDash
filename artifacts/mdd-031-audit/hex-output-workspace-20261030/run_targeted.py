#!/usr/bin/env python3
"""Run one named local regression and retain raw output and source identity."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
CASES = {
    "red": "hex_result_workspace_is_reserved_before_output_construction",
    "red2": "hex_result_workspace_is_reserved_before_output_construction",
    "diagnostic": "hex_result_workspace_is_reserved_before_output_construction",
    "green": "hex_result_workspace_is_reserved_before_output_construction",
    "encoding": "hex_preserves_null_bytes_nul_and_surrogate_encoding",
    "cancel": "hex_cancelled_after_scan_starts_stays_failed",
}


def sources():
    files = sorted((ROOT / "crates").rglob("*.rs"))
    files += [ROOT / "Cargo.lock", ROOT / "Cargo.toml"]
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in files}


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in CASES:
        raise SystemExit("expected red, red2, diagnostic, green, encoding or cancel")
    phase = sys.argv[1]
    folder = HERE / phase
    folder.mkdir(exist_ok=False)
    command = ["cargo", "test", "-p", "mdd-sql", "--locked", "--offline", "--jobs", "1",
               CASES[phase], "--", "--nocapture"]
    before = sources()
    start = datetime.now(timezone.utc).isoformat()
    t = time.monotonic()
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=600)
        code, stdout, stderr, timed_out = result.returncode, result.stdout, result.stderr, False
    except subprocess.TimeoutExpired as error:
        code, stdout, stderr, timed_out = None, error.stdout or b"", error.stderr or b"", True
    (folder / "stdout.txt").write_bytes(stdout)
    (folder / "stderr.txt").write_bytes(stderr)
    after = sources()
    record = {"command": command, "started_utc": start,
              "finished_utc": datetime.now(timezone.utc).isoformat(),
              "elapsed_seconds": time.monotonic() - t, "exit_code": code,
              "timed_out": timed_out, "source_sha256": before,
              "source_unchanged": before == after,
              "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
              "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
              "scope": "targeted local SQL check; no full profile or performance qualification"}
    (folder / "record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"phase": phase, "exit_code": code, "source_unchanged": before == after}))
    return 0 if code == (101 if phase in ("red", "red2") else 0) and before == after else 1


if __name__ == "__main__":
    raise SystemExit(main())
