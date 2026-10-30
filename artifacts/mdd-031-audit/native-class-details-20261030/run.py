from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[3]
output = Path(__file__).resolve().parent / "run1"
output.mkdir(exist_ok=False)
files = [
    "Cargo.lock",
    "crates/mdd-sql/src/provider/metadata.rs",
    "crates/mdd-sql/src/dialects/ast.rs",
    "crates/mdd-facts/src/definitions.rs",
    "crates/mdd-dex/src/definitions.rs",
    "tests/fixtures/definitions/generated/definitions-035.dex",
    "tests/fixtures/definitions/generated/nullable-root-class.dex",
    "tests/fixtures/definitions/generated/empty-class-data.dex",
]
def hashes():
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in files}

command = ["cargo", "test", "-p", "mdd-sql", "--locked", "--offline", "--jobs", "1", "native_class_definition_details_preserve_raw_offsets_and_sources", "--", "--nocapture"]
before = hashes()
started = datetime.now(timezone.utc).isoformat()
result = subprocess.run(command, cwd=root, capture_output=True)
ended = datetime.now(timezone.utc).isoformat()
(output / "stdout.txt").write_bytes(result.stdout)
(output / "stderr.txt").write_bytes(result.stderr)
record = {
    "command": command,
    "started_utc": started,
    "ended_utc": ended,
    "exit_code": result.returncode,
    "source_before_sha256": before,
    "source_after_sha256": hashes(),
    "scope": "one SQL provider test; selected source and fixture identities only, not complete workspace or qualification",
}
(output / "record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"exit_code": result.returncode, "source_unchanged": before == record["source_after_sha256"], "stdout": result.stdout.decode("utf-8", "replace"), "stderr": result.stderr.decode("utf-8", "replace")}, ensure_ascii=False))
raise SystemExit(result.returncode)
