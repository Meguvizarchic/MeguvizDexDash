"""Mutation check for MDD-044: change one behaviour of the pipeline benchmark at a time and
require the unit tests to notice.

    python -I artifacts/mdd-044/mutation/mutate_pipeline.py

Each mutant replaces one exact piece of benchmarks/producer-consumer-pipeline.py, runs
benchmarks/test_producer_consumer_pipeline.py (no engine, no APK, no network), and restores the
file in a `finally`. A mutant that leaves the tests green is a survivor and exits 1. A pattern
that no longer matches exactly once is also a failure, so the list cannot rot silently. Run it on
a clean checkout: it edits the module in place. The tail binds the result to the sha256 of the
three restored sources, so a result file cannot be mistaken for another revision's.
"""
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
TARGET = REPO / "benchmarks" / "producer-consumer-pipeline.py"
BACKUP = Path(tempfile.mkdtemp(prefix="mdd044-mutation-"))
SOURCES = ["benchmarks/producer-consumer-pipeline.py",
           "benchmarks/test_producer_consumer_pipeline.py",
           "conformance/protocol/column-batch-cases.json"]

MUTANTS = [
    ("the completeness gate accepts a non-ok operation_status",
     '    if terminal.get("operation_status") != "ok":', '    if False:'),
    ("the completeness gate accepts an incomplete execution",
     '    if (terminal.get("execution") or {}).get("complete") is not True:', '    if False:'),
    ("the completeness gate accepts a truncated result",
     '    if response.get("truncated") is not False:', '    if False:'),
    ("the completeness gate accepts more_available rows",
     '    if response.get("more_available") is not False:', '    if False:'),
    ("the completeness gate accepts a leftover next_cursor",
     '    if response.get("next_cursor") is not None:', '    if False:'),
    ("the completeness gate accepts partial/unknown coverage",
     '    if coverage.get("input") != "complete" or coverage.get("facts") != "complete":', '    if False:'),
    ("the completeness gate ignores emitted_rows vs delivered",
     '    if int(emitted) != delivered_rows:', '    if False:'),
    ("the completeness gate ignores the expected row count",
     '    if expected_rows is not None and delivered_rows != expected_rows:', '    if False:'),
    ("NULL canonicalizes to an empty string",
     '    if tag == "null":\n        return {"t": "null"}',
     '    if tag == "null":\n        return {"t": "text", "v": ""}'),
    ("the canonical digest ignores row order",
     '    document = {"columns": list(columns), "rows": canonical_rows(columns, rows)}',
     '    document = {"columns": list(columns), "rows": sorted(canonical_rows(columns, rows), key=lambda r: json.dumps(r, sort_keys=True))}'),
    ("the canonical digest drops duplicate rows",
     '    return [[canonical_cell(cell) for cell in row] for row in rows]',
     '    seen = []\n    for row in rows:\n        canonical = [canonical_cell(cell) for cell in row]\n        if canonical not in seen:\n            seen.append(canonical)\n    return seen'),
    ("f64 decode canonicalizes NaN, losing the payload",
     '                    rows[i].append({"t": "f64", "bits": "%016x" % struct.unpack("<Q", slot)[0]})',
     '                    value = struct.unpack("<d", slot)[0]\n                    if value != value:\n                        value = float("nan")\n                    rows[i].append({"t": "f64", "bits": "%016x" % struct.unpack("<Q", struct.pack("<d", value))[0]})'),
    ("text decode uses strict UTF-8, rejecting unpaired surrogates",
     '                text = raw.decode("utf-8", "surrogatepass")', '                text = raw.decode("utf-8")'),
    ("decode ignores the dex_mutf8 utf16_units count",
     '                if _mutf8_units(raw) != units[i]:', '                if False:'),
    ("decode accepts nonzero trailing bitmap bits",
     '        if row_count % 8 and bitmap[-1] >> (row_count % 8):', '        if False:'),
    ("decode accepts a nonzeroed NULL fixed-width slot",
     '                    if slot != b"\\0" * width:', '                    if False:'),
    ("decode accepts non-monotonic varlen offsets",
     '        if any(a > b for a, b in zip(offsets, offsets[1:])):', '        if False:'),
    ("decode accepts a wrong tail offset",
     '        if len(value_bytes) != offsets[-1] + units_len:', '        if False:'),
    ("decode accepts a NULL varlen row carrying bytes",
     '                if len(raw) != 0 or units[i] != 0:', '                if False:'),
    ("decode accepts unaccounted trailing bytes in the body",
     '    if cursor != len(blob):', '    if False:'),
    ("decode accepts nonzero descriptor flags",
     '        if descriptor["flags"] != 0:', '        if False:'),
    ("decode accepts a bool slot that is not 0/1",
     '                    if slot[0] not in (0, 1):', '                    if False:'),
    ("MCP uint64 is mistagged as i64",
     '    if kind == "uint64":\n        return {"t": "u64", "v": str(int(value))}',
     '    if kind == "uint64":\n        return {"t": "i64", "v": str(int(value))}'),
    ("the stdout proxy counts str length, not wire bytes",
     '        self.bytes += len(data)', '        self.bytes += len(str(data))'),
    ("the stream consumer ignores sequence/first_row continuity",
     '        if sequence != next_sequence or first_row != next_row:', '        if False:'),
    ("the encoding evaluation skips the canonical cell fidelity check",
     '        if canonical_rows(document["columns"], decoded["rows"]) != canonical_rows(document["columns"], document["rows"]):',
     '        if False:'),
    ("infer_schema accepts a mixed-type column",
     '        if len(tags[ordinal]) != 1:', '        if False:'),
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


survivors = []
killed = 0
original = TARGET.read_text(encoding="utf-8")
saved = BACKUP / TARGET.name
shutil.copyfile(TARGET, saved)
for index, (label, old, new) in enumerate(MUTANTS, 1):
    if original.count(old) != 1:
        print(f"{index:2} NOT APPLICABLE ({original.count(old)} matches): {label}")
        survivors.append((index, label, "pattern"))
        continue
    TARGET.write_text(original.replace(old, new), encoding="utf-8", newline="\n")
    try:
        done = subprocess.run([sys.executable, "-I", "-m", "unittest", "discover",
                               "-s", str(REPO / "benchmarks"), "-p", "test_producer_consumer_pipeline.py"],
                              capture_output=True, text=True, cwd=str(REPO), timeout=300)
    finally:
        shutil.copyfile(saved, TARGET)
    if done.returncode != 0:
        killed += 1
        print(f"{index:2} killed: {label}")
    else:
        print(f"{index:2} SURVIVED: {label}")
        survivors.append((index, label, "survived"))

restored = TARGET.read_text(encoding="utf-8")
if restored != original:
    print("FATAL: the target was not restored to its original bytes")
    survivors.append((0, "restore", "dirty"))
shutil.rmtree(BACKUP, ignore_errors=True)
print(f"killed {killed}/{len(MUTANTS)}; survivors: {survivors}")
print("sources sha256:")
for relative in SOURCES:
    print(f"  {sha256_file(REPO / relative)}  {relative}")
sys.exit(1 if survivors else 0)