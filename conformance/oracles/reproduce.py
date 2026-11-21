#!/usr/bin/env python3
"""Regenerate and check bounded fixture-level metamorphic properties."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

sys.dont_write_bytecode = True
from check_fixtures import Invalid, class_semantics, leb, leb_radix_reference

ROOT = Path(__file__).resolve().parents[2]
GENERATED = ROOT / "tests/fixtures/generated"
ARTIFACTS = ROOT / "artifacts/mdd-004"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(path):
    with zipfile.ZipFile(path) as archive:
        return [(member.filename, archive.read(member)) for member in archive.infolist()]


def run(args):
    completed = subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True, check=False)
    records.append({"argv": [sys.executable, *args], "exit_code": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr})
    if completed.returncode:
        raise RuntimeError("command failed: " + " ".join(args))


records = []


def main():
    check_only = "--check" in sys.argv[1:]
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    expectation_sha = digest(ROOT / "conformance/oracles/expected-results.json")
    prior_generated = {p.name: digest(p) for p in sorted(GENERATED.iterdir()) if p.is_file()} if GENERATED.exists() else {}
    prior_manifest = digest(ROOT / "tests/fixtures/manifest.json") if (ROOT / "tests/fixtures/manifest.json").exists() else None
    snapshots = []
    for _ in range(2):
        run(["tests/fixtures/generate.py"])
        snapshots.append({p.name: digest(p) for p in sorted(GENERATED.iterdir()) if p.is_file()})
        snapshots[-1]["manifest.json"] = digest(ROOT / "tests/fixtures/manifest.json")
    checks = []

    def check(name, condition, details):
        checks.append({"id": name, "passed": bool(condition), "details": details})

    check("deterministic-generation", snapshots[0] == snapshots[1], {"file_count_including_manifest": len(snapshots[0]), "sha256": snapshots[1]})
    if check_only and prior_generated:
        generated_only = {k: v for k, v in snapshots[1].items() if k != "manifest.json"}
        check("committed-fixtures-match-generator", generated_only == prior_generated and snapshots[1]["manifest.json"] == prior_manifest,
              {"file_count": len(generated_only)})
    check("independent-expectations-preserved", digest(ROOT / "conformance/oracles/expected-results.json") == expectation_sha, {"sha256": expectation_sha})
    stored, deflated = inventory(GENERATED / "multidex-stored.apk"), inventory(GENERATED / "multidex-deflated.apk")
    check("stored-vs-deflated", stored == deflated and digest(GENERATED / "multidex-stored.apk") != digest(GENERATED / "multidex-deflated.apk"),
          {"member_count": len(stored), "uncompressed_bytes": sum(len(value) for _, value in stored)})
    duplicate = inventory(GENERATED / "duplicate-content.apk")
    check("logical-duplicate", len(duplicate) == 2 and duplicate[0][0] != duplicate[1][0] and duplicate[0][1] == duplicate[1][1],
          {"occurrences": len(duplicate), "content_id": hashlib.sha256(duplicate[0][1]).hexdigest()})
    sequence = [digest(GENERATED / name) for name in ["minimal-035.dex", "structured-035.dex"]]
    reverse = [digest(GENERATED / name) for name in ["structured-035.dex", "minimal-035.dex"]]
    check("input-order", reverse == list(reversed(sequence)) and sorted(reverse) == sorted(sequence), {"forward": sequence, "reverse": reverse})
    renamed = inventory(GENERATED / "renamed-member.apk")
    check("member-rename", stored[0][0] != renamed[0][0] and [value for _, value in stored] == [value for _, value in renamed],
          {"old_name": stored[0][0], "new_name": renamed[0][0]})
    before_path, after_path = [GENERATED / name for name in ["class-reorder-before.dex", "class-reorder-after.dex"]]
    before_classes, after_classes = [class_semantics(path.read_bytes()) for path in [before_path, after_path]]
    check("dex-class-table-and-index-reordering",
          digest(before_path) != digest(after_path)
          and before_classes["semantic_classes"] == after_classes["semantic_classes"]
          and before_classes["physical_mapping"] != after_classes["physical_mapping"]
          and before_classes["string_data_offsets"] != after_classes["string_data_offsets"],
          {"before_sha256": digest(before_path), "after_sha256": digest(after_path), "before": before_classes, "after": after_classes,
           "comparison_scope": "complete two-class/two-native-method fixture: all encoded string/type/proto/method/class-data references and semantic values; physical definition IDs intentionally differ"})
    with tempfile.TemporaryDirectory(prefix="mdd-fixture-", dir=ARTIFACTS) as work:
        path = Path(work) / "source.dex"
        before, after = [(GENERATED / name).read_bytes() for name in ["structured-035.dex", "structured-035-same-size-changed.dex"]]
        path.write_bytes(before)
        original_stat = path.stat()
        path.write_bytes(after)
        os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        current_stat = path.stat()
        check("same-size-same-mtime-change", original_stat.st_size == current_stat.st_size and original_stat.st_mtime_ns == current_stat.st_mtime_ns
              and hashlib.sha256(before).digest() != hashlib.sha256(path.read_bytes()).digest(),
              {"bytes": current_stat.st_size, "mtime_ns": current_stat.st_mtime_ns, "before_sha256": hashlib.sha256(before).hexdigest(), "after_sha256": digest(path)})
        oracle_out = (Path(work) / "oracle-checks.json") if check_only else (ARTIFACTS / "oracle-checks.json")
        run(["conformance/oracles/check_fixtures.py", "--out", str(oracle_out)])
        oracle_report = json.loads(oracle_out.read_text(encoding="utf-8"))
    encoding_checks = []
    for signed in [False, True]:
        for prefix in [b"\x80" * 4, b"\xff" * 4]:
            for terminal in range(128):
                value = prefix + bytes([terminal])
                expected_valid = terminal <= 7 or terminal >= 120 if signed else terminal <= 15
                observed = []
                for reader in [leb, leb_radix_reference]:
                    try:
                        actual, consumed = reader(value, signed)
                        observed.append({"valid": True, "value": actual, "consumed": consumed})
                    except Invalid as exc:
                        observed.append({"valid": False, "error": str(exc)})
                encoding_checks.append({"signed": signed, "hex": value.hex(), "expected_valid": expected_valid,
                                        "observed": observed, "passed": all(item["valid"] == expected_valid for item in observed) and observed[0] == observed[1]})
    encoding_report = {
        "schema_version": "mdd.encoding-independent-review.v1",
        "reference": "https://source.android.com/docs/core/runtime/dex-format#leb128",
        "reviewed_date": "2026-10-28", "scope": "32-bit, at most five octets; bounded permissive non-shortest profile",
        "derivation": "Four initial octets encode 28 bits. The fifth unsigned payload must fit four remaining bits (0..15). The fifth signed payload must have bits 4..6 equal to its bit 3 sign, hence 0..7 or 120..127. Both extreme low-28-bit patterns are checked for every terminal payload.",
        "checks": encoding_checks, "success": all(item["passed"] for item in encoding_checks),
        "mutf8_review": "Handwritten decoder checked against Python UTF-8 surrogatepass after translating the sole allowed overlong C0 80 to NUL and explicitly rejecting four-byte UTF-8. Negative continuation/overlong/truncation/length vectors are required to agree in both formulations.",
        "not_claimed": "DexSQL profile qualification or complete DEX verifier qualification"}
    success = all(item["passed"] for item in checks) and oracle_report["success"] and encoding_report["success"]
    if not check_only:
        (ARTIFACTS / "encoding-independent-review.json").write_text(json.dumps(encoding_report, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        report = {"schema_version": "mdd.fixture-reproducibility.v1", "python": sys.version, "commands": records, "metamorphic_checks": checks,
                  "fixture_count": len(snapshots[0]) - 1, "oracle_check_count": len(oracle_report["checks"]),
                  "success": success,
                  "independent_leb_terminal_checks": len(encoding_checks),
                  "source_sha256": {name: digest(ROOT / name) for name in ["tests/fixtures/generate.py", "conformance/oracles/check_fixtures.py", "conformance/oracles/reproduce.py", "conformance/oracles/expected-results.json"]},
                  "qualification": "fixture reproducibility and bounded reference checks only; no production engine or external full-format oracle qualification",
                  "not_run": ["production parser", "AOSP verifier/dexdump", "AAPT2", "fuzz", "production lifecycle"]}
        (ARTIFACTS / "fixture-reproducibility.json").write_text(json.dumps(report, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    else:
        committed_report = json.loads((ARTIFACTS / "fixture-reproducibility.json").read_text(encoding="utf-8"))
        committed_oracles = json.loads((ARTIFACTS / "oracle-checks.json").read_text(encoding="utf-8"))
        success = success and committed_report.get("success") is True and committed_oracles.get("success") is True
    print(f"reproducibility: {len(checks)} metamorphic checks, {len(oracle_report['checks'])} oracle checks, success={success}")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
