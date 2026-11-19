"""MDD-054: does the comparator's test suite notice a weakened comparator? Standard library only.

Each mutant is one deliberate edit of `conformance/hostlab/compare_full_reports.py` that makes the comparison easier to pass
(drop repetitions, ignore more fields, stop checking a layer). The mutant is written into a PRIVATE copy of the two files -
never into this tree - and `test_compare_full_reports.py` runs against it. A mutant is killed when that suite fails. A
survivor is a hole in the tests, and is reported, not hidden.

    python -I artifacts/mdd-054/mutation/mutate_compare.py [--output FILE]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = "conformance/hostlab/compare_full_reports.py"
SUITE = "integrations/hostlab/test_compare_full_reports.py"

MUTANTS = [
    ("a bag is compared as a set (repetitions dropped)", "return sorted(canon(item) for item in value)", "return sorted({canon(item) for item in value})"),
    ("a bag is compared in order, not as a bag", "return sorted(canon(item) for item in value)", "return [canon(item) for item in value]"),
    ("an ordered group is treated as a bag", '"unclassified_protocol_callers", "discoveries",\n})', '"unclassified_protocol_callers", "discoveries", "limitations",\n})'),
    ("the key order of an object matters", "return json.dumps(value, sort_keys=True, ensure_ascii=False", "return json.dumps(value, sort_keys=False, ensure_ascii=False"),
    ("NULL and empty text are the same", 'return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)',
     'return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).replace("null", "\\"\\"")'),
    ("the queries are ignored", '"/native_audit/elapsed_ms",', '"/native_audit/elapsed_ms", "/native_audit/queries",'),
    ("the whole native record is ignored", '"/native_audit/native",', '"/native_audit",'),
    ("the coverage gaps are ignored", '"/native_audit/native",', '"/native_audit/native", "/coverage_gaps",'),
    ("a layer is any, not all", 'all(layer["equal"] for layer in layers)', 'any(layer["equal"] for layer in layers)'),
    ("the published rows are not compared", "layers = [run_identity_layer(a, b), report_layer(a, b), tsv_layer(a, b), groups_layer(a, b)]",
     "layers = [run_identity_layer(a, b), report_layer(a, b), groups_layer(a, b)]"),
    ("the report is not compared", "layers = [run_identity_layer(a, b), report_layer(a, b), tsv_layer(a, b), groups_layer(a, b)]",
     "layers = [run_identity_layer(a, b), tsv_layer(a, b), groups_layer(a, b)]"),
    ("the groups are not compared", "layers = [run_identity_layer(a, b), report_layer(a, b), tsv_layer(a, b), groups_layer(a, b)]",
     "layers = [run_identity_layer(a, b), report_layer(a, b), tsv_layer(a, b)]"),
    ("a counted fallback is tolerated", 'need(certificate.get("fallback_count") == 0,', 'need(True or certificate.get("fallback_count") == 0,'),
    ("a recorded fallback reason is tolerated", 'need(summary.get("backend_fallback_reason") is None,', 'need(True or summary.get("backend_fallback_reason") is None,'),
    ("an incomplete audit is tolerated", 'need(summary.get("audit_complete") is True,', 'need(True or summary.get("audit_complete") is True,'),
    ("a truncated result is tolerated", 'need(certificate.get("truncated") is False,', 'need(True or certificate.get("truncated") is False,'),
    ("an unconsumed page is tolerated", 'need(certificate.get("more_available") is False,', 'need(True or certificate.get("more_available") is False,'),
    ("another input is tolerated", 'need(sa.get("sample", {}).get("sha256") == sb.get("sample", {}).get("sha256"),', 'need(True or sa.get("sample", {}).get("sha256") == sb.get("sample", {}).get("sha256"),'),
    ("other tools are tolerated", 'need(sa.get("tools") == sb.get("tools"),', 'need(True or sa.get("tools") == sb.get("tools"),'),
    ("another reference source is tolerated", 'for key in ("input_sha256", "reference_source_commit", "tools"):', 'for key in ("input_sha256", "tools"):'),
    ("a missing feature is tolerated", "and len(summary[\"features\"]) == FEATURE_COUNT", "and len(summary[\"features\"]) >= 0"),
    ("a missing or extra group is tolerated by the run layer", "need(set(evidence) == set(EVIDENCE_KEYS),", "need(True or set(evidence) == set(EVIDENCE_KEYS),"),
    ("a missing group is not a difference", 'groups[name] = {"equal": False, "reason": "a group is missing"}', 'groups[name] = {"equal": True, "reason": "a group is missing"}'),
    ("a row beyond the shorter file is not compared", "for index in range(max(len(left), len(right))):", "for index in range(min(len(left), len(right))):"),
    ("the group digest ignores a type", "return json.dumps(value, sort_keys=True, ensure_ascii=False,", "return json.dumps(str(value), sort_keys=True, ensure_ascii=False,"),
    ("a duplicate JSON key is accepted", 'raise ValueError("duplicate JSON key: " + key)', "pass"),
    ("a non-finite number is accepted", 'raise ValueError("non-finite JSON constant: " + value)', "return 0"),
    ("a bag that is not a list is compared anyway", 'raise ValueError(f"group {name} is declared a multiset and must be a list")', "return value"),
    ("two reports in one run directory are accepted", "if len(found) != 1:\n            raise ValueError", "if len(found) < 1:\n            raise ValueError"),
    ("a long value is not cut", "cut = text if len(text) <= VALUE_LIMIT else text[:VALUE_LIMIT] + \"...\"", "cut = text"),
    ("the missing count of a bag is zero", '"missing_count": sum(missing.values())', '"missing_count": 0'),
    ("the first differing value is not kept", "entry[\"first_differences\"], entry[\"difference_count\"] = where, count", "entry[\"first_differences\"], entry[\"difference_count\"] = [], count"),
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_suite(copy_root: Path) -> "tuple[int, str]":
    done = subprocess.run([sys.executable, "-I", "-m", "unittest", "discover", "-s", "integrations/hostlab", "-p", "test_compare_full_reports.py"],
                          cwd=copy_root, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    return done.returncode, (done.stdout + done.stderr)[-400:]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    source = (ROOT / TARGET).read_text(encoding="utf-8")
    suite = (ROOT / SUITE).read_text(encoding="utf-8")
    results = []
    with tempfile.TemporaryDirectory(prefix="mdd054-mut-", dir=ROOT / "artifacts/local") as folder:
        copy_root = Path(folder)
        (copy_root / "conformance/hostlab").mkdir(parents=True)
        (copy_root / "integrations/hostlab").mkdir(parents=True)
        (copy_root / SUITE).write_text(suite, encoding="utf-8", newline="\n")
        (copy_root / TARGET).write_text(source, encoding="utf-8", newline="\n")
        code, tail = run_suite(copy_root)
        if code != 0:
            print("the unmutated suite does not pass:\n" + tail)
            return 2
        for name, old, new in MUTANTS:
            if source.count(old) != 1:
                results.append({"mutant": name, "result": "not_applied", "occurrences": source.count(old)})
                continue
            (copy_root / TARGET).write_text(source.replace(old, new), encoding="utf-8", newline="\n")
            code, tail = run_suite(copy_root)
            results.append({"mutant": name, "result": "killed" if code != 0 else "SURVIVED"})
        (copy_root / TARGET).write_text(source, encoding="utf-8", newline="\n")
    summary = {"target": TARGET, "target_sha256": sha256(ROOT / TARGET), "suite": SUITE, "suite_sha256": sha256(ROOT / SUITE),
               "mutants": len(results), "killed": sum(item["result"] == "killed" for item in results),
               "survived": [item["mutant"] for item in results if item["result"] == "SURVIVED"],
               "not_applied": [item["mutant"] for item in results if item["result"] == "not_applied"], "results": results}
    text = json.dumps(summary, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8", newline="\n")
    print(json.dumps({k: summary[k] for k in ("mutants", "killed", "survived", "not_applied")}, ensure_ascii=False))
    return 0 if not summary["survived"] and not summary["not_applied"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
