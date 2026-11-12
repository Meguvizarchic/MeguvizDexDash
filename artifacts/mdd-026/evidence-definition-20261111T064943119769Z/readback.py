#!/usr/bin/env python3
"""Independent readback of the definition/header evidence directory.

Re-reads the captured A0 tables and native probe stdout, re-enumerates every
row with the byte oracle, and checks that result.json's measured facts and
verdicts still follow from the captured bytes. It does not trust result.json's
comparisons: it recomputes them from the files on disk.
"""
from __future__ import annotations

import collections
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
EVIDENCE = HERE / "evidence"
sys.path.insert(0, str(HERE))
import oracle_bytes  # noqa: E402
import run_evidence as harness  # noqa: E402


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse_a0(raw, columns):
    lines = [line for line in raw.decode("utf-8", errors="replace").splitlines()
             if line.startswith("|")]
    require(lines, "A0 table absent")
    parsed = [[value.strip() for value in line.strip("|").split("|")] for line in lines]
    require(parsed[0] == [name for name, _ in columns], "A0 header drift")
    return [dict(zip([name for name, _ in columns], row)) for row in parsed[1:]]


def main():
    report = json.loads((HERE / "result.json").read_text(encoding="utf-8"))
    require(report["task_complete_proven"] is False and report["profile_admitted"] is False,
            "scope overclaimed")
    require(digest(harness.A0.read_bytes()) == report["a0_sha256"] == harness.A0_SHA,
            "A0 identity changed")
    require(digest(harness.SDK.read_bytes()) == report["sdk_dexdump_sha256"] == harness.SDK_SHA,
            "SDK identity changed")
    require(digest((EVIDENCE / "probe_all.exe").read_bytes()) == report["probe_binary_sha256"],
            "probe binary changed")
    for path, sha in report["sources"].items():
        require(digest((ROOT / path).read_bytes()) == sha, "source changed: " + path)
    checked = 0
    for case in report["cases"]:
        inputs = [(kind, Path(path)) for kind, path in case["inputs"]]
        occurrences = oracle_bytes.read_inputs(inputs)
        native = json.loads((EVIDENCE / ("native-" + case["name"]) / "stdout.txt")
                            .read_text(encoding="utf-8"))
        require(native["operation_status"] == "ok" and native["probe_complete"],
                "native terminal incomplete: " + case["name"])
        require(len(native["occurrences"]) == len(occurrences),
                "occurrence count differs: " + case["name"])
        facts = report["measured_facts"][case["name"]]
        for relation, spec in harness.RELATIONS.items():
            for content in (False, True):
                if content and spec["content"] is None:
                    continue
                key = relation + (":content" if content else ":full")
                fact = facts[key]
                columns = spec["content"] if content else spec["full"]
                names = [name for name, _ in columns]
                indexed = harness.oracle_rows(occurrences, relation, content)
                natural = [row for _, row in indexed]
                canonical = spec["canonical_content" if content else "canonical_full"]
                indexed.sort(key=lambda pair: canonical(pair[0], pair[1]))
                sorted_rows = [row for _, row in indexed]
                folder = "a0-" + case["name"] + "-" + key.replace(":", "-")
                a0 = parse_a0((EVIDENCE / folder / "stdout.txt").read_bytes(), columns)
                expected = [{name: harness.cell(name, row.get(name)) for name in names}
                            for row in sorted_rows]
                require(a0 == expected, "A0 sequence changed: " + case["name"] + "/" + key)
                native_rows = harness.native_rows(native, relation, content)
                if relation == "dex_files_identity":
                    oracle_native = [{k: row[k] for k in ("file_id", "source_path", "entry_name")}
                                     for row in natural]
                    require(native_rows == oracle_native,
                            "native identity sequence changed: " + case["name"])
                else:
                    require(native_rows == natural,
                            "native sequence changed: " + case["name"] + "/" + key)
                require(fact["oracle_rows"] == len(natural) and fact["a0_rows"] == len(a0)
                        and fact["native_rows"] == len(native_rows),
                        "row count drift: " + case["name"] + "/" + key)
                require(fact["exact_duplicate_rows_compared"] == harness.duplicate_count(natural),
                        "duplicate count drift: " + case["name"] + "/" + key)
                require(fact["a0_sequence_equal"] and fact["native_sequence_equal"],
                        "sequence flag drift: " + case["name"] + "/" + key)
                checked += 1
    # verdict consistency: every verdict state must follow from the measured facts.
    by_projection = {}
    for case in report["cases"]:
        for key, fact in report["measured_facts"][case["name"]].items():
            previous = by_projection.get(key)
            if previous is None or fact["exact_duplicate_rows_compared"] > previous["exact_duplicate_rows_compared"]:
                by_projection[key] = fact
    for verdict in report["verdicts"]:
        if verdict["category"] != "multiplicity":
            continue
        fact = by_projection[verdict["projection"]]
        expected_state = ("satisfied" if fact["exact_duplicate_rows_compared"] > 0
                          else "partial")
        require(verdict["state"] == expected_state,
                "multiplicity verdict drift: " + verdict["projection"])
    readback = {
        "schema_version": "mdd.evidence-definition-header-readback.v1",
        "status": "passed",
        "result_sha256": digest((HERE / "result.json").read_bytes()),
        "cases": len(report["cases"]),
        "projections_checked": checked,
        "verdicts": len(report["verdicts"]),
        "source_files_checked": len(report["sources"]),
        "task_complete_proven": False,
        "profile_admitted": False,
        "scope": "captured synthetic fixtures and A0/native outputs; no new execution",
    }
    (HERE / "readback.json").write_text(json.dumps(readback, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(readback))


if __name__ == "__main__":
    main()
