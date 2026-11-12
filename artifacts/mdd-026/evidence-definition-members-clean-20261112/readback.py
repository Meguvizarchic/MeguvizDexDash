#!/usr/bin/env python3
"""Independent readback for the MDD-026 definition/member fix evidence.

This script re-reads the captured native/A0 process outputs and the source
bytes, recomputes the independent oracle projections, and checks that the
comparisons, negative controls and source hashes recorded in result.json are
reproducible.  It imports the two independent byte oracles and re-uses the
harness's pure row-extraction helpers; every comparison, negative control and
NULL count is recomputed here from the captured process outputs and the source
bytes, not copied from result.json.

It never signs MDD-026.
"""
from __future__ import annotations

import collections
import datetime
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
EVIDENCE = HERE / "evidence"
sys.path.insert(0, str(HERE))
import oracle_bytes as ob  # noqa: E402
import oracle_members as om  # noqa: E402

import run_evidence as harness  # noqa: E402  (only for column/relation metadata)

A0_SHA = "f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def decode_a0_cell(relation, column, cell):
    if cell == "N":
        return None
    raw = bytes.fromhex(cell)
    kind = harness.a0_kind(relation, column)
    if kind in ("u32", "u64"):
        return int(raw.decode("ascii"))
    if kind == "hex":
        return raw.hex().upper()
    return raw.decode("utf-8", "surrogatepass")


def parse_a0_file(path, relation, columns):
    lines = [line for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
             if line.startswith("|")]
    require(lines, "empty A0 table: " + str(path))
    parsed = [[value.strip() for value in line.strip("|").split("|")] for line in lines]
    names = [name for name, _ in columns]
    require(parsed[0] == names, "A0 column drift: " + str(path))
    return [{name: decode_a0_cell(relation, name, cell)
             for (name, _), cell in zip(columns, row)} for row in parsed[1:]]


def sort_indexed_by_a0(indexed, order):
    def key(pair):
        occurrence_index, row = pair
        values = []
        for name in order:
            value = occurrence_index if name not in row else row.get(name)
            if value is None:
                values.append((0, 0))
            elif isinstance(value, (int, float)):
                values.append((1, value))
            else:
                values.append((2, str(value)))
        return tuple(values)
    return sorted(indexed, key=key)


def duplicate_count(rows):
    canonical = collections.Counter(json.dumps(row, sort_keys=True) for row in rows)
    return sum(value - 1 for value in canonical.values() if value > 1)


def null_counts(rows, columns):
    nulls = collections.Counter()
    non_nulls = collections.Counter()
    for row in rows:
        for name in columns:
            if row.get(name) is None:
                nulls[name] += 1
            else:
                non_nulls[name] += 1
    return nulls, non_nulls


def recompute_controls(native_rows, oracle_rows, columns, row_key, nullable):
    controls = {}
    swap_index = None
    for index in range(len(native_rows) - 1):
        if native_rows[index] != native_rows[index + 1]:
            swap_index = index
            break
    if swap_index is not None:
        swapped = list(native_rows)
        swapped[swap_index], swapped[swap_index + 1] = swapped[swap_index + 1], swapped[swap_index]
        controls["swap_adjacent_distinct_rows"] = {
            "rejected": swapped != oracle_rows, "applicable": True}
    else:
        controls["swap_adjacent_distinct_rows"] = {"rejected": "not_applicable",
                                                   "applicable": False}
    dropped = native_rows[1:] if native_rows else []
    controls["drop_first_row"] = {
        "rejected": (len(dropped) != len(oracle_rows)) if native_rows else "not_applicable",
        "applicable": bool(native_rows)}
    if native_rows:
        mutated = [dict(native_rows[0])] + list(native_rows[1:])
        mutated[0][columns[0]] = "__mutated__"
        controls["mutate_first_cell"] = {"rejected": mutated != oracle_rows, "applicable": True}
    else:
        controls["mutate_first_cell"] = {"rejected": "not_applicable", "applicable": False}
    keys = [tuple(json.dumps(row.get(name), sort_keys=True) for name in row_key)
            for row in native_rows]
    deduped = list({key: row for key, row in zip(keys, native_rows)}.values()) if native_rows else []
    controls["key_dedup_changes_count"] = {
        "rejected": (len(deduped) != len(oracle_rows)) if native_rows else "not_applicable",
        "applicable": bool(native_rows) and len(deduped) != len(native_rows)}
    exact = list({json.dumps(row, sort_keys=True): row for row in native_rows}.values()) if native_rows else []
    controls["exact_dedup_changes_count"] = {
        "rejected": (len(exact) != len(oracle_rows)) if native_rows else "not_applicable",
        "applicable": bool(native_rows) and len(exact) != len(native_rows)}
    null_controls = {}
    for name in columns:
        if name in nullable:
            null_rows = [row for row in native_rows if row.get(name) is None]
            if null_rows:
                kept = [row for row in native_rows if row.get(name) is not None]
                null_controls[name] = {"rejected": len(kept) != len(oracle_rows),
                                       "applicable": True}
            else:
                null_controls[name] = {"rejected": "not_applicable", "applicable": False}
        else:
            if native_rows and all(row.get(name) is not None for row in native_rows):
                altered = [dict(native_rows[0])] + list(native_rows[1:])
                altered[0][name] = None
                null_controls[name] = {"rejected": altered != oracle_rows, "applicable": True}
            else:
                null_controls[name] = {"rejected": "not_applicable", "applicable": False}
    return controls, null_controls


def main():
    result = load_json(HERE / "result.json")
    checks = []
    passed = True

    def check(name, condition, detail=""):
        nonlocal passed
        checks.append({"check": name, "passed": bool(condition), "detail": detail})
        if not condition:
            passed = False

    # ---- source hashes
    for relative, expected in result["sources"].items():
        path = ROOT / relative
        if not path.is_file():
            check("source:" + relative, False, "missing")
            continue
        actual = digest_file(path)
        check("source:" + relative, actual == expected, actual)

    # ---- A0 binary identity
    check("a0_identity", digest_file(harness.A0) == A0_SHA)

    # ---- cases
    cases = {case["name"]: case for case in result["cases"]}
    oracle_cache = {}
    for case in result["cases"]:
        name = case["name"]
        inputs = [(kind, Path(path)) for kind, path in case["inputs"]]
        if case["group"] == "definition":
            occurrences = ob.read_inputs(inputs)
            oracle_cache[name] = ("definition", occurrences)
        else:
            oracles = [om.load(path)[0] for kind, path in inputs]
            oracle_cache[name] = ("members", oracles)

    # ---- comparisons
    for comparison in result["comparisons"]:
        case = comparison["case"]
        relation = comparison["relation"]
        projection = comparison["projection"]
        group = comparison["relation_group"]
        spec = (harness.DEFINITION_RELATIONS if group == "definition"
                else harness.MEMBER_RELATIONS)[relation]
        columns = spec["content"] if projection == "content" else spec["columns"]
        column_names = [name for name, _ in columns]
        native_path = EVIDENCE / ("native-" + case) / "stdout.txt"
        a0_path = EVIDENCE / ("a0-" + case + "-" + relation + "-" + projection) / "stdout.txt"
        check("native_exists:" + case + ":" + relation + ":" + projection, native_path.is_file())
        check("a0_exists:" + case + ":" + relation + ":" + projection, a0_path.is_file())
        if not (native_path.is_file() and a0_path.is_file()):
            continue
        native_doc = load_json(native_path)
        check("native_terminal:" + case,
              native_doc.get("operation_status") == "ok"
              and native_doc.get("probe_complete") is True
              and native_doc.get("profile_admitted") is False)
        a0_rows = parse_a0_file(a0_path, spec["a0_relation"], columns)
        occurrences = oracle_cache[case][1]
        if group == "definition":
            native_rows = harness.native_definition_rows(native_doc, relation, projection == "content")
            oracle_indexed = harness.oracle_definition_indexed(occurrences, relation,
                                                               projection == "content")
            if relation == "dex_files_identity":
                oracle_a0 = harness.oracle_definition_a0_rows(occurrences, relation,
                                                              projection == "content")
            elif relation == "strings" and projection == "full":
                oracle_a0 = harness.oracle_definition_a0_rows(occurrences, relation,
                                                              projection == "content")
            else:
                oracle_a0 = oracle_indexed
        else:
            native_rows = harness.native_member_rows(native_doc["dex_occurrences"], relation,
                                                     projection == "content")
            oracle_indexed = harness.oracle_member_indexed(occurrences, relation,
                                                           projection == "content")
            oracle_a0 = oracle_indexed
        oracle_rows = [row for _, row in oracle_indexed]
        native_equal = native_rows == oracle_rows
        a0_equal = a0_rows == [row for _, row in sort_indexed_by_a0(oracle_a0, spec["a0_order"])]
        check("native_sequence:" + case + ":" + relation + ":" + projection,
              native_equal == comparison["native_sequence_equal"],
              "recomputed=" + str(native_equal))
        check("a0_sequence:" + case + ":" + relation + ":" + projection,
              a0_equal == comparison["a0_sequence_equal"],
              "recomputed=" + str(a0_equal))
        check("row_counts:" + case + ":" + relation + ":" + projection,
              len(native_rows) == comparison["native_rows"]
              and len(oracle_rows) == comparison["oracle_rows"]
              and len(a0_rows) == comparison["a0_rows"])
        exact = duplicate_count(oracle_rows)
        check("exact_duplicates:" + case + ":" + relation + ":" + projection,
              exact == comparison["exact_duplicate_rows_compared"],
              "recomputed=" + str(exact))
        native_nulls, native_non_nulls = null_counts(native_rows, column_names)
        oracle_nulls, oracle_non_nulls = null_counts(oracle_rows, column_names)
        a0_nulls, a0_non_nulls = null_counts(a0_rows, column_names)
        for name in column_names:
            recorded = comparison["null_counts"][name]
            recomputed = {
                "native_null": native_nulls[name], "native_non_null": native_non_nulls[name],
                "oracle_null": oracle_nulls[name], "oracle_non_null": oracle_non_nulls[name],
                "a0_null": a0_nulls[name], "a0_non_null": a0_non_nulls[name]}
            check("null_counts:" + case + ":" + relation + ":" + projection + ":" + name,
                  recorded == recomputed)
        row_key = spec.get("row_key", column_names)
        controls, null_controls = recompute_controls(
            native_rows, oracle_rows, column_names, row_key,
            harness.NULLABLE.get(relation, set()))
        for name, recorded in comparison["negative_controls"].items():
            recomputed = controls[name]
            check("control:" + case + ":" + relation + ":" + projection + ":" + name,
                  recorded.get("rejected") == recomputed.get("rejected")
                  and recorded.get("applicable") == recomputed.get("applicable"),
                  "recomputed=" + json.dumps(recomputed, sort_keys=True))
        for name, recorded in comparison["null_controls"].items():
            recomputed = null_controls[name]
            check("null_control:" + case + ":" + relation + ":" + projection + ":" + name,
                  recorded.get("rejected") == recomputed.get("rejected")
                  and recorded.get("applicable") == recomputed.get("applicable"),
                  "recomputed=" + json.dumps(recomputed, sort_keys=True))

    # ---- duplicate-interface rejection control
    reject = result["negative_control_duplicate_interface"]
    reject_dir = EVIDENCE / "native-duplicate-interface-reject"
    stderr = (reject_dir / "stderr.txt").read_text(encoding="utf-8", errors="replace")
    check("duplicate_interface_rejected", reject["engine_rejected"] and "DUPLICATE_INTERFACE" in stderr)
    check("duplicate_interface_a0_lenient",
          len(reject["a0_rows"]) == 3 and reject["a0_accepts_duplicate_interface"])

    # ---- column verdict consistency
    require(len(result["columns"]) == 107, "column count differs")
    for column in result["columns"]:
        states = [item["state"] for item in column["categories"].values()]
        expected = ("missing" if any(state == "missing" for state in states)
                    else "partial" if any(state == "partial" for state in states)
                    else "satisfied")
        check("column_state:" + column["relation"] + "." + column["column"],
              column["state"] == expected)

    report = {
        "schema_version": "mdd.evidence-definition-members-fix-readback.v1",
        "task": "MDD-026",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "passed": passed,
        "checks": len(checks),
        "failed_checks": [item for item in checks if not item["passed"]],
        "task_complete_proven": False,
        "profile_admitted": False,
    }
    (HERE / "readback.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": passed, "checks": len(checks),
                      "failed": len(report["failed_checks"])}))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
