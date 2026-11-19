"""MDD-054: compare two complete HostLab audit runs, A and B, item by item. Standard library only.

A run is the files HostLab's own full audit leaves behind plus the evidence HostLab's own `verify_audits.evidence`
builds from them: `summary.json` (the report), `features.tsv` (what HostLab publishes), `evidence.json` (the 20
evidence groups). The comparison asks, in this order, and reports every layer instead of stopping at the first:

1. run     both runs are complete, name the same input, the same reference source and the same tools, report no
           fallback, and carry all 27 FEATURE and all 20 groups;
2. report  every field of `summary.json` is equal except the fields of the versioned ignore list (engine identity and
           clocks, nothing else);
3. tsv     the published FEATURE rows are equal byte for byte, so their declaration order is part of the result;
4. groups  each of the 20 groups is equal. A group the contract declares a multiset is compared as a bag: its order
           does not matter, its repetitions do (a dropped duplicate is a difference). Every other group is compared in
           order. NULL is never an empty string, an empty list or zero, and an integer is never its text.

A difference is kept as evidence, not as "diff failed": the layer, the path, the expected and observed value (cut at
`VALUE_LIMIT` characters, with their full length and SHA-256), the count of differences, and for a bag the number of
missing and extra elements with the first few of each. Nothing is added to the ignore list to make a run pass: a field
that differs and is not on the list is a difference.
"""
from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA = "mdd.hostlab-full-comparison.v1"
VALUE_LIMIT = 240
DIFFERENCE_LIMIT = 40

EVIDENCE_KEYS = (
    "class_records", "discoveries", "families", "features", "gates", "home_probe_sha256", "invoke_edges",
    "limitations", "page_path_matrix", "protocol_definitions", "protocol_paths", "protocol_twins",
    "resource_fingerprints", "rule_sha256", "rule_version", "sample", "scope", "unclassified_protocol_callers",
    "unknown_families", "unregistered_protocols",
)
# The groups whose elements are a bag: the 2026-10-28 baseline contract (artifacts/mdd-005/preparation-20261028)
# sorted exactly these before hashing, so an equal bag is equal there and here.
MULTISET_GROUPS = frozenset({
    "class_records", "invoke_edges", "protocol_definitions", "protocol_twins", "unclassified_protocol_callers", "discoveries",
})
FEATURE_COUNT = 27

# Versioned and explicit. Only what a different engine or a different clock must change. `native` is the engine's own
# identity record: each run states its engine there (and in its certificate), so it is compared as identity by the
# harness, not as audit output. Wire format, version and path are the engine's; the counts it reports are not here.
IGNORE_LIST = {
    "schema": "mdd.hostlab-shadow-ignore.v1",
    "version": 1,
    "report_paths": (
        "/native_audit/native",
        "/native_audit/elapsed_ms",
        "/native_audit/phases/prepare_ms",
        "/native_audit/phases/structural_ms",
        "/native_audit/phases/surface_ms",
    ),
    "not_ignorable": (
        "NULL against empty", "repeat counts", "source-local ids", "declaration order", "coverage",
        "fingerprints", "offsets", "flags", "verdict and gate states",
    ),
}


# ---- reading --------------------------------------------------------------------------------------------------------

def _unique(pairs):
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def _nonfinite(value):
    raise ValueError("non-finite JSON constant: " + value)


def read_json(path: "str | Path") -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_unique, parse_constant=_nonfinite)


def load_run(directory: "str | Path", *, summary: "str | Path | None" = None) -> dict:
    """A run's files. `directory` holds evidence.json; the report files are where HostLab left them."""
    directory = Path(directory)
    if summary is None:
        found = sorted((directory / "state" / "reports").glob("*/*/*/summary.json"))
        if len(found) != 1:
            raise ValueError(f"{directory}: expected exactly one summary.json, found {len(found)}")
        summary = found[0]
    summary = Path(summary)
    return {
        "summary": read_json(summary),
        "tsv": (summary.with_name("features.tsv")).read_text(encoding="utf-8"),
        "evidence": read_json(directory / "evidence.json"),
        "certificate": read_json(directory / "certificate.json") if (directory / "certificate.json").is_file() else None,
    }


# ---- canonical form --------------------------------------------------------------------------------------------------

def canon(value: Any) -> str:
    """A string that is equal exactly when the JSON values are equal and of the same JSON type. `True` is not `1`, `1` is
    not `1.0`, `"1"` is not `1`, null is not the empty string, key order of an object does not matter."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canon(value).encode("utf-8")).hexdigest()


def shown(value: Any) -> dict:
    text = canon(value)
    cut = text if len(text) <= VALUE_LIMIT else text[:VALUE_LIMIT] + "..."
    return {"value": cut, "length": len(text), "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}


def group_form(name: str, value: Any) -> Any:
    """What a group is compared as: a bag becomes its sorted canonical elements, which keeps every repetition."""
    if name in MULTISET_GROUPS:
        if not isinstance(value, list):
            raise ValueError(f"group {name} is declared a multiset and must be a list")
        return sorted(canon(item) for item in value)
    return value


def group_digest(name: str, value: Any) -> dict:
    form = group_form(name, value)
    return {"sha256": digest(form), "count": len(value) if isinstance(value, (dict, list, tuple)) else None}


# ---- differences ---------------------------------------------------------------------------------------------------------

def deep_differences(expected: Any, observed: Any, where: str = "", limit: int = DIFFERENCE_LIMIT, ignore: tuple = ()) -> "tuple[list, int]":
    """Every place the two values differ, as {path, expected, observed}, and how many there are in all (the list is cut at
    `limit`). A missing key, an extra key, a different length and a different JSON type are differences; `True` and `1`
    are different types here."""
    found: list = []
    total = [0]

    def note(path: str, a: Any, b: Any) -> None:
        total[0] += 1
        if len(found) < limit:
            found.append({"path": path or "/", "expected": a if isinstance(a, str) and a in ("<absent>",) else shown(a),
                          "observed": b if isinstance(b, str) and b in ("<absent>",) else shown(b)})

    def walk(a: Any, b: Any, path: str) -> None:
        if any(path == item or path.startswith(item + "/") for item in ignore):
            return
        if type(a) is not type(b):
            note(path, a, b)
        elif isinstance(a, dict):
            for key in sorted(set(a) | set(b), key=str):
                child = f"{path}/{key}"
                if any(child == item or child.startswith(item + "/") for item in ignore):
                    continue
                if key not in a:
                    note(child, "<absent>", b[key])
                elif key not in b:
                    note(child, a[key], "<absent>")
                else:
                    walk(a[key], b[key], child)
        elif isinstance(a, list):
            if len(a) != len(b):
                note(path, {"items": len(a)}, {"items": len(b)})
            for index, (x, y) in enumerate(zip(a, b)):
                walk(x, y, f"{path}[{index}]")
        elif a != b:
            note(path, a, b)

    walk(expected, observed, where)
    return found, total[0]


def bag_differences(expected: list, observed: list, limit: int = 5) -> dict:
    """Missing and extra elements of two bags (their canonical strings), repetition counted."""
    a, b = Counter(expected), Counter(observed)
    missing, extra = a - b, b - a
    return {
        "expected_elements": len(expected), "observed_elements": len(observed),
        "missing_count": sum(missing.values()), "extra_count": sum(extra.values()),
        "missing_first": [dict(shown(json.loads(text)), times=times) for text, times in sorted(missing.items())[:limit]],
        "extra_first": [dict(shown(json.loads(text)), times=times) for text, times in sorted(extra.items())[:limit]],
    }


def _layer(name: str, differences: list, total: int, detail: "dict | None" = None) -> dict:
    layer = {"layer": name, "equal": total == 0, "difference_count": total, "differences": differences}
    if detail:
        layer["detail"] = detail
    return layer


# ---- the four layers --------------------------------------------------------------------------------------------------------

def run_identity_layer(a: dict, b: dict) -> dict:
    """Both runs are complete runs of the same thing; a mismatch here makes the rest meaningless, and is reported first."""
    problems: list = []

    def need(condition: bool, path: str, expected: Any, observed: Any) -> None:
        if not condition:
            problems.append({"path": path, "expected": shown(expected), "observed": shown(observed)})

    for side, run in (("A", a), ("B", b)):
        summary, evidence = run["summary"], run["evidence"]
        native = summary.get("native_audit") or {}
        need(summary.get("audit_complete") is True, f"/{side}/audit_complete", True, summary.get("audit_complete"))
        need(native.get("complete") is True, f"/{side}/native_audit/complete", True, native.get("complete"))
        need(native.get("source_sha_reverified") is True, f"/{side}/native_audit/source_sha_reverified", True, native.get("source_sha_reverified"))
        need(summary.get("backend_fallback_reason") is None, f"/{side}/backend_fallback_reason", None, summary.get("backend_fallback_reason"))
        need(summary.get("mode") == "full", f"/{side}/mode", "full", summary.get("mode"))
        need(isinstance(summary.get("features"), dict) and len(summary["features"]) == FEATURE_COUNT,
             f"/{side}/features", FEATURE_COUNT, len(summary.get("features") or {}))
        need(set(evidence) == set(EVIDENCE_KEYS), f"/{side}/evidence_groups", sorted(EVIDENCE_KEYS), sorted(evidence))
        certificate = run.get("certificate")
        if certificate is not None:
            need(certificate.get("fallback_count") == 0, f"/{side}/certificate/fallback_count", 0, certificate.get("fallback_count"))
            need(certificate.get("output_fully_materialized") is True, f"/{side}/certificate/output_fully_materialized", True, certificate.get("output_fully_materialized"))
            need(certificate.get("more_available") is False, f"/{side}/certificate/more_available", False, certificate.get("more_available"))
            need(certificate.get("truncated") is False, f"/{side}/certificate/truncated", False, certificate.get("truncated"))
    sa, sb = a["summary"], b["summary"]
    need(sa.get("sample", {}).get("sha256") == sb.get("sample", {}).get("sha256"), "/sample/sha256",
         sa.get("sample", {}).get("sha256"), sb.get("sample", {}).get("sha256"))
    need(sa.get("tools") == sb.get("tools"), "/tools", sa.get("tools"), sb.get("tools"))
    if a.get("certificate") is not None and b.get("certificate") is not None:
        for key in ("input_sha256", "reference_source_commit", "tools"):
            need(a["certificate"].get(key) == b["certificate"].get(key), f"/certificate/{key}", a["certificate"].get(key), b["certificate"].get(key))
    return _layer("run", problems[:DIFFERENCE_LIMIT], len(problems))


def report_layer(a: dict, b: dict) -> dict:
    found, total = deep_differences(a["summary"], b["summary"], ignore=IGNORE_LIST["report_paths"])
    return _layer("report", found, total, {"ignore_list": IGNORE_LIST["schema"] + " v" + str(IGNORE_LIST["version"]),
                                           "ignored_paths": list(IGNORE_LIST["report_paths"])})


def tsv_layer(a: dict, b: dict) -> dict:
    left, right = a["tsv"].splitlines(keepends=True), b["tsv"].splitlines(keepends=True)
    found: list = []
    total = 0
    for index in range(max(len(left), len(right))):
        x, y = left[index] if index < len(left) else "<absent>", right[index] if index < len(right) else "<absent>"
        if x != y:
            total += 1
            if len(found) < DIFFERENCE_LIMIT:
                found.append({"path": f"line {index + 1}", "expected": shown(x), "observed": shown(y)})
    return _layer("tsv", found, total, {"lines": [len(left), len(right)], "bytes_equal": a["tsv"] == b["tsv"]})


def groups_layer(a: dict, b: dict) -> dict:
    groups: dict = {}
    found: list = []
    total = 0
    for name in EVIDENCE_KEYS:
        if name not in a["evidence"] or name not in b["evidence"]:
            groups[name] = {"equal": False, "reason": "a group is missing"}
            found.append({"path": f"/{name}", "expected": shown(name in a["evidence"]), "observed": shown(name in b["evidence"])})
            total += 1
            continue
        left, right = a["evidence"][name], b["evidence"][name]
        form_a, form_b = group_form(name, left), group_form(name, right)
        entry = {"A": group_digest(name, left), "B": group_digest(name, right), "kind": "multiset" if name in MULTISET_GROUPS else "ordered"}
        entry["equal"] = canon(form_a) == canon(form_b)
        if not entry["equal"]:
            if name in MULTISET_GROUPS:
                entry["bag"] = bag_differences(form_a, form_b)
                if not entry["bag"]["missing_count"] and not entry["bag"]["extra_count"]:
                    entry["bag"]["note"] = "equal as bags; the hashes differ only by type"
            where, count = deep_differences(left, right, f"/{name}", limit=5)
            entry["first_differences"], entry["difference_count"] = where, count
            total += max(1, count)
            found.extend(where[:3])
        groups[name] = entry
    return _layer("groups", found[:DIFFERENCE_LIMIT], total, {"groups": groups})


def compare(a: dict, b: dict) -> dict:
    """The full comparison of run A (expected) and run B (observed). `equal` is true only if every layer is."""
    layers = [run_identity_layer(a, b), report_layer(a, b), tsv_layer(a, b), groups_layer(a, b)]
    return {"schema": SCHEMA, "equal": all(layer["equal"] for layer in layers),
            "layers": layers, "ignore_list": {k: IGNORE_LIST[k] for k in ("schema", "version", "report_paths")},
            "scope": "complete same-input audit evidence equality only; not a timing, not a profile qualification"}


def main(argv: "list[str] | None" = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print("usage: compare_full_reports.py RUN_DIR_A RUN_DIR_B", file=sys.stderr)
        return 2
    result = compare(load_run(args[0]), load_run(args[1]))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["equal"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
