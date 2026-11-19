"""MDD-054: write artifacts/mdd-054/full-equivalence.json from finished shadow runs. Standard library only.

    python -I integrations/hostlab/make_full_equivalence.py [--run LABEL=RUN_DIR]... [--validation LABEL=RUN_DIR:HISTORICAL_DIR]...
        [--attempt LABEL=RUN_DIR]... --output FILE

A RUN_DIR is what `run_shadow.py` leaves: A/ and B/ folders (each with evidence.json, certificate.json, state/reports/...),
comparison.json, shadow-run.json. The record keeps identities, counts and digests - never an evidence value, a path of
this machine or a byte of the private APK - so it can be committed.

--run is a pair that completed on both sides. --validation is a side-A-only run of this harness checked against an earlier,
independent run of the same engine and input (HISTORICAL_DIR holds that run's evidence.json and report): it shows that the
harness reproduces what was recorded before, which is what makes a later B run credible. --attempt is a side-B run that did
not complete: it is recorded as it ended, and compared with nothing.

For each completed pair and each validation run it also damages a copy of A's own evidence, one edit at a time, and shows that the comparison against the
undamaged A fails in the layer the edit belongs to. A comparator that passes the real pair but could not fail would prove
nothing; this shows on the real data (not only on the synthetic run of the unit tests) that it can.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "conformance/hostlab"))

import compare_full_reports as C  # noqa: E402

SCHEMA = "mdd.hostlab-full-equivalence.v1"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def first_none_path(value, path=""):
    if isinstance(value, dict):
        for key in sorted(value, key=str):
            found = first_none_path(value[key], f"{path}/{key}")
            if found:
                return found
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found = first_none_path(item, f"{path}[{index}]")
            if found:
                return found
    elif value is None:
        return path
    return None


def set_at(root, path: str, value) -> None:
    """Set the value at a /key[index]/key path built by `first_none_path`."""
    import re
    parts = re.findall(r"/([^/\[]+)|\[(\d+)\]", path)
    target = root
    steps = [(k, i) for k, i in parts]
    for position, (key, index) in enumerate(steps):
        last = position == len(steps) - 1
        slot = key if key else int(index)
        if last:
            target[slot] = value
        else:
            target = target[slot]


def controls(run: dict) -> "list[dict]":
    """Edits of a copy of A's own run; each comparison of A (expected) with the edit (observed) must fail in `layer`."""
    results = []

    def attempt(name: str, layer: str, edit) -> None:
        damaged = copy.deepcopy(run)
        try:
            edit(damaged)
        except StopIteration:
            results.append({"control": name, "layer": layer, "applied": False, "reason": "this run has no element to edit"})
            return
        outcome = C.compare(run, damaged)
        entry = next(item for item in outcome["layers"] if item["layer"] == layer)
        results.append({"control": name, "layer": layer, "applied": True, "comparison_equal": outcome["equal"],
                        "layer_equal": entry["equal"], "detected": (not outcome["equal"]) and not entry["equal"]})

    def drop_one_element(group):
        def edit(r):
            if not r["evidence"][group]:
                raise StopIteration
            r["evidence"][group].pop(0)
        return edit

    def drop_one_repeat(group):
        def edit(r):
            seen = {}
            for index, item in enumerate(r["evidence"][group]):
                key = C.canon(item)
                if key in seen:
                    r["evidence"][group].pop(index)
                    return
                seen[key] = index
            raise StopIteration
        return edit

    for group in sorted(C.MULTISET_GROUPS):
        attempt(f"one element of {group} dropped", "groups", drop_one_element(group))
        attempt(f"one repeated element of {group} counted once", "groups", drop_one_repeat(group))

    def null_to_empty(r):
        path = first_none_path(r["evidence"]["class_records"], "")
        if path is None:
            raise StopIteration
        set_at(r["evidence"]["class_records"], path, "")
    attempt("a NULL in class_records became an empty text", "groups", null_to_empty)

    def id_shift(r):
        record = next(item for item in r["evidence"]["class_records"] if isinstance(item.get("file_id"), int))
        record["file_id"] += 1
    attempt("a class attributed to the next DEX (source-local id)", "groups", id_shift)

    def fingerprint(r):
        name = sorted(r["evidence"]["resource_fingerprints"])[0]
        value = r["evidence"]["resource_fingerprints"][name]
        r["evidence"]["resource_fingerprints"][name] = ("0" if value[:1] != "0" else "1") + value[1:]
    attempt("one resource fingerprint changed", "groups", fingerprint)

    def reorder_ordered(r):
        items = r["evidence"]["limitations"]
        if len(items) < 2 or items[0] == items[1]:
            raise StopIteration
        items[0], items[1] = items[1], items[0]
    attempt("two limitations swapped (an ordered group)", "groups", reorder_ordered)

    def gate(r):
        r["evidence"]["gates"]["home_probe_exit_code"] = 1 - int(r["evidence"]["gates"]["home_probe_exit_code"])
    attempt("a gate exit code flipped", "groups", gate)

    def swap_rows(r):
        rows = r["tsv"].splitlines(keepends=True)
        feature_rows = [i for i, row in enumerate(rows) if row.startswith("FEATURE\t")]
        rows[feature_rows[0]], rows[feature_rows[1]] = rows[feature_rows[1]], rows[feature_rows[0]]
        r["tsv"] = "".join(rows)
    attempt("two published FEATURE rows swapped (declaration order)", "tsv", swap_rows)

    def feature_status(r):
        name = sorted(r["summary"]["features"])[0]
        r["summary"]["features"][name]["status"] = "MISSING" if r["summary"]["features"][name]["status"] != "MISSING" else "FOUND"
    attempt("one FEATURE status changed", "report", feature_status)
    attempt("the query count changed", "report", lambda r: r["summary"]["native_audit"].__setitem__("queries", r["summary"]["native_audit"]["queries"] + 1))
    attempt("a coverage gap added", "report", lambda r: r["summary"].__setitem__("coverage_gaps", list(r["summary"]["coverage_gaps"]) + ["x"]))
    attempt("a fallback recorded", "run", lambda r: r["summary"].__setitem__("backend_fallback_reason", "engine failed"))
    attempt("another input", "run", lambda r: r["summary"]["sample"].__setitem__("sha256", "0" * 64))
    return results


def describe_run(label: str, directory: Path) -> dict:
    a, b = C.load_run(directory / "A"), C.load_run(directory / "B")
    comparison = C.compare(a, b)
    ca, cb = a["certificate"], b["certificate"]
    groups = comparison["layers"][3]["detail"]["groups"]
    entry = {
        "run": label,
        "input": {"sha256": ca["input_sha256"], "version_code": a["summary"]["sample"].get("version_code"),
                  "package": a["summary"]["sample"].get("package")},
        "reference_source_commit": ca["reference_source_commit"],
        "engines": {"A": {k: ca["engine"].get(k) for k in ("engine", "version", "sha256")},
                    "B": {k: cb["engine"].get(k) for k in ("engine", "version", "build_id", "sha256", "wire", "implementation_scope")}},
        "complete": {"A": ca["complete"], "B": cb["complete"]},
        "counts": {"features": ca["feature_count"], "evidence_groups": ca["evidence_group_count"],
                   "class_count": [ca["class_count"], cb["class_count"]], "queries": [ca["queries"], cb["queries"]]},
        "fallback_count": [ca["fallback_count"], cb["fallback_count"]],
        "violations": [ca["violations"], cb["violations"]],
        "equal": comparison["equal"],
        "layers": [{"layer": item["layer"], "equal": item["equal"], "difference_count": item["difference_count"]} for item in comparison["layers"]],
        "groups": {name: {"equal": value["equal"], "kind": value.get("kind"), "count_A": value["A"]["count"], "count_B": value["B"]["count"],
                          "sha256_A": value["A"]["sha256"], "sha256_B": value["B"]["sha256"]} for name, value in groups.items()},
        "supervisor": {side: {k: read_supervisor(directory / side).get(k) for k in ("status", "exit_code", "peak_job_commit_bytes", "tree_empty_verified")}
                       for side in ("A", "B")},
        "wall_seconds_not_a_measurement": {"A": ca["wall_seconds"], "B": cb["wall_seconds"]},
        "published_rows": {"bytes_equal": comparison["layers"][2]["detail"]["bytes_equal"], "lines": comparison["layers"][2]["detail"]["lines"]},
        "files": {"A_evidence_sha256": sha256_file(directory / "A/evidence.json"), "B_evidence_sha256": sha256_file(directory / "B/evidence.json")},
    }
    if not comparison["equal"]:
        entry["first_differences"] = [{"layer": item["layer"], "differences": item["differences"][:5]} for item in comparison["layers"] if not item["equal"]]
        entry["bag_differences"] = {name: value["bag"] for name, value in groups.items() if "bag" in value}
    entry["controls_on_real_evidence"] = controls(a)
    return entry


def read_supervisor(folder: Path) -> dict:
    return json.loads((folder / "job/supervisor.json").read_text(encoding="utf-8"))


def describe_validation(label: str, run_dir: Path, historical: Path) -> dict:
    new, old = C.load_run(run_dir / "A"), C.load_run(historical)
    comparison = C.compare(old, new)
    groups = comparison["layers"][3]["detail"]["groups"]
    certificate = new["certificate"]
    supervisor = read_supervisor(run_dir / "A")
    return {
        "run": label, "side": "A", "engine": {k: certificate["engine"].get(k) for k in ("engine", "version", "sha256")},
        "input": {"sha256": certificate["input_sha256"], "version_code": new["summary"]["sample"].get("version_code")},
        "against": "an earlier run of the same engine and input, made by the 2026-10-28 baseline driver (not by this harness)",
        "equal": comparison["equal"],
        "layers": [{"layer": item["layer"], "equal": item["equal"], "difference_count": item["difference_count"]} for item in comparison["layers"]],
        "group_digests_equal": {name: value["equal"] for name, value in groups.items()},
        "counts": {"class_count": certificate["class_count"], "queries": certificate["queries"], "features": certificate["feature_count"],
                   "evidence_groups": certificate["evidence_group_count"]},
        "violations": certificate["violations"], "fallback_count": certificate["fallback_count"],
        "supervisor": {k: supervisor.get(k) for k in ("status", "exit_code", "peak_job_commit_bytes", "tree_empty_verified")},
        "limits": supervisor.get("limits"), "wall_seconds_not_a_measurement": certificate["wall_seconds"],
        "controls_on_real_evidence": controls(new),
    }


ERROR_LINE = re.compile(r"^(native_session\.\w+|[\w.]*Error[\w.]*): (.*)$")


def describe_attempt(label: str, run_dir: Path) -> dict:
    supervisor = read_supervisor(run_dir / "B")
    stderr = (run_dir / "B/job/stderr.txt").read_text(encoding="utf-8", errors="replace").splitlines()
    ended = next((m for m in (ERROR_LINE.match(line) for line in reversed(stderr)) if m), None)
    return {
        "attempt": label, "side": "B", "complete": False,
        "memory_limit_bytes": (supervisor.get("limits") or {}).get("memory_commit_bytes"),
        "status": supervisor.get("status"), "exit_code": supervisor.get("exit_code"), "reason": supervisor.get("reason"),
        "peak_job_commit_bytes": supervisor.get("peak_job_commit_bytes"), "wall_seconds_not_a_measurement": supervisor.get("wall_seconds"),
        "tree_empty_verified": supervisor.get("tree_empty_verified"),
        "ended_with": {"error": ended.group(1), "message": re.sub(r"[A-Za-z]:[\\/][^\s]*", "<path>", ended.group(2))} if ended else None,
        "report_written": (run_dir / "B/certificate.json").is_file(),
        "compared_with_anything": False,
    }


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--run", action="append", default=[], help="LABEL=RUN_DIR")
    parser.add_argument("--validation", action="append", default=[], help="LABEL=RUN_DIR:HISTORICAL_DIR")
    parser.add_argument("--attempt", action="append", default=[], help="LABEL=RUN_DIR")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if not (args.run or args.validation or args.attempt):
        parser.error("nothing to record")
    runs = [describe_run(label, Path(directory)) for label, _, directory in (item.partition("=") for item in args.run)]
    validations = []
    for item in args.validation:
        label, _, rest = item.partition("=")
        directory, _, historical = rest.partition("::")
        validations.append(describe_validation(label, Path(directory), Path(historical)))
    attempts = [describe_attempt(label, Path(directory)) for label, _, directory in (item.partition("=") for item in args.attempt)]
    undetected = [f"{run.get('run')}: {c['control']}" for run in runs + validations for c in run["controls_on_real_evidence"] if c["applied"] and not c["detected"]]
    if runs and all(run["equal"] for run in runs) and not attempts:
        status = "equivalence_shown_on_the_runs_listed"
    elif runs:
        status = "partial: some pairs completed, some did not"
    else:
        status = "engine_run_not_completed: the harness is validated against the reference engine; no A/B pair exists"
    record = {"schema": SCHEMA, "task": "MDD-054", "status": status, "runs": runs, "harness_validation": validations,
              "failed_engine_attempts": attempts, "controls_not_detected": undetected,
              "ignore_list": {k: C.IGNORE_LIST[k] for k in ("schema", "version", "report_paths")},
              "scope": "what the shadow harness and comparator were shown to do, and how the engine runs ended; a correctness record, no timing, no profile qualification",
              "not_proven": [
                  "that MeguvizDexDash gives the same complete HostLab audit as the reference engine on a real APK: no B run has completed, so no pair was compared",
                  "anything about the second authorized input (9.17.0): it was not run, because the first input already does not fit",
                  "that the engine can open an APK of this size in a bounded memory: it cannot in 14 GiB today (see failed_engine_attempts)",
                  "the repeated-element and NULL controls on real evidence: the real A evidence has no exactly repeated element in a bag group and no NULL in class_records, so those controls were not applicable here (the unit tests damage them on a synthetic run)",
                  "macOS, Linux or any machine but this Windows host; a Linux/WebKit or CI run of the shadow",
                  "that the audit conclusions are right: both sides run HostLab's own analyze.main, so a comparison shows the engines agree under that consumer, not that the consumer is correct",
              ]}
    args.output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"status": status, "controls_not_detected": undetected,
                      "validation": [{"run": v["run"], "equal": v["equal"]} for v in validations],
                      "attempts": [{"attempt": a["attempt"], "peak": a["peak_job_commit_bytes"], "ended_with": a["ended_with"]} for a in attempts]},
                     ensure_ascii=False))
    return 0 if not undetected and all(v["equal"] for v in validations) and all(r["equal"] for r in runs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
