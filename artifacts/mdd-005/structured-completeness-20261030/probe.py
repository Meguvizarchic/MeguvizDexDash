#!/usr/bin/env python3
"""Bounded red/green observation; structured qualification stays unavailable."""
import hashlib
import json
import subprocess
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BASE = "6e6cdf4"
TARGET = "benchmarks/run-existing-baselines.py"


def module(source, name):
    result = types.ModuleType(name)
    result.__file__ = str(ROOT / TARGET)
    exec(compile(source, result.__file__, "exec"), result.__dict__)
    return result


def observe(source, name, case):
    runner = module(source, name)
    item = runner.ContractTests().fixture()
    if case == "structured_missing":
        item["comparison_mode"] = "structured"
        item["result"]["response"].update(emitted_rows="2", total_rows="2")
        item["final_dto"] = {}
    elif case == "string_rows":
        item["result"]["response"].update(emitted_rows="2", total_rows="2")
        item["final_dto"]["rows"] = "ab"
    elif case == "boolean_fallback":
        item["fallback_count"] = False
    elif case != "complete_zero":
        raise ValueError("unknown observation")
    try:
        return {"kind": "accepted", "result": runner.consume(
            item, ["fixture-occurrence"], "fixture-request", ["structure"])}
    except ValueError as error:
        return {"kind": "rejected", "message": str(error)}


def main():
    old = subprocess.run(
        ["git", "-c", "safe.directory=D:/MeguvisDexDash", "show", f"{BASE}:{TARGET}"],
        cwd=ROOT, check=True, capture_output=True).stdout
    current = (ROOT / TARGET).read_bytes()
    cases = ("structured_missing", "string_rows", "boolean_fallback")
    observations = {}
    for index, case in enumerate(cases):
        red = observe(old, f"baseline_old_{index}", case)
        green = observe(current, f"baseline_current_{index}", case)
        if red.get("kind") != "accepted" or red["result"].get("complete_output") is not True:
            raise RuntimeError(f"historical false-completion was not reproduced: {case}")
        if green.get("kind") != "rejected":
            raise RuntimeError(f"candidate did not reject malformed output: {case}")
        observations[case] = {"old": red, "current": green}
    valid = observe(current, "baseline_valid", "complete_zero")
    if valid.get("kind") != "accepted" or valid["result"].get("complete_output") is not True:
        raise RuntimeError("valid zero-row ordered output was rejected")
    if (ROOT / TARGET).read_bytes() != current:
        raise RuntimeError("candidate source changed during observation")
    report = {"schema_version": "mdd.structured-completeness-observation.v1",
              "historical_git_ref": BASE, "old_sha256": hashlib.sha256(old).hexdigest(),
              "current_sha256": hashlib.sha256(current).hexdigest(),
              "observations": observations, "complete_zero": valid,
              "scope": "synthetic driver; no structured verifier or benchmark qualification"}
    (Path(__file__).parent / "result2.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"status": "observed", "false_completions_rejected": len(cases),
                      "complete_zero": valid["kind"]}))


if __name__ == "__main__":
    main()
