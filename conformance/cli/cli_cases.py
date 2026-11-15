#!/usr/bin/env python3
"""Check the frozen CLI contract against the real binary.

Usage: python -I conformance/cli/cli_cases.py [--binary PATH] [--cases FILE]

Every case in command-and-output-cases.json is run as a process. A case passes only
if the exit code, the shape of stdout and the shape of stderr are all as frozen, and
if the stream invariants hold: batches of one statement are numbered from 0 with
`first_row` accumulating, every statement ends in exactly one terminal, and the
terminal's `emitted_rows` equals the rows actually delivered.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASES = "conformance/cli/command-and-output-cases.json"
DEFAULT_BINARY = ROOT / "target" / "debug" / ("meguvizdexdash.exe" if os.name == "nt" else "meguvizdexdash")


def load_cases(path: Path | None = None) -> dict:
    return json.loads((path or ROOT / CASES).read_text(encoding="utf-8"))


def expand(argument: str, inputs: dict) -> str:
    for name, relative in inputs.items():
        argument = argument.replace("{" + name + "}", str(ROOT / relative))
    return argument


def run_process(binary: Path, args: list[str], stdin: str | None) -> tuple[int, bytes, bytes]:
    done = subprocess.run([str(binary), *args], input=(stdin or "").encode("utf-8"),
                          capture_output=True, timeout=300, check=False, cwd=ROOT)
    return done.returncode, done.stdout, done.stderr


def stream_problems(lines: list[dict]) -> list[str]:
    """Invariants of the stream, whatever the case expects."""
    problems = []
    if not lines or lines[0].get("kind") != "opened":
        return ["the stream does not start with `opened`"]
    if lines[0].get("protocol") != "mdd.cli-stream.v1":
        problems.append("the stream protocol is not mdd.cli-stream.v1")
    open_ids: dict = {}
    delivered: dict = {}
    for line in lines[1:]:
        kind, rid = line.get("kind"), line.get("id")
        if kind == "batch":
            batch = line["batch"]
            state = open_ids.setdefault(rid, {"next_sequence": 0, "next_row": 0})
            if batch["schema"] != "mdd.sdk-batch.v1":
                problems.append(f"{rid}: unknown batch schema")
            if batch["sequence"] != str(state["next_sequence"]):
                problems.append(f"{rid}: batch sequence {batch['sequence']} where {state['next_sequence']} was due")
            if batch["first_row"] != str(state["next_row"]):
                problems.append(f"{rid}: first_row {batch['first_row']} where {state['next_row']} was due")
            if batch["row_count"] != len(batch["rows"]) or batch["row_count"] < 1:
                problems.append(f"{rid}: row_count disagrees with the rows")
            state["next_sequence"] += 1
            state["next_row"] += batch["row_count"]
            delivered[rid] = state["next_row"]
        elif kind == "terminal":
            if rid in delivered and delivered[rid] != int(line["terminal"]["response"]["emitted_rows"]):
                problems.append(f"{rid}: emitted_rows differs from the rows delivered")
            if rid not in delivered and line["terminal"]["response"]["emitted_rows"] != "0":
                problems.append(f"{rid}: emitted_rows without any batch")
            if line.get("done"):
                problems.append(f"{rid}: two terminals")
            line["done"] = True
            open_ids.pop(rid, None)
            delivered.pop(rid, None)
        elif kind not in ("rejected",):
            problems.append(f"unknown line kind {kind!r}")
    if open_ids:
        problems.append("a statement has batches but no terminal: " + ", ".join(map(str, open_ids)))
    return problems


def check_terminal(where: str, terminal: dict, want: dict) -> list[str]:
    problems = []
    got = {
        "operation_status": terminal["operation_status"],
        "error_code": (terminal["error"] or {}).get("code"),
        "truncated": terminal["response"]["truncated"],
        "emitted_rows": terminal["response"]["emitted_rows"],
        "complete": terminal["execution"]["complete"],
        "columns": (terminal.get("data") or {}).get("columns"),
    }
    for key, expected in want.items():
        if got.get(key) != expected:
            problems.append(f"{where}: terminal {key} is {got.get(key)!r}, frozen as {expected!r}")
    return problems


def check_jsonl(lines: list[dict], want: dict) -> list[str]:
    problems = stream_problems(lines)
    kinds = [line["kind"] for line in lines]
    terminals = [line for line in lines if line["kind"] == "terminal"]
    if "kinds" in want and kinds != want["kinds"]:
        problems.append(f"line kinds are {kinds}, frozen as {want['kinds']}")
    if "first_kinds" in want and kinds[: len(want["first_kinds"])] != want["first_kinds"]:
        problems.append(f"first line kinds are {kinds[: len(want['first_kinds'])]}, frozen as {want['first_kinds']}")
    if "last_kind" in want and kinds[-1] != want["last_kind"]:
        problems.append(f"last line kind is {kinds[-1]}, frozen as {want['last_kind']}")
    if "terminal" in want:
        if len(terminals) != 1:
            problems.append(f"expected one terminal, found {len(terminals)}")
        else:
            problems += check_terminal("terminal", terminals[0]["terminal"], want["terminal"])
    if "terminal_ids" in want and [t["id"] for t in terminals] != want["terminal_ids"]:
        problems.append(f"terminal ids are {[t['id'] for t in terminals]}, frozen as {want['terminal_ids']}")
    if "terminal_each" in want:
        for t in terminals:
            problems += check_terminal(str(t["id"]), t["terminal"], want["terminal_each"])
    if "terminal_statuses" in want:
        statuses = [t["terminal"]["operation_status"] for t in terminals]
        if statuses != want["terminal_statuses"]:
            problems.append(f"terminal statuses are {statuses}, frozen as {want['terminal_statuses']}")
    if "rejected" in want:
        count = sum(1 for line in lines if line["kind"] == "rejected")
        if count != want["rejected"]:
            problems.append(f"{count} rejected lines, frozen as {want['rejected']}")
        for line in lines:
            if line["kind"] == "rejected" and line["error"]["code"] != "INVALID_ARGUMENT":
                problems.append("a rejected line without INVALID_ARGUMENT")
    return problems


def check_case(binary: Path, case: dict, inputs: dict, schema_check=None) -> list[str]:
    args = [expand(a, inputs) for a in case["args"]]
    code, out, err = run_process(binary, args, case.get("stdin"))
    problems = []
    if code != case["exit"]:
        problems.append(f"exit code {code}, frozen as {case['exit']}")
    want = case["stdout"]
    if want == "empty":
        if out:
            problems.append("stdout is not empty")
    elif "jsonl" in want:
        try:
            lines = [json.loads(line) for line in out.decode("utf-8").splitlines()]
        except (ValueError, UnicodeDecodeError) as error:
            lines = None
            problems.append(f"stdout is not JSON lines: {error}")
        if lines is not None:
            problems += check_jsonl(lines, want["jsonl"])
    elif "json" in want:
        try:
            value = json.loads(out)
        except ValueError as error:
            value = None
            problems.append(f"stdout is not one JSON value: {error}")
        if isinstance(value, dict):
            problems += [f"stdout JSON lacks `{key}`" for key in want["json"] if key not in value]
            if "schema" in want and schema_check is not None:
                problems += schema_check(value, want["schema"])
    elif "text_contains" in want:
        text = out.decode("utf-8", "replace")
        problems += [f"stdout lacks {piece!r}" for piece in want["text_contains"] if piece not in text]
    expected_err = case["stderr"]
    if expected_err == "empty":
        if err:
            problems.append("stderr is not empty: " + err.decode("utf-8", "replace")[:120])
    elif "json_error" in expected_err:
        try:
            error = json.loads(err)
            if error.get("code") != expected_err["json_error"]:
                problems.append(f"stderr error code {error.get('code')}, frozen as {expected_err['json_error']}")
        except ValueError:
            problems.append("stderr is not one JSON error object")
    elif "contains" in expected_err and expected_err["contains"] not in err.decode("utf-8", "replace"):
        problems.append(f"stderr lacks {expected_err['contains']!r}")
    return problems


def schema_check(value: dict, relative: str) -> list[str]:
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        return ["jsonschema is not installed, so the schema was not checked"]
    schema = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    return [f"schema: {error.message}" for error in Draft202012Validator(schema).iter_errors(value)]


def run_all(binary: Path, document: dict) -> dict:
    results = {}
    for case in document["cases"]:
        results[case["name"]] = check_case(binary, case, document["inputs"], schema_check)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--cases", type=Path)
    args = parser.parse_args()
    document = load_cases(args.cases)
    results = run_all(args.binary, document)
    failed = {name: problems for name, problems in results.items() if problems}
    for name, problems in failed.items():
        print("FAIL", name)
        for problem in problems:
            print("   ", problem)
    print(f"{len(results) - len(failed)}/{len(results)} cases hold")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
