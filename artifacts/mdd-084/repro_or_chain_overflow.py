#!/usr/bin/env python3
"""MDD-084 repro: OR-chain LIKE deep nesting must not overflow the process stack.

Runs the committed CLI against a matrix of deep OR-chain LIKE queries and checks
the phase expectations with explicit raises (no assert, -O safe):

  --phase pre   the unfixed evaluator/frontend MUST crash (Windows stack overflow
                exit 3221225725 / 0xC00000FD) on the deep cases;
  --phase post  no case may crash; admitted depths MUST evaluate to a complete ok
                terminal, and the over-limit case MUST be a fail-closed structured
                QUOTA_EXCEEDED rejection (never an empty success).

Usage:
  python repro_or_chain_overflow.py --binary PATH --phase pre|post --out PATH
      [--input PATH] [--dialect NAME]

The default input is the synthetic generated fixture dex committed in the repo.
"""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STACK_OVERFLOW_EXIT = 3221225725  # 0xC00000FD STATUS_STACK_OVERFLOW
DEFAULT_INPUT = ROOT / "tests/fixtures/annotations/generated/annotations-038.dex"


def chain_sql(depth: int, pattern: str) -> str:
    clause = f"descriptor LIKE '{pattern}'"
    for _ in range(depth):
        clause = f"({clause} OR descriptor LIKE 'L%')"
    return f"SELECT file_id FROM classes WHERE {clause}"


def flat_sql(terms: int) -> str:
    clause = " OR ".join(["descriptor LIKE 'L%'"] * terms)
    return f"SELECT file_id FROM classes WHERE {clause}"


def cases() -> dict:
    return {
        "paren_depth_9": chain_sql(9, "L%"),
        "paren_depth_10": chain_sql(10, "L%"),
        "paren_depth_11": chain_sql(11, "L%"),
        "paren_depth_10_prefix64": chain_sql(10, "L" + "a" * 63 + "%"),
        "flat_or_20": flat_sql(20),
        "paren_depth_60_over_limit": chain_sql(60, "L%"),
    }


def run_case(binary: str, sql: str, input_path: str, dialect: str) -> dict:
    proc = subprocess.run(
        [
            binary,
            "query",
            "--input",
            input_path,
            "--dialect",
            dialect,
            "--sql",
            sql,
            "--format",
            "jsonl",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(ROOT),
    )
    terminal = None
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("kind") == "terminal":
            terminal = record.get("terminal")
    result = {
        "exit_code": proc.returncode,
        "stack_overflow": proc.returncode == STACK_OVERFLOW_EXIT,
        "stderr_tail": proc.stderr[-200:],
        "terminal": None,
    }
    if terminal is not None:
        error = terminal.get("error")
        result["terminal"] = {
            "operation_status": terminal.get("operation_status"),
            "execution_complete": (terminal.get("execution") or {}).get("complete"),
            "emitted_rows": (terminal.get("response") or {}).get("emitted_rows"),
            "error_code": (error or {}).get("code"),
            "error_message": (error or {}).get("message"),
        }
    return result


def check_pre(name: str, result: dict) -> None:
    if name == "paren_depth_60_over_limit":
        term = result["terminal"]
        if result["stack_overflow"] or term is None:
            raise RuntimeError(f"pre/{name}: expected clean lexical rejection, got {result}")
        if term["error_code"] != "QUOTA_EXCEEDED" or term["error_message"] != "SQL_LEXICAL_DEPTH":
            raise RuntimeError(f"pre/{name}: unexpected rejection {term}")
        return
    if name == "paren_depth_9":
        if result["stack_overflow"]:
            raise RuntimeError(f"pre/{name}: depth 9 was measured safe before the fix, got {result}")
        return
    if not result["stack_overflow"]:
        raise RuntimeError(
            f"pre/{name}: the unfixed build MUST crash with exit {STACK_OVERFLOW_EXIT}, got {result}"
        )


def check_post(name: str, result: dict) -> None:
    if result["stack_overflow"]:
        raise RuntimeError(f"post/{name}: process still crashes after the fix: {result}")
    term = result["terminal"]
    if term is None:
        raise RuntimeError(f"post/{name}: no terminal record (crash or truncated stream): {result}")
    if name == "paren_depth_60_over_limit":
        if result["exit_code"] == 0 or term["operation_status"] != "error":
            raise RuntimeError(f"post/{name}: over-limit must fail closed, got {result}")
        if term["error_code"] != "QUOTA_EXCEEDED":
            raise RuntimeError(f"post/{name}: expected QUOTA_EXCEEDED, got {term}")
        if term["emitted_rows"] not in (None, "0") or term["execution_complete"] is not False:
            raise RuntimeError(f"post/{name}: rejection must not emit partial rows: {term}")
        return
    if result["exit_code"] != 0 or term["operation_status"] != "ok":
        raise RuntimeError(f"post/{name}: admitted depth must evaluate ok, got {result}")
    if term["execution_complete"] is not True:
        raise RuntimeError(f"post/{name}: execution must be complete, got {term}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--phase", required=True, choices=["pre", "post"])
    parser.add_argument("--out", required=True)
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--dialect", default="dexsql-0.1.1")
    args = parser.parse_args()

    binary = str(Path(args.binary).resolve())
    if not Path(binary).is_file():
        raise RuntimeError(f"binary not found: {binary}")
    if not Path(args.input).is_file():
        raise RuntimeError(f"input fixture not found: {args.input}")
    binary_sha256 = hashlib.sha256(Path(binary).read_bytes()).hexdigest()

    checker = check_pre if args.phase == "pre" else check_post
    results = {}
    for name, sql in cases().items():
        result = run_case(binary, sql, args.input, args.dialect)
        checker(name, result)
        results[name] = result
        print(f"{args.phase}/{name}: exit={result['exit_code']} terminal={result['terminal']}")

    def relative(path: str) -> str:
        """A path inside the repository is recorded relative to it, so the record names no machine."""
        try:
            return Path(path).resolve().relative_to(ROOT).as_posix()
        except ValueError:
            return Path(path).name

    evidence = {
        "task": "MDD-084",
        "phase": args.phase,
        "binary": relative(binary),
        "binary_sha256": binary_sha256,
        "input": relative(args.input),
        "dialect": args.dialect,
        "stack_overflow_exit_code": STACK_OVERFLOW_EXIT,
        "cases": results,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"evidence written: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())