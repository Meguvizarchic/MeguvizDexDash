#!/usr/bin/env python3
"""Bounded paired runner. Drivers must emit mdd.benchmark-output.v1 JSON.

This harness is not a DexSQL adapter. Missing drivers/inputs are preflight
blockers, never measurements. Native Windows supervision is not implemented;
running an engine on Windows fails closed before process creation.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAX_U64 = (1 << 64) - 1


def pairs_unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON key: " + key)
        obj[key] = value
    return obj


def reject_constant(value):
    raise ValueError("non-finite JSON value: " + value)


def loads(payload):
    return json.loads(payload, object_pairs_hook=pairs_unique,
                      parse_constant=reject_constant)


def canonical(value):
    """Type-preserving JSON codec; no floats or lone Unicode surrogates.

    Float raw bits and non-Unicode DEX text must use explicit tagged objects.
    Object key order is nonsemantic; array order and duplicate rows are retained.
    """
    def check(item):
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, int):
            if not -(1 << 63) <= item <= MAX_U64:
                raise ValueError("integer outside supported fixed-width range")
            return
        if isinstance(item, str):
            item.encode("utf-8", errors="strict")
            return
        if isinstance(item, list):
            for child in item:
                check(child)
            return
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("non-string JSON key")
                check(key)
                check(child)
            return
        raise ValueError("unsupported value; floats require tagged raw-bit encoding")
    check(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def decimal(value):
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise ValueError("decimal-u64 string required")
    if (len(value) > 1 and value.startswith("0")) or int(value) > MAX_U64:
        raise ValueError("noncanonical or overflowing decimal-u64")
    return int(value)


def consume(output, expected_inputs, expected_request, required_layers):
    if output["schema_version"] != "mdd.benchmark-output.v1":
        raise ValueError("driver output schema mismatch")
    if output["input_manifest"] != expected_inputs or output["request_key"] != expected_request:
        raise ValueError("driver input/request binding mismatch")
    if type(output["fallback_count"]) is not int or output["fallback_count"] != 0:
        raise ValueError("fallback cannot qualify a replacement")
    result = output["result"]
    if result["schema_version"] != "mdd.result.v1" or result["operation_status"] != "ok":
        raise ValueError("request failed")
    for name in ("request_id", "operation", "profile"):
        if not isinstance(result.get(name), str) or not result[name]:
            raise ValueError("missing result identity: " + name)
    if result["operation"] == "query":
        for name in ("snapshot_id", "query_id"):
            if not isinstance(result.get(name), str) or not result[name]:
                raise ValueError("missing query identity: " + name)
    if result["error"] is not None or result["execution"]["complete"] is not True:
        raise ValueError("missing complete computation")
    coverage = result["coverage"]
    if not isinstance(coverage.get("scope_id"), str) or not coverage["scope_id"]:
        raise ValueError("missing coverage scope")
    if coverage["input"] != "complete" or coverage["facts"] != "complete":
        raise ValueError("incomplete input/facts")
    layers = coverage["required_layers"]
    if (not isinstance(layers, list) or any(not isinstance(x, str) or not x for x in layers)
            or len(layers) != len(set(layers)) or set(layers) != set(required_layers)):
        raise ValueError("required fact scope differs")
    if any(issue.get("blocking") is not False for issue in coverage["issues"]):
        raise ValueError("blocking or unclassified coverage issue")
    response = result["response"]
    if not isinstance(response.get("schema_id"), str) or not response["schema_id"]:
        raise ValueError("missing response schema")
    if response["truncated"] is not False or response["more_available"] is not False or response["next_cursor"] is not None:
        raise ValueError("output is truncated or pages remain")
    if response["total_rows_exact"] is not True:
        raise ValueError("inexact row count")
    if decimal(response["emitted_rows"]) != decimal(response["total_rows"]):
        raise ValueError("emitted/total row mismatch")
    decimal(result["catalog_epoch"])
    mode = output["comparison_mode"]
    if mode not in ("ordered", "bag", "structured"):
        raise ValueError("unqualified comparison mode")
    if mode == "structured":
        # An arbitrary nested DTO does not expose how many result rows or pages
        # were actually consumed. A workload-specific verifier is required
        # before it can be admitted as a complete benchmark output.
        raise ValueError("structured output completeness verifier is not implemented")
    data = output["final_dto"]
    if mode in ("ordered", "bag"):
        if not isinstance(data, dict) or not isinstance(data.get("rows"), list):
            raise ValueError("materialized rows must be a list")
        rows = data["rows"]
        if len(rows) != int(response["total_rows"]):
            raise ValueError("not all rows materialized")
        if mode == "bag":
            data = dict(data, rows=sorted(rows, key=canonical))
    # Identity-bearing manifests and relation/column schema remain in digest.
    # Only runtime opaque handles and measurement fields are excluded.
    semantic = {
        "codec": "mdd-canonical-json-v1",
        "input_manifest": expected_inputs,
        "request_key": expected_request,
        "required_layers": sorted(required_layers),
        "schema": output["row_schema"],
        "comparison_mode": mode,
        "final_dto": data,
        "coverage": {k: coverage[k] for k in ("input", "facts", "required_layers", "issues")},
        "response": {k: response[k] for k in ("schema_id", "total_rows", "total_rows_exact", "truncated", "more_available", "next_cursor")},
        "warnings": result["warnings"],
    }
    payload = canonical(semantic)
    return {"canonical_sha256": hashlib.sha256(payload).hexdigest(),
            "canonical_bytes": len(payload), "complete_output": True,
            "comparison_mode": mode}


def preflight(plan):
    blockers = []
    if plan.get("readiness") != "ready":
        blockers.append("plan has not been qualified ready")
    if os.name != "posix":
        blockers.append("native Windows process-tree supervisor not implemented; Linux runner required")
    if not plan.get("environment"):
        blockers.append("frozen environment manifest is missing")
    else:
        environment = plan["environment"]
        artifact = ROOT / environment["path"]
        if not artifact.is_file() or digest(artifact) != environment["sha256"]:
            blockers.append("frozen environment manifest identity mismatch")
        if environment.get("resource_budget_verified") is not True:
            blockers.append("total CPU/memory budget and exclusive measurement window not verified")
    if not plan.get("inputs"):
        blockers.append("no actual input bindings")
    for item in plan.get("inputs", []):
        path = item.get("path")
        if not path or not Path(path).is_file():
            blockers.append("input missing: " + item["occurrence_id"])
        elif digest(path) != item["sha256"] or str(Path(path).stat().st_size) != item["bytes"]:
            blockers.append("input identity mismatch: " + item["occurrence_id"])
    runnable = [v for v in plan["variants"] if v.get("included")]
    if not {"A0", "A1"}.issubset({v["id"] for v in runnable}):
        blockers.append("A0/A1 qualified drivers are not both configured")
    for variant in runnable:
        if not variant.get("conformance_certificate"):
            blockers.append(variant["id"] + " lacks compatibility certificate")
        argv = variant.get("driver_argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
            blockers.append(variant["id"] + " lacks argument-vector driver")
        for label in ("engine_binary", "driver"):
            item = variant.get(label)
            if not item or not Path(item["path"]).is_file():
                blockers.append(variant["id"] + " missing " + label)
            elif digest(item["path"]) != item["sha256"]:
                blockers.append(variant["id"] + " changed " + label)
        if argv and variant.get("driver") and Path(argv[0]).resolve() != Path(variant["driver"]["path"]).resolve():
            blockers.append(variant["id"] + " argv executable is not the pinned driver")
    return {"schema_version": "mdd.baseline-preflight.v1", "status": "blocked" if blockers else "ready",
            "platform": platform.platform(), "blockers": blockers,
            "measured_runs": 0, "engine_executed": False}


def run_process(argv, timeout, cap, directory):
    """POSIX only: retain bounded stdout/stderr, terminate the owned group."""
    if os.name != "posix":
        raise ValueError("native Windows supervisor unavailable")
    out_path, err_path = directory / "stdout.json", directory / "stderr.log"
    with out_path.open("xb") as out, err_path.open("xb") as err:
        started = time.perf_counter()
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                shell=False, start_new_session=True)
        reason = None
        try:
            while proc.poll() is None:
                if time.perf_counter() - started > timeout:
                    reason = "timeout"
                    break
                if out_path.stat().st_size + err_path.stat().st_size > cap:
                    reason = "output_budget_exceeded"
                    break
                time.sleep(0.02)
        finally:
            # Kill the owned group even if the leader exited, preventing a
            # leftover producer from modifying captured output after validation.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        elapsed = time.perf_counter() - started
    if out_path.stat().st_size + err_path.stat().st_size > cap:
        reason = "output_budget_exceeded"
    return {"exit_code": proc.returncode, "wall_seconds": elapsed, "failure": reason,
            "stdout": str(out_path), "stderr": str(err_path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "benchmarks/baseline-manifest.json")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--qualify",action="store_true",help="one root-leased private static qualification, never an implicit formal benchmark")
    parser.add_argument("--variant",choices=["A0","A1"])
    parser.add_argument("--sample")
    parser.add_argument("--lease",type=Path)
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ContractTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    plan = loads(args.manifest.read_bytes())
    if plan.get('schema_version')=='mdd.baseline-plan.v2':
        driver=ROOT/plan['driver']['path'];argv=[plan['python']['path'],str(driver),'--manifest',str(args.manifest.resolve())]
        if args.qualify:
            if not args.variant or not args.sample or args.output is None or args.lease is None:
                parser.error('qualification requires explicit variant/sample/output/root lease')
            argv+=['--launch','--variant',args.variant,'--sample',args.sample,'--output',str(args.output),'--lease',str(args.lease)]
        else:
            argv+=['--preflight']
            if args.output:argv+=['--output',str(args.output)]
        return subprocess.run(argv,cwd=ROOT,shell=False).returncode
    report = preflight(plan)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["status"] != "ready":
        return 2
    if not args.preflight:
        # Engines are intentionally never launched until a workload-specific
        # adapter, canonical expected output and exclusive measurement lease
        # are reviewed together. run_process is the bounded execution primitive.
        print("Workload adapter and exclusive measurement gate required", file=sys.stderr)
        return 2
    return 0


class ContractTests(unittest.TestCase):
    def fixture(self):
        result = loads((ROOT / "contracts/examples/result_complete.example.json").read_bytes())
        result["coverage"]["required_layers"] = ["structure"]
        return {"schema_version": "mdd.benchmark-output.v1", "input_manifest": ["fixture-occurrence"],
                "request_key": "fixture-request", "fallback_count": 0, "result": result,
                "comparison_mode": "ordered", "row_schema": [{"ordinal": 0, "type": "utf8"}],
                "final_dto": {"rows": []}}

    def consume(self, item):
        return consume(item, ["fixture-occurrence"], "fixture-request", ["structure"])

    def test_empty_complete_result(self):
        self.assertTrue(self.consume(self.fixture())["complete_output"])

    def test_reject_incomplete_axes(self):
        for path, value in ((["operation_status"], "cancelled"), (["execution", "complete"], False),
                            (["coverage", "input"], "partial"), (["coverage", "facts"], "unknown"),
                            (["response", "more_available"], True), (["response", "truncated"], True),
                            (["response", "next_cursor"], "unconsumed")):
            item = self.fixture()
            ref = item["result"]
            for key in path[:-1]:
                ref = ref[key]
            ref[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.consume(item)

    def test_no_fallback(self):
        item = self.fixture(); item["fallback_count"] = 1
        with self.assertRaises(ValueError): self.consume(item)
        item["fallback_count"] = False
        with self.assertRaises(ValueError): self.consume(item)

    def test_input_binding(self):
        item = self.fixture(); item["input_manifest"] = ["other-occurrence"]
        with self.assertRaises(ValueError): self.consume(item)

    def test_scope_binding(self):
        item = self.fixture(); item["result"]["coverage"]["required_layers"] = []
        with self.assertRaises(ValueError): self.consume(item)

    def test_required_identity_and_scope_are_not_missing(self):
        for path, value in ((['request_id'], ''), (['snapshot_id'], None),
                            (['query_id'], None), (['coverage', 'scope_id'], ''),
                            (['response', 'schema_id'], None),
                            (['coverage', 'required_layers'], ['structure', 'structure'])):
            item = self.fixture()
            ref = item['result']
            for key in path[:-1]:
                ref = ref[key]
            ref[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.consume(item)

    def test_row_count(self):
        item = self.fixture(); item["final_dto"]["rows"] = [["unreported"]]
        with self.assertRaises(ValueError): self.consume(item)
        item["result"]["response"].update(emitted_rows="2", total_rows="2")
        item["final_dto"]["rows"] = "ab"
        with self.assertRaisesRegex(ValueError, "rows must be a list"):
            self.consume(item)

    def test_structured_output_without_verifier_is_not_complete(self):
        item = self.fixture(); item["comparison_mode"] = "structured"
        item["result"]["response"].update(emitted_rows="2", total_rows="2")
        item["final_dto"] = {}
        with self.assertRaisesRegex(ValueError, "completeness verifier"):
            self.consume(item)

    def test_bag_keeps_duplicates(self):
        left = self.fixture(); left["comparison_mode"] = "bag"
        left["final_dto"]["rows"] = [["a"], ["a"], ["b"]]
        left["result"]["response"].update(emitted_rows="3", total_rows="3")
        right = copy.deepcopy(left); right["final_dto"]["rows"].reverse()
        self.assertEqual(self.consume(left), self.consume(right))
        right["final_dto"]["rows"] = [["a"], ["b"], ["b"]]
        self.assertNotEqual(self.consume(left), self.consume(right))

    def test_null_and_empty_are_distinct(self):
        self.assertEqual(len({canonical(x) for x in (None, "", "NULL", 0, "0", {"bytes": ""})}), 6)

    def test_strict_json(self):
        for value in ('{"a":1,"a":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(ValueError): loads(value)

    def test_strict_numbers_and_text(self):
        for value in (1.0, "\ud800", 1 << 65):
            with self.assertRaises((ValueError, UnicodeError)): canonical(value)
        for value in ("01", "-1", "18446744073709551616", 0):
            with self.assertRaises(ValueError): decimal(value)


if __name__ == "__main__":
    raise SystemExit(main())
