#!/usr/bin/env python3
"""Bounded paired runner. Drivers must emit mdd.benchmark-output.v1 JSON.

This harness is not a DexSQL adapter. Missing drivers/inputs are preflight
blockers, never measurements. Native Windows supervision is not implemented;
running an engine on Windows fails closed before process creation.
"""
from __future__ import annotations

import argparse
import base64
import binascii
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


def valid_issue(issue):
    if not isinstance(issue, dict) or set(issue) - {
            'layer', 'reason', 'blocking', 'entity_id', 'member_id', 'range', 'details'}:
        return False
    if (not isinstance(issue.get('layer'), str) or not issue['layer']
            or not isinstance(issue.get('reason'), str) or not issue['reason']
            or type(issue.get('blocking')) is not bool):
        return False
    for key in ('entity_id', 'member_id'):
        value = issue.get(key)
        if value is not None and (not isinstance(value, str) or not value):
            return False
    if issue.get('range') is not None and not isinstance(issue['range'], dict):
        return False
    if 'details' in issue and not isinstance(issue['details'], dict):
        return False
    return True


def require_object_keys(value, required, label):
    if not isinstance(value, dict) or set(value) != set(required):
        raise ValueError('invalid ' + label + ' fields')


def verify_native_typed_rows(rows, schema, *, expected_snapshot_id, expected_occurrences,
                             max_rows, max_cells, max_variable_bytes):
    """Validate the native QueryIR row wire against a caller-trusted scope.

    This checks the current typed JSON representation, not SQL legacy DTOs.
    The caller must independently bind the supplied schema and occurrence
    roster to its captured scope. A successful result does not prove input
    coverage, computation, page consumption, or audit qualification. Limits
    count rows, cells and logical variable-width bytes, not allocations/RSS.
    """
    types = {'bool', 'i64', 'u64', 'utf16', 'bytes', 'entity'}
    kinds = {'string', 'type', 'prototype', 'class_definition', 'field_reference',
             'field_definition', 'method_reference', 'method_definition'}
    if (type(expected_snapshot_id) is not str or not expected_snapshot_id
            or type(expected_occurrences) is not tuple
            or any(type(item) is not str or not item for item in expected_occurrences)
            or len(set(expected_occurrences)) != len(expected_occurrences)
            or any(type(value) is not int or value < 0 or value > MAX_U64
                   for value in (max_rows, max_cells, max_variable_bytes))):
        raise ValueError('invalid trusted native row scope or limits')
    try:
        canonical(expected_snapshot_id)
        canonical(list(expected_occurrences))
    except UnicodeError as error:
        raise ValueError('native scope contains invalid Unicode') from error
    if type(schema) is not list or len(schema) > 256:
        raise ValueError('invalid native schema')
    seen = set()
    for column in schema:
        if (type(column) is not dict or set(column) != {'id', 'display_name', 'data_type', 'nullable'}
                or type(column['id']) is not str or not column['id'] or column['id'] in seen
                or type(column['display_name']) is not str
                or type(column['data_type']) is not str or column['data_type'] not in types
                or type(column['nullable']) is not bool):
            raise ValueError('invalid native column')
        seen.add(column['id'])
    try:
        canonical(schema)
    except UnicodeError as error:
        raise ValueError('native schema contains invalid Unicode') from error
    if type(rows) is not list or len(rows) > max_rows or len(rows) * len(schema) > max_cells:
        raise ValueError('native row/cell budget exceeded or rows invalid')
    occurrences = set(expected_occurrences)
    variable_bytes = 0

    def charge(amount):
        nonlocal variable_bytes
        variable_bytes += amount
        if variable_bytes > max_variable_bytes:
            raise ValueError('native variable-byte budget exceeded')

    def decimal_i64(value):
        if type(value) is not str or len(value) > 20 or not value:
            raise ValueError('invalid native i64')
        try:
            number = int(value)
        except ValueError as error:
            raise ValueError('invalid native i64') from error
        if str(number) != value or not -(1 << 63) <= number < (1 << 63):
            raise ValueError('noncanonical or overflowing native i64')

    for row in rows:
        if type(row) is not list or len(row) != len(schema):
            raise ValueError('native row width differs')
        for cell, column in zip(row, schema):
            if type(cell) is not dict or type(cell.get('type')) is not str:
                raise ValueError('invalid native value')
            kind = cell['type']
            if kind == 'null':
                if set(cell) != {'type'} or not column['nullable']:
                    raise ValueError('invalid native null')
                continue
            if set(cell) != {'type', 'value'} or kind != column['data_type']:
                raise ValueError('native value type differs from column')
            value = cell['value']
            if kind == 'bool':
                if type(value) is not bool:
                    raise ValueError('invalid native bool')
            elif kind == 'i64':
                decimal_i64(value)
            elif kind == 'u64':
                if type(value) is not str or len(value) > 20:
                    raise ValueError('invalid native u64')
                decimal(value)
            elif kind == 'utf16':
                if type(value) is not list:
                    raise ValueError('invalid native UTF-16')
                charge(len(value) * 2)
                if any(type(unit) is not int or not 0 <= unit <= 0xffff for unit in value):
                    raise ValueError('invalid native UTF-16 unit')
            elif kind == 'bytes':
                if type(value) is not str or len(value) % 4:
                    raise ValueError('invalid native base64')
                if value.endswith('==='):
                    raise ValueError('invalid native base64 padding')
                padding = 2 if value.endswith('==') else 1 if value.endswith('=') else 0
                charge(len(value) // 4 * 3 - padding)
                try:
                    decoded = base64.b64decode(value, validate=True)
                except (ValueError, binascii.Error) as error:
                    raise ValueError('invalid native base64') from error
                if base64.b64encode(decoded).decode('ascii') != value:
                    raise ValueError('noncanonical native base64')
            else:
                if (type(value) is not dict or set(value) != {'snapshot_id', 'dex_occurrence_id', 'kind', 'local_index'}
                        or type(value['snapshot_id']) is not str or value['snapshot_id'] != expected_snapshot_id
                        or type(value['dex_occurrence_id']) is not str or value['dex_occurrence_id'] not in occurrences
                        or type(value['kind']) is not str or value['kind'] not in kinds
                        or type(value['local_index']) is not int or not 0 <= value['local_index'] <= 0xffffffff):
                    raise ValueError('invalid or foreign native entity')
                charge(len(value['snapshot_id'].encode('utf-8', 'strict'))
                       + len(value['dex_occurrence_id'].encode('utf-8', 'strict')))
    return {'validated_rows': len(rows), 'validated_cells': len(rows) * len(schema),
            'logical_variable_bytes': variable_bytes, 'qualification': False}


def consume(output, expected_inputs, expected_request, required_layers, *, expected_identity,
            native_contract=None):
    """Check materialization against caller-trusted input and result identities.

    The caller must obtain expected_identity independently of the result under
    test. This comparison does not authenticate that identity, the selected
    scope, upstream pages, or the reported completeness of the input and facts.
    """
    if output["schema_version"] != "mdd.benchmark-output.v1":
        raise ValueError("driver output schema mismatch")
    if (canonical(output["input_manifest"]) != canonical(expected_inputs)
            or not isinstance(expected_request, str) or not expected_request
            or not isinstance(output["request_key"], str)
            or output["request_key"] != expected_request):
        raise ValueError("driver input/request binding mismatch")
    if type(output["fallback_count"]) is not int or output["fallback_count"] != 0:
        raise ValueError("fallback cannot qualify a replacement")
    result = output["result"]
    require_object_keys(result, ('schema_version', 'request_id', 'operation', 'profile',
        'sql_dialect', 'session_id', 'snapshot_id', 'catalog_epoch', 'query_id',
        'operation_status', 'coverage', 'execution', 'response', 'data', 'error', 'warnings'),
        'result')
    require_object_keys(result['coverage'], ('scope_id', 'input', 'facts', 'required_layers', 'issues'), 'coverage')
    require_object_keys(result['execution'], ('complete',), 'execution')
    require_object_keys(result['response'], ('schema_id', 'emitted_rows', 'total_rows',
        'total_rows_exact', 'more_available', 'truncated', 'next_cursor'), 'response')
    for name in ('sql_dialect', 'session_id', 'snapshot_id', 'query_id'):
        value = result[name]
        if value is not None and (not isinstance(value, str) or not value):
            raise ValueError('invalid optional result identity: ' + name)
    if result['data'] is not None and not isinstance(result['data'], dict):
        raise ValueError('invalid result data')
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
    issues = coverage["issues"]
    if (not isinstance(issues, list) or any(
            not valid_issue(issue) or issue["blocking"] is not False for issue in issues)):
        raise ValueError("blocking or unclassified coverage issue")
    warnings = result["warnings"]
    if (not isinstance(warnings, list) or any(
            not valid_issue(issue) or issue["blocking"] for issue in warnings)):
        raise ValueError("invalid or blocking result warning")
    response = result["response"]
    if not isinstance(response.get("schema_id"), str) or not response["schema_id"]:
        raise ValueError("missing response schema")
    identity_fields = ('request_id', 'operation', 'profile', 'sql_dialect', 'session_id',
                       'snapshot_id', 'catalog_epoch', 'query_id', 'scope_id', 'schema_id')
    require_object_keys(expected_identity, identity_fields, 'expected result identity')
    actual_identity = {name: result[name] for name in identity_fields[:-2]}
    actual_identity['scope_id'] = coverage['scope_id']
    actual_identity['schema_id'] = response['schema_id']
    for name in identity_fields:
        actual, expected = actual_identity[name], expected_identity[name]
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError('result identity differs: ' + name)
    if response["truncated"] is not False or response["more_available"] is not False or response["next_cursor"] is not None:
        raise ValueError("output is truncated or pages remain")
    if response["total_rows_exact"] is not True:
        raise ValueError("inexact row count")
    if decimal(response["emitted_rows"]) != decimal(response["total_rows"]):
        raise ValueError("emitted/total row mismatch")
    # Non-query operations can precede catalog creation; queries must bind
    # an actual catalog generation. Never accept a noncanonical non-null value.
    if result['operation'] == 'query' or result['catalog_epoch'] is not None:
        decimal(result['catalog_epoch'])
    mode = output["comparison_mode"]
    if mode not in ("ordered", "bag", "structured"):
        raise ValueError("unqualified comparison mode")
    if mode == "structured":
        # An arbitrary nested DTO does not expose how many result rows or pages
        # were actually consumed. A workload-specific verifier is required
        # before it can be admitted as a complete benchmark output.
        raise ValueError("structured output completeness verifier is not implemented")
    data = output["final_dto"]
    native_validation = None
    if mode in ("ordered", "bag"):
        schema = output["row_schema"]
        if (not isinstance(schema, list) or (native_contract is not None and len(schema) > 256) or any(
                not isinstance(column, dict) or type(column.get("ordinal")) is not int
                or column["ordinal"] != index or not isinstance(column.get("type"), str)
                or not column["type"] for index, column in enumerate(schema))):
            raise ValueError("invalid ordered row schema")
        if not isinstance(data, dict) or not isinstance(data.get("rows"), list):
            raise ValueError("materialized rows must be a list")
        rows = data["rows"]
        if len(rows) != int(response["total_rows"]):
            raise ValueError("not all rows materialized")
        if native_contract is not None:
            keys = {'schema', 'occurrences', 'max_rows', 'max_cells', 'max_variable_bytes'}
            if type(native_contract) is not dict or set(native_contract) != keys:
                raise ValueError('invalid native row contract')
            native_schema = native_contract['schema']
            native_validation = verify_native_typed_rows(
                rows, native_schema, expected_snapshot_id=expected_identity['snapshot_id'],
                expected_occurrences=native_contract['occurrences'],
                max_rows=native_contract['max_rows'], max_cells=native_contract['max_cells'],
                max_variable_bytes=native_contract['max_variable_bytes'])
            expected_schema = [{'ordinal': index, 'id': column['id'],
                                'display_name': column['display_name'], 'type': column['data_type'],
                                'nullable': column['nullable']} for index, column in enumerate(native_schema)]
            if canonical(schema) != canonical(expected_schema):
                raise ValueError('native row schema differs from trusted contract')
        elif any(not isinstance(row, list) or len(row) != len(schema) for row in rows):
            raise ValueError("row shape differs from declared schema")
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
    receipt = {"canonical_sha256": hashlib.sha256(payload).hexdigest(),
               "canonical_bytes": len(payload), "complete_output": True,
               "comparison_mode": mode}
    if native_validation is not None:
        receipt['native_typed_validation'] = native_validation
    return receipt


def compare_complete_rows(left, right, expected_inputs, expected_request, required_layers, *,
                          left_identity, right_identity, source_column_ids=(), native_contract=None):
    """Diagnose complete materialized row differences under the existing codec.

    Each side must first satisfy ``consume`` against independently supplied
    identities. This does not authenticate those expectations, validate cell
    types against the declared schema, establish real page consumption, or
    grant audit/performance qualification. Bag locations refer to canonical
    sorted positions, not the producer's original row number. Optional source
    columns are caller-selected row values, not authenticated provenance. An
    optional native contract validates typed cells using caller-trusted schema
    and occurrence rosters; it is not an authentication or audit certificate.
    """
    left_native = right_native = None
    if native_contract is not None:
        keys = {'schema', 'left_occurrences', 'right_occurrences',
                'max_rows', 'max_cells', 'max_variable_bytes'}
        if type(native_contract) is not dict or set(native_contract) != keys:
            raise ValueError('invalid native comparison contract')
        shared = {key: native_contract[key] for key in ('schema', 'max_rows', 'max_cells', 'max_variable_bytes')}
        left_native = dict(shared, occurrences=native_contract['left_occurrences'])
        right_native = dict(shared, occurrences=native_contract['right_occurrences'])
    left_certificate = consume(left, expected_inputs, expected_request, required_layers,
                               expected_identity=left_identity, native_contract=left_native)
    right_certificate = consume(right, expected_inputs, expected_request, required_layers,
                                expected_identity=right_identity, native_contract=right_native)
    common = {"comparison_codec": "mdd-canonical-json-v1-required-layers-set-v1",
              "left_sha256": left_certificate["canonical_sha256"],
              "right_sha256": right_certificate["canonical_sha256"],
              "comparison_left_sha256": left_certificate["canonical_sha256"],
              "comparison_right_sha256": right_certificate["canonical_sha256"],
              "qualification": False}
    if native_contract is not None:
        common['native_typed_validation'] = {
            'left': left_certificate['native_typed_validation'],
            'right': right_certificate['native_typed_validation']}
    # The v1 receipt preserves array order. Comparison treats required layers
    # as a set, matching the uniqueness and set-equality admission checks.
    # Normalize each side even when another difference returns early, so the
    # comparison digest always matches its declared codec.
    def normalized_hash(output, certificate, identity):
        coverage = output["result"]["coverage"]
        ordered = sorted(coverage["required_layers"])
        if coverage["required_layers"] == ordered:
            return certificate["canonical_sha256"]
        normalized_coverage = dict(coverage, required_layers=ordered)
        normalized_result = dict(output["result"], coverage=normalized_coverage)
        normalized_output = dict(output, result=normalized_result)
        return consume(normalized_output, expected_inputs, expected_request, required_layers,
                       expected_identity=identity)["canonical_sha256"]

    common["comparison_left_sha256"] = normalized_hash(left, left_certificate, left_identity)
    common["comparison_right_sha256"] = normalized_hash(right, right_certificate, right_identity)
    if left["result"]["operation"] != right["result"]["operation"]:
        return dict(common, equal_under_codec=False, difference={"kind": "operation"})
    if left["comparison_mode"] != right["comparison_mode"]:
        return dict(common, equal_under_codec=False, difference={"kind": "comparison_mode"})
    if canonical(left["row_schema"]) != canonical(right["row_schema"]):
        return dict(common, equal_under_codec=False, difference={"kind": "row_schema"})
    if (type(source_column_ids) is not tuple
            or any(type(item) is not str or not item for item in source_column_ids)
            or len(source_column_ids) != len(set(source_column_ids))):
        raise ValueError("invalid source column identity list")
    schema = left["row_schema"]
    positions = {}
    for index, column in enumerate(schema):
        column_id = column.get("id")
        if isinstance(column_id, str) and column_id:
            positions.setdefault(column_id, []).append(index)
    if any(len(positions.get(column_id, ())) != 1 for column_id in source_column_ids):
        raise ValueError("source column identity missing or ambiguous")

    def attach_sources(difference, left_row, right_row):
        if source_column_ids:
            for name, row in (("left_sources", left_row), ("right_sources", right_row)):
                if row is not None:
                    difference[name] = {column_id: copy.deepcopy(row[positions[column_id][0]])
                                        for column_id in source_column_ids}
        return difference

    left_rows = left["final_dto"]["rows"]
    right_rows = right["final_dto"]["rows"]
    mode = left["comparison_mode"]
    if mode == "bag":
        left_rows = sorted(left_rows, key=canonical)
        right_rows = sorted(right_rows, key=canonical)
    for row_index, (left_row, right_row) in enumerate(zip(left_rows, right_rows)):
        for column_index, (left_value, right_value) in enumerate(zip(left_row, right_row)):
            if canonical(left_value) != canonical(right_value):
                difference = {
                    "kind": "cell", "row_index": row_index, "column_index": column_index,
                    "row_order": "canonical_bag" if mode == "bag" else "delivered"}
                column_id = schema[column_index].get("id")
                if isinstance(column_id, str) and len(positions.get(column_id, ())) == 1:
                    difference["column_id"] = column_id
                return dict(common, equal_under_codec=False,
                            difference=attach_sources(difference, left_row, right_row))
    if len(left_rows) != len(right_rows):
        index = min(len(left_rows), len(right_rows))
        difference = {"kind": "row_count", "left_count": len(left_rows),
                      "right_count": len(right_rows)}
        return dict(common, equal_under_codec=False, difference=attach_sources(
            difference, left_rows[index] if index < len(left_rows) else None,
            right_rows[index] if index < len(right_rows) else None))
    if common["comparison_left_sha256"] != common["comparison_right_sha256"]:
        return dict(common, equal_under_codec=False, difference={"kind": "result_context"})
    return dict(common, equal_under_codec=True, difference=None)


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
        return consume(item, ["fixture-occurrence"], "fixture-request", ["structure"],
                       expected_identity=self.expected_identity())

    def expected_identity(self):
        # Frozen fixture expectations, not copied from the candidate response.
        return {'request_id': 'example-request-1', 'operation': 'query',
                'profile': 'mdd-native-v1', 'sql_dialect': None,
                'session_id': 'example-session', 'snapshot_id': 'example-snapshot',
                'catalog_epoch': '0', 'query_id': 'example-query',
                'scope_id': 'example-complete-scope', 'schema_id': 'example-rows-v1'}

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

    def test_input_binding_distinguishes_bool_and_integer(self):
        item = self.fixture(); item['input_manifest'] = [{'ordinal': True}]
        with self.assertRaises(ValueError):
            consume(item, [{'ordinal': 1}], 'fixture-request', ['structure'],
                    expected_identity=self.expected_identity())

    def test_result_identity_must_match_independent_expectations(self):
        for field in self.expected_identity():
            item = self.fixture()
            target = item['result']
            if field == 'scope_id': target = target['coverage']
            if field == 'schema_id': target = target['response']
            target[field] = 'different'
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.consume(item)
        item = self.fixture()
        expected = self.expected_identity()
        del expected['scope_id']
        with self.assertRaisesRegex(ValueError, 'expected result identity'):
            consume(item, ['fixture-occurrence'], 'fixture-request', ['structure'],
                    expected_identity=expected)
        expected = self.expected_identity()
        expected['unexpected'] = 'x'
        with self.assertRaisesRegex(ValueError, 'expected result identity'):
            consume(item, ['fixture-occurrence'], 'fixture-request', ['structure'],
                    expected_identity=expected)
        for field in ('session_id', 'sql_dialect'):
            item = self.fixture()
            item['result'][field] = None
            expected = self.expected_identity()
            expected[field] = None
            self.assertTrue(consume(item, ['fixture-occurrence'], 'fixture-request', ['structure'],
                                    expected_identity=expected)['complete_output'])

    def test_nullable_epoch_only_for_nonquery(self):
        item = self.fixture()
        item['result']['operation'] = 'inspect'
        item['result']['catalog_epoch'] = None
        item['result']['query_id'] = None
        expected = self.expected_identity()
        expected.update(operation='inspect', catalog_epoch=None, query_id=None)
        self.assertTrue(consume(item, ['fixture-occurrence'], 'fixture-request', ['structure'],
                                expected_identity=expected)['complete_output'])
        for value in ('01', '-1', '18446744073709551616', False):
            item['result']['catalog_epoch'] = value
            expected['catalog_epoch'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                consume(item, ['fixture-occurrence'], 'fixture-request', ['structure'],
                        expected_identity=expected)
        item = self.fixture()
        item['result']['catalog_epoch'] = None
        expected = self.expected_identity()
        expected['catalog_epoch'] = None
        with self.assertRaises(ValueError):
            consume(item, ['fixture-occurrence'], 'fixture-request', ['structure'],
                    expected_identity=expected)

    def test_coverage_issues_require_typed_reason_and_layer(self):
        for issue in ({'blocking': False}, {'blocking': False, 'layer': '', 'reason': 'x'},
                      {'blocking': False, 'layer': 'structure', 'reason': 1}):
            item = self.fixture(); item['result']['coverage']['issues'] = [issue]
            with self.subTest(issue=issue), self.assertRaises(ValueError):
                self.consume(item)
        item = self.fixture()
        item['result']['coverage']['issues'] = [
            {'blocking': False, 'layer': 'structure', 'reason': 'informational'}]
        self.assertTrue(self.consume(item)['complete_output'])

    def test_invalid_diagnostics_are_rejected(self):
        malformed = [None, {}, {'layer': 'x', 'reason': 'y', 'blocking': 0},
                     {'layer': 'x', 'reason': 'y', 'blocking': False, 'entity_id': ''},
                     {'layer': 'x', 'reason': 'y', 'blocking': False, 'details': []},
                     {'layer': 'x', 'reason': 'y', 'blocking': False, 'unexpected': 'x'}]
        for issue in malformed:
            for axis in ('warnings', 'coverage'):
                item = self.fixture()
                if axis == 'warnings': item['result']['warnings'] = [issue]
                else: item['result']['coverage']['issues'] = [issue]
                with self.subTest(axis=axis, issue=issue), self.assertRaises(ValueError):
                    self.consume(item)
        item = self.fixture()
        item['result']['warnings'] = 'not-an-array'
        with self.assertRaises(ValueError): self.consume(item)
        item = self.fixture()
        item['result']['warnings'] = [{'layer': 'structure', 'reason': 'incomplete',
                                      'blocking': True}]
        with self.assertRaises(ValueError): self.consume(item)
        item = self.fixture()
        item['result']['warnings'] = [{'layer': 'structure', 'reason': 'diagnostic',
                                      'blocking': False, 'entity_id': None, 'details': {}}]
        self.assertTrue(self.consume(item)['complete_output'])

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

    def test_result_envelope_requires_declared_shape(self):
        for name in ('session_id', 'sql_dialect', 'data'):
            item = self.fixture(); del item['result'][name]
            with self.subTest(missing=name), self.assertRaises(ValueError): self.consume(item)
        for name, value in (('session_id', ''), ('sql_dialect', 0), ('data', []),
                            ('undeclared', True)):
            item = self.fixture(); item['result'][name] = value
            with self.subTest(field=name), self.assertRaises(ValueError): self.consume(item)
        for name in ('coverage', 'execution', 'response'):
            item = self.fixture(); item['result'][name]['undeclared'] = True
            with self.subTest(nested=name), self.assertRaises(ValueError): self.consume(item)

    def test_row_count(self):
        item = self.fixture(); item["final_dto"]["rows"] = [["unreported"]]
        with self.assertRaises(ValueError): self.consume(item)
        item["result"]["response"].update(emitted_rows="2", total_rows="2")
        item["final_dto"]["rows"] = "ab"
        with self.assertRaisesRegex(ValueError, "rows must be a list"):
            self.consume(item)

    def test_rows_match_declared_shape(self):
        for schema, row in (([{'ordinal': 0, 'type': 'utf8'}], []),
                            ([{'ordinal': 0, 'type': 'utf8'}], ['a', 'b']),
                            ([{'ordinal': 0, 'type': 'utf8'}], 'a'),
                            ([{'ordinal': False, 'type': 'utf8'}], ['a']),
                            ([{'ordinal': 1, 'type': 'utf8'}], ['a']),
                            ([{'ordinal': 0, 'type': ''}], ['a'])):
            item = self.fixture()
            item['row_schema'] = schema
            item['result']['response'].update(emitted_rows='1', total_rows='1')
            item['final_dto']['rows'] = [row]
            with self.subTest(schema=schema, row=row), self.assertRaises(ValueError):
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
