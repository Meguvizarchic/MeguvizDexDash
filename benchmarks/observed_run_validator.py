#!/usr/bin/env python3
"""MDD-060: strict observed_run schema validator and benchmark aggregation guards.

Validates every single-run benchmark record against contracts/benchmark_result.schema.json
plus runtime invariants that JSON Schema alone cannot enforce (unsigned 64-bit bounds,
finite measurements, strict JSON object keys, non-serial overlap aggregation, prepare
scope honesty, and optional public redaction). Never relies on bare `assert`.
"""
from __future__ import annotations

import argparse
import datetime
import json
import math
import re
import statistics
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "contracts" / "benchmark_result.schema.json"
MAX_U64 = (1 << 64) - 1
MAX_JSON_SAFE_INT = 9007199254740991

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
U64_DECIMAL_RE = re.compile(r"^(0|[1-9][0-9]{0,19})$")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$"
)

VARIANTS = frozenset({"A0", "A1", "A2", "B0", "B1"})
CACHE_STATES = frozenset(
    {"cold", "warm_os", "warm_engine", "warm_persistent", "mixed", "uncontrolled"}
)
EXECUTION_STATUSES = frozenset({"completed", "failed", "cancelled", "timeout"})
COMPARISON_MODES = frozenset(
    {"ordered", "bag", "structured", "expected_failure", "not_compared"}
)
METRIC_UNITS = frozenset({"seconds", "milliseconds", "bytes", "count", "ratio"})

TOP_KEYS = frozenset(
    {
        "schema_version",
        "record_kind",
        "run_id",
        "pair_id",
        "block_id",
        "round",
        "workload_id",
        "variant",
        "timestamp_utc",
        "engine",
        "harness",
        "inputs",
        "environment",
        "execution",
        "correctness",
        "metrics",
        "artifacts",
    }
)
ENGINE_KEYS = frozenset(
    {"product", "version", "build_id", "binary_sha256", "source_commit", "profile", "sql_dialect"}
)
HARNESS_KEYS = frozenset({"revision", "manifest_sha256", "command_argv", "timing_boundary"})
INPUT_KEYS = frozenset({"occurrence_id", "sha256", "bytes"})
ENVIRONMENT_KEYS = frozenset(
    {
        "machine_id",
        "os",
        "cpu",
        "memory_bytes",
        "total_cpu_budget",
        "engine_threads",
        "concurrent_jobs",
        "cache_state",
        "cache_control",
        "background_load",
        "artifact_sha256",
    }
)
EXECUTION_KEYS = frozenset(
    {
        "status",
        "exit_code",
        "complete_output",
        "fallback_count",
        "contaminated",
        "contamination_reason",
        "wall_seconds",
    }
)
CORRECTNESS_KEYS = frozenset(
    {
        "scope_id",
        "input_complete",
        "facts_complete",
        "equivalent",
        "comparison_mode",
        "canonical_sha256",
        "certificate_sha256",
        "mismatch_count",
        "notes",
    }
)
METRIC_KEYS = frozenset({"value", "unit", "scope", "method", "unavailable_reason"})
METRIC_REQUIRED_KEYS = frozenset({"value", "unit", "scope", "method"})
ARTIFACT_KEYS = frozenset({"path", "sha256", "kind"})

FORBIDDEN_PUBLIC_RE = re.compile(
    r"(?:[A-Za-z]:[/\\]|/home/runner|handoff-archive|Bilibili|tv\.danmaku|bilibili_innocent|哔哩|Moss|bapis|kntr)",
    re.IGNORECASE,
)


class ObservedRunError(ValueError):
    """Raised when an observed_run record or aggregation violates the contract."""


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ObservedRunError(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def _reject_constant(value: str) -> None:
    raise ObservedRunError(f"non-finite JSON constant: {value}")


def parse_strict_json(payload: str) -> Any:
    try:
        return json.loads(payload, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise ObservedRunError(f"malformed JSON: {exc}") from exc


def load_schema(schema_path: Path = SCHEMA_PATH) -> dict[str, Any]:
    schema = parse_strict_json(schema_path.read_text(encoding="utf-8"))
    if not isinstance(schema, dict) or schema.get("x-contract-status") != "implemented":
        raise ObservedRunError("benchmark_result.schema.json must mark x-contract-status='implemented'")
    return schema


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ObservedRunError(msg)


def _is_nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and len(value) >= 1


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX64_RE.fullmatch(value))


def _check_u64_str(value: Any, label: str) -> int:
    _require(
        isinstance(value, str) and bool(U64_DECIMAL_RE.fullmatch(value)),
        f"{label} must be canonical u64 decimal string",
    )
    parsed = int(value)
    _require(0 <= parsed <= MAX_U64, f"{label} exceeds u64 max ({MAX_U64})")
    return parsed


def _check_exact_keys(obj: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    _require(isinstance(obj, dict), f"{label} must be a JSON object")
    missing = sorted(expected - set(obj))
    extra = sorted(set(obj) - expected)
    _require(not missing, f"{label} missing required keys: {missing}")
    _require(not extra, f"{label} has unexpected keys: {extra}")
    return obj


def _check_rfc3339(value: Any, label: str) -> None:
    _require(isinstance(value, str) and bool(RFC3339_RE.fullmatch(value)), f"{label} must be RFC 3339 date-time")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ObservedRunError(f"{label} invalid timestamp: {exc}") from exc
    _require(parsed.tzinfo is not None, f"{label} missing timezone offset")


def _check_number(value: Any, label: str, *, positive_only: bool = False) -> float:
    _require(
        isinstance(value, (int, float)) and type(value) is not bool,
        f"{label} must be a real number",
    )
    fval = float(value)
    _require(math.isfinite(fval), f"{label} must be finite")
    if positive_only:
        _require(fval > 0.0, f"{label} must be > 0")
    else:
        _require(fval >= 0.0, f"{label} must be >= 0")
    return fval


def validate_public_redaction(record: dict[str, Any]) -> None:
    """Reject local paths or restricted workspace/app names in public benchmark records."""
    serialized = json.dumps(record, ensure_ascii=False, allow_nan=False)
    hit = FORBIDDEN_PUBLIC_RE.search(serialized)
    if hit:
        raise ObservedRunError(f"record contains non-public path or restricted token: {hit.group(0)!r}")


def _validate_with_jsonschema(record: dict[str, Any], schema: dict[str, Any]) -> None:
    try:
        import jsonschema  # type: ignore
    except ImportError:
        return
    checker = jsonschema.FormatChecker()

    @checker.checks("date-time")
    def _is_datetime(instance: object) -> bool:
        if not isinstance(instance, str) or not RFC3339_RE.fullmatch(instance):
            return False
        norm = instance[:-1] + "+00:00" if instance.endswith("Z") else instance
        try:
            return datetime.datetime.fromisoformat(norm).tzinfo is not None
        except ValueError:
            return False

    validator = jsonschema.Draft202012Validator(schema, format_checker=checker)
    errors = sorted(validator.iter_errors(record), key=lambda err: list(err.path))
    if errors:
        first = errors[0]
        path = ".".join(str(p) for p in first.path) or "<root>"
        raise ObservedRunError(f"jsonschema violation at {path}: {first.message}")


def validate_observed_run(
    record: Any,
    *,
    schema: dict[str, Any] | None = None,
    check_redaction: bool = False,
) -> dict[str, Any]:
    """Validate one observed_run record strictly. Returns the validated dict or raises ObservedRunError."""
    loaded_schema = schema if schema is not None else load_schema()
    _check_exact_keys(record, TOP_KEYS, "observed_run")
    _validate_with_jsonschema(record, loaded_schema)

    _require(record["schema_version"] == "mdd.benchmark-run.v1", "schema_version must be mdd.benchmark-run.v1")
    _require(record["record_kind"] == "observed_run", "record_kind must be observed_run")
    _require(_is_nonempty_str(record["run_id"]), "run_id must be non-empty")
    _require(record["pair_id"] is None or _is_nonempty_str(record["pair_id"]), "pair_id must be null or non-empty")
    _require(_is_nonempty_str(record["block_id"]), "block_id must be non-empty")
    _require(type(record["round"]) is int and record["round"] >= 1, "round must be integer >= 1")
    _require(_is_nonempty_str(record["workload_id"]), "workload_id must be non-empty")
    _require(record["variant"] in VARIANTS, f"invalid variant: {record['variant']!r}")
    _check_rfc3339(record["timestamp_utc"], "timestamp_utc")

    engine = _check_exact_keys(record["engine"], ENGINE_KEYS, "engine")
    for key in ("product", "version", "build_id", "profile"):
        _require(_is_nonempty_str(engine[key]), f"engine.{key} must be non-empty")
    _require(_is_hex64(engine["binary_sha256"]), "engine.binary_sha256 must be hex64")
    for key in ("source_commit", "sql_dialect"):
        _require(engine[key] is None or _is_nonempty_str(engine[key]), f"engine.{key} must be null or non-empty")

    harness = _check_exact_keys(record["harness"], HARNESS_KEYS, "harness")
    _require(_is_nonempty_str(harness["revision"]), "harness.revision must be non-empty")
    _require(_is_hex64(harness["manifest_sha256"]), "harness.manifest_sha256 must be hex64")
    _require(
        isinstance(harness["command_argv"], list)
        and len(harness["command_argv"]) >= 1
        and all(isinstance(arg, str) for arg in harness["command_argv"]),
        "harness.command_argv must be non-empty list[str]",
    )
    _require(_is_nonempty_str(harness["timing_boundary"]), "harness.timing_boundary must be non-empty")

    inputs = record["inputs"]
    _require(isinstance(inputs, list) and len(inputs) >= 1, "inputs must be non-empty array")
    for idx, item in enumerate(inputs):
        inp = _check_exact_keys(item, INPUT_KEYS, f"inputs[{idx}]")
        _require(_is_nonempty_str(inp["occurrence_id"]), f"inputs[{idx}].occurrence_id must be non-empty")
        _require(_is_hex64(inp["sha256"]), f"inputs[{idx}].sha256 must be hex64")
        _check_u64_str(inp["bytes"], f"inputs[{idx}].bytes")

    env = _check_exact_keys(record["environment"], ENVIRONMENT_KEYS, "environment")
    for key in ("machine_id", "os", "cpu", "cache_control", "background_load"):
        _require(_is_nonempty_str(env[key]), f"environment.{key} must be non-empty")
    _check_u64_str(env["memory_bytes"], "environment.memory_bytes")
    _check_number(env["total_cpu_budget"], "environment.total_cpu_budget", positive_only=True)
    _require(type(env["engine_threads"]) is int and env["engine_threads"] >= 1, "environment.engine_threads must be >= 1")
    _require(type(env["concurrent_jobs"]) is int and env["concurrent_jobs"] >= 1, "environment.concurrent_jobs must be >= 1")
    _require(env["cache_state"] in CACHE_STATES, f"invalid environment.cache_state: {env['cache_state']!r}")
    _require(_is_hex64(env["artifact_sha256"]), "environment.artifact_sha256 must be hex64")

    exe = _check_exact_keys(record["execution"], EXECUTION_KEYS, "execution")
    _require(exe["status"] in EXECUTION_STATUSES, f"invalid execution.status: {exe['status']!r}")
    _require(exe["exit_code"] is None or type(exe["exit_code"]) is int, "execution.exit_code must be int|null")
    _require(type(exe["complete_output"]) is bool, "execution.complete_output must be bool")
    _require(type(exe["fallback_count"]) is int and exe["fallback_count"] >= 0, "execution.fallback_count must be >= 0")
    _require(type(exe["contaminated"]) is bool, "execution.contaminated must be bool")
    _require(
        exe["contamination_reason"] is None or _is_nonempty_str(exe["contamination_reason"]),
        "execution.contamination_reason must be null or non-empty",
    )
    if exe["contaminated"]:
        _require(
            _is_nonempty_str(exe["contamination_reason"]),
            "contaminated run must provide non-empty execution.contamination_reason",
        )
    _check_number(exe["wall_seconds"], "execution.wall_seconds")

    corr = _check_exact_keys(record["correctness"], CORRECTNESS_KEYS, "correctness")
    _require(_is_nonempty_str(corr["scope_id"]), "correctness.scope_id must be non-empty")
    _require(type(corr["input_complete"]) is bool, "correctness.input_complete must be bool")
    _require(type(corr["facts_complete"]) is bool, "correctness.facts_complete must be bool")
    _require(corr["equivalent"] is None or type(corr["equivalent"]) is bool, "correctness.equivalent must be bool|null")
    _require(corr["comparison_mode"] in COMPARISON_MODES, "invalid correctness.comparison_mode")
    _require(corr["canonical_sha256"] is None or _is_hex64(corr["canonical_sha256"]), "invalid canonical_sha256")
    _require(corr["certificate_sha256"] is None or _is_hex64(corr["certificate_sha256"]), "invalid certificate_sha256")
    _require(
        corr["mismatch_count"] is None or (type(corr["mismatch_count"]) is int and corr["mismatch_count"] >= 0),
        "invalid correctness.mismatch_count",
    )
    _require(
        isinstance(corr["notes"], list) and all(_is_nonempty_str(n) for n in corr["notes"]),
        "correctness.notes must be list[non-empty str]",
    )
    if corr["equivalent"] is True:
        _require(_is_hex64(corr["certificate_sha256"]), "equivalent=true requires certificate_sha256")
        _require(corr["mismatch_count"] == 0, "equivalent=true requires mismatch_count=0")

    metrics = record["metrics"]
    _require(isinstance(metrics, dict) and len(metrics) >= 1, "metrics must be non-empty object")
    for metric_name, raw_metric in metrics.items():
        _require(_is_nonempty_str(metric_name) and isinstance(raw_metric, dict), f"invalid metric entry {metric_name!r}")
        extra_m = set(raw_metric) - METRIC_KEYS
        missing_m = METRIC_REQUIRED_KEYS - set(raw_metric)
        _require(not missing_m and not extra_m, f"metrics.{metric_name} invalid keys: missing={missing_m}, extra={extra_m}")
        _require(raw_metric["unit"] in METRIC_UNITS, f"metrics.{metric_name}.unit invalid")
        _require(_is_nonempty_str(raw_metric["scope"]), f"metrics.{metric_name}.scope must be non-empty")
        _require(_is_nonempty_str(raw_metric["method"]), f"metrics.{metric_name}.method must be non-empty")
        unavail = raw_metric.get("unavailable_reason")
        _require(unavail is None or _is_nonempty_str(unavail), f"metrics.{metric_name}.unavailable_reason invalid")
        val = raw_metric["value"]
        if val is None:
            _require(_is_nonempty_str(unavail), f"metrics.{metric_name} with null value requires unavailable_reason")
        elif raw_metric["unit"] in ("bytes", "count"):
            _require(
                type(val) is int and 0 <= val <= MAX_JSON_SAFE_INT,
                f"metrics.{metric_name} with unit {raw_metric['unit']} must be int 0..{MAX_JSON_SAFE_INT}",
            )
        else:
            _check_number(val, f"metrics.{metric_name}.value")

        # MDD-060 aggregation honesty guard: prepare timing cannot claim pure parser cost
        if "prepare" in metric_name.lower():
            lower_scope = raw_metric["scope"].lower()
            _require(
                not re.search(r"(?:^|[^a-z])(pure[_ ]parser|parser[_ ]only|all[_ ]parsing|full[_ ]parser)", lower_scope),
                f"metrics.{metric_name}.scope falsely claims prepare is pure_parser",
            )
            _require(
                "explicit" in lower_scope or "open" in lower_scope or "session" in lower_scope,
                f"metrics.{metric_name}.scope must explicitly state explicit open/session boundary",
            )

    artifacts = record["artifacts"]
    _require(isinstance(artifacts, list) and len(artifacts) >= 1, "artifacts must be non-empty array")
    for idx, art in enumerate(artifacts):
        obj = _check_exact_keys(art, ARTIFACT_KEYS, f"artifacts[{idx}]")
        _require(_is_nonempty_str(obj["path"]), f"artifacts[{idx}].path must be non-empty")
        _require(_is_hex64(obj["sha256"]), f"artifacts[{idx}].sha256 must be hex64")
        _require(_is_nonempty_str(obj["kind"]), f"artifacts[{idx}].kind must be non-empty")

    if check_redaction:
        validate_public_redaction(record)
    return record


def load_observed_runs(path: Path, *, check_redaction: bool = False) -> list[dict[str, Any]]:
    schema = load_schema()
    text = path.read_text(encoding="utf-8")
    records: list[dict[str, Any]] = []
    if path.suffix == ".jsonl":
        for line_no, raw_line in enumerate(text.splitlines(), 1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                obj = parse_strict_json(stripped)
                validate_observed_run(obj, schema=schema, check_redaction=check_redaction)
            except ObservedRunError as exc:
                raise ObservedRunError(f"{path}:{line_no}: {exc}") from exc
            records.append(obj)
    else:
        payload = parse_strict_json(text)
        items = payload if isinstance(payload, list) else [payload]
        for idx, obj in enumerate(items):
            try:
                validate_observed_run(obj, schema=schema, check_redaction=check_redaction)
            except ObservedRunError as exc:
                raise ObservedRunError(f"{path}[{idx}]: {exc}") from exc
            records.append(obj)
    _require(len(records) >= 1, f"{path}: contains no observed_run records")
    return records


# ---- MDD-060 / MDD-005 Anti-fabrication Aggregation Guards ---------------------------------------------

def _is_qualified_record(rec: dict[str, Any]) -> bool:
    exe = rec["execution"]
    corr = rec["correctness"]
    return (
        exe["status"] == "completed"
        and exe["complete_output"] is True
        and exe["fallback_count"] == 0
        and exe["contaminated"] is False
        and corr["input_complete"] is True
        and corr["facts_complete"] is True
        and corr["equivalent"] is True
        and corr["mismatch_count"] == 0
    )


def aggregate_paired_metrics(
    records: Sequence[dict[str, Any]],
    *,
    workload_id: str,
    left_variant: str,
    right_variant: str,
    block_id: str | None = None,
) -> dict[str, Any]:
    """Compute strict per-pair speedup & reduction without mixing medians across rounds.

    Never computes paired speedup as median(left) / median(right); unpaired medians are
    reported separately and explicitly labelled as such. Contaminated, failed, timed-out,
    or non-equivalent runs are accounted separately and never silently discarded.
    """
    filtered = [
        rec for rec in records
        if rec["workload_id"] == workload_id
        and rec["variant"] in (left_variant, right_variant)
        and (block_id is None or rec["block_id"] == block_id)
    ]
    by_pair: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    unpaired_or_invalid: list[dict[str, Any]] = []
    for rec in filtered:
        pair_id = rec.get("pair_id")
        if not pair_id:
            unpaired_or_invalid.append({"run_id": rec["run_id"], "reason": "missing_pair_id"})
            continue
        key = (rec["block_id"], pair_id)
        slot = by_pair.setdefault(key, {})
        if rec["variant"] in slot:
            raise ObservedRunError(
                f"duplicate variant {rec['variant']} in pair {key} for {workload_id}"
            )
        slot[rec["variant"]] = rec

    valid_pairs: list[dict[str, Any]] = []
    excluded_pairs: list[dict[str, Any]] = []
    for (blk, pid), sides in sorted(by_pair.items()):
        if left_variant not in sides or right_variant not in sides:
            excluded_pairs.append({"block_id": blk, "pair_id": pid, "reason": "incomplete_pair"})
            continue
        left, right = sides[left_variant], sides[right_variant]
        if [i["sha256"] for i in left["inputs"]] != [i["sha256"] for i in right["inputs"]]:
            raise ObservedRunError(f"pair ({blk}, {pid}) mixes different input sha256 digests")
        if left["environment"]["cache_state"] != right["environment"]["cache_state"]:
            raise ObservedRunError(f"pair ({blk}, {pid}) mixes cache states")
        if not (_is_qualified_record(left) and _is_qualified_record(right)):
            excluded_pairs.append(
                {
                    "block_id": blk,
                    "pair_id": pid,
                    "reason": "failed_or_contaminated_or_nonequivalent",
                    "left_status": left["execution"]["status"],
                    "right_status": right["execution"]["status"],
                    "left_contaminated": left["execution"]["contaminated"],
                    "right_contaminated": right["execution"]["contaminated"],
                    "left_equivalent": left["correctness"]["equivalent"],
                    "right_equivalent": right["correctness"]["equivalent"],
                }
            )
            continue
        lw = float(left["execution"]["wall_seconds"])
        rw = float(right["execution"]["wall_seconds"])
        if lw <= 0.0 or rw <= 0.0:
            raise ObservedRunError(f"pair ({blk}, {pid}) has non-positive wall_seconds")
        valid_pairs.append(
            {
                "block_id": blk,
                "pair_id": pid,
                "left_run_id": left["run_id"],
                "right_run_id": right["run_id"],
                "left_wall_seconds": round(lw, 6),
                "right_wall_seconds": round(rw, 6),
                "pair_speedup": round(lw / rw, 6),
                "pair_reduction_fraction": round(1.0 - (rw / lw), 6),
            }
        )

    _require(len(valid_pairs) >= 1, f"no valid qualified pairs found for {workload_id}: {left_variant} vs {right_variant}")
    left_walls = [p["left_wall_seconds"] for p in valid_pairs]
    right_walls = [p["right_wall_seconds"] for p in valid_pairs]
    speedups = [p["pair_speedup"] for p in valid_pairs]
    reductions = [p["pair_reduction_fraction"] for p in valid_pairs]
    med_left = statistics.median(left_walls)
    med_right = statistics.median(right_walls)
    return {
        "workload_id": workload_id,
        "block_filter": block_id,
        "left_variant": left_variant,
        "right_variant": right_variant,
        "qualified_pair_count": len(valid_pairs),
        "excluded_pair_count": len(excluded_pairs),
        "excluded_pairs": excluded_pairs,
        "unpaired_runs": unpaired_or_invalid,
        "paired_median_speedup": round(statistics.median(speedups), 6),
        "paired_median_reduction_fraction": round(statistics.median(reductions), 6),
        "paired_reduction_min": round(min(reductions), 6),
        "paired_reduction_max": round(max(reductions), 6),
        "left_median_wall_seconds": round(med_left, 6),
        "right_median_wall_seconds": round(med_right, 6),
        "left_iqr_seconds": round(_iqr(left_walls), 6),
        "right_iqr_seconds": round(_iqr(right_walls), 6),
        "unpaired_median_ratio_for_reference_only": round(med_left / med_right, 6),
        "pairs": valid_pairs,
    }


def _iqr(values: Sequence[float]) -> float:
    ordered = sorted(values)
    n = len(ordered)
    if n < 2:
        return 0.0
    mid = n // 2
    low = ordered[:mid]
    high = ordered[mid + (n % 2):]
    return statistics.median(high) - statistics.median(low)


def check_prepare_not_pure_parser(record: dict[str, Any], *, max_explicit_prepare_seconds: float | None = None) -> None:
    """Enforce that prepare timing is never presented as full/pure parser cost or hiding lazy construction."""
    metrics = record.get("metrics", {})
    for name, item in metrics.items():
        if "prepare" not in name.lower():
            continue
        scope = item["scope"].lower()
        method = item["method"].lower()
        if "pure_parser" in scope or "all_parsing" in scope or "pure parser" in method:
            raise ObservedRunError(f"metric {name} illegally labels explicit prepare as pure parser cost")
        if max_explicit_prepare_seconds is not None and item["value"] is not None:
            if float(item["value"]) > max_explicit_prepare_seconds:
                raise ObservedRunError(f"metric {name} exceeds expected explicit prepare bound")
    notes = " ".join(record["correctness"].get("notes", [])).lower()
    if "lazy_folded_into_prepare" in notes:
        raise ObservedRunError("lazy fact construction must never be folded silently into explicit prepare")


def compose_non_additive_overlap(
    *,
    joint_wall_seconds: float,
    producer_cpu_or_component_seconds: float,
    consumer_cpu_or_component_seconds: float,
    claimed_total_seconds: float | None = None,
) -> dict[str, Any]:
    """Verify overlapping producer/consumer spans are never summed serially to replace joint wall clock."""
    _check_number(joint_wall_seconds, "joint_wall_seconds", positive_only=True)
    _check_number(producer_cpu_or_component_seconds, "producer_component_seconds")
    _check_number(consumer_cpu_or_component_seconds, "consumer_component_seconds")
    serial_sum = producer_cpu_or_component_seconds + consumer_cpu_or_component_seconds
    if claimed_total_seconds is not None:
        _check_number(claimed_total_seconds, "claimed_total_seconds", positive_only=True)
        if abs(claimed_total_seconds - serial_sum) <= 1e-6 and abs(claimed_total_seconds - joint_wall_seconds) > 1e-6:
            raise ObservedRunError(
                "overlapping producer and consumer durations must not be summed serially as joint wall_seconds"
            )
    overlap = max(0.0, serial_sum - joint_wall_seconds)
    return {
        "joint_wall_seconds": round(joint_wall_seconds, 6),
        "producer_component_seconds": round(producer_cpu_or_component_seconds, 6),
        "consumer_component_seconds": round(consumer_cpu_or_component_seconds, 6),
        "serial_sum_not_used_as_e2e": round(serial_sum, 6),
        "observed_overlap_seconds": round(overlap, 6),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help=".json or .jsonl files containing observed_run records")
    parser.add_argument("--redact", action="store_true", help="enforce public redaction rules (no local paths or private package literals)")
    args = parser.parse_args(argv)
    total = 0
    try:
        for item in args.inputs:
            recs = load_observed_runs(item.resolve(), check_redaction=args.redact)
            total += len(recs)
    except ObservedRunError as exc:
        print(f"VALIDATION FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"Validated {total} observed_run record(s) against {SCHEMA_PATH.relative_to(ROOT).as_posix()} (status=implemented).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
