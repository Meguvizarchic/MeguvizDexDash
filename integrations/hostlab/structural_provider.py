"""The structural audit (HL-10) over the MeguvizDexDash engine: one transaction, four distinguishable outcomes.
Integration layer; standard library only.

HostLab's `native_audit.run` opens a `NativeSession`, runs `Rules(session).run()` (the Graph and the 27 FEATURE
rules, business knowledge that lives in HostLab's `native_rules`, `native_graph` and the operator's catalog),
checks that all FEATUREs came out, counts the classes, checks that the APK did not change, and returns a record.
This module is that transaction with the engine's own account of what happened added, and it keeps four things
apart that a bare exception or a bare `complete: True` would blur:

* `complete`             every statement was covered completely, no layer of the dataset had an issue, all FEATUREs
                         are there and the source is the one that was named. MISSING and PARTIAL FEATURE verdicts
                         are results; they belong here.
* `audit_refused`        the audit's own conclusion that it will not judge this input (`UnsupportedAudit`: duplicate
                         class definitions, a signature it does not accept, a changed reference). The type and the
                         message are the audit's, unchanged; it is not an engine failure and never becomes one.
* `incomplete_coverage`  the engine answered, but not for everything (a statement it did not finish, facts it could
                         not build, a DEX it did not load). There is no business verdict to give and none is given.
* `failed`               anything else that went wrong: the engine said no, did not start, was lost, spoke out of
                         protocol, ran out of time. Classified by the engine's own code when it has one.

The business rules are not here. `run_structural` takes HostLab's `native_rules` module and the expected FEATURE
names as arguments (HostLab's own, or the frozen ones the tests load); nothing in this file names a class of the
audited application, and nothing filters an answer.

`NativeSession` is `native_session.NativeSession`, which honours the provider setting `native_engine`: with the
rollback value `dexsql` it hands back HostLab's own session and this module reports backend `dexsql` with no
engine identity. Results of the new engine are published only below its own namespaces (`provider.namespaces`).
"""
from __future__ import annotations

import importlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

import native_session
import provider

RESULT_SCHEMA = "mdd.hostlab-structural-result.v1"
OUTCOMES = ("complete", "incomplete_coverage", "audit_refused", "failed")


class IncompleteCoverage(RuntimeError):
    """Raised by `Outcome.raise_for_outcome` when the engine's coverage was not complete."""

    def __init__(self, message: str, reasons: "list | None" = None):
        super().__init__(message)
        self.reasons = list(reasons or [])


class SourceMismatch(RuntimeError):
    """The input is not the one that was named, or it changed during the analysis (HostLab's own refusals, same words)."""

    code = "SOURCE_CHANGED"


@dataclass
class Outcome:
    """The record, and the exception behind it when there is one (kept as it was raised)."""

    record: dict
    error: "BaseException | None" = None

    @property
    def outcome(self) -> str:
        return self.record["outcome"]

    def raise_for_outcome(self) -> dict:
        """HostLab's behaviour: the record for a complete audit; otherwise the exception it would have raised."""
        if self.outcome == "complete":
            return self.record
        if self.error is not None:
            raise self.error
        raise IncompleteCoverage("the engine's coverage was not complete", self.record["incomplete"]["reasons"])


def failure_of(error: BaseException) -> dict:
    """Code, origin, type and message of a failure. A deadline is DEADLINE_EXCEEDED (HostLab raises TimeoutError);
    everything else is classified by what the engine said, or stays UNCLASSIFIED."""
    if isinstance(error, TimeoutError):
        return {"code": "DEADLINE_EXCEEDED", "origin": "adapter", "type": type(error).__name__, "message": str(error)[:1000]}
    if isinstance(error, SourceMismatch):
        return {"code": error.code, "origin": "adapter", "type": type(error).__name__, "message": str(error)[:1000]}
    if isinstance(error, provider.ProviderError) and not isinstance(error, provider.ProviderUnavailable):
        # a refused configuration or a namespace collision: the adapter's own refusal, with the code provider.py gives it
        return {"code": error.code, "origin": "adapter", "type": type(error).__name__, "message": str(error)[:1000]}
    return provider.classify_failure(error)._asdict()


def _jsonable(discoveries: dict) -> dict:
    return {name: [list(item) for item in found] for name, found in discoveries.items()}


def run_structural(apk, *, sha256: str, rules_module: Any = None, expected_features: "Iterable[str] | None" = None,
                   timeout: float = 900, threads: int = 2, provider_config: Any = None, structural: Any = None,
                   state: Any = None, session_factory: "Callable[[Path], Any] | None" = None, runner: Any = None,
                   environ: "dict | None" = None, digest: Callable[[Path], str] = provider.file_sha256) -> Outcome:
    """Run the structural audit over `apk` and say what happened, in one of the four outcomes.

    `rules_module` is HostLab's `native_rules` (it supplies `Rules`, `CATALOG` and `UnsupportedAudit`);
    `expected_features` is HostLab's `EXPECTED_FEATURES`; both default to HostLab's own modules. `session_factory`
    replaces `native_session.NativeSession` (used by the tests to put a stand-in under the rules)."""
    rules_module = rules_module or importlib.import_module("native_rules")
    expected = set(expected_features if expected_features is not None
                   else importlib.import_module("analysis.run_intake").EXPECTED_FEATURES)
    refused = getattr(rules_module, "UnsupportedAudit", None) or importlib.import_module("native_graph").UnsupportedAudit
    started = time.monotonic()
    apk = Path(apk).resolve(strict=True)
    record: dict = {"schema": RESULT_SCHEMA, "outcome": "failed", "complete": False, "source_sha_reverified": False,
                    "apk_sha256": sha256, "features": {}, "discoveries": {}, "class_count": None,
                    "backend": None, "wire": None, "engine": None, "native": None,
                    "reference_sha256": (getattr(rules_module, "CATALOG", None) or {}).get("reference_sha256"),
                    "phases": {}, "queries": 0, "elapsed_ms": 0.0, "coverage": None, "dataset": None,
                    "audit_refusal": None, "failure": None, "incomplete": None}
    session: Any = None
    error: "BaseException | None" = None
    try:
        if digest(apk) != sha256:
            raise SourceMismatch("native audit input does not match its immutable APK identity")
        if session_factory is None:
            def session_factory(path):  # noqa: E306 - the default factory
                return native_session.NativeSession(path, timeout=timeout, threads=threads, provider_config=provider_config,
                                                    structural=structural, state=state, runner=runner, environ=environ)
        session = session_factory(apk)
        with session:  # `session` outlives the block: its coverage and identity belong in every record
            record["phases"]["prepare_ms"] = (time.monotonic() - started) * 1000
            began = time.monotonic()
            features, discoveries = rules_module.Rules(session).run()
            if set(features) != expected:
                raise RuntimeError("native audit did not produce the complete FEATURE set")
            record["phases"]["structural_ms"] = (time.monotonic() - began) * 1000
            record["features"], record["discoveries"] = features, _jsonable(discoveries)
            record["class_count"] = int(session.all("SELECT COUNT(*) AS n FROM classes ORDER BY n")[0]["n"])
        if digest(apk) != sha256:
            raise SourceMismatch("native audit APK changed during analysis")
        record["source_sha_reverified"] = True
        reasons = coverage_reasons(session)
        if reasons:
            record["incomplete"] = {"reasons": reasons, "layer_issues": _layer_issues(session)}
            record["outcome"] = "incomplete_coverage"
        else:
            record["outcome"], record["complete"] = "complete", True
    except refused as exc:
        record["outcome"], error = "audit_refused", exc
        record["audit_refusal"] = {"type": type(exc).__name__, "message": str(exc)}
        record["features"], record["discoveries"], record["class_count"] = {}, {}, None
    except native_session.EngineIncomplete as exc:
        record["outcome"], error = "incomplete_coverage", exc
        record["incomplete"] = {"reasons": ["statement_incomplete"], "layer_issues": _layer_issues(session),
                                "engine_error": failure_of(exc)}
        record["features"], record["discoveries"], record["class_count"] = {}, {}, None
    except provider.InventoryError as exc:
        record["outcome"], error = "incomplete_coverage", exc
        record["incomplete"] = {"reasons": ["dex_inventory_incomplete"], "inventory": exc.detail,
                                "layer_issues": _layer_issues(session)}
        record["features"], record["discoveries"], record["class_count"] = {}, {}, None
    except Exception as exc:  # noqa: BLE001 - classified, never swallowed: the record keeps the failure and `error` the exception
        record["outcome"], error = "failed", exc
        record["failure"] = failure_of(exc)
        record["features"], record["discoveries"], record["class_count"] = {}, {}, None
    _identify(record, session)
    record["elapsed_ms"] = (time.monotonic() - started) * 1000
    return Outcome(record, error)


def run(apk, **kwargs) -> dict:
    """`native_audit.run` for callers that expect HostLab's behaviour: the record, or the exception."""
    return run_structural(apk, **kwargs).raise_for_outcome()


def coverage_reasons(session: Any) -> list:
    """Why the engine's coverage of a finished session is not complete; empty if it is."""
    coverage = getattr(session, "coverage", None)
    if coverage is None:  # HostLab's own session reports none: the audit stays what it always was
        return []
    reasons = []
    if not coverage["statements"]:
        reasons.append("no_statement_was_covered")
    for name in ("input", "facts"):
        if coverage[name] != "complete":
            reasons.append(f"{name}_{coverage[name]}")
    if coverage.get("abandoned"):
        # a statement was sent but its result was walked away from: sent != covered is never complete
        reasons.append("statement_abandoned")
    if getattr(session, "layer_issues", None):
        reasons.append("dataset_layer_issues")
    return reasons


def _layer_issues(session: Any) -> list:
    return [native_session.issue_summary(i) for i in getattr(session, "layer_issues", [])] if session is not None else []


def _identify(record: dict, session: Any) -> None:
    """Who answered: the engine's identity, the wire, the dataset and the coverage the engine reported. A session
    that is HostLab's own (the rollback path) is DexSQL and has no engine identity."""
    if session is None:  # it was never created (the engine could not be started): nothing answered
        return
    record["queries"] = getattr(session, "queries", record["queries"])
    wire = getattr(session, "wire", None)
    if wire is None:
        record["backend"] = "dexsql"
        return
    identity = session.identity()
    record["backend"], record["wire"] = provider.ENGINE, wire
    record["engine"] = record["native"] = identity["engine"]
    record["dataset"], record["coverage"] = identity["dataset"], identity["coverage"]


# ---- publishing: only below the engine's own namespaces ---------------------------------------------------------------

def publish_result(record: dict, namespaces: "dict[str, Path]") -> Path:
    """Write the record below the engine's `reports` namespace, never replacing a file. HostLab's own report and
    cache directories are not touched (provider.namespaces refuses any overlap with them)."""
    if record.get("backend") != provider.ENGINE:
        raise provider.ProviderError("only results of " + provider.ENGINE + " are published in its namespace")
    name = f"structural/{record['apk_sha256'][:16]}-{record['wire']}-{record['outcome']}.json"
    return provider.publish(namespaces["reports"], name, record)
