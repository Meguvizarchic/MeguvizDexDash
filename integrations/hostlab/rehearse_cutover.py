#!/usr/bin/env python3
"""MDD-055: End-to-end HostLab cutover and explicit rollback rehearsal against a real engine binary."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import hostlab_test_support as support  # noqa: E402
import install_meguvizdexdash as installer  # noqa: E402
import native_session as ns  # noqa: E402
import provider  # noqa: E402

SCHEMA = "mdd.hostlab-cutover-rehearsal.v1"
EXAMPLE_CONFIG = HERE / "enablement-config.example.json"
DEFAULT_FIXTURE = ROOT / "tests/fixtures/generated/multidex-stored.apk"
DEFAULT_OUTPUT = ROOT / "artifacts/mdd-055/cutover-rehearsal.json"


class RehearsalError(RuntimeError):
    """Raised when a cutover, report provenance, or rollback invariant fails."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RehearsalError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def resolve_binary(explicit: "Path | None" = None) -> Path:
    if explicit is not None:
        return Path(explicit).expanduser().resolve(strict=True)
    for env_key in ("HOSTLAB_MEGUVIZDEXDASH", "MDD_WORKER_BINARY"):
        val = os.environ.get(env_key)
        if val:
            return Path(val).expanduser().resolve(strict=True)
    suffix = ".exe" if os.name == "nt" else ""
    for profile in ("release", "debug"):
        candidate = ROOT / "target" / profile / f"meguvizdexdash{suffix}"
        if candidate.is_file():
            return candidate.resolve()
    raise FileNotFoundError("no built meguvizdexdash binary found under target/{release,debug}")


def _seed_legacy_state(state: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for name in provider.LEGACY_NAMES:
        folder = state / name
        folder.mkdir(parents=True, exist_ok=True)
        marker = folder / "legacy-marker.json"
        marker.write_text(json.dumps({"owner": "legacy-hostlab", "dir": name}, sort_keys=True) + "\n", encoding="utf-8")
        snapshot[f"{name}/legacy-marker.json"] = sha256_file(marker)
    return snapshot


def _snapshot_legacy_state(state: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in provider.LEGACY_NAMES:
        folder = state / name
        if not folder.exists():
            continue
        for item in sorted(folder.rglob("*")):
            if item.is_file():
                rel = item.relative_to(state).as_posix()
                out[rel] = sha256_file(item)
    return out


def _backend_map(planned: dict[str, Any]) -> dict[str, str]:
    return {task["id"]: task["backend"] for task in planned["tasks"]}


def rehearse(binary: "Path | None" = None, fixture: Path = DEFAULT_FIXTURE) -> dict[str, Any]:
    binary_path = resolve_binary(binary)
    fixture_path = Path(fixture).resolve(strict=True)
    fixture_sha = sha256_file(fixture_path)
    fixture_stat = fixture_path.stat()
    initial_stat = (fixture_stat.st_size, fixture_stat.st_mtime_ns)
    legacy = support.load_frozen("analysis_plan")
    example = json.loads(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
    require(example.get("default_production_cutover") is False, "enablement example must not enable production by default")

    request = support.request(support.QUERY, support.LOCATE, support.DECODE, support.INFO, support.REFS, support.REFS_SITES,
                              backend="auto")

    with tempfile.TemporaryDirectory(prefix="mdd055-rehearsal-") as tmp_dir:
        tmp = Path(tmp_dir)
        state = tmp / "state"
        state.mkdir(parents=True)
        legacy_before = _seed_legacy_state(state)

        pin_manifest = tmp / "vendor" / "meguvizdexdash" / "manifest.json"
        pinned = installer.pin(binary_path, pin_manifest)
        status = installer.status(binary_path, pin_manifest, deep=True)
        require(status.get("available") is True, f"pinned engine status not available: {status}")

        # Stage 1: Baseline default (`dexsql`, empty environment)
        baseline_cfg = provider.load_config(environ={})
        require(baseline_cfg.native_engine == "dexsql", "default config must route auto to dexsql")
        baseline_plan = provider.plan(request, baseline_cfg, legacy=legacy)
        baseline_backends = _backend_map(baseline_plan)
        require(baseline_backends["q"] == "dexsql" and baseline_backends["rs"] == "sqlite",
                f"unexpected baseline plan backends: {baseline_backends}")
        disabled_rejected = False
        try:
            provider.plan(support.request(support.QUERY, backend=provider.ENGINE), baseline_cfg, legacy=legacy)
        except provider.ProviderDisabled:
            disabled_rejected = True
        require(disabled_rejected, "forced meguvizdexdash request must fail when native_engine=dexsql")

        # Stage 2: Explicit opt-in cutover to `meguvizdexdash`
        provider_doc = json.loads(json.dumps(example["provider_config"]))
        provider_doc["meguvizdexdash"]["manifest"] = str(pin_manifest)
        structural_doc = json.loads(json.dumps(example["structural_config"]))
        provider_path = tmp / "provider-config.json"
        structural_path = tmp / "structural-config.json"
        provider_path.write_text(json.dumps(provider_doc, indent=2) + "\n", encoding="utf-8")
        structural_path.write_text(json.dumps(structural_doc, indent=2) + "\n", encoding="utf-8")

        cutover_env = dict(os.environ)
        cutover_env.update({
            "HOSTLAB_MEGUVIZDEXDASH": str(binary_path),
            "HOSTLAB_PROVIDER_CONFIG": str(provider_path),
            "HOSTLAB_STRUCTURAL_CONFIG": str(structural_path),
        })
        cutover_cfg = provider.load_config(environ=cutover_env)
        cutover_settings = ns.load_structural_config(environ=cutover_env)
        require(cutover_cfg.native_engine == provider.ENGINE, "cutover config did not enable meguvizdexdash")
        require(cutover_settings.non_scalar_text == "lossy-replacement", "unexpected structural non_scalar_text")

        cutover_plan = provider.plan(request, cutover_cfg, legacy=legacy, engine_status=status)
        cutover_backends = _backend_map(cutover_plan)
        require(
            cutover_backends == {"q": "meguvizdexdash", "l": "meguvizdexdash", "d": "meguvizdexdash",
                                 "i": "meguvizdexdash", "r": "meguvizdexdash", "rs": "sqlite"},
            f"unexpected cutover routing: {cutover_backends}",
        )
        require(cutover_plan["provider"]["fallbacks"] == [], "planned cutover must not record fallbacks")
        source_meta = {"sha256": fixture_sha}
        run_id = provider.run_identity(cutover_plan, cutover_cfg, source=source_meta)

        session_summary: dict[str, Any] = {}
        prior_env_binary = os.environ.get(installer.ENV_BINARY)
        os.environ[installer.ENV_BINARY] = str(binary_path)
        try:
            session_ctx = ns.NativeSession(fixture_path, timeout=60, threads=1, state=state, environ=cutover_env)
            with session_ctx as session:
                dex_rows = session.all("SELECT file_id, entry_name, dex_version FROM dex_files ORDER BY file_id")
                string_rows = session.all("SELECT string_pool_id, string_idx, value FROM strings ORDER BY string_pool_id, string_idx")
                class_rows = session.all("SELECT file_id, class_idx, descriptor FROM classes ORDER BY file_id, class_idx")
                method_rows = session.all("SELECT file_id, method_idx, name FROM methods ORDER BY file_id, method_idx")
                terminal_payload = None
                for kind, payload in session.transport.statement(
                    "SELECT file_id, class_idx FROM classes ORDER BY file_id, class_idx"
                ):
                    if kind == "terminal":
                        terminal_payload = payload
                require(terminal_payload is not None, "missing terminal payload")
                require(terminal_payload["operation_status"] == "ok", f"terminal not ok: {terminal_payload}")
                require(terminal_payload["execution"]["complete"] is True, "terminal execution.complete must be true")
                require(terminal_payload["response"]["truncated"] is False, "terminal must not be truncated")
                require(terminal_payload["response"]["more_available"] is False, "terminal must not have remaining pages")
                require(terminal_payload["response"].get("next_cursor") is None, "terminal must not return next_cursor")
                cov = session.coverage
                comp = provider.completeness(
                    terminal_payload["operation_status"], cov["input"], cov["facts"], terminal_payload["execution"]["complete"]
                )
                require(comp["complete"] is True and cov["abandoned"] == 0, f"session coverage incomplete: {cov}")
                session_summary = {
                    "wire": session.wire,
                    "dex_count": len(dex_rows),
                    "strings_count": len(string_rows),
                    "classes_count": len(class_rows),
                    "methods_count": len(method_rows),
                    "statements": cov["statements"],
                    "abandoned": cov["abandoned"],
                    "coverage_input": cov["input"],
                    "coverage_facts": cov["facts"],
                    "operation_status": terminal_payload["operation_status"],
                    "execution_complete": terminal_payload["execution"]["complete"],
                    "truncated": terminal_payload["response"]["truncated"],
                    "more_available": terminal_payload["response"]["more_available"],
                    "next_cursor": terminal_payload["response"].get("next_cursor"),
                    "completeness_verdict": comp,
                }
        finally:
            if prior_env_binary is None:
                os.environ.pop(installer.ENV_BINARY, None)
            else:
                os.environ[installer.ENV_BINARY] = prior_env_binary

        report: dict[str, Any] = {
            "sample": {"sha256": fixture_sha},
            "plan": cutover_plan,
            "tasks": [{"id": t["id"], "backend": t["backend"]} for t in cutover_plan["tasks"]],
            "complete": True,
            "backend_fallback_reason": None,
        }
        eng_ns = provider.namespaces(state, cutover_plan["provider"]["engine"], cutover_cfg)
        provider.annotate_report(report, cutover_plan, run_id, eng_ns)
        provider.seal_report(report, fixture_path, initial_stat, source_meta)
        provider.check_report(report)
        require(report["complete"] is True and report["source_unchanged"] is True, "sealed report incomplete")

        eng_dir = provider.engine_dir(cutover_plan["provider"]["engine"])
        namespace_markers_present = all((state / provider.MDD_ROOT / kind / eng_dir / "NAMESPACE.json").is_file()
                                        for kind in ("cache", "reports", "completion"))
        require(namespace_markers_present, "isolated mdd-engine namespace markers missing")

        legacy_after_cutover = _snapshot_legacy_state(state)
        require(legacy_after_cutover == legacy_before, "cutover wrote or altered legacy HostLab directories")

        # Verify provenance reconstruction strictly from emitted report
        reconstructed = {
            "backend": report["provider"]["engine"]["backend"],
            "engine_version": report["backend_versions"]["meguvizdexdash"]["engine_version"],
            "build_id": report["backend_versions"]["meguvizdexdash"]["build_id"],
            "binary_sha256": report["backend_versions"]["meguvizdexdash"]["binary_sha256"],
            "profile": report["backend_versions"]["meguvizdexdash"]["profile"]["name"],
            "profile_admitted": report["backend_versions"]["meguvizdexdash"]["profile"]["admitted"],
            "dialect": report["backend_versions"]["meguvizdexdash"]["dialect"]["engine"],
            "config_digest": report["backend_versions"]["meguvizdexdash"]["config_digest"],
            "run_id": report["provider"]["run"]["id"],
            "source_sha256": report["provider"]["run"]["source_sha256"],
            "fallback_count": len(report["provider"]["fallbacks"]),
        }
        require(reconstructed["backend"] == "meguvizdexdash", "report backend reconstruction failed")
        require(reconstructed["source_sha256"] == fixture_sha, "report source_sha256 reconstruction failed")
        require(reconstructed["config_digest"] == cutover_cfg.digest(), "report config_digest reconstruction failed")
        require(reconstructed["fallback_count"] == 0, "expected zero fallbacks in cutover rehearsal")

        # Stage 3: Explicit rollback to `dexsql` (config edit + unset env)
        rollback_doc = json.loads(json.dumps(example["rollback_provider_config"]))
        rollback_doc["meguvizdexdash"]["manifest"] = str(pin_manifest)
        provider_path.write_text(json.dumps(rollback_doc, indent=2) + "\n", encoding="utf-8")

        rollback_cfg = provider.load_config(environ=cutover_env)
        unset_cfg = provider.load_config(environ={})
        require(rollback_cfg.native_engine == "dexsql", "rollback config failed to switch native_engine to dexsql")
        require(unset_cfg.native_engine == "dexsql", "unset env failed to revert native_engine to dexsql")
        rollback_plan = provider.plan(request, rollback_cfg, legacy=legacy)
        require(_backend_map(rollback_plan) == baseline_backends, "rollback plan differs from baseline plan")

        resume_refused = False
        try:
            provider.resume_compatible({"provider": cutover_plan["provider"]}, {"provider": rollback_plan.get("provider")})
        except ValueError as exc:
            if str(exc) == "checkpoint_engine_identity_changed":
                resume_refused = True
        require(resume_refused, "resume_compatible must reject cross-engine checkpoint after rollback")

        stub_calls: list[Any] = []

        class LegacyStub:
            def __init__(self, apk, timeout=900, threads=2):
                stub_calls.append({"apk_name": Path(apk).name, "timeout": timeout, "threads": threads})

        rollback_session = ns.NativeSession(fixture_path, timeout=30, threads=1, original=LegacyStub, environ=cutover_env)
        require(isinstance(rollback_session, LegacyStub) and len(stub_calls) == 1,
                "rollback NativeSession must delegate directly to legacy session without starting engine")

        legacy_after_rollback = _snapshot_legacy_state(state)
        require(legacy_after_rollback == legacy_before, "rollback altered legacy HostLab directories")

        return {
            "schema": SCHEMA,
            "task": "MDD-055",
            "qualification_claim": "functional_cutover_and_rollback_rehearsal_only",
            "performance_replacement_qualified": False,
            "default_production_cutover": False,
            "fixture": {"path": fixture_path.relative_to(ROOT).as_posix() if fixture_path.is_relative_to(ROOT) else fixture_path.name,
                        "sha256": fixture_sha},
            "engine_pin": {"engine_version": pinned["engine_version"], "build_id": pinned["build_id"],
                           "binary_sha256": pinned["sha256"], "platform": pinned["platform"]},
            "stage_1_baseline": {"native_engine": baseline_cfg.native_engine, "backends": baseline_backends,
                                 "forced_mdd_rejected_when_off": disabled_rejected},
            "stage_2_cutover": {
                "native_engine": cutover_cfg.native_engine,
                "structural_wire": cutover_settings.wire,
                "non_scalar_text": cutover_settings.non_scalar_text,
                "backends": cutover_backends,
                "session": session_summary,
                "reconstructed_provenance": reconstructed,
                "namespace_markers_present": namespace_markers_present,
                "legacy_tree_file_count": len(legacy_before),
                "legacy_tree_unchanged": legacy_after_cutover == legacy_before,
            },
            "stage_3_rollback": {
                "config_rollback_native_engine": rollback_cfg.native_engine,
                "env_unset_native_engine": unset_cfg.native_engine,
                "backends": _backend_map(rollback_plan),
                "matches_baseline_plan": _backend_map(rollback_plan) == baseline_backends,
                "cross_engine_checkpoint_refused": resume_refused,
                "delegated_to_legacy_session": len(stub_calls) == 1,
                "legacy_tree_unchanged_after_rollback": legacy_after_rollback == legacy_before,
            },
        }


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--binary", type=Path, default=None)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    record = rehearse(binary=args.binary, fixture=args.fixture)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"schema": SCHEMA, "output": str(args.output),
                      "build_id": record["engine_pin"]["build_id"],
                      "legacy_unchanged": record["stage_3_rollback"]["legacy_tree_unchanged_after_rollback"]},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
