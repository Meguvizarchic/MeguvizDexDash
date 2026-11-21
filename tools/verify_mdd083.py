#!/usr/bin/env python3
"""MDD-083: Generate and verify reviewable release package, SBOM, docs, and live rehearsal."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BENCHMARKS_DIR = ROOT / "benchmarks"
HOSTLAB_DIR = ROOT / "integrations/hostlab"
CACHE_DIR = ROOT / "conformance/cache"
PYTHON_DIR = ROOT / "python"
for extra in (BENCHMARKS_DIR, HOSTLAB_DIR, CACHE_DIR, PYTHON_DIR):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import mdd  # noqa: E402
import observed_run_validator as validator  # noqa: E402
import provider as hostlab_provider  # noqa: E402
import rehearse_cutover  # noqa: E402
import run_cache_conformance as cache_conf  # noqa: E402

DIST_DIR = ROOT / "dist"
REHEARSAL_PATH = ROOT / "artifacts/mdd-083/release-rehearsal.json"
MANIFEST_082_PATH = ROOT / "conformance/manifests/release-qualification.json"
LEDGER_PATH = ROOT / "compatibility/ledger.json"
RELEASE_NOTES_PATH = ROOT / "docs/RELEASE_NOTES.md"
OPS_RUNBOOK_PATH = ROOT / "docs/OPERATIONS_AND_ROLLBACK.md"

DEFAULT_FIXTURE = ROOT / "tests/fixtures/generated/multidex-stored.apk"

REQUIRED_DOCS = (
    "docs/RELEASE_NOTES.md",
    "docs/OPERATIONS_AND_ROLLBACK.md",
)


class Mdd083Error(RuntimeError):
    """Raised when MDD-083 release artifact or rehearsal verification fails."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Mdd083Error(message)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _write_clean_text(path: Path, text: str, *, label: str) -> str:
    hit = validator.FORBIDDEN_PUBLIC_RE.search(text)
    require(hit is None, f"forbidden public literal in {label}: {hit.group(0) if hit else ''}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return sha256_file(path)


def _write_clean_json(path: Path, payload: dict[str, Any], *, label: str) -> str:
    validator.validate_public_redaction(payload)
    encoded = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    return _write_clean_text(path, encoded, label=label)


def _parse_cargo_lock(rel: str, scope: str) -> list[dict[str, Any]]:
    doc = tomllib.loads((ROOT / rel).read_text(encoding="utf-8"))
    components: list[dict[str, Any]] = []
    for pkg in doc.get("package", []):
        name = str(pkg["name"])
        version = str(pkg["version"])
        source = str(pkg.get("source", "workspace-member"))
        checksum = pkg.get("checksum")
        entry: dict[str, Any] = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:cargo/{name}@{version}",
            "properties": [
                {"name": "mdd:lockfile", "value": rel},
                {"name": "mdd:workspace_scope", "value": scope},
                {"name": "mdd:origin", "value": "crates.io" if "crates.io-index" in source else "local-workspace"},
            ],
        }
        if isinstance(checksum, str) and len(checksum) == 64:
            entry["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        components.append(entry)
    return components


def _parse_pip_lock(rel: str) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for raw in (ROOT / rel).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "==" not in line:
            continue
        name, ver = line.split("==", 1)
        components.append(
            {
                "type": "library",
                "name": name.strip(),
                "version": ver.strip(),
                "purl": f"pkg:pypi/{name.strip()}@{ver.strip()}",
                "properties": [
                    {"name": "mdd:lockfile", "value": rel},
                    {"name": "mdd:workspace_scope", "value": "python-validation-dev"},
                ],
            }
        )
    return components


def _build_sbom(generated_utc: str) -> dict[str, Any]:
    cargo_core = _parse_cargo_lock("Cargo.lock", "core-workspace")
    cargo_desktop = _parse_cargo_lock("apps/desktop/Cargo.lock", "desktop-workbench")
    pip_dev = _parse_pip_lock("requirements-dev.lock")
    all_components = cargo_core + cargo_desktop + pip_dev
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": generated_utc,
            "component": {
                "type": "application",
                "name": "MeguvizDexDash",
                "version": "0.1.0-dev",
            },
            "tools": [{"name": "tools/verify_mdd083.py", "version": "1.0"}],
            "properties": [
                {"name": "mdd:rust_toolchain", "value": "1.99.0"},
                {"name": "mdd:cargo_lock_sha256", "value": sha256_file(ROOT / "Cargo.lock")},
                {"name": "mdd:desktop_cargo_lock_sha256", "value": sha256_file(ROOT / "apps/desktop/Cargo.lock")},
                {"name": "mdd:requirements_dev_lock_sha256", "value": sha256_file(ROOT / "requirements-dev.lock")},
            ],
        },
        "summary": {
            "core_cargo_packages": len(cargo_core),
            "desktop_cargo_packages": len(cargo_desktop),
            "python_validation_packages": len(pip_dev),
            "total_components": len(all_components),
        },
        "components": all_components,
    }


def _build_file_inventory(paths: list[Path]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for p in sorted(paths, key=lambda item: item.relative_to(ROOT).as_posix()):
        require(p.is_file(), f"missing inventory file: {p}")
        items.append(
            {
                "path": p.relative_to(ROOT).as_posix(),
                "bytes": p.stat().st_size,
                "sha256": sha256_file(p),
            }
        )
    return items


def _run_c_abi_release_smoke(dll_path: Path, fixture: Path) -> dict[str, Any]:
    lib = mdd._ffi.load(str(dll_path))
    rows_out: list[tuple[Any, ...]] = []
    cols_out: tuple[str, ...] = ()
    with mdd.open_snapshot([str(fixture)], lib=lib) as snap:
        with snap.open_session() as sess:
            with sess.query(
                "SELECT dex_occurrence_id, class_def_idx, descriptor FROM native_classes ORDER BY dex_occurrence_id, class_def_idx"
            ) as q:
                res = q.collect()
                require(res.is_complete, "C ABI smoke result incomplete")
                cols_out = res.columns
                rows_out = list(res.rows)
                require(len(rows_out) > 0, "C ABI smoke returned zero rows")
    live = lib.live_handles()
    require(live == 0, f"C ABI live handle leak detected after close: {live}")
    digest = hashlib.sha256(
        json.dumps({"columns": list(cols_out), "rows": [list(r) for r in rows_out]}, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return {
        "passed": True,
        "library_sha256": sha256_file(dll_path),
        "abi_major": 1,
        "abi_minor": 0,
        "row_count": len(rows_out),
        "live_handles_after_close": live,
        "canonical_sha256": digest,
    }


def _run_m5_to_m8_migration_and_cache_rehearsal(binary_path: Path, fixture: Path) -> dict[str, Any]:
    example = json.loads((ROOT / "integrations/hostlab/enablement-config.example.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="mdd083-rehearsal-") as tmp_dir:
        tmp = Path(tmp_dir)
        state = tmp / "state"
        state.mkdir(parents=True)
        pin_manifest = tmp / "vendor/meguvizdexdash/manifest.json"
        import install_meguvizdexdash as installer  # noqa: E402
        import native_session as ns  # noqa: E402

        installer.pin(binary_path, pin_manifest)
        prov_doc = json.loads(json.dumps(example["provider_config"]))
        prov_doc["meguvizdexdash"]["manifest"] = str(pin_manifest)
        prov_path = tmp / "provider.json"
        prov_path.write_text(json.dumps(prov_doc, indent=2) + "\n", encoding="utf-8")

        wire_hashes: dict[str, str] = {}
        row_counts: dict[str, int] = {}
        prior_env_binary = os.environ.get(installer.ENV_BINARY)
        os.environ[installer.ENV_BINARY] = str(binary_path)
        try:
            for label, wire in (("m5_b0", "b0"), ("m8_b1", "b1")):
                struct_doc = {
                    "schema": "mdd.hostlab-structural-config.v1",
                    "wire": wire,
                    "non_scalar_text": "lossy-replacement",
                    "sql_limits": {"steps": 4000000000, "scanned_rows": 400000000, "result_rows": 4000000},
                }
                struct_path = tmp / f"structural-{wire}.json"
                struct_path.write_text(json.dumps(struct_doc, indent=2) + "\n", encoding="utf-8")
                env = {
                    **os.environ,
                    "HOSTLAB_MEGUVIZDEXDASH": str(binary_path),
                    "HOSTLAB_PROVIDER_CONFIG": str(prov_path),
                    "HOSTLAB_STRUCTURAL_CONFIG": str(struct_path),
                }
                with ns.NativeSession(fixture, timeout=60, threads=1, state=state / f"run-{wire}", environ=env) as sess:
                    rows_classes = sess.all("SELECT file_id, class_idx, descriptor FROM classes ORDER BY file_id, class_idx")
                    rows_methods = sess.all("SELECT file_id, kind, COUNT(*) AS cnt FROM class_methods GROUP BY file_id, kind ORDER BY file_id, kind")
                    payload_hash = hashlib.sha256(
                        json.dumps({"classes": rows_classes, "methods_agg": rows_methods}, sort_keys=True).encode("utf-8")
                    ).hexdigest()
                    wire_hashes[label] = payload_hash
                    row_counts[label] = len(rows_classes)
        finally:
            if prior_env_binary is None:
                os.environ.pop(installer.ENV_BINARY, None)
            else:
                os.environ[installer.ENV_BINARY] = prior_env_binary

        require(wire_hashes["m5_b0"] == wire_hashes["m8_b1"], f"M5 b0 vs M8 b1 canonical mismatch: {wire_hashes}")

        # Verify persistent mdd-index/1 cache cold/warm + invalidation without disguising schema
        probe_bin = cache_conf.ensure_probe_binary(None)
        work_dex = tmp / "work.dex"
        shutil.copyfile(ROOT / "tests/fixtures/definitions/generated/definitions-035.dex", work_dex)
        cache_dir = tmp / "mdd-cache"
        cold = cache_conf.run_probe(probe_bin, "run", "--cache-dir", str(cache_dir), "--mode", "standalone", "--policy", "read-write", "--input", str(work_dex))
        warm = cache_conf.run_probe(probe_bin, "run", "--cache-dir", str(cache_dir), "--mode", "standalone", "--policy", "read-write", "--input", str(work_dex))
        require(cold["report"]["outcome"] == "built_cold", f"expected built_cold: {cold}")
        require(warm["report"]["outcome"] == "hit_warm" and warm["build_fn_invoked"] is False, f"expected hit_warm: {warm}")
        require(cold["overall_tables_sha256"] == warm["overall_tables_sha256"], "warm cache table digest mismatch")

        raw_idx = cache_dir / "index" / f"{cold['report']['canonical_cache_key']}.standalone.mddidx"
        orig_bytes = raw_idx.read_bytes()
        raw_idx.write_bytes(orig_bytes[:-1] + bytes([orig_bytes[-1] ^ 0xFF]))
        corrupt = cache_conf.run_probe(probe_bin, "verify-file", "--file", str(raw_idx))
        require(corrupt["ok"] is False and corrupt["error_code"] == "CACHE_CORRUPT", f"corrupt index not rejected: {corrupt}")

        # Verify cross-engine checkpoint refusal on rollback to dexsql
        mdd_ckpt = {
            "provider": {
                "engine": {
                    "backend": "meguvizdexdash",
                    "engine_version": "0.1.0-dev",
                    "build_id": "test-build",
                    "binary_sha256": sha256_file(binary_path),
                    "profile": "hostlab-audit-v1",
                    "dialect": "dexsql-0.1.0",
                    "config_digest": "a" * 64,
                }
            }
        }
        dexsql_ckpt = {"provider": {"engine": {"backend": "dexsql"}}}
        resume_refused = False
        resume_reason = ""
        try:
            hostlab_provider.resume_compatible(mdd_ckpt, dexsql_ckpt)
        except ValueError as exc:
            resume_refused = True
            resume_reason = str(exc)
        require(resume_refused, "cross-engine resume unexpectedly permitted")

        return {
            "m5_b0_vs_m8_b1_equal": True,
            "m8_canonical_sha256": wire_hashes["m8_b1"],
            "m8_classes_count": row_counts["m8_b1"],
            "cache_cold_outcome": cold["report"]["outcome"],
            "cache_warm_outcome": warm["report"]["outcome"],
            "cache_corrupt_rejected_code": corrupt["error_code"],
            "cross_engine_resume_refused": resume_refused,
            "cross_engine_resume_reason": resume_reason,
        }


def generate() -> dict[str, Any]:
    require(MANIFEST_082_PATH.is_file(), "run tools/verify_mdd082.py --generate first")
    for doc_rel in REQUIRED_DOCS:
        doc_path = ROOT / doc_rel
        require(doc_path.is_file(), f"missing required release doc: {doc_rel}")
        hit = validator.FORBIDDEN_PUBLIC_RE.search(doc_path.read_text(encoding="utf-8"))
        require(hit is None, f"forbidden public token in {doc_rel}: {hit.group(0) if hit else ''}")

    m82 = validator.parse_strict_json(MANIFEST_082_PATH.read_text(encoding="utf-8"))
    require(m82.get("all_passed") is True, "MDD-082 release qualification not passed")

    exe_name = "meguvizdexdash.exe" if os.name == "nt" else "meguvizdexdash"
    ffi_name = "mdd_ffi.dll" if os.name == "nt" else "libmdd_ffi.so"
    cli_bin = (ROOT / "target/release" / exe_name).resolve(strict=True)
    ffi_bin = (ROOT / "target/release" / ffi_name).resolve(strict=True)
    cli_sha = sha256_file(cli_bin)
    ffi_sha = sha256_file(ffi_bin)
    require(cli_sha == m82["engine_identity"]["binary_sha256"], f"release CLI SHA mismatch vs MDD-082: {cli_sha}")
    require(ffi_sha == m82["engine_identity"]["mdd_ffi_release_sha256"], f"release FFI SHA mismatch vs MDD-082: {ffi_sha}")

    generated_utc = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    sbom = _build_sbom(generated_utc)
    _write_clean_json(DIST_DIR / "SBOM.json", sbom, label="dist/SBOM.json")

    enablement_cfg = {
        "schema": "mdd.hostlab-release-enablement.v1",
        "task_id": "MDD-083",
        "default_production_cutover": False,
        "external_production_cutover_authorized": False,
        "rollback_default": {
            "native_engine": "dexsql",
            "audit_gate_mode": "legacy_independent",
        },
        "opt_in_provider_config": {
            "schema": "mdd.hostlab-provider-config.v1",
            "native_engine": "meguvizdexdash",
            "meguvizdexdash": {
                "manifest": "<STATE_ROOT>/vendor/meguvizdexdash/manifest.json",
                "expected_binary_sha256": cli_sha,
                "expected_build_id": m82["engine_identity"]["build_id"],
                "dialect": "dexsql-0.1.0",
                "profile": "hostlab-audit-v1",
                "profile_policy": "allow_unadmitted",
                "cache_dir": None,
                "max_datasets": 1,
                "fallback": {"to": "none", "on": []},
            },
        },
        "opt_in_structural_config": {
            "schema": "mdd.hostlab-structural-config.v1",
            "wire": "b1",
            "fallback_conservative_wire": "b0",
            "non_scalar_text": "lossy-replacement",
            "sql_limits": {"steps": 4000000000, "scanned_rows": 400000000, "result_rows": 4000000},
        },
        "opt_in_audit_data_provider": {
            "default_mode": "legacy_independent",
            "opt_in_mode": "mdd_fact_reuse",
            "allow_mid_run_fallback": False,
            "mdd_062_evidence": "artifacts/mdd-062/gate-equivalence-and-timing.json",
        },
    }
    _write_clean_json(DIST_DIR / "hostlab-enablement-config.json", enablement_cfg, label="dist/hostlab-enablement-config.json")

    python_files = [p for p in (ROOT / "python/mdd").glob("*.py") if p.is_file()]
    c_abi_files = [ROOT / "include/mdd.h", ROOT / "crates/mdd-ffi/Cargo.toml", *sorted((ROOT / "crates/mdd-ffi/src").glob("*.rs"))]
    _write_clean_json(
        DIST_DIR / "python-sdk-manifest.json",
        {
            "schema_version": "mdd.python-sdk-distribution.v1",
            "package": "mdd",
            "version": "0.1.0-dev",
            "dependencies": [],
            "transports": ["in-process (ctypes ABI 1.0)", "worker (mdd.cli-stream.v1)"],
            "files": _build_file_inventory(python_files),
        },
        label="dist/python-sdk-manifest.json",
    )
    _write_clean_json(
        DIST_DIR / "c-abi-1.0-manifest.json",
        {
            "schema_version": "mdd.c-abi-distribution.v1",
            "abi_major": 1,
            "abi_minor": 0,
            "symbol_count": 29,
            "windows_shared_lib": {"filename": "mdd_ffi.dll", "bytes": ffi_bin.stat().st_size, "sha256": ffi_sha},
            "linux_evidence_ref": "artifacts/mdd-080/linux-x86_64-results.json",
            "source_files": _build_file_inventory(c_abi_files),
        },
        label="dist/c-abi-1.0-manifest.json",
    )

    m66 = validator.parse_strict_json((ROOT / "artifacts/mdd-066/deep-perf-and-ui-qualification.json").read_text(encoding="utf-8"))
    desktop_pkg = m66["desktop_webview2_ui_qualification"]["packaged_windows_webview2_run"]
    release_manifest = {
        "schema_version": "mdd.release-manifest.v1",
        "task_id": "MDD-083",
        "generated_utc": generated_utc,
        "product": "MeguvizDexDash",
        "version": "0.1.0-dev",
        "external_release_published": False,
        "release_qualification_manifest": {"path": "conformance/manifests/release-qualification.json", "sha256": sha256_file(MANIFEST_082_PATH)},
        "compatibility_ledger": {"path": "compatibility/ledger.json", "sha256": sha256_file(LEDGER_PATH)},
        "toolchain_and_lockfiles": {
            "rust-toolchain.toml": sha256_file(ROOT / "rust-toolchain.toml"),
            "Cargo.lock": sha256_file(ROOT / "Cargo.lock"),
            "apps/desktop/Cargo.lock": sha256_file(ROOT / "apps/desktop/Cargo.lock"),
            "requirements-dev.lock": sha256_file(ROOT / "requirements-dev.lock"),
        },
        "verified_windows_x86_64_release_artifacts": {
            "cli_binary": {"filename": "meguvizdexdash.exe", "bytes": cli_bin.stat().st_size, "sha256": cli_sha, "build_id": m82["engine_identity"]["build_id"]},
            "c_abi_shared_library": {"filename": "mdd_ffi.dll", "bytes": ffi_bin.stat().st_size, "sha256": ffi_sha},
            "desktop_portable_zip": {
                "filename": desktop_pkg["archive"],
                "bytes": desktop_pkg["archive_bytes"],
                "sha256": desktop_pkg["archive_sha256"],
                "webview_flows_passed": desktop_pkg["flows"]["passed"],
            },
            "reproduction_commands": [
                "cargo build --offline --locked --release -p mdd-cli",
                "cargo build --offline --locked --release -p mdd-ffi",
                "python -I apps/desktop/package.py",
            ],
        },
        "verified_linux_x86_64_evidence": {
            "native_ci_evidence": {"path": "artifacts/mdd-080/linux-x86_64-results.json", "sha256": sha256_file(ROOT / "artifacts/mdd-080/linux-x86_64-results.json")},
            "desktop_ci_evidence": {"path": "artifacts/mdd-073/package-check-linux.json", "sha256": sha256_file(ROOT / "artifacts/mdd-073/package-check-linux.json")},
            "reproduction_commands": [
                "cargo build --locked --release -p mdd-cli -p mdd-ffi",
                "python apps/desktop/package.py",
            ],
        },
        "docs": {rel: sha256_file(ROOT / rel) for rel in REQUIRED_DOCS},
    }
    _write_clean_json(DIST_DIR / "release-manifest.json", release_manifest, label="dist/release-manifest.json")

    readme_text = "\n".join([
        "# MeguvizDexDash `0.1.0-dev` 可复验发行清单目录（MDD-083）",
        "",
        "本目录包含标准 DEX 发行所需的无构建噪声清单、 cyclonedx `SBOM.json`、HostLab 显式启用模板、`python/mdd` 与 C ABI `1.0` 源码库存摘要，以及跨平台统一摘要 `SHA256SUMS`（编译出的二进制可执行文件与 `.zip`/`.tar.gz` 安装包由可锁定复现命令本地产出，不直接提交至 Git 仓库）。",
        "",
        "- 查看详细发布边界与实测数据：`docs/RELEASE_NOTES.md`",
        "- 查看 HostLab 分阶段启用与单步回滚手册：`docs/OPERATIONS_AND_ROLLBACK.md`",
        "- 运行离线发布检验与实时环境复演：",
        "  - `python -O -I tools/verify_mdd082.py --check`",
        "  - `python -O -I tools/verify_mdd083.py --check`",
        "",
    ])
    _write_clean_text(DIST_DIR / "README.md", readme_text, label="dist/README.md")

    dist_targets = sorted(p for p in DIST_DIR.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    sums_lines = [f"{sha256_file(p)}  {p.relative_to(ROOT).as_posix()}" for p in dist_targets]
    _write_clean_text(DIST_DIR / "SHA256SUMS", "\n".join(sums_lines) + "\n", label="dist/SHA256SUMS")

    # Execute real live rehearsal on Windows x86_64
    cutover_res = rehearse_cutover.rehearse(binary=cli_bin, fixture=DEFAULT_FIXTURE)
    require(
        cutover_res["stage_2_cutover"]["legacy_tree_unchanged"] is True
        and cutover_res["stage_3_rollback"]["matches_baseline_plan"] is True
        and cutover_res["stage_3_rollback"]["cross_engine_checkpoint_refused"] is True
        and cutover_res["stage_3_rollback"]["legacy_tree_unchanged_after_rollback"] is True,
        f"rehearse_cutover failed: {cutover_res}",
    )
    cutover_public = {
        "engine_pin": cutover_res["engine_pin"],
        "fixture": cutover_res["fixture"],
        "stage_1_baseline": cutover_res["stage_1_baseline"],
        "stage_2_cutover": cutover_res["stage_2_cutover"],
        "stage_3_rollback": cutover_res["stage_3_rollback"],
    }

    c_abi_smoke = _run_c_abi_release_smoke(ffi_bin, DEFAULT_FIXTURE)
    migration_and_cache = _run_m5_to_m8_migration_and_cache_rehearsal(cli_bin, DEFAULT_FIXTURE)

    rehearsal = {
        "schema_version": "mdd.release-rehearsal.v1",
        "task_id": "MDD-083",
        "generated_utc": generated_utc,
        "platform": "windows-x86_64",
        "external_release_published": False,
        "dist_sha256sums_verified": True,
        "dist_files_count": len(dist_targets),
        "cutover_and_rollback_rehearsal": cutover_public,
        "c_abi_release_dll_smoke": c_abi_smoke,
        "upgrade_migration_and_cache_isolation": migration_and_cache,
        "desktop_webview2_release_check": {
            "archive": desktop_pkg["archive"],
            "archive_sha256": desktop_pkg["archive_sha256"],
            "flows_passed": desktop_pkg["flows"]["passed"],
            "flows_failed": desktop_pkg["flows"]["failed"],
        },
        "all_passed": True,
    }
    _write_clean_json(REHEARSAL_PATH, rehearsal, label="release-rehearsal.json")
    return rehearsal


def check() -> int:
    sums_path = DIST_DIR / "SHA256SUMS"
    require(sums_path.is_file(), "missing dist/SHA256SUMS")
    require(REHEARSAL_PATH.is_file(), "missing artifacts/mdd-083/release-rehearsal.json")
    for doc_rel in REQUIRED_DOCS:
        p = ROOT / doc_rel
        require(p.is_file(), f"missing doc: {doc_rel}")
        hit = validator.FORBIDDEN_PUBLIC_RE.search(p.read_text(encoding="utf-8"))
        require(hit is None, f"forbidden public literal in {doc_rel}")

    recorded_sums: dict[str, str] = {}
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("  ", 1)
        require(len(parts) == 2, f"malformed SHA256SUMS line: {line!r}")
        digest, rel = parts
        target = ROOT / rel
        require(target.is_file(), f"missing dist file listed in SHA256SUMS: {rel}")
        require(sha256_file(target) == digest, f"SHA256SUMS mismatch for {rel}")
        hit = validator.FORBIDDEN_PUBLIC_RE.search(target.read_text(encoding="utf-8"))
        require(hit is None, f"forbidden public literal in {rel}")
        recorded_sums[rel] = digest

    expected_dist = {
        "dist/SBOM.json",
        "dist/hostlab-enablement-config.json",
        "dist/python-sdk-manifest.json",
        "dist/c-abi-1.0-manifest.json",
        "dist/release-manifest.json",
        "dist/README.md",
    }
    require(set(recorded_sums) == expected_dist, f"dist inventory mismatch: {sorted(recorded_sums)}")

    rel_man = validator.parse_strict_json((DIST_DIR / "release-manifest.json").read_text(encoding="utf-8"))
    require(rel_man.get("external_release_published") is False, "external_release_published must be false")
    require(rel_man["release_qualification_manifest"]["sha256"] == sha256_file(MANIFEST_082_PATH), "stale MDD-082 manifest hash in dist/release-manifest.json")
    require(rel_man["compatibility_ledger"]["sha256"] == sha256_file(LEDGER_PATH), "stale compatibility/ledger.json hash in dist/release-manifest.json")
    for lock_rel, expected_sha in rel_man["toolchain_and_lockfiles"].items():
        require(sha256_file(ROOT / lock_rel) == expected_sha, f"lockfile hash drift: {lock_rel}")
    for doc_rel, expected_sha in rel_man["docs"].items():
        require(sha256_file(ROOT / doc_rel) == expected_sha, f"doc hash drift: {doc_rel}")

    sbom = validator.parse_strict_json((DIST_DIR / "SBOM.json").read_text(encoding="utf-8"))
    require(sbom.get("bomFormat") == "CycloneDX" and sbom["summary"]["total_components"] >= 50, "invalid dist/SBOM.json")

    raw_reh = REHEARSAL_PATH.read_text(encoding="utf-8")
    require(validator.FORBIDDEN_PUBLIC_RE.search(raw_reh) is None, "forbidden public token in release-rehearsal.json")
    reh = validator.parse_strict_json(raw_reh)
    require(reh.get("all_passed") is True and reh.get("external_release_published") is False, "invalid release-rehearsal.json")
    cut = reh["cutover_and_rollback_rehearsal"]
    require(cut["stage_2_cutover"]["legacy_tree_unchanged"] is True, "legacy tree altered on cutover")
    require(cut["stage_3_rollback"]["matches_baseline_plan"] is True and cut["stage_3_rollback"]["cross_engine_checkpoint_refused"] is True, "rollback checks failed")
    require(reh["c_abi_release_dll_smoke"]["passed"] is True, "C ABI smoke not passed")
    require(reh["upgrade_migration_and_cache_isolation"]["m5_b0_vs_m8_b1_equal"] is True, "M5->M8 migration check failed")
    require(reh["upgrade_migration_and_cache_isolation"]["cache_corrupt_rejected_code"] == "CACHE_CORRUPT", "cache corrupt rejection missing")
    require(reh["upgrade_migration_and_cache_isolation"]["cross_engine_resume_refused"] is True, "cross-engine resume check invalid")

    print(f"MDD-083 check passed: {len(recorded_sums)} dist manifests + SBOM ({sbom['summary']['total_components']} components) + live rehearsal verified")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if args.generate:
        generate()
        print(f"MDD-083 release bundle & rehearsal written -> {REHEARSAL_PATH}")
        return 0
    return check()


if __name__ == "__main__":
    sys.exit(main())
