#!/usr/bin/env python3
"""Run MDD-063 cache conformance & fault recovery suite and optionally verify the committed record."""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RECORD = ROOT / "artifacts/mdd-063/cache-fault-recovery.json"
MATRIX = ROOT / "conformance/cache/invalidation-matrix.json"
SOURCES = [
    "crates/mdd-cache/Cargo.toml",
    "crates/mdd-cache/src/lib.rs",
    "crates/mdd-cache/src/key.rs",
    "crates/mdd-cache/src/format.rs",
    "crates/mdd-cache/src/cas.rs",
    "crates/mdd-cache/src/guard.rs",
    "crates/mdd-cache/src/facts_codec.rs",
    "crates/mdd-cache/src/store.rs",
    "crates/mdd-cache/src/dependency_tracking.rs",
    "crates/mdd-cache/src/dependency_tracking/content_reuse.rs",
    "crates/mdd-cache/src/dependency_tracking/incremental_gate.rs",
    "crates/mdd-cache/examples/cache_probe.rs",
    "crates/mdd-cache/tests/cache_integration.rs",
    "conformance/cache/invalidation-matrix.json",
    "conformance/cache/run_cache_conformance.py",
    "conformance/cache/test_cache_conformance.py",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ensure_probe_binary(explicit: Path | None) -> Path:
    if explicit is not None:
        require(explicit.is_file(), f"cache_probe binary missing: {explicit}")
        return explicit.resolve()
    exe_name = "cache_probe.exe" if os.name == "nt" else "cache_probe"
    candidate = ROOT / "target/debug/examples" / exe_name
    if not candidate.is_file():
        done = subprocess.run(
            ["cargo", "build", "--offline", "--locked", "-p", "mdd-cache", "--example", "cache_probe"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        require(done.returncode == 0, f"failed building cache_probe: {done.stderr}")
    require(candidate.is_file(), f"cache_probe binary missing after build: {candidate}")
    return candidate


def run_probe(probe: Path, *args: str) -> dict:
    done = subprocess.run(
        [str(probe), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if args and args[0] == "verify-file":
        require(done.stdout.strip().startswith("{"), f"unexpected verify-file output: {done.stdout} / {done.stderr}")
        return json.loads(done.stdout)
    require(done.returncode == 0, f"cache_probe failed ({args}): stdout={done.stdout} stderr={done.stderr}")
    return json.loads(done.stdout)


def run_probe_failure(probe: Path, *args: str) -> str:
    done = subprocess.run(
        [str(probe), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    require(done.returncode != 0, f"expected failure from cache_probe ({args}), got exit 0: {done.stdout}")
    return done.stderr.strip()


def run_suite(probe: Path) -> dict:
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    fix_dir = ROOT / "tests/fixtures/generated"
    before_src = fix_dir / "structured-035.dex"
    after_src = fix_dir / "structured-035-same-size-changed.dex"
    apk_src = fix_dir / "multidex-deflated.apk"
    results = {}

    # 0. Run Rust cache integration tests directly (verifies partial/deadline/truncated/negative guards & RuleCacheKey).
    rust_tests = subprocess.run(
        ["cargo", "test", "--offline", "--locked", "-p", "mdd-cache"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    require(rust_tests.returncode == 0, f"mdd-cache cargo test failed: {rust_tests.stdout}\n{rust_tests.stderr}")

    with tempfile.TemporaryDirectory(prefix="mdd063-") as tmp:
        work = Path(tmp)
        cache_dir = work / "cache"
        in_dir = work / "inputs"
        in_dir.mkdir(parents=True, exist_ok=True)
        work_dex = in_dir / "sample.dex"
        shutil.copyfile(before_src, work_dex)

        # Case 1: cold / warm / bypass / source-deleted standalone equivalence
        bypass = run_probe(probe, "run", "--cache-dir", str(cache_dir), "--mode", "standalone", "--policy", "bypass", "--input", str(work_dex))
        require(bypass["report"]["outcome"] == "bypassed", "expected bypassed")
        require(bypass["build_fn_invoked"] is True, "bypass must invoke builder")

        cold = run_probe(probe, "run", "--cache-dir", str(cache_dir), "--mode", "standalone", "--policy", "read-write", "--input", str(work_dex))
        require(cold["report"]["outcome"] == "built_cold", f"expected built_cold, got {cold['report']['outcome']}")
        require(cold["build_fn_invoked"] is True, "cold must build")
        require(cold["overall_tables_sha256"] == bypass["overall_tables_sha256"], "cold != bypass")
        require(cold["raw_code_methods_sha256"] == bypass["raw_code_methods_sha256"], "cold raw != bypass")

        warm = run_probe(probe, "run", "--cache-dir", str(cache_dir), "--mode", "standalone", "--policy", "read-write", "--input", str(work_dex))
        require(warm["report"]["outcome"] == "hit_warm", f"expected hit_warm, got {warm['report']['outcome']}")
        require(warm["build_fn_invoked"] is False, "warm hit MUST NOT invoke builder")
        require(warm["overall_tables_sha256"] == bypass["overall_tables_sha256"], "warm != bypass")
        require(warm["report"]["runtime_snapshot_id"] != cold["report"]["runtime_snapshot_id"], "runtime snapshot_id reused across reopen")

        # Delete source file completely and reopen standalone index file directly in cache-only mode.
        key = cold["report"]["canonical_cache_key"]
        standalone_idx = cache_dir / "index" / f"{key}.standalone.mddidx"
        header_info = run_probe(probe, "inspect-header", str(standalone_idx))
        require(header_info["header"]["header_bytes"] == 128, "header must be 128B")
        require(header_info["header"]["endian"] == 1, "endian must be 1")

        backup_dex = work / "backup.dex"
        shutil.copyfile(work_dex, backup_dex)
        work_dex.unlink()
        warm_deleted = run_probe(probe, "run", "--cache-dir", str(cache_dir), "--index-file", str(standalone_idx))
        require(warm_deleted["ok"] is True, "standalone cache must work after source removal")
        shutil.copyfile(backup_dex, work_dex)

        results["cold_warm_bypass_equivalence_standalone"] = {
            "passed": True,
            "canonical_cache_key": key,
            "table_count": len(cold["table_digests"]),
            "overall_tables_sha256": cold["overall_tables_sha256"],
            "header_bytes": header_info["header"]["header_bytes"],
            "warm_build_fn_invoked": warm["build_fn_invoked"],
        }

        # Case 2: Thin mode CAS reuse + missing CAS -> STALE_CACHE + mutated CAS -> CACHE_CORRUPT
        thin_cold = run_probe(probe, "run", "--cache-dir", str(cache_dir), "--mode", "thin", "--policy", "read-write", "--input", str(work_dex))
        require(thin_cold["report"]["outcome"] == "built_cold", "thin expected built_cold")
        require(thin_cold["overall_tables_sha256"] == bypass["overall_tables_sha256"], "thin != bypass")
        thin_idx = cache_dir / "index" / f"{key}.thin.mddidx"
        content_hex = next(iter(thin_cold["verified_blob_digests"].values()))
        cas_blob = cache_dir / "cas/sha256" / content_hex[:2] / f"{content_hex}.blob"
        require(cas_blob.is_file(), f"missing CAS blob {cas_blob}")
        orig_cas = cas_blob.read_bytes()
        # Mutate CAS 1 byte -> CACHE_CORRUPT
        cas_blob.write_bytes(orig_cas[:-1] + bytes([orig_cas[-1] ^ 0xFF]))
        res_cas_corrupt = run_probe(probe, "verify-file", "--cache-dir", str(cache_dir), "--file", str(thin_idx))
        require(res_cas_corrupt["ok"] is False and res_cas_corrupt["error_code"] == "CACHE_CORRUPT", f"CAS corrupt failed: {res_cas_corrupt}")
        # Delete CAS -> STALE_CACHE
        cas_blob.unlink()
        res_cas_missing = run_probe(probe, "verify-file", "--cache-dir", str(cache_dir), "--file", str(thin_idx))
        require(res_cas_missing["ok"] is False and res_cas_missing["error_code"] == "STALE_CACHE", f"CAS missing failed: {res_cas_missing}")
        cas_blob.write_bytes(orig_cas)

        results["thin_mode_cas_persistence_and_faults"] = {
            "passed": True,
            "corrupt_cas_error": res_cas_corrupt["error_code"],
            "missing_cas_error": res_cas_missing["error_code"],
        }

        # Case 3 & 4: Path rename keeps key; same-size same-mtime 1-byte mutation invalidates key
        alt_dir = work / "moved_dir"
        alt_dir.mkdir(parents=True, exist_ok=True)
        moved_dex = alt_dir / "completely_different_name.dex"
        shutil.copyfile(work_dex, moved_dex)
        moved_hit = run_probe(probe, "run", "--cache-dir", str(cache_dir), "--mode", "standalone", "--policy", "cache-only", "--input", str(moved_dex))
        require(moved_hit["report"]["outcome"] == "hit_warm", "moved identical bytes must hit cache")
        require(moved_hit["report"]["canonical_cache_key"] == key, "path rename changed cache key")

        st_before = moved_dex.stat()
        shutil.copyfile(after_src, moved_dex)
        os.utime(moved_dex, ns=(st_before.st_atime_ns, st_before.st_mtime_ns))
        st_after = moved_dex.stat()
        require(st_before.st_size == st_after.st_size and st_before.st_mtime_ns == st_after.st_mtime_ns, "mtime/size test setup mismatch")
        # Cache-only against old key with mutated source MUST fail STALE_CACHE; opening mutated builds distinct key
        mutated_err = run_probe_failure(probe, "run", "--cache-dir", str(cache_dir), "--index-file", str(standalone_idx), "--input", str(moved_dex))
        require("STALE_CACHE" in mutated_err, f"expected STALE_CACHE on mutated disk file, got {mutated_err}")
        mutated_built = run_probe(probe, "run", "--cache-dir", str(cache_dir), "--mode", "standalone", "--policy", "read-write", "--input", str(moved_dex))
        require(mutated_built["report"]["canonical_cache_key"] != key, "1-byte same-size/same-mtime mutation must invalidate key")

        results["path_rename_preserves_cache_key"] = {"passed": True, "key": key}
        results["same_size_same_mtime_one_byte_mutation"] = {
            "passed": True,
            "size_bytes": st_after.st_size,
            "before_key": key,
            "after_key": mutated_built["report"]["canonical_cache_key"],
            "stale_error_detected": True,
        }

        # Case 5: Logical duplicate multiplicity preserved
        dup_bypass = run_probe(probe, "run", "--cache-dir", str(cache_dir), "--mode", "standalone", "--policy", "bypass", "--input", str(work_dex), "--input", str(work_dex))
        dup_cold = run_probe(probe, "run", "--cache-dir", str(cache_dir), "--mode", "standalone", "--policy", "read-write", "--input", str(work_dex), "--input", str(work_dex))
        dup_warm = run_probe(probe, "run", "--cache-dir", str(cache_dir), "--mode", "standalone", "--policy", "read-write", "--input", str(work_dex), "--input", str(work_dex))
        require(dup_cold["report"]["canonical_cache_key"] != key, "duplicate inputs collided with single-input key")
        require(dup_cold["table_digests"]["dex_files"][0] == 2, f"expected 2 dex_files rows, got {dup_cold['table_digests']['dex_files']}")
        require(dup_cold["overall_tables_sha256"] == dup_bypass["overall_tables_sha256"] == dup_warm["overall_tables_sha256"], "duplicate cold/warm/bypass mismatch")
        require(dup_warm["build_fn_invoked"] is False, "duplicate warm must skip builder")
        require(dup_warm["occurrence_reuse_map"]["by_content_id"], "expected reuse map entries")

        results["logical_duplicate_multiplicity_preserved"] = {
            "passed": True,
            "single_key": key,
            "duplicate_key": dup_cold["report"]["canonical_cache_key"],
            "dex_files_rows": dup_cold["table_digests"]["dex_files"][0],
            "overall_tables_sha256": dup_warm["overall_tables_sha256"],
        }

        # Case 6: Half-write .tmp, truncated, nonzero reserved, major=2, section flip & recovery
        orig_idx_bytes = standalone_idx.read_bytes()
        trunc_file = work / "trunc.mddidx"
        trunc_file.write_bytes(orig_idx_bytes[:64])
        res_trunc = run_probe(probe, "verify-file", "--file", str(trunc_file))
        require(res_trunc["error_code"] == "CACHE_CORRUPT", f"truncated header expected CACHE_CORRUPT, got {res_trunc}")

        reserved_bad = bytearray(orig_idx_bytes)
        reserved_bad[54] = 1
        reserved_bad[96:128] = hashlib.sha256(bytes(reserved_bad[:96])).digest()
        reserved_file = work / "reserved_bad.mddidx"
        reserved_file.write_bytes(bytes(reserved_bad))
        res_reserved = run_probe(probe, "verify-file", "--file", str(reserved_file))
        require(res_reserved["error_code"] == "CACHE_CORRUPT", f"nonzero reserved expected CACHE_CORRUPT, got {res_reserved}")

        v2_hdr = bytearray(orig_idx_bytes)
        v2_hdr[8:10] = (2).to_bytes(2, "little")
        v2_hdr[96:128] = hashlib.sha256(bytes(v2_hdr[:96])).digest()
        v2_file = work / "v2.mddidx"
        v2_file.write_bytes(bytes(v2_hdr))
        res_v2 = run_probe(probe, "verify-file", "--file", str(v2_file))
        require(res_v2["error_code"] == "STALE_CACHE", f"major=2 expected STALE_CACHE, got {res_v2}")

        tmp_leak = cache_dir / "index" / f".{key}.standalone.tmp.12345.deadbeef"
        tmp_leak.write_bytes(orig_idx_bytes[:200])
        res_tmp = run_probe(probe, "verify-file", "--file", str(tmp_leak))
        require(res_tmp["ok"] is False and res_tmp["error_code"] == "CACHE_CORRUPT", f"tmp file not rejected: {res_tmp}")

        # Flip payload byte inside live standalone_idx -> CacheOnly fails, ReadWrite heals and reclaims tmp_leak
        corrupted_live = bytearray(orig_idx_bytes)
        corrupted_live[len(corrupted_live) - 30] ^= 0xAA
        standalone_idx.write_bytes(bytes(corrupted_live))
        cache_only_err = run_probe_failure(probe, "run", "--cache-dir", str(cache_dir), "--mode", "standalone", "--policy", "cache-only", "--input", str(work_dex))
        require("CACHE_CORRUPT" in cache_only_err, f"CacheOnly corrupt err mismatch: {cache_only_err}")
        healed = run_probe(probe, "run", "--cache-dir", str(cache_dir), "--mode", "standalone", "--policy", "read-write", "--input", str(work_dex))
        require(healed["report"]["outcome"] == "rebuilt_corrupt", f"expected rebuilt_corrupt, got {healed['report']['outcome']}")
        require(healed["overall_tables_sha256"] == bypass["overall_tables_sha256"], "healed != bypass")
        require(not tmp_leak.exists(), "stale .tmp leak must be reclaimed during open_or_build")

        results["half_write_truncation_corruption_and_recovery"] = {
            "passed": True,
            "truncated_error": res_trunc["error_code"],
            "nonzero_reserved_error": res_reserved["error_code"],
            "unsupported_version_error": res_v2["error_code"],
            "recovered_outcome": healed["report"]["outcome"],
            "reclaimed_stale_tmp": True,
        }

        # Case 7: Multi-process concurrent lock contention on cold APK
        apk_copy = in_dir / "multi.apk"
        shutil.copyfile(apk_src, apk_copy)
        race_cache = work / "race_cache"
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(run_probe, probe, "run", "--cache-dir", str(race_cache), "--mode", "standalone", "--policy", "read-write", "--hold-ms", "150", "--input", str(apk_copy))
            f2 = pool.submit(run_probe, probe, "run", "--cache-dir", str(race_cache), "--mode", "standalone", "--policy", "read-write", "--hold-ms", "150", "--input", str(apk_copy))
            r1 = f1.result(timeout=60)
            r2 = f2.result(timeout=60)
        outcomes = {r1["report"]["outcome"], r2["report"]["outcome"]}
        require("built_cold" in outcomes, f"expected one built_cold in concurrent race, got {outcomes}")
        require(r1["overall_tables_sha256"] == r2["overall_tables_sha256"], "concurrent race produced divergent tables")
        leftover_temps = [p.name for p in (race_cache / "index").glob("*.tmp.*")]
        require(not leftover_temps, f"leftover temp files after concurrent publish: {leftover_temps}")

        results["concurrent_lock_writers_atomic_publish"] = {
            "passed": True,
            "worker_outcomes": sorted([r1["report"]["outcome"], r2["report"]["outcome"]]),
            "tables_sha256": r1["overall_tables_sha256"],
            "leftover_temps": 0,
        }

        results["partial_deadline_truncated_unpaged_negative_guard"] = {
            "passed": True,
            "verified_by": "crates/mdd-cache/tests/cache_integration.rs",
        }

    all_passed = all(v["passed"] for v in results.values()) and len(results) == len(matrix["cases"])
    return {
        "schema_version": "mdd.cache-fault-recovery.v1",
        "task_id": "MDD-063",
        "cache_format": "mdd-index/1",
        "source_sha256": {p: sha256_file(ROOT / p) for p in SOURCES},
        "cases": results,
        "all_passed": all_passed,
    }


def check_record(path: Path) -> int:
    require(path.is_file(), f"missing record: {path}")
    doc = json.loads(path.read_text(encoding="utf-8"))
    require(doc.get("all_passed") is True, "record all_passed is not true")
    recorded_hashes = doc.get("source_sha256", {})
    for rel in SOURCES:
        actual = sha256_file(ROOT / rel)
        require(recorded_hashes.get(rel) == actual, f"source hash drift for {rel}")
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    for case in matrix["cases"]:
        cid = case["id"]
        require(doc.get("cases", {}).get(cid, {}).get("passed") is True, f"matrix case not passed: {cid}")
    print(f"MDD-063 record check passed: {len(matrix['cases'])} cases, {len(SOURCES)} source hashes current")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=None, help="Ignored generic CLI binary arg when invoked by CI runner")
    parser.add_argument("--probe-binary", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    _ = args.binary

    if args.check:
        return check_record(RECORD)

    probe = ensure_probe_binary(args.probe_binary)
    report = run_suite(probe)
    out = args.out if args.out is not None else RECORD
    if not out.is_absolute():
        out = ROOT / out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"MDD-063 cache conformance passed ({len(report['cases'])} cases) -> {out}")
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
