"""MDD-054: the shadow harness. Run HostLab's own, unmodified full audit twice on one frozen input - A over the reference
engine, B over MeguvizDexDash - in separate workspaces, with nothing that publishes, dispatches or calls out, and compare the two
complete runs with `conformance/hostlab/compare_full_reports.py`.

What is the same for A and B: the HostLab source (checked against its git commit and its recorded file digests before and
after), the APK (its full SHA-256 before and after), the command (`analyze.main audit --mode full`), the timeout, the
resource limits (a Windows Job: memory commit, CPUs, processes), the environment without secrets. What is separate: the
HostLab state root (reports, checkpoints, queue), the cache directory, TEMP, the result directory - one folder per side, and
the harness refuses to start if one is inside another.

What B changes, and nothing else: the module `native_session` is the integration's (this directory) instead of HostLab's, and
`install_dexsql` is a stand-in that states the engine under test. HostLab's `native_audit`, `native_graph`, `native_rules`,
`native_surface`, `analyze`, `verify_audits`, the intake and home gates are the reference files.

The entry points that would publish, configure, call a service or choose a remote job are replaced by functions that record
the attempt and fail; Python sockets refuse network addresses. A violation is written into the run record and fails the run.

Standard library plus pywin32 (the isolated baseline interpreter has it) for the Job. Windows only, like the baseline.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "conformance/hostlab"))

import compare_full_reports as compare  # noqa: E402

RUN_SCHEMA = "mdd.hostlab-shadow-run.v1"
MANIFEST_SCHEMA = "mdd.hostlab-shadow-manifest.v1"
FORBIDDEN_ENTRY_POINTS = ("config", "api_private", "manifest", "select")
SECRET_NAME = re.compile(r"TOKEN|SECRET|PASSWORD|API_KEY", re.I)


class ShadowError(RuntimeError):
    pass


def read_json(path: "str | Path"):
    return compare.read_json(path)


def write_json(path: "str | Path", value) -> None:
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def sha256_file(path: "str | Path") -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


# ---- identity -----------------------------------------------------------------------------------------------------------------

def verify_reference(reference: Path, plan: dict) -> Path:
    """The HostLab source is the pinned commit, with no change and no untracked file, and each recorded file has its digest."""
    reference = Path(reference).resolve(strict=True)
    git = ["git", "-c", "safe.directory=" + str(reference), "-C", str(reference)]
    head = subprocess.check_output(git + ["rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(git + ["status", "--porcelain"], text=True)
    changed = subprocess.run(git[:1] + ["-c", "core.autocrlf=false"] + git[1:] + ["diff", "HEAD", "--quiet"], capture_output=True).returncode
    if head != plan["reference"]["commit"] or changed or any(line.startswith("??") for line in dirty.splitlines()):
        raise ShadowError("the HostLab reference is not the pinned commit, or has changed or untracked files")
    expected = read_json(ROOT / plan["reference"]["source_manifest"])["source_files"]
    for relative, identity in expected.items():
        if sha256_file(reference / relative) != identity["sha256"]:
            raise ShadowError("a HostLab reference file changed: " + relative)
    return reference


def verify_input(sample: dict, path: "str | Path") -> Path:
    path = Path(path).resolve(strict=True)
    if str(path.stat().st_size) != str(sample["bytes"]) or sha256_file(path) != sample["sha256"]:
        raise ShadowError("the input is not the pinned file: " + sample["occurrence_id"])
    return path


def disjoint(folders: "dict[str, Path]") -> None:
    """No workspace is, or is inside, another: the report, checkpoint, queue and cache paths of A and B cannot meet."""
    items = {name: Path(folder).resolve() for name, folder in folders.items()}
    for left, a in items.items():
        for right, b in items.items():
            if left < right and (a == b or a in b.parents or b in a.parents):
                raise ShadowError(f"workspaces {left} and {right} are not disjoint")


def child_environment(side_dir: Path) -> dict:
    """The parent's environment without secrets, with every writable location pointed into the side's own folder."""
    env = {key: value for key, value in os.environ.items() if not SECRET_NAME.search(key)}
    for stale in ("HOSTLAB_DEXSQL", "HOSTLAB_MEGUVIZDEXDASH", "HOSTLAB_PROVIDER_CONFIG", "HOSTLAB_STRUCTURAL_CONFIG", "DEXQ_CACHE_DIR", "MDD_CACHE_DIR"):
        env.pop(stale, None)
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8", TEMP=str(side_dir / "tmp"), TMP=str(side_dir / "tmp"),
               DEXQ_CACHE_DIR=str(side_dir / "cache"), XDG_CACHE_HOME=str(side_dir / "cache"))
    return env


# ---- the engine under test (B) -------------------------------------------------------------------------------------------------

def engine_stand_in(identity: dict) -> types.ModuleType:
    """`install_dexsql` for B: HostLab's audit records `install_dexsql.status()` as the engine of the run. It states the engine
    under test and installs nothing."""
    module = types.ModuleType("install_dexsql")
    module.__file__ = __file__
    module.VERSION = identity["version"]
    binary = Path(identity["path"])

    def status() -> dict:
        return dict(identity, available=True)

    def refuse(*_a, **_k):
        raise ShadowError("the shadow harness never installs or renews an engine")

    module.status, module.install = status, refuse
    module.verify = lambda path=None: binary
    module.executable = lambda: binary
    module.asset = lambda: (binary.name, identity["sha256"])
    return module


def write_b_configuration(side_dir: Path, pin_manifest: Path, plan: dict) -> dict:
    side = plan["sides"]["B"]
    provider = side_dir / "provider-config.json"
    write_json(provider, {"schema": "mdd.hostlab-provider-config.v1", "native_engine": "meguvizdexdash",
                          "meguvizdexdash": {"manifest": str(pin_manifest), "profile_policy": side["profile_policy"]}})
    structural = side_dir / "structural-config.json"
    body = {"schema": "mdd.hostlab-structural-config.v1", "wire": side["wire"]}
    if side.get("sql_limits"):
        body["sql_limits"] = side["sql_limits"]
    if side.get("non_scalar_text"):
        body["non_scalar_text"] = side["non_scalar_text"]
    write_json(structural, body)
    return {"HOSTLAB_PROVIDER_CONFIG": str(provider), "HOSTLAB_STRUCTURAL_CONFIG": str(structural)}


# ---- the worker: one side, one input ---------------------------------------------------------------------------------------------

def run_side(plan: dict, paths: dict, side: str, sample_id: str, out: Path) -> dict:
    sample = next(item for item in plan["inputs"] if item["occurrence_id"] == sample_id)
    reference = verify_reference(Path(paths["reference"]), plan)
    apk = verify_input(sample, paths["inputs"][sample_id])
    engine_path = Path(paths["engines"][side]).resolve(strict=True)
    engine_sha = sha256_file(engine_path)
    wanted = plan["sides"][side]
    if wanted.get("sha256") and engine_sha != wanted["sha256"]:
        raise ShadowError(f"engine {side} is not the pinned binary")
    state = out / "state"
    sys.dont_write_bytecode = True
    violations: list = []
    # This script's own folder holds the integration's `native_session`: it is on the path for B and must not be for A.
    sys.path[:] = [entry for entry in sys.path if Path(entry or ".").resolve() not in (HERE, ROOT / "conformance/hostlab")]
    sys.path.insert(0, str(reference / "tools/hostlab"))
    if side == "B":
        sys.path.insert(0, str(HERE))
        os.environ["HOSTLAB_MEGUVIZDEXDASH"] = str(engine_path)
        os.environ.update(write_b_configuration(out, Path(paths["b_pin_manifest"]), plan))
        build = next((item for item in read_json(paths["b_pin_manifest"])["builds"] if item["sha256"] == engine_sha), None)
        if build is None:
            raise ShadowError("the pin manifest does not name the binary that is run")
        identity = {"version": build["engine_version"], "build_id": build["build_id"], "sha256": engine_sha, "path": str(engine_path),
                    "engine": "meguvizdexdash", "wire": wanted["wire"], "pin_provider": "mdd-shadow-b-v1",
                    "implementation_scope": build["implementation_scope"]}
        sys.modules["install_dexsql"] = engine_stand_in(identity)
    else:
        os.environ["HOSTLAB_DEXSQL"] = str(engine_path)
        identity = {"version": wanted["version"], "sha256": engine_sha, "path": str(engine_path), "engine": "dexsql"}
    import analyze
    import hostlab
    import verify_audits
    from analysis.run_intake import EXPECTED_FEATURES
    hostlab.STATE = state
    hostlab.CONFIG = state / "config.json"

    def forbidden(name):
        def refuse(*_a, **_k):
            violations.append({"entry_point": name, "at": time.time()})
            raise ShadowError("the shadow forbids remote, configuration, AI and publish entry points: " + name)
        return refuse

    for name in FORBIDDEN_ENTRY_POINTS:
        setattr(hostlab, name, forbidden(name))
    original_connect = socket.socket.connect

    def offline(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            violations.append({"entry_point": "socket.connect", "address": repr(address)[:80]})
            raise ShadowError("Python network access is forbidden in the shadow")
        return original_connect(sock, address)

    socket.socket.connect = offline
    tools_before = analyze.tool_hashes()
    carrier: dict = {}
    started = time.perf_counter()
    exit_code = analyze.main(["audit", "--apk", str(apk), "--mode", "full", "--backend", "dexsql",
                              "--timeout", str(plan["resources"]["native_timeout_seconds"])], surface_output=carrier)
    elapsed = time.perf_counter() - started
    summaries = list((state / "reports").glob("*/*/*/summary.json"))
    if len(summaries) != 1:
        raise ShadowError("not exactly one fresh report")
    report = read_json(summaries[0])
    native = report.get("native_audit", {})
    problems = []
    if exit_code not in (0, 1) or report.get("audit_complete") is not True or report.get("mode") != "full":
        problems.append("the audit is not a complete full audit")
    if report.get("audit_backend") != "dexsql" or report.get("backend_fallback_reason") is not None:
        problems.append("a fallback is recorded")
    if report.get("home_probe_exit_code") != 0 or set(report.get("features", {})) != set(EXPECTED_FEATURES):
        problems.append("the home gate or the FEATURE set differs")
    if native.get("complete") is not True or native.get("source_sha_reverified") is not True or report["sample"].get("sha256") != sample["sha256"]:
        problems.append("the native audit is incomplete or names another input")
    if (native.get("native") or {}).get("sha256") != engine_sha:
        problems.append("the engine the report names is not the engine run")
    if report["sample"].get("certificate_sha256") != sample["expected_certificate_sha256"]:
        problems.append("the signer lineage differs")
    surface = carrier.get("report")
    if not isinstance(surface, dict) or surface.get("scan_execution", {}).get("dex_files") != sample["dex_members"]:
        problems.append("the surface report is missing or covers another DEX count")
    if sha256_file(apk) != sample["sha256"] or tools_before != analyze.tool_hashes():
        problems.append("the input or the HostLab tools changed during the run")
    if violations:
        problems.append("forbidden entry points were reached")
    if problems:
        write_json(out / "failure.json", {"problems": problems, "violations": violations, "exit_code": exit_code})
        raise ShadowError("; ".join(problems))
    surface["sample"] = report["sample"]
    evidence = verify_audits.evidence(report, surface, summaries[0].with_name("features.tsv"), summaries[0].with_name("home-frame.log"))
    hostlab.write_json(out / "evidence.json", evidence)
    groups = {name: compare.group_digest(name, value) for name, value in evidence.items()}
    certificate = {
        "schema": "mdd.hostlab-shadow-certificate.v1", "complete": True, "side": side, "engine": identity,
        "input_sha256": sample["sha256"], "reference_source_commit": plan["reference"]["commit"], "tools": tools_before,
        "feature_count": len(EXPECTED_FEATURES), "evidence_group_count": len(groups), "groups": groups,
        "fallback_count": 0, "output_fully_materialized": True, "more_available": False, "truncated": False,
        "business_exit_code": exit_code, "evidence_sha256": sha256_file(out / "evidence.json"),
        "violations": violations, "class_count": native["class_count"], "queries": native["queries"],
        "wall_seconds": elapsed, "native_phases": native.get("phases"),
        "state_root": "state", "files_written": sorted(str(p.relative_to(out)).replace("\\", "/") for p in out.rglob("*") if p.is_file()),
    }
    write_json(out / "certificate.json", certificate)
    return certificate


# ---- the orchestrator ----------------------------------------------------------------------------------------------------------------

def run_in_job(argv: list, directory: Path, env: dict, resources: dict) -> dict:
    """One worker in a Windows Job with the memory, CPU and process limits of the manifest (the baseline's supervisor)."""
    supervisor = ROOT / "artifacts/mdd-005/preparation-20261028"
    sys.path.insert(0, str(supervisor))
    from windows_job import run_job
    return run_job(argv, directory, cwd=ROOT, env=env, timeout_seconds=resources["worker_timeout_seconds"],
                   memory_bytes=int(resources["job_memory_commit_bytes"]), affinity_mask=int(resources["cpu_affinity_mask"]),
                   max_processes=resources["max_processes"])


def shadow(plan: dict, paths: dict, sample_id: str, sides: "list[str]", out: Path, manifest: Path, paths_file: Path) -> dict:
    sample = next(item for item in plan["inputs"] if item["occurrence_id"] == sample_id)
    verify_reference(Path(paths["reference"]), plan)
    verify_input(sample, paths["inputs"][sample_id])
    out = Path(out).resolve()
    folders = {side: out / side for side in sides}
    disjoint(folders)
    out.mkdir(parents=True, exist_ok=False)
    records: dict = {}
    for side, folder in folders.items():
        for name in ("tmp", "cache", "state"):
            (folder / name).mkdir(parents=True)
        argv = [paths.get("python") or sys.executable, "-B", str(Path(__file__).resolve()), "--manifest", str(manifest), "--paths", str(paths_file),
                "--worker", "--side", side, "--sample", sample_id, "--out", str(folder)]
        result = run_in_job(argv, folder / "job", child_environment(folder), plan["resources"])
        complete = result["status"] == "completed" and result["tree_empty_verified"] and (folder / "certificate.json").is_file()
        records[side] = {"supervisor": result, "complete": complete, "folder": side}
        if not complete:
            break
    comparison = None
    if all(records.get(side, {}).get("complete") for side in ("A", "B")):
        comparison = compare.compare(compare.load_run(folders["A"]), compare.load_run(folders["B"]))
        write_json(out / "comparison.json", comparison)
    record = {
        "schema": RUN_SCHEMA, "task": "MDD-054", "sample": sample_id, "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "sides": {side: {"complete": value["complete"], "status": value["supervisor"]["status"],
                         "peak_job_commit_bytes": value["supervisor"].get("peak_job_commit_bytes"),
                         "wall_seconds": value["supervisor"].get("wall_seconds"), "exit_code": value["supervisor"].get("exit_code"),
                         "reason": value["supervisor"].get("reason")} for side, value in records.items()},
        "equal": None if comparison is None else comparison["equal"],
        "layers": None if comparison is None else {item["layer"]: {"equal": item["equal"], "differences": item["difference_count"]} for item in comparison["layers"]},
        "platform": platform.platform(), "scope": "correctness shadow; wall times are not a measurement",
    }
    write_json(out / "shadow-run.json", record)
    return record


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--paths", type=Path, required=True, help="local file: reference, inputs, engines, b_pin_manifest, python (never committed)")
    parser.add_argument("--sample", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--sides", default="A,B")
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--side", choices=("A", "B"))
    args = parser.parse_args(argv)
    plan, paths = read_json(args.manifest), read_json(args.paths)
    if plan.get("schema") != MANIFEST_SCHEMA:
        raise ShadowError("not a shadow manifest")
    if args.worker:
        run_side(plan, paths, args.side, args.sample, args.out)
        return 0
    record = shadow(plan, paths, args.sample, args.sides.split(","), args.out, args.manifest.resolve(), args.paths.resolve())
    print(json.dumps(record, ensure_ascii=False, indent=2))
    return 0 if record["equal"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
