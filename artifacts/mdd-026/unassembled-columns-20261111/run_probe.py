#!/usr/bin/env python3
"""Compile and run the MDD-026 unassembled-columns evidence probe.

The probe is a standalone rustc invocation against the rlibs `cargo build
--offline -p mdd-facts` already produced. No new Cargo target or dependency is
created. Every command, its argv, exit code and output digest are recorded.
"""
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(label, argv):
    started = datetime.datetime.now(datetime.timezone.utc)
    completed = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True)
    finished = datetime.datetime.now(datetime.timezone.utc)
    folder = HERE / label
    folder.mkdir(exist_ok=True)
    (folder / "stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (folder / "stderr.txt").write_text(completed.stderr, encoding="utf-8")
    record = {
        "argv": [str(item) for item in argv],
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "exit_code": completed.returncode,
        "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
        "scope": "tiny development fixtures; not performance or a profile admission",
    }
    (folder / "record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    if completed.returncode != 0:
        print(f"FAILED {label}\n{completed.stderr}", file=sys.stderr)
        raise SystemExit(1)
    return completed


def rlibs():
    """Take the exact rlib paths cargo reports for the built package graph.

    Picking by directory mtime can select a stale or differently-featured build
    of the same crate name, which makes `MddError` nominally distinct. Cargo's
    own `--message-format=json` output names the exact artifacts it linked.
    """
    completed = run(
        "build-json",
        [
            "cargo",
            "build",
            "--offline",
            "-p",
            "mdd-facts",
            "--message-format=json",
        ],
    )
    wanted = {"mdd_dex", "mdd_facts", "mdd_input", "mdd_types", "serde_json"}
    found = {}
    for line in completed.stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("reason") != "compiler-artifact":
            continue
        name = message["target"]["name"].replace("-", "_")
        if name not in wanted:
            continue
        for path in message.get("filenames", []):
            if path.endswith(".rlib"):
                found[name] = pathlib.Path(path)
    missing = wanted - found.keys()
    if missing:
        raise SystemExit(f"cargo did not report rlibs for {sorted(missing)}")
    return found


def main():
    run("build", ["cargo", "build", "--offline", "-p", "mdd-facts"])
    linked = rlibs()
    argv = [
        "rustc",
        "--edition=2024",
        "--crate-name",
        "mdd_unassembled_probe",
        str(HERE / "probe_rows.rs"),
        "-L",
        "dependency=target/debug/deps",
        "-o",
        str(HERE / "probe_rows.exe"),
    ]
    for name, path in linked.items():
        argv += ["--extern", f"{name}={path}"]
    run("compile", argv)
    result = run("run", [str(HERE / "probe_rows.exe"), str(ROOT)])
    (HERE / "native-rows.json").write_text(result.stdout, encoding="utf-8")
    produced = json.loads(result.stdout)
    if produced["task_complete_proven"] or produced["profile_admitted"]:
        raise SystemExit("probe overclaimed scope")
    summaries = {
        "schema_version": "mdd.mdd-026.unassembled-columns-probe.v1",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "rlibs": {name: {"path": str(path), "sha256": digest(path)} for name, path in linked.items()},
        "probe_source": {
            "path": "artifacts/mdd-026/unassembled-columns-20261111/probe_rows.rs",
            "sha256": digest(HERE / "probe_rows.rs"),
        },
        "native_rows": {
            "path": "artifacts/mdd-026/unassembled-columns-20261111/native-rows.json",
            "sha256": digest(HERE / "native-rows.json"),
        },
        "dex_file_rows": {label: len(rows) for label, rows in produced["dex_files"].items()},
        "method_rows": {label: len(rows) for label, rows in produced["methods"].items()},
        "task_complete_proven": False,
        "profile_admitted": False,
    }
    (HERE / "probe.json").write_text(json.dumps(summaries, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
