#!/usr/bin/env python3
"""Compile the repository's conformance probes unmodified and run them.

The probe sources are read-only references.  This driver only compiles them
against the current Cargo artifacts and records the raw process terminals in
the evidence directory.  It never edits conformance/ or crates/.
"""
from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
NATIVE = HERE / "native"
PROBES = {
    "native_probe": "conformance/facts/native_probe.rs",
    "definition_projection_probe": "conformance/facts/definition_projection_probe.rs",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(label, argv, folder):
    folder.mkdir(parents=True, exist_ok=False)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    timer = time.monotonic()
    process = subprocess.run([str(item) for item in argv], cwd=ROOT, capture_output=True, timeout=300)
    (folder / "stdout.txt").write_bytes(process.stdout)
    (folder / "stderr.txt").write_bytes(process.stderr)
    record = {
        "argv": [str(item) for item in argv],
        "started_utc": started,
        "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "elapsed_seconds": time.monotonic() - timer,
        "exit_code": process.returncode,
        "stdout_sha256": hashlib.sha256(process.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(process.stderr).hexdigest(),
        "scope": "tiny synthetic conformance probe; not performance",
    }
    (folder / "record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    require(process.returncode == 0, label + " failed; raw output retained")
    return process.stdout


def main():
    NATIVE.mkdir(parents=True, exist_ok=True)
    build_output = run("cargo-build", ["cargo", "build", "-p", "mdd-facts", "--lib", "--jobs", "1",
                                       "--locked", "--offline", "--message-format=json"],
                       NATIVE / "cargo-build")
    libraries = {}
    for line in build_output.decode("utf-8", "replace").splitlines():
        item = json.loads(line)
        if item.get("reason") == "compiler-artifact":
            files = [name for name in item.get("filenames", []) if name.endswith(".rlib")]
            if len(files) == 1:
                libraries[item["target"]["name"]] = files[0]
    require({"mdd_dex", "mdd_facts", "mdd_input", "mdd_types", "serde_json"} <= set(libraries),
            "missing Cargo artifacts: " + repr(sorted(libraries)))
    binaries = {}
    for name, source in PROBES.items():
        executable = NATIVE / (name + ".exe")
        argv = ["rustc", "--edition=2024", "--crate-name", "mdd_evidence_" + name,
                source, "-L", "dependency=target/debug/deps", "-o", executable]
        for crate in ["mdd_dex", "mdd_facts", "mdd_input", "mdd_types", "serde_json"]:
            argv += ["--extern", crate + "=" + libraries[crate]]
        run("compile-" + name, argv, NATIVE / ("compile-" + name))
        binaries[name] = executable
    fixtures = {
        "members-dup": HERE / "fixtures/members-dup-035.dex",
        "classic": ROOT / "tests/fixtures/references/generated/classic-035.dex",
        "definitions": ROOT / "tests/fixtures/definitions/generated/definitions-035.dex",
    }
    for name, path in fixtures.items():
        require(path.is_file(), "missing fixture " + name)
    # General probe: members-dup and classic in one multi-input invocation.
    run("native-general-members-dup-classic",
        [binaries["native_probe"], fixtures["members-dup"], fixtures["classic"]],
        NATIVE / "native-general-members-dup-classic")
    # Definition probe: members-dup and definitions, one invocation each (the
    # probe captures its single argument twice and numbers file_id 0/1).
    run("native-definitions-members-dup",
        [binaries["definition_projection_probe"], fixtures["members-dup"]],
        NATIVE / "native-definitions-members-dup")
    run("native-definitions-definitions",
        [binaries["definition_projection_probe"], fixtures["definitions"]],
        NATIVE / "native-definitions-definitions")
    report = {
        "schema_version": "mdd.member-evidence-native-run.v1",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "task_complete_proven": False,
        "profile_admitted": False,
        "probe_sources": {name: {"path": source, "sha256": digest(ROOT / source)}
                          for name, source in PROBES.items()},
        "binaries": {name: {"path": str(path.relative_to(HERE)), "sha256": digest(path)}
                     for name, path in binaries.items()},
        "fixtures": {name: {"path": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
                            "sha256": digest(path)} for name, path in fixtures.items()},
        "libraries": libraries,
        "limits": [
            "The probes are the repository's conformance probes, compiled unmodified.",
            "Agreement with the independent Python oracle is evidence, not a task gate.",
        ],
    }
    (NATIVE / "run-record.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"binaries": {k: v["sha256"] for k, v in report["binaries"].items()},
                      "fixtures": {k: v["sha256"] for k, v in report["fixtures"].items()}}))


if __name__ == "__main__":
    main()
