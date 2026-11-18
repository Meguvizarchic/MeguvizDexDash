#!/usr/bin/env python3
"""Checks a package made by package.py from its own manifest, then (with --run-flows) runs the real user
flows against the unpacked copy, with no MDD_ENGINE set, so the engine used is the one inside the package.

    python apps/desktop/verify_package.py ARCHIVE [--run-flows] [--record path]
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXE = ".exe" if os.name == "nt" else ""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unpack(archive: Path, into: Path) -> Path:
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as z:
            names = z.namelist()
            z.extractall(into)
    else:
        with tarfile.open(archive) as t:
            names = t.getnames()
            t.extractall(into, filter="data")
    roots = {n.split("/")[0] for n in names}
    if len(roots) != 1:
        sys.exit(f"the archive has several top-level entries: {sorted(roots)}")
    return into / roots.pop()


def main() -> int:
    archive = Path(sys.argv[1]).resolve()
    problems: list[str] = []
    record: dict = {"schema_version": "mdd.desktop-package-check.v1", "task": "MDD-073", "archive": archive.name,
                    "archive_sha256": sha256(archive), "archive_bytes": archive.stat().st_size}
    work = Path(tempfile.mkdtemp(prefix="mdd-package-check-"))
    root = unpack(archive, work)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    record["platform"] = manifest["platform"]
    record["preview"] = manifest["preview"]

    listed = {f["path"]: f for f in manifest["files"]}
    on_disk = {p.name for p in root.iterdir() if p.is_file()}
    if on_disk != set(listed) | {"manifest.json"}:
        problems.append(f"files differ from the manifest: on disk {sorted(on_disk)}, listed {sorted(listed)}")
    for name, entry in listed.items():
        path = root / name
        if not path.is_file():
            problems.append(f"{name} is listed but missing")
            continue
        if path.stat().st_size != entry["bytes"] or sha256(path) != entry["sha256"]:
            problems.append(f"{name} does not match its manifest entry")
    record["files_checked"] = len(listed)
    if manifest.get("preview") is not True:
        problems.append("the manifest does not say this is a preview")

    engine = root / f"meguvizdexdash{EXE}"
    shown = subprocess.run([str(engine), "version"], capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    if shown.returncode != 0 or json.loads(shown.stdout) != manifest["engine"]:
        problems.append("the packaged engine does not report the identity the manifest records")
    record["engine_build_id"] = manifest["engine"].get("build_id")

    if "--run-flows" in sys.argv:
        env = {k: v for k, v in os.environ.items() if k != "MDD_ENGINE"}
        env["MDD_DESKTOP_EXE"] = str(root / f"meguvizdexdash-desktop{EXE}")
        flows_record = work / "flows.json"
        done = subprocess.run(["node", str(HERE / "e2e" / "run.mjs"), "--record", str(flows_record)], env=env, cwd=HERE, check=False)
        flows = json.loads(flows_record.read_text(encoding="utf-8")) if flows_record.exists() else {}
        record["flows"] = flows.get("summary")
        record["flows_platform"] = flows.get("platform")
        record["flows_results"] = flows.get("results")
        if done.returncode != 0:
            problems.append("the user flows failed against the unpacked package")
        engine = dict(flows.get("engine") or {})
        engine_path = engine.get("binary", "")
        if not engine_path or Path(engine_path).resolve().parent != root.resolve():
            problems.append(f"the flows did not use the packaged engine: {engine_path!r}")
        elif "--record" in sys.argv:
            # the temporary folder the archive was unpacked into is a detail of this machine, not evidence
            engine["binary"] = f"<unpacked package>/{Path(engine_path).name}"
        record["flows_engine"] = engine

    record["problems"] = problems
    print(json.dumps(record, indent=2))
    if "--record" in sys.argv:
        path = Path(sys.argv[sys.argv.index("--record") + 1])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
