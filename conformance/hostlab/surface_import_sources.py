#!/usr/bin/env python3
"""Copy the three HostLab sources that the frozen corpus lacks but native_surface.py needs.

conformance/corpus/hostlab/source-8782f43/ holds native_surface.py, native_audit.py and native_cli.py, but not
what they import: `surface_workers.py` (the family rules, `summarize`, `compare`), `audit_common.py` (the
resource fingerprints) and `priority_analysis.py` (`resource_changes`, `verdict`). Without them the frozen
surface scan cannot be run. This script copies them, byte for byte, from a local clone of the HostLab
repository at the pinned commit and refuses anything whose SHA-256 differs from the one recorded in the
committed evidence/hostlab_verification.json (an independent record, written long before this task).
Nothing is downloaded.

Usage:
  python -I conformance/hostlab/surface_import_sources.py --from <clone-root> [--force]
  python -I conformance/hostlab/surface_import_sources.py --check
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / "conformance/hostlab/surface-source-8782f43"
MANIFEST = DEST / "manifest.json"
COMMIT = "8782f43d537c442905123e35af325c412caa5188"
NAMES = ("surface_workers.py", "audit_common.py", "priority_analysis.py")
EVIDENCE = ROOT / "evidence/hostlab_verification.json"
ORIGIN = "https://raw.githubusercontent.com/jichuo1/innocent-lab-host-analysis/" + COMMIT + "/tools/hostlab/"


def recorded_digests() -> dict[str, str]:
    """The SHA-256 of each file as the committed evidence recorded it (two places must agree)."""
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    found: dict[str, set[str]] = {name: set() for name in NAMES}

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                short = key.rsplit("/", 1)[-1]
                if short in found and isinstance(value, str) and len(value) == 64:
                    found[short].add(value)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(evidence)
    for name, values in found.items():
        if len(values) != 1:
            raise SystemExit(f"{name}: the committed evidence names {len(values)} digests, expected exactly 1")
    return {name: next(iter(values)) for name, values in found.items()}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_manifest(files: dict[str, bytes]) -> dict:
    return {
        "schema": "mdd.hostlab-surface-source-manifest.v1",
        "commit": COMMIT,
        "about": "HostLab sources imported by the frozen native_surface.py but absent from source-8782f43/; copied "
                 "unchanged from a local clone at the pinned commit and checked against evidence/hostlab_verification.json",
        "files": [{"path": f"conformance/hostlab/surface-source-8782f43/{name}", "origin_url": ORIGIN + name,
                   "sha256": sha256(data), "bytes": len(data), "status": "obtained"} for name, data in sorted(files.items())],
    }


def check() -> int:
    recorded = recorded_digests()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    problems = []
    listed = {Path(item["path"]).name: item for item in manifest["files"]}
    if set(listed) != set(NAMES) or manifest.get("commit") != COMMIT:
        problems.append("manifest does not list exactly the three sources at the pinned commit")
    for name in NAMES:
        path = DEST / name
        if not path.is_file():
            problems.append(f"{name} is missing")
            continue
        data = path.read_bytes()
        if sha256(data) != recorded[name]:
            problems.append(f"{name}: SHA-256 differs from evidence/hostlab_verification.json")
        item = listed.get(name, {})
        if item.get("sha256") != sha256(data) or item.get("bytes") != len(data):
            problems.append(f"{name}: manifest entry differs from the file")
    for problem in problems:
        print(problem, file=sys.stderr)
    print("surface sources are current" if not problems else "surface sources are NOT current")
    return 1 if problems else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--from", dest="source", help="root of a local HostLab clone at the pinned commit")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if args.check:
        return check()
    if not args.source:
        parser.error("--from is required unless --check")
    clone = Path(args.source).resolve(strict=True)
    head = subprocess.run(["git", "-C", str(clone), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    if head != COMMIT:
        raise SystemExit(f"the clone is at {head}, not at {COMMIT}")
    recorded = recorded_digests()
    files = {}
    for name in NAMES:
        data = (clone / "tools/hostlab" / name).read_bytes()
        if sha256(data) != recorded[name]:
            raise SystemExit(f"{name}: SHA-256 {sha256(data)} differs from the committed evidence {recorded[name]}")
        files[name] = data
    if DEST.exists() and not args.force and any((DEST / name).exists() for name in NAMES):
        raise SystemExit(f"{DEST} already holds sources; pass --force to overwrite")
    DEST.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (DEST / name).write_bytes(data)
    MANIFEST.write_text(json.dumps(build_manifest(files), indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print("copied", ", ".join(NAMES))
    return check()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
