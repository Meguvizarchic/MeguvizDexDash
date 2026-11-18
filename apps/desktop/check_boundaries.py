#!/usr/bin/env python3
"""Checks what the desktop workbench is allowed to be made of.

  1. It holds no second core: none of its dependencies is an `mdd-*` crate. The engine is reached only
     through the `meguvizdexdash mcp` process.
  2. It opens no network by itself: on the release platforms (Windows, Linux, macOS) its dependency graph
     contains no HTTP client crate.
  3. Its window is granted no file-system, shell, HTTP or opener permission, and its Content-Security-Policy
     allows no connection but the shell's own IPC.

    python apps/desktop/check_boundaries.py [--record path]
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HTTP_CLIENT_CRATES = ["reqwest", "hyper", "ureq", "isahc", "surf", "attohttpc", "curl"]
TARGETS = ["x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu", "aarch64-apple-darwin"]
FORBIDDEN_PERMISSIONS = ("fs:", "shell:", "http:", "opener:", "process:", "os:", "updater:")


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=HERE, capture_output=True, text=True, check=False)


def in_graph(crate: str, target: str) -> bool:
    out = run("cargo", "tree", "--locked", "--target", target, "-i", crate)
    # cargo prints the package id as the first line when the crate is in the graph
    return out.returncode == 0 and out.stdout.lstrip().startswith(crate + " v")


def main() -> int:
    problems: list[str] = []
    record: dict = {"schema_version": "mdd.desktop-boundaries.v1", "task": "MDD-073"}

    meta = json.loads(run("cargo", "metadata", "--locked", "--format-version", "1", "--no-deps").stdout)
    package = next(p for p in meta["packages"] if p["name"] == "mdd-desktop")
    deps = sorted(d["name"] for d in package["dependencies"])
    record["direct_dependencies"] = deps
    core = [d for d in deps if d.startswith("mdd-")]
    if core:
        problems.append(f"the workbench depends on core crates: {core}")
    record["core_crates_linked"] = core

    full = json.loads(run("cargo", "metadata", "--locked", "--format-version", "1").stdout)
    names = {p["name"] for p in full["packages"]}
    record["resolved_packages"] = len(names)
    record["tauri_versions"] = sorted({p["version"] for p in full["packages"] if p["name"] in ("tauri", "tauri-plugin-dialog", "wry", "tao")})

    record["http_clients_in_graph"] = {}
    for target in TARGETS:
        found = [c for c in HTTP_CLIENT_CRATES if in_graph(c, target)]
        record["http_clients_in_graph"][target] = found
        if found:
            problems.append(f"{target}: HTTP client crates in the dependency graph: {found}")

    capability = json.loads((HERE / "capabilities" / "default.json").read_text(encoding="utf-8"))
    record["window_permissions"] = capability["permissions"]
    bad = [p for p in capability["permissions"] if p.startswith(FORBIDDEN_PERMISSIONS)]
    if bad:
        problems.append(f"the window is granted {bad}")

    config = json.loads((HERE / "tauri.conf.json").read_text(encoding="utf-8"))
    csp = config["app"]["security"]["csp"]
    record["csp"] = csp
    directives = {part.split()[0]: part.split()[1:] for part in (x.strip() for x in csp.split(";")) if part}
    if directives.get("default-src") != ["'none'"]:
        problems.append("the CSP's default-src is not 'none'")
    allowed = set(directives.get("connect-src", []))
    if not allowed <= {"ipc:", "http://ipc.localhost"}:
        problems.append(f"the CSP allows connections beyond the shell's IPC: {sorted(allowed)}")
    if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
        problems.append("the CSP allows inline or eval scripts or styles")

    record["problems"] = problems
    print(json.dumps(record, indent=2))
    if "--record" in sys.argv:
        path = Path(sys.argv[sys.argv.index("--record") + 1])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")
    if problems:
        print("\nBOUNDARY PROBLEMS:", *problems, sep="\n  ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
