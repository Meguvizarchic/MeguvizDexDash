#!/usr/bin/env python3
"""Builds the portable preview package of the desktop workbench for the platform this runs on.

    python apps/desktop/package.py [--skip-build] [--out DIR]

The package is a directory made into one archive (zip on Windows, tar.gz elsewhere):

    meguvizdexdash-desktop[.exe]   the window
    meguvizdexdash[.exe]           the engine it starts (found next to it, so the package needs no setup)
    README.txt
    manifest.json                  every file's size and sha256, the compiler and lock identities, the platform

It is an unsigned preview: no installer, no updater, no code signing, and no performance claim. The archive is
written with sorted entries and fixed timestamps, so the same inputs give the same bytes; that is what lets
`verify_package.py` check it from the manifest alone.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WINDOWS = os.name == "nt"
EXE = ".exe" if WINDOWS else ""
FIXED_TIME = (2020, 1, 1, 0, 0, 0)
FIXED_EPOCH = 1577836800  # 2020-01-01T00:00:00Z

README = """MeguvizDexDash desktop workbench - FUNCTION PREVIEW

What this is
  A window over the meguvizdexdash engine: open DEX/APK inputs, see where every fact comes from, run SQL with
  honest paging, read smali and follow references, look at the manifest and resources, compare two inputs,
  and export whole results. It contains no parser or query engine of its own; it starts the engine next to it
  (meguvizdexdash) and speaks the engine's MCP protocol to it. Nothing is uploaded: the window has no network.

What this is not
  Not a release. No profile is admitted, no performance claim is made, and nothing here replaces DexSQL in HostLab.
  The package is unsigned and has no installer. See docs/adr/ADR-desktop-shell.md and tasks/backlog.json (MDD-073, MDD-082).

Run
  {run}

Needs
  {needs}

Check this package
  python apps/desktop/verify_package.py <this archive>     (from the source repository)
  Every file's size and sha256 is in manifest.json.
"""

RUN = {
    "windows": "meguvizdexdash-desktop.exe",
    "linux": "./meguvizdexdash-desktop",
}
NEEDS = {
    "windows": "The Microsoft Edge WebView2 Runtime (part of Windows 11 and current Windows 10).",
    "linux": "GTK 3 and WebKitGTK 4.1 (apt: libwebkit2gtk-4.1-0 libgtk-3-0).",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def run(*args: str, cwd: Path) -> str:
    done = subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    if done.returncode != 0:
        sys.exit(f"{' '.join(args)} failed in {cwd}:\n{done.stdout}\n{done.stderr}")
    return done.stdout.strip()


def os_name() -> str:
    return "windows" if WINDOWS else platform.system().lower()


def arch_name() -> str:
    machine = platform.machine().lower()
    return {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}.get(machine, machine)


def version() -> str:
    for line in (HERE / "Cargo.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("version"):
            return line.split('"')[1]
    raise SystemExit("no version in Cargo.toml")


def build() -> None:
    print("building the engine (release)...", flush=True)
    run("cargo", "build", "--locked", "--release", "-p", "mdd-cli", cwd=ROOT)
    print("building the window (release)...", flush=True)
    run("cargo", "build", "--locked", "--release", cwd=HERE)


def git_state() -> dict:
    try:
        commit = run("git", "rev-parse", "HEAD", cwd=ROOT)
        dirty = bool(run("git", "status", "--porcelain", "--untracked-files=no", cwd=ROOT))
        return {"commit": commit, "tracked_files_modified": dirty}
    except SystemExit:
        return {"commit": None, "tracked_files_modified": None}


def main() -> int:
    out = Path(sys.argv[sys.argv.index("--out") + 1]) if "--out" in sys.argv else HERE / "dist"
    if "--skip-build" not in sys.argv:
        build()
    app = HERE / "target" / "release" / f"mdd-desktop{EXE}"
    engine = ROOT / "target" / "release" / f"meguvizdexdash{EXE}"
    for path in (app, engine):
        if not path.is_file():
            sys.exit(f"missing {path}: build first (omit --skip-build)")
    system = os_name()
    name = f"meguvizdexdash-desktop-preview-{version()}-{system}-{arch_name()}"
    stage = out / name
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    shutil.copyfile(app, stage / f"meguvizdexdash-desktop{EXE}")
    shutil.copyfile(engine, stage / f"meguvizdexdash{EXE}")
    (stage / "README.txt").write_text(README.format(run=RUN.get(system, "meguvizdexdash-desktop"), needs=NEEDS.get(system, "")), encoding="utf-8", newline="\n")
    if not WINDOWS:
        for executable in ("meguvizdexdash-desktop", "meguvizdexdash"):
            (stage / executable).chmod(0o755)

    engine_version = json.loads(run(str(stage / f"meguvizdexdash{EXE}"), "version", cwd=stage))
    files = [
        {"path": p.name, "bytes": p.stat().st_size, "sha256": sha256(p)}
        for p in sorted(stage.iterdir())
        if p.is_file()
    ]
    manifest = {
        "schema_version": "mdd.desktop-package.v1",
        "product": "MeguvizDexDash desktop workbench",
        "version": version(),
        "preview": True,
        "preview_meaning": "function preview: no profile admitted, no performance claim, unsigned, no installer",
        "platform": {"os": system, "arch": arch_name()},
        "requirements": NEEDS.get(system, ""),
        "engine": engine_version,
        "built_with": {
            "rustc": run("rustc", "-V", cwd=ROOT),
            "cargo": run("cargo", "-V", cwd=ROOT),
            "desktop_cargo_lock_sha256": sha256(HERE / "Cargo.lock"),
            "engine_cargo_lock_sha256": sha256(ROOT / "Cargo.lock"),
            "source": git_state(),
        },
        "files": files,
    }
    (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")

    members = sorted(p for p in stage.iterdir() if p.is_file())
    if WINDOWS:
        archive = out / f"{name}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for path in members:
                info = zipfile.ZipInfo(f"{name}/{path.name}", FIXED_TIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o755 if path.suffix == ".exe" else 0o644) << 16
                z.writestr(info, path.read_bytes())
    else:
        archive = out / f"{name}.tar.gz"
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for path in members:
                info = tarfile.TarInfo(f"{name}/{path.name}")
                info.size = path.stat().st_size
                info.mtime = FIXED_EPOCH
                info.mode = 0o755 if path.name in ("meguvizdexdash-desktop", "meguvizdexdash") else 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                tar.addfile(info, io.BytesIO(path.read_bytes()))
        with archive.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, compresslevel=9) as gz:
            gz.write(buffer.getvalue())
    print(json.dumps({"archive": str(archive), "bytes": archive.stat().st_size, "sha256": sha256(archive), "files": files}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
