#!/usr/bin/env python3
"""Writes artifacts/mdd-073/desktop-workflows.json: what was actually run for the desktop workbench, and what was not.

It re-runs the cheap checks itself (format, lint, Rust tests, front-end tests, fixture generator, boundaries) and reads
the records the expensive ones leave: the package check (verify_package.py --run-flows, which drives the real window from
the unpacked package), the mutation results, and, when CI has produced one, the Linux package check.

    python artifacts/mdd-073/build_record.py [--linux PATH]
    python artifacts/mdd-073/build_record.py --check          fail if the committed record is not what this would write

Inputs, all in artifacts/mdd-073/: package-check-windows.json, mutation/results.txt, optionally package-check-linux.json.
A record that is missing is said to be missing in the output; nothing is filled in.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DESKTOP = ROOT / "apps" / "desktop"
OUT = HERE / "desktop-workflows.json"
CASES = ROOT / "conformance" / "desktop" / "user-flow-cases.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command: list[str], cwd: Path) -> tuple[int, str]:
    done = subprocess.run(command, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    return done.returncode, done.stdout + done.stderr


def counts(output: str, pattern: str) -> list[int]:
    return [int(n) for n in re.findall(pattern, output)]


def checks() -> dict:
    out: dict = {}
    code, text = run(["cargo", "fmt", "--check"], DESKTOP)
    out["rustfmt"] = {"command": "cargo fmt --check (apps/desktop)", "passed": code == 0}
    code, text = run(["cargo", "clippy", "--locked", "--all-targets", "--", "-D", "warnings"], DESKTOP)
    out["clippy"] = {"command": "cargo clippy --locked --all-targets -- -D warnings (apps/desktop)", "passed": code == 0}
    code, text = run(["cargo", "test", "--locked", "--", "--test-threads=3"], DESKTOP)
    suites = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed", text)
    out["rust_tests"] = {
        "command": "cargo test --locked (apps/desktop): unit tests, and the shell and the comparison against the real engine process",
        "passed": code == 0,
        "suites": len(suites),
        "tests_passed": sum(int(done) for done, _ in suites),
        "tests_failed": sum(int(failed) for _, failed in suites) if suites else None,
    }
    code, text = run(["node", "--test", *sorted(str(p) for p in (DESKTOP / "ui-tests").glob("*.test.mjs"))], DESKTOP)
    passed = counts(text, r"ℹ pass (\d+)")
    out["frontend_tests"] = {
        "command": "node --test ui-tests/*.test.mjs (apps/desktop)",
        "passed": code == 0,
        "tests_passed": passed[0] if passed else 0,
    }
    code, text = run([sys.executable, str(ROOT / "tests" / "fixtures" / "desktop" / "generate.py"), "--check"], ROOT)
    out["fixtures"] = {"command": "tests/fixtures/desktop/generate.py --check", "passed": code == 0}
    boundary = HERE / "boundaries.json"
    code, text = run([sys.executable, str(DESKTOP / "check_boundaries.py"), "--record", str(boundary)], DESKTOP)
    out["boundaries"] = {"command": "apps/desktop/check_boundaries.py", "passed": code == 0, **json.loads(boundary.read_text(encoding="utf-8"))}
    return out


def mutation() -> dict:
    path = HERE / "mutation" / "results.txt"
    if not path.is_file():
        return {"status": "not_run", "reason": "artifacts/mdd-073/mutation/results.txt is missing"}
    text = path.read_text(encoding="utf-8")
    spec = importlib.util.spec_from_file_location("mutate_desktop", HERE / "mutation" / "mutate_desktop.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    recorded = re.search(r"sources sha256: ([0-9a-f]{64})", text)
    summary = re.search(r"mutants: (\d+)  killed: (\d+)  survived: (\d+)  invalid: (\d+)", text)
    current = module.sources_hash()
    return {
        "status": "current" if recorded and recorded.group(1) == current else "stale",
        "harness": "artifacts/mdd-073/mutation/mutate_desktop.py",
        "results": "artifacts/mdd-073/mutation/results.txt",
        "mutants": int(summary.group(1)) if summary else None,
        "killed": int(summary.group(2)) if summary else None,
        "survived": int(summary.group(3)) if summary else None,
        "invalid": int(summary.group(4)) if summary else None,
        "clean_tree_passes_before_and_after": all(
            "cargo test: passes" in part and "node --test: passes" in part
            for part in (
                text.split("clean tree, after the variants")[0],
                text.split("clean tree, after the variants")[-1],
            )
        )
        and "clean tree, before the variants" in text
        and "clean tree, after the variants" in text,
        "sources_sha256_recorded": recorded.group(1) if recorded else None,
        "sources_sha256_now": current,
        "not_covered": "the real-window user flows are not part of the mutation check (too slow per mutant); the check covers the Rust and front-end logic they rest on",
    }


def platform_record(path: Path, label: str) -> dict:
    if not path.is_file():
        return {
            "status": "not_run",
            "reason": f"{path.name} does not exist: no {label} run of the packaged window has been recorded",
        }
    record = json.loads(path.read_text(encoding="utf-8"))
    flows = record.get("flows") or {}
    return {
        "status": "passed" if not record.get("problems") and flows.get("failed") == 0 and flows.get("passed", 0) > 0 else "failed",
        "package": {k: record.get(k) for k in ("archive", "archive_sha256", "archive_bytes", "files_checked", "engine_build_id", "preview")},
        "driver": (record.get("flows_platform") or {}).get("driver"),
        "webview": (record.get("flows_platform") or {}).get("webview"),
        "flows": flows,
        "engine_used": record.get("flows_engine"),
        "problems": record.get("problems"),
        "results": record.get("flows_results"),
    }


def main() -> int:
    linux_path = Path(sys.argv[sys.argv.index("--linux") + 1]) if "--linux" in sys.argv else HERE / "package-check-linux.json"
    cases = json.loads(CASES.read_text(encoding="utf-8"))
    windows = platform_record(HERE / "package-check-windows.json", "Windows")
    linux = platform_record(linux_path, "Linux")
    by_id = {r["id"]: r for r in (windows.get("results") or [])}

    acceptance = []
    for number, text in cases["acceptance_items"].items():
        mapped = [c["id"] for c in cases["cases"] if int(number) in c["acceptance"]]
        statuses = {cid: by_id.get(cid, {}).get("status", "missing") for cid in mapped}
        entry = {"item": int(number), "text": text, "cases": statuses}
        if number == "5":
            entry["windows"] = windows["status"]
            entry["linux"] = linux["status"]
            entry["status"] = "met" if windows["status"] == linux["status"] == "passed" else "windows_only" if windows["status"] == "passed" else "not_met"
            entry["note"] = "package and unpacked-package flows on each platform; Linux only counts once CI has run them"
        else:
            runnable = {k: v for k, v in statuses.items() if v != "not_run"}
            entry["status"] = "met_on_windows" if runnable and all(v == "passed" for v in runnable.values()) else "not_met"
        acceptance.append(entry)

    record = {
        "schema_version": "mdd.desktop-workflows.v1",
        "task": "MDD-073",
        "scope": "development evidence for a function preview of the desktop workbench; nothing is admitted and no performance claim is made",
        "shell": "Tauri 2 with a static HTML/JS front end (docs/adr/ADR-desktop-shell.md); the engine is reached only through the meguvizdexdash mcp process",
        "sources": {
            "user_flow_cases_sha256": sha256(CASES),
            "desktop_cargo_lock_sha256": sha256(DESKTOP / "Cargo.lock"),
            "adr": "docs/adr/ADR-desktop-shell.md",
        },
        "acceptance": acceptance,
        "platforms": {"windows": {k: v for k, v in windows.items() if k != "results"}, "linux": {k: v for k, v in linux.items() if k != "results"}},
        "flows": {"windows": windows.get("results"), "linux": linux.get("results") or "not_run"},
        "checks": checks(),
        "mutation": mutation(),
        "not_proven": [
            "Linux: no run of the packaged window exists until CI produces package-check-linux.json; nothing is inferred from Windows",
            "macOS: no run, not advertised",
            "performance: none measured or claimed; MDD-082 is the gate for a performance release",
            "inputs larger than the engine's 100000-row paging window can only be compared inside a class prefix",
            "the packaged window is unsigned and has no installer or updater",
            "accessibility (keyboard-only use, screen readers) was not evaluated; the interface is Chinese only",
            "the NewPipe flow runs only where the public APK exists as a local, ignored file; elsewhere it is not_run",
            "the native open/save dialogs are not driven by the flows (they type paths instead); they are only known to compile and to be reachable from the window's commands",
            "dropping files onto the window is not implemented",
        ],
    }
    text = json.dumps(record, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if not OUT.is_file():
            print("no committed record")
            return 1
        committed = json.loads(OUT.read_text(encoding="utf-8"))
        same = committed == json.loads(text)
        print("the committed record is current" if same else "the committed record differs from what this would write")
        return 0 if same else 1
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(ROOT)}: " + ", ".join(f"item {a['item']} {a['status']}" for a in acceptance))
    return 0


if __name__ == "__main__":
    sys.exit(main())
