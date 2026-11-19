#!/usr/bin/env python3
"""Writes artifacts/mdd-073/desktop-workflows.json: what was actually run for the desktop workbench, and what was not.

It re-runs the cheap checks itself (format, lint, Rust tests, front-end tests, fixture generator, boundaries) and reads
the records the expensive ones leave: the package check (verify_package.py --run-flows, which drives the real window from
the unpacked package), the mutation results, and the package checks that Actions produced for Windows and Linux.

    python artifacts/mdd-073/build_record.py [--linux PATH]
    python artifacts/mdd-073/build_record.py --check          fail if the committed record is not what this would write

Inputs, all in artifacts/mdd-073/: package-check-windows.json (this machine), mutation/results.txt, and optionally
package-check-linux.json, package-check-windows-ci.json and windows-ci-control.json (from Actions).
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


# What Actions did with this branch, kept by hand from the runs' logs (the artifacts of the last two are the
# committed package-check-*.json files). Every failing Windows run below failed the same way: all 14 runnable flows
# stopped at "no page target", because the debugging port was requested through an environment variable that
# WebView2 ignores for an elevated host process.
CI_RUNS = [
    {"run": 44289279048, "commit": "637ad09", "linux": "13 passed, 1 failed (the runner asked a dead WebDriver session for page errors after the window was killed on purpose; fixed), 1 not_run", "windows": "stopped in check_boundaries.py (cargo output decoded with the runner's cp1252 code page; fixed)"},
    {"run": 44293339284, "commit": "c77eaf5", "linux": "14 passed, 0 failed, 1 not_run", "windows": "build, tests, boundaries and packaging passed; 0 of 14 flows could open a page (environment-variable route)"},
    {"run": 44297494288, "commit": "82fefd1", "linux": "14 passed, 0 failed, 1 not_run", "windows": "0 of 14 flows; the driver's failure report added (runtime 156.0.4314.58 installed, window alive)"},
    {"run": 44302297155, "commit": "ef71c37", "linux": "14 passed, 0 failed, 1 not_run", "windows": "0 of 14 flows; no Edge policy or WEBVIEW2_* variable on the runner, nothing listening"},
    {"run": 44435988796, "commit": "292e261", "linux": "14 passed, 0 failed, 1 not_run", "windows": "0 of 14 flows; the browser process had no --remote-debugging-port among its flags"},
    {"run": 44440042565, "commit": "04c6e32", "linux": "14 passed, 0 failed, 1 not_run", "windows": "14 passed, 0 failed, 1 not_run through the machine policy route; runner image 20261116.315.1, WebView2 Runtime 157.0.4341.46; core CI passed"},
    {"run": 44444607511, "commit": "e734e7c", "linux": "14 passed, 0 failed, 1 not_run (package-check-linux.json)", "windows": "14 passed, 0 failed, 1 not_run through the machine policy route (package-check-windows-ci.json); runner image 20261103.298.1, WebView2 Runtime 156.0.4314.58; the control with the environment variable only failed (windows-ci-control.json); core CI passed"},
]


def ci_control() -> dict:
    path = HERE / "windows-ci-control.json"
    if not path.is_file():
        return {"status": "not_run", "reason": "windows-ci-control.json does not exist"}
    control = json.loads(path.read_text(encoding="utf-8"))
    return {
        "status": control["control_outcome"]["status"],
        "summary": "windows-ci-control.json",
        "run": control["source"]["run"],
        "webview2_runtime": control["runner"]["webview2_runtime"],
        "driver_process_elevated": control["runner"]["driver_process_elevated"],
        "reading": control["reading"],
    }


def case_statuses(platform: dict, ids: list[str]) -> dict:
    by_id = {r["id"]: r for r in (platform.get("results") or [])}
    return {cid: by_id.get(cid, {}).get("status", "missing") for cid in ids}


def main() -> int:
    linux_path = Path(sys.argv[sys.argv.index("--linux") + 1]) if "--linux" in sys.argv else HERE / "package-check-linux.json"
    cases = json.loads(CASES.read_text(encoding="utf-8"))
    windows = platform_record(HERE / "package-check-windows.json", "Windows")
    windows_ci = platform_record(HERE / "package-check-windows-ci.json", "Windows (CI)")
    linux = platform_record(linux_path, "Linux")

    acceptance = []
    for number, text in cases["acceptance_items"].items():
        mapped = [c["id"] for c in cases["cases"] if int(number) in c["acceptance"]]
        statuses = case_statuses(windows, mapped)
        entry = {"item": int(number), "text": text, "cases": statuses}
        if number == "5":
            entry["windows"] = windows["status"]
            entry["windows_ci"] = windows_ci["status"]
            entry["linux"] = linux["status"]
            everywhere = windows["status"] == windows_ci["status"] == linux["status"] == "passed"
            entry["status"] = "met" if everywhere else "windows_only" if windows["status"] == "passed" else "not_met"
            entry["note"] = (
                "the package is built and the flows are run from the unpacked package on Windows (this machine, and Actions) and on Linux (Actions); "
                "'met' does not mean the archives are bit-identical across machines (the local and the Actions Windows archives differ), "
                "does not cover macOS, signing or an installer, and the Windows runs use different routes to the debugging port (see not_proven)"
            )
        else:
            runnable = {k: v for k, v in statuses.items() if v != "not_run"}
            entry["status"] = "met_on_windows" if runnable and all(v == "passed" for v in runnable.values()) else "not_met"
            entry["cases_windows_ci"] = case_statuses(windows_ci, mapped)
            entry["cases_linux_ci"] = case_statuses(linux, mapped)
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
        "platforms": {
            "windows": {k: v for k, v in windows.items() if k != "results"},
            "windows_ci": {k: v for k, v in windows_ci.items() if k != "results"},
            "linux": {k: v for k, v in linux.items() if k != "results"},
        },
        "flows": {"windows": windows.get("results"), "windows_ci": windows_ci.get("results") or "not_run", "linux": linux.get("results") or "not_run"},
        "ci": {"runs": CI_RUNS, "windows_environment_variable_control": ci_control()},
        "checks": checks(),
        "mutation": mutation(),
        "not_proven": [
            "Windows: this machine (non-elevated, WebView2 Runtime 140) drives the window through the WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS variable; Actions (elevated, Runtime 156.0.4314.58 and 157.0.4341.46) through a machine policy value, because WebView2 ignores the variable for an elevated host. No single route has been run in both places; the variable route on Actions was exercised by one control flow on 156 only (it failed), never on 157",
            "Linux: one Actions environment only (ubuntu-24.04, xvfb, WebKitGTK through tauri-driver); other distributions and WebKitGTK versions are untested",
            "the archives are not bit-identical across machines: the local and the Actions Windows archives have different sha256; only the manifest's per-file hashes are claimed to be re-checkable",
            "macOS: no run, not advertised",
            "performance: none measured or claimed; MDD-082 is the gate for a performance release",
            "inputs larger than the engine's 100000-row paging window can only be compared inside a class prefix",
            "the packaged window is unsigned and has no installer or updater",
            "accessibility (keyboard-only use, screen readers) was not evaluated; the interface is Chinese only",
            "the NewPipe flow runs only where the public APK exists as a local, ignored file: it ran on this machine and is not_run on Actions, so the only end-to-end run on a real application is the local Windows one",
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
