"""HostLab's independent Python gates (intake, home), run unchanged and timed whole (MDD-052).

In HostLab, `analyze.py` runs `run_intake.py` and `home_frame_audit.py` as separate Python processes after the native audit.
They read the APK again themselves. M5 keeps them exactly so; sharing the engine's facts with them is HL-12, a later step
that is not implemented, so nothing here credits any saving for it.

* `run_gate` starts the command exactly as given (no argument, directory or environment of its own), and the clock runs from
  before the process is started until it has ended and its output has been read: start-up, the work, and teardown.
* A gate that fails, or that is stopped at its time limit, is recorded as that; it is never dropped from the total.
* If the gate's script is given, its SHA-256 must be the pinned one before it runs and the same after: a gate that is not the
  recorded one, or that changes while it runs, is refused.
* `accounting` adds the surface time and every gate's full time. It has no place for a reuse saving, and refuses one.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

ROOT = Path(__file__).resolve().parents[2]
ACCOUNTING_SCHEMA = "mdd.hostlab-surface-gate-accounting.v1"
# The gates of HostLab at the pinned commit, by the path HostLab records for them in evidence/hostlab_verification.json.
GATES = {"intake": "analysis/run_intake.py", "home": "analysis/home_frame_audit.py"}
# What HostLab accepts from each (analyze.py): intake exits 0 or 1, home exits 0.
ACCEPTED_EXIT = {"intake": (0, 1), "home": (0,)}


class GateChanged(RuntimeError):
    """The script that was to run (or ran) is not the pinned one."""


def sha256_file(path: "str | Path") -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def pinned_digests(evidence: "Path | None" = None) -> dict[str, str]:
    """SHA-256 of the two gate scripts, from the committed evidence/hostlab_verification.json (where all three places that name
    a gate must agree)."""
    document = json.loads((evidence or ROOT / "evidence/hostlab_verification.json").read_text(encoding="utf-8"))
    found: dict[str, set[str]] = {name: set() for name in GATES}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                for name, relative in GATES.items():
                    if isinstance(value, str) and len(value) == 64 and (key == relative or key.endswith("/" + relative)):
                        found[name].add(value)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(document)
    bad = {name: sorted(values) for name, values in found.items() if len(values) != 1}
    if bad:
        raise ValueError(f"the evidence does not name exactly one digest for: {bad}")
    return {name: next(iter(values)) for name, values in found.items()}


def hostlab_argv(name: str, sandbox: "str | Path", apk: "str | Path", *, tsv: "str | Path | None" = None, python: str = sys.executable) -> list[str]:
    """The command line analyze.py uses for a gate: the interpreter, the script in the sandbox copy of the suite, the APK."""
    if name == "intake":
        if tsv is None:
            raise ValueError("the intake gate takes --tsv")
        return [python, str(Path(sandbox) / "run_intake.py"), str(apk), "--tsv", str(tsv)]
    if name == "home":
        return [python, str(Path(sandbox) / "home_frame_audit.py"), str(apk)]
    raise ValueError(f"unknown gate {name!r}")


@dataclass(frozen=True)
class GateRun:
    name: str
    argv: tuple[str, ...]
    exit_code: "int | None"
    timed_out: bool
    seconds: float
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int
    script_sha256: "str | None"

    @property
    def finished(self) -> bool:
        return not self.timed_out and self.exit_code is not None

    def accepted(self) -> bool:
        """HostLab's own acceptance of the exit status; a gate that did not finish is never accepted."""
        return self.finished and self.exit_code in ACCEPTED_EXIT.get(self.name, (0,))

    def record(self) -> dict[str, Any]:
        return dict(asdict(self), argv=list(self.argv), accepted=self.accepted())


def run_gate(name: str, argv: Sequence[str], *, script: "str | Path | None" = None, expected_script_sha256: "str | None" = None,
             cwd: "str | Path | None" = None, env: "dict | None" = None, timeout: float = 3600.0,
             clock: Callable[[], float] = time.monotonic, log_dir: "str | Path | None" = None) -> GateRun:
    """Run `argv` unchanged and time it from before the start to after the end, output read."""
    before = sha256_file(script) if script is not None else None
    if expected_script_sha256 is not None and before != expected_script_sha256:
        raise GateChanged(f"{name}: the gate script is {before}, not the pinned {expected_script_sha256}")
    started = clock()
    timed_out = False
    try:
        done = subprocess.run(list(argv), cwd=None if cwd is None else str(cwd), env=env, capture_output=True, timeout=timeout)
        exit_code, out, err = done.returncode, done.stdout, done.stderr
    except subprocess.TimeoutExpired as expired:
        timed_out, exit_code, out, err = True, None, expired.stdout or b"", expired.stderr or b""
    seconds = clock() - started
    after = sha256_file(script) if script is not None else None
    if after != before:
        raise GateChanged(f"{name}: the gate script changed while it ran")
    if log_dir is not None:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        (Path(log_dir) / f"{name}.stdout.log").write_bytes(out)
        (Path(log_dir) / f"{name}.stderr.log").write_bytes(err)
    return GateRun(name, tuple(map(str, argv)), exit_code, timed_out, seconds, hashlib.sha256(out).hexdigest(),
                   hashlib.sha256(err).hexdigest(), len(out), len(err), before)


def accounting(surface_seconds: float, gates: Sequence[GateRun], *, gate_reuse_benefit_seconds: float = 0.0) -> dict[str, Any]:
    """The surface time and every gate's full time, added. A reuse saving is refused: HL-12 is not implemented."""
    if gate_reuse_benefit_seconds != 0:
        raise ValueError("M5 does not pre-count a benefit of gate reuse: it is not implemented (HL-12)")
    if surface_seconds < 0 or any(g.seconds < 0 for g in gates):
        raise ValueError("a duration cannot be negative")
    gate_seconds = sum(g.seconds for g in gates)
    return {"schema": ACCOUNTING_SCHEMA, "surface_seconds": surface_seconds, "gate_seconds": gate_seconds,
            "total_seconds": surface_seconds + gate_seconds, "gates": [g.record() for g in gates],
            "all_gates_finished": all(g.finished for g in gates), "all_gates_accepted": all(g.accepted() for g in gates),
            "gate_reuse": {"status": "not_implemented", "task": "HL-12", "benefit_seconds_counted": 0.0}}
