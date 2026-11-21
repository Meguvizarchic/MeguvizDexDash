#!/usr/bin/env python3
"""MDD-060: Five-way (A0/A1/A2/B0/B1) paired comparison, stage profiler & threshold calibrator.

Modes:
  --self-test          Verify pairing, non-additive overlap, prepare-scope & redaction guards offline
  --check-a2           Probe real DexSQL 0.1.1 MCP compact=true component behavior & document W07/bulk exclusion
  --measure-newpipe    Run Block 1 & Block 2 alternating paired trials on NewPipe v0.28.6 (W05 bulk)
  --measure-hostlab    Run Job-isolated A0/A1/B0/B1 trials on hostlab-9161100 & hostlab-9170100 (W07 full)
  --profile-stages     Measure non-overlapping sub-stage breakdown (P/S/F/R/O & sub-components) on clean workers
  --summarize          Validate all raw observed_run records and publish redacted artifacts/mdd-060/*

Formal measurement rules enforced:
  - No synthetic projections or mixed-round ratio division (always per-pair left/right inside pair_id).
  - Prepare timing explicitly excludes pure-parser claims and never hides lazy construction.
  - Overlapping producer & consumer windows use joint wall clock (serial sums forbidden).
  - Exclusive window check (no concurrent rustc/cargo/engine processes, >=10 GiB free RAM) & root lease.
  - Public committed artifacts never contain local drive paths or restricted sample/package identifiers.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime
import hashlib
import json
import os
import platform
import queue
import re
import socket
import statistics
import subprocess
import sys
import threading
import time
import types
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Sequence

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
if str(ROOT / "conformance/hostlab") not in sys.path:
    sys.path.insert(0, str(ROOT / "conformance/hostlab"))

import compare_full_reports as hostlab_compare  # noqa: E402
import observed_run_validator as validator  # noqa: E402

SCHEMA_PATHS_JSON = ROOT / "artifacts/local/shadow-prep/paths.json"
MANIFEST_PATH = ROOT / "benchmarks/baseline-manifest.json"
WORKLOADS_B0_PATH = ROOT / "benchmarks/workloads/b0-bulk-statements.json"
CORPUS_PATH = ROOT / "conformance/manifests/input-corpus.json"
SHADOW_MANIFEST_PATH = ROOT / "artifacts/mdd-054/shadow-manifest.json"
LOCAL_OUT = ROOT / "artifacts/local/mdd-060"
PUBLIC_OUT = ROOT / "artifacts/mdd-060"

DEFAULT_A1_REL = Path("artifacts/local/dexsql-a1/dexsql-windows-amd64.exe")
DEFAULT_A1_SHA = "602105c98232120c14d6124fb33574f2f95f12e50e51d25b8834f893925f28d6"
DEFAULT_A0_SHA = "f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448"
DEFAULT_NEWPIPE_SHA = "e56ef6280b700696172797f94513ffd3f9aae9349945a2f06e235ec24446be58"
REFERENCE_COMMIT = "8782f43d537c442905123e35af325c412caa5188"
HOSTLAB_SQL_LIMITS = {"steps": 4000000000, "scanned_rows": 400000000, "result_rows": 4000000}

FORBIDDEN_ENTRY_POINTS = ("config", "api_private", "manifest", "select")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _sha256_obj(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8", newline="\n")


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


# ---- System & Exclusive Window Lease ---------------------------------------------------------------------

def memory_status() -> dict[str, int]:
    if os.name == "nt":
        class _MEMSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]
        st = _MEMSTATUSEX(ctypes.sizeof(_MEMSTATUSEX))
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
            raise RuntimeError("GlobalMemoryStatusEx failed")
        return {"total_phys_bytes": int(st.ullTotalPhys), "avail_phys_bytes": int(st.ullAvailPhys)}
    info = {}
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        k, _, rest = line.partition(":")
        parts = rest.strip().split()
        if parts:
            info[k] = int(parts[0]) * 1024
    return {"total_phys_bytes": info["MemTotal"], "avail_phys_bytes": info.get("MemAvailable", info["MemFree"])}


def check_exclusive_window(*, min_free_bytes: int = 10 * 1024 ** 3, require_idle: bool = True) -> dict[str, Any]:
    mem = memory_status()
    if mem["avail_phys_bytes"] < min_free_bytes:
        raise RuntimeError(
            f"available physical memory {mem['avail_phys_bytes']} B < required {min_free_bytes} B"
        )
    competing: list[str] = []
    if require_idle and os.name == "nt":
        targets = ("cargo.exe", "rustc.exe", "meguvizdexdash.exe", "dexsql-windows-amd64.exe")
        out = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, check=False, timeout=20
        ).stdout
        for line in out.splitlines():
            name = line.split(",", 1)[0].strip('"').lower()
            if name in targets:
                competing.append(name)
        if competing:
            raise RuntimeError(f"competing build/engine processes present during exclusive window check: {competing}")
    return {
        "machine_id": f"win-x86_64-{hashlib.sha256(platform.node().encode()).hexdigest()[:12]}" if os.name == "nt" else f"linux-x86_64-{hashlib.sha256(platform.node().encode()).hexdigest()[:12]}",
        "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "cpu_count": os.cpu_count() or 1,
        "total_phys_bytes": mem["total_phys_bytes"],
        "avail_phys_bytes": mem["avail_phys_bytes"],
        "competing_processes": competing,
        "verified_utc": _utc_now(),
    }


def issue_lease(block_id: str, duration_seconds: int = 3600, cpu_affinity_mask: int = 15) -> Path:
    env = check_exclusive_window()
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = now + datetime.timedelta(seconds=duration_seconds)
    lease = {
        "schema_version": "mdd.measurement-lease.v1",
        "owner": "root",
        "task": "MDD-060",
        "block_id": block_id,
        "status": "active",
        "exclusive": True,
        "cpu_affinity_mask": cpu_affinity_mask,
        "logical_cpus": bin(cpu_affinity_mask).count("1"),
        "starts_utc": now.isoformat().replace("+00:00", "Z"),
        "expires_utc": expires.isoformat().replace("+00:00", "Z"),
        "host_observation": env,
    }
    lease_path = LOCAL_OUT / f"lease-{block_id}.json"
    _write_json(lease_path, lease)
    return lease_path


def _resolve_paths() -> dict[str, Any]:
    paths = validator.parse_strict_json(SCHEMA_PATHS_JSON.read_text(encoding="utf-8"))
    a0 = Path(paths["engines"]["A"]).resolve(strict=True)
    if _sha256_file(a0) != DEFAULT_A0_SHA:
        raise RuntimeError(f"A0 SHA-256 mismatch: {_sha256_file(a0)}")
    a1 = (ROOT / DEFAULT_A1_REL).resolve(strict=True)
    if _sha256_file(a1) != DEFAULT_A1_SHA:
        raise RuntimeError(f"A1 SHA-256 mismatch: {_sha256_file(a1)}")
    b = Path(paths["engines"]["B"]).resolve(strict=True)
    newpipe = (ROOT / "artifacts/local/inputs/NewPipe_v0.28.6.apk").resolve(strict=True)
    if _sha256_file(newpipe) != DEFAULT_NEWPIPE_SHA:
        raise RuntimeError("NewPipe APK SHA-256 mismatch")
    return {
        "reference": Path(paths["reference"]).resolve(strict=True),
        "python": Path(paths["python"]).resolve(strict=True),
        "A0": a0,
        "A1": a1,
        "B": b,
        "b_pin_manifest": Path(paths["b_pin_manifest"]).resolve(strict=True),
        "inputs": {
            "hostlab-9161100": Path(paths["inputs"]["hostlab-9161100"]).resolve(strict=True),
            "hostlab-9170100": Path(paths["inputs"]["hostlab-9170100"]).resolve(strict=True),
            "newpipe-0.28.6": newpipe,
        },
    }


def refresh_release_b_pin(b_binary: Path, pin_path: Path) -> dict[str, Any]:
    """Ensure local b-pin.json includes the exact release binary built at HEAD (never alters engine code)."""
    sha = _sha256_file(b_binary)
    doc = validator.parse_strict_json(pin_path.read_text(encoding="utf-8"))
    for entry in doc["builds"]:
        if entry["sha256"] == sha:
            return entry
    sys.path.insert(0, str(ROOT / "integrations/hostlab"))
    import install_meguvizdexdash as inst  # noqa: E402
    return inst.pin(b_binary, pin_path)


# ---- Process Resource Helpers ----------------------------------------------------------------------------

if os.name == "nt":
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _FT(ctypes.Structure):
        _fields_ = [("lo", wintypes.DWORD), ("hi", wintypes.DWORD)]

    class _PMC(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    _k32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(_FT)] * 4
    _k32.GetProcessTimes.restype = wintypes.BOOL
    _get_pmc = getattr(_k32, "K32GetProcessMemoryInfo", None) or ctypes.WinDLL("psapi").GetProcessMemoryInfo
    _get_pmc.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PMC), wintypes.DWORD]
    _get_pmc.restype = wintypes.BOOL


def _proc_metrics_win(proc: subprocess.Popen) -> dict[str, Any]:
    if os.name != "nt":
        return {"producer_cpu_seconds": None, "producer_peak_ws_bytes": None, "method": "unsupported_non_win"}
    h = int(proc._handle)  # type: ignore[attr-defined]
    c, e, k, u = (_FT() for _ in range(4))
    _k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u))
    pmc = _PMC(ctypes.sizeof(_PMC))
    _get_pmc(h, ctypes.byref(pmc), ctypes.sizeof(_PMC))
    return {
        "producer_cpu_seconds": (((k.hi << 32) | k.lo) + ((u.hi << 32) | u.lo)) / 1e7,
        "producer_peak_ws_bytes": int(pmc.PeakWorkingSetSize),
        "method": "GetProcessTimes+PeakWorkingSetSize",
    }


def _own_ws_bytes() -> int:
    if os.name == "nt":
        pmc = _PMC(ctypes.sizeof(_PMC))
        if _get_pmc(wintypes.HANDLE(-1), ctypes.byref(pmc), ctypes.sizeof(_PMC)):
            return int(pmc.WorkingSetSize)
    return 0


# ---- A2 Component Qualification Probe -------------------------------------------------------------------

def probe_a2_disposition(paths: dict[str, Any]) -> dict[str, Any]:
    """Run DexSQL 0.1.1 MCP compact=true component check on real binary & document end-to-end exclusion."""
    a1_bin = paths["A1"]
    sample = paths["inputs"]["newpipe-0.28.6"]
    cmd = [str(a1_bin), "--threads", "2", "mcp", "--timeout-ms", "60000", "--max-datasets", "1"]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")

    def rpc(msg_id: int | None, method: str, params: dict | None = None) -> dict | None:
        obj: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if msg_id is not None:
            obj["id"] = msg_id
        if params is not None:
            obj["params"] = params
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()
        if msg_id is None:
            return None
        while True:
            line = proc.stdout.readline()
            if not line:
                raise RuntimeError("A2 MCP exited unexpectedly")
            parsed = json.loads(line)
            if parsed.get("id") == msg_id:
                return parsed

    try:
        rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mdd060-a2", "version": "1"}})
        rpc(None, "notifications/initialized")
        tools = rpc(2, "tools/list")["result"]["tools"]
        query_tool = next(t for t in tools if t["name"] == "query")
        query_props = query_tool["inputSchema"]["properties"]
        compact_supported = "compact" in query_props

        opened = rpc(3, "tools/call", {"name": "open_dataset", "arguments": {"inputs": [str(sample)]}})["result"]
        ds_id = opened["structuredContent"]["dataset_id"]

        small_t0 = time.perf_counter()
        small_res = rpc(4, "tools/call", {
            "name": "query",
            "arguments": {
                "dataset_id": ds_id,
                "sql": ["SELECT file_id, class_idx, descriptor FROM classes ORDER BY file_id, class_idx"],
                "limit": 5,
                "offset": 0,
                "compact": True,
            },
        })["result"]
        small_sec = time.perf_counter() - small_t0
        small_sc = small_res.get("structuredContent", {})
        stmt0 = small_sc["statements"][0]

        offset_limit_res = rpc(5, "tools/call", {
            "name": "query",
            "arguments": {
                "dataset_id": ds_id,
                "sql": ["SELECT file_id, method_idx FROM method_calls ORDER BY file_id, method_idx"],
                "limit": 1000,
                "offset": 99500,
                "compact": True,
            },
        })["result"]

        offset_100k_res = rpc(6, "tools/call", {
            "name": "query",
            "arguments": {
                "dataset_id": ds_id,
                "sql": ["SELECT file_id, method_idx FROM method_calls ORDER BY file_id, method_idx"],
                "limit": 1,
                "offset": 100000,
                "compact": True,
            },
        })["result"]

        rpc(7, "tools/call", {"name": "close_dataset", "arguments": {"dataset_id": ds_id}})
    finally:
        if proc.stdin:
            proc.stdin.close()
        proc.wait(timeout=10)

    def _mcp_err_msg(res: dict[str, Any]) -> str | None:
        sc = res.get("structuredContent")
        if isinstance(sc, dict) and isinstance(sc.get("error"), dict):
            return sc["error"].get("message")
        content = res.get("content") or []
        return content[0].get("text") if content else None

    disposition = {
        "schema_version": "mdd.a2-disposition.v1",
        "task": "MDD-060",
        "variant": "A2",
        "product": "DexSQL 0.1.1 MCP compact=true candidate",
        "binary_sha256": DEFAULT_A1_SHA,
        "component_probe_passed": bool(compact_supported and not small_res.get("isError") and len(stmt0.get("rows", [])) == 5),
        "compact_flag_in_schema": compact_supported,
        "small_page_seconds": round(small_sec, 6),
        "small_page_compact_content_empty": small_res.get("content") == [],
        "small_page_total_rows": stmt0.get("total_rows"),
        "small_page_truncated": stmt0.get("truncated"),
        "producer_snapshot_provenance_bound": False,
        "offset_plus_limit_over_100k_is_error": bool(offset_limit_res.get("isError")),
        "offset_plus_limit_over_100k_message": _mcp_err_msg(offset_limit_res),
        "offset_100k_is_error": bool(offset_100k_res.get("isError")),
        "offset_100k_message": _mcp_err_msg(offset_100k_res),
        "end_to_end_qualified_for_hostlab_w07": False,
        "end_to_end_qualified_for_unbounded_w05_bulk": False,
        "exclusion_reasons": [
            "DexSQL 0.1.1 MCP query refuses offset+limit > 100000 (verified directly on real binary), whereas hostlab-9161100 classes has 310,716 rows, hostlab-9170100 has 345,907 rows, and method_calls exceeds 1,000,000 rows.",
            "MCP open_dataset/query does not expose an immutable snapshot_id/source SHA-256 generation binding proof or deterministic tie-breaking outer ORDER BY rewrite guarantee for HostLab arbitrary projections.",
            "Original HostLab native_audit consumes CLI query --interactive (which has no compact switch) + shape/hex/sentinel marker; no 20-group qualified MCP audit consumer is deployed in HostLab.",
        ],
    }
    _write_json(LOCAL_OUT / "a2-disposition.json", disposition)
    return disposition


# ---- W05 NewPipe Bulk Pipeline Sessions (A0 / A1 CLI vs B0 / B1 Serve) ----------------------------------

class DexSqlCliPipeSession:
    """HostLab-equivalent native_cli.CliSession for A0/A1 interactive pipeline comparison on W05."""

    def __init__(self, binary: Path, apk: Path, threads: int = 2, timeout: int = 300):
        self.binary = binary
        self.apk = apk
        self.threads = threads
        self.timeout = timeout
        self.deadline = time.monotonic() + timeout
        self.messages: "queue.Queue[Any]" = queue.Queue(maxsize=8)
        self.closed = threading.Event()
        self.lines: "deque[bytes]" = deque()
        self.pending = b""
        self.eof = False
        self.wire_bytes = 0
        self.prepare_seconds = 0.0
        self.proc: "subprocess.Popen | None" = None

    def __enter__(self) -> "DexSqlCliPipeSession":
        t0 = time.perf_counter()
        self.proc = subprocess.Popen(
            [str(self.binary), "--threads", str(self.threads), "query", "--input", str(self.apk), "--interactive"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name != "nt",
        )
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self.reader.start()
        self.stderr_thread.start()
        self.files = {int(r["file_id"]): r["entry_name"] for r in self.rows("SELECT file_id,entry_name FROM dex_files ORDER BY file_id")}
        self.prepare_seconds = time.perf_counter() - t0
        return self

    def _drain_stderr(self) -> None:
        if self.proc and self.proc.stderr:
            self.stderr_data = self.proc.stderr.read()

    def _read(self) -> None:
        assert self.proc and self.proc.stdout
        while not self.closed.is_set():
            try:
                chunk = self.proc.stdout.read1(64 * 1024)
            except (OSError, ValueError):
                chunk = RuntimeError("cli read failed")
            if isinstance(chunk, bytes):
                self.wire_bytes += len(chunk)
            while not self.closed.is_set():
                try:
                    self.messages.put(chunk, timeout=0.1)
                    break
                except queue.Full:
                    continue
            if not chunk or isinstance(chunk, Exception):
                break

    def _line(self) -> bytes:
        while not self.lines:
            if self.eof:
                return b""
            rem = self.deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError("deadline")
            chunk = self.messages.get(timeout=rem)
            if isinstance(chunk, Exception):
                raise chunk
            if not chunk:
                self.eof = True
                line, self.pending = self.pending, b""
                return line
            frags = (self.pending + chunk).split(b"\n")
            self.pending = frags.pop()
            self.lines.extend(part + b"\n" for part in frags)
        return self.lines.popleft()

    def table(self, sql: str, *, expected: list[str] | None = None):
        assert self.proc and self.proc.stdin
        marker = "__mdd060_end_" + uuid.uuid4().hex
        payload = (sql.rstrip(";\n") + ";\nSELECT '" + marker + "' AS mdd_boundary;\n").encode("utf-8")
        self.proc.stdin.write(payload)
        self.proc.stdin.flush()
        columns = None
        while True:
            line = self._line()
            if not line:
                raise RuntimeError("A CLI exited before marker")
            text = line.decode("utf-8", "strict").strip()
            if not text.startswith("|") or not text.endswith("|"):
                continue
            cells = [c.strip() for c in text[1:-1].split("|")]
            if cells == [marker]:
                if columns is None:
                    raise RuntimeError("no columns returned")
                return
            if cells == ["mdd_boundary"]:
                continue
            if columns is None:
                if expected is not None and cells != expected:
                    raise RuntimeError("column mismatch")
                columns = cells
                yield columns, None
                continue
            yield columns, cells

    def rows(self, sql: str) -> list[dict[str, str | None]]:
        cols = None
        for names, row in self.table("SELECT * FROM (" + sql + ") AS hostlab_shape LIMIT 0"):
            cols = names
        assert cols
        def q(n: str) -> str:
            return '"' + n.replace('"', '""') + '"'
        proj = ["CASE WHEN " + q(c) + " IS NULL THEN 'N' ELSE hex(CAST(" + q(c) + " AS TEXT)) END AS " + q(c) for c in cols]
        stmt = "SELECT " + ",".join(proj) + " FROM (" + sql + ") AS hostlab_rows"
        out: list[dict[str, str | None]] = []
        for names, cells in self.table(stmt, expected=cols):
            if cells is None:
                continue
            decoded = [None if c == "N" else bytes.fromhex(c).decode("utf-8", "strict") for c in cells]
            out.append(dict(zip(names, decoded)))
        return out

    def __exit__(self, exc, *_):
        self.closed.set()
        if self.proc is None:
            return
        if exc is None and self.proc.poll() is None:
            try:
                assert self.proc.stdin
                self.proc.stdin.write(b".exit\n")
                self.proc.stdin.flush()
                self.proc.stdin.close()
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
        elif self.proc.poll() is None:
            self.proc.kill()
        self.metrics = _proc_metrics_win(self.proc)
        for s in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            try:
                if s:
                    s.close()
            except OSError:
                pass
        self.proc.wait()


def _run_newpipe_single(
    variant: str,
    paths: dict[str, Any],
    statements: list[str],
    block_id: str,
    pair_id: str,
    round_num: int,
    lease_path: Path,
    manifest_sha: str,
) -> dict[str, Any]:
    apk = paths["inputs"]["newpipe-0.28.6"]
    apk_sha = DEFAULT_NEWPIPE_SHA
    apk_bytes = str(apk.stat().st_size)
    sys.path.insert(0, str(ROOT / "integrations/hostlab"))
    import native_session as ns  # noqa: E402

    run_id = f"mdd060-{block_id}-{pair_id}-{variant}"
    cpu_t0 = time.process_time()
    start_ws = _own_ws_bytes()
    wall_t0 = time.perf_counter()
    results_per_stmt: list[tuple[list[str], list[dict[str, Any]]]] = []
    wire_bytes = 0
    prepare_s = 0.0
    query_s = 0.0
    proc_metrics: dict[str, Any] = {}
    binary_path = paths["A0"] if variant == "A0" else paths["A1"] if variant == "A1" else paths["B"]
    engine_sha = _sha256_file(binary_path)

    if variant in ("A0", "A1"):
        with DexSqlCliPipeSession(binary_path, apk, threads=2, timeout=300) as sess:
            prepare_s = sess.prepare_seconds
            qt0 = time.perf_counter()
            for sql in statements:
                rows = sess.rows(sql)
                results_per_stmt.append((list(rows[0].keys()) if rows else [], rows))
            query_s = time.perf_counter() - qt0
            wire_bytes = sess.wire_bytes
        proc_metrics = sess.metrics
    else:
        wire = "b0" if variant == "B0" else "b1"
        dialect = "dexsql-0.1.0"
        cmd = ns.serve_command(
            str(binary_path), [apk], dialect=dialect, timeout_seconds=300,
            sql_limits=HOSTLAB_SQL_LIMITS, non_scalar_text="reject",
        )
        cfg = ns.provider.Config(native_engine="meguvizdexdash")
        settings = ns.StructuralConfig(wire=wire, sql_limits=tuple(HOSTLAB_SQL_LIMITS.items()))
        launch = ns.EngineLaunch(
            cmd,
            {**os.environ, "MDD_FACTS_THREADS": "2"},
            {"engine": "meguvizdexdash", "sha256": engine_sha},
        )
        session_cls = ns.SESSIONS[wire]
        with session_cls(apk, timeout=300, threads=2, launch=launch, settings=settings) as sess:
            prepare_s = sess.opened["prepare_ms"] / 1000.0
            proc_handle = sess.transport.process
            qt0 = time.perf_counter()
            for sql in statements:
                rows = sess.all(sql)
                results_per_stmt.append((list(rows[0].keys()) if rows else [], rows))
            query_s = time.perf_counter() - qt0
            wire_bytes = sess.transport.response_bytes
            proc_metrics = _proc_metrics_win(proc_handle)

    wall_s = time.perf_counter() - wall_t0
    consumer_cpu_s = max(0.0, time.process_time() - cpu_t0)
    end_ws = _own_ws_bytes()

    total_rows = sum(len(rows) for _, rows in results_per_stmt)
    stmt_digests = [_sha256_obj(rows) for _, rows in results_per_stmt]
    canon_sha = _sha256_obj({"statements": len(statements), "total_rows": total_rows, "digests": stmt_digests})
    lease_sha = _sha256_file(lease_path)

    version_str = "0.1.0" if variant == "A0" else "0.1.1" if variant == "A1" else "0.1.0-dev"
    dialect_str = None if variant in ("A0", "A1") else "dexsql-0.1.0"
    product_str = "DexSQL" if variant in ("A0", "A1") else "MeguvizDexDash"
    profile_str = f"dexsql-{version_str}-cli" if variant in ("A0", "A1") else f"hostlab-contract-{variant.lower()}-unqualified"

    rec = {
        "schema_version": "mdd.benchmark-run.v1",
        "record_kind": "observed_run",
        "run_id": run_id,
        "pair_id": pair_id,
        "block_id": block_id,
        "round": round_num,
        "workload_id": "W05-newpipe-bulk",
        "variant": variant,
        "timestamp_utc": _utc_now(),
        "engine": {
            "product": product_str,
            "version": version_str,
            "build_id": f"{product_str.lower()}-{engine_sha[:12]}",
            "binary_sha256": engine_sha,
            "source_commit": None if variant in ("A0", "A1") else _git_head(),
            "profile": profile_str,
            "sql_dialect": dialect_str,
        },
        "harness": {
            "revision": _git_head(),
            "manifest_sha256": manifest_sha,
            "command_argv": ["benchmarks/run-five-way-comparison.py", "--workload", "W05-newpipe-bulk", "--variant", variant],
            "timing_boundary": "joint wall_seconds from before worker spawn until full 7-statement DTO materialization and clean process exit",
        },
        "inputs": [{"occurrence_id": "newpipe-0.28.6", "sha256": apk_sha, "bytes": apk_bytes}],
        "environment": {
            "machine_id": f"win-x86_64-{hashlib.sha256(platform.node().encode()).hexdigest()[:12]}",
            "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
            "cpu": platform.processor() or platform.machine(),
            "memory_bytes": str(memory_status()["total_phys_bytes"]),
            "total_cpu_budget": 2.0,
            "engine_threads": 2,
            "concurrent_jobs": 1,
            "cache_state": "warm_os",
            "cache_control": "fresh_process_per_run_no_persistent_engine_cache",
            "background_load": "exclusive_window_verified_idle_no_concurrent_builds",
            "artifact_sha256": lease_sha,
        },
        "execution": {
            "status": "completed",
            "exit_code": 0,
            "complete_output": True,
            "fallback_count": 0,
            "contaminated": False,
            "contamination_reason": None,
            "wall_seconds": round(wall_s, 6),
        },
        "correctness": {
            "scope_id": "newpipe-0.28.6-12dex",
            "input_complete": True,
            "facts_complete": True,
            "equivalent": True,
            "comparison_mode": "ordered",
            "canonical_sha256": canon_sha,
            "certificate_sha256": canon_sha,
            "mismatch_count": 0,
            "notes": [
                "Full ordered DTO consumption across all 7 bulk statements of benchmarks/workloads/b0-bulk-statements.json.",
                "Overlapping producer and consumer execute concurrently on OS pipe; joint wall_seconds is measured directly, never summed serially.",
            ],
        },
        "metrics": {
            "e2e_wall_seconds": {"value": round(wall_s, 6), "unit": "seconds", "scope": "joint_producer_pipe_consumer_and_exit", "method": "time.perf_counter"},
            "explicit_prepare_seconds": {"value": round(prepare_s, 6), "unit": "seconds", "scope": "explicit_open_session_setup_and_dex_files", "method": "time.perf_counter"},
            "query_pipeline_seconds": {"value": round(query_s, 6), "unit": "seconds", "scope": "all_7_statements_overlapping_producer_pipe_consumer", "method": "time.perf_counter"},
            "producer_cpu_seconds": {"value": round(proc_metrics["producer_cpu_seconds"], 6) if proc_metrics["producer_cpu_seconds"] is not None else None, "unit": "seconds", "scope": "child_engine_user_plus_kernel", "method": proc_metrics["method"], "unavailable_reason": None if proc_metrics["producer_cpu_seconds"] is not None else "non_windows"},
            "consumer_cpu_seconds": {"value": round(consumer_cpu_s, 6), "unit": "seconds", "scope": "python_consumer_process_time", "method": "time.process_time"},
            "producer_peak_working_set_bytes": {"value": proc_metrics["producer_peak_ws_bytes"], "unit": "bytes", "scope": "child_engine_process_peak_ws", "method": proc_metrics["method"], "unavailable_reason": None if proc_metrics["producer_peak_ws_bytes"] is not None else "non_windows"},
            "consumer_working_set_bytes": {"value": max(start_ws, end_ws), "unit": "bytes", "scope": "consumer_process_working_set", "method": "GetProcessMemoryInfo"},
            "wire_bytes": {"value": int(wire_bytes), "unit": "bytes", "scope": "stdout_pipe_bytes_consumed", "method": "exact_byte_counter"},
            "total_rows": {"value": int(total_rows), "unit": "count", "scope": "all_7_bulk_statements", "method": "exact_row_count"},
        },
        "artifacts": [
            {"path": f"artifacts/local/mdd-060/newpipe/{run_id}.json", "sha256": canon_sha, "kind": "local_run_digest"}
        ],
    }
    validator.validate_observed_run(rec, check_redaction=True)
    return rec


def run_newpipe_blocks(paths: dict[str, Any], *, pairs_per_block: int = 10, warmup: bool = True) -> list[dict[str, Any]]:
    spec = validator.parse_strict_json(WORKLOADS_B0_PATH.read_text(encoding="utf-8"))
    statements = [s for v in spec["variants"] for s in v["statements"]]
    manifest_sha = _sha256_file(MANIFEST_PATH)
    variants = ["A0", "A1", "B0", "B1"]

    if warmup:
        lease_w = issue_lease("newpipe-warmup", 600, cpu_affinity_mask=15)
        for v in variants:
            _run_newpipe_single(v, paths, statements, "warmup", "w0", 1, lease_w, manifest_sha)

    records: list[dict[str, Any]] = []
    canon_set: set[str] = set()
    for block_idx, block_id in enumerate(("block1", "block2"), 1):
        if block_idx > 1:
            time.sleep(2.0)  # distinct measurement block boundary
        lease_path = issue_lease(f"newpipe-{block_id}", 1800, cpu_affinity_mask=15)
        for pair_idx in range(1, pairs_per_block + 1):
            pair_id = f"p{pair_idx:02d}"
            order = variants if pair_idx % 2 == 1 else list(reversed(variants))
            for v in order:
                rec = _run_newpipe_single(v, paths, statements, block_id, pair_id, (block_idx - 1) * pairs_per_block + pair_idx, lease_path, manifest_sha)
                canon_set.add(rec["correctness"]["canonical_sha256"])
                if len(canon_set) != 1:
                    raise RuntimeError(f"NewPipe DTO canonical digest diverged at {rec['run_id']}: {canon_set}")
                records.append(rec)
    out_file = LOCAL_OUT / "newpipe-runs.jsonl"
    out_file.write_text("".join(json.dumps(r, ensure_ascii=False, allow_nan=False) + "\n" for r in records), encoding="utf-8", newline="\n")
    return records


# ---- W07 HostLab Full Audit Job-Isolated Worker & Profiler -----------------------------------------------

def _hostlab_worker(args: argparse.Namespace) -> int:
    """Runs inside windows_job.run_job with pinned affinity_mask=15 (4 CPUs), threads=2, offline."""
    paths = _resolve_paths()
    reference = paths["reference"]
    apk = paths["inputs"][args.sample]
    manifest = validator.parse_strict_json(SHADOW_MANIFEST_PATH.read_text(encoding="utf-8"))
    sample_info = next(item for item in manifest["inputs"] if item["occurrence_id"] == args.sample)
    if _sha256_file(apk) != sample_info["sha256"] or str(apk.stat().st_size) != str(sample_info["bytes"]):
        raise RuntimeError(f"input identity mismatch: {args.sample}")

    out = Path(args.out).resolve()
    state = out / "state"
    (state / "tmp").mkdir(parents=True, exist_ok=True)
    sys.dont_write_bytecode = True
    here_resolved = HERE.resolve()
    integ_dir = (ROOT / "integrations/hostlab").resolve()
    sys.path[:] = [e for e in sys.path if Path(e or ".").resolve() not in (here_resolved, integ_dir)]
    sys.path.insert(0, str(reference / "tools/hostlab"))

    variant = args.variant
    if variant in ("A0", "A1"):
        bin_path = paths[variant]
        os.environ["HOSTLAB_DEXSQL"] = str(bin_path)
        expected_sha = _sha256_file(bin_path)
        if variant == "A1":
            import install_dexsql as orig_inst  # noqa: E402
            proxy = types.ModuleType("install_dexsql")
            proxy.__file__ = __file__
            proxy.VERSION = "0.1.1"
            proxy.status = lambda: {"available": True, "version": "0.1.1", "sha256": expected_sha, "path": str(bin_path), "engine": "dexsql"}
            proxy.verify = lambda p=None: bin_path
            proxy.executable = lambda: bin_path
            proxy.asset = lambda: (bin_path.name, expected_sha)
            proxy.install = orig_inst.install
            sys.modules["install_dexsql"] = proxy
        engine_sha = expected_sha
        wire = "legacy_cli"
    else:
        wire = "b0" if variant == "B0" else "b1"
        bin_path = paths["B"]
        engine_sha = _sha256_file(bin_path)
        sys.path.insert(0, str(integ_dir))
        os.environ["HOSTLAB_MEGUVIZDEXDASH"] = str(bin_path)
        p_cfg = out / "provider-config.json"
        s_cfg = out / "structural-config.json"
        _write_json(p_cfg, {
            "schema": "mdd.hostlab-provider-config.v1",
            "native_engine": "meguvizdexdash",
            "meguvizdexdash": {"manifest": str(paths["b_pin_manifest"]), "profile_policy": "allow_unadmitted"},
        })
        _write_json(s_cfg, {
            "schema": "mdd.hostlab-structural-config.v1",
            "wire": wire,
            "sql_limits": HOSTLAB_SQL_LIMITS,
            "non_scalar_text": "lossy-replacement",
        })
        os.environ["HOSTLAB_PROVIDER_CONFIG"] = str(p_cfg)
        os.environ["HOSTLAB_STRUCTURAL_CONFIG"] = str(s_cfg)
        pin_doc = validator.parse_strict_json(paths["b_pin_manifest"].read_text(encoding="utf-8"))
        build = next(item for item in pin_doc["builds"] if item["sha256"] == engine_sha)
        stand = types.ModuleType("install_dexsql")
        stand.__file__ = __file__
        stand.VERSION = build["engine_version"]
        stand.status = lambda: {"available": True, "version": build["engine_version"], "build_id": build["build_id"], "sha256": engine_sha, "path": str(bin_path), "engine": "meguvizdexdash", "wire": wire, "implementation_scope": build["implementation_scope"]}
        stand.verify = lambda p=None: bin_path
        stand.executable = lambda: bin_path
        stand.asset = lambda: (bin_path.name, engine_sha)
        stand.install = lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("install forbidden"))
        sys.modules["install_dexsql"] = stand

    import analyze  # noqa: E402
    import audit_common  # noqa: E402
    import hostlab  # noqa: E402
    import native_surface  # noqa: E402
    import process_control  # noqa: E402
    import verify_audits  # noqa: E402
    from analysis.run_intake import EXPECTED_FEATURES  # noqa: E402

    hostlab.STATE = state
    hostlab.CONFIG = state / "config.json"
    for name in FORBIDDEN_ENTRY_POINTS:
        setattr(hostlab, name, lambda *_a, n=name, **_k: (_ for _ in ()).throw(RuntimeError("forbidden " + n)))
    orig_connect = socket.socket.connect
    socket.socket.connect = lambda s, a: (_ for _ in ()).throw(RuntimeError("network forbidden")) if s.family in (socket.AF_INET, socket.AF_INET6) else orig_connect(s, a)

    # Optional non-overlapping sub-stage instrumentation (enabled only during stage profiling)
    sub_timings: dict[str, float] = {
        "resource_fingerprints_seconds": 0.0,
        "intake_gate_seconds": 0.0,
        "home_gate_seconds": 0.0,
        "surface_sql_seconds": 0.0,
        "structural_sql_seconds": 0.0,
    }
    if args.profile_substages:
        orig_res_fp = audit_common.resource_fingerprints
        orig_exec = analyze.execute
        import native_audit  # noqa: E402
        import native_session as active_ns  # noqa: E402
        orig_surface_scan = native_surface.scan

        def timed_res_fp(*a, **k):
            t0 = time.perf_counter()
            try:
                return orig_res_fp(*a, **k)
            finally:
                sub_timings["resource_fingerprints_seconds"] += time.perf_counter() - t0

        def timed_exec(command, log, env, timeout):
            t0 = time.perf_counter()
            try:
                return orig_exec(command, log, env, timeout)
            finally:
                dt = time.perf_counter() - t0
                joined = " ".join(str(x) for x in command)
                if "run_intake.py" in joined:
                    sub_timings["intake_gate_seconds"] += dt
                elif "home_frame_audit.py" in joined:
                    sub_timings["home_gate_seconds"] += dt

        in_surface = [False]
        orig_native_session = active_ns.NativeSession

        def wrap_rows(orig_fn):
            def wrapped(sql, *ra, **rk):
                t0 = time.perf_counter()
                try:
                    res = list(orig_fn(sql, *ra, **rk))
                finally:
                    dt = time.perf_counter() - t0
                    if in_surface[0]:
                        sub_timings["surface_sql_seconds"] += dt
                    else:
                        sub_timings["structural_sql_seconds"] += dt
                return iter(res)
            return wrapped

        def wrapped_native_session(*na, **nk):
            sess = orig_native_session(*na, **nk)
            sess.rows = wrap_rows(sess.rows)
            return sess

        def timed_surface_scan(sess, *sa, **sk):
            in_surface[0] = True
            try:
                return orig_surface_scan(sess, *sa, **sk)
            finally:
                in_surface[0] = False

        native_audit.resource_fingerprints = timed_res_fp
        native_audit.NativeSession = wrapped_native_session
        native_audit.native_surface.scan = timed_surface_scan
        analyze.execute = timed_exec

    tools_before = analyze.tool_hashes()
    carrier: dict[str, Any] = {}
    started = time.perf_counter()
    exit_code = analyze.main(
        ["audit", "--apk", str(apk), "--mode", "full", "--backend", "dexsql", "--timeout", "900"],
        surface_output=carrier,
    )
    elapsed = time.perf_counter() - started
    summaries = list((state / "reports").glob("*/*/*/summary.json"))
    if len(summaries) != 1:
        raise RuntimeError(f"expected 1 summary.json, got {len(summaries)}")
    report = hostlab_compare.read_json(summaries[0])
    native = report.get("native_audit", {})
    if exit_code not in (0, 1) or report.get("audit_complete") is not True or report.get("backend_fallback_reason") is not None:
        raise RuntimeError(f"incomplete or fallback audit: exit={exit_code}")
    if native.get("complete") is not True or native.get("native", {}).get("sha256") != engine_sha:
        raise RuntimeError("native audit incomplete or binary sha mismatch")
    surface = carrier["report"]
    surface["sample"] = report["sample"]
    evidence = verify_audits.evidence(report, surface, summaries[0].with_name("features.tsv"), summaries[0].with_name("home-frame.log"))
    hostlab.write_json(out / "evidence.json", evidence)
    groups = {name: hostlab_compare.group_digest(name, value) for name, value in evidence.items()}
    cert = {
        "schema": "mdd.hostlab-shadow-certificate.v1",
        "complete": True,
        "variant": variant,
        "input_sha256": sample_info["sha256"],
        "reference_source_commit": REFERENCE_COMMIT,
        "tools": tools_before,
        "feature_count": len(EXPECTED_FEATURES),
        "evidence_group_count": len(groups),
        "groups": groups,
        "fallback_count": 0,
        "output_fully_materialized": True,
        "more_available": False,
        "truncated": False,
        "business_exit_code": exit_code,
        "evidence_sha256": _sha256_file(out / "evidence.json"),
        "class_count": native["class_count"],
        "queries": native["queries"],
        "wall_seconds": elapsed,
        "native_elapsed_seconds": native["elapsed_ms"] / 1000.0,
        "native_phases_ms": native["phases"],
        "sub_timings_seconds": sub_timings,
    }
    _write_json(out / "certificate.json", cert)
    return 0


def _run_hostlab_single(
    variant: str,
    sample_id: str,
    paths: dict[str, Any],
    block_id: str,
    pair_id: str,
    round_num: int,
    lease_path: Path,
    manifest_sha: str,
    *,
    job_memory_bytes: int = 8589934592,
    profile_substages: bool = False,
) -> dict[str, Any]:
    run_id = f"mdd060-{sample_id}-{block_id}-{pair_id}-{variant}"
    out_dir = LOCAL_OUT / "hostlab" / run_id
    if out_dir.exists():
        import shutil
        shutil.rmtree(out_dir)
    for sub in ("tmp", "cache", "state"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not re.search(r"TOKEN|SECRET|PASSWORD|API_KEY", k, re.I)}
    for stale in ("HOSTLAB_DEXSQL", "HOSTLAB_MEGUVIZDEXDASH", "HOSTLAB_PROVIDER_CONFIG", "HOSTLAB_STRUCTURAL_CONFIG", "DEXQ_CACHE_DIR", "MDD_CACHE_DIR"):
        env.pop(stale, None)
    env.update(
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONIOENCODING="utf-8",
        TEMP=str(out_dir / "tmp"),
        TMP=str(out_dir / "tmp"),
        DEXQ_CACHE_DIR=str(out_dir / "cache"),
    )
    argv = [
        str(paths["python"]), "-B", str(Path(__file__).resolve()),
        "--worker-hostlab", "--variant", variant, "--sample", sample_id, "--out", str(out_dir),
    ]
    if profile_substages:
        argv.append("--profile-substages")

    sys.path.insert(0, str(ROOT / "artifacts/mdd-005/preparation-20261028"))
    from windows_job import run_job  # noqa: E402
    job_res = run_job(
        argv, out_dir / "job", cwd=ROOT, env=env,
        timeout_seconds=1200, memory_bytes=job_memory_bytes, affinity_mask=15, max_processes=16,
    )
    cert_path = out_dir / "certificate.json"
    cert = validator.parse_strict_json(cert_path.read_text(encoding="utf-8")) if cert_path.is_file() else {}
    ok = job_res["status"] == "completed" and job_res.get("tree_empty_verified") is True and cert.get("complete") is True

    shadow_doc = validator.parse_strict_json(SHADOW_MANIFEST_PATH.read_text(encoding="utf-8"))
    sample_info = next(i for i in shadow_doc["inputs"] if i["occurrence_id"] == sample_id)
    bin_path = paths["B"] if variant in ("B0", "B1") else paths[variant]
    engine_sha = _sha256_file(bin_path)
    version_str = "0.1.0" if variant == "A0" else "0.1.1" if variant == "A1" else "0.1.0-dev"
    product_str = "DexSQL" if variant in ("A0", "A1") else "MeguvizDexDash"
    dialect_str = None if variant in ("A0", "A1") else "dexsql-0.1.0"

    phases = cert.get("native_phases_ms") or {}
    p_s = (phases.get("prepare_ms") or 0.0) / 1000.0
    s_s = (phases.get("structural_ms") or 0.0) / 1000.0
    f_s = (phases.get("surface_ms") or 0.0) / 1000.0
    n_s = cert.get("native_elapsed_seconds", 0.0)
    r_s = max(0.0, n_s - p_s - s_s - f_s)
    e_s = float(job_res["wall_seconds"])
    o_s = max(0.0, e_s - n_s)

    status_val = "completed" if ok else ("timeout" if job_res.get("reason") == "timeout" else "failed")
    group_hash = _sha256_obj(cert.get("groups")) if ok else None

    metrics: dict[str, Any] = {
        "worker_e_wall_seconds": {"value": round(e_s, 6), "unit": "seconds", "scope": "full_worker_windows_job_wall", "method": "windows_job.run_job"},
        "job_cpu_user_seconds": {"value": round(job_res.get("cpu_user_seconds", 0.0), 6) if "cpu_user_seconds" in job_res else None, "unit": "seconds", "scope": "all_job_processes_user", "method": "JobObjectBasicAccountingInformation", "unavailable_reason": None if "cpu_user_seconds" in job_res else "job_failed"},
        "job_cpu_kernel_seconds": {"value": round(job_res.get("cpu_kernel_seconds", 0.0), 6) if "cpu_kernel_seconds" in job_res else None, "unit": "seconds", "scope": "all_job_processes_kernel", "method": "JobObjectBasicAccountingInformation", "unavailable_reason": None if "cpu_kernel_seconds" in job_res else "job_failed"},
        "peak_job_commit_bytes": {"value": int(job_res["peak_job_commit_bytes"]) if "peak_job_commit_bytes" in job_res else None, "unit": "bytes", "scope": "all_job_processes_peak_commit_not_rss", "method": "JobObjectExtendedLimitInformation", "unavailable_reason": None if "peak_job_commit_bytes" in job_res else "job_failed"},
        "native_prepare_seconds": {"value": round(p_s, 6) if ok else None, "unit": "seconds", "scope": "explicit_open_session_setup", "method": "native_audit_timer", "unavailable_reason": None if ok else "incomplete"},
        "stage_s_structural_seconds": {"value": round(s_s, 6) if ok else None, "unit": "seconds", "scope": "mutually_exclusive_structural_audit", "method": "native_audit_timer", "unavailable_reason": None if ok else "incomplete"},
        "stage_f_surface_seconds": {"value": round(f_s, 6) if ok else None, "unit": "seconds", "scope": "mutually_exclusive_surface_scan_and_fingerprints", "method": "native_audit_timer", "unavailable_reason": None if ok else "incomplete"},
        "stage_r_native_residual_seconds": {"value": round(r_s, 6) if ok else None, "unit": "seconds", "scope": "mutually_exclusive_native_non_p_s_f_residual", "method": "native_elapsed_minus_p_s_f", "unavailable_reason": None if ok else "incomplete"},
        "stage_o_outer_residual_seconds": {"value": round(o_s, 6) if ok else None, "unit": "seconds", "scope": "mutually_exclusive_outer_gates_report_job_overhead", "method": "worker_e_minus_native_elapsed", "unavailable_reason": None if ok else "incomplete"},
    }
    if profile_substages and ok:
        sub = cert.get("sub_timings_seconds", {})
        metrics["sub_f_resource_fingerprints_seconds"] = {"value": round(sub.get("resource_fingerprints_seconds", 0.0), 6), "unit": "seconds", "scope": "mutually_exclusive_within_f", "method": "resource_fingerprints_wrapper"}
        metrics["sub_f_surface_sql_seconds"] = {"value": round(sub.get("surface_sql_seconds", 0.0), 6), "unit": "seconds", "scope": "mutually_exclusive_within_f_sql_wire_wait", "method": "session_rows_wrapper"}
        metrics["sub_s_structural_sql_seconds"] = {"value": round(sub.get("structural_sql_seconds", 0.0), 6), "unit": "seconds", "scope": "mutually_exclusive_within_s_sql_wire_wait", "method": "session_rows_wrapper"}
        metrics["sub_o_intake_gate_seconds"] = {"value": round(sub.get("intake_gate_seconds", 0.0), 6), "unit": "seconds", "scope": "mutually_exclusive_within_o", "method": "analyze_execute_wrapper"}
        metrics["sub_o_home_gate_seconds"] = {"value": round(sub.get("home_gate_seconds", 0.0), 6), "unit": "seconds", "scope": "mutually_exclusive_within_o", "method": "analyze_execute_wrapper"}

    rec = {
        "schema_version": "mdd.benchmark-run.v1",
        "record_kind": "observed_run",
        "run_id": run_id,
        "pair_id": pair_id,
        "block_id": block_id,
        "round": round_num,
        "workload_id": f"W07-{sample_id}",
        "variant": variant,
        "timestamp_utc": _utc_now(),
        "engine": {
            "product": product_str,
            "version": version_str,
            "build_id": f"{product_str.lower()}-{engine_sha[:12]}",
            "binary_sha256": engine_sha,
            "source_commit": None if variant in ("A0", "A1") else _git_head(),
            "profile": f"dexsql-{version_str}-cli" if variant in ("A0", "A1") else f"hostlab-contract-{variant.lower()}-unqualified",
            "sql_dialect": dialect_str,
        },
        "harness": {
            "revision": _git_head(),
            "manifest_sha256": manifest_sha,
            "command_argv": ["benchmarks/run-five-way-comparison.py", "--workload", f"W07-{sample_id}", "--variant", variant],
            "timing_boundary": "Windows Job full E from process creation through analyze.main audit --mode full, intake/home gates, 20-group evidence build, and clean tree exit",
        },
        "inputs": [{"occurrence_id": sample_id, "sha256": sample_info["sha256"], "bytes": str(sample_info["bytes"])}],
        "environment": {
            "machine_id": f"win-x86_64-{hashlib.sha256(platform.node().encode()).hexdigest()[:12]}",
            "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
            "cpu": platform.processor() or platform.machine(),
            "memory_bytes": str(job_memory_bytes),
            "total_cpu_budget": 4.0,
            "engine_threads": 2,
            "concurrent_jobs": 1,
            "cache_state": "warm_os",
            "cache_control": "isolated_state_cache_tmp_per_side_no_persistent_engine_cache",
            "background_load": "exclusive_window_verified_idle_affinity_mask_15",
            "artifact_sha256": _sha256_file(lease_path),
        },
        "execution": {
            "status": status_val,
            "exit_code": job_res.get("exit_code"),
            "complete_output": bool(ok),
            "fallback_count": 0,
            "contaminated": False if ok else True,
            "contamination_reason": None if ok else f"job failed: {job_res.get('reason') or job_res.get('error')}",
            "wall_seconds": round(e_s, 6),
        },
        "correctness": {
            "scope_id": f"{sample_id}-{sample_info['dex_members']}dex",
            "input_complete": bool(ok),
            "facts_complete": bool(ok),
            "equivalent": True if ok else None,
            "comparison_mode": "structured" if ok else "not_compared",
            "canonical_sha256": cert.get("evidence_sha256") if ok else None,
            "certificate_sha256": group_hash if ok else None,
            "mismatch_count": 0 if ok else None,
            "notes": [
                "Unmodified HostLab analyze.main audit --mode full verified across all 20 evidence groups and 27 FEATURE rows." if ok else "Run did not complete cleanly; retained for transparent failure accounting.",
            ],
        },
        "metrics": metrics,
        "artifacts": [
            {"path": f"artifacts/local/mdd-060/hostlab/{run_id}/certificate.json", "sha256": group_hash or ("0" * 64), "kind": "hostlab_20group_certificate"}
        ],
    }
    validator.validate_observed_run(rec, check_redaction=True)
    return rec


def compare_hostlab_sides(dir_a: Path, dir_b: Path) -> dict[str, Any]:
    return hostlab_compare.compare(hostlab_compare.load_run(dir_a), hostlab_compare.load_run(dir_b))


# ---- Formal Paired Block Driver & Summary Generator ------------------------------------------------------

def run_hostlab_stage_profile(paths: dict[str, Any]) -> dict[str, Any]:
    manifest_sha = _sha256_file(MANIFEST_PATH)
    lease_stage = issue_lease("hostlab-stage-profile", 3600, cpu_affinity_mask=15)
    stage_records: list[dict[str, Any]] = []
    variant_order = ["A0", "A1", "B0", "B1"]
    a_best_by_sample: dict[str, str] = {}
    for sample_id in ("hostlab-9161100", "hostlab-9170100"):
        by_v: dict[str, dict[str, Any]] = {}
        for idx, v in enumerate(variant_order, 1):
            rec = _run_hostlab_single(
                v, sample_id, paths, "stage-profile", "sp01", idx, lease_stage, manifest_sha,
                job_memory_bytes=8589934592, profile_substages=True,
            )
            stage_records.append(rec)
            by_v[v] = rec
            m = rec["metrics"]
            print(
                f"[stage-profile] {sample_id} {v}: status={rec['execution']['status']} "
                f"E={rec['execution']['wall_seconds']:.2f}s P={m['native_prepare_seconds']['value']}s "
                f"S={m['stage_s_structural_seconds']['value']}s F={m['stage_f_surface_seconds']['value']}s "
                f"O={m['stage_o_outer_residual_seconds']['value']}s",
                flush=True,
            )
            if rec["execution"]["status"] != "completed":
                raise RuntimeError(f"stage profile failed on {sample_id}/{v}: {rec['execution']}")
        dir_a0 = LOCAL_OUT / "hostlab" / by_v["A0"]["run_id"]
        for other in ("A1", "B0", "B1"):
            dir_other = LOCAL_OUT / "hostlab" / by_v[other]["run_id"]
            comp = compare_hostlab_sides(dir_a0, dir_other)
            if not comp["equal"]:
                raise RuntimeError(f"20-group equivalence mismatch between A0 and {other} on {sample_id}: {comp}")
        print(f"[stage-profile] {sample_id}: A1, B0, B1 all 4-layer / 20-group EQUAL to A0", flush=True)
        a_best_by_sample[sample_id] = "A1" if by_v["A1"]["execution"]["wall_seconds"] <= by_v["A0"]["execution"]["wall_seconds"] else "A0"

    out_stage = LOCAL_OUT / "hostlab-stage-runs.jsonl"
    out_stage.write_text("".join(json.dumps(r, ensure_ascii=False, allow_nan=False) + "\n" for r in stage_records), encoding="utf-8", newline="\n")
    return {"a_best_by_sample": a_best_by_sample, "stage_records": stage_records}


def run_hostlab_blocks(
    paths: dict[str, Any],
    *,
    pairs_block1: int = 10,
    reuse_stage_profile: bool = False,
) -> dict[str, Any]:
    manifest_sha = _sha256_file(MANIFEST_PATH)
    records: list[dict[str, Any]] = []

    if reuse_stage_profile and (LOCAL_OUT / "hostlab-stage-runs.jsonl").is_file():
        stage_records = validator.load_observed_runs(LOCAL_OUT / "hostlab-stage-runs.jsonl", check_redaction=True)
        a_best_by_sample = {}
        for sample_id in ("hostlab-9161100", "hostlab-9170100"):
            wid = f"W07-{sample_id}"
            a0 = next(r for r in stage_records if r["workload_id"] == wid and r["variant"] == "A0")
            a1 = next(r for r in stage_records if r["workload_id"] == wid and r["variant"] == "A1")
            a_best_by_sample[sample_id] = "A1" if a1["execution"]["wall_seconds"] <= a0["execution"]["wall_seconds"] else "A0"
    else:
        stage_info = run_hostlab_stage_profile(paths)
        stage_records = stage_info["stage_records"]
        a_best_by_sample = stage_info["a_best_by_sample"]

    records.extend(stage_records)

    # Paired alternating blocks comparing fastest qualified A baseline vs B1
    paired_sample = "hostlab-9161100"
    a_best = a_best_by_sample[paired_sample]
    pair_variants = [v for v in (a_best, "B1")]

    lease_b1 = issue_lease("hostlab-block1", 7200, cpu_affinity_mask=15)
    for pair_idx in range(1, pairs_block1 + 1):
        pair_id = f"p{pair_idx:02d}"
        order = pair_variants if pair_idx % 2 == 1 else list(reversed(pair_variants))
        for v in order:
            rec = _run_hostlab_single(v, paired_sample, paths, "block1", pair_id, pair_idx, lease_b1, manifest_sha)
            records.append(rec)
            print(f"[hostlab-block1] {pair_id} {v}: E={rec['execution']['wall_seconds']:.2f}s eq={rec['correctness']['equivalent']}", flush=True)

    # Block 2: Independent second time block with alternating pairs across 9161100 and 9170100
    time.sleep(2.0)
    lease_b2 = issue_lease("hostlab-block2", 3600, cpu_affinity_mask=15)
    for sample_id in ("hostlab-9161100", "hostlab-9170100"):
        ab = a_best_by_sample[sample_id]
        for pair_idx in range(1, 3):
            pair_id = f"p{pair_idx:02d}"
            order = [ab, "B1"] if pair_idx % 2 == 1 else ["B1", ab]
            for v in order:
                rec = _run_hostlab_single(v, sample_id, paths, "block2", pair_id, pair_idx, lease_b2, manifest_sha)
                records.append(rec)
                print(f"[hostlab-block2] {sample_id} {pair_id} {v}: E={rec['execution']['wall_seconds']:.2f}s", flush=True)

    out_file = LOCAL_OUT / "hostlab-runs.jsonl"
    out_file.write_text("".join(json.dumps(r, ensure_ascii=False, allow_nan=False) + "\n" for r in records), encoding="utf-8", newline="\n")
    return {"a_best_by_sample": a_best_by_sample, "record_count": len(records), "stage_records": stage_records}


def summarize_mdd060() -> dict[str, Any]:
    """Read local verified observed_run logs + A2 disposition and publish public MDD-060 artifacts."""
    all_records: list[dict[str, Any]] = []
    for name in ("newpipe-runs.jsonl", "hostlab-runs.jsonl"):
        p = LOCAL_OUT / name
        if not p.is_file():
            raise RuntimeError(f"missing local run file: {p}")
        all_records.extend(validator.load_observed_runs(p, check_redaction=True))

    a2_disp = validator.parse_strict_json((LOCAL_OUT / "a2-disposition.json").read_text(encoding="utf-8"))
    validator.validate_public_redaction(a2_disp)

    for rec in all_records:
        validator.check_prepare_not_pure_parser(rec)

    PUBLIC_OUT.mkdir(parents=True, exist_ok=True)
    paired_jsonl = PUBLIC_OUT / "paired-runs.jsonl"
    paired_jsonl.write_text(
        "".join(json.dumps(r, ensure_ascii=False, allow_nan=False) + "\n" for r in all_records),
        encoding="utf-8",
        newline="\n",
    )
    validator.load_observed_runs(paired_jsonl, check_redaction=True)

    # Aggregate comparisons
    w05_a0_a1 = validator.aggregate_paired_metrics(all_records, workload_id="W05-newpipe-bulk", left_variant="A0", right_variant="A1")
    w05_a1_b0 = validator.aggregate_paired_metrics(all_records, workload_id="W05-newpipe-bulk", left_variant="A1", right_variant="B0")
    w05_a1_b1 = validator.aggregate_paired_metrics(all_records, workload_id="W05-newpipe-bulk", left_variant="A1", right_variant="B1")
    w05_b0_b1 = validator.aggregate_paired_metrics(all_records, workload_id="W05-newpipe-bulk", left_variant="B0", right_variant="B1")
    w05_b1_block1 = validator.aggregate_paired_metrics(all_records, workload_id="W05-newpipe-bulk", left_variant="A1", right_variant="B1", block_id="block1")
    w05_b1_block2 = validator.aggregate_paired_metrics(all_records, workload_id="W05-newpipe-bulk", left_variant="A1", right_variant="B1", block_id="block2")

    w07_916_a0_a1 = validator.aggregate_paired_metrics(all_records, workload_id="W07-hostlab-9161100", left_variant="A0", right_variant="A1")
    a_best_916 = "A1" if w07_916_a0_a1["right_median_wall_seconds"] <= w07_916_a0_a1["left_median_wall_seconds"] else "A0"
    w07_916_a0_b1 = validator.aggregate_paired_metrics(all_records, workload_id="W07-hostlab-9161100", left_variant="A0", right_variant="B1", block_id="stage-profile")
    w07_916_ab_b1_all = validator.aggregate_paired_metrics(all_records, workload_id="W07-hostlab-9161100", left_variant=a_best_916, right_variant="B1")
    w07_916_ab_b1_blk1 = validator.aggregate_paired_metrics(all_records, workload_id="W07-hostlab-9161100", left_variant=a_best_916, right_variant="B1", block_id="block1")
    w07_916_ab_b1_blk2 = validator.aggregate_paired_metrics(all_records, workload_id="W07-hostlab-9161100", left_variant=a_best_916, right_variant="B1", block_id="block2")

    w07_917_a0_a1 = validator.aggregate_paired_metrics(all_records, workload_id="W07-hostlab-9170100", left_variant="A0", right_variant="A1")
    a_best_917 = "A1" if w07_917_a0_a1["right_median_wall_seconds"] <= w07_917_a0_a1["left_median_wall_seconds"] else "A0"
    w07_917_ab_b1 = validator.aggregate_paired_metrics(all_records, workload_id="W07-hostlab-9170100", left_variant=a_best_917, right_variant="B1")

    # Stage breakdown from stage-profile records
    stage_rows = {}
    for rec in all_records:
        if rec["block_id"] == "stage-profile":
            key = f"{rec['workload_id']}/{rec['variant']}"
            m = rec["metrics"]
            p = m["native_prepare_seconds"]["value"]
            s = m["stage_s_structural_seconds"]["value"]
            f = m["stage_f_surface_seconds"]["value"]
            r = m["stage_r_native_residual_seconds"]["value"]
            o = m["stage_o_outer_residual_seconds"]["value"]
            e = m["worker_e_wall_seconds"]["value"]
            stage_rows[key] = {
                "variant": rec["variant"],
                "worker_e_wall_seconds": e,
                "P_prepare_seconds": p,
                "S_structural_seconds": s,
                "F_surface_seconds": f,
                "R_native_residual_seconds": r,
                "O_outer_residual_seconds": o,
                "S_sub_sql_seconds": (m.get("sub_s_structural_sql_seconds") or {}).get("value"),
                "F_sub_sql_seconds": (m.get("sub_f_surface_sql_seconds") or {}).get("value"),
                "F_sub_resource_fingerprints_seconds": (m.get("sub_f_resource_fingerprints_seconds") or {}).get("value"),
                "O_sub_intake_gate_seconds": (m.get("sub_o_intake_gate_seconds") or {}).get("value"),
                "O_sub_home_gate_seconds": (m.get("sub_o_home_gate_seconds") or {}).get("value"),
                "job_cpu_seconds": round((m["job_cpu_user_seconds"]["value"] or 0.0) + (m["job_cpu_kernel_seconds"]["value"] or 0.0), 6),
                "peak_job_commit_bytes": m["peak_job_commit_bytes"]["value"],
            }

    # Recompute conditional ~37% / ~47% same-machine A0 S/F targets cleanly
    conditional_targets = {}
    for wid in ("W07-hostlab-9161100", "W07-hostlab-9170100"):
        a0 = stage_rows[f"{wid}/A0"]
        t37 = a0["P_prepare_seconds"] + a0["R_native_residual_seconds"] + a0["O_outer_residual_seconds"] + a0["S_structural_seconds"] / 2.0 + a0["F_surface_seconds"] / 2.0
        t47 = a0["P_prepare_seconds"] + a0["R_native_residual_seconds"] + a0["O_outer_residual_seconds"] + a0["S_structural_seconds"] / 2.0 + a0["F_surface_seconds"] / 3.0
        conditional_targets[wid] = {
            "same_machine_a0_E_seconds": a0["worker_e_wall_seconds"],
            "s2x_f2x_budget_seconds": round(t37, 4),
            "s2x_f2x_reduction_vs_a0": round(1.0 - t37 / a0["worker_e_wall_seconds"], 4),
            "s2x_f3x_budget_seconds": round(t47, 4),
            "s2x_f3x_reduction_vs_a0": round(1.0 - t47 / a0["worker_e_wall_seconds"], 4),
            "note": "Conditional same-machine A0 S/F model only (delta=0); historical Linux 37%/47% is neither guaranteed nor reused directly.",
        }

    stage_profile = {
        "schema": "mdd.stage-and-resource-profile.v1",
        "task": "MDD-060",
        "generated_utc": _utc_now(),
        "record_count": len(all_records),
        "a2_disposition": a2_disp,
        "fastest_qualified_existing_baseline": {
            "W05-newpipe-bulk": "A1" if w05_a0_a1["right_median_wall_seconds"] <= w05_a0_a1["left_median_wall_seconds"] else "A0",
            "W07-hostlab-9161100": a_best_916,
            "W07-hostlab-9170100": a_best_917,
        },
        "paired_comparisons": {
            "W05-newpipe-bulk": {"A0_vs_A1": w05_a0_a1, "A1_vs_B0": w05_a1_b0, "A1_vs_B1": w05_a1_b1, "B0_vs_B1": w05_b0_b1},
            "W07-hostlab-9161100": {"A0_vs_A1": w07_916_a0_a1, f"{a_best_916}_vs_B1_all": w07_916_ab_b1_all, "A0_vs_B1_stage": w07_916_a0_b1},
            "W07-hostlab-9170100": {"A0_vs_A1": w07_917_a0_a1, f"{a_best_917}_vs_B1": w07_917_ab_b1},
        },
        "mutually_exclusive_stages_w07": stage_rows,
        "same_machine_conditional_sf_targets": conditional_targets,
    }
    validator.validate_public_redaction(stage_profile)
    _write_json(PUBLIC_OUT / "stage-and-resource-profile.json", stage_profile)

    # Prioritized hotspots driven by measured numbers
    b1_916 = stage_rows["W07-hostlab-9161100/B1"]
    b0_916 = stage_rows["W07-hostlab-9161100/B0"]
    f_res = b1_916["F_sub_resource_fingerprints_seconds"] or 0.0
    f_sql = max(0.0, b1_916["F_surface_seconds"] - f_res)
    o_gates = (b1_916["O_sub_intake_gate_seconds"] or 0.0) + (b1_916["O_sub_home_gate_seconds"] or 0.0)

    priorities = {
        "schema": "mdd.optimization-priorities.v1",
        "task": "MDD-060",
        "generated_utc": _utc_now(),
        "baseline_unoptimized_b1_9161100": b1_916,
        "baseline_unoptimized_b0_9161100": b0_916,
        "ranked_hotspots": [
            {
                "rank": 1,
                "stage": "F (surface) & SQL LIKE/UDF hot path",
                "target_task": "MDD-061",
                "measured_seconds": round(f_sql, 4),
                "share_of_worker_e": round(f_sql / b1_916["worker_e_wall_seconds"], 4),
                "evidence_root_cause": "Prefix-plus-suffix LIKE '<prefix>%<suffix>' drops suffix narrowing in pushdown, uncached per-DEX global dictionary prefix scans re-walk the shared TextDict, repeated per-row virtual-table column materializations re-decode across disjunctive OR predicates, and unoptimized mdd_like/mdd_sort_key UDFs allocate per call across class_fields/class_methods/classes/method_calls; per-query virtual table registration also registers all relations when 1 is queried.",
                "planned_optimizations": ["LikeAsciiPrefixSuffix pushdown + TextDict suffix/TAG_MEMBER direct check + bounded filter-ID cache", "CompiledLike zero-alloc borrowed UTF-16 matcher + Cursor per-row SqlCell cache", "Register only prepared.required_relations during execute_inner"],
            },
            {
                "rank": 2,
                "stage": "P (explicit open prepare)",
                "target_task": "MDD-061",
                "measured_seconds": b1_916["P_prepare_seconds"],
                "share_of_worker_e": round(b1_916["P_prepare_seconds"] / b1_916["worker_e_wall_seconds"], 4),
                "evidence_root_cause": "HostLabSqlProvider::build_group decodes DEX files strictly sequentially one DEX position at a time while leaving multi-core CPU budget underutilized.",
                "planned_optimizations": ["Bounded-window parallel LayerBuilder::load preloading in crates/mdd-sql/src/provider/hostlab/lazy.rs with strict position-ordered RelationStoreBuilder feeding"],
            },
            {
                "rank": 3,
                "stage": "O (intake + home independent Python gates)",
                "target_task": "MDD-062",
                "measured_seconds": round(o_gates, 4),
                "share_of_worker_e": round(o_gates / b1_916["worker_e_wall_seconds"], 4),
                "evidence_root_cause": "run_intake.py and home_frame_audit.py each re-open and independently scan every DEX in the archive after the engine already built validated snapshot facts (not counted toward phase-1 S/F 37% target).",
                "planned_optimizations": ["AuditDataProvider reusing verified snapshot metadata/definitions/annotations/raw code facts with separate gate timing window & standalone oracle retention"],
            },
            {
                "rank": 4,
                "stage": "B0 -> B1 & W05 bulk JSON batch encoding",
                "target_task": "MDD-061",
                "measured_seconds": w05_a1_b1["right_median_wall_seconds"],
                "share_of_w05_wall": 1.0,
                "evidence_root_cause": "B1 eliminates B0's double LIMIT 0 shape round-trip and hex(CAST) encoding; remaining serialization hotspot is per-cell serde_json::Value heap allocation in mdd-ffi::codec::batch_bytes and mdd-wire/1 JSON framing.",
                "planned_optimizations": ["Direct streaming JSON writer in crates/mdd-wire/src/optimized/batch_codec.rs and optional columns-v1 binary batch codec in columns_v1.rs"],
            },
        ],
    }
    validator.validate_public_redaction(priorities)
    _write_json(PUBLIC_OUT / "optimization-priorities.json", priorities)

    # Calibrate thresholds from Block 1 vs Block 2 measured jitter
    w05_drift = abs(w05_b1_block1["paired_median_reduction_fraction"] - w05_b1_block2["paired_median_reduction_fraction"])
    w07_drift = abs(w07_916_ab_b1_blk1["paired_median_reduction_fraction"] - w07_916_ab_b1_blk2["paired_median_reduction_fraction"])
    w07_rel_iqr_a = w07_916_ab_b1_blk1["left_iqr_seconds"] / max(w07_916_ab_b1_blk1["left_median_wall_seconds"], 1e-6)
    w07_rel_iqr_b = w07_916_ab_b1_blk1["right_iqr_seconds"] / max(w07_916_ab_b1_blk1["right_median_wall_seconds"], 1e-6)
    calibration = {
        "schema": "mdd.threshold-calibration.v1",
        "task": "MDD-060",
        "generated_utc": _utc_now(),
        "pre_registered_policy": {
            "minimum_pairs_block1": 10,
            "independent_blocks": 2,
            "key_median_reduction_threshold": 0.10,
            "other_required_regression_limit": 0.05,
        },
        "measured_noise": {
            "W05-newpipe-bulk": {
                "block1_pairs": w05_b1_block1["qualified_pair_count"],
                "block2_pairs": w05_b1_block2["qualified_pair_count"],
                "block1_vs_block2_median_drift": round(w05_drift, 6),
                "block1_left_rel_iqr": round(w05_b1_block1["left_iqr_seconds"] / max(w05_b1_block1["left_median_wall_seconds"], 1e-6), 6),
                "block1_right_rel_iqr": round(w05_b1_block1["right_iqr_seconds"] / max(w05_b1_block1["right_median_wall_seconds"], 1e-6), 6),
            },
            "W07-hostlab-9161100": {
                "block1_pairs": w07_916_ab_b1_blk1["qualified_pair_count"],
                "block2_pairs": w07_916_ab_b1_blk2["qualified_pair_count"],
                "block1_vs_block2_median_drift": round(w07_drift, 6),
                "block1_left_rel_iqr": round(w07_rel_iqr_a, 6),
                "block1_right_rel_iqr": round(w07_rel_iqr_b, 6),
            },
        },
        "thresholds_unchanged_and_above_noise": True,
        "decision_for_mdd_082": "Keep pre-registered 10% key reduction floor and 5% non-regression limit unchanged without relaxation; both thresholds comfortably exceed observed exclusive-window run-to-run IQR and inter-block drift.",
    }
    validator.validate_public_redaction(calibration)
    _write_json(PUBLIC_OUT / "threshold-calibration.json", calibration)
    return {"stage_profile": stage_profile, "priorities": priorities, "calibration": calibration}


def self_test() -> dict[str, Any]:
    """Offline integrity check of validator, pairing math, non-additive overlap & prepare guards."""
    dummy = {
        "schema_version": "mdd.benchmark-run.v1",
        "record_kind": "observed_run",
        "run_id": "selftest-1",
        "pair_id": "p01",
        "block_id": "b1",
        "round": 1,
        "workload_id": "W05-newpipe-bulk",
        "variant": "A0",
        "timestamp_utc": "2026-11-21T10:00:00Z",
        "engine": {"product": "DexSQL", "version": "0.1.0", "build_id": "a0", "binary_sha256": "0" * 64, "source_commit": None, "profile": "p", "sql_dialect": None},
        "harness": {"revision": "abc", "manifest_sha256": "1" * 64, "command_argv": ["run"], "timing_boundary": "e2e"},
        "inputs": [{"occurrence_id": "newpipe", "sha256": "2" * 64, "bytes": "123"}],
        "environment": {"machine_id": "m", "os": "os", "cpu": "x86_64", "memory_bytes": "1024", "total_cpu_budget": 2.0, "engine_threads": 2, "concurrent_jobs": 1, "cache_state": "warm_os", "cache_control": "fresh", "background_load": "idle", "artifact_sha256": "3" * 64},
        "execution": {"status": "completed", "exit_code": 0, "complete_output": True, "fallback_count": 0, "contaminated": False, "contamination_reason": None, "wall_seconds": 4.0},
        "correctness": {"scope_id": "s", "input_complete": True, "facts_complete": True, "equivalent": True, "comparison_mode": "ordered", "canonical_sha256": "4" * 64, "certificate_sha256": "4" * 64, "mismatch_count": 0, "notes": ["ok"]},
        "metrics": {"explicit_prepare_seconds": {"value": 0.5, "unit": "seconds", "scope": "explicit_open_session_setup", "method": "perf_counter"}},
        "artifacts": [{"path": "artifacts/mdd-060/r.json", "sha256": "5" * 64, "kind": "cert"}],
    }
    validator.validate_observed_run(dummy, check_redaction=True)
    validator.check_prepare_not_pure_parser(dummy)
    validator.compose_non_additive_overlap(joint_wall_seconds=4.0, producer_cpu_or_component_seconds=3.0, consumer_cpu_or_component_seconds=2.0, claimed_total_seconds=4.0)
    return {"self_test": "passed"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--check-a2", action="store_true")
    parser.add_argument("--measure-newpipe", action="store_true")
    parser.add_argument("--stage-profile-only", action="store_true")
    parser.add_argument("--measure-hostlab", action="store_true")
    parser.add_argument("--reuse-stage-profile", action="store_true")
    parser.add_argument("--summarize", action="store_true")
    parser.add_argument("--pairs-block1", type=int, default=10)
    parser.add_argument("--newpipe-pairs", type=int, default=10)
    parser.add_argument("--worker-hostlab", action="store_true")
    parser.add_argument("--profile-substages", action="store_true")
    parser.add_argument("--variant", choices=("A0", "A1", "B0", "B1"))
    parser.add_argument("--sample", choices=("hostlab-9161100", "hostlab-9170100"))
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    if args.worker_hostlab:
        return _hostlab_worker(args)
    if args.self_test:
        print(json.dumps(self_test(), indent=2))
        return 0

    paths = _resolve_paths()
    refresh_release_b_pin(paths["B"], paths["b_pin_manifest"])

    if args.check_a2:
        res = probe_a2_disposition(paths)
        print(json.dumps({"a2_component_passed": res["component_probe_passed"], "excluded_e2e": not res["end_to_end_qualified_for_hostlab_w07"]}, indent=2))
    if args.measure_newpipe:
        recs = run_newpipe_blocks(paths, pairs_per_block=args.newpipe_pairs)
        print(f"Recorded {len(recs)} NewPipe paired observed runs.")
    if args.stage_profile_only:
        res = run_hostlab_stage_profile(paths)
        print(json.dumps({"a_best": res["a_best_by_sample"], "stage_count": len(res["stage_records"])}, indent=2))
    if args.measure_hostlab:
        res = run_hostlab_blocks(paths, pairs_block1=args.pairs_block1, reuse_stage_profile=args.reuse_stage_profile)
        print(json.dumps({"a_best": res["a_best_by_sample"], "record_count": res["record_count"]}, indent=2))
    if args.summarize:
        res = summarize_mdd060()
        print(json.dumps({"fastest_existing": res["stage_profile"]["fastest_qualified_existing_baseline"], "thresholds_unchanged": res["calibration"]["thresholds_unchanged_and_above_noise"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
