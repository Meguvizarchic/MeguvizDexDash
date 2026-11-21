#!/usr/bin/env python3
"""Unit and differential controls for MDD-065 generic DEX/APK consumer (`examples/generic-dex-audit`).

Usage:
    python -I conformance/generic-consumer/test_generic_consumer.py
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EXAMPLE_DIR = ROOT / "examples" / "generic-dex-audit"
AUDIT_PY = EXAMPLE_DIR / "audit.py"
PUBLIC_APK = HERE / "fixtures" / "public-app-audit.apk"
AB1_DEX = ROOT / "tests/fixtures/desktop/generated/ab1.dex"
AB2_DEX = ROOT / "tests/fixtures/desktop/generated/ab2.dex"

sys.path.insert(0, str(HERE))
import oracle  # noqa: E402

sys.path.insert(0, str(ROOT / "conformance" / "mcp"))
import tiny_dex  # noqa: E402

sys.path.insert(0, str(ROOT / "python"))
import mdd  # noqa: E402

STDLIB_AND_SDK_ALLOWED = {
    "__future__",
    "argparse",
    "hashlib",
    "json",
    "os",
    "pathlib",
    "subprocess",
    "sys",
    "typing",
    "mdd",
}

FORBIDDEN_TOKENS = (
    "integrations",
    "hostlab",
    "tv.danmaku",
    "tv/danmaku",
    "bilibili",
    "feature_",
    "dexmeguviz",
    "dexkit",
)


def _find_binary() -> Path:
    explicit = os.environ.get("MDD_WORKER_BINARY")
    if explicit and Path(explicit).is_file():
        return Path(explicit).resolve()
    name = "meguvizdexdash.exe" if sys.platform == "win32" else "meguvizdexdash"
    candidates = [ROOT / "target" / profile / name for profile in ("debug", "release") if (ROOT / "target" / profile / name).is_file()]
    if not candidates:
        raise FileNotFoundError("meguvizdexdash binary not built")
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _find_ffi_for(binary: Path) -> Path:
    explicit = os.environ.get("MDD_FFI_LIBRARY")
    if explicit and Path(explicit).is_file():
        return Path(explicit).resolve()
    name = "mdd_ffi.dll" if sys.platform == "win32" else ("libmdd_ffi.dylib" if sys.platform == "darwin" else "libmdd_ffi.so")
    sibling = binary.parent / name
    if sibling.is_file():
        return sibling
    return mdd.library().path


def scan_python_boundary(source: str, filename: str = "audit.py") -> list[str]:
    """Static AST + token check proving no business adapter or duplicate parser imports."""
    violations: list[str] = []
    tree = ast.parse(source, filename=filename)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_pkg = alias.name.split(".", 1)[0]
                if root_pkg not in STDLIB_AND_SDK_ALLOWED:
                    violations.append(f"disallowed import: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".", 1)[0]
            if mod not in STDLIB_AND_SDK_ALLOWED:
                violations.append(f"disallowed import-from: {node.module}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            # Ignore module/class/function docstrings; check runtime literals and SQL.
            low = node.value.lower()
            if "public sdk/worker/mcp only" in low:
                continue
            for tok in FORBIDDEN_TOKENS:
                if tok in low:
                    violations.append(f"forbidden runtime string token {tok!r} in {node.value!r}")
    for tok in ("hostlab", "tv.danmaku", "tv/danmaku", "bilibili", "dexmeguviz", "dexkit"):
        # Check non-comment executable lines (strip # comments and docstrings)
        for lineno, line in enumerate(source.splitlines(), start=1):
            code_part = line.split("#", 1)[0].lower()
            if "core_boundary" in code_part or "help=" in code_part or '"""' in code_part:
                continue
            if re.search(rf"\b{re.escape(tok)}", code_part):
                violations.append(f"line {lineno}: forbidden code token {tok!r}")
    return violations


def _load_audit_module():
    spec = importlib.util.spec_from_file_location("mdd_generic_dex_audit", AUDIT_PY)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load examples/generic-dex-audit/audit.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class BoundaryAndOwnershipTests(unittest.TestCase):
    def test_consumer_boundary_clean(self):
        source = AUDIT_PY.read_text(encoding="utf-8")
        self.assertEqual(scan_python_boundary(source, str(AUDIT_PY)), [])
        toml = (EXAMPLE_DIR / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("dependencies = []", toml)
        self.assertIn("include/mdd.h", toml)

    def test_boundary_scanner_rejects_adapter_coupling_negative_control(self):
        bad_samples = [
            "import integrations.hostlab.native_session\n",
            "from bilibili.rules import check\n",
            "x = 'SELECT * FROM method_calls WHERE class_descriptor LIKE \"Ltv/danmaku/%\"'\n",
            "y = 'FEATURE_CUSTOM_ADAPTER'\n",
            "import dexkit\n",
        ]
        for sample in bad_samples:
            self.assertTrue(scan_python_boundary(sample), f"failed to reject coupled sample: {sample!r}")

    def test_completeness_guard_rejects_partial_or_truncated_terminal(self):
        audit_mod = _load_audit_module()
        good_terminal = {
            "operation_status": "ok",
            "execution": {"complete": True},
            "response": {"truncated": False, "more_available": False, "next_cursor": None},
            "coverage": {"input": "complete", "facts": "complete"},
        }
        audit_mod._verify_sdk_completeness(mdd.Result((), [], good_terminal), "ok")
        for mutator in (
            lambda t: t["response"].__setitem__("truncated", True),
            lambda t: t["response"].__setitem__("more_available", True),
            lambda t: t["response"].__setitem__("next_cursor", "cursor-1"),
            lambda t: t["execution"].__setitem__("complete", False),
            lambda t: t["coverage"].__setitem__("facts", "incomplete"),
            lambda t: t.__setitem__("operation_status", "error"),
        ):
            bad = json.loads(json.dumps(good_terminal))
            mutator(bad)
            with self.assertRaises(audit_mod.AuditError):
                audit_mod._verify_sdk_completeness(mdd.Result((), [], bad), "damaged")


class ConsumerExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.binary = _find_binary()
        cls.ffi_lib = _find_ffi_for(cls.binary)
        cls.audit_mod = _load_audit_module()

    def _run(self, extra_args: list[str]) -> dict:
        return self.audit_mod.run_audit([*extra_args, "--binary", str(self.binary), "--ffi-lib", str(self.ffi_lib)])

    def test_public_apk_all_transports_match_oracle_and_each_other(self):
        rep_ffi = self._run(["--input", str(PUBLIC_APK), "--transport", "in-process"])
        rep_wnat = self._run(["--input", str(PUBLIC_APK), "--transport", "worker", "--dialect", "native-v1"])
        rep_wdex = self._run(["--input", str(PUBLIC_APK), "--transport", "worker", "--dialect", "dexsql-0.1.1"])
        rep_mcp = self._run(["--input", str(PUBLIC_APK), "--transport", "mcp", "--dialect", "dexsql-0.1.1"])

        self.assertEqual(rep_ffi["snapshot"]["snapshot_content_key"], rep_mcp["snapshot"]["snapshot_content_key"])
        self.assertEqual(rep_ffi["structure_audit"], rep_wnat["structure_audit"])
        self.assertEqual(rep_ffi["structure_audit"], rep_wdex["structure_audit"])
        self.assertEqual(rep_ffi["structure_audit"], rep_mcp["structure_audit"])
        self.assertEqual(rep_wdex["reachability_audit"], rep_mcp["reachability_audit"])

        ind = oracle.read_inputs([PUBLIC_APK])
        self.assertEqual(rep_ffi["structure_audit"]["occurrence_count"], 5)
        self.assertEqual(rep_ffi["structure_audit"]["distinct_content_count"], 4)
        self.assertEqual(ind["occurrence_count"], 5)
        self.assertEqual(ind["distinct_content_count"], 4)
        self.assertEqual(rep_ffi["structure_audit"]["classes"], ind["classes"])
        self.assertEqual(rep_ffi["structure_audit"]["defined_methods"], ind["defined_methods"])

        reach = rep_mcp["reachability_audit"]
        self.assertEqual(reach["distinct_edge_count"], 4)
        self.assertEqual(reach["total_call_site_count"], 5)
        self.assertEqual(reach["cross_dex_edge_count"], 4)
        # MainActivity.onCreate invokes Transport.connect twice -> call_site_count == 2
        dup_edge = [e for e in reach["edges"] if e["caller_descriptor"].endswith("MainActivity;->onCreate()V")]
        self.assertEqual(len(dup_edge), 1)
        self.assertEqual(dup_edge[0]["call_site_count"], 2)
        self.assertEqual(dup_edge[0]["callee_defined_in_file_ids"], [2, 3])

        # Verify raw bytecode digests against independent oracle and ensure MUTF-8 NUL survived cleanly.
        all_reachable_strings: list[str] = []
        for rm in reach["reachable_methods"]:
            oc = ind["occurrences"][rm["file_id"]]["code_by_method"][rm["method_idx"]]
            self.assertEqual(rm["code_off"], oc["code_off"])
            self.assertEqual(rm["insns_size"], oc["insns_size"])
            self.assertEqual(rm["opcode_sha256"], oc["opcode_sha256"])
            all_reachable_strings.extend(s for s in rm["referenced_strings"] if isinstance(s, str))
        self.assertIn("audit\u0000tag", all_reachable_strings)

        # Verify MCP enrichment exported components and separate display Smali.
        comps = rep_mcp["mcp_enrichment"]["exported_components"]
        self.assertEqual(len(comps), 2)
        self.assertEqual(rep_mcp["mcp_enrichment"]["smali_preview"]["text_format"], "mdd.smali.v1")
        self.assertFalse(rep_mcp["mcp_enrichment"]["smali_preview"]["replaces_raw_bytecode_facts"])

    def test_desktop_multi_dex_pair_cross_transport(self):
        rep_ffi = self._run(["--input", str(AB1_DEX), "--input", str(AB2_DEX), "--transport", "in-process"])
        rep_mcp = self._run(["--input", str(AB1_DEX), "--input", str(AB2_DEX), "--transport", "mcp", "--dialect", "dexsql-0.1.1"])
        self.assertEqual(rep_ffi["snapshot"]["snapshot_content_key"], rep_mcp["snapshot"]["snapshot_content_key"])
        self.assertEqual(rep_ffi["structure_audit"], rep_mcp["structure_audit"])
        self.assertEqual(rep_mcp["reachability_audit"]["cross_dex_edge_count"], 2)

    def test_cancel_probe_and_failure_refusals(self):
        rep = self._run(["--input", str(PUBLIC_APK), "--transport", "in-process", "--cancel-probe"])
        self.assertEqual(rep["cancel_probe"]["status"], "passed")
        self.assertEqual(rep["cancel_probe"]["error_code"], "CANCELLED")
        rep_w = self._run(["--input", str(PUBLIC_APK), "--transport", "worker", "--dialect", "native-v1", "--cancel-probe"])
        self.assertEqual(rep_w["cancel_probe"]["status"], "passed")

        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.dex"
            with self.assertRaises(self.audit_mod.AuditError) as ctx:
                self._run(["--input", str(missing), "--transport", "in-process"])
            self.assertEqual(ctx.exception.code, "INVALID_INPUT")
            bad = Path(tmp) / "corrupt.dex"
            bad.write_bytes(b"dex\n035\x00" + b"\x00" * 104)
            with self.assertRaises(self.audit_mod.AuditError) as ctx2:
                self._run(["--input", str(bad), "--transport", "worker", "--dialect", "dexsql-0.1.1"])
            self.assertEqual(ctx2.exception.code, "INVALID_INPUT")

    def test_dynamic_nonce_dex_not_hardcoded(self):
        nonce = f"mdd-nonce-{uuid.uuid4().hex}"
        dex_bytes = tiny_dex.build(
            "Lorg/dynamic/Probe;",
            [
                {
                    "name": "main",
                    "access": 0x9,
                    "registers": 1,
                    "outs": 0,
                    "code": [("const-string", 0, nonce), ("return-void",)],
                }
            ],
        )
        with tempfile.TemporaryDirectory() as tmp:
            dex_path = Path(tmp) / "dynamic.dex"
            dex_path.write_bytes(dex_bytes)
            ind = oracle.parse_dex(dex_bytes)
            rep = self._run(["--input", str(dex_path), "--transport", "mcp", "--dialect", "dexsql-0.1.1"])
            rm = rep["reachability_audit"]["reachable_methods"][0]
            self.assertIn(nonce, rm["referenced_strings"])
            expected_sha256 = f"sha256:{hashlib.sha256(dex_bytes).hexdigest()}"
            rep_ffi = self._run(["--input", str(dex_path), "--transport", "in-process"])
            self.assertEqual(rep_ffi["snapshot"]["dex_occurrences"][0]["content_id"], expected_sha256)
            self.assertEqual(rm["opcode_sha256"], ind["code_by_method"][0]["opcode_sha256"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
