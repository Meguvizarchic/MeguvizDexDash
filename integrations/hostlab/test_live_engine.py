"""The provider against the real `meguvizdexdash` binary. A missing binary fails the run; it is never skipped.

Needs the binary (`cargo build -p mdd-cli`) or MDD_WORKER_BINARY. No network, no download.
Run: python -I -m unittest discover -s integrations/hostlab -p "test_live_engine.py"

What is checked here and cannot be checked with a stand-in: that the installer's handshake works on the
real `version`, `capabilities` and `mcp`; that the arguments the provider builds are accepted by the engine
and DexSQL's are not; that the errors the engine really sends fall on the right side of the fallback rule;
and that the physical-DEX gate meets the real engine's `dex_files`.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hostlab_test_support as support  # noqa: E402
import install_meguvizdexdash as installer  # noqa: E402
import provider  # noqa: E402

ROOT = support.ROOT
ENGINE = provider.ENGINE
LEGACY = support.load_frozen("analysis_plan")
DEX = ROOT / "tests/fixtures/decode/generated/decode-all.dex"
MULTIDEX = ROOT / "tests/fixtures/generated/multidex-deflated.apk"
BAD_MEMBER = ROOT / "tests/fixtures/generated/invalid-dex-member.apk"


def find_binary() -> Path:
    explicit = os.environ.get("MDD_WORKER_BINARY")
    if explicit:
        return Path(explicit)
    name = "meguvizdexdash.exe" if sys.platform == "win32" else "meguvizdexdash"
    found = [ROOT / "target" / profile / name for profile in ("release", "debug") if (ROOT / "target" / profile / name).is_file()]
    if not found:
        raise AssertionError("the meguvizdexdash binary was not found; build it with `cargo build -p mdd-cli` "
                             "or set MDD_WORKER_BINARY (this test is never skipped)")
    return max(found, key=lambda path: path.stat().st_mtime)


class McpSession:
    """The smallest client HostLab's flow needs: initialize, call a tool, close."""

    def __init__(self, launched: provider.Launch):
        self.process = subprocess.Popen([launched.command, *launched.args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, env=launched.env)
        self.count = 0
        self.rpc("initialize", {"protocolVersion": installer.MCP_PROTOCOL, "capabilities": {},
                                "clientInfo": {"name": "provider-live-test", "version": "1"}})
        self.process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        self.process.stdin.flush()

    def rpc(self, method, params=None):
        self.count += 1
        message = {"jsonrpc": "2.0", "id": self.count, "method": method}
        if params is not None:
            message["params"] = params
        self.process.stdin.write((json.dumps(message) + "\n").encode())
        self.process.stdin.flush()
        return json.loads(self.process.stdout.readline())

    def call(self, name, **arguments):
        result = self.rpc("tools/call", {"name": name, "arguments": arguments})["result"]
        return result["isError"], result["structuredContent"]

    def close(self):
        self.process.stdin.close()
        code = self.process.wait(30)
        self.process.stdout.close()
        self.process.stderr.close()
        return code

    def abort(self):
        """Cleanup for a test that failed half way: the engine must not outlive it."""
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(30)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except OSError:
                    pass


class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = find_binary()
        cls.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.dir = Path(cls.tmp.name).resolve()
        cls.manifest = cls.dir / "manifest.json"
        cls.entry = installer.pin(cls.binary, cls.manifest)
        cls.config = provider.parse_config({"schema": provider.CONFIG_SCHEMA, "native_engine": ENGINE, ENGINE: {
            "manifest": str(cls.manifest), "profile_policy": "allow_unadmitted",
            "fallback": {"to": "dexsql", "on": ["UNSUPPORTED_QUERY", "UNSUPPORTED_CAPABILITY", "UNAVAILABLE_BACKEND"]}}})
        cls.state = cls.dir / "state"
        cls.legacy_files = {"dexq-cache/abcd.sqlite": b"legacy index", "reports/1/aa/20261101/report.json": b"old report"}
        for relative, content in cls.legacy_files.items():
            (cls.state / relative).parent.mkdir(parents=True, exist_ok=True)
            (cls.state / relative).write_bytes(content)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def session(self, launched=None):
        session = McpSession(launched or self.launch())
        self.addCleanup(session.abort)
        return session

    def launch(self, **options):
        with mock.patch.dict(os.environ, {installer.ENV_BINARY: str(self.binary)}):
            return provider.launch(options.get("config", self.config), threads=2, timeout_seconds=60, state=self.state)

    def test_the_real_binary_pins_verifies_and_installs(self):
        entry = self.entry
        described = subprocess.run([str(self.binary), "version"], capture_output=True, check=True).stdout
        version = json.loads(described)
        self.assertEqual((entry["engine_version"], entry["build_id"]), (version["engine_version"], version["build_id"]))
        self.assertEqual(entry["sha256"], installer.sha256(self.binary))
        self.assertEqual(entry["mcp_tools"], sorted(["open_dataset", "list_datasets", "close_dataset", "list_tables",
                                                     "describe_table", "query", "decode", "get_manifest",
                                                     "get_manifest_components", "list_resource_files",
                                                     "read_resource", "query_resources"]))
        status = installer.status(self.binary, self.manifest, deep=True)
        self.assertTrue(status["available"], status)
        vendor = self.dir / "vendor" / "meguvizdexdash"
        target = installer.install(self.binary, self.manifest, vendor=vendor)
        self.assertEqual(installer.sha256(target), entry["sha256"])
        self.assertTrue(installer.status(target, self.manifest, deep=True)["available"])

    def test_a_copy_with_one_changed_byte_is_not_the_pinned_engine(self):
        copy = self.dir / self.binary.name.replace("meguvizdexdash", "altered")
        copy.write_bytes(self.binary.read_bytes() + b"\x00")
        status = installer.status(copy, self.manifest, deep=True)
        self.assertEqual((status["available"], status["reason"]), (False, "digest_mismatch"))

    def test_the_old_installer_and_the_old_setting_do_not_accept_the_new_binary(self):
        legacy = support.load_frozen("install_dexsql")
        with self.assertRaises(RuntimeError):
            legacy.verify(self.binary)
        with mock.patch.dict(os.environ, {"HOSTLAB_DEXSQL": str(self.binary)}):
            self.assertFalse(legacy.status()["available"])

    def test_the_engine_takes_the_providers_arguments_and_refuses_dexsqls(self):
        refused = subprocess.run([str(self.binary), "--threads", "2", "mcp", "--timeout-ms", "1000", "--max-datasets", "1"],
                                 capture_output=True, input=b"", timeout=30)
        self.assertEqual(refused.returncode, 2)
        self.assertEqual(json.loads(refused.stderr.splitlines()[-1])["code"], "INVALID_ARGUMENT")
        session = self.session()
        self.assertEqual(session.close(), 0)

    def test_the_plan_names_the_real_engine_and_does_not_hide_that_no_profile_is_admitted(self):
        status = installer.status(self.binary, self.manifest, deep=True)
        with self.assertRaises(provider.ProviderUnavailable) as caught:
            provider.plan({"schema": 1, "backend": ENGINE, "tasks": [
                {"id": "q", "operation": "query", "sql": "SELECT 1", "dialect": "dexsql"}]},
                provider.parse_config({"schema": provider.CONFIG_SCHEMA, "native_engine": ENGINE}),
                legacy=LEGACY, engine_status=status)
        self.assertEqual(caught.exception.reason, "profile_not_admitted")
        result = provider.plan({"schema": 1, "tasks": [{"id": "q", "operation": "query", "sql": "SELECT 1", "dialect": "dexsql"},
                                                       {"id": "d", "operation": "decode", "method": "Lfoo;->bar()V"},
                                                       {"id": "i", "operation": "info"}]},
                               self.config, legacy=LEGACY, engine_status=status)
        engine = result["provider"]["engine"]
        self.assertEqual({t["backend"] for t in result["tasks"]}, {ENGINE})
        self.assertEqual((engine["engine_version"], engine["build_id"]), (self.entry["engine_version"], self.entry["build_id"]))
        self.assertFalse(engine["profile"]["admitted"])
        self.assertEqual(engine["dialect"]["engine"], "dexsql-0.1.0")

    def test_a_session_from_the_launch_description_meets_the_physical_dex_gate(self):
        launched = self.launch()
        apk = provider.controlled_input(MULTIDEX, [MULTIDEX.parent])
        expected = provider.archive_inventory(apk)
        session = self.session(launched)
        failed, opened = session.call("open_dataset", inputs=[str(apk)])
        self.assertFalse(failed, opened)
        self.assertTrue(opened["has_dex"])
        failed, answer = session.call("query", dataset_id=opened["dataset_id"], limit=1000, offset=0, timing=True,
                                      sql=["SELECT file_id,entry_name FROM dex_files ORDER BY file_id"])
        self.assertFalse(failed, answer)
        statement = answer["statements"][0]
        files = {int(row[0]["value"]): row[1]["value"] for row in statement["rows"]}
        self.assertEqual((statement["truncated"], statement["next_offset"]), (False, None))
        self.assertEqual(files, {0: "classes.dex", 1: "classes2.dex"})
        provider.verify_inventory(expected, files)
        with self.assertRaises(provider.InventoryError) as lost:
            provider.verify_inventory(expected, {0: "classes.dex"})
        self.assertEqual(lost.exception.detail, {"missing": ["classes2.dex"], "unexpected": []})
        self.assertFalse(session.call("close_dataset", dataset_id=opened["dataset_id"])[0])
        self.assertEqual(session.close(), 0)
        self.assertEqual(launched.identity["binary_sha256"], self.entry["sha256"])

    def test_the_errors_the_engine_really_sends_fall_on_the_right_side_of_the_rule(self):
        BackendError = support.frozen_batch(self.dir).BackendError
        session = self.session()
        failed, opened = session.call("open_dataset", inputs=[str(DEX)])
        self.assertFalse(failed)
        task = {"id": "q", "backend": ENGINE, "forced": False}
        taken = {}
        for label, sql in (("unimplemented function", "SELECT typeof(1) FROM dex_files"),
                           ("unknown relation", "SELECT * FROM no_such_table")):
            failed, answer = session.call("query", dataset_id=opened["dataset_id"], sql=[sql], limit=10)
            self.assertTrue(failed, label)
            error = BackendError("backend rejected operation", answer)
            audit = provider.AuditLog()

            def primary(error=error):
                raise error

            def fallback():
                return {"rows": [["from dexsql"]], "partial": False}
            try:
                taken[label] = provider.run_with_policy(task, primary, fallback, config=self.config, negotiation={}, audit=audit)
            except BackendError as raised:
                self.assertIs(raised, error)
                taken[label] = "raised " + raised.detail["error"]["code"]
            self.assertEqual(audit.records[0]["failure"]["origin"], "engine")
        self.assertEqual(taken["unknown relation"], "raised INVALID_ARGUMENT")
        self.assertEqual(taken["unimplemented function"]["fallback"]["code"], "UNSUPPORTED_QUERY")
        self.assertEqual(taken["unimplemented function"]["fallback"]["primary_failure"]["code"], "UNSUPPORTED_QUERY")
        failed, _ = session.call("query", dataset_id=opened["dataset_id"], sql=["SELECT file_id FROM dex_files"], limit=10)
        self.assertFalse(failed, "a rejected statement does not close the dataset")
        session.close()

    def test_a_member_the_engine_cannot_read_is_a_failure_with_evidence_not_a_skipped_member_or_a_fallback(self):
        BackendError = support.frozen_batch(self.dir).BackendError
        session = self.session()
        failed, answer = session.call("open_dataset", inputs=[str(BAD_MEMBER)])
        self.assertTrue(failed)
        self.assertEqual(answer["error"]["code"], "INVALID_INPUT")
        self.assertEqual(answer["error"]["details"]["input_coverage"], "partial")
        error = BackendError("backend rejected operation", answer)
        audit = provider.AuditLog()
        calls = []

        def primary():
            raise error

        def fallback():
            calls.append(1)
            return {}

        with self.assertRaises(BackendError) as raised:
            provider.run_with_policy({"id": "open", "backend": ENGINE, "forced": False}, primary, fallback, config=self.config,
                                     negotiation={}, audit=audit, source={"sha256": "ab" * 32, "size": 1})
        self.assertIs(raised.exception, error)
        self.assertEqual(calls, [])
        self.assertEqual(audit.records[0]["failure"]["code"], "INVALID_INPUT")
        self.assertEqual(raised.exception.detail["error"]["details"]["input_coverage"], "partial")
        session.close()

    def test_the_engine_writes_nothing_into_the_old_directories(self):
        launched = self.launch()
        session = self.session(launched)
        failed, opened = session.call("open_dataset", inputs=[str(DEX)])
        self.assertFalse(failed)
        session.call("query", dataset_id=opened["dataset_id"], sql=["SELECT file_id FROM dex_files"], limit=10)
        session.call("close_dataset", dataset_id=opened["dataset_id"])
        session.close()
        old = {p.relative_to(self.state).as_posix(): p.read_bytes() for p in self.state.rglob("*")
               if p.is_file() and "mdd-engine" not in p.parts}
        self.assertEqual(old, self.legacy_files)
        self.assertEqual(launched.env["MDD_CACHE_DIR"], str(launched.namespaces["cache"]))
        self.assertNotIn("DEXQ_CACHE_DIR", launched.env)


if __name__ == "__main__":
    unittest.main()
