"""The installer: what it refuses, and that it refuses before running anything.

Run: python -I -m unittest discover -s integrations/hostlab -p "test_install.py"
No network, no download, no real engine: a stand-in answers the handshake (test_live_engine.py uses the real one).
"""
import ast
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hostlab_test_support as support  # noqa: E402
import install_meguvizdexdash as installer  # noqa: E402

PLATFORM = installer.platform_key()


class InstallCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def pinned(self, **options):
        return support.pin_binary(self.dir, **options)

    def refused(self, reason, *args, **kwargs):
        with self.assertRaises(installer.EngineUnavailable) as caught:
            installer.verify(*args, **kwargs)
        self.assertEqual(caught.exception.reason, reason)
        self.assertEqual(caught.exception.code, "UNAVAILABLE_BACKEND")
        return caught.exception


class Pin(InstallCase):
    def test_a_pin_records_what_the_build_says_about_itself(self):
        binary, manifest, engine = self.pinned()
        document = json.loads(manifest.read_text(encoding="utf-8"))
        (entry,) = document["builds"]
        self.assertEqual(document["schema"], installer.MANIFEST_SCHEMA)
        self.assertEqual(entry["sha256"], installer.sha256(binary))
        self.assertEqual((entry["engine_version"], entry["build_id"]), ("0.1.0-test", support.BUILD_ID))
        self.assertEqual(entry["platform"], PLATFORM)
        self.assertEqual(entry["mcp_tools"], sorted(support.TOOLS))
        self.assertEqual([p["admitted"] for p in entry["profiles"]], [False, False])
        self.assertEqual(entry["implementation_scope"], "unqualified development build")

    def test_pinning_the_same_bytes_again_changes_nothing_and_a_conflicting_identity_is_refused(self):
        binary, manifest, engine = self.pinned()
        before = manifest.read_bytes()
        installer.pin(binary, manifest, runner=engine)
        self.assertEqual(manifest.read_bytes(), before)
        other = support.FakeEngine(version="0.9.9")
        with self.assertRaises(installer.EngineUnavailable) as caught:
            installer.pin(binary, manifest, runner=other)
        self.assertEqual(caught.exception.reason, "manifest_invalid")
        self.assertEqual(manifest.read_bytes(), before, "a conflicting pin must not rewrite the manifest")

    def test_a_second_build_is_added_beside_the_first(self):
        binary, manifest, engine = self.pinned()
        second = self.dir / "second.exe"
        second.write_bytes(b"stand-in engine 2")
        installer.pin(second, manifest, runner=support.FakeEngine(version="0.2.0", build_id="source-sha256:" + "cd" * 32))
        builds = json.loads(manifest.read_text(encoding="utf-8"))["builds"]
        self.assertEqual([b["engine_version"] for b in builds], ["0.1.0-test", "0.2.0"])

    def test_a_binary_that_is_not_the_product_is_not_pinned(self):
        binary = support.make_binary(self.dir)
        with self.assertRaises(installer.EngineUnavailable) as caught:
            installer.pin(binary, runner=support.FakeEngine(product="SomethingElse"))
        self.assertEqual(caught.exception.reason, "identity_mismatch")

    def test_a_binary_whose_handshake_fails_is_not_pinned(self):
        binary = support.make_binary(self.dir)
        for failing in ("version", "capabilities", "mcp"):
            with self.subTest(failing=failing), self.assertRaises(installer.EngineUnavailable) as caught:
                installer.pin(binary, runner=support.FakeEngine(fail=failing))
            self.assertEqual(caught.exception.reason, "handshake_failed")


class Verify(InstallCase):
    def test_a_pinned_binary_verifies_and_describes_itself(self):
        binary, manifest, engine = self.pinned()
        described = installer.status(binary, manifest, engine, deep=True)
        self.assertTrue(described["available"])
        self.assertEqual((described["version"], described["build_id"], described["sha256"]),
                         ("0.1.0-test", support.BUILD_ID, installer.sha256(binary)))
        self.assertEqual(described["mcp_tools"], sorted(support.TOOLS))

    def test_a_bad_sha_is_unusable_and_the_file_is_never_run(self):
        binary, manifest, engine = self.pinned()
        engine.calls.clear()
        binary.write_bytes(b"stand-in engine 1, altered")
        error = self.refused("digest_mismatch", binary, manifest, engine)
        self.assertEqual(engine.calls, [], "a binary with an unpinned digest must not be executed")
        self.assertNotIn(installer.sha256(binary), str(error), "the message names the pinned digests only by prefix")
        described = installer.status(binary, manifest, engine)
        self.assertEqual((described["available"], described["reason"], described["code"]),
                         (False, "digest_mismatch", "UNAVAILABLE_BACKEND"))

    def test_every_refusal_has_a_reason_and_none_of_them_runs_anything(self):
        binary, manifest, engine = self.pinned()
        engine.calls.clear()
        self.refused("binary_missing", self.dir / "absent.exe", manifest, engine)
        self.refused("manifest_missing", binary, self.dir / "absent.json", engine)
        self.refused("platform_unpinned", binary, manifest, engine, platform_name="Plan9/mips")
        self.assertEqual(engine.calls, [])

    def test_a_digest_pinned_for_another_platform_is_not_accepted_here(self):
        binary, manifest, engine = self.pinned()
        other = json.loads(manifest.read_text(encoding="utf-8"))
        other["builds"].append(dict(other["builds"][0], platform="Plan9/mips", sha256="ee" * 32))
        other["builds"][0]["platform"] = "Plan9/mips"
        self.refused("platform_unpinned", binary, other, engine)
        mixed = json.loads(manifest.read_text(encoding="utf-8"))
        mixed["builds"].append(dict(mixed["builds"][0], platform="Plan9/mips"))
        mixed["builds"][0]["sha256"] = "ee" * 32
        self.refused("platform_mismatch", binary, mixed, engine)

    def test_a_binary_that_reports_another_build_than_the_pin_is_refused(self):
        binary, manifest, engine = self.pinned()
        self.refused("identity_mismatch", binary, manifest, support.FakeEngine(build_id="source-sha256:" + "00" * 32))
        self.refused("identity_mismatch", binary, manifest, support.FakeEngine(version="9.9.9"))

    def test_the_deep_check_compares_capabilities_and_tools_with_the_pin(self):
        binary, manifest, engine = self.pinned()
        installer.verify(binary, manifest, engine, deep=True)
        self.refused("tools_mismatch", binary, manifest, support.FakeEngine(tools=support.TOOLS[:-1]), deep=True)
        self.refused("capabilities_mismatch", binary, manifest, support.FakeEngine(admitted=True), deep=True)
        # the shallow check is the cheap one used per run: it trusts the digest for the rest
        installer.verify(binary, manifest, support.FakeEngine(tools=support.TOOLS[:-1]))

    def test_an_mcp_server_that_reports_another_version_than_version_is_refused(self):
        binary = support.make_binary(self.dir)
        with self.assertRaises(installer.EngineUnavailable) as caught:
            installer.pin(binary, runner=support.FakeEngine(server_version="0.0.1"))
        self.assertEqual(caught.exception.reason, "identity_mismatch")

    def test_manifests_that_are_not_exactly_the_documented_shape_are_refused(self):
        binary, manifest, engine = self.pinned()
        good = json.loads(manifest.read_text(encoding="utf-8"))

        def with_build(**change):
            document = json.loads(json.dumps(good))
            document["builds"][0].update(change)
            return document

        for label, document in {
            "extra top-level key": dict(good, extra=1),
            "wrong schema": dict(good, schema="other"),
            "no builds": dict(good, builds=[]),
            "a digest that is not hex": with_build(sha256="XY" * 32),
            "a path as file name": with_build(file="../meguvizdexdash.exe"),
            "unsorted tools": with_build(mcp_tools=["query", "decode"]),
            "an admitted profile without its conformance digest": with_build(
                profiles=[{"name": "mdd-native-v1", "admitted": True, "conformance_manifest_sha256": None}]),
            "an unknown build key": with_build(url="https://example.invalid/engine"),
            "a duplicated pin": dict(good, builds=good["builds"] * 2),
        }.items():
            with self.subTest(label), self.assertRaises(installer.EngineUnavailable) as caught:
                installer.verify(binary, document, engine)
            self.assertEqual(caught.exception.reason, "manifest_invalid")

    def test_a_manifest_over_its_budget_or_not_json_is_refused(self):
        binary, manifest, engine = self.pinned()
        manifest.write_text("{not json", encoding="utf-8")
        self.refused("manifest_invalid", binary, manifest, engine)
        manifest.write_bytes(b" " * (installer.MANIFEST_LIMIT + 1))
        self.refused("manifest_invalid", binary, manifest, engine)

    def test_a_failure_that_is_not_a_refusal_is_not_swallowed(self):
        binary, manifest, engine = self.pinned()

        def broken(argv, stdin=None, timeout=30.0):
            raise RuntimeError("a bug in the runner")

        with self.assertRaises(RuntimeError):
            installer.status(binary, manifest, broken)


class NotTheOldBackend(InstallCase):
    def test_the_old_setting_cannot_point_at_this_engine(self):
        binary, manifest, engine = self.pinned()
        legacy = support.load_frozen("install_dexsql")
        with mock.patch.dict(os.environ, {"HOSTLAB_DEXSQL": str(binary)}):
            self.assertFalse(legacy.status()["available"], "the frozen DexSQL installer must reject the new engine")
            with self.assertRaises(RuntimeError):
                legacy.verify(binary)
            # and the new installer does not read the old setting
            self.refused("binary_missing", manifest=manifest, runner=engine, vendor=self.dir / "empty")

    def test_the_new_setting_is_its_own_variable(self):
        binary, manifest, engine = self.pinned()
        with mock.patch.dict(os.environ, {installer.ENV_BINARY: str(binary)}):
            self.assertEqual(installer.verify(manifest=manifest, runner=engine).path, binary.resolve())

    def test_a_pinned_binary_inside_the_legacy_install_directory_is_not_accepted(self):
        binary, manifest, engine = self.pinned()
        legacy_dir = self.dir / "vendor" / "dexsql"
        legacy_dir.mkdir(parents=True)
        inside = legacy_dir / binary.name
        shutil.copyfile(binary, inside)
        engine.calls.clear()
        with mock.patch.object(installer, "LEGACY_VENDOR", legacy_dir):
            self.refused("legacy_install_path", inside, manifest, engine)
            self.assertEqual(installer.status(inside, manifest, engine)["reason"], "legacy_install_path")
        self.assertEqual(engine.calls, [], "its digest is pinned, yet it is not run from there")
        installer.verify(binary, manifest, engine)  # the same bytes elsewhere are fine

    def test_the_legacy_install_directory_is_never_an_engine_location(self):
        legacy_dir = self.dir / "vendor" / "dexsql"
        legacy_dir.mkdir(parents=True)
        binary = support.make_binary(legacy_dir)
        engine = support.FakeEngine()
        with mock.patch.object(installer, "LEGACY_VENDOR", legacy_dir):
            with self.assertRaises(installer.EngineUnavailable) as caught:
                installer.pin(binary, runner=engine)
            self.assertEqual(caught.exception.reason, "legacy_install_path")
            self.assertEqual(engine.calls, [])
            with self.assertRaises(installer.EngineUnavailable) as caught:
                installer.install(self.dir / "x.exe", vendor=legacy_dir, runner=engine)
            self.assertEqual(caught.exception.reason, "legacy_install_path")


class Install(InstallCase):
    def test_install_copies_a_verified_build_to_its_own_directory(self):
        binary, manifest, engine = self.pinned()
        vendor = self.dir / "vendor" / "meguvizdexdash"
        target = installer.install(binary, manifest, engine, vendor=vendor)
        sha = installer.sha256(binary)
        self.assertEqual(target, (vendor / "0.1.0-test" / sha[:16] / binary.name).resolve())
        self.assertEqual(installer.sha256(target), sha)
        self.assertEqual(installer.install(binary, manifest, engine, vendor=vendor), target, "installing twice is the same")
        self.assertEqual(sorted(p.name for p in target.parent.iterdir()), [binary.name], "no staging file is left")
        self.assertEqual(installer.verify(manifest=manifest, runner=engine, vendor=vendor).path, target)

    def test_install_refuses_an_unpinned_build_and_leaves_nothing_behind(self):
        binary, manifest, engine = self.pinned()
        binary.write_bytes(b"not what was pinned")
        vendor = self.dir / "vendor" / "meguvizdexdash"
        engine.calls.clear()
        with self.assertRaises(installer.EngineUnavailable) as caught:
            installer.install(binary, manifest, engine, vendor=vendor)
        self.assertEqual(caught.exception.reason, "digest_mismatch")
        self.assertFalse(vendor.exists())
        self.assertEqual(engine.calls, [])

    def test_install_never_overwrites_what_is_installed(self):
        binary, manifest, engine = self.pinned()
        vendor = self.dir / "vendor" / "meguvizdexdash"
        target = installer.install(binary, manifest, engine, vendor=vendor)
        target.write_bytes(b"corrupted after install")
        with self.assertRaises(installer.EngineUnavailable) as caught:
            installer.install(binary, manifest, engine, vendor=vendor)
        self.assertEqual(caught.exception.reason, "digest_mismatch")
        self.assertEqual(target.read_bytes(), b"corrupted after install", "the existing file is left for the operator")

    def test_an_explicit_override_is_verified_and_never_copied(self):
        binary, manifest, engine = self.pinned()
        vendor = self.dir / "vendor" / "meguvizdexdash"
        with mock.patch.dict(os.environ, {installer.ENV_BINARY: str(binary)}):
            self.assertEqual(installer.install(self.dir / "ignored.exe", manifest, engine, vendor=vendor), binary.resolve())
        self.assertFalse(vendor.exists())

    def test_nothing_in_the_installer_can_reach_the_network(self):
        tree = ast.parse(Path(installer.__file__).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        network = {"urllib", "http", "socket", "ssl", "ftplib", "smtplib", "requests", "httpx", "aiohttp", "asyncio"}
        self.assertEqual(imported & network, set())


class Runner(unittest.TestCase):
    def test_the_default_runner_ends_a_process_that_does_not_answer(self):
        started = __import__("time").monotonic()
        with self.assertRaises(installer.EngineUnavailable) as caught:
            installer.default_runner([sys.executable, "-I", "-c", "import time; time.sleep(30)"], None, 0.5)
        self.assertEqual(caught.exception.reason, "handshake_failed")
        self.assertLess(__import__("time").monotonic() - started, 20)

    def test_the_default_runner_does_not_pass_credentials_to_the_engine(self):
        code = "import os; print(sorted(k for k in os.environ if 'TOKEN' in k or 'SECRET' in k or 'API_KEY' in k))"
        with mock.patch.dict(os.environ, {"HOSTLAB_TEST_TOKEN": "x", "MY_SECRET": "y", "OPENAI_API_KEY": "z"}):
            _, out, _ = installer.default_runner([sys.executable, "-I", "-c", code], None, 30)
        self.assertEqual(out.strip(), b"[]")


if __name__ == "__main__":
    unittest.main()
