"""MDD-054: the shadow harness's own rules, without an engine, an APK or a HostLab checkout.

The full run is the evidence of the equivalence (artifacts/mdd-054/full-equivalence.json); this file shows that the
isolation the run depends on is enforced and that the harness refuses to start when it is not.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run_shadow as S  # noqa: E402

PLAN = {
    "schema": S.MANIFEST_SCHEMA,
    "sides": {"A": {"engine": "dexsql", "version": "0.1.0", "sha256": "a" * 64},
              "B": {"engine": "meguvizdexdash", "wire": "b1", "profile_policy": "allow_unadmitted", "sql_limits": {"result_rows": 5}, "sha256": None}},
}


class Isolation(unittest.TestCase):
    def test_workspaces_that_meet_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            S.disjoint({"A": root / "a", "B": root / "b"})
            with self.assertRaises(S.ShadowError):
                S.disjoint({"A": root / "x", "B": root / "x"})
            with self.assertRaises(S.ShadowError):
                S.disjoint({"A": root / "x", "B": root / "x" / "inner"})
            with self.assertRaises(S.ShadowError):
                S.disjoint({"A": root / "x" / "inner", "B": root / "x"})

    def test_the_child_environment_has_no_secret_and_every_writable_place_is_the_sides_own(self):
        polluted = {"MY_API_KEY": "k", "GITHUB_TOKEN": "t", "DB_PASSWORD": "p", "CLIENT_SECRET": "s", "PATH": "p",
                    "HOSTLAB_DEXSQL": "stale", "HOSTLAB_PROVIDER_CONFIG": "stale", "DEXQ_CACHE_DIR": "stale", "MDD_CACHE_DIR": "stale"}
        with mock.patch.dict(os.environ, polluted, clear=False):
            env = S.child_environment(Path("D:/side/A"))
        for name in ("MY_API_KEY", "GITHUB_TOKEN", "DB_PASSWORD", "CLIENT_SECRET", "HOSTLAB_DEXSQL", "HOSTLAB_PROVIDER_CONFIG", "MDD_CACHE_DIR"):
            self.assertNotIn(name, env)
        self.assertIn("PATH", env)
        for name in ("TEMP", "TMP", "DEXQ_CACHE_DIR", "XDG_CACHE_HOME"):
            self.assertTrue(Path(env[name]).is_relative_to(Path("D:/side/A")), name)
        self.assertEqual(env["PYTHONDONTWRITEBYTECODE"], "1")

    def test_the_forbidden_entry_points_are_the_ones_that_publish_configure_or_choose_remote_jobs(self):
        self.assertEqual(S.FORBIDDEN_ENTRY_POINTS, ("config", "api_private", "manifest", "select"))


class EngineUnderTest(unittest.TestCase):
    def test_the_stand_in_states_the_engine_and_installs_nothing(self):
        identity = {"version": "0.1.0-dev", "sha256": "b" * 64, "path": "/x/engine", "engine": "meguvizdexdash"}
        module = S.engine_stand_in(identity)
        status = module.status()
        self.assertEqual((status["available"], status["sha256"], status["engine"]), (True, "b" * 64, "meguvizdexdash"))
        self.assertEqual(module.VERSION, "0.1.0-dev")
        self.assertEqual(module.asset(), ("engine", "b" * 64))
        with self.assertRaises(S.ShadowError):
            module.install()
        status["sha256"] = "tampered"
        self.assertEqual(module.status()["sha256"], "b" * 64, "the identity cannot be changed through a returned status")

    def test_the_configuration_written_for_b_is_what_the_integration_reads(self):
        import provider
        import native_session
        with tempfile.TemporaryDirectory() as folder:
            env = S.write_b_configuration(Path(folder), Path(folder) / "pin.json", PLAN)
            config = provider.load_config(None, env)
            self.assertEqual(config.native_engine, provider.ENGINE)
            self.assertEqual(config.engine.profile_policy, "allow_unadmitted")
            settings = native_session.load_structural_config(None, env)
            self.assertEqual(settings.wire, "b1")
            written = json.loads(Path(env["HOSTLAB_STRUCTURAL_CONFIG"]).read_text(encoding="utf-8"))
            self.assertEqual(written["sql_limits"], {"result_rows": 5})

    def test_without_sql_limits_the_engine_keeps_its_own_budget(self):
        plan = json.loads(json.dumps(PLAN))
        plan["sides"]["B"]["sql_limits"] = None
        with tempfile.TemporaryDirectory() as folder:
            env = S.write_b_configuration(Path(folder), Path(folder) / "pin.json", plan)
            self.assertNotIn("sql_limits", json.loads(Path(env["HOSTLAB_STRUCTURAL_CONFIG"]).read_text(encoding="utf-8")))


class Identity(unittest.TestCase):
    def test_an_input_that_is_not_the_pinned_file_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "x.apk"
            path.write_bytes(b"abc")
            good = {"occurrence_id": "x", "bytes": "3", "sha256": S.sha256_file(path)}
            self.assertEqual(S.verify_input(good, path), path.resolve())
            with self.assertRaises(S.ShadowError):
                S.verify_input(dict(good, sha256="0" * 64), path)
            with self.assertRaises(S.ShadowError):
                S.verify_input(dict(good, bytes="4"), path)

    def test_a_manifest_of_another_kind_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest = Path(folder) / "m.json"
            manifest.write_text(json.dumps({"schema": "other"}), encoding="utf-8")
            paths = Path(folder) / "p.json"
            paths.write_text("{}", encoding="utf-8")
            with self.assertRaises(S.ShadowError):
                S.main(["--manifest", str(manifest), "--paths", str(paths), "--sample", "x", "--out", str(Path(folder) / "o")])


if __name__ == "__main__":
    unittest.main()
