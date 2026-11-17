"""The surface provider's own switch and its cache (MDD-052, the rollback line): `surface_provider` is independent of
`native_engine`; `dexsql` restores the original path and starts nothing else; results of the two paths never share a cache
schema. No network, no engine process: the engine is a stand-in that answers `version`/`capabilities` and a relational
stand-in serves the facts.

Run: python -I -m unittest discover -s integrations/hostlab -p "test_surface_switch.py"
"""
import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hostlab_test_support as support  # noqa: E402
import install_meguvizdexdash as installer  # noqa: E402
import surface_support as S  # noqa: E402
import surface_provider as P  # noqa: E402
import provider as base  # noqa: E402

BASE_APK = S.GENERATED / "base.apk"
BASE_SHA = S.golden()["fixtures"]["base.apk"]["sha256"]
BASE_DIGEST = S.golden()["scenarios"]["base.apk"]["legacy"]["report_sha256"]


class StandIn:
    """A session (the interface of the original NativeSession and of ServeSession) answered from relation tables."""

    def __init__(self, session):
        self.session, self.files, self.apk = session, session.files, session.apk
        self.opened = {"snapshot_id": "snapshot-stand-in", "scope_id": "sha256:stand-in"}
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    def rows(self, sql, **bounds):
        return self.session.rows(sql, **bounds)

    def all(self, sql, **bounds):
        return self.session.all(sql, **bounds)


def stand_in(name="base.apk", apk=None, edit=None):
    return StandIn(S.facts(name, edit, apk))


def refuse(*_a, **_k):
    raise AssertionError("this path must not be used")


class Temp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name).resolve()


def surface(provider):
    return P.parse_surface_config({"schema": P.CONFIG_SCHEMA, "surface_provider": provider})


class TheSwitch(Temp):
    def test_the_default_keeps_the_original_path(self):
        self.assertEqual(P.SurfaceConfig().surface_provider, "dexsql")
        self.assertEqual(P.load_surface_config(environ={}), P.SurfaceConfig())
        self.assertEqual(P.PROVIDERS, ("dexsql", "meguvizdexdash"))

    def test_both_providers_are_accepted_and_have_different_identities(self):
        legacy, engine = surface("dexsql"), surface("meguvizdexdash")
        self.assertEqual((legacy.surface_provider, engine.surface_provider), ("dexsql", "meguvizdexdash"))
        self.assertNotEqual(legacy.digest(), engine.digest())
        self.assertEqual(legacy.digest(), surface("dexsql").digest())
        self.assertEqual(P.parse_surface_config({"schema": P.CONFIG_SCHEMA}), P.SurfaceConfig())

    def test_a_setting_that_is_not_understood_is_an_error_not_a_default(self):
        bad = [None, [], "dexsql", {}, {"schema": "other", "surface_provider": "dexsql"},
               {"schema": P.CONFIG_SCHEMA, "surface_provider": "sqlite"}, {"schema": P.CONFIG_SCHEMA, "surface_provider": None},
               {"schema": P.CONFIG_SCHEMA, "surface_provider": ["dexsql"]}, {"schema": P.CONFIG_SCHEMA, "surface_provider": "DEXSQL"},
               {"schema": P.CONFIG_SCHEMA, "surface_provider": "dexsql", "native_engine": "dexsql"},
               {"schema": P.CONFIG_SCHEMA, "provider": "dexsql"}]
        for value in bad:
            with self.subTest(value), self.assertRaises(base.ConfigError):
                P.parse_surface_config(value)

    def test_the_setting_is_read_from_a_file_or_the_environment(self):
        path = self.dir / "surface.json"
        path.write_text(json.dumps({"schema": P.CONFIG_SCHEMA, "surface_provider": "meguvizdexdash"}), encoding="utf-8")
        self.assertEqual(P.load_surface_config(path).surface_provider, "meguvizdexdash")
        self.assertEqual(P.load_surface_config(environ={"HOSTLAB_SURFACE_CONFIG": str(path)}).surface_provider, "meguvizdexdash")
        self.assertEqual(P.load_surface_config({"schema": P.CONFIG_SCHEMA, "surface_provider": "dexsql"}, environ={"HOSTLAB_SURFACE_CONFIG": str(path)}).surface_provider, "dexsql")
        path.write_text("not json", encoding="utf-8")
        with self.assertRaises(base.ConfigError):
            P.load_surface_config(path)
        path.write_text(" " * (64 * 1024 + 1), encoding="utf-8")
        with self.assertRaises(base.ConfigError):
            P.load_surface_config(path)

    def test_the_setting_is_not_part_of_the_providers_configuration(self):
        # provider.py's own configuration stays strict: the surface switch cannot be smuggled into it
        with self.assertRaises(base.ConfigError):
            base.parse_config({"schema": base.CONFIG_SCHEMA, "surface_provider": "meguvizdexdash"})
        self.assertEqual(base.parse_config({"schema": base.CONFIG_SCHEMA}).digest(), base.Config().digest())


class Running(Temp):
    def setUp(self):
        super().setUp()
        self.binary, self.manifest, self.fake = support.pin_binary(self.dir)
        self.state = self.dir / "state"
        self.legacy_calls = []
        self.pinned_calls = len(self.fake.calls)  # pinning ran the stand-in; what follows must not

    def config(self, native_engine="dexsql", policy="allow_unadmitted"):
        return base.parse_config({"schema": base.CONFIG_SCHEMA, "native_engine": native_engine,
                                  "meguvizdexdash": {"manifest": str(self.manifest), "profile_policy": policy}})

    def legacy_factory(self):
        def factory(apk, timeout, threads):
            self.legacy_calls.append((Path(apk).name, timeout, threads))
            return stand_in(Path(apk).name, apk)
        return factory

    def surface_run(self, provider, *, native_engine="dexsql", policy="allow_unadmitted", legacy=True, apk=BASE_APK, sha=BASE_SHA, **options):
        with mock.patch.dict(os.environ, {installer.ENV_BINARY: str(self.binary)}):
            return P.run_surface(apk, sha256=sha, surface=surface(provider), config=self.config(native_engine, policy), host=S.host(),
                                 state=self.state, legacy_session=self.legacy_factory() if legacy else None, runner=self.fake, **options)

    def served_by_stand_in(self, **kw):
        return mock.patch.object(P.ServeSession, "from_launch", side_effect=lambda launched, apk, **k: stand_in(Path(apk).name, apk, kw.get("edit")))

    # -- dexsql: the original path, nothing else
    def test_dexsql_runs_the_original_functions_and_starts_no_engine(self):
        with mock.patch.object(base, "launch", side_effect=refuse), mock.patch.object(P.ServeSession, "from_launch", side_effect=refuse):
            result = self.surface_run("dexsql")
        self.assertEqual(self.legacy_calls, [("base.apk", 900, 2)])
        self.assertEqual((result["provider"], result["engine"]), ("dexsql", None))
        self.assertEqual(result["report_sha256"], BASE_DIGEST)
        self.assertEqual(result["report"]["scan_execution"]["backend"], "dexsql")
        self.assertEqual(len(self.fake.calls), self.pinned_calls)

    def test_dexsql_needs_hostlabs_session_and_scan(self):
        with self.assertRaises(P.SurfaceError):
            self.surface_run("dexsql", legacy=False)
        host = S.host()
        bare = P.Host(host.workers, host.resource_fingerprints, host.unsupported)
        with self.assertRaises(P.SurfaceError):
            P.run_surface(BASE_APK, sha256=BASE_SHA, surface=surface("dexsql"), config=self.config(), host=bare, state=self.state,
                          legacy_session=self.legacy_factory())

    def test_dexsql_reports_the_same_whether_or_not_the_engine_is_installed(self):
        first = self.surface_run("dexsql")
        self.binary.unlink()
        second = self.surface_run("dexsql")
        self.assertEqual(first["report_sha256"], second["report_sha256"])

    # -- meguvizdexdash
    def test_the_engine_serves_the_surface_even_when_native_engine_is_dexsql(self):
        with self.served_by_stand_in():
            result = self.surface_run("meguvizdexdash", native_engine="dexsql", legacy=False)
        self.assertEqual(result["provider"], "meguvizdexdash")
        self.assertEqual(result["report_sha256"], BASE_DIGEST)
        self.assertEqual(result["report"]["scan_execution"]["backend"], "meguvizdexdash")
        self.assertEqual(result["engine"]["backend"], "meguvizdexdash")
        self.assertEqual(result["engine"]["dialect"]["engine"], "dexsql-0.1.0")
        self.assertEqual(result["source"]["sha256"], BASE_SHA)
        self.assertEqual(result["source"]["snapshot_id"], "snapshot-stand-in")

    def test_the_engine_path_never_touches_the_original_session(self):
        with self.served_by_stand_in():
            self.surface_run("meguvizdexdash", legacy=False)
        self.assertEqual(self.legacy_calls, [])

    def test_the_two_paths_give_one_report_with_only_the_engine_label_apart(self):
        with self.served_by_stand_in():
            engine = self.surface_run("meguvizdexdash")
        legacy = self.surface_run("dexsql")
        self.assertEqual(engine["report_sha256"], legacy["report_sha256"])
        self.assertIsNone(P.first_difference({k: v for k, v in engine["report"].items() if k != "scan_execution"},
                                             {k: v for k, v in legacy["report"].items() if k != "scan_execution"}))
        self.assertEqual({k: v for k, v in engine["report"]["scan_execution"].items() if k in ("backend", "dex_files")},
                         {"backend": "meguvizdexdash", "dex_files": 2})

    def test_an_engine_that_cannot_be_used_is_an_error_not_a_quiet_return_to_the_original(self):
        with mock.patch.object(P.ServeSession, "from_launch", side_effect=refuse):
            with self.assertRaises(base.ProviderUnavailable) as caught:
                self.surface_run("meguvizdexdash", policy="require_admitted")
        self.assertEqual(caught.exception.reason, "profile_not_admitted")
        self.assertEqual(self.legacy_calls, [])

    def test_a_source_that_is_not_the_one_named_is_refused_before_anything_runs(self):
        for provider in ("dexsql", "meguvizdexdash"):
            with self.subTest(provider), mock.patch.object(base, "launch", side_effect=refuse):
                with self.assertRaises(RuntimeError) as caught:
                    self.surface_run(provider, sha="0" * 64)
                self.assertIn("immutable APK identity", str(caught.exception))
        self.assertEqual(self.legacy_calls, [])

    def test_a_source_that_changes_while_it_is_read_is_refused(self):
        real = base.file_sha256
        calls = []

        def changing(path):
            calls.append(path)
            return real(path) if len(calls) == 1 else "f" * 64

        for provider in ("dexsql", "meguvizdexdash"):
            calls.clear()
            with self.subTest(provider), self.served_by_stand_in(), mock.patch.object(base, "file_sha256", side_effect=changing):
                with self.assertRaises(RuntimeError) as caught:
                    self.surface_run(provider)
                self.assertIn("changed during analysis", str(caught.exception))

    def test_a_dataset_that_lacks_a_physical_dex_member_is_refused(self):
        def one_file(launched, apk, **_):
            session = S.facts("base.apk", edit=lambda t: t["dex_files"].pop())
            return StandIn(session)

        with mock.patch.object(P.ServeSession, "from_launch", side_effect=one_file):
            with self.assertRaises(base.InventoryError) as caught:
                self.surface_run("meguvizdexdash")
        self.assertEqual(caught.exception.detail, {"missing": ["classes2.dex"], "unexpected": []})

    def test_the_engine_is_asked_for_the_configured_dialect_and_the_runs_deadline(self):
        seen = {}

        def capture(launched, apk, **kw):
            seen.update(kw, command=launched.command, apk=Path(apk).name)
            return stand_in(Path(apk).name, apk)

        with mock.patch.object(P.ServeSession, "from_launch", side_effect=capture):
            result = self.surface_run("meguvizdexdash", timeout=321, threads=3)
        self.assertEqual((seen["dialect"], seen["deadline_seconds"], seen["apk"]), ("dexsql-0.1.0", 321, "base.apk"))
        self.assertEqual(Path(seen["command"]).name, self.binary.name)
        self.assertEqual(result["source"]["bytes"], BASE_APK.stat().st_size)
        self.assertEqual(result["source"]["name"], "base.apk")
        self.assertEqual(result["report"]["scan_execution"]["workers"], base.effective_threads(3))

    def test_the_evidence_is_kept_only_when_asked_for(self):
        with self.served_by_stand_in():
            plain = self.surface_run("meguvizdexdash")
            asked = self.surface_run("meguvizdexdash", evidence=True)
        self.assertNotIn("evidence", plain)
        self.assertEqual(asked["evidence"]["schema"], P.EVIDENCE_SCHEMA)
        self.assertTrue(asked["evidence"]["methods"])
        self.assertEqual([d["entry_name"] for d in asked["evidence"]["dex"]], ["classes.dex", "classes2.dex"])
        self.assertEqual(asked["report_sha256"], plain["report_sha256"])

    def test_a_failure_of_the_session_leaves_nothing_in_the_store(self):
        def broken(launched, apk, **_):
            raise P.IncompleteFacts("stand-in failure")

        with mock.patch.object(P.ServeSession, "from_launch", side_effect=broken):
            with self.assertRaises(P.IncompleteFacts):
                self.surface_run("meguvizdexdash", use_store=True)
        stores = list(self.state.rglob("surface"))
        self.assertTrue(all(not list(s.glob("*.json")) or [p.name for p in s.glob("*.json")] == ["SCHEMA.json"] for s in stores))

    # -- rollback and the cache
    def test_switching_back_to_dexsql_neither_reads_nor_writes_the_engines_store(self):
        with self.served_by_stand_in():
            engine = self.surface_run("meguvizdexdash", use_store=True)
        store = next(self.state.rglob("surface"))
        before = {p.name: p.read_bytes() for p in store.iterdir()}
        self.assertEqual(len(before), 2)  # the marker and one result
        for _ in range(2):
            with mock.patch.object(P, "SurfaceStore", side_effect=refuse), mock.patch.object(P.ServeSession, "from_launch", side_effect=refuse):
                legacy = self.surface_run("dexsql", use_store=True)
            self.assertEqual(legacy["report_sha256"], engine["report_sha256"])
        self.assertEqual({p.name: p.read_bytes() for p in store.iterdir()}, before)

    def test_switching_to_the_engine_again_reuses_only_its_own_result(self):
        with self.served_by_stand_in():
            fresh = self.surface_run("meguvizdexdash", use_store=True)
        with mock.patch.object(P.ServeSession, "from_launch", side_effect=refuse):  # nothing is rescanned
            cached = self.surface_run("meguvizdexdash", use_store=True)
        self.assertEqual(cached["report_sha256"], fresh["report_sha256"])
        self.assertEqual(S.frozen().workers.compare(cached["report"], fresh["report"]), [])  # shapes restored

    def test_a_run_that_asks_for_the_evidence_does_not_touch_the_store(self):
        with self.served_by_stand_in():
            result = self.surface_run("meguvizdexdash", use_store=True, evidence=True)
        self.assertIn("evidence", result)
        self.assertEqual(list(self.state.rglob("surface")), [])

    def test_two_runs_that_store_the_same_result_are_not_a_conflict_but_two_different_ones_are(self):
        real = P.SurfaceStore.load
        calls = []

        def blind_once(self_, sha):
            calls.append(sha)
            return None if len(calls) == 1 else real(self_, sha)

        with self.served_by_stand_in():
            first = self.surface_run("meguvizdexdash", use_store=True)
            with mock.patch.object(P.SurfaceStore, "load", blind_once):
                second = self.surface_run("meguvizdexdash", use_store=True)  # it did not see the first one's result
        self.assertEqual(second["report_sha256"], first["report_sha256"])
        store = next(self.state.rglob("surface"))
        stored = next(p for p in store.glob("*.json") if p.name != "SCHEMA.json")
        different = json.loads(stored.read_text(encoding="utf-8"))
        different["report"]["limitations"] = ["another"]
        different["report_sha256"] = P.report_digest(different["report"])
        stored.write_text(json.dumps(different), encoding="utf-8")
        calls.clear()
        with self.served_by_stand_in(), mock.patch.object(P.SurfaceStore, "load", blind_once):
            with self.assertRaises(P.CacheMismatch) as caught:
                self.surface_run("meguvizdexdash", use_store=True)
        self.assertIn("different result", str(caught.exception))

    def test_a_result_of_another_engine_build_is_not_reused(self):
        with self.served_by_stand_in():
            self.surface_run("meguvizdexdash", use_store=True)
        (self.dir / "other").mkdir(exist_ok=True)
        other_binary, other_manifest, other = support.pin_binary(self.dir / "other", support.FakeEngine(build_id="source-sha256:" + "cd" * 32),
                                                                 content=b"another engine")
        with self.served_by_stand_in(), mock.patch.dict(os.environ, {installer.ENV_BINARY: str(other_binary)}):
            config = base.parse_config({"schema": base.CONFIG_SCHEMA, "meguvizdexdash": {"manifest": str(other_manifest), "profile_policy": "allow_unadmitted"}})
            result = P.run_surface(BASE_APK, sha256=BASE_SHA, surface=surface("meguvizdexdash"), config=config, host=S.host(),
                                   state=self.state, runner=other, use_store=True)
        self.assertEqual(result["report_sha256"], BASE_DIGEST)
        directories = [p for p in self.state.rglob("surface") if p.is_dir()]
        self.assertEqual(len(directories), 2)  # each build has its own namespace


def identity(**over):
    value = {"build_id": "b1", "binary_sha256": "s1", "dialect": {"engine": "dexsql-0.1.0"}}
    value.update(over)
    return value


def entry(store, sha=BASE_SHA, **over):
    report = copy.deepcopy(S.golden()["scenarios"]["base.apk"]["legacy"]["report"])
    report["scan_execution"] = {"backend": "meguvizdexdash"}
    value = P.envelope(report, provider=P.ENGINE, source={"name": "base.apk", "sha256": sha, "bytes": 1}, engine=store.engine)
    value.update(over)
    return value


class TheStore(Temp):
    RULE = S.golden()["oracle"]["rule_sha256"]

    def store(self, **over):
        return P.SurfaceStore(self.dir / "reports", identity(**over), self.RULE)

    def test_a_result_is_stored_and_read_back_whole(self):
        store = self.store()
        wanted = entry(store)
        path = store.save(wanted)
        self.assertEqual(path.parent, self.dir / "reports" / "surface")
        loaded = store.load(BASE_SHA)
        self.assertEqual(loaded["report_sha256"], wanted["report_sha256"])
        self.assertEqual(P.report_digest(loaded["report"]), wanted["report_sha256"])
        self.assertIsNone(store.load("0" * 64))

    def test_a_stored_result_is_never_replaced(self):
        store = self.store()
        store.save(entry(store))
        with self.assertRaises(base.NamespaceCollision):
            store.save(entry(store))

    def test_the_address_is_made_of_source_rules_build_and_dialect(self):
        keys = {self.store().key(BASE_SHA), self.store().key("1" * 64), self.store(build_id="b2").key(BASE_SHA),
                self.store(binary_sha256="s2").key(BASE_SHA), self.store(dialect={"engine": "dexsql-0.1.1"}).key(BASE_SHA),
                P.SurfaceStore(self.dir / "reports", identity(), "0" * 64).key(BASE_SHA)}
        self.assertEqual(len(keys), 6)
        self.assertEqual(self.store().key(BASE_SHA), self.store().key(BASE_SHA))

    def test_an_entry_that_is_not_exactly_this_providers_is_refused(self):
        store = self.store()
        good = entry(store)
        legacy_shape = copy.deepcopy(good["report"])  # what the original path writes: a bare report
        tampered = copy.deepcopy(good)
        tampered["report"]["class_records"][0]["method_bodies_sha256"] = "0" * 64
        cases = {
            "a bare report of the original path": legacy_shape,
            "another schema": dict(good, schema="mdd.hostlab-surface.v0"),
            "another provider": dict(good, provider="dexsql"),
            "no provider": {k: v for k, v in good.items() if k != "provider"},
            "another source": dict(good, source=dict(good["source"], sha256="2" * 64)),
            "other rules": dict(good, rule_sha256="3" * 64),
            "other rules in the report": dict(good, report=dict(good["report"], rule_sha256="3" * 64)),
            "another build": dict(good, engine=identity(build_id="other")),
            "another binary": dict(good, engine=identity(binary_sha256="other")),
            "another dialect": dict(good, engine=identity(dialect={"engine": "dexsql-0.1.1"})),
            "no engine": dict(good, engine=None),
            "a report that does not match its digest": tampered,
            "not an object": ["x"],
        }
        for label, value in cases.items():
            path = store.path(BASE_SHA)
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.subTest(label), self.assertRaises(P.CacheMismatch):
                store.load(BASE_SHA)
            path.unlink()

    def test_a_file_that_is_not_json_is_refused(self):
        store = self.store()
        store.path(BASE_SHA).write_text("{not json", encoding="utf-8")
        with self.assertRaises(P.CacheMismatch):
            store.load(BASE_SHA)

    def test_an_entry_of_another_build_cannot_be_saved_as_this_ones(self):
        store = self.store()
        with self.assertRaises(P.CacheMismatch):
            store.save(entry(store, engine=identity(build_id="other")))
        self.assertEqual([p.name for p in (self.dir / "reports" / "surface").glob("*.json")], ["SCHEMA.json"])

    def test_a_directory_claimed_by_another_schema_is_not_taken_over(self):
        self.store()
        marker = self.dir / "reports" / "surface" / "SCHEMA.json"
        self.assertEqual(json.loads(marker.read_text(encoding="utf-8"))["entry_schema"], P.SCHEMA)
        self.store()  # the same claim is fine
        marker.write_text(json.dumps({"schema": "mdd.hostlab-surface-store.v2", "entry_schema": "mdd.hostlab-surface.v2"}), encoding="utf-8")
        with self.assertRaises(P.CacheMismatch):
            self.store()

    def test_the_store_lies_under_the_engines_namespace_and_overlaps_nothing_of_hostlabs_or_dexsqls(self):
        binary, manifest, fake = support.pin_binary(self.dir)
        config = base.parse_config({"schema": base.CONFIG_SCHEMA, "meguvizdexdash": {"manifest": str(manifest), "profile_policy": "allow_unadmitted"}})
        with mock.patch.dict(os.environ, {installer.ENV_BINARY: str(binary)}):
            launched = base.launch(config, threads=1, timeout_seconds=10, state=self.dir / "state", runner=fake)
        store = P.SurfaceStore(launched.namespaces["reports"], launched.identity, self.RULE)
        for name, other in base.legacy_paths(self.dir / "state").items():
            self.assertFalse(base._related(store.root, other), name)
        self.assertTrue(store.root.is_relative_to(self.dir / "state" / base.MDD_ROOT))


if __name__ == "__main__":
    unittest.main()
