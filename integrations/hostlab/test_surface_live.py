"""The surface provider against the real `meguvizdexdash` binary. A missing binary fails the run; it is never skipped.

Needs the binary (`cargo build -p mdd-cli`) or MDD_WORKER_BINARY. No network, no download, no reference binary: what the
reference engine answered is the golden (conformance/hostlab/surface-goldens.json).

What this checks and the stand-in cannot: that the engine answers the provider's statements with the very relations the
reference engine returned, that the report the provider builds from the engine's stream has the original report's hash for
every fixture, that raw instruction bytes and resources equal the ones the fixtures were built from, that a partial or
refused answer of the real engine is an error, and that the filter does not bring the engine down.

Run: python -I -m unittest discover -s integrations/hostlab -p "test_surface_live.py"
"""
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import install_meguvizdexdash as installer  # noqa: E402
import surface_support as S  # noqa: E402
import surface_provider as P  # noqa: E402
import provider as base  # noqa: E402

ROOT = S.ROOT
DIALECT = "dexsql-0.1.0"
REPORT_FIXTURES = [n for n, s in S.golden()["scenarios"].items() if s["legacy"]["outcome"] == "report"]


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


class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = find_binary()
        cls.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.dir = Path(cls.tmp.name).resolve()
        cls.manifest = cls.dir / "manifest.json"
        cls.entry = installer.pin(cls.binary, cls.manifest)
        cls.config = base.parse_config({"schema": base.CONFIG_SCHEMA, "native_engine": "dexsql", base.ENGINE: {
            "manifest": str(cls.manifest), "profile_policy": "allow_unadmitted"}})
        cls.state = cls.dir / "state"

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def launch(self):
        with mock.patch.dict(os.environ, {installer.ENV_BINARY: str(self.binary)}):
            return base.launch(self.config, threads=2, timeout_seconds=120, state=self.state)

    def session(self, name, **options):
        return P.ServeSession.from_launch(self.launch(), S.GENERATED / name, dialect=DIALECT, deadline_seconds=120, **options)

    def run_surface(self, name, **options):
        apk = S.GENERATED / name
        with mock.patch.dict(os.environ, {installer.ENV_BINARY: str(self.binary)}):
            return P.run_surface(apk, sha256=S.golden()["fixtures"][name]["sha256"], surface=P.parse_surface_config(
                {"schema": P.CONFIG_SCHEMA, "surface_provider": "meguvizdexdash"}), config=self.config, host=S.host(), state=self.state, **options)

    # -- acceptance 1
    def test_every_fixture_has_the_original_report_hash_through_the_whole_run(self):
        for name in REPORT_FIXTURES:
            with self.subTest(name):
                result = self.run_surface(name)
                legacy = S.golden()["scenarios"][name]["legacy"]
                self.assertEqual(result["report_sha256"], legacy["report_sha256"])
                self.assertIsNone(P.first_difference({k: v for k, v in result["report"].items() if k not in P.VOLATILE}, legacy["report"]))
                self.assertEqual(result["provider"], "meguvizdexdash")
                self.assertEqual((result["engine"]["engine_version"], result["engine"]["build_id"]),
                                 (self.entry["engine_version"], self.entry["build_id"]))
                self.assertEqual(result["report"]["scan_execution"]["backend"], "meguvizdexdash")

    def test_the_engines_relations_are_the_ones_the_reference_engine_returned(self):
        for name, scenario in S.golden()["scenarios"].items():
            with self.subTest(name), self.session(name) as session:
                got = S.record_relations(lambda sql: [[None if row[k] is None else str(row[k]) for k in row] for row in session.rows(sql)])
                for relation, rows in scenario["relations"].items():
                    self.assertEqual(sorted(map(repr, got[relation])), sorted(map(repr, rows)), relation)

    def test_raw_instruction_bytes_and_resources_are_those_the_fixtures_were_built_from(self):
        for name in REPORT_FIXTURES:
            with self.subTest(name):
                result = self.run_surface(name, evidence=True)
                seen = {(m["entry_name"], m["class"], m["name"], m["proto"]): m for m in result["evidence"]["methods"]}
                built = {}
                for member, classes in S.expected()["files"][name]["dex"].items():
                    for item in classes:
                        if item["expected_family"]:
                            for m in item["methods"]:
                                built[(member, item["descriptor"], m["name"], m["proto"])] = m
                self.assertEqual(set(seen), set(built))
                for key, want in built.items():
                    self.assertEqual((seen[key]["body"], seen[key]["insns_sha256"], seen[key]["method_idx"]),
                                     (want["body"], want["insns_sha256"], want["method_idx"]), key)
                self.assertEqual(result["report"]["resource_fingerprints"], S.expected()["files"][name]["resource_sha256"])

    def test_no_text_rendering_is_asked_of_the_engine(self):
        sent = []
        real = P.ServeSession.rows

        def spy(self, sql, **bounds):
            sent.append(sql)
            return real(self, sql, **bounds)

        with mock.patch.object(P.ServeSession, "rows", spy):
            self.run_surface("base.apk")
        self.assertTrue(sent)
        for sql in sent:
            self.assertTrue(set(re.findall(r"\bFROM (\w+)", sql)) <= set(S.RELATIONS), sql)
            self.assertNotRegex(sql.lower(), r"opcode_hex|smali|decode")

    # -- acceptance 2 and 3
    def test_the_same_numbers_in_two_dex_files_do_not_join_on_the_real_engine(self):
        self.assertTrue(S.expected()["shared_method_idx_in_base"])
        self.assertEqual(self.run_surface("base.apk")["report_sha256"], S.golden()["scenarios"]["base.apk"]["legacy"]["report_sha256"])

    def test_a_class_without_methods_in_a_file_without_family_methods_has_a_defined_digest_where_the_original_raised(self):
        self.assertEqual(S.golden()["scenarios"]["fields-only.apk"]["legacy"]["type"], "KeyError")
        result = self.run_surface("fields-only.apk")
        nothing = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual([r["method_bodies_sha256"] for r in result["report"]["class_records"]], [nothing, nothing])
        self.assertEqual(result["report"]["families"]["comment_legacy_v2"]["classes"], 1)

    def test_the_cross_version_results_are_the_originals_on_the_real_engine(self):
        reports = {name: self.run_surface(name)["report"] for name in ("base.apk", "target.apk")}
        for key, wanted in S.golden()["cross_version"].items():
            before, after = key.split("->")
            with self.subTest(key):
                got = P.cross_version(reports[before], reports[after], S.host(), context=S.golden()["context"])
                self.assertEqual(json.loads(P.canonical_json(got)), wanted)

    # -- the engine's refusals are errors
    def test_a_statement_the_engine_rejects_is_its_error_with_its_code(self):
        with self.session("base.apk") as session:
            with self.assertRaises(P.EngineFailure) as caught:
                session.all("SELECT nope FROM classes ORDER BY 1")
            self.assertEqual(base.classify_failure(caught.exception).code, "INVALID_ARGUMENT")
            self.assertEqual(caught.exception.detail["error"]["stage"], "sql.sqlite")
            self.assertEqual(len(session.all("SELECT file_id FROM dex_files ORDER BY file_id")), 2)  # the session goes on

    def test_a_result_over_the_row_budget_is_an_error_not_a_shorter_result(self):
        with self.session("base.apk") as session:
            self.assertEqual(len(session.all("SELECT file_id FROM classes ORDER BY file_id,class_def_idx")), 15)
            with self.assertRaises(P.EngineFailure):
                session.all("SELECT file_id FROM classes ORDER BY file_id,class_def_idx", max_rows=3)

    def test_an_input_the_engine_refuses_is_an_error_not_an_empty_dataset(self):
        for relative in ("tests/fixtures/generated/invalid-dex-member.apk", "tests/fixtures/generated/unsupported-041.dex",
                         "tests/fixtures/generated/truncated-header.dex"):
            with self.subTest(relative):
                launched = self.launch()
                session = P.ServeSession.from_launch(launched, ROOT / relative, dialect=DIALECT, deadline_seconds=60)
                with self.assertRaises((P.IncompleteFacts, P.EngineFailure)):
                    with session:
                        pass

    def test_a_source_that_is_not_the_named_one_is_refused_on_the_real_engine_too(self):
        with mock.patch.dict(os.environ, {installer.ENV_BINARY: str(self.binary)}), self.assertRaises(RuntimeError):
            P.run_surface(S.GENERATED / "base.apk", sha256="0" * 64, surface=P.SurfaceConfig(base.ENGINE), config=self.config,
                          host=S.host(), state=self.state)

    # -- the engine must survive the filter
    def test_the_family_filter_does_not_bring_the_engine_down(self):
        with self.session("base.apk") as session:
            rows = session.all("SELECT file_id,class_def_idx,descriptor FROM classes WHERE file_id=0 AND (" +
                               P.family_filter(S.frozen().workers, "descriptor") + ") ORDER BY file_id,class_def_idx")
        self.assertEqual([r["descriptor"] for r in rows if r["descriptor"].startswith("Lcom/bilibili/app/comm/")],
                         ["Lcom/bilibili/app/comm/comment2/Holder;"])

    # -- the cache, with the real engine's identity
    def test_a_stored_result_is_reused_only_for_the_same_build_and_is_the_same_report(self):
        fresh = self.run_surface("base.apk", use_store=True)
        again = self.run_surface("base.apk", use_store=True)
        self.assertEqual(again["report_sha256"], fresh["report_sha256"])
        self.assertEqual(S.frozen().workers.compare(again["report"], fresh["report"]), [])
        self.assertEqual(again["engine"], fresh["engine"])
        stores = [p for p in self.state.rglob("surface") if p.is_dir()]
        self.assertEqual(len(stores), 1)
        self.assertTrue(all(p.name == "SCHEMA.json" or p.suffix == ".json" for p in stores[0].iterdir()))


if __name__ == "__main__":
    unittest.main()
