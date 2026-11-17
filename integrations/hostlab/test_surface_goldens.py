"""The golden of MDD-052 is what it says it is: made on the fixtures and sources it names, internally consistent, and
unable to pass when damaged. No network, no engine, no reference binary (it is only needed to *make* the golden).

Run: python -I -m unittest discover -s integrations/hostlab -p "test_surface_goldens.py"
"""
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import surface_make_goldens as G  # noqa: E402
import surface_support as S  # noqa: E402

ROOT = S.ROOT


def run(*argv):
    return subprocess.run([sys.executable, "-I", *argv], capture_output=True, text=True, cwd=str(ROOT), timeout=300)


class TheGoldenIsCurrent(unittest.TestCase):
    def test_it_passes_its_own_offline_check(self):
        self.assertEqual(G.check(), [])

    def test_the_command_line_check_agrees(self):
        done = run("integrations/hostlab/surface_make_goldens.py", "--check")
        self.assertEqual((done.returncode, done.stdout.strip()), (0, "surface goldens are current"), done.stderr)

    def test_the_fixtures_are_current_and_the_sources_are_the_recorded_ones(self):
        done = run("tests/fixtures/surface/generate.py", "--check")
        self.assertEqual((done.returncode, done.stdout.strip()), (0, "surface fixtures are current"), done.stderr)
        done = run("conformance/hostlab/surface_import_sources.py", "--check")
        self.assertEqual((done.returncode, done.stdout.strip()), (0, "surface sources are current"), done.stderr)

    def test_the_reference_engine_is_named_by_its_recorded_digest_and_is_not_in_the_repository(self):
        self.assertEqual(S.golden()["oracle"]["reference_engine"]["sha256"], "f354ebcf715de9a66ef8ebe08b2b36807ab58e25cd5a1c0812e497fc1fcfc448")
        for path in ROOT.rglob("*"):
            if path.is_file() and ".git" not in path.parts and "target" not in path.parts and "artifacts/local" not in path.as_posix():
                self.assertNotEqual(path.name.lower(), "dexsql-windows-amd64.exe", path)

    def test_no_machine_path_is_in_the_golden(self):
        text = S.GOLDENS.read_text(encoding="utf-8")
        for needle in ("DevArea", "Administrator", "C:\\\\", "/home/", "Users"):
            self.assertNotIn(needle, text)

    def test_the_fixtures_match_the_hand_derived_expectations_file(self):
        recorded = S.expected()["files"]
        for name, item in S.golden()["fixtures"].items():
            self.assertEqual({"bytes": recorded[name]["bytes"], "sha256": recorded[name]["sha256"]}, item)
            self.assertEqual(hashlib.sha256((S.GENERATED / name).read_bytes()).hexdigest(), item["sha256"])

    def test_every_scenario_says_what_the_original_did(self):
        outcomes = {n: s["legacy"]["outcome"] for n, s in S.golden()["scenarios"].items()}
        self.assertEqual(outcomes, {"base.apk": "report", "target.apk": "report", "plain.apk": "report",
                                    "fields-only.apk": "raised", "duplicate-resource.apk": "report"})
        self.assertEqual(S.golden()["scenarios"]["fields-only.apk"]["legacy"]["type"], "KeyError")

    def test_every_difference_from_the_original_is_declared_with_its_reason(self):
        declared = S.golden()["declared_differences"]
        self.assertEqual([d["id"] for d in declared], [f"DIFF-{i}" for i in range(1, 9)])
        for item in declared:
            self.assertTrue(item["title"] and item["original"] and item["new"] and item["reason"], item["id"])

    def test_the_declared_differences_are_the_makers_current_text(self):
        self.assertEqual(S.golden()["declared_differences"], G.DECLARED)


class ADamagedGoldenFails(unittest.TestCase):
    """Each damage is one change to a copy of the golden; the check must name a problem for every one."""

    def damaged(self, edit):
        golden = copy.deepcopy(S.golden())
        edit(golden)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "surface-goldens.json"
            path.write_text(json.dumps(golden), encoding="utf-8")
            return G.check(path)

    def test_a_changed_report_digest(self):
        def edit(g):
            digest = g["scenarios"]["base.apk"]["legacy"]["report_sha256"]
            g["scenarios"]["base.apk"]["legacy"]["report_sha256"] = ("0" if digest[0] != "0" else "1") + digest[1:]

        self.assertTrue(self.damaged(edit))

    def test_a_changed_class_in_the_recorded_report(self):
        def edit(g):
            g["scenarios"]["base.apk"]["legacy"]["report"]["class_records"][0]["class"] = "Lx/Y;"

        self.assertTrue(self.damaged(edit))

    def test_a_changed_row_in_a_recorded_statement(self):
        def edit(g):
            statement = next(s for s in g["scenarios"]["base.apk"]["legacy"]["statements"] if "FROM class_methods" in s["sql"] and s["rows"])
            statement["rows"][0][1] = "Lx/Y;"

        self.assertTrue(self.damaged(edit))

    def test_a_dropped_statement(self):
        def edit(g):
            g["scenarios"]["base.apk"]["legacy"]["statements"].pop()

        self.assertTrue(self.damaged(edit))

    def test_a_changed_relation_row(self):
        def edit(g):
            g["scenarios"]["base.apk"]["relations"]["code_items"][0][2] = "999"

        self.assertTrue(self.damaged(edit))

    def test_a_changed_fixture_digest(self):
        def edit(g):
            g["fixtures"]["base.apk"]["sha256"] = "0" * 64

        self.assertTrue(self.damaged(edit))

    def test_a_changed_source_digest(self):
        def edit(g):
            g["oracle"]["sources"]["conformance/hostlab/surface-source-8782f43"]["surface_workers"] = "0" * 64

        self.assertTrue(self.damaged(edit))

    def test_a_changed_cross_version_result(self):
        def edit(g):
            g["cross_version"]["base.apk->target.apk"]["changes"][0]["kind"] = "new_family_candidate"

        self.assertTrue(self.damaged(edit))

    def test_a_changed_recorded_exception(self):
        def edit(g):
            g["scenarios"]["fields-only.apk"]["legacy"]["resource_fingerprints"]["resources.arsc"] = "0" * 64

        self.assertTrue(self.damaged(edit))

    def test_a_changed_rule_hash(self):
        def edit(g):
            g["oracle"]["rule_sha256"] = "0" * 64

        self.assertTrue(self.damaged(edit))

    def test_a_changed_declared_difference(self):
        def edit(g):
            g["declared_differences"][1]["new"] = "anything else"

        self.assertTrue(self.damaged(edit))

    def test_a_dropped_declared_difference(self):
        def edit(g):
            g["declared_differences"].pop()

        self.assertTrue(self.damaged(edit))

    def test_something_that_is_not_a_golden(self):
        self.assertEqual(self.damaged(lambda g: g.update(schema="other")), ["not a surface golden"])


class TheImportedSourcesAreTheRecordedOnes(unittest.TestCase):
    def test_a_changed_byte_in_a_frozen_source_refuses_to_load_it(self):
        manifest = json.loads((S.SURFACE_SOURCES / "manifest.json").read_text(encoding="utf-8"))
        wanted = {Path(i["path"]).name: i["sha256"] for i in manifest["files"]}
        self.assertEqual(set(wanted), {"surface_workers.py", "audit_common.py", "priority_analysis.py"})
        with tempfile.TemporaryDirectory() as directory:
            for name in wanted:
                data = (S.SURFACE_SOURCES / name).read_bytes()
                changed = Path(directory) / name
                changed.write_bytes(data + b"\n")
                self.assertNotEqual(hashlib.sha256(changed.read_bytes()).hexdigest(), wanted[name])
        original = S.SURFACE_SOURCES
        try:
            with tempfile.TemporaryDirectory() as directory:
                for name in wanted:
                    (Path(directory) / name).write_bytes((original / name).read_bytes() + b"\n")
                (Path(directory) / "manifest.json").write_bytes((original / "manifest.json").read_bytes())
                S.SURFACE_SOURCES = Path(directory)
                with self.assertRaises(AssertionError):
                    S.load_surface_source("audit_common")
        finally:
            S.SURFACE_SOURCES = original

    def test_the_corpus_sources_are_checked_the_same_way(self):
        original = S.FROZEN
        try:
            with tempfile.TemporaryDirectory() as directory:
                for path in original.glob("native_*.py"):
                    (Path(directory) / path.name).write_bytes(path.read_bytes())
                (Path(directory) / "manifest.json").write_bytes((original / "manifest.json").read_bytes())
                (Path(directory) / "native_surface.py").write_bytes((original / "native_surface.py").read_bytes() + b"# changed\n")
                S.FROZEN = Path(directory)
                with self.assertRaises(AssertionError):
                    S.load_corpus("native_surface")
        finally:
            S.FROZEN = original


if __name__ == "__main__":
    unittest.main()
