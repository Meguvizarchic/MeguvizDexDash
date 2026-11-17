"""The surface provider against HostLab's own surface path (MDD-052). No network, no engine process, no reference binary.

The oracle is the frozen HostLab source (native_surface.scan, surface_workers, audit_common, priority_analysis), run
unchanged, and what the reference engine answered to it, frozen in conformance/hostlab/surface-goldens.json. The facts
the provider reads here come from a relational stand-in that holds the relations the reference engine returned
(`surface_support.FactSession`); test_surface_live.py runs the same comparisons against the real engine.

Each class answers one acceptance line of MDD-052 and every comparison has a negative control: a damaged golden, a
changed byte, a swapped source identity must fail.

Run: python -I -m unittest discover -s integrations/hostlab -p "test_surface_provider.py"
"""
import copy
import hashlib
import importlib.util
import json
import os
import re
import sqlite3
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hostlab_test_support as support  # noqa: E402
import surface_support as S  # noqa: E402
import surface_provider as P  # noqa: E402
import provider as base  # noqa: E402

FIXTURE_NAMES = [n for n, s in S.golden()["scenarios"].items() if s["legacy"]["outcome"] == "report"]
ALLOWED_RELATIONS = set(S.RELATIONS)


def _generator():
    spec = importlib.util.spec_from_file_location("surface_fixture_generator", S.FIXTURES / "generate.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GEN = _generator()


def report_of(session, apk=None, evidence=None):
    return P.build_report(session, S.host(), apk or session.apk, backend="meguvizdexdash", workers=1, evidence=evidence)


def original_report(session):
    """What HostLab's own functions make of the same session."""
    frozen = S.frozen()
    report = frozen.surface.scan(session)
    report["resource_fingerprints"] = frozen.audit_common.resource_fingerprints(session.apk)
    return report


def outcome(call):
    try:
        return ("report", P.report_digest(call()))
    except BaseException as error:  # noqa: BLE001 - what is compared is the refusal itself
        return ("raised", type(error).__name__, str(error))


def difference_from_golden(report, legacy):
    """None if `report` is the golden's report; else where it first differs."""
    if P.report_digest(report) == legacy["report_sha256"]:
        return None
    stable = json.loads(P.canonical_json({k: v for k, v in report.items() if k not in P.VOLATILE}))
    return P.first_difference(stable, legacy["report"]) or "report_sha256"


def modified_apk(directory, name, edit):
    """A copy of fixture `name` whose members are rewritten by `edit(members)` (a list of [name, data, method])."""
    with zipfile.ZipFile(S.GENERATED / name) as archive:
        members = [[i.filename, archive.read(i), "deflated" if i.compress_type == zipfile.ZIP_DEFLATED else "stored"]
                   for i in archive.infolist()]
    edit(members)
    path = Path(directory) / name
    path.write_bytes(GEN.zip_bytes([tuple(m) for m in members]))
    return path


class Temp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name).resolve()


# ---- the filter ----------------------------------------------------------------------------------------------------

class TheTwoLayerFilter(unittest.TestCase):
    """The engine's case-insensitive LIKE is only a candidate superset; the exact classifier is HostLab's. The SQL text is
    rebuilt here (balanced instead of chained), so it is compared by what it selects."""

    def candidates(self):
        workers = S.frozen().workers
        prefixes = {p for values in workers.FAMILIES.values() for p in values}
        prefixes |= {"Lcom/bilibili/app/comment3/ui/", "Lkntr/common/comment", "Lkntr/app/following/"}
        names = {"", "L", "Lcom/example/A;", "Lcom/bilibili/zzz/B;", "Lkntr/x/C;", "Ltv/danmaku/bili/Z;", "Lcom/bapis/x/AMoss;"}
        for p in prefixes:
            names |= {p + "X;", p.upper() + "x;", p.lower() + "x;", p[:-1] + "?x;", p[: len(p) // 2] + "x;", p[1:] + "x;"}
        for word in ("dynamic", "Dynamic", "FOLLOWING", "feed", "Feed", "other", "", "followingX"):
            names |= {"Lcom/bilibili/bplus/" + word + "/X;", "Lcom/bilibili/bplus/a" + word + "b;", "Lcom/bilibili/bplusx/" + word + "/X;"}
        return sorted(names)

    def selected(self, condition):
        db = sqlite3.connect(":memory:")
        try:
            db.execute("CREATE TABLE t (d TEXT)")
            db.executemany("INSERT INTO t VALUES (?)", [(n,) for n in self.candidates()])
            return {row[0] for row in db.execute("SELECT d FROM t WHERE " + condition)}
        finally:
            db.close()

    def test_the_family_filter_selects_what_the_original_chain_selects(self):
        chain = S.frozen().surface.family_filter("d")
        balanced = P.family_filter(S.frozen().workers, "d")
        self.assertNotEqual(chain, balanced)
        self.assertTrue(self.selected(chain))
        self.assertEqual(self.selected(balanced), self.selected(chain))

    def test_the_filter_is_a_superset_of_the_exact_classifier(self):
        workers = S.frozen().workers
        exact = {n for n in self.candidates() if workers.family(n) is not None}
        self.assertTrue(exact)
        self.assertLessEqual(exact, self.selected(P.family_filter(workers, "d")))

    def test_the_filter_is_shallow_because_the_engine_overflows_its_stack_on_a_chain(self):
        text = P.family_filter(S.frozen().workers, "d")
        depth = deepest = 0
        for ch in text:
            depth += ch == "("
            deepest = max(deepest, depth)
            depth -= ch == ")"
        self.assertLessEqual(deepest, 9)
        self.assertGreater(len(re.findall(" OR ", S.frozen().surface.family_filter("d"))), 30)  # the original is one long chain

    def test_balanced_or_keeps_every_term_once_and_in_order(self):
        terms = [f"t{i}" for i in range(7)]
        self.assertEqual(re.findall(r"t\d", P.balanced_or(terms)), terms)
        self.assertEqual(P.balanced_or(["a"]), "a")

    def test_an_or_condition_of_too_many_terms_is_refused(self):
        self.assertEqual(P.MAX_OR_TERMS, 64)
        with self.assertRaises(P.SurfaceError):
            P.balanced_or([f"t{i}" for i in range(P.MAX_OR_TERMS + 1)])
        P.balanced_or([f"t{i}" for i in range(P.MAX_OR_TERMS)])  # the cap itself is admitted

    def test_an_empty_or_condition_is_refused(self):
        with self.assertRaises(P.SurfaceError):
            P.balanced_or([])

    def test_sql_depth_measures_the_deepest_nesting(self):
        self.assertEqual(P.sql_depth("SELECT a FROM t ORDER BY a"), 0)
        self.assertEqual(P.sql_depth("(a OR (b AND c))"), 2)
        self.assertEqual(P.sql_depth("((()))"), 3)
        self.assertEqual(P.sql_depth("(a) OR (b)"), 1)

    def test_the_other_builders_are_the_originals(self):
        legacy = S.frozen().surface
        workers = S.frozen().workers
        for value in ("Lcom/x_y%z\\w;", "a'b", "", "100%_\\"):
            self.assertEqual(P.prefix("c", value), legacy.prefix("c", value))
        self.assertEqual(P.protocol_filter(workers, "c"), legacy.protocol_filter("c"))
        self.assertEqual(P.in_list(["a", "b'c"]), S.frozen().session_module.in_list(["a", "b'c"]))
        for bad in ("a\nb", "a\rb", "a\0b"):
            with self.assertRaises(ValueError):
                P.literal(bad)
            with self.assertRaises(ValueError):
                S.frozen().session_module.literal(bad)

    def test_legacy_body_order_is_the_originals(self):
        legacy = S.frozen().surface
        unsupported = S.frozen().unsupported
        for proto in ("()V", "(I)V", "(IJ)V", "(I[J)V", "(Ljava/lang/String;[[ILx/Y;)Lz/W;", "([[D)[I"):
            self.assertEqual(P.legacy_body_order(proto, unsupported), legacy.legacy_body_order(proto))
        for proto in ("(Lbroken)V", "(Q)V"):
            with self.assertRaises(unsupported):
                P.legacy_body_order(proto, unsupported)
            with self.assertRaises(unsupported):
                legacy.legacy_body_order(proto)
        with self.assertRaises(ValueError):  # no closing parenthesis: the original fails the same way
            P.legacy_body_order("(I", unsupported)
        with self.assertRaises(ValueError):
            legacy.legacy_body_order("(I")

    def test_two_overloads_are_visited_in_the_spaced_order_not_the_plain_one(self):
        # "(I)V" < "(IJ)V" as plain text, but "(I J)V" < "(I)V" with the original's spaces
        order = lambda p: P.legacy_body_order(p, S.frozen().unsupported)  # noqa: E731
        self.assertLess("(I)V", "(IJ)V")
        self.assertLess(order("(IJ)V"), order("(I)V"))


# ---- acceptance 1: bytes, records and the report hash agree -----------------------------------------------------------

class RawBytesRecordsAndTheReportHash(Temp):
    def test_every_fixture_has_the_original_report_hash(self):
        for name in FIXTURE_NAMES:
            with self.subTest(name):
                legacy = S.golden()["scenarios"][name]["legacy"]
                self.assertEqual(P.report_digest(report_of(S.facts(name))), legacy["report_sha256"])

    def test_the_class_and_method_records_are_the_originals_down_to_the_last_field(self):
        for name in FIXTURE_NAMES:
            with self.subTest(name):
                legacy = S.golden()["scenarios"][name]["legacy"]
                self.assertIsNone(difference_from_golden(report_of(S.facts(name)), legacy))

    def test_the_original_functions_over_the_same_stand_in_give_the_same_hash(self):
        # the stand-in is faithful: HostLab's own code over it reproduces what the reference engine gave it
        for name in FIXTURE_NAMES:
            with self.subTest(name):
                legacy = S.golden()["scenarios"][name]["legacy"]
                self.assertEqual(P.report_digest(original_report(S.facts(name))), legacy["report_sha256"])

    def test_raw_instruction_bytes_are_those_the_fixture_was_built_from(self):
        for name in FIXTURE_NAMES:
            with self.subTest(name):
                evidence = {"methods": [], "dex": [], "resources": [], "resource_duplicates": []}
                report_of(S.facts(name), evidence=evidence)
                seen = {(m["entry_name"], m["class"], m["name"], m["proto"]): m for m in evidence["methods"]}
                built = {}
                for member, classes in S.expected()["files"][name]["dex"].items():
                    for item in classes:
                        if item["expected_family"]:
                            for m in item["methods"]:
                                built[(member, item["descriptor"], m["name"], m["proto"])] = m
                self.assertEqual(set(seen), set(built))
                for key, want in built.items():
                    got = seen[key]
                    self.assertEqual((got["body"], got["insns_sha256"], got["method_idx"], got["insns_off"]),
                                     (want["body"], want["insns_sha256"], want["method_idx"], want["insns_off"]), key)
                    self.assertEqual(got["insns_bytes"], None if want["insns_units"] is None else 2 * want["insns_units"], key)

    def test_class_digests_equal_the_independent_recipe(self):
        for name in FIXTURE_NAMES:
            with self.subTest(name):
                report = report_of(S.facts(name))
                names = sorted(S.expected()["files"][name]["dex"], key=P.numeric_key)
                wanted = {}
                for member, classes in S.expected()["files"][name]["dex"].items():
                    for item in classes:
                        if item["expected_family"]:
                            wanted[(names.index(member), item["descriptor"])] = (item["expected_family"], item["method_bodies_sha256"])
                got = {(r["file_id"], r["class"]): (r["family"], r["method_bodies_sha256"]) for r in report["class_records"]}
                self.assertEqual(got, wanted)

    def test_resources_are_the_original_bytes_and_the_hand_made_hashes(self):
        frozen = S.frozen()
        for name in list(S.golden()["scenarios"]):
            with self.subTest(name):
                apk = S.GENERATED / name
                got = P.resource_fingerprints(apk)
                self.assertEqual(got, frozen.audit_common.resource_fingerprints(apk))
                self.assertEqual(got, S.expected()["files"][name]["resource_sha256"])

    def test_only_the_instruction_relations_are_read_and_no_text_rendering(self):
        for name in FIXTURE_NAMES:
            session = S.facts(name)
            report_of(session)
            for statement in session.statements:
                relations = set(re.findall(r"\bFROM (\w+)", statement["sql"]))
                self.assertTrue(relations <= ALLOWED_RELATIONS, statement["sql"])
                self.assertNotRegex(statement["sql"].lower(), r"opcode_hex|smali|decode")

    # -- negative controls
    def test_a_damaged_golden_does_not_match(self):
        report = report_of(S.facts("base.apk"))
        legacy = S.golden()["scenarios"]["base.apk"]["legacy"]
        self.assertIsNone(difference_from_golden(report, legacy))

        def flip(text):
            return ("0" if text[0] != "0" else "1") + text[1:]

        def damage_digest(g):
            g["report_sha256"] = flip(g["report_sha256"])

        def damage_class(g):
            g["report"]["class_records"][0]["method_bodies_sha256"] = flip(g["report"]["class_records"][0]["method_bodies_sha256"])

        def damage_resource(g):
            g["report"]["resource_fingerprints"]["resources.arsc"] = flip(g["report"]["resource_fingerprints"]["resources.arsc"])

        def damage_count(g):
            g["report"]["families"]["comment_legacy_v2"]["classes"] += 1

        def damage_edge(g):
            g["report"]["invoke_edges"].pop()

        for damage in (damage_digest, damage_class, damage_resource, damage_count, damage_edge):
            broken = copy.deepcopy(legacy)
            damage(broken)
            if damage is not damage_digest:
                broken["report_sha256"] = P.report_digest(broken["report"])  # a golden that is internally consistent but wrong
            with self.subTest(damage.__name__):
                self.assertIsNotNone(difference_from_golden(report, broken))

    def test_the_first_difference_is_named_by_its_coordinate(self):
        report = report_of(S.facts("base.apk"))
        legacy = copy.deepcopy(S.golden()["scenarios"]["base.apk"]["legacy"])
        legacy["report"]["class_records"][2]["superclass"] = "Lx/Other;"
        legacy["report_sha256"] = "0" * 64
        self.assertEqual(difference_from_golden(report, legacy), "class_records[2].superclass")

    def test_a_changed_instruction_byte_changes_the_report_and_names_the_class(self):
        member_offset = next(m["insns_off"] for item in S.expected()["files"]["base.apk"]["dex"]["classes.dex"]
                             if item["descriptor"] == "Lcom/bilibili/app/comm/comment2/Holder;" for m in item["methods"] if m["name"] == "bind")

        def edit(members):
            dex = bytearray(next(m for m in members if m[0] == "classes.dex")[1])
            dex[member_offset] ^= 0x01
            next(m for m in members if m[0] == "classes.dex")[1] = bytes(dex)

        apk = modified_apk(self.dir, "base.apk", edit)
        report = report_of(S.facts("base.apk", apk=apk), apk)
        difference = difference_from_golden(report, S.golden()["scenarios"]["base.apk"]["legacy"])
        self.assertIsNotNone(difference)
        self.assertRegex(difference, r"^(class_records\[\d+\]\.method_bodies_sha256|families\.comment_legacy_v2\.fingerprint)$")

    def test_a_changed_byte_in_a_resource_changes_the_report(self):
        def edit(members):
            next(m for m in members if m[0] == "resources.arsc")[1] = b"\x00\xff\x72\x65\x73\x6f\x75\x72\x63\x45"

        apk = modified_apk(self.dir, "base.apk", edit)
        report = report_of(S.facts("base.apk", apk=apk), apk)
        self.assertEqual(difference_from_golden(report, S.golden()["scenarios"]["base.apk"]["legacy"]), "resource_fingerprints.resources.arsc")

    def test_a_member_whose_bytes_do_not_match_its_checksum_is_refused_by_the_zip_reader(self):
        raw = bytearray((S.GENERATED / "base.apk").read_bytes())
        with zipfile.ZipFile(S.GENERATED / "base.apk") as archive:
            info = archive.getinfo("resources.arsc")
        raw[info.header_offset + 30 + len(info.filename)] ^= 0x01  # a data byte; the recorded CRC stays
        damaged = self.dir / "damaged.apk"
        damaged.write_bytes(bytes(raw))
        with self.assertRaises(zipfile.BadZipFile):
            P.resource_fingerprints(damaged)

    def test_smali_text_would_not_have_been_the_same_bytes(self):
        # the digest is over name+prototype and the raw instruction bytes: rendering the same bytes as text changes it
        expected = S.expected()["files"]["base.apk"]["dex"]["classes.dex"]
        holder = next(i for i in expected if i["descriptor"] == "Lcom/bilibili/app/comm/comment2/Holder;")
        raw = {(m["name"], m["proto"]): bytes.fromhex(m["insns_hex"] or "") for m in holder["methods"]}
        as_text = {k: v.hex(" ").encode() for k, v in raw.items()}  # any rendering of those bytes
        self.assertNotEqual(GEN.class_digest([(n, p, b) for (n, p), b in raw.items()]),
                            GEN.class_digest([(n, p, b) for (n, p), b in as_text.items()]))
        self.assertEqual(GEN.class_digest([(n, p, b) for (n, p), b in raw.items()]), holder["method_bodies_sha256"])


# ---- acceptance 2: local ids are read with their source -----------------------------------------------------------------

class LocalIdsAreReadWithTheirSource(Temp):
    def test_the_same_number_in_two_dex_files_names_two_methods_and_they_do_not_join(self):
        shared = S.expected()["shared_method_idx_in_base"]
        self.assertTrue(shared)
        session = S.facts("base.apk")
        by_file = {}
        for row in session.all("SELECT file_id,method_idx,method_descriptor FROM class_methods ORDER BY file_id,method_idx"):
            by_file.setdefault(row["file_id"], {})[row["method_idx"]] = row["method_descriptor"]
        index = shared[0]
        self.assertNotEqual(by_file["0"][str(index)], by_file["1"][str(index)])
        report = report_of(S.facts("base.apk"))
        self.assertIsNone(difference_from_golden(report, S.golden()["scenarios"]["base.apk"]["legacy"]))

    def test_the_same_class_in_two_dex_files_is_two_records_each_with_its_own_digest(self):
        report = report_of(S.facts("base.apk"))
        holders = [r for r in report["class_records"] if r["class"] == "Lcom/bilibili/app/comm/comment2/Holder;"]
        self.assertEqual(sorted(r["file_id"] for r in holders), [0, 1])
        self.assertEqual(len({r["method_bodies_sha256"] for r in holders}), 2)
        self.assertEqual(report["families"]["comment_legacy_v2"]["classes"], 2)

    def test_renumbering_the_engines_local_file_ids_changes_nothing(self):
        # the ids are local to the dataset; what is reported is the DEX file they stand for
        plain = P.report_digest(report_of(S.facts("base.apk")))
        swapped = P.report_digest(report_of(S.facts("base.apk", edit=lambda t: S.renumber(t, {0: 7, 1: 3}))))
        self.assertEqual(plain, swapped)

    def test_the_original_numbers_the_files_the_same_way(self):
        self.assertEqual(P.report_digest(original_report(S.facts("base.apk", edit=lambda t: S.renumber(t, {0: 7, 1: 3})))),
                         S.golden()["scenarios"]["base.apk"]["legacy"]["report_sha256"])

    def test_files_are_ordered_by_the_number_in_their_name_not_by_their_id_or_their_text(self):
        # text order puts classes10.dex before classes2.dex; HostLab's order is numeric, and its file_id is the position in it
        def rename(members):
            next(m for m in members if m[0] == "classes.dex")[0] = "classes10.dex"

        def rename_facts(tables):
            for row in tables["dex_files"]:
                if row[1] == "classes.dex":
                    row[1] = "classes10.dex"

        apk = modified_apk(self.dir, "base.apk", rename)
        wanted = outcome(lambda: original_report(S.facts("base.apk", rename_facts, apk)))
        got = outcome(lambda: report_of(S.facts("base.apk", rename_facts, apk), apk))
        self.assertEqual(wanted, got)
        self.assertEqual(got[0], "report")
        report = report_of(S.facts("base.apk", rename_facts, apk), apk)
        holders = {r["file_id"]: r["method_bodies_sha256"] for r in report["class_records"] if r["class"] == "Lcom/bilibili/app/comm/comment2/Holder;"}
        plain = {r["file_id"]: r["method_bodies_sha256"] for r in report_of(S.facts("base.apk"))["class_records"]
                 if r["class"] == "Lcom/bilibili/app/comm/comment2/Holder;"}
        self.assertEqual(holders, {0: plain[1], 1: plain[0]})

    # -- negative controls: a swapped or foreign source identity fails
    def test_swapped_entry_names_are_refused_because_the_bytes_are_not_the_facts(self):
        def swap(tables):
            rows = tables["dex_files"]
            rows[0][1], rows[1][1] = rows[1][1], rows[0][1]

        with self.assertRaises(P.SourceMismatch) as caught:
            report_of(S.facts("base.apk", edit=swap))
        self.assertRegex(str(caught.exception), r"length|checksum|signature")

    def test_facts_of_one_archive_with_the_bytes_of_another_are_refused(self):
        with self.assertRaises(P.SourceMismatch):
            report_of(S.facts("base.apk", apk=S.GENERATED / "target.apk"))

    def test_a_changed_header_signature_in_the_facts_is_refused(self):
        def change(tables):
            row = tables["dex_files"][0]
            row[5] = ("0" if row[5][0] != "0" else "1") + row[5][1:]

        with self.assertRaises(P.SourceMismatch) as caught:
            report_of(S.facts("base.apk", edit=change))
        self.assertIn("signature", str(caught.exception))

    def test_a_row_of_another_file_does_not_pass_for_the_file_that_was_asked_for(self):
        class Wrong(S.FactSession):
            def rows(self, sql, **bounds):
                for row in super().rows(sql, **bounds):
                    if "FROM classes" in sql and "file_id=0" in sql:
                        row = dict(row, file_id="1")
                    yield row

        session = Wrong(S.GENERATED / "base.apk", copy.deepcopy(S.golden()["scenarios"]["base.apk"]["relations"]))
        with self.assertRaises(P.SourceMismatch) as caught:
            report_of(session)
        self.assertIn("file_id 1", str(caught.exception))

    def test_a_code_row_of_another_file_does_not_pass_for_the_file_that_was_asked_for(self):
        class WrongCode(S.FactSession):
            def rows(self, sql, **bounds):
                for row in super().rows(sql, **bounds):
                    if "FROM code_items" in sql and "file_id=0" in sql:
                        row = dict(row, file_id="1")
                    yield row

        session = WrongCode(S.GENERATED / "base.apk", copy.deepcopy(S.golden()["scenarios"]["base.apk"]["relations"]))
        with self.assertRaises(P.SourceMismatch) as caught:
            report_of(session)
        self.assertIn("code row of file_id 1", str(caught.exception))

    def test_two_members_of_one_name_in_the_archive_are_refused(self):
        def duplicate(members):
            members.append(list(next(m for m in members if m[0] == "classes.dex")))

        apk = modified_apk(self.dir, "base.apk", duplicate)
        with self.assertRaises(P.SourceMismatch) as caught:
            report_of(S.facts("base.apk", apk=apk), apk)
        self.assertIn("2 members", str(caught.exception))

    def test_a_member_that_is_missing_from_the_archive_is_refused(self):
        apk = modified_apk(self.dir, "base.apk", lambda members: members.__setitem__(slice(None), [m for m in members if m[0] != "classes2.dex"]))
        with self.assertRaises(P.SourceMismatch):
            report_of(S.facts("base.apk", apk=apk), apk)

    def test_one_file_id_for_two_dex_files_or_one_name_for_two_files_is_refused(self):
        with self.assertRaises(P.SourceMismatch):
            P.read_identities(S.facts("base.apk", edit=lambda t: t["dex_files"][1].__setitem__(0, "0")))
        with self.assertRaises(P.SourceMismatch):
            P.read_identities(S.facts("base.apk", edit=lambda t: t["dex_files"][1].__setitem__(1, "classes.dex")))

    def test_a_dex_that_is_not_an_admitted_version_is_refused_as_the_original_refuses_it(self):
        def patch(members):
            dex = bytearray(next(m for m in members if m[0] == "classes.dex")[1])
            dex[4:7] = b"041"
            next(m for m in members if m[0] == "classes.dex")[1] = bytes(dex)

        apk = modified_apk(self.dir, "base.apk", patch)
        wanted = outcome(lambda: original_report(S.facts("base.apk", apk=apk)))
        got = outcome(lambda: report_of(S.facts("base.apk", apk=apk), apk))
        self.assertEqual(wanted, got)
        self.assertEqual(got, ("raised", "UnsupportedAudit", "native raw-code fingerprint DEX version is not admitted"))


# ---- acceptance 3: bodies, empty values, duplicates, order ------------------------------------------------------------------

def body_row(tables, method="bind", file="0", owner="Lcom/bilibili/app/comm/comment2/Holder;"):
    """The code_items row of a family method that has a body."""
    index = next(r[3] for r in tables["class_methods"] if r[0] == file and r[2] == owner and r[4] == method)
    return next(c for c in tables["code_items"] if c[0] == file and c[1] == index)


def class_row(tables, descriptor, file="0"):
    return next(r for r in tables["classes"] if r[0] == file and r[3] == descriptor)


class BodiesEmptyValuesDuplicatesAndOrder(Temp):
    HOLDER = "Lcom/bilibili/app/comm/comment2/Holder;"

    def same_as_the_original(self, name, edit):
        a = outcome(lambda: original_report(S.facts(name, edit)))
        b = outcome(lambda: report_of(S.facts(name, edit)))
        self.assertEqual(a, b)
        return b

    def test_methods_without_a_body_contribute_their_name_and_prototype_only(self):
        evidence = {"methods": [], "dex": [], "resources": [], "resource_duplicates": []}
        report_of(S.facts("base.apk"), evidence=evidence)
        bodiless = {(m["name"], m["proto"]) for m in evidence["methods"] if m["class"] == self.HOLDER and m["file_id"] == 0 and m["body"] == "none"}
        self.assertEqual(bodiless, {("hook", "(I)V"), ("jni", "()I")})  # abstract and native
        holder = next(i for i in S.expected()["files"]["base.apk"]["dex"]["classes.dex"] if i["descriptor"] == self.HOLDER)
        recipe = [(m["name"], m["proto"], bytes.fromhex(m["insns_hex"] or "")) for m in holder["methods"]]
        self.assertEqual(GEN.class_digest(recipe), holder["method_bodies_sha256"])

    def test_a_missing_code_row_and_an_unaltered_report_differ_exactly_in_that_method(self):
        def drop(tables):
            row = next(r for r in tables["class_methods"] if r[0] == "0" and r[4] == "bind")
            tables["code_items"] = [c for c in tables["code_items"] if not (c[0] == "0" and c[1] == row[3])]

        kind, digest = self.same_as_the_original("base.apk", drop)
        self.assertEqual(kind, "report")
        self.assertNotEqual(digest, S.golden()["scenarios"]["base.apk"]["legacy"]["report_sha256"])

    def test_an_empty_body_is_stated_as_empty_and_counts_as_no_instructions_as_in_the_original(self):
        def empty(tables):
            row = next(r for r in tables["class_methods"] if r[0] == "0" and r[4] == "bind")
            for c in tables["code_items"]:
                if c[0] == "0" and c[1] == row[3]:
                    c[3] = "0"

        def drop(tables):
            row = next(r for r in tables["class_methods"] if r[0] == "0" and r[4] == "bind")
            tables["code_items"] = [c for c in tables["code_items"] if not (c[0] == "0" and c[1] == row[3])]

        self.assertEqual(self.same_as_the_original("base.apk", empty), self.same_as_the_original("base.apk", drop))
        evidence = {"methods": [], "dex": [], "resources": [], "resource_duplicates": []}
        report_of(S.facts("base.apk", empty), evidence=evidence)
        bodies = {m["body"] for m in evidence["methods"] if m["name"] == "bind" and m["file_id"] == 0 and m["class"] == self.HOLDER}
        self.assertEqual(bodies, {"empty"})

    def test_a_family_class_without_any_method_in_a_file_without_family_methods(self):
        # the original raises KeyError in summarize; the provider gives the class the digest of nothing (DIFF-1)
        legacy = S.golden()["scenarios"]["fields-only.apk"]["legacy"]
        self.assertEqual((legacy["outcome"], legacy["type"]), ("raised", "KeyError"))
        with self.assertRaises(KeyError):
            original_report(S.facts("fields-only.apk"))
        report = report_of(S.facts("fields-only.apk"))
        nothing = hashlib.sha256(b"").hexdigest()
        self.assertEqual([(r["class"], r["method_bodies_sha256"], r["compose_signatures"]) for r in report["class_records"]],
                         [("Lcom/bilibili/app/comm/comment2/Holder;", nothing, []), ("Lcom/bilibili/bplus/dynamicFoo/Card;", nothing, [])])
        self.assertEqual([r["fields"] for r in report["class_records"]], [[("COUNT", "I"), ("tag", "Ljava/lang/String;")], [("id", "J")]])
        expected = S.expected()["files"]["fields-only.apk"]["dex"]["classes.dex"]
        self.assertEqual([i["method_bodies_sha256"] for i in expected], [nothing, nothing])

    def test_a_class_without_methods_in_a_file_that_has_family_methods_is_the_same_as_the_original(self):
        def strip(tables):
            tables["class_methods"] = [r for r in tables["class_methods"] if not (r[0] == "0" and r[2] == "Lkntr/app/following/Misc;")]

        kind, _ = self.same_as_the_original("base.apk", strip)
        self.assertEqual(kind, "report")

    def test_empty_values_survive_nulls_empty_lists_and_empty_resources(self):
        report = report_of(S.facts("base.apk"))
        record = next(r for r in report["class_records"] if r["class"] == "Lcom/bilibili/app/comment3/ui/holder/Item;")
        self.assertEqual(record["fields"], [])
        self.assertEqual(report["resource_fingerprints"]["res/layout/empty.xml"], hashlib.sha256(b"").hexdigest())

        def null_super(tables):
            class_row(tables, "Lcom/bilibili/app/comm/comment2/Holder;")[4] = None

        kind, _ = self.same_as_the_original("base.apk", null_super)
        self.assertEqual(kind, "report")
        self.assertIsNone(next(r for r in report_of(S.facts("base.apk", null_super))["class_records"] if r["class"] == self.HOLDER and r["file_id"] == 0)["superclass"])

    # -- duplicates
    def test_a_class_defined_twice_in_one_file_is_refused_as_in_the_original(self):
        def duplicate(tables):
            row = list(class_row(tables, self.HOLDER))
            row[1], row[2] = "99", "99"
            tables["classes"].append(row)

        a = self.same_as_the_original("base.apk", duplicate)
        self.assertEqual(a, ("raised", "UnsupportedAudit", "duplicate class definition in native surface scan"))

    def test_a_method_defined_twice_in_one_class_is_refused_as_in_the_original(self):
        def duplicate(tables):
            row = list(next(r for r in tables["class_methods"] if r[0] == "0" and r[4] == "bind"))
            row[3] = "9999"
            tables["class_methods"].append(row)

        a = self.same_as_the_original("base.apk", duplicate)
        self.assertEqual(a, ("raised", "UnsupportedAudit", "duplicate method definition in native surface scan"))

    def test_one_method_idx_for_two_methods_of_one_file_is_refused_where_the_original_keeps_the_last(self):
        def collide(tables):
            first, second = [r for r in tables["class_methods"] if r[0] == "0" and r[2] == self.HOLDER][:2]
            second[3] = first[3]

        self.assertEqual(outcome(lambda: original_report(S.facts("base.apk", collide)))[0], "report")  # silently wrong
        with self.assertRaises(P.SurfaceError) as caught:
            report_of(S.facts("base.apk", collide))
        self.assertIn("names two methods", str(caught.exception))

    def test_two_code_rows_for_one_method_are_refused_where_the_original_keeps_the_last(self):
        def twice(tables):
            tables["code_items"].append(list(body_row(tables)))

        self.assertEqual(outcome(lambda: original_report(S.facts("base.apk", twice)))[0], "report")
        with self.assertRaises(P.SurfaceError) as caught:
            report_of(S.facts("base.apk", twice))
        self.assertIn("two code rows", str(caught.exception))

    def test_a_dex_with_a_hash_in_its_name_or_an_ambiguous_number_is_refused_as_in_the_original(self):
        def logical(tables):
            tables["dex_files"][1][1] = "classes.dex#1"

        def ambiguous(tables):
            tables["dex_files"][0][1] = "classes02.dex"
            tables["dex_files"][1][1] = "classes2.dex"

        self.assertEqual(self.same_as_the_original("base.apk", logical)[2], "DEX 041 container fingerprint equivalence is not admitted")
        self.assertEqual(self.same_as_the_original("base.apk", ambiguous)[2], "ambiguous numeric DEX ordering in fingerprint input")

    def test_a_code_interval_outside_the_dex_or_at_an_odd_offset_is_refused_as_in_the_original(self):
        def far(tables):
            body_row(tables)[2] = "100000000"

        def odd(tables):
            row = body_row(tables)
            row[2] = str(int(row[2]) + 1)

        for edit in (far, odd):
            with self.subTest(edit.__name__):
                result = self.same_as_the_original("base.apk", edit)
                self.assertEqual(result, ("raised", "RuntimeError", "native code interval is outside the verified DEX"))

    # -- order
    def test_overloads_are_hashed_in_the_spaced_prototype_order(self):
        holder = next(i for i in S.expected()["files"]["base.apk"]["dex"]["classes.dex"] if i["descriptor"] == self.HOLDER)
        self.assertGreaterEqual({m["proto"] for m in holder["methods"] if m["name"] == "m"}, {"(I)V", "(IJ)V"})
        records = {r["class"]: r for r in report_of(S.facts("base.apk"))["class_records"] if r["file_id"] == 0}
        self.assertEqual(records[self.HOLDER]["method_bodies_sha256"], holder["method_bodies_sha256"])
        # the plain order gives another digest, so the comparison above can tell the two orders apart
        members = [(m["name"], m["proto"], bytes.fromhex(m["insns_hex"] or "")) for m in holder["methods"]]
        plain = hashlib.sha256()
        for name, proto, raw in sorted(members, key=lambda m: (m[0], m[1])):
            plain.update((name + proto).encode())
            plain.update(raw)
        self.assertNotEqual(plain.hexdigest(), holder["method_bodies_sha256"])

    def test_fields_and_methods_are_listed_sorted_and_classes_in_definition_order(self):
        report = report_of(S.facts("base.apk"))
        for record in report["class_records"]:
            self.assertEqual(record["fields"], sorted(record["fields"]))
            self.assertEqual(record["methods"], sorted(record["methods"]))
        self.assertEqual([r["file_id"] for r in report["class_records"]], sorted(r["file_id"] for r in report["class_records"]))
        defined = [r[3] for r in S.golden()["scenarios"]["base.apk"]["relations"]["classes"] if r[0] == "0"]
        listed = [r["class"] for r in report["class_records"] if r["file_id"] == 0]
        self.assertEqual(listed, [d for d in defined if d in listed])

    def test_the_order_the_engine_holds_its_rows_in_does_not_matter(self):
        def reverse(tables):
            for rows in tables.values():
                rows.reverse()

        self.assertEqual(P.report_digest(report_of(S.facts("base.apk", reverse))), S.golden()["scenarios"]["base.apk"]["legacy"]["report_sha256"])

    def test_duplicate_call_sites_are_one_edge_and_their_number_is_kept(self):
        report = report_of(S.facts("base.apk"))
        calls = S.golden()["scenarios"]["base.apk"]["relations"]["method_calls"]
        self.assertEqual(len(report["invoke_edges"]), len(set(map(tuple, report["invoke_edges"]))))

        def double(tables):
            tables["method_calls"] = tables["method_calls"] + [list(r) for r in tables["method_calls"]]

        again = report_of(S.facts("base.apk", double))
        self.assertEqual(again["invoke_edges"], report["invoke_edges"])
        self.assertEqual(sum(f["external_invoke_edges"] for f in again["families"].values()),
                         sum(f["external_invoke_edges"] for f in report["families"].values()))
        self.assertTrue(calls)
        self.assertEqual(outcome(lambda: original_report(S.facts("base.apk", double))), outcome(lambda: report_of(S.facts("base.apk", double))))


# ---- acceptance 3 (end): the cross-version comparison ----------------------------------------------------------------------------

class TheCrossVersionComparison(Temp):
    def reports(self):
        return {name: report_of(S.facts(name)) for name in ("base.apk", "target.apk")}

    def test_changes_resource_changes_and_verdict_are_the_originals_for_every_pair(self):
        reports = self.reports()
        context = S.golden()["context"]
        for key, wanted in S.golden()["cross_version"].items():
            before, after = key.split("->")
            with self.subTest(key):
                got = P.cross_version(reports[before], reports[after], S.host(), context=context)
                self.assertEqual(json.loads(P.canonical_json(got)), wanted)

    def test_the_four_classifications_are_all_present_and_unchanged(self):
        wanted = S.golden()["cross_version"]["base.apk->target.apk"]["changes"]
        kinds = {c["kind"] for c in wanted}
        self.assertEqual(kinds, {"new_family_candidate", "retired_family_candidate", "structure_or_call_path_changed",
                                 "protocol_signature_or_call_path_changed"})
        reports = self.reports()
        got = S.frozen().workers.compare(reports["base.apk"], reports["target.apk"])
        self.assertEqual([(c["family"], c["kind"]) for c in got], [(c["family"], c["kind"]) for c in wanted])
        # added in one direction is removed in the other
        back = {c["family"]: c["kind"] for c in S.frozen().workers.compare(reports["target.apk"], reports["base.apk"])}
        self.assertEqual(back["pgc_legacy"], "retired_family_candidate")
        self.assertEqual(back["comment_native_legacy"], "new_family_candidate")

    def test_resource_changes_list_added_removed_and_changed_names(self):
        reports = self.reports()
        resources = S.frozen().priority.resource_changes(reports["base.apk"], reports["target.apk"])
        self.assertEqual((resources["added"], resources["removed"], resources["changed"]),
                         (["res/layout/new.xml"], ["res/xml/b.xml"], ["res/layout/a.xml"]))

    def test_an_unchanged_pair_has_no_changes(self):
        reports = self.reports()
        self.assertEqual(S.frozen().workers.compare(reports["base.apk"], reports["base.apk"]), [])

    def test_a_stored_report_compares_with_a_fresh_one_as_two_fresh_ones_do(self):
        fresh = report_of(S.facts("base.apk"))
        stored = json.loads(json.dumps(fresh))
        compare = S.frozen().workers.compare
        self.assertNotEqual(compare(stored, fresh), [])  # JSON turned the signatures into lists: a spurious change
        self.assertEqual(compare(P.restore_shapes(json.loads(json.dumps(fresh))), fresh), [])
        self.assertEqual(P.report_digest(P.restore_shapes(json.loads(json.dumps(fresh)))), P.report_digest(fresh))

    def test_restoring_shapes_touches_nothing_that_is_not_there(self):
        self.assertEqual(P.restore_shapes({"rule_sha256": "x"}), {"rule_sha256": "x"})

    def test_reports_made_under_other_rules_are_not_compared(self):
        reports = self.reports()
        other = dict(reports["target.apk"], rule_sha256="0" * 64)
        with self.assertRaises(RuntimeError):
            P.cross_version(reports["base.apk"], other, S.host(), context=None)

    def test_a_host_without_the_comparison_functions_is_refused(self):
        host = S.host()
        bare = P.Host(host.workers, host.resource_fingerprints, host.unsupported)
        with self.assertRaises(P.SurfaceError):
            P.cross_version({}, {}, bare)

    def test_a_changed_family_in_the_golden_changes_the_classification_result(self):
        reports = self.reports()
        wanted = copy.deepcopy(S.golden()["cross_version"]["base.apk->target.apk"])
        wanted["changes"][0]["kind"] = "new_family_candidate"
        got = json.loads(P.canonical_json(P.cross_version(reports["base.apk"], reports["target.apk"], S.host(), context=S.golden()["context"])))
        self.assertNotEqual(got, wanted)
        self.assertEqual(P.first_difference(got, wanted), "changes[0].kind")


# ---- the original resource bytes -----------------------------------------------------------------------------------------------------

class ResourceFingerprints(Temp):
    NAMES = ["resources.arsc", "res/a.xml", "res/sub/dir/b.xml", "xres/c.xml", "res/d.xml/", "res/e.xmlx", "RES/f.xml",
             "assets/g.xml", "resources.arsc.bak", "res/.xml", "res/h.XML", "Resources.arsc", "res/i.xml.tmp", "res/j.png"]

    def test_the_same_members_are_fingerprinted_as_in_the_original(self):
        entries = [(n, f"data:{n}".encode(), "stored" if i % 2 else "deflated") for i, n in enumerate(self.NAMES)]
        path = self.dir / "names.apk"
        path.write_bytes(GEN.zip_bytes(entries))
        got = P.resource_fingerprints(path)
        self.assertEqual(got, S.frozen().audit_common.resource_fingerprints(path))
        self.assertEqual(sorted(got), ["res/.xml", "res/a.xml", "res/sub/dir/b.xml", "resources.arsc"])

    def test_a_name_that_occurs_twice_keeps_its_last_occurrence_and_both_are_listed(self):
        path = S.GENERATED / "duplicate-resource.apk"
        evidence = {}
        got = P.resource_fingerprints(path, evidence=evidence)
        self.assertEqual(got, S.frozen().audit_common.resource_fingerprints(path))
        self.assertEqual(got["res/layout/a.xml"], hashlib.sha256(b"second").hexdigest())
        self.assertEqual(evidence["resource_duplicates"], ["res/layout/a.xml"])
        self.assertEqual([r["sha256"] for r in evidence["resources"]], [hashlib.sha256(b"first").hexdigest(), hashlib.sha256(b"second").hexdigest()])

    def test_a_compressed_member_is_fingerprinted_by_its_original_bytes(self):
        got = P.resource_fingerprints(S.GENERATED / "base.apk")
        self.assertEqual(got["res/layout/a.xml"], hashlib.sha256(b"<layout a=1/>").hexdigest())

    def test_an_archive_that_is_not_a_zip_is_an_error_not_an_empty_result(self):
        path = self.dir / "not-a-zip.apk"
        path.write_bytes(b"this is not an archive")
        with self.assertRaises(zipfile.BadZipFile):
            P.resource_fingerprints(path)

    def test_a_different_byte_in_a_resource_is_a_different_fingerprint(self):
        entries = [("res/a.xml", b"abc", "stored")]
        a, b = self.dir / "a.apk", self.dir / "b.apk"
        a.write_bytes(GEN.zip_bytes(entries))
        b.write_bytes(GEN.zip_bytes([("res/a.xml", b"abd", "stored")]))
        self.assertNotEqual(P.resource_fingerprints(a), P.resource_fingerprints(b))


# ---- the engine's stream ---------------------------------------------------------------------------------------------------------------

SNAP = "snapshot-1"
OPENED = {"kind": "opened", "protocol": "mdd.cli-stream.v1",
          "dataset": {"snapshot_id": SNAP, "scope_id": "sha256:s", "sql_dialect": "dexsql-0.1.0", "layer_issues": [], "dex_count": 1}}


def terminal(emitted, **over):
    body = {"operation_status": "ok", "coverage": {"input": "complete", "facts": "complete"}, "execution": {"complete": True},
            "response": {"emitted_rows": str(emitted), "truncated": False, "more_available": False}, "snapshot_id": SNAP, "error": None}
    for key, value in over.items():
        if key == "input" or key == "facts":
            body["coverage"][key] = value
        elif key == "complete":
            body["execution"]["complete"] = value
        elif key in ("truncated", "more_available"):
            body["response"][key] = value
        elif key == "emitted":
            body["response"]["emitted_rows"] = value
        else:
            body[key] = value
    return {"kind": "terminal", "id": "@id", "terminal": body}


def batch(columns, rows):
    return {"kind": "batch", "id": "@id", "batch": {"columns": columns, "rows": rows}}


U = lambda v: {"t": "u64", "v": str(v)}  # noqa: E731
T = lambda v: {"t": "text", "v": v}  # noqa: E731
FILES = [batch(["file_id", "entry_name"], [[U(0), T("classes.dex")]]), terminal(1)]


def fake_session(directory, answers, opened=OPENED, then="close", log=None, deaf_seconds=0, **options):
    script = Path(directory) / "script.json"
    script.write_text(json.dumps({"opened": opened, "answers": answers, "then": then, "deaf_seconds": deaf_seconds,
                                  "log": None if log is None else str(log)}), encoding="utf-8")
    fake = Path(__file__).resolve().parent / "surface_fake_serve.py"
    options.setdefault("deadline_seconds", 20)
    return P.ServeSession([sys.executable, "-I", str(fake), str(script)], S.GENERATED / "plain.apk", **options)


class TheEnginesStream(Temp):
    def session(self, answers, opened=OPENED, then="close", **options):
        return fake_session(self.dir, answers, opened, then, **options)

    def query(self, answer, **options):
        with self.session([FILES[:], answer], **options) as session:
            return session.all("SELECT a FROM t ORDER BY a")

    def test_a_complete_answer_is_handed_over_as_typed_values(self):
        rows = self.query([batch(["a", "b", "c", "d"], [[U(1), {"t": "i64", "v": "-2"}, T("x"), {"t": "null"}]]), terminal(1)])
        self.assertEqual(rows, [{"a": 1, "b": -2, "c": "x", "d": None}])

    def test_the_files_of_the_dataset_are_read_when_it_is_opened(self):
        with self.session([FILES[:]]) as session:
            self.assertEqual(session.files, {0: "classes.dex"})
            self.assertEqual(session.opened["snapshot_id"], SNAP)

    def test_a_result_in_several_batches_is_one_result(self):
        rows = self.query([batch(["a"], [[U(1)], [U(2)]]), batch(["a"], [[U(3)]]), terminal(3)])
        self.assertEqual([r["a"] for r in rows], [1, 2, 3])

    def test_an_empty_complete_answer_is_an_empty_result(self):
        self.assertEqual(self.query([terminal(0)]), [])

    def test_nothing_that_is_not_complete_is_an_empty_or_a_shorter_result(self):
        rows = [batch(["a"], [[U(1)], [U(2)]])]
        broken = {
            "truncated": terminal(2, truncated=True), "more rows available": terminal(2, more_available=True),
            "input partial": terminal(2, input="partial"), "input unknown": terminal(2, input="unknown"),
            "facts partial": terminal(2, facts="partial"), "facts unknown": terminal(2, facts="unknown"),
            "execution incomplete": terminal(2, complete=False), "fewer rows than said": terminal(3),
            "more rows than said": terminal(1), "another snapshot": terminal(2, snapshot_id="snapshot-2"),
            "no snapshot": terminal(2, snapshot_id=None),
        }
        for label, last in broken.items():
            with self.subTest(label), self.assertRaises(P.IncompleteFacts):
                self.query(rows + [last])

    def test_an_error_status_is_the_engines_error_with_its_code(self):
        error = {"code": "INVALID_ARGUMENT", "kind": "invalid_query", "message": "no such column"}
        with self.assertRaises(P.EngineFailure) as caught:
            self.query([terminal(0, operation_status="error", error=error)])
        self.assertEqual(caught.exception.detail, {"error": error})
        self.assertEqual(base.classify_failure(caught.exception).code, "INVALID_ARGUMENT")

    def test_rows_before_an_error_are_not_a_result(self):
        with self.assertRaises(P.EngineFailure):
            self.query([batch(["a"], [[U(1)]]), terminal(1, operation_status="error", error={"code": "DEADLINE_EXCEEDED"})])

    def test_a_rejected_request_is_the_engines_error(self):
        with self.assertRaises(P.EngineFailure) as caught:
            self.query([{"kind": "rejected", "id": "@id", "error": {"code": "INVALID_ARGUMENT", "message": "bad"}}])
        self.assertEqual(base.classify_failure(caught.exception).code, "INVALID_ARGUMENT")

    def test_an_answer_for_another_request_is_refused(self):
        with self.assertRaises(P.IncompleteFacts):
            self.query([dict(terminal(0), id="other")])

    def test_a_stream_that_stops_early_is_not_an_empty_result(self):
        with self.assertRaises(P.IncompleteFacts) as caught:
            self.query([batch(["a"], [[U(1)]])], then="exit3")
        self.assertIn("exit status", str(caught.exception))

    def test_a_line_that_is_not_json_or_not_an_object_is_refused(self):
        for line in ("this is not json", "[1, 2]"):
            with self.subTest(line), self.assertRaises(P.IncompleteFacts):
                self.query([line])

    def test_cells_of_other_kinds_are_refused(self):
        for cell in ({"t": "f64", "bits": "3ff8000000000000"}, {"t": "bytes", "v": "0a"}, {"t": "u64"}, "x", {"t": "text", "v": 3}):
            with self.subTest(cell), self.assertRaises(P.SurfaceError):
                self.query([batch(["a"], [[cell]]), terminal(1)])

    def test_a_row_of_the_wrong_width_or_changing_columns_is_refused(self):
        with self.assertRaises(RuntimeError):
            self.query([batch(["a", "b"], [[U(1)]]), terminal(1)])
        with self.assertRaises(P.IncompleteFacts):
            self.query([batch(["a"], [[U(1)]]), batch(["b"], [[U(2)]]), terminal(2)])
        with self.assertRaises(RuntimeError):
            self.query([batch(["a", "a"], [[U(1), U(2)]]), terminal(1)])

    def test_the_byte_budget_is_enforced(self):
        with self.session([FILES[:], [batch(["a"], [[T("x" * 50)]]), terminal(1)]]) as session:
            with self.assertRaises(RuntimeError):
                session.all("SELECT a FROM t ORDER BY a", max_bytes=10)

    def test_a_statement_without_an_order_is_refused_before_anything_is_sent(self):
        with self.session([FILES[:]]) as session:
            with self.assertRaises(ValueError):
                session.all("SELECT a FROM t")

    def test_an_engine_that_does_not_open_the_dataset_properly_is_refused(self):
        cases = {"not an opening": {"kind": "terminal"}, "another protocol": dict(OPENED, protocol="other"),
                 "layers that could not be built": dict(OPENED, dataset=dict(OPENED["dataset"], layer_issues=[{"layer": "code"}])),
                 "another dialect": dict(OPENED, dataset=dict(OPENED["dataset"], sql_dialect="native-v1"))}
        for label, opened in cases.items():
            with self.subTest(label), self.assertRaises(P.IncompleteFacts):
                with self.session([FILES[:]], opened=opened, dialect="dexsql-0.1.0"):
                    pass

    def test_an_engine_that_never_answers_is_stopped_at_the_deadline(self):
        with self.assertRaises(TimeoutError):
            with self.session([FILES[:]], then="hang", deadline_seconds=3) as session:
                session.all("SELECT a FROM t ORDER BY a")

    def test_an_engine_that_ends_with_an_error_status_after_a_clean_close_is_an_error(self):
        with self.assertRaises(P.SurfaceError) as caught:
            with self.session([FILES[:]], then="exit3"):
                pass
        self.assertIn("status 3", str(caught.exception))

    def test_the_engine_does_not_outlive_a_failed_session(self):
        holder = {}
        raised = []

        def run():
            try:
                with self.session([FILES[:]], then="hang") as session:
                    holder["process"] = session._process
                    raise ValueError("the caller failed")
            except BaseException as error:  # noqa: BLE001 - the outcome is asserted below, not swallowed
                raised.append(error)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(timeout=15)
        self.assertFalse(worker.is_alive(), "the failed session did not stop the engine in time")
        self.assertEqual([type(e) for e in raised], [ValueError])
        self.assertIsNotNone(holder["process"].poll())

    def test_a_request_the_engine_does_not_read_is_stopped_at_the_deadline(self):
        # the engine answers the opening query, then stops reading stdin; a statement larger than the pipe buffer
        # cannot be written, and the write must be bounded by the deadline, not waited for forever
        big = "SELECT a FROM t WHERE x='" + "y" * 200000 + "' ORDER BY a"
        session = self.session([FILES[:]], deaf_seconds=8, deadline_seconds=3)
        with self.assertRaises(TimeoutError) as caught:
            with session:
                session.all(big)
        self.assertIn("read the request", str(caught.exception))
        self.assertIsNotNone(session._process.poll())

    def test_a_page_size_override_is_refused_because_the_stream_pages_by_batch_rows(self):
        log = self.dir / "requests.jsonl"
        with fake_session(self.dir, [FILES[:]], log=log) as session:
            with self.assertRaises(ValueError):
                session.all("SELECT a FROM t ORDER BY a", page_size=1000)
        requests = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(requests, [
            {"id": "r1", "sql": "SELECT file_id,entry_name FROM dex_files ORDER BY file_id", "batch_rows": 1000, "max_rows": 500000},
            {"op": "close"}])  # nothing was sent for the refused override


# ---- the details that are easy to get wrong ----------------------------------------------------------------------------------------

def most_ors_in_a_group(text):
    """The largest number of ` OR ` joining things at one parenthesis level: 1 in a balanced tree, as many as there are terms in a chain."""
    stack, worst = [0], 0
    index = 0
    while index < len(text):
        if text[index] == "(":
            stack.append(0)
        elif text[index] == ")":
            worst = max(worst, stack.pop())
        elif text.startswith(" OR ", index):
            stack[-1] += 1
        index += 1
    return max(worst, stack[0])


class TheDetailsThatAreEasyToGetWrong(Temp):
    HOLDER = "Lcom/bilibili/app/comm/comment2/Holder;"

    def test_each_group_of_the_filter_joins_two_things_at_most(self):
        self.assertLessEqual(most_ors_in_a_group(P.family_filter(S.frozen().workers, "d")), 1)
        self.assertGreater(most_ors_in_a_group(S.frozen().surface.family_filter("d")), 30)  # the original's chain, so the measure can tell

    def test_a_field_name_with_a_colon_is_cut_at_the_first_colon_as_in_the_original(self):
        def edit(tables):
            row = next(r for r in tables["class_fields"] if r[0] == "0" and r[4] == "tag")
            row[5] = self.HOLDER + "->tag:odd:Ljava/lang/String;"

        a = outcome(lambda: original_report(S.facts("base.apk", edit)))
        b = outcome(lambda: report_of(S.facts("base.apk", edit)))
        self.assertEqual(a, b)
        record = next(r for r in report_of(S.facts("base.apk", edit))["class_records"] if r["class"] == self.HOLDER and r["file_id"] == 0)
        self.assertIn(("tag", "odd:Ljava/lang/String;"), record["fields"])

    def test_the_order_the_engine_lists_methods_and_fields_in_does_not_matter(self):
        def edit(tables):
            first = next(r for r in tables["class_methods"] if r[0] == "0" and r[2] == self.HOLDER and r[5].endswith("->m(I)V"))
            second = next(r for r in tables["class_methods"] if r[0] == "0" and r[2] == self.HOLDER and r[5].endswith("->m(IJ)V"))
            swap = {first[3]: second[3], second[3]: first[3]}
            first[3], second[3] = second[3], first[3]
            for row in tables["code_items"]:
                if row[0] == "0":
                    row[1] = swap.get(row[1], row[1])
            fields = [r for r in tables["class_fields"] if r[0] == "0" and r[2] == self.HOLDER]
            self.assertEqual(len(fields), 2)
            fields[0][3], fields[1][3] = fields[1][3], fields[0][3]

        got = report_of(S.facts("base.apk", edit))
        self.assertEqual(P.report_digest(got), S.golden()["scenarios"]["base.apk"]["legacy"]["report_sha256"])
        self.assertEqual(outcome(lambda: original_report(S.facts("base.apk", edit))), outcome(lambda: report_of(S.facts("base.apk", edit))))

    def test_the_parts_handed_to_the_summary_are_the_originals(self):
        def doubled(tables):
            tables["method_calls"] = tables["method_calls"] + [list(r) for r in tables["method_calls"][:5]]

        workers = S.frozen().workers
        for name in FIXTURE_NAMES:
            for edit in (None, doubled):
                with self.subTest(name, edited=edit is not None):
                    captured = []
                    real = workers.summarize
                    with mock.patch.object(workers, "summarize", side_effect=lambda parts: (captured.append(copy.deepcopy(parts)), real(parts))[1]):
                        original_report(S.facts(name, edit))
                    mine = P.scan_parts(S.facts(name, edit), S.host(), S.GENERATED / name)
                    self.assertEqual(captured[0], mine)

    def test_a_repeated_call_site_adds_to_the_count_but_not_to_the_edges(self):
        def doubled(tables):
            tables["method_calls"] = tables["method_calls"] + [list(r) for r in tables["method_calls"]]

        single = P.scan_parts(S.facts("base.apk"), S.host(), S.GENERATED / "base.apk")
        twice = P.scan_parts(S.facts("base.apk", doubled), S.host(), S.GENERATED / "base.apk")
        self.assertEqual([p["edges"] for p in twice], [p["edges"] for p in single])
        self.assertEqual([[c[2] for c in p["edge_counts"]] for p in twice], [[2 * c[2] for c in p["edge_counts"]] for p in single])

    def test_integers_from_the_engine_are_numbers_and_nothing_else(self):
        for good, want in ((0, 0), (7, 7), ("12", 12), ("0", 0)):
            self.assertEqual(P.as_int(good, "x"), want)
        for bad in (-1, True, False, 1.5, None, "-1", "1.0", "", " 1", chr(0x661) + chr(0x662), [1], b"1"):
            with self.subTest(bad), self.assertRaises(P.SurfaceError):
                P.as_int(bad, "x")
        self.assertEqual(P.as_text("a", "x"), "a")
        for bad in (None, 1, b"x", ["a"]):
            with self.assertRaises(P.SurfaceError):
                P.as_text(bad, "x")
        self.assertEqual([P.numeric_key(n) for n in ("classes.dex", "classes2.dex", "classes10.dex", "x")], [1, 2, 10, 1])

    def test_member_and_field_descriptors_that_are_not_are_refused(self):
        self.assertEqual(P.member("Lo;->n(I)V"), ("Lo;", "n", "(I)V"))
        self.assertEqual(P.member("Lo;->a->b(I)V"), ("Lo;", "a->b", "(I)V"))  # cut at the first arrow, as the original does
        for bad in (None, 3, "no arrow", "Lo;->nothing"):
            with self.assertRaises(P.SurfaceError):
                P.member(bad)
        self.assertEqual(P.field_type("Lo;->n:I"), "I")
        for bad in (None, "Lo;->n"):
            with self.assertRaises(P.SurfaceError):
                P.field_type(bad)

    def test_each_fact_the_bytes_must_agree_with_is_checked_on_its_own(self):
        cases = {"length": (2, "9999"), "version": (3, "036"), "checksum": (4, "1"), "signature": (5, "0" * 40)}
        for label, (column, value) in cases.items():
            def edit(tables, column=column, value=value):
                tables["dex_files"][0][column] = value

            with self.subTest(label), self.assertRaises(P.SourceMismatch) as caught:
                report_of(S.facts("base.apk", edit))
            message = str(caught.exception)
            self.assertIn(label, message)
            for other in set(cases) - {label}:
                self.assertNotIn(other, message)

    def test_a_dex_without_its_magic_is_refused_as_the_original_refuses_it(self):
        def patch(members):
            data = bytearray(next(m for m in members if m[0] == "classes.dex")[1])
            data[0:4] = b"dxx\n"
            next(m for m in members if m[0] == "classes.dex")[1] = bytes(data)

        apk = modified_apk(self.dir, "base.apk", patch)
        a = outcome(lambda: original_report(S.facts("base.apk", apk=apk)))
        b = outcome(lambda: report_of(S.facts("base.apk", apk=apk), apk))
        self.assertEqual(a, b)
        self.assertEqual(b[1], "UnsupportedAudit")

    def test_the_size_limit_of_one_dex_file_is_the_originals(self):
        self.assertEqual(P.MAX_DEX_BYTES, 128 * 1024 * 1024)
        with mock.patch.object(P, "MAX_DEX_BYTES", 10), self.assertRaises(S.frozen().unsupported) as caught:
            report_of(S.facts("base.apk"))
        self.assertEqual(str(caught.exception), "single DEX fingerprint input exceeds admitted memory budget")

    def test_code_locations_are_only_those_asked_for_and_rows_outside_the_range_are_refused(self):
        classes = S.expected()["files"]["base.apk"]["dex"]["classes.dex"]
        wanted = {}
        for item in classes:
            for m in item["methods"]:
                if m["insns_units"] is not None and item["descriptor"] in (self.HOLDER, "Lkntr/common/comment/Panel;"):
                    wanted[m["method_idx"]] = (item["descriptor"], m["name"], m["proto"])
        got = P.code_locations(S.facts("base.apk"), {0: wanted})
        every = {m["method_idx"]: m for item in classes for m in item["methods"] if m["insns_units"] is not None}
        self.assertEqual(got, {(0, i): (every[i]["insns_off"], 2 * every[i]["insns_units"]) for i in wanted})
        self.assertGreater(len(every), len(wanted))  # rows of other methods exist, perhaps inside the range, and are left out
        self.assertEqual(P.code_locations(S.facts("base.apk"), {0: {}}), {})

        class Everything(S.FactSession):
            def rows(self, sql, **bounds):
                return super().rows(re.sub(r" AND method_idx BETWEEN \d+ AND \d+", "", sql), **bounds)

        lowest = min(wanted)
        with self.assertRaises(RuntimeError) as caught:
            P.code_locations(Everything(S.GENERATED / "base.apk", copy.deepcopy(S.golden()["scenarios"]["base.apk"]["relations"])),
                             {0: {lowest: wanted[lowest]}})
        self.assertEqual(str(caught.exception), "native code location is outside the requested method range")

    def test_the_report_says_what_it_is_made_of(self):
        report = report_of(S.facts("base.apk"))
        self.assertEqual({k: report["scan_execution"][k] for k in ("backend", "workers", "dex_files")},
                         {"backend": "meguvizdexdash", "workers": 1, "dex_files": 2})
        self.assertIsInstance(report["scan_execution"]["elapsed_ms"], float)
        self.assertGreaterEqual(report["scan_execution"]["elapsed_ms"], 0)
        for key in ("rule_version", "rule_sha256", "scope", "families", "protocol_twins", "class_records", "invoke_edges", "limitations"):
            self.assertIn(key, report)

    def test_a_restored_report_is_exactly_the_fresh_one(self):
        for name in ("base.apk", "target.apk"):
            fresh = report_of(S.facts(name))
            self.assertEqual(P.restore_shapes(json.loads(json.dumps(fresh))), fresh)

    def test_the_resource_evidence_has_the_sizes(self):
        evidence = {}
        P.resource_fingerprints(S.GENERATED / "duplicate-resource.apk", evidence=evidence)
        self.assertEqual([r["bytes"] for r in evidence["resources"]], [5, 6])

    def test_the_request_is_the_id_the_statement_and_the_budgets(self):
        log = self.dir / "requests.jsonl"
        with fake_session(self.dir, [FILES[:], [terminal(0)]], log=log, batch_rows=250) as session:
            session.all("SELECT a FROM t ORDER BY a", max_rows=77)
        requests = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(requests, [
            {"id": "r1", "sql": "SELECT file_id,entry_name FROM dex_files ORDER BY file_id", "batch_rows": 250, "max_rows": 500000},
            {"id": "r2", "sql": "SELECT a FROM t ORDER BY a", "batch_rows": 250, "max_rows": 77}, {"op": "close"}])

    def test_a_result_over_the_row_budget_that_the_engine_did_not_catch_is_refused(self):
        with fake_session(self.dir, [FILES[:], [batch(["a"], [[U(1)], [U(2)], [U(3)]]), terminal(3)]]) as session:
            with self.assertRaises(P.IncompleteFacts) as caught:
                session.all("SELECT a FROM t ORDER BY a", max_rows=2)
        self.assertIn("row budget", str(caught.exception))

    def test_an_oversized_line_is_refused(self):
        with mock.patch.object(P, "LINE_BUDGET", 200):
            with self.assertRaises(RuntimeError) as caught:
                with fake_session(self.dir, [FILES[:], [batch(["a"], [[T("x" * 400)]]), terminal(1)]]) as session:
                    session.all("SELECT a FROM t ORDER BY a")
        self.assertIn("byte budget", str(caught.exception))

    def test_the_engine_is_started_as_the_launch_says(self):
        launched = base.Launch("engine.exe", ["mcp"], {"A": "1"}, {})
        session = P.ServeSession.from_launch(launched, "x.apk", dialect="dexsql-0.1.0", deadline_seconds=12.5, batch_rows=7)
        self.assertEqual(session.argv, ["engine.exe", "serve", "--input", "x.apk", "--dialect", "dexsql-0.1.0", "--deadline-ms", "12500"])
        self.assertEqual((session.env, session.dialect, session.batch_rows), ({"A": "1"}, "dexsql-0.1.0", 7))


class TheLastDetails(Temp):
    def test_first_difference_names_the_coordinate_of_every_kind_of_difference(self):
        diff = P.first_difference
        self.assertIsNone(diff({"a": [1, (2, 3)], "b": None}, {"a": [1, [2, 3]], "b": None}))
        self.assertEqual(diff({"a": {"b": [1, 2]}}, {"a": {"b": [1, 3]}}), "a.b[1]")
        self.assertEqual(diff({"a": 1}, {"b": 1}), "a")
        self.assertEqual(diff({"a": 1, "z": 2}, {"a": 1}), "z")
        self.assertEqual(diff([1, 2], [1]), "[1]")
        self.assertEqual(diff([1], [1, 2]), "[1]")
        self.assertEqual(diff({"a": [[1], [2]]}, {"a": [[1], [3]]}), "a[1][0]")
        self.assertEqual(diff({"a": 1}, {"a": True}), "a")
        self.assertEqual(diff({"a": 1}, {"a": "1"}), "a")
        self.assertEqual(diff(1, 2), "<root>")
        self.assertIsNone(diff("x", "x"))
        self.assertEqual(diff({"a": None}, {"a": 0}), "a")

    def test_every_statement_that_reads_a_family_carries_its_filter(self):
        workers = S.frozen().workers
        session = S.facts("base.apk")
        report_of(session)
        sqls = [s["sql"] for s in session.statements]
        by_relation = {}
        for sql in sqls:
            by_relation.setdefault(re.search(r"FROM (\w+)", sql).group(1), []).append(sql)
        for sql in by_relation["classes"]:
            self.assertIn(P.family_filter(workers, "descriptor"), sql)
        for sql in by_relation["class_fields"]:
            self.assertIn(P.family_filter(workers, "class_descriptor"), sql)
        family_methods = [sql for sql in by_relation["class_methods"] if "method_name" in sql]
        protocol_methods = [sql for sql in by_relation["class_methods"] if "method_name" not in sql]
        self.assertEqual((len(family_methods), len(protocol_methods)), (2, 2))
        for sql in family_methods:
            self.assertIn(P.family_filter(workers, "class_descriptor"), sql)
        for sql in protocol_methods:
            self.assertIn(P.protocol_filter(workers, "class_descriptor"), sql)
        for sql in by_relation["method_calls"]:
            self.assertIn(P.family_filter(workers, "callee_class"), sql)
            self.assertIn(P.protocol_filter(workers, "callee_class"), sql)
        for sql in by_relation["code_items"]:
            self.assertIn("BETWEEN", sql)
        for sql in sqls:
            if "FROM dex_files" in sql:
                continue
            self.assertRegex(sql, r"WHERE file_id=\d+ AND (method_idx BETWEEN|\()")

    def test_the_deepest_statement_actually_sent_is_at_the_engines_stack_limit(self):
        self.assertEqual(P.MAX_SQL_DEPTH, 9)
        session = S.facts("base.apk")
        report_of(session)
        depths = {s["sql"]: P.sql_depth(s["sql"]) for s in session.statements}
        deepest = max(depths.values())
        self.assertEqual(deepest, P.MAX_SQL_DEPTH)  # the cap is the real deepest statement, not a loose bound
        self.assertTrue(all(d <= P.MAX_SQL_DEPTH for d in depths.values()))
        # the family filter alone is one level shallower than the per-file statement that wraps it
        self.assertEqual(P.sql_depth(P.family_filter(S.frozen().workers, "descriptor")) + 1, deepest)
        # method_calls carries both filters and reaches that deepest nesting
        calls = [sql for sql in depths if "FROM method_calls" in sql]
        self.assertTrue(calls)
        self.assertEqual(max(depths[sql] for sql in calls), deepest)

    def test_a_condition_deeper_than_the_engines_stack_limit_is_refused_before_it_is_sent(self):
        session = S.facts("base.apk")
        over = "(" * P.MAX_SQL_DEPTH + "descriptor LIKE 'L%'" + ")" * P.MAX_SQL_DEPTH  # wrapped by per_file: 10
        with self.assertRaises(P.SurfaceError) as caught:
            list(P.per_file(session, [0], "SELECT file_id,class_def_idx,descriptor FROM classes", over, "class_def_idx"))
        self.assertIn("stack", str(caught.exception))
        self.assertEqual([s for s in session.statements if "FROM classes" in s["sql"]], [])  # refused before sending
        at = "(" * (P.MAX_SQL_DEPTH - 1) + "descriptor LIKE 'L%'" + ")" * (P.MAX_SQL_DEPTH - 1)  # wrapped: 9, admitted
        list(P.per_file(session, [0], "SELECT file_id,class_def_idx,descriptor FROM classes", at, "class_def_idx"))
        self.assertTrue(any("FROM classes" in s["sql"] for s in session.statements))

    def test_a_code_interval_that_ends_past_the_dex_is_refused_even_if_it_starts_inside(self):
        size = (S.GENERATED / "base.apk").stat().st_size
        with zipfile.ZipFile(S.GENERATED / "base.apk") as archive:
            length = len(archive.read("classes.dex"))

        def edit(tables):
            row = body_row(tables)
            row[2] = str(length - 2)  # even, inside the file; the instructions run past its end
            row[3] = "4"

        self.assertGreater(size, length)
        result = outcome(lambda: report_of(S.facts("base.apk", edit)))
        self.assertEqual(result, ("raised", "RuntimeError", "native code interval is outside the verified DEX"))
        self.assertEqual(outcome(lambda: original_report(S.facts("base.apk", edit))), result)

    def test_a_line_of_an_unknown_kind_is_refused(self):
        with fake_session(self.dir, [FILES[:], [{"kind": "weird", "id": "@id"}]]) as session:
            with self.assertRaises(P.IncompleteFacts):
                session.all("SELECT a FROM t ORDER BY a")


if __name__ == "__main__":
    unittest.main()
