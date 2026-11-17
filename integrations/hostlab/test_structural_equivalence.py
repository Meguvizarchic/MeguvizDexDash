"""The structural audit over the real engine, B0 and B1, against the golden of the reference engine, with negative controls.

Needs the built binary (`cargo build -p mdd-cli`) or MDD_WORKER_BINARY; a missing binary fails the run, it is never skipped.
No network, no download, no private sample. The reference binary is NOT needed: its answers are in
conformance/hostlab/structural-goldens.json (written by conformance/hostlab/structural_a0_golden.py).
Run: python -I -m unittest discover -s integrations/hostlab -p "test_structural_equivalence.py"
"""
import dataclasses
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import hostlab_test_support as support  # noqa: E402
import native_session as ns  # noqa: E402
import provider  # noqa: E402
import structural_compare as compare  # noqa: E402
import structural_equivalence as eq  # noqa: E402
import structural_frozen as F  # noqa: E402
import structural_provider as sp  # noqa: E402

ROOT = F.ROOT
sys.path.insert(0, str(ROOT / "conformance/hostlab"))
import structural_a0_golden as golden_tool  # noqa: E402
import structural_dex as dex  # noqa: E402
import structural_worlds as worlds  # noqa: E402

_STATE: dict = {}


def live():
    """One pinned engine and one set of inputs for the whole module (the runs are the slow part)."""
    if "live" not in _STATE:
        directory = tempfile.TemporaryDirectory(prefix="mdd051-live-")
        _STATE["dir"] = directory
        _STATE["live"] = F.Live(directory.name)
        _STATE["golden"] = eq.load_golden()
        _STATE["results"] = {}
    return _STATE["live"], _STATE["golden"], _STATE["results"]


def tearDownModule():
    if "dir" in _STATE:
        _STATE["dir"].cleanup()


def result(world, wire):
    lv, golden, cache = live()
    if (world, wire) not in cache:
        cache[(world, wire)] = eq.run_world(lv, golden, world, wire)
    return cache[(world, wire)]


class GoldenTests(unittest.TestCase):
    def test_the_golden_is_made_from_these_inputs(self):
        lv, golden, _ = live()
        self.assertEqual(golden_tool.verify_inputs(golden), [])
        for filename, expected in golden["inputs"].items():
            self.assertEqual(lv.digests[filename], expected["sha256"], filename)

    def test_the_committed_catalog_is_what_the_writer_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            worlds.write_catalog(Path(directory))
            for relative in golden_tool.CATALOG_FILES:
                self.assertEqual((Path(directory) / relative).read_bytes(), (F.CATALOG_DIR / relative).read_bytes(), relative)

    def test_the_reference_is_dexsql_0_1_0(self):
        golden = eq.load_golden()
        self.assertEqual(golden["oracle"]["reference_engine"]["sha256"], golden_tool.REFERENCE_SHA256)
        self.assertFalse(golden["oracle"]["reference_engine"]["binary_in_repository"])
        self.assertEqual(len(golden["expected_features"]), 27)

    def test_the_golden_has_every_kind_of_verdict_and_every_kind_of_item(self):
        golden = eq.load_golden()
        statuses = {v["status"] for w in golden["worlds"].values() for v in w["record"]["features"].values()}
        self.assertEqual(statuses, {"FOUND", "MISSING", "PARTIAL"})
        refused = {name for name, w in golden["worlds"].items() if "raised" in w["audit"]}
        self.assertEqual(refused, {"duplicate", "badsig"})
        counts = golden["worlds"]["full"]["counts"]
        for kind in ("features", "discoveries", "class_records", "fields", "methods", "generic_members", "hierarchy_edges",
                     "statements", "call_count_rows", "repeated_call_rows", "protocol_definitions"):
            self.assertGreater(counts[kind], 0, kind)
        self.assertEqual(counts["features"], 27)
        for world in ("full", "partial"):
            self.assertEqual(set(golden["worlds"][world]["record"]["features"]), set(golden["expected_features"]))


class EquivalenceTests(unittest.TestCase):
    def worlds(self):
        return sorted(live()[1]["worlds"])

    def test_every_world_equals_the_golden_item_by_item(self):
        for world in self.worlds():
            for wire in eq.WIRES:
                with self.subTest(world=world, wire=wire):
                    got = result(world, wire)
                    self.assertEqual(got["differences"], [])
                    self.assertEqual(got["audit_differences"], [])
                    self.assertEqual(got["tsv_differences"], [])
                    self.assertEqual(got["counts"], live()[1]["worlds"][world]["counts"])

    def test_b0_and_b1_agree_with_each_other(self):
        for world in self.worlds():
            with self.subTest(world=world):
                self.assertEqual(result(world, "b0")["record_digest"], result(world, "b1")["record_digest"])

    def test_outcomes(self):
        expected = {"full": "complete", "partial": "complete", "sparse": "complete", "duplicate": "audit_refused", "badsig": "audit_refused"}
        for world, outcome in expected.items():
            for wire in eq.WIRES:
                with self.subTest(world=world, wire=wire):
                    self.assertEqual(result(world, wire)["outcome"], outcome)

    def test_b0_keeps_the_request_schedule_and_b1_halves_the_round_trips(self):
        for world in ("full", "partial", "sparse"):
            b0, b1 = result(world, "b0"), result(world, "b1")
            with self.subTest(world=world):
                self.assertEqual(b0["logical_statements"], b1["logical_statements"])  # the consumer asks the same
                self.assertEqual(b0["queries"], b1["queries"])
                self.assertEqual(b0["wire_requests"], 2 * b0["queries"])  # a shape statement and a data statement for each
                self.assertEqual(b1["wire_requests"], b1["queries"])      # the data statement alone (W-B1-2)

    def test_the_engine_is_named_not_dexsql(self):
        lv, golden, _ = live()
        entry = json.loads(lv.manifest.read_text(encoding="utf-8"))["builds"][-1]
        for wire in eq.WIRES:
            got = result("full", wire)
            identity = got["engine"]
            with self.subTest(wire=wire):
                self.assertEqual(identity["backend"], "meguvizdexdash")
                self.assertEqual((identity["engine_version"], identity["build_id"], identity["binary_sha256"]),
                                 (entry["engine_version"], entry["build_id"], entry["sha256"]))
                self.assertEqual(identity["binary_sha256"], F.sha256_file(lv.binary))
                self.assertIs(identity["profile"]["admitted"], False)  # stated, not hidden
                self.assertEqual(identity["dialect"]["engine"], "dexsql-0.1.0")
                self.assertNotIn("dexsql 0.1.0", json.dumps(identity))
                self.assertEqual(got["dataset"]["dex_count"], 2)
                self.assertEqual(got["dataset"]["layer_issues"], [])
                self.assertEqual((got["coverage"]["input"], got["coverage"]["facts"]), ("complete", "complete"))
                self.assertGreater(got["coverage"]["statements"], got["logical_statements"])

    def test_the_records_carry_the_wire_and_the_backend(self):
        lv, golden, _ = live()
        for wire in eq.WIRES:
            outcome = lv.outcome(lv.path("partial"), wire)
            with self.subTest(wire=wire):
                self.assertEqual((outcome.record["backend"], outcome.record["wire"], outcome.record["complete"]), ("meguvizdexdash", wire, True))
                self.assertEqual(outcome.record["reference_sha256"], json.loads((F.CATALOG_DIR / "analysis/audit_catalog.json").read_text())["reference_sha256"])

    def test_the_audits_own_refusals_are_verdicts_not_engine_failures(self):
        lv, golden, _ = live()
        for world in ("duplicate", "badsig"):
            for wire in eq.WIRES:
                outcome = lv.outcome(lv.path(world), wire)
                with self.subTest(world=world, wire=wire):
                    self.assertEqual(outcome.outcome, "audit_refused")
                    self.assertEqual(outcome.record["audit_refusal"]["type"], "UnsupportedAudit")
                    self.assertEqual(outcome.record["audit_refusal"]["message"], golden["worlds"][world]["audit"]["message"])
                    self.assertIsNone(outcome.record["failure"])
                    self.assertFalse(outcome.record["complete"])
                    with self.assertRaises(lv.graph.UnsupportedAudit):
                        outcome.raise_for_outcome()

    def test_unreadable_facts_are_incomplete_coverage_not_missing(self):
        lv, golden, _ = live()
        expected = golden["engine_worlds"]["badrefs"]
        self.assertEqual(expected["reference_engine_observation"]["outcome"], "complete")  # the reference engine reads it without a word
        for wire in eq.WIRES:
            outcome = lv.outcome(lv.path("badrefs"), wire)
            with self.subTest(wire=wire):
                self.assertEqual(outcome.outcome, expected["outcome"])
                self.assertFalse(outcome.record["complete"])
                self.assertEqual(outcome.record["features"], {})  # no MISSING invented for facts that could not be read
                self.assertEqual(outcome.record["incomplete"]["engine_error"]["code"], expected["engine_code"])
                self.assertEqual(outcome.record["incomplete"]["reasons"], ["statement_incomplete"])
                issues = outcome.record["incomplete"]["layer_issues"]
                self.assertEqual(len(issues), 1)
                self.assertEqual(issues[0]["reason"], "CALLER_INS_SIZE_MISMATCH")
                self.assertIsNone(outcome.record["failure"])
                with self.assertRaises(ns.EngineIncomplete):
                    outcome.raise_for_outcome()

    def test_the_engine_saying_no_is_a_failure_with_its_code(self):
        lv, golden, _ = live()
        bad_member = ROOT / "tests/fixtures/generated/invalid-dex-member.apk"
        for wire in eq.WIRES:
            outcome = lv.outcome(bad_member, wire)
            with self.subTest(case="invalid member", wire=wire):
                self.assertEqual(outcome.outcome, "failed")
                self.assertEqual((outcome.record["failure"]["code"], outcome.record["failure"]["origin"]), ("INVALID_INPUT", "engine"))
                self.assertEqual(outcome.record["features"], {})
            outcome = lv.outcome(lv.path("full"), wire, sql_limits={"result_rows": 1})
            with self.subTest(case="result budget", wire=wire):
                self.assertEqual(outcome.outcome, "failed")
                self.assertEqual((outcome.record["failure"]["code"], outcome.record["failure"]["origin"]), ("QUOTA_EXCEEDED", "engine"))
                self.assertIsNone(outcome.record["audit_refusal"])
            outcome = lv.outcome(lv.path("full"), wire, sha256="00" * 32)
            with self.subTest(case="wrong source digest", wire=wire):
                self.assertEqual(outcome.outcome, "failed")
                self.assertIn("immutable APK identity", outcome.record["failure"]["message"])

    def test_a_pinned_engine_that_is_not_there_is_unavailable(self):
        lv, golden, _ = live()
        with tempfile.TemporaryDirectory() as directory:
            config = lv.provider_config()
            config["meguvizdexdash"]["manifest"] = str(Path(directory) / "missing-manifest.json")
            with lv.environ():
                outcome = sp.run_structural(lv.path("sparse"), sha256=F.sha256_file(lv.path("sparse")), rules_module=lv.rules,
                                            expected_features=F.emitted_features(), provider_config=config,
                                            structural=lv.structural("b0"), state=lv.state)
        self.assertEqual(outcome.outcome, "failed")
        self.assertEqual(outcome.record["failure"]["code"], "UNAVAILABLE_BACKEND")
        self.assertIsNone(outcome.record["backend"])

    def test_the_wires_agree_with_the_reference_on_single_statements(self):
        lv, golden, _ = live()
        probes = eq.run_probes(lv, golden)
        self.assertEqual(sorted(probes), ["empty-result", "int64-min-literal", "null-column", "scalar-values", "supplementary-characters"])
        for name, probe in probes.items():
            for wire in eq.WIRES:
                with self.subTest(probe=name, wire=wire):
                    self.assertTrue(eq.probe_agreement(probe, wire), probe)
        scalar = probes["scalar-values"]["wires"]["b1"]["rows"][0]
        self.assertIsNone(scalar["c"])  # NULL stays NULL
        self.assertEqual(scalar["e"], "N")  # the text N stays the text N
        self.assertEqual(scalar["d"], "")
        self.assertEqual(scalar["b"], "-9223372036854775807")
        self.assertEqual(scalar["a"], "9223372036854775807")

    def test_the_int64_minimum_literal_is_a_pinned_difference_of_the_sql_layer(self):
        lv, golden, _ = live()
        probe = eq.run_probes(lv, golden)["int64-min-literal"]
        self.assertEqual(probe["a0"]["rows"], [{"b": "-9223372036854775808"}])  # the reference engine: the integer
        self.assertNotEqual(probe["wires"]["b0"], probe["a0"])                   # this engine: a REAL, passed on as it came
        self.assertEqual(probe["wires"]["b0"]["rows"], [{"b": "-9.22337203685478e+18"}])
        self.assertIn("float cell", probe["wires"]["b1"]["error"]["message"])    # and B1 will not call a REAL an integer

    def test_the_declared_difference_of_b1_is_the_only_one(self):
        lv, golden, _ = live()
        probes = eq.run_probes(lv, golden)
        supplementary = probes["supplementary-characters"]
        # the reference engine and B0 refuse strings that hold supplementary characters (HostLab's strict UTF-8 decode of
        # the hex cell); B1 reads them (W-B1-3)
        self.assertEqual(supplementary["a0"]["error"]["message"], "native audit returned a malformed hex cell")
        self.assertEqual(supplementary["wires"]["b0"]["error"]["message"], supplementary["a0"]["error"]["message"])
        values = [row["value"] for row in supplementary["wires"]["b1"]["rows"]]
        self.assertIn("Lfixture/\U0001F600;", values)
        # the declared difference must be the input's own string pool, read from its bytes independently of the engine
        pool = eq.dex_string_pool(ROOT / "tests/fixtures/query/generated/unicode-order-038.dex")
        self.assertEqual(supplementary["declared_expected"], pool)
        self.assertEqual(supplementary["wires"]["b1"]["rows"], pool)
        self.assertIn("W-B1-3", {change["id"] for change in ns.WIRE_CHANGES})
        for name in ("empty-result", "null-column", "scalar-values"):
            self.assertEqual(probes[name]["wires"]["b0"], probes[name]["wires"]["b1"], name)

    def test_the_probe_comparison_can_fail(self):
        base = {"a0": {"rows": [{"a": "1"}]}, "wires": {"b0": {"rows": [{"a": "1"}]}, "b1": {"rows": [{"a": "1"}]}}, "declared_difference": None}
        self.assertTrue(eq.probe_agreement(base, "b0") and eq.probe_agreement(base, "b1"))
        for wrong in ({"rows": [{"a": "2"}]}, {"rows": []}, {"error": {"type": "X", "message": "m"}}):
            damaged = json.loads(json.dumps(base))
            damaged["wires"]["b1"] = wrong
            self.assertFalse(eq.probe_agreement(damaged, "b1"), wrong)
        refused = {"a0": {"error": {"type": "RuntimeError", "message": "m"}}, "wires": {"b0": {"error": {"type": "E", "message": "m"}},
                   "b1": {"rows": [{"a": "1"}]}}, "declared_difference": "W-B1-3", "declared_expected": [{"a": "1"}]}
        self.assertTrue(eq.probe_agreement(refused, "b0"))
        self.assertTrue(eq.probe_agreement(refused, "b1"))
        # a declared difference must show the expected content: a non-empty but different answer is not agreement
        for wrong in ({"rows": [{"a": "2"}]}, {"rows": [{"a": "1"}, {"a": "3"}]}):
            damaged = json.loads(json.dumps(refused))
            damaged["wires"]["b1"] = wrong
            self.assertFalse(eq.probe_agreement(damaged, "b1"), wrong)
        no_expected = json.loads(json.dumps(refused))
        del no_expected["declared_expected"]
        self.assertFalse(eq.probe_agreement(no_expected, "b1"))  # without expected content, agreement is not proven
        refused["wires"]["b0"] = {"error": {"type": "E", "message": "another message"}}
        self.assertFalse(eq.probe_agreement(refused, "b0"))
        refused["wires"]["b1"] = {"error": {"type": "E", "message": "m"}}
        self.assertFalse(eq.probe_agreement(refused, "b1"))  # a declared difference still has to be the declared one
        undeclared = {"a0": {"error": {"type": "R", "message": "m"}}, "wires": {"b1": {"rows": [{"a": "1"}]}}, "declared_difference": None}
        self.assertFalse(eq.probe_agreement(undeclared, "b1"))


class NegativeControlTests(unittest.TestCase):
    """A comparison that cannot fail proves nothing: damage the golden, change a rule, change the sources, change the catalog."""

    def test_identical_records_have_no_difference(self):
        golden = live()[1]
        for world, entry in golden["worlds"].items():
            self.assertEqual(compare.compare(entry["record"], json.loads(json.dumps(entry["record"]))), [], world)

    def test_every_damage_to_a_golden_is_reported_at_the_place_damaged(self):
        golden = live()[1]
        total = 0
        for world in sorted(golden["worlds"]):
            record = golden["worlds"][world]["record"]
            for name, prefix, damaged in eq.damages(record):
                total += 1
                with self.subTest(world=world, damage=name):
                    found, differences = eq.detected(record, damaged, prefix)
                    self.assertTrue(found, (prefix, differences[:3]))
        self.assertGreater(total, 80)  # the controls cover every part of every world

    def test_damaged_goldens_fail_against_the_live_run(self):
        lv, golden, _ = live()
        for wire in eq.WIRES:
            with lv.environ():
                run = compare.project(F.record_run(lv.factory(wire), lv.rules, lv.graph, lv.path("partial")))
            self.assertEqual(compare.compare(golden["worlds"]["partial"]["record"], run), [])
            for name, prefix, damaged in eq.damages(golden["worlds"]["partial"]["record"])[:12]:
                with self.subTest(wire=wire, damage=name):
                    self.assertTrue(compare.compare(damaged, run))

    def test_the_damage_list_covers_every_compared_part(self):
        golden = live()[1]
        def parts(world):
            return {re.split(r"[/\[]", prefix[1:])[0] for _, prefix, _ in eq.damages(golden["worlds"][world]["record"])}

        self.assertEqual(parts("full"), {"features", "discoveries", "graph", "statements", "class_count", "files", "evidence",
                                         "unsupported_audit"})
        self.assertEqual(parts("duplicate"), {"graph", "statements", "files", "unsupported_audit"})

    def test_a_changed_rule_is_reported_by_the_live_comparison(self):
        lv, golden, _ = live()
        for change in eq.RULE_CHANGES:
            graph, rules = eq.with_changed_rule(lv, change)
            for wire in eq.WIRES:
                with self.subTest(change=change["name"], wire=wire):
                    run = lv.record(lv.path(change["world"]), wire, rules=rules, graph=graph)
                    found = compare.compare(golden["worlds"][change["world"]]["record"], run)
                    self.assertTrue(found)
                    self.assertTrue(any(item["path"].startswith(change["reported"]) for item in found), [i["path"] for i in found][:5])
                    run_unchanged = lv.record(lv.path(change["world"]), wire)  # the control: the unchanged rules agree
                    self.assertEqual(compare.compare(golden["worlds"][change["world"]]["record"], run_unchanged), [])

    def test_a_modified_frozen_source_is_refused_before_it_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory) / "source-8782f43"
            shutil.copytree(F.FROZEN, copy)
            target = copy / "native_rules.py"
            target.write_bytes(target.read_bytes().replace(b"static(value)", b"static( value )", 1))
            saved_f, saved_s = F.FROZEN, support.FROZEN
            F.FROZEN = support.FROZEN = copy
            try:
                with self.assertRaises(AssertionError) as caught:
                    F.frozen_source("native_rules")
                self.assertIn("not the frozen HostLab source", str(caught.exception))
                F.frozen_source("native_graph")  # an untouched file still loads
            finally:
                F.FROZEN, support.FROZEN = saved_f, saved_s

    def test_a_changed_reference_is_the_audits_own_refusal(self):
        lv, golden, _ = live()
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / "catalog"
            shutil.copytree(F.CATALOG_DIR, catalog)
            java = catalog / "analysis/HostCompatibilityAudit.java"
            java.write_bytes(java.read_bytes() + b"// edited\n")
            graph, rules = F.graph_and_rules(ns, catalog)
            for wire in eq.WIRES:
                outcome = lv.outcome(lv.path("sparse"), wire, rules=rules)
                with self.subTest(wire=wire):
                    self.assertEqual(outcome.outcome, "audit_refused")
                    self.assertIn("Java reference changed", outcome.record["audit_refusal"]["message"])
                    self.assertIsNone(outcome.record["failure"])

    def test_a_changed_catalog_changes_the_verdict_and_is_reported(self):
        lv, golden, _ = live()
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / "catalog"
            shutil.copytree(F.CATALOG_DIR, catalog)
            path = catalog / "analysis/audit_catalog.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["lists"]["run.blockCandidates"] = ["syn.cat.NotTheOwner"]
            path.write_text(json.dumps(document), encoding="utf-8")
            graph, rules = F.graph_and_rules(ns, catalog)
            run = lv.record(lv.path("full"), "b0", rules=rules, graph=graph)
        found = compare.compare(golden["worlds"]["full"]["record"], run)
        self.assertTrue(any(item["path"].startswith("/features/block_update") for item in found))

    def test_a_modified_input_is_refused_before_the_comparison(self):
        lv, golden, _ = live()
        damaged = json.loads(json.dumps(golden))
        damaged["inputs"]["full.apk"]["sha256"] = "00" * 32
        with self.assertRaises(AssertionError):
            eq.run_world(lv, damaged, "full", "b0")
        self.assertTrue(golden_tool.verify_inputs(damaged))
        for edit in (lambda g: g["provenance"]["sources"].__setitem__("integrations/hostlab/structural_compare.py", "00" * 32),
                     lambda g: g["provenance"]["catalog"].__setitem__("analysis/audit_catalog.json", "00" * 32),
                     lambda g: g["expected_features"].pop(),
                     lambda g: g["provenance"]["frozen_hostlab"].__setitem__("native_rules", "00" * 32),
                     lambda g: g["probes"]["scalar-values"].__setitem__("sql", "SELECT 1 ORDER BY 1")):
            damaged = json.loads(json.dumps(golden))
            edit(damaged)
            self.assertTrue(golden_tool.verify_inputs(damaged))


class NoBusinessFilteringTests(unittest.TestCase):
    """The engine answers by structure: the same classes under other names give the same answers under the same names."""

    MAPPING = (("Lcom/bapis/", "Lzzz/proto/"), ("Lsyn/fam/", "Lqqq/fam/"))

    @staticmethod
    def rename(members, mapping):
        def r(text):
            if text is None:
                return None
            for old, new in mapping:
                text = text.replace(old, new)
            return text

        def op(operation):
            if operation[0] == "invoke":
                owner, name, ret, params = operation[2]
                return (operation[0], operation[1], (r(owner), name, r(ret), tuple(r(p) for p in params)), operation[3])
            return operation

        out = []
        for member in members:
            classes = []
            for spec in member:
                classes.append(dataclasses.replace(
                    spec, descriptor=r(spec.descriptor), superclass=r(spec.superclass), interfaces=tuple(r(i) for i in spec.interfaces),
                    signature=r(spec.signature),
                    fields=[dataclasses.replace(f, type=r(f.type), signature=r(f.signature)) for f in spec.fields],
                    methods=[dataclasses.replace(m, ret=r(m.ret), params=tuple(r(p) for p in m.params), signature=r(m.signature),
                                                 code=None if m.code is None else [op(o) for o in m.code]) for m in spec.methods]))
            out.append(classes)
        return out

    def test_renamed_packages_give_the_renamed_answers(self):
        lv, golden, _ = live()
        members, container = worlds.world("full")
        renamed = self.rename(members, self.MAPPING)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "renamed.apk"
            path.write_bytes(dex.build_apk([("classes.dex", dex.build_dex(renamed[0])), ("classes2.dex", dex.build_dex(renamed[1]))]))
            original = {item["id"]: [] for item in compare.EVIDENCE}
            moved = {item["id"]: [] for item in compare.EVIDENCE}
            with lv.environ():
                with lv.factory("b0")(lv.path("full")) as session:
                    for item in compare.EVIDENCE:
                        for file in sorted(session.files):
                            original[item["id"]] += session.all(item["sql"].format(file=file))
                with lv.factory("b0")(path) as session:
                    for item in compare.EVIDENCE:
                        sql = item["sql"]
                        for old, new in self.MAPPING:
                            sql = sql.replace(old, new)
                        self.assertNotEqual(sql, item["sql"], item["id"])
                        for file in sorted(session.files):
                            moved[item["id"]] += session.all(sql.format(file=file))
        # names decide the order (and the numbering) of rows, so the answers are compared as sets of name-based facts
        columns = {"calls": ("method", "callee", "n"), "protocols": ("method_descriptor",),
                   "classes": ("descriptor", "superclass_descriptor"), "members": ("class_descriptor", "method_name", "method_descriptor")}

        def facts(rows, name, rename_back):
            out = []
            for row in rows:
                out.append(tuple(None if row[c] is None else (self.undo(row[c]) if rename_back else row[c]) for c in columns[name]))
            return sorted(out)

        for name in original:
            with self.subTest(statement=name):
                self.assertTrue(original[name])  # there is something to compare
                self.assertEqual(facts(moved[name], name, True), facts(original[name], name, False))
                self.assertEqual(len(moved[name]), len(original[name]))

    def undo(self, text):
        for old, new in self.MAPPING:
            text = text.replace(new, old)
        return text

    def test_the_renaming_helper_really_renames(self):
        members, _ = worlds.world("full")
        renamed = self.rename(members, self.MAPPING)
        names = {spec.descriptor for member in renamed for spec in member}
        self.assertIn("Lzzz/proto/bilibili/app/FooMoss;", names)
        self.assertIn("Lqqq/fam/Util;", names)
        self.assertFalse(any(name.startswith(("Lcom/bapis/", "Lsyn/fam/")) for name in names))


class RollbackAndOutputTests(unittest.TestCase):
    def test_the_engine_writes_only_below_its_own_namespace(self):
        lv, golden, _ = live()
        outcome = lv.outcome(lv.path("partial"), "b1")
        identity = outcome.record["engine"]
        config = provider.parse_config(lv.provider_config())
        spaces = provider.namespaces(lv.state, identity, config)
        provider.ensure_namespaces(spaces, identity)
        path = sp.publish_result(outcome.record, spaces)
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), outcome.record)
        names = {child.name for child in Path(lv.state).iterdir()}
        self.assertEqual(names, {provider.MDD_ROOT})
        self.assertTrue(names.isdisjoint(provider.LEGACY_NAMES))

    def test_the_business_rules_are_untouched_by_running_the_engine(self):
        before = {name: F.sha256_file(F.FROZEN / f"{name}.py") for name in ("native_graph", "native_rules", "native_audit", "native_session", "native_cli")}
        lv, golden, _ = live()
        lv.outcome(lv.path("sparse"), "b0")
        after = {name: F.sha256_file(F.FROZEN / f"{name}.py") for name in before}
        self.assertEqual(before, after)
        self.assertEqual(before, {name: golden["provenance"]["frozen_hostlab"][name] for name in before})

    def test_rollback_to_the_original_session_leaves_the_engine_alone(self):
        lv, golden, _ = live()
        config = lv.provider_config("dexsql")
        made = []

        class Original:
            def __init__(self, apk, timeout, threads):
                made.append(apk)

        from unittest import mock
        with lv.environ(), mock.patch.object(ns.subprocess, "Popen", side_effect=AssertionError("no process may start")):
            session = ns.NativeSession(lv.path("full"), provider_config=config, original=Original)
        self.assertIsInstance(session, Original)
        self.assertEqual(made, [lv.path("full")])


class WireRegistryTests(unittest.TestCase):
    def test_every_registered_change_is_observable_or_structural(self):
        ids = {c["id"] for c in ns.WIRE_CHANGES}
        self.assertEqual(ids, {"W-B0-1", "W-B0-2", "W-B0-3", "W-B0-4", "W-B0-5", "W-B0-6", "W-B1-1", "W-B1-2", "W-B1-3", "W-B1-4"})
        b0, b1 = result("full", "b0"), result("full", "b1")
        self.assertEqual(b0["wire_requests"], 2 * b1["wire_requests"])  # W-B1-2
        self.assertGreater(b0["coverage"]["statements"], b1["coverage"]["statements"])  # W-B0-2: no extra statements on B1
        self.assertEqual(b0["engine"]["config_digest"], b1["engine"]["config_digest"])
        command = ns.serve_command("e", ["a"], dialect="d", timeout_seconds=1)
        self.assertNotIn("--threads", command)  # W-B0-3


if __name__ == "__main__":
    unittest.main()
