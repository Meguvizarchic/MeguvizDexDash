"""structural_provider without the real engine: the four outcomes, identity, rollback, publishing and the layer boundary.

The rules module and the session are stand-ins here (the real frozen rules over the real engine are in
test_structural_equivalence.py); what is under test is the transaction around them: which outcome a given
happening leads to, that none of them is mistaken for another, and that the business knowledge stays outside.
Run: python -I -m unittest discover -s integrations/hostlab -p "test_structural_provider.py"
"""
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import hostlab_test_support as support  # noqa: E402
import native_session as ns  # noqa: E402
import provider  # noqa: E402
import structural_frozen as F  # noqa: E402
import structural_provider as sp  # noqa: E402

ROOT = support.ROOT
FEATURES = tuple(F.emitted_features())
SHA = "ab" * 32


class Refused(RuntimeError):
    """Stands in for native_graph.UnsupportedAudit."""


def verdicts(status="FOUND"):
    return {name: {"status": status, "detail": "detail of " + name} for name in FEATURES}


class FakeRules:
    """Stands in for the `native_rules` module: `Rules(session).run()` and what the provider reads from the module."""

    UnsupportedAudit = Refused
    CATALOG = {"reference_sha256": "cc" * 32}

    def __init__(self, result=None, error=None, seen=None):
        self.result, self.error, self.seen = result, error, seen if seen is not None else []
        outer = self

        class Rules:
            def __init__(self, session):
                outer.seen.append(session)
                self.session = session

            def run(self):
                if outer.error is not None:
                    raise outer.error
                return (outer.result if outer.result is not None else verdicts()), {"block_update": [("o", "m()V")]}

        self.Rules = Rules


class FakeSession:
    """The part of a B0/B1 session the provider reads."""

    wire = "b0"

    def __init__(self, *, coverage=None, layer_issues=(), count=7, queries=5, enter_error=None, close_error=None):
        self.queries = queries
        self._coverage = coverage or {"statements": 3, "input": "complete", "facts": "complete", "required_layers": ["metadata"], "issues": []}
        self.layer_issues = list(layer_issues)
        self.count, self.enter_error, self.close_error = count, enter_error, close_error
        self.statements = []

    @property
    def coverage(self):
        return self._coverage

    def identity(self):
        return {"engine": {"backend": "meguvizdexdash", "build_id": "b"}, "wire": self.wire, "transport": "cli_jsonl_v1",
                "dataset": {"snapshot_id": "s"}, "coverage": self._coverage, "queries": self.queries}

    def __enter__(self):
        if self.enter_error:
            raise self.enter_error
        return self

    def __exit__(self, *exc):
        if self.close_error and exc[0] is None:
            raise self.close_error

    def all(self, sql, **bounds):
        self.statements.append(sql)
        return [{"n": str(self.count)}]


class OriginalSession(FakeSession):
    """HostLab's own session: it knows no wire and reports no coverage."""

    def __init__(self, **kw):
        super().__init__(**kw)
        del self.__dict__["_coverage"]

    wire = None

    @property
    def coverage(self):  # type: ignore[override]
        raise AttributeError("coverage")


class ProviderTests(unittest.TestCase):
    def apk(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "a.apk"
        path.write_bytes(b"PK")
        return path

    def run_audit(self, session=None, rules=None, factory_error=None, digest=None, **kwargs):
        apk = self.apk()
        session = session or FakeSession()

        def factory(path):
            if factory_error:
                raise factory_error
            return session

        return sp.run_structural(apk, sha256=SHA, rules_module=rules or FakeRules(), expected_features=FEATURES,
                                 session_factory=factory, digest=digest or (lambda path: SHA), **kwargs)

    # ---- 1. a business verdict is a result ----

    def test_complete_record(self):
        out = self.run_audit()
        r = out.record
        self.assertEqual(out.outcome, "complete")
        self.assertTrue(r["complete"] and r["source_sha_reverified"])
        self.assertEqual((r["backend"], r["wire"], r["class_count"], r["queries"]), ("meguvizdexdash", "b0", 7, 5))
        self.assertEqual(r["engine"], {"backend": "meguvizdexdash", "build_id": "b"})
        self.assertEqual(r["native"], r["engine"])
        self.assertEqual(r["dataset"], {"snapshot_id": "s"})
        self.assertEqual(r["reference_sha256"], "cc" * 32)
        self.assertEqual(r["apk_sha256"], SHA)
        self.assertEqual(set(r["features"]), set(FEATURES))
        self.assertEqual(r["discoveries"], {"block_update": [["o", "m()V"]]})
        self.assertEqual(r["schema"], sp.RESULT_SCHEMA)
        self.assertIn("prepare_ms", r["phases"])
        self.assertIn("structural_ms", r["phases"])
        self.assertIsNone(r["failure"] or r["audit_refusal"] or r["incomplete"])
        self.assertIs(out.raise_for_outcome(), r)
        json.dumps(r)  # a record is plain data

    def test_missing_and_partial_verdicts_are_results_not_failures(self):
        for status in ("MISSING", "PARTIAL", "AMBIGUOUS"):
            with self.subTest(status=status):
                out = self.run_audit(rules=FakeRules(verdicts(status)))
                self.assertEqual(out.outcome, "complete")
                self.assertTrue(out.record["complete"])
                self.assertEqual({v["status"] for v in out.record["features"].values()}, {status})
                self.assertIsNone(out.error)

    def test_every_outcome_is_one_of_four(self):
        self.assertEqual(sp.OUTCOMES, ("complete", "incomplete_coverage", "audit_refused", "failed"))

    # ---- 2. the audit's own refusal is not an engine failure ----

    def test_unsupported_audit_is_a_refusal_with_its_own_words(self):
        error = Refused("duplicate class definitions in native structural audit")
        out = self.run_audit(rules=FakeRules(error=error))
        self.assertEqual(out.outcome, "audit_refused")
        self.assertFalse(out.record["complete"])
        self.assertEqual(out.record["audit_refusal"], {"type": "Refused", "message": str(error)})
        self.assertIsNone(out.record["failure"])
        self.assertIsNone(out.record["incomplete"])
        self.assertEqual(out.record["features"], {})  # no verdicts are made up for an input the audit will not judge
        self.assertIs(out.error, error)
        with self.assertRaises(Refused) as caught:  # HostLab's callers get the audit's own exception, as before
            out.raise_for_outcome()
        self.assertIs(caught.exception, error)
        # it still names the engine that was asked
        self.assertEqual((out.record["backend"], out.record["wire"]), ("meguvizdexdash", "b0"))

    def test_an_engine_error_that_says_the_same_words_is_still_an_engine_failure(self):
        error = ns.EngineRejected("duplicate class definitions in native structural audit",
                                  body={"code": "INVALID_INPUT", "stage": "x", "message": "m"})
        out = self.run_audit(rules=FakeRules(error=error))
        self.assertEqual(out.outcome, "failed")
        self.assertIsNone(out.record["audit_refusal"])

    def test_a_refusal_is_never_classified_as_a_failure_of_the_engine(self):
        out = self.run_audit(rules=FakeRules(error=Refused("x")))
        self.assertIsNone(out.record["failure"])
        self.assertEqual(provider.classify_failure(out.error).code, "UNCLASSIFIED")  # there is no engine code in it
        self.assertEqual(provider.classify_failure(out.error).origin, "unclassified")

    # ---- 3. incomplete coverage ----

    def test_a_statement_the_engine_could_not_cover(self):
        error = ns.EngineIncomplete("not covered", body={"code": "INCOMPLETE_FACTS", "stage": "facts", "message": "no"})
        session = FakeSession(layer_issues=[{"dex_occurrence_id": "d", "layers": "code", "error": {"code": "INVALID_INPUT", "message": "bad"}}])
        out = self.run_audit(session=session, rules=FakeRules(error=error))
        self.assertEqual(out.outcome, "incomplete_coverage")
        self.assertFalse(out.record["complete"])
        self.assertEqual(out.record["incomplete"]["reasons"], ["statement_incomplete"])
        self.assertEqual(out.record["incomplete"]["engine_error"]["code"], "INCOMPLETE_FACTS")
        self.assertEqual(out.record["incomplete"]["layer_issues"][0]["layers"], "code")
        self.assertEqual(out.record["features"], {})  # not "MISSING": nothing was concluded
        self.assertIsNone(out.record["failure"])
        with self.assertRaises(ns.EngineIncomplete):
            out.raise_for_outcome()

    def test_coverage_that_is_not_complete_at_the_end_withholds_completeness(self):
        base = {"statements": 3, "input": "complete", "facts": "complete", "required_layers": [], "issues": []}
        cases = {"facts_partial": ({**base, "facts": "partial"}, ()), "input_unknown": ({**base, "input": "unknown"}, ()),
                 "no_statement_was_covered": ({**base, "statements": 0}, ()),
                 "dataset_layer_issues": (base, [{"layers": "code", "error": {"code": "X"}}])}
        for reason, (coverage, issues) in cases.items():
            with self.subTest(reason=reason):
                out = self.run_audit(session=FakeSession(coverage=coverage, layer_issues=issues))
                self.assertEqual(out.outcome, "incomplete_coverage")
                self.assertFalse(out.record["complete"])
                self.assertIn(reason, out.record["incomplete"]["reasons"])
                self.assertEqual(set(out.record["features"]), set(FEATURES))  # computed, but not to be published as complete
                with self.assertRaises(sp.IncompleteCoverage) as caught:
                    out.raise_for_outcome()
                self.assertIn(reason, caught.exception.reasons)

    def test_an_incomplete_dex_inventory_is_incomplete_coverage(self):
        error = provider.InventoryError("backend did not load the complete physical DEX inventory", {"missing": ["classes2.dex"], "unexpected": []})
        out = self.run_audit(session=FakeSession(enter_error=error))
        self.assertEqual(out.outcome, "incomplete_coverage")
        self.assertEqual(out.record["incomplete"]["reasons"], ["dex_inventory_incomplete"])
        self.assertEqual(out.record["incomplete"]["inventory"]["missing"], ["classes2.dex"])

    def test_coverage_reasons(self):
        self.assertEqual(sp.coverage_reasons(FakeSession()), [])
        self.assertEqual(sp.coverage_reasons(OriginalSession()), [])  # HostLab's own session reports none
        self.assertEqual(sp.coverage_reasons(FakeSession(coverage={"statements": 0, "input": "partial", "facts": "unknown"})),
                         ["no_statement_was_covered", "input_partial", "facts_unknown"])
        self.assertEqual(sp.coverage_reasons(FakeSession(coverage={"statements": 2, "abandoned": 1, "input": "complete", "facts": "complete"})),
                         ["statement_abandoned"])

    def test_an_abandoned_statement_withholds_completeness(self):
        # sent != covered: a statement the consumer walked away from is not a complete result, even when every
        # terminal that was read said complete and the rules produced the whole FEATURE set
        base = {"statements": 3, "input": "complete", "facts": "complete", "required_layers": [], "issues": []}
        out = self.run_audit(session=FakeSession(coverage={**base, "abandoned": 1}))
        self.assertEqual(out.outcome, "incomplete_coverage")
        self.assertFalse(out.record["complete"])
        self.assertIn("statement_abandoned", out.record["incomplete"]["reasons"])
        self.assertEqual(set(out.record["features"]), set(FEATURES))  # computed, but not published as complete
        with self.assertRaises(sp.IncompleteCoverage) as caught:
            out.raise_for_outcome()
        self.assertIn("statement_abandoned", caught.exception.reasons)

    # ---- 4. failures keep what the engine said ----

    def test_failures_are_classified_by_the_engines_code(self):
        def body(code):
            return {"code": code, "stage": "s", "message": "m"}

        cases = [(ns.EngineRejected("q", body=body("QUOTA_EXCEEDED")), "QUOTA_EXCEEDED", "engine"),
                 (ns.EngineRejected("q", body=body("UNSUPPORTED_QUERY")), "UNSUPPORTED_QUERY", "engine"),
                 (ns.EngineLost("gone"), "WORKER_LOST", "engine"),
                 (ns.EngineProtocolError("garbled"), "INTERNAL_FAULT", "engine"),
                 (ns.SessionClosed("closed"), "SNAPSHOT_CLOSED", "engine"),
                 (TimeoutError("native audit deadline exhausted"), "DEADLINE_EXCEEDED", "adapter"),
                 (RuntimeError("something else"), "UNCLASSIFIED", "unclassified"),
                 (ValueError("audit SQL literal contains unsupported control characters"), "UNCLASSIFIED", "unclassified"),
                 (ns.provider.installer.EngineUnavailable("binary_missing", "no binary"), "UNAVAILABLE_BACKEND", "adapter")]
        for error, code, origin in cases:
            with self.subTest(error=type(error).__name__, code=code):
                out = self.run_audit(rules=FakeRules(error=error))
                self.assertEqual(out.outcome, "failed")
                self.assertFalse(out.record["complete"])
                self.assertEqual((out.record["failure"]["code"], out.record["failure"]["origin"]), (code, origin))
                self.assertEqual(out.record["failure"]["type"], type(error).__name__)
                self.assertEqual(out.record["features"], {})
                self.assertIsNone(out.record["audit_refusal"] or out.record["incomplete"])
                with self.assertRaises(type(error)) as caught:
                    out.raise_for_outcome()
                self.assertIs(caught.exception, error)

    def test_a_session_that_cannot_be_created_is_a_failure_with_no_engine_named(self):
        error = ns.provider.installer.EngineUnavailable("digest_mismatch", "not the pinned binary")
        out = self.run_audit(factory_error=error)
        self.assertEqual(out.outcome, "failed")
        self.assertEqual(out.record["failure"]["code"], "UNAVAILABLE_BACKEND")
        self.assertIsNone(out.record["backend"])  # nothing answered
        self.assertIsNone(out.record["engine"])

    def test_interrupts_are_not_swallowed(self):
        for error in (KeyboardInterrupt(), SystemExit(3)):
            with self.subTest(error=type(error).__name__):
                with self.assertRaises(type(error)):
                    self.run_audit(rules=FakeRules(error=error))

    def test_the_feature_set_must_be_complete(self):
        short = verdicts()
        short.pop(FEATURES[0])
        extra = dict(verdicts(), surprise={"status": "FOUND", "detail": ""})
        for name, result in (("missing", short), ("extra", extra)):
            with self.subTest(case=name):
                out = self.run_audit(rules=FakeRules(result))
                self.assertEqual(out.outcome, "failed")
                self.assertIn("complete FEATURE set", out.record["failure"]["message"])
                self.assertFalse(out.record["complete"])

    def test_the_source_must_be_the_one_named_and_must_not_change(self):
        out = self.run_audit(digest=lambda path: "00" * 32)
        self.assertEqual(out.outcome, "failed")
        self.assertIn("immutable APK identity", out.record["failure"]["message"])
        self.assertEqual((out.record["failure"]["code"], out.record["failure"]["origin"]), ("SOURCE_CHANGED", "adapter"))
        digests = iter([SHA, "11" * 32])
        out = self.run_audit(digest=lambda path: next(digests))
        self.assertEqual(out.outcome, "failed")
        self.assertIn("changed during analysis", out.record["failure"]["message"])
        self.assertEqual(out.record["failure"]["code"], "SOURCE_CHANGED")
        self.assertIsInstance(out.error, RuntimeError)  # still what HostLab raised: a RuntimeError with the same words
        self.assertFalse(out.record["source_sha_reverified"])
        self.assertFalse(out.record["complete"])

    def test_the_classes_are_counted_after_the_rules(self):
        session = FakeSession(count=12345)
        out = self.run_audit(session=session)
        self.assertEqual(out.record["class_count"], 12345)
        self.assertEqual(session.statements, ["SELECT COUNT(*) AS n FROM classes ORDER BY n"])

    def test_the_rules_get_the_session_itself(self):
        # nothing sits between the rules and the engine's answers: no wrapper, no filter
        seen = []
        session = FakeSession()
        self.run_audit(session=session, rules=FakeRules(seen=seen))
        self.assertEqual(len(seen), 1)
        self.assertIs(seen[0], session)

    def test_run_is_native_audit_run(self):
        apk = self.apk()
        record = sp.run(apk, sha256=SHA, rules_module=FakeRules(), expected_features=FEATURES,
                        session_factory=lambda path: FakeSession(), digest=lambda path: SHA)
        self.assertEqual(record["outcome"], "complete")
        with self.assertRaises(Refused):
            sp.run(apk, sha256=SHA, rules_module=FakeRules(error=Refused("no")), expected_features=FEATURES,
                   session_factory=lambda path: FakeSession(), digest=lambda path: SHA)

    # ---- 5. rollback ----

    def test_rollback_reports_dexsql_and_no_engine(self):
        out = self.run_audit(session=OriginalSession())
        self.assertEqual(out.outcome, "complete")
        self.assertEqual(out.record["backend"], "dexsql")
        self.assertIsNone(out.record["engine"] or out.record["wire"] or out.record["coverage"] or out.record["dataset"])
        self.assertTrue(out.record["complete"])

    def test_the_default_factory_follows_the_provider_setting(self):
        apk = self.apk()
        original = FakeSession()
        created = []

        def original_factory(path, timeout, threads):
            created.append((path, timeout, threads))
            return OriginalSession()

        config = {"schema": provider.CONFIG_SCHEMA, "native_engine": "dexsql"}
        with mock.patch.object(ns, "original_session", return_value=original_factory), \
                mock.patch.object(ns, "engine_launch", side_effect=AssertionError("the engine must not be launched")):
            out = sp.run_structural(apk, sha256=SHA, rules_module=FakeRules(), expected_features=FEATURES, timeout=44, threads=3,
                                    provider_config=config, digest=lambda path: SHA)
        self.assertEqual(out.record["backend"], "dexsql")
        self.assertEqual(out.outcome, "complete")
        self.assertEqual(created, [(apk.resolve(), 44, 3)])
        del original

    # ---- 6. the fallback policy composes with it ----

    def test_incomplete_coverage_and_refusals_never_fall_back(self):
        config = provider.parse_config({"schema": provider.CONFIG_SCHEMA, "native_engine": "meguvizdexdash",
                                        "meguvizdexdash": {"fallback": {"to": "dexsql", "on": ["UNAVAILABLE_BACKEND", "UNSUPPORTED_QUERY"]}}})
        task = {"id": "audit", "backend": provider.ENGINE, "forced": False}
        errors = [ns.EngineIncomplete("x", body={"code": "INCOMPLETE_FACTS", "stage": "s", "message": "m"}),
                  Refused("duplicate class definitions"), ns.EngineLost("gone"),
                  ns.EngineRejected("q", body={"code": "QUOTA_EXCEEDED", "stage": "s", "message": "m"})]
        for error in errors:
            with self.subTest(error=type(error).__name__):
                audit = provider.AuditLog()
                fallbacks = []

                def primary(error=error):
                    raise error

                with self.assertRaises(type(error)):
                    provider.run_with_policy(task, primary, lambda: fallbacks.append(1), config=config, negotiation={}, audit=audit)
                self.assertEqual(fallbacks, [])
                self.assertEqual(audit.records[0]["decision"]["action"], "fail")

    def test_an_explicit_not_here_may_fall_back_when_configured(self):
        config = provider.parse_config({"schema": provider.CONFIG_SCHEMA, "native_engine": "meguvizdexdash",
                                        "meguvizdexdash": {"fallback": {"to": "dexsql", "on": ["UNAVAILABLE_BACKEND"]}}})
        task = {"id": "audit", "backend": provider.ENGINE, "forced": False}

        def primary():
            raise ns.provider.installer.EngineUnavailable("binary_missing", "gone")

        result = provider.run_with_policy(task, primary, lambda: {"from": "dexsql"}, config=config, negotiation={}, audit=provider.AuditLog())
        self.assertEqual(result["fallback"]["to"], "dexsql")

    # ---- 7. publishing ----

    def test_results_are_published_below_the_engines_own_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            identity = {"build_id": "b", "binary_sha256": "d" * 64}
            config = provider.parse_config({"schema": provider.CONFIG_SCHEMA, "native_engine": "meguvizdexdash"})
            spaces = provider.namespaces(base / "state", identity, config)
            provider.ensure_namespaces(spaces, identity)
            record = self.run_audit().record
            path = sp.publish_result(record, spaces)
            self.assertTrue(path.is_file())
            self.assertTrue(path.resolve().is_relative_to((base / "state" / "mdd-engine").resolve()))
            for legacy in provider.LEGACY_NAMES:
                self.assertFalse(path.resolve().is_relative_to((base / "state" / legacy).resolve()), legacy)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), record)
            self.assertIn(record["wire"], path.name)
            self.assertIn(record["outcome"], path.name)
            with self.assertRaises(provider.NamespaceCollision):  # never replaced
                sp.publish_result(record, spaces)
            self.assertEqual(sorted(p.name for p in path.parent.iterdir()), [path.name])

    def test_only_engine_results_are_published(self):
        with tempfile.TemporaryDirectory() as directory:
            record = self.run_audit(session=OriginalSession()).record
            with self.assertRaises(provider.ProviderError):
                sp.publish_result(record, {"reports": Path(directory)})
            self.assertEqual(list(Path(directory).iterdir()), [])


class BoundaryTests(unittest.TestCase):
    """BIL names and business rules stay in HostLab's modules and the adapter's data; the core and these modules have none."""

    TOKENS = ("danmaku", "bilibili", "bapis", "kntr", "pegasus", "gemini", "theseus", "biligame", "videodetail")
    # what a package or class literal of the application looks like; the bare product name may appear in a comment or a
    # message of the core (two do, naming the build a measurement was made on), a literal a rule could match on may not
    PACKAGE_LITERALS = ("tv.danmaku", "tv/danmaku", "com.bilibili", "com/bilibili", "com.bapis", "com/bapis", "kntr.", "kntr/",
                        "pegasus", "theseus", "gemini", "biligame", "videodetail")

    @classmethod
    def setUpClass(cls):
        cls.rules_source = F.frozen_source("native_rules").decode("utf-8")

    def test_the_token_list_is_grounded_in_the_frozen_rules(self):
        for token in self.TOKENS:
            with self.subTest(token=token):
                self.assertIn(token, self.rules_source)

    def test_the_new_modules_name_no_application_class_and_no_rule(self):
        for name in ("native_session.py", "structural_provider.py"):
            text = (HERE / name).read_text(encoding="utf-8").lower()
            for token in self.TOKENS:
                with self.subTest(module=name, token=token):
                    self.assertNotIn(token, text)
            for feature in FEATURES:
                with self.subTest(module=name, feature=feature):
                    self.assertIsNone(re.search(r"(?<![a-z_])" + feature + r"(?![a-z_])", text))

    def test_the_core_names_no_application_class_outside_its_tests(self):
        offenders = []
        for path in sorted((ROOT / "crates").glob("*/src/**/*.rs")):
            relative = path.relative_to(ROOT).as_posix()
            if path.name == "tests.rs" or path.name.endswith("_tests.rs") or "/tests/" in relative:
                continue
            text = path.read_text(encoding="utf-8")
            marker = text.find("\n#[cfg(test)]")
            production = text if marker < 0 else text[:marker]
            hits = [token for token in self.PACKAGE_LITERALS if token in production.lower()]
            if hits:
                offenders.append((relative, hits))
        self.assertEqual(offenders, [])
        for path in sorted((ROOT / "python/mdd").glob("*.py")) + sorted((ROOT / "include").glob("*.h")):
            with self.subTest(path=path.name):
                self.assertFalse(any(token in path.read_text(encoding="utf-8").lower() for token in self.TOKENS))

    def test_the_boundary_scan_can_fail(self):
        # a production file with a package literal ahead of its test module is caught; one with it only inside the test module is not
        def scan(text):
            marker = text.find("\n#[cfg(test)]")
            production = text if marker < 0 else text[:marker]
            return [token for token in self.PACKAGE_LITERALS if token in production.lower()]

        self.assertEqual(scan('const X: &str = "Lcom/bilibili/Foo;";\n'), ["com/bilibili"])
        self.assertEqual(scan('fn f() {}\n#[cfg(test)]\nmod tests { const X: &str = "Lcom/bapis/Moss;"; }\n'), [])
        self.assertEqual(scan('const X: &str = "tv.danmaku.bili";\n#[cfg(test)]\nmod tests {}\n'), ["tv.danmaku"])

    def test_known_exception_feature_names_in_the_core(self):
        """The core crate mdd-facts holds a Rust skeleton of four of the rules (crates/mdd-facts/src/hostlab, built before
        this task). AGENTS.md keeps FEATURE out of the generic core, so this is pinned, not endorsed: the set of production
        files that name a FEATURE must not grow."""
        holders = set()
        for path in sorted((ROOT / "crates").glob("*/src/**/*.rs")):
            if path.name == "tests.rs" or path.name.endswith("_tests.rs"):
                continue
            text = path.read_text(encoding="utf-8")
            marker = text.find("\n#[cfg(test)]")
            production = text if marker < 0 else text[:marker]
            if any(re.search(r'"' + feature + r'"', production) for feature in FEATURES):
                holders.add(path.relative_to(ROOT).as_posix())
        self.assertEqual(holders, {"crates/mdd-facts/src/hostlab/rules.rs"})

    def test_the_rules_stay_the_frozen_ones(self):
        # the audit is not re-implemented: the modules it runs are the frozen source, loaded after their digest matched
        self.assertEqual(len(FEATURES), 27)
        self.assertEqual(len(set(FEATURES)), 27)
        graph, rules = F.graph_and_rules(ns)
        self.assertEqual(rules.Rules.__module__, "native_rules")
        self.assertIs(rules.UnsupportedAudit, graph.UnsupportedAudit)
        self.assertIs(rules.in_list, ns.in_list)  # the rules use this module's SQL literal builder, not a copy of it


if __name__ == "__main__":
    unittest.main()
