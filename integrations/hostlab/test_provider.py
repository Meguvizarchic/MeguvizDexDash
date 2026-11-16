"""Provider selection, fallback policy, report identity, namespaces and the gates that stay in force.

Run: python -I -m unittest discover -s integrations/hostlab -p "test_provider.py"
No network, no download, no real engine (test_live_engine.py uses the real one). HostLab's frozen
planner and gate functions (conformance/corpus/hostlab/source-8782f43, hash-checked) are the oracle.
"""
import itertools
import json
import os
import re
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hostlab_test_support as support  # noqa: E402
import install_meguvizdexdash as installer  # noqa: E402
import provider  # noqa: E402

ROOT = support.ROOT
LEGACY = support.load_frozen("analysis_plan")
ENGINE = provider.ENGINE


def cfg(native="meguvizdexdash", **engine):
    document = {"schema": provider.CONFIG_SCHEMA, "native_engine": native}
    if engine:
        document[ENGINE] = engine
    return provider.parse_config(document)


def fallback_cfg(on=("UNAVAILABLE_BACKEND", "UNSUPPORTED_CAPABILITY", "UNSUPPORTED_QUERY"), **engine):
    return cfg(profile_policy="allow_unadmitted", fallback={"to": "dexsql", "on": list(on)}, **engine)


request, QUERY, SQLITE_QUERY, LOCATE, DECODE, INFO, REFS, REFS_SITES = (
    support.request, support.QUERY, support.SQLITE_QUERY, support.LOCATE, support.DECODE, support.INFO, support.REFS,
    support.REFS_SITES)
PLAIN = provider.Config()


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.dir = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)
        self.engines = 0

    def engine(self, **options):
        """A pinned stand-in engine (a new directory each time) and its available status."""
        self.engines += 1
        directory = self.dir / f"engine{self.engines}"
        directory.mkdir()
        binary, manifest, fake = support.pin_binary(directory, support.FakeEngine(**options))
        self.binary, self.manifest, self.fake = binary, manifest, fake
        return installer.status(binary, manifest, fake, deep=True)

    def unavailable(self):
        self.engine()
        self.binary.write_bytes(b"altered after the pin")
        return installer.status(self.binary, self.manifest, self.fake)

    def plan(self, req, config, status=None, **options):
        return provider.plan(req, config, legacy=LEGACY, engine_status=status, **options)


# ---- configuration ----------------------------------------------------------------------------

class Configuration(Case):
    VALID = [
        {"schema": provider.CONFIG_SCHEMA},
        {"schema": provider.CONFIG_SCHEMA, "native_engine": "dexsql"},
        {"schema": provider.CONFIG_SCHEMA, "native_engine": ENGINE, ENGINE: {}},
        {"schema": provider.CONFIG_SCHEMA, ENGINE: {"dialect": "dexsql-0.1.1", "profile": "p", "max_datasets": 16,
                                                     "profile_policy": "allow_unadmitted", "cache_dir": "mdd/c",
                                                     "manifest": "m.json"}},
        {"schema": provider.CONFIG_SCHEMA, ENGINE: {"fallback": {"to": "dexsql", "on": ["UNSUPPORTED_QUERY"]}}},
        {"schema": provider.CONFIG_SCHEMA, ENGINE: {"fallback": {"to": "none", "on": []}}},
        {"schema": provider.CONFIG_SCHEMA, ENGINE: {"fallback": {}}},
    ]
    INVALID = [
        ("no schema", {"native_engine": "dexsql"}),
        ("wrong schema", {"schema": "x"}),
        ("unknown top key", {"schema": provider.CONFIG_SCHEMA, "backend": "dexsql"}),
        ("unknown engine", {"schema": provider.CONFIG_SCHEMA, "native_engine": "sqlite"}),
        ("unknown engine key", {"schema": provider.CONFIG_SCHEMA, ENGINE: {"url": "http://x"}}),
        ("bad dialect", {"schema": provider.CONFIG_SCHEMA, ENGINE: {"dialect": "native-v1"}}),
        ("bad policy", {"schema": provider.CONFIG_SCHEMA, ENGINE: {"profile_policy": "any"}}),
        ("zero datasets", {"schema": provider.CONFIG_SCHEMA, ENGINE: {"max_datasets": 0}}),
        ("boolean datasets", {"schema": provider.CONFIG_SCHEMA, ENGINE: {"max_datasets": True}}),
        ("too many datasets", {"schema": provider.CONFIG_SCHEMA, ENGINE: {"max_datasets": 17}}),
        ("empty profile", {"schema": provider.CONFIG_SCHEMA, ENGINE: {"profile": ""}}),
        ("empty cache dir", {"schema": provider.CONFIG_SCHEMA, ENGINE: {"cache_dir": ""}}),
        ("fallback to an unknown target", {"schema": provider.CONFIG_SCHEMA, ENGINE: {"fallback": {"to": "sqlite"}}}),
        ("fallback on a failure that is not 'not here'",
         {"schema": provider.CONFIG_SCHEMA, ENGINE: {"fallback": {"to": "dexsql", "on": ["INTERNAL_FAULT"]}}}),
        ("fallback on SOURCE_CHANGED",
         {"schema": provider.CONFIG_SCHEMA, ENGINE: {"fallback": {"to": "dexsql", "on": ["SOURCE_CHANGED"]}}}),
        ("fallback target without codes", {"schema": provider.CONFIG_SCHEMA, ENGINE: {"fallback": {"to": "dexsql"}}}),
        ("fallback codes without target",
         {"schema": provider.CONFIG_SCHEMA, ENGINE: {"fallback": {"on": ["UNSUPPORTED_QUERY"]}}}),
        ("none with codes",
         {"schema": provider.CONFIG_SCHEMA, ENGINE: {"fallback": {"to": "none", "on": ["UNSUPPORTED_QUERY"]}}}),
        ("duplicate codes", {"schema": provider.CONFIG_SCHEMA,
                             ENGINE: {"fallback": {"to": "dexsql", "on": ["UNSUPPORTED_QUERY", "UNSUPPORTED_QUERY"]}}}),
        ("not an object", []),
    ]

    def test_the_schema_file_and_the_parser_accept_and_refuse_the_same_documents(self):
        schema = json.loads((support.HERE / "config-schema.json").read_text(encoding="utf-8"))
        for document in self.VALID:
            with self.subTest(document=document):
                self.assertTrue(support.schema_valid(schema, document), "the schema refuses a valid document")
                provider.parse_config(document)
        for label, document in self.INVALID:
            with self.subTest(label):
                self.assertFalse(support.schema_valid(schema, document), "the schema accepts an invalid document")
                with self.assertRaises(provider.ConfigError):
                    provider.parse_config(document)

    def test_the_schema_lists_exactly_what_the_code_allows(self):
        schema = json.loads((support.HERE / "config-schema.json").read_text(encoding="utf-8"))
        engine = schema["properties"][ENGINE]["properties"]
        self.assertEqual(tuple(schema["properties"]["native_engine"]["enum"]), provider.NATIVE_ENGINES)
        self.assertEqual(tuple(engine["fallback"]["properties"]["on"]["items"]["enum"]), provider.FALLBACK_ELIGIBLE)
        self.assertEqual(tuple(engine["dialect"]["enum"]), provider.DIALECTS)
        self.assertEqual(tuple(engine["profile_policy"]["enum"]), provider.PROFILE_POLICIES)
        self.assertEqual(tuple(engine["fallback"]["properties"]["to"]["enum"]), provider.FALLBACK_TARGETS)
        defaults = provider.Config().effective()
        self.assertEqual(defaults["native_engine"], schema["properties"]["native_engine"]["default"])
        for key, value in engine.items():
            if key != "fallback":
                self.assertEqual(defaults[ENGINE][key], value["default"], key)

    def test_the_default_routes_nothing_to_the_new_engine(self):
        self.assertEqual(provider.Config().native_engine, "dexsql")
        self.assertEqual(provider.load_config(environ={}), provider.Config())

    def test_a_configuration_is_read_from_a_file_or_the_named_variable_and_a_missing_file_is_an_error(self):
        path = self.dir / "provider.json"
        path.write_text(json.dumps({"schema": provider.CONFIG_SCHEMA, "native_engine": ENGINE}), encoding="utf-8")
        self.assertEqual(provider.load_config(path).native_engine, ENGINE)
        self.assertEqual(provider.load_config(environ={"HOSTLAB_PROVIDER_CONFIG": str(path)}).native_engine, ENGINE)
        with self.assertRaises(OSError):
            provider.load_config(self.dir / "absent.json")
        with self.assertRaises(OSError):
            provider.load_config(environ={"HOSTLAB_PROVIDER_CONFIG": str(self.dir / "absent.json")})
        path.write_text("{", encoding="utf-8")
        with self.assertRaises(provider.ConfigError):
            provider.load_config(path)

    def test_the_digest_follows_the_effective_configuration_not_its_spelling(self):
        self.assertEqual(provider.parse_config({"schema": provider.CONFIG_SCHEMA}).digest(),
                         provider.parse_config({"schema": provider.CONFIG_SCHEMA, "native_engine": "dexsql",
                                                ENGINE: {"dialect": "dexsql-0.1.0", "fallback": {"to": "none"}}}).digest())
        self.assertNotEqual(cfg().digest(), cfg(dialect="dexsql-0.1.1").digest())
        self.assertNotEqual(cfg().digest(), cfg("dexsql").digest())


# ---- the old backends are not moved ---------------------------------------------------------------

LEGACY_REQUESTS = [
    request(SQLITE_QUERY, LOCATE, backend="sqlite"),
    request(QUERY, LOCATE, DECODE, backend="dexsql"),
    request(REFS, INFO, backend="dexsql"),
    request(QUERY, SQLITE_QUERY),
    request(LOCATE, REFS_SITES, DECODE),
    request(dict(DECODE, file_id=0)),
    request(INFO, REFS),
    request(LOCATE, backend="auto"),
    {"tasks": [LOCATE]},
    request(QUERY, backend="sqlite"),          # refused by the legacy planner
    request(REFS_SITES, backend="dexsql"),     # refused by the legacy planner
    request(backend="auto"),                   # refused: no tasks
    request(LOCATE, backend="nope"),           # refused: unknown backend
]


class LegacyIsUnchanged(Case):
    def outcome(self, call):
        try:
            return ("plan", call())
        except ValueError as error:
            return ("refused", str(error))

    def test_without_the_new_engine_the_plan_is_exactly_the_frozen_planner(self):
        configs = [PLAIN, cfg("dexsql"), cfg("dexsql", fallback={"to": "dexsql", "on": ["UNSUPPORTED_QUERY"]})]
        for req, config_, available, hit in itertools.product(LEGACY_REQUESTS, configs, (True, False), (True, False)):
            with self.subTest(request=req, config=config_.native_engine, dexsql=available, sqlite_hit=hit):
                expected = self.outcome(lambda: LEGACY.plan(req, dexsql_available=available, sqlite_cache_hit=hit))
                actual = self.outcome(lambda: provider.plan(req, config_, legacy=LEGACY, dexsql_available=available,
                                                            sqlite_cache_hit=hit))
                self.assertEqual(actual, expected)
                if expected[0] == "plan":
                    self.assertNotIn("provider", actual[1])

    def test_a_forced_dexsql_or_sqlite_request_is_not_moved_by_any_engine_setting(self):
        status = self.engine()
        for req in [r for r in LEGACY_REQUESTS if r.get("backend") in {"sqlite", "dexsql"}]:
            for available in (True, False):
                with self.subTest(request=req, dexsql=available):
                    expected = self.outcome(lambda: LEGACY.plan(req, dexsql_available=available))
                    for config_ in (cfg(profile_policy="allow_unadmitted"), fallback_cfg()):
                        actual = self.outcome(lambda: provider.plan(req, config_, legacy=LEGACY, engine_status=status,
                                                                    dexsql_available=available))
                        self.assertEqual(actual, expected)
                        if actual[0] == "plan":
                            self.assertNotIn(ENGINE, {t["backend"] for t in actual[1]["tasks"]})

    def test_a_forced_dexsql_request_with_the_engine_unavailable_still_means_dexsql(self):
        req = request(QUERY, backend="dexsql")
        result = self.plan(req, fallback_cfg(), self.unavailable())
        self.assertEqual({t["backend"] for t in result["tasks"]}, {"dexsql"})
        self.assertEqual(result, LEGACY.plan(req))

    def test_negotiation_means_nothing_to_a_request_that_names_a_legacy_backend(self):
        for backend in ("sqlite", "dexsql"):
            with self.assertRaisesRegex(provider.ProviderError, "negotiation applies"):
                self.plan(request(QUERY, backend=backend, negotiation={"fallback": "forbid"}), fallback_cfg())

    def test_fields_the_planner_does_not_know_stay_refused(self):
        for key in ("source_mode", "engine", "profile", "cache_dir"):
            with self.assertRaises(ValueError):
                self.plan(request(QUERY, **{key: "x"}), fallback_cfg(), self.engine())
        with self.assertRaises(provider.ConfigError):
            self.plan(request(QUERY, negotiation={"fallback": "forbid", "extra": 1}), fallback_cfg(), self.engine())
        with self.assertRaises(provider.ConfigError):
            self.plan(request(QUERY, negotiation={"fallback": "sometimes"}), fallback_cfg(), self.engine())


# ---- selection ----------------------------------------------------------------------------------------

class Selection(Case):
    def setUp(self):
        super().setUp()
        self.status = self.engine()
        self.config = cfg(profile_policy="allow_unadmitted")

    def test_auto_goes_where_native_engine_points_and_sqlite_work_stays_with_sqlite(self):
        req = request(QUERY, LOCATE, DECODE, INFO, REFS, REFS_SITES)
        result = self.plan(req, self.config, self.status)
        by_id = {t["id"]: t for t in result["tasks"]}
        self.assertEqual({k: v["backend"] for k, v in by_id.items()},
                         {"q": ENGINE, "l": ENGINE, "d": ENGINE, "i": ENGINE, "r": ENGINE, "rs": "sqlite"})
        self.assertTrue(all(by_id[k]["forced"] is False for k in "qldir"))
        self.assertEqual([g["backend"] for g in result["groups"]], ["sqlite", ENGINE])
        self.assertEqual(result["dataset_opens"], 2)
        legacy = LEGACY.plan(req)
        self.assertEqual(result["request_sha256"], legacy["request_sha256"], "an auto request keeps its identity")
        self.assertEqual({t["id"]: t["reason"] for t in result["tasks"]}, {t["id"]: t["reason"] for t in legacy["tasks"]})
        self.assertEqual(result["provider"]["selection"], "configured")

    def test_the_same_auto_request_under_the_rollback_value_is_the_legacy_plan(self):
        req = request(QUERY, LOCATE, DECODE, INFO, REFS_SITES)
        self.assertEqual(self.plan(req, cfg("dexsql"), self.status), LEGACY.plan(req))

    def test_a_request_that_names_the_engine_is_served_by_it_and_has_its_own_identity(self):
        req = request(QUERY, LOCATE, DECODE, INFO, REFS, backend=ENGINE)
        result = self.plan(req, self.config, self.status)
        self.assertEqual({t["backend"] for t in result["tasks"]}, {ENGINE})
        self.assertTrue(all(t["forced"] for t in result["tasks"]))
        self.assertEqual(result["provider"]["selection"], "forced")
        as_dexsql = LEGACY.plan(request(QUERY, LOCATE, DECODE, INFO, REFS, backend="dexsql"))
        self.assertNotEqual(result["request_sha256"], as_dexsql["request_sha256"],
                            "the same tasks for the new engine and for DexSQL are different requests")
        again = self.plan(req, self.config, self.status)
        self.assertEqual(result, again, "planning is deterministic")

    def test_the_plan_names_the_real_engine_profile_dialect_and_configuration(self):
        engine = self.plan(request(QUERY), self.config, self.status)["provider"]["engine"]
        self.assertEqual(engine["backend"], ENGINE)
        self.assertEqual((engine["engine_version"], engine["build_id"]), ("0.1.0-test", support.BUILD_ID))
        self.assertEqual(engine["binary_sha256"], installer.sha256(self.binary))
        self.assertEqual(engine["profile"], {"name": "mdd-native-v1", "admitted": False,
                                             "conformance_manifest_sha256": None, "policy": "allow_unadmitted"})
        self.assertEqual(engine["dialect"], {"hostlab": "dexsql", "engine": "dexsql-0.1.0", "revision": "0.1.0"})
        self.assertEqual(engine["config_digest"], self.config.digest())
        self.assertEqual(engine["implementation_scope"], "unqualified development build")
        self.assertNotIn("path", engine, "a plan is portable: it carries no local path")

    def test_a_forced_request_the_engine_cannot_serve_is_refused_in_the_plan(self):
        for task, why in ((SQLITE_QUERY, "dialect"), (REFS_SITES, "sites")):
            with self.subTest(why), self.assertRaises(provider.ProviderUnsupported) as caught:
                self.plan(request(task, backend=ENGINE), fallback_cfg(), self.status)
            self.assertEqual(caught.exception.code, "UNSUPPORTED_CAPABILITY")
        with self.assertRaises(ValueError) as caught:
            self.plan(request(backend=ENGINE), self.config, self.status)
        self.assertNotIsInstance(caught.exception, provider.ProviderUnsupported, "a malformed request is not 'unsupported'")

    def test_a_forced_request_is_refused_when_the_engine_is_switched_off(self):
        with self.assertRaises(provider.ProviderDisabled) as caught:
            self.plan(request(QUERY, backend=ENGINE), cfg("dexsql"), self.status)
        self.assertEqual(caught.exception.code, "UNAVAILABLE_BACKEND")
        self.assertIn("nothing is substituted", str(caught.exception))
        with self.assertRaises(provider.ProviderDisabled):
            self.plan(request(QUERY, backend=ENGINE), provider.Config(), self.status)

    def test_what_the_engine_cannot_do_is_visible_in_the_plan(self):
        status = self.engine(tools=tuple(t for t in support.TOOLS if t != "decode"))
        config = cfg(profile_policy="allow_unadmitted")
        result = self.plan(request(QUERY, INFO), config, status)
        self.assertEqual({t["backend"] for t in result["tasks"]}, {ENGINE})
        with self.assertRaises(provider.ProviderUnsupported) as caught:
            self.plan(request(QUERY, DECODE), config, status)
        self.assertEqual(caught.exception.reason, "tool_not_offered:decode")
        self.assertEqual(caught.exception.evidence["task"], "d")
        with self.assertRaises(provider.ProviderUnsupported):
            self.plan(request(QUERY, DECODE, backend=ENGINE), fallback_cfg(), status)

    def test_a_dialect_the_engine_does_not_offer_is_refused(self):
        status = self.engine(dialects=[{"name": "dexsql-0.1.0", "revision": "0.1.0", "features": []}])
        with self.assertRaises(provider.ProviderUnsupported) as caught:
            self.plan(request(QUERY), self.config, status)
        self.assertEqual(caught.exception.reason, "dialect_not_offered")
        status = self.engine()
        with self.assertRaises(provider.ProviderUnsupported):
            self.plan(request(QUERY), cfg(profile_policy="allow_unadmitted", dialect="dexsql-0.1.1",
                                          ), self.engine(dialects=[]))

    def test_a_profile_that_is_not_admitted_is_not_used_unless_the_operator_says_so(self):
        status = self.engine()
        with self.assertRaises(provider.ProviderUnavailable) as caught:
            self.plan(request(QUERY), cfg(), status)
        self.assertEqual(caught.exception.reason, "profile_not_admitted")
        admitted = self.engine(admitted=True)
        result = self.plan(request(QUERY), cfg(), admitted)
        self.assertTrue(result["provider"]["engine"]["profile"]["admitted"])
        with self.assertRaises(provider.ProviderUnavailable) as caught:
            self.plan(request(QUERY), cfg(profile="no-such-profile", profile_policy="allow_unadmitted"), status)
        self.assertEqual(caught.exception.reason, "profile_not_offered")
        shown = self.plan(request(QUERY), cfg(profile_policy="allow_unadmitted"), status)
        self.assertFalse(shown["provider"]["engine"]["profile"]["admitted"], "the plan says admitted=false")

    def test_the_tools_a_task_needs_cover_every_call_hostlab_sends(self):
        manifest = json.loads((ROOT / "conformance/mcp/hostlab-required-tools.json").read_text(encoding="utf-8"))
        sent = {call["tool"] for call in manifest["calls"]}
        needed = set(itertools.chain.from_iterable(provider.TOOLS_BY_OPERATION.values()))
        self.assertEqual(needed, sent)
        self.assertEqual(set(provider.TOOLS_BY_OPERATION), set(LEGACY.OPERATIONS))
        self.assertTrue(needed <= set(support.TOOLS))


# ---- unavailable engine: a bad sha, and the explicit fallback --------------------------------------------------

class Unavailable(Case):
    def test_a_bad_sha_makes_the_engine_unusable_and_nothing_else_serves_a_forced_request(self):
        status = self.unavailable()
        self.assertEqual((status["available"], status["reason"]), (False, "digest_mismatch"))
        for config in (cfg(profile_policy="allow_unadmitted"), fallback_cfg()):
            with self.subTest(fallback=config.engine.fallback.to), self.assertRaises(provider.ProviderUnavailable) as caught:
                self.plan(request(QUERY, backend=ENGINE), config, status)
            self.assertEqual((caught.exception.code, caught.exception.reason), ("UNAVAILABLE_BACKEND", "digest_mismatch"))

    def test_an_auto_request_without_a_fallback_fails_instead_of_going_to_dexsql(self):
        status = self.unavailable()
        with self.assertRaisesRegex(provider.ProviderUnavailable, "no fallback is permitted"):
            self.plan(request(QUERY, LOCATE), cfg(profile_policy="allow_unadmitted"), status)

    def test_an_explicit_fallback_is_recorded_in_the_plan(self):
        status = self.unavailable()
        result = self.plan(request(QUERY, LOCATE), fallback_cfg(), status)
        self.assertEqual({t["backend"] for t in result["tasks"]}, {"dexsql"})
        for task in result["tasks"]:
            self.assertEqual(task["fallback_from"], ENGINE)
            self.assertEqual(task["fallback"], {"from": ENGINE, "to": "dexsql", "code": "UNAVAILABLE_BACKEND",
                                                "reason": "digest_mismatch", "scope": "plan"})
        self.assertEqual(result["provider"]["fallbacks"][0]["task"], "q")
        self.assertIsNone(result["provider"]["engine"], "no engine ran, so none is claimed")
        self.assertEqual([g["backend"] for g in result["groups"]], ["dexsql"])

    def test_the_fallback_needs_the_code_to_be_enabled_the_target_to_exist_and_the_request_to_allow_it(self):
        status = self.unavailable()
        with self.assertRaises(provider.ProviderUnavailable):
            self.plan(request(QUERY), fallback_cfg(on=("UNSUPPORTED_QUERY",)), status)
        with self.assertRaisesRegex(provider.ProviderUnavailable, "fallback target dexsql is unavailable"):
            self.plan(request(QUERY), fallback_cfg(), status, dexsql_available=False)
        with self.assertRaises(provider.ProviderUnavailable):
            self.plan(request(QUERY, negotiation={"fallback": "forbid"}), fallback_cfg(), status)
        allowed = self.plan(request(QUERY, negotiation={"fallback": "configured"}), fallback_cfg(), status)
        self.assertEqual(allowed["tasks"][0]["backend"], "dexsql")
        self.assertEqual(allowed["provider"]["negotiation"], {"fallback": "configured"})

    def test_only_the_tasks_the_engine_cannot_serve_fall_back(self):
        status = self.engine(tools=tuple(t for t in support.TOOLS if t != "decode"))
        result = self.plan(request(QUERY, DECODE), fallback_cfg(), status)
        self.assertEqual({t["id"]: t["backend"] for t in result["tasks"]}, {"q": ENGINE, "d": "dexsql"})
        self.assertEqual(result["tasks"][1]["fallback"]["code"], "UNSUPPORTED_CAPABILITY")
        self.assertEqual([g["backend"] for g in result["groups"]], ["dexsql", ENGINE])
        with self.assertRaises(provider.ProviderUnsupported):
            self.plan(request(QUERY, DECODE), fallback_cfg(on=("UNAVAILABLE_BACKEND",)), status)

    def test_a_missing_status_is_treated_as_unavailable_not_as_available(self):
        with self.assertRaises(provider.ProviderUnavailable) as caught:
            self.plan(request(QUERY), cfg(profile_policy="allow_unadmitted"), None)
        self.assertEqual(caught.exception.reason, "not_probed")

    def test_a_checkpoint_made_by_another_engine_build_or_configuration_is_not_resumed(self):
        status = self.engine()
        config = cfg(profile_policy="allow_unadmitted")
        saved = self.plan(request(QUERY), config, status)
        provider.resume_compatible(saved, self.plan(request(QUERY), config, status))
        other_build = self.engine(build_id="source-sha256:" + "11" * 32)
        with self.assertRaisesRegex(ValueError, "checkpoint_engine_identity_changed"):
            provider.resume_compatible(saved, self.plan(request(QUERY), config, other_build))
        other_dialect = cfg(profile_policy="allow_unadmitted", dialect="dexsql-0.1.1")
        with self.assertRaisesRegex(ValueError, "checkpoint_engine_identity_changed"):
            provider.resume_compatible(saved, self.plan(request(QUERY), other_dialect, status))
        legacy = self.plan(request(QUERY, backend="dexsql"), config, status)
        with self.assertRaisesRegex(ValueError, "checkpoint_engine_identity_changed"):
            provider.resume_compatible(saved, dict(legacy, provider={"engine": None}))


# ---- failures at run time --------------------------------------------------------------------------------------

class BackendFailures(Case):
    def setUp(self):
        super().setUp()
        self.BackendError = support.frozen_batch(self.dir).BackendError
        self.task = {"id": "q", "backend": ENGINE, "forced": False}
        self.config = fallback_cfg()
        self.audit = provider.AuditLog()
        self.fallback_calls = 0

    def error(self, code, kind="invalid_query"):
        return self.BackendError("backend rejected operation", {"error": {"kind": kind, "code": code, "message": "m"}})

    def run_(self, primary, *, task=None, config=None, negotiation=None, **options):
        def fallback():
            self.fallback_calls += 1
            return {"rows": [["from dexsql"]], "partial": False}
        return provider.run_with_policy(task or self.task, primary, fallback, config=config or self.config,
                                        negotiation=negotiation or {}, audit=self.audit,
                                        source={"sha256": "ab" * 32, "size": 7}, **options)

    def raiser(self, error):
        def primary():
            raise error
        return primary

    def test_a_result_is_returned_as_it_is(self):
        self.assertEqual(self.run_(lambda: {"rows": []}), {"rows": []})
        self.assertEqual((self.fallback_calls, self.audit.records), (0, []))

    def test_each_not_here_error_falls_back_explicitly_and_keeps_the_original_failure(self):
        for code in provider.FALLBACK_ELIGIBLE:
            with self.subTest(code):
                self.fallback_calls, self.audit = 0, provider.AuditLog()
                result = self.run_(self.raiser(self.error(code)))
                self.assertEqual(self.fallback_calls, 1)
                self.assertEqual(result["rows"], [["from dexsql"]])
                self.assertEqual(result["fallback"]["from"], ENGINE)
                self.assertEqual((result["fallback"]["to"], result["fallback"]["code"]), ("dexsql", code))
                self.assertEqual(result["fallback"]["primary_failure"]["origin"], "engine")
                (record,) = self.audit.records
                self.assertEqual(record["decision"]["action"], "fallback")
                self.assertEqual(record["failure"]["code"], code)
                self.assertEqual(record["source"], {"sha256": "ab" * 32, "size": 7})

    def test_every_other_engine_code_fails_with_the_original_exception(self):
        others = [code for code in provider.ENGINE_CODES if code not in provider.FALLBACK_ELIGIBLE]
        self.assertEqual(len(others), 15)
        for code in others:
            with self.subTest(code):
                original = self.error(code)
                with self.assertRaises(self.BackendError) as caught:
                    self.run_(self.raiser(original))
                self.assertIs(caught.exception, original, "the exception itself is kept, not wrapped")
                self.assertEqual(original.detail["error"]["code"], code)
                self.assertEqual(original.provider_evidence["decision"]["action"], "fail")
                self.assertEqual(original.provider_evidence["decision"]["reason"], "error_is_not_a_not_here_error")
                self.assertIn("provider decision", "".join(getattr(original, "__notes__", [])))
        self.assertEqual(self.fallback_calls, 0)

    def test_the_decision_table_covers_every_engine_code(self):
        for code in provider.ENGINE_CODES:
            decision = provider.decide_fallback(self.config, {}, self.task, provider.Failure(code, "engine", "E", ""))
            self.assertEqual(decision.action == "fallback", code in provider.FALLBACK_ELIGIBLE, code)

    def test_the_engine_codes_are_the_ones_the_engine_defines(self):
        source = (ROOT / "crates/mdd-types/src/lib.rs").read_text(encoding="utf-8")
        defined = re.findall(r'Self::\w+ => "([A-Z_]+)"', source)
        self.assertEqual(sorted(defined), sorted(provider.ENGINE_CODES))

    def test_an_error_nobody_classified_is_never_an_empty_result_and_never_a_fallback(self):
        cases = {
            "a plain exception": RuntimeError("boom"),
            "a timeout": TimeoutError("native audit deadline exhausted"),
            "a code nobody knows": self.error("SOMETHING_NEW"),
            "no code at all": self.BackendError("backend rejected operation", {"error": {"kind": "invalid_query"}}),
            "no detail": self.BackendError("backend rejected operation"),
            "a detail that is not an object": self.BackendError("x", "text"),
            "a code of the wrong type": self.BackendError("x", {"error": {"code": ["UNSUPPORTED_QUERY"]}}),
            "a lower-case code": self.error("unsupported_query"),
        }
        for label, original in cases.items():
            with self.subTest(label):
                self.fallback_calls = 0
                with self.assertRaises(type(original)) as caught:
                    result = self.run_(self.raiser(original))
                    self.fail(f"returned {result!r} instead of raising")
                self.assertIs(caught.exception, original)
                self.assertEqual(self.fallback_calls, 0)
        failures = {r["failure"]["code"] for r in self.audit.records}
        self.assertEqual(failures, {"UNCLASSIFIED", "UNKNOWN_ENGINE_CODE"})

    def test_a_group_of_failures_is_a_fallback_only_if_they_are_all_the_same_not_here_error(self):
        same = ExceptionGroup("g", [self.error("UNSUPPORTED_QUERY"), self.error("UNSUPPORTED_QUERY")])
        self.assertEqual(self.run_(self.raiser(same))["fallback"]["code"], "UNSUPPORTED_QUERY")
        mixed = ExceptionGroup("g", [self.error("UNSUPPORTED_QUERY"), self.error("INTERNAL_FAULT")])
        with self.assertRaises(ExceptionGroup):
            self.run_(self.raiser(mixed))
        hidden = ExceptionGroup("g", [self.error("UNSUPPORTED_QUERY"), RuntimeError("something else")])
        with self.assertRaises(ExceptionGroup):
            self.run_(self.raiser(hidden))
        self.assertEqual(self.fallback_calls, 1)

    def test_a_forced_task_a_forbidding_request_and_a_missing_configuration_never_fall_back(self):
        error = self.error("UNSUPPORTED_QUERY")
        for label, kwargs, reason in (
            ("forced", {"task": dict(self.task, forced=True)}, "forced_backend_never_falls_back"),
            ("forbidden", {"negotiation": {"fallback": "forbid"}}, "fallback_forbidden_by_request"),
            ("not configured", {"config": cfg(profile_policy="allow_unadmitted")}, "fallback_not_configured"),
            ("code not enabled", {"config": fallback_cfg(on=("UNAVAILABLE_BACKEND",))}, "error_not_enabled_for_fallback"),
            ("not on the engine", {"task": dict(self.task, backend="dexsql")}, "task_not_on_engine"),
            ("target missing", {"dexsql_available": False}, "fallback_target_unavailable"),
        ):
            with self.subTest(label):
                with self.assertRaises(self.BackendError):
                    self.run_(self.raiser(error), **kwargs)
                self.assertEqual(self.audit.records[-1]["decision"]["reason"], reason)
        self.assertEqual(self.fallback_calls, 0)

    def test_a_task_that_already_has_rows_is_not_finished_by_another_backend(self):
        with self.assertRaises(self.BackendError):
            self.run_(self.raiser(self.error("UNSUPPORTED_QUERY")), admitted_rows=lambda: 3)
        self.assertEqual(self.audit.records[-1]["decision"]["reason"], "a_partial_result_was_already_admitted")
        self.assertEqual(self.fallback_calls, 0)

    def test_cancellation_and_interrupts_pass_through_untouched(self):
        for signal in (KeyboardInterrupt(), SystemExit(1), GeneratorExit()):
            with self.subTest(type(signal).__name__), self.assertRaises(type(signal)):
                self.run_(self.raiser(signal))
        self.assertEqual((self.fallback_calls, self.audit.records), (0, []))

    def test_a_fallback_that_fails_too_raises_its_own_error_and_both_are_recorded(self):
        def failing_fallback():
            raise self.error("INTERNAL_FAULT")
        with self.assertRaises(self.BackendError) as caught:
            provider.run_with_policy(self.task, self.raiser(self.error("UNSUPPORTED_QUERY")), failing_fallback,
                                     config=self.config, negotiation={}, audit=self.audit)
        self.assertEqual(caught.exception.provider_evidence["primary_failure"]["code"], "UNSUPPORTED_QUERY")
        self.assertEqual([("decision" in r, "fallback_failed" in r) for r in self.audit.records],
                         [(True, False), (False, True)])

    def test_a_result_that_already_carries_fallback_evidence_is_refused(self):
        with self.assertRaises(provider.ProviderError):
            provider.run_with_policy(self.task, self.raiser(self.error("UNSUPPORTED_QUERY")),
                                     lambda: {"rows": [], "fallback": {"from": "x"}}, config=self.config,
                                     negotiation={}, audit=self.audit)

    def test_an_engine_that_became_unusable_between_plan_and_launch_is_the_same_kind_of_failure(self):
        self.engine()
        config = fallback_cfg(manifest=str(self.manifest))
        self.binary.write_bytes(b"swapped after planning")
        state = self.dir / "state"

        def start():
            with mock.patch.dict(os.environ, {installer.ENV_BINARY: str(self.binary)}):
                return provider.launch(config, threads=1, timeout_seconds=10, state=state, runner=self.fake)

        result = self.run_(start, config=config)
        self.assertEqual(result["fallback"]["code"], "UNAVAILABLE_BACKEND")
        self.assertEqual(result["fallback"]["primary_failure"]["origin"], "adapter")
        with self.assertRaises(installer.EngineUnavailable):
            self.run_(start, config=config, task=dict(self.task, forced=True))
        self.assertFalse((state / provider.MDD_ROOT).exists(), "nothing is created for an engine that is not started")

    def test_coverage_maps_to_complete_only_when_everything_is_complete(self):
        ok = provider.completeness("ok", "complete", "complete", True)
        self.assertEqual(ok, {"complete": True, "partial": False, "failed": False, "reasons": []})
        for status, inp, facts, done in itertools.product(("ok", "error", "cancelled"), ("complete", "partial", "unknown"),
                                                          ("complete", "partial", "unknown"), (True, False)):
            result = provider.completeness(status, inp, facts, done)
            self.assertEqual(result["complete"], (status, inp, facts, done) == ("ok", "complete", "complete", True))
            self.assertEqual(result["failed"], status != "ok")
            self.assertFalse(result["complete"] and result["partial"])
        self.assertTrue(provider.completeness("ok", "unknown", "complete", True)["partial"])
        for bad in (("done", "complete", "complete", True), ("ok", "full", "complete", True),
                    ("ok", "complete", "complete", 1), ("ok", "complete", None, True)):
            with self.assertRaises(provider.ProviderError):
                provider.completeness(*bad)


# ---- reports ----------------------------------------------------------------------------------------------------------

class Reports(Case):
    def setUp(self):
        super().setUp()
        self.status = self.engine()
        self.config = cfg(profile_policy="allow_unadmitted")
        self.plan_ = self.plan(request(QUERY, LOCATE), self.config, self.status)
        self.legacy_versions = {"sqlite": "legacy-schema-1", "dexsql": {"available": True, "version": "0.1.0",
                                                                         "sha256": "f354ebcf" + "0" * 56}}

    def report(self):
        return {"schema": 1, "plan": self.plan_, "tasks": [{"id": "q", "backend": ENGINE, "status": "complete"}],
                "complete": True, "backend_versions": json.loads(json.dumps(self.legacy_versions))}

    def test_the_report_records_the_engine_version_digest_profile_dialect_and_configuration(self):
        run = provider.run_identity(self.plan_, self.config, {"sha256": "ab" * 32})
        report = provider.annotate_report(self.report(), self.plan_, run)
        provider.check_report(report)
        identity = report["backend_versions"][ENGINE]
        self.assertEqual(identity["engine_version"], "0.1.0-test")
        self.assertEqual(identity["binary_sha256"], installer.sha256(self.binary))
        self.assertEqual(identity["profile"]["name"], "mdd-native-v1")
        self.assertEqual(identity["dialect"]["engine"], "dexsql-0.1.0")
        self.assertEqual(identity["config_digest"], self.config.digest())
        self.assertEqual(report["backend_versions"]["dexsql"], self.legacy_versions["dexsql"], "DexSQL's entry is untouched")
        self.assertEqual(report["backend_versions"]["sqlite"], "legacy-schema-1")
        self.assertEqual(report["provider"]["run"], run)

    def test_a_report_that_used_the_engine_without_saying_so_is_refused(self):
        report = self.report()
        with self.assertRaisesRegex(provider.ProviderError, "must record its engine version"):
            provider.check_report(report)
        annotated = provider.annotate_report(self.report(), self.plan_)
        with self.assertRaisesRegex(provider.ProviderError, "run identity"):
            provider.check_report(annotated)
        tampered = provider.annotate_report(self.report(), self.plan_, {"id": "x"})
        del tampered["backend_versions"][ENGINE]["build_id"]
        with self.assertRaises(provider.ProviderError):
            provider.check_report(tampered)

    def test_the_new_engine_is_never_reported_as_dexsql(self):
        report = provider.annotate_report(self.report(), self.plan_, {"id": "x"})
        report["backend_versions"]["dexsql"] = dict(report["backend_versions"][ENGINE])
        with self.assertRaisesRegex(provider.ProviderError, "must describe DexSQL"):
            provider.check_report(report)
        again = provider.annotate_report(self.report(), self.plan_, {"id": "x"})
        with self.assertRaises(provider.ProviderError):
            provider.annotate_report(again, self.plan_, {"id": "x"})

    def test_a_report_of_a_legacy_run_is_not_touched(self):
        legacy_plan = LEGACY.plan(request(QUERY, backend="dexsql"))
        report = {"schema": 1, "plan": legacy_plan, "tasks": [], "backend_versions": json.loads(json.dumps(self.legacy_versions))}
        before = json.dumps(report, sort_keys=True)
        self.assertIs(provider.annotate_report(report, legacy_plan), report)
        provider.check_report(report)
        self.assertEqual(json.dumps(report, sort_keys=True), before)

    def test_the_run_identity_follows_engine_profile_dialect_configuration_request_and_source(self):
        base = provider.run_identity(self.plan_, self.config, {"sha256": "ab" * 32})
        self.assertEqual(base, provider.run_identity(self.plan_, self.config, {"sha256": "ab" * 32}))
        self.assertEqual(len(base["id"]), 32)
        variants = {
            "source": provider.run_identity(self.plan_, self.config, {"sha256": "cd" * 32}),
            "no source": provider.run_identity(self.plan_, self.config),
            "configuration": provider.run_identity(self.plan(request(QUERY, LOCATE), cfg(
                profile_policy="allow_unadmitted", max_datasets=2), self.status), cfg(
                profile_policy="allow_unadmitted", max_datasets=2), {"sha256": "ab" * 32}),
            "dialect": provider.run_identity(self.plan(request(QUERY, LOCATE), cfg(
                profile_policy="allow_unadmitted", dialect="dexsql-0.1.1"), self.status), cfg(
                profile_policy="allow_unadmitted", dialect="dexsql-0.1.1"), {"sha256": "ab" * 32}),
            "request": provider.run_identity(self.plan(request(QUERY), self.config, self.status), self.config,
                                             {"sha256": "ab" * 32}),
            "engine build": provider.run_identity(
                self.plan(request(QUERY, LOCATE), self.config, self.engine(build_id="source-sha256:" + "22" * 32)),
                self.config, {"sha256": "ab" * 32}),
        }
        for label, other in variants.items():
            self.assertNotEqual(other["id"], base["id"], label)
        with self.assertRaises(provider.ProviderError):
            provider.run_identity(LEGACY.plan(request(QUERY, backend="dexsql")), self.config)


# ---- namespaces, rollback ----------------------------------------------------------------------------------------------

def tree(path):
    """name -> bytes of every file below path, to show that nothing there changed."""
    return {str(p.relative_to(path)): p.read_bytes() for p in sorted(Path(path).rglob("*")) if p.is_file()}


class Namespaces(Case):
    def setUp(self):
        super().setUp()
        self.status = self.engine()
        self.config = cfg(profile_policy="allow_unadmitted", manifest=str(self.manifest))
        self.identity = provider.engine_identity(self.status, self.config)
        self.state = self.dir / "state"
        for relative, content in {"dexq-cache/abcd.sqlite": b"legacy index", "reports/1/aa/20261101/report.json": b"old report",
                                  "analysis-schedule/done.json": b"completion", "remote-requests/r.json": b"journal",
                                  "samples/ab/base.apk": b"apk"}.items():
            (self.state / relative).parent.mkdir(parents=True, exist_ok=True)
            (self.state / relative).write_bytes(content)
        self.legacy_before = tree(self.state)

    def test_the_engine_has_its_own_cache_reports_and_completion_directories(self):
        ns = provider.namespaces(self.state, self.identity, self.config, {})
        eng = provider.engine_dir(self.identity)
        self.assertEqual(ns["cache"], self.state.resolve() / "mdd-engine" / "cache" / eng)
        for name, path in ns.items():
            for legacy in provider.legacy_paths(self.state.resolve(), {}).values():
                self.assertFalse(provider._related(path, legacy), f"{name} {path} overlaps {legacy}")

    def test_another_engine_build_gets_another_directory(self):
        other = provider.engine_identity(self.engine(build_id="source-sha256:" + "33" * 32), self.config)
        self.assertNotEqual(provider.engine_dir(other), provider.engine_dir(self.identity))
        self.assertNotEqual(provider.namespaces(self.state, other, self.config, {})["cache"],
                            provider.namespaces(self.state, self.identity, self.config, {})["cache"])

    def test_a_cache_directory_that_would_share_space_with_dexsql_or_hostlab_is_refused(self):
        for label, value in {"the old query cache": "dexq-cache", "inside it": "dexq-cache/new", "the reports": "reports",
                             "inside the reports": "reports/1", "the state itself": ".", "the schedule": "analysis-schedule",
                             "a parent of the old cache": str(self.state.resolve().parent)}.items():
            with self.subTest(label), self.assertRaises(provider.NamespaceCollision):
                provider.namespaces(self.state, self.identity, cfg(profile_policy="allow_unadmitted", cache_dir=value), {})
        elsewhere = provider.namespaces(self.state, self.identity,
                                        cfg(profile_policy="allow_unadmitted", cache_dir=str(self.dir / "elsewhere")), {})
        self.assertEqual(elsewhere["cache"].parent, (self.dir / "elsewhere").resolve())

    def test_the_cache_variable_of_dexsql_is_respected_as_a_legacy_path(self):
        env = {"DEXQ_CACHE_DIR": str(self.state / "mdd-engine" / "cache")}
        with self.assertRaises(provider.NamespaceCollision):
            provider.namespaces(self.state, self.identity, self.config, env)

    def test_the_child_environment_has_the_engines_cache_and_none_of_dexsqls(self):
        ns = provider.namespaces(self.state, self.identity, self.config, {})
        ambient = {"PATH": os.environ.get("PATH", ""), "DEXQ_CACHE_DIR": str(self.state / "dexq-cache"),
                   "DEXQ_ROOTS": "/samples", "DEXQ_WORKERS": "4", "MDD_CACHE_DIR": "/somewhere/else",
                   "GITHUB_TOKEN": "t", "MY_PASSWORD": "p", "SERVICE_API_KEY": "k", "CLIENT_SECRET": "s"}
        env = provider.child_environment(99, ns["cache"], ambient)
        self.assertEqual(env["MDD_CACHE_DIR"], str(ns["cache"]))
        self.assertEqual(env["MDD_FACTS_THREADS"], str(min(99, os.cpu_count() or 1)))
        self.assertEqual(sorted(k for k in env if k.startswith("DEXQ_") or re.search("TOKEN|SECRET|PASSWORD|API_KEY", k)), [])
        self.assertEqual(env["PATH"], ambient["PATH"])

    def test_the_engine_is_started_the_way_its_mcp_command_takes_options(self):
        args = provider.mcp_arguments(self.config, 180)
        self.assertEqual(args, ["mcp", "--dialect", "dexsql-0.1.0", "--timeout-ms", "180000", "--max-datasets", "1"])
        self.assertNotIn("--threads", args, "the engine has no global --threads; DexSQL's argument list is not reused")

    def test_launch_verifies_the_engine_again_and_claims_only_its_own_directories(self):
        with mock.patch.dict(os.environ, {installer.ENV_BINARY: str(self.binary)}):
            launched = provider.launch(self.config, threads=2, timeout_seconds=30, state=self.state, runner=self.fake,
                                       environ={"PATH": "x", "MDD_CACHE_DIR": "/not/this"})
        self.assertEqual(launched.command, str(self.binary.resolve()))
        self.assertEqual(launched.args[0], "mcp")
        self.assertEqual(launched.env["MDD_CACHE_DIR"], str(launched.namespaces["cache"]))
        self.assertEqual(launched.identity["binary_sha256"], installer.sha256(self.binary))
        for name in ("cache", "reports", "completion"):
            marker = json.loads((launched.namespaces[name] / "NAMESPACE.json").read_text(encoding="utf-8"))
            self.assertEqual(marker["build_id"], support.BUILD_ID)
        self.assertEqual({k: v for k, v in tree(self.state).items() if not k.startswith("mdd-engine")}, self.legacy_before)

    def test_a_directory_claimed_by_another_build_is_not_taken_over(self):
        ns = provider.namespaces(self.state, self.identity, self.config, {})
        provider.ensure_namespaces(ns, self.identity)
        provider.ensure_namespaces(ns, self.identity)  # idempotent for the same build
        (ns["cache"] / "NAMESPACE.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(provider.NamespaceCollision):
            provider.ensure_namespaces(ns, self.identity)

    def test_publishing_never_overwrites_and_never_leaves_the_namespace(self):
        root = self.dir / "reports-root"
        first = provider.publish(root, "a/b/report.json", {"k": 1})
        before = first.read_bytes()
        with self.assertRaises(provider.NamespaceCollision):
            provider.publish(root, "a/b/report.json", {"k": 2})
        self.assertEqual(first.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in first.parent.iterdir()), ["report.json"], "no staging file is left")
        for bad in ("../x.json", "a/../../x.json", "/abs.json", "", "."):
            with self.subTest(bad), self.assertRaises(provider.NamespaceCollision):
                provider.publish(root, bad, b"x")
        self.assertFalse((self.dir / "x.json").exists())

    def test_publishing_without_hard_links_is_still_exclusive(self):
        root = self.dir / "no-links"
        with mock.patch.object(os, "link", side_effect=OSError(1, "not supported")):
            path = provider.publish(root, "r.json", b"one")
            with self.assertRaises(provider.NamespaceCollision):
                provider.publish(root, "r.json", b"two")
        self.assertEqual(path.read_bytes(), b"one")

    def test_rolling_back_keeps_new_results_under_their_identity_and_touches_nothing_old(self):
        # 1. a run on the new engine publishes a report and uses its cache
        with mock.patch.dict(os.environ, {installer.ENV_BINARY: str(self.binary)}):
            launched = provider.launch(self.config, threads=1, timeout_seconds=30, state=self.state, runner=self.fake)
        plan_ = self.plan(request(QUERY), self.config, self.status)
        run = provider.run_identity(plan_, self.config, {"sha256": "ab" * 32})
        report = provider.annotate_report({"schema": 1, "plan": plan_, "tasks": [{"id": "q", "backend": ENGINE}],
                                           "backend_versions": {"sqlite": "legacy-schema-1"}}, plan_, run, launched.namespaces)
        provider.check_report(report)
        published = provider.publish(launched.namespaces["reports"], f"{run['id']}/report.json", report)
        (launched.namespaces["cache"] / "entry.bin").write_bytes(b"engine cache")
        provider.publish(launched.namespaces["completion"], f"{run['id']}.json", {"complete": True})
        mine = tree(self.state / "mdd-engine")
        # 2. the one setting goes back to the original backend
        rolled_back = cfg("dexsql", profile_policy="allow_unadmitted", manifest=str(self.manifest))
        same_request = request(QUERY, LOCATE, DECODE)
        self.assertEqual(provider.plan(same_request, rolled_back, legacy=LEGACY, engine_status=self.status),
                         LEGACY.plan(same_request), "the original backend plans as it always did")
        with self.assertRaises(provider.ProviderDisabled):
            self.plan(request(QUERY, backend=ENGINE), rolled_back, self.status)
        # 3. nothing was deleted, nothing old was touched, and the new report still says what made it
        self.assertEqual(tree(self.state / "mdd-engine"), mine)
        self.assertEqual({k: v for k, v in tree(self.state).items() if not k.startswith("mdd-engine")}, self.legacy_before)
        saved = json.loads(published.read_text(encoding="utf-8"))
        self.assertEqual(saved["backend_versions"][ENGINE]["build_id"], support.BUILD_ID)
        self.assertEqual(saved["provider"]["run"]["id"], run["id"])
        self.assertNotIn(str(published.relative_to(self.state)), tree(self.state / "reports"), "not among the old reports")
        self.assertFalse(any("mdd-engine" in key for key in tree(self.state / "reports")))
        # 4. going forward again finds the same directories, and the old report cannot be overwritten
        again = provider.namespaces(self.state, self.identity, self.config, {})
        provider.ensure_namespaces(again, self.identity)
        with self.assertRaises(provider.NamespaceCollision):
            provider.publish(again["reports"], f"{run['id']}/report.json", {"overwritten": True})


# ---- the gates that stay in force ----------------------------------------------------------------------------------------

def build_zip(path, names, payload=b"dex\n035\x00"):
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            with warnings_ignored():
                archive.writestr(name, payload)
    return path


class warnings_ignored:
    def __enter__(self):
        import warnings
        self.context = warnings.catch_warnings()
        self.context.__enter__()
        warnings.simplefilter("ignore")

    def __exit__(self, *exc):
        return self.context.__exit__(*exc)


class Gates(Case):
    def setUp(self):
        super().setUp()
        self.batch = support.frozen_batch(self.dir)
        self.samples = self.dir / "samples"
        self.samples.mkdir()

    def same_outcome(self, ours, theirs):
        def run(call):
            try:
                return ("value", call())
            except Exception as error:  # the two implementations must refuse alike
                return ("refused", type(error).__name__ if isinstance(error, (ValueError, OSError)) else "other", str(error))
        a, b = run(ours), run(theirs)
        self.assertEqual(a, b)
        return a

    def test_the_input_gate_equals_hostlabs_for_files_inside_outside_and_of_the_wrong_kind(self):
        inside = build_zip(self.samples / "a.apk", ["classes.dex"])
        text = self.samples / "a.txt"
        text.write_text("x")
        outside = build_zip(self.dir / "outside.apk", ["classes.dex"])
        directory = self.samples / "folder.apk"
        directory.mkdir()
        roots = [self.samples]
        for apk in (inside, text, outside, directory, self.samples / "absent.apk"):
            with self.subTest(apk=apk.name):
                self.same_outcome(lambda: provider.controlled_input(apk, roots), lambda: self.batch.controlled_input(apk, roots))
        self.assertEqual(provider.controlled_input(inside, roots), inside.resolve())
        with self.assertRaisesRegex(ValueError, "outside the allowed roots"):
            provider.controlled_input(outside, roots)
        with self.assertRaisesRegex(ValueError, "must be an APK/DEX/ZIP/JAR"):
            provider.controlled_input(text, roots)
        with self.assertRaises(OSError):
            provider.controlled_input(self.samples / "absent.apk", roots)
        with self.assertRaises(OSError):
            provider.controlled_input(inside, [self.dir / "no-such-root"])

    def test_the_physical_dex_inventory_equals_hostlabs(self):
        fixtures = {p.name: p for p in (ROOT / "tests/fixtures/generated").glob("*.apk")}
        fixtures.update({"small.apk": ROOT / "tests/fixtures/decode/generated/manifest-small.apk",
                         "one.dex": ROOT / "tests/fixtures/decode/generated/decode-all.dex"})
        fixtures["nodex.apk"] = build_zip(self.samples / "nodex.apk", ["AndroidManifest.xml", "assets/classes.dex"])
        fixtures["dup.apk"] = build_zip(self.samples / "dup.apk", ["classes.dex", "classes.dex"])
        fixtures["multi.apk"] = build_zip(self.samples / "multi.apk", ["classes.dex", "classes2.dex", "classes10.dex", "x.txt"])
        self.assertGreaterEqual(len(fixtures), 8)
        outcomes = {}
        for name, path in sorted(fixtures.items()):
            with self.subTest(name):
                outcomes[name] = self.same_outcome(lambda: provider.archive_inventory(path), lambda: self.batch.archive_inventory(path))
        self.assertEqual(outcomes["multi.apk"], ("value", {"classes.dex", "classes2.dex", "classes10.dex"}))
        self.assertEqual(outcomes["one.dex"], ("value", None))
        self.assertEqual(outcomes["nodex.apk"][0], "refused")
        self.assertEqual(outcomes["dup.apk"][0], "refused")

    def test_a_backend_that_loaded_fewer_or_other_dex_files_than_the_archive_has_is_refused_alike(self):
        cases = [({"classes.dex", "classes2.dex"}, {0: "classes.dex", 1: "classes2.dex"}),
                 ({"classes.dex", "classes2.dex"}, {0: "classes.dex"}),
                 ({"classes.dex"}, {0: "classes.dex", 1: "classes2.dex"}),
                 ({"classes.dex"}, {0: "classes.dex#2", 1: "classes.dex#3"}),     # logical DEX of one member
                 ({"classes.dex", "classes2.dex"}, {0: "classes.dex#2", 1: "classes.dex"}),
                 (None, {0: "anything"})]
        for expected, files in cases:
            with self.subTest(expected=expected, files=files):
                def ours():
                    provider.verify_inventory(expected, files)
                def theirs():
                    self.batch.verify_inventory(expected, files)
                try:
                    theirs()
                except self.batch.BackendError as error:
                    with self.assertRaises(provider.InventoryError) as caught:
                        ours()
                    self.assertEqual((str(caught.exception), caught.exception.detail), (str(error), error.detail))
                else:
                    ours()

    def test_a_bad_source_sha_or_a_changed_source_leaves_a_report_incomplete(self):
        apk = build_zip(self.samples / "s.apk", ["classes.dex"])
        sha = provider.file_sha256(apk)
        stat = (apk.stat().st_size, apk.stat().st_mtime_ns)
        for label, sample, expect in (("named and unchanged", {"sha256": sha}, True), ("no sample", None, True),
                                      ("another sha", {"sha256": "00" * 32}, False)):
            with self.subTest(label):
                sealed = provider.seal_report({"complete": True}, apk, stat, sample)
                self.assertEqual((sealed["source_unchanged"], sealed["complete"]), (expect, expect))
        sealed = provider.seal_report({"complete": False}, apk, stat, {"sha256": sha})
        self.assertEqual((sealed["source_unchanged"], sealed["complete"]), (True, False), "sealing never completes a report")
        apk.write_bytes(apk.read_bytes()[:-1] + b"\x01")
        os.utime(apk, ns=(stat[1] + 10, stat[1] + 10))
        changed = provider.seal_report({"complete": True}, apk, stat, {"sha256": sha})
        self.assertEqual((changed["source_unchanged"], changed["complete"]), (False, False))
        apk.unlink()
        gone = provider.seal_report({"complete": True}, apk, stat, {"sha256": sha})
        self.assertEqual((gone["source_unchanged"], gone["complete"], gone["source_error"]), (False, False, "FileNotFoundError"))

    def test_the_source_identity_is_recorded_without_a_path(self):
        apk = build_zip(self.samples / "s.apk", ["classes.dex"])
        identity = provider.source_identity(apk, {"sha256": "ab" * 32})
        self.assertEqual(set(identity), {"name", "sha256", "size", "mtime_ns"})
        self.assertNotIn(str(self.samples), json.dumps(identity))

    def test_the_credential_stripping_equals_hostlabs_apart_from_the_variables_it_replaces(self):
        ambient = {"PATH": "p", "A_TOKEN": "1", "db_password": "2", "SOME_SECRET_X": "3", "KEY_API_KEY": "4", "KEEP": "5"}
        apk = self.samples / "a.apk"
        with mock.patch.dict(os.environ, ambient, clear=True):
            theirs = self.batch.child_environment(apk, 2)
        ours = provider.child_environment(2, self.dir / "cache", ambient)
        self.assertEqual({k for k in theirs if k.startswith(("DEXQ_",))}, {"DEXQ_ROOTS", "DEXQ_CACHE_DIR", "DEXQ_WORKERS"})
        shared = {k: v for k, v in theirs.items() if not k.startswith("DEXQ_")}
        self.assertEqual({k: v for k, v in ours.items() if k in shared}, shared)
        self.assertEqual(set(ours) - set(shared), {"MDD_CACHE_DIR", "MDD_FACTS_THREADS"})

    def test_remote_source_snapshot_rules_are_not_part_of_what_the_provider_reads_or_writes(self):
        # `resume` is passed to the planner untouched; the provider adds no field that would reach a dispatch.
        resume = {"run_id": 1, "attempt": 1, "request_id": "a" * 32}
        self.assertEqual(provider.plan(request(QUERY, backend="dexsql", resume=resume), PLAIN, legacy=LEGACY),
                         LEGACY.plan(request(QUERY, backend="dexsql", resume=resume)))
        source = Path(provider.__file__).read_text(encoding="utf-8")
        for word in ("module_source", "source_mode", "snapshot_transport", "workflow_dispatch"):
            self.assertNotIn(word, source)


if __name__ == "__main__":
    unittest.main()
