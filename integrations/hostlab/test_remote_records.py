"""The MDD-053 records: conformance/hostlab/remote-contracts.json and artifacts/mdd-053/remote-and-resume-equivalence.json.

Run: python -I -m unittest discover -s integrations/hostlab -p "test_remote_records.py"
The generator (remote_make_records.py) runs the adapters and the frozen HostLab code; these tests check that the committed files
are what it produces, that what they say agrees with sources the generator did not read, and that the generator itself refuses to
write a record whose controls fail. Not part of the mutation check: any change to an adapter changes the hashed inputs on purpose.
"""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import checkpoint_adapter as ca  # noqa: E402
import hostlab_test_support as support  # noqa: E402
import provider  # noqa: E402
import remote_make_records as records  # noqa: E402
import remote_runner_adapter as remote  # noqa: E402

ROOT = support.ROOT
CONTRACTS = ROOT / "conformance/hostlab/remote-contracts.json"
EQUIVALENCE = ROOT / "artifacts/mdd-053/remote-and-resume-equivalence.json"
TOOLS_AND_OPTIONS = json.loads((ROOT / "conformance/manifests/tools-and-options.json").read_text(encoding="utf-8"))


class Committed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contracts_text, cls.equivalence_text = records.build_all()
        cls.contracts = json.loads(CONTRACTS.read_text(encoding="utf-8"))
        cls.equivalence = json.loads(EQUIVALENCE.read_text(encoding="utf-8"))

    def test_the_committed_records_are_what_the_generator_produces(self):
        self.assertEqual(CONTRACTS.read_text(encoding="utf-8"), self.contracts_text)
        self.assertEqual(EQUIVALENCE.read_text(encoding="utf-8"), self.equivalence_text)
        self.assertEqual(records.main(["--check"]), 0)

    def test_the_generator_is_deterministic(self):
        again = records.build_all()
        self.assertEqual(again, (self.contracts_text, self.equivalence_text))

    def test_every_input_is_named_with_its_hash_and_the_hash_is_current(self):
        for document, listed in ((self.contracts, self.contracts["inputs"]), (self.equivalence, self.equivalence["inputs"]["files"])):
            self.assertEqual([i["path"] for i in listed], records.INPUTS)
            for item in listed:
                data = (ROOT / item["path"]).read_bytes()
                self.assertEqual((item["sha256"], item["bytes"]), (hashlib.sha256(data).hexdigest(), len(data)), item["path"])
        self.assertEqual(self.equivalence["remote_contract"]["sha256"], hashlib.sha256(CONTRACTS.read_bytes()).hexdigest())

    def test_the_contract_is_read_from_the_frozen_source_and_agrees_with_the_earlier_inventory(self):
        manifest = json.loads((ROOT / "conformance/corpus/hostlab/source-8782f43/manifest.json").read_text(encoding="utf-8"))
        frozen = next(f for f in manifest["files"] if f.get("path", "").endswith("/remote_mcp.py"))
        source = self.contracts["source"]
        self.assertEqual((source["sha256"], source["commit"], source["path"]),
                         (frozen["sha256"], manifest["commit"], frozen["path"]))
        tools = self.contracts["tools"]
        self.assertEqual([t["name"] for t in tools], list(remote.REMOTE_TOOLS))
        self.assertEqual(len(tools), 12)
        for tool, earlier in zip(tools, TOOLS_AND_OPTIONS["remote_orchestration"]):
            self.assertEqual(tool["signature"], earlier["signature"], tool["name"])
            self.assertEqual(tool["lines"], [earlier["line"], earlier["end_line"]], tool["name"])
            self.assertTrue(tool["signature_matches_mdd003_extraction"] and tool["docstring_matches_mdd003_extraction"])
            self.assertTrue(all(tool["documented_limits"].values()), tool["name"])
        by_name = {t["name"]: t for t in tools}
        self.assertEqual(by_name["version_matrix_status"]["forwards"][0]["kwargs"]["dispatch"], "False")
        self.assertEqual(by_name["submit_analysis"]["forwards"][0]["kwargs"]["apk_sha256"], "apk_sha256")
        self.assertEqual(by_name["submit_analysis"]["forwards"][0]["kwargs"]["sample_revision"], "sample_revision")
        self.assertEqual(by_name["job_result"]["forwards"][0]["call"], "remote_artifacts.get")
        self.assertEqual([c["call"] for c in by_name["submit_job"]["forwards"]], ["snapshot_transport.prepare", "remote_dispatch.dispatch"])
        self.assertEqual(by_name["plan_analysis"]["forwards"][0]["call"], "remote_schedule.describe")
        for name in remote.NON_DISPATCHING_TOOLS:
            self.assertEqual(by_name[name]["dispatch_class"], "non_dispatching")
        self.assertEqual(self.contracts["server"]["name"], "hostlab-remote")
        self.assertEqual(self.contracts["server"]["transport"], "stdio")

    def test_the_orchestration_tools_are_not_the_engines_or_dexqs(self):
        part = self.contracts["not_engine_tools"]
        self.assertEqual(part["orchestration_vs_engine_overlap"], [])
        self.assertEqual(part["orchestration_vs_dexq_overlap"], [])
        self.assertIn("query", part["engine_vs_dexq_overlap"])
        self.assertEqual(part["remote_orchestration"], list(remote.REMOTE_TOOLS))
        self.assertEqual(part["engine_native_mcp"], list(remote.ENGINE_NATIVE_TOOLS))
        self.assertEqual(part["legacy_dexq"], list(remote.LEGACY_DEXQ_TOOLS))
        self.assertLessEqual(set(part["engine_tools_served_today"]), set(part["engine_native_mcp"]))
        self.assertEqual(part["submit_job_operations"], list(remote.SUBMIT_JOB_OPERATIONS))

    def test_what_the_gateway_answers_and_refuses_is_recorded_as_run(self):
        keys = self.contracts["responses_keys"]
        self.assertIn("run_attempt", keys["job_status_known_run"])
        self.assertEqual(keys["job_status_no_run_yet"], ["lookup_elapsed_ms", "request_id", "status"])
        self.assertEqual(keys["job_result.collection"], ["artifact", "cache_hit", "elapsed_ms", "integrity", "run_attempt"])
        self.assertTrue(keys["plan_analysis_passthrough"] and keys["submit_analysis_passthrough"])
        checks = self.contracts["argument_checks"]
        outcomes = {json.dumps(p["arguments"], sort_keys=True): p["outcome"] for p in checks["job_result"]}
        self.assertEqual(outcomes["{}"], "accepted")
        self.assertEqual(outcomes['{"page_chars": 1023}'], "ToolError: page_chars must be 1024..128000")
        self.assertEqual(outcomes['{"sample_index": 0}'], "ToolError: sample_index applies only to grouped jobs")
        self.assertTrue(outcomes['{"result_file": "../result.txt"}'].startswith("ToolError: result_file must be a returned text file path"))
        def submit(**arguments):
            return next(p["outcome"] for p in checks["submit_job"] if p["arguments"] == arguments)

        self.assertEqual(submit(version_code=1, operation="info"), "accepted")
        self.assertEqual(submit(version_code=1, operation="plan_analysis"), "ToolError: Invalid bounded operation parameters")
        self.assertEqual(submit(version_code=1, operation="multipath_audit", source_mode="historical"),
                         "ToolError: New analysis cannot silently use historical source")
        self.assertEqual(submit(version_code=1, operation="query", max_cell_chars=16001),
                         "ToolError: max_cell_chars must be 1..16000 and only varies for query")
        self.assertEqual(checks["bad_request_id"], "ToolError: Invalid request ID")

    def test_the_binding_facts_are_checked_against_the_source_text(self):
        binding = self.contracts["run_attempt_and_artifact_binding"]
        self.assertTrue(binding["lookup_title_found_in_source"] and binding["artifact_call_found_in_source"])
        self.assertEqual(binding["run_keys_required_for_a_stored_matrix_run"], ["display_title", "head_sha", "run_attempt"])
        self.assertEqual(binding["artifact_limits"], remote.ARTIFACT_LIMITS)
        self.assertTrue(self.contracts["source_sha_binding"]["passed_on_found_in_source"])

    def test_the_worker_task_contract_says_what_the_frozen_planner_does(self):
        contract = self.contracts["worker_task_contract"]
        self.assertEqual(contract["limits"]["max_tasks"], 16)
        self.assertEqual(contract["limits"]["max_request_bytes"], 30000)
        self.assertEqual(contract["limits"]["backends"], ["auto", "dexsql", "sqlite"])  # the engine is not a frozen backend
        probes = {p["name"]: p["outcome"] for p in contract["probes"]}
        self.assertEqual(probes["backend meguvizdexdash (not a frozen backend)"], "ValueError: unsupported backend")
        self.assertEqual(probes["negotiation block (provider-only)"], "ValueError: unsupported analysis request fields")
        self.assertEqual(probes["resume with run, attempt and request"], "accepted")
        self.assertTrue(contract["fingerprint_covers_resume"])
        self.assertEqual(contract["continuation_requires"]["no ORDER BY"], "query_requires_stable_outer_order")
        self.assertEqual(contract["continuation_requires"]["volatile random()"], "query_volatile_order_or_values")
        self.assertIsNone(contract["continuation_requires"]["outer ORDER BY"])

    def test_the_path_scopes_stay_hostlabs_and_the_modules_that_are_not_here_are_listed(self):
        scopes = self.contracts["path_scopes"]
        for name in ("samples", "reports", "source-snapshots", "artifact-cache"):
            self.assertIn(name, scopes)
        self.assertEqual({n: s["adapter_access"] for n, s in scopes.items() if s["adapter_access"] != "none"}, {"samples": "read"})
        self.assertEqual(set(scopes), set(provider.LEGACY_NAMES))
        missing = self.contracts["not_in_the_frozen_copy"]
        names = {m["module"] for m in missing["modules"]}
        self.assertTrue({"version_matrix", "remote_schedule", "remote_artifacts", "remote_dispatch", "snapshot_transport"} <= names)
        self.assertFalse(any(m["in_frozen_copy"] for m in missing["modules"]))  # none is in the main frozen copy
        extra = {m["module"] for m in missing["modules"] if m["in_frozen_extra_copy"]}
        self.assertTrue({"remote_schedule", "remote_artifacts", "snapshot_transport"} <= extra)
        self.assertFalse({"version_matrix", "remote_dispatch"} & extra)  # these were not obtained
        also = missing["also_not_in_the_main_frozen_copy"]
        self.assertEqual({m["module"] for m in also}, {"analysis_checkpoint", "remote_job", "runner_worker"})
        self.assertTrue(all(m["in_frozen_extra_copy"] for m in also))

    def test_the_frozen_extra_copy_is_hashed_verified_and_shows_what_it_shows(self):
        part = self.contracts["frozen_extra_copy"]
        manifest = json.loads((ROOT / records.EXTRA / "manifest.json").read_text(encoding="utf-8"))
        inventory = json.loads((ROOT / "evidence/hostlab_integration_inventory.json").read_text(encoding="utf-8"))
        listed = {Path(f["path"]).stem: f for f in inventory["reviewed_source_files"]}
        self.assertEqual({m["module"] for m in part["modules"]},
                         {"analysis_checkpoint", "remote_artifacts", "remote_job", "remote_schedule", "runner_worker", "snapshot_transport"})
        by_name = {m["module"]: m for m in part["modules"]}
        for entry in manifest["files"]:
            module = by_name[Path(entry["path"]).stem]
            data = (ROOT / module["path"]).read_bytes()
            self.assertEqual((module["sha256"], module["bytes"]), (hashlib.sha256(data).hexdigest(), len(data)))
            self.assertEqual((module["sha256"], module["bytes"]), (entry["sha256"], entry["bytes"]))
            self.assertEqual((module["sha256"], module["bytes"]), (listed[module["module"]]["sha256"], listed[module["module"]]["bytes"]))
            self.assertTrue(module["matches_inventory"])
        limits = part["remote_artifacts_limits"]
        self.assertTrue(all(limits["equals_adapter_ARTIFACT_LIMITS"].values()))
        self.assertEqual(limits["frozen_constants"]["MAX_ARCHIVE_BYTES"], remote.ARTIFACT_LIMITS["max_zip_bytes"])
        self.assertEqual(limits["frozen_constants"]["MAX_FILES"], remote.ARTIFACT_LIMITS["max_files"])
        loader = part["analysis_checkpoint_loader"]
        self.assertTrue(loader["resume_origin_overwritten_unconditionally"])
        self.assertEqual(loader["demonstrated"], {"summary_with_adapter_lineage": "KeyError", "summary_with_loader_origin": "accepted"})
        self.assertIn("version_matrix.py", part["not_obtained"])

    def test_every_control_of_the_equivalence_record_holds_and_none_is_vacuous(self):
        controls = self.equivalence["controls"]
        self.assertEqual(self.equivalence["summary"], {"controls": len(controls), "ok": len(controls), "failed": []})
        self.assertGreaterEqual(len(controls), 55)
        ids = [c["id"] for c in controls]
        for needed in ("resume.walk.offsets", "snapshot.other_bytes_same_shape", "snapshot.engine_captured_other_bytes",
                       "ending.worker_lost_before_any_result", "ending.cancelled_by_hint", "ending.source_changed_during_the_run",
                       "ending.partial_by_budget", "cache.arbitrary_sql", "rollback.replay", "rollback.read_back",
                       "remote.unknown_dispatch_not_replayed", "remote.dispatch_audit", "remote.binding.negatives",
                       "remote.registrable", "optimizations.adapter_transparent", "optimizations.non_query_memo",
                       "resume.hostlab_loader_lineage"):
            self.assertIn(needed, ids)
        for control in controls:
            self.assertTrue(control["ok"], control["id"])
            self.assertEqual(control["expected"], control["observed"], control["id"])
            self.assertTrue(control["description"], control["id"])
        reasons = set(ca.REASONS) | set(remote.REASONS)

        def strings(value):
            if isinstance(value, str):
                yield value
            elif isinstance(value, dict):
                for item in value.values():
                    yield from strings(item)
            elif isinstance(value, list):
                for item in value:
                    yield from strings(item)

        negative = [c for c in controls if reasons & set(strings(c["expected"]))]
        self.assertGreaterEqual(len(negative), 35)  # most controls are refusals: the negative controls
        by_id = {c["id"]: c for c in controls}
        self.assertEqual(by_id["resume.walk.offsets"]["observed"]["offsets"], [[0, 3], [3, 3], [6, 1]])
        self.assertEqual(by_id["identity.same"]["observed"], None)
        self.assertEqual(by_id["ending.complete"]["observed"]["cache_refusal"], None)
        for name in ("worker_lost_before_any_result", "worker_lost_after_a_page", "cancelled_by_engine_code", "cancelled_by_hint",
                     "source_changed_during_the_run", "partial_by_budget"):
            self.assertIsNotNone(by_id["ending." + name]["observed"]["cache_refusal"], name)
            self.assertNotEqual(by_id["ending." + name]["observed"]["resume_success"], True, name)

    def test_existing_optimisations_are_kept_and_not_claimed(self):
        part = self.equivalence["existing_optimizations"]
        self.assertEqual(part["new_gains_claimed"], [])
        names = {k["name"] for k in part["kept"]}
        self.assertTrue({"non-query memo", "64 KiB read chunks", "bounded queue", "range filter", "durable version-matrix queue",
                         "checkpoint resume", "one session per backend", "bounded batch result budget"} <= names)
        manifest = {f["path"]: f["sha256"] for f in json.loads((ROOT / "conformance/corpus/hostlab/source-8782f43/manifest.json")
                                                                .read_text(encoding="utf-8"))["files"] if "path" in f}
        for item in part["kept"]:
            self.assertFalse(item["claimed_as_new_gain"] or item["reimplemented_by_the_adapters"], item["name"])
            self.assertEqual(item["status"], "kept_as_is")
            self.assertEqual(item["evidence"]["sha256"], manifest[item["evidence"]["file"]])
            self.assertEqual((ROOT / item["evidence"]["file"]).read_text(encoding="utf-8").count(item["evidence"]["anchor"]), 1)

    def test_what_was_not_run_and_not_proven_is_said(self):
        text = json.dumps(self.equivalence["not_run"] + self.equivalence["not_proven"])
        for phrase in ("workflow dispatch", "real engine", "analysis_checkpoint.py", "resume_origin", "OpenCapture", "nothing here is timed"):
            self.assertIn(phrase, text)


class GeneratorRefuses(unittest.TestCase):
    """The generator refuses to write a record whose facts do not hold, and `--check` fails on a stale file."""

    def test_a_failing_control_stops_the_record(self):
        controls = records.Controls()
        controls.add("a", "holds", 1, 1)
        controls.add("b", "does not hold", 1, 2)
        self.assertEqual([c["ok"] for c in controls.items], [True, False])
        with mock.patch.object(records, "remote_controls", lambda work, c: c.add("x", "fails", "refused", None)), \
                mock.patch.object(records, "resume_controls", lambda work, c: None):
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
                with self.assertRaises(records.Violation) as caught:
                    records.build_equivalence(Path(directory), "")
        self.assertIn("x", str(caught.exception))
        self.assertEqual(records.main.__name__, "main")

    def test_a_missing_anchor_stops_the_record(self):
        anchors = list(records.ANCHORS) + [("gone", records.FROZEN + "analysis_batch.py", "this text is nowhere", "x")]
        with mock.patch.object(records, "ANCHORS", anchors):
            with self.assertRaises(records.Violation):
                records.optimizations()
        twice = list(records.ANCHORS) + [("twice", records.FROZEN + "analysis_batch.py", "import os", "x")]
        with mock.patch.object(records, "ANCHORS", twice):
            with self.assertRaises(records.Violation):
                records.optimizations()

    def test_an_adapter_that_reimplements_an_optimisation_stops_the_record(self):
        real = records.read

        def read(relative):
            text = real(relative)
            return text + "\nreused = memo.get(identity) if task[\"operation\"] != \"query\" else None\n" \
                if relative.endswith("checkpoint_adapter.py") else text

        with mock.patch.object(records, "read", read):
            with self.assertRaises(records.Violation) as caught:
                records.optimizations()
        self.assertIn("reimplements", str(caught.exception))

    def test_check_fails_for_a_stale_or_missing_record_and_passes_for_a_current_one(self):
        contracts, equivalence = records.build_all()
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            a, b = Path(directory) / "contracts.json", Path(directory) / "equivalence.json"
            with mock.patch.object(records, "CONTRACTS", a), mock.patch.object(records, "EQUIVALENCE", b), \
                    mock.patch.object(records, "build_all", lambda: (contracts, equivalence)):
                self.assertEqual(records.main(["--check"]), 1)  # nothing written yet
                self.assertEqual(records.main([]), 0)
                self.assertEqual(records.main(["--check"]), 0)
                b.write_text(equivalence.replace('"ok": true', '"ok": false', 1), encoding="utf-8")
                self.assertEqual(records.main(["--check"]), 1)
                b.write_text(equivalence, encoding="utf-8")
                a.write_text(contracts + " ", encoding="utf-8")
                self.assertEqual(records.main(["--check"]), 1)

    def test_a_violation_is_reported_not_written(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            a, b = Path(directory) / "contracts.json", Path(directory) / "equivalence.json"

            def broken():
                raise records.Violation("the facts do not hold")

            with mock.patch.object(records, "CONTRACTS", a), mock.patch.object(records, "EQUIVALENCE", b), \
                    mock.patch.object(records, "build_all", broken):
                self.assertEqual(records.main([]), 2)
                self.assertFalse(a.exists() or b.exists())

    def test_the_contract_refuses_a_gateway_that_registers_other_tools(self):
        with mock.patch.object(remote, "REMOTE_TOOLS", tuple(reversed(remote.REMOTE_TOOLS))):
            with self.assertRaises(records.Violation):
                with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
                    records.build_contracts(Path(directory))

    def test_a_changed_docstring_limit_stops_the_contract(self):
        phrases = dict(records.DOC_PHRASES, plan_analysis=["this limit is not in the docstring"])
        with mock.patch.object(records, "DOC_PHRASES", phrases):
            with self.assertRaises(records.Violation):
                with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
                    records.build_contracts(Path(directory))


if __name__ == "__main__":
    unittest.main()
