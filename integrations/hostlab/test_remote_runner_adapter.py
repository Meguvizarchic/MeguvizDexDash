"""Remote runner adapter: tool registry, the gh guard, the job pin, the run/artifact binding, job states and path scopes,
with HostLab's frozen remote gateway (conformance/corpus/hostlab/source-8782f43/remote_mcp.py, hash-checked) running
unchanged under stand-ins. No network, no `gh`, no dispatch: the guard refuses a call that could dispatch before it runs.

Run: python -I -m unittest discover -s integrations/hostlab -p "test_remote_runner_adapter.py"
"""
import ast
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import checkpoint_test_support as cts  # noqa: E402
import hostlab_test_support as support  # noqa: E402
import provider  # noqa: E402
import remote_runner_adapter as remote  # noqa: E402
import remote_test_support as rts  # noqa: E402

ROOT = support.ROOT
HEAD = rts.HEAD
RID = rts.REQUEST_ID
SAMPLE = {"sha256": "ab" * 32, "revision": "rev-1", "version_code": 9170100}
TOOLS_AND_OPTIONS = json.loads((ROOT / "conformance/manifests/tools-and-options.json").read_text(encoding="utf-8"))


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.dir = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)
        self.count = 0

    def gateway(self, runs=None, **kwargs):
        self.count += 1
        return rts.Gateway(self.dir / f"gw{self.count}", rts.FakeGitHub(runs, **kwargs))

    def refused(self, reason, function, *args, component=None, **kwargs):
        with self.assertRaises(remote.RemoteRefused) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.reason, reason)
        if component is not None:
            self.assertEqual(caught.exception.component, component)
        return caught.exception


# ---- the registry ------------------------------------------------------------------------------------------------------------

class Registry(Case):
    def test_the_twelve_tools_are_the_ones_the_frozen_gateway_registers_in_the_order_it_registers_them(self):
        gateway = self.gateway()
        self.assertEqual(tuple(gateway.server.tools), remote.REMOTE_TOOLS)
        self.assertEqual(len(remote.REMOTE_TOOLS), 12)
        self.assertEqual(gateway.server.name, remote.REMOTE_SERVER)
        self.assertEqual([t["name"] for t in TOOLS_AND_OPTIONS["remote_orchestration"]], list(remote.REMOTE_TOOLS))

    def test_the_constants_agree_with_the_frozen_inventory_of_the_other_servers(self):
        for version, names in TOOLS_AND_OPTIONS["native_mcp"].items():
            self.assertEqual(sorted(t["name"] if isinstance(t, dict) else t for t in names), list(remote.ENGINE_NATIVE_TOOLS), version)
        self.assertEqual([t["name"] for t in TOOLS_AND_OPTIONS["legacy_dexq"]], list(remote.LEGACY_DEXQ_TOOLS))
        # the tools the engine really serves today are among the twelve native ones, and none is an orchestration tool
        self.assertLessEqual(set(support.TOOLS), set(remote.ENGINE_NATIVE_TOOLS))
        self.assertLessEqual(set(provider.TOOLS_BY_OPERATION["info"]), set(remote.ENGINE_NATIVE_TOOLS))
        self.assertEqual(sorted(remote.DISPATCHING_TOOLS + remote.NON_DISPATCHING_TOOLS), sorted(remote.REMOTE_TOOLS))
        self.assertEqual(set(remote.DISPATCHING_TOOLS) & set(remote.NON_DISPATCHING_TOOLS), set())

    def test_no_orchestration_tool_is_a_tool_of_the_engine_or_of_dexq_and_none_of_theirs_is_one_of_these(self):
        orchestration = set(remote.REMOTE_TOOLS)
        self.assertEqual(orchestration & set(remote.ENGINE_NATIVE_TOOLS), set())
        self.assertEqual(orchestration & set(remote.LEGACY_DEXQ_TOOLS), set())
        shared = set(remote.ENGINE_NATIVE_TOOLS) & set(remote.LEGACY_DEXQ_TOOLS)
        self.assertIn("query", shared)  # the reason a tool name alone proves nothing
        for tool in remote.REMOTE_TOOLS:
            self.assertEqual(remote.route(remote.REMOTE_SERVER, tool), "remote_orchestration")
            for server in (remote.ENGINE_SERVER, remote.LEGACY_SERVER):
                error = self.refused("tool_not_on_server", remote.route, server, tool, component=tool)
                self.assertIn(remote.REMOTE_SERVER, str(error))
        for tool in remote.ENGINE_NATIVE_TOOLS:
            self.assertEqual(remote.route(remote.ENGINE_SERVER, tool), "engine_native")
            error = self.refused("tool_not_on_server", remote.route, remote.REMOTE_SERVER, tool)
            self.assertIn(remote.ENGINE_SERVER, str(error))
        for tool in remote.LEGACY_DEXQ_TOOLS:
            self.assertEqual(remote.route(remote.LEGACY_SERVER, tool), "legacy_dexq")
            self.refused("tool_not_on_server", remote.route, remote.REMOTE_SERVER, tool)
        # the same name on two servers is routed by the pair, to two different families
        self.assertEqual((remote.route(remote.ENGINE_SERVER, "query"), remote.route(remote.LEGACY_SERVER, "query")),
                         ("engine_native", "legacy_dexq"))
        self.assertIn("dexq, meguvizdexdash", str(self.refused("tool_not_on_server", remote.route, remote.REMOTE_SERVER, "query")))
        self.assertNotIn("belongs", str(self.refused("tool_not_on_server", remote.route, remote.ENGINE_SERVER, "nothing")))
        self.refused("unknown_server", remote.route, "other", "query")
        self.refused("unknown_server", remote.route, "", "plan_analysis")
        self.assertEqual(remote.ENGINE_SERVER, provider.ENGINE)

    def test_the_operations_of_submit_job_are_not_tools(self):
        for operation in remote.SUBMIT_JOB_OPERATIONS:
            gateway = self.gateway()
            gateway.call("submit_job", version_code=1, operation=operation)  # accepted by the frozen gateway
            self.assertEqual(len(gateway.recorder.named("remote_dispatch.dispatch")), 1, operation)
            self.assertNotIn(operation, remote.REMOTE_TOOLS)
        gateway = self.gateway()
        with self.assertRaises(rts.ToolError):
            gateway.call("submit_job", version_code=1, operation="plan_analysis")  # a tool name is not an operation
        self.assertIn("query", remote.SUBMIT_JOB_OPERATIONS)
        self.assertIn("query", remote.ENGINE_NATIVE_TOOLS)

    def test_the_dispatch_class_follows_what_each_tool_hands_on(self):
        label_dispatches = {"version_matrix.create", "version_matrix.recover", "remote_schedule.submit", "remote_dispatch.dispatch"}
        minimal = {
            "plan_version_matrix": dict(samples=[], request={}), "submit_version_matrix": dict(samples=[], request={}),
            "advance_version_matrix": dict(matrix_id="m1"), "version_matrix_status": dict(matrix_id="m1"),
            "version_matrix_result": dict(matrix_id="m1"), "recover_version_matrix": dict(matrix_id="m1"),
            "plan_analysis": dict(request={}), "submit_analysis": dict(version_code=1, request={}),
            "submit_job": dict(version_code=1, operation="info"), "job_status": dict(request_id=RID), "list_jobs": {},
            "job_result": dict(request_id=RID),
        }
        for tool in remote.REMOTE_TOOLS:
            gateway = self.gateway([rts.run_record()])
            gateway.recorder.artifact_files = lambda request_id, run: write_result(self.dir, request_id, run)
            gateway.call(tool, **minimal[tool])
            handed_on = [c for c in gateway.recorder.calls
                         if c["call"] in label_dispatches or (c["call"] == "version_matrix.advance" and c["kwargs"].get("dispatch", True))]
            self.assertEqual(bool(handed_on), tool in remote.DISPATCHING_TOOLS, tool)
            self.assertEqual(remote.dispatch_class(tool), "dispatching" if tool in remote.DISPATCHING_TOOLS else "non_dispatching")
            self.assertEqual(gateway.github.guard.mutations, [], tool)  # the gateway itself never runs a mutating gh call
        self.refused("tool_not_on_server", remote.dispatch_class, "query", component="query")


# ---- the gh guard ------------------------------------------------------------------------------------------------------------

class Guard(Case):
    READS = [["api", "repos/o/r/actions/runs/1"], ["api", "repos/o/r/contents/index.json?ref=reports"],
             ["api", "-X", "GET", "x"], ["api", "--method", "get", "x"], ["api", "--method=GET", "x"], ["api", "-XGET", "x"],
             ["api", "--paginate", "-H", "Accept: x", "x"], ["api", "-HAccept: x", "x"], ["api", "-q.foo", "x"],
             ["api", "-t{{.}}", "x"], ["api", "-i", "x"], ["run", "list"], ["run", "view", "1"], ["run", "download", "1"],
             ["workflow", "list"], ["workflow", "view", "x"], ["release", "list"]]
    MUTATIONS = [["workflow", "run", "host-analysis.yml"], ["api", "-X", "POST", "x"], ["api", "--method", "PATCH", "x"],
                 ["api", "--method=DELETE", "x"], ["api", "-XPUT", "x"], ["api", "x", "-f", "a=b"], ["api", "x", "-F", "a=b"],
                 ["api", "x", "--field", "a=b"], ["api", "x", "--raw-field=a=b"], ["api", "x", "--input", "-"],
                 ["api", "x", "--input", "body.json"],
                 ["api", "x", "-fref=main"], ["api", "x", "-Fref=main"], ["api", "-fref=main", "x"], ["api", "x", "-f=ref=main"],
                 ["api", "x", "-if", "ref=main"], ["api", "x", "-z"],
                 ["api", "-X"], ["run", "rerun", "1"], ["run", "cancel", "1"], ["pr", "create"], ["release", "create"],
                 ["issue", "comment"], ["workflow", "enable", "x"], [], ["api", "-X", "POST"]]

    def test_only_reads_are_reads(self):
        for args in self.READS:
            self.assertEqual(remote.gh_effect(args), "read", args)
        for args in self.MUTATIONS:
            self.assertEqual(remote.gh_effect(args), "mutate", args)
        self.assertEqual(remote.gh_effect(["api", "x"], payload={"a": 1}), "mutate")
        self.assertEqual(remote.gh_effect(["api", "x"], payload=""), "mutate")

    def test_a_dispatch_is_refused_before_anything_is_run(self):
        ran = []
        guard = remote.GhGuard(lambda argv, input=None, **kw: ran.append(argv) or "ran")
        self.assertEqual(guard.run(["gh", "api", "x"], input=None, text=True), "ran")
        for argv, payload in ((["gh", "workflow", "run", "w"], None), (["gh", "api", "x"], '{"ref": "main"}'),
                              (["gh", "api", "-X", "POST", "x"], None)):
            with self.assertRaises(remote.DispatchRefused) as caught:
                guard.run(argv, input=payload)
            self.assertEqual(caught.exception.code, "INVALID_ARGUMENT")
        self.assertEqual(ran, [["gh", "api", "x"]])
        self.assertEqual([c["effect"] for c in guard.calls], ["read", "mutate", "mutate", "mutate"])
        self.assertEqual(len(guard.mutations), 3)
        self.assertTrue(guard.calls[2]["has_input"])
        permissive = remote.GhGuard(lambda argv, input=None, **kw: "ran", allow_mutation=True)
        self.assertEqual(permissive.run(["gh", "workflow", "run", "w"]), "ran")
        self.assertEqual(len(permissive.mutations), 1)

    def test_an_attached_field_shorthand_cannot_dispatch(self):
        ran = []
        guard = remote.GhGuard(lambda argv, input=None, **kw: ran.append(argv) or "ran")
        for argv in (["gh", "api", "x", "-fref=main"], ["gh", "api", "x", "-if", "ref=main"]):
            with self.assertRaises(remote.DispatchRefused) as caught:
                guard.run(argv)
            self.assertEqual(caught.exception.code, "INVALID_ARGUMENT")
        self.assertEqual(ran, [])  # refused before anything was run
        self.assertEqual([c["effect"] for c in guard.calls], ["mutate", "mutate"])

    def test_with_nothing_behind_it_the_guard_runs_nothing(self):
        guard = remote.GhGuard()
        done = guard.run(["gh", "api", "x"])
        self.assertEqual((done.returncode, done.stdout), (1, ""))

    def test_the_seven_tools_that_do_not_dispatch_cannot_dispatch_even_if_something_behind_them_tried(self):
        gateway = self.gateway_with_dispatching_artifacts()
        # the frozen gateway turns any ValueError (the refusal is one) into a tool error; the dispatch did not happen
        with self.assertRaises(rts.ToolError) as caught:
            gateway.call("job_result", request_id=RID)
        self.assertEqual(str(caught.exception), "artifact_collection_failed")
        self.assertEqual(len(gateway.github.guard.mutations), 1)
        self.assertEqual(gateway.github.guard.mutations[0]["args"][:2], ["workflow", "run"])
        self.assertNotIn(["workflow", "run", "host-analysis.yml"], gateway.github.ran)  # refused before it was run
        permissive = rts.Gateway(self.dir / "permissive", rts.FakeGitHub([rts.run_record()], allow_mutation=True))
        permissive.recorder.artifact_files = lambda request_id, run: permissive.module.gh(["workflow", "run", "w"]) and {}
        with self.assertRaises(rts.ToolError):  # nothing to collect, but this time the call got through
            permissive.call("job_result", request_id=RID)
        self.assertIn(["workflow", "run", "w"], permissive.github.ran)

    def gateway_with_dispatching_artifacts(self):
        gateway = self.gateway([rts.run_record()])

        def artifact(request_id, run):
            gateway.module.gh(["workflow", "run", "host-analysis.yml"])  # a read tool whose collaborator tries to dispatch
            return {}

        gateway.recorder.artifact_files = artifact
        return gateway


# ---- the frozen gateway, tool by tool ---------------------------------------------------------------------------------------------

def write_result(directory, request_id, run, tasks=None, extra=None):
    root = Path(directory) / "artifact"
    paths = rts.write_artifact(root, request_id, tasks=tasks, extra=extra)
    return {"files": [str(p) for p in paths], "root": str(root), "cache_hit": False, "artifact": {"name": "result"},
            "integrity": "verified", "elapsed_ms": 1.5, "run_attempt": run["run_attempt"]}


class Gateway(Case):
    def test_submit_job_records_the_request_before_it_dispatches_and_never_dispatches_again(self):
        gateway = self.gateway()
        answer = json.loads(gateway.call("submit_job", version_code=9170100, operation="query", argument="SELECT 1",
                                         max_cell_chars=500))
        request_id = answer["request_id"]
        self.assertEqual(len(request_id), 32)
        dispatched = gateway.recorder.named("remote_dispatch.dispatch")
        self.assertEqual(len(dispatched), 1)
        self.assertEqual(gateway.recorder.journal_at_dispatch[0]["status"], "dispatch_unknown")  # written ahead
        repository, workflow, inputs, gh = dispatched[0]["args"]
        self.assertEqual((repository, workflow), (rts.REPO, rts.WORKFLOW))
        self.assertEqual(inputs, {"request_id": request_id, "version_code": "9170100", "operation": "query",
                                  "argument": "SELECT 1", "max_cell_chars": "500"})
        self.assertIs(gh, gateway.module.gh)
        self.assertEqual(answer["dispatched"], True)
        self.assertEqual(gateway.journal(request_id)["status"], "queued")  # the journal now holds the dispatcher's word
        # the default cell width is not sent, so an older workflow can still serve the call
        plain = json.loads(gateway.call("submit_job", version_code=1, operation="info"))
        self.assertNotIn("max_cell_chars", gateway.recorder.named("remote_dispatch.dispatch")[1]["args"][2])
        self.assertIn("request_id", plain)

    def test_a_dispatch_whose_outcome_is_unknown_is_looked_up_and_never_sent_again(self):
        gateway = self.gateway()
        gateway.recorder.raises["remote_dispatch.dispatch"] = RuntimeError("the process died during dispatch")
        with self.assertRaises(RuntimeError):
            gateway.call("submit_job", version_code=1, operation="info")
        request_id = gateway.recorder.named("remote_dispatch.dispatch")[0]["args"][2]["request_id"]
        record = gateway.journal(request_id)
        self.assertEqual(record["status"], "dispatch_unknown")
        self.assertEqual(remote.job_state(record, None), "dispatch_unknown")
        # asking again looks the run up by its title; it does not dispatch
        status = json.loads(gateway.call("job_status", request_id=request_id))
        self.assertEqual(status["status"], "dispatch_pending")
        self.assertEqual(len(gateway.recorder.named("remote_dispatch.dispatch")), 1)
        self.assertEqual(gateway.github.guard.mutations, [])
        # when the run turns up it is found, and the mapping is written; still no second dispatch
        gateway.github.runs.append(rts.run_record(request_id, run_id=77, status="in_progress", conclusion=None))
        found = json.loads(gateway.call("job_status", request_id=request_id))
        self.assertEqual((found["id"], found["status"]), (77, "in_progress"))
        self.assertEqual(json.loads((gateway.state / "remote-job-map" / (request_id + ".json")).read_text()), {"run_id": 77})
        self.assertEqual(remote.job_state(record, gateway.github.runs[-1]), "running")
        self.assertEqual(len(gateway.recorder.named("remote_dispatch.dispatch")), 1)

    def test_submit_job_refuses_what_it_cannot_bound_and_dispatches_nothing(self):
        bad = [dict(version_code=0, operation="info"), dict(version_code=10 ** 10, operation="info"),
               dict(version_code=1, operation="nope"), dict(version_code=1, operation="info", argument="x" * 4097),
               dict(version_code=1, operation="query", max_cell_chars=0), dict(version_code=1, operation="query", max_cell_chars=16001),
               dict(version_code=1, operation="info", max_cell_chars=301), dict(version_code=1, operation="info", source_mode="nope"),
               dict(version_code=1, operation="info", source_mode="worktree"),
               dict(version_code=1, operation="multipath_audit", source_mode="historical"),
               dict(version_code=1, operation="source_check", source_mode="historical")]
        for arguments in bad:
            with self.subTest(arguments):
                gateway = self.gateway()
                with self.assertRaises(rts.ToolError):
                    gateway.call("submit_job", **arguments)
                self.assertEqual(gateway.recorder.named("remote_dispatch.dispatch"), [])
                self.assertFalse((gateway.state / "remote-requests").exists())
        for arguments in (dict(version_code=1, operation="query", max_cell_chars=16000), dict(version_code=1, operation="regenerate_ai",
                                                                                           source_mode="historical")):
            self.assertEqual(len(self.run_ok(arguments).recorder.named("remote_dispatch.dispatch")), 1)

    def run_ok(self, arguments):
        gateway = self.gateway()
        gateway.call("submit_job", **arguments)
        return gateway

    def test_a_complete_analysis_binds_its_source_snapshot_and_a_failed_snapshot_dispatches_nothing(self):
        gateway = self.gateway()
        gateway.call("submit_job", version_code=1, operation="multipath_audit")
        prepared = gateway.recorder.named("snapshot_transport.prepare")
        self.assertEqual(len(prepared), 1)
        inputs = gateway.recorder.named("remote_dispatch.dispatch")[0]["args"][2]
        self.assertEqual(json.loads(inputs["module_source"]), {"snapshot_sha256": "00" * 32})
        self.assertEqual(gateway.journal(inputs["request_id"])["module_source"], {"snapshot_sha256": "00" * 32})
        failing = self.gateway()
        failing.recorder.raises["snapshot_transport.prepare"] = OSError("no snapshot")
        with self.assertRaises(rts.ToolError) as caught:
            failing.call("submit_job", version_code=1, operation="source_check")
        self.assertIn("was not dispatched", str(caught.exception))
        self.assertEqual(failing.recorder.named("remote_dispatch.dispatch"), [])
        self.assertFalse((failing.state / "remote-requests").exists())

    def test_job_status_reports_the_attempt_and_never_dispatches(self):
        run = rts.run_record(attempt=3)
        gateway = self.gateway([run])
        gateway.recorder.returns["remote_schedule.observe"] = {
            "status": "completed", "conclusion": "success", "run_attempt": 3, "queued_at": 5.0, "dispatch": "confirmed",
            "run_updated_at": "t", "state_uncertain": False, "stale_observation_ignored": True}
        gateway.recorder.returns["remote_schedule.public_status"] = "succeeded"
        status = json.loads(gateway.call("job_status", request_id=RID))
        self.assertEqual({k: status[k] for k in ("id", "head_sha", "html_url", "request_id", "status", "conclusion",
                                                 "run_attempt", "stale_observation_ignored", "dispatch")},
                         {"id": 4242, "head_sha": HEAD, "html_url": run["html_url"], "request_id": RID, "status": "succeeded",
                          "conclusion": "success", "run_attempt": 3, "stale_observation_ignored": True, "dispatch": "confirmed"})
        self.assertIn("lookup_elapsed_ms", status)
        self.assertEqual(gateway.recorder.named("remote_schedule.observe")[0]["args"], (RID, run))
        self.assertEqual(gateway.github.guard.mutations, [])
        self.assertEqual(json.loads(gateway.call("job_status", request_id=rts.OTHER_REQUEST_ID))["status"], "dispatch_pending")
        with self.assertRaises(rts.ToolError):
            gateway.call("job_status", request_id="not-an-id")
        listing = json.loads(gateway.call("list_jobs"))
        self.assertEqual(set(listing[0]), {"id", "display_title", "status", "conclusion", "html_url"})

    def test_job_result_hands_the_run_attempt_and_head_sha_to_the_artifact_check(self):
        run = rts.run_record(attempt=2)
        gateway = self.gateway([run])
        gateway.recorder.artifact_files = lambda request_id, found: write_result(self.dir, request_id, found)
        result = json.loads(gateway.call("job_result", request_id=RID))
        fetched = gateway.recorder.named("remote_artifacts.get")[0]["args"]
        self.assertEqual(fetched[:2], (rts.REPO, RID))
        self.assertEqual({k: fetched[2][k] for k in ("id", "run_attempt", "head_sha", "display_title")},
                         {"id": 4242, "run_attempt": 2, "head_sha": HEAD, "display_title": "hostlab-" + RID})
        self.assertIs(fetched[3], gateway.module.gh)
        self.assertEqual(result["collection"]["run_attempt"], 2)
        self.assertEqual(result["task_summary"]["counts"], {"complete": 1})
        self.assertEqual(gateway.github.guard.mutations, [])
        # what the gateway handed over is exactly what the adapter's binding reads
        binding = remote.run_binding(fetched[2], RID, rts.REPO, rts.WORKFLOW)
        self.assertEqual((binding["run_attempt"], binding["head_sha"], binding["run_id"]), (2, HEAD, 4242))

    def test_job_result_waits_for_a_completed_run_and_checks_its_arguments(self):
        for run in (None, rts.run_record(status="in_progress", conclusion=None)):
            gateway = self.gateway([run] if run else [])
            with self.assertRaises(rts.ToolError) as caught:
                gateway.call("job_result", request_id=RID)
            self.assertIn("not completed", str(caught.exception))
            self.assertEqual(gateway.recorder.named("remote_artifacts.get"), [])
        gateway = self.gateway([rts.run_record()])
        gateway.recorder.artifact_files = lambda request_id, found: write_result(self.dir, request_id, found)
        bad = [dict(result_offset=-1), dict(result_offset=2147483648), dict(result_offset=True), dict(sample_index=-2),
               dict(sample_index=12), dict(page_chars=1023), dict(page_chars=128001), dict(result_file=5),
               dict(result_file="../result.txt"), dict(result_file="C:/result.txt"), dict(result_file="a//b.txt"),
               dict(result_file="evil.sh"), dict(result_file="x/" * 3000 + "result.txt")]
        for arguments in bad:
            with self.subTest(arguments), self.assertRaises(rts.ToolError):
                gateway.call("job_result", request_id=RID, **arguments)
        for arguments in (dict(result_offset=0, page_chars=1024), dict(result_file="job.json"), dict(page_chars=128000)):
            json.loads(gateway.call("job_result", request_id=RID, **arguments))
        with self.assertRaises(rts.ToolError):
            gateway.call("job_result", request_id=RID, sample_index=0)  # only grouped jobs have members

    def test_submit_analysis_hands_the_sample_binding_and_the_resume_claim_on_unchanged(self):
        gateway = self.gateway()
        request = {"schema": 1, "tasks": [{"id": "a", "operation": "info"}],
                   "resume": {"run_id": 5, "attempt": 2, "request_id": RID}}
        gateway.call("submit_analysis", version_code=9170100, request=request, apk_sha256="ab" * 32, sample_revision="rev-1",
                     idempotency_key="key-1")
        call = gateway.recorder.named("remote_schedule.submit")[0]
        self.assertEqual(call["args"][:2], (9170100, request))
        self.assertIs(call["args"][1], request)  # the same object: nothing was rewritten
        self.assertEqual({k: v for k, v in call["kwargs"].items()},
                         {"repository": rts.REPO, "workflow": rts.WORKFLOW, "apk_sha256": "ab" * 32,
                          "sample_revision": "rev-1", "idempotency_key": "key-1"})
        gateway.recorder.raises["remote_schedule.submit"] = ValueError("exact APK SHA and sample revision are required")
        with self.assertRaises(rts.ToolError) as caught:
            gateway.call("submit_analysis", version_code=1, request=request)
        self.assertEqual(str(caught.exception), "exact APK SHA and sample revision are required")
        gateway.call("plan_analysis", request=request)
        self.assertEqual(gateway.recorder.named("remote_schedule.describe")[0]["args"], (request,))

    def test_the_matrix_tools_hand_on_what_their_names_promise(self):
        gateway = self.gateway()
        samples, request = [{"x": 1}], {"y": 2}
        gateway.call("plan_version_matrix", samples=samples, request=request, max_parallel=3, runner_batch_size=2,
                     execution_policy="adaptive")
        self.assertEqual(gateway.recorder.named("version_matrix.plan")[0]["args"],
                         (samples, request, 3, True, 1800, 2, "adaptive"))
        gateway.call("version_matrix_status", matrix_id="m9")
        status = gateway.recorder.named("version_matrix.advance")[-1]
        self.assertEqual((status["args"], status["kwargs"]["dispatch"]), (("m9", gateway.module.gh, gateway.module.lookup,
                                                                          gateway.module.runs), False))
        gateway.call("advance_version_matrix", matrix_id="m9")
        self.assertNotIn("dispatch", gateway.recorder.named("version_matrix.advance")[-1]["kwargs"])
        gateway.call("version_matrix_result", matrix_id="m9", offset=2, limit=4, prefetch_only=True)
        self.assertEqual(len(gateway.recorder.named("version_matrix.prefetch")), 1)
        self.assertEqual(gateway.recorder.named("version_matrix.compare"), [])
        gateway.call("version_matrix_result", matrix_id="m9")
        self.assertEqual(len(gateway.recorder.named("version_matrix.compare")), 1)
        gateway.call("recover_version_matrix", matrix_id="m9", idempotency_key="k", include_unverified_results=True)
        recover = gateway.recorder.named("version_matrix.recover")[0]
        self.assertEqual((recover["args"][0], recover["kwargs"]["idempotency_key"], recover["kwargs"]["include_unverified_results"]),
                         ("m9", "k", True))
        submitted = self.gateway()
        submitted.call("submit_version_matrix", samples=samples, request=request, idempotency_key="stable")
        created = submitted.recorder.named("version_matrix.create")[0]
        self.assertEqual((created["kwargs"]["idempotency_key"], created["kwargs"]["repository"]), ("stable", rts.REPO))
        self.assertEqual(len(submitted.recorder.named("version_matrix.advance")), 1)
        refused = self.gateway()
        refused.recorder.returns["version_matrix.create"] = {"error": "capacity"}
        self.assertEqual(json.loads(refused.call("submit_version_matrix", samples=samples, request=request)), {"error": "capacity"})
        self.assertEqual(refused.recorder.named("version_matrix.advance"), [])  # nothing is advanced for a refused queue


# ---- the pin ----------------------------------------------------------------------------------------------------------------------------

class Pin(Case):
    def setUp(self):
        super().setUp()
        self.setup = cts.engine_setup(self.dir / "engine")
        self.tasks = [{"id": "l1", "operation": "locate", "kind": "class", "name": "Lfoo;"},
                      {"id": "q", "operation": "query", "sql": cts.NUMBERS, "dialect": "dexsql", "limit": 3}]

    def plan(self, request=None, **changes):
        options = dict(runner_revision=HEAD, sample=SAMPLE, legacy=self.setup.legacy, engine_status=self.setup.status)
        options.update(changes)
        return remote.plan_ci(request or cts.engine_request(*self.tasks), changes.pop("config", self.setup.config), **{
            k: v for k, v in options.items() if k != "config"})

    def test_a_job_is_pinned_to_the_runner_the_sample_the_backend_the_engine_and_the_configuration(self):
        planned = self.plan()
        self.assertEqual((planned["schema"], planned["dispatches"]), (remote.REMOTE_SCHEMA, False))
        pin = planned["pin"]
        self.assertEqual(pin["runner_revision"], HEAD)
        self.assertEqual(pin["task_backends"], {"l1": provider.ENGINE, "q": provider.ENGINE})
        self.assertEqual(pin["engine"], planned["plan"]["provider"]["engine"])
        self.assertEqual(pin["config_digest"], self.setup.config.digest())
        self.assertEqual(pin["request_sha256"], planned["plan"]["request_sha256"])
        self.assertEqual(pin["sample"], {"apk_sha256": SAMPLE["sha256"], "revision": "rev-1", "version_code": 9170100})
        self.assertEqual(planned["pin_sha256"], provider.digest_of(pin))
        self.assertEqual(self.plan()["pin"], pin)  # no clock, no randomness

    def test_the_resume_claim_is_not_part_of_the_pin(self):
        request = cts.engine_request(*self.tasks)
        resumed = dict(request, resume={"run_id": 5, "attempt": 1, "request_id": RID})
        self.assertEqual(self.plan(resumed)["pin"], self.plan(request)["pin"])

    def test_work_that_stays_on_a_legacy_backend_has_a_pin_without_an_engine(self):
        legacy = cts.engine_request(self.tasks[0], backend="dexsql")
        planned = self.plan(legacy, engine_status=None)
        self.assertIsNone(planned["pin"]["engine"])
        self.assertEqual(planned["pin"]["task_backends"], {"l1": "dexsql"})
        self.assertNotEqual(planned["pin"]["request_sha256"], self.plan(cts.engine_request(self.tasks[0]))["pin"]["request_sha256"])
        sqlite = self.plan(cts.engine_request({"id": "s", "operation": "query", "sql": "SELECT 1", "dialect": "sqlite"},
                                              backend="sqlite"), engine_status=None)
        self.assertEqual(sqlite["pin"]["task_backends"], {"s": "sqlite"})

    def test_an_unusable_engine_is_not_planned_around(self):
        down = {"available": False, "reason": "binary_missing"}
        with self.assertRaises(provider.ProviderUnavailable):
            self.plan(engine_status=down)

    def test_a_runner_revision_and_a_sample_are_exact(self):
        for bad in ("main", HEAD[:7], HEAD.upper(), "", None, 5):
            self.refused("invalid_runner_revision", self.plan, runner_revision=bad)
        for bad in (None, {}, dict(SAMPLE, sha256="AB" * 32), dict(SAMPLE, sha256="ab" * 31), dict(SAMPLE, revision=""),
                    dict(SAMPLE, revision=3), dict(SAMPLE, revision="x" * 257), dict(SAMPLE, version_code=0),
                    dict(SAMPLE, version_code=10 ** 10), dict(SAMPLE, version_code=True), dict(SAMPLE, version_code="1")):
            self.refused("invalid_sample", self.plan, sample=bad)
        self.assertIsNone(self.plan(sample={"sha256": SAMPLE["sha256"], "revision": "r"})["pin"]["sample"]["version_code"])

    def test_a_pin_is_checked_component_by_component(self):
        pin = self.plan()["pin"]
        remote.check_pin(pin, json.loads(json.dumps(pin)))
        other = cts.engine_setup(self.dir / "other", content=b"stand-in engine 2",
                                 fake=support.FakeEngine(build_id="source-sha256:" + "cd" * 32))
        cases = [
            ("runner_changed", "runner_revision", lambda p: p.update(runner_revision="1" * 40)),
            ("backend_changed", "task_backends", lambda p: p.update(task_backends={"l1": "dexsql", "q": provider.ENGINE})),
            ("backend_changed", "task_backends", lambda p: p["task_backends"].pop("q")),
            ("engine_changed", "engine", lambda p: p.update(engine=None)),
            ("engine_changed", "engine", lambda p: p["engine"].update(build_id="source-sha256:" + "cd" * 32)),
            ("engine_changed", "engine", lambda p: p.update(engine=other.status and
                                                            other.plan(cts.engine_request(*self.tasks))["provider"]["engine"])),
            ("config_changed", "config_digest", lambda p: p.update(config_digest="0" * 64)),
            ("request_changed", "request_sha256", lambda p: p.update(request_sha256="0" * 64)),
            ("source_changed", "sample", lambda p: p["sample"].update(apk_sha256="0" * 64)),
            ("source_changed", "sample", lambda p: p["sample"].update(revision="rev-2")),
            ("source_changed", "sample", lambda p: p["sample"].update(version_code=1)),
        ]
        for reason, component, edit in cases:
            with self.subTest(reason + "/" + component):
                changed = json.loads(json.dumps(pin))
                edit(changed)
                self.refused(reason, remote.check_pin, pin, changed, component=component)
        # the first difference is the one named: a changed runner is reported before a changed sample
        both = json.loads(json.dumps(pin))
        both["runner_revision"], both["sample"]["revision"] = "1" * 40, "x"
        self.refused("runner_changed", remote.check_pin, pin, both)


# ---- the run, its artifact and the result manifest ------------------------------------------------------------------------------------

class Artifact(Case):
    def setUp(self):
        super().setUp()
        self.root = self.dir / "artifact"
        self.files = rts.write_artifact(self.root)
        self.run = rts.run_record(attempt=2)
        self.pin = {"runner_revision": HEAD, "sample": {"apk_sha256": "ab" * 32}, "engine": None}

    def manifest(self, run=None, termination="complete", **changes):
        arguments = dict(run=run or self.run, request_id=RID, repository=rts.REPO, workflow=rts.WORKFLOW, root=self.root,
                         files=self.files, pin=self.pin, termination=termination)
        arguments.update(changes)
        return remote.result_manifest(**arguments)

    def verify(self, manifest, **changes):
        arguments = dict(run=self.run, request_id=RID, repository=rts.REPO, workflow=rts.WORKFLOW, pin=self.pin, root=self.root)
        arguments.update(changes)
        return remote.verify_result_manifest(manifest, **arguments)

    def test_a_run_is_bound_by_repository_workflow_request_run_attempt_head_and_title(self):
        binding = remote.run_binding(self.run, RID, rts.REPO, rts.WORKFLOW)
        self.assertEqual(binding, {"repository": rts.REPO, "workflow": rts.WORKFLOW, "request_id": RID, "run_id": 4242,
                                   "run_attempt": 2, "head_sha": HEAD, "display_title": "hostlab-" + RID})
        for bad in ("", "AB" * 16, "ab" * 15, None, 5):
            self.refused("request_id_mismatch", remote.run_binding, self.run, bad, rts.REPO, rts.WORKFLOW)
        for key, value in (("id", 0), ("id", "4242"), ("id", True), ("run_attempt", 0), ("run_attempt", "2"), ("head_sha", HEAD[:7]),
                           ("head_sha", HEAD.upper()), ("head_sha", None)):
            self.refused("invalid_run", remote.run_binding, dict(self.run, **{key: value}), RID, rts.REPO, rts.WORKFLOW)
        for run in (None, [], {}):
            self.refused("invalid_run", remote.run_binding, run, RID, rts.REPO, rts.WORKFLOW)
        self.refused("title_mismatch", remote.run_binding, dict(self.run, display_title="hostlab-" + rts.OTHER_REQUEST_ID), RID,
                     rts.REPO, rts.WORKFLOW, component="display_title")
        self.refused("title_mismatch", remote.run_binding, {k: v for k, v in self.run.items() if k != "display_title"}, RID,
                     rts.REPO, rts.WORKFLOW)

    def test_a_manifest_ties_the_artifact_to_its_run_attempt_sample_and_engine(self):
        manifest = self.manifest()
        self.assertEqual(manifest["schema"], remote.RESULT_SCHEMA)
        self.assertEqual(manifest["binding"]["run_attempt"], 2)
        self.assertEqual(manifest["pin"], self.pin)
        self.assertEqual(manifest["outcome"], {"conclusion": "success", "termination": "complete"})
        self.assertEqual([f["path"] for f in manifest["files"]], ["job.json", "result.txt", "summary.json"])
        for entry in manifest["files"]:
            data = (self.root / entry["path"]).read_bytes()
            self.assertEqual((entry["sha256"], entry["bytes"]), (hashlib.sha256(data).hexdigest(), len(data)))
        self.assertEqual(manifest["seal"]["digest"], provider.digest_of({k: manifest[k] for k in
                                                                         ("schema", "binding", "pin", "outcome", "files")}))
        self.verify(manifest)
        self.verify(json.loads(json.dumps(manifest)))
        self.assertEqual(self.manifest(), manifest)  # deterministic

    def test_a_result_is_not_read_back_for_another_run_attempt_head_request_or_repository(self):
        manifest = self.manifest()
        cases = [("run_mismatch", {"run": dict(self.run, id=4243)}), ("run_attempt_mismatch", {"run": dict(self.run, run_attempt=3)}),
                 ("run_attempt_mismatch", {"run": dict(self.run, run_attempt=1)}),
                 ("head_sha_mismatch", {"run": dict(self.run, head_sha="1" * 40)}),
                 ("title_mismatch", {"run": dict(self.run, display_title="hostlab-" + rts.OTHER_REQUEST_ID)}),
                 ("request_id_mismatch", {"request_id": rts.OTHER_REQUEST_ID,
                                          "run": dict(self.run, display_title="hostlab-" + rts.OTHER_REQUEST_ID)}),
                 ("repository_mismatch", {"repository": "someone/else"}), ("repository_mismatch", {"workflow": "other.yml"})]
        for reason, changes in cases:
            with self.subTest(reason, **{k: str(v)[:30] for k, v in changes.items()}):
                self.refused(reason, self.verify, manifest, **changes)

    def test_a_result_made_for_one_engine_cannot_be_claimed_by_another_job(self):
        manifest = self.manifest()
        for reason, edit in (("engine_changed", lambda p: p.update(engine={"build_id": "other"})),
                             ("source_changed", lambda p: p["sample"].update(apk_sha256="0" * 64)),
                             ("runner_changed", lambda p: p.update(runner_revision="2" * 40))):
            pin = json.loads(json.dumps(self.pin))
            edit(pin)
            self.refused(reason, self.verify, manifest, pin=pin)

    def test_the_files_must_still_be_the_files_that_were_listed(self):
        manifest = self.manifest()
        (self.root / "result.txt").write_text("changed", encoding="utf-8")
        self.refused("file_changed", self.verify, manifest, component="result.txt")
        (self.root / "result.txt").write_text(json.dumps({"schema": 1, "tasks": [{"id": "a", "status": "complete"}]}), encoding="utf-8")
        self.verify(manifest)
        (self.root / "summary.json").write_bytes((self.root / "summary.json").read_bytes() + b" ")
        self.refused("file_changed", self.verify, manifest)
        (self.root / "summary.json").write_text(json.dumps({"ok": True}), encoding="utf-8")
        (self.root / "extra.txt").write_text("x", encoding="utf-8")
        self.refused("unexpected_file", self.verify, manifest)
        (self.root / "extra.txt").unlink()
        (self.root / "job.json").unlink()
        self.refused("file_missing", self.verify, manifest, component="job.json")

    def test_a_manifest_that_was_edited_or_is_not_one_is_refused(self):
        manifest = self.manifest()
        for label, edit, reason in (
            ("a digest", lambda m: m["files"][0].update(sha256="0" * 64), "manifest_seal_mismatch"),
            ("the outcome", lambda m: m["outcome"].update(termination="partial"), "manifest_seal_mismatch"),
            ("the attempt", lambda m: m["binding"].update(run_attempt=3), "manifest_seal_mismatch"),
            ("the seal", lambda m: m["seal"].update(digest="0" * 64), "manifest_seal_mismatch"),
            ("the seal type", lambda m: m.update(seal="x"), "manifest_seal_mismatch"),
            ("the schema", lambda m: m.update(schema="other"), "manifest_malformed"),
            ("a missing part", lambda m: m.pop("pin"), "manifest_malformed"),
        ):
            with self.subTest(label):
                broken = json.loads(json.dumps(manifest))
                edit(broken)
                self.refused(reason, self.verify, broken)
        for bad in (None, [], "x", {}):
            self.refused("manifest_malformed", self.verify, bad)
        outside = json.loads(json.dumps(manifest))
        outside["files"][0]["path"] = "../elsewhere.txt"
        self.refused("file_outside_root", self.verify, self.resealed(outside))

    @staticmethod
    def resealed(manifest):
        body = {k: manifest[k] for k in ("schema", "binding", "pin", "outcome", "files")}
        return dict(manifest, seal={"algorithm": "sha256", "digest": provider.digest_of(body)})

    def test_only_a_successful_completed_run_has_a_manifest(self):
        for run, reason in ((dict(self.run, status="in_progress", conclusion=None), "run_not_completed"),
                            (dict(self.run, status="queued", conclusion=None), "run_not_completed"),
                            (dict(self.run, conclusion="failure"), "run_not_successful"),
                            (dict(self.run, conclusion="cancelled"), "run_not_successful"),
                            (dict(self.run, conclusion="timed_out"), "run_not_successful"),
                            (dict(self.run, conclusion=None), "run_not_successful")):
            self.refused(reason, self.manifest, run=run)
        self.refused("manifest_malformed", self.manifest, files=[])
        self.refused("file_outside_root", self.manifest, files=[self.dir / "elsewhere.txt"])
        (self.dir / "elsewhere.txt").write_text("x", encoding="utf-8")
        self.refused("file_outside_root", self.manifest, files=[self.dir / "elsewhere.txt"])
        self.refused("file_outside_root", self.manifest, files=[self.root])

    def test_the_artifact_limits_are_those_of_hostlabs_artifact_cache(self):
        self.assertEqual(remote.ARTIFACT_LIMITS, {"max_zip_bytes": 67108864, "max_unpacked_bytes": 134217728,
                                                  "max_file_bytes": 33554432, "max_files": 4096})
        with mock.patch.dict(remote.ARTIFACT_LIMITS, {"max_files": 2}):
            self.refused("artifact_limit", self.manifest)
        with mock.patch.dict(remote.ARTIFACT_LIMITS, {"max_file_bytes": 10}):
            self.refused("artifact_limit", self.manifest)
        with mock.patch.dict(remote.ARTIFACT_LIMITS, {"max_unpacked_bytes": 20}):
            self.refused("artifact_limit", self.manifest)
        with mock.patch.dict(remote.ARTIFACT_LIMITS, {"max_files": 3, "max_file_bytes": 10 ** 6, "max_unpacked_bytes": 10 ** 6}):
            self.manifest()
        self.refused("manifest_malformed", remote.file_entries, self.root, [self.files[0], self.files[0]])

    def test_only_a_completed_analysis_is_registrable_as_a_completed_result(self):
        self.assertTrue(remote.registrable_as_complete(self.manifest(termination="complete")))
        remote.require_registrable(self.manifest(termination="complete"))
        for termination in ("partial", "cancelled", "worker_lost", "source_changed", "in_flight", None, "success"):
            manifest = self.manifest(termination=termination)  # the artifact exists and can be read, but it is not a completion
            self.assertFalse(remote.registrable_as_complete(manifest), termination)
            self.refused("not_registrable", remote.require_registrable, manifest)
        self.assertFalse(remote.registrable_as_complete({}))
        self.assertFalse(remote.registrable_as_complete({"outcome": {"conclusion": "failure", "termination": "complete"}}))
        self.assertFalse(remote.registrable_as_complete({"outcome": {"conclusion": "success"}}))


# ---- job states ----------------------------------------------------------------------------------------------------------------------------

class JobStates(Case):
    def test_the_state_follows_the_journal_and_the_run(self):
        journal = {"status": "dispatch_unknown"}
        queued = {"status": "queued"}
        table = [
            (journal, None, "dispatch_unknown"), (queued, None, "dispatch_pending"), ({}, None, "dispatch_pending"),
            (None, None, "unknown"),
            (journal, rts.run_record(status="queued", conclusion=None), "running"),
            (None, rts.run_record(status="in_progress", conclusion=None), "running"),
            (None, rts.run_record(status="waiting", conclusion=None), "running"),
            (None, rts.run_record(conclusion="success"), "succeeded"),
            (None, rts.run_record(conclusion="failure"), "failed"), (None, rts.run_record(conclusion="timed_out"), "failed"),
            (None, rts.run_record(conclusion="startup_failure"), "failed"),
            (None, rts.run_record(conclusion="cancelled"), "cancelled"), (None, rts.run_record(conclusion="skipped"), "skipped"),
            (None, rts.run_record(conclusion=None), "unknown"), (None, rts.run_record(conclusion=""), "unknown"),
            (None, rts.run_record(conclusion=5), "unknown"),
        ]
        for record, run, state in table:
            self.assertEqual(remote.job_state(record, run), state, (record, run))
        self.assertEqual(set(remote.JOB_STATES), {s for _, _, s in table})

    def test_only_a_confirmed_failure_may_be_sent_again_and_only_under_a_new_key(self):
        for state in remote.JOB_STATES:
            for new_key in (True, False, None, "yes"):
                expected = state in ("failed", "cancelled", "skipped") and new_key is True
                self.assertEqual(remote.redispatch_allowed(state, new_idempotency_key=new_key), expected, (state, new_key))
        self.assertFalse(remote.redispatch_allowed("dispatch_unknown", new_idempotency_key=True))
        self.assertFalse(remote.redispatch_allowed("running", new_idempotency_key=True))
        self.assertFalse(remote.redispatch_allowed("succeeded", new_idempotency_key=True))

    def test_recover_takes_confirmed_failures_and_unverified_successes_on_request_only(self):
        for state in remote.JOB_STATES:
            for verified in (True, False):
                for opt_in in (True, False, None):
                    expected = state in ("failed", "cancelled", "skipped") or (
                        state == "succeeded" and not verified and opt_in is True)
                    self.assertEqual(remote.recover_eligible(state, verified=verified, include_unverified_results=opt_in), expected,
                                     (state, verified, opt_in))
        for state in ("running", "dispatch_unknown", "dispatch_pending", "unknown"):
            self.assertFalse(remote.recover_eligible(state, verified=False, include_unverified_results=True))


# ---- path scopes ------------------------------------------------------------------------------------------------------------------------------

class Scopes(Case):
    def setUp(self):
        super().setUp()
        self.setup = cts.engine_setup(self.dir / "engine")
        self.engine = self.setup.plan(cts.engine_request(
            {"id": "l1", "operation": "locate", "kind": "class", "name": "Lfoo;"}))["provider"]["engine"]
        self.state = self.dir / "state"
        self.ns = provider.namespaces(self.state, self.engine, self.setup.config)
        provider.ensure_namespaces(self.ns, self.engine)

    def test_hostlabs_scopes_stay_hostlabs_and_the_engine_has_its_own_copy_of_each(self):
        table = remote.scope_table(self.state, self.ns)
        for scope in ("samples", "reports", "source-snapshots", "artifact-cache"):
            self.assertIn(scope, table)
        for name, entry in table.items():
            self.assertEqual(entry["hostlab"], str(self.state.resolve() / name))
            self.assertEqual(entry["adapter_access"], "read" if name == "samples" else "none")
            mine, theirs = Path(entry["engine"]), Path(entry["hostlab"])
            self.assertTrue(mine.is_relative_to(self.ns["root"]), name)
            self.assertFalse(mine.is_relative_to(theirs) or theirs.is_relative_to(mine), name)
        engine = Path(self.ns["reports"]).name
        self.assertEqual(table["artifact-cache"]["engine"], str(Path(self.ns["root"]) / "remote" / engine / "artifact-cache"))
        self.assertEqual(table["reports"]["engine"], str(self.ns["reports"]))
        self.assertEqual(set(table), set(remote.SCOPES))
        for name in provider.LEGACY_NAMES:
            self.assertIn(name, table)  # every directory the provider keeps clear of is a scope here

    def test_the_adapter_writes_only_in_the_engines_directories(self):
        for name in ("root", "cache", "reports", "completion"):
            inside = Path(self.ns[name]) / "x" / "y.json"
            self.assertEqual(remote.assert_writable(inside, self.state, self.ns), inside.resolve())
        self.assertEqual(remote.assert_writable(Path(self.ns["root"]) / "remote" / "e" / "artifact-cache" / "z", self.state, self.ns).name, "z")
        outside = [self.state / name / "file" for name in remote.SCOPES] + [self.state / "other", self.dir / "elsewhere",
                                                                          Path(self.ns["root"]).parent / "file",
                                                                          Path(self.ns["root"]) / ".." / "samples" / "x"]
        for path in outside:
            self.refused("write_outside_engine_namespace", remote.assert_writable, path, self.state, self.ns)

    def test_a_namespace_that_reaches_into_a_hostlab_scope_is_still_not_writable(self):
        hostile = dict(self.ns, cache=self.state / "artifact-cache" / "eng-x")  # a caller's mistake, or worse
        self.refused("write_outside_engine_namespace", remote.assert_writable, self.state / "artifact-cache" / "eng-x" / "file",
                     self.state, hostile)
        self.refused("write_outside_engine_namespace", remote.assert_writable, self.state / "samples" / "x", self.state,
                     dict(self.ns, completion=self.state / "samples"))

    def test_the_engines_cache_may_sit_beside_its_namespace_root(self):
        config = provider.parse_config({"schema": provider.CONFIG_SCHEMA, "native_engine": provider.ENGINE,
                                        provider.ENGINE: {"cache_dir": "mdd-cache", "profile_policy": "allow_unadmitted"}})
        ns = provider.namespaces(self.state, self.engine, config)
        self.assertFalse(Path(ns["cache"]).is_relative_to(ns["root"]))
        target = Path(ns["cache"]) / "index" / "x.bin"
        self.assertEqual(remote.assert_writable(target, self.state, ns), target.resolve())
        self.refused("write_outside_engine_namespace", remote.assert_writable, Path(ns["cache"]).parent / "other" / "x", self.state, ns)

    def test_the_engine_cannot_be_given_a_cache_directory_inside_a_hostlab_scope(self):
        for scope in ("samples", "reports", "source-snapshots", "artifact-cache", "remote-output"):
            config = provider.parse_config({"schema": provider.CONFIG_SCHEMA, "native_engine": provider.ENGINE,
                                            provider.ENGINE: {"cache_dir": scope, "profile_policy": "allow_unadmitted"}})
            with self.assertRaises(provider.NamespaceCollision, msg=scope):
                provider.namespaces(self.state, self.engine, config)

    def test_the_engine_reads_a_staged_sample_by_its_hash_and_nothing_else(self):
        data = b"sample bytes"
        sha = hashlib.sha256(data).hexdigest()
        staged = self.state / "samples" / sha / "base.apk"
        staged.parent.mkdir(parents=True)
        staged.write_bytes(data)
        self.assertEqual(remote.sample_path(self.state, sha), staged.resolve())
        for bad in ("../" + sha, sha.upper(), sha[:-1], "", None, 5, sha + "/base.apk"):
            self.refused("invalid_sample", remote.sample_path, self.state, bad)
        self.refused("sample_missing", remote.sample_path, self.state, "0" * 64)
        staged.write_bytes(b"swapped")
        self.refused("sample_changed", remote.sample_path, self.state, sha, component="sha256")
        self.assertEqual(remote.sample_path(self.state, sha, verify=False), staged.resolve())


# ---- every refusal is declared ----------------------------------------------------------------------------------------------------------------------------

class Reasons(Case):
    def test_every_reason_has_an_engine_code_that_can_never_cause_a_fallback(self):
        for reason, code in remote.REASONS.items():
            self.assertIn(code, provider.ENGINE_CODES, reason)
            self.assertNotIn(code, provider.FALLBACK_ELIGIBLE, reason)
        error = remote.RemoteRefused("run_mismatch", "m", component="c")
        self.assertEqual((error.reason, error.component, error.code), ("run_mismatch", "c", "STALE_CACHE"))
        self.assertIsInstance(error, ValueError)
        self.assertEqual(str(remote.RemoteRefused("run_mismatch")), "run_mismatch")
        self.assertIsInstance(remote.DispatchRefused("dispatch_refused"), remote.RemoteRefused)

    def test_every_reason_the_code_names_is_declared(self):
        tree = ast.parse((Path(__file__).resolve().parent / "remote_runner_adapter.py").read_text(encoding="utf-8"))
        used = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") in ("RemoteRefused", "DispatchRefused"):
                if node.args and isinstance(node.args[0], ast.Constant):
                    used.add(node.args[0].value)
        self.assertGreater(len(used), 20)
        self.assertLessEqual(used, set(remote.REASONS), sorted(used - set(remote.REASONS)))


if __name__ == "__main__":
    unittest.main()
