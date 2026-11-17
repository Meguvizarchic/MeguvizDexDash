"""Checkpoint adapter: identity, page position, state, import, capture, writer, completion cache, replay, read-back.

Run: python -I -m unittest discover -s integrations/hostlab -p "test_checkpoint_adapter.py"
No network, no real engine (test_checkpoint_live_engine.py uses it). HostLab's frozen batch executor and paging module
(conformance/corpus/hostlab/source-8782f43, hash-checked) run unchanged; the engine is a scripted stand-in whose
answers have the real shape.
"""
import ast
import asyncio
import copy
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import checkpoint_adapter as ca  # noqa: E402
import checkpoint_test_support as cts  # noqa: E402
import hostlab_test_support as support  # noqa: E402
import provider  # noqa: E402

ROOT = support.ROOT
PAGING = support.load_frozen("analysis_paging")


def query(**extra):
    return {"id": "q", "operation": "query", "sql": cts.NUMBERS, "dialect": "dexsql", "limit": 3, **extra}


LOC = {"id": "l1", "operation": "locate", "kind": "class", "name": "Lfoo;"}
LOC2 = dict(LOC, id="l2")
INFO = {"id": "i", "operation": "info"}


def reseal(document):
    """What a forger without a key can do: change the body and compute the seal again."""
    body = {key: document[key] for key in ca._BODY}
    return dict(document, seal={"algorithm": "sha256", "digest": ca.digest_of(body)})


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.dir = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)
        self.count = 0

    def flow(self, *tasks, **kwargs):
        self.count += 1
        return cts.Flow(self.dir / f"flow{self.count}", cts.engine_request(*tasks), **kwargs)

    def refused(self, reason, function, *args, component=None, **kwargs):
        with self.assertRaises(ca.CheckpointRefused) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.reason, reason)
        if component is not None:
            self.assertEqual(caught.exception.component, component)
        return caught.exception


# ---- identity -----------------------------------------------------------------------------------------------------------

class Identity(Case):
    def test_the_identity_records_engine_profile_schema_source_rule_and_config(self):
        flow = self.flow(query(), LOC, rule_catalog="ab" * 32, catalog_epoch=0)
        identity = flow.expected
        engine = flow.engine
        self.assertEqual(identity["schema"], ca.IDENTITY_SCHEMA)
        self.assertEqual(identity["versions"], {"checkpoint": ca.CHECKPOINT_SCHEMA, "adapter": ca.ADAPTER_SCHEMA,
                                                "report": 1, "request": 1, "paging": "compat_offset"})
        for key in ("engine_version", "build_id", "binary_sha256", "profile", "dialect", "config_digest", "mcp_tools_sha256"):
            self.assertEqual(identity["engine"][key], engine[key], key)
        self.assertEqual(identity["engine"]["config_digest"], flow.setup.config.digest())
        self.assertEqual(identity["generation"], {"namespace": provider.engine_dir(engine), "catalog_epoch": 0})
        self.assertEqual(identity["rule"], {"request_sha256": provider.request_fingerprint(flow.request, flow.setup.legacy),
                                            "catalog_sha256": "ab" * 32})
        self.assertEqual(identity["source"], {"sha256": flow.sha, "revision": "rev-1"})
        self.assertIsNone(identity["snapshot"])

    def test_a_resumed_request_keeps_the_identity_of_the_original(self):
        flow = self.flow(query(), LOC)
        resumed = dict(flow.request, resume={"run_id": 5, "attempt": 1, "request_id": "a" * 32})
        again = ca.expected_identity(flow.plan, flow.setup.config, request=resumed, sha256=flow.sha, revision="rev-1",
                                     legacy=flow.setup.legacy)
        self.assertEqual(again, flow.expected)
        _, with_resume, sealed = ca.normalize_request(resumed, flow.setup.legacy)
        self.assertNotIn("resume", sealed)
        self.assertEqual(with_resume, flow.expected["rule"]["request_sha256"])
        # HostLab's own fingerprint is not stable under resume, which is why the adapter strips it
        self.assertNotEqual(flow.setup.legacy.fingerprint(dict(flow.frozen_request(), resume=resumed["resume"])),
                            flow.setup.legacy.fingerprint(flow.frozen_request()))

    def test_a_request_for_the_engine_never_shares_an_identity_with_the_same_request_for_dexsql(self):
        flow = self.flow(query(), LOC)
        legacy = flow.setup.legacy
        _, for_engine, _ = ca.normalize_request(flow.request, legacy)
        _, for_dexsql, _ = ca.normalize_request(dict(flow.request, backend="dexsql"), legacy)
        self.assertNotEqual(for_engine, for_dexsql)

    def test_a_plan_that_does_not_use_the_engine_has_no_checkpoint_identity(self):
        flow = self.flow(query(), LOC)
        legacy_plan = provider.plan(dict(flow.request, backend="dexsql"), flow.setup.config, legacy=flow.setup.legacy)
        self.refused("plan_does_not_use_engine", ca.expected_identity, legacy_plan, flow.setup.config,
                     request=flow.request, sha256=flow.sha, legacy=flow.setup.legacy)

    def test_a_plan_made_under_another_configuration_is_refused(self):
        flow = self.flow(query(), LOC)
        other = provider.parse_config({"schema": provider.CONFIG_SCHEMA, "native_engine": provider.ENGINE,
                                       provider.ENGINE: {"profile_policy": "allow_unadmitted", "max_datasets": 2}})
        self.assertNotEqual(other.digest(), flow.setup.config.digest())
        self.refused("config_changed", ca.expected_identity, flow.plan, other, request=flow.request, sha256=flow.sha,
                     legacy=flow.setup.legacy)

    def test_malformed_inputs_are_refused(self):
        flow = self.flow(query(), LOC)
        common = dict(request=flow.request, legacy=flow.setup.legacy)

        def build(**changes):
            return ca.expected_identity(flow.plan, flow.setup.config, **{**common, "sha256": flow.sha, **changes})

        for bad in ("A" * 64, "ab" * 31, "", None, 5):
            self.refused("source_changed", build, sha256=bad, component="sha256")
        for bad in ("", 3, "x" * 257):
            self.refused("source_changed", build, revision=bad, component="revision")
        self.assertIsNone(build(revision=None)["source"]["revision"])
        for bad in ("zz", "ab" * 31, 5):
            self.refused("rule_changed", build, rule_catalog_sha256=bad)
        for bad in (-1, True, "0", 1.5):
            self.refused("generation_changed", build, catalog_epoch=bad)
        broken = copy.deepcopy(flow.plan)
        del broken["provider"]["engine"]["mcp_tools_sha256"]
        self.refused("malformed_checkpoint", ca.expected_identity, broken, flow.setup.config, request=flow.request,
                     sha256=flow.sha, legacy=flow.setup.legacy)


class Snapshot(Case):
    def opened(self, apk=cts.APK_A):
        server = cts.FakeDexsql()
        failed, body = server.answer("open_dataset", {"inputs": [str(apk)]})
        self.assertFalse(failed)
        return body

    def test_the_session_handles_change_on_every_open_and_the_identity_does_not(self):
        first, second = self.opened(), self.opened()
        server = cts.FakeDexsql()
        server.opens = 7
        third = server.answer("open_dataset", {"inputs": [str(cts.APK_A)]})[1]
        for key in ("dataset_id", "snapshot_id", "scope_id"):
            self.assertNotEqual(first[key], third[key], key)
        self.assertEqual(ca.snapshot_identity(first), ca.snapshot_identity(third))
        self.assertEqual(ca.snapshot_identity(first), ca.snapshot_identity(second))
        self.assertEqual(set(ca.snapshot_identity(first)), {"content_key", "inputs"})
        self.assertEqual(ca.handles(first), {key: first[key] for key in ("dataset_id", "snapshot_id", "scope_id")})

    def test_the_identity_follows_the_bytes_not_the_path(self):
        copy_path = self.dir / "elsewhere.apk"
        shutil.copyfile(cts.APK_A, copy_path)
        self.assertEqual(ca.snapshot_identity(self.opened(cts.APK_A)), ca.snapshot_identity(self.opened(copy_path)))
        other = ca.snapshot_identity(self.opened(cts.APK_B))
        self.assertNotEqual(ca.snapshot_identity(self.opened(cts.APK_A))["content_key"], other["content_key"])
        self.assertEqual(ca.snapshot_identity(self.opened(cts.APK_A))["inputs"][0]["content_id"],
                         "sha256:" + cts.sha256_file(cts.APK_A))

    def test_an_unreadable_manifest_is_refused(self):
        good = self.opened()

        def broken(edit):
            body = copy.deepcopy(good)
            edit(body["snapshot_manifest"])
            return body

        cases = [
            lambda m: m.pop("snapshot_content_key"), lambda m: m.update(snapshot_content_key="sha256:" + "A" * 64),
            lambda m: m.update(snapshot_content_key="abc"), lambda m: m.update(sources=[]), lambda m: m.update(sources="x"),
            lambda m: m["sources"][0].update(content_id="nope"), lambda m: m["sources"][0].pop("input_kind"),
            lambda m: m["sources"][0].update(input_kind=3), lambda m: m["sources"][0].update(input_ordinal="1"),
            lambda m: m["sources"][0].update(input_ordinal="-1"), lambda m: m["sources"][0].update(byte_length="x"),
            lambda m: m["sources"][0].update(byte_length=True), lambda m: m["sources"][0].pop("byte_length"),
            lambda m: m["sources"][0].update(byte_length="²"), lambda m: m["sources"][0].update(byte_length="٣"),
            lambda m: m["sources"][0].update(byte_length=1.5), lambda m: m["sources"][0].update(input_ordinal=None),
            lambda m: m["sources"].append(dict(m["sources"][0])), lambda m: m["sources"].__setitem__(0, "x"),
        ]
        for index, edit in enumerate(cases):
            with self.subTest(index):
                self.refused("snapshot_unreadable", ca.snapshot_identity, broken(edit))
        self.refused("snapshot_unreadable", ca.snapshot_identity, {"dataset_id": "d"})
        self.refused("snapshot_unreadable", ca.snapshot_identity, None)

    def test_the_captured_bytes_must_be_the_bytes_hostlab_hashed(self):
        snapshot = ca.snapshot_identity(self.opened())
        ca.bind_to_sample(snapshot, cts.sha256_file(cts.APK_A))
        self.refused("source_binding_mismatch", ca.bind_to_sample, snapshot, cts.sha256_file(cts.APK_B), component="sha256")
        two = copy.deepcopy(snapshot)
        two["inputs"].append(dict(two["inputs"][0], ordinal=1))
        self.refused("source_binding_mismatch", ca.bind_to_sample, two, cts.sha256_file(cts.APK_A))


# ---- page position ----------------------------------------------------------------------------------------------------------

class Position(Case):
    def partial(self):
        flow = self.flow(query(pagination={"max_pages": 1}), LOC)
        attempt = flow.attempt()
        entry = next(t for t in attempt.report["tasks"] if t["id"] == "q")
        definition = flow.setup.legacy.validate(flow.frozen_request())["tasks"][0]
        return flow, attempt, entry, definition

    def test_a_partial_query_is_recorded_as_a_compatible_offset(self):
        flow, attempt, entry, task = self.partial()
        position = ca.page_position(task, entry["result"])
        rows = entry["result"]["typed_result"]["statements"][0]["rows"]
        self.assertEqual(position, {
            "schema": ca.POSITION_SCHEMA, "mode": "compat_offset", "task": "q",
            "sql_sha256": hashlib.sha256(cts.NUMBERS.encode()).hexdigest(), "start_offset": 0, "next_offset": 3, "rows": 3,
            "pages": 1, "total_rows": 7, "page_limit_cap": 3, "columns_sha256": ca.digest_of([["n", "utf8", False]]),
            "rows_sha256": ca.digest_of(rows)})
        self.assertEqual(attempt.document["state"]["tasks"][0]["position"], position)
        ca.check_position(position, task, entry["result"])

    def test_a_complete_result_has_no_position(self):
        flow = self.flow(query())
        attempt = flow.attempt()
        entry = attempt.report["tasks"][0]
        task = flow.setup.legacy.validate(flow.frozen_request())["tasks"][0]
        self.assertEqual(entry["status"], "complete")
        self.assertIsNone(ca.page_position(task, entry["result"]))
        self.refused("position_inconsistent", ca.check_position, {"mode": "compat_offset"}, task, entry["result"])

    def test_a_position_that_does_not_follow_from_the_rows_is_refused(self):
        _, _, entry, task = self.partial()
        result = entry["result"]
        changed = {
            "rows are missing": lambda r: r["typed_result"]["statements"][0]["rows"].pop(),
            "offset moved": lambda r: r["typed_result"]["statements"][0].update(next_offset=4),
            "offset and pagination moved together": lambda r: (r["typed_result"]["statements"][0].update(next_offset=4),
                                                               r["pagination"].update(next_offset=4)),
            "start moved": lambda r: r["typed_result"]["statements"][0].update(offset=1),
            "pagination disagrees": lambda r: r["pagination"].update(next_offset=2),
            "sql changed": lambda r: r["pagination"].update(sql_sha256="0" * 64),
            "pages unknown": lambda r: r["pagination"].update(pages=0),
            "flat rows differ": lambda r: r["rows"].pop(),
            "offset beyond budget": lambda r: r["typed_result"]["statements"][0].update(next_offset=100001),
            "cursor is text": lambda r: r["typed_result"]["statements"][0].update(next_offset="3"),
            "no pagination": lambda r: r.pop("pagination"),
        }
        for label, edit in changed.items():
            with self.subTest(label):
                broken = copy.deepcopy(result)
                edit(broken)
                self.refused("position_inconsistent", ca.page_position, task, broken)
        self.refused("position_inconsistent", ca.page_position, task, {"rows": []})
        self.refused("position_inconsistent", ca.page_position, dict(task, offset="0"), result)

    def test_a_native_cursor_is_never_recorded(self):
        _, _, entry, task = self.partial()
        position = ca.page_position(task, entry["result"])
        for extra in ({"cursor": "tok"}, {"next_cursor": "tok"}, {"cursor_token": "tok"}):
            self.refused("native_cursor_not_persistable", ca.check_position, dict(position, **extra), task, entry["result"])
        self.refused("native_cursor_not_persistable", ca.check_position, dict(position, mode="native_snapshot"), task, entry["result"])
        self.refused("position_inconsistent", ca.check_position, dict(position, next_offset=4), task, entry["result"])
        self.refused("position_inconsistent", ca.check_position, None, task, entry["result"])

    def test_the_next_page_must_continue_the_admitted_prefix(self):
        _, _, entry, task = self.partial()
        position = ca.page_position(task, entry["result"])
        page = {"offset": 3, "total_rows": 7, "columns": [{"name": "n", "data_type": "utf8", "nullable": False}]}
        ca.next_page_check(position, page)
        self.refused("page_does_not_continue", ca.next_page_check, position, dict(page, offset=4))
        self.refused("page_does_not_continue", ca.next_page_check, position, dict(page, offset=0))
        self.refused("page_does_not_continue", ca.next_page_check, position, dict(page, total_rows=8))
        self.refused("page_does_not_continue", ca.next_page_check, position, dict(page, total_rows=None))
        self.refused("page_does_not_continue", ca.next_page_check, position,
                     dict(page, columns=[{"name": "m", "data_type": "utf8", "nullable": False}]))
        ca.next_page_check(dict(position, total_rows=None), dict(page, total_rows=99))  # an unknown total claims nothing

    def test_a_native_cursor_maps_to_the_offset_the_executor_would_have_recorded(self):
        _, _, entry, task = self.partial()
        position = ca.page_position(task, entry["result"])
        binding = {"mode": "native_snapshot", "source_fingerprint": "ab" * 32, "worker_generation": "4",
                   "session_id": "s", "query_id": "q"}
        mapped = ca.compat_position_from_native(
            binding, task="q", sql_sha256=position["sql_sha256"], start_offset=0, rows_delivered=3, pages=1, total_rows=7,
            columns_sha256=position["columns_sha256"], rows_sha256=position["rows_sha256"])
        self.assertEqual({k: v for k, v in mapped.items() if k not in ("from_native", "page_limit_cap")},
                         {k: v for k, v in position.items() if k != "page_limit_cap"})
        self.assertEqual(mapped["from_native"], {"source_fingerprint": "ab" * 32, "worker_generation": "4", "cursor": "dropped"})
        self.assertNotIn("cursor", mapped)
        self.assertNotIn("next_cursor", mapped)
        args = dict(task="q", sql_sha256="0" * 64, start_offset=0, rows_delivered=3, pages=1, total_rows=7,
                    columns_sha256="1" * 64, rows_sha256="2" * 64)
        for label, changes in {"compat binding": {"binding": dict(binding, mode="compat_offset")},
                               "bad fingerprint": {"binding": dict(binding, source_fingerprint="AB" * 32)},
                               "negative rows": {"rows_delivered": -1}, "bool rows": {"rows_delivered": True},
                               "past the budget": {"start_offset": 99999, "rows_delivered": 2},
                               "total below delivery": {"total_rows": 2}, "text total": {"total_rows": "7"},
                               "no binding": {"binding": None}}.items():
            with self.subTest(label):
                self.refused("position_inconsistent", ca.compat_position_from_native,
                             **{"binding": binding, **args, **changes})
        self.assertIsNone(ca.compat_position_from_native(binding, **dict(args, total_rows=None))["total_rows"])


# ---- state ---------------------------------------------------------------------------------------------------------------------

class State(Case):
    def test_each_ending_is_told_apart(self):
        complete = self.flow(LOC, INFO).attempt()
        self.assertEqual(complete.document["state"]["termination"], "complete")
        self.assertEqual([t["disposition"] for t in complete.document["state"]["tasks"]], ["reuse", "reuse"])
        self.assertEqual(complete.document["state"]["failure_codes"], [])

        partial = self.flow(query(pagination={"max_pages": 1}), LOC).attempt()
        self.assertEqual(partial.document["state"]["termination"], "partial")
        self.assertEqual([(t["id"], t["disposition"]) for t in partial.document["state"]["tasks"]],
                         [("q", "continue"), ("l1", "reuse")])

        lost = self.flow(query(), LOC)
        lost.server.hooks.append(cts.worker_lost_after(2))
        lost = lost.attempt()
        self.assertEqual(lost.document["state"]["termination"], "worker_lost")
        self.assertEqual(lost.document["state"]["failure_codes"], ["WORKER_LOST"])
        self.assertEqual([(t["id"], t["status"], t["disposition"]) for t in lost.document["state"]["tasks"]],
                         [("q", "partial", "continue"), ("l1", "skipped", "rerun")])

        cancelled = self.flow(query(), LOC)
        cancelled.server.hooks.append(cts.worker_lost_after(
            2, {"error": {"kind": "cancelled", "code": "CANCELLED", "message": "cancelled", "dataset_closed": True}}))
        cancelled = cancelled.attempt()
        self.assertEqual(cancelled.document["state"]["termination"], "cancelled")

    def test_a_changed_source_ends_the_run_as_source_changed_whatever_else_is_said(self):
        flow = self.flow(LOC, INFO)
        flow.apk = self.dir / "moving.apk"
        shutil.copyfile(cts.APK_A, flow.apk)
        flow.sha = cts.sha256_file(flow.apk)

        def swap(name, arguments):
            if name == "query" and "classes" in arguments["sql"][0]:
                shutil.copyfile(cts.APK_B, flow.apk)  # the bytes change while the run is in progress
            return None

        flow.server.hooks.append(swap)
        attempt = flow.attempt(hint="cancelled")
        self.assertIs(attempt.report["source_unchanged"], False)
        self.assertEqual(attempt.document["state"]["termination"], "source_changed")
        self.assertEqual([t["disposition"] for t in attempt.document["state"]["tasks"]], ["rerun", "rerun"])
        self.refused("source_changed", ca.import_checkpoint, attempt.document, flow.expected, legacy=flow.setup.legacy)

    def test_the_hint_can_only_make_an_ending_worse(self):
        flow = self.flow(LOC, INFO)
        report = flow.attempt().report
        request = flow.setup.legacy.validate(flow.frozen_request())
        self.assertEqual(ca.derive_state(report, request, final=True)["termination"], "complete")
        for hint in ("cancelled", "worker_lost"):
            self.assertEqual(ca.derive_state(report, request, final=True, hint=hint)["termination"], hint)
        for bad in ("complete", "partial", "", 3):
            self.refused("invalid_hint", ca.derive_state, report, request, final=True, hint=bad)
        self.assertEqual(ca.derive_state(report, request, final=False)["termination"], "in_flight")
        self.assertEqual({t["disposition"] for t in ca.derive_state(report, request, final=False)["tasks"]}, {"rerun"})
        unverified = dict(report, source_unchanged=None)
        self.assertEqual(ca.derive_state(unverified, request, final=True)["termination"], "source_changed")
        self.assertEqual(ca.derive_state(dict(report, source_unchanged="yes"), request, final=True)["termination"], "source_changed")

    def test_a_failed_session_keeps_a_complete_report_from_being_complete(self):
        flow = self.flow(LOC, INFO)
        report = flow.attempt().report
        request = flow.setup.legacy.validate(flow.frozen_request())
        with_failure = copy.deepcopy(report)
        with_failure["sessions"].append({"backend": "dexsql", "error": "RuntimeError", "message": "closing failed", "detail": None})
        self.assertEqual(ca.derive_state(with_failure, request, final=True)["termination"], "partial")
        self.assertEqual(ca.derive_state(dict(report, complete=False), request, final=True)["termination"], "partial")
        fewer = copy.deepcopy(report)
        fewer["tasks"].pop()
        self.assertEqual(ca.derive_state(dict(fewer, complete=True), request, final=True)["termination"], "partial")
        self.assertEqual(ca.derive_state(dict(report, tasks=[]), request, final=True)["termination"], "partial")

    def test_duplicate_task_ids_never_make_a_report_complete(self):
        flow = self.flow(LOC, INFO)
        report = flow.attempt().report
        request = flow.setup.legacy.validate(flow.frozen_request())
        self.assertEqual(ca.derive_state(report, request, final=True)["termination"], "complete")
        # same count, but one id duplicated and the other missing: the id set differs
        replaced = copy.deepcopy(report)
        replaced["tasks"][1] = copy.deepcopy(replaced["tasks"][0])
        self.assertEqual(ca.derive_state(dict(replaced, complete=True), request, final=True)["termination"], "partial")
        # same id set, but a duplicate makes the count differ
        extra = copy.deepcopy(report)
        extra["tasks"].append(copy.deepcopy(extra["tasks"][1]))
        self.assertEqual(ca.derive_state(dict(extra, complete=True), request, final=True)["termination"], "partial")

    def test_worker_loss_and_cancellation_are_found_by_engine_code_or_by_exception_type(self):
        flow = self.flow(LOC, INFO)
        report = flow.attempt().report
        request = flow.setup.legacy.validate(flow.frozen_request())
        for record, code in ((dict(error="WorkerLost", message="gone", detail=None), "WORKER_LOST"),
                             (dict(error="Cancelled", message="stop", detail=None), "CANCELLED"),
                             (dict(error="CancelledError", message="stop", detail=None), "CANCELLED"),
                             (dict(error="BackendError", message="x", detail={"error": {"code": "WORKER_LOST"}}), "WORKER_LOST"),
                             (dict(error="BackendError", message="x", detail={"error": {"code": "DEADLINE_EXCEEDED"}}), "DEADLINE_EXCEEDED"),
                             (dict(error="RuntimeError", message="x", detail=None), "UNCLASSIFIED")):
            with self.subTest(code):
                broken = copy.deepcopy(report)
                broken["sessions"].append(dict(record, backend="dexsql"))
                self.assertEqual(ca.failure_codes(broken), {code})
        errored = copy.deepcopy(report)
        errored["tasks"][0] = {"id": "l1", "backend": "dexsql", "status": "error", "reason": "backend_request_failed",
                               "error": "WorkerLost", "message": "gone", "detail": None}
        self.assertEqual(ca.failure_codes(errored), {"WORKER_LOST"})
        errored["tasks"][0] = dict(report["tasks"][0], failure={"error": "Cancelled", "message": "", "detail": None})
        self.assertEqual(ca.failure_codes(errored), {"CANCELLED"})

    def test_a_partial_locate_is_never_seeded_because_the_frozen_executor_cannot_continue_it(self):
        flow = self.flow(dict(LOC, limit=1))
        flow.server.rules.insert(0, ("FROM classes WHERE descriptor", (["file_id", "descriptor"], [[0, "Lfoo;"], [1, "Lfoo;"]])))
        attempt = flow.attempt()
        entry = attempt.report["tasks"][0]
        self.assertEqual(entry["status"], "partial")
        state = attempt.document["state"]["tasks"][0]
        self.assertEqual((state["operation"], state["disposition"], state["position"], state["position_problem"]),
                         ("locate", "rerun", None, None))  # not "continue", and not a position that failed to check
        # the frozen executor, given that task as a resume seed, stops before running anything
        batch = cts.load_batch(self.dir, flow.server)
        seed = {"plan": attempt.report["plan"], "sessions": [s for s in attempt.report["sessions"] if "files" in s],
                "tasks": [entry], "resume_origin": {}}
        request = dict(flow.frozen_request(), resume={"run_id": 1, "attempt": 1, "request_id": "a" * 32})
        with self.assertRaises(KeyError) as caught:  # QueryPages reads task["offset"], which a locate task does not have
            cts.run(batch, flow.apk, request, resume=seed)
        self.assertEqual(caught.exception.args, ("offset",))
        self.refused("nothing_reusable", ca.import_checkpoint(attempt.document, flow.expected, legacy=flow.setup.legacy).seed)

    def test_an_inconsistent_partial_query_is_rerun_not_continued(self):
        flow = self.flow(query(pagination={"max_pages": 1}))
        attempt = flow.attempt()
        report = copy.deepcopy(attempt.report)
        report["tasks"][0]["result"]["pagination"]["next_offset"] = 2
        state = ca.derive_state(report, flow.setup.legacy.validate(flow.frozen_request()), final=True)
        self.assertEqual((state["tasks"][0]["disposition"], state["tasks"][0]["position"],
                          state["tasks"][0]["position_problem"]), ("rerun", None, "position_inconsistent"))


# ---- sealing and importing ----------------------------------------------------------------------------------------------------

class SealAndImport(Case):
    def setUp(self):
        super().setUp()
        self.flow_ = self.flow(query(pagination={"max_pages": 1}), LOC)
        self.attempt = self.flow_.attempt()
        self.document = self.attempt.document
        self.expected = self.flow_.expected
        self.legacy = self.flow_.setup.legacy

    def load(self, document=None, expected=None, **kwargs):
        return ca.import_checkpoint(document or self.document, expected or self.expected, legacy=self.legacy, **kwargs)

    def test_a_partial_checkpoint_is_resumable_but_never_a_success(self):
        resume = self.load(claim=self.attempt.origin)
        self.assertEqual(resume.termination, "partial")
        self.assertFalse(resume.success)
        self.assertEqual(resume.tasks("reuse"), ["l1"])
        self.assertEqual(resume.tasks("continue"), ["q"])
        self.assertFalse(resume.source_bound)
        self.assertEqual(resume.lineage()["seal"], ca.seal_digest(self.document))
        self.assertEqual(resume.lineage()["identity_sha256"], ca.digest_of(self.document["identity"]))
        seed = resume.seed()
        self.assertEqual({t["id"] for t in seed["tasks"]}, {"q", "l1"})
        self.assertEqual(seed["resume_origin"], resume.lineage())
        self.assertEqual(seed["plan"], self.document["report"]["plan"])
        self.assertTrue(all("files" in s for s in seed["sessions"]) and seed["sessions"])
        seed["tasks"][0]["status"] = "tampered"  # the seed is a copy
        self.assertNotEqual(self.document["report"]["tasks"][0]["status"], "tampered")

    def test_a_complete_checkpoint_is_the_only_one_that_is_a_success(self):
        complete = self.flow(LOC, INFO)
        attempt = complete.attempt()
        resume = ca.import_checkpoint(attempt.document, complete.expected, legacy=complete.setup.legacy)
        self.assertTrue(resume.success)
        self.assertEqual(resume.termination, "complete")

    def test_a_document_that_was_changed_after_sealing_is_refused(self):
        for label, edit in {
            "a row": lambda d: d["report"]["tasks"][1]["result"]["rows"].append(["x"]),
            "the identity": lambda d: d["identity"]["source"].update(revision="other"),
            "the origin": lambda d: d["origin"].update(run_id=9),
            "the seal": lambda d: d["seal"].update(digest="0" * 64),
            "the lineage": lambda d: d.update(resumed_from={"seal": "x"}),
        }.items():
            with self.subTest(label):
                broken = copy.deepcopy(self.document)
                edit(broken)
                self.refused("seal_mismatch", self.load, broken)
        for label, edit in {"no state": lambda d: d.pop("state"), "no seal": lambda d: d.pop("seal"),
                            "no report": lambda d: d.pop("report"), "no request": lambda d: d.pop("request"),
                            "no identity": lambda d: d.pop("identity")}.items():
            with self.subTest(label):
                broken = copy.deepcopy(self.document)
                edit(broken)
                self.refused("malformed_checkpoint", self.load, broken)
        broken = copy.deepcopy(self.document)
        broken["seal"] = "sha256"
        self.refused("seal_mismatch", self.load, broken)
        broken = copy.deepcopy(self.document)
        broken["seal"]["algorithm"] = "md5"  # the digest itself is right
        self.refused("seal_mismatch", self.load, broken)
        for bad in ([], "path", None, 5, b"{}"):
            self.refused("malformed_checkpoint", ca.import_checkpoint, bad, self.expected, legacy=self.legacy)

    def test_a_state_that_does_not_follow_from_its_report_is_refused_even_with_a_valid_seal(self):
        forged = copy.deepcopy(self.document)
        forged["state"]["termination"] = "complete"
        self.refused("state_mismatch", self.load, reseal(forged))
        forged = copy.deepcopy(self.document)
        forged["state"]["tasks"][1]["disposition"] = "continue"
        self.refused("state_mismatch", self.load, reseal(forged))
        forged = copy.deepcopy(self.document)
        forged["request"]["tasks"][0]["limit"] = 4
        self.refused("state_mismatch", self.load, reseal(forged))
        forged = copy.deepcopy(self.document)
        forged["request"] = {"tasks": []}
        self.refused("state_mismatch", self.load, reseal(forged))
        forged = copy.deepcopy(self.document)
        forged["request"]["resume"] = {"run_id": 1, "attempt": 1, "request_id": "a" * 32}  # a request is sealed without its resume
        self.refused("state_mismatch", self.load, reseal(forged))
        forged = copy.deepcopy(self.document)
        forged["state"]["hint"] = "bogus"
        self.refused("state_mismatch", self.load, reseal(forged))
        forged = copy.deepcopy(self.document)
        forged["report"]["tasks"][0]["result"]["rows"].append(["9"])
        self.refused("state_mismatch", self.load, reseal(forged))  # the position no longer matches the rows

    def test_old_and_unknown_formats_are_refused_not_upgraded(self):
        for schema in (2, 1, 3):
            self.refused("legacy_checkpoint_not_upgraded", self.load, dict(self.document, schema=schema))
        for schema in ("mdd.hostlab-checkpoint.v0", "mdd.hostlab-checkpoint.v2", None, 2.0, True):
            error = self.refused("unknown_checkpoint_schema", self.load, dict(self.document, schema=schema))
            self.assertEqual(error.code, "STALE_CACHE")

    def test_an_in_flight_checkpoint_is_never_resumed(self):
        flow = self.flow(query(), LOC)
        flow.attempt()
        inflight = json.loads((flow.root / ca.CheckpointWriter.INFLIGHT).read_text(encoding="utf-8"))
        self.assertEqual(inflight["state"]["termination"], "in_flight")
        self.assertEqual({t["disposition"] for t in inflight["state"]["tasks"]}, {"rerun"})
        self.refused("checkpoint_not_sealed", ca.import_checkpoint, inflight, flow.expected, legacy=flow.setup.legacy)

    def test_each_component_of_the_identity_is_enforced_with_its_own_reason(self):
        def mutated(edit):
            expected = copy.deepcopy(self.expected)
            edit(expected)
            return expected

        cases = [
            ("schema_changed", "schema", lambda e: e["versions"].update(adapter=2)),
            ("schema_changed", "schema", lambda e: e.update(schema="mdd.hostlab-checkpoint-identity.v2")),
            ("engine_changed", "engine", lambda e: e["engine"].update(build_id="source-sha256:" + "cd" * 32)),
            ("engine_changed", "engine", lambda e: e["engine"].update(binary_sha256="0" * 64)),
            ("engine_changed", "engine", lambda e: e["engine"].update(engine_version="9.9")),
            ("engine_changed", "engine", lambda e: e["engine"].update(platform="elsewhere")),
            ("engine_changed", "engine", lambda e: e["engine"].update(extra="a future field")),
            ("capability_changed", "capability", lambda e: e["engine"].update(mcp_tools_sha256="0" * 64)),
            ("profile_changed", "profile", lambda e: e["engine"]["profile"].update(admitted=True)),
            ("profile_changed", "profile", lambda e: e["engine"]["profile"].update(name="other")),
            ("dialect_changed", "dialect", lambda e: e["engine"]["dialect"].update(engine="dexsql-0.1.1")),
            ("config_changed", "config", lambda e: e["engine"].update(config_digest="0" * 64)),
            ("generation_changed", "generation", lambda e: e["generation"].update(namespace="eng-other")),
            ("generation_changed", "generation", lambda e: e["generation"].update(catalog_epoch=1)),
            ("request_changed", "request_sha256", lambda e: e["rule"].update(request_sha256="0" * 64)),
            ("rule_changed", "catalog_sha256", lambda e: e["rule"].update(catalog_sha256="0" * 64)),
            ("source_changed", "sha256", lambda e: e["source"].update(sha256="0" * 64)),
            ("source_changed", "revision", lambda e: e["source"].update(revision="rev-2")),
            ("source_changed", "revision", lambda e: e["source"].update(revision=None)),
        ]
        for reason, component, edit in cases:
            with self.subTest(reason + "/" + component):
                error = self.refused(reason, self.load, expected=mutated(edit), component=component)
                self.assertIn(error.code, ("STALE_CACHE", "INVALID_ARGUMENT", "SOURCE_CHANGED"))
        self.assertIsNotNone(self.load(expected=mutated(lambda e: e.update(snapshot={"anything": 1}))))  # bound later

    def test_another_engine_build_profile_dialect_or_configuration_cannot_resume(self):
        other_build = cts.engine_setup(self.dir / "other-build", content=b"stand-in engine 2",
                                       fake=support.FakeEngine(build_id="source-sha256:" + "cd" * 32))
        for label, setup, reason in (
            ("another build", other_build, "engine_changed"),
            ("another dialect", cts.engine_setup(self.dir / "other-dialect", dialect="dexsql-0.1.1"), "dialect_changed"),
            ("another configuration", cts.engine_setup(self.dir / "other-config", max_datasets=2), "config_changed"),
        ):
            with self.subTest(label):
                request = self.flow_.request
                plan = setup.plan(request)
                expected = ca.expected_identity(plan, setup.config, request=request, sha256=self.flow_.sha, revision="rev-1",
                                                legacy=setup.legacy)
                self.refused(reason, ca.import_checkpoint, self.document, expected, legacy=setup.legacy)

    def test_a_changed_request_cannot_resume(self):
        other = self.flow(query(pagination={"max_pages": 2}), LOC)
        self.refused("request_changed", ca.import_checkpoint, self.document, other.expected, legacy=other.setup.legacy)

    def test_the_run_and_attempt_claimed_must_be_the_ones_that_made_the_checkpoint(self):
        origin = self.attempt.origin
        for key, value in (("run_id", origin["run_id"] + 1), ("attempt", 2), ("request_id", "f" * 32)):
            self.refused("origin_mismatch", self.load, claim=dict(origin, **{key: value}))
        self.refused("origin_mismatch", self.load, claim=dict(origin, sample_index=3))
        self.assertEqual(self.load(claim=origin).claim, origin)
        self.assertIsNone(self.load().claim)
        for bad in ({"run_id": 1}, dict(origin, extra=1), dict(origin, run_id=0), dict(origin, run_id=True),
                    dict(origin, request_id="XYZ"), dict(origin, sample_index=12), dict(origin, attempt="1")):
            self.refused("origin_invalid", self.load, claim=bad)
        without_origin = reseal(dict(self.document, origin=None))
        self.refused("origin_mismatch", self.load, without_origin, claim=origin)
        self.assertIsNone(self.load(without_origin).document["origin"])

    def test_an_oversized_document_is_refused(self):
        huge = copy.deepcopy(self.document)
        huge["report"]["padding"] = "x" * (ca.MAX_DOCUMENT_BYTES + 1)
        self.refused("document_too_large", self.load, huge)

    def test_the_snapshot_the_engine_opens_must_be_the_snapshot_of_the_checkpoint(self):
        resume = self.load()
        saved = self.document["identity"]["snapshot"]
        self.assertIsNotNone(saved)
        other_key = dict(saved, content_key="sha256:" + "0" * 64)
        other_inputs = copy.deepcopy(saved)
        other_inputs["inputs"][0]["byte_length"] += 1
        for snapshot in (other_key, other_inputs, {"content_key": saved["content_key"], "inputs": []}, {}):
            error = self.refused("snapshot_changed", resume.bind_source, snapshot, component="snapshot")
            self.assertEqual(error.code, "SOURCE_CHANGED")
            self.assertFalse(resume.source_bound)
        resume.bind_source(copy.deepcopy(saved))
        self.assertTrue(resume.source_bound)

    def test_a_resume_with_nothing_reusable_is_not_a_resume(self):
        flow = self.flow(query(), LOC)
        flow.server.hooks.append(cts.worker_lost_after(1))
        lost = flow.attempt()
        self.assertEqual([t["disposition"] for t in lost.document["state"]["tasks"]], ["rerun", "rerun"])
        resume = ca.import_checkpoint(lost.document, flow.expected, legacy=flow.setup.legacy)
        self.refused("nothing_reusable", resume.seed)


# ---- running through the frozen executor ----------------------------------------------------------------------------------------

class Execution(Case):
    def offsets(self, server):
        return [(a["offset"], a["limit"]) for a in server.sql_calls("FROM numbers")]

    def test_a_resumed_query_continues_at_its_cursor_and_nothing_runs_twice(self):
        flow = self.flow(query(pagination={"max_pages": 1}), LOC)
        first = flow.attempt()
        self.assertEqual(first.report["tasks"][0]["status"], "partial")
        second = flow.attempt(resume=flow.resume(first))
        self.assertEqual(second.report["tasks"][0]["status"], "partial")
        third = flow.attempt(resume=flow.resume(second))
        self.assertTrue(third.report["complete"])
        self.assertEqual(self.offsets(flow.server), [(0, 3), (3, 3), (6, 1)])  # no prefix is fetched again
        self.assertEqual(len(flow.server.sql_calls("FROM classes")), 1)  # the complete task ran once, in the first attempt
        self.assertEqual(third.report["execution"]["reused_complete_tasks"], 1)
        self.assertTrue(next(t for t in third.report["tasks"] if t["id"] == "l1")["checkpoint_reused"])
        rows = [row[0]["value"] for row in third.report["tasks"][0]["result"]["typed_result"]["statements"][0]["rows"]]
        self.assertEqual(rows, [str(n) for n in range(7)])
        # the same rows as one uninterrupted run, with nothing duplicated or dropped
        whole = self.flow(query(), LOC).attempt()
        self.assertEqual(rows, [row[0]["value"] for row in whole.report["tasks"][0]["result"]["typed_result"]["statements"][0]["rows"]])
        self.assertEqual(third.report["tasks"][0]["result"]["rows"], whole.report["tasks"][0]["result"]["rows"])
        self.assertEqual(third.document["state"]["termination"], "complete")
        self.assertEqual(third.document["resumed_from"]["seal"], ca.seal_digest(second.document))
        self.assertEqual(second.document["resumed_from"]["seal"], ca.seal_digest(first.document))
        self.assertIsNone(first.document["resumed_from"])

    def test_the_adapter_changes_nothing_the_executor_does(self):
        tasks = (query(), LOC, LOC2, INFO)
        wired = self.flow(*tasks)
        bare = self.flow(*tasks)
        with_adapter = wired.attempt()
        without = cts.run(bare.batch, bare.apk, bare.frozen_request(), sample={"sha256": bare.sha})
        self.assertEqual(cts.normalized(with_adapter.report), cts.normalized(without))
        self.assertEqual(wired.server.calls[1:], bare.server.calls[1:])  # the same calls, in the same order
        # the executor's own optimisations still fire: the non-query memo, one session, paged queries
        by_id = {t["id"]: t for t in with_adapter.report["tasks"]}
        self.assertEqual(by_id["l2"]["reused_from"], "l1")
        self.assertEqual(len(wired.server.sql_calls("FROM classes")), 1)
        self.assertEqual(with_adapter.report["execution"]["dataset_opens"], 1)
        self.assertEqual(with_adapter.report["execution"]["admitted_query_pages"], 3)

    def test_other_bytes_with_the_same_sql_schema_and_count_are_not_stitched_in(self):
        flow = self.flow(query(pagination={"max_pages": 1}), LOC)
        first = flow.attempt()
        # APK_B answers this query with identical rows, columns and totals, yet it is another source
        other = self.flow(query(pagination={"max_pages": 1}), LOC, apk=cts.APK_B)
        self.refused("source_changed", ca.import_checkpoint, first.document, other.expected, legacy=other.setup.legacy,
                     component="sha256")
        # HostLab says it hashed A, the engine captured B: refused when the dataset is opened, before a page is read
        resume = flow.resume(first)
        flow.server.reset()
        second = flow.attempt(resume=resume, apk=cts.APK_B, sha=flow.sha)
        self.assertEqual(flow.server.sql_calls("FROM numbers"), [])
        self.assertFalse(second.report["complete"])
        failure = second.report["sessions"][-1]
        self.assertEqual(failure["error"], "ResumeRefused")
        self.assertEqual(failure["detail"]["error"]["code"], "SOURCE_CHANGED")
        self.assertEqual(failure["detail"]["error"]["reason"], "source_binding_mismatch")
        self.assertEqual(second.document["state"]["termination"], "source_changed")
        self.refused("source_changed", ca.import_checkpoint, second.document, flow.expected, legacy=flow.setup.legacy)
        # the checkpoint it was refused from is untouched and still resumable
        self.assertEqual(flow.resume(first).termination, "partial")

    def test_another_capture_of_the_same_bytes_is_refused_before_any_page(self):
        flow = self.flow(query(pagination={"max_pages": 1}), LOC)
        first = flow.attempt()

        def recapture(body):
            body["snapshot_manifest"]["snapshot_content_key"] = "sha256:" + "0" * 64
            return body

        flow.server.reset()
        flow.server.open_edit = recapture
        second = flow.attempt(resume=flow.resume(first))
        self.assertEqual(flow.server.sql_calls("FROM numbers"), [])
        self.assertEqual(second.report["sessions"][-1]["detail"]["error"]["reason"], "snapshot_changed")
        self.assertEqual(second.document["state"]["termination"], "source_changed")

    def test_the_same_bytes_at_another_path_resume(self):
        flow = self.flow(query(pagination={"max_pages": 1}), LOC)
        first = flow.attempt()
        elsewhere = self.dir / "staged" / "base.apk"
        elsewhere.parent.mkdir()
        shutil.copyfile(cts.APK_A, elsewhere)
        second = flow.attempt(resume=flow.resume(first), apk=elsewhere)
        self.assertEqual(second.report["tasks"][0]["status"], "partial")
        self.assertEqual(self.offsets(flow.server), [(0, 3), (3, 3)])
        self.assertEqual(second.document["identity"]["snapshot"], first.document["identity"]["snapshot"])

    def test_a_lost_worker_keeps_the_admitted_prefix_but_is_not_a_result(self):
        flow = self.flow(query(), LOC)
        flow.server.hooks.append(cts.worker_lost_after(2))
        lost = flow.attempt()
        self.assertFalse(lost.report["complete"])
        self.assertEqual(lost.document["state"]["termination"], "worker_lost")
        resume = flow.resume(lost)
        self.assertFalse(resume.success)
        self.assertEqual(resume.tasks("continue"), ["q"])
        flow.server.hooks.clear()
        flow.server.reset()
        done = flow.attempt(resume=resume)
        self.assertTrue(done.report["complete"])
        self.assertEqual(self.offsets(flow.server), [(3, 3), (6, 1)])  # continued where the lost worker stopped
        self.assertEqual(done.document["state"]["termination"], "complete")
        self.assertEqual(len(flow.server.sql_calls("FROM classes")), 1)

    def test_a_cancelled_run_is_resumable_as_work_but_never_as_a_result(self):
        flow = self.flow(LOC, INFO)
        attempt = flow.attempt(hint="cancelled")
        self.assertTrue(attempt.report["complete"])  # the executor finished; the caller says it was cancelled
        self.assertEqual(attempt.document["state"]["termination"], "cancelled")
        resume = flow.resume(attempt)
        self.assertFalse(resume.success)
        self.assertEqual(resume.termination, "cancelled")


# ---- capture and writer ------------------------------------------------------------------------------------------------------------

class CaptureAndWriter(Case):
    def test_progress_is_replaced_and_the_final_report_is_never_overwritten(self):
        flow = self.flow(query(pagination={"max_pages": 1}), LOC)
        calls = []
        capture = ca.OpenCapture(sha256=flow.sha)
        flow.batch.Client = capture.wrap(flow.server.client)
        writer = ca.CheckpointWriter(flow.root, flow.expected, flow.request, origin={"run_id": 7, "attempt": 2, "request_id": "a" * 32},
                                     capture=capture, legacy=flow.setup.legacy)

        def watch(report, final):
            calls.append(final)
            writer(report, final)

        cts.run(flow.batch, flow.apk, flow.frozen_request(), sample={"sha256": flow.sha}, checkpoint=watch)
        self.assertEqual(calls[-1], True)
        self.assertGreaterEqual(len(calls), 3)
        self.assertEqual(calls.count(True), 1)
        self.assertEqual(sorted(p.name for p in flow.root.iterdir()), ["checkpoint-7-2.json", "checkpoint.inflight.json"])
        sealed = writer.path.read_bytes()
        with self.assertRaises(provider.NamespaceCollision):
            writer(writer.document["report"], True)
        self.assertEqual(writer.path.read_bytes(), sealed)
        self.assertEqual(json.loads(sealed.decode())["seal"]["digest"], ca.seal_digest(writer.document))

    def run_with_flaky_replace(self, failing_calls):
        """A run in which os.replace fails (a file scanner holding the destination) on the numbered calls; None = always."""
        flow = self.flow(query(pagination={"max_pages": 1}), LOC)
        real, seen = ca.os.replace, {"calls": 0}

        def replace(source, target):
            seen["calls"] += 1
            if failing_calls is None or seen["calls"] in failing_calls:
                raise PermissionError(13, "the file is held by another process")
            return real(source, target)

        with mock.patch.object(ca.os, "replace", replace), mock.patch.object(ca.time, "sleep") as slept:
            attempt = flow.attempt()
        return flow, attempt, seen["calls"], slept.call_count

    def test_a_progress_file_that_cannot_be_replaced_for_a_moment_does_not_stop_the_analysis(self):
        flow, attempt, calls, slept = self.run_with_flaky_replace({1, 2, 4})
        self.assertEqual([(t["id"], t["status"]) for t in attempt.report["tasks"]], [("q", "partial"), ("l1", "complete")])
        self.assertNotIn("failure", attempt.report["tasks"][0])
        self.assertEqual(attempt.writer.inflight_errors, [])
        self.assertGreaterEqual(calls, 4)
        self.assertEqual(slept, 3)  # each failure waited before the next try
        self.assertEqual(json.loads((flow.root / ca.CheckpointWriter.INFLIGHT).read_text(encoding="utf-8"))["state"]["termination"], "in_flight")

    def test_a_progress_file_that_cannot_be_written_at_all_is_listed_not_raised_and_the_final_seal_still_stands(self):
        flow, attempt, calls, slept = self.run_with_flaky_replace(None)
        self.assertEqual([(t["id"], t["status"]) for t in attempt.report["tasks"]], [("q", "partial"), ("l1", "complete")])
        errors = attempt.writer.inflight_errors
        self.assertGreaterEqual(len(errors), 2)
        self.assertEqual(set(errors), {"PermissionError"})
        self.assertEqual(calls, len(errors) * ca.CheckpointWriter.INFLIGHT_TRIES)  # every write was tried the full number of times
        self.assertEqual(slept, calls)
        self.assertFalse((flow.root / ca.CheckpointWriter.INFLIGHT).exists())
        self.assertEqual([p.name for p in flow.root.iterdir()], ["checkpoint-101-1.json"])  # no stray staged file, the seal is there
        self.assertEqual(attempt.document["state"]["termination"], "partial")
        self.assertEqual(ca.import_checkpoint(attempt.document, flow.expected, legacy=flow.setup.legacy).termination, "partial")

    def test_the_final_seal_is_never_best_effort(self):
        flow = self.flow(LOC, INFO)
        done = flow.attempt()
        again = ca.CheckpointWriter(flow.root, flow.expected, flow.request, origin=done.origin, capture=done.capture,
                                    legacy=flow.setup.legacy)
        with self.assertRaises(provider.NamespaceCollision):  # the same file again: an error, not a silent skip
            again(done.report, True)
        self.assertEqual(again.inflight_errors, [])

    def test_a_worker_that_dies_leaves_only_an_in_flight_checkpoint(self):
        flow = self.flow(query(), LOC)
        capture = ca.OpenCapture(sha256=flow.sha)
        flow.batch.Client = capture.wrap(flow.server.client)
        writer = ca.CheckpointWriter(flow.root, flow.expected, flow.request, capture=capture, legacy=flow.setup.legacy)
        finished = cts.run(flow.batch, flow.apk, flow.frozen_request(), sample={"sha256": flow.sha})
        writer(finished, False)  # a progress report, and then nothing: the process is gone
        self.assertEqual([p.name for p in flow.root.iterdir()], ["checkpoint.inflight.json"])
        self.assertIsNone(writer.path)
        read = ca.read_back(flow.root / "checkpoint.inflight.json", flow.expected, legacy=flow.setup.legacy)
        self.assertEqual((read.kind, read.termination, read.resumable_here, read.reason),
                         ("mdd_checkpoint", "in_flight", False, "checkpoint_not_sealed"))

    def test_the_engine_must_have_been_captured_when_it_was_used(self):
        flow = self.flow(LOC)
        with self.assertRaises(ca.CheckpointRefused) as caught:
            flow.attempt(wire_capture=False)
        self.assertEqual(caught.exception.reason, "source_not_bound")
        self.assertEqual(caught.exception.code, "SOURCE_CHANGED")
        self.assertEqual(list(flow.root.glob("checkpoint-*.json")), [])  # nothing sealed

    def test_a_resumed_run_that_opened_the_engine_must_have_bound_the_checkpoint(self):
        flow = self.flow(query(pagination={"max_pages": 1}), LOC)
        first = flow.attempt()
        resume = flow.resume(first)
        capture = ca.OpenCapture(sha256=flow.sha)  # not given the resume
        flow.batch.Client = capture.wrap(flow.server.client)
        writer = ca.CheckpointWriter(flow.root, flow.expected, flow.request, capture=capture, resume=resume, legacy=flow.setup.legacy)
        with self.assertRaises(ca.CheckpointRefused) as caught:
            cts.run(flow.batch, flow.apk, flow.frozen_request(resume.claim), sample={"sha256": flow.sha},
                    resume=resume.seed(), checkpoint=writer)
        self.assertEqual(caught.exception.reason, "source_not_bound")

    def test_a_resumed_run_that_captured_another_snapshot_is_refused_even_if_the_checkpoint_was_bound(self):
        flow = self.flow(query(pagination={"max_pages": 1}), LOC)
        first = flow.attempt()
        resume = flow.resume(first)
        resume.bind_source(first.document["identity"]["snapshot"])  # bound by hand; the capture below is not wired to it
        sha_b = cts.sha256_file(cts.APK_B)
        capture = ca.OpenCapture(sha256=sha_b)
        flow.batch.Client = capture.wrap(flow.server.client)
        writer = ca.CheckpointWriter(flow.root, flow.expected, flow.request, capture=capture, resume=resume, legacy=flow.setup.legacy)
        with self.assertRaises(ca.CheckpointRefused) as caught:
            cts.run(flow.batch, cts.APK_B, flow.frozen_request(resume.claim), sample={"sha256": sha_b}, resume=resume.seed(),
                    checkpoint=writer)
        self.assertEqual(caught.exception.reason, "snapshot_changed")
        self.assertEqual(list(flow.root.glob("checkpoint-*.json")), [flow.root / "checkpoint-101-1.json"])  # only the first attempt's

    def test_results_need_a_snapshot_to_be_sealed(self):
        flow = self.flow(LOC, INFO)
        report = flow.attempt().report
        self.refused("results_without_snapshot_binding", ca.seal, report, identity=flow.expected, request=flow.request,
                     final=True, legacy=flow.setup.legacy)
        nothing = {"tasks": [{"id": "l1", "backend": "dexsql", "status": "skipped", "reason": "x"},
                             {"id": "i", "backend": "dexsql", "status": "skipped", "reason": "x"}],
                   "sessions": [], "source_unchanged": True, "complete": False}
        sealed = ca.seal(nothing, identity=flow.expected, request=flow.request, final=True, legacy=flow.setup.legacy)
        self.assertEqual(sealed["state"]["termination"], "partial")
        self.refused("request_changed", ca.seal, report, identity=flow.expected, request=cts.engine_request(LOC),
                     final=True, legacy=flow.setup.legacy)

    def test_results_without_a_snapshot_are_not_imported_even_when_resealed(self):
        # a complete checkpoint whose snapshot binding was stripped and resealed must not import: otherwise bind_source
        # (saved=None) would accept any snapshot and seed reuse, the very hole seal() refuses
        complete = self.flow(LOC, INFO)
        attempt = complete.attempt()
        self.assertTrue(attempt.document["identity"]["snapshot"])
        forged = reseal(dict(copy.deepcopy(attempt.document), identity=dict(attempt.document["identity"], snapshot=None)))
        self.refused("results_without_snapshot_binding", ca.import_checkpoint, forged, complete.expected,
                     legacy=complete.setup.legacy)
        # a partial checkpoint with a continued query is refused the same way
        partial_flow = self.flow(query(pagination={"max_pages": 1}), LOC)
        partial = partial_flow.attempt().document
        self.assertEqual({t["disposition"] for t in partial["state"]["tasks"]}, {"continue", "reuse"})
        stripped = copy.deepcopy(partial)
        stripped["identity"]["snapshot"] = None
        self.refused("results_without_snapshot_binding", ca.import_checkpoint, reseal(stripped), partial_flow.expected,
                     legacy=partial_flow.setup.legacy)
        # a continued query with no completed task is refused too (the check is not only about reuse)
        continued = self.flow(query(pagination={"max_pages": 1}))
        cont_doc = continued.attempt().document
        self.assertEqual([t["disposition"] for t in cont_doc["state"]["tasks"]], ["continue"])
        cont_stripped = copy.deepcopy(cont_doc)
        cont_stripped["identity"]["snapshot"] = None
        self.refused("results_without_snapshot_binding", ca.import_checkpoint, reseal(cont_stripped), continued.expected,
                     legacy=continued.setup.legacy)
        # but a checkpoint with nothing reusable (all rerun) and no snapshot still imports, mirroring seal()
        lost = self.flow(query(), LOC)
        lost.server.hooks.append(cts.worker_lost_after(1))
        document = lost.attempt().document
        self.assertEqual([t["disposition"] for t in document["state"]["tasks"]], ["rerun", "rerun"])
        unbound = reseal(dict(copy.deepcopy(document), identity=dict(document["identity"], snapshot=None)))
        resume = ca.import_checkpoint(unbound, lost.expected, legacy=lost.setup.legacy)
        self.refused("nothing_reusable", resume.seed)

    def test_the_run_identity_checks_origin_and_hint(self):
        flow = self.flow(LOC, INFO)
        for bad in ({"run_id": 1, "attempt": 1}, {"run_id": "1", "attempt": 1, "request_id": "a" * 32}):
            self.refused("origin_invalid", ca.CheckpointWriter, flow.root, flow.expected, flow.request, origin=bad)
        writer = ca.CheckpointWriter(flow.root, flow.expected, flow.request, legacy=flow.setup.legacy)
        writer.note("cancelled")
        writer.note(None)
        self.refused("invalid_hint", writer.note, "partial")

    def test_the_capture_reads_only_the_engines_answers(self):
        capture = ca.OpenCapture()
        capture.record("not json")
        capture.record(json.dumps({"dataset_id": "legacy", "dex_files": []}))
        capture.record(json.dumps([1, 2]))
        self.assertEqual(capture.opens, [])
        self.assertIsNone(capture.snapshot())
        server = cts.FakeDexsql()
        body = server.answer("open_dataset", {"inputs": [str(cts.APK_A)]})[1]
        capture.record(json.dumps(body))
        capture.record(json.dumps(body))
        self.assertEqual(len(capture.opens), 2)
        self.assertEqual(capture.snapshot(), ca.snapshot_identity(body))
        self.assertNotEqual(capture.opens[0]["handles"], {})
        other = server.answer("open_dataset", {"inputs": [str(cts.APK_B)]})[1]
        capture.record(json.dumps(other))
        self.refused("snapshots_disagree", capture.snapshot)
        with self.assertRaises(ca.CheckpointRefused):
            ca.OpenCapture().record(json.dumps({"snapshot_manifest": {}}))

    def test_a_lost_channel_becomes_worker_lost_and_nothing_else_does(self):
        class Raising:
            def __init__(self, error):
                self.error = error

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def call_tool(self, name, arguments, *args, **kwargs):
                raise self.error

        class ClosedResourceError(Exception):  # anyio's, matched by name so that anyio need not be imported
            pass

        async def call(error):
            wrapped = ca.OpenCapture().wrap(lambda params: Raising(error))
            async with wrapped(None) as client:
                await client.call_tool("query", {})

        for error in (BrokenPipeError("x"), ConnectionResetError("x"), ConnectionError("x"), EOFError("x"), ClosedResourceError()):
            with self.subTest(type(error).__name__), self.assertRaises(ca.WorkerLost) as caught:
                asyncio.run(call(error))
            self.assertEqual(caught.exception.detail["error"]["code"], "WORKER_LOST")
            self.assertIs(caught.exception.__cause__, error)
            self.assertIn("query", str(caught.exception))
            failure = provider.classify_failure({"error": "WorkerLost", "message": str(caught.exception), "detail": caught.exception.detail})
            self.assertEqual((failure.code, failure.origin), ("WORKER_LOST", "engine"))
        for error in (ValueError("x"), TimeoutError("deadline"), KeyError("k"), RuntimeError("x")):
            with self.subTest(type(error).__name__), self.assertRaises(type(error)) as caught:
                asyncio.run(call(error))
            self.assertIs(caught.exception, error)
        self.assertEqual(ca.WorkerLost.code, "WORKER_LOST")
        self.assertIn(ca.WorkerLost.code, provider.ENGINE_CODES)
        # a cancellation is not a lost worker: it is not even an Exception
        with self.assertRaises(asyncio.CancelledError):
            asyncio.run(call(asyncio.CancelledError()))

    def test_an_error_answer_to_open_dataset_is_not_a_snapshot(self):
        server = cts.FakeDexsql()
        body = server.answer("open_dataset", {"inputs": [str(cts.APK_A)]})[1]

        class Failing:
            def __init__(self, params):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def call_tool(self, name, arguments, *args, **kwargs):
                from types import SimpleNamespace
                return SimpleNamespace(content=[SimpleNamespace(text=json.dumps(body))], is_error=True)

        capture = ca.OpenCapture()

        async def go():
            async with capture.wrap(Failing)(None) as client:
                return await client.call_tool("open_dataset", {})

        self.assertTrue(asyncio.run(go()).is_error)
        self.assertEqual(capture.opens, [])  # a refusal that happens to carry a manifest is not a snapshot

    def test_the_capture_wrapper_passes_everything_else_through(self):
        flow = self.flow(LOC)
        capture = ca.OpenCapture()
        wrapped = capture.wrap(flow.server.client)

        async def go():
            async with wrapped(object()) as client:
                opened = await client.call_tool("open_dataset", {"inputs": [str(cts.APK_A)]})
                closed = await client.call_tool("close_dataset", {"dataset_id": "x"})
                refused = await client.call_tool("unknown_tool", {})
            return opened, closed, refused

        opened, closed, refused = asyncio.run(go())
        self.assertFalse(opened.is_error)
        self.assertFalse(closed.is_error)
        self.assertTrue(refused.is_error)
        self.assertEqual(len(capture.opens), 1)  # only the open was read


# ---- the completion cache ----------------------------------------------------------------------------------------------------------------

class Completion(Case):
    def setUp(self):
        super().setUp()
        self.flow_ = self.flow(LOC, INFO)
        self.attempt = self.flow_.attempt()
        self.cache = ca.CompletionCache(self.flow_.ns["completion"])
        self.legacy = self.flow_.setup.legacy

    def entries(self):
        return [p.name for p in self.flow_.ns["completion"].glob("*.json") if p.name != "NAMESPACE.json"]

    def store(self, document=None, cache=None):
        return (cache or self.cache).store(document or self.attempt.document, legacy=self.legacy)

    def test_a_complete_structured_result_is_stored_once_and_found_again(self):
        self.assertIsNone(self.cache.lookup(self.flow_.expected, legacy=self.legacy))
        path = self.store()
        self.assertEqual(path.parent, self.flow_.ns["completion"])
        self.assertEqual(path.name, self.cache.key(self.flow_.expected) + ".json")
        self.assertEqual(self.cache.key(self.flow_.expected), self.cache.key(self.attempt.document["identity"]))
        found = self.cache.lookup(self.flow_.expected, legacy=self.legacy)
        self.assertEqual(found, json.loads(json.dumps(self.attempt.document)))
        before = path.read_bytes()
        with self.assertRaises(provider.NamespaceCollision):
            self.store()
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.cache.rejected, [])

    def test_nothing_that_is_not_a_complete_verified_result_is_stored(self):
        moving = self.flow(LOC, INFO)
        moving.apk = self.dir / "moving.apk"
        shutil.copyfile(cts.APK_A, moving.apk)
        moving.sha = cts.sha256_file(moving.apk)
        moving.server.hooks.append(lambda name, arguments: shutil.copyfile(cts.APK_B, moving.apk) if name == "close_dataset" else None)
        changed = moving.attempt()
        lost = self.flow(LOC, INFO)
        lost.server.hooks.append(cts.worker_lost_after(1))
        lost = lost.attempt()
        partial = self.flow(query(pagination={"max_pages": 1}), LOC).attempt()
        inflight = json.loads((self.flow_.root / ca.CheckpointWriter.INFLIGHT).read_text(encoding="utf-8"))
        for label, document, reason in (
            ("source changed", changed.document, "source_changed"),
            ("cancelled", self.flow(LOC, INFO).attempt(hint="cancelled").document, "cancelled"),
            ("worker lost by hint", self.flow(LOC, INFO).attempt(hint="worker_lost").document, "worker_lost"),
            ("worker lost by engine code", lost.document, "worker_lost"),
            ("partial", partial.document, "partial"),
            ("in flight", inflight, "in_flight"),
        ):
            with self.subTest(label):
                self.assertEqual(document["state"]["termination"], reason)
                error = self.refused(reason, self.cache.store, document, legacy=self.legacy)
                self.assertIsInstance(error, ca.CompletionRefused)
        self.assertEqual(self.entries(), [])

    def test_arbitrary_sql_is_not_completion_cached(self):
        flow = self.flow(query(), LOC)
        attempt = flow.attempt()
        self.assertEqual(attempt.document["state"]["termination"], "complete")
        self.refused("arbitrary_sql_not_cached", ca.CompletionCache(flow.ns["completion"]).store, attempt.document,
                     legacy=flow.setup.legacy)

    def test_a_forged_or_unbound_document_is_not_stored(self):
        document = self.attempt.document
        unbound = copy.deepcopy(document)
        unbound["identity"]["snapshot"] = None
        self.refused("snapshot_not_bound", self.cache.store, reseal(unbound), legacy=self.legacy)
        wrong_bytes = copy.deepcopy(document)
        wrong_bytes["identity"]["snapshot"]["inputs"][0]["content_id"] = "sha256:" + "0" * 64
        self.refused("source_binding_mismatch", self.cache.store, reseal(wrong_bytes), legacy=self.legacy)
        no_inputs = copy.deepcopy(document)
        no_inputs["identity"]["snapshot"]["inputs"] = []
        self.refused("source_binding_mismatch", self.cache.store, reseal(no_inputs), legacy=self.legacy)
        tampered = copy.deepcopy(document)
        tampered["report"]["tasks"][0]["result"]["rows"].append(["x"])
        self.refused("seal_mismatch", self.cache.store, tampered, legacy=self.legacy)
        self.refused("state_mismatch", self.cache.store, reseal(dict(copy.deepcopy(document), request={"tasks": []})), legacy=self.legacy)
        self.refused("legacy_checkpoint_not_upgraded", self.cache.store, dict(document, schema=2), legacy=self.legacy)
        failed_session = copy.deepcopy(document["report"])
        failed_session["sessions"].append({"backend": "dexsql", "error": "RuntimeError", "message": "x", "detail": None})
        sealed = ca.seal(failed_session, identity=document["identity"], request=self.flow_.request, final=True, legacy=self.legacy)
        self.refused("partial", self.cache.store, sealed, legacy=self.legacy)
        self.assertEqual(self.entries(), [])

    def test_the_cache_belongs_to_the_engine_build_that_claimed_its_directory(self):
        other = self.flow(LOC, INFO, setup=cts.engine_setup(self.dir / "other-engine", content=b"stand-in engine 2",
                                                            fake=support.FakeEngine(build_id="source-sha256:" + "cd" * 32)))
        self.assertNotEqual(other.ns["completion"], self.flow_.ns["completion"])
        self.refused("generation_changed", self.store, cache=ca.CompletionCache(other.ns["completion"]), component="generation")
        bare = self.dir / "unclaimed"
        bare.mkdir()
        self.refused("generation_changed", self.store, cache=ca.CompletionCache(bare))
        self.refused("generation_changed", self.store, cache=ca.CompletionCache(self.dir / "absent"))
        (bare / "NAMESPACE.json").write_text("not json", encoding="utf-8")
        self.refused("generation_changed", self.store, cache=ca.CompletionCache(bare))

    def test_a_lookup_serves_only_an_entry_that_is_what_it_claims_to_be(self):
        path = self.store()
        good = path.read_bytes()
        expected = self.flow_.expected
        key = self.cache.key(expected)
        other_revision = self.flow(LOC, INFO, revision="rev-2")
        self.assertIsNone(self.cache.lookup(other_revision.expected, legacy=self.legacy))  # a different key altogether
        self.assertEqual(self.cache.rejected, [])
        plants = {
            "garbage": b"not json", "an empty file": b"", "a list": b"[]",
            "another engine's entry": json.dumps(self.flow(LOC, INFO, setup=cts.engine_setup(
                self.dir / "o2", content=b"stand-in engine 3", fake=support.FakeEngine(build_id="source-sha256:" + "ef" * 32))
            ).attempt().document).encode(),
            "a partial entry": json.dumps(self.flow(query(pagination={"max_pages": 1}), LOC).attempt().document).encode(),
            "a legacy entry": json.dumps({"schema": 2}).encode(),
            "another source's entry": json.dumps(self.flow(LOC, INFO, apk=cts.APK_B).attempt().document).encode(),
            "a worker-lost entry of the very same identity": json.dumps(self.flow(LOC, INFO).attempt(hint="worker_lost").document).encode(),
            "a cancelled entry of the very same identity": json.dumps(self.flow(LOC, INFO).attempt(hint="cancelled").document).encode(),
        }
        for label, data in plants.items():
            with self.subTest(label):
                path.write_bytes(data)
                self.cache.rejected.clear()
                self.assertIsNone(self.cache.lookup(expected, legacy=self.legacy))
                self.assertEqual(len(self.cache.rejected), 1)
                self.assertEqual(self.cache.rejected[0]["entry"], key + ".json")
                self.assertEqual(path.read_bytes(), data)  # kept where it is, never replaced by a success
        path.write_bytes(good)
        self.cache.rejected.clear()
        self.assertIsNotNone(self.cache.lookup(expected, legacy=self.legacy))
        unbound = copy.deepcopy(self.attempt.document)
        unbound["identity"]["snapshot"] = None
        path.write_text(json.dumps(reseal(unbound)), encoding="utf-8")
        self.assertIsNone(self.cache.lookup(expected, legacy=self.legacy))
        self.assertEqual(self.cache.rejected[-1]["reason"], "snapshot_changed")
        path.write_bytes(b"x" * (ca.MAX_DOCUMENT_BYTES + 1))
        self.assertIsNone(self.cache.lookup(expected, legacy=self.legacy))
        self.assertEqual(self.cache.rejected[-1]["reason"], "document_too_large")


# ---- rollback -----------------------------------------------------------------------------------------------------------------------------

class Rollback(Case):
    def job(self, **changes):
        return {"backend": "meguvizdexdash", "pages_accepted": 0, "rows_accepted": 0, "temp_side_effects": 0, **changes}

    def test_a_new_job_names_its_backend_and_is_not_replayed_after_work_was_accepted(self):
        table = [
            (self.job(), "dexsql", True, "replay", "nothing_accepted_and_no_side_effects"),
            (self.job(), "sqlite", True, "replay", "nothing_accepted_and_no_side_effects"),
            (self.job(backend="dexsql"), "meguvizdexdash", True, "replay", "nothing_accepted_and_no_side_effects"),
            (self.job(), "meguvizdexdash", True, "same_engine", "not_a_cross_engine_replay"),
            (self.job(pages_accepted=1), "dexsql", True, "refuse", "pages_already_accepted"),
            (self.job(rows_accepted=1), "dexsql", True, "refuse", "pages_already_accepted"),
            (self.job(temp_side_effects=1), "dexsql", True, "refuse", "temp_side_effects"),
            (self.job(pages_accepted=2, temp_side_effects=3), "dexsql", True, "refuse", "pages_already_accepted"),
            (self.job(), "auto", True, "refuse", "backend_not_explicit"),
            (self.job(), "", True, "refuse", "backend_not_explicit"),
            (self.job(), "dexsql", False, "refuse", "backend_not_explicit"),
            (self.job(), "dexsql", None, "refuse", "backend_not_explicit"),
            (self.job(), "dexsql", "yes", "refuse", "backend_not_explicit"),
            (self.job(pages_accepted=1), "meguvizdexdash", True, "same_engine", "not_a_cross_engine_replay"),
        ]
        for job, target, explicit, action, reason in table:
            with self.subTest((job, target, explicit)):
                decision = ca.replay_decision(job, target, explicit=explicit)
                self.assertEqual((decision.action, decision.reason), (action, reason))
                self.assertEqual(decision.to_dict(), {"action": action, "reason": reason})
                if action == "refuse":
                    error = self.refused(reason, ca.require_replay, job, target, explicit=explicit)
                    self.assertIsInstance(error, ca.ReplayRefused)
                else:
                    self.assertEqual(ca.require_replay(job, target, explicit=explicit), decision)

    def test_a_job_record_that_cannot_be_trusted_is_refused(self):
        for bad in (None, "x", self.job(backend="auto"), self.job(backend="other"), self.job(pages_accepted=-1),
                    self.job(pages_accepted=True), self.job(rows_accepted="1"), self.job(temp_side_effects=None),
                    {"backend": "dexsql"}):
            with self.subTest(bad):
                self.refused("invalid_job", ca.replay_decision, bad, "dexsql", explicit=True)

    def test_accepted_work_is_counted_from_the_report(self):
        flow = self.flow(query(pagination={"max_pages": 1}), LOC, INFO)
        attempt = flow.attempt()
        work = ca.accepted_work(attempt.report)
        self.assertEqual(work, {"pages_accepted": 1 + 1 + 1, "rows_accepted": 3 + 1})
        self.assertEqual(ca.accepted_work({"tasks": []}), {"pages_accepted": 0, "rows_accepted": 0})
        self.assertEqual(ca.accepted_work({"tasks": [{"status": "error"}, {"status": "skipped", "result": {}},
                                                     {"status": "error", "result": None}]}),
                         {"pages_accepted": 0, "rows_accepted": 0})
        stopped = {"tasks": [{"status": "partial", "result": {"rows": [], "pagination": {"pages": 0}}}]}
        self.assertEqual(ca.accepted_work(stopped), {"pages_accepted": 0, "rows_accepted": 0})
        self.assertEqual(ca.accepted_work({"tasks": [{"status": "partial", "result": {"smali": "x"}}]})["pages_accepted"], 1)
        job = self.job(**ca.accepted_work(attempt.report), temp_side_effects=0)
        self.assertEqual(ca.replay_decision(job, "dexsql", explicit=True).reason, "pages_already_accepted")

    def test_what_the_provider_would_not_fall_back_on_the_replay_guard_does_not_replay(self):
        flow = self.flow(query(pagination={"max_pages": 1}), LOC)
        attempt = flow.attempt()
        task = {"id": "q", "backend": provider.ENGINE, "forced": False}
        config = cts.engine_setup(self.dir / "fb", fallback={"to": "dexsql", "on": ["UNAVAILABLE_BACKEND"]}).config
        failure = provider.Failure("UNAVAILABLE_BACKEND", "adapter", "X", "gone")
        admitted = ca.accepted_work(attempt.report)["rows_accepted"]
        self.assertEqual(provider.decide_fallback(config, {}, task, failure, admitted_rows=0).action, "fallback")
        self.assertEqual(provider.decide_fallback(config, {}, task, failure, admitted_rows=admitted).action, "fail")
        job = self.job(**ca.accepted_work(attempt.report))
        self.assertEqual(ca.replay_decision(job, "dexsql", explicit=True).action, "refuse")

    def test_which_engine_calls_change_the_session_catalog(self):
        select = {"dataset_id": "d", "sql": ["SELECT 1"]}
        self.assertFalse(ca.is_temp_side_effect(select))
        self.assertFalse(ca.is_temp_side_effect({"sql": "  with a as (select 1) select * from a"}))
        self.assertFalse(ca.is_temp_side_effect({"sql": ["SELECT 1", "select 2"], "named_temp_queries": []}))
        self.assertTrue(ca.is_temp_side_effect(dict(select, named_temp_queries=[{"name": "t", "sql": "SELECT 1"}])))
        self.assertTrue(ca.is_temp_side_effect({"sql": ["CREATE TEMP TABLE t AS SELECT 1"]}))
        self.assertTrue(ca.is_temp_side_effect({"sql": ["SELECT 1", "DROP TABLE t"]}))
        self.assertTrue(ca.is_temp_side_effect({"sql": [5]}))
        self.assertFalse(ca.is_temp_side_effect({}))
        # the two shapes the frozen planner's prefix check lets through are side effects here
        self.assertTrue(ca.is_temp_side_effect({"sql": "WITH x AS(SELECT 1) INSERT INTO temp.t SELECT * FROM x"}))
        self.assertTrue(ca.is_temp_side_effect({"sql": "SELECT 1; CREATE TEMP TABLE t(x)"}))
        self.assertTrue(ca.is_temp_side_effect({"sql": "VALUES (1)"}))
        self.assertTrue(ca.is_temp_side_effect({"sql": "SELECT 'unterminated"}))
        # a keyword inside a literal or comment is not SQL: these stay pure
        self.assertFalse(ca.is_temp_side_effect({"sql": "SELECT 'INSERT INTO t' AS x"}))
        self.assertFalse(ca.is_temp_side_effect({"sql": "SELECT 1 -- DROP TABLE t"}))
        self.assertFalse(ca.is_temp_side_effect({"sql": "SELECT 1 /* CREATE TABLE t */"}))
        self.assertFalse(ca.is_temp_side_effect({"sql": "SELECT n FROM numbers ORDER BY n;"}))
        # what HostLab's executor sends for every task kind never counts
        flow = self.flow(query(), LOC, INFO)
        flow.attempt()
        self.assertFalse(any(ca.is_temp_side_effect(a) for n, a in flow.server.calls if n == "query"))

    def test_an_engine_job_is_read_back_under_its_own_identity_whatever_is_configured_now(self):
        flow = self.flow(query(pagination={"max_pages": 1}), LOC)
        attempt = flow.attempt()
        path = attempt.writer.path
        before, stamp = path.read_bytes(), path.stat().st_mtime_ns
        listing = sorted(p.name for p in flow.root.iterdir())
        read = ca.read_back(path)
        self.assertEqual((read.kind, read.termination, read.reason), ("mdd_checkpoint", "partial", None))
        self.assertEqual(read.identity, attempt.document["identity"])
        self.assertEqual(read.identity["engine"]["build_id"], flow.engine["build_id"])
        self.assertEqual(read.report, json.loads(json.dumps(attempt.report)))
        self.assertEqual(read.document_sha256, hashlib.sha256(before).hexdigest())
        self.assertFalse(read.resumable_here)  # nothing was asked of it
        # the rollback: another engine is configured now; the old job is still readable, and says why it is not resumable
        other = cts.engine_setup(self.dir / "newer", content=b"stand-in engine 2",
                                 fake=support.FakeEngine(build_id="source-sha256:" + "cd" * 32))
        newer = ca.expected_identity(other.plan(flow.request), other.config, request=flow.request, sha256=flow.sha,
                                     revision="rev-1", legacy=other.legacy)
        again = ca.read_back(path, newer)
        self.assertEqual((again.identity, again.resumable_here, again.reason),
                         (attempt.document["identity"], False, "engine_changed"))
        self.assertTrue(ca.read_back(path, flow.expected).resumable_here)
        self.assertEqual(ca.read_back(attempt.document).document_sha256, ca.digest_of(attempt.document))
        self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns, sorted(p.name for p in flow.root.iterdir())),
                         (before, stamp, listing))  # reading wrote nothing and changed nothing

    def test_a_read_back_checkpoint_reports_how_it_ended(self):
        flow = self.flow(LOC, INFO)
        complete = flow.attempt()
        self.assertEqual(ca.read_back(complete.document, flow.expected).termination, "complete")
        self.assertTrue(ca.read_back(complete.document, flow.expected).resumable_here)
        changed = dict(complete.document["state"], termination="source_changed")
        doc = reseal(dict(copy.deepcopy(complete.document), state=changed))
        read = ca.read_back(doc, flow.expected)
        self.assertEqual((read.resumable_here, read.reason), (False, "source_changed"))

    def test_a_hostlab_checkpoint_is_read_back_as_the_original_engines_and_never_upgraded(self):
        flow = self.flow(LOC, INFO)
        bare = cts.run(flow.batch, flow.apk, flow.frozen_request(), sample={"sha256": flow.sha})  # HostLab's own report
        read = ca.read_back(bare, flow.expected)
        self.assertEqual((read.kind, read.resumable_here, read.reason), ("hostlab_legacy", False, "legacy_checkpoint_not_upgraded"))
        self.assertEqual(read.identity["backends"], ["dexsql"])
        self.assertEqual(read.identity["backend_versions"], bare["backend_versions"])
        self.assertEqual(read.report, json.loads(json.dumps(bare)))
        self.refused("legacy_checkpoint_not_upgraded", ca.import_checkpoint, bare, flow.expected, legacy=flow.setup.legacy)
        path = self.dir / "checkpoint.json"
        path.write_text(json.dumps(dict(bare, schema=2)), encoding="utf-8")
        old = ca.read_back(path)
        self.assertEqual((old.kind, old.identity["schema"]), ("hostlab_legacy", 2))
        self.assertEqual(old.document_sha256, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_a_checkpoint_that_cannot_be_read_is_an_error(self):
        flow = self.flow(LOC, INFO)
        document = flow.attempt().document
        path = self.dir / "bad.json"
        path.write_text("{", encoding="utf-8")
        self.refused("malformed_checkpoint", ca.read_back, path)
        path.write_text("[]", encoding="utf-8")
        self.refused("malformed_checkpoint", ca.read_back, path)
        path.write_bytes(b"x" * (ca.MAX_DOCUMENT_BYTES + 1))
        self.refused("document_too_large", ca.read_back, path)
        self.refused("seal_mismatch", ca.read_back, dict(document, seal={"algorithm": "sha256", "digest": "0" * 64}))
        self.refused("unknown_checkpoint_schema", ca.read_back, dict(document, schema="x"))
        self.refused("malformed_checkpoint", ca.read_back, [])

    def test_where_checkpoints_live_is_inside_the_engines_namespace(self):
        flow = self.flow(LOC, INFO)
        root = ca.checkpoint_root(flow.ns)
        self.assertEqual(root, flow.ns["reports"] / "checkpoints")
        for name, other in provider.legacy_paths(flow.directory / "state").items():
            self.assertFalse(provider._related(root, other), name)


# ---- every refusal is declared ------------------------------------------------------------------------------------------------------------

class Reasons(Case):
    def test_every_reason_has_an_engine_code_that_can_never_cause_a_fallback(self):
        for reason, code in ca.REASONS.items():
            with self.subTest(reason):
                self.assertIn(code, provider.ENGINE_CODES)
                self.assertNotIn(code, provider.FALLBACK_ELIGIBLE)
        error = ca.CheckpointRefused("seal_mismatch", "m", component="c", extra=1)
        self.assertEqual((error.reason, error.component, error.code), ("seal_mismatch", "c", "CACHE_CORRUPT"))
        self.assertEqual(error.detail, {"error": {"kind": "checkpoint_refused", "code": "CACHE_CORRUPT", "reason": "seal_mismatch"}, "extra": 1})
        self.assertIsInstance(error, ValueError)  # HostLab turns a ValueError into a tool error
        self.assertEqual(str(ca.CheckpointRefused("seal_mismatch")), "seal_mismatch")

    def test_a_refusal_recorded_by_hostlab_is_classified_as_the_same_code_and_never_falls_back(self):
        flow = self.flow(LOC)
        task = {"id": "l1", "backend": provider.ENGINE, "forced": False}
        config = cts.engine_setup(self.dir / "fb", fallback={"to": "dexsql", "on": list(provider.FALLBACK_ELIGIBLE)}).config
        for reason, code in ca.REASONS.items():
            with self.subTest(reason):
                refusal = ca.CheckpointRefused(reason)
                failure = provider.classify_failure({"error": type(refusal).__name__, "message": str(refusal), "detail": refusal.detail})
                self.assertEqual((failure.code, failure.origin), (code, "engine"))
                self.assertEqual(provider.decide_fallback(config, {}, task, failure).action, "fail")
                self.assertEqual(provider.classify_failure(refusal).code, code)

    def test_every_reason_the_code_names_is_declared(self):
        tree = ast.parse((Path(__file__).resolve().parent / "checkpoint_adapter.py").read_text(encoding="utf-8"))
        used = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) in (
                    "CheckpointRefused", "ResumeRefused", "CompletionRefused", "ReplayRefused", "error"):
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    used.add(node.args[0].value)
        self.assertGreater(len(used), 25)
        self.assertLessEqual(used, set(ca.REASONS), sorted(used - set(ca.REASONS)))


if __name__ == "__main__":
    unittest.main()
