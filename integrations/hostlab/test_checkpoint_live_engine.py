"""The checkpoint adapter against the real `meguvizdexdash` binary, driven by HostLab's frozen batch executor and paging
module. A missing binary fails the run; it is never skipped.

Needs the binary (`cargo build -p mdd-cli`) or MDD_WORKER_BINARY. No network, no download.
Run: python -I -m unittest discover -s integrations/hostlab -p "test_checkpoint_live_engine.py"

What a stand-in cannot show and this does: that a second engine process, given nothing but the sealed checkpoint, continues
a query at the recorded offset and reads the same rows as an uninterrupted run; that the session handles of the same bytes
differ between processes while the snapshot identity does not; that other bytes giving the same rows, columns and totals are
refused; and that a killed engine process ends the run as WORKER_LOST with its admitted prefix intact.
"""
import asyncio
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import checkpoint_adapter as ca  # noqa: E402
import checkpoint_test_support as cts  # noqa: E402
import hostlab_test_support as support  # noqa: E402
import install_meguvizdexdash as installer  # noqa: E402
import provider  # noqa: E402
import test_live_engine as live  # noqa: E402

ENGINE = provider.ENGINE
DEX_FILES = cts.DEX_FILES
QUERY = {"id": "q", "operation": "query", "sql": DEX_FILES, "dialect": "dexsql", "limit": 1, "pagination": {"max_pages": 1}}
LOCATE = {"id": "l1", "operation": "locate", "kind": "class", "name": "Lfoo;"}


class LiveClient:
    """Stands where `analysis_batch.Client` stands, but speaks MCP to the real engine process the provider launches.
    `kill_after` ends the process after that many `query` calls, as an operating-system kill would."""

    instances: "list[LiveClient]" = []

    def __init__(self, launched, kill_after=None):
        self.launched, self.kill_after, self.queries, self.session = launched, kill_after, 0, None
        LiveClient.instances.append(self)

    async def __aenter__(self):
        self.session = live.McpSession(self.launched)
        return self

    async def __aexit__(self, *exc):
        await asyncio.to_thread(self.session.abort)
        return False

    @property
    def pid(self):
        return self.session.process.pid

    def _call(self, name, arguments):
        if name == "query":
            self.queries += 1
            if self.kill_after is not None and self.queries > self.kill_after:
                self.session.process.kill()
                self.session.process.wait(30)
        try:
            return self.session.call(name, **arguments)
        except (ValueError, OSError) as error:  # the engine's output ended: json.loads of an empty line, or a broken pipe
            raise EOFError("the engine process ended") from error

    async def call_tool(self, name, arguments, *args, **kwargs):
        failed, body = await asyncio.to_thread(self._call, name, arguments)
        return SimpleNamespace(content=[SimpleNamespace(text=json.dumps(body))], is_error=failed)


class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = live.find_binary()
        cls.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.dir = Path(cls.tmp.name).resolve()
        cls.manifest = cls.dir / "manifest.json"
        cls.entry = installer.pin(cls.binary, cls.manifest)
        cls.config = provider.parse_config({"schema": provider.CONFIG_SCHEMA, "native_engine": ENGINE, ENGINE: {
            "manifest": str(cls.manifest), "profile_policy": "allow_unadmitted"}})
        cls.status = installer.status(cls.binary, cls.manifest, deep=True)
        cls.legacy = support.load_frozen("analysis_plan")
        cls.count = 0

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        LiveClient.instances.clear()
        self.addCleanup(lambda: [c.session.abort() for c in LiveClient.instances if c.session is not None])

    def flow(self, *tasks, apk=cts.APK_A, kill_after=None):
        type(self).count += 1
        directory = self.dir / f"flow{self.count}"
        setup = cts.Setup(config=self.config, status=self.status, legacy=self.legacy, binary=self.binary, manifest=self.manifest,
                          fake=None, directory=directory)
        holder = {}

        def factory(params):
            return LiveClient(holder["flow"].launch(), kill_after=holder["kill_after"])

        flow = cts.Flow(directory, cts.engine_request(*tasks), apk=apk, setup=setup, client_factory=factory)
        holder.update(flow=flow, kill_after=kill_after)
        flow.holder = holder
        flow.launch = lambda: self.launch(flow)
        return flow

    def launch(self, flow):
        with mock.patch.dict(os.environ, {installer.ENV_BINARY: str(self.binary)}):
            return provider.launch(self.config, threads=2, timeout_seconds=60, state=flow.directory / "state")

    def rows(self, attempt, task="q"):
        entry = next(t for t in attempt.report["tasks"] if t["id"] == task)
        return entry["result"]["rows"]

    # ---------------------------------------------------------------------------------------------------------------

    def test_a_second_engine_process_continues_at_the_recorded_offset_and_reads_the_same_rows(self):
        flow = self.flow(QUERY, LOCATE)
        first = flow.attempt()
        self.assertEqual(first.report["tasks"][0]["status"], "partial")
        self.assertEqual(self.rows(first), [["0", "classes.dex"]])
        self.assertEqual(first.document["state"]["tasks"][0]["position"]["next_offset"], 1)
        second = flow.attempt(resume=flow.resume(first))
        self.assertTrue(second.report["complete"], second.report["tasks"])
        self.assertEqual(self.rows(second), [["0", "classes.dex"], ["1", "classes2.dex"]])
        self.assertEqual(second.report["tasks"][0]["result"]["pagination"]["requests_this_run"],
                         [{"offset": 1, "limit": 1, "rows": 1, "next_offset": None}])  # offset 0 was not asked for again
        self.assertEqual(second.report["execution"]["reused_complete_tasks"], 1)
        self.assertEqual(second.document["state"]["termination"], "complete")
        # an uninterrupted run on a third process reads the same rows
        whole = self.flow(dict(QUERY, limit=1000), LOCATE)
        uninterrupted = whole.attempt()
        self.assertEqual(self.rows(uninterrupted), self.rows(second))
        pids = [c.pid for c in LiveClient.instances]
        self.assertEqual(len(pids), 3)  # the first attempt, the resumed one and the whole run were three engine processes
        self.assertEqual(len(set(pids)), 3)

    def test_the_session_handles_differ_between_processes_and_the_snapshot_identity_does_not(self):
        flow = self.flow(QUERY, LOCATE)
        first = flow.attempt()
        second = flow.attempt(resume=flow.resume(first))
        one, two = first.capture.opens[0], second.capture.opens[0]
        for key in ("dataset_id", "snapshot_id", "scope_id"):
            self.assertNotEqual(one["handles"][key], two["handles"][key], key)
        self.assertEqual(one["snapshot"], two["snapshot"])
        self.assertEqual(one["snapshot"]["inputs"][0]["content_id"], "sha256:" + cts.sha256_file(cts.APK_A))
        self.assertTrue(one["snapshot"]["content_key"].startswith("sha256:"))
        # the same bytes at another path are the same snapshot; other bytes are not
        copy = self.dir / "elsewhere.apk"
        shutil.copyfile(cts.APK_A, copy)
        moved = self.flow(QUERY, LOCATE, apk=copy).attempt()
        self.assertEqual(moved.capture.opens[0]["snapshot"], one["snapshot"])
        other = self.flow(QUERY, LOCATE, apk=cts.APK_B).attempt()
        self.assertNotEqual(other.capture.opens[0]["snapshot"]["content_key"], one["snapshot"]["content_key"])

    def test_other_bytes_with_the_same_rows_columns_and_totals_are_refused(self):
        a = self.flow(QUERY, LOCATE)
        first = a.attempt()
        b = self.flow(QUERY, LOCATE, apk=cts.APK_B)
        other = b.attempt()
        # the premise: the two sources answer this query identically, down to the page and the total
        self.assertEqual(self.rows(first), self.rows(other))
        self.assertEqual(first.report["tasks"][0]["result"]["typed_result"]["statements"][0]["total_rows"],
                         other.report["tasks"][0]["result"]["typed_result"]["statements"][0]["total_rows"])
        with self.assertRaises(ca.ResumeRefused) as caught:
            ca.import_checkpoint(first.document, b.expected, legacy=self.legacy)
        self.assertEqual(caught.exception.reason, "source_changed")
        # HostLab hashed A but the engine is shown B: refused when the dataset opens, before any page is read
        refused = a.attempt(resume=a.resume(first), apk=cts.APK_B, sha=a.sha)
        self.assertFalse(refused.report["complete"])
        self.assertEqual(refused.report["sessions"][-1]["detail"]["error"]["reason"], "source_binding_mismatch")
        self.assertEqual(refused.report["execution"]["new_query_rows"], 0)
        self.assertEqual(self.rows(refused), [["0", "classes.dex"]])  # the prefix only; nothing of B was added
        self.assertEqual(refused.document["state"]["termination"], "source_changed")
        self.assertEqual(a.resume(first).termination, "partial")  # the checkpoint it was refused from still resumes

    def test_a_killed_engine_ends_the_run_as_worker_lost_and_a_new_process_continues(self):
        flow = self.flow(dict(QUERY, limit=1, pagination={"max_pages": 8}), LOCATE, kill_after=2)
        lost = flow.attempt()
        self.assertEqual(lost.document["state"]["termination"], "worker_lost")
        self.assertEqual(lost.document["state"]["failure_codes"], ["WORKER_LOST"])
        self.assertFalse(lost.report["complete"])
        self.assertEqual(self.rows(lost), [["0", "classes.dex"]])  # the page admitted before the kill is kept
        self.assertEqual(lost.document["state"]["tasks"][0]["disposition"], "continue")
        resume = flow.resume(lost)
        self.assertFalse(resume.success)
        cache = ca.CompletionCache(flow.ns["completion"])
        self.assertEqual(cache.rejected, [])
        with self.assertRaises(ca.CompletionRefused) as refused:
            cache.store(lost.document, legacy=self.legacy)
        self.assertEqual(refused.exception.reason, "worker_lost")
        flow.holder["kill_after"] = None
        done = flow.attempt(resume=resume)
        self.assertTrue(done.report["complete"], done.report["tasks"])
        self.assertEqual(self.rows(done), [["0", "classes.dex"], ["1", "classes2.dex"]])
        self.assertEqual(done.report["tasks"][0]["result"]["pagination"]["requests_this_run"][0]["offset"], 1)
        self.assertEqual(done.document["state"]["termination"], "complete")

    def test_a_complete_structured_result_is_cached_in_the_engines_own_directory_and_found_again(self):
        flow = self.flow(LOCATE, dict(LOCATE, id="l2"))
        attempt = flow.attempt()
        self.assertTrue(attempt.report["complete"], attempt.report["tasks"])
        self.assertEqual(next(t for t in attempt.report["tasks"] if t["id"] == "l2")["reused_from"], "l1")  # the memo still fires
        cache = ca.CompletionCache(flow.ns["completion"])
        path = cache.store(attempt.document, legacy=self.legacy)
        self.assertTrue(path.is_relative_to(flow.ns["completion"]))
        for name, other in provider.legacy_paths(flow.directory / "state").items():
            self.assertFalse(provider._related(path, other), name)
        self.assertIsNotNone(cache.lookup(flow.expected, legacy=self.legacy))
        self.assertEqual(attempt.document["identity"]["engine"]["build_id"], self.entry["build_id"])
        self.assertEqual(attempt.document["identity"]["engine"]["binary_sha256"], self.entry["sha256"])


if __name__ == "__main__":
    unittest.main()
