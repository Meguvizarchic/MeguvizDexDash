"""The SDK's worker transport. Run: python -I -m unittest discover -s python/tests -t python

Needs the library (`cargo build -p mdd-ffi`) and the worker binary (`cargo build -p mdd-cli`), or
MDD_FFI_LIBRARY and MDD_WORKER_BINARY. A missing binary fails the run; it is never skipped.

The real binary is used for what a worker really does (answer like the in-process library, refuse
a missing input, be killed mid-stream). A stand-in (stub_worker.py) is used for what a worker
should never do (exit cleanly without an answer, send half a line, send garbage, hang), so every
failure is reached on purpose. Every test ends by checking that nothing was left behind: each
process waited for, each pipe closed, each reader thread gone.
"""
import gc
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

import mdd  # noqa: E402
from mdd import errors  # noqa: E402

FIXTURE = str(ROOT / "tests/fixtures/definitions/generated/definitions-038.dex")
UNICODE = str(ROOT / "tests/fixtures/query/generated/unicode-order-038.dex")
STUB = str(Path(__file__).resolve().parent / "stub_worker.py")
CLASSES = "SELECT dex_occurrence_id,class_def_idx,descriptor FROM native_classes ORDER BY dex_occurrence_id,class_def_idx"
PROBE = ("SELECT 9223372036854775807, NULL, '', CAST(x'EDA080' AS TEXT), x'', superclass_type_idx "
         "FROM native_classes ORDER BY class_def_idx")
STRINGS = "SELECT value,raw_mutf8 FROM native_strings ORDER BY value,string_idx"
# many small rows: the answer is far larger than the pipe and the reader's queue together
FLOOD = "SELECT a.string_idx FROM native_strings a, native_strings b, native_strings c"  # 32,768 rows
BOUND = 10.0  # seconds a cleanup may take; it takes a fraction of one


def stub(name, **options):
    return mdd.Worker(["unused"], command=[sys.executable, "-I", STUB, name], **options)


def real(*paths, **options):
    return mdd.Worker(list(paths) or [FIXTURE], **options)


class WorkerCase(unittest.TestCase):
    def setUp(self):
        gc.collect()
        self.threads = threading.active_count()
        self.workers = []

    def track(self, worker):
        self.workers.append(worker)
        return worker

    def assertGone(self, worker):
        """The process was waited for, the pipes are closed and the reader threads have ended."""
        process = worker._process
        deadline = time.monotonic() + BOUND
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertIsNotNone(process.poll(), "the worker process is still running")
        for name in ("stdin", "stdout", "stderr"):
            self.assertTrue(getattr(process, name).closed, f"{name} is still open")
        for thread in worker._threads:
            self.assertFalse(thread.is_alive(), f"{thread.name} is still running")

    def tearDown(self):
        left = []
        for worker in self.workers:
            worker.close()
            if worker._process.poll() is None:
                left.append(worker.pid)
                worker._process.kill()  # do not leave a stray process behind a failed test
                worker._process.wait(timeout=BOUND)
        self.assertEqual(left, [], "a worker process was still running after close()")
        for worker in self.workers:
            self.assertGone(worker)
        gc.collect()
        deadline = time.monotonic() + BOUND
        while threading.active_count() > self.threads and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(threading.active_count(), self.threads, "a thread was left behind")


class Answers(WorkerCase):
    def test_a_worker_answers_like_the_in_process_library(self):
        with mdd.open_snapshot([FIXTURE, FIXTURE]) as snapshot, snapshot.open_session() as session:
            local = session.execute(CLASSES)
            local_probe = session.execute(PROBE).rows[0]
        worker = self.track(real(FIXTURE, FIXTURE))
        remote = worker.execute(CLASSES)
        self.assertEqual(remote.columns, local.columns)
        # the first column names the DEX occurrence, which carries the snapshot's own identity
        self.assertEqual([row[1:] for row in remote.rows], [row[1:] for row in local.rows])
        self.assertEqual(len({row[0] for row in remote.rows}), 2, "two captured copies are two occurrences")
        self.assertTrue(remote.is_complete)
        self.assertEqual(remote.coverage["input"], "complete")
        self.assertEqual(remote.coverage["facts"], "complete")
        probe = worker.execute(PROBE).rows[0]
        self.assertEqual(probe, local_probe)
        self.assertEqual(probe[0], 9223372036854775807)
        self.assertIsNone(probe[1])
        self.assertEqual((probe[2], probe[3], probe[4]), ("", "\ud800", b""))
        self.assertEqual(len({repr(probe[1]), repr(probe[2]), repr(probe[4])}), 3)

    def test_original_mutf8_text_arrives_with_its_bytes_and_unit_count(self):
        with mdd.open_snapshot([UNICODE]) as snapshot, snapshot.open_session() as session:
            local = session.execute(STRINGS).rows
        remote = self.track(real(UNICODE)).execute(STRINGS).rows
        self.assertEqual(remote, local)
        self.assertTrue(remote and all(isinstance(raw, mdd.DexMutf8) for _, raw in remote))

    def test_the_opened_line_names_the_snapshot_the_worker_read(self):
        worker = self.track(real())
        self.assertTrue(worker.description["snapshot_id"].startswith("snapshot-"))
        self.assertEqual(worker.description["sql_dialect"], "native-v1")

    def test_a_failed_statement_is_the_engines_error_and_the_worker_stays_usable(self):
        worker = self.track(real())
        with self.assertRaises(errors.MddError) as caught:
            worker.execute("SELECT * FROM no_such_relation")
        self.assertNotIsInstance(caught.exception, errors.WorkerLost)
        self.assertTrue(caught.exception.code)
        self.assertEqual(len(worker.execute(CLASSES).rows) > 0, True)

    def test_batches_are_contiguous_and_respect_the_batch_size(self):
        worker = self.track(real())
        with worker.query(CLASSES, batch_rows=1) as query:
            batches = list(query.batches())
        self.assertGreater(len(batches), 1)
        self.assertEqual([b.sequence for b in batches], list(range(len(batches))))
        self.assertEqual([b.first_row for b in batches], list(range(len(batches))))
        self.assertTrue(all(len(b.rows) == 1 for b in batches))
        self.assertEqual(query.terminal["operation_status"], "ok")

    def test_a_row_limit_is_a_failure_not_a_shorter_result(self):
        worker = self.track(real())
        with self.assertRaises(errors.MddError) as caught:
            worker.execute(CLASSES, max_rows=1)
        self.assertNotIsInstance(caught.exception, errors.WorkerLost)

    def test_a_missing_input_is_refused_not_lost(self):
        started = time.monotonic()
        with self.assertRaises(errors.InvalidInput) as caught:
            mdd.Worker(["definitely-not-here.dex"])
        self.assertNotIsInstance(caught.exception, errors.WorkerLost)
        self.assertEqual(caught.exception.code, "INVALID_INPUT")
        self.assertLess(time.monotonic() - started, BOUND)


class Losses(WorkerCase):
    def test_a_worker_killed_mid_stream_raises_worker_lost_after_the_batches_it_delivered(self):
        worker = self.track(real())
        delivered = 0
        with self.assertRaises(errors.WorkerLost) as caught:
            with worker.query(FLOOD, batch_rows=1) as query:
                for batch in query.batches():
                    delivered += len(batch.rows)
                    if delivered == 1:
                        started = time.monotonic()
                        worker._process.kill()
        self.assertLess(time.monotonic() - started, BOUND)
        error = caught.exception
        self.assertEqual(error.code, "WORKER_LOST")
        self.assertIsNone(error.status)
        self.assertGreaterEqual(error.details["rows_delivered"], 1)
        self.assertEqual(error.details["rows_delivered"], delivered, "what was delivered is what is reported")
        self.assertIsNotNone(error.details["exit_code"])
        self.assertTrue(worker.closed)
        self.assertGone(worker)

    def test_execute_never_returns_when_the_worker_dies_it_raises(self):
        worker = self.track(real())
        with worker.query(FLOOD, batch_rows=1) as query:
            iterator = query.batches()
            next(iterator)
            worker._process.kill()
            with self.assertRaises(errors.WorkerLost):
                for _ in iterator:
                    pass
            self.assertIsNone(query.terminal, "no terminal was ever seen, so none is invented")
        with self.assertRaises(errors.WorkerLost):
            # a fresh worker: collect() itself must raise, whatever it has gathered so far
            second = self.track(real())
            second._process.kill()
            second._process.wait()
            second.execute(CLASSES)

    def test_a_lost_worker_stays_lost_and_says_so_promptly(self):
        worker = self.track(real())
        worker._process.kill()
        worker._process.wait()
        with self.assertRaises(errors.MddError):
            worker.execute(CLASSES)
        started = time.monotonic()
        with self.assertRaises(errors.Closed):
            worker.query(CLASSES)
        self.assertLess(time.monotonic() - started, 1.0)
        worker.close()
        worker.close()

    def test_a_worker_that_crashes_before_it_is_open_is_lost(self):
        with self.assertRaises(errors.WorkerLost) as caught:
            stub("crash-before-opened")
        self.assertEqual(caught.exception.details["exit_code"], 3)
        self.assertEqual(caught.exception.details["during"], "startup")

    def test_a_worker_that_refuses_to_start_is_not_lost(self):
        with self.assertRaises(errors.InvalidInput) as caught:
            stub("refuse-before-opened")
        self.assertEqual(caught.exception.details["exit_code"], 2)
        self.assertEqual(caught.exception.message, "no such input")

    def test_a_worker_that_dies_inside_a_query_is_lost_with_its_exit_code(self):
        worker = self.track(stub("crash-mid-stream"))
        delivered = []
        with self.assertRaises(errors.WorkerLost) as caught:
            with worker.query("q") as query:
                for batch in query.batches():
                    delivered.append(batch)
        self.assertEqual(len(delivered), 1, "the batch that arrived is delivered before the loss")
        self.assertEqual(caught.exception.details["exit_code"], 9)
        self.assertEqual(caught.exception.details["rows_delivered"], 2)

    def test_a_worker_that_exits_cleanly_without_a_terminal_is_still_lost(self):
        worker = self.track(stub("clean-exit-no-terminal"))
        with self.assertRaises(errors.WorkerLost) as caught:
            worker.execute("q")
        self.assertEqual(caught.exception.details["exit_code"], 0, "an exit code of zero is not an answer")

    def test_a_line_cut_short_is_a_loss_not_a_short_result(self):
        worker = self.track(stub("partial-line"))
        with self.assertRaises(errors.WorkerLost) as caught:
            worker.execute("q")
        self.assertGreater(caught.exception.details["partial_line_bytes"], 0)

    def test_a_silent_worker_is_ended_at_the_callers_deadline(self):
        worker = self.track(stub("hang"))
        outcome = []

        def ask():
            try:
                worker.execute("q", timeout=0.5)
            except errors.MddError as error:
                outcome.append(error)

        # in a thread, so that a deadline that is not kept fails this test instead of hanging the run
        thread = threading.Thread(target=ask, daemon=True)
        started = time.monotonic()
        thread.start()
        thread.join(timeout=BOUND)
        if thread.is_alive():
            worker._process.kill()
            thread.join(timeout=BOUND)
            self.fail("the call outlived its deadline")
        self.assertLess(time.monotonic() - started, BOUND)
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], errors.DeadlineExceeded)
        self.assertEqual(outcome[0].code, "DEADLINE_EXCEEDED")
        self.assertGone(worker)


class Protocol(WorkerCase):
    def assertProtocolError(self, scenario, **options):
        worker = self.track(stub(scenario, **options))
        started = time.monotonic()
        with self.assertRaises(errors.WorkerProtocol) as caught:
            worker.execute("q", timeout=5.0)
        self.assertEqual(caught.exception.code, "WORKER_PROTOCOL")
        self.assertLess(time.monotonic() - started, BOUND)
        self.assertTrue(worker.closed)
        self.assertGone(worker)

    def test_a_line_that_is_not_json_ends_the_worker(self):
        self.assertProtocolError("garbage")

    def test_json_that_is_not_an_object_ends_the_worker(self):
        self.assertProtocolError("not-an-object")

    def test_an_answer_for_another_request_ends_the_worker(self):
        self.assertProtocolError("wrong-id")

    def test_an_unknown_kind_ends_the_worker(self):
        self.assertProtocolError("unknown-kind")

    def test_batches_out_of_order_end_the_worker(self):
        self.assertProtocolError("bad-sequence")
        self.assertProtocolError("bad-first-row")

    def test_a_batch_that_does_not_decode_ends_the_worker(self):
        self.assertProtocolError("undecodable-batch")

    def test_a_terminal_that_is_not_an_object_ends_the_worker(self):
        self.assertProtocolError("terminal-not-an-object")

    def test_a_line_over_the_limit_ends_the_worker_without_buffering_it(self):
        self.assertProtocolError("oversize", max_line_bytes=65536)

    def test_a_peer_that_does_not_speak_the_protocol_is_refused_at_startup(self):
        started = time.monotonic()
        with self.assertRaises(errors.WorkerProtocol):
            stub("not-the-protocol", startup_timeout=10.0)
        self.assertLess(time.monotonic() - started, BOUND)

    def test_a_rejected_request_is_the_engines_error_and_the_worker_goes_on(self):
        worker = self.track(stub("rejected-then-ok"))
        with self.assertRaises(errors.InvalidArgument):
            worker.execute("bad")
        self.assertEqual(worker.execute("good").rows, [(7,)])

    def test_a_failure_terminal_raises_after_its_batches(self):
        worker = self.track(stub("failure-terminal"))
        seen = []
        with self.assertRaises(errors.QuotaExceeded) as caught:
            with worker.query("q") as query:
                seen.extend(query.batches())
        self.assertEqual(len(seen), 1)
        self.assertEqual(caught.exception.terminal["operation_status"], "error")
        self.assertFalse(worker.closed, "a failed statement leaves the worker usable")

    def test_a_result_that_is_not_complete_is_not_returned(self):
        worker = self.track(stub("incomplete-terminal"))
        with self.assertRaises(errors.MddError) as caught:
            worker.execute("q")
        self.assertEqual(caught.exception.code, "INCOMPLETE_RESULT")


class Lifetime(WorkerCase):
    def test_close_asks_the_worker_to_end_and_is_idempotent(self):
        worker = real()
        process = worker._process
        worker.close()
        self.assertEqual(process.returncode, 0, "a worker that is asked to close ends by itself")
        worker.close()
        with self.assertRaises(errors.Closed):
            worker.query(CLASSES)
        self.assertGone(worker)

    def test_a_worker_that_ignores_close_is_killed_after_the_grace_period(self):
        worker = stub("ignore-close", grace=0.5)
        started = time.monotonic()
        worker.close()
        self.assertLess(time.monotonic() - started, BOUND)
        self.assertNotEqual(worker._process.returncode, 0)
        self.assertGone(worker)

    def test_leaving_a_with_block_by_exception_ends_the_worker(self):
        with self.assertRaises(RuntimeError):
            with real() as worker:
                self.track(worker)
                raise RuntimeError("the caller failed")
        self.assertGone(worker)

    def test_abandoning_a_query_half_way_ends_the_worker_and_says_so(self):
        worker = self.track(real())
        with worker.query(FLOOD, batch_rows=1) as query:
            for _ in query.batches():
                break
        self.assertTrue(worker.closed)
        with self.assertRaises(errors.Closed):
            worker.query(CLASSES)
        self.assertGone(worker)

    def test_a_query_that_ran_to_its_end_leaves_the_worker_usable(self):
        worker = self.track(real())
        for _ in range(3):
            with worker.query(CLASSES) as query:
                list(query.batches())
        self.assertFalse(worker.closed)

    def test_a_second_query_while_one_is_open_is_told_busy(self):
        worker = self.track(real())
        with worker.query(CLASSES) as first:
            with self.assertRaises(errors.Busy):
                worker.query(CLASSES)
            list(first.batches())
        self.assertEqual(len(worker.execute(CLASSES).rows) > 0, True)

    def test_dropping_a_worker_without_closing_it_reaps_its_process(self):
        worker = real()
        process, threads = worker._process, list(worker._threads)
        del worker
        gc.collect()
        deadline = time.monotonic() + BOUND
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertIsNotNone(process.poll(), "the process of a dropped worker was left running")
        for thread in threads:
            thread.join(timeout=BOUND)
            self.assertFalse(thread.is_alive())

    def test_cancel_from_another_thread_ends_the_worker_and_the_waiting_reader_raises(self):
        worker = self.track(real())
        outcome = []

        def read():
            try:
                with worker.query(FLOOD, batch_rows=1) as query:
                    for _ in query.batches():
                        time.sleep(0.001)
                outcome.append("finished")
            except errors.MddError as error:
                outcome.append(error)

        with worker.query(CLASSES) as _:
            pass
        reader = threading.Thread(target=read)
        reader.start()
        time.sleep(0.3)
        started = time.monotonic()
        worker.close()
        reader.join(timeout=BOUND)
        self.assertFalse(reader.is_alive(), "the reader was left waiting")
        self.assertLess(time.monotonic() - started, BOUND)
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], errors.MddError)
        self.assertNotEqual(outcome[0], "finished")
        self.assertGone(worker)

    def test_a_cancelled_query_raises_cancelled_and_never_returns_a_short_list(self):
        worker = self.track(real())
        with self.assertRaises(errors.Cancelled):
            with worker.query(FLOOD, batch_rows=1) as query:
                for _ in query.batches():
                    query.cancel()
        self.assertTrue(worker.closed)
        self.assertGone(worker)

    def test_workers_are_independent(self):
        first, second = self.track(real()), self.track(real())
        first._process.kill()
        first._process.wait()
        with self.assertRaises(errors.MddError):
            first.execute(CLASSES)
        self.assertTrue(second.execute(CLASSES).is_complete, "the other worker does not notice")
        results = []

        def run(worker):
            results.append(len(worker.execute(CLASSES).rows))

        a, b = self.track(real()), self.track(real())
        threads = [threading.Thread(target=run, args=(w,)) for w in (a, b)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=BOUND)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], results[1])


class Boundaries(WorkerCase):
    def test_no_business_package_is_imported_or_named_by_the_worker_transport(self):
        source = (ROOT / "python/mdd/worker.py").read_text(encoding="utf-8").lower()
        for word in ("hostlab", "bil_", "feature", "family"):
            self.assertNotIn(word, source)

    def test_a_worker_needs_an_input(self):
        with self.assertRaises(errors.InvalidArgument):
            mdd.Worker([])


if __name__ == "__main__":
    unittest.main()
