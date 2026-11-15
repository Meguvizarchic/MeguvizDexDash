"""Python SDK over the real library. Run: python -I -m unittest discover -s python/tests -t python

Needs the library built (`cargo build -p mdd-ffi`) or MDD_FFI_LIBRARY set. A missing
library fails the run; it is never skipped. Every test ends by checking that the number
of live ABI handles is back where it started, so a leaked handle fails the test that
leaked it.
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
CLASSES = "SELECT dex_occurrence_id,class_def_idx,descriptor FROM native_classes ORDER BY dex_occurrence_id,class_def_idx"
SLOW = ("SELECT COUNT(*) FROM native_strings a, native_strings b, native_strings c, "
        "native_strings d, native_strings e, native_strings f, native_strings g, native_strings h")


class SdkCase(unittest.TestCase):
    def setUp(self):
        gc.collect()
        self.baseline = mdd.live_handles()

    def tearDown(self):
        gc.collect()
        self.assertEqual(mdd.live_handles(), self.baseline, "the test leaked ABI handles")


class Basics(SdkCase):
    def test_the_library_negotiates_abi_1_0_and_is_not_an_admitted_profile(self):
        self.assertEqual(mdd.library().abi, (1, 0))
        caps = mdd.capabilities()
        self.assertIs(caps["profile_admitted"], False)
        self.assertEqual(caps["query_kinds"], ["sql"])

    def test_a_future_abi_is_refused_with_the_offered_version(self):
        import ctypes
        from mdd import _ffi
        info = _ffi.AbiInfo(ctypes.sizeof(_ffi.AbiInfo), 0, 0, 0)
        with self.assertRaises(errors.AbiMismatch) as raised:
            mdd.library().call("mdd_abi_negotiate_v1", 2, 0, ctypes.byref(info))
        self.assertEqual(raised.exception.details["offered_major"], 1)

    def test_no_business_package_is_imported_or_named(self):
        forbidden = ("hostlab", "bil", "meguviz_native", "analysis")
        loaded = [name for name in sys.modules if name.split(".")[0].lower() in forbidden]
        self.assertEqual(loaded, [])
        for source in (ROOT / "python/mdd").glob("*.py"):
            for line in source.read_text(encoding="utf-8").splitlines():
                if line.startswith(("import ", "from ")):
                    self.assertFalse(any(word in line.lower() for word in forbidden), f"{source.name}: {line}")


class Rows(SdkCase):
    def test_rows_keep_null_exact_integers_unpaired_surrogates_and_duplicates(self):
        with mdd.open_snapshot([FIXTURE, FIXTURE]) as snapshot, snapshot.open_session() as session:
            result = session.execute(CLASSES)
            occurrences = {row[0] for row in result.rows}
            self.assertEqual(len(occurrences), 2, "two captured copies are two occurrences")
            half = len(result.rows) // 2
            self.assertEqual([r[1:] for r in result.rows[:half]], [r[1:] for r in result.rows[half:]],
                             "duplicate content must stay duplicated")

            probe = session.execute(
                "SELECT 9223372036854775807, NULL, '', CAST(x'EDA080' AS TEXT), x'', superclass_type_idx "
                "FROM native_classes ORDER BY class_def_idx").rows[0]
            self.assertEqual(probe[0], 9223372036854775807)
            self.assertIsNone(probe[1])
            self.assertEqual(probe[2], "")
            self.assertEqual(probe[3], "\ud800")
            self.assertEqual(probe[3].encode("utf-16-be", "surrogatepass"), b"\xd8\x00")
            self.assertEqual(probe[4], b"")
            # NULL, empty text and empty bytes are three different values.
            self.assertEqual(len({repr(probe[1]), repr(probe[2]), repr(probe[4])}), 3)

    def test_original_mutf8_text_keeps_its_bytes_and_unit_count(self):
        with mdd.open_snapshot([UNICODE]) as snapshot, snapshot.open_session() as session:
            rows = session.execute("SELECT value,raw_mutf8 FROM native_strings ORDER BY value,string_idx").rows
            self.assertTrue(rows)
            for value, raw in rows:
                self.assertIsInstance(raw, mdd.DexMutf8)
                self.assertEqual(raw.utf16_units, len(value.encode("utf-16-le", "surrogatepass")) // 2)
                self.assertEqual(raw.text(), value)
            # The supplementary string sorts before U+E000 by UTF-16 code units.
            texts = [v for v, _ in rows]
            supplementary = next(t for t in texts if "\U0001f600" in t)
            private_use = next(t for t in texts if "" in t)
            self.assertLess(texts.index(supplementary), texts.index(private_use))

    def test_a_complete_result_carries_its_coverage_and_binds_the_snapshot(self):
        with mdd.open_snapshot([FIXTURE]) as snapshot, snapshot.open_session() as session:
            result = session.execute(CLASSES)
            self.assertTrue(result.is_complete)
            self.assertEqual(result.terminal["snapshot_id"], snapshot.manifest["snapshot_id"])
            self.assertEqual(result.coverage["input"], "complete")
            self.assertEqual(result.coverage["facts"], "complete")
            self.assertEqual(result.terminal["response"]["emitted_rows"], str(len(result.rows)))
            self.assertEqual(result.terminal["profile"], "native-unqualified")

    def test_batches_respect_the_demand_and_are_contiguous(self):
        with mdd.open_snapshot([FIXTURE, FIXTURE]) as snapshot, snapshot.open_session() as session:
            with session.query(CLASSES) as query:
                batches = list(query.batches(demand_rows=3))
                self.assertGreater(len(batches), 1)
                expected_first = 0
                for sequence, batch in enumerate(batches):
                    self.assertLessEqual(len(batch.rows), 3)
                    self.assertEqual(batch.sequence, sequence)
                    self.assertEqual(batch.first_row, expected_first)
                    expected_first += len(batch.rows)
                self.assertTrue(mdd.is_complete(query.terminal))


class Failures(SdkCase):
    def test_a_statement_that_cannot_run_raises_with_the_engine_code_never_an_empty_list(self):
        with mdd.open_snapshot([FIXTURE]) as snapshot, snapshot.open_session() as session:
            with self.assertRaises(errors.MddError) as raised:
                session.execute("SELECT no_such_column FROM native_classes")
            self.assertTrue(raised.exception.code)
            self.assertFalse(mdd.is_complete(raised.exception.terminal))

    def test_an_unavailable_layer_is_refused_by_name(self):
        with mdd.open_snapshot([FIXTURE]) as snapshot:
            with self.assertRaises(errors.Unsupported) as raised:
                snapshot.open_session(layers=["references"])
            self.assertEqual(raised.exception.code, "UNSUPPORTED_CAPABILITY")

    def test_a_missing_input_is_an_input_error(self):
        with self.assertRaises(errors.InvalidInput):
            mdd.open_snapshot([str(ROOT / "no/such/file.dex")])

    def test_a_cancelled_query_raises_and_never_returns_a_short_list(self):
        with mdd.open_snapshot([FIXTURE]) as snapshot, snapshot.open_session() as session:
            with session.query(CLASSES) as query:
                query.cancel()
                with self.assertRaises(errors.Cancelled) as raised:
                    query.collect()
                terminal = raised.exception.terminal
                self.assertEqual(terminal["operation_status"], "cancelled")
                self.assertFalse(mdd.is_complete(terminal))
                # The facts the session had established are not downgraded by the cancel.
                self.assertEqual(terminal["coverage"]["facts"], "complete")

    def test_cancel_from_another_thread_stops_a_running_statement(self):
        with mdd.open_snapshot([FIXTURE]) as snapshot, snapshot.open_session() as session:
            with session.query(SLOW) as query:
                threading.Timer(0.15, query.cancel).start()
                started = time.monotonic()
                with self.assertRaises(errors.Cancelled):
                    query.collect()
                self.assertLess(time.monotonic() - started, 10)


class Lifetimes(SdkCase):
    def test_leaving_a_with_block_by_exception_cancels_and_releases(self):
        class Boom(Exception):
            pass
        with mdd.open_snapshot([FIXTURE, FIXTURE]) as snapshot, snapshot.open_session() as session:
            with self.assertRaises(Boom):
                with session.query(CLASSES) as query:
                    for _ in query.batches(demand_rows=2):
                        raise Boom()
            self.assertTrue(query.closed)

    def test_abandoning_a_generator_midway_leaves_nothing_behind(self):
        with mdd.open_snapshot([FIXTURE, FIXTURE]) as snapshot, snapshot.open_session() as session:
            with session.query(CLASSES) as query:
                stream = query.batches(demand_rows=2)
                next(stream)
                stream.close()

    def test_unclosed_objects_are_released_by_the_garbage_collector(self):
        snapshot = mdd.open_snapshot([FIXTURE])
        session = snapshot.open_session()
        query = session.query(CLASSES)
        next(query.batches(demand_rows=2))
        self.assertGreater(mdd.live_handles(), self.baseline)
        del query, session, snapshot
        gc.collect()
        self.assertEqual(mdd.live_handles(), self.baseline)

    def test_use_after_close_raises_closed_and_close_is_idempotent(self):
        snapshot = mdd.open_snapshot([FIXTURE])
        session = snapshot.open_session()
        session.close()
        session.close()
        with self.assertRaises(errors.Closed):
            session.prepare("SELECT 1")
        snapshot.close()
        snapshot.close()
        with self.assertRaises(errors.Closed):
            snapshot.open_session()

    def test_closing_the_snapshot_keeps_the_sessions_that_already_exist(self):
        snapshot = mdd.open_snapshot([FIXTURE])
        session = snapshot.open_session()
        snapshot.close()
        self.assertTrue(session.execute(CLASSES).is_complete)
        session.close()

    def test_a_parent_is_not_collected_under_a_live_child(self):
        snapshot = mdd.open_snapshot([FIXTURE])
        session = snapshot.open_session()
        query = session.query(CLASSES)
        del snapshot, session
        gc.collect()
        self.assertTrue(query.collect().is_complete)
        query.close()


class Concurrency(SdkCase):
    def test_parallel_queries_on_one_session_give_identical_complete_results(self):
        with mdd.open_snapshot([FIXTURE, FIXTURE]) as snapshot, \
                snapshot.open_session(limits={"max_threads": 3}) as session:
            expected = session.execute(CLASSES).rows
            results, failures = [], []

            def work():
                try:
                    results.append(session.execute(CLASSES, demand_rows=4).rows)
                except Exception as error:  # noqa: BLE001 - collected for the assertion
                    failures.append(error)

            threads = [threading.Thread(target=work) for _ in range(3)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(failures, [])
            self.assertEqual(results, [expected] * 3)

    def test_the_session_thread_limit_is_enforced_and_reported_not_queued(self):
        with mdd.open_snapshot([FIXTURE]) as snapshot, snapshot.open_session() as session:
            holders = [session.query(SLOW) for _ in range(2)]  # the default allows two
            outcomes = [[], []]
            threads = [threading.Thread(target=lambda i=i: outcomes[i].append(_drain(holders[i])))
                       for i in range(2)]
            for thread in threads:
                thread.start()
            time.sleep(0.3)  # both are now inside their statements
            try:
                with session.query(CLASSES) as third:
                    with self.assertRaises(errors.QuotaExceeded) as raised:
                        third.collect()
                    self.assertEqual(raised.exception.code, "QUOTA_EXCEEDED")
                    self.assertEqual(raised.exception.terminal["operation_status"], "error")
            finally:
                for holder in holders:
                    holder.cancel()
                for thread in threads:
                    thread.join()
                for holder in holders:
                    holder.close()
            self.assertTrue(all(isinstance(o[0], errors.Cancelled) for o in outcomes))

    def test_a_second_consumer_of_one_query_is_told_to_retry_not_blocked(self):
        with mdd.open_snapshot([FIXTURE]) as snapshot, snapshot.open_session() as session:
            with session.query(SLOW) as query:
                outcome = []
                consumer = threading.Thread(target=lambda: outcome.append(_drain(query)))
                consumer.start()
                busy = None
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and busy is None:
                    time.sleep(0.02)
                    try:
                        next(iter(query.batches()))
                    except errors.Busy as error:
                        busy = error
                    except errors.MddError:
                        pass
                query.cancel()
                consumer.join()
                self.assertIsNotNone(busy, "the second consumer never saw BUSY")
                self.assertTrue(busy.retryable)


def _drain(query):
    try:
        return query.collect()
    except errors.MddError as error:
        return error


if __name__ == "__main__":
    unittest.main(verbosity=1)
