"""native_session (B0 and B1) without the real engine: a stand-in `serve` process plays scripted answers.

What is checked here and why a stand-in is the right tool: the failures that a real engine does not produce on demand
(the process dying mid-statement, a frame out of order, a hung engine, a row count that contradicts its frames), the
exact statements B0 sends compared with what HostLab's frozen CliSession would send, the DTO rules of both wires, and
the guards that rows() keeps. test_structural_equivalence.py runs the same sessions against the real binary.
Run: python -I -m unittest discover -s integrations/hostlab -p "test_structural_session.py"
"""
import json
import os
import subprocess
import sys
import tempfile
import time
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
sys.path.insert(0, str(ROOT / "python"))
from mdd import _cells as sdk_cells  # noqa: E402  (the SDK's decoder: the typed cells mean the same in both)

FAKE_SERVER = r'''
import json, sys, time
scenario = json.load(open(sys.argv[1], encoding="utf-8"))
log = open(sys.argv[2], "a", encoding="utf-8")
def out(frame, rid):
    if isinstance(frame, str):
        sys.stdout.write(frame); sys.stdout.flush(); return
    text = json.dumps(frame).replace("$id", rid)
    sys.stdout.write(text + "\n"); sys.stdout.flush()
if scenario.get("stderr"):
    sys.stderr.write(scenario["stderr"] + "\n"); sys.stderr.flush()
if scenario.get("exit_before_open") is not None:
    sys.exit(scenario["exit_before_open"])
if scenario.get("opened") is not None:
    out(scenario["opened"], "-")
steps = scenario["steps"]
count = 0
for line in sys.stdin:
    log.write(line); log.flush()
    request = json.loads(line)
    if request.get("op") == "close":
        if scenario.get("close") == "hang":
            time.sleep(120)
        sys.exit(scenario.get("exit_code", 0))
    step = steps[count] if count < len(steps) else {"frames": []}
    count += 1
    for frame in step["frames"]:
        out(frame, request["id"])
    if step.get("then") == "exit":
        sys.exit(step.get("code", 0))
    if step.get("then") == "hang":
        time.sleep(120)
if scenario.get("hang_at_end"):
    time.sleep(120)
sys.exit(scenario.get("exit_code", 0))
'''

OPENED = {"kind": "opened", "protocol": "mdd.cli-stream.v1",
          "dataset": {"dex_count": 1, "layer_issues": [], "profile": "hostlab-contract-unqualified",
                      "scope_id": "sha256:aa", "snapshot_id": "snapshot-bb", "sql_dialect": "dexsql-0.1.0"}}
COVERAGE = {"scope_id": "sha256:aa", "input": "complete", "facts": "complete", "required_layers": ["metadata"], "issues": []}


def terminal(columns, rows, *, status="ok", error=None, truncated=False, complete=True, coverage=None, more=False):
    return {"kind": "terminal", "id": "$id", "terminal": {
        "schema_version": "mdd.result.v1", "operation_status": status, "coverage": coverage or COVERAGE,
        "execution": {"complete": complete},
        "response": {"emitted_rows": str(rows), "total_rows": str(rows), "truncated": truncated, "more_available": more},
        "data": {"columns": columns} if columns is not None else None, "error": error}}


def batch(columns, rows, sequence=0, first_row=0, count=None):
    return {"kind": "batch", "id": "$id", "batch": {"schema": "mdd.sdk-batch.v1", "sequence": str(sequence),
                                                   "first_row": str(first_row), "row_count": len(rows) if count is None else count,
                                                   "columns": columns, "rows": rows}}


def text(value):
    return {"t": "text", "v": value}


def hexcell(value):
    return text("N" if value is None else value.encode("utf-8").hex().upper())


def b0_steps(columns, rows):
    """What a B0 rows() call needs from the engine: the shape statement, then the hex-projected data."""
    data = ([batch(columns, [[hexcell(v) for v in row] for row in rows])] if rows else []) + [terminal(columns, len(rows))]
    return [{"frames": [terminal(columns, 0)]}, {"frames": data}]


def b1_steps(columns, typed_rows):
    data = ([batch(columns, [list(row) for row in typed_rows])] if typed_rows else []) + [terminal(columns, len(typed_rows))]
    return [{"frames": data}]


FILES = ["file_id", "entry_name"]


def entry_steps(wire):
    return b0_steps(FILES, [("0", "classes.dex")]) if wire == "b0" else b1_steps(FILES, [[{"t": "u64", "v": "0"}, text("classes.dex")]])


class Harness:
    """A scripted engine process and the session over it."""

    def __init__(self, case, wire, steps, *, opened=OPENED, timeout=20, settings=None, with_entry=True, **scenario):
        self.case, self.wire, self.timeout = case, wire, timeout
        self.directory = Path(tempfile.mkdtemp(prefix="mdd051-fake-"))
        case.addCleanup(self.cleanup)
        self.server = self.directory / "fake_serve.py"
        self.server.write_text(FAKE_SERVER, encoding="utf-8")
        self.scenario = self.directory / "scenario.json"
        full = (entry_steps(wire) if with_entry else []) + list(steps)
        self.scenario.write_text(json.dumps({"opened": opened, "steps": full, **scenario}), encoding="utf-8")
        self.log = self.directory / "requests.log"
        self.log.write_text("", encoding="utf-8")
        self.apk = self.directory / "input.dex"
        self.apk.write_bytes(b"dex\n035\0 stand-in")
        command = [sys.executable, "-I", str(self.server), str(self.scenario), str(self.log)]
        self.launch = ns.EngineLaunch(command, dict(os.environ), {"stand_in": True})
        self.session = ns.SESSIONS[wire](self.apk, timeout=timeout, threads=2, launch=self.launch, settings=settings)

    def cleanup(self):
        process = getattr(self.session.transport, "process", None)
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(10)
        import shutil
        shutil.rmtree(self.directory, ignore_errors=True)

    def requests(self):
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines() if line.strip()]

    def sql(self):
        return [r["sql"] for r in self.requests() if "sql" in r]

    def process(self):
        return self.session.transport.process


def both(test):
    """Run a test method once per wire."""
    def run(self):
        for wire in ("b0", "b1"):
            with self.subTest(wire=wire):
                test(self, wire)
    run.__name__ = test.__name__
    return run


def steps_for(wire, columns, rows, typed=None):
    return b0_steps(columns, rows) if wire == "b0" else b1_steps(columns, typed if typed is not None else [[text(v) for v in row] for row in rows])


class LiteralTests(unittest.TestCase):
    """literal and in_list are HostLab's, with the same results and the same refusals."""

    @classmethod
    def setUpClass(cls):
        cls.frozen = F.execute("native_session", stubs={"native_cli": types_module("native_cli")})

    def test_same_results_on_awkward_values(self):
        values = ["", "a", "it's", "''", "Lcom/Foo$Bar;", "中文", "a\\b", "%_", "a b", "\t", "x" * 1000, "\x7f", " ", "😀"]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(ns.literal(value), self.frozen.literal(value))
        self.assertEqual(ns.in_list(values), self.frozen.in_list(values))
        self.assertEqual(ns.in_list(v for v in values), self.frozen.in_list(v for v in values))
        self.assertEqual(ns.in_list([]), self.frozen.in_list([]))

    def test_same_refusals(self):
        for value in ("a\nb", "a\rb", "a\0b", "\n", "tail\r"):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError) as mine:
                    ns.literal(value)
                with self.assertRaises(ValueError) as theirs:
                    self.frozen.literal(value)
                self.assertEqual(str(mine.exception), str(theirs.exception))
        with self.assertRaises(ValueError):
            ns.in_list(["ok", "bad\n"])

    def test_the_comparison_has_teeth(self):
        self.assertNotEqual(ns.literal("a'b"), self.frozen.literal("a"))
        self.assertNotEqual(ns.literal("a'b"), "'a'b'")


def types_module(name):
    import types
    module = types.ModuleType(name)
    module.CliSession = object
    return module


class ConfigTests(unittest.TestCase):
    def good(self, **extra):
        return {"schema": ns.STRUCTURAL_SCHEMA, **extra}

    def test_defaults_and_choices(self):
        self.assertEqual(ns.parse_structural_config(self.good()), ns.StructuralConfig())
        self.assertEqual(ns.StructuralConfig().wire, "b0")
        self.assertEqual(ns.StructuralConfig().non_scalar_text, "reject")
        config = ns.parse_structural_config(
            self.good(wire="b1", sql_limits={"result_rows": 5, "steps": 7}, max_line_bytes=2048,
                      non_scalar_text="lossy-replacement"))
        self.assertEqual(
            (config.wire, config.limits(), config.max_line_bytes, config.non_scalar_text),
            ("b1", {"steps": 7, "result_rows": 5}, 2048, "lossy-replacement"))

    def test_refused(self):
        bad = [None, [], "b1", {}, {"schema": "x"}, self.good(extra=1), self.good(wire="b2"), self.good(wire=None),
               self.good(sql_limits=[]), self.good(sql_limits={"rows": 1}), self.good(sql_limits={"steps": 0}),
               self.good(sql_limits={"steps": True}), self.good(sql_limits={"steps": "5"}), self.good(max_line_bytes=10),
               self.good(max_line_bytes=True), self.good(max_line_bytes=1 << 40),
               self.good(non_scalar_text=None), self.good(non_scalar_text=1), self.good(non_scalar_text="ignore")]
        for document in bad:
            with self.subTest(document=document):
                with self.assertRaises(provider.ConfigError):
                    ns.parse_structural_config(document)

    def test_loading(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "structural.json"
            path.write_text(json.dumps(self.good(wire="b1")), encoding="utf-8")
            self.assertEqual(ns.load_structural_config(path).wire, "b1")
            self.assertEqual(ns.load_structural_config(None, {ns.ENV_STRUCTURAL: str(path)}).wire, "b1")
            self.assertEqual(ns.load_structural_config(None, {}).wire, "b0")
            self.assertEqual(ns.load_structural_config(self.good(wire="b1")).wire, "b1")
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(provider.ConfigError):
                ns.load_structural_config(path)
            path.write_text(" " * (65 * 1024), encoding="utf-8")
            with self.assertRaises(provider.ConfigError):
                ns.load_structural_config(path)


class ServeCommandTests(unittest.TestCase):
    def test_arguments(self):
        command = ns.serve_command("engine", ["a.apk", Path("b.apk")], dialect="dexsql-0.1.0", timeout_seconds=90,
                                   sql_limits={"result_rows": 900000, "steps": 3})
        self.assertEqual(command, ["engine", "serve", "--dialect", "dexsql-0.1.0", "--deadline-ms", "90000",
                                   "--sql-max-steps", "3", "--sql-max-result-rows", "900000",
                                   "--input", "a.apk", "--input", "b.apk"])
        self.assertNotIn("--threads", command)  # the engine has no global --threads (its README of differences)
        self.assertEqual(ns.serve_command("e", [], dialect="d", timeout_seconds=0)[4], "--deadline-ms")
        self.assertEqual(ns.serve_command("e", [], dialect="d", timeout_seconds=0)[5], "1")

    def test_unknown_limit_names_are_not_passed(self):
        command = ns.serve_command("e", ["x"], dialect="d", timeout_seconds=1, sql_limits={"surprise": 1})
        self.assertFalse(any("surprise" in part for part in command))

    def test_non_scalar_text_flag_is_passed_only_for_opt_in(self):
        default_cmd = ns.serve_command("e", ["x"], dialect="d", timeout_seconds=1, non_scalar_text="reject")
        self.assertNotIn("--non-scalar-text", default_cmd)
        opt_in_cmd = ns.serve_command("e", ["x"], dialect="d", timeout_seconds=1, non_scalar_text="lossy-replacement")
        self.assertEqual(opt_in_cmd, ["e", "serve", "--dialect", "d", "--deadline-ms", "1000",
                                      "--non-scalar-text", "lossy-replacement", "--input", "x"])
        with self.assertRaises(provider.ConfigError):
            ns.serve_command("e", ["x"], dialect="d", timeout_seconds=1, non_scalar_text="invalid")


class CellTests(unittest.TestCase):
    def test_decoding_agrees_with_the_sdk(self):
        cells = [{"t": "null"}, {"t": "bool", "v": True}, {"t": "i64", "v": "-9223372036854775808"},
                 {"t": "u64", "v": "18446744073709551615"}, {"t": "f64", "bits": "3ff8000000000000"},
                 {"t": "bytes", "v": "00ff"}, {"t": "text", "v": ""}, {"t": "text", "v": "中"},
                 {"t": "text", "units": "d83d"}, {"t": "text", "units": "d83dde00"},
                 {"t": "dex_mutf8", "v": "c080", "utf16_units": "1"}, {"t": "dex_mutf8", "v": "eda0bdedb880", "utf16_units": 2}]
        for cell in cells:
            with self.subTest(cell=cell):
                mine, theirs = ns.decode_cell(cell), sdk_cells.decode_cell(cell)
                if isinstance(mine, (ns.DexMutf8, ns.SurrogateText)):
                    self.assertEqual(mine.text(), theirs.text() if hasattr(theirs, "text") else theirs)
                else:
                    self.assertEqual(mine, theirs)

    def test_malformed_cells_are_protocol_errors(self):
        for cell in ({}, {"t": "weird"}, {"t": "i64"}, {"t": "i64", "v": "x"}, {"t": "text"}, {"t": "text", "v": 5},
                     {"t": "f64", "bits": "zz"}, {"t": "bytes", "v": "g"}, "text", None, {"t": "dex_mutf8", "v": "c0"}):
            with self.subTest(cell=cell):
                with self.assertRaises(ns.EngineProtocolError):
                    ns.dto_value(ns.decode_cell(cell))

    def test_the_dto(self):
        self.assertIsNone(ns.dto_value(ns.decode_cell({"t": "null"})))
        self.assertEqual(ns.dto_value(ns.decode_cell({"t": "i64", "v": "-5"})), "-5")
        self.assertEqual(ns.dto_value(ns.decode_cell({"t": "u64", "v": "18446744073709551615"})), "18446744073709551615")
        self.assertEqual(ns.dto_value(ns.decode_cell({"t": "text", "v": ""})), "")
        self.assertEqual(ns.dto_value(ns.decode_cell({"t": "text", "v": "N"})), "N")  # the text "N" is not NULL
        self.assertEqual(ns.dto_value(ns.decode_cell({"t": "dex_mutf8", "v": "c080", "utf16_units": 1})), "\0")
        self.assertEqual(ns.dto_value(ns.decode_cell({"t": "dex_mutf8", "v": "eda0bdedb880", "utf16_units": 2})), "\U0001F600")
        for cell in ({"t": "f64", "bits": "3ff8000000000000"}, {"t": "bytes", "v": "00"}, {"t": "bool", "v": True},
                     {"t": "text", "units": "d83d"}, {"t": "dex_mutf8", "v": "eda0bd", "utf16_units": 1}):
            with self.subTest(cell=cell):
                with self.assertRaises(ns.EngineProtocolError):
                    ns.dto_value(ns.decode_cell(cell))
        with self.assertRaises(ns.EngineProtocolError):
            ns.dto_value(True)  # a bool is not an integer here

    def test_wire_changes_are_registered_once(self):
        ids = [change["id"] for change in ns.WIRE_CHANGES]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual({c["session"] for c in ns.WIRE_CHANGES}, {"b0", "b1"})
        for change in ns.WIRE_CHANGES:
            self.assertTrue(all(change[key] for key in ("id", "session", "layer", "a0", "new", "effect")), change["id"])


class SessionTests(unittest.TestCase):
    @both
    def test_rows_are_the_dto(self, wire):
        columns = ["a", "b", "c"]
        rows = [("1", None, ""), ("N", "中文", "it's")]
        typed = [[{"t": "u64", "v": "1"}, {"t": "null"}, text("")], [text("N"), text("中文"), text("it's")]]
        h = Harness(self, wire, steps_for(wire, columns, rows, typed))
        with h.session as session:
            self.assertEqual(session.files, {0: "classes.dex"})
            result = session.all("SELECT a,b,c FROM t ORDER BY a")
            self.assertEqual(result, [{"a": "1", "b": None, "c": ""}, {"a": "N", "b": "中文", "c": "it's"}])
            self.assertEqual(session.queries, 2)
            # every statement the engine ran reported its coverage: B0 sends a shape statement and a data statement each time
            self.assertEqual(session.coverage["statements"], 4 if wire == "b0" else 2)
        self.assertEqual(h.process().returncode, 0)

    @both
    def test_opened_describes_the_engine(self, wire):
        h = Harness(self, wire, [])
        with h.session as session:
            self.assertEqual(session.opened["backend"], "meguvizdexdash")
            self.assertEqual(session.opened["wire"], wire)
            self.assertEqual(session.opened["identity"], {"stand_in": True})
            self.assertEqual(session.opened["dataset"]["snapshot_id"], "snapshot-bb")
            self.assertEqual(session.opened["cache"], "memory_session")
            self.assertEqual(session.opened["source_diagnostics"], [])
            self.assertEqual(session.apk, h.apk.resolve())
            self.assertEqual(session.identity()["transport"], "cli_jsonl_v1" if wire == "b0" else "typed_batch_v1")

    def test_b0_sends_what_the_frozen_session_sends(self):
        frozen = F.frozen_cli(tempfile.gettempdir())
        for sql, columns in [("SELECT a FROM t ORDER BY a", ["a"]), ("SELECT x,y FROM t ORDER BY x,y", ["x", "y"]),
                             ('SELECT 1 AS "we\\"ird" FROM t ORDER BY 1', ['we"ird']),
                             ("select b from t order by b", ["b"]), ("SELECT cf.* FROM class_fields cf WHERE c IN ('L;') ORDER BY file_id", ["file_id", "name"])]:
            with self.subTest(sql=sql):
                wanted = []

                def table(self_, statement, *, expected=None, _wanted=wanted, _columns=columns):
                    _wanted.append(statement)
                    if len(_wanted) == 1:
                        yield _columns, None

                session = frozen.CliSession.__new__(frozen.CliSession)
                session.queries = 0
                frozen.CliSession.table = table
                try:
                    list(session.rows(sql))
                finally:
                    del frozen.CliSession.table
                h = Harness(self, "b0", b0_steps(columns, []))
                with h.session as mine:
                    self.assertEqual(mine.all(sql), [])
                self.assertEqual(h.sql()[2:], wanted)  # after the DEX inventory (shape + data), exactly the frozen pair
                self.assertEqual(len(wanted), 2)

    def test_b1_sends_the_statement_alone(self):
        h = Harness(self, "b1", b1_steps(["a"], [[text("x")]]))
        with h.session as session:
            session.all("SELECT a FROM t ORDER BY a")
        self.assertEqual(h.sql(), ["SELECT file_id,entry_name FROM dex_files ORDER BY file_id", "SELECT a FROM t ORDER BY a"])

    @both
    def test_request_ids_options_and_close(self, wire):
        h = Harness(self, wire, [])
        with h.session:
            pass
        requests = h.requests()
        self.assertEqual([r.get("id") for r in requests if "id" in r], sorted({r["id"] for r in requests if "id" in r}))
        self.assertEqual(requests[-1], {"op": "close"})
        self.assertEqual(h.process().returncode, 0)

    @both
    def test_stable_order_and_columns_are_required(self, wire):
        h = Harness(self, wire, [])
        with h.session as session:
            with self.assertRaises(ValueError):
                session.all("SELECT a FROM t")
            self.assertEqual(h.sql(), ["SELECT file_id,entry_name FROM dex_files ORDER BY file_id"] if wire == "b1" else h.sql())

    @both
    def test_ambiguous_columns_are_refused(self, wire):
        steps = b0_steps(["a", "a"], []) if wire == "b0" else b1_steps(["a", "a"], [[text("1"), text("2")]])
        h = Harness(self, wire, steps)
        with h.session as session:
            with self.assertRaises(ns.EngineProtocolError):
                session.all("SELECT 1 AS a, 2 AS a ORDER BY 1")

    @both
    def test_no_columns_are_refused(self, wire):
        steps = [{"frames": [terminal(None, 0)]}] * 2 if wire == "b0" else [{"frames": [terminal(None, 0)]}]
        h = Harness(self, wire, steps)
        with h.session as session:
            with self.assertRaises(ns.EngineProtocolError):
                session.all("SELECT 1 ORDER BY 1")

    @both
    def test_row_budget(self, wire):
        rows = [(str(i),) for i in range(5)]
        h = Harness(self, wire, steps_for(wire, ["a"], rows))
        with h.session as session:
            with self.assertRaises(ns.EngineProtocolError) as caught:
                session.all("SELECT a FROM t ORDER BY a", max_rows=4)
            self.assertEqual(caught.exception.code, "QUOTA_EXCEEDED")
            self.assertIn("row budget", str(caught.exception))

    @both
    def test_row_budget_boundary(self, wire):
        rows = [(str(i),) for i in range(4)]
        h = Harness(self, wire, steps_for(wire, ["a"], rows))
        with h.session as session:
            self.assertEqual(len(session.all("SELECT a FROM t ORDER BY a", max_rows=4)), 4)

    @both
    def test_byte_budget_counts_cell_bytes(self, wire):
        h = Harness(self, wire, steps_for(wire, ["a"], [("中文",), ("ab",)]))
        with h.session as session:
            with self.assertRaises(ns.EngineProtocolError) as caught:
                session.all("SELECT a FROM t ORDER BY a", max_bytes=7)  # 6 + 2 bytes
            self.assertIn("byte budget", str(caught.exception))
        h = Harness(self, wire, steps_for(wire, ["a"], [("中文",), ("ab",)]))
        with h.session as session:
            self.assertEqual(len(session.all("SELECT a FROM t ORDER BY a", max_bytes=8)), 2)

    def test_b0_refuses_a_malformed_hex_cell(self):
        for cell in ("ZZ", "C0", "4", "FF"):
            with self.subTest(cell=cell):
                steps = [{"frames": [terminal(["a"], 0)]}, {"frames": [batch(["a"], [[text(cell)]]), terminal(["a"], 1)]}]
                h = Harness(self, "b0", steps)
                with h.session as session:
                    with self.assertRaises(ns.EngineProtocolError) as caught:
                        session.all("SELECT a FROM t ORDER BY a")
                    self.assertIn("malformed hex cell", str(caught.exception))

    def test_b0_refuses_a_cell_that_is_not_text(self):
        steps = [{"frames": [terminal(["a"], 0)]}, {"frames": [batch(["a"], [[{"t": "u64", "v": "1"}]]), terminal(["a"], 1)]}]
        h = Harness(self, "b0", steps)
        with h.session as session:
            with self.assertRaises(ns.EngineProtocolError):
                session.all("SELECT a FROM t ORDER BY a")

    def test_b1_refuses_cells_the_dto_cannot_hold(self):
        for cell in ({"t": "f64", "bits": "3ff8000000000000"}, {"t": "bytes", "v": "00"}, {"t": "text", "units": "d83d"}):
            with self.subTest(cell=cell):
                h = Harness(self, "b1", b1_steps(["a"], [[cell]]))
                with h.session as session:
                    with self.assertRaises(ns.EngineProtocolError):
                        session.all("SELECT a FROM t ORDER BY a")

    def test_b1_typed_batches(self):
        rows = [[{"t": "u64", "v": "1"}, text("x")], [{"t": "null"}, {"t": "dex_mutf8", "v": "c080", "utf16_units": "1"}]]
        h = Harness(self, "b1", [{"frames": [batch(["a", "b"], rows[:1]), batch(["a", "b"], rows[1:], 1, 1), terminal(["a", "b"], 2)]}])
        with h.session as session:
            got = list(session.batches("SELECT a,b FROM t"))
            self.assertEqual([(b.sequence, b.first_row, b.columns) for b in got], [(0, 0, ("a", "b")), (1, 1, ("a", "b"))])
            self.assertEqual(got[0].rows, ((1, "x"),))
            self.assertIsNone(got[1].rows[0][0])
            self.assertEqual(got[1].rows[0][1].text(), "\0")

    # ---- what the engine says ----

    @both
    def test_engine_errors_keep_their_code(self, wire):
        for code, kind in (("UNSUPPORTED_QUERY", ns.EngineRejected), ("INVALID_ARGUMENT", ns.EngineRejected),
                           ("QUOTA_EXCEEDED", ns.EngineRejected), ("INCOMPLETE_FACTS", ns.EngineIncomplete),
                           ("PARTIAL_INPUT", ns.EngineIncomplete)):
            with self.subTest(code=code):
                error = {"code": code, "stage": "sql", "message": "no", "retryable": False, "details": {}}
                frames = [terminal(None, 0, status="error", error=error, complete=False)]
                h = Harness(self, wire, [{"frames": frames}] * 2)
                with h.session as session:
                    with self.assertRaises(kind) as caught:
                        session.all("SELECT a FROM t ORDER BY a")
                    self.assertEqual(caught.exception.detail["error"]["code"], code)
                    self.assertEqual(provider.classify_failure(caught.exception).code, code)
                    self.assertEqual(provider.classify_failure(caught.exception).origin, "engine")
                    self.assertIsInstance(caught.exception, RuntimeError)

    @both
    def test_a_rejected_request_is_the_engines_error(self, wire):
        frame = {"kind": "rejected", "id": "$id", "error": {"code": "INVALID_ARGUMENT", "stage": "cli.serve", "message": "bad", "details": {}}}
        h = Harness(self, wire, [{"frames": [frame]}] * 2)
        with h.session as session:
            with self.assertRaises(ns.EngineRejected) as caught:
                session.all("SELECT a FROM t ORDER BY a")
            self.assertEqual(caught.exception.code, "INVALID_ARGUMENT")
            self.assertIsNone(session.transport.broken)  # a rejected request does not break the session

    @both
    def test_an_unfinished_statement_is_incomplete_not_short(self, wire):
        for flags in ({"truncated": True}, {"more": True}, {"complete": False}):
            with self.subTest(flags=flags):
                rows = [("1",)]
                frames = [batch(["a"], [[hexcell("1")] if wire == "b0" else [text("1")]]), terminal(["a"], 1, **flags)]
                steps = [{"frames": [terminal(["a"], 0)]}, {"frames": frames}] if wire == "b0" else [{"frames": frames}]
                h = Harness(self, wire, steps)
                with h.session as session:
                    with self.assertRaises(ns.EngineIncomplete):
                        session.all("SELECT a FROM t ORDER BY a")

    @both
    def test_coverage_that_is_not_complete_is_incomplete(self, wire):
        for coverage in ({**COVERAGE, "facts": "partial"}, {**COVERAGE, "input": "unknown"}, {**COVERAGE, "facts": "unknown"}):
            with self.subTest(coverage=coverage):
                frames = [terminal(["a"], 0, coverage=coverage)]
                h = Harness(self, wire, [{"frames": frames}] * 2)
                with h.session as session:
                    with self.assertRaises(ns.EngineIncomplete) as caught:
                        session.all("SELECT a FROM t ORDER BY a")
                    self.assertIn("coverage", str(caught.exception))

    @both
    def test_an_unrecognised_coverage_state_is_a_protocol_error(self, wire):
        frames = [terminal(["a"], 0, coverage={**COVERAGE, "facts": "mostly"})]
        h = Harness(self, wire, [{"frames": frames}] * 2)
        with h.session as session:
            with self.assertRaises(ns.EngineProtocolError):
                session.all("SELECT a FROM t ORDER BY a")
            self.assertIsNotNone(session.transport.broken)

    @both
    def test_coverage_is_summed_over_the_session(self, wire):
        h = Harness(self, wire, steps_for(wire, ["a"], [("1",)]))
        with h.session as session:
            session.all("SELECT a FROM t ORDER BY a")
            coverage = session.coverage
            self.assertEqual((coverage["input"], coverage["facts"]), ("complete", "complete"))
            self.assertEqual(coverage["required_layers"], ["metadata"])

    # ---- the stream itself ----

    @both
    def test_contradictions_in_the_stream(self, wire):
        one = [hexcell("x")] if wire == "b0" else [text("x")]
        two = [hexcell("x"), hexcell("y")] if wire == "b0" else [text("x"), text("y")]
        cases = {
            "row count differs from the rows delivered": ([batch(["a"], [one]), terminal(["a"], 2)], "hang"),
            "batch out of sequence": ([batch(["a"], [one], sequence=3), terminal(["a"], 1)], "hang"),
            "batch first_row wrong": ([batch(["a"], [one], first_row=5), terminal(["a"], 1)], "hang"),
            "batch row_count wrong": ([batch(["a"], [one], count=2), terminal(["a"], 1)], "hang"),
            "ragged row": ([batch(["a", "b"], [one]), terminal(["a", "b"], 1)], "hang"),
            "frame for another request": ([{**batch(["a"], [one]), "id": "other"}, terminal(["a"], 1)], "hang"),
            "unknown kind": ([{"kind": "mystery", "id": "$id"}], "hang"),
            "terminal without status": ([{"kind": "terminal", "id": "$id", "terminal": {"coverage": COVERAGE}}], "hang"),
            "terminal not an object": ([{"kind": "terminal", "id": "$id", "terminal": 5}], "hang"),
            "not json": (["this is not json\n"], "hang"),
            "json but not an object": (["[1,2]\n"], "hang"),
            "no newline at the end": (['{"kind":"batch"'], "exit"),  # the engine ends in the middle of a frame
        }
        for name, (frames, then) in cases.items():
            with self.subTest(case=name):
                if wire == "b0":
                    # the shape statement first, so that the contradiction is in the data statement
                    steps = [{"frames": [terminal(["a"], 0)]}, {"frames": frames, "then": then}]
                else:
                    steps = [{"frames": frames, "then": then}]
                h = Harness(self, wire, steps, timeout=8)
                with h.session as session:
                    with self.assertRaises(ns.EngineError):
                        session.all("SELECT a FROM t ORDER BY a")
                    self.assertIsNotNone(session.transport.broken)
                    with self.assertRaises(ns.SessionClosed):  # a broken session is not used again
                        session.all("SELECT a FROM t ORDER BY a")

    @both
    def test_a_process_that_ends_before_the_terminal_is_lost(self, wire):
        for then in ("exit",):
            frames = [batch(["a"], [[hexcell("1")] if wire == "b0" else [text("1")]])]
            steps = [{"frames": [terminal(["a"], 0)]}, {"frames": frames, "then": then, "code": 0}] if wire == "b0" else [{"frames": frames, "then": then, "code": 0}]
            h = Harness(self, wire, steps)
            with h.session as session:
                with self.assertRaises(ns.EngineLost) as caught:
                    session.all("SELECT a FROM t ORDER BY a")
                self.assertEqual(caught.exception.code, "WORKER_LOST")
                self.assertEqual(provider.classify_failure(caught.exception).code, "WORKER_LOST")

    @both
    def test_a_hung_engine_runs_into_the_deadline(self, wire):
        steps = [{"frames": [], "then": "hang"}] if wire == "b1" else [{"frames": [terminal(["a"], 0)]}, {"frames": [], "then": "hang"}]
        h = Harness(self, wire, steps, timeout=3)
        started = time.monotonic()
        with h.session as session:
            with self.assertRaises(TimeoutError):
                session.all("SELECT a FROM t ORDER BY a")
        self.assertLess(time.monotonic() - started, 30)
        self.assertIsNotNone(h.process().poll())  # the process was not left behind

    @both
    def test_the_deadline_covers_the_whole_session(self, wire):
        h = Harness(self, wire, [], timeout=0.001)
        time.sleep(0.05)
        with self.assertRaises(TimeoutError):
            h.session.__enter__()
        self.assertIsNotNone(h.process().poll() if h.process() else 0)

    @both
    def test_the_engine_may_refuse_to_open(self, wire):
        body = {"code": "INVALID_INPUT", "stage": "capture", "message": "no such file", "retryable": False, "details": {}}
        h = Harness(self, wire, [], opened=None, with_entry=False, stderr=json.dumps(body), exit_before_open=2)
        with self.assertRaises(ns.EngineRejected) as caught:
            h.session.__enter__()
        self.assertEqual(caught.exception.code, "INVALID_INPUT")
        self.assertEqual(provider.classify_failure(caught.exception).code, "INVALID_INPUT")

    @both
    def test_an_engine_that_dies_silently_before_opening_is_lost(self, wire):
        h = Harness(self, wire, [], opened=None, with_entry=False, exit_before_open=3)
        with self.assertRaises(ns.EngineLost):
            h.session.__enter__()

    @both
    def test_the_first_frame_must_be_the_stream_protocol(self, wire):
        for opened in ({"kind": "batch"}, {**OPENED, "protocol": "other"}, {"kind": "opened", "protocol": "mdd.cli-stream.v1"},
                       {**OPENED, "dataset": {**OPENED["dataset"], "dex_count": "x"}}):
            with self.subTest(opened=opened):
                h = Harness(self, wire, [], opened=opened, with_entry=False, hang_at_end=True)
                with self.assertRaises(ns.EngineProtocolError):
                    h.session.__enter__()

    @both
    def test_a_nonzero_exit_after_a_clean_close_is_not_hidden(self, wire):
        h = Harness(self, wire, [], exit_code=7)
        with self.assertRaises(ns.EngineLost) as caught:
            with h.session:
                pass
        self.assertIn("exited unsuccessfully", str(caught.exception))

    @both
    def test_an_error_in_the_block_kills_the_engine(self, wire):
        h = Harness(self, wire, [], hang_at_end=True)
        with self.assertRaises(KeyError):
            with h.session:
                raise KeyError("consumer failed")
        self.assertIsNotNone(h.process().poll())
        self.assertNotIn({"op": "close"}, h.requests())  # it was ended, not asked politely

    @both
    def test_an_engine_that_ignores_close_is_killed(self, wire):
        h = Harness(self, wire, [], close="hang")
        h.session.transport.CLOSE_WAIT = 1.0
        started = time.monotonic()
        with self.assertRaises(ns.EngineLost) as caught:
            with h.session:
                pass
        self.assertIn("did not exit after close", str(caught.exception))
        self.assertLess(time.monotonic() - started, 30)
        self.assertIsNotNone(h.process().poll())

    @both
    def test_an_abandoned_statement_does_not_poison_the_next(self, wire):
        rows = [(str(i),) for i in range(3)]
        steps = steps_for(wire, ["a"], rows) + steps_for(wire, ["b"], [("later",)])
        h = Harness(self, wire, steps)
        with h.session as session:
            generator = session.rows("SELECT a FROM t ORDER BY a")
            self.assertEqual(next(generator), {"a": "0"})
            generator.close()  # the consumer walked away mid-statement
            self.assertEqual(session.all("SELECT b FROM t ORDER BY b"), [{"b": "later"}])
            self.assertIsNone(session.transport.broken)

    @both
    def test_an_abandoned_statement_withholds_completeness(self, wire):
        # W-B0-6 / fail-closed: a statement that was sent but walked away from is not covered. Whether its terminal
        # is still pending or has been skipped by the next statement, sent != covered must withhold completeness.
        rows = [(str(i),) for i in range(3)]
        steps = steps_for(wire, ["a"], rows) + steps_for(wire, ["b"], [("later",)])
        h = Harness(self, wire, steps)
        with h.session as session:
            generator = session.rows("SELECT a FROM t ORDER BY a")
            self.assertEqual(next(generator), {"a": "0"})
            generator.close()
            # the abandoned terminal has not been read yet: it is pending, and already uncovered
            self.assertGreater(session.coverage["abandoned"], 0)
            self.assertLess(session.coverage["statements"], session.transport.statement_count)
            self.assertIn("statement_abandoned", sp.coverage_reasons(session))
            # the next statement skips the abandoned terminal; it is counted as abandoned, still not complete
            self.assertEqual(session.all("SELECT b FROM t ORDER BY b"), [{"b": "later"}])
            self.assertGreater(session.coverage["abandoned"], 0)
            self.assertLess(session.coverage["statements"], session.transport.statement_count)
            self.assertIn("statement_abandoned", sp.coverage_reasons(session))

    @both
    def test_terminal_columns_must_match_the_batches(self, wire):
        # a terminal that names other columns than the batches contradicts itself; both wires refuse it
        one = [hexcell("1")] if wire == "b0" else [text("1")]
        frames = [batch(["a"], [one]), terminal(["b"], 1)]
        steps = [{"frames": [terminal(["a"], 0)]}, {"frames": frames}] if wire == "b0" else [{"frames": frames}]
        h = Harness(self, wire, steps)
        with h.session as session:
            with self.assertRaises(ns.EngineProtocolError):
                session.all("SELECT a FROM t ORDER BY a")

    @both
    def test_a_cancelled_terminal_is_fail_closed(self, wire):
        # a cancelled statement is not a result: it raises with the engine's code, never a shorter list of rows
        error = {"code": "CANCELLED", "stage": "sql", "message": "the statement was cancelled", "details": {}}
        frames = [terminal(["a"], 0, status="cancelled", error=error, complete=False)]
        steps = [{"frames": [terminal(["a"], 0)]}, {"frames": frames}] if wire == "b0" else [{"frames": frames}]
        h = Harness(self, wire, steps)
        with h.session as session:
            with self.assertRaises(ns.EngineError) as caught:
                session.all("SELECT a FROM t ORDER BY a")
            self.assertEqual(provider.classify_failure(caught.exception).code, "CANCELLED")
        self.assertFalse(provider.completeness("cancelled", "complete", "complete", True)["complete"])

    @both
    def test_the_statement_size_is_bounded(self, wire):
        h = Harness(self, wire, [])
        with h.session as session:
            with self.assertRaises(ns.EngineProtocolError) as caught:
                session.all("SELECT '" + "x" * (ns.MAX_SQL_BYTES + 1) + "' ORDER BY 1")
            self.assertEqual(caught.exception.code, "INVALID_ARGUMENT")

    @both
    def test_a_frame_over_the_byte_budget(self, wire):
        big = "y" * 5000
        steps = ([{"frames": [terminal(["a"], 0)]}] if wire == "b0" else []) + [
            {"frames": [batch(["a"], [[hexcell(big)] if wire == "b0" else [text(big)]]), terminal(["a"], 1)], "then": "hang"}]
        h = Harness(self, wire, steps, settings=ns.StructuralConfig(max_line_bytes=2048), timeout=10)
        with h.session as session:
            with self.assertRaises(ns.EngineProtocolError):
                session.all("SELECT a FROM t ORDER BY a")

    # ---- inventory and layers ----

    @both
    def test_layer_issues_are_reported_not_hidden(self, wire):
        issue = {"dex_occurrence_id": "d0", "layers": "code,references",
                 "error": {"code": "INVALID_INPUT", "stage": "facts.references", "message": "CALLER_INS_SIZE_MISMATCH",
                           "details": {"reason": "CALLER_INS_SIZE_MISMATCH"}}}
        opened = json.loads(json.dumps(OPENED))
        opened["dataset"]["layer_issues"] = [issue]
        h = Harness(self, wire, [], opened=opened)
        with h.session as session:
            self.assertEqual(len(session.layer_issues), 1)
            diagnostics = session.opened["source_diagnostics"]
            self.assertEqual(diagnostics[0]["reason"], "CALLER_INS_SIZE_MISMATCH")
            self.assertEqual(diagnostics[0]["layers"], "code,references")

    @both
    def test_the_physical_dex_inventory_is_checked(self, wire):
        archive = Path(tempfile.mkdtemp(prefix="mdd051-apk-")) / "x.apk"
        self.addCleanup(lambda: __import__("shutil").rmtree(archive.parent, ignore_errors=True))
        import zipfile
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("classes.dex", b"dex")
            z.writestr("classes2.dex", b"dex")
        h = Harness(self, wire, [])  # the engine reports only classes.dex
        session = ns.SESSIONS[wire](archive, timeout=20, launch=h.launch)
        h.session = session
        with self.assertRaises(provider.InventoryError) as caught:
            session.__enter__()
        self.assertEqual(caught.exception.detail["missing"], ["classes2.dex"])
        self.assertIsNotNone(session.transport.process.poll())  # and the engine was ended


class CoverageTests(unittest.TestCase):
    """The summed coverage keeps the worst state ever reported, whatever order the statements came in."""

    def test_the_worst_state_wins(self):
        for sequence, expected in ((["complete", "partial", "complete"], "partial"), (["partial", "complete"], "partial"),
                                   (["complete", "unknown", "partial"], "unknown"), (["unknown", "complete"], "unknown"),
                                   (["complete", "complete"], "complete"), ([], "complete")):
            with self.subTest(sequence=sequence):
                coverage = ns.Coverage()
                for state in sequence:
                    coverage.add({"input": state, "facts": state, "required_layers": ["metadata"], "issues": []})
                self.assertEqual((coverage.input, coverage.facts), (expected, expected))
                self.assertEqual(coverage.statements, len(sequence))

    def test_layers_and_issues_accumulate(self):
        coverage = ns.Coverage()
        coverage.add({"input": "complete", "facts": "complete", "required_layers": ["b", "a"], "issues": [{"x": 1}]})
        coverage.add({"input": "complete", "facts": "complete", "required_layers": ["c"], "issues": [{"x": 2}]})
        described = coverage.describe()
        self.assertEqual(described["required_layers"], ["a", "b", "c"])
        self.assertEqual(described["issues"], [{"x": 1}, {"x": 2}])

    def test_a_missing_report_is_unknown_not_complete(self):
        coverage = ns.Coverage()
        coverage.add({})
        self.assertEqual((coverage.input, coverage.facts), ("unknown", "unknown"))

    def test_the_session_keeps_the_worst_state_of_a_failed_statement(self):
        error = {"code": "INCOMPLETE_FACTS", "stage": "facts", "message": "no", "details": {}}
        partial = {**COVERAGE, "facts": "partial"}
        frames = [terminal(None, 0, status="error", error=error, complete=False, coverage=partial)]
        h = Harness(self, "b1", [{"frames": frames}])
        with h.session as session:
            with self.assertRaises(ns.EngineIncomplete):
                session.all("SELECT a FROM t ORDER BY a")
            self.assertEqual(session.coverage["facts"], "partial")
            self.assertEqual(session.coverage["statements"], 2)


class FactoryTests(unittest.TestCase):
    """NativeSession(...): the provider setting decides which path the audit takes."""

    def test_rollback_value_returns_hostlab_own_session_and_starts_nothing(self):
        sentinel = object()
        made = []

        def original(apk, timeout, threads):
            made.append((apk, timeout, threads))
            return sentinel

        config = {"schema": provider.CONFIG_SCHEMA, "native_engine": "dexsql"}
        with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("nothing may be started")), \
                mock.patch.object(ns.provider.installer, "verify", side_effect=AssertionError("nothing may be verified")):
            got = ns.NativeSession("some.apk", timeout=11, threads=3, provider_config=config, original=original)
        self.assertIs(got, sentinel)
        self.assertEqual(made, [("some.apk", 11, 3)])

    def test_default_configuration_is_the_rollback_value(self):
        for environ in ({}, {"HOSTLAB_PROVIDER_CONFIG": ""}):
            with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("nothing may be started")):
                got = ns.NativeSession("x.apk", provider_config=None, environ=environ, original=lambda *a, **k: "original")
            self.assertEqual(got, "original")

    def test_original_session_is_hostlab_native_cli(self):
        import types
        cli = types.ModuleType("native_cli")
        cli.CliSession = type("CliSession", (), {})
        with mock.patch.dict(sys.modules, {"native_cli": cli}):
            self.assertIs(ns.original_session(), cli.CliSession)

    def test_the_wire_is_chosen_by_the_structural_setting(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "a.dex"
            apk.write_bytes(b"dex")
            launched = ns.EngineLaunch(["x"], {}, {"id": 1})
            config = {"schema": provider.CONFIG_SCHEMA, "native_engine": "meguvizdexdash"}
            for wire, cls in (("b0", ns.B0Session), ("b1", ns.B1Session)):
                with mock.patch.object(ns, "engine_launch", return_value=launched) as made:
                    session = ns.NativeSession(apk, timeout=5, threads=1, provider_config=config,
                                               structural={"schema": ns.STRUCTURAL_SCHEMA, "wire": wire}, state=directory)
                self.assertIs(type(session), cls)
                self.assertEqual(made.call_args.kwargs["settings"].wire, wire)
                self.assertEqual(made.call_args.args[1], [apk.resolve()])

    def test_the_default_wire_is_b0(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "a.dex"
            apk.write_bytes(b"dex")
            with mock.patch.object(ns, "engine_launch", return_value=ns.EngineLaunch(["x"], {}, None)):
                session = ns.NativeSession(apk, provider_config={"schema": provider.CONFIG_SCHEMA, "native_engine": "meguvizdexdash"},
                                           state=directory, environ={})
            self.assertIs(type(session), ns.B0Session)

    def test_engine_launch_goes_through_the_pinned_engine_check(self):
        engine = support.FakeEngine()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            binary, manifest, engine = support.pin_binary(base, engine)
            config = provider.parse_config({"schema": provider.CONFIG_SCHEMA, "native_engine": "meguvizdexdash",
                                            "meguvizdexdash": {"manifest": str(manifest), "profile_policy": "allow_unadmitted"}})
            with mock.patch.dict(os.environ, {"HOSTLAB_MEGUVIZDEXDASH": str(binary)}):
                launch = ns.engine_launch(config, [base / "in.apk"], timeout=30, threads=2, state=base / "state",
                                          settings=ns.StructuralConfig(sql_limits=(("result_rows", 9),)), runner=engine)
            self.assertEqual(launch.command[:2], [str(binary.resolve()), "serve"])
            self.assertIn("--sql-max-result-rows", launch.command)
            self.assertEqual(launch.identity["backend"], "meguvizdexdash")
            self.assertEqual(launch.identity["profile"]["admitted"], False)
            self.assertEqual(launch.env["MDD_FACTS_THREADS"], str(provider.effective_threads(2)))
            self.assertTrue(str(launch.namespaces["reports"]).startswith(str(base.resolve() / "state" / "mdd-engine")))

    def test_an_unpinned_engine_is_not_started(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            binary, manifest, engine = support.pin_binary(base, support.FakeEngine())
            binary.write_bytes(b"a different binary")
            config = provider.parse_config({"schema": provider.CONFIG_SCHEMA, "native_engine": "meguvizdexdash",
                                            "meguvizdexdash": {"manifest": str(manifest), "profile_policy": "allow_unadmitted"}})
            engine.calls.clear()
            with mock.patch.dict(os.environ, {"HOSTLAB_MEGUVIZDEXDASH": str(binary)}):
                with self.assertRaises(ns.provider.installer.EngineUnavailable):
                    ns.engine_launch(config, [base / "in.apk"], timeout=30, threads=2, state=base / "state",
                                     settings=ns.StructuralConfig(), runner=engine)
            self.assertEqual(engine.calls, [])  # a binary with another digest is never run

    def test_b1_direct_dto_matches_conservative_decode_and_errors(self):
        valid_cells = [
            {"t": "null"},
            {"t": "i64", "v": "0"},
            {"t": "i64", "v": "-0"},
            {"t": "i64", "v": "-9223372036854775808"},
            {"t": "u64", "v": "18446744073709551615"},
            {"t": "i64", "v": "007"},
            {"t": "text", "v": "Lcom/example/A;"},
            {"t": "text", "v": "中文😀"},
            {"t": "text", "v": "\ud800"},
            {"t": "text", "units": "00610062"},
            {"t": "dex_mutf8", "v": "61c08062", "utf16_units": "3"},
        ]
        for cell in valid_cells:
            expected = ns.dto_value(ns.decode_cell(cell))
            actual = ns.B1Session._decode_dto_cell(cell)
            self.assertEqual(actual, expected, cell)

        invalid_cells = [
            {"t": "bool", "v": True},
            {"t": "f64", "bits": "0000000000000000"},
            {"t": "bytes", "v": "deadbeef"},
            {"t": "text", "units": "d800"},
            {"t": "text", "v": 123},
            {"t": "i64", "v": "not-an-int"},
            {"t": "unknown"},
            "bad-not-dict",
        ]
        for cell in invalid_cells:
            with self.assertRaises(ns.EngineProtocolError) as exp_ctx:
                ns.dto_value(ns.decode_cell(cell))
            with self.assertRaises(ns.EngineProtocolError) as act_ctx:
                ns.B1Session._decode_dto_cell(cell)
            self.assertEqual(str(act_ctx.exception), str(exp_ctx.exception), cell)

    def test_b1_direct_batches_all_matches_conservative_path(self):
        cols = ["c1", "c2", "c3", "c4", "c5", "c6"]
        rows = [
            [{"t": "u64", "v": "0"}, text("ascii"), {"t": "null"}, {"t": "i64", "v": "-7"},
             {"t": "text", "units": "0061"}, {"t": "dex_mutf8", "v": "c080", "utf16_units": "1"}],
            [{"t": "u64", "v": "42"}, text("中文"), {"t": "u64", "v": "999"}, {"t": "i64", "v": "0"},
             text("end"), {"t": "null"}],
        ]
        with mock.patch.dict(os.environ, {"MDD_OPT_WIRE_DIRECT_JSON": "1"}):
            h_direct = Harness(self, "b1", b1_steps(cols, rows))
            with h_direct.session as session:
                got_direct = session.all("SELECT c1,c2,c3,c4,c5,c6 FROM t ORDER BY c1")
        with mock.patch.dict(os.environ, {"MDD_OPT_WIRE_DIRECT_JSON": "0"}):
            h_ref = Harness(self, "b1", b1_steps(cols, rows))
            with h_ref.session as session:
                got_ref = session.all("SELECT c1,c2,c3,c4,c5,c6 FROM t ORDER BY c1")
        self.assertEqual(got_direct, got_ref)
        # Non-canonical leading-zero u64 still delegates identically.
        with mock.patch.dict(os.environ, {"MDD_OPT_WIRE_DIRECT_JSON": "1"}):
            h_lead = Harness(self, "b1", b1_steps(["a"], [[{"t": "u64", "v": "07"}]]))
            with h_lead.session as session:
                self.assertEqual(session.all("SELECT a FROM t ORDER BY a"), [{"a": "7"}])
        # Verify batch_rows=10000 is sent by direct batch reader.
        reqs = [r for r in h_direct.requests() if r.get("sql", "").startswith("SELECT c1")]
        self.assertEqual(reqs[0].get("batch_rows"), 10000)


if __name__ == "__main__":
    unittest.main()
