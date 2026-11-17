"""The independent gates (MDD-052, acceptance line 4): they run unchanged, they are timed whole, and no saving for sharing facts
with them is counted at this stage. A stand-in script plays the gate; HostLab's real gates need a real host APK.

Run: python -I -m unittest discover -s integrations/hostlab -p "test_surface_gate.py"
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import surface_gate as G  # noqa: E402

PROBE = '''\
import json, os, sys, time
args = sys.argv[1:]
sleep, code = float(args[0]), int(args[1])
print(json.dumps({"argv": args, "cwd": os.getcwd(), "probe": os.environ.get("GATE_PROBE")}))
sys.stderr.write("diagnostic\\n")
time.sleep(sleep)
sys.exit(code)
'''


class Temp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name).resolve()
        self.script = self.dir / "gate.py"
        self.script.write_text(PROBE, encoding="utf-8")

    def argv(self, sleep=0.0, code=0, *extra):
        return [sys.executable, "-I", str(self.script), str(sleep), str(code), *extra]


class TheGatesArePinned(unittest.TestCase):
    def test_the_two_gate_digests_are_those_of_the_committed_evidence(self):
        digests = G.pinned_digests()
        self.assertEqual(set(digests), {"intake", "home"})
        self.assertEqual(digests["intake"], "36fce528921e54be5600bd37eb4b6273e97552d2a0701170130b798fcbbe0068")
        self.assertEqual(digests["home"], "85351a40067cd129284ec10cd9809a9d7497aebbc93252d0ea7442c488e2b6bc")

    def test_an_evidence_file_that_does_not_name_a_gate_once_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text(json.dumps({"tools": {"analysis/run_intake.py": "0" * 64}}), encoding="utf-8")
            with self.assertRaises(ValueError):
                G.pinned_digests(path)
            path.write_text(json.dumps({"a": {"analysis/run_intake.py": "0" * 64, "analysis/home_frame_audit.py": "1" * 64},
                                        "b": {"tools/hostlab/analysis/run_intake.py": "2" * 64}}), encoding="utf-8")
            with self.assertRaises(ValueError):
                G.pinned_digests(path)

    def test_the_command_lines_are_those_hostlab_uses(self):
        self.assertEqual(G.hostlab_argv("intake", "/sb", "/a.apk", tsv="/o/features.tsv", python="py"),
                         ["py", str(Path("/sb") / "run_intake.py"), "/a.apk", "--tsv", "/o/features.tsv"])
        self.assertEqual(G.hostlab_argv("home", "/sb", "/a.apk", python="py"), ["py", str(Path("/sb") / "home_frame_audit.py"), "/a.apk"])
        with self.assertRaises(ValueError):
            G.hostlab_argv("intake", "/sb", "/a.apk")
        with self.assertRaises(ValueError):
            G.hostlab_argv("other", "/sb", "/a.apk")


class RunUnchanged(Temp):
    def test_the_gate_gets_exactly_the_arguments_directory_and_environment_it_was_given(self):
        elsewhere = self.dir / "elsewhere"
        elsewhere.mkdir()
        run = G.run_gate("home", self.argv(0, 0, "a b", "--flag=1", ""), cwd=elsewhere, env=dict(os.environ, GATE_PROBE="value"),
                         log_dir=self.dir / "logs")
        self.assertEqual(run.argv, tuple(self.argv(0, 0, "a b", "--flag=1", "")))
        self.assertTrue(run.accepted())
        saw = json.loads((self.dir / "logs" / "home.stdout.log").read_text(encoding="utf-8"))
        self.assertEqual(saw, {"argv": ["0", "0", "a b", "--flag=1", ""], "cwd": str(elsewhere), "probe": "value"})

    def test_without_an_environment_the_gate_inherits_ours_untouched(self):
        with mock.patch.dict(os.environ, {"GATE_PROBE": "inherited"}):
            run = G.run_gate("home", self.argv(), log_dir=self.dir / "logs")
        saw = json.loads((self.dir / "logs" / "home.stdout.log").read_text(encoding="utf-8"))
        self.assertEqual((saw["probe"], saw["cwd"]), ("inherited", os.getcwd()))
        self.assertTrue(run.accepted())

    def test_the_output_is_kept_byte_for_byte_when_logs_are_asked_for(self):
        run = G.run_gate("home", self.argv(), log_dir=self.dir / "logs")
        out = (self.dir / "logs" / "home.stdout.log").read_bytes()
        err = (self.dir / "logs" / "home.stderr.log").read_bytes()
        self.assertEqual((hashlib.sha256(out).hexdigest(), hashlib.sha256(err).hexdigest()), (run.stdout_sha256, run.stderr_sha256))
        self.assertEqual((len(out), len(err)), (run.stdout_bytes, run.stderr_bytes))
        self.assertIn(b"diagnostic", err)

    def test_the_script_is_not_touched(self):
        before = G.sha256_file(self.script)
        run = G.run_gate("home", self.argv(), script=self.script, expected_script_sha256=before)
        self.assertEqual((G.sha256_file(self.script), run.script_sha256), (before, before))


class Timing(Temp):
    def test_the_clock_runs_from_before_the_start_to_after_the_end(self):
        events = []
        real = subprocess.run

        def clock():
            events.append("clock")
            return 10.0 if events.count("clock") == 1 else 12.5

        def spy(*a, **k):
            events.append("run")
            return real(*a, **k)

        with mock.patch.object(subprocess, "run", side_effect=spy):
            run = G.run_gate("home", self.argv(), clock=clock)
        self.assertEqual(events, ["clock", "run", "clock"])
        self.assertEqual(run.seconds, 2.5)

    def test_the_time_covers_the_whole_process_not_a_part_of_it(self):
        started = time.monotonic()
        run = G.run_gate("home", self.argv(sleep=0.6))
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(run.seconds, 0.6)
        self.assertLessEqual(run.seconds, elapsed)

    def test_a_gate_that_fails_is_timed_and_recorded_not_dropped(self):
        run = G.run_gate("intake", self.argv(sleep=0.2, code=3))
        self.assertEqual((run.exit_code, run.finished, run.accepted(), run.timed_out), (3, True, False, False))
        self.assertGreaterEqual(run.seconds, 0.2)
        total = G.accounting(1.0, [run])
        self.assertAlmostEqual(total["total_seconds"], 1.0 + run.seconds)
        self.assertFalse(total["all_gates_accepted"])
        self.assertTrue(total["all_gates_finished"])

    def test_the_exit_statuses_hostlab_accepts(self):
        self.assertTrue(G.run_gate("intake", self.argv(code=0)).accepted())
        self.assertTrue(G.run_gate("intake", self.argv(code=1)).accepted())
        self.assertFalse(G.run_gate("intake", self.argv(code=2)).accepted())
        self.assertTrue(G.run_gate("home", self.argv(code=0)).accepted())
        self.assertFalse(G.run_gate("home", self.argv(code=1)).accepted())

    def test_a_gate_that_is_stopped_at_its_limit_is_a_time_out_not_a_success(self):
        run = G.run_gate("home", self.argv(sleep=30), timeout=0.8)
        self.assertEqual((run.timed_out, run.exit_code, run.finished, run.accepted()), (True, None, False, False))
        self.assertGreaterEqual(run.seconds, 0.8)
        total = G.accounting(0.0, [run])
        self.assertFalse(total["all_gates_finished"])
        self.assertGreaterEqual(total["gate_seconds"], 0.8)

    def test_timeout_and_exit_status_are_independent_acceptance_conditions(self):
        completed = G.run_gate("home", self.argv())
        for name, accepted_codes in (("home", (0,)), ("intake", (0, 1))):
            for timed_out in (False, True):
                for exit_code in (None, 0, 1, 3):
                    with self.subTest(name=name, timed_out=timed_out, exit_code=exit_code):
                        run = replace(completed, name=name, timed_out=timed_out, exit_code=exit_code)
                        finished = not timed_out and exit_code is not None
                        accepted = finished and exit_code in accepted_codes
                        self.assertEqual(run.finished, finished)
                        self.assertEqual(run.accepted(), accepted)
                        self.assertEqual(run.record()["accepted"], accepted)
                        total = G.accounting(2.0, [run])
                        self.assertEqual(total["all_gates_finished"], finished)
                        self.assertEqual(total["all_gates_accepted"], accepted)
                        self.assertAlmostEqual(total["total_seconds"], 2.0 + run.seconds)


class NoSavingIsCounted(Temp):
    def run_two(self):
        return [G.run_gate("intake", self.argv(0.1)), G.run_gate("home", self.argv(0.1))]

    def test_the_total_is_the_surface_time_plus_every_gates_full_time(self):
        gates = self.run_two()
        total = G.accounting(5.0, gates)
        self.assertEqual(total["gate_seconds"], gates[0].seconds + gates[1].seconds)
        self.assertEqual(total["total_seconds"], 5.0 + gates[0].seconds + gates[1].seconds)
        self.assertEqual([g["name"] for g in total["gates"]], ["intake", "home"])
        self.assertEqual(total["gate_reuse"], {"status": "not_implemented", "task": "HL-12", "benefit_seconds_counted": 0.0})
        self.assertEqual(total["schema"], G.ACCOUNTING_SCHEMA)

    def test_a_reuse_saving_is_refused(self):
        for saving in (0.001, 22.0, -1.0):
            with self.subTest(saving), self.assertRaises(ValueError) as caught:
                G.accounting(5.0, self.run_two(), gate_reuse_benefit_seconds=saving)
            self.assertIn("HL-12", str(caught.exception))
        G.accounting(5.0, self.run_two(), gate_reuse_benefit_seconds=0)

    def test_a_negative_duration_is_refused(self):
        with self.assertRaises(ValueError):
            G.accounting(-1.0, [])

    def test_no_gates_is_a_surface_time_only(self):
        total = G.accounting(2.0, [])
        self.assertEqual((total["gate_seconds"], total["total_seconds"], total["all_gates_finished"]), (0, 2.0, True))


class AGateThatIsNotTheRecordedOneDoesNotRun(Temp):
    def test_a_different_script_is_refused_before_anything_runs(self):
        marker = self.dir / "ran"
        self.script.write_text(PROBE + f"\nopen({str(marker)!r}, 'w').close()\n", encoding="utf-8")
        with self.assertRaises(G.GateChanged):
            G.run_gate("home", self.argv(), script=self.script, expected_script_sha256=hashlib.sha256(PROBE.encode()).hexdigest())
        self.assertFalse(marker.exists())

    def test_a_script_that_changes_while_it_runs_is_refused(self):
        self.script.write_text(PROBE.replace("time.sleep(sleep)", f"open({str(self.script)!r}, 'a').write('# changed')\ntime.sleep(sleep)"), encoding="utf-8")
        with self.assertRaises(G.GateChanged) as caught:
            G.run_gate("home", self.argv(), script=self.script)
        self.assertIn("changed while it ran", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
