"""Mutation check for MDD-051: change one behaviour of native_session.py or structural_provider.py at a time and require the
tests to notice.

    python -I artifacts/mdd-051/mutation/mutate_structural.py [--jobs N] [--only 3,17] [--list] [--out results.txt]

Each mutant replaces one exact piece of integrations/hostlab/native_session.py or structural_provider.py in a private copy of the
parts of the tree the tests read (the repository itself is never edited), then runs the three suites in order - provider, session,
equivalence - and stops at the first that fails. The equivalence suite needs the built engine (MDD_WORKER_BINARY, or target/); a
missing engine is an error. A mutant that leaves every suite green is a survivor and exits 1. A pattern that no longer matches
exactly once is a failure too, so the list cannot rot silently. A clean copy is run first and must pass.

Only these two modules are mutated. The helpers (structural_compare, structural_frozen, ...) are hashed into the golden, so any
change to them fails the golden's provenance check; their behaviour is covered by the negative controls of
test_structural_equivalence.py instead."""
import argparse
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
COPY = ("integrations", "conformance", "python", "include", "crates", "tests/fixtures")
SUITES = ("test_structural_provider.py", "test_structural_session.py", "test_structural_equivalence.py")
S, P = "native_session.py", "structural_provider.py"

MUTANTS = [
    # ---- native_session.py: the SQL literals HostLab's rules build their statements from
    (S, "literal lets a NUL through", r'''any(c in value for c in "\r\n\0")''', r'''any(c in value for c in "\r\n")'''),
    (S, "literal does not double a quote", '''value.replace("'", "''")''', '''value.replace("'", "\\\\'")'''),
    (S, "in_list separates with a space", '''return ",".join(literal(value) for value in values)''', '''return ", ".join(literal(value) for value in values)'''),
    # ---- configuration and the command line
    (S, "an unknown structural key is accepted", '''    if extra:
        raise provider.ConfigError(f"structural config has unsupported keys''', '''    if False:
        raise provider.ConfigError(f"structural config has unsupported keys'''),
    (S, "any wire is accepted", '''    if wire not in WIRES:''', '''    if False:'''),
    (S, "the engine gets DexSQL's --threads", '''    command = [str(binary), "serve", "--dialect", dialect,''', '''    command = [str(binary), "--threads", "2", "serve", "--dialect", dialect,'''),
    (S, "the SQL budgets are not passed", '''        if sql_limits and key in sql_limits:''', '''        if False:'''),
    # ---- typed cells and the DTO
    (S, "an integer is not rendered as text", '''    if type(value) is int:
        return str(value)''', '''    if type(value) is int:
        return value'''),
    (S, "a bool counts as an integer", '''    if type(value) is int:
        return str(value)''', '''    if isinstance(value, int):
        return str(value)'''),
    (S, "a REAL is rendered instead of refused", '''    raise EngineProtocolError(f"a {type(value).__name__} cell cannot be represented in the audit DTO")''',
     '''    return str(value)'''),
    (S, "MUTF-8 surrogates are decoded wrongly", '''units.append(((b & 0x0F) << 12) | ((data[i + 1] & 0x3F) << 6) | (data[i + 2] & 0x3F))''',
     '''units.append(((b & 0x0F) << 11) | ((data[i + 1] & 0x3F) << 6) | (data[i + 2] & 0x3F))'''),
    (S, "an unpaired surrogate is accepted as text", '''        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            raise EngineProtocolError("a text cell holds an unpaired surrogate; it is not valid Unicode text") from None
        return text''', '''        return text'''),
    # ---- what the engine says
    (S, "an engine error loses its code", '''        if code is None and body and isinstance(body.get("code"), str):''', '''        if False:'''),
    (S, "a failed terminal is read as a result", '''        if terminal["operation_status"] != "ok":
            error = terminal.get("error")''', '''        if False:
            error = terminal.get("error")'''),
    (S, "incomplete facts are an ordinary rejection", '''            cls = EngineIncomplete if code in INCOMPLETE_CODES else EngineRejected''', '''            cls = EngineRejected'''),
    (S, "the terminal row count is not checked", '''        if emitted != state.rows:''', '''        if False:'''),
    (S, "a truncated result is accepted", '''        if response.get("truncated") is not False or response.get("more_available") is not False:''', '''        if False:'''),
    (S, "incomplete coverage is accepted", '''        if not complete["complete"]:''', '''        if False:'''),
    (S, "batches may arrive out of sequence", '''int(document["sequence"]) == state.next_sequence''', '''True'''),
    (S, "a batch may start at any row", '''int(document["first_row"]) == state.rows''', '''True'''),
    (S, "a frame for another request is taken", '''                if frame.get("id") != state.id:''', '''                if False:'''),
    (S, "the worst coverage is not kept", '''        return a if order.get(a, 3) >= order.get(b, 3) else b''', '''        return a if order.get(a, 3) <= order.get(b, 3) else b'''),
    (S, "an abandoned statement is forgotten", '''                self.abandoned.add(state.id)''', '''                pass'''),
    # ---- the guards of rows()
    (S, "the stable-ordering guard is gone", '''        if "ORDER BY" not in sql.upper():
            raise ValueError("native audit requires stable ordering")''', '''        if False:
            raise ValueError("native audit requires stable ordering")'''),
    (S, "ambiguous columns are accepted", '''        if not columns or len(columns) != len(set(columns)):''', '''        if False:'''),
    (S, "B0 drops the shape statement's limit", '''AS hostlab_shape LIMIT 0"):''', '''AS hostlab_shape LIMIT 1"):'''),
    (S, "B0 projects the value, not its hex", '''ELSE hex(CAST(" + identifier(name) + " AS TEXT)) END AS''', '''ELSE CAST(" + identifier(name) + " AS TEXT) END AS'''),
    (S, "B0 reads the text N as NULL no more", '''                if cell == "N":
                    value = None''', '''                if cell == "":
                    value = None'''),
    (S, "B0 decodes leniently", '''bytes.fromhex(cell).decode("utf-8", "strict")''', '''bytes.fromhex(cell).decode("utf-8", "replace")'''),
    (S, "B0 allows one row too many", '''            count += 1
            if count > max_rows:''', '''            count += 1
            if count > max_rows + 1:'''),
    (S, "B1 allows one row too many", '''                count += 1
                if count > max_rows:''', '''                count += 1
                if count > max_rows + 1:'''),
    (S, "B0 counts no bytes", '''                used += len(value.encode()) if value is not None else 0''', '''                used += 0'''),
    (S, "B1 counts no bytes", '''                        used += len(value.encode())''', '''                        used += 0'''),
    (S, "B1 does not count its statements", '''            self._need_unambiguous(list(self.last_columns or ()))
        self.queries += 1''', '''            self._need_unambiguous(list(self.last_columns or ()))'''),
    # ---- the session
    (S, "the DEX inventory is not compared", '''            provider.verify_inventory(expected, self.files)''', '''            pass'''),
    (S, "an error in the block asks the engine to close politely", '''self.transport.close(clean=error is None and self.transport.broken is None)''', '''self.transport.close(clean=True)'''),
    (S, "a bad exit status after close is not reported", '''if clean and problem is None and process.poll() is not None and process.returncode:''', '''if False:'''),
    (S, "an engine that ignores close is not reported", '''                    self.kill()
                    problem = EngineLost("native audit CLI did not exit after close")''', '''                    self.kill()'''),
    # ---- the entry point
    (S, "the rollback value starts the engine", '''    if config.native_engine != provider.ENGINE:
        return (original or original_session())''', '''    if False:
        return (original or original_session())'''),
    (S, "the wire setting is ignored", '''    return SESSIONS[settings.wire](path''', '''    return SESSIONS["b0"](path'''),
    (S, "the engine's identity is dropped", '''    return EngineLaunch(command, launched.env, launched.identity, launched.namespaces, config)''', '''    return EngineLaunch(command, launched.env, None, launched.namespaces, config)'''),
    # ---- structural_provider.py
    (P, "the audit's refusal is an engine failure", '''    except refused as exc:''', '''    except KeyError as exc:'''),
    (P, "incomplete coverage is an engine failure", '''    except native_session.EngineIncomplete as exc:''', '''    except KeyError as exc:'''),
    (P, "an incomplete DEX inventory is an engine failure", '''    except provider.InventoryError as exc:''', '''    except KeyError as exc:'''),
    (P, "the FEATURE set is not checked", '''            if set(features) != expected:''', '''            if False:'''),
    (P, "coverage that is not complete is ignored", '''        if coverage[name] != "complete":''', '''        if False:'''),
    (P, "dataset layer issues are ignored", '''    if getattr(session, "layer_issues", None):''', '''    if False:'''),
    (P, "a statement-free session counts as covered", '''    if not coverage["statements"]:''', '''    if False:'''),
    (P, "incomplete coverage still completes", '''        if reasons:
            record["incomplete"]''', '''        if False:
            record["incomplete"]'''),
    (P, "the source is not checked before the run", '''        if digest(apk) != sha256:
            raise SourceMismatch("native audit input does not match''', '''        if False:
            raise SourceMismatch("native audit input does not match'''),
    (P, "the source is not checked after the run", '''        if digest(apk) != sha256:
            raise SourceMismatch("native audit APK changed''', '''        if False:
            raise SourceMismatch("native audit APK changed'''),
    (P, "a deadline is unclassified", '''    if isinstance(error, TimeoutError):''', '''    if False:'''),
    (P, "a source mismatch is unclassified", '''    if isinstance(error, SourceMismatch):''', '''    if False:'''),
    (P, "HostLab's own session is reported as the engine", '''        record["backend"] = "dexsql"
        return''', '''        record["backend"] = provider.ENGINE
        return'''),
    (P, "the engine's wire is not recorded", '''    record["backend"], record["wire"] = provider.ENGINE, wire''', '''    record["backend"], record["wire"] = provider.ENGINE, None'''),
    (P, "a non-complete outcome returns its record", '''        if self.outcome == "complete":
            return self.record''', '''        if True:
            return self.record'''),
    (P, "a result of DexSQL is published in the engine's namespace", '''    if record.get("backend") != provider.ENGINE:''', '''    if False:'''),
    (P, "a published result may replace another", '''    return provider.publish(namespaces["reports"], name, record)''', '''    path = namespaces["reports"] / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record), encoding="utf-8")
    return path'''),
    (P, "the class count is not taken", '''            record["class_count"] = int(session.all("SELECT COUNT(*) AS n FROM classes ORDER BY n")[0]["n"])''', '''            record["class_count"] = 0'''),
    (P, "the queries are not counted", '''    record["queries"] = getattr(session, "queries", record["queries"])''', '''    record["queries"] = 0'''),
    # ---- the guards added by the MDD-051 review: an abandoned statement is never a complete result
    (S, "an abandoned terminal is not counted as uncovered", '''                    self.abandoned.discard(frame["id"])
                    self.coverage.abandoned += 1  # sent but not covered: the result is not complete''', '''                    self.abandoned.discard(frame["id"])'''),
    (S, "pending abandoned statements are not counted", '''        described["abandoned"] += len(self.transport.abandoned)''', '''        pass'''),
    (S, "B0 ignores the terminal's columns", '''                elif final is not None and final != columns:
                    raise EngineProtocolError("native audit CLI column identity mismatch")''', '''                elif False:
                    raise EngineProtocolError("native audit CLI column identity mismatch")'''),
    (P, "an abandoned statement is ignored", '''    if coverage.get("abandoned"):''', '''    if False:'''),
]


def private_copy(destination: Path) -> None:
    for name in COPY:
        shutil.copytree(REPO / name, destination / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "target"))


def run_suites(root: Path, suites=SUITES, timeout=900):
    """(None, None) if every suite passes, else (name of the suite that failed, 'failed' or 'timeout')."""
    env = dict(os.environ)
    for name in suites:
        try:
            done = subprocess.run([sys.executable, "-I", "-m", "unittest", "discover", "-s", "integrations/hostlab", "-p", name],
                                  capture_output=True, text=True, cwd=str(root), timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            return name, "timeout"
        if done.returncode != 0:
            return name, "failed"
    return None, None


class Worker:
    def __init__(self):
        self.local = threading.local()
        self.roots = []

    def root(self) -> Path:
        if not hasattr(self.local, "root"):
            self.local.root = Path(tempfile.mkdtemp(prefix="mdd051-mutation-"))
            private_copy(self.local.root)
            self.roots.append(self.local.root)
        return self.local.root

    def cleanup(self):
        for root in self.roots:
            shutil.rmtree(root, ignore_errors=True)


def apply(root: Path, name: str, old: str, new: str) -> str:
    path = root / "integrations" / "hostlab" / name
    original = path.read_text(encoding="utf-8")
    if original.count(old) != 1:
        raise LookupError(f"{original.count(old)} matches")
    path.write_text(original.replace(old, new), encoding="utf-8", newline="\n")
    return original


def one(worker: Worker, index: int):
    name, label, old, new = MUTANTS[index - 1]
    root = worker.root()
    try:
        original = apply(root, name, old, new)
    except LookupError as error:
        return index, label, "pattern", str(error), 0.0
    started = time.monotonic()
    try:
        suite, how = run_suites(root)
    finally:
        (root / "integrations" / "hostlab" / name).write_text(original, encoding="utf-8", newline="\n")
    elapsed = time.monotonic() - started
    if suite is None:
        return index, label, "survived", "", elapsed
    return index, label, "killed" if how == "failed" else "killed by timeout", suite, elapsed


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--jobs", type=int, default=3)
    parser.add_argument("--only", help="comma separated mutant numbers")
    parser.add_argument("--list", action="store_true", help="only check that every pattern matches exactly once")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    chosen = [int(n) for n in args.only.split(",")] if args.only else list(range(1, len(MUTANTS) + 1))
    broken = []
    for index in chosen:
        name, label, old, new = MUTANTS[index - 1]
        count = (REPO / "integrations" / "hostlab" / name).read_text(encoding="utf-8").count(old)
        if count != 1 or old == new:
            broken.append((index, label, count))
    if broken:
        for index, label, count in broken:
            print(f"{index:2} NOT APPLICABLE ({count} matches): {label}")
        return 1
    if args.list:
        print(f"{len(chosen)} mutants, every pattern matches exactly once")
        return 0
    lines = []
    worker = Worker()
    try:
        clean = worker.root()
        suite, how = run_suites(clean)
        if suite is not None:
            print(f"the unmutated copy fails {suite} ({how}); nothing was mutated")
            return 2
        lines.append("clean copy: all suites pass")
        print(lines[-1], flush=True)
        # the record is current for exactly these files: the mutated modules, the suites and this list
        import hashlib
        for relative in ([f"integrations/hostlab/{name}" for name in (S, P) + SUITES]
                         + ["artifacts/mdd-051/mutation/mutate_structural.py"]):
            lines.append(f"sha256 {hashlib.sha256((REPO / relative).read_bytes()).hexdigest()} {relative}")
        lines.append(f"engine binary sha256 {hashlib.sha256(Path(os.environ['MDD_WORKER_BINARY']).read_bytes()).hexdigest()}"
                     if os.environ.get("MDD_WORKER_BINARY") else "engine binary: found under target/")
        survivors = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for index, label, verdict, detail, elapsed in pool.map(lambda i: one(worker, i), chosen):
                lines.append(f"{index:2} {verdict}{' (' + detail + ')' if detail and verdict != 'pattern' else ''}: {label}")
                print(lines[-1], f"[{elapsed:.0f}s]" if elapsed else "", flush=True)
                if verdict in ("survived", "pattern"):
                    survivors.append((index, label, verdict))
        lines.append(f"mutants: {len(chosen)}, survivors: {survivors}")
        print(lines[-1])
    finally:
        worker.cleanup()
    if args.out:
        args.out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
