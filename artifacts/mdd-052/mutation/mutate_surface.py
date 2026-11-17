"""Mutation check for MDD-052: change one behaviour of the surface provider or the gate harness at a time and require the
tests to notice.

    python -I artifacts/mdd-052/mutation/mutate_surface.py [name substring ...]

Each mutant replaces one exact piece of integrations/hostlab/surface_provider.py or surface_gate.py, runs the offline surface tests
(test_surface_provider/switch/gate/goldens: relational stand-in, fake engine process, frozen HostLab sources as the oracle), and
restores the file in a `finally` (and verifies the restore). A mutant that survives the offline tests is run against the live suite
(test_surface_live.py, the real engine: MDD_WORKER_BINARY or target/{release,debug}); it is killed only if that fails. A suite that
hangs past LIMIT seconds is killed whole (its process tree, so no fake or real engine is left behind) and counts as KILLED
(timeout/hang): a hang is a detection, not a pass. A mutant that leaves every suite green is a survivor and exits 1, and so is a
pattern that no longer matches exactly once, so the list cannot rot silently. Run it on a clean checkout: it edits the two modules
in place. With names, only the mutants whose label contains one. The full run is written to results.txt next to this script, ending
with a `sources sha256:` line that binds the result to the restored checkout; results-run1.txt is the interrupted historical part-run."""
import atexit
import hashlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
HOSTLAB = REPO / "integrations" / "hostlab"
BACKUP = Path(tempfile.mkdtemp(prefix="mdd052-mutation-"))
RESULTS = Path(__file__).resolve().parent / "results.txt"
OFFLINE = "test_surface_[pgs]*.py"  # provider, goldens, gate, switch
LIVE = "test_surface_live.py"
LIMIT = 1200  # seconds per suite; a suite that hangs past this is killed whole and counts as a detection

P = "surface_provider.py"
G = "surface_gate.py"

# What the result binds: the two mutated modules, their support and fake engine, the offline and live suites, the golden,
# the fixture expectations and generator, and the five synthetic APKs. Hashed on the restored (clean) tree.
SOURCES = [
    "integrations/hostlab/surface_provider.py", "integrations/hostlab/surface_gate.py",
    "integrations/hostlab/surface_support.py", "integrations/hostlab/surface_fake_serve.py",
    "integrations/hostlab/test_surface_provider.py", "integrations/hostlab/test_surface_goldens.py",
    "integrations/hostlab/test_surface_gate.py", "integrations/hostlab/test_surface_switch.py",
    "integrations/hostlab/test_surface_live.py", "conformance/hostlab/surface-goldens.json",
    "tests/fixtures/surface/expected.json", "tests/fixtures/surface/generate.py",
]
FIXTURES = ["tests/fixtures/surface/generated/" + n for n in
            ("base.apk", "target.apk", "plain.apk", "fields-only.apk", "duplicate-resource.apk")]

MUTANTS = [
    # -- the filter
    (P, "a family prefix is missing", '"Lkntr/common/comment", "Lkntr/app/following/"})', '"Lkntr/common/comment"})'),
    (P, "the feed leg is gone", 'for word in ("dynamic", "following", "feed")]', 'for word in ("dynamic", "following")]'),
    (P, "the legs lose their bplus condition", 'legs = ["(" + prefix(column, "Lcom/bilibili/bplus/") + " AND lower("', 'legs = ["(" + "1=1" + " AND lower("'),
    (P, "the legs are ORed with their word", '" AND lower(" + column + ") LIKE \'%" + word', '" OR lower(" + column + ") LIKE \'%" + word'),
    (P, "the filter is a chain of ORs", "return balanced_or([prefix(column, p) for p in sorted(prefixes)] + legs)",
     'return "(" + " OR ".join([prefix(column, p) for p in sorted(prefixes)] + legs) + ")"'),
    (P, "the tree is lopsided", "middle = len(terms) // 2", "middle = 1"),
    (P, "the tree drops a term", 'balanced_or(terms[middle:]) + ")"', 'balanced_or(terms[middle + 1:] or terms[middle:]) + ")"'),
    (P, "a percent sign is not escaped", r'.replace("%", "\\%")', ""),
    (P, "an underscore is not escaped", r'.replace("_", "\\_")', ""),
    (P, "the ESCAPE clause is missing", r'''+ " ESCAPE '\\'"''', ""),
    (P, "control characters in a literal are accepted", r'if any(c in value for c in "\r\n\0"):', "if False:"),
    (P, "quotes in a literal are not doubled", '''"'" + value.replace("'", "''") + "'"''', '''"'" + value + "'"'''),
    (P, "the protocol pattern lost its semicolon", "LIKE 'Lcom/bapis/%Moss;')\"", "LIKE 'Lcom/bapis/%Moss')\""),
    # -- parsers
    (P, "a member is cut at the last arrow", 'owner, tail = value.split("->", 1)', 'owner, tail = value.rsplit("->", 1)'),
    (P, "a method without parenthesis is not refused", 'if "(" not in tail:', "if False:"),
    (P, "a field type is cut at the last colon", 'return descriptor.split(":", 1)[1]', 'return descriptor.rsplit(":", 1)[1]'),
    (P, "negative numbers are accepted", "if type(value) is int and value >= 0:", "if type(value) is int:"),
    (P, "booleans are numbers", "if type(value) is int and value >= 0:", "if isinstance(value, int) and value >= 0:"),
    (P, "non-ASCII digits are numbers", "value.isascii() and value.isdigit()", "value.isdigit()"),
    (P, "anything is text", "    if not isinstance(value, str):\n        raise SurfaceError(f\"{what} is not text", "    if False:\n        raise SurfaceError(f\"{what} is not text"),
    (P, "a name without a number has no order", 'int(re.sub(r"\\D", "", name) or 1)', 'int(re.sub(r"\\D", "", name) or 0)'),
    (P, "overloads are not spaced", '"(" + " ".join(tokens) + ")" + result', '"(" + "".join(tokens) + ")" + result'),
    (P, "an unparsable prototype is accepted", 'if "".join(tokens) != parameters:', "if False:"),
    # -- the DEX files and their bytes
    (P, "a file_id may name two DEX files", "if identity.file_id in found:", "if False:"),
    (P, "two DEX files may share a name", "if len({i.entry_name for i in found.values()}) != len(found):", "if False:"),
    (P, "the length is not compared", "if len(raw) != identity.byte_len:", "if False:"),
    (P, "the version is not compared", 'if raw[4:7].decode("ascii") != identity.version:', "if False:"),
    (P, "the checksum is not compared", 'if int.from_bytes(raw[8:12], "little") != identity.checksum:', "if False:"),
    (P, "the signature is not compared", "if raw[12:32].hex() != identity.signature_hex:", "if False:"),
    (P, "the DEX version gate is gone", r'if raw[:4] != b"dex\n" or raw[4:7] not in DEX_VERSIONS:', "if False:"),
    (P, "the DEX magic is not checked", r'if raw[:4] != b"dex\n" or raw[4:7] not in DEX_VERSIONS:', "if raw[4:7] not in DEX_VERSIONS:"),
    (P, "bytes are not bound to the facts", "bind_dex(raw_of[file], identity, unsupported)", "pass"),
    (P, "an archive with two members of one name is read", "if members.count(identity.entry_name) != 1:", "if False:"),
    (P, "the size limit of a DEX is gone", "if info.file_size > MAX_DEX_BYTES:", "if False:"),
    # -- rows and local ids
    (P, "a row of another file passes", 'if as_int(row["file_id"], "file_id") != file:', "if False:"),
    (P, "the code ranges are not bounded", '" AND method_idx BETWEEN " + str(lower) + " AND " + str(upper)', '" AND method_idx >= 0"'),
    (P, "rows outside the range are accepted", "if not lower <= index <= upper:", "if False:"),
    (P, "rows of other methods are kept", "            if index in values:", "            if True:"),
    (P, "two code rows are accepted", "if (file, index) in result:", "if False:"),
    (P, "instruction size is taken as bytes", 'as_int(row["insns_size"], "code_items.insns_size") * 2)', 'as_int(row["insns_size"], "code_items.insns_size") * 1)'),
    (P, "a logical DEX name is accepted", 'if any("#" in n for n in names):', "if False:"),
    (P, "an ambiguous DEX number is accepted", "if len(numeric) != len(set(numeric)):", "if False:"),
    (P, "files are ordered as text", "names = sorted((i.entry_name for i in identities.values()), key=numeric_key)", "names = sorted(i.entry_name for i in identities.values())"),
    (P, "a class defined twice is accepted", "if (file, owner) in records:", "if False:"),
    (P, "a method defined twice is accepted", "if (file, owner, name, proto) in handles:", "if False:"),
    (P, "one method_idx may name two methods", "if index in methods.get(file, {}):", "if False:"),
    (P, "the engine's file_id is reported", '"file_id": ordinal[file], "family": group', '"file_id": file, "family": group'),
    (P, "edges carry the engine's file_id", "edges.add((ordinal[file], source,", "edges.add((file, source,"),
    (P, "the last DEX file is dropped", "for file in range(len(names))]", "for file in range(len(names) - 1)]"),
    # -- the digest of a class
    (P, "fields are not sorted", 'record["fields"].sort()', "pass"),
    (P, "methods are not sorted", 'record["methods"].sort()', "pass"),
    (P, "overloads are visited in plain order", "key=lambda m: (m[0], legacy_body_order(m[1], unsupported))", "key=lambda m: (m[0], m[1])"),
    (P, "name and prototype are not hashed", "digest.update((name + proto).encode())", "pass"),
    (P, "bodies are not hashed", "digest.update(raw[offset:offset + size])", "pass"),
    (P, "the code interval is not checked", "if offset < 0 or offset + size > len(raw) or offset % 2:", "if False:"),
    (P, "odd offsets are accepted", "if offset < 0 or offset + size > len(raw) or offset % 2:", "if offset < 0 or offset + size > len(raw):"),
    (P, "an interval may end past the DEX", "if offset < 0 or offset + size > len(raw) or offset % 2:", "if offset < 0 or offset > len(raw) or offset % 2:"),
    (P, "every method is a Composer method", "if COMPOSER in proto]", "if True]"),
    # -- calls and protocol definitions
    (P, "every caller is external", 'source = workers.family(caller) or "external_or_unknown"', 'source = "external_or_unknown"'),
    (P, "unregistered protocols are not recognised", 'callee.startswith("Lcom/bapis/") and callee.endswith("Moss;")', 'callee.startswith("Lcom/bapis/") and callee.endswith("Moss")'),
    (P, "the call count is one", '+ as_int(row["n"], "method_calls.n")', "+ 1"),
    (P, "an edge loses its target prototype", "callee, target_name, target_proto))", 'callee, target_name, ""))'),
    (P, "any Moss owner is a definition", 'if owner not in registered and not (owner.startswith("Lcom/bapis/") and owner.endswith("Moss;")):', "if owner not in registered:"),
    (P, "an unregistered definition has no owner", '"unregistered_protocol:" + owner)', '"unregistered_protocol:")'),
    # -- resources
    (P, "any xml is a resource", '(name.startswith("res/") and name.endswith(".xml"))', 'name.endswith(".xml")'),
    (P, "any file named like resources.arsc is a resource", 'name == "resources.arsc"', 'name.startswith("resources.arsc")'),
    (P, "the size of a resource is not counted", "size += len(chunk)", "size += 1"),
    (P, "duplicate names are not reported", 'evidence["resource_duplicates"] = sorted({s["name"] for s in seen if sum(t["name"] == s["name"] for t in seen) > 1})',
     'evidence["resource_duplicates"] = []'),
    # -- identity of a report and its shapes
    (P, "timing is part of the report's identity", 'VOLATILE = ("scan_execution", "sample")', 'VOLATILE = ("sample",)'),
    (P, "the identity depends on key order", "json.dumps(value, sort_keys=True, ensure_ascii=True", "json.dumps(value, sort_keys=False, ensure_ascii=True"),
    (P, "a list longer than the other is the same", 'return f"{path}[{min(len(a), len(b))}]" if len(a) != len(b) else None', "return None"),
    (P, "a missing key is not a difference", "if key not in a or key not in b:", "if False:"),
    (P, "a type change is not a difference", "return None if type(a) is type(b) and a == b else (path or \"<root>\")", "return None if a == b else (path or \"<root>\")"),
    (P, "protocol signatures stay lists", '    for path in report.get("protocol_paths", {}).values():\n        signatures(path)', '    for path in report.get("protocol_paths", {}).values():\n        pass'),
    (P, "twin signatures stay lists", '        signatures(twin["java_path"])\n        signatures(twin["kotlin_path"])', "        pass"),
    (P, "page matrix signatures stay lists", '        for path in page.get("protocols", {}).values():\n            signatures(path)', '        for path in page.get("protocols", {}).values():\n            pass'),
    (P, "edges stay lists", "report[key] = [tuple(item) for item in report[key]]", "report[key] = list(report[key])"),
    (P, "class record fields stay lists", 'record["fields"] = [tuple(f) for f in record["fields"]]', 'record["fields"] = list(record["fields"])'),
    # -- the engine's stream
    (P, "i64 cells are refused", 'kind in ("u64", "i64")', 'kind in ("u64",)'),
    (P, "a null cell is an empty text", "    if kind == \"null\":\n        return None", "    if kind == \"null\":\n        return \"\""),
    (P, "an error status is not an error", 'if terminal.get("operation_status") != "ok":', "if False:"),
    (P, "partial input coverage is complete", 'if coverage.get("input") != "complete":', "if False:"),
    (P, "partial fact coverage is complete", 'if coverage.get("facts") != "complete":', "if False:"),
    (P, "an incomplete execution is complete", 'if execution.get("complete") is not True:', "if False:"),
    (P, "more available rows are not truncation", 'if response.get("truncated") is not False or response.get("more_available") is not False:',
     'if response.get("truncated") is not False:'),
    (P, "a truncated result is complete", 'if response.get("truncated") is not False or response.get("more_available") is not False:',
     'if response.get("more_available") is not False:'),
    (P, "the emitted rows are not counted", 'if str(response.get("emitted_rows")) != str(emitted):', "if False:"),
    (P, "the row budget is not enforced", "if emitted > max_rows:", "if False:"),
    (P, "another snapshot's answer is accepted", 'if terminal.get("snapshot_id") != self.opened.get("snapshot_id"):', "if False:"),
    (P, "a rejected request is not an error", 'if kind == "rejected":', 'if kind == "never-rejected":'),
    (P, "an answer for another request is accepted", 'if line.get("id") != ident:', "if False:"),
    (P, "the columns may change between batches", 'elif columns != batch["columns"]:', "elif False:"),
    (P, "a row of the wrong width is accepted", "if len(raw) != len(columns):", "if False:"),
    (P, "duplicate column names are accepted", "if len(columns) != len(set(columns)):", "if False:"),
    (P, "the byte budget is not enforced", "if used > max_bytes:", "if False:"),
    (P, "an unknown line kind is a terminal", 'if kind != "terminal":', "if False:"),
    (P, "a statement without an order is sent", 'if "ORDER BY" not in sql.upper():', "if False:"),
    (P, "the budgets are not sent", '"batch_rows": self.batch_rows, "max_rows": max_rows}', '"batch_rows": self.batch_rows}'),
    (P, "any opening line is accepted", 'if opened.get("kind") != "opened" or opened.get("protocol") != ENGINE_PROTOCOL:', "if False:"),
    (P, "layers that could not be built are accepted", 'if self.opened.get("layer_issues"):', "if False:"),
    (P, "another dialect is accepted", 'if self.dialect is not None and self.opened.get("sql_dialect") != self.dialect:', "if False:"),
    (P, "a line that is not an object is accepted", "if not isinstance(value, dict):", "if False:"),
    (P, "an engine that exits with an error after close is fine", "if clean and process.returncode:", "if False:"),
    (P, "a failed session leaves the engine running", "                if process.poll() is None:\n                    process.kill()\n                process.wait()", "                process.wait()"),
    (P, "the deadline is passed in seconds", 'str(int(deadline_seconds * 1000))', "str(int(deadline_seconds))"),
    (P, "an over-long line is read", "if isinstance(line, bytes) and len(line) > LINE_BUDGET:", "if False:"),
    # -- the run, the switch and the store
    (P, "the source is not checked before", "    if base.file_sha256(apk) != sha256:\n        raise RuntimeError(\"native audit input", "    if False:\n        raise RuntimeError(\"native audit input"),
    (P, "the source is not checked after", "    if base.file_sha256(apk) != sha256:\n        raise RuntimeError(\"native audit APK", "    if False:\n        raise RuntimeError(\"native audit APK"),
    (P, "the physical DEX inventory is not compared", "base.verify_inventory(inventory, session.files)", "pass"),
    (P, "a stored result is not reused", "        if cached is not None:\n            return cached", "        if False:\n            return cached"),
    (P, "the original path may run without HostLab's scan", "if legacy_session is None or host.legacy_scan is None:", "if False:"),
    (P, "the original path is labelled as the engine", '"backend": "dexsql", "workers": 2', '"backend": "meguvizdexdash", "workers": 2'),
    (P, "the original path stores its result", "        saved = False", "        saved = use_store"),
    (P, "the store is used when evidence is asked for", "if use_store and not evidence else None", "if use_store else None"),
    (P, "a conflicting stored result is ignored", 'if existing is None or existing["report_sha256"] != result["report_sha256"]:', "if False:"),
    (P, "the store ignores the rule hash", '"source_sha256": sha256, "rule_sha256": self.rule_sha256,', '"source_sha256": sha256,'),
    (P, "the store ignores the engine build", '"build_id": self.engine["build_id"], "binary_sha256"', '"binary_sha256"'),
    (P, "the store ignores the engine binary", '"binary_sha256": self.engine["binary_sha256"],\n', "\n"),
    (P, "the store ignores the dialect", '"dialect": self.engine["dialect"]["engine"]})', "})"),
    (P, "a stored entry of another schema is read", 'entry.get("schema") != SCHEMA or entry.get("provider") != ENGINE', "False"),
    (P, "a stored entry of another source is read", '(entry.get("source") or {}).get("sha256") != sha256', "False"),
    (P, "a stored entry of other rules is read", 'if entry.get("rule_sha256") != self.rule_sha256 or (entry.get("report") or {}).get("rule_sha256") != self.rule_sha256:', "if False:"),
    (P, "a stored entry of another build is read", '"binary_sha256"), (identity.get("dialect") or {}).get("engine")) != (', '"binary_sha256"), (identity.get("dialect") or {}).get("engine")) == ('),
    (P, "a stored report that does not match its digest is read", 'if report_digest(entry["report"]) != entry.get("report_sha256"):', "if False:"),
    (P, "a directory of another schema is taken over", 'if json.loads(path.read_text(encoding="utf-8")) != marker:', "if False:"),
    (P, "a stored report keeps its lists", "        restore_shapes(entry[\"report\"])\n", "        pass\n"),
    (P, "an entry is saved without being checked", "        self.check(entry, entry[\"source\"][\"sha256\"])\n", ""),
    (P, "the surface switch accepts other providers", "if not isinstance(chosen, str) or chosen not in PROVIDERS:", "if not isinstance(chosen, str):"),
    (P, "the surface switch accepts other keys", 'extra = set(obj) - {"schema", "surface_provider"}', "extra = set()"),
    (P, "the surface switch defaults to the engine", "surface_provider: str = LEGACY", "surface_provider: str = ENGINE"),
    (P, "the surface switch has no schema", 'if obj.get("schema") != CONFIG_SCHEMA:', "if False:"),
    (P, "the comparison has no resource changes", "resources = host.resource_changes(baseline, target)", "resources = {}"),
    # -- the gates
    (G, "the time is not taken", "seconds = clock() - started", "seconds = 0.0"),
    (G, "the time stops early", "seconds = clock() - started", "seconds = clock() - started - 1.0"),
    (G, "a time-out has an exit status", "timed_out, exit_code, out, err = True, None,", "timed_out, exit_code, out, err = True, 0,"),
    (G, "a time-out is finished", "return not self.timed_out and self.exit_code is not None", "return self.exit_code is not None"),
    (G, "only exit 0 is accepted", "self.exit_code in ACCEPTED_EXIT.get(self.name, (0,))", "self.exit_code == 0"),
    (G, "the home gate may exit 1", '"home": (0,)}', '"home": (0, 1)}'),
    (G, "a gate that is not the pinned one runs", "if expected_script_sha256 is not None and before != expected_script_sha256:", "if False:"),
    (G, "a gate may change while it runs", "if after != before:", "if False:"),
    (G, "a negative saving is tolerated", "if gate_reuse_benefit_seconds != 0:", "if gate_reuse_benefit_seconds > 0:"),
    (G, "a negative duration is tolerated", "if surface_seconds < 0 or any(g.seconds < 0 for g in gates):", "if False:"),
    (G, "the gates are not in the total", '"total_seconds": surface_seconds + gate_seconds', '"total_seconds": surface_seconds'),
    (G, "only the slowest gate counts", "gate_seconds = sum(g.seconds for g in gates)", "gate_seconds = max((g.seconds for g in gates), default=0.0)"),
    (G, "every gate finished", '"all_gates_finished": all(g.finished for g in gates)', '"all_gates_finished": True'),
    (G, "a benefit is counted", '"benefit_seconds_counted": 0.0', '"benefit_seconds_counted": 22.0'),
    (G, "the log of stdout is stderr", "(Path(log_dir) / f\"{name}.stdout.log\").write_bytes(out)", "(Path(log_dir) / f\"{name}.stdout.log\").write_bytes(err)"),
    (G, "the gate gets an environment of its own", "env=env, capture_output=True", "env=dict(env or {}), capture_output=True"),
    (G, "the gate ignores its directory", "cwd=None if cwd is None else str(cwd), ", "cwd=None, "),
    (G, "the evidence may name a gate twice", "if len(values) != 1}", "if len(values) < 1}"),
    # -- MDD-052 review: code-row file_id, the SQL depth/term caps, the paging contract, the bounded request write
    (P, "code rows are not checked against their file", 'if as_int(row["file_id"], "code_items.file_id") != file:', "if False:"),
    (P, "code_items are read without their file_id", "SELECT file_id,method_idx,insns_off,insns_size FROM code_items",
     "SELECT method_idx,insns_off,insns_size FROM code_items"),
    (P, "the OR term cap is gone", "if len(terms) > MAX_OR_TERMS:", "if False:"),
    (P, "the OR term cap is raised", "MAX_OR_TERMS = 64", "MAX_OR_TERMS = 512"),
    (P, "an empty OR tree is accepted", "if not terms:", "if False:"),
    (P, "the SQL depth cap is gone", "if depth > MAX_SQL_DEPTH:", "if False:"),
    (P, "the SQL depth cap is raised", "MAX_SQL_DEPTH = 9", "MAX_SQL_DEPTH = 12"),
    (P, "the depth measure keeps the last level", "deepest = max(deepest, depth)", "deepest = depth"),
    (P, "a page_size override is silently ignored", "if page_size != 0:", "if False:"),
    (P, "the request write has no deadline", "writer.join(timeout=remaining)", "writer.join()"),
]


def hash_files(relatives) -> bytes:
    digest = hashlib.sha256()
    for relative in relatives:
        digest.update(relative.encode())
        digest.update((REPO / relative).read_bytes())
    return digest.digest()


def sources_sha256() -> str:
    digest = hashlib.sha256()
    digest.update(hash_files(SOURCES))
    digest.update(hash_files(FIXTURES))
    return digest.hexdigest()


LAST_OUTPUT = ""


def kill_tree(process: subprocess.Popen) -> None:
    """End the suite and everything it started: a hung test leaves its fake engine (or the real one) behind."""
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True, check=False)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def run_tests(pattern: str) -> str:
    """'pass', 'fail' or 'timeout'. A suite that hangs past LIMIT is killed whole (process tree) and reported as 'timeout';
    a hang is a detection, not a pass. The output of the last suite is kept in LAST_OUTPUT for diagnostics."""
    global LAST_OUTPUT
    command = [sys.executable, "-I", "-W", "error", "-m", "unittest", "discover", "-s", str(HOSTLAB), "-p", pattern, "-f"]
    process = subprocess.Popen(command, cwd=str(REPO), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=(os.name != "nt"))
    try:
        output, _ = process.communicate(timeout=LIMIT)
    except subprocess.TimeoutExpired:
        kill_tree(process)
        try:
            output, _ = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            output = b""
        LAST_OUTPUT = output.decode("utf-8", "replace")
        return "timeout"
    LAST_OUTPUT = output.decode("utf-8", "replace")
    return "pass" if process.returncode == 0 else "fail"


def find_binary() -> "Path | None":
    explicit = os.environ.get("MDD_WORKER_BINARY")
    if explicit:
        return Path(explicit)
    name = "meguvizdexdash.exe" if sys.platform == "win32" else "meguvizdexdash"
    found = [REPO / "target" / p / name for p in ("release", "debug") if (REPO / "target" / p / name).is_file()]
    return max(found, key=lambda path: path.stat().st_mtime) if found else None


def main(names: list[str]) -> int:
    originals = {}
    for name in (P, G):
        originals[name] = (HOSTLAB / name).read_bytes()
        shutil.copyfile(HOSTLAB / name, BACKUP / name)

    def restore() -> None:
        for name, data in originals.items():
            (HOSTLAB / name).write_bytes(data)

    atexit.register(restore)
    binary = find_binary()
    selected = [m for m in MUTANTS if not names or any(n in m[1] for n in names)]
    # the unmutated tree must pass first, or every mutant would count as killed
    clean = run_tests(OFFLINE)
    if clean != "pass":
        print(f"the offline tests do not pass on the unmutated tree ({clean})")
        print(LAST_OUTPUT[-2000:], file=sys.stderr)
        return 2
    live_run = binary is not None
    if live_run:
        env_binary = os.environ.get("MDD_WORKER_BINARY")
        os.environ["MDD_WORKER_BINARY"] = str(binary)
        live_clean = run_tests(LIVE)
        if env_binary is None:
            del os.environ["MDD_WORKER_BINARY"]
        if live_clean != "pass":
            print(f"the live tests do not pass on the unmutated tree ({live_clean})")
            print(LAST_OUTPUT[-2000:], file=sys.stderr)
            return 2
    survivors = []
    killed = timeouts = 0
    with open(RESULTS, "w", encoding="utf-8", newline="\n") as out:
        def emit(line: str) -> None:
            print(line, flush=True)
            out.write(line + "\n")
            out.flush()

        emit("# MDD-052 surface mutation check (full run; results-run1.txt is the interrupted historical part-run)")
        emit("# semantics: KILLED = the offline suite fails, or (for an offline survivor) the live suite fails; a suite that")
        emit(f"#   hangs past {LIMIT} s is killed whole (process tree) and counts as KILLED (timeout/hang) - a hang is a detection.")
        emit(f"# interpreter: {sys.executable}")
        emit(f"# offline pattern: {OFFLINE} ; live: {LIVE if live_run else 'not run (no engine binary)'}")
        emit(f"# mutants: {len(selected)}")
        for index, (name, label, old, new) in enumerate(selected, 1):
            path = HOSTLAB / name
            text = originals[name].decode("utf-8")
            if text.count(old) != 1:
                emit(f"{index:3} NOT APPLICABLE ({text.count(old)} matches): {label}")
                survivors.append((index, label, "pattern"))
                continue
            path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")
            verdict = None
            try:
                offline = run_tests(OFFLINE)
                if offline == "fail":
                    verdict = "killed"
                elif offline == "timeout":
                    verdict = f"killed (timeout/hang, offline suite stopped at {LIMIT} s)"
                    timeouts += 1
                elif live_run:
                    os.environ["MDD_WORKER_BINARY"] = str(binary)
                    live = run_tests(LIVE)
                    if live == "fail":
                        verdict = "killed (by the live tests only)"
                    elif live == "timeout":
                        verdict = f"killed (timeout/hang, live suite stopped at {LIMIT} s)"
                        timeouts += 1
            finally:
                restore()
                if path.read_bytes() != originals[name]:
                    emit(f"{index:3} RESTORE FAILED: {label}")
                    raise SystemExit(2)
            if verdict is None:
                emit(f"{index:3} SURVIVED: {label}")
                survivors.append((index, label, "survived"))
            else:
                killed += 1
                emit(f"{index:3} {verdict}: {label}")
        emit("live suite: " + ("run" if live_run else "not run (no engine binary)"))
        emit("survivors: " + repr(survivors))
        emit(f"totals: {len(selected)} mutants, {killed} killed ({timeouts} by timeout/hang), {len(survivors)} survived")
        emit("sources sha256: " + sources_sha256())
    shutil.rmtree(BACKUP, ignore_errors=True)
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
