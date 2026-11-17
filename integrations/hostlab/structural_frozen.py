"""The frozen HostLab structural-audit modules as an oracle. Test and generator support; the providers do not import it.

HostLab's `native_graph`, `native_rules` and `native_session` are loaded from
conformance/corpus/hostlab/source-8782f43 only after their SHA-256 equals the one recorded in that
directory's manifest (the same rule `hostlab_test_support.load_frozen` applies), and are then executed
twice over: once with the frozen `native_session` (which is `native_cli.CliSession`, driven here against the
reference engine, dexsql 0.1.0) and once with a replacement `native_session` module, so that the very same
Graph and Rules code produces the answers that are compared.

Two things the frozen tree does not contain are supplied from outside:

* `analysis/audit_catalog.json` and `analysis/HostCompatibilityAudit.java`, which `native_rules` reads next to
  itself. They hold the operator's business data and are not part of this repository. A synthetic catalog
  (conformance/hostlab/structural-catalog) is used instead; its `reference_sha256` is the real SHA-256 of the
  synthetic Java stand-in, so `Rules.__init__`'s own integrity check still runs.
* `analysis.run_intake.EXPECTED_FEATURES`: the 27 names are recomputed from the `emit` calls in the frozen rule
  source (`emitted_features`) and recorded in the goldens.
"""
from __future__ import annotations

import ast
import contextlib
import hashlib
import os
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FROZEN = ROOT / "conformance/corpus/hostlab/source-8782f43"
CATALOG_DIR = ROOT / "conformance/hostlab/structural-catalog"
for _directory in (HERE, ROOT / "conformance/hostlab"):  # the adapter's modules, and the fixture writers next to the goldens
    if str(_directory) not in sys.path:
        sys.path.insert(0, str(_directory))

import hostlab_test_support as support  # noqa: E402
import structural_compare as compare  # noqa: E402


@contextlib.contextmanager
def overlay(modules: "dict[str, types.ModuleType]"):
    saved = {key: sys.modules.get(key) for key in modules}
    sys.modules.update(modules)
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value


def frozen_source(name: str) -> bytes:
    """The frozen file's bytes, after the manifest's digest has been checked."""
    path = FROZEN / f"{name}.py"
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != support._frozen_digest(name):
        raise AssertionError(f"{path.name} is not the frozen HostLab source recorded in its manifest")
    return data


def modified_source(name: str, replacements: "tuple[tuple[str, str], ...]") -> bytes:
    """The frozen source with deliberate edits, for the negative controls only: every `old` must be in the source."""
    text = frozen_source(name).decode("utf-8")
    for old, new in replacements:
        if old not in text:
            raise AssertionError(f"{name}.py does not contain the text to be changed: {old!r}")
        text = text.replace(old, new)
    return text.encode("utf-8")


def execute(name: str, *, virtual_file: "Path | None" = None,
            stubs: "dict[str, types.ModuleType] | None" = None, source: "bytes | None" = None) -> types.ModuleType:
    """Run a frozen module in a fresh namespace. `virtual_file` is what the module sees as `__file__`
    (the frozen `native_rules` finds its catalog relative to it). `source` replaces the file's bytes and is for the
    negative controls (modified_source); the digest of the frozen file is checked either way."""
    data = frozen_source(name)
    if source is not None:
        data = source
    module = types.ModuleType(name)
    module.__file__ = str(virtual_file or FROZEN / f"{name}.py")
    # dataclasses look their own module up in sys.modules while a class is being made
    with overlay({**(stubs or {}), name: module}):
        exec(compile(data, module.__file__, "exec"), module.__dict__)
    return module


def graph_and_rules(session_module: types.ModuleType, catalog_dir: "Path | None" = None,
                    modified: "dict[str, tuple[tuple[str, str], ...]] | None" = None):
    """HostLab's Graph and Rules bound to `session_module` (it supplies `literal` and `in_list`). `modified` maps a
    module name to deliberate edits of its source (negative controls only)."""
    catalog = Path(catalog_dir or CATALOG_DIR)
    changes = modified or {}
    graph = execute("native_graph", stubs={"native_session": session_module},
                    source=modified_source("native_graph", changes["native_graph"]) if "native_graph" in changes else None)
    rules = execute("native_rules", virtual_file=catalog / "native_rules.py",
                    stubs={"native_session": session_module, "native_graph": graph},
                    source=modified_source("native_rules", changes["native_rules"]) if "native_rules" in changes else None)
    return graph, rules


class A0Oracle:
    """The frozen modules wired to the reference engine: `session` (native_session), `graph`, `rules` and `audit`
    (native_audit), all bound to one another, plus `expected` (EXPECTED_FEATURES)."""

    def __init__(self, a0_binary: "str | os.PathLike[str]", state: "str | os.PathLike[str]",
                 catalog_dir: "Path | None" = None):
        self.binary = Path(a0_binary).resolve(strict=True)
        self.state = Path(state)
        installer = types.ModuleType("install_dexsql")
        installer.verify = lambda: self.binary  # type: ignore[attr-defined]
        installer.status = lambda: {"backend": "dexsql", "version": "0.1.0", "binary_sha256": sha256_file(self.binary)}  # type: ignore[attr-defined]
        control = types.ModuleType("process_control")

        def terminate_tree(process: subprocess.Popen) -> None:
            if process.poll() is not None:
                return
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, check=False)
            else:
                process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

        control.terminate_tree = terminate_tree  # type: ignore[attr-defined]
        batch = support.frozen_batch(self.state)
        cli = execute("native_cli", stubs={"analysis_batch": batch, "install_dexsql": installer, "process_control": control})
        self.session = execute("native_session", stubs={"native_cli": cli})
        self.graph, self.rules = graph_and_rules(self.session, catalog_dir)
        self.expected = emitted_features()
        hostlab = types.ModuleType("hostlab")
        hostlab.digest = sha256_file  # type: ignore[attr-defined]
        hostlab.STATE = self.state  # type: ignore[attr-defined]
        common = types.ModuleType("audit_common")
        common.resource_fingerprints = lambda apk: {}  # type: ignore[attr-defined]  # only used with surface=True
        surface = types.ModuleType("native_surface")
        intake = types.ModuleType("analysis.run_intake")
        intake.EXPECTED_FEATURES = list(self.expected)  # type: ignore[attr-defined]
        package = types.ModuleType("analysis")
        package.run_intake = intake  # type: ignore[attr-defined]
        self.audit = execute("native_audit", stubs={
            "hostlab": hostlab, "install_dexsql": installer, "audit_common": common, "native_graph": self.graph,
            "native_session": self.session, "native_rules": self.rules, "native_surface": surface,
            "analysis": package, "analysis.run_intake": intake})
        self.write_tsv_stubs = {"analysis": package, "analysis.run_intake": intake}

    def session_factory(self, timeout: int = 300, threads: int = 2):
        return lambda apk: self.session.NativeSession(apk, timeout=timeout, threads=threads)

    def run_audit(self, apk: Path, sha256: str, timeout: int = 300) -> "dict[str, Any]":
        """The frozen `native_audit.run` (it imports EXPECTED_FEATURES when it is called)."""
        with overlay(self.write_tsv_stubs):
            return self.audit.run(apk, sha256=sha256, surface=False, timeout=timeout)

    def write_tsv(self, path: Path, result: dict, apk_name: str) -> None:
        with overlay(self.write_tsv_stubs):
            self.audit.write_tsv(path, result, apk_name)


def a0_session_module(a0_binary: "str | os.PathLike[str]", state: "str | os.PathLike[str]") -> types.ModuleType:
    """The frozen `native_session` driven against the reference engine binary (see A0Oracle)."""
    return A0Oracle(a0_binary, state).session


def frozen_cli(state: "str | os.PathLike[str]") -> types.ModuleType:
    """The frozen `native_cli` with stand-ins for everything it needs to start a process, so that its `CliSession`
    class can be used as a specification of what the consumer sends (no engine is started)."""
    installer = types.ModuleType("install_dexsql")

    def verify():
        raise AssertionError("the frozen CliSession must not start a process in this use")

    installer.verify = verify  # type: ignore[attr-defined]
    control = types.ModuleType("process_control")
    control.terminate_tree = lambda process: None  # type: ignore[attr-defined]
    return execute("native_cli", stubs={"analysis_batch": support.frozen_batch(Path(state)), "install_dexsql": installer,
                                       "process_control": control})


def find_engine_binary() -> Path:
    """`MDD_WORKER_BINARY`, else the newest build under this checkout's target directory. A missing binary is an error."""
    explicit = os.environ.get("MDD_WORKER_BINARY")
    if explicit:
        return Path(explicit)
    name = "meguvizdexdash.exe" if sys.platform == "win32" else "meguvizdexdash"
    found = [ROOT / "target" / profile / name for profile in ("release", "debug") if (ROOT / "target" / profile / name).is_file()]
    if not found:
        raise AssertionError("the meguvizdexdash binary was not found; build it with `cargo build -p mdd-cli` or set "
                             "MDD_WORKER_BINARY (these tests are never skipped)")
    return max(found, key=lambda path: path.stat().st_mtime)


def emitted_features() -> "list[str]":
    """The FEATURE names the frozen rules emit, in source order, read from the syntax tree of the frozen file:
    every `self.emit("<name>", ...)` call. This is the stand-in for HostLab's `EXPECTED_FEATURES`."""
    tree = ast.parse(frozen_source("native_rules").decode("utf-8"))
    names: list[str] = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "emit"
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "self"
                and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            names.append((node.lineno, node.col_offset, node.args[0].value))  # type: ignore[arg-type]
    names.sort()
    # comment_topology is emitted by two branches (MISSING or FOUND): one feature, named once, at its first place
    return list(dict.fromkeys(name for _, _, name in names))  # type: ignore[misc]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: "str | os.PathLike[str]") -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def record_run(session_factory, rules_module, graph_module, apk: Path, *, timeout: int = 300) -> "dict[str, Any]":
    """Run the frozen rules over one input through `session_factory(apk)` (a context manager, like
    `NativeSession`) and record everything the comparison needs, as plain data:

    * the 27 results and the discoveries,
    * the Graph after the run (class records, fields, methods with their signatures and generic types),
    * the statements the consumer sent, in order,
    * a legitimate failure of the audit itself (`UnsupportedAudit`) as a verdict, not as an exception.

    Engine failures are not caught: they propagate."""
    sent: list[str] = []
    with session_factory(apk) as session:
        original_rows = session.rows

        def logging_rows(sql, **bounds):
            sent.append(sql)
            return original_rows(sql, **bounds)

        session.rows = logging_rows  # `all` calls `self.rows`, so every statement is seen once
        rules = rules_module.Rules.__new__(rules_module.Rules)
        record: dict[str, Any] = {"files": dict(session.files), "unsupported_audit": None}
        try:
            rules.__init__(session)
            features, discoveries = rules.run()
        except graph_module.UnsupportedAudit as error:
            record["unsupported_audit"] = str(error)
            features, discoveries = {}, {}
        record["features"] = features
        record["discoveries"] = {name: [list(item) for item in found] for name, found in discoveries.items()}
        record["graph"] = describe_graph(getattr(rules, "g", None))
        # native_audit.run counts the classes only after the rules succeeded; after a refusal the statement stream may
        # be left half read, so nothing more is asked of the session
        record["class_count"] = (None if record["unsupported_audit"] is not None
                                 else int(session.all("SELECT COUNT(*) AS n FROM classes ORDER BY n")[0]["n"]))
        record["statements"] = list(sent)  # what the audit sent; the evidence statements below are asked afterwards
        record["evidence"] = {} if record["unsupported_audit"] is not None else compare.evidence_rows(session)
    return record


def describe_graph(graph) -> "dict[str, Any]":
    """The Graph's classes as plain data: the record of each class (file, index, access, superclass, interfaces),
    its fields and methods with their parsed types (including the generic arguments from Signature annotations)."""
    if graph is None:
        return {}
    classes: dict[str, Any] = {}
    for name in sorted(graph.classes, key=str):
        node = graph.classes[name]
        if node is None:
            classes[name] = None
            continue
        classes[name] = {
            "file": node["file"], "idx": node["idx"], "access": node["access"], "super": node["super"],
            "interfaces": list(node["interfaces"]), "members_loaded": node["members"],
            "fields": [{"name": f.name, "type": str(f.type), "raw": f.type.raw,
                        "generic": [str(g) for g in f.type.generic], "access": f.access} for f in node["fields"]],
            "methods": [{"name": m.name, "proto": m.proto, "args": [str(a) for a in m.args], "result": str(m.result),
                         "result_raw": m.result.raw, "result_generic": [str(g) for g in m.result.generic],
                         "arg_generics": [[str(g) for g in a.generic] for a in m.args], "access": m.access,
                         "file": m.file, "index": m.index} for m in node["methods"]]}
    return classes


def frozen_write_tsv(session_module, graph, rules, path: Path, result: dict, apk_name: str) -> str:
    """HostLab's own `native_audit.write_tsv`, applied to a result record (any engine's): the TSV that HostLab would publish."""
    expected = emitted_features()
    intake = types.ModuleType("analysis.run_intake")
    intake.EXPECTED_FEATURES = list(expected)  # type: ignore[attr-defined]
    package = types.ModuleType("analysis")
    package.run_intake = intake  # type: ignore[attr-defined]
    common = types.ModuleType("audit_common")
    common.resource_fingerprints = lambda apk: {}  # type: ignore[attr-defined]  # only run() with surface=True calls it
    stubs = {"hostlab": types.ModuleType("hostlab"), "install_dexsql": types.ModuleType("install_dexsql"),
             "audit_common": common, "native_surface": types.ModuleType("native_surface"),
             "native_graph": graph, "native_session": session_module, "native_rules": rules,
             "analysis": package, "analysis.run_intake": intake}
    audit = execute("native_audit", stubs=stubs)
    with overlay({"analysis": package, "analysis.run_intake": intake}):
        audit.write_tsv(path, result, apk_name)
    return Path(path).read_text(encoding="utf-8")


class Live:
    """The real engine, pinned, with the synthetic inputs built next to it: what the live tests and the evidence
    generator run the sessions against. A missing binary is an error."""

    def __init__(self, workdir: "str | os.PathLike[str]", binary: "Path | None" = None):
        import install_meguvizdexdash as installer
        import native_session
        import provider
        import structural_worlds as worlds
        self.ns, self.provider, self.installer, self.worlds = native_session, provider, installer, worlds
        self.work = Path(workdir)
        self.binary = Path(binary) if binary else find_engine_binary()
        self.manifest = self.work / "engine-manifest.json"
        installer.pin(self.binary, self.manifest)
        self.inputs = self.work / "inputs"
        self.digests = worlds.write_inputs(self.inputs)
        self.state = self.work / "state"
        self.graph, self.rules = graph_and_rules(native_session)

    def path(self, world: str) -> Path:
        members, container = self.worlds.world(world)
        return self.inputs / (world + (".dex" if container == "dex" else ".apk"))

    def provider_config(self, native_engine: str = "meguvizdexdash") -> dict:
        return {"schema": self.provider.CONFIG_SCHEMA, "native_engine": native_engine,
                "meguvizdexdash": {"manifest": str(self.manifest), "profile_policy": "allow_unadmitted"}}

    def structural(self, wire: str, **extra) -> dict:
        return {"schema": self.ns.STRUCTURAL_SCHEMA, "wire": wire, **extra}

    def environ(self):
        """The pinned binary is found through HOSTLAB_MEGUVIZDEXDASH, which provider.launch reads from the process."""
        from unittest import mock
        return mock.patch.dict(os.environ, {self.installer.ENV_BINARY: str(self.binary)})

    def factory(self, wire: str, **structural):
        def make(apk):
            return self.ns.NativeSession(apk, timeout=300, threads=2, provider_config=self.provider_config(),
                                         structural=self.structural(wire, **structural), state=self.state)
        return make

    def record(self, apk: Path, wire: str, rules=None, graph=None, **structural) -> dict:
        with self.environ():
            return compare.project(record_run(self.factory(wire, **structural), rules or self.rules, graph or self.graph, apk))

    def outcome(self, apk: Path, wire: str, *, sha256: "str | None" = None, rules=None, **structural):
        import structural_provider
        with self.environ():
            return structural_provider.run_structural(
                apk, sha256=sha256 or sha256_file(apk), rules_module=rules or self.rules, expected_features=emitted_features(),
                provider_config=self.provider_config(), structural=self.structural(wire, **structural), state=self.state)
