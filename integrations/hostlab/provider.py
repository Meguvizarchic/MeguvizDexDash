"""HostLab provider selection for the MeguvizDexDash engine. Integration layer; standard library only.

HostLab has two backends, `sqlite` (legacy dexq) and `dexsql` (the pinned closed-source
binary). This module adds a third, `meguvizdexdash`, beside them and changes nothing about the
first two:

* A request that names `sqlite` or `dexsql` is planned by HostLab's own planner and goes where
  it always went. No setting moves it to the new engine.
* A request that names `meguvizdexdash` is served by it or refused. It is never served by
  another backend.
* A request that says `auto` goes where `native_engine` points. `dexsql` (the default) is the
  rollback value and gives the legacy plan unchanged; `meguvizdexdash` sends the work that
  HostLab would have given DexSQL to the new engine.

The engine implementation (`meguvizdexdash`, its build and digest), the profile (`mdd-native-v1`
and whether it is admitted), the SQL dialect (`dexsql-0.1.0`) and the configuration are four
separate facts, and a report names each of them. What the engine cannot do is visible in the
plan, not discovered mid run. When it cannot serve a task that `auto` gave it, the only
permitted way out is an explicit, recorded fallback to `dexsql` for the three codes that say
"not here" (`UNAVAILABLE_BACKEND`, `UNSUPPORTED_CAPABILITY`, `UNSUPPORTED_QUERY`) and only if
the operator turned it on and the request did not forbid it. Every other failure stays a
failure and keeps its evidence.

`plan` does no I/O. HostLab's planner (analysis_plan) is injected, so the legacy rules are used
as they are, not copied.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, NamedTuple, Sequence

import install_meguvizdexdash as installer

CONFIG_SCHEMA = "mdd.hostlab-provider-config.v1"
PLAN_SCHEMA = "mdd.hostlab-provider-plan.v1"
RUN_SCHEMA = "mdd.hostlab-run-identity.v1"
ENGINE = "meguvizdexdash"
LEGACY_BACKENDS = ("sqlite", "dexsql")
REQUEST_BACKENDS = ("auto", "sqlite", "dexsql", ENGINE)
NATIVE_ENGINES = ("dexsql", ENGINE)
# The only errors that may end in a fallback: the engine (or its installation) says "not here".
FALLBACK_ELIGIBLE = ("UNAVAILABLE_BACKEND", "UNSUPPORTED_CAPABILITY", "UNSUPPORTED_QUERY")
# Every code of mdd_types::ErrorCode (checked against crates/mdd-types/src/lib.rs by the tests).
ENGINE_CODES = (
    "UNAVAILABLE_BACKEND", "UNSUPPORTED_CAPABILITY", "UNSUPPORTED_QUERY", "INVALID_ARGUMENT", "INVALID_INPUT",
    "PARTIAL_INPUT", "INCOMPLETE_FACTS", "SOURCE_CHANGED", "AMBIGUOUS_ENTITY", "STALE_CACHE", "CACHE_CORRUPT",
    "QUOTA_EXCEEDED", "DEADLINE_EXCEEDED", "CANCELLED", "SNAPSHOT_CLOSED", "INVALID_CURSOR", "INTERNAL_FAULT",
    "WORKER_LOST")
DIALECTS = ("dexsql-0.1.0", "dexsql-0.1.1")
PROFILE_POLICIES = ("require_admitted", "allow_unadmitted")
FALLBACK_TARGETS = ("none", "dexsql")
NEGOTIATION_FALLBACK = ("configured", "forbid")
HOSTLAB_RELATIONS = installer.HOSTLAB_RELATIONS
# The MCP tools a task needs from the engine. HostLab's session always opens and closes a
# dataset and reads dex_files through `query`.
TOOLS_BY_OPERATION = {
    "query": ("close_dataset", "open_dataset", "query"),
    "locate": ("close_dataset", "open_dataset", "query"),
    "refs": ("close_dataset", "open_dataset", "query"),
    "decode": ("close_dataset", "decode", "open_dataset", "query"),
    "info": ("close_dataset", "get_manifest", "open_dataset", "query"),
}
# HostLab's own state directories (docs/03_HOSTLAB_MIGRATION.md 8.3, remote_mcp.py, analysis_batch.py):
# the adapter never writes below any of them.
LEGACY_NAMES = ("dexq-cache", "reports", "remote-output", "remote-results", "analysis-schedule", "remote-requests",
                "remote-job-map", "version-matrices", "artifact-cache", "source-snapshots", "samples")
MDD_ROOT = "mdd-engine"
_SECRET = re.compile(r"TOKEN|SECRET|PASSWORD|API_KEY", re.I)
_LEGACY_ENV = ("DEXQ_CACHE_DIR", "DEXQ_ROOTS", "DEXQ_WORKERS")


# ---- errors --------------------------------------------------------------------------------
# All of them are ValueError, as HostLab's planner is: callers that turn a refused plan into a
# tool error keep doing so.

class ProviderError(ValueError):
    code = "INVALID_ARGUMENT"


class ConfigError(ProviderError):
    pass


class ProviderDisabled(ProviderError):
    """The request names an engine that the configuration turns off. Nothing is substituted."""

    code = "UNAVAILABLE_BACKEND"


class ProviderUnavailable(ProviderError):
    code = "UNAVAILABLE_BACKEND"

    def __init__(self, message: str, reason: str = "", evidence: "dict | None" = None):
        super().__init__(message)
        self.reason, self.evidence = reason, evidence or {}


class ProviderUnsupported(ProviderUnavailable):
    code = "UNSUPPORTED_CAPABILITY"


class NamespaceCollision(ProviderError):
    pass


class InventoryError(RuntimeError):
    def __init__(self, message: str, detail: "dict | None" = None):
        super().__init__(message)
        self.detail = detail


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest_of(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


# ---- configuration -------------------------------------------------------------------------

@dataclass(frozen=True)
class Fallback:
    to: str = "none"
    on: tuple[str, ...] = ()


@dataclass(frozen=True)
class EngineConfig:
    manifest: "str | None" = None
    dialect: str = "dexsql-0.1.0"
    profile: str = "mdd-native-v1"
    profile_policy: str = "require_admitted"
    cache_dir: "str | None" = None
    max_datasets: int = 1
    fallback: Fallback = Fallback()


@dataclass(frozen=True)
class Config:
    """`native_engine` is the one switch: `dexsql` is the rollback value."""

    native_engine: str = "dexsql"
    engine: EngineConfig = EngineConfig()

    def effective(self) -> dict[str, Any]:
        e = self.engine
        return {"schema": CONFIG_SCHEMA, "native_engine": self.native_engine,
                ENGINE: {"manifest": e.manifest, "dialect": e.dialect, "profile": e.profile,
                         "profile_policy": e.profile_policy, "cache_dir": e.cache_dir, "max_datasets": e.max_datasets,
                         "fallback": {"to": e.fallback.to, "on": list(e.fallback.on)}}}

    def digest(self) -> str:
        return digest_of(self.effective())


def _exact(obj: Any, allowed: set[str], where: str, required: "set[str] | None" = None) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ConfigError(f"{where} must be an object")
    extra = set(obj) - allowed
    if extra:
        raise ConfigError(f"{where} has unsupported keys: {sorted(extra)}")
    missing = (required or set()) - set(obj)
    if missing:
        raise ConfigError(f"{where} needs {sorted(missing)}")
    return obj


def _choice(value: Any, options: Sequence[str], where: str) -> str:
    if not isinstance(value, str) or value not in options:
        raise ConfigError(f"{where} must be one of {list(options)}")
    return value


def _text(value: Any, where: str, *, nullable: bool = False) -> "str | None":
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value:
        raise ConfigError(f"{where} must be a non-empty string of at most 4096 characters")
    return value


def parse_config(obj: Any) -> Config:
    """Strict: an unknown key, a wrong type or an ambiguous fallback is an error, never a default."""
    top = _exact(obj, {"schema", "native_engine", ENGINE}, "config", {"schema"})
    if top["schema"] != CONFIG_SCHEMA:
        raise ConfigError("config.schema must be " + CONFIG_SCHEMA)
    native = _choice(top.get("native_engine", "dexsql"), NATIVE_ENGINES, "config.native_engine")
    section = _exact(top.get(ENGINE, {}), {"manifest", "dialect", "profile", "profile_policy", "cache_dir",
                                           "max_datasets", "fallback"}, "config." + ENGINE)
    fallback = _exact(section.get("fallback", {}), {"to", "on"}, "config.fallback")
    target = _choice(fallback.get("to", "none"), FALLBACK_TARGETS, "config.fallback.to")
    on = fallback.get("on", [])
    if not isinstance(on, list) or len(set(map(str, on))) != len(on):
        raise ConfigError("config.fallback.on must be a list of unique codes")
    for code in on:
        _choice(code, FALLBACK_ELIGIBLE, "config.fallback.on[]")
    if (target == "none") != (not on):
        raise ConfigError("config.fallback needs `to: dexsql` together with a non-empty `on`, or neither")
    count = section.get("max_datasets", 1)
    if type(count) is not int or not 1 <= count <= 16:
        raise ConfigError("config.max_datasets must be an integer 1..16")
    return Config(native, EngineConfig(
        manifest=_text(section.get("manifest"), "config.manifest", nullable=True),
        dialect=_choice(section.get("dialect", "dexsql-0.1.0"), DIALECTS, "config.dialect"),
        profile=_text(section.get("profile", "mdd-native-v1"), "config.profile"),
        profile_policy=_choice(section.get("profile_policy", "require_admitted"), PROFILE_POLICIES,
                               "config.profile_policy"),
        cache_dir=_text(section.get("cache_dir"), "config.cache_dir", nullable=True),
        max_datasets=count, fallback=Fallback(target, tuple(on))))


def load_config(source: "dict | str | os.PathLike[str] | None" = None, environ: "dict | None" = None) -> Config:
    """A dict, a file, `HOSTLAB_PROVIDER_CONFIG`, or the defaults (which route nothing to the new engine)."""
    env = os.environ if environ is None else environ
    if source is None and env.get("HOSTLAB_PROVIDER_CONFIG"):
        source = env["HOSTLAB_PROVIDER_CONFIG"]
    if source is None:
        return Config()
    if isinstance(source, dict):
        return parse_config(source)
    path = Path(source)
    if path.stat().st_size > 64 * 1024:
        raise ConfigError("the provider configuration exceeds 64 KiB")
    try:
        return parse_config(json.loads(path.read_text(encoding="utf-8")))
    except ValueError as error:
        if isinstance(error, ConfigError):
            raise
        raise ConfigError("the provider configuration is not JSON") from None


# ---- requests ------------------------------------------------------------------------------

def split_request(request: Any) -> tuple[Any, dict[str, Any]]:
    """The request as HostLab's planner knows it, and the `negotiation` block it does not."""
    if not isinstance(request, dict) or "negotiation" not in request:
        return request, {}
    negotiation = _exact(request["negotiation"], {"fallback"}, "negotiation")
    mode = _choice(negotiation.get("fallback", "configured"), NEGOTIATION_FALLBACK, "negotiation.fallback")
    base = {key: value for key, value in request.items() if key != "negotiation"}
    return base, {"fallback": mode}


def request_fingerprint(request: Any, legacy: Any = None) -> str:
    """HostLab's fingerprint for requests it already knows. A request that names the new engine
    must not share an identity with the same request for DexSQL, so its backend is part of it."""
    legacy = legacy or _legacy()
    base, negotiation = split_request(request)
    forced = isinstance(base, dict) and base.get("backend") == ENGINE
    if not forced:
        return legacy.fingerprint(base) if not negotiation else digest_of(
            {"legacy": legacy.fingerprint(base), "negotiation": negotiation})
    placeholder = dict(base, backend="dexsql")
    return digest_of({"legacy": legacy.fingerprint(placeholder), "backend": ENGINE, "negotiation": negotiation})


def _legacy() -> Any:
    return importlib.import_module("analysis_plan")


# ---- the engine as the plan sees it ----------------------------------------------------------

def engine_gap(config: Config, status: "dict | None", tools: Sequence[str]) -> "tuple[str, str] | None":
    """Why the engine cannot serve a task needing `tools`, as (error code, reason), or None."""
    if not status or not status.get("available"):
        return (installer.UNAVAILABLE_CODE, (status or {}).get("reason", "not_probed"))
    profile = next((p for p in status["profiles"] if p["name"] == config.engine.profile), None)
    if profile is None:
        return (installer.UNAVAILABLE_CODE, "profile_not_offered")
    if config.engine.profile_policy == "require_admitted" and not profile["admitted"]:
        return (installer.UNAVAILABLE_CODE, "profile_not_admitted")
    if not any(d["name"] == config.engine.dialect and HOSTLAB_RELATIONS in d["features"]
               for d in status["sql_dialects"]):
        return ("UNSUPPORTED_CAPABILITY", "dialect_not_offered")
    missing = [tool for tool in tools if tool not in status["mcp_tools"]]
    if missing:
        return ("UNSUPPORTED_CAPABILITY", "tool_not_offered:" + ",".join(missing))
    return None


def engine_identity(status: dict, config: Config) -> dict[str, Any]:
    """What a report says about the engine: implementation, profile, dialect and configuration, separately."""
    profile = next(p for p in status["profiles"] if p["name"] == config.engine.profile)
    dialect = next(d for d in status["sql_dialects"] if d["name"] == config.engine.dialect)
    return {"backend": ENGINE, "product": installer.PRODUCT, "engine_version": status["version"],
            "build_id": status["build_id"], "binary_sha256": status["sha256"], "platform": status["platform"],
            "implementation_scope": status["implementation_scope"], "mcp_tools_sha256": status["mcp_tools_sha256"],
            "profile": {"name": profile["name"], "admitted": profile["admitted"],
                        "conformance_manifest_sha256": profile["conformance_manifest_sha256"],
                        "policy": config.engine.profile_policy},
            "dialect": {"hostlab": "dexsql", "engine": dialect["name"], "revision": dialect["revision"]},
            "config_digest": config.digest()}


def plan(request: Any, config: Config, *, legacy: Any = None, dexsql_available: bool = True,
         engine_status: "dict | None" = None, sqlite_cache_hit: bool = False) -> dict[str, Any]:
    legacy = legacy or _legacy()
    base, negotiation = split_request(request)
    backend = base.get("backend", "auto") if isinstance(base, dict) else "auto"
    if backend in LEGACY_BACKENDS and negotiation:
        raise ProviderError("negotiation applies to backend auto or " + ENGINE + " only")
    forced = backend == ENGINE
    routed = backend == "auto" and config.native_engine == ENGINE
    if forced and config.native_engine != ENGINE:
        raise ProviderDisabled("backend " + ENGINE + " is switched off (native_engine is "
                               + config.native_engine + "); nothing is substituted for it")
    if not forced and not routed:
        result = legacy.plan(base, dexsql_available=dexsql_available, sqlite_cache_hit=sqlite_cache_hit)
        if negotiation:
            result = dict(result, provider=_provider_block(config, "legacy", negotiation, None, []))
        return result

    legacy_request = dict(base, backend="dexsql") if forced else base
    try:
        planned = legacy.plan(legacy_request, dexsql_available=True, sqlite_cache_hit=sqlite_cache_hit)
    except ValueError as error:
        if forced:
            try:
                legacy.validate(dict(legacy_request, backend="auto"))
            except ValueError:
                raise error from None
            raise ProviderUnsupported(f"backend {ENGINE} cannot serve this request: {error}",
                                      "request_not_servable") from error
        raise
    operations = {task["id"]: task["operation"] for task in legacy.validate(legacy_request)["tasks"]}
    tasks: list[dict[str, Any]] = []
    fallbacks: list[dict[str, Any]] = []
    for item in planned["tasks"]:
        task = dict(item)
        if task["backend"] != "dexsql":
            tasks.append(task)
            continue
        gap = engine_gap(config, engine_status, TOOLS_BY_OPERATION[operations[task["id"]]])
        if gap is None:
            task.update(backend=ENGINE, forced=forced)
            tasks.append(task)
            continue
        code, reason = gap
        if forced or negotiation.get("fallback") == "forbid":
            cls = ProviderUnsupported if code == "UNSUPPORTED_CAPABILITY" else ProviderUnavailable
            raise cls(f"backend {ENGINE} cannot serve task {task['id']!r}: {reason}", reason,
                      {"task": task["id"], "code": code, "forced": forced})
        allowed = config.engine.fallback.to == "dexsql" and code in config.engine.fallback.on
        if not allowed:
            cls = ProviderUnsupported if code == "UNSUPPORTED_CAPABILITY" else ProviderUnavailable
            raise cls(f"backend {ENGINE} cannot serve task {task['id']!r} ({reason}) and no fallback is permitted "
                      f"for {code}", reason, {"task": task["id"], "code": code, "forced": False})
        if not dexsql_available:
            raise ProviderUnavailable(f"backend {ENGINE} cannot serve task {task['id']!r} ({reason}) and the "
                                      "fallback target dexsql is unavailable", reason,
                                      {"task": task["id"], "code": code, "target": "dexsql"})
        evidence = {"from": ENGINE, "to": "dexsql", "code": code, "reason": reason, "scope": "plan"}
        task.update(backend="dexsql", reason=code.lower() + "_fallback_to_dexsql", fallback_from=ENGINE,
                    forced=False, fallback=evidence)
        fallbacks.append(dict(evidence, task=task["id"]))
        tasks.append(task)
    groups = [{"backend": b, "task_ids": [t["id"] for t in tasks if t["backend"] == b]}
              for b in ("sqlite", "dexsql", ENGINE) if any(t["backend"] == b for t in tasks)]
    used = any(t["backend"] == ENGINE for t in tasks)
    identity = engine_identity(engine_status, config) if used else None
    result = dict(planned, tasks=tasks, groups=groups, dataset_opens=len(groups),
                  request_sha256=request_fingerprint(request, legacy))
    result["provider"] = _provider_block(config, "forced" if forced else "configured", negotiation, identity, fallbacks)
    return result


def _provider_block(config: Config, selection: str, negotiation: dict, identity: "dict | None",
                    fallbacks: list) -> dict[str, Any]:
    return {"schema": PLAN_SCHEMA, "native_engine": config.native_engine, "selection": selection,
            "negotiation": negotiation or {"fallback": "configured"}, "engine": identity,
            "config_digest": config.digest(), "fallbacks": fallbacks}


def resume_compatible(saved: dict, current: dict) -> None:
    """A checkpoint belongs to the engine build, profile, dialect and configuration that made it."""
    before, after = (saved.get("provider") or {}).get("engine"), (current.get("provider") or {}).get("engine")
    if before != after:
        raise ValueError("checkpoint_engine_identity_changed")


# ---- running ---------------------------------------------------------------------------------

def effective_threads(requested: int) -> int:
    return min(requested, os.cpu_count() or 1)


def mcp_arguments(config: Config, timeout_seconds: int) -> list[str]:
    """The new engine has no global `--threads`; its dialect and limits are options of `mcp`."""
    return ["mcp", "--dialect", config.engine.dialect, "--timeout-ms", str(timeout_seconds * 1000),
            "--max-datasets", str(config.engine.max_datasets)]


def child_environment(threads: int, cache_dir: Path, environ: "dict | None" = None) -> dict[str, str]:
    """HostLab's credential stripping, none of DexSQL's cache variables, and the engine's own cache."""
    env = {k: v for k, v in (os.environ if environ is None else environ).items()
           if not _SECRET.search(k) and k not in _LEGACY_ENV and k != "MDD_CACHE_DIR"}
    env.update(MDD_CACHE_DIR=str(cache_dir), MDD_FACTS_THREADS=str(effective_threads(threads)),
               PYTHONIOENCODING="utf-8")
    return env


@dataclass
class Launch:
    command: str
    args: list[str]
    env: dict[str, str]
    identity: dict[str, Any]
    namespaces: dict[str, Path] = field(default_factory=dict)


def launch(config: Config, *, threads: int, timeout_seconds: int, state: Path,
           runner: Any = None, environ: "dict | None" = None) -> Launch:
    """Verify the engine again, at the moment of starting it, and say how to start it.
    Raises `installer.EngineUnavailable` or `ProviderUnavailable` (code UNAVAILABLE_BACKEND, or
    UNSUPPORTED_CAPABILITY for a dialect the engine does not offer) when it cannot be used."""
    verified = installer.verify(manifest=config.engine.manifest, runner=runner or installer.default_runner)
    status = verified.describe()
    gap = engine_gap(config, status, ())
    if gap is not None:
        cls = ProviderUnsupported if gap[0] == "UNSUPPORTED_CAPABILITY" else ProviderUnavailable
        raise cls(f"engine not usable under this configuration: {gap[1]}", gap[1], {"code": gap[0]})
    identity = engine_identity(status, config)
    ns = namespaces(state, identity, config, environ)
    ensure_namespaces(ns, identity)
    return Launch(str(verified.path), mcp_arguments(config, timeout_seconds),
                  child_environment(threads, ns["cache"], environ), identity, ns)


# ---- gates that stay in force ------------------------------------------------------------------
# Ports of analysis_batch.py (controlled_input, archive_inventory, verify_inventory) and of its
# source check. The tests run the frozen originals as the oracle.

def controlled_input(apk: Any, roots: Sequence[Any]) -> Path:
    path = Path(apk).expanduser().resolve(strict=True)
    resolved = [Path(root).expanduser().resolve(strict=True) for root in roots]
    if not path.is_file() or path.suffix.lower() not in {".apk", ".dex", ".zip", ".jar"}:
        raise ValueError("analysis input must be an APK/DEX/ZIP/JAR file")
    if not any(path.is_relative_to(root) for root in resolved):
        raise ValueError("analysis input is outside the allowed roots")
    return path


def archive_inventory(apk: Path) -> "set[str] | None":
    """Physical DEX members, since a backend can silently skip a malformed member."""
    if apk.stat().st_size > 1024 * 1024 * 1024:
        raise ValueError("source input exceeds 1 GiB budget")
    if apk.suffix.lower() == ".dex":
        return None
    with zipfile.ZipFile(apk) as archive:
        infos = archive.infolist()
        if len(infos) > 100000:
            raise ValueError("archive exceeds entry budget")
        members = [i for i in infos if re.fullmatch(r"classes\d*\.dex", i.filename)]
    names = [i.filename for i in members]
    if not names or len(names) != len(set(names)):
        raise ValueError("archive needs an unambiguous classes*.dex member inventory")
    if sum(i.file_size for i in members) > 1024 * 1024 * 1024:
        raise ValueError("uncompressed DEX exceeds 1 GiB budget")
    return set(names)


def verify_inventory(expected: "set[str] | None", files: dict) -> None:
    actual = {re.sub(r"#\d+$", "", name) for name in files.values()}  # logical DEX #N share one member
    if expected is not None and actual != expected:
        raise InventoryError("backend did not load the complete physical DEX inventory",
                             {"missing": sorted(expected - actual), "unexpected": sorted(actual - expected)})


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def seal_report(report: dict, apk: Path, initial_stat: tuple[int, int], sample: "dict | None",
                digest: Callable[[Path], str] = file_sha256) -> dict:
    """A report is complete only if the source is the one that was named and was not changed."""
    try:
        current = (apk.stat().st_size, apk.stat().st_mtime_ns)
        unchanged = initial_stat == current and (not sample or digest(apk) == sample["sha256"])
    except OSError as error:
        report["source_unchanged"] = False
        report["source_error"] = type(error).__name__
    else:
        report["source_unchanged"] = bool(unchanged)
    report["complete"] = bool(report.get("complete")) and report["source_unchanged"]
    return report


def source_identity(apk: Path, sample: "dict | None") -> dict[str, Any]:
    stat = apk.stat()
    return {"name": apk.name, "sha256": sample["sha256"] if sample else None, "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns}


# ---- namespaces: nothing of DexSQL's or HostLab's is ever written -------------------------------

def _related(a: Path, b: Path) -> bool:
    na, nb = os.path.normcase(str(a)), os.path.normcase(str(b))
    return na == nb or na.startswith(nb + os.sep) or nb.startswith(na + os.sep)


def engine_dir(identity: dict) -> str:
    return "eng-" + digest_of({"build_id": identity["build_id"], "sha256": identity["binary_sha256"]})[:16]


def legacy_paths(state: Path, environ: "dict | None" = None) -> dict[str, Path]:
    env = os.environ if environ is None else environ
    paths = {name: state / name for name in LEGACY_NAMES}
    if env.get("DEXQ_CACHE_DIR"):
        paths["DEXQ_CACHE_DIR"] = Path(env["DEXQ_CACHE_DIR"]).expanduser().resolve()
    return paths


def namespaces(state: "str | os.PathLike[str]", identity: dict, config: Config, environ: "dict | None" = None) -> dict[str, Path]:
    """Where this engine's cache, reports and completed-request records live. Refuses any overlap
    with a path that DexSQL or HostLab uses (including an explicit `cache_dir` that points at one)."""
    base = Path(state).resolve()
    engine = engine_dir(identity)
    root = base / MDD_ROOT
    cache_root = (base / config.engine.cache_dir).resolve() if config.engine.cache_dir else root / "cache"
    mine = {"root": root, "cache": cache_root / engine, "reports": root / "reports" / engine,
            "completion": root / "completion" / engine}
    # the base of MDD_CACHE_DIR is checked too: a base that contains DexSQL's directories shares space with them
    for name, path in {**mine, "cache base": cache_root}.items():
        for legacy_name, other in legacy_paths(base, environ).items():
            if _related(path, other):
                raise NamespaceCollision(f"{ENGINE} {name} directory {path} overlaps HostLab/DexSQL {legacy_name} "
                                         f"({other}); it would not be kept apart")
    return mine


def ensure_namespaces(ns: dict[str, Path], identity: dict) -> None:
    """Create the directories and claim each with a marker; a directory claimed by another engine is a collision."""
    marker = {"schema": "mdd.hostlab-namespace.v1", "engine_dir": engine_dir(identity),
              "build_id": identity["build_id"], "binary_sha256": identity["binary_sha256"]}
    for name in ("cache", "reports", "completion"):
        directory = ns[name]
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "NAMESPACE.json"
        try:
            with path.open("x", encoding="utf-8") as stream:
                stream.write(json.dumps(marker, indent=2, sort_keys=True) + "\n")
        except FileExistsError:
            if json.loads(path.read_text(encoding="utf-8")) != marker:
                raise NamespaceCollision(f"{directory} belongs to another engine build") from None


def publish(root: Path, relative: str, payload: "bytes | dict") -> Path:
    """Write a file below `root` without ever replacing one: exclusive, staged, atomic where links exist."""
    for flavour in (PurePosixPath, PureWindowsPath):  # the same text must be safe on either kind of system
        pure = flavour(relative)
        if (not pure.parts or pure.anchor or pure.drive or pure.root or any(part in {"..", "."} for part in pure.parts)
                or ":" in relative or chr(0) in relative):
            raise NamespaceCollision("a published path must be relative and stay below its namespace")
    parts = PurePosixPath(relative.replace("\\", "/")).parts
    data = payload if isinstance(payload, bytes) else (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    target = root / Path(*parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    staged = target.parent / f".{target.name}.{os.getpid()}.{time.monotonic_ns()}.part"
    try:
        staged.write_bytes(data)
        try:
            os.link(staged, target)
        except FileExistsError:
            raise NamespaceCollision(f"{target.name} is already published; it is not overwritten") from None
        except OSError:  # a filesystem without hard links: still exclusive, no longer atomic
            try:
                with target.open("xb") as stream:
                    stream.write(data)
            except FileExistsError:
                raise NamespaceCollision(f"{target.name} is already published; it is not overwritten") from None
    finally:
        staged.unlink(missing_ok=True)
    return target


def run_identity(plan_: dict, config: Config, source: "dict | None" = None) -> dict[str, Any]:
    """Who made a result: the engine build, profile, dialect, configuration, request and source. No clock."""
    engine = (plan_.get("provider") or {}).get("engine")
    if engine is None:
        raise ProviderError("this plan does not use " + ENGINE)
    body = {"schema": RUN_SCHEMA, "engine": {k: engine[k] for k in ("engine_version", "build_id", "binary_sha256")},
            "profile": engine["profile"]["name"], "dialect": engine["dialect"]["engine"],
            "config_digest": config.digest(), "request_sha256": plan_["request_sha256"],
            "source_sha256": source.get("sha256") if source else None}
    return dict(body, id=digest_of(body)[:32])


# ---- the report ----------------------------------------------------------------------------------

def annotate_report(report: dict, plan_: dict, run: "dict | None" = None,
                    ns: "dict[str, Path] | None" = None) -> dict:
    """Add the engine's identity beside the legacy fields, never in place of them."""
    provider = plan_.get("provider")
    if provider is None:
        return report
    versions = report.setdefault("backend_versions", {})
    if provider["engine"] is not None:
        if ENGINE in versions:
            raise ProviderError("the report already carries an engine identity")
        versions[ENGINE] = provider["engine"]
    report["provider"] = dict(provider)
    if run is not None:
        report["provider"]["run"] = run
    if ns is not None:
        report["provider"]["namespaces"] = {name: str(path) for name, path in ns.items()}
    return report


def check_report(report: dict) -> None:
    """A report that used the new engine must say which engine, and DexSQL's entry must stay DexSQL's."""
    versions = report.get("backend_versions") or {}
    dexsql = versions.get("dexsql")
    if isinstance(dexsql, dict) and (dexsql.get("product") == installer.PRODUCT or "build_id" in dexsql):
        raise ProviderError("backend_versions.dexsql must describe DexSQL, not " + ENGINE)
    used = any(t.get("backend") == ENGINE for t in (report.get("plan") or {}).get("tasks", [])) or any(
        t.get("backend") == ENGINE for t in report.get("tasks", []))
    if not used:
        return
    identity = versions.get(ENGINE)
    needed = {"engine_version", "build_id", "binary_sha256", "profile", "dialect", "config_digest"}
    if not isinstance(identity, dict) or needed - set(identity):
        raise ProviderError("a report that used " + ENGINE + " must record its engine version, digest, profile, "
                            "dialect and configuration")
    if not isinstance(report.get("provider"), dict) or "run" not in report["provider"]:
        raise ProviderError("a report that used " + ENGINE + " must record its run identity")


COVERAGE_STATES = ("complete", "partial", "unknown")
OPERATION_STATES = ("ok", "error", "cancelled")


def completeness(operation_status: str, coverage_input: str, coverage_facts: str,
                 execution_complete: bool) -> dict[str, Any]:
    """The engine's three-state coverage as HostLab's complete/partial. Unknown is never complete."""
    if operation_status not in OPERATION_STATES or coverage_input not in COVERAGE_STATES \
            or coverage_facts not in COVERAGE_STATES or type(execution_complete) is not bool:
        raise ProviderError("unrecognised operation status or coverage state")
    reasons = []
    if operation_status != "ok":
        reasons.append("operation_" + operation_status)
    for name, state in (("input", coverage_input), ("facts", coverage_facts)):
        if state != "complete":
            reasons.append(f"{name}_{state}")
    if not execution_complete:
        reasons.append("execution_incomplete")
    complete = not reasons
    return {"complete": complete, "partial": not complete and operation_status == "ok",
            "failed": operation_status != "ok", "reasons": reasons}


# ---- failures: only "not here" may fall back -------------------------------------------------------

class Failure(NamedTuple):
    code: str
    origin: str
    type: str
    message: str


def _leaves(error: BaseException) -> list[BaseException]:
    if isinstance(error, BaseExceptionGroup):
        return [leaf for inner in error.exceptions for leaf in _leaves(inner)]
    return [error]


def _single(error: Any) -> Failure:
    if isinstance(error, dict):  # HostLab's failure() record
        detail, name, message = error.get("detail"), str(error.get("error", "dict")), str(error.get("message", ""))
    else:
        detail, name, message = getattr(error, "detail", None), type(error).__name__, str(error)
    if isinstance(error, (installer.EngineUnavailable, ProviderUnavailable)):  # includes ProviderUnsupported
        return Failure(error.code, "adapter", name, message[:1000])
    body = detail.get("error") if isinstance(detail, dict) else None
    code = body.get("code") if isinstance(body, dict) else None
    if isinstance(code, str):
        return Failure(code if code in ENGINE_CODES else "UNKNOWN_ENGINE_CODE", "engine", name, message[:1000])
    return Failure("UNCLASSIFIED", "unclassified", name, message[:1000])


def classify_failure(error: Any) -> Failure:
    """An exception group is one failure only if all its leaves are the same one."""
    leaves = _leaves(error) if isinstance(error, BaseException) else [error]
    found = [_single(leaf) for leaf in leaves]
    if len({f.code for f in found}) == 1:
        return found[0]
    return Failure("UNCLASSIFIED", "unclassified", type(error).__name__, "several different failures")


@dataclass(frozen=True)
class Decision:
    action: str  # "fallback" | "fail"
    reason: str
    code: str

    def to_dict(self) -> dict[str, str]:
        return {"action": self.action, "reason": self.reason, "code": self.code}


def decide_fallback(config: Config, negotiation: dict, task: dict, failure: Failure, *,
                    admitted_rows: int = 0, dexsql_available: bool = True) -> Decision:
    """Fallback only for an explicit "not here" on a task that `auto` gave the engine and that has
    produced nothing yet. Everything else, including every unrecognised failure, fails."""
    def no(reason: str) -> Decision:
        return Decision("fail", reason, failure.code)

    if task.get("backend") != ENGINE:
        return no("task_not_on_engine")
    if task.get("forced"):
        return no("forced_backend_never_falls_back")
    if negotiation.get("fallback") == "forbid":
        return no("fallback_forbidden_by_request")
    if config.engine.fallback.to != "dexsql":
        return no("fallback_not_configured")
    if failure.code not in FALLBACK_ELIGIBLE:
        return no("error_is_not_a_not_here_error")
    if failure.code not in config.engine.fallback.on:
        return no("error_not_enabled_for_fallback")
    if admitted_rows:
        return no("a_partial_result_was_already_admitted")
    if not dexsql_available:
        return no("fallback_target_unavailable")
    return Decision("fallback", "explicit_not_here_error", failure.code)


class AuditLog:
    """Every decision, with the failure that caused it and the identity of the source."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, **fields: Any) -> dict[str, Any]:
        entry = dict(fields, seq=len(self.records))
        self.records.append(entry)
        return entry


def run_with_policy(task: dict, primary: Callable[[], Any], fallback: Callable[[], Any], *, config: Config,
                    negotiation: dict, audit: AuditLog, source: "dict | None" = None,
                    admitted_rows: Callable[[], int] = lambda: 0, dexsql_available: bool = True) -> Any:
    """Run `primary`. If it raises, the original exception reaches the caller unchanged unless the
    policy allows the fallback, which then runs and whose result carries the evidence. Only
    `Exception` is considered: cancellation and interrupts pass straight through."""
    try:
        return primary()
    except Exception as error:
        failure = classify_failure(error)
        decision = decide_fallback(config, negotiation, task, failure, admitted_rows=admitted_rows(),
                                   dexsql_available=dexsql_available)
        entry = audit.record(task=task["id"], failure=failure._asdict(), decision=decision.to_dict(), source=source)
        if decision.action != "fallback":
            _attach(error, entry)
            raise
        evidence = {"from": ENGINE, "to": "dexsql", "code": failure.code, "scope": "run",
                    "primary_failure": failure._asdict()}
        try:
            result = fallback()
        except Exception as second:
            audit.record(task=task["id"], fallback_failed=classify_failure(second)._asdict(), source=source)
            _attach(second, dict(entry, primary_failure=failure._asdict()))
            raise
        if isinstance(result, dict):
            if "fallback" in result:
                raise ProviderError("a task result must not already carry fallback evidence")
            result = dict(result, fallback=evidence)
        return result


def _attach(error: BaseException, evidence: dict) -> None:
    """Keep the evidence with the exception HostLab will record; the exception itself is untouched."""
    try:
        error.provider_evidence = evidence  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        pass
    if hasattr(error, "add_note"):
        error.add_note("provider decision: " + canonical(evidence.get("decision", {})))
