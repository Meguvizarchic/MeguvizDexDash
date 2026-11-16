"""Verify, pin and install the MeguvizDexDash engine for HostLab. Standard library only.

This is the counterpart of HostLab's install_dexsql.py for the new engine, and it refuses the
same things (a missing file, a digest that is not the pinned one, an override that is
overwritten). It differs in where the bytes come from: there is no published release of
`meguvizdexdash`, so nothing is downloaded and no network connection is opened. The bytes are
a local build that the operator names, and they are used only when their SHA-256 equals a
digest recorded in a manifest (`pin` writes one from a build; reviewing and committing that
file is the operator's decision).

Verification, in this order, and it stops at the first failure:

1. the path is not inside the legacy DexSQL install directory;
2. the manifest is well formed and pins this file's SHA-256 for this platform;
3. only then is the file run: `version` must report the pinned engine version and build id,
   and, when `deep`, `capabilities` and the MCP `tools/list` must equal what was pinned.

Every refusal is an `EngineUnavailable`, whose code is the engine's `UNAVAILABLE_BACKEND`
and whose `reason` is one of `REASONS`. An engine that is not verified is never run for
anything but the handshake. HOSTLAB_MEGUVIZDEXDASH names an explicit binary (never copied over
or replaced); HOSTLAB_DEXSQL is not read here, so the old setting cannot point at this engine.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Sequence

MANIFEST_SCHEMA = "mdd.hostlab-engine-manifest.v1"
PRODUCT = "MeguvizDexDash"
UNAVAILABLE_CODE = "UNAVAILABLE_BACKEND"
HOSTLAB_RELATIONS = "hostlab-contract-relations"
MCP_PROTOCOL = "2025-06-18"
ENV_BINARY = "HOSTLAB_MEGUVIZDEXDASH"
ENV_MANIFEST = "HOSTLAB_MEGUVIZDEXDASH_MANIFEST"
HERE = Path(__file__).resolve().parent
VENDOR = HERE / "vendor" / "meguvizdexdash"
LEGACY_VENDOR = HERE / "vendor" / "dexsql"
DEFAULT_MANIFEST = VENDOR / "manifest.json"
OUTPUT_LIMIT = 4 * 1024 * 1024
MANIFEST_LIMIT = 1024 * 1024
HANDSHAKE_SECONDS = 30.0
REASONS = frozenset({
    "manifest_missing", "manifest_invalid", "platform_unpinned", "binary_missing", "binary_unreadable",
    "digest_mismatch", "platform_mismatch", "handshake_failed", "identity_mismatch",
    "capabilities_mismatch", "tools_mismatch", "legacy_install_path"})
_SECRET = re.compile(r"TOKEN|SECRET|PASSWORD|API_KEY", re.I)
_HEX64 = re.compile(r"[0-9a-f]{64}")
Runner = Callable[[Sequence[str], "bytes | None", float], "tuple[int, bytes, bytes]"]


class EngineUnavailable(RuntimeError):
    """The engine cannot be used. `code` is the engine's own code for it; `reason` says why."""

    code = UNAVAILABLE_CODE

    def __init__(self, reason: str, message: str):
        if reason not in REASONS:
            raise ValueError("unknown unavailability reason: " + reason)
        super().__init__(message)
        self.reason = reason


def platform_key() -> str:
    return f"{platform.system()}/{platform.machine()}"


def sha256(path: "str | os.PathLike[str]") -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def child_environment() -> dict[str, str]:
    """The environment of every process started here: HostLab's own rule, no credentials."""
    return {key: value for key, value in os.environ.items() if not _SECRET.search(key)}


def default_runner(argv: Sequence[str], stdin: "bytes | None" = None, timeout: float = HANDSHAKE_SECONDS) -> tuple[int, bytes, bytes]:
    options: dict[str, Any] = {"input": stdin} if stdin is not None else {"stdin": subprocess.DEVNULL}
    try:
        done = subprocess.run(list(argv), capture_output=True, timeout=timeout, env=child_environment(),
                              check=False, **options)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EngineUnavailable("handshake_failed",
                                f"could not run {Path(argv[0]).name} {argv[1] if len(argv) > 1 else ''}: "
                                f"{type(error).__name__}") from None
    return done.returncode, done.stdout, done.stderr


# ---- the manifest ----------------------------------------------------------------------

_PROFILE_KEYS = {"name", "admitted", "conformance_manifest_sha256"}
_DIALECT_KEYS = {"name", "revision", "features"}
_BUILD_KEYS = {"platform", "file", "sha256", "engine_version", "build_id", "implementation_scope",
               "profiles", "sql_dialects", "mcp_server_version", "mcp_tools", "mcp_tools_sha256"}


def _invalid(message: str) -> EngineUnavailable:
    return EngineUnavailable("manifest_invalid", "engine manifest is invalid: " + message)


def _check_build(build: Any) -> None:
    if not isinstance(build, dict) or set(build) != _BUILD_KEYS:
        raise _invalid("a build must have exactly the keys " + ", ".join(sorted(_BUILD_KEYS)))
    for key in ("platform", "file", "engine_version", "build_id", "implementation_scope", "mcp_server_version"):
        if not isinstance(build[key], str) or not build[key] or "\x00" in build[key]:
            raise _invalid(f"build.{key} must be a non-empty string")
    if re.search(r"[\\/]", build["file"]) or build["file"] in {".", ".."}:
        raise _invalid("build.file must be a file name, not a path")
    for key in ("sha256", "mcp_tools_sha256"):
        if not isinstance(build[key], str) or not _HEX64.fullmatch(build[key]):
            raise _invalid(f"build.{key} must be 64 lower-case hex digits")
    profiles = build["profiles"]
    if not isinstance(profiles, list) or not profiles:
        raise _invalid("build.profiles must be a non-empty list")
    for profile in profiles:
        if (not isinstance(profile, dict) or set(profile) != _PROFILE_KEYS or not isinstance(profile["name"], str)
                or not profile["name"] or type(profile["admitted"]) is not bool):
            raise _invalid("a profile needs name, admitted and conformance_manifest_sha256")
        digest = profile["conformance_manifest_sha256"]
        if digest is not None and not (isinstance(digest, str) and _HEX64.fullmatch(digest)):
            raise _invalid("conformance_manifest_sha256 must be a digest or null")
        if profile["admitted"] and digest is None:
            raise _invalid("an admitted profile needs its conformance manifest digest")
    dialects = build["sql_dialects"]
    if not isinstance(dialects, list):
        raise _invalid("build.sql_dialects must be a list")
    for dialect in dialects:
        if (not isinstance(dialect, dict) or set(dialect) != _DIALECT_KEYS or not isinstance(dialect["name"], str)
                or not isinstance(dialect["revision"], str) or not isinstance(dialect["features"], list)
                or not all(isinstance(feature, str) for feature in dialect["features"])):
            raise _invalid("a dialect needs name, revision and features")
    tools = build["mcp_tools"]
    if (not isinstance(tools, list) or not tools or not all(isinstance(tool, str) and tool for tool in tools)
            or tools != sorted(set(tools))):
        raise _invalid("build.mcp_tools must be a sorted list of unique tool names")


def parse_manifest(text: "str | bytes") -> dict[str, Any]:
    try:
        manifest = json.loads(text)
    except ValueError:
        raise _invalid("it is not JSON") from None
    if (not isinstance(manifest, dict) or set(manifest) != {"schema", "product", "builds"}
            or manifest["schema"] != MANIFEST_SCHEMA or manifest["product"] != PRODUCT):
        raise _invalid(f"it must be {{schema: {MANIFEST_SCHEMA}, product: {PRODUCT}, builds}}")
    builds = manifest["builds"]
    if not isinstance(builds, list) or not builds:
        raise _invalid("builds must be a non-empty list")
    for build in builds:
        _check_build(build)
    keys = [(build["platform"], build["sha256"]) for build in builds]
    if len(keys) != len(set(keys)):
        raise _invalid("a build is pinned twice")
    return manifest


def load_manifest(path: "str | os.PathLike[str] | None" = None) -> dict[str, Any]:
    chosen = Path(path) if path else Path(os.environ[ENV_MANIFEST]) if os.environ.get(ENV_MANIFEST) else DEFAULT_MANIFEST
    try:
        if chosen.stat().st_size > MANIFEST_LIMIT:
            raise _invalid("it exceeds its size budget")
        data = chosen.read_bytes()
    except FileNotFoundError:
        raise EngineUnavailable("manifest_missing", "no engine manifest at " + chosen.name) from None
    except OSError as error:
        raise EngineUnavailable("manifest_missing", f"engine manifest unreadable: {type(error).__name__}") from None
    return parse_manifest(data)


# ---- the handshake ----------------------------------------------------------------------

def _json_output(runner: Runner, argv: Sequence[str]) -> dict[str, Any]:
    code, out, _ = runner(argv, None, HANDSHAKE_SECONDS)
    if code != 0 or len(out) > OUTPUT_LIMIT:
        raise EngineUnavailable("handshake_failed", f"`{argv[1]}` exited {code} or answered too much")
    try:
        value = json.loads(out)
    except ValueError:
        raise EngineUnavailable("handshake_failed", f"`{argv[1]}` did not answer JSON") from None
    if not isinstance(value, dict):
        raise EngineUnavailable("handshake_failed", f"`{argv[1]}` did not answer an object")
    return value


def mcp_surface(path: "str | os.PathLike[str]", dialect: str, runner: Runner = default_runner) -> dict[str, Any]:
    """Start `mcp` once, ask `initialize` and `tools/list`, close its input: what a client would see."""
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": MCP_PROTOCOL, "capabilities": {},
                    "clientInfo": {"name": "hostlab-engine-install", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    stdin = b"".join(json.dumps(item).encode() + b"\n" for item in requests)
    code, out, _ = runner([str(path), "mcp", "--dialect", dialect], stdin, HANDSHAKE_SECONDS)
    if code != 0 or len(out) > OUTPUT_LIMIT:
        raise EngineUnavailable("handshake_failed", f"`mcp` exited {code} or answered too much")
    answers: dict[Any, Any] = {}
    for line in out.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            raise EngineUnavailable("handshake_failed", "`mcp` wrote a line that is not JSON") from None
        if isinstance(message, dict) and "id" in message:
            answers[message["id"]] = message
    try:
        server = answers[1]["result"]["serverInfo"]
        tools = answers[2]["result"]["tools"]
        names = sorted(tool["name"] for tool in tools)
        schemas = sorted(({"name": tool["name"], "inputSchema": tool.get("inputSchema")} for tool in tools),
                         key=lambda tool: tool["name"])
    except (KeyError, TypeError):
        raise EngineUnavailable("handshake_failed", "`mcp` did not answer initialize and tools/list") from None
    if server.get("name") != "meguvizdexdash" or len(set(names)) != len(names):
        raise EngineUnavailable("identity_mismatch", "`mcp` is not the meguvizdexdash server")
    return {"server_version": str(server.get("version")), "tools": names,
            "tools_sha256": hashlib.sha256(canonical(schemas).encode()).hexdigest()}


def observe(path: "str | os.PathLike[str]", dialect: str = "dexsql-0.1.0", runner: Runner = default_runner,
            *, deep: bool = True) -> dict[str, Any]:
    """What the binary says it is. Call only for a file whose digest has been checked."""
    version = _json_output(runner, [str(path), "version"])
    if version.get("product") != PRODUCT or not isinstance(version.get("engine_version"), str) \
            or not isinstance(version.get("build_id"), str):
        raise EngineUnavailable("identity_mismatch", "`version` does not describe MeguvizDexDash")
    seen = {"engine_version": version["engine_version"], "build_id": version["build_id"],
            "implementation_scope": str(version.get("implementation_scope", ""))}
    if deep:
        capabilities = _json_output(runner, [str(path), "capabilities"])
        if (capabilities.get("schema_version") != "mdd.capabilities.v1" or capabilities.get("product") != PRODUCT
                or capabilities.get("build_id") != seen["build_id"]
                or capabilities.get("engine_version") != seen["engine_version"]):
            raise EngineUnavailable("identity_mismatch", "`capabilities` and `version` describe different builds")
        seen["profiles"] = [{key: profile.get(key) for key in _PROFILE_KEYS} for profile in capabilities.get("profiles", [])]
        seen["sql_dialects"] = [{key: dialect_.get(key) for key in _DIALECT_KEYS}
                                for dialect_ in capabilities.get("sql_dialects", [])]
        surface = mcp_surface(path, dialect, runner)
        if surface["server_version"] != seen["engine_version"]:
            raise EngineUnavailable("identity_mismatch", "the MCP server and `version` report different versions")
        seen.update(mcp_server_version=surface["server_version"], mcp_tools=surface["tools"],
                    mcp_tools_sha256=surface["tools_sha256"])
    return seen


# ---- verify / status ---------------------------------------------------------------------

class Verified:
    """A binary whose digest is pinned and whose handshake matched the pin."""

    def __init__(self, path: Path, entry: dict[str, Any], manifest_path: "Path | None"):
        self.path, self.entry, self.manifest_path = path, entry, manifest_path

    def describe(self) -> dict[str, Any]:
        entry = self.entry
        return {"available": True, "backend": "meguvizdexdash", "version": entry["engine_version"],
                "build_id": entry["build_id"], "sha256": entry["sha256"], "platform": entry["platform"],
                "implementation_scope": entry["implementation_scope"], "path": str(self.path),
                "profiles": entry["profiles"], "sql_dialects": entry["sql_dialects"],
                "mcp_tools": entry["mcp_tools"], "mcp_tools_sha256": entry["mcp_tools_sha256"]}


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
    except ValueError:
        return False
    return True


def _entry_for(manifest: dict[str, Any], digest: str, platform_name: str) -> dict[str, Any]:
    here = [build for build in manifest["builds"] if build["platform"] == platform_name]
    if not here:
        raise EngineUnavailable("platform_unpinned", "the manifest pins no build for " + platform_name)
    for build in here:
        if build["sha256"] == digest:
            return build
    if any(build["sha256"] == digest for build in manifest["builds"]):
        raise EngineUnavailable("platform_mismatch", "that digest is pinned for another platform")
    raise EngineUnavailable("digest_mismatch", "the binary's SHA-256 is not a pinned one (" + digest[:12] + "...)")


def default_binary(manifest: dict[str, Any], vendor: Path = VENDOR, platform_name: "str | None" = None) -> Path:
    """The newest pin for this platform, at its install location."""
    here = [build for build in manifest["builds"] if build["platform"] == (platform_name or platform_key())]
    if not here:
        raise EngineUnavailable("platform_unpinned", "the manifest pins no build for " + (platform_name or platform_key()))
    build = here[-1]
    return vendor / build["engine_version"] / build["sha256"][:16] / build["file"]


def verify(path: "str | os.PathLike[str] | None" = None, manifest: "str | os.PathLike[str] | dict | None" = None,
           runner: Runner = default_runner, *, deep: bool = False, vendor: Path = VENDOR,
           platform_name: "str | None" = None) -> Verified:
    manifest_path: "Path | None" = None
    if isinstance(manifest, dict):
        document = parse_manifest(json.dumps(manifest))
    else:
        document = load_manifest(manifest)
        manifest_path = Path(manifest) if manifest else None
    chosen = Path(path) if path else Path(os.environ[ENV_BINARY]).expanduser() if os.environ.get(ENV_BINARY) \
        else default_binary(document, vendor, platform_name)
    chosen = chosen.resolve()
    if _inside(chosen, LEGACY_VENDOR):
        raise EngineUnavailable("legacy_install_path", "the legacy DexSQL install directory is not an engine location")
    try:
        if not chosen.is_file():
            raise EngineUnavailable("binary_missing", "no engine binary at " + chosen.name)
        digest = sha256(chosen)
    except OSError as error:
        raise EngineUnavailable("binary_unreadable", f"engine binary unreadable: {type(error).__name__}") from None
    entry = _entry_for(document, digest, platform_name or platform_key())
    # From here on the file is the pinned one and may be run.
    expected_dialect = next((d["name"] for d in entry["sql_dialects"] if HOSTLAB_RELATIONS in d["features"]), "dexsql-0.1.0")
    seen = observe(chosen, expected_dialect, runner, deep=deep)
    for key in ("engine_version", "build_id"):
        if seen[key] != entry[key]:
            raise EngineUnavailable("identity_mismatch", f"the binary reports {key} {seen[key]!r}, the pin says {entry[key]!r}")
    if deep:
        if seen["profiles"] != entry["profiles"] or seen["sql_dialects"] != entry["sql_dialects"]:
            raise EngineUnavailable("capabilities_mismatch", "the binary's profiles or dialects differ from the pin")
        if seen["mcp_tools"] != entry["mcp_tools"] or seen["mcp_tools_sha256"] != entry["mcp_tools_sha256"]:
            raise EngineUnavailable("tools_mismatch", "the binary's MCP tools differ from the pin")
    return Verified(chosen, entry, manifest_path)


def status(path: "str | os.PathLike[str] | None" = None, manifest: "str | os.PathLike[str] | dict | None" = None,
           runner: Runner = default_runner, *, deep: bool = False, vendor: Path = VENDOR,
           platform_name: "str | None" = None) -> dict[str, Any]:
    try:
        return verify(path, manifest, runner, deep=deep, vendor=vendor, platform_name=platform_name).describe()
    except EngineUnavailable as error:
        return {"available": False, "backend": "meguvizdexdash", "code": error.code, "reason": error.reason,
                "message": str(error)}


# ---- pin / install -----------------------------------------------------------------------

def pin(binary: "str | os.PathLike[str]", output: "str | os.PathLike[str] | None" = None, *,
        dialect: str = "dexsql-0.1.0", runner: Runner = default_runner,
        platform_name: "str | None" = None) -> dict[str, Any]:
    """The manifest entry for a local build, from what the build says about itself. Merged into
    `output` when given: an existing pin is kept, a conflicting one for the same bytes is an error."""
    source = Path(binary).expanduser().resolve()
    if _inside(source, LEGACY_VENDOR):
        raise EngineUnavailable("legacy_install_path", "the legacy DexSQL install directory is not an engine location")
    try:
        digest = sha256(source)
    except OSError as error:
        raise EngineUnavailable("binary_missing", f"cannot read {source.name}: {type(error).__name__}") from None
    seen = observe(source, dialect, runner, deep=True)
    entry = {"platform": platform_name or platform_key(), "file": source.name, "sha256": digest,
             **{key: seen[key] for key in ("engine_version", "build_id", "implementation_scope", "profiles",
                                           "sql_dialects", "mcp_server_version", "mcp_tools", "mcp_tools_sha256")}}
    _check_build(entry)
    builds = [entry]
    if output is not None:
        target = Path(output)
        if target.exists():
            existing = load_manifest(target)
            for build in existing["builds"]:
                if (build["platform"], build["sha256"]) == (entry["platform"], digest):
                    if build != entry:
                        raise _invalid("the same bytes are already pinned with a different identity")
                    return build
            builds = existing["builds"] + [entry]
        document = {"schema": MANIFEST_SCHEMA, "product": PRODUCT, "builds": builds}
        parse_manifest(json.dumps(document))
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", dir=target.parent, suffix=".tmp", delete=False, encoding="utf-8") as stream:
            staged = Path(stream.name)
            stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
        os.replace(staged, target)
    return entry


def install(binary: "str | os.PathLike[str]", manifest: "str | os.PathLike[str] | dict | None" = None,
            runner: Runner = default_runner, *, vendor: Path = VENDOR,
            platform_name: "str | None" = None) -> Path:
    """Copy a pinned local build to its install location; never overwrite what is there."""
    if os.environ.get(ENV_BINARY):
        return verify(manifest=manifest, runner=runner, vendor=vendor, platform_name=platform_name).path
    if _inside(vendor, LEGACY_VENDOR) or _inside(LEGACY_VENDOR, vendor):
        raise EngineUnavailable("legacy_install_path", "the install directory overlaps the legacy DexSQL one")
    checked = verify(binary, manifest, runner, deep=True, vendor=vendor, platform_name=platform_name)
    entry = checked.entry
    target = vendor / entry["engine_version"] / entry["sha256"][:16] / entry["file"]
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(dir=target.parent, prefix=".stage-", suffix=Path(entry["file"]).suffix)
        staged = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(checked.path.read_bytes())
            staged.chmod(0o755)
            verify(staged, manifest, runner, vendor=vendor, platform_name=platform_name)
            os.replace(staged, target)
        finally:
            staged.unlink(missing_ok=True)
    return verify(target, manifest, runner, deep=True, vendor=vendor, platform_name=platform_name).path


def main(argv: "Sequence[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--deep", action="store_true", help="also compare capabilities and MCP tools with the pin")
    parser.add_argument("--dialect", default="dexsql-0.1.0")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("check")
    pinning = sub.add_parser("pin", help="write or extend a manifest from a local build")
    pinning.add_argument("--output", type=Path, required=True)
    sub.add_parser("install", help="copy a pinned local build to the install directory")
    args = parser.parse_args(argv)
    try:
        if args.command == "pin":
            if not args.binary:
                parser.error("pin needs --binary")
            info: Any = pin(args.binary, args.output, dialect=args.dialect)
        elif args.command == "install":
            if not args.binary:
                parser.error("install needs --binary")
            install(args.binary, args.manifest)
            info = status(manifest=args.manifest, deep=True)
        else:
            info = status(args.binary, args.manifest, deep=args.deep)
    except EngineUnavailable as error:
        info = {"available": False, "code": error.code, "reason": error.reason, "message": str(error)}
    print(json.dumps(info, indent=2, sort_keys=True))
    return 0 if info.get("available", True) else 1


if __name__ == "__main__":
    sys.exit(main())
