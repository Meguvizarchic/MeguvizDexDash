"""Verified, transactional Actions artifact cache with bounded single-flight downloads."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import uuid
import zipfile

import hostlab
import remote_schedule

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_RESULT_BYTES = 128 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_FILES = 4096
DOWNLOAD_SLOTS = threading.BoundedSemaphore(4)


class ArtifactError(ValueError):
    """Stable, bounded error codes; never expose download URLs or credentials."""


def limits(profile="default"):
    if profile not in {"default", "frozen-report-v1"}:
        raise ArtifactError("unsupported_artifact_profile")
    return {"profile": profile, "archive_bytes": MAX_ARCHIVE_BYTES, "files": MAX_FILES,
            "file_bytes": MAX_FILE_BYTES,
            "result_bytes": 384 * 1024 * 1024 if profile == "frozen-report-v1" else MAX_RESULT_BYTES,
            "large_json_bytes": 128 * 1024 * 1024 if profile == "frozen-report-v1" else MAX_FILE_BYTES}


def file_limit(name, policy):
    if name in {"remote-output/ai-checkpoint.json", "remote-output/ai-resume-checkpoint.json",
                "remote-output/ai-completion-checkpoint.json", "remote-output/ai-final-checkpoint.json"}:
        return 64 * 1024 * 1024
    return (policy["large_json_bytes"] if name in {
        "remote-output/priority-target.json", "remote-output/priority-baseline.json"} else policy["file_bytes"])


def relative_name(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or "\\" in name or ":" in name
            or any(part in {"", ".", ".."} for part in name.split("/"))):
        raise ArtifactError("unsafe_artifact_path")
    for part in path.parts:
        if (part.endswith((".", " ")) or any(ord(c) < 32 for c in part)
                or part.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1, 10)], *[f"LPT{i}" for i in range(1, 10)]}):
            raise ArtifactError("unsafe_artifact_path")
    if path.suffix.lower() in {".apk", ".dex", ".sqlite", ".db", ".dxc2", ".exe", ".jar", ".pyc", ".env"} or path.name.lower() == ".env":
        raise ArtifactError("unexpected_artifact_payload")
    if any(p.lower() in {"classes", "jadx-output", "__pycache__"} for p in path.parts):
        raise ArtifactError("unexpected_artifact_payload")
    return path


def regular_file(root, name):
    path = root.joinpath(*relative_name(name).parts)
    for part in (root, *path.relative_to(root).parents):
        # Relative parents are checked below as concrete paths, including junctions.
        candidate = part if part == root else root / part
        if candidate.exists() and (candidate.is_symlink() or getattr(candidate.stat(), "st_file_attributes", 0) & 0x400):
            raise ArtifactError("linked_artifact_cache")
    if path.is_symlink() or getattr(path.stat(), "st_file_attributes", 0) & 0x400 or not path.is_file():
        raise ArtifactError("linked_artifact_cache")
    return path


def cache_directory(root):
    cursor = hostlab.STATE
    for part in (None, *root.relative_to(cursor).parts):
        if part is not None:
            cursor = cursor / part
        if cursor.exists() and (cursor.is_symlink() or getattr(cursor.stat(), "st_file_attributes", 0) & 0x400):
            raise ArtifactError("linked_artifact_cache")
        cursor.mkdir(exist_ok=True, parents=True)


def identity(repository, request_id, run):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not re.fullmatch(r"[0-9a-f]{32}", request_id):
        raise ArtifactError("invalid_artifact_identity")
    if (run.get("status") != "completed" or run.get("display_title") != "hostlab-" + request_id
            or type(run.get("id")) is not int or run["id"] <= 0
            or type(run.get("run_attempt", 1)) is not int or run.get("run_attempt", 1) < 1
            or not isinstance(run.get("head_sha"), str) or not re.fullmatch(r"[0-9a-f]{40}", run["head_sha"])):
        raise ArtifactError("invalid_artifact_identity")
    return {"repository": repository, "request_id": request_id, "run_id": run["id"],
            "run_attempt": run.get("run_attempt", 1), "head_sha": run["head_sha"]}


def cached(root, expected, *, profile="default"):
    policy = limits(profile)
    try:
        receipt_path = regular_file(root, "receipt.json")
        if receipt_path.stat().st_size > 1024 * 1024:
            return None
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        if not isinstance(receipt, dict) or receipt.get("schema") != 1 or receipt["identity"] != expected or not re.fullmatch(r"[0-9a-f]{32}", receipt["generation"]):
            return None
        if receipt.get("limits") != policy and not (profile == "default" and "limits" not in receipt):
            return None
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", receipt["artifact"]["digest"]):
            return None
        rows = receipt["files"]
        if (not isinstance(rows, list) or not 1 <= len(rows) <= policy["files"]
                or any(not isinstance(row, dict) or not isinstance(row.get("path"), str)
                       or type(row.get("bytes")) is not int for row in rows)
                or sum(r["bytes"] for r in rows) > policy["result_bytes"]):
            return None
        data = root / ("data-" + receipt["generation"])
        files = []
        seen = set()
        for row in rows:
            if row["path"].casefold() in seen or not 0 <= row["bytes"] <= file_limit(row["path"], policy):
                return None
            seen.add(row["path"].casefold())
            path = regular_file(data, row["path"])
            if path.stat().st_size != row["bytes"] or hostlab.digest(path) != row["sha256"]:
                return None
            files.append(str(path))
        return {"files": files, "root":str(data), "artifact": receipt["artifact"], "cache_hit": True,
                "run_attempt": expected["run_attempt"], "integrity": "github_archive_sha256_and_local_file_sha256",
                "profile": profile, "limits": policy}
    except (OSError, ValueError, KeyError, TypeError):
        return None


def download(endpoint, target):
    """gh handles authenticated redirects; stdout stays binary and never enters tool logs."""
    with target.open("wb") as stream:
        result = subprocess.run([os.environ.get("HOSTLAB_GH", "gh"), "api", endpoint],
                                stdout=stream, stderr=subprocess.PIPE, timeout=90)
    if result.returncode:
        raise ArtifactError("artifact_download_failed")


def unpack(archive_path, destination, *, profile="default"):
    policy = limits(profile)
    records = []; seen = set(); total = 0
    with zipfile.ZipFile(archive_path) as archive:
        if len(archive.infolist()) > policy["files"]:
            raise ArtifactError("artifact_entry_budget_exceeded")
        for info in archive.infolist():
            relative_name(info.orig_filename.rstrip("/") if info.is_dir() else info.orig_filename)
            name = info.filename.rstrip("/") if info.is_dir() else info.filename
            relative_name(name)
            if stat.S_ISLNK(info.external_attr >> 16) or info.flag_bits & 1:
                raise ArtifactError("unsupported_artifact_entry")
            if info.is_dir():
                continue
            if name.casefold() in seen or info.file_size > file_limit(name, policy):
                raise ArtifactError("ambiguous_or_oversized_artifact_entry")
            seen.add(name.casefold()); total += info.file_size
            if total > policy["result_bytes"]:
                raise ArtifactError("artifact_expansion_budget_exceeded")
            target = destination.joinpath(*PurePosixPath(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
            if target.stat().st_size != info.file_size:
                raise ArtifactError("artifact_entry_size_mismatch")
            records.append({"path": name, "bytes": info.file_size, "sha256": hostlab.digest(target)})
    if not records:
        raise ArtifactError("empty_artifact")
    return records


def get(repository, request_id, run, gh, *, downloader=None, profile="default"):
    policy = limits(profile)
    expected = identity(repository, request_id, run)
    scope = hashlib.sha256(repository.encode()).hexdigest()[:16]
    root = hostlab.STATE / "artifact-cache" / scope / str(run["id"]) / ("attempt-" + str(expected["run_attempt"]))
    if profile != "default":
        root = root / profile
    cache_directory(root)
    began = time.monotonic()
    hit = cached(root, expected, profile=profile)
    if hit:
        return {**hit, "elapsed_ms": (time.monotonic() - began) * 1000}
    downloader = downloader or download
    lock = None
    while lock is None:
        lock = remote_schedule.admission_lock(root / "download.lock")
        if lock is None:
            if time.monotonic() - began >= 60:
                raise ArtifactError("artifact_download_busy")
            time.sleep(.05)
    try:
        hit = cached(root, expected, profile=profile)
        if hit:
            return {**hit, "elapsed_ms": (time.monotonic() - began) * 1000}
        if not DOWNLOAD_SLOTS.acquire(timeout=60):
            raise ArtifactError("artifact_download_busy")
        try:
            endpoint = f"repos/{repository}/actions/runs/{run['id']}/artifacts?per_page=100&name=host-analysis-{run['id']}"
            listed = json.loads(gh(["api", endpoint]))
            artifacts = [a for a in listed["artifacts"] if a["name"] == "host-analysis-" + str(run["id"])]
            if len(artifacts) != 1:
                raise ArtifactError("artifact_missing_or_ambiguous")
            artifact = artifacts[0]
            if (artifact.get("expired") or type(artifact.get("id")) is not int or artifact["id"] <= 0
                    or artifact.get("workflow_run", {}).get("id") != run["id"]
                    or artifact["workflow_run"].get("head_sha") != expected["head_sha"]
                    or not isinstance(artifact.get("digest"), str)
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"])
                    or type(artifact.get("size_in_bytes")) is not int
                    or not 0 < artifact["size_in_bytes"] <= policy["archive_bytes"]):
                raise ArtifactError("artifact_identity_or_integrity_unavailable")
            if expected["run_attempt"] > 1 and (not run.get("run_started_at") or artifact.get("created_at", "") < run["run_started_at"]):
                raise ArtifactError("artifact_from_an_older_attempt")
            with tempfile.TemporaryDirectory(prefix=".fetch-", dir=root) as temp:
                stage = Path(temp); archive = stage / "artifact.zip"; data = stage / "data"
                data.mkdir()
                downloader(f"repos/{repository}/actions/artifacts/{artifact['id']}/zip", archive)
                if (archive.stat().st_size != artifact["size_in_bytes"]
                        or "sha256:" + hostlab.digest(archive) != artifact["digest"]):
                    raise ArtifactError("artifact_archive_digest_mismatch")
                records = unpack(archive, data, profile=profile)
                generation = uuid.uuid4().hex
                receipt = {"schema": 1, "identity": expected, "generation": generation,
                    "artifact": {key: artifact[key] for key in ("id", "name", "digest", "size_in_bytes")},
                    "files": records, "limits": policy}
                data.rename(root / ("data-" + generation))
                # The OS lock protects the stable temp name; publish only after every check succeeds.
                hostlab.write_json(root / "receipt.json", receipt)
            result = cached(root, expected, profile=profile)
            if result is None:
                raise ArtifactError("artifact_cache_publication_failed")
            return {**result, "cache_hit": False, "elapsed_ms": (time.monotonic() - began) * 1000}
        finally:
            DOWNLOAD_SLOTS.release()
    except (zipfile.BadZipFile, OSError, subprocess.TimeoutExpired) as exc:
        raise ArtifactError("artifact_transfer_or_cache_io_failed") from exc
    finally:
        lock.close()
