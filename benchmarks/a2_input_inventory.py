"""Bounded input identity and physical DEX inventory for the A2 candidate.

This implements the fixed HostLab archive-inventory rules, not an immutable
producer snapshot. The caller must independently prove that its open dataset
is bound to the same captured generation and that projected pagination has a
deterministic total order.
"""
from __future__ import annotations

import hashlib
import os
import re
import zipfile
from pathlib import Path


class InputInventoryError(RuntimeError):
    """Input identity, bounds, or physical DEX inventory is not valid."""


def _file_stat(stat):
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns


class PinnedInputInventory:
    """A single fixed input SHA-256 and HostLab-compatible physical inventory.

    ``verify_source`` is suitable for the A2 source callback. It detects an
    observed change around a complete hash, but does not establish snapshot
    isolation or guarantee that the producer read the hashed bytes.
    ``verify_inventory`` matches HostLab's physical-member comparison; raw DEX
    has no expected archive inventory and cannot claim archive coverage.
    """

    def __init__(self, source, expected_sha256: str, *, max_input_bytes=1024**3,
                 max_entries=100000, max_dex_bytes=1024**3):
        if (not isinstance(expected_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)):
            raise ValueError("a lowercase SHA-256 identity is required")
        if any(type(value) is not int or value <= 0
               for value in (max_input_bytes, max_entries, max_dex_bytes)):
            raise ValueError("positive input and archive limits are required")
        self.path = Path(source).resolve(strict=True)
        if not self.path.is_file():
            raise InputInventoryError("input is not a regular file")
        self.sha256 = expected_sha256
        self.max_input_bytes = max_input_bytes
        self.max_entries = max_entries
        self.max_dex_bytes = max_dex_bytes
        self._initial_stat = _file_stat(self.path.stat())
        self.verify_source()
        self.physical_members = self._inventory()
        self.verify_source()

    def verify_source(self):
        """Hash the complete fixed file and reject observed identity changes."""
        digest = hashlib.sha256()
        read_bytes = 0
        with self.path.open("rb") as stream:
            before = _file_stat(os.fstat(stream.fileno()))
            if before != self._initial_stat or before[2] > self.max_input_bytes:
                raise InputInventoryError("input identity or size differs")
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                read_bytes += len(block)
                if read_bytes > self.max_input_bytes:
                    raise InputInventoryError("input byte budget exceeded")
                digest.update(block)
            after = _file_stat(os.fstat(stream.fileno()))
        try:
            current = _file_stat(self.path.stat())
        except OSError as error:
            raise InputInventoryError("input disappeared during verification") from error
        if (before != after or after != current or current != self._initial_stat
                or read_bytes != current[2] or digest.hexdigest() != self.sha256):
            raise InputInventoryError("input changed or SHA-256 differs")

    def _inventory(self):
        if self.path.suffix.lower() == ".dex":
            return None
        try:
            with zipfile.ZipFile(self.path) as archive:
                infos = archive.infolist()
                if len(infos) > self.max_entries:
                    raise InputInventoryError("archive entry budget exceeded")
                members = [item for item in infos
                           if re.fullmatch(r"classes\d*\.dex", item.filename)]
                names = [item.filename for item in members]
                if not names or len(names) != len(set(names)):
                    raise InputInventoryError("DEX archive members are absent or ambiguous")
                if sum(item.file_size for item in members) > self.max_dex_bytes:
                    raise InputInventoryError("uncompressed DEX budget exceeded")
                return frozenset(names)
        except (OSError, zipfile.BadZipFile) as error:
            raise InputInventoryError("archive inventory failed") from error

    def verify_inventory(self, source, files):
        """Compare physical member names without merging logical DEX entries."""
        if Path(source).resolve(strict=True) != self.path:
            raise InputInventoryError("inventory refers to a different input")
        if not isinstance(files, dict) or not files:
            raise InputInventoryError("DEX inventory is missing")
        for file_id, name in files.items():
            if type(file_id) is not int or file_id < 0 or not isinstance(name, str) or not name:
                raise InputInventoryError("invalid logical DEX inventory row")
        self.verify_source()
        if self.physical_members is not None:
            actual = {re.sub(r"#\d+$", "", name) for name in files.values()}
            if actual != self.physical_members:
                raise InputInventoryError("physical DEX member inventory differs")
        self.verify_source()
