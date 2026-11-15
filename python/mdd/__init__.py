"""MeguvizDexDash Python SDK over the stable C ABI (major 1).

Standard library only. No business package is imported: this reads any DEX or APK the
core can capture. See `mdd.open_snapshot`.
"""
from . import errors
from ._cells import DexMutf8
from ._ffi import ABI_MAJOR, ABI_MINOR, Library, library, load
from .core import Batch, Input, Query, Result, Session, Snapshot, is_complete, open_snapshot
from .errors import MddError

__all__ = [
    "ABI_MAJOR", "ABI_MINOR", "Batch", "DexMutf8", "Input", "Library", "MddError", "Query",
    "Result", "Session", "Snapshot", "capabilities", "errors", "is_complete", "library",
    "live_handles", "load", "open_snapshot",
]


def capabilities() -> dict:
    """What this library offers: ABI, profile (never admitted here), query kinds, layers."""
    lib = library()
    return lib.json_view("mdd_capabilities_json_v1")


def live_handles() -> int:
    """Diagnostic: how many ABI handles are alive in this process."""
    return library().live_handles()
