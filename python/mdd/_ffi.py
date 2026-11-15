"""Load the library, declare every signature, negotiate the ABI, raise on failure.

Only `ctypes` from the standard library is used. Nothing here knows about a query
language or a business package: it moves handles, views and status codes.
"""
from __future__ import annotations

import ctypes
import json
import os
import sys
import warnings
from pathlib import Path
from typing import Any

from . import errors

ABI_MAJOR = 1
ABI_MINOR = 0

_u32, _u64, _vp = ctypes.c_uint32, ctypes.c_uint64, ctypes.c_void_p


class BytesView(ctypes.Structure):
    _fields_ = [("ptr", _vp), ("len", _u64)]


class AbiInfo(ctypes.Structure):
    _fields_ = [("struct_size", _u32), ("abi_major", _u32), ("abi_minor", _u32), ("reserved", _u32)]


_P = ctypes.POINTER
# name -> (argument types, takes a trailing out_error)
_SIGNATURES: dict[str, tuple[list[Any], bool]] = {
    "mdd_abi_negotiate_v1": ([_u32, _u32, _P(AbiInfo)], True),
    "mdd_capabilities_json_v1": ([_P(BytesView)], True),
    "mdd_open_snapshot_v1": ([_P(BytesView), _P(_u64)], True),
    "mdd_snapshot_manifest_json_v1": ([_u64, _P(BytesView)], True),
    "mdd_snapshot_close_v1": ([_u64], True),
    "mdd_snapshot_release": ([_u64], False),
    "mdd_open_session_v1": ([_u64, _P(BytesView), _P(_u64)], True),
    "mdd_session_close_v1": ([_u64], True),
    "mdd_session_release": ([_u64], False),
    "mdd_prepare_query_v1": ([_u64, _P(BytesView), _P(_u64)], True),
    "mdd_prepared_release": ([_u64], False),
    "mdd_start_query_v1": ([_u64, _P(BytesView), _P(_u64)], True),
    "mdd_query_next_v1": ([_u64, _u32, _P(_u64)], True),
    "mdd_query_cancel_v1": ([_u64], True),
    "mdd_query_release": ([_u64], False),
    "mdd_event_kind_v1": ([_u64, _P(_u32)], True),
    "mdd_event_batch_v1": ([_u64, _P(_u64)], True),
    "mdd_event_terminal_json_v1": ([_u64, _P(BytesView)], True),
    "mdd_event_release": ([_u64], False),
    "mdd_batch_json_v1": ([_u64, _P(BytesView)], True),
    "mdd_batch_row_count_v1": ([_u64, _P(_u32)], True),
    "mdd_batch_sequence_v1": ([_u64, _P(_u64)], True),
    "mdd_batch_ack_v1": ([_u64], True),
    "mdd_batch_retain": ([_u64], False),
    "mdd_batch_release": ([_u64], False),
    "mdd_error_json_v1": ([_u64, _P(BytesView)], False),
    "mdd_error_status_v1": ([_u64, _P(_u32)], False),
    "mdd_error_release": ([_u64], False),
    "mdd_debug_live_handles_v1": ([_P(_u64)], False),
}

EVENT_BATCH = 1
EVENT_TERMINAL = 2


def _library_names() -> list[str]:
    if sys.platform == "win32":
        return ["mdd_ffi.dll"]
    if sys.platform == "darwin":
        return ["libmdd_ffi.dylib"]
    return ["libmdd_ffi.so"]


def find_library() -> Path:
    """`MDD_FFI_LIBRARY`, else the newest build under this checkout's target directory."""
    explicit = os.environ.get("MDD_FFI_LIBRARY")
    if explicit:
        return Path(explicit)
    root = Path(__file__).resolve().parents[2]
    found = [root / "target" / profile / name
             for profile in ("release", "debug") for name in _library_names()
             if (root / "target" / profile / name).is_file()]
    if not found:
        raise FileNotFoundError(
            "mdd_ffi library not found; build it with `cargo build -p mdd-ffi` or set MDD_FFI_LIBRARY")
    chosen = max(found, key=lambda path: path.stat().st_mtime)
    if len(found) > 1:
        warnings.warn(f"both a debug and a release mdd_ffi exist; using the newer one, {chosen}. "
                      "Set MDD_FFI_LIBRARY to choose.", stacklevel=2)
    return chosen


def view_of(data: bytes) -> tuple[BytesView, Any]:
    """A request view and the buffer that must stay alive for the call."""
    if not data:
        return BytesView(None, 0), None
    buffer = ctypes.create_string_buffer(data, len(data))
    return BytesView(ctypes.addressof(buffer), len(data)), buffer


def read_view(view: BytesView) -> bytes:
    """Copy a library view into Python-owned bytes (the library's view is borrowed)."""
    return ctypes.string_at(view.ptr, view.len) if view.len else b""


class Library:
    def __init__(self, path: str | os.PathLike[str] | None = None):
        self.path = Path(path) if path else find_library()
        self._dll = ctypes.CDLL(str(self.path))
        for name, (argtypes, takes_error) in _SIGNATURES.items():
            function = getattr(self._dll, name)
            function.restype = _u32
            function.argtypes = [*argtypes, *([_P(_u64)] if takes_error else [])]
        self.abi = self._negotiate()

    def _negotiate(self) -> tuple[int, int]:
        info = AbiInfo(ctypes.sizeof(AbiInfo), 0, 0, 0)
        self.call("mdd_abi_negotiate_v1", ABI_MAJOR, ABI_MINOR, ctypes.byref(info))
        return info.abi_major, info.abi_minor

    def raw(self, name: str, *args: Any) -> int:
        """Call without raising: the status, for tests that look at it directly."""
        return getattr(self._dll, name)(*args)

    def call(self, name: str, *args: Any) -> None:
        takes_error = _SIGNATURES[name][1]
        function = getattr(self._dll, name)
        if not takes_error:
            status = function(*args)
            if status:
                raise errors.from_status(status, {"message": f"{name} failed", "code": ""})
            return
        error = _u64(0)
        status = function(*args, ctypes.byref(error))
        if status:
            raise errors.from_status(status, self._take_error(error.value))
        if error.value:  # a successful call never reports one; do not leak it if it did
            self._dll.mdd_error_release(error.value)

    def _take_error(self, handle: int) -> dict[str, Any]:
        if not handle:
            return {"message": "call failed without an error object"}
        view = BytesView()
        try:
            if self._dll.mdd_error_json_v1(handle, ctypes.byref(view)):
                return {"message": "error object unreadable"}
            return json.loads(read_view(view))
        finally:
            self._dll.mdd_error_release(handle)

    def release(self, name: str, handle: int) -> int:
        return getattr(self._dll, name)(handle)

    def live_handles(self) -> int:
        count = _u64(0)
        self.call("mdd_debug_live_handles_v1", ctypes.byref(count))
        return count.value

    def json_view(self, name: str, *args: Any) -> Any:
        view = BytesView()
        self.call(name, *args, ctypes.byref(view))
        return json.loads(read_view(view))


_library: Library | None = None


def library() -> Library:
    global _library
    if _library is None:
        _library = Library()
    return _library


def load(path: str | os.PathLike[str] | None = None) -> Library:
    """Load a specific library (also negotiating the ABI) and make it the default."""
    global _library
    _library = Library(path)
    return _library
