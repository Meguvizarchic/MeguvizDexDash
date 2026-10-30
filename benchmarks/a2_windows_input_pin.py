"""Windows read-sharing pin for an already identity-checked benchmark input.

This candidate blocks newly opened write/delete handles while it is held. It
does not establish a producer snapshot, prevent all possible mapped writes,
or qualify an A2 workload. The caller owns the pin and must close it explicitly.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path


class InputPinError(RuntimeError):
    """The input could not be pinned or its identity did not remain stable."""


class WindowsInputPin:
    """Hold a read handle sharing reads only, with fixed-source revalidation.

    ``source`` is a previously constructed PinnedInputInventory. The pin must
    cover producer open and every readback. Existing writable mappings, runtime
    process privileges, producer identity and snapshot capture require separate
    evidence. Hashing is synchronous and is not covered by a hard deadline.
    Keep a separate reference to this object before entering the context so
    that a failed CloseHandle can be retried even when __enter__ fails.
    """

    def __init__(self, source):
        if os.name != 'nt':
            raise InputPinError('Windows input pin requires Windows')
        if not isinstance(getattr(source, 'path', None), Path) or not callable(
                getattr(source, 'verify_source', None)):
            raise ValueError('a previously pinned input inventory is required')
        self._source = source
        self._kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self._kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32,
            ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        self._kernel.CreateFileW.restype = ctypes.c_void_p
        self._kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        self._kernel.CloseHandle.restype = ctypes.c_int
        self._handle = None
        self._state = 'new'

    def __enter__(self):
        if self._state != 'new':
            raise InputPinError('input pin is not reusable')
        # GENERIC_READ, FILE_SHARE_READ only, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL.
        handle = self._kernel.CreateFileW(str(self._source.path), 0x80000000, 1,
                                          None, 3, 0x80, None)
        if handle == ctypes.c_void_p(-1).value:
            self._state = 'failed'
            raise InputPinError('cannot acquire read-sharing input pin') from ctypes.WinError(ctypes.get_last_error())
        self._handle = handle
        self._state = 'held'
        try:
            self._source.verify_source()
        except BaseException as error:
            try:
                self.close()
            except BaseException as close_error:
                error.add_note('input pin close failed: ' + str(close_error))
            raise
        return self

    def verify(self):
        if self._state != 'held':
            raise InputPinError('input pin is not held')
        self._source.verify_source()

    def close(self):
        if self._handle is None:
            return
        if not self._kernel.CloseHandle(self._handle):
            self._state = 'failed'
            raise InputPinError('input pin close failed') from ctypes.WinError(ctypes.get_last_error())
        self._handle = None
        self._state = 'closed'

    def __exit__(self, error_type, error, traceback):
        verification_error = None
        try:
            self.verify()
        except BaseException as failure:
            verification_error = failure
        try:
            self.close()
        except BaseException as close_error:
            primary = error if error is not None else verification_error
            if primary is None:
                raise
            primary.add_note('input pin close failed: ' + str(close_error))
        if verification_error is not None:
            if error is None:
                raise verification_error
            error.add_note('input verification failed while pinned: ' + str(verification_error))
        return False
