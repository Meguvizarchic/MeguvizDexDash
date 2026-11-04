"""Windows read-sharing pin for an already identity-checked benchmark input.

This candidate blocks newly opened write/delete handles while it is held. It
does not establish a producer snapshot, prevent all possible mapped writes,
or qualify an A2 workload. The caller owns the pin and must close it explicitly.
"""
from __future__ import annotations

import ctypes
import inspect
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
        self._path = source.path
        self._sha256 = getattr(source, 'sha256', None)
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
        handle = self._kernel.CreateFileW(str(self._path), 0x80000000, 1,
                                          None, 3, 0x80, None)
        if handle == ctypes.c_void_p(-1).value:
            self._state = 'failed'
            raise InputPinError('cannot acquire read-sharing input pin') from ctypes.WinError(ctypes.get_last_error())
        self._handle = handle
        self._state = 'held'
        try:
            self.verify()
        except BaseException as error:
            try:
                self.close()
            except BaseException as close_error:
                error.add_note('input pin close failed: ' + str(close_error))
            raise
        return self

    @property
    def path(self):
        """The input path fixed when the pin was constructed."""
        return self._path

    @property
    def sha256(self):
        """The source digest fixed at construction, when one was supplied."""
        if not isinstance(self._sha256, str):
            raise InputPinError('source SHA-256 identity is unavailable')
        return self._sha256

    def verify(self):
        if self._state != 'held':
            raise InputPinError('input pin is not held')
        if (self._source.path != self._path
                or getattr(self._source, 'sha256', None) != self._sha256):
            raise InputPinError('input identity changed while pin was held')
        self._source.verify_source()
        if (self._source.path != self._path
                or getattr(self._source, 'sha256', None) != self._sha256):
            raise InputPinError('input identity changed during verification')

    def verify_source(self):
        """Source callback for the existing A1 dataset opener."""
        self.verify()

    def verify_inventory(self, source, files):
        """Delegate the original physical inventory check while the pin is held."""
        check = getattr(self._source, 'verify_inventory', None)
        if not callable(check):
            raise InputPinError('source inventory check is unavailable')
        self.verify()
        result = check(source, files)
        self.verify()
        return result

    def digest_physical_members(self, *, chunk_bytes=1024 * 1024):
        """Read selected APK members while this pin is held; not a snapshot proof."""
        check = getattr(self._source, 'digest_physical_members', None)
        if not callable(check):
            raise InputPinError('source physical member digest is unavailable')
        self.verify()
        result = check(chunk_bytes=chunk_bytes)
        self.verify()
        return result

    def bind_observed_members(self, source, files, *, chunk_bytes=1024 * 1024,
                              max_observed_rows=100000,
                              max_observed_name_bytes=16 * 1024 * 1024):
        """Associate observed rows while held; producer identity remains unproven."""
        check = getattr(self._source, 'bind_observed_members', None)
        if not callable(check):
            raise InputPinError('source physical member binding is unavailable')
        self.verify()
        kwargs = {'chunk_bytes': chunk_bytes, 'max_observed_rows': max_observed_rows,
                  'max_observed_name_bytes': max_observed_name_bytes}
        try:
            signature = inspect.signature(check)
        except (TypeError, ValueError) as error:
            raise InputPinError('source name-budget support cannot be established') from error
        try:
            signature.bind(source, files, **kwargs)
        except TypeError as error:
            raise InputPinError('source does not accept the required name budget') from error
        result = check(source, files, **kwargs)
        self.verify()
        return result

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
