"""Exclusive A1 dataset lifecycle, independent of query/audit admission.

The external owner exclusively controls the client and its process tree. This
module does not launch a producer, run a HostLab audit, establish snapshot or
ordering guarantees, or claim that a successfully closed process has exited.
"""
from __future__ import annotations

import asyncio
import inspect
import math
from typing import Callable

if __package__:
    from .a2_dataset_close import A1ExclusiveDatasetCloser
    from .a2_dataset_open import A1ExclusiveDatasetOpener
else:
    from a2_dataset_close import A1ExclusiveDatasetCloser
    from a2_dataset_open import A1ExclusiveDatasetOpener


class DatasetLifecycleError(RuntimeError):
    """The owner did not confirm an attempted transport shutdown."""


class A1DatasetLifecycle:
    """Open and close one dataset on an externally owned exclusive A1 client.

    ``abort_owned_transport`` must be an async callable which returns True only
    after its owner confirms termination of its own process tree. It must never
    act on a shared or unrelated process. Even on success, dataset closure is
    not a process-tree, immutable-input, full-result, or audit certificate.
    """

    def __init__(self, client, source, *, remaining_seconds: Callable[[], float],
                 abort_owned_transport: Callable, producer_timeout_ms: int = 5000,
                 close_call_seconds: float = 5.0, abort_seconds: float = 5.0):
        if not callable(abort_owned_transport):
            raise ValueError('an owned transport abort callback is required')
        if (not isinstance(abort_seconds, (int, float)) or isinstance(abort_seconds, bool)
                or not math.isfinite(abort_seconds) or abort_seconds <= 0):
            raise ValueError('a finite positive abort deadline is required')
        if (not isinstance(close_call_seconds, (int, float)) or isinstance(close_call_seconds, bool)
                or not math.isfinite(close_call_seconds) or close_call_seconds <= 0):
            raise ValueError('a finite positive close deadline is required')
        self._client = client
        self._remaining = remaining_seconds
        self._opener = A1ExclusiveDatasetOpener(client, source,
                                                remaining_seconds=remaining_seconds,
                                                producer_timeout_ms=producer_timeout_ms)
        self._abort_owned = abort_owned_transport
        self._abort_seconds = float(abort_seconds)
        self._close_seconds = float(close_call_seconds)
        self._state = 'new'
        self.opened = None
        self.close_confirmed = False
        self.abort_confirmed = False

    async def _abort(self):
        result = self._abort_owned()
        if not inspect.isawaitable(result):
            raise DatasetLifecycleError('owner abort did not return an awaitable')
        if await asyncio.wait_for(result, timeout=self._abort_seconds) is not True:
            raise DatasetLifecycleError('owner did not confirm transport shutdown')
        self.abort_confirmed = True

    async def _abort_preserving(self, primary):
        try:
            await self._abort()
        except BaseException as error:
            primary.add_note('owned transport shutdown was not confirmed: ' + str(error))

    async def __aenter__(self):
        if self._state != 'new':
            raise DatasetLifecycleError('dataset lifecycle is not reusable')
        self._state = 'opening'
        try:
            self.opened = await self._opener.open()
            self._closer = A1ExclusiveDatasetCloser(
                self._client, self.opened.dataset_id,
                remaining_seconds=self._remaining, per_call_seconds=self._close_seconds)
        except BaseException as error:
            self._state = 'failed'
            # A returned dataset is also live if construction after open failed.
            if self._opener.abort_required or self.opened is not None:
                await self._abort_preserving(error)
            raise
        self._state = 'open'
        return self.opened

    async def __aexit__(self, error_type, error, traceback):
        if self._state != 'open':
            raise DatasetLifecycleError('dataset lifecycle is not open')
        self._state = 'closing'
        if error is not None:
            # A failed or cancelled consumer can leave an in-flight request;
            # don't send close into a transport whose state is uncertain.
            self._state = 'failed'
            await self._abort_preserving(error)
            return False
        try:
            if await self._closer.close() is not True:
                raise DatasetLifecycleError('dataset close was not confirmed')
        except BaseException as close_error:
            self._state = 'failed'
            await self._abort_preserving(close_error)
            raise
        self.close_confirmed = True
        self._state = 'closed'
        return False
