"""Conservative open and identity readback for an exclusive A1 MCP client.

This component does not start or stop a process, provide snapshot isolation,
prove ordering, or qualify an A2 workload. An owner must stop its own transport
if an open request may have been sent and this operation fails or is cancelled.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import math
from pathlib import Path
from typing import Callable

if __package__:
    from .a2_dataset_close import DatasetCloseError, _payload
else:
    from a2_dataset_close import DatasetCloseError, _payload


class DatasetOpenError(RuntimeError):
    """An exclusive open failed; inspect ``abort_required`` on the opener."""


@dataclass(frozen=True)
class OpenedDataset:
    """Observed A1 identity and producer prepare time, not a snapshot proof."""

    dataset_id: str
    input_bytes: int
    prepare_ms: float


class A1ExclusiveDatasetOpener:
    """Open exactly one fixed source using an externally owned exclusive client.

    ``source`` supplies ``path`` and ``verify_source()`` as in
    PinnedInputInventory. ``remaining_seconds`` is the shared monotonic budget.
    No call made here validates that the producer has captured immutable bytes.
    The owner must check ``abort_required`` on every failure and cancellation,
    then terminate and confirm its own process tree before reusing resources.
    """

    def __init__(self, client, source, *, remaining_seconds: Callable[[], float],
                 producer_timeout_ms: int = 5000):
        if not callable(getattr(client, 'call_tool', None)):
            raise ValueError('exclusive MCP client is required')
        if not callable(getattr(source, 'verify_source', None)) or not isinstance(
                getattr(source, 'path', None), Path):
            raise ValueError('fixed input identity is required')
        if not callable(remaining_seconds):
            raise ValueError('shared deadline is required')
        if type(producer_timeout_ms) is not int or not 1 <= producer_timeout_ms <= 5000:
            raise ValueError('A1 producer timeout must be between 1 and 5000 ms')
        self._client, self._source = client, source
        self._remaining, self._producer_timeout_ms = remaining_seconds, producer_timeout_ms
        self._state = 'active'
        self._abort_required = False

    @property
    def abort_required(self):
        """Whether an owner must terminate the transport after a failed open."""
        return self._abort_required

    def _deadline(self):
        remaining = self._remaining()
        if (not isinstance(remaining, (int, float)) or isinstance(remaining, bool)
                or not math.isfinite(remaining) or remaining <= 0):
            raise DatasetOpenError('shared deadline is exhausted or invalid')
        return float(remaining)

    async def _call(self, tool, args):
        remaining = self._deadline()
        response = await asyncio.wait_for(self._client.call_tool(tool, args), timeout=remaining)
        self._deadline()
        try:
            return _payload(response, tool)
        except DatasetCloseError as error:
            raise DatasetOpenError(f'{tool}: {error}') from error

    @staticmethod
    def _idle(payload):
        usage = payload.get('usage')
        return (payload.get('datasets') == []
                and type(payload.get('admitted_requests')) is int
                and payload['admitted_requests'] == 0
                and type(payload.get('running_requests')) is int
                and payload['running_requests'] == 0
                and isinstance(usage, dict)
                and type(usage.get('datasets')) is int and usage['datasets'] == 0
                and type(usage.get('input_bytes')) is int and usage['input_bytes'] == 0)

    async def open(self):
        """Return the observed dataset only after source and exclusive readbacks."""
        if self._state != 'active':
            raise DatasetOpenError('dataset opener is not reusable')
        self._state = 'opening'
        try:
            self._source.verify_source()
            self._deadline()
            if not self._idle(await self._call('list_datasets', {})):
                raise DatasetOpenError('server is not empty and idle before open')
            self._source.verify_source()
            remaining = self._deadline()
            args = {'inputs': [str(self._source.path)],
                    'timeout_ms': min(self._producer_timeout_ms, max(1, int(remaining * 1000)))}
            # Once submitted, timeout or cancellation cannot prove whether a
            # dataset was created. The owned transport must then be terminated.
            self._abort_required = True
            opened = await self._call('open_dataset', args)
            dataset = opened.get('dataset_id')
            inputs = opened.get('inputs')
            input_bytes, prepare_ms = opened.get('input_bytes'), opened.get('prepare_ms')
            if (not isinstance(dataset, str) or not dataset or opened.get('has_dex') is not True
                    or not isinstance(inputs, list) or len(inputs) != 1
                    or not isinstance(inputs[0], str)
                    or type(input_bytes) is not int or input_bytes <= 0
                    or not isinstance(prepare_ms, (int, float)) or isinstance(prepare_ms, bool)
                    or not math.isfinite(prepare_ms) or prepare_ms < 0):
                raise DatasetOpenError('open receipt is incomplete or malformed')
            try:
                reported = Path(inputs[0]).resolve(strict=True)
            except (OSError, ValueError) as error:
                raise DatasetOpenError('reported input path cannot be resolved') from error
            if reported != self._source.path:
                raise DatasetOpenError('open receipt identifies a different input')
            self._source.verify_source()
            readback = await self._call('list_datasets', {})
            datasets, usage = readback.get('datasets'), readback.get('usage')
            if (not isinstance(datasets, list) or len(datasets) != 1
                    or not isinstance(datasets[0], dict) or datasets[0] != opened
                    or type(readback.get('admitted_requests')) is not int
                    or readback['admitted_requests'] != 0
                    or type(readback.get('running_requests')) is not int
                    or readback['running_requests'] != 0
                    or not isinstance(usage, dict) or type(usage.get('datasets')) is not int
                    or usage['datasets'] != 1 or type(usage.get('input_bytes')) is not int
                    or usage['input_bytes'] != input_bytes):
                raise DatasetOpenError('exclusive dataset readback differs or is not idle')
            self._source.verify_source()
            self._deadline()
            self._state = 'opened'
            self._abort_required = False
            return OpenedDataset(dataset, input_bytes, float(prepare_ms))
        except BaseException:
            self._state = 'failed'
            raise
