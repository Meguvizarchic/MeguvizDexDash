"""Conservative close and idle readback for one exclusive A1 MCP dataset.

This component never starts or kills a process and does not establish input
snapshot identity, ordering, consumer completion, or A2 qualification. Its
caller must exclusively own the client and terminate the process tree if a
close or readback fails or times out.
"""
from __future__ import annotations

import asyncio
import json
import math
from typing import Callable


class DatasetCloseError(RuntimeError):
    """The dataset close or the exclusive-server idle check failed."""

    def __init__(self, stage, message, *, producer_detail=None):
        super().__init__(message)
        self.stage = stage
        self.producer_detail = producer_detail


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _invalid_constant(_):
    raise ValueError('non-finite JSON constant')


def _payload(response, stage):
    """Accept a structured object, requiring textual copies to agree if present."""
    error = getattr(response, 'is_error', None)
    structured = getattr(response, 'structured_content', None)
    content = getattr(response, 'content', None)
    detail = {'structured_content': structured, 'content': content}
    if error is not False:
        raise DatasetCloseError(stage, 'MCP operation failed or error status is absent',
                                producer_detail=detail)
    if not isinstance(content, list):
        raise DatasetCloseError(stage, 'MCP content is absent or malformed', producer_detail=detail)
    parsed = []
    for item in content:
        text = getattr(item, 'text', None)
        if not isinstance(text, str):
            raise DatasetCloseError(stage, 'non-text lifecycle response', producer_detail=detail)
        try:
            parsed.append(json.loads(text, object_pairs_hook=_unique_object,
                                     parse_constant=_invalid_constant))
        except (ValueError, TypeError) as error:
            raise DatasetCloseError(stage, 'malformed lifecycle JSON', producer_detail=detail) from error
    if structured is None:
        if len(parsed) != 1 or not isinstance(parsed[0], dict):
            raise DatasetCloseError(stage, 'missing lifecycle object', producer_detail=detail)
        return parsed[0]
    if not isinstance(structured, dict) or any(item != structured for item in parsed):
        raise DatasetCloseError(stage, 'lifecycle content disagrees with structured object',
                                producer_detail=detail)
    return structured


class A1ExclusiveDatasetCloser:
    """Confirm close followed by an empty, idle exclusive A1 server readback.

    ``remaining_seconds`` is the caller's existing monotonic deadline. A single
    caller must exclusively own this client, and no other work may be submitted
    during or after close. A successful result confirms observed server state,
    not that the OS process or descendants have exited.
    """

    def __init__(self, client, dataset_id: str, *, remaining_seconds: Callable[[], float],
                 per_call_seconds: float = 5.0):
        if not isinstance(dataset_id, str) or not dataset_id:
            raise ValueError('dataset identity is required')
        if not callable(getattr(client, 'call_tool', None)) or not callable(remaining_seconds):
            raise ValueError('exclusive MCP client and deadline are required')
        if (not isinstance(per_call_seconds, (int, float)) or isinstance(per_call_seconds, bool)
                or not math.isfinite(per_call_seconds) or per_call_seconds <= 0):
            raise ValueError('a finite positive per-call deadline is required')
        self._client = client
        self._dataset = dataset_id
        self._remaining = remaining_seconds
        self._per_call = float(per_call_seconds)
        self._state = 'active'

    async def _call(self, tool, arguments):
        remaining = self._remaining()
        if (not isinstance(remaining, (int, float)) or isinstance(remaining, bool)
                or not math.isfinite(remaining) or remaining <= 0):
            raise DatasetCloseError(tool, 'shared deadline is exhausted or invalid')
        response = await asyncio.wait_for(self._client.call_tool(tool, arguments),
                                          timeout=min(float(remaining), self._per_call))
        remaining = self._remaining()
        if (not isinstance(remaining, (int, float)) or isinstance(remaining, bool)
                or not math.isfinite(remaining) or remaining <= 0):
            raise DatasetCloseError(tool, 'shared deadline expired during lifecycle response')
        return _payload(response, tool)

    async def close(self):
        """Return True only after the exact close and idle readback both succeed."""
        if self._state != 'active':
            raise DatasetCloseError('close_dataset', 'dataset closer is not reusable')
        self._state = 'closing'
        try:
            closed = await self._call('close_dataset', {'dataset_id': self._dataset})
            if closed.get('closed') is not True or closed.get('dataset_id') != self._dataset:
                raise DatasetCloseError('close_dataset', 'close receipt does not match dataset',
                                        producer_detail=closed)
            idle = await self._call('list_datasets', {})
            usage = idle.get('usage')
            if (idle.get('datasets') != [] or type(idle.get('admitted_requests')) is not int
                    or idle['admitted_requests'] != 0 or type(idle.get('running_requests')) is not int
                    or idle['running_requests'] != 0 or not isinstance(usage, dict)
                    or type(usage.get('datasets')) is not int or usage['datasets'] != 0
                    or type(usage.get('input_bytes')) is not int or usage['input_bytes'] != 0):
                raise DatasetCloseError('list_datasets', 'exclusive server is not empty and idle',
                                        producer_detail=idle)
            self._state = 'closed'
            return True
        except BaseException:
            self._state = 'failed'
            raise
