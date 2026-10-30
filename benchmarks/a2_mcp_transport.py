"""Bounded newline JSON-RPC adapter for the fixed benchmark MCP SDK.

This experimental adapter connects an already running WindowsJobPipeOwner to
MCP 2.2.0's public stream transport interface. It is not a snapshot, ordering,
query-completion, HostLab, or A2 certificate. EOF and transport failures are
sticky failures; caller code must still prove every application-level terminal.

Frame/total counters cover bytes consumed or submitted through this adapter.
SDK serialization, JSON parsing, OS/asyncio buffers and allocator overhead are
not covered by those counters or an RSS bound. The owned process's stderr is
never injected into the JSON channel. Startup and ownership retain the limits
and exclusions documented by a2_windows_pipe_owner.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from importlib import metadata
import json

import anyio
import mcp_types as types
from mcp.shared.message import SessionMessage

if __package__:
    from .a2_windows_pipe_owner import WindowsJobPipeOwner
else:
    from a2_windows_pipe_owner import WindowsJobPipeOwner


class McpPipeError(RuntimeError):
    """A framed MCP transport failed; this is not an unsupported query."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON object member')
        result[key] = value
    return result


def _invalid_constant(_):
    raise ValueError('non-finite JSON constant')


def _check_json(raw):
    """Require one strict UTF-8 JSON object before the SDK's model validation."""
    text = raw.decode('utf-8', 'strict')
    value = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    if not isinstance(value, dict):
        raise ValueError('JSON-RPC frame must be an object')
    return text


@dataclass(frozen=True)
class McpPipeLimits:
    max_frame_bytes: int
    max_input_bytes: int
    max_output_bytes: int
    max_input_frames: int
    max_output_frames: int
    read_chunk_bytes: int = 4096
    write_chunk_bytes: int = 4096

    def validate(self, owner):
        values = (self.max_frame_bytes, self.max_input_bytes, self.max_output_bytes,
                  self.max_input_frames, self.max_output_frames,
                  self.read_chunk_bytes, self.write_chunk_bytes)
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError('positive explicit MCP frame limits are required')
        if self.max_frame_bytes > 1024 * 1024:
            raise ValueError('a frame cannot exceed one MiB')
        if self.max_frame_bytes + 1 > min(self.max_input_bytes, self.max_output_bytes):
            raise ValueError('frame plus delimiter exceeds cumulative byte limits')
        if (self.read_chunk_bytes > owner._limits.max_read_bytes
                or self.write_chunk_bytes > owner._limits.max_write_bytes
                or self.max_input_bytes > owner._limits.max_output_bytes
                or self.max_output_bytes > owner._limits.max_input_bytes):
            raise ValueError('MCP limits exceed the owned pipe limits')


class _ReadStream:
    def __init__(self, transport):
        self._transport = transport
        self._buffer = bytearray()
        self._closed = False
        self._fault_delivered = False
        self._lock = asyncio.Lock()
        self._pending = None

    async def receive(self):
        try:
            async with self._lock:
                return await self._receive_locked()
        except asyncio.CancelledError as error:
            # SDK shutdown also cancels its reader. Only an explicit prior
            # shutdown intent with no buffered prefix avoids a sticky fault;
            # this never proves that the application consumed its results.
            if not self._transport._expected_shutdown or self._buffer:
                self._transport._record_failure(error)
            self._closed = True
            await self._transport._interrupt(error, self._pending)
            self._pending = None
            raise

    async def _read_owned(self, count):
        task = asyncio.create_task(self._transport.owner.read(count))
        self._pending = task
        try:
            result = await asyncio.shield(task)
        except asyncio.CancelledError:
            raise
        except BaseException:
            self._pending = None
            raise
        self._pending = None
        return result

    async def _receive_locked(self):
        if self._closed:
            raise anyio.EndOfStream
        try:
                transport = self._transport
                transport._require_active()
                limits = transport.limits
                while True:
                    newline = self._buffer.find(b'\n')
                    if newline >= 0:
                        if newline > limits.max_frame_bytes:
                            raise McpPipeError('inbound JSON frame exceeds its byte budget')
                        frame = bytes(self._buffer[:newline])
                        del self._buffer[:newline + 1]
                        transport._input_frames += 1
                        if transport._input_frames > limits.max_input_frames:
                            raise McpPipeError('inbound JSON frame count exceeded')
                        try:
                            text = _check_json(frame)
                            message = types.jsonrpc_message_adapter.validate_json(text, by_name=False)
                        except (ValueError, UnicodeError, RecursionError) as error:
                            raise McpPipeError('invalid inbound UTF-8 JSON-RPC frame') from error
                        return SessionMessage(message)
                    if len(self._buffer) > limits.max_frame_bytes:
                        raise McpPipeError('inbound JSON frame exceeds its byte budget')
                    remaining = limits.max_input_bytes - transport._input_bytes
                    if remaining <= 0:
                        raise McpPipeError('inbound cumulative byte budget exhausted')
                    count = min(limits.read_chunk_bytes,
                                limits.max_frame_bytes + 1 - len(self._buffer), remaining)
                    chunk = await self._read_owned(count)
                    transport._input_bytes += len(chunk)
                    self._buffer.extend(chunk)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self._closed = True
            await self._transport._poison(error)
            if not self._fault_delivered:
                self._fault_delivered = True
                return error
            raise anyio.EndOfStream from error

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return await self.receive()
        except anyio.EndOfStream:
            raise StopAsyncIteration

    async def aclose(self):
        self._closed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        await self.aclose()
        return False


class _WriteStream:
    def __init__(self, transport):
        self._transport = transport
        self._closed = False
        self._lock = asyncio.Lock()
        self._pending = None

    async def send(self, item):
        try:
            async with self._lock:
                await self._send_locked(item)
        except asyncio.CancelledError as error:
            self._closed = True
            self._transport._record_failure(error)
            await self._transport._interrupt(error, self._pending)
            self._pending = None
            raise

    async def _send_locked(self, item):
            if self._closed:
                raise anyio.ClosedResourceError
            try:
                transport = self._transport
                transport._require_active()
                if not isinstance(item, SessionMessage):
                    raise McpPipeError('outbound item is not an SDK SessionMessage')
                # This uses the same SDK serializer as stdio_client. Its
                # temporary allocation is outside the logical wire budget.
                payload = item.message.model_dump_json(by_alias=True, exclude_unset=True).encode('utf-8', 'strict')
                if b'\n' in payload:
                    raise McpPipeError('outbound JSON contains an unframed newline')
                _check_json(payload)
                if len(payload) > transport.limits.max_frame_bytes:
                    raise McpPipeError('outbound JSON frame exceeds its byte budget')
                framed = payload + b'\n'
                if (transport._output_frames + 1 > transport.limits.max_output_frames
                        or transport._output_bytes + len(framed) > transport.limits.max_output_bytes):
                    raise McpPipeError('outbound frame or cumulative byte budget exceeded')
                transport._output_frames += 1
                transport._output_bytes += len(framed)
                for start in range(0, len(framed), transport.limits.write_chunk_bytes):
                    task = asyncio.create_task(
                        transport.owner.write(framed[start:start + transport.limits.write_chunk_bytes]))
                    self._pending = task
                    try:
                        await asyncio.shield(task)
                    except asyncio.CancelledError:
                        raise
                    except BaseException:
                        self._pending = None
                        raise
                    self._pending = None
            except asyncio.CancelledError:
                raise
            except Exception as error:
                self._closed = True
                await self._transport._poison(error)
                raise

    async def aclose(self):
        self._closed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        await self.aclose()
        return False


class OwnedMcpTransport:
    """Single-use MCP SDK transport over one already launched owned Job pipe."""

    def __init__(self, owner: WindowsJobPipeOwner, limits: McpPipeLimits):
        if metadata.version('mcp') != '2.2.0' or metadata.version('mcp-types') != '2.2.0':
            raise McpPipeError('fixed MCP 2.2.0 and mcp-types 2.2.0 are required')
        if not isinstance(owner, WindowsJobPipeOwner) or not isinstance(limits, McpPipeLimits):
            raise ValueError('an owned pipe and explicit MCP limits are required')
        owner._check()
        limits.validate(owner)
        self.owner, self.limits = owner, limits
        self._input_bytes = self._output_bytes = 0
        self._input_frames = self._output_frames = 0
        self._state = 'new'
        self._failure = None
        self._expected_shutdown = False
        self._read = _ReadStream(self)
        self._write = _WriteStream(self)

    @property
    def failure(self):
        """First transport failure, distinct from SDK's connection-closed result."""
        return self._failure

    def _require_active(self):
        if self._state != 'active' or self._failure is not None:
            raise McpPipeError('MCP transport is not active') from self._failure
        self.owner._check()

    def _record_failure(self, error):
        if self._failure is None:
            self._failure = error
        self._state = 'failed'

    def expect_session_shutdown(self):
        """Declare caller intent to stop; this is not a completion receipt.

        The caller must separately consume and validate every result. This
        prevents reuse and rejects already buffered frame prefixes or an active
        writer; it cannot prove the peer has no other unconsumed data.
        """
        self._require_active()
        if self._read._buffer or self._write._lock.locked():
            raise McpPipeError('cannot declare shutdown with buffered data or an active writer')
        self._expected_shutdown = True
        self._write._closed = True

    async def _interrupt(self, error, pending):
        """Stop an owned IO task without letting AnyIO cancellation skip cleanup."""
        if pending is not None and not pending.done():
            pending.cancel()
        with anyio.CancelScope(shield=True):
            if pending is not None:
                try:
                    await asyncio.wait_for(asyncio.shield(pending),
                                           timeout=min(30, 2 * self.owner._job_limits.cleanup_seconds + 1))
                except asyncio.CancelledError:
                    pass
                except BaseException as cleanup_error:
                    error.add_note('owned IO termination: ' + str(cleanup_error))
            try:
                await asyncio.wait_for(self.owner.close(),
                                       timeout=min(30, 2 * self.owner._job_limits.cleanup_seconds + 1))
            except BaseException as cleanup_error:
                error.add_note('owned Job cleanup failed: ' + str(cleanup_error))

    async def _poison(self, error):
        self._record_failure(error)
        with anyio.CancelScope(shield=True):
            try:
                await self.owner.close()
            except BaseException as cleanup_error:
                error.add_note('owned Job cleanup failed: ' + str(cleanup_error))

    async def __aenter__(self):
        if self._state != 'new':
            raise McpPipeError('MCP transport is single-use')
        self.owner._check()
        self._state = 'active'
        return self._read, self._write

    async def __aexit__(self, exc_type, exc, traceback):
        self._read._closed = True
        self._write._closed = True
        try:
            # The SDK normally exits under an AnyIO cancellation scope. Protect
            # owned cleanup from level cancellation while retaining the outer
            # error; a timeout never becomes successful transport completion.
            with anyio.fail_after(
                    min(30, 2 * self.owner._job_limits.cleanup_seconds + 1), shield=True):
                await self.owner.close()
        except asyncio.CancelledError as cleanup_error:
            if isinstance(exc, asyncio.CancelledError):
                exc.add_note('owned Job cleanup was interrupted: ' + str(cleanup_error))
                raise exc
            if exc is not None:
                cleanup_error.add_note('cancellation interrupted handling: ' + str(exc))
            raise
        except BaseException as cleanup_error:
            if exc is not None:
                exc.add_note('owned Job cleanup failed: ' + str(cleanup_error))
                return False
            raise
        finally:
            self._state = 'closed'
        if self._failure is not None:
            if exc is not None:
                exc.add_note('MCP transport failed: ' + str(self._failure))
            else:
                raise McpPipeError('MCP transport failed before context close') from self._failure
        return False
