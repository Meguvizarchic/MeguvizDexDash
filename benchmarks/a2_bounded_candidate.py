"""Experimental A1 dataset composition; never an audit or A2 certificate.

The caller must provide independent snapshot, ordering and inventory
verification callbacks. Their True values are caller assertions, not facts
verified by this module or the producer. The fixed A1 does not itself expose
the producer generation/hash needed to qualify such an assertion.
"""
from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
import math
from pathlib import Path
import re
import time

from mcp import Client

if __package__:
    from .a2_compact_adapter import CompactRowsAdapter
    from .a2_dataset_lifecycle import A1DatasetLifecycle
    from .a2_hostlab_session import _DeliveryDigest
    from .a2_mcp_transport import McpPipeLimits, OwnedMcpTransport
    from .a2_windows_pipe_owner import WindowsJobPipeOwner
else:
    from a2_compact_adapter import CompactRowsAdapter
    from a2_dataset_lifecycle import A1DatasetLifecycle
    from a2_hostlab_session import _DeliveryDigest
    from a2_mcp_transport import McpPipeLimits, OwnedMcpTransport
    from a2_windows_pipe_owner import WindowsJobPipeOwner


class CandidateError(RuntimeError):
    """A required assertion, complete result or owned cleanup was missing."""


class _BoundSource:
    """Pin the caller's source identity without claiming producer snapshot binding."""

    def __init__(self, source):
        self._source = source
        self._path, self._sha256 = source.path, source.sha256

    @property
    def path(self):
        return self._path

    @property
    def sha256(self):
        return self._sha256

    def _check_identity(self):
        if self._source.path != self._path or self._source.sha256 != self._sha256:
            raise CandidateError('caller source identity changed')

    def verify_source(self):
        self._check_identity()
        self._source.verify_source()
        self._check_identity()

    def verify_inventory(self, source, files):
        self.verify_source()
        self._source.verify_inventory(source, files)
        self.verify_source()


class A1BoundedCandidate:
    """One task-confined, single-use A1 dataset over one externally owned Job.

    The three verifier callbacks must return exactly True after independently
    checking their stated condition; no default or fallback verifier exists.
    A callback return is a caller assertion, not a producer attestation.
    Successful context exit certifies neither a complete audit nor performance.
    The caller owns launch and must still supervise synchronous startup and
    identity hashing, which are outside the pipe owner's watchdog bounds.
    """

    _A1_SHA256 = '602105c98232120c14d6124fb33574f2f95f12e50e51d25b8834f893925f28d6'

    def __init__(self, owner: WindowsJobPipeOwner, source, *, mcp_limits: McpPipeLimits,
                 verify_snapshot_binding, verify_ordering, verify_inventory,
                 continuation_reason, ordering_terms=None, timeout=900):
        if not isinstance(owner, WindowsJobPipeOwner) or not isinstance(mcp_limits, McpPipeLimits):
            raise ValueError('one owned Job pipe and explicit MCP limits are required')
        if not all(callable(fn) for fn in (verify_snapshot_binding, verify_ordering,
                                           verify_inventory, continuation_reason)):
            raise ValueError('snapshot, ordering, inventory and continuation checks are required')
        if ordering_terms is not None and not callable(ordering_terms):
            raise ValueError('ordering terms must be supplied by a callable')
        if not all(callable(getattr(source, name, None)) for name in ('verify_source', 'verify_inventory')):
            raise ValueError('a fixed source and physical inventory verifier are required')
        if (not isinstance(getattr(source, 'sha256', None), str)
                or not re.fullmatch(r'[0-9a-f]{64}', source.sha256)
                or not isinstance(getattr(source, 'path', None), Path)
                or not source.path.is_absolute()):
            raise ValueError('source SHA-256 and path are required')
        if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
                or not math.isfinite(timeout) or timeout <= 0):
            raise ValueError('a finite positive session deadline is required')
        owner._check()
        if owner.executable_sha256 != self._A1_SHA256:
            raise CandidateError('owned producer is not the fixed A1 binary')
        self.owner, self.source, self.mcp_limits = owner, _BoundSource(source), mcp_limits
        self._verify_snapshot = verify_snapshot_binding
        self._verify_ordering = verify_ordering
        self._verify_inventory = verify_inventory
        self._continuation_reason = continuation_reason
        self._ordering_terms = ordering_terms
        self._deadline = min(time.monotonic() + timeout, owner._deadline)
        self._state = 'new'
        self._failed = False
        self._active_query = False
        self._receipts = []
        self._task = None
        self._stack = None
        self._transport = None
        self._lifecycle = None
        self._adapter = None
        self.dataset_id = None
        self.files = {}

    def remaining_seconds(self):
        return max(0.0, self._deadline - time.monotonic())

    @property
    def qualified(self):
        """This experimental composition never grants a profile qualification."""
        return False

    @property
    def deliveries(self):
        """Completed consumer-iteration receipts; not an audit certificate."""
        return tuple(self._receipts)

    def _same_task(self):
        if asyncio.current_task() is not self._task:
            raise CandidateError('candidate must be used and closed by its entering task')

    def _snapshot_assertion(self, dataset_id):
        if dataset_id != self.dataset_id:
            raise CandidateError('dataset identity differs from opened candidate')
        if self._verify_snapshot(dataset_id, self.source.sha256, self.owner.executable_sha256) is not True:
            raise CandidateError('caller did not verify producer snapshot binding')

    def _ordering_assertion(self, original, projected):
        if self._verify_ordering(original, projected) is not True:
            raise CandidateError('caller did not verify projected total order')

    async def _abort_owned(self):
        await self.owner.close()
        return self.owner.tree_empty_verified and self.owner._state == 'closed'

    async def _ensure_owner_closed(self):
        if self.owner._state != 'closed':
            await self.owner.close()
        if not self.owner.tree_empty_verified:
            raise CandidateError('owned Job cleanup was not confirmed')

    async def _declare_shutdown(self, exc_type, exc, traceback):
        if exc is None and self._lifecycle.close_confirmed:
            if self._transport.failure is not None:
                raise CandidateError('MCP transport failed before shutdown') from self._transport.failure
            self._transport.expect_session_shutdown()
        return False

    async def _result(self, sql, **bounds):
        try:
            result = await self._adapter.result(sql, **bounds)
        except Exception as error:
            if self._transport.failure is not None:
                raise CandidateError('MCP transport failed') from self._transport.failure
            raise
        if self._transport.failure is not None:
            raise CandidateError('MCP transport failed after query') from self._transport.failure
        if (not isinstance(result.columns, tuple) or not result.columns
                or not isinstance(result.rows, list) or type(result.total_rows) is not int
                or result.total_rows != len(result.rows) or type(result.page_count) is not int
                or result.page_count <= 0):
            raise CandidateError('query did not return a complete shaped result')
        return result

    async def _open_inventory(self):
        result = await self._result('SELECT file_id,entry_name FROM dex_files ORDER BY file_id')
        if result.columns != ('file_id', 'entry_name'):
            raise CandidateError('producer inventory schema differs')
        files = {}
        for row in result.rows:
            try:
                file_id, entry_name = int(row['file_id']), row['entry_name']
            except (KeyError, TypeError, ValueError) as error:
                raise CandidateError('invalid DEX inventory row') from error
            if file_id < 0 or file_id in files or not isinstance(entry_name, str) or not entry_name:
                raise CandidateError('ambiguous DEX inventory identity')
            files[file_id] = entry_name
        if not files:
            raise CandidateError('producer returned no DEX inventory')
        self.source.verify_inventory(self.source.path, files)
        if self._verify_inventory(self.source.path, dict(files)) is not True:
            raise CandidateError('caller did not verify producer inventory')
        self._adapter.verify_binding()
        self.files = files

    async def __aenter__(self):
        if self._state != 'new':
            raise CandidateError('candidate is single-use')
        if self.remaining_seconds() <= 0:
            raise TimeoutError('candidate deadline exhausted before session')
        self._task = asyncio.current_task()
        self._state = 'opening'
        self._stack = AsyncExitStack()
        await self._stack.__aenter__()
        # Ownership survives even if SDK construction/handshake fails before
        # its transport has entered the exit stack.
        self._stack.push_async_callback(self._ensure_owner_closed)
        try:
            self._transport = OwnedMcpTransport(self.owner, self.mcp_limits)
            client = await self._stack.enter_async_context(Client(self._transport, mode='legacy'))
            self._lifecycle = A1DatasetLifecycle(
                client, self.source, remaining_seconds=self.remaining_seconds,
                abort_owned_transport=self._abort_owned)
            # LIFO: close dataset first, then declare SDK shutdown, then close
            # client/transport and its owned Job. No callback certifies a query.
            self._stack.push_async_exit(self._declare_shutdown)
            opened = await self._stack.enter_async_context(self._lifecycle)
            self.dataset_id = opened.dataset_id
            self._adapter = CompactRowsAdapter(
                client, opened.dataset_id, verify_source=self.source.verify_source,
                verify_snapshot_binding=self._snapshot_assertion,
                verify_ordering=self._ordering_assertion,
                continuation_reason=self._continuation_reason,
                ordering_terms=self._ordering_terms,
                timeout=self.remaining_seconds())
            await self._open_inventory()
            self._state = 'active'
            return self
        except BaseException as error:
            self._state = 'failed'
            try:
                await self._stack.__aexit__(type(error), error, error.__traceback__)
            except BaseException as cleanup_error:
                error.add_note('candidate cleanup failed: ' + str(cleanup_error))
            raise

    def rows(self, sql, *, page_size=1000, max_rows=500000, max_bytes=128 * 1024 * 1024):
        """Reserve a query immediately; only full iteration emits a receipt."""
        self._same_task()
        if self._state != 'active' or self._failed or self._active_query:
            raise CandidateError('candidate is unusable or another query is unconsumed')
        self._active_query = True
        return self._iterate(sql, page_size=page_size, max_rows=max_rows, max_bytes=max_bytes)

    async def _iterate(self, sql, **bounds):
        complete = False
        try:
            self._same_task()
            result = await self._result(sql, **bounds)
            digest = _DeliveryDigest(sql, result.columns)
            for row in result.rows:
                self._same_task()
                if self._state != 'active' or self._failed:
                    raise CandidateError('candidate stopped before consumer iteration')
                prepared = digest.prepare(row)
                yield row
                # A row is acknowledged only when the consumer advances.
                digest.acknowledge(prepared)
            self._receipts.append(digest.receipt())
            complete = True
        finally:
            self._active_query = False
            if not complete:
                self._failed = True

    async def __aexit__(self, exc_type, exc, traceback):
        self._same_task()
        if self._state != 'active':
            raise CandidateError('candidate is not active')
        incomplete = self._failed or self._active_query
        if exc is None and incomplete:
            exc = CandidateError('query was not fully consumed')
            exc_type, traceback = type(exc), exc.__traceback__
        elif exc is not None and incomplete:
            exc.add_note('candidate also has an unconsumed or failed query')
        self._state = 'closing'
        try:
            await self._stack.__aexit__(exc_type, exc, traceback)
        except BaseException as cleanup_error:
            self._state = 'failed'
            if exc is not None:
                exc.add_note('candidate cleanup failed: ' + str(cleanup_error))
            else:
                raise
        else:
            self._state = 'closed' if exc is None else 'failed'
        if exc is not None:
            if incomplete and isinstance(exc, CandidateError) and str(exc) == 'query was not fully consumed':
                raise exc
            return False
        if not self._lifecycle.close_confirmed or not self.owner.tree_empty_verified:
            self._state = 'failed'
            raise CandidateError('dataset close or owned Job emptiness was not confirmed')
        return False
