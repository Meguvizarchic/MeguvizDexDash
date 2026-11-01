"""Candidate A2 compact-MCP query adapter for the fixed HostLab CLI DTO.

The caller owns one exclusive MCP client/dataset and supplies source,
producer-snapshot, ordering checks and the frozen HostLab continuation guard.
This module does not launch an engine, install a backend, qualify A2, or prove
a stable source snapshot or query order on its own.
Only a completely consumed query returns rows; failures never return a prefix.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Callable


class CompactAdapterError(RuntimeError):
    """Explicit A2 transport or compatibility failure; no automatic fallback."""

    def __init__(self, message, *, producer_detail=None):
        super().__init__(message)
        self.producer_detail = producer_detail


class OrderTerm:
    """One discovered raw projected-input column and a fixed sort direction."""

    __slots__ = ('column', 'descending')

    def __init__(self, column: str, descending: bool = False):
        self.column = column
        self.descending = descending


class CompleteRows:
    """One query's shape and fully received DTO, not a consumer receipt."""

    __slots__ = ('columns', 'rows', 'total_rows', 'page_count')

    def __init__(self, columns, rows, total_rows, page_count):
        self.columns = tuple(columns)
        self.rows = rows
        self.total_rows = total_rows
        self.page_count = page_count


def _quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _append_outer_order(statement: str, columns: tuple[str, ...], terms) -> str:
    """Build syntax only; this function does not prove ordering equivalence."""
    if not isinstance(terms, (list, tuple)) or not terms or len(terms) > len(columns):
        raise CompactAdapterError("explicit ordering terms are empty or invalid")
    seen = set()
    output = []
    for term in terms:
        if (type(term) is not OrderTerm or not isinstance(term.column, str)
                or type(term.descending) is not bool or term.column not in columns
                or term.column in seen):
            raise CompactAdapterError("explicit ordering term is invalid or not a discovered column")
        seen.add(term.column)
        output.append('hostlab_rows.' + _quote_identifier(term.column)
                      + (' DESC' if term.descending else ' ASC'))
    return statement + ' ORDER BY ' + ','.join(output)


class CompactRowsAdapter:
    """One exclusive, already-open DexSQL 0.1.1 dataset; no concurrent use.

    ``verify_source`` must raise if fixed input identity changed.
    ``verify_snapshot_binding`` must raise unless the producer dataset is bound
    to the intended immutable source generation; a pathname hash alone is not
    sufficient. Both run before and after each call. ``verify_ordering`` must
    raise unless the projected SQL guarantees a deterministic total order,
    including ties, across re-executions. ``continuation_reason`` must be the
    pinned HostLab guard. These external requirements are not established by
    this adapter, and no caller here qualifies a workload.
    """

    def __init__(self, client, dataset_id: str, *, verify_source: Callable[[], None],
                 verify_snapshot_binding: Callable[[str], None],
                 verify_ordering: Callable[[str, str], None],
                 continuation_reason: Callable[[str], str | None], timeout: float = 900,
                 ordering_terms: Callable[[str, tuple[str, ...]], list[OrderTerm]] | None = None,
                 producer_timeout_ms: int = 5000):
        if not isinstance(dataset_id, str) or not dataset_id:
            raise ValueError("dataset identity is required")
        if not all(callable(check) for check in (verify_source, verify_snapshot_binding,
                                                 verify_ordering, continuation_reason)):
            raise ValueError("source, producer snapshot, order and continuation checks are required")
        if ordering_terms is not None and not callable(ordering_terms):
            raise ValueError("ordering terms must be supplied by a callable")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout < float("inf"):
            raise ValueError("a finite positive deadline is required")
        if type(producer_timeout_ms) is not int or not 1 <= producer_timeout_ms <= (1 << 64) - 1:
            raise ValueError("producer timeout must match its configured maximum")
        self._client, self._dataset = client, dataset_id
        self._verify_source, self._continuation_reason = verify_source, continuation_reason
        self._verify_snapshot_binding, self._verify_ordering = verify_snapshot_binding, verify_ordering
        self._ordering_terms = ordering_terms
        self._producer_timeout_ms = producer_timeout_ms
        self._deadline = time.monotonic() + timeout
        self._lock = asyncio.Lock()
        self._poisoned = False
        self.queries = 0
        self.oversize_retries = 0

    def remaining_seconds(self) -> float:
        """Time remaining in the adapter's shared monotonic deadline."""
        return max(0.0, self._deadline - time.monotonic())

    def _checkpoint(self):
        if time.monotonic() >= self._deadline:
            raise TimeoutError("A2 compact dataset deadline exhausted")

    def verify_binding(self) -> None:
        """Invoke the caller's source and producer-generation checks."""
        self._checkpoint()
        self._verify_source()
        self._verify_snapshot_binding(self._dataset)
        if self.remaining_seconds() <= 0:
            raise TimeoutError("A2 compact dataset deadline exhausted during source verification")

    async def _page(self, sql: str, offset: int, limit: int, max_bytes: int):
        self._checkpoint()
        self._verify_source()
        self._verify_snapshot_binding(self._dataset)
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("A2 compact dataset deadline exhausted")
        result = await asyncio.wait_for(self._client.call_tool("query", {
            "dataset_id": self._dataset, "sql": [sql], "limit": limit,
            "offset": offset, "compact": True, "max_bytes": max_bytes,
            "timeout_ms": min(self._producer_timeout_ms, max(1, int(remaining * 1000))),
        }), timeout=remaining)
        self._verify_source()
        self._verify_snapshot_binding(self._dataset)
        if time.monotonic() >= self._deadline:
            raise TimeoutError("A2 compact dataset deadline exhausted during source verification")
        if result.is_error is True:
            detail = {
                "structured_content": result.structured_content,
                "text": "\n".join(getattr(item, "text", "") for item in result.content),
            }
            raise CompactAdapterError("compact producer rejected query", producer_detail=detail)
        if result.is_error is not False:
            raise CompactAdapterError("compact producer error status is missing or invalid")
        if not isinstance(result.content, list) or result.content:
            raise CompactAdapterError("compact response content is absent, invalid, or unexpectedly nonempty")
        raw = result.structured_content
        if not isinstance(raw, dict) or raw.get("dataset_id") != self._dataset:
            raise CompactAdapterError("compact dataset identity mismatch")
        # The producer is asked to bound each serialized response. Check again;
        # decoding the incoming response and allocator overhead are not covered.
        try:
            size = len(json.dumps(raw, ensure_ascii=False, allow_nan=False).encode("utf-8"))
        except (TypeError, ValueError, UnicodeError) as exc:
            raise CompactAdapterError("invalid compact response encoding") from exc
        if size > max_bytes:
            raise CompactAdapterError("compact response byte budget exceeded")
        statements = raw.get("statements")
        if not isinstance(statements, list) or len(statements) != 1 or not isinstance(statements[0], dict):
            raise CompactAdapterError("compact statement count mismatch")
        item = statements[0]
        columns, rows, total, cursor = (item.get("columns"), item.get("rows"),
                                        item.get("total_rows"), item.get("next_offset"))
        if (item.get("kind") != "query" or type(item.get("statement_index")) is not int
                or item["statement_index"] != 0 or "next_offset" not in item
                or type(item.get("offset")) is not int or item["offset"] != offset
                or type(item.get("truncated")) is not bool
                or not isinstance(columns, list) or not all(isinstance(x, str) for x in columns)
                or len(set(columns)) != len(columns) or not isinstance(rows, list)
                or len(rows) > limit or any(not isinstance(row, list) or len(row) != len(columns) for row in rows)
                or type(total) is not int or total < 0 or offset + len(rows) > total):
            raise CompactAdapterError("invalid compact page structure")
        if cursor is None:
            if item["truncated"] or offset + len(rows) != total:
                raise CompactAdapterError("compact terminal incomplete or truncated")
        elif (type(cursor) is not int or cursor != offset + len(rows) or cursor <= offset
              or cursor >= total or cursor > 100000):
            raise CompactAdapterError("compact cursor invalid or did not advance")
        self._checkpoint()
        return columns, rows, total, cursor

    async def rows(self, sql: str, *, page_size: int = 1000, max_rows: int = 500000,
                   max_bytes: int = 128 * 1024 * 1024, max_page_bytes: int = 128 * 1024):
        """Return complete HostLab-style dict rows, or raise without returning a prefix."""
        result = await self.result(sql, page_size=page_size, max_rows=max_rows,
                                   max_bytes=max_bytes, max_page_bytes=max_page_bytes)
        return result.rows

    async def result(self, sql: str, *, page_size: int = 1000, max_rows: int = 500000,
                     max_bytes: int = 128 * 1024 * 1024, max_page_bytes: int = 128 * 1024):
        """Return this query's shape and fully received rows after a valid terminal."""
        async with self._lock:
            if self._poisoned:
                raise CompactAdapterError("compact adapter is unusable after a failed query")
            try:
                return await self._rows(sql, page_size, max_rows, max_bytes, max_page_bytes)
            except BaseException:
                # Cancellation, bad pages, and source changes must not silently
                # reuse a dataset whose real state may have changed.
                self._poisoned = True
                raise

    async def _rows(self, sql: str, page_size: int, max_rows: int,
                    max_bytes: int, max_page_bytes: int):
        self._checkpoint()
        if not isinstance(sql, str) or not sql.strip() or len(sql.encode("utf-8")) > 256 * 1024:
            raise ValueError("invalid SQL or SQL byte budget exceeded")
        if "ORDER BY" not in sql.upper():
            raise ValueError("native audit requires stable ordering")
        if (any(type(x) is not int or x <= 0 for x in (page_size, max_rows, max_bytes, max_page_bytes))
                or page_size > 1000 or not 4096 <= max_page_bytes <= 131072):
            raise ValueError("invalid query bounds")
        source_sql = sql.rstrip(";\n")
        names, shape_rows, shape_total, shape_next = await self._page(
            "SELECT * FROM (" + source_sql + ") AS hostlab_shape LIMIT 0", 0, 1, max_page_bytes)
        if not names or shape_rows or shape_total != 0 or shape_next is not None:
            raise CompactAdapterError("invalid HostLab shape result")
        projections = ["CASE WHEN " + _quote_identifier(name) + " IS NULL THEN 'N' ELSE hex(CAST("
                       + _quote_identifier(name) + " AS TEXT)) END AS " + _quote_identifier(name) for name in names]
        statement = "SELECT " + ",".join(projections) + " FROM (" + source_sql + ") AS hostlab_rows"
        if self._ordering_terms is not None:
            terms = self._ordering_terms(source_sql, tuple(names))
            statement = _append_outer_order(statement, tuple(names), terms)
        if len(statement.encode("utf-8")) > 256 * 1024:
            raise CompactAdapterError("projected SQL exceeds HostLab byte budget")
        self._verify_ordering(source_sql, statement)
        self._checkpoint()
        offset, total, result, used, pages = 0, None, [], 0, 0
        page_limit = page_size
        while True:
            if offset + page_limit > 100000:
                requested = 100000 - offset
                if requested <= 0:
                    raise CompactAdapterError("compact producer offset limit prevents complete output")
            else:
                requested = page_limit
            try:
                columns, rows, current_total, cursor = await self._page(
                    statement, offset, requested, max_page_bytes)
            except CompactAdapterError as exc:
                detail = exc.producer_detail
                raw = detail.get("structured_content") if isinstance(detail, dict) else None
                error = raw.get("error") if isinstance(raw, dict) else None
                if (not isinstance(error, dict) or error.get("kind") != "output_too_large"
                        or error.get("dataset_closed") is not False
                        or raw.get("dataset_id") != self._dataset or requested <= 1
                        or self._continuation_reason(source_sql) is not None):
                    raise
                # Only the same producer/dataset and an explicit live-dataset
                # error permit retrying this offset. Never admit partial rows.
                page_limit = max(1, requested // 2)
                self.oversize_retries += 1
                continue
            if columns != names or (total is not None and total != current_total):
                raise CompactAdapterError("compact schema or total changed between pages")
            pages += 1
            total = current_total
            if total > max_rows:
                raise CompactAdapterError("HostLab complete row budget exceeded")
            for cells in rows:
                self._checkpoint()
                decoded = []
                for cell in cells:
                    self._checkpoint()
                    if not isinstance(cell, str):
                        raise CompactAdapterError("projected compact cell is not text")
                    if cell == "N":
                        value = None
                    else:
                        try:
                            value = bytes.fromhex(cell).decode("utf-8", "strict")
                        except (ValueError, UnicodeError) as exc:
                            raise CompactAdapterError("malformed HostLab hex cell") from exc
                    used += len(value.encode("utf-8")) if value is not None else 0
                    if used > max_bytes:
                        raise CompactAdapterError("HostLab complete byte budget exceeded")
                    decoded.append(value)
                result.append(dict(zip(names, decoded)))
            self._checkpoint()
            if cursor is None:
                if len(result) != total:
                    raise CompactAdapterError("not all rows were consumed")
                complete = CompleteRows(names, result, total, pages)
                self._checkpoint()
                self.queries += 1
                return complete
            reason = self._continuation_reason(source_sql)
            if reason is not None:
                raise CompactAdapterError("unsafe compact continuation: " + str(reason))
            offset = cursor
