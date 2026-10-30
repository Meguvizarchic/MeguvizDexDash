"""Verify an MDD selected-scope v1 preimage against a caller-trusted roster.

This checks framing and hashes, not that the roster, snapshot, DEX or audit is
authentic or complete. The roster must come from independently checked input
and inventory evidence; a preimage alone does not encode the per-input counts.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

_PREFIX = b'mdd-selected-scope-v1'
_MAX_U64 = (1 << 64) - 1
_CONTENT_ID = re.compile(r'sha256:[0-9a-f]{64}\Z')
_POLICIES = {'top-level-classes-v1', 'all-dex-members-v1', 'resources-only-v1'}


@dataclass(frozen=True)
class ExpectedDex:
    content_id: str
    archive_member_ordinal: int | None
    logical_header_byte_offset: int


@dataclass(frozen=True)
class ExpectedInput:
    input_ordinal: int
    content_id: str
    selection_policy: str
    dexes: tuple[ExpectedDex, ...]


@dataclass(frozen=True)
class ScopeCommitmentObservation:
    scope_id: str
    scope_content_key: str
    snapshot_id: str
    input_count: int
    dex_count: int


def verify_scope_preimage(preimage: bytes, *, snapshot_id: str,
                          expected_inputs: tuple[ExpectedInput, ...],
                          scope_id: str, scope_content_key: str,
                          captured_source_count: int, max_entries: int,
                          max_bytes: int) -> ScopeCommitmentObservation:
    """Compare all v1 frames with trusted expectations and verify both digests.

    The caller supplies the expected snapshot and ordered roster independently;
    success does not certify input coverage, fact completeness or delivery.
    The caller also supplies the independently trusted captured source count.
    Limits separately bound captured sources, selected inputs, DEXes and
    preimage bytes, not RSS or CPU.
    """
    if (type(max_entries) is not int or max_entries < 0 or type(max_bytes) is not int
            or max_bytes < 0 or type(preimage) is not bytes or len(preimage) > max_bytes):
        raise ValueError('invalid scope preimage bounds')
    if (type(expected_inputs) is not tuple or not isinstance(snapshot_id, str)
            or not snapshot_id or len(snapshot_id) > max_bytes
            or not isinstance(scope_id, str) or not _CONTENT_ID.fullmatch(scope_id)
            or not isinstance(scope_content_key, str) or not _CONTENT_ID.fullmatch(scope_content_key)):
        raise ValueError('invalid expected scope identity')
    if (type(captured_source_count) is not int or captured_source_count < 0
            or captured_source_count > max_entries or not expected_inputs
            or len(expected_inputs) > captured_source_count or len(expected_inputs) > max_entries
            or not preimage.startswith(_PREFIX)):
        raise ValueError('scope input count or prefix differs')
    position = len(_PREFIX)
    dex_count = 0

    def frame(expected: bytes):
        nonlocal position
        if position + 8 > len(preimage):
            raise ValueError('truncated scope frame length')
        count = int.from_bytes(preimage[position:position + 8], 'little')
        position += 8
        if count > len(preimage) - position or count != len(expected):
            raise ValueError('scope frame length differs')
        if memoryview(preimage)[position:position + count] != expected:
            raise ValueError('scope frame value differs')
        position += count

    def number(value: int) -> bytes:
        if type(value) is not int or not 0 <= value <= _MAX_U64:
            raise ValueError('invalid scope ordinal or offset')
        return value.to_bytes(8, 'little')

    def content(value: str) -> bytes:
        if not isinstance(value, str) or not _CONTENT_ID.fullmatch(value):
            raise ValueError('invalid content identity')
        return value.encode('ascii')

    last_ordinal = -1
    for item in expected_inputs:
        if type(item) is not ExpectedInput or type(item.dexes) is not tuple:
            raise ValueError('invalid expected input roster')
        if (type(item.input_ordinal) is not int or item.input_ordinal <= last_ordinal
                or item.input_ordinal >= captured_source_count):
            raise ValueError('input ordinals must be strictly ordered')
        last_ordinal = item.input_ordinal
        if type(item.selection_policy) is not str or item.selection_policy not in _POLICIES:
            raise ValueError('invalid scope selection policy')
        dex_count += len(item.dexes)
        if dex_count > max_entries:
            raise ValueError('scope roster entry budget exceeded')
        frame(number(item.input_ordinal))
        frame(content(item.content_id))
        frame(item.selection_policy.encode('ascii'))
        for dex in item.dexes:
            if type(dex) is not ExpectedDex:
                raise ValueError('invalid expected DEX roster')
            ordinal = dex.archive_member_ordinal
            if ordinal is not None and (type(ordinal) is not int or ordinal == _MAX_U64):
                raise ValueError('invalid archive member ordinal')
            frame(content(dex.content_id))
            frame(number(_MAX_U64 if ordinal is None else ordinal))
            frame(number(dex.logical_header_byte_offset))
    prefix_end = position
    frame(snapshot_id.encode('utf-8', 'strict'))
    if position != len(preimage):
        raise ValueError('unexpected trailing scope bytes')
    actual_content = 'sha256:' + hashlib.sha256(preimage[:prefix_end]).hexdigest()
    actual_scope = 'sha256:' + hashlib.sha256(preimage).hexdigest()
    if actual_content != scope_content_key or actual_scope != scope_id:
        raise ValueError('scope commitment hash differs')
    return ScopeCommitmentObservation(actual_scope, actual_content, snapshot_id,
                                      len(expected_inputs), dex_count)
