"""Check a capture manifest against independently trusted input identities.

This is a structural/content-key check, not proof that a producer captured
those bytes or that archive members, facts, or result pages are complete.
"""
from dataclasses import dataclass
import hashlib
import json
import re

_CONTENT_ID = re.compile(r'sha256:[0-9a-f]{64}\Z')
_U64 = (1 << 64) - 1


@dataclass(frozen=True)
class ExpectedSource:
    content_id: str
    byte_length: int
    input_kind: str


@dataclass(frozen=True)
class SnapshotObservation:
    snapshot_id: str
    snapshot_content_key: str
    source_count: int
    captured_input_bytes: int


def verify_snapshot_manifest(manifest, *, expected_snapshot_id, expected_sources,
                             max_sources, max_input_bytes):
    """Verify identity/ordering and recompute the capture-owned-v1 content key.

    The caller must independently establish expected_snapshot_id and each
    source's content identity, length and kind. Origin labels are not identity.
    Limits describe logical sources/bytes, not CPU, allocation or RSS.
    """
    if (type(max_sources) is not int or not 0 <= max_sources <= _U64
            or type(max_input_bytes) is not int or not 0 <= max_input_bytes <= _U64
            or type(expected_sources) is not tuple or not expected_sources
            or len(expected_sources) > max_sources
            or type(expected_snapshot_id) is not str or not expected_snapshot_id):
        raise ValueError('invalid trusted snapshot expectations or limits')
    fields = {'schema_version', 'snapshot_id', 'snapshot_content_key',
              'capture_policy', 'sources', 'captured_input_bytes', 'scope'}
    if type(manifest) is not dict or set(manifest) != fields:
        raise ValueError('invalid snapshot manifest fields')
    if (manifest['schema_version'] != 'mdd.snapshot.capture.v1'
            or manifest['capture_policy'] != 'owned-captured-bytes-v1'
            or manifest['snapshot_id'] != expected_snapshot_id
            or type(manifest['scope']) is not str):
        raise ValueError('snapshot manifest identity or policy differs')
    sources = manifest['sources']
    if type(sources) is not list or len(sources) != len(expected_sources):
        raise ValueError('snapshot source count differs')
    total = 0
    items = []
    for ordinal, (source, expected) in enumerate(zip(sources, expected_sources)):
        if (type(expected) is not ExpectedSource or type(expected.content_id) is not str
                or not _CONTENT_ID.fullmatch(expected.content_id)
                or type(expected.byte_length) is not int or not 0 <= expected.byte_length <= _U64
                or type(expected.input_kind) is not str
                or expected.input_kind not in ('raw-dex', 'apk-zip')):
            raise ValueError('invalid trusted source identity')
        required = {'occurrence_id', 'input_ordinal', 'content_id', 'byte_length', 'input_kind'}
        if (type(source) is not dict or not required <= set(source)
                or set(source) - required - {'origin_display'}):
            raise ValueError('invalid snapshot source fields')
        origin = source.get('origin_display')
        if origin is not None and type(origin) is not str:
            raise ValueError('invalid source display origin')
        if (source['occurrence_id'] != f'{expected_snapshot_id}:source:{ordinal}'
                or source['input_ordinal'] != str(ordinal)
                or source['content_id'] != expected.content_id
                or source['byte_length'] != str(expected.byte_length)
                or source['input_kind'] != expected.input_kind):
            raise ValueError('snapshot source identity differs')
        total += expected.byte_length
        if total > max_input_bytes or total > _U64:
            raise ValueError('captured input byte budget exceeded')
        items.append([expected.content_id, expected.input_kind])
    canonical = json.dumps(['capture-owned-v1', items], ensure_ascii=False,
                           separators=(',', ':')).encode('utf-8')
    key = 'sha256:' + hashlib.sha256(canonical).hexdigest()
    if manifest['captured_input_bytes'] != str(total) or manifest['snapshot_content_key'] != key:
        raise ValueError('snapshot content key or byte total differs')
    return SnapshotObservation(expected_snapshot_id, key, len(sources), total)
