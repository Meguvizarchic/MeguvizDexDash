"""Cross-check selected scope against a caller-trusted capture roster.

This compares commitments and identities only. It does not authenticate the
producer, inventory, DEX contents, facts, execution, or delivery.
"""
from dataclasses import dataclass

from scope_commitment import ExpectedInput, verify_scope_preimage
from snapshot_commitment import verify_snapshot_manifest


@dataclass(frozen=True)
class CaptureScopeObservation:
    snapshot_id: str
    snapshot_content_key: str
    scope_id: str
    scope_content_key: str
    captured_source_count: int
    selected_input_count: int
    selected_dex_count: int
    all_captured_sources_selected: bool


def verify_capture_scope(manifest, preimage, *, expected_snapshot_id,
                         expected_sources, expected_inputs, scope_id,
                         scope_content_key, max_sources, max_input_bytes,
                         max_scope_entries, max_scope_bytes):
    """Compare a capture and selected scope using independently trusted rosters.

    Exact DEX members and selection policy must come from independent inventory
    evidence. The returned all-selected flag is only a roster comparison, not
    a completeness certificate or proof of actual captured bytes.
    """
    capture = verify_snapshot_manifest(
        manifest, expected_snapshot_id=expected_snapshot_id,
        expected_sources=expected_sources, max_sources=max_sources,
        max_input_bytes=max_input_bytes)
    if type(expected_inputs) is not tuple:
        raise ValueError('invalid selected input roster')
    for selected in expected_inputs:
        if (type(selected) is not ExpectedInput or type(selected.input_ordinal) is not int
                or not 0 <= selected.input_ordinal < len(expected_sources)
                or selected.content_id != expected_sources[selected.input_ordinal].content_id):
            raise ValueError('selected input does not match captured source')
    scope = verify_scope_preimage(
        preimage, snapshot_id=expected_snapshot_id, expected_inputs=expected_inputs,
        scope_id=scope_id, scope_content_key=scope_content_key,
        captured_source_count=len(expected_sources), max_entries=max_scope_entries,
        max_bytes=max_scope_bytes)
    return CaptureScopeObservation(
        capture.snapshot_id, capture.snapshot_content_key, scope.scope_id,
        scope.scope_content_key, capture.source_count, scope.input_count,
        scope.dex_count, scope.input_count == capture.source_count)
