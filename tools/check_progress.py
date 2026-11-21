#!/usr/bin/env python3
"""Reject unsupported task completion and stale evidence identities."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_mdd073_preview(task_id: str, output: str) -> None:
    manifest_path = ROOT / 'artifacts/mdd-073/preview-manifest.json'
    require(manifest_path.is_file(), f'done task missing preview manifest: {task_id}: {output}')
    doc = json.loads(manifest_path.read_text(encoding='utf-8'))
    require(doc.get('task') == 'MDD-073', f'{task_id} preview manifest task mismatch')
    require(doc.get('preview') is True, f'{task_id} preview manifest must set preview=true')
    require(
        doc.get('performance_replacement_qualified') is False,
        f'{task_id} preview manifest must mark performance_replacement_qualified=false',
    )
    platforms = doc.get('tested_platforms')
    capabilities = doc.get('capabilities')
    require(isinstance(platforms, list) and len(platforms) > 0, f'{task_id} preview manifest missing tested_platforms')
    require(isinstance(capabilities, list) and len(capabilities) > 0, f'{task_id} preview manifest missing capabilities')
    for entry in platforms:
        ev = entry.get('evidence') if isinstance(entry, dict) else None
        require(isinstance(ev, str) and (ROOT / ev).is_file(), f'{task_id} preview missing platform evidence: {ev}')


def check_mdd055_preview(task_id: str, output: str) -> None:
    previews_root = ROOT / 'artifacts/previews'
    require(previews_root.is_dir(), f'done task missing previews dir: {task_id}: {output}')
    manifests = sorted(previews_root.glob('*/preview-manifest.json'))
    require(len(manifests) > 0, f'done task missing <build_id>/preview-manifest.json: {task_id}: {output}')
    for manifest_path in manifests:
        doc = json.loads(manifest_path.read_text(encoding='utf-8'))
        require(doc.get('preview') is True, f'{task_id} preview manifest must set preview=true: {manifest_path}')
        require(
            doc.get('performance_replacement_qualified') is False,
            f'{task_id} preview manifest must set performance_replacement_qualified=false: {manifest_path}',
        )
        capabilities = doc.get('capabilities')
        require(isinstance(capabilities, list) and len(capabilities) > 0, f'{task_id} preview missing capabilities: {manifest_path}')
        for file_entry in doc.get('files', []):
            rel = file_entry.get('path')
            expected_sha = file_entry.get('sha256')
            require(isinstance(rel, str) and isinstance(expected_sha, str), f'{task_id} preview malformed file entry: {manifest_path}')
            target = (manifest_path.parent / rel).resolve()
            require(target.is_relative_to(ROOT) and target.is_file(), f'{task_id} preview missing file: {target}')
            actual_sha = hashlib.sha256(target.read_bytes()).hexdigest()
            require(actual_sha == expected_sha, f'{task_id} preview file sha256 mismatch: {rel}')


DESCRIPTIVE_OUTPUT_CHECKS = {
    ('MDD-073', '桌面功能预览制品及已测平台/能力清单；未获性能替代资格时显式标 preview。'): check_mdd073_preview,
    ('MDD-055', 'artifacts/previews/<build_id>/ 中可审查的 HostLab 功能预览包、能力清单和未获性能替代资格标识。'): check_mdd055_preview,
}


def main():
    graph = json.loads((ROOT/'tasks/backlog.json').read_text(encoding='utf-8'))
    tasks = graph['tasks']
    by_id = {t['id']:t for t in tasks}
    require(len(tasks) == len(by_id) == 52, 'task IDs/count differ from the canonical graph')
    seen, active = set(), set()
    def visit(task_id):
        if task_id in active:
            raise ValueError('dependency cycle: '+task_id)
        if task_id in seen:
            return
        active.add(task_id)
        task = by_id[task_id]
        require(task['status'] in ['todo','in_progress','blocked','done'], 'invalid task status: '+task_id)
        for dependency in task['depends_on']:
            visit(dependency)
            if task['status'] == 'done' and by_id[dependency]['status'] != 'done':
                raise ValueError('done with incomplete dependency: '+task_id+' -> '+dependency)
        if task['status'] == 'done':
            for output in task['outputs']:
                descriptive_check = DESCRIPTIVE_OUTPUT_CHECKS.get((task_id, output))
                if descriptive_check is not None:
                    descriptive_check(task_id, output)
                    continue
                candidate = (ROOT/output).resolve()
                if not candidate.is_relative_to(ROOT) or not candidate.exists():
                    raise ValueError('done task missing output: '+task_id+': '+output)
            if not task.get('implementation_evidence'):
                raise ValueError('done task has no actual implementation evidence: '+task_id)
            for evidence in task['implementation_evidence']:
                if not (ROOT/evidence).is_file():
                    raise ValueError('missing evidence: '+evidence)
        active.remove(task_id)
        seen.add(task_id)
    for task_id in by_id:
        visit(task_id)
    index = json.loads((ROOT/'artifacts/index.json').read_text(encoding='utf-8'))
    for item in index.get('development_records',[]):
        path = (ROOT/item['path']).resolve()
        if not path.is_relative_to(ROOT):
            raise ValueError('artifact path escapes project')
        data = path.read_bytes()
        if len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError('stale artifact identity: '+item['path'])
    print('Progress graph, completed task outputs, evidence presence and artifact hashes passed')


if __name__ == '__main__':
    main()
