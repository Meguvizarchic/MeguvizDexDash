#!/usr/bin/env python3
"""Reject unsupported task completion and stale evidence identities."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


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
