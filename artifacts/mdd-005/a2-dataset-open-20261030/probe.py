"""Synthetic protocol checks only; no A2, snapshot or production qualification."""
import asyncio
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_dataset_open import A1ExclusiveDatasetOpener, DatasetOpenError


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def response(data, text=None):
    return SimpleNamespace(is_error=False, structured_content=data,
                           content=[] if text is None else [SimpleNamespace(text=text)])


class Source:
    def __init__(self, fail_at=0):
        self.path = (ROOT / 'tests/fixtures/generated/structured-035.dex').resolve(strict=True)
        self.calls, self.fail_at = 0, fail_at

    def verify_source(self):
        self.calls += 1
        if self.calls == self.fail_at:
            raise RuntimeError('synthetic source change')


class Client:
    def __init__(self, source, *, busy=False, different_path=False, mismatch=False,
                 invalid_counts=False, text=None, stall=False):
        self.calls, self.source = [], source
        self.busy, self.different_path, self.mismatch = busy, different_path, mismatch
        self.invalid_counts, self.text, self.stall = invalid_counts, text, stall
        self.opened = {'dataset_id': 'synthetic-dataset', 'inputs': [str(source.path)],
                       'has_dex': True, 'input_bytes': 536, 'prepare_ms': 2.0,
                       'archive_inputs': []}

    async def call_tool(self, tool, args):
        self.calls.append((tool, args))
        if tool == 'open_dataset':
            require(args['inputs'] == [str(self.source.path)], 'wrong opened path')
            require(type(args['timeout_ms']) is int and 1 <= args['timeout_ms'] <= 5000,
                    'wrong producer timeout')
            if self.stall:
                await asyncio.Event().wait()
            result = dict(self.opened)
            if self.different_path:
                result['inputs'] = [str(ROOT / 'tests/fixtures/generated/minimal-035.dex')]
            return response(result, self.text)
        require(tool == 'list_datasets', 'unexpected operation')
        is_open = any(call[0] == 'open_dataset' for call in self.calls)
        datasets = [dict(self.opened)] if is_open or self.busy else []
        if self.mismatch and is_open:
            datasets[0]['dataset_id'] = 'another-dataset'
        used = 536 if datasets else 0
        return response({'datasets': datasets, 'admitted_requests': False if self.invalid_counts else 0,
                         'running_requests': 0, 'usage': {'datasets': len(datasets), 'input_bytes': used}})


async def main():
    checks = []
    source = Source()
    client = Client(source)
    opened = A1ExclusiveDatasetOpener(client, source, remaining_seconds=lambda: 10)
    result = await opened.open()
    require(result.dataset_id == 'synthetic-dataset' and result.input_bytes == 536,
            'valid observed result differs')
    require(not opened.abort_required and source.calls == 4, 'valid checks missing')
    checks.append('exclusive_open_and_readback')
    try:
        await opened.open()
    except DatasetOpenError:
        checks.append('no_reuse')
    else:
        raise RuntimeError('opener reused')
    for name, kwargs, fail_at, needs_abort in [
        ('busy_before_open', {'busy': True}, 0, False),
        ('invalid_counter_before_open', {'invalid_counts': True}, 0, False),
        ('foreign_input_after_open', {'different_path': True}, 0, True),
        ('mismatched_readback', {'mismatch': True}, 0, True),
        ('source_changed_after_open', {}, 3, True),
        ('duplicate_json', {'text': '{"x":1,"x":2}'}, 0, True),
    ]:
        source = Source(fail_at)
        client = Client(source, **kwargs)
        opener = A1ExclusiveDatasetOpener(client, source, remaining_seconds=lambda: 10)
        try:
            await opener.open()
        except (DatasetOpenError, RuntimeError):
            require(opener.abort_required is needs_abort, name + ': wrong cleanup obligation')
            checks.append(name)
        else:
            raise RuntimeError(name + ': expected failure')
    source = Source()
    client = Client(source, stall=True)
    opener = A1ExclusiveDatasetOpener(client, source, remaining_seconds=lambda: 10)
    task = asyncio.create_task(opener.open())
    while not any(item[0] == 'open_dataset' for item in client.calls):
        await asyncio.sleep(0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        require(opener.abort_required, 'cancel lost cleanup obligation')
        checks.append('cancel_during_open')
    else:
        raise RuntimeError('cancel unexpectedly succeeded')
    print(json.dumps({'status': 'passed', 'checks': checks,
                      'source_sha256': hashlib.sha256((ROOT / 'benchmarks/a2_dataset_open.py').read_bytes()).hexdigest(),
                      'scope': 'synthetic client only; no actual producer, snapshot or A2 qualification'}))


if __name__ == '__main__':
    asyncio.run(main())
