"""Synthetic lifecycle checks; not producer snapshot, audit or A2 qualification."""
import asyncio
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_dataset_lifecycle import A1DatasetLifecycle, DatasetLifecycleError


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def response(payload):
    return SimpleNamespace(is_error=False, structured_content=payload, content=[])


class Source:
    def __init__(self):
        self.path = (ROOT / 'tests/fixtures/generated/structured-035.dex').resolve(strict=True)
        self.checks = 0

    def verify_source(self):
        self.checks += 1


class Client:
    def __init__(self, source, *, busy=False, mismatch=False, bad_close=False, stall=False,
                 stall_close=False):
        self.source = source
        self.busy, self.mismatch, self.bad_close, self.stall = busy, mismatch, bad_close, stall
        self.stall_close = stall_close
        self.opened, self.calls = False, []
        self.dataset = {'dataset_id': 'test-dataset', 'inputs': [str(source.path)],
                        'input_bytes': 536, 'has_dex': True, 'prepare_ms': 2.0,
                        'archive_inputs': []}

    async def call_tool(self, name, arguments):
        self.calls.append(name)
        if name == 'open_dataset':
            require(arguments['inputs'] == [str(self.source.path)], 'wrong source')
            if self.stall:
                await asyncio.Event().wait()
            self.opened = True
            return response(dict(self.dataset))
        if name == 'close_dataset':
            require(arguments['dataset_id'] == 'test-dataset', 'wrong close id')
            if self.stall_close:
                await asyncio.Event().wait()
            self.opened = False
            return response({'closed': True, 'dataset_id': 'bad' if self.bad_close else 'test-dataset'})
        require(name == 'list_datasets', 'unexpected tool')
        if self.opened or self.busy:
            dataset = dict(self.dataset)
            if self.mismatch:
                dataset['dataset_id'] = 'bad'
            entries = [dataset]
        else:
            entries = []
        return response({'datasets': entries, 'admitted_requests': 0, 'running_requests': 0,
                         'usage': {'datasets': len(entries), 'input_bytes': 536 if entries else 0}})


class Owner:
    def __init__(self, result=True):
        self.calls, self.result = 0, result

    async def abort(self):
        self.calls += 1
        return self.result


def make(source, client, owner):
    return A1DatasetLifecycle(client, source, remaining_seconds=lambda: 10,
                              abort_owned_transport=owner.abort, abort_seconds=1)


async def main():
    checks = []
    source = Source(); client = Client(source); owner = Owner()
    life = make(source, client, owner)
    async with life as opened:
        require(opened.dataset_id == 'test-dataset', 'wrong dataset')
        require(not life.close_confirmed, 'closed before exit')
    require(life.close_confirmed and not life.abort_confirmed and owner.calls == 0,
            'clean close or owner state differs')
    require(client.calls == ['list_datasets', 'open_dataset', 'list_datasets',
                             'close_dataset', 'list_datasets'], 'wrong call order')
    checks.append('open_close_and_idle')
    try:
        await life.__aenter__()
    except DatasetLifecycleError:
        checks.append('lifecycle_not_reused')
    else:
        raise RuntimeError('lifecycle reused')

    source = Source(); client = Client(source, busy=True); owner = Owner()
    life = make(source, client, owner)
    try:
        async with life:
            raise RuntimeError('busy server was accepted')
    except RuntimeError as error:
        require('not empty' in str(error) and owner.calls == 0, 'busy owner was terminated')
        checks.append('busy_preflight_does_not_abort')
    else:
        raise RuntimeError('busy open succeeded')

    source = Source(); client = Client(source, mismatch=True); owner = Owner()
    life = make(source, client, owner)
    try:
        async with life:
            raise RuntimeError('mismatch accepted')
    except RuntimeError as error:
        require('readback differs' in str(error) and owner.calls == 1 and life.abort_confirmed,
                'uncertain open not aborted')
        checks.append('open_mismatch_aborts')
    else:
        raise RuntimeError('mismatched open succeeded')

    source = Source(); client = Client(source, bad_close=True); owner = Owner()
    life = make(source, client, owner)
    try:
        async with life:
            pass
    except RuntimeError as error:
        require('close receipt' in str(error) and owner.calls == 1 and life.abort_confirmed,
                'close mismatch not aborted')
        require(not life.close_confirmed, 'bad close reported confirmed')
        checks.append('close_failure_aborts')
    else:
        raise RuntimeError('bad close succeeded')

    source = Source(); client = Client(source); owner = Owner(False)
    life = make(source, client, owner)
    try:
        async with life:
            raise ValueError('original consumer error')
    except ValueError as error:
        require(str(error) == 'original consumer error' and owner.calls == 1,
                'consumer error was replaced')
        require(any('not confirmed' in note for note in getattr(error, '__notes__', [])),
                'abort failure detail missing')
        require(not life.abort_confirmed and not life.close_confirmed, 'failed abort was accepted')
        checks.append('abort_failure_preserves_primary')
    else:
        raise RuntimeError('consumer error swallowed')

    source = Source(); client = Client(source, stall=True); owner = Owner()
    life = make(source, client, owner)
    async def stalled():
        async with life:
            pass
    task = asyncio.create_task(stalled())
    while 'open_dataset' not in client.calls:
        await asyncio.sleep(0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        require(owner.calls == 1 and life.abort_confirmed, 'cancelled open not aborted')
        checks.append('cancel_open_aborts')
    else:
        raise RuntimeError('cancelled open succeeded')

    source = Source(); client = Client(source); owner = Owner()
    life = make(source, client, owner)
    try:
        async with life:
            raise asyncio.CancelledError('synthetic consumer cancellation')
    except asyncio.CancelledError:
        require(owner.calls == 1 and life.abort_confirmed and 'close_dataset' not in client.calls,
                'cancelled consumer sent close or failed to abort')
        checks.append('cancel_consumer_aborts_without_close')
    else:
        raise RuntimeError('consumer cancellation swallowed')
    source = Source(); client = Client(source, stall_close=True); owner = Owner()
    life = make(source, client, owner)
    async def stalled_close():
        async with life:
            pass
    task = asyncio.create_task(stalled_close())
    while 'close_dataset' not in client.calls:
        await asyncio.sleep(0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        require(owner.calls == 1 and life.abort_confirmed and not life.close_confirmed,
                'cancelled close not aborted or falsely confirmed')
        checks.append('cancel_close_aborts')
    else:
        raise RuntimeError('cancelled close unexpectedly succeeded')
    print(json.dumps({'status': 'passed', 'checks': checks,
                      'source_sha256': hashlib.sha256((ROOT / 'benchmarks/a2_dataset_lifecycle.py').read_bytes()).hexdigest(),
                      'scope': 'synthetic exclusive client and owner only; no actual process, snapshot or audit qualification'}))


if __name__ == '__main__':
    asyncio.run(main())
