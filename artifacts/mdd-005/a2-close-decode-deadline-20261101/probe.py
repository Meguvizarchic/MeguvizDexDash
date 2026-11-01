"""Controlled lifecycle deadline regression; no A2 qualification implied."""
import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
import a2_dataset_close as closing


class Client:
    async def call_tool(self, name, arguments):
        if name == 'close_dataset':
            value = {'closed': True, 'dataset_id': 'fixture'}
        else:
            value = {'datasets': [], 'admitted_requests': 0, 'running_requests': 0,
                     'usage': {'datasets': 0, 'input_bytes': 0}}
        return SimpleNamespace(is_error=False, structured_content=value, content=[])


async def main():
    remaining = [10.0]
    original = closing._payload

    def decode(response, stage):
        value = original(response, stage)
        if stage == 'list_datasets':
            remaining[0] = 0.0
        return value

    closer = closing.A1ExclusiveDatasetCloser(Client(), 'fixture',
                                               remaining_seconds=lambda: remaining[0])
    with patch.object(closing, '_payload', decode):
        try:
            await closer.close()
        except closing.DatasetCloseError as error:
            if error.stage != 'list_datasets':
                raise RuntimeError('wrong failure stage') from error
            print('PASS: expired during final decode is rejected')
        else:
            raise RuntimeError('expired during final decode was reported successful')
    checks = [0]

    def during_final_check():
        checks[0] += 1
        return 0 if checks[0] >= 7 else 10

    closer = closing.A1ExclusiveDatasetCloser(Client(), 'fixture',
                                               remaining_seconds=during_final_check)
    try:
        await closer.close()
    except closing.DatasetCloseError as error:
        if error.stage != 'list_datasets':
            raise RuntimeError('wrong final-check failure stage') from error
        print('PASS: final idle verification deadline is checked')
    else:
        raise RuntimeError('expired during idle verification was reported successful')
    closer = closing.A1ExclusiveDatasetCloser(Client(), 'fixture', remaining_seconds=lambda: 10)
    if await closer.close() is not True:
        raise RuntimeError('valid close was not confirmed')
    print('PASS: valid close still succeeds')


if __name__ == '__main__':
    asyncio.run(main())
