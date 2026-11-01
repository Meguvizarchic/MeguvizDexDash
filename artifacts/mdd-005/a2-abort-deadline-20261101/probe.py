"""Synthetic owner-cleanup deadline regression, not A2 qualification."""
import asyncio
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_dataset_lifecycle import A1DatasetLifecycle, DatasetLifecycleError


class Client:
    async def call_tool(self, *_):
        raise RuntimeError('not used')


class Source:
    path = ROOT / 'synthetic.dex'

    def verify_source(self):
        pass


async def main():
    async def slow_abort():
        # Model a blocking callback that prevents asyncio's timer from firing.
        time.sleep(0.15)
        return True

    life = A1DatasetLifecycle(Client(), Source(), remaining_seconds=lambda: 5,
                              abort_owned_transport=slow_abort, abort_seconds=0.02)
    try:
        await life._abort()
    except (TimeoutError, DatasetLifecycleError):
        if life.abort_confirmed:
            raise RuntimeError('expired abort marked confirmed')
        print('PASS: expired blocking abort is not confirmed')
    else:
        raise RuntimeError('expired blocking abort was accepted')

    cleanup_ran = []

    def slow_factory():
        time.sleep(0.15)

        async def cleanup():
            cleanup_ran.append(True)
            return True

        return cleanup()

    life = A1DatasetLifecycle(Client(), Source(), remaining_seconds=lambda: 5,
                              abort_owned_transport=slow_factory, abort_seconds=0.02)
    try:
        await life._abort()
    except (TimeoutError, DatasetLifecycleError):
        if not cleanup_ran or life.abort_confirmed:
            raise RuntimeError('late factory cleanup was skipped or marked confirmed')
        print('PASS: late factory cleanup runs without confirming success')
    else:
        raise RuntimeError('expired factory was accepted')

    async def quick_abort():
        return True

    life = A1DatasetLifecycle(Client(), Source(), remaining_seconds=lambda: 5,
                              abort_owned_transport=quick_abort, abort_seconds=1)
    await life._abort()
    if not life.abort_confirmed:
        raise RuntimeError('timely confirmed abort was not recorded')
    print('PASS: timely abort is confirmed')


if __name__ == '__main__':
    asyncio.run(main())
