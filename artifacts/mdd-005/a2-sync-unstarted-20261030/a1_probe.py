"""Real A1 transport and synthetic DEX; snapshot/order/inventory checks are mocked."""
import asyncio
import ctypes
from concurrent.futures import Future
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading

from mcp import Client
import win32api
import win32process

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_compact_adapter import CompactRowsAdapter
from a2_dataset_close import A1ExclusiveDatasetCloser
from a2_hostlab_session import HostlabCompactSession, HostlabSessionError
from a2_mcp_transport import McpPipeLimits, OwnedMcpTransport
from a2_windows_job_owner import JobLimits
from a2_windows_pipe_owner import PipeLimits, WindowsJobPipeOwner


class Memory(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint32), ('load', ctypes.c_uint32)] + [
        (name, ctypes.c_uint64) for name in ('total', 'available', 'page_total',
        'page_available', 'virtual_total', 'virtual_available', 'extended')]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    memory = Memory()
    memory.length = ctypes.sizeof(memory)
    require(ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)), 'memory read failed')
    print(json.dumps({'available_bytes': memory.available, 'minimum_bytes': 3 * 1024 ** 3,
                      'admitted': memory.available >= 3 * 1024 ** 3}), flush=True)
    require(memory.available >= 3 * 1024 ** 3, 'below original 3 GiB admission')
    engine = (ROOT / 'artifacts/local/baseline-engines/A1-0.1.1-windows/dexsql-windows-amd64.exe').resolve(strict=True)
    fixture = (ROOT / 'tests/fixtures/generated/structured-035.dex').resolve(strict=True)
    engine_sha = '602105c98232120c14d6124fb33574f2f95f12e50e51d25b8834f893925f28d6'
    fixture_sha = '108cf907d330b823c6e32d38eaab8f23709fe493f52537688bbd09ba3e271605'
    require(sha(engine) == engine_sha and sha(fixture) == fixture_sha, 'pinned identity changed')
    spec = importlib.util.spec_from_file_location('legacy_fixture',
        ROOT / 'artifacts/mdd-005/preparation-20261028/a2_compact_fixture_probe.py')
    legacy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(legacy)
    allowed, _ = win32process.GetProcessAffinityMask(win32api.GetCurrentProcess())
    job = JobLimits(memory_commit_bytes=512 * 1024 ** 2, affinity_mask=allowed & -allowed,
                    active_processes=8, lifetime_seconds=30, cleanup_seconds=5)
    pipe = PipeLimits(max_write_bytes=4096, max_input_bytes=1024 * 1024,
                      max_read_bytes=4096, max_output_bytes=4 * 1024 * 1024,
                      max_stderr_bytes=128 * 1024, io_seconds=5)
    limits = McpPipeLimits(max_frame_bytes=128 * 1024, max_input_bytes=4 * 1024 * 1024,
                           max_output_bytes=1024 * 1024, max_input_frames=128, max_output_frames=128)
    env = {k: v for k, v in os.environ.items() if k.upper() in
           {'SYSTEMROOT', 'WINDIR', 'PATH', 'TEMP', 'TMP', 'COMSPEC', 'PATHEXT'}}
    loop = asyncio.new_event_loop()
    ready = threading.Event()
    def run_loop():
        asyncio.set_event_loop(loop)
        loop.call_soon(ready.set)
        loop.run_forever()
    thread = threading.Thread(target=run_loop)
    thread.start()
    require(ready.wait(5), 'owner loop did not start')
    owner = None
    client = None
    transport = None
    shutdown_event = None
    setup_result = Future()
    sql = 'SELECT string_pool_id,string_idx,value FROM strings ORDER BY string_pool_id,string_idx'
    async def own_transport():
        nonlocal owner, client, transport, shutdown_event
        try:
            owner = await WindowsJobPipeOwner.launch(engine,
                ['--threads', '1', 'mcp', '--max-datasets', '1', '--timeout-ms', '5000'],
                cwd=ROOT, env=env, expected_sha256=engine_sha, job_limits=job, pipe_limits=pipe)
            transport = OwnedMcpTransport(owner, limits)
            async with Client(transport, mode='legacy') as entered_client:
                client = entered_client
                opened = await client.call_tool('open_dataset', {'inputs': [str(fixture)]})
                require(opened.is_error is False and isinstance(opened.structured_content, dict), 'open failed')
                dataset = opened.structured_content.get('dataset_id')
                require(isinstance(dataset, str) and dataset, 'dataset id missing')
                standard = await legacy.consume(client, dataset, sql, False)
                shutdown_event = asyncio.Event()
                setup_result.set_result((dataset, [dict(zip(standard['columns'], row)) for row in standard['rows']]))
                await shutdown_event.wait()
                transport.expect_session_shutdown()
        except BaseException as error:
            if not setup_result.done():
                setup_result.set_exception(error)
            raise
        finally:
            if owner is not None:
                await owner.close()
    def wait(coro):
        return asyncio.run_coroutine_threadsafe(coro, loop).result(timeout=25)
    owner_task = asyncio.run_coroutine_threadsafe(own_transport(), loop)
    try:
        dataset, expected = setup_result.result(timeout=25)
        def verify_source():
            require(sha(fixture) == fixture_sha, 'fixture changed')
        adapter = CompactRowsAdapter(client, dataset, verify_source=verify_source,
            verify_snapshot_binding=lambda dataset: None, verify_ordering=lambda source, projected: None,
            continuation_reason=lambda sql: None, timeout=20)
        closer = A1ExclusiveDatasetCloser(client, dataset, remaining_seconds=lambda: adapter.remaining_seconds())
        async def close_dataset():
            return await closer.close()
        def abort_transport():
            wait(owner.close())
            return owner.tree_empty_verified
        session = HostlabCompactSession(fixture, adapter, loop,
            verify_inventory=lambda source, files: None, close_dataset=close_dataset,
            abort_transport=abort_transport)
        try:
            with session:
                actual = list(session.rows(sql, page_size=2))
                require(actual == expected and len(actual) == 7, 'full DTO differs')
                pending = session.rows(sql, page_size=2)
        except HostlabSessionError as error:
            require('unconsumed' in str(error), 'unexpected session failure')
        else:
            raise RuntimeError('unstarted iterator did not block session completion')
        try:
            next(pending)
        except HostlabSessionError:
            pass
        else:
            raise RuntimeError('closed session dispatched a pending query')
        require(session.queries == 2 and len(session.deliveries) == 2, 'receipt count differs')
        loop.call_soon_threadsafe(shutdown_event.set)
        owner_task.result(timeout=25)
        require(owner.tree_empty_verified and transport.failure is None, 'owner shutdown incomplete')
        require(sha(engine) == engine_sha and sha(fixture) == fixture_sha, 'identity changed')
        print(json.dumps({'status': 'passed', 'rows': len(expected), 'query_receipts': session.queries,
            'engine_sha256': engine_sha, 'fixture_sha256': fixture_sha,
            'scope': 'fixed A1 synthetic DEX; snapshot/order/inventory mocked; no A2 qualification'}))
    finally:
        if not owner_task.done():
            if shutdown_event is not None:
                loop.call_soon_threadsafe(shutdown_event.set)
            else:
                owner_task.cancel()
            owner_task.result(timeout=25)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)
        require(not thread.is_alive(), 'owner loop did not stop')
        loop.close()


if __name__ == '__main__':
    main()
