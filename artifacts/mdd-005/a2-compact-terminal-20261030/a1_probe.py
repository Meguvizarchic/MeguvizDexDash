"""Fixed A1 with a tiny synthetic DEX; callback claims are mocked, not qualification."""
import asyncio
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

from mcp import Client
import win32api
import win32process

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_compact_adapter import CompactRowsAdapter
from a2_dataset_close import A1ExclusiveDatasetCloser
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


async def main():
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
    require(sha(engine) == engine_sha and sha(fixture) == fixture_sha, 'pinned inputs changed')
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
    owned = await WindowsJobPipeOwner.launch(engine,
        ['--threads', '1', 'mcp', '--max-datasets', '1', '--timeout-ms', '5000'],
        cwd=ROOT, env=env, expected_sha256=engine_sha, job_limits=job, pipe_limits=pipe)
    transport = OwnedMcpTransport(owned, limits)
    try:
        async with asyncio.timeout(25), Client(transport, mode='legacy') as client:
            opened = await client.call_tool('open_dataset', {'inputs': [str(fixture)]})
            require(opened.is_error is False and isinstance(opened.structured_content, dict), 'open failed')
            dataset = opened.structured_content.get('dataset_id')
            require(isinstance(dataset, str) and dataset, 'dataset id missing')
            sql = 'SELECT string_pool_id,string_idx,value FROM strings ORDER BY string_pool_id,string_idx'
            original = await legacy.consume(client, dataset, sql, False)
            def verify_source():
                require(sha(fixture) == fixture_sha, 'fixture changed')
            # Explicitly mocked binding/order checks: A1 does not prove generation here.
            adapter = CompactRowsAdapter(client, dataset, verify_source=verify_source,
                verify_snapshot_binding=lambda dataset: None, verify_ordering=lambda source, projected: None,
                continuation_reason=lambda sql: None, timeout=20)
            result = await adapter.result(sql, page_size=2)
            expected = [dict(zip(original['columns'], row)) for row in original['rows']]
            require(result.rows == expected and result.total_rows == len(expected), 'DTO differs')
            closer = A1ExclusiveDatasetCloser(client, dataset, remaining_seconds=lambda: 10)
            require(await closer.close() is True, 'close not confirmed')
            transport.expect_session_shutdown()
        require(transport.failure is None and owned.tree_empty_verified, 'transport or job incomplete')
        require(sha(engine) == engine_sha and sha(fixture) == fixture_sha, 'identity changed')
        print(json.dumps({'status': 'passed', 'rows': result.total_rows, 'pages': result.page_count,
            'engine_sha256': engine_sha, 'fixture_sha256': fixture_sha,
            'scope': 'fixed A1 and synthetic DEX, mocked generation/order checks; no A2 qualification'}))
    finally:
        await owned.close()


if __name__ == '__main__':
    asyncio.run(main())
