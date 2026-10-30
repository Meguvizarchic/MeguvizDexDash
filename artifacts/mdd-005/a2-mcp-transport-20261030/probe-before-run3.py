"""Local fixed-SDK and synthetic-protocol checks; not HostLab/A2 qualification."""
import asyncio
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import mcp_types as types
from mcp import Client
from mcp.shared.message import SessionMessage
import win32api
import win32process

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'benchmarks'))
from a2_windows_job_owner import JobLimits
from a2_windows_pipe_owner import PipeLimits, WindowsJobPipeOwner
from a2_mcp_transport import McpPipeError, McpPipeLimits, OwnedMcpTransport
from a2_dataset_close import A1ExclusiveDatasetCloser


class Memory(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint32), ('load', ctypes.c_uint32)] + [
        (name, ctypes.c_uint64) for name in ('total', 'available', 'page_total',
        'page_available', 'virtual_total', 'virtual_available', 'extended')]


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def admission():
    memory = Memory(); memory.length = ctypes.sizeof(memory)
    require(ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)), 'memory observation failed')
    minimum = 3 * 1024 ** 3
    return {'available_bytes': str(memory.available), 'minimum_bytes': str(minimum),
            'admitted': memory.available >= minimum}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def main():
    admissions = []
    def admit():
        item = admission(); admissions.append(item)
        (HERE / 'admission-run3.json').write_text(json.dumps(admissions, indent=2) + '\n', encoding='utf8')
        require(item['admitted'], 'below original 3 GiB admission before owned child')
    admit()
    allowed, _ = win32process.GetProcessAffinityMask(win32api.GetCurrentProcess())
    job = JobLimits(memory_commit_bytes=512 * 1024 ** 2, affinity_mask=allowed & -allowed,
                    active_processes=8, lifetime_seconds=30, cleanup_seconds=5)
    pipe = PipeLimits(max_write_bytes=4096, max_input_bytes=1024 * 1024,
                      max_read_bytes=4096, max_output_bytes=4 * 1024 * 1024,
                      max_stderr_bytes=128 * 1024, io_seconds=5)
    limits = McpPipeLimits(max_frame_bytes=128 * 1024, max_input_bytes=4 * 1024 * 1024,
                           max_output_bytes=1024 * 1024, max_input_frames=128,
                           max_output_frames=128)
    env = {k: v for k, v in os.environ.items() if k.upper() in
           {'SYSTEMROOT', 'WINDIR', 'PATH', 'TEMP', 'TMP', 'COMSPEC', 'PATHEXT'}}
    python = Path(sys.executable).resolve(strict=True)
    python_sha = sha(python)
    checks = []

    async def launch(executable, args, digest):
        admit()
        return await WindowsJobPipeOwner.launch(executable, args, cwd=ROOT, env=env,
            expected_sha256=digest, job_limits=job, pipe_limits=pipe)

    # A valid first frame followed by a malformed frame must leave a failure,
    # not a successful stream with an ignored partial prefix.
    scripts = {
        'malformed_after_valid': 'import sys,time;sys.stdout.buffer.write(b"{\\"jsonrpc\\":\\"2.0\\",\\"method\\":\\"notice\\"}\\nnot-json\\n");sys.stdout.buffer.flush();time.sleep(2)',
        'invalid_utf8': 'import sys,time;sys.stdout.buffer.write(b"{\\"jsonrpc\\":\\"2.0\\",\\"id\\":1,\\"result\\":\\"\\xff\\"}\\n");sys.stdout.buffer.flush();time.sleep(2)',
        'duplicate_member': 'import sys,time;sys.stdout.buffer.write(b"{\\"jsonrpc\\":\\"2.0\\",\\"jsonrpc\\":\\"2.0\\",\\"method\\":\\"x\\"}\\n");sys.stdout.buffer.flush();time.sleep(2)',
        'truncated_eof': 'import sys;sys.stdout.buffer.write(b"{\\"jsonrpc\\":\\"2.0\\",\\"id\\":1");sys.stdout.buffer.flush()',
        'oversized_frame': 'import sys,time;sys.stdout.buffer.write(b" "*65);sys.stdout.buffer.flush();time.sleep(2)',
    }
    small = McpPipeLimits(max_frame_bytes=64, max_input_bytes=1024, max_output_bytes=1024,
                          max_input_frames=4, max_output_frames=4,
                          read_chunk_bytes=32, write_chunk_bytes=32)
    for name, script in scripts.items():
        owned = await launch(python, ['-B', '-c', script], python_sha)
        transport = OwnedMcpTransport(owned, small)
        try:
            try:
                async with transport as (reader, _writer):
                    if name == 'malformed_after_valid':
                        first = await reader.receive()
                        require(isinstance(first, SessionMessage), 'valid prefix was not decoded')
                    failure = await reader.receive()
                    require(isinstance(failure, Exception), 'invalid frame was not an explicit error')
                    require(transport.failure is failure, 'transport did not retain original failure')
                raise RuntimeError('failed stream context returned success')
            except McpPipeError as error:
                require(transport.failure is not None, 'transport failure was lost')
                require(error.__cause__ is transport.failure, 'original failure cause was lost')
            require(owned.tree_empty_verified, 'failed stream owned Job not empty')
            checks.append(name)
        finally:
            await owned.close()

    # Outbound over-budget messages must fail before a partial frame is sent.
    owned = await launch(python, ['-B', '-c', 'import time;time.sleep(10)'], python_sha)
    transport = OwnedMcpTransport(owned, small)
    try:
        try:
            async with transport as (_reader, writer):
                message = types.jsonrpc_message_adapter.validate_json(
                    json.dumps({'jsonrpc':'2.0','method':'notice','params':{'data':'x'*200}}), by_name=False)
                await writer.send(SessionMessage(message))
            raise RuntimeError('oversized outbound frame returned success')
        except McpPipeError:
            require(transport.failure is not None, 'outbound failure was lost')
        require(owned.tree_empty_verified, 'outbound quota owned Job not empty')
        checks.append('outbound_frame_quota')
    finally:
        await owned.close()

    # A cancellation while a partial inbound frame exists poisons the stream
    # and preserves cancellation instead of yielding a successful prefix.
    owned = await launch(python, ['-B', '-c',
        'import sys,time;sys.stdout.buffer.write(b"{\\"jsonrpc\\":\\"2.0\\",");sys.stdout.buffer.flush();time.sleep(10)'], python_sha)
    transport = OwnedMcpTransport(owned, small)
    try:
        try:
            async with transport as (reader, _writer):
                pending = asyncio.create_task(reader.receive())
                deadline = time.monotonic() + 2
                while not reader._buffer and time.monotonic() < deadline:
                    await asyncio.sleep(.01)
                require(bool(reader._buffer), 'partial inbound frame was not observed')
                pending.cancel()
                try:
                    await pending
                    raise RuntimeError('partial read cancellation was swallowed')
                except asyncio.CancelledError as error:
                    require(transport.failure is error, 'read cancellation was not retained')
            raise RuntimeError('partial read context returned success')
        except McpPipeError as error:
            require(isinstance(error.__cause__, asyncio.CancelledError), 'read cancellation cause lost')
        require(owned.tree_empty_verified, 'partial read cancellation Job not empty')
        checks.append('partial_read_cancellation')
    finally:
        await owned.close()

    # Block the second chunk only after the first has really been submitted.
    owned = await launch(python, ['-B', '-c', 'import sys;sys.stdin.buffer.read()'], python_sha)
    transport = OwnedMcpTransport(owned, small)
    try:
        try:
            async with transport as (_reader, writer):
                original_write = owned.write
                second_chunk = asyncio.Event()
                gate = asyncio.Event()
                calls = 0
                async def gated_write(data):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        second_chunk.set()
                        await gate.wait()
                    return await original_write(data)
                owned.write = gated_write
                message = types.jsonrpc_message_adapter.validate_json(
                    json.dumps({'jsonrpc':'2.0','method':'abcdefghijklmnopqrst'}), by_name=False)
                pending = asyncio.create_task(writer.send(SessionMessage(message)))
                await asyncio.wait_for(second_chunk.wait(), timeout=2)
                require(calls == 2 and owned._input_bytes > 0, 'first output chunk was not submitted')
                pending.cancel()
                try:
                    await pending
                    raise RuntimeError('partial write cancellation was swallowed')
                except asyncio.CancelledError as error:
                    require(transport.failure is error, 'write cancellation was not retained')
            raise RuntimeError('partial write context returned success')
        except McpPipeError as error:
            require(isinstance(error.__cause__, asyncio.CancelledError), 'write cancellation cause lost')
        require(owned.tree_empty_verified, 'partial write cancellation Job not empty')
        checks.append('partial_write_cancellation')
    finally:
        await owned.close()

    # Use the real pinned A1 and pinned SDK, but only a tiny public fixture.
    engine = (ROOT / 'artifacts/local/baseline-engines/A1-0.1.1-windows/dexsql-windows-amd64.exe').resolve(strict=True)
    fixture = (ROOT / 'tests/fixtures/generated/structured-035.dex').resolve(strict=True)
    engine_sha = '602105c98232120c14d6124fb33574f2f95f12e50e51d25b8834f893925f28d6'
    fixture_sha = '108cf907d330b823c6e32d38eaab8f23709fe493f52537688bbd09ba3e271605'
    require(sha(engine) == engine_sha and sha(fixture) == fixture_sha, 'pinned A1 or fixture changed')
    owned = await launch(engine, ['--threads', '1', 'mcp', '--max-datasets', '1', '--timeout-ms', '5000'], engine_sha)
    transport = OwnedMcpTransport(owned, limits)
    try:
        async with asyncio.timeout(25), Client(transport, mode='legacy') as client:
            opened = await client.call_tool('open_dataset', {'inputs':[str(fixture)]})
            require(not opened.is_error and isinstance(opened.structured_content, dict), 'A1 open failed')
            dataset = opened.structured_content.get('dataset_id')
            require(isinstance(dataset, str) and dataset, 'A1 dataset identity missing')
            result = await client.call_tool('query', {'dataset_id':dataset,
                'sql':['SELECT COUNT(*) AS n FROM strings'], 'limit':1, 'offset':0,
                'compact':True, 'max_bytes':131072, 'timeout_ms':5000})
            require(not result.is_error and isinstance(result.structured_content, dict), 'A1 query failed')
            statements = result.structured_content.get('statements')
            require(isinstance(statements, list) and len(statements) == 1, 'A1 statement missing')
            statement = statements[0]
            require(statement.get('kind') == 'query' and statement.get('total_rows') == 1
                    and statement.get('next_offset') is None and statement.get('truncated') is False
                    and len(statement.get('rows', [])) == 1, 'A1 result not complete')
            close_deadline = time.monotonic() + 10
            closer = A1ExclusiveDatasetCloser(client, dataset,
                                               remaining_seconds=lambda: close_deadline - time.monotonic())
            require(await closer.close() is True, 'A1 close not confirmed')
            transport.expect_session_shutdown()
        print(json.dumps({'a1_transport_failure': repr(transport.failure),
                          'a1_owner_failure': repr(owned._failure),
                          'a1_owner_notes': getattr(owned._failure, '__notes__', []),
                          'a1_owner_state': owned._state,
                          'a1_tree_empty': owned.tree_empty_verified}), flush=True)
        require(transport.failure is None and owned.tree_empty_verified, 'A1 transport or Job incomplete')
        require(sha(engine) == engine_sha and sha(fixture) == fixture_sha, 'A1 input identity changed')
        checks.append('fixed_a1_sdk_open_query_close')
    finally:
        await owned.close()
    print(json.dumps({'status':'passed','checks':checks,'a1_sha256':engine_sha,
                      'fixture_sha256':fixture_sha,'scope':'bounded synthetic protocol and A1 fixture; no full audit, snapshot or A2 qualification'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))
