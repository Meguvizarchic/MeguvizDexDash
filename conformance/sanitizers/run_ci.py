"""Finite Linux-only ASan/libFuzzer smoke. No missing command/configuration is a skip."""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
TARGETS = ('archive', 'mutf8_leb', 'header_raw', 'header_repaired', 'code_payload', 'encoded_values')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write(path, obj):
    path.write_text(json.dumps(obj, indent=2) + '\n', encoding='utf-8', newline='\n')


def fetch(url):
    from pinned_fetch import fetch_following
    with fetch_following(url) as response:
        return response.read()


def verify_inputs():
    lock = json.loads((ROOT / 'conformance/sanitizers/toolchain-lock.json').read_text())
    if digest(fetch(lock['official_manifest_url'])) != lock['manifest_sha256']:
        raise RuntimeError('test toolchain manifest changed')
    for crate in lock['crates'].values():
        if digest(fetch(crate['download_url'])) != crate['checksum']:
            raise RuntimeError('dev tool crate checksum mismatch')
    manifest = json.loads((ROOT / 'conformance/sanitizers/corpus-manifest.json').read_text())
    expected = {target: set() for target in TARGETS}
    for seed in manifest['files']:
        path = ROOT / seed['path']
        data = path.read_bytes()
        if len(data) != seed['bytes'] or digest(data) != seed['sha256']:
            raise RuntimeError('seed bytes differ from manifest')
        if seed['source'].startswith('tests/fixtures/'):
            if digest((ROOT / seed['source']).read_bytes()) != seed['sha256']:
                raise RuntimeError('synthetic source changed; explicit corpus refresh required')
        expected[seed['target']].add(path.name)
    for target in TARGETS:
        actual = {p.name for p in (ROOT / 'fuzz/corpus' / target).iterdir()}
        if actual != expected[target]:
            raise RuntimeError(f'extra/missing seed files: {target}')
    return lock


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--seconds', type=int, default=15, choices=range(1, 61))
    args = parser.parse_args()
    lock = verify_inputs()
    if args.verify_only:
        print(json.dumps({'verified': True, 'nightly': lock['nightly'], 'target': lock['target']}))
        return
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise RuntimeError('this ASan profile requires x86_64 Linux, not a default skip')
    if not args.output:
        raise RuntimeError('--output is required')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, CARGO_BUILD_JOBS='2', ASAN_OPTIONS='detect_leaks=1:detect_stack_use_after_return=1')
    scratch = out / 'scratch'
    scratch.mkdir()
    env['TMPDIR'] = str(scratch)
    nightly, target = lock['nightly'], lock['target']
    summary = {'schema_version': 'mdd.parser-safety-ci.v1', 'started_utc': datetime.now(timezone.utc).isoformat(),
               'nightly': nightly, 'target': target, 'seconds_budget_per_target': args.seconds,
               'scope': '6 bounded targets; Rust ASan; no SQLite/FFI UBSan/TSan/full G1/026 qualification',
               'runs': [], 'status': 'running', 'private_inputs': False}

    def command(name, argv, *, extra_env=None, timeout=600, expected_asan_failure=False):
        directory = out / name
        directory.mkdir()
        before = time.monotonic()
        run_env = dict(env, **(extra_env or {}))
        with (directory / 'stdout.txt').open('wb') as stdout, (directory / 'stderr.txt').open('wb') as stderr:
            process = subprocess.Popen(argv, cwd=ROOT, env=run_env, stdout=stdout, stderr=stderr,
                                       start_new_session=True)
            timed_out = False
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                # Kill the owned command group only; record timeout as a failure.
                import signal
                os.killpg(process.pid, signal.SIGKILL)
                code = process.wait()
                timed_out = True
        output = (directory / 'stderr.txt').read_bytes()
        record = dict(command=argv, seconds=time.monotonic() - before, exit_code=code, timed_out=timed_out,
                      rustflags=run_env.get('RUSTFLAGS'), asan_options=run_env['ASAN_OPTIONS'],
                      stdout_sha256=digest((directory / 'stdout.txt').read_bytes()), stderr_sha256=digest(output))
        write(directory / 'record.json', record)
        summary['runs'].append(dict(name=name, **record))
        write(out / 'summary.json', summary)
        if timed_out:
            raise RuntimeError(f'{name}: hard timeout, never successful')
        if expected_asan_failure:
            if code == 0 or b'ERROR: AddressSanitizer: heap-buffer-overflow' not in output:
                raise RuntimeError('ASan positive control did not produce expected detection')
        elif code != 0:
            raise RuntimeError(f'{name}: nonzero status {code}')
        return output.decode(errors='replace')

    try:
        command('rustc-identity', ['rustc', f'+{nightly}', '-Vv'], timeout=60)
        if b'41089d07a' not in (out / 'rustc-identity/stdout.txt').read_bytes():
            raise RuntimeError('installed nightly compiler revision differs from lock')
        command('cargo-fuzz-identity', ['cargo', f'+{nightly}', 'fuzz', '--version'], timeout=60)
        if b'0.13.2' not in (out / 'cargo-fuzz-identity/stdout.txt').read_bytes():
            raise RuntimeError('installed cargo-fuzz version differs from lock')
        asan_env = {'RUSTFLAGS': '-Zsanitizer=address -Cdebuginfo=1 -Coverflow-checks=yes',
                    'CARGO_TARGET_DIR': str(ROOT / 'fuzz/target/asan')}
        base = ['cargo', f'+{nightly}']
        flags = ['--manifest-path', 'fuzz/Cargo.toml', '--locked', '-Zbuild-std', '--target', target]
        command('asan-detection-control', base + ['run'] + flags + ['--features', 'detection-control',
                '--bin', 'asan-detection-control'], extra_env=asan_env, expected_asan_failure=True)
        command('asan-oracle-tests', base + ['test'] + flags + ['--lib'], extra_env=asan_env)
        command('asan-mutation-smoke', base + ['run'] + flags + ['--bin', 'mutation-smoke', '--',
                'fuzz/corpus', '8'], extra_env=asan_env)
        real_cargo = shutil.which('cargo')
        if not real_cargo:
            raise RuntimeError('cargo executable absent')
        shim_dir = out / 'cargo-shim'
        shim_dir.mkdir()
        shim = shim_dir / 'cargo'
        shutil.copyfile(ROOT / 'conformance/sanitizers/cargo_locked.py', shim)
        shim.chmod(0o755)
        fuzz_env = {'PATH': str(shim_dir) + os.pathsep + env['PATH'], 'MDD_REAL_CARGO': real_cargo,
                    'MDD_CARGO_LOG': str(out / 'cargo-child-commands.jsonl'),
                    'RUSTUP_TOOLCHAIN': nightly, 'RUSTFLAGS': '-Coverflow-checks=yes'}
        lock_before = digest((ROOT / 'fuzz/Cargo.lock').read_bytes())
        for index, name in enumerate(TARGETS):
            runtime_corpus = out / 'corpus' / name
            shutil.copytree(ROOT / 'fuzz/corpus' / name, runtime_corpus)
            crash_dir = out / 'crashes' / name
            crash_dir.mkdir(parents=True)
            text = command('fuzz-' + name, [real_cargo, f'+{nightly}'] + ['fuzz', 'run', name, str(runtime_corpus),
                           '--fuzz-dir', 'fuzz', '--features', 'libfuzzer', '--sanitizer', 'address',
                           '--target', target, '--build-std', '--', f'-max_total_time={args.seconds}', '-timeout=3',
                           '-rss_limit_mb=1024', '-max_len=65536', f'-seed={617349 + index}',
                           '-print_final_stats=1', '-artifact_prefix=' + str(crash_dir) + '/'],
                           extra_env=fuzz_env, timeout=600)
            units = re.findall(r'stat::number_of_executed_units:\s*(\d+)', text)
            counters = re.findall(r'cov:\s*(\d+)\s+ft:\s*(\d+)', text)
            if not units or int(units[-1]) <= 0 or not counters:
                raise RuntimeError(f'{name}: missing actual libFuzzer execution/coverage counters')
            if list(crash_dir.iterdir()):
                raise RuntimeError(f'{name}: crash artifact is a failure')
            summary['runs'][-1].update(executions=int(units[-1]), coverage_counters=int(counters[-1][0]),
                                     initial_coverage_counters=int(counters[0][0]),
                                     features=int(counters[-1][1]), seed=617349 + index,
                                     crash_files=0, coverage_percent=None)
            write(out / 'summary.json', summary)
        if digest((ROOT / 'fuzz/Cargo.lock').read_bytes()) != lock_before:
            raise RuntimeError('cargo-fuzz changed independent lock; reject unreviewed resolution')
        summary['status'] = 'bounded-smoke-passed'
    except BaseException as error:
        summary['status'] = 'failed'
        summary['failure'] = str(error)
        raise
    finally:
        summary['finished_utc'] = datetime.now(timezone.utc).isoformat()
        write(out / 'summary.json', summary)


if __name__ == '__main__':
    main()
