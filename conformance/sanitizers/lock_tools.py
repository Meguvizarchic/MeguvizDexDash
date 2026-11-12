"""Acquire real official test-tool identities. Explicit refresh, never called by CI."""
from pathlib import Path
import hashlib
import json
import tomllib

from pinned_fetch import fetch_following

ROOT = Path(__file__).resolve().parents[2]


def get(url):
    with fetch_following(url) as response:
        return response.read()


def main():
    current = tomllib.loads(get('https://static.rust-lang.org/dist/channel-rust-nightly.toml').decode())
    date = current['date']
    url = f'https://static.rust-lang.org/dist/{date}/channel-rust-nightly.toml'
    raw = get(url)
    manifest = tomllib.loads(raw.decode())
    host = 'x86_64-unknown-linux-gnu'
    packages = {}
    for name in ('rustc', 'cargo', 'rust-std', 'rust-src'):
        package = manifest['pkg'][name]
        target = package['target']['*' if name == 'rust-src' else host]
        if not target['available']:
            raise RuntimeError(f'required nightly package unavailable: {name}')
        # Probe actual downloadable component existence, without downloading the toolchain locally.
        with fetch_following(target['xz_url'], method='HEAD') as r:
            if r.status != 200:
                raise RuntimeError('component not downloadable')
        packages[name] = dict(version=package['version'], url=target['xz_url'],
                              sha256=target['xz_hash'], available=True)
    crates = {}
    for name, version, repo in (
        ('libfuzzer-sys', '0.4.13', 'https://github.com/rust-fuzz/libfuzzer'),
        ('cargo-fuzz', '0.13.2', 'https://github.com/rust-fuzz/cargo-fuzz/'),
    ):
        value = json.loads(get(f'https://crates.io/api/v1/crates/{name}/{version}'))['version']
        if value['yanked'] or value['crate'] != name or value['repository'] != repo:
            raise RuntimeError('unexpected dev tool source identity')
        crates[name] = dict(version=version, checksum=value['checksum'], repository=repo,
                            download_url=f'https://crates.io/api/v1/crates/{name}/{version}/download')
    result = dict(schema_version='mdd.parser-test-toolchain.v1', test_only=True,
                  release_toolchain='1.99.0', nightly=f'nightly-{date}', target=host,
                  official_manifest_url=url, manifest_sha256=hashlib.sha256(raw).hexdigest(),
                  packages=packages, crates=crates)
    (ROOT / 'conformance/sanitizers/toolchain-lock.json').write_text(
        json.dumps(result, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({'nightly': result['nightly'], 'target': host, 'all_components_http_200': True}))


if __name__ == '__main__':
    main()
