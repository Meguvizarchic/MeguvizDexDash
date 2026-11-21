#!/usr/bin/env python3
"""Reconstruct and verify the immutable original handoff from Git blobs."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASE = '3bbf1088137e70c5d3d722534a5eeab8b69a596c'


def blob(path):
    return subprocess.run(['git', '-c', 'safe.directory='+str(ROOT), 'show',
                           BASE+':'+path], cwd=ROOT, check=True, capture_output=True).stdout


def main():
    manifest_bytes = blob('PACKAGE_MANIFEST.json')
    manifest = json.loads(manifest_bytes)
    staging = ROOT / 'handoff'
    staging.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='verified-', dir=staging) as tmp_dir:
        destination = Path(tmp_dir).resolve()
        if not destination.is_relative_to(staging.resolve()):
            raise ValueError('unexpected handoff reconstruction destination')
        for item in manifest['files']:
            path = (destination/item['path']).resolve()
            if not path.is_relative_to(destination):
                raise ValueError('handoff path escapes reconstruction')
            data = blob(item['path'])
            if len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
                raise ValueError('original Git blob identity differs: '+item['path'])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (destination/'PACKAGE_MANIFEST.json').write_bytes(manifest_bytes)
        subprocess.run([sys.executable, str(destination/'tools/verify_kit.py'),
                        '--require-schema'], cwd=destination, check=True)
        subprocess.run([sys.executable, str(destination/'tools/recompute_targets.py')],
                       cwd=destination, check=True)
    print('Immutable Git handoff verified; this is not an engine test.')


if __name__ == '__main__':
    main()
