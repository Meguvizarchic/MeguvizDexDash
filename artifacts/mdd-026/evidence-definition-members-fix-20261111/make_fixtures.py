#!/usr/bin/env python3
"""Generate the synthetic fixtures used by this evidence directory.

The duplicate-content APK carries two byte-identical DEX members so content
projections contain exact duplicate rows.  The two-interfaces DEX is a valid
fixture with one class implementing two distinct interfaces, which exercises
class_interfaces.ordinal 0/1 (the project's duplicate-interface.dex is an
error-case fixture and is rejected by the engine, so it cannot serve as a
positive case).

Everything is written inside this evidence directory.
"""
from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
EVIDENCE = HERE / "evidence"
DEX = ROOT / "tests/fixtures/definitions/generated/definitions-035.dex"
DEX_SHA = "4e8f9e8deedf44c8793e10d99f2614e0bed705dcac617c0d74137e7b2bd459cc"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    content = DEX.read_bytes()
    if digest(content) != DEX_SHA:
        raise SystemExit("source fixture identity mismatch")
    apk = EVIDENCE / "duplicate-content.apk"
    with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as archive:
        for entry in ("classes.dex", "classes2.dex"):
            info = zipfile.ZipInfo(entry, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, content)
    two = HERE / "fixtures/generated/two-interfaces.dex"
    if not two.is_file():
        raise SystemExit("run generate_two_interfaces.py first")
    manifest = {
        "schema_version": "mdd.evidence-definition-members-fix-fixtures.v1",
        "task": "MDD-026",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_fixture": {
            "path": DEX.relative_to(ROOT).as_posix(),
            "sha256": DEX_SHA,
            "bytes": len(content),
        },
        "fixtures": [
            {
                "id": "duplicate-content.apk",
                "path": apk.relative_to(HERE).as_posix(),
                "bytes": apk.stat().st_size,
                "sha256": digest(apk.read_bytes()),
                "members": ["classes.dex", "classes2.dex"],
                "member_sha256": DEX_SHA,
                "purpose": "two byte-identical DEX members so content projections contain exact duplicate rows",
            },
            {
                "id": "two-interfaces.dex",
                "path": two.relative_to(HERE).as_posix(),
                "bytes": two.stat().st_size,
                "sha256": digest(two.read_bytes()),
                "purpose": "valid DEX; class Lfixture/Base; implements Lfixture/I0; and Lfixture/I1; (ordinal 0/1)",
            },
        ],
    }
    (HERE / "fixtures.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"apk": manifest["fixtures"][0]["sha256"],
                      "two_interfaces": manifest["fixtures"][1]["sha256"]}))


if __name__ == "__main__":
    main()
