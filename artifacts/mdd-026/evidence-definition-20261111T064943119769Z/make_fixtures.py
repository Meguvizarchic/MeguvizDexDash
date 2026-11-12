#!/usr/bin/env python3
"""Generate the synthetic fixtures used by the definition/header evidence.

The duplicate-content APK is the fixture that exercises exact-duplicate row
preservation: two archive members carry byte-identical DEX content, so every
content projection of the DEX relations contains byte-identical rows. The
generator writes only inside this evidence directory.
"""
from __future__ import annotations

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
    manifest = {
        "schema_version": "mdd.evidence-definition-fixtures.v1",
        "task": "MDD-026",
        "generated_utc": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(),
        "source_fixture": {
            "path": DEX.relative_to(ROOT).as_posix(),
            "sha256": DEX_SHA,
            "bytes": len(content),
        },
        "fixtures": [{
            "id": "duplicate-content.apk",
            "path": apk.relative_to(HERE).as_posix(),
            "bytes": apk.stat().st_size,
            "sha256": digest(apk.read_bytes()),
            "members": ["classes.dex", "classes2.dex"],
            "member_sha256": DEX_SHA,
            "purpose": "two byte-identical DEX members so content projections contain exact duplicate rows",
        }],
    }
    (HERE / "fixtures.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"apk": str(apk.relative_to(HERE)), "sha256": manifest["fixtures"][0]["sha256"]}))


if __name__ == "__main__":
    main()
