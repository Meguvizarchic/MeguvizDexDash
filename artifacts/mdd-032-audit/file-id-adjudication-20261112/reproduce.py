#!/usr/bin/env python3
"""Adjudicate how the frozen A0 backend (dexsql 0.1.0) numbers DEX members.

Usage: python -I reproduce.py A0_EXE DEX_FIXTURE OUTPUT_JSON [BILIBILI_APK]

Synthetic archives are written to a fresh temporary directory (never into the
repository). Every observation is the raw table returned by A0; nothing is
derived from the project's own implementation.
"""
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

CASES = {
    "zip-lex": ["classes.dex", "classes10.dex", "classes2.dex", "classes3.dex"],
    "zip-numeric": ["classes.dex", "classes2.dex", "classes3.dex", "classes10.dex"],
    "zip-reverse": ["classes3.dex", "classes2.dex", "classes.dex"],
    "zip-twelve": ["classes7.dex", "classes.dex", "classes12.dex", "classes3.dex",
                   "classes10.dex", "classes2.dex", "classes9.dex", "classes11.dex",
                   "classes4.dex", "classes8.dex", "classes5.dex", "classes6.dex"],
}
SQL = "SELECT file_id,string_pool_id,entry_name FROM dex_files ORDER BY file_id"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def query(exe, apk, sql):
    done = subprocess.run([str(exe), "query", "--input", str(apk), "--sql", sql],
                          capture_output=True, text=True, check=False, timeout=600)
    if done.returncode != 0:
        raise RuntimeError(f"A0 failed ({done.returncode}): {done.stderr[:400]}")
    return done.stdout


def parse(table):
    rows = []
    for line in table.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.startswith("|") and cells and cells[0].isdigit():
            rows.append(cells)
    return rows


def main():
    if len(sys.argv) not in (4, 5):
        raise SystemExit(__doc__)
    exe, dex, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    payload = dex.read_bytes()
    report = {"a0_sha256": sha256(exe), "dex_fixture": dex.as_posix(),
              "dex_fixture_sha256": sha256(dex), "sql": SQL, "synthetic": {}}
    with tempfile.TemporaryDirectory(prefix="mdd-fileid-") as tmp:
        for name, members in CASES.items():
            apk = Path(tmp) / f"{name}.apk"
            with zipfile.ZipFile(apk, "w", zipfile.ZIP_STORED) as archive:
                for member in members:
                    archive.writestr(member, payload)
            rows = parse(query(exe, apk, SQL))
            report["synthetic"][name] = {
                "zip_order": members,
                "a0_file_id_to_entry": [[int(r[0]), r[2]] for r in rows],
                "a0_order_equals_zip_order": [r[2] for r in rows] == members,
            }
    if len(sys.argv) == 5:
        apk = Path(sys.argv[4])
        rows = parse(query(exe, apk, SQL + " LIMIT 8"))
        counts = parse(query(exe, apk, "SELECT file_id,count(*) AS n FROM classes "
                                       "WHERE file_id IN (0,1,4) GROUP BY file_id ORDER BY file_id"))
        report["real_apk"] = {"sha256": sha256(apk),
                              "first_eight_file_id_to_entry": [[int(r[0]), r[2]] for r in rows],
                              "class_count_by_file_id": {r[0]: int(r[1]) for r in counts}}
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    ok = all(v["a0_order_equals_zip_order"] for v in report["synthetic"].values())
    print("A0 numbers DEX members in archive enumeration order:", ok)
    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
