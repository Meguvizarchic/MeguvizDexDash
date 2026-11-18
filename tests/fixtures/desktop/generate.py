#!/usr/bin/env python3
"""Writes the three tiny DEX files the desktop workbench's comparison tests read, byte for byte.

    a.dex  Ldemo/A;  same, ops ("alpha"), body (const-string + return-void), gone
    b.dex  Ldemo/A;  same, ops ("beta": same opcodes, different operand), body (return-void only), added
    c.dex  Ldemo/C;  only

and, for the browsing flows:

    ab1.dex  Ldemo/A;->foo()V calls Ldemo/B;->bar()V         (tiny_dex.foo_a)
    ab2.dex  Ldemo/B;->bar()V calls Ldemo/A;->foo()V         (tiny_dex.bar_b), so the two call each other across DEX files
    long.dex Ldemo/L;->long()V: 500 const-string instructions, so its smali needs more than one page

So A against B (b.dex with c.dex) has one method that is only in A, two only in B, one with equal opcodes and an
equal operand, one with equal opcodes and a different operand, one with different opcodes, and one class only in B.
The DEX writer is conformance/mcp/tiny_dex.py; nothing here imports the engine under test.

    python tests/fixtures/desktop/generate.py          write the files
    python tests/fixtures/desktop/generate.py --check  fail if the files on disk differ from what would be written
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "conformance" / "mcp"))
from tiny_dex import bar_b, build, foo_a  # noqa: E402


def method(name: str, *code: tuple) -> dict:
    return {"name": name, "access": 0x9, "registers": 1, "outs": 0, "code": list(code)}


def files() -> dict[str, bytes]:
    return {
        "a.dex": build("Ldemo/A;", [
            method("same", ("const-string", 0, "x"), ("return-void",)),
            method("ops", ("const-string", 0, "alpha"), ("return-void",)),
            method("body", ("const-string", 0, "x"), ("return-void",)),
            method("gone", ("return-void",)),
        ]),
        "b.dex": build("Ldemo/A;", [
            method("same", ("const-string", 0, "x"), ("return-void",)),
            method("ops", ("const-string", 0, "beta"), ("return-void",)),
            method("body", ("return-void",)),
            method("added", ("return-void",)),
        ]),
        "c.dex": build("Ldemo/C;", [method("only", ("return-void",))]),
        "ab1.dex": foo_a(),
        "ab2.dex": bar_b(),
        "long.dex": build("Ldemo/L;", [method("long", *([("const-string", 0, "needle")] * 500), ("return-void",))]),
    }


def main() -> int:
    out = HERE / "generated"
    expected = files()
    if "--check" in sys.argv:
        bad = [name for name, data in expected.items() if not (out / name).is_file() or (out / name).read_bytes() != data]
        if bad:
            print("differ from the generator:", ", ".join(bad))
            return 1
        print("fixtures equal the generator's output")
        return 0
    out.mkdir(exist_ok=True)
    for name, data in expected.items():
        (out / name).write_bytes(data)
    manifest = {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in expected.items()}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("wrote", ", ".join(expected))
    return 0


if __name__ == "__main__":
    sys.exit(main())
