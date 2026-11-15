"""Independent synthetic DEX whose strings tell UTF-16 order from UTF-8 order apart.

'Lfixture/<U+E000>;' and 'Lfixture/<U+1F600>;' differ only in one scalar. By UTF-16
code units the supplementary string sorts first (0xD83D < 0xE000); by UTF-8 bytes
it sorts last (0xF0 > 0xEE). A text ORDER BY that compares bytes instead of code
units therefore reorders them, which is what the cross-path query test must catch.

The DEX is built with the independent writer in tests/fixtures/references/generate.py,
which sorts the string pool by UTF-16 code units as the format requires.

Usage: python -I tests/fixtures/query/generate_unicode_order.py
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
OUT = HERE / "generated"

BMP_HIGH = "Lfixture/" + chr(0xE000) + ";"
SUPPLEMENTARY = "Lfixture/" + chr(0x1F600) + ";"

spec = importlib.util.spec_from_file_location(
    "reference_fixture", ROOT / "tests/fixtures/references/generate.py"
)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
fixture.LOOKUP = SUPPLEMENTARY
fixture.S = BMP_HIGH
data, _layout = fixture.build("poly-custom-038")


for value in (BMP_HIGH, SUPPLEMENTARY):
    if fixture.mutf(value)[1:-1] not in data:
        raise SystemExit("the writer no longer emits " + repr(value))


def units(value):
    raw = value.encode("utf-16-le", "surrogatepass")
    return list(struct.unpack("<" + "H" * (len(raw) // 2), raw))


by_units = sorted([BMP_HIGH, SUPPLEMENTARY], key=units)
by_bytes = sorted([BMP_HIGH, SUPPLEMENTARY], key=lambda value: value.encode("utf-8"))
if by_units == by_bytes:
    raise SystemExit("the two strings no longer separate UTF-16 order from UTF-8 order")

OUT.mkdir(exist_ok=True)
(OUT / "unicode-order-038.dex").write_bytes(data)
(OUT / "unicode-order-038.json").write_text(
    json.dumps(
        {
            "fixture_sha256": hashlib.sha256(data).hexdigest(),
            "utf16_units": {BMP_HIGH: units(BMP_HIGH), SUPPLEMENTARY: units(SUPPLEMENTARY)},
            "order_by_utf16_units": by_units,
            "order_by_utf8_bytes": by_bytes,
            "scope": "independent synthetic writer, not A0 qualification",
        },
        ensure_ascii=True,
        indent=2,
    )
    + "\n",
    encoding="utf-8",
    newline="\n",
)
print(json.dumps({"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}))
