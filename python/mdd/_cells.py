"""Decode the typed cells of a batch into Python values without losing anything.

NULL is ``None`` and nothing else is. 64-bit integers arrive as decimal strings and
become exact ``int``. Floats arrive as their bit pattern. Text is ``str``; text that
holds an unpaired surrogate arrives as UTF-16 units and becomes a ``str`` holding that
surrogate code point, which Python permits and which round-trips with
``s.encode('utf-16-be', 'surrogatepass')``.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DexMutf8:
    """A DEX string kept as its original MUTF-8 bytes plus the UTF-16 unit count."""

    raw: bytes
    utf16_units: int

    def text(self) -> str:
        """Decode MUTF-8 (NUL as C0 80, surrogates as 3-byte forms) to a ``str``."""
        units: list[int] = []
        data, i = self.raw, 0
        while i < len(data):
            b = data[i]
            if b < 0x80:
                units.append(b)
                i += 1
            elif b & 0xE0 == 0xC0:
                units.append(((b & 0x1F) << 6) | (data[i + 1] & 0x3F))
                i += 2
            else:
                units.append(((b & 0x0F) << 12) | ((data[i + 1] & 0x3F) << 6) | (data[i + 2] & 0x3F))
                i += 3
        raw = b"".join(struct.pack(">H", u) for u in units)
        return raw.decode("utf-16-be", "surrogatepass")


def decode_cell(cell: dict[str, Any]) -> Any:
    tag = cell["t"]
    if tag == "null":
        return None
    if tag == "bool":
        return bool(cell["v"])
    if tag in ("i64", "u64"):
        return int(cell["v"])
    if tag == "f64":
        return struct.unpack(">d", bytes.fromhex(cell["bits"]))[0]
    if tag == "bytes":
        return bytes.fromhex(cell["v"])
    if tag == "dex_mutf8":
        return DexMutf8(bytes.fromhex(cell["v"]), int(cell["utf16_units"]))
    if tag == "text":
        if "units" in cell:
            return bytes.fromhex(cell["units"]).decode("utf-16-be", "surrogatepass")
        return cell["v"]
    raise ValueError(f"unknown cell tag {tag!r}")
