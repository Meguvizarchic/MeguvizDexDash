#!/usr/bin/env python3
"""MDD-042 decode conformance: the engine, an independent renderer and hand-written texts.

For every method the fixtures define, the text the engine's `decode` tool returns (all its
pages, joined) must equal the text conformance/decode/oracle.py renders from the DEX bytes,
and for the methods in hand-expected.txt it must equal the text written by hand. The
engine's page fields (byte offsets, line counts, mid-line flags) are checked against the
text itself, and the refusals against their kinds.

What this does not show: that the text is what the reference engine prints for anything
beyond the one method on record. Its frame and the common instructions are checked against
that recording by conformance/mcp/lifecycle_replay.py.

Usage: python -I conformance/decode/run_decode_conformance.py [--binary PATH] [--out FILE]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "conformance" / "mcp"))
import oracle  # noqa: E402
from mcp_client import DEFAULT_BINARY, McpClient  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "decode" / "generated"
HAND = HERE / "hand-expected.txt"
MAIN, OLD = FIXTURES / "decode-all.dex", FIXTURES / "decode-v035.dex"


class Report:
    def __init__(self) -> None:
        self.checks: list[dict] = []

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"name": name, "equal": bool(ok), "detail": detail if not ok else ""})


def read_hand() -> dict[str, str]:
    entries: dict[str, str] = {}
    current = None
    for line in HAND.read_text(encoding="utf-8").splitlines(keepends=True):
        if line.startswith("### "):
            title = line[4:].strip()
            if "->" in title and title.startswith("L"):
                current = title
                entries[current] = ""
            continue
        if current is not None:
            entries[current] += line
    return entries


def decode_all_pages(client: McpClient, dataset: str, **selector) -> tuple[str, list[dict]]:
    """The text of one method, page by page, and the pages."""
    text, pages, offset = "", [], 0
    for _ in range(100000):
        reply = client.call("decode", dataset_id=dataset, offset=offset, max_lines=1000, **selector)
        if reply["_is_error"]:
            raise RuntimeError(json.dumps(reply["error"]))
        method = reply["methods"][0]
        pages.append(method)
        text += method["smali"]
        if method["next_offset"] is None:
            return text, pages
        offset = method["next_offset"]
    raise RuntimeError("a page walk did not end")


def check_texts(report: Report, client: McpClient) -> dict[str, tuple[str, int, str]]:
    """Engine text == oracle text for every defined method of both fixtures. Returns the engine's map."""
    opened = client.call("open_dataset", inputs=[str(MAIN), str(OLD)])
    dataset = opened["dataset_id"]
    report.add("both fixtures open with every layer built", not opened["_is_error"] and opened["diagnostics"] == [],
               json.dumps(opened.get("diagnostics")))
    hand = read_hand()
    seen: dict[str, tuple[str, int, str]] = {}
    for file_id, path in ((0, MAIN), (1, OLD)):
        data = path.read_bytes()
        expected = oracle.render_all(data)
        facts = oracle.facts_of(data)
        different, shown = [], 0
        for descriptor, want in expected.items():
            selector = {"file_id": file_id, "method_idx": facts[descriptor]["method_idx"]}
            text, pages = decode_all_pages(client, dataset, **selector)
            shown += 1
            meta = pages[0]
            numbers_ok = (meta["file_id"] == file_id and meta["descriptor"] == descriptor
                          and meta["access_flags"] == facts[descriptor]["access_flags"]
                          and meta["registers"] == facts[descriptor]["registers"]
                          and meta["code_units"] == facts[descriptor]["code_units"]
                          and meta["try_count"] == facts[descriptor]["try_count"]
                          and meta["declaration"] == want.splitlines()[0]
                          and meta["total_bytes"] == len(want.encode("utf-8"))
                          and meta["total_lines"] == want.count("\n"))
            if text != want or not numbers_ok:
                different.append((descriptor, "text" if text != want else "numbers"))
            seen[(file_id, descriptor)] = (text, meta["method_idx"], want)
        report.add(f"{path.name}: the engine's text equals the independent renderer's, and the numbers equal the code item's, "
                   f"for all {shown} methods", not different, json.dumps(different[:6]))
    mismatched = []
    for descriptor, want in hand.items():
        got = seen.get((0, descriptor))
        if got is None or got[0] != want or got[2] != want:
            mismatched.append(descriptor)
    report.add(f"the {len(hand)} hand-written texts equal both the engine's and the independent renderer's",
               not mismatched, json.dumps(mismatched[:8]))
    report.add("every opcode that has a valid operand set in these fixtures is covered",
               len([d for d in expected_op_methods()]) >= 200, str(len(list(expected_op_methods()))))
    return {"dataset": dataset}


def expected_op_methods():
    return [d for d in oracle.render_all(MAIN.read_bytes()) if "->op_" in d]


def check_paging(report: Report, client: McpClient, dataset: str) -> None:
    long = "Ldecode/T;->long_body()V"
    page = client.call("decode", dataset_id=dataset, method=long, file_id=0)
    method = page["methods"][0]
    whole = oracle.render_all(MAIN.read_bytes())[long]
    total_lines = whole.count("\n")
    report.add("a first page holds max_lines (200) lines, ends on a line boundary and says where it continues",
               method["start_line"] == 0 and method["end_line"] == 200 and not method["starts_mid_line"]
               and not method["ends_mid_line"] and method["offset"] == 0
               and method["next_offset"] == len("".join(whole.splitlines(keepends=True)[:200]).encode())
               and method["smali"].count("\n") == 200 and method["total_lines"] == total_lines, json.dumps(
                   {k: v for k, v in method.items() if k != "smali"}))
    # a complete walk by lines
    pieces, offset, line, pages = [], 0, 0, 0
    ok = True
    while True:
        r = client.call("decode", dataset_id=dataset, method=long, file_id=0, offset=offset, max_lines=200)["methods"][0]
        ok &= r["offset"] == offset and r["start_line"] == line and not r["starts_mid_line"] and not r["ends_mid_line"]
        ok &= r["end_line"] - r["start_line"] == r["smali"].count("\n")
        pieces.append(r["smali"])
        pages += 1
        line = r["end_line"]
        if r["next_offset"] is None:
            break
        ok &= r["next_offset"] == offset + len(r["smali"].encode())
        offset = r["next_offset"]
    report.add("a walk by lines (200 per page) rebuilds the text, with offsets in bytes and lines counted apart",
               ok and "".join(pieces) == whole and pages == -(-total_lines // 200),
               f"{pages} pages for {total_lines} lines")
    # a walk by bytes, which cuts inside lines
    for budget in (1, 7, 100):
        pieces, offset, cuts, previous_mid = [], 0, 0, False
        ok = True
        guard = 0
        while guard < 200000:
            guard += 1
            r = client.call("decode", dataset_id=dataset, method=long, file_id=0, offset=offset, max_lines=1000, max_bytes=budget)
            if r["_is_error"]:
                ok = False
                break
            m = r["methods"][0]
            size = len(m["smali"].encode())
            ok &= 0 < size <= budget and m["starts_mid_line"] == previous_mid
            cuts += m["ends_mid_line"]
            previous_mid = m["ends_mid_line"]
            pieces.append(m["smali"])
            if m["next_offset"] is None:
                break
            ok &= m["next_offset"] == offset + size
            offset = m["next_offset"]
            if budget == 1 and guard > 3000:
                pieces.append(whole[len("".join(pieces)):])  # enough pages seen; the rest is checked by the larger budgets
                break
        report.add(f"a walk by bytes (max_bytes={budget}) never exceeds the budget, cuts mid-line and rebuilds the text",
                   ok and "".join(pieces) == whole and cuts > 0, f"cuts={cuts} pieces={len(pieces)}")
    # a page cut inside a multi-byte character is moved back to the character boundary
    name = chr(0xE9) + chr(0x4E2D)
    descriptor = f"Ldecode/T;->{name}()V"
    text = oracle.render_all(MAIN.read_bytes())[descriptor]
    for budget in (14, 15, 16, 17, 18, 20):
        pieces, offset, ok = [], 0, True
        while True:
            r = client.call("decode", dataset_id=dataset, method=descriptor, file_id=0, offset=offset, max_lines=1000, max_bytes=budget)
            if r["_is_error"]:
                ok = False
                break
            m = r["methods"][0]
            ok &= len(m["smali"].encode()) <= budget
            pieces.append(m["smali"])
            if m["next_offset"] is None:
                break
            offset = m["next_offset"]
        report.add(f"max_bytes={budget} over a method name with 2- and 3-byte characters keeps every page valid and joins back",
                   ok and "".join(pieces) == text, "".join(pieces))
    at_char = text.encode("utf-8").index(name.encode("utf-8"))
    inside = client.call("decode", dataset_id=dataset, method=descriptor, file_id=0, offset=at_char + 1)
    report.add("an offset inside a character is refused", inside["_is_error"] and inside["error"]["kind"] == "invalid_offset",
               json.dumps(inside.get("error")))
    total = len(text.encode("utf-8"))
    past = client.call("decode", dataset_id=dataset, method=descriptor, file_id=0, offset=total + 1)
    report.add("an offset past the end is refused", past["_is_error"] and past["error"]["kind"] == "invalid_offset",
               json.dumps(past.get("error")))
    end = client.call("decode", dataset_id=dataset, method=descriptor, file_id=0, offset=total)
    m = end["methods"][0] if not end["_is_error"] else {}
    report.add("an offset at the end is an empty final page", m.get("smali") == "" and m.get("next_offset") is None,
               json.dumps(m))
    tiny = client.call("decode", dataset_id=dataset, method=descriptor, file_id=0, offset=at_char, max_bytes=1)
    report.add("a byte budget smaller than the next character is refused, not answered with an empty page",
               tiny["_is_error"], json.dumps(tiny.get("error")))
    mid = client.call("decode", dataset_id=dataset, method=long, file_id=0, offset=5, max_lines=2)["methods"][0]
    report.add("a page that starts inside a line says so and counts that line as one of its lines",
               mid["starts_mid_line"] and mid["start_line"] == 0 and mid["end_line"] == 2
               and mid["smali"] == whole[5:whole.index("\n", whole.index("\n") + 1) + 1], json.dumps(mid)[:200])


def check_selection_and_errors(report: Report, client: McpClient, dataset: str) -> None:
    ambiguous = client.call("decode", dataset_id=dataset, method="Ldecode/T;->op_00()V")
    error = ambiguous.get("error", {})
    report.add("a descriptor defined in two DEX files is refused as ambiguous and names both",
               ambiguous["_is_error"] and error.get("kind") == "ambiguous"
               and error.get("message") == "method occurs in multiple DEX files; supply file_id from {0, 1}"
               and error.get("file_id") is None and error.get("method_idx") is None
               and error.get("code_unit_offset") is None and ambiguous["dataset_id"] == dataset, json.dumps(ambiguous))
    for file_id, path in ((0, MAIN), (1, OLD)):
        got = client.call("decode", dataset_id=dataset, method="Ldecode/T;->op_00()V", file_id=file_id)
        want = oracle.render_all(path.read_bytes())["Ldecode/T;->op_00()V"]
        report.add(f"file_id {file_id} chooses its own definition of the ambiguous descriptor",
                   not got["_is_error"] and got["methods"][0]["smali"] == want and got["methods"][0]["file_id"] == file_id)
    only = client.call("decode", dataset_id=dataset, method="Ldecode/T;->only_here()V")
    report.add("a descriptor defined once needs no file_id and reports the file it is in",
               not only["_is_error"] and only["methods"][0]["file_id"] == 1)
    refused = {
        "a method that is only referred to": {"method": "Ldecode/Other;->work()V"},
        "a descriptor nobody defines": {"method": "Ldecode/T;->nothing()V"},
        "a file_id that is not in the dataset": {"file_id": 9, "method_idx": 0},
        "a method_idx that is only a reference": {"file_id": 0, "method_idx": 1},
    }
    for label, arguments in refused.items():
        got = client.call("decode", dataset_id=dataset, **arguments)
        error = got.get("error", {})
        report.add(f"{label} is not found", got["_is_error"] and error.get("kind") == "not_found"
                   and "code_unit_offset" in error and "file_id" in error and "method_idx" in error, json.dumps(error)[:200])
    invalid = {
        "no selector": {},
        "two selectors": {"method": "Ldecode/T;->op_00()V", "class": "Ldecode/T;"},
        "method_idx without file_id": {"method_idx": 0},
    }
    for label, arguments in invalid.items():
        got = client.call("decode", dataset_id=dataset, **arguments)
        report.add(f"{label} is refused as an invalid argument", got["_is_error"] and got["error"]["kind"] == "invalid_argument",
                   json.dumps(got.get("error")))
    for label, arguments in {"a class": {"class": "Ldecode/T;"},
                             "the context mode": {"method": "Ldecode/T;->only_here()V", "mode": "context"}}.items():
        got = client.call("decode", dataset_id=dataset, **arguments)
        report.add(f"{label} is refused as not implemented, not answered with a stand-in",
                   got["_is_error"] and got["error"]["kind"] == "not_implemented", json.dumps(got.get("error")))
    summary = client.call("decode", dataset_id=dataset, method="Ldecode/T;->only_here()V", mode="summary")
    method = summary["methods"][0] if not summary["_is_error"] else {}
    facts = oracle.facts_of(OLD.read_bytes())["Ldecode/T;->only_here()V"]
    report.add("the summary mode answers the method's numbers and no text",
               summary.get("mode") == "summary" and method.get("smali") is None and method.get("registers") == facts["registers"]
               and method.get("code_units") == facts["code_units"] and method.get("try_count") == facts["try_count"]
               and method.get("declaration") == ".method public static only_here()V" and "next_offset" not in method,
               json.dumps(summary)[:300])
    from mcp_client import McpError
    for label, arguments in {"max_lines 0": {"max_lines": 0}, "max_lines 1001": {"max_lines": 1001},
                             "an unknown mode": {"mode": "dex"}, "method_limit 51": {"method_limit": 51},
                             "an unknown argument": {"compact": True}, "a negative offset": {"offset": -1}}.items():
        try:
            client.call("decode", dataset_id=dataset, method="Ldecode/T;->only_here()V", **arguments)
            report.add(f"{label} is a protocol error", False, "answered")
        except McpError as error:
            report.add(f"{label} is a protocol error", error.code == -32602, str(error))
    closed = client.call("decode", dataset_id="dataset-nobody", method="Ldecode/T;->only_here()V")
    report.add("an unknown dataset is refused as unknown_dataset",
               closed["_is_error"] and closed["error"]["kind"] == "unknown_dataset")


def run(binary: Path) -> dict:
    report = Report()
    reproduced = subprocess.run([sys.executable, "-I", str(ROOT / "tests/fixtures/decode/generate.py"), "--check"],
                                capture_output=True, text=True, check=False)
    report.add("the fixtures reproduce byte for byte from their generator", reproduced.returncode == 0, reproduced.stdout)
    client = McpClient(binary)
    client.initialize()
    state = check_texts(report, client)
    check_paging(report, client, state["dataset"])
    check_selection_and_errors(report, client, state["dataset"])
    code = client.close()
    report.add("the server exits cleanly", code == 0, str(code))
    failed = [c for c in report.checks if not c["equal"]]
    return {"checks": report.checks, "passed": len(report.checks) - len(failed), "failed": len(failed), "equal": not failed}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = run(args.binary)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"checks={len(result['checks'])} passed={result['passed']} failed={result['failed']} equal={result['equal']}")
    for check in result["checks"]:
        if not check["equal"]:
            print("FAIL", check["name"], check["detail"][:400])
    return 0 if result["equal"] else 1


if __name__ == "__main__":
    sys.exit(main())
