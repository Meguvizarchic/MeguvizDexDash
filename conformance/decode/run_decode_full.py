#!/usr/bin/env python3
"""MDD-071 conformance of the complete decode: classes, the three modes, annotations, debug lines, fields, the context
view and every kind of page.

What is compared with what:

* the text of every class and of every defined method of four fixtures, as the engine returns it page by page, with the
  text conformance/decode/oracle.py + oracle_class.py write from the DEX bytes (two programs written from one
  specification: they agree only if the specification is unambiguous);
* a set of hand-written texts (hand-expected-class.txt) with both;
* the numbers of every page (offsets in UTF-8 bytes, lines, mid-line flags, totals) with the text itself;
* the context view of every method and class with the full text it numbers, line by line;
* every page walk (by method_offset, by byte offset, by byte budget) with the whole it must rebuild;
* every refusal with its kind.

What this does not show: that the text is what any other tool prints for the same bytes. The one reference output with
the same frame is checked by conformance/decode/a0_replay.py.

Usage: python -I conformance/decode/run_decode_full.py [--binary PATH] [--out FILE]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "conformance" / "mcp"))
import oracle  # noqa: E402
import oracle_class as oc  # noqa: E402
from mcp_client import DEFAULT_BINARY, McpClient, McpError  # noqa: E402

GENERATED = ROOT / "tests" / "fixtures" / "decode" / "generated"
FIXTURES = {
    "decode-all.dex": GENERATED / "decode-all.dex",
    "decode-v035.dex": GENERATED / "decode-v035.dex",
    "decode-class.dex": GENERATED / "decode-class.dex",
    "annotations-038.dex": ROOT / "tests" / "fixtures" / "annotations" / "generated" / "annotations-038.dex",
}
HAND = HERE / "hand-expected-class.txt"
KINDS = ("class", "method", "class-context", "method-context")
SMALI_FORMAT = "mdd.smali.v1"
CONTEXT_FORMAT = "mdd.smali-context.v1"


class Report:
    def __init__(self) -> None:
        self.checks: list[dict] = []
        self.counts: dict[str, int] = {}

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"name": name, "equal": bool(ok), "detail": "" if ok else detail[:400]})

    def count(self, what: str, n: int = 1) -> None:
        self.counts[what] = self.counts.get(what, 0) + n


def read_hand() -> dict[tuple[str, str, str], str]:
    entries: dict[tuple[str, str, str], str] = {}
    current = None
    for line in HAND.read_text(encoding="utf-8").splitlines(keepends=True):
        if line.startswith("### "):
            parts = line[4:].strip().split(" ", 2)
            if len(parts) == 3 and parts[0].endswith(".dex") and parts[1] in KINDS:
                current = (parts[0], parts[1], parts[2])
                entries[current] = ""
                continue
        if current is not None:
            entries[current] += line
    return entries


def decode(client: McpClient, dataset: str, **arguments) -> dict:
    return client.call("decode", dataset_id=dataset, **arguments)


def text_pages(client: McpClient, dataset: str, selector: dict, **page) -> list[dict]:
    """The rows of one method's text, page by page, until next_offset is null."""
    rows, offset = [], 0
    for _ in range(100000):
        reply = decode(client, dataset, offset=offset, **selector, **page)
        if reply["_is_error"]:
            raise RuntimeError(json.dumps(reply["error"]))
        row = reply["methods"][0]
        rows.append(row)
        if row["next_offset"] is None:
            return rows
        offset = row["next_offset"]
    raise RuntimeError("a page walk did not end")


def lines_of(text: str) -> int:
    return text.count("\n") + (1 if text and not text.endswith("\n") else 0)


def check_page_numbers(rows: list[dict], full: str) -> str:
    """Every number of every page against the text itself; '' when all hold, else the first thing that does not."""
    data = full.encode("utf-8")
    offset = 0
    for i, row in enumerate(rows):
        piece = row["smali"].encode("utf-8")
        last = i == len(rows) - 1
        if row["offset"] != offset:
            return f"page {i}: offset {row['offset']} is not {offset}"
        if data[offset:offset + len(piece)] != piece:
            return f"page {i}: the text is not the bytes of the whole at its offset"
        end = offset + len(piece)
        if row["next_offset"] != (None if last else end):
            return f"page {i}: next_offset {row['next_offset']} is not {None if last else end}"
        if row["total_bytes"] != len(data) or row["total_lines"] != lines_of(full):
            return f"page {i}: totals {row['total_bytes']}/{row['total_lines']} are not {len(data)}/{lines_of(full)}"
        start_line = data[:offset].count(b"\n")
        if row["start_line"] != start_line:
            return f"page {i}: start_line {row['start_line']} is not {start_line}"
        starts_mid = offset > 0 and data[offset - 1:offset] != b"\n"
        if row["starts_mid_line"] != starts_mid:
            return f"page {i}: starts_mid_line is {row['starts_mid_line']}"
        ends_mid = end < len(data) and end > 0 and data[end - 1:end] != b"\n"
        if row["ends_mid_line"] != ends_mid:
            return f"page {i}: ends_mid_line is {row['ends_mid_line']}"
        touched = data[offset:end].count(b"\n") + (1 if end > offset and data[end - 1:end] != b"\n" else 0)
        if row["end_line"] != start_line + touched:
            return f"page {i}: end_line {row['end_line']} is not {start_line + touched}"
        offset = end
    if offset != len(data):
        return "the pages do not cover the text"
    return ""


def method_selector(file_id: int, method_idx: int) -> dict:
    return {"file_id": file_id, "method_idx": method_idx}


# ---- 1. the texts -------------------------------------------------------------------------------------

def check_texts(report: Report, client: McpClient) -> dict:
    """Engine text == independent reader's text for every class and method of every fixture; numbers; context view."""
    opened: dict[str, tuple[str, oc.Classes]] = {}
    for name, path in FIXTURES.items():
        data = path.read_bytes()
        reply = client.call("open_dataset", inputs=[str(path)])
        report.add(f"{name} opens with every layer built", not reply["_is_error"] and reply["diagnostics"] == [], json.dumps(reply.get("diagnostics")))
        opened[name] = (reply["dataset_id"], oc.Classes(data))
    for name, (dataset, classes) in opened.items():
        bad_class, bad_context_class, bad_text, bad_numbers, bad_context, bad_pages, bad_omitted = [], [], [], [], [], [], []
        n_methods = 0
        for entry in classes.classes:
            descriptor = entry["descriptor"]
            want = oc.class_text(classes, descriptor)
            reply = decode(client, dataset, **{"class": descriptor}, mode="smali", max_lines=1000, method_limit=1)
            got = reply["class"].get("smali")
            header = reply["class"]
            if got != want or header["total_bytes"] != len(want.encode()) or header["total_lines"] != lines_of(want) or header["truncated"]:
                bad_class.append(descriptor)
            if header["declaration"] != want.splitlines()[0]:
                bad_class.append(descriptor + " declaration")
            context = decode(client, dataset, **{"class": descriptor}, mode="context", max_lines=1000, method_limit=1)
            if context["class"].get("smali") != oc.class_context(want):
                bad_context_class.append(descriptor)
            report.count("classes")
        for index, access, code in classes.dex.defined:
            n_methods += 1
            want, extras = oc.method_text(classes, index, access, code)
            descriptor = classes.dex.method_text(index)
            selector_file = method_selector(0, index)
            rows = text_pages(client, dataset, selector_file, max_lines=1000)
            got = "".join(r["smali"] for r in rows)
            if got != want:
                bad_text.append(descriptor)
            first = rows[0]
            facts = {"registers": None, "code_units": None, "try_count": None}
            if code:
                registers, _ins, _outs, tries, _debug, size = oracle.struct.unpack_from("<HHHHII", classes.data, code)
                facts = {"registers": registers, "code_units": size, "try_count": tries}
            if (first["access_flags"] != access or first["declaration"] != want.splitlines()[0] or first["descriptor"] != descriptor
                    or any(first[k] != v for k, v in facts.items()) or first["method_idx"] != index):
                bad_numbers.append(descriptor)
            problem = check_page_numbers(rows, want)
            if problem:
                bad_pages.append(f"{descriptor}: {problem}")
            omitted = {}
            if extras.unplaced:
                omitted["debug_events_not_at_an_instruction"] = extras.unplaced
            if extras.not_lines:
                omitted["positions_not_source_lines"] = extras.not_lines
            if first.get("omitted", {}) != omitted:
                bad_omitted.append(descriptor)
            # the context view of the same method
            crows = text_pages(client, dataset, selector_file, mode="context", max_lines=1000)
            cgot = "".join(r["smali"] for r in crows)
            cwant = oc.context(want)
            if cgot != cwant or crows[0]["source_total_lines"] != lines_of(want) or crows[0]["total_lines"] != lines_of(cwant):
                bad_context.append(descriptor)
            problem = check_page_numbers(crows, cwant)
            if problem:
                bad_pages.append(f"{descriptor} (context): {problem}")
            report.count("method texts")
        label = f"{name}: {len(classes.classes)} classes, {n_methods} methods"
        report.add(f"{label}: the class texts equal the independent reader's", not bad_class, json.dumps(bad_class[:5]))
        report.add(f"{label}: the class context views equal the independent reader's", not bad_context_class, json.dumps(bad_context_class[:5]))
        report.add(f"{label}: the method texts (all pages) equal the independent reader's", not bad_text, json.dumps(bad_text[:5]))
        report.add(f"{label}: access flags, registers, code units, tries and declaration equal the code item's", not bad_numbers, json.dumps(bad_numbers[:5]))
        report.add(f"{label}: every page number (byte offset, lines, mid-line flags, totals) equals the text's own", not bad_pages, json.dumps(bad_pages[:3]))
        report.add(f"{label}: the context views equal the independent reader's and name the full text's line count", not bad_context, json.dumps(bad_context[:5]))
        report.add(f"{label}: `omitted` counts what the independent reader leaves out", not bad_omitted, json.dumps(bad_omitted[:5]))
    return {name: dataset for name, (dataset, _) in opened.items()}


def check_hand_texts(report: Report, client: McpClient, datasets: dict) -> None:
    hand = read_hand()
    bad = []
    classes = {name: oc.Classes(path.read_bytes()) for name, path in FIXTURES.items() if name in {k[0] for k in hand}}
    for (fixture, kind, descriptor), want in hand.items():
        dataset = datasets[fixture]
        indexed = classes[fixture]
        if kind in ("class", "class-context"):
            reply = decode(client, dataset, **{"class": descriptor}, mode="smali" if kind == "class" else "context", max_lines=1000, method_limit=1)
            engine = reply["class"]["smali"]
            reader = oc.class_text(indexed, descriptor) if kind == "class" else oc.class_context(oc.class_text(indexed, descriptor))
        else:
            index = next(i for i, _, _ in indexed.dex.defined if indexed.dex.method_text(i) == descriptor)
            rows = text_pages(client, dataset, method_selector(0, index), mode="smali" if kind == "method" else "context", max_lines=1000)
            engine = "".join(r["smali"] for r in rows)
            access, code = next((a, c) for i, a, c in indexed.dex.defined if i == index)
            full = oc.method_text(indexed, index, access, code)[0]
            reader = full if kind == "method" else oc.context(full)
        if engine != want or reader != want:
            bad.append(f"{fixture} {kind} {descriptor}: engine {'=' if engine == want else '!='} hand, reader {'=' if reader == want else '!='} hand")
    report.add(f"the {len(hand)} hand-written class and method texts equal both the engine's and the independent reader's", not bad, json.dumps(bad[:4]))


# ---- 2. classes, pages and budgets ---------------------------------------------------------------------

def class_methods_by_idx(classes: oc.Classes, descriptor: str) -> list[int]:
    entry = classes.by_descriptor(descriptor)
    return sorted(m[0] for m in entry["direct"] + entry["virtual"])


def walk_class(client: McpClient, dataset: str, descriptor: str, **arguments) -> list[dict]:
    pages, offset = [], 0
    for _ in range(1000):
        reply = decode(client, dataset, **{"class": descriptor}, method_offset=offset, **arguments)
        if reply["_is_error"]:
            raise RuntimeError(json.dumps(reply["error"]))
        pages.append(reply)
        if reply["next_method_offset"] is None:
            return pages
        if reply["next_method_offset"] <= offset:
            raise RuntimeError("a class page that does not advance")
        offset = reply["next_method_offset"]
    raise RuntimeError("a class walk did not end")


def check_class_pages(report: Report, client: McpClient, datasets: dict) -> None:
    dataset = datasets["decode-all.dex"]
    classes = oc.Classes(FIXTURES["decode-all.dex"].read_bytes())
    descriptor = "Ldecode/T;"
    wanted = class_methods_by_idx(classes, descriptor)
    for mode in ("summary", "smali", "context"):
        bad = []
        for limit in (1, 3, 20, 50):
            pages = walk_class(client, dataset, descriptor, mode=mode, method_limit=limit, max_lines=3)
            seen = [m["method_idx"] for p in pages for m in p["methods"]]
            if seen != wanted:
                bad.append(f"limit {limit}: the methods are not the class's in method_idx order")
            if len(pages) != -(-len(wanted) // limit):
                bad.append(f"limit {limit}: {len(pages)} pages")
            for i, p in enumerate(pages):
                last = i == len(pages) - 1
                expected_next = None if last else p["method_offset"] + len(p["methods"])
                if p["next_method_offset"] != expected_next or p["total_methods"] != len(wanted):
                    bad.append(f"limit {limit} page {i}: next_method_offset/total_methods")
                if p["mode"] != mode or p["text_format"] != {"summary": None, "smali": SMALI_FORMAT, "context": CONTEXT_FORMAT}[mode]:
                    bad.append(f"limit {limit} page {i}: mode/text_format")
            if pages[0]["method_offset"] != 0:
                bad.append("the first page does not start at 0")
        report.add(f"a class is listed in {mode} mode by method_offset: every method once, in method_idx order, the last page ends", not bad, json.dumps(bad[:3]))
    end = decode(client, dataset, **{"class": descriptor}, method_offset=len(wanted))
    report.add("method_offset equal to total_methods is an empty last page", not end["_is_error"] and end["methods"] == [] and end["next_method_offset"] is None, json.dumps(end)[:200])
    past = decode(client, dataset, **{"class": descriptor}, method_offset=len(wanted) + 1)
    report.add("method_offset past total_methods is an invalid_range error", past["_is_error"] and past["error"]["kind"] == "invalid_range", json.dumps(past.get("error")))

    # a byte budget: one budget for the text of the page; cut methods go on by their own offset
    from_each = {}
    for index in wanted:
        access, code = next((a, c) for i, a, c in classes.dex.defined if i == index)
        from_each[index] = oc.method_text(classes, index, access, code)[0]
    for budget in (80, 300, 1200, 20000):
        bad, rebuilt = [], {}
        pages = walk_class(client, dataset, descriptor, mode="smali", method_limit=50, max_lines=1000, max_bytes=budget)
        for i, page in enumerate(pages):
            total = sum(len(m["smali"].encode()) for m in page["methods"])
            if total > budget:
                bad.append(f"page {i}: {total} bytes over a budget of {budget}")
            if not page["methods"]:
                bad.append(f"page {i}: empty")
            for m in page["methods"]:
                rebuilt[m["method_idx"]] = m["smali"]
                # a method cut by the budget continues on its own
                offset = m["next_offset"]
                while offset is not None:
                    row = decode(client, dataset, file_id=0, method_idx=m["method_idx"], offset=offset, max_lines=1000)["methods"][0]
                    rebuilt[m["method_idx"]] += row["smali"]
                    offset = row["next_offset"]
        if set(rebuilt) != set(wanted) or any(rebuilt[i] != from_each[i] for i in wanted):
            bad.append("the pages and the continuations do not rebuild every method's text")
        report.add(f"max_bytes {budget} on a class page bounds its text, and cut methods continue on their own to the same text", not bad, json.dumps(bad[:3]))
    tiny = decode(client, dataset, **{"class": descriptor}, mode="smali", max_bytes=0)
    report.add("a byte budget that cannot hold one character is an error, not an empty page", tiny["_is_error"] and tiny["error"]["kind"] == "invalid_input", json.dumps(tiny.get("error")))

    # the class text is one page of lines; a small max_lines says it is cut, and it is cut where it says
    other = datasets["decode-class.dex"]
    klass = oc.Classes(FIXTURES["decode-class.dex"].read_bytes())
    whole = oc.class_text(klass, "Ldecode/K;")
    cut = decode(client, other, **{"class": "Ldecode/K;"}, mode="smali", max_lines=5, method_limit=1)["class"]
    report.add("the class text cut by max_lines says so and is the first lines of the whole",
               cut["truncated"] is True and cut["end_line"] == 5 and cut["total_lines"] == lines_of(whole) and cut["smali"] == "".join(whole.splitlines(keepends=True)[:5]), json.dumps(cut)[:200])
    later = decode(client, other, **{"class": "Ldecode/K;"}, mode="smali", method_offset=1, method_limit=1)["class"]
    report.add("a later page of a class does not repeat the class text", "smali" not in later and later["descriptor"] == "Ldecode/K;", json.dumps(later)[:200])
    facts = decode(client, other, **{"class": "Ldecode/K;"})["class"]
    entry = klass.by_descriptor("Ldecode/K;")
    report.add("the class object's facts are the class definition's",
               (facts["access_flags"], facts["superclass"], facts["interfaces"], facts["static_fields"], facts["instance_fields"], facts["source_file"], facts["file_id"], facts["class_def_idx"])
               == (entry["access"], entry["super"], entry["interfaces"], len(entry["static_fields"]), len(entry["instance_fields"]), oracle.text(entry["source"]), 0, entry["index"]) and "smali" not in facts, json.dumps(facts))


def check_byte_pages(report: Report, client: McpClient, datasets: dict) -> None:
    """Pages of one method by every combination of line and byte budgets rebuild its text, and never cut a character."""
    dataset = datasets["decode-all.dex"]
    classes = oc.Classes(FIXTURES["decode-all.dex"].read_bytes())
    bad = []
    chosen = ["Ldecode/T;->switch_packed()V", "Ldecode/T;->try_catch()V", "Ldecode/T;->literals()V", "Ldecode/T;->é中()V", "Ldecode/T;->abstract_one(I)I"]
    for descriptor in chosen:
        index = next(i for i, _, _ in classes.dex.defined if classes.dex.method_text(i) == descriptor)
        access, code = next((a, c) for i, a, c in classes.dex.defined if i == index)
        full = oc.method_text(classes, index, access, code)[0]
        for mode, want in (("smali", full), ("context", oc.context(full))):
            for lines in (1, 2, 1000):
                for budget in (None, 4, 5, 9, 64):
                    page = {"max_lines": lines, "mode": mode}
                    if budget is not None:
                        page["max_bytes"] = budget
                    try:
                        rows = text_pages(client, dataset, method_selector(0, index), **page)
                    except RuntimeError as error:
                        if budget is not None and budget < 4 and "invalid_input" in str(error):
                            continue
                        bad.append(f"{descriptor} {mode} {page}: {error}"[:160])
                        continue
                    problem = check_page_numbers(rows, want)
                    if problem or (budget is not None and any(len(r["smali"].encode()) > budget for r in rows)):
                        bad.append(f"{descriptor} {mode} {page}: {problem or 'a page over its byte budget'}")
    report.add("pages by max_lines and max_bytes (in smali and context, over a name with non-ASCII characters) rebuild the text, "
               "stay in their budgets, and have the numbers of the text", not bad, json.dumps(bad[:3]))
    # the byte offset is a byte offset: it moves by UTF-8 bytes where one character is two or three bytes
    descriptor = "Ldecode/T;->é中()V"
    index = next(i for i, _, _ in classes.dex.defined if classes.dex.method_text(i) == descriptor)
    first = decode(client, dataset, file_id=0, method_idx=index, max_lines=1)["methods"][0]
    declaration = first["smali"]
    report.add("next_offset counts UTF-8 bytes, not characters or code units",
               first["next_offset"] == len(declaration.encode()) and len(declaration.encode()) > len(declaration), json.dumps(first)[:200])
    inside = decode(client, dataset, file_id=0, method_idx=index, offset=len(".method public static é".encode()) - 1)
    report.add("an offset inside a character is refused as a range error", inside["_is_error"] and inside["error"]["kind"] == "invalid_range", json.dumps(inside.get("error")))
    # three units, three numbers: the code unit count of a method is not its text's byte or line count
    sw = decode(client, dataset, method="Ldecode/T;->switch_packed()V", max_lines=1000)["methods"][0]
    report.add("code_units, total_bytes and total_lines are three different numbers of one method",
               len({sw["code_units"], sw["total_bytes"], sw["total_lines"]}) == 3, json.dumps({k: sw[k] for k in ("code_units", "total_bytes", "total_lines")}))


def check_no_body_and_summary(report: Report, client: McpClient, datasets: dict) -> None:
    dataset = datasets["decode-all.dex"]
    abstract = decode(client, dataset, method="Ldecode/T;->abstract_one(I)I")["methods"][0]
    native = decode(client, dataset, method="Ldecode/T;->native_one(Ljava/lang/String;)Z")["methods"][0]
    ok = all(m["registers"] is None and m["code_units"] is None and m["try_count"] is None and ".registers" not in m["smali"] and m["smali"].endswith(".end method\n")
             for m in (abstract, native))
    report.add("a method without a body has null registers, code units and tries, no registers line, and still ends its block", ok, json.dumps([abstract, native])[:300])
    empty = decode(client, dataset, method="Ldecode/T;->all_flags([I)V")["methods"][0]
    report.add("a method with a body of one instruction is not mistaken for one without", empty["registers"] == 2 and empty["code_units"] == 1, json.dumps(empty)[:200])
    ctx = decode(client, dataset, method="Ldecode/T;->abstract_one(I)I", mode="context")["methods"][0]
    report.add("the context of a method without a body is its header and its method line", ctx["smali"].count("\n") == 2 and "line 0: .method" in ctx["smali"], json.dumps(ctx)[:200])
    summary = decode(client, dataset, method="Ldecode/T;->try_catch()V", mode="summary")
    row = summary["methods"][0]
    report.add("the summary has the numbers, the declaration and no text, and names no text format",
               "smali" not in row and row["try_count"] == 2 and summary["text_format"] is None, json.dumps(summary)[:200])


def check_refusals(report: Report, client: McpClient, datasets: dict) -> None:
    dataset = datasets["decode-all.dex"]
    pair = datasets["both"]
    T = "Ldecode/T;"
    cases = [
        ("no selector", dataset, {}, "invalid_argument"),
        ("a method and a class", dataset, {"method": T + "->op_00()V", "class": T}, "invalid_argument"),
        ("method_idx without file_id", dataset, {"method_idx": 3}, "invalid_argument"),
        ("an empty class", dataset, {"class": ""}, "invalid_argument"),
        ("an empty method", dataset, {"method": ""}, "invalid_argument"),
        ("a class nobody defines", dataset, {"class": "Lnope/N;"}, "not_found"),
        ("a class that is only referred to", dataset, {"class": "Ldecode/Other;"}, "not_found"),
        ("a class with a file_id that is not in the dataset", dataset, {"class": T, "file_id": 9}, "not_found"),
        ("a class defined in two files, without file_id", pair, {"class": T}, "ambiguous"),
        ("a class with an offset", dataset, {"class": T, "offset": 7}, "invalid_argument"),
        ("a class in summary mode with an offset", dataset, {"class": T, "mode": "summary", "offset": 7}, "invalid_argument"),
        ("method_offset past the methods", dataset, {"class": T, "method_offset": 100000}, "invalid_range"),
        ("a method with method_offset", dataset, {"method": T + "->op_00()V", "method_offset": 1}, "invalid_argument"),
        ("a method in summary mode with an offset", dataset, {"method": T + "->op_00()V", "mode": "summary", "offset": 1}, "invalid_argument"),
        ("an offset past the end of a text", dataset, {"method": T + "->op_00()V", "offset": 100000}, "invalid_range"),
        ("an offset past the end of a context", dataset, {"method": T + "->op_00()V", "mode": "context", "offset": 100000}, "invalid_range"),
        ("a method only referred to", dataset, {"method": "Ldecode/Other;->work()V"}, "not_found"),
        ("a method_idx that is no method of the file", dataset, {"file_id": 0, "method_idx": 99999}, "not_found"),
    ]
    for label, ds, arguments, kind in cases:
        reply = decode(client, ds, **arguments)
        report.add(f"{label} is refused as {kind}", reply["_is_error"] and reply["error"]["kind"] == kind, json.dumps(reply.get("error"))[:200])
    protocol = [("max_lines 0", {"max_lines": 0}), ("max_lines 1001", {"max_lines": 1001}), ("method_limit 0", {"method_limit": 0}),
                ("method_limit 51", {"method_limit": 51}), ("an unknown mode", {"mode": "xml"}), ("an unknown argument", {"compact": True}),
                ("a negative method_offset", {"method_offset": -1}), ("a negative offset", {"offset": -1})]
    for label, extra in protocol:
        try:
            decode(client, dataset, **{"class": T}, **extra)
            report.add(f"{label} is a protocol error", False, "answered")
        except McpError as error:
            report.add(f"{label} is a protocol error", error.code == -32602, str(error))


def check_limits(report: Report, binary: Path) -> None:
    """A page over the server's result budget is refused whole, never clipped."""
    client = McpClient(binary, ["--max-result-bytes", "4000"])
    try:
        client.initialize()
        dataset = client.call("open_dataset", inputs=[str(FIXTURES["decode-all.dex"])])["dataset_id"]
        small = decode(client, dataset, method="Ldecode/T;->op_00()V")
        big = decode(client, dataset, **{"class": "Ldecode/T;"}, mode="smali", method_limit=50, max_lines=1000)
        details = big.get("error", {}).get("details", {})
        report.add("a result over the byte budget is refused whole (quota_exceeded, with the budget, the limit and what was observed)",
                   not small["_is_error"] and big["_is_error"] and big["error"]["code"] == "QUOTA_EXCEEDED" and details.get("budget") == "max_result_bytes"
                   and int(details["observed"]) > int(details["limit"]) == 4000 and "methods" not in big, json.dumps(big)[:300])
    finally:
        client.close()


def check_deadline(report: Report, binary: Path) -> None:
    """A class page that outlives its deadline closes its dataset, as a method decode and a query do, and no other."""
    import importlib.util
    import shutil
    import tempfile
    spec = importlib.util.spec_from_file_location("decode_fixtures", ROOT / "tests" / "fixtures" / "decode" / "generate.py")
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    program = fixtures.Program()
    # 200,000 instructions in the first method of the class: far more than a millisecond of rendering, still a small file
    program.methods.append(fixtures.Method("huge", ["public", "static"], registers=1, code=[fixtures.op("nop")] * 200000 + [fixtures.RET]))
    directory = Path(tempfile.mkdtemp(prefix="mdd-class-deadline-"))
    client = None
    try:
        huge = directory / "huge.dex"
        huge.write_bytes(program.build("035"))
        client = McpClient(binary)
        client.initialize()
        slow = client.call("open_dataset", inputs=[str(huge)])["dataset_id"]
        other = client.call("open_dataset", inputs=[str(FIXTURES["decode-all.dex"])])["dataset_id"]
        summary = decode(client, slow, **{"class": "Ldecode/T;"})
        report.add("a class summary renders no text, so the 200,000-instruction method costs it nothing", not summary["_is_error"] and summary["methods"][0]["code_units"] == 200001, json.dumps(summary)[:200])
        for mode in ("smali", "context"):
            late = decode(client, slow, **{"class": "Ldecode/T;"}, mode=mode, timeout_ms=1)
            error = late.get("error", {})
            report.add(f"a class page in {mode} mode that outlives its deadline says so and that the dataset was closed",
                       late["_is_error"] and error.get("kind") == "timeout" and error.get("dataset_closed") is True and late.get("dataset_id") == slow, json.dumps(late)[:300])
            after = decode(client, slow, **{"class": "Ldecode/T;"})
            report.add(f"the dataset closed by a class page in {mode} mode is refused as unknown_dataset",
                       after["_is_error"] and after["error"]["kind"] == "unknown_dataset", json.dumps(after.get("error")))
            slow = client.call("open_dataset", inputs=[str(huge)])["dataset_id"]
        fine = decode(client, other, **{"class": "Ldecode/T;"})
        report.add("the other dataset still lists its class", not fine["_is_error"] and fine["total_methods"] == 238)
        whole = decode(client, slow, **{"class": "Ldecode/T;"}, mode="smali", method_limit=1, max_lines=1000)
        report.add("the same class decodes within the default deadline, so the deadline above was the cause",
                   not whole["_is_error"] and whole["methods"][0]["total_lines"] == 200000 + 5, json.dumps(whole)[:200])
    finally:
        if client is not None:
            client.close()
        shutil.rmtree(directory, ignore_errors=True)


def check_layers(report: Report, client: McpClient) -> None:
    """A fault in one layer does not take the other texts with it."""
    path = GENERATED / "decode-bad-invoke.dex"
    reply = client.call("open_dataset", inputs=[str(path)])
    dataset = reply["dataset_id"]
    shown = decode(client, dataset, method="Ldecode/T;->good()V", max_lines=1000)
    row = shown["methods"][0] if not shown["_is_error"] else {}
    report.add("with the references layer not built, a method still shows its text and its annotation layer is not reported missing",
               "omitted" not in row and "const-string v0" in row.get("smali", ""), json.dumps(shown)[:300])


# ---- the run -----------------------------------------------------------------------------------------------

def run(binary: Path) -> dict:
    report = Report()
    client = McpClient(binary)
    client.initialize()
    try:
        datasets = check_texts(report, client)
        datasets["both"] = client.call("open_dataset", inputs=[str(FIXTURES["decode-all.dex"]), str(FIXTURES["decode-v035.dex"])])["dataset_id"]
        check_hand_texts(report, client, datasets)
        check_class_pages(report, client, datasets)
        check_byte_pages(report, client, datasets)
        check_no_body_and_summary(report, client, datasets)
        check_refusals(report, client, datasets)
        check_layers(report, client)
    finally:
        client.close()
    check_limits(report, binary)
    check_deadline(report, binary)
    failed = [c for c in report.checks if not c["equal"]]
    return {"checks": report.checks, "passed": len(report.checks) - len(failed), "failed": len(failed), "counts": report.counts,
            "equal": not failed}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--out", type=Path)
    options = parser.parse_args()
    result = run(options.binary)
    if options.out:
        options.out.write_text(json.dumps(result, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    for check in result["checks"]:
        if not check["equal"]:
            print("FAIL", check["name"], check["detail"])
    print(f"checks={len(result['checks'])} passed={result['passed']} failed={result['failed']} equal={result['equal']}")
    return 0 if result["equal"] else 1


if __name__ == "__main__":
    sys.exit(main())
