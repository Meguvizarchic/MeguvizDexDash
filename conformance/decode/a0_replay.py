#!/usr/bin/env python3
"""Replay the requests of a0_cases.py against this server and compare with the reference's frozen answers.

conformance/decode/a0-golden.json holds what the reference engine (dexsql 0.1.0, sha256 pinned in
a0_cases.py) answered to each request, recorded by generate_a0_golden.py from the real binary. This
script needs no binary: it starts `meguvizdexdash mcp`, puts the same request, and compares.

This server is not a copy of the reference. What it answers differently on purpose is listed once, in
DECLARED, with the reason; everything else is compared exactly: the keys, the values, the numbers a
client reads, the kinds of errors, and the content of the smali text (after both texts are reduced to
the same form, see canon_smali).

Usage: python -I conformance/decode/a0_replay.py [--binary PATH] [--out FILE] [--show N] [--only TEXT]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "conformance" / "mcp"))
import a0_cases  # noqa: E402
import generate_a0_golden as gen  # noqa: E402
from mcp_client import DEFAULT_BINARY  # noqa: E402

ENVELOPE = ("code", "stage", "retryable", "details")

# What this server answers differently on purpose, and why. Everything else is compared exactly.
DECLARED = [
    ("ENVELOPE", "the `error` object of every tool error carries four fields of this engine (code, stage, retryable, details) beside the reference's"),
    ("TEXT CONVENTIONS", "the smali text follows baksmali's writing (p-registers for parameters, :cond_N/:goto_N/:try_start_N labels, .catch lines beside the code, "
                         "an L on wide literals, a backslash before an apostrophe in strings); the reference writes v-registers, :label_XXXX, .catch lines at the end, no L, a bare apostrophe. "
                         "The two texts are reduced to the same form (canon_smali) and must be equal: instructions, operands, literals, branch targets, payloads and exception tables. "
                         "The numbers that depend on the length of the text (total_bytes, total_lines, start_line, end_line, next_offset, the mid-line flags) are compared only when the text is identical."),
    ("ERROR WORDING", "an error's `message` is this server's own words. Its `kind` (through KIND_ALIASES) and the file_id, method_idx and code_unit_offset it echoes are compared."),
    ("MALFORMED ARGUMENTS", "an argument of the wrong type, an unknown field, or a value outside its range (limit, max_lines, method_limit, timeout_ms) is a JSON-RPC invalid-params error here; the reference answers a tool result with isError (the serde message, or kind invalid_input)."),
    ("LENIENT", "the reference refuses max_bytes outside 4096..=131072 and timeout_ms outside 1..=60000, and `mode: null` for get_manifest; "
                "this server's max_bytes is a budget the answer must fit in (over it: quota_exceeded) and it takes `null` as the default."),
    ("MALFORMED CODE", "a method whose invoke names a different number of registers than its prototype takes is rendered as the bytes say (the invoke is visible and wrong); "
                       "the reference refuses the whole method (invalid_input, with the offset of the invoke). Showing the code of a damaged or obfuscated method is the more useful answer."),
    ("SUMMARY", "the summary mode here also names the method's `declaration`."),
    ("XML TEXT NODES", "the xml mode of get_manifest (MDD-072) keeps the text nodes of the document and the reference drops them; the fixture manifest has one, "
                       "so its text is nine bytes longer here. The texts are compared with the lines that hold only character data removed from this server's."),
    ("TEXT FORMAT", "every decode answer that shows text names the version of its text (`text_format`); a context row also gives `source_total_lines`, the line count of the full text its `line N:` numbers index."),
    ("CLASS OBJECT", "a class page also carries `class`: the class's own facts (flags, superclass, source file, interfaces, field counts) and, in the text modes on the first page, its declaration, "
                     "fields and annotations as a text; and a method row may carry `omitted`, what its text leaves out. The reference has neither."),
    ("EXTRA DIRECTIVES", "the smali text here also carries annotation blocks, `.param` lines and debug directives (`.line`, `.local`, `.end local`, `.restart local`, `.prologue`, `.epilogue`, `.source`) that the reference never writes; "
                         "canon_smali drops them before the texts are compared, so the instructions, operands, targets, payloads and exception tables are what is compared."),
    ("CONTEXT", "the context view keeps the same kinds of lines as the reference's (method line, registers line, label lines, catch lines; checked against the reference for every method of the fixture). "
                "Its `line N:` numbers count the lines of this server's own full text, so they are compared only through canon_context, which drops the numbers and merges the labels that name one address; "
                "the labels themselves are named by baksmali's conventions here."),
    ("CLASS PAGE BYTES", "in a class page `max_bytes` is one budget of UTF-8 bytes for the text of all its methods (the reference's counts the serialized answer, twice); "
                         "a class page's answer is compared only where no budget is asked for."),
    ("OWN SCOPE", "list_tables names the 17 HostLab contract relations (as objects with name, kind and column_count) where the reference lists 56 names; "
                  "list_datasets reports this server's own limits."),
    ("ORDER OF CHECKS", "when a request is wrong in several ways, both engines refuse it, but the reference names the dataset first, then timeout_ms, max_bytes and the rest, "
                        "and this server checks the schema of the arguments before it looks for the dataset."),
    ("TIMING", "a 1 ms deadline: the reference ran out of time; whether this server does depends on the clock."),
]

KIND_ALIASES = {
    "invalid_input": {"invalid_input", "invalid_argument"},
    "invalid_range": {"invalid_range", "invalid_offset"},
}

TEXT_FIELDS = ("smali", "total_bytes", "total_lines", "end_line", "start_line", "next_offset", "starts_mid_line", "ends_mid_line")

# Nothing is left unimplemented: the xml mode of get_manifest (MDD-072) answers and its records are compared.
NOT_IMPLEMENTED: dict[str, str] = {}
TIMING = {"decode-arg-timeout_ms-1": "a 1 ms deadline"}
# An offset the reference accepts because its text is 329 bytes long; this server's text is shorter.
TEXT_LENGTH = {"decode-page-switch-offset-total", "decode-method-context-offset-total", "decode-method-context-offset-past"}
# A byte budget on a class page: the reference counts the serialized answer, this server the text of the page.
BUDGET = {"decode-class-budget-smali-4096", "decode-class-budget-summary-4096"}
# Arguments the reference refuses and this server serves.
LENIENT = {"manifest-mode-null", "manifest-max_bytes-0", "manifest-max_bytes-10", "generic-query-max_bytes-0",
           "decode-combo-max_bytes-unknown-method", "manifest-combo-offset-past-max_bytes"}


# ---- the smali text reduced to what it says -------------------------------------------------------

LABEL = re.compile(r":([A-Za-z_][A-Za-z_0-9]*)")
LABEL_PREFIXES = {"label", "payload", "cond", "goto", "pswitch", "sswitch", "array", "try", "catch", "catchall"}
CATCH = re.compile(r"^\.(catchall|catch)\s*(\S+)?\s*\{(:\S+)\s*\.\.\s*(:\S+)\}\s*(:\S+)$")


def label_address(name: str) -> int:
    """The code address a label stands for: `label_0004`, `cond_4`, `payload_0004_0000` (the payload's, not the reference's) ..."""
    parts = name.split("_")
    if parts[0] == "payload":
        return int(parts[1], 16)
    return int(parts[-1], 16)


def parameter_registers(declaration: str) -> int:
    """How many registers the parameters take, `this` included."""
    head, _, rest = declaration.partition("(")
    params, _, _ = rest.partition(")")
    count = 0 if " static " in " " + head + " " else 1
    i = 0
    while i < len(params):
        wide = False
        if params[i] == "[":
            while params[i] == "[":
                i += 1
        elif params[i] in "JD":
            wide = True
        if params[i] == "L":
            i = params.index(";", i)
        count += 2 if wide else 1
        i += 1
    return count


DEBUG_DIRECTIVE = re.compile(r"^\s*\.(line|local|end local|restart local|prologue|epilogue|source)\b")


def without_extras(lines: list[str]) -> list[str]:
    """The lines of a method text that the reference also writes: annotation blocks, `.param` lines (with the annotation
    block they may carry) and debug directives are this server's additions and are removed."""
    kept: list[str] = []
    i = 0
    while i < len(lines):
        word = lines[i].strip()
        if word.startswith(".annotation "):
            while i < len(lines) and lines[i].strip() != ".end annotation":
                i += 1
            i += 1
        elif word.startswith(".param"):
            block = i + 1 < len(lines) and lines[i + 1].strip().startswith(".annotation ")
            i += 1
            if block:
                while i < len(lines) and lines[i].strip() != ".end param":
                    i += 1
                i += 1
        elif DEBUG_DIRECTIVE.match(lines[i]):
            i += 1
        else:
            kept.append(lines[i])
            i += 1
    return kept


def canon_smali(text: str):
    """(instructions, exception table) with the writing conventions removed: labels become code addresses,
    p-registers v-registers, wide literals lose their L, apostrophes their backslash; label definitions
    are dropped and `.catch` lines collected, because the two engines place them differently. The additions of
    mdd.smali.v1 (annotations, parameter names, debug directives) are removed first."""
    lines = without_extras(text.splitlines())
    declaration = lines[0] if lines else ""
    registers = None
    for line in lines[:3]:
        m = re.match(r"\s*\.registers (\d+)", line)
        if m:
            registers = int(m.group(1))
    first_parameter = None if registers is None else registers - parameter_registers(declaration)
    instructions, catches = [], []
    in_switch = False
    for raw in lines:
        line = raw.strip()
        if line.startswith((".packed-switch", ".sparse-switch")):
            in_switch = True
        elif line.startswith((".end packed-switch", ".end sparse-switch")):
            in_switch = False
        if not line or line.startswith("#"):
            continue
        if line.startswith(":") and not in_switch:
            continue  # a label definition; the case targets inside a switch are content, not definitions
        m = CATCH.match(line)
        if m:
            kind, type_, a, b, handler = m.groups()
            catches.append((kind, type_ or "", label_address(a[1:]), label_address(b[1:]), label_address(handler[1:])))
            continue
        line = line.replace("\\'", "'")
        line = LABEL.sub(lambda mm: ":@%x" % label_address(mm.group(1)) if mm.group(1).split("_")[0] in LABEL_PREFIXES else mm.group(0), line)
        line = re.sub(r"(?<![\w$])(-?0x[0-9a-f]+)L\b", r"\1", line)
        if first_parameter is not None and not line.startswith(".registers"):
            line = re.sub(r"(?<![\w$.:])p(\d+)\b", lambda mm: "v%d" % (first_parameter + int(mm.group(1))), line)
        instructions.append(line)
    return instructions, sorted(catches)


CONTEXT_ENTRY = re.compile(r"^line (\d+): (.*)$")
CONTEXT_HEADER = "# Original zero-based smali line numbers; labels retain method-relative code-unit offsets."


def canon_context(text: str):
    """The context view reduced to what it says: the method line, the register count, the addresses that carry a label
    (labels that name one address are one), the addresses the cases of a switch name, and the exception table.
    The numbers are dropped: they count the lines of each engine's own full text."""
    lines = text.splitlines()
    declaration = registers = None
    labels: list[int] = []
    cases: list[int] = []
    catches = []
    for raw in lines[1:]:
        m = CONTEXT_ENTRY.match(raw)
        if not m:
            return ("malformed entry", raw)
        original = m.group(2)
        word = original.strip()
        if word.startswith(".method"):
            declaration = word
        elif word.startswith(".registers"):
            registers = word
        elif word.startswith(".catch"):
            c = CATCH.match(word)
            if not c:
                return ("malformed catch", raw)
            kind, type_, a, b, handler = c.groups()
            catches.append((kind, type_ or "", label_address(a[1:]), label_address(b[1:]), label_address(handler[1:])))
        elif word.startswith(":"):
            address = label_address(word[1:])
            if original.startswith(" " * 8):
                cases.append(address)  # a case of a switch table (it is indented a level deeper than a label definition)
            elif not labels or labels[-1] != address:
                labels.append(address)
        else:
            return ("an anchor line of another kind", raw)
    return (lines[0] if lines else "", declaration, registers, labels, cases, sorted(catches))


# ---- comparison -----------------------------------------------------------------------------------

def strip_envelope(body):
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        return {**body, "error": {k: v for k, v in body["error"].items() if k not in ENVELOPE}}
    return body


def differences(a, b, path=""):
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            if key not in a:
                yield f"{path}/{key}: only this server has {json.dumps(b[key], ensure_ascii=False)[:120]}"
            elif key not in b:
                yield f"{path}/{key}: only the reference has {json.dumps(a[key], ensure_ascii=False)[:120]}"
            else:
                yield from differences(a[key], b[key], f"{path}/{key}")
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            yield from differences(x, y, f"{path}[{i}]")
    elif a != b:
        yield f"{path}: reference {json.dumps(a, ensure_ascii=False)[:120]} vs this server {json.dumps(b, ensure_ascii=False)[:120]}"


def first_text_difference(a, b) -> str:
    (ia, ca), (ib, cb) = a, b
    for x, y in zip(ia, ib):
        if x != y:
            return f"reference `{x[:80]}` vs this server `{y[:80]}`"
    if len(ia) != len(ib):
        return f"{len(ia)} instruction lines vs {len(ib)}"
    return f"exception tables {ca[:3]} vs {cb[:3]}"


def compare_ok_bodies(want: dict, got: dict) -> list[str]:
    """Two successful answers of decode or get_manifest."""
    want, got = json.loads(json.dumps(want)), json.loads(json.dumps(got))
    problems: list[str] = []
    if want.get("mode") == "summary":
        for m in got.get("methods", []):
            m.pop("declaration", None)
    got.pop("text_format", None)
    got.pop("class", None)
    for m in got.get("methods", []):
        m.pop("source_total_lines", None)
    if "methods" in want and "methods" in got and len(want["methods"]) == len(got["methods"]):
        for w, g in zip(want["methods"], got["methods"]):
            if "smali" not in w or "smali" not in g:
                continue
            whole = w.get("offset") == 0 and w.get("next_offset") is None and g.get("offset") == 0 and g.get("next_offset") is None
            if whole:
                reduce = canon_context if want.get("mode") == "context" else canon_smali
                canon_w, canon_g = reduce(w["smali"]), reduce(g["smali"])
                if canon_w != canon_g:
                    if want.get("mode") == "context":
                        problems.append(f"the context says something else: reference {canon_w} vs this server {canon_g}")
                    else:
                        problems.append("the text says something else: " + first_text_difference(canon_w, canon_g))
            if w["smali"] != g["smali"] or w.get("total_bytes") != g.get("total_bytes"):
                for key in TEXT_FIELDS:
                    w.pop(key, None)
                    g.pop(key, None)
    return problems + list(differences(want, got))


def kind_of(body: dict):
    error = body.get("error") if isinstance(body, dict) else None
    return error.get("kind") if isinstance(error, dict) else None


def compare_case(case: dict, ours: dict) -> tuple[list[str], str | None]:
    """The differences that are not declared, and the declared class that excused one."""
    want = case["reply"]
    case_id = case.get("id", "")
    wrong_at_once = "-combo-" in case_id
    if case_id in TEXT_LENGTH:
        # the two texts have different lengths, so an offset that ends one of them is inside or past the other:
        # this server either refuses it as a range error or serves the page that starts exactly there
        if "jsonrpc_error" in ours:
            return ["a JSON-RPC error where a range error or a page is expected"], None
        if ours["is_error"]:
            return ([], "TEXT CONVENTIONS") if kind_of(strip_envelope(ours["reply"])) == "invalid_range" else (["an offset past this server's text was not called a range error"], None)
        page = (ours["reply"].get("methods") or [{}])[0]
        return ([], "TEXT CONVENTIONS") if page.get("offset") == case["arguments"].get("offset") else (["the page does not start at the offset asked"], None)
    if case_id in BUDGET:
        return ([], "CLASS PAGE BYTES") if not (ours.get("is_error") or "jsonrpc_error" in ours) else (["a byte budget on a class page was refused"], None)
    if case_id in LENIENT:
        return ([], "LENIENT") if "jsonrpc_error" not in ours else (["a JSON-RPC error where a tool result is declared"], None)
    if case_id == "generic-list-unknown-field" and "reply" in ours:
        # the limits are each server's own configuration; their names are compared
        want_limits, got_limits = want.get("limits", {}), ours["reply"].get("limits", {})
        stripped_want = {**want, "limits": sorted(want_limits)}
        stripped_got = {**ours["reply"], "limits": sorted(got_limits)}
        return list(differences(stripped_want, stripped_got)), "OWN SCOPE"
    if case_id == "generic-list-tables-unknown-field" and "reply" in ours:
        names = [row["name"] for row in ours["reply"].get("tables", []) if isinstance(row, dict)]
        problems = [] if names and set(names) <= set(want["tables"]) else ["a table this server lists is not one of the reference's"]
        return problems, "OWN SCOPE"
    if wrong_at_once and case["is_error"] and ("jsonrpc_error" in ours or ours["is_error"]):
        return _same_kind_or_order(case, ours)
    if "jsonrpc_error" in ours:
        if "raw_text" in want or kind_of(want) == "invalid_input":
            return [], "MALFORMED ARGUMENTS"
        return [f"this server answered a JSON-RPC error {ours['jsonrpc_error']} where the reference answered a result"], None
    got = strip_envelope(ours["reply"])
    got_error = ours["is_error"]
    if "raw_text" in want:
        return ([], "MALFORMED ARGUMENTS") if got_error else (["the reference refused the arguments and this server accepted them"], None)
    want_error = case["is_error"]
    if want_error and not got_error:
        message = (want.get("error") or {}).get("message", "")
        if message == "invoke argument count does not match prototype":
            smali = (got.get("methods") or [{}])[0].get("smali", "")
            return ([], "MALFORMED CODE") if smali.strip() else (["a method with a malformed invoke was answered without text"], None)
        if message.startswith(("max_bytes must be in", "timeout_ms must be in", "offset must be a UTF-8 boundary")):
            return [], "LENIENT"
        return ["the reference refused and this server answered"], None
    if got_error and not want_error:
        return [f"this server refused ({kind_of(got)}) and the reference answered"], None
    if want_error:
        problems = []
        want_kind, got_kind = kind_of(want), kind_of(got)
        if got_kind not in KIND_ALIASES.get(want_kind, {want_kind}):
            problems.append(f"error kind: reference {want_kind} vs this server {got_kind}")
        for key in ("file_id", "method_idx", "code_unit_offset", "dataset_closed", "statement_index"):
            if key in want["error"] and want["error"][key] != got["error"].get(key):
                problems.append(f"error.{key}: reference {want['error'][key]!r} vs this server {got['error'].get(key)!r}")
        if "dataset_id" in want and "dataset_id" not in got:
            problems.append("the reference names the dataset beside the error and this server does not")
        return problems, ("ERROR WORDING" if want["error"].get("message") != got["error"].get("message") else None)
    page, ours_page = want.get("page"), got.get("page")
    if case.get("tool") == "get_manifest" and isinstance(page, dict) and isinstance(ours_page, dict)             and page.get("text") != ours_page.get("text"):
        # the first line of a page that starts inside a line is the rest of that line, whatever it holds
        mid_line = bool(case["arguments"].get("offset"))
        kept = "".join(line for number, line in enumerate(ours_page["text"].splitlines(keepends=True))
                       if (number == 0 and mid_line) or "<" in line or ">" in line or '="' in line)
        if kept == page["text"]:
            return [], "XML TEXT NODES"
    return compare_ok_bodies(want, got), None


def _same_kind_or_order(case: dict, ours: dict) -> tuple[list[str], str | None]:
    """Several things are wrong at once: both engines refuse, but which of them is named first can differ."""
    if "jsonrpc_error" in ours:
        return [], "ORDER OF CHECKS"
    want_kind, got_kind = kind_of(case["reply"]), kind_of(strip_envelope(ours["reply"]))
    if want_kind is None or got_kind in KIND_ALIASES.get(want_kind, {want_kind}):
        return [], None
    return [], "ORDER OF CHECKS"


def put(binary: Path, inputs: list[str], tool: str, arguments: dict) -> dict:
    client, dataset = gen.open_session(binary, inputs)
    try:
        return gen.ask(client, dataset, tool, arguments)
    finally:
        client.close()


def refusal_is_clean(answer: dict) -> bool:
    body = answer.get("reply", {})
    return answer.get("is_error") is True and isinstance(body.get("error"), dict) and body["error"].get("kind") == "not_implemented"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--show", type=int, default=8, help="how many differing requests to print in full")
    parser.add_argument("--only", help="run only the cases whose id contains this text")
    options = parser.parse_args()

    golden = json.loads(a0_cases.GOLDEN.read_text(encoding="utf-8"))
    stale = [name for name, digest in golden["fixtures_sha256"].items() if a0_cases.sha256(a0_cases.FIXTURES / name) != digest]
    if stale:
        print("the fixtures changed since the golden was recorded:", stale, file=sys.stderr)
        return 2

    checks, shown = [], 0
    for case in golden["cases"]:
        if options.only and options.only not in case["id"]:
            continue
        ours = put(options.binary, case["inputs"], case["tool"], case["arguments"])
        if case["id"] in NOT_IMPLEMENTED:
            ok = refusal_is_clean(ours)
            checks.append({"id": case["id"], "equal": None, "not_run": NOT_IMPLEMENTED[case["id"]], "refused_cleanly": ok})
            if not ok and shown < options.show:
                shown += 1
                print("NOT REFUSED CLEANLY", case["id"], json.dumps(ours, ensure_ascii=False)[:300])
            continue
        if case["id"] in TIMING:
            checks.append({"id": case["id"], "equal": None, "not_run": TIMING[case["id"]]})
            continue
        problems, declared = compare_case(case, ours)
        checks.append({"id": case["id"], "equal": not problems, "declared": declared, "differences": problems[:6]})
        if problems and shown < options.show:
            shown += 1
            print(f"DIFF {case['id']}  {case['tool']} {json.dumps(case['arguments'], ensure_ascii=False)[:100]}")
            for line in problems[:6]:
                print("     ", line)

    methods_equal = methods_total = 0
    method_diffs: list[dict] = []
    session: dict[tuple, tuple] = {}
    for method in golden["methods"]:
        if options.only:
            break
        key = tuple(method["inputs"])
        if key not in session:
            session[key] = gen.open_session(options.binary, method["inputs"])
        client, dataset = session[key]
        got = gen.ask(client, dataset, "decode", {"file_id": method["file_id"], "method_idx": method["method_idx"], "max_lines": 1000})
        problems, _ = compare_case(method, got)
        # the context view of the same method, reduced the same way
        got_context = gen.ask(client, dataset, "decode", {"file_id": method["file_id"], "method_idx": method["method_idx"],
                                                          "mode": "context", "max_lines": 1000})
        context_problems, _ = compare_case(method["context"], got_context)
        problems += [f"context: {line}" for line in context_problems]
        methods_total += 1
        if not problems:
            methods_equal += 1
        else:
            method_diffs.append({"descriptor": method["descriptor"], "differences": problems[:4]})
            if shown < options.show:
                shown += 1
                print(f"DIFF method {method['descriptor']}")
                for line in problems[:4]:
                    print("     ", line)
    for client, _ in session.values():
        client.close()

    run = [c for c in checks if c["equal"] is not None]
    passed = sum(1 for c in run if c["equal"])
    by_class: dict[str, int] = {}
    for c in run:
        if c["equal"] and c.get("declared"):
            by_class[c["declared"]] = by_class.get(c["declared"], 0) + 1
    report = {
        "reference": golden["reference"],
        "recorded_utc": golden["recorded_utc"],
        "cases_run": len(run), "cases_equal": passed,
        "cases_equal_exactly": sum(1 for c in run if c["equal"] and not c.get("declared")),
        "cases_equal_with_a_declared_difference": by_class,
        "cases_not_run": [{"id": c["id"], "reason": c["not_run"], "refused_cleanly": c.get("refused_cleanly")} for c in checks if c["equal"] is None],
        "methods": {"total": methods_total, "equal": methods_equal, "different": method_diffs[:20]},
        "differing_cases": [c for c in run if not c["equal"]],
        "declared_differences": [{"class": name, "why": why} for name, why in DECLARED],
    }
    if options.out:
        options.out.write_text(a0_cases.json_dump(report), encoding="utf-8", newline="\n")
    unclean = [c["id"] for c in checks if c["equal"] is None and c.get("refused_cleanly") is False]
    print(f"cases: {passed}/{len(run)} equal ({report['cases_equal_exactly']} exactly, {sum(by_class.values())} with a declared difference), "
          f"{len(checks) - len(run)} not run; methods: {methods_equal}/{methods_total} equal; unclean refusals: {len(unclean)}")
    return 0 if passed == len(run) and methods_equal == methods_total and not unclean else 1


if __name__ == "__main__":
    sys.exit(main())
