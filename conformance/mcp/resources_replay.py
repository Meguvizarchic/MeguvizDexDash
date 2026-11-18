#!/usr/bin/env python3
"""Replay the reference engine's recorded answers for the resource tools (MDD-072).

artifacts/mdd-072/a0-probe/calls.jsonl holds every call put to the reference engine (A0,
dexsql 0.1.0) by the probe scripts next to it: the tool, its arguments, the inputs it was
opened on and the answer. The inputs are saved in tests/fixtures/resources/probe/<probe>/.
This opens the same inputs in meguvizdexdash, makes the same calls and compares each answer
with the recorded one.

A verdict is one of
  match         every field the reference answered is ours, equal; ours may add only the
                fields listed in EXTRA_KEYS and, inside an error, EXTRA_ERROR_KEYS
  declared      different, and the difference is one of the classes in DECLARED; the
                classifier names the class and checks the evidence for it
  differs       different and not declared: a defect to fix or to declare
  error         the call could not be made

Usage: python -I conformance/mcp/resources_replay.py [--binary PATH] [--out FILE] [--show N]
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mcp_client import DEFAULT_BINARY, ROOT, McpClient, McpError  # noqa: E402

CALLS = ROOT / "artifacts" / "mdd-072" / "a0-probe" / "calls.jsonl"
# the questions put to the reference about a real application: the APK and the recording of the
# answers (a few MB of the application's own strings and layouts) are ignored local files, made by
# artifacts/mdd-072/probe/probe_newpipe.py
NEWPIPE_CALLS = ROOT / "artifacts" / "local" / "a0-probe" / "newpipe.jsonl"
NEWPIPE_APK = ROOT / "artifacts" / "local" / "inputs" / "NewPipe_v0.28.6.apk"
NEWPIPE_SHA256 = "e56ef6280b700696172797f94513ffd3f9aae9349945a2f06e235ec24446be58"
FIXTURES = ROOT / "tests" / "fixtures" / "resources" / "probe"

# fields only meant to differ in value, or that this engine adds beside the reference's
MASKED = {"dataset_id", "prepare_ms"}
EXTRA_KEYS = {"source", "skipped_chunks", "raw_name_hex", "snapshot_id", "scope_id", "profile",
              "sql_dialect", "dex_count", "snapshot_manifest", "diagnostics"}
EXTRA_ERROR_KEYS = {"code", "details", "retryable", "stage", "dataset_closed"}

DECLARED = {
    "ERROR_WORDING": "both refuse with the same kind; the message is worded differently",
    "ARGUMENT_RANGE_SHAPE": "an argument outside its range is a JSON-RPC invalid-params error here, an isError tool result in the reference",
    "XML_TEXT_NODES": "the XML view here keeps text nodes; the reference omits them",
    "NAMESPACES_KEPT": "the XML view here writes every namespace declaration and namespaced attribute under the prefix the document gave it; the reference writes the android namespace only, always as android",
    "STRING_VALUE_AS_INDEX": "in a layout the reference writes a string-typed android attribute as its pool index; this engine writes the string",
    "STRICT_INPUT": "a malformed input (wrong table magic, an AXML namespace not declared, a repeated attribute) is refused here and read leniently by the reference",
    "FRAMEWORK_NAMES": "the reference names ids of the framework's own resources from an embedded table; this engine writes the id",
    "CONTROL_CHARS": "the reference rewrites or drops control characters in attribute values; this engine keeps them exactly",
    "UNKNOWN_UNIT": "a dimension or fraction unit outside the platform's table is written out in full here, as a bare number by the reference",
    "ENUM_ON_STRING_TYPE": "the reference names a flag word from the data word of a string-typed protectionLevel; this engine shows the string",
    "RAW_WORD_IN_LAYOUT": "in a layout (not the manifest) the reference writes the stored word of a typed value, a dimension, a reference, an integer or a boolean, as an unsigned decimal; this engine spells the typed value",
    "FRAMEWORK_ENUMS": "the reference names the enumerations and flags of the framework's layout attributes (fill_parent, horizontal, top|fill_horizontal) from an embedded table; this engine names only installLocation, launchMode, protectionLevel and foregroundServiceType, and writes the number for any other",
    "NEGATIVE_DIMENSION": "the reference reads the mantissa of a dimension as unsigned; a negative dimension is written -3dip here (the platform's reading) and 16777213dip there",
    "ROW_BUDGET": "the page ends one row earlier or later under a small max_bytes; the rows shown are the reference's rows",
    "LIST_TABLES_SHAPE": "list_tables answers objects here, names in the reference (declared in MDD-042)",
}

STRICT_MESSAGES = ("not a resource table", "AXML namespace URI is not in scope", "duplicate expanded attribute name")
FRAMEWORK = re.compile(r"^@?android:\w+/[\w.]+$|^@0[0-9a-f]{7}$")
REFERENCE_FORM = re.compile(r"^[@?]0[0-9a-f]{7}$")


def compare(reference, ours, path="", diffs=None):
    """Collect (path, reference, ours) wherever the reference's field is not ours."""
    diffs = [] if diffs is None else diffs
    if isinstance(reference, dict) and isinstance(ours, dict):
        for key, value in reference.items():
            if key in MASKED:
                continue
            if key not in ours:
                diffs.append((f"{path}/{key}", value, "<missing>"))
            else:
                compare(value, ours[key], f"{path}/{key}", diffs)
        extras = EXTRA_KEYS | (EXTRA_ERROR_KEYS if path == "/error" else set())
        for key in ours:
            if key not in reference and key not in extras and not key.startswith("_") and key not in MASKED:
                diffs.append((f"{path}/{key}", "<absent>", ours[key]))
    elif isinstance(reference, list) and isinstance(ours, list):
        if len(reference) != len(ours):
            diffs.append((f"{path}[len]", len(reference), len(ours)))
        for index, (a, b) in enumerate(zip(reference, ours)):
            compare(a, b, f"{path}[{index}]", diffs)
    elif reference != ours or type(reference) is not type(ours):
        diffs.append((path or "/", reference, ours))
    return diffs


ATTRIBUTE = re.compile(r'^(\s*)(<[\w.:-]+ )?([\w.:-]+)="(.*)"(/?>?)$')


def unescape(text: str) -> str:
    """The text of an XML attribute value, character and entity references resolved."""
    text = re.sub(r"&#x([0-9A-Fa-f]+);", lambda m: chr(int(m.group(1), 16)), text)
    for entity, char in (("&quot;", '"'), ("&apos;", "'"), ("&lt;", "<"), ("&gt;", ">"), ("&amp;", "&")):
        text = text.replace(entity, char)
    return text


def prefix_of(name: str) -> str:
    return name.split(":", 1)[0] if ":" in name else ""


def inserted_class(line: str):
    """The declared class of a line only this engine writes, or None."""
    stripped = line.strip()
    if stripped.startswith("xmlns:"):
        return "NAMESPACES_KEPT"
    match = ATTRIBUTE.match(line)
    if match:
        prefix = prefix_of(match.group(3))
        return "NAMESPACES_KEPT" if prefix and prefix != "android" else None
    if stripped.startswith("</"):
        return "XML_TEXT_NODES"
    if "<" not in stripped and ">" not in stripped:
        return "XML_TEXT_NODES"
    return None


def pair_classes(reference: str, ours: str):
    """The declared classes that explain one line of ours differing from the reference's."""
    r, o = ATTRIBUTE.match(reference), ATTRIBUTE.match(ours)
    if not (r and o):
        return None
    classes = set()
    if r.group(2) != o.group(2) and (r.group(2) or '').split(':')[-1] != (o.group(2) or '').split(':')[-1]:
        return None
    r_name, o_name = r.group(3), o.group(3)
    if r_name != o_name:
        if r_name.split(":")[-1] == o_name.split(":")[-1] and prefix_of(r_name) == "android"                 and prefix_of(o_name) not in ("", "android"):
            classes.add("NAMESPACES_KEPT")
        else:
            return None
    r_value, o_value = unescape(r.group(4)), unescape(o.group(4))
    if r_value != o_value:
        cls = value_class(r_name, r_value, o_value)
        if cls is None and re.fullmatch(r"-?\d+", r_value) and not re.fullmatch(r"-?[\d.]+", o_value):
            cls = "STRING_VALUE_AS_INDEX"
        if cls is None:
            return None
        classes.add(cls)
    if r.group(5) != o.group(5):
        # a tag that gained an attribute or a child ends differently: a consequence, never a class
        classes.add("TAIL")
    return classes


SINGLE_LINE_TAG = re.compile(r'^(\s*)(<[\w.:-]+) ((?:[\w.:-]+="[^"]*"\s*)+)(/?>)$')


def one_attribute_per_line(text: str) -> list[str]:
    """The lines of an XML text with every tag written the long way, so that a tag the reference wrote on one line
    (because it kept one attribute) and this engine wrote on several (because it kept two) compare line for line."""
    lines = []
    for line in text.splitlines():
        match = SINGLE_LINE_TAG.match(line)
        if not match:
            lines.append(line)
            continue
        indent, head, body, tail = match.groups()
        attributes = re.findall(r'[\w.:-]+="[^"]*"', body)
        lines.append(indent + head)
        lines.extend(f"{indent}  {attribute}" for attribute in attributes)
        lines[-1] += tail
    return lines


def xml_classes(reference: str, ours: str):
    """The declared classes that explain every difference between two XML texts, or None."""
    a, b = one_attribute_per_line(reference), one_attribute_per_line(ours)
    classes = set()
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        if tag == "delete":
            return None
        theirs, mine = a[i1:i2], b[j1:j2]
        # each of the reference's lines in the block must be explained by one of ours; whatever
        # is left of ours must be lines only this engine writes
        left = list(mine)
        for line in theirs:
            for candidate in left:
                found = pair_classes(line, candidate)
                if found is not None:
                    classes |= found
                    left.remove(candidate)
                    break
            else:
                return None
        for line in left:
            cls = inserted_class(line)
            if cls is None:
                return None
            classes.add(cls)
    # a difference of line endings alone explains nothing; beside a declared class it is the consequence of it
    if classes == {"TAIL"}:
        return None
    classes.discard("TAIL")
    return classes


def control_normalised(text: str) -> str:
    """What the reference makes of a text: line ends and tabs become spaces, other controls go."""
    text = re.sub(r"[\n\t\r]", " ", text)
    return re.sub(r"[\x00-\x1f]", "", text)


def _f32(word: int) -> str:
    """The shortest decimal of the f32 with these bits, as Rust writes it."""
    import struct
    value = struct.unpack("<f", struct.pack("<I", word))[0]
    if value != value:
        return "NaN"
    if value in (float("inf"), float("-inf")):
        return "inf" if value > 0 else "-inf"
    text = repr(struct.unpack("<f", struct.pack("<f", value))[0])
    # python's repr of the f32 widened to f64 is longer than the shortest f32 text; search the shortest that reads back
    for digits in range(1, 10):
        candidate = f"{value:.{digits}g}"
        if struct.unpack("<f", struct.pack("<f", float(candidate)))[0] == value:
            number = float(candidate)
            return str(int(number)) if number == int(number) and abs(number) < 1e16 else candidate
    return text


def _complex(word: int) -> float:
    mults = [0.00390625, 3.051758e-05, 1.192093e-07, 4.656613e-10]
    mantissa = word & 0xFFFFFF00
    if mantissa >= 0x80000000:
        mantissa -= 0x100000000
    return mantissa * mults[(word >> 4) & 3]


def stored_word_forms(word: int) -> set:
    """Every way this engine spells a stored 32-bit word, whatever its type: what a decimal word can mean."""
    forms = {str(word - (1 << 32) if word >= 1 << 31 else word), f"0x{word:08x}", f"#{word:08x}",
             "true" if word else "false", f"@{word:08x}", f"?{word:08x}"}
    units = ["px", "dip", "sp", "pt", "in", "mm"]
    if (word & 15) < len(units):
        forms.add(f"{_complex(word):.17g}".rstrip("0").rstrip(".") + units[word & 15])
        forms.add(repr(_complex(word)).removesuffix(".0") + units[word & 15])
    if (word & 15) < 2:
        forms.add(repr(_complex(word) * 100.0).removesuffix(".0") + ["%", "%p"][word & 15])
    forms.add(_f32(word))
    return forms


def value_class(path: str, reference, ours):
    """The declared class of one differing summary value, or None."""
    if not (isinstance(reference, str) and isinstance(ours, str)):
        return None
    if FRAMEWORK.match(reference) and REFERENCE_FORM.match(ours):
        return "FRAMEWORK_NAMES"
    if control_normalised(ours) == reference and ours != reference:
        return "CONTROL_CHARS"
    if ours.startswith("<0x") and ", unit " in ours and re.fullmatch(r"[0-9.]+", reference):
        return "UNKNOWN_UNIT"
    if re.fullmatch(r"\d+", reference) and int(reference) < 1 << 32 and ours in stored_word_forms(int(reference)):
        return "RAW_WORD_IN_LAYOUT"
    if re.fullmatch(r"\d+dip|\d+sp|\d+px|\d+pt|\d+in|\d+mm", reference):
        number, unit = re.fullmatch(r"(\d+)([a-z]+)", reference).groups()
        if int(number) >= 1 << 23 and ours == f"{int(number) - (1 << 24)}{unit}":
            return "NEGATIVE_DIMENSION"
    if re.fullmatch(r"[A-Za-z_]+(\|[A-Za-z_]+)*", reference) and re.fullmatch(r"-?\d+|0x[0-9a-f]{8}", ours):
        return "FRAMEWORK_ENUMS"
    if path.endswith("android:protectionLevel") and ours in {
            "signature", "dangerous", "normal", "signature|privileged", "bogus"}:
        return "ENUM_ON_STRING_TYPE"
    return None


def classify(record, reference, ours, diffs, full_text=lambda record: None):
    """The declared class of a difference, or None when it is not declared."""
    if not diffs:
        return ["match"]
    tool = record["tool"]
    ref_error = record["is_error"]
    our_error = ours.get("_is_error", False) or "_jsonrpc_error" in ours
    if tool == "list_tables":
        return ["LIST_TABLES_SHAPE"]
    if "_jsonrpc_error" in ours:
        if ref_error and (isinstance(reference, str) or reference.get("error", {}).get("kind") == "invalid_input"):
            return ["ARGUMENT_RANGE_SHAPE"]
        return None
    if ref_error and our_error:
        ours_error = ours.get("error", {})
        if reference.get("error", {}).get("kind") == ours_error.get("kind") and \
                all(path == "/error/message" for path, _, _ in diffs):
            return ["ERROR_WORDING"]
        return None
    if not ref_error and our_error:
        if any(m in json.dumps(ours.get("error", {})) for m in STRICT_MESSAGES):
            return ["STRICT_INPUT"]
        return None
    if ref_error and not our_error:
        # an offset valid in our longer XML text and past the end of the reference's shorter one
        if reference.get("error", {}).get("kind") == "invalid_range" and "page" in ours:
            return ["XML_TEXT_NODES"]
        return None
    # both answered
    ref_text = reference.get("page", {}).get("text") if isinstance(reference, dict) else None
    our_text = ours.get("page", {}).get("text") if isinstance(ours, dict) else None
    if ref_text is not None and our_text is not None and ref_text != our_text:
        if not all(p.startswith("/page/") for p, _, _ in diffs):
            return None
        if reference["page"].get("next_offset") is None and ours["page"].get("next_offset") is None \
                and not record["arguments"].get("offset"):
            found = xml_classes(ref_text, our_text)
        else:
            # a page of a text that differs from the reference's: the whole texts are judged
            whole = full_text(record)
            if whole:
                found = xml_classes(whole[0], whole[1])
            elif not record["arguments"].get("offset") and reference["page"].get("next_offset") is not None \
                    and ours["page"].get("next_offset") is not None:
                # two first pages of a text too long for one: the lines both cover are judged
                shared = min(len(ref_text.splitlines()), len(our_text.splitlines())) - 1
                found = xml_classes("\n".join(ref_text.splitlines()[:shared]),
                                    "\n".join(our_text.splitlines()[:shared]))
            else:
                found = None
        return sorted(found) if found else None
    classes = set()
    for path, ref_value, our_value in diffs:
        if path.startswith(("/application/", "/manifest/")) or "/attributes/" in path or path.endswith("/value"):
            cls = value_class(path, ref_value, our_value)
            if cls is None:
                return None
            classes.add(cls)
        else:
            classes = set()
            break
    if classes:
        return sorted(classes)
    rows_key = next((k for k in ("values", "files", "components") if k in reference), None)
    if rows_key and record["arguments"].get("max_bytes") is not None:
        a, b = reference[rows_key], ours.get(rows_key, [])
        common = min(len(a), len(b))
        if a[:common] == b[:common] and a != b:
            return ["ROW_BUDGET"]
    return None


def call(client: McpClient, tool: str, arguments: dict) -> dict:
    """McpClient.call with the arguments as a dict: a tool may take a parameter called `name`."""
    response = client.request("tools/call", {"name": tool, "arguments": arguments})
    if "error" in response:
        raise McpError(response["error"])
    result = response["result"]
    structured = dict(result["structuredContent"])
    structured["_is_error"] = result["isError"]
    return structured


FIXTURE_MANIFEST = FIXTURES / "manifest.json"


def fixture_hashes() -> dict[str, str]:
    """SHA-256 of every saved input, by path under the probe directory."""
    return {str(path.relative_to(FIXTURES)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(FIXTURES.rglob("*.apk"))}


def verify_fixtures() -> list[str]:
    """The saved inputs that are not the ones the reference was asked about."""
    recorded = json.loads(FIXTURE_MANIFEST.read_text(encoding="utf-8"))["files"]
    current = fixture_hashes()
    return sorted(name for name in set(recorded) | set(current) if recorded.get(name) != current.get(name))


def newpipe_present() -> bool:
    return NEWPIPE_CALLS.is_file() and NEWPIPE_APK.is_file() and hashlib.sha256(NEWPIPE_APK.read_bytes()).hexdigest() == NEWPIPE_SHA256


def shorten(value, limit=160):
    """A value for the report: long texts are cut, so the report does not carry a page of someone else's strings."""
    text = json.dumps(value, ensure_ascii=False)
    return value if len(text) <= limit else text[:limit] + f"...({len(text)} characters)"


def load_calls() -> list[dict]:
    """The recorded calls; those about the real application are included when the APK is here."""
    files = [CALLS] + ([NEWPIPE_CALLS] if newpipe_present() else [])
    return [json.loads(line) for path in files for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def input_path(record: dict, name: str) -> Path:
    return NEWPIPE_APK if record["probe"] == "probe_newpipe" else FIXTURES / record["probe"] / name


def run(binary: Path, show: int) -> dict:
    results, counts, classes = [], Counter(), Counter()
    client = McpClient(binary)
    client.initialize()
    datasets: dict[tuple, str] = {}
    shown = 0
    records = load_calls()
    # the reference's whole text of each XML or text resource, from the record that read it whole
    complete = {}
    for rec in records:
        reply = rec["reply"]
        if rec["tool"] in ("get_manifest", "read_resource") and not rec["is_error"] and isinstance(reply, dict)                 and isinstance(reply.get("page"), dict) and reply["page"].get("next_offset") is None                 and not rec["arguments"].get("offset") and not rec["arguments"].get("max_bytes")                 and rec["arguments"].get("mode", "xml") == "xml":
            complete[(rec["tool"], tuple(rec["inputs"]), rec["arguments"].get("name") or rec["arguments"].get("mode"))] =                 reply["page"]["text"]
    complete_by_size = {len(text.encode()): text for text in complete.values()}
    for number, record in enumerate(records):
        tool, arguments = record["tool"], dict(record["arguments"])
        inputs = tuple(record["inputs"])
        label = f"{number:03d} {record['probe']} {tool} {json.dumps(arguments, ensure_ascii=False)[:90]}"
        try:
            if tool == "open_dataset":
                for dataset in datasets.values():
                    call(client, "close_dataset", {"dataset_id": dataset})
                datasets.clear()
                paths = [str(input_path(record, name)) for name in inputs]
                ours = call(client, "open_dataset", {"inputs": paths})
                if not ours["_is_error"]:
                    datasets[inputs] = ours["dataset_id"]
                    ours["inputs"] = list(inputs)
            else:
                # a call the reference answered "not open" was made after its dataset was closed
                closed = record["is_error"] and isinstance(record["reply"], dict)                     and record["reply"].get("error", {}).get("kind") == "unknown_dataset"
                ours = call(client, tool, {"dataset_id": "dataset-closed" if closed else datasets.get(inputs, "none"),
                                           **arguments})
        except McpError as error:
            ours = {"_is_error": True, "_jsonrpc_error": error.error}
        except Exception as error:  # noqa: BLE001 - reported, never hidden
            results.append({"call": label, "verdict": "error", "detail": repr(error)})
            counts["error"] += 1
            continue
        reference = record["reply"]
        if tool == "open_dataset":
            keep = ("archive_inputs", "has_dex", "input_bytes", "inputs")
            diffs = compare({k: reference[k] for k in keep if k in reference},
                            {k: ours.get(k) for k in keep}) if not record["is_error"] else []
        elif "_jsonrpc_error" in ours:
            diffs = [("/jsonrpc_error", reference, ours["_jsonrpc_error"])]
        elif record["is_error"] != ours["_is_error"]:
            diffs = [("/is_error", record["is_error"], ours["_is_error"])]
        else:
            diffs = compare(reference, ours)
        def full_text(rec, _inputs=inputs, _reference=reference):
            """(the reference's whole text, ours) for the resource a paged record is about."""
            key = (rec["tool"], _inputs, rec["arguments"].get("name") or rec["arguments"].get("mode"))
            whole = complete.get(key)
            page = _reference.get("page") if isinstance(_reference, dict) else None
            if whole is None and page is not None:
                # the same text read whole through another input: found by its size, and trusted
                # only when this page is the slice of it the page says it is
                whole = complete_by_size.get(page["total_bytes"])
                start = rec["arguments"].get("offset", 0)
                if whole is not None and whole.encode()[start:start + len(page["text"].encode())] != page["text"].encode():
                    whole = None
            if whole is None:
                return None
            args = {k: v for k, v in rec["arguments"].items() if k not in ("offset", "max_bytes")}
            reply = call(client, rec["tool"], {"dataset_id": datasets.get(_inputs, "none"), **args, "max_bytes": 131072})
            return (whole, reply["page"]["text"]) if "page" in reply else None

        found = classify(record, reference, ours, diffs, full_text) if diffs else ["match"]
        verdict = "match" if found == ["match"] else ("declared" if found else "differs")
        counts[verdict] += 1
        for cls in (found or []):
            if verdict == "declared":
                classes[cls] += 1
        entry = {"call": label, "verdict": verdict}
        if verdict == "declared":
            entry["classes"] = found
        if verdict != "match":
            entry["diffs"] = [{"path": p, "reference": shorten(r), "ours": shorten(o)} for p, r, o in diffs[:8]]
            if ours.get("_is_error"):
                entry["ours_error"] = ours.get("error", ours.get("_jsonrpc_error"))
            if verdict == "differs" and shown < show:
                shown += 1
                print(label)
                for p, r, o in diffs[:4]:
                    print(f"    {p}: reference {json.dumps(r, ensure_ascii=False)[:160]}  ours {json.dumps(o, ensure_ascii=False)[:160]}")
        results.append(entry)
    client.close()
    absent = not newpipe_present()
    return {"counts": dict(counts), "classes": dict(classes), "results": results,
            "newpipe": {"records": sum(1 for _ in NEWPIPE_CALLS.open(encoding="utf-8")) if NEWPIPE_CALLS.is_file() else 0,
                        "run": not absent, "apk_sha256": NEWPIPE_SHA256,
                        "not_run": "the NewPipe APK or its recording (artifacts/local) is an ignored local file and is not here" if absent else None}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--show", type=int, default=0, help="print the first N undeclared differences")
    parser.add_argument("--write-fixture-manifest", action="store_true",
                        help="record the hashes of the saved inputs (after the probes were rerun)")
    args = parser.parse_args()
    if args.write_fixture_manifest:
        FIXTURE_MANIFEST.write_text(json.dumps({"about": "the inputs the reference engine was asked about (artifacts/mdd-072/probe)",
                                                "files": fixture_hashes()}, indent=1, sort_keys=True) + "\n",
                                    encoding="utf-8", newline="\n")
        return 0
    changed = verify_fixtures()
    if changed:
        print("the saved inputs differ from the recorded hashes:", changed, file=sys.stderr)
        return 2
    report = run(args.binary, args.show)
    print(json.dumps(report["counts"], sort_keys=True), json.dumps(report["classes"], sort_keys=True))
    if args.out:
        args.out.write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    return 0 if not report["counts"].get("differs") and not report["counts"].get("error") else 1


if __name__ == "__main__":
    sys.exit(main())
