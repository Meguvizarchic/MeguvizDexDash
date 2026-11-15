#!/usr/bin/env python3
"""Independent oracle for conformance/analysis/soundness-cases.json.

Usage: python -I conformance/analysis/oracle.py [--cases PATH]

It reads the same labelled programs as the Rust tests but shares no code with them: its
own table of what each op does, its own control-flow construction, and a different
algorithm for reaching definitions (a worklist over single instructions, where the Rust
analysis iterates over blocks). It never decodes bytes, so it says nothing about the
decoder; it checks that the analysis semantics written in the expectations are what a
second implementation derives from the programs.

Every case is computed and compared with its hand-written `expect`; any difference, or a
program the oracle cannot interpret, makes the run fail. Checks raise, never `assert`,
so `python -O` cannot remove them.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT = ROOT / "conformance/analysis/soundness-cases.json"

GOTO = {"goto"}
COND = {"if-eqz", "if-nez", "if-eq", "if-ne", "if-lt"}
SWITCH = {"packed-switch", "sparse-switch"}
RETURN = {"return", "return-void", "return-wide", "return-object"}
THROW_OP = {"throw"}
MAY_THROW = {"div-int", "array-length", "aget", "throw", "monitor-enter", "invoke-static", "invoke-virtual"}
PAYLOAD = {"packed-payload", "sparse-payload"}


class Refused(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refused(message)


def effects(op: list) -> tuple[list[str], list[str]]:
    """(uses, defs) of one instruction, as register names, uses first."""
    name = op[0]

    def pair(n: int) -> list[str]:
        return [f"v{n}", f"v{n + 1}"]

    reg = lambda n: [f"v{n}"]  # noqa: E731
    if name == "nop" or name == "return-void" or name == "goto":
        return [], []
    if name in ("const/4", "const/16"):
        return [], reg(op[1])
    if name in ("move", "move-object", "neg-int", "array-length"):
        return reg(op[2]), reg(op[1])
    if name == "move-wide":
        return pair(op[2]), pair(op[1])
    if name == "int-to-long":
        return reg(op[2]), pair(op[1])
    if name in ("move-result", "move-result-object"):
        return ["result"], reg(op[1])
    if name == "move-result-wide":
        return ["result"], pair(op[1])
    if name == "move-exception":
        return ["exception"], reg(op[1])
    if name in ("invoke-static", "invoke-virtual"):
        return [f"v{n}" for n in op[1]], ["result"]
    if name in ("return", "return-object", "throw", "monitor-enter"):
        return reg(op[1]), []
    if name == "return-wide":
        return pair(op[1]), []
    if name in ("if-eqz", "if-nez", "packed-switch", "sparse-switch"):
        return reg(op[1]), []
    if name in ("if-eq", "if-ne", "if-lt"):
        return reg(op[1]) + reg(op[2]), []
    if name in ("add-int", "sub-int", "div-int", "aget"):
        return reg(op[2]) + reg(op[3]), reg(op[1])
    if name == "add-long":
        return pair(op[2]) + pair(op[3]), pair(op[1])
    if name == "add-int/lit8":
        return reg(op[2]), reg(op[1])
    if name == "add-int/2addr":
        return reg(op[1]) + reg(op[2]), reg(op[1])
    if name == "add-long/2addr":
        return pair(op[1]) + pair(op[2]), pair(op[1])
    raise Refused(f"no effects for {name}")


def compute(case: dict) -> dict:
    # ---- items: instructions and payloads, labels attached to the item that follows
    items: list[list] = []
    label_item: dict[str, int] = {}
    for op in case["program"]:
        if op[0] == "label":
            label_item[op[1]] = len(items)
        else:
            items.append(op)
    is_instruction = [op[0] not in PAYLOAD for op in items]
    n_items = len(items)

    def name_of(index: int) -> str:
        names = sorted(name for name, at in label_item.items() if at == index)
        return names[0] if names else f"@{index}"

    def target(label: str) -> int:
        require(label in label_item, f"unknown label {label}")
        return label_item[label]

    # ---- flow of each instruction
    def jump_targets(index: int) -> list[tuple[int, str]]:
        op = items[index]
        name = op[0]
        if name == "goto":
            return [(target(op[1]), "branch")]
        if name in ("if-eqz", "if-nez"):
            return [(target(op[2]), "branch")]
        if name in ("if-eq", "if-ne", "if-lt"):
            return [(target(op[3]), "branch")]
        if name in SWITCH:
            payload = items[target(op[2])]
            require(payload[0] in PAYLOAD, "switch must name a payload")
            if payload[0] == "packed-payload":
                return [(target(label), f"switch:{int(payload[2]) + n}") for n, label in enumerate(payload[3])]
            return [(target(label), f"switch:{key}") for key, label in payload[2]]
        return []

    def continues(name: str) -> bool:
        return name not in GOTO and name not in RETURN and name not in THROW_OP

    # ---- blocks: leaders
    leaders: set[int] = {0}
    for index, op in enumerate(items):
        if not is_instruction[index]:
            continue
        name = op[0]
        for to, _ in jump_targets(index):
            leaders.add(to)
        if name in GOTO or name in COND or name in SWITCH or name in RETURN or name in THROW_OP:
            if index + 1 < n_items and is_instruction[index + 1]:
                leaders.add(index + 1)
        if index + 1 < n_items and not is_instruction[index + 1] and index + 2 < n_items and is_instruction[index + 2]:
            leaders.add(index + 2)  # code after a payload starts a new run
    tries = []
    for item in case["tries"]:
        start, end = target(item["from"]), target(item["to"])
        handlers = [(int(t), target(label)) for t, label in item.get("catches", [])]
        catch_all = target(item["catch_all"]) if item.get("catch_all") else None
        tries.append((start, end, handlers, catch_all))
        leaders.update([start, end])
        leaders.update(h for _, h in handlers)
        if catch_all is not None:
            leaders.add(catch_all)
    leaders = {i for i in leaders if i < n_items and is_instruction[i]}
    starts = sorted(leaders)
    block_of: dict[int, int] = {}
    blocks: list[tuple[int, int]] = []  # [first, last] instruction item indices
    for position, first in enumerate(starts):
        limit = starts[position + 1] if position + 1 < len(starts) else n_items
        last = first
        while last + 1 < limit and is_instruction[last + 1]:
            last += 1
        blocks.append((first, last))
        for i in range(first, last + 1):
            block_of[i] = position

    def try_of(first: int):
        for start, end, handlers, catch_all in tries:
            if start <= first < end:
                return handlers, catch_all
        return None

    # ---- edges, per block
    edges: list[tuple[int, str, str, str]] = []  # (from block, to, kind, certainty)
    pending_issues: list[tuple[int, str, int]] = []
    for position, (first, last) in enumerate(blocks):
        name = items[last][0]
        certain = "definite"
        if name in COND or name in SWITCH:
            certain = "possible"
        for to, kind in jump_targets(last):
            edges.append((position, str(block_of[to]), kind, "definite" if name in GOTO else "possible"))
        if continues(name):
            nxt = last + 1
            if nxt < n_items and is_instruction[nxt]:
                edges.append((position, str(block_of[nxt]), "fallthrough", certain))
            elif nxt < n_items:
                pending_issues.append((position, "fallthrough_into_data", nxt))
            else:
                pending_issues.append((position, "fallthrough_past_end", n_items))
        if name in RETURN:
            edges.append((position, "return", "return", "definite"))
        throwing = [i for i in range(first, last + 1) if items[i][0] in MAY_THROW]
        if throwing:
            found = try_of(first)
            caught_all = False
            if found:
                handlers, catch_all = found
                for type_idx, to in handlers:
                    edges.append((position, str(block_of[to]), f"exception:{type_idx}", "possible"))
                if catch_all is not None:
                    caught_all = True
                    edges.append((position, str(block_of[catch_all]), "exception:any", "possible"))
            if not caught_all:
                edges.append((position, "exit", "exception_exit", "possible"))

    # ---- reachability
    reached = {0}
    frontier = [0]
    while frontier:
        current = frontier.pop()
        for src, to, _, _ in edges:
            if src == current and to.isdigit() and int(to) not in reached:
                reached.add(int(to))
                frontier.append(int(to))
    issues = [[kind, name_of(at)] for position, kind, at in pending_issues if position in reached]

    # ---- reaching definitions, one instruction at a time
    ins_total = case["ins"]
    params = [f"v{n}" for n in range(case["registers"] - ins_total, case["registers"])]
    defs: dict[tuple, str] = {}  # (kind, key...) -> name

    def def_name(site: tuple, reg: str) -> str:
        if site[0] == "entry":
            return f"entry:{reg}"
        if site[0] == "handler":
            return f"handler:{name_of(site[1])}"
        return f"{name_of(site[1])}:{reg}"

    instructions = [i for i in range(n_items) if is_instruction[i]]
    handler_entries = {first for position, (first, _) in enumerate(blocks)
                       if any(e[1] == str(position) and e[2].startswith("exception") for e in edges)}
    regs_all = set(params)
    for i in instructions:
        u, d = effects(items[i])
        regs_all.update(u, d)
    undefined = "<undefined>"
    state_in: dict[int, dict[str, set]] = {}
    entry_state = {r: {undefined} for r in regs_all}
    for r in params:
        entry_state[r] = {def_name(("entry",), r)}
    state_in[instructions[0]] = entry_state
    work = [instructions[0]]
    handler_blocks_of = {}
    for position, (first, last) in enumerate(blocks):
        handler_blocks_of[position] = [int(e[1]) for e in edges if e[0] == position and e[2].startswith("exception") and e[1].isdigit()]

    def push(index: int, incoming: dict, exception_def: str | None = None) -> None:
        current = state_in.setdefault(index, {})
        before = {r: set(s) for r, s in current.items()}
        for r, s in incoming.items():
            current.setdefault(r, set()).update(s)
        if exception_def is not None:
            current["exception"] = {exception_def}
        if current != before:
            work.append(index)

    while work:
        i = work.pop()
        state = {r: set(s) for r, s in state_in[i].items()}
        op = items[i]
        position = block_of[i]
        if op[0] in MAY_THROW:
            for h in handler_blocks_of[position]:
                first = blocks[h][0]
                push(first, state, def_name(("handler", first), "exception"))
        uses, defs_now = effects(op)
        for r in defs_now:
            state[r] = {def_name(("insn", i), r)}
        last_in_block = blocks[position][1] == i
        successors = []
        if not last_in_block:
            successors.append(i + 1)
        else:
            for src, to, kind, _ in edges:
                if src == position and to.isdigit() and not kind.startswith("exception"):
                    successors.append(blocks[int(to)][0])
        for s in successors:
            push(s, state)

    uses_out = []
    for i in instructions:
        if i not in state_in or block_of[i] not in reached:
            continue
        uses, _ = effects(items[i])
        for r in sorted(set(uses)):
            tokens = state_in[i].get(r, {undefined})
            uses_out.append([name_of(i), r, sorted(t for t in tokens if t != undefined), undefined in tokens])
    rows = lambda xs: sorted(xs, key=lambda x: json.dumps(x))  # noqa: E731
    def edge_json(e):
        src, to, kind, certain = e
        return [name_of(blocks[src][0]), name_of(blocks[int(to)][0]) if to.isdigit() else ("return" if to == "return" else "exception_exit"), kind, certain]
    return {
        "blocks": [name_of(blocks[p][0]) for p in range(len(blocks))],
        "edges": rows([edge_json(e) for e in edges]),
        "unreachable": rows([name_of(blocks[p][0]) for p in range(len(blocks)) if p not in reached]),
        "issues": rows(issues),
        "uses": rows(uses_out),
    }


def normalise_expected(expect: dict) -> dict:
    rows = lambda xs: sorted(xs, key=lambda x: json.dumps(x))  # noqa: E731
    return {
        "blocks": expect["blocks"], "edges": rows(expect["edges"]),
        "unreachable": rows(expect["unreachable"]), "issues": rows(expect["issues"]),
        "uses": rows(expect["uses"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=DEFAULT)
    args = parser.parse_args()
    document = json.loads(args.cases.read_text(encoding="utf-8"))
    failed = 0
    for case in document["cases"]:
        try:
            got = compute(case)
        except Refused as error:
            print(f"REFUSED {case['name']}: {error}")
            failed += 1
            continue
        want = normalise_expected(case["expect"])
        bad = [key for key in want if got[key] != want[key]]
        if bad:
            failed += 1
            print(f"DIFFERS {case['name']}: {bad}")
            for key in bad:
                print(f"   {key}\n     oracle: {json.dumps(got[key])}\n     expect: {json.dumps(want[key])}")
        else:
            print(f"ok      {case['name']}")
    print(f"{len(document['cases']) - failed}/{len(document['cases'])} cases agree")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
