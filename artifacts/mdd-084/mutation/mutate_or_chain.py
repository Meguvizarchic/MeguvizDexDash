#!/usr/bin/env python3
"""Mutation check for MDD-084: a deep OR/AND/NOT chain or a long LIKE pattern must be evaluated, or refused, without
overflowing the call stack.

It uses the machinery of artifacts/mdd-042/mutation/mutate_mcp.py (one source file edited in place per mutant, the suites
run, the original bytes written back in a finally block, commands with time limits, parts, assembly) with this task's
mutants and suites. A mutant is killed when the unit tests of mdd-query and mdd-sql, the MCP process tests or a replay fails;
the replays include the crash reproduction of this task (repro_or_chain_overflow.py, phase post) against the mutated build.

Usage: the same as mutate_mcp.py
  mutate_or_chain.py                     every mutant, then the clean-tree check
  mutate_or_chain.py --part K/N          the mutants whose position is K-1 modulo N
  mutate_or_chain.py --clean-only        only the clean-tree check and the hash
  mutate_or_chain.py --assemble FILE...  merge the parts and the clean-tree output
  mutate_or_chain.py --anchors           only say which mutants' anchors are not unique in their file (no build, no run)
  mutate_or_chain.py NAME...             only the mutants whose name contains one of the words
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("mutate_mcp", ROOT / "artifacts/mdd-042/mutation/mutate_mcp.py")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

PY = base.PY
OPERATORS = "crates/mdd-query/src/operators/mod.rs"
AST = "crates/mdd-sql/src/dialects/ast.rs"

# the suites of this task: the engine crates that hold the evaluator and the rewrite, then the process tests
base.UNIT_MCP = [*base.CARGO, "-p", "mdd-query", "-p", "mdd-sql", "--lib", *base.TAIL]
base.UNIT_SMALI = [*base.CARGO, "-p", "mdd-service", "--lib", *base.TAIL]
base.REPLAYS = [
    *base.REPLAYS,
    ("or-chain crash", [PY, "-I", "artifacts/mdd-084/repro_or_chain_overflow.py", "--binary", "target/debug/meguvizdexdash" + (".exe" if sys.platform == "win32" else ""),
                        "--phase", "post", "--out", "artifacts/local/mdd-084-mutation-repro.json"]),
]
base.SOURCES = [*base.SOURCES, OPERATORS, AST, "artifacts/mdd-084/repro_or_chain_overflow.py"]

MUTANTS = [
    # ---- the predicate evaluator
    ("evaluator: an AND is an OR", OPERATORS, [("            Ok(left.and(right))", "            Ok(left.or(right))")]),
    ("evaluator: an OR is an AND", OPERATORS, [("            Ok(left.or(right))", "            Ok(left.and(right))")]),
    ("evaluator: a NOT does not negate", OPERATORS,
     [("            Ok(predicate_at(value, row, source, control, reference, depth + 1)?.not())",
       "            Ok(predicate_at(value, row, source, control, reference, depth + 1)?)")]),
    ("evaluator: a predicate deeper than 64 is walked", OPERATORS, [("    if depth > PREDICATE_EVAL_DEPTH {", "    if depth > 100_000 {")]),
    ("evaluator: the depth limit is one too low", OPERATORS, [("    if depth > PREDICATE_EVAL_DEPTH {", "    if depth >= PREDICATE_EVAL_DEPTH {")]),
    ("validation: a predicate deeper than 64 is accepted", OPERATORS,
     [('    if depth > 64 {\n        return Err(invalid("PREDICATE_DEPTH_LIMIT"));', '    if depth > 6400 {\n        return Err(invalid("PREDICATE_DEPTH_LIMIT"));')]),
    # ---- the reference LIKE matcher
    ("like: a pattern with a star tries one start too few", OPERATORS, [("            if next <= text.len() - t {", "            if next < text.len() - t {")]),
    ("like: a pattern with a star does not backtrack", OPERATORS, [("                stack.push((t, p, next));", "                let _ = next;")]),
    ("like: a literal matches any unit", OPERATORS, [("                    if text.get(t) != Some(&unit) {", "                    if false {")]),
    ("like: an underscore matches past the end", OPERATORS, [("                LikeToken::AnyOne => {\n                    if t == text.len() {", "                LikeToken::AnyOne => {\n                    if false {")]),
    # ---- the SQL rewrite
    ("rewrite: the depth of the rewrite is not capped", AST, [("        if depth > self.limits.max_ast_depth.min(MAX_AST_REWRITE_DEPTH)", "        if depth > self.limits.max_ast_depth")]),
    ("rewrite: the rewrite runs on a small stack", AST, [("            .stack_size(AST_REWRITE_STACK_BYTES)", "            .stack_size(AST_REWRITE_STACK_BYTES / 256)")]),
]

base.MUTANTS = MUTANTS


def anchors() -> int:
    """Which anchors are not unique in their file (no build, no run)."""
    bad = 0
    for name, relative, edits in MUTANTS:
        text = (ROOT / relative).read_text(encoding="utf-8")
        for old, _new in edits:
            count = text.count(old)
            if count != 1:
                bad += 1
                print(f"ANCHOR {count}x  {name}  [{relative}]")
    print(f"{len(MUTANTS)} mutants, {bad} anchors that are not unique")
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--anchors"]:
        sys.exit(anchors())
    sys.exit(base.main())
