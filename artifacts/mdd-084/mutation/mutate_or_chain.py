#!/usr/bin/env python3
"""Mutation check for MDD-084: a deep OR/AND/NOT chain or a long LIKE pattern must be evaluated, or refused, without
overflowing the call stack.

Uses tools/mutation_harness.py with only the mdd-query/mdd-sql evaluator/rewrite sources and reproduction suite.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))

import mutation_harness as H  # noqa: E402

PY = H.PY
OPERATORS = "crates/mdd-query/src/operators/mod.rs"
AST = "crates/mdd-sql/src/dialects/ast.rs"
AST_REWRITE = "crates/mdd-sql/src/dialects/ast/rewrite.rs"

SOURCES = [
    OPERATORS,
    "crates/mdd-query/src/executor/tests.rs",
    AST,
    "crates/mdd-sql/src/dialects/ast/binding.rs",
    "crates/mdd-sql/src/dialects/ast/affinity.rs",
    "crates/mdd-sql/src/dialects/ast/compound.rs",
    AST_REWRITE,
    "crates/mdd-sql/src/dialects/ast/validate.rs",
    "artifacts/mdd-084/repro_or_chain_overflow.py",
]

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
    ("rewrite: the depth of the rewrite is not capped", AST_REWRITE, [("        if depth > self.limits.max_ast_depth.min(MAX_AST_REWRITE_DEPTH)", "        if depth > self.limits.max_ast_depth")]),
    ("rewrite: the rewrite runs on a small stack", AST, [("            .stack_size(AST_REWRITE_STACK_BYTES)", "            .stack_size(AST_REWRITE_STACK_BYTES / 256)")]),
]

SUITE = H.MutationSuite(
    name="MDD-084",
    sources=SOURCES,
    unit_suites=[
        ("unit", [*H.CARGO, "-p", "mdd-query", "-p", "mdd-sql", "--lib", *H.TAIL]),
    ],
    replays=[
        ("or-chain crash", [PY, "-I", "artifacts/mdd-084/repro_or_chain_overflow.py", "--binary", H.BINARY,
                            "--phase", "post", "--out", "artifacts/local/mdd-084-mutation-repro.json"]),
    ],
    mutants=MUTANTS,
)
base = SUITE


def sources_sha256() -> str:
    return SUITE.sources_sha256()


if __name__ == "__main__":
    sys.exit(SUITE.main())
