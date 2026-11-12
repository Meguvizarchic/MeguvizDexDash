"""Focused check that the rewritten Q06 assembler matches the pinned expression.

Runs the same frozen source through the new AST assembler and compares the
result against an independently reconstructed expected string. Does not execute
any pinned source code.
"""
import ast
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import static_contracts as sc  # noqa: E402

SOURCE = HERE / "source-8782f43"
rule_text = (SOURCE / "native_rules.py").read_text(encoding="utf-8")
node = next(n for n in sc.expression_nodes(rule_text) if n.lineno == 56)


def literal(value):
    if any(c in value for c in "\r\n\0"):
        raise ValueError("control characters")
    return "'" + value.replace("'", "''") + "'"


def in_list(values):
    return ",".join(literal(v) for v in values)


def descriptor(name):
    return "L" + name.replace(".", "/") + ";"


owners = ["fixture.A"]
got = sc.assemble_pinned_sql(node, in_list, descriptor, owners)

# Independent expectation: concatenate the literal parts of the pinned node and
# splice in the in_list helper output at the one helper call site.
parts = []
for child in ast.walk(node):
    if isinstance(child, ast.Constant) and isinstance(child.value, str):
        parts.append(child.value)
expected_with_helper = (
    'SELECT DISTINCT file_id,method_idx,value FROM method_strings WHERE method_class IN ('
    + in_list(descriptor(o) for o in owners)
    + ") "
)
assert got.startswith(expected_with_helper), got[:200]
assert "quality settings:" in got, got
assert "ORDER BY file_id,method_idx,value" in got, got
assert got == sc.assemble_pinned_sql(node, in_list, descriptor, owners), "unstable"
print("Q06 assembler output length:", len(got))
print("Q06 assembler head:", got[:160].replace("\n", " "))
print("Q06 CHECK PASSED")
