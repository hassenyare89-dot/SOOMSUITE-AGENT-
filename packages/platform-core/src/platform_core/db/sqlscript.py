"""Split a multi-statement SQL script (asyncpg executes one statement per call)."""

from __future__ import annotations


def split_sql(script: str) -> list[str]:
    statements: list[str] = []
    buf: list[str] = []
    in_dollar = False
    in_single = False
    i = 0
    while i < len(script):
        ch = script[i]
        nxt = script[i + 1] if i + 1 < len(script) else ""
        if not in_single and ch == "$" and nxt == "$":
            in_dollar = not in_dollar
            buf.append("$$")
            i += 2
            continue
        if not in_dollar and ch == "'":
            in_single = not in_single
        if not in_dollar and not in_single and ch == "-" and nxt == "-":
            end = script.find("\n", i)
            i = len(script) if end == -1 else end
            continue
        if ch == ";" and not in_dollar and not in_single:
            stmt = "".join(buf).strip()
            if stmt:
                statements.append(stmt)
            buf = []
        else:
            buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        statements.append(tail)
    return statements


def execute_script(op, script: str) -> None:
    for statement in split_sql(script):
        op.execute(statement)
