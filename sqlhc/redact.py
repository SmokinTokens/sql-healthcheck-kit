"""Query-text redactor.

Query text from the plan cache can hold data inside literals (emails, names,
account numbers). redact(sql) replaces:
  - string literals  '...'  N'...'  (with '' escapes)   -> '?'
  - hex/binary literals 0x1A2B                           -> 0x?
  - numeric literals 42  3.14  1e5  (not inside names)  -> ?
It keeps keywords, object names, @variables and [bracketed names].
"Double-quoted" text is replaced with "?" too: under QUOTED_IDENTIFIER OFF it is
a string literal, and the redactor cannot tell which mode the session used.
Comments are dropped (they can hold data too). Pure stdlib.
Text cut off in the middle of a literal is still hidden.
"""
import re

_TOKEN = re.compile(r"""
    (?P<comment_line>--[^\r\n]*)
  | (?P<comment_block>/\*.*?(?:\*/|$))
  | (?P<string>N?'(?:[^']|'')*(?:'|$))
  | (?P<bracket>\[(?:[^\]]|\]\])*(?:\]|$))
  | (?P<dquote>"(?:[^"]|"")*(?:"|$))
  | (?P<hex>\b0[xX][0-9A-Fa-f]*)
  | (?P<word>[@#$]*[A-Za-z_][A-Za-z0-9_@#$]*)
  | (?P<number>(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)
  | (?P<other>.)
""", re.S | re.X)


def redact(sql: str) -> str:
    out = []
    for m in _TOKEN.finditer(sql):
        kind = m.lastgroup
        if kind in ("comment_line", "comment_block"):
            out.append(" ")
        elif kind == "string":
            out.append("'?'")
        elif kind == "dquote":
            out.append('"?"')
        elif kind == "hex":
            out.append("0x?")
        elif kind == "number":
            out.append("?")
        else:
            out.append(m.group(0))
    return re.sub(r"\s+", " ", "".join(out)).strip()
